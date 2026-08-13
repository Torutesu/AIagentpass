import Darwin
import Foundation

public enum NativeDarwinGitWorktreeObservationError: String, Error, Equatable, Sendable {
  case invalidProcess = "invalid_process"
  case processUnavailable = "process_unavailable"
  case processChanged = "process_changed"
  case currentDirectoryUnavailable = "current_directory_unavailable"
  case currentDirectoryChanged = "current_directory_changed"
  case repositoryUnavailable = "repository_unavailable"
  case unsafeFilesystemObject = "unsafe_filesystem_object"
  case malformedGitMetadata = "malformed_git_metadata"
  case unsupportedGitLayout = "unsupported_git_layout"
  case observationChanged = "observation_changed"
}

public struct NativeAgentWorktreeObservation: Equatable, Sendable {
  public let binding: NativeAgentWorktreeBinding

  public var repositoryPath: String { binding.repositoryPath }
  public var branch: String? {
    guard case .branch(let value) = binding.head else { return nil }
    return value
  }

  public init(binding: NativeAgentWorktreeBinding) {
    self.binding = binding
  }
}

internal struct NativeDarwinWorktreeProcessSnapshot: Equatable, Sendable {
  let pid: Int32
  let uid: UInt32
  let pidVersion: UInt64
}

internal struct NativeDarwinCurrentDirectorySnapshot: Equatable, Sendable {
  let path: String
  let device: UInt64
  let inode: UInt64
  let generation: UInt32
}

internal protocol NativeDarwinWorktreeProcessAdapter: Sendable {
  func process(pid: Int32) throws -> NativeDarwinWorktreeProcessSnapshot
  func currentDirectory(pid: Int32) throws -> NativeDarwinCurrentDirectorySnapshot
}

/// Observes Git authority from OS-owned peer state. Request DTO paths are not
/// accepted by this API. The root process and cwd vnode are sampled before and
/// after all filesystem reads so PID reuse, exec replacement, and chdir races
/// fail closed.
public struct NativeDarwinGitWorktreeObserver: Sendable {
  private let processAdapter: any NativeDarwinWorktreeProcessAdapter

  public init() {
    processAdapter = NativeDarwinWorktreeSystemAdapter()
  }

  internal init(processAdapter: any NativeDarwinWorktreeProcessAdapter) {
    self.processAdapter = processAdapter
  }

  public func observe(pid: Int32, expectedUserID: UInt32) throws -> NativeAgentWorktreeObservation {
    guard pid > 0 else { throw NativeDarwinGitWorktreeObservationError.invalidProcess }
    let processBefore = try processAdapter.process(pid: pid)
    guard processBefore.pid == pid, processBefore.uid == expectedUserID,
      processBefore.pidVersion > 0
    else { throw NativeDarwinGitWorktreeObservationError.invalidProcess }
    let cwdBefore = try processAdapter.currentDirectory(pid: pid)
    let observation = try NativeGitFilesystemObserver().observe(
      currentDirectory: cwdBefore.path,
      expectedDirectory: cwdBefore,
      expectedUserID: expectedUserID
    )
    let cwdAfter = try processAdapter.currentDirectory(pid: pid)
    let processAfter = try processAdapter.process(pid: pid)
    guard processBefore == processAfter else {
      throw NativeDarwinGitWorktreeObservationError.processChanged
    }
    guard cwdBefore == cwdAfter else {
      throw NativeDarwinGitWorktreeObservationError.currentDirectoryChanged
    }
    try NativeGitFilesystemObserver().revalidate(observation.binding)
    let cwdFinal = try processAdapter.currentDirectory(pid: pid)
    let processFinal = try processAdapter.process(pid: pid)
    guard processBefore == processFinal else {
      throw NativeDarwinGitWorktreeObservationError.processChanged
    }
    guard cwdBefore == cwdFinal else {
      throw NativeDarwinGitWorktreeObservationError.currentDirectoryChanged
    }
    return observation
  }
}

private struct NativeDarwinWorktreeSystemAdapter: NativeDarwinWorktreeProcessAdapter {
  func process(pid: Int32) throws -> NativeDarwinWorktreeProcessSnapshot {
    var information = proc_bsdinfo()
    let expected = Int32(MemoryLayout<proc_bsdinfo>.size)
    let count = withUnsafeMutablePointer(to: &information) {
      proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, $0, expected)
    }
    guard count == expected, information.pbi_pid == UInt32(pid), information.pbi_start_tvsec > 0,
      information.pbi_start_tvusec < 1_000_000,
      information.pbi_start_tvsec <= (UInt64.max - information.pbi_start_tvusec) / 1_000_000
    else { throw NativeDarwinGitWorktreeObservationError.processUnavailable }
    return NativeDarwinWorktreeProcessSnapshot(
      pid: pid,
      uid: UInt32(information.pbi_uid),
      pidVersion: information.pbi_start_tvsec * 1_000_000 + information.pbi_start_tvusec
    )
  }

  func currentDirectory(pid: Int32) throws -> NativeDarwinCurrentDirectorySnapshot {
    var information = proc_vnodepathinfo()
    let expected = Int32(MemoryLayout<proc_vnodepathinfo>.size)
    let count = withUnsafeMutablePointer(to: &information) {
      proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, $0, expected)
    }
    guard count == expected else {
      throw NativeDarwinGitWorktreeObservationError.currentDirectoryUnavailable
    }
    let bytes = withUnsafeBytes(of: information.pvi_cdir.vip_path) { Array($0) }
    guard let terminator = bytes.firstIndex(of: 0), terminator > 0, terminator < MAXPATHLEN,
      let path = String(bytes: bytes[..<terminator], encoding: .utf8),
      path.hasPrefix("/"), path.utf8.count < MAXPATHLEN
    else { throw NativeDarwinGitWorktreeObservationError.currentDirectoryUnavailable }
    let stat = information.pvi_cdir.vip_vi.vi_stat
    guard stat.vst_dev > 0, stat.vst_ino > 0 else {
      throw NativeDarwinGitWorktreeObservationError.currentDirectoryUnavailable
    }
    return NativeDarwinCurrentDirectorySnapshot(
      path: path,
      device: UInt64(stat.vst_dev),
      inode: stat.vst_ino,
      generation: stat.vst_gen
    )
  }
}

internal struct NativeGitFilesystemObserver: Sendable {
  private static let maximumGitFileBytes = 8 * 1_024
  private static let maximumHeadBytes = 2 * 1_024
  private static let maximumConfigBytes = 256 * 1_024
  private static let maximumPackedRefsBytes = 8 * 1_024 * 1_024
  private static let maximumReferenceDepth = 8
  private static let maximumAncestors = 64

  func observe(
    currentDirectory: String,
    expectedDirectory: NativeDarwinCurrentDirectorySnapshot? = nil,
    expectedUserID: UInt32
  ) throws -> NativeAgentWorktreeObservation {
    let canonicalCWD = try Self.canonicalAbsolutePath(currentDirectory)
    let cwd = try SecureDirectory.open(canonicalCWD, expectedUserID: expectedUserID)
    defer { cwd.close() }
    if let expectedDirectory {
      guard cwd.identity.device == expectedDirectory.device,
        cwd.identity.inode == expectedDirectory.inode,
        cwd.identity.generation == expectedDirectory.generation
      else { throw NativeDarwinGitWorktreeObservationError.currentDirectoryChanged }
    }

    let repository = try findRepository(from: canonicalCWD, expectedUserID: expectedUserID)
    defer { repository.directory.close() }
    let metadata = try readGitLayout(repository: repository, expectedUserID: expectedUserID)
    defer {
      metadata.gitDirectory.close()
      if metadata.commonDirectory.descriptor != metadata.gitDirectory.descriptor {
        metadata.commonDirectory.close()
      }
    }
    let configuration = try readConfiguration(from: metadata.commonDirectory)
    try rejectUnsupportedAuthorityFeatures(metadata)
    let headAuthority = try readHeadAuthority(
      gitDirectory: metadata.gitDirectory,
      commonDirectory: metadata.commonDirectory,
      objectFormat: configuration.objectFormat)
    let binding: NativeAgentWorktreeBinding
    do {
      binding = try NativeAgentWorktreeBinding(
        layout: metadata.layout,
        repositoryPath: repository.path,
        gitDirectoryPath: metadata.gitDirectory.path,
        commonDirectoryPath: metadata.commonDirectory.path,
        repositoryIdentity: repository.directory.identity,
        gitDirectoryIdentity: metadata.gitDirectory.identity,
        commonDirectoryIdentity: metadata.commonDirectory.identity,
        objectFormat: configuration.objectFormat,
        head: headAuthority.head,
        headObjectID: headAuthority.objectID,
        headTreeID: headAuthority.treeID,
        remotes: configuration.remotes
      )
    } catch {
      throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
    }
    try revalidate(binding)
    return NativeAgentWorktreeObservation(binding: binding)
  }

  func revalidate(_ binding: NativeAgentWorktreeBinding) throws {
    let repository = try SecureDirectory.open(
      binding.repositoryPath, expectedUserID: binding.repositoryIdentity.ownerUserID)
    defer { repository.close() }
    let git = try SecureDirectory.open(
      binding.gitDirectoryPath, expectedUserID: binding.gitDirectoryIdentity.ownerUserID)
    defer { git.close() }
    let common = try SecureDirectory.open(
      binding.commonDirectoryPath, expectedUserID: binding.commonDirectoryIdentity.ownerUserID)
    defer { common.close() }
    guard repository.identity == binding.repositoryIdentity,
      git.identity == binding.gitDirectoryIdentity,
      common.identity == binding.commonDirectoryIdentity,
      try currentAuthority(gitDirectory: git, commonDirectory: common) == binding.authoritySnapshot
    else { throw NativeDarwinGitWorktreeObservationError.observationChanged }
  }

  private func findRepository(from path: String, expectedUserID: UInt32) throws -> Repository {
    var candidate = path
    for _ in 0..<Self.maximumAncestors {
      let directory = try SecureDirectory.open(candidate, expectedUserID: expectedUserID)
      var info = stat()
      if fstatat(directory.descriptor, ".git", &info, AT_SYMLINK_NOFOLLOW) == 0 {
        let type = info.st_mode & S_IFMT
        guard type == S_IFDIR || type == S_IFREG else {
          directory.close()
          throw NativeDarwinGitWorktreeObservationError.unsafeFilesystemObject
        }
        return Repository(path: candidate, directory: directory)
      }
      directory.close()
      guard candidate != "/" else { break }
      candidate = Self.parent(of: candidate)
    }
    throw NativeDarwinGitWorktreeObservationError.repositoryUnavailable
  }

  private func readGitLayout(repository: Repository, expectedUserID: UInt32) throws -> GitLayout {
    var info = stat()
    guard fstatat(repository.directory.descriptor, ".git", &info, AT_SYMLINK_NOFOLLOW) == 0 else {
      throw NativeDarwinGitWorktreeObservationError.repositoryUnavailable
    }
    if info.st_mode & S_IFMT == S_IFDIR {
      let path = repository.path + "/.git"
      let git = try SecureDirectory.open(path, expectedUserID: expectedUserID)
      return GitLayout(layout: .embedded, gitDirectory: git, commonDirectory: git)
    }
    guard info.st_mode & S_IFMT == S_IFREG, info.st_nlink == 1,
      info.st_uid == expectedUserID, info.st_mode & 0o022 == 0
    else { throw NativeDarwinGitWorktreeObservationError.unsafeFilesystemObject }
    let gitFile = try readFile(
      directory: repository.directory, name: ".git", maximum: Self.maximumGitFileBytes)
    let prefix = "gitdir: "
    guard gitFile.hasPrefix(prefix), gitFile.hasSuffix("\n"),
      !gitFile.dropLast().contains("\n")
    else { throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata }
    let rawGitDirectory = String(gitFile.dropFirst(prefix.count).dropLast())
    let gitPath = try Self.resolve(rawGitDirectory, relativeTo: repository.path)
    let git = try SecureDirectory.open(gitPath, expectedUserID: expectedUserID)
    do {
      let commonFile = try readFile(
        directory: git, name: "commondir", maximum: Self.maximumGitFileBytes)
      guard commonFile.hasSuffix("\n"), !commonFile.dropLast().contains("\n") else {
        throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
      }
      let commonPath = try Self.resolve(String(commonFile.dropLast()), relativeTo: gitPath)
      let common = try SecureDirectory.open(commonPath, expectedUserID: expectedUserID)
      do {
        let backlink = try readFile(
          directory: git, name: "gitdir", maximum: Self.maximumGitFileBytes)
        guard backlink.hasSuffix("\n"), !backlink.dropLast().contains("\n"),
          try Self.resolve(String(backlink.dropLast()), relativeTo: gitPath)
            == repository.path + "/.git"
        else {
          throw NativeDarwinGitWorktreeObservationError.unsupportedGitLayout
        }
        return GitLayout(layout: .linked, gitDirectory: git, commonDirectory: common)
      } catch {
        common.close()
        throw error
      }
    } catch let error as NativeDarwinGitWorktreeObservationError {
      git.close()
      throw error
    } catch {
      git.close()
      throw NativeDarwinGitWorktreeObservationError.unsupportedGitLayout
    }
  }

  private func readHead(from directory: SecureDirectory) throws -> NativeAgentGitHead {
    let value = try readFile(directory: directory, name: "HEAD", maximum: Self.maximumHeadBytes)
    guard value.hasSuffix("\n"), !value.dropLast().contains("\n") else {
      throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
    }
    let line = String(value.dropLast())
    if line.hasPrefix("ref: refs/heads/") {
      return .branch(String(line.dropFirst("ref: refs/heads/".count)))
    }
    return .detached(line)
  }

  private func currentAuthority(
    gitDirectory: SecureDirectory,
    commonDirectory: SecureDirectory
  ) throws -> NativeAgentWorktreeAuthoritySnapshot {
    let configuration = try readConfiguration(from: commonDirectory)
    let layout = GitLayout(
      layout: gitDirectory.path == commonDirectory.path ? .embedded : .linked,
      gitDirectory: gitDirectory,
      commonDirectory: commonDirectory)
    try rejectUnsupportedAuthorityFeatures(layout)
    let head = try readHeadAuthority(
      gitDirectory: gitDirectory,
      commonDirectory: commonDirectory,
      objectFormat: configuration.objectFormat)
    return NativeAgentWorktreeAuthoritySnapshot(
      objectFormat: configuration.objectFormat,
      head: head.head,
      objectID: head.objectID,
      treeID: head.treeID,
      remotes: configuration.remotes)
  }

  private func readHeadAuthority(
    gitDirectory: SecureDirectory,
    commonDirectory: SecureDirectory,
    objectFormat: NativeAgentGitObjectFormat
  ) throws -> GitHeadAuthority {
    let head = try readHead(from: gitDirectory)
    let objectID: String?
    switch head {
    case .branch(let branch):
      objectID = try resolveReference(
        "refs/heads/" + branch,
        commonDirectory: commonDirectory,
        objectFormat: objectFormat,
        visited: [],
        depth: 0)
    case .detached(let value):
      guard Self.validObjectID(value, format: objectFormat) else {
        throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
      }
      objectID = value
    }
    guard let objectID else {
      return GitHeadAuthority(head: head, objectID: nil, treeID: nil)
    }
    let treeID = try readCommitTreeID(
      objectID: objectID,
      commonDirectory: commonDirectory,
      objectFormat: objectFormat)
    return GitHeadAuthority(head: head, objectID: objectID, treeID: treeID)
  }

  private func resolveReference(
    _ name: String,
    commonDirectory: SecureDirectory,
    objectFormat: NativeAgentGitObjectFormat,
    visited: Set<String>,
    depth: Int
  ) throws -> String? {
    guard depth < Self.maximumReferenceDepth, Self.validReferenceName(name),
      !visited.contains(name)
    else { throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata }
    var visited = visited
    visited.insert(name)
    if let loose = try readOptionalFile(
      path: commonDirectory.path + "/" + name,
      expectedUserID: commonDirectory.identity.ownerUserID,
      maximum: Self.maximumHeadBytes)
    {
      guard loose.hasSuffix("\n"), !loose.dropLast().contains("\n") else {
        throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
      }
      let value = String(loose.dropLast())
      if value.hasPrefix("ref: ") {
        // Files-backend symbolic branch refs add another mutable authority
        // chain. v2 permits a symbolic HEAD only and rejects symbolic branch
        // refs rather than silently following them.
        throw NativeDarwinGitWorktreeObservationError.unsupportedGitLayout
      }
      guard Self.validObjectID(value, format: objectFormat) else {
        throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
      }
      return value
    }
    return try readPackedReference(
      name,
      commonDirectory: commonDirectory,
      objectFormat: objectFormat)
  }

  private func readPackedReference(
    _ target: String,
    commonDirectory: SecureDirectory,
    objectFormat: NativeAgentGitObjectFormat
  ) throws -> String? {
    guard
      let packed = try readOptionalFile(
        path: commonDirectory.path + "/packed-refs",
        expectedUserID: commonDirectory.identity.ownerUserID,
        maximum: Self.maximumPackedRefsBytes)
    else { return nil }
    guard packed.hasSuffix("\n") else {
      throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
    }
    var result: String?
    var previousRecord: String?
    var seen = Set<String>()
    var advertisedSorted = false
    var previousSortedName: String?
    var recordCount = 0
    for rawLine in packed.split(separator: "\n", omittingEmptySubsequences: false).dropLast() {
      let line = String(rawLine)
      guard line.utf8.count <= 2_100 else {
        throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
      }
      if line.isEmpty { continue }
      if line.hasPrefix("#") {
        if line.hasPrefix("# pack-refs with:") {
          advertisedSorted = line.split(separator: " ").contains("sorted")
        }
        continue
      }
      if line.hasPrefix("^") {
        guard previousRecord != nil,
          previousRecord?.hasPrefix("refs/tags/") == true,
          Self.validObjectID(String(line.dropFirst()), format: objectFormat)
        else { throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata }
        continue
      }
      recordCount += 1
      guard recordCount <= 100_000,
        let separator = line.firstIndex(of: " "),
        line[line.index(after: separator)...].firstIndex(of: " ") == nil
      else { throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata }
      let objectID = String(line[..<separator])
      let name = String(line[line.index(after: separator)...])
      guard Self.validObjectID(objectID, format: objectFormat), Self.validReferenceName(name)
      else { throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata }
      guard seen.insert(name).inserted else {
        throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
      }
      guard !name.hasPrefix("refs/replace/") else {
        throw NativeDarwinGitWorktreeObservationError.unsupportedGitLayout
      }
      if advertisedSorted, let previousSortedName, name <= previousSortedName {
        throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
      }
      previousSortedName = name
      previousRecord = name
      if name == target {
        guard result == nil else {
          throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
        }
        result = objectID
      }
    }
    return result
  }

  private func readCommitTreeID(
    objectID: String,
    commonDirectory: SecureDirectory,
    objectFormat: NativeAgentGitObjectFormat
  ) throws -> String {
    do {
      let store = try NativeGitObjectStore(
        commonGitDirectoryPath: commonDirectory.path,
        expectedUserID: commonDirectory.identity.ownerUserID)
      let treeID = try store.readCommitTreeOID(oid: objectID)
      guard Self.validObjectID(treeID, format: objectFormat) else {
        throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
      }
      _ = try store.readCommitRootTree(oid: objectID)
      return treeID
    } catch let error as NativeDarwinGitWorktreeObservationError {
      throw error
    } catch {
      throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
    }
  }

  private func rejectUnsupportedAuthorityFeatures(_ metadata: GitLayout) throws {
    let candidates = [
      metadata.commonDirectory.path + "/objects/info/alternates",
      metadata.commonDirectory.path + "/objects/info/http-alternates",
      metadata.commonDirectory.path + "/info/grafts",
      metadata.commonDirectory.path + "/refs/replace",
      metadata.commonDirectory.path + "/shallow",
      metadata.commonDirectory.path + "/config.worktree",
      metadata.gitDirectory.path + "/shallow",
      metadata.gitDirectory.path + "/config.worktree",
    ]
    for path in Set(candidates) where try Self.filesystemEntryExists(path) {
      throw NativeDarwinGitWorktreeObservationError.unsupportedGitLayout
    }
  }

  private func readOptionalFile(
    path: String,
    expectedUserID: UInt32,
    maximum: Int
  ) throws -> String? {
    var pathInformation = stat()
    if lstat(path, &pathInformation) != 0 {
      if errno == ENOENT { return nil }
      throw NativeDarwinGitWorktreeObservationError.unsafeFilesystemObject
    }
    guard let slash = path.lastIndex(of: "/"), slash != path.startIndex else {
      throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
    }
    let parentPath = String(path[..<slash])
    let name = String(path[path.index(after: slash)...])
    let parent = try SecureDirectory.open(parentPath, expectedUserID: expectedUserID)
    defer { parent.close() }
    var descriptorInformation = stat()
    if fstatat(parent.descriptor, name, &descriptorInformation, AT_SYMLINK_NOFOLLOW) != 0 {
      throw NativeDarwinGitWorktreeObservationError.unsafeFilesystemObject
    }
    guard pathInformation.st_dev == descriptorInformation.st_dev,
      pathInformation.st_ino == descriptorInformation.st_ino,
      pathInformation.st_gen == descriptorInformation.st_gen
    else { throw NativeDarwinGitWorktreeObservationError.observationChanged }
    return try readFile(directory: parent, name: name, maximum: maximum)
  }

  private static func filesystemEntryExists(_ path: String) throws -> Bool {
    var information = stat()
    if lstat(path, &information) == 0 { return true }
    if errno == ENOENT { return false }
    throw NativeDarwinGitWorktreeObservationError.unsafeFilesystemObject
  }

  private static func validObjectID(
    _ value: String,
    format: NativeAgentGitObjectFormat
  ) -> Bool {
    value.utf8.count == format.objectIDHexLength
      && value.range(of: "^[0-9a-f]+$", options: .regularExpression) != nil
  }

  private static func validReferenceName(_ value: String) -> Bool {
    guard value.hasPrefix("refs/"), value.utf8.count <= 1_024,
      !value.contains(".."), !value.contains("@{")
    else { return false }
    return value.split(separator: "/", omittingEmptySubsequences: false).allSatisfy {
      !$0.isEmpty && !$0.hasPrefix(".") && !$0.hasSuffix(".") && !$0.hasSuffix(".lock")
        && !$0.unicodeScalars.contains(where: {
          $0.value < 0x20 || $0.value == 0x7f || " ~^:?*[\\".unicodeScalars.contains($0)
        })
    }
  }

  private func readConfiguration(from directory: SecureDirectory) throws -> GitConfiguration {
    let config = try readFile(
      directory: directory, name: "config", maximum: Self.maximumConfigBytes)
    var section = GitConfigSection.other
    var urls: [String: String] = [:]
    var repositoryFormatVersion: Int?
    var objectFormat: NativeAgentGitObjectFormat?
    var compatibilityObjectFormat: NativeAgentGitObjectFormat?
    var referenceStorage: String?
    var sawExtension = false
    let remotePattern = #"^\[[Rr][Ee][Mm][Oo][Tt][Ee] \"([A-Za-z0-9][A-Za-z0-9._-]{0,127})\"\]$"#
    for rawLine in config.split(separator: "\n", omittingEmptySubsequences: false) {
      let line = rawLine.trimmingCharacters(in: .whitespaces)
      if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }
      let lower = line.lowercased()
      if line.hasPrefix("[") {
        guard lower != "[include]", !lower.hasPrefix("[includeif ") else {
          throw NativeDarwinGitWorktreeObservationError.unsupportedGitLayout
        }
        if let remote = Self.firstCapture(in: line, pattern: remotePattern) {
          section = .remote(remote)
        } else if lower == "[core]" {
          section = .core
        } else if lower == "[extensions]" {
          section = .extensions
        } else {
          section = .other
        }
        if lower.hasPrefix("[remote "), case .other = section {
          throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
        }
        continue
      }
      guard !lower.hasPrefix("include"), !line.hasSuffix("\\") else {
        throw NativeDarwinGitWorktreeObservationError.unsupportedGitLayout
      }
      let pieces = line.split(separator: "=", maxSplits: 1).map {
        $0.trimmingCharacters(in: .whitespaces)
      }
      guard pieces.count == 2 else {
        throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
      }
      let key = pieces[0].lowercased()
      let value = pieces[1]
      switch section {
      case .remote(let name) where key == "url":
        guard urls[name] == nil else {
          throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
        }
        urls[name] = value
      case .remote where key == "pushurl":
        // Push-only authority must not be silently omitted from the digest.
        throw NativeDarwinGitWorktreeObservationError.unsupportedGitLayout
      case .remote where key == "promisor" || key == "partialclonefilter":
        throw NativeDarwinGitWorktreeObservationError.unsupportedGitLayout
      case .core where key == "repositoryformatversion":
        guard repositoryFormatVersion == nil, let parsed = Int(value), parsed == 0 || parsed == 1
        else { throw NativeDarwinGitWorktreeObservationError.unsupportedGitLayout }
        repositoryFormatVersion = parsed
      case .core where key == "bare":
        guard value.lowercased() == "false" else {
          throw NativeDarwinGitWorktreeObservationError.unsupportedGitLayout
        }
      case .core where key == "worktree" || key == "alternaterefscommand":
        throw NativeDarwinGitWorktreeObservationError.unsupportedGitLayout
      case .extensions where key == "objectformat":
        guard objectFormat == nil,
          let parsed = NativeAgentGitObjectFormat(rawValue: value.lowercased())
        else { throw NativeDarwinGitWorktreeObservationError.unsupportedGitLayout }
        objectFormat = parsed
        sawExtension = true
      case .extensions where key == "compatobjectformat":
        guard compatibilityObjectFormat == nil,
          let parsed = NativeAgentGitObjectFormat(rawValue: value.lowercased())
        else { throw NativeDarwinGitWorktreeObservationError.unsupportedGitLayout }
        compatibilityObjectFormat = parsed
        sawExtension = true
      case .extensions where key == "refstorage":
        guard referenceStorage == nil, value.lowercased() == "files" else {
          throw NativeDarwinGitWorktreeObservationError.unsupportedGitLayout
        }
        referenceStorage = "files"
        sawExtension = true
      case .extensions:
        // partialClone, worktreeConfig, reftable, compatObjectFormat, and
        // every future extension require a separately reviewed observer.
        throw NativeDarwinGitWorktreeObservationError.unsupportedGitLayout
      default:
        break
      }
    }
    do {
      let format = objectFormat ?? .sha1
      guard !sawExtension || repositoryFormatVersion == 1,
        format == .sha1 || repositoryFormatVersion == 1,
        compatibilityObjectFormat == nil
          || (format == .sha256 && compatibilityObjectFormat == .sha1),
        referenceStorage == nil || referenceStorage == "files"
      else { throw NativeDarwinGitWorktreeObservationError.unsupportedGitLayout }
      return GitConfiguration(
        objectFormat: format,
        remotes: try urls.keys.sorted().map {
          try NativeAgentGitRemote(name: $0, url: urls[$0]!)
        })
    } catch {
      if let error = error as? NativeDarwinGitWorktreeObservationError { throw error }
      throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
    }
  }

  private func readFile(directory: SecureDirectory, name: String, maximum: Int) throws -> String {
    guard !name.contains("/") else {
      throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
    }
    let descriptor = openat(directory.descriptor, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else {
      throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
    }
    defer { _ = close(descriptor) }
    var before = stat()
    guard fstat(descriptor, &before) == 0, before.st_mode & S_IFMT == S_IFREG,
      before.st_nlink == 1, before.st_uid == directory.identity.ownerUserID,
      before.st_mode & 0o022 == 0, before.st_size >= 0, before.st_size <= maximum
    else { throw NativeDarwinGitWorktreeObservationError.unsafeFilesystemObject }
    var data = Data()
    var buffer = [UInt8](repeating: 0, count: 4_096)
    while true {
      let count = Darwin.read(descriptor, &buffer, buffer.count)
      guard count >= 0 else { throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata }
      if count == 0 { break }
      guard data.count + count <= maximum else {
        throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
      }
      data.append(contentsOf: buffer[..<count])
    }
    var after = stat()
    guard fstat(descriptor, &after) == 0, Self.sameFile(before, after),
      data.count == Int(after.st_size), !data.contains(0),
      let string = String(data: data, encoding: .utf8)
    else { throw NativeDarwinGitWorktreeObservationError.observationChanged }
    return string
  }

  private static func sameFile(_ lhs: stat, _ rhs: stat) -> Bool {
    lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino && lhs.st_gen == rhs.st_gen
      && lhs.st_size == rhs.st_size && lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec
      && lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec
      && lhs.st_ctimespec.tv_sec == rhs.st_ctimespec.tv_sec
      && lhs.st_ctimespec.tv_nsec == rhs.st_ctimespec.tv_nsec
  }

  private static func canonicalAbsolutePath(_ path: String) throws -> String {
    guard path.hasPrefix("/"), path != "/", !path.hasSuffix("/"), path.utf8.count < MAXPATHLEN,
      !path.split(separator: "/", omittingEmptySubsequences: false).dropFirst().contains(where: {
        $0.isEmpty || $0 == "." || $0 == ".."
      })
    else { throw NativeDarwinGitWorktreeObservationError.unsafeFilesystemObject }
    return path
  }

  private static func resolve(_ path: String, relativeTo base: String) throws -> String {
    guard !path.isEmpty, !path.contains("\0") else {
      throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
    }
    var components = path.hasPrefix("/") ? [] : base.split(separator: "/").map(String.init)
    for component in path.split(separator: "/", omittingEmptySubsequences: false) {
      if component.isEmpty || component == "." { continue }
      if component == ".." {
        guard !components.isEmpty else {
          throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
        }
        components.removeLast()
      } else {
        components.append(String(component))
      }
    }
    return try canonicalAbsolutePath("/" + components.joined(separator: "/"))
  }

  private static func parent(of path: String) -> String {
    guard let slash = path.lastIndex(of: "/"), slash != path.startIndex else { return "/" }
    return String(path[..<slash])
  }

  private static func firstCapture(in value: String, pattern: String) -> String? {
    guard let regex = try? NSRegularExpression(pattern: pattern),
      let match = regex.firstMatch(in: value, range: NSRange(value.startIndex..., in: value)),
      match.numberOfRanges == 2, let range = Range(match.range(at: 1), in: value)
    else { return nil }
    return String(value[range])
  }
}

private struct Repository {
  let path: String
  let directory: SecureDirectory
}

private struct GitLayout {
  let layout: NativeAgentGitDirectoryLayout
  let gitDirectory: SecureDirectory
  let commonDirectory: SecureDirectory
}

private struct GitHeadAuthority {
  let head: NativeAgentGitHead
  let objectID: String?
  let treeID: String?
}

private struct GitConfiguration {
  let objectFormat: NativeAgentGitObjectFormat
  let remotes: [NativeAgentGitRemote]
}

private enum GitConfigSection {
  case core
  case extensions
  case remote(String)
  case other
}

private final class SecureDirectory: @unchecked Sendable {
  let path: String
  let descriptor: Int32
  let identity: NativeAgentWorktreeDirectoryIdentity
  private var isClosed = false

  private init(path: String, descriptor: Int32, identity: NativeAgentWorktreeDirectoryIdentity) {
    self.path = path
    self.descriptor = descriptor
    self.identity = identity
  }

  func close() {
    if !isClosed {
      _ = Darwin.close(descriptor)
      isClosed = true
    }
  }

  static func open(_ path: String, expectedUserID: UInt32) throws -> SecureDirectory {
    let components = path.split(separator: "/").map(String.init)
    guard !components.isEmpty else {
      throw NativeDarwinGitWorktreeObservationError.unsafeFilesystemObject
    }
    var descriptor = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else {
      throw NativeDarwinGitWorktreeObservationError.unsafeFilesystemObject
    }
    for component in components {
      let next = openat(descriptor, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
      _ = Darwin.close(descriptor)
      guard next >= 0 else {
        throw NativeDarwinGitWorktreeObservationError.unsafeFilesystemObject
      }
      descriptor = next
    }
    do {
      var info = stat()
      guard fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
        info.st_dev > 0, info.st_ino > 0, info.st_uid == expectedUserID,
        info.st_mode & 0o022 == 0
      else { throw NativeDarwinGitWorktreeObservationError.unsafeFilesystemObject }
      let identity = try NativeAgentWorktreeDirectoryIdentity(
        device: UInt64(info.st_dev), inode: UInt64(info.st_ino), generation: info.st_gen,
        ownerUserID: UInt32(info.st_uid), permissions: UInt16(info.st_mode & 0o777))
      return SecureDirectory(path: path, descriptor: descriptor, identity: identity)
    } catch {
      _ = Darwin.close(descriptor)
      throw error
    }
  }
}
