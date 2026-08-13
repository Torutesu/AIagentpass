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
    let head = try readHead(from: metadata.gitDirectory)
    let remotes = try readRemotes(from: metadata.commonDirectory)
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
        head: head,
        remotes: remotes
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
      try readHead(from: git) == binding.head,
      try readRemotes(from: common) == binding.remotes
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
      return GitLayout(layout: .linked, gitDirectory: git, commonDirectory: common)
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

  private func readRemotes(from directory: SecureDirectory) throws -> [NativeAgentGitRemote] {
    let config = try readFile(
      directory: directory, name: "config", maximum: Self.maximumConfigBytes)
    var currentRemote: String?
    var URLs: [String: String] = [:]
    let remotePattern = #"^\[[Rr][Ee][Mm][Oo][Tt][Ee] \"([A-Za-z0-9][A-Za-z0-9._-]{0,127})\"\]$"#
    for rawLine in config.split(separator: "\n", omittingEmptySubsequences: false) {
      let line = rawLine.trimmingCharacters(in: .whitespaces)
      if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }
      let lower = line.lowercased()
      if line.hasPrefix("[") {
        guard lower != "[include]", !lower.hasPrefix("[includeif ") else {
          throw NativeDarwinGitWorktreeObservationError.unsupportedGitLayout
        }
        currentRemote = Self.firstCapture(in: line, pattern: remotePattern)
        if lower.hasPrefix("[remote "), currentRemote == nil {
          throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
        }
        continue
      }
      guard !lower.hasPrefix("include"), !line.hasSuffix("\\") else {
        throw NativeDarwinGitWorktreeObservationError.unsupportedGitLayout
      }
      guard let name = currentRemote else { continue }
      let pieces = line.split(separator: "=", maxSplits: 1).map {
        $0.trimmingCharacters(in: .whitespaces)
      }
      guard pieces.count == 2 else {
        throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
      }
      if pieces[0].lowercased() == "url" {
        guard URLs[name] == nil else {
          throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
        }
        URLs[name] = pieces[1]
      } else if pieces[0].lowercased() == "pushurl" {
        // Push-only authority must not be silently omitted from the digest.
        throw NativeDarwinGitWorktreeObservationError.unsupportedGitLayout
      }
    }
    do {
      return try URLs.keys.sorted().map { try NativeAgentGitRemote(name: $0, url: URLs[$0]!) }
    } catch {
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
