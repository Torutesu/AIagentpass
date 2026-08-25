import Darwin
import Foundation
import Testing

@testable import AgentPassNativeCore

private final class WorktreeProcessAdapter: NativeDarwinWorktreeProcessAdapter, @unchecked Sendable
{
  var processes: [NativeDarwinWorktreeProcessSnapshot]
  var directories: [NativeDarwinCurrentDirectorySnapshot]

  init(
    processes: [NativeDarwinWorktreeProcessSnapshot],
    directories: [NativeDarwinCurrentDirectorySnapshot]
  ) {
    self.processes = processes
    self.directories = directories
  }

  func process(pid: Int32) throws -> NativeDarwinWorktreeProcessSnapshot {
    guard !processes.isEmpty else {
      throw NativeDarwinGitWorktreeObservationError.processUnavailable
    }
    return processes.removeFirst()
  }

  func currentDirectory(pid: Int32) throws -> NativeDarwinCurrentDirectorySnapshot {
    guard !directories.isEmpty else {
      throw NativeDarwinGitWorktreeObservationError.currentDirectoryUnavailable
    }
    return directories.removeFirst()
  }
}

private func temporaryGitRepository() throws -> URL {
  let root = FileManager.default.temporaryDirectory
    .appendingPathComponent("agentpass-worktree-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
  try runGit(["init", "--initial-branch=main", root.path], currentDirectory: nil)
  try runGit(["remote", "add", "origin", "git@github.com:org/project.git"], currentDirectory: root)
  let nested = root.appendingPathComponent("Sources/Nested", isDirectory: true)
  try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
  guard let resolved = realpath(root.path, nil) else {
    throw NativeDarwinGitWorktreeObservationError.unsafeFilesystemObject
  }
  defer { free(resolved) }
  return URL(fileURLWithPath: String(cString: resolved), isDirectory: true)
}

private func runGit(_ arguments: [String], currentDirectory: URL?) throws {
  let process = Process()
  process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
  process.arguments = arguments
  process.currentDirectoryURL = currentDirectory
  process.standardOutput = FileHandle.nullDevice
  process.standardError = FileHandle.nullDevice
  try process.run()
  process.waitUntilExit()
  guard process.terminationStatus == 0 else {
    throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata
  }
}

private func gitOutput(_ arguments: [String], currentDirectory: URL) throws -> String {
  let process = Process()
  let output = Pipe()
  process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
  process.arguments = arguments
  process.currentDirectoryURL = currentDirectory
  process.standardOutput = output
  process.standardError = FileHandle.nullDevice
  try process.run()
  process.waitUntilExit()
  guard process.terminationStatus == 0,
    let value = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)
  else { throw NativeDarwinGitWorktreeObservationError.malformedGitMetadata }
  return value.trimmingCharacters(in: .whitespacesAndNewlines)
}

private func cwdSnapshot(_ path: String) throws -> NativeDarwinCurrentDirectorySnapshot {
  var info = stat()
  guard lstat(path, &info) == 0 else {
    throw NativeDarwinGitWorktreeObservationError.currentDirectoryUnavailable
  }
  return .init(
    path: path,
    device: UInt64(info.st_dev),
    inode: UInt64(info.st_ino),
    generation: info.st_gen
  )
}

@Test func filesystemObserverDerivesStableBindingFromRealGitRepository() throws {
  let repository = try temporaryGitRepository()
  defer { try? FileManager.default.removeItem(at: repository) }
  let nested = repository.appendingPathComponent("Sources/Nested").path
  let observer = NativeGitFilesystemObserver()
  let first = try observer.observe(currentDirectory: nested, expectedUserID: UInt32(geteuid()))
  let second = try observer.observe(currentDirectory: nested, expectedUserID: UInt32(geteuid()))

  #expect(first == second)
  #expect(first.repositoryPath == repository.path)
  #expect(first.branch == "main")
  #expect(first.binding.objectFormat == .sha1)
  #expect(first.binding.headObjectID == nil)
  #expect(first.binding.headTreeID == nil)
  #expect(
    first.binding.remotes == [
      try NativeAgentGitRemote(name: "origin", url: "git@github.com:org/project.git")
    ])
}

@Test func filesystemObserverBindsResolvedCommitAndTreeAndPackedReference() throws {
  let repository = try temporaryGitRepository()
  defer { try? FileManager.default.removeItem(at: repository) }
  try runGit(
    [
      "-c", "user.name=AgentPass Test", "-c", "user.email=test@agentpass.local", "commit",
      "--allow-empty", "-m", "initial",
    ],
    currentDirectory: repository)
  let expectedCommit = try gitOutput(["rev-parse", "HEAD"], currentDirectory: repository)
  let expectedTree = try gitOutput(["rev-parse", "HEAD^{tree}"], currentDirectory: repository)
  let loose = try NativeGitFilesystemObserver().observe(
    currentDirectory: repository.path, expectedUserID: UInt32(geteuid()))
  #expect(loose.binding.headObjectID == expectedCommit)
  #expect(loose.binding.headTreeID == expectedTree)

  try runGit(["pack-refs", "--all"], currentDirectory: repository)
  let packed = try NativeGitFilesystemObserver().observe(
    currentDirectory: repository.path, expectedUserID: UInt32(geteuid()))
  #expect(packed.binding.headObjectID == expectedCommit)
  #expect(packed.binding.headTreeID == expectedTree)
  #expect(packed.binding.digest == loose.binding.digest)
}

@Test func filesystemObserverSupportsSHA256RepositoryAuthority() throws {
  let repository = try temporaryGitRepository()
  defer { try? FileManager.default.removeItem(at: repository) }
  try FileManager.default.removeItem(at: repository)
  try runGit(
    ["init", "--object-format=sha256", "--initial-branch=main", repository.path],
    currentDirectory: nil)
  try runGit(
    [
      "-c", "user.name=AgentPass Test", "-c", "user.email=test@agentpass.local", "commit",
      "--allow-empty", "-m", "initial",
    ],
    currentDirectory: repository)
  let observation = try NativeGitFilesystemObserver().observe(
    currentDirectory: repository.path, expectedUserID: UInt32(geteuid()))
  #expect(observation.binding.objectFormat == .sha256)
  #expect(observation.binding.headObjectID?.count == 64)
  #expect(observation.binding.headTreeID?.count == 64)
}

@Test func filesystemObserverSupportsRealLinkedWorktree() throws {
  let repository = try temporaryGitRepository()
  let linked = repository.deletingLastPathComponent()
    .appendingPathComponent("agentpass-linked-\(UUID().uuidString)", isDirectory: true)
  defer {
    try? FileManager.default.removeItem(at: linked)
    try? FileManager.default.removeItem(at: repository)
  }
  try runGit(
    [
      "-c", "user.name=AgentPass Test", "-c", "user.email=test@agentpass.local", "commit",
      "--allow-empty", "-m", "initial",
    ],
    currentDirectory: repository)
  try runGit(
    ["worktree", "add", "-b", "feature/linked", linked.path], currentDirectory: repository)
  guard let resolved = realpath(linked.path, nil) else {
    throw NativeDarwinGitWorktreeObservationError.unsafeFilesystemObject
  }
  defer { free(resolved) }

  let observation = try NativeGitFilesystemObserver().observe(
    currentDirectory: String(cString: resolved), expectedUserID: UInt32(geteuid()))
  #expect(observation.binding.layout == .linked)
  #expect(observation.branch == "feature/linked")
  #expect(
    observation.binding.gitDirectoryPath.hasPrefix(
      observation.binding.commonDirectoryPath + "/worktrees/"))
}

@Test func filesystemObserverRejectsSymlinkedGitDirectory() throws {
  let repository = try temporaryGitRepository()
  defer { try? FileManager.default.removeItem(at: repository) }
  let original = repository.appendingPathComponent("metadata")
  try FileManager.default.moveItem(at: repository.appendingPathComponent(".git"), to: original)
  try FileManager.default.createSymbolicLink(
    at: repository.appendingPathComponent(".git"), withDestinationURL: original)
  #expect(throws: NativeDarwinGitWorktreeObservationError.unsafeFilesystemObject) {
    _ = try NativeGitFilesystemObserver().observe(
      currentDirectory: repository.path, expectedUserID: UInt32(geteuid()))
  }
}

@Test func filesystemObserverRejectsHardLinkedGitMetadata() throws {
  let repository = try temporaryGitRepository()
  defer { try? FileManager.default.removeItem(at: repository) }
  let head = repository.appendingPathComponent(".git/HEAD").path
  let alias = repository.appendingPathComponent(".git/HEAD.alias").path
  guard link(head, alias) == 0 else {
    throw NativeDarwinGitWorktreeObservationError.unsafeFilesystemObject
  }
  #expect(throws: NativeDarwinGitWorktreeObservationError.unsafeFilesystemObject) {
    _ = try NativeGitFilesystemObserver().observe(
      currentDirectory: repository.path, expectedUserID: UInt32(geteuid()))
  }
}

@Test func processObserverRejectsPIDVersionAndCWDDrift() throws {
  let repository = try temporaryGitRepository()
  defer { try? FileManager.default.removeItem(at: repository) }
  let directory = try cwdSnapshot(repository.path)
  let process = NativeDarwinWorktreeProcessSnapshot(pid: 42, uid: UInt32(geteuid()), pidVersion: 7)

  let processDrift = NativeDarwinGitWorktreeObserver(
    processAdapter: WorktreeProcessAdapter(
      processes: [process, .init(pid: 42, uid: UInt32(geteuid()), pidVersion: 8)],
      directories: [directory, directory]
    ))
  #expect(throws: NativeDarwinGitWorktreeObservationError.processChanged) {
    _ = try processDrift.observe(pid: 42, expectedUserID: UInt32(geteuid()))
  }

  let changedDirectory = NativeDarwinCurrentDirectorySnapshot(
    path: directory.path,
    device: directory.device,
    inode: directory.inode + 1,
    generation: directory.generation
  )
  let cwdDrift = NativeDarwinGitWorktreeObserver(
    processAdapter: WorktreeProcessAdapter(
      processes: [process, process], directories: [directory, changedDirectory]
    ))
  #expect(throws: NativeDarwinGitWorktreeObservationError.currentDirectoryChanged) {
    _ = try cwdDrift.observe(pid: 42, expectedUserID: UInt32(geteuid()))
  }
}

@Test func filesystemObserverRejectsConfigIncludeAndDuplicateRemoteURL() throws {
  let repository = try temporaryGitRepository()
  defer { try? FileManager.default.removeItem(at: repository) }
  let config = repository.appendingPathComponent(".git/config")
  try "[include]\n\tpath = /tmp/other\n".write(to: config, atomically: true, encoding: .utf8)
  #expect(throws: NativeDarwinGitWorktreeObservationError.unsupportedGitLayout) {
    _ = try NativeGitFilesystemObserver().observe(
      currentDirectory: repository.path, expectedUserID: UInt32(geteuid()))
  }

  try "[remote \"origin\"]\n\turl = one\n\turl = two\n".write(
    to: config, atomically: true, encoding: .utf8)
  #expect(throws: NativeDarwinGitWorktreeObservationError.malformedGitMetadata) {
    _ = try NativeGitFilesystemObserver().observe(
      currentDirectory: repository.path, expectedUserID: UInt32(geteuid()))
  }

  try "[remote \"origin\"]\n\turl = fetch\n\tpushurl = push\n".write(
    to: config, atomically: true, encoding: .utf8)
  #expect(throws: NativeDarwinGitWorktreeObservationError.unsupportedGitLayout) {
    _ = try NativeGitFilesystemObserver().observe(
      currentDirectory: repository.path, expectedUserID: UInt32(geteuid()))
  }
}

@Test func filesystemObserverDetectsBranchAndRemoteDriftOnRevalidation() throws {
  let repository = try temporaryGitRepository()
  defer { try? FileManager.default.removeItem(at: repository) }
  let observer = NativeGitFilesystemObserver()
  let binding = try observer.observe(
    currentDirectory: repository.path, expectedUserID: UInt32(geteuid())
  ).binding

  try "ref: refs/heads/other\n".write(
    to: repository.appendingPathComponent(".git/HEAD"), atomically: true, encoding: .utf8)
  #expect(throws: NativeDarwinGitWorktreeObservationError.observationChanged) {
    try observer.revalidate(binding)
  }

  try "ref: refs/heads/main\n".write(
    to: repository.appendingPathComponent(".git/HEAD"), atomically: true, encoding: .utf8)
  try "[remote \"origin\"]\n\turl = git@github.com:org/other.git\n".write(
    to: repository.appendingPathComponent(".git/config"), atomically: true, encoding: .utf8)
  #expect(throws: NativeDarwinGitWorktreeObservationError.observationChanged) {
    try observer.revalidate(binding)
  }
}

@Test func filesystemObserverRejectsAlternativeAndMutableGitAuthorityFeatures() throws {
  let repository = try temporaryGitRepository()
  defer { try? FileManager.default.removeItem(at: repository) }
  try runGit(
    [
      "-c", "user.name=AgentPass Test", "-c", "user.email=test@agentpass.local", "commit",
      "--allow-empty", "-m", "initial",
    ], currentDirectory: repository)
  let forbidden = [
    ".git/objects/info/alternates",
    ".git/objects/info/http-alternates",
    ".git/info/grafts",
    ".git/shallow",
    ".git/config.worktree",
  ]
  for relative in forbidden {
    let target = repository.appendingPathComponent(relative)
    try "forbidden\n".write(to: target, atomically: true, encoding: .utf8)
    #expect(throws: NativeDarwinGitWorktreeObservationError.unsupportedGitLayout) {
      _ = try NativeGitFilesystemObserver().observe(
        currentDirectory: repository.path, expectedUserID: UInt32(geteuid()))
    }
    try FileManager.default.removeItem(at: target)
  }
}

@Test func filesystemObserverRejectsMalformedPackedRefsAndUnsupportedExtensions() throws {
  let repository = try temporaryGitRepository()
  defer { try? FileManager.default.removeItem(at: repository) }
  try runGit(
    [
      "-c", "user.name=AgentPass Test", "-c", "user.email=test@agentpass.local", "commit",
      "--allow-empty", "-m", "initial",
    ], currentDirectory: repository)
  let head = try gitOutput(["rev-parse", "HEAD"], currentDirectory: repository)
  try FileManager.default.removeItem(at: repository.appendingPathComponent(".git/refs/heads/main"))
  try "\(head) refs/heads/main\n\(head) refs/heads/main\n".write(
    to: repository.appendingPathComponent(".git/packed-refs"), atomically: true, encoding: .utf8)
  #expect(throws: NativeDarwinGitWorktreeObservationError.malformedGitMetadata) {
    _ = try NativeGitFilesystemObserver().observe(
      currentDirectory: repository.path, expectedUserID: UInt32(geteuid()))
  }

  try
    "[core]\n\trepositoryformatversion = 1\n\tbare = false\n[extensions]\n\tworktreeConfig = true\n"
    .write(
      to: repository.appendingPathComponent(".git/config"), atomically: true, encoding: .utf8)
  #expect(throws: NativeDarwinGitWorktreeObservationError.unsupportedGitLayout) {
    _ = try NativeGitFilesystemObserver().observe(
      currentDirectory: repository.path, expectedUserID: UInt32(geteuid()))
  }
}

@Test func filesystemObserverBindsNearestRepositoryAndRejectsBareRepository() throws {
  let repository = try temporaryGitRepository()
  defer { try? FileManager.default.removeItem(at: repository) }
  let root = try NativeGitFilesystemObserver().observe(
    currentDirectory: repository.path, expectedUserID: UInt32(geteuid()))
  let nested = repository.appendingPathComponent("Sources/Nested")
  try runGit(["init", "--initial-branch=main", nested.path], currentDirectory: nil)
  let nestedObservation = try NativeGitFilesystemObserver().observe(
    currentDirectory: nested.path, expectedUserID: UInt32(geteuid()))
  #expect(nestedObservation.repositoryPath == nested.path)
  #expect(nestedObservation.binding.digest != root.binding.digest)

  let bare = repository.deletingLastPathComponent()
    .appendingPathComponent("agentpass-bare-\(UUID().uuidString)", isDirectory: true)
  defer { try? FileManager.default.removeItem(at: bare) }
  try runGit(["init", "--bare", bare.path], currentDirectory: nil)
  guard let resolved = realpath(bare.path, nil) else {
    throw NativeDarwinGitWorktreeObservationError.unsafeFilesystemObject
  }
  defer { free(resolved) }
  #expect(throws: NativeDarwinGitWorktreeObservationError.self) {
    _ = try NativeGitFilesystemObserver().observe(
      currentDirectory: String(cString: resolved), expectedUserID: UInt32(geteuid()))
  }
}

@Test func filesystemObserverDetectsRepositoryPathSwap() throws {
  let repository = try temporaryGitRepository()
  let moved = repository.deletingLastPathComponent()
    .appendingPathComponent("agentpass-moved-\(UUID().uuidString)", isDirectory: true)
  defer {
    try? FileManager.default.removeItem(at: repository)
    try? FileManager.default.removeItem(at: moved)
  }
  let observer = NativeGitFilesystemObserver()
  let binding = try observer.observe(
    currentDirectory: repository.path, expectedUserID: UInt32(geteuid())
  ).binding
  try FileManager.default.moveItem(at: repository, to: moved)
  try runGit(["init", "--initial-branch=main", repository.path], currentDirectory: nil)
  #expect(throws: NativeDarwinGitWorktreeObservationError.observationChanged) {
    try observer.revalidate(binding)
  }
}

@Test func processObserverRejectsProcessDeathDuringObservation() throws {
  let repository = try temporaryGitRepository()
  defer { try? FileManager.default.removeItem(at: repository) }
  let directory = try cwdSnapshot(repository.path)
  let process = NativeDarwinWorktreeProcessSnapshot(
    pid: 42, uid: UInt32(geteuid()), pidVersion: 7)
  let observer = NativeDarwinGitWorktreeObserver(
    processAdapter: WorktreeProcessAdapter(
      processes: [process], directories: [directory, directory]
    ))
  #expect(throws: NativeDarwinGitWorktreeObservationError.processUnavailable) {
    _ = try observer.observe(pid: 42, expectedUserID: UInt32(geteuid()))
  }
}

@Test func processObserverRejectsDriftAfterFilesystemRevalidation() throws {
  let repository = try temporaryGitRepository()
  defer { try? FileManager.default.removeItem(at: repository) }
  let directory = try cwdSnapshot(repository.path)
  let process = NativeDarwinWorktreeProcessSnapshot(
    pid: 42, uid: UInt32(geteuid()), pidVersion: 7)
  let observer = NativeDarwinGitWorktreeObserver(
    processAdapter: WorktreeProcessAdapter(
      processes: [process, process, .init(pid: 42, uid: UInt32(geteuid()), pidVersion: 8)],
      directories: [directory, directory, directory]
    ))
  #expect(throws: NativeDarwinGitWorktreeObservationError.processChanged) {
    _ = try observer.observe(pid: 42, expectedUserID: UInt32(geteuid()))
  }
}
