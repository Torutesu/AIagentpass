import Darwin
import Foundation
import Testing

@testable import AgentPassNativeCore

private struct TemporaryGitRepository {
  let url: URL

  init(objectFormat: String? = nil) throws {
    url = FileManager.default.temporaryDirectory
      .appendingPathComponent("agentpass-object-store-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
    var arguments = ["init", "--initial-branch=main"]
    if let objectFormat { arguments += ["--object-format=\(objectFormat)"] }
    try runGit(arguments, in: url)
  }

  func remove() {
    try? FileManager.default.removeItem(at: url)
  }

  func commit(message: String = "initial") throws -> (commit: String, tree: String) {
    try runGit(["add", "file.txt"], in: url)
    try runGit(
      [
        "-c", "user.name=AgentPass Test", "-c", "user.email=test@agentpass.local",
        "commit", "-m", message,
      ], in: url)
    let commit = try runGit(["rev-parse", "HEAD"], in: url).trimmingCharacters(
      in: .whitespacesAndNewlines)
    let tree = try runGit(["rev-parse", "HEAD^{tree}"], in: url).trimmingCharacters(
      in: .whitespacesAndNewlines)
    return (commit, tree)
  }

  func store() throws -> NativeGitObjectStore {
    guard let path = realpath(url.appendingPathComponent(".git").path, nil) else {
      throw TestGitError.failed
    }
    defer { free(path) }
    return try NativeGitObjectStore(
      commonGitDirectoryPath: String(cString: path), expectedUID: UInt32(geteuid()))
  }
}

private enum TestGitError: Error {
  case failed
}

@discardableResult
private func runGit(_ arguments: [String], in directory: URL) throws -> String {
  let process = Process()
  process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
  process.arguments = arguments
  process.currentDirectoryURL = directory
  let output = Pipe()
  let errors = Pipe()
  process.standardOutput = output
  process.standardError = errors
  try process.run()
  process.waitUntilExit()
  guard process.terminationStatus == 0 else { throw TestGitError.failed }
  return String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
}

private func runGitWithInput(_ arguments: [String], input: String, in directory: URL) throws
  -> String
{
  let process = Process()
  process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
  process.arguments = arguments
  process.currentDirectoryURL = directory
  let output = Pipe()
  let errors = Pipe()
  let standardInput = Pipe()
  process.standardOutput = output
  process.standardError = errors
  process.standardInput = standardInput
  try process.run()
  standardInput.fileHandleForWriting.write(Data(input.utf8))
  standardInput.fileHandleForWriting.closeFile()
  process.waitUntilExit()
  guard process.terminationStatus == 0 else { throw TestGitError.failed }
  return String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
}

private func writeFile(_ contents: String, in repository: URL) throws {
  try Data(contents.utf8).write(to: repository.appendingPathComponent("file.txt"), options: .atomic)
}

@Test func nativeGitObjectStoreReadsLooseSHA1CommitTreeAndBlob() throws {
  let repository = try TemporaryGitRepository()
  defer { repository.remove() }
  try writeFile("hello sha1\n", in: repository.url)
  let identifiers = try repository.commit()
  let store = try repository.store()

  let commit = try store.readObject(oid: identifiers.commit)
  #expect(commit.type == .commit)
  #expect(try store.readCommitTreeOID(oid: identifiers.commit) == identifiers.tree)
  let tree = try store.readCommitRootTreeEntries(oid: identifiers.commit)
  #expect(tree.count == 1)
  #expect(tree[0].mode == "100644")
  #expect(tree[0].name == "file.txt")
  #expect(tree[0].oid.count == 40)
}

@Test func nativeGitObjectStoreReadsLooseSHA256WhenGitSupportsIt() throws {
  let repository: TemporaryGitRepository
  do {
    repository = try TemporaryGitRepository(objectFormat: "sha256")
  } catch {
    return
  }
  defer { repository.remove() }
  try writeFile("hello sha256\n", in: repository.url)
  let identifiers = try repository.commit()
  let store = try repository.store()

  let object = try store.readObject(oid: identifiers.commit)
  #expect(object.type == .commit)
  #expect(identifiers.commit.count == 64)
  #expect(try store.readCommitTreeOID(oid: identifiers.commit) == identifiers.tree)
  #expect(try store.readCommitRootTreeEntries(oid: identifiers.commit).first?.oid.count == 64)
}

@Test func nativeGitObjectStoreReadsPackedCommitAfterGitGC() throws {
  let repository = try TemporaryGitRepository()
  defer { repository.remove() }
  var firstLines = (0..<8_192).map { "packed content line \($0)" }
  try writeFile(firstLines.joined(separator: "\n") + "\n", in: repository.url)
  let first = try repository.commit(message: "first")
  firstLines[4_096] = "packed content line 4096 changed"
  let secondPayload = firstLines.joined(separator: "\n") + "\n"
  try writeFile(secondPayload, in: repository.url)
  let second = try repository.commit(message: "second")
  try runGit(["gc", "--aggressive", "--prune=now"], in: repository.url)

  let packDirectory = repository.url.appendingPathComponent(".git/objects/pack")
  let packFiles = try FileManager.default.contentsOfDirectory(atPath: packDirectory.path)
  #expect(packFiles.contains(where: { $0.hasSuffix(".idx") }))
  #expect(packFiles.contains(where: { $0.hasSuffix(".pack") }))
  let indexName = try #require(packFiles.first(where: { $0.hasSuffix(".idx") }))
  let verification = try runGit(
    ["verify-pack", "-v", packDirectory.appendingPathComponent(indexName).path],
    in: repository.url)
  #expect(
    verification.split(separator: "\n").contains(where: { $0.split(separator: " ").count >= 7 }))

  let store = try repository.store()
  let object = try store.readObject(oid: second.commit)
  #expect(object.type == .commit)
  #expect(try store.readCommitTreeOID(oid: second.commit) == second.tree)
  let firstEntry = try #require(try store.readCommitRootTreeEntries(oid: first.commit).first)
  let secondEntry = try #require(try store.readCommitRootTreeEntries(oid: second.commit).first)
  #expect(firstEntry.name == "file.txt")
  #expect(secondEntry.name == "file.txt")
  #expect(
    try store.readObject(oid: firstEntry.oid).payload
      == Data(
        (0..<8_192).map { "packed content line \($0)" }.joined(separator: "\n").appending("\n").utf8
      ))
  #expect(try store.readObject(oid: secondEntry.oid).payload == Data(secondPayload.utf8))
  #expect(try store.readObject(oid: first.commit).type == .commit)

  let promisor = packDirectory.appendingPathComponent("pack-test.promisor")
  try Data().write(to: promisor, options: .atomic)
  #expect(throws: NativeGitObjectStoreError.self) {
    _ = try store.readObject(oid: second.commit)
  }
}

@Test func nativeGitObjectStoreRejectsCorruptLooseObjectAndMalformedRootTree() throws {
  let repository = try TemporaryGitRepository()
  defer { repository.remove() }
  try writeFile("corruption target\n", in: repository.url)
  let identifiers = try repository.commit()
  let loose = repository.url.appendingPathComponent(
    ".git/objects/\(identifiers.commit.prefix(2))/\(identifiers.commit.dropFirst(2))")
  var corrupt = try Data(contentsOf: loose)
  corrupt[corrupt.startIndex] ^= 0xff
  guard chmod(loose.path, 0o600) == 0 else { throw TestGitError.failed }
  try corrupt.write(to: loose)
  #expect(throws: NativeGitObjectStoreError.self) {
    _ = try repository.store().readObject(oid: identifiers.commit)
  }

  try FileManager.default.removeItem(at: repository.url)
  let second = try TemporaryGitRepository()
  defer { second.remove() }
  let malformedTree = try runGitWithInput(
    ["hash-object", "--literally", "-w", "--stdin", "-t", "tree"],
    input: "not-a-tree", in: second.url
  ).trimmingCharacters(in: .whitespacesAndNewlines)
  let commit = """
    tree \(malformedTree)
    author AgentPass Test <test@agentpass.local> 0 +0000
    committer AgentPass Test <test@agentpass.local> 0 +0000

    malformed tree
    """
  let malformedCommit = try runGitWithInput(
    ["hash-object", "--literally", "-w", "--stdin", "-t", "commit"],
    input: commit, in: second.url
  ).trimmingCharacters(in: .whitespacesAndNewlines)
  #expect(throws: NativeGitObjectStoreError.self) {
    _ = try second.store().readCommitRootTree(oid: malformedCommit)
  }
}

@Test func nativeGitObjectStoreAcceptsSignedCommitHeaderContinuations() throws {
  let repository = try TemporaryGitRepository()
  defer { repository.remove() }
  try writeFile("signed header base\n", in: repository.url)
  let identifiers = try repository.commit()
  let payload = """
    tree \(identifiers.tree)
    author AgentPass Test <test@agentpass.local> 0 +0000
    committer AgentPass Test <test@agentpass.local> 0 +0000
    gpgsig -----BEGIN PGP SIGNATURE-----
     abcdef
     -----END PGP SIGNATURE-----

    signed-header test
    """
  let signedOID = try runGitWithInput(
    ["hash-object", "-w", "--stdin", "-t", "commit"], input: payload, in: repository.url
  )
  .trimmingCharacters(in: .whitespacesAndNewlines)
  let store = try repository.store()
  #expect(try store.readCommitTreeOID(oid: signedOID) == identifiers.tree)
}
