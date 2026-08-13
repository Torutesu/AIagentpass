import CryptoKit
import Darwin
import Foundation
import Testing

@testable import AgentPassNativeCore

private struct DurableReceiptFixture {
  let root: URL
  let binding: NativeAgentQualificationDurableReceiptBinding

  private static func canonicalTemporaryDirectory() throws -> URL {
    let source = FileManager.default.temporaryDirectory.path
    guard let pointer = Darwin.realpath(source, nil) else {
      throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    defer { free(pointer) }
    return URL(fileURLWithPath: String(cString: pointer), isDirectory: true)
  }

  init() throws {
    let candidate = try Self.canonicalTemporaryDirectory()
      .appendingPathComponent("agentpass-n3e-fired-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: candidate, withIntermediateDirectories: false)
    guard let pointer = Darwin.realpath(candidate.path, nil) else {
      throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    let canonicalRoot = URL(fileURLWithPath: String(cString: pointer), isDirectory: true)
    free(pointer)
    root = canonicalRoot
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
    binding = try NativeAgentQualificationDurableReceiptBinding(
      candidateDigest: Data(repeating: 0x11, count: 32),
      sourceCommitDigest: Data(repeating: 0x22, count: 32),
      codeIdentityDigest: Data(repeating: 0x33, count: 32),
      runIDDigest: Data(repeating: 0x44, count: 32),
      scenario: .postActivationPreAuditKill,
      phase: .postActivationPreAudit)
  }

  func remove() { try? FileManager.default.removeItem(at: root) }
}

private func receiptPath(_ fixture: DurableReceiptFixture) -> String {
  fixture.root.appendingPathComponent(
    NativeAgentQualificationDurableReceiptStore.receiptFileName).path
}

@Test("durable fired receipt is canonical, closed, private, and digest-bound")
func durableReceiptIsCanonicalAndSecretFree() throws {
  let fixture = try DurableReceiptFixture()
  defer { fixture.remove() }
  let store = try NativeAgentQualificationDurableReceiptStore(testRootPath: fixture.root.path)
  let receipt = try store.writeInjected(binding: fixture.binding, generation: 7)

  let data = try Data(contentsOf: URL(fileURLWithPath: receiptPath(fixture)))
  #expect(data.last == 0x0a)
  let payload = Data(data.dropLast())
  let object = try #require(JSONSerialization.jsonObject(with: payload) as? [String: Any])
  #expect(Set(object.keys) == [
    "armed_receipt_sha256", "candidate_sha256", "code_identity_sha256", "generation", "kind",
    "outcome", "phase", "run_id_sha256", "scenario", "schema_version", "source_commit_sha256",
  ])
  #expect(try NativeStrictJSON.data(object) == payload)
  #expect(String(data: data, encoding: .utf8)?.contains("injected") == true)
  #expect(String(data: data, encoding: .utf8)?.contains("proof") == false)
  #expect(String(data: data, encoding: .utf8)?.contains("/private") == false)

  var info = stat()
  #expect(lstat(receiptPath(fixture), &info) == 0)
  #expect((info.st_mode & S_IFMT) == S_IFREG)
  #expect((info.st_mode & 0o7777) == 0o600)
  #expect(info.st_nlink == 1)
  #expect(info.st_uid == geteuid())
  #expect(receipt.armedReceiptDigest == NativeAgentQualificationDurableReceiptStore.armedReceiptDigest(
    candidateDigest: fixture.binding.candidateDigest,
    sourceCommitDigest: fixture.binding.sourceCommitDigest,
    codeIdentityDigest: fixture.binding.codeIdentityDigest,
    runIDDigest: fixture.binding.runIDDigest,
    phase: fixture.binding.phase,
    generation: 7))
}

@Test("armed receipt digest exactly matches the qualification endpoint formula")
func armedReceiptDigestMatchesEndpointFormula() throws {
  let fixture = try DurableReceiptFixture()
  defer { fixture.remove() }
  let phaseDigest = Data(SHA256.hash(data: Data(fixture.binding.phase.rawValue.utf8)))
  var material = Data("AgentPassQualificationReceipt/v1\0".utf8)
  material.append(fixture.binding.candidateDigest)
  material.append(fixture.binding.sourceCommitDigest)
  material.append(fixture.binding.codeIdentityDigest)
  material.append(fixture.binding.runIDDigest)
  material.append(phaseDigest)
  material.append(contentsOf: withUnsafeBytes(of: UInt64(7).bigEndian) { Array($0) })
  let expected = Data(SHA256.hash(data: material))
  #expect(NativeAgentQualificationDurableReceiptStore.armedReceiptDigest(
    candidateDigest: fixture.binding.candidateDigest,
    sourceCommitDigest: fixture.binding.sourceCommitDigest,
    codeIdentityDigest: fixture.binding.codeIdentityDigest,
    runIDDigest: fixture.binding.runIDDigest,
    phase: fixture.binding.phase,
    generation: 7) == expected)
}

@Test("receipt survives store restart and repeated write is idempotent")
func durableReceiptSurvivesRestart() throws {
  let fixture = try DurableReceiptFixture()
  defer { fixture.remove() }
  do {
    let store = try NativeAgentQualificationDurableReceiptStore(testRootPath: fixture.root.path)
    _ = try store.writeInjected(binding: fixture.binding, generation: 3)
  }
  let restarted = try NativeAgentQualificationDurableReceiptStore(testRootPath: fixture.root.path)
  let loaded = try #require(try restarted.read(expected: fixture.binding))
  #expect(loaded.generation == 3)
  #expect(try restarted.writeInjected(binding: fixture.binding, generation: 3) == loaded)
}

@Test("substitution and mismatched cleanup are rejected without deleting evidence")
func durableReceiptRejectsSubstitutionAndWrongCleanup() throws {
  let fixture = try DurableReceiptFixture()
  defer { fixture.remove() }
  let store = try NativeAgentQualificationDurableReceiptStore(testRootPath: fixture.root.path)
  _ = try store.writeInjected(binding: fixture.binding, generation: 1)

  let other = try NativeAgentQualificationDurableReceiptBinding(
    candidateDigest: Data(repeating: 0x99, count: 32),
    sourceCommitDigest: fixture.binding.sourceCommitDigest,
    codeIdentityDigest: fixture.binding.codeIdentityDigest,
    runIDDigest: fixture.binding.runIDDigest,
    scenario: fixture.binding.scenario,
    phase: fixture.binding.phase)
  #expect(throws: NativeAgentQualificationDurableReceiptStoreError.conflict) {
    _ = try store.writeInjected(binding: other, generation: 1)
  }
  #expect(throws: NativeAgentQualificationDurableReceiptStoreError.conflict) {
    _ = try store.remove(expected: other)
  }
  #expect(try store.read(expected: fixture.binding)?.generation == 1)
}

@Test("symlink substitution is rejected by no-follow and single-link validation")
func durableReceiptRejectsSymlinkSubstitution() throws {
  let fixture = try DurableReceiptFixture()
  defer { fixture.remove() }
  let store = try NativeAgentQualificationDurableReceiptStore(testRootPath: fixture.root.path)
  _ = try store.writeInjected(binding: fixture.binding, generation: 2)
  let path = receiptPath(fixture)
  let backup = fixture.root.appendingPathComponent("backup").path
  try FileManager.default.moveItem(atPath: path, toPath: backup)
  try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: backup)
  #expect(throws: NativeAgentQualificationDurableReceiptStoreError.self) {
    _ = try store.read()
  }
}

@Test("cleanup is exact and fsyncs the parent boundary")
func durableReceiptCleanupIsExact() throws {
  let fixture = try DurableReceiptFixture()
  defer { fixture.remove() }
  let store = try NativeAgentQualificationDurableReceiptStore(testRootPath: fixture.root.path)
  _ = try store.writeInjected(binding: fixture.binding, generation: 4)
  #expect(try store.remove(expected: fixture.binding))
  #expect(try store.read() == nil)
  #expect(try store.remove(expected: fixture.binding) == false)
}
