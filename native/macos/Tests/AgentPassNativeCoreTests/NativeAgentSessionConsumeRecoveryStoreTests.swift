import Foundation
import Testing

@testable import AgentPassNativeCore

private let recoveryOrganization = "33333333-3333-4333-8333-333333333333"
private let recoveryDevice = "44444444-4444-4444-8444-444444444444"
private let recoveryAgent = "55555555-5555-4555-8555-555555555555"

private func recoveryDirectory() throws -> (URL, String) {
  let requestedRoot = FileManager.default.temporaryDirectory
    .appendingPathComponent("agentpass-recovery-\(UUID().uuidString)")
  try FileManager.default.createDirectory(
    at: requestedRoot, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
  let canonicalPath =
    requestedRoot.path.hasPrefix("/var/")
    ? "/private\(requestedRoot.path)" : requestedRoot.path
  let root = URL(fileURLWithPath: canonicalPath, isDirectory: true)
  return (root, root.appendingPathComponent("consume-recovery.json").path)
}

private func recoveryEvidence(
  expiry: Int64 = 2_000_000,
  worktreeByte: UInt8 = 0xd
) throws -> NativeAgentSessionConsumeRecoveryEvidence {
  try NativeAgentSessionConsumeRecoveryEvidence(
    organizationID: recoveryOrganization,
    deviceID: recoveryDevice,
    agentID: recoveryAgent,
    adapterKind: .claudeCode,
    grantProofDigest: Data(repeating: 0xa, count: 32),
    processBindingDigest: Data(repeating: 0xb, count: 32),
    ancestryBindingDigest: Data(repeating: 0xc, count: 32),
    worktreeBindingDigest: Data(repeating: worktreeByte, count: 32),
    controlSequence: 7,
    authorityGeneration: 8,
    keyGeneration: 9,
    recoveryExpiresAtMilliseconds: expiry)
}

@Test func recoveryStoreRestartAndExactReplayPreserveOnlyDigestEvidence() throws {
  let (root, path) = try recoveryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }
  let evidence = try recoveryEvidence()
  _ = try NativeAgentSessionConsumeRecoveryStore(path: path).save(evidence)

  let restarted = try NativeAgentSessionConsumeRecoveryStore(path: path)
  #expect(try restarted.lookup(evidence) == evidence)
  let text = String(decoding: try Data(contentsOf: URL(fileURLWithPath: path)), as: UTF8.self)
  #expect(text.contains("grant_proof_sha256"))
  #expect(!text.contains("/Users/"))
  #expect(!text.contains("private-token"))
  #expect(!text.contains("123456"))
  #expect(
    (try FileManager.default.attributesOfItem(atPath: path)[.posixPermissions] as? NSNumber)?
      .uint16Value == 0o600)
}

@Test func recoveryStoreAllowsNewBootstrapTimeButRejectsAuthoritySubstitution() throws {
  let (root, path) = try recoveryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }
  let store = try NativeAgentSessionConsumeRecoveryStore(path: path)
  let evidence = try recoveryEvidence()
  _ = try store.save(evidence)
  let laterBootstrap = try recoveryEvidence(expiry: evidence.recoveryExpiresAtMilliseconds + 5_000)
  #expect(
    try store.save(laterBootstrap, nowMilliseconds: 1_500_000)
      .recoveryExpiresAtMilliseconds == evidence.recoveryExpiresAtMilliseconds)
  let changed = try recoveryEvidence(worktreeByte: 0xe)
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.conflict) {
    _ = try store.lookup(changed)
  }
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.conflict) {
    _ = try store.save(changed)
  }
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.conflict) {
    _ = try store.completeAfterLocalActivation(changed)
  }
}

@Test func recoveryStorePrunesDeterministicallyAndReleasesCapacity() throws {
  let (root, path) = try recoveryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }
  let store = try NativeAgentSessionConsumeRecoveryStore(path: path)
  let expired = try recoveryEvidence(expiry: 1_000_000)
  _ = try store.save(expired)
  #expect(try store.pruneExpired(nowMilliseconds: 1_000_000) == 1)
  #expect(!FileManager.default.fileExists(atPath: path))
  #expect(try store.lookup(expired) == nil)

  let replacement = try recoveryEvidence(expiry: 3_000_000)
  _ = try store.save(replacement, nowMilliseconds: 1_000_001)
  #expect(try store.lookup(replacement) == replacement)
}

@Test func recoveryStoreDerivesBoundAndShortensItToLeaseExpiry() throws {
  let bound = try NativeAgentSessionConsumeRecoveryEvidence.recoveryExpiry(
    bootstrapIssuedAtMilliseconds: 1_000_000,
    requestedTTLSeconds: 60)
  #expect(bound == 1_060_000)
  let shortened = try NativeAgentSessionConsumeRecoveryEvidence.recoveryExpiry(
    bootstrapIssuedAtMilliseconds: 1_000_000,
    requestedTTLSeconds: 60,
    leaseExpiresAtMilliseconds: 1_020_000)
  #expect(shortened == 1_020_000)
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.invalidEvidence) {
    _ = try NativeAgentSessionConsumeRecoveryEvidence.recoveryExpiry(
      bootstrapIssuedAtMilliseconds: 1_000_000,
      requestedTTLSeconds: 60,
      leaseExpiresAtMilliseconds: 1_000_000)
  }
}

@Test func recoveryStoreRejectsTamperModeSymlinkAndHardlink() throws {
  let (root, path) = try recoveryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }
  let evidence = try recoveryEvidence()
  _ = try NativeAgentSessionConsumeRecoveryStore(path: path).save(evidence)

  try FileManager.default.setAttributes([.posixPermissions: 0o640], ofItemAtPath: path)
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.invalidState) {
    _ = try NativeAgentSessionConsumeRecoveryStore(path: path)
  }
  try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)

  let hardlink = root.appendingPathComponent("hardlink.json")
  try FileManager.default.linkItem(atPath: path, toPath: hardlink.path)
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.invalidState) {
    _ = try NativeAgentSessionConsumeRecoveryStore(path: hardlink.path)
  }
  try FileManager.default.removeItem(at: hardlink)

  let target = root.appendingPathComponent("target.json")
  try FileManager.default.moveItem(atPath: path, toPath: target.path)
  try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: target.path)
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.invalidState) {
    _ = try NativeAgentSessionConsumeRecoveryStore(path: path)
  }
}

@Test func recoveryStoreCleansCrashRemnantAndRequiresPrivateDirectory() throws {
  let (root, path) = try recoveryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }
  let remnant = root.appendingPathComponent(
    ".agentpass-session-consume-recovery.tmp-crash")
  try Data("partial".utf8).write(to: remnant)
  try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: remnant.path)
  _ = try NativeAgentSessionConsumeRecoveryStore(path: path)
  #expect(!FileManager.default.fileExists(atPath: remnant.path))

  try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: root.path)
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.invalidState) {
    _ = try NativeAgentSessionConsumeRecoveryStore(path: path)
  }
}

@Test func recoveryStoreTerminalDeletionRequiresExactTuple() throws {
  let (root, path) = try recoveryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }
  let store = try NativeAgentSessionConsumeRecoveryStore(path: path)
  let evidence = try recoveryEvidence()
  _ = try store.save(evidence)
  #expect(try store.completeAfterLocalActivation(evidence))
  #expect(!FileManager.default.fileExists(atPath: path))
  #expect(try NativeAgentSessionConsumeRecoveryStore(path: path).lookup(evidence) == nil)

  _ = try store.save(evidence)
  #expect(try store.abandon(evidence))
  #expect(!FileManager.default.fileExists(atPath: path))
}
