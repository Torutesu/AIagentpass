import Foundation
import Testing

@testable import AgentPassNativeCore

private let recoveryOrganization = "33333333-3333-4333-8333-333333333333"
private let recoveryDevice = "44444444-4444-4444-8444-444444444444"
private let recoveryAgent = "55555555-5555-4555-8555-555555555555"
private let recoverySession = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

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

private func preparedRecoveryRecord(
  _ evidence: NativeAgentSessionConsumeRecoveryEvidence,
  expiry: Int64? = nil,
  digestByte: UInt8 = 0xe
) throws -> NativeAgentSessionConsumeRecoveryPreparedRecord {
  try NativeAgentSessionConsumeRecoveryPreparedRecord(
    evidence: evidence,
    sessionID: recoverySession,
    sessionDigest: Data(repeating: digestByte, count: 32),
    resultDigest: Data(repeating: digestByte &+ 1, count: 32),
    auditEvidenceDigest: Data(repeating: digestByte &+ 2, count: 32),
    expiresAtMilliseconds: expiry)
}

private func auditedRecoveryRecord(
  _ evidence: NativeAgentSessionConsumeRecoveryEvidence,
  expiry: Int64? = nil,
  digestByte: UInt8 = 0xe
) throws -> NativeAgentSessionConsumeRecoveryAuditedRecord {
  let prepared = try preparedRecoveryRecord(evidence, expiry: expiry, digestByte: digestByte)
  return try NativeAgentSessionConsumeRecoveryAuditedRecord(
    preparedRecord: prepared,
    auditDigest: Data(repeating: digestByte &+ 3, count: 32))
}

private func completeRecovery(
  _ store: NativeAgentSessionConsumeRecoveryStore,
  evidence: NativeAgentSessionConsumeRecoveryEvidence,
  auditedRecord: NativeAgentSessionConsumeRecoveryAuditedRecord
) throws -> NativeAgentSessionConsumeRecoveryAuditedRecord {
  switch try store.lookupExact(evidence) {
  case .pending:
    _ = try store.prepareForActivation(
      evidence, preparedRecord: auditedRecord.preparedRecord)
  case .auditPrepared(let prepared) where prepared == auditedRecord.preparedRecord:
    break
  case .audited:
    break
  default:
    throw NativeAgentSessionConsumeRecoveryStoreError.conflict
  }
  return try store.completeAfterAudit(
    evidence, preparedRecord: auditedRecord.preparedRecord,
    auditedRecord: auditedRecord)
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
    _ = try completeRecovery(
      store, evidence: changed, auditedRecord: try auditedRecoveryRecord(changed))
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
  let audited = try auditedRecoveryRecord(evidence)
  #expect(try completeRecovery(store, evidence: evidence, auditedRecord: audited) == audited)
  #expect(FileManager.default.fileExists(atPath: path))
  #expect(try store.lookupExact(evidence) == .audited(audited))
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.conflict) {
    _ = try store.lookup(evidence)
  }
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.conflict) {
    _ = try store.save(evidence)
  }
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.conflict) {
    _ = try store.abandon(evidence)
  }
}

@Test func recoveryStoreAuditedTerminalSurvivesRestartAndExpires() throws {
  let (root, path) = try recoveryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }
  let evidence = try recoveryEvidence()
  let audited = try auditedRecoveryRecord(evidence, expiry: 1_900_000)
  let store = try NativeAgentSessionConsumeRecoveryStore(path: path)
  _ = try store.save(evidence)
  _ = try completeRecovery(store, evidence: evidence, auditedRecord: audited)

  let text = String(decoding: try Data(contentsOf: URL(fileURLWithPath: path)), as: UTF8.self)
  #expect(text.contains("\"state\":\"audited\""))
  #expect(text.contains("session_sha256"))
  #expect(text.contains("result_sha256"))
  #expect(text.contains("audit_sha256"))
  #expect(!text.contains("/Users/"))
  #expect(!text.contains("private-token"))

  let restarted = try NativeAgentSessionConsumeRecoveryStore(path: path)
  #expect(try restarted.lookupExact(evidence) == .audited(audited))
  #expect(
    try completeRecovery(restarted, evidence: evidence, auditedRecord: audited) == audited)
  #expect(
    try restarted.lookupExact(evidence, nowMilliseconds: audited.expiresAtMilliseconds)
      == .missing)
  #expect(!FileManager.default.fileExists(atPath: path))
}

@Test func recoveryStoreAuditedLookupRejectsTupleAndResultConflicts() throws {
  let (root, path) = try recoveryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }
  let evidence = try recoveryEvidence()
  let audited = try auditedRecoveryRecord(evidence)
  let store = try NativeAgentSessionConsumeRecoveryStore(path: path)
  _ = try store.save(evidence)
  _ = try completeRecovery(store, evidence: evidence, auditedRecord: audited)

  let changedTuple = try recoveryEvidence(worktreeByte: 0xf)
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.conflict) {
    _ = try store.lookupExact(changedTuple)
  }
  let changedResult = try auditedRecoveryRecord(evidence, digestByte: 0x1)
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.conflict) {
    _ = try completeRecovery(store, evidence: evidence, auditedRecord: changedResult)
  }
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.conflict) {
    _ = try completeRecovery(store, evidence: changedTuple, auditedRecord: audited)
  }
}

@Test func recoveryStorePreparedStateBindsPublicSessionAndPrunesWithoutAuthority() throws {
  let (root, path) = try recoveryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }
  let evidence = try recoveryEvidence(expiry: 1_800_000)
  let prepared = try preparedRecoveryRecord(evidence, expiry: 1_700_000)
  let store = try NativeAgentSessionConsumeRecoveryStore(path: path)
  _ = try store.save(evidence)
  #expect(try store.prepareForActivation(evidence, preparedRecord: prepared) == prepared)

  let text = String(decoding: try Data(contentsOf: URL(fileURLWithPath: path)), as: UTF8.self)
  #expect(text.contains("\"state\":\"audit_prepared\""))
  #expect(text.contains("\"session_id\":\"\(recoverySession)\""))
  #expect(!text.contains("local_lease_id"))
  #expect(!text.contains("credential"))
  #expect(
    try NativeAgentSessionConsumeRecoveryStore(path: path).lookupExact(evidence)
      == .auditPrepared(prepared))

  #expect(try store.pruneExpired(nowMilliseconds: prepared.expiresAtMilliseconds) == 1)
  #expect(try store.lookupExact(evidence) == .missing)
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.invalidState) {
    _ = try store.completeAfterAudit(
      evidence,
      preparedRecord: prepared,
      auditedRecord: try NativeAgentSessionConsumeRecoveryAuditedRecord(
        preparedRecord: prepared, auditDigest: Data(repeating: 0x4, count: 32)))
  }
}

@Test func recoveryStoreRejectsSessionIDSubstitutionAndNonCanonicalEncoding() throws {
  let (root, path) = try recoveryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }
  let evidence = try recoveryEvidence()
  let prepared = try preparedRecoveryRecord(evidence)
  let store = try NativeAgentSessionConsumeRecoveryStore(path: path)
  _ = try store.save(evidence)
  _ = try store.prepareForActivation(evidence, preparedRecord: prepared)
  let changed = try NativeAgentSessionConsumeRecoveryPreparedRecord(
    evidence: evidence,
    sessionID: "22222222-2222-4222-8222-222222222222",
    sessionDigest: prepared.sessionDigest,
    resultDigest: prepared.resultDigest,
    auditEvidenceDigest: prepared.auditEvidenceDigest,
    expiresAtMilliseconds: prepared.expiresAtMilliseconds)
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.conflict) {
    _ = try store.prepareForActivation(evidence, preparedRecord: changed)
  }

  let url = URL(fileURLWithPath: path)
  let current = try String(contentsOf: url, encoding: .utf8)
  let uppercase = current.replacingOccurrences(
    of: recoverySession, with: recoverySession.uppercased())
  #expect(uppercase != current)
  try Data(uppercase.utf8).write(to: url)
  try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.invalidState) {
    _ = try NativeAgentSessionConsumeRecoveryStore(path: path)
  }
}

@Test func recoveryStoreRejectsLegacyVersionAndStateReinterpretation() throws {
  let (root, path) = try recoveryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }
  let evidence = try recoveryEvidence()
  _ = try NativeAgentSessionConsumeRecoveryStore(path: path).save(evidence)
  let url = URL(fileURLWithPath: path)
  let current = String(decoding: try Data(contentsOf: url), as: UTF8.self)
  for version in ["1", "2"] {
    let legacy = current.replacingOccurrences(of: "\"version\":3", with: "\"version\":\(version)")
    #expect(legacy != current)
    try Data(legacy.utf8).write(to: url)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
    #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.invalidState) {
      _ = try NativeAgentSessionConsumeRecoveryStore(path: path)
    }
  }
}

@Test func recoveryStoreRejectsNonCanonicalBytesAndTamperedState() throws {
  let (root, path) = try recoveryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }
  let evidence = try recoveryEvidence()
  let audited = try auditedRecoveryRecord(evidence)
  let store = try NativeAgentSessionConsumeRecoveryStore(path: path)
  _ = try store.save(evidence)
  _ = try completeRecovery(store, evidence: evidence, auditedRecord: audited)
  let url = URL(fileURLWithPath: path)
  let current = try Data(contentsOf: url)

  var nonCanonical = Data(current.dropLast())
  nonCanonical.append(0x20)
  nonCanonical.append(0x0a)
  try nonCanonical.write(to: url)
  try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.invalidState) {
    _ = try NativeAgentSessionConsumeRecoveryStore(path: path)
  }

  try current.write(to: url)
  try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
  let tampered = String(decoding: current, as: UTF8.self)
    .replacingOccurrences(of: "\"state\":\"audited\"", with: "\"state\":\"pending\"")
  #expect(tampered != String(decoding: current, as: UTF8.self))
  try Data(tampered.utf8).write(to: url)
  try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.invalidState) {
    _ = try NativeAgentSessionConsumeRecoveryStore(path: path)
  }
}

@Test func recoveryStoreRejectsUnboundedTerminalData() throws {
  let evidence = try recoveryEvidence()
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.invalidEvidence) {
    _ = try NativeAgentSessionConsumeRecoveryPreparedRecord(
      evidence: evidence,
      sessionID: recoverySession,
      sessionDigest: Data(repeating: 1, count: 31),
      resultDigest: Data(repeating: 2, count: 32),
      auditEvidenceDigest: Data(repeating: 3, count: 32))
  }
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.invalidEvidence) {
    _ = try NativeAgentSessionConsumeRecoveryPreparedRecord(
      evidence: evidence,
      sessionID: recoverySession,
      sessionDigest: Data(repeating: 1, count: 32),
      resultDigest: Data(repeating: 2, count: 32),
      auditEvidenceDigest: Data(repeating: 3, count: 32),
      expiresAtMilliseconds: evidence.recoveryExpiresAtMilliseconds + 1)
  }
  let prepared = try preparedRecoveryRecord(evidence)
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.invalidEvidence) {
    _ = try NativeAgentSessionConsumeRecoveryAuditedRecord(
      preparedRecord: prepared, auditDigest: Data(repeating: 1, count: 31))
  }
}
