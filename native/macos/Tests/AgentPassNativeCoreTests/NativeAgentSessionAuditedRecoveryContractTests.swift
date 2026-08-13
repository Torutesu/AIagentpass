import CoreFoundation
import CryptoKit
import Foundation
import Testing

@testable import AgentPassNativeCore

// N3-E3c-1b freezes the closed production surface of the v3 recovery-store
// transition:
//
//   NativeAgentSessionConsumeRecoveryAuditedRecord
//   NativeAgentSessionConsumeRecoveryStoring.prepareForActivation(
//     _:preparedRecord:
//   ) -> NativeAgentSessionConsumeRecoveryPreparedRecord
//   NativeAgentSessionConsumeRecoveryStoring.completeAfterAudit(
//     _:preparedRecord:auditedRecord:
//   ) -> NativeAgentSessionConsumeRecoveryAuditedRecord
//   NativeAgentSessionConsumeRecoveryStoring.lookupExact(
//     _:
//   ) -> NativeAgentSessionConsumeRecoveryLookup
//
// A terminal record is the only permitted retry source after the audit has
// become durable; it must never be treated as active local authority.

private enum N3EAuditedRecoveryContractError: Error, Equatable, Sendable {
  case invalidRecord
  case invalidEncoding
}

private let n3eAuditedOrganizationID = "66666666-6666-4666-8666-666666666666"
private let n3eAuditedDeviceID = "44444444-4444-4444-8444-444444444444"
private let n3eAuditedAgentID = "33333333-3333-4333-8333-333333333333"
private let n3eAuditedSessionID = "11111111-1111-4111-8111-111111111111"
private let n3eAuditedToken = String(repeating: "a", count: 64)
private let n3eAuditedExpiry: Int64 = 2_000_000
private let n3eAuditedTerminalExpiry: Int64 = 1_900_000
private let n3eAuditedAt: Int64 = 1_500_000

private let n3eAuditedImmutableKeys: Set<String> = [
  "adapter_kind", "agent_id", "ancestry_binding_sha256", "authority_generation",
  "control_sequence", "device_id", "grant_proof_sha256", "key_generation",
  "organization_id", "process_binding_sha256", "recovery_expires_at_ms",
  "worktree_binding_sha256",
]

private let n3eAuditedPreparedKeys: Set<String> = n3eAuditedImmutableKeys.union([
  "audit_evidence_sha256", "expires_at_ms", "result_sha256", "session_id",
  "session_sha256", "state",
])

private let n3eAuditedTerminalKeys: Set<String> = n3eAuditedPreparedKeys.union([
  "audit_sha256"
])

private let n3eAuditedForbiddenKeys: Set<String> = [
  "bootstrap_id", "cloud_lease", "connection_token", "credential", "lease", "lease_id",
  "path", "pid", "proof", "proof_bytes", "private_key", "secret",
]

private func n3eAuditedHex(_ data: Data) -> String {
  data.map { String(format: "%02x", $0) }.joined()
}

private func n3eAuditedData(_ value: Any?) -> Data? {
  guard let value = value as? String,
    value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
  else { return nil }
  var result = Data(capacity: 32)
  var index = value.startIndex
  while index < value.endIndex {
    let next = value.index(index, offsetBy: 2)
    guard let byte = UInt8(value[index..<next], radix: 16) else { return nil }
    result.append(byte)
    index = next
  }
  return result.count == 32 ? result : nil
}

private func n3eAuditedInt(_ value: Any?) -> Int64? {
  guard let value = value as? NSNumber,
    CFGetTypeID(value) != CFBooleanGetTypeID(),
    value.doubleValue.isFinite,
    value.doubleValue.rounded() == value.doubleValue,
    Double(value.int64Value) == value.doubleValue,
    value.int64Value >= 0
  else { return nil }
  return value.int64Value
}

private func n3eAuditedDigest(domain: String, object: [String: Any]) throws -> Data {
  let canonical = try NativeStrictJSON.data(object)
  let domainData =
    Data("AgentPass/SessionAuditedRecovery/v1\0".utf8)
    + Data(domain.utf8) + Data([0])
  return Data(SHA256.hash(data: domainData + canonical))
}

private func n3eAuditedBinding(worktreeByte: UInt8 = 0xaa) throws
  -> NativeAgentSessionBinding
{
  try NativeAgentSessionBinding(
    agentID: n3eAuditedAgentID,
    deviceID: n3eAuditedDeviceID,
    processBindingDigest: Data(repeating: 0xbb, count: 32),
    ancestryBindingDigest: Data(repeating: 0xcc, count: 32),
    worktreeBindingDigest: Data(repeating: worktreeByte, count: 32),
    controlSequence: 12,
    authorityGeneration: 7,
    keyGeneration: 99)
}

private func n3eAuditedRecoveryEvidence(worktreeByte: UInt8 = 0xaa) throws
  -> NativeAgentSessionConsumeRecoveryEvidence
{
  try NativeAgentSessionConsumeRecoveryEvidence(
    organizationID: n3eAuditedOrganizationID,
    deviceID: n3eAuditedDeviceID,
    agentID: n3eAuditedAgentID,
    adapterKind: .claudeCode,
    grantProofDigest: Data(repeating: 0x11, count: 32),
    processBindingDigest: Data(repeating: 0xbb, count: 32),
    ancestryBindingDigest: Data(repeating: 0xcc, count: 32),
    worktreeBindingDigest: Data(repeating: worktreeByte, count: 32),
    controlSequence: 12,
    authorityGeneration: 7,
    keyGeneration: 99,
    recoveryExpiresAtMilliseconds: n3eAuditedExpiry)
}

private func n3eAuditedAuditEvidence(
  binding: NativeAgentSessionBinding,
  sessionID: String = n3eAuditedSessionID
) throws -> NativeAgentSessionAuditEvidence {
  try NativeAgentSessionAuditEvidence(
    action: .sessionActivated,
    sessionID: sessionID,
    binding: binding)
}

private func n3eAuditedRecord(
  evidence: NativeAgentSessionConsumeRecoveryEvidence,
  sessionID: String = n3eAuditedSessionID,
  terminalExpiry: Int64 = n3eAuditedTerminalExpiry
) throws -> NativeAgentSessionConsumeRecoveryAuditedRecord {
  let sessionDigest = try n3eAuditedDigest(
    domain: "session",
    object: ["session_id": sessionID])
  let resultDigest = try n3eAuditedDigest(
    domain: "result",
    object: [
      "expires_at_ms": Int64(1_900_000),
      "max_signatures": 2,
      "session_id": sessionID,
      "state": NativeAgentSessionState.active.rawValue,
      "used_signatures": 0,
    ])
  let auditEvidence = try n3eAuditedAuditEvidence(
    binding: try NativeAgentSessionBinding(
      agentID: evidence.agentID,
      deviceID: evidence.deviceID,
      processBindingDigest: evidence.processBindingDigest,
      ancestryBindingDigest: evidence.ancestryBindingDigest,
      worktreeBindingDigest: evidence.worktreeBindingDigest,
      controlSequence: evidence.controlSequence,
      authorityGeneration: evidence.authorityGeneration,
      keyGeneration: evidence.keyGeneration),
    sessionID: sessionID)
  let auditEvidenceDigest = try auditEvidence.evidenceDigest()
  let prepared = try NativeAgentSessionConsumeRecoveryPreparedRecord(
    evidence: evidence,
    sessionID: sessionID,
    sessionDigest: sessionDigest,
    resultDigest: resultDigest,
    auditEvidenceDigest: auditEvidenceDigest,
    expiresAtMilliseconds: terminalExpiry)
  return try NativeAgentSessionConsumeRecoveryAuditedRecord(
    preparedRecord: prepared,
    auditDigest: Data(repeating: 0x44, count: 32))
}

private func n3eComplete(
  _ store: NativeAgentSessionConsumeRecoveryStore,
  evidence: NativeAgentSessionConsumeRecoveryEvidence,
  record: NativeAgentSessionConsumeRecoveryAuditedRecord
) throws {
  _ = try store.prepareForActivation(evidence, preparedRecord: record.preparedRecord)
  _ = try store.completeAfterAudit(
    evidence, preparedRecord: record.preparedRecord, auditedRecord: record)
}

private func n3eAuditedRecoveryDirectory() throws -> (root: URL, path: String) {
  let requestedRoot = FileManager.default.temporaryDirectory
    .appendingPathComponent("agentpass-n3e-audited-\(UUID().uuidString)")
  try FileManager.default.createDirectory(
    at: requestedRoot,
    withIntermediateDirectories: true,
    attributes: [.posixPermissions: 0o700])
  let canonicalPath =
    requestedRoot.path.hasPrefix("/var/")
    ? "/private\(requestedRoot.path)" : requestedRoot.path
  let root = URL(fileURLWithPath: canonicalPath, isDirectory: true)
  return (root, root.appendingPathComponent("consume-recovery.json").path)
}

@Test("N3-E3c-1 audited terminal record is exact, secret-free, and bounded")
func n3eAuditedRecoveryTerminalShapeIsFrozen() throws {
  let (root, path) = try n3eAuditedRecoveryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }
  let evidence = try n3eAuditedRecoveryEvidence()
  let record = try n3eAuditedRecord(evidence: evidence)
  let store = try NativeAgentSessionConsumeRecoveryStore(path: path)
  _ = try store.save(evidence)
  _ = try n3eComplete(store, evidence: evidence, record: record)

  let bytes = try Data(contentsOf: URL(fileURLWithPath: path))
  #expect(bytes.count <= 256 * 1024)
  #expect(bytes.last == 0x0a)
  let payload = Data(bytes.dropLast())
  let object = try NativeStrictJSON.object(from: payload, maxBytes: 256 * 1024, maxDepth: 8)
  #expect(n3eAuditedInt(object["version"]) == 3)
  let records = try #require(object["records"] as? [[String: Any]])
  let terminal = try #require(records.first)
  #expect(Set(terminal.keys) == n3eAuditedTerminalKeys)
  #expect(terminal["state"] as? String == "audited")
  #expect(terminal.keys.allSatisfy { !n3eAuditedForbiddenKeys.contains($0) })
  #expect(n3eAuditedData(terminal["session_sha256"]) != nil)
  #expect(n3eAuditedData(terminal["result_sha256"]) != nil)
  #expect(n3eAuditedData(terminal["audit_evidence_sha256"]) != nil)
  #expect(terminal["session_id"] as? String == n3eAuditedSessionID)
  #expect(n3eAuditedData(terminal["audit_sha256"]) != nil)
  #expect(n3eAuditedInt(terminal["expires_at_ms"]) == n3eAuditedTerminalExpiry)

  let text = String(decoding: bytes, as: UTF8.self)
  #expect(!text.contains("proof-secret"))
  #expect(!text.contains("/Users/"))
  #expect(!text.contains("connection-token"))
  #expect(!text.contains("private-key-material"))
}

@Test("N3-E3c-1 terminal expiry cannot extend the immutable recovery bound")
func n3eAuditedRecoveryExpiryIsBounded() throws {
  let evidence = try n3eAuditedRecoveryEvidence()
  let prepared = try NativeAgentSessionConsumeRecoveryPreparedRecord(
    evidence: evidence,
    sessionID: n3eAuditedSessionID,
    sessionDigest: Data(repeating: 1, count: 32),
    resultDigest: Data(repeating: 2, count: 32),
    auditEvidenceDigest: Data(repeating: 3, count: 32),
    expiresAtMilliseconds: n3eAuditedTerminalExpiry)
  let shortened = try NativeAgentSessionConsumeRecoveryAuditedRecord(
    preparedRecord: prepared, auditDigest: Data(repeating: 4, count: 32))
  #expect(shortened.expiresAtMilliseconds == n3eAuditedTerminalExpiry)
  #expect(shortened.expiresAtMilliseconds < evidence.recoveryExpiresAtMilliseconds)

  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.invalidEvidence) {
    _ = try NativeAgentSessionConsumeRecoveryPreparedRecord(
      evidence: evidence,
      sessionID: n3eAuditedSessionID,
      sessionDigest: Data(repeating: 1, count: 32),
      resultDigest: Data(repeating: 2, count: 32),
      auditEvidenceDigest: Data(repeating: 3, count: 32),
      expiresAtMilliseconds: evidence.recoveryExpiresAtMilliseconds + 1)
  }
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.invalidEvidence) {
    _ = try NativeAgentSessionConsumeRecoveryPreparedRecord(
      evidence: evidence,
      sessionID: n3eAuditedSessionID,
      sessionDigest: Data(repeating: 1, count: 31),
      resultDigest: Data(repeating: 2, count: 32),
      auditEvidenceDigest: Data(repeating: 3, count: 32),
      expiresAtMilliseconds: n3eAuditedTerminalExpiry)
  }
}

@Test("N3-E3c-1 audit and result digest bindings are deterministic and sensitive")
func n3eAuditedRecoveryDigestBindingIsDeterministic() throws {
  let binding = try n3eAuditedBinding()
  let audit = try n3eAuditedAuditEvidence(binding: binding)
  let sameAudit = try n3eAuditedAuditEvidence(binding: binding)
  #expect(try audit.evidenceDigest() == sameAudit.evidenceDigest())

  let changedAudit = try n3eAuditedAuditEvidence(
    binding: try n3eAuditedBinding(worktreeByte: 0xab))
  #expect(try audit.evidenceDigest() != changedAudit.evidenceDigest())

  let result = try n3eAuditedDigest(
    domain: "result",
    object: ["session_id": n3eAuditedSessionID, "used_signatures": 0])
  let changedResult = try n3eAuditedDigest(
    domain: "result",
    object: ["session_id": n3eAuditedSessionID, "used_signatures": 1])
  let sameResult = try n3eAuditedDigest(
    domain: "result",
    object: ["session_id": n3eAuditedSessionID, "used_signatures": 0])
  #expect(result == sameResult)
  #expect(result != changedResult)
  #expect(result.count == 32)
  #expect(try audit.evidenceDigest().count == 32)
}

@Test("N3-E3c-1 audited transition is idempotent and rejects substitution")
func n3eAuditedRecoveryTransitionIsOneWay() throws {
  let (root, path) = try n3eAuditedRecoveryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }
  let evidence = try n3eAuditedRecoveryEvidence()
  let record = try n3eAuditedRecord(evidence: evidence)
  let store = try NativeAgentSessionConsumeRecoveryStore(path: path)
  _ = try store.save(evidence)

  #expect(
    try store.prepareForActivation(evidence, preparedRecord: record.preparedRecord)
      == record.preparedRecord)
  #expect(
    try store.prepareForActivation(evidence, preparedRecord: record.preparedRecord)
      == record.preparedRecord)
  #expect(
    try store.completeAfterAudit(
      evidence, preparedRecord: record.preparedRecord, auditedRecord: record) == record)
  #expect(
    try store.completeAfterAudit(
      evidence, preparedRecord: record.preparedRecord, auditedRecord: record) == record)
  #expect(try store.lookupExact(evidence) == .audited(record))

  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.conflict) {
    _ = try store.save(evidence)
  }
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.conflict) {
    let changed = try n3eAuditedRecord(evidence: evidence, terminalExpiry: n3eAuditedAt)
    _ = try store.completeAfterAudit(
      evidence, preparedRecord: changed.preparedRecord, auditedRecord: changed)
  }
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.conflict) {
    _ = try store.lookupExact(try n3eAuditedRecoveryEvidence(worktreeByte: 0xab))
  }
}

@Test("N3-E3c-1 restart retries the terminal receipt without restoring authority")
func n3eAuditedRecoveryRestartHasExactRetryAndNoAuthority() throws {
  let (root, path) = try n3eAuditedRecoveryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }
  let evidence = try n3eAuditedRecoveryEvidence()
  let record = try n3eAuditedRecord(evidence: evidence)
  let firstStore = try NativeAgentSessionConsumeRecoveryStore(path: path)
  _ = try firstStore.save(evidence)
  _ = try n3eComplete(firstStore, evidence: evidence, record: record)

  // Reopening the store returns the same terminal bytes without reconstructing
  // local authority. Coordinator tests separately cover exact Cloud recovery.
  let restartedStore = try NativeAgentSessionConsumeRecoveryStore(path: path)
  #expect(try restartedStore.lookupExact(evidence) == .audited(record))
  #expect(try restartedStore.lookupExact(evidence) == .audited(record))

  let binding = try n3eAuditedBinding()
  let restartedRegistry = NativeAgentSessionRegistry()
  #expect(throws: NativeAgentSessionRegistryError.sessionMissing) {
    _ = try restartedRegistry.status(
      sessionID: n3eAuditedSessionID,
      connectionTokenIdentity: n3eAuditedToken,
      binding: binding,
      wallClock: NativeAgentWallClockValue(millisecondsSinceUnixEpoch: n3eAuditedAt),
      monotonicClock: try NativeAgentMonotonicClockValue(
        nanoseconds: 1, bootIdentity: "restarted"))
  }
}

@Test("N3-E3c-1 malformed terminal bytes fail closed after restart")
func n3eAuditedRecoveryRestartRejectsMalformedTerminalRecord() throws {
  let (root, path) = try n3eAuditedRecoveryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }
  let evidence = try n3eAuditedRecoveryEvidence()
  let record = try n3eAuditedRecord(evidence: evidence)
  let store = try NativeAgentSessionConsumeRecoveryStore(path: path)
  _ = try store.save(evidence)
  _ = try n3eComplete(store, evidence: evidence, record: record)

  var text = try String(contentsOfFile: path, encoding: .utf8)
  text = text.replacingOccurrences(
    of: "\"state\":\"audited\"",
    with: "\"state\":\"audited\",\"unknown\":1",
    options: [], range: nil)
  try Data(text.utf8).write(to: URL(fileURLWithPath: path), options: .atomic)
  try FileManager.default.setAttributes(
    [.posixPermissions: 0o600], ofItemAtPath: path)
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.invalidState) {
    _ = try NativeAgentSessionConsumeRecoveryStore(path: path)
  }
}
