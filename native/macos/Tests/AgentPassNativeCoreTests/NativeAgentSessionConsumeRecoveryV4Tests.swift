import CryptoKit
import Foundation
import Testing

@testable import AgentPassNativeCore

private let v4Organization = "33333333-3333-4333-8333-333333333333"
private let v4Device = "44444444-4444-4444-8444-444444444444"
private let v4Agent = "55555555-5555-4555-8555-555555555555"
private let v4Session = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

private func v4Directory() throws -> (root: URL, path: String) {
  let requestedRoot = FileManager.default.temporaryDirectory
    .appendingPathComponent("agentpass-recovery-v4-\(UUID().uuidString)")
  try FileManager.default.createDirectory(
    at: requestedRoot,
    withIntermediateDirectories: true,
    attributes: [.posixPermissions: 0o700])
  let canonicalPath = requestedRoot.path.hasPrefix("/var/")
    ? "/private\(requestedRoot.path)" : requestedRoot.path
  let root = URL(fileURLWithPath: canonicalPath, isDirectory: true)
  return (root, root.appendingPathComponent("consume-recovery-v4.json").path)
}

private func v4Evidence(
  expiry: Int64 = 2_000_000,
  transactionByte: UInt8 = 0x1a,
  worktreeByte: UInt8 = 0x2a
) throws -> NativeAgentSessionConsumeRecoveryV4Evidence {
  let base = try NativeAgentSessionConsumeRecoveryEvidence(
    organizationID: v4Organization,
    deviceID: v4Device,
    agentID: v4Agent,
    adapterKind: .claudeCode,
    grantProofDigest: Data(repeating: 0x0a, count: 32),
    processBindingDigest: Data(repeating: 0x0b, count: 32),
    ancestryBindingDigest: Data(repeating: 0x0c, count: 32),
    worktreeBindingDigest: Data(repeating: worktreeByte, count: 32),
    controlSequence: 7,
    authorityGeneration: 8,
    keyGeneration: 9,
    recoveryExpiresAtMilliseconds: expiry)
  return try NativeAgentSessionConsumeRecoveryV4Evidence(
    evidence: base, transactionDigest: Data(repeating: transactionByte, count: 32))
}

private func v4Prepared(
  _ evidence: NativeAgentSessionConsumeRecoveryV4Evidence,
  digestByte: UInt8 = 0x30,
  expiry: Int64? = nil
) throws -> NativeAgentSessionConsumeRecoveryV4PreparedRecord {
  try NativeAgentSessionConsumeRecoveryV4PreparedRecord(
    evidence: evidence,
    sessionID: v4Session,
    sessionDigest: Data(repeating: digestByte, count: 32),
    resultDigest: Data(repeating: digestByte &+ 1, count: 32),
    auditEvidenceDigest: Data(repeating: digestByte &+ 2, count: 32),
    expiresAtMilliseconds: expiry)
}

private func v4Terminal(
  _ prepared: NativeAgentSessionConsumeRecoveryV4PreparedRecord,
  outcome: NativeAgentSessionConsumeRecoveryV4Outcome,
  commitReceiptDigest: Data? = nil,
  auditByte: UInt8 = 0x40
) throws -> NativeAgentSessionConsumeRecoveryV4AuditedTerminalRecord {
  try NativeAgentSessionConsumeRecoveryV4AuditedTerminalRecord(
    preparedRecord: prepared,
    outcome: outcome,
    commitReceiptDigest: commitReceiptDigest,
    auditDigest: Data(repeating: auditByte, count: 32))
}

@Test("v4 persists exact prepared, commit receipt, and activated audit states")
func v4PersistsExactTransactionAndActivatedTerminal() throws {
  let location = try v4Directory()
  defer { try? FileManager.default.removeItem(at: location.root) }

  let evidence = try v4Evidence()
  let prepared = try v4Prepared(evidence)
  let receipt = try NativeAgentSessionConsumeRecoveryV4CommitReceipt(
    preparedRecord: prepared, commitReceiptDigest: Data(repeating: 0x50, count: 32))
  let terminal = try v4Terminal(
    prepared, outcome: .activated, commitReceiptDigest: receipt.commitReceiptDigest)
  let store = try NativeAgentSessionConsumeRecoveryV4Store(path: location.path)

  _ = try store.save(evidence)
  #expect(try store.prepareForActivation(evidence, preparedRecord: prepared) == prepared)
  #expect(try store.lookupExact(evidence) == .auditPrepared(prepared))
  #expect(
    try store.recordCommitReceipt(
      evidence, preparedRecord: prepared, commitReceipt: receipt) == receipt)
  #expect(try store.lookupExact(evidence) == .commitReceipt(receipt))
  #expect(
    try store.completeAfterAudit(
      evidence, preparedRecord: prepared, auditedRecord: terminal) == terminal)
  #expect(try store.completeAfterAudit(
    evidence, preparedRecord: prepared, auditedRecord: terminal) == terminal)

  let bytes = try Data(contentsOf: URL(fileURLWithPath: location.path))
  #expect(bytes.last == 0x0a)
  let payload = Data(bytes.dropLast())
  let object = try NativeStrictJSON.object(from: payload, maxBytes: 256 * 1024, maxDepth: 8)
  #expect(try NativeStrictJSON.data(object) == payload)
  #expect(object["version"] as? Int == 4)
  let records = try #require(object["records"] as? [[String: Any]])
  let record = try #require(records.first)
  #expect(record["state"] as? String == "audited")
  #expect(record["outcome"] as? String == "activated")
  #expect(record["transaction_sha256"] as? String == String(repeating: "1a", count: 32))
  #expect(record["commit_receipt_sha256"] as? String == String(repeating: "50", count: 32))
  #expect(!record.keys.contains(where: { $0.localizedCaseInsensitiveContains("lease") }))
  #expect(!record.keys.contains(where: { $0.localizedCaseInsensitiveContains("token") }))
  #expect(!record.keys.contains(where: { $0.localizedCaseInsensitiveContains("path") }))
  #expect(!record.keys.contains(where: { $0.localizedCaseInsensitiveContains("secret") }))

  let restarted = try NativeAgentSessionConsumeRecoveryV4Store(path: location.path)
  #expect(try restarted.lookupExact(evidence) == .audited(terminal))
}

@Test("v4 terminal outcomes are closed and receipt rules are exact")
func v4SupportsAbortedAndOutcomeUnknownWithoutAuthorityReconstruction() throws {
  let abortedLocation = try v4Directory()
  defer { try? FileManager.default.removeItem(at: abortedLocation.root) }
  let abortedEvidence = try v4Evidence(transactionByte: 0x2b)
  let abortedPrepared = try v4Prepared(abortedEvidence)
  let aborted = try v4Terminal(abortedPrepared, outcome: .aborted)
  let abortedStore = try NativeAgentSessionConsumeRecoveryV4Store(path: abortedLocation.path)
  _ = try abortedStore.save(abortedEvidence)
  _ = try abortedStore.prepareForActivation(abortedEvidence, preparedRecord: abortedPrepared)
  #expect(
    try abortedStore.completeAfterAudit(
      abortedEvidence, preparedRecord: abortedPrepared, auditedRecord: aborted) == aborted)

  let unknownLocation = try v4Directory()
  defer { try? FileManager.default.removeItem(at: unknownLocation.root) }
  let unknownEvidence = try v4Evidence(transactionByte: 0x3c)
  let unknownPrepared = try v4Prepared(unknownEvidence)
  let unknown = try v4Terminal(unknownPrepared, outcome: .outcomeUnknown)
  let unknownStore = try NativeAgentSessionConsumeRecoveryV4Store(path: unknownLocation.path)
  _ = try unknownStore.save(unknownEvidence)
  _ = try unknownStore.prepareForActivation(unknownEvidence, preparedRecord: unknownPrepared)
  #expect(
    try unknownStore.completeAfterAudit(
      unknownEvidence, preparedRecord: unknownPrepared, auditedRecord: unknown) == unknown)

  let receiptUnknownLocation = try v4Directory()
  defer { try? FileManager.default.removeItem(at: receiptUnknownLocation.root) }
  let receiptUnknownEvidence = try v4Evidence(transactionByte: 0x4d)
  let receiptUnknownPrepared = try v4Prepared(receiptUnknownEvidence)
  let receiptUnknownReceipt = try NativeAgentSessionConsumeRecoveryV4CommitReceipt(
    preparedRecord: receiptUnknownPrepared,
    commitReceiptDigest: Data(repeating: 0x51, count: 32))
  let receiptUnknown = try v4Terminal(
    receiptUnknownPrepared,
    outcome: .outcomeUnknown,
    commitReceiptDigest: receiptUnknownReceipt.commitReceiptDigest)
  let receiptUnknownStore = try NativeAgentSessionConsumeRecoveryV4Store(
    path: receiptUnknownLocation.path)
  _ = try receiptUnknownStore.save(receiptUnknownEvidence)
  _ = try receiptUnknownStore.prepareForActivation(
    receiptUnknownEvidence, preparedRecord: receiptUnknownPrepared)
  _ = try receiptUnknownStore.recordCommitReceipt(
    receiptUnknownEvidence,
    preparedRecord: receiptUnknownPrepared,
    commitReceipt: receiptUnknownReceipt)
  #expect(
    try receiptUnknownStore.completeAfterAudit(
      receiptUnknownEvidence,
      preparedRecord: receiptUnknownPrepared,
      auditedRecord: receiptUnknown) == receiptUnknown)

  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.invalidEvidence) {
    _ = try v4Terminal(abortedPrepared, outcome: .activated)
  }
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.invalidEvidence) {
    _ = try v4Terminal(
      abortedPrepared, outcome: .aborted, commitReceiptDigest: Data(repeating: 1, count: 32))
  }
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.conflict) {
    _ = try abortedStore.completeAfterAudit(
      abortedEvidence,
      preparedRecord: abortedPrepared,
      auditedRecord: try v4Terminal(
        abortedPrepared,
        outcome: .activated,
        commitReceiptDigest: Data(repeating: 2, count: 32)))
  }
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.conflict) {
    _ = try unknownStore.completeAfterAudit(
      unknownEvidence,
      preparedRecord: unknownPrepared,
      auditedRecord: try v4Terminal(
        unknownPrepared,
        outcome: .outcomeUnknown,
        commitReceiptDigest: Data(repeating: 3, count: 32)))
  }
  #expect(try abortedStore.lookupExact(abortedEvidence) == .audited(aborted))
  #expect(try unknownStore.lookupExact(unknownEvidence) == .audited(unknown))
  #expect(try receiptUnknownStore.lookupExact(receiptUnknownEvidence) == .audited(receiptUnknown))
}

@Test("v4 rejects transaction, receipt, state, expiry, and encoding substitutions")
func v4ExactConflictExpiryAndTamperChecks() throws {
  let location = try v4Directory()
  defer { try? FileManager.default.removeItem(at: location.root) }
  let evidence = try v4Evidence(expiry: 1_500_000)
  let prepared = try v4Prepared(evidence, expiry: 1_400_000)
  let receipt = try NativeAgentSessionConsumeRecoveryV4CommitReceipt(
    preparedRecord: prepared, commitReceiptDigest: Data(repeating: 0x61, count: 32))
  let store = try NativeAgentSessionConsumeRecoveryV4Store(path: location.path)
  _ = try store.save(evidence, nowMilliseconds: 1_000_000)
  _ = try store.prepareForActivation(evidence, preparedRecord: prepared)

  let changedTransaction = try v4Evidence(expiry: 1_600_000, transactionByte: 0x62)
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.conflict) {
    _ = try store.lookupExact(changedTransaction)
  }
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.conflict) {
    _ = try store.save(changedTransaction)
  }
  let changedPrepared = try v4Prepared(evidence, digestByte: 0x70)
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.conflict) {
    _ = try store.prepareForActivation(evidence, preparedRecord: changedPrepared)
  }
  #expect(try store.recordCommitReceipt(
    evidence, preparedRecord: prepared, commitReceipt: receipt) == receipt)
  let changedReceipt = try NativeAgentSessionConsumeRecoveryV4CommitReceipt(
    preparedRecord: prepared, commitReceiptDigest: Data(repeating: 0x71, count: 32))
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.conflict) {
    _ = try store.recordCommitReceipt(
      evidence, preparedRecord: prepared, commitReceipt: changedReceipt)
  }
  #expect(try store.pruneExpired(nowMilliseconds: 1_400_000) == 1)
  #expect(try store.lookupExact(evidence) == .missing)

  let activeLocation = try v4Directory()
  defer { try? FileManager.default.removeItem(at: activeLocation.root) }
  let activeEvidence = try v4Evidence(transactionByte: 0x72)
  let activePrepared = try v4Prepared(activeEvidence)
  let activeStore = try NativeAgentSessionConsumeRecoveryV4Store(path: activeLocation.path)
  _ = try activeStore.save(activeEvidence)
  _ = try activeStore.prepareForActivation(activeEvidence, preparedRecord: activePrepared)
  _ = try activeStore.recordCommitReceipt(
    activeEvidence,
    preparedRecord: activePrepared,
    commitReceipt: try NativeAgentSessionConsumeRecoveryV4CommitReceipt(
      preparedRecord: activePrepared, commitReceiptDigest: Data(repeating: 0x73, count: 32)))

  let current = try String(contentsOf: URL(fileURLWithPath: activeLocation.path), encoding: .utf8)
  let nonCanonical = current.replacingOccurrences(of: "\n", with: " \n")
  try Data(nonCanonical.utf8).write(to: URL(fileURLWithPath: activeLocation.path))
  try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: activeLocation.path)
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.invalidState) {
    _ = try NativeAgentSessionConsumeRecoveryV4Store(path: activeLocation.path)
  }
}

@Test("v4 never reinterprets a v3 file, and v3 never decodes v4")
func v4AndV3FormatsAreNonInterpreting() throws {
  let location = try v4Directory()
  defer { try? FileManager.default.removeItem(at: location.root) }
  let base = try NativeAgentSessionConsumeRecoveryEvidence(
    organizationID: v4Organization,
    deviceID: v4Device,
    agentID: v4Agent,
    adapterKind: .claudeCode,
    grantProofDigest: Data(repeating: 1, count: 32),
    processBindingDigest: Data(repeating: 2, count: 32),
    ancestryBindingDigest: Data(repeating: 3, count: 32),
    worktreeBindingDigest: Data(repeating: 4, count: 32),
    controlSequence: 1,
    authorityGeneration: 1,
    keyGeneration: 1,
    recoveryExpiresAtMilliseconds: 2_000_000)
  _ = try NativeAgentSessionConsumeRecoveryStore(path: location.path).save(base)
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.invalidState) {
    _ = try NativeAgentSessionConsumeRecoveryV4Store(path: location.path)
  }

  try FileManager.default.removeItem(atPath: location.path)
  let v4 = try NativeAgentSessionConsumeRecoveryV4Evidence(
    evidence: base, transactionDigest: Data(repeating: 5, count: 32))
  _ = try NativeAgentSessionConsumeRecoveryV4Store(path: location.path).save(v4)
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.invalidState) {
    _ = try NativeAgentSessionConsumeRecoveryStore(path: location.path)
  }
}

@Test("v4 transaction digest helper is deterministic and fixed size")
func v4TransactionDigestIsExact() throws {
  let bytes = Data("canonical-transaction".utf8)
  #expect(
    NativeAgentSessionConsumeRecoveryV4Evidence.digest(of: bytes)
      == Data(SHA256.hash(data: bytes)))
  #expect(throws: NativeAgentSessionConsumeRecoveryStoreError.invalidEvidence) {
    _ = try NativeAgentSessionConsumeRecoveryV4Evidence(
      evidence: try v4Evidence().evidence, transactionDigest: Data(repeating: 1, count: 31))
  }
}
