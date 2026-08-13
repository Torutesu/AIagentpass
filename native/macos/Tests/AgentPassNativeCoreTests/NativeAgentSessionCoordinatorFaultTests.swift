import CryptoKit
import Foundation
import Testing

@testable import AgentPassNativeCore

// N3-E lane 2 deliberately keeps all fault injection in this file.  The
// fakes expose only effects which the Coordinator's public protocols expose:
// call counts, consumed inputs, returned errors, and registry/audit state.

private enum N3EFault: Error, Sendable {
  case injected
}

private let n3eAgentID = "33333333-3333-4333-8333-333333333333"
private let n3eDeviceID = "44444444-4444-4444-8444-444444444444"
private let n3eOrganizationID = "66666666-6666-4666-8666-666666666666"
private let n3eSessionID = "11111111-1111-4111-8111-111111111111"
private let n3eOtherSessionID = "22222222-2222-4222-8222-222222222222"
private let n3eToken = String(repeating: "a", count: 64)
private let n3eOtherToken = String(repeating: "b", count: 64)
private let n3eWall = Int64(1_786_615_200_000)
private let n3eProof = Data(repeating: 0xee, count: 32)

private struct N3ERandom: NativeAgentRandomBytesGenerating {
  let byte: UInt8

  func randomBytes(count: Int) throws -> Data {
    Data(repeating: byte, count: count)
  }
}

private final class N3EWallClock: NativeAgentWallClock, @unchecked Sendable {
  private let lock = NSLock()
  private var value: NativeAgentWallClockValue
  private var failingCalls: Set<Int> = []
  private(set) var calls = 0

  init(_ milliseconds: Int64) {
    value = NativeAgentWallClockValue(millisecondsSinceUnixEpoch: milliseconds)
  }

  func sample() throws -> NativeAgentWallClockValue {
    try lock.withLock {
      calls += 1
      if failingCalls.remove(calls) != nil { throw N3EFault.injected }
      return value
    }
  }

  func set(_ milliseconds: Int64) {
    lock.withLock { value = NativeAgentWallClockValue(millisecondsSinceUnixEpoch: milliseconds) }
  }

  func fail(call: Int) {
    _ = lock.withLock { failingCalls.insert(call) }
  }
}

private final class N3EMonotonicClock: NativeAgentMonotonicClock, @unchecked Sendable {
  private let lock = NSLock()
  private var nanoseconds: UInt64
  private var bootIdentity: String
  private var bootByCall: [Int: String] = [:]
  private var failingCalls: Set<Int> = []
  private(set) var calls = 0

  init(_ nanoseconds: UInt64, bootIdentity: String = "boot") {
    self.nanoseconds = nanoseconds
    self.bootIdentity = bootIdentity
  }

  func sample() throws -> NativeAgentMonotonicClockValue {
    try lock.withLock {
      calls += 1
      if failingCalls.remove(calls) != nil { throw N3EFault.injected }
      let boot = bootByCall[calls] ?? bootIdentity
      return try NativeAgentMonotonicClockValue(nanoseconds: nanoseconds, bootIdentity: boot)
    }
  }

  func set(nanoseconds: UInt64, bootIdentity: String? = nil) {
    lock.withLock {
      self.nanoseconds = nanoseconds
      if let bootIdentity { self.bootIdentity = bootIdentity }
    }
  }

  func setBoot(forCall call: Int, to bootIdentity: String) {
    lock.withLock { bootByCall[call] = bootIdentity }
  }

  func fail(call: Int) {
    _ = lock.withLock { failingCalls.insert(call) }
  }
}

private final class N3EConnection: @unchecked Sendable {
  private let lock = NSLock()
  private var failingCalls: Set<Int> = []
  private(set) var calls = 0
  var onValidate: (@Sendable () -> Void)?

  func validate() throws {
    let (shouldFail, callback) = lock.withLock { () -> (Bool, (@Sendable () -> Void)?) in
      calls += 1
      return (failingCalls.remove(calls) != nil, onValidate)
    }
    callback?()
    if shouldFail { throw N3EFault.injected }
  }

  func fail(call: Int) {
    _ = lock.withLock { failingCalls.insert(call) }
  }
}

private final class N3EBindingObserver: NativeAgentSessionBindingObserving,
  @unchecked Sendable
{
  private let lock = NSLock()
  private var value: NativeAgentSessionBinding
  private var failuresRemaining = 0
  private(set) var calls = 0
  var onObserve: (@Sendable () -> Void)?

  init(_ value: NativeAgentSessionBinding) {
    self.value = value
  }

  func observeSessionBinding(agentID: String) throws -> NativeAgentSessionBinding {
    let result: (NativeAgentSessionBinding, Bool, (@Sendable () -> Void)?) = lock.withLock {
      calls += 1
      let shouldFail = failuresRemaining > 0
      if shouldFail { failuresRemaining -= 1 }
      return (value, shouldFail, onObserve)
    }
    result.2?()
    if result.1 || result.0.agentID != agentID {
      throw N3EFault.injected
    }
    return result.0
  }

  func failNext(_ count: Int = 1) {
    lock.withLock { failuresRemaining += count }
  }

  func replace(_ value: NativeAgentSessionBinding) {
    lock.withLock { self.value = value }
  }
}

private enum N3EGrantAmbiguity: CaseIterable {
  case beforeCommit
  case afterCommitResponseLost
}

private final class N3EGrantConsumer: NativeAgentGrantLeaseConsuming, @unchecked Sendable {
  private let lock = NSLock()
  private let lease: NativeAgentVerifiedCloudLease
  private var ambiguity: N3EGrantAmbiguity?
  private(set) var calls = 0
  private(set) var commitCount = 0
  private(set) var requests: [NativeAgentGrantConsumptionRequest] = []
  var onCall: (@Sendable () -> Void)?

  init(lease: NativeAgentVerifiedCloudLease, ambiguity: N3EGrantAmbiguity? = nil) {
    self.lease = lease
    self.ambiguity = ambiguity
  }

  func consumeGrant(_ request: NativeAgentGrantConsumptionRequest)
    throws -> NativeAgentVerifiedCloudLease
  {
    let (call, mode, callback) = lock.withLock {
      () -> (Int, N3EGrantAmbiguity?, (@Sendable () -> Void)?) in
      calls += 1
      requests.append(request)
      return (calls, ambiguity, onCall)
    }
    callback?()
    if call == 1, let mode {
      if mode == .afterCommitResponseLost { lock.withLock { commitCount += 1 } }
      lock.withLock { ambiguity = nil }
      throw N3EFault.injected
    }
    lock.withLock {
      if commitCount == 0 { commitCount = 1 }
    }
    return lease
  }
}

private final class N3EAudit: NativeAgentSessionAuditAppending, @unchecked Sendable {
  private let lock = NSLock()
  private var failingActions: Set<NativeAgentSessionAuditAction> = []
  private(set) var events: [NativeAgentSessionAuditEvidence] = []
  private var durableEvents: [NativeAgentSessionAuditEvidence] = []
  var onAppend: (@Sendable (NativeAgentSessionAuditEvidence) -> Void)?

  func appendAgentSessionAudit(_ evidence: NativeAgentSessionAuditEvidence) throws
    -> NativeAgentSessionAuditReceipt
  {
    let (shouldFail, callback, index) = lock.withLock {
      events.append(evidence)
      return (failingActions.contains(evidence.action), onAppend, events.count)
    }
    callback?(evidence)
    if shouldFail { throw N3EFault.injected }
    lock.withLock { durableEvents.append(evidence) }
    return try NativeAgentSessionAuditReceipt(
      evidenceDigest: evidence.evidenceDigest(),
      recordDigest: Data(repeating: UInt8(index), count: 32), recordIndex: index)
  }

  func reconcileAgentSessionActivationAudit(
    _ evidence: NativeAgentSessionAuditEvidence
  ) throws -> NativeAgentSessionAuditReceipt {
    let digest = try evidence.evidenceDigest()
    let existing: (Int, NativeAgentSessionAuditEvidence)? = try lock.withLock {
      let candidates = try durableEvents.enumerated().compactMap {
        index, candidate -> (Int, NativeAgentSessionAuditEvidence)? in
        guard candidate.action == .sessionActivated else { return nil }
        let candidateDigest = try candidate.evidenceDigest()
        if candidate.sessionID == evidence.sessionID || candidateDigest == digest {
          guard candidate == evidence else { throw N3EFault.injected }
          return (index + 1, candidate)
        }
        return nil
      }
      guard candidates.count <= 1 else { throw N3EFault.injected }
      return candidates.first
    }
    if let existing {
      return try NativeAgentSessionAuditReceipt(
        evidenceDigest: digest,
        recordDigest: Data(repeating: UInt8(existing.0), count: 32),
        recordIndex: existing.0)
    }
    return try appendAgentSessionAudit(evidence)
  }

  func reconcileAgentSessionActivationOutcomeAudit(
    _ evidence: NativeAgentSessionAuditEvidence
  ) throws -> NativeAgentSessionAuditReceipt {
    if let existing = try lookupAgentSessionActivationOutcomeAudit(evidence) {
      return existing
    }
    return try appendAgentSessionAudit(evidence)
  }

  func fail(_ action: NativeAgentSessionAuditAction) {
    _ = lock.withLock { failingActions.insert(action) }
  }

  func lookupAgentSessionActivationOutcomeAudit(
    _ evidence: NativeAgentSessionAuditEvidence
  ) throws -> NativeAgentSessionAuditReceipt? {
    let digest = try evidence.evidenceDigest()
    return try lock.withLock {
      let candidates = try durableEvents.enumerated().compactMap {
        index, candidate -> (Int, NativeAgentSessionAuditEvidence)? in
        let activationOutcomes: Set<NativeAgentSessionAuditAction> = [
          .sessionActivated, .sessionActivationAborted,
          .sessionActivationOutcomeUnknown,
        ]
        guard activationOutcomes.contains(candidate.action) else { return nil }
        let candidateDigest = try candidate.evidenceDigest()
        if candidate.sessionID == evidence.sessionID || candidateDigest == digest {
          guard candidate == evidence else { throw N3EFault.injected }
          return (index + 1, candidate)
        }
        return nil
      }
      guard candidates.count <= 1 else { throw N3EFault.injected }
      guard let existing = candidates.first else { return nil }
      return try NativeAgentSessionAuditReceipt(
        evidenceDigest: digest,
        recordDigest: Data(repeating: UInt8(existing.0), count: 32),
        recordIndex: existing.0)
    }
  }
}

private final class N3ERecoveryStore: NativeAgentSessionConsumeRecoveryStoring,
  @unchecked Sendable
{
  private let lock = NSLock()
  private var state: NativeAgentSessionConsumeRecoveryLookup = .missing

  func save(
    _ evidence: NativeAgentSessionConsumeRecoveryEvidence,
    nowMilliseconds: Int64?
  ) throws -> NativeAgentSessionConsumeRecoveryEvidence {
    try lock.withLock {
      switch state {
      case .missing: state = .pending(evidence)
      case .pending(let existing) where existing == evidence: break
      default:
        throw NativeAgentSessionConsumeRecoveryStoreError.conflict
      }
      return evidence
    }
  }

  func prepareForActivation(
    _ expected: NativeAgentSessionConsumeRecoveryEvidence,
    preparedRecord: NativeAgentSessionConsumeRecoveryPreparedRecord
  ) throws -> NativeAgentSessionConsumeRecoveryPreparedRecord {
    try lock.withLock {
      guard preparedRecord.evidence == expected else {
        throw NativeAgentSessionConsumeRecoveryStoreError.conflict
      }
      switch state {
      case .pending(let existing) where existing == expected:
        state = .auditPrepared(preparedRecord)
      case .auditPrepared(let existing) where existing == preparedRecord:
        break
      default:
        throw NativeAgentSessionConsumeRecoveryStoreError.conflict
      }
      return preparedRecord
    }
  }

  func completeAfterAudit(
    _ expected: NativeAgentSessionConsumeRecoveryEvidence,
    preparedRecord: NativeAgentSessionConsumeRecoveryPreparedRecord,
    auditedRecord: NativeAgentSessionConsumeRecoveryAuditedRecord
  ) throws -> NativeAgentSessionConsumeRecoveryAuditedRecord {
    try lock.withLock {
      guard preparedRecord.evidence == expected,
        auditedRecord.preparedRecord == preparedRecord
      else { throw NativeAgentSessionConsumeRecoveryStoreError.conflict }
      switch state {
      case .auditPrepared(let existing) where existing == preparedRecord:
        state = .audited(auditedRecord)
      case .audited(let existing) where existing == auditedRecord:
        break
      default:
        throw NativeAgentSessionConsumeRecoveryStoreError.conflict
      }
      return auditedRecord
    }
  }

  func lookupExact(
    _ expected: NativeAgentSessionConsumeRecoveryEvidence,
    nowMilliseconds: Int64?
  ) throws -> NativeAgentSessionConsumeRecoveryLookup {
    try lock.withLock {
      switch state {
      case .missing: return .missing
      case .pending(let existing):
        guard existing == expected else {
          throw NativeAgentSessionConsumeRecoveryStoreError.conflict
        }
      case .auditPrepared(let existing):
        guard existing.evidence == expected else {
          throw NativeAgentSessionConsumeRecoveryStoreError.conflict
        }
      case .audited(let existing):
        guard existing.evidence == expected else {
          throw NativeAgentSessionConsumeRecoveryStoreError.conflict
        }
      }
      return state
    }
  }

  func abandon(_ expected: NativeAgentSessionConsumeRecoveryEvidence) throws -> Bool {
    try lock.withLock {
      guard case .pending(let existing) = state else {
        if case .missing = state { return false }
        throw NativeAgentSessionConsumeRecoveryStoreError.conflict
      }
      guard existing == expected else {
        throw NativeAgentSessionConsumeRecoveryStoreError.conflict
      }
      state = .missing
      return true
    }
  }
}

private enum N3EV4RecoveryFailurePoint: Hashable, Sendable {
  case prepare
  case receipt
  case terminal
}

private final class N3ERecoveryV4Store: NativeAgentSessionConsumeRecoveryV4Storing,
  @unchecked Sendable
{
  private let lock = NSLock()
  private var failingPoints: Set<N3EV4RecoveryFailurePoint> = []
  private(set) var state: NativeAgentSessionConsumeRecoveryV4Lookup = .missing
  private(set) var prepareCalls = 0
  private(set) var receiptCalls = 0
  private(set) var terminalCalls = 0

  func fail(_ point: N3EV4RecoveryFailurePoint) {
    _ = lock.withLock { failingPoints.insert(point) }
  }

  func save(
    _ evidence: NativeAgentSessionConsumeRecoveryV4Evidence,
    nowMilliseconds: Int64?
  ) throws -> NativeAgentSessionConsumeRecoveryV4Evidence {
    try lock.withLock {
      if let nowMilliseconds {
        guard nowMilliseconds >= 0,
          evidence.recoveryExpiresAtMilliseconds > nowMilliseconds
        else { throw NativeAgentSessionConsumeRecoveryStoreError.invalidEvidence }
      }
      switch state {
      case .missing:
        state = .pending(evidence)
      case .pending(let existing) where existing == evidence:
        break
      default:
        throw NativeAgentSessionConsumeRecoveryStoreError.conflict
      }
      return evidence
    }
  }

  func prepareForActivation(
    _ expected: NativeAgentSessionConsumeRecoveryV4Evidence,
    preparedRecord: NativeAgentSessionConsumeRecoveryV4PreparedRecord
  ) throws -> NativeAgentSessionConsumeRecoveryV4PreparedRecord {
    try lock.withLock {
      prepareCalls += 1
      if failingPoints.remove(.prepare) != nil { throw N3EFault.injected }
      guard preparedRecord.evidence == expected else {
        throw NativeAgentSessionConsumeRecoveryStoreError.conflict
      }
      switch state {
      case .pending(let existing) where existing == expected:
        state = .auditPrepared(preparedRecord)
      case .auditPrepared(let existing) where existing == preparedRecord:
        break
      default:
        throw NativeAgentSessionConsumeRecoveryStoreError.conflict
      }
      return preparedRecord
    }
  }

  func recordCommitReceipt(
    _ expected: NativeAgentSessionConsumeRecoveryV4Evidence,
    preparedRecord: NativeAgentSessionConsumeRecoveryV4PreparedRecord,
    commitReceipt: NativeAgentSessionConsumeRecoveryV4CommitReceipt
  ) throws -> NativeAgentSessionConsumeRecoveryV4CommitReceipt {
    try lock.withLock {
      receiptCalls += 1
      if failingPoints.remove(.receipt) != nil { throw N3EFault.injected }
      guard preparedRecord.evidence == expected,
        commitReceipt.preparedRecord == preparedRecord
      else { throw NativeAgentSessionConsumeRecoveryStoreError.conflict }
      switch state {
      case .auditPrepared(let existing) where existing == preparedRecord:
        state = .commitReceipt(commitReceipt)
      case .commitReceipt(let existing) where existing == commitReceipt:
        break
      default:
        throw NativeAgentSessionConsumeRecoveryStoreError.conflict
      }
      return commitReceipt
    }
  }

  func completeAfterAudit(
    _ expected: NativeAgentSessionConsumeRecoveryV4Evidence,
    preparedRecord: NativeAgentSessionConsumeRecoveryV4PreparedRecord,
    auditedRecord: NativeAgentSessionConsumeRecoveryV4AuditedTerminalRecord
  ) throws -> NativeAgentSessionConsumeRecoveryV4AuditedTerminalRecord {
    try lock.withLock {
      terminalCalls += 1
      if failingPoints.remove(.terminal) != nil { throw N3EFault.injected }
      guard preparedRecord.evidence == expected,
        auditedRecord.preparedRecord == preparedRecord
      else { throw NativeAgentSessionConsumeRecoveryStoreError.conflict }
      switch state {
      case .auditPrepared(let existing)
        where existing == preparedRecord
          && auditedRecord.outcome != .activated
          && auditedRecord.commitReceiptDigest == nil:
        state = .audited(auditedRecord)
      case .commitReceipt(let existing)
        where existing.preparedRecord == preparedRecord
          && (auditedRecord.outcome == .activated
            || auditedRecord.outcome == .outcomeUnknown)
          && auditedRecord.commitReceiptDigest == existing.commitReceiptDigest:
        state = .audited(auditedRecord)
      case .audited(let existing) where existing == auditedRecord:
        break
      default:
        throw NativeAgentSessionConsumeRecoveryStoreError.conflict
      }
      return auditedRecord
    }
  }

  func lookupExact(
    _ expected: NativeAgentSessionConsumeRecoveryV4Evidence,
    nowMilliseconds: Int64?
  ) throws -> NativeAgentSessionConsumeRecoveryV4Lookup {
    try lock.withLock {
      if let nowMilliseconds {
        guard nowMilliseconds >= 0 else {
          throw NativeAgentSessionConsumeRecoveryStoreError.invalidEvidence
        }
        let expiry: Int64? = switch state {
        case .missing: nil
        case .pending(let value): value.recoveryExpiresAtMilliseconds
        case .auditPrepared(let value): value.expiresAtMilliseconds
        case .commitReceipt(let value): value.expiresAtMilliseconds
        case .audited(let value): value.expiresAtMilliseconds
        }
        if let expiry, expiry <= nowMilliseconds { state = .missing }
      }
      switch state {
      case .missing:
        return .missing
      case .pending(let existing):
        guard existing == expected else {
          throw NativeAgentSessionConsumeRecoveryStoreError.conflict
        }
      case .auditPrepared(let existing):
        guard existing.evidence == expected else {
          throw NativeAgentSessionConsumeRecoveryStoreError.conflict
        }
      case .commitReceipt(let existing):
        guard existing.evidence == expected else {
          throw NativeAgentSessionConsumeRecoveryStoreError.conflict
        }
      case .audited(let existing):
        guard existing.evidence == expected else {
          throw NativeAgentSessionConsumeRecoveryStoreError.conflict
        }
      }
      return state
    }
  }

  func pruneExpired(nowMilliseconds: Int64) throws -> Int {
    try lock.withLock {
      guard nowMilliseconds >= 0 else {
        throw NativeAgentSessionConsumeRecoveryStoreError.invalidEvidence
      }
      let expiry: Int64? = switch state {
      case .missing: nil
      case .pending(let value): value.recoveryExpiresAtMilliseconds
      case .auditPrepared(let value): value.expiresAtMilliseconds
      case .commitReceipt(let value): value.expiresAtMilliseconds
      case .audited(let value): value.expiresAtMilliseconds
      }
      guard let expiry, expiry <= nowMilliseconds else { return 0 }
      state = .missing
      return 1
    }
  }
}

private struct N3EFixture {
  let coordinator: NativeAgentSessionCoordinator
  let store: NativeAgentBootstrapChallengeStore
  let bootstrapID: String
  let proof: Data
  let binding: NativeAgentSessionBinding
  let lease: NativeAgentVerifiedCloudLease
  let registry: NativeAgentSessionRegistry
  let connection: N3EConnection
  let observer: N3EBindingObserver
  let grant: N3EGrantConsumer
  let audit: N3EAudit
  let wall: N3EWallClock
  let monotonic: N3EMonotonicClock
  let activationRecoveryStore: any NativeAgentSessionConsumeRecoveryV4Storing
}

private func n3eHex(_ data: Data) -> String {
  data.map { String(format: "%02x", $0) }.joined()
}

private func n3eBinding(worktreeByte: UInt8 = 0xaa) throws -> NativeAgentSessionBinding {
  try NativeAgentSessionBinding(
    agentID: n3eAgentID,
    deviceID: n3eDeviceID,
    processBindingDigest: Data(repeating: 0xbb, count: 32),
    ancestryBindingDigest: Data(repeating: 0xcc, count: 32),
    worktreeBindingDigest: Data(repeating: worktreeByte, count: 32),
    controlSequence: 12,
    authorityGeneration: 7,
    keyGeneration: 99
  )
}

private func n3eLease(
  binding: NativeAgentSessionBinding,
  sessionID: String = n3eSessionID,
  organizationID: String = n3eOrganizationID,
  expiresAt: String = "2026-08-13T10:15:00.000Z"
) throws -> NativeAgentVerifiedCloudLease {
  let object: [String: Any] = [
    "version": 1,
    "type": "agentpass.agent-session-lease",
    "session_id": sessionID,
    "grant_id": "55555555-5555-4555-8555-555555555555",
    "organization_id": organizationID,
    "device_id": n3eDeviceID,
    "agent_id": n3eAgentID,
    "agent_kind": "claude-code",
    "adapter_id": "77777777-7777-4777-8777-777777777777",
    "adapter_version": "1.0.0",
    "process_binding_sha256": n3eHex(binding.processBindingDigest),
    "ancestry_binding_sha256": n3eHex(binding.ancestryBindingDigest),
    "worktree_binding_sha256": n3eHex(binding.worktreeBindingDigest),
    "max_signatures": 2,
    "used_signatures": 0,
    "not_before": "2026-08-13T10:00:00.000Z",
    "expires_at": expiresAt,
    "control_sequence": 12,
    "authority_generation": 7,
  ]
  return try NativeAgentLeaseCodec.decode(
    NativeStrictJSON.data(object), expectedBinding: binding)
}

private func n3eAuthority(
  globalLimit: Int = 8,
  perAgentLimit: Int = 4,
  perWorktreeLimit: Int = 2
) throws -> NativeAgentRuntimeAuthorityConfiguration {
  let configuration = try NativeAgentRuntimeConfiguration(
    deviceAPIOrigin: URL(string: "https://api.agentpass.test"),
    organizationID: n3eOrganizationID,
    deviceID: n3eDeviceID,
    deviceKeyTag: NativeEnrollmentKeyMaterial.fixedApplicationTag,
    signingIntentDirectory: "/var/db/com.agentpass.service/agent-signing-intents",
    globalSessionLimit: globalLimit,
    perAgentSessionLimit: min(perAgentLimit, globalLimit),
    perWorktreeSessionLimit: min(perWorktreeLimit, globalLimit),
    bootstrapAttemptLimit: 3,
    worktreeObservationPolicyVersion: 2
  )
  guard let authority = configuration.authority else { throw N3EFault.injected }
  return authority
}

private func n3eFixture(
  token: String = n3eToken,
  registry: NativeAgentSessionRegistry? = nil,
  globalLimit: Int = 8,
  ambiguity: N3EGrantAmbiguity? = nil,
  randomByte: UInt8 = 1,
  recoveryStore: any NativeAgentSessionConsumeRecoveryStoring = N3ERecoveryStore(),
  activationRecoveryStore: any NativeAgentSessionConsumeRecoveryV4Storing = N3ERecoveryV4Store(),
  grantConsumer: N3EGrantConsumer? = nil,
  auditAppender: N3EAudit? = nil,
  bootstrapIssuedAt: Int64 = n3eWall
) throws -> N3EFixture {
  let binding = try n3eBinding()
  let lease = try n3eLease(binding: binding)
  let store = NativeAgentBootstrapChallengeStore(random: N3ERandom(byte: randomByte))
  let bootHash = n3eHex(Data(SHA256.hash(data: Data("boot".utf8))))
  let connectionBinding = try NativeAgentBootstrapConnectionBinding(
    connectionTokenIdentity: token,
    processBindingHash: n3eHex(binding.processBindingDigest),
    ancestryBindingHash: n3eHex(binding.ancestryBindingDigest),
    bootIdentityHash: bootHash
  )
  let challenge = try store.begin(
    agentID: n3eAgentID,
    adapterKind: .claudeCode,
    requestedTTLSeconds: 900,
    clientNonce: Data(repeating: 5, count: 32),
    connectionBinding: connectionBinding,
    nowMilliseconds: bootstrapIssuedAt,
    nowMonotonicNanoseconds: 1_000
  )
  let actualRegistry = registry ?? NativeAgentSessionRegistry()
  let connection = N3EConnection()
  let observer = N3EBindingObserver(binding)
  let grant = grantConsumer ?? N3EGrantConsumer(lease: lease, ambiguity: ambiguity)
  let audit = auditAppender ?? N3EAudit()
  let wall = N3EWallClock(bootstrapIssuedAt + 1_000)
  let monotonic = N3EMonotonicClock(2_000)
  let coordinator = try NativeAgentSessionCoordinator(
    connectionTokenIdentity: token,
    connectionRevalidator: { try connection.validate() },
    bootstrapStore: store,
    bindingObserver: observer,
    grantConsumer: grant,
    recoveryStore: recoveryStore,
    activationRecoveryStore: activationRecoveryStore,
    registry: actualRegistry,
    audit: audit,
    wallClock: wall,
    monotonicClock: monotonic,
    random: N3ERandom(byte: 9),
    authority: try n3eAuthority(globalLimit: globalLimit)
  )
  return N3EFixture(
    coordinator: coordinator,
    store: store,
    bootstrapID: challenge.bootstrapID,
    proof: n3eProof,
    binding: binding,
    lease: lease,
    registry: actualRegistry,
    connection: connection,
    observer: observer,
    grant: grant,
    audit: audit,
    wall: wall,
    monotonic: monotonic,
    activationRecoveryStore: activationRecoveryStore
  )
}

private func n3eDirectStatus(
  _ fixture: N3EFixture,
  token: String = n3eToken,
  sessionID: String = n3eSessionID
) throws -> NativeAgentSessionRegistryStatus {
  try fixture.registry.status(
    sessionID: sessionID,
    connectionTokenIdentity: token,
    binding: fixture.binding,
    wallClock: NativeAgentWallClockValue(millisecondsSinceUnixEpoch: n3eWall + 2_000),
    monotonicClock: try NativeAgentMonotonicClockValue(
      nanoseconds: 3_000, bootIdentity: "boot")
  )
}

@Test("N3-E table: connection and binding faults preserve challenge effects")
func n3eConnectionAndBindingFaults() throws {
  enum Scenario: CaseIterable {
    case connectionBeforeReobserve
    case bindingAfterChallengeConsume
  }

  for scenario in Scenario.allCases {
    let fixture = try n3eFixture()
    switch scenario {
    case .connectionBeforeReobserve:
      fixture.connection.fail(call: 1)
      #expect(throws: NativeAgentSessionCoordinatorError.connectionDenied) {
        _ = try fixture.coordinator.start(
          bootstrapID: fixture.bootstrapID, proof: fixture.proof)
      }
      #expect(fixture.grant.calls == 0)
      #expect(throws: NativeAgentSessionCoordinatorError.invalidated) {
        _ = try fixture.coordinator.start(
          bootstrapID: fixture.bootstrapID, proof: fixture.proof)
      }

    case .bindingAfterChallengeConsume:
      fixture.observer.failNext()
      #expect(throws: NativeAgentSessionCoordinatorError.bindingDenied) {
        _ = try fixture.coordinator.start(
          bootstrapID: fixture.bootstrapID, proof: fixture.proof)
      }
      #expect(fixture.grant.calls == 0)
      // consume() removes the challenge before binding observation; there is
      // no exposed retry path after this ambiguity.
      #expect(throws: NativeAgentSessionCoordinatorError.challengeDenied) {
        _ = try fixture.coordinator.start(
          bootstrapID: fixture.bootstrapID, proof: fixture.proof)
      }
    }
  }
}

@Test("N3-E table: Grant pre/post-commit ambiguity retries the exact request")
func n3eGrantAmbiguityIsExactRetry() throws {
  for ambiguity in N3EGrantAmbiguity.allCases {
    let fixture = try n3eFixture(ambiguity: ambiguity)
    #expect(throws: NativeAgentSessionCoordinatorError.grantDenied) {
      _ = try fixture.coordinator.start(
        bootstrapID: fixture.bootstrapID, proof: fixture.proof)
    }
    let result = try fixture.coordinator.start(
      bootstrapID: fixture.bootstrapID, proof: fixture.proof)
    #expect(result.status.state == .active)
    #expect(fixture.grant.calls == 2)
    #expect(fixture.grant.requests.count == 2)
    #expect(fixture.grant.requests[0] == fixture.grant.requests[1])
    #expect(fixture.grant.commitCount == 1)
    #expect(try n3eDirectStatus(fixture).state == .active)
  }
}

@Test("N3-E3c-1c binding drift before hidden commit or publish never exposes authority")
func n3eActivationRevalidatesBindingAtCommitAndPublish() throws {
  for driftValidationCall in [2, 3] {
    let fixture = try n3eFixture()
    fixture.connection.onValidate = { [weak connection = fixture.connection, weak observer = fixture.observer] in
      guard connection?.calls == driftValidationCall,
        let changed = try? n3eBinding(worktreeByte: UInt8(0xaa + driftValidationCall))
      else { return }
      observer?.replace(changed)
    }

    #expect(throws: NativeAgentSessionCoordinatorError.bindingDenied) {
      _ = try fixture.coordinator.start(
        bootstrapID: fixture.bootstrapID, proof: fixture.proof)
    }
    #expect(throws: NativeAgentSessionRegistryError.sessionMissing) {
      _ = try n3eDirectStatus(fixture)
    }
  }
}

@Test("N3-E table: activation clock faults remain bounded and retryable")
func n3eActivationClockFaults() throws {
  enum ClockKind {
    case wall
    case monotonic
  }
  struct Scenario {
    let kind: ClockKind
    let call: Int
    let error: NativeAgentSessionCoordinatorError
  }
  let scenarios = [
    Scenario(kind: .wall, call: 1, error: .activationDenied),
    Scenario(kind: .monotonic, call: 1, error: .activationDenied),
    Scenario(kind: .wall, call: 2, error: .activationDenied),
    Scenario(kind: .monotonic, call: 2, error: .activationDenied),
  ]

  for scenario in scenarios {
    let fixture = try n3eFixture()
    switch scenario.kind {
    case .wall: fixture.wall.fail(call: scenario.call)
    case .monotonic: fixture.monotonic.fail(call: scenario.call)
    }
    #expect(throws: scenario.error) {
      _ = try fixture.coordinator.start(
        bootstrapID: fixture.bootstrapID, proof: fixture.proof)
    }
    let result = try fixture.coordinator.start(
      bootstrapID: fixture.bootstrapID, proof: fixture.proof)
    #expect(result.status.state == .active)
    #expect(fixture.grant.calls == 1)
  }
}

@Test("N3-E table: registry admission and activation audit are fail closed")
func n3eRegistryAndActivationAuditFaults() throws {
  let auditFailure = try n3eFixture()
  auditFailure.audit.fail(.sessionActivated)
  #expect(throws: NativeAgentSessionCoordinatorError.auditUnavailable) {
    _ = try auditFailure.coordinator.start(
      bootstrapID: auditFailure.bootstrapID, proof: auditFailure.proof)
  }
  #expect(throws: NativeAgentSessionRegistryError.sessionMissing) {
    _ = try n3eDirectStatus(auditFailure)
  }
  #expect(auditFailure.audit.events.map(\.action) == [.sessionActivated])

  let capacityFailure = try n3eFixture(globalLimit: 1)
  let blockingLease = try n3eLease(
    binding: capacityFailure.binding, sessionID: n3eOtherSessionID)
  let blockingDeadline = try NativeAgentSessionDeadline(
    signedWallExpiryMilliseconds: blockingLease.expiresAtMilliseconds,
    wallClock: NativeAgentWallClockValue(millisecondsSinceUnixEpoch: n3eWall + 1_000),
    monotonicClock: try NativeAgentMonotonicClockValue(
      nanoseconds: 2_000, bootIdentity: "boot")
  )
  _ = try capacityFailure.registry.activate(
    lease: blockingLease,
    localLeaseID: "88888888-8888-4888-8888-888888888888",
    connectionTokenIdentity: n3eOtherToken,
    deadline: blockingDeadline,
    globalLimit: 1,
    perAgentLimit: 1,
    perWorktreeLimit: 1
  )
  #expect(throws: NativeAgentSessionCoordinatorError.activationDenied) {
    _ = try capacityFailure.coordinator.start(
      bootstrapID: capacityFailure.bootstrapID, proof: capacityFailure.proof)
  }
  #expect(capacityFailure.audit.events.isEmpty)
  #expect(
    try n3eDirectStatus(
      capacityFailure, token: n3eOtherToken, sessionID: n3eOtherSessionID
    ).state == .active
  )
}

@Test("N3-E table: connection loss during Cloud and audit cannot publish authority")
func n3eConnectionLossDuringCloudAndAudit() throws {
  enum Stage: CaseIterable {
    case cloud
    case audit
  }

  for stage in Stage.allCases {
    let fixture = try n3eFixture()
    switch stage {
    case .cloud:
      fixture.grant.onCall = { [weak coordinator = fixture.coordinator] in
        coordinator?.invalidateConnection()
      }
      #expect(throws: NativeAgentSessionCoordinatorError.invalidated) {
        _ = try fixture.coordinator.start(
          bootstrapID: fixture.bootstrapID, proof: fixture.proof)
      }
      #expect(throws: NativeAgentSessionRegistryError.sessionMissing) {
        _ = try n3eDirectStatus(fixture)
      }

    case .audit:
      fixture.audit.onAppend = { [weak coordinator = fixture.coordinator] evidence in
        if evidence.action == .sessionActivated { coordinator?.invalidateConnection() }
      }
      #expect(throws: NativeAgentSessionCoordinatorError.invalidated) {
        _ = try fixture.coordinator.start(
          bootstrapID: fixture.bootstrapID, proof: fixture.proof)
      }
      #expect(throws: NativeAgentSessionRegistryError.sessionMissing) {
        _ = try n3eDirectStatus(fixture)
      }
      #expect(fixture.audit.events.map(\.action) == [.sessionActivated])
    }
  }
}

@Test("N3-E table: rollback, advance, boot change, and expiry are observable")
func n3eDeadlineFaultsAreTerminalOrLive() throws {
  enum Scenario: CaseIterable {
    case wallRollback
    case wallAdvance
    case wallExpiry
    case monotonicRollback
    case bootChange
  }

  for scenario in Scenario.allCases {
    let fixture = try n3eFixture()
    _ = try fixture.coordinator.start(
      bootstrapID: fixture.bootstrapID, proof: fixture.proof)
    switch scenario {
    case .wallRollback:
      fixture.wall.set(n3eWall)
    case .wallAdvance:
      fixture.wall.set(n3eWall + 2_000)
    case .wallExpiry:
      fixture.wall.set(.max)
    case .monotonicRollback:
      fixture.monotonic.set(nanoseconds: 1_999)
    case .bootChange:
      fixture.monotonic.set(nanoseconds: 3_000, bootIdentity: "other-boot")
    }
    let status = try fixture.coordinator.status(sessionID: n3eSessionID)
    switch scenario {
    case .wallAdvance:
      #expect(status.state == .active)
    case .wallRollback, .wallExpiry, .monotonicRollback, .bootChange:
      #expect(status.state == .expired)
    }
  }
}

@Test("N3-E rejects boot change between bootstrap and deadline samples")
func n3eBootChangeBetweenBootstrapAndDeadlineSamplesIsRejected() throws {
  let fixture = try n3eFixture()
  // consume() samples call 1; deadline construction samples call 2.  The
  // The deadline must remain on the same boot identity captured by bootstrap.
  fixture.monotonic.setBoot(forCall: 2, to: "other-boot")
  #expect(throws: NativeAgentSessionCoordinatorError.bindingDenied) {
    _ = try fixture.coordinator.start(
      bootstrapID: fixture.bootstrapID, proof: fixture.proof)
  }
  #expect(throws: NativeAgentSessionRegistryError.sessionMissing) {
    _ = try n3eDirectStatus(fixture)
  }
}

@Test("N3-E response abort revokes the published local authority")
func n3eResponseAbortCompensates() throws {
  let fixture = try n3eFixture()
  _ = try fixture.coordinator.start(
    bootstrapID: fixture.bootstrapID, proof: fixture.proof)
  fixture.coordinator.abortActivation(sessionID: n3eSessionID)
  #expect(throws: NativeAgentSessionCoordinatorError.sessionDenied) {
    _ = try fixture.coordinator.status(sessionID: n3eSessionID)
  }
  #expect(try n3eDirectStatus(fixture).state == .revoked)
  fixture.coordinator.abortActivation(sessionID: n3eSessionID)
  #expect(try n3eDirectStatus(fixture).state == .revoked)
}

@Test("N3-E cross-connection status and close cannot affect the owner")
func n3eCrossConnectionCannotUseOrCloseSession() throws {
  let owner = try n3eFixture()
  _ = try owner.coordinator.start(
    bootstrapID: owner.bootstrapID, proof: owner.proof)
  let other = try n3eFixture(token: n3eOtherToken, registry: owner.registry)

  #expect(throws: NativeAgentSessionCoordinatorError.sessionDenied) {
    _ = try other.coordinator.status(sessionID: n3eSessionID)
  }
  #expect(throws: NativeAgentSessionCoordinatorError.sessionDenied) {
    _ = try other.coordinator.close(sessionID: n3eSessionID, reason: .completed)
  }
  #expect(try owner.coordinator.status(sessionID: n3eSessionID).state == .active)
  #expect(try n3eDirectStatus(owner).state == .active)
}

@Test("N3-E a fresh coordinator and registry cannot recover active authority")
func n3eFreshCoordinatorRestartHasNoRecoverableLocalAuthority() throws {
  let original = try n3eFixture()
  _ = try original.coordinator.start(
    bootstrapID: original.bootstrapID, proof: original.proof)
  #expect(try n3eDirectStatus(original).state == .active)

  // A daemon restart reconstructs both the coordinator and its deliberately
  // non-Codable in-memory registry.  The old bootstrap is not reintroduced.
  let restarted = try n3eFixture()
  restarted.store.invalidate()
  #expect(throws: NativeAgentSessionCoordinatorError.sessionDenied) {
    _ = try restarted.coordinator.status(sessionID: n3eSessionID)
  }
  #expect(throws: NativeAgentSessionRegistryError.sessionMissing) {
    _ = try n3eDirectStatus(restarted)
  }
  #expect(throws: NativeAgentSessionCoordinatorError.challengeDenied) {
    _ = try restarted.coordinator.start(
      bootstrapID: original.bootstrapID, proof: original.proof)
  }
  #expect(try n3eDirectStatus(original).state == .active)
}

@Test("N3-E restart after Cloud commit converges through durable digest evidence")
func n3eRestartAfterCloudCommitConvergesExactlyWithoutRestoringAuthority() throws {
  let requestedRoot = FileManager.default.temporaryDirectory
    .appendingPathComponent("agentpass-n3e-restart-\(UUID().uuidString)")
  try FileManager.default.createDirectory(
    at: requestedRoot, withIntermediateDirectories: true,
    attributes: [.posixPermissions: 0o700])
  let canonicalPath =
    requestedRoot.path.hasPrefix("/var/")
    ? "/private\(requestedRoot.path)" : requestedRoot.path
  let root = URL(fileURLWithPath: canonicalPath, isDirectory: true)
  defer { try? FileManager.default.removeItem(at: root) }
  let recoveryPath = root.appendingPathComponent("consume-recovery.json").path
  let activationRecoveryPath = root.appendingPathComponent("activation-recovery-v4.json").path
  let firstRecovery = try NativeAgentSessionConsumeRecoveryStore(path: recoveryPath)
  let binding = try n3eBinding()
  let cloud = N3EGrantConsumer(
    lease: try n3eLease(binding: binding), ambiguity: .afterCommitResponseLost)
  let first = try n3eFixture(
    recoveryStore: firstRecovery,
    activationRecoveryStore: try NativeAgentSessionConsumeRecoveryV4Store(
      path: activationRecoveryPath),
    grantConsumer: cloud)

  #expect(throws: NativeAgentSessionCoordinatorError.grantDenied) {
    _ = try first.coordinator.start(bootstrapID: first.bootstrapID, proof: first.proof)
  }
  #expect(cloud.commitCount == 1)
  #expect(throws: NativeAgentSessionRegistryError.sessionMissing) {
    _ = try n3eDirectStatus(first)
  }
  #expect(FileManager.default.fileExists(atPath: recoveryPath))

  let restartedRecovery = try NativeAgentSessionConsumeRecoveryStore(path: recoveryPath)
  let restarted = try n3eFixture(
    randomByte: 2, recoveryStore: restartedRecovery,
    activationRecoveryStore: try NativeAgentSessionConsumeRecoveryV4Store(
      path: activationRecoveryPath),
    grantConsumer: cloud,
    bootstrapIssuedAt: n3eWall + 5_000)
  #expect(restarted.bootstrapID != first.bootstrapID)
  let result = try restarted.coordinator.start(
    bootstrapID: restarted.bootstrapID, proof: restarted.proof)
  #expect(result.status.state == .active)
  #expect(cloud.calls == 2)
  #expect(cloud.commitCount == 1)
  #expect(cloud.requests[0].proof == cloud.requests[1].proof)
  #expect(cloud.requests[0].binding == cloud.requests[1].binding)
  #expect(FileManager.default.fileExists(atPath: recoveryPath))
  let recoveryBytes = try Data(contentsOf: URL(fileURLWithPath: activationRecoveryPath))
  #expect(String(decoding: recoveryBytes, as: UTF8.self).contains("\"state\":\"audited\""))
  #expect(try restarted.coordinator.status(sessionID: n3eSessionID).state == .active)

  let terminalStore = try NativeAgentSessionConsumeRecoveryStore(path: recoveryPath)
  let afterAuditedRestart = try n3eFixture(
    randomByte: 3, recoveryStore: terminalStore,
    activationRecoveryStore: try NativeAgentSessionConsumeRecoveryV4Store(
      path: activationRecoveryPath),
    grantConsumer: cloud,
    bootstrapIssuedAt: n3eWall + 10_000)
  #expect(throws: NativeAgentSessionCoordinatorError.sessionDenied) {
    _ = try afterAuditedRestart.coordinator.start(
      bootstrapID: afterAuditedRestart.bootstrapID, proof: afterAuditedRestart.proof)
  }
  #expect(cloud.calls == 3)
  #expect(cloud.commitCount == 1)
  #expect(afterAuditedRestart.audit.events.isEmpty)
  #expect(throws: NativeAgentSessionRegistryError.sessionMissing) {
    _ = try n3eDirectStatus(afterAuditedRestart)
  }
}

@Test("N3-E3c-1c restart terminalizes a commit-receipt audit failure as outcome unknown")
func n3eCommitReceiptRestartBecomesOutcomeUnknownWithoutAuthority() throws {
  let requestedRoot = FileManager.default.temporaryDirectory
    .appendingPathComponent("agentpass-n3e-audit-reconcile-\(UUID().uuidString)")
  try FileManager.default.createDirectory(
    at: requestedRoot, withIntermediateDirectories: true,
    attributes: [.posixPermissions: 0o700])
  let canonicalPath =
    requestedRoot.path.hasPrefix("/var/")
    ? "/private\(requestedRoot.path)" : requestedRoot.path
  let root = URL(fileURLWithPath: canonicalPath, isDirectory: true)
  defer { try? FileManager.default.removeItem(at: root) }
  let recoveryPath = root.appendingPathComponent("consume-recovery.json").path
  let activationRecoveryPath = root.appendingPathComponent("activation-recovery-v4.json").path
  let binding = try n3eBinding()
  let cloud = N3EGrantConsumer(lease: try n3eLease(binding: binding))
  let audit = N3EAudit()
  audit.fail(.sessionActivated)

  let first = try n3eFixture(
    recoveryStore: try NativeAgentSessionConsumeRecoveryStore(path: recoveryPath),
    activationRecoveryStore: try NativeAgentSessionConsumeRecoveryV4Store(
      path: activationRecoveryPath),
    grantConsumer: cloud, auditAppender: audit)
  #expect(throws: NativeAgentSessionCoordinatorError.auditUnavailable) {
    _ = try first.coordinator.start(bootstrapID: first.bootstrapID, proof: first.proof)
  }
  #expect(cloud.commitCount == 1)
  #expect(audit.events.filter { $0.action == .sessionActivated }.count == 1)
  #expect(
    String(
      decoding: try Data(contentsOf: URL(fileURLWithPath: activationRecoveryPath)),
      as: UTF8.self
    ).contains("\"state\":\"commit_receipt\""))
  #expect(throws: NativeAgentSessionRegistryError.sessionMissing) {
    _ = try n3eDirectStatus(first)
  }

  let restarted = try n3eFixture(
    randomByte: 2,
    recoveryStore: try NativeAgentSessionConsumeRecoveryStore(path: recoveryPath),
    activationRecoveryStore: try NativeAgentSessionConsumeRecoveryV4Store(
      path: activationRecoveryPath),
    grantConsumer: cloud,
    auditAppender: audit,
    bootstrapIssuedAt: n3eWall)
  #expect(throws: NativeAgentSessionCoordinatorError.sessionDenied) {
    _ = try restarted.coordinator.start(
      bootstrapID: restarted.bootstrapID, proof: restarted.proof)
  }
  #expect(cloud.commitCount == 1)
  #expect(cloud.calls == 2)
  #expect(audit.events.filter { $0.action == .sessionActivated }.count == 1)
  #expect(
    audit.events.filter { $0.action == .sessionActivationOutcomeUnknown }.count == 1)
  #expect(
    String(
      decoding: try Data(contentsOf: URL(fileURLWithPath: activationRecoveryPath)),
      as: UTF8.self
    ).contains("\"outcome\":\"outcome_unknown\""))
  #expect(throws: NativeAgentSessionRegistryError.sessionMissing) {
    _ = try n3eDirectStatus(restarted)
  }
}

@Test("N3-E3c-1c v4 durability failures never publish hidden authority")
func n3eV4DurabilityFailureMatrix() throws {
  for point in [
    N3EV4RecoveryFailurePoint.prepare,
    .receipt,
    .terminal,
  ] {
    let activationStore = N3ERecoveryV4Store()
    activationStore.fail(point)
    let fixture = try n3eFixture(activationRecoveryStore: activationStore)
    let expected: NativeAgentSessionCoordinatorError =
      point == .terminal ? .auditUnavailable : .activationDenied
    #expect(throws: expected) {
      _ = try fixture.coordinator.start(
        bootstrapID: fixture.bootstrapID, proof: fixture.proof)
    }
    #expect(throws: NativeAgentSessionRegistryError.sessionMissing) {
      _ = try n3eDirectStatus(fixture)
    }

    switch point {
    case .prepare:
      guard case .pending = activationStore.state else {
        Issue.record("prepare failure must retain only pending v4 evidence")
        continue
      }
      #expect(fixture.audit.events.isEmpty)
      #expect(
        try fixture.coordinator.start(
          bootstrapID: fixture.bootstrapID, proof: fixture.proof
        ).status.state == .active)
    case .receipt:
      guard case .auditPrepared = activationStore.state else {
        Issue.record("receipt failure must retain durable prepared evidence")
        continue
      }
      #expect(fixture.audit.events.isEmpty)
      #expect(throws: NativeAgentSessionCoordinatorError.sessionDenied) {
        _ = try fixture.coordinator.start(
          bootstrapID: fixture.bootstrapID, proof: fixture.proof)
      }
      guard case .audited(let terminal) = activationStore.state else {
        Issue.record("prepared retry must terminalize")
        continue
      }
      #expect(terminal.outcome == .outcomeUnknown)
      #expect(throws: NativeAgentSessionCoordinatorError.challengeDenied) {
        _ = try fixture.coordinator.start(
          bootstrapID: fixture.bootstrapID, proof: fixture.proof)
      }
    case .terminal:
      guard case .commitReceipt = activationStore.state else {
        Issue.record("terminal failure must retain the exact commit receipt")
        continue
      }
      #expect(fixture.audit.events.map(\.action) == [.sessionActivated])
      #expect(throws: NativeAgentSessionCoordinatorError.sessionDenied) {
        _ = try fixture.coordinator.start(
          bootstrapID: fixture.bootstrapID, proof: fixture.proof)
      }
      guard case .audited(let terminal) = activationStore.state else {
        Issue.record("durable success audit must be reused")
        continue
      }
      #expect(terminal.outcome == .activated)
      #expect(fixture.audit.events.map(\.action) == [.sessionActivated])
      #expect(throws: NativeAgentSessionCoordinatorError.challengeDenied) {
        _ = try fixture.coordinator.start(
          bootstrapID: fixture.bootstrapID, proof: fixture.proof)
      }
    }
  }
}
