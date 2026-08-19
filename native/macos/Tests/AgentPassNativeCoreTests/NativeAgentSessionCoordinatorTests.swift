import CryptoKit
import Foundation
import Testing

@testable import AgentPassNativeCore

private let coordinatorAgentID = "33333333-3333-4333-8333-333333333333"
private let coordinatorDeviceID = "44444444-4444-4444-8444-444444444444"
private let coordinatorOrganizationID = "66666666-6666-4666-8666-666666666666"
private let coordinatorSessionID = "11111111-1111-4111-8111-111111111111"
private let coordinatorToken = String(repeating: "a", count: 64)
private let coordinatorWall = Int64(1_786_615_200_000)

private struct CoordinatorRandom: NativeAgentRandomBytesGenerating {
  let byte: UInt8
  func randomBytes(count: Int) throws -> Data { Data(repeating: byte, count: count) }
}

private struct CoordinatorWallClock: NativeAgentWallClock {
  let milliseconds: Int64
  func sample() throws -> NativeAgentWallClockValue {
    NativeAgentWallClockValue(millisecondsSinceUnixEpoch: milliseconds)
  }
}

private struct CoordinatorMonotonicClock: NativeAgentMonotonicClock {
  let nanoseconds: UInt64
  let bootIdentity: String
  func sample() throws -> NativeAgentMonotonicClockValue {
    try NativeAgentMonotonicClockValue(
      nanoseconds: nanoseconds, bootIdentity: bootIdentity)
  }
}

private final class CoordinatorBindingObserver: NativeAgentSessionBindingObserving,
  @unchecked Sendable
{
  private let lock = NSLock()
  private var value: NativeAgentSessionBinding
  init(_ value: NativeAgentSessionBinding) { self.value = value }
  func observeSessionBinding(agentID: String) throws -> NativeAgentSessionBinding {
    let result = lock.withLock { value }
    guard result.agentID == agentID else {
      throw NativeAgentSessionCoordinatorError.bindingDenied
    }
    return result
  }
  func replace(_ value: NativeAgentSessionBinding) { lock.withLock { self.value = value } }
}

private final class CoordinatorGrantConsumer: NativeAgentGrantLeaseConsuming,
  @unchecked Sendable
{
  private let lock = NSLock()
  private var lease: NativeAgentVerifiedCloudLease
  private var failuresRemaining: Int
  private(set) var calls = 0
  init(_ lease: NativeAgentVerifiedCloudLease, failures: Int = 0) {
    self.lease = lease
    failuresRemaining = failures
  }
  func consumeGrant(_ request: NativeAgentGrantConsumptionRequest) throws
    -> NativeAgentVerifiedCloudLease
  {
    return try lock.withLock {
      calls += 1
      if failuresRemaining > 0 {
        failuresRemaining -= 1
        throw NativeAgentGrantLeaseHTTPError.unavailable
      }
      return lease
    }
  }
}

private final class CoordinatorAudit: NativeAgentSessionAuditAppending, @unchecked Sendable {
  private let lock = NSLock()
  var fail = false
  var substituteReceiptEvidence = false
  private(set) var events: [NativeAgentSessionAuditEvidence] = []
  func appendAgentSessionAudit(_ evidence: NativeAgentSessionAuditEvidence) throws
    -> NativeAgentSessionAuditReceipt
  {
    let index = try lock.withLock {
      if fail { throw NativeAgentSessionCoordinatorError.auditUnavailable }
      events.append(evidence)
      return events.count
    }
    return try NativeAgentSessionAuditReceipt(
      evidenceDigest: substituteReceiptEvidence
        ? Data(repeating: 0xff, count: 32) : evidence.evidenceDigest(),
      recordDigest: Data(repeating: UInt8(index), count: 32), recordIndex: index)
  }

  func reconcileAgentSessionActivationAudit(
    _ evidence: NativeAgentSessionAuditEvidence
  ) throws -> NativeAgentSessionAuditReceipt {
    try appendAgentSessionAudit(evidence)
  }

  func lookupAgentSessionActivationOutcomeAudit(
    _ evidence: NativeAgentSessionAuditEvidence
  ) throws -> NativeAgentSessionAuditReceipt? {
    let digest = try evidence.evidenceDigest()
    return try lock.withLock {
      let matches = try events.enumerated().filter {
        try $0.element.evidenceDigest() == digest
          || $0.element.sessionID == evidence.sessionID
      }
      guard matches.count <= 1 else {
        throw NativeAgentSessionCoordinatorError.auditUnavailable
      }
      guard let match = matches.first else { return nil }
      guard match.element == evidence else {
        throw NativeAgentSessionCoordinatorError.auditUnavailable
      }
      return try NativeAgentSessionAuditReceipt(
        evidenceDigest: digest,
        recordDigest: Data(repeating: UInt8(match.offset + 1), count: 32),
        recordIndex: match.offset + 1)
    }
  }
}

private final class CoordinatorRecoveryStore: NativeAgentSessionConsumeRecoveryStoring,
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

private final class CoordinatorRecoveryV4Store: NativeAgentSessionConsumeRecoveryV4Storing,
  @unchecked Sendable
{
  private let lock = NSLock()
  private var state: NativeAgentSessionConsumeRecoveryV4Lookup = .missing

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
        if let expiry, expiry <= nowMilliseconds {
          state = .missing
        }
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

private final class InvalidatingCoordinatorAudit: NativeAgentSessionAuditAppending,
  @unchecked Sendable
{
  private let lock = NSLock()
  weak var coordinator: NativeAgentSessionCoordinator?
  private(set) var events: [NativeAgentSessionAuditEvidence] = []

  func appendAgentSessionAudit(_ evidence: NativeAgentSessionAuditEvidence) throws
    -> NativeAgentSessionAuditReceipt
  {
    let index = lock.withLock {
      events.append(evidence)
      return events.count
    }
    if evidence.action == .sessionActivated {
      coordinator?.invalidateConnection()
    }
    return try NativeAgentSessionAuditReceipt(
      evidenceDigest: evidence.evidenceDigest(),
      recordDigest: Data(repeating: UInt8(index), count: 32),
      recordIndex: index)
  }

  func reconcileAgentSessionActivationAudit(
    _ evidence: NativeAgentSessionAuditEvidence
  ) throws -> NativeAgentSessionAuditReceipt {
    try appendAgentSessionAudit(evidence)
  }

  func lookupAgentSessionActivationOutcomeAudit(
    _ evidence: NativeAgentSessionAuditEvidence
  ) throws -> NativeAgentSessionAuditReceipt? {
    let digest = try evidence.evidenceDigest()
    return try lock.withLock {
      guard let match = try events.enumerated().first(where: {
        try $0.element.evidenceDigest() == digest
          || $0.element.sessionID == evidence.sessionID
      }) else { return nil }
      guard match.element == evidence else {
        throw NativeAgentSessionCoordinatorError.auditUnavailable
      }
      return try NativeAgentSessionAuditReceipt(
        evidenceDigest: digest,
        recordDigest: Data(repeating: UInt8(match.offset + 1), count: 32),
        recordIndex: match.offset + 1)
    }
  }
}

private func coordinatorHex(_ data: Data) -> String {
  data.map { String(format: "%02x", $0) }.joined()
}

private func coordinatorWorktree() throws -> NativeAgentWorktreeBinding {
  let repository = try NativeAgentWorktreeDirectoryIdentity(
    device: 1, inode: 20, generation: 1, ownerUserID: 501, permissions: 0o755)
  let git = try NativeAgentWorktreeDirectoryIdentity(
    device: 1, inode: 21, generation: 1, ownerUserID: 501, permissions: 0o755)
  let remote = try NativeAgentGitRemote(name: "origin", url: "git@example.test:repo.git")
  return try NativeAgentWorktreeBinding(
    layout: .embedded,
    repositoryPath: "/work/repo",
    gitDirectoryPath: "/work/repo/.git",
    commonDirectoryPath: "/work/repo/.git",
    repositoryIdentity: repository,
    gitDirectoryIdentity: git,
    commonDirectoryIdentity: git,
    objectFormat: .sha1,
    head: .branch("feature/native"),
    headObjectID: String(repeating: "a", count: 40),
    headTreeID: String(repeating: "b", count: 40),
    remotes: [remote])
}

private func coordinatorBinding(worktree: UInt8 = 0xaa) throws
  -> NativeAgentSessionBinding
{
  let worktreeDigest = worktree == 0xaa
    ? try coordinatorWorktree().digest
    : Data(repeating: worktree, count: 32)
  return try NativeAgentSessionBinding(
    agentID: coordinatorAgentID, deviceID: coordinatorDeviceID,
    processBindingDigest: Data(repeating: 0xbb, count: 32),
    ancestryBindingDigest: Data(repeating: 0xcc, count: 32),
    worktreeBindingDigest: worktreeDigest,
    controlSequence: 12, authorityGeneration: 7, keyGeneration: 99)
}

private func coordinatorLease(
  binding: NativeAgentSessionBinding,
  organizationID: String = coordinatorOrganizationID,
  expiresAt: String = "2026-08-13T10:15:00.000Z"
) throws -> NativeAgentVerifiedCloudLease {
  let object: [String: Any] = [
    "version": 1, "type": "agentpass.agent-session-lease",
    "session_id": coordinatorSessionID,
    "grant_id": "55555555-5555-4555-8555-555555555555",
    "organization_id": organizationID, "device_id": coordinatorDeviceID,
    "agent_id": coordinatorAgentID, "agent_kind": "claude-code",
    "adapter_id": "77777777-7777-4777-8777-777777777777",
    "adapter_version": "1.0.0",
    "process_binding_sha256": coordinatorHex(binding.processBindingDigest),
    "ancestry_binding_sha256": coordinatorHex(binding.ancestryBindingDigest),
    "worktree_binding_sha256": coordinatorHex(binding.worktreeBindingDigest),
    "max_signatures": 2, "used_signatures": 0,
    "not_before": "2026-08-13T10:00:00.000Z", "expires_at": expiresAt,
    "control_sequence": 12, "authority_generation": 7,
  ]
  return try NativeAgentLeaseCodec.decode(
    NativeStrictJSON.data(object), expectedBinding: binding)
}

private func coordinatorSigningRequest(
  requestID: String = "22222222-2222-4222-8222-222222222222",
  capabilityID: String = "88888888-8888-4888-8888-888888888888",
  nonce: UInt8 = 0x2a
) throws -> AgentPassAgentSignRequest {
  let capability = try NativeStrictJSON.data([
    "version": 1,
    "capability_id": capabilityID,
    "nonce": String(repeating: "N", count: 32),
    "issuer": "agentpass-cloud",
    "key_id": "capability-v1",
    "audience": ["agent_id": coordinatorAgentID, "device_id": coordinatorDeviceID],
    "scope": [
      "operations": ["git.commit.sign"],
      "repositories": ["/work/repo"],
      "branches": ["allow": ["feature/native"], "deny": []],
      "remotes": ["allow": ["git@example.test:repo.git"], "deny": []],
    ],
    "not_before": "2026-08-13T10:00:00.000Z",
    "expires_at": "2026-08-13T10:15:00.000Z",
    "sequence": 1,
    "signature": String(repeating: "A", count: 88),
  ])
  return try #require(AgentPassAgentSignRequest(
    sessionID: coordinatorSessionID,
    requestID: requestID,
    capabilityID: capabilityID,
    capability: capability,
    commitPayload: Data("commit payload".utf8),
    requestNonce: Data(repeating: nonce, count: 16),
    createdAtMilliseconds: coordinatorWall + 1_000))
}

private func coordinatorSigningAuthority(
  request: AgentPassAgentSignRequest,
  binding: NativeAgentSessionBinding
) throws -> NativeSigningTransactionAuthority {
  try NativeSigningTransactionAuthority(
    request: try NativeSigningTransactionRequest(request),
    binding: binding,
    worktree: try coordinatorWorktree(),
    keyLifecycleIdentity: String(repeating: "f", count: 64))
}

private func coordinatorAuthority() throws -> NativeAgentRuntimeAuthorityConfiguration {
  let configuration = try NativeAgentRuntimeConfiguration(
    deviceAPIOrigin: URL(string: "https://api.agentpass.test")!,
    organizationID: coordinatorOrganizationID, deviceID: coordinatorDeviceID,
    deviceKeyTag: NativeEnrollmentKeyMaterial.fixedApplicationTag,
    signingIntentDirectory: "/var/db/com.agentpass.service/agent-signing-intents",
    globalSessionLimit: 8, perAgentSessionLimit: 4, perWorktreeSessionLimit: 2,
    bootstrapAttemptLimit: 3, worktreeObservationPolicyVersion: 2)
  return try #require(configuration.authority)
}

private struct CoordinatorFixture {
  let coordinator: NativeAgentSessionCoordinator
  let bootstrapID: String
  let proof = Data(repeating: 0xee, count: 32)
  let registry: NativeAgentSessionRegistry
  let observer: CoordinatorBindingObserver
  let consumer: CoordinatorGrantConsumer
  let audit: CoordinatorAudit
  let activationRecoveryStore: CoordinatorRecoveryV4Store
}

private func coordinatorFixture(
  auditFails: Bool = false,
  grantFailures: Int = 0,
  leaseOrganizationID: String = coordinatorOrganizationID,
  leaseExpiresAt: String = "2026-08-13T10:15:00.000Z",
  coordinatorBootIdentity: String = "boot"
) throws -> CoordinatorFixture {
  let binding = try coordinatorBinding()
  let store = NativeAgentBootstrapChallengeStore(random: CoordinatorRandom(byte: 1))
  let bootHash = Data(SHA256.hash(data: Data("boot".utf8))).map {
    String(format: "%02x", $0)
  }.joined()
  let connection = try NativeAgentBootstrapConnectionBinding(
    connectionTokenIdentity: coordinatorToken,
    processBindingHash: String(repeating: "b", count: 64),
    ancestryBindingHash: String(repeating: "c", count: 64), bootIdentityHash: bootHash)
  let challenge = try store.begin(
    agentID: coordinatorAgentID, adapterKind: .claudeCode, requestedTTLSeconds: 900,
    clientNonce: Data(repeating: 5, count: 32), connectionBinding: connection,
    nowMilliseconds: coordinatorWall, nowMonotonicNanoseconds: 1_000)
  let observer = CoordinatorBindingObserver(binding)
  let consumer = CoordinatorGrantConsumer(
    try coordinatorLease(
      binding: binding, organizationID: leaseOrganizationID, expiresAt: leaseExpiresAt),
    failures: grantFailures)
  let registry = NativeAgentSessionRegistry()
  let audit = CoordinatorAudit()
  audit.fail = auditFails
  let activationRecoveryStore = CoordinatorRecoveryV4Store()
  let coordinator = try NativeAgentSessionCoordinator(
    connectionTokenIdentity: coordinatorToken, connectionRevalidator: {},
    bootstrapStore: store, bindingObserver: observer, grantConsumer: consumer,
    recoveryStore: CoordinatorRecoveryStore(),
    activationRecoveryStore: activationRecoveryStore,
    registry: registry, audit: audit,
    wallClock: CoordinatorWallClock(milliseconds: coordinatorWall + 1_000),
    monotonicClock: CoordinatorMonotonicClock(
      nanoseconds: 2_000, bootIdentity: coordinatorBootIdentity),
    random: CoordinatorRandom(byte: 9), authority: coordinatorAuthority())
  return CoordinatorFixture(
    coordinator: coordinator, bootstrapID: challenge.bootstrapID, registry: registry,
    observer: observer, consumer: consumer, audit: audit,
    activationRecoveryStore: activationRecoveryStore)
}

@Test func coordinatorStartsStatusesClosesAndReplaysExactResult() throws {
  let fixture = try coordinatorFixture()
  let first = try fixture.coordinator.start(
    bootstrapID: fixture.bootstrapID, proof: fixture.proof)
  let replay = try fixture.coordinator.start(
    bootstrapID: fixture.bootstrapID, proof: fixture.proof)
  #expect(first == replay)
  #expect(first.status.state == .active)
  #expect(fixture.consumer.calls == 1)
  #expect(try fixture.coordinator.status(sessionID: coordinatorSessionID).state == .active)
  #expect(
    try fixture.coordinator.close(sessionID: coordinatorSessionID, reason: .completed).state
      == .closed)
  #expect(fixture.audit.events.map(\.action) == [.sessionActivated, .sessionClosed])
}

@Test func coordinatorSigningHandoffUsesOnlyActiveLeaseAndTracksBudget() throws {
  let fixture = try coordinatorFixture()
  _ = try fixture.coordinator.start(bootstrapID: fixture.bootstrapID, proof: fixture.proof)
  let request = try coordinatorSigningRequest()
  let binding = try coordinatorBinding()
  let authority = try coordinatorSigningAuthority(
    request: request, binding: binding)
  var observedBinding: NativeAgentSessionBinding?
  let handoff = try fixture.coordinator.makeSigningHandoff(request: request) { binding in
    observedBinding = binding
    return authority
  }
  #expect(observedBinding == binding)

  let directory = FileManager.default.temporaryDirectory
    .appendingPathComponent("agentpass-coordinator-signing-\(UUID().uuidString)")
  try FileManager.default.createDirectory(
    at: directory, withIntermediateDirectories: true,
    attributes: [.posixPermissions: 0o700])
  defer { try? FileManager.default.removeItem(at: directory) }
  let transactions = try NativeSigningTransactionStore(
    path: directory.appendingPathComponent("transactions.json").path)
  let adapter = try NativeAgentSessionCoordinatorSigningAdapter(
    handoff: handoff, coordinator: fixture.coordinator, transactionStore: transactions)
  let completed = try adapter.execute { payload in
    #expect(payload == request.commitPayload)
    return Data("verified-signature".utf8)
  }
  #expect(completed.phase == .completed)
  #expect(completed.remainingSignatures == 1)
  #expect(try fixture.coordinator.status(sessionID: coordinatorSessionID).usedSignatures == 1)

  let secondRequest = try coordinatorSigningRequest(
    requestID: "99999999-9999-4999-8999-999999999999",
    capabilityID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    nonce: 0x2b)
  let secondAuthority = try coordinatorSigningAuthority(
    request: secondRequest, binding: binding)
  let secondHandoff = try fixture.coordinator.makeSigningHandoff(
    request: secondRequest) { _ in secondAuthority }
  let secondAdapter = try NativeAgentSessionCoordinatorSigningAdapter(
    handoff: secondHandoff, coordinator: fixture.coordinator, transactionStore: transactions)
  _ = try secondAdapter.execute { _ in Data("second-signature".utf8) }
  #expect(try fixture.coordinator.status(sessionID: coordinatorSessionID).state == .closed)

  #expect(throws: NativeAgentSessionCoordinatorError.sessionDenied) {
    _ = try fixture.coordinator.makeSigningHandoff(request: secondRequest) { _ in nil }
  }
}

@Test func coordinatorSigningHandoffFailsClosedWithoutAuthority() throws {
  let fixture = try coordinatorFixture()
  _ = try fixture.coordinator.start(bootstrapID: fixture.bootstrapID, proof: fixture.proof)
  let request = try coordinatorSigningRequest()
  #expect(throws: NativeAgentSessionCoordinatorError.sessionDenied) {
    _ = try fixture.coordinator.makeSigningHandoff(request: request) { _ in nil }
  }
  _ = try fixture.coordinator.close(sessionID: coordinatorSessionID, reason: .completed)
  #expect(throws: NativeAgentSessionCoordinatorError.sessionDenied) {
    _ = try fixture.coordinator.makeSigningHandoff(request: request) { _ in
      try coordinatorSigningAuthority(request: request, binding: try coordinatorBinding())
    }
  }
}

@Test func coordinatorRejectsConflictingRetryWithoutSecondCloudCall() throws {
  let fixture = try coordinatorFixture()
  _ = try fixture.coordinator.start(bootstrapID: fixture.bootstrapID, proof: fixture.proof)
  #expect(throws: NativeAgentSessionCoordinatorError.challengeDenied) {
    _ = try fixture.coordinator.start(
      bootstrapID: fixture.bootstrapID, proof: Data(repeating: 0xdd, count: 32))
  }
  #expect(fixture.consumer.calls == 1)
}

@Test func coordinatorBindingDriftRevokesBeforeReturningStatus() throws {
  let fixture = try coordinatorFixture()
  _ = try fixture.coordinator.start(bootstrapID: fixture.bootstrapID, proof: fixture.proof)
  fixture.observer.replace(try coordinatorBinding(worktree: 0xab))
  #expect(throws: NativeAgentSessionCoordinatorError.bindingDenied) {
    _ = try fixture.coordinator.status(sessionID: coordinatorSessionID)
  }
  let status = try fixture.registry.status(
    sessionID: coordinatorSessionID, connectionTokenIdentity: coordinatorToken,
    binding: try coordinatorBinding(),
    wallClock: NativeAgentWallClockValue(millisecondsSinceUnixEpoch: coordinatorWall + 2_000),
    monotonicClock: NativeAgentMonotonicClockValue(
      nanoseconds: 3_000, bootIdentity: "boot"))
  #expect(status.state == .revoked)
}

@Test func coordinatorAuditFailureCompensatesActivatedAuthority() throws {
  let fixture = try coordinatorFixture(auditFails: true)
  #expect(throws: NativeAgentSessionCoordinatorError.auditUnavailable) {
    _ = try fixture.coordinator.start(bootstrapID: fixture.bootstrapID, proof: fixture.proof)
  }
  #expect(throws: NativeAgentSessionRegistryError.sessionMissing) {
    _ = try fixture.registry.status(
      sessionID: coordinatorSessionID, connectionTokenIdentity: coordinatorToken,
      binding: try coordinatorBinding(),
      wallClock: NativeAgentWallClockValue(millisecondsSinceUnixEpoch: coordinatorWall + 2_000),
      monotonicClock: NativeAgentMonotonicClockValue(
        nanoseconds: 3_000, bootIdentity: "boot"))
  }
}

@Test func coordinatorRejectsSubstitutedAuditReceiptAndRevokesAuthority() throws {
  let fixture = try coordinatorFixture()
  fixture.audit.substituteReceiptEvidence = true
  #expect(throws: NativeAgentSessionCoordinatorError.auditUnavailable) {
    _ = try fixture.coordinator.start(bootstrapID: fixture.bootstrapID, proof: fixture.proof)
  }
  #expect(fixture.audit.events.map(\.action) == [.sessionActivated])
  #expect(throws: NativeAgentSessionRegistryError.sessionMissing) {
    _ = try fixture.registry.status(
      sessionID: coordinatorSessionID, connectionTokenIdentity: coordinatorToken,
      binding: try coordinatorBinding(),
      wallClock: NativeAgentWallClockValue(millisecondsSinceUnixEpoch: coordinatorWall + 2_000),
      monotonicClock: NativeAgentMonotonicClockValue(
        nanoseconds: 3_000, bootIdentity: "boot"))
  }
}

@Test func coordinatorConnectionInvalidationRevokesOnlyOwnedAuthority() throws {
  let fixture = try coordinatorFixture()
  _ = try fixture.coordinator.start(bootstrapID: fixture.bootstrapID, proof: fixture.proof)
  fixture.coordinator.invalidateConnection()
  let status = try fixture.registry.status(
    sessionID: coordinatorSessionID, connectionTokenIdentity: coordinatorToken,
    binding: try coordinatorBinding(),
    wallClock: NativeAgentWallClockValue(millisecondsSinceUnixEpoch: coordinatorWall + 2_000),
    monotonicClock: NativeAgentMonotonicClockValue(
      nanoseconds: 3_000, bootIdentity: "boot"))
  #expect(status.state == .revoked)
  #expect(throws: NativeAgentSessionCoordinatorError.invalidated) {
    _ = try fixture.coordinator.status(sessionID: coordinatorSessionID)
  }
}

@Test func coordinatorRetriesOnlyTheExactGrantConsumptionAfterTransientFailure() throws {
  let fixture = try coordinatorFixture(grantFailures: 1)
  #expect(throws: NativeAgentSessionCoordinatorError.grantDenied) {
    _ = try fixture.coordinator.start(bootstrapID: fixture.bootstrapID, proof: fixture.proof)
  }
  #expect(throws: NativeAgentSessionCoordinatorError.challengeDenied) {
    _ = try fixture.coordinator.start(
      bootstrapID: fixture.bootstrapID, proof: Data(repeating: 0xdd, count: 32))
  }
  #expect(
    try fixture.coordinator.start(bootstrapID: fixture.bootstrapID, proof: fixture.proof)
      .status.state == .active)
  #expect(fixture.consumer.calls == 2)
}

@Test func coordinatorRejectsBootTenantAndRequestedTTLSubstitution() throws {
  let wrongBoot = try coordinatorFixture(coordinatorBootIdentity: "other-boot")
  #expect(throws: NativeAgentSessionCoordinatorError.bindingDenied) {
    _ = try wrongBoot.coordinator.start(
      bootstrapID: wrongBoot.bootstrapID, proof: wrongBoot.proof)
  }

  let wrongTenant = try coordinatorFixture(
    leaseOrganizationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
  #expect(throws: NativeAgentSessionCoordinatorError.leaseDenied) {
    _ = try wrongTenant.coordinator.start(
      bootstrapID: wrongTenant.bootstrapID, proof: wrongTenant.proof)
  }

  let excessiveTTL = try coordinatorFixture(leaseExpiresAt: "2026-08-13T10:16:00.000Z")
  #expect(throws: NativeAgentSessionCoordinatorError.leaseDenied) {
    _ = try excessiveTTL.coordinator.start(
      bootstrapID: excessiveTTL.bootstrapID, proof: excessiveTTL.proof)
  }
}

@Test func coordinatorRetriesMissingCloseAuditWithoutReopeningAuthority() throws {
  let fixture = try coordinatorFixture()
  _ = try fixture.coordinator.start(bootstrapID: fixture.bootstrapID, proof: fixture.proof)
  fixture.audit.fail = true
  #expect(throws: NativeAgentSessionCoordinatorError.auditUnavailable) {
    _ = try fixture.coordinator.close(sessionID: coordinatorSessionID, reason: .completed)
  }
  fixture.audit.fail = false
  #expect(
    try fixture.coordinator.close(sessionID: coordinatorSessionID, reason: .completed).state
      == .closed)
  #expect(fixture.audit.events.map(\.action) == [.sessionActivated, .sessionClosed])
}

@Test func connectionInvalidationDuringActivationCannotPublishAuthority() throws {
  let binding = try coordinatorBinding()
  let store = NativeAgentBootstrapChallengeStore(random: CoordinatorRandom(byte: 1))
  let bootHash = Data(SHA256.hash(data: Data("boot".utf8))).map {
    String(format: "%02x", $0)
  }.joined()
  let connection = try NativeAgentBootstrapConnectionBinding(
    connectionTokenIdentity: coordinatorToken,
    processBindingHash: String(repeating: "b", count: 64),
    ancestryBindingHash: String(repeating: "c", count: 64), bootIdentityHash: bootHash)
  let challenge = try store.begin(
    agentID: coordinatorAgentID, adapterKind: .claudeCode, requestedTTLSeconds: 900,
    clientNonce: Data(repeating: 5, count: 32), connectionBinding: connection,
    nowMilliseconds: coordinatorWall, nowMonotonicNanoseconds: 1_000)
  let registry = NativeAgentSessionRegistry()
  let audit = InvalidatingCoordinatorAudit()
  let coordinator = try NativeAgentSessionCoordinator(
    connectionTokenIdentity: coordinatorToken, connectionRevalidator: {},
    bootstrapStore: store, bindingObserver: CoordinatorBindingObserver(binding),
    grantConsumer: CoordinatorGrantConsumer(try coordinatorLease(binding: binding)),
    recoveryStore: CoordinatorRecoveryStore(),
    activationRecoveryStore: CoordinatorRecoveryV4Store(),
    registry: registry, audit: audit,
    wallClock: CoordinatorWallClock(milliseconds: coordinatorWall + 1_000),
    monotonicClock: CoordinatorMonotonicClock(nanoseconds: 2_000, bootIdentity: "boot"),
    random: CoordinatorRandom(byte: 9), authority: coordinatorAuthority())
  audit.coordinator = coordinator

  #expect(throws: NativeAgentSessionCoordinatorError.invalidated) {
    _ = try coordinator.start(
      bootstrapID: challenge.bootstrapID, proof: Data(repeating: 0xee, count: 32))
  }
  #expect(throws: NativeAgentSessionRegistryError.sessionMissing) {
    _ = try registry.status(
      sessionID: coordinatorSessionID, connectionTokenIdentity: coordinatorToken,
      binding: binding,
      wallClock: NativeAgentWallClockValue(millisecondsSinceUnixEpoch: coordinatorWall + 2_000),
      monotonicClock: NativeAgentMonotonicClockValue(
        nanoseconds: 3_000, bootIdentity: "boot"))
  }
  #expect(audit.events.map(\.action) == [.sessionActivated])
}
