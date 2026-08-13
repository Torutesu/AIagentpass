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

  func completeAfterLocalActivation(
    _ expected: NativeAgentSessionConsumeRecoveryEvidence,
    auditedRecord: NativeAgentSessionConsumeRecoveryAuditedRecord
  ) throws -> NativeAgentSessionConsumeRecoveryAuditedRecord {
    try lock.withLock {
      guard auditedRecord.evidence == expected else {
        throw NativeAgentSessionConsumeRecoveryStoreError.conflict
      }
      switch state {
      case .pending(let existing) where existing == expected:
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
}

private func coordinatorBinding(worktree: UInt8 = 0xaa) throws
  -> NativeAgentSessionBinding
{
  try NativeAgentSessionBinding(
    agentID: coordinatorAgentID, deviceID: coordinatorDeviceID,
    processBindingDigest: Data(repeating: 0xbb, count: 32),
    ancestryBindingDigest: Data(repeating: 0xcc, count: 32),
    worktreeBindingDigest: Data(repeating: worktree, count: 32),
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
    "process_binding_sha256": String(repeating: "b", count: 64),
    "ancestry_binding_sha256": String(repeating: "c", count: 64),
    "worktree_binding_sha256": String(repeating: "a", count: 64),
    "max_signatures": 2, "used_signatures": 0,
    "not_before": "2026-08-13T10:00:00.000Z", "expires_at": expiresAt,
    "control_sequence": 12, "authority_generation": 7,
  ]
  return try NativeAgentLeaseCodec.decode(
    NativeStrictJSON.data(object), expectedBinding: binding)
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
  let coordinator = try NativeAgentSessionCoordinator(
    connectionTokenIdentity: coordinatorToken, connectionRevalidator: {},
    bootstrapStore: store, bindingObserver: observer, grantConsumer: consumer,
    recoveryStore: CoordinatorRecoveryStore(),
    registry: registry, audit: audit,
    wallClock: CoordinatorWallClock(milliseconds: coordinatorWall + 1_000),
    monotonicClock: CoordinatorMonotonicClock(
      nanoseconds: 2_000, bootIdentity: coordinatorBootIdentity),
    random: CoordinatorRandom(byte: 9), authority: coordinatorAuthority())
  return CoordinatorFixture(
    coordinator: coordinator, bootstrapID: challenge.bootstrapID, registry: registry,
    observer: observer, consumer: consumer, audit: audit)
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
  let status = try fixture.registry.status(
    sessionID: coordinatorSessionID, connectionTokenIdentity: coordinatorToken,
    binding: try coordinatorBinding(),
    wallClock: NativeAgentWallClockValue(millisecondsSinceUnixEpoch: coordinatorWall + 2_000),
    monotonicClock: NativeAgentMonotonicClockValue(
      nanoseconds: 3_000, bootIdentity: "boot"))
  #expect(status.state == .revoked)
}

@Test func coordinatorRejectsSubstitutedAuditReceiptAndRevokesAuthority() throws {
  let fixture = try coordinatorFixture()
  fixture.audit.substituteReceiptEvidence = true
  #expect(throws: NativeAgentSessionCoordinatorError.auditUnavailable) {
    _ = try fixture.coordinator.start(bootstrapID: fixture.bootstrapID, proof: fixture.proof)
  }
  #expect(fixture.audit.events.map(\.action) == [.sessionActivated])
  let status = try fixture.registry.status(
    sessionID: coordinatorSessionID, connectionTokenIdentity: coordinatorToken,
    binding: try coordinatorBinding(),
    wallClock: NativeAgentWallClockValue(millisecondsSinceUnixEpoch: coordinatorWall + 2_000),
    monotonicClock: NativeAgentMonotonicClockValue(
      nanoseconds: 3_000, bootIdentity: "boot"))
  #expect(status.state == .revoked)
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
    registry: registry, audit: audit,
    wallClock: CoordinatorWallClock(milliseconds: coordinatorWall + 1_000),
    monotonicClock: CoordinatorMonotonicClock(nanoseconds: 2_000, bootIdentity: "boot"),
    random: CoordinatorRandom(byte: 9), authority: coordinatorAuthority())
  audit.coordinator = coordinator

  #expect(throws: NativeAgentSessionCoordinatorError.invalidated) {
    _ = try coordinator.start(
      bootstrapID: challenge.bootstrapID, proof: Data(repeating: 0xee, count: 32))
  }
  let status = try registry.status(
    sessionID: coordinatorSessionID, connectionTokenIdentity: coordinatorToken,
    binding: binding,
    wallClock: NativeAgentWallClockValue(millisecondsSinceUnixEpoch: coordinatorWall + 2_000),
    monotonicClock: NativeAgentMonotonicClockValue(nanoseconds: 3_000, bootIdentity: "boot"))
  #expect(status.state == .revoked)
  #expect(audit.events.map(\.action) == [.sessionActivated, .sessionInvalidated])
}
