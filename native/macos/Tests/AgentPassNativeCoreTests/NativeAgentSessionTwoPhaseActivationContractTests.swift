// N3-E3c-1c contract tests.
//
// These are black-box tests: no registry storage or implementation detail is
// inspected.  The production registry publishes the two-phase admission
// surface used below.
//
// The contract frozen here is:
//
//   reserveActivation(...) -> NativeAgentSessionActivationReservation
//   commitActivation(_:)   -> NativeAgentSessionRegistryStatus
//   publishActivation(_:)  -> NativeAgentSessionRegistryStatus
//   cancelActivation(_:)   -> Void
//
// reserveActivation records only an authority-free admission reservation.
// commitActivation moves it to a hidden in-memory state. The lease becomes
// visible to status/signing APIs exactly once, at publishActivation.
//
import Dispatch
import Foundation
import Testing
@testable import AgentPassNativeCore

private let twoPhaseToken = String(repeating: "a", count: 64)
private let twoPhaseWallClock = NativeAgentWallClockValue(
  millisecondsSinceUnixEpoch: 1_786_615_201_000
)
private func twoPhaseMonotonicClock() throws -> NativeAgentMonotonicClockValue {
  try NativeAgentMonotonicClockValue(
    nanoseconds: 2_000,
    bootIdentity: "two-phase-contract-boot"
  )
}

private struct TwoPhaseFixture: Sendable {
  let sessionID: String
  let localLeaseID: String
  let connectionTokenIdentity: String
  let binding: NativeAgentSessionBinding
  let lease: NativeAgentVerifiedCloudLease
  let deadline: NativeAgentSessionDeadline
}

private func twoPhaseFixture(
  index: Int,
  agentID: String = "33333333-3333-4333-8333-333333333333",
  token: String = twoPhaseToken
) throws -> TwoPhaseFixture {
  let suffix = String(format: "%012x", index + 1)
  let sessionID = String(format: "%08x-1111-4111-8111-%@", index + 1, suffix)
  let localLeaseID = String(format: "%08x-2222-4222-8222-%@", index + 1, suffix)
  let deviceID = "44444444-4444-4444-8444-444444444444"
  let binding = try NativeAgentSessionBinding(
    agentID: agentID,
    deviceID: deviceID,
    processBindingDigest: Data(repeating: 0xbb, count: 32),
    ancestryBindingDigest: Data(repeating: 0xcc, count: 32),
    worktreeBindingDigest: Data(repeating: 0xaa, count: 32),
    controlSequence: 12,
    authorityGeneration: 7,
    keyGeneration: 99
  )
  let object: [String: Any] = [
    "version": 1,
    "type": "agentpass.agent-session-lease",
    "session_id": sessionID,
    "grant_id": "55555555-5555-4555-8555-555555555555",
    "organization_id": "66666666-6666-4666-8666-666666666666",
    "device_id": deviceID,
    "agent_id": agentID,
    "agent_kind": "claude-code",
    "adapter_id": "77777777-7777-4777-8777-777777777777",
    "adapter_version": "1.0.0",
    "process_binding_sha256": String(repeating: "b", count: 64),
    "ancestry_binding_sha256": String(repeating: "c", count: 64),
    "worktree_binding_sha256": String(repeating: "a", count: 64),
    "max_signatures": 2,
    "used_signatures": 0,
    "not_before": "2026-08-13T10:00:00.000Z",
    "expires_at": "2026-08-13T10:15:00.000Z",
    "control_sequence": 12,
    "authority_generation": 7,
  ]
  let lease = try NativeAgentLeaseCodec.decode(
    try NativeStrictJSON.data(object),
    expectedBinding: binding
  )
  let deadline = try NativeAgentSessionDeadline(
    signedWallExpiryMilliseconds: 1_786_616_100_000,
    wallClock: NativeAgentWallClockValue(
      millisecondsSinceUnixEpoch: 1_786_615_200_000
    ),
    monotonicClock: NativeAgentMonotonicClockValue(
      nanoseconds: 1_000,
      bootIdentity: "two-phase-contract-boot"
    )
  )
  return TwoPhaseFixture(
    sessionID: sessionID,
    localLeaseID: localLeaseID,
    connectionTokenIdentity: token,
    binding: binding,
    lease: lease,
    deadline: deadline
  )
}

private func reserveActivation(
  _ registry: NativeAgentSessionRegistry,
  _ fixture: TwoPhaseFixture,
  globalLimit: Int = 1,
  perAgentLimit: Int = 1,
  perWorktreeLimit: Int = 1
) throws -> NativeAgentSessionActivationReservation {
  try registry.reserveActivation(
    lease: fixture.lease,
    localLeaseID: fixture.localLeaseID,
    connectionTokenIdentity: fixture.connectionTokenIdentity,
    deadline: fixture.deadline,
    globalLimit: globalLimit,
    perAgentLimit: perAgentLimit,
    perWorktreeLimit: perWorktreeLimit
  )
}

private func expectClosedCommit(
  _ operation: () throws -> Void
) {
  do {
    try operation()
    #expect(Bool(false), "a closed or committed reservation must not mutate authority")
  } catch let error as NativeAgentSessionRegistryError {
    #expect(
      error == .reservationMissing || error == .reservationMismatch || error == .transitionDenied
    )
  } catch {
    #expect(Bool(false), "unexpected reservation error: \(error)")
  }
}

private final class TwoPhaseCounterBox: @unchecked Sendable {
  private let lock = NSLock()
  private var count = 0
  private var failures: [String] = []

  func increment() {
    lock.withLock { count += 1 }
  }

  var value: Int {
    lock.withLock { count }
  }

  func record(_ error: any Error) {
    lock.withLock { failures.append(String(describing: error)) }
  }

  var firstFailure: String? {
    lock.withLock { failures.first }
  }
}

@Test("N3-E3c-1c: reservation is authority-free until publication")
func unpublishedActivationGrantsNoStatusOrSigningAuthority() throws {
  let registry = NativeAgentSessionRegistry()
  let fixture = try twoPhaseFixture(index: 0)
  let reservation = try reserveActivation(registry, fixture)

  #expect(reservation.plannedStatus.sessionID == fixture.sessionID)
  #expect(
    throws: NativeAgentSessionRegistryError.sessionMissing,
    "an uncommitted admission must not be visible as a session"
  ) {
    _ = try registry.status(
      sessionID: fixture.sessionID,
      connectionTokenIdentity: fixture.connectionTokenIdentity,
      binding: fixture.binding,
      wallClock: twoPhaseWallClock,
      monotonicClock: try twoPhaseMonotonicClock()
    )
  }

  _ = try registry.commitActivation(reservation)
  #expect(throws: NativeAgentSessionRegistryError.sessionMissing) {
    _ = try registry.status(
      sessionID: fixture.sessionID,
      connectionTokenIdentity: fixture.connectionTokenIdentity,
      binding: fixture.binding,
      wallClock: twoPhaseWallClock,
      monotonicClock: try twoPhaseMonotonicClock()
    )
  }
  #expect(
    throws: NativeAgentSessionRegistryError.sessionMissing,
    "an uncommitted admission must not reach signing-budget APIs"
  ) {
    _ = try registry.reserve(
      sessionID: fixture.sessionID,
      requestID: "88888888-8888-4888-8888-888888888888",
      capabilityID: "99999999-9999-4999-8999-999999999999",
      nonce: Data(repeating: 1, count: 32),
      payloadDigest: Data(repeating: 1, count: 32),
      connectionTokenIdentity: fixture.connectionTokenIdentity,
      binding: fixture.binding,
      wallClock: twoPhaseWallClock,
      monotonicClock: try twoPhaseMonotonicClock()
    )
  }

  // Keep the reservation live for the duration of the assertions.  This also
  // prevents a future implementation from optimizing an unused token away.
  _ = reservation
}

@Test("N3-E3c-1c: one reservation can commit and publish exactly once")
func reservationCommitAndPublishAreExactlyOnce() throws {
  let registry = NativeAgentSessionRegistry()
  let fixture = try twoPhaseFixture(index: 1)
  let reservation = try reserveActivation(registry, fixture)

  let committed = try registry.commitActivation(reservation)
  #expect(committed.sessionID == fixture.sessionID)
  #expect(committed.state == .active)

  expectClosedCommit { _ = try registry.commitActivation(reservation) }
  #expect(throws: NativeAgentSessionRegistryError.sessionMissing) {
    _ = try registry.status(
      sessionID: fixture.sessionID,
      connectionTokenIdentity: fixture.connectionTokenIdentity,
      binding: fixture.binding,
      wallClock: twoPhaseWallClock,
      monotonicClock: try twoPhaseMonotonicClock()
    )
  }
  let published = try registry.publishActivation(reservation)
  expectClosedCommit { _ = try registry.publishActivation(reservation) }
  #expect(
    try registry.status(
      sessionID: fixture.sessionID,
      connectionTokenIdentity: fixture.connectionTokenIdentity,
      binding: fixture.binding,
      wallClock: twoPhaseWallClock,
      monotonicClock: try twoPhaseMonotonicClock()
    ) == published
  )
}

@Test("N3-E3c-1c: cancellation is idempotent or permanently closed")
func reservationCancelIsIdempotentOrClosed() throws {
  let registry = NativeAgentSessionRegistry()
  let fixture = try twoPhaseFixture(index: 2)
  let reservation = try reserveActivation(registry, fixture)

  #expect(try registry.cancelActivation(reservation))
  #expect(try !registry.cancelActivation(reservation))

  // Cancellation must release admission capacity without creating authority.
  let replacement = try reserveActivation(registry, fixture)
  #expect(replacement.plannedStatus.sessionID == fixture.sessionID)
  #expect(try registry.cancelActivation(replacement))
}

@Test("N3-E3c-1c: reservation substitution is denied")
func reservationCannotMoveBetweenRegistryOwners() throws {
  let owner = NativeAgentSessionRegistry()
  let foreign = NativeAgentSessionRegistry()
  let fixture = try twoPhaseFixture(index: 3)
  let reservation = try reserveActivation(owner, fixture)

  expectClosedCommit { _ = try foreign.commitActivation(reservation) }
  expectClosedCommit { _ = try foreign.publishActivation(reservation) }
  #expect(try !foreign.cancelActivation(reservation))

  // The owner still has the only valid copy; a failed foreign operation must
  // not consume or mutate it.
  #expect(try owner.commitActivation(reservation).state == .active)
  #expect(try owner.publishActivation(reservation).state == .active)
}

@Test("N3-E3c-1c: pending reservations consume admission capacity")
func pendingReservationCountsAgainstCapacity() throws {
  let registry = NativeAgentSessionRegistry()
  let first = try twoPhaseFixture(index: 4)
  let second = try twoPhaseFixture(index: 5)
  _ = try reserveActivation(registry, first, globalLimit: 1)

  #expect(throws: NativeAgentSessionRegistryError.sessionCapacityExceeded) {
    _ = try reserveActivation(registry, second, globalLimit: 1)
  }
}

@Test("N3-E3c-1c: invalidation removes pending admission")
func invalidationRemovesPendingReservation() throws {
  let registry = NativeAgentSessionRegistry()
  let fixture = try twoPhaseFixture(index: 6)
  let reservation = try reserveActivation(registry, fixture)

  registry.invalidateAll(as: .revoked)
  expectClosedCommit { _ = try registry.commitActivation(reservation) }

  // The pending slot is gone, and a replacement may be admitted.  It is still
  // authority-free until its own commit.
  let replacement = try reserveActivation(registry, fixture)
  #expect(try registry.cancelActivation(replacement))
}

@Test("N3-E3c-1c: invalidation removes hidden committed authority")
func invalidationRemovesHiddenCommit() throws {
  let registry = NativeAgentSessionRegistry()
  let fixture = try twoPhaseFixture(index: 8)
  let reservation = try reserveActivation(registry, fixture)
  _ = try registry.commitActivation(reservation)

  registry.invalidateAll(as: .revoked)
  expectClosedCommit { _ = try registry.publishActivation(reservation) }
  #expect(throws: NativeAgentSessionRegistryError.sessionMissing) {
    _ = try registry.status(
      sessionID: fixture.sessionID,
      connectionTokenIdentity: fixture.connectionTokenIdentity,
      binding: fixture.binding,
      wallClock: twoPhaseWallClock,
      monotonicClock: try twoPhaseMonotonicClock()
    )
  }

  let replacement = try reserveActivation(registry, fixture)
  #expect(try registry.cancelActivation(replacement))
}

@Test("N3-E3c-1c: hidden commits continue to consume admission capacity")
func hiddenCommitCountsAgainstCapacity() throws {
  let registry = NativeAgentSessionRegistry()
  let first = try twoPhaseFixture(index: 9)
  let second = try twoPhaseFixture(index: 10)
  let reservation = try reserveActivation(registry, first, globalLimit: 1)
  _ = try registry.commitActivation(reservation)

  #expect(throws: NativeAgentSessionRegistryError.sessionCapacityExceeded) {
    _ = try reserveActivation(registry, second, globalLimit: 1)
  }
}

@Test("N3-E3c-1c: 100 competing reserve/commit operations cannot over-admit")
func competingReservationsCannotOverAdmit() throws {
  let registry = NativeAgentSessionRegistry()
  let fixtures = try (0..<100).map { try twoPhaseFixture(index: 100 + $0) }
  let committedCount = TwoPhaseCounterBox()

  DispatchQueue.concurrentPerform(iterations: fixtures.count) { index in
    do {
      let reservation = try reserveActivation(
        registry,
        fixtures[index],
        globalLimit: 1,
        perAgentLimit: 1,
        perWorktreeLimit: 1
      )
      _ = try registry.commitActivation(reservation)
      committedCount.increment()
    } catch NativeAgentSessionRegistryError.sessionCapacityExceeded {
      // Expected for every contender except the linearized winner.
    } catch {
      committedCount.record(error)
    }
  }

  #expect(committedCount.firstFailure == nil)
  #expect(committedCount.value == 1)
}

@Test("N3-E3c-1c: a fresh registry has no reservation authority")
func freshRegistryCannotUsePriorReservation() throws {
  let original = NativeAgentSessionRegistry()
  let fresh = NativeAgentSessionRegistry()
  let fixture = try twoPhaseFixture(index: 7)
  let reservation = try reserveActivation(original, fixture)

  expectClosedCommit { _ = try fresh.commitActivation(reservation) }
  expectClosedCommit { _ = try fresh.publishActivation(reservation) }
  #expect(try !fresh.cancelActivation(reservation))
}
