import Dispatch
import Foundation
import Testing
@testable import AgentPassNativeCore

private let registrySession = "11111111-1111-4111-8111-111111111111"
private let registryLease = "22222222-2222-4222-8222-222222222222"
private let registryToken = String(repeating: "a", count: 64)

private func registryBinding() throws -> NativeAgentSessionBinding {
    try NativeAgentSessionBinding(agentID: "33333333-3333-4333-8333-333333333333", deviceID: "44444444-4444-4444-8444-444444444444", processBindingDigest: Data(repeating: 0xbb, count: 32), ancestryBindingDigest: Data(repeating: 0xcc, count: 32), worktreeBindingDigest: Data(repeating: 0xaa, count: 32), controlSequence: 12, authorityGeneration: 7, keyGeneration: 99)
}

private func registryLeaseDocument(max: Int = 2, used: Int = 0) throws -> NativeAgentVerifiedCloudLease {
    let object: [String: Any] = ["version":1,"type":"agentpass.agent-session-lease","session_id":registrySession,"grant_id":"55555555-5555-4555-8555-555555555555","organization_id":"66666666-6666-4666-8666-666666666666","device_id":"44444444-4444-4444-8444-444444444444","agent_id":"33333333-3333-4333-8333-333333333333","agent_kind":"claude-code","adapter_id":"77777777-7777-4777-8777-777777777777","adapter_version":"1.0.0","process_binding_sha256":String(repeating:"b",count:64),"ancestry_binding_sha256":String(repeating:"c",count:64),"worktree_binding_sha256":String(repeating:"a",count:64),"max_signatures":max,"used_signatures":used,"not_before":"2026-08-13T10:00:00.000Z","expires_at":"2026-08-13T10:15:00.000Z","control_sequence":12,"authority_generation":7]
    return try NativeAgentLeaseCodec.decode(try NativeStrictJSON.data(object), expectedBinding: registryBinding())
}

private func registryDeadline() throws -> NativeAgentSessionDeadline {
    try NativeAgentSessionDeadline(signedWallExpiryMilliseconds: 1_786_616_100_000, wallClock: NativeAgentWallClockValue(millisecondsSinceUnixEpoch: 1_786_615_200_000), monotonicClock: NativeAgentMonotonicClockValue(nanoseconds: 1_000, bootIdentity: "boot"))
}

private func activate(_ registry: NativeAgentSessionRegistry, max: Int = 2, used: Int = 0) throws {
    _ = try registry.activate(lease: registryLeaseDocument(max: max, used: used), localLeaseID: registryLease, connectionTokenIdentity: registryToken, deadline: registryDeadline())
}

private func reserve(_ registry: NativeAgentSessionRegistry, request: String, capability: String, nonce: UInt8) throws -> NativeAgentSessionReservation {
    try registry.reserve(sessionID: registrySession, requestID: request, capabilityID: capability, nonce: Data(repeating: nonce, count: 32), payloadDigest: Data(repeating: nonce, count: 32), connectionTokenIdentity: registryToken, binding: registryBinding(), wallClock: NativeAgentWallClockValue(millisecondsSinceUnixEpoch: 1_786_615_201_000), monotonicClock: NativeAgentMonotonicClockValue(nanoseconds: 2_000, bootIdentity: "boot"))
}

@Test func registryActivatesStatusAndClosesOnlyForMatchingConnection() throws {
    let registry = NativeAgentSessionRegistry(); try activate(registry)
    let status = try registry.status(sessionID: registrySession, connectionTokenIdentity: registryToken, binding: registryBinding(), wallClock: NativeAgentWallClockValue(millisecondsSinceUnixEpoch: 1_786_615_201_000), monotonicClock: NativeAgentMonotonicClockValue(nanoseconds: 2_000, bootIdentity: "boot"))
    #expect(status.state == .active && status.remainingSignatures == 2)
    #expect(throws: NativeAgentSessionRegistryError.connectionMismatch) { _ = try registry.close(sessionID: registrySession, connectionTokenIdentity: String(repeating:"b",count:64)) }
    #expect(try registry.close(sessionID: registrySession, connectionTokenIdentity: registryToken).state == .closed)
    #expect(try registry.close(sessionID: registrySession, connectionTokenIdentity: registryToken).state == .closed)
}

@Test func reservationIntentCompletionConsumesBudgetBeforeKeyUse() throws {
    let registry = NativeAgentSessionRegistry(); try activate(registry, max: 1)
    let reservation = try reserve(registry, request: "88888888-8888-4888-8888-888888888888", capability: "99999999-9999-4999-8999-999999999999", nonce: 1)
    try registry.beginSigningIntent(reservation); try registry.recordSigned(reservation)
    let status = try registry.complete(reservation)
    #expect(status.state == .closed && status.usedSignatures == 1 && status.remainingSignatures == 0)
}

@Test func preKeyReleaseRefundsBudgetButKeepsReplayEvidence() throws {
    let registry = NativeAgentSessionRegistry(); try activate(registry, max: 1)
    let request = "88888888-8888-4888-8888-888888888888", capability = "99999999-9999-4999-8999-999999999999"
    let reservation = try reserve(registry, request: request, capability: capability, nonce: 1)
    try registry.releaseBeforeKey(reservation)
    #expect(throws: NativeAgentSessionRegistryError.requestReplay) { _ = try reserve(registry, request: request, capability: capability, nonce: 1) }
    let next = try reserve(registry, request: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", capability: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", nonce: 2)
    #expect(next.budgetSequence == 1)
}

@Test func outcomeUnknownIsTerminalAndBudgetRemainsConsumed() throws {
    let registry = NativeAgentSessionRegistry(); try activate(registry, max: 2)
    let reservation = try reserve(registry, request: "88888888-8888-4888-8888-888888888888", capability: "99999999-9999-4999-8999-999999999999", nonce: 1)
    try registry.beginSigningIntent(reservation); try registry.markOutcomeUnknown(reservation)
    #expect(throws: NativeAgentSessionRegistryError.sessionNotActive) { _ = try reserve(registry, request: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", capability: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", nonce: 2) }
}

private final class RegistryResultBox: @unchecked Sendable {
    private let lock = NSLock(); private var successCount = 0
    func success() { lock.withLock { successCount += 1 } }
    var count: Int { lock.withLock { successCount } }
}

@Test func hundredConcurrentRequestsCannotOverspendOneBudgetUnit() throws {
    let registry = NativeAgentSessionRegistry(); try activate(registry, max: 1)
    let box = RegistryResultBox()
    DispatchQueue.concurrentPerform(iterations: 100) { index in
        let suffix = String(format: "%012x", index + 1)
        if (try? reserve(registry, request: "aaaaaaaa-aaaa-4aaa-8aaa-\(suffix)", capability: "bbbbbbbb-bbbb-4bbb-8bbb-\(suffix)", nonce: UInt8(index % 200 + 1))) != nil { box.success() }
    }
    #expect(box.count == 1)
}
