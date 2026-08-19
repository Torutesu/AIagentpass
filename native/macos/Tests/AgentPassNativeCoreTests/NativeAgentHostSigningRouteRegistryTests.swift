import CryptoKit
import Foundation
import Testing

@testable import AgentPassNativeCore

private let routeAgentID = "33333333-3333-4333-8333-333333333333"
private let routeDeviceID = "44444444-4444-4444-8444-444444444444"
private let routeOrganizationID = "66666666-6666-4666-8666-666666666666"
private let routeSessionID = "11111111-1111-4111-8111-111111111111"
private let routeRequestID = "22222222-2222-4222-8222-222222222222"
private let routeCapabilityID = "88888888-8888-4888-8888-888888888888"
private let routeToken = String(repeating: "a", count: 64)
private let routeNow: Int64 = 1_786_615_201_000

private struct RouteRandom: NativeAgentRandomBytesGenerating {
    func randomBytes(count: Int) throws -> Data { Data(repeating: 9, count: count) }
}

private struct RouteWallClock: NativeAgentWallClock {
    func sample() throws -> NativeAgentWallClockValue {
        NativeAgentWallClockValue(millisecondsSinceUnixEpoch: routeNow)
    }
}

private struct RouteMonotonicClock: NativeAgentMonotonicClock {
    func sample() throws -> NativeAgentMonotonicClockValue {
        try NativeAgentMonotonicClockValue(nanoseconds: 2_000, bootIdentity: "route-test-boot")
    }
}

private struct RouteBindingObserver: NativeAgentSessionBindingObserving {
    let binding: NativeAgentSessionBinding

    func observeSessionBinding(agentID: String) throws -> NativeAgentSessionBinding {
        guard agentID == binding.agentID else {
            throw NativeAgentSessionCoordinatorError.bindingDenied
        }
        return binding
    }
}

private struct RouteGrantConsumer: NativeAgentGrantLeaseConsuming {
    let lease: NativeAgentVerifiedCloudLease

    func consumeGrant(_ request: NativeAgentGrantConsumptionRequest)
        throws -> NativeAgentVerifiedCloudLease
    {
        lease
    }
}

private final class RouteAudit: NativeAgentSessionAuditAppending, @unchecked Sendable {
    private let lock = NSLock()
    private var nextIndex = 0

    @discardableResult
    func appendAgentSessionAudit(_ evidence: NativeAgentSessionAuditEvidence)
        throws -> NativeAgentSessionAuditReceipt
    {
        try record(evidence)
    }

    @discardableResult
    func reconcileAgentSessionActivationAudit(_ evidence: NativeAgentSessionAuditEvidence)
        throws -> NativeAgentSessionAuditReceipt
    {
        try record(evidence)
    }

    @discardableResult
    func reconcileAgentSessionActivationOutcomeAudit(
        _ evidence: NativeAgentSessionAuditEvidence
    ) throws -> NativeAgentSessionAuditReceipt {
        try record(evidence)
    }

    func lookupAgentSessionActivationOutcomeAudit(
        _ evidence: NativeAgentSessionAuditEvidence
    ) throws -> NativeAgentSessionAuditReceipt? {
        nil
    }

    private func record(_ evidence: NativeAgentSessionAuditEvidence)
        throws -> NativeAgentSessionAuditReceipt
    {
        let evidenceDigest = try evidence.evidenceDigest()
        return try lock.withLock {
            nextIndex += 1
            return try NativeAgentSessionAuditReceipt(
                evidenceDigest: evidenceDigest,
                recordDigest: Data(repeating: UInt8(nextIndex), count: 32),
                recordIndex: nextIndex)
        }
    }
}

private struct RouteValues {
    let binding: NativeAgentSessionBinding
    let identity: NativeProcessIdentity
    let request: AgentPassAgentSignRequest
    let authority: NativeSigningTransactionAuthority
    let adapter: NativeAgentSessionCoordinatorSigningAdapter
    let root: URL
}

private final class RouteCallCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0

    var count: Int { lock.withLock { value } }
    func increment() { lock.withLock { value += 1 } }
}

private func routeWorktree() throws -> NativeAgentWorktreeBinding {
    let repository = try NativeAgentWorktreeDirectoryIdentity(
        device: 1, inode: 20, generation: 1, ownerUserID: 501, permissions: 0o755)
    let git = try NativeAgentWorktreeDirectoryIdentity(
        device: 1, inode: 21, generation: 1, ownerUserID: 501, permissions: 0o755)
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
        remotes: [try NativeAgentGitRemote(name: "origin", url: "git@example.test:repo.git")])
}

private func routeBinding() throws -> NativeAgentSessionBinding {
    try NativeAgentSessionBinding(
        agentID: routeAgentID,
        deviceID: routeDeviceID,
        processBindingDigest: Data(repeating: 0xbb, count: 32),
        ancestryBindingDigest: Data(repeating: 0xcc, count: 32),
        worktreeBindingDigest: Data(repeating: 0xdd, count: 32),
        controlSequence: 12,
        authorityGeneration: 7,
        keyGeneration: 99)
}

private func routeLease(binding: NativeAgentSessionBinding) throws -> NativeAgentVerifiedCloudLease {
    func hex(_ value: Data) -> String { value.map { String(format: "%02x", $0) }.joined() }
    return try NativeAgentLeaseCodec.decode(
        NativeStrictJSON.data([
            "version": 1,
            "type": "agentpass.agent-session-lease",
            "session_id": routeSessionID,
            "grant_id": "55555555-5555-4555-8555-555555555555",
            "organization_id": routeOrganizationID,
            "device_id": routeDeviceID,
            "agent_id": routeAgentID,
            "agent_kind": "claude-code",
            "adapter_id": "77777777-7777-4777-8777-777777777777",
            "adapter_version": "1.0.0",
            "process_binding_sha256": hex(binding.processBindingDigest),
            "ancestry_binding_sha256": hex(binding.ancestryBindingDigest),
            "worktree_binding_sha256": hex(binding.worktreeBindingDigest),
            "max_signatures": 2,
            "used_signatures": 0,
            "not_before": "2026-08-13T10:00:00.000Z",
            "expires_at": "2026-08-13T10:15:00.000Z",
            "control_sequence": 12,
            "authority_generation": 7,
        ]),
        expectedBinding: binding)
}

private func routeRequest() throws -> AgentPassAgentSignRequest {
    let capability = try NativeStrictJSON.data([
        "version": 1,
        "capability_id": routeCapabilityID,
        "nonce": String(repeating: "N", count: 32),
        "issuer": "agentpass-cloud",
        "key_id": "capability-v1",
        "audience": ["agent_id": routeAgentID, "device_id": routeDeviceID],
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
        sessionID: routeSessionID,
        requestID: routeRequestID,
        capabilityID: routeCapabilityID,
        capability: capability,
        commitPayload: Data("commit payload".utf8),
        requestNonce: Data(repeating: 0x2a, count: 16),
        createdAtMilliseconds: routeNow))
}

private func routeProcessIdentity() throws -> NativeProcessIdentity {
    let facts = try NativeObservedProcessFacts(
        uid: 501,
        pid: 700,
        pidVersion: 1,
        bootIdentity: "route-test-boot",
        executableFileIdentity: try NativeExecutableFileIdentity(
            deviceID: 1, inode: 700, fileSize: 1, modificationTimeNanoseconds: 1),
        codeDirectoryHash: String(repeating: "a", count: 64),
        bundleIdentifier: "dev.agentpass.agent-host",
        teamIdentifier: "ABCDE12345",
        signatureKind: .developerID,
        entitlements: [:])
    return NativeProcessIdentity(observation: try NativeProcessObservation(process: facts, ancestry: []))
}

private func routeRuntimeAuthority(directory: URL) throws -> NativeAgentRuntimeAuthorityConfiguration {
    let configuration = try NativeAgentRuntimeConfiguration(
        deviceAPIOrigin: URL(string: "https://api.agentpass.test"),
        organizationID: routeOrganizationID,
        deviceID: routeDeviceID,
        deviceKeyTag: NativeEnrollmentKeyMaterial.fixedApplicationTag,
        signingIntentDirectory: directory.path,
        globalSessionLimit: 8,
        perAgentSessionLimit: 4,
        perWorktreeSessionLimit: 2,
        bootstrapAttemptLimit: 3,
        worktreeObservationPolicyVersion: 2)
    return try #require(configuration.authority)
}

private func routeValues() throws -> RouteValues {
    let root = FileManager.default.temporaryDirectory
        .standardizedFileURL
        .appendingPathComponent("agentpass-route-test-\(UUID().uuidString)")
        .standardizedFileURL
    try FileManager.default.createDirectory(
        at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])

    let binding = try routeBinding()
    let lease = try routeLease(binding: binding)
    let request = try routeRequest()
    let authority = try NativeSigningTransactionAuthority(
        request: try NativeSigningTransactionRequest(request),
        binding: binding,
        worktree: try routeWorktree(),
        keyLifecycleIdentity: String(repeating: "f", count: 64))
    let challengeStore = NativeAgentBootstrapChallengeStore(random: RouteRandom())
    let bootHash = Data(SHA256.hash(data: Data("route-test-boot".utf8)))
        .map { String(format: "%02x", $0) }.joined()
    let connection = try NativeAgentBootstrapConnectionBinding(
        connectionTokenIdentity: routeToken,
        processBindingHash: binding.processBindingDigest.map { String(format: "%02x", $0) }.joined(),
        ancestryBindingHash: binding.ancestryBindingDigest.map { String(format: "%02x", $0) }.joined(),
        bootIdentityHash: bootHash)
    let challenge = try challengeStore.begin(
        agentID: routeAgentID,
        adapterKind: .claudeCode,
        requestedTTLSeconds: 900,
        clientNonce: Data(repeating: 5, count: 32),
        connectionBinding: connection,
        nowMilliseconds: routeNow - 1_000,
        nowMonotonicNanoseconds: 1_000)
    let recoveryPath = root.appendingPathComponent("recovery.json").path
    let recoveryV4Path = root.appendingPathComponent("recovery-v4.json").path
    let coordinator = try NativeAgentSessionCoordinator(
        connectionTokenIdentity: routeToken,
        connectionRevalidator: {},
        bootstrapStore: challengeStore,
        bindingObserver: RouteBindingObserver(binding: binding),
        grantConsumer: RouteGrantConsumer(lease: lease),
        recoveryStore: try NativeAgentSessionConsumeRecoveryStore(path: recoveryPath),
        activationRecoveryStore: try NativeAgentSessionConsumeRecoveryV4Store(path: recoveryV4Path),
        registry: NativeAgentSessionRegistry(),
        audit: RouteAudit(),
        wallClock: RouteWallClock(),
        monotonicClock: RouteMonotonicClock(),
        random: RouteRandom(),
        authority: try routeRuntimeAuthority(directory: root))
    _ = try coordinator.start(
        bootstrapID: challenge.bootstrapID, proof: challenge.challenge)
    let handoff = try coordinator.makeSigningHandoff(request: request) { _ in authority }
    let adapter = try NativeAgentSessionCoordinatorSigningAdapter(
        handoff: handoff,
        coordinator: coordinator,
        transactionStore: try NativeSigningTransactionStore(
            path: root.appendingPathComponent("transactions.json").path))
    return RouteValues(
        binding: binding,
        identity: try routeProcessIdentity(),
        request: request,
        authority: authority,
        adapter: adapter,
        root: root)
}

private func issueRoute(
    _ values: RouteValues,
    registry: NativeAgentHostSigningRouteRegistry,
    expiresAt: Int64 = routeNow + 60_000
) throws -> NativeAgentHostSigningRoute {
    try registry.issue(
        adapter: values.adapter,
        connectionTokenIdentity: routeToken,
        childProcessIdentity: values.identity,
        worktreeBindingDigest: values.binding.worktreeBindingDigest,
        expiresAtMilliseconds: expiresAt,
        nowMilliseconds: routeNow)
}

private func consume(
    _ route: NativeAgentHostSigningRoute,
    registry: NativeAgentHostSigningRouteRegistry,
    values: RouteValues,
    now: Int64 = routeNow,
    requestID: String? = nil,
    createdAt: Int64? = nil
) throws {
    _ = try registry.consume(
        routeID: route.routeID,
        connectionTokenIdentity: routeToken,
        childProcessIdentity: values.identity,
        worktreeBindingDigest: values.binding.worktreeBindingDigest,
        requestID: requestID ?? route.requestCorrelation.requestID,
        createdAtMilliseconds: createdAt ?? route.requestCorrelation.createdAtMilliseconds,
        nowMilliseconds: now)
}

@Test("Host route rejects substituted bindings and exact correlation")
func hostSigningRouteRejectsInvalidBindings() throws {
    let values = try routeValues()
    defer { try? FileManager.default.removeItem(at: values.root) }
    let registry = NativeAgentHostSigningRouteRegistry()
    let route = try issueRoute(values, registry: registry)

    #expect(throws: NativeAgentHostSigningRouteError.connectionMismatch) {
        _ = try registry.consume(
            routeID: route.routeID, connectionTokenIdentity: String(repeating: "b", count: 64),
            childProcessIdentity: values.identity,
            worktreeBindingDigest: values.binding.worktreeBindingDigest,
            requestID: route.requestCorrelation.requestID,
            createdAtMilliseconds: route.requestCorrelation.createdAtMilliseconds,
            nowMilliseconds: routeNow)
    }
    #expect(throws: NativeAgentHostSigningRouteError.requestCorrelationMismatch) {
        try consume(route, registry: registry, values: values,
                    requestID: "99999999-9999-4999-8999-999999999999")
    }
    #expect(route.currentState == .issued)
    try consume(route, registry: registry, values: values)
}

@Test("Host route is one shot and replay is rejected")
func hostSigningRouteConsumesOnce() throws {
    let values = try routeValues()
    defer { try? FileManager.default.removeItem(at: values.root) }
    let registry = NativeAgentHostSigningRouteRegistry()
    let route = try issueRoute(values, registry: registry)
    try consume(route, registry: registry, values: values)
    #expect(throws: NativeAgentHostSigningRouteError.routeReplay) {
        try consume(route, registry: registry, values: values)
    }
}

@Test("Host route expires before it can be consumed")
func hostSigningRouteRejectsExpiry() throws {
    let values = try routeValues()
    defer { try? FileManager.default.removeItem(at: values.root) }
    let registry = NativeAgentHostSigningRouteRegistry()
    let route = try issueRoute(values, registry: registry, expiresAt: routeNow + 1)
    #expect(throws: NativeAgentHostSigningRouteError.expired) {
        try consume(route, registry: registry, values: values, now: routeNow + 1)
    }
    #expect(route.currentState == .expired)
}

@Test("Host route close and invalidation are terminal")
func hostSigningRouteCloseAndInvalidateRejectUse() throws {
    let values = try routeValues()
    defer { try? FileManager.default.removeItem(at: values.root) }
    let registry = NativeAgentHostSigningRouteRegistry()
    let closed = try issueRoute(values, registry: registry)
    try registry.close(routeID: closed.routeID, connectionTokenIdentity: routeToken)
    #expect(throws: NativeAgentHostSigningRouteError.closed) {
        try consume(closed, registry: registry, values: values)
    }

    let invalidated = try issueRoute(values, registry: registry)
    try registry.invalidate(routeID: invalidated.routeID)
    #expect(throws: NativeAgentHostSigningRouteError.invalidated) {
        try consume(invalidated, registry: registry, values: values)
    }
}

@Test("Host route execute invokes the provider exactly once")
func hostSigningRouteExecutesProviderOnce() throws {
    let values = try routeValues()
    defer { try? FileManager.default.removeItem(at: values.root) }
    let registry = NativeAgentHostSigningRouteRegistry()
    let route = try issueRoute(values, registry: registry)
    let calls = RouteCallCounter()
    let signature = try registry.execute(
        routeID: route.routeID,
        connectionTokenIdentity: routeToken,
        childProcessIdentity: values.identity,
        worktreeBindingDigest: values.binding.worktreeBindingDigest,
        requestID: route.requestCorrelation.requestID,
        createdAtMilliseconds: route.requestCorrelation.createdAtMilliseconds,
        nowMilliseconds: routeNow) { payload in
            calls.increment()
            #expect(payload == values.request.commitPayload)
            return Data("verified-signature".utf8)
        }
    #expect(signature == Data("verified-signature".utf8))
    #expect(calls.count == 1)
    #expect(throws: NativeAgentHostSigningRouteError.routeReplay) {
        _ = try registry.execute(
            routeID: route.routeID,
            connectionTokenIdentity: routeToken,
            childProcessIdentity: values.identity,
            worktreeBindingDigest: values.binding.worktreeBindingDigest,
            requestID: route.requestCorrelation.requestID,
            createdAtMilliseconds: route.requestCorrelation.createdAtMilliseconds,
            nowMilliseconds: routeNow) { _ in
                calls.increment()
                return Data("unexpected".utf8)
            }
    }
    #expect(calls.count == 1)
}
