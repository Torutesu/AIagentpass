import AgentPassNativeCore
import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeServiceSupport

private let adversarialOrganization = "11111111-1111-4111-8111-111111111111"
private let adversarialDevice = "22222222-2222-4222-8222-222222222222"
private let adversarialNow: Int64 = 1_786_579_200_000

private final class AdversarialSnapshotStore: NativeDeviceRefreshSnapshotStore, @unchecked Sendable {
    private let lock = NSLock()
    private var bytes: Data?

    init(snapshot: NativeDeviceRefreshSnapshot? = nil) throws {
        if let snapshot {
            bytes = try NativeDeviceRefreshSnapshotCodec.encode(snapshot)
        }
    }

    func load() throws -> Data? { lock.withLock { bytes } }

    func save(_ canonicalSnapshot: Data) throws {
        lock.withLock { bytes = canonicalSnapshot }
    }

    func snapshot() throws -> NativeDeviceRefreshSnapshot? {
        guard let bytes = try load() else { return nil }
        return try NativeDeviceRefreshSnapshotCodec.decode(bytes)
    }
}

private final class AdversarialBundleStore: NativeDeviceSyncBundleInstalling, @unchecked Sendable {
    private let lock = NSLock()
    private var current: NativeAtomicControlBundleSnapshot?
    private(set) var installCount = 0
    var failNextInstall = false

    func active() throws -> NativeAtomicControlBundleSnapshot? { lock.withLock { current } }

    func install(
        descriptor: NativeAtomicControlBundleDescriptor,
        canonicalBytes: Data
    ) throws -> NativeAtomicControlBundleSnapshot {
        try lock.withLock {
            if failNextInstall {
                failNextInstall = false
                throw NativeAtomicControlBundleStoreError(.ioFailure)
            }
            installCount += 1
            let next = NativeAtomicControlBundleSnapshot(
                descriptor: descriptor,
                canonicalBytes: canonicalBytes
            )
            current = next
            return next
        }
    }
}

private final class AdversarialActivator: NativeDeviceSyncBundleActivating, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var invocations = 0
    private(set) var bundles: [Data] = []
    var failNext = false
    var onInvocation: (@Sendable () -> Void)?

    func activateVerifiedBundle(_ canonicalBundle: Data, nowMilliseconds: Int64) throws {
        let shouldFail = lock.withLock { () -> Bool in
            invocations += 1
            bundles.append(canonicalBundle)
            return failNext
        }
        onInvocation?()
        if shouldFail {
            lock.withLock { failNext = false }
            throw NativeDeviceSyncCoordinatorError.activationUnavailable
        }
    }
}

private final class AdversarialClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Int64

    init(_ value: Int64 = adversarialNow) { self.value = value }

    func now() -> Int64 { lock.withLock { value } }

    func advance(by milliseconds: Int64) {
        lock.withLock { value += milliseconds }
    }
}

private final class AdversarialSigner: P256MessageSigner, @unchecked Sendable {
    private let key = P256.Signing.PrivateKey()
    var publicKeyX963: Data { key.publicKey.x963Representation }
    func sign(message: Data) throws -> Data { try key.signature(for: message).rawRepresentation }
}

private final class AdversarialTransport: NativeDeviceSyncTransporting, @unchecked Sendable {
    private let lock = NSLock()
    private var polls: [NativeDeviceSyncRefreshPollResponse]
    private var fetches: [NativeDeviceSyncBundleFetchResponse]
    private let acknowledgementState: NativeDeviceRefreshState
    private var pollFailure: Error?
    private var fetchFailure: Error?
    private var acknowledgementFailure: Error?
    private(set) var acknowledgements: [NativeBundleAcknowledgement] = []
    private(set) var polledGenerations: [Int64] = []
    private var inFlightPolls = 0
    private(set) var maximumConcurrentPolls = 0
    var pollGate: AdversarialReleaseGate?

    init(
        polls: [NativeDeviceSyncRefreshPollResponse] = [],
        fetches: [NativeDeviceSyncBundleFetchResponse] = [],
        acknowledgementState: NativeDeviceRefreshState = .applied
    ) {
        self.polls = polls
        self.fetches = fetches
        self.acknowledgementState = acknowledgementState
    }

    func failPoll(with error: Error) { lock.withLock { pollFailure = error } }
    func failFetch(with error: Error) { lock.withLock { fetchFailure = error } }
    func failAcknowledgement(with error: Error) { lock.withLock { acknowledgementFailure = error } }

    func pollRefresh(afterGeneration: Int64, waitMilliseconds: Int) async throws -> NativeDeviceSyncRefreshPollResponse {
        let failure: Error? = lock.withLock {
            polledGenerations.append(afterGeneration)
            inFlightPolls += 1
            maximumConcurrentPolls = max(maximumConcurrentPolls, inFlightPolls)
            return pollFailure
        }
        defer { lock.withLock { inFlightPolls -= 1 } }
        if let pollGate { await pollGate.wait() }
        if let failure { throw failure }
        return try lock.withLock {
            guard !polls.isEmpty else { throw NativeDeviceSyncCoordinatorError.transportUnavailable }
            return polls.removeFirst()
        }
    }

    func fetchBundle() async throws -> NativeDeviceSyncBundleFetchResponse {
        let failure = lock.withLock { fetchFailure }
        if let failure { throw failure }
        return try lock.withLock {
            guard !fetches.isEmpty else { throw NativeDeviceSyncCoordinatorError.transportUnavailable }
            return fetches.removeFirst()
        }
    }

    func submitAcknowledgement(_ acknowledgement: NativeBundleAcknowledgement) async throws -> NativeDeviceSyncAcknowledgementResponse {
        let (failure, duplicate): (Error?, Bool) = lock.withLock {
            acknowledgements.append(acknowledgement)
            return (acknowledgementFailure, acknowledgements.count > 1)
        }
        if let failure { throw failure }
        return NativeDeviceSyncAcknowledgementResponse(
            accepted: true,
            duplicate: duplicate,
            observedGeneration: 1,
            refreshState: acknowledgementState
        )
    }
}

private final class AdversarialReleaseGate: @unchecked Sendable {
    private let lock = NSLock()
    private var released = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        await withCheckedContinuation { continuation in
            let resumeNow = lock.withLock { () -> Bool in
                if released { return true }
                waiters.append(continuation)
                return false
            }
            if resumeNow { continuation.resume() }
        }
    }

    func release() {
        let continuations = lock.withLock { () -> [CheckedContinuation<Void, Never>] in
            released = true
            let pending = waiters
            waiters.removeAll()
            return pending
        }
        continuations.forEach { $0.resume() }
    }
}

private struct AdversarialFixture {
    let refreshKey = Curve25519.Signing.PrivateKey()
    let bundleKey = Curve25519.Signing.PrivateKey()
    let deviceSigner = AdversarialSigner()
    let nonce = Data(repeating: 0x41, count: 16).base64URL

    var refreshTrust: NativeRefreshHintTrust {
        get throws {
            try NativeRefreshHintTrust(
                organizationID: adversarialOrganization,
                deviceID: adversarialDevice,
                publicKeysPEM: ["refresh-v1": ed25519PEM(refreshKey.publicKey)]
            )
        }
    }

    var bundleTrust: NativeControlBundleV2Trust {
        NativeControlBundleV2Trust(
            publicKey: bundleKey.publicKey,
            issuer: "agentpass-cloud",
            keyID: "control-v2",
            audience: .init(organizationID: adversarialOrganization, deviceID: adversarialDevice)
        )
    }

    func hint(generation: Int64) throws -> NativeRefreshHint {
        let unsigned = NativeRefreshHint(
            organizationID: adversarialOrganization,
            deviceID: adversarialDevice,
            authorityGeneration: generation,
            publishedAt: "2026-08-13T00:00:00.000Z",
            expiresAt: "2026-08-13T00:05:00.000Z",
            nonce: nonce,
            keyID: "refresh-v1",
            signature: Data(repeating: 0, count: 64).base64URL
        )
        let signature = try refreshKey.signature(for: NativeRefreshHintCodec.signingData(unsigned))
        return NativeRefreshHint(
            organizationID: unsigned.organizationID,
            deviceID: unsigned.deviceID,
            authorityGeneration: generation,
            publishedAt: unsigned.publishedAt,
            expiresAt: unsigned.expiresAt,
            nonce: unsigned.nonce,
            keyID: unsigned.keyID,
            signature: signature.base64URL
        )
    }

    func bundle(
        generation: Int64,
        sequence: Int64,
        expiresAt: String = "2026-08-13T00:05:00.000Z"
    ) throws -> NativeDeviceSyncBundleFetchResponse {
        let unsigned: [String: Any] = [
            "format_epoch": 2,
            "issuer": "agentpass-cloud",
            "organization_id": adversarialOrganization,
            "device_id": adversarialDevice,
            "audience": ["organization_id": adversarialOrganization, "device_id": adversarialDevice],
            "issued_at": "2026-08-13T00:00:00.000Z",
            "expires_at": expiresAt,
            "sequence": sequence,
            "policy_scope": [
                "operations": ["git.commit.sign"],
                "repositories": ["/work/project"],
                "branches": ["allow": ["feature/*"]],
                "remotes": ["allow": ["git@github.com:org/repo.git"]]
            ],
            "global_revoked": false,
            "revoked_devices": [],
            "revoked_agents": [],
            "revoked_capabilities": [],
            "offline_ttl_ms": 60_000,
            "key_id": "control-v2"
        ]
        let data = try NativeControlBundleV2Codec.issue(
            unsignedJSON: JSONSerialization.data(withJSONObject: unsigned, options: [.sortedKeys, .withoutEscapingSlashes]),
            signingKey: bundleKey,
            nowMilliseconds: adversarialNow
        )
        return NativeDeviceSyncBundleFetchResponse(
            bundleData: data,
            bundle: try NativeControlBundleV2Codec.parse(data, nowMilliseconds: adversarialNow),
            desiredGeneration: generation
        )
    }

    func coordinator(
        transport: AdversarialTransport,
        snapshot: AdversarialSnapshotStore,
        bundles: AdversarialBundleStore,
        activator: AdversarialActivator,
        now: @escaping @Sendable () -> Int64 = { adversarialNow }
    ) throws -> NativeDeviceSyncCoordinator {
        try NativeDeviceSyncCoordinator(
            organizationID: adversarialOrganization,
            deviceID: adversarialDevice,
            deviceKeyEpoch: 3,
            transport: transport,
            hintVerifier: NativeRefreshHintVerifier(trust: refreshTrust),
            bundleTrust: bundleTrust,
            snapshotStore: snapshot,
            bundleStore: bundles,
            activator: activator,
            acknowledgementSigner: deviceSigner,
            nowMilliseconds: now
        )
    }
}

@Test
func coordinatorRestartsFromEveryDurableStateAndConverges() async throws {
    let fixture = AdversarialFixture()
    let response = try fixture.bundle(generation: 1, sequence: 1)
    let statementHash = try NativeControlBundleV2Codec.statementHash(response.bundle)

    for durableState in NativeDeviceRefreshMachineState.allCases {
        let snapshot = try adversarialSnapshot(
            state: durableState,
            statementHash: statementHash
        )
        let snapshotStore = try AdversarialSnapshotStore(snapshot: snapshot)
        let transport = AdversarialTransport(
            polls: [.init(hint: nil), .init(hint: nil)],
            fetches: [.init(bundleData: response.bundleData, bundle: response.bundle, desiredGeneration: 1)],
            acknowledgementState: durableState == .blocked ? .blocked : .applied
        )
        let bundles = AdversarialBundleStore()
        let activator = AdversarialActivator()
        let coordinator = try fixture.coordinator(
            transport: transport,
            snapshot: snapshotStore,
            bundles: bundles,
            activator: activator
        )

        let result = try await coordinator.synchronize(waitMilliseconds: 0)
        switch durableState {
        case .idle, .pollDue, .acknowledged:
            #expect(result == .noChange(generation: 1) || result == .noChange(generation: 0))
        case .blocked:
            #expect(result == .blocked(generation: 1, sequence: 1, reason: .bundleSignatureInvalid))
        case .hinted, .fetching, .verifying, .staging, .applied:
            #expect(result == .applied(generation: 1, sequence: 1))
        }
        #expect(await coordinator.snapshot().state == .idle)
        #expect(try snapshotStore.snapshot()?.state == .idle)
    }
}

@Test
func coordinatorReplaysActivationExactlyAfterDurableStagingFailure() async throws {
    let fixture = AdversarialFixture()
    let response = try fixture.bundle(generation: 1, sequence: 7)
    let statementHash = try NativeControlBundleV2Codec.statementHash(response.bundle)
    let snapshotStore = try AdversarialSnapshotStore(snapshot: adversarialSnapshot(state: .staging, statementHash: statementHash, sequence: 7))
    let transport = AdversarialTransport(
        fetches: [
            .init(bundleData: response.bundleData, bundle: response.bundle, desiredGeneration: 1),
            .init(bundleData: response.bundleData, bundle: response.bundle, desiredGeneration: 1)
        ]
    )
    let bundles = AdversarialBundleStore()
    let activator = AdversarialActivator()
    activator.failNext = true

    let first = try fixture.coordinator(
        transport: transport,
        snapshot: snapshotStore,
        bundles: bundles,
        activator: activator
    )
    await #expect(throws: NativeDeviceSyncCoordinatorError.activationUnavailable) {
        try await first.synchronize(waitMilliseconds: 0)
    }
    #expect(try snapshotStore.snapshot()?.state == .staging)
    #expect(activator.invocations == 1)

    let restarted = try fixture.coordinator(
        transport: transport,
        snapshot: snapshotStore,
        bundles: bundles,
        activator: activator
    )
    #expect(try await restarted.synchronize(waitMilliseconds: 0) == .applied(generation: 1, sequence: 7))
    #expect(activator.invocations == 2)
    #expect(activator.bundles.count == 2)
    #expect(activator.bundles[0] == activator.bundles[1])
    #expect(bundles.installCount == 2)
}

@Test
func coordinatorDoesNotApplyAnAlreadyExpiredBundleDuringVerification() async throws {
    let fixture = AdversarialFixture()
    let clock = AdversarialClock()
    let response = try fixture.bundle(
        generation: 1,
        sequence: 3,
        expiresAt: "2026-08-13T00:00:01.000Z"
    )
    let statementHash = try NativeControlBundleV2Codec.statementHash(response.bundle)
    let snapshotStore = try AdversarialSnapshotStore(snapshot: adversarialSnapshot(state: .staging, statementHash: statementHash, sequence: 3))
    let transport = AdversarialTransport(
        fetches: [.init(bundleData: response.bundleData, bundle: response.bundle, desiredGeneration: 1)],
        acknowledgementState: .blocked
    )
    let bundles = AdversarialBundleStore()
    let activator = AdversarialActivator()
    activator.onInvocation = { clock.advance(by: 2_000) }
    let coordinator = try fixture.coordinator(
        transport: transport,
        snapshot: snapshotStore,
        bundles: bundles,
        activator: activator,
        now: { clock.now() }
    )

    let result = try await coordinator.synchronize(waitMilliseconds: 0)
    #expect(result == .blocked(generation: 1, sequence: 3, reason: .bundleExpired))
    #expect(activator.invocations == 1)
    #expect(transport.acknowledgements.first?.result == .blocked)
    #expect(transport.acknowledgements.first?.reasonCode == .bundleExpired)
}

@Test
func concurrentSynchronizeCallsExposeTheMissingWholeCycleLock() async throws {
    let fixture = AdversarialFixture()
    let gate = AdversarialReleaseGate()
    let transport = AdversarialTransport(
        polls: [.init(hint: nil), .init(hint: nil)]
    )
    transport.pollGate = gate
    let snapshotStore = try AdversarialSnapshotStore()
    let coordinator = try fixture.coordinator(
        transport: transport,
        snapshot: snapshotStore,
        bundles: AdversarialBundleStore(),
        activator: AdversarialActivator()
    )

    let first = Task { try await coordinator.synchronize(waitMilliseconds: 0) }
    let second = Task { try await coordinator.synchronize(waitMilliseconds: 0) }
    for _ in 0..<100 {
        if transport.maximumConcurrentPolls >= 2 { break }
        try await Task.sleep(nanoseconds: 5_000_000)
    }
    gate.release()
    _ = try await first.value
    _ = try await second.value

    #expect(transport.maximumConcurrentPolls <= 1)
}

@Test
func deviceSyncErrorsRemainRedactedAcrossCoordinatorTransportAndStateMachine() async throws {
    let marker = "SECRET_DEVICE_NONCE_PRIVATE_PAYLOAD_4f6c8d"
    let errors: [any Error] = [
        NativeDeviceSyncCoordinatorError.transportUnavailable,
        NativeDeviceSyncCoordinatorError.verificationFailed,
        NativeDeviceSyncCoordinatorError.activationUnavailable,
        NativeDeviceSyncHTTPTransportError.unexpectedStatusCode(503),
        NativeDeviceSyncHTTPTransportError.unexpectedURL,
        NativeDeviceRefreshStateMachineError(.statementHashConflict, failClosed: true)
    ]
    for error in errors {
        let description = String(describing: error)
        #expect(!description.contains(marker))
        #expect(!(error.localizedDescription).contains(marker))
    }

    let transport = AdversarialTransport()
    transport.failPoll(with: NSError(domain: marker, code: 17, userInfo: [NSLocalizedDescriptionKey: marker]))
    let fixture = AdversarialFixture()
    let snapshot = try AdversarialSnapshotStore()
    let coordinator = try fixture.coordinator(
        transport: transport,
        snapshot: snapshot,
        bundles: AdversarialBundleStore(),
        activator: AdversarialActivator()
    )
    let task = Task { try await coordinator.synchronize(waitMilliseconds: 0) }
    do {
        _ = try await task.value
        Issue.record("expected transport failure")
    } catch {
        #expect(error as? NativeDeviceSyncCoordinatorError == .transportUnavailable)
        #expect(!String(describing: error).contains(marker))
        #expect(!(error.localizedDescription).contains(marker))
    }
}

private func adversarialSnapshot(
    state: NativeDeviceRefreshMachineState,
    statementHash: String,
    sequence: Int64 = 1
) throws -> NativeDeviceRefreshSnapshot {
    let hasHint = [.hinted, .fetching, .verifying, .staging, .applied, .blocked, .acknowledged].contains(state)
    let hasBundle = [.verifying, .staging, .applied, .blocked, .acknowledged].contains(state)
    return NativeDeviceRefreshSnapshot(
        state: state,
        organizationID: adversarialOrganization,
        deviceID: adversarialDevice,
        generation: hasHint ? 1 : 0,
        sequence: hasBundle ? sequence : nil,
        statementHash: hasBundle ? statementHash : nil,
        refreshNonce: hasHint ? Data(repeating: 0x41, count: 16).base64URL : nil,
        sequenceWatermark: hasBundle ? sequence : 0,
        blockedReason: state == .blocked ? .bundleSignatureInvalid : nil,
        revision: 9
    )
}

private func ed25519PEM(_ key: Curve25519.Signing.PublicKey) -> String {
    let prefix = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])
    return "-----BEGIN PUBLIC KEY-----\n\((prefix + key.rawRepresentation).base64EncodedString())\n-----END PUBLIC KEY-----\n"
}

private extension Data {
    var base64URL: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
