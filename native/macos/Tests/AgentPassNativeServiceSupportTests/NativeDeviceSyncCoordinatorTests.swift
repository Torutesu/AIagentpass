import AgentPassNativeCore
import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeServiceSupport

private let coordinatorOrganization = "11111111-1111-4111-8111-111111111111"
private let coordinatorDevice = "22222222-2222-4222-8222-222222222222"
private let coordinatorNow: Int64 = 1_786_579_200_000

private final class CoordinatorSnapshotStore: NativeDeviceRefreshSnapshotStore, @unchecked Sendable {
    private let lock = NSLock()
    private var value: Data?
    var failNextSave = false

    func load() throws -> Data? { lock.withLock { value } }
    func save(_ canonicalSnapshot: Data) throws {
        try lock.withLock {
            if failNextSave {
                failNextSave = false
                throw NativeDeviceRefreshStateMachineError(.snapshotSaveFailed)
            }
            value = canonicalSnapshot
        }
    }
}

private final class CoordinatorBundleStore: NativeDeviceSyncBundleInstalling, @unchecked Sendable {
    private let lock = NSLock()
    private var snapshot: NativeAtomicControlBundleSnapshot?
    var failNextInstall = false

    func active() throws -> NativeAtomicControlBundleSnapshot? { lock.withLock { snapshot } }
    func install(descriptor: NativeAtomicControlBundleDescriptor, canonicalBytes: Data) throws -> NativeAtomicControlBundleSnapshot {
        try lock.withLock {
            if failNextInstall {
                failNextInstall = false
                throw NativeAtomicControlBundleStoreError(.ioFailure)
            }
            let next = NativeAtomicControlBundleSnapshot(descriptor: descriptor, canonicalBytes: canonicalBytes)
            snapshot = next
            return next
        }
    }
}

private final class CoordinatorActivator: NativeDeviceSyncBundleActivating, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var calls = 0
    func activateVerifiedBundle(_ canonicalBundle: Data, nowMilliseconds: Int64) throws {
        lock.withLock { calls += 1 }
    }
}

private struct CoordinatorSigner: P256MessageSigner {
    let key: P256.Signing.PrivateKey
    var publicKeyX963: Data { key.publicKey.x963Representation }
    func sign(message: Data) throws -> Data { try key.signature(for: message).rawRepresentation }
}

private final class CoordinatorTransport: NativeDeviceSyncTransporting, @unchecked Sendable {
    private let lock = NSLock()
    var polls: [NativeDeviceSyncRefreshPollResponse]
    var fetches: [NativeDeviceSyncBundleFetchResponse]
    var acknowledgementState: NativeDeviceRefreshState
    var failSnapshotAfterRemoteACK: CoordinatorSnapshotStore?
    private(set) var acknowledgements: [NativeBundleAcknowledgement] = []
    private(set) var afterGenerations: [Int64] = []

    init(polls: [NativeDeviceSyncRefreshPollResponse], fetches: [NativeDeviceSyncBundleFetchResponse], acknowledgementState: NativeDeviceRefreshState = .applied) {
        self.polls = polls
        self.fetches = fetches
        self.acknowledgementState = acknowledgementState
    }

    func pollRefresh(afterGeneration: Int64, waitMilliseconds: Int) async throws -> NativeDeviceSyncRefreshPollResponse {
        try lock.withLock {
            afterGenerations.append(afterGeneration)
            guard !polls.isEmpty else { throw NativeDeviceSyncCoordinatorError.transportUnavailable }
            return polls.removeFirst()
        }
    }

    func fetchBundle() async throws -> NativeDeviceSyncBundleFetchResponse {
        try lock.withLock {
            guard !fetches.isEmpty else { throw NativeDeviceSyncCoordinatorError.transportUnavailable }
            return fetches.removeFirst()
        }
    }

    func submitAcknowledgement(_ acknowledgement: NativeBundleAcknowledgement) async throws -> NativeDeviceSyncAcknowledgementResponse {
        lock.withLock { acknowledgements.append(acknowledgement) }
        failSnapshotAfterRemoteACK?.failNextSave = true
        return NativeDeviceSyncAcknowledgementResponse(
            accepted: true,
            duplicate: acknowledgements.count > 1,
            observedGeneration: lock.withLock { afterGenerations.last.map { $0 + 1 } ?? 1 },
            refreshState: acknowledgementState
        )
    }
}

private struct CoordinatorFixture {
    let refreshKey = Curve25519.Signing.PrivateKey()
    let bundleKey = Curve25519.Signing.PrivateKey()
    let deviceSigner = CoordinatorSigner(key: P256.Signing.PrivateKey())
    let nonce = Data(repeating: 0x41, count: 16).base64URL

    var refreshTrust: NativeRefreshHintTrust {
        get throws {
            try NativeRefreshHintTrust(
                organizationID: coordinatorOrganization,
                deviceID: coordinatorDevice,
                publicKeysPEM: ["refresh-v1": ed25519PEM(refreshKey.publicKey)]
            )
        }
    }

    var bundleTrust: NativeControlBundleV2Trust {
        NativeControlBundleV2Trust(
            publicKey: bundleKey.publicKey,
            issuer: "agentpass-cloud",
            keyID: "control-v2",
            audience: .init(organizationID: coordinatorOrganization, deviceID: coordinatorDevice)
        )
    }

    func hint(generation: Int64) throws -> NativeRefreshHint {
        let unsigned = NativeRefreshHint(
            organizationID: coordinatorOrganization,
            deviceID: coordinatorDevice,
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
            nonce: nonce,
            keyID: unsigned.keyID,
            signature: signature.base64URL
        )
    }

    func bundle(generation: Int64, sequence: Int64, signingKey: Curve25519.Signing.PrivateKey? = nil) throws -> NativeDeviceSyncBundleFetchResponse {
        let key = signingKey ?? bundleKey
        let unsigned: [String: Any] = [
            "format_epoch": 2, "issuer": "agentpass-cloud",
            "organization_id": coordinatorOrganization, "device_id": coordinatorDevice,
            "audience": ["organization_id": coordinatorOrganization, "device_id": coordinatorDevice],
            "issued_at": "2026-08-13T00:00:00.000Z", "expires_at": "2026-08-13T00:05:00.000Z",
            "sequence": sequence,
            "policy_scope": [
                "operations": ["git.commit.sign"], "repositories": ["/work/project"],
                "branches": ["allow": ["feature/*"]], "remotes": ["allow": ["git@github.com:org/repo.git"]]
            ],
            "global_revoked": false, "revoked_devices": [], "revoked_agents": [], "revoked_capabilities": [],
            "offline_ttl_ms": 60_000, "key_id": "control-v2"
        ]
        let data = try NativeControlBundleV2Codec.issue(
            unsignedJSON: JSONSerialization.data(withJSONObject: unsigned, options: [.sortedKeys, .withoutEscapingSlashes]),
            signingKey: key,
            nowMilliseconds: coordinatorNow
        )
        return NativeDeviceSyncBundleFetchResponse(
            bundleData: data,
            bundle: try NativeControlBundleV2Codec.parse(data, nowMilliseconds: coordinatorNow),
            desiredGeneration: generation
        )
    }

    func coordinator(transport: CoordinatorTransport, snapshot: CoordinatorSnapshotStore, bundles: CoordinatorBundleStore, activator: CoordinatorActivator) throws -> NativeDeviceSyncCoordinator {
        try NativeDeviceSyncCoordinator(
            organizationID: coordinatorOrganization,
            deviceID: coordinatorDevice,
            deviceKeyEpoch: 3,
            transport: transport,
            hintVerifier: NativeRefreshHintVerifier(trust: refreshTrust),
            bundleTrust: bundleTrust,
            snapshotStore: snapshot,
            bundleStore: bundles,
            activator: activator,
            acknowledgementSigner: deviceSigner,
            nowMilliseconds: { coordinatorNow }
        )
    }
}

@Test func coordinatorCompletesAuthenticatedApplyAndExactACKCycle() async throws {
    let fixture = CoordinatorFixture()
    let transport = CoordinatorTransport(
        polls: [.init(hint: try fixture.hint(generation: 1))],
        fetches: [try fixture.bundle(generation: 1, sequence: 1)]
    )
    let snapshot = CoordinatorSnapshotStore(), bundles = CoordinatorBundleStore(), activator = CoordinatorActivator()
    let coordinator = try fixture.coordinator(transport: transport, snapshot: snapshot, bundles: bundles, activator: activator)
    #expect(try await coordinator.synchronize(waitMilliseconds: 30_000) == .applied(generation: 1, sequence: 1))
    #expect(activator.calls == 1)
    let acknowledgement = try #require(transport.acknowledgements.first)
    #expect(acknowledgement.deviceKeyEpoch == 3)
    #expect(acknowledgement.nonce == fixture.nonce)
    let state = await coordinator.snapshot()
    #expect(state.state == .idle)
    #expect(state.generation == 1)
    #expect(state.refreshNonce == nil)
}

@Test func coordinatorRetriesExactACKAfterRemoteSuccessAndLocalCrash() async throws {
    let fixture = CoordinatorFixture()
    let transport = CoordinatorTransport(
        polls: [.init(hint: try fixture.hint(generation: 1))],
        fetches: [try fixture.bundle(generation: 1, sequence: 1)]
    )
    let snapshot = CoordinatorSnapshotStore(), bundles = CoordinatorBundleStore(), activator = CoordinatorActivator()
    transport.failSnapshotAfterRemoteACK = snapshot
    let first = try fixture.coordinator(transport: transport, snapshot: snapshot, bundles: bundles, activator: activator)
    await #expect(throws: NativeDeviceRefreshStateMachineError.self) {
        try await first.synchronize()
    }
    transport.failSnapshotAfterRemoteACK = nil
    let restarted = try fixture.coordinator(transport: transport, snapshot: snapshot, bundles: bundles, activator: activator)
    #expect(try await restarted.synchronize() == .applied(generation: 1, sequence: 1))
    #expect(transport.acknowledgements.count == 2)
    let firstACK = transport.acknowledgements[0], secondACK = transport.acknowledgements[1]
    #expect(firstACK.organizationID == secondACK.organizationID)
    #expect(firstACK.deviceID == secondACK.deviceID)
    #expect(firstACK.deviceKeyEpoch == secondACK.deviceKeyEpoch)
    #expect(firstACK.sequence == secondACK.sequence)
    #expect(firstACK.statementHash == secondACK.statementHash)
    #expect(firstACK.result == secondACK.result)
    #expect(firstACK.observedAt == secondACK.observedAt)
    #expect(firstACK.nonce == secondACK.nonce)
}

@Test func coordinatorRefetchesAfterSupersededGenerationAndBlocksForgedBundle() async throws {
    let fixture = CoordinatorFixture()
    let forgedKey = Curve25519.Signing.PrivateKey()
    let transport = CoordinatorTransport(
        polls: [.init(hint: try fixture.hint(generation: 1)), .init(hint: try fixture.hint(generation: 2))],
        fetches: [try fixture.bundle(generation: 2, sequence: 2), try fixture.bundle(generation: 2, sequence: 2, signingKey: forgedKey)],
        acknowledgementState: .blocked
    )
    let snapshot = CoordinatorSnapshotStore(), bundles = CoordinatorBundleStore(), activator = CoordinatorActivator()
    let coordinator = try fixture.coordinator(transport: transport, snapshot: snapshot, bundles: bundles, activator: activator)
    #expect(try await coordinator.synchronize() == .blocked(generation: 2, sequence: 2, reason: .bundleSignatureInvalid))
    #expect(transport.afterGenerations == [0, 1])
    #expect(activator.calls == 0)
    #expect(transport.acknowledgements.first?.reasonCode == .bundleSignatureInvalid)
}

private func ed25519PEM(_ key: Curve25519.Signing.PublicKey) -> String {
    let prefix = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])
    return "-----BEGIN PUBLIC KEY-----\n\((prefix + key.rawRepresentation).base64EncodedString())\n-----END PUBLIC KEY-----\n"
}

private extension Data {
    var base64URL: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}
