import CryptoKit
import Foundation
import Testing

@testable import AgentPassNativeCore

private let brokerAgentID = "33333333-3333-4333-8333-333333333333"
private let brokerDeviceID = "44444444-4444-4444-8444-444444444444"
private let brokerOrganizationID = "66666666-6666-4666-8666-666666666666"
private let brokerSessionID = "11111111-1111-4111-8111-111111111111"
private let brokerRequestID = "22222222-2222-4222-8222-222222222222"
private let brokerCapabilityID = "88888888-8888-4888-8888-888888888888"
private let brokerToken = String(repeating: "a", count: 64)
private let brokerWall: Int64 = 1_786_615_200_000
private let brokerCapabilityPublicKeyPEM = """
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA6tOzXpegx8uirXcRscbgSA9jsm/JG0Odtv7b56m0pxw=
-----END PUBLIC KEY-----
"""
private let brokerCapabilityKeyID = "capability-v1"

private struct BrokerRandom: NativeAgentRandomBytesGenerating {
    func randomBytes(count: Int) throws -> Data { Data(repeating: 9, count: count) }
}

private struct BrokerWallClock: NativeAgentWallClock {
    func sample() throws -> NativeAgentWallClockValue {
        NativeAgentWallClockValue(millisecondsSinceUnixEpoch: brokerWall + 1_000)
    }
}

private struct BrokerMonotonicClock: NativeAgentMonotonicClock {
    func sample() throws -> NativeAgentMonotonicClockValue {
        try NativeAgentMonotonicClockValue(nanoseconds: 2_000, bootIdentity: "broker-test-boot")
    }
}

private struct BrokerBindingObserver: NativeAgentSessionBindingObserving {
    let binding: NativeAgentSessionBinding

    func observeSessionBinding(agentID: String) throws -> NativeAgentSessionBinding {
        guard agentID == binding.agentID else {
            throw NativeAgentSessionCoordinatorError.bindingDenied
        }
        return binding
    }
}

private struct BrokerGrantConsumer: NativeAgentGrantLeaseConsuming {
    let lease: NativeAgentVerifiedCloudLease

    func consumeGrant(_ request: NativeAgentGrantConsumptionRequest)
        throws -> NativeAgentVerifiedCloudLease
    {
        lease
    }
}

private final class BrokerAudit: NativeAgentSessionAuditAppending, @unchecked Sendable {
    private let lock = NSLock()
    private var nextIndex = 0

    @discardableResult
    func appendAgentSessionAudit(_ evidence: NativeAgentSessionAuditEvidence)
        throws -> NativeAgentSessionAuditReceipt
    {
        try append(evidence)
    }

    @discardableResult
    func reconcileAgentSessionActivationAudit(_ evidence: NativeAgentSessionAuditEvidence)
        throws -> NativeAgentSessionAuditReceipt
    {
        try append(evidence)
    }

    @discardableResult
    func reconcileAgentSessionActivationOutcomeAudit(
        _ evidence: NativeAgentSessionAuditEvidence
    ) throws -> NativeAgentSessionAuditReceipt {
        try append(evidence)
    }

    func lookupAgentSessionActivationOutcomeAudit(
        _ evidence: NativeAgentSessionAuditEvidence
    ) throws -> NativeAgentSessionAuditReceipt? {
        nil
    }

    private func append(_ evidence: NativeAgentSessionAuditEvidence)
        throws -> NativeAgentSessionAuditReceipt
    {
        let index = lock.withLock {
            nextIndex += 1
            return nextIndex
        }
        return try NativeAgentSessionAuditReceipt(
            evidenceDigest: evidence.evidenceDigest(),
            recordDigest: Data(repeating: UInt8(index), count: 32),
            recordIndex: index)
    }
}

private func brokerWorktree() throws -> NativeAgentWorktreeBinding {
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

private func brokerBinding() throws -> NativeAgentSessionBinding {
    try NativeAgentSessionBinding(
        agentID: brokerAgentID,
        deviceID: brokerDeviceID,
        processBindingDigest: Data(repeating: 0xbb, count: 32),
        ancestryBindingDigest: Data(repeating: 0xcc, count: 32),
        worktreeBindingDigest: try brokerWorktree().digest,
        controlSequence: 12,
        authorityGeneration: 7,
        keyGeneration: 99)
}

private func brokerLease(binding: NativeAgentSessionBinding)
    throws -> NativeAgentVerifiedCloudLease
{
    func hex(_ value: Data) -> String {
        value.map { String(format: "%02x", $0) }.joined()
    }

    return try NativeAgentLeaseCodec.decode(
        NativeStrictJSON.data([
            "version": 1,
            "type": "agentpass.agent-session-lease",
            "session_id": brokerSessionID,
            "grant_id": "55555555-5555-4555-8555-555555555555",
            "organization_id": brokerOrganizationID,
            "device_id": brokerDeviceID,
            "agent_id": brokerAgentID,
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

private func brokerRequest(
    requestID: String = brokerRequestID,
    capabilityID: String = brokerCapabilityID
) throws -> AgentPassAgentSignRequest {
    let capability = try NativeStrictJSON.data([
        "version": 1,
        "capability_id": capabilityID,
        "nonce": String(repeating: "N", count: 32),
        "issuer": "agentpass-cloud",
        "key_id": "capability-v1",
        "audience": ["agent_id": brokerAgentID, "device_id": brokerDeviceID],
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
        sessionID: brokerSessionID,
        requestID: requestID,
        capabilityID: capabilityID,
        capability: capability,
        commitPayload: Data("commit payload".utf8),
        requestNonce: Data(repeating: 0x2a, count: 16),
        createdAtMilliseconds: brokerWall + 1_000))
}

private func brokerAuthority(
    request: AgentPassAgentSignRequest,
    binding: NativeAgentSessionBinding
) throws -> NativeSigningTransactionAuthority {
    try NativeSigningTransactionAuthority(
        request: try NativeSigningTransactionRequest(request),
        binding: binding,
        worktree: try brokerWorktree(),
        keyLifecycleIdentity: String(repeating: "f", count: 64))
}

private func brokerRuntimeAuthority() throws -> NativeAgentRuntimeAuthorityConfiguration {
    let configuration = try NativeAgentRuntimeConfiguration(
        deviceAPIOrigin: URL(string: "https://api.agentpass.test"),
        organizationID: brokerOrganizationID,
        deviceID: brokerDeviceID,
        deviceKeyTag: NativeEnrollmentKeyMaterial.fixedApplicationTag,
        signingIntentDirectory: "/private/tmp/agentpass-broker-signing-intents",
        globalSessionLimit: 8,
        perAgentSessionLimit: 4,
        perWorktreeSessionLimit: 2,
        bootstrapAttemptLimit: 3,
        worktreeObservationPolicyVersion: 2,
        capabilityPublicKeyPEM: brokerCapabilityPublicKeyPEM,
        capabilityKeyID: brokerCapabilityKeyID)
    return try #require(configuration.authority)
}

private final class BrokerFixture {
    let root: URL
    let coordinator: NativeAgentSessionCoordinator
    let request: AgentPassAgentSignRequest
    let binding: NativeAgentSessionBinding

    init(start: Bool) throws {
        root = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
            .appendingPathComponent("agentpass-dedicated-broker-\(UUID().uuidString)")
            .standardizedFileURL
        try FileManager.default.createDirectory(
            at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let binding = try brokerBinding()
        self.binding = binding

        let bootstrapStore = NativeAgentBootstrapChallengeStore(random: BrokerRandom())
        let bootHash = Data(SHA256.hash(data: Data("broker-test-boot".utf8)))
            .map { String(format: "%02x", $0) }.joined()
        let connection = try NativeAgentBootstrapConnectionBinding(
            connectionTokenIdentity: brokerToken,
            processBindingHash: binding.processBindingDigest
                .map { String(format: "%02x", $0) }.joined(),
            ancestryBindingHash: binding.ancestryBindingDigest
                .map { String(format: "%02x", $0) }.joined(),
            bootIdentityHash: bootHash)
        let challenge = try bootstrapStore.begin(
            agentID: brokerAgentID,
            adapterKind: .claudeCode,
            requestedTTLSeconds: 900,
            clientNonce: Data(repeating: 5, count: 32),
            connectionBinding: connection,
            nowMilliseconds: brokerWall,
            nowMonotonicNanoseconds: 1_000)

        let coordinator = try NativeAgentSessionCoordinator(
            connectionTokenIdentity: brokerToken,
            connectionRevalidator: {},
            bootstrapStore: bootstrapStore,
            bindingObserver: BrokerBindingObserver(binding: binding),
            grantConsumer: BrokerGrantConsumer(lease: try brokerLease(binding: binding)),
            recoveryStore: try NativeAgentSessionConsumeRecoveryStore(
                path: root.appendingPathComponent("recovery-v3.json").standardizedFileURL.path),
            activationRecoveryStore: try NativeAgentSessionConsumeRecoveryV4Store(
                path: root.appendingPathComponent("recovery-v4.json").standardizedFileURL.path),
            registry: NativeAgentSessionRegistry(),
            audit: BrokerAudit(),
            wallClock: BrokerWallClock(),
            monotonicClock: BrokerMonotonicClock(),
            random: BrokerRandom(),
            authority: try brokerRuntimeAuthority())
        self.coordinator = coordinator
        self.request = try brokerRequest()

        if start {
            _ = try coordinator.start(
                bootstrapID: challenge.bootstrapID,
                proof: Data(repeating: 0xee, count: 32))
        }
    }

    deinit {
        try? FileManager.default.removeItem(at: root)
    }
}

private enum BrokerProviderFailure: Error { case failed }

@Test("Dedicated broker fails explicitly when its service association is absent")
func dedicatedBrokerRejectsMissingAssociation() throws {
    let broker = NativeAgentDedicatedSigningHandoffBroker(association: nil)
    let input: NativeAgentDedicatedSigningHandoffInputs? = nil
    #expect(throws: NativeAgentDedicatedSigningHandoffBrokerError.associationMissing) {
        _ = try broker.makeAdapter(for: input)
    }
}

@Test("Dedicated broker fails explicitly when no service handoff inputs exist")
func dedicatedBrokerRejectsMissingHandoff() throws {
    let fixture = try BrokerFixture(start: false)
    let association = NativeAgentDedicatedSigningAssociation(
        coordinator: fixture.coordinator,
        transactionStore: try NativeSigningTransactionStore(
            path: fixture.root.appendingPathComponent("transactions.json").standardizedFileURL.path))
    let broker = NativeAgentDedicatedSigningHandoffBroker(association: association)

    #expect(throws: NativeAgentDedicatedSigningHandoffBrokerError.handoffMissing) {
        _ = try broker.makeAdapter(for: nil)
    }
}

@Test("Dedicated broker rejects inputs issued by a different association")
func dedicatedBrokerRejectsAssociationInputSubstitution() throws {
    let fixture = try BrokerFixture(start: false)
    let firstAssociation = NativeAgentDedicatedSigningAssociation(
        coordinator: fixture.coordinator,
        transactionStore: try NativeSigningTransactionStore(
            path: fixture.root.appendingPathComponent("transactions-a.json").standardizedFileURL.path))
    let secondAssociation = NativeAgentDedicatedSigningAssociation(
        coordinator: fixture.coordinator,
        transactionStore: try NativeSigningTransactionStore(
            path: fixture.root.appendingPathComponent("transactions-b.json").standardizedFileURL.path))
    let input = firstAssociation.makeHandoffInputs(
        request: fixture.request,
        authorityProvider: { [request = fixture.request] binding in
            try brokerAuthority(request: request, binding: binding)
        })

    #expect(throws: NativeAgentDedicatedSigningHandoffBrokerError.invalidAssociation) {
        _ = try NativeAgentDedicatedSigningHandoffBroker(association: secondAssociation)
            .makeAdapter(for: input)
    }
}

@Test("Dedicated broker creates a fresh adapter for each service request")
func dedicatedBrokerCreatesFreshAdapterPerRequest() throws {
    let fixture = try BrokerFixture(start: true)
    let association = NativeAgentDedicatedSigningAssociation(
        coordinator: fixture.coordinator,
        transactionStore: try NativeSigningTransactionStore(
            path: fixture.root.appendingPathComponent("transactions.json").standardizedFileURL.path))
    let inputs = association.makeHandoffInputs(
        request: fixture.request,
        authorityProvider: { [request = fixture.request] binding in
            try brokerAuthority(request: request, binding: binding)
        },
    )
    let broker = NativeAgentDedicatedSigningHandoffBroker(association: association)

    let first = try broker.makeAdapter(for: inputs)
    let second = try broker.makeAdapter(for: inputs)
    #expect(ObjectIdentifier(first) != ObjectIdentifier(second))
    #expect(first.currentPhase == NativeAgentSessionCoordinatorSigningAdapterPhase.ready)
    #expect(second.currentPhase == NativeAgentSessionCoordinatorSigningAdapterPhase.ready)
}

@Test("Dedicated broker delegates provider-once and outcome-unknown to the existing adapter")
func dedicatedBrokerDelegatesAdapterOutcomeSemantics() throws {
    let fixture = try BrokerFixture(start: true)
    let association = NativeAgentDedicatedSigningAssociation(
        coordinator: fixture.coordinator,
        transactionStore: try NativeSigningTransactionStore(
            path: fixture.root.appendingPathComponent("transactions.json").standardizedFileURL.path))
    let inputs = association.makeHandoffInputs(
        request: fixture.request,
        authorityProvider: { [request = fixture.request] binding in
            try brokerAuthority(request: request, binding: binding)
        },
    )
    let broker = NativeAgentDedicatedSigningHandoffBroker(association: association)
    let adapter = try broker.makeAdapter(for: inputs)
    let calls = LockIsolatedInt()
    let expectedPayload = fixture.request.commitPayload

    #expect(throws: NativeAgentSessionCoordinatorSigningAdapterError.outcomeUnknown) {
        _ = try adapter.execute { payload in
            calls.increment()
            #expect(payload == expectedPayload)
            throw BrokerProviderFailure.failed
        }
    }
    #expect(calls.value == 1)
    #expect(adapter.currentPhase == .unknown)
    #expect(throws: NativeAgentDedicatedSigningHandoffBrokerError.handoffMissing) {
        _ = try broker.makeAdapter(for: inputs)
    }
}

@Test("Dedicated broker contract contains no Host or Child authority surface")
func dedicatedBrokerHasNoTransportAuthoritySurface() throws {
    let testDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    let sourceURL = testDirectory
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent(
            "Sources/AgentPassNativeCore/NativeAgentDedicatedSigningHandoffBroker.swift")
    let source = try String(contentsOf: sourceURL, encoding: .utf8)

    #expect(source.contains("AgentPassHostSignRequest") == false)
    #expect(source.contains("AgentPassChildGitSignRequest") == false)
    #expect(source.contains("NativeAgentSessionCoordinator"))
    #expect(source.contains("NativeAgentSessionCoordinatorSigningAdapter"))
    #expect(source.contains("makeSigningHandoff"))
    #expect(source.contains("provider(" ) == false)
}

private final class LockIsolatedInt: @unchecked Sendable {
    private let lock = NSLock()
    private var storage = 0

    var value: Int { lock.withLock { storage } }
    func increment() { lock.withLock { storage += 1 } }
}
