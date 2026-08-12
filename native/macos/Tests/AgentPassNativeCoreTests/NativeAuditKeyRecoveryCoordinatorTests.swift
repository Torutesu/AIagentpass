import CryptoKit
import Darwin
import Foundation
import Testing
@testable import AgentPassNativeCore

private struct RecoveryCoordinatorSigner: P256MessageSigner {
    let key: P256.Signing.PrivateKey
    init(_ byte: UInt8) throws {
        key = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: byte, count: 32))
    }
    var publicKeyX963: Data { key.publicKey.x963Representation }
    func sign(message: Data) throws -> Data { try key.signature(for: message).rawRepresentation }
}

private enum RecoveryCoordinatorTransportError: Error { case lost, shouldNotSend }

private final class RecoveryCoordinatorTransport: NativeAuditKeyRecoveryTransitionTransport, @unchecked Sendable {
    private let lock = NSLock()
    private let handler: (Data, Int) throws -> Data
    private(set) var requests: [Data] = []

    init(_ handler: @escaping (Data, Int) throws -> Data) { self.handler = handler }

    func submitRecoveryTransition(transitionData: Data) throws -> Data {
        lock.lock()
        requests.append(transitionData)
        let attempt = requests.count
        lock.unlock()
        return try handler(transitionData, attempt)
    }
}

private final class RecoveryCoordinatorFixture {
    let authorities: [(String, Curve25519.Signing.PrivateKey)]
    let policy: NativeAuditKeyRecoveryPolicy
    let old: RecoveryCoordinatorSigner
    let replacement: RecoveryCoordinatorSigner
    let lifecycleRoot: URL
    let lifecycleStore: NativeKeyLifecycleStore
    let recoveryEvidenceData: Data
    let authorization: NativeAuditKeyRecoveryAuthorization
    let approvals: [NativeAuditKeyRecoveryApproval]
    let replacementSignature: Data
    let lifecycleData: Data

    init(
        authorities: [(String, Curve25519.Signing.PrivateKey)],
        policy: NativeAuditKeyRecoveryPolicy,
        old: RecoveryCoordinatorSigner,
        replacement: RecoveryCoordinatorSigner,
        lifecycleRoot: URL,
        lifecycleStore: NativeKeyLifecycleStore,
        recoveryEvidenceData: Data,
        authorization: NativeAuditKeyRecoveryAuthorization,
        approvals: [NativeAuditKeyRecoveryApproval],
        replacementSignature: Data,
        lifecycleData: Data
    ) {
        self.authorities = authorities
        self.policy = policy
        self.old = old
        self.replacement = replacement
        self.lifecycleRoot = lifecycleRoot
        self.lifecycleStore = lifecycleStore
        self.recoveryEvidenceData = recoveryEvidenceData
        self.authorization = authorization
        self.approvals = approvals
        self.replacementSignature = replacementSignature
        self.lifecycleData = lifecycleData
    }

    deinit { try? FileManager.default.removeItem(at: lifecycleRoot) }

    func plan(nowMilliseconds: Int64? = nil) throws -> NativeAuditKeyRecoveryPlan {
        try NativeAuditKeyRecoveryPlan(
            pinnedPolicy: policy,
            installationID: "installation-001",
            authorization: authorization,
            approvals: approvals,
            replacementSignature: replacementSignature,
            retiringPublicKeyX963: old.publicKeyX963,
            lifecycleRecordData: lifecycleData,
            nowMilliseconds: nowMilliseconds
        )
    }
}

private func recoveryCoordinatorFixture(
    generation: Int = 1,
    operationID: String = "recovery-operation-1",
    requestID: String = "recovery-request-1",
    previousTransitionHash: String = String(repeating: "0", count: 64),
    previousReceiptHash: String = String(repeating: "0", count: 64),
    old: RecoveryCoordinatorSigner? = nil,
    replacement: RecoveryCoordinatorSigner? = nil,
    previousLifecycleHead: String = String(repeating: "9", count: 64),
    checkpointIndex: Int = 7,
    eventIndex: Int = 10,
    createdAt: String = "2030-01-01T00:00:01.000Z",
    expiresAt: String = "2030-01-01T00:15:01.000Z"
) throws -> RecoveryCoordinatorFixture {
    let authorities = [
        ("alpha", try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x31, count: 32))),
        ("bravo", try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x32, count: 32)))
    ]
    let policy = try NativeAuditKeyRecoveryPolicy(
        policyID: "offline-main",
        threshold: 2,
        keys: authorities.map { try NativeAuditKeyRecoveryPolicyKey(id: $0.0, publicKey: $0.1.publicKey) }
    )
    let retiring = try old ?? RecoveryCoordinatorSigner(UInt8(generation))
    let next = try replacement ?? RecoveryCoordinatorSigner(UInt8(generation + 1))
    let sourcePolicy: [String: Any] = [
        "version": 1,
        "policy_id": "offline-main",
        "threshold": 2,
        "authorities": authorities.map {
            ["id": $0.0, "public_key": recoveryCoordinatorPEM($0.1.publicKey)]
        }
    ]
    let sourcePolicyData = try NativeAuditLog.canonical(sourcePolicy)
    let lifecycleRoot = try recoveryCoordinatorRoot("agentpass-recovery-lifecycle")
    let lifecycleDirectory = lifecycleRoot.appendingPathComponent("ledger")
    try FileManager.default.createDirectory(
        at: lifecycleDirectory,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    guard chmod(lifecycleDirectory.path, 0o700) == 0 else { throw POSIXError(.EIO) }
    let lifecycleStore = try NativeKeyLifecycleStore(
        directory: lifecycleDirectory.path,
        recoveryPublicKeys: authorities.map { $0.1.publicKey.rawRepresentation },
        recoveryThreshold: 2
    )
    let setupTime = "2029-12-31T23:59:59.000Z"
    let approvalKey = try RecoveryCoordinatorSigner(0x51)
    _ = try lifecycleStore.stage(
        role: .sessionApproval, generation: 1, applicationTag: "approval.g1",
        publicKeyX963: approvalKey.publicKeyX963, createdAt: setupTime
    )
    let approvalBootstrap = try lifecycleStore.transitionStatement(
        role: .sessionApproval, generation: 1, reason: "bootstrap", challengeID: "approval-bootstrap",
        createdAt: setupTime, continuity: .bootstrap
    )
    let approvalMessage = try approvalBootstrap.canonicalData()
    _ = try lifecycleStore.activate(
        statement: approvalBootstrap, oldSignature: nil,
        newSignature: approvalKey.sign(message: approvalMessage),
        approvalSignature: approvalKey.sign(message: approvalMessage),
        approvalPublicKeyX963: approvalKey.publicKeyX963
    )

    var activeAudit = generation == 1 ? retiring : try RecoveryCoordinatorSigner(0x61)
    _ = try lifecycleStore.stage(
        role: .auditCheckpoint, generation: 1, applicationTag: "audit.g1",
        publicKeyX963: activeAudit.publicKeyX963, createdAt: setupTime
    )
    let auditBootstrap = try lifecycleStore.transitionStatement(
        role: .auditCheckpoint, generation: 1, reason: "bootstrap", challengeID: "audit-bootstrap",
        createdAt: setupTime, continuity: .bootstrap
    )
    let auditBootstrapMessage = try auditBootstrap.canonicalData()
    _ = try lifecycleStore.activate(
        statement: auditBootstrap, oldSignature: nil,
        newSignature: activeAudit.sign(message: auditBootstrapMessage),
        approvalSignature: approvalKey.sign(message: auditBootstrapMessage),
        approvalPublicKeyX963: approvalKey.publicKeyX963
    )
    if generation > 1 {
        for nextGeneration in 2...generation {
            let candidate = nextGeneration == generation
                ? retiring
                : try RecoveryCoordinatorSigner(UInt8(0x61 + nextGeneration))
            _ = try lifecycleStore.stage(
                role: .auditCheckpoint, generation: nextGeneration,
                applicationTag: "audit.g\(nextGeneration)",
                publicKeyX963: candidate.publicKeyX963, createdAt: setupTime
            )
            let statement = try lifecycleStore.transitionStatement(
                role: .auditCheckpoint, generation: nextGeneration,
                reason: "rotation", challengeID: "audit-rotation-\(nextGeneration)",
                createdAt: setupTime, continuity: .clean
            )
            let statementData = try statement.canonicalData()
            _ = try lifecycleStore.activate(
                statement: statement,
                oldSignature: activeAudit.sign(message: statementData),
                newSignature: candidate.sign(message: statementData),
                approvalSignature: approvalKey.sign(message: statementData),
                approvalPublicKeyX963: approvalKey.publicKeyX963
            )
            activeAudit = candidate
        }
    }
    _ = try lifecycleStore.stage(
        role: .auditCheckpoint, generation: generation + 1,
        applicationTag: "audit.recovered.g\(generation + 1)",
        publicKeyX963: next.publicKeyX963, createdAt: setupTime
    )
    let stagedState = try lifecycleStore.verify()
    let active = try #require(stagedState.active(for: .auditCheckpoint))
    #expect(active.publicKeyX963 == retiring.publicKeyX963)
    let nonceBytes = Data(SHA256.hash(data: Data(requestID.utf8)))
    let nonce = nonceBytes.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
    let requestObject: [String: Any] = [
        "version": 1,
        "installation_id": "installation-001",
        "role": NativeKeyRole.auditCheckpoint.rawValue,
        "from_generation": generation,
        "from_fingerprint": active.fingerprint,
        "proposed_generation": generation + 1,
        "proposed_public_key": try SSHSIG.authorizedKey(publicKeyX963: next.publicKeyX963),
        "recovery_policy_version": 1,
        "recovery_policy_id": "offline-main",
        "recovery_policy_hash": NativeAuditLog.hash(sourcePolicyData),
        "lifecycle_head_hash": stagedState.headHash,
        "audit_entries": 7,
        "audit_head_hash": String(repeating: "8", count: 64),
        "latest_checkpoint_hash": String(repeating: "c", count: 64),
        "latest_receipt_hash": String(repeating: "d", count: 64),
        "control_sequence": 1,
        "nonce": nonce,
        "issued_at": createdAt,
        "expires_at": expiresAt
    ]
    let requestData = try NativeAuditLog.canonical(requestObject)
    let requestHash = NativeAuditLog.hash(requestData)
    let recoveryAuthorizations = try authorities.map { authority -> Data in
        var statement: [String: Any] = [
            "version": 1,
            "signer_id": authority.0,
            "request_hash": requestHash,
            "signed_at": createdAt,
            "public_key_fingerprint": try NativeRecoveryVerifier.authorityFingerprint(
                rawEd25519PublicKey: authority.1.publicKey.rawRepresentation
            )
        ]
        statement["signature"] = try authority.1.signature(
            for: NativeAuditLog.canonical(statement)
        ).base64EncodedString()
        return try NativeAuditLog.canonical(statement)
    }
    let recoveryEvidence = try NativeRecoveryEvidenceBundle(
        requestData: requestData,
        policyData: sourcePolicyData,
        authorizationData: recoveryAuthorizations
    ).canonicalData()
    let recoveryStatement = try lifecycleStore.transitionStatement(
        role: .auditCheckpoint,
        generation: generation + 1,
        reason: "offline-threshold-recovery:\(requestHash)",
        challengeID: nonce,
        createdAt: createdAt,
        continuity: .recovered
    )
    let lifecycle = try lifecycleStore.prepareActivationRecordData(
        statement: recoveryStatement,
        oldSignature: nil,
        newSignature: next.sign(message: recoveryStatement.canonicalData()),
        approvalSignature: recoveryEvidence,
        approvalPublicKeyX963: Data()
    )
    let lifecycleHead = try lifecycleStore.validatePreparedRecordData(lifecycle).headHash
    let authorization = try NativeAuditKeyRecoveryAuthorization(
        tenant: "native-host",
        installationID: "installation-001",
        operationID: operationID,
        recoveryRequestID: requestHash,
        policy: policy,
        fromGeneration: generation,
        oldPublicKeyX963: retiring.publicKeyX963,
        newPublicKeyX963: next.publicKeyX963,
        lifecycleHeadHash: lifecycleHead,
        createdAt: createdAt,
        expiresAt: expiresAt,
        previousTransitionHash: previousTransitionHash,
        previousTransitionReceiptHash: previousReceiptHash,
        lastCheckpointIndex: checkpointIndex,
        lastCheckpointHash: String(repeating: "c", count: 64),
        lastCheckpointReceiptHash: String(repeating: "d", count: 64),
        previousAnchorEventIndex: eventIndex,
        previousAnchorEventHash: String(repeating: "a", count: 64)
    )
    let message = try authorization.canonicalData()
    let approvals = try authorities.map {
        try NativeAuditKeyRecoveryApproval(keyID: $0.0, signature: $0.1.signature(for: message))
    }
    return RecoveryCoordinatorFixture(
        authorities: authorities,
        policy: policy,
        old: retiring,
        replacement: next,
        lifecycleRoot: lifecycleRoot,
        lifecycleStore: lifecycleStore,
        recoveryEvidenceData: recoveryEvidence,
        authorization: authorization,
        approvals: approvals,
        replacementSignature: try next.sign(message: message),
        lifecycleData: lifecycle
    )
}

private func recoveryCoordinatorRoot(_ prefix: String = "agentpass-recovery-coordinator") throws -> URL {
    let build = URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent(".build")
    let root = build.appendingPathComponent("\(prefix)-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    guard chmod(root.path, 0o700) == 0, let resolved = Darwin.realpath(root.path, nil) else { throw POSIXError(.EIO) }
    defer { free(resolved) }
    return URL(fileURLWithPath: String(cString: resolved))
}

private func recoveryCoordinatorPEM(_ key: Curve25519.Signing.PublicKey) -> String {
    let der = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) + key.rawRepresentation
    return "-----BEGIN PUBLIC KEY-----\n\(der.base64EncodedString())\n-----END PUBLIC KEY-----\n"
}

private func recoveryCoordinatorFingerprint(_ key: Curve25519.Signing.PublicKey) -> String {
    let der = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) + key.rawRepresentation
    return "SHA256:" + Data(SHA256.hash(data: der)).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private func recoveryCoordinatorReceipt(
    _ transitionData: Data,
    fixture: RecoveryCoordinatorFixture,
    anchor: Curve25519.Signing.PrivateKey,
    index: Int = 1,
    receivedAt: String = "2030-01-01T00:00:02.000Z"
) throws -> Data {
    let transition = try NativeAuditKeyRecoveryTransition.decodeCanonical(
        transitionData,
        pinnedPolicy: fixture.policy,
        expectedInstallationID: "installation-001"
    )
    var object: [String: Any] = [
        "version": 2,
        "tenant": transition.tenant,
        "index": index,
        "transition_hash": transition.transitionHash,
        "received_at": receivedAt,
        "previous_receipt_hash": transition.previousTransitionReceiptHash,
        "event_index": transition.previousAnchorEventIndex + 1,
        "previous_event_hash": transition.previousAnchorEventHash,
        "last_checkpoint_index": transition.lastCheckpointIndex,
        "last_checkpoint_hash": transition.lastCheckpointHash,
        "last_checkpoint_receipt_hash": transition.lastCheckpointReceiptHash
    ]
    object["signature"] = try anchor.signature(for: NativeAuditLog.canonical(object)).base64EncodedString()
    object["anchor_key_fingerprint"] = recoveryCoordinatorFingerprint(anchor.publicKey)
    object["receipt_hash"] = NativeAuditLog.hash(try NativeAuditLog.canonical(object))
    return try NativeAuditLog.canonical(object)
}

private func recoveryCoordinatorEnvironment(
    fixture: RecoveryCoordinatorFixture,
    anchor: Curve25519.Signing.PrivateKey,
    root: URL? = nil
) throws -> (URL, NativeAuditKeyTransitionStore, NativeAuditKeyRecoveryPlanJournal) {
    let root = try root ?? recoveryCoordinatorRoot()
    let journalRoot = root.appendingPathComponent("journal")
    if !FileManager.default.fileExists(atPath: journalRoot.path) {
        try FileManager.default.createDirectory(at: journalRoot, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        guard chmod(journalRoot.path, 0o700) == 0 else { throw POSIXError(.EIO) }
    }
    let store = try NativeAuditKeyTransitionStore(
        path: root.appendingPathComponent("transitions.jsonl").path,
        tenant: "native-host",
        anchorPublicKeyPEM: recoveryCoordinatorPEM(anchor.publicKey),
        recoveryPolicyData: fixture.policy.canonicalData(),
        installationID: "installation-001"
    )
    let journal = try NativeAuditKeyRecoveryPlanJournal(
        rootPath: journalRoot.path,
        tenant: "native-host",
        pinnedPolicy: fixture.policy,
        installationID: "installation-001"
    )
    return (root, store, journal)
}

private func recoveryCoordinator(
    fixture: RecoveryCoordinatorFixture,
    store: NativeAuditKeyTransitionStore,
    journal: NativeAuditKeyRecoveryPlanJournal,
    transport: RecoveryCoordinatorTransport
) throws -> NativeAuditKeyRecoveryCoordinator {
    try NativeAuditKeyRecoveryCoordinator(
        tenant: "native-host",
        installationID: "installation-001",
        pinnedPolicy: fixture.policy,
        transitionStore: store,
        planJournal: journal,
        transport: transport,
        preparedRecordVerifier: fixture.lifecycleStore,
        lifecycleAncestryVerifier: fixture.lifecycleStore
    )
}

private func recoveryJournalRecord(_ root: URL, prefix: String) throws -> URL {
    let journal = root.appendingPathComponent("journal")
    let name = try #require(FileManager.default.contentsOfDirectory(atPath: journal.path).first { $0.hasPrefix(prefix) })
    return journal.appendingPathComponent(name)
}

private func rewriteRecoveryJournal(_ url: URL, mode: mode_t = 0o400, mutate: (inout Data) -> Void) throws {
    var data = try Data(contentsOf: url)
    mutate(&data)
    guard chmod(url.path, 0o600) == 0 else { throw POSIXError(.EIO) }
    let descriptor = open(url.path, O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw POSIXError(.EIO) }
    defer { close(descriptor) }
    try data.withUnsafeBytes { bytes in
        var offset = 0
        while offset < bytes.count {
            let amount = Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
            guard amount > 0 else { throw POSIXError(.EIO) }
            offset += amount
        }
    }
    guard fchmod(descriptor, mode) == 0, fsync(descriptor) == 0 else { throw POSIXError(.EIO) }
}

private func substitutedLifecycleRecord(
    _ data: Data,
    mutate: (inout [String: Any]) throws -> Void
) throws -> Data {
    var object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    object.removeValue(forKey: "record_hash")
    try mutate(&object)
    object["record_hash"] = NativeAuditLog.hash(try NativeAuditLog.canonical(object))
    return try NativeAuditLog.canonical(object)
}

private func recoveryLifecyclePreviousHead(_ data: Data) throws -> String {
    let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    return try #require(object["previous_record_hash"] as? String)
}

private func recoveryAuthorization(
    fixture: RecoveryCoordinatorFixture,
    lifecycleData: Data,
    operationID: String
) throws -> (NativeAuditKeyRecoveryAuthorization, [NativeAuditKeyRecoveryApproval], Data) {
    let lifecycle = try #require(JSONSerialization.jsonObject(with: lifecycleData) as? [String: Any])
    let lifecycleHead = try #require(lifecycle["record_hash"] as? String)
    let original = fixture.authorization
    let authorization = try NativeAuditKeyRecoveryAuthorization(
        tenant: original.tenant, installationID: original.installationID,
        operationID: operationID, recoveryRequestID: original.recoveryRequestID,
        policy: fixture.policy, fromGeneration: original.fromGeneration,
        oldPublicKeyX963: fixture.old.publicKeyX963,
        newPublicKeyX963: fixture.replacement.publicKeyX963,
        lifecycleHeadHash: lifecycleHead, createdAt: original.createdAt, expiresAt: original.expiresAt,
        previousTransitionHash: original.previousTransitionHash,
        previousTransitionReceiptHash: original.previousTransitionReceiptHash,
        lastCheckpointIndex: original.lastCheckpointIndex,
        lastCheckpointHash: original.lastCheckpointHash,
        lastCheckpointReceiptHash: original.lastCheckpointReceiptHash,
        previousAnchorEventIndex: original.previousAnchorEventIndex,
        previousAnchorEventHash: original.previousAnchorEventHash
    )
    let message = try authorization.canonicalData()
    let approvals = try fixture.authorities.map {
        try NativeAuditKeyRecoveryApproval(keyID: $0.0, signature: $0.1.signature(for: message))
    }
    return (authorization, approvals, try fixture.replacement.sign(message: message))
}

private func recoveryHighSSignature(_ signature: Data) throws -> Data {
    let low = try NativeP256CanonicalSignature.canonicalized(signature)
    let order: [UInt8] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
    ]
    let s = Array(low.suffix(32))
    var high = Array(repeating: UInt8(0), count: 32)
    var borrow = 0
    for index in stride(from: 31, through: 0, by: -1) {
        var value = Int(order[index]) - Int(s[index]) - borrow
        if value < 0 { value += 256; borrow = 1 } else { borrow = 0 }
        high[index] = UInt8(value)
    }
    return low.prefix(32) + Data(high)
}

@Test func auditKeyRecoveryCoordinatorPersistsBeforeNetworkAndAuthorizesOnlyAfterStoreFsync() throws {
    let fixture = try recoveryCoordinatorFixture()
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, store, journal) = try recoveryCoordinatorEnvironment(fixture: fixture, anchor: anchor)
    defer { try? FileManager.default.removeItem(at: root) }
    let transport = RecoveryCoordinatorTransport { data, _ in
        #expect(try journal.pending()?.plan.transitionData == data)
        #expect(try journal.status().pendingSubmissionIntent?.preparation.plan.transitionData == data)
        #expect(try store.status().count == 0)
        return try recoveryCoordinatorReceipt(data, fixture: fixture, anchor: anchor)
    }
    let coordinator = try recoveryCoordinator(fixture: fixture, store: store, journal: journal, transport: transport)
    let plan = try coordinator.prepare(
        authorization: fixture.authorization,
        approvals: fixture.approvals,
        replacementSignature: fixture.replacementSignature,
        retiringPublicKeyX963: fixture.old.publicKeyX963,
        lifecycleRecordData: fixture.lifecycleData,
        nowMilliseconds: 1_893_456_002_000
    )
    let result = try coordinator.authorizeActivation(plan: plan)
    #expect(result.transitionData == plan.transitionData)
    #expect(result.transitionStoreStatus.count == 1)
    #expect(!result.recoveredFromStore)
    #expect(try journal.pending() == nil)
}

@Test func auditKeyRecoveryCoordinatorRetriesByteExactPlanAfterLostResponseAndRestart() throws {
    let fixture = try recoveryCoordinatorFixture()
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, store, journal) = try recoveryCoordinatorEnvironment(fixture: fixture, anchor: anchor)
    defer { try? FileManager.default.removeItem(at: root) }
    let transport = RecoveryCoordinatorTransport { data, attempt in
        if attempt == 1 { throw RecoveryCoordinatorTransportError.lost }
        return try recoveryCoordinatorReceipt(data, fixture: fixture, anchor: anchor)
    }
    var coordinator: NativeAuditKeyRecoveryCoordinator? = try recoveryCoordinator(fixture: fixture, store: store, journal: journal, transport: transport)
    let plan = try fixture.plan(nowMilliseconds: 1_893_456_002_000)
    #expect(throws: RecoveryCoordinatorTransportError.self) { try coordinator!.authorizeActivation(plan: plan) }
    coordinator = nil
    let restarted = try recoveryCoordinator(fixture: fixture, store: store, journal: journal, transport: transport)
    let durable = try #require(try restarted.pendingPlan())
    let result = try restarted.authorizeActivation(plan: durable)
    #expect(transport.requests == [plan.transitionData, plan.transitionData])
    #expect(!result.recoveredFromStore)
}

@Test func auditKeyRecoveryCoordinatorReconcilesStoreAcceptedJournalIncompleteCrash() throws {
    let fixture = try recoveryCoordinatorFixture()
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, store, journal) = try recoveryCoordinatorEnvironment(fixture: fixture, anchor: anchor)
    defer { try? FileManager.default.removeItem(at: root) }
    let transport = RecoveryCoordinatorTransport { _, _ in throw RecoveryCoordinatorTransportError.shouldNotSend }
    let coordinator = try recoveryCoordinator(fixture: fixture, store: store, journal: journal, transport: transport)
    let plan = try fixture.plan()
    let prepared = try journal.prepare(plan, preparedAt: fixture.authorization.createdAt)
    _ = try journal.recordSubmissionIntent(prepared, intendedAt: fixture.authorization.createdAt)
    _ = try store.accept(
        transitionData: plan.transitionData,
        receiptData: recoveryCoordinatorReceipt(plan.transitionData, fixture: fixture, anchor: anchor),
        retiringPublicKeyX963: plan.retiringPublicKeyX963
    )
    let recovered = try coordinator.recoverAuthorizedLifecycleRecord(
        currentLifecycleHeadHash: try recoveryLifecyclePreviousHead(fixture.lifecycleData),
        currentAuditGeneration: 1
    )
    #expect(recovered == fixture.lifecycleData)
    #expect(try journal.pending() == nil)
    #expect(transport.requests.isEmpty)
}

@Test func auditKeyRecoveryCoordinatorReturnsNoLifecycleBytesAfterLocalActivation() throws {
    let fixture = try recoveryCoordinatorFixture()
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, store, journal) = try recoveryCoordinatorEnvironment(fixture: fixture, anchor: anchor)
    defer { try? FileManager.default.removeItem(at: root) }
    let transport = RecoveryCoordinatorTransport { data, _ in
        try recoveryCoordinatorReceipt(data, fixture: fixture, anchor: anchor)
    }
    let coordinator = try recoveryCoordinator(fixture: fixture, store: store, journal: journal, transport: transport)
    let plan = try fixture.plan()
    _ = try coordinator.authorizeActivation(plan: plan)
    #expect(try coordinator.recoverAuthorizedLifecycleRecord(
        currentLifecycleHeadHash: fixture.authorization.lifecycleHeadHash,
        currentAuditGeneration: 2
    ) == nil)
}

@Test func auditKeyRecoveryCoordinatorRejectsEqualOrHigherGenerationWithDivergentHead() throws {
    let fixture = try recoveryCoordinatorFixture()
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, store, journal) = try recoveryCoordinatorEnvironment(fixture: fixture, anchor: anchor)
    defer { try? FileManager.default.removeItem(at: root) }
    let transport = RecoveryCoordinatorTransport { data, _ in
        try recoveryCoordinatorReceipt(data, fixture: fixture, anchor: anchor)
    }
    let coordinator = try recoveryCoordinator(fixture: fixture, store: store, journal: journal, transport: transport)
    _ = try coordinator.authorizeActivation(plan: fixture.plan())
    let divergentHead = String(repeating: "8", count: 64)
    #expect(throws: AgentPassNativeError.self) {
        try coordinator.recoverAuthorizedLifecycleRecord(
            currentLifecycleHeadHash: divergentHead,
            currentAuditGeneration: fixture.authorization.toGeneration
        )
    }
    #expect(throws: AgentPassNativeError.self) {
        try coordinator.recoverAuthorizedLifecycleRecord(
            currentLifecycleHeadHash: divergentHead,
            currentAuditGeneration: fixture.authorization.toGeneration + 1
        )
    }
}

@Test func auditKeyRecoveryCoordinatorRejectsMalformedReceiptWithoutActivationAuthority() throws {
    let fixture = try recoveryCoordinatorFixture()
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, store, journal) = try recoveryCoordinatorEnvironment(fixture: fixture, anchor: anchor)
    defer { try? FileManager.default.removeItem(at: root) }
    let transport = RecoveryCoordinatorTransport { _, _ in Data("{}".utf8) }
    let coordinator = try recoveryCoordinator(fixture: fixture, store: store, journal: journal, transport: transport)
    let plan = try fixture.plan()
    #expect(throws: AgentPassNativeError.self) { try coordinator.authorizeActivation(plan: plan) }
    #expect(try store.status().count == 0)
    #expect(try journal.pending()?.plan == plan)
}

@Test func auditKeyRecoveryJournalAllowsOnePendingAndRejectsEquivocation() throws {
    let fixture = try recoveryCoordinatorFixture()
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, _, journal) = try recoveryCoordinatorEnvironment(fixture: fixture, anchor: anchor)
    defer { try? FileManager.default.removeItem(at: root) }
    let first = try fixture.plan()
    _ = try journal.prepare(first, preparedAt: fixture.authorization.createdAt)
    let competingFixture = try recoveryCoordinatorFixture(
        operationID: "recovery-operation-other",
        requestID: "recovery-request-other",
        replacement: try RecoveryCoordinatorSigner(3)
    )
    #expect(throws: AgentPassNativeError.self) {
        try journal.prepare(competingFixture.plan(), preparedAt: competingFixture.authorization.createdAt)
    }
    #expect(try journal.pending()?.plan.transitionData == first.transitionData)
}

@Test func auditKeyRecoveryJournalRejectsHistoricalOperationAndRequestReplay() throws {
    let firstFixture = try recoveryCoordinatorFixture()
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, _, journal) = try recoveryCoordinatorEnvironment(fixture: firstFixture, anchor: anchor)
    defer { try? FileManager.default.removeItem(at: root) }
    let first = try firstFixture.plan()
    let prepared = try journal.prepare(first, preparedAt: firstFixture.authorization.createdAt)
    _ = try journal.recordSubmissionIntent(prepared, intendedAt: firstFixture.authorization.createdAt)
    let receiptHash = String(repeating: "e", count: 64)
    _ = try journal.complete(prepared, transitionStoreReceiptHash: receiptHash, completedAt: "2030-01-01T00:00:02.000Z")

    let reusedOperation = try recoveryCoordinatorFixture(
        generation: 2,
        operationID: firstFixture.authorization.operationID,
        requestID: "recovery-request-2",
        previousTransitionHash: first.transition.transitionHash,
        previousReceiptHash: receiptHash,
        old: firstFixture.replacement,
        replacement: try RecoveryCoordinatorSigner(3),
        checkpointIndex: 8,
        eventIndex: 12,
        createdAt: "2030-01-01T00:00:03.000Z",
        expiresAt: "2030-01-01T00:15:03.000Z"
    )
    #expect(throws: AgentPassNativeError.self) {
        try journal.prepare(reusedOperation.plan(), preparedAt: reusedOperation.authorization.createdAt)
    }
    // Re-sign the same exact, fully validated recovery request/lifecycle binding
    // under a different operation ID. This remains a valid v3 transition, but
    // the durable journal must reject reuse of the historical request ID.
    let reusedRequestAuthorization = try NativeAuditKeyRecoveryAuthorization(
        tenant: firstFixture.authorization.tenant,
        installationID: firstFixture.authorization.installationID,
        operationID: "recovery-operation-2",
        recoveryRequestID: firstFixture.authorization.recoveryRequestID,
        policy: firstFixture.policy,
        fromGeneration: firstFixture.authorization.fromGeneration,
        oldPublicKeyX963: firstFixture.old.publicKeyX963,
        newPublicKeyX963: firstFixture.replacement.publicKeyX963,
        lifecycleHeadHash: firstFixture.authorization.lifecycleHeadHash,
        createdAt: firstFixture.authorization.createdAt,
        expiresAt: firstFixture.authorization.expiresAt,
        previousTransitionHash: firstFixture.authorization.previousTransitionHash,
        previousTransitionReceiptHash: firstFixture.authorization.previousTransitionReceiptHash,
        lastCheckpointIndex: firstFixture.authorization.lastCheckpointIndex,
        lastCheckpointHash: firstFixture.authorization.lastCheckpointHash,
        lastCheckpointReceiptHash: firstFixture.authorization.lastCheckpointReceiptHash,
        previousAnchorEventIndex: firstFixture.authorization.previousAnchorEventIndex,
        previousAnchorEventHash: firstFixture.authorization.previousAnchorEventHash
    )
    let reusedRequestMessage = try reusedRequestAuthorization.canonicalData()
    let reusedRequestApprovals = try firstFixture.authorities.map {
        try NativeAuditKeyRecoveryApproval(keyID: $0.0, signature: $0.1.signature(for: reusedRequestMessage))
    }
    let reusedRequest = try NativeAuditKeyRecoveryPlan(
        pinnedPolicy: firstFixture.policy,
        installationID: firstFixture.authorization.installationID,
        authorization: reusedRequestAuthorization,
        approvals: reusedRequestApprovals,
        replacementSignature: firstFixture.replacement.sign(message: reusedRequestMessage),
        retiringPublicKeyX963: firstFixture.old.publicKeyX963,
        lifecycleRecordData: firstFixture.lifecycleData
    )
    #expect(throws: AgentPassNativeError.self) {
        try journal.prepare(reusedRequest, preparedAt: reusedRequestAuthorization.createdAt)
    }
}

@Test func auditKeyRecoveryJournalRecoversExactlyOneFsyncedRecordAheadOfTip() throws {
    let fixture = try recoveryCoordinatorFixture()
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, _, journal) = try recoveryCoordinatorEnvironment(fixture: fixture, anchor: anchor)
    let tip = root.appendingPathComponent("journal/tip.json")
    let originalTip = try Data(contentsOf: tip)
    _ = try journal.prepare(fixture.plan(), preparedAt: fixture.authorization.createdAt)
    try rewriteRecoveryJournal(tip, mode: 0o600) { $0 = originalTip }
    let restarted = try NativeAuditKeyRecoveryPlanJournal(
        rootPath: root.appendingPathComponent("journal").path,
        tenant: "native-host",
        pinnedPolicy: fixture.policy,
        installationID: "installation-001"
    )
    #expect(try restarted.pending()?.plan.transitionData == fixture.plan().transitionData)
    try? FileManager.default.removeItem(at: root)
}

@Test func auditKeyRecoveryJournalDetectsRecordTamperingAndTailTruncation() throws {
    let fixture = try recoveryCoordinatorFixture()
    let anchor = Curve25519.Signing.PrivateKey()
    let (tamperRoot, _, tamperJournal) = try recoveryCoordinatorEnvironment(fixture: fixture, anchor: anchor)
    _ = try tamperJournal.prepare(fixture.plan(), preparedAt: fixture.authorization.createdAt)
    let record = try recoveryJournalRecord(tamperRoot, prefix: "prepare-")
    try rewriteRecoveryJournal(record) { $0[$0.count / 2] ^= 1 }
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRecoveryPlanJournal(
            rootPath: tamperRoot.appendingPathComponent("journal").path,
            tenant: "native-host",
            pinnedPolicy: fixture.policy,
            installationID: "installation-001"
        )
    }
    try? FileManager.default.removeItem(at: tamperRoot)

    let (truncateRoot, _, truncateJournal) = try recoveryCoordinatorEnvironment(fixture: fixture, anchor: anchor)
    let prepared = try truncateJournal.prepare(fixture.plan(), preparedAt: fixture.authorization.createdAt)
    _ = try truncateJournal.recordSubmissionIntent(prepared, intendedAt: fixture.authorization.createdAt)
    _ = try truncateJournal.complete(prepared, transitionStoreReceiptHash: String(repeating: "e", count: 64), completedAt: "2030-01-01T00:00:02.000Z")
    try FileManager.default.removeItem(at: recoveryJournalRecord(truncateRoot, prefix: "completed-"))
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRecoveryPlanJournal(
            rootPath: truncateRoot.appendingPathComponent("journal").path,
            tenant: "native-host",
            pinnedPolicy: fixture.policy,
            installationID: "installation-001"
        )
    }
    try? FileManager.default.removeItem(at: truncateRoot)
}

@Test func auditKeyRecoveryJournalRejectsSymlinkHardlinkAndPermissiveDirectory() throws {
    let fixture = try recoveryCoordinatorFixture()
    let parent = try recoveryCoordinatorRoot("agentpass-recovery-links")
    defer { try? FileManager.default.removeItem(at: parent) }
    let actual = parent.appendingPathComponent("actual")
    try FileManager.default.createDirectory(at: actual, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    let linked = parent.appendingPathComponent("linked")
    try FileManager.default.createSymbolicLink(atPath: linked.path, withDestinationPath: actual.path)
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRecoveryPlanJournal(rootPath: linked.path, tenant: "native-host", pinnedPolicy: fixture.policy, installationID: "installation-001")
    }
    let permissive = parent.appendingPathComponent("permissive")
    try FileManager.default.createDirectory(at: permissive, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o755])
    guard chmod(permissive.path, 0o755) == 0 else { throw POSIXError(.EIO) }
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRecoveryPlanJournal(rootPath: permissive.path, tenant: "native-host", pinnedPolicy: fixture.policy, installationID: "installation-001")
    }
    let secure = parent.appendingPathComponent("secure")
    try FileManager.default.createDirectory(at: secure, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    var journal: NativeAuditKeyRecoveryPlanJournal? = try NativeAuditKeyRecoveryPlanJournal(rootPath: secure.path, tenant: "native-host", pinnedPolicy: fixture.policy, installationID: "installation-001")
    _ = try journal!.prepare(fixture.plan(), preparedAt: fixture.authorization.createdAt)
    journal = nil
    let recordName = try #require(FileManager.default.contentsOfDirectory(atPath: secure.path).first { $0.hasPrefix("prepare-") })
    let record = secure.appendingPathComponent(recordName)
    let alias = parent.appendingPathComponent("hardlink")
    guard linkat(AT_FDCWD, record.path, AT_FDCWD, alias.path, 0) == 0 else { throw POSIXError(.EIO) }
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRecoveryPlanJournal(rootPath: secure.path, tenant: "native-host", pinnedPolicy: fixture.policy, installationID: "installation-001")
    }
}

@Test func auditKeyRecoveryJournalDetectsDirectoryPathSwap() throws {
    let fixture = try recoveryCoordinatorFixture()
    let root = try recoveryCoordinatorRoot("agentpass-recovery-swap")
    let moved = root.deletingLastPathComponent().appendingPathComponent("\(root.lastPathComponent)-moved")
    defer {
        try? FileManager.default.removeItem(at: root)
        try? FileManager.default.removeItem(at: moved)
    }
    let journal = try NativeAuditKeyRecoveryPlanJournal(rootPath: root.path, tenant: "native-host", pinnedPolicy: fixture.policy, installationID: "installation-001")
    try FileManager.default.moveItem(at: root, to: moved)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    guard chmod(root.path, 0o700) == 0 else { throw POSIXError(.EIO) }
    #expect(throws: AgentPassNativeError.self) {
        try journal.prepare(fixture.plan(), preparedAt: fixture.authorization.createdAt)
    }
}

@Test func auditKeyRecoveryPlanRejectsPinnedTrustRetiringKeyAndLifecycleSubstitution() throws {
    let fixture = try recoveryCoordinatorFixture()
    let plan = try fixture.plan()
    let foreignAuthority = Curve25519.Signing.PrivateKey()
    let foreignPolicy = try NativeAuditKeyRecoveryPolicy(
        policyID: "offline-main",
        threshold: 1,
        keys: [try NativeAuditKeyRecoveryPolicyKey(id: "alpha", publicKey: foreignAuthority.publicKey)]
    )
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRecoveryPlan(
            transitionData: plan.transitionData,
            retiringPublicKeyX963: plan.retiringPublicKeyX963,
            lifecycleRecordData: plan.lifecycleRecordData,
            pinnedPolicy: foreignPolicy,
            installationID: "installation-001"
        )
    }
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRecoveryPlan(
            transitionData: plan.transitionData,
            retiringPublicKeyX963: try RecoveryCoordinatorSigner(9).publicKeyX963,
            lifecycleRecordData: plan.lifecycleRecordData,
            pinnedPolicy: fixture.policy,
            installationID: "installation-001"
        )
    }
    var lifecycle = plan.lifecycleRecordData
    lifecycle[lifecycle.count - 2] ^= 1
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRecoveryPlan(
            transitionData: plan.transitionData,
            retiringPublicKeyX963: plan.retiringPublicKeyX963,
            lifecycleRecordData: lifecycle,
            pinnedPolicy: fixture.policy,
            installationID: "installation-001"
        )
    }
}

@Test func auditKeyRecoveryPlanRejectsLifecycleGenerationKeyFingerprintContinuityAndOldGenerationSubstitution() throws {
    let fixture = try recoveryCoordinatorFixture()
    let plan = try fixture.plan()
    func expectRejected(_ data: Data) {
        #expect(throws: AgentPassNativeError.self) {
            try NativeAuditKeyRecoveryPlan(
                transitionData: plan.transitionData,
                retiringPublicKeyX963: plan.retiringPublicKeyX963,
                lifecycleRecordData: data,
                pinnedPolicy: fixture.policy,
                installationID: "installation-001"
            )
        }
    }

    expectRejected(try substitutedLifecycleRecord(plan.lifecycleRecordData) {
        $0["generation"] = fixture.authorization.toGeneration + 1
    })
    let foreign = try RecoveryCoordinatorSigner(9)
    expectRejected(try substitutedLifecycleRecord(plan.lifecycleRecordData) {
        $0["public_key"] = foreign.publicKeyX963.base64EncodedString()
    })
    expectRejected(try substitutedLifecycleRecord(plan.lifecycleRecordData) {
        $0["fingerprint"] = NativeAuditCheckpoints.fingerprint(foreign.publicKeyX963)
    })
    expectRejected(try substitutedLifecycleRecord(plan.lifecycleRecordData) {
        $0["continuity"] = NativeKeyContinuity.clean.rawValue
    })
    expectRejected(try substitutedLifecycleRecord(plan.lifecycleRecordData) {
        $0["old_generation"] = fixture.authorization.fromGeneration + 1
    })
    expectRejected(try substitutedLifecycleRecord(plan.lifecycleRecordData) {
        $0["old_fingerprint"] = NativeAuditCheckpoints.fingerprint(foreign.publicKeyX963)
    })
}

@Test func auditKeyRecoveryCoordinatorRejectsCryptographicLifecycleSubstitutionBeforeTransport() throws {
    let fixture = try recoveryCoordinatorFixture()
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, store, journal) = try recoveryCoordinatorEnvironment(fixture: fixture, anchor: anchor)
    defer { try? FileManager.default.removeItem(at: root) }
    let transport = RecoveryCoordinatorTransport { _, _ in throw RecoveryCoordinatorTransportError.shouldNotSend }
    let coordinator = try recoveryCoordinator(fixture: fixture, store: store, journal: journal, transport: transport)
    let mutations: [(String, (inout [String: Any]) throws -> Void)] = [
        ("new-signature", { object in
            let encoded = try #require(object["new_signature"] as? String)
            var signature = try #require(Data(base64Encoded: encoded))
            signature[0] ^= 1
            object["new_signature"] = signature.base64EncodedString()
        }),
        ("threshold-evidence", { object in
            let encoded = try #require(object["approval_signature"] as? String)
            var evidence = try #require(Data(base64Encoded: encoded))
            evidence[evidence.count / 2] ^= 1
            object["approval_signature"] = evidence.base64EncodedString()
        }),
        ("reason", { $0["reason"] = "offline-threshold-recovery:substituted" }),
        ("challenge", { $0["challenge_id"] = "substituted-challenge" })
    ]
    for (name, mutation) in mutations {
        let lifecycle = try substitutedLifecycleRecord(fixture.lifecycleData, mutate: mutation)
        let inputs = try recoveryAuthorization(
            fixture: fixture, lifecycleData: lifecycle, operationID: "tampered-\(name)"
        )
        #expect(throws: AgentPassNativeError.self) {
            try coordinator.prepare(
                authorization: inputs.0, approvals: inputs.1,
                replacementSignature: inputs.2,
                retiringPublicKeyX963: fixture.old.publicKeyX963,
                lifecycleRecordData: lifecycle,
                nowMilliseconds: 1_893_456_002_000
            )
        }
    }
    #expect(transport.requests.isEmpty)
    #expect(try journal.pending() == nil)
}

@Test func auditKeyRecoveryNormalizesProductionP256ProofAndRejectsHighSMalleation() throws {
    let fixture = try recoveryCoordinatorFixture()
    let low = try NativeP256CanonicalSignature.canonicalized(fixture.replacementSignature)
    let high = try recoveryHighSSignature(low)
    #expect(NativeP256CanonicalSignature.isCanonicalLowS(low))
    #expect(!NativeP256CanonicalSignature.isCanonicalLowS(high))
    #expect(try NativeP256CanonicalSignature.canonicalized(high) == low)

    let normalized = try NativeAuditKeyRecoveryTransition(
        authorization: fixture.authorization, policy: fixture.policy,
        approvals: fixture.approvals, replacementSignature: high
    )
    let canonical = try NativeAuditKeyRecoveryTransition(
        authorization: fixture.authorization, policy: fixture.policy,
        approvals: fixture.approvals, replacementSignature: low
    )
    #expect(try normalized.canonicalData() == canonical.canonicalData())

    var object = try #require(JSONSerialization.jsonObject(with: canonical.canonicalData()) as? [String: Any])
    object["new_signature"] = high.base64EncodedString()
    object.removeValue(forKey: "transition_hash")
    object["transition_hash"] = NativeAuditLog.hash(try NativeAuditLog.canonical(object))
    let malleated = try NativeAuditLog.canonical(object)
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRecoveryTransition.decodeCanonical(
            malleated, pinnedPolicy: fixture.policy, expectedInstallationID: "installation-001"
        )
    }
}

@Test func auditKeyRecoveryCoordinatorAcceptsOnlyStoreProvenLifecycleDescendant() throws {
    let fixture = try recoveryCoordinatorFixture()
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, store, journal) = try recoveryCoordinatorEnvironment(fixture: fixture, anchor: anchor)
    defer { try? FileManager.default.removeItem(at: root) }
    let transport = RecoveryCoordinatorTransport { data, _ in
        try recoveryCoordinatorReceipt(data, fixture: fixture, anchor: anchor)
    }
    let coordinator = try recoveryCoordinator(fixture: fixture, store: store, journal: journal, transport: transport)
    _ = try coordinator.authorizeActivation(plan: fixture.plan())
    _ = try fixture.lifecycleStore.appendPreparedRecordData(fixture.lifecycleData)
    let git = try RecoveryCoordinatorSigner(0x71)
    let descendant = try fixture.lifecycleStore.stage(
        role: .gitSigning, generation: 1, applicationTag: "git.descendant.g1",
        publicKeyX963: git.publicKeyX963, createdAt: "2030-01-01T00:00:03.000Z"
    )
    #expect(try coordinator.recoverAuthorizedLifecycleRecord(
        currentLifecycleHeadHash: descendant.headHash,
        currentAuditGeneration: fixture.authorization.toGeneration
    ) == nil)
}

@Test func auditKeyRecoveryCoordinatorRejectsAcceptedStoreWithEmptyOrRolledBackJournal() throws {
    let fixture = try recoveryCoordinatorFixture()
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, store, journal) = try recoveryCoordinatorEnvironment(fixture: fixture, anchor: anchor)
    defer { try? FileManager.default.removeItem(at: root) }
    let receipt = try recoveryCoordinatorReceipt(fixture.plan().transitionData, fixture: fixture, anchor: anchor)
    _ = try store.accept(
        transitionData: fixture.plan().transitionData, receiptData: receipt,
        retiringPublicKeyX963: fixture.old.publicKeyX963
    )
    let transport = RecoveryCoordinatorTransport { _, _ in throw RecoveryCoordinatorTransportError.shouldNotSend }
    #expect(throws: AgentPassNativeError.self) {
        try recoveryCoordinator(fixture: fixture, store: store, journal: journal, transport: transport)
    }

    let journalRoot = root.appendingPathComponent("journal")
    try FileManager.default.removeItem(at: journalRoot)
    try FileManager.default.createDirectory(
        at: journalRoot, withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    guard chmod(journalRoot.path, 0o700) == 0 else { throw POSIXError(.EIO) }
    let rolledBack = try NativeAuditKeyRecoveryPlanJournal(
        rootPath: journalRoot.path, tenant: "native-host",
        pinnedPolicy: fixture.policy, installationID: "installation-001"
    )
    #expect(throws: AgentPassNativeError.self) {
        try recoveryCoordinator(fixture: fixture, store: store, journal: rolledBack, transport: transport)
    }
    #expect(transport.requests.isEmpty)
}

@Test func auditKeyRecoveryCoordinatorRejectsStaleForkBeforeNetwork() throws {
    let fixture = try recoveryCoordinatorFixture(
        previousTransitionHash: String(repeating: "f", count: 64),
        previousReceiptHash: String(repeating: "e", count: 64)
    )
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, store, journal) = try recoveryCoordinatorEnvironment(fixture: fixture, anchor: anchor)
    defer { try? FileManager.default.removeItem(at: root) }
    let transport = RecoveryCoordinatorTransport { _, _ in throw RecoveryCoordinatorTransportError.shouldNotSend }
    let coordinator = try recoveryCoordinator(fixture: fixture, store: store, journal: journal, transport: transport)
    #expect(throws: AgentPassNativeError.self) {
        try coordinator.prepare(
            authorization: fixture.authorization,
            approvals: fixture.approvals,
            replacementSignature: fixture.replacementSignature,
            retiringPublicKeyX963: fixture.old.publicKeyX963,
            lifecycleRecordData: fixture.lifecycleData,
            nowMilliseconds: 1_893_456_002_000
        )
    }
    #expect(transport.requests.isEmpty)
    #expect(try journal.pending() == nil)
}

@Test func auditKeyRecoveryCoordinatorRejectsStoreAcceptedJournalEquivocationOnRestart() throws {
    let acceptedFixture = try recoveryCoordinatorFixture()
    let competingFixture = try recoveryCoordinatorFixture(
        operationID: "recovery-operation-competing",
        requestID: "recovery-request-competing",
        replacement: try RecoveryCoordinatorSigner(3)
    )
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, store, journal) = try recoveryCoordinatorEnvironment(fixture: acceptedFixture, anchor: anchor)
    defer { try? FileManager.default.removeItem(at: root) }
    _ = try journal.prepare(competingFixture.plan(), preparedAt: competingFixture.authorization.createdAt)
    let accepted = try acceptedFixture.plan()
    _ = try store.accept(
        transitionData: accepted.transitionData,
        receiptData: recoveryCoordinatorReceipt(accepted.transitionData, fixture: acceptedFixture, anchor: anchor),
        retiringPublicKeyX963: accepted.retiringPublicKeyX963
    )
    let transport = RecoveryCoordinatorTransport { _, _ in throw RecoveryCoordinatorTransportError.shouldNotSend }
    #expect(throws: AgentPassNativeError.self) {
        try recoveryCoordinator(fixture: acceptedFixture, store: store, journal: journal, transport: transport)
    }
    #expect(transport.requests.isEmpty)
}

@Test func auditKeyRecoveryJournalRejectsRecordModeDowngrade() throws {
    let fixture = try recoveryCoordinatorFixture()
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, _, journal) = try recoveryCoordinatorEnvironment(fixture: fixture, anchor: anchor)
    _ = try journal.prepare(fixture.plan(), preparedAt: fixture.authorization.createdAt)
    let record = try recoveryJournalRecord(root, prefix: "prepare-")
    guard chmod(record.path, 0o600) == 0 else { throw POSIXError(.EIO) }
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRecoveryPlanJournal(
            rootPath: root.appendingPathComponent("journal").path,
            tenant: "native-host",
            pinnedPolicy: fixture.policy,
            installationID: "installation-001"
        )
    }
    try? FileManager.default.removeItem(at: root)
}

@Test func auditKeyRecoveryJournalRecoversPreRenameTemporaryCrashRemnants() throws {
    let fixture = try recoveryCoordinatorFixture()
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, _, journal) = try recoveryCoordinatorEnvironment(fixture: fixture, anchor: anchor)
    _ = try journal.prepare(fixture.plan(), preparedAt: fixture.authorization.createdAt)
    let journalRoot = root.appendingPathComponent("journal")
    let recordTemporary = journalRoot.appendingPathComponent(".record-\(UUID().uuidString).tmp")
    let tipTemporary = journalRoot.appendingPathComponent(".tip-\(UUID().uuidString).tmp")
    try Data("partial-record".utf8).write(to: recordTemporary, options: .withoutOverwriting)
    try Data("partial-tip".utf8).write(to: tipTemporary, options: .withoutOverwriting)
    guard chmod(recordTemporary.path, 0o400) == 0,
          chmod(tipTemporary.path, 0o600) == 0 else { throw POSIXError(.EIO) }
    let restarted = try NativeAuditKeyRecoveryPlanJournal(
        rootPath: journalRoot.path,
        tenant: "native-host",
        pinnedPolicy: fixture.policy,
        installationID: "installation-001"
    )
    #expect(try restarted.pending()?.plan.transitionData == fixture.plan().transitionData)
    #expect(!FileManager.default.fileExists(atPath: recordTemporary.path))
    #expect(!FileManager.default.fileExists(atPath: tipTemporary.path))
    try? FileManager.default.removeItem(at: root)
}

@Test func auditKeyRecoveryJournalRefusesUnsafeTemporaryCrashRemnant() throws {
    let fixture = try recoveryCoordinatorFixture()
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, _, _) = try recoveryCoordinatorEnvironment(fixture: fixture, anchor: anchor)
    defer { try? FileManager.default.removeItem(at: root) }
    let journalRoot = root.appendingPathComponent("journal")
    let temporary = journalRoot.appendingPathComponent(".record-\(UUID().uuidString).tmp")
    try Data("uncommitted".utf8).write(to: temporary, options: .withoutOverwriting)
    guard chmod(temporary.path, 0o600) == 0 else { throw POSIXError(.EIO) }
    let alias = root.appendingPathComponent("temporary-hardlink")
    guard linkat(AT_FDCWD, temporary.path, AT_FDCWD, alias.path, 0) == 0 else { throw POSIXError(.EIO) }
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRecoveryPlanJournal(
            rootPath: journalRoot.path,
            tenant: "native-host",
            pinnedPolicy: fixture.policy,
            installationID: "installation-001"
        )
    }
    #expect(FileManager.default.fileExists(atPath: temporary.path))
}

@Test func auditKeyRecoveryAbortAcceptsExactExpiryBoundaryAndPersistsAuditResult() throws {
    let fixture = try recoveryCoordinatorFixture()
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, store, journal) = try recoveryCoordinatorEnvironment(fixture: fixture, anchor: anchor)
    defer { try? FileManager.default.removeItem(at: root) }
    let transport = RecoveryCoordinatorTransport { _, _ in throw RecoveryCoordinatorTransportError.shouldNotSend }
    let coordinator = try recoveryCoordinator(fixture: fixture, store: store, journal: journal, transport: transport)
    _ = try coordinator.prepare(
        authorization: fixture.authorization, approvals: fixture.approvals,
        replacementSignature: fixture.replacementSignature,
        retiringPublicKeyX963: fixture.old.publicKeyX963,
        lifecycleRecordData: fixture.lifecycleData,
        nowMilliseconds: 1_893_456_002_000
    )
    let result = try coordinator.abortExpiredUnsubmittedPending(nowMilliseconds: 1_893_456_901_000)
    #expect(result.authorizationExpiresAt == fixture.authorization.expiresAt)
    #expect(result.abortedAt == fixture.authorization.expiresAt)
    #expect(result.abortRecordHash.wholeMatch(of: /^[0-9a-f]{64}$/) != nil)
    let status = try journal.status()
    #expect(status.pending == nil)
    #expect(status.pendingSubmissionIntent == nil)
    #expect(status.aborted == [result])
    #expect(transport.requests.isEmpty)
}

@Test func auditKeyRecoveryAbortRejectsBeforeExpiryAndAfterSubmissionIntent() throws {
    let fixture = try recoveryCoordinatorFixture()
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, store, journal) = try recoveryCoordinatorEnvironment(fixture: fixture, anchor: anchor)
    defer { try? FileManager.default.removeItem(at: root) }
    let transport = RecoveryCoordinatorTransport { _, _ in throw RecoveryCoordinatorTransportError.lost }
    let coordinator = try recoveryCoordinator(fixture: fixture, store: store, journal: journal, transport: transport)
    let plan = try coordinator.prepare(
        authorization: fixture.authorization, approvals: fixture.approvals,
        replacementSignature: fixture.replacementSignature,
        retiringPublicKeyX963: fixture.old.publicKeyX963,
        lifecycleRecordData: fixture.lifecycleData,
        nowMilliseconds: 1_893_456_002_000
    )
    #expect(throws: AgentPassNativeError.self) {
        try coordinator.abortExpiredUnsubmittedPending(nowMilliseconds: 1_893_456_900_999)
    }
    #expect(throws: RecoveryCoordinatorTransportError.self) {
        try coordinator.authorizeActivation(plan: plan)
    }
    #expect(try journal.status().pendingSubmissionIntent?.preparation.plan == plan)
    #expect(throws: AgentPassNativeError.self) {
        try coordinator.abortExpiredUnsubmittedPending(nowMilliseconds: 1_893_456_901_000)
    }
}

@Test func auditKeyRecoveryAbortRepairsTipCrashAndSurvivesRestart() throws {
    let fixture = try recoveryCoordinatorFixture()
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, _, journal) = try recoveryCoordinatorEnvironment(fixture: fixture, anchor: anchor)
    let preparation = try journal.prepare(fixture.plan(), preparedAt: fixture.authorization.createdAt)
    let tip = root.appendingPathComponent("journal/tip.json")
    let preAbortTip = try Data(contentsOf: tip)
    let expected = try journal.abortExpiredUnsubmitted(preparation, abortedAt: fixture.authorization.expiresAt)
    try rewriteRecoveryJournal(tip, mode: 0o600) { $0 = preAbortTip }
    let restarted = try NativeAuditKeyRecoveryPlanJournal(
        rootPath: root.appendingPathComponent("journal").path,
        tenant: "native-host", pinnedPolicy: fixture.policy, installationID: "installation-001"
    )
    #expect(try restarted.status().aborted == [expected])
    #expect(try restarted.pending() == nil)
    try? FileManager.default.removeItem(at: root)
}

@Test func auditKeyRecoveryAbortDetectsTamperAndRollback() throws {
    let fixture = try recoveryCoordinatorFixture()
    let anchor = Curve25519.Signing.PrivateKey()
    let (tamperRoot, _, tamperJournal) = try recoveryCoordinatorEnvironment(fixture: fixture, anchor: anchor)
    let tamperPreparation = try tamperJournal.prepare(fixture.plan(), preparedAt: fixture.authorization.createdAt)
    _ = try tamperJournal.abortExpiredUnsubmitted(tamperPreparation, abortedAt: fixture.authorization.expiresAt)
    let abortRecord = try recoveryJournalRecord(tamperRoot, prefix: "aborted-")
    try rewriteRecoveryJournal(abortRecord) { $0[$0.count / 2] ^= 1 }
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRecoveryPlanJournal(
            rootPath: tamperRoot.appendingPathComponent("journal").path,
            tenant: "native-host", pinnedPolicy: fixture.policy, installationID: "installation-001"
        )
    }
    try? FileManager.default.removeItem(at: tamperRoot)

    let (rollbackRoot, _, rollbackJournal) = try recoveryCoordinatorEnvironment(fixture: fixture, anchor: anchor)
    let rollbackPreparation = try rollbackJournal.prepare(fixture.plan(), preparedAt: fixture.authorization.createdAt)
    _ = try rollbackJournal.abortExpiredUnsubmitted(rollbackPreparation, abortedAt: fixture.authorization.expiresAt)
    try FileManager.default.removeItem(at: recoveryJournalRecord(rollbackRoot, prefix: "aborted-"))
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRecoveryPlanJournal(
            rootPath: rollbackRoot.appendingPathComponent("journal").path,
            tenant: "native-host", pinnedPolicy: fixture.policy, installationID: "installation-001"
        )
    }
    try? FileManager.default.removeItem(at: rollbackRoot)
}

@Test func auditKeyRecoveryCleanAbortAllowsNewPlanAtSameGenerationWithoutReplay() throws {
    let first = try recoveryCoordinatorFixture()
    let second = try recoveryCoordinatorFixture(
        operationID: "recovery-operation-2",
        requestID: "recovery-request-2",
        replacement: try RecoveryCoordinatorSigner(3),
        createdAt: "2030-01-01T00:16:00.000Z",
        expiresAt: "2030-01-01T00:31:00.000Z"
    )
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, _, journal) = try recoveryCoordinatorEnvironment(fixture: first, anchor: anchor)
    defer { try? FileManager.default.removeItem(at: root) }
    let firstPreparation = try journal.prepare(first.plan(), preparedAt: first.authorization.createdAt)
    _ = try journal.abortExpiredUnsubmitted(firstPreparation, abortedAt: first.authorization.expiresAt)
    let secondPreparation = try journal.prepare(second.plan(), preparedAt: second.authorization.createdAt)
    #expect(secondPreparation.fromGeneration == firstPreparation.fromGeneration)
    #expect(try journal.pending() == secondPreparation)
    #expect(throws: AgentPassNativeError.self) {
        try journal.prepare(first.plan(), preparedAt: first.authorization.createdAt)
    }
}
