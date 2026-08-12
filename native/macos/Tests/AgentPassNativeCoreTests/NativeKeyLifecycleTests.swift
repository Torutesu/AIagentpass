import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore

private struct LifecycleSoftwareSigner: NativeLifecycleKeyHandle {
    let privateKey: P256.Signing.PrivateKey
    init() { privateKey = P256.Signing.PrivateKey() }
    var publicKeyX963: Data { privateKey.publicKey.x963Representation }
    func sign(message: Data) throws -> Data { try privateKey.signature(for: message).rawRepresentation }
}

private struct LifecycleRecoverySigner {
    let privateKey = Curve25519.Signing.PrivateKey()
    var publicKey: Data { privateKey.publicKey.rawRepresentation }
    func sign(message: Data) throws -> Data { try privateKey.signature(for: message) }
}

private final class LifecycleRecoveryPreparationProvider: NativeLifecycleKeyProvider, @unchecked Sendable {
    private let keys: [String: LifecycleSoftwareSigner]
    init(keys: [String: LifecycleSoftwareSigner]) { self.keys = keys }
    func create(applicationTag: String, requiresUserPresence: Bool) throws -> any NativeLifecycleKeyHandle {
        throw AgentPassNativeError.invalidConfiguration("Unexpected recovery preparation key creation")
    }
    func load(applicationTag: String) throws -> any NativeLifecycleKeyHandle {
        guard let key = keys[applicationTag] else { throw AgentPassNativeError.invalidKey("Missing test lifecycle key") }
        return key
    }
    func exists(applicationTag: String) throws -> Bool { keys[applicationTag] != nil }
    func delete(applicationTag: String) throws { throw AgentPassNativeError.invalidConfiguration("Unexpected recovery preparation deletion") }
}

private let lifecycleTime = "2027-02-03T04:05:06.000Z"
private let lifecycleDeletionTime = "2027-03-10T04:05:06.000Z"

private func lifecycleDirectory() throws -> URL {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    return root
}

private func bootstrapApproval(_ store: NativeKeyLifecycleStore, signer: LifecycleSoftwareSigner) throws {
    try store.stage(role: .sessionApproval, generation: 1, applicationTag: "approval.g1", publicKeyX963: signer.publicKeyX963, createdAt: lifecycleTime)
    let statement = try store.transitionStatement(role: .sessionApproval, generation: 1, reason: "initial enrollment", challengeID: "challenge-approval-1", createdAt: lifecycleTime, continuity: .bootstrap)
    let message = try statement.canonicalData()
    _ = try store.activate(statement: statement, oldSignature: nil, newSignature: signer.sign(message: message), approvalSignature: signer.sign(message: message), approvalPublicKeyX963: signer.publicKeyX963)
}

private func bootstrapRole(_ role: NativeKeyRole, store: NativeKeyLifecycleStore, signer: LifecycleSoftwareSigner, approval: LifecycleSoftwareSigner) throws {
    try store.stage(role: role, generation: 1, applicationTag: "\(role.rawValue).g1", publicKeyX963: signer.publicKeyX963, createdAt: lifecycleTime)
    let statement = try store.transitionStatement(role: role, generation: 1, reason: "initial enrollment", challengeID: "challenge-\(role.rawValue)-1", createdAt: lifecycleTime, continuity: .bootstrap)
    let message = try statement.canonicalData()
    _ = try store.activate(statement: statement, oldSignature: nil, newSignature: signer.sign(message: message), approvalSignature: approval.sign(message: message), approvalPublicKeyX963: approval.publicKeyX963)
}

private func rotateRole(_ role: NativeKeyRole, store: NativeKeyLifecycleStore, old: LifecycleSoftwareSigner, new: LifecycleSoftwareSigner, approval: LifecycleSoftwareSigner, generation: Int = 2) throws {
    try store.stage(role: role, generation: generation, applicationTag: "\(role.rawValue).g\(generation)", publicKeyX963: new.publicKeyX963, createdAt: lifecycleTime)
    let statement = try store.transitionStatement(role: role, generation: generation, reason: "scheduled rotation", challengeID: "challenge-\(role.rawValue)-\(generation)", createdAt: lifecycleTime)
    let message = try statement.canonicalData()
    _ = try store.activate(statement: statement, oldSignature: old.sign(message: message), newSignature: new.sign(message: message), approvalSignature: approval.sign(message: message), approvalPublicKeyX963: approval.publicKeyX963)
}

private func recordFiles(_ directory: URL) throws -> [URL] {
    try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil).sorted { $0.lastPathComponent < $1.lastPathComponent }
}

private final class LifecycleConcurrentResults: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [Bool] = []

    func append(_ value: Bool) {
        lock.lock()
        values.append(value)
        lock.unlock()
    }

    func snapshot() -> [Bool] {
        lock.lock()
        defer { lock.unlock() }
        return values
    }
}

@Test func lifecyclePreviewHeadsExactlyMatchSubsequentImmutableRecords() throws {
    let directory = try lifecycleDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try NativeKeyLifecycleStore(directory: directory.path)
    let approval = LifecycleSoftwareSigner()

    let stagedApprovalHead = try store.previewStageHead(role: .sessionApproval, generation: 1, applicationTag: "approval.g1", publicKeyX963: approval.publicKeyX963, createdAt: lifecycleTime)
    let staged = try store.stage(role: .sessionApproval, generation: 1, applicationTag: "approval.g1", publicKeyX963: approval.publicKeyX963, createdAt: lifecycleTime)
    #expect(staged.headHash == stagedApprovalHead)

    let statement = try store.transitionStatement(role: .sessionApproval, generation: 1, reason: "initial enrollment", challengeID: "preview-approval", createdAt: lifecycleTime, continuity: .bootstrap)
    let message = try statement.canonicalData()
    let signature = try approval.sign(message: message)
    let activationHead = try store.previewActivationHead(statement: statement, oldSignature: nil, newSignature: signature, approvalSignature: signature, approvalPublicKeyX963: approval.publicKeyX963)
    let activated = try store.activate(statement: statement, oldSignature: nil, newSignature: signature, approvalSignature: signature, approvalPublicKeyX963: approval.publicKeyX963)
    #expect(activated.headHash == activationHead)

    #expect(throws: AgentPassNativeError.self) {
        try store.previewStageHead(role: .sessionApproval, generation: 1, applicationTag: "approval.g1", publicKeyX963: approval.publicKeyX963, createdAt: lifecycleTime)
    }
}

@Test func lifecycleAncestryRequiresCommittedAncestorAndExactCurrentHead() throws {
    let directory = try lifecycleDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try NativeKeyLifecycleStore(directory: directory.path)
    let approval = LifecycleSoftwareSigner()

    let staged = try store.stage(
        role: .sessionApproval, generation: 1, applicationTag: "approval.g1",
        publicKeyX963: approval.publicKeyX963, createdAt: lifecycleTime
    )
    let statement = try store.transitionStatement(
        role: .sessionApproval, generation: 1, reason: "initial enrollment",
        challengeID: "ancestry-approval", createdAt: lifecycleTime, continuity: .bootstrap
    )
    let message = try statement.canonicalData()
    let signature = try approval.sign(message: message)
    let activated = try store.activate(
        statement: statement, oldSignature: nil, newSignature: signature,
        approvalSignature: signature, approvalPublicKeyX963: approval.publicKeyX963
    )

    #expect(try store.verifyCurrentHeadDescendsFrom(
        ancestorHeadHash: staged.headHash, currentHeadHash: activated.headHash
    ))
    #expect(try store.verifyCurrentHeadDescendsFrom(
        ancestorHeadHash: activated.headHash, currentHeadHash: activated.headHash
    ))
    #expect(try !store.verifyCurrentHeadDescendsFrom(
        ancestorHeadHash: String(repeating: "a", count: 64), currentHeadHash: activated.headHash
    ))
    #expect(try !store.verifyCurrentHeadDescendsFrom(
        ancestorHeadHash: NativeKeyLifecycleStore.zeroHash, currentHeadHash: activated.headHash
    ))
    #expect(throws: AgentPassNativeError.self) {
        try store.verifyCurrentHeadDescendsFrom(
            ancestorHeadHash: staged.headHash, currentHeadHash: staged.headHash
        )
    }
}

@Test func lifecyclePreparedRecordBytesReplayExactlyAndRejectTamper() throws {
    let directory = try lifecycleDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try NativeKeyLifecycleStore(directory: directory.path)
    let approval = LifecycleSoftwareSigner()

    let stagedData = try store.prepareStageRecordData(role: .sessionApproval, generation: 1, applicationTag: "approval.g1", publicKeyX963: approval.publicKeyX963, createdAt: lifecycleTime)
    let stagedObject = try #require(JSONSerialization.jsonObject(with: stagedData) as? [String: Any])
    let stagedHead = try #require(stagedObject["record_hash"] as? String)
    let staged = try store.appendPreparedRecordData(stagedData)
    #expect(staged.headHash == stagedHead)

    let statement = try store.transitionStatement(role: .sessionApproval, generation: 1, reason: "initial enrollment", challengeID: "prepared-approval", createdAt: lifecycleTime, continuity: .bootstrap)
    let message = try statement.canonicalData()
    let signature = try approval.sign(message: message)
    let activationData = try store.prepareActivationRecordData(statement: statement, oldSignature: nil, newSignature: signature, approvalSignature: signature, approvalPublicKeyX963: approval.publicKeyX963)
    let activationObject = try #require(JSONSerialization.jsonObject(with: activationData) as? [String: Any])
    let activationHead = try #require(activationObject["record_hash"] as? String)
    let activated = try store.appendPreparedRecordData(activationData)
    #expect(activated.headHash == activationHead)
    #expect(activated.active(for: .sessionApproval)?.publicKeyX963 == approval.publicKeyX963)

    var tampered = activationObject
    tampered["reason"] = "substituted"
    let tamperedData = try JSONSerialization.data(withJSONObject: tampered, options: [.sortedKeys, .withoutEscapingSlashes])
    #expect(throws: AgentPassNativeError.self) { try store.appendPreparedRecordData(tamperedData) }
    #expect(try store.verify().headHash == activationHead)
}

@Test func lifecycleRotatesAllRolesAndVerifiesHistoricalStateAfterRestart() throws {
    let directory = try lifecycleDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try NativeKeyLifecycleStore(directory: directory.path)
    let approval1 = LifecycleSoftwareSigner()
    let approval2 = LifecycleSoftwareSigner()
    let git1 = LifecycleSoftwareSigner()
    let git2 = LifecycleSoftwareSigner()
    let audit1 = LifecycleSoftwareSigner()
    let audit2 = LifecycleSoftwareSigner()

    try bootstrapApproval(store, signer: approval1)
    try bootstrapRole(.gitSigning, store: store, signer: git1, approval: approval1)
    try bootstrapRole(.auditCheckpoint, store: store, signer: audit1, approval: approval1)
    try rotateRole(.gitSigning, store: store, old: git1, new: git2, approval: approval1)
    try rotateRole(.auditCheckpoint, store: store, old: audit1, new: audit2, approval: approval1)
    try rotateRole(.sessionApproval, store: store, old: approval1, new: approval2, approval: approval1)

    let state = try store.verify()
    #expect(state.sequence == 12)
    #expect(state.active(for: .gitSigning)?.publicKeyX963 == git2.publicKeyX963)
    #expect(state.active(for: .auditCheckpoint)?.publicKeyX963 == audit2.publicKeyX963)
    #expect(state.active(for: .sessionApproval)?.publicKeyX963 == approval2.publicKeyX963)
    #expect(state.generation(1, for: .gitSigning)?.status == .retired)
    #expect(state.generation(1, for: .auditCheckpoint)?.status == .retired)
    #expect(state.generation(1, for: .sessionApproval)?.status == .retired)
    #expect(try recordFiles(directory).allSatisfy { ((try? FileManager.default.attributesOfItem(atPath: $0.path)[.posixPermissions] as? NSNumber)?.intValue) == 0o400 })

    let restarted = try NativeKeyLifecycleStore(directory: directory.path, expectedHeadHash: state.headHash)
    #expect(try restarted.verify() == state)
}

@Test func lifecycleRejectsWrongSignaturesMutatedStatementsAndApprovalSubstitution() throws {
    let directory = try lifecycleDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try NativeKeyLifecycleStore(directory: directory.path)
    let approval = LifecycleSoftwareSigner()
    let imposter = LifecycleSoftwareSigner()
    let git1 = LifecycleSoftwareSigner()
    let git2 = LifecycleSoftwareSigner()
    try bootstrapApproval(store, signer: approval)
    try bootstrapRole(.gitSigning, store: store, signer: git1, approval: approval)
    try store.stage(role: .gitSigning, generation: 2, applicationTag: "git.g2", publicKeyX963: git2.publicKeyX963, createdAt: lifecycleTime)
    let statement = try store.transitionStatement(role: .gitSigning, generation: 2, reason: "rotate", challengeID: "challenge-git-2", createdAt: lifecycleTime)
    let message = try statement.canonicalData()
    let mutated = NativeKeyTransitionStatement(role: .gitSigning, oldGeneration: 1, newGeneration: 2, oldFingerprint: statement.oldFingerprint, newFingerprint: statement.newFingerprint, stateSequence: statement.stateSequence, reason: "different reason", challengeID: statement.challengeID, createdAt: statement.createdAt, previousLifecycleHead: statement.previousLifecycleHead, continuity: .clean)

    #expect(throws: AgentPassNativeError.self) { try store.activate(statement: mutated, oldSignature: git1.sign(message: message), newSignature: git2.sign(message: message), approvalSignature: approval.sign(message: message), approvalPublicKeyX963: approval.publicKeyX963) }
    #expect(throws: AgentPassNativeError.self) { try store.activate(statement: statement, oldSignature: imposter.sign(message: message), newSignature: git2.sign(message: message), approvalSignature: approval.sign(message: message), approvalPublicKeyX963: approval.publicKeyX963) }
    #expect(throws: AgentPassNativeError.self) { try store.activate(statement: statement, oldSignature: git1.sign(message: message), newSignature: imposter.sign(message: message), approvalSignature: approval.sign(message: message), approvalPublicKeyX963: approval.publicKeyX963) }
    #expect(throws: AgentPassNativeError.self) { try store.activate(statement: statement, oldSignature: git1.sign(message: message), newSignature: git2.sign(message: message), approvalSignature: imposter.sign(message: message), approvalPublicKeyX963: imposter.publicKeyX963) }
    #expect(try store.verify().generation(2, for: .gitSigning)?.status == .staged)
}

@Test func lifecycleEnforcesGenerationMonotonicitySingleStageAndPermanentTagUniqueness() throws {
    let directory = try lifecycleDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try NativeKeyLifecycleStore(directory: directory.path)
    let approval = LifecycleSoftwareSigner()
    #expect(throws: AgentPassNativeError.self) { try store.stage(role: .gitSigning, generation: 1, applicationTag: "premature", publicKeyX963: LifecycleSoftwareSigner().publicKeyX963, createdAt: lifecycleTime) }
    try bootstrapApproval(store, signer: approval)
    let git = LifecycleSoftwareSigner()
    #expect(throws: AgentPassNativeError.self) { try store.stage(role: .gitSigning, generation: 2, applicationTag: "gap", publicKeyX963: git.publicKeyX963, createdAt: lifecycleTime) }
    try store.stage(role: .gitSigning, generation: 1, applicationTag: "git.g1", publicKeyX963: git.publicKeyX963, createdAt: lifecycleTime)
    #expect(throws: AgentPassNativeError.self) { try store.stage(role: .gitSigning, generation: 2, applicationTag: "git.g2", publicKeyX963: LifecycleSoftwareSigner().publicKeyX963, createdAt: lifecycleTime) }
    #expect(throws: AgentPassNativeError.self) { try store.stage(role: .auditCheckpoint, generation: 1, applicationTag: "git.g1", publicKeyX963: LifecycleSoftwareSigner().publicKeyX963, createdAt: lifecycleTime) }
    #expect(throws: AgentPassNativeError.self) { try store.stage(role: .auditCheckpoint, generation: 1, applicationTag: "audit.reused-key", publicKeyX963: git.publicKeyX963, createdAt: lifecycleTime) }
}

@Test func lifecycleDeletionRequiresRetirementAuthorizationIntentAndConfirmedAbsence() throws {
    let directory = try lifecycleDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try NativeKeyLifecycleStore(directory: directory.path)
    let approval = LifecycleSoftwareSigner()
    let git1 = LifecycleSoftwareSigner()
    let git2 = LifecycleSoftwareSigner()
    try bootstrapApproval(store, signer: approval)
    try bootstrapRole(.gitSigning, store: store, signer: git1, approval: approval)
    #expect(throws: AgentPassNativeError.self) { try store.deletionStatement(role: .gitSigning, generation: 1, reason: "delete", challengeID: "delete-1", createdAt: lifecycleTime) }
    try rotateRole(.gitSigning, store: store, old: git1, new: git2, approval: approval)
    let pinnedHead = try store.verify().headHash
    let deletion = try store.deletionStatement(role: .gitSigning, generation: 1, reason: "retention expired", challengeID: "delete-git-1", createdAt: lifecycleDeletionTime, transitionArchived: true, externallyPinnedHeadHash: pinnedHead)
    #expect(throws: AgentPassNativeError.self) { try store.recordDeletionIntent(role: .gitSigning, generation: 1, reason: "retention expired", challengeID: "delete-git-1", createdAt: lifecycleDeletionTime, approvalSignature: approval.sign(message: deletion), approvalPublicKeyX963: approval.publicKeyX963) }
    #expect(throws: AgentPassNativeError.self) { try store.recordDeletionIntent(role: .gitSigning, generation: 1, reason: "retention expired", challengeID: "delete-git-1", createdAt: lifecycleDeletionTime, approvalSignature: LifecycleSoftwareSigner().sign(message: deletion), approvalPublicKeyX963: approval.publicKeyX963, transitionArchived: true, externallyPinnedHeadHash: pinnedHead) }
    let intent = try store.recordDeletionIntent(role: .gitSigning, generation: 1, reason: "retention expired", challengeID: "delete-git-1", createdAt: lifecycleDeletionTime, approvalSignature: approval.sign(message: deletion), approvalPublicKeyX963: approval.publicKeyX963, transitionArchived: true, externallyPinnedHeadHash: pinnedHead)
    #expect(intent.generation(1, for: .gitSigning)?.status == .deletionIntent)
    #expect(throws: AgentPassNativeError.self) { try store.recordDeleted(role: .gitSigning, generation: 1, createdAt: lifecycleDeletionTime, exactKeyIsAbsent: false) }
    let deleted = try store.recordDeleted(role: .gitSigning, generation: 1, createdAt: lifecycleDeletionTime, exactKeyIsAbsent: true)
    #expect(deleted.generation(1, for: .gitSigning)?.status == .deleted)
    #expect(deleted.active(for: .gitSigning)?.generation == 2)
    #expect(throws: AgentPassNativeError.self) { try store.stage(role: .auditCheckpoint, generation: 1, applicationTag: "git_signing.g1", publicKeyX963: LifecycleSoftwareSigner().publicKeyX963, createdAt: lifecycleTime) }
}

@Test func lifecycleRecoveryIsExplicitAndRequiresPinnedAuthority() throws {
    let directory = try lifecycleDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let recovery = LifecycleRecoverySigner()
    let approval = LifecycleSoftwareSigner()
    let git1 = LifecycleSoftwareSigner()
    let git2 = LifecycleSoftwareSigner()
    let store = try NativeKeyLifecycleStore(directory: directory.path, recoveryPublicKeys: [recovery.publicKey])
    try bootstrapApproval(store, signer: approval)
    try bootstrapRole(.gitSigning, store: store, signer: git1, approval: approval)
    try store.stage(role: .gitSigning, generation: 2, applicationTag: "git.recovered.g2", publicKeyX963: git2.publicKeyX963, createdAt: lifecycleTime)
    let statement = try store.transitionStatement(role: .gitSigning, generation: 2, reason: "lost old hardware key", challengeID: "recovery-1", createdAt: lifecycleTime, continuity: .recovered)
    let message = try statement.canonicalData()
    #expect(throws: AgentPassNativeError.self) { try store.activate(statement: statement, oldSignature: nil, newSignature: git2.sign(message: message), approvalSignature: approval.sign(message: message), approvalPublicKeyX963: approval.publicKeyX963) }
    let state = try store.activate(statement: statement, oldSignature: nil, newSignature: git2.sign(message: message), approvalSignature: recovery.sign(message: message), approvalPublicKeyX963: recovery.publicKey)
    #expect(state.active(for: .gitSigning)?.generation == 2)
    #expect(state.generation(1, for: .gitSigning)?.status == .retired)
    #expect(throws: AgentPassNativeError.self) { try NativeKeyLifecycleStore(directory: directory.path) }
    #expect(try NativeKeyLifecycleStore(directory: directory.path, recoveryPublicKeys: [recovery.publicKey]).verify() == state)
}

@Test func lifecycleThresholdRecoveryPersistsAndReplaysCompleteCeremony() throws {
    let directory = try lifecycleDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let first = LifecycleRecoverySigner(), second = LifecycleRecoverySigner()
    let approval = LifecycleSoftwareSigner(), old = LifecycleSoftwareSigner(), replacement = LifecycleSoftwareSigner()
    let store = try NativeKeyLifecycleStore(directory: directory.path, recoveryPublicKeys: [first.publicKey, second.publicKey], recoveryThreshold: 2)
    try bootstrapApproval(store, signer: approval)
    try bootstrapRole(.gitSigning, store: store, signer: old, approval: approval)
    _ = try store.stage(role: .gitSigning, generation: 2, applicationTag: "git.threshold.g2", publicKeyX963: replacement.publicKeyX963, createdAt: lifecycleTime)
    let stagedState = try store.verify()
    let active = try #require(stagedState.active(for: .gitSigning))

    let policy: [String: Any] = [
        "version": 1, "policy_id": "offline-recovery", "threshold": 2,
        "authorities": [
            ["id": "security-1", "public_key": lifecycleRecoveryPEM(first.publicKey)],
            ["id": "security-2", "public_key": lifecycleRecoveryPEM(second.publicKey)]
        ]
    ]
    let policyData = try lifecycleCanonicalJSON(policy)
    let nonce = lifecycleBase64URL(Data(repeating: 7, count: 32))
    let request: [String: Any] = [
        "version": 1, "installation_id": "test-installation", "role": "git_signing",
        "from_generation": active.generation, "from_fingerprint": active.fingerprint,
        "proposed_generation": 2, "proposed_public_key": try SSHSIG.authorizedKey(publicKeyX963: replacement.publicKeyX963),
        "recovery_policy_version": 1, "recovery_policy_id": "offline-recovery",
        "recovery_policy_hash": lifecycleSHA256(policyData), "lifecycle_head_hash": stagedState.headHash,
        "audit_entries": 3, "audit_head_hash": String(repeating: "a", count: 64),
        "latest_checkpoint_hash": String(repeating: "b", count: 64), "latest_receipt_hash": String(repeating: "c", count: 64),
        "control_sequence": 2, "nonce": nonce, "issued_at": lifecycleTime, "expires_at": "2027-02-03T04:15:06.000Z"
    ]
    let requestData = try lifecycleCanonicalJSON(request)
    let requestHash = lifecycleSHA256(requestData)
    func authorization(id: String, signer: LifecycleRecoverySigner) throws -> Data {
        var statement: [String: Any] = [
            "version": 1, "signer_id": id, "request_hash": requestHash, "signed_at": lifecycleTime,
            "public_key_fingerprint": try NativeRecoveryVerifier.authorityFingerprint(rawEd25519PublicKey: signer.publicKey)
        ]
        statement["signature"] = try signer.sign(message: lifecycleCanonicalJSON(statement)).base64EncodedString()
        return try lifecycleCanonicalJSON(statement)
    }
    let evidence = try NativeRecoveryEvidenceBundle(requestData: requestData, policyData: policyData, authorizationData: [try authorization(id: "security-1", signer: first), try authorization(id: "security-2", signer: second)]).canonicalData()
    let transition = try store.transitionStatement(role: .gitSigning, generation: 2, reason: "offline-threshold-recovery:\(requestHash)", challengeID: nonce, createdAt: lifecycleTime, continuity: .recovered)
    #expect(throws: AgentPassNativeError.self) {
        try store.activate(statement: transition, oldSignature: nil, newSignature: replacement.sign(message: transition.canonicalData()), approvalSignature: first.sign(message: transition.canonicalData()), approvalPublicKeyX963: first.publicKey)
    }
    let final = try store.activateRecovered(statement: transition, newSignature: replacement.sign(message: transition.canonicalData()), evidenceData: evidence)
    #expect(final.active(for: .gitSigning)?.generation == 2)
    #expect(try NativeKeyLifecycleStore(directory: directory.path, recoveryPublicKeys: [first.publicKey, second.publicKey], recoveryThreshold: 2).verify() == final)
    #expect(throws: AgentPassNativeError.self) {
        try NativeKeyLifecycleStore(directory: directory.path, recoveryPublicKeys: [first.publicKey, second.publicKey], recoveryThreshold: 1)
    }
}

@Test func lifecycleCoordinatorPreparesRecoveredAuditActivationWithoutMutation() throws {
    let directory = try lifecycleDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let first = LifecycleRecoverySigner(), second = LifecycleRecoverySigner()
    let approval = LifecycleSoftwareSigner(), old = LifecycleSoftwareSigner(), replacement = LifecycleSoftwareSigner()
    let store = try NativeKeyLifecycleStore(
        directory: directory.path,
        recoveryPublicKeys: [first.publicKey, second.publicKey],
        recoveryThreshold: 2
    )
    try bootstrapApproval(store, signer: approval)
    try bootstrapRole(.auditCheckpoint, store: store, signer: old, approval: approval)
    _ = try store.stage(
        role: .auditCheckpoint, generation: 2, applicationTag: "audit.recovered.g2",
        publicKeyX963: replacement.publicKeyX963, createdAt: lifecycleTime
    )
    let stagedState = try store.verify()
    let active = try #require(stagedState.active(for: .auditCheckpoint))
    let policy: [String: Any] = [
        "version": 1, "policy_id": "offline-recovery", "threshold": 2,
        "authorities": [
            ["id": "security-1", "public_key": lifecycleRecoveryPEM(first.publicKey)],
            ["id": "security-2", "public_key": lifecycleRecoveryPEM(second.publicKey)]
        ]
    ]
    let policyData = try lifecycleCanonicalJSON(policy)
    let nonce = lifecycleBase64URL(Data(repeating: 8, count: 32))
    let request: [String: Any] = [
        "version": 1, "installation_id": "test-installation", "role": "audit_checkpoint",
        "from_generation": active.generation, "from_fingerprint": active.fingerprint,
        "proposed_generation": 2, "proposed_public_key": try SSHSIG.authorizedKey(publicKeyX963: replacement.publicKeyX963),
        "recovery_policy_version": 1, "recovery_policy_id": "offline-recovery",
        "recovery_policy_hash": lifecycleSHA256(policyData), "lifecycle_head_hash": stagedState.headHash,
        "audit_entries": 3, "audit_head_hash": String(repeating: "a", count: 64),
        "latest_checkpoint_hash": String(repeating: "b", count: 64), "latest_receipt_hash": String(repeating: "c", count: 64),
        "control_sequence": 2, "nonce": nonce, "issued_at": lifecycleTime, "expires_at": "2027-02-03T04:15:06.000Z"
    ]
    let requestData = try lifecycleCanonicalJSON(request)
    let requestHash = lifecycleSHA256(requestData)
    func authorization(id: String, signer: LifecycleRecoverySigner) throws -> Data {
        var statement: [String: Any] = [
            "version": 1, "signer_id": id, "request_hash": requestHash, "signed_at": lifecycleTime,
            "public_key_fingerprint": try NativeRecoveryVerifier.authorityFingerprint(rawEd25519PublicKey: signer.publicKey)
        ]
        statement["signature"] = try signer.sign(message: lifecycleCanonicalJSON(statement)).base64EncodedString()
        return try lifecycleCanonicalJSON(statement)
    }
    let authorizationData = [
        try authorization(id: "security-1", signer: first),
        try authorization(id: "security-2", signer: second)
    ]
    let verification = try NativeRecoveryVerifier.verify(
        requestData: requestData, policyData: policyData, authorizationData: authorizationData,
        nowMilliseconds: Int64(lifecycleTimeDate().timeIntervalSince1970 * 1_000)
    )
    let evidence = try NativeRecoveryEvidenceBundle(
        requestData: requestData, policyData: policyData, authorizationData: authorizationData
    ).canonicalData()
    let coordinator = try NativeKeyLifecycleCoordinator(
        store: store,
        provider: LifecycleRecoveryPreparationProvider(keys: ["audit.recovered.g2": replacement]),
        baseTags: [.gitSigning: "git", .auditCheckpoint: "audit", .sessionApproval: "approval"]
    )
    let preparation = try coordinator.prepareRecoveredAuditActivation(verification: verification, evidenceData: evidence)
    #expect(try store.verify() == stagedState)
    #expect(preparation.lifecycleHeadHash != stagedState.headHash)
    #expect(preparation.replacementPublicKeyX963 == replacement.publicKeyX963)
    #expect(preparation.retiringPublicKeyX963 == old.publicKeyX963)
    #expect(try store.validatePreparedRecordData(preparation.lifecycleRecordData).headHash == preparation.lifecycleHeadHash)
}

private func lifecycleTimeDate() -> Date {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.date(from: lifecycleTime)!
}

private func lifecycleCanonicalJSON(_ object: Any) throws -> Data {
    try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
}

private func lifecycleSHA256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

private func lifecycleBase64URL(_ data: Data) -> String {
    data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}

private func lifecycleRecoveryPEM(_ raw: Data) -> String {
    let prefix = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])
    return "-----BEGIN PUBLIC KEY-----\n\((prefix + raw).base64EncodedString())\n-----END PUBLIC KEY-----\n"
}

@Test func lifecycleRejectsUnknownFilesSymlinksAndPermissiveRecords() throws {
    let directory = try lifecycleDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try NativeKeyLifecycleStore(directory: directory.path)
    let approval = LifecycleSoftwareSigner()
    try bootstrapApproval(store, signer: approval)
    let unknown = directory.appendingPathComponent("README")
    try Data("x".utf8).write(to: unknown)
    #expect(throws: AgentPassNativeError.self) { try NativeKeyLifecycleStore(directory: directory.path) }
    try FileManager.default.removeItem(at: unknown)

    let first = try #require(recordFiles(directory).first)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: first.path)
    #expect(throws: AgentPassNativeError.self) { try NativeKeyLifecycleStore(directory: directory.path) }
    try FileManager.default.setAttributes([.posixPermissions: 0o400], ofItemAtPath: first.path)

    let backup = directory.deletingLastPathComponent().appendingPathComponent(UUID().uuidString)
    try FileManager.default.moveItem(at: first, to: backup)
    try FileManager.default.createSymbolicLink(atPath: first.path, withDestinationPath: backup.path)
    #expect(throws: AgentPassNativeError.self) { try NativeKeyLifecycleStore(directory: directory.path) }
}

@Test func lifecycleRejectsRecordMutationUnknownKeysAndSequenceGaps() throws {
    let directory = try lifecycleDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try NativeKeyLifecycleStore(directory: directory.path)
    let approval = LifecycleSoftwareSigner()
    try bootstrapApproval(store, signer: approval)
    var files = try recordFiles(directory)
    let second = files[1]
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: second.path)
    var object = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: second)) as? [String: Any])
    object["unexpected"] = true
    try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]).write(to: second)
    try FileManager.default.setAttributes([.posixPermissions: 0o400], ofItemAtPath: second.path)
    #expect(throws: AgentPassNativeError.self) { try NativeKeyLifecycleStore(directory: directory.path) }

    try FileManager.default.removeItem(at: second)
    files = try recordFiles(directory)
    #expect(files.count == 1)
    #expect(throws: AgentPassNativeError.self) { try NativeKeyLifecycleStore(directory: directory.path, expectedHeadHash: store.verify().headHash) }
}

@Test func lifecycleDetectsInProcessAndExternallyPinnedRollback() throws {
    let directory = try lifecycleDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try NativeKeyLifecycleStore(directory: directory.path)
    let approval = LifecycleSoftwareSigner()
    try bootstrapApproval(store, signer: approval)
    let state = try store.verify()
    let last = try #require(recordFiles(directory).last)
    try FileManager.default.removeItem(at: last)
    #expect(throws: AgentPassNativeError.self) { try store.verify() }
    #expect(throws: AgentPassNativeError.self) { try NativeKeyLifecycleStore(directory: directory.path, expectedHeadHash: state.headHash) }
}

@Test func lifecycleRejectsSequenceGapsHardLinksAndNonCanonicalJSON() throws {
    let gapDirectory = try lifecycleDirectory()
    defer { try? FileManager.default.removeItem(at: gapDirectory) }
    let gapStore = try NativeKeyLifecycleStore(directory: gapDirectory.path)
    try bootstrapApproval(gapStore, signer: LifecycleSoftwareSigner())
    let gapFiles = try recordFiles(gapDirectory)
    try FileManager.default.removeItem(at: gapFiles[0])
    #expect(throws: AgentPassNativeError.self) { try NativeKeyLifecycleStore(directory: gapDirectory.path) }

    let linkDirectory = try lifecycleDirectory()
    defer { try? FileManager.default.removeItem(at: linkDirectory) }
    let linkStore = try NativeKeyLifecycleStore(directory: linkDirectory.path)
    try bootstrapApproval(linkStore, signer: LifecycleSoftwareSigner())
    let linkedRecord = try #require(recordFiles(linkDirectory).first)
    let outsideLink = linkDirectory.deletingLastPathComponent().appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: outsideLink) }
    try FileManager.default.linkItem(at: linkedRecord, to: outsideLink)
    #expect(throws: AgentPassNativeError.self) { try NativeKeyLifecycleStore(directory: linkDirectory.path) }

    try FileManager.default.removeItem(at: outsideLink)
    let canonicalRecord = try #require(recordFiles(linkDirectory).first)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: canonicalRecord.path)
    let canonicalData = try Data(contentsOf: canonicalRecord)
    try (Data(" \n".utf8) + canonicalData).write(to: canonicalRecord)
    try FileManager.default.setAttributes([.posixPermissions: 0o400], ofItemAtPath: canonicalRecord.path)
    #expect(throws: AgentPassNativeError.self) { try NativeKeyLifecycleStore(directory: linkDirectory.path) }
}

@Test func lifecycleRejectsTimestampRollbackWithoutPoisoningTheLedger() throws {
    let directory = try lifecycleDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try NativeKeyLifecycleStore(directory: directory.path)
    let approval = LifecycleSoftwareSigner()
    try bootstrapApproval(store, signer: approval)
    let before = try store.verify()
    #expect(throws: AgentPassNativeError.self) { try store.stage(role: .gitSigning, generation: 1, applicationTag: "git.old-time", publicKeyX963: LifecycleSoftwareSigner().publicKeyX963, createdAt: "2027-01-01T00:00:00.000Z") }
    #expect(try store.verify() == before)
    #expect(try recordFiles(directory).count == 2)
}

@Test func lifecycleRecoversStrictlyValidatedCommittedTemporaryTail() throws {
    let directory = try lifecycleDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try NativeKeyLifecycleStore(directory: directory.path)
    try bootstrapApproval(store, signer: LifecycleSoftwareSigner())
    let before = try store.verify()
    let finalRecord = try #require(try recordFiles(directory).filter { $0.pathExtension == "json" }.last)
    let temporary = directory.appendingPathComponent(".lifecycle-01234567-89AB-CDEF-0123-456789ABCDEF.tmp")
    try FileManager.default.linkItem(at: finalRecord, to: temporary)

    let recovered = try NativeKeyLifecycleStore(directory: directory.path, expectedHeadHash: before.headHash)

    #expect(try recovered.verify() == before)
    #expect(!FileManager.default.fileExists(atPath: temporary.path))
    let attributes = try FileManager.default.attributesOfItem(atPath: finalRecord.path)
    #expect((attributes[.referenceCount] as? NSNumber)?.intValue == 1)
}

@Test func lifecycleRejectsUnsafeTemporaryCrashRemnant() throws {
    let directory = try lifecycleDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try NativeKeyLifecycleStore(directory: directory.path)
    try bootstrapApproval(store, signer: LifecycleSoftwareSigner())
    let finalRecord = try #require(try recordFiles(directory).filter { $0.pathExtension == "json" }.last)
    let temporary = directory.appendingPathComponent(".lifecycle-FEDCBA98-7654-3210-FEDC-BA9876543210.tmp")
    try Data(contentsOf: finalRecord).write(to: temporary, options: .withoutOverwriting)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: temporary.path)

    #expect(throws: AgentPassNativeError.self) { try NativeKeyLifecycleStore(directory: directory.path) }
    #expect(FileManager.default.fileExists(atPath: temporary.path))
}

@Test func lifecycleConcurrentWritersSerializeWithoutLedgerCorruption() throws {
    let directory = try lifecycleDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let bootstrapStore = try NativeKeyLifecycleStore(directory: directory.path)
    try bootstrapApproval(bootstrapStore, signer: LifecycleSoftwareSigner())
    let first = try NativeKeyLifecycleStore(directory: directory.path)
    let second = try NativeKeyLifecycleStore(directory: directory.path)
    let firstKey = LifecycleSoftwareSigner()
    let secondKey = LifecycleSoftwareSigner()
    let results = LifecycleConcurrentResults()
    let group = DispatchGroup()
    let queue = DispatchQueue(label: "agentpass.lifecycle.concurrent", attributes: .concurrent)

    group.enter()
    queue.async {
        defer { group.leave() }
        results.append((try? first.stage(role: .gitSigning, generation: 1, applicationTag: "git.concurrent", publicKeyX963: firstKey.publicKeyX963, createdAt: lifecycleTime)) != nil)
    }
    group.enter()
    queue.async {
        defer { group.leave() }
        results.append((try? second.stage(role: .auditCheckpoint, generation: 1, applicationTag: "audit.concurrent", publicKeyX963: secondKey.publicKeyX963, createdAt: lifecycleTime)) != nil)
    }
    group.wait()

    let outcomes = results.snapshot()
    #expect(outcomes.filter { $0 }.count == 1)
    #expect(outcomes.filter { !$0 }.count == 1)
    let state = try NativeKeyLifecycleStore(directory: directory.path).verify()
    #expect(state.sequence == 3)
    #expect(state.generations.filter { $0.role != .sessionApproval }.count == 1)
}

@Test func secureEnclaveExactTagAPIsRejectMalformedTagsBeforeKeychainAccess() {
    #expect(throws: AgentPassNativeError.self) { try SecureEnclaveKeyStore.exists(applicationTag: "") }
    #expect(throws: AgentPassNativeError.self) { try SecureEnclaveKeyStore.loadExisting(applicationTag: "bad\0tag") }
    #expect(throws: AgentPassNativeError.self) { try SecureEnclaveKeyStore.delete(applicationTag: String(repeating: "x", count: 513)) }
}
