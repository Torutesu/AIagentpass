import CryptoKit
import Darwin
import Foundation
import Testing
@testable import AgentPassNativeCore

private final class CoordinatorKey: NativeLifecycleKeyHandle, @unchecked Sendable {
    let privateKey = P256.Signing.PrivateKey()
    var publicKeyX963: Data { privateKey.publicKey.x963Representation }
    func sign(message: Data) throws -> Data { try privateKey.signature(for: message).rawRepresentation }
}

private final class CoordinatorProvider: NativeLifecycleKeyProvider, @unchecked Sendable {
    private var keys: [String: CoordinatorKey] = [:]
    private var failAfterNextDelete = false
    private let lock = NSLock()
    func create(applicationTag: String, requiresUserPresence: Bool) throws -> any NativeLifecycleKeyHandle {
        lock.lock(); defer { lock.unlock() }
        guard keys[applicationTag] == nil else { throw AgentPassNativeError.invalidKey("duplicate") }
        let key = CoordinatorKey(); keys[applicationTag] = key; return key
    }
    func load(applicationTag: String) throws -> any NativeLifecycleKeyHandle {
        lock.lock(); defer { lock.unlock() }
        guard let key = keys[applicationTag] else { throw AgentPassNativeError.invalidKey("missing") }
        return key
    }
    func exists(applicationTag: String) throws -> Bool { lock.lock(); defer { lock.unlock() }; return keys[applicationTag] != nil }
    func delete(applicationTag: String) throws {
        lock.lock(); defer { lock.unlock() }
        guard keys.removeValue(forKey: applicationTag) != nil else { throw AgentPassNativeError.invalidKey("missing") }
        if failAfterNextDelete { failAfterNextDelete = false; throw CoordinatorDeletionInterruption.afterExactKeyDeletion }
    }
    func interruptAfterNextDelete() { lock.lock(); failAfterNextDelete = true; lock.unlock() }
    @discardableResult func substitute(applicationTag: String) -> CoordinatorKey {
        lock.lock(); defer { lock.unlock() }
        let key = CoordinatorKey(); keys[applicationTag] = key; return key
    }
}

private enum CoordinatorDeletionInterruption: Error { case afterExactKeyDeletion }

private struct CoordinatorDeletionVerifier: NativeLifecycleDeletionProofVerifier {
    let archivedAt: Date
    let verifiedAt: Date
    func verify(_ proof: NativeLifecycleDeletionProof, role: NativeKeyRole, generation: Int, fingerprint: String) throws -> (archivedAt: Date, verifiedAt: Date) {
        guard proof.transitionReceiptHash == String(repeating: "a", count: 64) else { throw AgentPassNativeError.invalidSignature("receipt") }
        return (archivedAt, verifiedAt)
    }
}

private struct CoordinatorLeasedDeletionVerifier: NativeAuditLifecycleDeletionLeaseVerifier {
    let archivedAt: Date
    let verifiedAt: Date
    let archiveDirectory: String
    let segment: NativeAuditRetentionSegment
    let identities: [NativeAuditRetentionFileIdentity]
    let swapAfterAcquire: Bool

    func verify(_ proof: NativeLifecycleDeletionProof, role: NativeKeyRole, generation: Int, fingerprint: String) throws -> (archivedAt: Date, verifiedAt: Date) {
        guard role == .auditCheckpoint,
              proof.transitionReceiptHash == String(repeating: "a", count: 64) else {
            throw AgentPassNativeError.invalidSignature("receipt")
        }
        return (archivedAt, verifiedAt)
    }

    func acquireDeletionEvidenceLease(
        _ proof: NativeLifecycleDeletionProof,
        role: NativeKeyRole,
        generation: Int,
        fingerprint: String
    ) throws -> NativeLifecycleDeletionEvidenceLease {
        let times = try verify(proof, role: role, generation: generation, fingerprint: fingerprint)
        let lease = try NativeAuditRetainedArchiveLease(archiveDirectory: archiveDirectory, segment: segment, expectedFileIdentities: identities)
        if swapAfterAcquire {
            let root = URL(fileURLWithPath: archiveDirectory)
            let target = root.appendingPathComponent(segment.auditArchiveFile)
            let original = root.appendingPathComponent("leased-original-audit.jsonl")
            try FileManager.default.moveItem(at: target, to: original)
            try Data("retained-audit\n".utf8).write(to: target)
            guard chmod(target.path, 0o600) == 0 else { throw POSIXError(.EIO) }
        }
        let binding = NativeAuditDeletionIntentBinding(
            bundleSHA256: String(repeating: "4", count: 64), retainedSegmentHash: String(repeating: "5", count: 64),
            retainedIdentityHash: String(repeating: "6", count: 64), archivePathChainHash: lease.pathChainHash,
            operationID: "coordinator-delete-audit",
            spoolManifestHash: String(repeating: "7", count: 64), spoolDirectoryName: "spool-" + String(repeating: "7", count: 64),
            spoolDevice: identities[0].device, spoolInode: identities[0].inode
        )
        return NativeLifecycleDeletionEvidenceLease(
            archivedAt: times.archivedAt,
            verifiedAt: times.verifiedAt,
            archiveLease: lease,
            binding: binding
        )
    }

    func acquireRecordedDeletionArchiveLease(role: NativeKeyRole, generation: Int, fingerprint: String, lifecycleHeadHash: String, binding: NativeAuditDeletionIntentBinding) throws -> NativeLifecycleDeletionEvidenceLease {
        guard role == .auditCheckpoint else { throw AgentPassNativeError.invalidConfiguration("role") }
        let lease = try NativeAuditRetainedArchiveLease(
            archiveDirectory: archiveDirectory,
            segment: segment,
            expectedFileIdentities: identities
        )
        guard lease.pathChainHash == binding.archivePathChainHash else {
            throw AgentPassNativeError.invalidSignature("archive path chain")
        }
        return NativeLifecycleDeletionEvidenceLease(archivedAt: archivedAt, verifiedAt: verifiedAt, archiveLease: lease, binding: binding)
    }
}

private func coordinatorRetainedArchive(root: URL) throws -> (URL, NativeAuditRetentionSegment, [NativeAuditRetentionFileIdentity]) {
    let archive = root.appendingPathComponent("retained-archives", isDirectory: true)
    try FileManager.default.createDirectory(at: archive, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    guard chmod(archive.path, 0o700) == 0 else { throw POSIXError(.EIO) }
    let audit = Data("retained-audit\n".utf8)
    let checkpoints = Data("retained-checkpoints\n".utf8)
    let receipts = Data("retained-receipts\n".utf8)
    let segment = NativeAuditRetentionSegment(
        segmentID: "retained-segment",
        auditArchiveFile: "audit.jsonl", auditArchiveSHA256: NativeAuditLog.hash(audit),
        firstEventIndex: 1, lastEventIndex: 1,
        previousEventHash: NativeAuditLog.zeroHash, terminalEventHash: String(repeating: "1", count: 64),
        checkpointArchiveFile: "checkpoints.jsonl", checkpointArchiveSHA256: NativeAuditLog.hash(checkpoints),
        firstCheckpointIndex: 1, lastCheckpointIndex: 1,
        previousCheckpointHash: NativeAuditLog.zeroHash, terminalCheckpointHash: String(repeating: "2", count: 64),
        receiptArchiveFile: "receipts.jsonl", receiptArchiveSHA256: NativeAuditLog.hash(receipts),
        firstReceiptIndex: 1, lastReceiptIndex: 1,
        previousReceiptHash: NativeAuditLog.zeroHash, terminalReceiptHash: String(repeating: "3", count: 64),
        anchoredEventIndex: 1, anchoredEventHash: String(repeating: "1", count: 64),
        sealedAt: "2027-01-01T00:00:00.000Z", latestAnchorReceivedAt: "2027-01-01T00:01:00.000Z"
    )
    for (name, data) in [
        (segment.auditArchiveFile, audit),
        (segment.checkpointArchiveFile, checkpoints),
        (segment.receiptArchiveFile, receipts),
    ] {
        let path = archive.appendingPathComponent(name)
        try data.write(to: path)
        guard chmod(path.path, 0o600) == 0 else { throw POSIXError(.EIO) }
    }
    let observation = try NativeAuditRetentionArchiveObservation.observe(archiveDirectory: archive.path, segment: segment)
    return (archive, segment, try #require(observation.fileIdentities))
}

private struct CoordinatorApproval: P256MessageSigner {
    let privateKey = P256.Signing.PrivateKey()
    var publicKeyX963: Data { privateKey.publicKey.x963Representation }
    func sign(message: Data) throws -> Data { try privateKey.signature(for: message).rawRepresentation }
}

private final class CoordinatorClock: @unchecked Sendable {
    private var date: Date
    private let lock = NSLock()
    init(_ date: Date) { self.date = date }
    func get() -> Date { lock.lock(); defer { lock.unlock() }; return date }
    func set(_ value: Date) { lock.lock(); defer { lock.unlock() }; date = value }
}

private final class CoordinatorPreviewBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: NativeServiceKeyActivationPreview?
    func set(_ preview: NativeServiceKeyActivationPreview) { lock.lock(); value = preview; lock.unlock() }
    func get() -> NativeServiceKeyActivationPreview? { lock.lock(); defer { lock.unlock() }; return value }
}

private enum CoordinatorGateInterruption: Error { case afterExactPreview }

private func coordinatorRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    return root
}

private func durableCoordinatorRoot() throws -> URL {
    let parent = URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent(".build")
    guard let canonicalParent = Darwin.realpath(parent.path, nil) else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    defer { free(canonicalParent) }
    let root = URL(fileURLWithPath: String(cString: canonicalParent)).appendingPathComponent("coordinator-side-effects-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    return root
}

private func bootstrapCoordinatorApproval(_ store: NativeKeyLifecycleStore, approval: CoordinatorApproval, date: Date) throws {
    let timestamp = ISO8601DateFormatter.coordinatorString(date)
    _ = try store.stage(role: .sessionApproval, generation: 1, applicationTag: "approval.g1", publicKeyX963: approval.publicKeyX963, createdAt: timestamp)
    let statement = try store.transitionStatement(role: .sessionApproval, generation: 1, reason: "bootstrap", challengeID: "approval-bootstrap", createdAt: timestamp, continuity: .bootstrap)
    let message = try statement.canonicalData()
    _ = try store.activate(statement: statement, oldSignature: nil, newSignature: approval.sign(message: message), approvalSignature: approval.sign(message: message), approvalPublicKeyX963: approval.publicKeyX963)
}

@discardableResult
private func appendDurableCoordinatorRecord(
    _ payload: Data,
    role: NativeKeyRole,
    kind: NativeLifecycleMutationKind,
    createdAt: String,
    store: NativeKeyLifecycleStore,
    pin: NativeLifecyclePinTransaction,
    outbox: NativeLifecycleMutationOutbox
) throws -> NativeKeyLifecycleSnapshot {
    let before = try store.verify()
    let object = try #require(try JSONSerialization.jsonObject(with: payload) as? [String: Any])
    let newHead = try #require(object["record_hash"] as? String)
    let operationID = UUID()
    let pinSequence = (try pin.current()?.sequence ?? 0) + 1
    let outboxPreparation = try outbox.prepare(operationID: operationID, pinSequence: pinSequence, role: role, kind: kind, lifecycleSequence: before.sequence + 1, oldLifecycleHead: before.headHash, newLifecycleHead: newHead, createdAt: createdAt, payload: payload)
    let action = try #require(NativeLifecyclePinAction(rawValue: kind.rawValue))
    let pinPreparation = try pin.prepare(operationID: operationID, sequence: pinSequence, role: role, action: action, oldLifecycleHead: before.headHash, newLifecycleHead: newHead, preparedAt: createdAt)
    let next = try store.appendPreparedRecordData(payload)
    _ = try pin.commit(pinPreparation, observedOldLifecycleHead: before.headHash, observedNewLifecycleHead: next.headHash)
    _ = try outbox.complete(outboxPreparation, observedNewLifecycleHead: next.headHash)
    return next
}

private func bootstrapDurableCoordinatorApproval(
    _ store: NativeKeyLifecycleStore,
    approval: CoordinatorApproval,
    date: Date,
    pin: NativeLifecyclePinTransaction,
    outbox: NativeLifecycleMutationOutbox
) throws {
    let timestamp = ISO8601DateFormatter.coordinatorString(date)
    let stage = try store.prepareStageRecordData(role: .sessionApproval, generation: 1, applicationTag: "approval.g1", publicKeyX963: approval.publicKeyX963, createdAt: timestamp)
    _ = try appendDurableCoordinatorRecord(stage, role: .sessionApproval, kind: .staged, createdAt: timestamp, store: store, pin: pin, outbox: outbox)
    let statement = try store.transitionStatement(role: .sessionApproval, generation: 1, reason: "bootstrap", challengeID: "approval-bootstrap", createdAt: timestamp, continuity: .bootstrap)
    let signature = try approval.sign(message: statement.canonicalData())
    let activation = try store.prepareActivationRecordData(statement: statement, oldSignature: nil, newSignature: signature, approvalSignature: signature, approvalPublicKeyX963: approval.publicKeyX963)
    _ = try appendDurableCoordinatorRecord(activation, role: .sessionApproval, kind: .activated, createdAt: timestamp, store: store, pin: pin, outbox: outbox)
}

@Test func lifecycleCoordinatorBindsKeyCreationActivationAndDeletion() throws {
    let root = try coordinatorRoot(); defer { try? FileManager.default.removeItem(at: root) }
    let store = try NativeKeyLifecycleStore(directory: root.path)
    let provider = CoordinatorProvider()
    let approval = CoordinatorApproval()
    let start = Date(timeIntervalSince1970: 1_800_000_000)
    let clock = CoordinatorClock(start)
    try bootstrapCoordinatorApproval(store, approval: approval, date: start)
    let archived = start.addingTimeInterval(40 * 86_400)
    let verified = archived.addingTimeInterval(31 * 86_400)
    let coordinator = try NativeKeyLifecycleCoordinator(store: store, provider: provider, baseTags: [.gitSigning: "git", .auditCheckpoint: "audit", .sessionApproval: "approval"], deletionProofVerifier: CoordinatorDeletionVerifier(archivedAt: archived, verifiedAt: verified), now: { clock.get() })

    let first = try coordinator.stageServiceKey(role: .gitSigning)
    #expect(first.applicationTag == "git.g1")
    let bootstrap = try coordinator.activationStatement(role: .gitSigning, generation: 1, reason: "bootstrap", challengeID: "git-bootstrap", continuity: .bootstrap)
    let bootstrapData = try bootstrap.canonicalData()
    _ = try coordinator.activateServiceKey(statement: bootstrap, approvalSignature: approval.sign(message: bootstrapData), approvalPublicKeyX963: approval.publicKeyX963)

    _ = try coordinator.stageServiceKey(role: .gitSigning)
    let rotation = try coordinator.activationStatement(role: .gitSigning, generation: 2, reason: "rotation", challengeID: "git-rotation")
    _ = try coordinator.activateServiceKey(statement: rotation, approvalSignature: approval.sign(message: rotation.canonicalData()), approvalPublicKeyX963: approval.publicKeyX963)
    clock.set(verified)
    let head = try store.verify().headHash
    let proof = NativeLifecycleDeletionProof(lifecycleHeadHash: head, transitionReceiptHash: String(repeating: "a", count: 64), transitionArchivedAt: ISO8601DateFormatter.coordinatorString(archived), verifiedAt: ISO8601DateFormatter.coordinatorString(verified))
    let deletion = try coordinator.deletionStatement(role: .gitSigning, generation: 1, reason: "retention", challengeID: "delete-git-1", minimumRetirementAgeSeconds: 2_592_000, proof: proof)
    let final = try coordinator.deleteRetiredServiceKey(role: .gitSigning, generation: 1, reason: "retention", challengeID: "delete-git-1", minimumRetirementAgeSeconds: 2_592_000, proof: proof, approvalSignature: approval.sign(message: deletion), approvalPublicKeyX963: approval.publicKeyX963)
    #expect(final.generation(1, for: .gitSigning)?.status == .deleted)
    #expect(final.active(for: .gitSigning)?.generation == 2)
    #expect(try !provider.exists(applicationTag: "git.g1"))
}

@Test(arguments: [false, true])
func lifecycleCoordinatorRequiresLiveRetainedArchiveLeaseForAuditKeyDeletion(swapAfterAcquire: Bool) throws {
    let root = try durableCoordinatorRoot(); defer { try? FileManager.default.removeItem(at: root) }
    let ledger = root.appendingPathComponent("ledger", isDirectory: true)
    try FileManager.default.createDirectory(at: ledger, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    let store = try NativeKeyLifecycleStore(directory: ledger.path)
    let provider = CoordinatorProvider()
    let approval = CoordinatorApproval()
    let start = Date(timeIntervalSince1970: 1_800_000_000)
    let clock = CoordinatorClock(start)
    let archived = start.addingTimeInterval(40 * 86_400)
    let verified = archived.addingTimeInterval(31 * 86_400)
    try bootstrapCoordinatorApproval(store, approval: approval, date: start)
    let retained = try coordinatorRetainedArchive(root: root)
    let verifier = CoordinatorLeasedDeletionVerifier(
        archivedAt: archived,
        verifiedAt: verified,
        archiveDirectory: retained.0.path,
        segment: retained.1,
        identities: retained.2,
        swapAfterAcquire: swapAfterAcquire
    )
    let coordinator = try NativeKeyLifecycleCoordinator(
        store: store,
        provider: provider,
        baseTags: [.gitSigning: "git", .auditCheckpoint: "audit", .sessionApproval: "approval"],
        deletionProofVerifier: verifier,
        now: { clock.get() }
    )
    let first = try coordinator.stageServiceKey(role: .auditCheckpoint)
    let bootstrap = try coordinator.activationStatement(role: .auditCheckpoint, generation: first.generation, reason: "bootstrap", challengeID: "audit-bootstrap", continuity: .bootstrap)
    _ = try coordinator.activateServiceKey(statement: bootstrap, approvalSignature: approval.sign(message: bootstrap.canonicalData()), approvalPublicKeyX963: approval.publicKeyX963)
    let second = try coordinator.stageServiceKey(role: .auditCheckpoint)
    let rotation = try coordinator.activationStatement(role: .auditCheckpoint, generation: second.generation, reason: "rotation", challengeID: "audit-rotation")
    _ = try coordinator.activateServiceKey(statement: rotation, approvalSignature: approval.sign(message: rotation.canonicalData()), approvalPublicKeyX963: approval.publicKeyX963)
    clock.set(verified)
    let head = try store.verify().headHash
    let proof = NativeLifecycleDeletionProof(
        lifecycleHeadHash: head,
        transitionReceiptHash: String(repeating: "a", count: 64),
        transitionArchivedAt: ISO8601DateFormatter.coordinatorString(archived),
        verifiedAt: ISO8601DateFormatter.coordinatorString(verified)
    )
    if swapAfterAcquire {
        let before = try store.verify()
        #expect(throws: AgentPassNativeError.self) {
            let statement = try coordinator.deletionStatement(
                role: .auditCheckpoint, generation: first.generation, reason: "retention",
                challengeID: "delete-audit-1", minimumRetirementAgeSeconds: 2_592_000, proof: proof
            )
            try coordinator.deleteRetiredServiceKey(
                role: .auditCheckpoint, generation: first.generation, reason: "retention",
                challengeID: "delete-audit-1", minimumRetirementAgeSeconds: 2_592_000, proof: proof,
                approvalSignature: approval.sign(message: statement), approvalPublicKeyX963: approval.publicKeyX963
            )
        }
        #expect(try provider.exists(applicationTag: first.applicationTag))
        #expect(try store.verify() == before)
        #expect(try store.verify().generation(first.generation, for: .auditCheckpoint)?.status == .retired)
    } else {
        let statement = try coordinator.deletionStatement(
            role: .auditCheckpoint, generation: first.generation, reason: "retention",
            challengeID: "delete-audit-1", minimumRetirementAgeSeconds: 2_592_000, proof: proof
        )
        let result = try coordinator.deleteRetiredServiceKey(
            role: .auditCheckpoint, generation: first.generation, reason: "retention",
            challengeID: "delete-audit-1", minimumRetirementAgeSeconds: 2_592_000, proof: proof,
            approvalSignature: approval.sign(message: statement), approvalPublicKeyX963: approval.publicKeyX963
        )
        #expect(result.generation(first.generation, for: .auditCheckpoint)?.status == .deleted)
        #expect(try !provider.exists(applicationTag: first.applicationTag))
    }
}

@Test(arguments: [false, true])
func lifecycleCoordinatorRecoversAuditDeletionCrashFromExactSignedIntentBinding(replaceArchiveAncestorBeforeRecovery: Bool) throws {
    let root = try durableCoordinatorRoot(); defer { try? FileManager.default.removeItem(at: root) }
    let ledger = root.appendingPathComponent("ledger"), pins = root.appendingPathComponent("pins"), outboxRoot = root.appendingPathComponent("outbox")
    for directory in [ledger, pins, outboxRoot] { try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]) }
    let store = try NativeKeyLifecycleStore(directory: ledger.path)
    let pin = try NativeLifecyclePinTransaction(rootPath: pins.path)
    let outbox = try NativeLifecycleMutationOutbox(rootPath: outboxRoot.path)
    let provider = CoordinatorProvider(), approval = CoordinatorApproval()
    let start = Date(timeIntervalSince1970: 1_800_000_000)
    let archived = start.addingTimeInterval(40 * 86_400), verified = archived.addingTimeInterval(31 * 86_400)
    let clock = CoordinatorClock(start)
    try bootstrapDurableCoordinatorApproval(store, approval: approval, date: start, pin: pin, outbox: outbox)
    let retained = try coordinatorRetainedArchive(root: root)
    let verifier = CoordinatorLeasedDeletionVerifier(archivedAt: archived, verifiedAt: verified, archiveDirectory: retained.0.path, segment: retained.1, identities: retained.2, swapAfterAcquire: false)
    let coordinator = try NativeKeyLifecycleCoordinator(store: store, provider: provider, baseTags: [.gitSigning: "git", .auditCheckpoint: "audit", .sessionApproval: "approval"], deletionProofVerifier: verifier, pinTransaction: pin, mutationOutbox: outbox, now: { clock.get() })
    let first = try coordinator.stageServiceKey(role: .auditCheckpoint)
    let bootstrap = try coordinator.activationStatement(role: .auditCheckpoint, generation: first.generation, reason: "bootstrap", challengeID: "crash-audit-bootstrap", continuity: .bootstrap)
    _ = try coordinator.activateServiceKey(statement: bootstrap, approvalSignature: approval.sign(message: bootstrap.canonicalData()), approvalPublicKeyX963: approval.publicKeyX963)
    let second = try coordinator.stageServiceKey(role: .auditCheckpoint)
    let rotation = try coordinator.activationStatement(role: .auditCheckpoint, generation: second.generation, reason: "rotation", challengeID: "crash-audit-rotation")
    _ = try coordinator.activateServiceKey(statement: rotation, approvalSignature: approval.sign(message: rotation.canonicalData()), approvalPublicKeyX963: approval.publicKeyX963)
    clock.set(verified)
    let beforeIntent = try store.verify()
    let proof = NativeLifecycleDeletionProof(lifecycleHeadHash: beforeIntent.headHash, transitionReceiptHash: String(repeating: "a", count: 64), transitionArchivedAt: ISO8601DateFormatter.coordinatorString(archived), verifiedAt: ISO8601DateFormatter.coordinatorString(verified))
    let statement = try coordinator.deletionStatement(role: .auditCheckpoint, generation: first.generation, reason: "retention", challengeID: "crash-delete-audit", minimumRetirementAgeSeconds: 2_592_000, proof: proof)
    provider.interruptAfterNextDelete()
    #expect(throws: CoordinatorDeletionInterruption.self) {
        try coordinator.deleteRetiredServiceKey(role: .auditCheckpoint, generation: first.generation, reason: "retention", challengeID: "crash-delete-audit", minimumRetirementAgeSeconds: 2_592_000, proof: proof, approvalSignature: approval.sign(message: statement), approvalPublicKeyX963: approval.publicKeyX963)
    }
    let intentState = try store.verify()
    let intentTarget = try #require(intentState.generation(first.generation, for: .auditCheckpoint))
    #expect(intentTarget.status == .deletionIntent)
    #expect(intentTarget.auditDeletionBinding != nil)
    #expect(intentTarget.deletionIntentLifecycleHead == beforeIntent.headHash)
    #expect(try !provider.exists(applicationTag: first.applicationTag))
    #expect(try outbox.pending() == nil)
    #expect(try pin.pending() == nil)

    if replaceArchiveAncestorBeforeRecovery {
        let moved = root.appendingPathComponent("retained-archives-before-recovery", isDirectory: true)
        try FileManager.default.moveItem(at: retained.0, to: moved)
        try FileManager.default.createDirectory(at: retained.0, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        guard chmod(retained.0.path, 0o700) == 0 else { throw POSIXError(.EIO) }
        // Preserve all three file inodes while replacing only their ancestor directory. File
        // identity verification alone therefore succeeds; the signed path-chain hash must fail.
        for identity in retained.2 {
            try FileManager.default.moveItem(
                at: moved.appendingPathComponent(identity.name),
                to: retained.0.appendingPathComponent(identity.name)
            )
        }
    }

    let restarted = try NativeKeyLifecycleCoordinator(store: store, provider: provider, baseTags: [.gitSigning: "git", .auditCheckpoint: "audit", .sessionApproval: "approval"], deletionProofVerifier: verifier, pinTransaction: pin, mutationOutbox: outbox, now: { clock.get() })
    if replaceArchiveAncestorBeforeRecovery {
        #expect(throws: AgentPassNativeError.self) { try restarted.recoverKeychainSideEffects() }
        #expect(try store.verify().generation(first.generation, for: .auditCheckpoint)?.status == .deletionIntent)
        #expect(try !provider.exists(applicationTag: first.applicationTag))
        return
    }
    let recovered = try restarted.recoverKeychainSideEffects()
    #expect(recovered.generation(first.generation, for: .auditCheckpoint)?.status == .deleted)
    #expect(recovered.active(for: .auditCheckpoint)?.generation == second.generation)
    #expect(try !provider.exists(applicationTag: first.applicationTag))
    #expect(try outbox.current()?.kind == .deleted)
    #expect(try pin.current()?.action == .deleted)
}

@Test func lifecycleCoordinatorCleansUnstagedCreatedKeysAndRejectsUnverifiedDeletion() throws {
    let root = try coordinatorRoot(); defer { try? FileManager.default.removeItem(at: root) }
    let store = try NativeKeyLifecycleStore(directory: root.path)
    let provider = CoordinatorProvider()
    let coordinator = try NativeKeyLifecycleCoordinator(store: store, provider: provider, baseTags: [.gitSigning: "git", .auditCheckpoint: "audit", .sessionApproval: "approval"])
    #expect(throws: AgentPassNativeError.self) { try coordinator.stageServiceKey(role: .gitSigning) }
    #expect(try !provider.exists(applicationTag: "git.g1"))
}

@Test func lifecycleCoordinatorRotatesClientOwnedApprovalKeysWithTwoProofs() throws {
    let root = try coordinatorRoot(); defer { try? FileManager.default.removeItem(at: root) }
    let store = try NativeKeyLifecycleStore(directory: root.path)
    let provider = CoordinatorProvider()
    let oldApproval = CoordinatorApproval()
    let newApproval = CoordinatorApproval()
    let start = Date(timeIntervalSince1970: 1_800_000_000)
    try bootstrapCoordinatorApproval(store, approval: oldApproval, date: start)
    let coordinator = try NativeKeyLifecycleCoordinator(store: store, provider: provider, baseTags: [.gitSigning: "git", .auditCheckpoint: "audit", .sessionApproval: "approval"], now: { start.addingTimeInterval(1) })

    let plan = try coordinator.approvalKeyStagePlan()
    #expect(plan.generation == 2)
    #expect(plan.applicationTag == "approval.g2")
    let staged = try coordinator.stageApprovalKey(generation: plan.generation, applicationTag: plan.applicationTag, publicKeyX963: newApproval.publicKeyX963)
    #expect(staged.fingerprint == NativeKeyLifecycleStore.fingerprint(newApproval.publicKeyX963))
    let statement = try coordinator.activationStatement(role: .sessionApproval, generation: 2, reason: "approval rotation", challengeID: "approval-rotation")
    let message = try statement.canonicalData()
    let final = try coordinator.activateApprovalKey(statement: statement, oldApprovalSignature: oldApproval.sign(message: message), newApprovalSignature: newApproval.sign(message: message), oldApprovalPublicKeyX963: oldApproval.publicKeyX963)
    #expect(final.active(for: .sessionApproval)?.generation == 2)
    #expect(final.generation(1, for: .sessionApproval)?.status == .retired)

    #expect(throws: AgentPassNativeError.self) {
        try coordinator.activateApprovalKey(statement: statement, oldApprovalSignature: newApproval.sign(message: message), newApprovalSignature: newApproval.sign(message: message), oldApprovalPublicKeyX963: oldApproval.publicKeyX963)
    }
}

@Test func lifecycleCoordinatorAuthorizesAbortsBeforeExactKeyDeletionAndResumesCrashes() throws {
    let root = try coordinatorRoot(); defer { try? FileManager.default.removeItem(at: root) }
    let store = try NativeKeyLifecycleStore(directory: root.path)
    let provider = CoordinatorProvider()
    let approval = CoordinatorApproval()
    let start = Date(timeIntervalSince1970: 1_800_000_000)
    let clock = CoordinatorClock(start)
    try bootstrapCoordinatorApproval(store, approval: approval, date: start)
    let coordinator = try NativeKeyLifecycleCoordinator(store: store, provider: provider, baseTags: [.gitSigning: "git", .auditCheckpoint: "audit", .sessionApproval: "approval"], now: { clock.get() })

    let staged = try coordinator.stageServiceKey(role: .gitSigning)
    let pinnedHead = try store.verify().headHash
    let statement = try coordinator.abortStatement(role: .gitSigning, generation: staged.generation, reason: "operator cancelled", challengeID: "abort-git-1", externallyPinnedHeadHash: pinnedHead)
    let aborted = try coordinator.abortStagedServiceKey(role: .gitSigning, generation: staged.generation, reason: "operator cancelled", challengeID: "abort-git-1", externallyPinnedHeadHash: pinnedHead, approvalSignature: approval.sign(message: statement), approvalPublicKeyX963: approval.publicKeyX963)
    #expect(aborted.generation(1, for: .gitSigning)?.status == .aborted)
    #expect(try !provider.exists(applicationTag: "git.g1"))
    #expect(try coordinator.stageServiceKey(role: .gitSigning).applicationTag == "git.g2")

    let audit = try coordinator.stageServiceKey(role: .auditCheckpoint)
    let auditHead = try store.verify().headHash
    let auditStatement = try coordinator.abortStatement(role: .auditCheckpoint, generation: audit.generation, reason: "crash repair", challengeID: "abort-audit-1", externallyPinnedHeadHash: auditHead)
    _ = try store.recordAbortIntent(role: .auditCheckpoint, generation: audit.generation, reason: "crash repair", challengeID: "abort-audit-1", createdAt: ISO8601DateFormatter.coordinatorString(start), approvalSignature: approval.sign(message: auditStatement), approvalPublicKeyX963: approval.publicKeyX963, externallyPinnedHeadHash: auditHead)
    let repaired = try coordinator.resumeRecordedAbort(role: .auditCheckpoint, generation: audit.generation)
    #expect(repaired.generation(1, for: .auditCheckpoint)?.status == .aborted)
    #expect(try !provider.exists(applicationTag: "audit.g1"))
}

@Test func lifecycleCoordinatorPreparesExternalPinBeforeStageAndActivation() throws {
    let testParent = URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent(".build")
    guard let canonicalParent = Darwin.realpath(testParent.path, nil) else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    defer { free(canonicalParent) }
    let root = URL(fileURLWithPath: String(cString: canonicalParent)).appendingPathComponent("coordinator-pin-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let ledger = root.appendingPathComponent("ledger")
    let pins = root.appendingPathComponent("pins")
    try FileManager.default.createDirectory(at: ledger, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    try FileManager.default.createDirectory(at: pins, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    let store = try NativeKeyLifecycleStore(directory: ledger.path)
    let pin = try NativeLifecyclePinTransaction(rootPath: pins.path)
    let provider = CoordinatorProvider()
    let approval = CoordinatorApproval()
    let start = Date(timeIntervalSince1970: 1_800_000_000)

    // Bootstrap approval directly because this test targets service-key coordinator pin ordering.
    try bootstrapCoordinatorApproval(store, approval: approval, date: start)
    let coordinator = try NativeKeyLifecycleCoordinator(store: store, provider: provider, baseTags: [.gitSigning: "git", .auditCheckpoint: "audit", .sessionApproval: "approval"], pinTransaction: pin, now: { start })
    let staged = try coordinator.stageServiceKey(role: .gitSigning)
    #expect(try pin.current()?.newLifecycleHead == staged.lifecycleHeadHash)
    #expect(try pin.pending() == nil)

    let statement = try coordinator.activationStatement(role: .gitSigning, generation: staged.generation, reason: "pin test", challengeID: "pin-activate", continuity: .bootstrap)
    let previewBox = CoordinatorPreviewBox()
    let activated = try coordinator.activateServiceKey(statement: statement, approvalSignature: approval.sign(message: statement.canonicalData()), approvalPublicKeyX963: approval.publicKeyX963) { preview in
        let pendingPin = try pin.pending()
        let observed = try store.verify()
        #expect(pendingPin == nil)
        #expect(observed.headHash == staged.lifecycleHeadHash)
        previewBox.set(preview)
    }
    let preview = try #require(previewBox.get())
    let replacement = try provider.load(applicationTag: staged.applicationTag)
    #expect(preview.lifecycleHeadHash == activated.headHash)
    #expect(preview.replacementPublicKeyX963 == replacement.publicKeyX963)
    #expect((try JSONSerialization.jsonObject(with: preview.canonicalLifecycleRecord) as? [String: Any])?["record_hash"] as? String == activated.headHash)
    #expect(try pin.current()?.sequence == 2)
    #expect(try pin.current()?.newLifecycleHead == activated.headHash)
    #expect(try pin.pending() == nil)
}

@Test func lifecycleCoordinatorPreCommitGateFailureLeavesLedgerPinAndOutboxUnchanged() throws {
    let testParent = URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent(".build")
    guard let canonicalParent = Darwin.realpath(testParent.path, nil) else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    defer { free(canonicalParent) }
    let root = URL(fileURLWithPath: String(cString: canonicalParent)).appendingPathComponent("coordinator-gate-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let ledger = root.appendingPathComponent("ledger"), pins = root.appendingPathComponent("pins"), outboxRoot = root.appendingPathComponent("outbox")
    for directory in [ledger, pins, outboxRoot] { try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]) }
    let store = try NativeKeyLifecycleStore(directory: ledger.path)
    let pin = try NativeLifecyclePinTransaction(rootPath: pins.path)
    let outbox = try NativeLifecycleMutationOutbox(rootPath: outboxRoot.path)
    let provider = CoordinatorProvider(), approval = CoordinatorApproval()
    let start = Date(timeIntervalSince1970: 1_800_000_000)
    try bootstrapCoordinatorApproval(store, approval: approval, date: start)
    // Join after the direct two-record approval bootstrap.
    let bootstrapHead = try store.verify().headHash
    let bootstrapMarker = try pin.prepare(operationID: UUID(), sequence: 1, role: .sessionApproval, action: .activated, oldLifecycleHead: NativeKeyLifecycleStore.zeroHash, newLifecycleHead: bootstrapHead, preparedAt: ISO8601DateFormatter.coordinatorString(start))
    _ = try pin.commit(bootstrapMarker, observedOldLifecycleHead: NativeKeyLifecycleStore.zeroHash, observedNewLifecycleHead: bootstrapHead)
    let coordinator = try NativeKeyLifecycleCoordinator(store: store, provider: provider, baseTags: [.gitSigning: "git", .auditCheckpoint: "audit", .sessionApproval: "approval"], pinTransaction: pin, mutationOutbox: outbox, now: { start })
    let staged = try coordinator.stageServiceKey(role: .auditCheckpoint)
    let statement = try coordinator.activationStatement(role: .auditCheckpoint, generation: staged.generation, reason: "gate", challengeID: "gate-failure", continuity: .bootstrap)
    let before = try store.verify()
    #expect(throws: AgentPassNativeError.self) {
        try coordinator.activateServiceKey(statement: statement, approvalSignature: approval.sign(message: statement.canonicalData()), approvalPublicKeyX963: approval.publicKeyX963) { _ in
            throw AgentPassNativeError.invalidSignature("anchor unavailable")
        }
    }
    #expect(try store.verify() == before)
    #expect(try pin.pending() == nil)
    #expect(try outbox.pending() == nil)
}

@Test func lifecycleCoordinatorReplaysByteExactOutboxAcrossStageAndSignedActivationCrashes() throws {
    let testParent = URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent(".build")
    guard let canonicalParent = Darwin.realpath(testParent.path, nil) else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    defer { free(canonicalParent) }
    let root = URL(fileURLWithPath: String(cString: canonicalParent)).appendingPathComponent("coordinator-outbox-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let ledger = root.appendingPathComponent("ledger")
    let pins = root.appendingPathComponent("pins")
    let outboxRoot = root.appendingPathComponent("outbox")
    for directory in [ledger, pins, outboxRoot] {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    }
    let store = try NativeKeyLifecycleStore(directory: ledger.path)
    let pin = try NativeLifecyclePinTransaction(rootPath: pins.path)
    let outbox = try NativeLifecycleMutationOutbox(rootPath: outboxRoot.path)
    let approval = CoordinatorApproval()
    let provider = CoordinatorProvider()
    let start = Date(timeIntervalSince1970: 1_800_000_000)
    let timestamp = ISO8601DateFormatter.coordinatorString(start)

    let stagePayload = try store.prepareStageRecordData(role: .sessionApproval, generation: 1, applicationTag: "approval.g1", publicKeyX963: approval.publicKeyX963, createdAt: timestamp)
    let stageHead = try #require((JSONSerialization.jsonObject(with: stagePayload) as? [String: Any])?["record_hash"] as? String)
    let stageOperation = UUID()
    _ = try outbox.prepare(operationID: stageOperation, pinSequence: 1, role: .sessionApproval, kind: .staged, lifecycleSequence: 1, oldLifecycleHead: NativeKeyLifecycleStore.zeroHash, newLifecycleHead: stageHead, createdAt: timestamp, payload: stagePayload)
    _ = try pin.prepare(operationID: stageOperation, sequence: 1, role: .sessionApproval, action: .staged, oldLifecycleHead: NativeKeyLifecycleStore.zeroHash, newLifecycleHead: stageHead, preparedAt: timestamp)

    _ = try NativeKeyLifecycleCoordinator(store: store, provider: provider, baseTags: [.gitSigning: "git", .auditCheckpoint: "audit", .sessionApproval: "approval"], pinTransaction: pin, mutationOutbox: outbox, now: { start })
    #expect(try store.verify().headHash == stageHead)
    #expect(try pin.current()?.newLifecycleHead == stageHead)
    #expect(try outbox.pending() == nil)

    let statement = try store.transitionStatement(role: .sessionApproval, generation: 1, reason: "bootstrap", challengeID: "outbox-bootstrap", createdAt: timestamp, continuity: .bootstrap)
    let message = try statement.canonicalData()
    let signature = try approval.sign(message: message)
    let activationPayload = try store.prepareActivationRecordData(statement: statement, oldSignature: nil, newSignature: signature, approvalSignature: signature, approvalPublicKeyX963: approval.publicKeyX963)
    let activationHead = try #require((JSONSerialization.jsonObject(with: activationPayload) as? [String: Any])?["record_hash"] as? String)
    let activationOperation = UUID()
    _ = try outbox.prepare(operationID: activationOperation, pinSequence: 2, role: .sessionApproval, kind: .activated, lifecycleSequence: 2, oldLifecycleHead: stageHead, newLifecycleHead: activationHead, createdAt: timestamp, payload: activationPayload)
    // Simulate a crash after outbox.prepare but before pin.prepare. Startup must recreate the
    // exact pin, replay the already signed bytes, and complete both durable transactions.
    let coordinator = try NativeKeyLifecycleCoordinator(store: store, provider: provider, baseTags: [.gitSigning: "git", .auditCheckpoint: "audit", .sessionApproval: "approval"], pinTransaction: pin, mutationOutbox: outbox, now: { start.addingTimeInterval(100) })
    let final = try store.verify()
    #expect(final.headHash == activationHead)
    #expect(final.active(for: .sessionApproval)?.publicKeyX963 == approval.publicKeyX963)
    #expect(try pin.current()?.sequence == 2)
    #expect(try outbox.current()?.payload == activationPayload)
    #expect(try outbox.pending() == nil)

    let audit = try coordinator.stageServiceKey(role: .auditCheckpoint)
    let pinnedHead = try store.verify().headHash
    let abortData = try coordinator.abortStatement(role: .auditCheckpoint, generation: audit.generation, reason: "cancel staged audit", challengeID: "outbox-abort", externallyPinnedHeadHash: pinnedHead)
    let aborted = try coordinator.abortStagedServiceKey(role: .auditCheckpoint, generation: audit.generation, reason: "cancel staged audit", challengeID: "outbox-abort", externallyPinnedHeadHash: pinnedHead, approvalSignature: approval.sign(message: abortData), approvalPublicKeyX963: approval.publicKeyX963)
    #expect(aborted.generation(audit.generation, for: .auditCheckpoint)?.status == .aborted)
    #expect(try pin.current()?.sequence == 5)
    #expect(try outbox.current()?.kind == .aborted)
    #expect(try outbox.pending() == nil)
}

@Test func lifecycleCoordinatorCommitsExactExternallyAuthorizedAuditActivationAfterRestartBoundary() throws {
    let root = try durableCoordinatorRoot(); defer { try? FileManager.default.removeItem(at: root) }
    let ledger = root.appendingPathComponent("ledger"), pins = root.appendingPathComponent("pins"), outboxRoot = root.appendingPathComponent("outbox")
    for directory in [ledger, pins, outboxRoot] { try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]) }
    let store = try NativeKeyLifecycleStore(directory: ledger.path)
    let pin = try NativeLifecyclePinTransaction(rootPath: pins.path)
    let outbox = try NativeLifecycleMutationOutbox(rootPath: outboxRoot.path)
    let provider = CoordinatorProvider(), approval = CoordinatorApproval()
    let start = Date(timeIntervalSince1970: 1_800_000_000)
    try bootstrapDurableCoordinatorApproval(store, approval: approval, date: start, pin: pin, outbox: outbox)
    let coordinator = try NativeKeyLifecycleCoordinator(store: store, provider: provider, baseTags: [.gitSigning: "git", .auditCheckpoint: "audit", .sessionApproval: "approval"], pinTransaction: pin, mutationOutbox: outbox, now: { start })
    let staged = try coordinator.stageServiceKey(role: .auditCheckpoint)
    let statement = try coordinator.activationStatement(role: .auditCheckpoint, generation: staged.generation, reason: "externally anchored activation", challengeID: "authorized-audit-recovery", continuity: .bootstrap)
    let preview = CoordinatorPreviewBox()
    #expect(throws: CoordinatorGateInterruption.self) {
        try coordinator.activateServiceKey(statement: statement, approvalSignature: approval.sign(message: statement.canonicalData()), approvalPublicKeyX963: approval.publicKeyX963) {
            preview.set($0)
            throw CoordinatorGateInterruption.afterExactPreview
        }
    }
    let exact = try #require(preview.get())
    #expect(try store.verify().headHash == statement.previousLifecycleHead)
    #expect(try outbox.pending() == nil)
    #expect(try pin.pending() == nil)

    let recovered = try coordinator.commitAuthorizedAuditActivationRecord(exact.canonicalLifecycleRecord)
    #expect(recovered.headHash == exact.lifecycleHeadHash)
    #expect(recovered.active(for: .auditCheckpoint)?.generation == staged.generation)
    #expect(try outbox.current()?.payload == exact.canonicalLifecycleRecord)
    #expect(try pin.current()?.newLifecycleHead == exact.lifecycleHeadHash)
}

@Test func lifecycleCoordinatorRecoversAuthorizedAbortKeychainSideEffectExactlyOnce() throws {
    let root = try durableCoordinatorRoot(); defer { try? FileManager.default.removeItem(at: root) }
    let ledger = root.appendingPathComponent("ledger"), pins = root.appendingPathComponent("pins"), outboxRoot = root.appendingPathComponent("outbox")
    for directory in [ledger, pins, outboxRoot] { try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]) }
    let store = try NativeKeyLifecycleStore(directory: ledger.path)
    let pin = try NativeLifecyclePinTransaction(rootPath: pins.path)
    let outbox = try NativeLifecycleMutationOutbox(rootPath: outboxRoot.path)
    let provider = CoordinatorProvider(), approval = CoordinatorApproval()
    let start = Date(timeIntervalSince1970: 1_800_000_000)
    let clock = CoordinatorClock(start)
    let timestamp = ISO8601DateFormatter.coordinatorString(start)
    try bootstrapDurableCoordinatorApproval(store, approval: approval, date: start, pin: pin, outbox: outbox)
    let coordinator = try NativeKeyLifecycleCoordinator(store: store, provider: provider, baseTags: [.gitSigning: "git", .auditCheckpoint: "audit", .sessionApproval: "approval"], pinTransaction: pin, mutationOutbox: outbox, now: { clock.get() })
    let staged = try coordinator.stageServiceKey(role: .auditCheckpoint)
    let stagedState = try store.verify()
    let statement = try store.abortStatement(role: .auditCheckpoint, generation: staged.generation, reason: "startup recovery", challengeID: "recover-abort", createdAt: timestamp, externallyPinnedHeadHash: stagedState.headHash)
    let intent = try store.prepareAbortIntentRecordData(role: .auditCheckpoint, generation: staged.generation, reason: "startup recovery", challengeID: "recover-abort", createdAt: timestamp, approvalSignature: approval.sign(message: statement), approvalPublicKeyX963: approval.publicKeyX963, externallyPinnedHeadHash: stagedState.headHash)
    let intentState = try appendDurableCoordinatorRecord(intent, role: .auditCheckpoint, kind: .abortIntent, createdAt: timestamp, store: store, pin: pin, outbox: outbox)

    // Simulate interruption after the exact key was removed but before the terminal payload could
    // be prepared. A retry must accept absence only because the verified abort intent remains.
    clock.set(start.addingTimeInterval(-1))
    #expect(throws: AgentPassNativeError.self) { try coordinator.recoverKeychainSideEffects() }
    #expect(try !provider.exists(applicationTag: staged.applicationTag))
    #expect(try store.verify() == intentState)
    #expect(try outbox.pending() == nil)
    #expect(try pin.pending() == nil)
    clock.set(start)

    let recovered = try coordinator.recoverKeychainSideEffects()
    #expect(recovered.generation(staged.generation, for: .auditCheckpoint)?.status == .aborted)
    #expect(try !provider.exists(applicationTag: staged.applicationTag))
    #expect(try outbox.current()?.kind == .aborted)
    #expect(try pin.current()?.action == .aborted)
    #expect(try outbox.pending() == nil)
    #expect(try pin.pending() == nil)

    let repeated = try coordinator.recoverKeychainSideEffects()
    #expect(repeated == recovered)
    #expect(try outbox.current()?.lifecycleSequence == recovered.sequence)
}

@Test func lifecycleCoordinatorRecoversDeletionIntentEvenWhenExactRetiredKeyStillExists() throws {
    let root = try durableCoordinatorRoot(); defer { try? FileManager.default.removeItem(at: root) }
    let ledger = root.appendingPathComponent("ledger"), pins = root.appendingPathComponent("pins"), outboxRoot = root.appendingPathComponent("outbox")
    for directory in [ledger, pins, outboxRoot] { try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]) }
    let store = try NativeKeyLifecycleStore(directory: ledger.path)
    let pin = try NativeLifecyclePinTransaction(rootPath: pins.path)
    let outbox = try NativeLifecycleMutationOutbox(rootPath: outboxRoot.path)
    let provider = CoordinatorProvider(), approval = CoordinatorApproval()
    let start = Date(timeIntervalSince1970: 1_800_000_000)
    let deletionDate = start.addingTimeInterval(31 * 86_400)
    let clock = CoordinatorClock(start)
    try bootstrapDurableCoordinatorApproval(store, approval: approval, date: start, pin: pin, outbox: outbox)
    let coordinator = try NativeKeyLifecycleCoordinator(store: store, provider: provider, baseTags: [.gitSigning: "git", .auditCheckpoint: "audit", .sessionApproval: "approval"], pinTransaction: pin, mutationOutbox: outbox, now: { clock.get() })
    let first = try coordinator.stageServiceKey(role: .gitSigning)
    let bootstrap = try coordinator.activationStatement(role: .gitSigning, generation: first.generation, reason: "bootstrap", challengeID: "recover-delete-bootstrap", continuity: .bootstrap)
    _ = try coordinator.activateServiceKey(statement: bootstrap, approvalSignature: approval.sign(message: bootstrap.canonicalData()), approvalPublicKeyX963: approval.publicKeyX963)
    let second = try coordinator.stageServiceKey(role: .gitSigning)
    let rotation = try coordinator.activationStatement(role: .gitSigning, generation: second.generation, reason: "rotation", challengeID: "recover-delete-rotation")
    _ = try coordinator.activateServiceKey(statement: rotation, approvalSignature: approval.sign(message: rotation.canonicalData()), approvalPublicKeyX963: approval.publicKeyX963)

    clock.set(deletionDate)
    let timestamp = ISO8601DateFormatter.coordinatorString(deletionDate)
    let retiredState = try store.verify()
    let statement = try store.deletionStatement(role: .gitSigning, generation: first.generation, reason: "retention elapsed", challengeID: "recover-delete", createdAt: timestamp, minimumRetirementAgeSeconds: 2_592_000, transitionArchived: true, externallyPinnedHeadHash: retiredState.headHash)
    let intent = try store.prepareDeletionIntentRecordData(role: .gitSigning, generation: first.generation, reason: "retention elapsed", challengeID: "recover-delete", createdAt: timestamp, approvalSignature: approval.sign(message: statement), approvalPublicKeyX963: approval.publicKeyX963, minimumRetirementAgeSeconds: 2_592_000, transitionArchived: true, externallyPinnedHeadHash: retiredState.headHash)
    _ = try appendDurableCoordinatorRecord(intent, role: .gitSigning, kind: .deletionIntent, createdAt: timestamp, store: store, pin: pin, outbox: outbox)
    #expect(try provider.exists(applicationTag: first.applicationTag))

    let recovered = try coordinator.recoverKeychainSideEffects()
    #expect(recovered.generation(first.generation, for: .gitSigning)?.status == .deleted)
    #expect(recovered.active(for: .gitSigning)?.generation == second.generation)
    #expect(try !provider.exists(applicationTag: first.applicationTag))
    #expect(try outbox.current()?.kind == .deleted)
    #expect(try pin.current()?.action == .deleted)
}

@Test func lifecycleCoordinatorSideEffectRecoveryFailsClosedOnSubstitutedOrAmbiguousTarget() throws {
    let root = try durableCoordinatorRoot(); defer { try? FileManager.default.removeItem(at: root) }
    let ledger = root.appendingPathComponent("ledger"), pins = root.appendingPathComponent("pins"), outboxRoot = root.appendingPathComponent("outbox")
    for directory in [ledger, pins, outboxRoot] { try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]) }
    let store = try NativeKeyLifecycleStore(directory: ledger.path)
    let pin = try NativeLifecyclePinTransaction(rootPath: pins.path)
    let outbox = try NativeLifecycleMutationOutbox(rootPath: outboxRoot.path)
    let provider = CoordinatorProvider(), approval = CoordinatorApproval()
    let start = Date(timeIntervalSince1970: 1_800_000_000)
    let timestamp = ISO8601DateFormatter.coordinatorString(start)
    try bootstrapDurableCoordinatorApproval(store, approval: approval, date: start, pin: pin, outbox: outbox)
    let coordinator = try NativeKeyLifecycleCoordinator(store: store, provider: provider, baseTags: [.gitSigning: "git", .auditCheckpoint: "audit", .sessionApproval: "approval"], pinTransaction: pin, mutationOutbox: outbox, now: { start })
    let staged = try coordinator.stageServiceKey(role: .gitSigning)
    let stagedState = try store.verify()
    let statement = try store.abortStatement(role: .gitSigning, generation: staged.generation, reason: "substitution test", challengeID: "recover-substitution", createdAt: timestamp, externallyPinnedHeadHash: stagedState.headHash)
    let intent = try store.prepareAbortIntentRecordData(role: .gitSigning, generation: staged.generation, reason: "substitution test", challengeID: "recover-substitution", createdAt: timestamp, approvalSignature: approval.sign(message: statement), approvalPublicKeyX963: approval.publicKeyX963, externallyPinnedHeadHash: stagedState.headHash)
    let intentState = try appendDurableCoordinatorRecord(intent, role: .gitSigning, kind: .abortIntent, createdAt: timestamp, store: store, pin: pin, outbox: outbox)
    let committedPin = try pin.current()
    let replacement = provider.substitute(applicationTag: staged.applicationTag)
    #expect(replacement.publicKeyX963 != stagedState.generation(staged.generation, for: .gitSigning)?.publicKeyX963)

    #expect(throws: AgentPassNativeError.self) { try coordinator.recoverKeychainSideEffects() }
    #expect(try store.verify() == intentState)
    #expect(try provider.load(applicationTag: staged.applicationTag).publicKeyX963 == replacement.publicKeyX963)
    #expect(try pin.current() == committedPin)
    #expect(try pin.pending() == nil)
    #expect(try outbox.pending() == nil)
}

private extension ISO8601DateFormatter {
    static func coordinatorString(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }
}
