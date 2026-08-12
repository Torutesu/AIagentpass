import CryptoKit
import Darwin
import Foundation
import Testing
@testable import AgentPassNativeCore

private struct MigrationSoftwareKey: Sendable {
    let privateKey = P256.Signing.PrivateKey()
    var publicKey: Data { privateKey.publicKey.x963Representation }
    func sign(_ data: Data) throws -> Data { try privateKey.signature(for: data).rawRepresentation }
}

private let migrationNow = Date(timeIntervalSince1970: 1_900_000_000)
private let migrationInitialHead = String(repeating: "0", count: 64)
private let migrationApprovalIdentity = NativeLegacyMigrationHelperIdentity(
    bundleID: "dev.agentpass.legacy-approval-migration",
    teamID: "TEAMID1234",
    codeDirectoryHash: String(repeating: "a", count: 40)
)
private let migrationServiceIdentity = NativeLegacyMigrationHelperIdentity(
    bundleID: "dev.agentpass.legacy-service-migration",
    teamID: "TEAMID1234",
    codeDirectoryHash: String(repeating: "b", count: 40)
)
private let migrationIdentities: [NativeKeyRole: NativeLegacyMigrationHelperIdentity] = [
    .sessionApproval: migrationApprovalIdentity,
    .gitSigning: migrationServiceIdentity,
    .auditCheckpoint: migrationServiceIdentity
]
private let migrationTargets: [NativeKeyRole: String] = [
    .sessionApproval: "TEAMID1234.dev.agentpass.approval-keys",
    .gitSigning: "TEAMID1234.dev.agentpass.service-keys",
    .auditCheckpoint: "TEAMID1234.dev.agentpass.service-keys"
]
private let migrationOldTags: [NativeKeyRole: String] = [
    .sessionApproval: "dev.agentpass.session-approval.v1",
    .gitSigning: "dev.agentpass.git-signing",
    .auditCheckpoint: "dev.agentpass.audit-checkpoint"
]
private let migrationNewTags: [NativeKeyRole: String] = [
    .sessionApproval: "dev.agentpass.session-approval.g1",
    .gitSigning: "dev.agentpass.git-signing.g1",
    .auditCheckpoint: "dev.agentpass.audit-checkpoint.g1"
]

private func migrationTimestamp(_ date: Date) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: date)
}

private func migrationCoordinator(history: [Data] = [], now: Date = migrationNow) throws -> NativeLegacyMigrationCoordinator {
    try NativeLegacyMigrationCoordinator(
        helperIdentities: migrationIdentities,
        sourceAccessGroup: "TEAMID1234.dev.agentpass.keys",
        targetAccessGroups: migrationTargets,
        expectedOldTags: migrationOldTags,
        expectedNewTags: migrationNewTags,
        appVersion: "0.17.0-migration.1",
        initialLifecycleHead: migrationInitialHead,
        historicalPublicKeysX963: history,
        now: { now }
    )
}

private func migrationPlan(role: NativeKeyRole, order: Int, head: String, old: MigrationSoftwareKey, new: MigrationSoftwareKey, operationID: UUID = UUID(), identity: NativeLegacyMigrationHelperIdentity? = nil, sourceGroup: String = "TEAMID1234.dev.agentpass.keys", targetGroup: String? = nil, issuedAt: Date = migrationNow.addingTimeInterval(-10), expiresAt: Date = migrationNow.addingTimeInterval(300)) -> NativeLegacyMigrationPlan {
    NativeLegacyMigrationPlan(
        operationID: operationID,
        nonce: "nonce-\(operationID.uuidString.lowercased())",
        role: role,
        roleOrder: order,
        sourceAccessGroup: sourceGroup,
        targetAccessGroup: targetGroup ?? migrationTargets[role]!,
        helperIdentity: identity ?? migrationIdentities[role]!,
        appVersion: "0.17.0-migration.1",
        initialLifecycleHead: migrationInitialHead,
        previousLifecycleHead: head,
        issuedAt: migrationTimestamp(issuedAt),
        expiresAt: migrationTimestamp(expiresAt),
        binding: .init(role: role, oldApplicationTag: migrationOldTags[role]!, newApplicationTag: migrationNewTags[role]!, oldPublicKeyX963: old.publicKey, newPublicKeyX963: new.publicKey)
    )
}

private func migrationProofs(plan: NativeLegacyMigrationPlan, old: MigrationSoftwareKey, replacement: MigrationSoftwareKey, approval: MigrationSoftwareKey) throws -> NativeLegacyMigrationProofs {
    try .init(
        oldRoleSignature: old.sign(plan.oldRoleSigningData()),
        replacementKeySignature: replacement.sign(plan.replacementProofData()),
        humanPresenceApprovalSignature: approval.sign(plan.humanPresenceApprovalData())
    )
}

private struct MigrationAdoptionEvidence {
    let manifestData: Data
    let receiptData: [Data]
    let replacements: [NativeKeyRole: MigrationSoftwareKey]
    let observed: [NativeLegacyMigrationObservedTargetKey]
}

private func completedMigrationAdoptionEvidence() throws -> MigrationAdoptionEvidence {
    let coordinator = try migrationCoordinator()
    let oldApproval = MigrationSoftwareKey(), newApproval = MigrationSoftwareKey()
    let oldGit = MigrationSoftwareKey(), newGit = MigrationSoftwareKey()
    let oldAudit = MigrationSoftwareKey(), newAudit = MigrationSoftwareKey()
    let approval = try commitApproval(coordinator, old: oldApproval, new: newApproval)
    let gitPlan = migrationPlan(role: .gitSigning, order: 2, head: approval.2.lifecycleHead, old: oldGit, new: newGit)
    let gitReceipt = try coordinator.commit(planData: gitPlan.canonicalData(), proofs: migrationProofs(plan: gitPlan, old: oldGit, replacement: newGit, approval: newApproval))
    let auditPlan = migrationPlan(role: .auditCheckpoint, order: 3, head: gitReceipt.lifecycleHead, old: oldAudit, new: newAudit)
    let auditReceipt = try coordinator.commit(planData: auditPlan.canonicalData(), proofs: migrationProofs(plan: auditPlan, old: oldAudit, replacement: newAudit, approval: newApproval))
    let unsigned = try coordinator.unsignedCompletionManifest(completedAt: migrationTimestamp(migrationNow))
    let manifest = try coordinator.complete(completedAt: unsigned.completedAt, approvalSignature: newApproval.sign(unsigned.unsignedCanonicalData()))
    let replacements: [NativeKeyRole: MigrationSoftwareKey] = [.sessionApproval: newApproval, .gitSigning: newGit, .auditCheckpoint: newAudit]
    let observed = NativeLegacyMigrationCoordinator.requiredOrder.map {
        NativeLegacyMigrationObservedTargetKey(role: $0, applicationTag: migrationNewTags[$0]!, publicKeyX963: replacements[$0]!.publicKey)
    }
    return .init(manifestData: try manifest.canonicalData(), receiptData: try [approval.2, gitReceipt, auditReceipt].map { try $0.canonicalData() }, replacements: replacements, observed: observed)
}

private struct MigrationAdoptionDurableState {
    let root: URL
    let ledger: URL
    let pin: URL
    let outbox: URL
    let store: NativeKeyLifecycleStore
    let pinTransaction: NativeLifecyclePinTransaction
    let mutationOutbox: NativeLifecycleMutationOutbox
}

private func migrationAdoptionDurableState(pinFault: @escaping @Sendable (NativeLifecyclePinCrashPoint) throws -> Void = { _ in }, outboxFault: @escaping @Sendable (NativeLifecycleMutationOutboxCrashPoint) throws -> Void = { _ in }) throws -> MigrationAdoptionDurableState {
    let testParent = URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent(".build")
    guard let canonicalParent = Darwin.realpath(testParent.path, nil) else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    defer { free(canonicalParent) }
    let root = URL(fileURLWithPath: String(cString: canonicalParent)).appendingPathComponent("agentpass-migration-adoption-\(UUID().uuidString)")
    let ledger = root.appendingPathComponent("ledger")
    let pin = root.appendingPathComponent("pin")
    let outbox = root.appendingPathComponent("outbox")
    for directory in [root, ledger, pin, outbox] {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }
    return try .init(root: root, ledger: ledger, pin: pin, outbox: outbox,
                     store: NativeKeyLifecycleStore(directory: ledger.path),
                     pinTransaction: NativeLifecyclePinTransaction(rootPath: pin.path, faultInjector: pinFault),
                     mutationOutbox: NativeLifecycleMutationOutbox(rootPath: outbox.path, faultInjector: outboxFault))
}

private func completedAdoptionPlan(evidence: MigrationAdoptionEvidence, state: MigrationAdoptionDurableState) throws -> NativeLegacyMigrationAdoptionPlan {
    let builder = try NativeLegacyMigrationAdoptionBuilder(store: state.store, pinTransaction: state.pinTransaction, mutationOutbox: state.mutationOutbox, completionManifestData: evidence.manifestData, receiptData: evidence.receiptData, observedTargetKeys: evidence.observed)
    while let request = try builder.nextSigningRequest() {
        let replacement = evidence.replacements[request.role]!
        let approval = evidence.replacements[.sessionApproval]!
        let entry = try builder.commit(request, signatures: .init(replacementSignature: replacement.sign(request.transitionStatementData), approvalSignature: approval.sign(request.transitionStatementData)))
        #expect(try NativeLegacyMigrationAdoptionEntry.decodeCanonical(entry.canonicalData()) == entry)
    }
    return try builder.finalize()
}

private enum MigrationInjectedCrash: Error { case stop }

private final class MigrationOneShotOutboxFault: @unchecked Sendable {
    private let lock = NSLock()
    private var fired = false
    func inject(_ point: NativeLifecycleMutationOutboxCrashPoint) throws {
        lock.lock(); defer { lock.unlock() }
        if !fired, case .afterPrepareRename = point {
            fired = true
            throw MigrationInjectedCrash.stop
        }
    }
}

private final class MigrationOneShotPinFault: @unchecked Sendable {
    private let lock = NSLock()
    private var fired = false
    func inject(_ point: NativeLifecyclePinCrashPoint) throws {
        lock.lock(); defer { lock.unlock() }
        if !fired, case .afterPinRename = point {
            fired = true
            throw MigrationInjectedCrash.stop
        }
    }
}

private func commitApproval(_ coordinator: NativeLegacyMigrationCoordinator, old: MigrationSoftwareKey, new: MigrationSoftwareKey, operationID: UUID = UUID()) throws -> (NativeLegacyMigrationPlan, NativeLegacyMigrationProofs, NativeLegacyMigrationReceipt) {
    let plan = migrationPlan(role: .sessionApproval, order: 1, head: migrationInitialHead, old: old, new: new, operationID: operationID)
    let proofs = try migrationProofs(plan: plan, old: old, replacement: new, approval: old)
    return (plan, proofs, try coordinator.commit(planData: plan.canonicalData(), proofs: proofs))
}

@Test func legacyMigrationCompletesApprovalFirstAndProducesVerifiableManifest() throws {
    let coordinator = try migrationCoordinator()
    let oldApproval = MigrationSoftwareKey(), newApproval = MigrationSoftwareKey()
    let oldGit = MigrationSoftwareKey(), newGit = MigrationSoftwareKey()
    let oldAudit = MigrationSoftwareKey(), newAudit = MigrationSoftwareKey()

    let approval = try commitApproval(coordinator, old: oldApproval, new: newApproval)
    #expect(approval.2.role == .sessionApproval)
    #expect(approval.0.binding.newApplicationTag == "dev.agentpass.session-approval.g1")
    #expect(approval.0.targetAccessGroup == "TEAMID1234.dev.agentpass.approval-keys")

    let gitPlan = migrationPlan(role: .gitSigning, order: 2, head: approval.2.lifecycleHead, old: oldGit, new: newGit)
    #expect(gitPlan.targetAccessGroup == "TEAMID1234.dev.agentpass.service-keys")
    let gitReceipt = try coordinator.commit(planData: gitPlan.canonicalData(), proofs: migrationProofs(plan: gitPlan, old: oldGit, replacement: newGit, approval: newApproval))
    let auditPlan = migrationPlan(role: .auditCheckpoint, order: 3, head: gitReceipt.lifecycleHead, old: oldAudit, new: newAudit)
    let auditReceipt = try coordinator.commit(planData: auditPlan.canonicalData(), proofs: migrationProofs(plan: auditPlan, old: oldAudit, replacement: newAudit, approval: newApproval))

    let unsigned = try coordinator.unsignedCompletionManifest(completedAt: migrationTimestamp(migrationNow))
    let manifest = try coordinator.complete(completedAt: unsigned.completedAt, approvalSignature: newApproval.sign(unsigned.unsignedCanonicalData()))
    let decoded = try NativeLegacyMigrationCompletionManifest.decodeCanonical(manifest.canonicalData())
    let receipts = [approval.2, gitReceipt, auditReceipt]
    try decoded.verify(receipts: receipts)
    #expect(try NativeLegacyMigrationReceipt.decodeCanonical(gitReceipt.canonicalData()) == gitReceipt)
    #expect(decoded.newLifecycleHead == auditReceipt.lifecycleHead)
    #expect(decoded.operationIDs.count == 3)
    #expect(decoded.roleReceiptHashes.count == 3)
    #expect(decoded.approvalPublicKeyX963 == newApproval.publicKey)
    #expect(decoded.newLifecycleHead != decoded.initialLifecycleHead)

    var forgedReceipt = try JSONSerialization.jsonObject(with: gitReceipt.canonicalData()) as! [String: Any]
    forgedReceipt["lifecycle_head"] = String(repeating: "f", count: 64)
    let forgedData = try NativeAuditLog.canonical(forgedReceipt)
    let forged = try NativeLegacyMigrationReceipt.decodeCanonical(forgedData)
    #expect(throws: AgentPassNativeError.self) { try decoded.verify(receipts: [approval.2, forged, auditReceipt]) }
}

@Test func legacyMigrationRejectsWrongOrderMutationsAndProofSubstitution() throws {
    let coordinator = try migrationCoordinator()
    let oldApproval = MigrationSoftwareKey(), newApproval = MigrationSoftwareKey()
    let oldGit = MigrationSoftwareKey(), newGit = MigrationSoftwareKey()
    let gitFirst = migrationPlan(role: .gitSigning, order: 1, head: migrationInitialHead, old: oldGit, new: newGit)
    #expect(throws: AgentPassNativeError.self) { try coordinator.validatePreparedPlan(gitFirst.canonicalData()) }

    let plan = migrationPlan(role: .sessionApproval, order: 1, head: migrationInitialHead, old: oldApproval, new: newApproval)
    let proofs = try migrationProofs(plan: plan, old: oldApproval, replacement: newApproval, approval: oldApproval)
    var object = try JSONSerialization.jsonObject(with: plan.canonicalData()) as! [String: Any]
    object["nonce"] = "mutated-nonce"
    let mutated = try NativeAuditLog.canonical(object)
    #expect(throws: AgentPassNativeError.self) { try coordinator.commit(planData: mutated, proofs: proofs) }

    let copiedProof = NativeLegacyMigrationProofs(oldRoleSignature: proofs.oldRoleSignature, replacementKeySignature: proofs.replacementKeySignature, humanPresenceApprovalSignature: proofs.oldRoleSignature)
    #expect(throws: AgentPassNativeError.self) { try coordinator.commit(planData: plan.canonicalData(), proofs: copiedProof) }
    var pretty = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
    pretty.append(0x0a)
    #expect(throws: AgentPassNativeError.self) { try NativeLegacyMigrationPlan.decodeCanonical(pretty) }
}

@Test func legacyMigrationBindsSourceTargetTeamAndHelperIdentity() throws {
    let coordinator = try migrationCoordinator()
    let old = MigrationSoftwareKey(), new = MigrationSoftwareKey()
    let wrongSource = migrationPlan(role: .sessionApproval, order: 1, head: migrationInitialHead, old: old, new: new, sourceGroup: "TEAMID1234.attacker.keys")
    #expect(throws: AgentPassNativeError.self) { try coordinator.validatePreparedPlan(wrongSource.canonicalData()) }
    let wrongTarget = migrationPlan(role: .sessionApproval, order: 1, head: migrationInitialHead, old: old, new: new, targetGroup: "TEAMID1234.dev.agentpass.service-keys")
    #expect(throws: AgentPassNativeError.self) { try coordinator.validatePreparedPlan(wrongTarget.canonicalData()) }
    let wrongTeam = NativeLegacyMigrationHelperIdentity(bundleID: migrationApprovalIdentity.bundleID, teamID: "EVILTEAM99", codeDirectoryHash: migrationApprovalIdentity.codeDirectoryHash)
    let substituted = migrationPlan(role: .sessionApproval, order: 1, head: migrationInitialHead, old: old, new: new, identity: wrongTeam)
    #expect(throws: AgentPassNativeError.self) { try coordinator.validatePreparedPlan(substituted.canonicalData()) }
    let wrongHelperRole = migrationPlan(role: .sessionApproval, order: 1, head: migrationInitialHead, old: old, new: new, identity: migrationServiceIdentity)
    #expect(throws: AgentPassNativeError.self) { try coordinator.validatePreparedPlan(wrongHelperRole.canonicalData()) }
    let wrongCDHash = NativeLegacyMigrationHelperIdentity(bundleID: migrationApprovalIdentity.bundleID, teamID: migrationApprovalIdentity.teamID, codeDirectoryHash: String(repeating: "f", count: 40))
    let substitutedBinary = migrationPlan(role: .sessionApproval, order: 1, head: migrationInitialHead, old: old, new: new, identity: wrongCDHash)
    #expect(throws: AgentPassNativeError.self) { try coordinator.validatePreparedPlan(substitutedBinary.canonicalData()) }
    var wrongTagObject = try JSONSerialization.jsonObject(with: migrationPlan(role: .sessionApproval, order: 1, head: migrationInitialHead, old: old, new: new).canonicalData()) as! [String: Any]
    wrongTagObject["new_application_tag"] = "dev.agentpass.attacker.g1"
    #expect(throws: AgentPassNativeError.self) { try coordinator.validatePreparedPlan(NativeAuditLog.canonical(wrongTagObject)) }
}

@Test func legacyMigrationRejectsExpiredPrematureAndOverlongPlans() throws {
    let coordinator = try migrationCoordinator()
    let old = MigrationSoftwareKey(), new = MigrationSoftwareKey()
    let expired = migrationPlan(role: .sessionApproval, order: 1, head: migrationInitialHead, old: old, new: new, issuedAt: migrationNow.addingTimeInterval(-600), expiresAt: migrationNow.addingTimeInterval(-1))
    #expect(throws: AgentPassNativeError.self) { try coordinator.validatePreparedPlan(expired.canonicalData()) }
    let premature = migrationPlan(role: .sessionApproval, order: 1, head: migrationInitialHead, old: old, new: new, issuedAt: migrationNow.addingTimeInterval(1), expiresAt: migrationNow.addingTimeInterval(60))
    #expect(throws: AgentPassNativeError.self) { try coordinator.validatePreparedPlan(premature.canonicalData()) }
    let overlong = migrationPlan(role: .sessionApproval, order: 1, head: migrationInitialHead, old: old, new: new, issuedAt: migrationNow.addingTimeInterval(-1), expiresAt: migrationNow.addingTimeInterval(3601))
    #expect(throws: AgentPassNativeError.self) { try coordinator.validatePreparedPlan(overlong.canonicalData()) }
}

@Test func legacyMigrationIsIdempotentAfterLostResponseAndRejectsUUIDReplay() throws {
    let coordinator = try migrationCoordinator()
    let old = MigrationSoftwareKey(), new = MigrationSoftwareKey(), operationID = UUID()
    let plan = migrationPlan(role: .sessionApproval, order: 1, head: migrationInitialHead, old: old, new: new, operationID: operationID)
    let proofs = try migrationProofs(plan: plan, old: old, replacement: new, approval: old)
    let first = try coordinator.commit(planData: plan.canonicalData(), proofs: proofs)
    // Simulate a lost response plus helper restart after expiry. The fsync'd canonical receipt
    // restores committed state without re-running the key operation or accepting a fresh plan.
    let restarted = try migrationCoordinator(now: migrationNow.addingTimeInterval(10_000))
    let restored = try restarted.restoreCommittedReceipt(first.canonicalData())
    let retried = try restarted.commit(planData: plan.canonicalData(), proofs: proofs)
    #expect(restored == first)
    #expect(retried == first)
    #expect(restarted.currentLifecycleHead == first.lifecycleHead)

    let replacement = MigrationSoftwareKey()
    let replay = migrationPlan(role: .sessionApproval, order: 1, head: migrationInitialHead, old: old, new: replacement, operationID: operationID)
    let replayProofs = try migrationProofs(plan: replay, old: old, replacement: replacement, approval: old)
    #expect(throws: AgentPassNativeError.self) { try restarted.commit(planData: replay.canonicalData(), proofs: replayProofs) }
}

@Test func legacyMigrationRejectsDuplicateAndHistoricalKeyReuse() throws {
    let coordinator = try migrationCoordinator()
    let oldApproval = MigrationSoftwareKey(), newApproval = MigrationSoftwareKey()
    let approval = try commitApproval(coordinator, old: oldApproval, new: newApproval)
    let oldGit = MigrationSoftwareKey()
    let duplicate = migrationPlan(role: .gitSigning, order: 2, head: approval.2.lifecycleHead, old: oldGit, new: newApproval)
    #expect(throws: AgentPassNativeError.self) { try coordinator.validatePreparedPlan(duplicate.canonicalData()) }
    let duplicateOld = migrationPlan(role: .gitSigning, order: 2, head: approval.2.lifecycleHead, old: oldApproval, new: MigrationSoftwareKey())
    #expect(throws: AgentPassNativeError.self) { try coordinator.validatePreparedPlan(duplicateOld.canonicalData()) }
    let uniqueGit = migrationPlan(role: .gitSigning, order: 2, head: approval.2.lifecycleHead, old: oldGit, new: MigrationSoftwareKey())
    var reusedNonce = try JSONSerialization.jsonObject(with: uniqueGit.canonicalData()) as! [String: Any]
    reusedNonce["nonce"] = approval.0.nonce
    #expect(throws: AgentPassNativeError.self) { try coordinator.validatePreparedPlan(NativeAuditLog.canonical(reusedNonce)) }

    let historical = MigrationSoftwareKey(), current = MigrationSoftwareKey()
    let rollbackCoordinator = try migrationCoordinator(history: [historical.publicKey])
    let rollback = migrationPlan(role: .sessionApproval, order: 1, head: migrationInitialHead, old: current, new: historical)
    #expect(throws: AgentPassNativeError.self) { try rollbackCoordinator.validatePreparedPlan(rollback.canonicalData()) }
}

@Test func legacyMigrationAdoptionProducesExactStoreRecordsAndConvergesAllDurableHeads() throws {
    let evidence = try completedMigrationAdoptionEvidence()
    let durable = try migrationAdoptionDurableState()
    defer { try? FileManager.default.removeItem(at: durable.root) }
    let plan = try completedAdoptionPlan(evidence: evidence, state: durable)
    let decoded = try NativeLegacyMigrationAdoptionPlan.decodeCanonical(plan.canonicalData())
    #expect(decoded == plan)
    #expect(decoded.entries.map(\.role) == [.sessionApproval, .gitSigning, .auditCheckpoint])
    #expect(decoded.initialLifecycleHead == NativeKeyLifecycleStore.zeroHash)
    #expect(decoded.finalLifecycleSequence == 6)

    let result = try decoded.execute(store: durable.store, pinTransaction: durable.pinTransaction, mutationOutbox: durable.mutationOutbox, observedTargetKeys: evidence.observed, completedAt: migrationTimestamp(migrationNow))
    #expect(try NativeLegacyMigrationAdoptionResult.decodeCanonical(result.canonicalData(), plan: decoded) == result)
    let state = try durable.store.verify(expectedHeadHash: decoded.finalLifecycleHead)
    #expect(result.finalLifecycleHead == decoded.finalLifecycleHead)
    #expect(state.sequence == 6)
    #expect(state.active(for: .sessionApproval)?.publicKeyX963 == evidence.replacements[.sessionApproval]!.publicKey)
    #expect(state.active(for: .gitSigning)?.publicKeyX963 == evidence.replacements[.gitSigning]!.publicKey)
    #expect(state.active(for: .auditCheckpoint)?.publicKeyX963 == evidence.replacements[.auditCheckpoint]!.publicKey)
    #expect(try durable.pinTransaction.current()?.sequence == 6)
    #expect(try durable.pinTransaction.current()?.newLifecycleHead == state.headHash)
    #expect(try durable.mutationOutbox.current()?.pinSequence == 6)
    #expect(try durable.mutationOutbox.current()?.payload == decoded.entries.last?.activationRecordData)

    // Lost response after every durable commit is safe: the exact plan returns the same result.
    let retried = try decoded.execute(store: durable.store, pinTransaction: durable.pinTransaction, mutationOutbox: durable.mutationOutbox, observedTargetKeys: evidence.observed, completedAt: migrationTimestamp(migrationNow))
    #expect(retried == result)
    var forgedResult = try JSONSerialization.jsonObject(with: result.canonicalData()) as! [String: Any]
    forgedResult["final_lifecycle_head"] = String(repeating: "f", count: 64)
    #expect(throws: AgentPassNativeError.self) { try NativeLegacyMigrationAdoptionResult.decodeCanonical(NativeAuditLog.canonical(forgedResult), plan: decoded) }
}

@Test func legacyMigrationAdoptionBuilderRestoresSignedPrefixAndRejectsEquivocation() throws {
    let evidence = try completedMigrationAdoptionEvidence()
    let durable = try migrationAdoptionDurableState()
    defer { try? FileManager.default.removeItem(at: durable.root) }
    let firstBuilder = try NativeLegacyMigrationAdoptionBuilder(store: durable.store, pinTransaction: durable.pinTransaction, mutationOutbox: durable.mutationOutbox, completionManifestData: evidence.manifestData, receiptData: evidence.receiptData, observedTargetKeys: evidence.observed)
    let nextRequest = try firstBuilder.nextSigningRequest()
    let request = try #require(nextRequest)
    let approval = evidence.replacements[.sessionApproval]!
    let entry = try firstBuilder.commit(request, signatures: .init(replacementSignature: approval.sign(request.transitionStatementData), approvalSignature: approval.sign(request.transitionStatementData)))

    let restarted = try NativeLegacyMigrationAdoptionBuilder(store: durable.store, pinTransaction: durable.pinTransaction, mutationOutbox: durable.mutationOutbox, completionManifestData: evidence.manifestData, receiptData: evidence.receiptData, observedTargetKeys: evidence.observed)
    #expect(try restarted.restoreCommittedEntry(entry.canonicalData()) == entry)
    #expect(try restarted.nextSigningRequest()?.role == .gitSigning)
    var forged = try JSONSerialization.jsonObject(with: entry.canonicalData()) as! [String: Any]
    forged["helper_cdhash"] = String(repeating: "f", count: 40)
    #expect(throws: AgentPassNativeError.self) { try restarted.restoreCommittedEntry(NativeAuditLog.canonical(forged)) }
}

@Test func legacyMigrationAdoptionRejectsOrphanSubstitutedAndNonPristineState() throws {
    let evidence = try completedMigrationAdoptionEvidence()
    let durable = try migrationAdoptionDurableState()
    defer { try? FileManager.default.removeItem(at: durable.root) }
    var substituted = evidence.observed
    substituted[1] = .init(role: .gitSigning, applicationTag: migrationNewTags[.gitSigning]!, publicKeyX963: MigrationSoftwareKey().publicKey)
    #expect(throws: AgentPassNativeError.self) {
        try NativeLegacyMigrationAdoptionBuilder(store: durable.store, pinTransaction: durable.pinTransaction, mutationOutbox: durable.mutationOutbox, completionManifestData: evidence.manifestData, receiptData: evidence.receiptData, observedTargetKeys: substituted)
    }
    #expect(throws: AgentPassNativeError.self) {
        try NativeLegacyMigrationAdoptionBuilder(store: durable.store, pinTransaction: durable.pinTransaction, mutationOutbox: durable.mutationOutbox, completionManifestData: evidence.manifestData, receiptData: Array(evidence.receiptData.dropLast()), observedTargetKeys: evidence.observed)
    }
    _ = try durable.store.stage(role: .sessionApproval, generation: 1, applicationTag: "attacker.g1", publicKeyX963: MigrationSoftwareKey().publicKey, createdAt: migrationTimestamp(migrationNow))
    #expect(throws: AgentPassNativeError.self) {
        try NativeLegacyMigrationAdoptionBuilder(store: durable.store, pinTransaction: durable.pinTransaction, mutationOutbox: durable.mutationOutbox, completionManifestData: evidence.manifestData, receiptData: evidence.receiptData, observedTargetKeys: evidence.observed)
    }

    let pending = try migrationAdoptionDurableState()
    defer { try? FileManager.default.removeItem(at: pending.root) }
    _ = try pending.mutationOutbox.prepare(operationID: UUID(), pinSequence: 1, role: .sessionApproval, kind: .staged, lifecycleSequence: 1, oldLifecycleHead: NativeKeyLifecycleStore.zeroHash, newLifecycleHead: String(repeating: "a", count: 64), createdAt: migrationTimestamp(migrationNow), payload: Data("pending".utf8))
    #expect(throws: AgentPassNativeError.self) {
        try NativeLegacyMigrationAdoptionBuilder(store: pending.store, pinTransaction: pending.pinTransaction, mutationOutbox: pending.mutationOutbox, completionManifestData: evidence.manifestData, receiptData: evidence.receiptData, observedTargetKeys: evidence.observed)
    }
}

@Test func legacyMigrationAdoptionRejectsCanonicalRecordAndHelperProofSubstitution() throws {
    let evidence = try completedMigrationAdoptionEvidence()
    let durable = try migrationAdoptionDurableState()
    defer { try? FileManager.default.removeItem(at: durable.root) }
    let plan = try completedAdoptionPlan(evidence: evidence, state: durable)
    var planObject = try JSONSerialization.jsonObject(with: plan.canonicalData()) as! [String: Any]
    var entryData = try #require(Data(base64Encoded: (planObject["entries"] as! [String])[1]))
    var entryObject = try JSONSerialization.jsonObject(with: entryData) as! [String: Any]
    entryObject["helper_bundle_id"] = NativeLegacyMigrationV017.approvalHelperBundleID
    entryData = try NativeAuditLog.canonical(entryObject)
    var entries = planObject["entries"] as! [String]
    entries[1] = entryData.base64EncodedString()
    planObject["entries"] = entries
    #expect(throws: AgentPassNativeError.self) { try NativeLegacyMigrationAdoptionPlan.decodeCanonical(NativeAuditLog.canonical(planObject)) }

    planObject = try JSONSerialization.jsonObject(with: plan.canonicalData()) as! [String: Any]
    entryData = try #require(Data(base64Encoded: (planObject["entries"] as! [String])[2]))
    entryObject = try JSONSerialization.jsonObject(with: entryData) as! [String: Any]
    var activationData = try #require(Data(base64Encoded: entryObject["activation_record"] as! String))
    var activation = try JSONSerialization.jsonObject(with: activationData) as! [String: Any]
    activation["approval_signature"] = Data(repeating: 0x41, count: 64).base64EncodedString()
    activationData = try NativeAuditLog.canonical(activation)
    entryObject["activation_record"] = activationData.base64EncodedString()
    entryData = try NativeAuditLog.canonical(entryObject)
    entries = planObject["entries"] as! [String]
    entries[2] = entryData.base64EncodedString()
    planObject["entries"] = entries
    #expect(throws: AgentPassNativeError.self) { try NativeLegacyMigrationAdoptionPlan.decodeCanonical(NativeAuditLog.canonical(planObject)) }
}

@Test func legacyMigrationAdoptionRecoversExactOutboxPreparationAfterCrash() throws {
    let evidence = try completedMigrationAdoptionEvidence()
    let normal = try migrationAdoptionDurableState()
    let plan = try completedAdoptionPlan(evidence: evidence, state: normal)
    try FileManager.default.removeItem(at: normal.root)

    let fault = MigrationOneShotOutboxFault()
    let crashing = try migrationAdoptionDurableState(outboxFault: fault.inject)
    let root = crashing.root, ledger = crashing.ledger, pin = crashing.pin, outbox = crashing.outbox
    #expect(throws: MigrationInjectedCrash.self) {
        try plan.execute(store: crashing.store, pinTransaction: crashing.pinTransaction, mutationOutbox: crashing.mutationOutbox, observedTargetKeys: evidence.observed, completedAt: migrationTimestamp(migrationNow))
    }
    #expect(try crashing.store.verify().sequence == 0)
    #expect(try crashing.mutationOutbox.pending()?.payload == plan.entries[0].stageRecordData)

    let restartedStore = try NativeKeyLifecycleStore(directory: ledger.path)
    let restartedPin = try NativeLifecyclePinTransaction(rootPath: pin.path)
    let restartedOutbox = try NativeLifecycleMutationOutbox(rootPath: outbox.path)
    let result = try plan.execute(store: restartedStore, pinTransaction: restartedPin, mutationOutbox: restartedOutbox, observedTargetKeys: evidence.observed, completedAt: migrationTimestamp(migrationNow))
    #expect(result.finalLifecycleSequence == 6)
    #expect(try restartedStore.verify().headHash == plan.finalLifecycleHead)
    try? FileManager.default.removeItem(at: root)
}

@Test func legacyMigrationAdoptionRecoversLedgerAndCommittedPinAfterLostResponse() throws {
    let evidence = try completedMigrationAdoptionEvidence()
    let normal = try migrationAdoptionDurableState()
    let plan = try completedAdoptionPlan(evidence: evidence, state: normal)
    try FileManager.default.removeItem(at: normal.root)

    let fault = MigrationOneShotPinFault()
    let crashing = try migrationAdoptionDurableState(pinFault: fault.inject)
    let root = crashing.root, ledger = crashing.ledger, pin = crashing.pin, outbox = crashing.outbox
    #expect(throws: MigrationInjectedCrash.self) {
        try plan.execute(store: crashing.store, pinTransaction: crashing.pinTransaction, mutationOutbox: crashing.mutationOutbox, observedTargetKeys: evidence.observed, completedAt: migrationTimestamp(migrationNow))
    }
    #expect(try crashing.store.verify().sequence == 1)
    #expect(try crashing.pinTransaction.current()?.sequence == 1)
    #expect(try crashing.mutationOutbox.pending()?.lifecycleSequence == 1)

    let restartedStore = try NativeKeyLifecycleStore(directory: ledger.path)
    let restartedPin = try NativeLifecyclePinTransaction(rootPath: pin.path)
    let restartedOutbox = try NativeLifecycleMutationOutbox(rootPath: outbox.path)
    let result = try plan.execute(store: restartedStore, pinTransaction: restartedPin, mutationOutbox: restartedOutbox, observedTargetKeys: evidence.observed, completedAt: migrationTimestamp(migrationNow))
    #expect(result.finalLifecycleSequence == 6)
    #expect(try restartedPin.current()?.newLifecycleHead == plan.finalLifecycleHead)
    #expect(try restartedOutbox.current()?.newLifecycleHead == plan.finalLifecycleHead)
    try? FileManager.default.removeItem(at: root)
}
