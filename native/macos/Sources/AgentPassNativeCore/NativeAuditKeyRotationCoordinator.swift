import Foundation

/// The verified checkpoint boundary at which the retiring audit key is frozen.
///
/// Callers obtain these values from `NativeAuditAnchorReceipts.status(...)` and
/// its last verified version-2 receipt.  The coordinator deliberately accepts
/// the status and receipt together so a rotation cannot race ahead of an
/// unanchored checkpoint.
public struct NativeAuditKeyRotationCheckpointBoundary: Equatable, Sendable {
    public let anchorStatus: NativeAuditAnchorStatus
    public let finalReceipt: NativeAuditAnchorReceipt

    public init(anchorStatus: NativeAuditAnchorStatus, finalReceipt: NativeAuditAnchorReceipt) {
        self.anchorStatus = anchorStatus
        self.finalReceipt = finalReceipt
    }
}

/// An exact, signed transition that may be durably retained and retried after a
/// process restart.  Retrying this value never re-signs or changes its bytes.
public struct NativeAuditKeyRotationPlan: Equatable, Sendable {
    public let transition: NativeAuditKeyTransition
    public let transitionData: Data
    public let retiringPublicKeyX963: Data
    /// Exact signed lifecycle activation record whose hash is committed by the
    /// transition. Production plans retain it so activation can resume after an
    /// accepted anchor response even if the daemon exits before ledger commit.
    public let lifecycleRecordData: Data?

    /// Restores a previously retained exact plan without producing new ECDSA
    /// signatures.  Both signatures and the retiring-key binding are verified.
    public init(transitionData: Data, retiringPublicKeyX963: Data, lifecycleRecordData: Data? = nil) throws {
        transition = try NativeAuditKeyTransition.decodeCanonical(
            transitionData,
            retiringPublicKeyX963: retiringPublicKeyX963
        )
        if let lifecycleRecordData {
            guard lifecycleRecordData.count > 0,
                  lifecycleRecordData.count <= NativeLifecycleMutationOutbox.maximumPayloadBytes,
                  let decoded = try? JSONSerialization.jsonObject(with: lifecycleRecordData),
                  let object = decoded as? [String: Any],
                  object["action"] as? String == "activated",
                  object["role"] as? String == NativeKeyRole.auditCheckpoint.rawValue,
                  object["record_hash"] as? String == transition.lifecycleHeadHash else {
                throw AgentPassNativeError.invalidSignature("Audit-key rotation lifecycle record does not match the anchored activation head")
            }
        }
        self.transitionData = transitionData
        self.retiringPublicKeyX963 = retiringPublicKeyX963
        self.lifecycleRecordData = lifecycleRecordData
    }
}

/// The only successful output of rotation orchestration.  Possession of this
/// value means the exact transition and anchor receipt are already durable in
/// `NativeAuditKeyTransitionStore`; it is therefore safe for the lifecycle
/// layer to begin replacement-key activation.
public struct NativeAuditKeyActivationAuthorization: Equatable, Sendable {
    public let transition: NativeAuditKeyTransition
    public let receipt: NativeAuditKeyTransitionReceipt
    public let transitionData: Data
    public let receiptData: Data
    public let transitionStoreStatus: NativeAuditKeyTransitionStoreStatus
    public let recoveredFromStore: Bool
}

/// Injectable anchor boundary.  Implementations must make exact transition
/// replay idempotent and return the same canonical receipt after a lost reply.
public protocol NativeAuditKeyTransitionTransport: Sendable {
    func submit(transitionData: Data) throws -> Data
}

/// Serial, bounded orchestration of one audit-key transition at a time.
///
/// Each authorization attempt performs at most one transport request and one
/// store acceptance.  No activation authorization is returned until the store
/// has verified and fsync'd the exact transition/receipt pair.
public final class NativeAuditKeyRotationCoordinator: @unchecked Sendable {
    private static let zeroHash = String(repeating: "0", count: 64)

    private let tenant: String
    private let store: NativeAuditKeyTransitionStore
    private let planJournal: NativeAuditKeyRotationPlanJournal
    private let transport: any NativeAuditKeyTransitionTransport
    private let lock = NSLock()

    public init(
        tenant: String,
        transitionStore: NativeAuditKeyTransitionStore,
        planJournal: NativeAuditKeyRotationPlanJournal,
        transport: any NativeAuditKeyTransitionTransport
    ) throws {
        guard tenant.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", options: .regularExpression) != nil else {
            throw AgentPassNativeError.invalidConfiguration("Native audit key rotation tenant is invalid")
        }
        self.tenant = tenant
        store = transitionStore
        self.planJournal = planJournal
        self.transport = transport
        try validateDurableState()
    }

    /// Returns the sole exact plan which must be retried after restart, if any.
    public func pendingPlan() throws -> NativeAuditKeyRotationPlan? {
        lock.lock()
        defer { lock.unlock() }
        return try planJournal.pending()?.plan
    }

    /// Reconciles the narrow crash window where the transition store accepted
    /// the exact plan but the journal completion rename was not observed, then
    /// returns the signed lifecycle record still requiring local commit.
    public func recoverAuthorizedLifecycleRecord(currentLifecycleHeadHash: String, currentAuditGeneration: Int) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        var journal = try planJournal.status()
        let transitions = try store.status()
        if transitions.count == journal.count + 1 {
            guard let pending = journal.pending,
                  pending.plan.transition == transitions.latestTransition,
                  let receipt = transitions.latestReceipt else {
                throw AgentPassNativeError.invalidSignature("Accepted audit-key transition has no exact pending recovery plan")
            }
            _ = try planJournal.complete(pending, transitionStoreReceiptHash: receipt.receiptHash, completedAt: receipt.receivedAt)
            journal = try planJournal.status()
        }
        guard let completed = journal.completed.last else { return nil }
        let plan = completed.preparation.plan
        guard transitions.latestTransition == plan.transition,
              transitions.latestReceipt?.receiptHash == completed.transitionStoreReceiptHash,
              let payload = plan.lifecycleRecordData else {
            return nil
        }
        if currentLifecycleHeadHash == plan.transition.lifecycleHeadHash { return nil }
        if currentAuditGeneration >= plan.transition.toGeneration { return nil }
        guard currentAuditGeneration == plan.transition.fromGeneration else {
            throw AgentPassNativeError.invalidSignature("Authorized audit-key activation generation does not continue local lifecycle state")
        }
        guard let object = try JSONSerialization.jsonObject(with: payload) as? [String: Any],
              object["previous_record_hash"] as? String == currentLifecycleHeadHash,
              object["record_hash"] as? String == plan.transition.lifecycleHeadHash else {
            throw AgentPassNativeError.invalidSignature("Authorized audit-key activation does not extend the current lifecycle head")
        }
        return payload
    }

    /// Freezes the final old-key checkpoint into a dual-signed canonical plan.
    /// Keep the returned plan until authorization succeeds; it is the durable
    /// retry token for an ambiguous anchor response.
    public func prepare(
        operationID: String,
        fromGeneration: Int,
        lifecycleHeadHash: String,
        checkpointBoundary: NativeAuditKeyRotationCheckpointBoundary,
        retiringSigner: any P256MessageSigner,
        replacementSigner: any P256MessageSigner,
        createdAt: String,
        lifecycleRecordData: Data? = nil
    ) throws -> NativeAuditKeyRotationPlan {
        lock.lock()
        defer { lock.unlock() }
        try Self.validate(checkpointBoundary)
        guard checkpointBoundary.finalReceipt.tenant == tenant else {
            throw AgentPassNativeError.invalidSignature("Native audit key rotation checkpoint tenant does not match the coordinator")
        }
        let status = try store.status()
        try validatePreparationContinuity(status: status, fromGeneration: fromGeneration, retiringPublicKeyX963: retiringSigner.publicKeyX963)

        let previousTransition = status.latestTransition
        let statement = try NativeAuditKeyTransitionStatement(
            tenant: tenant,
            operationID: operationID,
            fromGeneration: fromGeneration,
            oldPublicKeyX963: retiringSigner.publicKeyX963,
            newPublicKeyX963: replacementSigner.publicKeyX963,
            lifecycleHeadHash: lifecycleHeadHash,
            lastCheckpointIndex: checkpointBoundary.finalReceipt.index,
            lastCheckpointHash: checkpointBoundary.finalReceipt.checkpointHash,
            lastCheckpointReceiptHash: checkpointBoundary.finalReceipt.receiptHash,
            previousTransitionHash: previousTransition?.transitionHash ?? Self.zeroHash,
            previousTransitionReceiptHash: status.latestReceipt?.receiptHash ?? Self.zeroHash,
            previousAnchorEventIndex: checkpointBoundary.finalReceipt.eventIndex!,
            previousAnchorEventHash: checkpointBoundary.finalReceipt.receiptHash,
            retiringGenerationPendingCheckpointCount: checkpointBoundary.anchorStatus.pending,
            createdAt: createdAt
        )
        let transition = try NativeAuditKeyTransition(
            statement: statement,
            retiringSigner: retiringSigner,
            replacementSigner: replacementSigner
        )
        let plan = try NativeAuditKeyRotationPlan(
            transitionData: try transition.canonicalData(),
            retiringPublicKeyX963: retiringSigner.publicKeyX963,
            lifecycleRecordData: lifecycleRecordData
        )
        _ = try planJournal.prepare(plan, preparedAt: createdAt)
        return plan
    }

    /// Sends and durably records a prepared transition, or recovers an already
    /// committed exact transition without contacting the anchor again.
    public func authorizeActivation(
        plan: NativeAuditKeyRotationPlan,
        checkpointBoundary: NativeAuditKeyRotationCheckpointBoundary
    ) throws -> NativeAuditKeyActivationAuthorization {
        lock.lock()
        defer { lock.unlock() }
        try Self.validate(checkpointBoundary)
        guard checkpointBoundary.finalReceipt.tenant == tenant else {
            throw AgentPassNativeError.invalidSignature("Native audit key rotation checkpoint tenant does not match the coordinator")
        }
        try validate(plan: plan, checkpointBoundary: checkpointBoundary)

        let journalPreparation = try planJournal.prepare(plan, preparedAt: plan.transition.createdAt)

        let before = try store.status()
        if let authorization = try recoveredAuthorization(plan: plan, status: before) {
            _ = try planJournal.complete(journalPreparation, transitionStoreReceiptHash: authorization.receipt.receiptHash, completedAt: authorization.receipt.receivedAt)
            return authorization
        }
        try validateSubmissionContinuity(plan: plan, status: before)

        // There is deliberately no activation callback before these two steps.
        let receiptData = try transport.submit(transitionData: plan.transitionData)
        let committed = try store.accept(
            transitionData: plan.transitionData,
            receiptData: receiptData,
            retiringPublicKeyX963: before.count == 0 ? plan.retiringPublicKeyX963 : nil
        )
        guard committed.count == before.count + 1,
              committed.latestTransition == plan.transition,
              let receipt = committed.latestReceipt else {
            throw AgentPassNativeError.invalidSignature("Native audit key transition was not durably committed as the expected next transition")
        }
        _ = try planJournal.complete(journalPreparation, transitionStoreReceiptHash: receipt.receiptHash, completedAt: receipt.receivedAt)
        return NativeAuditKeyActivationAuthorization(
            transition: plan.transition,
            receipt: receipt,
            transitionData: plan.transitionData,
            receiptData: receiptData,
            transitionStoreStatus: committed,
            recoveredFromStore: false
        )
    }

    private func validateDurableState() throws {
        let journal = try planJournal.status()
        let transitions = try store.status()
        guard transitions.count == journal.count || transitions.count == journal.count + (journal.pending == nil ? 0 : 1) else {
            throw AgentPassNativeError.invalidSignature("Audit-key rotation journal and transition store counts diverge")
        }
        if let latestCompletion = journal.completed.last {
            guard let latestTransition = transitions.latestTransition, let latestReceipt = transitions.latestReceipt,
                  latestCompletion.preparation.plan.transition == latestTransition,
                  latestCompletion.transitionStoreReceiptHash == latestReceipt.receiptHash else {
                throw AgentPassNativeError.invalidSignature("Audit-key rotation journal completion disagrees with transition evidence")
            }
        }
        if transitions.count == journal.count + 1 {
            guard let pending = journal.pending,
                  pending.plan.transition == transitions.latestTransition,
                  transitions.latestReceipt != nil else {
                throw AgentPassNativeError.invalidSignature("Audit-key rotation transition has no exact pending journal plan")
            }
        }
    }

    private func validatePreparationContinuity(
        status: NativeAuditKeyTransitionStoreStatus,
        fromGeneration: Int,
        retiringPublicKeyX963: Data
    ) throws {
        if let previous = status.latestTransition {
            let expectedKey = try SSHSIG.p256PublicKey(fromAuthorizedKey: previous.newPublicKey)
            guard fromGeneration == previous.toGeneration, retiringPublicKeyX963 == expectedKey else {
                throw AgentPassNativeError.invalidSignature("Native audit key rotation does not continue the durable transition chain")
            }
        } else if fromGeneration <= 0 {
            throw AgentPassNativeError.invalidConfiguration("Native audit key rotation generation is invalid")
        }
    }

    private func validate(plan: NativeAuditKeyRotationPlan, checkpointBoundary: NativeAuditKeyRotationCheckpointBoundary) throws {
        let decoded = try NativeAuditKeyTransition.decodeCanonical(
            plan.transitionData,
            retiringPublicKeyX963: plan.retiringPublicKeyX963
        )
        guard decoded == plan.transition,
              decoded.tenant == tenant,
              decoded.lastCheckpointIndex == checkpointBoundary.finalReceipt.index,
              decoded.lastCheckpointHash == checkpointBoundary.finalReceipt.checkpointHash,
              decoded.lastCheckpointReceiptHash == checkpointBoundary.finalReceipt.receiptHash,
              decoded.previousAnchorEventIndex == checkpointBoundary.finalReceipt.eventIndex,
              decoded.previousAnchorEventHash == checkpointBoundary.finalReceipt.receiptHash,
              decoded.retiringGenerationPendingCheckpointCount == 0 else {
            throw AgentPassNativeError.invalidSignature("Native audit key rotation plan no longer matches the final old-key checkpoint boundary")
        }
    }

    private func validateSubmissionContinuity(plan: NativeAuditKeyRotationPlan, status: NativeAuditKeyTransitionStoreStatus) throws {
        if let previous = status.latestTransition, let previousReceipt = status.latestReceipt {
            let expectedKey = try SSHSIG.p256PublicKey(fromAuthorizedKey: previous.newPublicKey)
            guard plan.retiringPublicKeyX963 == expectedKey,
                  plan.transition.fromGeneration == previous.toGeneration,
                  plan.transition.previousTransitionHash == previous.transitionHash,
                  plan.transition.previousTransitionReceiptHash == previousReceipt.receiptHash else {
                throw AgentPassNativeError.invalidSignature("Native audit key rotation plan is stale or forks the durable transition chain")
            }
        } else {
            guard status.count == 0,
                  plan.transition.previousTransitionHash == Self.zeroHash,
                  plan.transition.previousTransitionReceiptHash == Self.zeroHash else {
                throw AgentPassNativeError.invalidSignature("Native audit key rotation plan does not begin at the durable transition-chain origin")
            }
        }
    }

    private func recoveredAuthorization(
        plan: NativeAuditKeyRotationPlan,
        status: NativeAuditKeyTransitionStoreStatus
    ) throws -> NativeAuditKeyActivationAuthorization? {
        guard let latest = status.latestTransition, let receipt = status.latestReceipt else { return nil }
        if latest.operationID == plan.transition.operationID || latest.toGeneration == plan.transition.toGeneration {
            guard latest == plan.transition, try latest.canonicalData() == plan.transitionData else {
                throw AgentPassNativeError.invalidSignature("Native audit key rotation replay conflicts with durable transition evidence")
            }
            return NativeAuditKeyActivationAuthorization(
                transition: latest,
                receipt: receipt,
                transitionData: plan.transitionData,
                receiptData: try Self.canonicalReceiptData(receipt),
                transitionStoreStatus: status,
                recoveredFromStore: true
            )
        }
        return nil
    }

    private static func validate(_ boundary: NativeAuditKeyRotationCheckpointBoundary) throws {
        let status = boundary.anchorStatus
        let receipt = boundary.finalReceipt
        guard status.configured, status.pending == 0, status.checkpoints > 0,
              status.checkpoints == status.receipts,
              receipt.version == 2, receipt.index == status.receipts,
              status.latestReceiptHash == receipt.receiptHash,
              receipt.eventIndex != nil, receipt.eventIndex! > 0,
              receipt.previousEventHash != nil,
              receipt.tenant.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", options: .regularExpression) != nil,
              isHash(receipt.checkpointHash), isHash(receipt.receiptHash),
              isHash(receipt.previousReceiptHash), isHash(receipt.previousEventHash!) else {
            throw AgentPassNativeError.invalidSignature("Native audit key rotation requires one final anchored old-key checkpoint and zero pending receipts")
        }
    }

    private static func canonicalReceiptData(_ receipt: NativeAuditKeyTransitionReceipt) throws -> Data {
        try NativeAuditLog.canonical([
            "version": receipt.version, "tenant": receipt.tenant, "index": receipt.index,
            "transition_hash": receipt.transitionHash, "received_at": receipt.receivedAt,
            "previous_receipt_hash": receipt.previousReceiptHash,
            "event_index": receipt.eventIndex, "previous_event_hash": receipt.previousEventHash,
            "last_checkpoint_index": receipt.lastCheckpointIndex,
            "last_checkpoint_hash": receipt.lastCheckpointHash,
            "last_checkpoint_receipt_hash": receipt.lastCheckpointReceiptHash,
            "anchor_key_fingerprint": receipt.anchorKeyFingerprint,
            "signature": receipt.signature, "receipt_hash": receipt.receiptHash
        ])
    }

    private static func isHash(_ value: String) -> Bool {
        value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
    }
}
