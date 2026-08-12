import Foundation

public protocol NativeLifecycleKeyHandle: P256MessageSigner, Sendable {}

extension SecureEnclaveKeyStore: NativeLifecycleKeyHandle {}

public protocol NativeLifecycleKeyProvider: Sendable {
    func create(applicationTag: String, requiresUserPresence: Bool) throws -> any NativeLifecycleKeyHandle
    func load(applicationTag: String) throws -> any NativeLifecycleKeyHandle
    func exists(applicationTag: String) throws -> Bool
    func delete(applicationTag: String) throws
}

public struct SecureEnclaveLifecycleKeyProvider: NativeLifecycleKeyProvider {
    private let accessGroup: String?

    public init(accessGroup: String?) { self.accessGroup = accessGroup }

    public func create(applicationTag: String, requiresUserPresence: Bool) throws -> any NativeLifecycleKeyHandle {
        try SecureEnclaveKeyStore.create(applicationTag: applicationTag, accessGroup: accessGroup, requiresUserPresence: requiresUserPresence)
    }

    public func load(applicationTag: String) throws -> any NativeLifecycleKeyHandle {
        try SecureEnclaveKeyStore.loadExisting(applicationTag: applicationTag, accessGroup: accessGroup)
    }

    public func exists(applicationTag: String) throws -> Bool {
        try SecureEnclaveKeyStore.exists(applicationTag: applicationTag, accessGroup: accessGroup)
    }

    public func delete(applicationTag: String) throws {
        _ = try SecureEnclaveKeyStore.delete(applicationTag: applicationTag, accessGroup: accessGroup)
    }
}

public struct NativeLifecycleDeletionProof: Sendable {
    public let lifecycleHeadHash: String
    public let transitionReceiptHash: String
    public let transitionArchivedAt: String
    public let verifiedAt: String

    public init(lifecycleHeadHash: String, transitionReceiptHash: String, transitionArchivedAt: String, verifiedAt: String) {
        self.lifecycleHeadHash = lifecycleHeadHash
        self.transitionReceiptHash = transitionReceiptHash
        self.transitionArchivedAt = transitionArchivedAt
        self.verifiedAt = verifiedAt
    }
}

public protocol NativeLifecycleDeletionProofVerifier: Sendable {
    /// Verifies an externally signed archive/anchor receipt and returns trusted receipt and verification times.
    func verify(_ proof: NativeLifecycleDeletionProof, role: NativeKeyRole, generation: Int, fingerprint: String) throws -> (archivedAt: Date, verifiedAt: Date)
}

public struct NativeLifecycleDeletionEvidenceLease: @unchecked Sendable {
    public let archivedAt: Date
    public let verifiedAt: Date
    private let archiveLease: NativeAuditRetainedArchiveLease?
    public let binding: NativeAuditDeletionIntentBinding?
    private let spoolLease: NativeAuditDeletionRecoverySpoolLease?

    public init(archivedAt: Date, verifiedAt: Date, archiveLease: NativeAuditRetainedArchiveLease? = nil, binding: NativeAuditDeletionIntentBinding? = nil, spoolLease: NativeAuditDeletionRecoverySpoolLease? = nil) {
        self.archivedAt = archivedAt
        self.verifiedAt = verifiedAt
        self.archiveLease = archiveLease
        self.binding = binding; self.spoolLease = spoolLease
    }

    public func revalidateRetainedArchive() throws {
        try archiveLease?.revalidate()
        try spoolLease?.revalidate()
    }
}

/// Required authority for deleting an audit-checkpoint key.  Unlike a timestamp-only proof,
/// this capability pins the exact retained archive descriptors through the Keychain mutation.
public protocol NativeAuditLifecycleDeletionLeaseVerifier: NativeLifecycleDeletionProofVerifier {
    func acquireDeletionEvidenceLease(
        _ proof: NativeLifecycleDeletionProof,
        role: NativeKeyRole,
        generation: Int,
        fingerprint: String
    ) throws -> NativeLifecycleDeletionEvidenceLease

    /// Reacquires only the retained-filesystem capability for an already durable deletion intent.
    /// The lifecycle ledger remains the authorization source during crash recovery.
    func acquireRecordedDeletionArchiveLease(
        role: NativeKeyRole,
        generation: Int,
        fingerprint: String,
        lifecycleHeadHash: String,
        binding: NativeAuditDeletionIntentBinding
    ) throws -> NativeLifecycleDeletionEvidenceLease
}

public struct NativeLifecycleStageResult: Sendable {
    public let role: NativeKeyRole
    public let generation: Int
    public let applicationTag: String
    public let fingerprint: String
    public let lifecycleHeadHash: String
}

public struct NativeRecoveredAuditActivationPreparation: Sendable {
    public let statement: NativeKeyTransitionStatement
    public let lifecycleRecordData: Data
    public let lifecycleHeadHash: String
    public let retiringPublicKeyX963: Data
    public let replacementPublicKeyX963: Data
    public let replacementSignature: Data
}

/// Exact activation material exposed to a pre-commit gate. Audit-key rotation uses this to
/// anchor the final old-key boundary against the precise post-activation lifecycle head before
/// the lifecycle ledger, external pin, or mutation outbox advances.
public struct NativeServiceKeyActivationPreview: Sendable {
    public let statement: NativeKeyTransitionStatement
    public let retiringPublicKeyX963: Data?
    public let replacementPublicKeyX963: Data
    public let lifecycleHeadHash: String
    public let canonicalLifecycleRecord: Data
}

/// Coordinates lifecycle records with exact-tag key operations. Low-level ledger methods remain
/// replay primitives; production mutation must pass through this type.
public final class NativeKeyLifecycleCoordinator: @unchecked Sendable {
    private let store: NativeKeyLifecycleStore
    private let provider: any NativeLifecycleKeyProvider
    private let baseTags: [NativeKeyRole: String]
    private let deletionProofVerifier: (any NativeLifecycleDeletionProofVerifier)?
    private let pinTransaction: NativeLifecyclePinTransaction?
    private let mutationOutbox: NativeLifecycleMutationOutbox?
    private let now: @Sendable () -> Date
    private let lock = NSLock()

    public init(store: NativeKeyLifecycleStore, provider: any NativeLifecycleKeyProvider, baseTags: [NativeKeyRole: String], deletionProofVerifier: (any NativeLifecycleDeletionProofVerifier)? = nil, pinTransaction: NativeLifecyclePinTransaction? = nil, mutationOutbox: NativeLifecycleMutationOutbox? = nil, now: @escaping @Sendable () -> Date = Date.init) throws {
        guard NativeKeyRole.allCases.allSatisfy({ baseTags[$0]?.isEmpty == false }) else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle coordinator requires signing, audit, and approval base tags")
        }
        self.store = store
        self.provider = provider
        self.baseTags = baseTags
        self.deletionProofVerifier = deletionProofVerifier
        self.pinTransaction = pinTransaction
        self.mutationOutbox = mutationOutbox
        self.now = now
        guard mutationOutbox == nil || pinTransaction != nil else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle mutation outbox requires an external pin transaction")
        }
        if mutationOutbox != nil { _ = try recoverPendingMutation() }
    }

    /// Completes the sole byte-exact write-ahead mutation after a process or machine restart.
    /// A third ledger head, mismatched pin, or altered payload fails closed.
    @discardableResult
    public func recoverPendingMutation() throws -> NativeKeyLifecycleSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return try recoverPendingMutationUnlocked()
    }

    private func recoverPendingMutationUnlocked() throws -> NativeKeyLifecycleSnapshot {
        guard let mutationOutbox, let pinTransaction else { return try store.verify() }
        guard let pending = try mutationOutbox.pending() else {
            if try pinTransaction.pending() != nil {
                throw AgentPassNativeError.invalidSignature("Lifecycle pin is pending without byte-exact mutation evidence")
            }
            return try store.verify()
        }
        let state = try store.verify()
        guard state.headHash == pending.oldLifecycleHead || state.headHash == pending.newLifecycleHead else {
            throw AgentPassNativeError.invalidSignature("Pending lifecycle mutation does not bracket the observed ledger head")
        }
        let pin: NativeLifecyclePinPreparation
        if let existing = try pinTransaction.pending() {
            guard existing.operationID == pending.operationID,
                  existing.sequence == pending.pinSequence,
                  existing.role == pending.role,
                  existing.action.rawValue == pending.kind.rawValue,
                  existing.oldLifecycleHead == pending.oldLifecycleHead,
                  existing.newLifecycleHead == pending.newLifecycleHead,
                  existing.preparedAt == pending.createdAt else {
                throw AgentPassNativeError.invalidSignature("Lifecycle pin and mutation outbox disagree")
            }
            pin = existing
        } else {
            guard (try pinTransaction.current()?.sequence ?? 0) + 1 == pending.pinSequence else {
                throw AgentPassNativeError.invalidSignature("Lifecycle mutation outbox pin sequence is not next")
            }
            guard let action = NativeLifecyclePinAction(rawValue: pending.kind.rawValue) else {
                throw AgentPassNativeError.invalidConfiguration("Lifecycle mutation kind has no pin action")
            }
            pin = try pinTransaction.prepare(operationID: pending.operationID, sequence: pending.pinSequence, role: pending.role, action: action, oldLifecycleHead: pending.oldLifecycleHead, newLifecycleHead: pending.newLifecycleHead, preparedAt: pending.createdAt)
        }
        let next = state.headHash == pending.oldLifecycleHead ? try store.appendPreparedRecordData(pending.payload) : state
        guard next.sequence == pending.lifecycleSequence, next.headHash == pending.newLifecycleHead else {
            throw AgentPassNativeError.invalidSignature("Replayed lifecycle mutation produced an unexpected ledger state")
        }
        _ = try pinTransaction.commit(pin, observedOldLifecycleHead: pending.oldLifecycleHead, observedNewLifecycleHead: next.headHash)
        _ = try mutationOutbox.complete(pending, observedNewLifecycleHead: next.headHash)
        return next
    }

    /// Finishes an authorized Keychain side effect left between an intent record and its terminal
    /// lifecycle record. Recovery never invents authority: the fully verified lifecycle snapshot
    /// must contain the exact intent, and the byte-exact terminal mutation is journaled through the
    /// mutation outbox and external pin before the ledger advances.
    @discardableResult
    public func recoverKeychainSideEffects() throws -> NativeKeyLifecycleSnapshot {
        lock.lock()
        defer { lock.unlock() }

        _ = try recoverPendingMutationUnlocked()
        let initial = try store.verify()
        let intents = initial.generations
            .filter { $0.status == .abortIntent || $0.status == .deletionIntent }
            .sorted {
                if $0.role.rawValue != $1.role.rawValue { return $0.role.rawValue < $1.role.rawValue }
                return $0.generation < $1.generation
            }
        guard !intents.isEmpty else { return initial }
        guard mutationOutbox != nil, pinTransaction != nil else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle Keychain recovery requires the mutation outbox and external pin transaction")
        }
        guard Set(intents.map(\.applicationTag)).count == intents.count else {
            throw AgentPassNativeError.invalidSignature("Lifecycle Keychain recovery found ambiguous intent targets")
        }

        var state = initial
        for intent in intents {
            guard intent.role == .gitSigning || intent.role == .auditCheckpoint,
                  let baseTag = baseTags[intent.role],
                  intent.applicationTag == "\(baseTag).g\(intent.generation)",
                  let current = state.generation(intent.generation, for: intent.role),
                  current.status == intent.status,
                  current.applicationTag == intent.applicationTag,
                  current.publicKeyX963 == intent.publicKeyX963 else {
                throw AgentPassNativeError.invalidSignature("Lifecycle Keychain recovery found an ambiguous or non-service intent target")
            }

            let auditArchiveLease: NativeLifecycleDeletionEvidenceLease?
            if current.role == .auditCheckpoint, current.status == .deletionIntent {
                guard let verifier = deletionProofVerifier as? any NativeAuditLifecycleDeletionLeaseVerifier else {
                    throw AgentPassNativeError.invalidConfiguration("Audit-key deletion recovery requires a retained-archive lease verifier")
                }
                guard let binding = current.auditDeletionBinding, let intentHead = current.deletionIntentLifecycleHead else { throw AgentPassNativeError.invalidSignature("Recorded audit deletion intent has no exact evidence binding") }
                auditArchiveLease = try verifier.acquireRecordedDeletionArchiveLease(
                    role: current.role,
                    generation: current.generation,
                    fingerprint: current.fingerprint,
                    lifecycleHeadHash: intentHead,
                    binding: binding
                )
                guard auditArchiveLease?.binding == binding else { throw AgentPassNativeError.invalidSignature("Recovered audit deletion evidence differs from its signed intent") }
                try auditArchiveLease?.revalidateRetainedArchive()
            } else {
                auditArchiveLease = nil
            }

            if try provider.exists(applicationTag: current.applicationTag) {
                let key = try provider.load(applicationTag: current.applicationTag)
                guard key.publicKeyX963 == current.publicKeyX963 else {
                    throw AgentPassNativeError.invalidKey("Lifecycle Keychain recovery refuses a substituted exact-tag key")
                }
                try auditArchiveLease?.revalidateRetainedArchive()
                try provider.delete(applicationTag: current.applicationTag)
            }
            guard try !provider.exists(applicationTag: current.applicationTag) else {
                throw AgentPassNativeError.invalidKey("Lifecycle Keychain recovery could not remove the exact target key")
            }
            try auditArchiveLease?.revalidateRetainedArchive()

            let timestamp = Self.timestamp(now())
            let kind: NativeLifecycleMutationKind
            let payload: Data
            switch current.status {
            case .abortIntent:
                kind = .aborted
                payload = try store.prepareAbortedRecordData(role: current.role, generation: current.generation, createdAt: timestamp, exactKeyIsAbsent: true)
            case .deletionIntent:
                kind = .deleted
                payload = try store.prepareDeletedRecordData(role: current.role, generation: current.generation, createdAt: timestamp, exactKeyIsAbsent: true)
            default:
                throw AgentPassNativeError.invalidSignature("Lifecycle Keychain recovery intent changed during recovery")
            }
            let newHead = try Self.preparedRecordHead(payload)
            guard let action = NativeLifecyclePinAction(rawValue: kind.rawValue) else {
                throw AgentPassNativeError.invalidConfiguration("Lifecycle recovery mutation has no pin action")
            }
            let preparation = try prepareDurableMutation(
                existingPin: try matchingPendingPin(role: current.role, action: action, oldHead: state.headHash),
                role: current.role,
                kind: kind,
                oldState: state,
                newHead: newHead,
                createdAt: timestamp,
                payload: payload
            )
            let previousHead = state.headHash
            state = try store.appendPreparedRecordData(payload)
            try completeDurableMutation(preparation, oldHead: previousHead, newState: state)
        }
        return state
    }

    /// Commits the exact audit activation record only after the independent
    /// rotation journal proves that its transition was accepted by the anchor.
    /// The record is fully replay-validated before pin/outbox state advances.
    @discardableResult
    public func commitAuthorizedAuditActivationRecord(_ payload: Data) throws -> NativeKeyLifecycleSnapshot {
        lock.lock()
        defer { lock.unlock() }
        guard mutationOutbox != nil, pinTransaction != nil else {
            throw AgentPassNativeError.invalidConfiguration("Authorized audit activation recovery requires mutation outbox and external pin")
        }
        _ = try recoverPendingMutationUnlocked()
        let oldState = try store.verify()
        let predicted = try store.validatePreparedRecordData(payload)
        guard let object = try? JSONSerialization.jsonObject(with: payload) as? [String: Any],
              object["action"] as? String == "activated",
              object["role"] as? String == NativeKeyRole.auditCheckpoint.rawValue,
              let createdAt = object["created_at"] as? String,
              object["previous_record_hash"] as? String == oldState.headHash,
              object["record_hash"] as? String == predicted.headHash,
              predicted.sequence == oldState.sequence + 1 else {
            throw AgentPassNativeError.invalidSignature("Authorized audit activation record is not the exact next lifecycle mutation")
        }
        let preparation = try prepareDurableMutation(
            existingPin: try matchingPendingPin(role: .auditCheckpoint, action: .activated, oldHead: oldState.headHash),
            role: .auditCheckpoint,
            kind: .activated,
            oldState: oldState,
            newHead: predicted.headHash,
            createdAt: createdAt,
            payload: payload
        )
        let next = try store.appendPreparedRecordData(payload)
        try completeDurableMutation(preparation, oldHead: oldState.headHash, newState: next)
        return next
    }

    @discardableResult
    public func stageServiceKey(role: NativeKeyRole) throws -> NativeLifecycleStageResult {
        lock.lock()
        defer { lock.unlock() }
        guard role == .gitSigning || role == .auditCheckpoint, let base = baseTags[role] else {
            throw AgentPassNativeError.invalidConfiguration("Service coordinator cannot create approval keys")
        }
        let before = try store.verify()
        let generation = (before.generations.filter { $0.role == role }.map(\.generation).max() ?? 0) + 1
        let tag = "\(base).g\(generation)"
        let timestamp = Self.timestamp(now())
        let pending = try matchingPendingPin(role: role, action: .staged, oldHead: before.headHash)
        let key: any NativeLifecycleKeyHandle
        if try provider.exists(applicationTag: tag) {
            guard pending != nil else { throw AgentPassNativeError.invalidKey("Lifecycle generation tag already exists") }
            key = try provider.load(applicationTag: tag)
        } else {
            key = try provider.create(applicationTag: tag, requiresUserPresence: false)
        }
        var durableMutationWasPrepared = pending != nil
        do {
            let payload = try store.prepareStageRecordData(role: role, generation: generation, applicationTag: tag, publicKeyX963: key.publicKeyX963, createdAt: timestamp)
            let newHead = try Self.preparedRecordHead(payload)
            let preparation = try prepareDurableMutation(existingPin: pending, role: role, kind: .staged, oldState: before, newHead: newHead, createdAt: timestamp, payload: payload)
            durableMutationWasPrepared = preparation.pin != nil || preparation.outbox != nil
            let state = mutationOutbox == nil
                ? try store.stage(role: role, generation: generation, applicationTag: tag, publicKeyX963: key.publicKeyX963, createdAt: timestamp)
                : try store.appendPreparedRecordData(payload)
            try completeDurableMutation(preparation, oldHead: before.headHash, newState: state)
            return NativeLifecycleStageResult(role: role, generation: generation, applicationTag: tag, fingerprint: NativeKeyLifecycleStore.fingerprint(key.publicKeyX963), lifecycleHeadHash: state.headHash)
        } catch {
            // Roll back only the exact key created by this call. A failed cleanup leaves a harmless,
            // never-staged orphan that remains unusable until an authorized repair.
            if !durableMutationWasPrepared, let loaded = try? provider.load(applicationTag: tag), loaded.publicKeyX963 == key.publicKeyX963 { try? provider.delete(applicationTag: tag) }
            throw error
        }
    }

    public func approvalKeyStagePlan() throws -> (generation: Int, applicationTag: String) {
        lock.lock()
        defer { lock.unlock() }
        let state = try store.verify()
        guard state.generations.first(where: { $0.role == .sessionApproval && $0.status == .staged }) == nil,
              let base = baseTags[.sessionApproval] else {
            throw AgentPassNativeError.invalidConfiguration("An approval key is already staged")
        }
        let generation = (state.generations.filter { $0.role == .sessionApproval }.map(\.generation).max() ?? 0) + 1
        return (generation, "\(base).g\(generation)")
    }

    /// Records a client-created, human-presence key. Authority is not granted until activation,
    /// where both the retiring and replacement keys prove possession over the same statement.
    @discardableResult
    public func stageApprovalKey(generation: Int, applicationTag: String, publicKeyX963: Data) throws -> NativeLifecycleStageResult {
        lock.lock()
        defer { lock.unlock() }
        let state = try store.verify()
        guard state.generations.first(where: { $0.role == .sessionApproval && $0.status == .staged }) == nil,
              let base = baseTags[.sessionApproval] else {
            throw AgentPassNativeError.invalidConfiguration("An approval key is already staged")
        }
        let expectedGeneration = (state.generations.filter { $0.role == .sessionApproval }.map(\.generation).max() ?? 0) + 1
        let expectedTag = "\(base).g\(expectedGeneration)"
        guard generation == expectedGeneration, applicationTag == expectedTag else {
            throw AgentPassNativeError.invalidConfiguration("Approval key stage request does not match the current lifecycle plan")
        }
        let timestamp = Self.timestamp(now())
        let pending = try matchingPendingPin(role: .sessionApproval, action: .staged, oldHead: state.headHash)
        let payload = try store.prepareStageRecordData(role: .sessionApproval, generation: generation, applicationTag: applicationTag, publicKeyX963: publicKeyX963, createdAt: timestamp)
        let newHead = try Self.preparedRecordHead(payload)
        let preparation = try prepareDurableMutation(existingPin: pending, role: .sessionApproval, kind: .staged, oldState: state, newHead: newHead, createdAt: timestamp, payload: payload)
        let next = mutationOutbox == nil
            ? try store.stage(role: .sessionApproval, generation: generation, applicationTag: applicationTag, publicKeyX963: publicKeyX963, createdAt: timestamp)
            : try store.appendPreparedRecordData(payload)
        try completeDurableMutation(preparation, oldHead: state.headHash, newState: next)
        return NativeLifecycleStageResult(role: .sessionApproval, generation: generation, applicationTag: applicationTag, fingerprint: NativeKeyLifecycleStore.fingerprint(publicKeyX963), lifecycleHeadHash: next.headHash)
    }

    public func activationStatement(role: NativeKeyRole, generation: Int, reason: String, challengeID: String, continuity: NativeKeyContinuity = .clean) throws -> NativeKeyTransitionStatement {
        lock.lock()
        defer { lock.unlock() }
        return try store.transitionStatement(role: role, generation: generation, reason: reason, challengeID: challengeID, createdAt: Self.timestamp(now()), continuity: continuity)
    }

    public func abortStatement(role: NativeKeyRole, generation: Int, reason: String, challengeID: String, externallyPinnedHeadHash: String) throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        return try store.abortStatement(role: role, generation: generation, reason: reason, challengeID: challengeID, createdAt: Self.timestamp(now()), externallyPinnedHeadHash: externallyPinnedHeadHash)
    }

    /// Authorizes the abort before deleting the exact service-owned staged key. A crash after the
    /// deletion is resumed from the durable abort intent and can never grant that generation.
    @discardableResult
    public func abortStagedServiceKey(role: NativeKeyRole, generation: Int, reason: String, challengeID: String, externallyPinnedHeadHash: String, approvalSignature: Data, approvalPublicKeyX963: Data) throws -> NativeKeyLifecycleSnapshot {
        lock.lock()
        defer { lock.unlock() }
        guard role == .gitSigning || role == .auditCheckpoint else {
            throw AgentPassNativeError.invalidConfiguration("Client-owned approval keys require the client abort path")
        }
        let timestamp = Self.timestamp(now())
        let beforeIntent = try store.verify()
        let intentPayload = try store.prepareAbortIntentRecordData(role: role, generation: generation, reason: reason, challengeID: challengeID, createdAt: timestamp, approvalSignature: approvalSignature, approvalPublicKeyX963: approvalPublicKeyX963, externallyPinnedHeadHash: externallyPinnedHeadHash)
        let intentHead = try Self.preparedRecordHead(intentPayload)
        let pendingIntentPin = try matchingPendingPin(role: role, action: .abortIntent, oldHead: beforeIntent.headHash)
        let intentPreparation = try prepareDurableMutation(existingPin: pendingIntentPin, role: role, kind: .abortIntent, oldState: beforeIntent, newHead: intentHead, createdAt: timestamp, payload: intentPayload)
        var state = mutationOutbox == nil
            ? try store.recordAbortIntent(role: role, generation: generation, reason: reason, challengeID: challengeID, createdAt: timestamp, approvalSignature: approvalSignature, approvalPublicKeyX963: approvalPublicKeyX963, externallyPinnedHeadHash: externallyPinnedHeadHash)
            : try store.appendPreparedRecordData(intentPayload)
        try completeDurableMutation(intentPreparation, oldHead: beforeIntent.headHash, newState: state)
        guard let target = state.generation(generation, for: role), target.status == .abortIntent else {
            throw AgentPassNativeError.invalidConfiguration("Staged-key abort intent was not persisted")
        }
        let key = try provider.load(applicationTag: target.applicationTag)
        guard key.publicKeyX963 == target.publicKeyX963 else {
            throw AgentPassNativeError.invalidKey("Staged-key abort target does not match the exact keychain binding")
        }
        try provider.delete(applicationTag: target.applicationTag)
        guard try !provider.exists(applicationTag: target.applicationTag) else {
            throw AgentPassNativeError.invalidKey("Exact staged key remains after abort deletion")
        }
        let abortedPayload = try store.prepareAbortedRecordData(role: role, generation: generation, createdAt: timestamp, exactKeyIsAbsent: true)
        let abortedHead = try Self.preparedRecordHead(abortedPayload)
        let abortedPreparation = try prepareDurableMutation(existingPin: try matchingPendingPin(role: role, action: .aborted, oldHead: state.headHash), role: role, kind: .aborted, oldState: state, newHead: abortedHead, createdAt: timestamp, payload: abortedPayload)
        let beforeAborted = state
        state = mutationOutbox == nil
            ? try store.recordAborted(role: role, generation: generation, createdAt: timestamp, exactKeyIsAbsent: true)
            : try store.appendPreparedRecordData(abortedPayload)
        try completeDurableMutation(abortedPreparation, oldHead: beforeAborted.headHash, newState: state)
        return state
    }

    @discardableResult
    public func resumeRecordedAbort(role: NativeKeyRole, generation: Int) throws -> NativeKeyLifecycleSnapshot {
        lock.lock()
        defer { lock.unlock() }
        let state = try store.verify()
        guard let target = state.generation(generation, for: role), target.status == .abortIntent else {
            throw AgentPassNativeError.invalidConfiguration("No staged-key abort intent can be resumed")
        }
        if try provider.exists(applicationTag: target.applicationTag) {
            let key = try provider.load(applicationTag: target.applicationTag)
            guard key.publicKeyX963 == target.publicKeyX963 else {
                throw AgentPassNativeError.invalidKey("Abort repair refuses a substituted exact-tag key")
            }
            try provider.delete(applicationTag: target.applicationTag)
        }
        guard try !provider.exists(applicationTag: target.applicationTag) else {
            throw AgentPassNativeError.invalidKey("Abort repair could not remove the exact staged key")
        }
        let timestamp = Self.timestamp(now())
        let payload = try store.prepareAbortedRecordData(role: role, generation: generation, createdAt: timestamp, exactKeyIsAbsent: true)
        let newHead = try Self.preparedRecordHead(payload)
        let preparation = try prepareDurableMutation(existingPin: try matchingPendingPin(role: role, action: .aborted, oldHead: state.headHash), role: role, kind: .aborted, oldState: state, newHead: newHead, createdAt: timestamp, payload: payload)
        let next = mutationOutbox == nil
            ? try store.recordAborted(role: role, generation: generation, createdAt: timestamp, exactKeyIsAbsent: true)
            : try store.appendPreparedRecordData(payload)
        try completeDurableMutation(preparation, oldHead: state.headHash, newState: next)
        return next
    }

    @discardableResult
    public func activateServiceKey(statement: NativeKeyTransitionStatement, approvalSignature: Data, approvalPublicKeyX963: Data, beforeCommit: ((NativeServiceKeyActivationPreview) throws -> Void)? = nil) throws -> NativeKeyLifecycleSnapshot {
        lock.lock()
        defer { lock.unlock() }
        guard statement.role == .gitSigning || statement.role == .auditCheckpoint, statement.continuity != .recovered else {
            throw AgentPassNativeError.invalidConfiguration("Service-key activation requires clean or bootstrap continuity")
        }
        let state = try store.verify()
        guard let staged = state.generation(statement.newGeneration, for: statement.role), staged.status == .staged else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle staged key is missing")
        }
        let replacement = try provider.load(applicationTag: staged.applicationTag)
        guard replacement.publicKeyX963 == staged.publicKeyX963 else { throw AgentPassNativeError.invalidKey("Staged keychain binding does not match the lifecycle ledger") }
        let message = try statement.canonicalData()
        let oldSignature: Data?
        let retiringPublicKeyX963: Data?
        if statement.continuity == .bootstrap {
            oldSignature = nil
            retiringPublicKeyX963 = nil
        } else {
            guard let active = state.active(for: statement.role) else { throw AgentPassNativeError.invalidConfiguration("Lifecycle active key is missing") }
            let retiring = try provider.load(applicationTag: active.applicationTag)
            guard retiring.publicKeyX963 == active.publicKeyX963 else { throw AgentPassNativeError.invalidKey("Active keychain binding does not match the lifecycle ledger") }
            oldSignature = try retiring.sign(message: message)
            retiringPublicKeyX963 = retiring.publicKeyX963
        }
        let newSignature = try replacement.sign(message: message)
        let payload = try store.prepareActivationRecordData(statement: statement, oldSignature: oldSignature, newSignature: newSignature, approvalSignature: approvalSignature, approvalPublicKeyX963: approvalPublicKeyX963)
        let newHead = try Self.preparedRecordHead(payload)
        try beforeCommit?(NativeServiceKeyActivationPreview(statement: statement, retiringPublicKeyX963: retiringPublicKeyX963, replacementPublicKeyX963: replacement.publicKeyX963, lifecycleHeadHash: newHead, canonicalLifecycleRecord: payload))
        let pending = try matchingPendingPin(role: statement.role, action: .activated, oldHead: state.headHash)
        let preparation = try prepareDurableMutation(existingPin: pending, role: statement.role, kind: .activated, oldState: state, newHead: newHead, createdAt: statement.createdAt, payload: payload)
        let next = mutationOutbox == nil
            ? try store.activate(statement: statement, oldSignature: oldSignature, newSignature: newSignature, approvalSignature: approvalSignature, approvalPublicKeyX963: approvalPublicKeyX963)
            : try store.appendPreparedRecordData(payload)
        try completeDurableMutation(preparation, oldHead: state.headHash, newState: next)
        return next
    }

    @discardableResult
    public func activateApprovalKey(statement: NativeKeyTransitionStatement, oldApprovalSignature: Data, newApprovalSignature: Data, oldApprovalPublicKeyX963: Data) throws -> NativeKeyLifecycleSnapshot {
        lock.lock()
        defer { lock.unlock() }
        guard statement.role == .sessionApproval, statement.continuity == .clean else {
            throw AgentPassNativeError.invalidConfiguration("Approval-key activation requires clean continuity")
        }
        // The ledger verifier independently validates old-key continuity, new-key possession,
        // and that authorization came from the currently active approval generation.
        let state = try store.verify()
        let payload = try store.prepareActivationRecordData(statement: statement, oldSignature: oldApprovalSignature, newSignature: newApprovalSignature, approvalSignature: oldApprovalSignature, approvalPublicKeyX963: oldApprovalPublicKeyX963)
        let newHead = try Self.preparedRecordHead(payload)
        let pending = try matchingPendingPin(role: statement.role, action: .activated, oldHead: state.headHash)
        let preparation = try prepareDurableMutation(existingPin: pending, role: statement.role, kind: .activated, oldState: state, newHead: newHead, createdAt: statement.createdAt, payload: payload)
        let next = mutationOutbox == nil
            ? try store.activate(statement: statement, oldSignature: oldApprovalSignature, newSignature: newApprovalSignature, approvalSignature: oldApprovalSignature, approvalPublicKeyX963: oldApprovalPublicKeyX963)
            : try store.appendPreparedRecordData(payload)
        try completeDurableMutation(preparation, oldHead: state.headHash, newState: next)
        return next
    }

    @discardableResult
    public func activateRecoveredKey(verification: NativeRecoveryVerification, evidenceData: Data, clientNewKeySignature: Data? = nil) throws -> NativeKeyLifecycleSnapshot {
        lock.lock()
        defer { lock.unlock() }
        let request = verification.request
        let statement = try store.transitionStatement(
            role: request.role, generation: request.proposedGeneration,
            reason: "offline-threshold-recovery:\(verification.requestHash)",
            challengeID: request.nonce, createdAt: request.issuedAt, continuity: .recovered
        )
        let message = try statement.canonicalData()
        let newSignature: Data
        if request.role == .sessionApproval {
            guard let clientNewKeySignature, clientNewKeySignature.count == 64 else {
                throw AgentPassNativeError.invalidSignature("Recovered approval key requires client proof of possession")
            }
            newSignature = clientNewKeySignature
        } else {
            let state = try store.verify()
            guard let staged = state.generation(request.proposedGeneration, for: request.role), staged.status == .staged else {
                throw AgentPassNativeError.invalidConfiguration("Recovered service key is not staged")
            }
            let replacement = try provider.load(applicationTag: staged.applicationTag)
            guard replacement.publicKeyX963 == request.proposedPublicKeyX963 else {
                throw AgentPassNativeError.invalidKey("Recovered service key does not match its exact keychain binding")
            }
            newSignature = try replacement.sign(message: message)
        }
        let state = try store.verify()
        let payload = try store.prepareActivationRecordData(statement: statement, oldSignature: nil, newSignature: newSignature, approvalSignature: evidenceData, approvalPublicKeyX963: Data())
        let newHead = try Self.preparedRecordHead(payload)
        let preparation = try prepareDurableMutation(existingPin: try matchingPendingPin(role: request.role, action: .recoveredActivation, oldHead: state.headHash), role: request.role, kind: .recoveredActivation, oldState: state, newHead: newHead, createdAt: statement.createdAt, payload: payload)
        let next = mutationOutbox == nil
            ? try store.activateRecovered(statement: statement, newSignature: newSignature, evidenceData: evidenceData)
            : try store.appendPreparedRecordData(payload)
        try completeDurableMutation(preparation, oldHead: state.headHash, newState: next)
        return next
    }

    public func recoveredActivationStatement(verification: NativeRecoveryVerification) throws -> NativeKeyTransitionStatement {
        lock.lock()
        defer { lock.unlock() }
        let request = verification.request
        return try store.transitionStatement(
            role: request.role,
            generation: request.proposedGeneration,
            reason: "offline-threshold-recovery:\(verification.requestHash)",
            challengeID: request.nonce,
            createdAt: request.issuedAt,
            continuity: .recovered
        )
    }

    /// Produces the byte-exact recovered audit activation record without
    /// mutating ledger, external pin, outbox, or Keychain state. An external
    /// anchor journal must authorize this exact record before it is committed.
    public func prepareRecoveredAuditActivation(
        verification: NativeRecoveryVerification,
        evidenceData: Data
    ) throws -> NativeRecoveredAuditActivationPreparation {
        lock.lock()
        defer { lock.unlock() }
        let request = verification.request
        guard verification.valid, request.role == .auditCheckpoint,
              !evidenceData.isEmpty,
              evidenceData.count <= NativeRecoveryEvidenceBundle.maximumBytes else {
            throw AgentPassNativeError.invalidConfiguration("Recovered audit activation evidence is invalid")
        }
        let state = try store.verify()
        guard state.headHash == request.lifecycleHeadHash,
              let active = state.active(for: .auditCheckpoint),
              active.generation == request.fromGeneration,
              active.fingerprint == request.fromFingerprint,
              let staged = state.generation(request.proposedGeneration, for: .auditCheckpoint),
              staged.status == .staged,
              staged.publicKeyX963 == request.proposedPublicKeyX963 else {
            throw AgentPassNativeError.invalidSignature("Recovered audit activation no longer matches the exact lifecycle state")
        }
        let replacement = try provider.load(applicationTag: staged.applicationTag)
        guard replacement.publicKeyX963 == staged.publicKeyX963 else {
            throw AgentPassNativeError.invalidKey("Recovered audit replacement does not match its exact Keychain binding")
        }
        let statement = try store.transitionStatement(
            role: .auditCheckpoint,
            generation: staged.generation,
            reason: "offline-threshold-recovery:\(verification.requestHash)",
            challengeID: request.nonce,
            createdAt: request.issuedAt,
            continuity: .recovered
        )
        let replacementSignature = try replacement.sign(message: statement.canonicalData())
        let payload = try store.prepareActivationRecordData(
            statement: statement,
            oldSignature: nil,
            newSignature: replacementSignature,
            approvalSignature: evidenceData,
            approvalPublicKeyX963: Data()
        )
        let predicted = try store.validatePreparedRecordData(payload)
        return NativeRecoveredAuditActivationPreparation(
            statement: statement,
            lifecycleRecordData: payload,
            lifecycleHeadHash: predicted.headHash,
            retiringPublicKeyX963: active.publicKeyX963,
            replacementPublicKeyX963: staged.publicKeyX963,
            replacementSignature: replacementSignature
        )
    }

    public func deletionStatement(role: NativeKeyRole, generation: Int, reason: String, challengeID: String, minimumRetirementAgeSeconds: Int, proof: NativeLifecycleDeletionProof) throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        let evidence: (archivedAt: Date, verifiedAt: Date)
        let binding: NativeAuditDeletionIntentBinding?
        if role == .auditCheckpoint {
            guard let verifier = deletionProofVerifier as? any NativeAuditLifecycleDeletionLeaseVerifier else { throw AgentPassNativeError.invalidConfiguration("Audit-key deletion requires a retained-archive lease verifier") }
            let state = try store.verify()
            guard let target = state.generation(generation, for: role), target.status == .retired, proof.lifecycleHeadHash == state.headHash else { throw AgentPassNativeError.invalidSignature("Deletion proof does not bind the current lifecycle state") }
            let leased = try verifier.acquireDeletionEvidenceLease(proof, role: role, generation: generation, fingerprint: target.fingerprint)
            guard let exactBinding = leased.binding else { throw AgentPassNativeError.invalidSignature("Audit-key deletion evidence has no durable spool binding") }
            try leased.revalidateRetainedArchive()
            try validateDeletionEvidenceDates(archivedAt: leased.archivedAt, verifiedAt: leased.verifiedAt, target: target, minimumRetirementAgeSeconds: minimumRetirementAgeSeconds)
            evidence = (leased.archivedAt, leased.verifiedAt); binding = exactBinding
        } else {
            evidence = try verifiedDeletionEvidence(role: role, generation: generation, proof: proof, minimumRetirementAgeSeconds: minimumRetirementAgeSeconds); binding = nil
        }
        return try store.deletionStatement(role: role, generation: generation, reason: reason, challengeID: challengeID, createdAt: Self.timestamp(evidence.verifiedAt), minimumRetirementAgeSeconds: minimumRetirementAgeSeconds, transitionArchived: true, externallyPinnedHeadHash: proof.lifecycleHeadHash, auditDeletionBinding: binding)
    }

    @discardableResult
    public func deleteRetiredServiceKey(role: NativeKeyRole, generation: Int, reason: String, challengeID: String, minimumRetirementAgeSeconds: Int, proof: NativeLifecycleDeletionProof, approvalSignature: Data, approvalPublicKeyX963: Data) throws -> NativeKeyLifecycleSnapshot {
        lock.lock()
        defer { lock.unlock() }
        guard role == .gitSigning || role == .auditCheckpoint else { throw AgentPassNativeError.invalidConfiguration("Approval keys must be deleted by the approval-key client") }
        let leasedEvidence: NativeLifecycleDeletionEvidenceLease?
        let evidence: (archivedAt: Date, verifiedAt: Date)
        if role == .auditCheckpoint {
            guard let verifier = deletionProofVerifier as? any NativeAuditLifecycleDeletionLeaseVerifier else {
                throw AgentPassNativeError.invalidConfiguration("Audit-key deletion requires a retained-archive lease verifier")
            }
            let state = try store.verify()
            guard proof.lifecycleHeadHash == state.headHash,
                  let target = state.generation(generation, for: role), target.status == .retired else {
                throw AgentPassNativeError.invalidSignature("Deletion proof does not bind the current lifecycle state")
            }
            let leased = try verifier.acquireDeletionEvidenceLease(
                proof,
                role: role,
                generation: generation,
                fingerprint: target.fingerprint
            )
            guard leased.binding != nil else { throw AgentPassNativeError.invalidSignature("Audit-key deletion evidence has no durable spool binding") }
            try validateDeletionEvidenceDates(
                archivedAt: leased.archivedAt,
                verifiedAt: leased.verifiedAt,
                target: target,
                minimumRetirementAgeSeconds: minimumRetirementAgeSeconds
            )
            try leased.revalidateRetainedArchive()
            leasedEvidence = leased
            evidence = (leased.archivedAt, leased.verifiedAt)
        } else {
            leasedEvidence = nil
            evidence = try verifiedDeletionEvidence(role: role, generation: generation, proof: proof, minimumRetirementAgeSeconds: minimumRetirementAgeSeconds)
        }
        let timestamp = Self.timestamp(evidence.verifiedAt)
        let beforeIntent = try store.verify()
        try leasedEvidence?.revalidateRetainedArchive()
        let intentPayload = try store.prepareDeletionIntentRecordData(role: role, generation: generation, reason: reason, challengeID: challengeID, createdAt: timestamp, approvalSignature: approvalSignature, approvalPublicKeyX963: approvalPublicKeyX963, minimumRetirementAgeSeconds: minimumRetirementAgeSeconds, transitionArchived: true, externallyPinnedHeadHash: proof.lifecycleHeadHash, auditDeletionBinding: leasedEvidence?.binding)
        let intentHead = try Self.preparedRecordHead(intentPayload)
        let intentPreparation = try prepareDurableMutation(existingPin: try matchingPendingPin(role: role, action: .deletionIntent, oldHead: beforeIntent.headHash), role: role, kind: .deletionIntent, oldState: beforeIntent, newHead: intentHead, createdAt: timestamp, payload: intentPayload)
        var state = mutationOutbox == nil
            ? try store.recordDeletionIntent(role: role, generation: generation, reason: reason, challengeID: challengeID, createdAt: timestamp, approvalSignature: approvalSignature, approvalPublicKeyX963: approvalPublicKeyX963, minimumRetirementAgeSeconds: minimumRetirementAgeSeconds, transitionArchived: true, externallyPinnedHeadHash: proof.lifecycleHeadHash, auditDeletionBinding: leasedEvidence?.binding)
            : try store.appendPreparedRecordData(intentPayload)
        try completeDurableMutation(intentPreparation, oldHead: beforeIntent.headHash, newState: state)
        guard let target = state.generation(generation, for: role), target.status == .deletionIntent else { throw AgentPassNativeError.invalidConfiguration("Lifecycle deletion intent was not persisted") }
        let key = try provider.load(applicationTag: target.applicationTag)
        guard key.publicKeyX963 == target.publicKeyX963 else { throw AgentPassNativeError.invalidKey("Deletion target does not match the exact keychain binding") }
        try leasedEvidence?.revalidateRetainedArchive()
        try provider.delete(applicationTag: target.applicationTag)
        guard try !provider.exists(applicationTag: target.applicationTag) else { throw AgentPassNativeError.invalidKey("Exact lifecycle key remains after deletion") }
        try leasedEvidence?.revalidateRetainedArchive()
        let deletedPayload = try store.prepareDeletedRecordData(role: role, generation: generation, createdAt: timestamp, exactKeyIsAbsent: true)
        let deletedHead = try Self.preparedRecordHead(deletedPayload)
        let deletedPreparation = try prepareDurableMutation(existingPin: try matchingPendingPin(role: role, action: .deleted, oldHead: state.headHash), role: role, kind: .deleted, oldState: state, newHead: deletedHead, createdAt: timestamp, payload: deletedPayload)
        let beforeDeleted = state
        state = mutationOutbox == nil
            ? try store.recordDeleted(role: role, generation: generation, createdAt: timestamp, exactKeyIsAbsent: true)
            : try store.appendPreparedRecordData(deletedPayload)
        try completeDurableMutation(deletedPreparation, oldHead: beforeDeleted.headHash, newState: state)
        return state
    }

    @discardableResult
    public func resumeRecordedDeletion(role: NativeKeyRole, generation: Int) throws -> NativeKeyLifecycleSnapshot {
        lock.lock()
        defer { lock.unlock() }
        let state = try store.verify()
        guard let target = state.generation(generation, for: role), target.status == .deletionIntent else { throw AgentPassNativeError.invalidConfiguration("No lifecycle deletion intent can be resumed") }
        let auditArchiveLease: NativeLifecycleDeletionEvidenceLease?
        if role == .auditCheckpoint {
            guard let verifier = deletionProofVerifier as? any NativeAuditLifecycleDeletionLeaseVerifier else {
                throw AgentPassNativeError.invalidConfiguration("Audit-key deletion recovery requires a retained-archive lease verifier")
            }
            guard let binding = target.auditDeletionBinding, let intentHead = target.deletionIntentLifecycleHead else { throw AgentPassNativeError.invalidSignature("Recorded audit deletion intent has no exact evidence binding") }
            auditArchiveLease = try verifier.acquireRecordedDeletionArchiveLease(
                role: role,
                generation: generation,
                fingerprint: target.fingerprint,
                lifecycleHeadHash: intentHead,
                binding: binding
            )
            guard auditArchiveLease?.binding == binding else { throw AgentPassNativeError.invalidSignature("Recovered audit deletion evidence differs from its signed intent") }
            try auditArchiveLease?.revalidateRetainedArchive()
        } else {
            auditArchiveLease = nil
        }
        guard try !provider.exists(applicationTag: target.applicationTag) else { throw AgentPassNativeError.invalidKey("Deletion cannot be completed while the exact key still exists") }
        try auditArchiveLease?.revalidateRetainedArchive()
        let timestamp = Self.timestamp(now())
        let payload = try store.prepareDeletedRecordData(role: role, generation: generation, createdAt: timestamp, exactKeyIsAbsent: true)
        let newHead = try Self.preparedRecordHead(payload)
        let preparation = try prepareDurableMutation(existingPin: try matchingPendingPin(role: role, action: .deleted, oldHead: state.headHash), role: role, kind: .deleted, oldState: state, newHead: newHead, createdAt: timestamp, payload: payload)
        let next = mutationOutbox == nil
            ? try store.recordDeleted(role: role, generation: generation, createdAt: timestamp, exactKeyIsAbsent: true)
            : try store.appendPreparedRecordData(payload)
        try completeDurableMutation(preparation, oldHead: state.headHash, newState: next)
        try auditArchiveLease?.revalidateRetainedArchive()
        return next
    }

    private func verifiedDeletionEvidence(role: NativeKeyRole, generation: Int, proof: NativeLifecycleDeletionProof, minimumRetirementAgeSeconds: Int) throws -> (archivedAt: Date, verifiedAt: Date) {
        guard let deletionProofVerifier else { throw AgentPassNativeError.invalidConfiguration("Externally signed deletion proof verification is not configured") }
        let state = try store.verify()
        guard proof.lifecycleHeadHash == state.headHash, let target = state.generation(generation, for: role), target.status == .retired,
              proof.transitionReceiptHash.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
            throw AgentPassNativeError.invalidSignature("Deletion proof does not bind the current lifecycle state")
        }
        let evidence = try deletionProofVerifier.verify(proof, role: role, generation: generation, fingerprint: target.fingerprint)
        try validateDeletionEvidenceDates(archivedAt: evidence.archivedAt, verifiedAt: evidence.verifiedAt, target: target, minimumRetirementAgeSeconds: minimumRetirementAgeSeconds)
        return evidence
    }

    private func validateDeletionEvidenceDates(
        archivedAt: Date,
        verifiedAt: Date,
        target: NativeKeyGeneration,
        minimumRetirementAgeSeconds: Int
    ) throws {
        guard let retiredAt = Self.date(target.retiredAt), archivedAt >= retiredAt,
              verifiedAt.timeIntervalSince(archivedAt) >= Double(minimumRetirementAgeSeconds) else {
            throw AgentPassNativeError.invalidConfiguration("Trusted deletion retention interval has not elapsed")
        }
    }

    private struct DurableMutationPreparation {
        let outbox: NativeLifecycleMutationPreparation?
        let pin: NativeLifecyclePinPreparation?
    }

    private func prepareDurableMutation(existingPin: NativeLifecyclePinPreparation?, role: NativeKeyRole, kind: NativeLifecycleMutationKind, oldState: NativeKeyLifecycleSnapshot, newHead: String, createdAt: String, payload: Data) throws -> DurableMutationPreparation {
        guard let mutationOutbox, let pinTransaction else {
            guard let action = NativeLifecyclePinAction(rawValue: kind.rawValue) else {
                throw AgentPassNativeError.invalidConfiguration("Lifecycle mutation kind has no pin action")
            }
            return DurableMutationPreparation(outbox: nil, pin: try preparePin(existing: existingPin, role: role, action: action, oldHead: oldState.headHash, newHead: newHead, preparedAt: createdAt))
        }
        guard existingPin == nil, try mutationOutbox.pending() == nil else {
            throw AgentPassNativeError.invalidSignature("A lifecycle mutation must be recovered before a new mutation starts")
        }
        let pinSequence = (try pinTransaction.current()?.sequence ?? 0) + 1
        let operationID = UUID()
        let outboxPreparation = try mutationOutbox.prepare(
            operationID: operationID,
            pinSequence: pinSequence,
            role: role,
            kind: kind,
            lifecycleSequence: oldState.sequence + 1,
            oldLifecycleHead: oldState.headHash,
            newLifecycleHead: newHead,
            createdAt: createdAt,
            payload: payload
        )
        guard let action = NativeLifecyclePinAction(rawValue: kind.rawValue) else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle mutation kind has no pin action")
        }
        let pinPreparation = try pinTransaction.prepare(operationID: operationID, sequence: pinSequence, role: role, action: action, oldLifecycleHead: oldState.headHash, newLifecycleHead: newHead, preparedAt: createdAt)
        return DurableMutationPreparation(outbox: outboxPreparation, pin: pinPreparation)
    }

    private func completeDurableMutation(_ preparation: DurableMutationPreparation, oldHead: String, newState: NativeKeyLifecycleSnapshot) throws {
        try commitPin(preparation.pin, oldHead: oldHead, newHead: newState.headHash)
        if let mutationOutbox, let outboxPreparation = preparation.outbox {
            guard newState.sequence == outboxPreparation.lifecycleSequence else {
                throw AgentPassNativeError.invalidSignature("Completed lifecycle mutation sequence does not match its outbox")
            }
            _ = try mutationOutbox.complete(outboxPreparation, observedNewLifecycleHead: newState.headHash)
        }
    }

    private static func preparedRecordHead(_ data: Data) throws -> String {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let value = object["record_hash"] as? String,
              value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
            throw AgentPassNativeError.invalidSignature("Prepared lifecycle record has no valid head hash")
        }
        return value
    }

    private func matchingPendingPin(role: NativeKeyRole, action: NativeLifecyclePinAction, oldHead: String) throws -> NativeLifecyclePinPreparation? {
        guard let pinTransaction, let pending = try pinTransaction.pending() else { return nil }
        guard pending.role == role, pending.action == action, pending.oldLifecycleHead == oldHead else {
            throw AgentPassNativeError.invalidSignature("A different lifecycle pin operation is already pending")
        }
        return pending
    }

    private func preparePin(existing: NativeLifecyclePinPreparation?, role: NativeKeyRole, action: NativeLifecyclePinAction, oldHead: String, newHead: String, preparedAt: String) throws -> NativeLifecyclePinPreparation? {
        guard let pinTransaction else { return nil }
        if let existing {
            guard existing.role == role, existing.action == action,
                  existing.oldLifecycleHead == oldHead, existing.newLifecycleHead == newHead else {
                throw AgentPassNativeError.invalidSignature("Retried lifecycle mutation does not match its durable pin preparation")
            }
            return existing
        }
        let sequence = (try pinTransaction.current()?.sequence ?? 0) + 1
        return try pinTransaction.prepare(operationID: UUID(), sequence: sequence, role: role, action: action, oldLifecycleHead: oldHead, newLifecycleHead: newHead, preparedAt: preparedAt)
    }

    private func commitPin(_ preparation: NativeLifecyclePinPreparation?, oldHead: String, newHead: String) throws {
        guard let pinTransaction, let preparation else { return }
        _ = try pinTransaction.commit(preparation, observedOldLifecycleHead: oldHead, observedNewLifecycleHead: newHead)
    }

    private static func timestamp(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }

    private static func date(_ value: String?) -> Date? {
        guard let value else { return nil }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: value)
    }
}
