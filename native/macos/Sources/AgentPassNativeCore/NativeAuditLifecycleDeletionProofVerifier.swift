import Foundation

public protocol NativeLifecycleHeadAncestryVerifier: Sendable {
    func provesCurrentHeadDescendsFrom(ancestorHeadHash: String, currentHeadHash: String) throws -> Bool
}

extension NativeKeyLifecycleStore: NativeLifecycleHeadAncestryVerifier {
    public func provesCurrentHeadDescendsFrom(ancestorHeadHash: String, currentHeadHash: String) throws -> Bool {
        try verifyCurrentHeadDescendsFrom(ancestorHeadHash: ancestorHeadHash, currentHeadHash: currentHeadHash)
    }
}

/// Concrete deletion-proof verification for retired audit-checkpoint keys.
///
/// The verifier snapshots only already-verifiable durable evidence at construction:
/// the latest audit-key transition accepted by the external anchor, a signed prune
/// authorization and receipt, the signed post-prune manifest, and its signed
/// post-deletion completion proof. Caller-provided timestamps in
/// `NativeLifecycleDeletionProof` are never treated as authority.
///
/// The current retention schema does not bind lifecycle transitions for
/// `git_signing` or `session_approval`, and the transition store exposes only its
/// latest verified transition. Those cases therefore fail closed.
public struct NativeAuditLifecycleDeletionProofVerifier: NativeLifecycleDeletionProofVerifier, Sendable {
    private let transitionStore: NativeAuditKeyTransitionStore
    private let lifecycleAncestryVerifier: any NativeLifecycleHeadAncestryVerifier
    private let transitionHash: String
    private let lifecycleHeadHash: String
    private let transitionReceiptHash: String
    private let retiredGeneration: Int
    private let retiredFingerprint: String
    private let archivedAtString: String
    private let verifiedAtString: String
    private let archivedAt: Date
    private let verifiedAt: Date

    /// Builds an immutable proof snapshot from canonical signed artifacts.
    ///
    /// - Parameters:
    ///   - transitionStore: Durable store that re-verifies the complete transition
    ///     chain and its external-anchor receipts when `status()` is read.
    ///   - retentionVerifier: Verifier configured with the trusted retention
    ///     authorizer, external anchor key, tenant, and minimum policy.
    ///   - trustedCurrentBoundary: Boundary obtained from the verified current
    ///     audit/anchor state, not from the deletion request.
    ///   - minimumDeletionRetentionSeconds: Additional local deletion floor. The
    ///     signed authorization may increase, but never lower, this interval.
    public init(
        transitionStore: NativeAuditKeyTransitionStore,
        lifecycleAncestryVerifier: any NativeLifecycleHeadAncestryVerifier,
        retentionVerifier: NativeAuditRetentionVerifier,
        authorizationData: Data,
        pruneReceiptData: Data,
        postPruneManifestData: Data,
        completionProofData: Data,
        completionStatementData: Data,
        quarantinedMarkerData: Data,
        manifestCommitMarkerData: Data,
        priorPruneState: NativeAuditPruneChainState,
        trustedCurrentBoundary: NativeAuditRetentionBoundary,
        expectedNextRetained: NativeAuditRetentionSegment,
        expectedNextRetainedFileIdentities: [NativeAuditRetentionFileIdentity],
        minimumDeletionRetentionSeconds: Int,
        now: Date = Date()
    ) throws {
        guard minimumDeletionRetentionSeconds > 0,
              minimumDeletionRetentionSeconds <= NativeAuditRetentionVerifier.maximumSafeInteger else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle deletion retention policy is invalid")
        }

        let status = try transitionStore.status()
        guard status.count > 0,
              let transition = status.latestTransition,
              let transitionReceipt = status.latestReceipt else {
            throw AgentPassNativeError.invalidSignature("Deletion proof is missing a verified audit-key transition and external receipt")
        }
        guard transitionReceipt.transitionHash == transition.transitionHash else {
            throw AgentPassNativeError.invalidSignature("Deletion proof transition store does not bind its latest external receipt")
        }
        guard try lifecycleAncestryVerifier.provesCurrentHeadDescendsFrom(
            ancestorHeadHash: transition.lifecycleHeadHash,
            currentHeadHash: trustedCurrentBoundary.lifecycleHeadHash
        ) else {
            throw AgentPassNativeError.invalidSignature("Deletion proof lifecycle boundary does not descend from the anchored audit-key transition")
        }
        guard trustedCurrentBoundary.auditKeyTransitionReceiptHash == transitionReceipt.receiptHash else {
            throw AgentPassNativeError.invalidSignature("Deletion proof current boundary does not bind the exact audit-key transition receipt")
        }

        // Completion time is authoritative only when bound to the executor's durable
        // post-unlink statement by the signed completion proof.
        let manifest = try NativeAuditPostPruneManifest.decodeCanonical(postPruneManifestData)
        let completionStatement = try NativeAuditPruneExecutorCompletionStatement.decodeCanonical(completionStatementData)
        let completionProof = try NativeAuditPruneCompletionProof.decodeCanonical(completionProofData)
        guard manifest.expectedNextRetainedHash != NativeAuditLog.zeroHash,
              manifest.retainedIdentityHash != NativeAuditLog.zeroHash,
              completionProof.expectedNextRetainedHash != NativeAuditLog.zeroHash,
              completionProof.retainedIdentityHash != NativeAuditLog.zeroHash,
              expectedNextRetainedFileIdentities.count == 3,
              let completion = Self.date(completionStatement.completedAt) else {
            throw AgentPassNativeError.invalidSignature("Deletion proof requires non-null schema-v3 retained and executor-completion evidence")
        }
        guard completion <= now else {
            throw AgentPassNativeError.invalidSignature("Deletion proof post-prune completion time is in the future")
        }

        _ = try retentionVerifier.verifyCompletedPruneEvidence(
            authorizationData: authorizationData,
            receiptData: pruneReceiptData,
            manifestData: postPruneManifestData,
            completionProofData: completionProofData,
            completionStatementData: completionStatementData,
            quarantinedMarkerData: quarantinedMarkerData,
            manifestCommitMarkerData: manifestCommitMarkerData,
            prior: priorPruneState,
            currentBoundary: trustedCurrentBoundary,
            expectedNextRetained: expectedNextRetained,
            expectedNextRetainedFileIdentities: expectedNextRetainedFileIdentities
        )
        let authorization = try NativeAuditPruneAuthorization.decodeCanonical(authorizationData)
        let receipt = try NativeAuditPruneReceipt.decodeCanonical(pruneReceiptData)

        guard manifest.lifecycleHeadHash == trustedCurrentBoundary.lifecycleHeadHash,
              manifest.auditKeyTransitionReceiptHash == transitionReceipt.receiptHash,
              authorization.boundary.lifecycleHeadHash == trustedCurrentBoundary.lifecycleHeadHash,
              authorization.boundary.auditKeyTransitionReceiptHash == transitionReceipt.receiptHash,
              receipt.receiptHash == manifest.pruneReceiptHash else {
            throw AgentPassNativeError.invalidSignature("Deletion proof retention evidence is missing the lifecycle-head or transition-receipt binding")
        }
        guard authorization.retentionSeconds >= minimumDeletionRetentionSeconds else {
            throw AgentPassNativeError.invalidConfiguration("Deletion proof attempts to downgrade the minimum retention policy")
        }
        let segmentAnchorDates = authorization.segments.compactMap { Self.date($0.latestAnchorReceivedAt) }
        guard segmentAnchorDates.count == authorization.segments.count,
              let latestSegmentAnchor = segmentAnchorDates.max(),
              completion >= latestSegmentAnchor.addingTimeInterval(TimeInterval(authorization.retentionSeconds)) else {
            throw AgentPassNativeError.invalidConfiguration("Pruned audit segments had not satisfied the signed retention interval at completion")
        }
        guard let transitionArchived = Self.date(transitionReceipt.receivedAt),
              completion >= transitionArchived else {
            throw AgentPassNativeError.invalidSignature("Deletion proof signed timestamps are not monotonic")
        }
        let requiredInterval = max(minimumDeletionRetentionSeconds, authorization.retentionSeconds)
        guard completion.timeIntervalSince(transitionArchived) >= TimeInterval(requiredInterval) else {
            throw AgentPassNativeError.invalidConfiguration("Externally archived audit-key transition has not satisfied the signed retention interval")
        }

        lifecycleHeadHash = trustedCurrentBoundary.lifecycleHeadHash
        self.transitionStore = transitionStore
        self.lifecycleAncestryVerifier = lifecycleAncestryVerifier
        transitionHash = transition.transitionHash
        transitionReceiptHash = transitionReceipt.receiptHash
        retiredGeneration = transition.fromGeneration
        retiredFingerprint = transition.oldKeyFingerprint
        archivedAtString = transitionReceipt.receivedAt
        verifiedAtString = completionStatement.completedAt
        archivedAt = transitionArchived
        verifiedAt = completion
    }

    public func verify(
        _ proof: NativeLifecycleDeletionProof,
        role: NativeKeyRole,
        generation: Int,
        fingerprint: String
    ) throws -> (archivedAt: Date, verifiedAt: Date) {
        let currentTransitionState = try transitionStore.status()
        guard let currentTransition = currentTransitionState.latestTransition,
              currentTransition.transitionHash == transitionHash,
              currentTransitionState.latestReceipt?.receiptHash == transitionReceiptHash,
              try lifecycleAncestryVerifier.provesCurrentHeadDescendsFrom(
                ancestorHeadHash: currentTransition.lifecycleHeadHash,
                currentHeadHash: lifecycleHeadHash
              ) else {
            throw AgentPassNativeError.invalidSignature("Deletion proof evidence changed after verification")
        }
        guard role == .auditCheckpoint else {
            throw AgentPassNativeError.invalidSignature("Deletion proof has no externally archived transition binding for this key role")
        }
        guard generation == retiredGeneration, fingerprint == retiredFingerprint else {
            throw AgentPassNativeError.invalidSignature("Deletion proof does not identify the retired audit-key generation and fingerprint")
        }
        guard proof.lifecycleHeadHash == lifecycleHeadHash,
              proof.transitionReceiptHash == transitionReceiptHash else {
            throw AgentPassNativeError.invalidSignature("Deletion proof does not bind the current lifecycle head and exact transition receipt")
        }
        guard proof.transitionArchivedAt == archivedAtString,
              proof.verifiedAt == verifiedAtString else {
            throw AgentPassNativeError.invalidSignature("Deletion proof contains caller timestamps that differ from signed evidence")
        }
        return (archivedAt, verifiedAt)
    }

    private static func date(_ value: String) -> Date? {
        guard !value.isEmpty, value.utf8.count <= 64 else { return nil }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let result = fractional.date(from: value) { return result }
        let whole = ISO8601DateFormatter()
        whole.formatOptions = [.withInternetDateTime]
        return whole.date(from: value)
    }
}
