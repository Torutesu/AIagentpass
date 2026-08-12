import AgentPassNativeCore
import Darwin
import Foundation

/// Breaks the lifecycle-coordinator/service-store construction cycle without ever
/// providing a permissive fallback. Until a provider is installed, verification
/// fails closed. The provider rebuilds the Core verifier for every call.
final class ServiceLifecycleDeletionProofVerifierBox: NativeAuditLifecycleDeletionLeaseVerifier, @unchecked Sendable {
    private let lock = NSLock()
    private var provider: ServiceAuditKeyDeletionEvidenceProvider?

    func install(_ value: ServiceAuditKeyDeletionEvidenceProvider) throws {
        lock.lock()
        defer { lock.unlock() }
        guard provider == nil else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle deletion proof provider is already installed")
        }
        provider = value
    }

    func verify(
        _ proof: NativeLifecycleDeletionProof,
        role: NativeKeyRole,
        generation: Int,
        fingerprint: String
    ) throws -> (archivedAt: Date, verifiedAt: Date) {
        lock.lock()
        let current = provider
        lock.unlock()
        guard let current else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle deletion proof provider is not installed")
        }
        return try current.makeVerifier().verify(proof, role: role, generation: generation, fingerprint: fingerprint)
    }

    func acquireDeletionEvidenceLease(
        _ proof: NativeLifecycleDeletionProof,
        role: NativeKeyRole,
        generation: Int,
        fingerprint: String
    ) throws -> NativeLifecycleDeletionEvidenceLease {
        lock.lock()
        let current = provider
        lock.unlock()
        guard let current else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle deletion proof provider is not installed")
        }
        return try current.acquireDeletionEvidenceLease(
            proof,
            role: role,
            generation: generation,
            fingerprint: fingerprint
        )
    }

    func acquireRecordedDeletionArchiveLease(
        role: NativeKeyRole,
        generation: Int,
        fingerprint: String,
        lifecycleHeadHash: String,
        binding: NativeAuditDeletionIntentBinding
    ) throws -> NativeLifecycleDeletionEvidenceLease {
        lock.lock()
        let current = provider
        lock.unlock()
        guard let current else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle deletion proof provider is not installed")
        }
        return try current.acquireRecordedDeletionArchiveLease(
            role: role,
            generation: generation,
            fingerprint: fingerprint,
            lifecycleHeadHash: lifecycleHeadHash,
            binding: binding
        )
    }
}

/// Trusted Service-owned inputs for retired audit-checkpoint key deletion.
/// None of these artifacts is accepted over XPC.
final class ServiceAuditKeyDeletionEvidenceProvider: @unchecked Sendable {
    static let maximumBundleBytes = NativeAuditRetentionVerifier.maximumDocumentBytes * 7

    private let evidenceBundlePath: String
    private let archiveDirectory: String
    private let recoverySpoolDirectory: String
    private let lifecycleStore: NativeKeyLifecycleStore
    private let transitionStore: NativeAuditKeyTransitionStore
    private let auditLog: NativeAuditLog
    private let checkpoints: NativeAuditCheckpoints
    private let anchorReceipts: NativeAuditAnchorReceipts
    private let retentionVerifier: NativeAuditRetentionVerifier
    private let minimumRetentionSeconds: Int

    init(
        evidenceBundlePath: String,
        archiveDirectory: String,
        tenant: String,
        retentionAuthorizerPublicKeyX963: Data,
        anchorPublicKeyPEM: String,
        minimumRetentionSeconds: Int,
        lifecycleStore: NativeKeyLifecycleStore,
        transitionStore: NativeAuditKeyTransitionStore,
        auditLog: NativeAuditLog,
        checkpoints: NativeAuditCheckpoints,
        anchorReceipts: NativeAuditAnchorReceipts
    ) throws {
        guard evidenceBundlePath.hasPrefix("/"), archiveDirectory.hasPrefix("/"),
              minimumRetentionSeconds > 0,
              minimumRetentionSeconds <= NativeAuditRetentionVerifier.maximumSafeInteger else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key deletion evidence configuration is invalid")
        }
        self.evidenceBundlePath = URL(fileURLWithPath: evidenceBundlePath).standardizedFileURL.path
        self.archiveDirectory = URL(fileURLWithPath: archiveDirectory).standardizedFileURL.path
        recoverySpoolDirectory = URL(fileURLWithPath: evidenceBundlePath).deletingLastPathComponent().appendingPathComponent(".agentpass-audit-key-deletion-spool", isDirectory: true).standardizedFileURL.path
        try NativeAuditDeletionRecoverySpool.ensureRoot(recoverySpoolDirectory)
        self.lifecycleStore = lifecycleStore
        self.transitionStore = transitionStore
        self.auditLog = auditLog
        self.checkpoints = checkpoints
        self.anchorReceipts = anchorReceipts
        self.minimumRetentionSeconds = minimumRetentionSeconds
        retentionVerifier = try NativeAuditRetentionVerifier(
            tenant: tenant,
            authorizerPublicKeyX963: retentionAuthorizerPublicKeyX963,
            anchorPublicKeyPEM: anchorPublicKeyPEM,
            minimumRetentionSeconds: minimumRetentionSeconds
        )
    }

    /// Called once before the listener starts. Operations call this same path again.
    func validate() throws {
        let lifecycle = try lifecycleStore.verify()
        if let pending = lifecycle.generations.first(where: { $0.role == .auditCheckpoint && $0.status == .deletionIntent }) {
            guard let binding = pending.auditDeletionBinding,
                  let intentHead = pending.deletionIntentLifecycleHead else {
                throw AgentPassNativeError.invalidSignature("Recorded audit deletion intent has no exact evidence binding")
            }
            _ = try acquireRecordedDeletionArchiveLease(
                role: .auditCheckpoint,
                generation: pending.generation,
                fingerprint: pending.fingerprint,
                lifecycleHeadHash: intentHead,
                binding: binding
            )
        } else {
            _ = try makeVerifier()
        }
    }

    func makeVerifier(now: Date = Date()) throws -> NativeAuditLifecycleDeletionProofVerifier {
        let evidence = try loadEvidenceBundle()
        _ = try makeArchiveLease(evidence)
        let boundary = try trustedBoundary()
        return try NativeAuditLifecycleDeletionProofVerifier(
            transitionStore: transitionStore,
            lifecycleAncestryVerifier: lifecycleStore,
            retentionVerifier: retentionVerifier,
            authorizationData: evidence.authorizationData,
            pruneReceiptData: evidence.pruneReceiptData,
            postPruneManifestData: evidence.manifestData,
            completionProofData: evidence.completionProofData,
            completionStatementData: evidence.completionStatementData,
            quarantinedMarkerData: evidence.quarantinedMarkerData,
            manifestCommitMarkerData: evidence.manifestCommitMarkerData,
            priorPruneState: evidence.priorState,
            trustedCurrentBoundary: boundary,
            expectedNextRetained: evidence.expectedNextRetained,
            expectedNextRetainedFileIdentities: evidence.expectedNextRetainedFileIdentities,
            minimumDeletionRetentionSeconds: minimumRetentionSeconds,
            now: now
        )
    }

    func acquireDeletionEvidenceLease(
        _ proof: NativeLifecycleDeletionProof,
        role: NativeKeyRole,
        generation: Int,
        fingerprint: String,
        now: Date = Date()
    ) throws -> NativeLifecycleDeletionEvidenceLease {
        let evidence = try loadEvidenceBundle()
        let archiveLease = try makeArchiveLease(evidence)
        let boundary = try trustedBoundary()
        let verifier = try makeVerifier(evidence: evidence, boundary: boundary, now: now)
        let times = try verifier.verify(proof, role: role, generation: generation, fingerprint: fingerprint)
        let prepared = try NativeAuditDeletionRecoverySpool.prepare(
            rootPath: recoverySpoolDirectory,
            bundleData: evidence.bundleData,
            segment: evidence.expectedNextRetained,
            identities: evidence.expectedNextRetainedFileIdentities,
            sourceLease: archiveLease
        )
        try archiveLease.revalidate()
        try prepared.spoolLease.revalidate()
        return NativeLifecycleDeletionEvidenceLease(
            archivedAt: times.archivedAt,
            verifiedAt: times.verifiedAt,
            archiveLease: archiveLease,
            binding: prepared.binding,
            spoolLease: prepared.spoolLease
        )
    }

    func acquireRecordedDeletionArchiveLease(
        role: NativeKeyRole,
        generation: Int,
        fingerprint: String,
        lifecycleHeadHash: String,
        binding: NativeAuditDeletionIntentBinding
    ) throws -> NativeLifecycleDeletionEvidenceLease {
        guard role == .auditCheckpoint else {
            throw AgentPassNativeError.invalidConfiguration("Retained archive leases apply only to audit-checkpoint keys")
        }
        let spool = try NativeAuditDeletionRecoverySpool.open(rootPath: recoverySpoolDirectory, binding: binding)
        let evidence = try Self.loadEvidenceBundle(data: spool.bundleData)
        let archiveLease = try makeArchiveLease(evidence)
        guard archiveLease.pathChainHash == binding.archivePathChainHash else {
            throw AgentPassNativeError.invalidSignature("Recorded audit deletion archive path chain differs from its signed intent")
        }
        try archiveLease.revalidate()
        let status = try transitionStore.status()
        guard let transition = status.latestTransition,
              let receipt = status.latestReceipt,
              receipt.transitionHash == transition.transitionHash,
              transition.fromGeneration == generation,
              transition.oldKeyFingerprint == fingerprint else {
            throw AgentPassNativeError.invalidSignature("Recorded audit-key deletion does not match the retained evidence transition")
        }
        let authorization = try NativeAuditPruneAuthorization.decodeCanonical(evidence.authorizationData)
        guard NativeAuditDeletionEvidenceHash.canonicalData(evidence.bundleData) == binding.bundleSHA256,
              authorization.operationID == binding.operationID,
              try NativeAuditDeletionEvidenceHash.retainedSegment(evidence.expectedNextRetained) == binding.retainedSegmentHash,
              try NativeAuditDeletionEvidenceHash.retainedIdentities(evidence.expectedNextRetainedFileIdentities) == binding.retainedIdentityHash else {
            throw AgentPassNativeError.invalidSignature("Recorded deletion intent and spooled bundle differ")
        }
        let boundary = try trustedBoundary(lifecycleHeadOverride: lifecycleHeadHash)
        let verifier = try makeVerifier(evidence: evidence, boundary: boundary, now: Date())
        let completion = try NativeAuditPruneExecutorCompletionStatement.decodeCanonical(evidence.completionStatementData)
        let proof = NativeLifecycleDeletionProof(lifecycleHeadHash: lifecycleHeadHash, transitionReceiptHash: receipt.receiptHash, transitionArchivedAt: receipt.receivedAt, verifiedAt: completion.completedAt)
        let times = try verifier.verify(proof, role: role, generation: generation, fingerprint: fingerprint)
        try spool.revalidate()
        return NativeLifecycleDeletionEvidenceLease(archivedAt: times.archivedAt, verifiedAt: times.verifiedAt, archiveLease: archiveLease, binding: binding, spoolLease: spool)
    }

    private func makeVerifier(
        evidence: Evidence,
        boundary: NativeAuditRetentionBoundary,
        now: Date
    ) throws -> NativeAuditLifecycleDeletionProofVerifier {
        try NativeAuditLifecycleDeletionProofVerifier(
            transitionStore: transitionStore,
            lifecycleAncestryVerifier: lifecycleStore,
            retentionVerifier: retentionVerifier,
            authorizationData: evidence.authorizationData,
            pruneReceiptData: evidence.pruneReceiptData,
            postPruneManifestData: evidence.manifestData,
            completionProofData: evidence.completionProofData,
            completionStatementData: evidence.completionStatementData,
            quarantinedMarkerData: evidence.quarantinedMarkerData,
            manifestCommitMarkerData: evidence.manifestCommitMarkerData,
            priorPruneState: evidence.priorState,
            trustedCurrentBoundary: boundary,
            expectedNextRetained: evidence.expectedNextRetained,
            expectedNextRetainedFileIdentities: evidence.expectedNextRetainedFileIdentities,
            minimumDeletionRetentionSeconds: minimumRetentionSeconds,
            now: now
        )
    }

    private func makeArchiveLease(_ evidence: Evidence) throws -> NativeAuditRetainedArchiveLease {
        try NativeAuditRetainedArchiveLease(
            archiveDirectory: archiveDirectory,
            segment: evidence.expectedNextRetained,
            expectedFileIdentities: evidence.expectedNextRetainedFileIdentities
        )
    }

    private func trustedBoundary(lifecycleHeadOverride: String? = nil) throws -> NativeAuditRetentionBoundary {
        let lifecycle = try lifecycleStore.verify()
        guard let activeAudit = lifecycle.active(for: .auditCheckpoint) else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key deletion requires an active lifecycle audit key")
        }

        let transitionStatus = try transitionStore.status()
        guard transitionStatus.count > 0,
              let transition = transitionStatus.latestTransition,
              transitionStatus.latestRecoveryTransition == nil,
              let transitionReceipt = transitionStatus.latestReceipt,
              transitionReceipt.transitionHash == transition.transitionHash,
              transitionStatus.latestEventIndex == transitionReceipt.eventIndex,
              transitionStatus.latestEventHash == transitionReceipt.receiptHash,
              transition.toGeneration == activeAudit.generation,
              transition.newKeyFingerprint == activeAudit.fingerprint else {
            throw AgentPassNativeError.invalidSignature("Audit-key deletion requires the latest verified non-recovery audit transition and active generation")
        }

        let audit = try auditLog.verify()
        let verifiedCheckpoints = try checkpoints.verify()
        let receiptStatus = try anchorReceipts.status(checkpoints: verifiedCheckpoints)
        let verifiedReceipts = try anchorReceipts.verifiedReceipts(checkpoints: verifiedCheckpoints)
        guard receiptStatus.pending == 0,
              receiptStatus.checkpoints == verifiedCheckpoints.count,
              receiptStatus.receipts == verifiedReceipts.count,
              let checkpoint = verifiedCheckpoints.last,
              let checkpointReceipt = verifiedReceipts.last,
              checkpoint.entries == audit.entries,
              checkpoint.headHash == audit.headHash,
              checkpointReceipt.version == 2,
              checkpointReceipt.index == verifiedCheckpoints.count,
              checkpointReceipt.checkpointHash == checkpoint.checkpointHash,
              receiptStatus.latestReceiptHash == checkpointReceipt.receiptHash,
              let checkpointEventIndex = checkpointReceipt.eventIndex,
              checkpointReceipt.previousEventHash != nil,
              transition.lastCheckpointIndex == verifiedCheckpoints.count,
              transition.lastCheckpointHash == checkpoint.checkpointHash,
              transition.lastCheckpointReceiptHash == checkpointReceipt.receiptHash,
              transition.previousAnchorEventIndex == checkpointEventIndex,
              transition.previousAnchorEventHash == checkpointReceipt.receiptHash,
              transitionReceipt.lastCheckpointIndex == verifiedCheckpoints.count,
              transitionReceipt.lastCheckpointHash == checkpoint.checkpointHash,
              transitionReceipt.lastCheckpointReceiptHash == checkpointReceipt.receiptHash,
              transitionReceipt.eventIndex == checkpointEventIndex + 1,
              transitionReceipt.previousEventHash == checkpointReceipt.receiptHash else {
            throw AgentPassNativeError.invalidSignature("Audit-key deletion evidence is stale or not bound to the fully anchored latest checkpoint event")
        }

        if let lifecycleHeadOverride {
            guard try lifecycleStore.provesCurrentHeadDescendsFrom(ancestorHeadHash: lifecycleHeadOverride, currentHeadHash: lifecycle.headHash) else { throw AgentPassNativeError.invalidSignature("Recorded deletion lifecycle intent is not an ancestor of current state") }
        }
        return NativeAuditRetentionBoundary(
            lifecycleHeadHash: lifecycleHeadOverride ?? lifecycle.headHash,
            auditKeyTransitionReceiptHash: transitionReceipt.receiptHash,
            anchorEventIndex: transitionReceipt.eventIndex,
            anchorEventHash: transitionReceipt.receiptHash,
            checkpointIndex: verifiedCheckpoints.count,
            checkpointHash: checkpoint.checkpointHash,
            checkpointReceiptHash: checkpointReceipt.receiptHash
        )
    }

    fileprivate struct Evidence {
        let bundleData: Data
        let authorizationData: Data
        let pruneReceiptData: Data
        let manifestData: Data
        let completionProofData: Data
        let completionStatementData: Data
        let quarantinedMarkerData: Data
        let manifestCommitMarkerData: Data
        let priorState: NativeAuditPruneChainState
        let expectedNextRetained: NativeAuditRetentionSegment
        let expectedNextRetainedFileIdentities: [NativeAuditRetentionFileIdentity]
    }

    private func loadEvidenceBundle() throws -> Evidence {
        try Self.loadEvidenceBundle(path: evidenceBundlePath)
    }

    private static func loadEvidenceBundle(path evidenceBundlePath: String) throws -> Evidence {
        try loadEvidenceBundle(data: Self.readProtectedRegularFile(path: evidenceBundlePath, maximumBytes: Self.maximumBundleBytes, label: "Audit-key deletion evidence bundle"))
    }

    private static func loadEvidenceBundle(data: Data) throws -> Evidence {
        let rootKeys: Set<String> = [
            "version", "authorization_base64", "anchor_prune_receipt_base64",
            "post_prune_manifest_base64", "completion_proof_base64",
            "executor_completion_statement_base64", "executor_quarantined_marker_base64",
            "executor_manifest_commit_marker_base64", "prior_chain_state",
            "expected_next_retained", "expected_next_retained_file_identities"
        ]
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == rootKeys,
              try Self.canonical(object) == data,
              Self.exactInteger(object["version"]) == 4,
              let authorizationData = Self.canonicalBase64(object["authorization_base64"]),
              let pruneReceiptData = Self.canonicalBase64(object["anchor_prune_receipt_base64"]),
              let manifestData = Self.canonicalBase64(object["post_prune_manifest_base64"]),
              let completionProofData = Self.canonicalBase64(object["completion_proof_base64"]),
              let completionStatementData = Self.canonicalBase64(object["executor_completion_statement_base64"]),
              let quarantinedMarkerData = Self.canonicalBase64(object["executor_quarantined_marker_base64"]),
              let manifestCommitMarkerData = Self.canonicalBase64(object["executor_manifest_commit_marker_base64"]),
              authorizationData.count <= NativeAuditRetentionVerifier.maximumDocumentBytes,
              pruneReceiptData.count <= NativeAuditRetentionVerifier.maximumDocumentBytes,
              manifestData.count <= NativeAuditRetentionVerifier.maximumDocumentBytes,
              completionProofData.count <= NativeAuditRetentionVerifier.maximumDocumentBytes,
              completionStatementData.count <= 4096,
              quarantinedMarkerData.count <= 4096,
              manifestCommitMarkerData.count <= 4096,
              let priorObject = object["prior_chain_state"] as? [String: Any] else {
            throw AgentPassNativeError.invalidSignature("Audit-key deletion evidence bundle is not exact canonical schema")
        }

        // Decode every signed document now so malformed or noncanonical bytes fail at startup,
        // before any archive path from the authorization is used.
        _ = try NativeAuditPruneAuthorization.decodeCanonical(authorizationData)
        _ = try NativeAuditPruneReceipt.decodeCanonical(pruneReceiptData)
        _ = try NativeAuditPostPruneManifest.decodeCanonical(manifestData)
        _ = try NativeAuditPruneCompletionProof.decodeCanonical(completionProofData)
        _ = try NativeAuditPruneExecutorCompletionStatement.decodeCanonical(completionStatementData)
        let prior = try Self.priorState(priorObject)
        let retained = try Self.expectedSegment(object["expected_next_retained"])
        let retainedIdentities = try Self.expectedFileIdentities(
            object["expected_next_retained_file_identities"],
            retained: retained
        )
        return Evidence(
            bundleData: data,
            authorizationData: authorizationData,
            pruneReceiptData: pruneReceiptData,
            manifestData: manifestData,
            completionProofData: completionProofData,
            completionStatementData: completionStatementData,
            quarantinedMarkerData: quarantinedMarkerData,
            manifestCommitMarkerData: manifestCommitMarkerData,
            priorState: prior,
            expectedNextRetained: retained,
            expectedNextRetainedFileIdentities: retainedIdentities
        )
    }

    private static func priorState(_ object: [String: Any]) throws -> NativeAuditPruneChainState {
        let keys: Set<String> = [
            "sequence", "authorization_hash", "receipt_hash", "manifest_hash",
            "last_event_index", "last_checkpoint_index", "last_receipt_index",
            "last_event_hash", "last_checkpoint_hash", "last_archive_receipt_hash"
        ]
        guard Set(object.keys) == keys,
              let sequence = exactInteger(object["sequence"]), sequence >= 0,
              let lastEventIndex = exactInteger(object["last_event_index"]), lastEventIndex >= 0,
              let lastCheckpointIndex = exactInteger(object["last_checkpoint_index"]), lastCheckpointIndex >= 0,
              let lastReceiptIndex = exactInteger(object["last_receipt_index"]), lastReceiptIndex >= 0,
              let authorizationHash = hash(object["authorization_hash"]),
              let receiptHash = hash(object["receipt_hash"]),
              let manifestHash = hash(object["manifest_hash"]),
              let lastEventHash = hash(object["last_event_hash"]),
              let lastCheckpointHash = hash(object["last_checkpoint_hash"]),
              let lastArchiveReceiptHash = hash(object["last_archive_receipt_hash"]) else {
            throw AgentPassNativeError.invalidSignature("Audit-key deletion prior prune state is not exact schema")
        }
        if sequence == 0 {
            guard lastEventIndex == 0, lastCheckpointIndex == 0, lastReceiptIndex == 0,
                  [authorizationHash, receiptHash, manifestHash, lastEventHash, lastCheckpointHash, lastArchiveReceiptHash]
                    .allSatisfy({ $0 == NativeAuditLog.zeroHash }) else {
                throw AgentPassNativeError.invalidSignature("Initial audit prune state is not the exact zero state")
            }
        } else {
            guard lastEventIndex > 0, lastCheckpointIndex > 0, lastReceiptIndex > 0,
                  ![authorizationHash, receiptHash, manifestHash, lastEventHash, lastCheckpointHash, lastArchiveReceiptHash]
                    .contains(NativeAuditLog.zeroHash) else {
                throw AgentPassNativeError.invalidSignature("Noninitial audit prune state is incomplete")
            }
        }
        return NativeAuditPruneChainState(
            sequence: sequence,
            authorizationHash: authorizationHash,
            receiptHash: receiptHash,
            manifestHash: manifestHash,
            lastEventIndex: lastEventIndex,
            lastCheckpointIndex: lastCheckpointIndex,
            lastReceiptIndex: lastReceiptIndex,
            lastEventHash: lastEventHash,
            lastCheckpointHash: lastCheckpointHash,
            lastArchiveReceiptHash: lastArchiveReceiptHash
        )
    }

    private static func expectedSegment(_ value: Any?) throws -> NativeAuditRetentionSegment {
        let keys: Set<String> = [
            "segment_id", "audit_archive_file", "audit_archive_sha256", "first_event_index", "last_event_index",
            "previous_event_hash", "terminal_event_hash", "checkpoint_archive_file", "checkpoint_archive_sha256",
            "first_checkpoint_index", "last_checkpoint_index", "previous_checkpoint_hash", "terminal_checkpoint_hash",
            "receipt_archive_file", "receipt_archive_sha256", "first_receipt_index", "last_receipt_index",
            "previous_receipt_hash", "terminal_receipt_hash", "anchored_event_index", "anchored_event_hash",
            "sealed_at", "latest_anchor_received_at"
        ]
        guard let object = value as? [String: Any], Set(object.keys) == keys else {
            throw AgentPassNativeError.invalidSignature("Audit-key deletion expected retained segment is not exact schema")
        }
        let encoded = try canonical(object)
        return try JSONDecoder().decode(NativeAuditRetentionSegment.self, from: encoded)
    }

    private static func expectedFileIdentities(
        _ value: Any?,
        retained: NativeAuditRetentionSegment
    ) throws -> [NativeAuditRetentionFileIdentity] {
        let keys = Set(["name", "device", "inode", "mode", "owner", "group", "linkCount", "size", "sha256"])
        guard let objects = value as? [[String: Any]], objects.count == 3 else {
            throw AgentPassNativeError.invalidSignature("Audit-key deletion retained file identities are not exact non-null schema")
        }
        let identities = try objects.map { object -> NativeAuditRetentionFileIdentity in
            guard Set(object.keys) == keys else {
                throw AgentPassNativeError.invalidSignature("Audit-key deletion retained file identity has unknown or missing fields")
            }
            let encoded = try canonical(object)
            let identity = try JSONDecoder().decode(NativeAuditRetentionFileIdentity.self, from: encoded)
            guard identity.linkCount == 1,
                  identity.size > 0,
                  identity.size <= NativeAuditRetentionArchiveObservation.maximumArchiveBytes,
                  (identity.mode & UInt32(S_IFMT)) == UInt32(S_IFREG),
                  identity.mode & 0o077 == 0,
                  hash(identity.sha256) != nil else {
                throw AgentPassNativeError.invalidSignature("Audit-key deletion retained file identity is invalid")
            }
            return identity
        }
        guard identities.map(\.name) == [
            retained.auditArchiveFile,
            retained.checkpointArchiveFile,
            retained.receiptArchiveFile,
        ], identities.map(\.sha256) == [
            retained.auditArchiveSHA256,
            retained.checkpointArchiveSHA256,
            retained.receiptArchiveSHA256,
        ], Set(identities.map(\.name)).count == 3 else {
            throw AgentPassNativeError.invalidSignature("Audit-key deletion retained identities do not bind the exact retained segment")
        }
        return identities
    }

    private static func canonicalBase64(_ value: Any?) -> Data? {
        guard let text = value as? String, text.utf8.count <= maximumBundleBytes,
              let result = Data(base64Encoded: text), result.base64EncodedString() == text else { return nil }
        return result
    }

    private static func hash(_ value: Any?) -> String? {
        guard let value = value as? String,
              value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else { return nil }
        return value
    }

    private static func exactInteger(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber,
              String(cString: number.objCType) != "c",
              CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        let double = number.doubleValue
        guard double.isFinite, double.rounded(.towardZero) == double,
              double >= 0, double <= Double(NativeAuditRetentionVerifier.maximumSafeInteger),
              let result = Int(exactly: double) else { return nil }
        return result
    }

    private static func canonical(_ object: [String: Any]) throws -> Data {
        guard JSONSerialization.isValidJSONObject(object) else {
            throw AgentPassNativeError.invalidSignature("Audit-key deletion evidence contains invalid JSON")
        }
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    }

    private static func readProtectedRegularFile(path: String, maximumBytes: Int, label: String) throws -> Data {
        let url = URL(fileURLWithPath: path).standardizedFileURL
        guard url.path.hasPrefix("/"), url.path != "/", url.resolvingSymlinksInPath().path == url.path else {
            throw AgentPassNativeError.invalidConfiguration("\(label) path must be absolute and contain no symbolic links")
        }
        var current = url.deletingLastPathComponent()
        while true {
            var info = stat()
            guard lstat(current.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
                  info.st_uid == 0, info.st_mode & 0o022 == 0 else {
                throw AgentPassNativeError.invalidConfiguration("\(label) ancestry must be root-owned directories without group/world write permission")
            }
            if current.path == "/" { break }
            current.deleteLastPathComponent()
        }
        let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { close(descriptor) }
        var before = stat()
        guard fstat(descriptor, &before) == 0, (before.st_mode & S_IFMT) == S_IFREG,
              before.st_uid == 0, before.st_mode & 0o077 == 0, before.st_nlink == 1,
              before.st_size > 0, before.st_size <= maximumBytes else {
            throw AgentPassNativeError.invalidConfiguration("\(label) must be a private root-owned single-link regular file within its size limit")
        }
        var bytes = Data()
        bytes.reserveCapacity(Int(before.st_size))
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = Darwin.read(descriptor, &buffer, buffer.count)
            guard count >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            if count == 0 { break }
            guard bytes.count <= maximumBytes - count else {
                throw AgentPassNativeError.invalidSignature("\(label) exceeds its verification limit")
            }
            bytes.append(buffer, count: count)
        }
        var after = stat()
        guard fstat(descriptor, &after) == 0,
              before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_mode == after.st_mode, before.st_uid == after.st_uid,
              before.st_gid == after.st_gid, before.st_nlink == after.st_nlink,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec else {
            throw AgentPassNativeError.invalidSignature("\(label) changed while it was being read")
        }
        return bytes
    }
}
