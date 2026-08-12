import Darwin
import Foundation

/// The only network capability needed by the prune coordinator. Implementations POST the
/// exact bytes to `/v1/audit-prunes/:tenant` and return the exact response body.
public protocol NativeAuditPruneTransport: Sendable {
    func submitAuditPrune(tenant: String, authorizationData: Data) throws -> Data
    func submitAuditPrune(tenant: String, authorizationData: Data, externalLeaseData: Data?) throws -> Data
}

public extension NativeAuditPruneTransport {
    func submitAuditPrune(tenant: String, authorizationData: Data, externalLeaseData: Data?) throws -> Data {
        try submitAuditPrune(tenant: tenant, authorizationData: authorizationData)
    }
}

/// Service-owned state. Implementations must derive both values from locally verified,
/// externally anchored state rather than from an XPC or CLI request.
public struct NativeAuditPruneTrustSnapshot: Equatable, Sendable {
    public static let version = 1
    public let version: Int
    public let revision: Int
    public let boundary: NativeAuditRetentionBoundary
    public let chainState: NativeAuditPruneChainState
    public let activeReservationID: String?

    public init(revision: Int, boundary: NativeAuditRetentionBoundary, chainState: NativeAuditPruneChainState, activeReservationID: String? = nil) {
        version = Self.version; self.revision = revision; self.boundary = boundary
        self.chainState = chainState; self.activeReservationID = activeReservationID
    }
}

public struct NativeAuditPruneMutationReservation: Equatable, Sendable {
    public static let version = 1
    public let version: Int
    public let reservationID: String
    public let operationID: String
    public let snapshotRevision: Int
    public let boundary: NativeAuditRetentionBoundary
    public let chainState: NativeAuditPruneChainState

    public init(reservationID: String, operationID: String, snapshotRevision: Int, boundary: NativeAuditRetentionBoundary, chainState: NativeAuditPruneChainState) {
        version = Self.version; self.reservationID = reservationID; self.operationID = operationID
        self.snapshotRevision = snapshotRevision; self.boundary = boundary; self.chainState = chainState
    }
}

/// Monotonic external position already established by the Node prune-receipt chain before any
/// local unlink. Comparing this avoids a second post-unlink proof-pin transaction and its crash
/// ambiguity while still detecting coherent rollback of all local Core files.
public struct NativeAuditPruneExternalReceiptPosition: Equatable, Sendable {
    public let sequence: Int
    public let receiptHash: String
    public init(sequence: Int, receiptHash: String) { self.sequence = sequence; self.receiptHash = receiptHash }
}

public struct NativeAuditPruneExternalReceiptHead: Equatable, Sendable {
    public let canonicalData: Data
    public let position: NativeAuditPruneExternalReceiptPosition?
    public init(canonicalData: Data, position: NativeAuditPruneExternalReceiptPosition?) {
        self.canonicalData = canonicalData; self.position = position
    }
}

public enum NativeAuditPruneExternalObservationPurpose: String, Equatable, Sendable {
    case prepare, submit, execute, status, reconcile
}

public struct NativeAuditPruneExternalReceiptLease: Equatable, Sendable {
    public let canonicalData: Data
    public let leaseID: String
    public let purpose: NativeAuditPruneExternalObservationPurpose
    public let operationID: String?
    public let position: NativeAuditPruneExternalReceiptPosition?
    public let principalFingerprint: String
    public let processEpoch: String
    /// Conservative monotonic deadline. Production verifiers subtract clock-skew margin from
    /// the signed Node expiry before constructing this value.
    public let destructiveDeadlineUptimeNanoseconds: UInt64

    public init(canonicalData: Data, leaseID: String, purpose: NativeAuditPruneExternalObservationPurpose, operationID: String?, position: NativeAuditPruneExternalReceiptPosition?, principalFingerprint: String = "", processEpoch: String = "", destructiveDeadlineUptimeNanoseconds: UInt64) {
        self.canonicalData = canonicalData; self.leaseID = leaseID; self.purpose = purpose
        self.operationID = operationID; self.position = position; self.principalFingerprint = principalFingerprint
        self.processEpoch = processEpoch
        self.destructiveDeadlineUptimeNanoseconds = destructiveDeadlineUptimeNanoseconds
    }
}

/// A short-lived, one-shot capability minted only after the Service has fetched and verified
/// the Node receipt head outside both Service and coordinator locks. The trust source binds it
/// to one exact local generation and consumes it before Core reads or mutates prune state.
public struct NativeAuditPruneExternalReceiptObservation: Equatable, Sendable {
    public let observationID: String
    public let generation: Int
    public let purpose: NativeAuditPruneExternalObservationPurpose
    public let operationID: String?
    public let trustRevision: Int
    public let reservationID: String?
    public let chainSequence: Int
    public let chainReceiptHash: String
    public let position: NativeAuditPruneExternalReceiptPosition?
    public let externalLease: NativeAuditPruneExternalReceiptLease?
    public let expiresAtUptimeNanoseconds: UInt64

    public init(observationID: String, generation: Int, purpose: NativeAuditPruneExternalObservationPurpose, operationID: String?, trustRevision: Int, reservationID: String?, chainSequence: Int, chainReceiptHash: String, position: NativeAuditPruneExternalReceiptPosition?, externalLease: NativeAuditPruneExternalReceiptLease? = nil, expiresAtUptimeNanoseconds: UInt64) {
        self.observationID = observationID; self.generation = generation; self.purpose = purpose
        self.operationID = operationID; self.trustRevision = trustRevision; self.reservationID = reservationID
        self.chainSequence = chainSequence; self.chainReceiptHash = chainReceiptHash
        self.position = position; self.externalLease = externalLease; self.expiresAtUptimeNanoseconds = expiresAtUptimeNanoseconds
    }
}

/// Implementations atomically snapshot and reserve the prune mutation domain. A reservation
/// must survive process restart and prevent any competing boundary/chain mutation until
/// `complete` or `cancel` succeeds. Reacquiring with `expected` is exact and idempotent.
public protocol NativeAuditPruneTrustSource: Sendable {
    func currentAuditPruneTrustSnapshot() throws -> NativeAuditPruneTrustSnapshot
    func acquireAuditPruneMutationReservation(operationID: String, expected: NativeAuditPruneMutationReservation?) throws -> NativeAuditPruneMutationReservation
    func validateAuditPruneMutationReservation(_ reservation: NativeAuditPruneMutationReservation) throws
    func completeAuditPruneMutationReservation(_ reservation: NativeAuditPruneMutationReservation, nextState: NativeAuditPruneChainState) throws
    func cancelAuditPruneMutationReservation(_ reservation: NativeAuditPruneMutationReservation) throws
    /// Atomically consumes one exact externally verified observation. Production sources reject
    /// missing, expired, replayed, wrong-purpose, wrong-operation, or stale-generation values.
    func consumeAuditPruneExternalReceiptObservation(_ observation: NativeAuditPruneExternalReceiptObservation?, purpose: NativeAuditPruneExternalObservationPurpose, operationID: String?) throws -> NativeAuditPruneExternalReceiptPosition?
    func validateConsumedAuditPruneExternalLease(_ observation: NativeAuditPruneExternalReceiptObservation, purpose: NativeAuditPruneExternalObservationPurpose, operationID: String?) throws
}

public extension NativeAuditPruneTrustSource {
    func consumeAuditPruneExternalReceiptObservation(_ observation: NativeAuditPruneExternalReceiptObservation?, purpose: NativeAuditPruneExternalObservationPurpose, operationID: String?) throws -> NativeAuditPruneExternalReceiptPosition? { nil }
    func validateConsumedAuditPruneExternalLease(_ observation: NativeAuditPruneExternalReceiptObservation, purpose: NativeAuditPruneExternalObservationPurpose, operationID: String?) throws {}
}

public enum NativeAuditPruneCoordinatorCrashPoint: Equatable, Sendable {
    case afterPreparationDurable
    case afterReceiptDurable
    case beforeExecutor
    case afterExecutorBeforeCompletion
    case afterCompletionDurable
}

public struct NativeAuditPrunePreparedOperation: Equatable, Sendable {
    public let authorizationData: Data
    public let authorization: NativeAuditPruneAuthorization
    public let priorState: NativeAuditPruneChainState
    public let boundary: NativeAuditRetentionBoundary
    public let reservation: NativeAuditPruneMutationReservation
    public let expectedNextRetained: NativeAuditRetentionSegment?
    /// Exact descriptor-observed identities captured before the authorization is signed.
    /// Revalidation must match all of them, not merely file content hashes.
    public let fileIdentities: [NativeAuditRetentionFileIdentity]
    public let expectedNextRetainedFileIdentities: [NativeAuditRetentionFileIdentity]?
    public let preparedAt: String
}

public struct NativeAuditPruneAcceptedOperation: Equatable, Sendable {
    public let preparation: NativeAuditPrunePreparedOperation
    public let receiptData: Data
    public let receipt: NativeAuditPruneReceipt
}

public struct NativeAuditPruneCoordinatorResult: Equatable, Sendable {
    public let accepted: NativeAuditPruneAcceptedOperation
    public let manifest: NativeAuditPostPruneManifest
    public let manifestData: Data
    public let completionProof: NativeAuditPruneCompletionProof
    public let completionProofData: Data
    public let completionStatementData: Data
    public let quarantinedMarkerData: Data
    public let manifestCommitMarkerData: Data
    public let deletionEvidenceBundleData: Data
    public let nextState: NativeAuditPruneChainState
    public let recovered: Bool
    /// Compare this with the independently monotonic Node receipt-chain head. Local journal/tip
    /// agreement alone cannot detect a coherent rollback of all local files.
    public var externallyPinnableReceiptPosition: NativeAuditPruneExternalReceiptPosition {
        .init(sequence: accepted.receipt.sequence, receiptHash: accepted.receipt.receiptHash)
    }
}

/// Post-deletion proof. Unlike `NativeAuditPostPruneManifest` (the executor's signed intent),
/// this document can only be constructed after `03-completed.json` is fsynced and every exact
/// target inode is absent from both source and quarantine.
public struct NativeAuditPruneCompletionProof: Codable, Equatable, Sendable {
    public static let version = 2
    public let version: Int
    public let tenant: String
    public let operationID: String
    public let sequence: Int
    public let authorizationHash: String
    public let anchorPruneReceiptHash: String
    public let manifestHash: String
    public let prunedSegmentsHash: String
    public let executorCompletionHash: String
    public let expectedNextRetainedHash: String
    public let retainedIdentityHash: String
    public let completedAt: String
    public let signerFingerprint: String
    public let signature: String
    public let proofHash: String

    enum CodingKeys: String, CodingKey, CaseIterable {
        case version, tenant, sequence, signature
        case operationID = "operation_id"
        case authorizationHash = "authorization_hash"
        case anchorPruneReceiptHash = "anchor_prune_receipt_hash"
        case manifestHash = "manifest_hash"
        case prunedSegmentsHash = "pruned_segments_hash"
        case executorCompletionHash = "executor_completion_hash"
        case expectedNextRetainedHash = "expected_next_retained_hash"
        case retainedIdentityHash = "retained_identity_hash"
        case completedAt = "completed_at"
        case signerFingerprint = "signer_fingerprint"
        case proofHash = "proof_hash"
    }

    private static func createValidated(plan: NativeAuditPrunePlan, manifest: NativeAuditPostPruneManifest, executorCompletionHash: String, completedAt: String, signer: P256MessageSigner) throws -> Self {
        guard executorCompletionHash.wholeMatch(of: /^[0-9a-f]{64}$/) != nil,
              manifest.authorizationHash == plan.authorization.authorizationHash,
              manifest.pruneReceiptHash == plan.receipt.receiptHash,
              manifest.operationID == plan.authorization.operationID,
              manifest.sequence == plan.authorization.sequence else {
            throw AgentPassNativeError.invalidSignature("Audit prune completion proof inputs are not exactly bound")
        }
        let segmentsHash = try Self.segmentsHash(plan.authorization.segments)
        guard manifest.prunedSegmentsHash == segmentsHash else {
            throw AgentPassNativeError.invalidSignature("Audit prune completion proof segment hash is inconsistent")
        }
        let fingerprint = NativeAuditCheckpoints.fingerprint(signer.publicKeyX963)
        var object = signingObject(version: version, tenant: plan.authorization.tenant, operationID: plan.authorization.operationID, sequence: plan.authorization.sequence, authorizationHash: plan.authorization.authorizationHash, anchorPruneReceiptHash: plan.receipt.receiptHash, manifestHash: manifest.manifestHash, prunedSegmentsHash: segmentsHash, executorCompletionHash: executorCompletionHash, expectedNextRetainedHash: manifest.expectedNextRetainedHash, retainedIdentityHash: manifest.retainedIdentityHash, completedAt: completedAt, signerFingerprint: fingerprint)
        let raw = try NativeP256CanonicalSignature.canonicalized(signer.sign(message: NativeAuditLog.canonical(object)))
        let signature = raw.base64EncodedString(); object["signature"] = signature
        let hash = NativeAuditLog.hash(try NativeAuditLog.canonical(object))
        return Self(version: version, tenant: plan.authorization.tenant, operationID: plan.authorization.operationID, sequence: plan.authorization.sequence, authorizationHash: plan.authorization.authorizationHash, anchorPruneReceiptHash: plan.receipt.receiptHash, manifestHash: manifest.manifestHash, prunedSegmentsHash: segmentsHash, executorCompletionHash: executorCompletionHash, expectedNextRetainedHash: manifest.expectedNextRetainedHash, retainedIdentityHash: manifest.retainedIdentityHash, completedAt: completedAt, signerFingerprint: fingerprint, signature: signature, proofHash: hash)
    }

    /// The production factory accepts only an executor result whose exact `01 → 02 → 03`
    /// durable phase chain has already been recovered and verified.
    static func create(plan: NativeAuditPrunePlan, execution: NativeAuditPruneExecutionResult, signer: P256MessageSigner) throws -> Self {
        let manifest = execution.manifest
        guard execution.manifestData == (try manifest.canonicalData()),
              execution.durableCompletionHash == NativeAuditLog.hash(execution.completionStatementData) else {
            throw AgentPassNativeError.invalidSignature("Audit prune executor result is not an exact durable completion capability")
        }
        let completion = try NativeAuditPruneExecutorCompletionStatement.verifyCanonicalPhaseChain(
            quarantinedMarkerData: execution.quarantinedMarkerData,
            manifestCommitMarkerData: execution.manifestCommitMarkerData,
            completionStatementData: execution.completionStatementData,
            operationID: plan.authorization.operationID,
            manifestHash: manifest.manifestHash
        )
        guard completion.authorizationHash == plan.authorization.authorizationHash,
              completion.receiptHash == plan.receipt.receiptHash,
              completion.expectedNextRetainedHash == manifest.expectedNextRetainedHash,
              completion.retainedIdentityHash == manifest.retainedIdentityHash,
              completion.completedAt == execution.completedAt else {
            throw AgentPassNativeError.invalidSignature("Audit prune durable completion capability is not bound to its signed plan")
        }
        return try createValidated(plan: plan, manifest: manifest, executorCompletionHash: execution.durableCompletionHash, completedAt: execution.completedAt, signer: signer)
    }

    public func canonicalData() throws -> Data {
        var object = Self.signingObject(self); object["signature"] = signature; object["proof_hash"] = proofHash
        return try NativeAuditLog.canonical(object)
    }

    public static func decodeCanonical(_ data: Data) throws -> Self {
        guard !data.isEmpty, data.count <= NativeAuditRetentionVerifier.maximumDocumentBytes,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set(CodingKeys.allCases.map(\.stringValue)),
              let value = try? JSONDecoder().decode(Self.self, from: data),
              try value.canonicalData() == data else {
            throw AgentPassNativeError.invalidSignature("Audit prune completion proof is not exact canonical schema")
        }
        return value
    }

    static func signingObject(_ value: Self) -> [String: Any] {
        signingObject(version: value.version, tenant: value.tenant, operationID: value.operationID, sequence: value.sequence, authorizationHash: value.authorizationHash, anchorPruneReceiptHash: value.anchorPruneReceiptHash, manifestHash: value.manifestHash, prunedSegmentsHash: value.prunedSegmentsHash, executorCompletionHash: value.executorCompletionHash, expectedNextRetainedHash: value.expectedNextRetainedHash, retainedIdentityHash: value.retainedIdentityHash, completedAt: value.completedAt, signerFingerprint: value.signerFingerprint)
    }

    static func signingObject(version: Int, tenant: String, operationID: String, sequence: Int, authorizationHash: String, anchorPruneReceiptHash: String, manifestHash: String, prunedSegmentsHash: String, executorCompletionHash: String, expectedNextRetainedHash: String, retainedIdentityHash: String, completedAt: String, signerFingerprint: String) -> [String: Any] {
        ["version": version, "tenant": tenant, "operation_id": operationID, "sequence": sequence, "authorization_hash": authorizationHash, "anchor_prune_receipt_hash": anchorPruneReceiptHash, "manifest_hash": manifestHash, "pruned_segments_hash": prunedSegmentsHash, "executor_completion_hash": executorCompletionHash, "expected_next_retained_hash": expectedNextRetainedHash, "retained_identity_hash": retainedIdentityHash, "completed_at": completedAt, "signer_fingerprint": signerFingerprint]
    }

    static func segmentsHash(_ segments: [NativeAuditRetentionSegment]) throws -> String {
        let values = try segments.map { try JSONSerialization.jsonObject(with: JSONEncoder().encode($0)) }
        return NativeAuditLog.hash(try NativeAuditLog.canonical(["segments": values]))
    }
}

public struct NativeAuditPruneJournalStatus: Equatable, Sendable {
    public let completed: [NativeAuditPruneCoordinatorResult]
    public let pendingPreparation: NativeAuditPrunePreparedOperation?
    public let pendingReceiptData: Data?
}

extension NativeAuditRetentionArchiveObservation {
    /// Rehydrates only identities that were produced by the descriptor-relative observer and
    /// protected by the prune journal's immutable hash chain. This does not observe a new path
    /// and therefore cannot silently refresh a deletion capability to a replacement inode.
    fileprivate init(persistedSegment segment: NativeAuditRetentionSegment, identities: [NativeAuditRetentionFileIdentity]) throws {
        guard identities.count == 3,
              identities.map(\.name) == [segment.auditArchiveFile, segment.checkpointArchiveFile, segment.receiptArchiveFile],
              identities.map(\.sha256) == [segment.auditArchiveSHA256, segment.checkpointArchiveSHA256, segment.receiptArchiveSHA256],
              identities.allSatisfy({
                  ($0.mode & UInt32(S_IFMT)) == UInt32(S_IFREG) && $0.owner == geteuid() &&
                  $0.mode & 0o077 == 0 && $0.linkCount == 1 && $0.size > 0 &&
                  $0.size <= NativeAuditRetentionArchiveObservation.maximumArchiveBytes
              }) else {
            throw AgentPassNativeError.invalidSignature("Persisted audit prune filesystem identities are invalid")
        }
        self.segment = segment
        auditArchiveBytes = identities[0].size
        checkpointArchiveBytes = identities[1].size
        receiptArchiveBytes = identities[2].size
        fileIdentities = identities
    }
}

/// Append-only, owner-private WAL for prune capabilities. Every record is an immutable 0400
/// regular file and every tip update is an atomic 0600 replacement. At most one fully valid
/// record may be ahead of the tip, which is the crash shape produced between record fsync and
/// tip rename. Any truncation, fork, unknown entry, link, path swap, or wider rollback fails.
public final class NativeAuditPruneJournal: @unchecked Sendable {
    private static let tipName = "tip.json"
    private static let maximumRecords = 1_000_000
    private static let maximumRecordBytes = NativeAuditRetentionVerifier.maximumDocumentBytes * 12

    private let rootPath: String
    private let descriptor: Int32
    private let device: dev_t
    private let inode: ino_t
    private let tenant: String
    private let lock = NSLock()

    public init(directory: String, tenant: String) throws {
        guard directory.hasPrefix("/"), Self.isSlug(tenant) else {
            throw AgentPassNativeError.invalidConfiguration("Audit prune journal path or tenant is invalid")
        }
        let canonical = try Self.realPath(directory)
        guard canonical == directory else {
            throw AgentPassNativeError.invalidConfiguration("Audit prune journal path must be canonical and contain no symbolic links")
        }
        try Self.validateProtectedAncestors(canonical)
        let fd = open(canonical, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw Self.posixError() }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == geteuid(), info.st_mode & 0o777 == 0o700 else {
            close(fd)
            throw AgentPassNativeError.invalidConfiguration("Audit prune journal must be a service-owned 0700 directory")
        }
        rootPath = canonical
        descriptor = fd
        device = info.st_dev
        inode = info.st_ino
        self.tenant = tenant
        do {
            try withLock {
                let records = try readRecords()
                if try !entryExists(Self.tipName) {
                    guard records.isEmpty else {
                        throw AgentPassNativeError.invalidSignature("Audit prune journal tip is missing")
                    }
                    try writeTip(records: records)
                } else {
                    try verifyOrRepairTip(records)
                }
                _ = try reduce(records)
            }
        } catch {
            close(fd)
            throw error
        }
    }

    deinit { close(descriptor) }

    public func status() throws -> NativeAuditPruneJournalStatus {
        try withLock { try statusUnlocked() }
    }

    @discardableResult
    public func prepare(_ value: NativeAuditPrunePreparedOperation) throws -> NativeAuditPrunePreparedOperation {
        try withLock {
            var records = try verifiedRecords()
            let state = try reduce(records)
            if let existing = state.preparations.first(where: { $0.authorization.operationID == value.authorization.operationID }) {
                guard existing == value else {
                    throw AgentPassNativeError.invalidSignature("Audit prune operation ID equivocates with its durable preparation")
                }
                return existing
            }
            guard state.pendingPreparation == nil else {
                throw AgentPassNativeError.invalidSignature("A different audit prune operation is already pending")
            }
            guard !state.preparations.contains(where: {
                $0.authorization.authorizationHash == value.authorization.authorizationHash ||
                $0.authorization.sequence == value.authorization.sequence
            }) else {
                throw AgentPassNativeError.invalidSignature("Audit prune sequence or authorization replay is forbidden")
            }
            let record = try makePrepareRecord(value, index: records.count + 1, previousHash: records.last?.recordHash ?? NativeAuditLog.zeroHash)
            guard try decodePreparation(record.object) == value else {
                throw AgentPassNativeError.invalidSignature("Audit prune preparation is not exact journal schema")
            }
            _ = try reduce(records + [record])
            try append(record)
            records.append(record)
            try writeTip(records: records)
            return value
        }
    }

    @discardableResult
    public func acceptReceipt(operationID: String, receiptData: Data) throws -> NativeAuditPruneAcceptedOperation {
        try withLock {
            var records = try verifiedRecords()
            let state = try reduce(records)
            guard let preparation = state.preparations.first(where: { $0.authorization.operationID == operationID }) else {
                throw AgentPassNativeError.invalidSignature("Audit prune receipt has no durable preparation")
            }
            if let existing = state.receipts[operationID] {
                guard existing == receiptData else {
                    throw AgentPassNativeError.invalidSignature("Audit prune anchor receipt equivocates with durable bytes")
                }
                return try accepted(preparation, receiptData: existing)
            }
            guard state.pendingPreparation?.authorization.operationID == operationID else {
                throw AgentPassNativeError.invalidSignature("Audit prune receipt is not for the one pending operation")
            }
            let receipt = try NativeAuditPruneReceipt.decodeCanonical(receiptData)
            guard receipt.tenant == tenant,
                  receipt.authorizationHash == preparation.authorization.authorizationHash else {
                throw AgentPassNativeError.invalidSignature("Audit prune receipt is not bound to its durable authorization")
            }
            let record = try makeReceiptRecord(operationID: operationID, authorizationHash: preparation.authorization.authorizationHash, receiptData: receiptData, index: records.count + 1, previousHash: records.last?.recordHash ?? NativeAuditLog.zeroHash)
            _ = try reduce(records + [record])
            try append(record)
            records.append(record)
            try writeTip(records: records)
            return NativeAuditPruneAcceptedOperation(preparation: preparation, receiptData: receiptData, receipt: receipt)
        }
    }

    @discardableResult
    public func complete(
        operationID: String,
        manifestData: Data,
        completionProofData: Data,
        completionStatementData: Data,
        quarantinedMarkerData: Data,
        manifestCommitMarkerData: Data,
        deletionEvidenceBundleData: Data,
        nextState: NativeAuditPruneChainState,
        recovered: Bool
    ) throws -> NativeAuditPruneCoordinatorResult {
        try withLock {
            var records = try verifiedRecords()
            let state = try reduce(records)
            guard let preparation = state.preparations.first(where: { $0.authorization.operationID == operationID }),
                  let receiptData = state.receipts[operationID] else {
                throw AgentPassNativeError.invalidSignature("Audit prune completion lacks durable authorization and receipt")
            }
            let accepted = try accepted(preparation, receiptData: receiptData)
            if let existing = state.completions.first(where: { $0.accepted.preparation.authorization.operationID == operationID }) {
                guard existing.manifestData == manifestData,
                      existing.completionProofData == completionProofData,
                      existing.completionStatementData == completionStatementData,
                      existing.quarantinedMarkerData == quarantinedMarkerData,
                      existing.manifestCommitMarkerData == manifestCommitMarkerData,
                      existing.deletionEvidenceBundleData == deletionEvidenceBundleData,
                      existing.nextState == nextState else {
                    throw AgentPassNativeError.invalidSignature("Audit prune completion equivocates with durable evidence")
                }
                return existing
            }
            guard state.pendingPreparation?.authorization.operationID == operationID,
                  state.pendingReceiptData != nil else {
                throw AgentPassNativeError.invalidSignature("Audit prune completion is not the one accepted pending operation")
            }
            let manifest = try NativeAuditPostPruneManifest.decodeCanonical(manifestData)
            let completionProof = try NativeAuditPruneCompletionProof.decodeCanonical(completionProofData)
            guard manifest.authorizationHash == preparation.authorization.authorizationHash,
                  manifest.pruneReceiptHash == accepted.receipt.receiptHash,
                  nextState.sequence == preparation.authorization.sequence,
                  nextState.authorizationHash == preparation.authorization.authorizationHash,
                  nextState.receiptHash == accepted.receipt.receiptHash,
                  nextState.manifestHash == manifest.manifestHash,
                  completionProof.authorizationHash == preparation.authorization.authorizationHash,
                  completionProof.anchorPruneReceiptHash == accepted.receipt.receiptHash,
                  completionProof.manifestHash == manifest.manifestHash else {
                throw AgentPassNativeError.invalidSignature("Audit prune completion is not bound to its signed capability")
            }
            try Self.verifyDeletionBundle(
                deletionEvidenceBundleData,
                preparation: preparation,
                receiptData: receiptData,
                manifestData: manifestData,
                completionProofData: completionProofData,
                completionStatementData: completionStatementData,
                quarantinedMarkerData: quarantinedMarkerData,
                manifestCommitMarkerData: manifestCommitMarkerData
            )
            let record = try makeCompletionRecord(operationID: operationID, authorizationHash: preparation.authorization.authorizationHash, receiptHash: accepted.receipt.receiptHash, manifestData: manifestData, completionProofData: completionProofData, completionStatementData: completionStatementData, quarantinedMarkerData: quarantinedMarkerData, manifestCommitMarkerData: manifestCommitMarkerData, bundleData: deletionEvidenceBundleData, nextState: nextState, recovered: recovered, index: records.count + 1, previousHash: records.last?.recordHash ?? NativeAuditLog.zeroHash)
            _ = try reduce(records + [record])
            try append(record)
            records.append(record)
            try writeTip(records: records)
            return NativeAuditPruneCoordinatorResult(accepted: accepted, manifest: manifest, manifestData: manifestData, completionProof: completionProof, completionProofData: completionProofData, completionStatementData: completionStatementData, quarantinedMarkerData: quarantinedMarkerData, manifestCommitMarkerData: manifestCommitMarkerData, deletionEvidenceBundleData: deletionEvidenceBundleData, nextState: nextState, recovered: recovered)
        }
    }

    // MARK: durable record reduction

    private struct Record {
        let index: Int
        let phase: String
        let operationID: String
        let previousRecordHash: String
        let object: [String: Any]
        let data: Data
        let recordHash: String
    }

    private struct Reduced {
        var preparations: [NativeAuditPrunePreparedOperation] = []
        var receipts: [String: Data] = [:]
        var completions: [NativeAuditPruneCoordinatorResult] = []
        var pendingPreparation: NativeAuditPrunePreparedOperation?
        var pendingReceiptData: Data?
    }

    private func statusUnlocked() throws -> NativeAuditPruneJournalStatus {
        let state = try reduce(verifiedRecords())
        return NativeAuditPruneJournalStatus(completed: state.completions, pendingPreparation: state.pendingPreparation, pendingReceiptData: state.pendingReceiptData)
    }

    private func reduce(_ records: [Record]) throws -> Reduced {
        var state = Reduced()
        for record in records {
            switch record.phase {
            case "prepared":
                guard state.pendingPreparation == nil else {
                    throw AgentPassNativeError.invalidSignature("Audit prune journal contains concurrent pending operations")
                }
                let value = try decodePreparation(record.object)
                guard !state.preparations.contains(where: {
                    $0.authorization.operationID == value.authorization.operationID ||
                    $0.authorization.authorizationHash == value.authorization.authorizationHash ||
                    $0.authorization.sequence == value.authorization.sequence
                }) else {
                    throw AgentPassNativeError.invalidSignature("Audit prune journal replays an operation, sequence, or authorization")
                }
                state.preparations.append(value)
                state.pendingPreparation = value
            case "receipt":
                guard let pending = state.pendingPreparation,
                      pending.authorization.operationID == record.operationID,
                      state.pendingReceiptData == nil,
                      let authorizationHash = record.object["authorization_hash"] as? String,
                      authorizationHash == pending.authorization.authorizationHash,
                      let data = Self.exactBase64(record.object["receipt_base64"], maximum: NativeAuditRetentionVerifier.maximumDocumentBytes) else {
                    throw AgentPassNativeError.invalidSignature("Audit prune receipt journal record is out of order or malformed")
                }
                let receipt = try NativeAuditPruneReceipt.decodeCanonical(data)
                guard receipt.authorizationHash == authorizationHash, receipt.tenant == tenant else {
                    throw AgentPassNativeError.invalidSignature("Audit prune receipt journal binding is invalid")
                }
                state.receipts[record.operationID] = data
                state.pendingReceiptData = data
            case "completed":
                guard let pending = state.pendingPreparation,
                      pending.authorization.operationID == record.operationID,
                      let receiptData = state.pendingReceiptData,
                      let manifestData = Self.exactBase64(record.object["manifest_base64"], maximum: NativeAuditRetentionVerifier.maximumDocumentBytes),
                      let completionProofData = Self.exactBase64(record.object["completion_proof_base64"], maximum: NativeAuditRetentionVerifier.maximumDocumentBytes),
                      let completionStatementData = Self.exactBase64(record.object["executor_completion_statement_base64"], maximum: 4096),
                      let quarantinedMarkerData = Self.exactBase64(record.object["executor_quarantined_marker_base64"], maximum: 4096),
                      let manifestCommitMarkerData = Self.exactBase64(record.object["executor_manifest_commit_marker_base64"], maximum: 4096),
                      let bundleData = Self.exactBase64(record.object["deletion_evidence_bundle_base64"], maximum: NativeAuditRetentionVerifier.maximumDocumentBytes * 7),
                      let nextObject = record.object["next_chain_state"] as? [String: Any],
                      let recovered = record.object["recovered"] as? Bool else {
                    throw AgentPassNativeError.invalidSignature("Audit prune completion journal record is out of order or malformed")
                }
                let next = try Self.decodeState(nextObject)
                let accepted = try accepted(pending, receiptData: receiptData)
                let manifest = try NativeAuditPostPruneManifest.decodeCanonical(manifestData)
                let completionProof = try NativeAuditPruneCompletionProof.decodeCanonical(completionProofData)
                guard record.object["authorization_hash"] as? String == pending.authorization.authorizationHash,
                      record.object["receipt_hash"] as? String == accepted.receipt.receiptHash,
                      manifest.authorizationHash == pending.authorization.authorizationHash,
                      manifest.pruneReceiptHash == accepted.receipt.receiptHash,
                      completionProof.authorizationHash == pending.authorization.authorizationHash,
                      completionProof.anchorPruneReceiptHash == accepted.receipt.receiptHash,
                      completionProof.manifestHash == manifest.manifestHash,
                      next.authorizationHash == pending.authorization.authorizationHash,
                      next.receiptHash == accepted.receipt.receiptHash,
                      next.manifestHash == manifest.manifestHash else {
                    throw AgentPassNativeError.invalidSignature("Audit prune completion journal binding is invalid")
                }
                try Self.verifyDeletionBundle(bundleData, preparation: pending, receiptData: receiptData, manifestData: manifestData, completionProofData: completionProofData, completionStatementData: completionStatementData, quarantinedMarkerData: quarantinedMarkerData, manifestCommitMarkerData: manifestCommitMarkerData)
                state.completions.append(NativeAuditPruneCoordinatorResult(accepted: accepted, manifest: manifest, manifestData: manifestData, completionProof: completionProof, completionProofData: completionProofData, completionStatementData: completionStatementData, quarantinedMarkerData: quarantinedMarkerData, manifestCommitMarkerData: manifestCommitMarkerData, deletionEvidenceBundleData: bundleData, nextState: next, recovered: recovered))
                state.pendingPreparation = nil
                state.pendingReceiptData = nil
            default:
                throw AgentPassNativeError.invalidSignature("Audit prune journal phase is unknown")
            }
        }
        return state
    }

    private func accepted(_ preparation: NativeAuditPrunePreparedOperation, receiptData: Data) throws -> NativeAuditPruneAcceptedOperation {
        let receipt = try NativeAuditPruneReceipt.decodeCanonical(receiptData)
        guard receipt.tenant == tenant, receipt.authorizationHash == preparation.authorization.authorizationHash else {
            throw AgentPassNativeError.invalidSignature("Audit prune durable receipt binding is invalid")
        }
        return NativeAuditPruneAcceptedOperation(preparation: preparation, receiptData: receiptData, receipt: receipt)
    }

    private func makePrepareRecord(_ value: NativeAuditPrunePreparedOperation, index: Int, previousHash: String) throws -> Record {
        let object: [String: Any] = [
            "version": 1, "index": index, "phase": "prepared", "tenant": tenant,
            "operation_id": value.authorization.operationID, "previous_record_hash": previousHash,
            "authorization_base64": value.authorizationData.base64EncodedString(),
            "prior_chain_state": Self.stateObject(value.priorState),
            "mutation_reservation": try Self.reservationObject(value.reservation),
            "expected_next_retained": try Self.segmentObject(value.expectedNextRetained),
            "file_identities": try Self.fileIdentityObjects(value.fileIdentities),
            "expected_next_retained_file_identities": value.expectedNextRetainedFileIdentities == nil ? NSNull() : try Self.fileIdentityObjects(value.expectedNextRetainedFileIdentities!),
            "prepared_at": value.preparedAt
        ]
        return try makeRecord(object)
    }

    private func makeReceiptRecord(operationID: String, authorizationHash: String, receiptData: Data, index: Int, previousHash: String) throws -> Record {
        try makeRecord([
            "version": 1, "index": index, "phase": "receipt", "tenant": tenant,
            "operation_id": operationID, "previous_record_hash": previousHash,
            "authorization_hash": authorizationHash, "receipt_base64": receiptData.base64EncodedString()
        ])
    }

    private func makeCompletionRecord(operationID: String, authorizationHash: String, receiptHash: String, manifestData: Data, completionProofData: Data, completionStatementData: Data, quarantinedMarkerData: Data, manifestCommitMarkerData: Data, bundleData: Data, nextState: NativeAuditPruneChainState, recovered: Bool, index: Int, previousHash: String) throws -> Record {
        try makeRecord([
            "version": 1, "index": index, "phase": "completed", "tenant": tenant,
            "operation_id": operationID, "previous_record_hash": previousHash,
            "authorization_hash": authorizationHash, "receipt_hash": receiptHash,
            "manifest_base64": manifestData.base64EncodedString(),
            "completion_proof_base64": completionProofData.base64EncodedString(),
            "executor_completion_statement_base64": completionStatementData.base64EncodedString(),
            "executor_quarantined_marker_base64": quarantinedMarkerData.base64EncodedString(),
            "executor_manifest_commit_marker_base64": manifestCommitMarkerData.base64EncodedString(),
            "deletion_evidence_bundle_base64": bundleData.base64EncodedString(),
            "next_chain_state": Self.stateObject(nextState), "recovered": recovered
        ])
    }

    private func makeRecord(_ input: [String: Any]) throws -> Record {
        var object = input
        let hash = NativeAuditLog.hash(try NativeAuditLog.canonical(object))
        object["record_hash"] = hash
        let data = try NativeAuditLog.canonical(object)
        guard let index = object["index"] as? Int,
              let phase = object["phase"] as? String,
              let operationID = object["operation_id"] as? String,
              let previous = object["previous_record_hash"] as? String else {
            throw AgentPassNativeError.invalidSignature("Audit prune journal record construction failed")
        }
        return Record(index: index, phase: phase, operationID: operationID, previousRecordHash: previous, object: object, data: data, recordHash: hash)
    }

    private func decodePreparation(_ object: [String: Any]) throws -> NativeAuditPrunePreparedOperation {
        guard let authorizationData = Self.exactBase64(object["authorization_base64"], maximum: NativeAuditRetentionVerifier.maximumDocumentBytes),
              let priorObject = object["prior_chain_state"] as? [String: Any],
              let preparedAt = object["prepared_at"] as? String,
              Self.date(preparedAt) != nil else {
            throw AgentPassNativeError.invalidSignature("Audit prune preparation journal record is malformed")
        }
        let authorization = try NativeAuditPruneAuthorization.decodeCanonical(authorizationData)
        guard authorization.tenant == tenant, authorization.operationID == object["operation_id"] as? String else {
            throw AgentPassNativeError.invalidSignature("Audit prune preparation tenant or operation binding is invalid")
        }
        let prior = try Self.decodeState(priorObject)
        guard let reservationObject = object["mutation_reservation"] as? [String: Any] else {
            throw AgentPassNativeError.invalidSignature("Audit prune preparation lacks its atomic mutation reservation")
        }
        let reservation = try Self.decodeReservation(reservationObject)
        let retained = try Self.decodeSegment(object["expected_next_retained"])
        guard let identityValues = object["file_identities"] as? [[String: Any]] else {
            throw AgentPassNativeError.invalidSignature("Audit prune preparation lacks descriptor-observed identities")
        }
        let identities = try Self.decodeFileIdentities(identityValues)
        let retainedIdentities: [NativeAuditRetentionFileIdentity]?
        if object["expected_next_retained_file_identities"] is NSNull {
            retainedIdentities = nil
        } else if let values = object["expected_next_retained_file_identities"] as? [[String: Any]] {
            retainedIdentities = try Self.decodeFileIdentities(values)
        } else {
            throw AgentPassNativeError.invalidSignature("Audit prune retained identities are not exact schema")
        }
        guard identities.count == authorization.segments.count * 3 else {
            throw AgentPassNativeError.invalidSignature("Audit prune preparation has incomplete filesystem identities")
        }
        guard reservation.operationID == authorization.operationID,
              reservation.boundary == authorization.boundary,
              reservation.chainState == prior,
              (retained == nil ? retainedIdentities == nil : retainedIdentities?.count == 3) else {
            throw AgentPassNativeError.invalidSignature("Audit prune reservation or retained identity binding is invalid")
        }
        return NativeAuditPrunePreparedOperation(authorizationData: authorizationData, authorization: authorization, priorState: prior, boundary: authorization.boundary, reservation: reservation, expectedNextRetained: retained, fileIdentities: identities, expectedNextRetainedFileIdentities: retainedIdentities, preparedAt: preparedAt)
    }

    private func readRecords() throws -> [Record] {
        try validateRoot()
        let names = try Self.names(descriptor)
        let recordNames = names.filter { $0 != Self.tipName && !$0.hasPrefix(".tmp-") }
        guard names.allSatisfy({ $0 == Self.tipName || $0.hasPrefix(".tmp-") || Self.recordNamePattern($0) }),
              recordNames.count <= Self.maximumRecords else {
            throw AgentPassNativeError.invalidSignature("Audit prune journal contains an unknown or excessive entry")
        }
        // A temporary file can only be recovered by unlinking it before it has a public name.
        // Its contents have no authority and it must be private, single-link, and regular.
        for temporary in names.filter({ $0.hasPrefix(".tmp-") }) {
            try Self.removeSafeTemporary(descriptor, name: temporary)
        }
        var result: [Record] = []
        for (offset, name) in recordNames.sorted().enumerated() {
            let expectedIndex = offset + 1
            guard name.hasPrefix(String(format: "%020d-", expectedIndex)) else {
                throw AgentPassNativeError.invalidSignature("Audit prune journal record sequence has a gap or rollback")
            }
            let data = try Self.readFile(descriptor, name: name, mode: 0o400, maximum: Self.maximumRecordBytes)
            guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  try NativeAuditLog.canonical(object) == data,
                  Self.exactInteger(object["version"]) == 1,
                  Self.exactInteger(object["index"]) == expectedIndex,
                  object["tenant"] as? String == tenant,
                  let phase = object["phase"] as? String,
                  ["prepared", "receipt", "completed"].contains(phase),
                  name == Self.recordName(index: expectedIndex, phase: phase),
                  let operationID = object["operation_id"] as? String, Self.isSlug(operationID),
                  let previous = object["previous_record_hash"] as? String, Self.isHash(previous),
                  let recordHash = object["record_hash"] as? String, Self.isHash(recordHash) else {
                throw AgentPassNativeError.invalidSignature("Audit prune journal record schema is invalid")
            }
            let expectedKeys: Set<String>
            switch phase {
            case "prepared": expectedKeys = ["version", "index", "phase", "tenant", "operation_id", "previous_record_hash", "authorization_base64", "prior_chain_state", "mutation_reservation", "expected_next_retained", "file_identities", "expected_next_retained_file_identities", "prepared_at", "record_hash"]
            case "receipt": expectedKeys = ["version", "index", "phase", "tenant", "operation_id", "previous_record_hash", "authorization_hash", "receipt_base64", "record_hash"]
            default: expectedKeys = ["version", "index", "phase", "tenant", "operation_id", "previous_record_hash", "authorization_hash", "receipt_hash", "manifest_base64", "completion_proof_base64", "executor_completion_statement_base64", "executor_quarantined_marker_base64", "executor_manifest_commit_marker_base64", "deletion_evidence_bundle_base64", "next_chain_state", "recovered", "record_hash"]
            }
            guard Set(object.keys) == expectedKeys,
                  previous == (result.last?.recordHash ?? NativeAuditLog.zeroHash) else {
                throw AgentPassNativeError.invalidSignature("Audit prune journal hash chain is invalid")
            }
            var unhashed = object; unhashed.removeValue(forKey: "record_hash")
            guard NativeAuditLog.hash(try NativeAuditLog.canonical(unhashed)) == recordHash else {
                throw AgentPassNativeError.invalidSignature("Audit prune journal record hash is invalid")
            }
            result.append(Record(index: expectedIndex, phase: phase, operationID: operationID, previousRecordHash: previous, object: object, data: data, recordHash: recordHash))
        }
        return result
    }

    private func verifiedRecords() throws -> [Record] {
        let records = try readRecords()
        try verifyOrRepairTip(records)
        _ = try reduce(records)
        return records
    }

    private func verifyOrRepairTip(_ records: [Record]) throws {
        let data = try Self.readFile(descriptor, name: Self.tipName, mode: 0o600, maximum: 4096)
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set(["version", "records", "head_hash", "tip_hash"]),
              try NativeAuditLog.canonical(object) == data,
              Self.exactInteger(object["version"]) == 1,
              let count = Self.exactInteger(object["records"]), count >= 0,
              let head = object["head_hash"] as? String, Self.isHash(head),
              let tipHash = object["tip_hash"] as? String, Self.isHash(tipHash) else {
            throw AgentPassNativeError.invalidSignature("Audit prune journal tip is invalid")
        }
        var unhashed = object; unhashed.removeValue(forKey: "tip_hash")
        guard NativeAuditLog.hash(try NativeAuditLog.canonical(unhashed)) == tipHash,
              count <= records.count,
              count == 0 ? head == NativeAuditLog.zeroHash : records[count - 1].recordHash == head else {
            throw AgentPassNativeError.invalidSignature("Audit prune journal tip detects truncation or rollback")
        }
        if records.count == count { return }
        guard records.count == count + 1 else {
            throw AgentPassNativeError.invalidSignature("Audit prune journal has more than one uncommitted tail record")
        }
        // The record itself and the full phase machine were verified before repairing the tip.
        _ = try reduce(records)
        try writeTip(records: records)
    }

    private func append(_ record: Record) throws {
        try validateRoot()
        try Self.writeImmutable(descriptor, name: Self.recordName(index: record.index, phase: record.phase), data: record.data)
    }

    private func writeTip(records: [Record]) throws {
        let statement: [String: Any] = ["version": 1, "records": records.count, "head_hash": records.last?.recordHash ?? NativeAuditLog.zeroHash]
        var object = statement
        object["tip_hash"] = NativeAuditLog.hash(try NativeAuditLog.canonical(statement))
        try Self.replaceMutable(descriptor, name: Self.tipName, data: try NativeAuditLog.canonical(object))
    }

    private func validateRoot() throws {
        var info = stat()
        guard fstat(descriptor, &info) == 0, info.st_dev == device, info.st_ino == inode,
              (info.st_mode & S_IFMT) == S_IFDIR, info.st_uid == geteuid(), info.st_mode & 0o777 == 0o700,
              try Self.realPath(rootPath) == rootPath else {
            throw AgentPassNativeError.invalidConfiguration("Audit prune journal directory identity changed")
        }
    }

    private func withLock<T>(_ body: () throws -> T) throws -> T {
        lock.lock(); defer { lock.unlock() }
        guard flock(descriptor, LOCK_EX) == 0 else { throw Self.posixError() }
        defer { flock(descriptor, LOCK_UN) }
        return try body()
    }

    // MARK: exact schemas shared with ServiceAuditKeyDeletionEvidenceProvider

    public static func deletionEvidenceBundle(
        preparation: NativeAuditPrunePreparedOperation,
        receiptData: Data,
        manifestData: Data,
        completionProofData: Data,
        completionStatementData: Data,
        quarantinedMarkerData: Data,
        manifestCommitMarkerData: Data
    ) throws -> Data {
        guard let retained = preparation.expectedNextRetained, let retainedIdentities = preparation.expectedNextRetainedFileIdentities, retainedIdentities.count == 3 else { throw AgentPassNativeError.invalidSignature("Audit prune deletion evidence forbids a null retained capability") }
        // Schema v4 is deliberately self-contained after deletion. A verifier must not reopen
        // any pruned archive path; authorization hashes, retained boundary and completion proof
        // carry all durable semantics needed by `verifyCompletedPruneEvidence`.
        let object: [String: Any] = [
            "version": 4,
            "authorization_base64": preparation.authorizationData.base64EncodedString(),
            "anchor_prune_receipt_base64": receiptData.base64EncodedString(),
            "post_prune_manifest_base64": manifestData.base64EncodedString(),
            "completion_proof_base64": completionProofData.base64EncodedString(),
            "executor_completion_statement_base64": completionStatementData.base64EncodedString(),
            "executor_quarantined_marker_base64": quarantinedMarkerData.base64EncodedString(),
            "executor_manifest_commit_marker_base64": manifestCommitMarkerData.base64EncodedString(),
            "prior_chain_state": stateObject(preparation.priorState),
            "expected_next_retained": try segmentObject(retained),
            "expected_next_retained_file_identities": try fileIdentityObjects(retainedIdentities)
        ]
        let data = try NativeAuditLog.canonical(object)
        try verifyDeletionBundle(data, preparation: preparation, receiptData: receiptData, manifestData: manifestData, completionProofData: completionProofData, completionStatementData: completionStatementData, quarantinedMarkerData: quarantinedMarkerData, manifestCommitMarkerData: manifestCommitMarkerData)
        return data
    }

    /// Recovery/Service parser for exact schema-v3 evidence. It performs no filesystem reads.
    static func verifyDeletionBundle(_ data: Data, preparation: NativeAuditPrunePreparedOperation, receiptData: Data, manifestData: Data, completionProofData: Data, completionStatementData: Data? = nil, quarantinedMarkerData: Data? = nil, manifestCommitMarkerData: Data? = nil) throws {
        guard let retained = preparation.expectedNextRetained, let retainedIdentities = preparation.expectedNextRetainedFileIdentities, retainedIdentities.count == 3 else { throw AgentPassNativeError.invalidSignature("Audit prune deletion-evidence bundle has a null retained capability") }
        guard !data.isEmpty, data.count <= NativeAuditRetentionVerifier.maximumDocumentBytes * 7,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set(["version", "authorization_base64", "anchor_prune_receipt_base64", "post_prune_manifest_base64", "completion_proof_base64", "executor_completion_statement_base64", "executor_quarantined_marker_base64", "executor_manifest_commit_marker_base64", "prior_chain_state", "expected_next_retained", "expected_next_retained_file_identities"]),
              try NativeAuditLog.canonical(object) == data,
              exactInteger(object["version"]) == 4,
              exactBase64(object["authorization_base64"], maximum: NativeAuditRetentionVerifier.maximumDocumentBytes) == preparation.authorizationData,
              exactBase64(object["anchor_prune_receipt_base64"], maximum: NativeAuditRetentionVerifier.maximumDocumentBytes) == receiptData,
              exactBase64(object["post_prune_manifest_base64"], maximum: NativeAuditRetentionVerifier.maximumDocumentBytes) == manifestData,
              exactBase64(object["completion_proof_base64"], maximum: NativeAuditRetentionVerifier.maximumDocumentBytes) == completionProofData,
              let statement = exactBase64(object["executor_completion_statement_base64"], maximum: 4096),
              completionStatementData == nil || statement == completionStatementData,
              let quarantined = exactBase64(object["executor_quarantined_marker_base64"], maximum: 4096),
              quarantinedMarkerData == nil || quarantined == quarantinedMarkerData,
              let committed = exactBase64(object["executor_manifest_commit_marker_base64"], maximum: 4096),
              manifestCommitMarkerData == nil || committed == manifestCommitMarkerData,
              (try NativeAuditPruneExecutorCompletionStatement.verifyCanonicalPhaseChain(quarantinedMarkerData: quarantined, manifestCommitMarkerData: committed, completionStatementData: statement, operationID: preparation.authorization.operationID, manifestHash: NativeAuditPostPruneManifest.decodeCanonical(manifestData).manifestHash)).statementHash.wholeMatch(of: /^[0-9a-f]{64}$/) != nil,
              let prior = object["prior_chain_state"] as? [String: Any],
              try decodeState(prior) == preparation.priorState,
              try decodeSegment(object["expected_next_retained"]) == retained,
              let identityObjects = object["expected_next_retained_file_identities"] as? [[String: Any]],
              try decodeFileIdentities(identityObjects) == retainedIdentities else {
            throw AgentPassNativeError.invalidSignature("Audit prune deletion-evidence bundle is not exact Service schema")
        }
    }

    private static func reservationObject(_ value: NativeAuditPruneMutationReservation) throws -> [String: Any] {
        ["version": value.version, "reservation_id": value.reservationID, "operation_id": value.operationID, "snapshot_revision": value.snapshotRevision, "boundary": try JSONSerialization.jsonObject(with: JSONEncoder().encode(value.boundary)), "chain_state": stateObject(value.chainState)]
    }

    private static func decodeReservation(_ object: [String: Any]) throws -> NativeAuditPruneMutationReservation {
        guard Set(object.keys) == Set(["version", "reservation_id", "operation_id", "snapshot_revision", "boundary", "chain_state"]),
              exactInteger(object["version"]) == NativeAuditPruneMutationReservation.version,
              let reservationID = object["reservation_id"] as? String, isSlug(reservationID),
              let operationID = object["operation_id"] as? String, isSlug(operationID),
              let revision = exactInteger(object["snapshot_revision"]), revision >= 0,
              let boundaryObject = object["boundary"] as? [String: Any],
              let stateObject = object["chain_state"] as? [String: Any] else {
            throw AgentPassNativeError.invalidSignature("Audit prune mutation reservation is not exact schema")
        }
        let boundaryData = try NativeAuditLog.canonical(boundaryObject)
        let boundary = try JSONDecoder().decode(NativeAuditRetentionBoundary.self, from: boundaryData)
        let state = try decodeState(stateObject)
        return NativeAuditPruneMutationReservation(reservationID: reservationID, operationID: operationID, snapshotRevision: revision, boundary: boundary, chainState: state)
    }

    private static func stateObject(_ value: NativeAuditPruneChainState) -> [String: Any] {
        [
            "sequence": value.sequence, "authorization_hash": value.authorizationHash,
            "receipt_hash": value.receiptHash, "manifest_hash": value.manifestHash,
            "last_event_index": value.lastEventIndex, "last_checkpoint_index": value.lastCheckpointIndex,
            "last_receipt_index": value.lastReceiptIndex, "last_event_hash": value.lastEventHash,
            "last_checkpoint_hash": value.lastCheckpointHash,
            "last_archive_receipt_hash": value.lastArchiveReceiptHash
        ]
    }

    private static func decodeState(_ object: [String: Any]) throws -> NativeAuditPruneChainState {
        let keys = Set(["sequence", "authorization_hash", "receipt_hash", "manifest_hash", "last_event_index", "last_checkpoint_index", "last_receipt_index", "last_event_hash", "last_checkpoint_hash", "last_archive_receipt_hash"])
        guard Set(object.keys) == keys,
              let sequence = exactInteger(object["sequence"]), sequence >= 0,
              let event = exactInteger(object["last_event_index"]), event >= 0,
              let checkpoint = exactInteger(object["last_checkpoint_index"]), checkpoint >= 0,
              let receipt = exactInteger(object["last_receipt_index"]), receipt >= 0,
              let authorizationHash = object["authorization_hash"] as? String, isHash(authorizationHash),
              let receiptHash = object["receipt_hash"] as? String, isHash(receiptHash),
              let manifestHash = object["manifest_hash"] as? String, isHash(manifestHash),
              let eventHash = object["last_event_hash"] as? String, isHash(eventHash),
              let checkpointHash = object["last_checkpoint_hash"] as? String, isHash(checkpointHash),
              let archiveReceiptHash = object["last_archive_receipt_hash"] as? String, isHash(archiveReceiptHash) else {
            throw AgentPassNativeError.invalidSignature("Audit prune chain state journal schema is invalid")
        }
        let hashes = [authorizationHash, receiptHash, manifestHash, eventHash, checkpointHash, archiveReceiptHash]
        guard sequence == 0
                ? event == 0 && checkpoint == 0 && receipt == 0 && hashes.allSatisfy({ $0 == NativeAuditLog.zeroHash })
                : event > 0 && checkpoint > 0 && receipt > 0 && !hashes.contains(NativeAuditLog.zeroHash) else {
            throw AgentPassNativeError.invalidSignature("Audit prune chain state is incomplete or rolled back")
        }
        return NativeAuditPruneChainState(sequence: sequence, authorizationHash: authorizationHash, receiptHash: receiptHash, manifestHash: manifestHash, lastEventIndex: event, lastCheckpointIndex: checkpoint, lastReceiptIndex: receipt, lastEventHash: eventHash, lastCheckpointHash: checkpointHash, lastArchiveReceiptHash: archiveReceiptHash)
    }

    private static func segmentObject(_ value: NativeAuditRetentionSegment?) throws -> Any {
        guard let value else { return NSNull() }
        return try JSONSerialization.jsonObject(with: JSONEncoder().encode(value))
    }

    private static func decodeSegment(_ value: Any?) throws -> NativeAuditRetentionSegment? {
        if value is NSNull { return nil }
        guard let object = value as? [String: Any] else {
            throw AgentPassNativeError.invalidSignature("Audit prune retained segment journal schema is invalid")
        }
        let data = try NativeAuditLog.canonical(object)
        let decoded = try JSONDecoder().decode(NativeAuditRetentionSegment.self, from: data)
        guard try segmentObject(decoded) as? NSDictionary == object as NSDictionary? else {
            throw AgentPassNativeError.invalidSignature("Audit prune retained segment is not exact schema")
        }
        return decoded
    }

    private static func fileIdentityObjects(_ values: [NativeAuditRetentionFileIdentity]) throws -> [[String: Any]] {
        try values.map {
            guard let object = try JSONSerialization.jsonObject(with: JSONEncoder().encode($0)) as? [String: Any] else {
                throw AgentPassNativeError.invalidSignature("Audit prune file identity cannot be encoded")
            }
            return object
        }
    }

    private static func decodeFileIdentities(_ values: [[String: Any]]) throws -> [NativeAuditRetentionFileIdentity] {
        let keys = Set(["name", "device", "inode", "mode", "owner", "group", "linkCount", "size", "sha256"])
        return try values.map { object in
            guard Set(object.keys) == keys else {
                throw AgentPassNativeError.invalidSignature("Audit prune file identity journal schema is invalid")
            }
            let data = try NativeAuditLog.canonical(object)
            let value = try JSONDecoder().decode(NativeAuditRetentionFileIdentity.self, from: data)
            guard value.linkCount == 1, value.size > 0, isHash(value.sha256) else {
                throw AgentPassNativeError.invalidSignature("Audit prune file identity journal value is invalid")
            }
            return value
        }
    }

    // MARK: descriptor-relative filesystem primitives

    private static func recordName(index: Int, phase: String) -> String { String(format: "%020d-%@.json", index, phase) }
    private static func recordNamePattern(_ value: String) -> Bool {
        value.range(of: "^[0-9]{20}-(prepared|receipt|completed)\\.json$", options: .regularExpression) != nil
    }
    private func entryExists(_ name: String) throws -> Bool {
        var info = stat()
        if fstatat(descriptor, name, &info, AT_SYMLINK_NOFOLLOW) == 0 { return true }
        if errno == ENOENT { return false }
        throw Self.posixError()
    }
    private static func exactInteger(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue.isFinite, number.doubleValue.rounded(.towardZero) == number.doubleValue,
              number.doubleValue >= 0, number.doubleValue <= Double(NativeAuditRetentionVerifier.maximumSafeInteger) else { return nil }
        return Int(exactly: number.doubleValue)
    }
    private static func exactBase64(_ value: Any?, maximum: Int) -> Data? {
        guard let text = value as? String, text.utf8.count <= maximum * 2,
              let data = Data(base64Encoded: text), data.count <= maximum,
              data.base64EncodedString() == text else { return nil }
        return data
    }
    private static func isHash(_ value: String) -> Bool { value.wholeMatch(of: /^[0-9a-f]{64}$/) != nil }
    fileprivate static func isSlug(_ value: String) -> Bool { value.wholeMatch(of: /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/) != nil }
    fileprivate static func date(_ value: String) -> Date? {
        guard value.utf8.count <= 64 else { return nil }
        let fractional = ISO8601DateFormatter(); fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let result = fractional.date(from: value) { return result }
        return ISO8601DateFormatter().date(from: value)
    }
    private static func realPath(_ path: String) throws -> String {
        guard let pointer = realpath(path, nil) else { throw posixError() }
        defer { free(pointer) }
        return String(cString: pointer)
    }
    private static func validateProtectedAncestors(_ path: String) throws {
        var current = URL(fileURLWithPath: path).deletingLastPathComponent()
        while true {
            var info = stat()
            guard lstat(current.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
                  info.st_uid == 0 || info.st_uid == geteuid(), info.st_mode & 0o022 == 0 else {
                throw AgentPassNativeError.invalidConfiguration("Audit prune journal ancestry is not protected")
            }
            if current.path == "/" { break }
            current.deleteLastPathComponent()
        }
    }
    private static func writeImmutable(_ directory: Int32, name: String, data: Data) throws {
        guard !data.isEmpty, data.count <= maximumRecordBytes else {
            throw AgentPassNativeError.invalidConfiguration("Audit prune journal record exceeds its limit")
        }
        let temporary = ".tmp-\(UUID().uuidString.lowercased())"
        let fd = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw posixError() }
        var renamed = false
        defer { close(fd); if !renamed { _ = unlinkat(directory, temporary, 0) } }
        try writeAll(fd, data: data)
        guard fchmod(fd, 0o400) == 0, fsync(fd) == 0,
              renameatx_np(directory, temporary, directory, name, UInt32(RENAME_EXCL)) == 0,
              fsync(directory) == 0 else { throw posixError() }
        renamed = true
    }
    private static func replaceMutable(_ directory: Int32, name: String, data: Data) throws {
        let temporary = ".tmp-\(UUID().uuidString.lowercased())"
        let fd = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw posixError() }
        var renamed = false
        defer { close(fd); if !renamed { _ = unlinkat(directory, temporary, 0) } }
        try writeAll(fd, data: data)
        guard fchmod(fd, 0o600) == 0, fsync(fd) == 0,
              renameat(directory, temporary, directory, name) == 0,
              fsync(directory) == 0 else { throw posixError() }
        renamed = true
    }
    private static func writeAll(_ fd: Int32, data: Data) throws {
        try data.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let count = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                guard count > 0 else { throw posixError() }
                offset += count
            }
        }
    }
    private static func readFile(_ directory: Int32, name: String, mode: mode_t, maximum: Int) throws -> Data {
        let fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw posixError() }
        defer { close(fd) }
        var before = stat()
        guard fstat(fd, &before) == 0, (before.st_mode & S_IFMT) == S_IFREG,
              before.st_uid == geteuid(), before.st_mode & 0o777 == mode, before.st_nlink == 1,
              before.st_size > 0, before.st_size <= maximum else {
            throw AgentPassNativeError.invalidSignature("Audit prune journal file protection is invalid")
        }
        var data = Data(); data.reserveCapacity(Int(before.st_size)); var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = Darwin.read(fd, &buffer, buffer.count)
            guard count >= 0 else { throw posixError() }
            if count == 0 { break }
            guard data.count <= maximum - count else { throw AgentPassNativeError.invalidSignature("Audit prune journal file exceeds its limit") }
            data.append(buffer, count: count)
        }
        var after = stat()
        guard data.count == Int(before.st_size), fstat(fd, &after) == 0,
              before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_mode == after.st_mode, before.st_uid == after.st_uid,
              before.st_gid == after.st_gid, before.st_nlink == after.st_nlink,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec else {
            throw AgentPassNativeError.invalidSignature("Audit prune journal file changed while read")
        }
        return data
    }
    private static func names(_ directory: Int32) throws -> [String] {
        let duplicate = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard duplicate >= 0, let stream = fdopendir(duplicate) else {
            if duplicate >= 0 { close(duplicate) }
            throw posixError()
        }
        defer { closedir(stream) }
        var values: [String] = []
        while let entry = readdir(stream) {
            let name = withUnsafePointer(to: &entry.pointee.d_name) { pointer in
                pointer.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) { String(cString: $0) }
            }
            if name != "." && name != ".." { values.append(name) }
        }
        return values
    }
    private static func removeSafeTemporary(_ directory: Int32, name: String) throws {
        guard name.wholeMatch(of: /^\.tmp-[0-9a-f-]{36}$/) != nil else {
            throw AgentPassNativeError.invalidSignature("Audit prune journal temporary file name is invalid")
        }
        var info = stat()
        guard fstatat(directory, name, &info, AT_SYMLINK_NOFOLLOW) == 0,
              (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == geteuid(),
              info.st_mode & 0o077 == 0, info.st_nlink == 1 else {
            throw AgentPassNativeError.invalidSignature("Audit prune journal temporary file is unsafe")
        }
        guard unlinkat(directory, name, 0) == 0, fsync(directory) == 0 else { throw posixError() }
    }
    private static func posixError() -> Error { POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
}

/// Production orchestration for one externally authorized prune. The durable receipt is the
/// capability boundary: no call to `NativeAuditPruneExecutor` is reachable before that exact
/// receipt has been verified and committed to the journal.
public final class NativeAuditPruneCoordinator: @unchecked Sendable {
    private let tenant: String
    private let archiveDirectory: String
    private let journal: NativeAuditPruneJournal
    private let verifier: NativeAuditRetentionVerifier
    private let signer: P256MessageSigner
    private let transport: NativeAuditPruneTransport
    private let trustSource: NativeAuditPruneTrustSource
    private let now: @Sendable () -> Date
    private let executorFault: @Sendable (NativeAuditPruneExecutionCrashPoint) throws -> Void
    private let fault: @Sendable (NativeAuditPruneCoordinatorCrashPoint) throws -> Void
    private let lock = NSLock()
    private var submissionInFlightOperationID: String?

    public init(
        tenant: String,
        archiveDirectory: String,
        journal: NativeAuditPruneJournal,
        verifier: NativeAuditRetentionVerifier,
        signer: P256MessageSigner,
        transport: NativeAuditPruneTransport,
        trustSource: NativeAuditPruneTrustSource,
        now: @escaping @Sendable () -> Date = Date.init,
        executorFaultInjector: @escaping @Sendable (NativeAuditPruneExecutionCrashPoint) throws -> Void = { _ in },
        faultInjector: @escaping @Sendable (NativeAuditPruneCoordinatorCrashPoint) throws -> Void = { _ in }
    ) throws {
        guard NativeAuditPruneJournal.isSlug(tenant), archiveDirectory.hasPrefix("/") else {
            throw AgentPassNativeError.invalidConfiguration("Audit prune coordinator tenant or archive path is invalid")
        }
        self.tenant = tenant
        self.archiveDirectory = archiveDirectory
        self.journal = journal
        self.verifier = verifier
        self.signer = signer
        self.transport = transport
        self.trustSource = trustSource
        self.now = now
        executorFault = executorFaultInjector
        fault = faultInjector
    }

    public func status(observation: NativeAuditPruneExternalReceiptObservation? = nil) throws -> NativeAuditPruneJournalStatus {
        try auditedStatus(observation: observation, purpose: .status).status
    }

    @discardableResult
    public func prepare(
        operationID: String,
        retentionSeconds: Int,
        segments: [NativeAuditRetentionSegment],
        expectedNextRetained: NativeAuditRetentionSegment? = nil,
        observation: NativeAuditPruneExternalReceiptObservation? = nil
    ) throws -> NativeAuditPrunePreparedOperation {
        try withLock {
            guard NativeAuditPruneJournal.isSlug(operationID) else {
                throw AgentPassNativeError.invalidConfiguration("Audit prune operation ID is invalid")
            }
            let audited = try auditedStatus(observation: observation, purpose: .prepare, expectedOperationID: operationID)
            let status = audited.status
            if let pending = status.pendingPreparation {
                guard pending.authorization.operationID == operationID,
                      pending.authorization.retentionSeconds == retentionSeconds,
                      pending.authorization.segments == segments,
                      pending.expectedNextRetained == expectedNextRetained else {
                    throw AgentPassNativeError.invalidSignature("A different audit prune operation is already pending")
                }
                let restored = try trustSource.acquireAuditPruneMutationReservation(operationID: operationID, expected: pending.reservation)
                guard restored == pending.reservation else { throw AgentPassNativeError.invalidSignature("Audit prune mutation reservation changed across retry") }
                try trustSource.validateAuditPruneMutationReservation(restored)
                return pending
            }
            guard !status.completed.contains(where: { $0.accepted.preparation.authorization.operationID == operationID }) else {
                throw AgentPassNativeError.invalidSignature("Audit prune operation replay is forbidden")
            }
            let reservation = try trustSource.acquireAuditPruneMutationReservation(operationID: operationID, expected: nil)
            var keepReservation = false
            defer { if !keepReservation { try? trustSource.cancelAuditPruneMutationReservation(reservation) } }
            guard reservation.version == NativeAuditPruneMutationReservation.version,
                  reservation.operationID == operationID,
                  reservation.snapshotRevision == audited.snapshot.revision,
                  reservation.boundary == audited.snapshot.boundary,
                  reservation.chainState == audited.snapshot.chainState else {
                throw AgentPassNativeError.invalidSignature("Audit prune mutation reservation does not match its atomic snapshot")
            }
            try trustSource.validateAuditPruneMutationReservation(reservation)
            let current = now()
            let boundary = reservation.boundary
            let prior = reservation.chainState
            if let last = status.completed.last {
                guard prior == last.nextState else {
                    throw AgentPassNativeError.invalidSignature("Audit prune chain state rolled back or was not durably advanced")
                }
            }
            let observations = try segments.map { try NativeAuditRetentionArchiveObservation.observe(archiveDirectory: archiveDirectory, segment: $0) }
            try Self.validateConstruction(prior: prior, boundary: boundary, segments: observations.map(\.segment), retained: expectedNextRetained, retentionSeconds: retentionSeconds, now: current)
            guard let retained = expectedNextRetained else { throw AgentPassNativeError.invalidConfiguration("Production audit prune requires a non-null retained boundary") }
            let retainedObservation = try NativeAuditRetentionArchiveObservation.observe(archiveDirectory: archiveDirectory, segment: retained)
            let identities = observations.flatMap { $0.fileIdentities ?? [] }
            let retainedIdentities = retainedObservation.fileIdentities
            guard identities.count == observations.count * 3, let retainedIdentities, retainedIdentities.count == 3 else { throw AgentPassNativeError.invalidSignature("Audit prune authorization lacks exact descriptor-observed identities") }
            let timestamp = Self.timestamp(current)
            let authorization = try NativeAuditPruneAuthorization.create(
                tenant: tenant, operationID: operationID, sequence: prior.sequence + 1,
                previousAuthorizationHash: prior.authorizationHash,
                previousPruneReceiptHash: prior.receiptHash,
                previousManifestHash: prior.manifestHash,
                retentionSeconds: retentionSeconds, requestedAt: timestamp,
                boundary: boundary, segments: observations.map(\.segment), signer: signer
            )
            let data = try authorization.canonicalData()
            guard try NativeAuditPruneAuthorization.decodeCanonical(data) == authorization else {
                throw AgentPassNativeError.invalidSignature("Audit prune authorization did not round-trip canonically")
            }
            let prepared = NativeAuditPrunePreparedOperation(authorizationData: data, authorization: authorization, priorState: prior, boundary: boundary, reservation: reservation, expectedNextRetained: expectedNextRetained, fileIdentities: identities, expectedNextRetainedFileIdentities: retainedIdentities, preparedAt: timestamp)
            let durable = try journal.prepare(prepared)
            keepReservation = true
            try fault(.afterPreparationDurable)
            return durable
        }
    }

    /// Submits or re-submits the exact durable bytes. A lost response leaves the preparation
    /// pending; the anchor endpoint's operation/hash idempotency makes retries safe.
    @discardableResult
    public func submitPending(observation: NativeAuditPruneExternalReceiptObservation? = nil) throws -> NativeAuditPruneAcceptedOperation {
        var alreadyAccepted: NativeAuditPruneAcceptedOperation?
        let prepared: NativeAuditPrunePreparedOperation = try withLock {
            guard submissionInFlightOperationID == nil else {
                throw AgentPassNativeError.invalidConfiguration("Audit prune anchor submission is already in progress")
            }
            let status = try auditedStatus(observation: observation, purpose: .submit).status
            guard let prepared = status.pendingPreparation else {
                throw AgentPassNativeError.invalidSignature("No audit prune operation is pending")
            }
            if let receiptData = status.pendingReceiptData {
                alreadyAccepted = try verifiedAccepted(prepared: prepared, receiptData: receiptData, now: now())
                return prepared
            }
            let reservation = try trustSource.acquireAuditPruneMutationReservation(operationID: prepared.authorization.operationID, expected: prepared.reservation)
            guard reservation == prepared.reservation else { throw AgentPassNativeError.invalidSignature("Audit prune mutation reservation changed before anchor submission") }
            try trustSource.validateAuditPruneMutationReservation(reservation)
            submissionInFlightOperationID = prepared.authorization.operationID
            return prepared
        }
        if let alreadyAccepted { return alreadyAccepted }
        let response: Data
        do {
            response = try transport.submitAuditPrune(tenant: tenant, authorizationData: prepared.authorizationData, externalLeaseData: observation?.externalLease?.canonicalData)
        } catch {
            try? withLock { submissionInFlightOperationID = nil }
            throw error
        }
        return try withLock {
            defer { submissionInFlightOperationID = nil }
            let current = try journal.status()
            guard current.pendingPreparation == prepared, current.pendingReceiptData == nil else {
                throw AgentPassNativeError.invalidSignature("Audit prune journal changed across anchor submission")
            }
            let reservation = try trustSource.acquireAuditPruneMutationReservation(operationID: prepared.authorization.operationID, expected: prepared.reservation)
            guard reservation == prepared.reservation else { throw AgentPassNativeError.invalidSignature("Audit prune mutation reservation changed across anchor submission") }
            try trustSource.validateAuditPruneMutationReservation(reservation)
            let accepted = try verifiedAccepted(prepared: prepared, receiptData: response, now: now())
            let durable = try journal.acceptReceipt(operationID: prepared.authorization.operationID, receiptData: accepted.receiptData)
            try fault(.afterReceiptDurable)
            return durable
        }
    }

    /// Executes only a journal-accepted receipt. Filesystem identities, retention age, signed
    /// boundary, and prior chain state are re-read immediately before entering the executor.
    @discardableResult
    public func executePending(observation: NativeAuditPruneExternalReceiptObservation? = nil) throws -> NativeAuditPruneCoordinatorResult {
        try withLock {
            let audited = try auditedStatus(observation: observation, purpose: .execute)
            let status = audited.status
            guard let prepared = status.pendingPreparation,
                  let receiptData = status.pendingReceiptData else {
                throw AgentPassNativeError.invalidSignature("Audit prune execution requires a durable verified anchor receipt")
            }
            let reservation = try trustSource.acquireAuditPruneMutationReservation(operationID: prepared.authorization.operationID, expected: prepared.reservation)
            guard reservation == prepared.reservation else { throw AgentPassNativeError.invalidSignature("Audit prune mutation reservation changed before execution") }
            try trustSource.validateAuditPruneMutationReservation(reservation)
            let current = now()
            let executor = try NativeAuditPruneExecutor(archiveDirectory: archiveDirectory, faultInjector: executorFault)
            let hasIntent = try executor.hasDurableIntent(operationID: prepared.authorization.operationID)
            // Before the first executor intent, every source path must still resolve to the
            // exact prepare-time inode. Once an intent exists, the executor alone decides
            // whether each exact inode may be in source, quarantine, or durably unlinked.
            let plan = try makePlan(prepared: prepared, receiptData: receiptData, now: current, allowExecutorOwnedPaths: hasIntent)
            try fault(.beforeExecutor)
            let execution: NativeAuditPruneExecutionResult
            if hasIntent {
                execution = try executor.recover(plan: plan, verifier: verifier, currentBoundary: prepared.boundary, expectedNextRetained: prepared.expectedNextRetained, expectedNextRetainedFileIdentities: prepared.expectedNextRetainedFileIdentities, completionNow: now, now: current, beforeIrreversibleUnlink: {
                    if let observation { try self.trustSource.validateConsumedAuditPruneExternalLease(observation, purpose: .execute, operationID: prepared.authorization.operationID) }
                })
            } else {
                execution = try executor.execute(plan: plan, verifier: verifier, currentBoundary: prepared.boundary, expectedNextRetained: prepared.expectedNextRetained, expectedNextRetainedFileIdentities: prepared.expectedNextRetainedFileIdentities, completedAt: Self.timestamp(current), now: current, signer: signer, completionNow: now, beforeDurableIntent: {
                    try self.trustSource.validateAuditPruneMutationReservation(reservation)
                    try self.revalidateCurrentIdentities(prepared)
                }, beforeIrreversibleUnlink: {
                    if let observation { try self.trustSource.validateConsumedAuditPruneExternalLease(observation, purpose: .execute, operationID: prepared.authorization.operationID) }
                })
            }
            try fault(.afterExecutorBeforeCompletion)
            let proof = try NativeAuditPruneCompletionProof.create(plan: plan, execution: execution, signer: signer)
            let proofData = try proof.canonicalData()
            let bundle = try NativeAuditPruneJournal.deletionEvidenceBundle(preparation: prepared, receiptData: receiptData, manifestData: execution.manifestData, completionProofData: proofData, completionStatementData: execution.completionStatementData, quarantinedMarkerData: execution.quarantinedMarkerData, manifestCommitMarkerData: execution.manifestCommitMarkerData)
            let next = try verifier.verifyCompletedPruneEvidence(authorizationData: prepared.authorizationData, receiptData: receiptData, manifestData: execution.manifestData, completionProofData: proofData, completionStatementData: execution.completionStatementData, quarantinedMarkerData: execution.quarantinedMarkerData, manifestCommitMarkerData: execution.manifestCommitMarkerData, prior: prepared.priorState, currentBoundary: prepared.boundary, expectedNextRetained: prepared.expectedNextRetained, expectedNextRetainedFileIdentities: prepared.expectedNextRetainedFileIdentities)
            let completed = try journal.complete(operationID: prepared.authorization.operationID, manifestData: execution.manifestData, completionProofData: proofData, completionStatementData: execution.completionStatementData, quarantinedMarkerData: execution.quarantinedMarkerData, manifestCommitMarkerData: execution.manifestCommitMarkerData, deletionEvidenceBundleData: bundle, nextState: next, recovered: hasIntent || execution.recovered)
            try trustSource.completeAuditPruneMutationReservation(reservation, nextState: next)
            try fault(.afterCompletionDurable)
            return completed
        }
    }

    /// Startup reconciliation. It never contacts the anchor when a receipt is already durable,
    /// and never enters the executor while only a preparation exists.
    public func reconcile(
        observation: NativeAuditPruneExternalReceiptObservation? = nil,
        submissionObservation: NativeAuditPruneExternalReceiptObservation? = nil,
        executionObservation: NativeAuditPruneExternalReceiptObservation? = nil
    ) throws -> NativeAuditPruneCoordinatorResult? {
        let audited = try auditedStatus(observation: observation, purpose: .reconcile)
        let status = audited.status
        guard status.pendingPreparation != nil else {
            if let last = status.completed.last,
               audited.snapshot.chainState == last.accepted.preparation.priorState,
               audited.snapshot.activeReservationID == last.accepted.preparation.reservation.reservationID {
                try trustSource.completeAuditPruneMutationReservation(last.accepted.preparation.reservation, nextState: last.nextState)
            }
            return nil
        }
        if status.pendingReceiptData == nil { _ = try submitPending(observation: submissionObservation) }
        return try executePending(observation: executionObservation)
    }

    private func verifiedAccepted(prepared: NativeAuditPrunePreparedOperation, receiptData: Data, now: Date) throws -> NativeAuditPruneAcceptedOperation {
        let plan = try makePlan(prepared: prepared, receiptData: receiptData, now: now, allowExecutorOwnedPaths: false)
        return NativeAuditPruneAcceptedOperation(preparation: prepared, receiptData: receiptData, receipt: plan.receipt)
    }

    private func makePlan(prepared: NativeAuditPrunePreparedOperation, receiptData: Data, now: Date, allowExecutorOwnedPaths: Bool) throws -> NativeAuditPrunePlan {
        guard prepared.fileIdentities.count == prepared.authorization.segments.count * 3 else {
            throw AgentPassNativeError.invalidSignature("Audit prune durable plan has incomplete filesystem identities")
        }
        var persisted: [NativeAuditRetentionArchiveObservation] = []
        for (index, segment) in prepared.authorization.segments.enumerated() {
            let start = index * 3
            persisted.append(try NativeAuditRetentionArchiveObservation(persistedSegment: segment, identities: Array(prepared.fileIdentities[start..<(start + 3)])))
        }
        if !allowExecutorOwnedPaths {
            let current = try prepared.authorization.segments.map {
                try NativeAuditRetentionArchiveObservation.observe(archiveDirectory: archiveDirectory, segment: $0)
            }
            guard current.flatMap({ $0.fileIdentities ?? [] }) == prepared.fileIdentities else {
                throw AgentPassNativeError.invalidSignature("Audit prune archive identity changed after authorization")
            }
        }
        if allowExecutorOwnedPaths {
            return try verifier.persistedExecutablePlan(authorizationData: prepared.authorizationData, receiptData: receiptData, observedArchives: persisted, prior: prepared.priorState, currentBoundary: prepared.boundary)
        }
        return try verifier.eligiblePlan(authorizationData: prepared.authorizationData, receiptData: receiptData, observedArchives: persisted, prior: prepared.priorState, currentBoundary: prepared.boundary, now: now)
    }

    private func revalidateCurrentIdentities(_ prepared: NativeAuditPrunePreparedOperation) throws {
        let current = try prepared.authorization.segments.flatMap {
            try NativeAuditRetentionArchiveObservation.observe(archiveDirectory: archiveDirectory, segment: $0).fileIdentities ?? []
        }
        guard current == prepared.fileIdentities else {
            throw AgentPassNativeError.invalidSignature("Audit prune source identity changed before durable executor intent")
        }
        if let retained = prepared.expectedNextRetained {
            let retainedCurrent = try NativeAuditRetentionArchiveObservation.observe(archiveDirectory: archiveDirectory, segment: retained).fileIdentities
            guard retainedCurrent == prepared.expectedNextRetainedFileIdentities else {
                throw AgentPassNativeError.invalidSignature("Audit prune retained boundary identity changed before durable executor intent")
            }
        } else if prepared.expectedNextRetainedFileIdentities != nil {
            throw AgentPassNativeError.invalidSignature("Audit prune has orphan retained filesystem identities")
        }
    }

    private func auditedStatus(observation: NativeAuditPruneExternalReceiptObservation?, purpose: NativeAuditPruneExternalObservationPurpose, expectedOperationID: String? = nil) throws -> (status: NativeAuditPruneJournalStatus, snapshot: NativeAuditPruneTrustSnapshot) {
        let status = try journal.status()
        let snapshot = try trustSource.currentAuditPruneTrustSnapshot()
        guard snapshot.version == NativeAuditPruneTrustSnapshot.version, snapshot.revision >= 0 else {
            throw AgentPassNativeError.invalidSignature("Audit prune trust snapshot is invalid")
        }
        let known = Set(status.completed.map { $0.accepted.preparation.authorization.operationID } + (status.pendingPreparation.map { [$0.authorization.operationID] } ?? []))
        try NativeAuditPruneExecutor(archiveDirectory: archiveDirectory).verifyKnownOperations(known)
        let operationID = expectedOperationID ?? status.pendingPreparation?.authorization.operationID ?? observation?.operationID
        if let pinned = try trustSource.consumeAuditPruneExternalReceiptObservation(observation, purpose: purpose, operationID: operationID) {
            let localReceipt: NativeAuditPruneReceipt?
            if let data = status.pendingReceiptData { localReceipt = try NativeAuditPruneReceipt.decodeCanonical(data) }
            else { localReceipt = status.completed.last?.accepted.receipt }
            let matchesLocal = localReceipt.map { pinned == .init(sequence: $0.sequence, receiptHash: $0.receiptHash) } ?? false
            let recoverableLostResponse = purpose == .submit && status.pendingReceiptData == nil && status.pendingPreparation?.authorization.sequence == pinned.sequence
            guard matchesLocal || recoverableLostResponse else { throw AgentPassNativeError.invalidSignature("Audit prune journal disagrees with the external Node receipt-chain position") }
        }
        if let pending = status.pendingPreparation {
            guard snapshot.chainState == pending.priorState,
                  snapshot.boundary == pending.boundary,
                  snapshot.activeReservationID == pending.reservation.reservationID else {
                throw AgentPassNativeError.invalidSignature("Audit prune trusted state diverges from the pending journal reservation")
            }
            return (status, snapshot)
        }
        if let last = status.completed.last {
            let finalized = snapshot.chainState == last.nextState && snapshot.activeReservationID == nil
            let completionCrash = snapshot.chainState == last.accepted.preparation.priorState && snapshot.boundary == last.accepted.preparation.boundary && snapshot.activeReservationID == last.accepted.preparation.reservation.reservationID
            guard finalized || completionCrash else {
                throw AgentPassNativeError.invalidSignature("Audit prune trusted chain and journal detect coherent rollback or incomplete mutation")
            }
            return (status, snapshot)
        }
        guard snapshot.chainState == NativeAuditPruneChainState(), snapshot.activeReservationID == nil else {
            throw AgentPassNativeError.invalidSignature("Audit prune trusted chain is ahead of an empty journal")
        }
        return (status, snapshot)
    }

    private func withLock<T>(_ body: () throws -> T) throws -> T {
        lock.lock(); defer { lock.unlock() }
        return try body()
    }

    private static func validateConstruction(prior: NativeAuditPruneChainState, boundary: NativeAuditRetentionBoundary, segments: [NativeAuditRetentionSegment], retained: NativeAuditRetentionSegment?, retentionSeconds: Int, now: Date) throws {
        guard retentionSeconds > 0, retentionSeconds <= NativeAuditRetentionVerifier.maximumSafeInteger,
              !segments.isEmpty, segments.count <= NativeAuditRetentionVerifier.maximumSegments,
              prior.sequence < NativeAuditRetentionVerifier.maximumSafeInteger,
              boundary.anchorEventIndex > 0, boundary.checkpointIndex > 0 else {
            throw AgentPassNativeError.invalidConfiguration("Audit prune construction inputs are invalid")
        }
        var event = prior.lastEventIndex + 1, checkpoint = prior.lastCheckpointIndex + 1, receipt = prior.lastReceiptIndex + 1
        var eventHash = prior.lastEventHash, checkpointHash = prior.lastCheckpointHash, receiptHash = prior.lastArchiveReceiptHash
        var ids = Set<String>(), files = Set<String>()
        for segment in segments {
            guard ids.insert(segment.segmentID).inserted,
                  files.insert(segment.auditArchiveFile).inserted,
                  files.insert(segment.checkpointArchiveFile).inserted,
                  files.insert(segment.receiptArchiveFile).inserted,
                  segment.firstEventIndex == event, segment.firstCheckpointIndex == checkpoint,
                  segment.firstReceiptIndex == receipt, segment.previousEventHash == eventHash,
                  segment.previousCheckpointHash == checkpointHash, segment.previousReceiptHash == receiptHash,
                  segment.firstCheckpointIndex == segment.firstReceiptIndex,
                  segment.lastCheckpointIndex == segment.lastReceiptIndex,
                  segment.anchoredEventIndex == segment.lastEventIndex,
                  segment.anchoredEventHash == segment.terminalEventHash,
                  let anchored = NativeAuditPruneJournal.date(segment.latestAnchorReceivedAt),
                  now.timeIntervalSince(anchored) >= TimeInterval(retentionSeconds) else {
                throw AgentPassNativeError.invalidSignature("Audit prune candidates are not contiguous, unique, anchored, and old enough")
            }
            event = segment.lastEventIndex + 1; checkpoint = segment.lastCheckpointIndex + 1; receipt = segment.lastReceiptIndex + 1
            eventHash = segment.terminalEventHash; checkpointHash = segment.terminalCheckpointHash; receiptHash = segment.terminalReceiptHash
        }
        let last = segments.last!
        guard last.lastCheckpointIndex <= boundary.checkpointIndex,
              last.lastReceiptIndex <= boundary.anchorEventIndex else {
            throw AgentPassNativeError.invalidSignature("Audit prune candidates exceed the anchored boundary")
        }
        if let retained {
            let retainedFiles = Set([retained.auditArchiveFile, retained.checkpointArchiveFile, retained.receiptArchiveFile])
            guard files.isDisjoint(with: retainedFiles), retained.firstEventIndex == event,
                  retained.firstCheckpointIndex == checkpoint, retained.firstReceiptIndex == receipt,
                  retained.previousEventHash == eventHash, retained.previousCheckpointHash == checkpointHash,
                  retained.previousReceiptHash == receiptHash else {
                throw AgentPassNativeError.invalidSignature("Audit prune retained boundary has a gap, overlap, or target collision")
            }
        }
    }

    private static func timestamp(_ value: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: value)
    }

    private static func retainedSegmentHash(_ value: NativeAuditRetentionSegment) throws -> String {
        NativeAuditLog.hash(try NativeAuditLog.canonical(["expected_next_retained": JSONSerialization.jsonObject(with: JSONEncoder().encode(value))]))
    }

    private static func retainedIdentityHash(_ values: [NativeAuditRetentionFileIdentity]) throws -> String {
        NativeAuditLog.hash(try NativeAuditLog.canonical(["retained_file_identities": values.map { try JSONSerialization.jsonObject(with: JSONEncoder().encode($0)) }]))
    }
}
