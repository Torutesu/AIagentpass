import CryptoKit
import Darwin
import Foundation

/// Exact schema-v3 recovery artifact retained before the first anchor request.
/// Reconstructing a plan verifies the pinned recovery policy, installation,
/// replacement possession proof, retiring-key identity, and lifecycle record.
public struct NativeAuditKeyRecoveryPlan: Equatable, Sendable {
    private static let lifecycleRecordKeys: Set<String> = [
        "version", "sequence", "previous_record_hash", "action", "role", "generation",
        "application_tag", "public_key", "fingerprint", "created_at", "continuity",
        "reason", "challenge_id", "old_generation", "old_fingerprint", "old_signature",
        "new_signature", "approval_signature", "approval_public_key", "minimum_retirement_age_seconds",
        "transition_archived", "externally_pinned_head_hash", "record_hash"
    ]

    public let transition: NativeAuditKeyRecoveryTransition
    public let transitionData: Data
    public let retiringPublicKeyX963: Data
    public let lifecycleRecordData: Data

    public init(
        pinnedPolicy: NativeAuditKeyRecoveryPolicy,
        installationID: String,
        authorization: NativeAuditKeyRecoveryAuthorization,
        approvals: [NativeAuditKeyRecoveryApproval],
        replacementSignature: Data,
        retiringPublicKeyX963: Data,
        lifecycleRecordData: Data,
        nowMilliseconds: Int64? = nil
    ) throws {
        let transition = try NativeAuditKeyRecoveryTransition(
            authorization: authorization,
            policy: pinnedPolicy,
            approvals: approvals,
            replacementSignature: replacementSignature
        )
        try transition.verify(
            pinnedPolicy: pinnedPolicy,
            expectedInstallationID: installationID,
            nowMilliseconds: nowMilliseconds
        )
        try self.init(
            transitionData: transition.canonicalData(),
            retiringPublicKeyX963: retiringPublicKeyX963,
            lifecycleRecordData: lifecycleRecordData,
            pinnedPolicy: pinnedPolicy,
            installationID: installationID
        )
    }

    /// Restores exact durable bytes. This never recreates or re-signs the transition.
    public init(
        transitionData: Data,
        retiringPublicKeyX963: Data,
        lifecycleRecordData: Data,
        pinnedPolicy: NativeAuditKeyRecoveryPolicy,
        installationID: String
    ) throws {
        let transition = try NativeAuditKeyRecoveryTransition.decodeCanonical(
            transitionData,
            pinnedPolicy: pinnedPolicy,
            expectedInstallationID: installationID
        )
        guard transition.oldKeyFingerprint == NativeAuditCheckpoints.fingerprint(retiringPublicKeyX963) else {
            throw AgentPassNativeError.invalidKey("Audit-key recovery plan does not bind the retiring public key")
        }
        guard !lifecycleRecordData.isEmpty,
              lifecycleRecordData.count <= NativeLifecycleMutationOutbox.maximumPayloadBytes,
              let decoded = try? JSONSerialization.jsonObject(with: lifecycleRecordData),
              let object = decoded as? [String: Any],
              Set(object.keys) == Self.lifecycleRecordKeys,
              Self.exactInteger(object["version"]) == 1,
              let sequence = Self.exactInteger(object["sequence"]), sequence > 0,
              let previousRecordHash = object["previous_record_hash"] as? String,
              Self.isHash(previousRecordHash),
              object["action"] as? String == "activated",
              object["role"] as? String == NativeKeyRole.auditCheckpoint.rawValue,
              Self.exactInteger(object["generation"]) == transition.toGeneration,
              let publicKeyText = object["public_key"] as? String,
              let publicKey = Data(base64Encoded: publicKeyText),
              publicKey.base64EncodedString() == publicKeyText,
              (try? SSHSIG.authorizedKey(publicKeyX963: publicKey)) == transition.newPublicKey,
              object["fingerprint"] as? String == transition.newKeyFingerprint,
              object["created_at"] as? String == transition.createdAt,
              object["continuity"] as? String == NativeKeyContinuity.recovered.rawValue,
              let reason = object["reason"] as? String,
              reason == "offline-threshold-recovery:\(transition.recoveryRequestID)",
              let challengeID = object["challenge_id"] as? String,
              Self.exactInteger(object["old_generation"]) == transition.fromGeneration,
              object["old_fingerprint"] as? String == transition.oldKeyFingerprint,
              object["old_signature"] as? String == "",
              let newSignatureText = object["new_signature"] as? String,
              let lifecycleNewSignature = Data(base64Encoded: newSignatureText),
              lifecycleNewSignature.base64EncodedString() == newSignatureText,
              NativeP256CanonicalSignature.isCanonicalLowS(lifecycleNewSignature),
              let approvalSignatureText = object["approval_signature"] as? String,
              let recoveryEvidenceData = Data(base64Encoded: approvalSignatureText),
              recoveryEvidenceData.base64EncodedString() == approvalSignatureText,
              object["approval_public_key"] as? String == "",
              Self.exactInteger(object["minimum_retirement_age_seconds"]) == 0,
              object["transition_archived"] as? Bool == false,
              object["externally_pinned_head_hash"] as? String == "",
              let recordHash = object["record_hash"] as? String,
              recordHash == transition.lifecycleHeadHash,
              Self.isHash(recordHash),
              try NativeAuditLog.canonical(object) == lifecycleRecordData else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery lifecycle record is not the exact canonical anchored activation")
        }
        var unhashed = object
        unhashed.removeValue(forKey: "record_hash")
        guard NativeAuditLog.hash(try NativeAuditLog.canonical(unhashed)) == recordHash else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery lifecycle record hash does not bind its exact semantics")
        }
        let lifecycleStatement = NativeKeyTransitionStatement(
            role: .auditCheckpoint,
            oldGeneration: transition.fromGeneration,
            newGeneration: transition.toGeneration,
            oldFingerprint: transition.oldKeyFingerprint,
            newFingerprint: transition.newKeyFingerprint,
            stateSequence: sequence,
            reason: reason,
            challengeID: challengeID,
            createdAt: transition.createdAt,
            previousLifecycleHead: previousRecordHash,
            continuity: .recovered
        )
        guard NativeP256LifecycleVerifier().isValid(
            signature: lifecycleNewSignature,
            message: try lifecycleStatement.canonicalData(),
            publicKeyX963: publicKey
        ) else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery lifecycle replacement proof is invalid")
        }
        let historicalEvidence = try NativeRecoveryVerifier.verifyHistoricalEvidence(recoveryEvidenceData)
        let request = historicalEvidence.request
        let sourcePolicy = try NativeRecoveryVerifier.policyMetadata(
            NativeRecoveryEvidenceBundle.decode(recoveryEvidenceData).policyData
        )
        guard historicalEvidence.requestHash == transition.recoveryRequestID,
              request.installationID == transition.installationID,
              request.role == .auditCheckpoint,
              request.fromGeneration == transition.fromGeneration,
              request.fromFingerprint == transition.oldKeyFingerprint,
              request.proposedGeneration == transition.toGeneration,
              request.proposedPublicKeyX963 == publicKey,
              request.lifecycleHeadHash == previousRecordHash,
              request.issuedAt == transition.createdAt,
              request.expiresAt == transition.expiresAt,
              request.nonce == challengeID,
              sourcePolicy.id == transition.recoveryPolicyID,
              sourcePolicy.threshold == transition.recoveryEvidence.policy.threshold,
              sourcePolicy.authorityPublicKeyFingerprints == transition.recoveryEvidence.policy.keys.map(\.fingerprint).sorted() else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery lifecycle evidence is not bound to the exact schema-v3 authorization")
        }
        self.transition = transition
        self.transitionData = transitionData
        self.retiringPublicKeyX963 = retiringPublicKeyX963
        self.lifecycleRecordData = lifecycleRecordData
    }

    private static func exactInteger(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber,
              String(cString: number.objCType) == "q" else { return nil }
        return number.intValue
    }

    private static func isHash(_ value: String) -> Bool {
        value.wholeMatch(of: /^[0-9a-f]{64}$/) != nil
    }
}

public struct NativeAuditKeyRecoveryJournalPreparation: Equatable, Sendable {
    public let plan: NativeAuditKeyRecoveryPlan
    public let preparedAt: String
    public let planHash: String
    public var operationID: String { plan.transition.operationID }
    public var recoveryRequestID: String { plan.transition.recoveryRequestID }
    public var fromGeneration: Int { plan.transition.fromGeneration }
    public var toGeneration: Int { plan.transition.toGeneration }
}

public struct NativeAuditKeyRecoveryJournalCompletion: Equatable, Sendable {
    public let preparation: NativeAuditKeyRecoveryJournalPreparation
    public let transitionStoreReceiptHash: String
    public let completedAt: String
}

public struct NativeAuditKeyRecoverySubmissionIntent: Equatable, Sendable {
    public let preparation: NativeAuditKeyRecoveryJournalPreparation
    public let intendedAt: String
    public let transitionHash: String
}

public struct NativeAuditKeyRecoveryAbortAuditResult: Equatable, Sendable {
    public let preparation: NativeAuditKeyRecoveryJournalPreparation
    public let authorizationExpiresAt: String
    public let abortedAt: String
    public let abortRecordHash: String
}

public struct NativeAuditKeyRecoveryJournalStatus: Equatable, Sendable {
    public let completed: [NativeAuditKeyRecoveryJournalCompletion]
    public let aborted: [NativeAuditKeyRecoveryAbortAuditResult]
    public let pending: NativeAuditKeyRecoveryJournalPreparation?
    public let pendingSubmissionIntent: NativeAuditKeyRecoverySubmissionIntent?
}

/// Root-private immutable WAL. Records are immutable 0400 files; the mutable
/// 0600 tip is atomically replaced only after each record and directory fsync.
/// A single record ahead of the tip is the only recoverable crash shape.
public final class NativeAuditKeyRecoveryPlanJournal: @unchecked Sendable {
    private static let maximumRecordBytes = NativeAuditKeyRecoveryTransition.maximumEncodedBytes + NativeLifecycleMutationOutbox.maximumPayloadBytes + 128 * 1024
    private static let maximumEntries = 1_000_000
    private static let tipName = "tip.json"
    private static let zeroHash = String(repeating: "0", count: 64)

    private let rootPath: String
    private let rootDescriptor: Int32
    private let rootDevice: dev_t
    private let rootInode: ino_t
    private let tenant: String
    private let policy: NativeAuditKeyRecoveryPolicy
    private let installationID: String
    private let lock = NSLock()

    public init(
        rootPath: String,
        tenant: String,
        pinnedPolicy: NativeAuditKeyRecoveryPolicy,
        installationID: String
    ) throws {
        guard rootPath.hasPrefix("/"), Self.isSlug(tenant), Self.isSlug(installationID) else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key recovery journal path, tenant, or installation is invalid")
        }
        _ = try pinnedPolicy.canonicalData()
        let canonical = try Self.realPath(rootPath)
        guard canonical == rootPath else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key recovery journal path must not traverse symbolic links")
        }
        try Self.validateProtectedAncestors(canonical)
        let descriptor = open(canonical, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw Self.posixError() }
        var info = stat()
        guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == geteuid(), info.st_mode & 0o777 == 0o700 else {
            close(descriptor)
            throw AgentPassNativeError.invalidConfiguration("Audit-key recovery journal must be a service-owned 0700 directory")
        }
        self.rootPath = canonical
        rootDescriptor = descriptor
        rootDevice = info.st_dev
        rootInode = info.st_ino
        self.tenant = tenant
        policy = pinnedPolicy
        self.installationID = installationID
        do {
            try withLock {
                let state = try readState(allowMissingTip: true)
                if !fileExists(Self.tipName) {
                    guard state.preparations.isEmpty, state.completed.isEmpty, state.aborted.isEmpty else {
                        throw AgentPassNativeError.invalidSignature("Audit-key recovery journal tip is missing")
                    }
                    try writeTip(state)
                } else {
                    try verifyOrRecoverTip(state)
                }
            }
        } catch {
            close(descriptor)
            throw error
        }
    }

    deinit { close(rootDescriptor) }

    @discardableResult
    public func prepare(_ plan: NativeAuditKeyRecoveryPlan, preparedAt: String) throws -> NativeAuditKeyRecoveryJournalPreparation {
        let candidate = try makePreparation(plan, preparedAt: preparedAt)
        return try withLock {
            let state = try readVerifiedState()
            if let known = state.preparations[candidate.operationID] {
                guard known == candidate else {
                    throw AgentPassNativeError.invalidSignature("Audit-key recovery generation, operation, or request equivocates")
                }
                guard state.pending == known else {
                    throw AgentPassNativeError.invalidSignature("Historical audit-key recovery operation replay is forbidden")
                }
                return known
            }
            guard state.pending == nil else {
                throw AgentPassNativeError.invalidSignature("A different audit-key recovery plan is already pending")
            }
            guard !state.preparations.values.contains(where: { $0.recoveryRequestID == candidate.recoveryRequestID }) else {
                throw AgentPassNativeError.invalidSignature("Audit-key recovery operation or request replay is forbidden")
            }
            if let previous = state.completed.last {
                // Ordinary v2 rotations may legitimately occur between two v3
                // recoveries. The transition store, not this v3-only journal,
                // proves the intervening chain. The journal still forbids
                // generation rollback and operation/request replay.
                guard candidate.fromGeneration >= previous.preparation.toGeneration else {
                    throw AgentPassNativeError.invalidSignature("Audit-key recovery journal generation moved backwards")
                }
            }
            let sequence = state.recordHashes.count + 1
            try writeImmutable(name: Self.recordName(kind: "prepare", sequence: sequence, preparation: candidate), data: try encode(candidate, completion: nil))
            let updated = try readState(allowMissingTip: false)
            try writeTip(updated)
            return candidate
        }
    }

    @discardableResult
    public func complete(
        _ preparation: NativeAuditKeyRecoveryJournalPreparation,
        transitionStoreReceiptHash: String,
        completedAt: String
    ) throws -> NativeAuditKeyRecoveryJournalCompletion {
        guard Self.isHash(transitionStoreReceiptHash), Self.validTimestamp(completedAt) else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key recovery completion fields are invalid")
        }
        let candidate = NativeAuditKeyRecoveryJournalCompletion(
            preparation: preparation,
            transitionStoreReceiptHash: transitionStoreReceiptHash,
            completedAt: completedAt
        )
        return try withLock {
            let state = try readVerifiedState()
            guard state.preparations[preparation.operationID] == preparation else {
                throw AgentPassNativeError.invalidSignature("Audit-key recovery completion has no exact prepared plan")
            }
            if let known = state.completed.first(where: { $0.preparation.operationID == preparation.operationID }) {
                guard known == candidate else { throw AgentPassNativeError.invalidSignature("Audit-key recovery completion receipt equivocates") }
                return known
            }
            guard state.pending == preparation else {
                throw AgentPassNativeError.invalidSignature("Audit-key recovery completion is stale or out of order")
            }
            if let previous = state.completed.last {
                guard Self.date(completedAt)! >= Self.date(previous.completedAt)! else {
                    throw AgentPassNativeError.invalidSignature("Audit-key recovery completion time moved backwards")
                }
            }
            guard state.pendingSubmissionIntent?.preparation == preparation else {
                throw AgentPassNativeError.invalidSignature("Audit-key recovery completion has no durable submission intent")
            }
            let sequence = state.recordHashes.count + 1
            try writeImmutable(name: Self.recordName(kind: "completed", sequence: sequence, preparation: preparation), data: try encode(preparation, completion: candidate))
            let updated = try readState(allowMissingTip: false)
            try writeTip(updated)
            return candidate
        }
    }

    public func pending() throws -> NativeAuditKeyRecoveryJournalPreparation? {
        try withLock { try readVerifiedState().pending }
    }

    @discardableResult
    public func recordSubmissionIntent(
        _ preparation: NativeAuditKeyRecoveryJournalPreparation,
        intendedAt: String
    ) throws -> NativeAuditKeyRecoverySubmissionIntent {
        guard Self.validTimestamp(intendedAt) else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key recovery submission-intent time is invalid")
        }
        let candidate = NativeAuditKeyRecoverySubmissionIntent(
            preparation: preparation,
            intendedAt: intendedAt,
            transitionHash: preparation.plan.transition.transitionHash
        )
        return try withLock {
            let state = try readVerifiedState()
            guard state.pending == preparation else {
                throw AgentPassNativeError.invalidSignature("Audit-key recovery submission intent has no exact pending plan")
            }
            if let known = state.pendingSubmissionIntent {
                guard known.preparation == preparation,
                      known.transitionHash == candidate.transitionHash else {
                    throw AgentPassNativeError.invalidSignature("Audit-key recovery submission intent equivocates")
                }
                return known
            }
            let sequence = state.recordHashes.count + 1
            try writeImmutable(
                name: Self.recordName(kind: "submission", sequence: sequence, preparation: preparation),
                data: try encodeSubmissionIntent(candidate)
            )
            let updated = try readState(allowMissingTip: false)
            try writeTip(updated)
            return candidate
        }
    }

    @discardableResult
    public func abortExpiredUnsubmitted(
        _ preparation: NativeAuditKeyRecoveryJournalPreparation,
        abortedAt: String
    ) throws -> NativeAuditKeyRecoveryAbortAuditResult {
        guard Self.validTimestamp(abortedAt),
              let abortedDate = Self.date(abortedAt),
              let expiryDate = Self.date(preparation.plan.transition.expiresAt),
              abortedDate >= expiryDate else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key recovery abort requires an expired signed authorization")
        }
        return try withLock {
            let state = try readVerifiedState()
            guard state.pending == preparation else {
                throw AgentPassNativeError.invalidSignature("Audit-key recovery abort has no exact pending plan")
            }
            guard state.pendingSubmissionIntent == nil else {
                throw AgentPassNativeError.invalidSignature("A submitted or ambiguously submitted audit-key recovery plan is never abortable")
            }
            let sequence = state.recordHashes.count + 1
            let data = try encodeAbort(preparation, abortedAt: abortedAt)
            let result = NativeAuditKeyRecoveryAbortAuditResult(
                preparation: preparation,
                authorizationExpiresAt: preparation.plan.transition.expiresAt,
                abortedAt: abortedAt,
                abortRecordHash: Self.hash(data)
            )
            try writeImmutable(name: Self.recordName(kind: "aborted", sequence: sequence, preparation: preparation), data: data)
            let updated = try readState(allowMissingTip: false)
            try writeTip(updated)
            return result
        }
    }

    public func status() throws -> NativeAuditKeyRecoveryJournalStatus {
        try withLock {
            let state = try readVerifiedState()
            return NativeAuditKeyRecoveryJournalStatus(
                completed: state.completed,
                aborted: state.aborted,
                pending: state.pending,
                pendingSubmissionIntent: state.pendingSubmissionIntent
            )
        }
    }

    private struct DiskState {
        let preparations: [String: NativeAuditKeyRecoveryJournalPreparation]
        let completed: [NativeAuditKeyRecoveryJournalCompletion]
        let aborted: [NativeAuditKeyRecoveryAbortAuditResult]
        let pending: NativeAuditKeyRecoveryJournalPreparation?
        let pendingSubmissionIntent: NativeAuditKeyRecoverySubmissionIntent?
        let recordHashes: [String]
        let records: [(generation: Int, kind: Int)]
    }

    private struct Tip: Equatable {
        let tenant: String
        let installationID: String
        let policyHash: String
        let recordCount: Int
        let firstGeneration: Int?
        let lastGeneration: Int?
        let pendingGeneration: Int?
        let latestRecordHash: String
    }

    private func readVerifiedState() throws -> DiskState {
        let state = try readState(allowMissingTip: false)
        try verifyOrRecoverTip(state)
        return state
    }

    private func readState(allowMissingTip: Bool) throws -> DiskState {
        try validateRootIdentity()
        try removeUncommittedTemporaryFiles()
        let names = try directoryNames()
        if !allowMissingTip, !names.contains(Self.tipName) {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery journal tip is missing")
        }
        var files: [(sequence: Int, kind: String, generation: Int, operationHash: String, data: Data)] = []
        for name in names where name != Self.tipName {
            guard let parsed = Self.parseRecordName(name) else {
                throw AgentPassNativeError.invalidSignature("Audit-key recovery journal contains an unknown entry")
            }
            files.append((parsed.sequence, parsed.kind, parsed.generation, parsed.operationHash,
                          try readPrivateFile(name, expectedMode: 0o400)))
        }
        files.sort { $0.sequence < $1.sequence }
        guard files.count <= Self.maximumEntries,
              files.enumerated().allSatisfy({ $0.element.sequence == $0.offset + 1 }) else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery journal limit or replay invariant failed")
        }
        var preparations: [String: NativeAuditKeyRecoveryJournalPreparation] = [:]
        var historicalRequests = Set<String>()
        var completed: [NativeAuditKeyRecoveryJournalCompletion] = []
        var aborted: [NativeAuditKeyRecoveryAbortAuditResult] = []
        var pending: NativeAuditKeyRecoveryJournalPreparation?
        var pendingIntent: NativeAuditKeyRecoverySubmissionIntent?
        var minimumGeneration = 0
        var recordKinds: [(generation: Int, kind: Int)] = []
        for file in files {
            let operationHash: (NativeAuditKeyRecoveryJournalPreparation) -> String = {
                Self.hash(Data($0.operationID.utf8))
            }
            switch file.kind {
            case "prepare":
                let preparation = try decode(file.data, expectedKind: "prepare").preparation
                guard pending == nil,
                      preparation.fromGeneration >= minimumGeneration,
                      preparations[preparation.operationID] == nil,
                      !historicalRequests.contains(preparation.recoveryRequestID),
                      preparation.fromGeneration == file.generation,
                      operationHash(preparation) == file.operationHash else {
                    throw AgentPassNativeError.invalidSignature("Audit-key recovery prepare replays, equivocates, or moves generation backwards")
                }
                preparations[preparation.operationID] = preparation
                historicalRequests.insert(preparation.recoveryRequestID)
                pending = preparation
                recordKinds.append((file.generation, 0))
            case "submission":
                let intent = try decodeSubmissionIntent(file.data)
                guard pending == intent.preparation, pendingIntent == nil,
                      intent.preparation.fromGeneration == file.generation,
                      operationHash(intent.preparation) == file.operationHash else {
                    throw AgentPassNativeError.invalidSignature("Audit-key recovery submission intent is orphaned or equivocates")
                }
                pendingIntent = intent
                recordKinds.append((file.generation, 1))
            case "completed":
                let decoded = try decode(file.data, expectedKind: "completed")
                guard let completion = decoded.completion,
                      pending == completion.preparation,
                      pendingIntent?.preparation == completion.preparation,
                      completion.preparation.fromGeneration == file.generation,
                      operationHash(completion.preparation) == file.operationHash else {
                    throw AgentPassNativeError.invalidSignature("Audit-key recovery completion is orphaned or lacks submission intent")
                }
                if let latest = completed.last, Self.date(completion.completedAt)! < Self.date(latest.completedAt)! {
                    throw AgentPassNativeError.invalidSignature("Audit-key recovery completion time moved backwards")
                }
                completed.append(completion)
                minimumGeneration = completion.preparation.toGeneration
                pending = nil
                pendingIntent = nil
                recordKinds.append((file.generation, 2))
            case "aborted":
                let result = try decodeAbort(file.data)
                guard pending == result.preparation, pendingIntent == nil,
                      result.preparation.fromGeneration == file.generation,
                      operationHash(result.preparation) == file.operationHash else {
                    throw AgentPassNativeError.invalidSignature("Audit-key recovery abort is orphaned or follows submission")
                }
                aborted.append(result)
                minimumGeneration = result.preparation.fromGeneration
                pending = nil
                recordKinds.append((file.generation, 3))
            default:
                throw AgentPassNativeError.invalidSignature("Audit-key recovery journal record kind is invalid")
            }
        }
        return DiskState(
            preparations: preparations,
            completed: completed,
            aborted: aborted,
            pending: pending,
            pendingSubmissionIntent: pendingIntent,
            recordHashes: files.map { Self.hash($0.data) },
            records: recordKinds
        )
    }

    private func makePreparation(_ plan: NativeAuditKeyRecoveryPlan, preparedAt: String) throws -> NativeAuditKeyRecoveryJournalPreparation {
        let exact = try NativeAuditKeyRecoveryPlan(
            transitionData: plan.transitionData,
            retiringPublicKeyX963: plan.retiringPublicKeyX963,
            lifecycleRecordData: plan.lifecycleRecordData,
            pinnedPolicy: policy,
            installationID: installationID
        )
        guard exact == plan, plan.transition.tenant == tenant, Self.validTimestamp(preparedAt) else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key recovery journal plan fields are invalid")
        }
        return NativeAuditKeyRecoveryJournalPreparation(
            plan: plan,
            preparedAt: preparedAt,
            planHash: Self.hash(Self.planBytes(plan))
        )
    }

    private static func planBytes(_ plan: NativeAuditKeyRecoveryPlan) -> Data {
        var result = Data()
        for field in [plan.transitionData, plan.retiringPublicKeyX963, plan.lifecycleRecordData] {
            var length = UInt64(field.count).bigEndian
            withUnsafeBytes(of: &length) { result.append(contentsOf: $0) }
            result.append(field)
        }
        return result
    }

    private func encode(
        _ preparation: NativeAuditKeyRecoveryJournalPreparation,
        completion: NativeAuditKeyRecoveryJournalCompletion?
    ) throws -> Data {
        let plan = preparation.plan
        var object: [String: Any] = [
            "version": 1,
            "record_kind": completion == nil ? "prepare" : "completed",
            "tenant": tenant,
            "installation_id": installationID,
            "recovery_policy_hash": policy.policyHash,
            "operation_id": preparation.operationID,
            "recovery_request_id": preparation.recoveryRequestID,
            "from_generation": preparation.fromGeneration,
            "to_generation": preparation.toGeneration,
            "prepared_at": preparation.preparedAt,
            "transition_data": plan.transitionData.base64EncodedString(),
            "transition_bytes": plan.transitionData.count,
            "retiring_public_key_x963": plan.retiringPublicKeyX963.base64EncodedString(),
            "retiring_public_key_bytes": plan.retiringPublicKeyX963.count,
            "lifecycle_record_data": plan.lifecycleRecordData.base64EncodedString(),
            "lifecycle_record_bytes": plan.lifecycleRecordData.count,
            "plan_hash": preparation.planHash
        ]
        if let completion {
            object["transition_store_receipt_hash"] = completion.transitionStoreReceiptHash
            object["completed_at"] = completion.completedAt
        }
        object["record_hash"] = Self.hash(try Self.canonical(object))
        return try Self.canonical(object)
    }

    private func decode(
        _ data: Data,
        expectedKind: String
    ) throws -> (preparation: NativeAuditKeyRecoveryJournalPreparation, completion: NativeAuditKeyRecoveryJournalCompletion?) {
        guard !data.isEmpty, data.count <= Self.maximumRecordBytes,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              try Self.canonical(object) == data,
              Self.integer(object["version"]) == 1,
              object["record_kind"] as? String == expectedKind,
              object["tenant"] as? String == tenant,
              object["installation_id"] as? String == installationID,
              object["recovery_policy_hash"] as? String == policy.policyHash,
              let operationID = object["operation_id"] as? String,
              let requestID = object["recovery_request_id"] as? String,
              let fromGeneration = Self.integer(object["from_generation"]),
              let toGeneration = Self.integer(object["to_generation"]),
              let preparedAt = object["prepared_at"] as? String,
              let transition = Self.canonicalBase64(object["transition_data"]),
              Self.integer(object["transition_bytes"]) == transition.count,
              let retiring = Self.canonicalBase64(object["retiring_public_key_x963"]),
              Self.integer(object["retiring_public_key_bytes"]) == retiring.count,
              let lifecycle = Self.canonicalBase64(object["lifecycle_record_data"]),
              Self.integer(object["lifecycle_record_bytes"]) == lifecycle.count,
              let planHash = object["plan_hash"] as? String,
              let recordHash = object["record_hash"] as? String else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery journal record schema is invalid")
        }
        let baseKeys: Set<String> = [
            "version", "record_kind", "tenant", "installation_id", "recovery_policy_hash",
            "operation_id", "recovery_request_id", "from_generation", "to_generation", "prepared_at",
            "transition_data", "transition_bytes", "retiring_public_key_x963", "retiring_public_key_bytes",
            "lifecycle_record_data", "lifecycle_record_bytes", "plan_hash", "record_hash"
        ]
        let expectedKeys = expectedKind == "completed"
            ? baseKeys.union(["transition_store_receipt_hash", "completed_at"])
            : baseKeys
        guard Set(object.keys) == expectedKeys else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery journal record has unknown or missing fields")
        }
        var unhashed = object
        unhashed.removeValue(forKey: "record_hash")
        guard recordHash == Self.hash(try Self.canonical(unhashed)) else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery journal record hash is invalid")
        }
        let plan = try NativeAuditKeyRecoveryPlan(
            transitionData: transition,
            retiringPublicKeyX963: retiring,
            lifecycleRecordData: lifecycle,
            pinnedPolicy: policy,
            installationID: installationID
        )
        let preparation = try makePreparation(plan, preparedAt: preparedAt)
        guard preparation.operationID == operationID,
              preparation.recoveryRequestID == requestID,
              preparation.fromGeneration == fromGeneration,
              preparation.toGeneration == toGeneration,
              preparation.planHash == planHash else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery journal plan binding is invalid")
        }
        if expectedKind == "completed" {
            guard let receiptHash = object["transition_store_receipt_hash"] as? String,
                  Self.isHash(receiptHash), let completedAt = object["completed_at"] as? String,
                  Self.validTimestamp(completedAt) else {
                throw AgentPassNativeError.invalidSignature("Audit-key recovery completion binding is invalid")
            }
            return (preparation, NativeAuditKeyRecoveryJournalCompletion(
                preparation: preparation,
                transitionStoreReceiptHash: receiptHash,
                completedAt: completedAt
            ))
        }
        return (preparation, nil)
    }

    private func encodeSubmissionIntent(_ intent: NativeAuditKeyRecoverySubmissionIntent) throws -> Data {
        var object = try Self.object(encode(intent.preparation, completion: nil))
        object.removeValue(forKey: "record_hash")
        object["record_kind"] = "submission"
        object["intended_at"] = intent.intendedAt
        object["transition_hash"] = intent.transitionHash
        object["record_hash"] = Self.hash(try Self.canonical(object))
        return try Self.canonical(object)
    }

    private func decodeSubmissionIntent(_ data: Data) throws -> NativeAuditKeyRecoverySubmissionIntent {
        var object = try Self.object(data)
        guard try Self.canonical(object) == data,
              object["record_kind"] as? String == "submission",
              let intendedAt = object["intended_at"] as? String, Self.validTimestamp(intendedAt),
              let transitionHash = object["transition_hash"] as? String, Self.isHash(transitionHash),
              let recordHash = object["record_hash"] as? String else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery submission-intent schema is invalid")
        }
        var unhashed = object
        unhashed.removeValue(forKey: "record_hash")
        guard recordHash == Self.hash(try Self.canonical(unhashed)) else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery submission-intent hash is invalid")
        }
        object.removeValue(forKey: "intended_at")
        object.removeValue(forKey: "transition_hash")
        object["record_kind"] = "prepare"
        object.removeValue(forKey: "record_hash")
        object["record_hash"] = Self.hash(try Self.canonical(object))
        let preparation = try decode(Self.canonical(object), expectedKind: "prepare").preparation
        guard transitionHash == preparation.plan.transition.transitionHash else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery submission intent does not bind the exact transition")
        }
        return NativeAuditKeyRecoverySubmissionIntent(
            preparation: preparation, intendedAt: intendedAt, transitionHash: transitionHash
        )
    }

    private func encodeAbort(
        _ preparation: NativeAuditKeyRecoveryJournalPreparation,
        abortedAt: String
    ) throws -> Data {
        var object = try Self.object(encode(preparation, completion: nil))
        object.removeValue(forKey: "record_hash")
        object["record_kind"] = "aborted"
        object["authorization_expires_at"] = preparation.plan.transition.expiresAt
        object["aborted_at"] = abortedAt
        object["record_hash"] = Self.hash(try Self.canonical(object))
        return try Self.canonical(object)
    }

    private func decodeAbort(_ data: Data) throws -> NativeAuditKeyRecoveryAbortAuditResult {
        var object = try Self.object(data)
        guard try Self.canonical(object) == data,
              object["record_kind"] as? String == "aborted",
              let expiresAt = object["authorization_expires_at"] as? String,
              let abortedAt = object["aborted_at"] as? String,
              Self.validTimestamp(expiresAt), Self.validTimestamp(abortedAt),
              let expiry = Self.date(expiresAt), let abortDate = Self.date(abortedAt), abortDate >= expiry,
              let recordHash = object["record_hash"] as? String else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery abort schema or expiry boundary is invalid")
        }
        var unhashed = object
        unhashed.removeValue(forKey: "record_hash")
        guard recordHash == Self.hash(try Self.canonical(unhashed)) else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery abort hash is invalid")
        }
        object.removeValue(forKey: "authorization_expires_at")
        object.removeValue(forKey: "aborted_at")
        object["record_kind"] = "prepare"
        object.removeValue(forKey: "record_hash")
        object["record_hash"] = Self.hash(try Self.canonical(object))
        let preparation = try decode(Self.canonical(object), expectedKind: "prepare").preparation
        guard expiresAt == preparation.plan.transition.expiresAt else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery abort does not bind signed expiry")
        }
        return NativeAuditKeyRecoveryAbortAuditResult(
            preparation: preparation,
            authorizationExpiresAt: expiresAt,
            abortedAt: abortedAt,
            // Public audit identity is the hash of the exact immutable bytes on
            // disk, not the record's internal self-hash (which excludes its own
            // `record_hash` field). This remains byte-exact across restart and
            // one-record-ahead tip repair.
            abortRecordHash: Self.hash(data)
        )
    }

    private func verifyOrRecoverTip(_ state: DiskState) throws {
        let expected = makeTip(state)
        let actual = try decodeTip(readPrivateFile(Self.tipName, expectedMode: 0o600))
        if actual == expected { return }
        guard actual == tipBeforeLastRecord(state) else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery journal tip detects truncation or tampering")
        }
        try writeTip(state)
    }

    private func makeTip(_ state: DiskState) -> Tip {
        let records = Self.recordKinds(state)
        return Tip(
            tenant: tenant,
            installationID: installationID,
            policyHash: policy.policyHash,
            recordCount: records.count,
            firstGeneration: records.first?.generation,
            lastGeneration: records.last?.generation,
            pendingGeneration: state.pending?.fromGeneration,
            latestRecordHash: state.recordHashes.last ?? Self.zeroHash
        )
    }

    private func tipBeforeLastRecord(_ state: DiskState) -> Tip {
        let records = Array(Self.recordKinds(state).dropLast())
        return Tip(
            tenant: tenant,
            installationID: installationID,
            policyHash: policy.policyHash,
            recordCount: records.count,
            firstGeneration: records.first?.generation,
            lastGeneration: records.last?.generation,
            pendingGeneration: records.last.map { $0.kind == 0 || $0.kind == 1 ? $0.generation : nil } ?? nil,
            latestRecordHash: state.recordHashes.dropLast().last ?? Self.zeroHash
        )
    }

    private static func recordKinds(_ state: DiskState) -> [(generation: Int, kind: Int)] {
        state.records
    }

    private func writeTip(_ state: DiskState) throws {
        let data = try encodeTip(makeTip(state))
        let temporary = ".tip-\(UUID().uuidString).tmp"
        let descriptor = openat(rootDescriptor, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw Self.posixError() }
        var cleanup = true
        defer { close(descriptor); if cleanup { unlinkat(rootDescriptor, temporary, 0) } }
        try Self.writeAll(data, descriptor)
        guard fchmod(descriptor, 0o600) == 0, fsync(descriptor) == 0 else { throw Self.posixError() }
        try validateDescriptor(descriptor, expectedMode: 0o600)
        try validateRootIdentity()
        guard renameat(rootDescriptor, temporary, rootDescriptor, Self.tipName) == 0 else { throw Self.posixError() }
        cleanup = false
        try validatePathIdentity(Self.tipName, descriptor: descriptor)
        guard fsync(rootDescriptor) == 0 else { throw Self.posixError() }
        try validateRootIdentity()
        try validatePathIdentity(Self.tipName, descriptor: descriptor)
    }

    private func encodeTip(_ tip: Tip) throws -> Data {
        var object: [String: Any] = [
            "version": 1,
            "tenant": tip.tenant,
            "installation_id": tip.installationID,
            "recovery_policy_hash": tip.policyHash,
            "record_count": tip.recordCount,
            "first_generation": tip.firstGeneration ?? NSNull(),
            "last_generation": tip.lastGeneration ?? NSNull(),
            "pending_generation": tip.pendingGeneration ?? NSNull(),
            "latest_record_hash": tip.latestRecordHash
        ]
        object["tip_hash"] = Self.hash(try Self.canonical(object))
        return try Self.canonical(object)
    }

    private func decodeTip(_ data: Data) throws -> Tip {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == ["version", "tenant", "installation_id", "recovery_policy_hash", "record_count", "first_generation", "last_generation", "pending_generation", "latest_record_hash", "tip_hash"],
              try Self.canonical(object) == data,
              Self.integer(object["version"]) == 1,
              object["tenant"] as? String == tenant,
              object["installation_id"] as? String == installationID,
              object["recovery_policy_hash"] as? String == policy.policyHash,
              let count = Self.integer(object["record_count"]), count >= 0,
              let latest = object["latest_record_hash"] as? String, Self.isHash(latest),
              let tipHash = object["tip_hash"] as? String else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery journal tip schema is invalid")
        }
        var unhashed = object
        unhashed.removeValue(forKey: "tip_hash")
        guard tipHash == Self.hash(try Self.canonical(unhashed)) else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery journal tip hash is invalid")
        }
        func nullable(_ key: String) -> Int? { object[key] is NSNull ? nil : Self.integer(object[key]) }
        return Tip(
            tenant: tenant,
            installationID: installationID,
            policyHash: policy.policyHash,
            recordCount: count,
            firstGeneration: nullable("first_generation"),
            lastGeneration: nullable("last_generation"),
            pendingGeneration: nullable("pending_generation"),
            latestRecordHash: latest
        )
    }

    private func writeImmutable(name: String, data: Data) throws {
        guard !data.isEmpty, data.count <= Self.maximumRecordBytes else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key recovery journal record is too large")
        }
        try validateRootIdentity()
        if fileExists(name) {
            guard try readPrivateFile(name, expectedMode: 0o400) == data else {
                throw AgentPassNativeError.invalidSignature("Refusing to overwrite audit-key recovery journal evidence")
            }
            return
        }
        let temporary = ".record-\(UUID().uuidString).tmp"
        let descriptor = openat(rootDescriptor, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw Self.posixError() }
        var cleanup = true
        defer { close(descriptor); if cleanup { unlinkat(rootDescriptor, temporary, 0) } }
        try Self.writeAll(data, descriptor)
        guard fchmod(descriptor, 0o400) == 0, fsync(descriptor) == 0 else { throw Self.posixError() }
        try validateDescriptor(descriptor, expectedMode: 0o400)
        guard renameatx_np(rootDescriptor, temporary, rootDescriptor, name, UInt32(RENAME_EXCL)) == 0 else {
            if errno == EEXIST, try readPrivateFile(name, expectedMode: 0o400) == data { return }
            throw AgentPassNativeError.invalidSignature("Audit-key recovery journal destination exists or cannot be committed")
        }
        cleanup = false
        try validatePathIdentity(name, descriptor: descriptor)
        guard fsync(rootDescriptor) == 0 else { throw Self.posixError() }
        try validateRootIdentity()
        try validatePathIdentity(name, descriptor: descriptor)
    }

    private func readPrivateFile(_ name: String, expectedMode: mode_t) throws -> Data {
        guard !name.contains("/"), name.first != "." else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key recovery journal filename is invalid")
        }
        try validateRootIdentity()
        let descriptor = openat(rootDescriptor, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw Self.posixError() }
        defer { close(descriptor) }
        try validateDescriptor(descriptor, expectedMode: expectedMode)
        var before = stat()
        guard fstat(descriptor, &before) == 0, before.st_size > 0, before.st_size <= Self.maximumRecordBytes else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key recovery journal record size is invalid")
        }
        var data = Data(count: Int(before.st_size))
        try data.withUnsafeMutableBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let amount = Darwin.read(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                guard amount > 0 else { throw Self.posixError() }
                offset += amount
            }
        }
        var after = stat()
        guard fstat(descriptor, &after) == 0,
              before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery journal record changed while being read")
        }
        try validateRootIdentity()
        try validatePathIdentity(name, descriptor: descriptor)
        return data
    }

    private func validateDescriptor(_ descriptor: Int32, expectedMode: mode_t) throws {
        var info = stat()
        guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == geteuid(), info.st_mode & 0o777 == expectedMode, info.st_nlink == 1 else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key recovery journal files must be owner-only single-link regular files")
        }
    }

    private func validatePathIdentity(_ name: String, descriptor: Int32) throws {
        var descriptorInfo = stat()
        var pathInfo = stat()
        guard fstat(descriptor, &descriptorInfo) == 0,
              fstatat(rootDescriptor, name, &pathInfo, AT_SYMLINK_NOFOLLOW) == 0,
              (pathInfo.st_mode & S_IFMT) == S_IFREG,
              descriptorInfo.st_dev == pathInfo.st_dev,
              descriptorInfo.st_ino == pathInfo.st_ino else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery journal pathname was substituted")
        }
    }

    private func validateRootIdentity() throws {
        try Self.validateProtectedAncestors(rootPath)
        var descriptorInfo = stat()
        var pathInfo = stat()
        guard fstat(rootDescriptor, &descriptorInfo) == 0,
              descriptorInfo.st_dev == rootDevice, descriptorInfo.st_ino == rootInode,
              descriptorInfo.st_uid == geteuid(), descriptorInfo.st_mode & 0o777 == 0o700,
              lstat(rootPath, &pathInfo) == 0, (pathInfo.st_mode & S_IFMT) == S_IFDIR,
              pathInfo.st_dev == rootDevice, pathInfo.st_ino == rootInode else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery journal directory was substituted or made permissive")
        }
    }

    private func directoryNames() throws -> [String] {
        let names = try FileManager.default.contentsOfDirectory(atPath: rootPath).sorted()
        guard names.count <= Self.maximumEntries * 2 + 1 else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key recovery journal record limit exceeded")
        }
        return names
    }

    /// A crash before rename can leave only a randomly named temporary inode.
    /// Such a name is never authoritative. It may be removed only after proving
    /// that it is still the same private, service-owned, single-link regular file
    /// opened descriptor-relatively from the pinned journal directory.
    private func removeUncommittedTemporaryFiles() throws {
        let names = try FileManager.default.contentsOfDirectory(atPath: rootPath).sorted()
        for name in names where Self.isTemporaryName(name) {
            try removeUncommittedTemporaryFile(name)
        }
    }

    private func removeUncommittedTemporaryFile(_ name: String) throws {
        try validateRootIdentity()
        let descriptor = openat(rootDescriptor, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw Self.posixError() }
        defer { close(descriptor) }
        var info = stat()
        guard fstat(descriptor, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == geteuid(),
              (info.st_mode & 0o777 == 0o600 || info.st_mode & 0o777 == 0o400),
              info.st_nlink == 1,
              info.st_size >= 0,
              info.st_size <= Self.maximumRecordBytes else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key recovery temporary file is unsafe")
        }
        try validatePathIdentity(name, descriptor: descriptor)
        guard unlinkat(rootDescriptor, name, 0) == 0,
              fsync(rootDescriptor) == 0 else { throw Self.posixError() }
        try validateRootIdentity()
    }

    private func fileExists(_ name: String) -> Bool {
        var info = stat()
        return fstatat(rootDescriptor, name, &info, AT_SYMLINK_NOFOLLOW) == 0
    }

    private func withLock<T>(_ body: () throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        guard flock(rootDescriptor, LOCK_EX) == 0 else { throw Self.posixError() }
        defer { flock(rootDescriptor, LOCK_UN) }
        return try body()
    }

    private static func recordName(
        kind: String,
        sequence: Int,
        preparation: NativeAuditKeyRecoveryJournalPreparation
    ) -> String {
        String(format: "%@-%020d-%020d-%@.json", kind, sequence, preparation.fromGeneration,
               hash(Data(preparation.operationID.utf8)))
    }

    private static func parseRecordName(_ name: String) -> (kind: String, sequence: Int, generation: Int, operationHash: String)? {
        guard let match = name.wholeMatch(of: /^(prepare|submission|completed|aborted)-([0-9]{20})-([0-9]{20})-([0-9a-f]{64})\.json$/),
              let sequence = Int(match.2), sequence > 0,
              let generation = Int(match.3), generation > 0 else { return nil }
        return (String(match.1), sequence, generation, String(match.4))
    }

    private static func isTemporaryName(_ name: String) -> Bool {
        name.wholeMatch(of: /^\.(record|tip)-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\.tmp$/) != nil
    }

    private static func validateProtectedAncestors(_ path: String) throws {
        var current = "/"
        var root = stat()
        guard lstat(current, &root) == 0, (root.st_mode & S_IFMT) == S_IFDIR,
              root.st_uid == 0, root.st_mode & 0o022 == 0 else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key recovery filesystem root is not protected")
        }
        for component in path.split(separator: "/", omittingEmptySubsequences: true) {
            current = current == "/" ? "/\(component)" : "\(current)/\(component)"
            var info = stat()
            guard lstat(current, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
                  (info.st_uid == 0 || info.st_uid == geteuid()), info.st_mode & 0o022 == 0 else {
                throw AgentPassNativeError.invalidConfiguration("Audit-key recovery journal ancestors must be trusted non-writable directories")
            }
        }
    }

    private static func realPath(_ path: String) throws -> String {
        guard let value = Darwin.realpath(path, nil) else { throw posixError() }
        defer { free(value) }
        return String(cString: value)
    }

    private static func canonicalBase64(_ value: Any?) -> Data? {
        guard let text = value as? String, let data = Data(base64Encoded: text),
              data.base64EncodedString() == text else { return nil }
        return data
    }

    private static func integer(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber,
              String(cString: number.objCType) == "q" else { return nil }
        return number.intValue
    }

    private static func validTimestamp(_ value: String) -> Bool {
        value.range(of: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$", options: .regularExpression) != nil && date(value) != nil
    }

    private static func date(_ value: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: value)
    }

    private static func isSlug(_ value: String) -> Bool {
        value.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", options: .regularExpression) != nil
    }

    private static func isHash(_ value: String) -> Bool {
        value.wholeMatch(of: /^[0-9a-f]{64}$/) != nil
    }

    private static func canonical(_ object: [String: Any]) throws -> Data {
        guard JSONSerialization.isValidJSONObject(object) else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key recovery journal value is not JSON")
        }
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    }

    private static func object(_ data: Data) throws -> [String: Any] {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery journal record is not a JSON object")
        }
        return object
    }

    private static func hash(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func writeAll(_ data: Data, _ descriptor: Int32) throws {
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let amount = Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                guard amount > 0 else { throw Self.posixError() }
                offset += amount
            }
        }
    }

    private static func posixError() -> POSIXError {
        POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
}

public protocol NativeAuditKeyRecoveryTransitionTransport: Sendable {
    /// The request is exactly `transitionData`; the response must be the exact
    /// canonical schema-v2 transition receipt bytes.
    func submitRecoveryTransition(transitionData: Data) throws -> Data
}

/// Non-mutating full lifecycle replay boundary. Production uses the protected
/// lifecycle store so staged-key state, signatures, threshold evidence,
/// reason/challenge, and exact next-record semantics are all checked together.
public protocol NativeAuditKeyRecoveryPreparedRecordVerifier: Sendable {
    func verifyPreparedAuditRecoveryRecord(_ data: Data) throws -> String
}

extension NativeKeyLifecycleStore: NativeAuditKeyRecoveryPreparedRecordVerifier {
    public func verifyPreparedAuditRecoveryRecord(_ data: Data) throws -> String {
        try validatePreparedRecordData(data).headHash
    }
}

public struct NativeAuditKeyRecoveryActivationAuthorization: Equatable, Sendable {
    public let transition: NativeAuditKeyRecoveryTransition
    public let receipt: NativeAuditKeyTransitionReceipt
    public let transitionData: Data
    public let receiptData: Data
    public let transitionStoreStatus: NativeAuditKeyTransitionStoreStatus
    public let recoveredFromStore: Bool
}

/// Crash-safe schema-v3 audit-key recovery orchestrator. It performs at most
/// one network submission per call and never returns activation authority until
/// the exact transition/receipt pair has been verified and fsync'd by the store.
public final class NativeAuditKeyRecoveryCoordinator: @unchecked Sendable {
    private static let zeroHash = String(repeating: "0", count: 64)

    private let tenant: String
    private let installationID: String
    private let policy: NativeAuditKeyRecoveryPolicy
    private let store: NativeAuditKeyTransitionStore
    private let journal: NativeAuditKeyRecoveryPlanJournal
    private let transport: any NativeAuditKeyRecoveryTransitionTransport
    private let preparedRecordVerifier: any NativeAuditKeyRecoveryPreparedRecordVerifier
    private let lifecycleAncestryVerifier: any NativeLifecycleHeadAncestryVerifier
    private let lock = NSLock()

    public init(
        tenant: String,
        installationID: String,
        pinnedPolicy: NativeAuditKeyRecoveryPolicy,
        transitionStore: NativeAuditKeyTransitionStore,
        planJournal: NativeAuditKeyRecoveryPlanJournal,
        transport: any NativeAuditKeyRecoveryTransitionTransport,
        preparedRecordVerifier: any NativeAuditKeyRecoveryPreparedRecordVerifier,
        lifecycleAncestryVerifier: any NativeLifecycleHeadAncestryVerifier
    ) throws {
        guard tenant.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", options: .regularExpression) != nil,
              installationID.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", options: .regularExpression) != nil else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key recovery coordinator identity is invalid")
        }
        _ = try pinnedPolicy.canonicalData()
        self.tenant = tenant
        self.installationID = installationID
        policy = pinnedPolicy
        store = transitionStore
        journal = planJournal
        self.transport = transport
        self.preparedRecordVerifier = preparedRecordVerifier
        self.lifecycleAncestryVerifier = lifecycleAncestryVerifier
        try validateDurableState()
    }

    /// Source-compatible fail-closed boundary for callers not yet migrated to
    /// inject the protected lifecycle store. Recovery cannot be enabled safely
    /// through this initializer.
    public convenience init(
        tenant: String,
        installationID: String,
        pinnedPolicy: NativeAuditKeyRecoveryPolicy,
        transitionStore: NativeAuditKeyTransitionStore,
        planJournal: NativeAuditKeyRecoveryPlanJournal,
        transport: any NativeAuditKeyRecoveryTransitionTransport
    ) throws {
        throw AgentPassNativeError.invalidConfiguration("Audit-key recovery requires prepared-record and lifecycle-ancestry verifiers")
    }

    public func pendingPlan() throws -> NativeAuditKeyRecoveryPlan? {
        lock.lock(); defer { lock.unlock() }
        return try journal.pending()?.plan
    }

    /// Aborts only a signed plan that expired without any durable evidence that
    /// it was submitted. `nowMilliseconds` is supplied by the trusted service
    /// boundary; ambiguous/lost-response plans remain permanently non-abortable.
    public func abortExpiredUnsubmittedPending(
        nowMilliseconds: Int64
    ) throws -> NativeAuditKeyRecoveryAbortAuditResult {
        lock.lock(); defer { lock.unlock() }
        guard nowMilliseconds >= 0 else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key recovery abort time is invalid")
        }
        try validateDurableState()
        let state = try journal.status()
        guard let preparation = state.pending else {
            throw AgentPassNativeError.invalidConfiguration("There is no pending audit-key recovery plan to abort")
        }
        guard state.pendingSubmissionIntent == nil else {
            throw AgentPassNativeError.invalidSignature("A submitted or ambiguously submitted audit-key recovery plan is never abortable")
        }
        let storeStatus = try store.status()
        if try recoveredAuthorization(plan: preparation.plan, status: storeStatus) != nil {
            throw AgentPassNativeError.invalidSignature("The pending audit-key recovery transition was already accepted")
        }
        guard let expiry = Self.milliseconds(preparation.plan.transition.expiresAt),
              nowMilliseconds >= expiry else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key recovery authorization has not expired")
        }
        return try journal.abortExpiredUnsubmitted(
            preparation,
            abortedAt: Self.timestamp(nowMilliseconds)
        )
    }

    /// Production construction boundary: signatures are verified and exact
    /// transition/lifecycle bytes are durable before this method returns.
    public func prepare(
        authorization: NativeAuditKeyRecoveryAuthorization,
        approvals: [NativeAuditKeyRecoveryApproval],
        replacementSignature: Data,
        retiringPublicKeyX963: Data,
        lifecycleRecordData: Data,
        nowMilliseconds: Int64
    ) throws -> NativeAuditKeyRecoveryPlan {
        lock.lock(); defer { lock.unlock() }
        let plan = try NativeAuditKeyRecoveryPlan(
            pinnedPolicy: policy,
            installationID: installationID,
            authorization: authorization,
            approvals: approvals,
            replacementSignature: replacementSignature,
            retiringPublicKeyX963: retiringPublicKeyX963,
            lifecycleRecordData: lifecycleRecordData,
            nowMilliseconds: nowMilliseconds
        )
        try validatePreparation(plan)
        try verifyPreparedLifecycle(plan)
        _ = try journal.prepare(plan, preparedAt: authorization.createdAt)
        return plan
    }

    public func authorizeActivation(plan: NativeAuditKeyRecoveryPlan) throws -> NativeAuditKeyRecoveryActivationAuthorization {
        lock.lock(); defer { lock.unlock() }
        try validatePlan(plan)
        let preparation = try journal.prepare(plan, preparedAt: plan.transition.createdAt)
        let before = try store.status()
        if let recovered = try recoveredAuthorization(plan: plan, status: before) {
            _ = try journal.complete(preparation, transitionStoreReceiptHash: recovered.receipt.receiptHash, completedAt: recovered.receipt.receivedAt)
            return recovered
        }
        try validateSubmissionContinuity(plan, status: before)
        // Re-run the complete protected-ledger replay immediately before the
        // irreversible external submission to close prepare/submit TOCTOU.
        try verifyPreparedLifecycle(plan)
        _ = try journal.recordSubmissionIntent(preparation, intendedAt: Self.timestampNow())
        let receiptData = try transport.submitRecoveryTransition(transitionData: plan.transitionData)
        let committed = try store.accept(
            transitionData: plan.transitionData,
            receiptData: receiptData,
            retiringPublicKeyX963: before.count == 0 ? plan.retiringPublicKeyX963 : nil
        )
        guard committed.count == before.count + 1,
              committed.latestRecoveryTransition == plan.transition,
              let receipt = committed.latestReceipt else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery transition was not committed as the exact next transition")
        }
        _ = try journal.complete(preparation, transitionStoreReceiptHash: receipt.receiptHash, completedAt: receipt.receivedAt)
        return NativeAuditKeyRecoveryActivationAuthorization(
            transition: plan.transition,
            receipt: receipt,
            transitionData: plan.transitionData,
            receiptData: receiptData,
            transitionStoreStatus: committed,
            recoveredFromStore: false
        )
    }

    /// Repairs store-accepted/journal-incomplete state and returns the exact
    /// lifecycle bytes while local generation/head still precede activation.
    public func recoverAuthorizedLifecycleRecord(
        currentLifecycleHeadHash: String,
        currentAuditGeneration: Int
    ) throws -> Data? {
        lock.lock(); defer { lock.unlock() }
        var state = try journal.status()
        let transitions = try store.status()
        if let pending = state.pending,
           transitions.latestRecoveryTransition == pending.plan.transition,
           let receipt = transitions.latestReceipt {
            _ = try journal.complete(pending, transitionStoreReceiptHash: receipt.receiptHash, completedAt: receipt.receivedAt)
            state = try journal.status()
        }
        guard let completion = state.completed.last,
              transitions.latestRecoveryTransition == completion.preparation.plan.transition,
              transitions.latestReceipt?.receiptHash == completion.transitionStoreReceiptHash else { return nil }
        let plan = completion.preparation.plan
        if currentLifecycleHeadHash == plan.transition.lifecycleHeadHash { return nil }
        if currentAuditGeneration >= plan.transition.toGeneration {
            guard try lifecycleAncestryVerifier.provesCurrentHeadDescendsFrom(
                ancestorHeadHash: plan.transition.lifecycleHeadHash,
                currentHeadHash: currentLifecycleHeadHash
            ) else {
                throw AgentPassNativeError.invalidSignature("Local audit generation reached or passed recovery activation without the anchored lifecycle head or a verified descendant")
            }
            return nil
        }
        guard currentAuditGeneration == plan.transition.fromGeneration,
              let object = try JSONSerialization.jsonObject(with: plan.lifecycleRecordData) as? [String: Any],
              object["previous_record_hash"] as? String == currentLifecycleHeadHash,
              object["record_hash"] as? String == plan.transition.lifecycleHeadHash else {
            throw AgentPassNativeError.invalidSignature("Recovered audit-key lifecycle activation does not extend local state")
        }
        return plan.lifecycleRecordData
    }

    private func validateDurableState() throws {
        var journalState = try journal.status()
        let storeState = try store.status()
        let recoveryHistory = try store.verifiedRecoveryHistory()

        // Reconcile the one legitimate crash window first: the exact pending
        // bytes reached the store but completion was not fsync'd. No lifecycle
        // payload is reconstructed from store data; the exact pending journal
        // payload is mandatory.
        if let pending = journalState.pending,
           let accepted = recoveryHistory.last,
           accepted.transitionData == pending.plan.transitionData,
           accepted.retiringPublicKeyX963 == pending.plan.retiringPublicKeyX963 {
            _ = try journal.complete(
                pending,
                transitionStoreReceiptHash: accepted.receipt.receiptHash,
                completedAt: accepted.receipt.receivedAt
            )
            journalState = try journal.status()
        }

        // Every locally accepted v3 transition must have one exact completed
        // plan carrying the otherwise unreconstructable lifecycle payload, and
        // every completion must have exact transition-store evidence.
        for accepted in recoveryHistory {
            guard journalState.completed.contains(where: {
                $0.preparation.plan.transitionData == accepted.transitionData &&
                $0.preparation.plan.retiringPublicKeyX963 == accepted.retiringPublicKeyX963 &&
                $0.transitionStoreReceiptHash == accepted.receipt.receiptHash
            }) else {
                throw AgentPassNativeError.invalidSignature("Accepted schema-v3 transition has no exact completed recovery plan and lifecycle payload")
            }
        }
        for completion in journalState.completed {
            guard recoveryHistory.contains(where: {
                $0.transitionData == completion.preparation.plan.transitionData &&
                $0.retiringPublicKeyX963 == completion.preparation.plan.retiringPublicKeyX963 &&
                $0.receipt.receiptHash == completion.transitionStoreReceiptHash
            }) else {
                throw AgentPassNativeError.invalidSignature("Audit-key recovery journal completion has no exact transition-store evidence")
            }
        }
        if let pending = journalState.pending {
            if storeState.count == 0 {
                guard pending.plan.transition.previousTransitionHash == Self.zeroHash,
                      pending.plan.transition.previousTransitionReceiptHash == Self.zeroHash else {
                    throw AgentPassNativeError.invalidSignature("Pending audit-key recovery plan forks an empty transition store")
                }
            } else {
                let latestGeneration = storeState.latestRecoveryTransition?.toGeneration ?? storeState.latestTransition?.toGeneration
                guard let latestGeneration else {
                    throw AgentPassNativeError.invalidSignature("Transition store omitted its latest transition")
                }
                switch latestGeneration {
                case pending.fromGeneration:
                    try validateSubmissionContinuity(pending.plan, status: storeState)
                case pending.toGeneration:
                    guard storeState.latestRecoveryTransition == pending.plan.transition,
                          storeState.latestReceipt != nil else {
                        throw AgentPassNativeError.invalidSignature("Audit-key recovery journal conflicts with accepted transition evidence")
                    }
                default:
                    throw AgentPassNativeError.invalidSignature("Pending audit-key recovery plan is stale relative to the transition store")
                }
            }
        }
        if let latest = journalState.completed.last {
            let latestStoreGeneration = storeState.latestRecoveryTransition?.toGeneration ?? storeState.latestTransition?.toGeneration
            guard let latestStoreGeneration, latestStoreGeneration >= latest.preparation.toGeneration else {
                throw AgentPassNativeError.invalidSignature("Audit-key recovery journal is ahead of transition store evidence")
            }
            if latestStoreGeneration == latest.preparation.toGeneration {
                guard storeState.latestRecoveryTransition == latest.preparation.plan.transition,
                      storeState.latestReceipt?.receiptHash == latest.transitionStoreReceiptHash else {
                    throw AgentPassNativeError.invalidSignature("Audit-key recovery completion conflicts with transition store")
                }
            }
        }
    }

    private func validatePreparation(_ plan: NativeAuditKeyRecoveryPlan) throws {
        try validatePlan(plan)
        let status = try store.status()
        try validateSubmissionContinuity(plan, status: status)
    }

    private func verifyPreparedLifecycle(_ plan: NativeAuditKeyRecoveryPlan) throws {
        guard try preparedRecordVerifier.verifyPreparedAuditRecoveryRecord(plan.lifecycleRecordData) == plan.transition.lifecycleHeadHash else {
            throw AgentPassNativeError.invalidSignature("Prepared audit recovery lifecycle replay does not produce the anchored head")
        }
    }

    private func validatePlan(_ plan: NativeAuditKeyRecoveryPlan) throws {
        let exact = try NativeAuditKeyRecoveryPlan(
            transitionData: plan.transitionData,
            retiringPublicKeyX963: plan.retiringPublicKeyX963,
            lifecycleRecordData: plan.lifecycleRecordData,
            pinnedPolicy: policy,
            installationID: installationID
        )
        guard exact == plan, plan.transition.tenant == tenant else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery plan crossed a trust boundary")
        }
    }

    private func validateSubmissionContinuity(
        _ plan: NativeAuditKeyRecoveryPlan,
        status: NativeAuditKeyTransitionStoreStatus
    ) throws {
        if status.count == 0 {
            guard plan.transition.previousTransitionHash == Self.zeroHash,
                  plan.transition.previousTransitionReceiptHash == Self.zeroHash else {
                throw AgentPassNativeError.invalidSignature("First audit-key recovery transition does not begin at chain origin")
            }
            return
        }
        guard let receipt = status.latestReceipt else {
            throw AgentPassNativeError.invalidSignature("Audit-key transition store has no latest receipt")
        }
        let previousGeneration: Int
        let previousHash: String
        let previousPublicKey: String
        if let previous = status.latestRecoveryTransition {
            previousGeneration = previous.toGeneration
            previousHash = previous.transitionHash
            previousPublicKey = previous.newPublicKey
        } else if let previous = status.latestTransition {
            previousGeneration = previous.toGeneration
            previousHash = previous.transitionHash
            previousPublicKey = previous.newPublicKey
        } else {
            throw AgentPassNativeError.invalidSignature("Audit-key transition store latest transition is unavailable")
        }
        guard plan.transition.fromGeneration == previousGeneration,
              plan.transition.previousTransitionHash == previousHash,
              plan.transition.previousTransitionReceiptHash == receipt.receiptHash,
              plan.retiringPublicKeyX963 == (try SSHSIG.p256PublicKey(fromAuthorizedKey: previousPublicKey)) else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery plan is stale or forks durable transition history")
        }
    }

    private func recoveredAuthorization(
        plan: NativeAuditKeyRecoveryPlan,
        status: NativeAuditKeyTransitionStoreStatus
    ) throws -> NativeAuditKeyRecoveryActivationAuthorization? {
        guard let latest = status.latestRecoveryTransition, let receipt = status.latestReceipt else { return nil }
        if latest.operationID == plan.transition.operationID || latest.recoveryRequestID == plan.transition.recoveryRequestID || latest.toGeneration == plan.transition.toGeneration {
            guard latest == plan.transition, try latest.canonicalData() == plan.transitionData else {
                throw AgentPassNativeError.invalidSignature("Audit-key recovery replay conflicts with durable transition evidence")
            }
            return NativeAuditKeyRecoveryActivationAuthorization(
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

    private static func canonicalReceiptData(_ receipt: NativeAuditKeyTransitionReceipt) throws -> Data {
        try NativeAuditLog.canonical([
            "version": receipt.version,
            "tenant": receipt.tenant,
            "index": receipt.index,
            "transition_hash": receipt.transitionHash,
            "received_at": receipt.receivedAt,
            "previous_receipt_hash": receipt.previousReceiptHash,
            "event_index": receipt.eventIndex,
            "previous_event_hash": receipt.previousEventHash,
            "last_checkpoint_index": receipt.lastCheckpointIndex,
            "last_checkpoint_hash": receipt.lastCheckpointHash,
            "last_checkpoint_receipt_hash": receipt.lastCheckpointReceiptHash,
            "anchor_key_fingerprint": receipt.anchorKeyFingerprint,
            "signature": receipt.signature,
            "receipt_hash": receipt.receiptHash
        ])
    }

    private static func timestampNow() -> String {
        timestamp(Int64((Date().timeIntervalSince1970 * 1_000).rounded(.down)))
    }

    private static func timestamp(_ milliseconds: Int64) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: Date(timeIntervalSince1970: Double(milliseconds) / 1_000))
    }

    private static func milliseconds(_ timestamp: String) -> Int64? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard let date = formatter.date(from: timestamp) else { return nil }
        return Int64((date.timeIntervalSince1970 * 1_000).rounded())
    }
}
