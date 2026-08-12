import CryptoKit
import Darwin
import Foundation

public enum NativeKeyRole: String, CaseIterable, Codable, Sendable {
    case gitSigning = "git_signing"
    case auditCheckpoint = "audit_checkpoint"
    case sessionApproval = "session_approval"
}

public enum NativeKeyContinuity: String, Codable, Sendable {
    case bootstrap
    case clean
    case recovered
}

public enum NativeKeyGenerationStatus: String, Codable, Sendable {
    case staged
    case abortIntent = "abort_intent"
    case aborted
    case active
    case retired
    case deletionIntent = "deletion_intent"
    case deleted
}

public protocol NativeLifecycleSignatureVerifier: Sendable {
    func isValid(signature: Data, message: Data, publicKeyX963: Data) -> Bool
}

public struct NativeP256LifecycleVerifier: NativeLifecycleSignatureVerifier {
    public init() {}

    public func isValid(signature: Data, message: Data, publicKeyX963: Data) -> Bool {
        guard signature.count == 64,
              let key = try? P256.Signing.PublicKey(x963Representation: publicKeyX963),
              let value = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else { return false }
        return key.isValidSignature(value, for: message)
    }
}

public struct NativeKeyTransitionStatement: Equatable, Sendable {
    public let role: NativeKeyRole
    public let oldGeneration: Int
    public let newGeneration: Int
    public let oldFingerprint: String
    public let newFingerprint: String
    public let stateSequence: Int
    public let reason: String
    public let challengeID: String
    public let createdAt: String
    public let previousLifecycleHead: String
    public let continuity: NativeKeyContinuity

    public init(role: NativeKeyRole, oldGeneration: Int, newGeneration: Int, oldFingerprint: String, newFingerprint: String, stateSequence: Int, reason: String, challengeID: String, createdAt: String, previousLifecycleHead: String, continuity: NativeKeyContinuity) {
        self.role = role
        self.oldGeneration = oldGeneration
        self.newGeneration = newGeneration
        self.oldFingerprint = oldFingerprint
        self.newFingerprint = newFingerprint
        self.stateSequence = stateSequence
        self.reason = reason
        self.challengeID = challengeID
        self.createdAt = createdAt
        self.previousLifecycleHead = previousLifecycleHead
        self.continuity = continuity
    }

    public func canonicalData() throws -> Data {
        try lifecycleCanonical([
            "version": 1,
            "role": role.rawValue,
            "old_generation": oldGeneration,
            "new_generation": newGeneration,
            "old_fingerprint": oldFingerprint,
            "new_fingerprint": newFingerprint,
            "state_sequence": stateSequence,
            "reason": reason,
            "challenge_id": challengeID,
            "created_at": createdAt,
            "previous_lifecycle_head": previousLifecycleHead,
            "continuity": continuity.rawValue
        ])
    }

    public static func decodeCanonical(_ data: Data) throws -> Self {
        let keys: Set<String> = ["version", "role", "old_generation", "new_generation", "old_fingerprint", "new_fingerprint", "state_sequence", "reason", "challenge_id", "created_at", "previous_lifecycle_head", "continuity"]
        guard data.count > 0, data.count <= 16 * 1024,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == keys,
              try lifecycleCanonical(object) == data, object["version"] as? Int == 1,
              let roleValue = object["role"] as? String, let role = NativeKeyRole(rawValue: roleValue),
              let oldGeneration = object["old_generation"] as? Int, oldGeneration >= 0,
              let newGeneration = object["new_generation"] as? Int, newGeneration > 0,
              let oldFingerprint = object["old_fingerprint"] as? String,
              let newFingerprint = object["new_fingerprint"] as? String,
              let stateSequence = object["state_sequence"] as? Int, stateSequence > 0,
              let reason = object["reason"] as? String, !reason.isEmpty,
              let challengeID = object["challenge_id"] as? String, !challengeID.isEmpty,
              let createdAt = object["created_at"] as? String,
              let previousLifecycleHead = object["previous_lifecycle_head"] as? String,
              let continuityValue = object["continuity"] as? String, let continuity = NativeKeyContinuity(rawValue: continuityValue),
              newFingerprint.range(of: "^SHA256:[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil,
              previousLifecycleHead.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
              ISO8601DateFormatter.lifecycleDate(createdAt) != nil else {
            throw AgentPassNativeError.invalidSignature("Lifecycle transition statement is not exact canonical schema")
        }
        if continuity == .bootstrap {
            guard oldGeneration == 0, oldFingerprint.isEmpty else { throw AgentPassNativeError.invalidSignature("Lifecycle bootstrap statement is invalid") }
        } else {
            guard oldGeneration > 0, oldFingerprint.range(of: "^SHA256:[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil else { throw AgentPassNativeError.invalidSignature("Lifecycle transition old generation is invalid") }
        }
        return Self(role: role, oldGeneration: oldGeneration, newGeneration: newGeneration, oldFingerprint: oldFingerprint, newFingerprint: newFingerprint, stateSequence: stateSequence, reason: reason, challengeID: challengeID, createdAt: createdAt, previousLifecycleHead: previousLifecycleHead, continuity: continuity)
    }
}

private extension ISO8601DateFormatter {
    static func lifecycleDate(_ value: String) -> Date? {
        let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: value)
    }
}

public struct NativeAuditDeletionIntentBinding: Equatable, Sendable {
    public let bundleSHA256: String
    public let retainedSegmentHash: String
    public let retainedIdentityHash: String
    public let archivePathChainHash: String
    public let operationID: String
    public let spoolManifestHash: String
    public let spoolDirectoryName: String
    public let spoolDevice: UInt64
    public let spoolInode: UInt64

    public init(bundleSHA256: String, retainedSegmentHash: String, retainedIdentityHash: String, archivePathChainHash: String, operationID: String, spoolManifestHash: String, spoolDirectoryName: String, spoolDevice: UInt64, spoolInode: UInt64) {
        self.bundleSHA256 = bundleSHA256; self.retainedSegmentHash = retainedSegmentHash
        self.retainedIdentityHash = retainedIdentityHash; self.archivePathChainHash = archivePathChainHash
        self.operationID = operationID
        self.spoolManifestHash = spoolManifestHash; self.spoolDirectoryName = spoolDirectoryName
        self.spoolDevice = spoolDevice; self.spoolInode = spoolInode
    }
}

public struct NativeKeyGeneration: Equatable, Sendable {
    public let role: NativeKeyRole
    public let generation: Int
    public let applicationTag: String
    public let publicKeyX963: Data
    public let fingerprint: String
    public var status: NativeKeyGenerationStatus
    public let createdAt: String
    public var retiredAt: String?
    public var deletionIntentAt: String?
    public var deletedAt: String?
    public var auditDeletionBinding: NativeAuditDeletionIntentBinding?
    public var deletionIntentLifecycleHead: String?
}

public struct NativeKeyLifecycleSnapshot: Equatable, Sendable {
    public let sequence: Int
    public let headHash: String
    public let latestTimestamp: String?
    public let generations: [NativeKeyGeneration]

    public func active(for role: NativeKeyRole) -> NativeKeyGeneration? {
        generations.first { $0.role == role && $0.status == .active }
    }

    public func generation(_ generation: Int, for role: NativeKeyRole) -> NativeKeyGeneration? {
        generations.first { $0.role == role && $0.generation == generation }
    }
}

public struct NativeKeyLifecycleRecord: Equatable, Sendable {
    public let sequence: Int
    public let previousRecordHash: String
    public let action: String
    public let role: NativeKeyRole
    public let generation: Int
    public let applicationTag: String
    public let publicKeyX963: Data
    public let fingerprint: String
    public let createdAt: String
    public let continuity: NativeKeyContinuity
    public let reason: String
    public let challengeID: String
    public let oldGeneration: Int
    public let oldFingerprint: String
    public let oldSignature: Data
    public let newSignature: Data
    public let approvalSignature: Data
    public let approvalPublicKeyX963: Data
    public let minimumRetirementAgeSeconds: Int
    public let transitionArchived: Bool
    public let externallyPinnedHeadHash: String
    public let auditDeletionBinding: NativeAuditDeletionIntentBinding?
    public let recordHash: String
}

/// A protected, append-only lifecycle ledger. Each record is a separately durable file.
/// Full-disk rollback across process restarts requires passing an externally pinned head.
public final class NativeKeyLifecycleStore: @unchecked Sendable {
    public static let zeroHash = String(repeating: "0", count: 64)
    private static let recordKeys: Set<String> = [
        "version", "sequence", "previous_record_hash", "action", "role", "generation",
        "application_tag", "public_key", "fingerprint", "created_at", "continuity",
        "reason", "challenge_id", "old_generation", "old_fingerprint", "old_signature",
        "new_signature", "approval_signature", "approval_public_key", "minimum_retirement_age_seconds",
        "transition_archived", "externally_pinned_head_hash", "record_hash"
    ]
    private static let recordV2Keys = recordKeys.union(["audit_deletion_binding"])
    private static let validActions: Set<String> = ["staged", "abort_intent", "aborted", "activated", "deletion_intent", "deleted"]

    private let directory: String
    private let verifier: any NativeLifecycleSignatureVerifier
    private let recoveryPublicKeys: [Data]
    private let recoveryThreshold: Int?
    private let lock = NSLock()
    private let directoryDescriptor: Int32
    private var pinnedHead: String

    public init(directory: String, verifier: any NativeLifecycleSignatureVerifier = NativeP256LifecycleVerifier(), recoveryPublicKeys: [Data] = [], recoveryThreshold: Int? = nil, expectedHeadHash: String? = nil) throws {
        guard directory.hasPrefix("/") else { throw AgentPassNativeError.invalidConfiguration("Key lifecycle directory must be absolute") }
        let canonicalDirectory = URL(fileURLWithPath: directory).standardizedFileURL.path
        self.directory = canonicalDirectory
        self.verifier = verifier
        self.recoveryPublicKeys = recoveryPublicKeys
        self.recoveryThreshold = recoveryThreshold
        pinnedHead = Self.zeroHash
        try Self.validatePrivateDirectory(canonicalDirectory)
        for key in recoveryPublicKeys { try Self.validateRecoveryPublicKey(key) }
        if let recoveryThreshold {
            guard !recoveryPublicKeys.isEmpty, (1...recoveryPublicKeys.count).contains(recoveryThreshold) else {
                throw AgentPassNativeError.invalidConfiguration("Lifecycle recovery threshold is invalid")
            }
        }
        let descriptor = open(canonicalDirectory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        directoryDescriptor = descriptor
        do {
            let snapshot = try Self.withDirectoryLock(descriptor) {
                try Self.read(directory: canonicalDirectory, verifier: verifier, recoveryPublicKeys: recoveryPublicKeys, recoveryThreshold: recoveryThreshold)
            }
            if let expectedHeadHash, expectedHeadHash != snapshot.headHash {
                throw AgentPassNativeError.invalidSignature("Key lifecycle rollback or head substitution detected")
            }
            pinnedHead = snapshot.headHash
        } catch {
            close(descriptor)
            throw error
        }
    }

    deinit { close(directoryDescriptor) }

    public func verify(expectedHeadHash: String? = nil) throws -> NativeKeyLifecycleSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return try withLedgerLock { try verifyUnlocked(expectedHeadHash: expectedHeadHash) }
    }

    /// Proves that `ancestorHeadHash` is a committed member of the one verified
    /// hash chain ending at the exact current head supplied by the caller.
    /// This is intentionally stronger than comparing two caller-provided hashes:
    /// rollback, a temporary tail, an unrelated valid-looking hash, and a stale
    /// current head all fail closed under the ledger lock.
    public func verifyCurrentHeadDescendsFrom(
        ancestorHeadHash: String,
        currentHeadHash: String
    ) throws -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return try withLedgerLock {
            let snapshot = try verifyUnlocked(expectedHeadHash: currentHeadHash)
            guard snapshot.headHash == currentHeadHash,
                  ancestorHeadHash != Self.zeroHash,
                  Self.isHash(ancestorHeadHash) else { return false }
            let records = try Self.readCommittedRecords(directory: directory)
            return records.contains { $0.recordHash == ancestorHeadHash }
        }
    }

    @discardableResult
    public func stage(role: NativeKeyRole, generation: Int, applicationTag: String, publicKeyX963: Data, createdAt: String) throws -> NativeKeyLifecycleSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return try withLedgerLock {
        let state = try verifyUnlocked()
        let record = try stageRecord(state: state, role: role, generation: generation, applicationTag: applicationTag, publicKeyX963: publicKeyX963, createdAt: createdAt)
        try append(record)
        return try verifyUnlocked()
        }
    }

    /// Computes the exact next immutable record head without mutating the ledger. This is used to
    /// durably prepare an external pin transaction before the record is appended.
    public func previewStageHead(role: NativeKeyRole, generation: Int, applicationTag: String, publicKeyX963: Data, createdAt: String) throws -> String {
        lock.lock()
        defer { lock.unlock() }
        return try withLedgerLock {
            let state = try verifyUnlocked()
            return try stageRecord(state: state, role: role, generation: generation, applicationTag: applicationTag, publicKeyX963: publicKeyX963, createdAt: createdAt).recordHash
        }
    }

    /// Returns the exact canonical record bytes that `stage` would append. Callers may durably
    /// retain these bytes in a write-ahead outbox before changing an external lifecycle pin.
    public func prepareStageRecordData(role: NativeKeyRole, generation: Int, applicationTag: String, publicKeyX963: Data, createdAt: String) throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        return try withLedgerLock {
            let state = try verifyUnlocked()
            return try Self.recordData(stageRecord(state: state, role: role, generation: generation, applicationTag: applicationTag, publicKeyX963: publicKeyX963, createdAt: createdAt))
        }
    }

    public func transitionStatement(role: NativeKeyRole, generation: Int, reason: String, challengeID: String, createdAt: String, continuity: NativeKeyContinuity = .clean) throws -> NativeKeyTransitionStatement {
        lock.lock()
        defer { lock.unlock() }
        return try withLedgerLock {
            let state = try verifyUnlocked()
            return try transitionStatement(state: state, role: role, generation: generation, reason: reason, challengeID: challengeID, createdAt: createdAt, continuity: continuity)
        }
    }

    @discardableResult
    public func activate(statement: NativeKeyTransitionStatement, oldSignature: Data?, newSignature: Data, approvalSignature: Data, approvalPublicKeyX963: Data) throws -> NativeKeyLifecycleSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return try withLedgerLock {
        let state = try verifyUnlocked()
        let record = try activationRecord(state: state, statement: statement, oldSignature: oldSignature, newSignature: newSignature, approvalSignature: approvalSignature, approvalPublicKeyX963: approvalPublicKeyX963)
        try append(record)
        return try verifyUnlocked()
        }
    }

    public func previewActivationHead(statement: NativeKeyTransitionStatement, oldSignature: Data?, newSignature: Data, approvalSignature: Data, approvalPublicKeyX963: Data) throws -> String {
        lock.lock()
        defer { lock.unlock() }
        return try withLedgerLock {
            let state = try verifyUnlocked()
            return try activationRecord(state: state, statement: statement, oldSignature: oldSignature, newSignature: newSignature, approvalSignature: approvalSignature, approvalPublicKeyX963: approvalPublicKeyX963).recordHash
        }
    }

    /// Returns the byte-exact signed activation record for write-ahead persistence and replay.
    public func prepareActivationRecordData(statement: NativeKeyTransitionStatement, oldSignature: Data?, newSignature: Data, approvalSignature: Data, approvalPublicKeyX963: Data) throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        return try withLedgerLock {
            let state = try verifyUnlocked()
            return try Self.recordData(activationRecord(state: state, statement: statement, oldSignature: oldSignature, newSignature: newSignature, approvalSignature: approvalSignature, approvalPublicKeyX963: approvalPublicKeyX963))
        }
    }

    /// Appends a previously prepared canonical record only after replay-validating the complete
    /// resulting ledger. This is intentionally the sole byte-replay entry point.
    @discardableResult
    public func appendPreparedRecordData(_ data: Data) throws -> NativeKeyLifecycleSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return try withLedgerLock {
            let state = try verifyUnlocked()
            let record = try Self.decodeRecord(data)
            guard try Self.recordData(record) == data,
                  record.sequence == state.sequence + 1,
                  record.previousRecordHash == state.headHash else {
                throw AgentPassNativeError.invalidSignature("Prepared lifecycle record does not exactly extend the current ledger")
            }
            let records = try Self.readCommittedRecords(directory: directory)
            guard records.count == state.sequence else {
                throw AgentPassNativeError.invalidSignature("Prepared lifecycle replay observed a divergent ledger")
            }
            _ = try Self.replay(records + [record], verifier: verifier, recoveryPublicKeys: recoveryPublicKeys, recoveryThreshold: recoveryThreshold)
            try append(record)
            return try verifyUnlocked()
        }
    }

    /// Fully replays an exact prepared record without writing it. Recovery
    /// coordinators use this before creating pin/outbox evidence so malformed or
    /// unauthorised payloads cannot leave a poisoned pending mutation.
    public func validatePreparedRecordData(_ data: Data) throws -> NativeKeyLifecycleSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return try withLedgerLock {
            let state = try verifyUnlocked()
            let record = try Self.decodeRecord(data)
            guard try Self.recordData(record) == data,
                  record.sequence == state.sequence + 1,
                  record.previousRecordHash == state.headHash else {
                throw AgentPassNativeError.invalidSignature("Prepared lifecycle record does not exactly extend the current ledger")
            }
            let records = try Self.readCommittedRecords(directory: directory)
            guard records.count == state.sequence else {
                throw AgentPassNativeError.invalidSignature("Prepared lifecycle validation observed a divergent ledger")
            }
            return try Self.replay(records + [record], verifier: verifier, recoveryPublicKeys: recoveryPublicKeys, recoveryThreshold: recoveryThreshold)
        }
    }

    @discardableResult
    public func activateRecovered(statement: NativeKeyTransitionStatement, newSignature: Data, evidenceData: Data) throws -> NativeKeyLifecycleSnapshot {
        try activate(statement: statement, oldSignature: nil, newSignature: newSignature, approvalSignature: evidenceData, approvalPublicKeyX963: Data())
    }

    public func deletionStatement(role: NativeKeyRole, generation: Int, reason: String, challengeID: String, createdAt: String, minimumRetirementAgeSeconds: Int = 2_592_000, transitionArchived: Bool = false, externallyPinnedHeadHash: String? = nil, auditDeletionBinding: NativeAuditDeletionIntentBinding? = nil) throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        return try withLedgerLock {
            let state = try verifyUnlocked()
            try Self.validateNotBefore(createdAt, previous: state.latestTimestamp)
            _ = try Self.requiredGeneration(state, role: role, generation: generation, status: .retired)
            return try Self.deletionStatement(role: role, generation: generation, sequence: state.sequence + 1, reason: reason, challengeID: challengeID, createdAt: createdAt, previous: state.headHash, minimumRetirementAgeSeconds: minimumRetirementAgeSeconds, transitionArchived: transitionArchived, externallyPinnedHeadHash: externallyPinnedHeadHash ?? "", auditDeletionBinding: auditDeletionBinding)
        }
    }

    public func abortStatement(role: NativeKeyRole, generation: Int, reason: String, challengeID: String, createdAt: String, externallyPinnedHeadHash: String? = nil) throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        return try withLedgerLock {
            let state = try verifyUnlocked()
            try Self.validateNotBefore(createdAt, previous: state.latestTimestamp)
            _ = try Self.requiredGeneration(state, role: role, generation: generation, status: .staged)
            return try Self.abortStatement(role: role, generation: generation, sequence: state.sequence + 1, reason: reason, challengeID: challengeID, createdAt: createdAt, previous: state.headHash, externallyPinnedHeadHash: externallyPinnedHeadHash ?? state.headHash)
        }
    }

    @discardableResult
    public func recordAbortIntent(role: NativeKeyRole, generation: Int, reason: String, challengeID: String, createdAt: String, approvalSignature: Data, approvalPublicKeyX963: Data, externallyPinnedHeadHash: String) throws -> NativeKeyLifecycleSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return try withLedgerLock {
            let state = try verifyUnlocked()
            try Self.validateNotBefore(createdAt, previous: state.latestTimestamp)
            let target = try Self.requiredGeneration(state, role: role, generation: generation, status: .staged)
            guard externallyPinnedHeadHash == state.headHash,
                  let approval = state.active(for: .sessionApproval), approval.publicKeyX963 == approvalPublicKeyX963 else {
                throw AgentPassNativeError.invalidSignature("Staged-key abort requires the active approval authority and current external lifecycle pin")
            }
            let message = try Self.abortStatement(role: role, generation: generation, sequence: state.sequence + 1, reason: reason, challengeID: challengeID, createdAt: createdAt, previous: state.headHash, externallyPinnedHeadHash: externallyPinnedHeadHash)
            guard verifier.isValid(signature: approvalSignature, message: message, publicKeyX963: approvalPublicKeyX963) else {
                throw AgentPassNativeError.invalidSignature("Staged-key abort approval signature is invalid")
            }
            let record = try makeRecord(sequence: state.sequence + 1, previous: state.headHash, action: "abort_intent", role: role, generation: generation, applicationTag: target.applicationTag, publicKey: target.publicKeyX963, createdAt: createdAt, continuity: .clean, reason: reason, challengeID: challengeID, approvalSignature: approvalSignature, approvalPublicKey: approvalPublicKeyX963, externallyPinnedHeadHash: externallyPinnedHeadHash)
            try append(record)
            return try verifyUnlocked()
        }
    }

    public func prepareAbortIntentRecordData(role: NativeKeyRole, generation: Int, reason: String, challengeID: String, createdAt: String, approvalSignature: Data, approvalPublicKeyX963: Data, externallyPinnedHeadHash: String) throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        return try withLedgerLock {
            let state = try verifyUnlocked()
            try Self.validateNotBefore(createdAt, previous: state.latestTimestamp)
            let target = try Self.requiredGeneration(state, role: role, generation: generation, status: .staged)
            guard externallyPinnedHeadHash == state.headHash,
                  let approval = state.active(for: .sessionApproval), approval.publicKeyX963 == approvalPublicKeyX963 else {
                throw AgentPassNativeError.invalidSignature("Staged-key abort requires the active approval authority and current external lifecycle pin")
            }
            let message = try Self.abortStatement(role: role, generation: generation, sequence: state.sequence + 1, reason: reason, challengeID: challengeID, createdAt: createdAt, previous: state.headHash, externallyPinnedHeadHash: externallyPinnedHeadHash)
            guard verifier.isValid(signature: approvalSignature, message: message, publicKeyX963: approvalPublicKeyX963) else {
                throw AgentPassNativeError.invalidSignature("Staged-key abort approval signature is invalid")
            }
            return try Self.recordData(makeRecord(sequence: state.sequence + 1, previous: state.headHash, action: "abort_intent", role: role, generation: generation, applicationTag: target.applicationTag, publicKey: target.publicKeyX963, createdAt: createdAt, continuity: .clean, reason: reason, challengeID: challengeID, approvalSignature: approvalSignature, approvalPublicKey: approvalPublicKeyX963, externallyPinnedHeadHash: externallyPinnedHeadHash))
        }
    }

    @discardableResult
    public func recordAborted(role: NativeKeyRole, generation: Int, createdAt: String, exactKeyIsAbsent: Bool) throws -> NativeKeyLifecycleSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return try withLedgerLock {
            guard exactKeyIsAbsent else { throw AgentPassNativeError.invalidKey("Refusing to finalize staged-key abort while the exact key may still exist") }
            let state = try verifyUnlocked()
            try Self.validateNotBefore(createdAt, previous: state.latestTimestamp)
            let target = try Self.requiredGeneration(state, role: role, generation: generation, status: .abortIntent)
            let record = try makeRecord(sequence: state.sequence + 1, previous: state.headHash, action: "aborted", role: role, generation: generation, applicationTag: target.applicationTag, publicKey: target.publicKeyX963, createdAt: createdAt, continuity: .clean)
            try append(record)
            return try verifyUnlocked()
        }
    }

    public func prepareAbortedRecordData(role: NativeKeyRole, generation: Int, createdAt: String, exactKeyIsAbsent: Bool) throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        return try withLedgerLock {
            guard exactKeyIsAbsent else { throw AgentPassNativeError.invalidKey("Refusing to finalize staged-key abort while the exact key may still exist") }
            let state = try verifyUnlocked()
            try Self.validateNotBefore(createdAt, previous: state.latestTimestamp)
            let target = try Self.requiredGeneration(state, role: role, generation: generation, status: .abortIntent)
            return try Self.recordData(makeRecord(sequence: state.sequence + 1, previous: state.headHash, action: "aborted", role: role, generation: generation, applicationTag: target.applicationTag, publicKey: target.publicKeyX963, createdAt: createdAt, continuity: .clean))
        }
    }

    @discardableResult
    public func recordDeletionIntent(role: NativeKeyRole, generation: Int, reason: String, challengeID: String, createdAt: String, approvalSignature: Data, approvalPublicKeyX963: Data, minimumRetirementAgeSeconds: Int = 2_592_000, transitionArchived: Bool = false, externallyPinnedHeadHash: String? = nil, auditDeletionBinding: NativeAuditDeletionIntentBinding? = nil) throws -> NativeKeyLifecycleSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return try withLedgerLock {
        let state = try verifyUnlocked()
        try Self.validateNotBefore(createdAt, previous: state.latestTimestamp)
        let target = try Self.requiredGeneration(state, role: role, generation: generation, status: .retired)
        guard (86_400...31_536_000).contains(minimumRetirementAgeSeconds), transitionArchived,
              externallyPinnedHeadHash == state.headHash,
              let retiredAt = target.retiredAt,
              let retiredDate = Self.timestampDate(retiredAt), let deletionDate = Self.timestampDate(createdAt),
              deletionDate.timeIntervalSince(retiredDate) >= Double(minimumRetirementAgeSeconds) else {
            throw AgentPassNativeError.invalidConfiguration("Deletion requires bounded retirement age, archived transition, and the current externally pinned lifecycle head")
        }
        let approval = try Self.requiredActive(state, role: .sessionApproval)
        guard approval.publicKeyX963 == approvalPublicKeyX963 else { throw AgentPassNativeError.invalidSignature("Approval-key substitution detected") }
        let message = try Self.deletionStatement(role: role, generation: generation, sequence: state.sequence + 1, reason: reason, challengeID: challengeID, createdAt: createdAt, previous: state.headHash, minimumRetirementAgeSeconds: minimumRetirementAgeSeconds, transitionArchived: transitionArchived, externallyPinnedHeadHash: externallyPinnedHeadHash ?? "", auditDeletionBinding: auditDeletionBinding)
        guard verifier.isValid(signature: approvalSignature, message: message, publicKeyX963: approvalPublicKeyX963) else {
            throw AgentPassNativeError.invalidSignature("Deletion approval signature is invalid")
        }
        let record = try makeRecord(sequence: state.sequence + 1, previous: state.headHash, action: "deletion_intent", role: role, generation: generation, applicationTag: target.applicationTag, publicKey: target.publicKeyX963, createdAt: createdAt, continuity: .clean, reason: reason, challengeID: challengeID, approvalSignature: approvalSignature, approvalPublicKey: approvalPublicKeyX963, minimumRetirementAgeSeconds: minimumRetirementAgeSeconds, transitionArchived: transitionArchived, externallyPinnedHeadHash: externallyPinnedHeadHash ?? "", auditDeletionBinding: auditDeletionBinding)
        try append(record)
        return try verifyUnlocked()
        }
    }

    public func prepareDeletionIntentRecordData(role: NativeKeyRole, generation: Int, reason: String, challengeID: String, createdAt: String, approvalSignature: Data, approvalPublicKeyX963: Data, minimumRetirementAgeSeconds: Int = 2_592_000, transitionArchived: Bool = false, externallyPinnedHeadHash: String? = nil, auditDeletionBinding: NativeAuditDeletionIntentBinding? = nil) throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        return try withLedgerLock {
            let state = try verifyUnlocked()
            try Self.validateNotBefore(createdAt, previous: state.latestTimestamp)
            let target = try Self.requiredGeneration(state, role: role, generation: generation, status: .retired)
            guard (86_400...31_536_000).contains(minimumRetirementAgeSeconds), transitionArchived,
                  externallyPinnedHeadHash == state.headHash,
                  let retiredAt = target.retiredAt,
                  let retiredDate = Self.timestampDate(retiredAt), let deletionDate = Self.timestampDate(createdAt),
                  deletionDate.timeIntervalSince(retiredDate) >= Double(minimumRetirementAgeSeconds) else {
                throw AgentPassNativeError.invalidConfiguration("Deletion requires bounded retirement age, archived transition, and the current externally pinned lifecycle head")
            }
            let approval = try Self.requiredActive(state, role: .sessionApproval)
            guard approval.publicKeyX963 == approvalPublicKeyX963 else { throw AgentPassNativeError.invalidSignature("Approval-key substitution detected") }
            let message = try Self.deletionStatement(role: role, generation: generation, sequence: state.sequence + 1, reason: reason, challengeID: challengeID, createdAt: createdAt, previous: state.headHash, minimumRetirementAgeSeconds: minimumRetirementAgeSeconds, transitionArchived: transitionArchived, externallyPinnedHeadHash: externallyPinnedHeadHash ?? "", auditDeletionBinding: auditDeletionBinding)
            guard verifier.isValid(signature: approvalSignature, message: message, publicKeyX963: approvalPublicKeyX963) else {
                throw AgentPassNativeError.invalidSignature("Deletion approval signature is invalid")
            }
            return try Self.recordData(makeRecord(sequence: state.sequence + 1, previous: state.headHash, action: "deletion_intent", role: role, generation: generation, applicationTag: target.applicationTag, publicKey: target.publicKeyX963, createdAt: createdAt, continuity: .clean, reason: reason, challengeID: challengeID, approvalSignature: approvalSignature, approvalPublicKey: approvalPublicKeyX963, minimumRetirementAgeSeconds: minimumRetirementAgeSeconds, transitionArchived: transitionArchived, externallyPinnedHeadHash: externallyPinnedHeadHash ?? "", auditDeletionBinding: auditDeletionBinding))
        }
    }

    /// Records cryptographic deletion only after the caller has proved the exact key is absent.
    @discardableResult
    public func recordDeleted(role: NativeKeyRole, generation: Int, createdAt: String, exactKeyIsAbsent: Bool) throws -> NativeKeyLifecycleSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return try withLedgerLock {
        guard exactKeyIsAbsent else { throw AgentPassNativeError.invalidKey("Refusing to record deletion while the exact key may still exist") }
        let state = try verifyUnlocked()
        try Self.validateNotBefore(createdAt, previous: state.latestTimestamp)
        let target = try Self.requiredGeneration(state, role: role, generation: generation, status: .deletionIntent)
        let record = try makeRecord(sequence: state.sequence + 1, previous: state.headHash, action: "deleted", role: role, generation: generation, applicationTag: target.applicationTag, publicKey: target.publicKeyX963, createdAt: createdAt, continuity: .clean)
        try append(record)
        return try verifyUnlocked()
        }
    }

    public func prepareDeletedRecordData(role: NativeKeyRole, generation: Int, createdAt: String, exactKeyIsAbsent: Bool) throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        return try withLedgerLock {
            guard exactKeyIsAbsent else { throw AgentPassNativeError.invalidKey("Refusing to record deletion while the exact key may still exist") }
            let state = try verifyUnlocked()
            try Self.validateNotBefore(createdAt, previous: state.latestTimestamp)
            let target = try Self.requiredGeneration(state, role: role, generation: generation, status: .deletionIntent)
            return try Self.recordData(makeRecord(sequence: state.sequence + 1, previous: state.headHash, action: "deleted", role: role, generation: generation, applicationTag: target.applicationTag, publicKey: target.publicKeyX963, createdAt: createdAt, continuity: .clean))
        }
    }

    private func withLedgerLock<T>(_ body: () throws -> T) throws -> T {
        try Self.withDirectoryLock(directoryDescriptor, body)
    }

    private static func withDirectoryLock<T>(_ descriptor: Int32, _ body: () throws -> T) throws -> T {
        guard flock(descriptor, LOCK_EX) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { flock(descriptor, LOCK_UN) }
        return try body()
    }

    private func validateThresholdRecovery(_ verification: NativeRecoveryVerification, statement: NativeKeyTransitionStatement, staged: NativeKeyGeneration) throws {
        try Self.validateThresholdRecovery(verification, statement: statement, staged: staged, recoveryPublicKeys: recoveryPublicKeys, recoveryThreshold: recoveryThreshold)
    }

    private static func validateThresholdRecovery(_ verification: NativeRecoveryVerification, statement: NativeKeyTransitionStatement, staged: NativeKeyGeneration, recoveryPublicKeys: [Data], recoveryThreshold: Int?) throws {
        guard let recoveryThreshold else { throw AgentPassNativeError.invalidConfiguration("Threshold recovery is not configured for lifecycle replay") }
        let pinnedFingerprints = try Set(recoveryPublicKeys.map { try NativeRecoveryVerifier.authorityFingerprint(rawEd25519PublicKey: $0) })
        let request = verification.request
        guard verification.threshold == recoveryThreshold,
              Set(verification.authorityPublicKeyFingerprints) == pinnedFingerprints,
              statement.continuity == .recovered,
              statement.reason == "offline-threshold-recovery:\(verification.requestHash)",
              statement.challengeID == request.nonce,
              statement.createdAt == request.issuedAt,
              statement.role == request.role,
              statement.oldGeneration == request.fromGeneration,
              statement.oldFingerprint == request.fromFingerprint,
              statement.newGeneration == request.proposedGeneration,
              statement.newFingerprint == staged.fingerprint,
              statement.previousLifecycleHead == request.lifecycleHeadHash,
              staged.generation == request.proposedGeneration,
              staged.publicKeyX963 == request.proposedPublicKeyX963 else {
            throw AgentPassNativeError.invalidSignature("Threshold recovery evidence or pinned policy does not match the lifecycle transition")
        }
    }

    private func stageRecord(state: NativeKeyLifecycleSnapshot, role: NativeKeyRole, generation: Int, applicationTag: String, publicKeyX963: Data, createdAt: String) throws -> NativeKeyLifecycleRecord {
        try Self.validatePublicKey(publicKeyX963)
        try Self.validateText(applicationTag, label: "application tag", maximum: 512)
        try Self.validateTimestamp(createdAt)
        try Self.validateNotBefore(createdAt, previous: state.latestTimestamp)
        if state.active(for: .sessionApproval) == nil && role != .sessionApproval {
            throw AgentPassNativeError.invalidConfiguration("The session approval authority must be bootstrapped first")
        }
        guard !state.generations.contains(where: { ($0.status == .staged || $0.status == .abortIntent) && $0.role == role }) else {
            throw AgentPassNativeError.invalidConfiguration("A staged or aborting key already exists for role \(role.rawValue)")
        }
        guard !state.generations.contains(where: { $0.applicationTag == applicationTag }) else {
            throw AgentPassNativeError.invalidKey("Lifecycle application tag reuse is forbidden")
        }
        guard !state.generations.contains(where: { $0.publicKeyX963 == publicKeyX963 || $0.fingerprint == Self.fingerprint(publicKeyX963) }) else {
            throw AgentPassNativeError.invalidKey("Lifecycle public-key reuse across generations is forbidden")
        }
        let maximum = state.generations.filter { $0.role == role }.map(\.generation).max() ?? 0
        guard generation == maximum + 1, generation > 0 else {
            throw AgentPassNativeError.invalidConfiguration("Key generation must increase by exactly one")
        }
        return try makeRecord(sequence: state.sequence + 1, previous: state.headHash, action: "staged", role: role, generation: generation, applicationTag: applicationTag, publicKey: publicKeyX963, createdAt: createdAt, continuity: .clean)
    }

    private func activationRecord(state: NativeKeyLifecycleSnapshot, statement: NativeKeyTransitionStatement, oldSignature: Data?, newSignature: Data, approvalSignature: Data, approvalPublicKeyX963: Data) throws -> NativeKeyLifecycleRecord {
        let expected = try transitionStatement(state: state, role: statement.role, generation: statement.newGeneration, reason: statement.reason, challengeID: statement.challengeID, createdAt: statement.createdAt, continuity: statement.continuity)
        guard statement == expected else { throw AgentPassNativeError.invalidSignature("Key transition statement does not match current lifecycle state") }
        let staged = try Self.requiredGeneration(state, role: statement.role, generation: statement.newGeneration, status: .staged)
        let message = try statement.canonicalData()
        // Recovered audit activations are committed into a schema-v3 transition
        // hash. Normalize Secure Enclave/CryptoKit output before record hashing;
        // clean/bootstrap lifecycle and v2 audit-key artifacts retain their
        // established byte compatibility.
        let storedNewSignature = statement.continuity == .recovered
            ? try NativeP256CanonicalSignature.canonicalized(newSignature)
            : newSignature
        guard verifier.isValid(signature: storedNewSignature, message: message, publicKeyX963: staged.publicKeyX963) else {
            throw AgentPassNativeError.invalidSignature("Replacement key proof-of-possession is invalid")
        }
        let activeApproval = state.active(for: .sessionApproval)
        switch statement.continuity {
        case .bootstrap:
            try Self.validatePublicKey(approvalPublicKeyX963)
            guard verifier.isValid(signature: approvalSignature, message: message, publicKeyX963: approvalPublicKeyX963) else {
                throw AgentPassNativeError.invalidSignature("Lifecycle approval signature is invalid")
            }
            guard state.active(for: statement.role) == nil, oldSignature == nil else {
                throw AgentPassNativeError.invalidSignature("Bootstrap cannot replace an active generation")
            }
            if statement.role == .sessionApproval && activeApproval == nil {
                guard state.sequence == 1, approvalPublicKeyX963 == staged.publicKeyX963 else {
                    throw AgentPassNativeError.invalidSignature("Initial approval bootstrap must be self-authorized")
                }
            } else {
                guard let activeApproval, approvalPublicKeyX963 == activeApproval.publicKeyX963 else {
                    throw AgentPassNativeError.invalidSignature("Role bootstrap requires the active approval key")
                }
            }
        case .clean:
            try Self.validatePublicKey(approvalPublicKeyX963)
            guard verifier.isValid(signature: approvalSignature, message: message, publicKeyX963: approvalPublicKeyX963) else {
                throw AgentPassNativeError.invalidSignature("Lifecycle approval signature is invalid")
            }
            let old = try Self.requiredActive(state, role: statement.role)
            guard let oldSignature, verifier.isValid(signature: oldSignature, message: message, publicKeyX963: old.publicKeyX963) else {
                throw AgentPassNativeError.invalidSignature("Retiring key continuity signature is invalid")
            }
            guard let activeApproval, approvalPublicKeyX963 == activeApproval.publicKeyX963 else {
                throw AgentPassNativeError.invalidSignature("Approval-key substitution detected")
            }
        case .recovered:
            guard oldSignature == nil else { throw AgentPassNativeError.invalidSignature("Recovered transition cannot assert old-key continuity") }
            if approvalPublicKeyX963.isEmpty {
                let evidence = try NativeRecoveryVerifier.verifyHistoricalEvidence(approvalSignature)
                try validateThresholdRecovery(evidence, statement: statement, staged: staged)
            } else {
                guard recoveryThreshold == nil, recoveryPublicKeys.contains(approvalPublicKeyX963), Self.isValidRecoverySignature(approvalSignature, message: message, publicKey: approvalPublicKeyX963) else {
                    throw AgentPassNativeError.invalidSignature("Recovered transition requires a pinned recovery authority")
                }
            }
        }
        return try makeRecord(sequence: state.sequence + 1, previous: state.headHash, action: "activated", role: staged.role, generation: staged.generation, applicationTag: staged.applicationTag, publicKey: staged.publicKeyX963, createdAt: statement.createdAt, continuity: statement.continuity, reason: statement.reason, challengeID: statement.challengeID, oldGeneration: statement.oldGeneration, oldFingerprint: statement.oldFingerprint, oldSignature: oldSignature ?? Data(), newSignature: storedNewSignature, approvalSignature: approvalSignature, approvalPublicKey: approvalPublicKeyX963)
    }

    private func transitionStatement(state: NativeKeyLifecycleSnapshot, role: NativeKeyRole, generation: Int, reason: String, challengeID: String, createdAt: String, continuity: NativeKeyContinuity) throws -> NativeKeyTransitionStatement {
        try Self.validateText(reason, label: "transition reason", maximum: 1024)
        try Self.validateText(challengeID, label: "challenge ID", maximum: 256)
        try Self.validateTimestamp(createdAt)
        try Self.validateNotBefore(createdAt, previous: state.latestTimestamp)
        let staged = try Self.requiredGeneration(state, role: role, generation: generation, status: .staged)
        let old = state.active(for: role)
        if continuity == .clean { guard old != nil else { throw AgentPassNativeError.invalidConfiguration("Clean continuity requires an active retiring key") } }
        if continuity == .bootstrap { guard old == nil else { throw AgentPassNativeError.invalidConfiguration("Bootstrap cannot replace an active key") } }
        return NativeKeyTransitionStatement(role: role, oldGeneration: old?.generation ?? 0, newGeneration: staged.generation, oldFingerprint: old?.fingerprint ?? "", newFingerprint: staged.fingerprint, stateSequence: state.sequence + 1, reason: reason, challengeID: challengeID, createdAt: createdAt, previousLifecycleHead: state.headHash, continuity: continuity)
    }

    private func verifyUnlocked(expectedHeadHash: String? = nil) throws -> NativeKeyLifecycleSnapshot {
        let snapshot = try Self.read(directory: directory, verifier: verifier, recoveryPublicKeys: recoveryPublicKeys, recoveryThreshold: recoveryThreshold)
        guard snapshot.headHash == pinnedHead else { throw AgentPassNativeError.invalidSignature("Key lifecycle rollback or concurrent mutation detected") }
        if let expectedHeadHash, expectedHeadHash != snapshot.headHash { throw AgentPassNativeError.invalidSignature("Key lifecycle externally pinned head does not match") }
        return snapshot
    }

    private func append(_ unsigned: NativeKeyLifecycleRecord) throws {
        let data = try Self.recordData(unsigned)
        let name = String(format: "%020d-%@.json", unsigned.sequence, unsigned.recordHash)
        try Self.atomicRecordWrite(directory: directory, name: name, data: data)
        pinnedHead = unsigned.recordHash
    }

    private func makeRecord(sequence: Int, previous: String, action: String, role: NativeKeyRole, generation: Int, applicationTag: String, publicKey: Data, createdAt: String, continuity: NativeKeyContinuity, reason: String = "", challengeID: String = "", oldGeneration: Int = 0, oldFingerprint: String = "", oldSignature: Data = Data(), newSignature: Data = Data(), approvalSignature: Data = Data(), approvalPublicKey: Data = Data(), minimumRetirementAgeSeconds: Int = 0, transitionArchived: Bool = false, externallyPinnedHeadHash: String = "", auditDeletionBinding: NativeAuditDeletionIntentBinding? = nil) throws -> NativeKeyLifecycleRecord {
        try Self.validateTimestamp(createdAt)
        if let auditDeletionBinding { try Self.validateAuditDeletionBinding(auditDeletionBinding) }
        let base = NativeKeyLifecycleRecord(sequence: sequence, previousRecordHash: previous, action: action, role: role, generation: generation, applicationTag: applicationTag, publicKeyX963: publicKey, fingerprint: Self.fingerprint(publicKey), createdAt: createdAt, continuity: continuity, reason: reason, challengeID: challengeID, oldGeneration: oldGeneration, oldFingerprint: oldFingerprint, oldSignature: oldSignature, newSignature: newSignature, approvalSignature: approvalSignature, approvalPublicKeyX963: approvalPublicKey, minimumRetirementAgeSeconds: minimumRetirementAgeSeconds, transitionArchived: transitionArchived, externallyPinnedHeadHash: externallyPinnedHeadHash, auditDeletionBinding: auditDeletionBinding, recordHash: "")
        let hash = Self.hash(try Self.recordData(base, includeHash: false))
        return NativeKeyLifecycleRecord(sequence: base.sequence, previousRecordHash: base.previousRecordHash, action: base.action, role: base.role, generation: base.generation, applicationTag: base.applicationTag, publicKeyX963: base.publicKeyX963, fingerprint: base.fingerprint, createdAt: base.createdAt, continuity: base.continuity, reason: base.reason, challengeID: base.challengeID, oldGeneration: base.oldGeneration, oldFingerprint: base.oldFingerprint, oldSignature: base.oldSignature, newSignature: base.newSignature, approvalSignature: base.approvalSignature, approvalPublicKeyX963: base.approvalPublicKeyX963, minimumRetirementAgeSeconds: base.minimumRetirementAgeSeconds, transitionArchived: base.transitionArchived, externallyPinnedHeadHash: base.externallyPinnedHeadHash, auditDeletionBinding: base.auditDeletionBinding, recordHash: hash)
    }

    private static func read(directory: String, verifier: any NativeLifecycleSignatureVerifier, recoveryPublicKeys: [Data], recoveryThreshold: Int?) throws -> NativeKeyLifecycleSnapshot {
        try validatePrivateDirectory(directory)
        let names = try FileManager.default.contentsOfDirectory(atPath: directory).sorted()
        guard names.count <= 1_000_000 else { throw AgentPassNativeError.invalidConfiguration("Key lifecycle record limit exceeded") }
        let recordNames = names.filter { parseFilename($0) != nil }
        let temporaryNames = names.filter { parseTemporaryFilename($0) }
        guard recordNames.count + temporaryNames.count == names.count, temporaryNames.count <= 1 else {
            throw AgentPassNativeError.invalidSignature("Key lifecycle contains an unknown file or multiple crash remnants")
        }

        var uncommittedTemporary: (name: String, record: NativeKeyLifecycleRecord)?
        if let temporaryName = temporaryNames.first {
            let inspected = try inspectTemporaryRecord(directory: directory, name: temporaryName)
            let destinationName = String(format: "%020d-%@.json", inspected.record.sequence, inspected.record.recordHash)
            if inspected.linkCount == 2 {
                guard recordNames.last == destinationName, inspected.record.sequence == recordNames.count else {
                    throw AgentPassNativeError.invalidSignature("Committed lifecycle crash remnant is not the ledger tail")
                }
                let destination = URL(fileURLWithPath: directory).appendingPathComponent(destinationName).path
                var destinationInfo = stat()
                guard lstat(destination, &destinationInfo) == 0,
                      (destinationInfo.st_mode & S_IFMT) == S_IFREG,
                      destinationInfo.st_uid == geteuid(),
                      destinationInfo.st_mode & 0o777 == 0o400,
                      destinationInfo.st_nlink == 2,
                      destinationInfo.st_dev == inspected.device,
                      destinationInfo.st_ino == inspected.inode else {
                    throw AgentPassNativeError.invalidSignature("Lifecycle crash remnant does not link to its canonical record")
                }
                try removeRecoveredTemporary(directory: directory, name: temporaryName)
            } else {
                uncommittedTemporary = (temporaryName, inspected.record)
            }
        }

        var records: [NativeKeyLifecycleRecord] = []
        var expectedSequence = 1
        var previous = zeroHash
        for name in recordNames {
            guard let parsed = parseFilename(name), parsed.sequence == expectedSequence else {
                throw AgentPassNativeError.invalidSignature("Key lifecycle contains an unknown file, sequence gap, or reordered record")
            }
            let path = URL(fileURLWithPath: directory).appendingPathComponent(name).path
            try validatePrivateRecord(path)
            let attributes = try FileManager.default.attributesOfItem(atPath: path)
            guard (attributes[.size] as? NSNumber)?.intValue ?? 0 <= 1_048_576 else { throw AgentPassNativeError.invalidConfiguration("Key lifecycle record exceeds 1 MiB") }
            let data = try Data(contentsOf: URL(fileURLWithPath: path), options: [.mappedIfSafe])
            let record = try decodeRecord(data)
            guard record.sequence == expectedSequence, record.previousRecordHash == previous, record.recordHash == parsed.hash,
                  record.recordHash == hash(try recordData(record, includeHash: false)) else {
                throw AgentPassNativeError.invalidSignature("Key lifecycle record hash chain is invalid")
            }
            records.append(record)
            expectedSequence += 1
            previous = record.recordHash
        }
        let snapshot = try replay(records, verifier: verifier, recoveryPublicKeys: recoveryPublicKeys, recoveryThreshold: recoveryThreshold)
        if let temporary = uncommittedTemporary {
            guard temporary.record.sequence == snapshot.sequence + 1,
                  temporary.record.previousRecordHash == snapshot.headHash,
                  temporary.record.recordHash == hash(try recordData(temporary.record, includeHash: false)) else {
                throw AgentPassNativeError.invalidSignature("Uncommitted lifecycle crash remnant does not extend the current ledger")
            }
            _ = try replay(records + [temporary.record], verifier: verifier, recoveryPublicKeys: recoveryPublicKeys, recoveryThreshold: recoveryThreshold)
            try removeRecoveredTemporary(directory: directory, name: temporary.name)
        }
        return snapshot
    }

    private static func replay(_ records: [NativeKeyLifecycleRecord], verifier: any NativeLifecycleSignatureVerifier, recoveryPublicKeys: [Data], recoveryThreshold: Int?) throws -> NativeKeyLifecycleSnapshot {
        var generations: [NativeKeyGeneration] = []
        var tags = Set<String>()
        var previous = zeroHash
        var previousTimestamp: Date?
        for (offset, record) in records.enumerated() {
            guard record.sequence == offset + 1, record.previousRecordHash == previous else { throw AgentPassNativeError.invalidSignature("Key lifecycle sequence rollback or gap detected") }
            guard let timestamp = timestampDate(record.createdAt), previousTimestamp == nil || timestamp >= previousTimestamp! else { throw AgentPassNativeError.invalidSignature("Key lifecycle timestamp rollback detected") }
            guard record.auditDeletionBinding == nil || (record.action == "deletion_intent" && record.role == .auditCheckpoint) else {
                throw AgentPassNativeError.invalidSignature("Audit deletion evidence binding appears on an unrelated lifecycle record")
            }
            switch record.action {
            case "staged":
                guard record.oldGeneration == 0, record.oldFingerprint.isEmpty, record.oldSignature.isEmpty, record.newSignature.isEmpty, record.approvalSignature.isEmpty, record.approvalPublicKeyX963.isEmpty, record.reason.isEmpty, record.challengeID.isEmpty, record.minimumRetirementAgeSeconds == 0, !record.transitionArchived, record.externallyPinnedHeadHash.isEmpty else { throw AgentPassNativeError.invalidSignature("Staged lifecycle record contains forbidden transition fields") }
                guard !tags.contains(record.applicationTag), !generations.contains(where: { $0.role == record.role && $0.status == .staged }) else { throw AgentPassNativeError.invalidKey("Lifecycle tag reuse or staged-key equivocation detected") }
                let maximum = generations.filter { $0.role == record.role }.map(\.generation).max() ?? 0
                guard record.generation == maximum + 1 else { throw AgentPassNativeError.invalidSignature("Per-role key generation gap or rollback detected") }
                guard record.continuity == .clean else { throw AgentPassNativeError.invalidSignature("Staged record has invalid continuity semantics") }
                generations.append(NativeKeyGeneration(role: record.role, generation: record.generation, applicationTag: record.applicationTag, publicKeyX963: record.publicKeyX963, fingerprint: record.fingerprint, status: .staged, createdAt: record.createdAt, retiredAt: nil, deletionIntentAt: nil, deletedAt: nil, auditDeletionBinding: nil, deletionIntentLifecycleHead: nil))
                tags.insert(record.applicationTag)
            case "activated":
                guard record.minimumRetirementAgeSeconds == 0, !record.transitionArchived, record.externallyPinnedHeadHash.isEmpty else { throw AgentPassNativeError.invalidSignature("Activation contains forbidden deletion evidence") }
                guard let stagedIndex = generations.firstIndex(where: { $0.role == record.role && $0.generation == record.generation && $0.status == .staged }), generations[stagedIndex].applicationTag == record.applicationTag, generations[stagedIndex].publicKeyX963 == record.publicKeyX963 else { throw AgentPassNativeError.invalidSignature("Activation does not match exactly one staged key") }
                let oldIndex = generations.firstIndex { $0.role == record.role && $0.status == .active }
                let statement = NativeKeyTransitionStatement(role: record.role, oldGeneration: record.oldGeneration, newGeneration: record.generation, oldFingerprint: record.oldFingerprint, newFingerprint: record.fingerprint, stateSequence: record.sequence, reason: record.reason, challengeID: record.challengeID, createdAt: record.createdAt, previousLifecycleHead: record.previousRecordHash, continuity: record.continuity)
                let message = try statement.canonicalData()
                guard verifier.isValid(signature: record.newSignature, message: message, publicKeyX963: record.publicKeyX963) else { throw AgentPassNativeError.invalidSignature("Lifecycle replacement-key signature is invalid") }
                switch record.continuity {
                case .bootstrap:
                    guard verifier.isValid(signature: record.approvalSignature, message: message, publicKeyX963: record.approvalPublicKeyX963) else { throw AgentPassNativeError.invalidSignature("Lifecycle approval signature is invalid") }
                    guard oldIndex == nil, record.oldGeneration == 0, record.oldFingerprint.isEmpty, record.oldSignature.isEmpty else { throw AgentPassNativeError.invalidSignature("Invalid lifecycle bootstrap") }
                    let activeApproval = generations.first { $0.role == .sessionApproval && $0.status == .active }
                    if record.role == .sessionApproval && activeApproval == nil {
                        guard record.sequence == 2, record.approvalPublicKeyX963 == record.publicKeyX963 else { throw AgentPassNativeError.invalidSignature("Invalid initial approval bootstrap") }
                    } else {
                        guard let activeApproval, activeApproval.publicKeyX963 == record.approvalPublicKeyX963 else { throw AgentPassNativeError.invalidSignature("Role bootstrap approval key is invalid") }
                    }
                case .clean:
                    guard verifier.isValid(signature: record.approvalSignature, message: message, publicKeyX963: record.approvalPublicKeyX963) else { throw AgentPassNativeError.invalidSignature("Lifecycle approval signature is invalid") }
                    guard let oldIndex, generations[oldIndex].generation == record.oldGeneration, generations[oldIndex].fingerprint == record.oldFingerprint, let approval = generations.first(where: { $0.role == .sessionApproval && $0.status == .active }), approval.publicKeyX963 == record.approvalPublicKeyX963, verifier.isValid(signature: record.oldSignature, message: message, publicKeyX963: generations[oldIndex].publicKeyX963) else { throw AgentPassNativeError.invalidSignature("Lifecycle clean-continuity proof is invalid") }
                    generations[oldIndex].status = .retired
                    generations[oldIndex].retiredAt = record.createdAt
                case .recovered:
                    guard record.oldSignature.isEmpty else { throw AgentPassNativeError.invalidSignature("Recovered lifecycle transition asserts false old-key continuity") }
                    if record.approvalPublicKeyX963.isEmpty {
                        let evidence = try NativeRecoveryVerifier.verifyHistoricalEvidence(record.approvalSignature)
                        try validateThresholdRecovery(evidence, statement: statement, staged: generations[stagedIndex], recoveryPublicKeys: recoveryPublicKeys, recoveryThreshold: recoveryThreshold)
                    } else {
                        guard recoveryThreshold == nil, recoveryPublicKeys.contains(record.approvalPublicKeyX963), Self.isValidRecoverySignature(record.approvalSignature, message: message, publicKey: record.approvalPublicKeyX963) else { throw AgentPassNativeError.invalidSignature("Lifecycle recovery authority is not pinned or its signature is invalid") }
                    }
                    if let oldIndex {
                        guard generations[oldIndex].generation == record.oldGeneration, generations[oldIndex].fingerprint == record.oldFingerprint else { throw AgentPassNativeError.invalidSignature("Recovered transition replaced an unexpected generation") }
                        generations[oldIndex].status = .retired
                        generations[oldIndex].retiredAt = record.createdAt
                    }
                }
                generations[stagedIndex].status = .active
            case "abort_intent":
                guard record.continuity == .clean,
                      let index = generations.firstIndex(where: { $0.role == record.role && $0.generation == record.generation }),
                      generations[index].status == .staged,
                      generations[index].applicationTag == record.applicationTag,
                      generations[index].publicKeyX963 == record.publicKeyX963,
                      record.oldGeneration == 0, record.oldFingerprint.isEmpty, record.oldSignature.isEmpty, record.newSignature.isEmpty,
                      record.minimumRetirementAgeSeconds == 0, !record.transitionArchived,
                      record.externallyPinnedHeadHash == record.previousRecordHash,
                      let approval = generations.first(where: { $0.role == .sessionApproval && $0.status == .active }),
                      approval.publicKeyX963 == record.approvalPublicKeyX963 else {
                    throw AgentPassNativeError.invalidSignature("Staged-key abort intent is invalid or targets a substituted key")
                }
                let message = try abortStatement(role: record.role, generation: record.generation, sequence: record.sequence, reason: record.reason, challengeID: record.challengeID, createdAt: record.createdAt, previous: record.previousRecordHash, externallyPinnedHeadHash: record.externallyPinnedHeadHash)
                guard verifier.isValid(signature: record.approvalSignature, message: message, publicKeyX963: record.approvalPublicKeyX963) else {
                    throw AgentPassNativeError.invalidSignature("Staged-key abort intent signature is invalid")
                }
                generations[index].status = .abortIntent
            case "aborted":
                guard record.continuity == .clean,
                      let index = generations.firstIndex(where: { $0.role == record.role && $0.generation == record.generation }),
                      generations[index].status == .abortIntent,
                      generations[index].applicationTag == record.applicationTag,
                      generations[index].publicKeyX963 == record.publicKeyX963,
                      record.reason.isEmpty, record.challengeID.isEmpty,
                      record.oldGeneration == 0, record.oldFingerprint.isEmpty, record.oldSignature.isEmpty, record.newSignature.isEmpty,
                      record.approvalSignature.isEmpty, record.approvalPublicKeyX963.isEmpty,
                      record.minimumRetirementAgeSeconds == 0, !record.transitionArchived, record.externallyPinnedHeadHash.isEmpty else {
                    throw AgentPassNativeError.invalidSignature("Aborted record has no matching authorized abort intent")
                }
                generations[index].status = .aborted
            case "deletion_intent":
                guard record.continuity == .clean, let index = generations.firstIndex(where: { $0.role == record.role && $0.generation == record.generation }), generations[index].status == .retired, generations[index].applicationTag == record.applicationTag, generations[index].publicKeyX963 == record.publicKeyX963, record.oldSignature.isEmpty, record.newSignature.isEmpty, (86_400...31_536_000).contains(record.minimumRetirementAgeSeconds), record.transitionArchived, record.externallyPinnedHeadHash == record.previousRecordHash, let retiredAt = generations[index].retiredAt, let retiredDate = timestampDate(retiredAt), let deletionDate = timestampDate(record.createdAt), deletionDate.timeIntervalSince(retiredDate) >= Double(record.minimumRetirementAgeSeconds) else { throw AgentPassNativeError.invalidSignature("Deletion intent targets an ineligible, substituted, or externally unpinned key") }
                guard let approval = generations.first(where: { $0.role == .sessionApproval && $0.status == .active }), approval.publicKeyX963 == record.approvalPublicKeyX963 else { throw AgentPassNativeError.invalidSignature("Deletion approval-key substitution detected") }
                let message = try deletionStatement(role: record.role, generation: record.generation, sequence: record.sequence, reason: record.reason, challengeID: record.challengeID, createdAt: record.createdAt, previous: record.previousRecordHash, minimumRetirementAgeSeconds: record.minimumRetirementAgeSeconds, transitionArchived: record.transitionArchived, externallyPinnedHeadHash: record.externallyPinnedHeadHash, auditDeletionBinding: record.auditDeletionBinding)
                guard verifier.isValid(signature: record.approvalSignature, message: message, publicKeyX963: record.approvalPublicKeyX963) else { throw AgentPassNativeError.invalidSignature("Deletion intent signature is invalid") }
                generations[index].status = .deletionIntent
                generations[index].deletionIntentAt = record.createdAt
                generations[index].auditDeletionBinding = record.auditDeletionBinding
                generations[index].deletionIntentLifecycleHead = record.externallyPinnedHeadHash
            case "deleted":
                guard record.continuity == .clean, let index = generations.firstIndex(where: { $0.role == record.role && $0.generation == record.generation }), generations[index].status == .deletionIntent, generations[index].applicationTag == record.applicationTag, generations[index].publicKeyX963 == record.publicKeyX963, record.reason.isEmpty, record.challengeID.isEmpty, record.oldSignature.isEmpty, record.newSignature.isEmpty, record.approvalSignature.isEmpty, record.approvalPublicKeyX963.isEmpty, record.minimumRetirementAgeSeconds == 0, !record.transitionArchived, record.externallyPinnedHeadHash.isEmpty else { throw AgentPassNativeError.invalidSignature("Deleted record has no matching deletion intent") }
                generations[index].status = .deleted
                generations[index].deletedAt = record.createdAt
            default:
                throw AgentPassNativeError.invalidSignature("Unknown key lifecycle action")
            }
            previous = record.recordHash
            previousTimestamp = timestamp
        }
        for role in NativeKeyRole.allCases {
            guard generations.filter({ $0.role == role && $0.status == .active }).count <= 1,
                  generations.filter({ $0.role == role && ($0.status == .staged || $0.status == .abortIntent) }).count <= 1 else { throw AgentPassNativeError.invalidSignature("Lifecycle has equivocal active, staged, or aborting generations") }
        }
        return NativeKeyLifecycleSnapshot(sequence: records.count, headHash: previous, latestTimestamp: records.last?.createdAt, generations: generations)
    }

    /// Reads only committed immutable records. The caller must already hold the directory lock
    /// and must have called `verifyUnlocked`, which recovers or rejects any temporary tail.
    private static func readCommittedRecords(directory: String) throws -> [NativeKeyLifecycleRecord] {
        let names = try FileManager.default.contentsOfDirectory(atPath: directory).sorted()
        let recordNames = names.filter { parseFilename($0) != nil }
        guard recordNames.count == names.count else {
            throw AgentPassNativeError.invalidSignature("Lifecycle replay requires a clean committed ledger")
        }
        var records: [NativeKeyLifecycleRecord] = []
        var expectedSequence = 1
        var previous = zeroHash
        for name in recordNames {
            guard let parsed = parseFilename(name), parsed.sequence == expectedSequence else {
                throw AgentPassNativeError.invalidSignature("Lifecycle replay contains a sequence gap")
            }
            let path = URL(fileURLWithPath: directory).appendingPathComponent(name).path
            try validatePrivateRecord(path)
            let attributes = try FileManager.default.attributesOfItem(atPath: path)
            guard (attributes[.size] as? NSNumber)?.intValue ?? 0 <= 1_048_576 else {
                throw AgentPassNativeError.invalidConfiguration("Key lifecycle record exceeds 1 MiB")
            }
            let data = try Data(contentsOf: URL(fileURLWithPath: path), options: [.mappedIfSafe])
            let record = try decodeRecord(data)
            guard record.sequence == expectedSequence,
                  record.previousRecordHash == previous,
                  record.recordHash == parsed.hash,
                  record.recordHash == hash(try recordData(record, includeHash: false)) else {
                throw AgentPassNativeError.invalidSignature("Lifecycle replay record hash chain is invalid")
            }
            records.append(record)
            expectedSequence += 1
            previous = record.recordHash
        }
        return records
    }

    private static func requiredGeneration(_ state: NativeKeyLifecycleSnapshot, role: NativeKeyRole, generation: Int, status: NativeKeyGenerationStatus) throws -> NativeKeyGeneration {
        guard let value = state.generations.first(where: { $0.role == role && $0.generation == generation && $0.status == status }) else { throw AgentPassNativeError.invalidConfiguration("Expected \(status.rawValue) key generation does not exist") }
        return value
    }

    private static func requiredActive(_ state: NativeKeyLifecycleSnapshot, role: NativeKeyRole) throws -> NativeKeyGeneration {
        guard let value = state.active(for: role) else { throw AgentPassNativeError.invalidConfiguration("No active key exists for role \(role.rawValue)") }
        return value
    }

    private static func deletionStatement(role: NativeKeyRole, generation: Int, sequence: Int, reason: String, challengeID: String, createdAt: String, previous: String, minimumRetirementAgeSeconds: Int, transitionArchived: Bool, externallyPinnedHeadHash: String, auditDeletionBinding: NativeAuditDeletionIntentBinding?) throws -> Data {
        try validateText(reason, label: "deletion reason", maximum: 1024)
        try validateText(challengeID, label: "challenge ID", maximum: 256)
        try validateTimestamp(createdAt)
        var object: [String: Any] = ["version": auditDeletionBinding == nil ? 1 : 2, "action": "deletion_intent", "role": role.rawValue, "generation": generation, "state_sequence": sequence, "reason": reason, "challenge_id": challengeID, "created_at": createdAt, "previous_lifecycle_head": previous, "minimum_retirement_age_seconds": minimumRetirementAgeSeconds, "transition_archived": transitionArchived, "externally_pinned_head_hash": externallyPinnedHeadHash]
        if let auditDeletionBinding {
            try validateAuditDeletionBinding(auditDeletionBinding)
            object["audit_deletion_binding"] = auditDeletionBindingObject(auditDeletionBinding)
        }
        return try lifecycleCanonical(object)
    }

    private static func abortStatement(role: NativeKeyRole, generation: Int, sequence: Int, reason: String, challengeID: String, createdAt: String, previous: String, externallyPinnedHeadHash: String) throws -> Data {
        try validateText(reason, label: "abort reason", maximum: 1024)
        try validateText(challengeID, label: "challenge ID", maximum: 256)
        try validateTimestamp(createdAt)
        guard externallyPinnedHeadHash == previous else { throw AgentPassNativeError.invalidSignature("Staged-key abort external pin is stale") }
        return try lifecycleCanonical(["version": 1, "action": "abort_intent", "role": role.rawValue, "generation": generation, "state_sequence": sequence, "reason": reason, "challenge_id": challengeID, "created_at": createdAt, "previous_lifecycle_head": previous, "externally_pinned_head_hash": externallyPinnedHeadHash])
    }

    private static func recordData(_ record: NativeKeyLifecycleRecord, includeHash: Bool = true) throws -> Data {
        var object: [String: Any] = [
            "version": record.auditDeletionBinding == nil ? 1 : 2, "sequence": record.sequence, "previous_record_hash": record.previousRecordHash,
            "action": record.action, "role": record.role.rawValue, "generation": record.generation,
            "application_tag": record.applicationTag, "public_key": record.publicKeyX963.base64EncodedString(),
            "fingerprint": record.fingerprint, "created_at": record.createdAt, "continuity": record.continuity.rawValue,
            "reason": record.reason, "challenge_id": record.challengeID, "old_generation": record.oldGeneration,
            "old_fingerprint": record.oldFingerprint, "old_signature": record.oldSignature.base64EncodedString(),
            "new_signature": record.newSignature.base64EncodedString(), "approval_signature": record.approvalSignature.base64EncodedString(),
            "approval_public_key": record.approvalPublicKeyX963.base64EncodedString(),
            "minimum_retirement_age_seconds": record.minimumRetirementAgeSeconds,
            "transition_archived": record.transitionArchived,
            "externally_pinned_head_hash": record.externallyPinnedHeadHash
        ]
        if let binding = record.auditDeletionBinding { object["audit_deletion_binding"] = auditDeletionBindingObject(binding) }
        if includeHash { object["record_hash"] = record.recordHash }
        return try lifecycleCanonical(object)
    }

    private static func decodeRecord(_ data: Data) throws -> NativeKeyLifecycleRecord {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let version = int(object["version"]), (version == 1 && Set(object.keys) == recordKeys) || (version == 2 && Set(object.keys) == recordV2Keys),
              (try? lifecycleCanonical(object)) == data,
              let sequence = int(object["sequence"]), sequence > 0,
              let previous = object["previous_record_hash"] as? String, isHash(previous),
              let action = object["action"] as? String, validActions.contains(action),
              let roleValue = object["role"] as? String, let role = NativeKeyRole(rawValue: roleValue),
              let generation = int(object["generation"]), generation > 0,
              let applicationTag = object["application_tag"] as? String,
              let publicKeyValue = object["public_key"] as? String, let publicKey = Data(base64Encoded: publicKeyValue),
              let fingerprint = object["fingerprint"] as? String, fingerprint == self.fingerprint(publicKey),
              let createdAt = object["created_at"] as? String,
              let continuityValue = object["continuity"] as? String, let continuity = NativeKeyContinuity(rawValue: continuityValue),
              let reason = object["reason"] as? String, let challengeID = object["challenge_id"] as? String,
              let oldGeneration = int(object["old_generation"]), oldGeneration >= 0,
              let oldFingerprint = object["old_fingerprint"] as? String,
              let oldSignatureValue = object["old_signature"] as? String, let oldSignature = Data(base64Encoded: oldSignatureValue),
              let newSignatureValue = object["new_signature"] as? String, let newSignature = Data(base64Encoded: newSignatureValue),
              let approvalSignatureValue = object["approval_signature"] as? String, let approvalSignature = Data(base64Encoded: approvalSignatureValue),
              let approvalKeyValue = object["approval_public_key"] as? String, let approvalKey = Data(base64Encoded: approvalKeyValue),
              let minimumRetirementAgeSeconds = int(object["minimum_retirement_age_seconds"]), minimumRetirementAgeSeconds >= 0,
              let transitionArchived = object["transition_archived"] as? Bool,
              let externallyPinnedHeadHash = object["externally_pinned_head_hash"] as? String,
              let recordHash = object["record_hash"] as? String, isHash(recordHash) else { throw AgentPassNativeError.invalidSignature("Key lifecycle record schema or key set is invalid") }
        let auditDeletionBinding = try version == 2 ? decodeAuditDeletionBinding(object["audit_deletion_binding"]) : nil
        try validatePublicKey(publicKey)
        if !approvalKey.isEmpty {
            if continuity == .recovered { try validateRecoveryPublicKey(approvalKey) }
            else { try validatePublicKey(approvalKey) }
        }
        try validateText(applicationTag, label: "application tag", maximum: 512)
        if !reason.isEmpty { try validateText(reason, label: "reason", maximum: 1024) }
        if !challengeID.isEmpty { try validateText(challengeID, label: "challenge ID", maximum: 256) }
        try validateTimestamp(createdAt)
        return NativeKeyLifecycleRecord(sequence: sequence, previousRecordHash: previous, action: action, role: role, generation: generation, applicationTag: applicationTag, publicKeyX963: publicKey, fingerprint: fingerprint, createdAt: createdAt, continuity: continuity, reason: reason, challengeID: challengeID, oldGeneration: oldGeneration, oldFingerprint: oldFingerprint, oldSignature: oldSignature, newSignature: newSignature, approvalSignature: approvalSignature, approvalPublicKeyX963: approvalKey, minimumRetirementAgeSeconds: minimumRetirementAgeSeconds, transitionArchived: transitionArchived, externallyPinnedHeadHash: externallyPinnedHeadHash, auditDeletionBinding: auditDeletionBinding, recordHash: recordHash)
    }

    private static func auditDeletionBindingObject(_ value: NativeAuditDeletionIntentBinding) -> [String: Any] {
        ["bundle_sha256": value.bundleSHA256, "retained_segment_hash": value.retainedSegmentHash,
         "retained_identity_hash": value.retainedIdentityHash, "archive_path_chain_hash": value.archivePathChainHash,
         "operation_id": value.operationID,
         "spool_manifest_hash": value.spoolManifestHash, "spool_directory_name": value.spoolDirectoryName,
         "spool_device": value.spoolDevice, "spool_inode": value.spoolInode]
    }

    private static func validateAuditDeletionBinding(_ value: NativeAuditDeletionIntentBinding) throws {
        guard [value.bundleSHA256, value.retainedSegmentHash, value.retainedIdentityHash, value.archivePathChainHash, value.spoolManifestHash].allSatisfy(isHash),
              !value.operationID.isEmpty, value.operationID.utf8.count <= 128,
              value.spoolDirectoryName.range(of: "^spool-[0-9a-f]{64}$", options: .regularExpression) != nil,
              value.spoolDevice > 0, value.spoolInode > 0 else {
            throw AgentPassNativeError.invalidSignature("Audit deletion intent binding is invalid")
        }
    }

    private static func decodeAuditDeletionBinding(_ raw: Any?) throws -> NativeAuditDeletionIntentBinding {
        let keys: Set<String> = ["bundle_sha256", "retained_segment_hash", "retained_identity_hash", "archive_path_chain_hash", "operation_id", "spool_manifest_hash", "spool_directory_name", "spool_device", "spool_inode"]
        guard let object = raw as? [String: Any], Set(object.keys) == keys,
              let bundle = object["bundle_sha256"] as? String,
              let segment = object["retained_segment_hash"] as? String,
              let identities = object["retained_identity_hash"] as? String,
              let pathChain = object["archive_path_chain_hash"] as? String,
              let operationID = object["operation_id"] as? String,
              let manifest = object["spool_manifest_hash"] as? String,
              let directory = object["spool_directory_name"] as? String,
              let device = int(object["spool_device"]), device > 0,
              let inode = int(object["spool_inode"]), inode > 0 else {
            throw AgentPassNativeError.invalidSignature("Audit deletion intent binding schema is invalid")
        }
        let value = NativeAuditDeletionIntentBinding(bundleSHA256: bundle, retainedSegmentHash: segment, retainedIdentityHash: identities, archivePathChainHash: pathChain, operationID: operationID, spoolManifestHash: manifest, spoolDirectoryName: directory, spoolDevice: UInt64(device), spoolInode: UInt64(inode))
        try validateAuditDeletionBinding(value)
        return value
    }

    public static func fingerprint(_ publicKey: Data) -> String {
        "SHA256:" + Data(SHA256.hash(data: publicKey)).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    private static func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    private static func isHash(_ value: String) -> Bool { value.count == 64 && value.allSatisfy { $0.isHexDigit && !$0.isUppercase } }

    private static func int(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        let result = number.intValue
        return number.stringValue == String(result) ? result : nil
    }

    private static func validatePublicKey(_ value: Data) throws {
        guard value.count == 65, value.first == 0x04, (try? P256.Signing.PublicKey(x963Representation: value)) != nil else { throw AgentPassNativeError.invalidKey("Lifecycle P-256 public key is invalid") }
    }

    private static func validateRecoveryPublicKey(_ value: Data) throws {
        guard value.count == 32, (try? Curve25519.Signing.PublicKey(rawRepresentation: value)) != nil else {
            throw AgentPassNativeError.invalidKey("Lifecycle Ed25519 recovery public key is invalid")
        }
    }

    private static func isValidRecoverySignature(_ signature: Data, message: Data, publicKey: Data) -> Bool {
        guard signature.count == 64, let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else { return false }
        return key.isValidSignature(signature, for: message)
    }

    private static func validateText(_ value: String, label: String, maximum: Int) throws {
        guard !value.isEmpty, !value.utf8.contains(0), value.utf8.count <= maximum else { throw AgentPassNativeError.invalidConfiguration("Lifecycle \(label) is invalid") }
    }

    private static func validateTimestamp(_ value: String) throws {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard formatter.date(from: value) != nil else { throw AgentPassNativeError.invalidConfiguration("Lifecycle timestamp must be fractional ISO-8601") }
    }

    private static func timestampDate(_ value: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: value)
    }

    private static func validateNotBefore(_ value: String, previous: String?) throws {
        guard let previous else { return }
        guard let date = timestampDate(value), let previousDate = timestampDate(previous), date >= previousDate else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle timestamp must not move backwards")
        }
    }

    private static func parseFilename(_ name: String) -> (sequence: Int, hash: String)? {
        let pattern = /^([0-9]{20})-([0-9a-f]{64})\.json$/
        guard let match = name.wholeMatch(of: pattern), let sequence = Int(match.1) else { return nil }
        return (sequence, String(match.2))
    }

    private static func parseTemporaryFilename(_ name: String) -> Bool {
        name.wholeMatch(of: /^\.lifecycle-[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\.tmp$/) != nil
    }

    private static func inspectTemporaryRecord(directory: String, name: String) throws -> (record: NativeKeyLifecycleRecord, linkCount: UInt16, device: Int32, inode: UInt64) {
        guard parseTemporaryFilename(name) else { throw AgentPassNativeError.invalidSignature("Lifecycle crash remnant filename is invalid") }
        let path = URL(fileURLWithPath: directory).appendingPathComponent(name).path
        var info = stat()
        guard lstat(path, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == geteuid(),
              info.st_mode & 0o777 == 0o400,
              (1...2).contains(info.st_nlink),
              info.st_size > 0, info.st_size <= 1_048_576 else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle crash remnant is not a private immutable record")
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: path), options: [.mappedIfSafe])
        let record = try decodeRecord(data)
        guard record.recordHash == hash(try recordData(record, includeHash: false)) else {
            throw AgentPassNativeError.invalidSignature("Lifecycle crash remnant hash is invalid")
        }
        return (record, info.st_nlink, info.st_dev, info.st_ino)
    }

    private static func removeRecoveredTemporary(directory: String, name: String) throws {
        let path = URL(fileURLWithPath: directory).appendingPathComponent(name).path
        guard unlink(path) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let descriptor = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { close(descriptor) }
        guard fsync(descriptor) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    }

    private static func validatePrivateDirectory(_ path: String) throws {
        var info = stat()
        guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR, info.st_uid == geteuid(), info.st_mode & 0o077 == 0 else { throw AgentPassNativeError.invalidConfiguration("Key lifecycle directory must be a private service-owned directory") }
    }

    private static func validatePrivateRecord(_ path: String) throws {
        var info = stat()
        guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == geteuid(), info.st_mode & 0o777 == 0o400, info.st_nlink == 1 else { throw AgentPassNativeError.invalidConfiguration("Key lifecycle record must be a private immutable regular file with one link") }
    }

    private static func atomicRecordWrite(directory: String, name: String, data: Data) throws {
        guard !data.isEmpty, data.count <= 1_048_576 else { throw AgentPassNativeError.invalidConfiguration("Key lifecycle record size is invalid") }
        let temporary = URL(fileURLWithPath: directory).appendingPathComponent(".lifecycle-\(UUID().uuidString).tmp").path
        let destination = URL(fileURLWithPath: directory).appendingPathComponent(name).path
        let descriptor = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        var shouldRemove = true
        defer { close(descriptor); if shouldRemove { unlink(temporary) } }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                guard count > 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
                offset += count
            }
        }
        guard fchmod(descriptor, 0o400) == 0, fsync(descriptor) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        guard link(temporary, destination) == 0 else { throw AgentPassNativeError.invalidSignature("Lifecycle record sequence/hash already exists or cannot be committed") }
        guard unlink(temporary) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        shouldRemove = false
        let directoryDescriptor = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard directoryDescriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { close(directoryDescriptor) }
        guard fsync(directoryDescriptor) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    }
}

private func lifecycleCanonical(_ object: [String: Any]) throws -> Data {
    guard JSONSerialization.isValidJSONObject(object) else { throw AgentPassNativeError.invalidSignature("Lifecycle object is not valid JSON") }
    return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
}
