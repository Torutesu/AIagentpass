import Darwin
import Foundation

/// Durable, locally verified evidence that the anchor accepted an audit-key transition.
///
/// Each JSONL record retains the exact canonical transition and receipt bytes together
/// with the retiring P-256 public key needed to re-verify the otherwise self-contained
/// dual-signature proof after restart. A separately fsync'd tip makes valid tail
/// truncation detectable. The JSONL append is committed before the tip is advanced, so
/// a lost response or crash can be recovered by replaying the one already-durable record.
public struct NativeAuditKeyTransitionStoreStatus: Codable, Equatable, Sendable {
    public let count: Int
    public let latestTransition: NativeAuditKeyTransition?
    public let latestRecoveryTransition: NativeAuditKeyRecoveryTransition?
    public let latestReceipt: NativeAuditKeyTransitionReceipt?
    public let latestEventIndex: Int?
    public let latestEventHash: String?

    enum CodingKeys: String, CodingKey {
        case count
        case latestTransition = "latest_transition"
        case latestRecoveryTransition = "latest_recovery_transition"
        case latestReceipt = "latest_receipt"
        case latestEventIndex = "latest_event_index"
        case latestEventHash = "latest_event_hash"
    }
}

/// Exact verified schema-v3 evidence retained by the transition store. This is
/// intentionally read-only and includes the bytes needed to cross-check the
/// separate recovery plan journal after restart.
public struct NativeAuditKeyRecoveryTransitionStoreEvidence: Equatable, Sendable {
    public let transition: NativeAuditKeyRecoveryTransition
    public let transitionData: Data
    public let receipt: NativeAuditKeyTransitionReceipt
    public let receiptData: Data
    public let retiringPublicKeyX963: Data
}

public final class NativeAuditKeyTransitionStore: @unchecked Sendable {
    public static let maximumLogBytes = 128 * 1024 * 1024
    private static let maximumRecordBytes = 256 * 1024
    private static let maximumTipBytes = 64 * 1024
    private static let zeroHash = String(repeating: "0", count: 64)

    private struct VerifiedRecord: Equatable {
        let transitionData: Data
        let receiptData: Data
        let retiringPublicKeyX963: Data
        let transition: NativeAuditKeyTransition?
        let recoveryTransition: NativeAuditKeyRecoveryTransition?
        let receipt: NativeAuditKeyTransitionReceipt
        let recordHash: String

        var version: Int { transition?.version ?? recoveryTransition!.version }
        var operationID: String { transition?.operationID ?? recoveryTransition!.operationID }
        var recoveryRequestID: String? { recoveryTransition?.recoveryRequestID }
        var fromGeneration: Int { transition?.fromGeneration ?? recoveryTransition!.fromGeneration }
        var toGeneration: Int { transition?.toGeneration ?? recoveryTransition!.toGeneration }
        var oldKeyFingerprint: String { transition?.oldKeyFingerprint ?? recoveryTransition!.oldKeyFingerprint }
        var newKeyFingerprint: String { transition?.newKeyFingerprint ?? recoveryTransition!.newKeyFingerprint }
        var newPublicKey: String { transition?.newPublicKey ?? recoveryTransition!.newPublicKey }
        var lifecycleHeadHash: String { transition?.lifecycleHeadHash ?? recoveryTransition!.lifecycleHeadHash }
        var createdAt: String { transition?.createdAt ?? recoveryTransition!.createdAt }
        var expiresAt: String? { recoveryTransition?.expiresAt }
        var transitionHash: String { transition?.transitionHash ?? recoveryTransition!.transitionHash }
        var previousTransitionHash: String { transition?.previousTransitionHash ?? recoveryTransition!.previousTransitionHash }
        var previousTransitionReceiptHash: String { transition?.previousTransitionReceiptHash ?? recoveryTransition!.previousTransitionReceiptHash }
        var lastCheckpointIndex: Int { transition?.lastCheckpointIndex ?? recoveryTransition!.lastCheckpointIndex }
        var previousAnchorEventIndex: Int { transition?.previousAnchorEventIndex ?? recoveryTransition!.previousAnchorEventIndex }
        var previousAnchorEventHash: String { transition?.previousAnchorEventHash ?? recoveryTransition!.previousAnchorEventHash }
    }

    private struct Tip: Codable, Equatable {
        let version: Int
        let tenant: String
        let count: Int
        let recordHash: String
        let transitionHash: String
        let receiptHash: String
        let eventIndex: Int
        let eventHash: String
        let generation: Int

        enum CodingKeys: String, CodingKey, CaseIterable {
            case version, tenant, count, generation
            case recordHash = "record_hash"
            case transitionHash = "transition_hash"
            case receiptHash = "receipt_hash"
            case eventIndex = "event_index"
            case eventHash = "event_hash"
        }
    }

    private let path: String
    private let parentPath: String
    private let fileName: String
    private let tipName: String
    private let tenant: String
    private let receiptVerifier: NativeAuditKeyTransitionReceiptVerifier
    private let recoveryReceiptVerifier: NativeAuditKeyRecoveryTransitionReceiptVerifier
    private let recoveryPolicy: NativeAuditKeyRecoveryPolicy?
    private let installationID: String?
    private let processLock = NSLock()
    private let beforeAppendValidation: (@Sendable () throws -> Void)?

    public convenience init(path: String, tenant: String, anchorPublicKeyPEM: String) throws {
        try self.init(path: path, tenant: tenant, anchorPublicKeyPEM: anchorPublicKeyPEM, recoveryPolicyData: nil, installationID: nil, testingBeforeAppendValidation: nil)
    }

    public convenience init(path: String, tenant: String, anchorPublicKeyPEM: String, recoveryPolicyData: Data, installationID: String) throws {
        try self.init(path: path, tenant: tenant, anchorPublicKeyPEM: anchorPublicKeyPEM, recoveryPolicyData: recoveryPolicyData, installationID: installationID, testingBeforeAppendValidation: nil)
    }

    init(
        path: String,
        tenant: String,
        anchorPublicKeyPEM: String,
        recoveryPolicyData: Data? = nil,
        installationID: String? = nil,
        testingBeforeAppendValidation: (@Sendable () throws -> Void)?
    ) throws {
        guard path.hasPrefix("/"), !path.hasSuffix("/"),
              tenant.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", options: .regularExpression) != nil else {
            throw AgentPassNativeError.invalidConfiguration("Native audit key transition store path or tenant is invalid")
        }
        let canonical = path
        let parent = URL(fileURLWithPath: canonical).deletingLastPathComponent().path
        let name = URL(fileURLWithPath: canonical).lastPathComponent
        guard !name.isEmpty, name != ".", name != "..", name.utf8.count <= Int(NAME_MAX) - 64 else {
            throw AgentPassNativeError.invalidConfiguration("Native audit key transition store file name is invalid")
        }
        self.path = canonical
        parentPath = parent
        fileName = name
        tipName = name + ".tip"
        self.tenant = tenant
        receiptVerifier = try NativeAuditKeyTransitionReceiptVerifier(tenant: tenant, anchorPublicKeyPEM: anchorPublicKeyPEM)
        recoveryReceiptVerifier = try NativeAuditKeyRecoveryTransitionReceiptVerifier(tenant: tenant, anchorPublicKeyPEM: anchorPublicKeyPEM)
        guard (recoveryPolicyData == nil) == (installationID == nil) else {
            throw AgentPassNativeError.invalidConfiguration("Recovery-enabled audit transition store requires both policy and installation ID")
        }
        recoveryPolicy = try recoveryPolicyData.map(NativeAuditKeyRecoveryPolicy.decodeCanonical)
        if let installationID, !NativeAuditKeyRecoveryTransitionStoreValidation.isSlug(installationID) {
            throw AgentPassNativeError.invalidConfiguration("Audit-key recovery installation ID is invalid")
        }
        self.installationID = installationID
        beforeAppendValidation = testingBeforeAppendValidation
        _ = try withLockedStore(createIfMissing: true) { records, _, _, parentDescriptor in
            try reconcileTip(records: records, parentDescriptor: parentDescriptor)
            return Self.makeStatus(records)
        }
    }

    public func status() throws -> NativeAuditKeyTransitionStoreStatus {
        processLock.lock()
        defer { processLock.unlock() }
        return try withLockedStore(createIfMissing: false) { records, _, _, parentDescriptor in
            try verifyTip(records: records, parentDescriptor: parentDescriptor)
            return Self.makeStatus(records)
        }
    }

    public func verifiedRecoveryHistory() throws -> [NativeAuditKeyRecoveryTransitionStoreEvidence] {
        processLock.lock()
        defer { processLock.unlock() }
        return try withLockedStore(createIfMissing: false) { records, _, _, parentDescriptor in
            try verifyTip(records: records, parentDescriptor: parentDescriptor)
            return records.compactMap { record in
                guard let transition = record.recoveryTransition else { return nil }
                return NativeAuditKeyRecoveryTransitionStoreEvidence(
                    transition: transition,
                    transitionData: record.transitionData,
                    receipt: record.receipt,
                    receiptData: record.receiptData,
                    retiringPublicKeyX963: record.retiringPublicKeyX963
                )
            }
        }
    }

    /// Verifies and durably stores one exact transition/receipt pair.
    ///
    /// `retiringPublicKeyX963` is mandatory for the first locally retained transition,
    /// because the v2 transition wire artifact intentionally carries only the replacement
    /// key. For later transitions the previous replacement key is authoritative; a supplied
    /// value must match it exactly.
    @discardableResult
    public func accept(
        transitionData: Data,
        receiptData: Data,
        retiringPublicKeyX963 suppliedRetiringKey: Data? = nil
    ) throws -> NativeAuditKeyTransitionStoreStatus {
        processLock.lock()
        defer { processLock.unlock() }
        return try withLockedStore(createIfMissing: false) { records, logDescriptor, tipDescriptor, parentDescriptor in
            try verifyTip(records: records, parentDescriptor: parentDescriptor)

            if let exact = records.first(where: { $0.transitionData == transitionData && $0.receiptData == receiptData }) {
                if let suppliedRetiringKey, suppliedRetiringKey != exact.retiringPublicKeyX963 {
                    throw AgentPassNativeError.invalidKey("Native audit key transition replay used a different retiring key")
                }
                return Self.makeStatus(records)
            }

            let expectedRetiringKey: Data
            if let previous = records.last {
                expectedRetiringKey = try SSHSIG.p256PublicKey(fromAuthorizedKey: previous.newPublicKey)
                if let suppliedRetiringKey, suppliedRetiringKey != expectedRetiringKey {
                    throw AgentPassNativeError.invalidKey("Native audit key transition retiring key does not continue the stored key chain")
                }
            } else {
                guard let suppliedRetiringKey else {
                    throw AgentPassNativeError.invalidKey("The first native audit key transition requires its retiring public key")
                }
                expectedRetiringKey = suppliedRetiringKey
            }

            let candidate = try verifyRecord(
                transitionData: transitionData,
                receiptData: receiptData,
                retiringPublicKeyX963: expectedRetiringKey,
                previous: records.last
            )
            if records.contains(where: {
                $0.operationID == candidate.operationID ||
                ($0.recoveryRequestID != nil && $0.recoveryRequestID == candidate.recoveryRequestID) ||
                $0.receipt.index == candidate.receipt.index ||
                $0.oldKeyFingerprint == candidate.newKeyFingerprint ||
                $0.newKeyFingerprint == candidate.newKeyFingerprint
            }) {
                throw AgentPassNativeError.invalidSignature("Native audit key transition equivocation was detected")
            }

            let encoded = try encodeRecord(candidate, previousRecordHash: records.last?.recordHash ?? Self.zeroHash)
            guard encoded.count <= Self.maximumRecordBytes else {
                throw AgentPassNativeError.invalidConfiguration("Native audit key transition evidence record is too large")
            }
            var logInfo = stat()
            guard fstat(logDescriptor, &logInfo) == 0,
                  logInfo.st_size >= 0,
                  logInfo.st_size <= Self.maximumLogBytes,
                  Int64(encoded.count) <= Int64(Self.maximumLogBytes) - logInfo.st_size else {
                throw AgentPassNativeError.invalidConfiguration("Native audit key transition evidence exceeds the 128 MiB verification limit")
            }

            try beforeAppendValidation?()
            try validateDescriptor(logDescriptor, parentDescriptor: parentDescriptor, name: fileName, expectedMode: 0o600, label: "Native audit key transition log")
            try validateDescriptor(tipDescriptor, parentDescriptor: parentDescriptor, name: tipName, expectedMode: 0o600, label: "Native audit key transition tip")
            try writeAll(logDescriptor, encoded)
            guard fsync(logDescriptor) == 0 else { throw Self.posixError() }
            try validateDescriptor(logDescriptor, parentDescriptor: parentDescriptor, name: fileName, expectedMode: 0o600, label: "Native audit key transition log")

            let committed = records + [candidate]
            try writeTip(makeTip(committed), parentDescriptor: parentDescriptor)
            guard fsync(parentDescriptor) == 0 else { throw Self.posixError() }
            return Self.makeStatus(committed)
        }
    }

    private func withLockedStore<T>(
        createIfMissing: Bool,
        _ body: ([VerifiedRecord], Int32, Int32, Int32) throws -> T
    ) throws -> T {
        let parentDescriptor = try openProtectedParent()
        defer { close(parentDescriptor) }
        guard flock(parentDescriptor, LOCK_EX) == 0 else { throw Self.posixError() }
        defer { flock(parentDescriptor, LOCK_UN) }

        let logDescriptor = try openStoreFile(parentDescriptor: parentDescriptor, name: fileName, create: createIfMissing, label: "Native audit key transition log")
        defer { close(logDescriptor) }
        let tipDescriptor = try openStoreFile(parentDescriptor: parentDescriptor, name: tipName, create: createIfMissing, label: "Native audit key transition tip")
        defer { close(tipDescriptor) }
        guard flock(logDescriptor, LOCK_EX) == 0 else { throw Self.posixError() }
        defer { flock(logDescriptor, LOCK_UN) }

        let logData = try readAll(logDescriptor, maximumBytes: Self.maximumLogBytes, label: "Native audit key transition log")
        let records = try decodeAndVerifyRecords(logData)
        _ = try readAll(tipDescriptor, maximumBytes: Self.maximumTipBytes, label: "Native audit key transition tip")
        return try body(records, logDescriptor, tipDescriptor, parentDescriptor)
    }

    private func openProtectedParent() throws -> Int32 {
        guard let resolved = Darwin.realpath(parentPath, nil) else { throw Self.posixError() }
        defer { free(resolved) }
        guard String(cString: resolved) == parentPath else {
            throw AgentPassNativeError.invalidConfiguration("Native audit key transition store parent must not traverse symbolic links")
        }
        let descriptor = open(parentPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw Self.posixError() }
        do {
            var info = stat()
            guard fstat(descriptor, &info) == 0,
                  (info.st_mode & S_IFMT) == S_IFDIR,
                  info.st_uid == geteuid(),
                  info.st_mode & 0o777 == 0o700 else {
                throw AgentPassNativeError.invalidConfiguration("Native audit key transition store parent must be an owner-only 0700 directory")
            }
            return descriptor
        } catch {
            close(descriptor)
            throw error
        }
    }

    private func openStoreFile(parentDescriptor: Int32, name: String, create: Bool, label: String) throws -> Int32 {
        var flags = O_RDWR | O_APPEND | O_NOFOLLOW | O_CLOEXEC
        if create { flags |= O_CREAT }
        let descriptor = openat(parentDescriptor, name, flags, 0o600)
        guard descriptor >= 0 else { throw Self.posixError() }
        do {
            try validateDescriptor(descriptor, parentDescriptor: parentDescriptor, name: name, expectedMode: 0o600, label: label)
            return descriptor
        } catch {
            close(descriptor)
            throw error
        }
    }

    private func validateDescriptor(_ descriptor: Int32, parentDescriptor: Int32, name: String, expectedMode: mode_t, label: String) throws {
        var descriptorInfo = stat()
        var pathInfo = stat()
        guard fstat(descriptor, &descriptorInfo) == 0,
              fstatat(parentDescriptor, name, &pathInfo, AT_SYMLINK_NOFOLLOW) == 0,
              (descriptorInfo.st_mode & S_IFMT) == S_IFREG,
              (pathInfo.st_mode & S_IFMT) == S_IFREG,
              descriptorInfo.st_uid == geteuid(), pathInfo.st_uid == geteuid(),
              descriptorInfo.st_mode & 0o777 == expectedMode,
              pathInfo.st_mode & 0o777 == expectedMode,
              descriptorInfo.st_nlink == 1, pathInfo.st_nlink == 1,
              descriptorInfo.st_dev == pathInfo.st_dev,
              descriptorInfo.st_ino == pathInfo.st_ino else {
            throw AgentPassNativeError.invalidConfiguration("\(label) must remain the same owner-only regular file with one link")
        }
    }

    private func readAll(_ descriptor: Int32, maximumBytes: Int, label: String) throws -> Data {
        var before = stat()
        guard fstat(descriptor, &before) == 0, before.st_size >= 0, before.st_size <= maximumBytes else {
            throw AgentPassNativeError.invalidConfiguration("\(label) exceeds its verification limit")
        }
        var result = Data(count: Int(before.st_size))
        let total = try result.withUnsafeMutableBytes { bytes -> Int in
            var offset = 0
            while offset < bytes.count {
                let count = pread(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset, off_t(offset))
                guard count >= 0 else { throw Self.posixError() }
                guard count > 0 else { break }
                offset += count
            }
            return offset
        }
        guard total == result.count else {
            throw AgentPassNativeError.invalidSignature("\(label) changed while it was read")
        }
        var after = stat()
        guard fstat(descriptor, &after) == 0,
              before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_size == after.st_size, before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec else {
            throw AgentPassNativeError.invalidSignature("\(label) changed while it was read")
        }
        return result
    }

    private func decodeAndVerifyRecords(_ data: Data) throws -> [VerifiedRecord] {
        guard data.isEmpty || (data.last == 0x0a && data.range(of: Data("\n\n".utf8)) == nil) else {
            throw AgentPassNativeError.invalidSignature("Native audit key transition log is truncated or has invalid framing")
        }
        if data.isEmpty { return [] }
        var records: [VerifiedRecord] = []
        var expectedPreviousRecordHash = Self.zeroHash
        for line in data.dropLast().split(separator: 0x0a, omittingEmptySubsequences: false) {
            guard !line.isEmpty, line.count <= Self.maximumRecordBytes else {
                throw AgentPassNativeError.invalidSignature("Native audit key transition log record framing is invalid")
            }
            let lineData = Data(line)
            guard let object = try JSONSerialization.jsonObject(with: lineData) as? [String: Any],
                  Set(object.keys) == Set(["version", "tenant", "index", "retiring_public_key", "transition", "receipt", "previous_record_hash", "record_hash"]),
                  Self.integer(object["version"]) == 1,
                  object["tenant"] as? String == tenant,
                  let index = Self.integer(object["index"]), index == records.count + 1,
                  let retiringEncoded = object["retiring_public_key"] as? String,
                  let transitionEncoded = object["transition"] as? String,
                  let receiptEncoded = object["receipt"] as? String,
                  let previousRecordHash = object["previous_record_hash"] as? String,
                  previousRecordHash == expectedPreviousRecordHash,
                  let recordHash = object["record_hash"] as? String,
                  let retiring = Self.canonicalBase64(retiringEncoded),
                  let transitionData = Self.canonicalBase64(transitionEncoded),
                  let receiptData = Self.canonicalBase64(receiptEncoded) else {
                throw AgentPassNativeError.invalidSignature("Native audit key transition log schema is invalid")
            }
            var unhashed = object
            unhashed.removeValue(forKey: "record_hash")
            guard recordHash == NativeAuditLog.hash(try NativeAuditLog.canonical(unhashed)),
                  try NativeAuditLog.canonical(object) == lineData else {
                throw AgentPassNativeError.invalidSignature("Native audit key transition log record is noncanonical or has an invalid hash")
            }
            let record = try verifyRecord(
                transitionData: transitionData,
                receiptData: receiptData,
                retiringPublicKeyX963: retiring,
                previous: records.last
            )
            guard record.recordHash == recordHash else {
                throw AgentPassNativeError.invalidSignature("Native audit key transition log record hash is invalid")
            }
            guard !records.contains(where: {
                $0.operationID == record.operationID ||
                ($0.recoveryRequestID != nil && $0.recoveryRequestID == record.recoveryRequestID) ||
                $0.oldKeyFingerprint == record.newKeyFingerprint ||
                $0.newKeyFingerprint == record.newKeyFingerprint
            }) else {
                throw AgentPassNativeError.invalidSignature("Native audit key transition history contains equivocation or key reuse")
            }
            records.append(record)
            expectedPreviousRecordHash = recordHash
        }
        return records
    }

    private func verifyRecord(
        transitionData: Data,
        receiptData: Data,
        retiringPublicKeyX963: Data,
        previous: VerifiedRecord?
    ) throws -> VerifiedRecord {
        guard let raw = try JSONSerialization.jsonObject(with: transitionData) as? [String: Any],
              let version = Self.integer(raw["version"]) else {
            throw AgentPassNativeError.invalidSignature("Native audit key transition version is invalid")
        }
        let transition: NativeAuditKeyTransition?
        let recoveryTransition: NativeAuditKeyRecoveryTransition?
        switch version {
        case 2:
            transition = try NativeAuditKeyTransition.decodeCanonical(transitionData, retiringPublicKeyX963: retiringPublicKeyX963)
            recoveryTransition = nil
        case 3:
            guard let recoveryPolicy, let installationID else {
                throw AgentPassNativeError.invalidConfiguration("Audit-key recovery transition store has no pinned recovery trust")
            }
            let recovered = try NativeAuditKeyRecoveryTransition.decodeCanonical(
                transitionData,
                pinnedPolicy: recoveryPolicy,
                expectedInstallationID: installationID
            )
            guard recovered.oldKeyFingerprint == NativeAuditCheckpoints.fingerprint(retiringPublicKeyX963) else {
                throw AgentPassNativeError.invalidKey("Audit-key recovery transition does not continue the retiring key identity")
            }
            transition = nil
            recoveryTransition = recovered
        default:
            throw AgentPassNativeError.invalidSignature("Native audit key transition version is unsupported")
        }
        let transitionTenant = transition?.tenant ?? recoveryTransition!.tenant
        guard transitionTenant == tenant else {
            throw AgentPassNativeError.invalidSignature("Native audit key transition tenant does not match the store")
        }
        let expectedIndex = (previous?.receipt.index ?? 0) + 1
        let receipt = if let transition {
            try receiptVerifier.verify(receiptData: receiptData, transition: transition, expectedTransitionIndex: expectedIndex)
        } else {
            try recoveryReceiptVerifier.verify(receiptData: receiptData, transition: recoveryTransition!, expectedTransitionIndex: expectedIndex)
        }
        if let previous {
            let expectedRetiringKey = try SSHSIG.p256PublicKey(fromAuthorizedKey: previous.newPublicKey)
            let candidateFrom = transition?.fromGeneration ?? recoveryTransition!.fromGeneration
            let candidateTo = transition?.toGeneration ?? recoveryTransition!.toGeneration
            let candidateOldFingerprint = transition?.oldKeyFingerprint ?? recoveryTransition!.oldKeyFingerprint
            let candidatePreviousHash = transition?.previousTransitionHash ?? recoveryTransition!.previousTransitionHash
            let candidatePreviousReceipt = transition?.previousTransitionReceiptHash ?? recoveryTransition!.previousTransitionReceiptHash
            let candidateEventIndex = transition?.previousAnchorEventIndex ?? recoveryTransition!.previousAnchorEventIndex
            let candidateEventHash = transition?.previousAnchorEventHash ?? recoveryTransition!.previousAnchorEventHash
            let candidateCheckpoint = transition?.lastCheckpointIndex ?? recoveryTransition!.lastCheckpointIndex
            let candidateCreatedAt = transition?.createdAt ?? recoveryTransition!.createdAt
            guard retiringPublicKeyX963 == expectedRetiringKey,
                  candidateFrom == previous.toGeneration,
                  candidateTo == previous.toGeneration + 1,
                  candidateOldFingerprint == previous.newKeyFingerprint,
                  candidatePreviousHash == previous.transitionHash,
                  candidatePreviousReceipt == previous.receipt.receiptHash,
                  candidateEventIndex > previous.receipt.eventIndex,
                  candidateEventHash != Self.zeroHash,
                  candidateCheckpoint > previous.lastCheckpointIndex,
                  receipt.eventIndex > previous.receipt.eventIndex,
                  Self.date(candidateCreatedAt) > Self.date(previous.createdAt),
                  Self.date(candidateCreatedAt) >= Self.date(previous.receipt.receivedAt),
                  Self.date(receipt.receivedAt) >= Self.date(previous.receipt.receivedAt) else {
                throw AgentPassNativeError.invalidSignature("Native audit key transition chain continuity is invalid")
            }
        } else {
            let previousHash = transition?.previousTransitionHash ?? recoveryTransition!.previousTransitionHash
            let previousReceipt = transition?.previousTransitionReceiptHash ?? recoveryTransition!.previousTransitionReceiptHash
            guard previousHash == Self.zeroHash, previousReceipt == Self.zeroHash else {
                throw AgentPassNativeError.invalidSignature("The first native audit key transition must begin at the transition-chain origin")
            }
        }
        let provisional = VerifiedRecord(
            transitionData: transitionData,
            receiptData: receiptData,
            retiringPublicKeyX963: retiringPublicKeyX963,
            transition: transition,
            recoveryTransition: recoveryTransition,
            receipt: receipt,
            recordHash: ""
        )
        let hash = try recordHash(provisional, previousRecordHash: previous?.recordHash ?? Self.zeroHash)
        return VerifiedRecord(
            transitionData: transitionData,
            receiptData: receiptData,
            retiringPublicKeyX963: retiringPublicKeyX963,
            transition: transition,
            recoveryTransition: recoveryTransition,
            receipt: receipt,
            recordHash: hash
        )
    }

    private func encodeRecord(_ record: VerifiedRecord, previousRecordHash: String) throws -> Data {
        var object = recordObject(record, previousRecordHash: previousRecordHash)
        object["record_hash"] = record.recordHash
        return try NativeAuditLog.canonical(object) + Data([0x0a])
    }

    private func recordHash(_ record: VerifiedRecord, previousRecordHash: String) throws -> String {
        NativeAuditLog.hash(try NativeAuditLog.canonical(recordObject(record, previousRecordHash: previousRecordHash)))
    }

    private func recordObject(_ record: VerifiedRecord, previousRecordHash: String) -> [String: Any] {
        [
            "version": 1,
            "tenant": tenant,
            "index": record.receipt.index,
            "retiring_public_key": record.retiringPublicKeyX963.base64EncodedString(),
            "transition": record.transitionData.base64EncodedString(),
            "receipt": record.receiptData.base64EncodedString(),
            "previous_record_hash": previousRecordHash
        ]
    }

    private func reconcileTip(records: [VerifiedRecord], parentDescriptor: Int32) throws {
        let tipData = try readNamedFile(parentDescriptor: parentDescriptor, name: tipName, maximumBytes: Self.maximumTipBytes, label: "Native audit key transition tip")
        if tipData.isEmpty {
            guard records.isEmpty else {
                // The only safe recovery is an append committed after an already-existing
                // empty tip. A missing/empty tip with evidence cannot distinguish deletion.
                throw AgentPassNativeError.invalidSignature("Native audit key transition tip is missing; truncation cannot be excluded")
            }
            try writeTip(makeTip(records), parentDescriptor: parentDescriptor)
            return
        }
        let tip = try decodeTip(tipData)
        if tip == makeTip(records) { return }
        guard records.count == tip.count + 1,
              tip == makeTip(Array(records.dropLast())) else {
            throw AgentPassNativeError.invalidSignature("Native audit key transition log was truncated or diverged from its durable tip")
        }
        try writeTip(makeTip(records), parentDescriptor: parentDescriptor)
    }

    private func verifyTip(records: [VerifiedRecord], parentDescriptor: Int32) throws {
        let data = try readNamedFile(parentDescriptor: parentDescriptor, name: tipName, maximumBytes: Self.maximumTipBytes, label: "Native audit key transition tip")
        guard !data.isEmpty, try decodeTip(data) == makeTip(records) else {
            throw AgentPassNativeError.invalidSignature("Native audit key transition log was truncated or diverged from its durable tip")
        }
    }

    private func decodeTip(_ data: Data) throws -> Tip {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set(Tip.CodingKeys.allCases.map(\.stringValue)) else {
            throw AgentPassNativeError.invalidSignature("Native audit key transition tip schema is invalid")
        }
        let tip = try JSONDecoder().decode(Tip.self, from: data)
        guard tip.version == 1, tip.tenant == tenant, tip.count >= 0,
              try NativeAuditLog.canonical(object) == data else {
            throw AgentPassNativeError.invalidSignature("Native audit key transition tip is invalid or noncanonical")
        }
        return tip
    }

    private func readNamedFile(parentDescriptor: Int32, name: String, maximumBytes: Int, label: String) throws -> Data {
        let descriptor = openat(parentDescriptor, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw Self.posixError() }
        defer { close(descriptor) }
        try validateDescriptor(descriptor, parentDescriptor: parentDescriptor, name: name, expectedMode: 0o600, label: label)
        return try readAll(descriptor, maximumBytes: maximumBytes, label: label)
    }

    private func writeTip(_ tip: Tip, parentDescriptor: Int32) throws {
        let data = try NativeAuditLog.canonical(try Self.jsonObject(tip))
        guard data.count <= Self.maximumTipBytes else {
            throw AgentPassNativeError.invalidConfiguration("Native audit key transition tip is too large")
        }
        let temporary = ".\(tipName).\(UUID().uuidString).tmp"
        let descriptor = openat(parentDescriptor, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw Self.posixError() }
        var renamed = false
        defer {
            close(descriptor)
            if !renamed { unlinkat(parentDescriptor, temporary, 0) }
        }
        try writeAll(descriptor, data)
        guard fchmod(descriptor, 0o600) == 0, fsync(descriptor) == 0 else { throw Self.posixError() }
        try validateDescriptor(descriptor, parentDescriptor: parentDescriptor, name: temporary, expectedMode: 0o600, label: "Native audit key transition temporary tip")
        guard renameat(parentDescriptor, temporary, parentDescriptor, tipName) == 0 else { throw Self.posixError() }
        renamed = true
        guard fsync(parentDescriptor) == 0 else { throw Self.posixError() }
    }

    private func writeAll(_ descriptor: Int32, _ data: Data) throws {
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                guard count > 0 else { throw Self.posixError() }
                offset += count
            }
        }
    }

    private static func makeStatus(_ records: [VerifiedRecord]) -> NativeAuditKeyTransitionStoreStatus {
        NativeAuditKeyTransitionStoreStatus(
            count: records.count,
            latestTransition: records.last?.transition,
            latestRecoveryTransition: records.last?.recoveryTransition,
            latestReceipt: records.last?.receipt,
            latestEventIndex: records.last?.receipt.eventIndex,
            latestEventHash: records.last?.receipt.receiptHash
        )
    }

    private func makeTip(_ records: [VerifiedRecord]) -> Tip {
        let latest = records.last
        return Tip(
            version: 1,
            tenant: tenant,
            count: records.count,
            recordHash: latest?.recordHash ?? Self.zeroHash,
            transitionHash: latest?.transitionHash ?? Self.zeroHash,
            receiptHash: latest?.receipt.receiptHash ?? Self.zeroHash,
            eventIndex: latest?.receipt.eventIndex ?? 0,
            eventHash: latest?.receipt.receiptHash ?? Self.zeroHash,
            generation: latest?.toGeneration ?? 0
        )
    }

    private static func canonicalBase64(_ value: String) -> Data? {
        guard value.utf8.count <= maximumRecordBytes * 2,
              let data = Data(base64Encoded: value),
              data.base64EncodedString() == value else { return nil }
        return data
    }

    private static func integer(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        let result = number.int64Value
        guard result >= Int64(Int.min), result <= Int64(Int.max),
              NSNumber(value: result) == number else { return nil }
        return Int(result)
    }

    private static func date(_ value: String) -> Date {
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = fractional.date(from: value) { return date }
        return ISO8601DateFormatter().date(from: value) ?? .distantPast
    }

    private static func jsonObject<T: Encodable>(_ value: T) throws -> [String: Any] {
        guard let object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) as? [String: Any] else {
            throw AgentPassNativeError.invalidConfiguration("Native audit key transition tip cannot be encoded")
        }
        return object
    }

    private static func posixError() -> POSIXError {
        POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
}
