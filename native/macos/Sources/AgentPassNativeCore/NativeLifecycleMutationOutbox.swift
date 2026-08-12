import CryptoKit
import Darwin
import Foundation

/// The complete set of lifecycle ledger mutations which must be replayable after a crash.
public enum NativeLifecycleMutationKind: String, CaseIterable, Sendable {
    case staged
    case activated
    case recoveredActivation = "recovered_activation"
    case abortIntent = "abort_intent"
    case aborted
    case deletionIntent = "deletion_intent"
    case deleted
}

public enum NativeLifecycleMutationOutboxCrashPoint: Sendable {
    case afterPrepareTemporaryFileSync
    case afterPrepareRename
    case afterCompletedTemporaryFileSync
    case afterCompletedRename
}

/// A byte-exact lifecycle mutation retained before either the external pin or ledger changes.
/// `payload` is deliberately opaque: replay must submit these exact bytes, never reconstruct it.
public struct NativeLifecycleMutationPreparation: Equatable, Sendable {
    public let operationID: UUID
    public let pinSequence: Int
    public let role: NativeKeyRole
    public let kind: NativeLifecycleMutationKind
    public let lifecycleSequence: Int
    public let oldLifecycleHead: String
    public let newLifecycleHead: String
    public let createdAt: String
    public let payload: Data

    public init(operationID: UUID, pinSequence: Int, role: NativeKeyRole, kind: NativeLifecycleMutationKind, lifecycleSequence: Int, oldLifecycleHead: String, newLifecycleHead: String, createdAt: String, payload: Data) {
        self.operationID = operationID
        self.pinSequence = pinSequence
        self.role = role
        self.kind = kind
        self.lifecycleSequence = lifecycleSequence
        self.oldLifecycleHead = oldLifecycleHead
        self.newLifecycleHead = newLifecycleHead
        self.createdAt = createdAt
        self.payload = payload
    }

    public var payloadHash: String { Self.hash(payload) }

    public func canonicalData() throws -> Data {
        try NativeLifecycleMutationOutbox.canonicalRecord(self, recordKind: "prepare")
    }

    private static func hash(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

/// Immutable write-ahead storage for lifecycle mutation bytes. The filesystem layout has no
/// mutable pointer: contiguous `completed` records define history and at most one subsequent
/// `prepare` record is pending. Every read validates the entire chain before returning data.
public final class NativeLifecycleMutationOutbox: @unchecked Sendable {
    public static let maximumPayloadBytes = 1_048_576
    private static let maximumRecordBytes = 1_500_000

    private let rootPath: String
    private let rootDescriptor: Int32
    private let rootDevice: dev_t
    private let rootInode: ino_t
    private let fault: @Sendable (NativeLifecycleMutationOutboxCrashPoint) throws -> Void
    private let processLock = NSLock()

    public init(rootPath: String, faultInjector: @escaping @Sendable (NativeLifecycleMutationOutboxCrashPoint) throws -> Void = { _ in }) throws {
        guard rootPath.hasPrefix("/") else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle mutation outbox root must be absolute")
        }
        let standardized = URL(fileURLWithPath: rootPath).standardizedFileURL.path
        let canonical = try Self.realPath(standardized)
        guard standardized == canonical else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle mutation outbox root and every ancestor must not be a symbolic link")
        }
        try Self.validateProtectedAncestors(canonical)
        var supplied = stat()
        guard lstat(canonical, &supplied) == 0, (supplied.st_mode & S_IFMT) == S_IFDIR else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle mutation outbox root must be an existing directory")
        }
        let descriptor = open(canonical, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw Self.posixError() }
        var info = stat()
        guard fstat(descriptor, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == geteuid(),
              info.st_mode & 0o077 == 0 else {
            close(descriptor)
            throw AgentPassNativeError.invalidConfiguration("Lifecycle mutation outbox root must be a private service-owned directory")
        }
        self.rootPath = canonical
        rootDescriptor = descriptor
        rootDevice = info.st_dev
        rootInode = info.st_ino
        fault = faultInjector
        do {
            try withExclusiveLock {
                try recoverTemporaryFiles()
                _ = try readState()
            }
        } catch {
            close(descriptor)
            throw error
        }
    }

    deinit { close(rootDescriptor) }

    /// Persists the only acceptable next mutation and its exact replay bytes.
    @discardableResult
    public func prepare(
        operationID: UUID,
        pinSequence: Int,
        role: NativeKeyRole,
        kind: NativeLifecycleMutationKind,
        lifecycleSequence: Int,
        oldLifecycleHead: String,
        newLifecycleHead: String,
        createdAt: String,
        payload: Data
    ) throws -> NativeLifecycleMutationPreparation {
        let candidate = NativeLifecycleMutationPreparation(
            operationID: operationID,
            pinSequence: pinSequence,
            role: role,
            kind: kind,
            lifecycleSequence: lifecycleSequence,
            oldLifecycleHead: oldLifecycleHead,
            newLifecycleHead: newLifecycleHead,
            createdAt: createdAt,
            payload: payload
        )
        try Self.validate(candidate)
        return try withExclusiveLock {
            try recoverTemporaryFiles()
            let state = try readState()
            if let completed = state.completedBySequence[pinSequence] {
                guard let existing = state.preparations[pinSequence], existing == candidate,
                      completed == candidate else {
                    throw AgentPassNativeError.invalidSignature("Lifecycle mutation replay conflicts with completed history")
                }
                return existing
            }
            guard state.nextSequence == nil || pinSequence == state.nextSequence else {
                throw AgentPassNativeError.invalidSignature("Lifecycle mutation pin sequence is stale or has a gap")
            }
            if let previous = state.completed.last {
                guard candidate.oldLifecycleHead == previous.newLifecycleHead,
                      candidate.lifecycleSequence == previous.lifecycleSequence + 1 else {
                    throw AgentPassNativeError.invalidSignature("Lifecycle mutation does not extend the completed ledger sequence")
                }
                guard Self.timestampDate(candidate.createdAt)! >= Self.timestampDate(previous.createdAt)! else {
                    throw AgentPassNativeError.invalidSignature("Lifecycle mutation time must not move backwards")
                }
            }
            if let pending = state.pending {
                guard pending == candidate else {
                    throw AgentPassNativeError.invalidSignature("A different lifecycle mutation is already pending")
                }
                return pending
            }
            guard !state.preparations.values.contains(where: { $0.operationID == candidate.operationID }) else {
                throw AgentPassNativeError.invalidSignature("Lifecycle mutation operation UUID reuse is forbidden")
            }
            let data = try Self.canonicalRecord(candidate, recordKind: "prepare")
            try writeImmutable(
                name: Self.prepareName(candidate),
                data: data,
                temporaryPoint: .afterPrepareTemporaryFileSync,
                renamedPoint: .afterPrepareRename
            )
            return candidate
        }
    }

    /// Marks an operation complete only after the caller observes the exact prepared new head.
    /// Repeating an exact completion is idempotent; no generic "complete latest" API exists.
    @discardableResult
    public func complete(_ preparation: NativeLifecycleMutationPreparation, observedNewLifecycleHead: String) throws -> NativeLifecycleMutationPreparation {
        try Self.validate(preparation)
        guard observedNewLifecycleHead == preparation.newLifecycleHead else {
            throw AgentPassNativeError.invalidSignature("Observed lifecycle head does not match the prepared mutation")
        }
        return try withExclusiveLock {
            try recoverTemporaryFiles()
            let state = try readState()
            guard state.preparations[preparation.pinSequence] == preparation else {
                throw AgentPassNativeError.invalidSignature("Lifecycle mutation completion has no exact prepared payload")
            }
            if let completed = state.completedBySequence[preparation.pinSequence] {
                guard completed == preparation else {
                    throw AgentPassNativeError.invalidSignature("Lifecycle mutation completion equivocates with history")
                }
                return preparation
            }
            guard state.nextSequence == preparation.pinSequence,
                  state.pending == preparation,
                  state.completed.last?.newLifecycleHead == preparation.oldLifecycleHead || state.completed.isEmpty else {
                throw AgentPassNativeError.invalidSignature("Lifecycle mutation completion is stale or non-contiguous")
            }
            try writeImmutable(
                name: Self.completedName(preparation.pinSequence),
                data: Self.canonicalRecord(preparation, recordKind: "completed"),
                temporaryPoint: .afterCompletedTemporaryFileSync,
                renamedPoint: .afterCompletedRename
            )
            return preparation
        }
    }

    /// Returns the sole unresolved operation, including byte-for-byte replay payload.
    public func pending() throws -> NativeLifecycleMutationPreparation? {
        try withExclusiveLock {
            try recoverTemporaryFiles()
            return try readState().pending
        }
    }

    public func current() throws -> NativeLifecycleMutationPreparation? {
        try withExclusiveLock {
            try recoverTemporaryFiles()
            return try readState().completed.last
        }
    }

    private struct DiskState {
        let preparations: [Int: NativeLifecycleMutationPreparation]
        let completed: [NativeLifecycleMutationPreparation]
        let completedBySequence: [Int: NativeLifecycleMutationPreparation]
        let nextSequence: Int?
        let pending: NativeLifecycleMutationPreparation?
    }

    private func readState() throws -> DiskState {
        try validateRootIdentity()
        let names = try directoryNames()
        try validateRootIdentity()
        var preparations: [Int: NativeLifecycleMutationPreparation] = [:]
        var completions: [Int: NativeLifecycleMutationPreparation] = [:]
        for name in names {
            if let parsed = Self.parsePrepareName(name) {
                let decoded = try readRecord(name: name, expectedRecordKind: "prepare")
                guard decoded.pinSequence == parsed.sequence, decoded.operationID == parsed.operationID,
                      preparations.updateValue(decoded, forKey: parsed.sequence) == nil else {
                    throw AgentPassNativeError.invalidSignature("Lifecycle mutation prepare filename is inconsistent")
                }
            } else if let sequence = Self.parseCompletedName(name) {
                let decoded = try readRecord(name: name, expectedRecordKind: "completed")
                guard decoded.pinSequence == sequence,
                      completions.updateValue(decoded, forKey: sequence) == nil else {
                    throw AgentPassNativeError.invalidSignature("Lifecycle mutation completion filename is inconsistent")
                }
            } else if Self.isTemporaryName(name) {
                throw AgentPassNativeError.invalidSignature("Unrecovered lifecycle mutation temporary file remains")
            } else {
                throw AgentPassNativeError.invalidSignature("Lifecycle mutation outbox contains an unknown entry")
            }
        }
        if preparations.isEmpty, completions.isEmpty {
            return DiskState(preparations: [:], completed: [], completedBySequence: [:], nextSequence: nil, pending: nil)
        }
        var completed: [NativeLifecycleMutationPreparation] = []
        if !completions.isEmpty {
            let first = completions.keys.min()!
            let last = completions.keys.max()!
            guard last - first + 1 == completions.count else {
                throw AgentPassNativeError.invalidSignature("Lifecycle mutation completion history has a sequence gap")
            }
            for sequence in first...last {
                guard let completion = completions[sequence], let preparation = preparations[sequence], completion == preparation else {
                    throw AgentPassNativeError.invalidSignature("Lifecycle mutation history has a gap or mismatched completion")
                }
                if let previous = completed.last {
                    guard completion.oldLifecycleHead == previous.newLifecycleHead,
                          completion.lifecycleSequence == previous.lifecycleSequence + 1 else {
                        throw AgentPassNativeError.invalidSignature("Lifecycle mutation history has a head or ledger sequence gap")
                    }
                    guard Self.timestampDate(completion.createdAt)! >= Self.timestampDate(previous.createdAt)! else {
                        throw AgentPassNativeError.invalidSignature("Lifecycle mutation history time moved backwards")
                    }
                }
                completed.append(completion)
            }
        }
        let firstSequence = completions.keys.min() ?? preparations.keys.min()
        let nextSequence = completions.keys.max().map { $0 + 1 } ?? firstSequence
        guard let firstSequence,
              preparations.keys.allSatisfy({ $0 >= firstSequence && $0 <= (nextSequence ?? firstSequence) }) else {
            throw AgentPassNativeError.invalidSignature("Lifecycle mutation preparations are stale or have a gap")
        }
        let pending = nextSequence.flatMap { preparations[$0] }
        guard preparations.count == completed.count + (pending == nil ? 0 : 1) else {
            throw AgentPassNativeError.invalidSignature("Lifecycle mutation history contains orphaned preparations")
        }
        if let pending, let previous = completed.last {
            guard pending.oldLifecycleHead == previous.newLifecycleHead,
                  pending.lifecycleSequence == previous.lifecycleSequence + 1 else {
                throw AgentPassNativeError.invalidSignature("Pending lifecycle mutation does not extend history")
            }
            guard Self.timestampDate(pending.createdAt)! >= Self.timestampDate(previous.createdAt)! else {
                throw AgentPassNativeError.invalidSignature("Pending lifecycle mutation time moved backwards")
            }
        }
        guard Set(preparations.values.map(\.operationID)).count == preparations.count else {
            throw AgentPassNativeError.invalidSignature("Lifecycle mutation operation UUID was reused")
        }
        return DiskState(preparations: preparations, completed: completed, completedBySequence: completions, nextSequence: nextSequence, pending: pending)
    }

    private func recoverTemporaryFiles() throws {
        try validateRootIdentity()
        let temporaryNames = try directoryNames().filter(Self.isTemporaryName)
        guard temporaryNames.count <= 8 else {
            throw AgentPassNativeError.invalidSignature("Too many lifecycle mutation crash remnants")
        }
        try validateRootIdentity()
        for name in temporaryNames {
            let data = try readPrivateFile(name: name, allowTemporary: true)
            let envelope = try Self.decodeEnvelope(data)
            let destination: String
            switch envelope.recordKind {
            case "prepare": destination = Self.prepareName(envelope.preparation)
            case "completed": destination = Self.completedName(envelope.preparation.pinSequence)
            default: throw AgentPassNativeError.invalidSignature("Lifecycle mutation crash remnant kind is invalid")
            }
            if fileExists(name: destination) {
                guard try readPrivateFile(name: destination, allowTemporary: false) == data else {
                    throw AgentPassNativeError.invalidSignature("Lifecycle mutation crash remnant conflicts with destination")
                }
            }
            guard unlinkat(rootDescriptor, name, 0) == 0, fsync(rootDescriptor) == 0 else {
                throw Self.posixError()
            }
        }
    }

    private func writeImmutable(name: String, data: Data, temporaryPoint: NativeLifecycleMutationOutboxCrashPoint, renamedPoint: NativeLifecycleMutationOutboxCrashPoint) throws {
        guard !data.isEmpty, data.count <= Self.maximumRecordBytes else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle mutation outbox record size is invalid")
        }
        try validateRootIdentity()
        if fileExists(name: name) {
            guard try readPrivateFile(name: name, allowTemporary: false) == data else {
                throw AgentPassNativeError.invalidSignature("Refusing to overwrite a lifecycle mutation record")
            }
            return
        }
        let temporary = ".lifecycle-mutation-\(UUID().uuidString).tmp"
        let descriptor = openat(rootDescriptor, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw Self.posixError() }
        var removeTemporary = true
        defer {
            close(descriptor)
            if removeTemporary { unlinkat(rootDescriptor, temporary, 0) }
        }
        try Self.writeAll(data, to: descriptor)
        guard fchmod(descriptor, 0o400) == 0, fsync(descriptor) == 0 else { throw Self.posixError() }
        try validateDescriptor(descriptor, expectedMode: 0o400)
        removeTemporary = false
        try fault(temporaryPoint)
        removeTemporary = true
        try validateRootIdentity()
        guard renameatx_np(rootDescriptor, temporary, rootDescriptor, name, UInt32(RENAME_EXCL)) == 0 else {
            if errno == EEXIST, try readPrivateFile(name: name, allowTemporary: false) == data { return }
            throw AgentPassNativeError.invalidSignature("Lifecycle mutation destination already exists or cannot be committed")
        }
        removeTemporary = false
        try fault(renamedPoint)
        try validateRootIdentity()
        try validatePathIdentity(name: name, descriptor: descriptor)
        guard fsync(rootDescriptor) == 0 else { throw Self.posixError() }
        try validateRootIdentity()
    }

    fileprivate static func canonicalRecord(_ preparation: NativeLifecycleMutationPreparation, recordKind: String) throws -> Data {
        try validate(preparation)
        guard recordKind == "prepare" || recordKind == "completed" else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle mutation record kind is invalid")
        }
        let base: [String: Any] = [
            "version": 1,
            "record_kind": recordKind,
            "operation_id": preparation.operationID.uuidString,
            "pin_sequence": preparation.pinSequence,
            "role": preparation.role.rawValue,
            "mutation_kind": preparation.kind.rawValue,
            "lifecycle_sequence": preparation.lifecycleSequence,
            "old_lifecycle_head": preparation.oldLifecycleHead,
            "new_lifecycle_head": preparation.newLifecycleHead,
            "created_at": preparation.createdAt,
            "payload_encoding": "base64",
            "payload": preparation.payload.base64EncodedString(),
            "payload_bytes": preparation.payload.count,
            "payload_hash": preparation.payloadHash
        ]
        var record = base
        record["record_hash"] = hash(try canonical(base))
        return try canonical(record)
    }

    private static func decodeEnvelope(_ data: Data) throws -> (recordKind: String, preparation: NativeLifecycleMutationPreparation) {
        let keys: Set<String> = [
            "version", "record_kind", "operation_id", "pin_sequence", "role", "mutation_kind",
            "lifecycle_sequence", "old_lifecycle_head", "new_lifecycle_head", "created_at",
            "payload_encoding", "payload", "payload_bytes", "payload_hash", "record_hash"
        ]
        guard !data.isEmpty, data.count <= maximumRecordBytes,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == keys, try canonical(object) == data,
              exactInteger(object["version"]) == 1,
              let recordKind = object["record_kind"] as? String,
              recordKind == "prepare" || recordKind == "completed",
              let operationText = object["operation_id"] as? String,
              let operationID = UUID(uuidString: operationText), operationID.uuidString == operationText,
              let pinSequence = exactInteger(object["pin_sequence"]),
              let roleText = object["role"] as? String, let role = NativeKeyRole(rawValue: roleText),
              let mutationText = object["mutation_kind"] as? String, let mutationKind = NativeLifecycleMutationKind(rawValue: mutationText),
              let lifecycleSequence = exactInteger(object["lifecycle_sequence"]),
              let oldHead = object["old_lifecycle_head"] as? String,
              let newHead = object["new_lifecycle_head"] as? String,
              let createdAt = object["created_at"] as? String,
              object["payload_encoding"] as? String == "base64",
              let payloadText = object["payload"] as? String,
              let payload = Data(base64Encoded: payloadText), payload.base64EncodedString() == payloadText,
              let payloadBytes = exactInteger(object["payload_bytes"]), payloadBytes == payload.count,
              let payloadHash = object["payload_hash"] as? String, payloadHash == hash(payload),
              let recordHash = object["record_hash"] as? String else {
            throw AgentPassNativeError.invalidSignature("Lifecycle mutation record is not exact canonical schema")
        }
        var unsigned = object
        unsigned.removeValue(forKey: "record_hash")
        guard recordHash == hash(try canonical(unsigned)) else {
            throw AgentPassNativeError.invalidSignature("Lifecycle mutation record hash is invalid")
        }
        let preparation = NativeLifecycleMutationPreparation(
            operationID: operationID,
            pinSequence: pinSequence,
            role: role,
            kind: mutationKind,
            lifecycleSequence: lifecycleSequence,
            oldLifecycleHead: oldHead,
            newLifecycleHead: newHead,
            createdAt: createdAt,
            payload: payload
        )
        try validate(preparation)
        return (recordKind, preparation)
    }

    private static func validate(_ preparation: NativeLifecycleMutationPreparation) throws {
        guard preparation.pinSequence > 0, preparation.lifecycleSequence > 0,
              isHead(preparation.oldLifecycleHead), isHead(preparation.newLifecycleHead),
              preparation.oldLifecycleHead != preparation.newLifecycleHead,
              !preparation.payload.isEmpty, preparation.payload.count <= maximumPayloadBytes,
              preparation.createdAt.wholeMatch(of: /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/) != nil,
              timestampDate(preparation.createdAt) != nil else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle mutation preparation fields are invalid")
        }
        try rejectPrivateKeyMaterial(preparation.payload)
    }

    /// Opaque signatures can be indistinguishable from scalar bytes, so callers still own the
    /// semantic public-only payload contract. These checks reject serialised private-key formats
    /// and explicit secret-bearing JSON fields at the persistence boundary.
    private static func rejectPrivateKeyMaterial(_ payload: Data) throws {
        let uppercase = String(decoding: payload, as: UTF8.self).uppercased()
        let forbiddenMarkers = ["-----BEGIN PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----"]
        guard !forbiddenMarkers.contains(where: uppercase.contains) else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle mutation payload must not contain private keys")
        }
        if let object = try? JSONSerialization.jsonObject(with: payload) {
            let forbiddenKeys: Set<String> = ["private_key", "privatekey", "private_key_data", "secret_key", "secret", "seed", "key_material"]
            func containsForbiddenKey(_ value: Any) -> Bool {
                if let dictionary = value as? [String: Any] {
                    if dictionary.keys.contains(where: { forbiddenKeys.contains($0.lowercased()) }) { return true }
                    return dictionary.values.contains(where: containsForbiddenKey)
                }
                if let array = value as? [Any] { return array.contains(where: containsForbiddenKey) }
                return false
            }
            guard !containsForbiddenKey(object) else {
                throw AgentPassNativeError.invalidConfiguration("Lifecycle mutation payload contains a secret-bearing field")
            }
        }
    }

    private func readRecord(name: String, expectedRecordKind: String) throws -> NativeLifecycleMutationPreparation {
        let envelope = try Self.decodeEnvelope(readPrivateFile(name: name, allowTemporary: false))
        guard envelope.recordKind == expectedRecordKind else {
            throw AgentPassNativeError.invalidSignature("Lifecycle mutation record kind does not match filename")
        }
        return envelope.preparation
    }

    private func readPrivateFile(name: String, allowTemporary: Bool) throws -> Data {
        guard !name.contains("/"), allowTemporary || name.first != "." else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle mutation filename is invalid")
        }
        try validateRootIdentity()
        let descriptor = openat(rootDescriptor, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw Self.posixError() }
        defer { close(descriptor) }
        try validateDescriptor(descriptor, expectedMode: 0o400)
        var before = stat()
        guard fstat(descriptor, &before) == 0, before.st_size > 0, before.st_size <= Self.maximumRecordBytes else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle mutation record size is invalid")
        }
        var data = Data(count: Int(before.st_size))
        try data.withUnsafeMutableBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.read(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                guard count > 0 else { throw Self.posixError() }
                offset += count
            }
        }
        var after = stat()
        guard fstat(descriptor, &after) == 0,
              after.st_dev == before.st_dev, after.st_ino == before.st_ino, after.st_size == before.st_size else {
            throw AgentPassNativeError.invalidSignature("Lifecycle mutation record changed while being read")
        }
        try validateRootIdentity()
        try validatePathIdentity(name: name, descriptor: descriptor)
        return data
    }

    private func validateDescriptor(_ descriptor: Int32, expectedMode: mode_t) throws {
        var info = stat()
        guard fstat(descriptor, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == geteuid(), info.st_mode & 0o777 == expectedMode, info.st_nlink == 1 else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle mutation records must be private service-owned single-link regular files")
        }
    }

    private func validatePathIdentity(name: String, descriptor: Int32) throws {
        var descriptorInfo = stat()
        var pathInfo = stat()
        guard fstat(descriptor, &descriptorInfo) == 0,
              fstatat(rootDescriptor, name, &pathInfo, AT_SYMLINK_NOFOLLOW) == 0,
              (pathInfo.st_mode & S_IFMT) == S_IFREG,
              descriptorInfo.st_dev == pathInfo.st_dev, descriptorInfo.st_ino == pathInfo.st_ino else {
            throw AgentPassNativeError.invalidSignature("Lifecycle mutation pathname was substituted")
        }
    }

    private func validateRootIdentity() throws {
        try Self.validateProtectedAncestors(rootPath)
        var descriptorInfo = stat()
        var pathInfo = stat()
        guard fstat(rootDescriptor, &descriptorInfo) == 0,
              descriptorInfo.st_dev == rootDevice, descriptorInfo.st_ino == rootInode,
              descriptorInfo.st_uid == geteuid(), descriptorInfo.st_mode & 0o077 == 0,
              lstat(rootPath, &pathInfo) == 0, (pathInfo.st_mode & S_IFMT) == S_IFDIR,
              pathInfo.st_dev == rootDevice, pathInfo.st_ino == rootInode else {
            throw AgentPassNativeError.invalidSignature("Lifecycle mutation outbox root was substituted or permissions changed")
        }
    }

    private func directoryNames() throws -> [String] {
        let names = try FileManager.default.contentsOfDirectory(atPath: rootPath)
        guard names.count <= 1_000_000 else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle mutation record limit exceeded")
        }
        return names.sorted()
    }

    private func fileExists(name: String) -> Bool {
        var info = stat()
        return fstatat(rootDescriptor, name, &info, AT_SYMLINK_NOFOLLOW) == 0
    }

    private func withExclusiveLock<T>(_ body: () throws -> T) throws -> T {
        processLock.lock()
        defer { processLock.unlock() }
        guard flock(rootDescriptor, LOCK_EX) == 0 else { throw Self.posixError() }
        defer { flock(rootDescriptor, LOCK_UN) }
        return try body()
    }

    private static func prepareName(_ preparation: NativeLifecycleMutationPreparation) -> String {
        String(format: "prepare-%020d-%@.json", preparation.pinSequence, preparation.operationID.uuidString)
    }

    private static func completedName(_ sequence: Int) -> String {
        String(format: "completed-%020d.json", sequence)
    }

    private static func parsePrepareName(_ name: String) -> (sequence: Int, operationID: UUID)? {
        let pattern = /^prepare-([0-9]{20})-([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})\.json$/
        guard let match = name.wholeMatch(of: pattern), let sequence = Int(match.1),
              let operationID = UUID(uuidString: String(match.2)), operationID.uuidString == String(match.2) else { return nil }
        return (sequence, operationID)
    }

    private static func parseCompletedName(_ name: String) -> Int? {
        guard let match = name.wholeMatch(of: /^completed-([0-9]{20})\.json$/) else { return nil }
        return Int(match.1)
    }

    private static func isTemporaryName(_ name: String) -> Bool {
        name.wholeMatch(of: /^\.lifecycle-mutation-[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\.tmp$/) != nil
    }

    private static func validateProtectedAncestors(_ path: String) throws {
        guard path.hasPrefix("/") else { throw AgentPassNativeError.invalidConfiguration("Lifecycle mutation outbox root must be absolute") }
        var current = "/"
        var rootInfo = stat()
        guard lstat(current, &rootInfo) == 0, (rootInfo.st_mode & S_IFMT) == S_IFDIR,
              rootInfo.st_uid == 0, rootInfo.st_mode & 0o022 == 0 else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle mutation filesystem root is not protected")
        }
        for component in path.split(separator: "/", omittingEmptySubsequences: true) {
            current = current == "/" ? "/\(component)" : "\(current)/\(component)"
            var info = stat()
            guard lstat(current, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
                  (info.st_uid == 0 || info.st_uid == geteuid()), info.st_mode & 0o022 == 0 else {
                throw AgentPassNativeError.invalidConfiguration("Lifecycle mutation ancestors must be root/service-owned, non-writable directories without symlinks")
            }
        }
    }

    private static func realPath(_ path: String) throws -> String {
        guard let resolved = Darwin.realpath(path, nil) else { throw posixError() }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    private static func exactInteger(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, String(cString: number.objCType) == "q" else { return nil }
        return number.intValue
    }

    private static func timestampDate(_ value: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: value)
    }

    private static func isHead(_ value: String) -> Bool { value.wholeMatch(of: /^[0-9a-f]{64}$/) != nil }

    private static func canonical(_ object: [String: Any]) throws -> Data {
        guard JSONSerialization.isValidJSONObject(object) else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle mutation record is not valid JSON")
        }
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    }

    private static func hash(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func writeAll(_ data: Data, to descriptor: Int32) throws {
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                guard count > 0 else { throw posixError() }
                offset += count
            }
        }
    }

    private static func posixError() -> POSIXError { POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
}
