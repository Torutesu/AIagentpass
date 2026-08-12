import CryptoKit
import Darwin
import Foundation

public enum NativeLifecyclePinAction: String, CaseIterable, Sendable {
    case staged
    case abortIntent = "abort_intent"
    case aborted
    case activated
    /// An `activated` lifecycle record whose transition continuity is `.recovered`.
    case recoveredActivation = "recovered_activation"
    case deletionIntent = "deletion_intent"
    case deleted
}

public enum NativeLifecyclePinCrashPoint: Sendable {
    case afterPreparationTemporaryFileSync
    case afterPreparationRename
    case afterPinTemporaryFileSync
    case afterPinRename
}

public struct NativeLifecyclePinPreparation: Equatable, Sendable {
    public let operationID: UUID
    public let sequence: Int
    public let role: NativeKeyRole
    public let action: NativeLifecyclePinAction
    public let oldLifecycleHead: String
    public let newLifecycleHead: String
    public let preparedAt: String

    public init(operationID: UUID, sequence: Int, role: NativeKeyRole, action: NativeLifecyclePinAction, oldLifecycleHead: String, newLifecycleHead: String, preparedAt: String) {
        self.operationID = operationID
        self.sequence = sequence
        self.role = role
        self.action = action
        self.oldLifecycleHead = oldLifecycleHead
        self.newLifecycleHead = newLifecycleHead
        self.preparedAt = preparedAt
    }

    public func canonicalData() throws -> Data {
        try NativeLifecyclePinTransaction.canonicalRecord(self, kind: "prepare")
    }
}

public enum NativeLifecyclePinRecoveryDisposition: Equatable, Sendable {
    /// The ledger still has the old head. The immutable preparation remains pending.
    case prepared(NativeLifecyclePinPreparation)
    /// The ledger has the new head and the durable pin exists (or was completed by recovery).
    case committed(NativeLifecyclePinPreparation)
}

/// Durable external lifecycle pin state. Every preparation and commit is an immutable,
/// canonical file. There is no mutable "current" pointer: the highest contiguous committed
/// sequence is the current pin, while its matching preparation provides crash-recovery intent.
public final class NativeLifecyclePinTransaction: @unchecked Sendable {
    private static let maximumRecordBytes = 64 * 1024

    private let rootPath: String
    private let rootDescriptor: Int32
    private let rootDevice: dev_t
    private let rootInode: ino_t
    private let fault: @Sendable (NativeLifecyclePinCrashPoint) throws -> Void
    private let processLock = NSLock()

    public init(rootPath: String, faultInjector: @escaping @Sendable (NativeLifecyclePinCrashPoint) throws -> Void = { _ in }) throws {
        guard rootPath.hasPrefix("/") else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle pin root must be absolute")
        }
        let standardized = URL(fileURLWithPath: rootPath).standardizedFileURL.path
        let canonical = try Self.realPath(standardized)
        guard standardized == canonical else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle pin root and every ancestor must not be a symbolic link (supplied \(standardized), resolved \(canonical))")
        }
        try Self.validateProtectedAncestors(canonical)
        var supplied = stat()
        guard lstat(canonical, &supplied) == 0, (supplied.st_mode & S_IFMT) == S_IFDIR else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle pin root must be an existing directory and not a symbolic link")
        }
        let descriptor = open(canonical, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw Self.posixError() }
        var info = stat()
        guard fstat(descriptor, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == geteuid(),
              info.st_mode & 0o077 == 0 else {
            close(descriptor)
            throw AgentPassNativeError.invalidConfiguration("Lifecycle pin root must be a private service-owned directory")
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

    /// Creates (or idempotently returns) the only valid preparation for the next sequence.
    @discardableResult
    public func prepare(operationID: UUID, sequence: Int, role: NativeKeyRole, action: NativeLifecyclePinAction, oldLifecycleHead: String, newLifecycleHead: String, preparedAt: String) throws -> NativeLifecyclePinPreparation {
        let candidate = NativeLifecyclePinPreparation(operationID: operationID, sequence: sequence, role: role, action: action, oldLifecycleHead: oldLifecycleHead, newLifecycleHead: newLifecycleHead, preparedAt: preparedAt)
        try Self.validate(candidate)
        return try withExclusiveLock {
            try recoverTemporaryFiles()
            let state = try readState()
            if sequence <= state.committed.count {
                guard let existing = state.preparations[sequence], existing == candidate,
                      state.committed[sequence - 1] == candidate else {
                    throw AgentPassNativeError.invalidSignature("Lifecycle pin preparation conflicts with committed history")
                }
                return existing
            }
            guard sequence == state.committed.count + 1 else {
                throw AgentPassNativeError.invalidSignature("Lifecycle pin preparation sequence is stale or has a gap")
            }
            if let current = state.committed.last {
                guard candidate.oldLifecycleHead == current.newLifecycleHead else {
                    throw AgentPassNativeError.invalidSignature("Lifecycle pin preparation does not extend the durable pin")
                }
                guard Self.timestampDate(candidate.preparedAt)! >= Self.timestampDate(current.preparedAt)! else {
                    throw AgentPassNativeError.invalidSignature("Lifecycle pin preparation time must not move backwards")
                }
            }
            if let pending = state.pending {
                guard pending == candidate else {
                    throw AgentPassNativeError.invalidSignature("A different lifecycle pin operation is already prepared")
                }
                return pending
            }
            guard !state.preparations.values.contains(where: { $0.operationID == candidate.operationID }) else {
                throw AgentPassNativeError.invalidSignature("Lifecycle pin operation UUID reuse is forbidden")
            }
            let data = try Self.canonicalRecord(candidate, kind: "prepare")
            try writeImmutable(name: Self.prepareName(candidate), data: data, temporaryPoint: .afterPreparationTemporaryFileSync, renamedPoint: .afterPreparationRename)
            return candidate
        }
    }

    /// Commits the prepared new head. Both caller observations are required to match the journal,
    /// preventing a generic "commit latest" call from approving a substituted ledger transition.
    @discardableResult
    public func commit(_ preparation: NativeLifecyclePinPreparation, observedOldLifecycleHead: String, observedNewLifecycleHead: String) throws -> NativeLifecyclePinPreparation {
        try Self.validate(preparation)
        guard observedOldLifecycleHead == preparation.oldLifecycleHead,
              observedNewLifecycleHead == preparation.newLifecycleHead else {
            throw AgentPassNativeError.invalidSignature("Observed lifecycle heads do not match the prepared transaction")
        }
        return try withExclusiveLock {
            try commitLocked(preparation)
        }
    }

    /// Resolves an indeterminate response without guessing. An unchanged ledger leaves the
    /// preparation pending; the exact new ledger head completes the pin; every other head fails.
    @discardableResult
    public func recover(_ preparation: NativeLifecyclePinPreparation, observedOldLifecycleHead: String, observedCurrentLifecycleHead: String) throws -> NativeLifecyclePinRecoveryDisposition {
        try Self.validate(preparation)
        guard observedOldLifecycleHead == preparation.oldLifecycleHead else {
            throw AgentPassNativeError.invalidSignature("Recovery old lifecycle head does not match the prepared transaction")
        }
        return try withExclusiveLock {
            try recoverTemporaryFiles()
            let state = try readState()
            let recorded = state.preparations[preparation.sequence]
            guard recorded == preparation else {
                throw AgentPassNativeError.invalidSignature("Recovery journal is missing or does not exactly match the operation")
            }
            if preparation.sequence <= state.committed.count {
                guard state.committed[preparation.sequence - 1] == preparation,
                      observedCurrentLifecycleHead == preparation.newLifecycleHead else {
                    throw AgentPassNativeError.invalidSignature("Committed lifecycle pin conflicts with the observed ledger head")
                }
                return .committed(preparation)
            }
            guard state.pending == preparation else {
                throw AgentPassNativeError.invalidSignature("Lifecycle pin journal is stale or non-contiguous")
            }
            if observedCurrentLifecycleHead == preparation.oldLifecycleHead {
                return .prepared(preparation)
            }
            guard observedCurrentLifecycleHead == preparation.newLifecycleHead else {
                throw AgentPassNativeError.invalidSignature("Observed lifecycle head is neither the prepared old nor new head")
            }
            _ = try commitLocked(preparation, temporaryFilesAlreadyRecovered: true)
            return .committed(preparation)
        }
    }

    /// Returns the highest durable pin after validating the complete journal/pin history.
    public func current() throws -> NativeLifecyclePinPreparation? {
        try withExclusiveLock {
            try recoverTemporaryFiles()
            return try readState().committed.last
        }
    }

    /// Returns the one unresolved immutable preparation after validating the complete history.
    /// At startup, pass this value to `recover`. If the observed ledger is still at `old`, the
    /// journal remains durable so the coordinator can retry the exact mutation or run its
    /// separately authorized cancellation/abort flow; the journal is never silently discarded.
    public func pending() throws -> NativeLifecyclePinPreparation? {
        try withExclusiveLock {
            try recoverTemporaryFiles()
            return try readState().pending
        }
    }

    private func commitLocked(_ preparation: NativeLifecyclePinPreparation, temporaryFilesAlreadyRecovered: Bool = false) throws -> NativeLifecyclePinPreparation {
        if !temporaryFilesAlreadyRecovered { try recoverTemporaryFiles() }
        let state = try readState()
        guard state.preparations[preparation.sequence] == preparation else {
            throw AgentPassNativeError.invalidSignature("Lifecycle pin commit has no exact prepared journal")
        }
        if preparation.sequence <= state.committed.count {
            guard state.committed[preparation.sequence - 1] == preparation else {
                throw AgentPassNativeError.invalidSignature("Lifecycle pin commit equivocates with durable history")
            }
            return preparation
        }
        guard preparation.sequence == state.committed.count + 1,
              state.pending == preparation,
              state.committed.last?.newLifecycleHead == preparation.oldLifecycleHead || state.committed.isEmpty else {
            throw AgentPassNativeError.invalidSignature("Lifecycle pin commit is stale or does not extend the durable pin")
        }
        let data = try Self.canonicalRecord(preparation, kind: "pin")
        try writeImmutable(name: Self.pinName(preparation.sequence), data: data, temporaryPoint: .afterPinTemporaryFileSync, renamedPoint: .afterPinRename)
        return preparation
    }

    private struct DiskState {
        let preparations: [Int: NativeLifecyclePinPreparation]
        let committed: [NativeLifecyclePinPreparation]
        let pending: NativeLifecyclePinPreparation?
    }

    private func readState() throws -> DiskState {
        try validateRootIdentity()
        let names = try directoryNames()
        try validateRootIdentity()
        var preparations: [Int: NativeLifecyclePinPreparation] = [:]
        var pins: [Int: NativeLifecyclePinPreparation] = [:]
        for name in names {
            if let parsed = Self.parsePrepareName(name) {
                let decoded = try readRecord(name: name, expectedKind: "prepare")
                guard decoded.sequence == parsed.sequence, decoded.operationID == parsed.operationID,
                      preparations.updateValue(decoded, forKey: parsed.sequence) == nil else {
                    throw AgentPassNativeError.invalidSignature("Lifecycle pin journal filename or sequence is inconsistent")
                }
            } else if let sequence = Self.parsePinName(name) {
                let decoded = try readRecord(name: name, expectedKind: "pin")
                guard decoded.sequence == sequence, pins.updateValue(decoded, forKey: sequence) == nil else {
                    throw AgentPassNativeError.invalidSignature("Lifecycle pin filename or sequence is inconsistent")
                }
            } else if Self.isTemporaryName(name) {
                throw AgentPassNativeError.invalidSignature("Unrecovered lifecycle pin temporary file remains")
            } else {
                throw AgentPassNativeError.invalidSignature("Lifecycle pin root contains an unknown entry")
            }
        }
        var committed: [NativeLifecyclePinPreparation] = []
        if !pins.isEmpty {
            for sequence in 1...pins.count {
                guard let pin = pins[sequence], let journal = preparations[sequence], pin == journal else {
                    throw AgentPassNativeError.invalidSignature("Lifecycle pin history has a gap or mismatched journal")
                }
                if let previous = committed.last, pin.oldLifecycleHead != previous.newLifecycleHead {
                    throw AgentPassNativeError.invalidSignature("Lifecycle pin history does not form a continuous head chain")
                }
                if let previous = committed.last,
                   Self.timestampDate(pin.preparedAt)! < Self.timestampDate(previous.preparedAt)! {
                    throw AgentPassNativeError.invalidSignature("Lifecycle pin preparation time moved backwards")
                }
                committed.append(pin)
            }
        }
        guard preparations.keys.allSatisfy({ $0 >= 1 && $0 <= committed.count + 1 }) else {
            throw AgentPassNativeError.invalidSignature("Lifecycle pin journal is stale or has a sequence gap")
        }
        let pending = preparations[committed.count + 1]
        guard preparations.count == committed.count + (pending == nil ? 0 : 1) else {
            throw AgentPassNativeError.invalidSignature("Lifecycle pin history contains duplicate or orphaned journals")
        }
        if let pending, let current = committed.last, pending.oldLifecycleHead != current.newLifecycleHead {
            throw AgentPassNativeError.invalidSignature("Pending lifecycle pin does not extend the durable pin")
        }
        if let pending, let current = committed.last,
           Self.timestampDate(pending.preparedAt)! < Self.timestampDate(current.preparedAt)! {
            throw AgentPassNativeError.invalidSignature("Pending lifecycle pin preparation time moved backwards")
        }
        guard Set(preparations.values.map(\.operationID)).count == preparations.count else {
            throw AgentPassNativeError.invalidSignature("Lifecycle pin operation UUID was reused")
        }
        return DiskState(preparations: preparations, committed: committed, pending: pending)
    }

    private func recoverTemporaryFiles() throws {
        try validateRootIdentity()
        let temporaryNames = try directoryNames().filter(Self.isTemporaryName)
        guard temporaryNames.count <= 8 else {
            throw AgentPassNativeError.invalidSignature("Too many lifecycle pin crash remnants")
        }
        try validateRootIdentity()
        for name in temporaryNames {
            let data = try readPrivateFile(name: name, allowTemporary: true)
            let object = try Self.decodeEnvelope(data)
            let destination: String
            switch object.kind {
            case "prepare": destination = Self.prepareName(object.preparation)
            case "pin": destination = Self.pinName(object.preparation.sequence)
            default: throw AgentPassNativeError.invalidSignature("Lifecycle pin crash remnant kind is invalid")
            }
            if fileExists(name: destination) {
                guard try readPrivateFile(name: destination, allowTemporary: false) == data else {
                    throw AgentPassNativeError.invalidSignature("Lifecycle pin crash remnant conflicts with its destination")
                }
            }
            guard unlinkat(rootDescriptor, name, 0) == 0 else { throw Self.posixError() }
            guard fsync(rootDescriptor) == 0 else { throw Self.posixError() }
        }
    }

    private func writeImmutable(name: String, data: Data, temporaryPoint: NativeLifecyclePinCrashPoint, renamedPoint: NativeLifecyclePinCrashPoint) throws {
        guard !data.isEmpty, data.count <= Self.maximumRecordBytes else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle pin record size is invalid")
        }
        try validateRootIdentity()
        guard !fileExists(name: name) else {
            let existing = try readPrivateFile(name: name, allowTemporary: false)
            guard existing == data else { throw AgentPassNativeError.invalidSignature("Refusing to overwrite a lifecycle pin record") }
            return
        }
        let temporary = ".lifecycle-pin-\(UUID().uuidString).tmp"
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
        // A fault injected here models process death: normal scope cleanup must not erase the
        // durable remnant that a fresh process is expected to inspect and safely discard.
        removeTemporary = false
        do {
            try fault(temporaryPoint)
        } catch {
            throw error
        }
        removeTemporary = true
        try validateRootIdentity()
        guard renameatx_np(rootDescriptor, temporary, rootDescriptor, name, UInt32(RENAME_EXCL)) == 0 else {
            if errno == EEXIST, try readPrivateFile(name: name, allowTemporary: false) == data { return }
            throw AgentPassNativeError.invalidSignature("Lifecycle pin destination already exists or cannot be committed")
        }
        removeTemporary = false
        try fault(renamedPoint)
        try validateRootIdentity()
        try validatePathIdentity(name: name, descriptor: descriptor)
        guard fsync(rootDescriptor) == 0 else { throw Self.posixError() }
        try validateRootIdentity()
    }

    private func readRecord(name: String, expectedKind: String) throws -> NativeLifecyclePinPreparation {
        let envelope = try Self.decodeEnvelope(readPrivateFile(name: name, allowTemporary: false))
        guard envelope.kind == expectedKind else {
            throw AgentPassNativeError.invalidSignature("Lifecycle pin record kind does not match its filename")
        }
        return envelope.preparation
    }

    private func readPrivateFile(name: String, allowTemporary: Bool) throws -> Data {
        guard !name.contains("/"), allowTemporary || name.first != "." else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle pin filename is invalid")
        }
        try validateRootIdentity()
        let descriptor = openat(rootDescriptor, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw Self.posixError() }
        defer { close(descriptor) }
        try validateDescriptor(descriptor, expectedMode: 0o400)
        var info = stat()
        guard fstat(descriptor, &info) == 0, info.st_size > 0, info.st_size <= Self.maximumRecordBytes else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle pin file size is invalid")
        }
        var data = Data(count: Int(info.st_size))
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
              after.st_dev == info.st_dev, after.st_ino == info.st_ino,
              after.st_size == info.st_size else {
            throw AgentPassNativeError.invalidSignature("Lifecycle pin file changed while being read")
        }
        try validateRootIdentity()
        try validatePathIdentity(name: name, descriptor: descriptor)
        return data
    }

    private func validateDescriptor(_ descriptor: Int32, expectedMode: mode_t) throws {
        var info = stat()
        guard fstat(descriptor, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == geteuid(),
              info.st_mode & 0o777 == expectedMode,
              info.st_nlink == 1 else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle pin records must be private service-owned single-link regular files")
        }
    }

    private func validatePathIdentity(name: String, descriptor: Int32) throws {
        var descriptorInfo = stat()
        var pathInfo = stat()
        guard fstat(descriptor, &descriptorInfo) == 0,
              fstatat(rootDescriptor, name, &pathInfo, AT_SYMLINK_NOFOLLOW) == 0,
              (pathInfo.st_mode & S_IFMT) == S_IFREG,
              descriptorInfo.st_dev == pathInfo.st_dev,
              descriptorInfo.st_ino == pathInfo.st_ino else {
            throw AgentPassNativeError.invalidSignature("Lifecycle pin pathname was substituted")
        }
    }

    private func validateRootIdentity() throws {
        try Self.validateProtectedAncestors(rootPath)
        var descriptorInfo = stat()
        var pathInfo = stat()
        guard fstat(rootDescriptor, &descriptorInfo) == 0,
              descriptorInfo.st_dev == rootDevice, descriptorInfo.st_ino == rootInode,
              descriptorInfo.st_uid == geteuid(), descriptorInfo.st_mode & 0o077 == 0,
              lstat(rootPath, &pathInfo) == 0,
              (pathInfo.st_mode & S_IFMT) == S_IFDIR,
              pathInfo.st_dev == rootDevice, pathInfo.st_ino == rootInode else {
            throw AgentPassNativeError.invalidSignature("Lifecycle pin root pathname was substituted or permissions changed")
        }
    }

    private func directoryNames() throws -> [String] {
        let names = try FileManager.default.contentsOfDirectory(atPath: rootPath)
        guard names.count <= 1_000_000 else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle pin record limit exceeded")
        }
        return names.sorted()
    }

    private func fileExists(name: String) -> Bool {
        var info = stat()
        if fstatat(rootDescriptor, name, &info, AT_SYMLINK_NOFOLLOW) == 0 { return true }
        return false
    }

    private func withExclusiveLock<T>(_ body: () throws -> T) throws -> T {
        processLock.lock()
        defer { processLock.unlock() }
        guard flock(rootDescriptor, LOCK_EX) == 0 else { throw Self.posixError() }
        defer { flock(rootDescriptor, LOCK_UN) }
        return try body()
    }

    fileprivate static func canonicalRecord(_ preparation: NativeLifecyclePinPreparation, kind: String) throws -> Data {
        try validate(preparation)
        let base: [String: Any] = [
            "version": 1,
            "kind": kind,
            "operation_id": preparation.operationID.uuidString,
            "sequence": preparation.sequence,
            "role": preparation.role.rawValue,
            "action": preparation.action.rawValue,
            "old_lifecycle_head": preparation.oldLifecycleHead,
            "new_lifecycle_head": preparation.newLifecycleHead,
            "prepared_at": preparation.preparedAt
        ]
        var record = base
        record["record_hash"] = hash(try canonical(base))
        return try canonical(record)
    }

    private static func decodeEnvelope(_ data: Data) throws -> (kind: String, preparation: NativeLifecyclePinPreparation) {
        let keys: Set<String> = ["version", "kind", "operation_id", "sequence", "role", "action", "old_lifecycle_head", "new_lifecycle_head", "prepared_at", "record_hash"]
        guard !data.isEmpty, data.count <= maximumRecordBytes,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == keys,
              try canonical(object) == data,
              exactInteger(object["version"]) == 1,
              let kind = object["kind"] as? String, kind == "prepare" || kind == "pin",
              let operationText = object["operation_id"] as? String,
              let operationID = UUID(uuidString: operationText), operationID.uuidString == operationText,
              let sequence = exactInteger(object["sequence"]),
              let roleText = object["role"] as? String, let role = NativeKeyRole(rawValue: roleText),
              let actionText = object["action"] as? String, let action = NativeLifecyclePinAction(rawValue: actionText),
              let oldHead = object["old_lifecycle_head"] as? String,
              let newHead = object["new_lifecycle_head"] as? String,
              let preparedAt = object["prepared_at"] as? String,
              let recordHash = object["record_hash"] as? String else {
            throw AgentPassNativeError.invalidSignature("Lifecycle pin record is not exact canonical schema")
        }
        var unsigned = object
        unsigned.removeValue(forKey: "record_hash")
        guard recordHash == hash(try canonical(unsigned)) else {
            throw AgentPassNativeError.invalidSignature("Lifecycle pin record hash is invalid")
        }
        let preparation = NativeLifecyclePinPreparation(operationID: operationID, sequence: sequence, role: role, action: action, oldLifecycleHead: oldHead, newLifecycleHead: newHead, preparedAt: preparedAt)
        try validate(preparation)
        return (kind, preparation)
    }

    private static func validate(_ preparation: NativeLifecyclePinPreparation) throws {
        guard preparation.sequence > 0,
              isHead(preparation.oldLifecycleHead),
              isHead(preparation.newLifecycleHead),
              preparation.oldLifecycleHead != preparation.newLifecycleHead,
              preparation.operationID.uuidString.count == 36,
              preparation.preparedAt.wholeMatch(of: /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/) != nil,
              timestampDate(preparation.preparedAt) != nil else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle pin preparation fields are invalid")
        }
    }

    private static func timestampDate(_ value: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: value)
    }

    /// Walks the supplied absolute namespace without following any component. System-owned
    /// ancestors and service-owned ancestors are accepted, but group/world-writable directories
    /// are not: otherwise an attacker could replace a later path component between operations.
    private static func validateProtectedAncestors(_ path: String) throws {
        guard path.hasPrefix("/") else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle pin root must be absolute")
        }
        var current = "/"
        var rootInfo = stat()
        guard lstat(current, &rootInfo) == 0,
              (rootInfo.st_mode & S_IFMT) == S_IFDIR,
              rootInfo.st_uid == 0,
              rootInfo.st_mode & 0o022 == 0 else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle pin filesystem root is not protected")
        }
        for component in path.split(separator: "/", omittingEmptySubsequences: true) {
            current = current == "/" ? "/\(component)" : "\(current)/\(component)"
            var info = stat()
            guard lstat(current, &info) == 0,
                  (info.st_mode & S_IFMT) == S_IFDIR,
                  (info.st_uid == 0 || info.st_uid == geteuid()),
                  info.st_mode & 0o022 == 0 else {
                throw AgentPassNativeError.invalidConfiguration("Lifecycle pin path ancestors must be root/service-owned non-writable directories without symlinks")
            }
        }
    }

    private static func realPath(_ path: String) throws -> String {
        guard let resolved = Darwin.realpath(path, nil) else { throw posixError() }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    /// JSONSerialization bridges booleans and integral floating-point values to `Int` through
    /// NSNumber. Requiring the native signed-integer representation keeps the schema type-exact.
    private static func exactInteger(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber,
              String(cString: number.objCType) == "q" else { return nil }
        return number.intValue
    }

    private static func prepareName(_ preparation: NativeLifecyclePinPreparation) -> String {
        String(format: "prepare-%020d-%@.json", preparation.sequence, preparation.operationID.uuidString)
    }

    private static func pinName(_ sequence: Int) -> String {
        String(format: "pin-%020d.json", sequence)
    }

    private static func parsePrepareName(_ name: String) -> (sequence: Int, operationID: UUID)? {
        let pattern = /^prepare-([0-9]{20})-([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})\.json$/
        guard let match = name.wholeMatch(of: pattern),
              let sequence = Int(match.1),
              let operationID = UUID(uuidString: String(match.2)),
              operationID.uuidString == String(match.2) else { return nil }
        return (sequence, operationID)
    }

    private static func parsePinName(_ name: String) -> Int? {
        let pattern = /^pin-([0-9]{20})\.json$/
        guard let match = name.wholeMatch(of: pattern) else { return nil }
        return Int(match.1)
    }

    private static func isTemporaryName(_ name: String) -> Bool {
        name.wholeMatch(of: /^\.lifecycle-pin-[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\.tmp$/) != nil
    }

    private static func isHead(_ value: String) -> Bool {
        value.wholeMatch(of: /^[0-9a-f]{64}$/) != nil
    }

    private static func canonical(_ object: [String: Any]) throws -> Data {
        guard JSONSerialization.isValidJSONObject(object) else {
            throw AgentPassNativeError.invalidConfiguration("Lifecycle pin record is not valid JSON")
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

    private static func posixError() -> POSIXError {
        POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
}
