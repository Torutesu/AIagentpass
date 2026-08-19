import Darwin
import Foundation

/// The Cloud audit head which is durable independently from pending event files.
/// A nil event ID is used only for the initial/migrated hash anchor.
public struct NativeDeviceAuditHead: Equatable, Sendable {
    public let lastHash: String
    public let lastEventID: String?

    public init(lastHash: String, lastEventID: String?) {
        self.lastHash = lastHash
        self.lastEventID = lastEventID
    }
}

/// Test-only fault points for exercising the durable acknowledgement protocol.
/// This is internal so the production API remains source-compatible and the
/// service cannot accidentally depend on a crash-injection surface.
enum NativeDeviceAuditOutboxCrashPoint: Sendable {
    case afterHeadTemporaryFileSync
    case afterHeadRename
    case afterHeadPersistedBeforeAcknowledgementDeletion
    case afterAcknowledgementDeletion
}

/// Durable, byte-exact queue for redacted Device audit events.
///
/// Each event is stored as one immutable private file. The Cloud head is kept
/// in a separate canonical metadata file. Enqueue validates that an event
/// extends the durable head (and any already-pending local tail), while an
/// acknowledgement advances the head before removing event files. This order
/// means a crash can only leave a replayable event, never a deleted event with
/// a stale chain head.
public final class NativeDeviceAuditOutbox: @unchecked Sendable {
    public static let maximumPendingEvents = 4_096
    private static let maximumFileBytes = NativeDeviceAuditEvent.maxBytes
    private static let headName = "head.json"
    private static let genesisHash = String(repeating: "0", count: 64)
    private let rootPath: String
    private let rootDescriptor: Int32
    private let rootDevice: dev_t
    private let rootInode: ino_t
    private let fault: @Sendable (NativeDeviceAuditOutboxCrashPoint) throws -> Void
    private let lock = NSLock()

    public convenience init(rootPath: String) throws {
        try self.init(rootPath: rootPath, faultInjector: { _ in })
    }

    init(
        rootPath: String,
        faultInjector: @escaping @Sendable (NativeDeviceAuditOutboxCrashPoint) throws -> Void
    ) throws {
        guard rootPath.hasPrefix("/") else {
            throw AgentPassNativeError.invalidConfiguration("Device audit outbox root must be absolute")
        }
        let path = URL(fileURLWithPath: rootPath).standardizedFileURL.path
        try Self.prepareRoot(path)
        let descriptor = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw Self.posixError() }
        var info = stat()
        guard fstat(descriptor, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == geteuid(), info.st_mode & 0o077 == 0 else {
            close(descriptor)
            throw AgentPassNativeError.invalidConfiguration("Device audit outbox root must be a private service-owned directory")
        }
        self.rootPath = path
        self.rootDescriptor = descriptor
        self.rootDevice = info.st_dev
        self.rootInode = info.st_ino
        self.fault = faultInjector
        do {
            try withLock {
                try validateRoot()
                try recoverTemporaryFiles()
                _ = try loadOrCreateHead()
                _ = try pendingEntries()
            }
        } catch {
            close(descriptor)
            throw error
        }
    }

    deinit { close(rootDescriptor) }

    /// Returns the last Cloud-confirmed audit head. This remains stable across
    /// process restarts and is never advanced merely by enqueueing locally.
    public func currentHead() throws -> NativeDeviceAuditHead {
        try withLock {
            try validateRoot()
            return try loadOrCreateHead()
        }
    }

    /// Returns the chain hash which a newly-created event must use. A pending
    /// local event tail takes precedence over the last Cloud-confirmed head.
    public func nextPreviousHash() throws -> String {
        try withLock {
            try validateRoot()
            let head = try loadOrCreateHead()
            return try chainTail(head: head, entries: try pendingEntries())
        }
    }

    @discardableResult
    public func enqueue(_ event: NativeDeviceAuditEvent) throws -> NativeDeviceAuditEvent {
        let data = try event.canonicalData()
        guard data.count <= Self.maximumFileBytes else {
            throw AgentPassNativeError.invalidConfiguration("Device audit outbox event is too large")
        }
        return try withLock {
            try validateRoot()
            let head = try loadOrCreateHead()
            let entries = try pendingEntries()
            let name = Self.fileName(event.eventID)
            if let existing = entries.first(where: { $0.name == name }) {
                guard existing.data == data else {
                    throw AgentPassNativeError.invalidSignature("Device audit outbox event ID was reused with different evidence")
                }
                return event
            }
            guard entries.count < Self.maximumPendingEvents else {
                throw AgentPassNativeError.invalidConfiguration("Device audit outbox capacity is exhausted")
            }
            let expectedPreviousHash = try chainTail(head: head, entries: entries)
            guard event.previousHash == expectedPreviousHash else {
                throw AgentPassNativeError.invalidSignature("Device audit event does not extend the durable audit head")
            }
            guard !entries.contains(where: { $0.event.eventHash == event.eventHash }) else {
                throw AgentPassNativeError.invalidSignature("Device audit event hash was reused with different evidence")
            }
            try writeImmutable(name: name, data: data)
            return event
        }
    }

    public func pending(limit: Int = NativeDeviceAuditBatch.maxEvents) throws -> [NativeDeviceAuditEvent] {
        guard (1...NativeDeviceAuditBatch.maxEvents).contains(limit) else {
            throw AgentPassNativeError.invalidConfiguration("Device audit outbox batch limit is invalid")
        }
        return try withLock {
            try validateRoot()
            let head = try loadOrCreateHead()
            let entries = try pendingEntries()
            let ordered = try orderedEntries(head: head, entries: entries, includingHeadEvent: true)
            return ordered.prefix(limit).map(\.event)
        }
    }

    /// Applies one Cloud ingestion response after the caller has verified its
    /// transport and device binding. Head metadata is committed before event
    /// removal so a crash leaves an exact replay rather than a chain gap.
    public func acknowledge(_ response: NativeDeviceAuditIngestionResponse) throws {
        let accepted = response.acceptedEventIDs.map { $0.lowercased() }
        let duplicates = response.duplicateEventIDs.map { $0.lowercased() }
        let acknowledged = accepted + duplicates
        guard !acknowledged.isEmpty,
              acknowledged.allSatisfy(Self.isUUID),
              Set(accepted).count == accepted.count,
              Set(duplicates).count == duplicates.count,
              Set(acknowledged).count == acknowledged.count else {
            throw AgentPassNativeError.invalidSignature("Device audit ingestion response has no unique acknowledged events")
        }
        guard response.chainStatus == "continuous", response.gapCount == 0 else {
            throw AgentPassNativeError.invalidSignature("Device audit ingestion response reports an audit gap")
        }
        let incoming = NativeDeviceAuditHead(
            lastHash: response.headHash,
            lastEventID: response.headEventID?.lowercased()
        )
        try Self.validateHead(incoming)

        try withLock {
            try validateRoot()
            let current = try loadOrCreateHead()
            let entries = try pendingEntries()
            let byID = Dictionary(uniqueKeysWithValues: entries.map { ($0.event.eventID, $0) })

            for eventID in acknowledged {
                if let entry = byID[eventID] {
                    guard entry.event.eventID == eventID else {
                        throw AgentPassNativeError.invalidSignature("Device audit acknowledgement filename is inconsistent")
                    }
                }
            }
            let missing = acknowledged.filter { byID[$0] == nil }
            if !missing.isEmpty {
                // A crash after head.json was committed can leave a response
                // replay with no event files. Only an exact current head with
                // its named terminal event is replayable; arbitrary unknown
                // IDs remain an equivocation and are rejected.
                guard incoming == current,
                      let headEventID = incoming.lastEventID,
                      Set(acknowledged) == Set([headEventID]) else {
                    throw AgentPassNativeError.invalidSignature("Device audit ingestion response acknowledges an unknown event")
                }
            }

            if incoming != current {
                guard let headEventID = incoming.lastEventID,
                      acknowledged.contains(headEventID),
                      let headEntry = byID[headEventID],
                      headEntry.event.eventHash == incoming.lastHash else {
                    throw AgentPassNativeError.invalidSignature("Device audit ingestion response head is not an acknowledged event")
                }
                let chain = try orderedExtensions(head: current, entries: entries)
                guard let headIndex = chain.firstIndex(where: { $0.eventID == headEventID }) else {
                    throw AgentPassNativeError.invalidSignature("Device audit ingestion response head is not contiguous")
                }
                let expectedIDs = chain.prefix(headIndex + 1).map(\.eventID)
                guard acknowledged.count == expectedIDs.count,
                      Set(acknowledged) == Set(expectedIDs) else {
                    throw AgentPassNativeError.invalidSignature("Device audit acknowledgement skips or exceeds the contiguous chain")
                }
            } else {
                // An unchanged genesis head cannot acknowledge a pending
                // event, and an unchanged non-genesis head may only replay
                // that exact head event after a response-loss crash.
                guard let headEventID = incoming.lastEventID,
                      Set(acknowledged) == Set([headEventID]) else {
                    throw AgentPassNativeError.invalidSignature("Device audit ingestion response acknowledges pending events without advancing the head")
                }
                if let headEntry = byID[headEventID] {
                    guard headEntry.event.eventHash == incoming.lastHash else {
                        throw AgentPassNativeError.invalidSignature("Device audit ingestion response head equivocates")
                    }
                }
            }

            if incoming != current {
                try persistHead(incoming)
            }
            try fault(.afterHeadPersistedBeforeAcknowledgementDeletion)

            var removed = false
            for eventID in acknowledged {
                guard let entry = byID[eventID] else { continue }
                try removeEvent(name: entry.name, expected: entry.event)
                removed = true
            }
            if removed {
                guard fsync(rootDescriptor) == 0 else { throw Self.posixError() }
            }
            try fault(.afterAcknowledgementDeletion)
        }
    }

    private struct FileEntry {
        let name: String
        let data: Data
        let event: NativeDeviceAuditEvent
    }

    private func loadOrCreateHead() throws -> NativeDeviceAuditHead {
        let names = try directoryNames()
        if names.contains(Self.headName) {
            return try readHead()
        }
        let entries = try pendingEntries()
        let head: NativeDeviceAuditHead
        if entries.isEmpty {
            head = NativeDeviceAuditHead(lastHash: Self.genesisHash, lastEventID: nil)
        } else {
            let hashes = Set(entries.map { $0.event.eventHash })
            let roots = entries.filter { !hashes.contains($0.event.previousHash) }
            guard roots.count == 1 else {
                throw AgentPassNativeError.invalidSignature("Device audit outbox has no unique chain anchor")
            }
            head = NativeDeviceAuditHead(lastHash: roots[0].event.previousHash, lastEventID: nil)
        }
        try Self.validateHead(head)
        try persistHead(head)
        return head
    }

    private func pendingEntries() throws -> [FileEntry] {
        let names = try directoryNames()
        let eventNames = names.filter { $0 != Self.headName }
        guard eventNames.count <= Self.maximumPendingEvents else {
            throw AgentPassNativeError.invalidSignature("Device audit outbox contains too many events")
        }
        let entries = try eventNames.sorted().map { name -> FileEntry in
            guard Self.isEventName(name) else {
                throw AgentPassNativeError.invalidSignature("Device audit outbox contains an unexpected file")
            }
            let data = try readPrivateFile(name: name, maximumBytes: Self.maximumFileBytes)
            let event = try NativeDeviceAuditEvent.decode(data)
            guard Self.fileName(event.eventID) == name else {
                throw AgentPassNativeError.invalidSignature("Device audit outbox event filename is inconsistent")
            }
            return FileEntry(name: name, data: data, event: event)
        }
        guard Set(entries.map { $0.event.eventID }).count == entries.count,
              Set(entries.map { $0.event.eventHash }).count == entries.count else {
            throw AgentPassNativeError.invalidSignature("Device audit outbox contains duplicate event evidence")
        }
        return entries
    }

    private func chainTail(head: NativeDeviceAuditHead, entries: [FileEntry]) throws -> String {
        try orderedExtensions(head: head, entries: entries).last?.eventHash ?? head.lastHash
    }

    private func orderedExtensions(head: NativeDeviceAuditHead, entries: [FileEntry]) throws -> [NativeDeviceAuditEvent] {
        try orderedEntries(head: head, entries: entries, includingHeadEvent: false).map(\.event)
    }

    private func orderedEntries(head: NativeDeviceAuditHead, entries: [FileEntry], includingHeadEvent: Bool) throws -> [FileEntry] {
        try Self.validateHead(head)
        let byID = Dictionary(uniqueKeysWithValues: entries.map { ($0.event.eventID, $0) })
        let byHash = Dictionary(uniqueKeysWithValues: entries.map { ($0.event.eventHash, $0) })
        var consumed = Set<String>()
        var result: [FileEntry] = []

        // Acknowledgement commits the Cloud head before deleting files. On a
        // restart, files for the head and its already-acknowledged ancestors
        // can therefore still be present and must remain replayable.
        if let headEventID = head.lastEventID {
            if let headEntry = byID[headEventID] {
                guard headEntry.event.eventHash == head.lastHash else {
                    throw AgentPassNativeError.invalidSignature("Device audit outbox head equivocates with a pending event")
                }
                var reverse = [headEntry]
                consumed.insert(headEventID)
                var previousHash = headEntry.event.previousHash
                while let predecessor = byHash[previousHash] {
                    guard consumed.insert(predecessor.event.eventID).inserted else {
                        throw AgentPassNativeError.invalidSignature("Device audit outbox contains a cycle before its durable head")
                    }
                    reverse.append(predecessor)
                    previousHash = predecessor.event.previousHash
                }
                if includingHeadEvent {
                    result.append(contentsOf: reverse.reversed())
                }
            }
        }
        var currentHash = head.lastHash
        while true {
            let candidates = entries.filter { !consumed.contains($0.event.eventID) && $0.event.previousHash == currentHash }
            guard candidates.count <= 1 else {
                throw AgentPassNativeError.invalidSignature("Device audit outbox contains an equivocal chain fork")
            }
            guard let candidate = candidates.first else { break }
            result.append(candidate)
            consumed.insert(candidate.event.eventID)
            currentHash = candidate.event.eventHash
        }
        guard consumed.count == entries.count else {
            throw AgentPassNativeError.invalidSignature("Device audit outbox contains a disconnected chain")
        }
        return result
    }

    private func readHead() throws -> NativeDeviceAuditHead {
        let data = try readPrivateFile(name: Self.headName, maximumBytes: 1024)
        let object = try NativeStrictJSON.object(from: data, maxBytes: 1024, maxDepth: 4)
        guard Set(object.keys) == Set(["last_hash", "last_event_id"]),
              let lastHash = object["last_hash"] as? String else {
            throw AgentPassNativeError.invalidSignature("Device audit head metadata is not the exact closed schema")
        }
        let lastEventID: String?
        if object["last_event_id"] is NSNull {
            lastEventID = nil
        } else if let value = object["last_event_id"] as? String, Self.isUUID(value), value == value.lowercased() {
            lastEventID = value
        } else {
            throw AgentPassNativeError.invalidSignature("Device audit head metadata event ID is invalid")
        }
        let head = NativeDeviceAuditHead(lastHash: lastHash, lastEventID: lastEventID)
        try Self.validateHead(head)
        guard try Self.headData(head) == data else {
            throw AgentPassNativeError.invalidSignature("Device audit head metadata is not canonical")
        }
        return head
    }

    private func persistHead(_ head: NativeDeviceAuditHead) throws {
        try Self.validateHead(head)
        try writeAtomic(name: Self.headName, data: try Self.headData(head), replaceExisting: true)
    }

    private func writeImmutable(name: String, data: Data) throws {
        try writeAtomic(name: name, data: data, replaceExisting: false)
    }

    private func writeAtomic(name: String, data: Data, replaceExisting: Bool) throws {
        let temporary = ".\(name).tmp-\(UUID().uuidString.lowercased())"
        var descriptor = openat(rootDescriptor, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o400)
        guard descriptor >= 0 else { throw Self.posixError() }
        var renamed = false
        defer {
            if descriptor >= 0 { close(descriptor) }
            if !renamed { unlinkat(rootDescriptor, temporary, 0) }
        }
        try Self.writeAll(data, to: descriptor)
        guard fchmod(descriptor, 0o400) == 0,
              fsync(descriptor) == 0 else { throw Self.posixError() }
        try fault(.afterHeadTemporaryFileSync)
        guard close(descriptor) == 0 else { throw Self.posixError() }
        descriptor = -1
        try validateRoot()
        if replaceExisting {
            guard renameat(rootDescriptor, temporary, rootDescriptor, name) == 0 else { throw Self.posixError() }
        } else {
            guard renameatx_np(rootDescriptor, temporary, rootDescriptor, name, UInt32(RENAME_EXCL)) == 0 else {
                if errno == EEXIST, try readPrivateFile(name: name, maximumBytes: Self.maximumFileBytes) == data { return }
                throw Self.posixError()
            }
        }
        renamed = true
        try fault(.afterHeadRename)
        guard fsync(rootDescriptor) == 0 else { throw Self.posixError() }
    }

    private func removeEvent(name: String, expected: NativeDeviceAuditEvent) throws {
        let data = try readPrivateFile(name: name, maximumBytes: Self.maximumFileBytes)
        let actual = try NativeDeviceAuditEvent.decode(data)
        guard actual == expected else {
            throw AgentPassNativeError.invalidSignature("Device audit outbox event changed before acknowledgement")
        }
        guard unlinkat(rootDescriptor, name, 0) == 0 else {
            if errno == ENOENT { return }
            throw Self.posixError()
        }
    }

    private func recoverTemporaryFiles() throws {
        let names = try directoryNames()
        let temporaryNames = names.filter(Self.isTemporaryName)
        guard temporaryNames.count <= 8 else {
            throw AgentPassNativeError.invalidSignature("Device audit outbox contains too many temporary files")
        }
        guard !temporaryNames.isEmpty else { return }
        for name in temporaryNames {
            var info = stat()
            guard fstatat(rootDescriptor, name, &info, AT_SYMLINK_NOFOLLOW) == 0,
                  (info.st_mode & S_IFMT) == S_IFREG,
                  info.st_uid == geteuid(), info.st_mode & 0o777 == 0o400,
                  info.st_nlink == 1 else {
                throw AgentPassNativeError.invalidSignature("Device audit outbox temporary file metadata is invalid")
            }
            guard unlinkat(rootDescriptor, name, 0) == 0 else { throw Self.posixError() }
        }
        guard fsync(rootDescriptor) == 0 else { throw Self.posixError() }
    }

    private func readPrivateFile(name: String, maximumBytes: Int) throws -> Data {
        guard !name.contains("/") else { throw AgentPassNativeError.invalidConfiguration("Device audit outbox filename is invalid") }
        try validateRoot()
        let descriptor = openat(rootDescriptor, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw Self.posixError() }
        defer { close(descriptor) }
        var before = stat()
        guard fstat(descriptor, &before) == 0,
              (before.st_mode & S_IFMT) == S_IFREG,
              before.st_uid == geteuid(), before.st_mode & 0o777 == 0o400,
              before.st_nlink == 1,
              before.st_size > 0, before.st_size <= off_t(maximumBytes) else {
            throw AgentPassNativeError.invalidSignature("Device audit outbox file metadata is invalid")
        }
        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 16 * 1024)
        while true {
            let count = Darwin.read(descriptor, &buffer, buffer.count)
            guard count >= 0 else { throw Self.posixError() }
            if count == 0 { break }
            guard result.count + count <= maximumBytes else {
                throw AgentPassNativeError.invalidSignature("Device audit outbox file exceeds its bound")
            }
            result.append(buffer, count: count)
        }
        var after = stat()
        guard fstat(descriptor, &after) == 0,
              before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              result.count == Int(before.st_size) else {
            throw AgentPassNativeError.invalidSignature("Device audit outbox file changed while being read")
        }
        var pathInfo = stat()
        guard fstatat(rootDescriptor, name, &pathInfo, AT_SYMLINK_NOFOLLOW) == 0,
              pathInfo.st_dev == before.st_dev, pathInfo.st_ino == before.st_ino else {
            throw AgentPassNativeError.invalidSignature("Device audit outbox pathname was substituted")
        }
        return result
    }

    private func directoryNames() throws -> [String] {
        try validateRoot()
        let names = try FileManager.default.contentsOfDirectory(atPath: rootPath)
        guard names.count <= Self.maximumPendingEvents + 16 else {
            throw AgentPassNativeError.invalidConfiguration("Device audit outbox directory is too large")
        }
        try validateRoot()
        return names.sorted()
    }

    private func validateRoot() throws {
        var descriptorInfo = stat()
        var pathInfo = stat()
        guard fstat(rootDescriptor, &descriptorInfo) == 0,
              descriptorInfo.st_dev == rootDevice, descriptorInfo.st_ino == rootInode,
              (descriptorInfo.st_mode & S_IFMT) == S_IFDIR,
              descriptorInfo.st_uid == geteuid(), descriptorInfo.st_mode & 0o077 == 0,
              lstat(rootPath, &pathInfo) == 0,
              (pathInfo.st_mode & S_IFMT) == S_IFDIR,
              pathInfo.st_dev == rootDevice, pathInfo.st_ino == rootInode else {
            throw AgentPassNativeError.invalidSignature("Device audit outbox root was substituted or permissions changed")
        }
    }

    private static func prepareRoot(_ path: String) throws {
        var info = stat()
        if lstat(path, &info) != 0 {
            guard errno == ENOENT else { throw posixError() }
            try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        }
        var prepared = stat()
        guard lstat(path, &prepared) == 0,
              (prepared.st_mode & S_IFMT) == S_IFDIR,
              prepared.st_uid == geteuid(), prepared.st_mode & 0o077 == 0 else {
            throw AgentPassNativeError.invalidConfiguration("Device audit outbox root must be a private service-owned directory")
        }
    }

    private static func headData(_ head: NativeDeviceAuditHead) throws -> Data {
        try NativeStrictJSON.data([
            "last_hash": head.lastHash,
            "last_event_id": head.lastEventID ?? NSNull()
        ])
    }

    private static func validateHead(_ head: NativeDeviceAuditHead) throws {
        guard head.lastHash.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
            throw AgentPassNativeError.invalidSignature("Device audit head hash is invalid")
        }
        if let eventID = head.lastEventID {
            guard isUUID(eventID), eventID == eventID.lowercased() else {
                throw AgentPassNativeError.invalidSignature("Device audit head event ID is invalid")
            }
        }
    }

    private static func isUUID(_ value: String) -> Bool {
        guard let uuid = UUID(uuidString: value) else { return false }
        return uuid.uuidString.lowercased() == value.lowercased()
    }

    private static func fileName(_ eventID: String) -> String { "event_\(eventID.lowercased()).json" }

    private static func isEventName(_ name: String) -> Bool {
        name.range(of: "^event_[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\.json$", options: .regularExpression) != nil
    }

    private static func isTemporaryName(_ name: String) -> Bool {
        name.range(of: "^(\\.head\\.json|event_[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\.json)\\.tmp-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", options: .regularExpression) != nil
    }

    private static func writeAll(_ data: Data, to descriptor: Int32) throws {
        try data.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else {
                throw AgentPassNativeError.invalidConfiguration("Device audit outbox file is empty")
            }
            var offset = 0
            while offset < buffer.count {
                let count = Darwin.write(descriptor, base.advanced(by: offset), buffer.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw Self.posixError() }
                offset += count
            }
        }
    }

    private func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock(); defer { lock.unlock() }
        return try body()
    }

    private static func posixError() -> AgentPassNativeError {
        AgentPassNativeError.invalidConfiguration("Device audit outbox filesystem operation failed")
    }
}
