import Darwin
import Foundation

/// Durable, byte-exact queue for redacted Device audit events.
///
/// Each event is stored as one immutable private file.  A response may remove
/// only IDs which are currently pending; accepted and duplicate IDs are both
/// terminal from the device's perspective.  A lost response therefore leaves
/// the exact event bytes available for retry, while an equivocal response
/// cannot acknowledge an unrelated event.
public final class NativeDeviceAuditOutbox: @unchecked Sendable {
    public static let maximumPendingEvents = 4_096
    private static let maximumFileBytes = NativeDeviceAuditEvent.maxBytes
    private let rootPath: String
    private let lock = NSLock()

    public init(rootPath: String) throws {
        guard rootPath.hasPrefix("/") else { throw AgentPassNativeError.invalidConfiguration("Device audit outbox root must be absolute") }
        let path = URL(fileURLWithPath: rootPath).standardizedFileURL.path
        try Self.prepareRoot(path)
        self.rootPath = path
        let existing = try FileManager.default.contentsOfDirectory(atPath: path)
        guard existing.count <= Self.maximumPendingEvents else { throw AgentPassNativeError.invalidSignature("Device audit outbox contains too many events") }
    }

    @discardableResult
    public func enqueue(_ event: NativeDeviceAuditEvent) throws -> NativeDeviceAuditEvent {
        let data = try event.canonicalData()
        guard data.count <= Self.maximumFileBytes else { throw AgentPassNativeError.invalidConfiguration("Device audit outbox event is too large") }
        return try withLock {
            try validateRoot()
            let name = Self.fileName(event.eventID)
            let path = URL(fileURLWithPath: rootPath).appendingPathComponent(name).path
            var existingInfo = stat()
            if lstat(path, &existingInfo) == 0 {
                let existing = try Self.readPrivateFile(path, maximumBytes: Self.maximumFileBytes)
                guard existing == data else { throw AgentPassNativeError.invalidSignature("Device audit outbox event ID was reused with different evidence") }
                return event
            }
            guard try pendingUnsafe().count < Self.maximumPendingEvents else { throw AgentPassNativeError.invalidConfiguration("Device audit outbox capacity is exhausted") }
            try Self.writeImmutable(path: path, data: data, directory: rootPath)
            return event
        }
    }

    public func pending(limit: Int = NativeDeviceAuditBatch.maxEvents) throws -> [NativeDeviceAuditEvent] {
        guard (1...NativeDeviceAuditBatch.maxEvents).contains(limit) else { throw AgentPassNativeError.invalidConfiguration("Device audit outbox batch limit is invalid") }
        return try withLock {
            try validateRoot()
            return try pendingUnsafe().prefix(limit).map { try NativeDeviceAuditEvent.decode($0) }
        }
    }

    /// Applies one Cloud ingestion response after the caller has verified its
    /// transport and device binding.  Unknown IDs, duplicate response IDs, or
    /// overlap between accepted and duplicate are rejected before deletion.
    public func acknowledge(_ response: NativeDeviceAuditIngestionResponse) throws {
        let acknowledged = response.acceptedEventIDs + response.duplicateEventIDs
        guard !acknowledged.isEmpty, Set(acknowledged).count == acknowledged.count else {
            throw AgentPassNativeError.invalidSignature("Device audit ingestion response has no unique acknowledged events")
        }
        try withLock {
            try validateRoot()
            let pending = try pendingFiles()
            let pendingIDs = Set(pending.compactMap { Self.eventID(from: $0.name) })
            guard Set(acknowledged).isSubset(of: pendingIDs) else {
                throw AgentPassNativeError.invalidSignature("Device audit ingestion response acknowledges an unknown event")
            }
            for eventID in acknowledged {
                let path = URL(fileURLWithPath: rootPath).appendingPathComponent(Self.fileName(eventID)).path
                var info = stat()
                guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_nlink == 1 else {
                    throw AgentPassNativeError.invalidSignature("Device audit outbox acknowledgement file is invalid")
                }
            }
            for eventID in acknowledged {
                let path = URL(fileURLWithPath: rootPath).appendingPathComponent(Self.fileName(eventID)).path
                guard unlink(path) == 0 else { throw Self.posixError() }
            }
            let directoryFD = open(rootPath, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
            guard directoryFD >= 0 else { throw Self.posixError() }
            defer { close(directoryFD) }
            guard fsync(directoryFD) == 0 else {
                // The unlink has happened; a directory durability failure must
                // fail closed and never be reported as a successful drain.
                throw Self.posixError()
            }
        }
    }

    private struct FileEntry { let name: String; let data: Data }

    private func pendingUnsafe() throws -> [Data] {
        try pendingFiles().sorted { $0.name < $1.name }.map(\.data)
    }

    private func pendingFiles() throws -> [FileEntry] {
        let names = try FileManager.default.contentsOfDirectory(atPath: rootPath)
        guard names.count <= Self.maximumPendingEvents else { throw AgentPassNativeError.invalidSignature("Device audit outbox contains too many events") }
        return try names.sorted().map { name in
            guard name.range(of: "^event_[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\.json$", options: .regularExpression) != nil else {
                throw AgentPassNativeError.invalidSignature("Device audit outbox contains an unexpected file")
            }
            let path = URL(fileURLWithPath: rootPath).appendingPathComponent(name).path
            return FileEntry(name: name, data: try Self.readPrivateFile(path, maximumBytes: Self.maximumFileBytes))
        }
    }

    private func withLock<T>(_ body: () throws -> T) rethrows -> T { lock.lock(); defer { lock.unlock() }; return try body() }
    private func validateRoot() throws { try Self.validatePrivateDirectory(rootPath) }

    private static func fileName(_ eventID: String) -> String { "event_\(eventID.lowercased()).json" }
    private static func eventID(from name: String) -> String? { String(name.dropFirst(6).dropLast(5)) }

    private static func prepareRoot(_ path: String) throws {
        var info = stat()
        if lstat(path, &info) != 0 {
            guard errno == ENOENT else { throw posixError() }
            try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        }
        try validatePrivateDirectory(path)
    }

    private static func validatePrivateDirectory(_ path: String) throws {
        var info = stat()
        guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == geteuid(), info.st_mode & 0o077 == 0 else {
            throw AgentPassNativeError.invalidConfiguration("Device audit outbox root must be a private service-owned directory")
        }
    }

    private static func readPrivateFile(_ path: String, maximumBytes: Int) throws -> Data {
        var before = stat()
        guard lstat(path, &before) == 0, (before.st_mode & S_IFMT) == S_IFREG,
              before.st_uid == geteuid(), before.st_mode & 0o0777 == 0o400,
              before.st_nlink == 1, before.st_size > 0, before.st_size <= maximumBytes else {
            throw AgentPassNativeError.invalidSignature("Device audit outbox file metadata is invalid")
        }
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw posixError() }
        defer { close(fd) }
        var result = Data(); var buffer = [UInt8](repeating: 0, count: 16 * 1024)
        while true {
            let count = Darwin.read(fd, &buffer, buffer.count)
            guard count >= 0 else { throw posixError() }
            if count == 0 { break }
            guard result.count + count <= maximumBytes else { throw AgentPassNativeError.invalidSignature("Device audit outbox file exceeds its bound") }
            result.append(buffer, count: count)
        }
        var after = stat()
        guard fstat(fd, &after) == 0, before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              result.count == Int(before.st_size) else { throw AgentPassNativeError.invalidSignature("Device audit outbox file changed while reading") }
        return result
    }

    private static func writeImmutable(path: String, data: Data, directory: String) throws {
        let temporary = path + ".tmp-\(UUID().uuidString.lowercased())"
        let fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o400)
        guard fd >= 0 else { throw posixError() }
        do {
            try data.withUnsafeBytes { buffer in
                guard let base = buffer.baseAddress else { throw AgentPassNativeError.invalidConfiguration("Device audit outbox event is empty") }
                var offset = 0
                while offset < buffer.count {
                    let count = Darwin.write(fd, base.advanced(by: offset), buffer.count - offset)
                    guard count > 0 else { throw posixError() }
                    offset += count
                }
            }
            guard fsync(fd) == 0, fchmod(fd, 0o400) == 0, close(fd) == 0 else { throw posixError() }
            guard rename(temporary, path) == 0 else { throw posixError() }
            let directoryFD = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
            guard directoryFD >= 0 else { throw posixError() }
            defer { close(directoryFD) }
            guard fsync(directoryFD) == 0 else { throw posixError() }
        } catch {
            close(fd)
            unlink(temporary)
            throw error
        }
    }

    private static func posixError() -> AgentPassNativeError { AgentPassNativeError.invalidConfiguration("Device audit outbox filesystem operation failed") }
}
