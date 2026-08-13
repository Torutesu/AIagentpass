import CryptoKit
import Darwin
import Foundation

public struct NativeAuditEvent: Sendable {
    public let operation: String
    public let decision: String
    public let requestID: String?
    public let reason: String?
    public let agentID: String?
    public let repository: String?
    public let branch: String?
    public let remote: String?
    public let payloadSHA256: String?
    public let expiresAt: String?

    public init(operation: String, decision: String, requestID: String? = nil, reason: String? = nil, agentID: String? = nil, repository: String? = nil, branch: String? = nil, remote: String? = nil, payloadSHA256: String? = nil, expiresAt: String? = nil) {
        self.operation = operation
        self.decision = decision
        self.requestID = requestID
        self.reason = reason
        self.agentID = agentID
        self.repository = repository
        self.branch = branch
        self.remote = remote
        self.payloadSHA256 = payloadSHA256
        self.expiresAt = expiresAt
    }
}

public struct NativeAuditStatus: Codable, Equatable, Sendable {
    public let valid: Bool
    public let entries: Int
    public let headHash: String
    enum CodingKeys: String, CodingKey { case valid, entries; case headHash = "head_hash" }
}

/// The durable identity of one record in the verified audit chain.
///
/// This is intentionally limited to the fields needed to reconcile a prepared
/// agent-session activation. It is not a generic audit-record query result.
public struct NativeAuditRecordReceipt: Equatable, Sendable {
    public let index: Int
    public let recordHash: String

    public init(index: Int, recordHash: String) throws {
        guard index >= 1,
              recordHash.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
            throw AgentPassNativeError.invalidSignature("Native audit record receipt is invalid")
        }
        self.index = index
        self.recordHash = recordHash
    }
}

/// Result of the narrowly-scoped lookup for an agent session activation audit.
/// The enum is deliberately closed: callers cannot treat an unverified record
/// or an ambiguous match as an exact durable audit receipt.
public enum NativeAuditAgentSessionActivationAuditLookup: Equatable, Sendable {
    case missing
    case exact(NativeAuditRecordReceipt)
    case conflict
}

public struct NativeAuditRotation: Codable, Equatable, Sendable {
    public let entries: Int
    public let headHash: String
    public let archiveFile: String
    enum CodingKeys: String, CodingKey {
        case entries
        case headHash = "head_hash"
        case archiveFile = "archive_file"
    }
}

public enum NativeAuditAppendPreflightAction: String, Codable, Equatable, Sendable {
    case append
    case rotateThenAppend = "rotate_then_append"
}

public struct NativeAuditAppendPreflight: Codable, Equatable, Sendable {
    public let action: NativeAuditAppendPreflightAction
    public let auditStatus: NativeAuditStatus
    public let activeBytes: Int
    public let appendBytes: Int
    public let projectedBytes: Int
    public let rotationThresholdBytes: Int
    public let verificationLimitBytes: Int
    public let archiveConfigured: Bool

    enum CodingKeys: String, CodingKey {
        case action
        case auditStatus = "audit_status"
        case activeBytes = "active_bytes"
        case appendBytes = "append_bytes"
        case projectedBytes = "projected_bytes"
        case rotationThresholdBytes = "rotation_threshold_bytes"
        case verificationLimitBytes = "verification_limit_bytes"
        case archiveConfigured = "archive_configured"
    }
}

/// Creates the durable checkpoint which must precede an automatic audit segment rotation.
/// The audit log's state lock is not held while this method runs, so implementations may
/// safely call `NativeAuditCheckpoints.create()`, which verifies the audit log.
public protocol NativeAuditRotationCheckpointing: Sendable {
    func checkpointBeforeAuditRotation(expectedAuditStatus: NativeAuditStatus) throws -> NativeAuditCheckpoint
}

public struct NativeAuditStorageStatus: Codable, Equatable, Sendable {
    public let configured: Bool
    public let segments: Int
    public let activeBytes: Int
    public let rotationReady: Bool
    enum CodingKeys: String, CodingKey {
        case configured, segments
        case activeBytes = "active_bytes"
        case rotationReady = "rotation_ready"
    }
}

public struct NativeAuditEvidenceStorageStatus: Codable, Equatable, Sendable {
    public let configured: Bool
    public let totalRecords: Int
    public let segments: Int
    public let activeRecords: Int
    public let activeBytes: Int
    public let rotationReady: Bool
    enum CodingKeys: String, CodingKey {
        case configured, segments
        case totalRecords = "total_records"
        case activeRecords = "active_records"
        case activeBytes = "active_bytes"
        case rotationReady = "rotation_ready"
    }
}

public struct NativeAuditEvidenceRotation: Codable, Equatable, Sendable {
    public let firstIndex: Int
    public let lastIndex: Int
    public let terminalHash: String
    public let archiveFile: String
    enum CodingKeys: String, CodingKey {
        case firstIndex = "first_index"
        case lastIndex = "last_index"
        case terminalHash = "terminal_hash"
        case archiveFile = "archive_file"
    }
}

public final class NativeAuditLog: @unchecked Sendable {
    public static let zeroHash = String(repeating: "0", count: 64)
    public static let defaultRotationMinimumBytes = 64 * 1024 * 1024
    public static let defaultVerificationLimitBytes = 128 * 1024 * 1024
    public static let defaultAppendRotationThresholdBytes = 120 * 1024 * 1024
    private let file: String
    private let archiveDirectory: String?
    private let verificationLimitBytes: Int
    private let appendRotationThresholdBytes: Int
    private let appendAndRotationLock = NSLock()
    private let lock = NSLock()

    public init(path: String, archiveDirectory: String? = nil, verificationLimitBytes: Int = NativeAuditLog.defaultVerificationLimitBytes, appendRotationThresholdBytes: Int = NativeAuditLog.defaultAppendRotationThresholdBytes) throws {
        guard path.hasPrefix("/") else { throw AgentPassNativeError.invalidConfiguration("Native audit path must be absolute") }
        guard verificationLimitBytes > 0,
              appendRotationThresholdBytes > 0,
              appendRotationThresholdBytes < verificationLimitBytes else {
            throw AgentPassNativeError.invalidConfiguration("Native audit append rotation threshold must be positive and below the verification limit")
        }
        file = URL(fileURLWithPath: path).standardizedFileURL.path
        self.verificationLimitBytes = verificationLimitBytes
        self.appendRotationThresholdBytes = appendRotationThresholdBytes
        if let archiveDirectory {
            guard archiveDirectory.hasPrefix("/") else { throw AgentPassNativeError.invalidConfiguration("Native audit archive directory must be absolute") }
            let directory = URL(fileURLWithPath: archiveDirectory).standardizedFileURL.path
            try validatePrivateDirectory(directory, label: "Native audit archive directory")
            let activeParent = URL(fileURLWithPath: file).deletingLastPathComponent().path
            guard directory != activeParent else { throw AgentPassNativeError.invalidConfiguration("Native audit archive directory must be separate from the active log directory") }
            var archiveInfo = stat()
            var parentInfo = stat()
            guard stat(directory, &archiveInfo) == 0, stat(activeParent, &parentInfo) == 0, archiveInfo.st_dev == parentInfo.st_dev else {
                throw AgentPassNativeError.invalidConfiguration("Native audit archive and active log must be on the same filesystem")
            }
            self.archiveDirectory = directory
        } else {
            self.archiveDirectory = nil
        }
        if try pathEntryExists(file) { try validatePrivateRegularFile(file, label: "Native audit log") }
    }

    public func verify() throws -> NativeAuditStatus {
        lock.lock()
        defer { lock.unlock() }
        return try verifyUnlocked()
    }

    /// Looks up one exact `agent.session.session_activated` audit event.
    ///
    /// The complete active log and every configured archive are verified while
    /// the audit lock is held. Only an exact, unique `(sessionID,
    /// evidenceDigest)` pair can produce `.exact`; duplicate or substituted
    /// activation evidence produces `.conflict`. This method never appends.
    public func lookupAgentSessionActivationAudit(sessionID: UUID, expectedAgentID: UUID, evidenceDigest: Data) throws -> NativeAuditAgentSessionActivationAuditLookup {
        guard evidenceDigest.count == 32 else {
            throw AgentPassNativeError.invalidConfiguration("Native audit evidence digest must contain 32 bytes")
        }
        let sessionID = sessionID.uuidString.lowercased()
        let expectedAgentID = expectedAgentID.uuidString.lowercased()
        let evidenceDigest = evidenceDigest.map { String(format: "%02x", $0) }.joined()
        let activationKeys: Set<String> = ["timestamp", "previous_hash", "operation", "decision", "request_id", "agent_id", "payload_sha256"]
        appendAndRotationLock.lock()
        defer { appendAndRotationLock.unlock() }
        lock.lock()
        defer { lock.unlock() }

        var matches: [NativeAuditRecordReceipt] = []
        var conflictingCandidate = false
        _ = try verifyUnlocked(onRecord: { index, recordHash, record in
            guard record["operation"] as? String == "agent.session.session_activated" else { return }
            guard Set(record.keys) == activationKeys else {
                throw AgentPassNativeError.invalidSignature("Native session activation audit record has an invalid field set")
            }
            guard let decision = record["decision"] as? String,
                  decision == "allow",
                  let requestID = record["request_id"] as? String,
                  let agentID = record["agent_id"] as? String,
                  let payloadSHA256 = record["payload_sha256"] as? String else {
                throw AgentPassNativeError.invalidSignature("Native session activation audit record is malformed")
            }
            guard requestID == requestID.lowercased(),
                  UUID(uuidString: requestID)?.uuidString.lowercased() == requestID,
                  agentID == agentID.lowercased(),
                  UUID(uuidString: agentID)?.uuidString.lowercased() == agentID,
                  payloadSHA256.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
                throw AgentPassNativeError.invalidSignature("Native session activation audit identity is malformed")
            }
            if requestID == sessionID && agentID == expectedAgentID && payloadSHA256 == evidenceDigest {
                matches.append(try NativeAuditRecordReceipt(index: index, recordHash: recordHash))
            } else if requestID == sessionID || payloadSHA256 == evidenceDigest {
                conflictingCandidate = true
            }
        })

        guard !conflictingCandidate, matches.count == 1 else {
            if matches.isEmpty && !conflictingCandidate { return .missing }
            return .conflict
        }
        return .exact(matches[0])
    }

    /// Hex convenience overload. The string must already be lowercase and
    /// exactly 64 hexadecimal characters; normalization is intentionally not
    /// performed at this untrusted boundary.
    public func lookupAgentSessionActivationAudit(sessionID: UUID, expectedAgentID: UUID, evidenceDigest: String) throws -> NativeAuditAgentSessionActivationAuditLookup {
        guard evidenceDigest.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
            throw AgentPassNativeError.invalidConfiguration("Native audit evidence digest must be lowercase hexadecimal")
        }
        var bytes = Data(capacity: 32)
        var cursor = evidenceDigest.startIndex
        while cursor < evidenceDigest.endIndex {
            let next = evidenceDigest.index(cursor, offsetBy: 2)
            guard let byte = UInt8(evidenceDigest[cursor..<next], radix: 16) else {
                throw AgentPassNativeError.invalidConfiguration("Native audit evidence digest is invalid")
            }
            bytes.append(byte)
            cursor = next
        }
        return try lookupAgentSessionActivationAudit(sessionID: sessionID, expectedAgentID: expectedAgentID, evidenceDigest: bytes)
    }

    func verify(headsAtEntries requestedEntries: Set<Int>) throws -> (status: NativeAuditStatus, heads: [Int: String]) {
        lock.lock()
        defer { lock.unlock() }
        guard requestedEntries.allSatisfy({ $0 >= 0 }) else {
            throw AgentPassNativeError.invalidSignature("Native audit checkpoint entry count is invalid")
        }
        var heads: [Int: String] = requestedEntries.contains(0) ? [0: Self.zeroHash] : [:]
        let status = try verifyUnlocked { entries, hash in
            if requestedEntries.contains(entries) { heads[entries] = hash }
        }
        guard heads.count == requestedEntries.count else {
            throw AgentPassNativeError.invalidSignature("Native audit checkpoint is ahead of the audit log")
        }
        return (status, heads)
    }

    public func canRotate(minimumBytes: Int = NativeAuditLog.defaultRotationMinimumBytes) throws -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard minimumBytes > 0 else { throw AgentPassNativeError.invalidConfiguration("Native audit rotation threshold must be positive") }
        guard archiveDirectory != nil else { throw AgentPassNativeError.invalidConfiguration("Native audit archive directory is not configured") }
        _ = try verifyUnlocked()
        return try activeBytesUnlocked() >= minimumBytes
    }

    public func storageStatus() throws -> NativeAuditStorageStatus {
        lock.lock()
        defer { lock.unlock() }
        _ = try verifyUnlocked()
        let bytes = try activeBytesUnlocked()
        let segments = try archiveDirectory.map { try archiveSegments(directory: $0).count } ?? 0
        return NativeAuditStorageStatus(configured: archiveDirectory != nil, segments: segments, activeBytes: bytes, rotationReady: archiveDirectory != nil && bytes >= Self.defaultRotationMinimumBytes)
    }

    public func preflightAppend(_ event: NativeAuditEvent, timestamp: Date = Date()) throws -> NativeAuditAppendPreflight {
        appendAndRotationLock.lock()
        defer { appendAndRotationLock.unlock() }
        lock.lock()
        defer { lock.unlock() }
        let status = try verifyUnlocked()
        let appendData = try encodedRecord(event, timestamp: timestamp, previousHash: status.headHash)
        return try appendPreflightUnlocked(status: status, appendBytes: appendData.count)
    }

    @discardableResult
    public func append(_ event: NativeAuditEvent, timestamp: Date = Date(), rotationCheckpointing: (any NativeAuditRotationCheckpointing)? = nil) throws -> NativeAuditStatus {
        appendAndRotationLock.lock()
        defer { appendAndRotationLock.unlock() }

        lock.lock()
        var status: NativeAuditStatus
        var appendData: Data
        var preflight: NativeAuditAppendPreflight
        do {
            status = try verifyUnlocked()
            appendData = try encodedRecord(event, timestamp: timestamp, previousHash: status.headHash)
            preflight = try appendPreflightUnlocked(status: status, appendBytes: appendData.count)
            lock.unlock()
        } catch {
            lock.unlock()
            throw error
        }

        if preflight.action == .rotateThenAppend {
            guard archiveDirectory != nil else {
                throw AgentPassNativeError.invalidConfiguration("Native audit append stopped before the verification ceiling: configure an audit archive directory (active=\(preflight.activeBytes) bytes, projected=\(preflight.projectedBytes), rotation_threshold=\(preflight.rotationThresholdBytes), verification_limit=\(preflight.verificationLimitBytes))")
            }
            guard let rotationCheckpointing else {
                throw AgentPassNativeError.invalidConfiguration("Native audit append requires a checkpoint before rotation: pass rotationCheckpointing backed by NativeAuditCheckpoints")
            }
            let checkpoint = try rotationCheckpointing.checkpointBeforeAuditRotation(expectedAuditStatus: status)
            guard checkpoint.entries == status.entries, checkpoint.headHash == status.headHash else {
                throw AgentPassNativeError.invalidSignature("Native audit rotation checkpoint does not bind the expected audit head")
            }

            lock.lock()
            do {
                let current = try verifyUnlocked()
                guard current == status else {
                    throw AgentPassNativeError.invalidSignature("Native audit changed while preparing its rotation; retry the append")
                }
                _ = try rotateUnlocked(minimumBytes: 1, status: current)
                status = try verifyUnlocked()
                appendData = try encodedRecord(event, timestamp: timestamp, previousHash: status.headHash)
                preflight = try appendPreflightUnlocked(status: status, appendBytes: appendData.count)
                guard preflight.action == .append else {
                    throw AgentPassNativeError.invalidConfiguration("Native audit event cannot fit below the configured rotation threshold")
                }
                try durableAppend(path: file, data: appendData)
                lock.unlock()
            } catch {
                lock.unlock()
                throw error
            }
        } else {
            lock.lock()
            do {
                let current = try verifyUnlocked()
                guard current == status else {
                    throw AgentPassNativeError.invalidSignature("Native audit changed after append preflight; retry the append")
                }
                try durableAppend(path: file, data: appendData)
                lock.unlock()
            } catch {
                lock.unlock()
                throw error
            }
        }

        return NativeAuditStatus(valid: true, entries: status.entries + 1, headHash: try recordHash(appendData))
    }

    private func encodedRecord(_ event: NativeAuditEvent, timestamp: Date, previousHash: String) throws -> Data {
        guard !event.operation.isEmpty, event.operation.utf8.count <= 64, ["allow", "deny", "error"].contains(event.decision) else {
            throw AgentPassNativeError.invalidConfiguration("Native audit event operation or decision is invalid")
        }
        var record: [String: Any] = [
            "timestamp": auditTimestamp(timestamp),
            "previous_hash": previousHash,
            "operation": event.operation,
            "decision": event.decision
        ]
        if let value = event.reason { record["reason"] = Self.bounded(value, bytes: 1024) }
        if let value = event.requestID {
            guard UUID(uuidString: value) != nil else { throw AgentPassNativeError.invalidConfiguration("Native audit request ID is invalid") }
            record["request_id"] = value.lowercased()
        }
        if let value = event.agentID { record["agent_id"] = Self.bounded(value, bytes: 128) }
        if let value = event.repository { record["repository"] = Self.bounded(value, bytes: 4096) }
        if let value = event.branch { record["branch"] = Self.bounded(value, bytes: 512) }
        if let value = event.remote { record["remote"] = Self.bounded(value, bytes: 4096) }
        if let value = event.payloadSHA256 {
            guard value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else { throw AgentPassNativeError.invalidConfiguration("Native audit payload hash is invalid") }
            record["payload_sha256"] = value
        }
        if let value = event.expiresAt {
            guard value.utf8.count <= 64, isAuditTimestamp(value) else { throw AgentPassNativeError.invalidConfiguration("Native audit expiry timestamp is invalid") }
            record["expires_at"] = value
        }
        record["hash"] = Self.hash(try Self.canonical(record))
        return try Self.canonical(record) + Data("\n".utf8)
    }

    private func appendPreflightUnlocked(status: NativeAuditStatus, appendBytes: Int) throws -> NativeAuditAppendPreflight {
        let activeBytes = try activeBytesUnlocked()
        guard appendBytes <= appendRotationThresholdBytes else {
            throw AgentPassNativeError.invalidConfiguration("Native audit event exceeds the configured append rotation threshold")
        }
        let (projectedBytes, overflow) = activeBytes.addingReportingOverflow(appendBytes)
        guard !overflow else {
            throw AgentPassNativeError.invalidConfiguration("Native audit append would exceed the verification ceiling")
        }
        return NativeAuditAppendPreflight(
            action: projectedBytes > appendRotationThresholdBytes ? .rotateThenAppend : .append,
            auditStatus: status,
            activeBytes: activeBytes,
            appendBytes: appendBytes,
            projectedBytes: projectedBytes,
            rotationThresholdBytes: appendRotationThresholdBytes,
            verificationLimitBytes: verificationLimitBytes,
            archiveConfigured: archiveDirectory != nil
        )
    }

    private func recordHash(_ encodedRecord: Data) throws -> String {
        guard var record = try JSONSerialization.jsonObject(with: encodedRecord) as? [String: Any],
              let hash = record.removeValue(forKey: "hash") as? String else {
            throw AgentPassNativeError.invalidSignature("Native audit append result is invalid")
        }
        return hash
    }

    public func rotate(minimumBytes: Int = NativeAuditLog.defaultRotationMinimumBytes) throws -> NativeAuditRotation {
        appendAndRotationLock.lock()
        defer { appendAndRotationLock.unlock() }
        lock.lock()
        defer { lock.unlock() }
        let status = try verifyUnlocked()
        return try rotateUnlocked(minimumBytes: minimumBytes, status: status)
    }

    private func rotateUnlocked(minimumBytes: Int, status: NativeAuditStatus) throws -> NativeAuditRotation {
        guard minimumBytes > 0 else { throw AgentPassNativeError.invalidConfiguration("Native audit rotation threshold must be positive") }
        guard let archiveDirectory else { throw AgentPassNativeError.invalidConfiguration("Native audit archive directory is not configured") }
        try validatePrivateDirectory(archiveDirectory, label: "Native audit archive directory")
        guard try pathEntryExists(file) else { throw AgentPassNativeError.invalidConfiguration("Native audit log does not exist") }
        try validatePrivateRegularFile(file, label: "Native audit log")
        var info = stat()
        guard lstat(file, &info) == 0, info.st_size >= minimumBytes, info.st_size > 0 else {
            throw AgentPassNativeError.invalidConfiguration("Native audit log has not reached the rotation threshold")
        }
        let name = Self.archiveName(entries: status.entries, headHash: status.headHash)
        let destination = URL(fileURLWithPath: archiveDirectory).appendingPathComponent(name).path
        guard !(try pathEntryExists(destination)) else { throw AgentPassNativeError.invalidSignature("Native audit archive segment already exists") }
        guard Darwin.rename(file, destination) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let descriptor = open(destination, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { close(descriptor) }
        guard fchmod(descriptor, 0o400) == 0, fsync(descriptor) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        try fsyncDirectory(archiveDirectory)
        let activeParent = URL(fileURLWithPath: file).deletingLastPathComponent().path
        if activeParent != archiveDirectory { try fsyncDirectory(activeParent) }
        return NativeAuditRotation(entries: status.entries, headHash: status.headHash, archiveFile: name)
    }

    private func verifyUnlocked(onEntry: ((Int, String) -> Void)? = nil, onRecord: ((Int, String, [String: Any]) throws -> Void)? = nil) throws -> NativeAuditStatus {
        var previous = Self.zeroHash
        var entries = 0
        if let archiveDirectory {
            try validatePrivateDirectory(archiveDirectory, label: "Native audit archive directory")
            for segment in try archiveSegments(directory: archiveDirectory) {
                let before = entries
                try verifySegment(path: segment.path, label: "Native audit archive segment", previous: &previous, entries: &entries, onEntry: onEntry, onRecord: onRecord)
                guard entries > before, entries == segment.entries, previous == segment.headHash else {
                    throw AgentPassNativeError.invalidSignature("Native audit archive filename does not match its terminal state")
                }
            }
        }
        if try pathEntryExists(file) {
            try verifySegment(path: file, label: "Native audit log", previous: &previous, entries: &entries, onEntry: onEntry, onRecord: onRecord)
        }
        return NativeAuditStatus(valid: true, entries: entries, headHash: previous)
    }

    private func activeBytesUnlocked() throws -> Int {
        guard try pathEntryExists(file) else { return 0 }
        try validatePrivateRegularFile(file, label: "Native audit log")
        var info = stat()
        guard lstat(file, &info) == 0, info.st_size >= 0, info.st_size <= Int.max else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        return Int(info.st_size)
    }

    private func verifySegment(path: String, label: String, previous: inout String, entries: inout Int, onEntry: ((Int, String) -> Void)? = nil, onRecord: ((Int, String, [String: Any]) throws -> Void)? = nil) throws {
        try validatePrivateRegularFile(path, label: label)
        let data = try Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe)
        guard data.count <= verificationLimitBytes else { throw AgentPassNativeError.invalidSignature("\(label) exceeds the verification limit") }
        try validateJSONLinesFraming(data, label: label)
        for line in data.split(separator: 0x0a, omittingEmptySubsequences: true) {
            let object: Any
            do {
                object = try JSONSerialization.jsonObject(with: Data(line))
            } catch {
                throw AgentPassNativeError.invalidSignature("\(label) contains malformed JSON")
            }
            guard var record = object as? [String: Any],
                  let expected = record.removeValue(forKey: "hash") as? String,
                  expected.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
                  let previousHash = record["previous_hash"] as? String,
                  previousHash.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
                  previousHash == previous,
                  let timestamp = record["timestamp"] as? String, isAuditTimestamp(timestamp),
                  let operation = record["operation"] as? String, !operation.isEmpty, operation.utf8.count <= 64,
                  let decision = record["decision"] as? String, ["allow", "deny", "error"].contains(decision),
                  Self.validOptionalString(record, key: "reason", bytes: 1024),
                  Self.validOptionalUUID(record, key: "request_id"),
                  Self.validOptionalString(record, key: "agent_id", bytes: 128),
                  Self.validOptionalString(record, key: "repository", bytes: 4096),
                  Self.validOptionalString(record, key: "branch", bytes: 512),
                  Self.validOptionalString(record, key: "remote", bytes: 4096),
                  Self.validOptionalHash(record, key: "payload_sha256"),
                  Self.validOptionalTimestamp(record, key: "expires_at"),
                  expected == Self.hash(try Self.canonical(record)) else {
                throw AgentPassNativeError.invalidSignature("Native audit chain is invalid at entry \(entries + 1)")
            }
            var canonicalRecord = record
            canonicalRecord["hash"] = expected
            guard try Self.canonical(canonicalRecord) == Data(line) else {
                throw AgentPassNativeError.invalidSignature("Native audit record is not canonical at entry \(entries + 1)")
            }
            previous = expected
            guard entries < Int.max else { throw AgentPassNativeError.invalidSignature("Native audit entry count exceeds the supported range") }
            entries += 1
            onEntry?(entries, expected)
            try onRecord?(entries, expected, record)
        }
    }

    private func archiveSegments(directory: String) throws -> [(path: String, entries: Int, headHash: String)] {
        let names = try FileManager.default.contentsOfDirectory(atPath: directory)
        var result: [(path: String, entries: Int, headHash: String)] = []
        for name in names {
            guard let parsed = Self.parseArchiveName(name) else {
                throw AgentPassNativeError.invalidConfiguration("Native audit archive directory contains an unknown entry")
            }
            result.append((URL(fileURLWithPath: directory).appendingPathComponent(name).path, parsed.entries, parsed.headHash))
        }
        result.sort { $0.entries < $1.entries }
        if result.count > 1 {
            for index in 1..<result.count where result[index - 1].entries >= result[index].entries {
                throw AgentPassNativeError.invalidSignature("Native audit archive segment order is invalid")
            }
        }
        return result
    }

    private static func archiveName(entries: Int, headHash: String) -> String {
        "audit-\(String(format: "%020d", entries))-\(headHash).jsonl"
    }

    private static func parseArchiveName(_ name: String) -> (entries: Int, headHash: String)? {
        guard name.range(of: "^audit-[0-9]{20}-[0-9a-f]{64}\\.jsonl$", options: .regularExpression) != nil else { return nil }
        let start = name.index(name.startIndex, offsetBy: 6)
        let countEnd = name.index(start, offsetBy: 20)
        let hashStart = name.index(countEnd, offsetBy: 1)
        let hashEnd = name.index(hashStart, offsetBy: 64)
        guard let entries = Int(name[start..<countEnd]), entries > 0 else { return nil }
        return (entries, String(name[hashStart..<hashEnd]))
    }

    static func canonical(_ object: [String: Any]) throws -> Data {
        guard JSONSerialization.isValidJSONObject(object) else { throw AgentPassNativeError.invalidSignature("Native audit record is not valid JSON") }
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    }

    static func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }

    private static func bounded(_ value: String, bytes: Int) -> String {
        if value.utf8.count <= bytes { return value }
        var result = ""
        var used = 0
        for character in value {
            let count = String(character).utf8.count
            if used + count > bytes { break }
            result.append(character)
            used += count
        }
        return result
    }

    private static func validOptionalString(_ record: [String: Any], key: String, bytes: Int) -> Bool {
        guard let value = record[key] else { return true }
        guard let string = value as? String else { return false }
        return string.utf8.count <= bytes
    }

    private static func validOptionalUUID(_ record: [String: Any], key: String) -> Bool {
        guard let value = record[key] else { return true }
        guard let string = value as? String, UUID(uuidString: string)?.uuidString.lowercased() == string else { return false }
        return true
    }

    private static func validOptionalHash(_ record: [String: Any], key: String) -> Bool {
        guard let value = record[key] else { return true }
        guard let string = value as? String else { return false }
        return string.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
    }

    private static func validOptionalTimestamp(_ record: [String: Any], key: String) -> Bool {
        guard let value = record[key] else { return true }
        guard let string = value as? String, string.utf8.count <= 64 else { return false }
        return isAuditTimestamp(string)
    }

}

public struct NativeAuditCheckpoint: Codable, Equatable, Sendable {
    public let version: Int
    public let createdAt: String
    public let entries: Int
    public let headHash: String
    public let previousCheckpointHash: String
    public let publicKeyFingerprint: String
    public let signature: String
    public let checkpointHash: String
    public let keyGeneration: Int?
    public let lifecycleHeadHash: String?
    enum CodingKeys: String, CodingKey {
        case version, entries, signature
        case createdAt = "created_at"
        case headHash = "head_hash"
        case previousCheckpointHash = "previous_checkpoint_hash"
        case publicKeyFingerprint = "public_key_fingerprint"
        case checkpointHash = "checkpoint_hash"
        case keyGeneration = "key_generation"
        case lifecycleHeadHash = "lifecycle_head_hash"
    }
}

public final class NativeAuditCheckpoints: @unchecked Sendable {
    public static let defaultRotationMinimumBytes = 64 * 1024 * 1024
    private let file: String
    private let archiveDirectory: String?
    private let auditLog: NativeAuditLog
    private let signer: P256MessageSigner
    private let verificationKeys: [String: P256.Signing.PublicKey]
    private let verificationGenerations: [String: Int]
    private let requireLifecycleBinding: Bool
    private let keyGeneration: Int?
    private let lifecycleHeadHash: String?
    private let lock = NSLock()

    public init(path: String, auditLog: NativeAuditLog, signer: P256MessageSigner, archiveDirectory: String? = nil, verificationPublicKeys: [Data] = [], verificationGenerations: [String: Int] = [:], keyGeneration: Int? = nil, lifecycleHeadHash: String? = nil, requireLifecycleBinding: Bool = false) throws {
        guard path.hasPrefix("/") else { throw AgentPassNativeError.invalidConfiguration("Native audit checkpoint path must be absolute") }
        file = URL(fileURLWithPath: path).standardizedFileURL.path
        self.archiveDirectory = try prepareEvidenceArchiveDirectory(archiveDirectory, activeFile: file, label: "Native audit checkpoint archive directory")
        self.auditLog = auditLog
        self.signer = signer
        guard (keyGeneration == nil) == (lifecycleHeadHash == nil),
              keyGeneration.map({ $0 > 0 }) ?? true,
              lifecycleHeadHash.map({ $0.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil }) ?? true else {
            throw AgentPassNativeError.invalidConfiguration("Native audit checkpoint lifecycle binding is incomplete or invalid")
        }
        self.keyGeneration = keyGeneration
        self.lifecycleHeadHash = lifecycleHeadHash
        self.requireLifecycleBinding = requireLifecycleBinding
        var keys: [String: P256.Signing.PublicKey] = [:]
        for raw in verificationPublicKeys + [signer.publicKeyX963] {
            let key = try P256.Signing.PublicKey(x963Representation: raw)
            let fingerprint = Self.fingerprint(raw)
            if let existing = keys[fingerprint], existing.x963Representation != key.x963Representation {
                throw AgentPassNativeError.invalidKey("Native audit verification-key fingerprint collision")
            }
            keys[fingerprint] = key
        }
        verificationKeys = keys
        guard verificationGenerations.allSatisfy({ fingerprint, generation in keys[fingerprint] != nil && generation > 0 }) else {
            throw AgentPassNativeError.invalidConfiguration("Native audit checkpoint generation map is invalid")
        }
        if let keyGeneration,
           verificationGenerations[Self.fingerprint(signer.publicKeyX963)] != keyGeneration {
            throw AgentPassNativeError.invalidConfiguration("Native audit checkpoint signer is not bound to its key generation")
        }
        self.verificationGenerations = verificationGenerations
        if requireLifecycleBinding, keyGeneration == nil {
            throw AgentPassNativeError.invalidConfiguration("Native audit checkpoints require lifecycle binding")
        }
        if try pathEntryExists(file) { try validatePrivateRegularFile(file, label: "Native audit checkpoint log") }
    }

    public func create(timestamp: Date = Date()) throws -> NativeAuditCheckpoint {
        lock.lock()
        defer { lock.unlock() }
        let audit = try auditLog.verify()
        let existing = try readAndVerifyUnlocked()
        var statement: [String: Any] = [
            "version": keyGeneration == nil ? 1 : 2,
            "created_at": auditTimestamp(timestamp),
            "entries": audit.entries,
            "head_hash": audit.headHash,
            "previous_checkpoint_hash": existing.last?.checkpointHash ?? NativeAuditLog.zeroHash
        ]
        if let keyGeneration, let lifecycleHeadHash {
            statement["key_generation"] = keyGeneration
            statement["lifecycle_head_hash"] = lifecycleHeadHash
        }
        let statementData = try NativeAuditLog.canonical(statement)
        let signature = try signer.sign(message: statementData).base64EncodedString()
        var record = statement
        record["public_key_fingerprint"] = Self.fingerprint(signer.publicKeyX963)
        record["signature"] = signature
        record["checkpoint_hash"] = NativeAuditLog.hash(try NativeAuditLog.canonical(record))
        let data = try NativeAuditLog.canonical(record)
        let checkpoint = try JSONDecoder().decode(NativeAuditCheckpoint.self, from: data)
        try durableAppend(path: file, data: data + Data("\n".utf8))
        return checkpoint
    }

    public func verify() throws -> [NativeAuditCheckpoint] {
        lock.lock()
        defer { lock.unlock() }
        return try readAndVerifyUnlocked()
    }

    public func storageStatus(minimumBytes: Int = NativeAuditCheckpoints.defaultRotationMinimumBytes) throws -> NativeAuditEvidenceStorageStatus {
        lock.lock()
        defer { lock.unlock() }
        guard minimumBytes > 0 else { throw AgentPassNativeError.invalidConfiguration("Native audit checkpoint rotation threshold must be positive") }
        let state = try readAndVerifyStorageUnlocked()
        let bytes = try privateRegularFileBytes(file, label: "Native audit checkpoint log")
        return NativeAuditEvidenceStorageStatus(configured: archiveDirectory != nil, totalRecords: state.records.count, segments: state.segments, activeRecords: state.activeRecords, activeBytes: bytes, rotationReady: archiveDirectory != nil && state.activeRecords > 0 && bytes >= minimumBytes)
    }

    @discardableResult
    public func rotate(minimumBytes: Int = NativeAuditCheckpoints.defaultRotationMinimumBytes) throws -> NativeAuditEvidenceRotation {
        lock.lock()
        defer { lock.unlock() }
        guard minimumBytes > 0 else { throw AgentPassNativeError.invalidConfiguration("Native audit checkpoint rotation threshold must be positive") }
        guard let archiveDirectory else { throw AgentPassNativeError.invalidConfiguration("Native audit checkpoint archive directory is not configured") }
        let state = try readAndVerifyStorageUnlocked()
        let bytes = try privateRegularFileBytes(file, label: "Native audit checkpoint log")
        guard state.activeRecords > 0, bytes >= minimumBytes, let terminal = state.records.last else {
            throw AgentPassNativeError.invalidConfiguration("Native audit checkpoint log has not reached the rotation threshold")
        }
        let first = state.records.count - state.activeRecords + 1
        let name = Self.archiveName(first: first, last: state.records.count, terminalHash: terminal.checkpointHash)
        try rotateEvidenceFile(file, archiveDirectory: archiveDirectory, archiveName: name)
        return NativeAuditEvidenceRotation(firstIndex: first, lastIndex: state.records.count, terminalHash: terminal.checkpointHash, archiveFile: name)
    }

    private func readAndVerifyUnlocked() throws -> [NativeAuditCheckpoint] {
        try readAndVerifyStorageUnlocked().records
    }

    private func readAndVerifyStorageUnlocked() throws -> (records: [NativeAuditCheckpoint], segments: Int, activeRecords: Int) {
        var previous = NativeAuditLog.zeroHash
        var previousEntries = 0
        var previousGeneration: Int?
        var activeFingerprint: String?
        var retiredFingerprints: Set<String> = []
        var result: [NativeAuditCheckpoint] = []
        let segments = try archiveDirectory.map { try Self.archiveSegments(directory: $0) } ?? []
        for segment in segments {
            let first = result.count + 1
            try readSegment(path: segment.path, label: "Native audit checkpoint archive segment", previous: &previous, previousEntries: &previousEntries, previousGeneration: &previousGeneration, activeFingerprint: &activeFingerprint, retiredFingerprints: &retiredFingerprints, result: &result)
            guard first == segment.first, result.count == segment.last, result.count >= first, previous == segment.terminalHash else {
                throw AgentPassNativeError.invalidSignature("Native audit checkpoint archive filename does not match its contents")
            }
        }
        let beforeActive = result.count
        if try pathEntryExists(file) {
            try readSegment(path: file, label: "Native audit checkpoint log", previous: &previous, previousEntries: &previousEntries, previousGeneration: &previousGeneration, activeFingerprint: &activeFingerprint, retiredFingerprints: &retiredFingerprints, result: &result)
        }
        let requested = Set(result.map(\.entries))
        let audit = try auditLog.verify(headsAtEntries: requested)
        guard result.allSatisfy({ audit.heads[$0.entries] == $0.headHash }) else {
            throw AgentPassNativeError.invalidSignature("Native audit checkpoint does not match the historical audit head")
        }
        return (result, segments.count, result.count - beforeActive)
    }

    private func readSegment(path: String, label: String, previous: inout String, previousEntries: inout Int, previousGeneration: inout Int?, activeFingerprint: inout String?, retiredFingerprints: inout Set<String>, result: inout [NativeAuditCheckpoint]) throws {
        let data = try readEvidenceSegment(path, label: label)
        for line in data.split(separator: 0x0a, omittingEmptySubsequences: true) {
            let checkpoint = try JSONDecoder().decode(NativeAuditCheckpoint.self, from: Data(line))
            let lifecycleBindingIsValid = checkpoint.version == 1
                ? !requireLifecycleBinding && checkpoint.keyGeneration == nil && checkpoint.lifecycleHeadHash == nil
                : checkpoint.version == 2 && (checkpoint.keyGeneration ?? 0) > 0 && checkpoint.lifecycleHeadHash?.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
            guard lifecycleBindingIsValid, checkpoint.previousCheckpointHash == previous,
                  checkpoint.entries >= previousEntries,
                  checkpoint.entries >= 0,
                  checkpoint.headHash.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
                  checkpoint.checkpointHash.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
                  isAuditTimestamp(checkpoint.createdAt),
                  let publicKey = verificationKeys[checkpoint.publicKeyFingerprint],
                  checkpoint.version == 1 || verificationGenerations[checkpoint.publicKeyFingerprint] == checkpoint.keyGeneration,
                  let signature = Data(base64Encoded: checkpoint.signature), signature.count == 64 else {
                throw AgentPassNativeError.invalidSignature("Native audit checkpoint chain is invalid")
            }
            if let generation = checkpoint.keyGeneration {
                guard previousGeneration.map({ generation >= $0 }) ?? true,
                      !retiredFingerprints.contains(checkpoint.publicKeyFingerprint) else {
                    throw AgentPassNativeError.invalidSignature("Native audit checkpoint key generation rolled back")
                }
                if let currentFingerprint = activeFingerprint, currentFingerprint != checkpoint.publicKeyFingerprint {
                    guard previousGeneration.map({ generation > $0 }) ?? true else {
                        throw AgentPassNativeError.invalidSignature("Native audit checkpoint key changed without a generation transition")
                    }
                    retiredFingerprints.insert(currentFingerprint)
                }
                previousGeneration = generation
                activeFingerprint = checkpoint.publicKeyFingerprint
            } else {
                guard previousGeneration == nil else {
                    throw AgentPassNativeError.invalidSignature("Native audit checkpoint lifecycle binding was removed")
                }
            }
            var statement: [String: Any] = ["version": checkpoint.version, "created_at": checkpoint.createdAt, "entries": checkpoint.entries, "head_hash": checkpoint.headHash, "previous_checkpoint_hash": checkpoint.previousCheckpointHash]
            if checkpoint.version == 2 {
                statement["key_generation"] = checkpoint.keyGeneration!
                statement["lifecycle_head_hash"] = checkpoint.lifecycleHeadHash!
            }
            let signed = try NativeAuditLog.canonical(statement)
            let ecdsa = try P256.Signing.ECDSASignature(rawRepresentation: signature)
            guard publicKey.isValidSignature(ecdsa, for: signed) else { throw AgentPassNativeError.invalidSignature("Native audit checkpoint signature is invalid") }
            var record = statement
            record["public_key_fingerprint"] = checkpoint.publicKeyFingerprint
            record["signature"] = checkpoint.signature
            record["checkpoint_hash"] = checkpoint.checkpointHash
            let canonicalRecord = try NativeAuditLog.canonical(record)
            var unhashed = record
            unhashed.removeValue(forKey: "checkpoint_hash")
            guard checkpoint.checkpointHash == NativeAuditLog.hash(try NativeAuditLog.canonical(unhashed)), canonicalRecord == Data(line) else { throw AgentPassNativeError.invalidSignature("Native audit checkpoint hash or canonical encoding is invalid") }
            previous = checkpoint.checkpointHash
            previousEntries = checkpoint.entries
            result.append(checkpoint)
        }
    }

    private static func archiveName(first: Int, last: Int, terminalHash: String) -> String {
        "checkpoints-\(String(format: "%020d", first))-\(String(format: "%020d", last))-\(terminalHash).jsonl"
    }

    private static func archiveSegments(directory: String) throws -> [(path: String, first: Int, last: Int, terminalHash: String)] {
        try validatePrivateDirectory(directory, label: "Native audit checkpoint archive directory")
        var result: [(String, Int, Int, String)] = []
        for name in try FileManager.default.contentsOfDirectory(atPath: directory) {
            guard name.range(of: "^checkpoints-[0-9]{20}-[0-9]{20}-[0-9a-f]{64}\\.jsonl$", options: .regularExpression) != nil else {
                throw AgentPassNativeError.invalidConfiguration("Native audit checkpoint archive directory contains an unknown entry")
            }
            let parts = name.dropLast(6).split(separator: "-")
            guard parts.count == 4, let first = Int(parts[1]), let last = Int(parts[2]), first > 0, last >= first else {
                throw AgentPassNativeError.invalidSignature("Native audit checkpoint archive filename is invalid")
            }
            result.append((URL(fileURLWithPath: directory).appendingPathComponent(name).path, first, last, String(parts[3])))
        }
        result.sort { $0.1 < $1.1 }
        var expected = 1
        for segment in result {
            guard segment.1 == expected, segment.2 < Int.max else { throw AgentPassNativeError.invalidSignature("Native audit checkpoint archive segment range has a gap or overlap") }
            expected = segment.2 + 1
        }
        return result
    }

    public static func fingerprint(_ publicKey: Data) -> String {
        let encoded = Data(SHA256.hash(data: publicKey)).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        return "SHA256:\(encoded)"
    }
}

extension NativeAuditCheckpoints: NativeAuditRotationCheckpointing {
    public func checkpointBeforeAuditRotation(expectedAuditStatus: NativeAuditStatus) throws -> NativeAuditCheckpoint {
        let checkpoint = try create()
        guard checkpoint.entries == expectedAuditStatus.entries,
              checkpoint.headHash == expectedAuditStatus.headHash else {
            throw AgentPassNativeError.invalidSignature("Native audit changed before its rotation checkpoint was created")
        }
        return checkpoint
    }
}

public struct NativeAuditAnchorReceipt: Codable, Equatable, Sendable {
    public let version: Int
    public let tenant: String
    public let index: Int
    public let checkpointHash: String
    public let receivedAt: String
    public let previousReceiptHash: String
    public let eventIndex: Int?
    public let previousEventHash: String?
    public let anchorKeyFingerprint: String
    public let signature: String
    public let receiptHash: String
    enum CodingKeys: String, CodingKey {
        case version, tenant, index, signature
        case checkpointHash = "checkpoint_hash"
        case receivedAt = "received_at"
        case previousReceiptHash = "previous_receipt_hash"
        case eventIndex = "event_index"
        case previousEventHash = "previous_event_hash"
        case anchorKeyFingerprint = "anchor_key_fingerprint"
        case receiptHash = "receipt_hash"
    }
}

public struct NativeAuditAnchorStatus: Codable, Equatable, Sendable {
    public let configured: Bool
    public let checkpoints: Int
    public let receipts: Int
    public let pending: Int
    public let latestReceiptHash: String?
    enum CodingKeys: String, CodingKey {
        case configured, checkpoints, receipts, pending
        case latestReceiptHash = "latest_receipt_hash"
    }
}

public final class NativeAuditAnchorReceipts: @unchecked Sendable {
    public static let defaultRotationMinimumBytes = 64 * 1024 * 1024
    private static let receiptV1Keys: Set<String> = ["version", "tenant", "index", "checkpoint_hash", "received_at", "previous_receipt_hash", "anchor_key_fingerprint", "signature", "receipt_hash"]
    private static let receiptV2Keys: Set<String> = receiptV1Keys.union(["event_index", "previous_event_hash"])
    private let file: String
    private let archiveDirectory: String?
    private let tenant: String
    private let anchorKey: Curve25519.Signing.PublicKey
    private let anchorKeyFingerprint: String
    private let lock = NSLock()

    public init(path: String, tenant: String, anchorPublicKeyPEM: String, archiveDirectory: String? = nil) throws {
        guard path.hasPrefix("/"), tenant.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", options: .regularExpression) != nil else {
            throw AgentPassNativeError.invalidConfiguration("Native audit anchor receipt path or tenant is invalid")
        }
        let parsed = try Self.ed25519PublicKey(anchorPublicKeyPEM)
        file = URL(fileURLWithPath: path).standardizedFileURL.path
        self.archiveDirectory = try prepareEvidenceArchiveDirectory(archiveDirectory, activeFile: file, label: "Native audit anchor receipt archive directory")
        self.tenant = tenant
        anchorKey = parsed.key
        anchorKeyFingerprint = "SHA256:" + Data(SHA256.hash(data: parsed.der)).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        if try pathEntryExists(file) { try validatePrivateRegularFile(file, label: "Native audit anchor receipt log") }
    }

    public func status(checkpoints: [NativeAuditCheckpoint]) throws -> NativeAuditAnchorStatus {
        lock.lock()
        defer { lock.unlock() }
        let receipts = try readAndVerifyUnlocked(checkpoints: checkpoints)
        return Self.status(checkpoints: checkpoints, receipts: receipts)
    }

    /// Returns the fully verified receipt chain. Rotation callers use the exact final receipt as
    /// the immutable old-key boundary; no unverified JSON is exposed through this API.
    public func verifiedReceipts(checkpoints: [NativeAuditCheckpoint]) throws -> [NativeAuditAnchorReceipt] {
        lock.lock()
        defer { lock.unlock() }
        return try readAndVerifyUnlocked(checkpoints: checkpoints)
    }

    public func pendingCheckpoint(checkpoints: [NativeAuditCheckpoint]) throws -> NativeAuditCheckpoint? {
        lock.lock()
        defer { lock.unlock() }
        let receipts = try readAndVerifyUnlocked(checkpoints: checkpoints)
        let latestIndex = receipts.last?.index ?? 0
        return latestIndex < checkpoints.count ? checkpoints[latestIndex] : nil
    }

    @discardableResult
    public func accept(receiptData: Data, checkpoint: NativeAuditCheckpoint, checkpoints: [NativeAuditCheckpoint]) throws -> NativeAuditAnchorStatus {
        lock.lock()
        defer { lock.unlock() }
        let receipts = try readAndVerifyUnlocked(checkpoints: checkpoints)
        let latestIndex = receipts.last?.index ?? 0
        guard latestIndex < checkpoints.count, checkpoints[latestIndex] == checkpoint else {
            throw AgentPassNativeError.invalidSignature("Native audit anchor receipt does not match the next local checkpoint")
        }
        let receipt = try Self.decodeReceipt(receiptData)
        try verify(receipt, checkpoint: checkpoint, previousReceipt: receipts.last, expectedIndex: latestIndex + 1, minimumReceivedAt: receipts.last.flatMap { Self.receiptDate($0.receivedAt) })
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        try durableAppend(path: file, data: try encoder.encode(receipt) + Data("\n".utf8))
        return Self.status(checkpoints: checkpoints, receipts: receipts + [receipt])
    }

    public func storageStatus(checkpoints: [NativeAuditCheckpoint], minimumBytes: Int = NativeAuditAnchorReceipts.defaultRotationMinimumBytes) throws -> NativeAuditEvidenceStorageStatus {
        lock.lock()
        defer { lock.unlock() }
        guard minimumBytes > 0 else { throw AgentPassNativeError.invalidConfiguration("Native audit anchor receipt rotation threshold must be positive") }
        let state = try readAndVerifyStorageUnlocked(checkpoints: checkpoints)
        let bytes = try privateRegularFileBytes(file, label: "Native audit anchor receipt log")
        return NativeAuditEvidenceStorageStatus(configured: archiveDirectory != nil, totalRecords: state.records.count, segments: state.segments, activeRecords: state.activeRecords, activeBytes: bytes, rotationReady: archiveDirectory != nil && state.activeRecords > 0 && bytes >= minimumBytes)
    }

    @discardableResult
    public func rotate(checkpoints: [NativeAuditCheckpoint], minimumBytes: Int = NativeAuditAnchorReceipts.defaultRotationMinimumBytes) throws -> NativeAuditEvidenceRotation {
        lock.lock()
        defer { lock.unlock() }
        guard minimumBytes > 0 else { throw AgentPassNativeError.invalidConfiguration("Native audit anchor receipt rotation threshold must be positive") }
        guard let archiveDirectory else { throw AgentPassNativeError.invalidConfiguration("Native audit anchor receipt archive directory is not configured") }
        let state = try readAndVerifyStorageUnlocked(checkpoints: checkpoints)
        let bytes = try privateRegularFileBytes(file, label: "Native audit anchor receipt log")
        guard state.activeRecords > 0, bytes >= minimumBytes, let terminal = state.records.last else {
            throw AgentPassNativeError.invalidConfiguration("Native audit anchor receipt log has not reached the rotation threshold")
        }
        let first = state.records.count - state.activeRecords + 1
        let name = Self.archiveName(first: first, last: state.records.count, terminalHash: terminal.receiptHash)
        try rotateEvidenceFile(file, archiveDirectory: archiveDirectory, archiveName: name)
        return NativeAuditEvidenceRotation(firstIndex: first, lastIndex: state.records.count, terminalHash: terminal.receiptHash, archiveFile: name)
    }

    private func readAndVerifyUnlocked(checkpoints: [NativeAuditCheckpoint]) throws -> [NativeAuditAnchorReceipt] {
        try readAndVerifyStorageUnlocked(checkpoints: checkpoints).records
    }

    private func readAndVerifyStorageUnlocked(checkpoints: [NativeAuditCheckpoint]) throws -> (records: [NativeAuditAnchorReceipt], segments: Int, activeRecords: Int) {
        var previous = NativeAuditLog.zeroHash
        var previousReceivedAt: Date?
        var receipts: [NativeAuditAnchorReceipt] = []
        let segments = try archiveDirectory.map { try Self.archiveSegments(directory: $0) } ?? []
        for segment in segments {
            let first = receipts.count + 1
            try readSegment(path: segment.path, label: "Native audit anchor receipt archive segment", checkpoints: checkpoints, previous: &previous, previousReceivedAt: &previousReceivedAt, receipts: &receipts)
            guard first == segment.first, receipts.count == segment.last, receipts.count >= first, previous == segment.terminalHash else {
                throw AgentPassNativeError.invalidSignature("Native audit anchor receipt archive filename does not match its contents")
            }
        }
        let beforeActive = receipts.count
        if try pathEntryExists(file) {
            try readSegment(path: file, label: "Native audit anchor receipt log", checkpoints: checkpoints, previous: &previous, previousReceivedAt: &previousReceivedAt, receipts: &receipts)
        }
        guard receipts.count <= checkpoints.count else { throw AgentPassNativeError.invalidSignature("Native audit anchor receipt log is ahead of local checkpoints") }
        return (receipts, segments.count, receipts.count - beforeActive)
    }

    private func readSegment(path: String, label: String, checkpoints: [NativeAuditCheckpoint], previous: inout String, previousReceivedAt: inout Date?, receipts: inout [NativeAuditAnchorReceipt]) throws {
        let data = try readEvidenceSegment(path, label: label)
        for line in data.split(separator: 0x0a, omittingEmptySubsequences: true) {
            let index = receipts.count
            guard index < checkpoints.count else { throw AgentPassNativeError.invalidSignature("Native audit anchor receipt log is ahead of local checkpoints") }
            let receipt = try Self.decodeReceipt(Data(line))
            try verify(receipt, checkpoint: checkpoints[index], previousReceipt: receipts.last, expectedIndex: index + 1, minimumReceivedAt: previousReceivedAt)
            previous = receipt.receiptHash
            previousReceivedAt = Self.receiptDate(receipt.receivedAt)
            receipts.append(receipt)
        }
    }

    private func verify(_ receipt: NativeAuditAnchorReceipt, checkpoint: NativeAuditCheckpoint, previousReceipt: NativeAuditAnchorReceipt?, expectedIndex: Int, minimumReceivedAt: Date?) throws {
        let receivedAt = Self.receiptDate(receipt.receivedAt)
        guard let receivedAt else { throw AgentPassNativeError.invalidSignature("Native audit anchor receipt timestamp is invalid") }
        let previousReceiptHash = previousReceipt?.receiptHash ?? NativeAuditLog.zeroHash
        let eventBindingIsValid: Bool
        if receipt.version == 1 {
            eventBindingIsValid = previousReceipt?.version != 2 && receipt.eventIndex == nil && receipt.previousEventHash == nil
        } else if receipt.version == 2, let eventIndex = receipt.eventIndex,
                  let previousEventHash = receipt.previousEventHash,
                  eventIndex >= expectedIndex,
                  previousEventHash.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil {
            if let previousEventIndex = previousReceipt?.eventIndex {
                eventBindingIsValid = eventIndex > previousEventIndex &&
                    (eventIndex != previousEventIndex + 1 || previousEventHash == previousReceipt?.receiptHash)
            } else {
                // A v2 checkpoint may follow the deterministic legacy event
                // origin or one or more transition events that this stream does
                // not store. Cross-stream callers bind the exact global tip.
                eventBindingIsValid = true
            }
        } else {
            eventBindingIsValid = false
        }
        guard eventBindingIsValid, receipt.tenant == tenant, receipt.index == expectedIndex,
              receipt.checkpointHash == checkpoint.checkpointHash, receipt.previousReceiptHash == previousReceiptHash,
              receipt.anchorKeyFingerprint == anchorKeyFingerprint,
              minimumReceivedAt.map({ receivedAt >= $0 }) ?? true,
              receipt.receiptHash.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
              let signature = Data(base64Encoded: receipt.signature), signature.count == 64 else {
            throw AgentPassNativeError.invalidSignature("Native audit anchor receipt statement is invalid")
        }
        var statement: [String: Any] = ["version": receipt.version, "tenant": receipt.tenant, "index": receipt.index, "checkpoint_hash": receipt.checkpointHash, "received_at": receipt.receivedAt, "previous_receipt_hash": receipt.previousReceiptHash]
        if receipt.version == 2 {
            statement["event_index"] = receipt.eventIndex
            statement["previous_event_hash"] = receipt.previousEventHash
        }
        guard anchorKey.isValidSignature(signature, for: try NativeAuditLog.canonical(statement)) else {
            throw AgentPassNativeError.invalidSignature("Native audit anchor receipt signature is invalid")
        }
        guard receipt.receiptHash == NativeAuditLog.hash(try Self.nodeReceiptHashData(receipt)) else {
            throw AgentPassNativeError.invalidSignature("Native audit anchor receipt hash is invalid")
        }
    }

    private static func decodeReceipt(_ data: Data) throws -> NativeAuditAnchorReceipt {
        guard data.count > 0, data.count <= 64 * 1024,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let version = object["version"] as? Int,
              Set(object.keys) == (version == 1 ? receiptV1Keys : version == 2 ? receiptV2Keys : []) else {
            throw AgentPassNativeError.invalidSignature("Native audit anchor receipt encoding is invalid")
        }
        return try JSONDecoder().decode(NativeAuditAnchorReceipt.self, from: data)
    }

    private static func status(checkpoints: [NativeAuditCheckpoint], receipts: [NativeAuditAnchorReceipt]) -> NativeAuditAnchorStatus {
        let latestIndex = receipts.last?.index ?? 0
        return NativeAuditAnchorStatus(configured: true, checkpoints: checkpoints.count, receipts: latestIndex, pending: checkpoints.count - latestIndex, latestReceiptHash: receipts.last?.receiptHash)
    }

    private static func archiveName(first: Int, last: Int, terminalHash: String) -> String {
        "receipts-\(String(format: "%020d", first))-\(String(format: "%020d", last))-\(terminalHash).jsonl"
    }

    private static func archiveSegments(directory: String) throws -> [(path: String, first: Int, last: Int, terminalHash: String)] {
        try validatePrivateDirectory(directory, label: "Native audit anchor receipt archive directory")
        var result: [(String, Int, Int, String)] = []
        for name in try FileManager.default.contentsOfDirectory(atPath: directory) {
            guard name.range(of: "^receipts-[0-9]{20}-[0-9]{20}-[0-9a-f]{64}\\.jsonl$", options: .regularExpression) != nil else {
                throw AgentPassNativeError.invalidConfiguration("Native audit anchor receipt archive directory contains an unknown entry")
            }
            let parts = name.dropLast(6).split(separator: "-")
            guard parts.count == 4, let first = Int(parts[1]), let last = Int(parts[2]), first > 0, last >= first else {
                throw AgentPassNativeError.invalidSignature("Native audit anchor receipt archive filename is invalid")
            }
            result.append((URL(fileURLWithPath: directory).appendingPathComponent(name).path, first, last, String(parts[3])))
        }
        result.sort { $0.1 < $1.1 }
        var expected = 1
        for segment in result {
            guard segment.1 == expected, segment.2 < Int.max else { throw AgentPassNativeError.invalidSignature("Native audit anchor receipt archive segment range has a gap or overlap") }
            expected = segment.2 + 1
        }
        return result
    }

    private static func receiptDate(_ value: String) -> Date? {
        guard value.utf8.count <= 64 else { return nil }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = fractional.date(from: value) { return date }
        let basic = ISO8601DateFormatter()
        basic.formatOptions = [.withInternetDateTime]
        return basic.date(from: value)
    }

    private static func nodeReceiptHashData(_ receipt: NativeAuditAnchorReceipt) throws -> Data {
        if receipt.version == 2 {
            let object: [String: Any] = [
                "version": receipt.version, "tenant": receipt.tenant, "index": receipt.index,
                "checkpoint_hash": receipt.checkpointHash, "received_at": receipt.receivedAt,
                "previous_receipt_hash": receipt.previousReceiptHash, "event_index": receipt.eventIndex!,
                "previous_event_hash": receipt.previousEventHash!, "anchor_key_fingerprint": receipt.anchorKeyFingerprint,
                "signature": receipt.signature
            ]
            return try NativeAuditLog.canonical(object)
        }
        let values: [Any] = [receipt.version, receipt.tenant, receipt.index, receipt.checkpointHash, receipt.receivedAt, receipt.previousReceiptHash, receipt.anchorKeyFingerprint, receipt.signature]
        let encoded = try values.map { value -> String in
            let data = try JSONSerialization.data(withJSONObject: [value], options: [.withoutEscapingSlashes])
            let array = String(decoding: data, as: UTF8.self)
            return String(array.dropFirst().dropLast())
        }
        let keys = ["version", "tenant", "index", "checkpoint_hash", "received_at", "previous_receipt_hash", "anchor_key_fingerprint", "signature"]
        return Data(("{" + zip(keys, encoded).map { pair in "\"\(pair.0)\":\(pair.1)" }.joined(separator: ",") + "}").utf8)
    }

    private static func ed25519PublicKey(_ pem: String) throws -> (key: Curve25519.Signing.PublicKey, der: Data) {
        let lines = pem.split(whereSeparator: \.isNewline).map(String.init)
        guard lines.first == "-----BEGIN PUBLIC KEY-----", lines.last == "-----END PUBLIC KEY-----", lines.count >= 3,
              let der = Data(base64Encoded: lines.dropFirst().dropLast().joined()), der.count == 44,
              der.prefix(12) == Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) else {
            throw AgentPassNativeError.invalidKey("Native audit anchor receipt key must be Ed25519 SPKI PEM")
        }
        return (try Curve25519.Signing.PublicKey(rawRepresentation: der.suffix(32)), der)
    }
}

private func durableAppend(path: String, data: Data) throws {
    guard !data.isEmpty else { throw AgentPassNativeError.invalidConfiguration("Native audit append must not be empty") }
    let existed = try pathEntryExists(path)
    let descriptor = open(path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
    guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    defer { close(descriptor) }
    guard flock(descriptor, LOCK_EX) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    defer { flock(descriptor, LOCK_UN) }
    try data.withUnsafeBytes { bytes in
        var offset = 0
        while offset < bytes.count {
            let written = Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
            guard written > 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            offset += written
        }
    }
    guard fchmod(descriptor, 0o600) == 0, fsync(descriptor) == 0 else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    if !existed {
        let parent = URL(fileURLWithPath: path).deletingLastPathComponent().path
        let directory = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard directory >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { close(directory) }
        guard fsync(directory) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    }
}

private func pathEntryExists(_ path: String) throws -> Bool {
    var info = stat()
    if lstat(path, &info) == 0 { return true }
    if errno == ENOENT { return false }
    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
}

private func validateJSONLinesFraming(_ data: Data, label: String) throws {
    guard data.isEmpty || (data.last == 0x0a && data.range(of: Data("\n\n".utf8)) == nil) else {
        throw AgentPassNativeError.invalidSignature("\(label) has incomplete or empty records")
    }
}

private func validatePrivateRegularFile(_ path: String, label: String) throws {
    var info = stat()
    guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
          info.st_uid == geteuid(), info.st_mode & 0o077 == 0, info.st_nlink == 1 else {
        throw AgentPassNativeError.invalidConfiguration("\(label) must be owned by the service account and be a private regular file")
    }
}

private func validatePrivateDirectory(_ path: String, label: String) throws {
    var info = stat()
    guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
          info.st_uid == geteuid(), info.st_mode & 0o077 == 0 else {
        throw AgentPassNativeError.invalidConfiguration("\(label) must be owned by the service account and be a private directory")
    }
}

private func fsyncDirectory(_ path: String) throws {
    let descriptor = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    defer { close(descriptor) }
    guard fsync(descriptor) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
}

private func prepareEvidenceArchiveDirectory(_ archiveDirectory: String?, activeFile: String, label: String) throws -> String? {
    guard let archiveDirectory else { return nil }
    guard archiveDirectory.hasPrefix("/") else { throw AgentPassNativeError.invalidConfiguration("\(label) must be absolute") }
    let directory = URL(fileURLWithPath: archiveDirectory).standardizedFileURL.path
    try validatePrivateDirectory(directory, label: label)
    let parent = URL(fileURLWithPath: activeFile).deletingLastPathComponent().path
    guard directory != parent else { throw AgentPassNativeError.invalidConfiguration("\(label) must be separate from the active log directory") }
    try validateSameFilesystem(directory, parent, label: label)
    return directory
}

private func validateSameFilesystem(_ directory: String, _ activeParent: String, label: String) throws {
    var archiveInfo = stat()
    var parentInfo = stat()
    guard stat(directory, &archiveInfo) == 0, stat(activeParent, &parentInfo) == 0, archiveInfo.st_dev == parentInfo.st_dev else {
        throw AgentPassNativeError.invalidConfiguration("\(label) and active log must be on the same filesystem")
    }
}

private func readEvidenceSegment(_ path: String, label: String) throws -> Data {
    try validatePrivateRegularFile(path, label: label)
    let data = try Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe)
    guard data.count <= 128 * 1024 * 1024 else { throw AgentPassNativeError.invalidSignature("\(label) exceeds the verification limit") }
    try validateJSONLinesFraming(data, label: label)
    return data
}

private func privateRegularFileBytes(_ path: String, label: String) throws -> Int {
    guard try pathEntryExists(path) else { return 0 }
    try validatePrivateRegularFile(path, label: label)
    var info = stat()
    guard lstat(path, &info) == 0, info.st_size >= 0, info.st_size <= Int.max else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    return Int(info.st_size)
}

private func rotateEvidenceFile(_ activeFile: String, archiveDirectory: String, archiveName: String) throws {
    try validatePrivateDirectory(archiveDirectory, label: "Native audit evidence archive directory")
    try validatePrivateRegularFile(activeFile, label: "Native audit evidence active log")
    let activeParent = URL(fileURLWithPath: activeFile).deletingLastPathComponent().path
    try validateSameFilesystem(archiveDirectory, activeParent, label: "Native audit evidence archive directory")
    let destination = URL(fileURLWithPath: archiveDirectory).appendingPathComponent(archiveName).path
    guard !(try pathEntryExists(destination)) else { throw AgentPassNativeError.invalidSignature("Native audit evidence archive segment already exists") }
    guard Darwin.rename(activeFile, destination) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    let descriptor = open(destination, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    defer { close(descriptor) }
    guard fchmod(descriptor, 0o400) == 0, fsync(descriptor) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    try fsyncDirectory(archiveDirectory)
    try fsyncDirectory(activeParent)
}

private func auditTimestamp(_ date: Date) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: date)
}

private func isAuditTimestamp(_ value: String) -> Bool {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.date(from: value) != nil
}
