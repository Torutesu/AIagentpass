import CryptoKit
import Darwin
import Foundation

public struct NativeAuditEvent: Sendable {
    public let operation: String
    public let decision: String
    public let reason: String?
    public let agentID: String?
    public let repository: String?
    public let branch: String?
    public let remote: String?
    public let payloadSHA256: String?
    public let expiresAt: String?

    public init(operation: String, decision: String, reason: String? = nil, agentID: String? = nil, repository: String? = nil, branch: String? = nil, remote: String? = nil, payloadSHA256: String? = nil, expiresAt: String? = nil) {
        self.operation = operation
        self.decision = decision
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

public final class NativeAuditLog: @unchecked Sendable {
    public static let zeroHash = String(repeating: "0", count: 64)
    private let file: String
    private let lock = NSLock()

    public init(path: String) throws {
        guard path.hasPrefix("/") else { throw AgentPassNativeError.invalidConfiguration("Native audit path must be absolute") }
        file = URL(fileURLWithPath: path).standardizedFileURL.path
        if try pathEntryExists(file) { try validatePrivateRegularFile(file, label: "Native audit log") }
    }

    public func verify() throws -> NativeAuditStatus {
        lock.lock()
        defer { lock.unlock() }
        return try verifyUnlocked()
    }

    @discardableResult
    public func append(_ event: NativeAuditEvent, timestamp: Date = Date()) throws -> NativeAuditStatus {
        lock.lock()
        defer { lock.unlock() }
        let status = try verifyUnlocked()
        guard !event.operation.isEmpty, event.operation.utf8.count <= 64, ["allow", "deny", "error"].contains(event.decision) else {
            throw AgentPassNativeError.invalidConfiguration("Native audit event operation or decision is invalid")
        }
        var record: [String: Any] = [
            "timestamp": auditTimestamp(timestamp),
            "previous_hash": status.headHash,
            "operation": event.operation,
            "decision": event.decision
        ]
        if let value = event.reason { record["reason"] = Self.bounded(value, bytes: 1024) }
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
        try durableAppend(path: file, data: try Self.canonical(record) + Data("\n".utf8))
        return NativeAuditStatus(valid: true, entries: status.entries + 1, headHash: record["hash"] as! String)
    }

    private func verifyUnlocked() throws -> NativeAuditStatus {
        guard try pathEntryExists(file) else { return NativeAuditStatus(valid: true, entries: 0, headHash: Self.zeroHash) }
        try validatePrivateRegularFile(file, label: "Native audit log")
        let data = try Data(contentsOf: URL(fileURLWithPath: file), options: .mappedIfSafe)
        guard data.count <= 128 * 1024 * 1024 else { throw AgentPassNativeError.invalidSignature("Native audit log exceeds the verification limit") }
        try validateJSONLinesFraming(data, label: "Native audit log")
        var previous = Self.zeroHash
        var entries = 0
        for line in data.split(separator: 0x0a, omittingEmptySubsequences: true) {
            guard var record = try JSONSerialization.jsonObject(with: Data(line)) as? [String: Any],
                  let expected = record.removeValue(forKey: "hash") as? String,
                  expected.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
                  let previousHash = record["previous_hash"] as? String,
                  previousHash.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
                  previousHash == previous,
                  let timestamp = record["timestamp"] as? String, isAuditTimestamp(timestamp),
                  let operation = record["operation"] as? String, !operation.isEmpty, operation.utf8.count <= 64,
                  let decision = record["decision"] as? String, ["allow", "deny", "error"].contains(decision),
                  Self.validOptionalString(record, key: "reason", bytes: 1024),
                  Self.validOptionalString(record, key: "agent_id", bytes: 128),
                  Self.validOptionalString(record, key: "repository", bytes: 4096),
                  Self.validOptionalString(record, key: "branch", bytes: 512),
                  Self.validOptionalString(record, key: "remote", bytes: 4096),
                  Self.validOptionalHash(record, key: "payload_sha256"),
                  Self.validOptionalTimestamp(record, key: "expires_at"),
                  expected == Self.hash(try Self.canonical(record)) else {
                throw AgentPassNativeError.invalidSignature("Native audit chain is invalid at entry \(entries + 1)")
            }
            previous = expected
            entries += 1
        }
        return NativeAuditStatus(valid: true, entries: entries, headHash: previous)
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
    enum CodingKeys: String, CodingKey {
        case version, entries, signature
        case createdAt = "created_at"
        case headHash = "head_hash"
        case previousCheckpointHash = "previous_checkpoint_hash"
        case publicKeyFingerprint = "public_key_fingerprint"
        case checkpointHash = "checkpoint_hash"
    }
}

public final class NativeAuditCheckpoints: @unchecked Sendable {
    private let file: String
    private let auditLog: NativeAuditLog
    private let signer: P256MessageSigner
    private let lock = NSLock()

    public init(path: String, auditLog: NativeAuditLog, signer: P256MessageSigner) throws {
        guard path.hasPrefix("/") else { throw AgentPassNativeError.invalidConfiguration("Native audit checkpoint path must be absolute") }
        file = URL(fileURLWithPath: path).standardizedFileURL.path
        self.auditLog = auditLog
        self.signer = signer
        if try pathEntryExists(file) { try validatePrivateRegularFile(file, label: "Native audit checkpoint log") }
    }

    public func create(timestamp: Date = Date()) throws -> NativeAuditCheckpoint {
        lock.lock()
        defer { lock.unlock() }
        let audit = try auditLog.verify()
        let existing = try readAndVerifyUnlocked()
        let statement: [String: Any] = [
            "version": 1,
            "created_at": auditTimestamp(timestamp),
            "entries": audit.entries,
            "head_hash": audit.headHash,
            "previous_checkpoint_hash": existing.last?.checkpointHash ?? NativeAuditLog.zeroHash
        ]
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

    private func readAndVerifyUnlocked() throws -> [NativeAuditCheckpoint] {
        guard try pathEntryExists(file) else { return [] }
        try validatePrivateRegularFile(file, label: "Native audit checkpoint log")
        let data = try Data(contentsOf: URL(fileURLWithPath: file), options: .mappedIfSafe)
        guard data.count <= 128 * 1024 * 1024 else { throw AgentPassNativeError.invalidSignature("Native audit checkpoint log exceeds the verification limit") }
        try validateJSONLinesFraming(data, label: "Native audit checkpoint log")
        var previous = NativeAuditLog.zeroHash
        var previousEntries = 0
        var result: [NativeAuditCheckpoint] = []
        let publicKey = try P256.Signing.PublicKey(x963Representation: signer.publicKeyX963)
        for line in data.split(separator: 0x0a, omittingEmptySubsequences: true) {
            let checkpoint = try JSONDecoder().decode(NativeAuditCheckpoint.self, from: Data(line))
            guard checkpoint.version == 1, checkpoint.previousCheckpointHash == previous,
                  checkpoint.entries >= previousEntries,
                  checkpoint.entries >= 0,
                  checkpoint.headHash.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
                  checkpoint.checkpointHash.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
                  isAuditTimestamp(checkpoint.createdAt),
                  checkpoint.publicKeyFingerprint == Self.fingerprint(signer.publicKeyX963),
                  let signature = Data(base64Encoded: checkpoint.signature), signature.count == 64 else {
                throw AgentPassNativeError.invalidSignature("Native audit checkpoint chain is invalid")
            }
            let statement: [String: Any] = ["version": checkpoint.version, "created_at": checkpoint.createdAt, "entries": checkpoint.entries, "head_hash": checkpoint.headHash, "previous_checkpoint_hash": checkpoint.previousCheckpointHash]
            let signed = try NativeAuditLog.canonical(statement)
            let ecdsa = try P256.Signing.ECDSASignature(rawRepresentation: signature)
            guard publicKey.isValidSignature(ecdsa, for: signed) else { throw AgentPassNativeError.invalidSignature("Native audit checkpoint signature is invalid") }
            var record = statement
            record["public_key_fingerprint"] = checkpoint.publicKeyFingerprint
            record["signature"] = checkpoint.signature
            guard checkpoint.checkpointHash == NativeAuditLog.hash(try NativeAuditLog.canonical(record)) else { throw AgentPassNativeError.invalidSignature("Native audit checkpoint hash is invalid") }
            previous = checkpoint.checkpointHash
            previousEntries = checkpoint.entries
            result.append(checkpoint)
        }
        let audit = try auditLog.verify()
        guard previousEntries <= audit.entries else { throw AgentPassNativeError.invalidSignature("Native audit checkpoint is ahead of the audit log") }
        if let latest = result.last, latest.entries == audit.entries, latest.headHash != audit.headHash {
            throw AgentPassNativeError.invalidSignature("Native audit checkpoint does not match the audit head")
        }
        return result
    }

    public static func fingerprint(_ publicKey: Data) -> String {
        let encoded = Data(SHA256.hash(data: publicKey)).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        return "SHA256:\(encoded)"
    }
}

public struct NativeAuditAnchorReceipt: Codable, Equatable, Sendable {
    public let version: Int
    public let tenant: String
    public let index: Int
    public let checkpointHash: String
    public let receivedAt: String
    public let previousReceiptHash: String
    public let anchorKeyFingerprint: String
    public let signature: String
    public let receiptHash: String
    enum CodingKeys: String, CodingKey {
        case version, tenant, index, signature
        case checkpointHash = "checkpoint_hash"
        case receivedAt = "received_at"
        case previousReceiptHash = "previous_receipt_hash"
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
    private static let receiptKeys: Set<String> = ["version", "tenant", "index", "checkpoint_hash", "received_at", "previous_receipt_hash", "anchor_key_fingerprint", "signature", "receipt_hash"]
    private let file: String
    private let tenant: String
    private let anchorKey: Curve25519.Signing.PublicKey
    private let anchorKeyFingerprint: String
    private let lock = NSLock()

    public init(path: String, tenant: String, anchorPublicKeyPEM: String) throws {
        guard path.hasPrefix("/"), tenant.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", options: .regularExpression) != nil else {
            throw AgentPassNativeError.invalidConfiguration("Native audit anchor receipt path or tenant is invalid")
        }
        let parsed = try Self.ed25519PublicKey(anchorPublicKeyPEM)
        file = URL(fileURLWithPath: path).standardizedFileURL.path
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

    public func pendingCheckpoint(checkpoints: [NativeAuditCheckpoint]) throws -> NativeAuditCheckpoint? {
        lock.lock()
        defer { lock.unlock() }
        let receipts = try readAndVerifyUnlocked(checkpoints: checkpoints)
        return receipts.count < checkpoints.count ? checkpoints[receipts.count] : nil
    }

    @discardableResult
    public func accept(receiptData: Data, checkpoint: NativeAuditCheckpoint, checkpoints: [NativeAuditCheckpoint]) throws -> NativeAuditAnchorStatus {
        lock.lock()
        defer { lock.unlock() }
        let receipts = try readAndVerifyUnlocked(checkpoints: checkpoints)
        guard receipts.count < checkpoints.count, checkpoints[receipts.count] == checkpoint else {
            throw AgentPassNativeError.invalidSignature("Native audit anchor receipt does not match the next local checkpoint")
        }
        let receipt = try Self.decodeReceipt(receiptData)
        try verify(receipt, checkpoint: checkpoint, previousReceiptHash: receipts.last?.receiptHash ?? NativeAuditLog.zeroHash, expectedIndex: receipts.count + 1, minimumReceivedAt: receipts.last.flatMap { Self.receiptDate($0.receivedAt) })
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        try durableAppend(path: file, data: try encoder.encode(receipt) + Data("\n".utf8))
        return Self.status(checkpoints: checkpoints, receipts: receipts + [receipt])
    }

    private func readAndVerifyUnlocked(checkpoints: [NativeAuditCheckpoint]) throws -> [NativeAuditAnchorReceipt] {
        guard try pathEntryExists(file) else { return [] }
        try validatePrivateRegularFile(file, label: "Native audit anchor receipt log")
        let data = try Data(contentsOf: URL(fileURLWithPath: file), options: .mappedIfSafe)
        guard data.count <= 128 * 1024 * 1024 else { throw AgentPassNativeError.invalidSignature("Native audit anchor receipt log exceeds the verification limit") }
        try validateJSONLinesFraming(data, label: "Native audit anchor receipt log")
        let lines = data.split(separator: 0x0a, omittingEmptySubsequences: true)
        guard lines.count <= checkpoints.count else { throw AgentPassNativeError.invalidSignature("Native audit anchor receipt log is ahead of local checkpoints") }
        var previous = NativeAuditLog.zeroHash
        var previousReceivedAt: Date?
        var receipts: [NativeAuditAnchorReceipt] = []
        for (index, line) in lines.enumerated() {
            let receipt = try Self.decodeReceipt(Data(line))
            try verify(receipt, checkpoint: checkpoints[index], previousReceiptHash: previous, expectedIndex: index + 1, minimumReceivedAt: previousReceivedAt)
            previous = receipt.receiptHash
            previousReceivedAt = Self.receiptDate(receipt.receivedAt)
            receipts.append(receipt)
        }
        return receipts
    }

    private func verify(_ receipt: NativeAuditAnchorReceipt, checkpoint: NativeAuditCheckpoint, previousReceiptHash: String, expectedIndex: Int, minimumReceivedAt: Date?) throws {
        let receivedAt = Self.receiptDate(receipt.receivedAt)
        guard let receivedAt else { throw AgentPassNativeError.invalidSignature("Native audit anchor receipt timestamp is invalid") }
        guard receipt.version == 1, receipt.tenant == tenant, receipt.index == expectedIndex,
              receipt.checkpointHash == checkpoint.checkpointHash, receipt.previousReceiptHash == previousReceiptHash,
              receipt.anchorKeyFingerprint == anchorKeyFingerprint,
              minimumReceivedAt.map({ receivedAt >= $0 }) ?? true,
              receipt.receiptHash.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
              let signature = Data(base64Encoded: receipt.signature), signature.count == 64 else {
            throw AgentPassNativeError.invalidSignature("Native audit anchor receipt statement is invalid")
        }
        let statement: [String: Any] = ["version": receipt.version, "tenant": receipt.tenant, "index": receipt.index, "checkpoint_hash": receipt.checkpointHash, "received_at": receipt.receivedAt, "previous_receipt_hash": receipt.previousReceiptHash]
        guard anchorKey.isValidSignature(signature, for: try NativeAuditLog.canonical(statement)) else {
            throw AgentPassNativeError.invalidSignature("Native audit anchor receipt signature is invalid")
        }
        guard receipt.receiptHash == NativeAuditLog.hash(try Self.nodeReceiptHashData(receipt)) else {
            throw AgentPassNativeError.invalidSignature("Native audit anchor receipt hash is invalid")
        }
    }

    private static func decodeReceipt(_ data: Data) throws -> NativeAuditAnchorReceipt {
        guard data.count > 0, data.count <= 64 * 1024,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == receiptKeys else {
            throw AgentPassNativeError.invalidSignature("Native audit anchor receipt encoding is invalid")
        }
        return try JSONDecoder().decode(NativeAuditAnchorReceipt.self, from: data)
    }

    private static func status(checkpoints: [NativeAuditCheckpoint], receipts: [NativeAuditAnchorReceipt]) -> NativeAuditAnchorStatus {
        NativeAuditAnchorStatus(configured: true, checkpoints: checkpoints.count, receipts: receipts.count, pending: checkpoints.count - receipts.count, latestReceiptHash: receipts.last?.receiptHash)
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
          info.st_uid == geteuid(), info.st_mode & 0o077 == 0 else {
        throw AgentPassNativeError.invalidConfiguration("\(label) must be owned by the service account and be a private regular file")
    }
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
