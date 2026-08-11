import CryptoKit
import CoreFoundation
import Darwin
import Foundation

public protocol NativeControlValidating: Sendable {
    func validateControl(agentID: String, nowMilliseconds: Int64) throws
}

public struct NativeControlStatus: Codable, Equatable, Sendable {
    public let configured: Bool
    public let sequence: Int64
    public let expiresAt: String
    public let globalRevoked: Bool
    public let revokedAgents: Int
    public let keyFingerprint: String
    public let operational: Bool
    public let expired: Bool
    enum CodingKeys: String, CodingKey {
        case configured, sequence
        case expiresAt = "expires_at"
        case globalRevoked = "global_revoked"
        case revokedAgents = "revoked_agents"
        case keyFingerprint = "key_fingerprint"
        case operational, expired
    }
}

public final class NativeControlManager: NativeControlValidating, @unchecked Sendable {
    private struct Policy: Decodable {
        struct Control: Decodable { let required: Bool; let publicKey: String; enum CodingKeys: String, CodingKey { case required; case publicKey = "public_key" } }
        let control: Control?
    }
    private struct Bundle {
        let sequence: Int64
        let expiresAt: String
        let expiresAtMilliseconds: Int64
        let globalRevoked: Bool
        let revokedAgents: [String]
        let fingerprint: String
        let canonicalRecord: Data
    }

    private let statePath: String
    private let updateMarkerPath: String
    private let publicKey: Curve25519.Signing.PublicKey
    private let publicKeyDER: Data
    private var active: Bundle
    private var operational = true
    private let lock = NSLock()

    public init(policyData: Data, statePath: String, nowMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) throws {
        guard statePath.hasPrefix("/") else { throw AgentPassNativeError.invalidConfiguration("Native control state path must be absolute") }
        let policy = try JSONDecoder().decode(Policy.self, from: policyData)
        guard let control = policy.control, control.required else {
            throw AgentPassNativeError.invalidConfiguration("Native control state requires control.required=true")
        }
        let parsed = try Self.ed25519Key(fromPEM: control.publicKey)
        publicKey = parsed.key
        publicKeyDER = parsed.der
        self.statePath = URL(fileURLWithPath: statePath).standardizedFileURL.path
        updateMarkerPath = self.statePath + ".pending-audit"
        guard try pathEntryExists(self.statePath) else {
            throw AgentPassNativeError.invalidConfiguration("Required native control state is missing")
        }
        try validatePrivateStateFile(self.statePath)
        let data = try Data(contentsOf: URL(fileURLWithPath: self.statePath), options: .mappedIfSafe)
        guard data.count > 0, data.count <= 256 * 1024 else { throw AgentPassNativeError.invalidConfiguration("Native control state size is invalid") }
        active = try Self.verify(data: data, publicKey: publicKey, publicKeyDER: publicKeyDER, nowMilliseconds: nowMilliseconds, allowExpired: true)
        if try pathEntryExists(updateMarkerPath) {
            try validatePrivateStateFile(updateMarkerPath)
            operational = false
        }
    }

    @discardableResult
    public func apply(bundleData: Data, nowMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) throws -> NativeControlStatus {
        guard bundleData.count > 0, bundleData.count <= 256 * 1024 else { throw AgentPassNativeError.unauthorizedClient("Native control bundle size is invalid") }
        let candidate = try Self.verify(data: bundleData, publicKey: publicKey, publicKeyDER: publicKeyDER, nowMilliseconds: nowMilliseconds, allowExpired: false)
        lock.lock()
        defer { lock.unlock() }
        guard operational else { throw AgentPassNativeError.unauthorizedClient("Native remote control integrity failure") }
        try validateSequence(candidate)
        if candidate.sequence == active.sequence {
            return Self.status(active, operational: operational, nowMilliseconds: nowMilliseconds)
        }
        try atomicStateWrite(path: statePath, data: candidate.canonicalRecord + Data("\n".utf8))
        active = candidate
        return Self.status(candidate, nowMilliseconds: nowMilliseconds)
    }

    public func validateBundle(bundleData: Data, nowMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) throws {
        guard bundleData.count > 0, bundleData.count <= 256 * 1024 else { throw AgentPassNativeError.unauthorizedClient("Native control bundle size is invalid") }
        let candidate = try Self.verify(data: bundleData, publicKey: publicKey, publicKeyDER: publicKeyDER, nowMilliseconds: nowMilliseconds, allowExpired: false)
        lock.lock()
        defer { lock.unlock() }
        guard operational else { throw AgentPassNativeError.unauthorizedClient("Native remote control integrity failure") }
        try validateSequence(candidate)
    }

    public func validateControl(agentID: String, nowMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) throws {
        lock.lock()
        defer { lock.unlock() }
        guard operational else { throw AgentPassNativeError.unauthorizedClient("Native remote control integrity failure") }
        guard nowMilliseconds < active.expiresAtMilliseconds else { throw AgentPassNativeError.unauthorizedClient("Native remote control bundle has expired") }
        guard !active.globalRevoked else { throw AgentPassNativeError.unauthorizedClient("remote_global_revocation") }
        guard !active.revokedAgents.contains(agentID) else { throw AgentPassNativeError.unauthorizedClient("remote_agent_revoked") }
    }

    public func status() -> NativeControlStatus {
        lock.lock()
        defer { lock.unlock() }
        return Self.status(active, operational: operational, nowMilliseconds: Int64(Date().timeIntervalSince1970 * 1000))
    }

    public func beginAuditedUpdate() throws {
        lock.lock()
        defer { lock.unlock() }
        guard operational else { throw AgentPassNativeError.unauthorizedClient("Native remote control integrity failure") }
        do { try atomicStateWrite(path: updateMarkerPath, data: Data("pending\n".utf8)) }
        catch {
            operational = false
            throw error
        }
    }

    public func completeAuditedUpdate() throws {
        lock.lock()
        defer { lock.unlock() }
        guard unlink(updateMarkerPath) == 0 else {
            operational = false
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        do { try synchronizeParent(of: updateMarkerPath) }
        catch {
            operational = false
            throw error
        }
    }

    public func invalidate() {
        lock.lock()
        operational = false
        try? atomicStateWrite(path: updateMarkerPath, data: Data("invalid\n".utf8))
        lock.unlock()
    }

    private func validateSequence(_ candidate: Bundle) throws {
        guard candidate.sequence >= active.sequence else { throw AgentPassNativeError.unauthorizedClient("Native control sequence rollback detected") }
        if candidate.sequence == active.sequence, candidate.canonicalRecord != active.canonicalRecord {
            throw AgentPassNativeError.unauthorizedClient("Native control sequence equivocation detected")
        }
    }

    private static func status(_ bundle: Bundle, operational: Bool = true, nowMilliseconds: Int64) -> NativeControlStatus {
        NativeControlStatus(configured: true, sequence: bundle.sequence, expiresAt: bundle.expiresAt, globalRevoked: bundle.globalRevoked, revokedAgents: bundle.revokedAgents.count, keyFingerprint: bundle.fingerprint, operational: operational, expired: nowMilliseconds >= bundle.expiresAtMilliseconds)
    }

    private static func verify(data: Data, publicKey: Curve25519.Signing.PublicKey, publicKeyDER: Data, nowMilliseconds: Int64, allowExpired: Bool) throws -> Bundle {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              object["version"] as? Int == 1,
              let sequenceNumber = object["sequence"] as? NSNumber,
              let issuedString = object["issued_at"] as? String,
              let expiresString = object["expires_at"] as? String,
              let globalRevokedNumber = object["global_revoked"] as? NSNumber,
              let revokedInput = object["revoked_agents"] as? [Any],
              let fingerprint = object["key_fingerprint"] as? String,
              let signatureString = object["signature"] as? String else {
            throw AgentPassNativeError.unauthorizedClient("Native control bundle is malformed")
        }
        guard CFGetTypeID(sequenceNumber) != CFBooleanGetTypeID() else {
            throw AgentPassNativeError.unauthorizedClient("Native control sequence is invalid")
        }
        guard CFGetTypeID(globalRevokedNumber) == CFBooleanGetTypeID() else {
            throw AgentPassNativeError.unauthorizedClient("Native control global revocation value is invalid")
        }
        let globalRevoked = globalRevokedNumber.boolValue
        let sequence = sequenceNumber.int64Value
        guard sequence >= 1, Double(sequence) == sequenceNumber.doubleValue, sequence <= 9_007_199_254_740_991 else {
            throw AgentPassNativeError.unauthorizedClient("Native control sequence is invalid")
        }
        guard let issued = controlDate(issuedString), let expires = controlDate(expiresString) else {
            throw AgentPassNativeError.unauthorizedClient("Native control timestamps are invalid")
        }
        let issuedMilliseconds = Int64(issued.timeIntervalSince1970 * 1000)
        let expiresMilliseconds = Int64(expires.timeIntervalSince1970 * 1000)
        guard issuedMilliseconds <= nowMilliseconds + 60_000,
              expiresMilliseconds > issuedMilliseconds,
              expiresMilliseconds - issuedMilliseconds <= 7 * 24 * 60 * 60 * 1000,
              allowExpired || expiresMilliseconds > nowMilliseconds else {
            throw AgentPassNativeError.unauthorizedClient("Native control bundle validity window is invalid or expired")
        }
        let revoked = try revokedInput.map { value -> String in
            guard let id = value as? String, id.range(of: "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$", options: .regularExpression) != nil else {
                throw AgentPassNativeError.unauthorizedClient("Native control contains an invalid Agent ID")
            }
            return id
        }
        let normalizedRevoked = Array(Set(revoked)).sorted()
        guard normalizedRevoked.count <= 10_000 else { throw AgentPassNativeError.unauthorizedClient("Native control revoked Agent list is too large") }
        let expectedFingerprint = controlFingerprint(publicKeyDER)
        guard fingerprint == expectedFingerprint,
              signatureString.range(of: "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$", options: .regularExpression) != nil,
              let signature = Data(base64Encoded: signatureString), signature.count == 64 else {
            throw AgentPassNativeError.unauthorizedClient("Native control key fingerprint or signature encoding is invalid")
        }
        let statement: [String: Any] = [
            "version": 1,
            "sequence": sequence,
            "issued_at": controlTimestamp(issued),
            "expires_at": controlTimestamp(expires),
            "global_revoked": globalRevoked,
            "revoked_agents": normalizedRevoked
        ]
        let statementData = try NativeAuditLog.canonical(statement)
        guard publicKey.isValidSignature(signature, for: statementData) else { throw AgentPassNativeError.unauthorizedClient("Native control signature is invalid") }
        var record = statement
        record["key_fingerprint"] = fingerprint
        record["signature"] = signatureString
        let canonicalRecord = try NativeAuditLog.canonical(record)
        return Bundle(sequence: sequence, expiresAt: statement["expires_at"] as! String, expiresAtMilliseconds: expiresMilliseconds, globalRevoked: globalRevoked, revokedAgents: normalizedRevoked, fingerprint: fingerprint, canonicalRecord: canonicalRecord)
    }

    private static func ed25519Key(fromPEM pem: String) throws -> (key: Curve25519.Signing.PublicKey, der: Data) {
        let body = pem.components(separatedBy: .newlines).filter { !$0.hasPrefix("-----") }.joined()
        guard let der = Data(base64Encoded: body), der.count == 44,
              der.prefix(12) == Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) else {
            throw AgentPassNativeError.invalidConfiguration("Native control public key must be Ed25519 SPKI PEM")
        }
        return (try Curve25519.Signing.PublicKey(rawRepresentation: der.suffix(32)), der)
    }
}

private func controlDate(_ value: String) -> Date? {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.date(from: value)
}

private func controlTimestamp(_ date: Date) -> String {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = TimeZone(secondsFromGMT: 0)
    formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
    return formatter.string(from: date)
}

private func controlFingerprint(_ der: Data) -> String {
    "SHA256:" + Data(SHA256.hash(data: der)).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}

private func pathEntryExists(_ path: String) throws -> Bool {
    var info = stat()
    if lstat(path, &info) == 0 { return true }
    if errno == ENOENT { return false }
    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
}

private func validatePrivateStateFile(_ path: String) throws {
    var info = stat()
    guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == geteuid(), info.st_mode & 0o077 == 0 else {
        throw AgentPassNativeError.invalidConfiguration("Native control state must be owned by the service account and be a private regular file")
    }
}

private func atomicStateWrite(path: String, data: Data) throws {
    let temporary = "\(path).tmp.\(UUID().uuidString)"
    let descriptor = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
    guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    var keep = false
    defer {
        close(descriptor)
        if !keep { unlink(temporary) }
    }
    try data.withUnsafeBytes { bytes in
        var offset = 0
        while offset < bytes.count {
            let written = Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
            guard written > 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            offset += written
        }
    }
    guard fchmod(descriptor, 0o600) == 0, fsync(descriptor) == 0, rename(temporary, path) == 0 else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    keep = true
    try synchronizeParent(of: path)
}

private func synchronizeParent(of path: String) throws {
    let parent = URL(fileURLWithPath: path).deletingLastPathComponent().path
    let directory = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    guard directory >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    defer { close(directory) }
    guard fsync(directory) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
}
