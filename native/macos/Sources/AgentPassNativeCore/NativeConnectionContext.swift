import CryptoKit
import Foundation

/// Stable, non-sensitive failure codes for the connection-context boundary.
///
/// The cases intentionally have no associated values.  In particular, an
/// OS error, a caller-provided token, and a token-derived field are never
/// interpolated into an error returned by this boundary.
public enum NativeConnectionContextError: String, CaseIterable, Error, Equatable, Hashable, Sendable, Codable, LocalizedError {
    case malformedAuditToken = "malformed_audit_token"
    case allZeroAuditToken = "all_zero_audit_token"
    case broadAuditTokenInput = "broad_audit_token_input"
    case invalidAuditTokenField = "invalid_audit_token_field"
    case invalidSerializedContext = "invalid_serialized_context"
    case peerIdentityMismatch = "peer_identity_mismatch"

    public var errorDescription: String? { rawValue }
    public var code: String { rawValue }
}

/// The fixed-width fields extracted by a service-side NSXPC adapter.
///
/// `AgentPassNativeCore` deliberately does not import NSXPC or expose
/// `audit_token_t`.  A service target should extract the eight `UInt32`
/// fields from the connection's audit token and pass them to `init(words:)`,
/// or pass the named fields to the strict initializer below.  The adapter
/// accepts exactly the Darwin audit-token shape, derives a stable digest, and
/// does not expose or encode the original fields as a token.
///
/// This type is not `Codable`.  Persist and transmit the resulting
/// `NativeConnectionContext` instead; it contains only the safe peer identity
/// projection and the one-way token identity digest.
struct NativeAuditTokenFieldAdapter: Equatable, Hashable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let fieldCount = 8

    private let auditUserID: UInt32
    private let effectiveUserIDValue: UInt32
    private let effectiveGroupID: UInt32
    private let realUserID: UInt32
    private let realGroupID: UInt32
    private let pidValue: Int32
    private let auditSessionIDValue: UInt32
    private let pidVersionValue: UInt32
    private let tokenIdentityValue: String

    /// Creates an adapter from the eight `audit_token_t.val` fields, in their
    /// Darwin order: auid, euid, egid, ruid, rgid, pid, asid, pidversion.
    ///
    /// A variable-length or oversized collection is rejected rather than
    /// truncated.  This prevents a caller from supplying a broad input that
    /// could be interpreted differently by different adapters.
    init(words: [UInt32]) throws {
        guard words.count == Self.fieldCount else {
            if words.count > Self.fieldCount {
                throw NativeConnectionContextError.broadAuditTokenInput
            }
            throw NativeConnectionContextError.malformedAuditToken
        }
        guard words.contains(where: { $0 != 0 }) else {
            throw NativeConnectionContextError.allZeroAuditToken
        }

        let rawPID = words[5]
        guard rawPID > 0, rawPID <= UInt32(Int32.max) else {
            throw NativeConnectionContextError.invalidAuditTokenField
        }

        try self.init(
            auditUserID: words[0],
            effectiveUserID: words[1],
            effectiveGroupID: words[2],
            realUserID: words[3],
            realGroupID: words[4],
            pid: Int32(rawPID),
            auditSessionID: words[6],
            pidVersion: words[7]
        )
    }

    /// Creates an adapter from fields extracted by a service-side
    /// `audit_token_t` bridge.  The raw token itself never crosses this API.
    init(
        auditUserID: UInt32,
        effectiveUserID: UInt32,
        effectiveGroupID: UInt32,
        realUserID: UInt32,
        realGroupID: UInt32,
        pid: Int32,
        auditSessionID: UInt32,
        pidVersion: UInt32
    ) throws {
        guard pid > 0, auditSessionID > 0, auditSessionID < UInt32.max, pidVersion > 0,
              effectiveUserID < UInt32.max else {
            throw NativeConnectionContextError.invalidAuditTokenField
        }

        let fields = [
            auditUserID,
            effectiveUserID,
            effectiveGroupID,
            realUserID,
            realGroupID,
            UInt32(pid),
            auditSessionID,
            pidVersion
        ]
        guard fields.contains(where: { $0 != 0 }) else {
            throw NativeConnectionContextError.allZeroAuditToken
        }

        self.auditUserID = auditUserID
        self.effectiveUserIDValue = effectiveUserID
        self.effectiveGroupID = effectiveGroupID
        self.realUserID = realUserID
        self.realGroupID = realGroupID
        self.pidValue = pid
        self.auditSessionIDValue = auditSessionID
        self.pidVersionValue = pidVersion
        self.tokenIdentityValue = Self.tokenIdentity(for: fields)
    }

    /// The effective user ID extracted from the token.
    var effectiveUserID: UInt32 { effectiveUserIDValue }

    /// The process ID extracted from the token.
    var pid: Int32 { pidValue }

    /// The audit session ID extracted from the token.
    var auditSessionID: UInt32 { auditSessionIDValue }

    /// The PID-generation value extracted from the token.
    var pidVersion: UInt32 { pidVersionValue }

    /// A one-way, fixed-format identity of the complete token field set.
    /// The raw fields are never returned.
    var tokenIdentity: String { tokenIdentityValue }

    /// A deliberately redacted representation safe for diagnostics.
    var description: String {
        "NativeAuditTokenFieldAdapter(tokenIdentity: \(tokenIdentityValue))"
    }

    var debugDescription: String { description }

    private static func tokenIdentity(for fields: [UInt32]) -> String {
        var data = Data(capacity: fields.count * MemoryLayout<UInt32>.size)
        for field in fields {
            var bigEndian = field.bigEndian
            withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
        }
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

/// Compatibility spelling for service adapters that model the extracted
/// fields as a value rather than an implementation detail.
typealias NativeAuditTokenFields = NativeAuditTokenFieldAdapter

/// The immutable, safe projection of a captured connection peer.
///
/// It contains the identity facts needed for authorization and re-observation
/// binding, but never retains the raw audit token or its individual fields.
public struct NativeConnectionPeerIdentity: Codable, Equatable, Hashable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let pid: Int32
    public let effectiveUserID: UInt32
    public let auditSessionID: UInt32
    public let pidVersion: UInt64
    public let tokenIdentity: String

    internal init(adapter: NativeAuditTokenFieldAdapter) {
        self.pid = adapter.pid
        self.effectiveUserID = adapter.effectiveUserID
        self.auditSessionID = adapter.auditSessionID
        self.pidVersion = UInt64(adapter.pidVersion)
        self.tokenIdentity = adapter.tokenIdentity
    }

    internal init(pid: Int32, effectiveUserID: UInt32, auditSessionID: UInt32, pidVersion: UInt64, tokenIdentity: String) throws {
        guard Self.isValid(pid: pid, effectiveUserID: effectiveUserID, auditSessionID: auditSessionID, pidVersion: pidVersion, tokenIdentity: tokenIdentity) else {
            throw NativeConnectionContextError.invalidAuditTokenField
        }
        self.pid = pid
        self.effectiveUserID = effectiveUserID
        self.auditSessionID = auditSessionID
        self.pidVersion = pidVersion
        self.tokenIdentity = tokenIdentity
    }

    public var description: String {
        "NativeConnectionPeerIdentity(pid: \(pid), effectiveUserID: \(effectiveUserID), auditSessionID: \(auditSessionID), pidVersion: \(pidVersion), tokenIdentity: \(tokenIdentity))"
    }

    public var debugDescription: String { description }

    private enum CodingKeys: String, CodingKey {
        case version
        case pid
        case effectiveUserID = "effective_user_id"
        case auditSessionID = "audit_session_id"
        case pidVersion = "pid_version"
        case tokenIdentity = "token_identity"
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode("native_connection_peer_identity/v1", forKey: .version)
        try container.encode(pid, forKey: .pid)
        try container.encode(effectiveUserID, forKey: .effectiveUserID)
        try container.encode(auditSessionID, forKey: .auditSessionID)
        try container.encode(pidVersion, forKey: .pidVersion)
        try container.encode(tokenIdentity, forKey: .tokenIdentity)
    }

    public init(from decoder: Decoder) throws {
        do {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            guard try container.decode(String.self, forKey: .version) == "native_connection_peer_identity/v1" else {
                throw NativeConnectionContextError.invalidSerializedContext
            }
            let pid = try container.decode(Int32.self, forKey: .pid)
            let effectiveUserID = try container.decode(UInt32.self, forKey: .effectiveUserID)
            let auditSessionID = try container.decode(UInt32.self, forKey: .auditSessionID)
            let pidVersion = try container.decode(UInt64.self, forKey: .pidVersion)
            let tokenIdentity = try container.decode(String.self, forKey: .tokenIdentity)
            guard Self.isValid(
                pid: pid,
                effectiveUserID: effectiveUserID,
                auditSessionID: auditSessionID,
                pidVersion: pidVersion,
                tokenIdentity: tokenIdentity
            ) else {
                throw NativeConnectionContextError.invalidSerializedContext
            }
            self.pid = pid
            self.effectiveUserID = effectiveUserID
            self.auditSessionID = auditSessionID
            self.pidVersion = pidVersion
            self.tokenIdentity = tokenIdentity
        } catch let error as NativeConnectionContextError {
            throw error
        } catch {
            throw NativeConnectionContextError.invalidSerializedContext
        }
    }

    private static func isValid(
        pid: Int32,
        effectiveUserID: UInt32,
        auditSessionID: UInt32,
        pidVersion: UInt64,
        tokenIdentity: String
    ) -> Bool {
        pid > 0 && effectiveUserID < UInt32.max && auditSessionID > 0 && auditSessionID < UInt32.max &&
            pidVersion > 0 && tokenIdentity.count == 64 &&
            tokenIdentity.unicodeScalars.allSatisfy { scalar in
                (scalar.value >= 48 && scalar.value <= 57) ||
                    (scalar.value >= 97 && scalar.value <= 102)
            }
    }
}

public typealias NativePeerIdentity = NativeConnectionPeerIdentity

/// Immutable connection-scoped identity captured from a strict audit-token
/// field adapter.  Re-observation must be performed by extracting a fresh
/// adapter from the live connection and calling `validate(reobserved:)`.
public struct NativeConnectionContext: Codable, Equatable, Hashable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let peerIdentity: NativeConnectionPeerIdentity

    init(capturing adapter: NativeAuditTokenFieldAdapter) {
        self.peerIdentity = NativeConnectionPeerIdentity(adapter: adapter)
    }

    init(auditTokenFields adapter: NativeAuditTokenFieldAdapter) {
        self.init(capturing: adapter)
    }

    init(auditTokenWords words: [UInt32]) throws {
        self.init(capturing: try NativeAuditTokenFieldAdapter(words: words))
    }

    /// Captures the public, OS-owned peer fields exposed by NSXPCConnection
    /// together with the kernel process-generation snapshot. This is the
    /// production path on SDKs that intentionally do not expose raw
    /// `audit_token_t`. None of these values may come from an Agent DTO.
    public init(osProcessID pid: Int32, effectiveUserID: UInt32, auditSessionID: UInt32, pidVersion: UInt64) throws {
        guard pid > 0, effectiveUserID < UInt32.max,
              auditSessionID > 0, auditSessionID < UInt32.max, pidVersion > 0 else {
            throw NativeConnectionContextError.invalidAuditTokenField
        }
        var identity = Data("AgentPass-NSXPC-Peer-Identity-v1\0".utf8)
        for field in [UInt64(UInt32(bitPattern: pid)), UInt64(effectiveUserID), UInt64(auditSessionID), pidVersion] {
            var bigEndian = field.bigEndian
            withUnsafeBytes(of: &bigEndian) { identity.append(contentsOf: $0) }
        }
        let digest = SHA256.hash(data: identity).map { String(format: "%02x", $0) }.joined()
        self.peerIdentity = try NativeConnectionPeerIdentity(
            pid: pid,
            effectiveUserID: effectiveUserID,
            auditSessionID: auditSessionID,
            pidVersion: pidVersion,
            tokenIdentity: digest
        )
    }

    public var pid: Int32 { peerIdentity.pid }
    public var effectiveUserID: UInt32 { peerIdentity.effectiveUserID }
    public var auditSessionID: UInt32 { peerIdentity.auditSessionID }
    public var pidVersion: UInt64 { peerIdentity.pidVersion }
    public var tokenIdentity: String { peerIdentity.tokenIdentity }

    func matches(reobserved adapter: NativeAuditTokenFieldAdapter) -> Bool {
        NativeConnectionPeerIdentity(adapter: adapter) == peerIdentity
    }

    func validate(reobserved adapter: NativeAuditTokenFieldAdapter) throws {
        guard matches(reobserved: adapter) else {
            throw NativeConnectionContextError.peerIdentityMismatch
        }
    }

    public var description: String {
        "NativeConnectionContext(\(peerIdentity.description))"
    }

    public var debugDescription: String { description }

    private enum CodingKeys: String, CodingKey {
        case version
        case peerIdentity = "peer_identity"
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode("native_connection_context/v1", forKey: .version)
        try container.encode(peerIdentity, forKey: .peerIdentity)
    }

    public init(from decoder: Decoder) throws {
        do {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            guard try container.decode(String.self, forKey: .version) == "native_connection_context/v1" else {
                throw NativeConnectionContextError.invalidSerializedContext
            }
            self.peerIdentity = try container.decode(NativeConnectionPeerIdentity.self, forKey: .peerIdentity)
        } catch let error as NativeConnectionContextError {
            throw error
        } catch {
            throw NativeConnectionContextError.invalidSerializedContext
        }
    }
}
