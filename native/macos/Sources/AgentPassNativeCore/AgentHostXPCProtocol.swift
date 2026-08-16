import Foundation

/// The contract for the supervised Agent Host connection.
///
/// This is deliberately separate from `AgentPassAgentXPCProtocol`. The Host
/// is a supervisor, not an Agent, and therefore must not be able to present a
/// capability, select a key or algorithm, name a repository, choose an
/// operation, or choose a session identifier on behalf of a child.
public enum AgentPassHostXPCContract {
    public static let protocolVersion = 1
    public static let digestBytes = 32
    public static let minimumNonceBytes = 16
    public static let maximumNonceBytes = 64
    public static let maximumCommitPayloadBytes = 1 * 1024 * 1024
    public static let maximumSignatureBytes = 4 * 1024
    public static let fixedSignatureBudget = 2
    public static let maximumChildPID = Int(Int32.max)
    /// PID versions are represented as a bounded microsecond process-start
    /// identity. The upper bound is the same 2100 boundary used by native
    /// timestamp DTOs, so negative, zero, and arbitrary-width values fail
    /// before they can become an observation hint.
    public static let maximumChildPIDVersion: Int64 = 4_102_444_800_000_000

    public enum SessionStatus: String, CaseIterable, Sendable {
        case prepared
        case attached
        case active
        case expired
        case revoked
        case closed
    }

    public enum CloseReason: String, CaseIterable, Sendable {
        case completed
        case cancelled
        case clientShutdown = "client_shutdown"
    }

    public enum SessionPhase: String, CaseIterable, Sendable {
        case new
        case prepared
        case attached
        case closed
    }

    public enum Operation: String, CaseIterable, Sendable {
        case prepare
        case attachChild = "attach_child"
        case signPayload = "sign_payload"
        case status
        case close
    }

    public enum ValidationError: Error, Equatable, Sendable {
        case invalidField
        case invalidOrdering
    }

    /// Contract-level ordering is intentionally exposed without wiring a
    /// listener or service. Runtime code may use the same closed transition
    /// table when it is implemented, while tests can prove that a valid
    /// payload shape is not sufficient to authorize an early sign.
    public static func isAllowed(_ operation: Operation, in phase: SessionPhase) -> Bool {
        switch (phase, operation) {
        case (.new, .prepare):
            return true
        case (.prepared, .attachChild), (.prepared, .close):
            return true
        case (.attached, .signPayload), (.attached, .status), (.attached, .close):
            return true
        default:
            return false
        }
    }

    public static func requireAllowed(_ operation: Operation, in phase: SessionPhase) throws {
        guard isAllowed(operation, in: phase) else {
            throw ValidationError.invalidOrdering
        }
    }

    public static func isDigest(_ value: Data) -> Bool {
        value.count == digestBytes && value.contains(where: { $0 != 0 })
    }

    public static func isUUID(_ value: String) -> Bool {
        guard value.utf8.count == 36, let uuid = UUID(uuidString: value) else { return false }
        return uuid.uuidString.lowercased() == value.lowercased()
    }

    public static func canonicalUUID(_ value: String) -> String? {
        guard value.utf8.count == 36, let uuid = UUID(uuidString: value) else { return nil }
        return uuid.uuidString.lowercased()
    }

    public static func isTimestamp(_ value: Int64) -> Bool {
        (1...4_102_444_800_000).contains(value)
    }

    fileprivate static func containsForbiddenAuthorityKey(_ coder: NSCoder) -> Bool {
        Self.forbiddenAuthorityKeys.contains { coder.containsValue(forKey: $0) }
    }

    fileprivate static func containsForbiddenRequestAuthorityKey(_ coder: NSCoder) -> Bool {
        containsForbiddenAuthorityKey(coder) || Self.requestOnlyForbiddenKeys.contains { coder.containsValue(forKey: $0) }
    }

    /// These names are reserved so a later archive extension cannot silently
    /// turn a Host DTO into an authority-bearing request. They are checked at
    /// decode time as well as kept out of every public DTO property.
    private static let forbiddenAuthorityKeys = [
        "capability", "capability_id", "private_key", "private_key_data",
        "key", "key_id", "algorithm", "signer", "signer_arguments",
        "operation", "repository", "repository_path", "worktree_path",
        "branch", "remote", "session_token", "token", "ttl_seconds",
        "scope", "authority", "lease", "agent_id", "adapter_kind",
    ]

    private static let requestOnlyForbiddenKeys = [
        "session_id", "status", "expires_at_ms", "max_signatures", "used_signatures",
        "child_attached", "attached_at_ms", "closed_at_ms", "signature", "remaining_signatures",
    ]
}

/// A prepare request. The service assigns the session identifier in the
/// response; this request has no caller-selected session ID or authority.
@objc(AgentPassHostPrepareRequest)
public final class AgentPassHostPrepareRequest: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }

    public let protocolVersion: Int
    public let launchNonce: Data

    public init?(
        protocolVersion: Int = AgentPassHostXPCContract.protocolVersion,
        launchNonce: Data
    ) {
        guard protocolVersion == AgentPassHostXPCContract.protocolVersion,
              (AgentPassHostXPCContract.minimumNonceBytes...AgentPassHostXPCContract.maximumNonceBytes).contains(launchNonce.count) else {
            return nil
        }
        self.protocolVersion = protocolVersion
        self.launchNonce = launchNonce
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard !AgentPassHostXPCContract.containsForbiddenRequestAuthorityKey(coder),
              coder.containsValue(forKey: Keys.protocolVersion),
              let protocolVersion = coder.decodeObject(of: NSNumber.self, forKey: Keys.protocolVersion)?.intValue,
              let launchNonce = coder.decodeObject(of: NSData.self, forKey: Keys.launchNonce) as Data? else {
            return nil
        }
        self.init(protocolVersion: protocolVersion, launchNonce: launchNonce)
    }

    public func encode(with coder: NSCoder) {
        coder.encode(NSNumber(value: protocolVersion), forKey: Keys.protocolVersion)
        coder.encode(launchNonce as NSData, forKey: Keys.launchNonce)
    }

    private enum Keys {
        static let protocolVersion = "protocol_version"
        static let launchNonce = "launch_nonce"
    }
}

/// The service-assigned identity of a prepared Host session.
@objc(AgentPassHostPrepareResponse)
public final class AgentPassHostPrepareResponse: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }

    public let protocolVersion: Int
    public let sessionID: String
    public let status: String
    public let expiresAtMilliseconds: Int64
    public let maxSignatures: Int

    public init?(
        protocolVersion: Int = AgentPassHostXPCContract.protocolVersion,
        sessionID: String,
        status: AgentPassHostXPCContract.SessionStatus,
        expiresAtMilliseconds: Int64,
        maxSignatures: Int
    ) {
        guard protocolVersion == AgentPassHostXPCContract.protocolVersion,
              let sessionID = AgentPassHostXPCContract.canonicalUUID(sessionID),
              status == .prepared,
              AgentPassHostXPCContract.isTimestamp(expiresAtMilliseconds),
              maxSignatures == AgentPassHostXPCContract.fixedSignatureBudget else {
            return nil
        }
        self.protocolVersion = protocolVersion
        self.sessionID = sessionID
        self.status = status.rawValue
        self.expiresAtMilliseconds = expiresAtMilliseconds
        self.maxSignatures = maxSignatures
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard !AgentPassHostXPCContract.containsForbiddenAuthorityKey(coder),
              coder.containsValue(forKey: Keys.protocolVersion),
              coder.containsValue(forKey: Keys.expiresAtMilliseconds),
              coder.containsValue(forKey: Keys.maxSignatures),
              let protocolVersion = coder.decodeObject(of: NSNumber.self, forKey: Keys.protocolVersion)?.intValue,
              let sessionID = coder.decodeObject(of: NSString.self, forKey: Keys.sessionID) as String?,
              let status = coder.decodeObject(of: NSString.self, forKey: Keys.status) as String?,
              let status = AgentPassHostXPCContract.SessionStatus(rawValue: status),
              let expiresAtMilliseconds = coder.decodeObject(of: NSNumber.self, forKey: Keys.expiresAtMilliseconds)?.int64Value,
              let maxSignatures = coder.decodeObject(of: NSNumber.self, forKey: Keys.maxSignatures)?.intValue else {
            return nil
        }
        self.init(protocolVersion: protocolVersion, sessionID: sessionID, status: status, expiresAtMilliseconds: expiresAtMilliseconds, maxSignatures: maxSignatures)
    }

    public func encode(with coder: NSCoder) {
        coder.encode(NSNumber(value: protocolVersion), forKey: Keys.protocolVersion)
        coder.encode(sessionID as NSString, forKey: Keys.sessionID)
        coder.encode(status as NSString, forKey: Keys.status)
        coder.encode(NSNumber(value: expiresAtMilliseconds), forKey: Keys.expiresAtMilliseconds)
        coder.encode(NSNumber(value: maxSignatures), forKey: Keys.maxSignatures)
    }

    private enum Keys {
        static let protocolVersion = "protocol_version"
        static let sessionID = "session_id"
        static let status = "status"
        static let expiresAtMilliseconds = "expires_at_ms"
        static let maxSignatures = "max_signatures"
    }
}

/// A public observation hint. The native service must independently observe
/// the child and compare these digests; these fields are never authority.
@objc(AgentPassHostAttachChildRequest)
public final class AgentPassHostAttachChildRequest: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }

    public let protocolVersion: Int
    public let childPID: Int
    public let childPIDVersion: Int64
    public let executableIdentityDigest: Data
    public let ancestryBindingDigest: Data
    public let worktreeBindingDigest: Data

    public init?(
        protocolVersion: Int = AgentPassHostXPCContract.protocolVersion,
        childPID: Int,
        childPIDVersion: Int64,
        executableIdentityDigest: Data,
        ancestryBindingDigest: Data,
        worktreeBindingDigest: Data
    ) {
        guard protocolVersion == AgentPassHostXPCContract.protocolVersion,
              (1...AgentPassHostXPCContract.maximumChildPID).contains(childPID),
              (1...AgentPassHostXPCContract.maximumChildPIDVersion).contains(childPIDVersion),
              AgentPassHostXPCContract.isDigest(executableIdentityDigest),
              AgentPassHostXPCContract.isDigest(ancestryBindingDigest),
              AgentPassHostXPCContract.isDigest(worktreeBindingDigest) else {
            return nil
        }
        self.protocolVersion = protocolVersion
        self.childPID = childPID
        self.childPIDVersion = childPIDVersion
        self.executableIdentityDigest = executableIdentityDigest
        self.ancestryBindingDigest = ancestryBindingDigest
        self.worktreeBindingDigest = worktreeBindingDigest
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard !AgentPassHostXPCContract.containsForbiddenRequestAuthorityKey(coder),
              coder.containsValue(forKey: Keys.protocolVersion),
              coder.containsValue(forKey: Keys.childPID),
              coder.containsValue(forKey: Keys.childPIDVersion),
              let protocolVersion = coder.decodeObject(of: NSNumber.self, forKey: Keys.protocolVersion)?.intValue,
              let childPID = coder.decodeObject(of: NSNumber.self, forKey: Keys.childPID)?.intValue,
              let childPIDVersion = coder.decodeObject(of: NSNumber.self, forKey: Keys.childPIDVersion)?.int64Value,
              let executableIdentityDigest = coder.decodeObject(of: NSData.self, forKey: Keys.executableIdentityDigest) as Data?,
              let ancestryBindingDigest = coder.decodeObject(of: NSData.self, forKey: Keys.ancestryBindingDigest) as Data?,
              let worktreeBindingDigest = coder.decodeObject(of: NSData.self, forKey: Keys.worktreeBindingDigest) as Data? else {
            return nil
        }
        self.init(
            protocolVersion: protocolVersion,
            childPID: childPID,
            childPIDVersion: childPIDVersion,
            executableIdentityDigest: executableIdentityDigest,
            ancestryBindingDigest: ancestryBindingDigest,
            worktreeBindingDigest: worktreeBindingDigest
        )
    }

    public func encode(with coder: NSCoder) {
        coder.encode(NSNumber(value: protocolVersion), forKey: Keys.protocolVersion)
        coder.encode(NSNumber(value: childPID), forKey: Keys.childPID)
        coder.encode(NSNumber(value: childPIDVersion), forKey: Keys.childPIDVersion)
        coder.encode(executableIdentityDigest as NSData, forKey: Keys.executableIdentityDigest)
        coder.encode(ancestryBindingDigest as NSData, forKey: Keys.ancestryBindingDigest)
        coder.encode(worktreeBindingDigest as NSData, forKey: Keys.worktreeBindingDigest)
    }

    private enum Keys {
        static let protocolVersion = "protocol_version"
        static let childPID = "child_pid"
        static let childPIDVersion = "child_pid_version"
        static let executableIdentityDigest = "executable_identity_digest"
        static let ancestryBindingDigest = "ancestry_binding_digest"
        static let worktreeBindingDigest = "worktree_binding_digest"
    }
}

@objc(AgentPassHostAttachChildResponse)
public final class AgentPassHostAttachChildResponse: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }

    public let protocolVersion: Int
    public let sessionID: String
    public let status: String
    public let attachedAtMilliseconds: Int64
    public let maxSignatures: Int

    public init?(
        protocolVersion: Int = AgentPassHostXPCContract.protocolVersion,
        sessionID: String,
        attachedAtMilliseconds: Int64,
        maxSignatures: Int
    ) {
        guard protocolVersion == AgentPassHostXPCContract.protocolVersion,
              let sessionID = AgentPassHostXPCContract.canonicalUUID(sessionID),
              AgentPassHostXPCContract.isTimestamp(attachedAtMilliseconds),
              maxSignatures == AgentPassHostXPCContract.fixedSignatureBudget else {
            return nil
        }
        self.protocolVersion = protocolVersion
        self.sessionID = sessionID
        self.status = AgentPassHostXPCContract.SessionStatus.attached.rawValue
        self.attachedAtMilliseconds = attachedAtMilliseconds
        self.maxSignatures = maxSignatures
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard !AgentPassHostXPCContract.containsForbiddenAuthorityKey(coder),
              coder.containsValue(forKey: Keys.protocolVersion),
              coder.containsValue(forKey: Keys.attachedAtMilliseconds),
              coder.containsValue(forKey: Keys.maxSignatures),
              let protocolVersion = coder.decodeObject(of: NSNumber.self, forKey: Keys.protocolVersion)?.intValue,
              let sessionID = coder.decodeObject(of: NSString.self, forKey: Keys.sessionID) as String?,
              let attachedAtMilliseconds = coder.decodeObject(of: NSNumber.self, forKey: Keys.attachedAtMilliseconds)?.int64Value,
              let maxSignatures = coder.decodeObject(of: NSNumber.self, forKey: Keys.maxSignatures)?.intValue else {
            return nil
        }
        self.init(protocolVersion: protocolVersion, sessionID: sessionID, attachedAtMilliseconds: attachedAtMilliseconds, maxSignatures: maxSignatures)
    }

    public func encode(with coder: NSCoder) {
        coder.encode(NSNumber(value: protocolVersion), forKey: Keys.protocolVersion)
        coder.encode(sessionID as NSString, forKey: Keys.sessionID)
        coder.encode(status as NSString, forKey: Keys.status)
        coder.encode(NSNumber(value: attachedAtMilliseconds), forKey: Keys.attachedAtMilliseconds)
        coder.encode(NSNumber(value: maxSignatures), forKey: Keys.maxSignatures)
    }

    private enum Keys {
        static let protocolVersion = "protocol_version"
        static let sessionID = "session_id"
        static let status = "status"
        static let attachedAtMilliseconds = "attached_at_ms"
        static let maxSignatures = "max_signatures"
    }
}

/// The only sign request shape: a bounded opaque commit payload.
@objc(AgentPassHostSignRequest)
public final class AgentPassHostSignRequest: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }
    public let requestSequence: UInt32
    public let commitPayload: Data

    public init?(requestSequence: UInt32, commitPayload: Data) {
        guard (1...UInt32(AgentPassHostXPCContract.fixedSignatureBudget)).contains(requestSequence),
              !commitPayload.isEmpty,
              commitPayload.count <= AgentPassHostXPCContract.maximumCommitPayloadBytes else {
            return nil
        }
        self.requestSequence = requestSequence
        self.commitPayload = commitPayload
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard !AgentPassHostXPCContract.containsForbiddenRequestAuthorityKey(coder),
              let requestSequence = coder.decodeObject(of: NSNumber.self, forKey: Keys.requestSequence)?.uint32Value,
              let commitPayload = coder.decodeObject(of: NSData.self, forKey: Keys.commitPayload) as Data? else {
            return nil
        }
        self.init(requestSequence: requestSequence, commitPayload: commitPayload)
    }

    public func encode(with coder: NSCoder) {
        coder.encode(NSNumber(value: requestSequence), forKey: Keys.requestSequence)
        coder.encode(commitPayload as NSData, forKey: Keys.commitPayload)
    }

    private enum Keys {
        static let requestSequence = "request_sequence"
        static let commitPayload = "commit_payload"
    }
}

@objc(AgentPassHostSignResponse)
public final class AgentPassHostSignResponse: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }
    public let responseSequence: UInt32
    public let signature: Data
    public let remainingSignatures: Int

    public init?(responseSequence: UInt32, signature: Data, remainingSignatures: Int) {
        guard (1...UInt32(AgentPassHostXPCContract.fixedSignatureBudget)).contains(responseSequence),
              !signature.isEmpty,
              signature.count <= AgentPassHostXPCContract.maximumSignatureBytes,
              remainingSignatures == AgentPassHostXPCContract.fixedSignatureBudget - Int(responseSequence) else {
            return nil
        }
        self.responseSequence = responseSequence
        self.signature = signature
        self.remainingSignatures = remainingSignatures
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard !AgentPassHostXPCContract.containsForbiddenAuthorityKey(coder),
              let responseSequence = coder.decodeObject(of: NSNumber.self, forKey: Keys.responseSequence)?.uint32Value,
              let signature = coder.decodeObject(of: NSData.self, forKey: Keys.signature) as Data?,
              let remainingSignatures = coder.decodeObject(of: NSNumber.self, forKey: Keys.remainingSignatures)?.intValue else {
            return nil
        }
        self.init(responseSequence: responseSequence, signature: signature, remainingSignatures: remainingSignatures)
    }

    public func encode(with coder: NSCoder) {
        coder.encode(NSNumber(value: responseSequence), forKey: Keys.responseSequence)
        coder.encode(signature as NSData, forKey: Keys.signature)
        coder.encode(NSNumber(value: remainingSignatures), forKey: Keys.remainingSignatures)
    }

    private enum Keys {
        static let responseSequence = "response_sequence"
        static let signature = "signature"
        static let remainingSignatures = "remaining_signatures"
    }
}

/// Version-only status request. Session identity is connection-owned and therefore
/// cannot be selected or substituted by the caller.
@objc(AgentPassHostStatusRequest)
public final class AgentPassHostStatusRequest: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }
    public let protocolVersion: Int

    public init?(protocolVersion: Int = AgentPassHostXPCContract.protocolVersion) {
        guard protocolVersion == AgentPassHostXPCContract.protocolVersion else { return nil }
        self.protocolVersion = protocolVersion
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard !AgentPassHostXPCContract.containsForbiddenRequestAuthorityKey(coder),
              coder.containsValue(forKey: Keys.protocolVersion),
              let protocolVersion = coder.decodeObject(of: NSNumber.self, forKey: Keys.protocolVersion)?.intValue else {
            return nil
        }
        self.init(protocolVersion: protocolVersion)
    }

    public func encode(with coder: NSCoder) {
        coder.encode(NSNumber(value: protocolVersion), forKey: Keys.protocolVersion)
    }

    private enum Keys { static let protocolVersion = "protocol_version" }
}

@objc(AgentPassHostStatusResponse)
public final class AgentPassHostStatusResponse: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }

    public let sessionID: String
    public let status: String
    public let expiresAtMilliseconds: Int64
    public let maxSignatures: Int
    public let usedSignatures: Int
    public let childAttached: Bool

    public init?(
        sessionID: String,
        status: AgentPassHostXPCContract.SessionStatus,
        expiresAtMilliseconds: Int64,
        maxSignatures: Int,
        usedSignatures: Int,
        childAttached: Bool
    ) {
        guard let sessionID = AgentPassHostXPCContract.canonicalUUID(sessionID),
              AgentPassHostXPCContract.isTimestamp(expiresAtMilliseconds),
              maxSignatures == AgentPassHostXPCContract.fixedSignatureBudget,
              (0...maxSignatures).contains(usedSignatures),
              ((status == .prepared || status == .expired || status == .revoked || status == .closed) && !childAttached)
                || ((status == .attached || status == .active) && childAttached) else {
            return nil
        }
        self.sessionID = sessionID
        self.status = status.rawValue
        self.expiresAtMilliseconds = expiresAtMilliseconds
        self.maxSignatures = maxSignatures
        self.usedSignatures = usedSignatures
        self.childAttached = childAttached
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard !AgentPassHostXPCContract.containsForbiddenAuthorityKey(coder),
              coder.containsValue(forKey: Keys.expiresAtMilliseconds),
              coder.containsValue(forKey: Keys.maxSignatures),
              coder.containsValue(forKey: Keys.usedSignatures),
              coder.containsValue(forKey: Keys.childAttached),
              let sessionID = coder.decodeObject(of: NSString.self, forKey: Keys.sessionID) as String?,
              let status = coder.decodeObject(of: NSString.self, forKey: Keys.status) as String?,
              let status = AgentPassHostXPCContract.SessionStatus(rawValue: status),
              let expiresAtMilliseconds = coder.decodeObject(of: NSNumber.self, forKey: Keys.expiresAtMilliseconds)?.int64Value,
              let maxSignatures = coder.decodeObject(of: NSNumber.self, forKey: Keys.maxSignatures)?.intValue,
              let usedSignatures = coder.decodeObject(of: NSNumber.self, forKey: Keys.usedSignatures)?.intValue,
              let childAttached = coder.decodeObject(of: NSNumber.self, forKey: Keys.childAttached)?.boolValue else {
            return nil
        }
        self.init(sessionID: sessionID, status: status, expiresAtMilliseconds: expiresAtMilliseconds, maxSignatures: maxSignatures, usedSignatures: usedSignatures, childAttached: childAttached)
    }

    public func encode(with coder: NSCoder) {
        coder.encode(sessionID as NSString, forKey: Keys.sessionID)
        coder.encode(status as NSString, forKey: Keys.status)
        coder.encode(NSNumber(value: expiresAtMilliseconds), forKey: Keys.expiresAtMilliseconds)
        coder.encode(NSNumber(value: maxSignatures), forKey: Keys.maxSignatures)
        coder.encode(NSNumber(value: usedSignatures), forKey: Keys.usedSignatures)
        coder.encode(NSNumber(value: childAttached), forKey: Keys.childAttached)
    }

    private enum Keys {
        static let sessionID = "session_id"
        static let status = "status"
        static let expiresAtMilliseconds = "expires_at_ms"
        static let maxSignatures = "max_signatures"
        static let usedSignatures = "used_signatures"
        static let childAttached = "child_attached"
    }
}

@objc(AgentPassHostCloseRequest)
public final class AgentPassHostCloseRequest: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }

    public let reason: String

    public init?(reason: AgentPassHostXPCContract.CloseReason) {
        self.reason = reason.rawValue
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard !AgentPassHostXPCContract.containsForbiddenRequestAuthorityKey(coder),
              let reason = coder.decodeObject(of: NSString.self, forKey: Keys.reason) as String?,
              let reason = AgentPassHostXPCContract.CloseReason(rawValue: reason) else {
            return nil
        }
        self.init(reason: reason)
    }

    public func encode(with coder: NSCoder) {
        coder.encode(reason as NSString, forKey: Keys.reason)
    }

    private enum Keys { static let reason = "reason" }
}

@objc(AgentPassHostCloseResponse)
public final class AgentPassHostCloseResponse: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }
    public static let closedStatus = AgentPassHostXPCContract.SessionStatus.closed.rawValue

    public let sessionID: String
    public let status: String
    public let closedAtMilliseconds: Int64

    public init?(sessionID: String, closedAtMilliseconds: Int64) {
        guard let sessionID = AgentPassHostXPCContract.canonicalUUID(sessionID),
              AgentPassHostXPCContract.isTimestamp(closedAtMilliseconds) else {
            return nil
        }
        self.sessionID = sessionID
        self.status = Self.closedStatus
        self.closedAtMilliseconds = closedAtMilliseconds
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard !AgentPassHostXPCContract.containsForbiddenAuthorityKey(coder),
              coder.containsValue(forKey: Keys.closedAtMilliseconds),
              let sessionID = coder.decodeObject(of: NSString.self, forKey: Keys.sessionID) as String?,
              let status = coder.decodeObject(of: NSString.self, forKey: Keys.status) as String?,
              status == Self.closedStatus,
              let closedAtMilliseconds = coder.decodeObject(of: NSNumber.self, forKey: Keys.closedAtMilliseconds)?.int64Value else {
            return nil
        }
        self.init(sessionID: sessionID, closedAtMilliseconds: closedAtMilliseconds)
    }

    public func encode(with coder: NSCoder) {
        coder.encode(sessionID as NSString, forKey: Keys.sessionID)
        coder.encode(status as NSString, forKey: Keys.status)
        coder.encode(NSNumber(value: closedAtMilliseconds), forKey: Keys.closedAtMilliseconds)
    }

    private enum Keys {
        static let sessionID = "session_id"
        static let status = "status"
        static let closedAtMilliseconds = "closed_at_ms"
    }
}

/// Host-only XPC surface. It is connection-owned and intentionally disjoint
/// from both the management and Agent protocols.
@objc public protocol AgentPassHostXPCProtocol {
    func prepareHostSession(_ request: AgentPassHostPrepareRequest, withReply reply: @escaping (AgentPassHostPrepareResponse?, NSError?) -> Void)
    func attachHostChild(_ request: AgentPassHostAttachChildRequest, withReply reply: @escaping (AgentPassHostAttachChildResponse?, NSError?) -> Void)
    func signHostPayload(_ request: AgentPassHostSignRequest, withReply reply: @escaping (AgentPassHostSignResponse?, NSError?) -> Void)
    func hostSessionStatus(_ request: AgentPassHostStatusRequest, withReply reply: @escaping (AgentPassHostStatusResponse?, NSError?) -> Void)
    func closeHostSession(_ request: AgentPassHostCloseRequest, withReply reply: @escaping (AgentPassHostCloseResponse?, NSError?) -> Void)
}

public enum AgentPassHostXPCInterface {
    public static func make() -> NSXPCInterface {
        let interface = NSXPCInterface(with: AgentPassHostXPCProtocol.self)
        register(AgentPassHostPrepareRequest.self, on: interface, selector: #selector(AgentPassHostXPCProtocol.prepareHostSession(_:withReply:)))
        register(AgentPassHostPrepareResponse.self, on: interface, selector: #selector(AgentPassHostXPCProtocol.prepareHostSession(_:withReply:)), reply: true)
        register(AgentPassHostAttachChildRequest.self, on: interface, selector: #selector(AgentPassHostXPCProtocol.attachHostChild(_:withReply:)))
        register(AgentPassHostAttachChildResponse.self, on: interface, selector: #selector(AgentPassHostXPCProtocol.attachHostChild(_:withReply:)), reply: true)
        register(AgentPassHostSignRequest.self, on: interface, selector: #selector(AgentPassHostXPCProtocol.signHostPayload(_:withReply:)))
        register(AgentPassHostSignResponse.self, on: interface, selector: #selector(AgentPassHostXPCProtocol.signHostPayload(_:withReply:)), reply: true)
        register(AgentPassHostStatusRequest.self, on: interface, selector: #selector(AgentPassHostXPCProtocol.hostSessionStatus(_:withReply:)))
        register(AgentPassHostStatusResponse.self, on: interface, selector: #selector(AgentPassHostXPCProtocol.hostSessionStatus(_:withReply:)), reply: true)
        register(AgentPassHostCloseRequest.self, on: interface, selector: #selector(AgentPassHostXPCProtocol.closeHostSession(_:withReply:)))
        register(AgentPassHostCloseResponse.self, on: interface, selector: #selector(AgentPassHostXPCProtocol.closeHostSession(_:withReply:)), reply: true)
        return interface
    }

    private static func register(_ type: AnyClass, on interface: NSXPCInterface, selector: Selector, reply: Bool = false) {
        interface.setClasses(NSSet(array: [type]) as! Set<AnyHashable>, for: selector, argumentIndex: 0, ofReply: reply)
    }
}
