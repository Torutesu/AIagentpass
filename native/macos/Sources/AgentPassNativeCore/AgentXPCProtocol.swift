import Foundation

/// The only adapter kinds currently admitted by the Agent XPC contract.
///
/// This is deliberately a closed list. Adding an adapter is a protocol change,
/// not a caller-controlled string expansion.
public enum AgentPassAgentAdapterKind: String, Sendable {
    case claudeCode = "claude_code"
    case cursor
    case generic
}

/// The only reasons an Agent connection may explicitly close a session.
public enum AgentPassAgentSessionCloseReason: String, Sendable {
    case completed
    case cancelled
    case clientShutdown = "client_shutdown"
}

/// Stable validation failure for Agent XPC DTO construction and decoding.
/// Values intentionally do not include caller-controlled strings or secret data.
public enum AgentPassAgentXPCValidationError: Error, Equatable, Sendable {
    case invalidField
}

/// A strict, secure-coded request used to establish the connection-scoped Agent
/// bootstrap handoff. The native service obtains process identity from the XPC
/// peer; no PID, audit token, argv, environment, path, or credential is carried
/// by this object.
@objc(AgentPassAgentBootstrapRequest)
public final class AgentPassAgentBootstrapRequest: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }

    public static let currentProtocolVersion = 1
    public static let minimumNonceBytes = 16
    public static let maximumNonceBytes = 64
    public static let minimumSessionTTLSeconds = 60
    public static let maximumSessionTTLSeconds = 28_800

    public let protocolVersion: Int
    public let agentID: String
    public let adapterKind: String
    public let requestedTTLSeconds: Int
    public let bootstrapNonce: Data

    public init?(
        protocolVersion: Int = AgentPassAgentBootstrapRequest.currentProtocolVersion,
        agentID: String,
        adapterKind: String,
        requestedTTLSeconds: Int,
        bootstrapNonce: Data
    ) {
        guard protocolVersion == Self.currentProtocolVersion,
              let agentID = AgentXPCValidation.uuid(agentID),
              AgentPassAgentAdapterKind(rawValue: adapterKind) != nil,
              (Self.minimumSessionTTLSeconds...Self.maximumSessionTTLSeconds).contains(requestedTTLSeconds),
              (Self.minimumNonceBytes...Self.maximumNonceBytes).contains(bootstrapNonce.count) else {
            return nil
        }
        self.protocolVersion = protocolVersion
        self.agentID = agentID
        self.adapterKind = adapterKind
        self.requestedTTLSeconds = requestedTTLSeconds
        self.bootstrapNonce = bootstrapNonce
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard coder.containsValue(forKey: Keys.protocolVersion),
              coder.containsValue(forKey: Keys.requestedTTLSeconds),
              let protocolVersion = coder.decodeObject(of: NSNumber.self, forKey: Keys.protocolVersion)?.intValue,
              let agentID = coder.decodeObject(of: NSString.self, forKey: Keys.agentID) as String?,
              let adapterKind = coder.decodeObject(of: NSString.self, forKey: Keys.adapterKind) as String?,
              let requestedTTLSeconds = coder.decodeObject(of: NSNumber.self, forKey: Keys.requestedTTLSeconds)?.intValue,
              let bootstrapNonce = coder.decodeObject(of: NSData.self, forKey: Keys.bootstrapNonce) as Data? else {
            return nil
        }
        self.init(
            protocolVersion: protocolVersion,
            agentID: agentID,
            adapterKind: adapterKind,
            requestedTTLSeconds: requestedTTLSeconds,
            bootstrapNonce: bootstrapNonce
        )
    }

    public func encode(with coder: NSCoder) {
        coder.encode(NSNumber(value: protocolVersion), forKey: Keys.protocolVersion)
        coder.encode(agentID as NSString, forKey: Keys.agentID)
        coder.encode(adapterKind as NSString, forKey: Keys.adapterKind)
        coder.encode(NSNumber(value: requestedTTLSeconds), forKey: Keys.requestedTTLSeconds)
        coder.encode(bootstrapNonce as NSData, forKey: Keys.bootstrapNonce)
    }

    private enum Keys {
        static let protocolVersion = "protocol_version"
        static let agentID = "agent_id"
        static let adapterKind = "adapter_kind"
        static let requestedTTLSeconds = "requested_ttl_seconds"
        static let bootstrapNonce = "bootstrap_nonce"
    }
}

/// The response to bootstrap. `challenge` is a one-time bounded proof input;
/// it is not a bearer session token or a capability value.
@objc(AgentPassAgentBootstrapResponse)
public final class AgentPassAgentBootstrapResponse: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }

    public static let minimumChallengeBytes = 16
    public static let maximumChallengeBytes = 256

    public let bootstrapID: String
    public let challenge: Data
    public let expiresAtMilliseconds: Int64

    public init?(bootstrapID: String, challenge: Data, expiresAtMilliseconds: Int64) {
        guard let bootstrapID = AgentXPCValidation.uuid(bootstrapID),
              (Self.minimumChallengeBytes...Self.maximumChallengeBytes).contains(challenge.count),
              AgentXPCValidation.timestamp(expiresAtMilliseconds) else {
            return nil
        }
        self.bootstrapID = bootstrapID
        self.challenge = challenge
        self.expiresAtMilliseconds = expiresAtMilliseconds
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard coder.containsValue(forKey: Keys.expiresAtMilliseconds),
              let bootstrapID = coder.decodeObject(of: NSString.self, forKey: Keys.bootstrapID) as String?,
              let challenge = coder.decodeObject(of: NSData.self, forKey: Keys.challenge) as Data?,
              let expiresAtMilliseconds = coder.decodeObject(of: NSNumber.self, forKey: Keys.expiresAtMilliseconds)?.int64Value else {
            return nil
        }
        self.init(bootstrapID: bootstrapID, challenge: challenge, expiresAtMilliseconds: expiresAtMilliseconds)
    }

    public func encode(with coder: NSCoder) {
        coder.encode(bootstrapID as NSString, forKey: Keys.bootstrapID)
        coder.encode(challenge as NSData, forKey: Keys.challenge)
        coder.encode(NSNumber(value: expiresAtMilliseconds), forKey: Keys.expiresAtMilliseconds)
    }

    private enum Keys {
        static let bootstrapID = "bootstrap_id"
        static let challenge = "challenge"
        static let expiresAtMilliseconds = "expires_at_ms"
    }
}

/// A one-time proof of the bootstrap challenge. The proof is opaque to the
/// transport, bounded, and never treated as a reusable session credential.
@objc(AgentPassAgentSessionRequest)
public final class AgentPassAgentSessionRequest: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }

    public static let minimumProofBytes = 16
    public static let maximumProofBytes = 4 * 1024

    public let bootstrapID: String
    public let proof: Data

    public init?(bootstrapID: String, proof: Data) {
        guard let bootstrapID = AgentXPCValidation.uuid(bootstrapID),
              (Self.minimumProofBytes...Self.maximumProofBytes).contains(proof.count) else {
            return nil
        }
        self.bootstrapID = bootstrapID
        self.proof = proof
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard let bootstrapID = coder.decodeObject(of: NSString.self, forKey: Keys.bootstrapID) as String?,
              let proof = coder.decodeObject(of: NSData.self, forKey: Keys.proof) as Data? else {
            return nil
        }
        self.init(bootstrapID: bootstrapID, proof: proof)
    }

    public func encode(with coder: NSCoder) {
        coder.encode(bootstrapID as NSString, forKey: Keys.bootstrapID)
        coder.encode(proof as NSData, forKey: Keys.proof)
    }

    private enum Keys {
        static let bootstrapID = "bootstrap_id"
        static let proof = "proof"
    }
}

/// The public, correlation-only lease returned after a successful session
/// start. It contains digests, not raw process identity or a capability secret.
@objc(AgentPassAgentSessionResponse)
public final class AgentPassAgentSessionResponse: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }

    public static let minimumSignatureBudget = 1
    public static let maximumSignatureBudget = 1_024

    public let sessionID: String
    public let leaseID: String
    public let processBindingDigest: Data
    public let worktreeBindingDigest: Data
    public let expiresAtMilliseconds: Int64
    public let maxSignatures: Int

    public init?(
        sessionID: String,
        leaseID: String,
        processBindingDigest: Data,
        worktreeBindingDigest: Data,
        expiresAtMilliseconds: Int64,
        maxSignatures: Int
    ) {
        guard let sessionID = AgentXPCValidation.uuid(sessionID),
              let leaseID = AgentXPCValidation.uuid(leaseID),
              AgentXPCValidation.digest(processBindingDigest),
              AgentXPCValidation.digest(worktreeBindingDigest),
              AgentXPCValidation.timestamp(expiresAtMilliseconds),
              (Self.minimumSignatureBudget...Self.maximumSignatureBudget).contains(maxSignatures) else {
            return nil
        }
        self.sessionID = sessionID
        self.leaseID = leaseID
        self.processBindingDigest = processBindingDigest
        self.worktreeBindingDigest = worktreeBindingDigest
        self.expiresAtMilliseconds = expiresAtMilliseconds
        self.maxSignatures = maxSignatures
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard coder.containsValue(forKey: Keys.expiresAtMilliseconds),
              coder.containsValue(forKey: Keys.maxSignatures),
              let sessionID = coder.decodeObject(of: NSString.self, forKey: Keys.sessionID) as String?,
              let leaseID = coder.decodeObject(of: NSString.self, forKey: Keys.leaseID) as String?,
              let processBindingDigest = coder.decodeObject(of: NSData.self, forKey: Keys.processBindingDigest) as Data?,
              let worktreeBindingDigest = coder.decodeObject(of: NSData.self, forKey: Keys.worktreeBindingDigest) as Data?,
              let expiresAtMilliseconds = coder.decodeObject(of: NSNumber.self, forKey: Keys.expiresAtMilliseconds)?.int64Value,
              let maxSignatures = coder.decodeObject(of: NSNumber.self, forKey: Keys.maxSignatures)?.intValue else {
            return nil
        }
        self.init(
            sessionID: sessionID,
            leaseID: leaseID,
            processBindingDigest: processBindingDigest,
            worktreeBindingDigest: worktreeBindingDigest,
            expiresAtMilliseconds: expiresAtMilliseconds,
            maxSignatures: maxSignatures
        )
    }

    public func encode(with coder: NSCoder) {
        coder.encode(sessionID as NSString, forKey: Keys.sessionID)
        coder.encode(leaseID as NSString, forKey: Keys.leaseID)
        coder.encode(processBindingDigest as NSData, forKey: Keys.processBindingDigest)
        coder.encode(worktreeBindingDigest as NSData, forKey: Keys.worktreeBindingDigest)
        coder.encode(NSNumber(value: expiresAtMilliseconds), forKey: Keys.expiresAtMilliseconds)
        coder.encode(NSNumber(value: maxSignatures), forKey: Keys.maxSignatures)
    }

    private enum Keys {
        static let sessionID = "session_id"
        static let leaseID = "lease_id"
        static let processBindingDigest = "process_binding_digest"
        static let worktreeBindingDigest = "worktree_binding_digest"
        static let expiresAtMilliseconds = "expires_at_ms"
        static let maxSignatures = "max_signatures"
    }
}

/// Request for a read-only session status snapshot.
@objc(AgentPassAgentSessionStatusRequest)
public final class AgentPassAgentSessionStatusRequest: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }
    public let sessionID: String

    public init?(sessionID: String) {
        guard let sessionID = AgentXPCValidation.uuid(sessionID) else { return nil }
        self.sessionID = sessionID
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard let sessionID = coder.decodeObject(of: NSString.self, forKey: Keys.sessionID) as String? else { return nil }
        self.init(sessionID: sessionID)
    }

    public func encode(with coder: NSCoder) {
        coder.encode(sessionID as NSString, forKey: Keys.sessionID)
    }

    private enum Keys { static let sessionID = "session_id" }
}

/// Closed session lifecycle values returned by the Agent surface.
@objc(AgentPassAgentSessionStatusResponse)
public final class AgentPassAgentSessionStatusResponse: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }

    public let sessionID: String
    public let status: String
    public let expiresAtMilliseconds: Int64
    public let maxSignatures: Int
    public let usedSignatures: Int

    public init?(
        sessionID: String,
        status: String,
        expiresAtMilliseconds: Int64,
        maxSignatures: Int,
        usedSignatures: Int
    ) {
        guard let sessionID = AgentXPCValidation.uuid(sessionID),
              AgentXPCValidation.sessionStatus(status),
              AgentXPCValidation.timestamp(expiresAtMilliseconds),
              (AgentPassAgentSessionResponse.minimumSignatureBudget...AgentPassAgentSessionResponse.maximumSignatureBudget).contains(maxSignatures),
              (0...maxSignatures).contains(usedSignatures) else {
            return nil
        }
        self.sessionID = sessionID
        self.status = status
        self.expiresAtMilliseconds = expiresAtMilliseconds
        self.maxSignatures = maxSignatures
        self.usedSignatures = usedSignatures
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard coder.containsValue(forKey: Keys.expiresAtMilliseconds),
              coder.containsValue(forKey: Keys.maxSignatures),
              coder.containsValue(forKey: Keys.usedSignatures),
              let sessionID = coder.decodeObject(of: NSString.self, forKey: Keys.sessionID) as String?,
              let status = coder.decodeObject(of: NSString.self, forKey: Keys.status) as String?,
              let expiresAtMilliseconds = coder.decodeObject(of: NSNumber.self, forKey: Keys.expiresAtMilliseconds)?.int64Value,
              let maxSignatures = coder.decodeObject(of: NSNumber.self, forKey: Keys.maxSignatures)?.intValue,
              let usedSignatures = coder.decodeObject(of: NSNumber.self, forKey: Keys.usedSignatures)?.intValue else {
            return nil
        }
        self.init(
            sessionID: sessionID,
            status: status,
            expiresAtMilliseconds: expiresAtMilliseconds,
            maxSignatures: maxSignatures,
            usedSignatures: usedSignatures
        )
    }

    public func encode(with coder: NSCoder) {
        coder.encode(sessionID as NSString, forKey: Keys.sessionID)
        coder.encode(status as NSString, forKey: Keys.status)
        coder.encode(NSNumber(value: expiresAtMilliseconds), forKey: Keys.expiresAtMilliseconds)
        coder.encode(NSNumber(value: maxSignatures), forKey: Keys.maxSignatures)
        coder.encode(NSNumber(value: usedSignatures), forKey: Keys.usedSignatures)
    }

    private enum Keys {
        static let sessionID = "session_id"
        static let status = "status"
        static let expiresAtMilliseconds = "expires_at_ms"
        static let maxSignatures = "max_signatures"
        static let usedSignatures = "used_signatures"
    }
}

/// A fixed Git commit-sign request. There is intentionally no operation,
/// namespace, key selector, signer argument, session token, or private key field:
/// this DTO can express only the first supported operation.
@objc(AgentPassAgentSignRequest)
public final class AgentPassAgentSignRequest: NSObject, NSSecureCoding, @unchecked Sendable {
    public static var supportsSecureCoding: Bool { true }

    public static let minimumNonceBytes = 16
    public static let maximumNonceBytes = 64
    public static let maximumCommitPayloadBytes = 1 * 1024 * 1024

    public let sessionID: String
    public let requestID: String
    public let capabilityID: String
    public let commitPayload: Data
    public let requestNonce: Data
    public let createdAtMilliseconds: Int64

    public init?(
        sessionID: String,
        requestID: String,
        capabilityID: String,
        commitPayload: Data,
        requestNonce: Data,
        createdAtMilliseconds: Int64
    ) {
        guard let sessionID = AgentXPCValidation.uuid(sessionID),
              let requestID = AgentXPCValidation.uuid(requestID),
              let capabilityID = AgentXPCValidation.uuid(capabilityID),
              !commitPayload.isEmpty,
              commitPayload.count <= Self.maximumCommitPayloadBytes,
              (Self.minimumNonceBytes...Self.maximumNonceBytes).contains(requestNonce.count),
              AgentXPCValidation.timestamp(createdAtMilliseconds) else {
            return nil
        }
        self.sessionID = sessionID
        self.requestID = requestID
        self.capabilityID = capabilityID
        self.commitPayload = commitPayload
        self.requestNonce = requestNonce
        self.createdAtMilliseconds = createdAtMilliseconds
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard coder.containsValue(forKey: Keys.createdAtMilliseconds),
              let sessionID = coder.decodeObject(of: NSString.self, forKey: Keys.sessionID) as String?,
              let requestID = coder.decodeObject(of: NSString.self, forKey: Keys.requestID) as String?,
              let capabilityID = coder.decodeObject(of: NSString.self, forKey: Keys.capabilityID) as String?,
              let commitPayload = coder.decodeObject(of: NSData.self, forKey: Keys.commitPayload) as Data?,
              let requestNonce = coder.decodeObject(of: NSData.self, forKey: Keys.requestNonce) as Data?,
              let createdAtMilliseconds = coder.decodeObject(of: NSNumber.self, forKey: Keys.createdAtMilliseconds)?.int64Value else {
            return nil
        }
        self.init(
            sessionID: sessionID,
            requestID: requestID,
            capabilityID: capabilityID,
            commitPayload: commitPayload,
            requestNonce: requestNonce,
            createdAtMilliseconds: createdAtMilliseconds
        )
    }

    public func encode(with coder: NSCoder) {
        coder.encode(sessionID as NSString, forKey: Keys.sessionID)
        coder.encode(requestID as NSString, forKey: Keys.requestID)
        coder.encode(capabilityID as NSString, forKey: Keys.capabilityID)
        coder.encode(commitPayload as NSData, forKey: Keys.commitPayload)
        coder.encode(requestNonce as NSData, forKey: Keys.requestNonce)
        coder.encode(NSNumber(value: createdAtMilliseconds), forKey: Keys.createdAtMilliseconds)
    }

    private enum Keys {
        static let sessionID = "session_id"
        static let requestID = "request_id"
        static let capabilityID = "capability_id"
        static let commitPayload = "commit_payload"
        static let requestNonce = "request_nonce"
        static let createdAtMilliseconds = "created_at_ms"
    }
}

/// The result of the fixed Git commit-sign operation. The signature is the
/// intended output, never a key or a general signing handle.
@objc(AgentPassAgentSignResponse)
public final class AgentPassAgentSignResponse: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }

    public static let maximumSignatureBytes = 64 * 1024

    public let requestID: String
    public let signature: Data
    public let remainingSignatures: Int

    public init?(requestID: String, signature: Data, remainingSignatures: Int) {
        guard let requestID = AgentXPCValidation.uuid(requestID),
              !signature.isEmpty,
              signature.count <= Self.maximumSignatureBytes,
              (0...AgentPassAgentSessionResponse.maximumSignatureBudget).contains(remainingSignatures) else {
            return nil
        }
        self.requestID = requestID
        self.signature = signature
        self.remainingSignatures = remainingSignatures
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard coder.containsValue(forKey: Keys.remainingSignatures),
              let requestID = coder.decodeObject(of: NSString.self, forKey: Keys.requestID) as String?,
              let signature = coder.decodeObject(of: NSData.self, forKey: Keys.signature) as Data?,
              let remainingSignatures = coder.decodeObject(of: NSNumber.self, forKey: Keys.remainingSignatures)?.intValue else {
            return nil
        }
        self.init(requestID: requestID, signature: signature, remainingSignatures: remainingSignatures)
    }

    public func encode(with coder: NSCoder) {
        coder.encode(requestID as NSString, forKey: Keys.requestID)
        coder.encode(signature as NSData, forKey: Keys.signature)
        coder.encode(NSNumber(value: remainingSignatures), forKey: Keys.remainingSignatures)
    }

    private enum Keys {
        static let requestID = "request_id"
        static let signature = "signature"
        static let remainingSignatures = "remaining_signatures"
    }
}

/// A bounded close request. Closing is the only lifecycle mutation exposed to
/// an Agent after session creation.
@objc(AgentPassAgentCloseSessionRequest)
public final class AgentPassAgentCloseSessionRequest: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }
    public let sessionID: String
    public let reason: String

    public init?(sessionID: String, reason: String) {
        guard let sessionID = AgentXPCValidation.uuid(sessionID),
              AgentPassAgentSessionCloseReason(rawValue: reason) != nil else {
            return nil
        }
        self.sessionID = sessionID
        self.reason = reason
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard let sessionID = coder.decodeObject(of: NSString.self, forKey: Keys.sessionID) as String?,
              let reason = coder.decodeObject(of: NSString.self, forKey: Keys.reason) as String? else {
            return nil
        }
        self.init(sessionID: sessionID, reason: reason)
    }

    public func encode(with coder: NSCoder) {
        coder.encode(sessionID as NSString, forKey: Keys.sessionID)
        coder.encode(reason as NSString, forKey: Keys.reason)
    }

    private enum Keys {
        static let sessionID = "session_id"
        static let reason = "reason"
    }
}

@objc(AgentPassAgentCloseSessionResponse)
public final class AgentPassAgentCloseSessionResponse: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }
    public static let closedStatus = "closed"

    public let sessionID: String
    public let status: String
    public let closedAtMilliseconds: Int64

    public init?(sessionID: String, closedAtMilliseconds: Int64) {
        guard let sessionID = AgentXPCValidation.uuid(sessionID),
              AgentXPCValidation.timestamp(closedAtMilliseconds) else {
            return nil
        }
        self.sessionID = sessionID
        self.status = Self.closedStatus
        self.closedAtMilliseconds = closedAtMilliseconds
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard coder.containsValue(forKey: Keys.closedAtMilliseconds),
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

/// A dedicated Agent-only XPC surface. It is intentionally disjoint from
/// `AgentPassNativeServiceProtocol`: no setup approval, key lifecycle, audit
/// administration/pruning, ControlBundle mutation, or management status call
/// is expressible here.
@objc public protocol AgentPassAgentXPCProtocol {
    func bootstrapAgent(_ request: AgentPassAgentBootstrapRequest, withReply reply: @escaping (AgentPassAgentBootstrapResponse?, NSError?) -> Void)
    func startAgentSession(_ request: AgentPassAgentSessionRequest, withReply reply: @escaping (AgentPassAgentSessionResponse?, NSError?) -> Void)
    func agentSessionStatus(_ request: AgentPassAgentSessionStatusRequest, withReply reply: @escaping (AgentPassAgentSessionStatusResponse?, NSError?) -> Void)
    func signGitCommit(_ request: AgentPassAgentSignRequest, withReply reply: @escaping (AgentPassAgentSignResponse?, NSError?) -> Void)
    func closeAgentSession(_ request: AgentPassAgentCloseSessionRequest, withReply reply: @escaping (AgentPassAgentCloseSessionResponse?, NSError?) -> Void)
}

/// Creates the interface that a future Agent listener and client must use.
/// Registering the exact secure-coded classes here prevents an XPC endpoint
/// from accidentally widening the allowed object graph when it is wired.
public enum AgentPassAgentXPCInterface {
    public static func make() -> NSXPCInterface {
        let interface = NSXPCInterface(with: AgentPassAgentXPCProtocol.self)
        register(AgentPassAgentBootstrapRequest.self, on: interface, selector: #selector(AgentPassAgentXPCProtocol.bootstrapAgent(_:withReply:)))
        register(AgentPassAgentBootstrapResponse.self, on: interface, selector: #selector(AgentPassAgentXPCProtocol.bootstrapAgent(_:withReply:)), reply: true)
        register(AgentPassAgentSessionRequest.self, on: interface, selector: #selector(AgentPassAgentXPCProtocol.startAgentSession(_:withReply:)))
        register(AgentPassAgentSessionResponse.self, on: interface, selector: #selector(AgentPassAgentXPCProtocol.startAgentSession(_:withReply:)), reply: true)
        register(AgentPassAgentSessionStatusRequest.self, on: interface, selector: #selector(AgentPassAgentXPCProtocol.agentSessionStatus(_:withReply:)))
        register(AgentPassAgentSessionStatusResponse.self, on: interface, selector: #selector(AgentPassAgentXPCProtocol.agentSessionStatus(_:withReply:)), reply: true)
        register(AgentPassAgentSignRequest.self, on: interface, selector: #selector(AgentPassAgentXPCProtocol.signGitCommit(_:withReply:)))
        register(AgentPassAgentSignResponse.self, on: interface, selector: #selector(AgentPassAgentXPCProtocol.signGitCommit(_:withReply:)), reply: true)
        register(AgentPassAgentCloseSessionRequest.self, on: interface, selector: #selector(AgentPassAgentXPCProtocol.closeAgentSession(_:withReply:)))
        register(AgentPassAgentCloseSessionResponse.self, on: interface, selector: #selector(AgentPassAgentXPCProtocol.closeAgentSession(_:withReply:)), reply: true)
        return interface
    }

    private static func register(_ type: AnyClass, on interface: NSXPCInterface, selector: Selector, reply: Bool = false) {
        interface.setClasses(NSSet(array: [type]) as! Set<AnyHashable>, for: selector, argumentIndex: 0, ofReply: reply)
    }
}

private enum AgentXPCValidation {
    static let maximumTimestampMilliseconds: Int64 = 4_102_444_800_000 // 2100-01-01T00:00:00Z

    static func uuid(_ value: String) -> String? {
        guard value.utf8.count == 36, let uuid = UUID(uuidString: value) else { return nil }
        return uuid.uuidString.lowercased()
    }

    static func digest(_ value: Data) -> Bool { value.count == 32 }

    static func timestamp(_ value: Int64) -> Bool {
        (0...maximumTimestampMilliseconds).contains(value)
    }

    static func sessionStatus(_ value: String) -> Bool {
        ["active", "expired", "revoked", "closed"].contains(value)
    }
}
