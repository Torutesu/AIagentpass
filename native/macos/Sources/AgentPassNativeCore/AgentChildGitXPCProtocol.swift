import Foundation

/// Child-side signing channel used after the Host has registered the child
/// identity on its connection-owned session. The child connection itself is
/// the authority boundary; no session ID, capability, key selector, path, or
/// inherited descriptor is carried by these DTOs.
public enum AgentPassChildGitXPCContract {
    public static let protocolVersion = 3
    public static let maximumPayloadBytes = 1 * 1024 * 1024
    public static let maximumSignatureBytes = 4 * 1024
    public static let attachTicketBytes = 32
    public static let maximumAttachTicketLifetimeMilliseconds: Int64 = 5 * 60 * 1_000
    public static let maximumRequests: UInt32 = UInt32(NativeAgentSignatureBudget.maximumSignatures)

    public static func validSequence(_ value: UInt32) -> Bool {
        (1...maximumRequests).contains(value)
    }

    public static func canonicalRequestID(_ value: String) -> String? {
        AgentPassHostXPCContract.canonicalUUID(value)
    }

    /// A legacy request may omit both fields for source compatibility. The
    /// service binds that compatibility path only to the strict pair it issued
    /// in the attach response; partial or malformed correlation is rejected.
    public static func validRequestCorrelation(requestID: String, createdAtMilliseconds: Int64) -> Bool {
        if requestID.isEmpty && createdAtMilliseconds == 0 {
            return true
        }
        return canonicalRequestID(requestID) != nil
            && AgentPassHostXPCContract.isTimestamp(createdAtMilliseconds)
    }
}

/// The Child service needs to match one observed ancestor of a Git helper to
/// the process facts captured when the Host attached the supervised child.
/// `NativeProcessIdentity.canonicalBindingHash` includes ancestry, so this
/// process-only projection is deliberately explicit and computed by Core's
/// canonicalizer rather than reconstructed in the Service target.
public extension NativeObservedProcessFacts {
    var canonicalProcessBindingHash: String {
        let observation = try! NativeProcessObservation(process: self, ancestry: [])
        return NativeProcessIdentity(observation: observation).canonicalBindingHash
    }
}

@objc(AgentPassChildGitAttachRequest)
public final class AgentPassChildGitAttachRequest: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }

    public let protocolVersion: Int

    public init?(protocolVersion: Int = AgentPassChildGitXPCContract.protocolVersion) {
        guard protocolVersion == AgentPassChildGitXPCContract.protocolVersion else {
            return nil
        }
        self.protocolVersion = protocolVersion
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard !Self.containsForbiddenKey(coder),
              coder.containsValue(forKey: Keys.protocolVersion),
              let protocolVersion = coder.decodeObject(of: NSNumber.self, forKey: Keys.protocolVersion)?.intValue else {
            return nil
        }
        self.init(protocolVersion: protocolVersion)
    }

    public func encode(with coder: NSCoder) {
        coder.encode(NSNumber(value: protocolVersion), forKey: Keys.protocolVersion)
    }

    private enum Keys {
        static let protocolVersion = "protocol_version"
    }

    private static func containsForbiddenKey(_ coder: NSCoder) -> Bool {
        forbiddenKeys.contains { coder.containsValue(forKey: $0) }
    }

    private static let forbiddenKeys = [
        "session_id", "capability", "capability_id", "private_key", "private_key_data",
        "key", "key_id", "algorithm", "operation", "repository", "repository_path",
        "worktree_path", "token", "session_token", "scope", "authority", "lease",
        "argv", "environment", "env", "file", "path", "attach_ticket", "expires_at_ms",
        "future_authority"
    ]
}

@objc(AgentPassChildGitAttachResponse)
public final class AgentPassChildGitAttachResponse: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }

    public let protocolVersion: Int
    public let attachTicket: Data
    public let expiresAtMilliseconds: Int64
    /// Issued by the service for the one sign operation bound to this ticket.
    public let requestID: String
    public let createdAtMilliseconds: Int64

    public init?(
        protocolVersion: Int = AgentPassChildGitXPCContract.protocolVersion,
        attachTicket: Data,
        expiresAtMilliseconds: Int64,
        requestID: String,
        createdAtMilliseconds: Int64
    ) {
        guard protocolVersion == AgentPassChildGitXPCContract.protocolVersion,
              attachTicket.count == AgentPassChildGitXPCContract.attachTicketBytes,
              attachTicket.contains(where: { $0 != 0 }),
              AgentPassHostXPCContract.isTimestamp(expiresAtMilliseconds),
              let canonicalRequestID = AgentPassChildGitXPCContract.canonicalRequestID(requestID),
              AgentPassHostXPCContract.isTimestamp(createdAtMilliseconds),
              createdAtMilliseconds <= expiresAtMilliseconds else {
            return nil
        }
        self.protocolVersion = protocolVersion
        self.attachTicket = attachTicket
        self.expiresAtMilliseconds = expiresAtMilliseconds
        self.requestID = canonicalRequestID
        self.createdAtMilliseconds = createdAtMilliseconds
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard !Self.containsForbiddenKey(coder),
              coder.containsValue(forKey: Keys.protocolVersion),
              coder.containsValue(forKey: Keys.attachTicket),
              coder.containsValue(forKey: Keys.expiresAtMilliseconds),
              coder.containsValue(forKey: Keys.requestID),
              coder.containsValue(forKey: Keys.createdAtMilliseconds),
              let protocolVersion = coder.decodeObject(of: NSNumber.self, forKey: Keys.protocolVersion)?.intValue,
              let attachTicket = coder.decodeObject(of: NSData.self, forKey: Keys.attachTicket) as Data?,
              let expiresAtMilliseconds = coder.decodeObject(of: NSNumber.self, forKey: Keys.expiresAtMilliseconds)?.int64Value,
              let requestID = coder.decodeObject(of: NSString.self, forKey: Keys.requestID) as String?,
              let createdAtMilliseconds = coder.decodeObject(of: NSNumber.self, forKey: Keys.createdAtMilliseconds)?.int64Value else {
            return nil
        }
        self.init(
            protocolVersion: protocolVersion,
            attachTicket: attachTicket,
            expiresAtMilliseconds: expiresAtMilliseconds,
            requestID: requestID,
            createdAtMilliseconds: createdAtMilliseconds
        )
    }

    public func encode(with coder: NSCoder) {
        coder.encode(NSNumber(value: protocolVersion), forKey: Keys.protocolVersion)
        coder.encode(attachTicket as NSData, forKey: Keys.attachTicket)
        coder.encode(NSNumber(value: expiresAtMilliseconds), forKey: Keys.expiresAtMilliseconds)
        coder.encode(requestID as NSString, forKey: Keys.requestID)
        coder.encode(NSNumber(value: createdAtMilliseconds), forKey: Keys.createdAtMilliseconds)
    }

    private enum Keys {
        static let protocolVersion = "protocol_version"
        static let attachTicket = "attach_ticket"
        static let expiresAtMilliseconds = "expires_at_ms"
        static let requestID = "request_id"
        static let createdAtMilliseconds = "created_at_ms"
    }

    private static func containsForbiddenKey(_ coder: NSCoder) -> Bool {
        forbiddenKeys.contains { coder.containsValue(forKey: $0) }
    }

    private static let forbiddenKeys = [
        "session_id", "capability", "capability_id", "private_key", "private_key_data",
        "key", "key_id", "algorithm", "operation", "repository", "repository_path",
        "worktree_path", "token", "session_token", "scope", "authority", "lease",
        "argv", "environment", "env", "file", "path", "future_authority"
    ]
}

@objc(AgentPassChildGitSignRequest)
public final class AgentPassChildGitSignRequest: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }

    public let protocolVersion: Int
    public let requestSequence: UInt32
    public let commitPayload: Data
    public let attachTicket: Data
    /// Optional on the source-compatible client path; the service binds an
    /// omitted value to the ID and timestamp issued with the attach ticket.
    public let requestID: String
    public let createdAtMilliseconds: Int64

    /// Source-compatible initializer for legacy callers. The service accepts
    /// this shape only by binding it to the strict service-generated attach
    /// response pair.
    public convenience init?(
        protocolVersion: Int = AgentPassChildGitXPCContract.protocolVersion,
        requestSequence: UInt32,
        commitPayload: Data,
        attachTicket: Data
    ) {
        self.init(
            protocolVersion: protocolVersion,
            requestSequence: requestSequence,
            commitPayload: commitPayload,
            attachTicket: attachTicket,
            requestID: "",
            createdAtMilliseconds: 0
        )
    }

    public init?(
        protocolVersion: Int = AgentPassChildGitXPCContract.protocolVersion,
        requestSequence: UInt32,
        commitPayload: Data,
        attachTicket: Data,
        requestID: String,
        createdAtMilliseconds: Int64
    ) {
        guard protocolVersion == AgentPassChildGitXPCContract.protocolVersion,
              AgentPassChildGitXPCContract.validSequence(requestSequence),
              !commitPayload.isEmpty,
              commitPayload.count <= AgentPassChildGitXPCContract.maximumPayloadBytes,
              attachTicket.count == AgentPassChildGitXPCContract.attachTicketBytes,
              attachTicket.contains(where: { $0 != 0 }),
              AgentPassChildGitXPCContract.validRequestCorrelation(
                  requestID: requestID,
                  createdAtMilliseconds: createdAtMilliseconds
              ) else {
            return nil
        }
        self.protocolVersion = protocolVersion
        self.requestSequence = requestSequence
        self.commitPayload = commitPayload
        self.attachTicket = attachTicket
        self.requestID = requestID.isEmpty ? "" : requestID.lowercased()
        self.createdAtMilliseconds = createdAtMilliseconds
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard !Self.containsForbiddenKey(coder),
              let protocolVersion = coder.decodeObject(of: NSNumber.self, forKey: Keys.protocolVersion)?.intValue,
              let requestSequence = coder.decodeObject(of: NSNumber.self, forKey: Keys.requestSequence)?.uint32Value,
              let commitPayload = coder.decodeObject(of: NSData.self, forKey: Keys.commitPayload) as Data?,
              let attachTicket = coder.decodeObject(of: NSData.self, forKey: Keys.attachTicket) as Data?,
              let requestID = coder.decodeObject(of: NSString.self, forKey: Keys.requestID) as String?,
              let createdAtMilliseconds = coder.decodeObject(of: NSNumber.self, forKey: Keys.createdAtMilliseconds)?.int64Value else {
            return nil
        }
        self.init(
            protocolVersion: protocolVersion,
            requestSequence: requestSequence,
            commitPayload: commitPayload,
            attachTicket: attachTicket,
            requestID: requestID,
            createdAtMilliseconds: createdAtMilliseconds
        )
    }

    public func encode(with coder: NSCoder) {
        coder.encode(NSNumber(value: protocolVersion), forKey: Keys.protocolVersion)
        coder.encode(NSNumber(value: requestSequence), forKey: Keys.requestSequence)
        coder.encode(commitPayload as NSData, forKey: Keys.commitPayload)
        coder.encode(attachTicket as NSData, forKey: Keys.attachTicket)
        coder.encode(requestID as NSString, forKey: Keys.requestID)
        coder.encode(NSNumber(value: createdAtMilliseconds), forKey: Keys.createdAtMilliseconds)
    }

    private enum Keys {
        static let protocolVersion = "protocol_version"
        static let requestSequence = "request_sequence"
        static let commitPayload = "commit_payload"
        static let attachTicket = "attach_ticket"
        static let requestID = "request_id"
        static let createdAtMilliseconds = "created_at_ms"
    }

    private static let forbiddenKeys = [
        "session_id", "capability", "capability_id", "private_key", "private_key_data",
        "key", "key_id", "algorithm", "operation", "repository", "repository_path",
        "worktree_path", "token", "session_token", "scope", "authority", "lease",
        "argv", "environment", "env", "file", "path", "future_authority"
    ]

    private static func containsForbiddenKey(_ coder: NSCoder) -> Bool {
        forbiddenKeys.contains { coder.containsValue(forKey: $0) }
    }
}

@objc(AgentPassChildGitSignResponse)
public final class AgentPassChildGitSignResponse: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }

    public let protocolVersion: Int
    public let responseSequence: UInt32
    public let signature: Data
    public let maxSignatures: Int
    public let usedSignatures: Int
    public let remainingSignatures: Int
    public let requestID: String
    public let createdAtMilliseconds: Int64

    public init?(
        protocolVersion: Int = AgentPassChildGitXPCContract.protocolVersion,
        responseSequence: UInt32,
        signature: Data,
        maxSignatures: Int,
        usedSignatures: Int,
        remainingSignatures: Int,
        requestID: String,
        createdAtMilliseconds: Int64
    ) {
        guard protocolVersion == AgentPassChildGitXPCContract.protocolVersion,
              AgentPassChildGitXPCContract.validSequence(responseSequence),
              !signature.isEmpty,
              signature.count <= AgentPassChildGitXPCContract.maximumSignatureBytes,
              (NativeAgentSignatureBudget.minimumSignatures...NativeAgentSignatureBudget.maximumSignatures).contains(maxSignatures),
              (0...maxSignatures).contains(usedSignatures),
              remainingSignatures == maxSignatures - usedSignatures,
              let canonicalRequestID = AgentPassChildGitXPCContract.canonicalRequestID(requestID),
              AgentPassHostXPCContract.isTimestamp(createdAtMilliseconds) else {
            return nil
        }
        self.protocolVersion = protocolVersion
        self.responseSequence = responseSequence
        self.signature = signature
        self.maxSignatures = maxSignatures
        self.usedSignatures = usedSignatures
        self.remainingSignatures = remainingSignatures
        self.requestID = canonicalRequestID
        self.createdAtMilliseconds = createdAtMilliseconds
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard let protocolVersion = coder.decodeObject(of: NSNumber.self, forKey: Keys.protocolVersion)?.intValue,
              let responseSequence = coder.decodeObject(of: NSNumber.self, forKey: Keys.responseSequence)?.uint32Value,
              let signature = coder.decodeObject(of: NSData.self, forKey: Keys.signature) as Data?,
              let maxSignatures = coder.decodeObject(of: NSNumber.self, forKey: Keys.maxSignatures)?.intValue,
              let usedSignatures = coder.decodeObject(of: NSNumber.self, forKey: Keys.usedSignatures)?.intValue,
              let remainingSignatures = coder.decodeObject(of: NSNumber.self, forKey: Keys.remainingSignatures)?.intValue,
              let requestID = coder.decodeObject(of: NSString.self, forKey: Keys.requestID) as String?,
              let createdAtMilliseconds = coder.decodeObject(of: NSNumber.self, forKey: Keys.createdAtMilliseconds)?.int64Value else {
            return nil
        }
        self.init(protocolVersion: protocolVersion, responseSequence: responseSequence, signature: signature, maxSignatures: maxSignatures, usedSignatures: usedSignatures, remainingSignatures: remainingSignatures, requestID: requestID, createdAtMilliseconds: createdAtMilliseconds)
    }

    public func encode(with coder: NSCoder) {
        coder.encode(NSNumber(value: protocolVersion), forKey: Keys.protocolVersion)
        coder.encode(NSNumber(value: responseSequence), forKey: Keys.responseSequence)
        coder.encode(signature as NSData, forKey: Keys.signature)
        coder.encode(NSNumber(value: maxSignatures), forKey: Keys.maxSignatures)
        coder.encode(NSNumber(value: usedSignatures), forKey: Keys.usedSignatures)
        coder.encode(NSNumber(value: remainingSignatures), forKey: Keys.remainingSignatures)
        coder.encode(requestID as NSString, forKey: Keys.requestID)
        coder.encode(NSNumber(value: createdAtMilliseconds), forKey: Keys.createdAtMilliseconds)
    }

    private enum Keys {
        static let protocolVersion = "protocol_version"
        static let responseSequence = "response_sequence"
        static let signature = "signature"
        static let maxSignatures = "max_signatures"
        static let usedSignatures = "used_signatures"
        static let remainingSignatures = "remaining_signatures"
        static let requestID = "request_id"
        static let createdAtMilliseconds = "created_at_ms"
    }
}

@objc public protocol AgentPassChildGitXPCProtocol {
    func attachChildGit(_ request: AgentPassChildGitAttachRequest, withReply reply: @escaping (AgentPassChildGitAttachResponse?, NSError?) -> Void)
    func signChildGitCommit(_ request: AgentPassChildGitSignRequest, withReply reply: @escaping (AgentPassChildGitSignResponse?, NSError?) -> Void)
}

public enum AgentPassChildGitXPCInterface {
    public static func make() -> NSXPCInterface {
        let interface = NSXPCInterface(with: AgentPassChildGitXPCProtocol.self)
        let attachSelector = #selector(AgentPassChildGitXPCProtocol.attachChildGit(_:withReply:))
        interface.setClasses(
            NSSet(array: [AgentPassChildGitAttachRequest.self]) as! Set<AnyHashable>,
            for: attachSelector,
            argumentIndex: 0,
            ofReply: false
        )
        interface.setClasses(
            NSSet(array: [AgentPassChildGitAttachResponse.self]) as! Set<AnyHashable>,
            for: attachSelector,
            argumentIndex: 0,
            ofReply: true
        )
        let selector = #selector(AgentPassChildGitXPCProtocol.signChildGitCommit(_:withReply:))
        interface.setClasses(
            NSSet(array: [AgentPassChildGitSignRequest.self]) as! Set<AnyHashable>,
            for: selector,
            argumentIndex: 0,
            ofReply: false
        )
        interface.setClasses(
            NSSet(array: [AgentPassChildGitSignResponse.self]) as! Set<AnyHashable>,
            for: selector,
            argumentIndex: 0,
            ofReply: true
        )
        return interface
    }
}
