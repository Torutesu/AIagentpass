import Foundation

/// Child-side signing channel used after the Host has registered the child
/// identity on its connection-owned session. The child connection itself is
/// the authority boundary; no session ID, capability, key selector, path, or
/// inherited descriptor is carried by these DTOs.
public enum AgentPassChildGitXPCContract {
    public static let protocolVersion = 2
    public static let maximumPayloadBytes = 1 * 1024 * 1024
    public static let maximumSignatureBytes = 4 * 1024
    public static let attachTicketBytes = 32
    public static let maximumAttachTicketLifetimeMilliseconds: Int64 = 5 * 60 * 1_000
    public static let maximumRequests: UInt32 = UInt32(NativeAgentSignatureBudget.maximumSignatures)

    public static func validSequence(_ value: UInt32) -> Bool {
        (1...maximumRequests).contains(value)
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

    public init?(
        protocolVersion: Int = AgentPassChildGitXPCContract.protocolVersion,
        attachTicket: Data,
        expiresAtMilliseconds: Int64
    ) {
        guard protocolVersion == AgentPassChildGitXPCContract.protocolVersion,
              attachTicket.count == AgentPassChildGitXPCContract.attachTicketBytes,
              attachTicket.contains(where: { $0 != 0 }),
              AgentPassHostXPCContract.isTimestamp(expiresAtMilliseconds) else {
            return nil
        }
        self.protocolVersion = protocolVersion
        self.attachTicket = attachTicket
        self.expiresAtMilliseconds = expiresAtMilliseconds
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard !Self.containsForbiddenKey(coder),
              coder.containsValue(forKey: Keys.protocolVersion),
              coder.containsValue(forKey: Keys.attachTicket),
              coder.containsValue(forKey: Keys.expiresAtMilliseconds),
              let protocolVersion = coder.decodeObject(of: NSNumber.self, forKey: Keys.protocolVersion)?.intValue,
              let attachTicket = coder.decodeObject(of: NSData.self, forKey: Keys.attachTicket) as Data?,
              let expiresAtMilliseconds = coder.decodeObject(of: NSNumber.self, forKey: Keys.expiresAtMilliseconds)?.int64Value else {
            return nil
        }
        self.init(
            protocolVersion: protocolVersion,
            attachTicket: attachTicket,
            expiresAtMilliseconds: expiresAtMilliseconds
        )
    }

    public func encode(with coder: NSCoder) {
        coder.encode(NSNumber(value: protocolVersion), forKey: Keys.protocolVersion)
        coder.encode(attachTicket as NSData, forKey: Keys.attachTicket)
        coder.encode(NSNumber(value: expiresAtMilliseconds), forKey: Keys.expiresAtMilliseconds)
    }

    private enum Keys {
        static let protocolVersion = "protocol_version"
        static let attachTicket = "attach_ticket"
        static let expiresAtMilliseconds = "expires_at_ms"
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

    public init?(
        protocolVersion: Int = AgentPassChildGitXPCContract.protocolVersion,
        requestSequence: UInt32,
        commitPayload: Data,
        attachTicket: Data
    ) {
        guard protocolVersion == AgentPassChildGitXPCContract.protocolVersion,
              AgentPassChildGitXPCContract.validSequence(requestSequence),
              !commitPayload.isEmpty,
              commitPayload.count <= AgentPassChildGitXPCContract.maximumPayloadBytes,
              attachTicket.count == AgentPassChildGitXPCContract.attachTicketBytes,
              attachTicket.contains(where: { $0 != 0 }) else {
            return nil
        }
        self.protocolVersion = protocolVersion
        self.requestSequence = requestSequence
        self.commitPayload = commitPayload
        self.attachTicket = attachTicket
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard !Self.containsForbiddenKey(coder),
              let protocolVersion = coder.decodeObject(of: NSNumber.self, forKey: Keys.protocolVersion)?.intValue,
              let requestSequence = coder.decodeObject(of: NSNumber.self, forKey: Keys.requestSequence)?.uint32Value,
              let commitPayload = coder.decodeObject(of: NSData.self, forKey: Keys.commitPayload) as Data?,
              let attachTicket = coder.decodeObject(of: NSData.self, forKey: Keys.attachTicket) as Data? else {
            return nil
        }
        self.init(
            protocolVersion: protocolVersion,
            requestSequence: requestSequence,
            commitPayload: commitPayload,
            attachTicket: attachTicket
        )
    }

    public func encode(with coder: NSCoder) {
        coder.encode(NSNumber(value: protocolVersion), forKey: Keys.protocolVersion)
        coder.encode(NSNumber(value: requestSequence), forKey: Keys.requestSequence)
        coder.encode(commitPayload as NSData, forKey: Keys.commitPayload)
        coder.encode(attachTicket as NSData, forKey: Keys.attachTicket)
    }

    private enum Keys {
        static let protocolVersion = "protocol_version"
        static let requestSequence = "request_sequence"
        static let commitPayload = "commit_payload"
        static let attachTicket = "attach_ticket"
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

    public init?(
        protocolVersion: Int = AgentPassChildGitXPCContract.protocolVersion,
        responseSequence: UInt32,
        signature: Data,
        maxSignatures: Int,
        usedSignatures: Int,
        remainingSignatures: Int
    ) {
        guard protocolVersion == AgentPassChildGitXPCContract.protocolVersion,
              AgentPassChildGitXPCContract.validSequence(responseSequence),
              !signature.isEmpty,
              signature.count <= AgentPassChildGitXPCContract.maximumSignatureBytes,
              (NativeAgentSignatureBudget.minimumSignatures...NativeAgentSignatureBudget.maximumSignatures).contains(maxSignatures),
              (0...maxSignatures).contains(usedSignatures),
              remainingSignatures == maxSignatures - usedSignatures else {
            return nil
        }
        self.protocolVersion = protocolVersion
        self.responseSequence = responseSequence
        self.signature = signature
        self.maxSignatures = maxSignatures
        self.usedSignatures = usedSignatures
        self.remainingSignatures = remainingSignatures
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard let protocolVersion = coder.decodeObject(of: NSNumber.self, forKey: Keys.protocolVersion)?.intValue,
              let responseSequence = coder.decodeObject(of: NSNumber.self, forKey: Keys.responseSequence)?.uint32Value,
              let signature = coder.decodeObject(of: NSData.self, forKey: Keys.signature) as Data?,
              let maxSignatures = coder.decodeObject(of: NSNumber.self, forKey: Keys.maxSignatures)?.intValue,
              let usedSignatures = coder.decodeObject(of: NSNumber.self, forKey: Keys.usedSignatures)?.intValue,
              let remainingSignatures = coder.decodeObject(of: NSNumber.self, forKey: Keys.remainingSignatures)?.intValue else {
            return nil
        }
        self.init(protocolVersion: protocolVersion, responseSequence: responseSequence, signature: signature, maxSignatures: maxSignatures, usedSignatures: usedSignatures, remainingSignatures: remainingSignatures)
    }

    public func encode(with coder: NSCoder) {
        coder.encode(NSNumber(value: protocolVersion), forKey: Keys.protocolVersion)
        coder.encode(NSNumber(value: responseSequence), forKey: Keys.responseSequence)
        coder.encode(signature as NSData, forKey: Keys.signature)
        coder.encode(NSNumber(value: maxSignatures), forKey: Keys.maxSignatures)
        coder.encode(NSNumber(value: usedSignatures), forKey: Keys.usedSignatures)
        coder.encode(NSNumber(value: remainingSignatures), forKey: Keys.remainingSignatures)
    }

    private enum Keys {
        static let protocolVersion = "protocol_version"
        static let responseSequence = "response_sequence"
        static let signature = "signature"
        static let maxSignatures = "max_signatures"
        static let usedSignatures = "used_signatures"
        static let remainingSignatures = "remaining_signatures"
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
