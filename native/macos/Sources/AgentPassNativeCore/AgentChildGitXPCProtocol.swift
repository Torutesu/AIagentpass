import Foundation

/// Child-side signing channel used after the Host has registered the child
/// identity on its connection-owned session. The child connection itself is
/// the authority boundary; no session ID, capability, key selector, path, or
/// inherited descriptor is carried by these DTOs.
public enum AgentPassChildGitXPCContract {
    public static let protocolVersion = 1
    public static let maximumPayloadBytes = 1 * 1024 * 1024
    public static let maximumSignatureBytes = 4 * 1024
    public static let maximumRequests: UInt32 = 2

    public static func validSequence(_ value: UInt32) -> Bool {
        (1...maximumRequests).contains(value)
    }
}

@objc(AgentPassChildGitSignRequest)
public final class AgentPassChildGitSignRequest: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }

    public let protocolVersion: Int
    public let requestSequence: UInt32
    public let commitPayload: Data

    public init?(
        protocolVersion: Int = AgentPassChildGitXPCContract.protocolVersion,
        requestSequence: UInt32,
        commitPayload: Data
    ) {
        guard protocolVersion == AgentPassChildGitXPCContract.protocolVersion,
              AgentPassChildGitXPCContract.validSequence(requestSequence),
              !commitPayload.isEmpty,
              commitPayload.count <= AgentPassChildGitXPCContract.maximumPayloadBytes else {
            return nil
        }
        self.protocolVersion = protocolVersion
        self.requestSequence = requestSequence
        self.commitPayload = commitPayload
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard !Self.containsForbiddenKey(coder),
              let protocolVersion = coder.decodeObject(of: NSNumber.self, forKey: Keys.protocolVersion)?.intValue,
              let requestSequence = coder.decodeObject(of: NSNumber.self, forKey: Keys.requestSequence)?.uint32Value,
              let commitPayload = coder.decodeObject(of: NSData.self, forKey: Keys.commitPayload) as Data? else {
            return nil
        }
        self.init(protocolVersion: protocolVersion, requestSequence: requestSequence, commitPayload: commitPayload)
    }

    public func encode(with coder: NSCoder) {
        coder.encode(NSNumber(value: protocolVersion), forKey: Keys.protocolVersion)
        coder.encode(NSNumber(value: requestSequence), forKey: Keys.requestSequence)
        coder.encode(commitPayload as NSData, forKey: Keys.commitPayload)
    }

    private enum Keys {
        static let protocolVersion = "protocol_version"
        static let requestSequence = "request_sequence"
        static let commitPayload = "commit_payload"
    }

    private static let forbiddenKeys = [
        "session_id", "capability", "capability_id", "private_key", "private_key_data",
        "key", "key_id", "algorithm", "operation", "repository", "repository_path",
        "worktree_path", "token", "session_token", "scope", "authority", "lease",
        "argv", "environment", "env", "file", "path"
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

    public init?(
        protocolVersion: Int = AgentPassChildGitXPCContract.protocolVersion,
        responseSequence: UInt32,
        signature: Data
    ) {
        guard protocolVersion == AgentPassChildGitXPCContract.protocolVersion,
              AgentPassChildGitXPCContract.validSequence(responseSequence),
              !signature.isEmpty,
              signature.count <= AgentPassChildGitXPCContract.maximumSignatureBytes else {
            return nil
        }
        self.protocolVersion = protocolVersion
        self.responseSequence = responseSequence
        self.signature = signature
        super.init()
    }

    public required convenience init?(coder: NSCoder) {
        guard let protocolVersion = coder.decodeObject(of: NSNumber.self, forKey: Keys.protocolVersion)?.intValue,
              let responseSequence = coder.decodeObject(of: NSNumber.self, forKey: Keys.responseSequence)?.uint32Value,
              let signature = coder.decodeObject(of: NSData.self, forKey: Keys.signature) as Data? else {
            return nil
        }
        self.init(protocolVersion: protocolVersion, responseSequence: responseSequence, signature: signature)
    }

    public func encode(with coder: NSCoder) {
        coder.encode(NSNumber(value: protocolVersion), forKey: Keys.protocolVersion)
        coder.encode(NSNumber(value: responseSequence), forKey: Keys.responseSequence)
        coder.encode(signature as NSData, forKey: Keys.signature)
    }

    private enum Keys {
        static let protocolVersion = "protocol_version"
        static let responseSequence = "response_sequence"
        static let signature = "signature"
    }
}

@objc public protocol AgentPassChildGitXPCProtocol {
    func signChildGitCommit(_ request: AgentPassChildGitSignRequest, withReply reply: @escaping (AgentPassChildGitSignResponse?, NSError?) -> Void)
}

public enum AgentPassChildGitXPCInterface {
    public static func make() -> NSXPCInterface {
        let interface = NSXPCInterface(with: AgentPassChildGitXPCProtocol.self)
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
