import Foundation

public enum NativeAgentLaunchAuthorityHandoffError: Error, Equatable, Sendable {
    case malformed
    case invalidFields
    case oversized

    public var stableCode: String {
        switch self {
        case .malformed: return "malformed"
        case .invalidFields: return "invalid_fields"
        case .oversized: return "oversized"
        }
    }
}

/// Canonical one-use authority delivered to the signed Agent Host over an
/// inherited private descriptor. The public launch command cannot construct or
/// select any field in this document. In particular, the proof never enters
/// argv, the environment, a URL, Git configuration, or Host durable state.
public struct NativeAgentLaunchAuthorityHandoff: Equatable, Sendable {
    public static let schemaVersion = 1
    public static let maximumDocumentBytes = 16 * 1024
    public static let maximumProofBytes = AgentPassAgentSessionRequest.maximumProofBytes
    public static let expectedKeys: Set<String> = [
        "schema_version", "agent_id", "agent_kind", "requested_ttl_seconds", "proof"
    ]

    public let agentID: String
    public let agentKind: AgentPassAgentAdapterKind
    public let requestedTTLSeconds: Int
    public let proof: Data

    public init(
        agentID: String,
        agentKind: AgentPassAgentAdapterKind,
        requestedTTLSeconds: Int,
        proof: Data
    ) throws {
        guard let identifier = UUID(uuidString: agentID)?.uuidString.lowercased(),
              identifier == agentID,
              agentKind == .claudeCode || agentKind == .cursor,
              (AgentPassAgentBootstrapRequest.minimumSessionTTLSeconds...AgentPassAgentBootstrapRequest.maximumSessionTTLSeconds)
                .contains(requestedTTLSeconds),
              try Self.isCanonicalProof(proof) else {
            throw NativeAgentLaunchAuthorityHandoffError.invalidFields
        }
        self.agentID = identifier
        self.agentKind = agentKind
        self.requestedTTLSeconds = requestedTTLSeconds
        self.proof = proof
    }

    public static func decode(_ data: Data) throws -> Self {
        guard !data.isEmpty, data.count <= maximumDocumentBytes else {
            throw NativeAgentLaunchAuthorityHandoffError.oversized
        }
        let object: [String: Any]
        do {
            object = try NativeStrictJSON.object(from: data, maxBytes: maximumDocumentBytes, maxDepth: 32)
        } catch {
            throw NativeAgentLaunchAuthorityHandoffError.malformed
        }
        guard Set(object.keys) == expectedKeys,
              object["schema_version"] as? Int == schemaVersion,
              let agentID = object["agent_id"] as? String,
              let kindValue = object["agent_kind"] as? String,
              let agentKind = AgentPassAgentAdapterKind(rawValue: kindValue),
              let requestedTTLSeconds = object["requested_ttl_seconds"] as? Int,
              let proofString = object["proof"] as? String else {
            throw NativeAgentLaunchAuthorityHandoffError.invalidFields
        }
        do {
            guard try NativeStrictJSON.data(object) == data else {
                throw NativeAgentLaunchAuthorityHandoffError.malformed
            }
            return try Self(
                agentID: agentID,
                agentKind: agentKind,
                requestedTTLSeconds: requestedTTLSeconds,
                proof: Data(proofString.utf8)
            )
        } catch let error as NativeAgentLaunchAuthorityHandoffError {
            throw error
        } catch {
            throw NativeAgentLaunchAuthorityHandoffError.malformed
        }
    }

    private static func isCanonicalProof(_ proof: Data) throws -> Bool {
        guard (AgentPassAgentSessionRequest.minimumProofBytes...maximumProofBytes).contains(proof.count) else {
            return false
        }
        do {
            let object = try NativeStrictJSON.object(from: proof, maxBytes: maximumProofBytes, maxDepth: 32)
            return try NativeStrictJSON.data(object) == proof
        } catch {
            return false
        }
    }
}
