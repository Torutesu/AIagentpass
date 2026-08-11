import CryptoKit
import Foundation
import Security

public protocol NativeSessionValidating: Sendable {
    func validateSession(token: String?, agentID: String, nowMilliseconds: Int64) throws
}

public struct NativeIssuedSession: Codable, Equatable, Sendable {
    public let token: String
    public let agentID: String
    public let expiresAt: String
    enum CodingKeys: String, CodingKey { case token; case agentID = "agent_id"; case expiresAt = "expires_at" }
}

public struct NativeSessionRevocation: Codable, Equatable, Sendable {
    public let revokedSessions: Int
    public let generation: Int
    enum CodingKeys: String, CodingKey { case generation; case revokedSessions = "revoked_sessions" }
}

public final class NativeSessionManager: NativeSessionValidating, @unchecked Sendable {
    private struct Policy: Decodable {
        struct Agent: Decodable { let id: String }
        struct Session: Decodable { let required: Bool; let ttlSeconds: Int; enum CodingKeys: String, CodingKey { case required; case ttlSeconds = "ttl_seconds" } }
        let agents: [Agent]
        let session: Session
    }
    private struct Challenge: Codable {
        let version: Int
        let action: String
        let challengeID: String
        let nonce: String
        let agentID: String
        let ttlSeconds: Int
        let issuedAtMilliseconds: Int64
        let expiresAtMilliseconds: Int64
        enum CodingKeys: String, CodingKey {
            case version, action, nonce
            case challengeID = "challenge_id"
            case agentID = "agent_id"
            case ttlSeconds = "ttl_seconds"
            case issuedAtMilliseconds = "issued_at_ms"
            case expiresAtMilliseconds = "expires_at_ms"
        }
    }
    private struct Pending { let digest: Data; let agentID: String; let expiresAtMilliseconds: Int64; let generation: Int }
    private struct Session { let agentID: String; let expiresAtMilliseconds: Int64 }

    private let required: Bool
    private let policyTTLSeconds: Int
    private let agentIDs: Set<String>
    private let approvalPublicKey: P256.Signing.PublicKey
    private var pending: [String: Pending] = [:]
    private var sessions: [String: Session] = [:]
    private var generation = 0
    private let lock = NSLock()

    public init(policyData: Data, approvalPublicKey: String) throws {
        let policy = try JSONDecoder().decode(Policy.self, from: policyData)
        guard (60...86_400).contains(policy.session.ttlSeconds), !policy.agents.isEmpty else {
            throw AgentPassNativeError.invalidConfiguration("Native session policy is invalid")
        }
        let ids = policy.agents.map(\.id)
        guard Set(ids).count == ids.count, ids.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 128 }) else {
            throw AgentPassNativeError.invalidConfiguration("Native session Agent IDs are invalid")
        }
        required = policy.session.required
        policyTTLSeconds = policy.session.ttlSeconds
        agentIDs = Set(ids)
        self.approvalPublicKey = try P256.Signing.PublicKey(x963Representation: SSHSIG.p256PublicKey(fromAuthorizedKey: approvalPublicKey))
    }

    public var sessionRequired: Bool { required }
    public var approvalKeyFingerprint: String { NativeAuditCheckpoints.fingerprint(approvalPublicKey.x963Representation) }

    public func beginSession(agentID: String, requestedTTLSeconds: Int, nowMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) throws -> Data {
        guard required else { throw AgentPassNativeError.invalidConfiguration("Native sessions are disabled by policy") }
        guard agentIDs.contains(agentID) else { throw AgentPassNativeError.unauthorizedClient("Cannot create a session for an unknown Agent") }
        guard requestedTTLSeconds >= 60 else { throw AgentPassNativeError.unauthorizedClient("Native session TTL must be at least 60 seconds") }
        let ttl = min(requestedTTLSeconds, policyTTLSeconds, 86_400)
        let challenge = Challenge(
            version: 1,
            action: "session.start",
            challengeID: UUID().uuidString.lowercased(),
            nonce: try randomBytes(count: 32).base64URLEncodedString(),
            agentID: agentID,
            ttlSeconds: ttl,
            issuedAtMilliseconds: nowMilliseconds,
            expiresAtMilliseconds: nowMilliseconds + 60_000
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(challenge)
        lock.lock()
        defer { lock.unlock() }
        purge(nowMilliseconds: nowMilliseconds)
        guard pending.count < 32, pending.values.filter({ $0.agentID == agentID }).count < 4 else {
            throw AgentPassNativeError.unauthorizedClient("Native session challenge capacity exceeded")
        }
        pending[challenge.challengeID] = Pending(digest: Data(SHA256.hash(data: data)), agentID: agentID, expiresAtMilliseconds: challenge.expiresAtMilliseconds, generation: generation)
        return data
    }

    public func completeSession(challengeData: Data, signature: Data, nowMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) throws -> NativeIssuedSession {
        guard challengeData.count > 0, challengeData.count <= 4096, signature.count == 64 else {
            throw AgentPassNativeError.unauthorizedClient("Native session approval is malformed")
        }
        let challenge = try JSONDecoder().decode(Challenge.self, from: challengeData)
        let digest = Data(SHA256.hash(data: challengeData))
        lock.lock()
        purge(nowMilliseconds: nowMilliseconds)
        let expected = pending.removeValue(forKey: challenge.challengeID)
        lock.unlock()
        guard let expected, expected.expiresAtMilliseconds >= nowMilliseconds,
              expected.digest.constantTimeEquals(digest), challenge.version == 1,
              challenge.action == "session.start", challenge.expiresAtMilliseconds >= nowMilliseconds,
              challenge.issuedAtMilliseconds <= nowMilliseconds + 5_000,
              agentIDs.contains(challenge.agentID), (60...policyTTLSeconds).contains(challenge.ttlSeconds) else {
            throw AgentPassNativeError.unauthorizedClient("Native session challenge is invalid, expired, or already used")
        }
        let ecdsa = try P256.Signing.ECDSASignature(rawRepresentation: signature)
        guard approvalPublicKey.isValidSignature(ecdsa, for: challengeData) else {
            throw AgentPassNativeError.unauthorizedClient("Native session approval signature is invalid")
        }
        let token = try randomBytes(count: 32).base64URLEncodedString()
        let tokenHash = NativeAuditLog.hash(Data(token.utf8))
        let expires = nowMilliseconds + Int64(challenge.ttlSeconds) * 1000
        lock.lock()
        defer { lock.unlock() }
        purge(nowMilliseconds: nowMilliseconds)
        guard expected.generation == generation else {
            throw AgentPassNativeError.unauthorizedClient("Native session approval was invalidated by revocation")
        }
        guard sessions.count < 1024 else { throw AgentPassNativeError.unauthorizedClient("Native session capacity exceeded") }
        sessions[tokenHash] = Session(agentID: challenge.agentID, expiresAtMilliseconds: expires)
        return NativeIssuedSession(token: token, agentID: challenge.agentID, expiresAt: sessionTimestamp(milliseconds: expires))
    }

    public func validateSession(token: String?, agentID: String, nowMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) throws {
        guard required else { return }
        guard let token, token.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil else {
            throw AgentPassNativeError.unauthorizedClient("Native session is required")
        }
        let tokenHash = NativeAuditLog.hash(Data(token.utf8))
        lock.lock()
        defer { lock.unlock() }
        purge(nowMilliseconds: nowMilliseconds)
        guard let session = sessions[tokenHash], session.agentID == agentID, session.expiresAtMilliseconds > nowMilliseconds else {
            throw AgentPassNativeError.unauthorizedClient("Native session is invalid, expired, or bound to another Agent")
        }
    }

    public func status(nowMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) -> (required: Bool, active: Int, generation: Int) {
        lock.lock()
        defer { lock.unlock() }
        purge(nowMilliseconds: nowMilliseconds)
        return (required, sessions.count, generation)
    }

    public func revokeAll() -> NativeSessionRevocation {
        lock.lock()
        defer { lock.unlock() }
        let count = sessions.count
        sessions.removeAll(keepingCapacity: false)
        pending.removeAll(keepingCapacity: false)
        generation += 1
        return NativeSessionRevocation(revokedSessions: count, generation: generation)
    }

    public func discardSession(token: String) {
        let tokenHash = NativeAuditLog.hash(Data(token.utf8))
        lock.lock()
        sessions.removeValue(forKey: tokenHash)
        lock.unlock()
    }

    private func purge(nowMilliseconds: Int64) {
        pending = pending.filter { $0.value.expiresAtMilliseconds >= nowMilliseconds }
        sessions = sessions.filter { $0.value.expiresAtMilliseconds > nowMilliseconds }
    }
}

private func randomBytes(count: Int) throws -> Data {
    var data = Data(repeating: 0, count: count)
    let status = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
    guard status == errSecSuccess else { throw AgentPassNativeError.keychain("Secure random generation", status) }
    return data
}

private func sessionTimestamp(milliseconds: Int64) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: Date(timeIntervalSince1970: Double(milliseconds) / 1000))
}

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    func constantTimeEquals(_ other: Data) -> Bool {
        guard count == other.count else { return false }
        return zip(self, other).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }
}
