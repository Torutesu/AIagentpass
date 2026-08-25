import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore

private let sessionAgentID = "11111111-1111-4111-8111-111111111111"

private func sessionPolicy(required: Bool = true, ttl: Int = 300) throws -> Data {
    try JSONSerialization.data(withJSONObject: [
        "agents": [["id": sessionAgentID]],
        "session": ["required": required, "ttl_seconds": ttl]
    ], options: [.sortedKeys])
}

private func multiAgentSessionPolicy() throws -> Data {
    try JSONSerialization.data(withJSONObject: [
        "agents": [["id": sessionAgentID], ["id": "22222222-2222-4222-8222-222222222222"]],
        "session": ["required": true, "ttl_seconds": 300]
    ], options: [.sortedKeys])
}

@Test func nativeSessionTargetedRevocationDoesNotAffectAnotherAgent() throws {
    let otherAgentID = "22222222-2222-4222-8222-222222222222"
    let approvalKey = P256.Signing.PrivateKey()
    let publicKey = try SSHSIG.authorizedKey(publicKeyX963: approvalKey.publicKey.x963Representation)
    let manager = try NativeSessionManager(policyData: multiAgentSessionPolicy(), approvalPublicKey: publicKey)
    let now: Int64 = 1_800_000_000_000
    func issue(_ agentID: String) throws -> NativeIssuedSession {
        let challenge = try manager.beginSession(agentID: agentID, requestedTTLSeconds: 300, nowMilliseconds: now)
        return try manager.completeSession(challengeData: challenge, signature: approvalKey.signature(for: challenge).rawRepresentation, nowMilliseconds: now + 1)
    }
    let target = try issue(sessionAgentID)
    let other = try issue(otherAgentID)
    let targetPending = try manager.beginSession(agentID: sessionAgentID, requestedTTLSeconds: 300, nowMilliseconds: now + 1)
    let otherPending = try manager.beginSession(agentID: otherAgentID, requestedTTLSeconds: 300, nowMilliseconds: now + 1)
    let revoked = try manager.revoke(agentID: sessionAgentID)
    #expect(revoked.revokedSessions == 1)
    #expect(throws: AgentPassNativeError.self) { try manager.validateSession(token: target.token, agentID: sessionAgentID, nowMilliseconds: now + 2) }
    try manager.validateSession(token: other.token, agentID: otherAgentID, nowMilliseconds: now + 2)
    #expect(throws: AgentPassNativeError.self) { try manager.completeSession(challengeData: targetPending, signature: approvalKey.signature(for: targetPending).rawRepresentation, nowMilliseconds: now + 2) }
    _ = try manager.completeSession(challengeData: otherPending, signature: approvalKey.signature(for: otherPending).rawRepresentation, nowMilliseconds: now + 2)
    #expect(throws: AgentPassNativeError.self) { _ = try manager.revoke(agentID: "unknown") }
}

@Test func nativeSessionRequiresSignedOneTimeApprovalAndBindsAgent() throws {
    let approvalKey = P256.Signing.PrivateKey()
    let publicKey = try SSHSIG.authorizedKey(publicKeyX963: approvalKey.publicKey.x963Representation)
    let manager = try NativeSessionManager(policyData: sessionPolicy(), approvalPublicKey: publicKey)
    let now: Int64 = 1_800_000_000_000
    let challenge = try manager.beginSession(agentID: sessionAgentID, requestedTTLSeconds: 999, nowMilliseconds: now)
    let signature = try approvalKey.signature(for: challenge).rawRepresentation
    let issued = try manager.completeSession(challengeData: challenge, signature: signature, nowMilliseconds: now + 1)
    #expect(issued.agentID == sessionAgentID)
    #expect(issued.token.count == 43)
    try manager.validateSession(token: issued.token, agentID: sessionAgentID, nowMilliseconds: now + 299_000)
    let revoked = manager.revokeAll()
    #expect(revoked.revokedSessions == 1)
    #expect(revoked.generation == 1)
    #expect(throws: AgentPassNativeError.self) { try manager.validateSession(token: issued.token, agentID: sessionAgentID, nowMilliseconds: now + 1) }
    #expect(throws: AgentPassNativeError.self) { try manager.validateSession(token: issued.token, agentID: "other", nowMilliseconds: now + 1) }
    #expect(throws: AgentPassNativeError.self) { try manager.validateSession(token: issued.token, agentID: sessionAgentID, nowMilliseconds: now + 301_000) }
    #expect(throws: AgentPassNativeError.self) { try manager.completeSession(challengeData: challenge, signature: signature, nowMilliseconds: now + 2) }

    let pending = try manager.beginSession(agentID: sessionAgentID, requestedTTLSeconds: 300, nowMilliseconds: now + 1)
    #expect(manager.revokeAll().generation == 2)
    let pendingSignature = try approvalKey.signature(for: pending).rawRepresentation
    #expect(throws: AgentPassNativeError.self) { try manager.completeSession(challengeData: pending, signature: pendingSignature, nowMilliseconds: now + 2) }
}

@Test func nativeSessionConsumesForgedAndMutatedChallenges() throws {
    let approvalKey = P256.Signing.PrivateKey()
    let publicKey = try SSHSIG.authorizedKey(publicKeyX963: approvalKey.publicKey.x963Representation)
    let manager = try NativeSessionManager(policyData: sessionPolicy(), approvalPublicKey: publicKey)
    let now: Int64 = 1_800_000_000_000

    let forgedChallenge = try manager.beginSession(agentID: sessionAgentID, requestedTTLSeconds: 300, nowMilliseconds: now)
    let wrongSignature = try P256.Signing.PrivateKey().signature(for: forgedChallenge).rawRepresentation
    #expect(throws: AgentPassNativeError.self) { try manager.completeSession(challengeData: forgedChallenge, signature: wrongSignature, nowMilliseconds: now + 1) }
    let correctSignature = try approvalKey.signature(for: forgedChallenge).rawRepresentation
    #expect(throws: AgentPassNativeError.self) { try manager.completeSession(challengeData: forgedChallenge, signature: correctSignature, nowMilliseconds: now + 2) }

    let mutableChallenge = try manager.beginSession(agentID: sessionAgentID, requestedTTLSeconds: 300, nowMilliseconds: now)
    var object = try #require(JSONSerialization.jsonObject(with: mutableChallenge) as? [String: Any])
    object["ttl_seconds"] = 60
    let mutated = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    let mutatedSignature = try approvalKey.signature(for: mutated).rawRepresentation
    #expect(throws: AgentPassNativeError.self) { try manager.completeSession(challengeData: mutated, signature: mutatedSignature, nowMilliseconds: now + 1) }
}

@Test func nativeSessionPolicyAndAuthorizedKeyFailClosed() throws {
    let approvalKey = P256.Signing.PrivateKey()
    let publicKey = try SSHSIG.authorizedKey(publicKeyX963: approvalKey.publicKey.x963Representation)
    let disabled = try NativeSessionManager(policyData: sessionPolicy(required: false), approvalPublicKey: publicKey)
    try disabled.validateSession(token: nil, agentID: sessionAgentID, nowMilliseconds: 0)
    #expect(throws: AgentPassNativeError.self) { try disabled.beginSession(agentID: sessionAgentID, requestedTTLSeconds: 300, nowMilliseconds: 0) }
    #expect(throws: (any Error).self) { try NativeSessionManager(policyData: sessionPolicy(ttl: 59), approvalPublicKey: publicKey) }
    #expect(throws: (any Error).self) { try NativeSessionManager(policyData: sessionPolicy(), approvalPublicKey: "ssh-ed25519 invalid") }
}

@Test func nativeSessionBoundsPendingApprovalRequests() throws {
    let approvalKey = P256.Signing.PrivateKey()
    let publicKey = try SSHSIG.authorizedKey(publicKeyX963: approvalKey.publicKey.x963Representation)
    let manager = try NativeSessionManager(policyData: sessionPolicy(), approvalPublicKey: publicKey)
    for offset in 0..<4 {
        _ = try manager.beginSession(agentID: sessionAgentID, requestedTTLSeconds: 300, nowMilliseconds: Int64(offset))
    }
    #expect(throws: AgentPassNativeError.self) { try manager.beginSession(agentID: sessionAgentID, requestedTTLSeconds: 300, nowMilliseconds: 4) }
    #expect(throws: AgentPassNativeError.self) { try manager.beginSession(agentID: "unknown", requestedTTLSeconds: 300, nowMilliseconds: 4) }
}
