import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore

private let authenticatedSessionID = "11111111-1111-4111-8111-111111111111"

private func authenticatedObservation(
    pid: Int32 = 42,
    uid: UInt32 = 501,
    pidVersion: UInt64 = 9,
    codeHash: String = String(repeating: "a", count: 64),
    teamID: String? = "ABCDE12345"
) throws -> NativeProcessObservation {
    let facts = try NativeObservedProcessFacts(
        uid: uid,
        pid: pid,
        pidVersion: pidVersion,
        bootIdentity: "boot-1",
        executableFileIdentity: NativeExecutableFileIdentity(
            deviceID: 1,
            inode: 2,
            fileSize: 3,
            modificationTimeNanoseconds: 4
        ),
        codeDirectoryHash: codeHash,
        bundleIdentifier: "dev.agentpass.agent-host",
        teamIdentifier: teamID,
        signatureKind: .developerID,
        entitlements: [NativeAgentCodeRequirement.clientEntitlement: .boolean(true)]
    )
    return try NativeProcessObservation(process: facts, ancestry: [])
}

private func authenticatedPeer(
    observation: NativeProcessObservation? = nil,
    processPolicy: NativeProcessIdentityPolicy? = nil
) throws -> NativeAgentAuthenticatedGitBridgePeerBinding {
    let observation = try observation ?? authenticatedObservation()
    let context = try NativeConnectionContext(
        osProcessID: observation.process.pid,
        effectiveUserID: observation.process.uid,
        auditSessionID: 7,
        pidVersion: observation.process.pidVersion
    )
    let policy = try processPolicy ?? NativeProcessIdentityPolicy(
        expectedCodeDirectoryHash: observation.process.codeDirectoryHash,
        expectedBundleIdentifier: observation.process.bundleIdentifier,
        expectedTeamIdentifier: observation.process.teamIdentifier,
        expectedSignatureKind: observation.process.signatureKind,
        requiredEntitlements: observation.process.entitlements
    )
    return try NativeAgentAuthenticatedGitBridgePeerBinding(
        connectionContext: context,
        observation: observation,
        processPolicy: policy
    )
}

private func authenticatedSession(
    peer: NativeAgentAuthenticatedGitBridgePeerBinding,
    authenticator: NativeAgentAuthenticatedGitBridgeRequestAuthenticator? = nil,
    maxSignatures: Int = 2,
    usedSignatures: Int = 0
) throws -> NativeAgentAuthenticatedGitBridgeSession {
    let childPolicy = try NativeProcessIdentityPolicy.exact(peer.processIdentity)
    return try NativeAgentAuthenticatedGitBridgeSession(
        sessionID: authenticatedSessionID,
        peer: peer,
        childPolicy: childPolicy,
        signatureBudget: NativeAgentSignatureBudgetLedger(
            try NativeAgentSignatureBudget(maxSignatures: maxSignatures, usedSignatures: usedSignatures)
        ),
        authenticator: authenticator ?? NativeAgentAuthenticatedGitBridgeRequestAuthenticator(keyData: Data(repeating: 0x5a, count: 32))!
    )
}

@Test func authenticatedPeerRequiresUIDPIDGenerationAndCodeIdentityTogether() throws {
    let observation = try authenticatedObservation()
    let peer = try authenticatedPeer(observation: observation)
    #expect(peer.effectiveUserID == 501)
    #expect(peer.auditTokenIdentity.count == 64)
    #expect(peer.processBindingHash.count == 64)

    let unchangedContext = peer.connectionContext
    try peer.revalidate(connectionContext: unchangedContext, observation: observation)

    let changedCode = try authenticatedObservation(codeHash: String(repeating: "b", count: 64))
    #expect(throws: NativeAgentAuthenticatedGitBridgeError.processIdentityChanged) {
        try peer.revalidate(connectionContext: unchangedContext, observation: changedCode)
    }

    let changedContext = try NativeConnectionContext(
        osProcessID: 42,
        effectiveUserID: 501,
        auditSessionID: 8,
        pidVersion: 9
    )
    #expect(throws: NativeAgentAuthenticatedGitBridgeError.peerIdentityMismatch) {
        try peer.revalidate(connectionContext: changedContext, observation: observation)
    }
}

@Test func authenticatedPeerRejectsCodeIdentityPolicyMismatchAtConstruction() throws {
    let observation = try authenticatedObservation()
    let policy = try NativeProcessIdentityPolicy(expectedTeamIdentifier: "FOREIGNTEAM")
    #expect(throws: NativeAgentAuthenticatedGitBridgeError.codeIdentityDenied) {
        _ = try authenticatedPeer(observation: observation, processPolicy: policy)
    }
}

@Test func authenticatedSessionUsesClosedStateMachineAndMonotonicRequestSequence() throws {
    let observation = try authenticatedObservation()
    let peer = try authenticatedPeer(observation: observation)
    let session = try authenticatedSession(peer: peer)
    #expect(session.snapshot.phase == .new)
    #expect(try session.prepare(launchNonce: Data(repeating: 1, count: 16)).phase == .prepared)
    #expect(try session.attach(childIdentity: peer.processIdentity).phase == .attached)

    let payload = Data("commit-payload".utf8)
    let request = try #require(session.makeRequest(requestSequence: 1, payload: payload))
    let authorized = try session.authorizeAndConsume(
        request,
        reobservedConnectionContext: peer.connectionContext,
        reobservedObservation: observation
    )
    #expect(authorized.payload == payload)
    #expect(authorized.payloadDigest == Data(SHA256.hash(data: payload)))
    #expect(session.snapshot.requestCount == 1)

    let replayError = #expect(throws: NativeAgentAuthenticatedGitBridgeError.self) {
        _ = try session.authorizeAndConsume(
            request,
            reobservedConnectionContext: peer.connectionContext,
            reobservedObservation: observation
        )
    }
    #expect(replayError == .requestReplay || replayError == .requestSequenceMismatch || replayError == .sessionClosed)
    #expect(session.snapshot.phase == .closed)
}

@Test func authenticatedSessionClosesOnPeerDriftBeforeKeyUse() throws {
    let observation = try authenticatedObservation()
    let peer = try authenticatedPeer(observation: observation)
    let session = try authenticatedSession(peer: peer)
    _ = try session.prepare(launchNonce: Data(repeating: 2, count: 16))
    _ = try session.attach(childIdentity: peer.processIdentity)
    let request = try #require(session.makeRequest(requestSequence: 1, payload: Data([1, 2, 3])))

    let driftedContext = try NativeConnectionContext(
        osProcessID: observation.process.pid,
        effectiveUserID: observation.process.uid,
        auditSessionID: 99,
        pidVersion: observation.process.pidVersion
    )
    #expect(throws: NativeAgentAuthenticatedGitBridgeError.peerIdentityMismatch) {
        _ = try session.authorizeAndConsume(
            request,
            reobservedConnectionContext: driftedContext,
            reobservedObservation: observation
        )
    }
    #expect(session.snapshot.phase == .closed)
}

@Test func authenticatedRequestProofBindsPeerAndPayloadAndNeverEncodesAKey() throws {
    let observation = try authenticatedObservation()
    let peer = try authenticatedPeer(observation: observation)
    let authenticator = try #require(NativeAgentAuthenticatedGitBridgeRequestAuthenticator(keyData: Data(repeating: 0x11, count: 32)))
    let request = try #require(authenticator.makeRequest(
        sessionID: authenticatedSessionID,
        requestSequence: 1,
        payload: Data([9, 8, 7]),
        peer: peer
    ))
    #expect(request.proof.count == 32)
    #expect(request.payloadDigest == Data(SHA256.hash(data: request.payload)))

    let archived = try NSKeyedArchiver.archivedData(withRootObject: request, requiringSecureCoding: true)
    let decoded = try NSKeyedUnarchiver.unarchivedObject(
        ofClass: NativeAgentAuthenticatedGitBridgeSignRequest.self,
        from: archived
    )
    #expect(decoded?.sessionID == request.sessionID)
    #expect(decoded?.payload == request.payload)
    #expect(String(decoding: archived, as: UTF8.self).contains("private_key") == false)
}

@Test func authenticatedSessionRejectsTamperingAndSequenceSkipBeforeConsumption() throws {
    let observation = try authenticatedObservation()
    let peer = try authenticatedPeer(observation: observation)
    let session = try authenticatedSession(peer: peer)
    _ = try session.prepare(launchNonce: Data(repeating: 3, count: 16))
    _ = try session.attach(childIdentity: peer.processIdentity)

    let skipped = try #require(session.makeRequest(requestSequence: 2, payload: Data([1])))
    #expect(throws: NativeAgentAuthenticatedGitBridgeError.requestSequenceMismatch) {
        _ = try session.authorizeAndConsume(
            skipped,
            reobservedConnectionContext: peer.connectionContext,
            reobservedObservation: observation
        )
    }
    #expect(session.snapshot.phase == .closed)

    let freshSession = try authenticatedSession(peer: peer)
    _ = try freshSession.prepare(launchNonce: Data(repeating: 4, count: 16))
    _ = try freshSession.attach(childIdentity: peer.processIdentity)
    let original = try #require(freshSession.makeRequest(requestSequence: 1, payload: Data([4, 5])))
    let tampered = try #require(NativeAgentAuthenticatedGitBridgeSignRequest(
        sessionID: original.sessionID,
        requestSequence: original.requestSequence,
        payload: Data([4, 6]),
        proof: original.proof
    ))
    #expect(throws: NativeAgentAuthenticatedGitBridgeError.requestAuthenticationFailed) {
        _ = try freshSession.authorizeAndConsume(
            tampered,
            reobservedConnectionContext: peer.connectionContext,
            reobservedObservation: observation
        )
    }
    #expect(freshSession.snapshot.phase == .closed)
}

@Test func authenticatedDTORejectsAuthorityAndSecretFieldsDuringSecureDecode() throws {
    let coder = TestForbiddenKeyCoder()
    #expect(NativeAgentAuthenticatedGitBridgeSignRequest(coder: coder) == nil)
}

@Test func authenticatedSessionUsesCloudUsedCountAndStopsAtCloudMax() throws {
    let observation = try authenticatedObservation()
    let peer = try authenticatedPeer(observation: observation)
    let session = try authenticatedSession(peer: peer, maxSignatures: 5, usedSignatures: 4)
    _ = try session.prepare(launchNonce: Data(repeating: 5, count: 16))
    _ = try session.attach(childIdentity: peer.processIdentity)

    let request = try #require(session.makeRequest(requestSequence: 1, payload: Data([5])))
    _ = try session.authorizeAndConsume(
        request,
        reobservedConnectionContext: peer.connectionContext,
        reobservedObservation: observation
    )
    #expect(session.snapshot.maxSignatures == 5)
    #expect(session.snapshot.usedSignatures == 5)
    #expect(session.snapshot.remainingSignatures == 0)
    #expect(session.makeRequest(requestSequence: 2, payload: Data([6])) == nil)
    #expect(session.snapshot.phase == .attached)
}

private final class TestForbiddenKeyCoder: NSCoder {
    override func containsValue(forKey key: String) -> Bool {
        key == "private_key"
    }
}
