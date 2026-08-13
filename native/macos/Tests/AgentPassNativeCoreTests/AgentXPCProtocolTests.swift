import AgentPassNativeCore
import Foundation
import ObjectiveC.runtime
import Testing

private let fixedUUID = "11111111-1111-4111-8111-111111111111"
private let fixedUUID2 = "22222222-2222-4222-8222-222222222222"
private let fixedUUID3 = "33333333-3333-4333-8333-333333333333"
private let digest = Data(repeating: 0xA5, count: 32)
private let nonce = Data(repeating: 0x5A, count: 32)

private func archive(_ object: NSSecureCoding) throws -> Data {
    try NSKeyedArchiver.archivedData(withRootObject: object, requiringSecureCoding: true)
}

private func unarchive<T: NSObject & NSSecureCoding>(_ type: T.Type, from data: Data) throws -> T {
    let object = try NSKeyedUnarchiver.unarchivedObject(ofClass: type, from: data)
    return try #require(object)
}

private func protocolSelectors(_ proto: Protocol) -> Set<String> {
    var count: UInt32 = 0
    guard let descriptions = protocol_copyMethodDescriptionList(proto, true, true, &count) else { return [] }
    defer { free(descriptions) }
    return Set((0..<Int(count)).compactMap { index in
        guard let selector = descriptions[index].name else { return nil }
        return NSStringFromSelector(selector)
    })
}

@Test func agentProtocolIsDedicatedAndContainsOnlyAgentOperations() {
    let selectors = protocolSelectors(AgentPassAgentXPCProtocol.self)
    #expect(selectors == [
        "bootstrapAgent:withReply:",
        "startAgentSession:withReply:",
        "agentSessionStatus:withReply:",
        "signGitCommit:withReply:",
        "closeAgentSession:withReply:"
    ])
}

@Test func agentProtocolHasNoManagementSelectors() {
    let agentSelectors = protocolSelectors(AgentPassAgentXPCProtocol.self)
    let forbiddenNames = [
        "health", "publicKey", "auditStatus", "auditPublicKey", "createAuditCheckpoint",
        "rotateAudit", "rotateAuditEvidence", "keyLifecycleStatus", "stageKey",
        "approvalKeyStagePlan", "stageApprovalKey", "beginKeyActivation", "completeKeyActivation",
        "completeApprovalKeyActivation", "beginKeyAbort", "completeKeyAbort", "beginKeyDeletion",
        "completeKeyDeletion", "beginRecovery", "prepareRecoveryInstallation", "completeRecovery",
        "prepareAuditRecoveryInstallation", "completeAuditRecovery", "abortExpiredAuditRecovery",
        "auditRecoveryStatus", "auditAnchorStatus", "pushAuditAnchor", "prepareAuditPrune",
        "submitAuditPrune", "executeAuditPrune", "auditPruneStatus", "beginSession", "completeSession", "revokeSessions",
        "validateSession", "applyControlBundle", "controlStatus", "refreshControl", "validateControl"
    ]
    let forbiddenAgentSelectors = agentSelectors.filter { selector in
        forbiddenNames.contains { selector.hasPrefix($0) }
    }
    #expect(forbiddenAgentSelectors.isEmpty)
}

@Test func agentXPCInterfaceRegistersOnlyTheContractDTOs() throws {
    let interface = AgentPassAgentXPCInterface.make()
    let bootstrapSelector = #selector(AgentPassAgentXPCProtocol.bootstrapAgent(_:withReply:))
    let signSelector = #selector(AgentPassAgentXPCProtocol.signGitCommit(_:withReply:))
    let requestClasses = interface.classes(for: bootstrapSelector, argumentIndex: 0, ofReply: false)
    let responseClasses = interface.classes(for: bootstrapSelector, argumentIndex: 0, ofReply: true)
    let signRequestClasses = interface.classes(for: signSelector, argumentIndex: 0, ofReply: false)
    #expect(requestClasses.contains { String(describing: $0).contains("AgentPassAgentBootstrapRequest") })
    #expect(responseClasses.contains { String(describing: $0).contains("AgentPassAgentBootstrapResponse") })
    #expect(signRequestClasses.contains { String(describing: $0).contains("AgentPassAgentSignRequest") })
    #expect(requestClasses.contains { String(describing: $0).contains("AgentPassNativeServiceProtocol") } == false)
    #expect(protocolSelectors(AgentPassAgentXPCProtocol.self).intersection(protocolSelectors(AgentPassNativeServiceProtocol.self)).isEmpty)
}

@Test func bootstrapRequestRoundTripsAsSecureCodedClosedDTO() throws {
    let request = try #require(AgentPassAgentBootstrapRequest(
        agentID: fixedUUID,
        adapterKind: AgentPassAgentAdapterKind.claudeCode.rawValue,
        requestedTTLSeconds: 3_600,
        bootstrapNonce: nonce
    ))
    let decoded = try unarchive(AgentPassAgentBootstrapRequest.self, from: try archive(request))
    #expect(decoded.protocolVersion == 1)
    #expect(decoded.agentID == fixedUUID)
    #expect(decoded.adapterKind == "claude_code")
    #expect(decoded.requestedTTLSeconds == 3_600)
    #expect(decoded.bootstrapNonce == nonce)
}

@Test func agentDTOsRoundTripWithoutBearerOrPrivateMaterial() throws {
    let bootstrap = try #require(AgentPassAgentBootstrapResponse(bootstrapID: fixedUUID, challenge: nonce, expiresAtMilliseconds: 4_000_000_000_000))
    let sessionRequest = try #require(AgentPassAgentSessionRequest(bootstrapID: fixedUUID, proof: nonce))
    let session = try #require(AgentPassAgentSessionResponse(
        sessionID: fixedUUID,
        leaseID: fixedUUID2,
        processBindingDigest: digest,
        worktreeBindingDigest: digest,
        expiresAtMilliseconds: 4_000_000_000_000,
        maxSignatures: 2
    ))
    let statusRequest = try #require(AgentPassAgentSessionStatusRequest(sessionID: fixedUUID))
    let status = try #require(AgentPassAgentSessionStatusResponse(
        sessionID: fixedUUID,
        status: "active",
        expiresAtMilliseconds: 4_000_000_000_000,
        maxSignatures: 2,
        usedSignatures: 1
    ))
    let signRequest = try #require(AgentPassAgentSignRequest(
        sessionID: fixedUUID,
        requestID: fixedUUID2,
        capabilityID: fixedUUID3,
        commitPayload: Data("tree abc\nauthor AgentPass\n\nmessage\n".utf8),
        requestNonce: nonce,
        createdAtMilliseconds: 4_000_000_000_000
    ))
    let signResponse = try #require(AgentPassAgentSignResponse(requestID: fixedUUID2, signature: Data(repeating: 0x01, count: 64), remainingSignatures: 1))
    let closeRequest = try #require(AgentPassAgentCloseSessionRequest(sessionID: fixedUUID, reason: "completed"))
    let closeResponse = try #require(AgentPassAgentCloseSessionResponse(sessionID: fixedUUID, closedAtMilliseconds: 4_000_000_000_000))

    let decodedBootstrap = try unarchive(AgentPassAgentBootstrapResponse.self, from: try archive(bootstrap))
    let decodedSessionRequest = try unarchive(AgentPassAgentSessionRequest.self, from: try archive(sessionRequest))
    let decodedSession = try unarchive(AgentPassAgentSessionResponse.self, from: try archive(session))
    let decodedStatusRequest = try unarchive(AgentPassAgentSessionStatusRequest.self, from: try archive(statusRequest))
    let decodedStatus = try unarchive(AgentPassAgentSessionStatusResponse.self, from: try archive(status))
    let decodedSignRequest = try unarchive(AgentPassAgentSignRequest.self, from: try archive(signRequest))
    let decodedSignResponse = try unarchive(AgentPassAgentSignResponse.self, from: try archive(signResponse))
    let decodedCloseRequest = try unarchive(AgentPassAgentCloseSessionRequest.self, from: try archive(closeRequest))
    let decodedCloseResponse = try unarchive(AgentPassAgentCloseSessionResponse.self, from: try archive(closeResponse))

    #expect(decodedBootstrap.challenge == nonce)
    #expect(decodedSessionRequest.proof == nonce)
    #expect(decodedSession.processBindingDigest == digest)
    #expect(decodedStatusRequest.sessionID == fixedUUID)
    #expect(decodedStatus.usedSignatures == 1)
    #expect(decodedSignRequest.commitPayload.starts(with: Data("tree".utf8)))
    #expect(decodedSignResponse.signature.count == 64)
    #expect(decodedCloseRequest.reason == "completed")
    #expect(decodedCloseResponse.status == "closed")

    let publicPropertyNames = [
        "token", "sessionToken", "capability", "privateKey", "privateKeyData", "operation", "namespace", "signerArguments"
    ]
    for name in publicPropertyNames {
        #expect(String(describing: type(of: decodedSignRequest)).contains(name) == false)
    }
}

@Test func agentDTOConstructorsRejectUnboundedOrOpenValues() {
    #expect(AgentPassAgentBootstrapRequest(
        agentID: fixedUUID,
        adapterKind: "management",
        requestedTTLSeconds: 3_600,
        bootstrapNonce: nonce
    ) == nil)
    #expect(AgentPassAgentBootstrapRequest(
        agentID: fixedUUID,
        adapterKind: "claude_code",
        requestedTTLSeconds: 1,
        bootstrapNonce: nonce
    ) == nil)
    #expect(AgentPassAgentBootstrapRequest(
        agentID: fixedUUID,
        adapterKind: "claude_code",
        requestedTTLSeconds: 3_600,
        bootstrapNonce: Data(repeating: 0, count: 65)
    ) == nil)
    #expect(AgentPassAgentSessionResponse(
        sessionID: fixedUUID,
        leaseID: fixedUUID2,
        processBindingDigest: Data(repeating: 0, count: 31),
        worktreeBindingDigest: digest,
        expiresAtMilliseconds: 4_000_000_000_000,
        maxSignatures: 2
    ) == nil)
    #expect(AgentPassAgentSessionStatusResponse(
        sessionID: fixedUUID,
        status: "management_mutation",
        expiresAtMilliseconds: 4_000_000_000_000,
        maxSignatures: 2,
        usedSignatures: 0
    ) == nil)
    #expect(AgentPassAgentSignRequest(
        sessionID: fixedUUID,
        requestID: fixedUUID2,
        capabilityID: fixedUUID3,
        commitPayload: Data(repeating: 0, count: AgentPassAgentSignRequest.maximumCommitPayloadBytes + 1),
        requestNonce: nonce,
        createdAtMilliseconds: 4_000_000_000_000
    ) == nil)
    #expect(AgentPassAgentCloseSessionRequest(sessionID: fixedUUID, reason: "revoke_all") == nil)
}

@Test func secureDecoderRejectsWrongObjectClassesAndMissingRequiredFields() throws {
    let archiver = NSKeyedArchiver(requiringSecureCoding: true)
    archiver.encode("not-a-uuid" as NSString, forKey: "session_id")
    archiver.encode(NSNumber(value: 1), forKey: "max_signatures")
    archiver.finishEncoding()
    let wrongDecoded = try? NSKeyedUnarchiver.unarchivedObject(ofClass: AgentPassAgentSessionResponse.self, from: archiver.encodedData)
    #expect(wrongDecoded == nil)

    let incompleteArchiver = NSKeyedArchiver(requiringSecureCoding: true)
    incompleteArchiver.encode(fixedUUID as NSString, forKey: "session_id")
    incompleteArchiver.finishEncoding()
    let incompleteDecoded = try? NSKeyedUnarchiver.unarchivedObject(ofClass: AgentPassAgentSessionStatusRequest.self, from: incompleteArchiver.encodedData)
    #expect(incompleteDecoded == nil)
}
