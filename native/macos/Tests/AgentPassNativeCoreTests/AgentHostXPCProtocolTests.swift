import AgentPassNativeCore
import Foundation
import ObjectiveC.runtime
import Testing

private let hostSessionID = "22222222-2222-4222-8222-222222222222"
private let hostDigest = Data(repeating: 0x11, count: AgentPassHostXPCContract.digestBytes)
private let hostDigest2 = Data(repeating: 0x22, count: AgentPassHostXPCContract.digestBytes)
private let hostDigest3 = Data(repeating: 0x33, count: AgentPassHostXPCContract.digestBytes)
private let hostNonce = Data(repeating: 0x44, count: AgentPassHostXPCContract.minimumNonceBytes)
private let hostRequestID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
private let hostCreatedAtMilliseconds: Int64 = 4_000_000_000_000

private func archive(_ object: NSSecureCoding) throws -> Data {
    try NSKeyedArchiver.archivedData(withRootObject: object, requiringSecureCoding: true)
}

private func unarchive<T: NSObject & NSSecureCoding>(_ type: T.Type, from data: Data) throws -> T {
    let object = try NSKeyedUnarchiver.unarchivedObject(ofClass: type, from: data)
    return try #require(object)
}

private final class HostForbiddenKeyCoder: NSCoder {
    private let forbiddenKey: String

    init(forbiddenKey: String) {
        self.forbiddenKey = forbiddenKey
        super.init()
    }

    override var allowsKeyedCoding: Bool { true }

    override func containsValue(forKey key: String) -> Bool {
        key == forbiddenKey || key == "commit_payload"
    }

}

@Test func hostDTOsRoundTripWithSecureCodingAndServiceAssignedSessionOnly() throws {
    let prepare = try #require(AgentPassHostPrepareRequest(launchNonce: hostNonce))
    let prepareResponse = try #require(AgentPassHostPrepareResponse(
        sessionID: hostSessionID,
        status: .prepared,
        expiresAtMilliseconds: 4_000_000_000_000,
        maxSignatures: 5,
        usedSignatures: 3
    ))
    let attach = try #require(AgentPassHostAttachChildRequest(
        childPID: 42,
        childPIDVersion: 1_735_000_000_000_000,
        executableIdentityDigest: hostDigest,
        ancestryBindingDigest: hostDigest2,
        worktreeBindingDigest: hostDigest3
    ))
    let attachResponse = try #require(AgentPassHostAttachChildResponse(
        sessionID: hostSessionID,
        attachedAtMilliseconds: 4_000_000_000_000,
        maxSignatures: 5,
        usedSignatures: 3
    ))
    let sign = try #require(AgentPassHostSignRequest(
        requestSequence: 1,
        commitPayload: Data("tree deadbeef\n".utf8),
        requestID: hostRequestID,
        createdAtMilliseconds: hostCreatedAtMilliseconds
    ))
    let signResponse = try #require(AgentPassHostSignResponse(
        responseSequence: 1,
        signature: Data(repeating: 0x55, count: 64),
        maxSignatures: 5,
        usedSignatures: 4,
        remainingSignatures: 1,
        requestID: hostRequestID,
        createdAtMilliseconds: hostCreatedAtMilliseconds
    ))
    let statusRequest = try #require(AgentPassHostStatusRequest())
    let statusResponse = try #require(AgentPassHostStatusResponse(
        sessionID: hostSessionID,
        status: .active,
        expiresAtMilliseconds: 4_000_000_000_000,
        maxSignatures: 5,
        usedSignatures: 4,
        childAttached: true
    ))
    let closeRequest = try #require(AgentPassHostCloseRequest(reason: .completed))
    let closeResponse = try #require(AgentPassHostCloseResponse(sessionID: hostSessionID, closedAtMilliseconds: 4_000_000_000_000))
    let controlRequest = try #require(AgentPassHostControlCloseRequest(
        sessionID: hostSessionID,
        operationID: hostRequestID,
        reason: .clientShutdown
    ))
    let controlResponse = try #require(AgentPassHostControlCloseResponse(
        operationID: hostRequestID,
        sessionID: hostSessionID,
        closedAtMilliseconds: 4_000_000_000_000
    ))

    #expect((try unarchive(AgentPassHostPrepareRequest.self, from: archive(prepare))).launchNonce == hostNonce)
    #expect((try unarchive(AgentPassHostPrepareResponse.self, from: archive(prepareResponse))).sessionID == hostSessionID)
    #expect((try unarchive(AgentPassHostAttachChildRequest.self, from: archive(attach))).childPIDVersion == 1_735_000_000_000_000)
    #expect((try unarchive(AgentPassHostAttachChildResponse.self, from: archive(attachResponse))).status == "attached")
    let decodedSign = try unarchive(AgentPassHostSignRequest.self, from: archive(sign))
    #expect(decodedSign.requestSequence == 1)
    #expect(decodedSign.requestID == hostRequestID)
    #expect(decodedSign.createdAtMilliseconds == hostCreatedAtMilliseconds)
    let decodedSignResponse = try unarchive(AgentPassHostSignResponse.self, from: archive(signResponse))
    #expect(decodedSignResponse.responseSequence == 1)
    #expect(decodedSignResponse.requestID == hostRequestID)
    #expect(decodedSignResponse.createdAtMilliseconds == hostCreatedAtMilliseconds)
    #expect((try unarchive(AgentPassHostStatusRequest.self, from: archive(statusRequest))).protocolVersion == 1)
    #expect((try unarchive(AgentPassHostStatusResponse.self, from: archive(statusResponse))).childAttached)
    #expect((try unarchive(AgentPassHostCloseRequest.self, from: archive(closeRequest))).reason == "completed")
    #expect((try unarchive(AgentPassHostCloseResponse.self, from: archive(closeResponse))).status == "closed")
    let decodedControlRequest = try unarchive(AgentPassHostControlCloseRequest.self, from: archive(controlRequest))
    #expect(decodedControlRequest.sessionID == hostSessionID)
    #expect(decodedControlRequest.operationID == hostRequestID)
    let decodedControlResponse = try unarchive(AgentPassHostControlCloseResponse.self, from: archive(controlResponse))
    #expect(decodedControlResponse.operationID == hostRequestID)
    #expect(decodedControlResponse.status == "closed")

    let signLabels = Set(Mirror(reflecting: sign).children.compactMap(\.label))
    #expect(signLabels == ["requestSequence", "commitPayload", "requestID", "createdAtMilliseconds"])
    for forbidden in ["capability", "privateKey", "algorithm", "operation", "repositoryPath", "sessionID", "token"] {
        #expect(signLabels.contains(forbidden) == false)
    }
}

@Test func hostControlDTORejectsMalformedOrAuthorityBearingValues() throws {
    #expect(AgentPassHostControlCloseRequest(
        sessionID: hostSessionID,
        operationID: "not-a-uuid",
        reason: .completed
    ) == nil)
    #expect(AgentPassHostControlCloseRequest(
        sessionID: "not-a-uuid",
        operationID: hostRequestID,
        reason: .completed
    ) == nil)
    let labels = Set(Mirror(reflecting: try #require(AgentPassHostControlCloseRequest(
        sessionID: hostSessionID,
        operationID: hostRequestID,
        reason: .completed
    ))).children.compactMap(\.label))
    #expect(labels == ["protocolVersion", "sessionID", "operationID", "reason"])
    for forbidden in ["token", "capability", "privateKey", "pid", "filePath", "environment"] {
        #expect(labels.contains(forbidden) == false)
    }
}

@Test func attachRejectsMalformedPIDVersionProtocolAndDigests() {
    func attach(
        protocolVersion: Int = AgentPassHostXPCContract.protocolVersion,
        pid: Int = 42,
        pidVersion: Int64 = 1_735_000_000_000_000,
        executable: Data = hostDigest,
        ancestry: Data = hostDigest2,
        worktree: Data = hostDigest3
    ) -> AgentPassHostAttachChildRequest? {
        AgentPassHostAttachChildRequest(
            protocolVersion: protocolVersion,
            childPID: pid,
            childPIDVersion: pidVersion,
            executableIdentityDigest: executable,
            ancestryBindingDigest: ancestry,
            worktreeBindingDigest: worktree
        )
    }

    #expect(attach(pid: 0) == nil)
    #expect(attach(pid: -1) == nil)
    #expect(attach(pid: Int(Int32.max) + 1) == nil)
    #expect(attach(pidVersion: 0) == nil)
    #expect(attach(pidVersion: -1) == nil)
    #expect(attach(pidVersion: AgentPassHostXPCContract.maximumChildPIDVersion + 1) == nil)
    #expect(attach(protocolVersion: 0) == nil)
    #expect(attach(protocolVersion: 2) == nil)
    #expect(attach(executable: Data(repeating: 0, count: 32)) == nil)
    #expect(attach(ancestry: Data(repeating: 0xAA, count: 31)) == nil)
    #expect(attach(worktree: Data(repeating: 0xAA, count: 33)) == nil)
}

@Test func hostPrepareAndResponsesRejectMalformedVersionAndBounds() {
    #expect(AgentPassHostPrepareRequest(protocolVersion: 0, launchNonce: hostNonce) == nil)
    #expect(AgentPassHostPrepareRequest(launchNonce: Data(repeating: 0, count: 15)) == nil)
    #expect(AgentPassHostPrepareRequest(launchNonce: Data(repeating: 0, count: 65)) == nil)
    #expect(AgentPassHostPrepareResponse(protocolVersion: 2, sessionID: hostSessionID, status: .prepared, expiresAtMilliseconds: 1, maxSignatures: 1, usedSignatures: 0) == nil)
    #expect(AgentPassHostPrepareResponse(sessionID: hostSessionID, status: .active, expiresAtMilliseconds: 1, maxSignatures: 1, usedSignatures: 0) == nil)
    #expect(AgentPassHostPrepareResponse(sessionID: hostSessionID, status: .prepared, expiresAtMilliseconds: 0, maxSignatures: 2, usedSignatures: 0) == nil)
    #expect(AgentPassHostPrepareResponse(sessionID: hostSessionID, status: .prepared, expiresAtMilliseconds: -1, maxSignatures: 1, usedSignatures: 0) == nil)
    #expect(AgentPassHostPrepareResponse(sessionID: hostSessionID, status: .prepared, expiresAtMilliseconds: 1, maxSignatures: 0, usedSignatures: 0) == nil)
    #expect(AgentPassHostPrepareResponse(sessionID: hostSessionID, status: .prepared, expiresAtMilliseconds: 1, maxSignatures: 2, usedSignatures: 3) == nil)
    #expect(AgentPassHostStatusRequest(protocolVersion: 2) == nil)
}

@Test func signCarriesOnlySequenceAndPayloadAndOrderingRejectsSignBeforeAttach() throws {
    let request = try #require(AgentPassHostSignRequest(requestSequence: 1, commitPayload: Data(repeating: 0x01, count: 1)))
    #expect(request.requestSequence == 1)
    #expect(request.commitPayload.count == 1)
    #expect(request.requestID.isEmpty)
    #expect(request.createdAtMilliseconds == 0)
    #expect(AgentPassHostXPCContract.isAllowed(.signPayload, in: .prepared) == false)
    #expect(AgentPassHostXPCContract.isAllowed(.status, in: .prepared) == false)
    #expect(throws: AgentPassHostXPCContract.ValidationError.invalidOrdering) {
        try AgentPassHostXPCContract.requireAllowed(.signPayload, in: .prepared)
    }
    try AgentPassHostXPCContract.requireAllowed(.signPayload, in: .attached)
    #expect(AgentPassHostSignRequest(requestSequence: 0, commitPayload: Data([1])) == nil)
    #expect(AgentPassHostSignRequest(requestSequence: 3, commitPayload: Data([1])) != nil)
    #expect(AgentPassHostSignRequest(requestSequence: 1, commitPayload: Data()) == nil)
    #expect(AgentPassHostSignRequest(requestSequence: 1, commitPayload: Data(repeating: 0x01, count: AgentPassHostXPCContract.maximumCommitPayloadBytes + 1)) == nil)
    #expect(AgentPassHostSignRequest(requestSequence: 1, commitPayload: Data([1]), requestID: hostRequestID, createdAtMilliseconds: hostCreatedAtMilliseconds) != nil)
    #expect(AgentPassHostSignRequest(requestSequence: 1, commitPayload: Data([1]), requestID: "", createdAtMilliseconds: hostCreatedAtMilliseconds) == nil)
    #expect(AgentPassHostSignRequest(requestSequence: 1, commitPayload: Data([1]), requestID: hostRequestID, createdAtMilliseconds: 0) == nil)
    #expect(AgentPassHostSignRequest(requestSequence: 1, commitPayload: Data([1]), requestID: "not-a-uuid", createdAtMilliseconds: hostCreatedAtMilliseconds) == nil)
    #expect(AgentPassHostSignResponse(responseSequence: 1, signature: Data([1]), maxSignatures: 5, usedSignatures: 5, remainingSignatures: 0) != nil)
    #expect(AgentPassHostSignResponse(responseSequence: 2, signature: Data([1]), maxSignatures: 5, usedSignatures: 5, remainingSignatures: 0) != nil)
    #expect(AgentPassHostSignResponse(responseSequence: 1, signature: Data([1]), maxSignatures: 5, usedSignatures: 4, remainingSignatures: 0) == nil)
    #expect(AgentPassHostSignResponse(responseSequence: 1, signature: Data([1]), maxSignatures: 5, usedSignatures: 4, remainingSignatures: 1, requestID: hostRequestID, createdAtMilliseconds: hostCreatedAtMilliseconds) != nil)
    #expect(AgentPassHostSignResponse(responseSequence: 1, signature: Data([1]), maxSignatures: 5, usedSignatures: 4, remainingSignatures: 1, requestID: "", createdAtMilliseconds: hostCreatedAtMilliseconds) == nil)
    #expect(AgentPassHostSignResponse(responseSequence: 1, signature: Data([1]), maxSignatures: 5, usedSignatures: 4, remainingSignatures: 1, requestID: hostRequestID, createdAtMilliseconds: 0) == nil)
}

@Test func everyHostRequestShapeExcludesAuthorityKeyMaterialAndPaths() throws {
    let requests: [NSObject] = [
        try #require(AgentPassHostPrepareRequest(launchNonce: hostNonce)),
        try #require(AgentPassHostAttachChildRequest(
            childPID: 42,
            childPIDVersion: 1_735_000_000_000_000,
            executableIdentityDigest: hostDigest,
            ancestryBindingDigest: hostDigest2,
            worktreeBindingDigest: hostDigest3
        )),
        try #require(AgentPassHostSignRequest(requestSequence: 1, commitPayload: Data([0x01]))),
        try #require(AgentPassHostStatusRequest()),
        try #require(AgentPassHostCloseRequest(reason: .completed)),
    ]
    let forbiddenFragments = [
        "capability", "privateKey", "key", "algorithm", "repository", "worktreePath",
        "operation", "sessionID", "sessionToken", "token", "ttl", "scope", "authority",
    ]

    for request in requests {
        let labels = Set(Mirror(reflecting: request).children.compactMap(\.label))
        for fragment in forbiddenFragments {
            #expect(labels.allSatisfy { $0.localizedCaseInsensitiveContains(fragment) == false })
        }
    }
}

@Test func hostRequestsRejectUnexpectedAuthorityKeysIncludingCallerSessionID() {
    for key in ["capability", "lease", "grant", "private_key", "key", "authority", "algorithm", "operation", "repository_path", "session_id", "agent_id", "adapter_kind"] {
        #expect(AgentPassHostSignRequest(coder: HostForbiddenKeyCoder(forbiddenKey: key)) == nil)
    }
}
