import AgentPassNativeCore
import Foundation
import ObjectiveC.runtime
import Testing

private func childArchive(_ object: NSSecureCoding) throws -> Data {
    try NSKeyedArchiver.archivedData(withRootObject: object, requiringSecureCoding: true)
}

private let childTicket = Data(repeating: 0x71, count: AgentPassChildGitXPCContract.attachTicketBytes)
private let childRequestID = "88888888-8888-4888-8888-888888888888"
private let childCreatedAtMilliseconds: Int64 = 1_786_616_000_000

@Test func childGitDTOsRoundTripWithoutSessionOrAuthority() throws {
    let request = try #require(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data("tree abc\n".utf8), attachTicket: childTicket, requestID: childRequestID, createdAtMilliseconds: childCreatedAtMilliseconds))
    let attach = try #require(AgentPassChildGitAttachRequest())
    let attachResponse = try #require(AgentPassChildGitAttachResponse(attachTicket: childTicket, expiresAtMilliseconds: 1_786_616_100_000, requestID: childRequestID, createdAtMilliseconds: childCreatedAtMilliseconds))
    let response = try #require(AgentPassChildGitSignResponse(responseSequence: 1, signature: Data(repeating: 0x44, count: 64), maxSignatures: 5, usedSignatures: 4, remainingSignatures: 1, requestID: childRequestID, createdAtMilliseconds: childCreatedAtMilliseconds))
    let requestData = try childArchive(request)
    let responseData = try childArchive(response)
    let attachData = try childArchive(attach)
    let attachResponseData = try childArchive(attachResponse)
    let decodedRequest = try NSKeyedUnarchiver.unarchivedObject(ofClass: AgentPassChildGitSignRequest.self, from: requestData)
    let decodedResponse = try NSKeyedUnarchiver.unarchivedObject(ofClass: AgentPassChildGitSignResponse.self, from: responseData)
    let decodedAttach = try NSKeyedUnarchiver.unarchivedObject(ofClass: AgentPassChildGitAttachRequest.self, from: attachData)
    let decodedAttachResponse = try NSKeyedUnarchiver.unarchivedObject(ofClass: AgentPassChildGitAttachResponse.self, from: attachResponseData)
    #expect(decodedRequest?.commitPayload == request.commitPayload)
    #expect(decodedRequest?.attachTicket == childTicket)
    #expect(decodedRequest?.requestID == childRequestID)
    #expect(decodedRequest?.createdAtMilliseconds == childCreatedAtMilliseconds)
    #expect(decodedResponse?.signature == response.signature)
    #expect(decodedResponse?.requestID == childRequestID)
    #expect(decodedResponse?.createdAtMilliseconds == childCreatedAtMilliseconds)
    #expect(decodedAttach?.protocolVersion == AgentPassChildGitXPCContract.protocolVersion)
    #expect(decodedAttachResponse?.attachTicket == childTicket)
    #expect(decodedAttachResponse?.requestID == childRequestID)
    #expect(decodedAttachResponse?.createdAtMilliseconds == childCreatedAtMilliseconds)
    #expect(String(decoding: requestData, as: UTF8.self).contains("session_id") == false)
}

@Test func childGitDTOsRejectInvalidSequenceAndBounds() {
    #expect(AgentPassChildGitSignRequest(requestSequence: 0, commitPayload: Data([1]), attachTicket: childTicket) == nil)
    #expect(AgentPassChildGitSignRequest(requestSequence: 3, commitPayload: Data([1]), attachTicket: childTicket) != nil)
    #expect(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data(), attachTicket: childTicket) == nil)
    #expect(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data(), attachTicket: childTicket) == nil)
    #expect(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data(repeating: 1, count: AgentPassChildGitXPCContract.maximumPayloadBytes + 1), attachTicket: childTicket) == nil)
    #expect(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data([1]), attachTicket: Data()) == nil)
    #expect(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data([1]), attachTicket: childTicket, requestID: "not-a-uuid", createdAtMilliseconds: childCreatedAtMilliseconds) == nil)
    #expect(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data([1]), attachTicket: childTicket, requestID: childRequestID, createdAtMilliseconds: 0) == nil)
    #expect(AgentPassChildGitSignResponse(responseSequence: 0, signature: Data([1]), maxSignatures: 5, usedSignatures: 1, remainingSignatures: 4, requestID: childRequestID, createdAtMilliseconds: childCreatedAtMilliseconds) == nil)
    #expect(AgentPassChildGitSignResponse(responseSequence: 1, signature: Data(), maxSignatures: 5, usedSignatures: 1, remainingSignatures: 4, requestID: childRequestID, createdAtMilliseconds: childCreatedAtMilliseconds) == nil)
    #expect(AgentPassChildGitSignResponse(responseSequence: 1, signature: Data(repeating: 1, count: AgentPassChildGitXPCContract.maximumSignatureBytes + 1), maxSignatures: 5, usedSignatures: 1, remainingSignatures: 4, requestID: childRequestID, createdAtMilliseconds: childCreatedAtMilliseconds) == nil)
    #expect(AgentPassChildGitSignResponse(responseSequence: 1, signature: Data([1]), maxSignatures: 5, usedSignatures: 4, remainingSignatures: 0, requestID: childRequestID, createdAtMilliseconds: childCreatedAtMilliseconds) == nil)
}

@Test func childGitDTOsRejectUnknownAuthorityFieldsAndUnsupportedVersions() throws {
    #expect(AgentPassChildGitSignRequest(protocolVersion: 1, requestSequence: 1, commitPayload: Data([1]), attachTicket: childTicket) == nil)
    #expect(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data([1]), attachTicket: Data(repeating: 1, count: 31)) == nil)
    #expect(AgentPassChildGitSignResponse(protocolVersion: 2, responseSequence: 1, signature: Data([1]), maxSignatures: 5, usedSignatures: 1, remainingSignatures: 4, requestID: childRequestID, createdAtMilliseconds: childCreatedAtMilliseconds) == nil)
    #expect(AgentPassChildGitSignResponse(responseSequence: 1, signature: Data([1]), maxSignatures: 5, usedSignatures: 1, remainingSignatures: 4, requestID: "not-a-uuid", createdAtMilliseconds: childCreatedAtMilliseconds) == nil)
}
