import AgentPassNativeCore
import Foundation
import ObjectiveC.runtime
import Testing

private func childArchive(_ object: NSSecureCoding) throws -> Data {
    try NSKeyedArchiver.archivedData(withRootObject: object, requiringSecureCoding: true)
}

private func childArchiveWithAuthorityKey(_ key: String) throws -> Data {
    let archiver = NSKeyedArchiver(requiringSecureCoding: true)
    archiver.encode(NSNumber(value: 1), forKey: "protocol_version")
    archiver.encode(NSNumber(value: 1), forKey: "request_sequence")
    archiver.encode(Data([1, 2, 3]) as NSData, forKey: "commit_payload")
    archiver.encode(Data(repeating: 0x71, count: AgentPassChildGitXPCContract.attachTicketBytes) as NSData, forKey: "attach_ticket")
    archiver.encode(Data([9]) as NSData, forKey: key)
    archiver.finishEncoding()
    return archiver.encodedData
}

private let childTicket = Data(repeating: 0x71, count: AgentPassChildGitXPCContract.attachTicketBytes)

@Test func childGitProtocolHasOnlyAdmissionAndSigningSelectors() {
    var count: UInt32 = 0
    let descriptions = protocol_copyMethodDescriptionList(AgentPassChildGitXPCProtocol.self, true, true, &count)
    defer { free(descriptions) }
    let selectors = Set((0..<Int(count)).compactMap { descriptions?[$0].name.map(NSStringFromSelector) })
    #expect(selectors == ["attachChildGit:withReply:", "signChildGitCommit:withReply:"])
}

@Test func childGitDTOsRoundTripWithoutSessionOrAuthority() throws {
    let request = try #require(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data("tree abc\n".utf8), attachTicket: childTicket))
    let attach = try #require(AgentPassChildGitAttachRequest())
    let attachResponse = try #require(AgentPassChildGitAttachResponse(attachTicket: childTicket, expiresAtMilliseconds: 1_786_616_100_000))
    let response = try #require(AgentPassChildGitSignResponse(responseSequence: 1, signature: Data(repeating: 0x44, count: 64), maxSignatures: 5, usedSignatures: 4, remainingSignatures: 1))
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
    #expect(decodedResponse?.signature == response.signature)
    #expect(decodedAttach?.protocolVersion == AgentPassChildGitXPCContract.protocolVersion)
    #expect(decodedAttachResponse?.attachTicket == childTicket)
    #expect(String(decoding: requestData, as: UTF8.self).contains("session_id") == false)
}

@Test func childGitDTOsRejectInvalidSequenceAndBounds() {
    #expect(AgentPassChildGitSignRequest(requestSequence: 0, commitPayload: Data([1]), attachTicket: childTicket) == nil)
    #expect(AgentPassChildGitSignRequest(requestSequence: 3, commitPayload: Data([1]), attachTicket: childTicket) != nil)
    #expect(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data(), attachTicket: childTicket) == nil)
    #expect(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data(), attachTicket: childTicket) == nil)
    #expect(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data(repeating: 1, count: AgentPassChildGitXPCContract.maximumPayloadBytes + 1), attachTicket: childTicket) == nil)
    #expect(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data([1]), attachTicket: Data()) == nil)
    #expect(AgentPassChildGitSignResponse(responseSequence: 0, signature: Data([1]), maxSignatures: 5, usedSignatures: 1, remainingSignatures: 4) == nil)
    #expect(AgentPassChildGitSignResponse(responseSequence: 1, signature: Data(), maxSignatures: 5, usedSignatures: 1, remainingSignatures: 4) == nil)
    #expect(AgentPassChildGitSignResponse(responseSequence: 1, signature: Data(repeating: 1, count: AgentPassChildGitXPCContract.maximumSignatureBytes + 1), maxSignatures: 5, usedSignatures: 1, remainingSignatures: 4) == nil)
    #expect(AgentPassChildGitSignResponse(responseSequence: 1, signature: Data([1]), maxSignatures: 5, usedSignatures: 4, remainingSignatures: 0) == nil)
}

@Test func childGitDTOsRejectUnknownAuthorityFieldsAndUnsupportedVersions() throws {
    let authority = try childArchiveWithAuthorityKey("session_id")
    let authorityDecoded = try? NSKeyedUnarchiver.unarchivedObject(ofClass: AgentPassChildGitSignRequest.self, from: authority)
    #expect(authorityDecoded == nil)

    #expect(AgentPassChildGitSignRequest(protocolVersion: 1, requestSequence: 1, commitPayload: Data([1]), attachTicket: childTicket) == nil)
    #expect(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data([1]), attachTicket: Data(repeating: 1, count: 31)) == nil)
    #expect(AgentPassChildGitSignResponse(protocolVersion: 3, responseSequence: 1, signature: Data([1]), maxSignatures: 5, usedSignatures: 1, remainingSignatures: 4) == nil)
}

@Test func childGitInterfaceRegistersOnlyItsDTOs() {
    let interface = AgentPassChildGitXPCInterface.make()
    let selector = #selector(AgentPassChildGitXPCProtocol.signChildGitCommit(_:withReply:))
    let requestClasses = interface.classes(for: selector, argumentIndex: 0, ofReply: false)
    let responseClasses = interface.classes(for: selector, argumentIndex: 0, ofReply: true)
    let requestNames = Set(requestClasses.map { String(describing: $0.base).split(separator: ".").last.map(String.init) ?? "" })
    let responseNames = Set(responseClasses.map { String(describing: $0.base).split(separator: ".").last.map(String.init) ?? "" })
    #expect(requestNames == ["AgentPassChildGitSignRequest"])
    #expect(responseNames == ["AgentPassChildGitSignResponse"])
    let attachSelector = #selector(AgentPassChildGitXPCProtocol.attachChildGit(_:withReply:))
    #expect(Set(interface.classes(for: attachSelector, argumentIndex: 0, ofReply: false).map { String(describing: $0.base).split(separator: ".").last.map(String.init) ?? "" }) == ["AgentPassChildGitAttachRequest"])
    #expect(Set(interface.classes(for: attachSelector, argumentIndex: 0, ofReply: true).map { String(describing: $0.base).split(separator: ".").last.map(String.init) ?? "" }) == ["AgentPassChildGitAttachResponse"])
}
