import AgentPassNativeCore
import Foundation
import ObjectiveC.runtime
import Testing

private func childArchive(_ object: NSSecureCoding) throws -> Data {
    try NSKeyedArchiver.archivedData(withRootObject: object, requiringSecureCoding: true)
}

@Test func childGitProtocolHasOnlyTheSigningSelector() {
    var count: UInt32 = 0
    let descriptions = protocol_copyMethodDescriptionList(AgentPassChildGitXPCProtocol.self, true, true, &count)
    defer { free(descriptions) }
    let selectors = Set((0..<Int(count)).compactMap { descriptions?[$0].name.map(NSStringFromSelector) })
    #expect(selectors == ["signChildGitCommit:withReply:"])
}

@Test func childGitDTOsRoundTripWithoutSessionOrAuthority() throws {
    let request = try #require(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data("tree abc\n".utf8)))
    let response = try #require(AgentPassChildGitSignResponse(responseSequence: 1, signature: Data(repeating: 0x44, count: 64)))
    let requestData = try childArchive(request)
    let responseData = try childArchive(response)
    let decodedRequest = try NSKeyedUnarchiver.unarchivedObject(ofClass: AgentPassChildGitSignRequest.self, from: requestData)
    let decodedResponse = try NSKeyedUnarchiver.unarchivedObject(ofClass: AgentPassChildGitSignResponse.self, from: responseData)
    #expect(decodedRequest?.commitPayload == request.commitPayload)
    #expect(decodedResponse?.signature == response.signature)
    #expect(String(decoding: requestData, as: UTF8.self).contains("session_id") == false)
}

@Test func childGitDTOsRejectInvalidSequenceAndBounds() {
    #expect(AgentPassChildGitSignRequest(requestSequence: 0, commitPayload: Data([1])) == nil)
    #expect(AgentPassChildGitSignRequest(requestSequence: 3, commitPayload: Data([1])) == nil)
    #expect(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data()) == nil)
    #expect(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data(repeating: 1, count: AgentPassChildGitXPCContract.maximumPayloadBytes + 1)) == nil)
    #expect(AgentPassChildGitSignResponse(responseSequence: 0, signature: Data([1])) == nil)
    #expect(AgentPassChildGitSignResponse(responseSequence: 1, signature: Data()) == nil)
    #expect(AgentPassChildGitSignResponse(responseSequence: 1, signature: Data(repeating: 1, count: AgentPassChildGitXPCContract.maximumSignatureBytes + 1)) == nil)
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
}
