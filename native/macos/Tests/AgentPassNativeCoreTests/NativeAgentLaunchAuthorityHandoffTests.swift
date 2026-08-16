import Foundation
import Testing
@testable import AgentPassNativeCore

private let launchAgentID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

private func launchProof(_ extra: [String: Any] = [:]) throws -> Data {
    var object: [String: Any] = [
        "version": 1,
        "nonce": "AAAAAAAAAAAAAAAAAAAAAA"
    ]
    for (key, value) in extra { object[key] = value }
    return try NativeStrictJSON.data(object)
}

private func launchHandoffData(
    agentID: String = launchAgentID,
    agentKind: String = "claude_code",
    ttl: Int = 600,
    proof: Data? = nil
) throws -> Data {
    let proof = try proof ?? launchProof()
    return try NativeStrictJSON.data([
        "schema_version": 1,
        "agent_id": agentID,
        "agent_kind": agentKind,
        "requested_ttl_seconds": ttl,
        "proof": String(decoding: proof, as: UTF8.self)
    ])
}

@Test func launchAuthorityHandoffDecodesOnlyCanonicalPrivateAuthority() throws {
    let data = try launchHandoffData()
    let handoff = try NativeAgentLaunchAuthorityHandoff.decode(data)

    #expect(handoff.agentID == launchAgentID)
    #expect(handoff.agentKind == .claudeCode)
    #expect(handoff.requestedTTLSeconds == 600)
    #expect(handoff.proof == (try launchProof()))
    #expect(try NativeAgentLaunchAuthorityHandoff.decode(data) == handoff)
}

@Test func launchAuthorityHandoffRejectsAliasesUnknownFieldsAndNoncanonicalBytes() throws {
    let uppercaseID = launchAgentID.uppercased()
    #expect(throws: NativeAgentLaunchAuthorityHandoffError.invalidFields) {
        try NativeAgentLaunchAuthorityHandoff.decode(launchHandoffData(agentID: uppercaseID))
    }

    let unknown = try NativeStrictJSON.data([
        "schema_version": 1,
        "agent_id": launchAgentID,
        "agent_kind": "claude_code",
        "requested_ttl_seconds": 600,
        "proof": String(decoding: try launchProof(), as: UTF8.self),
        "session": "forbidden"
    ])
    #expect(throws: NativeAgentLaunchAuthorityHandoffError.invalidFields) {
        try NativeAgentLaunchAuthorityHandoff.decode(unknown)
    }

    let canonical = try launchHandoffData()
    #expect(throws: NativeAgentLaunchAuthorityHandoffError.malformed) {
        try NativeAgentLaunchAuthorityHandoff.decode(Data(" \n".utf8) + canonical)
    }
}

@Test func launchAuthorityHandoffRejectsDuplicateAndNoncanonicalProofs() throws {
    let duplicate = Data("{\"agent_id\":\"(launchAgentID)\",\"agent_id\":\"(launchAgentID)\",\"agent_kind\":\"claude_code\",\"proof\":\"{}\",\"requested_ttl_seconds\":600,\"schema_version\":1}".utf8)
    #expect(throws: NativeAgentLaunchAuthorityHandoffError.malformed) {
        try NativeAgentLaunchAuthorityHandoff.decode(duplicate)
    }

    #expect(throws: NativeAgentLaunchAuthorityHandoffError.invalidFields) {
        try NativeAgentLaunchAuthorityHandoff.decode(
            launchHandoffData(proof: Data("{ \"version\": 1 }".utf8)))
    }
}

@Test func launchAuthorityHandoffEnforcesKindTTLAndSizeBounds() throws {
    #expect(throws: NativeAgentLaunchAuthorityHandoffError.invalidFields) {
        try NativeAgentLaunchAuthorityHandoff.decode(launchHandoffData(agentKind: "custom"))
    }
    #expect(throws: NativeAgentLaunchAuthorityHandoffError.invalidFields) {
        try NativeAgentLaunchAuthorityHandoff.decode(launchHandoffData(ttl: 59))
    }
    #expect(throws: NativeAgentLaunchAuthorityHandoffError.oversized) {
        try NativeAgentLaunchAuthorityHandoff.decode(
            Data(repeating: 0x20, count: NativeAgentLaunchAuthorityHandoff.maximumDocumentBytes + 1))
    }
}
