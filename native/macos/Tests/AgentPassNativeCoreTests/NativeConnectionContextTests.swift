import Foundation
import Testing
@testable import AgentPassNativeCore

private let connectionWords: [UInt32] = [
    501, // auid
    501, // euid
    20,  // egid
    501, // ruid
    20,  // rgid
    42_424,
    77,
    19
]

private func adapter(words: [UInt32] = connectionWords) throws -> NativeAuditTokenFieldAdapter {
    try NativeAuditTokenFieldAdapter(words: words)
}

private func replacing(_ index: Int, with value: UInt32) -> [UInt32] {
    var copy = connectionWords
    copy[index] = value
    return copy
}

private func expectConnectionError(
    _ expected: NativeConnectionContextError,
    operation: () throws -> Void
) throws {
    do {
        try operation()
        Issue.record("expected NativeConnectionContextError.\(expected.rawValue)")
    } catch let actual as NativeConnectionContextError {
        #expect(actual == expected)
        #expect(actual.code == expected.rawValue)
        #expect(actual.errorDescription == expected.rawValue)
    } catch {
        Issue.record("unexpected error: \(error)")
    }
}

@Test func strictAuditTokenAdapterAcceptsOnlyThePortableEightFieldShape() throws {
    let extracted = try adapter()
    let named = try NativeAuditTokenFieldAdapter(
        auditUserID: connectionWords[0],
        effectiveUserID: connectionWords[1],
        effectiveGroupID: connectionWords[2],
        realUserID: connectionWords[3],
        realGroupID: connectionWords[4],
        pid: Int32(connectionWords[5]),
        auditSessionID: connectionWords[6],
        pidVersion: connectionWords[7]
    )

    #expect(extracted == named)
    #expect(extracted.pid == 42_424)
    #expect(extracted.effectiveUserID == 501)
    #expect(extracted.auditSessionID == 77)
    #expect(extracted.pidVersion == 19)
    #expect(extracted.tokenIdentity.count == 64)
    #expect(extracted.tokenIdentity == extracted.tokenIdentity.lowercased())
    #expect(extracted.description.contains(extracted.tokenIdentity))
    #expect(!extracted.description.contains("42,424"))
    #expect(!extracted.description.contains("auditUserID"))
    #expect(!extracted.description.contains("raw"))
}

@Test func strictAuditTokenAdapterRejectsMalformedBroadAndAllZeroInputs() throws {
    try expectConnectionError(.malformedAuditToken) {
        _ = try NativeAuditTokenFieldAdapter(words: [])
    }
    try expectConnectionError(.malformedAuditToken) {
        _ = try NativeAuditTokenFieldAdapter(words: Array(repeating: 1, count: 7))
    }
    try expectConnectionError(.broadAuditTokenInput) {
        _ = try NativeAuditTokenFieldAdapter(words: Array(repeating: 1, count: 9))
    }
    try expectConnectionError(.allZeroAuditToken) {
        _ = try NativeAuditTokenFieldAdapter(words: Array(repeating: 0, count: 8))
    }
}

@Test func strictAuditTokenAdapterRejectsInvalidIdentityFields() throws {
    for index in [5, 6, 7] {
        try expectConnectionError(.invalidAuditTokenField) {
            _ = try adapter(words: replacing(index, with: 0))
        }
    }
    try expectConnectionError(.invalidAuditTokenField) {
        _ = try adapter(words: replacing(1, with: UInt32.max))
    }
    try expectConnectionError(.invalidAuditTokenField) {
        _ = try adapter(words: replacing(5, with: UInt32.max))
    }
}

@Test func nativeConnectionContextCapturesOnlyTheSafePeerProjection() throws {
    let context = NativeConnectionContext(capturing: try adapter())
    #expect(context.pid == 42_424)
    #expect(context.effectiveUserID == 501)
    #expect(context.auditSessionID == 77)
    #expect(context.pidVersion == 19)
    #expect(context.peerIdentity.pid == context.pid)
    #expect(context.peerIdentity.tokenIdentity == context.tokenIdentity)

    let encoded = try JSONEncoder().encode(context)
    let json = String(decoding: encoded, as: UTF8.self)
    let object = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
    #expect(object["version"] as? String == "native_connection_context/v1")
    #expect(json.contains("peer_identity"))
    #expect(json.contains("token_identity"))
    #expect(!json.contains("audit_token"))
    #expect(!json.contains("auditUserID"))
    #expect(!json.contains("effectiveGroupID"))
    #expect(!json.contains("raw"))
    #expect(!json.contains("words"))

    let decoded = try JSONDecoder().decode(NativeConnectionContext.self, from: encoded)
    #expect(decoded == context)
    #expect(decoded.description == context.description)
    #expect(!context.description.contains("audit_token"))
    #expect(!context.description.contains("auditUserID"))
    #expect(!context.description.contains("raw"))
}

@Test func nativeConnectionContextBindsReobservationToTheWholeTokenIdentity() throws {
    let context = NativeConnectionContext(capturing: try adapter())
    try context.validate(reobserved: try adapter())
    #expect(context.matches(reobserved: try adapter()))

    for index in 0..<connectionWords.count {
        let changed = try adapter(words: replacing(index, with: connectionWords[index] &+ 1))
        #expect(!context.matches(reobserved: changed))
        try expectConnectionError(.peerIdentityMismatch) {
            try context.validate(reobserved: changed)
        }
    }
}

@Test func nativeConnectionContextCapturesPublicNSXPCFieldsAndFullKernelPIDVersion() throws {
    let largePIDVersion = UInt64(UInt32.max) + 42
    let context = try NativeConnectionContext(
        osProcessID: 42_424,
        effectiveUserID: 501,
        auditSessionID: 77,
        pidVersion: largePIDVersion
    )

    #expect(context.pid == 42_424)
    #expect(context.effectiveUserID == 501)
    #expect(context.auditSessionID == 77)
    #expect(context.pidVersion == largePIDVersion)
    #expect(context.tokenIdentity.count == 64)
    #expect(!context.description.contains("audit_token"))
}

@Test func publicNSXPCProjectionRemainsDistinctFromTheFullAuditTokenProjection() throws {
    let fullAuditTokenContext = NativeConnectionContext(capturing: try adapter())
    let publicNSXPCContext = try NativeConnectionContext(
        osProcessID: fullAuditTokenContext.pid,
        effectiveUserID: fullAuditTokenContext.effectiveUserID,
        auditSessionID: fullAuditTokenContext.auditSessionID,
        pidVersion: fullAuditTokenContext.pidVersion
    )

    #expect(publicNSXPCContext.pid == fullAuditTokenContext.pid)
    #expect(publicNSXPCContext.effectiveUserID == fullAuditTokenContext.effectiveUserID)
    #expect(publicNSXPCContext.auditSessionID == fullAuditTokenContext.auditSessionID)
    #expect(publicNSXPCContext.pidVersion == fullAuditTokenContext.pidVersion)
    #expect(publicNSXPCContext.tokenIdentity != fullAuditTokenContext.tokenIdentity)
}

@Test func nativeConnectionContextRejectsForgedSerializedValuesAndUsesStableErrors() throws {
    let invalidVersion = Data(#"{"version":"native_connection_context/v99","peer_identity":{}}"#.utf8)
    try expectConnectionError(.invalidSerializedContext) {
        _ = try JSONDecoder().decode(NativeConnectionContext.self, from: invalidVersion)
    }

    let invalidPeer = Data(#"{"version":"native_connection_context/v1","peer_identity":{"version":"native_connection_peer_identity/v1","pid":0,"effective_user_id":501,"audit_session_id":77,"pid_version":19,"token_identity":"0000000000000000000000000000000000000000000000000000000000000000"}}"#.utf8)
    try expectConnectionError(.invalidSerializedContext) {
        _ = try JSONDecoder().decode(NativeConnectionContext.self, from: invalidPeer)
    }

    #expect(NativeConnectionContextError.allCases.map(\.rawValue) == [
        "malformed_audit_token",
        "all_zero_audit_token",
        "broad_audit_token_input",
        "invalid_audit_token_field",
        "invalid_serialized_context",
        "peer_identity_mismatch"
    ])
}
