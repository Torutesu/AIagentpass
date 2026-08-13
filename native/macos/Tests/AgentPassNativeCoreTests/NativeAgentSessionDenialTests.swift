import Foundation
import Testing
@testable import AgentPassNativeCore

@Test func agentSessionDenialReasonsAreClosedAndWireUnique() {
    let reasons = NativeAgentSessionDenialReason.allCases
    #expect(reasons.count == 16)
    #expect(Set(reasons.map(\.rawValue)).count == reasons.count)
    #expect(Set(reasons.map(\.errorCode)).count == reasons.count)
    #expect(reasons.map(\.errorCode) == [
        1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008,
        1009, 1010, 1011, 1012, 1013, 1014, 1015, 1099
    ])
    #expect(reasons.allSatisfy { !$0.message.isEmpty && $0.message.utf8.count <= 128 })
}

@Test func agentSessionDenialReasonsRoundTripThroughCodable() throws {
    let encoder = JSONEncoder()
    let decoder = JSONDecoder()

    for reason in NativeAgentSessionDenialReason.allCases {
        let encoded = try encoder.encode(reason)
        #expect(String(decoding: encoded, as: UTF8.self) == "\"\(reason.rawValue)\"")
        #expect(try decoder.decode(NativeAgentSessionDenialReason.self, from: encoded) == reason)
    }

    #expect((try? decoder.decode(NativeAgentSessionDenialReason.self, from: Data("\"not_a_reason\"".utf8))) == nil)
}

@Test func agentSessionDenialNSErrorProjectionIsBounded() {
    for reason in NativeAgentSessionDenialReason.allCases {
        let error = reason.nsError

        #expect(error.domain == NativeAgentSessionDenialReason.errorDomain)
        #expect(error.code == reason.errorCode)
        #expect(error.localizedDescription == reason.message)
        #expect(error.userInfo.count == 2)
        #expect(error.userInfo.keys.contains(NSLocalizedDescriptionKey))
        #expect(error.userInfo.keys.contains(NativeAgentSessionDenialReason.reasonCodeUserInfoKey))
        #expect((error.userInfo[NativeAgentSessionDenialReason.reasonCodeUserInfoKey] as? NSNumber)?.intValue == reason.errorCode)
        #expect(NativeAgentSessionDenialReason.reason(from: error) == reason)
        #expect(NativeAgentSessionDenialNSError.reason(from: error) == reason)
        #expect(NativeAgentSessionDenialNSError.make(reason) == error)
    }
}

@Test func agentSessionDenialNSErrorRejectsUnboundedOrForeignErrors() {
    let original = NativeAgentSessionDenialReason.processDenied.nsError
    let wrongCode = NSError(
        domain: NativeAgentSessionDenialReason.errorDomain,
        code: NativeAgentSessionDenialReason.processDenied.errorCode + 1,
        userInfo: [
            NSLocalizedDescriptionKey: "The agent process is not authorized.",
            NativeAgentSessionDenialReason.reasonCodeUserInfoKey: NativeAgentSessionDenialReason.processDenied.errorCode
        ]
    )
    let extraDiagnostic = NSError(
        domain: NativeAgentSessionDenialReason.errorDomain,
        code: original.code,
        userInfo: [
            NSLocalizedDescriptionKey: original.localizedDescription,
            NativeAgentSessionDenialReason.reasonCodeUserInfoKey: original.code,
            NSUnderlyingErrorKey: NSError(domain: NSOSStatusErrorDomain, code: -50)
        ]
    )
    let foreign = NSError(
        domain: NSOSStatusErrorDomain,
        code: original.code,
        userInfo: [NSLocalizedDescriptionKey: "Security.framework detail"]
    )

    #expect(NativeAgentSessionDenialReason.reason(from: wrongCode) == nil)
    #expect(NativeAgentSessionDenialReason.reason(from: extraDiagnostic) == nil)
    #expect(NativeAgentSessionDenialReason.reason(from: foreign) == nil)
}
