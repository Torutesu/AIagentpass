@testable import AgentPassNativeService
import Darwin
import Foundation
import Testing

private let validAuditTokenWords: [UInt32] = [
    501, // auid
    501, // euid
    20,  // egid
    501, // ruid
    20,  // rgid
    42,  // pid
    77,  // asid
    19   // pidversion
]

private func rawAuditToken(words: [UInt32]) -> audit_token_t {
    var token = audit_token_t()
    token.val = (
        words[0], words[1], words[2], words[3],
        words[4], words[5], words[6], words[7]
    )
    return token
}

private func source(for words: [UInt32]) -> NativeMacOSAuditTokenSource {
    NativeMacOSAuditTokenSource { _ in rawAuditToken(words: words) }
}

@Test func macOSAuditTokenSourceExtractsAndBindsAllEightFields() throws {
    let source = source(for: validAuditTokenWords)
    let complete = try source.completeAuditToken(
        for: NSXPCConnection(serviceName: "dev.agentpass.test-only")
    )
    let expected = try NativeAgentAuthenticatedHostCompleteAuditToken(words: validAuditTokenWords)
    #expect(complete == expected)
}

@Test func macOSAuditTokenSourceRejectsInvalidCredentialAndProcessFields() throws {
    let invalidWords: [[UInt32]] = [
        [0, 0, 0, 0, 0, 0, 0, 0],
        [501, UInt32.max, 20, 501, 20, 42, 77, 19],
        [501, 501, UInt32.max, 501, 20, 42, 77, 19],
        [501, 501, 20, UInt32.max, 20, 42, 77, 19],
        [501, 501, 20, 501, UInt32.max, 42, 77, 19],
        [501, 501, 20, 501, 20, 0, 77, 19],
        [501, 501, 20, 501, 20, 42, 0, 19],
        [501, 501, 20, 501, 20, 42, 77, 0]
    ]

    for words in invalidWords {
        let source = source(for: words)
        #expect(throws: NativeAgentAuthenticatedHostAuditTokenError.invalidAuditToken) {
            _ = try source.completeAuditToken(
                for: NSXPCConnection(serviceName: "dev.agentpass.test-only")
            )
        }
    }
}

@Test func macOSAuditTokenSourceAllowsTheDocumentedNoAuditUserSentinel() throws {
    let words = [UInt32.max, 501, 20, 501, 20, 42, 77, 19]
    let source = source(for: words)
    let token = try source.completeAuditToken(
        for: NSXPCConnection(serviceName: "dev.agentpass.test-only")
    )
    #expect(token == (try NativeAgentAuthenticatedHostCompleteAuditToken(words: words)))
}

@Test func macOSAuditTokenSourceMapsReaderFailureToUnavailableWithoutFallback() throws {
    let source = NativeMacOSAuditTokenSource { _ in
        throw NativeAgentAuthenticatedHostAuditTokenError.auditTokenUnavailable
    }

    #expect(throws: NativeAgentAuthenticatedHostAuditTokenError.auditTokenUnavailable) {
        _ = try source.completeAuditToken(
            for: NSXPCConnection(serviceName: "dev.agentpass.test-only")
        )
    }
}
