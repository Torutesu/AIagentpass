import AgentPassNativeService
import Foundation
import Testing
@testable import AgentPassNativeCore

@Test func hostConnectionAttributesRejectInvalidPeerFactsBeforeContextConstruction() throws {
    #expect(throws: NativeAgentAuthenticatedHostConnectionAttributeError.invalidConnectionAttributes) {
        _ = try NativeAgentAuthenticatedHostConnectionAttributes(
            processIdentifier: 0,
            effectiveUserID: 501,
            auditSessionIdentifier: 7
        )
    }
    #expect(throws: NativeAgentAuthenticatedHostConnectionAttributeError.invalidConnectionAttributes) {
        _ = try NativeAgentAuthenticatedHostConnectionAttributes(
            processIdentifier: 42,
            effectiveUserID: 501,
            auditSessionIdentifier: 0
        )
    }
}

@Test func hostConnectionAttributeOSBoundaryCanBeInjectedIntoTheCoreContextFactory() throws {
    let expected = try NativeAgentAuthenticatedHostConnectionAttributes(
        processIdentifier: 42,
        effectiveUserID: 501,
        auditSessionIdentifier: 77
    )
    let source = NativeAgentAuthenticatedHostClosureConnectionAttributeSource { _ in expected }
    let connection = NSXPCConnection(serviceName: "dev.agentpass.test-only")
    let observed = try source.attributes(for: connection)
    #expect(observed == expected)

    let processFacts = try NativeObservedProcessFacts(
        uid: observed.effectiveUserID,
        pid: observed.processIdentifier,
        pidVersion: 19,
        bootIdentity: "listener-test-boot",
        executableFileIdentity: try NativeExecutableFileIdentity(
            deviceID: 1,
            inode: 42,
            fileSize: 3,
            modificationTimeNanoseconds: 4
        ),
        codeDirectoryHash: String(repeating: "a", count: 64),
        bundleIdentifier: "dev.agentpass.test",
        teamIdentifier: "ABCDE12345",
        signatureKind: .developerID,
        entitlements: [:]
    )
    let observation = try NativeProcessObservation(process: processFacts, ancestry: [])
    let contextFactory: NativeAgentAuthenticatedHostListenerDelegate.PeerContextFactory = { attributes, observation in
        try NativeConnectionContext(
            osProcessID: attributes.processIdentifier,
            effectiveUserID: attributes.effectiveUserID,
            auditSessionID: attributes.auditSessionIdentifier,
            pidVersion: observation.process.pidVersion
        )
    }
    let context = try contextFactory(observed, observation)

    #expect(context.pid == expected.processIdentifier)
    #expect(context.effectiveUserID == expected.effectiveUserID)
    #expect(context.auditSessionID == expected.auditSessionIdentifier)
    #expect(context.pidVersion == observation.process.pidVersion)
}

@Test func hostConnectionAttributeSourceDoesNotClaimACompleteRawAuditToken() throws {
    // An unactivated test connection has no live peer and must fail closed;
    // this assertion also keeps the public-API limitation explicit. A raw
    // audit-token integration would need a different transport boundary.
    #expect(throws: NativeAgentAuthenticatedHostConnectionAttributeError.invalidConnectionAttributes) {
        _ = try NativeAgentAuthenticatedHostNSXPCConnectionAttributeSource()
            .attributes(for: NSXPCConnection(serviceName: "dev.agentpass.test-only"))
    }
}
