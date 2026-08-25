@testable import AgentPassNativeCore
import Foundation
import Testing
@testable import AgentPassNativeService

private func controlObservation(
    pid: Int32 = 42,
    pidVersion: UInt64 = 19,
    codeDirectoryHash: String = String(repeating: "a", count: 64)
) throws -> NativeProcessObservation {
    let facts = try NativeObservedProcessFacts(
        uid: 501,
        pid: pid,
        pidVersion: pidVersion,
        bootIdentity: "control-registry-test-boot",
        executableFileIdentity: try NativeExecutableFileIdentity(
            deviceID: 1,
            inode: UInt64(pid),
            fileSize: 3,
            modificationTimeNanoseconds: 4
        ),
        codeDirectoryHash: codeDirectoryHash,
        bundleIdentifier: "dev.agentpass.agent-host",
        teamIdentifier: "ABCDE12345",
        signatureKind: .developerID,
        entitlements: [:]
    )
    return try NativeProcessObservation(process: facts, ancestry: [])
}

private func controlEndpoint(
    observation: NativeProcessObservation
) throws -> NativeAgentAuthenticatedHostEndpoint {
    let identity = NativeProcessIdentity(observation: observation)
    let token = try NativeAgentAuthenticatedHostCompleteAuditToken(words: [
        501, 501, 20, 501, 20, UInt32(identity.pid), 77, UInt32(identity.pidVersion)
    ])
    let context = try token.context(matching: observation)
    return try NativeAgentAuthenticatedHostEndpoint(
        connectionContext: context,
        initialPeerObservation: observation,
        peerProcessPolicy: try NativeProcessIdentityPolicy.exact(identity),
        childProcessPolicy: try NativeProcessIdentityPolicy.exact(identity),
        observeConnectionContext: { context },
        observePeerProcess: { observation },
        observeChild: { _, _ in
            throw NativeAgentAuthenticatedHostEndpointError.childObservationFailed
        },
        signer: NativeAgentAuthenticatedHostClosureSigner { _ in Data([1]) },
        signerPolicy: .developmentLegacySignerAllowed,
        nowMilliseconds: { 4_000_000_000_000 },
        sessionLifetimeMilliseconds: 1_000,
        signatureBudgetProvider: {
            try NativeAgentSignatureBudget(maxSignatures: 2, usedSignatures: 0)
        }
    )
}

private func prepareControlSession(
    _ endpoint: NativeAgentAuthenticatedHostEndpoint
) throws -> AgentPassHostPrepareResponse {
    let request = try #require(AgentPassHostPrepareRequest(launchNonce: Data(repeating: 0x11, count: 16)))
    var response: AgentPassHostPrepareResponse?
    var error: NSError?
    endpoint.prepareHostSession(request) { value, failure in
        response = value
        error = failure
    }
    if let error { throw error }
    return try #require(response)
}

@Test("control close is idempotent across response loss and rejects altered replay")
func controlCloseConvergesAfterResponseLoss() throws {
    let observation = try controlObservation()
    let ownerIdentity = NativeProcessIdentity(observation: observation)
    let endpoint = try controlEndpoint(observation: observation)
    let prepared = try prepareControlSession(endpoint)
    let registry = NativeAgentHostControlRegistry()
    try registry.register(sessionID: prepared.sessionID, endpoint: endpoint, ownerIdentity: ownerIdentity)

    let operationID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    let firstRequest = try #require(AgentPassHostControlCloseRequest(
        sessionID: prepared.sessionID,
        operationID: operationID,
        reason: .clientShutdown
    ))
    let first = try registry.close(request: firstRequest, controllerIdentity: ownerIdentity)
    let retry = try registry.close(request: firstRequest, controllerIdentity: ownerIdentity)
    #expect(retry == first)

    let altered = try #require(AgentPassHostControlCloseRequest(
        sessionID: prepared.sessionID,
        operationID: operationID,
        reason: .completed
    ))
    #expect(throws: NativeAgentHostControlRegistryError.controlReplay) {
        _ = try registry.close(request: altered, controllerIdentity: ownerIdentity)
    }
}

@Test("control close rejects a different signed principal")
func controlCloseRejectsPeerMismatch() throws {
    let observation = try controlObservation()
    let ownerIdentity = NativeProcessIdentity(observation: observation)
    let endpoint = try controlEndpoint(observation: observation)
    let prepared = try prepareControlSession(endpoint)
    let registry = NativeAgentHostControlRegistry()
    try registry.register(sessionID: prepared.sessionID, endpoint: endpoint, ownerIdentity: ownerIdentity)

    let otherIdentity = NativeProcessIdentity(observation: try controlObservation(
        pid: 43,
        pidVersion: 20,
        codeDirectoryHash: String(repeating: "b", count: 64)
    ))
    let request = try #require(AgentPassHostControlCloseRequest(
        sessionID: prepared.sessionID,
        operationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        reason: .cancelled
    ))
    #expect(ownerIdentity.canonicalControlPrincipalHash != otherIdentity.canonicalControlPrincipalHash)
    #expect(throws: NativeAgentHostControlRegistryError.controlPeerMismatch) {
        _ = try registry.close(request: request, controllerIdentity: otherIdentity)
    }
}

@Test("control principal identity permits a distinct process of the same signed product")
func controlPrincipalExcludesProcessCoordinates() throws {
    let first = NativeProcessIdentity(observation: try controlObservation(pid: 42, pidVersion: 19))
    let second = NativeProcessIdentity(observation: try controlObservation(pid: 43, pidVersion: 20))
    #expect(first.canonicalBindingHash != second.canonicalBindingHash)
    #expect(first.canonicalControlPrincipalHash == second.canonicalControlPrincipalHash)
}

@Test("dedicated control endpoint authenticates its own peer before closing another connection's session")
func dedicatedControlEndpointClosesOwnerSession() throws {
    let ownerObservation = try controlObservation()
    let ownerIdentity = NativeProcessIdentity(observation: ownerObservation)
    let ownerEndpoint = try controlEndpoint(observation: ownerObservation)
    let prepared = try prepareControlSession(ownerEndpoint)
    let registry = NativeAgentHostControlRegistry()
    try registry.register(sessionID: prepared.sessionID, endpoint: ownerEndpoint, ownerIdentity: ownerIdentity)

    let controllerObservation = try controlObservation(pid: 43, pidVersion: 20)
    let controllerIdentity = NativeProcessIdentity(observation: controllerObservation)
    let controllerToken = try NativeAgentAuthenticatedHostCompleteAuditToken(words: [
        501, 501, 20, 501, 20, UInt32(controllerIdentity.pid), 77, UInt32(controllerIdentity.pidVersion)
    ])
    let controllerContext = try controllerToken.context(matching: controllerObservation)
    let controlEndpoint = try NativeAgentAuthenticatedHostControlEndpoint(
        connectionContext: controllerContext,
        initialPeerObservation: controllerObservation,
        peerProcessPolicy: try NativeProcessIdentityPolicy.exact(controllerIdentity),
        observeConnectionContext: { controllerContext },
        observePeerProcess: { controllerObservation },
        registry: registry
    )
    let request = try #require(AgentPassHostControlCloseRequest(
        sessionID: prepared.sessionID,
        operationID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        reason: .completed
    ))
    var response: AgentPassHostControlCloseResponse?
    var error: NSError?
    controlEndpoint.closeHostSessionFromControl(request) { value, failure in
        response = value
        error = failure
    }
    #expect(error == nil)
    #expect(response?.sessionID == prepared.sessionID)
    #expect(response?.status == AgentPassHostXPCContract.SessionStatus.closed.rawValue)
}

@Test("dedicated control endpoint rejects peer identity drift before registry access")
func dedicatedControlEndpointRejectsPeerDrift() throws {
    let ownerObservation = try controlObservation()
    let ownerIdentity = NativeProcessIdentity(observation: ownerObservation)
    let ownerEndpoint = try controlEndpoint(observation: ownerObservation)
    let prepared = try prepareControlSession(ownerEndpoint)
    let registry = NativeAgentHostControlRegistry()
    try registry.register(sessionID: prepared.sessionID, endpoint: ownerEndpoint, ownerIdentity: ownerIdentity)

    let controllerObservation = try controlObservation(pid: 43, pidVersion: 20)
    let controllerIdentity = NativeProcessIdentity(observation: controllerObservation)
    let controllerToken = try NativeAgentAuthenticatedHostCompleteAuditToken(words: [
        501, 501, 20, 501, 20, UInt32(controllerIdentity.pid), 77, UInt32(controllerIdentity.pidVersion)
    ])
    let controllerContext = try controllerToken.context(matching: controllerObservation)
    let driftedObservation = try controlObservation(
        pid: 43,
        pidVersion: 20,
        codeDirectoryHash: String(repeating: "c", count: 64)
    )
    let controlEndpoint = try NativeAgentAuthenticatedHostControlEndpoint(
        connectionContext: controllerContext,
        initialPeerObservation: controllerObservation,
        peerProcessPolicy: try NativeProcessIdentityPolicy.exact(controllerIdentity),
        observeConnectionContext: { controllerContext },
        observePeerProcess: { driftedObservation },
        registry: registry
    )
    let request = try #require(AgentPassHostControlCloseRequest(
        sessionID: prepared.sessionID,
        operationID: "ffffffff-ffff-4fff-8fff-ffffffffffff",
        reason: .cancelled
    ))
    var response: AgentPassHostControlCloseResponse?
    var error: NSError?
    controlEndpoint.closeHostSessionFromControl(request) { value, failure in
        response = value
        error = failure
    }
    #expect(response == nil)
    #expect(error?.localizedDescription == NativeAgentHostControlRegistryError.controlPeerMismatch.rawValue)
    let stillLiveRequest = try #require(AgentPassHostControlCloseRequest(
        sessionID: prepared.sessionID,
        operationID: "11111111-1111-4111-8111-111111111111",
        reason: .completed
    ))
    let closed = try registry.close(request: stillLiveRequest, controllerIdentity: ownerIdentity)
    #expect(closed.sessionID == prepared.sessionID)
}
