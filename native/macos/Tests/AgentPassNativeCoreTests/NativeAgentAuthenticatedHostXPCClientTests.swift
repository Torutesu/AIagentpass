import AgentPassNativeCore
import Foundation
import Testing

@Test func authenticatedHostClientRejectsOperationsBeforeConnectionOwnedSession() throws {
    let client = NativeAgentAuthenticatedHostXPCClient(
        machServiceName: "dev.agentpass.test-host-unavailable",
        timeout: .milliseconds(1)
    )

    #expect(throws: NativeAgentAuthenticatedHostXPCClient.Error.invalidState) {
        _ = try client.attach(
            childPID: 1,
            childPIDVersion: 1,
            executableIdentityDigest: Data(repeating: 1, count: 32),
            ancestryBindingDigest: Data(repeating: 2, count: 32),
            worktreeBindingDigest: Data(repeating: 3, count: 32)
        )
    }
    #expect(throws: NativeAgentAuthenticatedHostXPCClient.Error.invalidState) {
        _ = try client.sign(payload: Data([1]))
    }
    #expect(throws: NativeAgentAuthenticatedHostXPCClient.Error.invalidState) {
        _ = try client.status()
    }
}

@Test func authenticatedHostClientRejectsInvalidPrepareWithoutCallingRemote() throws {
    let client = NativeAgentAuthenticatedHostXPCClient(
        machServiceName: "dev.agentpass.test-host-unavailable",
        timeout: .milliseconds(1)
    )

    #expect(throws: NativeAgentAuthenticatedHostXPCClient.Error.invalidRequest) {
        _ = try client.prepare(launchNonce: Data())
    }
}
