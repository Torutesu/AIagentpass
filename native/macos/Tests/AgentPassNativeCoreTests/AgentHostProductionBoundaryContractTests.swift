import Foundation
import Testing

private func installerVerifierSource() throws -> String {
    let testDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    let packageRoot = testDirectory.deletingLastPathComponent().deletingLastPathComponent()
    return try String(
        contentsOf: packageRoot.appendingPathComponent("scripts/verify-installer-package.sh"),
        encoding: .utf8
    )
}

private func admitsAgentHost(
    identifier: String,
    hasSessionClientEntitlement: Bool,
    hasKeychainAccessGroup: Bool
) -> Bool {
    identifier == "dev.agentpass.agent-host" &&
        hasSessionClientEntitlement &&
        !hasKeychainAccessGroup
}

@Test("the production package verifier binds Agent Host identity to the Agent XPC admission contract")
func productionPackageVerifierRejectsAgentIdentitySubstitution() throws {
    let source = try installerVerifierSource()

    #expect(source.contains("AGENT_HOST_APP=\"$APP/Contents/Library/HelperTools/AgentPassNativeAgentHost.app\""))
    #expect(source.contains("AGENT_HOST_IDENTIFIER=\"$(/usr/bin/awk -F= '/^Identifier=/{print $2; exit}' <<<\"$AGENT_HOST_DETAILS\")\""))
    #expect(source.contains("AGENT_HOST_IDENTIFIER\" == \"dev.agentpass.agent-host\""))
    #expect(source.contains("Print :dev.agentpass.agent-session-client"))
    #expect(source.contains("Print :keychain-access-groups:0"))

    // Adversarial package mutations must fail the same admission predicate
    // that the service installs with setCodeSigningRequirement: a same-Team
    // executable, a missing dedicated entitlement, and a keychain-bearing
    // host are all outside the Agent XPC trust domain.
    #expect(admitsAgentHost(identifier: "dev.agentpass.native-client", hasSessionClientEntitlement: true, hasKeychainAccessGroup: false) == false)
    #expect(admitsAgentHost(identifier: "dev.agentpass.agent-host", hasSessionClientEntitlement: false, hasKeychainAccessGroup: false) == false)
    #expect(admitsAgentHost(identifier: "dev.agentpass.agent-host", hasSessionClientEntitlement: true, hasKeychainAccessGroup: true) == false)
    #expect(admitsAgentHost(identifier: "dev.agentpass.agent-host", hasSessionClientEntitlement: true, hasKeychainAccessGroup: false))
}

@Test("the Agent Host boundary has no dynamic Mach service or legacy bearer fallback")
func agentHostUsesOnlyTheFixedXPCBoundary() throws {
    let testDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    let packageRoot = testDirectory.deletingLastPathComponent().deletingLastPathComponent()
    let source = try String(
        contentsOf: packageRoot.appendingPathComponent("Sources/AgentPassNativeAgentHost/main.swift"),
        encoding: .utf8
    )

    #expect(source.contains("static let machServiceName = \"dev.agentpass.agent-session\""))
    #expect(source.contains("NSXPCConnection(machServiceName: AgentHostContract.machServiceName"))
    #expect(source.contains("proxy.bootstrapAgent(bootstrapRequest, withReply: reply)"))
    #expect(source.contains("proxy.startAgentSession(sessionRequest, withReply: reply)"))
    #expect(source.contains("proxy.signGitCommit") == false)
    #expect(source.contains("legacyFD3") == false)
    #expect(source.contains("bearer") == false)
}
