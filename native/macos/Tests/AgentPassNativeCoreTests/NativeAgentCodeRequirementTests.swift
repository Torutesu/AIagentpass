import AgentPassNativeCore
import Testing

@Test func agentHostRequirementUsesADistinctFixedPrincipal() throws {
    let value = try NativeAgentCodeRequirement.requirement(teamID: "ABCDE12345")
    #expect(value.contains("identifier \"dev.agentpass.agent-host\""))
    #expect(value.contains("entitlement[\"dev.agentpass.agent-session-client\"] = true"))
    #expect(value.contains("certificate leaf[subject.OU] = \"ABCDE12345\""))
    #expect(!value.contains(NativeClientCodeRequirement.clientBundleID))
    #expect(value != (try NativeClientCodeRequirement.requirement(teamID: "ABCDE12345")))
}

@Test func agentHostRequirementRejectsUnboundedTeamIdentity() {
    #expect(throws: (any Error).self) {
        _ = try NativeAgentCodeRequirement.requirement(teamID: "team-id")
    }
}
