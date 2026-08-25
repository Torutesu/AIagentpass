import Testing
@testable import AgentPassNativeCore

@Suite(.serialized)
struct NativeClientCodeRequirementTests {
    @Test func derivesTheExactClientRequirementFromTheServiceAccessGroup() throws {
        let teamID = "ABCDE12345"
        let requirement = try NativeClientCodeRequirement.requirement(
            serviceAccessGroup: teamID + NativeClientCodeRequirement.serviceAccessGroupSuffix
        )
        #expect(requirement == "anchor apple generic and identifier \"dev.agentpass.native-client\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"ABCDE12345\" and entitlement[\"keychain-access-groups\"] = \"ABCDE12345.dev.agentpass.approval-keys\"")
        #expect(try NativeClientCodeRequirement.teamID(serviceAccessGroup: "ABCDE12345.dev.agentpass.service-keys") == teamID)
    }

    @Test func rejectsSubstitutedGroupsAndTeamIdentifiers() {
        for value in [
            "ABCDE12345.dev.agentpass.approval-keys",
            "abcde12345.dev.agentpass.service-keys",
            "ABCDE1234.dev.agentpass.service-keys",
            "ABCDE12345X.dev.agentpass.service-keys",
            "AAAAA11111.dev.agentpass.service-keys.extra"
        ] {
            #expect(throws: (any Error).self) { try NativeClientCodeRequirement.requirement(serviceAccessGroup: value) }
        }
        #expect(throws: (any Error).self) { try NativeClientCodeRequirement.requirement(teamID: "TEAM ID!!!") }
    }
}
