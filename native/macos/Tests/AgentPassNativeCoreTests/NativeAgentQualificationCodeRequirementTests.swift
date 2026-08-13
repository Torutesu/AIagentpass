import AgentPassNativeCore
import Testing

@Suite("Agent qualification code requirement")
struct NativeAgentQualificationCodeRequirementTests {
  @Test("pins a distinct Developer ID controller and dedicated entitlement")
  func exactRequirement() throws {
    let value = try NativeAgentQualificationCodeRequirement.requirement(teamID: "ABCDE12345")
    #expect(value.contains("anchor apple generic"))
    #expect(value.contains("identifier \"dev.agentpass.qualification-controller\""))
    #expect(value.contains("certificate leaf[field.1.2.840.113635.100.6.1.13] exists"))
    #expect(value.contains("certificate leaf[subject.OU] = \"ABCDE12345\""))
    #expect(value.contains("entitlement[\"dev.agentpass.qualification-control\"] = true"))
    #expect(!value.contains(NativeAgentCodeRequirement.hostBundleID))
    #expect(!value.contains(NativeAgentCodeRequirement.clientEntitlement))
  }

  @Test("derives the Team ID only from the fixed service access group")
  func derivesTeamID() throws {
    #expect(
      try NativeAgentQualificationCodeRequirement.requirement(
        serviceAccessGroup: "ABCDE12345.dev.agentpass.service-keys")
        == NativeAgentQualificationCodeRequirement.requirement(teamID: "ABCDE12345"))
    #expect(throws: Error.self) {
      _ = try NativeAgentQualificationCodeRequirement.requirement(
        serviceAccessGroup: "ABCDE12345.dev.agentpass.approval-keys")
    }
  }

  @Test("rejects malformed Team IDs")
  func rejectsMalformedTeamID() {
    for value in ["", "short", "abcde12345", "ABCDE1234-", "ABCDE123456"] {
      #expect(throws: Error.self) {
        _ = try NativeAgentQualificationCodeRequirement.requirement(teamID: value)
      }
    }
  }
}
