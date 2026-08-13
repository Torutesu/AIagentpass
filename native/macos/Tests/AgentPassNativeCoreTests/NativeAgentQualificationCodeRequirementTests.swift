import AgentPassNativeCore
import Foundation
import Testing

@Suite("Agent qualification code requirement")
struct NativeAgentQualificationCodeRequirementTests {
  private let cdhash = String(repeating: "a", count: 40)

  @Test("pins a distinct Developer ID controller and dedicated entitlement")
  func exactRequirement() throws {
    let value = try NativeAgentQualificationCodeRequirement.requirement(
      teamID: "ABCDE12345", controllerCodeDirectoryHash: cdhash)
    #expect(value.contains("anchor apple generic"))
    #expect(value.contains("identifier \"dev.agentpass.qualification-controller\""))
    #expect(value.contains("certificate leaf[field.1.2.840.113635.100.6.1.13] exists"))
    #expect(value.contains("certificate leaf[subject.OU] = \"ABCDE12345\""))
    #expect(value.contains("entitlement[\"dev.agentpass.qualification-control\"] exists"))
    #expect(value.contains("cdhash H\"\(cdhash)\""))
    #expect(!value.contains(NativeAgentCodeRequirement.hostBundleID))
    #expect(!value.contains(NativeAgentCodeRequirement.clientEntitlement))
  }

  @Test("derives the Team ID only from the fixed service access group")
  func derivesTeamID() throws {
    #expect(
      try NativeAgentQualificationCodeRequirement.requirement(
        serviceAccessGroup: "ABCDE12345.dev.agentpass.service-keys",
        controllerCodeDirectoryHash: cdhash)
        == NativeAgentQualificationCodeRequirement.requirement(
          teamID: "ABCDE12345", controllerCodeDirectoryHash: cdhash))
    #expect(throws: Error.self) {
      _ = try NativeAgentQualificationCodeRequirement.requirement(
        serviceAccessGroup: "ABCDE12345.dev.agentpass.approval-keys",
        controllerCodeDirectoryHash: cdhash)
    }
  }

  @Test("rejects malformed Team IDs")
  func rejectsMalformedTeamID() {
    for value in ["", "short", "abcde12345", "ABCDE1234-", "ABCDE123456"] {
      #expect(throws: Error.self) {
        _ = try NativeAgentQualificationCodeRequirement.requirement(
          teamID: value, controllerCodeDirectoryHash: cdhash)
      }
    }
  }

  @Test("rejects malformed CodeDirectory hashes")
  func rejectsMalformedCodeDirectoryHash() {
    for value in ["", String(repeating: "a", count: 39), String(repeating: "a", count: 41), String(repeating: "A", count: 40), String(repeating: "g", count: 40), String(repeating: "0", count: 40)] {
      #expect(throws: Error.self) {
        _ = try NativeAgentQualificationCodeRequirement.requirement(
          teamID: "ABCDE12345", controllerCodeDirectoryHash: value)
      }
    }
  }

  @Test("Apple requirement parser accepts the exact controller requirement")
  func appleParserAcceptsRequirement() throws {
    let requirement = try NativeAgentQualificationCodeRequirement.requirement(
      teamID: "ABCDE12345", controllerCodeDirectoryHash: cdhash)
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
      "agentpass-controller-csreq-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: directory) }
    let output = directory.appendingPathComponent("controller.csreq")
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/csreq")
    process.arguments = ["-r=\(requirement)", "-b", output.path]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    process.waitUntilExit()
    #expect(process.terminationStatus == 0)
    let attributes = try FileManager.default.attributesOfItem(atPath: output.path)
    #expect((attributes[.size] as? NSNumber)?.intValue ?? 0 > 0)
  }
}
