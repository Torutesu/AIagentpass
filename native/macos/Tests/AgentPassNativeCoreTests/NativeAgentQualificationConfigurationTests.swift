import AgentPassNativeCore
import Foundation
import Testing

@Suite("Agent qualification configuration")
struct NativeAgentQualificationConfigurationTests {
  private let now = Date(timeIntervalSince1970: 2_000_000_000)
  private let digest = String(repeating: "a", count: 64)
  private let serviceAccessGroup = "ABCDE12345.dev.agentpass.service-keys"

  private func make(
    mode: String? = NativeAgentQualificationConfiguration.modeMarker,
    machServiceName: String? = NativeAgentQualificationConfiguration.machServiceName,
    candidateDigest: String? = nil,
    sourceCommitDigest: String? = nil,
    codeIdentityDigest: String? = nil,
    runBindingDigest: String? = nil,
    controllerServiceAccessGroup: String? = nil,
    expiresAtEpochSeconds: UInt64? = nil,
    scenario: NativeAgentQualificationFaultScenario? = nil,
    phase: NativeAgentQualificationFaultPhase? = nil
  ) throws -> NativeAgentQualificationConfiguration {
    try NativeAgentQualificationConfiguration(
      mode: mode,
      machServiceName: machServiceName,
      candidateDigest: candidateDigest ?? digest,
      sourceCommitDigest: sourceCommitDigest ?? digest,
      codeIdentityDigest: codeIdentityDigest ?? digest,
      runBindingDigest: runBindingDigest ?? digest,
      controllerServiceAccessGroup: controllerServiceAccessGroup ?? serviceAccessGroup,
      expiresAtEpochSeconds:
        expiresAtEpochSeconds ?? UInt64(now.timeIntervalSince1970) + 60,
      scenario: scenario ?? .preCloudKill,
      phase: phase ?? .preCloud,
      wallTime: now
    )
  }

  @Test("all absent fields produce the disabled state")
  func disabledState() throws {
    let value = try NativeAgentQualificationConfiguration(wallTime: now)
    #expect(value == .disabled)
    #expect(!value.isConfigured)
    #expect(value.values == nil)
  }

  @Test("partial configuration is rejected")
  func rejectsPartialConfiguration() {
    #expect(throws: NativeAgentQualificationConfigurationError.partialConfiguration) {
      _ = try NativeAgentQualificationConfiguration(
        mode: NativeAgentQualificationConfiguration.modeMarker,
        wallTime: now
      )
    }
  }

  @Test("mode and Mach service are fixed")
  func rejectsWrongModeAndService() {
    #expect(throws: NativeAgentQualificationConfigurationError.invalidMode) {
      _ = try make(mode: "qualification")
    }
    #expect(throws: NativeAgentQualificationConfigurationError.invalidMachService) {
      _ = try make(machServiceName: "dev.agentpass.native-service")
    }
  }

  @Test("digests require 64 lowercase hexadecimal non-zero characters")
  func rejectsNonCanonicalDigests() {
    #expect(
      throws: NativeAgentQualificationConfigurationError.invalidDigest(field: "candidateDigest")
    ) {
      _ = try make(candidateDigest: String(repeating: "A", count: 64))
    }
    #expect(
      throws: NativeAgentQualificationConfigurationError.invalidDigest(field: "sourceCommitDigest")
    ) {
      _ = try make(sourceCommitDigest: String(repeating: "g", count: 64))
    }
    #expect(
      throws: NativeAgentQualificationConfigurationError.invalidDigest(field: "codeIdentityDigest")
    ) {
      _ = try make(codeIdentityDigest: String(repeating: "a", count: 63))
    }
    #expect(
      throws: NativeAgentQualificationConfigurationError.zeroDigest(field: "runBindingDigest")
    ) {
      _ = try make(runBindingDigest: String(repeating: "0", count: 64))
    }
  }

  @Test("expiry is validated against the injected wall clock and bounded")
  func rejectsStaleAndOverlongExpiry() throws {
    let current = UInt64(now.timeIntervalSince1970)
    #expect(throws: NativeAgentQualificationConfigurationError.expired) {
      _ = try make(expiresAtEpochSeconds: current)
    }
    #expect(throws: NativeAgentQualificationConfigurationError.expired) {
      _ = try make(expiresAtEpochSeconds: current - 1)
    }
    #expect(throws: NativeAgentQualificationConfigurationError.expiryTooFarInFuture) {
      _ = try make(
        expiresAtEpochSeconds: current
          + NativeAgentQualificationConfiguration.maximumLifetimeSeconds + 1)
    }
    let boundary = try make(
      expiresAtEpochSeconds: current + NativeAgentQualificationConfiguration.maximumLifetimeSeconds)
    #expect(boundary.isConfigured)
  }

  @Test("the controller requirement is derived from the fixed service group")
  func derivesControllerRequirement() throws {
    let value = try make()
    let configured = try #require(value.values)
    let expectedRequirement = try NativeAgentQualificationCodeRequirement.requirement(
      serviceAccessGroup: serviceAccessGroup)
    #expect(configured.controllerDesignatedRequirement == expectedRequirement)
    #expect(throws: NativeAgentQualificationConfigurationError.invalidControllerServiceAccessGroup)
    {
      _ = try make(controllerServiceAccessGroup: "ABCDE12345.dev.agentpass.approval-keys")
    }
  }

  @Test("all six scenario and phase pairs are closed and exact")
  func acceptsOnlyMatchingPairs() throws {
    for scenario in NativeAgentQualificationFaultScenario.allCases {
      let value = try make(scenario: scenario, phase: scenario.phase)
      #expect(value.values?.scenario == scenario)
      #expect(value.values?.phase == scenario.phase)
    }

    #expect(
      throws: NativeAgentQualificationConfigurationError.invalidPhaseScenarioPair
    ) {
      _ = try make(scenario: .preCloudKill, phase: .transportReply)
    }
  }

  @Test("valid configuration exposes only bounded qualification metadata")
  func acceptsValidConfiguration() throws {
    let value = try make()
    let configured = try #require(value.values)
    #expect(configured.mode.rawValue == NativeAgentQualificationConfiguration.modeMarker)
    #expect(configured.machServiceName == NativeAgentQualificationConfiguration.machServiceName)
    #expect(configured.candidateDigest == digest)
    #expect(configured.expiresAtEpochSeconds == UInt64(now.timeIntervalSince1970) + 60)
    #expect(configured.scenario == .preCloudKill)
    #expect(configured.phase == .preCloud)
  }
}
