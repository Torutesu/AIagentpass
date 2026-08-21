import Foundation
import Testing

@testable import AgentPassNativeCore

private let runtimeOrigin = URL(string: "https://api.agentpass.test")!
private let runtimeOrganization = "11111111-1111-4111-8111-111111111111"
private let runtimeDevice = "22222222-2222-4222-8222-222222222222"
private let runtimeCapabilityPublicKeyPEM = """
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA6tOzXpegx8uirXcRscbgSA9jsm/JG0Odtv7b56m0pxw=
-----END PUBLIC KEY-----
"""
private let runtimeCapabilityKeyID = "capability-v1"

private func runtimeConfiguration(
  origin: URL? = runtimeOrigin,
  organizationID: String? = runtimeOrganization,
  deviceID: String? = runtimeDevice,
  deviceKeyTag: String? = NativeEnrollmentKeyMaterial.fixedApplicationTag,
  intentDirectory: String? = "/Library/Application Support/AgentPass/agent-signing-intents",
  globalLimit: Int? = 128,
  perAgentLimit: Int? = 8,
  perWorktreeLimit: Int? = 4,
  bootstrapLimit: Int? = 16,
  observationPolicy: Int? = 2,
  capabilityPublicKeyPEM: String? = runtimeCapabilityPublicKeyPEM,
  capabilityKeyID: String? = runtimeCapabilityKeyID
) throws -> NativeAgentRuntimeConfiguration {
  try NativeAgentRuntimeConfiguration(
    deviceAPIOrigin: origin,
    organizationID: organizationID,
    deviceID: deviceID,
    deviceKeyTag: deviceKeyTag,
    signingIntentDirectory: intentDirectory,
    globalSessionLimit: globalLimit,
    perAgentSessionLimit: perAgentLimit,
    perWorktreeSessionLimit: perWorktreeLimit,
    bootstrapAttemptLimit: bootstrapLimit,
    worktreeObservationPolicyVersion: observationPolicy,
    capabilityPublicKeyPEM: capabilityPublicKeyPEM,
    capabilityKeyID: capabilityKeyID
  )
}

@Test func agentRuntimeConfigurationIsExplicitlyDisabledOnlyWhenEveryFieldIsAbsent() throws {
  let disabled = try runtimeConfiguration(
    origin: nil, organizationID: nil, deviceID: nil, deviceKeyTag: nil,
    intentDirectory: nil, globalLimit: nil, perAgentLimit: nil, perWorktreeLimit: nil,
    bootstrapLimit: nil, observationPolicy: nil,
    capabilityPublicKeyPEM: nil, capabilityKeyID: nil
  )
  #expect(disabled == .disabled)
  #expect(disabled.authority == nil)

  #expect(throws: NativeAgentRuntimeConfigurationError.incomplete) {
    _ = try runtimeConfiguration(deviceID: nil)
  }
}

@Test func agentRuntimeConfigurationNormalizesOneCompleteImmutableAuthority() throws {
  let authority = try #require(runtimeConfiguration().authority)
  #expect(authority.deviceAPIOrigin.absoluteString == "https://api.agentpass.test/")
  #expect(authority.organizationID == runtimeOrganization)
  #expect(authority.deviceID == runtimeDevice)
  #expect(authority.deviceKeyTag == NativeEnrollmentKeyMaterial.fixedApplicationTag)
  #expect(authority.capabilityPublicKeyPEM == runtimeCapabilityPublicKeyPEM)
  #expect(authority.capabilityKeyID == runtimeCapabilityKeyID)
  #expect(authority.globalSessionLimit == 128)
  #expect(authority.perAgentSessionLimit == 8)
  #expect(authority.perWorktreeSessionLimit == 4)
  #expect(authority.bootstrapAttemptLimit == 16)
  #expect(authority.worktreeObservationPolicy == .v2)
}

@Test func agentRuntimeConfigurationRequiresCompleteCapabilityTrust() throws {
  #expect(throws: NativeAgentRuntimeConfigurationError.incomplete) {
    _ = try runtimeConfiguration(capabilityPublicKeyPEM: nil)
  }
  #expect(throws: NativeAgentRuntimeConfigurationError.incomplete) {
    _ = try runtimeConfiguration(capabilityKeyID: nil)
  }
  #expect(throws: NativeAgentRuntimeConfigurationError.invalidCapabilityKey) {
    _ = try runtimeConfiguration(capabilityPublicKeyPEM: "not-a-public-key")
  }
  for value in ["", "-capability", "capability key", String(repeating: "a", count: 129)] {
    #expect(throws: NativeAgentRuntimeConfigurationError.invalidCapabilityKeyID) {
      _ = try runtimeConfiguration(capabilityKeyID: value)
    }
  }
}

@Test func agentRuntimeConfigurationRejectsUnsafeOriginsAndIdentities() throws {
  for text in [
    "http://api.agentpass.test", "https://user@api.agentpass.test",
    "https://api.agentpass.test/v1", "https://api.agentpass.test/?token=x",
    "https://api.agentpass.test/#fragment",
  ] {
    #expect(throws: NativeAgentRuntimeConfigurationError.invalidOrigin) {
      _ = try runtimeConfiguration(origin: URL(string: text)!)
    }
  }
  for value in [
    "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", "not-a-uuid",
    "00000000-0000-0000-0000-000000000000",
  ] {
    #expect(throws: NativeAgentRuntimeConfigurationError.invalidIdentity) {
      _ = try runtimeConfiguration(organizationID: value)
    }
  }
}

@Test func agentRuntimeConfigurationRejectsKeyPathLimitAndPolicySubstitution() throws {
  #expect(throws: NativeAgentRuntimeConfigurationError.invalidDeviceKey) {
    _ = try runtimeConfiguration(deviceKeyTag: "dev.agentpass.git-signing")
  }
  for path in ["relative", "/", "/private/../tmp", "/private/tmp/"] {
    #expect(throws: NativeAgentRuntimeConfigurationError.invalidPath) {
      _ = try runtimeConfiguration(intentDirectory: path)
    }
  }
  for limits in [(0, 1, 1, 1), (2, 3, 1, 1), (2, 1, 3, 1), (2, 1, 1, 0), (1_025, 1, 1, 1)] {
    #expect(throws: NativeAgentRuntimeConfigurationError.invalidLimit) {
      _ = try runtimeConfiguration(
        globalLimit: limits.0, perAgentLimit: limits.1,
        perWorktreeLimit: limits.2, bootstrapLimit: limits.3
      )
    }
  }
  #expect(throws: NativeAgentRuntimeConfigurationError.unsupportedObservationPolicy) {
    _ = try runtimeConfiguration(observationPolicy: 1)
  }
}
