import Foundation

public enum NativeAgentRuntimeConfigurationError: String, Error, Equatable, Sendable {
  case incomplete = "incomplete"
  case invalidOrigin = "invalid_origin"
  case invalidIdentity = "invalid_identity"
  case invalidDeviceKey = "invalid_device_key"
  case invalidPath = "invalid_path"
  case invalidLimit = "invalid_limit"
  case unsupportedObservationPolicy = "unsupported_observation_policy"
}

public enum NativeAgentWorktreeObservationPolicyVersion: Int, CaseIterable, Sendable {
  case v2 = 2
}

/// The complete immutable authority needed to construct the production Agent
/// runtime. It contains no repository path, bearer token, Grant, private key,
/// or test-observation switch.
public struct NativeAgentRuntimeAuthorityConfiguration: Equatable, Sendable {
  public let deviceAPIOrigin: URL
  public let organizationID: String
  public let deviceID: String
  public let deviceKeyTag: String
  public let signingIntentDirectory: String
  public let globalSessionLimit: Int
  public let perAgentSessionLimit: Int
  public let perWorktreeSessionLimit: Int
  public let bootstrapAttemptLimit: Int
  public let worktreeObservationPolicy: NativeAgentWorktreeObservationPolicyVersion

  fileprivate init(
    deviceAPIOrigin: URL,
    organizationID: String,
    deviceID: String,
    deviceKeyTag: String,
    signingIntentDirectory: String,
    globalSessionLimit: Int,
    perAgentSessionLimit: Int,
    perWorktreeSessionLimit: Int,
    bootstrapAttemptLimit: Int,
    worktreeObservationPolicy: NativeAgentWorktreeObservationPolicyVersion
  ) {
    self.deviceAPIOrigin = deviceAPIOrigin
    self.organizationID = organizationID
    self.deviceID = deviceID
    self.deviceKeyTag = deviceKeyTag
    self.signingIntentDirectory = signingIntentDirectory
    self.globalSessionLimit = globalSessionLimit
    self.perAgentSessionLimit = perAgentSessionLimit
    self.perWorktreeSessionLimit = perWorktreeSessionLimit
    self.bootstrapAttemptLimit = bootstrapAttemptLimit
    self.worktreeObservationPolicy = worktreeObservationPolicy
  }
}

/// All Agent authority is either absent or complete. Optional fields are
/// accepted only at the service-configuration boundary so a partial runtime
/// cannot be represented after this initializer returns.
public enum NativeAgentRuntimeConfiguration: Equatable, Sendable {
  case disabled
  case enabled(NativeAgentRuntimeAuthorityConfiguration)

  public init(
    deviceAPIOrigin: URL?,
    organizationID: String?,
    deviceID: String?,
    deviceKeyTag: String?,
    signingIntentDirectory: String?,
    globalSessionLimit: Int?,
    perAgentSessionLimit: Int?,
    perWorktreeSessionLimit: Int?,
    bootstrapAttemptLimit: Int?,
    worktreeObservationPolicyVersion: Int?
  ) throws {
    let presence = [
      deviceAPIOrigin != nil,
      organizationID != nil,
      deviceID != nil,
      deviceKeyTag != nil,
      signingIntentDirectory != nil,
      globalSessionLimit != nil,
      perAgentSessionLimit != nil,
      perWorktreeSessionLimit != nil,
      bootstrapAttemptLimit != nil,
      worktreeObservationPolicyVersion != nil,
    ]
    if !presence.contains(true) {
      self = .disabled
      return
    }
    guard presence.allSatisfy({ $0 }),
      let rawOrigin = deviceAPIOrigin,
      let rawOrganizationID = organizationID,
      let rawDeviceID = deviceID,
      let rawDeviceKeyTag = deviceKeyTag,
      let rawIntentDirectory = signingIntentDirectory,
      let rawGlobalLimit = globalSessionLimit,
      let rawPerAgentLimit = perAgentSessionLimit,
      let rawPerWorktreeLimit = perWorktreeSessionLimit,
      let rawBootstrapLimit = bootstrapAttemptLimit,
      let rawObservationPolicy = worktreeObservationPolicyVersion
    else {
      throw NativeAgentRuntimeConfigurationError.incomplete
    }

    let origin = try Self.origin(rawOrigin)
    let normalizedOrganizationID = try Self.uuid(rawOrganizationID)
    let normalizedDeviceID = try Self.uuid(rawDeviceID)
    guard rawDeviceKeyTag == NativeEnrollmentKeyMaterial.fixedApplicationTag else {
      throw NativeAgentRuntimeConfigurationError.invalidDeviceKey
    }
    let intentDirectory = try Self.directory(rawIntentDirectory)
    guard (1...NativeAgentSessionRegistry.maximumActiveSessions).contains(rawGlobalLimit),
      (1...rawGlobalLimit).contains(rawPerAgentLimit),
      (1...rawGlobalLimit).contains(rawPerWorktreeLimit),
      (1...64).contains(rawBootstrapLimit)
    else {
      throw NativeAgentRuntimeConfigurationError.invalidLimit
    }
    guard
      let observationPolicy = NativeAgentWorktreeObservationPolicyVersion(
        rawValue: rawObservationPolicy)
    else {
      throw NativeAgentRuntimeConfigurationError.unsupportedObservationPolicy
    }

    self = .enabled(
      NativeAgentRuntimeAuthorityConfiguration(
        deviceAPIOrigin: origin,
        organizationID: normalizedOrganizationID,
        deviceID: normalizedDeviceID,
        deviceKeyTag: rawDeviceKeyTag,
        signingIntentDirectory: intentDirectory,
        globalSessionLimit: rawGlobalLimit,
        perAgentSessionLimit: rawPerAgentLimit,
        perWorktreeSessionLimit: rawPerWorktreeLimit,
        bootstrapAttemptLimit: rawBootstrapLimit,
        worktreeObservationPolicy: observationPolicy
      )
    )
  }

  public var authority: NativeAgentRuntimeAuthorityConfiguration? {
    guard case .enabled(let authority) = self else { return nil }
    return authority
  }

  private static func origin(_ value: URL) throws -> URL {
    guard let components = URLComponents(url: value, resolvingAgainstBaseURL: false),
      components.scheme == "https",
      components.host?.isEmpty == false,
      components.user == nil,
      components.password == nil,
      components.query == nil,
      components.fragment == nil,
      components.path.isEmpty || components.path == "/"
    else {
      throw NativeAgentRuntimeConfigurationError.invalidOrigin
    }
    var normalized = components
    normalized.path = "/"
    guard let result = normalized.url,
      result.scheme == "https",
      result.host == value.host,
      result.port == value.port
    else {
      throw NativeAgentRuntimeConfigurationError.invalidOrigin
    }
    return result
  }

  private static func uuid(_ value: String) throws -> String {
    guard
      value.range(
        of: "^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        options: .regularExpression
      ) != nil,
      UUID(uuidString: value)?.uuidString.lowercased() == value
    else {
      throw NativeAgentRuntimeConfigurationError.invalidIdentity
    }
    return value
  }

  private static func directory(_ value: String) throws -> String {
    guard value.hasPrefix("/"), value != "/", value.utf8.count <= 1_024,
      !value.hasSuffix("/"),
      URL(fileURLWithPath: value, isDirectory: true).standardizedFileURL.path == value,
      !value.split(separator: "/", omittingEmptySubsequences: false).contains(where: {
        $0 == "." || $0 == ".."
      })
    else {
      throw NativeAgentRuntimeConfigurationError.invalidPath
    }
    return value
  }
}
