import Foundation

/// The only mode in which the qualification control plane may be enabled.
/// This marker is intentionally fixed; it is not a feature flag that callers
/// can rename or extend.
public enum NativeAgentQualificationMode: String, CaseIterable, Equatable, Sendable {
  case qualification = "n3e-qualification"
}

public enum NativeAgentQualificationConfigurationError: Error, Equatable, Sendable {
  case partialConfiguration
  case invalidMode
  case invalidMachService
  case invalidDigest(field: String)
  case zeroDigest(field: String)
  case invalidControllerServiceAccessGroup
  case invalidControllerCodeDirectoryHash
  case invalidWallTime
  case expired
  case expiryTooFarInFuture
  case invalidPhaseScenarioPair
}

/// The validated, bounded configuration for the qualification-only control
/// plane. The default value is disabled. A configured value can be created
/// only by supplying every field in the block; a partially populated block is
/// rejected instead of being interpreted as disabled.
public struct NativeAgentQualificationConfiguration: Equatable, Sendable {
  public static let machServiceName = AgentPassQualificationXPCContract.machServiceName
  public static let modeMarker = NativeAgentQualificationMode.qualification.rawValue

  /// Qualification control is deliberately short-lived. The expiry is stored
  /// as an unsigned whole Unix second, while the validation clock is injected
  /// as a `Date` so callers and tests cannot silently use a second clock.
  public static let maximumLifetimeSeconds: UInt64 = 15 * 60

  public enum State: Equatable, Sendable {
    case disabled
    case configured(Values)
  }

  /// All fields in this value are bounded, non-secret identity metadata. The
  /// controller requirement is derived during construction and cannot be
  /// supplied as free-form configuration text.
  public struct Values: Equatable, Sendable {
    public let mode: NativeAgentQualificationMode
    public let machServiceName: String
    public let candidateDigest: String
    public let sourceCommitDigest: String
    public let codeIdentityDigest: String
    public let runBindingDigest: String
    public let controllerDesignatedRequirement: String
    public let expiresAtEpochSeconds: UInt64
    public let scenario: NativeAgentQualificationFaultScenario
    public let phase: NativeAgentQualificationFaultPhase

    fileprivate init(
      mode: NativeAgentQualificationMode,
      machServiceName: String,
      candidateDigest: String,
      sourceCommitDigest: String,
      codeIdentityDigest: String,
      runBindingDigest: String,
      controllerDesignatedRequirement: String,
      expiresAtEpochSeconds: UInt64,
      scenario: NativeAgentQualificationFaultScenario,
      phase: NativeAgentQualificationFaultPhase
    ) {
      self.mode = mode
      self.machServiceName = machServiceName
      self.candidateDigest = candidateDigest
      self.sourceCommitDigest = sourceCommitDigest
      self.codeIdentityDigest = codeIdentityDigest
      self.runBindingDigest = runBindingDigest
      self.controllerDesignatedRequirement = controllerDesignatedRequirement
      self.expiresAtEpochSeconds = expiresAtEpochSeconds
      self.scenario = scenario
      self.phase = phase
    }
  }

  public let state: State

  public var isConfigured: Bool {
    if case .configured = state { return true }
    return false
  }

  public var values: Values? {
    guard case .configured(let values) = state else { return nil }
    return values
  }

  public static let disabled = Self(state: .disabled)

  private init(state: State) {
    self.state = state
  }

  /// Creates either the completely disabled state (when every configuration
  /// field is absent) or one complete, validated configured state.
  ///
  /// `controllerServiceAccessGroup` is the only controller identity input.
  /// Its Team ID is validated and the exact designated requirement is derived
  /// through `NativeAgentQualificationCodeRequirement`; no caller-provided
  /// requirement string is accepted.
  public init(
    mode: String? = nil,
    machServiceName: String? = nil,
    candidateDigest: String? = nil,
    sourceCommitDigest: String? = nil,
    codeIdentityDigest: String? = nil,
    runBindingDigest: String? = nil,
    controllerServiceAccessGroup: String? = nil,
    controllerCodeDirectoryHash: String? = nil,
    expiresAtEpochSeconds: UInt64? = nil,
    scenario: NativeAgentQualificationFaultScenario? = nil,
    phase: NativeAgentQualificationFaultPhase? = nil,
    wallTime: Date = Date()
  ) throws {
    let supplied = [
      mode != nil,
      machServiceName != nil,
      candidateDigest != nil,
      sourceCommitDigest != nil,
      codeIdentityDigest != nil,
      runBindingDigest != nil,
      controllerServiceAccessGroup != nil,
      controllerCodeDirectoryHash != nil,
      expiresAtEpochSeconds != nil,
      scenario != nil,
      phase != nil,
    ]

    guard supplied.contains(true) else {
      self.state = .disabled
      return
    }
    guard supplied.allSatisfy({ $0 }) else {
      throw NativeAgentQualificationConfigurationError.partialConfiguration
    }

    guard let mode, mode == Self.modeMarker else {
      throw NativeAgentQualificationConfigurationError.invalidMode
    }
    guard let machServiceName, machServiceName == Self.machServiceName else {
      throw NativeAgentQualificationConfigurationError.invalidMachService
    }
    guard let mode = NativeAgentQualificationMode(rawValue: mode),
      let candidateDigest,
      let sourceCommitDigest,
      let codeIdentityDigest,
      let runBindingDigest,
      let controllerServiceAccessGroup,
      let controllerCodeDirectoryHash,
      let expiresAtEpochSeconds,
      let scenario,
      let phase
    else {
      // The all-or-none guard above makes this unreachable. Keep it explicit
      // so a future field addition cannot turn a missing value into authority.
      throw NativeAgentQualificationConfigurationError.partialConfiguration
    }

    try Self.validateDigest(candidateDigest, field: "candidateDigest")
    try Self.validateDigest(sourceCommitDigest, field: "sourceCommitDigest")
    try Self.validateDigest(codeIdentityDigest, field: "codeIdentityDigest")
    try Self.validateDigest(runBindingDigest, field: "runBindingDigest")

    guard Self.isClosedPair(scenario: scenario, phase: phase) else {
      throw NativeAgentQualificationConfigurationError.invalidPhaseScenarioPair
    }

    guard wallTime.timeIntervalSince1970.isFinite,
      wallTime.timeIntervalSince1970 >= 0,
      Double(expiresAtEpochSeconds).isFinite
    else {
      throw NativeAgentQualificationConfigurationError.invalidWallTime
    }

    let now = wallTime.timeIntervalSince1970
    let expiry = Double(expiresAtEpochSeconds)
    guard expiry > now else {
      throw NativeAgentQualificationConfigurationError.expired
    }
    guard expiry - now <= Double(Self.maximumLifetimeSeconds) else {
      throw NativeAgentQualificationConfigurationError.expiryTooFarInFuture
    }

    let controllerRequirement: String
    do {
      controllerRequirement = try NativeAgentQualificationCodeRequirement.requirement(
        serviceAccessGroup: controllerServiceAccessGroup,
        controllerCodeDirectoryHash: controllerCodeDirectoryHash)
    } catch {
      if (try? NativeClientCodeRequirement.teamID(
        serviceAccessGroup: controllerServiceAccessGroup)) == nil
      {
        throw NativeAgentQualificationConfigurationError.invalidControllerServiceAccessGroup
      }
      throw NativeAgentQualificationConfigurationError.invalidControllerCodeDirectoryHash
    }

    self.state = .configured(
      Values(
        mode: mode,
        machServiceName: machServiceName,
        candidateDigest: candidateDigest,
        sourceCommitDigest: sourceCommitDigest,
        codeIdentityDigest: codeIdentityDigest,
        runBindingDigest: runBindingDigest,
        controllerDesignatedRequirement: controllerRequirement,
        expiresAtEpochSeconds: expiresAtEpochSeconds,
        scenario: scenario,
        phase: phase
      ))
  }

  private static func validateDigest(_ value: String, field: String) throws {
    guard value.utf8.count == 64 else {
      throw NativeAgentQualificationConfigurationError.invalidDigest(field: field)
    }
    guard
      value.utf8.allSatisfy({ byte in
        (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
      })
    else {
      throw NativeAgentQualificationConfigurationError.invalidDigest(field: field)
    }
    guard value.utf8.contains(where: { $0 != 48 }) else {
      throw NativeAgentQualificationConfigurationError.zeroDigest(field: field)
    }
  }

  /// Keep the qualification inventory closed at this boundary even if a
  /// different caller later adds a case to the controller's enum.
  private static func isClosedPair(
    scenario: NativeAgentQualificationFaultScenario,
    phase: NativeAgentQualificationFaultPhase
  ) -> Bool {
    switch (scenario, phase) {
    case (.preCloudKill, .preCloud),
      (.postCloudPreLocalKill, .postCloudPreLocal),
      (.postActivationPreAuditKill, .postActivationPreAudit),
      (.postAuditPreReplyLoss, .postAuditPreReply),
      (.auditFsyncFailure, .auditFsync),
      (.transportReplyLoss, .transportReply):
      return true
    default:
      return false
    }
  }
}
