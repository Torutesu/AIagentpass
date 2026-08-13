import Foundation

/// The only activation boundaries at which the N3-E2 qualification harness may
/// inject a fault. Keep this list closed: adding a boundary requires a new
/// qualification contract and a new physical test.
public enum NativeAgentQualificationFaultPhase: String, CaseIterable, Equatable, Sendable {
  case preCloud = "pre-cloud"
  case postCloudPreLocal = "post-cloud-pre-local"
  case postActivationPreAudit = "post-activation-pre-audit"
  case postAuditPreReply = "post-audit-pre-reply"
  case auditFsync = "audit-fsync"
  case transportReply = "transport-reply"
}

/// The complete N3-E2 qualification inventory. Each scenario owns exactly one
/// injection boundary so a controller request cannot pair unrelated values.
public enum NativeAgentQualificationFaultScenario: String, CaseIterable, Equatable, Sendable {
  case preCloudKill = "pre-cloud-kill"
  case postCloudPreLocalKill = "post-cloud-pre-local-kill"
  case postActivationPreAuditKill = "post-activation-pre-audit-kill"
  case postAuditPreReplyLoss = "post-audit-pre-reply-loss"
  case auditFsyncFailure = "audit-fsync-failure"
  case transportReplyLoss = "transport-reply-loss"

  public var phase: NativeAgentQualificationFaultPhase {
    switch self {
    case .preCloudKill: .preCloud
    case .postCloudPreLocalKill: .postCloudPreLocal
    case .postActivationPreAuditKill: .postActivationPreAudit
    case .postAuditPreReplyLoss: .postAuditPreReply
    case .auditFsyncFailure: .auditFsync
    case .transportReplyLoss: .transportReply
    }
  }
}

/// A named qualification result. It deliberately has no associated data.
public enum NativeAgentQualificationFaultOutcome: String, Equatable, Sendable {
  case armed
  case injected
  case notArmed = "not-armed"
  case bindingMismatch = "binding-mismatch"
  case scenarioMismatch = "scenario-mismatch"
  case phaseMismatch = "phase-mismatch"
  case reset

  /// Compatibility vocabulary for callers that describe the successful
  /// one-shot transition as consumed or triggered.
  public static var consumed: Self { .injected }
  public static var triggered: Self { .injected }
}

public enum NativeAgentQualificationFaultControllerError: Error, Equatable, Sendable {
  case disabled
  case alreadyArmed
  case generationExhausted
  case invalidRunBinding
}

/// A release/run binding accepted by the qualification controller.
///
/// The value is opaque to the controller: it is only compared for equality.
/// The fixed representation prevents accidental use of an unbounded label or
/// an environment-derived value as the qualification authority.
public struct NativeAgentQualificationRunBinding: Equatable, Hashable, Sendable {
  private static let byteCount = 32
  private let canonicalValue: String

  public init(_ value: String) throws {
    guard Self.isCanonical(value) else {
      throw NativeAgentQualificationFaultControllerError.invalidRunBinding
    }
    canonicalValue = value
  }

  public init(rawValue value: String) throws {
    try self.init(value)
  }

  private static func isCanonical(_ value: String) -> Bool {
    guard value.utf8.count == byteCount * 2 else { return false }
    return value.utf8.allSatisfy { byte in
      (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
    }
  }
}

/// The sole stable output of the fault controller. Do not add fields here:
/// receipts may cross a qualification boundary and must remain harmless even
/// when retained by an external runner.
public struct NativeAgentQualificationFaultReceipt: Equatable, Sendable {
  public let scenario: NativeAgentQualificationFaultScenario
  public let phase: NativeAgentQualificationFaultPhase
  public let generation: UInt64
  public let outcome: NativeAgentQualificationFaultOutcome

  fileprivate init(
    scenario: NativeAgentQualificationFaultScenario,
    phase: NativeAgentQualificationFaultPhase,
    generation: UInt64,
    outcome: NativeAgentQualificationFaultOutcome
  ) {
    self.scenario = scenario
    self.phase = phase
    self.generation = generation
    self.outcome = outcome
  }
}

/// An in-memory, one-shot fault controller for qualification builds.
///
/// The controller starts disabled. A controller has one armed slot shared by
/// all its callers; arming is rejected while that slot is occupied. All state
/// transitions, including the check-and-clear in `consume`, are performed
/// while holding one non-reentrant lock. No caller-provided object is retained
/// other than the validated opaque binding and the bounded scenario label.
public final class NativeAgentQualificationFaultController: @unchecked Sendable {
  /// The generation space is intentionally finite. Exhaustion fails closed
  /// instead of wrapping and making an old receipt look current.
  public static let maximumGeneration: UInt64 = 1_000_000

  private struct ArmedFault {
    let runBinding: NativeAgentQualificationRunBinding
    let scenario: NativeAgentQualificationFaultScenario
    let phase: NativeAgentQualificationFaultPhase
    let generation: UInt64
  }

  private let lock = NSLock()
  private var enabled: Bool
  private var generation: UInt64
  private var armedFault: ArmedFault?

  public init(enabled: Bool = false) {
    self.enabled = enabled
    generation = 0
    armedFault = nil
  }

  /// Internal starting point used only to exercise the finite generation
  /// boundary without performing a million test transitions.
  internal init(enabled: Bool, startingGeneration: UInt64) throws {
    guard startingGeneration <= Self.maximumGeneration else {
      throw NativeAgentQualificationFaultControllerError.generationExhausted
    }
    self.enabled = enabled
    generation = startingGeneration
    armedFault = nil
  }

  public var isEnabled: Bool {
    lock.lock()
    defer { lock.unlock() }
    return enabled
  }

  public var isArmed: Bool {
    lock.lock()
    defer { lock.unlock() }
    return armedFault != nil
  }

  public var currentGeneration: UInt64 {
    lock.lock()
    defer { lock.unlock() }
    return generation
  }

  /// Enables qualification control. This method is intentionally not
  /// connected to the Agent protocol; a production deployment must leave
  /// the controller at its default disabled state.
  public func enable() {
    lock.lock()
    enabled = true
    lock.unlock()
  }

  /// Disables control and removes any armed transition atomically.
  public func disable() {
    lock.lock()
    enabled = false
    armedFault = nil
    lock.unlock()
  }

  /// Removes an armed transition while preserving the monotonic generation.
  /// The returned receipt is the only information about the removed slot.
  @discardableResult
  public func reset() -> NativeAgentQualificationFaultReceipt? {
    lock.lock()
    defer { lock.unlock() }
    guard let armedFault else { return nil }
    self.armedFault = nil
    return Self.receipt(for: armedFault, outcome: .reset)
  }

  /// Arms exactly one named transition for one release/run binding.
  @discardableResult
  public func arm(
    runBinding: NativeAgentQualificationRunBinding,
    scenario: NativeAgentQualificationFaultScenario
  ) throws -> NativeAgentQualificationFaultReceipt {
    lock.lock()
    defer { lock.unlock() }
    guard enabled else { throw NativeAgentQualificationFaultControllerError.disabled }
    guard armedFault == nil else {
      throw NativeAgentQualificationFaultControllerError.alreadyArmed
    }
    guard generation < Self.maximumGeneration else {
      throw NativeAgentQualificationFaultControllerError.generationExhausted
    }

    generation += 1
    let value = ArmedFault(
      runBinding: runBinding,
      scenario: scenario,
      phase: scenario.phase,
      generation: generation
    )
    armedFault = value
    return Self.receipt(for: value, outcome: .armed)
  }

  /// Attempts to consume the armed transition. Mismatches return a harmless
  /// receipt and leave the slot untouched. The matching transition clears
  /// the slot as part of the same locked operation, so it can be observed at
  /// most once even when many callers arrive concurrently.
  public func consume(
    runBinding: NativeAgentQualificationRunBinding,
    scenario: NativeAgentQualificationFaultScenario,
    phase: NativeAgentQualificationFaultPhase
  ) -> NativeAgentQualificationFaultReceipt {
    lock.lock()
    defer { lock.unlock() }

    guard let armedFault else {
      return NativeAgentQualificationFaultReceipt(
        scenario: scenario,
        phase: phase,
        generation: generation,
        outcome: .notArmed
      )
    }
    guard armedFault.runBinding == runBinding else {
      return Self.receipt(
        for: armedFault, outcome: .bindingMismatch, phase: phase, scenario: scenario)
    }
    guard armedFault.scenario == scenario else {
      return Self.receipt(
        for: armedFault, outcome: .scenarioMismatch, phase: phase, scenario: scenario)
    }
    guard armedFault.phase == phase else {
      return Self.receipt(
        for: armedFault, outcome: .phaseMismatch, phase: phase, scenario: scenario)
    }

    self.armedFault = nil
    return Self.receipt(for: armedFault, outcome: .injected)
  }

  private static func receipt(
    for armedFault: ArmedFault,
    outcome: NativeAgentQualificationFaultOutcome,
    phase: NativeAgentQualificationFaultPhase? = nil,
    scenario: NativeAgentQualificationFaultScenario? = nil
  ) -> NativeAgentQualificationFaultReceipt {
    NativeAgentQualificationFaultReceipt(
      scenario: scenario ?? armedFault.scenario,
      phase: phase ?? armedFault.phase,
      generation: armedFault.generation,
      outcome: outcome
    )
  }
}
