import AgentPassNativeCore
import CryptoKit
import Foundation

/// The stable error vocabulary for the qualification bridge.
///
/// No request-derived value is placed in an NSError. This is intentionally a
/// separate domain from the production Agent session denial vocabulary.
public enum NativeAgentQualificationEndpointError: Int, Error, Equatable, Sendable {
  case invalidated = 2001
  case disabled = 2002
  case bindingMismatch = 2003
  case invalidPhase = 2004
  case alreadyArmed = 2005
  case wrongReceipt = 2006
  case generationExhausted = 2007
  case expired = 2008
  case internalFailure = 2099

  public static let errorDomain = "dev.agentpass.qualification-endpoint"
  public static let reasonCodeUserInfoKey = "AgentPassQualificationReasonCode"

  public var message: String {
    switch self {
    case .invalidated: return "The qualification endpoint is invalidated."
    case .disabled: return "Qualification control is disabled."
    case .bindingMismatch: return "The qualification binding is not accepted."
    case .invalidPhase: return "The qualification phase is not accepted."
    case .alreadyArmed: return "A qualification fault is already armed."
    case .wrongReceipt: return "The qualification receipt is not accepted."
    case .generationExhausted: return "Qualification control is unavailable."
    case .expired: return "Qualification control has expired."
    case .internalFailure: return "Qualification control is unavailable."
    }
  }

  public var nsError: NSError {
    NSError(
      domain: Self.errorDomain,
      code: rawValue,
      userInfo: [
        NSLocalizedDescriptionKey: message,
        Self.reasonCodeUserInfoKey: NSNumber(value: rawValue),
      ])
  }
}

/// Immutable release/run values used by one qualification endpoint instance.
///
/// The run binding is retained only for the in-process controller comparison;
/// only its separately supplied digest is accepted by the XPC DTOs and
/// returned in responses.
public struct NativeAgentQualificationEndpointConfiguration: Equatable, Sendable {
  public let candidateDigest: Data
  public let sourceCommitDigest: Data
  public let codeIdentityDigest: Data
  public let runIDDigest: Data
  public let runBinding: NativeAgentQualificationRunBinding
  public let expiresAtEpochSeconds: UInt64
  public let scenario: NativeAgentQualificationFaultScenario
  public let phase: NativeAgentQualificationFaultPhase

  public init(values: NativeAgentQualificationConfiguration.Values) throws {
    guard let candidateDigest = Self.data(hex: values.candidateDigest),
      let sourceCommitDigest = Self.data(hex: values.sourceCommitDigest),
      let codeIdentityDigest = Self.data(hex: values.codeIdentityDigest),
      let runIDDigest = Self.data(hex: values.runBindingDigest)
    else { throw NativeAgentQualificationEndpointError.bindingMismatch }
    guard AgentPassQualificationXPCContract.isDigest(candidateDigest),
      AgentPassQualificationXPCContract.isDigest(sourceCommitDigest),
      AgentPassQualificationXPCContract.isDigest(codeIdentityDigest),
      AgentPassQualificationXPCContract.isDigest(runIDDigest)
    else {
      throw NativeAgentQualificationEndpointError.bindingMismatch
    }
    self.candidateDigest = Data(candidateDigest)
    self.sourceCommitDigest = Data(sourceCommitDigest)
    self.codeIdentityDigest = Data(codeIdentityDigest)
    self.runIDDigest = Data(runIDDigest)
    self.runBinding = try NativeAgentQualificationRunBinding(values.runBindingDigest)
    self.expiresAtEpochSeconds = values.expiresAtEpochSeconds
    self.scenario = values.scenario
    self.phase = values.phase
  }

  private static func data(hex: String) -> Data? {
    guard hex.utf8.count == 64 else { return nil }
    var data = Data(capacity: 32)
    var index = hex.startIndex
    for _ in 0..<32 {
      let next = hex.index(index, offsetBy: 2)
      guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
      data.append(byte)
      index = next
    }
    return data
  }
}

/// Qualification-only implementation of the existing XPC DTO contract.
///
/// This object is deliberately only a bridge for arm/status/disarm. It does
/// not create an XPC listener, perform peer authentication, sign, persist, or
/// expose any production Agent capability. Listener setup and code-signing
/// authorization remain outside this file.
public final class NativeAgentQualificationEndpoint: NSObject,
  AgentPassQualificationXPCProtocol, @unchecked Sendable
{
  private struct ArmedReceipt: Equatable, Sendable {
    let phase: AgentPassQualificationXPCContract.FaultPhase
    let generation: UInt64
    let digest: Data
  }

  private enum State: Equatable, Sendable {
    case disarmed
    case armed
    case fired
  }

  private let controller: NativeAgentQualificationFaultController
  private let configuration: NativeAgentQualificationEndpointConfiguration
  private let wallTime: @Sendable () -> Date
  private let lock = NSLock()
  private var state: State = .disarmed
  private var armedReceipt: ArmedReceipt?
  private var hasArmed = false
  private var invalidated = false

  public init(
    controller: NativeAgentQualificationFaultController,
    configuration: NativeAgentQualificationEndpointConfiguration,
    wallTime: @escaping @Sendable () -> Date = Date.init
  ) {
    self.controller = controller
    self.configuration = configuration
    self.wallTime = wallTime
    super.init()
  }

  /// Convenience initializer for service wiring and focused tests.
  public convenience init(
    controller: NativeAgentQualificationFaultController,
    values: NativeAgentQualificationConfiguration.Values,
    wallTime: @escaping @Sendable () -> Date = Date.init
  ) throws {
    self.init(
      controller: controller,
      configuration: try NativeAgentQualificationEndpointConfiguration(values: values),
      wallTime: wallTime)
  }

  // MARK: AgentPassQualificationXPCProtocol

  public func armFault(
    _ request: AgentPassQualificationArmFaultRequest,
    withReply reply: @escaping (AgentPassQualificationArmFaultResponse?, NSError?) -> Void
  ) {
    let result:
      Result<AgentPassQualificationArmFaultResponse, NativeAgentQualificationEndpointError>
    lock.lock()
    result = armLocked(request)
    lock.unlock()
    finish(result, reply: reply)
  }

  public func readStatus(
    _ request: AgentPassQualificationStatusRequest,
    withReply reply: @escaping (AgentPassQualificationStatusResponse?, NSError?) -> Void
  ) {
    let result: Result<AgentPassQualificationStatusResponse, NativeAgentQualificationEndpointError>
    lock.lock()
    result = statusLocked(request)
    lock.unlock()
    finish(result, reply: reply)
  }

  public func disarmFault(
    _ request: AgentPassQualificationDisarmRequest,
    withReply reply: @escaping (AgentPassQualificationDisarmResponse?, NSError?) -> Void
  ) {
    let result: Result<AgentPassQualificationDisarmResponse, NativeAgentQualificationEndpointError>
    lock.lock()
    result = disarmLocked(request)
    lock.unlock()
    finish(result, reply: reply)
  }

  // MARK: Lifecycle

  /// Invalidates the bridge and clears any armed controller state. This is
  /// idempotent and fails closed; subsequent XPC operations receive the same
  /// stable invalidated error.
  public func invalidate() {
    lock.lock()
    guard !invalidated else {
      lock.unlock()
      return
    }
    invalidated = true
    state = .disarmed
    armedReceipt = nil
    controller.disable()
    lock.unlock()
  }

  /// Explicit shutdown spelling for service lifecycle owners.
  public func shutdown() {
    invalidate()
  }

  // MARK: Locked operations

  private func armLocked(
    _ request: AgentPassQualificationArmFaultRequest
  ) -> Result<AgentPassQualificationArmFaultResponse, NativeAgentQualificationEndpointError> {
    guard !invalidated else { return .failure(.invalidated) }
    guard matchesConfiguredArmBinding(request) else { return .failure(.bindingMismatch) }
    guard let phase = AgentPassQualificationXPCContract.FaultPhase(rawValue: request.faultPhase)
    else { return .failure(.invalidPhase) }
    guard ensureActiveLocked() else { return .failure(.expired) }
    guard phase.rawValue == configuration.phase.rawValue else { return .failure(.invalidPhase) }
    synchronizeStateLocked()
    guard controller.isEnabled else { return .failure(.disabled) }
    guard !hasArmed else { return .failure(.alreadyArmed) }

    let scenario = scenario(for: phase)
    guard scenario == configuration.scenario else { return .failure(.invalidPhase) }
    let receipt: NativeAgentQualificationFaultReceipt
    do {
      receipt = try controller.arm(runBinding: configuration.runBinding, scenario: scenario)
    } catch let error as NativeAgentQualificationFaultControllerError {
      return .failure(map(error))
    } catch {
      return .failure(.internalFailure)
    }

    let receiptDigest = Self.receiptDigest(
      phase: phase,
      generation: receipt.generation,
      configuration: configuration
    )
    guard
      let response = AgentPassQualificationArmFaultResponse(
        faultPhaseDigest: AgentPassQualificationXPCContract.digest(faultPhase: phase),
        candidateDigest: configuration.candidateDigest,
        sourceCommitDigest: configuration.sourceCommitDigest,
        codeIdentityDigest: configuration.codeIdentityDigest,
        runIDDigest: configuration.runIDDigest,
        receiptDigest: receiptDigest
      )
    else {
      _ = controller.reset()
      return .failure(.internalFailure)
    }

    armedReceipt = ArmedReceipt(
      phase: phase,
      generation: receipt.generation,
      digest: receiptDigest
    )
    hasArmed = true
    state = .armed
    return .success(response)
  }

  private func statusLocked(
    _ request: AgentPassQualificationStatusRequest
  ) -> Result<AgentPassQualificationStatusResponse, NativeAgentQualificationEndpointError> {
    guard !invalidated else { return .failure(.invalidated) }
    guard request.protocolVersion == AgentPassQualificationXPCContract.protocolVersion,
      request.candidateDigest == configuration.candidateDigest,
      request.runIDDigest == configuration.runIDDigest
    else { return .failure(.bindingMismatch) }
    guard ensureActiveLocked() else { return .failure(.expired) }
    guard controller.isEnabled else {
      clearLocked()
      return .failure(.disabled)
    }

    synchronizeStateLocked()
    let phaseDigest =
      armedReceipt.map {
        AgentPassQualificationXPCContract.digest(faultPhase: $0.phase)
      } ?? Self.clearedPhaseDigest
    let receiptDigest =
      armedReceipt?.digest ?? Self.clearedReceiptDigest(configuration: configuration)
    let status: AgentPassQualificationXPCContract.Status =
      switch state {
      case .armed: .armed
      case .fired: .fired
      case .disarmed: .disarmed
      }
    guard
      let response = AgentPassQualificationStatusResponse(
        status: status,
        faultPhaseDigest: phaseDigest,
        candidateDigest: configuration.candidateDigest,
        sourceCommitDigest: configuration.sourceCommitDigest,
        codeIdentityDigest: configuration.codeIdentityDigest,
        runIDDigest: configuration.runIDDigest,
        receiptDigest: receiptDigest
      )
    else { return .failure(.internalFailure) }
    return .success(response)
  }

  private func disarmLocked(
    _ request: AgentPassQualificationDisarmRequest
  ) -> Result<AgentPassQualificationDisarmResponse, NativeAgentQualificationEndpointError> {
    guard !invalidated else { return .failure(.invalidated) }
    guard request.protocolVersion == AgentPassQualificationXPCContract.protocolVersion,
      request.candidateDigest == configuration.candidateDigest,
      request.runIDDigest == configuration.runIDDigest
    else { return .failure(.bindingMismatch) }
    guard ensureActiveLocked() else { return .failure(.expired) }
    guard controller.isEnabled else {
      clearLocked()
      return .failure(.disabled)
    }

    synchronizeStateLocked()
    guard let armedReceipt,
      request.receiptDigest == armedReceipt.digest
    else { return .failure(.wrongReceipt) }

    if state == .armed {
      _ = controller.reset()
    }
    let response = AgentPassQualificationDisarmResponse(
      candidateDigest: configuration.candidateDigest,
      runIDDigest: configuration.runIDDigest,
      receiptDigest: armedReceipt.digest
    )
    guard let response else { return .failure(.internalFailure) }
    clearLockedWithoutDisabling()
    return .success(response)
  }

  /// The controller has an atomic one-shot consume operation but no observer
  /// callback. When a status request observes that its armed slot disappeared,
  /// the only safe interpretation available through the existing API is that
  /// the fault fired; the receipt remains bound to the original arm.
  private func synchronizeStateLocked() {
    guard state == .armed, armedReceipt != nil, !controller.isArmed else { return }
    state = .fired
  }

  private func clearLocked() {
    armedReceipt = nil
    state = .disarmed
    controller.disable()
  }

  private func clearLockedWithoutDisabling() {
    armedReceipt = nil
    state = .disarmed
  }

  private func ensureActiveLocked() -> Bool {
    let now = wallTime().timeIntervalSince1970
    guard now.isFinite, now >= 0, now < Double(configuration.expiresAtEpochSeconds) else {
      clearLocked()
      return false
    }
    return true
  }

  private func matchesConfiguredArmBinding(_ request: AgentPassQualificationArmFaultRequest) -> Bool
  {
    request.protocolVersion == AgentPassQualificationXPCContract.protocolVersion
      && request.candidateDigest == configuration.candidateDigest
      && request.sourceCommitDigest == configuration.sourceCommitDigest
      && request.codeIdentityDigest == configuration.codeIdentityDigest
      && request.runIDDigest == configuration.runIDDigest
  }

  private func scenario(
    for phase: AgentPassQualificationXPCContract.FaultPhase
  ) -> NativeAgentQualificationFaultScenario {
    switch phase {
    case .preCloud: .preCloudKill
    case .postCloudPreLocal: .postCloudPreLocalKill
    case .postActivationPreAudit: .postActivationPreAuditKill
    case .postAuditPreReply: .postAuditPreReplyLoss
    case .auditFsync: .auditFsyncFailure
    case .transportReply: .transportReplyLoss
    }
  }

  private func map(
    _ error: NativeAgentQualificationFaultControllerError
  ) -> NativeAgentQualificationEndpointError {
    switch error {
    case .disabled: .disabled
    case .alreadyArmed: .alreadyArmed
    case .generationExhausted: .generationExhausted
    case .invalidRunBinding: .internalFailure
    }
  }

  // MARK: Stable receipt material

  private static let receiptDomain = Data("AgentPassQualificationReceipt/v1\0".utf8)
  private static let clearedPhaseDigest = Data(
    SHA256.hash(data: Data("AgentPassQualificationClearedPhase/v1".utf8)))

  private static func receiptDigest(
    phase: AgentPassQualificationXPCContract.FaultPhase,
    generation: UInt64,
    configuration: NativeAgentQualificationEndpointConfiguration
  ) -> Data {
    var material = receiptDomain
    material.append(configuration.candidateDigest)
    material.append(configuration.sourceCommitDigest)
    material.append(configuration.codeIdentityDigest)
    material.append(configuration.runIDDigest)
    material.append(AgentPassQualificationXPCContract.digest(faultPhase: phase))
    material.append(contentsOf: withUnsafeBytes(of: generation.bigEndian) { Array($0) })
    return Data(SHA256.hash(data: material))
  }

  private static func clearedReceiptDigest(
    configuration: NativeAgentQualificationEndpointConfiguration
  ) -> Data {
    var material = Data("AgentPassQualificationClearedReceipt/v1\0".utf8)
    material.append(configuration.candidateDigest)
    material.append(configuration.sourceCommitDigest)
    material.append(configuration.codeIdentityDigest)
    material.append(configuration.runIDDigest)
    return Data(SHA256.hash(data: material))
  }

  private func finish<Response>(
    _ result: Result<Response, NativeAgentQualificationEndpointError>,
    reply: @escaping (Response?, NSError?) -> Void
  ) {
    switch result {
    case .success(let response): reply(response, nil)
    case .failure(let error): reply(nil, error.nsError)
    }
  }
}
