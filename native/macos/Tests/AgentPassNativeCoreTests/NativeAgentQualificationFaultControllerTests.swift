import Dispatch
import Foundation
import Testing

@testable import AgentPassNativeCore

private let qualificationScenario = NativeAgentQualificationFaultScenario.preCloudKill
private let qualificationBinding = try! NativeAgentQualificationRunBinding(
  String(repeating: "a", count: 64)
)
private let otherQualificationBinding = try! NativeAgentQualificationRunBinding(
  String(repeating: "b", count: 64)
)

private final class QualificationCounter: @unchecked Sendable {
  private let lock = NSLock()
  private var value = 0

  func increment() {
    lock.lock()
    value += 1
    lock.unlock()
  }

  var count: Int {
    lock.lock()
    defer { lock.unlock() }
    return value
  }
}

@Test("the controller starts disabled and exposes exactly six closed phases")
func qualificationControllerStartsDisabled() {
  let controller = NativeAgentQualificationFaultController()
  #expect(controller.isEnabled == false)
  #expect(controller.isArmed == false)
  #expect(controller.currentGeneration == 0)
  #expect(
    NativeAgentQualificationFaultPhase.allCases.map(\.rawValue) == [
      "pre-cloud",
      "post-cloud-pre-local",
      "post-activation-pre-audit",
      "post-audit-pre-reply",
      "audit-fsync",
      "transport-reply",
    ])
}

@Test("arming is disabled by default and accepts one fixed run binding")
func qualificationControllerArmingRules() throws {
  let controller = NativeAgentQualificationFaultController()
  #expect(throws: NativeAgentQualificationFaultControllerError.disabled) {
    _ = try controller.arm(
      runBinding: qualificationBinding,
      scenario: qualificationScenario
    )
  }

  controller.enable()
  let armed = try controller.arm(
    runBinding: qualificationBinding,
    scenario: .postCloudPreLocalKill
  )
  #expect(armed.scenario == .postCloudPreLocalKill)
  #expect(armed.phase == .postCloudPreLocal)
  #expect(armed.generation == 1)
  #expect(armed.outcome == .armed)
  #expect(controller.isArmed)
  #expect(throws: NativeAgentQualificationFaultControllerError.alreadyArmed) {
    _ = try controller.arm(
      runBinding: otherQualificationBinding,
      scenario: .auditFsyncFailure
    )
  }
}

@Test("wrong binding and phase do not consume the armed fault")
func qualificationControllerMismatchesAreNonDestructive() throws {
  let controller = NativeAgentQualificationFaultController(enabled: true)
  _ = try controller.arm(
    runBinding: qualificationBinding,
    scenario: .transportReplyLoss
  )

  let wrongBinding = controller.consume(
    runBinding: otherQualificationBinding,
    scenario: .transportReplyLoss,
    phase: .transportReply
  )
  #expect(wrongBinding.outcome == .bindingMismatch)
  #expect(controller.isArmed)

  let wrongPhase = controller.consume(
    runBinding: qualificationBinding,
    scenario: .transportReplyLoss,
    phase: .auditFsync
  )
  #expect(wrongPhase.outcome == .phaseMismatch)
  #expect(controller.isArmed)

  let wrongScenario = controller.consume(
    runBinding: qualificationBinding,
    scenario: .auditFsyncFailure,
    phase: .transportReply
  )
  #expect(wrongScenario.outcome == .scenarioMismatch)
  #expect(controller.isArmed)

  let injected = controller.consume(
    runBinding: qualificationBinding,
    scenario: .transportReplyLoss,
    phase: .transportReply
  )
  #expect(injected.outcome == .injected)
  #expect(injected.generation == 1)
  #expect(controller.isArmed == false)
}

@Test("matching consume is exactly once and self-clears")
func qualificationControllerIsOneShot() throws {
  let controller = NativeAgentQualificationFaultController(enabled: true)
  _ = try controller.arm(
    runBinding: qualificationBinding,
    scenario: .auditFsyncFailure
  )
  #expect(
    controller.consume(
      runBinding: qualificationBinding,
      scenario: .auditFsyncFailure,
      phase: .auditFsync
    ).outcome == .injected)
  #expect(
    controller.consume(
      runBinding: qualificationBinding,
      scenario: .auditFsyncFailure,
      phase: .auditFsync
    ).outcome == .notArmed)
}

@Test("reset and disable clear the armed slot without rewinding generation")
func qualificationControllerResetAndDisable() throws {
  let controller = NativeAgentQualificationFaultController(enabled: true)
  _ = try controller.arm(
    runBinding: qualificationBinding,
    scenario: qualificationScenario
  )
  let reset = controller.reset()
  #expect(reset?.outcome == .reset)
  #expect(controller.isArmed == false)
  #expect(controller.currentGeneration == 1)

  _ = try controller.arm(
    runBinding: qualificationBinding,
    scenario: qualificationScenario
  )
  controller.disable()
  #expect(controller.isEnabled == false)
  #expect(controller.isArmed == false)
  #expect(controller.currentGeneration == 2)
  #expect(throws: NativeAgentQualificationFaultControllerError.disabled) {
    _ = try controller.arm(
      runBinding: qualificationBinding,
      scenario: qualificationScenario
    )
  }
}

@Test("generation is monotonic and exhaustion fails closed")
func qualificationControllerGenerationIsBounded() throws {
  let controller = try NativeAgentQualificationFaultController(
    enabled: true,
    startingGeneration: NativeAgentQualificationFaultController.maximumGeneration
  )
  #expect(throws: NativeAgentQualificationFaultControllerError.generationExhausted) {
    _ = try controller.arm(
      runBinding: qualificationBinding,
      scenario: qualificationScenario
    )
  }
  #expect(controller.currentGeneration == NativeAgentQualificationFaultController.maximumGeneration)
}

@Test("one armed transition wins under one hundred concurrent arm attempts")
func qualificationControllerAllowsOneConcurrentArm() {
  let controller = NativeAgentQualificationFaultController(enabled: true)
  let armed = QualificationCounter()

  DispatchQueue.concurrentPerform(iterations: 100) { index in
    let binding =
      (try? NativeAgentQualificationRunBinding(
        String(format: "%064x", index + 1)
      )) ?? qualificationBinding
    if (try? controller.arm(
      runBinding: binding,
      scenario: qualificationScenario
    )) != nil {
      armed.increment()
    }
  }

  #expect(armed.count == 1)
  #expect(controller.isArmed)
}

@Test("one hundred concurrent consumes produce exactly one injection")
func qualificationControllerConsumesExactlyOnceUnderConcurrency() throws {
  let controller = NativeAgentQualificationFaultController(enabled: true)
  _ = try controller.arm(
    runBinding: qualificationBinding,
    scenario: .postActivationPreAuditKill
  )
  let injected = QualificationCounter()
  let notArmed = QualificationCounter()

  DispatchQueue.concurrentPerform(iterations: 100) { _ in
    let receipt = controller.consume(
      runBinding: qualificationBinding,
      scenario: .postActivationPreAuditKill,
      phase: .postActivationPreAudit
    )
    switch receipt.outcome {
    case .injected: injected.increment()
    case .notArmed: notArmed.increment()
    default: break
    }
  }

  #expect(injected.count == 1)
  #expect(notArmed.count == 99)
  #expect(controller.isArmed == false)
}

@Test("invalid bindings and unknown scenario raw values are rejected")
func qualificationControllerRejectsUnboundedInputs() {
  #expect(throws: NativeAgentQualificationFaultControllerError.invalidRunBinding) {
    _ = try NativeAgentQualificationRunBinding("not-a-fixed-binding")
  }
  #expect(NativeAgentQualificationFaultScenario(rawValue: "/tmp/qualification") == nil)
  #expect(NativeAgentQualificationFaultScenario(rawValue: "two--segments") == nil)
}
