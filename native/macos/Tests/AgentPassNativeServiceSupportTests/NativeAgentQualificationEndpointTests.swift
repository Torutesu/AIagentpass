import AgentPassNativeCore
import Foundation
import Testing

@testable import AgentPassNativeServiceSupport

private let endpointCandidate = Data(repeating: 0x11, count: 32)
private let endpointSource = Data(repeating: 0x22, count: 32)
private let endpointCodeIdentity = Data(repeating: 0x33, count: 32)
private let endpointRunID = Data(repeating: 0x55, count: 32)
private let endpointRunDigest = AgentPassQualificationXPCContract.digest(runID: endpointRunID)!
private let endpointNow = Date(timeIntervalSince1970: 2_000_000_000)
private let endpointServiceAccessGroup = "ABCDE12345.dev.agentpass.service-keys"
private let endpointBinding = try! NativeAgentQualificationRunBinding(
  endpointRunDigest.map { String(format: "%02x", $0) }.joined())

private func endpointHex(_ data: Data) -> String {
  data.map { String(format: "%02x", $0) }.joined()
}

private func endpointValues(
  scenario: NativeAgentQualificationFaultScenario = .preCloudKill,
  expiresAtEpochSeconds: UInt64 = 2_000_000_060
) throws -> NativeAgentQualificationConfiguration.Values {
  let configuration = try NativeAgentQualificationConfiguration(
    mode: NativeAgentQualificationConfiguration.modeMarker,
    machServiceName: NativeAgentQualificationConfiguration.machServiceName,
    candidateDigest: endpointHex(endpointCandidate),
    sourceCommitDigest: endpointHex(endpointSource),
    codeIdentityDigest: endpointHex(endpointCodeIdentity),
    runBindingDigest: endpointHex(endpointRunDigest),
    controllerServiceAccessGroup: endpointServiceAccessGroup,
    controllerCodeDirectoryHash: String(repeating: "e", count: 40),
    expiresAtEpochSeconds: expiresAtEpochSeconds,
    scenario: scenario,
    phase: scenario.phase,
    wallTime: endpointNow)
  return try #require(configuration.values)
}

private func makeEndpoint(
  enabled: Bool = true,
  scenario: NativeAgentQualificationFaultScenario = .preCloudKill,
  wallTime: @escaping @Sendable () -> Date = { endpointNow }
) throws -> (NativeAgentQualificationEndpoint, NativeAgentQualificationFaultController) {
  let controller = NativeAgentQualificationFaultController(enabled: enabled)
  let endpoint = try NativeAgentQualificationEndpoint(
    controller: controller,
    values: endpointValues(scenario: scenario),
    wallTime: wallTime
  )
  return (endpoint, controller)
}

private func armRequest(
  phase: AgentPassQualificationXPCContract.FaultPhase = .preCloud,
  candidate: Data = endpointCandidate,
  source: Data = endpointSource,
  codeIdentity: Data = endpointCodeIdentity
) -> AgentPassQualificationArmFaultRequest {
  // All values in these tests are valid DTO digests, so force-unwrapping
  // isolates endpoint behavior from DTO-construction failures.
  return AgentPassQualificationArmFaultRequest(
    faultPhase: phase,
    candidateDigest: candidate,
    sourceCommitDigest: source,
    codeIdentityDigest: codeIdentity,
    runID: endpointRunID
  )!
}

private func waitForArm(
  _ endpoint: NativeAgentQualificationEndpoint,
  _ request: AgentPassQualificationArmFaultRequest
) -> (AgentPassQualificationArmFaultResponse?, NSError?) {
  var result: (AgentPassQualificationArmFaultResponse?, NSError?)!
  endpoint.armFault(request) { response, error in result = (response, error) }
  return result
}

private func waitForStatus(
  _ endpoint: NativeAgentQualificationEndpoint,
  _ request: AgentPassQualificationStatusRequest
) -> (AgentPassQualificationStatusResponse?, NSError?) {
  var result: (AgentPassQualificationStatusResponse?, NSError?)!
  endpoint.readStatus(request) { response, error in result = (response, error) }
  return result
}

private func waitForDisarm(
  _ endpoint: NativeAgentQualificationEndpoint,
  _ request: AgentPassQualificationDisarmRequest
) -> (AgentPassQualificationDisarmResponse?, NSError?) {
  var result: (AgentPassQualificationDisarmResponse?, NSError?)!
  endpoint.disarmFault(request) { response, error in result = (response, error) }
  return result
}

@Test("endpoint configuration derives the controller binding from the configured run digest")
func endpointConfigurationDerivesRunBinding() throws {
  let values = try endpointValues()
  let configuration = try NativeAgentQualificationEndpointConfiguration(values: values)
  #expect(configuration.runIDDigest == endpointRunDigest)
  #expect(configuration.runBinding == endpointBinding)
}

@Test("arm binds all four immutable digests and maps every phase")
func endpointArmsAndMapsPhases() throws {
  for phase in AgentPassQualificationXPCContract.FaultPhase.allCases {
    let scenario = NativeAgentQualificationFaultScenario.allCases.first {
      $0.phase.rawValue == phase.rawValue
    }!
    let (endpoint, controller) = try makeEndpoint(scenario: scenario)
    let request = armRequest(phase: phase)
    let (response, error) = waitForArm(endpoint, request)
    #expect(error == nil)
    #expect(response?.status == AgentPassQualificationXPCContract.Status.armed.rawValue)
    #expect(
      response?.faultPhaseDigest == AgentPassQualificationXPCContract.digest(faultPhase: phase))
    #expect(controller.isArmed)

    let statusRequest = AgentPassQualificationStatusRequest(
      candidateDigest: endpointCandidate,
      runIDDigest: endpointRunDigest
    )!
    let (status, statusError) = waitForStatus(endpoint, statusRequest)
    #expect(statusError == nil)
    #expect(status?.status == AgentPassQualificationXPCContract.Status.armed.rawValue)
    #expect(status?.faultPhaseDigest == AgentPassQualificationXPCContract.digest(faultPhase: phase))

    let disarmRequest = AgentPassQualificationDisarmRequest(
      candidateDigest: endpointCandidate,
      runIDDigest: endpointRunDigest,
      receiptDigest: response!.receiptDigest
    )!
    let (disarmed, disarmError) = waitForDisarm(endpoint, disarmRequest)
    #expect(disarmError == nil)
    #expect(disarmed?.status == AgentPassQualificationXPCContract.Status.disarmed.rawValue)
    #expect(!controller.isArmed)
  }
}

@Test("wrong binding, disabled state, and a second arm return stable errors")
func endpointRejectsBindingAndStateErrors() throws {
  let (endpoint, _) = try makeEndpoint()
  let wrongSource = armRequest(source: Data(repeating: 0x99, count: 32))
  let (_, bindingError) = waitForArm(endpoint, wrongSource)
  #expect(bindingError?.domain == NativeAgentQualificationEndpointError.errorDomain)
  #expect(bindingError?.code == NativeAgentQualificationEndpointError.bindingMismatch.rawValue)
  #expect(bindingError?.userInfo.count == 2)
  #expect(bindingError?.userInfo["request"] == nil)

  let first = waitForArm(endpoint, armRequest())
  #expect(first.1 == nil)
  let (_, secondError) = waitForArm(endpoint, armRequest())
  #expect(secondError?.code == NativeAgentQualificationEndpointError.alreadyArmed.rawValue)

  let (phaseEndpoint, _) = try makeEndpoint()
  let (_, phaseError) = waitForArm(phaseEndpoint, armRequest(phase: .auditFsync))
  #expect(phaseError?.code == NativeAgentQualificationEndpointError.invalidPhase.rawValue)

  let (disabledEndpoint, _) = try makeEndpoint(enabled: false)
  let (_, disabledError) = waitForArm(disabledEndpoint, armRequest())
  #expect(disabledError?.code == NativeAgentQualificationEndpointError.disabled.rawValue)

  let wrongStatusRequest = AgentPassQualificationStatusRequest(
    candidateDigest: Data(repeating: 0x98, count: 32),
    runIDDigest: endpointRunDigest
  )!
  let (_, statusBindingError) = waitForStatus(endpoint, wrongStatusRequest)
  #expect(
    statusBindingError?.code == NativeAgentQualificationEndpointError.bindingMismatch.rawValue)

  let wrongDisarmRequest = AgentPassQualificationDisarmRequest(
    candidateDigest: endpointCandidate,
    runIDDigest: endpointRunDigest,
    receiptDigest: Data(repeating: 0x88, count: 32)
  )!
  let (_, disarmReceiptError) = waitForDisarm(endpoint, wrongDisarmRequest)
  #expect(disarmReceiptError?.code == NativeAgentQualificationEndpointError.wrongReceipt.rawValue)
}

@Test("wrong receipt is non-destructive and exact receipt disarms")
func endpointRejectsWrongReceipt() throws {
  let (endpoint, controller) = try makeEndpoint()
  let (armed, armError) = waitForArm(endpoint, armRequest())
  #expect(armError == nil)

  let wrongReceipt = Data(repeating: 0x77, count: 32)
  let wrongRequest = AgentPassQualificationDisarmRequest(
    candidateDigest: endpointCandidate,
    runIDDigest: endpointRunDigest,
    receiptDigest: wrongReceipt
  )!
  let (_, wrongError) = waitForDisarm(endpoint, wrongRequest)
  #expect(wrongError?.code == NativeAgentQualificationEndpointError.wrongReceipt.rawValue)
  #expect(controller.isArmed)

  let correctRequest = AgentPassQualificationDisarmRequest(
    candidateDigest: endpointCandidate,
    runIDDigest: endpointRunDigest,
    receiptDigest: armed!.receiptDigest
  )!
  let (disarmed, correctError) = waitForDisarm(endpoint, correctRequest)
  #expect(correctError == nil)
  #expect(disarmed?.receiptDigest == armed?.receiptDigest)
  #expect(!controller.isArmed)

  let (_, secondError) = waitForDisarm(endpoint, correctRequest)
  #expect(secondError?.code == NativeAgentQualificationEndpointError.wrongReceipt.rawValue)
  let (_, rearmError) = waitForArm(endpoint, armRequest())
  #expect(rearmError?.code == NativeAgentQualificationEndpointError.alreadyArmed.rawValue)
}

@Test("status reports fired after the controller consumes the one-shot fault")
func endpointReportsFiredAfterExternalConsumption() throws {
  let (endpoint, controller) = try makeEndpoint(scenario: .transportReplyLoss)
  let (armed, error) = waitForArm(endpoint, armRequest(phase: .transportReply))
  #expect(error == nil)

  let binding = endpointBinding
  let consumed = controller.consume(
    runBinding: binding,
    scenario: .transportReplyLoss,
    phase: .transportReply
  )
  #expect(consumed.outcome == .injected)

  let statusRequest = AgentPassQualificationStatusRequest(
    candidateDigest: endpointCandidate,
    runIDDigest: endpointRunDigest
  )!
  let (status, statusError) = waitForStatus(endpoint, statusRequest)
  #expect(statusError == nil)
  #expect(status?.status == AgentPassQualificationXPCContract.Status.fired.rawValue)
  #expect(status?.receiptDigest == armed?.receiptDigest)
}

@Test("invalidate and shutdown clear state and reject every subsequent operation")
func endpointLifecycleClearsAndInvalidates() throws {
  let (endpoint, controller) = try makeEndpoint()
  let (armed, error) = waitForArm(endpoint, armRequest())
  #expect(error == nil)
  #expect(armed != nil)
  endpoint.invalidate()
  endpoint.shutdown()
  #expect(!controller.isArmed)
  #expect(!controller.isEnabled)

  let (status, statusError) = waitForStatus(
    endpoint,
    AgentPassQualificationStatusRequest(
      candidateDigest: endpointCandidate,
      runIDDigest: endpointRunDigest
    )!
  )
  #expect(status == nil)
  #expect(statusError?.code == NativeAgentQualificationEndpointError.invalidated.rawValue)
}

@Test("receipt digest is deterministic, bound, and contains no run binding")
func endpointReceiptDigestIsDeterministicAndSecretFree() throws {
  let (first, _) = try makeEndpoint()
  let (second, _) = try makeEndpoint()
  let firstArm = waitForArm(first, armRequest())
  let secondArm = waitForArm(second, armRequest())
  #expect(firstArm.1 == nil)
  #expect(secondArm.1 == nil)
  #expect(firstArm.0?.receiptDigest == secondArm.0?.receiptDigest)
  #expect(firstArm.0?.receiptDigest != endpointBindingValue())

  let (differentPhase, _) = try makeEndpoint(scenario: .auditFsyncFailure)
  let differentArm = waitForArm(differentPhase, armRequest(phase: .auditFsync))
  #expect(differentArm.1 == nil)
  #expect(differentArm.0?.receiptDigest != firstArm.0?.receiptDigest)
}

private func endpointBindingValue() -> Data {
  Data(endpointBindingString().utf8)
}

private func endpointBindingString() -> String {
  endpointHex(endpointRunDigest)
}

@Test("expiry disables and clears the endpoint on every operation")
func endpointExpiryFailsClosed() throws {
  let expiredNow = Date(timeIntervalSince1970: 2_000_000_061)
  let (endpoint, controller) = try makeEndpoint(wallTime: { expiredNow })
  let (_, error) = waitForArm(endpoint, armRequest())
  #expect(error?.code == NativeAgentQualificationEndpointError.expired.rawValue)
  #expect(!controller.isEnabled)
  #expect(!controller.isArmed)
}
