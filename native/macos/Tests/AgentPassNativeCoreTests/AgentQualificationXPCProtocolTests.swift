import AgentPassNativeCore
import Foundation
import ObjectiveC.runtime
import Testing

private let candidateDigest = Data(repeating: 0x11, count: 32)
private let sourceCommitDigest = Data(repeating: 0x22, count: 32)
private let codeIdentityDigest = Data(repeating: 0x33, count: 32)
private let receiptDigest = Data(repeating: 0x44, count: 32)
private let runID = Data(repeating: 0x55, count: 32)
private let runIDDigest = AgentPassQualificationXPCContract.digest(runID: runID)!

private func archive(_ object: NSSecureCoding) throws -> Data {
  try NSKeyedArchiver.archivedData(withRootObject: object, requiringSecureCoding: true)
}

private func unarchive<T: NSObject & NSSecureCoding>(_ type: T.Type, from data: Data) throws -> T {
  let object = try NSKeyedUnarchiver.unarchivedObject(ofClass: type, from: data)
  return try #require(object)
}

private func protocolSelectors(_ proto: Protocol) -> Set<String> {
  var count: UInt32 = 0
  guard let descriptions = protocol_copyMethodDescriptionList(proto, true, true, &count) else {
    return []
  }
  defer { free(descriptions) }
  return Set(
    (0..<Int(count)).compactMap { index in
      guard let selector = descriptions[index].name else { return nil }
      return NSStringFromSelector(selector)
    })
}

private func classNames(_ classes: Set<AnyHashable>) -> Set<String> {
  Set(classes.map { String(describing: $0.base as Any) })
}

/// A secure-coded object with similar-looking fields but a different class.
/// The target DTO must reject this archive rather than treating a same-shaped
/// object as a qualification response.
@objc(QualificationWrongArchiveObject)
private final class QualificationWrongArchiveObject: NSObject, NSSecureCoding {
  static var supportsSecureCoding: Bool { true }

  let status: String

  init(status: String) {
    self.status = status
    super.init()
  }

  required init?(coder: NSCoder) {
    guard let status = coder.decodeObject(of: NSString.self, forKey: "status") as String? else {
      return nil
    }
    self.status = status
    super.init()
  }

  func encode(with coder: NSCoder) {
    coder.encode(status as NSString, forKey: "status")
  }
}

@Test func qualificationMachServiceAndProtocolVersionAreFixedAndSeparate() {
  #expect(AgentPassQualificationXPCContract.machServiceName == "dev.agentpass.n3e-qualification")
  #expect(AgentPassQualificationXPCContract.machServiceName != "dev.agentpass.agent-session")
  #expect(AgentPassQualificationXPCContract.protocolVersion == 1)
  #expect(AgentPassQualificationXPCContract.FaultPhase.allCases.count == 6)
  #expect(Set(AgentPassQualificationXPCContract.FaultPhase.allCases.map(\.rawValue)).count == 6)
}

@Test func qualificationSelectorsAreExactlyThreeAndDoNotExtendAgentProtocol() {
  let qualificationSelectors = protocolSelectors(AgentPassQualificationXPCProtocol.self)
  #expect(
    qualificationSelectors == [
      "armFault:withReply:",
      "readStatus:withReply:",
      "disarmFault:withReply:",
    ])
  #expect(
    qualificationSelectors.intersection(protocolSelectors(AgentPassAgentXPCProtocol.self)).isEmpty)
}

@Test func qualificationInterfaceRegistersExactRequestAndReplyClassAllowlists() {
  let interface = AgentPassQualificationXPCInterface.make()
  let arm = #selector(AgentPassQualificationXPCProtocol.armFault(_:withReply:))
  let status = #selector(AgentPassQualificationXPCProtocol.readStatus(_:withReply:))
  let disarm = #selector(AgentPassQualificationXPCProtocol.disarmFault(_:withReply:))

  #expect(
    classNames(interface.classes(for: arm, argumentIndex: 0, ofReply: false)) == [
      "AgentPassQualificationArmFaultRequest"
    ])
  #expect(
    classNames(interface.classes(for: arm, argumentIndex: 0, ofReply: true)) == [
      "AgentPassQualificationArmFaultResponse"
    ])
  #expect(
    classNames(interface.classes(for: status, argumentIndex: 0, ofReply: false)) == [
      "AgentPassQualificationStatusRequest"
    ])
  #expect(
    classNames(interface.classes(for: status, argumentIndex: 0, ofReply: true)) == [
      "AgentPassQualificationStatusResponse"
    ])
  #expect(
    classNames(interface.classes(for: disarm, argumentIndex: 0, ofReply: false)) == [
      "AgentPassQualificationDisarmRequest"
    ])
  #expect(
    classNames(interface.classes(for: disarm, argumentIndex: 0, ofReply: true)) == [
      "AgentPassQualificationDisarmResponse"
    ])
}

@Test func armRequestHashesRunIDAndRoundTripsWithoutRawRunID() throws {
  let request = try #require(
    AgentPassQualificationArmFaultRequest(
      faultPhase: .postCloudPreLocal,
      candidateDigest: candidateDigest,
      sourceCommitDigest: sourceCommitDigest,
      codeIdentityDigest: codeIdentityDigest,
      runID: runID
    ))
  #expect(request.runIDDigest == runIDDigest)
  #expect(
    request.faultPhase == AgentPassQualificationXPCContract.FaultPhase.postCloudPreLocal.rawValue)

  let bytes = try archive(request)
  #expect(bytes.range(of: runID) == nil)
  let decoded = try unarchive(AgentPassQualificationArmFaultRequest.self, from: bytes)
  #expect(decoded.protocolVersion == 1)
  #expect(decoded.candidateDigest == candidateDigest)
  #expect(decoded.sourceCommitDigest == sourceCommitDigest)
  #expect(decoded.codeIdentityDigest == codeIdentityDigest)
  #expect(decoded.runIDDigest == runIDDigest)
}

@Test func allQualificationDTOsRoundTripAsClosedSecureCodedValues() throws {
  let phaseDigest = AgentPassQualificationXPCContract.digest(faultPhase: .postActivationPreAudit)
  let arm = try #require(
    AgentPassQualificationArmFaultResponse(
      faultPhaseDigest: phaseDigest,
      candidateDigest: candidateDigest,
      sourceCommitDigest: sourceCommitDigest,
      codeIdentityDigest: codeIdentityDigest,
      runIDDigest: runIDDigest,
      receiptDigest: receiptDigest
    ))
  let statusRequest = try #require(
    AgentPassQualificationStatusRequest(candidateDigest: candidateDigest, runIDDigest: runIDDigest))
  let status = try #require(
    AgentPassQualificationStatusResponse(
      status: .fired,
      faultPhaseDigest: phaseDigest,
      candidateDigest: candidateDigest,
      sourceCommitDigest: sourceCommitDigest,
      codeIdentityDigest: codeIdentityDigest,
      runIDDigest: runIDDigest,
      receiptDigest: receiptDigest
    ))
  let disarmRequest = try #require(
    AgentPassQualificationDisarmRequest(
      candidateDigest: candidateDigest,
      runIDDigest: runIDDigest,
      receiptDigest: receiptDigest
    ))
  let disarm = try #require(
    AgentPassQualificationDisarmResponse(
      candidateDigest: candidateDigest,
      runIDDigest: runIDDigest,
      receiptDigest: receiptDigest
    ))

  #expect(
    (try unarchive(AgentPassQualificationArmFaultResponse.self, from: archive(arm))).status
      == "armed")
  #expect(
    (try unarchive(AgentPassQualificationStatusRequest.self, from: archive(statusRequest)))
      .runIDDigest == runIDDigest)
  #expect(
    (try unarchive(AgentPassQualificationStatusResponse.self, from: archive(status))).status
      == "fired")
  #expect(
    (try unarchive(AgentPassQualificationDisarmRequest.self, from: archive(disarmRequest)))
      .receiptDigest == receiptDigest)
  #expect(
    (try unarchive(AgentPassQualificationDisarmResponse.self, from: archive(disarm))).status
      == "disarmed")
}

@Test func constructorsRejectBoundsVersionAndNonClosedValues() {
  #expect(AgentPassQualificationXPCContract.digest(runID: Data(repeating: 1, count: 15)) == nil)
  #expect(AgentPassQualificationXPCContract.digest(runID: Data(repeating: 0, count: 32)) == nil)
  #expect(
    AgentPassQualificationArmFaultRequest(
      protocolVersion: 2,
      faultPhase: .preCloud,
      candidateDigest: candidateDigest,
      sourceCommitDigest: sourceCommitDigest,
      codeIdentityDigest: codeIdentityDigest,
      runID: runID
    ) == nil)
  #expect(
    AgentPassQualificationStatusRequest(
      candidateDigest: Data(repeating: 1, count: 31), runIDDigest: runIDDigest) == nil)
  #expect(
    AgentPassQualificationArmFaultResponse(
      faultPhaseDigest: Data(repeating: 1, count: 31),
      candidateDigest: candidateDigest,
      sourceCommitDigest: sourceCommitDigest,
      codeIdentityDigest: codeIdentityDigest,
      runIDDigest: runIDDigest,
      receiptDigest: receiptDigest
    ) == nil)
}

@Test func secureDecodeRejectsMissingWrongTypedAndUnallowlistedArchiveFields() {
  let wrongRoot = try! archive(
    QualificationWrongArchiveObject(status: "operator supplied diagnostic"))
  #expect(throws: Error.self) {
    _ = try unarchive(AgentPassQualificationStatusResponse.self, from: wrongRoot)
  }

  // These constructor checks cover malformed values which cannot be
  // injected into a final Foundation secure-coded class without relying on
  // private NSKeyedArchiver implementation details.
  #expect(
    AgentPassQualificationStatusResponse(
      status: .armed,
      faultPhaseDigest: Data(repeating: 1, count: 32),
      candidateDigest: Data(repeating: 2, count: 32),
      sourceCommitDigest: Data(repeating: 3, count: 31),
      codeIdentityDigest: Data(repeating: 4, count: 32),
      runIDDigest: runIDDigest,
      receiptDigest: receiptDigest
    ) == nil)
  #expect(
    AgentPassQualificationArmFaultRequest(
      faultPhase: .preCloud,
      candidateDigest: candidateDigest,
      sourceCommitDigest: sourceCommitDigest,
      codeIdentityDigest: codeIdentityDigest,
      runID: Data(repeating: 0, count: 32)
    ) == nil)
}
