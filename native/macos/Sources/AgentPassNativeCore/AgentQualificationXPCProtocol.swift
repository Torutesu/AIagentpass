import CryptoKit
import Foundation

/// The wire contract used only by the N3-E2 qualification harness.
///
/// This is intentionally a different Mach service from the production Agent
/// session service. It is a fault-injection control plane, not an Agent
/// capability plane: it can arm one fixed fault, read a redacted receipt, and
/// disarm that fault. It cannot sign, carry a proof, or read a secret.
public enum AgentPassQualificationXPCContract {
  /// The production launchd job reserves this name so qualification can test
  /// the exact candidate bytes. The service constructs no listener unless a
  /// complete, root-owned, candidate-bound qualification configuration is
  /// present; the ordinary product does not bundle the controller principal.
  public static let machServiceName = "dev.agentpass.n3e-qualification"
  public static let protocolVersion = 1
  public static let digestBytes = 32
  public static let minimumRunIDBytes = 16
  public static let maximumRunIDBytes = 64

  /// The only six fault injection points admitted by the qualification
  /// protocol. Adding a phase is a protocol change and requires a new
  /// qualification contract version.
  public enum FaultPhase: String, CaseIterable, Sendable {
    case preCloud = "pre-cloud"
    case postCloudPreLocal = "post-cloud-pre-local"
    case postActivationPreAudit = "post-activation-pre-audit"
    case postAuditPreReply = "post-audit-pre-reply"
    case auditFsync = "audit-fsync"
    case transportReply = "transport-reply"
  }

  /// A status is deliberately closed. There is no free-form diagnostic
  /// string in any DTO crossing this boundary.
  public enum Status: String, CaseIterable, Sendable {
    case armed
    case fired
    case disarmed
  }

  /// The qualification harness binds the random run identifier to a digest
  /// before it crosses the wire. The raw random value is never a DTO field,
  /// persisted receipt field, or response field.
  public static func digest(runID: Data) -> Data? {
    guard (minimumRunIDBytes...maximumRunIDBytes).contains(runID.count),
      runID.contains(where: { $0 != 0 })
    else { return nil }
    return Data(SHA256.hash(data: runID))
  }

  public static func digest(faultPhase: FaultPhase) -> Data {
    Data(SHA256.hash(data: Data(faultPhase.rawValue.utf8)))
  }

  public static func isDigest(_ value: Data) -> Bool {
    value.count == digestBytes && value.contains(where: { $0 != 0 })
  }

  public static func makeInterface() -> NSXPCInterface {
    AgentPassQualificationXPCInterface.make()
  }
}

/// A qualification-only XPC surface. It is intentionally disjoint from
/// `AgentPassAgentXPCProtocol`; none of its selectors may be added to that
/// production protocol.
@objc public protocol AgentPassQualificationXPCProtocol {
  func armFault(
    _ request: AgentPassQualificationArmFaultRequest,
    withReply reply: @escaping (AgentPassQualificationArmFaultResponse?, NSError?) -> Void)
  func readStatus(
    _ request: AgentPassQualificationStatusRequest,
    withReply reply: @escaping (AgentPassQualificationStatusResponse?, NSError?) -> Void)
  func disarmFault(
    _ request: AgentPassQualificationDisarmRequest,
    withReply reply: @escaping (AgentPassQualificationDisarmResponse?, NSError?) -> Void)
}

/// Request to arm exactly one fixed fault phase.
///
/// The request contains only digests plus a closed phase name. `runID` is an
/// input to the initializer, not a stored property or an encoded field; only
/// its SHA-256 digest is sent over XPC.
@objc(AgentPassQualificationArmFaultRequest)
public final class AgentPassQualificationArmFaultRequest: NSObject, NSSecureCoding {
  public static var supportsSecureCoding: Bool { true }

  public let protocolVersion: Int
  public let faultPhase: String
  public let candidateDigest: Data
  public let sourceCommitDigest: Data
  public let codeIdentityDigest: Data
  public let runIDDigest: Data

  public init?(
    protocolVersion: Int = AgentPassQualificationXPCContract.protocolVersion,
    faultPhase: AgentPassQualificationXPCContract.FaultPhase,
    candidateDigest: Data,
    sourceCommitDigest: Data,
    codeIdentityDigest: Data,
    runID: Data
  ) {
    guard protocolVersion == AgentPassQualificationXPCContract.protocolVersion,
      AgentPassQualificationXPCContract.isDigest(candidateDigest),
      AgentPassQualificationXPCContract.isDigest(sourceCommitDigest),
      AgentPassQualificationXPCContract.isDigest(codeIdentityDigest),
      let runIDDigest = AgentPassQualificationXPCContract.digest(runID: runID)
    else {
      return nil
    }
    self.protocolVersion = protocolVersion
    self.faultPhase = faultPhase.rawValue
    self.candidateDigest = candidateDigest
    self.sourceCommitDigest = sourceCommitDigest
    self.codeIdentityDigest = codeIdentityDigest
    self.runIDDigest = runIDDigest
    super.init()
  }

  public required convenience init?(coder: NSCoder) {
    guard let protocolVersion = QualificationXPCCoding.int(coder, key: Keys.protocolVersion),
      let faultPhase = QualificationXPCCoding.string(coder, key: Keys.faultPhase),
      let candidateDigest = QualificationXPCCoding.data(coder, key: Keys.candidateDigest),
      let sourceCommitDigest = QualificationXPCCoding.data(coder, key: Keys.sourceCommitDigest),
      let codeIdentityDigest = QualificationXPCCoding.data(coder, key: Keys.codeIdentityDigest),
      let runIDDigest = QualificationXPCCoding.data(coder, key: Keys.runIDDigest),
      let phase = AgentPassQualificationXPCContract.FaultPhase(rawValue: faultPhase),
      protocolVersion == AgentPassQualificationXPCContract.protocolVersion,
      AgentPassQualificationXPCContract.isDigest(candidateDigest),
      AgentPassQualificationXPCContract.isDigest(sourceCommitDigest),
      AgentPassQualificationXPCContract.isDigest(codeIdentityDigest),
      AgentPassQualificationXPCContract.isDigest(runIDDigest)
    else {
      return nil
    }
    self.init(
      decodedProtocolVersion: protocolVersion,
      faultPhase: phase.rawValue,
      candidateDigest: candidateDigest,
      sourceCommitDigest: sourceCommitDigest,
      codeIdentityDigest: codeIdentityDigest,
      runIDDigest: runIDDigest
    )
  }

  private init?(
    decodedProtocolVersion: Int,
    faultPhase: String,
    candidateDigest: Data,
    sourceCommitDigest: Data,
    codeIdentityDigest: Data,
    runIDDigest: Data
  ) {
    guard decodedProtocolVersion == AgentPassQualificationXPCContract.protocolVersion,
      AgentPassQualificationXPCContract.FaultPhase(rawValue: faultPhase) != nil,
      AgentPassQualificationXPCContract.isDigest(candidateDigest),
      AgentPassQualificationXPCContract.isDigest(sourceCommitDigest),
      AgentPassQualificationXPCContract.isDigest(codeIdentityDigest),
      AgentPassQualificationXPCContract.isDigest(runIDDigest)
    else { return nil }
    self.protocolVersion = decodedProtocolVersion
    self.faultPhase = faultPhase
    self.candidateDigest = candidateDigest
    self.sourceCommitDigest = sourceCommitDigest
    self.codeIdentityDigest = codeIdentityDigest
    self.runIDDigest = runIDDigest
    super.init()
  }

  public func encode(with coder: NSCoder) {
    coder.encode(NSNumber(value: protocolVersion), forKey: Keys.protocolVersion)
    coder.encode(faultPhase as NSString, forKey: Keys.faultPhase)
    coder.encode(candidateDigest as NSData, forKey: Keys.candidateDigest)
    coder.encode(sourceCommitDigest as NSData, forKey: Keys.sourceCommitDigest)
    coder.encode(codeIdentityDigest as NSData, forKey: Keys.codeIdentityDigest)
    coder.encode(runIDDigest as NSData, forKey: Keys.runIDDigest)
  }

  private enum Keys {
    static let protocolVersion = "protocol_version"
    static let faultPhase = "fault_phase"
    static let candidateDigest = "candidate_digest"
    static let sourceCommitDigest = "source_commit_digest"
    static let codeIdentityDigest = "code_identity_digest"
    static let runIDDigest = "run_id_digest"
  }
}

/// Secret-free acknowledgement of an arm operation. The phase and run ID are
/// represented only by digests; the receipt digest is an opaque correlation
/// value, never a bearer credential.
@objc(AgentPassQualificationArmFaultResponse)
public final class AgentPassQualificationArmFaultResponse: NSObject, NSSecureCoding {
  public static var supportsSecureCoding: Bool { true }

  public let protocolVersion: Int
  public let status: String
  public let faultPhaseDigest: Data
  public let candidateDigest: Data
  public let sourceCommitDigest: Data
  public let codeIdentityDigest: Data
  public let runIDDigest: Data
  public let receiptDigest: Data

  public init?(
    protocolVersion: Int = AgentPassQualificationXPCContract.protocolVersion,
    status: AgentPassQualificationXPCContract.Status = .armed,
    faultPhaseDigest: Data,
    candidateDigest: Data,
    sourceCommitDigest: Data,
    codeIdentityDigest: Data,
    runIDDigest: Data,
    receiptDigest: Data
  ) {
    guard protocolVersion == AgentPassQualificationXPCContract.protocolVersion,
      status == .armed,
      AgentPassQualificationXPCContract.isDigest(faultPhaseDigest),
      AgentPassQualificationXPCContract.isDigest(candidateDigest),
      AgentPassQualificationXPCContract.isDigest(sourceCommitDigest),
      AgentPassQualificationXPCContract.isDigest(codeIdentityDigest),
      AgentPassQualificationXPCContract.isDigest(runIDDigest),
      AgentPassQualificationXPCContract.isDigest(receiptDigest)
    else { return nil }
    self.protocolVersion = protocolVersion
    self.status = status.rawValue
    self.faultPhaseDigest = faultPhaseDigest
    self.candidateDigest = candidateDigest
    self.sourceCommitDigest = sourceCommitDigest
    self.codeIdentityDigest = codeIdentityDigest
    self.runIDDigest = runIDDigest
    self.receiptDigest = receiptDigest
    super.init()
  }

  public required convenience init?(coder: NSCoder) {
    guard let values = QualificationXPCCoding.commonResponseValues(coder, keys: Keys.self),
      let status = AgentPassQualificationXPCContract.Status(rawValue: values.status),
      status == .armed,
      let faultPhaseDigest = QualificationXPCCoding.data(coder, key: Keys.faultPhaseDigest),
      let receiptDigest = QualificationXPCCoding.data(coder, key: Keys.receiptDigest)
    else { return nil }
    self.init(
      protocolVersion: values.protocolVersion,
      status: status,
      faultPhaseDigest: faultPhaseDigest,
      candidateDigest: values.candidateDigest,
      sourceCommitDigest: values.sourceCommitDigest,
      codeIdentityDigest: values.codeIdentityDigest,
      runIDDigest: values.runIDDigest,
      receiptDigest: receiptDigest
    )
  }

  public func encode(with coder: NSCoder) {
    QualificationXPCCoding.encodeCommonResponse(
      protocolVersion: protocolVersion,
      status: status,
      candidateDigest: candidateDigest,
      sourceCommitDigest: sourceCommitDigest,
      codeIdentityDigest: codeIdentityDigest,
      runIDDigest: runIDDigest,
      coder: coder,
      keys: Keys.self
    )
    coder.encode(faultPhaseDigest as NSData, forKey: Keys.faultPhaseDigest)
    coder.encode(receiptDigest as NSData, forKey: Keys.receiptDigest)
  }

  private enum Keys {
    static let protocolVersion = "protocol_version"
    static let status = "status"
    static let candidateDigest = "candidate_digest"
    static let sourceCommitDigest = "source_commit_digest"
    static let codeIdentityDigest = "code_identity_digest"
    static let runIDDigest = "run_id_digest"
    static let faultPhaseDigest = "fault_phase_digest"
    static let receiptDigest = "receipt_digest"
  }
}

/// Request to read one qualification receipt. It contains no path, PID,
/// process identity, payload, proof, key, token, or arbitrary string.
@objc(AgentPassQualificationStatusRequest)
public final class AgentPassQualificationStatusRequest: NSObject, NSSecureCoding {
  public static var supportsSecureCoding: Bool { true }

  public let protocolVersion: Int
  public let candidateDigest: Data
  public let runIDDigest: Data

  public init?(
    protocolVersion: Int = AgentPassQualificationXPCContract.protocolVersion,
    candidateDigest: Data,
    runIDDigest: Data
  ) {
    guard protocolVersion == AgentPassQualificationXPCContract.protocolVersion,
      AgentPassQualificationXPCContract.isDigest(candidateDigest),
      AgentPassQualificationXPCContract.isDigest(runIDDigest)
    else { return nil }
    self.protocolVersion = protocolVersion
    self.candidateDigest = candidateDigest
    self.runIDDigest = runIDDigest
    super.init()
  }

  public required convenience init?(coder: NSCoder) {
    guard let protocolVersion = QualificationXPCCoding.int(coder, key: Keys.protocolVersion),
      let candidateDigest = QualificationXPCCoding.data(coder, key: Keys.candidateDigest),
      let runIDDigest = QualificationXPCCoding.data(coder, key: Keys.runIDDigest)
    else { return nil }
    self.init(
      protocolVersion: protocolVersion, candidateDigest: candidateDigest, runIDDigest: runIDDigest)
  }

  public func encode(with coder: NSCoder) {
    coder.encode(NSNumber(value: protocolVersion), forKey: Keys.protocolVersion)
    coder.encode(candidateDigest as NSData, forKey: Keys.candidateDigest)
    coder.encode(runIDDigest as NSData, forKey: Keys.runIDDigest)
  }

  private enum Keys {
    static let protocolVersion = "protocol_version"
    static let candidateDigest = "candidate_digest"
    static let runIDDigest = "run_id_digest"
  }
}

/// A secret-free status and receipt. The only strings admitted are the three
/// fixed values in `AgentPassQualificationXPCContract.Status`.
@objc(AgentPassQualificationStatusResponse)
public final class AgentPassQualificationStatusResponse: NSObject, NSSecureCoding {
  public static var supportsSecureCoding: Bool { true }

  public let protocolVersion: Int
  public let status: String
  public let faultPhaseDigest: Data
  public let candidateDigest: Data
  public let sourceCommitDigest: Data
  public let codeIdentityDigest: Data
  public let runIDDigest: Data
  public let receiptDigest: Data

  public init?(
    protocolVersion: Int = AgentPassQualificationXPCContract.protocolVersion,
    status: AgentPassQualificationXPCContract.Status,
    faultPhaseDigest: Data,
    candidateDigest: Data,
    sourceCommitDigest: Data,
    codeIdentityDigest: Data,
    runIDDigest: Data,
    receiptDigest: Data
  ) {
    guard protocolVersion == AgentPassQualificationXPCContract.protocolVersion,
      AgentPassQualificationXPCContract.Status.allCases.contains(status),
      AgentPassQualificationXPCContract.isDigest(faultPhaseDigest),
      AgentPassQualificationXPCContract.isDigest(candidateDigest),
      AgentPassQualificationXPCContract.isDigest(sourceCommitDigest),
      AgentPassQualificationXPCContract.isDigest(codeIdentityDigest),
      AgentPassQualificationXPCContract.isDigest(runIDDigest),
      AgentPassQualificationXPCContract.isDigest(receiptDigest)
    else { return nil }
    self.protocolVersion = protocolVersion
    self.status = status.rawValue
    self.faultPhaseDigest = faultPhaseDigest
    self.candidateDigest = candidateDigest
    self.sourceCommitDigest = sourceCommitDigest
    self.codeIdentityDigest = codeIdentityDigest
    self.runIDDigest = runIDDigest
    self.receiptDigest = receiptDigest
    super.init()
  }

  public required convenience init?(coder: NSCoder) {
    guard let values = QualificationXPCCoding.commonResponseValues(coder, keys: Keys.self),
      let status = AgentPassQualificationXPCContract.Status(rawValue: values.status),
      let faultPhaseDigest = QualificationXPCCoding.data(coder, key: Keys.faultPhaseDigest),
      let receiptDigest = QualificationXPCCoding.data(coder, key: Keys.receiptDigest)
    else { return nil }
    self.init(
      protocolVersion: values.protocolVersion,
      status: status,
      faultPhaseDigest: faultPhaseDigest,
      candidateDigest: values.candidateDigest,
      sourceCommitDigest: values.sourceCommitDigest,
      codeIdentityDigest: values.codeIdentityDigest,
      runIDDigest: values.runIDDigest,
      receiptDigest: receiptDigest
    )
  }

  public func encode(with coder: NSCoder) {
    QualificationXPCCoding.encodeCommonResponse(
      protocolVersion: protocolVersion,
      status: status,
      candidateDigest: candidateDigest,
      sourceCommitDigest: sourceCommitDigest,
      codeIdentityDigest: codeIdentityDigest,
      runIDDigest: runIDDigest,
      coder: coder,
      keys: Keys.self
    )
    coder.encode(faultPhaseDigest as NSData, forKey: Keys.faultPhaseDigest)
    coder.encode(receiptDigest as NSData, forKey: Keys.receiptDigest)
  }

  private enum Keys {
    static let protocolVersion = "protocol_version"
    static let status = "status"
    static let candidateDigest = "candidate_digest"
    static let sourceCommitDigest = "source_commit_digest"
    static let codeIdentityDigest = "code_identity_digest"
    static let runIDDigest = "run_id_digest"
    static let faultPhaseDigest = "fault_phase_digest"
    static let receiptDigest = "receipt_digest"
  }
}

/// Request to disarm the exact receipt identified by its candidate/run
/// binding. The prior receipt digest prevents a caller from disarming another
/// qualification run.
@objc(AgentPassQualificationDisarmRequest)
public final class AgentPassQualificationDisarmRequest: NSObject, NSSecureCoding {
  public static var supportsSecureCoding: Bool { true }

  public let protocolVersion: Int
  public let candidateDigest: Data
  public let runIDDigest: Data
  public let receiptDigest: Data

  public init?(
    protocolVersion: Int = AgentPassQualificationXPCContract.protocolVersion,
    candidateDigest: Data,
    runIDDigest: Data,
    receiptDigest: Data
  ) {
    guard protocolVersion == AgentPassQualificationXPCContract.protocolVersion,
      AgentPassQualificationXPCContract.isDigest(candidateDigest),
      AgentPassQualificationXPCContract.isDigest(runIDDigest),
      AgentPassQualificationXPCContract.isDigest(receiptDigest)
    else { return nil }
    self.protocolVersion = protocolVersion
    self.candidateDigest = candidateDigest
    self.runIDDigest = runIDDigest
    self.receiptDigest = receiptDigest
    super.init()
  }

  public required convenience init?(coder: NSCoder) {
    guard let protocolVersion = QualificationXPCCoding.int(coder, key: Keys.protocolVersion),
      let candidateDigest = QualificationXPCCoding.data(coder, key: Keys.candidateDigest),
      let runIDDigest = QualificationXPCCoding.data(coder, key: Keys.runIDDigest),
      let receiptDigest = QualificationXPCCoding.data(coder, key: Keys.receiptDigest)
    else { return nil }
    self.init(
      protocolVersion: protocolVersion,
      candidateDigest: candidateDigest,
      runIDDigest: runIDDigest,
      receiptDigest: receiptDigest
    )
  }

  public func encode(with coder: NSCoder) {
    coder.encode(NSNumber(value: protocolVersion), forKey: Keys.protocolVersion)
    coder.encode(candidateDigest as NSData, forKey: Keys.candidateDigest)
    coder.encode(runIDDigest as NSData, forKey: Keys.runIDDigest)
    coder.encode(receiptDigest as NSData, forKey: Keys.receiptDigest)
  }

  private enum Keys {
    static let protocolVersion = "protocol_version"
    static let candidateDigest = "candidate_digest"
    static let runIDDigest = "run_id_digest"
    static let receiptDigest = "receipt_digest"
  }
}

/// Secret-free acknowledgement of disarm.
@objc(AgentPassQualificationDisarmResponse)
public final class AgentPassQualificationDisarmResponse: NSObject, NSSecureCoding {
  public static var supportsSecureCoding: Bool { true }

  public let protocolVersion: Int
  public let status: String
  public let candidateDigest: Data
  public let runIDDigest: Data
  public let receiptDigest: Data

  public init?(
    protocolVersion: Int = AgentPassQualificationXPCContract.protocolVersion,
    status: AgentPassQualificationXPCContract.Status = .disarmed,
    candidateDigest: Data,
    runIDDigest: Data,
    receiptDigest: Data
  ) {
    guard protocolVersion == AgentPassQualificationXPCContract.protocolVersion,
      status == .disarmed,
      AgentPassQualificationXPCContract.isDigest(candidateDigest),
      AgentPassQualificationXPCContract.isDigest(runIDDigest),
      AgentPassQualificationXPCContract.isDigest(receiptDigest)
    else { return nil }
    self.protocolVersion = protocolVersion
    self.status = status.rawValue
    self.candidateDigest = candidateDigest
    self.runIDDigest = runIDDigest
    self.receiptDigest = receiptDigest
    super.init()
  }

  public required convenience init?(coder: NSCoder) {
    guard let protocolVersion = QualificationXPCCoding.int(coder, key: Keys.protocolVersion),
      let statusValue = QualificationXPCCoding.string(coder, key: Keys.status),
      let status = AgentPassQualificationXPCContract.Status(rawValue: statusValue),
      status == .disarmed,
      let candidateDigest = QualificationXPCCoding.data(coder, key: Keys.candidateDigest),
      let runIDDigest = QualificationXPCCoding.data(coder, key: Keys.runIDDigest),
      let receiptDigest = QualificationXPCCoding.data(coder, key: Keys.receiptDigest)
    else { return nil }
    self.init(
      protocolVersion: protocolVersion,
      status: status,
      candidateDigest: candidateDigest,
      runIDDigest: runIDDigest,
      receiptDigest: receiptDigest
    )
  }

  public func encode(with coder: NSCoder) {
    coder.encode(NSNumber(value: protocolVersion), forKey: Keys.protocolVersion)
    coder.encode(status as NSString, forKey: Keys.status)
    coder.encode(candidateDigest as NSData, forKey: Keys.candidateDigest)
    coder.encode(runIDDigest as NSData, forKey: Keys.runIDDigest)
    coder.encode(receiptDigest as NSData, forKey: Keys.receiptDigest)
  }

  private enum Keys {
    static let protocolVersion = "protocol_version"
    static let status = "status"
    static let candidateDigest = "candidate_digest"
    static let runIDDigest = "run_id_digest"
    static let receiptDigest = "receipt_digest"
  }
}

/// Registers exactly the DTO used by each argument and reply position. No
/// NSObject, NSString, NSData, or unrelated production DTO is registered as a
/// wildcard, so an endpoint cannot silently widen this contract.
public enum AgentPassQualificationXPCInterface {
  public static func make() -> NSXPCInterface {
    let interface = NSXPCInterface(with: AgentPassQualificationXPCProtocol.self)
    register(
      AgentPassQualificationArmFaultRequest.self, on: interface,
      selector: #selector(AgentPassQualificationXPCProtocol.armFault(_:withReply:)))
    register(
      AgentPassQualificationArmFaultResponse.self, on: interface,
      selector: #selector(AgentPassQualificationXPCProtocol.armFault(_:withReply:)), reply: true)
    register(
      AgentPassQualificationStatusRequest.self, on: interface,
      selector: #selector(AgentPassQualificationXPCProtocol.readStatus(_:withReply:)))
    register(
      AgentPassQualificationStatusResponse.self, on: interface,
      selector: #selector(AgentPassQualificationXPCProtocol.readStatus(_:withReply:)), reply: true)
    register(
      AgentPassQualificationDisarmRequest.self, on: interface,
      selector: #selector(AgentPassQualificationXPCProtocol.disarmFault(_:withReply:)))
    register(
      AgentPassQualificationDisarmResponse.self, on: interface,
      selector: #selector(AgentPassQualificationXPCProtocol.disarmFault(_:withReply:)), reply: true)
    return interface
  }

  private static func register(
    _ type: AnyClass, on interface: NSXPCInterface, selector: Selector, reply: Bool = false
  ) {
    interface.setClasses(
      NSSet(array: [type]) as! Set<AnyHashable>, for: selector, argumentIndex: 0, ofReply: reply)
  }
}

private enum QualificationXPCCoding {
  struct CommonResponseValues {
    let protocolVersion: Int
    let status: String
    let candidateDigest: Data
    let sourceCommitDigest: Data
    let codeIdentityDigest: Data
    let runIDDigest: Data
  }

  static func int(_ coder: NSCoder, key: String) -> Int? {
    guard coder.containsValue(forKey: key),
      let number = coder.decodeObject(of: NSNumber.self, forKey: key)
    else { return nil }
    return number.intValue
  }

  static func string(_ coder: NSCoder, key: String) -> String? {
    guard coder.containsValue(forKey: key),
      let value = coder.decodeObject(of: NSString.self, forKey: key) as String?
    else { return nil }
    return value
  }

  static func data(_ coder: NSCoder, key: String) -> Data? {
    guard coder.containsValue(forKey: key),
      let value = coder.decodeObject(of: NSData.self, forKey: key) as Data?
    else { return nil }
    return value
  }

  static func commonResponseValues(_ coder: NSCoder, keys: Any.Type) -> CommonResponseValues? {
    let protocolKey = "protocol_version"
    let statusKey = "status"
    let candidateKey = "candidate_digest"
    let sourceKey = "source_commit_digest"
    let codeIdentityKey = "code_identity_digest"
    let runIDKey = "run_id_digest"
    guard let protocolVersion = int(coder, key: protocolKey),
      let status = string(coder, key: statusKey),
      let candidateDigest = data(coder, key: candidateKey),
      let sourceCommitDigest = data(coder, key: sourceKey),
      let codeIdentityDigest = data(coder, key: codeIdentityKey),
      let runIDDigest = data(coder, key: runIDKey),
      protocolVersion == AgentPassQualificationXPCContract.protocolVersion,
      AgentPassQualificationXPCContract.isDigest(candidateDigest),
      AgentPassQualificationXPCContract.isDigest(sourceCommitDigest),
      AgentPassQualificationXPCContract.isDigest(codeIdentityDigest),
      AgentPassQualificationXPCContract.isDigest(runIDDigest)
    else { return nil }
    return CommonResponseValues(
      protocolVersion: protocolVersion,
      status: status,
      candidateDigest: candidateDigest,
      sourceCommitDigest: sourceCommitDigest,
      codeIdentityDigest: codeIdentityDigest,
      runIDDigest: runIDDigest
    )
  }

  static func encodeCommonResponse<K>(
    protocolVersion: Int,
    status: String,
    candidateDigest: Data,
    sourceCommitDigest: Data,
    codeIdentityDigest: Data,
    runIDDigest: Data,
    coder: NSCoder,
    keys: K.Type
  ) {
    coder.encode(NSNumber(value: protocolVersion), forKey: "protocol_version")
    coder.encode(status as NSString, forKey: "status")
    coder.encode(candidateDigest as NSData, forKey: "candidate_digest")
    coder.encode(sourceCommitDigest as NSData, forKey: "source_commit_digest")
    coder.encode(codeIdentityDigest as NSData, forKey: "code_identity_digest")
    coder.encode(runIDDigest as NSData, forKey: "run_id_digest")
  }
}
