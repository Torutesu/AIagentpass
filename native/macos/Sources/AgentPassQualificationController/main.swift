import AgentPassNativeCore
import Darwin
import Foundation

private enum ControllerContract {
  static let serviceConfigurationPath = "/Library/Application Support/AgentPass/native-service.json"
  static let candidateManifestPath =
    "/private/var/db/agentpass-qualification/controller/controller-candidate.json"
  static let candidateSignaturePath =
    "/private/var/db/agentpass-qualification/controller/controller-candidate.sig"
  static let candidatePublicKeyPath =
    "/private/var/db/agentpass-qualification/controller/release-public.pem"
  static let timeout: DispatchTime = .now() + .seconds(5)
}

private enum ControllerFailure: String, Error {
  case invalidCommand = "invalid_command"
  case rootRequired = "root_required"
  case protectedInputUnavailable = "protected_input_unavailable"
  case candidateBindingInvalid = "candidate_binding_invalid"
  case endpointUnavailable = "endpoint_unavailable"
  case endpointRejected = "endpoint_rejected"
  case endpointTimeout = "endpoint_timeout"
  case responseInvalid = "response_invalid"
}

private struct ControllerOutput: Encodable {
  let schemaVersion: Int
  let command: String
  let ok: Bool
  let status: String?
  let candidateSHA256: String?
  let runIDSHA256: String?
  let receiptSHA256: String?
  let error: String?

  enum CodingKeys: String, CodingKey {
    case command, ok, status, error
    case schemaVersion = "schema_version"
    case candidateSHA256 = "candidate_sha256"
    case runIDSHA256 = "run_id_sha256"
    case receiptSHA256 = "receipt_sha256"
  }
}

private func writeOutput(_ value: ControllerOutput) {
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
  let fallback = Data("{\"command\":\"local\",\"error\":\"response_invalid\",\"ok\":false,\"schema_version\":1}".utf8)
  FileHandle.standardOutput.write(((try? encoder.encode(value)) ?? fallback) + Data("\n".utf8))
}

private func emit(_ value: ControllerOutput, status: Int32) -> Never {
  writeOutput(value)
  exit(status)
}

private func fail(_ command: String, _ reason: ControllerFailure, status: Int32 = 1) -> Never {
  emit(
    ControllerOutput(
      schemaVersion: 1, command: command, ok: false, status: nil,
      candidateSHA256: nil, runIDSHA256: nil, receiptSHA256: nil,
      error: reason.rawValue),
    status: status)
}

private func verifyProtectedParents(path: String) throws {
  let url = URL(fileURLWithPath: path).standardizedFileURL
  guard url.path == path, path.hasPrefix("/") else { throw POSIXError(.EINVAL) }
  var current = url.deletingLastPathComponent()
  while true {
    var state = stat()
    guard lstat(current.path, &state) == 0,
      (state.st_mode & S_IFMT) == S_IFDIR,
      state.st_uid == 0,
      (state.st_mode & 0o022) == 0
    else { throw POSIXError(.EPERM) }
    if current.path == "/" { break }
    current.deleteLastPathComponent()
  }
}

private func readProtectedFile(path: String, maximumBytes: Int) throws -> Data {
  try verifyProtectedParents(path: path)
  let descriptor = Darwin.open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
  guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
  defer { Darwin.close(descriptor) }

  var before = stat()
  guard fstat(descriptor, &before) == 0,
    (before.st_mode & S_IFMT) == S_IFREG,
    before.st_uid == 0,
    (before.st_mode & 0o7777) == 0o600,
    before.st_nlink == 1,
    before.st_size > 0,
    before.st_size <= maximumBytes
  else { throw POSIXError(.EPERM) }

  var bytes = Data(count: Int(before.st_size))
  let count = bytes.withUnsafeMutableBytes { buffer -> Int in
    guard let base = buffer.baseAddress else { return -1 }
    var offset = 0
    while offset < buffer.count {
      let amount = Darwin.read(descriptor, base.advanced(by: offset), buffer.count - offset)
      if amount <= 0 { return -1 }
      offset += amount
    }
    return offset
  }
  var after = stat()
  var pathState = stat()
  guard count == bytes.count,
    fstat(descriptor, &after) == 0,
    lstat(path, &pathState) == 0,
    before.st_dev == after.st_dev,
    before.st_ino == after.st_ino,
    before.st_size == after.st_size,
    before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
    before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
    before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
    before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec,
    after.st_dev == pathState.st_dev,
    after.st_ino == pathState.st_ino
  else { throw POSIXError(.EIO) }
  try verifyProtectedParents(path: path)
  return bytes
}

private func hex(_ data: Data) -> String {
  data.map { String(format: "%02x", $0) }.joined()
}

private enum WireReply {
  case arm(AgentPassQualificationArmFaultResponse?, NSError?)
  case status(AgentPassQualificationStatusResponse?, NSError?)
  case disarm(AgentPassQualificationDisarmResponse?, NSError?)
  case connectionFailure
}

private final class ReplyBox: @unchecked Sendable {
  private let lock = NSLock()
  private var value: WireReply?

  func setOnce(_ candidate: WireReply) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard value == nil else { return false }
    value = candidate
    return true
  }

  func get() -> WireReply? {
    lock.lock()
    defer { lock.unlock() }
    return value
  }
}

private final class QualificationClient {
  private let connection: NSXPCConnection

  init() {
    connection = NSXPCConnection(
      machServiceName: AgentPassQualificationXPCContract.machServiceName,
      options: .privileged)
    connection.remoteObjectInterface = AgentPassQualificationXPCContract.makeInterface()
    connection.resume()
  }

  deinit { connection.invalidate() }

  func arm(_ request: AgentPassQualificationArmFaultRequest) throws -> WireReply {
    try execute { proxy, box, semaphore in
    proxy.armFault(request) { response, error in
      if box.setOnce(.arm(response, error)) { semaphore.signal() }
    }
    }
  }

  func status(_ request: AgentPassQualificationStatusRequest) throws -> WireReply {
    try execute { proxy, box, semaphore in
    proxy.readStatus(request) { response, error in
      if box.setOnce(.status(response, error)) { semaphore.signal() }
    }
    }
  }

  func disarm(_ request: AgentPassQualificationDisarmRequest) throws -> WireReply {
    try execute { proxy, box, semaphore in
    proxy.disarmFault(request) { response, error in
      if box.setOnce(.disarm(response, error)) { semaphore.signal() }
    }
    }
  }

  private func execute(
    _ invoke: (
      _ proxy: AgentPassQualificationXPCProtocol,
      _ box: ReplyBox,
      _ semaphore: DispatchSemaphore
    ) -> Void
  ) throws -> WireReply {
    let box = ReplyBox()
    let semaphore = DispatchSemaphore(value: 0)
    let proxy = connection.remoteObjectProxyWithErrorHandler { _ in
      if box.setOnce(.connectionFailure) { semaphore.signal() }
    } as! AgentPassQualificationXPCProtocol
    invoke(proxy, box, semaphore)
    guard semaphore.wait(timeout: ControllerContract.timeout) == .success else {
      throw ControllerFailure.endpointTimeout
    }
    guard let reply = box.get() else { throw ControllerFailure.responseInvalid }
    return reply
  }
}

private func validateCommon(
  context: NativeAgentQualificationControllerContext,
  candidate: Data,
  run: Data
) -> Bool {
  candidate == context.candidateDigest && run == context.runIDDigest
}

private func output(
  command: NativeAgentQualificationControllerCommand,
  context: NativeAgentQualificationControllerContext,
  status: String,
  receipt: Data
) -> Never {
  guard AgentPassQualificationXPCContract.Status(rawValue: status) != nil,
    AgentPassQualificationXPCContract.isDigest(receipt)
  else { fail(command.rawValue, .responseInvalid) }
  emit(
    ControllerOutput(
      schemaVersion: 1, command: command.rawValue, ok: true, status: status,
      candidateSHA256: hex(context.candidateDigest),
      runIDSHA256: hex(context.runIDDigest), receiptSHA256: hex(receipt), error: nil),
    status: 0)
}

private func successValue(
  command: NativeAgentQualificationControllerCommand,
  context: NativeAgentQualificationControllerContext,
  status: String,
  receipt: Data
) -> ControllerOutput? {
  guard AgentPassQualificationXPCContract.Status(rawValue: status) != nil,
    AgentPassQualificationXPCContract.isDigest(receipt)
  else { return nil }
  return ControllerOutput(
    schemaVersion: 1, command: command.rawValue, ok: true, status: status,
    candidateSHA256: hex(context.candidateDigest),
    runIDSHA256: hex(context.runIDDigest), receiptSHA256: hex(receipt), error: nil)
}

private func durableReceipt(
  context: NativeAgentQualificationControllerContext
) throws -> NativeAgentQualificationDurableReceipt? {
  let binding = try NativeAgentQualificationDurableReceiptBinding(
    candidateDigest: context.candidateDigest,
    sourceCommitDigest: context.sourceCommitDigest,
    codeIdentityDigest: context.codeIdentityDigest,
    runIDDigest: context.runIDDigest,
    scenario: context.scenario,
    phase: context.phase)
  return try NativeAgentQualificationDurableReceiptStore().read(expected: binding)
}

private func removeDurableReceipt(
  context: NativeAgentQualificationControllerContext,
  expectedDigest: Data
) throws {
  guard let receipt = try durableReceipt(context: context),
    receipt.armedReceiptDigest == expectedDigest else {
    throw ControllerFailure.responseInvalid
  }
  let binding = receipt.binding
  guard try NativeAgentQualificationDurableReceiptStore().remove(expected: binding) else {
    throw ControllerFailure.responseInvalid
  }
}

private func finishAfterFired(
  client: QualificationClient,
  context: NativeAgentQualificationControllerContext,
  receiptDigest: Data
) -> Never {
  guard let durable = try? durableReceipt(context: context),
    durable.armedReceiptDigest == receiptDigest else {
    fail(NativeAgentQualificationControllerCommand.arm.rawValue, .responseInvalid)
  }

  let disarmRequest: AgentPassQualificationDisarmRequest
  do { disarmRequest = try context.makeDisarmRequest(receiptDigest: receiptDigest) }
  catch { fail(NativeAgentQualificationControllerCommand.arm.rawValue, .responseInvalid) }

  do {
    let reply = try client.disarm(disarmRequest)
    if case .disarm(let response, let error) = reply,
      error == nil, let response,
      response.status == AgentPassQualificationXPCContract.Status.disarmed.rawValue,
      validateCommon(context: context, candidate: response.candidateDigest, run: response.runIDDigest) {
      try removeDurableReceipt(context: context, expectedDigest: receiptDigest)
      output(
        command: .arm, context: context, status: response.status,
        receipt: response.receiptDigest)
    }
  } catch {
    // A daemon restart loses the in-memory endpoint state. The durable
    // receipt is the only accepted recovery authority in that case.
  }

  do {
    try removeDurableReceipt(context: context, expectedDigest: receiptDigest)
    output(
      command: .arm, context: context,
      status: AgentPassQualificationXPCContract.Status.disarmed.rawValue,
      receipt: receiptDigest)
  } catch {
    fail(NativeAgentQualificationControllerCommand.arm.rawValue, .endpointUnavailable)
  }
}

private func recoverDisarmAfterXPCLoss(
  context: NativeAgentQualificationControllerContext
) -> Never {
  guard let durable = try? durableReceipt(context: context) else {
    fail(NativeAgentQualificationControllerCommand.disarm.rawValue, .endpointUnavailable)
  }
  do {
    try removeDurableReceipt(
      context: context, expectedDigest: durable.armedReceiptDigest)
    output(
      command: .disarm, context: context,
      status: AgentPassQualificationXPCContract.Status.disarmed.rawValue,
      receipt: durable.armedReceiptDigest)
  } catch {
    fail(NativeAgentQualificationControllerCommand.disarm.rawValue, .endpointUnavailable)
  }
}

let arguments = Array(CommandLine.arguments.dropFirst())
let command: NativeAgentQualificationControllerCommand
do {
  command = try NativeAgentQualificationControllerCommand.parse(arguments: arguments)
} catch {
  fail("local", .invalidCommand, status: 2)
}

guard geteuid() == 0 else { fail(command.rawValue, .rootRequired) }
for key in ProcessInfo.processInfo.environment.keys {
  unsetenv(key)
}
_ = setenv("PATH", "/usr/bin:/bin:/usr/sbin:/sbin", 1)
_ = umask(0o077)

let serviceData: Data
let manifestData: Data
let signatureData: Data
let publicKeyData: Data
do {
  serviceData = try readProtectedFile(
    path: ControllerContract.serviceConfigurationPath,
    maximumBytes: NativeAgentQualificationControllerContext.maximumServiceConfigurationBytes)
  manifestData = try readProtectedFile(
    path: ControllerContract.candidateManifestPath,
    maximumBytes: NativeAgentQualificationControllerContext.maximumManifestBytes)
  signatureData = try readProtectedFile(
    path: ControllerContract.candidateSignaturePath, maximumBytes: 256)
  publicKeyData = try readProtectedFile(
    path: ControllerContract.candidatePublicKeyPath, maximumBytes: 4 * 1024)
} catch {
  fail(command.rawValue, .protectedInputUnavailable)
}

let context: NativeAgentQualificationControllerContext
do {
  context = try NativeAgentQualificationControllerContext.verify(
    manifestData: manifestData,
    signatureData: signatureData,
    publicKeyPEM: publicKeyData,
    serviceConfigurationData: serviceData)
} catch {
  fail(command.rawValue, .candidateBindingInvalid)
}

do {
  let client = QualificationClient()
  switch command {
  case .arm:
    let request = try context.makeArmRequest()
    let reply = try client.arm(request)
    guard let expectedPhase = AgentPassQualificationXPCContract.FaultPhase(
      rawValue: context.phase.rawValue)
    else { fail(command.rawValue, .candidateBindingInvalid) }
    guard case .arm(let response, let error) = reply, error == nil, let response,
      response.status == AgentPassQualificationXPCContract.Status.armed.rawValue,
      validateCommon(context: context, candidate: response.candidateDigest, run: response.runIDDigest),
      response.sourceCommitDigest == context.sourceCommitDigest,
      response.codeIdentityDigest == context.codeIdentityDigest,
      response.faultPhaseDigest == AgentPassQualificationXPCContract.digest(
        faultPhase: expectedPhase),
      let armedOutput = successValue(
        command: command, context: context, status: response.status,
        receipt: response.receiptDigest)
    else { fail(command.rawValue, .endpointRejected) }
    // The service clears the armed fault when this connection disappears.
    // Keep the controller alive on this exact connection until the boundary
    // fires, then disarm with the original receipt before exiting.
    writeOutput(armedOutput)
    let statusRequest = try context.makeStatusRequest()
    while Date().timeIntervalSince1970 < Double(context.expiresAtEpochSeconds) {
      usleep(100_000)
      let statusReply: WireReply
      do {
        statusReply = try client.status(statusRequest)
      } catch {
        guard let durable = try? durableReceipt(context: context),
          durable.armedReceiptDigest == response.receiptDigest,
          let firedOutput = successValue(
            command: command, context: context,
            status: AgentPassQualificationXPCContract.Status.fired.rawValue,
            receipt: durable.armedReceiptDigest)
        else { fail(command.rawValue, .endpointUnavailable) }
        writeOutput(firedOutput)
        finishAfterFired(client: client, context: context, receiptDigest: durable.armedReceiptDigest)
      }
      guard case .status(let current, let statusError) = statusReply,
        statusError == nil, let current,
        validateCommon(context: context, candidate: current.candidateDigest, run: current.runIDDigest),
        current.sourceCommitDigest == context.sourceCommitDigest,
        current.codeIdentityDigest == context.codeIdentityDigest,
        current.receiptDigest == response.receiptDigest
      else {
        if let durable = try? durableReceipt(context: context),
          durable.armedReceiptDigest == response.receiptDigest {
          let firedOutput = successValue(
            command: command, context: context,
            status: AgentPassQualificationXPCContract.Status.fired.rawValue,
            receipt: durable.armedReceiptDigest)!
          writeOutput(firedOutput)
          finishAfterFired(client: client, context: context, receiptDigest: durable.armedReceiptDigest)
        }
        fail(command.rawValue, .endpointUnavailable)
      }
      if current.status == AgentPassQualificationXPCContract.Status.armed.rawValue { continue }
      guard let durable = try? durableReceipt(context: context) else {
        fail(command.rawValue, .responseInvalid)
      }
      guard current.status == AgentPassQualificationXPCContract.Status.fired.rawValue,
        durable.armedReceiptDigest == current.receiptDigest,
        let firedOutput = successValue(
          command: command, context: context, status: current.status,
          receipt: current.receiptDigest)
      else { fail(command.rawValue, .responseInvalid) }
      writeOutput(firedOutput)
      finishAfterFired(client: client, context: context, receiptDigest: current.receiptDigest)
    }
    fail(command.rawValue, .endpointTimeout)

  case .status:
    let request = try context.makeStatusRequest()
    let reply = try client.status(request)
    guard case .status(let response, let error) = reply, error == nil, let response,
      validateCommon(context: context, candidate: response.candidateDigest, run: response.runIDDigest),
      response.sourceCommitDigest == context.sourceCommitDigest,
      response.codeIdentityDigest == context.codeIdentityDigest
    else { fail(command.rawValue, .endpointRejected) }
    if response.status == AgentPassQualificationXPCContract.Status.fired.rawValue {
      guard let durable = try? durableReceipt(context: context),
        durable.armedReceiptDigest == response.receiptDigest else {
        fail(command.rawValue, .responseInvalid)
      }
    }
    output(command: command, context: context, status: response.status, receipt: response.receiptDigest)

  case .disarm:
    let statusRequest = try context.makeStatusRequest()
    let statusReply: WireReply
    do {
      statusReply = try client.status(statusRequest)
    } catch {
      recoverDisarmAfterXPCLoss(context: context)
    }
    guard case .status(let current, let statusError) = statusReply,
      statusError == nil, let current,
      validateCommon(context: context, candidate: current.candidateDigest, run: current.runIDDigest)
    else {
      if case .connectionFailure = statusReply {
        recoverDisarmAfterXPCLoss(context: context)
      }
      fail(command.rawValue, .endpointRejected)
    }
    if current.status == AgentPassQualificationXPCContract.Status.disarmed.rawValue {
      output(command: command, context: context, status: current.status, receipt: current.receiptDigest)
    }
    if current.status == AgentPassQualificationXPCContract.Status.fired.rawValue {
      guard let durable = try? durableReceipt(context: context),
        durable.armedReceiptDigest == current.receiptDigest else {
        fail(command.rawValue, .responseInvalid)
      }
    }
    let disarmRequest = try context.makeDisarmRequest(receiptDigest: current.receiptDigest)
    let reply = try client.disarm(disarmRequest)
    guard case .disarm(let response, let error) = reply, error == nil, let response,
      response.status == AgentPassQualificationXPCContract.Status.disarmed.rawValue,
      validateCommon(context: context, candidate: response.candidateDigest, run: response.runIDDigest)
    else { fail(command.rawValue, .endpointRejected) }
    if current.status == AgentPassQualificationXPCContract.Status.fired.rawValue {
      do {
        try removeDurableReceipt(context: context, expectedDigest: current.receiptDigest)
      } catch {
        fail(command.rawValue, .responseInvalid)
      }
    }
    output(command: command, context: context, status: response.status, receipt: response.receiptDigest)
  }
} catch let failure as ControllerFailure {
  fail(command.rawValue, failure)
} catch {
  fail(command.rawValue, .responseInvalid)
}
