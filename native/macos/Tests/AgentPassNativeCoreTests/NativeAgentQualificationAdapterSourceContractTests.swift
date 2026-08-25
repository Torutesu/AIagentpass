import Foundation
import Testing

private func nativeServiceSource() throws -> String {
  let testDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
  let sourceURL = testDirectory
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .appendingPathComponent("Sources/AgentPassNativeService/main.swift")
  return try String(contentsOf: sourceURL, encoding: .utf8)
}

private func qualificationControllerSource() throws -> String {
  let testDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
  let sourceURL = testDirectory
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .appendingPathComponent("Sources/AgentPassQualificationController/main.swift")
  return try String(contentsOf: sourceURL, encoding: .utf8)
}

private func sourceSlice(_ source: String, from marker: String, to endMarker: String) throws -> String {
  let start = try #require(source.range(of: marker))
  let remainder = source[start.upperBound...]
  guard let end = remainder.range(of: endMarker) else {
    Issue.record("qualification adapter source boundary is missing")
    return ""
  }
  return String(remainder[..<end.lowerBound])
}

@Test("all six qualification adapters persist fired evidence before injecting")
func qualificationAdaptersPersistBeforeFaultAction() throws {
  let source = try nativeServiceSource()
  #expect(source.contains("try? durableReceiptStore.writeInjected") == false)
  #expect(source.components(separatedBy: "try durableReceiptStore.writeInjected(").count - 1 == 3)

  let coordinator = try sourceSlice(
    source,
    from: "private final class NativeAgentSessionQualificationFaultConsumerAdapter",
    to: "private final class NativeAgentAuditDurabilityQualificationFaultConsumerAdapter")
  let audit = try sourceSlice(
    source,
    from: "private final class NativeAgentAuditDurabilityQualificationFaultConsumerAdapter",
    to: "private final class NativeAgentTransportReplyQualificationFaultConsumerAdapter")
  let transport = try sourceSlice(
    source,
    from: "private final class NativeAgentTransportReplyQualificationFaultConsumerAdapter",
    to: "private final class AgentRuntimeDependencies")

  #expect(coordinator.contains("guard receipt.outcome == .injected else { return }"))
  #expect(coordinator.range(of: "try durableReceiptStore.writeInjected")!.lowerBound < coordinator.range(of: "fatalAction()")!.lowerBound)
  #expect(audit.range(of: "try durableReceiptStore.writeInjected")!.lowerBound < audit.range(of: "throw AgentPassNativeError")!.lowerBound)
  #expect(transport.range(of: "guard receipt.outcome == .injected else { return false }") != nil)
  #expect(transport.range(of: "try durableReceiptStore.writeInjected")!.lowerBound < transport.range(of: "return true")!.lowerBound)
  #expect(transport.contains("A failed durable commit is not an injected transport fault."))
  #expect(transport.contains("// not drop the reply when the evidence boundary is unavailable."))
}

@Test("qualification runtime shares one root-owned durable receipt store")
func qualificationRuntimeWiresOneDurableStore() throws {
  let source = try nativeServiceSource()
  let runtime = try sourceSlice(
    source,
    from: "private final class QualificationRuntime",
    to: "private func bootstrapInput")
  #expect(runtime.contains("let durableReceiptStore = try NativeAgentQualificationDurableReceiptStore()"))
  #expect(runtime.components(separatedBy: "durableReceiptStore: durableReceiptStore").count - 1 == 3)
}

@Test("controller disarm recovers only an exact durable receipt after XPC loss")
func qualificationControllerHasDigestBoundRecovery() throws {
  let source = try qualificationControllerSource()
  #expect(source.contains("private func recoverDisarmAfterXPCLoss"))
  #expect(source.contains("try removeDurableReceipt(") )
  #expect(source.contains("durable.armedReceiptDigest"))
  #expect(source.contains("if case .connectionFailure = statusReply"))
  #expect(source.contains("status: AgentPassQualificationXPCContract.Status.disarmed.rawValue"))
  let disarm = try sourceSlice(
    source,
    from: "case .disarm:",
    to: "} catch let failure as ControllerFailure")
  let emptyEndpoint = try #require(disarm.range(
    of: "if current.status == AgentPassQualificationXPCContract.Status.disarmed.rawValue"))
  let remainder = disarm[emptyEndpoint.lowerBound...]
  #expect(remainder.contains("if let durable = try? durableReceipt(context: context)"))
  #expect(remainder.contains("expectedDigest: durable.armedReceiptDigest"))
  #expect(remainder.contains("receipt: durable.armedReceiptDigest"))
}
