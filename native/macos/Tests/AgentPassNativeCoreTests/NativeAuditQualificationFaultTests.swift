import Foundation
import Testing

@testable import AgentPassNativeCore

private enum NativeAuditQualificationFault: Error, Equatable {
  case injected
}

private struct ThrowingNativeAuditDurabilityFaultConsumer:
  NativeAuditDurabilityQualificationFaultConsuming, Sendable
{
  func reachBeforeAgentActivationFsync() throws {
    throw NativeAuditQualificationFault.injected
  }
}

private final class CountingNativeAuditDurabilityFaultConsumer:
  NativeAuditDurabilityQualificationFaultConsuming, @unchecked Sendable
{
  private let lock = NSLock()
  private var invocationCount = 0

  func reachBeforeAgentActivationFsync() throws {
    lock.lock()
    invocationCount += 1
    lock.unlock()
  }

  var count: Int {
    lock.lock()
    defer { lock.unlock() }
    return invocationCount
  }
}

private struct NativeAuditQualificationFixture {
  let root: URL
  let file: URL
  let sessionID = UUID(uuidString: "11111111-1111-4111-8111-111111111111")!
  let agentID = UUID(uuidString: "22222222-2222-4222-8222-222222222222")!
  let evidenceDigest = Data(repeating: 0xab, count: 32)

  init() throws {
    root = FileManager.default.temporaryDirectory
      .appendingPathComponent("agentpass-audit-qualification-\(UUID().uuidString)")
    file = root.appendingPathComponent("audit.jsonl")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
  }

  func remove() {
    try? FileManager.default.removeItem(at: root)
  }

  func activationEvent() -> NativeAuditEvent {
    NativeAuditEvent(
      operation: "agent.session.session_activated",
      decision: "allow",
      requestID: sessionID.uuidString,
      agentID: agentID.uuidString,
      payloadSHA256: evidenceDigest.map { String(format: "%02x", $0) }.joined()
    )
  }
}

@Test("the default audit durability qualification consumer is a no-op")
func nativeAuditActivationAppendWithNoopQualificationConsumerSucceeds() throws {
  let fixture = try NativeAuditQualificationFixture()
  defer { fixture.remove() }

  let log = try NativeAuditLog(path: fixture.file.path)
  let status = try log.append(fixture.activationEvent(), timestamp: Date(timeIntervalSince1970: 1))

  #expect(status.entries == 1)
  #expect(try log.verify() == status)
  #expect(
    try log.lookupAgentSessionActivationAudit(
      sessionID: fixture.sessionID,
      expectedAgentID: fixture.agentID,
      evidenceDigest: fixture.evidenceDigest
    ) == .exact(try NativeAuditRecordReceipt(index: 1, recordHash: status.headHash))
  )
}

@Test("a fault immediately before activation fsync reports failure but preserves the record")
func nativeAuditActivationFsyncQualificationFailureKeepsExactDurableRecord() throws {
  let fixture = try NativeAuditQualificationFixture()
  defer { fixture.remove() }

  let log = try NativeAuditLog(
    path: fixture.file.path,
    durabilityQualificationFaultConsumer: ThrowingNativeAuditDurabilityFaultConsumer()
  )

  #expect(throws: NativeAuditQualificationFault.self) {
    try log.append(fixture.activationEvent(), timestamp: Date(timeIntervalSince1970: 1))
  }

  // The consumer runs after the complete JSONL record has been written. A
  // real fsync boundary can therefore leave a valid record even though the
  // caller receives an error and must treat the outcome as ambiguous.
  let bytes = try Data(contentsOf: fixture.file)
  #expect(bytes.last == 0x0a)
  #expect(bytes.split(separator: 0x0a, omittingEmptySubsequences: true).count == 1)

  let restarted = try NativeAuditLog(path: fixture.file.path)
  let status = try restarted.verify()
  #expect(status.entries == 1)
  #expect(
    try restarted.lookupAgentSessionActivationAudit(
      sessionID: fixture.sessionID,
      expectedAgentID: fixture.agentID,
      evidenceDigest: fixture.evidenceDigest
    ) == .exact(try NativeAuditRecordReceipt(index: 1, recordHash: status.headHash))
  )
}

@Test("non-agent and non-activation audit events do not reach the qualification consumer")
func nativeAuditQualificationConsumerIsScopedToAgentActivation() throws {
  let fixture = try NativeAuditQualificationFixture()
  defer { fixture.remove() }

  let consumer = CountingNativeAuditDurabilityFaultConsumer()
  let log = try NativeAuditLog(
    path: fixture.file.path,
    durabilityQualificationFaultConsumer: consumer
  )

  _ = try log.append(
    NativeAuditEvent(operation: "session.session_activated", decision: "allow"),
    timestamp: Date(timeIntervalSince1970: 1)
  )
  _ = try log.append(
    NativeAuditEvent(operation: "agent.session.session_started", decision: "allow"),
    timestamp: Date(timeIntervalSince1970: 2)
  )
  _ = try log.append(
    NativeAuditEvent(operation: "agent.session.session_activated", decision: "allow"),
    timestamp: Date(timeIntervalSince1970: 3)
  )

  #expect(consumer.count == 1)
  #expect(try log.verify().entries == 3)
}
