import Foundation
import Testing

@testable import AgentPassNativeCore

private let reconciliationSessionID = UUID(uuidString: "11111111-1111-4111-8111-111111111111")!
private let reconciliationOtherSessionID = UUID(uuidString: "22222222-2222-4222-8222-222222222222")!
private let reconciliationAgentID = UUID(uuidString: "33333333-3333-4333-8333-333333333333")!
private let reconciliationOtherAgentID = UUID(uuidString: "44444444-4444-4444-8444-444444444444")!
private let reconciliationDigest = Data(repeating: 0xab, count: 32)
private let reconciliationOtherDigest = Data(repeating: 0xcd, count: 32)

private func reconciliationRoot() throws -> URL {
  let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  try FileManager.default.createDirectory(
    at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
  return root
}

private func reconciliationHex(_ data: Data) -> String {
  data.map { String(format: "%02x", $0) }.joined()
}

private func appendActivation(
  to log: NativeAuditLog, sessionID: UUID = reconciliationSessionID,
  agentID: UUID = reconciliationAgentID, digest: Data = reconciliationDigest,
  timestamp: TimeInterval = 1, reason: String? = nil
) throws -> NativeAuditStatus {
  try log.append(
    NativeAuditEvent(
      operation: "agent.session.session_activated",
      decision: "allow",
      requestID: sessionID.uuidString.lowercased(),
      reason: reason,
      agentID: agentID.uuidString.lowercased(),
      payloadSHA256: reconciliationHex(digest)
    ),
    timestamp: Date(timeIntervalSince1970: timestamp)
  )
}

@Test func nativeAuditAgentSessionActivationLookupReturnsVerifiedReceiptAndNeverAppends() throws {
  let root = try reconciliationRoot()
  defer { try? FileManager.default.removeItem(at: root) }
  let file = root.appendingPathComponent("audit.jsonl")
  let log = try NativeAuditLog(path: file.path)
  _ = try log.append(
    NativeAuditEvent(operation: "session.start", decision: "allow"),
    timestamp: Date(timeIntervalSince1970: 0))
  let activation = try appendActivation(to: log)
  let bytesBefore = try Data(contentsOf: file)

  let dataResult = try log.lookupAgentSessionActivationAudit(
    sessionID: reconciliationSessionID, expectedAgentID: reconciliationAgentID,
    evidenceDigest: reconciliationDigest)
  let hexResult = try log.lookupAgentSessionActivationAudit(
    sessionID: reconciliationSessionID, expectedAgentID: reconciliationAgentID,
    evidenceDigest: reconciliationHex(reconciliationDigest))
  #expect(
    dataResult
      == .exact(
        try NativeAuditRecordReceipt(index: activation.entries, recordHash: activation.headHash)))
  #expect(hexResult == dataResult)
  #expect(
    try log.lookupAgentSessionActivationAudit(
      sessionID: reconciliationOtherSessionID, expectedAgentID: reconciliationAgentID,
      evidenceDigest: reconciliationDigest) == .conflict)
  #expect(
    try log.lookupAgentSessionActivationAudit(
      sessionID: reconciliationSessionID, expectedAgentID: reconciliationOtherAgentID,
      evidenceDigest: reconciliationDigest) == .conflict)
  #expect(try Data(contentsOf: file) == bytesBefore)
  #expect(try log.verify() == activation)
}

@Test func nativeAuditAgentSessionActivationLookupScansRotatedArchives() throws {
  let root = try reconciliationRoot()
  defer { try? FileManager.default.removeItem(at: root) }
  let archive = root.appendingPathComponent("archive")
  try FileManager.default.createDirectory(
    at: archive, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
  let log = try NativeAuditLog(
    path: root.appendingPathComponent("audit.jsonl").path, archiveDirectory: archive.path)
  let activation = try appendActivation(to: log)
  let rotation = try log.rotate(minimumBytes: 1)
  _ = try log.append(
    NativeAuditEvent(operation: "session.close", decision: "allow"),
    timestamp: Date(timeIntervalSince1970: 2))

  let result = try log.lookupAgentSessionActivationAudit(
    sessionID: reconciliationSessionID, expectedAgentID: reconciliationAgentID,
    evidenceDigest: reconciliationDigest)
  #expect(result == .exact(try NativeAuditRecordReceipt(index: 1, recordHash: rotation.headHash)))
  #expect(try log.verify().entries == 2)
  #expect(activation.entries == 1)
}

@Test func nativeAuditAgentSessionActivationLookupRejectsDuplicatesAndSubstitution() throws {
  let root = try reconciliationRoot()
  defer { try? FileManager.default.removeItem(at: root) }
  let duplicateLog = try NativeAuditLog(path: root.appendingPathComponent("duplicate.jsonl").path)
  _ = try appendActivation(to: duplicateLog)
  _ = try appendActivation(to: duplicateLog, timestamp: 2)
  #expect(
    try duplicateLog.lookupAgentSessionActivationAudit(
      sessionID: reconciliationSessionID, expectedAgentID: reconciliationAgentID,
      evidenceDigest: reconciliationDigest) == .conflict)

  let substitutionLog = try NativeAuditLog(
    path: root.appendingPathComponent("substitution.jsonl").path)
  _ = try appendActivation(to: substitutionLog, digest: reconciliationOtherDigest)
  #expect(
    try substitutionLog.lookupAgentSessionActivationAudit(
      sessionID: reconciliationSessionID, expectedAgentID: reconciliationAgentID,
      evidenceDigest: reconciliationDigest) == .conflict)

  let agentSubstitutionLog = try NativeAuditLog(
    path: root.appendingPathComponent("agent-substitution.jsonl").path)
  _ = try appendActivation(to: agentSubstitutionLog, agentID: reconciliationOtherAgentID)
  #expect(
    try agentSubstitutionLog.lookupAgentSessionActivationAudit(
      sessionID: reconciliationSessionID, expectedAgentID: reconciliationAgentID,
      evidenceDigest: reconciliationDigest) == .conflict)

  let digestCollisionLog = try NativeAuditLog(
    path: root.appendingPathComponent("digest-collision.jsonl").path)
  _ = try appendActivation(to: digestCollisionLog, sessionID: reconciliationOtherSessionID)
  #expect(
    try digestCollisionLog.lookupAgentSessionActivationAudit(
      sessionID: reconciliationSessionID, expectedAgentID: reconciliationAgentID,
      evidenceDigest: reconciliationDigest) == .conflict)
}

@Test
func nativeAuditAgentSessionActivationLookupRejectsMalformedInputsAndNonCanonicalOrTamperedStorage()
  throws
{
  let root = try reconciliationRoot()
  defer { try? FileManager.default.removeItem(at: root) }
  let file = root.appendingPathComponent("audit.jsonl")
  let log = try NativeAuditLog(path: file.path)
  _ = try appendActivation(to: log)
  #expect(throws: AgentPassNativeError.self) {
    try log.lookupAgentSessionActivationAudit(
      sessionID: reconciliationSessionID, expectedAgentID: reconciliationAgentID,
      evidenceDigest: Data(repeating: 0, count: 31))
  }
  #expect(throws: AgentPassNativeError.self) {
    try log.lookupAgentSessionActivationAudit(
      sessionID: reconciliationSessionID, expectedAgentID: reconciliationAgentID,
      evidenceDigest: reconciliationHex(reconciliationDigest).uppercased())
  }

  var lines = try String(contentsOf: file, encoding: .utf8).split(
    separator: "\n", omittingEmptySubsequences: false
  ).map(String.init)
  lines[0] = "  \(lines[0])"
  try Data(lines.joined(separator: "\n").utf8).write(to: file)
  #expect(throws: AgentPassNativeError.self) {
    try log.lookupAgentSessionActivationAudit(
      sessionID: reconciliationSessionID, expectedAgentID: reconciliationAgentID,
      evidenceDigest: reconciliationDigest)
  }

  let tamperedFile = root.appendingPathComponent("tampered.jsonl")
  let tamperedLog = try NativeAuditLog(path: tamperedFile.path)
  _ = try appendActivation(to: tamperedLog)
  var tampered = try Data(contentsOf: tamperedFile)
  tampered[tampered.startIndex] ^= 1
  try tampered.write(to: tamperedFile)
  #expect(throws: AgentPassNativeError.self) {
    try tamperedLog.lookupAgentSessionActivationAudit(
      sessionID: reconciliationSessionID, expectedAgentID: reconciliationAgentID,
      evidenceDigest: reconciliationDigest)
  }

  let extraFieldLog = try NativeAuditLog(
    path: root.appendingPathComponent("extra-field.jsonl").path)
  _ = try appendActivation(to: extraFieldLog, reason: "unexpected")
  #expect(throws: AgentPassNativeError.self) {
    try extraFieldLog.lookupAgentSessionActivationAudit(
      sessionID: reconciliationSessionID, expectedAgentID: reconciliationAgentID,
      evidenceDigest: reconciliationDigest)
  }
}

@Test func nativeAuditActivationOutcomeLookupAcceptsOnlyTheExactClosedOutcome() throws {
  let cases: [(NativeAgentSessionAuditAction, String, String)] = [
    (.sessionActivated, "agent.session.session_activated", "allow"),
    (.sessionActivationAborted, "agent.session.session_activation_aborted", "deny"),
    (
      .sessionActivationOutcomeUnknown,
      "agent.session.session_activation_outcome_unknown",
      "error"
    ),
  ]

  for (action, operation, decision) in cases {
    let root = try reconciliationRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let log = try NativeAuditLog(path: root.appendingPathComponent("audit.jsonl").path)
    let status = try log.append(
      NativeAuditEvent(
        operation: operation,
        decision: decision,
        requestID: reconciliationSessionID.uuidString.lowercased(),
        agentID: reconciliationAgentID.uuidString.lowercased(),
        payloadSHA256: reconciliationHex(reconciliationDigest)
      ),
      timestamp: Date(timeIntervalSince1970: 1)
    )

    #expect(
      try log.lookupAgentSessionActivationOutcomeAudit(
        action: action,
        sessionID: reconciliationSessionID,
        expectedAgentID: reconciliationAgentID,
        evidenceDigest: reconciliationDigest
      ) == .exact(
        try NativeAuditRecordReceipt(index: status.entries, recordHash: status.headHash))
    )
  }
}

@Test func nativeAuditActivationOutcomeLookupRejectsCrossOutcomeSubstitution() throws {
  let root = try reconciliationRoot()
  defer { try? FileManager.default.removeItem(at: root) }
  let log = try NativeAuditLog(path: root.appendingPathComponent("audit.jsonl").path)
  _ = try log.append(
    NativeAuditEvent(
      operation: "agent.session.session_activation_outcome_unknown",
      decision: "error",
      requestID: reconciliationSessionID.uuidString.lowercased(),
      agentID: reconciliationAgentID.uuidString.lowercased(),
      payloadSHA256: reconciliationHex(reconciliationDigest)
    ),
    timestamp: Date(timeIntervalSince1970: 1)
  )

  #expect(
    try log.lookupAgentSessionActivationOutcomeAudit(
      action: .sessionActivated,
      sessionID: reconciliationSessionID,
      expectedAgentID: reconciliationAgentID,
      evidenceDigest: reconciliationDigest
    ) == .conflict
  )

  let malformed = try NativeAuditLog(
    path: root.appendingPathComponent("wrong-decision.jsonl").path)
  _ = try malformed.append(
    NativeAuditEvent(
      operation: "agent.session.session_activation_aborted",
      decision: "allow",
      requestID: reconciliationSessionID.uuidString.lowercased(),
      agentID: reconciliationAgentID.uuidString.lowercased(),
      payloadSHA256: reconciliationHex(reconciliationDigest)
    ),
    timestamp: Date(timeIntervalSince1970: 1)
  )
  #expect(throws: AgentPassNativeError.self) {
    try malformed.lookupAgentSessionActivationOutcomeAudit(
      action: .sessionActivationAborted,
      sessionID: reconciliationSessionID,
      expectedAgentID: reconciliationAgentID,
      evidenceDigest: reconciliationDigest)
  }
}
