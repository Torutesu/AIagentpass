import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore

private struct AuditSoftwareSigner: P256MessageSigner {
    let privateKey = P256.Signing.PrivateKey()
    var publicKeyX963: Data { privateKey.publicKey.x963Representation }
    func sign(message: Data) throws -> Data { try privateKey.signature(for: message).rawRepresentation }
}

@Test func nativeAuditChainsRecordsAndFailsClosedAfterTampering() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let file = root.appendingPathComponent("audit.jsonl")
    let log = try NativeAuditLog(path: file.path)
    try log.append(NativeAuditEvent(operation: "git.commit.sign", decision: "allow", agentID: "agent-one", payloadSHA256: String(repeating: "a", count: 64)), timestamp: Date(timeIntervalSince1970: 1))
    let status = try log.append(NativeAuditEvent(operation: "git.commit.sign", decision: "deny", reason: "branch_denied"), timestamp: Date(timeIntervalSince1970: 2))
    #expect(status.entries == 2)
    #expect(status.headHash.count == 64)
    #expect((try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber)?.intValue == 0o600)

    var lines = try String(contentsOf: file, encoding: .utf8).split(separator: "\n").map(String.init)
    lines[0] = lines[0].replacingOccurrences(of: "agent-one", with: "agent-evil")
    try Data((lines.joined(separator: "\n") + "\n").utf8).write(to: file)
    #expect(throws: AgentPassNativeError.self) { try log.verify() }
    #expect(throws: AgentPassNativeError.self) { try log.append(NativeAuditEvent(operation: "test", decision: "allow")) }
}

@Test func nativeAuditCheckpointsUseASeparateSignedChain() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let log = try NativeAuditLog(path: root.appendingPathComponent("audit.jsonl").path)
    let signer = AuditSoftwareSigner()
    let checkpointFile = root.appendingPathComponent("checkpoints.jsonl")
    let checkpoints = try NativeAuditCheckpoints(path: checkpointFile.path, auditLog: log, signer: signer)
    try log.append(NativeAuditEvent(operation: "one", decision: "allow"), timestamp: Date(timeIntervalSince1970: 1))
    let first = try checkpoints.create(timestamp: Date(timeIntervalSince1970: 2))
    try log.append(NativeAuditEvent(operation: "two", decision: "allow"), timestamp: Date(timeIntervalSince1970: 3))
    let second = try checkpoints.create(timestamp: Date(timeIntervalSince1970: 4))
    #expect(first.entries == 1)
    #expect(second.entries == 2)
    #expect(second.previousCheckpointHash == first.checkpointHash)
    #expect(try checkpoints.verify() == [first, second])

    var records = try String(contentsOf: checkpointFile, encoding: .utf8).split(separator: "\n").map(String.init)
    records[0] = records[0].replacingOccurrences(of: "\"entries\":1", with: "\"entries\":9")
    try Data((records.joined(separator: "\n") + "\n").utf8).write(to: checkpointFile)
    #expect(throws: (any Error).self) { try checkpoints.verify() }
    #expect(throws: (any Error).self) { try checkpoints.create() }
}

@Test func nativeAuditRejectsSymlinkedAndPermissiveFiles() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let target = root.appendingPathComponent("target")
    try Data("\n".utf8).write(to: target)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
    let link = root.appendingPathComponent("link")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
    #expect(throws: AgentPassNativeError.self) { try NativeAuditLog(path: link.path) }
    let brokenLink = root.appendingPathComponent("broken-link")
    try FileManager.default.createSymbolicLink(atPath: brokenLink.path, withDestinationPath: root.appendingPathComponent("missing").path)
    #expect(throws: AgentPassNativeError.self) { try NativeAuditLog(path: brokenLink.path) }
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: target.path)
    #expect(throws: AgentPassNativeError.self) { try NativeAuditLog(path: target.path) }
    #expect(throws: AgentPassNativeError.self) { try NativeAuditCheckpoints(path: "relative.jsonl", auditLog: try NativeAuditLog(path: root.appendingPathComponent("audit.jsonl").path), signer: AuditSoftwareSigner()) }
}

@Test func nativeAuditCheckpointRejectsKeySubstitutionAndAuditTruncation() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let auditFile = root.appendingPathComponent("audit.jsonl")
    let checkpointFile = root.appendingPathComponent("checkpoints.jsonl")
    let log = try NativeAuditLog(path: auditFile.path)
    let signer = AuditSoftwareSigner()
    let checkpoints = try NativeAuditCheckpoints(path: checkpointFile.path, auditLog: log, signer: signer)
    try log.append(NativeAuditEvent(operation: "one", decision: "allow"))
    try log.append(NativeAuditEvent(operation: "two", decision: "allow"))
    _ = try checkpoints.create()

    let substituted = try NativeAuditCheckpoints(path: checkpointFile.path, auditLog: log, signer: AuditSoftwareSigner())
    #expect(throws: AgentPassNativeError.self) { try substituted.verify() }

    let firstAuditRecord = try String(contentsOf: auditFile, encoding: .utf8).split(separator: "\n")[0]
    try Data("\(firstAuditRecord)\n".utf8).write(to: auditFile)
    #expect(throws: AgentPassNativeError.self) { try checkpoints.verify() }
}

@Test func nativeAuditRejectsIncompleteJSONLinesBeforeAppend() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let auditFile = root.appendingPathComponent("audit.jsonl")
    let log = try NativeAuditLog(path: auditFile.path)
    try log.append(NativeAuditEvent(operation: "one", decision: "allow"))
    var data = try Data(contentsOf: auditFile)
    data.removeLast()
    try data.write(to: auditFile)
    #expect(throws: AgentPassNativeError.self) { try log.verify() }
    #expect(throws: AgentPassNativeError.self) { try log.append(NativeAuditEvent(operation: "two", decision: "allow")) }
}

@Test func nativeAuditValidatesSessionExpiryMetadata() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let log = try NativeAuditLog(path: root.appendingPathComponent("audit.jsonl").path)
    try log.append(NativeAuditEvent(operation: "session.start", decision: "allow", expiresAt: "2027-01-15T08:00:00.000Z"))
    #expect(try log.verify().entries == 1)
    #expect(throws: AgentPassNativeError.self) { try log.append(NativeAuditEvent(operation: "session.start", decision: "allow", expiresAt: "not-a-date")) }
}
