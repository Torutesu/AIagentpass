import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore

private struct AuditSoftwareSigner: P256MessageSigner {
    let privateKey = P256.Signing.PrivateKey()
    var publicKeyX963: Data { privateKey.publicKey.x963Representation }
    func sign(message: Data) throws -> Data { try privateKey.signature(for: message).rawRepresentation }
}

private func anchorPublicKeyPEM(_ key: Curve25519.Signing.PublicKey) -> String {
    let der = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) + key.rawRepresentation
    return "-----BEGIN PUBLIC KEY-----\n\(der.base64EncodedString())\n-----END PUBLIC KEY-----\n"
}

private func anchorReceiptData(checkpoint: NativeAuditCheckpoint, index: Int, previous: String, tenant: String, key: Curve25519.Signing.PrivateKey, receivedAt: String = "2027-01-15T08:00:00.000Z") throws -> Data {
    let statement: [String: Any] = ["version": 1, "tenant": tenant, "index": index, "checkpoint_hash": checkpoint.checkpointHash, "received_at": receivedAt, "previous_receipt_hash": previous]
    let signature = try key.signature(for: NativeAuditLog.canonical(statement)).base64EncodedString()
    let der = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) + key.publicKey.rawRepresentation
    let fingerprint = "SHA256:" + Data(SHA256.hash(data: der)).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    let ordered = "{\"version\":1,\"tenant\":\"\(tenant)\",\"index\":\(index),\"checkpoint_hash\":\"\(checkpoint.checkpointHash)\",\"received_at\":\"\(receivedAt)\",\"previous_receipt_hash\":\"\(previous)\",\"anchor_key_fingerprint\":\"\(fingerprint)\",\"signature\":\"\(signature)\"}"
    let receiptHash = NativeAuditLog.hash(Data(ordered.utf8))
    let receipt: [String: Any] = statement.merging(["anchor_key_fingerprint": fingerprint, "signature": signature, "receipt_hash": receiptHash]) { current, _ in current }
    return try NativeAuditLog.canonical(receipt)
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

@Test func nativeAuditRotationPreservesChainAndCheckpointContinuity() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let archive = root.appendingPathComponent("archive")
    try FileManager.default.createDirectory(at: archive, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let auditFile = root.appendingPathComponent("audit.jsonl")
    let checkpointFile = root.appendingPathComponent("checkpoints.jsonl")
    let signer = AuditSoftwareSigner()
    let log = try NativeAuditLog(path: auditFile.path, archiveDirectory: archive.path)
    let checkpoints = try NativeAuditCheckpoints(path: checkpointFile.path, auditLog: log, signer: signer)
    try log.append(NativeAuditEvent(operation: "one", decision: "allow"), timestamp: Date(timeIntervalSince1970: 1))
    try log.append(NativeAuditEvent(operation: "two", decision: "deny"), timestamp: Date(timeIntervalSince1970: 2))
    let checkpoint = try checkpoints.create(timestamp: Date(timeIntervalSince1970: 3))
    let rotation = try log.rotate(minimumBytes: 1)
    #expect(rotation.entries == 2)
    #expect(rotation.headHash == checkpoint.headHash)
    #expect(rotation.archiveFile.contains("00000000000000000002"))
    #expect(!FileManager.default.fileExists(atPath: auditFile.path))
    #expect((try FileManager.default.attributesOfItem(atPath: archive.appendingPathComponent(rotation.archiveFile).path)[.posixPermissions] as? NSNumber)?.intValue == 0o400)
    let rotatedStorage = try log.storageStatus()
    #expect(rotatedStorage.configured)
    #expect(rotatedStorage.segments == 1)
    #expect(rotatedStorage.activeBytes == 0)
    #expect(!rotatedStorage.rotationReady)

    let after = try log.append(NativeAuditEvent(operation: "three", decision: "allow"), timestamp: Date(timeIntervalSince1970: 4))
    #expect(after.entries == 3)
    #expect(after.headHash != rotation.headHash)
    #expect(try checkpoints.verify() == [checkpoint])
    let restarted = try NativeAuditLog(path: auditFile.path, archiveDirectory: archive.path)
    #expect(try restarted.verify() == after)
}

@Test func nativeAuditRotationRejectsSmallLogsAndArchiveTampering() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let archive = root.appendingPathComponent("archive")
    try FileManager.default.createDirectory(at: archive, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let log = try NativeAuditLog(path: root.appendingPathComponent("audit.jsonl").path, archiveDirectory: archive.path)
    try log.append(NativeAuditEvent(operation: "one", decision: "allow"))
    #expect(throws: AgentPassNativeError.self) { try log.rotate() }
    let rotation = try log.rotate(minimumBytes: 1)
    let segment = archive.appendingPathComponent(rotation.archiveFile)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: segment.path)
    var data = try Data(contentsOf: segment)
    data[data.startIndex] ^= 1
    try data.write(to: segment)
    try FileManager.default.setAttributes([.posixPermissions: 0o400], ofItemAtPath: segment.path)
    #expect(throws: (any Error).self) { try log.verify() }
    #expect(throws: (any Error).self) { try log.append(NativeAuditEvent(operation: "two", decision: "allow")) }
}

@Test func nativeAuditArchiveRejectsUnknownEntriesAndUnsafeDirectories() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let archive = root.appendingPathComponent("archive")
    try FileManager.default.createDirectory(at: archive, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let auditFile = root.appendingPathComponent("audit.jsonl")
    #expect(throws: AgentPassNativeError.self) { try NativeAuditLog(path: auditFile.path, archiveDirectory: root.path) }
    let log = try NativeAuditLog(path: auditFile.path, archiveDirectory: archive.path)
    try Data("unexpected\n".utf8).write(to: archive.appendingPathComponent("README"))
    #expect(throws: AgentPassNativeError.self) { try log.verify() }
    try FileManager.default.removeItem(at: archive.appendingPathComponent("README"))
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: archive.path)
    #expect(throws: AgentPassNativeError.self) { try NativeAuditLog(path: auditFile.path, archiveDirectory: archive.path) }
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

@Test func nativeAuditAnchorReceiptsAreVerifiedChainedAndPersisted() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let log = try NativeAuditLog(path: root.appendingPathComponent("audit.jsonl").path)
    let checkpoints = try NativeAuditCheckpoints(path: root.appendingPathComponent("checkpoints.jsonl").path, auditLog: log, signer: AuditSoftwareSigner())
    try log.append(NativeAuditEvent(operation: "one", decision: "allow"))
    let first = try checkpoints.create()
    try log.append(NativeAuditEvent(operation: "two", decision: "allow"))
    let second = try checkpoints.create()
    let records = try checkpoints.verify()
    let anchorKey = Curve25519.Signing.PrivateKey()
    let receiptFile = root.appendingPathComponent("anchor.receipts.jsonl")
    let manager = try NativeAuditAnchorReceipts(path: receiptFile.path, tenant: "native-host", anchorPublicKeyPEM: anchorPublicKeyPEM(anchorKey.publicKey))
    #expect(try manager.status(checkpoints: records).pending == 2)
    #expect(try manager.pendingCheckpoint(checkpoints: records) == first)
    let firstData = try anchorReceiptData(checkpoint: first, index: 1, previous: NativeAuditLog.zeroHash, tenant: "native-host", key: anchorKey)
    let firstStatus = try manager.accept(receiptData: firstData, checkpoint: first, checkpoints: records)
    #expect(firstStatus.receipts == 1)
    #expect(firstStatus.pending == 1)
    let firstReceipt = try JSONDecoder().decode(NativeAuditAnchorReceipt.self, from: firstData)
    let rolledBack = try anchorReceiptData(checkpoint: second, index: 2, previous: firstReceipt.receiptHash, tenant: "native-host", key: anchorKey, receivedAt: "2027-01-15T07:59:59.000Z")
    #expect(throws: AgentPassNativeError.self) { try manager.accept(receiptData: rolledBack, checkpoint: second, checkpoints: records) }
    let secondData = try anchorReceiptData(checkpoint: second, index: 2, previous: firstReceipt.receiptHash, tenant: "native-host", key: anchorKey)
    #expect(try manager.accept(receiptData: secondData, checkpoint: second, checkpoints: records).pending == 0)
    #expect((try FileManager.default.attributesOfItem(atPath: receiptFile.path)[.posixPermissions] as? NSNumber)?.intValue == 0o600)
    let restarted = try NativeAuditAnchorReceipts(path: receiptFile.path, tenant: "native-host", anchorPublicKeyPEM: anchorPublicKeyPEM(anchorKey.publicKey))
    #expect(try restarted.status(checkpoints: records).receipts == 2)

    var forged = try JSONSerialization.jsonObject(with: secondData) as! [String: Any]
    forged["checkpoint_hash"] = String(repeating: "f", count: 64)
    #expect(throws: AgentPassNativeError.self) { try manager.accept(receiptData: NativeAuditLog.canonical(forged), checkpoint: second, checkpoints: records) }
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
