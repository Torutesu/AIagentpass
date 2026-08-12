import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore

private struct AuditSoftwareSigner: P256MessageSigner {
    let privateKey = P256.Signing.PrivateKey()
    var publicKeyX963: Data { privateKey.publicKey.x963Representation }
    func sign(message: Data) throws -> Data { try privateKey.signature(for: message).rawRepresentation }
}

private func appendAuditCheckpoint(path: String, audit: NativeAuditStatus, signer: AuditSoftwareSigner, generation: Int, lifecycleHead: String, previous: String, timestamp: Date) throws -> NativeAuditCheckpoint {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let statement: [String: Any] = [
        "version": 2,
        "created_at": formatter.string(from: timestamp),
        "entries": audit.entries,
        "head_hash": audit.headHash,
        "previous_checkpoint_hash": previous,
        "key_generation": generation,
        "lifecycle_head_hash": lifecycleHead
    ]
    let signature = try signer.sign(message: NativeAuditLog.canonical(statement)).base64EncodedString()
    var record = statement
    record["public_key_fingerprint"] = NativeAuditCheckpoints.fingerprint(signer.publicKeyX963)
    record["signature"] = signature
    record["checkpoint_hash"] = NativeAuditLog.hash(try NativeAuditLog.canonical(record))
    let data = try NativeAuditLog.canonical(record)
    let checkpoint = try JSONDecoder().decode(NativeAuditCheckpoint.self, from: data)
    let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: path))
    defer { try? handle.close() }
    try handle.seekToEnd()
    try handle.write(contentsOf: data + Data("\n".utf8))
    return checkpoint
}

private func anchorPublicKeyPEM(_ key: Curve25519.Signing.PublicKey) -> String {
    let der = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) + key.rawRepresentation
    return "-----BEGIN PUBLIC KEY-----\n\(der.base64EncodedString())\n-----END PUBLIC KEY-----\n"
}

private func anchorReceiptData(checkpoint: NativeAuditCheckpoint, index: Int, previous: String, tenant: String, key: Curve25519.Signing.PrivateKey, receivedAt: String = "2027-01-15T08:00:00.000Z", version: Int = 1, eventIndex: Int? = nil, previousEventHash: String? = nil) throws -> Data {
    var statement: [String: Any] = ["version": version, "tenant": tenant, "index": index, "checkpoint_hash": checkpoint.checkpointHash, "received_at": receivedAt, "previous_receipt_hash": previous]
    if version == 2 { statement["event_index"] = eventIndex ?? index; statement["previous_event_hash"] = previousEventHash ?? previous }
    let signature = try key.signature(for: NativeAuditLog.canonical(statement)).base64EncodedString()
    let der = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) + key.publicKey.rawRepresentation
    let fingerprint = "SHA256:" + Data(SHA256.hash(data: der)).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    var unsigned = statement.merging(["anchor_key_fingerprint": fingerprint, "signature": signature]) { current, _ in current }
    let ordered = "{\"version\":1,\"tenant\":\"\(tenant)\",\"index\":\(index),\"checkpoint_hash\":\"\(checkpoint.checkpointHash)\",\"received_at\":\"\(receivedAt)\",\"previous_receipt_hash\":\"\(previous)\",\"anchor_key_fingerprint\":\"\(fingerprint)\",\"signature\":\"\(signature)\"}"
    let receiptHash = NativeAuditLog.hash(version == 2 ? try NativeAuditLog.canonical(unsigned) : Data(ordered.utf8))
    unsigned["receipt_hash"] = receiptHash
    let receipt = unsigned
    return try NativeAuditLog.canonical(receipt)
}

@Test func nativeAuditAnchorReceiptsAllowSignedGlobalEventGapsButRejectBrokenDirectPredecessors() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let log = try NativeAuditLog(path: root.appendingPathComponent("audit.jsonl").path)
    let checkpoints = try NativeAuditCheckpoints(path: root.appendingPathComponent("checkpoints.jsonl").path, auditLog: log, signer: AuditSoftwareSigner())
    try log.append(NativeAuditEvent(operation: "one", decision: "allow"))
    let first = try checkpoints.create()
    try log.append(NativeAuditEvent(operation: "two", decision: "allow"))
    let second = try checkpoints.create()
    try log.append(NativeAuditEvent(operation: "three", decision: "allow"))
    let third = try checkpoints.create()
    let records = try checkpoints.verify()
    let anchor = Curve25519.Signing.PrivateKey()
    let manager = try NativeAuditAnchorReceipts(
        path: root.appendingPathComponent("receipts.jsonl").path, tenant: "native-host",
        anchorPublicKeyPEM: anchorPublicKeyPEM(anchor.publicKey)
    )
    let firstData = try anchorReceiptData(
        checkpoint: first, index: 1, previous: NativeAuditLog.zeroHash,
        tenant: "native-host", key: anchor, version: 2
    )
    _ = try manager.accept(receiptData: firstData, checkpoint: first, checkpoints: records)
    let firstReceipt = try JSONDecoder().decode(NativeAuditAnchorReceipt.self, from: firstData)
    let transitionEventHash = String(repeating: "e", count: 64)
    let secondData = try anchorReceiptData(
        checkpoint: second, index: 2, previous: firstReceipt.receiptHash,
        tenant: "native-host", key: anchor, version: 2,
        eventIndex: 3, previousEventHash: transitionEventHash
    )
    _ = try manager.accept(receiptData: secondData, checkpoint: second, checkpoints: records)
    let secondReceipt = try JSONDecoder().decode(NativeAuditAnchorReceipt.self, from: secondData)
    let broken = try anchorReceiptData(
        checkpoint: third, index: 3, previous: secondReceipt.receiptHash,
        tenant: "native-host", key: anchor, version: 2,
        eventIndex: 4, previousEventHash: String(repeating: "f", count: 64)
    )
    #expect(throws: AgentPassNativeError.self) {
        try manager.accept(receiptData: broken, checkpoint: third, checkpoints: records)
    }
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

@Test func nativeAuditAppendPreflightRotatesNonSignEventsBelowVerificationCeiling() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let archive = root.appendingPathComponent("archive")
    try FileManager.default.createDirectory(at: archive, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let auditFile = root.appendingPathComponent("audit.jsonl")
    let checkpointFile = root.appendingPathComponent("checkpoints.jsonl")

    let initial = try NativeAuditLog(path: auditFile.path, archiveDirectory: archive.path, verificationLimitBytes: 8_192, appendRotationThresholdBytes: 4_096)
    _ = try initial.append(NativeAuditEvent(operation: "policy.reload", decision: "error", reason: "invalid_policy"), timestamp: Date(timeIntervalSince1970: 1))
    let activeBytes = try initial.storageStatus().activeBytes
    let threshold = activeBytes + 1

    let log = try NativeAuditLog(path: auditFile.path, archiveDirectory: archive.path, verificationLimitBytes: threshold + 1_024, appendRotationThresholdBytes: threshold)
    let checkpoints = try NativeAuditCheckpoints(path: checkpointFile.path, auditLog: log, signer: AuditSoftwareSigner())
    let event = NativeAuditEvent(operation: "lease.revoke", decision: "deny", reason: "policy_changed")
    let preflight = try log.preflightAppend(event, timestamp: Date(timeIntervalSince1970: 2))
    #expect(preflight.action == .rotateThenAppend)
    #expect(preflight.projectedBytes < preflight.verificationLimitBytes)
    #expect(preflight.archiveConfigured)

    #expect(throws: AgentPassNativeError.self) {
        try log.append(event, timestamp: Date(timeIntervalSince1970: 2))
    }
    #expect(try log.verify().entries == 1)
    #expect(try log.storageStatus().segments == 0)

    let status = try log.append(event, timestamp: Date(timeIntervalSince1970: 2), rotationCheckpointing: checkpoints)
    #expect(status.entries == 2)
    #expect(try log.storageStatus().segments == 1)
    #expect(try log.storageStatus().activeBytes <= threshold)
    let records = try checkpoints.verify()
    #expect(records.count == 1)
    #expect(records[0].entries == 1)
    #expect(records[0].headHash == preflight.auditStatus.headHash)
}

@Test func nativeAuditAppendPreflightFailsClosedWithActionableStatusWhenArchiveIsMissing() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let auditFile = root.appendingPathComponent("audit.jsonl")

    let initial = try NativeAuditLog(path: auditFile.path, verificationLimitBytes: 8_192, appendRotationThresholdBytes: 4_096)
    _ = try initial.append(NativeAuditEvent(operation: "config.reload", decision: "allow"), timestamp: Date(timeIntervalSince1970: 1))
    let bytesBefore = try initial.storageStatus().activeBytes
    let event = NativeAuditEvent(operation: "agent.authenticate", decision: "deny", reason: "identity_changed")
    let appendBytes = try initial.preflightAppend(event, timestamp: Date(timeIntervalSince1970: 2)).appendBytes
    let threshold = max(bytesBefore, appendBytes) + 1
    let log = try NativeAuditLog(path: auditFile.path, verificationLimitBytes: threshold + 32, appendRotationThresholdBytes: threshold)
    let preflight = try log.preflightAppend(event, timestamp: Date(timeIntervalSince1970: 2))
    #expect(preflight.action == .rotateThenAppend)
    #expect(!preflight.archiveConfigured)
    #expect(preflight.projectedBytes > preflight.verificationLimitBytes)

    do {
        _ = try log.append(event, timestamp: Date(timeIntervalSince1970: 2))
        Issue.record("append should stop before crossing the configured ceiling")
    } catch {
        let message = error.localizedDescription
        #expect(message.contains("configure an audit archive directory"))
        #expect(message.contains("projected="))
        #expect(message.contains("verification_limit="))
    }
    #expect(try log.storageStatus().activeBytes == bytesBefore)
    #expect(try log.verify().entries == 1)
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

@Test func nativeAuditCheckpointsMatchEveryHistoricalHeadIncludingZeroAndRepeatedCounts() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let auditFile = root.appendingPathComponent("audit.jsonl")
    let log = try NativeAuditLog(path: auditFile.path)
    let checkpoints = try NativeAuditCheckpoints(path: root.appendingPathComponent("checkpoints.jsonl").path, auditLog: log, signer: AuditSoftwareSigner())
    let zeroOne = try checkpoints.create(timestamp: Date(timeIntervalSince1970: 1))
    let zeroTwo = try checkpoints.create(timestamp: Date(timeIntervalSince1970: 2))
    #expect(zeroOne.entries == 0 && zeroOne.headHash == NativeAuditLog.zeroHash)
    #expect(zeroTwo.entries == 0 && zeroTwo.headHash == NativeAuditLog.zeroHash)
    try log.append(NativeAuditEvent(operation: "one", decision: "allow"), timestamp: Date(timeIntervalSince1970: 3))
    let oneOne = try checkpoints.create(timestamp: Date(timeIntervalSince1970: 4))
    let oneTwo = try checkpoints.create(timestamp: Date(timeIntervalSince1970: 5))
    #expect(oneOne.entries == 1 && oneTwo.headHash == oneOne.headHash)
    #expect(try checkpoints.verify().count == 4)

    try FileManager.default.removeItem(at: auditFile)
    let replacement = try NativeAuditLog(path: auditFile.path)
    try replacement.append(NativeAuditEvent(operation: "different", decision: "deny"), timestamp: Date(timeIntervalSince1970: 3))
    #expect(throws: AgentPassNativeError.self) { try checkpoints.verify() }
}

@Test func nativeAuditCheckpointsVerifyMixedKeyGenerationsAndBindLifecycleHeads() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let log = try NativeAuditLog(path: root.appendingPathComponent("audit.jsonl").path)
    let firstSigner = AuditSoftwareSigner()
    let secondSigner = AuditSoftwareSigner()
    let path = root.appendingPathComponent("checkpoints.jsonl").path
    let firstHead = String(repeating: "1", count: 64)
    let secondHead = String(repeating: "2", count: 64)
    let firstFingerprint = NativeAuditCheckpoints.fingerprint(firstSigner.publicKeyX963)
    let secondFingerprint = NativeAuditCheckpoints.fingerprint(secondSigner.publicKeyX963)
    let firstStore = try NativeAuditCheckpoints(path: path, auditLog: log, signer: firstSigner, verificationGenerations: [firstFingerprint: 1], keyGeneration: 1, lifecycleHeadHash: firstHead, requireLifecycleBinding: true)
    try log.append(NativeAuditEvent(operation: "one", decision: "allow"))
    let first = try firstStore.create()
    let repeated = try firstStore.create()
    #expect(first.version == 2 && first.keyGeneration == 1 && first.lifecycleHeadHash == firstHead)
    let secondStore = try NativeAuditCheckpoints(path: path, auditLog: log, signer: secondSigner, verificationPublicKeys: [firstSigner.publicKeyX963], verificationGenerations: [firstFingerprint: 1, secondFingerprint: 2], keyGeneration: 2, lifecycleHeadHash: secondHead, requireLifecycleBinding: true)
    try log.append(NativeAuditEvent(operation: "two", decision: "allow"))
    let second = try secondStore.create()
    #expect(second.keyGeneration == 2 && second.lifecycleHeadHash == secondHead)
    #expect(try secondStore.verify() == [first, repeated, second])
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditCheckpoints(path: path, auditLog: log, signer: secondSigner, verificationPublicKeys: [firstSigner.publicKeyX963], verificationGenerations: [firstFingerprint: 2, secondFingerprint: 2], keyGeneration: 2, lifecycleHeadHash: secondHead, requireLifecycleBinding: true).verify()
    }
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditCheckpoints(path: path, auditLog: log, signer: secondSigner, keyGeneration: 2, lifecycleHeadHash: secondHead).verify()
    }
}

@Test func nativeAuditCheckpointsRejectGenerationRollbackAndRetiredKeyReuse() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let log = try NativeAuditLog(path: root.appendingPathComponent("audit.jsonl").path)
    try log.append(NativeAuditEvent(operation: "one", decision: "allow"))
    let audit = try log.verify()
    let firstSigner = AuditSoftwareSigner()
    let secondSigner = AuditSoftwareSigner()
    let path = root.appendingPathComponent("checkpoints.jsonl").path
    FileManager.default.createFile(atPath: path, contents: Data(), attributes: [.posixPermissions: 0o600])
    let first = try appendAuditCheckpoint(path: path, audit: audit, signer: firstSigner, generation: 1, lifecycleHead: String(repeating: "1", count: 64), previous: NativeAuditLog.zeroHash, timestamp: Date(timeIntervalSince1970: 1))
    let second = try appendAuditCheckpoint(path: path, audit: audit, signer: secondSigner, generation: 2, lifecycleHead: String(repeating: "2", count: 64), previous: first.checkpointHash, timestamp: Date(timeIntervalSince1970: 2))
    _ = try appendAuditCheckpoint(path: path, audit: audit, signer: firstSigner, generation: 1, lifecycleHead: String(repeating: "3", count: 64), previous: second.checkpointHash, timestamp: Date(timeIntervalSince1970: 3))
    let firstFingerprint = NativeAuditCheckpoints.fingerprint(firstSigner.publicKeyX963)
    let secondFingerprint = NativeAuditCheckpoints.fingerprint(secondSigner.publicKeyX963)
    let verifier = try NativeAuditCheckpoints(path: path, auditLog: log, signer: secondSigner, verificationPublicKeys: [firstSigner.publicKeyX963], verificationGenerations: [firstFingerprint: 1, secondFingerprint: 2], keyGeneration: 2, lifecycleHeadHash: String(repeating: "2", count: 64), requireLifecycleBinding: true)
    #expect(throws: AgentPassNativeError.self) { try verifier.verify() }
}

@Test func nativeAuditCheckpointsRejectKeySubstitutionWithinGeneration() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let log = try NativeAuditLog(path: root.appendingPathComponent("audit.jsonl").path)
    let audit = try log.verify()
    let firstSigner = AuditSoftwareSigner()
    let substituteSigner = AuditSoftwareSigner()
    let path = root.appendingPathComponent("checkpoints.jsonl").path
    FileManager.default.createFile(atPath: path, contents: Data(), attributes: [.posixPermissions: 0o600])
    let first = try appendAuditCheckpoint(path: path, audit: audit, signer: firstSigner, generation: 7, lifecycleHead: String(repeating: "a", count: 64), previous: NativeAuditLog.zeroHash, timestamp: Date(timeIntervalSince1970: 1))
    _ = try appendAuditCheckpoint(path: path, audit: audit, signer: substituteSigner, generation: 7, lifecycleHead: String(repeating: "b", count: 64), previous: first.checkpointHash, timestamp: Date(timeIntervalSince1970: 2))
    let firstFingerprint = NativeAuditCheckpoints.fingerprint(firstSigner.publicKeyX963)
    let substituteFingerprint = NativeAuditCheckpoints.fingerprint(substituteSigner.publicKeyX963)
    let verifier = try NativeAuditCheckpoints(path: path, auditLog: log, signer: substituteSigner, verificationPublicKeys: [firstSigner.publicKeyX963], verificationGenerations: [firstFingerprint: 7, substituteFingerprint: 7], keyGeneration: 7, lifecycleHeadHash: String(repeating: "b", count: 64), requireLifecycleBinding: true)
    #expect(throws: AgentPassNativeError.self) { try verifier.verify() }
}

@Test func nativeAuditCheckpointsRejectMissingLifecycleBindingWhenRequired() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let log = try NativeAuditLog(path: root.appendingPathComponent("audit.jsonl").path)
    let signer = AuditSoftwareSigner()
    let path = root.appendingPathComponent("checkpoints.jsonl").path
    let unbound = try NativeAuditCheckpoints(path: path, auditLog: log, signer: signer)
    _ = try unbound.create()
    let fingerprint = NativeAuditCheckpoints.fingerprint(signer.publicKeyX963)
    let boundVerifier = try NativeAuditCheckpoints(path: path, auditLog: log, signer: signer, verificationGenerations: [fingerprint: 1], keyGeneration: 1, lifecycleHeadHash: String(repeating: "c", count: 64), requireLifecycleBinding: true)
    #expect(throws: AgentPassNativeError.self) { try boundVerifier.verify() }
}

@Test func nativeAuditCheckpointArchivesRestartAcrossMultipleSegmentsAndDetectLoss() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let archive = root.appendingPathComponent("checkpoint-archive")
    try FileManager.default.createDirectory(at: archive, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let log = try NativeAuditLog(path: root.appendingPathComponent("audit.jsonl").path)
    let signer = AuditSoftwareSigner()
    let path = root.appendingPathComponent("checkpoints.jsonl")
    let checkpoints = try NativeAuditCheckpoints(path: path.path, auditLog: log, signer: signer, archiveDirectory: archive.path)
    try log.append(NativeAuditEvent(operation: "one", decision: "allow"))
    _ = try checkpoints.create()
    #expect(throws: AgentPassNativeError.self) { try checkpoints.rotate() }
    let first = try checkpoints.rotate(minimumBytes: 1)
    #expect(first.firstIndex == 1 && first.lastIndex == 1)
    try log.append(NativeAuditEvent(operation: "two", decision: "allow"))
    _ = try checkpoints.create()
    let second = try checkpoints.rotate(minimumBytes: 1)
    #expect(second.firstIndex == 2 && second.lastIndex == 2)
    try log.append(NativeAuditEvent(operation: "three", decision: "allow"))
    _ = try checkpoints.create()

    let restarted = try NativeAuditCheckpoints(path: path.path, auditLog: log, signer: signer, archiveDirectory: archive.path)
    #expect(try restarted.verify().count == 3)
    let status = try restarted.storageStatus(minimumBytes: 1)
    #expect(status.totalRecords == 3 && status.segments == 2 && status.activeRecords == 1 && status.rotationReady)
    try FileManager.default.removeItem(at: archive.appendingPathComponent(first.archiveFile))
    #expect(throws: AgentPassNativeError.self) { try restarted.verify() }
}

@Test func nativeAuditCheckpointArchivesRejectTamperUnknownSymlinkAndPermissions() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let archive = root.appendingPathComponent("checkpoint-archive")
    try FileManager.default.createDirectory(at: archive, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let log = try NativeAuditLog(path: root.appendingPathComponent("audit.jsonl").path)
    let signer = AuditSoftwareSigner()
    let path = root.appendingPathComponent("checkpoints.jsonl")
    let checkpoints = try NativeAuditCheckpoints(path: path.path, auditLog: log, signer: signer, archiveDirectory: archive.path)
    try log.append(NativeAuditEvent(operation: "one", decision: "allow"))
    _ = try checkpoints.create()
    let rotation = try checkpoints.rotate(minimumBytes: 1)
    let segment = archive.appendingPathComponent(rotation.archiveFile)
    let wrongName = "checkpoints-00000000000000000001-00000000000000000001-\(String(repeating: "f", count: 64)).jsonl"
    try FileManager.default.moveItem(at: segment, to: archive.appendingPathComponent(wrongName))
    #expect(throws: AgentPassNativeError.self) { try checkpoints.verify() }
    try FileManager.default.moveItem(at: archive.appendingPathComponent(wrongName), to: segment)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: segment.path)
    var bytes = try Data(contentsOf: segment)
    bytes[bytes.startIndex] ^= 1
    try bytes.write(to: segment)
    try FileManager.default.setAttributes([.posixPermissions: 0o400], ofItemAtPath: segment.path)
    #expect(throws: (any Error).self) { try checkpoints.verify() }

    try FileManager.default.removeItem(at: segment)
    try Data("unknown".utf8).write(to: archive.appendingPathComponent("README"))
    #expect(throws: AgentPassNativeError.self) { try checkpoints.verify() }
    try FileManager.default.removeItem(at: archive.appendingPathComponent("README"))
    try FileManager.default.createSymbolicLink(atPath: archive.appendingPathComponent(rotation.archiveFile).path, withDestinationPath: path.path)
    #expect(throws: AgentPassNativeError.self) { try checkpoints.verify() }
    try FileManager.default.removeItem(at: archive.appendingPathComponent(rotation.archiveFile))
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: archive.path)
    #expect(throws: AgentPassNativeError.self) { try NativeAuditCheckpoints(path: path.path, auditLog: log, signer: signer, archiveDirectory: archive.path) }
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
    let firstData = try anchorReceiptData(checkpoint: first, index: 1, previous: NativeAuditLog.zeroHash, tenant: "native-host", key: anchorKey, version: 2)
    let firstStatus = try manager.accept(receiptData: firstData, checkpoint: first, checkpoints: records)
    #expect(firstStatus.receipts == 1)
    #expect(firstStatus.pending == 1)
    let firstReceipt = try JSONDecoder().decode(NativeAuditAnchorReceipt.self, from: firstData)
    let rolledBack = try anchorReceiptData(checkpoint: second, index: 2, previous: firstReceipt.receiptHash, tenant: "native-host", key: anchorKey, receivedAt: "2027-01-15T07:59:59.000Z", version: 2)
    #expect(throws: AgentPassNativeError.self) { try manager.accept(receiptData: rolledBack, checkpoint: second, checkpoints: records) }
    let secondData = try anchorReceiptData(checkpoint: second, index: 2, previous: firstReceipt.receiptHash, tenant: "native-host", key: anchorKey, version: 2)
    #expect(try manager.accept(receiptData: secondData, checkpoint: second, checkpoints: records).pending == 0)
    #expect((try FileManager.default.attributesOfItem(atPath: receiptFile.path)[.posixPermissions] as? NSNumber)?.intValue == 0o600)
    let restarted = try NativeAuditAnchorReceipts(path: receiptFile.path, tenant: "native-host", anchorPublicKeyPEM: anchorPublicKeyPEM(anchorKey.publicKey))
    #expect(try restarted.status(checkpoints: records).receipts == 2)
    let verified = try restarted.verifiedReceipts(checkpoints: records)
    #expect(verified.count == 2)
    #expect(verified.last?.checkpointHash == second.checkpointHash)

    var forged = try JSONSerialization.jsonObject(with: secondData) as! [String: Any]
    forged["checkpoint_hash"] = String(repeating: "f", count: 64)
    #expect(throws: AgentPassNativeError.self) { try manager.accept(receiptData: NativeAuditLog.canonical(forged), checkpoint: second, checkpoints: records) }
}

@Test func nativeAuditReceiptArchivesPreserveAbsolutePendingIndexesAcrossRestart() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let archive = root.appendingPathComponent("receipt-archive")
    try FileManager.default.createDirectory(at: archive, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let log = try NativeAuditLog(path: root.appendingPathComponent("audit.jsonl").path)
    let checkpointsStore = try NativeAuditCheckpoints(path: root.appendingPathComponent("checkpoints.jsonl").path, auditLog: log, signer: AuditSoftwareSigner())
    for operation in ["one", "two", "three"] {
        try log.append(NativeAuditEvent(operation: operation, decision: "allow"))
        _ = try checkpointsStore.create()
    }
    let checkpoints = try checkpointsStore.verify()
    let anchorKey = Curve25519.Signing.PrivateKey()
    let path = root.appendingPathComponent("receipts.jsonl")
    let receipts = try NativeAuditAnchorReceipts(path: path.path, tenant: "native-host", anchorPublicKeyPEM: anchorPublicKeyPEM(anchorKey.publicKey), archiveDirectory: archive.path)
    let firstData = try anchorReceiptData(checkpoint: checkpoints[0], index: 1, previous: NativeAuditLog.zeroHash, tenant: "native-host", key: anchorKey, receivedAt: "2027-01-15T08:00:00.000Z")
    _ = try receipts.accept(receiptData: firstData, checkpoint: checkpoints[0], checkpoints: checkpoints)
    #expect(throws: AgentPassNativeError.self) { try receipts.rotate(checkpoints: checkpoints) }
    let firstRotation = try receipts.rotate(checkpoints: checkpoints, minimumBytes: 1)
    let firstReceipt = try JSONDecoder().decode(NativeAuditAnchorReceipt.self, from: firstData)
    let secondData = try anchorReceiptData(checkpoint: checkpoints[1], index: 2, previous: firstReceipt.receiptHash, tenant: "native-host", key: anchorKey, receivedAt: "2027-01-15T08:01:00.000Z")
    _ = try receipts.accept(receiptData: secondData, checkpoint: checkpoints[1], checkpoints: checkpoints)
    let secondRotation = try receipts.rotate(checkpoints: checkpoints, minimumBytes: 1)
    #expect(firstRotation.firstIndex == 1 && secondRotation.firstIndex == 2)

    let restarted = try NativeAuditAnchorReceipts(path: path.path, tenant: "native-host", anchorPublicKeyPEM: anchorPublicKeyPEM(anchorKey.publicKey), archiveDirectory: archive.path)
    #expect(try restarted.status(checkpoints: checkpoints).pending == 1)
    #expect(try restarted.pendingCheckpoint(checkpoints: checkpoints) == checkpoints[2])
    let storage = try restarted.storageStatus(checkpoints: checkpoints, minimumBytes: 1)
    #expect(storage.totalRecords == 2 && storage.segments == 2 && storage.activeRecords == 0)

    try FileManager.default.removeItem(at: archive.appendingPathComponent(firstRotation.archiveFile))
    #expect(throws: AgentPassNativeError.self) { try restarted.status(checkpoints: checkpoints) }
}

@Test func nativeAuditReceiptArchivesRejectUnknownSymlinkAndPermissiveEntries() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let archive = root.appendingPathComponent("receipt-archive")
    try FileManager.default.createDirectory(at: archive, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let log = try NativeAuditLog(path: root.appendingPathComponent("audit.jsonl").path)
    let checkpointStore = try NativeAuditCheckpoints(path: root.appendingPathComponent("checkpoints.jsonl").path, auditLog: log, signer: AuditSoftwareSigner())
    try log.append(NativeAuditEvent(operation: "one", decision: "allow"))
    let checkpoint = try checkpointStore.create()
    let key = Curve25519.Signing.PrivateKey()
    let path = root.appendingPathComponent("receipts.jsonl")
    let receipts = try NativeAuditAnchorReceipts(path: path.path, tenant: "native-host", anchorPublicKeyPEM: anchorPublicKeyPEM(key.publicKey), archiveDirectory: archive.path)
    let data = try anchorReceiptData(checkpoint: checkpoint, index: 1, previous: NativeAuditLog.zeroHash, tenant: "native-host", key: key)
    _ = try receipts.accept(receiptData: data, checkpoint: checkpoint, checkpoints: [checkpoint])
    let rotation = try receipts.rotate(checkpoints: [checkpoint], minimumBytes: 1)
    let segment = archive.appendingPathComponent(rotation.archiveFile)
    let wrongName = "receipts-00000000000000000001-00000000000000000002-\(rotation.terminalHash).jsonl"
    try FileManager.default.moveItem(at: segment, to: archive.appendingPathComponent(wrongName))
    #expect(throws: AgentPassNativeError.self) { try receipts.status(checkpoints: [checkpoint]) }
    try FileManager.default.moveItem(at: archive.appendingPathComponent(wrongName), to: segment)
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: segment.path)
    #expect(throws: AgentPassNativeError.self) { try receipts.status(checkpoints: [checkpoint]) }
    try FileManager.default.removeItem(at: segment)
    try FileManager.default.createSymbolicLink(atPath: segment.path, withDestinationPath: path.path)
    #expect(throws: AgentPassNativeError.self) { try receipts.status(checkpoints: [checkpoint]) }
    try FileManager.default.removeItem(at: segment)
    try Data("unknown".utf8).write(to: archive.appendingPathComponent("unknown"))
    #expect(throws: AgentPassNativeError.self) { try receipts.status(checkpoints: [checkpoint]) }
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
