import CryptoKit
import Darwin
import Foundation
import Testing
@testable import AgentPassNativeCore

private struct StoreTransitionSigner: P256MessageSigner {
    let privateKey: P256.Signing.PrivateKey

    init(_ byte: UInt8) throws {
        privateKey = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: byte, count: 32))
    }

    var publicKeyX963: Data { privateKey.publicKey.x963Representation }
    func sign(message: Data) throws -> Data { try privateKey.signature(for: message).rawRepresentation }
}

private struct StoreTransitionEvidence {
    let old: StoreTransitionSigner
    let replacement: StoreTransitionSigner
    let transition: NativeAuditKeyTransition
    let transitionData: Data
    let receiptData: Data
    let receipt: NativeAuditKeyTransitionReceipt
}

private func storeAnchorPEM(_ key: Curve25519.Signing.PublicKey) -> String {
    let der = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) + key.rawRepresentation
    return "-----BEGIN PUBLIC KEY-----\n\(der.base64EncodedString())\n-----END PUBLIC KEY-----\n"
}

private func storeAnchorFingerprint(_ key: Curve25519.Signing.PublicKey) -> String {
    let der = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) + key.rawRepresentation
    return "SHA256:" + Data(SHA256.hash(data: der)).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private func makeStoreEvidence(
    anchor: Curve25519.Signing.PrivateKey,
    old: StoreTransitionSigner,
    replacement: StoreTransitionSigner,
    generation: Int,
    operationID: String,
    transitionIndex: Int,
    previousTransitionHash: String = String(repeating: "0", count: 64),
    previousTransitionReceiptHash: String = String(repeating: "0", count: 64),
    previousEventIndex: Int = 10,
    previousEventHash: String = String(repeating: "a", count: 64),
    checkpointIndex: Int = 7,
    createdAt: String = "2030-01-01T00:00:01.000Z",
    receivedAt: String = "2030-01-01T00:00:02.000Z"
) throws -> StoreTransitionEvidence {
    let statement = try NativeAuditKeyTransitionStatement(
        tenant: "native-host",
        operationID: operationID,
        fromGeneration: generation,
        oldPublicKeyX963: old.publicKeyX963,
        newPublicKeyX963: replacement.publicKeyX963,
        lifecycleHeadHash: String(repeating: "b", count: 64),
        lastCheckpointIndex: checkpointIndex,
        lastCheckpointHash: String(repeating: Character(String(checkpointIndex % 10)), count: 64),
        lastCheckpointReceiptHash: String(repeating: "c", count: 64),
        previousTransitionHash: previousTransitionHash,
        previousTransitionReceiptHash: previousTransitionReceiptHash,
        previousAnchorEventIndex: previousEventIndex,
        previousAnchorEventHash: previousEventHash,
        createdAt: createdAt
    )
    let transition = try NativeAuditKeyTransition(statement: statement, retiringSigner: old, replacementSigner: replacement)
    let transitionData = try transition.canonicalData()
    var receiptStatement: [String: Any] = [
        "version": 2,
        "tenant": transition.tenant,
        "index": transitionIndex,
        "transition_hash": transition.transitionHash,
        "received_at": receivedAt,
        "previous_receipt_hash": transition.previousTransitionReceiptHash,
        "event_index": transition.previousAnchorEventIndex + 1,
        "previous_event_hash": transition.previousAnchorEventHash,
        "last_checkpoint_index": transition.lastCheckpointIndex,
        "last_checkpoint_hash": transition.lastCheckpointHash,
        "last_checkpoint_receipt_hash": transition.lastCheckpointReceiptHash
    ]
    receiptStatement["signature"] = try anchor.signature(for: NativeAuditLog.canonical(receiptStatement)).base64EncodedString()
    receiptStatement["anchor_key_fingerprint"] = storeAnchorFingerprint(anchor.publicKey)
    receiptStatement["receipt_hash"] = NativeAuditLog.hash(try NativeAuditLog.canonical(receiptStatement))
    let receiptData = try NativeAuditLog.canonical(receiptStatement)
    let verifier = try NativeAuditKeyTransitionReceiptVerifier(tenant: "native-host", anchorPublicKeyPEM: storeAnchorPEM(anchor.publicKey))
    let receipt = try verifier.verify(receiptData: receiptData, transition: transition, expectedTransitionIndex: transitionIndex)
    return StoreTransitionEvidence(old: old, replacement: replacement, transition: transition, transitionData: transitionData, receiptData: receiptData, receipt: receipt)
}

private func makeProtectedStoreDirectory() throws -> URL {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("agentpass-transition-store-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    guard chmod(root.path, 0o700) == 0 else { throw POSIXError(.EIO) }
    guard let resolved = Darwin.realpath(root.path, nil) else { throw POSIXError(.EIO) }
    defer { free(resolved) }
    return URL(fileURLWithPath: String(cString: resolved))
}

private func overwriteStoreFile(_ url: URL, data: Data, mode: mode_t = 0o600) throws {
    let descriptor = open(url.path, O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw POSIXError(.EIO) }
    defer { close(descriptor) }
    try data.withUnsafeBytes { bytes in
        var offset = 0
        while offset < bytes.count {
            let count = Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
            guard count > 0 else { throw POSIXError(.EIO) }
            offset += count
        }
    }
    guard fchmod(descriptor, mode) == 0, fsync(descriptor) == 0 else { throw POSIXError(.EIO) }
}

@Test func auditTransitionStoreSurvivesRestartAndLostResponseReplayExactlyOnce() throws {
    let root = try makeProtectedStoreDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let file = root.appendingPathComponent("transitions.jsonl")
    let anchor = Curve25519.Signing.PrivateKey()
    let evidence = try makeStoreEvidence(
        anchor: anchor,
        old: try StoreTransitionSigner(1),
        replacement: try StoreTransitionSigner(2),
        generation: 1,
        operationID: "rotation-0001",
        transitionIndex: 1
    )
    let pem = storeAnchorPEM(anchor.publicKey)
    let store = try NativeAuditKeyTransitionStore(path: file.path, tenant: "native-host", anchorPublicKeyPEM: pem)
    let committed = try store.accept(
        transitionData: evidence.transitionData,
        receiptData: evidence.receiptData,
        retiringPublicKeyX963: evidence.old.publicKeyX963
    )
    #expect(committed.count == 1)
    #expect(committed.latestTransition == evidence.transition)
    #expect(committed.latestReceipt == evidence.receipt)
    #expect(committed.latestEventIndex == evidence.receipt.eventIndex)
    #expect(committed.latestEventHash == evidence.receipt.receiptHash)

    // Simulate a response lost after both fsync boundaries, then a helper restart.
    let restarted = try NativeAuditKeyTransitionStore(path: file.path, tenant: "native-host", anchorPublicKeyPEM: pem)
    let replay = try restarted.accept(
        transitionData: evidence.transitionData,
        receiptData: evidence.receiptData,
        retiringPublicKeyX963: evidence.old.publicKeyX963
    )
    #expect(replay == committed)
    let lines = try String(contentsOf: file, encoding: .utf8).split(separator: "\n")
    #expect(lines.count == 1)
}

@Test func auditTransitionStoreVerifiesGenerationHashReceiptAndEventContinuity() throws {
    let root = try makeProtectedStoreDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let anchor = Curve25519.Signing.PrivateKey()
    let first = try makeStoreEvidence(
        anchor: anchor, old: try StoreTransitionSigner(3), replacement: try StoreTransitionSigner(4),
        generation: 1, operationID: "rotation-0001", transitionIndex: 1
    )
    let second = try makeStoreEvidence(
        anchor: anchor, old: first.replacement, replacement: try StoreTransitionSigner(5),
        generation: 2, operationID: "rotation-0002", transitionIndex: 2,
        previousTransitionHash: first.transition.transitionHash,
        previousTransitionReceiptHash: first.receipt.receiptHash,
        previousEventIndex: first.receipt.eventIndex + 1,
        previousEventHash: String(repeating: "d", count: 64),
        checkpointIndex: first.transition.lastCheckpointIndex + 1,
        createdAt: "2030-01-01T00:00:03.000Z",
        receivedAt: "2030-01-01T00:00:04.000Z"
    )
    let store = try NativeAuditKeyTransitionStore(path: root.appendingPathComponent("transitions.jsonl").path, tenant: "native-host", anchorPublicKeyPEM: storeAnchorPEM(anchor.publicKey))
    _ = try store.accept(transitionData: first.transitionData, receiptData: first.receiptData, retiringPublicKeyX963: first.old.publicKeyX963)
    let status = try store.accept(transitionData: second.transitionData, receiptData: second.receiptData)
    #expect(status.count == 2)
    #expect(status.latestTransition?.toGeneration == 3)
    let delayedFirstReplay = try store.accept(
        transitionData: first.transitionData,
        receiptData: first.receiptData,
        retiringPublicKeyX963: first.old.publicKeyX963
    )
    #expect(delayedFirstReplay == status)

    let reusedHistoricalKey = try makeStoreEvidence(
        anchor: anchor, old: second.replacement, replacement: first.old,
        generation: 3, operationID: "rotation-reuse", transitionIndex: 3,
        previousTransitionHash: second.transition.transitionHash,
        previousTransitionReceiptHash: second.receipt.receiptHash,
        previousEventIndex: second.receipt.eventIndex + 1,
        previousEventHash: String(repeating: "e", count: 64), checkpointIndex: 9,
        createdAt: "2030-01-01T00:00:05.000Z", receivedAt: "2030-01-01T00:00:06.000Z"
    )
    #expect(throws: AgentPassNativeError.self) {
        try store.accept(transitionData: reusedHistoricalKey.transitionData, receiptData: reusedHistoricalKey.receiptData)
    }

    let discontinuous = try makeStoreEvidence(
        anchor: anchor, old: second.replacement, replacement: try StoreTransitionSigner(6),
        generation: 3, operationID: "rotation-0003", transitionIndex: 3,
        previousTransitionHash: String(repeating: "e", count: 64),
        previousTransitionReceiptHash: second.receipt.receiptHash,
        previousEventIndex: second.receipt.eventIndex + 1,
        previousEventHash: String(repeating: "f", count: 64), checkpointIndex: 9,
        createdAt: "2030-01-01T00:00:05.000Z", receivedAt: "2030-01-01T00:00:06.000Z"
    )
    #expect(throws: AgentPassNativeError.self) {
        try store.accept(transitionData: discontinuous.transitionData, receiptData: discontinuous.receiptData)
    }
}

@Test func auditTransitionStoreRejectsTailTruncationUnknownSchemaAndTamperingOnRestart() throws {
    let root = try makeProtectedStoreDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let file = root.appendingPathComponent("transitions.jsonl")
    let anchor = Curve25519.Signing.PrivateKey()
    let first = try makeStoreEvidence(anchor: anchor, old: try StoreTransitionSigner(7), replacement: try StoreTransitionSigner(8), generation: 1, operationID: "rotation-0001", transitionIndex: 1)
    let second = try makeStoreEvidence(
        anchor: anchor, old: first.replacement, replacement: try StoreTransitionSigner(9), generation: 2,
        operationID: "rotation-0002", transitionIndex: 2,
        previousTransitionHash: first.transition.transitionHash,
        previousTransitionReceiptHash: first.receipt.receiptHash,
        previousEventIndex: first.receipt.eventIndex + 1,
        previousEventHash: String(repeating: "d", count: 64), checkpointIndex: 8,
        createdAt: "2030-01-01T00:00:03.000Z", receivedAt: "2030-01-01T00:00:04.000Z"
    )
    let pem = storeAnchorPEM(anchor.publicKey)
    let store = try NativeAuditKeyTransitionStore(path: file.path, tenant: "native-host", anchorPublicKeyPEM: pem)
    _ = try store.accept(transitionData: first.transitionData, receiptData: first.receiptData, retiringPublicKeyX963: first.old.publicKeyX963)
    let oneRecord = try Data(contentsOf: file)
    _ = try store.accept(transitionData: second.transitionData, receiptData: second.receiptData)
    try overwriteStoreFile(file, data: oneRecord)
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyTransitionStore(path: file.path, tenant: "native-host", anchorPublicKeyPEM: pem)
    }

    // Restore two records, then prove exact-schema parsing rejects an extra field.
    try? FileManager.default.removeItem(at: file)
    try? FileManager.default.removeItem(at: URL(fileURLWithPath: file.path + ".tip"))
    let clean = try NativeAuditKeyTransitionStore(path: file.path, tenant: "native-host", anchorPublicKeyPEM: pem)
    _ = try clean.accept(transitionData: first.transitionData, receiptData: first.receiptData, retiringPublicKeyX963: first.old.publicKeyX963)
    var object = try #require(JSONSerialization.jsonObject(with: Data((try Data(contentsOf: file)).dropLast())) as? [String: Any])
    object["unknown"] = true
    try overwriteStoreFile(file, data: try NativeAuditLog.canonical(object) + Data([0x0a]))
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyTransitionStore(path: file.path, tenant: "native-host", anchorPublicKeyPEM: pem)
    }
}

@Test func auditTransitionStoreRejectsSymlinkHardlinkUnsafeModesAndOversize() throws {
    let anchor = Curve25519.Signing.PrivateKey()
    let pem = storeAnchorPEM(anchor.publicKey)

    do {
        let root = try makeProtectedStoreDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appendingPathComponent("target")
        FileManager.default.createFile(atPath: target.path, contents: Data(), attributes: [.posixPermissions: 0o600])
        let link = root.appendingPathComponent("transitions.jsonl")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        #expect(throws: Error.self) { try NativeAuditKeyTransitionStore(path: link.path, tenant: "native-host", anchorPublicKeyPEM: pem) }
    }
    do {
        let root = try makeProtectedStoreDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appendingPathComponent("target")
        FileManager.default.createFile(atPath: target.path, contents: Data(), attributes: [.posixPermissions: 0o600])
        let linkURL = root.appendingPathComponent("transitions.jsonl")
        guard Darwin.link(target.path, linkURL.path) == 0 else { throw POSIXError(.EIO) }
        #expect(throws: AgentPassNativeError.self) { try NativeAuditKeyTransitionStore(path: linkURL.path, tenant: "native-host", anchorPublicKeyPEM: pem) }
    }
    do {
        let root = try makeProtectedStoreDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("transitions.jsonl")
        FileManager.default.createFile(atPath: file.path, contents: Data(), attributes: [.posixPermissions: 0o644])
        #expect(throws: AgentPassNativeError.self) { try NativeAuditKeyTransitionStore(path: file.path, tenant: "native-host", anchorPublicKeyPEM: pem) }
    }
    do {
        let root = try makeProtectedStoreDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        guard chmod(root.path, 0o755) == 0 else { throw POSIXError(.EIO) }
        #expect(throws: AgentPassNativeError.self) { try NativeAuditKeyTransitionStore(path: root.appendingPathComponent("transitions.jsonl").path, tenant: "native-host", anchorPublicKeyPEM: pem) }
    }
    do {
        let root = try makeProtectedStoreDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("transitions.jsonl")
        _ = try NativeAuditKeyTransitionStore(path: file.path, tenant: "native-host", anchorPublicKeyPEM: pem)
        guard truncate(file.path, off_t(NativeAuditKeyTransitionStore.maximumLogBytes + 1)) == 0 else { throw POSIXError(.EIO) }
        #expect(throws: AgentPassNativeError.self) { try NativeAuditKeyTransitionStore(path: file.path, tenant: "native-host", anchorPublicKeyPEM: pem) }
    }
}

@Test func auditTransitionStoreDetectsPathSwapBeforeAppendAndWritesNeitherPath() throws {
    let root = try makeProtectedStoreDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let file = root.appendingPathComponent("transitions.jsonl")
    let moved = root.appendingPathComponent("moved.jsonl")
    let anchor = Curve25519.Signing.PrivateKey()
    let evidence = try makeStoreEvidence(anchor: anchor, old: try StoreTransitionSigner(10), replacement: try StoreTransitionSigner(11), generation: 1, operationID: "rotation-0001", transitionIndex: 1)
    let store = try NativeAuditKeyTransitionStore(
        path: file.path,
        tenant: "native-host",
        anchorPublicKeyPEM: storeAnchorPEM(anchor.publicKey),
        testingBeforeAppendValidation: {
            try FileManager.default.moveItem(at: file, to: moved)
            guard FileManager.default.createFile(atPath: file.path, contents: Data(), attributes: [.posixPermissions: 0o600]) else {
                throw POSIXError(.EIO)
            }
        }
    )
    #expect(throws: AgentPassNativeError.self) {
        try store.accept(transitionData: evidence.transitionData, receiptData: evidence.receiptData, retiringPublicKeyX963: evidence.old.publicKeyX963)
    }
    #expect((try Data(contentsOf: file)).isEmpty)
    #expect((try Data(contentsOf: moved)).isEmpty)
}

@Test func auditTransitionStoreDetectsTipPathSwapBeforeAppend() throws {
    let root = try makeProtectedStoreDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let file = root.appendingPathComponent("transitions.jsonl")
    let tip = URL(fileURLWithPath: file.path + ".tip")
    let movedTip = root.appendingPathComponent("moved.tip")
    let anchor = Curve25519.Signing.PrivateKey()
    let evidence = try makeStoreEvidence(anchor: anchor, old: try StoreTransitionSigner(14), replacement: try StoreTransitionSigner(15), generation: 1, operationID: "rotation-0001", transitionIndex: 1)
    let store = try NativeAuditKeyTransitionStore(
        path: file.path,
        tenant: "native-host",
        anchorPublicKeyPEM: storeAnchorPEM(anchor.publicKey),
        testingBeforeAppendValidation: {
            try FileManager.default.moveItem(at: tip, to: movedTip)
            guard FileManager.default.createFile(atPath: tip.path, contents: Data(), attributes: [.posixPermissions: 0o600]) else {
                throw POSIXError(.EIO)
            }
        }
    )
    #expect(throws: AgentPassNativeError.self) {
        try store.accept(transitionData: evidence.transitionData, receiptData: evidence.receiptData, retiringPublicKeyX963: evidence.old.publicKeyX963)
    }
    #expect((try Data(contentsOf: file)).isEmpty)
    #expect((try Data(contentsOf: tip)).isEmpty)
}

@Test func auditTransitionStoreRejectsMissingFirstRetiringKeyAndReceiptEquivocation() throws {
    let root = try makeProtectedStoreDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let anchor = Curve25519.Signing.PrivateKey()
    let evidence = try makeStoreEvidence(anchor: anchor, old: try StoreTransitionSigner(12), replacement: try StoreTransitionSigner(13), generation: 1, operationID: "rotation-0001", transitionIndex: 1)
    let store = try NativeAuditKeyTransitionStore(path: root.appendingPathComponent("transitions.jsonl").path, tenant: "native-host", anchorPublicKeyPEM: storeAnchorPEM(anchor.publicKey))
    #expect(throws: AgentPassNativeError.self) {
        try store.accept(transitionData: evidence.transitionData, receiptData: evidence.receiptData)
    }
    var receipt = try #require(JSONSerialization.jsonObject(with: evidence.receiptData) as? [String: Any])
    receipt["receipt_hash"] = String(repeating: "f", count: 64)
    #expect(throws: AgentPassNativeError.self) {
        try store.accept(
            transitionData: evidence.transitionData,
            receiptData: try NativeAuditLog.canonical(receipt),
            retiringPublicKeyX963: evidence.old.publicKeyX963
        )
    }
    #expect(try store.status().count == 0)
}

@Test func auditTransitionStoreRejectsBooleanIntegerSubstitutionInRecordSchema() throws {
    let root = try makeProtectedStoreDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let file = root.appendingPathComponent("transitions.jsonl")
    let anchor = Curve25519.Signing.PrivateKey()
    let evidence = try makeStoreEvidence(anchor: anchor, old: try StoreTransitionSigner(16), replacement: try StoreTransitionSigner(17), generation: 1, operationID: "rotation-0001", transitionIndex: 1)
    let pem = storeAnchorPEM(anchor.publicKey)
    let store = try NativeAuditKeyTransitionStore(path: file.path, tenant: "native-host", anchorPublicKeyPEM: pem)
    _ = try store.accept(transitionData: evidence.transitionData, receiptData: evidence.receiptData, retiringPublicKeyX963: evidence.old.publicKeyX963)
    var object = try #require(JSONSerialization.jsonObject(with: Data((try Data(contentsOf: file)).dropLast())) as? [String: Any])
    object["version"] = true
    object.removeValue(forKey: "record_hash")
    object["record_hash"] = NativeAuditLog.hash(try NativeAuditLog.canonical(object))
    try overwriteStoreFile(file, data: try NativeAuditLog.canonical(object) + Data([0x0a]))
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyTransitionStore(path: file.path, tenant: "native-host", anchorPublicKeyPEM: pem)
    }
}
