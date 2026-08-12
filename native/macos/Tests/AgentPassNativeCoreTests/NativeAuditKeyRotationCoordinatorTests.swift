import CryptoKit
import Darwin
import Foundation
import Testing
@testable import AgentPassNativeCore

private struct RotationSigner: P256MessageSigner {
    let key: P256.Signing.PrivateKey
    init(_ byte: UInt8) throws { key = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: byte, count: 32)) }
    var publicKeyX963: Data { key.publicKey.x963Representation }
    func sign(message: Data) throws -> Data { try key.signature(for: message).rawRepresentation }
}

private enum RotationTransportError: Error { case lostResponse }

private final class RotationTransport: NativeAuditKeyTransitionTransport, @unchecked Sendable {
    private let lock = NSLock()
    private let handler: (Data, Int) throws -> Data
    private(set) var requests: [Data] = []
    private(set) var responses: [Data] = []

    init(handler: @escaping (Data, Int) throws -> Data) { self.handler = handler }
    func submit(transitionData: Data) throws -> Data {
        lock.lock()
        requests.append(transitionData)
        let count = requests.count
        lock.unlock()
        let response = try handler(transitionData, count)
        lock.lock()
        responses.append(response)
        lock.unlock()
        return response
    }
}

private func rotationPEM(_ key: Curve25519.Signing.PublicKey) -> String {
    let der = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) + key.rawRepresentation
    return "-----BEGIN PUBLIC KEY-----\n\(der.base64EncodedString())\n-----END PUBLIC KEY-----\n"
}

private func rotationFingerprint(_ key: Curve25519.Signing.PublicKey) -> String {
    let der = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) + key.rawRepresentation
    return "SHA256:" + Data(SHA256.hash(data: der)).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}

private func rotationReceipt(_ transitionData: Data, anchor: Curve25519.Signing.PrivateKey, receivedAt: String = "2030-01-01T00:00:02.000Z") throws -> Data {
    let transition = try NativeAuditKeyTransition.decodeCanonical(transitionData)
    var value: [String: Any] = [
        "version": 2, "tenant": transition.tenant, "index": 1,
        "transition_hash": transition.transitionHash, "received_at": receivedAt,
        "previous_receipt_hash": transition.previousTransitionReceiptHash,
        "event_index": transition.previousAnchorEventIndex + 1,
        "previous_event_hash": transition.previousAnchorEventHash,
        "last_checkpoint_index": transition.lastCheckpointIndex,
        "last_checkpoint_hash": transition.lastCheckpointHash,
        "last_checkpoint_receipt_hash": transition.lastCheckpointReceiptHash
    ]
    value["signature"] = try anchor.signature(for: NativeAuditLog.canonical(value)).base64EncodedString()
    value["anchor_key_fingerprint"] = rotationFingerprint(anchor.publicKey)
    value["receipt_hash"] = NativeAuditLog.hash(try NativeAuditLog.canonical(value))
    return try NativeAuditLog.canonical(value)
}

private func rotationBoundary(pending: Int = 0, checkpointHash: String = String(repeating: "b", count: 64)) throws -> NativeAuditKeyRotationCheckpointBoundary {
    let receiptData = try NativeAuditLog.canonical([
        "version": 2, "tenant": "native-host", "index": 7,
        "checkpoint_hash": checkpointHash, "received_at": "2030-01-01T00:00:00.000Z",
        "previous_receipt_hash": String(repeating: "c", count: 64),
        "event_index": 10, "previous_event_hash": String(repeating: "d", count: 64),
        "anchor_key_fingerprint": "SHA256:" + String(repeating: "A", count: 43),
        "signature": Data(repeating: 1, count: 64).base64EncodedString(),
        "receipt_hash": String(repeating: "e", count: 64)
    ])
    let receipt = try JSONDecoder().decode(NativeAuditAnchorReceipt.self, from: receiptData)
    return NativeAuditKeyRotationCheckpointBoundary(
        anchorStatus: NativeAuditAnchorStatus(
            configured: true, checkpoints: 7, receipts: 7 - pending, pending: pending,
            latestReceiptHash: pending == 0 ? receipt.receiptHash : String(repeating: "f", count: 64)
        ),
        finalReceipt: receipt
    )
}

private func rotationStore(anchor: Curve25519.Signing.PrivateKey) throws -> (URL, NativeAuditKeyTransitionStore, NativeAuditKeyRotationPlanJournal) {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("agentpass-rotation-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    guard chmod(root.path, 0o700) == 0, let resolved = Darwin.realpath(root.path, nil) else { throw POSIXError(.EIO) }
    defer { free(resolved) }
    let canonical = URL(fileURLWithPath: String(cString: resolved))
    let journalRoot = canonical.appendingPathComponent("plan-journal")
    try FileManager.default.createDirectory(at: journalRoot, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    return (canonical, try NativeAuditKeyTransitionStore(
        path: canonical.appendingPathComponent("transitions.jsonl").path,
        tenant: "native-host", anchorPublicKeyPEM: rotationPEM(anchor.publicKey)
    ), try NativeAuditKeyRotationPlanJournal(rootPath: journalRoot.path, tenant: "native-host"))
}

@Test func auditKeyRotationPersistsAnchorEvidenceBeforeAuthorizingActivation() throws {
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, store, journal) = try rotationStore(anchor: anchor)
    defer { try? FileManager.default.removeItem(at: root) }
    let transport = RotationTransport { data, _ in
        #expect(try store.status().count == 0)
        return try rotationReceipt(data, anchor: anchor)
    }
    let coordinator = try NativeAuditKeyRotationCoordinator(tenant: "native-host", transitionStore: store, planJournal: journal, transport: transport)
    let boundary = try rotationBoundary()
    let plan = try coordinator.prepare(
        operationID: "rotation-0001", fromGeneration: 1, lifecycleHeadHash: String(repeating: "a", count: 64),
        checkpointBoundary: boundary, retiringSigner: try RotationSigner(1), replacementSigner: try RotationSigner(2),
        createdAt: "2030-01-01T00:00:01.000Z"
    )
    let authorization = try coordinator.authorizeActivation(plan: plan, checkpointBoundary: boundary)
    #expect(authorization.transitionStoreStatus.count == 1)
    #expect(authorization.receiptData == transport.responses.first)
    #expect(!authorization.recoveredFromStore)
    #expect(try store.status().latestTransition == plan.transition)
}

@Test func auditKeyRotationRejectsPendingCheckpointReceiptsWithoutContactingAnchor() throws {
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, store, journal) = try rotationStore(anchor: anchor)
    defer { try? FileManager.default.removeItem(at: root) }
    let transport = RotationTransport { _, _ in throw RotationTransportError.lostResponse }
    let coordinator = try NativeAuditKeyRotationCoordinator(tenant: "native-host", transitionStore: store, planJournal: journal, transport: transport)
    #expect(throws: AgentPassNativeError.self) {
        try coordinator.prepare(
            operationID: "rotation-0001", fromGeneration: 1, lifecycleHeadHash: String(repeating: "a", count: 64),
            checkpointBoundary: try rotationBoundary(pending: 1), retiringSigner: try RotationSigner(1), replacementSigner: try RotationSigner(2),
            createdAt: "2030-01-01T00:00:01.000Z"
        )
    }
    #expect(transport.requests.isEmpty)
}

@Test func auditKeyRotationRetriesExactPlanAfterLostResponseAndRecoversAfterRestart() throws {
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, store, journal) = try rotationStore(anchor: anchor)
    defer { try? FileManager.default.removeItem(at: root) }
    let transport = RotationTransport { data, attempt in
        if attempt == 1 { throw RotationTransportError.lostResponse }
        return try rotationReceipt(data, anchor: anchor)
    }
    let boundary = try rotationBoundary()
    let first = try NativeAuditKeyRotationCoordinator(tenant: "native-host", transitionStore: store, planJournal: journal, transport: transport)
    let plan = try first.prepare(
        operationID: "rotation-0001", fromGeneration: 1, lifecycleHeadHash: String(repeating: "a", count: 64),
        checkpointBoundary: boundary, retiringSigner: try RotationSigner(3), replacementSigner: try RotationSigner(4),
        createdAt: "2030-01-01T00:00:01.000Z"
    )
    #expect(throws: RotationTransportError.self) { try first.authorizeActivation(plan: plan, checkpointBoundary: boundary) }
    #expect(try store.status().count == 0)

    let restoredPlan = try NativeAuditKeyRotationPlan(
        transitionData: plan.transitionData,
        retiringPublicKeyX963: plan.retiringPublicKeyX963
    )
    let restarted = try NativeAuditKeyRotationCoordinator(tenant: "native-host", transitionStore: store, planJournal: journal, transport: transport)
    let committed = try restarted.authorizeActivation(plan: restoredPlan, checkpointBoundary: boundary)
    #expect(transport.requests == [plan.transitionData, plan.transitionData])
    #expect(!committed.recoveredFromStore)

    let afterCommitRestart = try NativeAuditKeyRotationCoordinator(tenant: "native-host", transitionStore: store, planJournal: journal, transport: transport)
    let recovered = try afterCommitRestart.authorizeActivation(plan: restoredPlan, checkpointBoundary: boundary)
    #expect(recovered.recoveredFromStore)
    #expect(recovered.receiptData == committed.receiptData)
    #expect(transport.requests.count == 2)
}

@Test func auditKeyRotationFailsClosedOnBoundaryDriftForkAndMismatchedReceipt() throws {
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, store, journal) = try rotationStore(anchor: anchor)
    defer { try? FileManager.default.removeItem(at: root) }
    let goodTransport = RotationTransport { data, _ in try rotationReceipt(data, anchor: anchor) }
    let coordinator = try NativeAuditKeyRotationCoordinator(tenant: "native-host", transitionStore: store, planJournal: journal, transport: goodTransport)
    let boundary = try rotationBoundary()
    let firstPlan = try coordinator.prepare(
        operationID: "rotation-0001", fromGeneration: 1, lifecycleHeadHash: String(repeating: "a", count: 64),
        checkpointBoundary: boundary, retiringSigner: try RotationSigner(5), replacementSigner: try RotationSigner(6),
        createdAt: "2030-01-01T00:00:01.000Z"
    )
    #expect(throws: AgentPassNativeError.self) {
        try coordinator.prepare(
            operationID: "rotation-0001", fromGeneration: 1, lifecycleHeadHash: String(repeating: "a", count: 64),
            checkpointBoundary: boundary, retiringSigner: try RotationSigner(5), replacementSigner: try RotationSigner(7),
            createdAt: "2030-01-01T00:00:01.000Z"
        )
    }
    #expect(throws: AgentPassNativeError.self) {
        try coordinator.authorizeActivation(plan: firstPlan, checkpointBoundary: try rotationBoundary(checkpointHash: String(repeating: "f", count: 64)))
    }
    _ = try coordinator.authorizeActivation(plan: firstPlan, checkpointBoundary: boundary)

    let (otherRoot, otherStore, otherJournal) = try rotationStore(anchor: anchor)
    defer { try? FileManager.default.removeItem(at: otherRoot) }
    let badTransport = RotationTransport { data, _ in
        try rotationReceipt(data, anchor: anchor, receivedAt: "2029-12-31T23:59:59.000Z")
    }
    let bad = try NativeAuditKeyRotationCoordinator(tenant: "native-host", transitionStore: otherStore, planJournal: otherJournal, transport: badTransport)
    let badPlan = try bad.prepare(
        operationID: "rotation-bad", fromGeneration: 1, lifecycleHeadHash: String(repeating: "a", count: 64),
        checkpointBoundary: boundary, retiringSigner: try RotationSigner(8), replacementSigner: try RotationSigner(9),
        createdAt: "2030-01-01T00:00:01.000Z"
    )
    #expect(throws: AgentPassNativeError.self) { try bad.authorizeActivation(plan: badPlan, checkpointBoundary: boundary) }
    #expect(try otherStore.status().count == 0)
}

@Test func auditKeyRotationRecoversAcceptedTransitionAndExactLifecycleRecordAfterRestart() throws {
    let anchor = Curve25519.Signing.PrivateKey()
    let (root, store, journal) = try rotationStore(anchor: anchor)
    defer { try? FileManager.default.removeItem(at: root) }
    let transport = RotationTransport { _, _ in throw RotationTransportError.lostResponse }
    let coordinator = try NativeAuditKeyRotationCoordinator(tenant: "native-host", transitionStore: store, planJournal: journal, transport: transport)
    let targetHead = String(repeating: "a", count: 64)
    let payload = try NativeAuditLog.canonical([
        "action": "activated",
        "role": NativeKeyRole.auditCheckpoint.rawValue,
        "previous_record_hash": String(repeating: "9", count: 64),
        "record_hash": targetHead
    ])
    let boundary = try rotationBoundary()
    let plan = try coordinator.prepare(
        operationID: "rotation-crash-after-anchor", fromGeneration: 1, lifecycleHeadHash: targetHead,
        checkpointBoundary: boundary, retiringSigner: try RotationSigner(10), replacementSigner: try RotationSigner(11),
        createdAt: "2030-01-01T00:00:01.000Z", lifecycleRecordData: payload
    )

    // Model anchor/store acceptance followed by power loss before the journal
    // completion and local lifecycle append.
    _ = try store.accept(
        transitionData: plan.transitionData,
        receiptData: rotationReceipt(plan.transitionData, anchor: anchor),
        retiringPublicKeyX963: plan.retiringPublicKeyX963
    )
    let restarted = try NativeAuditKeyRotationCoordinator(tenant: "native-host", transitionStore: store, planJournal: journal, transport: transport)
    #expect(try restarted.recoverAuthorizedLifecycleRecord(
        currentLifecycleHeadHash: String(repeating: "9", count: 64),
        currentAuditGeneration: 1
    ) == payload)
    #expect(try journal.pending() == nil)
    #expect(try restarted.recoverAuthorizedLifecycleRecord(
        currentLifecycleHeadHash: targetHead,
        currentAuditGeneration: 2
    ) == nil)
    #expect(transport.requests.isEmpty)
}
