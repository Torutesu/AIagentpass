import CryptoKit
import Darwin
import Foundation
import Testing
@testable import AgentPassNativeCore

private struct JournalRotationSigner: P256MessageSigner {
    let key: P256.Signing.PrivateKey
    init(_ byte: UInt8) throws {
        key = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: byte, count: 32))
    }
    var publicKeyX963: Data { key.publicKey.x963Representation }
    func sign(message: Data) throws -> Data { try key.signature(for: message).rawRepresentation }
}

private func journalDirectory(_ prefix: String = "agentpass-rotation-plan-journal") throws -> URL {
    let build = URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent(".build")
    let url = build.appendingPathComponent("\(prefix)-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    guard chmod(url.path, 0o700) == 0, let resolved = Darwin.realpath(url.path, nil) else { throw POSIXError(.EIO) }
    defer { free(resolved) }
    return URL(fileURLWithPath: String(cString: resolved))
}

private func journalPlan(
    tenant: String = "native-host",
    operationID: String = UUID().uuidString.lowercased(),
    generation: Int,
    old: JournalRotationSigner,
    replacement: JournalRotationSigner,
    previousTransitionHash: String = String(repeating: "0", count: 64),
    previousReceiptHash: String = String(repeating: "0", count: 64),
    createdAt: String = "2032-01-01T00:00:00.000Z"
) throws -> NativeAuditKeyRotationPlan {
    let statement = try NativeAuditKeyTransitionStatement(
        tenant: tenant,
        operationID: operationID,
        fromGeneration: generation,
        oldPublicKeyX963: old.publicKeyX963,
        newPublicKeyX963: replacement.publicKeyX963,
        lifecycleHeadHash: String(repeating: "1", count: 64),
        lastCheckpointIndex: generation,
        lastCheckpointHash: String(repeating: "2", count: 64),
        lastCheckpointReceiptHash: String(repeating: "3", count: 64),
        previousTransitionHash: previousTransitionHash,
        previousTransitionReceiptHash: previousReceiptHash,
        previousAnchorEventIndex: generation,
        previousAnchorEventHash: String(repeating: "4", count: 64),
        createdAt: createdAt
    )
    let transition = try NativeAuditKeyTransition(statement: statement, retiringSigner: old, replacementSigner: replacement)
    return try NativeAuditKeyRotationPlan(transitionData: transition.canonicalData(), retiringPublicKeyX963: old.publicKeyX963)
}

private func journalRecordURL(_ root: URL, prefix: String) throws -> URL {
    let name = try #require(FileManager.default.contentsOfDirectory(atPath: root.path).first(where: { $0.hasPrefix(prefix) }))
    return root.appendingPathComponent(name)
}

private func rewriteJournalFile(_ url: URL, finalMode: mode_t = 0o400, mutate: (inout Data) -> Void) throws {
    var data = try Data(contentsOf: url)
    mutate(&data)
    guard chmod(url.path, 0o600) == 0 else { throw POSIXError(.EIO) }
    let descriptor = open(url.path, O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw POSIXError(.EIO) }
    defer { close(descriptor) }
    try data.withUnsafeBytes { bytes in
        var offset = 0
        while offset < bytes.count {
            let amount = Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
            guard amount > 0 else { throw POSIXError(.EIO) }
            offset += amount
        }
    }
    guard fchmod(descriptor, finalMode) == 0, fsync(descriptor) == 0 else { throw POSIXError(.EIO) }
}

@Test func rotationPlanJournalPersistsExactBytesRestartsAndSupportsArbitraryGeneration() throws {
    let root = try journalDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let old = try JournalRotationSigner(11)
    let replacement = try JournalRotationSigner(12)
    let plan = try journalPlan(operationID: "rotation-0001", generation: 41, old: old, replacement: replacement)
    let journal = try NativeAuditKeyRotationPlanJournal(rootPath: root.path, tenant: "native-host")
    let prepared = try journal.prepare(plan, preparedAt: "2032-01-01T00:00:01.000Z")

    #expect(prepared.fromGeneration == 41)
    #expect(prepared.toGeneration == 42)
    #expect(prepared.operationID == "rotation-0001")
    #expect(prepared.transitionData == plan.transitionData)
    #expect(prepared.retiringPublicKeyX963 == plan.retiringPublicKeyX963)
    #expect(try journal.prepare(plan, preparedAt: "2032-01-01T00:00:01.000Z") == prepared)

    let restarted = try NativeAuditKeyRotationPlanJournal(rootPath: root.path, tenant: "native-host")
    let pendingAfterRestart = try restarted.pending()
    let resumed = try #require(pendingAfterRestart)
    #expect(resumed == prepared)
    #expect(resumed.transitionData == plan.transitionData)
    let receiptHash = String(repeating: "a", count: 64)
    let completed = try restarted.complete(resumed, transitionStoreReceiptHash: receiptHash, completedAt: "2032-01-01T00:00:02.000Z")
    #expect(completed.transitionStoreReceiptHash == receiptHash)
    #expect(try restarted.status().completed == [completed])
    #expect(try restarted.pending() == nil)

    let finalRestart = try NativeAuditKeyRotationPlanJournal(rootPath: root.path, tenant: "native-host")
    #expect(try finalRestart.status().completed == [completed])
}

@Test func rotationPlanJournalPersistsExactLifecycleActivationRecoveryBytes() throws {
    let root = try journalDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let base = try journalPlan(operationID: "rotation-with-lifecycle-record", generation: 51, old: try JournalRotationSigner(34), replacement: try JournalRotationSigner(35))
    let payload = try JSONSerialization.data(withJSONObject: [
        "action": "activated",
        "role": NativeKeyRole.auditCheckpoint.rawValue,
        "previous_record_hash": String(repeating: "0", count: 64),
        "record_hash": base.transition.lifecycleHeadHash
    ], options: [.sortedKeys, .withoutEscapingSlashes])
    let plan = try NativeAuditKeyRotationPlan(
        transitionData: base.transitionData,
        retiringPublicKeyX963: base.retiringPublicKeyX963,
        lifecycleRecordData: payload
    )
    var journal: NativeAuditKeyRotationPlanJournal? = try NativeAuditKeyRotationPlanJournal(rootPath: root.path, tenant: "native-host")
    let prepared = try journal!.prepare(plan, preparedAt: "2032-01-01T00:00:01.000Z")
    #expect(prepared.plan.lifecycleRecordData == payload)
    journal = nil

    let restarted = try NativeAuditKeyRotationPlanJournal(rootPath: root.path, tenant: "native-host")
    #expect(try restarted.pending()?.plan.lifecycleRecordData == payload)

    var tampered = payload
    tampered[tampered.count - 2] ^= 1
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRotationPlan(
            transitionData: base.transitionData,
            retiringPublicKeyX963: base.retiringPublicKeyX963,
            lifecycleRecordData: tampered
        )
    }
}

@Test func rotationPlanJournalAllowsOnlyOnePendingAndRejectsEquivocationAndOperationIDReuse() throws {
    let root = try journalDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let journal = try NativeAuditKeyRotationPlanJournal(rootPath: root.path, tenant: "native-host")
    let operation = "rotation-reused-operation"
    let first = try journalPlan(operationID: operation, generation: 9, old: try JournalRotationSigner(13), replacement: try JournalRotationSigner(14))
    let prepared = try journal.prepare(first, preparedAt: "2032-01-01T00:00:01.000Z")

    let competing = try journalPlan(generation: 9, old: try JournalRotationSigner(13), replacement: try JournalRotationSigner(15))
    #expect(throws: AgentPassNativeError.self) {
        try journal.prepare(competing, preparedAt: "2032-01-01T00:00:01.000Z")
    }
    let later = try journalPlan(generation: 10, old: try JournalRotationSigner(14), replacement: try JournalRotationSigner(16))
    #expect(throws: AgentPassNativeError.self) {
        try journal.prepare(later, preparedAt: "2032-01-01T00:00:03.000Z")
    }

    _ = try journal.complete(prepared, transitionStoreReceiptHash: String(repeating: "b", count: 64), completedAt: "2032-01-01T00:00:02.000Z")
    let reused = try journalPlan(
        operationID: operation, generation: 10, old: try JournalRotationSigner(14), replacement: try JournalRotationSigner(16),
        previousTransitionHash: first.transition.transitionHash, previousReceiptHash: String(repeating: "b", count: 64),
        createdAt: "2032-01-01T00:00:03.000Z"
    )
    #expect(throws: AgentPassNativeError.self) {
        try journal.prepare(reused, preparedAt: "2032-01-01T00:00:03.000Z")
    }
}

@Test func rotationPlanJournalRecoversOneFsyncedRecordAheadOfTip() throws {
    let root = try journalDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let tip = root.appendingPathComponent("tip.json")
    var journal: NativeAuditKeyRotationPlanJournal? = try NativeAuditKeyRotationPlanJournal(rootPath: root.path, tenant: "native-host")
    let tipBeforePrepare = try Data(contentsOf: tip)
    let plan = try journalPlan(operationID: "rotation-crash-recovery", generation: 77, old: try JournalRotationSigner(32), replacement: try JournalRotationSigner(33))
    _ = try journal!.prepare(plan, preparedAt: "2032-01-01T00:00:01.000Z")
    journal = nil

    // Model power loss after the immutable record+directory fsync but before
    // the atomic tip replacement became durable.
    try rewriteJournalFile(tip, finalMode: 0o600) { $0 = tipBeforePrepare }
    let restarted = try NativeAuditKeyRotationPlanJournal(rootPath: root.path, tenant: "native-host")
    #expect(try restarted.pending()?.transitionData == plan.transitionData)
}

@Test func rotationPlanJournalEnforcesGenerationAndReceiptChainContinuity() throws {
    let root = try journalDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let old = try JournalRotationSigner(17)
    let replacement = try JournalRotationSigner(18)
    let first = try journalPlan(generation: 100, old: old, replacement: replacement)
    let journal = try NativeAuditKeyRotationPlanJournal(rootPath: root.path, tenant: "native-host")
    let prepared = try journal.prepare(first, preparedAt: "2032-01-01T00:00:01.000Z")
    let receiptHash = String(repeating: "c", count: 64)
    _ = try journal.complete(prepared, transitionStoreReceiptHash: receiptHash, completedAt: "2032-01-01T00:00:02.000Z")

    let gap = try journalPlan(generation: 102, old: replacement, replacement: try JournalRotationSigner(19), previousTransitionHash: first.transition.transitionHash, previousReceiptHash: receiptHash, createdAt: "2032-01-01T00:00:03.000Z")
    #expect(throws: AgentPassNativeError.self) { try journal.prepare(gap, preparedAt: "2032-01-01T00:00:03.000Z") }
    let wrongReceipt = try journalPlan(generation: 101, old: replacement, replacement: try JournalRotationSigner(19), previousTransitionHash: first.transition.transitionHash, previousReceiptHash: String(repeating: "d", count: 64), createdAt: "2032-01-01T00:00:03.000Z")
    #expect(throws: AgentPassNativeError.self) { try journal.prepare(wrongReceipt, preparedAt: "2032-01-01T00:00:03.000Z") }
    let next = try journalPlan(generation: 101, old: replacement, replacement: try JournalRotationSigner(19), previousTransitionHash: first.transition.transitionHash, previousReceiptHash: receiptHash, createdAt: "2032-01-01T00:00:03.000Z")
    #expect(try journal.prepare(next, preparedAt: "2032-01-01T00:00:03.000Z").fromGeneration == 101)
}

@Test func rotationPlanJournalCompletionBindsExactReceiptHash() throws {
    let root = try journalDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let journal = try NativeAuditKeyRotationPlanJournal(rootPath: root.path, tenant: "native-host")
    let plan = try journalPlan(generation: 5, old: try JournalRotationSigner(20), replacement: try JournalRotationSigner(21))
    let prepared = try journal.prepare(plan, preparedAt: "2032-01-01T00:00:01.000Z")
    let exact = String(repeating: "e", count: 64)
    let completion = try journal.complete(prepared, transitionStoreReceiptHash: exact, completedAt: "2032-01-01T00:00:02.000Z")
    #expect(try journal.complete(prepared, transitionStoreReceiptHash: exact, completedAt: "2032-01-01T00:00:02.000Z") == completion)
    #expect(throws: AgentPassNativeError.self) {
        try journal.complete(prepared, transitionStoreReceiptHash: String(repeating: "f", count: 64), completedAt: "2032-01-01T00:00:02.000Z")
    }
}

@Test func rotationPlanJournalRejectsTenantBoundaryMismatch() throws {
    let root = try journalDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let journal = try NativeAuditKeyRotationPlanJournal(rootPath: root.path, tenant: "native-host")
    let wrongTenant = try journalPlan(tenant: "other-host", generation: 7, old: try JournalRotationSigner(22), replacement: try JournalRotationSigner(23))
    #expect(throws: AgentPassNativeError.self) {
        try journal.prepare(wrongTenant, preparedAt: "2032-01-01T00:00:01.000Z")
    }
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRotationPlanJournal(rootPath: root.path, tenant: "other-host")
    }
}

@Test func rotationPlanJournalDetectsRecordTamperingAndTailTruncation() throws {
    let tamperRoot = try journalDirectory("agentpass-rotation-tamper")
    defer { try? FileManager.default.removeItem(at: tamperRoot) }
    var journal: NativeAuditKeyRotationPlanJournal? = try NativeAuditKeyRotationPlanJournal(rootPath: tamperRoot.path, tenant: "native-host")
    let plan = try journalPlan(generation: 30, old: try JournalRotationSigner(24), replacement: try JournalRotationSigner(25))
    _ = try journal!.prepare(plan, preparedAt: "2032-01-01T00:00:01.000Z")
    journal = nil
    let prepareFile = try journalRecordURL(tamperRoot, prefix: "prepare-")
    try rewriteJournalFile(prepareFile) { data in data[data.count / 2] ^= 1 }
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRotationPlanJournal(rootPath: tamperRoot.path, tenant: "native-host")
    }

    let truncateRoot = try journalDirectory("agentpass-rotation-truncate")
    defer { try? FileManager.default.removeItem(at: truncateRoot) }
    var truncateJournal: NativeAuditKeyRotationPlanJournal? = try NativeAuditKeyRotationPlanJournal(rootPath: truncateRoot.path, tenant: "native-host")
    let truncatePlan = try journalPlan(generation: 31, old: try JournalRotationSigner(26), replacement: try JournalRotationSigner(27))
    let pending = try truncateJournal!.prepare(truncatePlan, preparedAt: "2032-01-01T00:00:01.000Z")
    _ = try truncateJournal!.complete(pending, transitionStoreReceiptHash: String(repeating: "1", count: 64), completedAt: "2032-01-01T00:00:02.000Z")
    truncateJournal = nil
    try FileManager.default.removeItem(at: journalRecordURL(truncateRoot, prefix: "completed-"))
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRotationPlanJournal(rootPath: truncateRoot.path, tenant: "native-host")
    }
}

@Test func rotationPlanJournalRejectsSymlinksHardlinksAndPermissivePaths() throws {
    let parent = try journalDirectory("agentpass-rotation-links")
    defer { try? FileManager.default.removeItem(at: parent) }
    let actual = parent.appendingPathComponent("actual")
    try FileManager.default.createDirectory(at: actual, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    let link = parent.appendingPathComponent("linked")
    try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: actual.path)
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRotationPlanJournal(rootPath: link.path, tenant: "native-host")
    }

    let permissive = parent.appendingPathComponent("permissive")
    try FileManager.default.createDirectory(at: permissive, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o755])
    guard chmod(permissive.path, 0o755) == 0 else { throw POSIXError(.EIO) }
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRotationPlanJournal(rootPath: permissive.path, tenant: "native-host")
    }

    let secure = parent.appendingPathComponent("secure")
    try FileManager.default.createDirectory(at: secure, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    var journal: NativeAuditKeyRotationPlanJournal? = try NativeAuditKeyRotationPlanJournal(rootPath: secure.path, tenant: "native-host")
    let plan = try journalPlan(generation: 6, old: try JournalRotationSigner(28), replacement: try JournalRotationSigner(29))
    _ = try journal!.prepare(plan, preparedAt: "2032-01-01T00:00:01.000Z")
    journal = nil
    let record = try journalRecordURL(secure, prefix: "prepare-")
    let alias = parent.appendingPathComponent("record-hardlink")
    guard linkat(AT_FDCWD, record.path, AT_FDCWD, alias.path, 0) == 0 else { throw POSIXError(.EIO) }
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRotationPlanJournal(rootPath: secure.path, tenant: "native-host")
    }
}

@Test func rotationPlanJournalDetectsDirectoryPathSwap() throws {
    let root = try journalDirectory("agentpass-rotation-swap")
    let parent = root.deletingLastPathComponent()
    let moved = parent.appendingPathComponent("\(root.lastPathComponent)-moved")
    defer {
        try? FileManager.default.removeItem(at: root)
        try? FileManager.default.removeItem(at: moved)
    }
    let journal = try NativeAuditKeyRotationPlanJournal(rootPath: root.path, tenant: "native-host")
    try FileManager.default.moveItem(at: root, to: moved)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    guard chmod(root.path, 0o700) == 0 else { throw POSIXError(.EIO) }
    let plan = try journalPlan(generation: 4, old: try JournalRotationSigner(30), replacement: try JournalRotationSigner(31))
    #expect(throws: AgentPassNativeError.self) {
        try journal.prepare(plan, preparedAt: "2032-01-01T00:00:01.000Z")
    }
}
