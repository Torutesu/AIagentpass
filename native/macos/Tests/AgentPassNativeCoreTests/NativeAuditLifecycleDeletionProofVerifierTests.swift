import CryptoKit
import Darwin
import Foundation
import Testing
@testable import AgentPassNativeCore

private struct DeletionProofP256Signer: P256MessageSigner {
    let key: P256.Signing.PrivateKey

    init(_ byte: UInt8) throws {
        key = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: byte, count: 32))
    }

    var publicKeyX963: Data { key.publicKey.x963Representation }
    func sign(message: Data) throws -> Data { try key.signature(for: message).rawRepresentation }
}

private struct DeletionProofAncestry: NativeLifecycleHeadAncestryVerifier {
    let acceptedAncestor: String
    let acceptedCurrent: String

    func provesCurrentHeadDescendsFrom(ancestorHeadHash: String, currentHeadHash: String) throws -> Bool {
        ancestorHeadHash == acceptedAncestor && currentHeadHash == acceptedCurrent
    }
}

private final class DeletionProofMutableAncestry: NativeLifecycleHeadAncestryVerifier, @unchecked Sendable {
    private let lock = NSLock()
    private var accepted = true

    func reject() {
        lock.lock(); accepted = false; lock.unlock()
    }

    func provesCurrentHeadDescendsFrom(ancestorHeadHash: String, currentHeadHash: String) throws -> Bool {
        lock.lock(); defer { lock.unlock() }
        return accepted
    }
}

private final class DeletionProofPruneTrust: NativeAuditPruneTrustSource, @unchecked Sendable {
    private let lock = NSLock()
    private let boundary: NativeAuditRetentionBoundary
    private var state = NativeAuditPruneChainState()
    private var revision = 1
    private var reservation: NativeAuditPruneMutationReservation?

    init(boundary: NativeAuditRetentionBoundary) { self.boundary = boundary }

    func currentAuditPruneTrustSnapshot() throws -> NativeAuditPruneTrustSnapshot {
        lock.lock(); defer { lock.unlock() }
        return NativeAuditPruneTrustSnapshot(
            revision: revision,
            boundary: boundary,
            chainState: state,
            activeReservationID: reservation?.reservationID
        )
    }

    func acquireAuditPruneMutationReservation(
        operationID: String,
        expected: NativeAuditPruneMutationReservation?
    ) throws -> NativeAuditPruneMutationReservation {
        lock.lock(); defer { lock.unlock() }
        if let expected {
            guard reservation == expected else { throw AgentPassNativeError.invalidSignature("Test prune reservation changed") }
            return expected
        }
        guard reservation == nil else { throw AgentPassNativeError.invalidSignature("Test prune mutation is already reserved") }
        let value = NativeAuditPruneMutationReservation(
            reservationID: "reservation-\(operationID)",
            operationID: operationID,
            snapshotRevision: revision,
            boundary: boundary,
            chainState: state
        )
        reservation = value
        return value
    }

    func validateAuditPruneMutationReservation(_ value: NativeAuditPruneMutationReservation) throws {
        lock.lock(); defer { lock.unlock() }
        guard reservation == value, value.snapshotRevision == revision,
              value.boundary == boundary, value.chainState == state else {
            throw AgentPassNativeError.invalidSignature("Test prune reservation is stale")
        }
    }

    func completeAuditPruneMutationReservation(
        _ value: NativeAuditPruneMutationReservation,
        nextState: NativeAuditPruneChainState
    ) throws {
        lock.lock(); defer { lock.unlock() }
        guard reservation == value else { throw AgentPassNativeError.invalidSignature("Test prune completion reservation changed") }
        state = nextState
        revision += 1
        reservation = nil
    }

    func cancelAuditPruneMutationReservation(_ value: NativeAuditPruneMutationReservation) throws {
        lock.lock(); defer { lock.unlock() }
        guard reservation == value else { throw AgentPassNativeError.invalidSignature("Test prune cancellation reservation changed") }
        reservation = nil
    }
}

private struct DeletionProofPruneTransport: NativeAuditPruneTransport {
    let receivedAt: String

    func submitAuditPrune(tenant: String, authorizationData: Data) throws -> Data {
        let authorization = try NativeAuditPruneAuthorization.decodeCanonical(authorizationData)
        guard tenant == authorization.tenant else { throw AgentPassNativeError.invalidSignature("Test prune tenant changed") }
        return try deletionPruneReceipt(authorization, receivedAt: receivedAt).canonicalData()
    }
}

private struct DeletionProofFixture {
    let directory: URL
    let store: NativeAuditKeyTransitionStore
    let retentionVerifier: NativeAuditRetentionVerifier
    let authorizationData: Data
    let pruneReceiptData: Data
    let manifestData: Data
    let completionProofData: Data
    let completionStatementData: Data
    let quarantinedMarkerData: Data
    let manifestCommitMarkerData: Data
    let deletionEvidenceBundleData: Data
    let archivePaths: [URL]
    let expectedNextRetained: NativeAuditRetentionSegment
    let expectedNextRetainedFileIdentities: [NativeAuditRetentionFileIdentity]
    let prunePlan: NativeAuditPrunePlan
    let boundary: NativeAuditRetentionBoundary
    let transition: NativeAuditKeyTransition
    let transitionReceipt: NativeAuditKeyTransitionReceipt
    let manifest: NativeAuditPostPruneManifest
    let completionProof: NativeAuditPruneCompletionProof

    var archiveDirectory: URL { directory.appendingPathComponent("archives", isDirectory: true) }
    var retainedArchivePaths: [URL] {
        [
            archiveDirectory.appendingPathComponent(expectedNextRetained.auditArchiveFile),
            archiveDirectory.appendingPathComponent(expectedNextRetained.checkpointArchiveFile),
            archiveDirectory.appendingPathComponent(expectedNextRetained.receiptArchiveFile),
        ]
    }

    var proof: NativeLifecycleDeletionProof {
        NativeLifecycleDeletionProof(
            lifecycleHeadHash: boundary.lifecycleHeadHash,
            transitionReceiptHash: transitionReceipt.receiptHash,
            transitionArchivedAt: transitionReceipt.receivedAt,
            verifiedAt: try! NativeAuditPruneExecutorCompletionStatement
                .decodeCanonical(completionStatementData).completedAt
        )
    }
}

private func deletionRetainedLease(_ fixture: DeletionProofFixture) throws -> NativeAuditRetainedArchiveLease {
    try NativeAuditRetainedArchiveLease(
        archiveDirectory: fixture.archiveDirectory.path,
        segment: fixture.expectedNextRetained,
        expectedFileIdentities: fixture.expectedNextRetainedFileIdentities
    )
}

@Test func retainedArchiveDeletionLeaseRejectsMissingAndReplacementFiles() throws {
    for replacement in [false, true] {
        let fixture = try makeDeletionFixture()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let target = fixture.retainedArchivePaths[0]
        try FileManager.default.removeItem(at: target)
        if replacement {
            try Data("retained-audit-archive\n".utf8).write(to: target)
            guard chmod(target.path, 0o600) == 0 else { throw POSIXError(.EIO) }
        }
        #expect(throws: (any Error).self) { try deletionRetainedLease(fixture) }
    }
}

@Test func retainedArchiveDeletionLeaseRejectsSymlinkAndHardlink() throws {
    do {
        let fixture = try makeDeletionFixture()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let target = fixture.retainedArchivePaths[0]
        let moved = fixture.archiveDirectory.appendingPathComponent("moved-retained-audit.jsonl")
        try FileManager.default.moveItem(at: target, to: moved)
        guard symlink(moved.path, target.path) == 0 else { throw POSIXError(.EIO) }
        #expect(throws: (any Error).self) { try deletionRetainedLease(fixture) }
    }
    do {
        let fixture = try makeDeletionFixture()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let target = fixture.retainedArchivePaths[0]
        let alias = fixture.archiveDirectory.appendingPathComponent("retained-hardlink.jsonl")
        guard link(target.path, alias.path) == 0 else { throw POSIXError(.EIO) }
        #expect(throws: AgentPassNativeError.self) { try deletionRetainedLease(fixture) }
    }
}

@Test func retainedArchiveDeletionLeaseDetectsPostVerificationPathSwap() throws {
    let fixture = try makeDeletionFixture()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let lease = try deletionRetainedLease(fixture)
    let target = fixture.retainedArchivePaths[0]
    let original = fixture.archiveDirectory.appendingPathComponent("original-retained-audit.jsonl")
    try FileManager.default.moveItem(at: target, to: original)
    try Data("retained-audit-archive\n".utf8).write(to: target)
    guard chmod(target.path, 0o600) == 0 else { throw POSIXError(.EIO) }

    #expect(throws: AgentPassNativeError.self) { try lease.revalidate() }
}

@Test func retainedArchiveDeletionLeaseDetectsArchiveDirectoryRenameAndReplacement() throws {
    let fixture = try makeDeletionFixture()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let lease = try deletionRetainedLease(fixture)
    let moved = fixture.directory.appendingPathComponent("archives-moved", isDirectory: true)
    try FileManager.default.moveItem(at: fixture.archiveDirectory, to: moved)
    try FileManager.default.createDirectory(at: fixture.archiveDirectory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    guard chmod(fixture.archiveDirectory.path, 0o700) == 0 else { throw POSIXError(.EIO) }
    #expect(throws: AgentPassNativeError.self) { try lease.revalidate() }
}

@Test func retainedArchiveDeletionLeaseDetectsTrustRootParentRenameAndReplacement() throws {
    let fixture = try makeDeletionFixture()
    let moved = fixture.directory.deletingLastPathComponent()
        .appendingPathComponent("moved-\(UUID().uuidString)", isDirectory: true)
    defer {
        try? FileManager.default.removeItem(at: fixture.directory)
        try? FileManager.default.removeItem(at: moved)
    }
    let lease = try deletionRetainedLease(fixture)
    try FileManager.default.moveItem(at: fixture.directory, to: moved)
    try FileManager.default.createDirectory(
        at: fixture.archiveDirectory,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
    )
    guard chmod(fixture.directory.path, 0o700) == 0,
          chmod(fixture.archiveDirectory.path, 0o700) == 0 else { throw POSIXError(.EIO) }

    #expect(throws: AgentPassNativeError.self) { try lease.revalidate() }
}

@Test func retainedArchiveDeletionLeaseDetectsMultipleAncestorReplacement() throws {
    let fixture = try makeDeletionFixture()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let first = fixture.directory.appendingPathComponent("level-one", isDirectory: true)
    let second = first.appendingPathComponent("level-two", isDirectory: true)
    let nestedArchive = second.appendingPathComponent("archives", isDirectory: true)
    try FileManager.default.createDirectory(at: second, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    guard chmod(first.path, 0o700) == 0, chmod(second.path, 0o700) == 0 else { throw POSIXError(.EIO) }
    try FileManager.default.moveItem(at: fixture.archiveDirectory, to: nestedArchive)
    let lease = try NativeAuditRetainedArchiveLease(
        archiveDirectory: nestedArchive.path,
        segment: fixture.expectedNextRetained,
        expectedFileIdentities: fixture.expectedNextRetainedFileIdentities
    )

    let moved = fixture.directory.appendingPathComponent("level-one-moved", isDirectory: true)
    try FileManager.default.moveItem(at: first, to: moved)
    try FileManager.default.createDirectory(at: nestedArchive, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    guard chmod(first.path, 0o700) == 0, chmod(second.path, 0o700) == 0,
          chmod(nestedArchive.path, 0o700) == 0 else { throw POSIXError(.EIO) }

    #expect(throws: AgentPassNativeError.self) { try lease.revalidate() }
}

@Test func retainedArchiveDeletionLeaseStickyRejectsAncestorSymlinkRestorationRace() throws {
    let fixture = try makeDeletionFixture()
    let moved = fixture.directory.deletingLastPathComponent()
        .appendingPathComponent("moved-\(UUID().uuidString)", isDirectory: true)
    defer {
        if FileManager.default.fileExists(atPath: fixture.directory.path) {
            try? FileManager.default.removeItem(at: fixture.directory)
        }
        try? FileManager.default.removeItem(at: moved)
    }
    let lease = try deletionRetainedLease(fixture)
    try FileManager.default.moveItem(at: fixture.directory, to: moved)
    guard symlink(moved.path, fixture.directory.path) == 0 else { throw POSIXError(.EIO) }
    #expect(throws: AgentPassNativeError.self) { try lease.revalidate() }

    guard unlink(fixture.directory.path) == 0 else { throw POSIXError(.EIO) }
    try FileManager.default.moveItem(at: moved, to: fixture.directory)
    // Even though every pathname once again resolves to the original inode, the queued rename
    // event permanently invalidates this lease and prevents a swap-and-restore bypass.
    #expect(throws: AgentPassNativeError.self) { try lease.revalidate() }
}

private func deletionPreparedSpool(_ fixture: DeletionProofFixture) throws -> (URL, NativeAuditDeletionPreparedEvidence) {
    let root = fixture.directory.appendingPathComponent("deletion-spool", isDirectory: true)
    try NativeAuditDeletionRecoverySpool.ensureRoot(root.path)
    let prepared = try NativeAuditDeletionRecoverySpool.prepare(
        rootPath: root.path,
        bundleData: fixture.deletionEvidenceBundleData,
        segment: fixture.expectedNextRetained,
        identities: fixture.expectedNextRetainedFileIdentities,
        sourceLease: deletionRetainedLease(fixture)
    )
    return (root, prepared)
}

@Test func auditDeletionRecoverySpoolIsDurableAndRejectsTampering() throws {
    let fixture = try makeDeletionFixture()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let (root, prepared) = try deletionPreparedSpool(fixture)
    try prepared.spoolLease.revalidate()
    #expect(prepared.binding.bundleSHA256 == NativeAuditDeletionEvidenceHash.canonicalData(fixture.deletionEvidenceBundleData))

    let bundle = root.appendingPathComponent(prepared.binding.spoolDirectoryName).appendingPathComponent("bundle-v4.json")
    guard chmod(bundle.path, 0o600) == 0 else { throw POSIXError(.EIO) }
    try Data("{}".utf8).write(to: bundle)
    guard chmod(bundle.path, 0o400) == 0 else { throw POSIXError(.EIO) }
    #expect(throws: AgentPassNativeError.self) {
        _ = try NativeAuditDeletionRecoverySpool.open(rootPath: root.path, binding: prepared.binding)
    }
}

@Test func auditDeletionRecoverySpoolRejectsDirectoryRollbackAndCanonicalBundleSubstitution() throws {
    let fixture = try makeDeletionFixture()
    let other = try makeDeletionFixture(lifecycleCharacter: "e")
    defer {
        try? FileManager.default.removeItem(at: fixture.directory)
        try? FileManager.default.removeItem(at: other.directory)
    }
    let (root, prepared) = try deletionPreparedSpool(fixture)
    let original = root.appendingPathComponent(prepared.binding.spoolDirectoryName)
    let moved = root.appendingPathComponent("moved-spool")
    try FileManager.default.moveItem(at: original, to: moved)
    try FileManager.default.copyItem(at: moved, to: original)
    #expect(throws: AgentPassNativeError.self) {
        _ = try NativeAuditDeletionRecoverySpool.open(rootPath: root.path, binding: prepared.binding)
    }

    try FileManager.default.removeItem(at: original)
    try FileManager.default.moveItem(at: moved, to: original)
    let bundle = original.appendingPathComponent("bundle-v4.json")
    guard chmod(bundle.path, 0o600) == 0 else { throw POSIXError(.EIO) }
    try other.deletionEvidenceBundleData.write(to: bundle)
    guard chmod(bundle.path, 0o400) == 0 else { throw POSIXError(.EIO) }
    #expect(throws: AgentPassNativeError.self) {
        _ = try NativeAuditDeletionRecoverySpool.open(rootPath: root.path, binding: prepared.binding)
    }
}

private let deletionPolicySeconds = 7 * 24 * 60 * 60
private let deletionAuthorizer = try! DeletionProofP256Signer(0x31)
private let deletionAnchor = try! Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x32, count: 32))

private func deletionHash(_ character: Character) -> String {
    String(repeating: character, count: 64)
}

private func deletionDate(_ value: String) -> Date {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.date(from: value)!
}

private func deletionHighSDocument(_ data: Data, hashKey: String) throws -> Data {
    guard var object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
          let encoded = object["signature"] as? String,
          let low = Data(base64Encoded: encoded), low.count == 64,
          NativeP256CanonicalSignature.isCanonicalLowS(low) else {
        throw AgentPassNativeError.invalidSignature("Test document does not contain a canonical P-256 signature")
    }
    let order: [UInt8] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
    ]
    let scalar = [UInt8](low.suffix(32))
    var highScalar = [UInt8](repeating: 0, count: 32)
    var borrow = 0
    for index in stride(from: 31, through: 0, by: -1) {
        var difference = Int(order[index]) - Int(scalar[index]) - borrow
        if difference < 0 { difference += 256; borrow = 1 } else { borrow = 0 }
        highScalar[index] = UInt8(difference)
    }
    let high = Data(low.prefix(32)) + Data(highScalar)
    guard !NativeP256CanonicalSignature.isCanonicalLowS(high) else {
        throw AgentPassNativeError.invalidSignature("Test signature was not converted to high-S")
    }
    object["signature"] = high.base64EncodedString()
    object.removeValue(forKey: hashKey)
    object[hashKey] = NativeAuditLog.hash(try NativeAuditLog.canonical(object))
    return try NativeAuditLog.canonical(object)
}

private func deletionAnchorPEM() -> String {
    let prefix = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])
    return "-----BEGIN PUBLIC KEY-----\n\((prefix + deletionAnchor.publicKey.rawRepresentation).base64EncodedString())\n-----END PUBLIC KEY-----\n"
}

private func deletionAnchorFingerprint() -> String {
    let prefix = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])
    return "SHA256:" + Data(SHA256.hash(data: prefix + deletionAnchor.publicKey.rawRepresentation))
        .base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private func deletionDirectory() throws -> URL {
    let candidate = FileManager.default.temporaryDirectory
        .appendingPathComponent("agentpass-deletion-proof-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(
        at: candidate,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    guard chmod(candidate.path, 0o700) == 0,
          let resolved = Darwin.realpath(candidate.path, nil) else {
        throw POSIXError(.EIO)
    }
    defer { free(resolved) }
    return URL(fileURLWithPath: String(cString: resolved), isDirectory: true)
}

private func deletionTransitionReceipt(
    transition: NativeAuditKeyTransition,
    receivedAt: String
) throws -> (Data, NativeAuditKeyTransitionReceipt) {
    var statement: [String: Any] = [
        "version": 2,
        "tenant": transition.tenant,
        "index": 1,
        "transition_hash": transition.transitionHash,
        "received_at": receivedAt,
        "previous_receipt_hash": transition.previousTransitionReceiptHash,
        "event_index": transition.previousAnchorEventIndex + 1,
        "previous_event_hash": transition.previousAnchorEventHash,
        "last_checkpoint_index": transition.lastCheckpointIndex,
        "last_checkpoint_hash": transition.lastCheckpointHash,
        "last_checkpoint_receipt_hash": transition.lastCheckpointReceiptHash,
    ]
    statement["signature"] = try deletionAnchor.signature(for: NativeAuditLog.canonical(statement)).base64EncodedString()
    statement["anchor_key_fingerprint"] = deletionAnchorFingerprint()
    statement["receipt_hash"] = NativeAuditLog.hash(try NativeAuditLog.canonical(statement))
    let data = try NativeAuditLog.canonical(statement)
    let verifier = try NativeAuditKeyTransitionReceiptVerifier(
        tenant: "native-host",
        anchorPublicKeyPEM: deletionAnchorPEM()
    )
    return (data, try verifier.verify(receiptData: data, transition: transition, expectedTransitionIndex: 1))
}

private func deletionPruneReceipt(
    _ authorization: NativeAuditPruneAuthorization,
    receivedAt: String
) throws -> NativeAuditPruneReceipt {
    var statement: [String: Any] = [
        "version": 1,
        "tenant": authorization.tenant,
        "sequence": authorization.sequence,
        "authorization_hash": authorization.authorizationHash,
        "previous_receipt_hash": authorization.previousPruneReceiptHash,
        "anchor_event_index": authorization.boundary.anchorEventIndex + 1,
        "previous_anchor_event_hash": authorization.boundary.anchorEventHash,
        "received_at": receivedAt,
    ]
    let signature = try deletionAnchor.signature(for: NativeAuditLog.canonical(statement)).base64EncodedString()
    statement["anchor_key_fingerprint"] = deletionAnchorFingerprint()
    statement["signature"] = signature
    let receiptHash = NativeAuditLog.hash(try NativeAuditLog.canonical(statement))
    return NativeAuditPruneReceipt(
        version: 1,
        tenant: authorization.tenant,
        sequence: authorization.sequence,
        authorizationHash: authorization.authorizationHash,
        previousReceiptHash: authorization.previousPruneReceiptHash,
        anchorEventIndex: authorization.boundary.anchorEventIndex + 1,
        previousAnchorEventHash: authorization.boundary.anchorEventHash,
        receivedAt: receivedAt,
        anchorKeyFingerprint: deletionAnchorFingerprint(),
        signature: signature,
        receiptHash: receiptHash
    )
}

private func makeDeletionFixture(
    lifecycleCharacter: Character = "b",
    transitionReceivedAt: String = "2027-01-01T00:01:00.000Z",
    signedRetentionSeconds: Int = deletionPolicySeconds,
    verifierMinimumSeconds: Int = deletionPolicySeconds
) throws -> DeletionProofFixture {
    let directory = try deletionDirectory()
    let retiring = try DeletionProofP256Signer(0x33)
    let replacement = try DeletionProofP256Signer(0x34)
    let statement = try NativeAuditKeyTransitionStatement(
        tenant: "native-host",
        operationID: "rotation-1-\(lifecycleCharacter)",
        fromGeneration: 4,
        oldPublicKeyX963: retiring.publicKeyX963,
        newPublicKeyX963: replacement.publicKeyX963,
        lifecycleHeadHash: deletionHash(lifecycleCharacter),
        lastCheckpointIndex: 2,
        lastCheckpointHash: deletionHash("c"),
        lastCheckpointReceiptHash: deletionHash("d"),
        previousAnchorEventIndex: 10,
        previousAnchorEventHash: deletionHash("e"),
        createdAt: "2027-01-01T00:00:00.000Z"
    )
    let transition = try NativeAuditKeyTransition(
        statement: statement,
        retiringSigner: retiring,
        replacementSigner: replacement
    )
    let transitionReceiptEvidence = try deletionTransitionReceipt(
        transition: transition,
        receivedAt: transitionReceivedAt
    )
    let store = try NativeAuditKeyTransitionStore(
        path: directory.appendingPathComponent("transitions.jsonl").path,
        tenant: "native-host",
        anchorPublicKeyPEM: deletionAnchorPEM()
    )
    _ = try store.accept(
        transitionData: transition.canonicalData(),
        receiptData: transitionReceiptEvidence.0,
        retiringPublicKeyX963: retiring.publicKeyX963
    )

    let boundary = NativeAuditRetentionBoundary(
        lifecycleHeadHash: deletionHash(lifecycleCharacter),
        auditKeyTransitionReceiptHash: transitionReceiptEvidence.1.receiptHash,
        anchorEventIndex: transitionReceiptEvidence.1.eventIndex,
        anchorEventHash: transitionReceiptEvidence.1.receiptHash,
        checkpointIndex: 2,
        checkpointHash: transition.lastCheckpointHash,
        checkpointReceiptHash: transition.lastCheckpointReceiptHash
    )
    let archiveDirectory = directory.appendingPathComponent("archives", isDirectory: true)
    let journalDirectory = directory.appendingPathComponent("prune-journal", isDirectory: true)
    for path in [archiveDirectory, journalDirectory] {
        try FileManager.default.createDirectory(at: path, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        guard chmod(path.path, 0o700) == 0 else { throw POSIXError(.EIO) }
    }
    let auditData = Data("audit-archive\n".utf8)
    let checkpointData = Data("checkpoint-archive\n".utf8)
    let receiptData = Data("receipt-archive\n".utf8)
    let segment = NativeAuditRetentionSegment(
        segmentID: "segment-1",
        auditArchiveFile: "pruned-audit.jsonl",
        auditArchiveSHA256: NativeAuditLog.hash(auditData),
        firstEventIndex: 1,
        lastEventIndex: 5,
        previousEventHash: NativeAuditLog.zeroHash,
        terminalEventHash: deletionHash("1"),
        checkpointArchiveFile: "pruned-checkpoints.jsonl",
        checkpointArchiveSHA256: NativeAuditLog.hash(checkpointData),
        firstCheckpointIndex: 1,
        lastCheckpointIndex: 1,
        previousCheckpointHash: NativeAuditLog.zeroHash,
        terminalCheckpointHash: deletionHash("2"),
        receiptArchiveFile: "pruned-receipts.jsonl",
        receiptArchiveSHA256: NativeAuditLog.hash(receiptData),
        firstReceiptIndex: 1,
        lastReceiptIndex: 1,
        previousReceiptHash: NativeAuditLog.zeroHash,
        terminalReceiptHash: deletionHash("3"),
        anchoredEventIndex: 5,
        anchoredEventHash: deletionHash("1"),
        sealedAt: "2027-01-01T00:01:30.000Z",
        latestAnchorReceivedAt: "2027-01-01T00:02:00.000Z"
    )
    let retainedAuditData = Data("retained-audit-archive\n".utf8)
    let retainedCheckpointData = Data("retained-checkpoint-archive\n".utf8)
    let retainedReceiptData = Data("retained-receipt-archive\n".utf8)
    let retained = NativeAuditRetentionSegment(
        segmentID: "segment-2",
        auditArchiveFile: "retained-audit.jsonl",
        auditArchiveSHA256: NativeAuditLog.hash(retainedAuditData),
        firstEventIndex: 6,
        lastEventIndex: 10,
        previousEventHash: segment.terminalEventHash,
        terminalEventHash: deletionHash("4"),
        checkpointArchiveFile: "retained-checkpoints.jsonl",
        checkpointArchiveSHA256: NativeAuditLog.hash(retainedCheckpointData),
        firstCheckpointIndex: 2,
        lastCheckpointIndex: 2,
        previousCheckpointHash: segment.terminalCheckpointHash,
        terminalCheckpointHash: deletionHash("5"),
        receiptArchiveFile: "retained-receipts.jsonl",
        receiptArchiveSHA256: NativeAuditLog.hash(retainedReceiptData),
        firstReceiptIndex: 2,
        lastReceiptIndex: 2,
        previousReceiptHash: segment.terminalReceiptHash,
        terminalReceiptHash: deletionHash("6"),
        anchoredEventIndex: 10,
        anchoredEventHash: deletionHash("4"),
        sealedAt: "2027-01-02T00:01:30.000Z",
        latestAnchorReceivedAt: "2027-01-02T00:02:00.000Z"
    )
    let archivePaths = [
        archiveDirectory.appendingPathComponent(segment.auditArchiveFile),
        archiveDirectory.appendingPathComponent(segment.checkpointArchiveFile),
        archiveDirectory.appendingPathComponent(segment.receiptArchiveFile),
    ]
    let retainedPaths = [
        archiveDirectory.appendingPathComponent(retained.auditArchiveFile),
        archiveDirectory.appendingPathComponent(retained.checkpointArchiveFile),
        archiveDirectory.appendingPathComponent(retained.receiptArchiveFile),
    ]
    for (path, data) in zip(
        archivePaths + retainedPaths,
        [auditData, checkpointData, receiptData, retainedAuditData, retainedCheckpointData, retainedReceiptData]
    ) {
        try data.write(to: path)
        guard chmod(path.path, 0o600) == 0 else { throw POSIXError(.EIO) }
    }
    let retentionVerifier = try NativeAuditRetentionVerifier(
        tenant: "native-host",
        authorizerPublicKeyX963: deletionAuthorizer.publicKeyX963,
        anchorPublicKeyPEM: deletionAnchorPEM(),
        minimumRetentionSeconds: verifierMinimumSeconds
    )
    let completion = deletionDate("2027-01-08T00:04:00.000Z")
    let coordinator = try NativeAuditPruneCoordinator(
        tenant: "native-host",
        archiveDirectory: archiveDirectory.path,
        journal: try NativeAuditPruneJournal(directory: journalDirectory.path, tenant: "native-host"),
        verifier: retentionVerifier,
        signer: deletionAuthorizer,
        transport: DeletionProofPruneTransport(receivedAt: "2027-01-08T00:04:00.000Z"),
        trustSource: DeletionProofPruneTrust(boundary: boundary),
        now: { completion }
    )
    let prepared = try coordinator.prepare(
        operationID: "prune-1-\(lifecycleCharacter)",
        retentionSeconds: signedRetentionSeconds,
        segments: [segment],
        expectedNextRetained: retained
    )
    let accepted = try coordinator.submitPending()
    let observation = try NativeAuditRetentionArchiveObservation.observe(
        archiveDirectory: archiveDirectory.path,
        segment: segment
    )
    let plan = try retentionVerifier.eligiblePlan(
        authorizationData: prepared.authorizationData,
        receiptData: accepted.receiptData,
        observedArchives: [observation],
        prior: .init(),
        currentBoundary: boundary,
        now: completion
    )
    let result = try coordinator.executePending()
    guard let retainedIdentities = prepared.expectedNextRetainedFileIdentities else {
        throw AgentPassNativeError.invalidSignature("Coordinator omitted retained identities")
    }
    return DeletionProofFixture(
        directory: directory,
        store: store,
        retentionVerifier: retentionVerifier,
        authorizationData: prepared.authorizationData,
        pruneReceiptData: accepted.receiptData,
        manifestData: result.manifestData,
        completionProofData: result.completionProofData,
        completionStatementData: result.completionStatementData,
        quarantinedMarkerData: result.quarantinedMarkerData,
        manifestCommitMarkerData: result.manifestCommitMarkerData,
        deletionEvidenceBundleData: result.deletionEvidenceBundleData,
        archivePaths: archivePaths,
        expectedNextRetained: retained,
        expectedNextRetainedFileIdentities: retainedIdentities,
        prunePlan: plan,
        boundary: boundary,
        transition: transition,
        transitionReceipt: transitionReceiptEvidence.1,
        manifest: result.manifest,
        completionProof: result.completionProof
    )
}

private func makeDeletionVerifier(
    _ fixture: DeletionProofFixture,
    minimumSeconds: Int = deletionPolicySeconds,
    authorizationData: Data? = nil,
    pruneReceiptData: Data? = nil,
    manifestData: Data? = nil,
    completionProofData: Data? = nil,
    completionStatementData: Data? = nil,
    quarantinedMarkerData: Data? = nil,
    manifestCommitMarkerData: Data? = nil,
    expectedNextRetained: NativeAuditRetentionSegment? = nil,
    expectedNextRetainedFileIdentities: [NativeAuditRetentionFileIdentity]? = nil,
    ancestryVerifier: (any NativeLifecycleHeadAncestryVerifier)? = nil,
    now: Date = deletionDate("2027-01-08T00:05:00.000Z")
) throws -> NativeAuditLifecycleDeletionProofVerifier {
    try NativeAuditLifecycleDeletionProofVerifier(
        transitionStore: fixture.store,
        lifecycleAncestryVerifier: ancestryVerifier ?? DeletionProofAncestry(
            acceptedAncestor: fixture.transition.lifecycleHeadHash,
            acceptedCurrent: fixture.boundary.lifecycleHeadHash
        ),
        retentionVerifier: fixture.retentionVerifier,
        authorizationData: authorizationData ?? fixture.authorizationData,
        pruneReceiptData: pruneReceiptData ?? fixture.pruneReceiptData,
        postPruneManifestData: manifestData ?? fixture.manifestData,
        completionProofData: completionProofData ?? fixture.completionProofData,
        completionStatementData: completionStatementData ?? fixture.completionStatementData,
        quarantinedMarkerData: quarantinedMarkerData ?? fixture.quarantinedMarkerData,
        manifestCommitMarkerData: manifestCommitMarkerData ?? fixture.manifestCommitMarkerData,
        priorPruneState: .init(),
        trustedCurrentBoundary: fixture.boundary,
        expectedNextRetained: expectedNextRetained ?? fixture.expectedNextRetained,
        expectedNextRetainedFileIdentities: expectedNextRetainedFileIdentities ?? fixture.expectedNextRetainedFileIdentities,
        minimumDeletionRetentionSeconds: minimumSeconds,
        now: now
    )
}

@Test func lifecycleDeletionProofRechecksAncestryAtUseTime() throws {
    let fixture = try makeDeletionFixture()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let ancestry = DeletionProofMutableAncestry()
    let verifier = try makeDeletionVerifier(fixture, ancestryVerifier: ancestry)
    ancestry.reject()
    #expect(throws: AgentPassNativeError.self) {
        try verifier.verify(
            fixture.proof,
            role: .auditCheckpoint,
            generation: fixture.transition.fromGeneration,
            fingerprint: fixture.transition.oldKeyFingerprint
        )
    }
}

@Test func lifecycleDeletionProofRejectsFutureDatedSignedManifest() throws {
    let fixture = try makeDeletionFixture()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    #expect(throws: AgentPassNativeError.self) {
        try makeDeletionVerifier(
            fixture,
            now: deletionDate("2027-01-07T23:59:59.000Z")
        )
    }
}

@Test func lifecycleDeletionProofDerivesTrustedTimesFromExactSignedEvidence() throws {
    let fixture = try makeDeletionFixture()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let verifier = try makeDeletionVerifier(fixture)

    let result = try verifier.verify(
        fixture.proof,
        role: .auditCheckpoint,
        generation: fixture.transition.fromGeneration,
        fingerprint: fixture.transition.oldKeyFingerprint
    )
    #expect(result.archivedAt == deletionDate(fixture.transitionReceipt.receivedAt))
    #expect(result.verifiedAt == deletionDate(fixture.proof.verifiedAt))
}

@Test func lifecycleDeletionProofVerifiesAfterPrunedTargetsAreGone() throws {
    let fixture = try makeDeletionFixture()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    #expect(fixture.archivePaths.allSatisfy { !FileManager.default.fileExists(atPath: $0.path) })

    let verifier = try makeDeletionVerifier(fixture)
    _ = try verifier.verify(
        fixture.proof,
        role: .auditCheckpoint,
        generation: fixture.transition.fromGeneration,
        fingerprint: fixture.transition.oldKeyFingerprint
    )
    #expect(fixture.archivePaths.allSatisfy { !FileManager.default.fileExists(atPath: $0.path) })
}

@Test func lifecycleDeletionProofRejectsCallerTimestampsRoleGenerationAndFingerprint() throws {
    let fixture = try makeDeletionFixture()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let verifier = try makeDeletionVerifier(fixture)
    let forgedTime = NativeLifecycleDeletionProof(
        lifecycleHeadHash: fixture.boundary.lifecycleHeadHash,
        transitionReceiptHash: fixture.transitionReceipt.receiptHash,
        transitionArchivedAt: "2020-01-01T00:00:00.000Z",
        verifiedAt: fixture.proof.verifiedAt
    )
    #expect(throws: AgentPassNativeError.self) {
        try verifier.verify(forgedTime, role: .auditCheckpoint, generation: 4, fingerprint: fixture.transition.oldKeyFingerprint)
    }
    let forgedVerificationTime = NativeLifecycleDeletionProof(
        lifecycleHeadHash: fixture.boundary.lifecycleHeadHash,
        transitionReceiptHash: fixture.transitionReceipt.receiptHash,
        transitionArchivedAt: fixture.transitionReceipt.receivedAt,
        verifiedAt: "2037-01-08T00:04:00.000Z"
    )
    #expect(throws: AgentPassNativeError.self) {
        try verifier.verify(forgedVerificationTime, role: .auditCheckpoint, generation: 4, fingerprint: fixture.transition.oldKeyFingerprint)
    }
    #expect(throws: AgentPassNativeError.self) {
        try verifier.verify(fixture.proof, role: .gitSigning, generation: 4, fingerprint: fixture.transition.oldKeyFingerprint)
    }
    #expect(throws: AgentPassNativeError.self) {
        try verifier.verify(fixture.proof, role: .auditCheckpoint, generation: 3, fingerprint: fixture.transition.oldKeyFingerprint)
    }
    #expect(throws: AgentPassNativeError.self) {
        try verifier.verify(fixture.proof, role: .auditCheckpoint, generation: 4, fingerprint: "SHA256:" + String(repeating: "A", count: 43))
    }
}

@Test func lifecycleDeletionProofRejectsHeadReceiptAndArtifactSubstitution() throws {
    let fixture = try makeDeletionFixture()
    let other = try makeDeletionFixture(lifecycleCharacter: "f")
    defer {
        try? FileManager.default.removeItem(at: fixture.directory)
        try? FileManager.default.removeItem(at: other.directory)
    }
    let verifier = try makeDeletionVerifier(fixture)
    let wrongHead = NativeLifecycleDeletionProof(
        lifecycleHeadHash: deletionHash("9"),
        transitionReceiptHash: fixture.transitionReceipt.receiptHash,
        transitionArchivedAt: fixture.transitionReceipt.receivedAt,
        verifiedAt: fixture.proof.verifiedAt
    )
    let wrongReceipt = NativeLifecycleDeletionProof(
        lifecycleHeadHash: fixture.boundary.lifecycleHeadHash,
        transitionReceiptHash: deletionHash("8"),
        transitionArchivedAt: fixture.transitionReceipt.receivedAt,
        verifiedAt: fixture.proof.verifiedAt
    )
    #expect(throws: AgentPassNativeError.self) {
        try verifier.verify(wrongHead, role: .auditCheckpoint, generation: 4, fingerprint: fixture.transition.oldKeyFingerprint)
    }
    #expect(throws: AgentPassNativeError.self) {
        try verifier.verify(wrongReceipt, role: .auditCheckpoint, generation: 4, fingerprint: fixture.transition.oldKeyFingerprint)
    }
    #expect(throws: AgentPassNativeError.self) {
        try makeDeletionVerifier(fixture, pruneReceiptData: other.pruneReceiptData)
    }
    #expect(throws: AgentPassNativeError.self) {
        try makeDeletionVerifier(fixture, manifestData: other.manifestData)
    }
    #expect(throws: AgentPassNativeError.self) {
        try makeDeletionVerifier(fixture, completionProofData: other.completionProofData)
    }
}

@Test func lifecycleDeletionProofRejectsHighSCompletionProof() throws {
    let fixture = try makeDeletionFixture()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let highSProof = try deletionHighSDocument(fixture.completionProofData, hashKey: "proof_hash")
    #expect(throws: AgentPassNativeError.self) {
        try makeDeletionVerifier(fixture, completionProofData: highSProof)
    }
}

@Test func lifecycleDeletionProofRejectsNoncanonicalAndMissingTransitionEvidence() throws {
    let fixture = try makeDeletionFixture()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    for (kind, artifact) in [
        ("authorization", fixture.authorizationData),
        ("receipt", fixture.pruneReceiptData),
        ("manifest", fixture.manifestData),
        ("completion", fixture.completionProofData),
    ] {
        var noncanonical = artifact
        noncanonical.append(0x0a)
        if kind == "authorization" {
            #expect(throws: AgentPassNativeError.self) {
                try makeDeletionVerifier(fixture, authorizationData: noncanonical)
            }
        } else if kind == "receipt" {
            #expect(throws: AgentPassNativeError.self) {
                try makeDeletionVerifier(fixture, pruneReceiptData: noncanonical)
            }
        } else if kind == "manifest" {
            #expect(throws: AgentPassNativeError.self) {
                try makeDeletionVerifier(fixture, manifestData: noncanonical)
            }
        } else {
            #expect(throws: AgentPassNativeError.self) {
                try makeDeletionVerifier(fixture, completionProofData: noncanonical)
            }
        }
    }

    let emptyDirectory = try deletionDirectory()
    defer { try? FileManager.default.removeItem(at: emptyDirectory) }
    let emptyStore = try NativeAuditKeyTransitionStore(
        path: emptyDirectory.appendingPathComponent("transitions.jsonl").path,
        tenant: "native-host",
        anchorPublicKeyPEM: deletionAnchorPEM()
    )
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditLifecycleDeletionProofVerifier(
            transitionStore: emptyStore,
            lifecycleAncestryVerifier: DeletionProofAncestry(
                acceptedAncestor: fixture.transition.lifecycleHeadHash,
                acceptedCurrent: fixture.boundary.lifecycleHeadHash
            ),
            retentionVerifier: fixture.retentionVerifier,
            authorizationData: fixture.authorizationData,
            pruneReceiptData: fixture.pruneReceiptData,
            postPruneManifestData: fixture.manifestData,
            completionProofData: fixture.completionProofData,
            completionStatementData: fixture.completionStatementData,
            quarantinedMarkerData: fixture.quarantinedMarkerData,
            manifestCommitMarkerData: fixture.manifestCommitMarkerData,
            priorPruneState: .init(),
            trustedCurrentBoundary: fixture.boundary,
            expectedNextRetained: fixture.expectedNextRetained,
            expectedNextRetainedFileIdentities: fixture.expectedNextRetainedFileIdentities,
            minimumDeletionRetentionSeconds: deletionPolicySeconds
        )
    }
}

@Test func lifecycleDeletionProofRejectsPolicyDowngradeAndTransitionAgeBypass() throws {
    let downgrade = try makeDeletionFixture(
        signedRetentionSeconds: 60 * 60,
        verifierMinimumSeconds: 60 * 60
    )
    defer { try? FileManager.default.removeItem(at: downgrade.directory) }
    #expect(throws: AgentPassNativeError.self) {
        try makeDeletionVerifier(downgrade, minimumSeconds: deletionPolicySeconds)
    }

    let tooRecent = try makeDeletionFixture(
        transitionReceivedAt: "2027-01-07T00:01:00.000Z"
    )
    defer { try? FileManager.default.removeItem(at: tooRecent.directory) }
    #expect(throws: AgentPassNativeError.self) {
        try makeDeletionVerifier(tooRecent)
    }
}
