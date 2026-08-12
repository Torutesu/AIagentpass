import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore

private struct RetentionSigner: P256MessageSigner {
    let key = try! P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x41, count: 32))
    var publicKeyX963: Data { key.publicKey.x963Representation }
    func sign(message: Data) throws -> Data { try key.signature(for: message).rawRepresentation }
}

private let retentionSigner = RetentionSigner()
private let retentionAnchor = try! Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x52, count: 32))
private let retentionSeconds = 7 * 24 * 60 * 60

private func retentionHash(_ character: Character) -> String { String(repeating: character, count: 64) }
private func retentionArchiveData(_ kind: String, _ id: String) -> Data { Data("\(kind):\(id)\n".utf8) }

private func retentionAnchorPEM() -> String {
    let prefix = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])
    let body = (prefix + retentionAnchor.publicKey.rawRepresentation).base64EncodedString()
    return "-----BEGIN PUBLIC KEY-----\n\(body)\n-----END PUBLIC KEY-----\n"
}

private func retentionAnchorFingerprint() -> String {
    let der = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) + retentionAnchor.publicKey.rawRepresentation
    return "SHA256:" + Data(SHA256.hash(data: der)).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}

private func retentionDate(_ value: String) -> Date {
    let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return f.date(from: value)!
}

private let retentionBoundary = NativeAuditRetentionBoundary(
    lifecycleHeadHash: retentionHash("1"), auditKeyTransitionReceiptHash: retentionHash("2"),
    anchorEventIndex: 20, anchorEventHash: retentionHash("3"), checkpointIndex: 10,
    checkpointHash: retentionHash("4"), checkpointReceiptHash: retentionHash("5")
)

private func retentionSegment(
    id: String = "segment-1", event: ClosedRange<Int> = 1...100, checkpoint: ClosedRange<Int> = 1...2,
    previousEvent: String = NativeAuditLog.zeroHash, previousCheckpoint: String = NativeAuditLog.zeroHash,
    previousReceipt: String = NativeAuditLog.zeroHash, terminalEvent: String = retentionHash("a"),
    terminalCheckpoint: String = retentionHash("b"), terminalReceipt: String = retentionHash("c"),
    auditHash: String? = nil, anchoredAt: String = "2027-01-01T00:00:00.000Z"
) -> NativeAuditRetentionSegment {
    NativeAuditRetentionSegment(
        segmentID: id, auditArchiveFile: "audit-\(id).jsonl", auditArchiveSHA256: auditHash ?? NativeAuditLog.hash(retentionArchiveData("audit", id)),
        firstEventIndex: event.lowerBound, lastEventIndex: event.upperBound, previousEventHash: previousEvent, terminalEventHash: terminalEvent,
        checkpointArchiveFile: "checkpoints-\(id).jsonl", checkpointArchiveSHA256: NativeAuditLog.hash(retentionArchiveData("checkpoint", id)),
        firstCheckpointIndex: checkpoint.lowerBound, lastCheckpointIndex: checkpoint.upperBound, previousCheckpointHash: previousCheckpoint, terminalCheckpointHash: terminalCheckpoint,
        receiptArchiveFile: "receipts-\(id).jsonl", receiptArchiveSHA256: NativeAuditLog.hash(retentionArchiveData("receipt", id)),
        firstReceiptIndex: checkpoint.lowerBound, lastReceiptIndex: checkpoint.upperBound, previousReceiptHash: previousReceipt, terminalReceiptHash: terminalReceipt,
        anchoredEventIndex: event.upperBound, anchoredEventHash: terminalEvent, sealedAt: "2026-12-31T23:00:00.000Z", latestAnchorReceivedAt: anchoredAt
    )
}

private func retentionObservation(_ segment: NativeAuditRetentionSegment) throws -> NativeAuditRetentionArchiveObservation {
    try NativeAuditRetentionArchiveObservation(segment: segment, auditArchiveData: retentionArchiveData("audit", segment.segmentID), checkpointArchiveData: retentionArchiveData("checkpoint", segment.segmentID), receiptArchiveData: retentionArchiveData("receipt", segment.segmentID))
}

private func retentionObservations(_ segments: [NativeAuditRetentionSegment]) throws -> [NativeAuditRetentionArchiveObservation] {
    try segments.map(retentionObservation)
}

private func retentionAuthorization(segments: [NativeAuditRetentionSegment], sequence: Int = 1, prior: NativeAuditPruneChainState = .init(), seconds: Int = retentionSeconds, boundary: NativeAuditRetentionBoundary = retentionBoundary) throws -> NativeAuditPruneAuthorization {
    try NativeAuditPruneAuthorization.create(
        tenant: "native-host", operationID: "prune-\(sequence)", sequence: sequence,
        previousAuthorizationHash: prior.authorizationHash, previousPruneReceiptHash: prior.receiptHash,
        previousManifestHash: prior.manifestHash, retentionSeconds: seconds,
        requestedAt: "2027-01-15T00:00:00.000Z", boundary: boundary, segments: segments, signer: retentionSigner
    )
}

private func retentionReceipt(_ authorization: NativeAuditPruneAuthorization, receivedAt: String = "2027-01-16T00:00:00.000Z") throws -> NativeAuditPruneReceipt {
    let statement: [String: Any] = [
        "version": 1, "tenant": authorization.tenant, "sequence": authorization.sequence,
        "authorization_hash": authorization.authorizationHash, "previous_receipt_hash": authorization.previousPruneReceiptHash,
        "anchor_event_index": authorization.boundary.anchorEventIndex + 1,
        "previous_anchor_event_hash": authorization.boundary.anchorEventHash, "received_at": receivedAt
    ]
    let signature = try retentionAnchor.signature(for: NativeAuditLog.canonical(statement)).base64EncodedString()
    var hashed = statement
    hashed["anchor_key_fingerprint"] = retentionAnchorFingerprint(); hashed["signature"] = signature
    let receiptHash = NativeAuditLog.hash(try NativeAuditLog.canonical(hashed))
    return NativeAuditPruneReceipt(version: 1, tenant: authorization.tenant, sequence: authorization.sequence, authorizationHash: authorization.authorizationHash, previousReceiptHash: authorization.previousPruneReceiptHash, anchorEventIndex: authorization.boundary.anchorEventIndex + 1, previousAnchorEventHash: authorization.boundary.anchorEventHash, receivedAt: receivedAt, anchorKeyFingerprint: retentionAnchorFingerprint(), signature: signature, receiptHash: receiptHash)
}

private func retentionVerifier() throws -> NativeAuditRetentionVerifier {
    try NativeAuditRetentionVerifier(tenant: "native-host", authorizerPublicKeyX963: retentionSigner.publicKeyX963, anchorPublicKeyPEM: retentionAnchorPEM(), minimumRetentionSeconds: retentionSeconds)
}

private final class RetentionFaultBox: @unchecked Sendable {
    private let lock = NSLock()
    private var target: NativeAuditPruneExecutionCrashPoint?
    init(_ target: NativeAuditPruneExecutionCrashPoint?) { self.target = target }
    func inject(_ point: NativeAuditPruneExecutionCrashPoint) throws {
        try lock.withLock {
            if target == point {
                target = nil
                throw RetentionInjectedFailure.crash
            }
        }
    }
}

private enum RetentionInjectedFailure: Error { case crash }

private func retentionTemporaryDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("agentpass-retention-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
    let resolved = try #require(realpath(url.path, nil))
    defer { free(resolved) }
    return URL(fileURLWithPath: String(cString: resolved), isDirectory: true)
}

private func writeRetentionArchives(_ segment: NativeAuditRetentionSegment, to directory: URL) throws {
    let entries = [
        (segment.auditArchiveFile, retentionArchiveData("audit", segment.segmentID)),
        (segment.checkpointArchiveFile, retentionArchiveData("checkpoint", segment.segmentID)),
        (segment.receiptArchiveFile, retentionArchiveData("receipt", segment.segmentID)),
    ]
    for (name, data) in entries {
        let path = directory.appendingPathComponent(name).path
        FileManager.default.createFile(atPath: path, contents: data, attributes: [.posixPermissions: 0o600])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
    }
}

private func executableRetentionPlan(directory: URL, segment: NativeAuditRetentionSegment = retentionSegment(), authorization: NativeAuditPruneAuthorization? = nil) throws -> (NativeAuditPrunePlan, NativeAuditRetentionVerifier) {
    let verifier = try retentionVerifier()
    let observation = try NativeAuditRetentionArchiveObservation.observe(archiveDirectory: directory.path, segment: segment)
    let value = try authorization ?? retentionAuthorization(segments: [segment])
    let receipt = try retentionReceipt(value)
    let plan = try verifier.eligiblePlan(
        authorizationData: value.canonicalData(), receiptData: receipt.canonicalData(),
        observedArchives: [observation], prior: .init(), currentBoundary: retentionBoundary,
        now: retentionDate("2027-01-20T00:02:00.000Z")
    )
    return (plan, verifier)
}

private func retainedSegment(after segment: NativeAuditRetentionSegment, auditFile: String? = nil) -> NativeAuditRetentionSegment {
    NativeAuditRetentionSegment(
        segmentID: "retained", auditArchiveFile: auditFile ?? "audit-retained.jsonl", auditArchiveSHA256: NativeAuditLog.hash(retentionArchiveData("audit", "retained")),
        firstEventIndex: segment.lastEventIndex + 1, lastEventIndex: segment.lastEventIndex + 100, previousEventHash: segment.terminalEventHash, terminalEventHash: retentionHash("d"),
        checkpointArchiveFile: "checkpoints-retained.jsonl", checkpointArchiveSHA256: NativeAuditLog.hash(retentionArchiveData("checkpoint", "retained")),
        firstCheckpointIndex: segment.lastCheckpointIndex + 1, lastCheckpointIndex: segment.lastCheckpointIndex + 2, previousCheckpointHash: segment.terminalCheckpointHash, terminalCheckpointHash: retentionHash("e"),
        receiptArchiveFile: "receipts-retained.jsonl", receiptArchiveSHA256: NativeAuditLog.hash(retentionArchiveData("receipt", "retained")),
        firstReceiptIndex: segment.lastReceiptIndex + 1, lastReceiptIndex: segment.lastReceiptIndex + 2, previousReceiptHash: segment.terminalReceiptHash, terminalReceiptHash: retentionHash("f"),
        anchoredEventIndex: segment.lastEventIndex + 100, anchoredEventHash: retentionHash("d"), sealedAt: "2027-01-01T00:00:00.000Z", latestAnchorReceivedAt: "2027-01-02T00:00:00.000Z"
    )
}

@Test func auditRetentionProducesEligibleExactPlanAndVerifiesPostPruneManifest() throws {
    let first = retentionSegment()
    let second = retentionSegment(id: "segment-2", event: 101...200, checkpoint: 3...4, previousEvent: first.terminalEventHash, previousCheckpoint: first.terminalCheckpointHash, previousReceipt: first.terminalReceiptHash, terminalEvent: retentionHash("6"), terminalCheckpoint: retentionHash("7"), terminalReceipt: retentionHash("8"))
    let authorization = try retentionAuthorization(segments: [first, second])
    let receipt = try retentionReceipt(authorization)
    let verifier = try retentionVerifier()
    let now = retentionDate("2027-01-20T00:00:00.000Z")
    let plan = try verifier.eligiblePlan(authorizationData: authorization.canonicalData(), receiptData: receipt.canonicalData(), observedArchives: retentionObservations([first, second]), prior: .init(), currentBoundary: retentionBoundary, now: now)
    let expectedAuthorizationData = try authorization.canonicalData()
    let expectedReceiptData = try receipt.canonicalData()
    #expect(plan.authorizationData == expectedAuthorizationData)
    #expect(plan.receiptData == expectedReceiptData)
    #expect(plan.nextState.lastEventIndex == 200)

    let retained = retentionSegment(id: "segment-3", event: 201...300, checkpoint: 5...6, previousEvent: second.terminalEventHash, previousCheckpoint: second.terminalCheckpointHash, previousReceipt: second.terminalReceiptHash, terminalEvent: retentionHash("a"), terminalCheckpoint: retentionHash("b"), terminalReceipt: retentionHash("c"))
    let manifest = try NativeAuditPostPruneManifest.create(plan: plan, completedAt: "2027-01-20T00:01:00.000Z", nextRetainedEventIndex: 201, nextRetainedCheckpointIndex: 5, nextRetainedReceiptIndex: 5, nextRetainedEventPreviousHash: second.terminalEventHash, nextRetainedCheckpointPreviousHash: second.terminalCheckpointHash, nextRetainedReceiptPreviousHash: second.terminalReceiptHash, signer: retentionSigner)
    let state = try verifier.verifyPostPruneManifest(manifest.canonicalData(), plan: plan, currentBoundary: retentionBoundary, expectedNextRetained: retained, now: now.addingTimeInterval(120))
    #expect(state.sequence == 1)
    #expect(state.manifestHash == manifest.manifestHash)

    let nextBoundary = NativeAuditRetentionBoundary(lifecycleHeadHash: retentionBoundary.lifecycleHeadHash, auditKeyTransitionReceiptHash: retentionBoundary.auditKeyTransitionReceiptHash, anchorEventIndex: receipt.anchorEventIndex, anchorEventHash: receipt.receiptHash, checkpointIndex: retentionBoundary.checkpointIndex, checkpointHash: retentionBoundary.checkpointHash, checkpointReceiptHash: retentionBoundary.checkpointReceiptHash)
    let nextAuthorization = try retentionAuthorization(segments: [retained], sequence: 2, prior: state, boundary: nextBoundary)
    let nextReceipt = try retentionReceipt(nextAuthorization)
    let nextPlan = try verifier.eligiblePlan(authorizationData: nextAuthorization.canonicalData(), receiptData: nextReceipt.canonicalData(), observedArchives: retentionObservations([retained]), prior: state, currentBoundary: nextBoundary, now: now)
    #expect(nextPlan.nextState.lastEventHash == retained.terminalEventHash)
}

@Test func auditRetentionRejectsGapsOverlapAndRollback() throws {
    let first = retentionSegment()
    let gap = retentionSegment(id: "gap", event: 102...200, checkpoint: 3...4, previousEvent: first.terminalEventHash, previousCheckpoint: first.terminalCheckpointHash, previousReceipt: first.terminalReceiptHash)
    let overlap = retentionSegment(id: "overlap", event: 100...200, checkpoint: 3...4, previousEvent: first.terminalEventHash, previousCheckpoint: first.terminalCheckpointHash, previousReceipt: first.terminalReceiptHash)
    let verifier = try retentionVerifier(); let now = retentionDate("2027-01-20T00:00:00.000Z")
    for segments in [[first, gap], [first, overlap]] {
        let a = try retentionAuthorization(segments: segments); let r = try retentionReceipt(a)
        #expect(throws: AgentPassNativeError.self) { try verifier.eligiblePlan(authorizationData: a.canonicalData(), receiptData: r.canonicalData(), observedArchives: retentionObservations(segments), prior: .init(), currentBoundary: retentionBoundary, now: now) }
    }
    let valid = try retentionAuthorization(segments: [first]); let receipt = try retentionReceipt(valid)
    let advanced = NativeAuditPruneChainState(sequence: 1, authorizationHash: retentionHash("a"), receiptHash: retentionHash("b"), manifestHash: retentionHash("c"), lastEventIndex: 100, lastCheckpointIndex: 2, lastReceiptIndex: 2)
    #expect(throws: AgentPassNativeError.self) { try verifier.eligiblePlan(authorizationData: valid.canonicalData(), receiptData: receipt.canonicalData(), observedArchives: retentionObservations([first]), prior: advanced, currentBoundary: retentionBoundary, now: now) }
}

@Test func auditRetentionRejectsPathAndHashSubstitution() throws {
    let actual = retentionSegment()
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditRetentionArchiveObservation(segment: actual, auditArchiveData: Data("substituted".utf8), checkpointArchiveData: retentionArchiveData("checkpoint", actual.segmentID), receiptArchiveData: retentionArchiveData("receipt", actual.segmentID))
    }
    let substituted = retentionSegment(auditHash: retentionHash("0"))
    let authorization = try retentionAuthorization(segments: [substituted]); let receipt = try retentionReceipt(authorization)
    #expect(throws: AgentPassNativeError.self) { try retentionVerifier().eligiblePlan(authorizationData: authorization.canonicalData(), receiptData: receipt.canonicalData(), observedArchives: retentionObservations([actual]), prior: .init(), currentBoundary: retentionBoundary, now: retentionDate("2027-01-20T00:00:00.000Z")) }

    let traversal = retentionSegment(id: "../escape")
    let bad = try retentionAuthorization(segments: [traversal]); let badReceipt = try retentionReceipt(bad)
    #expect(throws: AgentPassNativeError.self) { try retentionVerifier().eligiblePlan(authorizationData: bad.canonicalData(), receiptData: badReceipt.canonicalData(), observedArchives: retentionObservations([traversal]), prior: .init(), currentBoundary: retentionBoundary, now: retentionDate("2027-01-20T00:00:00.000Z")) }
}

@Test func auditRetentionRejectsInsufficientAgeAndPolicyDowngrade() throws {
    let young = retentionSegment(anchoredAt: "2027-01-19T00:00:00.000Z")
    let youngAuthorization = try retentionAuthorization(segments: [young]); let youngReceipt = try retentionReceipt(youngAuthorization)
    let now = retentionDate("2027-01-20T00:00:00.000Z")
    #expect(throws: AgentPassNativeError.self) { try retentionVerifier().eligiblePlan(authorizationData: youngAuthorization.canonicalData(), receiptData: youngReceipt.canonicalData(), observedArchives: retentionObservations([young]), prior: .init(), currentBoundary: retentionBoundary, now: now) }
    let old = retentionSegment(); let downgrade = try retentionAuthorization(segments: [old], seconds: retentionSeconds - 1); let downgradeReceipt = try retentionReceipt(downgrade)
    #expect(throws: AgentPassNativeError.self) { try retentionVerifier().eligiblePlan(authorizationData: downgrade.canonicalData(), receiptData: downgradeReceipt.canonicalData(), observedArchives: retentionObservations([old]), prior: .init(), currentBoundary: retentionBoundary, now: now) }
}

@Test func auditRetentionRejectsUnknownSchemaNoncanonicalAndBoundaryRollback() throws {
    let segment = retentionSegment(); let authorization = try retentionAuthorization(segments: [segment]); let receipt = try retentionReceipt(authorization)
    var object = try JSONSerialization.jsonObject(with: authorization.canonicalData()) as! [String: Any]
    object["future_field"] = true
    let unknown = try NativeAuditLog.canonical(object)
    #expect(throws: AgentPassNativeError.self) { try NativeAuditPruneAuthorization.decodeCanonical(unknown) }
    object.removeValue(forKey: "future_field")
    var nested = object["boundary"] as! [String: Any]
    nested["future_field"] = true; object["boundary"] = nested
    #expect(throws: AgentPassNativeError.self) { try NativeAuditPruneAuthorization.decodeCanonical(NativeAuditLog.canonical(object)) }
    let pretty = try JSONSerialization.data(withJSONObject: try JSONSerialization.jsonObject(with: authorization.canonicalData()), options: [.prettyPrinted, .sortedKeys])
    #expect(throws: AgentPassNativeError.self) { try NativeAuditPruneAuthorization.decodeCanonical(pretty) }
    var unknownReceipt = try JSONSerialization.jsonObject(with: receipt.canonicalData()) as! [String: Any]
    unknownReceipt["future_field"] = true
    #expect(throws: AgentPassNativeError.self) { try NativeAuditPruneReceipt.decodeCanonical(NativeAuditLog.canonical(unknownReceipt)) }
    let changedBoundary = NativeAuditRetentionBoundary(lifecycleHeadHash: retentionHash("0"), auditKeyTransitionReceiptHash: retentionBoundary.auditKeyTransitionReceiptHash, anchorEventIndex: retentionBoundary.anchorEventIndex, anchorEventHash: retentionBoundary.anchorEventHash, checkpointIndex: retentionBoundary.checkpointIndex, checkpointHash: retentionBoundary.checkpointHash, checkpointReceiptHash: retentionBoundary.checkpointReceiptHash)
    #expect(throws: AgentPassNativeError.self) { try retentionVerifier().eligiblePlan(authorizationData: authorization.canonicalData(), receiptData: receipt.canonicalData(), observedArchives: retentionObservations([segment]), prior: .init(), currentBoundary: changedBoundary, now: retentionDate("2027-01-20T00:00:00.000Z")) }
}

@Test func auditRetentionRejectsForgedExternalReceiptAndPostPruneSubstitution() throws {
    let segment = retentionSegment(); let authorization = try retentionAuthorization(segments: [segment]); let receipt = try retentionReceipt(authorization)
    var receiptObject = try JSONSerialization.jsonObject(with: receipt.canonicalData()) as! [String: Any]
    receiptObject["previous_anchor_event_hash"] = retentionHash("0")
    let forged = try NativeAuditLog.canonical(receiptObject)
    let verifier = try retentionVerifier(); let now = retentionDate("2027-01-20T00:00:00.000Z")
    #expect(throws: AgentPassNativeError.self) { try verifier.eligiblePlan(authorizationData: authorization.canonicalData(), receiptData: forged, observedArchives: retentionObservations([segment]), prior: .init(), currentBoundary: retentionBoundary, now: now) }

    let plan = try verifier.eligiblePlan(authorizationData: authorization.canonicalData(), receiptData: receipt.canonicalData(), observedArchives: retentionObservations([segment]), prior: .init(), currentBoundary: retentionBoundary, now: now)
    let badManifest = try NativeAuditPostPruneManifest.create(plan: plan, completedAt: "2027-01-20T00:01:00.000Z", nextRetainedEventIndex: 102, nextRetainedCheckpointIndex: 3, nextRetainedReceiptIndex: 3, nextRetainedEventPreviousHash: segment.terminalEventHash, nextRetainedCheckpointPreviousHash: segment.terminalCheckpointHash, nextRetainedReceiptPreviousHash: segment.terminalReceiptHash, signer: retentionSigner)
    #expect(throws: AgentPassNativeError.self) { try verifier.verifyPostPruneManifest(badManifest.canonicalData(), plan: plan, currentBoundary: retentionBoundary, expectedNextRetained: nil, now: now.addingTimeInterval(120)) }
}

@Test func auditPruneExecutorQuarantinesPersistsManifestAndRejectsReuse() throws {
    let directory = try retentionTemporaryDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
    let segment = retentionSegment(); try writeRetentionArchives(segment, to: directory)
    let retained = retainedSegment(after: segment); try writeRetentionArchives(retained, to: directory)
    let retainedIdentities = try NativeAuditRetentionArchiveObservation.observe(
        archiveDirectory: directory.path,
        segment: retained
    ).fileIdentities
    let (plan, verifier) = try executableRetentionPlan(directory: directory, segment: segment)
    let executor = try NativeAuditPruneExecutor(archiveDirectory: directory.path)
    let result = try executor.execute(
        plan: plan, verifier: verifier, currentBoundary: retentionBoundary,
        expectedNextRetained: retained, expectedNextRetainedFileIdentities: retainedIdentities,
        completedAt: "2027-01-20T00:01:00.000Z",
        now: retentionDate("2027-01-20T00:02:00.000Z"), signer: retentionSigner
    )
    #expect(result.manifest.authorizationHash == plan.authorization.authorizationHash)
    #expect(!result.recovered)
    for name in [segment.auditArchiveFile, segment.checkpointArchiveFile, segment.receiptArchiveFile] {
        #expect(!FileManager.default.fileExists(atPath: directory.appendingPathComponent(name).path))
    }
    let recovered = try NativeAuditPruneExecutor(archiveDirectory: directory.path).recover(
        plan: plan, verifier: verifier, currentBoundary: retentionBoundary,
        expectedNextRetained: retained, expectedNextRetainedFileIdentities: retainedIdentities,
        now: retentionDate("2027-01-20T00:03:00.000Z")
    )
    #expect(recovered.manifestData == result.manifestData)
    #expect(recovered.recovered)
    #expect(throws: AgentPassNativeError.self) {
        try executor.execute(
            plan: plan, verifier: verifier, currentBoundary: retentionBoundary,
            expectedNextRetained: retained, expectedNextRetainedFileIdentities: retainedIdentities,
            completedAt: "2027-01-20T00:04:00.000Z",
            now: retentionDate("2027-01-20T00:05:00.000Z"), signer: retentionSigner
        )
    }
}

@Test(arguments: [
    NativeAuditPruneExecutionCrashPoint.afterIntentSynced,
    .afterFileQuarantined(0), .afterFileQuarantined(1), .afterFileQuarantined(2),
    .afterQuarantineSynced, .afterManifestCommitted,
    .afterFileUnlinked(0), .afterFileUnlinked(1), .afterFileUnlinked(2),
    .afterCompletionSynced,
]) func auditPruneExecutorRecoversEveryDurablePhase(crashPoint: NativeAuditPruneExecutionCrashPoint) throws {
    let directory = try retentionTemporaryDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
    let segment = retentionSegment(); try writeRetentionArchives(segment, to: directory)
    let (plan, verifier) = try executableRetentionPlan(directory: directory, segment: segment)
    let faults = RetentionFaultBox(crashPoint)
    let executor = try NativeAuditPruneExecutor(archiveDirectory: directory.path, faultInjector: faults.inject)
    #expect(throws: RetentionInjectedFailure.self) {
        try executor.execute(
            plan: plan, verifier: verifier, currentBoundary: retentionBoundary, expectedNextRetained: nil,
            completedAt: "2027-01-20T00:01:00.000Z", now: retentionDate("2027-01-20T00:02:00.000Z"), signer: retentionSigner
        )
    }
    let result = try NativeAuditPruneExecutor(archiveDirectory: directory.path).recover(
        plan: plan, verifier: verifier, currentBoundary: retentionBoundary,
        expectedNextRetained: nil, now: retentionDate("2027-01-20T00:03:00.000Z")
    )
    #expect(result.recovered)
    for name in [segment.auditArchiveFile, segment.checkpointArchiveFile, segment.receiptArchiveFile] {
        #expect(!FileManager.default.fileExists(atPath: directory.appendingPathComponent(name).path))
    }
}

@Test func auditPruneExecutorRejectsPathSwapAndHardlinks() throws {
    let swappedDirectory = try retentionTemporaryDirectory(); defer { try? FileManager.default.removeItem(at: swappedDirectory) }
    let segment = retentionSegment(); try writeRetentionArchives(segment, to: swappedDirectory)
    let (plan, verifier) = try executableRetentionPlan(directory: swappedDirectory, segment: segment)
    let auditPath = swappedDirectory.appendingPathComponent(segment.auditArchiveFile).path
    try FileManager.default.removeItem(atPath: auditPath)
    FileManager.default.createFile(atPath: auditPath, contents: retentionArchiveData("audit", segment.segmentID), attributes: [.posixPermissions: 0o600])
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: auditPath)
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditPruneExecutor(archiveDirectory: swappedDirectory.path).execute(
            plan: plan, verifier: verifier, currentBoundary: retentionBoundary, expectedNextRetained: nil,
            completedAt: "2027-01-20T00:01:00.000Z", now: retentionDate("2027-01-20T00:02:00.000Z"), signer: retentionSigner
        )
    }
    #expect(FileManager.default.fileExists(atPath: auditPath))

    let hardlinkDirectory = try retentionTemporaryDirectory(); defer { try? FileManager.default.removeItem(at: hardlinkDirectory) }
    try writeRetentionArchives(segment, to: hardlinkDirectory)
    let source = hardlinkDirectory.appendingPathComponent(segment.auditArchiveFile).path
    let alias = hardlinkDirectory.appendingPathComponent("audit-hardlink.jsonl").path
    #expect(link(source, alias) == 0)
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditRetentionArchiveObservation.observe(archiveDirectory: hardlinkDirectory.path, segment: segment)
    }
}

@Test func auditPruneExecutorRejectsUnknownQuarantineFileAndPlanEquivocation() throws {
    let unknownDirectory = try retentionTemporaryDirectory(); defer { try? FileManager.default.removeItem(at: unknownDirectory) }
    let segment = retentionSegment(); try writeRetentionArchives(segment, to: unknownDirectory)
    let (plan, verifier) = try executableRetentionPlan(directory: unknownDirectory, segment: segment)
    let fault = RetentionFaultBox(.afterIntentSynced)
    #expect(throws: RetentionInjectedFailure.self) {
        try NativeAuditPruneExecutor(archiveDirectory: unknownDirectory.path, faultInjector: fault.inject).execute(
            plan: plan, verifier: verifier, currentBoundary: retentionBoundary, expectedNextRetained: nil,
            completedAt: "2027-01-20T00:01:00.000Z", now: retentionDate("2027-01-20T00:02:00.000Z"), signer: retentionSigner
        )
    }
    let state = unknownDirectory.appendingPathComponent(".agentpass-prune-transactions")
    let operation = try #require(FileManager.default.contentsOfDirectory(at: state, includingPropertiesForKeys: nil).first)
    let unknown = operation.appendingPathComponent("quarantine/unknown.jsonl")
    FileManager.default.createFile(atPath: unknown.path, contents: Data("unknown".utf8), attributes: [.posixPermissions: 0o600])
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditPruneExecutor(archiveDirectory: unknownDirectory.path).recover(
            plan: plan, verifier: verifier, currentBoundary: retentionBoundary,
            expectedNextRetained: nil, now: retentionDate("2027-01-20T00:03:00.000Z")
        )
    }

    let equivocationDirectory = try retentionTemporaryDirectory(); defer { try? FileManager.default.removeItem(at: equivocationDirectory) }
    try writeRetentionArchives(segment, to: equivocationDirectory)
    let (firstPlan, firstVerifier) = try executableRetentionPlan(directory: equivocationDirectory, segment: segment)
    let firstFault = RetentionFaultBox(.afterIntentSynced)
    #expect(throws: RetentionInjectedFailure.self) {
        try NativeAuditPruneExecutor(archiveDirectory: equivocationDirectory.path, faultInjector: firstFault.inject).execute(
            plan: firstPlan, verifier: firstVerifier, currentBoundary: retentionBoundary, expectedNextRetained: nil,
            completedAt: "2027-01-20T00:01:00.000Z", now: retentionDate("2027-01-20T00:02:00.000Z"), signer: retentionSigner
        )
    }
    let conflictingAuthorization = try NativeAuditPruneAuthorization.create(
        tenant: "native-host", operationID: firstPlan.authorization.operationID, sequence: 1,
        retentionSeconds: retentionSeconds + 1, requestedAt: "2027-01-15T00:00:00.000Z",
        boundary: retentionBoundary, segments: [segment], signer: retentionSigner
    )
    let (conflictingPlan, _) = try executableRetentionPlan(directory: equivocationDirectory, segment: segment, authorization: conflictingAuthorization)
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditPruneExecutor(archiveDirectory: equivocationDirectory.path).recover(
            plan: conflictingPlan, verifier: firstVerifier, currentBoundary: retentionBoundary,
            expectedNextRetained: nil, now: retentionDate("2027-01-20T00:03:00.000Z")
        )
    }
}

@Test func auditPruneExecutorRejectsDataOnlyPlanAndRetainedBoundaryDeletion() throws {
    let dataOnlySegment = retentionSegment()
    let authorization = try retentionAuthorization(segments: [dataOnlySegment]); let receipt = try retentionReceipt(authorization)
    let verifier = try retentionVerifier()
    let plan = try verifier.eligiblePlan(
        authorizationData: authorization.canonicalData(), receiptData: receipt.canonicalData(),
        observedArchives: retentionObservations([dataOnlySegment]), prior: .init(), currentBoundary: retentionBoundary,
        now: retentionDate("2027-01-20T00:02:00.000Z")
    )
    let dataOnlyDirectory = try retentionTemporaryDirectory(); defer { try? FileManager.default.removeItem(at: dataOnlyDirectory) }
    try writeRetentionArchives(dataOnlySegment, to: dataOnlyDirectory)
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditPruneExecutor(archiveDirectory: dataOnlyDirectory.path).execute(
            plan: plan, verifier: verifier, currentBoundary: retentionBoundary, expectedNextRetained: nil,
            completedAt: "2027-01-20T00:01:00.000Z", now: retentionDate("2027-01-20T00:02:00.000Z"), signer: retentionSigner
        )
    }

    let collisionDirectory = try retentionTemporaryDirectory(); defer { try? FileManager.default.removeItem(at: collisionDirectory) }
    try writeRetentionArchives(dataOnlySegment, to: collisionDirectory)
    let (executable, executableVerifier) = try executableRetentionPlan(directory: collisionDirectory, segment: dataOnlySegment)
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditPruneExecutor(archiveDirectory: collisionDirectory.path).execute(
            plan: executable, verifier: executableVerifier, currentBoundary: retentionBoundary,
            expectedNextRetained: retainedSegment(after: dataOnlySegment, auditFile: dataOnlySegment.auditArchiveFile),
            completedAt: "2027-01-20T00:01:00.000Z", now: retentionDate("2027-01-20T00:02:00.000Z"), signer: retentionSigner
        )
    }
}
