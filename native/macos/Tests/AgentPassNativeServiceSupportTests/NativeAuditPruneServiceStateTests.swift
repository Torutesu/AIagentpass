import AgentPassNativeCore
import AgentPassNativeServiceSupport
import CryptoKit
import Foundation
import Testing

private func pruneBoundary(event: Int = 7, checkpoint: Int = 5, lifecycle: String = String(repeating: "1", count: 64), transition: String = String(repeating: "2", count: 64)) -> NativeAuditRetentionBoundary {
    .init(lifecycleHeadHash: lifecycle, auditKeyTransitionReceiptHash: transition,
          anchorEventIndex: event, anchorEventHash: String(repeating: "3", count: 64),
          checkpointIndex: checkpoint, checkpointHash: String(repeating: "4", count: 64),
          checkpointReceiptHash: String(repeating: "5", count: 64))
}

private func pruneTrustDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("agentpass-prune-trust-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    return url
}

private final class TestPrunePin: NativeAuditPruneWALHeadPin, @unchecked Sendable {
    private let lock = NSLock(); private var head: String?
    func currentAuditPruneTrustHead() throws -> String? { lock.lock(); defer { lock.unlock() }; return head }
    func advanceAuditPruneTrustHead(expected: String?, newHead: String) throws {
        lock.lock(); defer { lock.unlock() }
        guard head == expected else { throw AgentPassNativeError.invalidSignature("pin compare-and-swap failed") }
        head = newHead
    }
}

private final class TestObservationClock: @unchecked Sendable {
    private let lock = NSLock(); private var value: UInt64 = 1_000
    func now() -> UInt64 { lock.lock(); defer { lock.unlock() }; return value }
    func advance(_ amount: UInt64) { lock.lock(); value += amount; lock.unlock() }
}

private func pruneLease(_ position: NativeAuditPruneExternalReceiptPosition?, purpose: NativeAuditPruneExternalObservationPurpose, operationID: String? = nil, deadline: UInt64 = .max) -> NativeAuditPruneExternalReceiptLease {
    .init(canonicalData: Data("{}".utf8), leaseID: UUID().uuidString.lowercased(), purpose: purpose, operationID: operationID, position: position, destructiveDeadlineUptimeNanoseconds: deadline)
}

private func substituteBooleanInInitialRecord(_ mutate: (inout [String: Any]) -> Void) throws -> URL {
    let root = try pruneTrustDirectory()
    _ = try NativeAuditPruneServiceTrustSource(rootPath: root.path, tenant: "tenant-1", initialBoundary: pruneBoundary())
    let recordURL = root.appendingPathComponent("record-00000000000000000000.json")
    var object = try JSONSerialization.jsonObject(with: Data(contentsOf: recordURL)) as! [String: Any]
    mutate(&object); object.removeValue(forKey: "record_hash")
    let unsigned = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    let hash = SHA256.hash(data: unsigned).map { String(format: "%02x", $0) }.joined()
    object["record_hash"] = hash
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: recordURL.path)
    try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]).write(to: recordURL)
    try FileManager.default.setAttributes([.posixPermissions: 0o400], ofItemAtPath: recordURL.path)
    let tipURL = root.appendingPathComponent("tip.json")
    var tip = try JSONSerialization.jsonObject(with: Data(contentsOf: tipURL)) as! [String: Any]; tip["record_hash"] = hash
    try JSONSerialization.data(withJSONObject: tip, options: [.sortedKeys, .withoutEscapingSlashes]).write(to: tipURL, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tipURL.path)
    return root
}

@Test func auditPruneTrustPersistsReservationAndExactChainAdvance() throws {
    let root = try pruneTrustDirectory()
    let source = try NativeAuditPruneServiceTrustSource(rootPath: root.path, tenant: "tenant-1", initialBoundary: pruneBoundary())
    let before = try source.currentAuditPruneTrustSnapshot()
    let reservation = try source.acquireAuditPruneMutationReservation(operationID: "operation-1", expected: nil)
    #expect(reservation.snapshotRevision == before.revision)
    try source.validateAuditPruneMutationReservation(reservation)
    let next = NativeAuditPruneChainState(sequence: 1, authorizationHash: String(repeating: "a", count: 64), receiptHash: String(repeating: "b", count: 64), manifestHash: String(repeating: "c", count: 64), lastEventIndex: 2, lastCheckpointIndex: 1, lastReceiptIndex: 1, lastEventHash: String(repeating: "d", count: 64), lastCheckpointHash: String(repeating: "e", count: 64), lastArchiveReceiptHash: String(repeating: "f", count: 64))
    try source.completeAuditPruneMutationReservation(reservation, nextState: next)
    let restarted = try NativeAuditPruneServiceTrustSource(rootPath: root.path, tenant: "tenant-1", initialBoundary: pruneBoundary())
    #expect(try restarted.currentAuditPruneTrustSnapshot().chainState == next)
}

@Test func auditPruneExternalReceiptObservationsAreOneShotFreshAndGenerationBound() throws {
    let walRoot = try pruneTrustDirectory(); let walPin = TestPrunePin()
    let walOnly = try NativeAuditPruneServiceTrustSource(rootPath: walRoot.path, tenant: "tenant-1", initialBoundary: pruneBoundary(), walHeadPin: walPin)
    #expect(try walOnly.currentTrustHeadHash() == walPin.currentAuditPruneTrustHead())
    #expect(!walOnly.externalReceiptPositionProviderConfigured)
    #expect(throws: (any Error).self) {
        _ = try walOnly.issueAuditPruneExternalReceiptObservation(lease: pruneLease(nil, purpose: .status), purpose: .status)
    }

    let clock = TestObservationClock()
    let emptyRoot = try pruneTrustDirectory()
    let emptySource = try NativeAuditPruneServiceTrustSource(
        rootPath: emptyRoot.path, tenant: "tenant-1", initialBoundary: pruneBoundary(),
        externalReceiptObservationRequired: true, observationClock: { clock.now() }
    )
    #expect(emptySource.externalReceiptPositionProviderConfigured)
    let zero = try emptySource.issueAuditPruneExternalReceiptObservation(lease: pruneLease(nil, purpose: .status), purpose: .status)
    #expect(try emptySource.consumeAuditPruneExternalReceiptObservation(zero, purpose: .status, operationID: nil) == nil)
    #expect(throws: (any Error).self) {
        _ = try emptySource.consumeAuditPruneExternalReceiptObservation(zero, purpose: .status, operationID: nil)
    }
    let stale = try emptySource.issueAuditPruneExternalReceiptObservation(lease: pruneLease(nil, purpose: .status), purpose: .status)
    clock.advance(5_000_000_001)
    #expect(throws: (any Error).self) {
        _ = try emptySource.consumeAuditPruneExternalReceiptObservation(stale, purpose: .status, operationID: nil)
    }
    let wrongPurpose = try emptySource.issueAuditPruneExternalReceiptObservation(lease: pruneLease(nil, purpose: .status), purpose: .status)
    #expect(throws: (any Error).self) {
        _ = try emptySource.consumeAuditPruneExternalReceiptObservation(wrongPurpose, purpose: .execute, operationID: nil)
    }
    let destructive = try emptySource.issueAuditPruneExternalReceiptObservation(
        lease: pruneLease(nil, purpose: .prepare, operationID: "lease-deadline", deadline: clock.now() + 100),
        purpose: .prepare, operationID: "lease-deadline"
    )
    _ = try emptySource.consumeAuditPruneExternalReceiptObservation(destructive, purpose: .prepare, operationID: "lease-deadline")
    try emptySource.validateConsumedAuditPruneExternalLease(destructive, purpose: .prepare, operationID: "lease-deadline")
    clock.advance(101)
    #expect(throws: (any Error).self) {
        try emptySource.validateConsumedAuditPruneExternalLease(destructive, purpose: .prepare, operationID: "lease-deadline")
    }
    try emptySource.finishAuditPruneExternalReceiptObservation(destructive)

    let malformedRoot = try pruneTrustDirectory()
    let malformedSource = try NativeAuditPruneServiceTrustSource(
        rootPath: malformedRoot.path, tenant: "tenant-1", initialBoundary: pruneBoundary(),
        externalReceiptObservationRequired: true
    )
    #expect(throws: (any Error).self) {
        _ = try malformedSource.issueAuditPruneExternalReceiptObservation(lease: pruneLease(.init(sequence: 0, receiptHash: "not-a-receipt-hash"), purpose: .status), purpose: .status)
    }

    let externalRoot = try pruneTrustDirectory()
    let externalSource = try NativeAuditPruneServiceTrustSource(
        rootPath: externalRoot.path, tenant: "tenant-1", initialBoundary: pruneBoundary(),
        externalReceiptObservationRequired: true
    )
    let reservation = try externalSource.acquireAuditPruneMutationReservation(operationID: "operation-external", expected: nil)
    let position = NativeAuditPruneExternalReceiptPosition(sequence: 1, receiptHash: String(repeating: "a", count: 64))
    let submitted = try externalSource.issueAuditPruneExternalReceiptObservation(lease: pruneLease(position, purpose: .submit, operationID: "operation-external"), purpose: .submit)
    #expect(try externalSource.consumeAuditPruneExternalReceiptObservation(submitted, purpose: .submit, operationID: "operation-external") == position)
    #expect(try externalSource.currentTrustHeadHash() != position.receiptHash)
    try externalSource.completeAuditPruneMutationReservation(
        reservation,
        nextState: NativeAuditPruneChainState(sequence: 1, authorizationHash: String(repeating: "1", count: 64), receiptHash: position.receiptHash, manifestHash: String(repeating: "3", count: 64))
    )
    let exact = try externalSource.issueAuditPruneExternalReceiptObservation(lease: pruneLease(position, purpose: .status), purpose: .status)
    #expect(try externalSource.consumeAuditPruneExternalReceiptObservation(exact, purpose: .status, operationID: nil) == position)
    #expect(throws: (any Error).self) {
        _ = try externalSource.issueAuditPruneExternalReceiptObservation(lease: pruneLease(.init(sequence: 2, receiptHash: String(repeating: "b", count: 64)), purpose: .status), purpose: .status)
    }
    #expect(throws: (any Error).self) {
        _ = try externalSource.issueAuditPruneExternalReceiptObservation(lease: pruneLease(.init(sequence: 1, receiptHash: String(repeating: "c", count: 64)), purpose: .status), purpose: .status)
    }
    #expect(throws: (any Error).self) {
        _ = try externalSource.issueAuditPruneExternalReceiptObservation(lease: pruneLease(nil, purpose: .status), purpose: .status)
    }

    let generationRoot = try pruneTrustDirectory()
    let generationSource = try NativeAuditPruneServiceTrustSource(rootPath: generationRoot.path, tenant: "tenant-1", initialBoundary: pruneBoundary(), externalReceiptObservationRequired: true)
    let generationObservation = try generationSource.issueAuditPruneExternalReceiptObservation(lease: pruneLease(nil, purpose: .prepare, operationID: "operation-generation"), purpose: .prepare, operationID: "operation-generation")
    _ = try generationSource.acquireAuditPruneMutationReservation(operationID: "operation-generation", expected: nil)
    #expect(throws: (any Error).self) {
        _ = try generationSource.consumeAuditPruneExternalReceiptObservation(generationObservation, purpose: .prepare, operationID: "operation-generation")
    }
}

@Test func auditPruneTrustFreezesBoundaryAndRejectsRollbackTip() throws {
    let root = try pruneTrustDirectory()
    let source = try NativeAuditPruneServiceTrustSource(rootPath: root.path, tenant: "tenant-1", initialBoundary: pruneBoundary())
    _ = try source.acquireAuditPruneMutationReservation(operationID: "operation-1", expected: nil)
    #expect(throws: (any Error).self) { try source.refreshVerifiedBoundary(pruneBoundary(event: 8, checkpoint: 6)) }
    #expect(throws: (any Error).self) {
        _ = try NativeAuditPruneServiceTrustSource(rootPath: root.path, tenant: "tenant-1", initialBoundary: pruneBoundary(event: 8, checkpoint: 6))
    }

    let originalTip = try Data(contentsOf: root.appendingPathComponent("tip.json"))
    let originalObject = try JSONSerialization.jsonObject(with: originalTip) as! [String: Any]
    var rolled = originalObject
    rolled["revision"] = 0
    let record0 = try Data(contentsOf: root.appendingPathComponent("record-00000000000000000000.json"))
    rolled["record_hash"] = (try JSONSerialization.jsonObject(with: record0) as! [String: Any])["record_hash"]
    try JSONSerialization.data(withJSONObject: rolled, options: [.sortedKeys, .withoutEscapingSlashes]).write(to: root.appendingPathComponent("tip.json"), options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: root.appendingPathComponent("tip.json").path)
    #expect(throws: (any Error).self) { _ = try NativeAuditPruneServiceTrustSource(rootPath: root.path, tenant: "tenant-1", initialBoundary: pruneBoundary()) }
}

@Test func auditPruneEvidencePublicationIsAtomicAndPrivate() throws {
    let root = try pruneTrustDirectory()
    let path = root.appendingPathComponent("evidence.json").path
    try NativeAuditPruneEvidencePublisher.publish(Data("first".utf8), path: path)
    try NativeAuditPruneEvidencePublisher.publish(Data("second".utf8), path: path)
    #expect(try Data(contentsOf: URL(fileURLWithPath: path)) == Data("second".utf8))
    let attributes = try FileManager.default.attributesOfItem(atPath: path)
    #expect((attributes[.posixPermissions] as? NSNumber)?.uint16Value == 0o600)
}

@Test func auditPruneTrustRepairsExactPinnedRecordAheadOfTip() throws {
    let root = try pruneTrustDirectory(); let pin = TestPrunePin()
    var source: NativeAuditPruneServiceTrustSource? = try .init(rootPath: root.path, tenant: "tenant-1", initialBoundary: pruneBoundary(), walHeadPin: pin)
    #expect(try source?.currentTrustHeadHash() != nil)
    let record0 = try Data(contentsOf: root.appendingPathComponent("tip.json"))
    _ = try source!.acquireAuditPruneMutationReservation(operationID: "operation-1", expected: nil)
    try record0.write(to: root.appendingPathComponent("tip.json"), options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: root.appendingPathComponent("tip.json").path)
    source = nil
    let restarted = try NativeAuditPruneServiceTrustSource(rootPath: root.path, tenant: "tenant-1", initialBoundary: pruneBoundary(), walHeadPin: pin)
    #expect(try restarted.currentAuditPruneTrustSnapshot().activeReservationID != nil)
}

@Test func auditPruneTrustRepairsPinnedInitialRecordWithMissingTip() throws {
    let root = try pruneTrustDirectory(); let pin = TestPrunePin()
    var source: NativeAuditPruneServiceTrustSource? = try .init(rootPath: root.path, tenant: "tenant-1", initialBoundary: pruneBoundary(), walHeadPin: pin)
    #expect(try source?.currentTrustHeadHash() == pin.currentAuditPruneTrustHead())
    try FileManager.default.removeItem(at: root.appendingPathComponent("tip.json"))
    source = nil
    let restarted = try NativeAuditPruneServiceTrustSource(rootPath: root.path, tenant: "tenant-1", initialBoundary: pruneBoundary(), walHeadPin: pin)
    #expect(try restarted.currentTrustHeadHash() == pin.currentAuditPruneTrustHead())
}

@Test func auditPruneTrustRejectsBooleanIntegerAndPathSwap() throws {
    let root = try pruneTrustDirectory()
    var source: NativeAuditPruneServiceTrustSource? = try .init(rootPath: root.path, tenant: "tenant-1", initialBoundary: pruneBoundary())
    let tipURL = root.appendingPathComponent("tip.json")
    var tip = try JSONSerialization.jsonObject(with: Data(contentsOf: tipURL)) as! [String: Any]
    tip["revision"] = true
    try JSONSerialization.data(withJSONObject: tip, options: [.sortedKeys, .withoutEscapingSlashes]).write(to: tipURL, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tipURL.path)
    #expect(throws: (any Error).self) { _ = try source!.currentAuditPruneTrustSnapshot() }
    source = nil

    let second = try pruneTrustDirectory()
    let live = try NativeAuditPruneServiceTrustSource(rootPath: second.path, tenant: "tenant-1", initialBoundary: pruneBoundary())
    let moved = second.deletingLastPathComponent().appendingPathComponent(second.lastPathComponent + "-moved")
    try FileManager.default.moveItem(at: second, to: moved)
    try FileManager.default.createDirectory(at: second, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    #expect(throws: (any Error).self) { _ = try live.currentAuditPruneTrustSnapshot() }
}

@Test func auditPruneTrustRejectsBooleanIntegersInRecordBoundaryAndChain() throws {
    let revisionRoot = try substituteBooleanInInitialRecord { $0["revision"] = true }
    #expect(throws: (any Error).self) { _ = try NativeAuditPruneServiceTrustSource(rootPath: revisionRoot.path, tenant: "tenant-1", initialBoundary: pruneBoundary()) }
    let boundaryRoot = try substituteBooleanInInitialRecord {
        var boundary = $0["boundary"] as! [String: Any]; boundary["anchor_event_index"] = true; $0["boundary"] = boundary
    }
    #expect(throws: (any Error).self) { _ = try NativeAuditPruneServiceTrustSource(rootPath: boundaryRoot.path, tenant: "tenant-1", initialBoundary: pruneBoundary()) }
    let chainRoot = try substituteBooleanInInitialRecord {
        var chain = $0["chain_state"] as! [String: Any]; chain["sequence"] = true; $0["chain_state"] = chain
    }
    #expect(throws: (any Error).self) { _ = try NativeAuditPruneServiceTrustSource(rootPath: chainRoot.path, tenant: "tenant-1", initialBoundary: pruneBoundary()) }
}

@Test func auditPruneTrustRemovesOnlySafeTipTempRemnants() throws {
    let root = try pruneTrustDirectory()
    _ = try NativeAuditPruneServiceTrustSource(rootPath: root.path, tenant: "tenant-1", initialBoundary: pruneBoundary())
    let temp = root.appendingPathComponent(".tip-00000000-0000-0000-0000-000000000000")
    try Data("partial".utf8).write(to: temp); try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: temp.path)
    _ = try NativeAuditPruneServiceTrustSource(rootPath: root.path, tenant: "tenant-1", initialBoundary: pruneBoundary())
    #expect(!FileManager.default.fileExists(atPath: temp.path))

    let unsafeRoot = try pruneTrustDirectory()
    _ = try NativeAuditPruneServiceTrustSource(rootPath: unsafeRoot.path, tenant: "tenant-1", initialBoundary: pruneBoundary())
    let unsafe = unsafeRoot.appendingPathComponent(".tip-11111111-1111-1111-1111-111111111111")
    try FileManager.default.createSymbolicLink(at: unsafe, withDestinationURL: unsafeRoot.appendingPathComponent("tip.json"))
    #expect(throws: (any Error).self) { _ = try NativeAuditPruneServiceTrustSource(rootPath: unsafeRoot.path, tenant: "tenant-1", initialBoundary: pruneBoundary()) }
}
