import AgentPassNativeServiceSupport
import AgentPassNativeCore
import CryptoKit
import Foundation
import Testing

private final class DelayedPruneHeadProvider: NativeAuditPruneExternalReceiptPositionProvider, @unchecked Sendable {
    let started = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)
    private let countLock = NSLock()
    private var acquireCountStorage = 0
    var acquireCount: Int { countLock.withLock { acquireCountStorage } }

    func readAuditPruneReceiptHead() throws -> NativeAuditPruneExternalReceiptHead {
        started.signal()
        guard release.wait(timeout: .now() + 10) == .success else {
            throw AgentPassNativeError.invalidConfiguration("test head read timed out")
        }
        return .init(canonicalData: Data("{}".utf8), position: nil)
    }

    func acquireAuditPruneReceiptLease(purpose: NativeAuditPruneExternalObservationPurpose, operationID: String, expected: NativeAuditPruneExternalReceiptPosition?) throws -> NativeAuditPruneExternalReceiptLease {
        countLock.withLock { acquireCountStorage += 1 }
        return .init(canonicalData: Data("{}".utf8), leaseID: String(repeating: "L", count: 43), purpose: purpose, operationID: operationID, position: expected, destructiveDeadlineUptimeNanoseconds: DispatchTime.now().uptimeNanoseconds + 30_000_000_000)
    }

    func releaseAuditPruneReceiptLease(_ lease: NativeAuditPruneExternalReceiptLease) throws {}
}

private func concurrencyPruneTrust() throws -> NativeAuditPruneServiceTrustSource {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("agentpass-prune-concurrency-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    let boundary = NativeAuditRetentionBoundary(
        lifecycleHeadHash: String(repeating: "1", count: 64),
        auditKeyTransitionReceiptHash: String(repeating: "2", count: 64),
        anchorEventIndex: 1, anchorEventHash: String(repeating: "3", count: 64),
        checkpointIndex: 1, checkpointHash: String(repeating: "4", count: 64),
        checkpointReceiptHash: String(repeating: "5", count: 64)
    )
    return try NativeAuditPruneServiceTrustSource(
        rootPath: root.path, tenant: "tenant-1", initialBoundary: boundary,
        externalReceiptObservationRequired: true
    )
}

@Test func serviceAuthorizationGateAllowsNestedHelpersWithoutDeadlock() {
    let gate = ServiceAuthorizationGate()
    let completed = DispatchSemaphore(value: 0)
    let worker = Thread {
        _ = gate.withLock {
            gate.withLock { completed.signal() }
        }
    }
    worker.start()
    #expect(completed.wait(timeout: .now() + 10) == .success)
}

@Test func serviceAuthorizationGateSerializesConcurrentPendingStateMutation() async {
    let gate = ServiceAuthorizationGate()
    let iterations = 2_000
    nonisolated(unsafe) var value = 0
    await withTaskGroup(of: Void.self) { group in
        for _ in 0..<iterations {
            group.addTask {
                gate.withLock { value += 1 }
            }
        }
    }
    #expect(value == iterations)
}

@Test func auditPruneNetworkWaitReleasesGlobalGateAndConcurrentStagesFailClosed() {
    let gate = ServiceAuthorizationGate()
    let networkStarted = DispatchSemaphore(value: 0)
    let releaseNetwork = DispatchSemaphore(value: 0)
    let submissionFinished = DispatchSemaphore(value: 0)
    nonisolated(unsafe) var submissionInFlight = false
    nonisolated(unsafe) var concurrentSubmitRejected = false
    nonisolated(unsafe) var concurrentExecuteRejected = false

    let submitter = Thread {
        gate.withLock { submissionInFlight = true }
        networkStarted.signal()
        _ = releaseNetwork.wait(timeout: .now() + 10)
        gate.withLock { submissionInFlight = false }
        submissionFinished.signal()
    }
    submitter.start()
    #expect(networkStarted.wait(timeout: .now() + 10) == .success)

    let observerFinished = DispatchSemaphore(value: 0)
    let observer = Thread {
        gate.withLock {
            concurrentSubmitRejected = submissionInFlight
            concurrentExecuteRejected = submissionInFlight
        }
        observerFinished.signal()
    }
    observer.start()
    #expect(observerFinished.wait(timeout: .now() + 2) == .success)
    #expect(concurrentSubmitRejected)
    #expect(concurrentExecuteRejected)
    releaseNetwork.signal()
    #expect(submissionFinished.wait(timeout: .now() + 10) == .success)
    #expect(gate.withLock { !submissionInFlight })
}

@Test func delayedProductionPruneHeadFetchDoesNotHoldAuthorizationGate() throws {
    let gate = ServiceAuthorizationGate()
    let provider = DelayedPruneHeadProvider()
    let trust = try concurrencyPruneTrust()
    let fetcher = NativeAuditPruneExternalObservationFetcher(provider: provider, trustSource: trust)
    let fetchFinished = DispatchSemaphore(value: 0)
    let managementFinished = DispatchSemaphore(value: 0)
    nonisolated(unsafe) var fetched: Result<NativeAuditPruneExternalReceiptObservation, Error>?

    let fetchThread = Thread {
        // This is the production call shape: authorization preflight ends before HTTPS begins.
        gate.withLock {}
        do { fetched = .success(try fetcher.fetch(purpose: .status)) }
        catch { fetched = .failure(error) }
        fetchFinished.signal()
    }
    fetchThread.start()
    #expect(provider.started.wait(timeout: .now() + 10) == .success)

    let managementThread = Thread {
        _ = gate.withLock { managementFinished.signal() }
    }
    managementThread.start()
    #expect(managementFinished.wait(timeout: .now() + 2) == .success)
    provider.release.signal()
    #expect(fetchFinished.wait(timeout: .now() + 10) == .success)
    let observation = try #require(fetched).get()
    #expect(try trust.consumeAuditPruneExternalReceiptObservation(observation, purpose: .status, operationID: nil) == nil)
    #expect(provider.acquireCount == 0, "read-only status must never acquire an exclusive Node lease")
}

@Test func auditRecoveryApprovalJournalPersistsAndRevalidatesExactPresenceProof() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("agentpass-approval-journal-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    let key = P256.Signing.PrivateKey()
    let publicKey = key.publicKey.x963Representation
    let statement = Data("exact lifecycle statement".utf8)
    let authorization = Data("exact anchor authorization".utf8)
    let signature = try NativeP256CanonicalSignature.canonicalized(key.signature(for: statement).rawRepresentation)
    let fingerprint = NativeKeyLifecycleStore.fingerprint(publicKey)

    do {
        let journal = try NativeAuditRecoveryApprovalJournal(rootPath: root.path)
        _ = try journal.append(
            operationID: "operation-1", signerFingerprint: fingerprint,
            signerPublicKeyX963: publicKey, statementData: statement,
            authorizationData: authorization, signature: signature,
            createdAt: "2026-08-11T00:00:00.000Z"
        )
    }
    let restarted = try NativeAuditRecoveryApprovalJournal(rootPath: root.path)
    _ = try restarted.require(
        operationID: "operation-1", statementData: statement,
        authorizationData: authorization, expectedSignerFingerprint: fingerprint
    )
    #expect(throws: (any Error).self) {
        _ = try restarted.require(
            operationID: "operation-1", statementData: statement,
            authorizationData: Data("substituted".utf8), expectedSignerFingerprint: fingerprint
        )
    }
}

@Test func auditRecoveryApprovalJournalRejectsInsecureDirectoryAndUnknownEntry() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("agentpass-approval-journal-bad-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o755])
    #expect(throws: (any Error).self) { _ = try NativeAuditRecoveryApprovalJournal(rootPath: root.path) }
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
    try Data("{}".utf8).write(to: root.appendingPathComponent("unknown.json"))
    #expect(throws: (any Error).self) { _ = try NativeAuditRecoveryApprovalJournal(rootPath: root.path) }
}
