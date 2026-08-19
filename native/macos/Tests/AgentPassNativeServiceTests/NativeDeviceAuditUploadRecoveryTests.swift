import AgentPassNativeCore
import AgentPassNativeServiceSupport
import Darwin
import Foundation
import Testing
@testable import AgentPassNativeService

private enum UploadRecoveryTestError: Error {
    case diskFull
}

private actor UploadRecoveryFake: NativeDeviceAuditBatchUploading {
    var calls = 0
    var response: NativeDeviceAuditIngestionResponse?
    var failure: NativeDeviceSyncHTTPTransportError?
    var blockUntilCancelled = false

    func uploadAuditBatch(_ batch: NativeDeviceAuditBatch) async throws -> NativeDeviceAuditIngestionResponse {
        calls += 1
        if blockUntilCancelled {
            try await Task.sleep(nanoseconds: UInt64.max)
        }
        if let failure { throw failure }
        guard let response else { throw NativeDeviceSyncHTTPTransportError.transportFailure }
        return response
    }

    func configure(response: NativeDeviceAuditIngestionResponse? = nil, failure: NativeDeviceSyncHTTPTransportError? = nil, blockUntilCancelled: Bool = false) {
        self.response = response
        self.failure = failure
        self.blockUntilCancelled = blockUntilCancelled
    }
}

private func uploadRecoveryRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("agentpass-device-audit-upload-recovery-\(UUID().uuidString)")
    try FileManager.default.createDirectory(
        at: root,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    return root
}

private func uploadRecoveryEvent() throws -> NativeDeviceAuditEvent {
    try NativeDeviceAuditEvent(
        eventID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        requestID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        agentID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        decision: "allow",
        reason: "allowed",
        policySequence: 7,
        capabilitySequence: 9,
        repository: "/Users/agent/repository",
        branch: "refs/heads/main",
        remote: "origin",
        payloadDigest: String(repeating: "a", count: 64),
        deviceTimestamp: "2026-08-20T05:00:00.000Z",
        previousHash: String(repeating: "0", count: 64)
    )
}

private func uploadRecoveryResponse(for event: NativeDeviceAuditEvent) -> NativeDeviceAuditIngestionResponse {
    NativeDeviceAuditIngestionResponse(
        deviceID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        acceptedEventIDs: [event.eventID],
        duplicateEventIDs: [],
        gapCount: 0,
        headHash: event.eventHash,
        headEventID: event.eventID,
        chainStatus: "continuous"
    )
}

@Test("device audit upload health is durable across degraded and recovered restarts")
func deviceAuditUploadHealthSurvivesRestart() throws {
    let root = try uploadRecoveryRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let path = root.appendingPathComponent("upload-health.json").path
    let first = try NativeDeviceAuditUploadHealthStore(path: path)
    #expect(first.snapshot().state == NativeDeviceAuditUploadHealth.operational)

    try first.recordFailure(UploadRecoveryTestError.diskFull)
    let degraded = try NativeDeviceAuditUploadHealthStore(path: path)
    #expect(degraded.snapshot().state == NativeDeviceAuditUploadHealth.degraded)
    #expect(degraded.snapshot().consecutiveFailures == 1)
    #expect(degraded.snapshot().lastError != nil)

    try degraded.recordSuccess()
    let recovered = try NativeDeviceAuditUploadHealthStore(path: path)
    #expect(recovered.snapshot().state == NativeDeviceAuditUploadHealth.operational)
    #expect(recovered.snapshot().consecutiveFailures == 0)
    #expect(recovered.snapshot().lastError == nil)
}

@Test("device audit upload health is atomically replaced with private durable bytes")
func deviceAuditUploadHealthUsesPrivateAtomicPersistence() throws {
    let root = try uploadRecoveryRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let path = root.appendingPathComponent("upload-health.json").path
    let store = try NativeDeviceAuditUploadHealthStore(path: path)
    try store.recordFailure(UploadRecoveryTestError.diskFull)

    var info = stat()
    #expect(lstat(path, &info) == 0)
    #expect((info.st_mode & S_IFMT) == S_IFREG)
    #expect(info.st_uid == geteuid())
    #expect(info.st_mode & 0o077 == 0)
    #expect(try FileManager.default.contentsOfDirectory(atPath: root.path).allSatisfy { !$0.contains("tmp-") })
    let restarted = try NativeDeviceAuditUploadHealthStore(path: path)
    #expect(restarted.snapshot().state == NativeDeviceAuditUploadHealth.degraded)
}

@Test("successful signing audit records require durable device enqueue")
func successfulSigningAuditRequiresDurableEnqueue() throws {
    let event = NativeAuditEvent(
        operation: "git.commit.sign",
        decision: "allow",
        requestID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        reason: "allowed",
        agentID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        repository: "/Users/agent/repository",
        branch: "refs/heads/main",
        remote: "origin",
        payloadSHA256: String(repeating: "a", count: 64)
    )
    #expect(NativeDeviceAuditUploadPolicy.requiresDurableEnqueue(for: event))

    let denied = NativeAuditEvent(
        operation: "git.commit.sign",
        decision: "deny",
        reason: "policy_changed"
    )
    #expect(!NativeDeviceAuditUploadPolicy.requiresDurableEnqueue(for: denied))
}

@Test("required enqueue failure is returned while best-effort failure remains retryable")
func deviceAuditUploadAdmissionFailsClosedOnlyWhenRequired() throws {
    let root = try uploadRecoveryRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let health = try NativeDeviceAuditUploadHealthStore(path: root.appendingPathComponent("upload-health.json").path)

    #expect(throws: UploadRecoveryTestError.self) {
        try NativeDeviceAuditUploadAdmission.attempt(required: true, health: health) {
            throw UploadRecoveryTestError.diskFull
        }
    }
    #expect(health.snapshot().state == NativeDeviceAuditUploadHealth.degraded)

    try NativeDeviceAuditUploadAdmission.attempt(required: false, health: health) {
        throw UploadRecoveryTestError.diskFull
    }
    #expect(health.snapshot().consecutiveFailures == 2)
}

@Test("required signing audit admission fails closed when the durable outbox is absent")
func requiredSigningAuditAdmissionRequiresOutbox() throws {
    #expect(throws: AgentPassNativeError.self) {
        try NativeDeviceAuditUploadAdmission.validate(required: true, outboxAvailable: false)
    }
    try NativeDeviceAuditUploadAdmission.validate(required: false, outboxAvailable: false)
}

@Test("upload supervisor retries after an outage and clears persisted degraded health")
func uploadSupervisorRecoversAfterTransportRestoration() async throws {
    let root = try uploadRecoveryRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let outbox = try NativeDeviceAuditOutbox(rootPath: root.appendingPathComponent("outbox").path)
    let event = try uploadRecoveryEvent()
    _ = try outbox.enqueue(event)
    let fake = UploadRecoveryFake()
    await fake.configure(failure: .transportFailure)
    let health = try NativeDeviceAuditUploadHealthStore(path: root.appendingPathComponent("upload-health.json").path)
    let supervisor = NativeDeviceAuditUploadRetrySupervisor(
        coordinator: NativeDeviceAuditUploadCoordinator(outbox: outbox, transport: fake),
        health: health,
        intervalNanoseconds: 1
    )

    #expect(await supervisor.runOnce() == false)
    #expect(health.snapshot().state == NativeDeviceAuditUploadHealth.degraded)
    #expect(try outbox.pending() == [event])

    await fake.configure(response: uploadRecoveryResponse(for: event), failure: nil)
    #expect(await supervisor.runOnce() == true)
    #expect(try outbox.pending().isEmpty)
    #expect(health.snapshot().state == NativeDeviceAuditUploadHealth.operational)
    #expect(await fake.calls == 2)
}

@Test("cancelling the upload supervisor does not record cancellation as a failure or restart it")
func uploadSupervisorCancellationIsTerminal() async throws {
    let root = try uploadRecoveryRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let outbox = try NativeDeviceAuditOutbox(rootPath: root.appendingPathComponent("outbox").path)
    _ = try outbox.enqueue(try uploadRecoveryEvent())
    let fake = UploadRecoveryFake()
    await fake.configure(blockUntilCancelled: true)
    let health = try NativeDeviceAuditUploadHealthStore(path: root.appendingPathComponent("upload-health.json").path)
    let supervisor = NativeDeviceAuditUploadRetrySupervisor(
        coordinator: NativeDeviceAuditUploadCoordinator(outbox: outbox, transport: fake),
        health: health,
        intervalNanoseconds: UInt64.max
    )
    let task = supervisor.start()
    for _ in 0..<200 {
        if await fake.calls == 1 { break }
        await Task.yield()
    }
    task.cancel()
    await task.value
    #expect(health.snapshot().consecutiveFailures == 0)
    #expect(health.snapshot().lastError == nil)
    #expect(await fake.calls == 1)
}
