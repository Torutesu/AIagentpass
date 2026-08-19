import AgentPassNativeCore
import AgentPassNativeServiceSupport
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

    func uploadAuditBatch(_ batch: NativeDeviceAuditBatch) async throws -> NativeDeviceAuditIngestionResponse {
        calls += 1
        if let failure { throw failure }
        guard let response else { throw NativeDeviceSyncHTTPTransportError.transportFailure }
        return response
    }

    func configure(response: NativeDeviceAuditIngestionResponse? = nil, failure: NativeDeviceSyncHTTPTransportError? = nil) {
        self.response = response
        self.failure = failure
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
