import AgentPassNativeCore
import Foundation
import Testing
@testable import AgentPassNativeServiceSupport

private actor FakeAuditUploader: NativeDeviceAuditBatchUploading {
    private(set) var calls = 0
    var response: NativeDeviceAuditIngestionResponse?
    var shouldFail = false

    func uploadAuditBatch(_ batch: NativeDeviceAuditBatch) async throws -> NativeDeviceAuditIngestionResponse {
        calls += 1
        if shouldFail { throw NativeDeviceSyncHTTPTransportError.transportFailure }
        guard let response else { throw NativeDeviceSyncHTTPTransportError.transportFailure }
        return response
    }

    func configure(response: NativeDeviceAuditIngestionResponse?, shouldFail: Bool) {
        self.response = response; self.shouldFail = shouldFail
    }
}

private func coordinatorRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("agentpass-audit-coordinator-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    return root
}

private func coordinatorEvent() throws -> NativeDeviceAuditEvent {
    try NativeDeviceAuditEvent(
        eventID: "99999999-9999-4999-8999-999999999999",
        requestID: "88888888-8888-4888-8888-888888888888",
        agentID: "77777777-7777-4777-8777-777777777777",
        decision: "allow", reason: "allowed", policySequence: 1, capabilitySequence: 1,
        repository: "/Users/agent/repository", branch: "refs/heads/main", remote: "origin",
        payloadDigest: String(repeating: "a", count: 64),
        deviceTimestamp: "2026-08-20T05:00:00.000Z",
        previousHash: String(repeating: "0", count: 64)
    )
}

@Test("upload coordinator keeps exact events after response loss and drains after retry")
func uploadCoordinatorRetriesWithoutDeletingOnFailure() async throws {
    let root = try coordinatorRoot(); defer { try? FileManager.default.removeItem(at: root) }
    let outbox = try NativeDeviceAuditOutbox(rootPath: root.path)
    let event = try coordinatorEvent(); _ = try outbox.enqueue(event)
    let fake = FakeAuditUploader(); await fake.configure(response: nil, shouldFail: true)
    let coordinator = NativeDeviceAuditUploadCoordinator(outbox: outbox, transport: fake)
    do { _ = try await coordinator.flush(); Issue.record("transport failure unexpectedly succeeded") } catch is NativeDeviceSyncHTTPTransportError {}
    #expect(try outbox.pending() == [event])

    await fake.configure(response: NativeDeviceAuditIngestionResponse(deviceID: "device", acceptedEventIDs: [event.eventID], duplicateEventIDs: [], gapCount: 0, headHash: event.eventHash, headEventID: event.eventID, chainStatus: "continuous"), shouldFail: false)
    #expect(try await coordinator.flush() == 1)
    #expect(try outbox.pending().isEmpty)
    #expect(await fake.calls == 2)
}

@Test("upload coordinator bounds retry attempts and never loops indefinitely")
func uploadCoordinatorBoundsAttempts() async throws {
    let root = try coordinatorRoot(); defer { try? FileManager.default.removeItem(at: root) }
    let outbox = try NativeDeviceAuditOutbox(rootPath: root.path)
    _ = try outbox.enqueue(try coordinatorEvent())
    let fake = FakeAuditUploader(); await fake.configure(response: nil, shouldFail: true)
    let coordinator = NativeDeviceAuditUploadCoordinator(outbox: outbox, transport: fake)
    #expect(try await coordinator.flush(maximumAttempts: 3) == 0)
    #expect(await fake.calls == 3)
    #expect(try outbox.pending().count == 1)
    do { _ = try await coordinator.flush(maximumAttempts: 9); Issue.record("invalid attempt bound unexpectedly succeeded") } catch is AgentPassNativeError {}
}
