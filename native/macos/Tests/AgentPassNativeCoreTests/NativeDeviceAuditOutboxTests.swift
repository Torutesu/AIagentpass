import Foundation
import Testing
@testable import AgentPassNativeCore

private let outboxRequestID = "22222222-2222-4222-8222-222222222222"
private let outboxAgentID = "33333333-3333-4333-8333-333333333333"

private func outboxRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("agentpass-device-audit-outbox-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    return root
}

private func outboxEvent(_ id: String, previousHash: String = String(repeating: "0", count: 64)) throws -> NativeDeviceAuditEvent {
    try NativeDeviceAuditEvent(
        eventID: id,
        requestID: outboxRequestID,
        agentID: outboxAgentID,
        decision: "allow",
        reason: "allowed",
        policySequence: 7,
        capabilitySequence: 9,
        repository: "/Users/agent/repository",
        branch: "refs/heads/main",
        remote: "origin",
        payloadDigest: String(repeating: "a", count: 64),
        deviceTimestamp: "2026-08-20T05:00:00.000Z",
        previousHash: previousHash
    )
}

@Test("device audit outbox survives restart and preserves exact event bytes")
func deviceAuditOutboxSurvivesRestart() throws {
    let root = try outboxRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let event = try outboxEvent("11111111-1111-4111-8111-111111111111")
    let outbox = try NativeDeviceAuditOutbox(rootPath: root.path)
    _ = try outbox.enqueue(event)
    _ = try outbox.enqueue(event)
    let restarted = try NativeDeviceAuditOutbox(rootPath: root.path)
    #expect(try restarted.pending() == [event])
    #expect(try Data(contentsOf: root.appendingPathComponent("event_\(event.eventID).json")) == event.canonicalData())
}

@Test("device audit outbox rejects event equivocation and unknown acknowledgements")
func deviceAuditOutboxRejectsEquivocation() throws {
    let root = try outboxRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let event = try outboxEvent("44444444-4444-4444-8444-444444444444")
    let outbox = try NativeDeviceAuditOutbox(rootPath: root.path)
    _ = try outbox.enqueue(event)
    let substituted = try outboxEvent("44444444-4444-4444-8444-444444444444", previousHash: String(repeating: "b", count: 64))
    #expect(throws: AgentPassNativeError.self) { try outbox.enqueue(substituted) }
    let unknown = NativeDeviceAuditIngestionResponse(deviceID: "55555555-5555-4555-8555-555555555555", acceptedEventIDs: ["66666666-6666-4666-8666-666666666666"], duplicateEventIDs: [], gapCount: 0, headHash: event.eventHash, headEventID: event.eventID, chainStatus: "continuous")
    #expect(throws: AgentPassNativeError.self) { try outbox.acknowledge(unknown) }
    #expect(try outbox.pending() == [event])
}

@Test("device audit outbox removes only accepted and duplicate IDs")
func deviceAuditOutboxAcknowledgesExactly() throws {
    let root = try outboxRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let first = try outboxEvent("77777777-7777-4777-8777-777777777777")
    let second = try outboxEvent("88888888-8888-4888-8888-888888888888", previousHash: first.eventHash)
    let outbox = try NativeDeviceAuditOutbox(rootPath: root.path)
    _ = try outbox.enqueue(first)
    _ = try outbox.enqueue(second)
    let response = NativeDeviceAuditIngestionResponse(deviceID: "22222222-2222-4222-8222-222222222222", acceptedEventIDs: [first.eventID], duplicateEventIDs: [], gapCount: 0, headHash: first.eventHash, headEventID: first.eventID, chainStatus: "continuous")
    try outbox.acknowledge(response)
    #expect(try outbox.pending() == [second])
    let restarted = try NativeDeviceAuditOutbox(rootPath: root.path)
    #expect(try restarted.pending() == [second])
}
