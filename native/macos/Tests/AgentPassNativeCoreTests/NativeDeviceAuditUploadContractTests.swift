import Foundation
import Testing
@testable import AgentPassNativeCore

private let auditEventID = "11111111-1111-4111-8111-111111111111"
private let auditRequestID = "22222222-2222-4222-8222-222222222222"
private let auditAgentID = "33333333-3333-4333-8333-333333333333"

private func uploadEvent(decision: String = "allow", reason: String = "allowed") throws -> NativeDeviceAuditEvent {
    try NativeDeviceAuditEvent(
        eventID: auditEventID,
        requestID: auditRequestID,
        agentID: auditAgentID,
        decision: decision,
        reason: reason,
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

@Test("device audit event canonicalization computes and verifies the Cloud chain hash")
func deviceAuditEventCanonicalization() throws {
    let event = try uploadEvent()
    let data = try event.canonicalData()
    let decoded = try NativeDeviceAuditEvent.decode(data)
    #expect(decoded == event)
    #expect(event.eventHash.count == 64)
    #expect(try NativeDeviceAuditEvent.decode(data).unsignedCanonicalData() == event.unsignedCanonicalData())
}

@Test("device audit event rejects hash, decision/reason, and unknown-field substitutions")
func deviceAuditEventRejectsSubstitutions() throws {
    let event = try uploadEvent()
    var object = try #require(JSONSerialization.jsonObject(with: event.canonicalData()) as? [String: Any])
    object["event_hash"] = String(repeating: "b", count: 64)
    #expect(throws: NativeDeviceSyncContractError.self) { try NativeDeviceAuditEvent.decode(try JSONSerialization.data(withJSONObject: object)) }

    object = try #require(JSONSerialization.jsonObject(with: event.canonicalData()) as? [String: Any])
    object["decision"] = "deny"
    object["unexpected"] = true
    #expect(throws: NativeDeviceSyncContractError.self) { try NativeDeviceAuditEvent.decode(try JSONSerialization.data(withJSONObject: object)) }
}

@Test("device audit batch is bounded, canonical, and UUID-bound")
func deviceAuditBatchIsBounded() throws {
    let event = try uploadEvent()
    let batch = try NativeDeviceAuditBatch(batchID: "44444444-4444-4444-8444-444444444444", events: [event])
    let object = try #require(JSONSerialization.jsonObject(with: batch.canonicalData()) as? [String: Any])
    #expect(object.keys.sorted() == ["batch_id", "events"])
    #expect((object["events"] as? [[String: Any]])?.count == 1)
    #expect(throws: NativeDeviceSyncContractError.self) { try NativeDeviceAuditBatch(batchID: "not-a-uuid", events: [event]) }
}
