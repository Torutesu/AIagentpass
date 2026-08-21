import Foundation
import CryptoKit
import Testing
@testable import AgentPassNativeCore

private let auditEventID = "11111111-1111-4111-8111-111111111111"
private let auditRequestID = "22222222-2222-4222-8222-222222222222"
private let auditAgentID = "33333333-3333-4333-8333-333333333333"

private func uploadEvent(
    eventID: String = auditEventID,
    previousHash: String = String(repeating: "0", count: 64),
    decision: String = "allow",
    reason: String = "allowed"
) throws -> NativeDeviceAuditEvent {
    try NativeDeviceAuditEvent(
        eventID: eventID,
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
        previousHash: previousHash
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

@Test("device audit batch uses a deterministic content-derived schema batch ID")
func deviceAuditBatchIsBounded() throws {
    let event = try uploadEvent()
    let batch = try NativeDeviceAuditBatch(events: [event])
    let repeated = try NativeDeviceAuditBatch(events: [event])
    #expect(batch.batchID == repeated.batchID)
    #expect(batch.batchID.range(of: "^audit-[0-9a-f]{64}$", options: .regularExpression) != nil)
    #expect(batch.batchID == (try NativeDeviceAuditBatch.batchID(for: [event])))
    let object = try #require(JSONSerialization.jsonObject(with: batch.canonicalData()) as? [String: Any])
    #expect(object.keys.sorted() == ["batch_id", "events"])
    #expect((object["events"] as? [[String: Any]])?.count == 1)
    #expect(throws: NativeDeviceSyncContractError.self) { try NativeDeviceAuditBatch(batchID: "44444444-4444-4444-8444-444444444444", events: [event]) }
}

@Test("device audit batch identity follows canonical event order without hashing its own batch ID")
func deviceAuditBatchIdentityUsesOrderedContent() throws {
    let first = try uploadEvent(eventID: "44444444-4444-4444-8444-444444444444")
    let second = try uploadEvent(eventID: "55555555-5555-4555-8555-555555555555", previousHash: first.eventHash)
    let batch = try NativeDeviceAuditBatch(events: [first, second])
    let content = try NativeStrictJSON.data([
        "events": try [first, second].map { try JSONSerialization.jsonObject(with: $0.canonicalData()) }
    ])
    let expected = "audit-" + Data(SHA256.hash(data: content)).map { String(format: "%02x", $0) }.joined()
    #expect(batch.batchID == expected)
    #expect(batch.batchID != (try NativeDeviceAuditBatch.batchID(for: [first])))
}
