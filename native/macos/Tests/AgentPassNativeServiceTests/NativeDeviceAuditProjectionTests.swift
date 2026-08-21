import AgentPassNativeCore
import Foundation
import Testing
@testable import AgentPassNativeService

private let projectionRequestID = "11111111-1111-4111-8111-111111111111"
private let projectionAgentID = "22222222-2222-4222-8222-222222222222"
private let projectionDigest = String(repeating: "a", count: 64)
private let projectionPreviousHash = String(repeating: "0", count: 64)

private func projectionEvent(
    decision: String = "deny",
    reason: String? = "branch denied: 日本語の診断詳細"
) -> NativeAuditEvent {
    NativeAuditEvent(
        operation: "git.commit.sign",
        decision: decision,
        requestID: projectionRequestID,
        reason: reason,
        agentID: projectionAgentID,
        repository: "/work/repository",
        branch: "refs/heads/main",
        remote: "origin",
        payloadSHA256: projectionDigest
    )
}

@Test("device audit projection maps localized deny text to a stable Cloud reason")
func deviceAuditProjectionRedactsLocalizedReason() throws {
    let projected = try #require(
        NativeServiceDeviceAuditProjection.project(
            local: projectionEvent(),
            eventID: "33333333-3333-4333-8333-333333333333",
            policySequence: 7,
            capabilitySequence: 11,
            deviceTimestamp: "2026-08-20T05:00:00.000Z",
            previousHash: projectionPreviousHash
        )
    )

    #expect(projected.reason == "branch_denied")
    #expect(projected.decision == "deny")
    #expect(try String(decoding: projected.canonicalData(), as: UTF8.self).contains("日本語") == false)
}

@Test("device audit projection uses signer_failed for an unmapped error and keeps allow canonical")
func deviceAuditProjectionUsesClosedReasons() throws {
    let error = try #require(
        NativeServiceDeviceAuditProjection.project(
            local: projectionEvent(decision: "error", reason: "The Secure Enclave returned a localized failure"),
            eventID: "44444444-4444-4444-8444-444444444444",
            policySequence: 1,
            capabilitySequence: 2,
            deviceTimestamp: "2026-08-20T05:00:00.000Z",
            previousHash: projectionPreviousHash
        )
    )
    #expect(error.reason == "signer_failed")

    let allowed = try #require(
        NativeServiceDeviceAuditProjection.project(
            local: projectionEvent(decision: "allow", reason: "authorized_intent"),
            eventID: "55555555-5555-4555-8555-555555555555",
            policySequence: 1,
            capabilitySequence: 2,
            deviceTimestamp: "2026-08-20T05:00:00.000Z",
            previousHash: projectionPreviousHash
        )
    )
    #expect(allowed.reason == "allowed")
}

@Test("device audit projection fails safe to local-only when a required field is absent")
func deviceAuditProjectionDoesNotInventRequiredFields() {
    let missingPayload = NativeAuditEvent(
        operation: "git.commit.sign",
        decision: "error",
        requestID: projectionRequestID,
        reason: "signer failed",
        agentID: projectionAgentID,
        repository: "/work/repository",
        branch: "refs/heads/main",
        remote: "origin"
    )
    #expect(
        NativeServiceDeviceAuditProjection.project(
            local: missingPayload,
            eventID: "66666666-6666-4666-8666-666666666666",
            policySequence: 1,
            capabilitySequence: 2,
            deviceTimestamp: "2026-08-20T05:00:00.000Z",
            previousHash: projectionPreviousHash
        ) == nil
    )
}
