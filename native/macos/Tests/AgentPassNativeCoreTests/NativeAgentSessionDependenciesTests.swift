import Foundation
import Testing
@testable import AgentPassNativeCore

private let dependencyAgentID = "11111111-1111-4111-8111-111111111111"
private let dependencyDeviceID = "22222222-2222-4222-8222-222222222222"
private let dependencyBootstrapID = "66666666-6666-4666-8666-666666666666"

private func dependencyBinding() throws -> NativeAgentSessionBinding {
    try NativeAgentSessionBinding(
        agentID: dependencyAgentID,
        deviceID: dependencyDeviceID,
        processBindingDigest: Data(repeating: 1, count: 32),
        ancestryBindingDigest: Data(repeating: 2, count: 32),
        worktreeBindingDigest: Data(repeating: 3, count: 32),
        controlSequence: 7,
        authorityGeneration: 8,
        keyGeneration: 9
    )
}

@Test func sessionBindingRejectsCallerShapedOrIncompleteAuthority() throws {
    let binding = try dependencyBinding()
    #expect(binding.agentID == dependencyAgentID)
    #expect(binding.controlSequence == 7)

    #expect(throws: NativeAgentSessionBoundaryError.invalidIdentity) {
        _ = try NativeAgentSessionBinding(agentID: "agent", deviceID: dependencyDeviceID, processBindingDigest: Data(repeating: 1, count: 32), ancestryBindingDigest: Data(repeating: 2, count: 32), worktreeBindingDigest: Data(repeating: 3, count: 32), controlSequence: 1, authorityGeneration: 1, keyGeneration: 1)
    }
    #expect(throws: NativeAgentSessionBoundaryError.invalidDigest) {
        _ = try NativeAgentSessionBinding(agentID: dependencyAgentID, deviceID: dependencyDeviceID, processBindingDigest: Data(repeating: 1, count: 31), ancestryBindingDigest: Data(repeating: 2, count: 32), worktreeBindingDigest: Data(repeating: 3, count: 32), controlSequence: 1, authorityGeneration: 1, keyGeneration: 1)
    }
    #expect(throws: NativeAgentSessionBoundaryError.invalidGeneration) {
        _ = try NativeAgentSessionBinding(agentID: dependencyAgentID, deviceID: dependencyDeviceID, processBindingDigest: Data(repeating: 1, count: 32), ancestryBindingDigest: Data(repeating: 2, count: 32), worktreeBindingDigest: Data(repeating: 3, count: 32), controlSequence: 0, authorityGeneration: 1, keyGeneration: 1)
    }
}

@Test func grantConsumptionRequestBoundsTransientProof() throws {
    let binding = try dependencyBinding()
    let request = try NativeAgentGrantConsumptionRequest(bootstrapID: dependencyBootstrapID, proof: Data(repeating: 4, count: 16), binding: binding)
    #expect(request.proof.count == 16)
    #expect(throws: NativeAgentSessionBoundaryError.invalidBootstrapProof) {
        _ = try NativeAgentGrantConsumptionRequest(bootstrapID: dependencyBootstrapID, proof: Data(repeating: 4, count: 15), binding: binding)
    }
    #expect(throws: NativeAgentSessionBoundaryError.invalidBootstrapProof) {
        _ = try NativeAgentGrantConsumptionRequest(bootstrapID: dependencyBootstrapID, proof: Data(repeating: 4, count: 4_097), binding: binding)
    }
}

@Test func auditEvidenceAllowsOnlyUUIDsDigestsAndStableReasonCodes() throws {
    let evidence = try NativeAgentSessionAuditEvidence(action: .signingIntent, sessionID: "33333333-3333-4333-8333-333333333333", requestID: "55555555-5555-4555-8555-555555555555", capabilityID: "44444444-4444-4444-8444-444444444444", payloadDigest: Data(repeating: 7, count: 32), binding: dependencyBinding(), reasonCode: "request_reserved")
    #expect(evidence.action == .signingIntent)
    #expect(evidence.reasonCode == "request_reserved")
    #expect(throws: NativeAgentSessionBoundaryError.invalidAuditEvidence) {
        _ = try NativeAgentSessionAuditEvidence(action: .sessionDenied, binding: try dependencyBinding(), reasonCode: "/Users/private/token")
    }
    #expect(throws: NativeAgentSessionBoundaryError.invalidAuditEvidence) {
        _ = try NativeAgentSessionAuditEvidence(action: .signingCompleted, payloadDigest: Data(repeating: 1, count: 31), binding: try dependencyBinding())
    }
}

@Test func agentSessionAuditReceiptBindsCanonicalEvidenceAndDurableRecord() throws {
    let evidence = try NativeAgentSessionAuditEvidence(
        action: .signingIntent,
        sessionID: "33333333-3333-4333-8333-333333333333",
        requestID: "55555555-5555-4555-8555-555555555555",
        capabilityID: "44444444-4444-4444-8444-444444444444",
        payloadDigest: Data(repeating: 7, count: 32),
        binding: dependencyBinding(),
        reasonCode: "request_reserved"
    )
    let digest = try evidence.evidenceDigest()
    #expect(digest.map { String(format: "%02x", $0) }.joined() == "16745baeadd964683c7cfe3560927663a5e2e03e73e0f11bc4fed0e48ed523d3")

    let receipt = try NativeAgentSessionAuditReceipt(
        evidenceDigest: digest,
        recordDigest: Data(repeating: 8, count: 32),
        recordIndex: 42
    )
    #expect(receipt.evidenceDigest == digest)
    #expect(receipt.recordIndex == 42)
    #expect(throws: NativeAgentSessionBoundaryError.invalidAuditEvidence) {
        _ = try NativeAgentSessionAuditReceipt(
            evidenceDigest: Data(repeating: 1, count: 31),
            recordDigest: Data(repeating: 2, count: 32), recordIndex: 1)
    }
    #expect(throws: NativeAgentSessionBoundaryError.invalidAuditEvidence) {
        _ = try NativeAgentSessionAuditReceipt(
            evidenceDigest: digest,
            recordDigest: Data(repeating: 2, count: 32), recordIndex: 0)
    }
}

@Test func fixedSignerProtocolHasNoOperationOrKeySelectionParameters() throws {
    final class Signer: NativeAgentGitCommitSigning, @unchecked Sendable {
        func signGitCommitPayload(_ payload: Data) throws -> Data { Data(payload.reversed()) }
    }
    let signer = Signer()
    #expect(try signer.signGitCommitPayload(Data([1, 2, 3])) == Data([3, 2, 1]))
}
