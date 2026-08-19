import AgentPassNativeCore
import Foundation
import Testing

private let projectionAgentID = "11111111-1111-4111-8111-111111111111"
private let projectionDeviceID = "22222222-2222-4222-8222-222222222222"
private let projectionSessionID = "33333333-3333-4333-8333-333333333333"

private func activationProjection(
    _ activation: NativeAgentHostQualifiedSessionActivation
) -> (sessionID: String, agentID: String, deviceID: String) {
    (
        activation.sessionID,
        activation.binding.agentID,
        activation.binding.deviceID
    )
}

@Test func hostActivationProjectionContainsOnlyServiceAssignedIdentity() throws {
    let activation = try NativeAgentHostQualifiedSessionActivation(
        sessionID: projectionSessionID,
        binding: try NativeAgentSessionBinding(
            agentID: projectionAgentID,
            deviceID: projectionDeviceID,
            processBindingDigest: Data(repeating: 0x11, count: 32),
            ancestryBindingDigest: Data(repeating: 0x22, count: 32),
            worktreeBindingDigest: Data(repeating: 0x33, count: 32),
            controlSequence: 7,
            authorityGeneration: 8,
            keyGeneration: 9
        )
    )

    #expect(activationProjection(activation).sessionID == projectionSessionID)
    #expect(activationProjection(activation).agentID == projectionAgentID)
    #expect(activationProjection(activation).deviceID == projectionDeviceID)

    // The Host lifecycle projection deliberately excludes binding proofs,
    // process/worktree digests, counters, and other authority material.
    let labels = Set(Mirror(reflecting: activationProjection(activation)).children.compactMap(\.label))
    #expect(labels == ["sessionID", "agentID", "deviceID"])
}
