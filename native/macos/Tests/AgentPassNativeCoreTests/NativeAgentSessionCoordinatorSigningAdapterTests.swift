import Foundation
import Testing

@testable import AgentPassNativeCore

private let adapterSessionID = "11111111-1111-4111-8111-111111111111"
private let adapterRequestID = "22222222-2222-4222-8222-222222222222"
private let adapterCapabilityID = "33333333-3333-4333-8333-333333333333"
private let adapterAgentID = "44444444-4444-4444-8444-444444444444"
private let adapterDeviceID = "55555555-5555-4555-8555-555555555555"
private let adapterOrganizationID = "66666666-6666-4666-8666-666666666666"

private struct AdapterHandoffValues {
    let request: AgentPassAgentSignRequest
    let binding: NativeAgentSessionBinding
    let lease: NativeAgentVerifiedCloudLease
    let authority: NativeSigningTransactionAuthority
}

private func adapterHex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

private func adapterCapability(_ capabilityID: String) throws -> Data {
    try NativeStrictJSON.data([
        "version": 1,
        "capability_id": capabilityID,
        "nonce": String(repeating: "N", count: 32),
        "issuer": "agentpass-cloud",
        "key_id": "capability-v1",
        "audience": ["agent_id": adapterAgentID, "device_id": adapterDeviceID],
        "scope": [
            "operations": ["git.commit.sign"],
            "repositories": ["/work/repo"],
            "branches": ["allow": ["feature/native"], "deny": []],
            "remotes": ["allow": ["git@example.test:repo.git"], "deny": []],
        ],
        "not_before": "2026-08-19T02:59:59.000Z",
        "expires_at": "2026-08-19T03:15:00.000Z",
        "sequence": 1,
        "signature": String(repeating: "A", count: 88),
    ])
}

private func adapterRequest(
    sessionID: String = adapterSessionID,
    requestID: String = adapterRequestID,
    capabilityID: String = adapterCapabilityID
) throws -> AgentPassAgentSignRequest {
    try #require(AgentPassAgentSignRequest(
        sessionID: sessionID,
        requestID: requestID,
        capabilityID: capabilityID,
        capability: try adapterCapability(capabilityID),
        commitPayload: Data("commit payload".utf8),
        requestNonce: Data(repeating: 0x2a, count: 16),
        createdAtMilliseconds: 1_787_000_000_000))
}

private func adapterBinding(
    processByte: UInt8 = 0x11,
    worktreeByte: UInt8 = 0x33
) throws -> NativeAgentSessionBinding {
    try NativeAgentSessionBinding(
        agentID: adapterAgentID,
        deviceID: adapterDeviceID,
        processBindingDigest: Data(repeating: processByte, count: 32),
        ancestryBindingDigest: Data(repeating: 0x22, count: 32),
        worktreeBindingDigest: Data(repeating: worktreeByte, count: 32),
        controlSequence: 12,
        authorityGeneration: 7,
        keyGeneration: 9)
}

private func adapterLease(
    binding: NativeAgentSessionBinding,
    sessionID: String = adapterSessionID
) throws -> NativeAgentVerifiedCloudLease {
    try NativeAgentLeaseCodec.decode(
        NativeStrictJSON.data([
            "version": 1,
            "type": "agentpass.agent-session-lease",
            "session_id": sessionID,
            "grant_id": "77777777-7777-4777-8777-777777777777",
            "organization_id": adapterOrganizationID,
            "device_id": adapterDeviceID,
            "agent_id": adapterAgentID,
            "agent_kind": "claude-code",
            "adapter_id": "88888888-8888-4888-8888-888888888888",
            "adapter_version": "1.0.0",
            "process_binding_sha256": adapterHex(binding.processBindingDigest),
            "ancestry_binding_sha256": adapterHex(binding.ancestryBindingDigest),
            "worktree_binding_sha256": adapterHex(binding.worktreeBindingDigest),
            "max_signatures": 2,
            "used_signatures": 0,
            "not_before": "2026-08-19T03:00:00.000Z",
            "expires_at": "2026-08-19T03:15:00.000Z",
            "control_sequence": 12,
            "authority_generation": 7,
        ]),
        expectedBinding: binding)
}

private func adapterWorktree() throws -> NativeAgentWorktreeBinding {
    let repository = try NativeAgentWorktreeDirectoryIdentity(
        device: 1, inode: 20, generation: 1, ownerUserID: 501, permissions: 0o755)
    let git = try NativeAgentWorktreeDirectoryIdentity(
        device: 1, inode: 21, generation: 1, ownerUserID: 501, permissions: 0o755)
    let remote = try NativeAgentGitRemote(name: "origin", url: "git@example.test:repo.git")
    return try NativeAgentWorktreeBinding(
        layout: .embedded,
        repositoryPath: "/work/repo",
        gitDirectoryPath: "/work/repo/.git",
        commonDirectoryPath: "/work/repo/.git",
        repositoryIdentity: repository,
        gitDirectoryIdentity: git,
        commonDirectoryIdentity: git,
        objectFormat: .sha1,
        head: .branch("feature/native"),
        headObjectID: String(repeating: "a", count: 40),
        headTreeID: String(repeating: "b", count: 40),
        remotes: [remote])
}

private func adapterValues(
    sessionID: String = adapterSessionID,
    capabilityID: String = adapterCapabilityID
) throws -> AdapterHandoffValues {
    let request = try adapterRequest(sessionID: sessionID, capabilityID: capabilityID)
    let binding = try adapterBinding()
    let lease = try adapterLease(binding: binding, sessionID: sessionID)
    let authority = try NativeSigningTransactionAuthority(
        request: try NativeSigningTransactionRequest(request),
        binding: binding,
        worktree: try adapterWorktree(),
        keyLifecycleIdentity: String(repeating: "f", count: 64))
    return AdapterHandoffValues(
        request: request, binding: binding, lease: lease, authority: authority)
}

@Test("handoff rejects missing and substituted session capability lease bindings")
func signingHandoffValidationFailsClosed() throws {
    let valid = try adapterValues()
    _ = try NativeAgentSessionCoordinatorSigningHandoff.issue(
        request: valid.request,
        binding: valid.binding,
        lease: valid.lease,
        authority: valid.authority)

    let changedSession = try adapterValues(
        sessionID: "99999999-9999-4999-8999-999999999999")
    #expect(throws: NativeAgentSessionCoordinatorSigningAdapterError.invalidHandoff) {
        _ = try NativeAgentSessionCoordinatorSigningHandoff.issue(
            request: changedSession.request,
            binding: valid.binding,
            lease: valid.lease,
            authority: valid.authority)
    }

    let changedCapability = try adapterValues(
        capabilityID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    #expect(throws: NativeAgentSessionCoordinatorSigningAdapterError.invalidHandoff) {
        _ = try NativeAgentSessionCoordinatorSigningHandoff.issue(
            request: changedCapability.request,
            binding: valid.binding,
            lease: valid.lease,
            authority: valid.authority)
    }

    let changedBinding = try adapterBinding(processByte: 0x44)
    #expect(throws: NativeAgentSessionCoordinatorSigningAdapterError.invalidHandoff) {
        _ = try NativeAgentSessionCoordinatorSigningHandoff.issue(
            request: valid.request,
            binding: changedBinding,
            lease: valid.lease,
            authority: valid.authority)
    }

    let changedLease = try adapterLease(
        binding: valid.binding,
        sessionID: "99999999-9999-4999-8999-999999999999")
    #expect(throws: NativeAgentSessionCoordinatorSigningAdapterError.invalidHandoff) {
        _ = try NativeAgentSessionCoordinatorSigningHandoff.issue(
            request: valid.request,
            binding: valid.binding,
            lease: changedLease,
            authority: valid.authority)
    }
}

@Test("Host and Child payload types cannot supply the handoff authority")
func hostAndChildPayloadsDoNotAppearInTheCoreAuthorityAdapter() throws {
    let testDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    let sourceURL = testDirectory
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent(
            "Sources/AgentPassNativeCore/NativeAgentSessionCoordinatorSigningAdapter.swift")
    let source = try String(contentsOf: sourceURL, encoding: .utf8)

    #expect(source.contains("AgentPassHostSignRequest") == false)
    #expect(source.contains("AgentPassChildGitSignRequest") == false)
    #expect(source.contains("NativeAgentSessionBinding"))
    #expect(source.contains("NativeAgentVerifiedCloudLease"))
    #expect(source.contains("NativeSigningTransactionAuthority"))
    #expect(source.contains("NativeAgentSessionCoordinator"))
    #expect(source.contains("NativeSigningTransactionStore"))
}
