import AgentPassNativeService
import Foundation
import Testing
@testable import AgentPassNativeCore

private func childTestObservation() throws -> NativeProcessObservation {
    let facts = try NativeObservedProcessFacts(
        uid: 501,
        pid: 42,
        pidVersion: 9,
        bootIdentity: "boot-child-test",
        executableFileIdentity: NativeExecutableFileIdentity(deviceID: 1, inode: 2, fileSize: 3, modificationTimeNanoseconds: 4),
        codeDirectoryHash: String(repeating: "a", count: 64),
        bundleIdentifier: "dev.agentpass.child",
        teamIdentifier: "ABCDE12345",
        signatureKind: .developerID,
        entitlements: [:]
    )
    return try NativeProcessObservation(process: facts, ancestry: [])
}

@Test func childRegistryRequiresTheRegisteredIdentityAndConsumesInOrder() throws {
    let identity = NativeProcessIdentity(observation: try childTestObservation())
    let registry = NativeAgentAuthenticatedChildGitSessionRegistry()
    let signer = NativeAgentAuthenticatedChildClosureSigner { payload in
        Data(payload.reversed())
    }
    let worktreeDigest = Data(repeating: 0x31, count: 32)
    try registry.register(
        sessionID: "session-1",
        identity: identity,
        worktreeBindingDigest: worktreeDigest,
        signer: signer
    )
    let request = try #require(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data([1, 2, 3])))
    let result = try registry.sign(identity: identity, worktreeBindingDigest: worktreeDigest, request: request)
    #expect(result.signature == Data([3, 2, 1]))
    #expect(result.remaining == 1)
}

@Test func childRegistryClosesOnWorktreeDriftAndRejectsReplay() throws {
    let identity = NativeProcessIdentity(observation: try childTestObservation())
    let registry = NativeAgentAuthenticatedChildGitSessionRegistry()
    try registry.register(
        sessionID: "session-2",
        identity: identity,
        worktreeBindingDigest: Data(repeating: 0x41, count: 32),
        signer: NativeAgentAuthenticatedChildClosureSigner { $0 }
    )
    let request = try #require(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data([8])))
    #expect(throws: NativeAgentAuthenticatedChildGitError.worktreeChanged) {
        _ = try registry.sign(identity: identity, worktreeBindingDigest: Data(repeating: 0x42, count: 32), request: request)
    }
    #expect(throws: NativeAgentAuthenticatedChildGitError.closed) {
        _ = try registry.sign(identity: identity, worktreeBindingDigest: Data(repeating: 0x41, count: 32), request: request)
    }
}

@Test func childRegistryRejectsARepeatedPayloadAsReplay() throws {
    let identity = NativeProcessIdentity(observation: try childTestObservation())
    let registry = NativeAgentAuthenticatedChildGitSessionRegistry()
    try registry.register(
        sessionID: "session-replay",
        identity: identity,
        worktreeBindingDigest: Data(repeating: 0x61, count: 32),
        signer: NativeAgentAuthenticatedChildClosureSigner { $0 }
    )
    let request = try #require(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data([7, 7, 7])))

    _ = try registry.sign(
        identity: identity,
        worktreeBindingDigest: Data(repeating: 0x61, count: 32),
        request: request
    )
    #expect(throws: NativeAgentAuthenticatedChildGitError.replay) {
        _ = try registry.sign(
            identity: identity,
            worktreeBindingDigest: Data(repeating: 0x61, count: 32),
            request: request
        )
    }
    #expect(throws: NativeAgentAuthenticatedChildGitError.closed) {
        _ = try registry.sign(
            identity: identity,
            worktreeBindingDigest: Data(repeating: 0x61, count: 32),
            request: request
        )
    }
}

@Test func childRegistryClosesWhenSignerFails() throws {
    let identity = NativeProcessIdentity(observation: try childTestObservation())
    let registry = NativeAgentAuthenticatedChildGitSessionRegistry()
    try registry.register(
        sessionID: "session-3",
        identity: identity,
        worktreeBindingDigest: Data(repeating: 0x51, count: 32),
        signer: NativeAgentAuthenticatedChildClosureSigner { _ in
            throw NativeAgentAuthenticatedChildGitError.signerFailed
        }
    )
    let request = try #require(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data([9])))
    #expect(throws: NativeAgentAuthenticatedChildGitError.signerFailed) {
        _ = try registry.sign(identity: identity, worktreeBindingDigest: Data(repeating: 0x51, count: 32), request: request)
    }
    #expect(throws: NativeAgentAuthenticatedChildGitError.closed) {
        _ = try registry.sign(identity: identity, worktreeBindingDigest: Data(repeating: 0x51, count: 32), request: request)
    }
}
