import AgentPassNativeService
import Foundation
import Testing
@testable import AgentPassNativeCore

private final class ChildSignerCallCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0

    func increment() {
        lock.lock()
        value += 1
        lock.unlock()
    }

    func read() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

private func adversarialChildObservation(
    codeDirectoryHash: String = String(repeating: "a", count: 64),
    pidVersion: UInt64 = 9
) throws -> NativeProcessObservation {
    let facts = try NativeObservedProcessFacts(
        uid: 501,
        pid: 42,
        pidVersion: pidVersion,
        bootIdentity: "child-adversarial-boot",
        executableFileIdentity: try NativeExecutableFileIdentity(
            deviceID: 1,
            inode: 2,
            fileSize: 3,
            modificationTimeNanoseconds: 4
        ),
        codeDirectoryHash: codeDirectoryHash,
        bundleIdentifier: "dev.agentpass.git-sign-xpc",
        teamIdentifier: "ABCDE12345",
        signatureKind: .developerID,
        entitlements: [:]
    )
    return try NativeProcessObservation(process: facts, ancestry: [])
}

private func adversarialRequest(_ sequence: UInt32 = 1, _ byte: UInt8) throws -> AgentPassChildGitSignRequest {
    try #require(AgentPassChildGitSignRequest(requestSequence: sequence, commitPayload: Data([byte])))
}

@Test func childRegistryDeniesPIDGenerationAndCodeIdentitySubstitution() throws {
    let registered = NativeProcessIdentity(observation: try adversarialChildObservation())
    let pidReused = NativeProcessIdentity(observation: try adversarialChildObservation(pidVersion: 10))
    let codeReplaced = NativeProcessIdentity(observation: try adversarialChildObservation(codeDirectoryHash: String(repeating: "b", count: 64)))
    let registry = NativeAgentAuthenticatedChildGitSessionRegistry()
    let worktree = Data(repeating: 0x21, count: AgentPassHostXPCContract.digestBytes)
    try registry.register(
        sessionID: "44444444-4444-4444-8444-444444444444",
        identity: registered,
        worktreeBindingDigest: worktree,
        signer: NativeAgentAuthenticatedChildClosureSigner { _ in Data([1]) }
    )

    #expect(throws: NativeAgentAuthenticatedChildGitError.childNotRegistered) {
        _ = try registry.sign(identity: pidReused, worktreeBindingDigest: worktree, request: try adversarialRequest(1, 1))
    }
    #expect(throws: NativeAgentAuthenticatedChildGitError.childNotRegistered) {
        _ = try registry.sign(identity: codeReplaced, worktreeBindingDigest: worktree, request: try adversarialRequest(1, 2))
    }
    #expect(try registry.sign(identity: registered, worktreeBindingDigest: worktree, request: try adversarialRequest(1, 3)).signature == Data([1]))
}

@Test func childRegistryClosesOnSequenceSkipAndDoesNotReopenWithAValidSequence() throws {
    let identity = NativeProcessIdentity(observation: try adversarialChildObservation())
    let registry = NativeAgentAuthenticatedChildGitSessionRegistry()
    let worktree = Data(repeating: 0x22, count: AgentPassHostXPCContract.digestBytes)
    try registry.register(
        sessionID: "55555555-5555-4555-8555-555555555555",
        identity: identity,
        worktreeBindingDigest: worktree,
        signer: NativeAgentAuthenticatedChildClosureSigner { _ in Data([2]) }
    )

    #expect(throws: NativeAgentAuthenticatedChildGitError.sequenceMismatch) {
        _ = try registry.sign(identity: identity, worktreeBindingDigest: worktree, request: try adversarialRequest(2, 1))
    }
    #expect(throws: NativeAgentAuthenticatedChildGitError.closed) {
        _ = try registry.sign(identity: identity, worktreeBindingDigest: worktree, request: try adversarialRequest(1, 2))
    }
}

@Test func childRegistryEnforcesTheTwoRequestBudgetAcrossDistinctPayloads() throws {
    let identity = NativeProcessIdentity(observation: try adversarialChildObservation())
    let registry = NativeAgentAuthenticatedChildGitSessionRegistry()
    let worktree = Data(repeating: 0x23, count: AgentPassHostXPCContract.digestBytes)
    try registry.register(
        sessionID: "66666666-6666-4666-8666-666666666666",
        identity: identity,
        worktreeBindingDigest: worktree,
        signer: NativeAgentAuthenticatedChildClosureSigner { payload in payload }
    )

    #expect(try registry.sign(identity: identity, worktreeBindingDigest: worktree, request: try adversarialRequest(1, 3)).remaining == 1)
    #expect(try registry.sign(identity: identity, worktreeBindingDigest: worktree, request: try adversarialRequest(1, 4)).remaining == 0)
    #expect(throws: NativeAgentAuthenticatedChildGitError.closed) {
        _ = try registry.sign(identity: identity, worktreeBindingDigest: worktree, request: try adversarialRequest(1, 5))
    }
}

@Test func childEndpointResponseLossCannotBeRetriedOnTheSameConnection() throws {
    let identity = NativeProcessIdentity(observation: try adversarialChildObservation())
    let registry = NativeAgentAuthenticatedChildGitSessionRegistry()
    let worktree = Data(repeating: 0x24, count: AgentPassHostXPCContract.digestBytes)
    let signerCalls = ChildSignerCallCounter()
    try registry.register(
        sessionID: "77777777-7777-4777-8777-777777777777",
        identity: identity,
        worktreeBindingDigest: worktree,
        signer: NativeAgentAuthenticatedChildClosureSigner { _ in
            signerCalls.increment()
            return Data([9])
        }
    )
    let endpoint = NativeAgentAuthenticatedChildGitEndpoint(
        registry: registry,
        identityObserver: { identity },
        worktreeDigestObserver: { worktree }
    )
    let request = try adversarialRequest(1, 9)

    endpoint.signChildGitCommit(request) { _, _ in
        // Deliberately drop the first reply to model XPC response loss.
    }
    #expect(signerCalls.read() == 1)

    var error: NSError?
    endpoint.signChildGitCommit(request) { _, responseError in error = responseError }
    #expect(error?.userInfo[NSLocalizedDescriptionKey] as? String == NativeAgentAuthenticatedChildGitError.replay.rawValue)
    #expect(signerCalls.read() == 1)
}
