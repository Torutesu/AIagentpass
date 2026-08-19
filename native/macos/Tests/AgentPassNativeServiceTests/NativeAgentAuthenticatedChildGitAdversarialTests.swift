import AgentPassNativeService
import Foundation
import Testing
@testable import AgentPassNativeCore

private func adversarialChildBudget(maxSignatures: Int = 2, usedSignatures: Int = 0) -> NativeAgentSignatureBudgetLedger {
    NativeAgentSignatureBudgetLedger(try! NativeAgentSignatureBudget(maxSignatures: maxSignatures, usedSignatures: usedSignatures))
}

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
    try #require(AgentPassChildGitSignRequest(requestSequence: sequence, commitPayload: Data([byte]), attachTicket: Data(repeating: 0x71, count: AgentPassChildGitXPCContract.attachTicketBytes)))
}

private func adversarialHelperIdentity(for child: NativeProcessIdentity, pid: Int32 = 43) throws -> NativeProcessIdentity {
    let facts = try NativeObservedProcessFacts(
        uid: child.uid,
        pid: pid,
        pidVersion: child.pidVersion + 1,
        bootIdentity: child.bootIdentity,
        executableFileIdentity: child.executableFileIdentity,
        codeDirectoryHash: child.codeDirectoryHash,
        bundleIdentifier: "dev.agentpass.git-sign-xpc",
        teamIdentifier: child.teamIdentifier,
        signatureKind: child.signatureKind,
        entitlements: child.entitlements
    )
    return NativeProcessIdentity(observation: try NativeProcessObservation(process: facts, ancestry: [.observed(child.process)]))
}

private func issueAdversarialTicket(
    _ registry: NativeAgentAuthenticatedChildGitSessionRegistry,
    child: NativeProcessIdentity,
    helper: NativeProcessIdentity,
    worktree: Data
) throws -> Data {
    try registry.issueAttachTicket(helperIdentity: helper, worktreeBindingDigest: worktree, nowMilliseconds: 1_000).value
}

@Test func childRegistryDeniesPIDGenerationAndCodeIdentitySubstitution() throws {
    let registered = NativeProcessIdentity(observation: try adversarialChildObservation())
    let helper = try adversarialHelperIdentity(for: registered)
    let pidReused = NativeProcessIdentity(observation: try adversarialChildObservation(pidVersion: 10))
    let codeReplaced = NativeProcessIdentity(observation: try adversarialChildObservation(codeDirectoryHash: String(repeating: "b", count: 64)))
    let registry = NativeAgentAuthenticatedChildGitSessionRegistry()
    let worktree = Data(repeating: 0x21, count: AgentPassHostXPCContract.digestBytes)
    try registry.register(
        sessionID: "44444444-4444-4444-8444-444444444444",
        identity: registered,
        worktreeBindingDigest: worktree,
        signer: NativeAgentAuthenticatedChildClosureSigner { _ in Data([1]) },
        signatureBudget: adversarialChildBudget()
    )
    let ticket = try issueAdversarialTicket(registry, child: registered, helper: helper, worktree: worktree)
    let registeredRequest = try #require(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data([3]), attachTicket: ticket))

    #expect(throws: NativeAgentAuthenticatedChildGitError.childIdentityChanged) {
        _ = try registry.sign(attachTicket: ticket, helperIdentity: adversarialHelperIdentity(for: pidReused), worktreeBindingDigest: worktree, request: registeredRequest, nowMilliseconds: 1_000)
    }
    #expect(throws: NativeAgentAuthenticatedChildGitError.closed) {
        _ = try registry.sign(attachTicket: ticket, helperIdentity: adversarialHelperIdentity(for: codeReplaced, pid: 44), worktreeBindingDigest: worktree, request: registeredRequest, nowMilliseconds: 1_000)
    }
}

@Test func childRegistryClosesOnSequenceSkipAndDoesNotReopenWithAValidSequence() throws {
    let identity = NativeProcessIdentity(observation: try adversarialChildObservation())
    let helper = try adversarialHelperIdentity(for: identity)
    let registry = NativeAgentAuthenticatedChildGitSessionRegistry()
    let worktree = Data(repeating: 0x22, count: AgentPassHostXPCContract.digestBytes)
    try registry.register(
        sessionID: "55555555-5555-4555-8555-555555555555",
        identity: identity,
        worktreeBindingDigest: worktree,
        signer: NativeAgentAuthenticatedChildClosureSigner { _ in Data([2]) },
        signatureBudget: adversarialChildBudget()
    )
    let ticket = try issueAdversarialTicket(registry, child: identity, helper: helper, worktree: worktree)

    #expect(throws: NativeAgentAuthenticatedChildGitError.sequenceMismatch) {
        _ = try registry.sign(attachTicket: ticket, helperIdentity: helper, worktreeBindingDigest: worktree, request: try #require(AgentPassChildGitSignRequest(requestSequence: 2, commitPayload: Data([1]), attachTicket: ticket)), nowMilliseconds: 1_000)
    }
    #expect(throws: NativeAgentAuthenticatedChildGitError.closed) {
        _ = try registry.sign(attachTicket: ticket, helperIdentity: helper, worktreeBindingDigest: worktree, request: try #require(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data([2]), attachTicket: ticket)), nowMilliseconds: 1_000)
    }
}

@Test func childRegistryUsesTheAuthoritativeBudgetAcrossDistinctPayloads() throws {
    let identity = NativeProcessIdentity(observation: try adversarialChildObservation())
    let helper = try adversarialHelperIdentity(for: identity)
    let registry = NativeAgentAuthenticatedChildGitSessionRegistry()
    let worktree = Data(repeating: 0x23, count: AgentPassHostXPCContract.digestBytes)
    try registry.register(
        sessionID: "66666666-6666-4666-8666-666666666666",
        identity: identity,
        worktreeBindingDigest: worktree,
        signer: NativeAgentAuthenticatedChildClosureSigner { payload in payload },
        signatureBudget: adversarialChildBudget(maxSignatures: 5, usedSignatures: 3)
    )

    let firstTicket = try issueAdversarialTicket(registry, child: identity, helper: helper, worktree: worktree)
    #expect(try registry.sign(attachTicket: firstTicket, helperIdentity: helper, worktreeBindingDigest: worktree, request: try #require(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data([3]), attachTicket: firstTicket)), nowMilliseconds: 1_000).budget.remainingSignatures == 1)
    let secondTicket = try issueAdversarialTicket(registry, child: identity, helper: helper, worktree: worktree)
    #expect(try registry.sign(attachTicket: secondTicket, helperIdentity: helper, worktreeBindingDigest: worktree, request: try #require(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data([4]), attachTicket: secondTicket)), nowMilliseconds: 1_000).budget.remainingSignatures == 0)
    #expect(throws: NativeAgentAuthenticatedChildGitError.closed) {
        _ = try registry.sign(attachTicket: secondTicket, helperIdentity: helper, worktreeBindingDigest: worktree, request: try #require(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data([5]), attachTicket: secondTicket)), nowMilliseconds: 1_000)
    }
}

@Test func childEndpointResponseLossCannotBeRetriedOnTheSameConnection() throws {
    let identity = NativeProcessIdentity(observation: try adversarialChildObservation())
    let helper = try adversarialHelperIdentity(for: identity)
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
        },
        signatureBudget: adversarialChildBudget()
    )
    let endpoint = NativeAgentAuthenticatedChildGitEndpoint(
        registry: registry,
        identityObserver: { helper },
        worktreeDigestObserver: { worktree },
        nowMilliseconds: { 1_000 }
    )
    var attachedTicket: Data?
    endpoint.attachChildGit(try #require(AgentPassChildGitAttachRequest())) { response, _ in
        attachedTicket = response?.attachTicket
    }
    let ticket = try #require(attachedTicket)
    let request = try #require(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data([9]), attachTicket: ticket))

    endpoint.signChildGitCommit(request) { _, _ in
        // Deliberately drop the first reply to model XPC response loss.
    }
    #expect(signerCalls.read() == 1)

    var error: NSError?
    endpoint.signChildGitCommit(request) { _, responseError in error = responseError }
    #expect(error?.userInfo[NSLocalizedDescriptionKey] as? String == NativeAgentAuthenticatedChildGitError.outcomeUnknown.rawValue)
    #expect(signerCalls.read() == 1)
}
