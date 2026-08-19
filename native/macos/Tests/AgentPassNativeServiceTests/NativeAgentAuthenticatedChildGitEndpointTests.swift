import AgentPassNativeService
import Foundation
import Testing
@testable import AgentPassNativeCore

private func childBudget(maxSignatures: Int = 2, usedSignatures: Int = 0) -> NativeAgentSignatureBudgetLedger {
    NativeAgentSignatureBudgetLedger(try! NativeAgentSignatureBudget(maxSignatures: maxSignatures, usedSignatures: usedSignatures))
}

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

private func childHelperIdentity(for child: NativeProcessIdentity) throws -> NativeProcessIdentity {
    let facts = try NativeObservedProcessFacts(
        uid: child.uid,
        pid: child.pid + 1,
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

private func issueChildTicket(
    _ registry: NativeAgentAuthenticatedChildGitSessionRegistry,
    child: NativeProcessIdentity,
    helper: NativeProcessIdentity,
    worktree: Data
) throws -> Data {
    try registry.issueAttachTicket(
        helperIdentity: helper,
        worktreeBindingDigest: worktree,
        nowMilliseconds: 1_000
    ).value
}

@Test func childRegistryRequiresTheRegisteredIdentityAndConsumesInOrder() throws {
    let identity = NativeProcessIdentity(observation: try childTestObservation())
    let helper = try childHelperIdentity(for: identity)
    let registry = NativeAgentAuthenticatedChildGitSessionRegistry()
    let signer = NativeAgentAuthenticatedChildClosureSigner { payload in
        Data(payload.reversed())
    }
    let worktreeDigest = Data(repeating: 0x31, count: 32)
    try registry.register(
        sessionID: "session-1",
        identity: identity,
        worktreeBindingDigest: worktreeDigest,
        signer: signer,
        signatureBudget: childBudget()
    )
    let ticket = try issueChildTicket(registry, child: identity, helper: helper, worktree: worktreeDigest)
    let request = try #require(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data([1, 2, 3]), attachTicket: ticket))
    let result = try registry.sign(attachTicket: ticket, helperIdentity: helper, worktreeBindingDigest: worktreeDigest, request: request, nowMilliseconds: 1_000)
    #expect(result.signature == Data([3, 2, 1]))
    #expect(result.budget.remainingSignatures == 1)
}

@Test func childTicketExpiryFailsClosed() throws {
    let identity = NativeProcessIdentity(observation: try childTestObservation())
    let helper = try childHelperIdentity(for: identity)
    let registry = NativeAgentAuthenticatedChildGitSessionRegistry()
    let worktree = Data(repeating: 0x32, count: 32)
    try registry.register(
        sessionID: "session-ticket-expiry",
        identity: identity,
        worktreeBindingDigest: worktree,
        signer: NativeAgentAuthenticatedChildClosureSigner { $0 },
        signatureBudget: childBudget(),
        expiresAtMilliseconds: 60_000,
        nowMilliseconds: 1_000
    )

    let ticket = try registry.issueAttachTicket(
        helperIdentity: helper,
        worktreeBindingDigest: worktree,
        nowMilliseconds: 1_000
    ).value
    let request = try #require(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data([1]), attachTicket: ticket))
    #expect(throws: NativeAgentAuthenticatedChildGitError.attachTicketExpired) {
        _ = try registry.sign(
            attachTicket: ticket,
            helperIdentity: helper,
            worktreeBindingDigest: worktree,
            request: request,
            nowMilliseconds: 31_001
        )
    }

    #expect(throws: NativeAgentAuthenticatedChildGitError.closed) {
        _ = try registry.issueAttachTicket(
            helperIdentity: helper,
            worktreeBindingDigest: worktree,
            nowMilliseconds: 32_000
        )
    }
}

@Test func childSessionCanIssueAFreshTicketAfterTheTicketLifetime() throws {
    let identity = NativeProcessIdentity(observation: try childTestObservation())
    let helper = try childHelperIdentity(for: identity)
    let registry = NativeAgentAuthenticatedChildGitSessionRegistry()
    let worktree = Data(repeating: 0x33, count: 32)
    try registry.register(
        sessionID: "session-ticket-renewal",
        identity: identity,
        worktreeBindingDigest: worktree,
        signer: NativeAgentAuthenticatedChildClosureSigner { $0 },
        signatureBudget: childBudget(maxSignatures: 2)
    )

    let firstTicket = try registry.issueAttachTicket(
        helperIdentity: helper,
        worktreeBindingDigest: worktree,
        nowMilliseconds: 1_000
    ).value
    let firstRequest = try #require(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data([1]), attachTicket: firstTicket))
    _ = try registry.sign(
        attachTicket: firstTicket,
        helperIdentity: helper,
        worktreeBindingDigest: worktree,
        request: firstRequest,
        nowMilliseconds: 1_000
    )

    let secondTicket = try registry.issueAttachTicket(
        helperIdentity: helper,
        worktreeBindingDigest: worktree,
        nowMilliseconds: 32_000
    ).value
    #expect(secondTicket != firstTicket)
}

@Test func childRegistryClosesOnWorktreeDriftAndRejectsReplay() throws {
    let identity = NativeProcessIdentity(observation: try childTestObservation())
    let helper = try childHelperIdentity(for: identity)
    let registry = NativeAgentAuthenticatedChildGitSessionRegistry()
    try registry.register(
        sessionID: "session-2",
        identity: identity,
        worktreeBindingDigest: Data(repeating: 0x41, count: 32),
        signer: NativeAgentAuthenticatedChildClosureSigner { $0 },
        signatureBudget: childBudget()
    )
    let worktree = Data(repeating: 0x41, count: 32)
    let ticket = try issueChildTicket(registry, child: identity, helper: helper, worktree: worktree)
    let request = try #require(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data([8]), attachTicket: ticket))
    #expect(throws: NativeAgentAuthenticatedChildGitError.worktreeChanged) {
        _ = try registry.sign(attachTicket: ticket, helperIdentity: helper, worktreeBindingDigest: Data(repeating: 0x42, count: 32), request: request, nowMilliseconds: 1_000)
    }
    #expect(throws: NativeAgentAuthenticatedChildGitError.closed) {
        _ = try registry.sign(attachTicket: ticket, helperIdentity: helper, worktreeBindingDigest: worktree, request: request, nowMilliseconds: 1_000)
    }
}

@Test func childRegistryRejectsARepeatedPayloadAsReplay() throws {
    let identity = NativeProcessIdentity(observation: try childTestObservation())
    let helper = try childHelperIdentity(for: identity)
    let registry = NativeAgentAuthenticatedChildGitSessionRegistry()
    try registry.register(
        sessionID: "session-replay",
        identity: identity,
        worktreeBindingDigest: Data(repeating: 0x61, count: 32),
        signer: NativeAgentAuthenticatedChildClosureSigner { $0 },
        signatureBudget: childBudget()
    )
    let worktree = Data(repeating: 0x61, count: 32)
    let ticket = try issueChildTicket(registry, child: identity, helper: helper, worktree: worktree)
    let request = try #require(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data([7, 7, 7]), attachTicket: ticket))

    _ = try registry.sign(
        attachTicket: ticket,
        helperIdentity: helper,
        worktreeBindingDigest: worktree,
        request: request,
        nowMilliseconds: 1_000
    )
    #expect(throws: NativeAgentAuthenticatedChildGitError.attachTicketReplay) {
        _ = try registry.sign(
            attachTicket: ticket,
            helperIdentity: helper,
            worktreeBindingDigest: worktree,
            request: request,
            nowMilliseconds: 1_000
        )
    }
    #expect(throws: NativeAgentAuthenticatedChildGitError.attachTicketReplay) {
        _ = try registry.sign(
            attachTicket: ticket,
            helperIdentity: helper,
            worktreeBindingDigest: worktree,
            request: request,
            nowMilliseconds: 1_000
        )
    }
}

@Test func childRegistryClosesWhenSignerFails() throws {
    let identity = NativeProcessIdentity(observation: try childTestObservation())
    let helper = try childHelperIdentity(for: identity)
    let registry = NativeAgentAuthenticatedChildGitSessionRegistry()
    try registry.register(
        sessionID: "session-3",
        identity: identity,
        worktreeBindingDigest: Data(repeating: 0x51, count: 32),
        signer: NativeAgentAuthenticatedChildClosureSigner { _ in
            throw NativeAgentAuthenticatedChildGitError.signerFailed
        },
        signatureBudget: childBudget()
    )
    let worktree = Data(repeating: 0x51, count: 32)
    let ticket = try issueChildTicket(registry, child: identity, helper: helper, worktree: worktree)
    let request = try #require(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data([9]), attachTicket: ticket))
    #expect(throws: NativeAgentAuthenticatedChildGitError.signerFailed) {
        _ = try registry.sign(attachTicket: ticket, helperIdentity: helper, worktreeBindingDigest: worktree, request: request, nowMilliseconds: 1_000)
    }
    #expect(throws: NativeAgentAuthenticatedChildGitError.closed) {
        _ = try registry.sign(attachTicket: ticket, helperIdentity: helper, worktreeBindingDigest: worktree, request: request, nowMilliseconds: 1_000)
    }
}
