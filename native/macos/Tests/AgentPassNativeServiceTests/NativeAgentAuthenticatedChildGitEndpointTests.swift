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

private final class BlockingChildSigner: @unchecked Sendable {
    let started = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var calls = 0

    var callCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return calls
    }

    func sign(_ payload: Data) -> Data {
        lock.lock()
        calls += 1
        lock.unlock()
        started.signal()
        _ = release.wait(timeout: .now() + 5)
        return Data(payload.reversed())
    }
}

private final class ChildTicketFactory: @unchecked Sendable {
    private let lock = NSLock()
    private var value: UInt8

    init(startingAt value: UInt8) {
        self.value = value
    }

    func make() -> Data {
        lock.lock()
        defer {
            value += 1
            lock.unlock()
        }
        return Data(repeating: value, count: AgentPassChildGitXPCContract.attachTicketBytes)
    }
}

private final class ChildResponseBox: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: AgentPassChildGitSignResponse?

    var value: AgentPassChildGitSignResponse? {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }

    func store(_ response: AgentPassChildGitSignResponse?) {
        lock.lock()
        stored = response
        lock.unlock()
    }
}

private final class FailingAfterAttachIdentityObserver: @unchecked Sendable {
    private let lock = NSLock()
    private let identity: NativeProcessIdentity
    private var calls = 0

    init(identity: NativeProcessIdentity) {
        self.identity = identity
    }

    func observe() throws -> NativeProcessIdentity {
        lock.lock()
        calls += 1
        let call = calls
        lock.unlock()
        guard call == 1 else {
            throw NativeAgentAuthenticatedChildGitError.invalidRequest
        }
        return identity
    }
}

private final class ContextualChildSigner: NativeAgentAuthenticatedChildContextualSigning, @unchecked Sendable {
    private(set) var observedHelper: NativeProcessIdentity?
    private(set) var observedWorktree: Data?

    func signChildPayload(_ payload: Data) throws -> Data {
        Data(payload.reversed())
    }

    func signChildPayload(
        _ payload: Data,
        helperIdentity: NativeProcessIdentity,
        worktreeBindingDigest: Data
    ) throws -> Data {
        observedHelper = helperIdentity
        observedWorktree = worktreeBindingDigest
        return Data(payload.reversed())
    }
}

@Test func childRegistryPassesFreshObservationsToContextualSigner() throws {
    let identity = NativeProcessIdentity(observation: try childTestObservation())
    let helper = try childHelperIdentity(for: identity)
    let registry = NativeAgentAuthenticatedChildGitSessionRegistry()
    let signer = ContextualChildSigner()
    let worktree = Data(repeating: 0x38, count: 32)
    try registry.register(
        sessionID: "session-contextual",
        identity: identity,
        worktreeBindingDigest: worktree,
        signer: signer,
        signatureBudget: childBudget()
    )
    let ticket = try issueChildTicket(registry, child: identity, helper: helper, worktree: worktree)
    let request = try #require(AgentPassChildGitSignRequest(
        requestSequence: 1,
        commitPayload: Data([7, 8]),
        attachTicket: ticket
    ))
    let result = try registry.sign(
        attachTicket: ticket,
        helperIdentity: helper,
        worktreeBindingDigest: worktree,
        request: request,
        nowMilliseconds: 1_000
    )
    #expect(result.signature == Data([8, 7]))
    #expect(signer.observedHelper?.canonicalBindingHash == helper.canonicalBindingHash)
    #expect(signer.observedWorktree == worktree)
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

@Test func childRegistryClassifiesARepeatedRequestAsOutcomeUnknown() throws {
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
    #expect(throws: NativeAgentAuthenticatedChildGitError.outcomeUnknown) {
        _ = try registry.sign(
            attachTicket: ticket,
            helperIdentity: helper,
            worktreeBindingDigest: worktree,
            request: request,
            nowMilliseconds: 1_000
        )
    }
    #expect(throws: NativeAgentAuthenticatedChildGitError.outcomeUnknown) {
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
    #expect(throws: NativeAgentAuthenticatedChildGitError.outcomeUnknown) {
        _ = try registry.sign(attachTicket: ticket, helperIdentity: helper, worktreeBindingDigest: worktree, request: request, nowMilliseconds: 1_000)
    }
}

@Test func childConnectionInvalidationRetiresAnUnconsumedTicketAndAllowsReconnect() throws {
    let identity = NativeProcessIdentity(observation: try childTestObservation())
    let helper = try childHelperIdentity(for: identity)
    let ticketFactory = ChildTicketFactory(startingAt: 0x71)
    let registry = NativeAgentAuthenticatedChildGitSessionRegistry(ticketFactory: { ticketFactory.make() })
    let worktree = Data(repeating: 0x81, count: 32)
    try registry.register(
        sessionID: "session-invalidation-reconnect",
        identity: identity,
        worktreeBindingDigest: worktree,
        signer: NativeAgentAuthenticatedChildClosureSigner { $0 },
        signatureBudget: childBudget(maxSignatures: 2)
    )
    let endpoint = NativeAgentAuthenticatedChildGitEndpoint(
        registry: registry,
        identityObserver: { helper },
        worktreeDigestObserver: { worktree },
        nowMilliseconds: { 1_000 }
    )
    var firstResponse: AgentPassChildGitAttachResponse?
    endpoint.attachChildGit(try #require(AgentPassChildGitAttachRequest())) { response, _ in
        firstResponse = response
    }
    let first = try #require(firstResponse)
    endpoint.connectionInvalidated()

    let oldRequest = try #require(AgentPassChildGitSignRequest(
        requestSequence: 1,
        commitPayload: Data([1]),
        attachTicket: first.attachTicket,
        requestID: first.requestID,
        createdAtMilliseconds: first.createdAtMilliseconds
    ))
    #expect(throws: NativeAgentAuthenticatedChildGitError.attachTicketReplay) {
        _ = try registry.sign(
            attachTicket: first.attachTicket,
            helperIdentity: helper,
            worktreeBindingDigest: worktree,
            request: oldRequest,
            nowMilliseconds: 1_000
        )
    }

    let reconnect = NativeAgentAuthenticatedChildGitEndpoint(
        registry: registry,
        identityObserver: { helper },
        worktreeDigestObserver: { worktree },
        nowMilliseconds: { 1_000 }
    )
    var secondResponse: AgentPassChildGitAttachResponse?
    reconnect.attachChildGit(try #require(AgentPassChildGitAttachRequest())) { response, _ in
        secondResponse = response
    }
    let second = try #require(secondResponse)
    #expect(second.attachTicket != first.attachTicket)
    let request = try #require(AgentPassChildGitSignRequest(
        requestSequence: 1,
        commitPayload: Data([2]),
        attachTicket: second.attachTicket,
        requestID: second.requestID,
        createdAtMilliseconds: second.createdAtMilliseconds
    ))
    var signError: NSError?
    reconnect.signChildGitCommit(request) { response, error in
        #expect(response?.requestID == second.requestID)
        #expect(response?.createdAtMilliseconds == second.createdAtMilliseconds)
        signError = error
    }
    #expect(signError == nil)
}

@Test func childConnectionInvalidationPreservesAnAdmittedUncertainOperation() throws {
    let identity = NativeProcessIdentity(observation: try childTestObservation())
    let helper = try childHelperIdentity(for: identity)
    let ticketFactory = ChildTicketFactory(startingAt: 0x91)
    let blocker = BlockingChildSigner()
    let registry = NativeAgentAuthenticatedChildGitSessionRegistry(ticketFactory: { ticketFactory.make() })
    let worktree = Data(repeating: 0x82, count: 32)
    try registry.register(
        sessionID: "session-invalidation-uncertain",
        identity: identity,
        worktreeBindingDigest: worktree,
        signer: NativeAgentAuthenticatedChildClosureSigner { payload in blocker.sign(payload) },
        signatureBudget: childBudget(maxSignatures: 2)
    )
    let endpoint = NativeAgentAuthenticatedChildGitEndpoint(
        registry: registry,
        identityObserver: { helper },
        worktreeDigestObserver: { worktree },
        nowMilliseconds: { 1_000 }
    )
    var attachResponse: AgentPassChildGitAttachResponse?
    endpoint.attachChildGit(try #require(AgentPassChildGitAttachRequest())) { response, _ in
        attachResponse = response
    }
    let attached = try #require(attachResponse)
    let request = try #require(AgentPassChildGitSignRequest(
        requestSequence: 1,
        commitPayload: Data([3]),
        attachTicket: attached.attachTicket,
        requestID: attached.requestID,
        createdAtMilliseconds: attached.createdAtMilliseconds
    ))
    let finished = DispatchSemaphore(value: 0)
    let signResponse = ChildResponseBox()
    DispatchQueue.global().async {
        endpoint.signChildGitCommit(request) { response, _ in
            signResponse.store(response)
            finished.signal()
        }
    }
    #expect(blocker.started.wait(timeout: .now() + 2) == .success)
    endpoint.connectionInvalidated()
    blocker.release.signal()
    #expect(finished.wait(timeout: .now() + 2) == .success)
    #expect(signResponse.value?.signature == Data([3]))
    #expect(blocker.callCount == 1)

    let reconnect = NativeAgentAuthenticatedChildGitEndpoint(
        registry: registry,
        identityObserver: { helper },
        worktreeDigestObserver: { worktree },
        nowMilliseconds: { 1_000 }
    )
    var reconnectResponse: AgentPassChildGitAttachResponse?
    reconnect.attachChildGit(try #require(AgentPassChildGitAttachRequest())) { response, _ in
        reconnectResponse = response
    }
    let reattached = try #require(reconnectResponse)
    let retry = try #require(AgentPassChildGitSignRequest(
        requestSequence: 1,
        commitPayload: Data([3]),
        attachTicket: reattached.attachTicket,
        requestID: reattached.requestID,
        createdAtMilliseconds: reattached.createdAtMilliseconds
    ))
    var retryError: NSError?
    reconnect.signChildGitCommit(retry) { _, error in retryError = error }
    #expect(retryError?.userInfo[NSLocalizedDescriptionKey] as? String == NativeAgentAuthenticatedChildGitError.replay.rawValue)
    #expect(blocker.callCount == 1)
}

@Test func childEndpointRetiresTicketWhenFailureOccursBeforeRegistryAdmission() throws {
    let identity = NativeProcessIdentity(observation: try childTestObservation())
    let helper = try childHelperIdentity(for: identity)
    let observer = FailingAfterAttachIdentityObserver(identity: helper)
    let registry = NativeAgentAuthenticatedChildGitSessionRegistry()
    let worktree = Data(repeating: 0x83, count: 32)
    try registry.register(
        sessionID: "session-pre-admission-failure",
        identity: identity,
        worktreeBindingDigest: worktree,
        signer: NativeAgentAuthenticatedChildClosureSigner { $0 },
        signatureBudget: childBudget()
    )
    let endpoint = NativeAgentAuthenticatedChildGitEndpoint(
        registry: registry,
        identityObserver: observer.observe,
        worktreeDigestObserver: { worktree },
        nowMilliseconds: { 1_000 }
    )
    var attachResponse: AgentPassChildGitAttachResponse?
    endpoint.attachChildGit(try #require(AgentPassChildGitAttachRequest())) { response, _ in
        attachResponse = response
    }
    let attached = try #require(attachResponse)
    let request = try #require(AgentPassChildGitSignRequest(
        requestSequence: 1,
        commitPayload: Data([4]),
        attachTicket: attached.attachTicket,
        requestID: attached.requestID,
        createdAtMilliseconds: attached.createdAtMilliseconds
    ))

    var signError: NSError?
    endpoint.signChildGitCommit(request) { _, error in signError = error }
    #expect(signError?.userInfo[NSLocalizedDescriptionKey] as? String == NativeAgentAuthenticatedChildGitError.invalidRequest.rawValue)

    endpoint.connectionInvalidated()

    let reconnect = NativeAgentAuthenticatedChildGitEndpoint(
        registry: registry,
        identityObserver: { helper },
        worktreeDigestObserver: { worktree },
        nowMilliseconds: { 1_000 }
    )
    var reconnectResponse: AgentPassChildGitAttachResponse?
    reconnect.attachChildGit(try #require(AgentPassChildGitAttachRequest())) { response, _ in
        reconnectResponse = response
    }
    #expect(reconnectResponse != nil)
}
