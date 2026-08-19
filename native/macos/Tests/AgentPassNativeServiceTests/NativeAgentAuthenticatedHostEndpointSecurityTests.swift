import AgentPassNativeService
import Foundation
import Testing
@testable import AgentPassNativeCore

private let securityChildTicket = Data(repeating: 0x71, count: AgentPassChildGitXPCContract.attachTicketBytes)

private final class EndpointTestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Int64

    init(_ value: Int64) {
        self.value = value
    }

    func read() -> Int64 {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func set(_ value: Int64) {
        lock.lock()
        self.value = value
        lock.unlock()
    }
}

private final class EndpointTestRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var signCount = 0
    private(set) var registerCount = 0
    private(set) var unregisterCount = 0
    private(set) var unregisteredBindings: [String] = []

    func recordSign() {
        lock.lock()
        signCount += 1
        lock.unlock()
    }

    func recordRegister() {
        lock.lock()
        registerCount += 1
        lock.unlock()
    }

    func recordUnregister(_ binding: String) {
        lock.lock()
        unregisterCount += 1
        unregisteredBindings.append(binding)
        lock.unlock()
    }
}

private struct EndpointObservationSource: NativeProcessObservationSource {
    let value: NativeProcessObservation

    func observe() throws -> NativeProcessObservation {
        value
    }
}

private enum EndpointSignerBehavior: Sendable {
    case success
    case failure
    case empty
}

private final class HostEndpointHarness: @unchecked Sendable {
    let hostObservation: NativeProcessObservation
    let childObservation: NativeProcessObservation
    let childHelperObservation: NativeProcessObservation
    let hostContext: NativeConnectionContext
    let childWorktreeDigest = Data(repeating: 0x31, count: AgentPassHostXPCContract.digestBytes)
    let clock = EndpointTestClock(1_000)
    let recorder = EndpointTestRecorder()
    let registry = NativeAgentAuthenticatedChildGitSessionRegistry()

    private let lock = NSLock()
    private var livePeerObservation: NativeProcessObservation
    private var liveChildObservation: NativeProcessObservation
    private var liveChildWorktreeDigest: Data
    private var childObservationShouldFail = false
    private var signerBehavior: EndpointSignerBehavior = .success
    private var signatureBudgetValue: NativeAgentSignatureBudget

    init() throws {
        let host = try Self.observation(
            pid: 42,
            pidVersion: 9,
            codeDirectoryHash: String(repeating: "a", count: 64),
            bundleIdentifier: "dev.agentpass.agent-host"
        )
        let child = try Self.observation(
            pid: 84,
            pidVersion: 12,
            codeDirectoryHash: String(repeating: "b", count: 64),
            bundleIdentifier: "dev.agentpass.git-sign-xpc"
        )
        hostObservation = host
        childObservation = child
        childHelperObservation = try Self.helperObservation(for: child)
        hostContext = try NativeConnectionContext(
            osProcessID: host.process.pid,
            effectiveUserID: host.process.uid,
            auditSessionID: 7,
            pidVersion: hostObservation.process.pidVersion
        )
        livePeerObservation = hostObservation
        liveChildObservation = childObservation
        liveChildWorktreeDigest = childWorktreeDigest
        signatureBudgetValue = try NativeAgentSignatureBudget(maxSignatures: 2, usedSignatures: 0)
    }

    func setPeerObservation(_ observation: NativeProcessObservation) {
        lock.lock()
        livePeerObservation = observation
        lock.unlock()
    }

    func setChildObservation(_ observation: NativeProcessObservation) {
        lock.lock()
        liveChildObservation = observation
        lock.unlock()
    }

    func setChildWorktreeDigest(_ digest: Data) {
        lock.lock()
        liveChildWorktreeDigest = digest
        lock.unlock()
    }

    func failChildObservation() {
        lock.lock()
        childObservationShouldFail = true
        lock.unlock()
    }

    func setSignerBehavior(_ behavior: EndpointSignerBehavior) {
        lock.lock()
        signerBehavior = behavior
        lock.unlock()
    }

    func setSignatureBudget(maxSignatures: Int, usedSignatures: Int) throws {
        lock.lock()
        defer { lock.unlock() }
        signatureBudgetValue = try NativeAgentSignatureBudget(
            maxSignatures: maxSignatures,
            usedSignatures: usedSignatures
        )
    }

    func makeEndpoint(provideSignatureBudget: Bool = true) throws -> NativeAgentAuthenticatedHostEndpoint {
        let hostIdentity = NativeProcessIdentity(observation: hostObservation)
        let childIdentity = NativeProcessIdentity(observation: childObservation)
        let peerPolicy = try NativeProcessIdentityPolicy.exact(hostIdentity)
        let childPolicy = try NativeProcessIdentityPolicy.exact(childIdentity)
        let childSigner = NativeAgentAuthenticatedChildClosureSigner { _ in Data([0x71]) }
        let signatureBudgetProvider: NativeAgentAuthenticatedHostEndpoint.SignatureBudgetProvider?
        if provideSignatureBudget {
            signatureBudgetProvider = { [self] in
                lock.lock()
                defer { lock.unlock() }
                return signatureBudgetValue
            }
        } else {
            signatureBudgetProvider = nil
        }

        return try NativeAgentAuthenticatedHostEndpoint(
            connectionContext: hostContext,
            initialPeerObservation: hostObservation,
            peerProcessPolicy: peerPolicy,
            childProcessPolicy: childPolicy,
            observeConnectionContext: { [self] in hostContext },
            observePeerProcess: { [self] in
                lock.lock()
                defer { lock.unlock() }
                return livePeerObservation
            },
            observeChild: { [self] _, _ in
                lock.lock()
                let shouldFail = childObservationShouldFail
                let observation = liveChildObservation
                let worktreeDigest = liveChildWorktreeDigest
                lock.unlock()
                if shouldFail { throw NativeAgentAuthenticatedHostEndpointError.childObservationFailed }
                return try NativeAgentAuthenticatedHostChildObservation(
                    observationSource: EndpointObservationSource(value: observation),
                    worktreeBindingDigest: worktreeDigest
                )
            },
            signer: NativeAgentAuthenticatedHostClosureSigner { [self] _ in
                lock.lock()
                let behavior = signerBehavior
                lock.unlock()
                recorder.recordSign()
                switch behavior {
                case .success: return Data([0x91, 0x92])
                case .failure: throw NativeAgentAuthenticatedHostEndpointError.signerFailed
                case .empty: return Data()
                }
            },
            nowMilliseconds: { [self] in clock.read() },
            sessionLifetimeMilliseconds: 100,
            childRegistrar: { [self] sessionID, observation, signatureBudget in
                try registry.register(
                    sessionID: sessionID,
                    identity: observation.identity,
                    worktreeBindingDigest: observation.worktreeBindingDigest,
                    signer: childSigner,
                    signatureBudget: signatureBudget,
                    expiresAtMilliseconds: 10_000,
                    nowMilliseconds: 1_000
                )
                recorder.recordRegister()
            },
            childUnregistrar: { [self] bindingHash in
                registry.unregister(identityBindingHash: bindingHash)
                recorder.recordUnregister(bindingHash)
            },
            signatureBudgetProvider: signatureBudgetProvider
        )
    }

    func childIdentity() -> NativeProcessIdentity {
        lock.lock()
        defer { lock.unlock() }
        return NativeProcessIdentity(observation: childHelperObservation)
    }

    func childWorktree() -> Data {
        lock.lock()
        defer { lock.unlock() }
        return liveChildWorktreeDigest
    }

    func childEndpoint() -> NativeAgentAuthenticatedChildGitEndpoint {
        NativeAgentAuthenticatedChildGitEndpoint(
            registry: registry,
            identityObserver: { [self] in childIdentity() },
            worktreeDigestObserver: { [self] in childWorktree() },
            nowMilliseconds: { [self] in clock.read() }
        )
    }

    func childEndpointWithTicket() throws -> (NativeAgentAuthenticatedChildGitEndpoint, Data) {
        let endpoint = childEndpoint()
        var ticket: Data?
        var error: NSError?
        endpoint.attachChildGit(try #require(AgentPassChildGitAttachRequest())) { response, responseError in
            ticket = response?.attachTicket
            error = responseError
        }
        #expect(error == nil)
        return (endpoint, try #require(ticket))
    }

    func childAdmissionError() -> String? {
        var error: NSError?
        childEndpoint().attachChildGit(AgentPassChildGitAttachRequest()!) { _, responseError in
            error = responseError
        }
        return error?.userInfo[NSLocalizedDescriptionKey] as? String
    }

    func attachRequest(
        childPID: Int? = nil,
        childPIDVersion: Int64? = nil,
        executableIdentityDigest: Data? = nil,
        ancestryBindingDigest: Data? = nil,
        worktreeBindingDigest: Data? = nil
    ) throws -> AgentPassHostAttachChildRequest {
        let observation = try NativeAgentAuthenticatedHostChildObservation(
            observationSource: EndpointObservationSource(value: childObservation),
            worktreeBindingDigest: childWorktreeDigest
        )
        return try #require(AgentPassHostAttachChildRequest(
            childPID: childPID ?? Int(observation.identity.pid),
            childPIDVersion: childPIDVersion ?? Int64(observation.identity.pidVersion),
            executableIdentityDigest: executableIdentityDigest ?? observation.executableIdentityDigest,
            ancestryBindingDigest: ancestryBindingDigest ?? observation.ancestryBindingDigest,
            worktreeBindingDigest: worktreeBindingDigest ?? observation.worktreeBindingDigest
        ))
    }

    static func observation(
        pid: Int32,
        pidVersion: UInt64,
        codeDirectoryHash: String,
        bundleIdentifier: String
    ) throws -> NativeProcessObservation {
        let facts = try NativeObservedProcessFacts(
            uid: 501,
            pid: pid,
            pidVersion: pidVersion,
            bootIdentity: "endpoint-test-boot",
            executableFileIdentity: try NativeExecutableFileIdentity(
                deviceID: 1,
                inode: UInt64(pid),
                fileSize: 3,
                modificationTimeNanoseconds: 4
            ),
            codeDirectoryHash: codeDirectoryHash,
            bundleIdentifier: bundleIdentifier,
            teamIdentifier: "ABCDE12345",
            signatureKind: .developerID,
            entitlements: [:]
        )
        return try NativeProcessObservation(process: facts, ancestry: [])
    }

    static func helperObservation(for child: NativeProcessObservation) throws -> NativeProcessObservation {
        let facts = try NativeObservedProcessFacts(
            uid: child.process.uid,
            pid: child.process.pid + 1,
            pidVersion: child.process.pidVersion + 1,
            bootIdentity: child.process.bootIdentity,
            executableFileIdentity: child.process.executableFileIdentity,
            codeDirectoryHash: child.process.codeDirectoryHash,
            bundleIdentifier: "dev.agentpass.git-sign-xpc-helper",
            teamIdentifier: child.process.teamIdentifier,
            signatureKind: child.process.signatureKind,
            entitlements: child.process.entitlements
        )
        return try NativeProcessObservation(process: facts, ancestry: [.observed(child.process)])
    }
}

private func prepare(_ endpoint: NativeAgentAuthenticatedHostEndpoint) throws -> AgentPassHostPrepareResponse {
    var result: AgentPassHostPrepareResponse?
    var error: NSError?
    endpoint.prepareHostSession(
        try #require(AgentPassHostPrepareRequest(launchNonce: Data(repeating: 0x41, count: 16)))
    ) { response, responseError in
        result = response
        error = responseError
    }
    #expect(error == nil)
    return try #require(result)
}

private func attach(
    _ endpoint: NativeAgentAuthenticatedHostEndpoint,
    request: AgentPassHostAttachChildRequest
) throws -> AgentPassHostAttachChildResponse {
    var result: AgentPassHostAttachChildResponse?
    var error: NSError?
    endpoint.attachHostChild(request) { response, responseError in
        result = response
        error = responseError
    }
    #expect(error == nil)
    return try #require(result)
}

private func errorCode(
    _ endpoint: NativeAgentAuthenticatedHostEndpoint,
    sign request: AgentPassHostSignRequest
) -> Int? {
    var error: NSError?
    endpoint.signHostPayload(request) { _, responseError in error = responseError }
    return error?.code
}

private func childErrorCode(
    _ endpoint: NativeAgentAuthenticatedChildGitEndpoint,
    request: AgentPassChildGitSignRequest
) -> String? {
    var error: NSError?
    endpoint.signChildGitCommit(request) { _, responseError in error = responseError }
    return error?.userInfo[NSLocalizedDescriptionKey] as? String
}

@Test func hostEndpointExpiryRevokesChildRegistrationBeforeAnyLaterSign() throws {
    let harness = try HostEndpointHarness()
    let endpoint = try harness.makeEndpoint()
    _ = try prepare(endpoint)
    _ = try attach(endpoint, request: harness.attachRequest())
    #expect(harness.recorder.registerCount == 1)

    harness.clock.set(1_100)
    var status: AgentPassHostStatusResponse?
    var statusError: NSError?
    endpoint.hostSessionStatus(try #require(AgentPassHostStatusRequest())) { response, error in
        status = response
        statusError = error
    }
    #expect(statusError == nil)
    #expect(status?.status == AgentPassHostXPCContract.SessionStatus.expired.rawValue)
    #expect(status?.childAttached == false)
    #expect(harness.recorder.unregisterCount == 1)

    let hostRequest = try #require(AgentPassHostSignRequest(requestSequence: 1, commitPayload: Data([1])))
    #expect(errorCode(endpoint, sign: hostRequest) == 8)
    #expect(harness.recorder.signCount == 0)

    #expect(harness.childAdmissionError() == NativeAgentAuthenticatedChildGitError.childNotRegistered.rawValue)
}

@Test func hostEndpointSignerFailureRevokesChildRegistrationAndBudget() throws {
    let harness = try HostEndpointHarness()
    harness.setSignerBehavior(.failure)
    let endpoint = try harness.makeEndpoint()
    _ = try prepare(endpoint)
    _ = try attach(endpoint, request: harness.attachRequest())

    let request = try #require(AgentPassHostSignRequest(requestSequence: 1, commitPayload: Data([3])))
    #expect(errorCode(endpoint, sign: request) == 9)
    #expect(harness.recorder.signCount == 1)
    #expect(harness.recorder.unregisterCount == 1)

    #expect(harness.childAdmissionError() == NativeAgentAuthenticatedChildGitError.childNotRegistered.rawValue)
}

@Test func hostEndpointEmptySignatureRevokesChildRegistrationAndBudget() throws {
    let harness = try HostEndpointHarness()
    harness.setSignerBehavior(.empty)
    let endpoint = try harness.makeEndpoint()
    _ = try prepare(endpoint)
    _ = try attach(endpoint, request: harness.attachRequest())

    let request = try #require(AgentPassHostSignRequest(requestSequence: 1, commitPayload: Data([4])))
    #expect(errorCode(endpoint, sign: request) == 9)
    #expect(harness.recorder.signCount == 1)
    #expect(harness.recorder.unregisterCount == 1)

    #expect(harness.childAdmissionError() == NativeAgentAuthenticatedChildGitError.childNotRegistered.rawValue)
}

@Test func hostEndpointResponseLossDoesNotPermitSameSequenceToSignTwice() throws {
    let harness = try HostEndpointHarness()
    let endpoint = try harness.makeEndpoint()
    _ = try prepare(endpoint)
    _ = try attach(endpoint, request: harness.attachRequest())

    let first = try #require(AgentPassHostSignRequest(requestSequence: 1, commitPayload: Data([5])))
    endpoint.signHostPayload(first) { _, _ in
        // Deliberately discard the reply: this models a transport response loss.
    }
    #expect(harness.recorder.signCount == 1)

    let retry = try #require(AgentPassHostSignRequest(requestSequence: 1, commitPayload: Data([5])))
    var retryError: NSError?
    endpoint.signHostPayload(retry) { _, responseError in retryError = responseError }
    #expect(retryError?.code == 11)
    #expect(retryError?.localizedDescription == NativeAgentAuthenticatedHostEndpointError.outcomeUnknown.rawValue)
    #expect(harness.recorder.signCount == 1)
    #expect(harness.recorder.unregisterCount == 1)
    #expect(harness.childAdmissionError() == NativeAgentAuthenticatedChildGitError.childNotRegistered.rawValue)

    var status: AgentPassHostStatusResponse?
    endpoint.hostSessionStatus(try #require(AgentPassHostStatusRequest())) { response, _ in status = response }
    #expect(status?.status == AgentPassHostXPCContract.SessionStatus.expired.rawValue)
    #expect(status?.usedSignatures == 1)
}

@Test func hostEndpointPeerDriftRevokesChildRegistrationBeforeReturningError() throws {
    let harness = try HostEndpointHarness()
    let endpoint = try harness.makeEndpoint()
    _ = try prepare(endpoint)
    _ = try attach(endpoint, request: harness.attachRequest())

    harness.setPeerObservation(try HostEndpointHarness.observation(
        pid: 42,
        pidVersion: 9,
        codeDirectoryHash: String(repeating: "c", count: 64),
        bundleIdentifier: "dev.agentpass.agent-host"
    ))

    let request = try #require(AgentPassHostSignRequest(requestSequence: 1, commitPayload: Data([6])))
    #expect(errorCode(endpoint, sign: request) == 4)
    #expect(harness.recorder.signCount == 0)
    #expect(harness.recorder.unregisterCount == 1)

    #expect(harness.childAdmissionError() == NativeAgentAuthenticatedChildGitError.childNotRegistered.rawValue)
}

@Test func hostEndpointStatusPeerDriftRevokesChildBeforeChildSignerInvocation() throws {
    let harness = try HostEndpointHarness()
    let endpoint = try harness.makeEndpoint()
    _ = try prepare(endpoint)
    _ = try attach(endpoint, request: harness.attachRequest())

    harness.setPeerObservation(try HostEndpointHarness.observation(
        pid: 42,
        pidVersion: 9,
        codeDirectoryHash: String(repeating: "c", count: 64),
        bundleIdentifier: "dev.agentpass.agent-host"
    ))

    var status: AgentPassHostStatusResponse?
    var statusError: NSError?
    endpoint.hostSessionStatus(try #require(AgentPassHostStatusRequest())) { response, responseError in
        status = response
        statusError = responseError
    }
    #expect(status == nil)
    #expect(statusError?.code == 4)
    #expect(harness.recorder.unregisterCount == 1)

    #expect(harness.childAdmissionError() == NativeAgentAuthenticatedChildGitError.childNotRegistered.rawValue)
    #expect(harness.recorder.signCount == 0)
}

@Test func hostEndpointClosePeerDriftRevokesChildBeforeChildSignerInvocation() throws {
    let harness = try HostEndpointHarness()
    let endpoint = try harness.makeEndpoint()
    _ = try prepare(endpoint)
    _ = try attach(endpoint, request: harness.attachRequest())

    harness.setPeerObservation(try HostEndpointHarness.observation(
        pid: 42,
        pidVersion: 9,
        codeDirectoryHash: String(repeating: "c", count: 64),
        bundleIdentifier: "dev.agentpass.agent-host"
    ))

    var close: AgentPassHostCloseResponse?
    var closeError: NSError?
    endpoint.closeHostSession(try #require(AgentPassHostCloseRequest(reason: .completed))) { response, responseError in
        close = response
        closeError = responseError
    }
    #expect(close == nil)
    #expect(closeError?.code == 4)
    #expect(harness.recorder.unregisterCount == 1)

    #expect(harness.childAdmissionError() == NativeAgentAuthenticatedChildGitError.childNotRegistered.rawValue)
    #expect(harness.recorder.signCount == 0)
}

@Test func hostEndpointRejectsPIDIdentityAndWorktreeMismatchDuringAttach() throws {
    enum Mismatch {
        case pid
        case pidVersion
        case executable
        case ancestry
        case worktree
    }

    for mismatch in [Mismatch.pid, .pidVersion, .executable, .ancestry, .worktree] {
        let harness = try HostEndpointHarness()
        let endpoint = try harness.makeEndpoint()
        _ = try prepare(endpoint)
        let request: AgentPassHostAttachChildRequest
        switch mismatch {
        case .pid:
            request = try harness.attachRequest(childPID: 85)
        case .pidVersion:
            request = try harness.attachRequest(childPIDVersion: 13)
        case .executable:
            request = try harness.attachRequest(executableIdentityDigest: Data(repeating: 0x61, count: 32))
        case .ancestry:
            request = try harness.attachRequest(ancestryBindingDigest: Data(repeating: 0x62, count: 32))
        case .worktree:
            request = try harness.attachRequest(worktreeBindingDigest: Data(repeating: 0x63, count: 32))
        }

        var error: NSError?
        endpoint.attachHostChild(request) { _, responseError in error = responseError }
        #expect(error?.code == 6)
        #expect(harness.recorder.registerCount == 0)
        #expect(harness.recorder.unregisterCount == 0)
    }
}

@Test func hostEndpointFailsClosedWhenCloudBudgetProviderIsNotWired() throws {
    let harness = try HostEndpointHarness()
    let endpoint = try harness.makeEndpoint(provideSignatureBudget: false)
    var response: AgentPassHostPrepareResponse?
    var error: NSError?
    endpoint.prepareHostSession(
        try #require(AgentPassHostPrepareRequest(launchNonce: Data(repeating: 0x51, count: 16)))
    ) { value, responseError in
        response = value
        error = responseError
    }
    #expect(response == nil)
    #expect(error?.code == 2)
    #expect(harness.recorder.signCount == 0)
}

@Test func hostAndChildConsumeOneAuthoritativeCloudBudgetWithoutTruncationOrExpansion() throws {
    let harness = try HostEndpointHarness()
    try harness.setSignatureBudget(maxSignatures: 5, usedSignatures: 3)
    let endpoint = try harness.makeEndpoint()
    let prepared = try prepare(endpoint)
    #expect(prepared.maxSignatures == 5)
    #expect(prepared.usedSignatures == 3)
    let attached = try attach(endpoint, request: harness.attachRequest())
    #expect(attached.maxSignatures == 5)
    #expect(attached.usedSignatures == 3)

    let hostRequest = try #require(AgentPassHostSignRequest(requestSequence: 1, commitPayload: Data([0x61])))
    var hostResponse: AgentPassHostSignResponse?
    var hostError: NSError?
    endpoint.signHostPayload(hostRequest) { response, responseError in
        hostResponse = response
        hostError = responseError
    }
    #expect(hostError == nil)
    #expect(hostResponse?.maxSignatures == 5)
    #expect(hostResponse?.usedSignatures == 4)
    #expect(hostResponse?.remainingSignatures == 1)
    #expect(hostResponse?.requestID.isEmpty == false)
    #expect(hostResponse?.createdAtMilliseconds == 1_000)

    let (childEndpoint, childTicket) = try harness.childEndpointWithTicket()
    let childRequest = try #require(AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: Data([0x62]), attachTicket: childTicket))
    var childResponse: AgentPassChildGitSignResponse?
    var childError: NSError?
    childEndpoint.signChildGitCommit(childRequest) { response, responseError in
        childResponse = response
        childError = responseError
    }
    #expect(childError == nil)
    #expect(childResponse?.maxSignatures == 5)
    #expect(childResponse?.usedSignatures == 5)
    #expect(childResponse?.remainingSignatures == 0)

    let exhaustedHostRequest = try #require(AgentPassHostSignRequest(requestSequence: 2, commitPayload: Data([0x63])))
    #expect(errorCode(endpoint, sign: exhaustedHostRequest) == 2)
    #expect(harness.recorder.signCount == 1)
    #expect(harness.childAdmissionError() == NativeAgentAuthenticatedChildGitError.closed.rawValue)
}

@Test func hostPrepareRejectsAnAlreadyExhaustedCloudBudget() throws {
    let harness = try HostEndpointHarness()
    try harness.setSignatureBudget(maxSignatures: 5, usedSignatures: 5)
    let endpoint = try harness.makeEndpoint()
    var response: AgentPassHostPrepareResponse?
    var error: NSError?
    endpoint.prepareHostSession(
        try #require(AgentPassHostPrepareRequest(launchNonce: Data(repeating: 0x52, count: 16)))
    ) { value, responseError in
        response = value
        error = responseError
    }
    #expect(response == nil)
    #expect(error?.code == 2)
}
