@testable import AgentPassNativeService
import Foundation
import Testing
@testable import AgentPassNativeCore

private let hostAuditTokenWords: [UInt32] = [
    501, // auid
    501, // euid
    20,  // egid
    501, // ruid
    20,  // rgid
    42,  // pid
    77,  // asid
    19   // pidversion
]

private final class MutableAuditTokenState: @unchecked Sendable {
    private let lock = NSLock()
    private var value: NativeAgentAuthenticatedHostCompleteAuditToken

    init(_ value: NativeAgentAuthenticatedHostCompleteAuditToken) {
        self.value = value
    }

    func read() -> NativeAgentAuthenticatedHostCompleteAuditToken {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func set(_ value: NativeAgentAuthenticatedHostCompleteAuditToken) {
        lock.lock()
        self.value = value
        lock.unlock()
    }
}

private final class SignRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var count = 0

    func record() {
        lock.lock()
        count += 1
        lock.unlock()
    }
}

private func hostObservation(
    pid: Int32 = 42,
    uid: UInt32 = 501,
    pidVersion: UInt64 = 19,
    codeDirectoryHash: String = String(repeating: "a", count: 64),
    bundleIdentifier: String = "dev.agentpass.agent-host"
) throws -> NativeProcessObservation {
    let facts = try NativeObservedProcessFacts(
        uid: uid,
        pid: pid,
        pidVersion: pidVersion,
        bootIdentity: "listener-test-boot",
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

private func token(_ words: [UInt32] = hostAuditTokenWords) throws -> NativeAgentAuthenticatedHostCompleteAuditToken {
    try NativeAgentAuthenticatedHostCompleteAuditToken(words: words)
}

private func changed(_ index: Int) -> [UInt32] {
    var words = hostAuditTokenWords
    words[index] &+= 1
    return words
}

@Test func hostCompleteAuditTokenRejectsAnythingOtherThanAValidEightWordToken() throws {
    #expect(throws: NativeAgentAuthenticatedHostAuditTokenError.invalidAuditToken) {
        _ = try token(Array(repeating: 1, count: 7))
    }
    #expect(throws: NativeAgentAuthenticatedHostAuditTokenError.invalidAuditToken) {
        _ = try token(Array(repeating: 1, count: 9))
    }
    #expect(throws: NativeAgentAuthenticatedHostAuditTokenError.invalidAuditToken) {
        _ = try token(changed(5).enumerated().map { $0.offset == 5 ? 0 : $0.element })
    }
}

@Test func hostCompleteAuditTokenContextBindsEveryAuditTokenField() throws {
    let observation = try hostObservation()
    let completeToken = try token()
    let context = try completeToken.context(matching: observation)
    let expected = NativeConnectionContext(capturing: try NativeAuditTokenFieldAdapter(words: hostAuditTokenWords))
    #expect(context == expected)

    for index in 0..<hostAuditTokenWords.count {
        let changedWords = changed(index)
        let changedToken = try token(changedWords)
        let changedObservation = try hostObservation(
            pid: Int32(changedWords[5]),
            uid: changedWords[1],
            pidVersion: UInt64(changedWords[7])
        )
        let changedContext = try changedToken.context(matching: changedObservation)
        #expect(changedContext != context, "changed audit_token_t field at index \(index) was not bound")
    }
}

@Test func childCodeSigningRequirementFailsClosedWhenProductConfigurationOmitsIt() {
    #expect(throws: AgentPassNativeError.self) {
        _ = try deriveDedicatedChildCodeSigningRequirement(
            configuredChildRequirement: nil,
            hostCodeSigningRequirement: "anchor apple generic and identifier \"dev.agentpass.agent-host\"",
            managementCodeSigningRequirement: "anchor apple generic and identifier \"dev.agentpass.native-client\""
        )
    }
}

@Test func childCodeSigningRequirementRejectsHostReuseAndAmbiguousPrincipals() {
    let hostRequirement = "anchor apple generic and identifier \"dev.agentpass.agent-host\""
    let managementRequirement = "anchor apple generic and identifier \"dev.agentpass.native-client\""
    #expect(throws: AgentPassNativeError.self) {
        _ = try deriveDedicatedChildCodeSigningRequirement(
            configuredChildRequirement: hostRequirement,
            hostCodeSigningRequirement: hostRequirement,
            managementCodeSigningRequirement: managementRequirement
        )
    }
    #expect(throws: AgentPassNativeError.self) {
        _ = try deriveDedicatedChildCodeSigningRequirement(
            configuredChildRequirement: "anchor apple generic and identifier \"dev.agentpass.git-sign-xpc\" or identifier \"dev.agentpass.agent-host\"",
            hostCodeSigningRequirement: hostRequirement,
            managementCodeSigningRequirement: managementRequirement
        )
    }
}

@Test func childCodeSigningRequirementAcceptsOnlyTheFixedDedicatedHelperPrincipal() throws {
    let requirement = "anchor apple generic and identifier \"dev.agentpass.git-sign-xpc\" and certificate leaf[subject.OU] = \"ABCDE12345\""
    #expect(try deriveDedicatedChildCodeSigningRequirement(
        configuredChildRequirement: requirement,
        hostCodeSigningRequirement: "anchor apple generic and identifier \"dev.agentpass.agent-host\"",
        managementCodeSigningRequirement: "anchor apple generic and identifier \"dev.agentpass.native-client\""
    ) == requirement)
}

@Test func hostListenerDefaultAuditTokenSourceFailsClosedWhenTheOSSourceIsUnavailable() throws {
    let delegate = NativeAgentAuthenticatedHostListenerDelegate(
        allowedClientUID: 501,
        codeSigningRequirement: "anchor apple generic and identifier \"dev.agentpass.test\"",
        peerPolicyFactory: { _ in try NativeProcessIdentityPolicy(expectedUID: 501) },
        childPolicy: nil,
        childFactory: nil,
        signer: NativeAgentAuthenticatedHostClosureSigner { _ in Data([1]) }
    )

    let accepted = delegate.listener(
        NSXPCListener.anonymous(),
        shouldAcceptNewConnection: NSXPCConnection(serviceName: "dev.agentpass.test-only")
    )
    #expect(accepted == false)
}

@Test func hostEndpointRevalidatesTheCompleteTokenBeforeAProtectedOperation() throws {
    let initialToken = try token()
    let observation = try hostObservation()
    let childObservation = try hostObservation(
        pid: 84,
        pidVersion: 12,
        codeDirectoryHash: String(repeating: "b", count: 64),
        bundleIdentifier: "dev.agentpass.git-sign-xpc"
    )
    let state = MutableAuditTokenState(initialToken)
    let source = NativeAgentAuthenticatedHostClosureAuditTokenSource { _ in state.read() }
    let initialContext = try source.completeAuditToken(
        for: NSXPCConnection(serviceName: "dev.agentpass.test-only")
    ).context(matching: observation)
    let peerPolicy = try NativeProcessIdentityPolicy.exact(NativeProcessIdentity(observation: observation))
    let childPolicy = try NativeProcessIdentityPolicy.exact(NativeProcessIdentity(observation: childObservation))
    let signer = SignRecorder()
    let endpoint = try NativeAgentAuthenticatedHostEndpoint(
        connectionContext: initialContext,
        initialPeerObservation: observation,
        peerProcessPolicy: peerPolicy,
        childProcessPolicy: childPolicy,
        observeConnectionContext: {
            try source.completeAuditToken(
                for: NSXPCConnection(serviceName: "dev.agentpass.test-only")
            ).context(matching: observation)
        },
        observePeerProcess: { observation },
        observeChild: { _, _ in
            try NativeAgentAuthenticatedHostChildObservation(
                observationSource: FixedObservationSource(observation: childObservation),
                worktreeBindingDigest: Data(repeating: 0x31, count: AgentPassHostXPCContract.digestBytes)
            )
        },
        signer: NativeAgentAuthenticatedHostClosureSigner { _ in
            signer.record()
            return Data([1])
        },
        signerPolicy: .developmentLegacySignerAllowed,
        nowMilliseconds: { 1_000 },
        sessionLifetimeMilliseconds: 100,
        signatureBudgetProvider: {
            try NativeAgentSignatureBudget(maxSignatures: 2, usedSignatures: 0)
        }
    )

    let prepared = try prepareHostSession(endpoint)
    _ = try #require(prepared)
    let childDigest = try NativeAgentAuthenticatedHostChildObservation(
        observationSource: FixedObservationSource(observation: childObservation),
        worktreeBindingDigest: Data(repeating: 0x31, count: AgentPassHostXPCContract.digestBytes)
    )
    let attach = try #require(AgentPassHostAttachChildRequest(
        childPID: Int(childObservation.process.pid),
        childPIDVersion: Int64(childObservation.process.pidVersion),
        executableIdentityDigest: childDigest.executableIdentityDigest,
        ancestryBindingDigest: childDigest.ancestryBindingDigest,
        worktreeBindingDigest: childDigest.worktreeBindingDigest
    ))
    var attachError: NSError?
    endpoint.attachHostChild(attach) { _, error in attachError = error }
    #expect(attachError == nil)

    state.set(try token(changed(0)))
    let request = try #require(AgentPassHostSignRequest(requestSequence: 1, commitPayload: Data([1])))
    var signError: NSError?
    endpoint.signHostPayload(request) { _, error in signError = error }
    #expect(signError?.code == 3)
    #expect(signError?.localizedDescription == NativeAgentAuthenticatedHostEndpointError.peerIdentityMismatch.rawValue)
    #expect(signer.count == 0)
}

private struct FixedObservationSource: NativeProcessObservationSource {
    let observation: NativeProcessObservation

    func observe() throws -> NativeProcessObservation {
        observation
    }
}

private func prepareHostSession(_ endpoint: NativeAgentAuthenticatedHostEndpoint) throws -> AgentPassHostPrepareResponse? {
    var response: AgentPassHostPrepareResponse?
    var error: NSError?
    endpoint.prepareHostSession(try #require(AgentPassHostPrepareRequest(launchNonce: Data(repeating: 0x41, count: 16)))) {
        response = $0
        error = $1
    }
    #expect(error == nil)
    return response
}

@Test func injectedAgentSessionTokenMismatchTerminallyClosesBeforeProtectedOperation() throws {
    let expected = try token().context(matching: hostObservation())
    let changed = try token(changed(0)).context(matching: hostObservation())
    var terminalCloseCount = 0
    var protectedOperationRan = false

    do {
        try authorizeAgentSessionConnectionToken(
            expected: expected,
            current: { changed },
            terminalClose: { terminalCloseCount += 1 }
        )
        protectedOperationRan = true
    } catch let error as NativeAgentAuthenticatedHostAuditTokenError {
        #expect(error == .invalidAuditToken)
    }

    #expect(terminalCloseCount == 1)
    #expect(!protectedOperationRan)
}
