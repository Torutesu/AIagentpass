import AgentPassNativeCore
import Foundation
import ObjectiveC.runtime
import Testing

private let harnessSessionID = "33333333-3333-4333-8333-333333333333"
private let harnessRequestID = "55555555-5555-4555-8555-555555555555"
private let harnessCapabilityID = "66666666-6666-4666-8666-666666666666"
private let harnessErrorDomain = "dev.agentpass.agent.xpc.harness"

private func harnessCapability() throws -> Data {
    try NativeStrictJSON.data([
        "version": 1, "capability_id": harnessCapabilityID,
        "nonce": String(repeating: "N", count: 32), "issuer": "agentpass-cloud",
        "key_id": "capability-v1",
        "audience": ["agent_id": harnessSessionID, "device_id": harnessRequestID],
        "scope": [
            "operations": ["git.commit.sign"], "repositories": ["/work/repo"],
            "branches": ["allow": ["feature/*"], "deny": []],
            "remotes": ["allow": ["git@example.test:repo.git"], "deny": []],
        ],
        "not_before": "2027-01-15T07:59:59.000Z", "expires_at": "2027-01-15T08:00:30.000Z",
        "sequence": 1, "signature": String(repeating: "A", count: 86) + "==",
    ])
}
// The timeout runs on Dispatch rather than blocking a Swift cooperative-executor
// thread, so the full parallel native suite cannot starve XPC and URLSession work.
private let harnessReplyTimeout: DispatchTimeInterval = .seconds(15)

private final class HarnessResultBox<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Value?
    func set(_ value: Value) { lock.withLock { self.value = value } }
    func get() -> Value? { lock.withLock { value } }
}

private final class HarnessContinuation: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Never>?
    private var timeoutWorkItem: DispatchWorkItem?

    init(_ continuation: CheckedContinuation<Void, Never>) {
        self.continuation = continuation
    }

    func resume() {
        let pending: (CheckedContinuation<Void, Never>?, DispatchWorkItem?) = lock.withLock {
            defer {
                continuation = nil
                timeoutWorkItem = nil
            }
            return (continuation, timeoutWorkItem)
        }
        pending.1?.cancel()
        pending.0?.resume()
    }

    func armTimeout(after interval: DispatchTimeInterval) {
        let workItem = DispatchWorkItem { [weak self] in self?.resume() }
        lock.withLock { timeoutWorkItem = workItem }
        DispatchQueue.global(qos: .userInitiated).asyncAfter(
            deadline: .now() + interval,
            execute: workItem
        )
    }
}

private func enforceHarnessReplyTimeout(_ reply: HarnessContinuation) {
    reply.armTimeout(after: harnessReplyTimeout)
}

private final class DummyAgentEndpoint: NSObject, AgentPassAgentXPCProtocol, @unchecked Sendable {
    private let denySigning: Bool
    private let lock = NSLock()
    private var invokedValues: [String] = []
    init(denySigning: Bool = false) { self.denySigning = denySigning }

    var invoked: [String] { lock.withLock { invokedValues } }

    private func record(_ selector: String) {
        lock.withLock { invokedValues.append(selector) }
    }

    func bootstrapAgent(_ request: AgentPassAgentBootstrapRequest, withReply reply: @escaping (AgentPassAgentBootstrapResponse?, NSError?) -> Void) {
        record("bootstrapAgent:withReply:")
        reply(nil, stableError())
    }
    func startAgentSession(_ request: AgentPassAgentSessionRequest, withReply reply: @escaping (AgentPassAgentSessionResponse?, NSError?) -> Void) {
        record("startAgentSession:withReply:")
        reply(nil, stableError())
    }
    func agentSessionStatus(_ request: AgentPassAgentSessionStatusRequest, withReply reply: @escaping (AgentPassAgentSessionStatusResponse?, NSError?) -> Void) {
        record("agentSessionStatus:withReply:")
        reply(AgentPassAgentSessionStatusResponse(sessionID: harnessSessionID, status: "active", expiresAtMilliseconds: 4_000_000_000_000, maxSignatures: 2, usedSignatures: 0), nil)
    }
    func signGitCommit(_ request: AgentPassAgentSignRequest, withReply reply: @escaping (AgentPassAgentSignResponse?, NSError?) -> Void) {
        record("signGitCommit:withReply:")
        if denySigning { reply(nil, stableError()) }
        else { reply(AgentPassAgentSignResponse(requestID: harnessRequestID, signature: Data(repeating: 0x33, count: 64), remainingSignatures: 1), nil) }
    }
    func closeAgentSession(_ request: AgentPassAgentCloseSessionRequest, withReply reply: @escaping (AgentPassAgentCloseSessionResponse?, NSError?) -> Void) {
        record("closeAgentSession:withReply:")
        reply(nil, stableError())
    }

    private func stableError() -> NSError {
        NSError(domain: harnessErrorDomain, code: 1001, userInfo: [NSLocalizedDescriptionKey: "agent operation denied"])
    }
}

private final class AgentNegativeHarness: NSObject, NSXPCListenerDelegate {
    let endpoint: DummyAgentEndpoint
    private let listener = NSXPCListener.anonymous()
    private var connections: [NSXPCConnection] = []
    private var acceptedConnections: [NSXPCConnection] = []
    private var closed = false

    init(endpoint: DummyAgentEndpoint = DummyAgentEndpoint()) {
        self.endpoint = endpoint
        super.init()
        listener.delegate = self
        listener.resume()
    }
    func connection(interface: NSXPCInterface) -> NSXPCConnection {
        let value = NSXPCConnection(listenerEndpoint: listener.endpoint)
        value.remoteObjectInterface = interface
        value.resume()
        connections.append(value)
        return value
    }
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.exportedInterface = AgentPassAgentXPCInterface.make()
        connection.exportedObject = endpoint
        acceptedConnections.append(connection)
        connection.resume()
        return true
    }

    func close() {
        guard !closed else { return }
        closed = true
        listener.delegate = nil
        connections.forEach { $0.invalidate() }
        acceptedConnections.forEach { $0.invalidate() }
        connections.removeAll()
        acceptedConnections.removeAll()
        listener.invalidate()
    }

    deinit { close() }
}

private func protocolSelectors(_ proto: Protocol) -> Set<String> {
    var count: UInt32 = 0
    guard let descriptions = protocol_copyMethodDescriptionList(proto, true, true, &count) else { return [] }
    defer { free(descriptions) }
    return Set((0..<Int(count)).compactMap { descriptions[$0].name.map(NSStringFromSelector) })
}

@Test func agentAnonymousXPCInvokesOnlyTheExactAgentStatusSelector() async throws {
    let harness = AgentNegativeHarness()
    defer { harness.close() }
    let connection = harness.connection(interface: AgentPassAgentXPCInterface.make())
    let request = try #require(AgentPassAgentSessionStatusRequest(sessionID: harnessSessionID))
    let result = HarnessResultBox<AgentPassAgentSessionStatusResponse>()
    await withCheckedContinuation { continuation in
        let reply = HarnessContinuation(continuation)
        enforceHarnessReplyTimeout(reply)
        let proxy = connection.remoteObjectProxyWithErrorHandler { _ in
            reply.resume()
        } as! AgentPassAgentXPCProtocol
        proxy.agentSessionStatus(request) { response, _ in
            if let response { result.set(response) }
            reply.resume()
        }
    }
    #expect(result.get()?.status == "active")
    #expect(harness.endpoint.invoked == ["agentSessionStatus:withReply:"])
}

@Test func agentInterfaceHasNoManagementSelectorAndManagementProxyCannotDispatch() async {
    let interface = AgentPassAgentXPCInterface.make()
    let agentSelectors = protocolSelectors(AgentPassAgentXPCProtocol.self)
    let managementSelectors = protocolSelectors(AgentPassNativeServiceProtocol.self)
    #expect(agentSelectors == ["bootstrapAgent:withReply:", "startAgentSession:withReply:", "agentSessionStatus:withReply:", "signGitCommit:withReply:", "closeAgentSession:withReply:"])
    #expect(agentSelectors.intersection(managementSelectors).isEmpty)
    #expect(interface.classes(for: #selector(AgentPassAgentXPCProtocol.signGitCommit(_:withReply:)), argumentIndex: 0, ofReply: false).isEmpty == false)

    let harness = AgentNegativeHarness()
    defer { harness.close() }
    let connection = harness.connection(interface: NSXPCInterface(with: AgentPassNativeServiceProtocol.self))
    let result = HarnessResultBox<NSError>()
    await withCheckedContinuation { continuation in
        let reply = HarnessContinuation(continuation)
        enforceHarnessReplyTimeout(reply)
        let proxy = connection.remoteObjectProxyWithErrorHandler { error in
            result.set(error as NSError)
            reply.resume()
        } as! AgentPassNativeServiceProtocol
        proxy.sign(request: Data("management-probe".utf8) as NSData) { _, error in
            result.set(error ?? NSError(domain: harnessErrorDomain, code: 1999))
            reply.resume()
        }
    }
    let error = result.get()
    #expect(error != nil)
    #expect(error?.code != 1999)
    #expect(harness.endpoint.invoked.isEmpty)
}

@Test func agentDeniedSignReturnsAStableFailClosedNSError() async throws {
    let harness = AgentNegativeHarness(endpoint: DummyAgentEndpoint(denySigning: true))
    defer { harness.close() }
    let connection = harness.connection(interface: AgentPassAgentXPCInterface.make())
    let request = try #require(AgentPassAgentSignRequest(sessionID: harnessSessionID, requestID: harnessRequestID, capabilityID: harnessCapabilityID, capability: try harnessCapability(), commitPayload: Data("tree abc\n\nmessage\n".utf8), requestNonce: Data(repeating: 1, count: 32), createdAtMilliseconds: 4_000_000_000_000))
    let result = HarnessResultBox<NSError>()
    await withCheckedContinuation { continuation in
        let reply = HarnessContinuation(continuation)
        enforceHarnessReplyTimeout(reply)
        let proxy = connection.remoteObjectProxyWithErrorHandler { error in
            result.set(error as NSError)
            reply.resume()
        } as! AgentPassAgentXPCProtocol
        proxy.signGitCommit(request) { _, error in
            if let error { result.set(error) }
            reply.resume()
        }
    }
    let error = try #require(result.get())
    #expect(error.domain == harnessErrorDomain)
    #expect(error.code == 1001)
    #expect(error.localizedDescription == "agent operation denied")
    #expect(harness.endpoint.invoked == ["signGitCommit:withReply:"])
}
