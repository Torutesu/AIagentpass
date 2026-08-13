import AgentPassNativeCore
import Foundation
import ObjectiveC.runtime
import Testing

private let harnessSessionID = "33333333-3333-4333-8333-333333333333"
private let harnessRequestID = "55555555-5555-4555-8555-555555555555"
private let harnessCapabilityID = "66666666-6666-4666-8666-666666666666"
private let harnessErrorDomain = "dev.agentpass.agent.xpc.harness"
// The full native suite deliberately runs hundreds of filesystem and crypto
// tests in parallel. Give the real XPC daemon enough scheduling headroom while
// retaining a finite failure bound for this integration harness.
private let harnessReplyTimeout: DispatchTimeInterval = .seconds(15)

private final class HarnessResultBox<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Value?
    func set(_ value: Value) { lock.withLock { self.value = value } }
    func get() -> Value? { lock.withLock { value } }
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
        connection.resume()
        return true
    }
    deinit { connections.forEach { $0.invalidate() }; listener.invalidate() }
}

private func protocolSelectors(_ proto: Protocol) -> Set<String> {
    var count: UInt32 = 0
    guard let descriptions = protocol_copyMethodDescriptionList(proto, true, true, &count) else { return [] }
    defer { free(descriptions) }
    return Set((0..<Int(count)).compactMap { descriptions[$0].name.map(NSStringFromSelector) })
}

@Test func agentAnonymousXPCInvokesOnlyTheExactAgentStatusSelector() throws {
    let harness = AgentNegativeHarness()
    let connection = harness.connection(interface: AgentPassAgentXPCInterface.make())
    let proxy = connection.remoteObjectProxyWithErrorHandler { _ in } as! AgentPassAgentXPCProtocol
    let request = try #require(AgentPassAgentSessionStatusRequest(sessionID: harnessSessionID))
    let result = HarnessResultBox<AgentPassAgentSessionStatusResponse>()
    let done = DispatchSemaphore(value: 0)
    proxy.agentSessionStatus(request) { response, _ in
        if let response { result.set(response) }
        done.signal()
    }
    #expect(done.wait(timeout: .now() + harnessReplyTimeout) == .success)
    #expect(result.get()?.status == "active")
    #expect(harness.endpoint.invoked == ["agentSessionStatus:withReply:"])
}

@Test func agentInterfaceHasNoManagementSelectorAndManagementProxyCannotDispatch() {
    let interface = AgentPassAgentXPCInterface.make()
    let agentSelectors = protocolSelectors(AgentPassAgentXPCProtocol.self)
    let managementSelectors = protocolSelectors(AgentPassNativeServiceProtocol.self)
    #expect(agentSelectors == ["bootstrapAgent:withReply:", "startAgentSession:withReply:", "agentSessionStatus:withReply:", "signGitCommit:withReply:", "closeAgentSession:withReply:"])
    #expect(agentSelectors.intersection(managementSelectors).isEmpty)
    #expect(interface.classes(for: #selector(AgentPassAgentXPCProtocol.signGitCommit(_:withReply:)), argumentIndex: 0, ofReply: false).isEmpty == false)

    let harness = AgentNegativeHarness()
    let connection = harness.connection(interface: NSXPCInterface(with: AgentPassNativeServiceProtocol.self))
    let result = HarnessResultBox<NSError>()
    let done = DispatchSemaphore(value: 0)
    let proxy = connection.remoteObjectProxyWithErrorHandler { error in result.set(error as NSError); done.signal() } as! AgentPassNativeServiceProtocol
    proxy.sign(request: Data("management-probe".utf8) as NSData) { _, error in
        result.set(error ?? NSError(domain: harnessErrorDomain, code: 1999)); done.signal()
    }
    #expect(done.wait(timeout: .now() + harnessReplyTimeout) == .success)
    #expect(result.get() != nil)
    #expect(result.get()?.code != 1999)
    #expect(harness.endpoint.invoked.isEmpty)
}

@Test func agentDeniedSignReturnsAStableFailClosedNSError() throws {
    let harness = AgentNegativeHarness(endpoint: DummyAgentEndpoint(denySigning: true))
    let connection = harness.connection(interface: AgentPassAgentXPCInterface.make())
    let proxy = connection.remoteObjectProxyWithErrorHandler { _ in } as! AgentPassAgentXPCProtocol
    let request = try #require(AgentPassAgentSignRequest(sessionID: harnessSessionID, requestID: harnessRequestID, capabilityID: harnessCapabilityID, commitPayload: Data("tree abc\n\nmessage\n".utf8), requestNonce: Data(repeating: 1, count: 32), createdAtMilliseconds: 4_000_000_000_000))
    let result = HarnessResultBox<NSError>()
    let done = DispatchSemaphore(value: 0)
    proxy.signGitCommit(request) { _, error in if let error { result.set(error) }; done.signal() }
    #expect(done.wait(timeout: .now() + harnessReplyTimeout) == .success)
    let error = try #require(result.get())
    #expect(error.domain == harnessErrorDomain)
    #expect(error.code == 1001)
    #expect(error.localizedDescription == "agent operation denied")
    #expect(harness.endpoint.invoked == ["signGitCommit:withReply:"])
}
