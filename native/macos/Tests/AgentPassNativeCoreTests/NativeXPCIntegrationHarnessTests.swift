import AgentPassNativeCore
import Foundation
import Testing

private let xpcHarnessErrorDomain = "AgentPass.XPCIntegrationHarness"
private let xpcHarnessReplyTimeout: DispatchTimeInterval = .seconds(15)

private final class SendableXPCProxy: @unchecked Sendable {
    let value: AgentPassNativeServiceProtocol
    init(_ value: AgentPassNativeServiceProtocol) { self.value = value }
}

private struct XPCSignResult: Sendable {
    let signature: String?
    let errorDomain: String?
    let errorCode: Int?
    let errorDescription: String?
}

/// This is a deterministic local XPC boundary harness. It deliberately uses
/// an anonymous NSXPCListener, so the test exercises Foundation's actual XPC
/// marshalling and remote proxy callbacks without requiring a signed launchd
/// Mach service or Secure Enclave hardware.
private final class NativeXPCIntegrationHarness: NSObject, NSXPCListenerDelegate {
    let service: NativeXPCHarnessService
    private let listener: NSXPCListener
    private(set) var connection: NSXPCConnection!
    private var acceptedConnections: [NSXPCConnection] = []
    private var closed = false

    init(service: NativeXPCHarnessService = NativeXPCHarnessService()) {
        self.service = service
        listener = NSXPCListener.anonymous()
        super.init()
        listener.delegate = self
        listener.resume()
        connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
        connection.remoteObjectInterface = NSXPCInterface(with: AgentPassNativeServiceProtocol.self)
        connection.resume()
        print("XPC integration harness: anonymous NSXPC listener active; launchd privileged Mach-service, code-signing requirement, and Secure Enclave are intentionally unavailable in this deterministic test.")
    }

    func proxy() -> AgentPassNativeServiceProtocol {
        connection.remoteObjectProxyWithErrorHandler { _ in } as! AgentPassNativeServiceProtocol
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        newConnection.exportedInterface = NSXPCInterface(with: AgentPassNativeServiceProtocol.self)
        newConnection.exportedObject = service
        acceptedConnections.append(newConnection)
        newConnection.resume()
        return true
    }

    func close() {
        guard !closed else { return }
        closed = true
        listener.delegate = nil
        connection.invalidate()
        acceptedConnections.forEach { $0.invalidate() }
        acceptedConnections.removeAll()
        listener.invalidate()
    }

    deinit { close() }
}

private final class NativeXPCHarnessService: NSObject, AgentPassNativeServiceProtocol, @unchecked Sendable {
    private let lock = NSLock()
    private var refreshState = "idle"
    private var refreshGeneration: Int64 = 0
    private var refreshInFlight = false
    private var refreshStarts = 0
    private var refreshCallers = 0
    private var refreshWaiters: [(NSData?, NSError?) -> Void] = []

    func beginRefreshAwaitingConvergence() {
        lock.withLock {
            refreshState = "hinted"
            refreshInFlight = true
            refreshStarts += 1
        }
    }

    func releaseRefreshConvergence() {
        let waiters: [(NSData?, NSError?) -> Void] = lock.withLock {
            refreshState = "idle"
            refreshGeneration += 1
            refreshInFlight = false
            let pending = refreshWaiters
            refreshWaiters.removeAll()
            return pending
        }
        let response = try? JSONSerialization.data(withJSONObject: [
            "status": "updated",
            "refresh_state": "idle",
            "generation": refreshGeneration
        ], options: [.sortedKeys])
        waiters.forEach { $0(response as NSData?, nil) }
    }

    var snapshot: (state: String, generation: Int64, inFlight: Bool, starts: Int, callers: Int) {
        lock.withLock { (refreshState, refreshGeneration, refreshInFlight, refreshStarts, refreshCallers) }
    }

    func health(withReply reply: @escaping (NSDictionary) -> Void) {
        let current = snapshot
        reply([
            "ok": true,
            "protocol_version": 13,
            "control_configured": true,
            "control_refresh_configured": true,
            "control_operational": current.state == "idle",
            "control_refresh_in_flight": current.inFlight,
            "control_refresh_state": current.state,
            "control_refresh_generation": current.generation
        ])
    }

    func controlStatus(withReply reply: @escaping (NSData?, NSError?) -> Void) {
        let current = snapshot
        do {
            let data = try JSONSerialization.data(withJSONObject: [
                "version": 1,
                "configured": true,
                "operational": current.state == "idle",
                "refresh_state": current.state,
                "refresh_generation": current.generation,
                "refresh_in_flight": current.inFlight
            ], options: [.sortedKeys])
            reply(data as NSData, nil)
        } catch {
            reply(nil, harnessError("status encoding failed"))
        }
    }

    func refreshControl(withReply reply: @escaping (NSData?, NSError?) -> Void) {
        let shouldWait = lock.withLock { () -> Bool in
            refreshCallers += 1
            guard refreshInFlight else { return false }
            refreshWaiters.append(reply)
            return true
        }
        if shouldWait { return }
        reply(nil, harnessError("refresh is not configured"))
    }

    func sign(request: NSData, withReply reply: @escaping (NSString?, NSError?) -> Void) {
        let current = snapshot
        guard current.state == "idle" && !current.inFlight else {
            reply(nil, harnessError("signing denied while durable refresh state is awaiting convergence"))
            return
        }
        reply("harness-signature" as NSString, nil)
    }

    // The harness only exposes the four calls under test. All other protocol
    // selectors fail closed so accidental test expansion cannot become a
    // silent no-op.
    func publicKey(withReply reply: @escaping (NSString?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func auditStatus(withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func auditPublicKey(withReply reply: @escaping (NSString?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func createAuditCheckpoint(withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func rotateAudit(withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func rotateAuditEvidence(withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func keyLifecycleStatus(withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func stageKey(role: NSString, withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func approvalKeyStagePlan(withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func stageApprovalKey(generation: Int, applicationTag: NSString, publicKey: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func beginKeyActivation(role: NSString, generation: Int, reason: NSString, withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func completeKeyActivation(challengeID: NSString, approvalSignature: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func completeApprovalKeyActivation(challengeID: NSString, oldSignature: NSData, newSignature: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func beginKeyAbort(role: NSString, generation: Int, reason: NSString, withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func completeKeyAbort(challengeID: NSString, approvalSignature: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func beginKeyDeletion(role: NSString, generation: Int, reason: NSString, minimumRetentionSeconds: Int, proof: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func completeKeyDeletion(challengeID: NSString, approvalSignature: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func beginRecovery(role: NSString, withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func prepareRecoveryInstallation(evidence: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func completeRecovery(challengeID: NSString, localSignature: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func prepareAuditRecoveryInstallation(evidence: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func completeAuditRecovery(challengeID: NSString, localSignature: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func abortExpiredAuditRecovery(withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func auditRecoveryStatus(withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func auditAnchorStatus(withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func pushAuditAnchor(withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func prepareAuditPrune(request: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func submitAuditPrune(withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func executeAuditPrune(withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func auditPruneStatus(withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func beginSession(agentID: NSString, ttlSeconds: Int, withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func completeSession(challenge: NSData, signature: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func revokeSessions(withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func revokeSessions(agentID: NSString, withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func validateSession(token: NSString?, agentID: NSString, withReply reply: @escaping (Bool, NSError?) -> Void) { reply(false, unsupportedError()) }
    func applyControlBundle(bundle: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) { reply(nil, unsupportedError()) }
    func validateControl(agentID: NSString, withReply reply: @escaping (Bool, NSError?) -> Void) { reply(false, unsupportedError()) }
}

private func harnessError(_ message: String) -> NSError {
    NSError(domain: xpcHarnessErrorDomain, code: 1001, userInfo: [NSLocalizedDescriptionKey: message])
}

private func unsupportedError() -> NSError {
    NSError(domain: xpcHarnessErrorDomain, code: 1000, userInfo: [NSLocalizedDescriptionKey: "selector is outside this integration harness"])
}

private func waitForDataCall(
    _ invoke: (@escaping (NSData?, NSError?) -> Void) -> Void
) async throws -> Data {
    try await waitForXPCReply { complete in
        invoke { data, callbackError in
            if let callbackError {
                complete(.failure(callbackError))
            } else if let data {
                complete(.success(data as Data))
            } else {
                complete(.failure(harnessError("XPC returned no data")))
            }
        }
    }
}

private final class XPCReplyGate<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var completion: ((Result<Value, Error>) -> Void)?
    private var timeoutWorkItem: DispatchWorkItem?

    init(completion: @escaping (Result<Value, Error>) -> Void) {
        self.completion = completion
    }

    func armTimeout() {
        let workItem = DispatchWorkItem { [weak self] in
            self?.complete(.failure(harnessError("XPC reply timed out")))
        }
        lock.withLock { timeoutWorkItem = workItem }
        DispatchQueue.global(qos: .userInitiated).asyncAfter(
            deadline: .now() + xpcHarnessReplyTimeout,
            execute: workItem
        )
    }

    func complete(_ result: Result<Value, Error>) {
        let pending: (((Result<Value, Error>) -> Void)?, DispatchWorkItem?) = lock.withLock {
            defer {
                completion = nil
                timeoutWorkItem = nil
            }
            return (completion, timeoutWorkItem)
        }
        pending.1?.cancel()
        pending.0?(result)
    }
}

private func waitForXPCReply<Value: Sendable>(
    _ invoke: (@escaping (Result<Value, Error>) -> Void) -> Void
) async throws -> Value {
    try await withCheckedThrowingContinuation { continuation in
        let gate = XPCReplyGate<Value> { result in
            continuation.resume(with: result)
        }
        gate.armTimeout()
        invoke { result in gate.complete(result) }
    }
}

private func waitForHealthCall(_ proxy: AgentPassNativeServiceProtocol) async throws -> [String: Any] {
    let data: Data = try await waitForDataCall { reply in
        proxy.health { health in
            do {
                reply(try JSONSerialization.data(withJSONObject: health, options: [.sortedKeys]) as NSData, nil)
            } catch {
                reply(nil, error as NSError)
            }
        }
    }
    guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw harnessError("XPC returned an invalid health response")
    }
    return object
}

private func waitForSignCall(_ proxy: AgentPassNativeServiceProtocol) async throws -> XPCSignResult {
    try await waitForXPCReply { complete in
        proxy.sign(request: Data("commit".utf8) as NSData) { signature, callbackError in
            complete(.success(XPCSignResult(
                signature: signature as String?,
                errorDomain: callbackError?.domain,
                errorCode: callbackError?.code,
                errorDescription: callbackError?.localizedDescription
            )))
        }
    }
}

@Test func nativeXPCHealthAndStatusRoundTrip() async throws {
    let harness = NativeXPCIntegrationHarness()
    defer { harness.close() }
    let proxy = harness.proxy()
    let health = try await waitForHealthCall(proxy)
    #expect(health["ok"] as? Bool == true)
    #expect(health["protocol_version"] as? Int == 13)
    #expect(health["control_refresh_state"] as? String == "idle")

    let status = try await waitForDataCall { proxy.controlStatus(withReply: $0) }
    let object = try #require(JSONSerialization.jsonObject(with: status) as? [String: Any])
    #expect(object["refresh_state"] as? String == "idle")
    #expect(object["configured"] as? Bool == true)
}

@Test func nativeXPCManualRefreshJoinsAndDeniesSigningDuringConvergence() async throws {
    let harness = NativeXPCIntegrationHarness()
    defer { harness.close() }
    let proxy = harness.proxy()
    let concurrentProxy = SendableXPCProxy(proxy)
    harness.service.beginRefreshAwaitingConvergence()

    async let first = waitForDataCall { concurrentProxy.value.refreshControl(withReply: $0) }
    async let second = waitForDataCall { concurrentProxy.value.refreshControl(withReply: $0) }

    try await waitUntilXPC { harness.service.snapshot.callers == 2 }
    let health = try await waitForHealthCall(proxy)
    #expect(health["control_refresh_in_flight"] as? Bool == true)
    #expect(health["control_refresh_state"] as? String == "hinted")
    #expect(health["control_operational"] as? Bool == false)
    #expect(harness.service.snapshot.starts == 1)

    let signing = try await waitForSignCall(proxy)
    #expect(signing.signature == nil)
    #expect(signing.errorDomain == xpcHarnessErrorDomain)
    #expect(signing.errorCode == 1001)
    #expect(signing.errorDescription?.contains("awaiting convergence") == true)

    harness.service.releaseRefreshConvergence()
    let completedResults = try await [first, second]
    #expect(completedResults.count == 2)
    for data in completedResults {
        let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(object["status"] as? String == "updated")
        #expect(object["refresh_state"] as? String == "idle")
    }
    #expect(harness.service.snapshot.starts == 1)
    #expect(harness.service.snapshot.state == "idle")
    let finalHealth = try await waitForHealthCall(proxy)
    #expect(finalHealth["control_operational"] as? Bool == true)
}

private func waitUntilXPC(
    _ predicate: @escaping () -> Bool
) async throws {
    for _ in 0..<200 {
        if predicate() { return }
        try await Task.sleep(nanoseconds: 5_000_000)
    }
    throw harnessError("XPC harness did not reach the expected state")
}
