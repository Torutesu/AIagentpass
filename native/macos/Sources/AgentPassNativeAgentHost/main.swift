import AgentPassNativeCore
import Darwin
import Foundation
import Security

enum AgentHostContract {
    static let machServiceName = "dev.agentpass.agent-session"
    static let probeSessionID = "00000000-0000-4000-8000-000000000000"
    static let activationDocumentFD: Int32 = 3
    static let nonceBytes = 32
    static let xpcTimeout: DispatchTimeInterval = .seconds(5)
    static let statusPollInterval: DispatchTimeInterval = .seconds(1)
    static let expiryGraceSeconds: Int64 = 5
}

private struct ProbeOutput: Encodable {
    let ok: Bool
    let operation: String
    let service: String
    let sessionStatus: String?
    let error: String?

    enum CodingKeys: String, CodingKey {
        case ok, operation, service, error
        case sessionStatus = "session_status"
    }
}

private struct ActivationOutput: Encodable {
    let ok: Bool
    let operation: String
    let status: String
    let error: String?
}

private func writeActivation(_ output: ActivationOutput) {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = (try? encoder.encode(output)) ?? Data("{\"error\":\"encoding_failure\",\"ok\":false}\n".utf8)
    FileHandle.standardOutput.write(data + Data("\n".utf8))
}

private func runHostLaunchPlan(projectPath: String) -> Never {
    let handoff: NativeAgentLaunchAuthorityHandoff
    do {
        handoff = try readLaunchAuthorityHandoff()
    } catch let error as NativeAgentLaunchAuthorityHandoffError {
        emitActivation(
            ActivationOutput(
                ok: false,
                operation: "host-launch",
                status: "rejected",
                error: "launch_plan_authority_" + error.stableCode
            ),
            status: 2
        )
    } catch {
        emitActivation(
            ActivationOutput(ok: false, operation: "host-launch", status: "rejected", error: "launch_plan_authority_rejected"),
            status: 2
        )
    }

    let plan: NativeAgentHostLaunchPlan
    do {
        plan = try NativeAgentHostLaunchPlan(projectPath: projectPath, authorityHandoff: handoff)
    } catch {
        emitActivation(
            ActivationOutput(ok: false, operation: "host-launch", status: "rejected", error: "launch_plan_project_rejected"),
            status: 2
        )
    }

    do {
        let serviceClient = AgentHostServiceClient(handoff: handoff)
        let terminalController = ActivationSignalController()
        terminalController.install()
        defer { terminalController.shutdown() }
        serviceClient.connection.invalidationHandler = {
            terminalController.requestStop()
        }
        terminalController.setConnection(serviceClient.connection)
        let connection = try NativeAgentHostConnectionBinding(
            connectionID: "agent-host",
            agentID: handoff.agentID
        )
        let runtime = try NativeAgentHostRuntime(
            plan: plan,
            connection: connection,
            supervisor: NativeAgentHostChildSupervisor(),
            adapter: AgentHostServiceLifecycleAdapter(client: serviceClient)
        )
        let coordinator = try runtime.start()
        terminalController.markBootstrapKnown()
        terminalController.setStopHandler {
            _ = try? coordinator.requestTermination()
        }
        // Keep the Host process alive for the entire child/session lifetime.
        // The authenticated child XPC client is connection-owned by the
        // supervisor; returning from this function would invalidate it and
        // silently strand the child without its signing broker.
        writeActivation(ActivationOutput(ok: true, operation: "host-launch", status: "active", error: nil))
        _ = try coordinator.waitForChild()
        writeActivation(ActivationOutput(ok: true, operation: "host-launch", status: "closed", error: nil))
        exit(0)
    } catch let error as NativeAgentHostLifecycleError where error == .sessionCloseFailed {
        emitActivation(
            ActivationOutput(ok: false, operation: "host-launch", status: "error", error: "agent_session_close_failed"),
            status: 1
        )
    } catch let error as NativeAgentHostLifecycleError where error == .signalFailed {
        emitActivation(
            ActivationOutput(ok: false, operation: "host-launch", status: "error", error: "host_child_termination_failed"),
            status: 1
        )
    } catch let error as NativeAgentHostLifecycleAdapterError where error == .unavailable {
        emitActivation(
            ActivationOutput(ok: false, operation: "host-launch", status: "rejected", error: "service_binding_contract_unavailable"),
            status: 2
        )
    } catch {
        emitActivation(
            ActivationOutput(ok: false, operation: "host-launch", status: "error", error: "host_launch_rejected"),
            status: 1
        )
    }
}

private final class ProbeResultBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: ProbeOutput?

    func set(_ value: ProbeOutput) {
        lock.lock()
        defer { lock.unlock() }
        self.value = value
    }

    func get() -> ProbeOutput? {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

private func readLaunchAuthorityHandoff(
    from descriptor: Int32 = AgentHostContract.activationDocumentFD
) throws -> NativeAgentLaunchAuthorityHandoff {
    var descriptorInfo = stat()
    guard Darwin.fstat(descriptor, &descriptorInfo) == 0 else {
        throw NativeAgentLaunchAuthorityHandoffError.malformed
    }
    let fileType = descriptorInfo.st_mode & S_IFMT
    guard fileType == S_IFIFO || fileType == S_IFSOCK else {
        // Never consume authority from a seekable regular file or another
        // replayable descriptor type.
        throw NativeAgentLaunchAuthorityHandoffError.malformed
    }
    var data = Data()
    var buffer = [UInt8](repeating: 0, count: 4 * 1024)
    defer {
        _ = Darwin.close(descriptor)
        data.resetBytes(in: data.startIndex..<data.endIndex)
        _ = buffer.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) }
    }
    while true {
        let count = buffer.withUnsafeMutableBytes { bytes in
            Darwin.read(descriptor, bytes.baseAddress, bytes.count)
        }
        if count == 0 { break }
        if count < 0 {
            if errno == EINTR { continue }
            throw NativeAgentLaunchAuthorityHandoffError.malformed
        }
        data.append(buffer, count: count)
        if data.count > NativeAgentLaunchAuthorityHandoff.maximumDocumentBytes {
            throw NativeAgentLaunchAuthorityHandoffError.oversized
        }
    }
    return try NativeAgentLaunchAuthorityHandoff.decode(data)
}

private func emitProbe(_ output: ProbeOutput, status: Int32) -> Never {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = (try? encoder.encode(output)) ?? Data("{\"ok\":false,\"error\":\"encoding_failure\"}".utf8)
    FileHandle.standardOutput.write(data + Data("\n".utf8))
    exit(status)
}

private func emitActivation(_ output: ActivationOutput, status: Int32) -> Never {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = (try? encoder.encode(output)) ?? Data("{\"error\":\"encoding_failure\",\"ok\":false,\"operation\":\"qualification-activate\",\"status\":\"error\"}".utf8)
    FileHandle.standardOutput.write(data + Data("\n".utf8))
    exit(status)
}

private func randomNonce() -> Data? {
    var nonce = Data(repeating: 0, count: AgentHostContract.nonceBytes)
    let result = nonce.withUnsafeMutableBytes { bytes in
        SecRandomCopyBytes(kSecRandomDefault, bytes.count, bytes.baseAddress!)
    }
    return result == errSecSuccess ? nonce : nil
}

/// The launch command owns one authenticated Service connection. All
/// lifecycle hooks below use that same connection; no session identifier or
/// binding material is accepted from argv, environment, or the child.
private final class AgentHostServiceClient: @unchecked Sendable {
    let connection: NSXPCConnection
    let proxy: AgentPassAgentXPCProtocol
    let handoff: NativeAgentLaunchAuthorityHandoff

    init(handoff: NativeAgentLaunchAuthorityHandoff) {
        self.handoff = handoff
        let connection = NSXPCConnection(machServiceName: AgentHostContract.machServiceName, options: .privileged)
        connection.remoteObjectInterface = AgentPassAgentXPCInterface.make()
        connection.resume()
        self.connection = connection
        self.proxy = connection.remoteObjectProxyWithErrorHandler { _ in } as! AgentPassAgentXPCProtocol
    }

    deinit { connection.invalidate() }

    func close(sessionID: String, reason: AgentPassAgentSessionCloseReason = .clientShutdown) -> Bool {
        guard let request = AgentPassAgentCloseSessionRequest(
            sessionID: sessionID,
            reason: reason.rawValue
        ) else { return false }
        guard case .response = waitForReply({ reply in
            proxy.closeAgentSession(request, withReply: reply)
        }) else { return false }
        return true
    }
}

private struct AgentHostServiceLifecycleAdapter: NativeAgentHostLifecycleAdapter {
    let client: AgentHostServiceClient

    func hooks(for plan: NativeAgentHostLaunchPlan) throws -> NativeAgentHostLifecycleCoordinatorHooks {
        guard plan.authorityHandoff == client.handoff else {
            throw NativeAgentHostLifecycleAdapterError.unavailable
        }

        return NativeAgentHostLifecycleCoordinatorHooks(
            bootstrap: { connection, context in
                guard connection.agentID == plan.authorityHandoff.agentID else {
                    throw NativeAgentHostLifecycleAdapterError.unavailable
                }
                guard let nonce = randomNonce(),
                      let request = AgentPassAgentBootstrapRequest(
                        agentID: connection.agentID,
                        adapterKind: context.adapter.rawValue,
                        requestedTTLSeconds: context.requestedTTLSeconds,
                        bootstrapNonce: nonce
                      ) else {
                    throw NativeAgentHostLifecycleAdapterError.unavailable
                }
                guard case .response(let bootstrap) = waitForReply({ reply in
                    client.proxy.bootstrapAgent(request, withReply: reply)
                }),
                let sessionRequest = AgentPassAgentSessionRequest(
                    bootstrapID: bootstrap.bootstrapID,
                    proof: plan.authorityHandoff.proof
                ) else {
                    throw NativeAgentHostLifecycleAdapterError.unavailable
                }
                guard case .response(let session) = waitForReply({ reply in
                    client.proxy.startAgentSession(sessionRequest, withReply: reply)
                }),
                let binding = try? NativeAgentSessionBinding(
                    agentID: connection.agentID,
                    deviceID: session.deviceID,
                    processBindingDigest: session.processBindingDigest,
                    ancestryBindingDigest: session.ancestryBindingDigest,
                    worktreeBindingDigest: session.worktreeBindingDigest,
                    controlSequence: session.controlSequence,
                    authorityGeneration: session.authorityGeneration,
                    keyGeneration: session.keyGeneration
                ),
                let activation = try? NativeAgentHostQualifiedSessionActivation(
                    sessionID: session.sessionID,
                    binding: binding
                ) else {
                    throw NativeAgentHostLifecycleAdapterError.unavailable
                }
                let sessionID = session.sessionID
                return NativeAgentHostLifecycleBootstrapReceipt(
                    activation: activation,
                    rollback: { _ = client.close(sessionID: sessionID) }
                )
            },
            reobserveAuthority: { identity in
                guard let request = AgentPassAgentSessionStatusRequest(sessionID: identity.sessionID) else {
                    throw NativeAgentHostLifecycleAdapterError.unavailable
                }
                guard case .response(let status) = waitForReply({ reply in
                    client.proxy.agentSessionStatus(request, withReply: reply)
                }) else {
                    throw NativeAgentHostLifecycleAdapterError.unavailable
                }
                return status.status == "active" ? .authorized : .lost
            },
            close: { identity, _ in
                guard client.close(sessionID: identity.sessionID) else {
                    throw NativeAgentHostLifecycleAdapterError.unavailable
                }
            }
        )
    }
}

private enum XPCReplyResult<T> {
    case response(T)
    case remoteFailure
    case timedOut
}

private func waitForReply<T>(
    _ invoke: (@escaping (T?, NSError?) -> Void) -> Void
) -> XPCReplyResult<T> {
    let semaphore = DispatchSemaphore(value: 0)
    let lock = NSLock()
    var result: XPCReplyResult<T>?
    var completed = false
    let complete: (T?, NSError?) -> Void = { response, _ in
        lock.lock()
        if !completed {
            completed = true
            result = response.map(XPCReplyResult.response) ?? .remoteFailure
            semaphore.signal()
        }
        lock.unlock()
    }
    invoke(complete)
    guard semaphore.wait(timeout: .now() + AgentHostContract.xpcTimeout) == .success else {
        return .timedOut
    }
    lock.lock()
    defer { lock.unlock() }
    return result ?? .remoteFailure
}

/// Converts process signals into a cooperative stop request. The signal
/// handlers are installed before any bootstrap/start request so a transport
/// stall cannot leave an active session waiting for its full TTL.
private final class ActivationSignalController: @unchecked Sendable {
    let wake = DispatchSemaphore(value: 0)

    private let lock = NSLock()
    private var stopRequested = false
    private var bootstrapKnown = false
    private var connection: NSXPCConnection?
    private var stopHandler: (@Sendable () -> Void)?
    private var termSource: DispatchSourceSignal?
    private var intSource: DispatchSourceSignal?

    func install() {
        signal(SIGTERM, SIG_IGN)
        signal(SIGINT, SIG_IGN)
        let queue = DispatchQueue(label: "dev.agentpass.agent-host.signals")
        let termSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: queue)
        let intSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: queue)
        termSource.setEventHandler { [weak self] in self?.requestStop() }
        intSource.setEventHandler { [weak self] in self?.requestStop() }
        lock.lock()
        self.termSource = termSource
        self.intSource = intSource
        let alreadyStopped = stopRequested
        lock.unlock()
        termSource.resume()
        intSource.resume()
        if alreadyStopped { requestStop() }
    }

    func setConnection(_ connection: NSXPCConnection) {
        lock.lock()
        self.connection = connection
        let shouldInvalidate = stopRequested && !bootstrapKnown
        lock.unlock()
        if shouldInvalidate { connection.invalidate() }
    }

    func markBootstrapKnown() {
        lock.lock()
        bootstrapKnown = true
        lock.unlock()
    }

    func setStopHandler(_ handler: @escaping @Sendable () -> Void) {
        lock.lock()
        stopHandler = handler
        let alreadyStopped = stopRequested
        lock.unlock()
        if alreadyStopped { handler() }
    }

    var isStopRequested: Bool {
        lock.lock()
        defer { lock.unlock() }
        return stopRequested
    }

    func requestStop() {
        lock.lock()
        stopRequested = true
        let shouldInvalidate = !bootstrapKnown
        let connection = self.connection
        let stopHandler = self.stopHandler
        lock.unlock()
        if shouldInvalidate { connection?.invalidate() }
        stopHandler?()
        wake.signal()
    }

    func shutdown() {
        lock.lock()
        let termSource = self.termSource
        let intSource = self.intSource
        self.termSource = nil
        self.intSource = nil
        lock.unlock()
        termSource?.cancel()
        intSource?.cancel()
    }
}

private func closeSession(
    proxy: AgentPassAgentXPCProtocol,
    sessionID: String
) -> Bool {
    guard let request = AgentPassAgentCloseSessionRequest(
        sessionID: sessionID,
        reason: AgentPassAgentSessionCloseReason.clientShutdown.rawValue
    ) else { return false }
    guard case .response = waitForReply({ reply in
        proxy.closeAgentSession(request, withReply: reply)
    }) else { return false }
    return true
}

private func runQualificationActivation() -> Never {
    let document: NativeAgentLaunchAuthorityHandoff
    do {
        document = try readLaunchAuthorityHandoff()
    } catch let error as NativeAgentLaunchAuthorityHandoffError {
        emitActivation(
            ActivationOutput(ok: false, operation: "qualification-activate", status: "rejected", error: "activation_document_\(error.stableCode)"),
            status: 2
        )
    } catch {
        emitActivation(
            ActivationOutput(ok: false, operation: "qualification-activate", status: "rejected", error: "activation_document_rejected"),
            status: 2
        )
    }

    guard let nonce = randomNonce(),
          let bootstrapRequest = AgentPassAgentBootstrapRequest(
            agentID: document.agentID,
            adapterKind: document.agentKind.rawValue,
            requestedTTLSeconds: document.requestedTTLSeconds,
            bootstrapNonce: nonce
          ) else {
        emitActivation(
            ActivationOutput(ok: false, operation: "qualification-activate", status: "rejected", error: "activation_request_rejected"),
            status: 2
        )
    }

    let signalController = ActivationSignalController()
    signalController.install()
    defer { signalController.shutdown() }

    let connection = NSXPCConnection(machServiceName: AgentHostContract.machServiceName, options: .privileged)
    connection.remoteObjectInterface = AgentPassAgentXPCInterface.make()
    connection.resume()
    signalController.setConnection(connection)
    defer { connection.invalidate() }

    let finishActivation: (ActivationOutput, Int32) -> Never = { output, status in
        signalController.shutdown()
        connection.invalidate()
        emitActivation(output, status: status)
    }

    let proxy = connection.remoteObjectProxyWithErrorHandler { _ in } as! AgentPassAgentXPCProtocol
    let bootstrapResult = waitForReply { reply in
        proxy.bootstrapAgent(bootstrapRequest, withReply: reply)
    }
    guard case .response(let bootstrap) = bootstrapResult else {
        finishActivation(
            ActivationOutput(
                ok: false,
                operation: "qualification-activate",
                status: "rejected",
                error: signalController.isStopRequested ? "activation_interrupted" : "agent_activation_rejected"
            ),
            1
        )
    }
    signalController.markBootstrapKnown()

    guard !signalController.isStopRequested,
          let sessionRequest = AgentPassAgentSessionRequest(
            bootstrapID: bootstrap.bootstrapID,
            proof: document.proof
          ) else {
        finishActivation(
            ActivationOutput(ok: false, operation: "qualification-activate", status: "interrupted", error: "activation_interrupted"),
            1
        )
    }

    let firstStartResult = waitForReply { reply in
        proxy.startAgentSession(sessionRequest, withReply: reply)
    }
    let session: AgentPassAgentSessionResponse
    switch firstStartResult {
    case .response(let response):
        session = response
    case .timedOut:
        // A completed activation may have committed its durable result while
        // the first reply was lost. Retry exactly once over this same XPC
        // connection and with the same one-time bootstrap request.
        let retryResult = waitForReply { reply in
            proxy.startAgentSession(sessionRequest, withReply: reply)
        }
        guard case .response(let response) = retryResult else {
            finishActivation(
                ActivationOutput(ok: false, operation: "qualification-activate", status: "error", error: "agent_activation_reply_lost"),
                1
            )
        }
        session = response
    case .remoteFailure:
        finishActivation(
            ActivationOutput(ok: false, operation: "qualification-activate", status: "rejected", error: "agent_activation_rejected"),
            1
        )
    }

    let expiryMilliseconds = session.expiresAtMilliseconds
    let nowMilliseconds = Int64(Date().timeIntervalSince1970 * 1_000)
    let remainingSeconds = max(1, (expiryMilliseconds - nowMilliseconds + 999) / 1_000)
    let hardDeadline = DispatchTime.now() + .seconds(Int(min(remainingSeconds + AgentHostContract.expiryGraceSeconds, 28_805)))
    let statusOutput = ActivationOutput(ok: true, operation: "qualification-activate", status: "active", error: nil)
    let closedOutput = ActivationOutput(ok: true, operation: "qualification-activate", status: "closed", error: nil)
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    if let data = try? encoder.encode(statusOutput) {
        FileHandle.standardOutput.write(data + Data("\n".utf8))
    }

    while true {
        if signalController.isStopRequested {
            if closeSession(proxy: proxy, sessionID: session.sessionID) {
                finishActivation(closedOutput, 0)
            }
            finishActivation(
                ActivationOutput(ok: false, operation: "qualification-activate", status: "error", error: "agent_session_close_failed"),
                1
            )
        }

        if DispatchTime.now() >= hardDeadline {
            _ = closeSession(proxy: proxy, sessionID: session.sessionID)
            finishActivation(
                ActivationOutput(ok: false, operation: "qualification-activate", status: "error", error: "agent_session_expiry_timeout"),
                1
            )
        }

        guard let statusRequest = AgentPassAgentSessionStatusRequest(sessionID: session.sessionID) else {
            _ = closeSession(proxy: proxy, sessionID: session.sessionID)
            finishActivation(
                ActivationOutput(ok: false, operation: "qualification-activate", status: "error", error: "agent_session_status_failed"),
                1
            )
        }
        let statusResult = waitForReply { reply in
            proxy.agentSessionStatus(statusRequest, withReply: reply)
        }
        guard case .response(let current) = statusResult else {
            let closed = closeSession(proxy: proxy, sessionID: session.sessionID)
            if signalController.isStopRequested, closed {
                finishActivation(closedOutput, 0)
            }
            finishActivation(
                ActivationOutput(ok: false, operation: "qualification-activate", status: "error", error: "agent_session_status_failed"),
                1
            )
        }
        guard current.status == "active" else {
            finishActivation(closedOutput, 0)
        }
        _ = signalController.wake.wait(timeout: .now() + AgentHostContract.statusPollInterval)
    }
}

private func runStatusProbe() -> Never {
    guard let request = AgentPassAgentSessionStatusRequest(sessionID: AgentHostContract.probeSessionID) else {
        emitProbe(
            ProbeOutput(ok: false, operation: "status", service: AgentHostContract.machServiceName, sessionStatus: nil, error: "invalid_fixed_probe_request"),
            status: 1
        )
    }

    let connection = NSXPCConnection(machServiceName: AgentHostContract.machServiceName, options: .privileged)
    connection.remoteObjectInterface = AgentPassAgentXPCInterface.make()
    connection.resume()
    defer { connection.invalidate() }

    let semaphore = DispatchSemaphore(value: 0)
    let result = ProbeResultBox()
    let proxy = connection.remoteObjectProxyWithErrorHandler { _ in
        result.set(ProbeOutput(ok: false, operation: "status", service: AgentHostContract.machServiceName, sessionStatus: nil, error: "agent_endpoint_unavailable"))
        semaphore.signal()
    } as! AgentPassAgentXPCProtocol

    proxy.agentSessionStatus(request) { response, _ in
        if let response {
            result.set(ProbeOutput(ok: true, operation: "status", service: AgentHostContract.machServiceName, sessionStatus: response.status, error: nil))
        } else {
            result.set(ProbeOutput(ok: false, operation: "status", service: AgentHostContract.machServiceName, sessionStatus: nil, error: "agent_endpoint_rejected_probe"))
        }
        semaphore.signal()
    }

    guard semaphore.wait(timeout: .now() + .seconds(2)) == .success else {
        emitProbe(
            ProbeOutput(ok: false, operation: "status", service: AgentHostContract.machServiceName, sessionStatus: nil, error: "agent_endpoint_timeout"),
            status: 1
        )
    }
    guard let output = result.get() else {
        emitProbe(
            ProbeOutput(ok: false, operation: "status", service: AgentHostContract.machServiceName, sessionStatus: nil, error: "agent_endpoint_empty_response"),
            status: 1
        )
    }
    emitProbe(output, status: output.ok ? 0 : 1)
}

#if !AGENTPASS_HOST_TESTING
let arguments = Array(CommandLine.arguments.dropFirst())
guard arguments.isEmpty || arguments == ["status"] || arguments == ["probe"] || arguments == ["qualification-activate"]
    || (arguments.count == 2 && arguments[0] == "launch") else {
    FileHandle.standardError.write(Data("Usage: agentpass-native-agent-host [status|probe|qualification-activate|launch PROJECT_PATH]\n".utf8))
    exit(2)
}

if arguments == ["qualification-activate"] {
    runQualificationActivation()
} else if arguments.count == 2, arguments[0] == "launch" {
    runHostLaunchPlan(projectPath: arguments[1])
} else {
    runStatusProbe()
}
#endif
