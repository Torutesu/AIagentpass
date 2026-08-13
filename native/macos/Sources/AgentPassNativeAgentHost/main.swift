import AgentPassNativeCore
import Darwin
import Foundation
import Security

enum AgentHostContract {
    static let machServiceName = "dev.agentpass.agent-session"
    static let probeSessionID = "00000000-0000-4000-8000-000000000000"
    static let activationDocumentFD: Int32 = 3
    static let maximumActivationDocumentBytes = 16 * 1024
    static let maximumProofBytes = AgentPassAgentSessionRequest.maximumProofBytes
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

/// The only document accepted by `qualification-activate`.
///
/// The proof is deliberately a String rather than a decoded JSON object. Its
/// UTF-8 bytes are handed to the XPC DTO unchanged; this host never verifies,
/// normalizes, logs, or re-encodes authority-bearing proof material.
struct AgentHostActivationDocument: Equatable, Sendable {
    let schemaVersion: Int
    let agentID: String
    let agentKind: String
    let requestedTTLSeconds: Int
    let proof: String

    static let expectedSchemaVersion = 1
    static let expectedKeys: Set<String> = [
        "schema_version", "agent_id", "agent_kind", "requested_ttl_seconds", "proof"
    ]

    enum DecodeError: Error, Equatable {
        case malformed
        case fields
        case oversized

        var stableCode: String {
            switch self {
            case .malformed: return "malformed"
            case .fields: return "invalid_fields"
            case .oversized: return "oversized"
            }
        }
    }

    private struct CodableDocument: Decodable {
        let schemaVersion: Int
        let agentID: String
        let agentKind: String
        let requestedTTLSeconds: Int
        let proof: String

        enum CodingKeys: String, CodingKey, CaseIterable {
            case schemaVersion = "schema_version"
            case agentID = "agent_id"
            case agentKind = "agent_kind"
            case requestedTTLSeconds = "requested_ttl_seconds"
            case proof
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            guard Set(container.allKeys.map(\.stringValue)) == AgentHostActivationDocument.expectedKeys else {
                throw DecodeError.fields
            }
            schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
            agentID = try container.decode(String.self, forKey: .agentID)
            agentKind = try container.decode(String.self, forKey: .agentKind)
            requestedTTLSeconds = try container.decode(Int.self, forKey: .requestedTTLSeconds)
            proof = try container.decode(String.self, forKey: .proof)
        }
    }

    init(schemaVersion: Int, agentID: String, agentKind: String, requestedTTLSeconds: Int, proof: String) throws {
        guard schemaVersion == Self.expectedSchemaVersion,
              UUID(uuidString: agentID) != nil,
              agentKind == AgentPassAgentAdapterKind.claudeCode.rawValue || agentKind == AgentPassAgentAdapterKind.cursor.rawValue,
              (AgentPassAgentBootstrapRequest.minimumSessionTTLSeconds...AgentPassAgentBootstrapRequest.maximumSessionTTLSeconds).contains(requestedTTLSeconds),
              !proof.isEmpty,
              Data(proof.utf8).count >= AgentPassAgentSessionRequest.minimumProofBytes,
              Data(proof.utf8).count <= AgentHostContract.maximumProofBytes,
              proof.utf8.first == 123,
              proof.utf8.last == 125,
              (try? JSONSerialization.jsonObject(with: Data(proof.utf8), options: [.fragmentsAllowed])) is [String: Any] else {
            throw DecodeError.fields
        }
        self.schemaVersion = schemaVersion
        self.agentID = agentID
        self.agentKind = agentKind
        self.requestedTTLSeconds = requestedTTLSeconds
        self.proof = proof
    }

    static func decode(_ data: Data) throws -> AgentHostActivationDocument {
        guard !data.isEmpty, data.count <= AgentHostContract.maximumActivationDocumentBytes else {
            throw DecodeError.oversized
        }
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .useDefaultKeys
        let decoded: CodableDocument
        do {
            decoded = try decoder.decode(CodableDocument.self, from: data)
        } catch let error as DecodeError {
            throw error
        } catch {
            throw DecodeError.malformed
        }
        let canonicalObject: [String: Any] = [
            "schema_version": decoded.schemaVersion,
            "agent_id": decoded.agentID,
            "agent_kind": decoded.agentKind,
            "requested_ttl_seconds": decoded.requestedTTLSeconds,
            "proof": decoded.proof
        ]
        guard let canonicalData = try? JSONSerialization.data(
            withJSONObject: canonicalObject,
            options: [.sortedKeys, .withoutEscapingSlashes]
        ), canonicalData == data else {
            throw DecodeError.malformed
        }
        let proofData = Data(decoded.proof.utf8)
        guard let proofObject = try? NativeStrictJSON.object(
            from: proofData,
            maxBytes: AgentHostContract.maximumProofBytes,
            maxDepth: 32
        ), let canonicalProof = try? NativeStrictJSON.data(proofObject), canonicalProof == proofData else {
            throw DecodeError.fields
        }
        do {
            return try AgentHostActivationDocument(
                schemaVersion: decoded.schemaVersion,
                agentID: decoded.agentID,
                agentKind: decoded.agentKind,
                requestedTTLSeconds: decoded.requestedTTLSeconds,
                proof: decoded.proof
            )
        } catch let error as DecodeError {
            throw error
        } catch {
            throw DecodeError.fields
        }
    }

    static func read(from descriptor: Int32 = AgentHostContract.activationDocumentFD) throws -> AgentHostActivationDocument {
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4 * 1024)
        while true {
            let count = buffer.withUnsafeMutableBytes { bytes in
                Darwin.read(descriptor, bytes.baseAddress, bytes.count)
            }
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw DecodeError.malformed
            }
            data.append(buffer, count: count)
            if data.count > AgentHostContract.maximumActivationDocumentBytes {
                throw DecodeError.oversized
            }
        }
        return try decode(data)
    }
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
        lock.unlock()
        if shouldInvalidate { connection?.invalidate() }
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
    let document: AgentHostActivationDocument
    do {
        document = try AgentHostActivationDocument.read()
    } catch let error as AgentHostActivationDocument.DecodeError {
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
            adapterKind: document.agentKind,
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
            proof: Data(document.proof.utf8)
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
guard arguments.isEmpty || arguments == ["status"] || arguments == ["probe"] || arguments == ["qualification-activate"] else {
    FileHandle.standardError.write(Data("Usage: agentpass-native-agent-host [status|probe|qualification-activate]\n".utf8))
    exit(2)
}

if arguments == ["qualification-activate"] {
    runQualificationActivation()
} else {
    runStatusProbe()
}
#endif
