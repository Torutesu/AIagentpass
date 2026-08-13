import AgentPassNativeCore
import Foundation

private enum AgentHostContract {
    static let machServiceName = "dev.agentpass.agent-session"
    static let probeSessionID = "00000000-0000-4000-8000-000000000000"
    static let timeout: DispatchTime = .now() + .seconds(2)
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

private func emit(_ output: ProbeOutput, status: Int32) -> Never {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = (try? encoder.encode(output)) ?? Data("{\"ok\":false,\"error\":\"encoding_failure\"}".utf8)
    FileHandle.standardOutput.write(data + Data("\n".utf8))
    exit(status)
}

// N2 is intentionally a narrow, non-secret probe. Do not add flags that accept
// a session token, private key, signing payload, or configuration path here.
let arguments = Array(CommandLine.arguments.dropFirst())
guard arguments.isEmpty || arguments == ["status"] || arguments == ["probe"] else {
    FileHandle.standardError.write(Data("Usage: agentpass-native-agent-host [status|probe]\n".utf8))
    exit(2)
}

guard let request = AgentPassAgentSessionStatusRequest(sessionID: AgentHostContract.probeSessionID) else {
    emit(
        ProbeOutput(
            ok: false,
            operation: "status",
            service: AgentHostContract.machServiceName,
            sessionStatus: nil,
            error: "invalid_fixed_probe_request"
        ),
        status: 1
    )
}

let connection = NSXPCConnection(machServiceName: AgentHostContract.machServiceName, options: .privileged)
connection.remoteObjectInterface = AgentPassAgentXPCInterface.make()
connection.resume()
defer { connection.invalidate() }

let semaphore = DispatchSemaphore(value: 0)
private let result = ProbeResultBox()
let proxy = connection.remoteObjectProxyWithErrorHandler { _ in
    result.set(
        ProbeOutput(
            ok: false,
            operation: "status",
            service: AgentHostContract.machServiceName,
            sessionStatus: nil,
            error: "agent_endpoint_unavailable"
        )
    )
    semaphore.signal()
} as! AgentPassAgentXPCProtocol

proxy.agentSessionStatus(request) { response, _ in
    if let response {
        result.set(
            ProbeOutput(
                ok: true,
                operation: "status",
                service: AgentHostContract.machServiceName,
                sessionStatus: response.status,
                error: nil
            )
        )
    } else {
        result.set(
            ProbeOutput(
                ok: false,
                operation: "status",
                service: AgentHostContract.machServiceName,
                sessionStatus: nil,
                error: "agent_endpoint_rejected_probe"
            )
        )
    }
    semaphore.signal()
}

guard semaphore.wait(timeout: AgentHostContract.timeout) == .success else {
    emit(
        ProbeOutput(
            ok: false,
            operation: "status",
            service: AgentHostContract.machServiceName,
            sessionStatus: nil,
            error: "agent_endpoint_timeout"
        ),
        status: 1
    )
}

guard let output = result.get() else {
    emit(
        ProbeOutput(
            ok: false,
            operation: "status",
            service: AgentHostContract.machServiceName,
            sessionStatus: nil,
            error: "agent_endpoint_empty_response"
        ),
        status: 1
    )
}
emit(output, status: output.ok ? 0 : 1)
