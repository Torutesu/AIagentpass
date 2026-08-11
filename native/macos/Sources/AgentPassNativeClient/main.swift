import AgentPassNativeCore
import Foundation

struct Output: Encodable {
    let ok: Bool
    let version: Int?
    let stdout_base64: String?
    let public_key: String?
    let error: String?
}

private func emit(_ output: Output, status: Int32 = 0) -> Never {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = (try? encoder.encode(output)) ?? Data("{\"ok\":false,\"error\":\"encoding failure\"}".utf8)
    FileHandle.standardOutput.write(data + Data("\n".utf8))
    exit(status)
}

guard CommandLine.arguments.count >= 3, CommandLine.arguments[1] == "--service" else {
    emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Usage: agentpass-native-client --service MACH_SERVICE sign|ping|public-key"), status: 2)
}
let serviceName = CommandLine.arguments[2]
let command = CommandLine.arguments.count > 3 ? CommandLine.arguments[3] : ""
let connection = NSXPCConnection(machServiceName: serviceName, options: .privileged)
connection.remoteObjectInterface = NSXPCInterface(with: AgentPassNativeServiceProtocol.self)
connection.resume()
defer { connection.invalidate() }
let semaphore = DispatchSemaphore(value: 0)
var result: Output?
let proxy = connection.remoteObjectProxyWithErrorHandler { error in
    result = Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: error.localizedDescription)
    semaphore.signal()
} as! AgentPassNativeServiceProtocol

switch command {
case "sign":
    let request = FileHandle.standardInput.readDataToEndOfFile()
    guard !request.isEmpty, request.count <= 12 * 1024 * 1024 else {
        emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Native request size is invalid"), status: 1)
    }
    proxy.sign(request: request as NSData) { signature, error in
        result = error.map { Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: $0.localizedDescription) }
            ?? Output(ok: true, version: nil, stdout_base64: Data((signature! as String).utf8).base64EncodedString(), public_key: nil, error: nil)
        semaphore.signal()
    }
case "ping":
    proxy.health { health in
        result = Output(ok: health["ok"] as? Bool == true, version: health["protocol_version"] as? Int, stdout_base64: nil, public_key: nil, error: nil)
        semaphore.signal()
    }
case "public-key":
    proxy.publicKey { key, error in
        result = error.map { Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: $0.localizedDescription) }
            ?? Output(ok: true, version: nil, stdout_base64: nil, public_key: key as String?, error: nil)
        semaphore.signal()
    }
default:
    emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Unknown native client command"), status: 2)
}

guard semaphore.wait(timeout: .now() + 30) == .success, let result else {
    emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Native broker request timed out"), status: 1)
}
emit(result, status: result.ok ? 0 : 1)
