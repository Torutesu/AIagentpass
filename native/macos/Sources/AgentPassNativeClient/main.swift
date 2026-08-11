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
    emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Usage: agentpass-native-client --service MACH_SERVICE sign|ping|public-key|audit-status|audit-public-key|audit-checkpoint"), status: 2)
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

private func dataOutput(_ data: NSData?, error: NSError?) -> Output {
    if let error { return Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: error.localizedDescription) }
    guard let data else { return Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Native service returned an empty response") }
    return Output(ok: true, version: nil, stdout_base64: (data as Data).base64EncodedString(), public_key: nil, error: nil)
}

private func keyOutput(_ key: NSString?, error: NSError?) -> Output {
    if let error { return Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: error.localizedDescription) }
    guard let key else { return Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Native service returned an empty public key") }
    return Output(ok: true, version: nil, stdout_base64: nil, public_key: key as String, error: nil)
}

switch command {
case "sign":
    let request = FileHandle.standardInput.readDataToEndOfFile()
    guard !request.isEmpty, request.count <= 12 * 1024 * 1024 else {
        emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Native request size is invalid"), status: 1)
    }
    proxy.sign(request: request as NSData) { signature, error in
        if let error { result = Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: error.localizedDescription) }
        else if let signature { result = Output(ok: true, version: nil, stdout_base64: Data((signature as String).utf8).base64EncodedString(), public_key: nil, error: nil) }
        else { result = Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Native service returned an empty signature") }
        semaphore.signal()
    }
case "ping":
    proxy.health { health in
        let ok = health["ok"] as? Bool == true
        result = Output(ok: ok, version: health["protocol_version"] as? Int, stdout_base64: nil, public_key: nil, error: ok ? nil : (health["error"] as? String ?? "Native service health check failed"))
        semaphore.signal()
    }
case "public-key":
    proxy.publicKey { key, error in
        result = keyOutput(key, error: error)
        semaphore.signal()
    }
case "audit-status":
    proxy.auditStatus { data, error in
        result = dataOutput(data, error: error)
        semaphore.signal()
    }
case "audit-public-key":
    proxy.auditPublicKey { key, error in
        result = keyOutput(key, error: error)
        semaphore.signal()
    }
case "audit-checkpoint":
    proxy.createAuditCheckpoint { data, error in
        result = dataOutput(data, error: error)
        semaphore.signal()
    }
default:
    emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Unknown native client command"), status: 2)
}

guard semaphore.wait(timeout: .now() + 30) == .success, let result else {
    emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Native broker request timed out"), status: 1)
}
emit(result, status: result.ok ? 0 : 1)
