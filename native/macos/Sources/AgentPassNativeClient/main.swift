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
    emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Usage: agentpass-native-client --service MACH_SERVICE sign|ping|public-key|audit-status|audit-public-key|audit-checkpoint|audit-anchor-status|audit-anchor-push|approval-public-key|session-start|session-revoke|session-validate|control-apply|control-status|control-validate"), status: 2)
}
let serviceName = CommandLine.arguments[2]
let command = CommandLine.arguments.count > 3 ? CommandLine.arguments[3] : ""
let sessionApprovalKeyTag = "dev.agentpass.session-approval.v1"
if command == "approval-public-key" {
    do {
        let key = try SecureEnclaveKeyStore(applicationTag: sessionApprovalKeyTag, requiresUserPresence: true)
        emit(Output(ok: true, version: nil, stdout_base64: nil, public_key: try SSHSIG.authorizedKey(publicKeyX963: key.publicKeyX963), error: nil))
    } catch { emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: error.localizedDescription), status: 1) }
}
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
case "audit-anchor-status":
    proxy.auditAnchorStatus { data, error in
        result = dataOutput(data, error: error)
        semaphore.signal()
    }
case "audit-anchor-push":
    proxy.pushAuditAnchor { data, error in
        result = dataOutput(data, error: error)
        semaphore.signal()
    }
case "session-start":
    let request = FileHandle.standardInput.readDataToEndOfFile()
    guard request.count > 0, request.count <= 16 * 1024,
          let object = try? JSONSerialization.jsonObject(with: request) as? [String: Any],
          let agentID = object["agent_id"] as? String,
          let ttlSeconds = object["ttl_seconds"] as? Int else {
        emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Native session request is invalid"), status: 1)
    }
    proxy.beginSession(agentID: agentID as NSString, ttlSeconds: ttlSeconds) { challenge, beginError in
        guard beginError == nil, let challenge else {
            result = Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: beginError?.localizedDescription ?? "Native service returned an empty session challenge")
            semaphore.signal()
            return
        }
        do {
            let challengeObject = try JSONSerialization.jsonObject(with: challenge as Data) as? [String: Any]
            guard let approvedAgentID = challengeObject?["agent_id"] as? String,
                  let approvedTTL = challengeObject?["ttl_seconds"] as? Int else {
                throw AgentPassNativeError.invalidConfiguration("Native service returned an invalid session challenge")
            }
            let reason = "Start a \(approvedTTL)-second AgentPass session for Agent \(approvedAgentID)"
            let key = try SecureEnclaveKeyStore(applicationTag: sessionApprovalKeyTag, createIfMissing: false, requiresUserPresence: true, operationPrompt: reason)
            let signature = try key.sign(message: challenge as Data)
            proxy.completeSession(challenge: challenge, signature: signature as NSData) { issued, completeError in
                result = dataOutput(issued, error: completeError)
                semaphore.signal()
            }
        } catch {
            result = Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: error.localizedDescription)
            semaphore.signal()
        }
    }
case "session-revoke":
    proxy.revokeSessions { data, error in
        result = dataOutput(data, error: error)
        semaphore.signal()
    }
case "session-validate":
    let request = FileHandle.standardInput.readDataToEndOfFile()
    guard request.count > 0, request.count <= 16 * 1024,
          let object = try? JSONSerialization.jsonObject(with: request) as? [String: Any],
          let agentID = object["agent_id"] as? String else {
        emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Native session validation request is invalid"), status: 1)
    }
    let token = object["session"] as? String
    proxy.validateSession(token: token as NSString?, agentID: agentID as NSString) { valid, error in
        if let error { result = Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: error.localizedDescription) }
        else {
            let data = try? JSONSerialization.data(withJSONObject: ["valid": valid], options: [.sortedKeys])
            result = dataOutput(data as NSData?, error: nil)
        }
        semaphore.signal()
    }
case "control-apply":
    let request = FileHandle.standardInput.readDataToEndOfFile()
    guard request.count > 0, request.count <= 300 * 1024,
          let object = try? JSONSerialization.jsonObject(with: request) as? [String: Any],
          let bundle = object["bundle"], JSONSerialization.isValidJSONObject(bundle),
          let bundleData = try? JSONSerialization.data(withJSONObject: bundle, options: [.sortedKeys, .withoutEscapingSlashes]) else {
        emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Native control apply request is invalid"), status: 1)
    }
    proxy.applyControlBundle(bundle: bundleData as NSData) { data, error in
        result = dataOutput(data, error: error)
        semaphore.signal()
    }
case "control-status":
    proxy.controlStatus { data, error in
        result = dataOutput(data, error: error)
        semaphore.signal()
    }
case "control-validate":
    let request = FileHandle.standardInput.readDataToEndOfFile()
    guard request.count > 0, request.count <= 16 * 1024,
          let object = try? JSONSerialization.jsonObject(with: request) as? [String: Any],
          let agentID = object["agent_id"] as? String else {
        emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Native control validation request is invalid"), status: 1)
    }
    proxy.validateControl(agentID: agentID as NSString) { valid, error in
        if let error { result = Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: error.localizedDescription) }
        else {
            let data = try? JSONSerialization.data(withJSONObject: ["valid": valid], options: [.sortedKeys])
            result = dataOutput(data as NSData?, error: nil)
        }
        semaphore.signal()
    }
default:
    emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Unknown native client command"), status: 2)
}

let timeout: DispatchTime = .now() + (command == "session-start" ? 120 : 30)
guard semaphore.wait(timeout: timeout) == .success, let result else {
    emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Native broker request timed out"), status: 1)
}
emit(result, status: result.ok ? 0 : 1)
