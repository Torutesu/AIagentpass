import AgentPassNativeCore
import Foundation
import Security

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

private func bootstrapTag(_ value: String) throws -> String {
    guard value.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,255}\\.g1$", options: .regularExpression) != nil else {
        throw AgentPassNativeError.invalidConfiguration("Bootstrap approval tag must be a bounded generation-1 application tag")
    }
    return value
}

private func approvalKeyAccessGroup() throws -> String {
    guard let task = SecTaskCreateFromSelf(nil),
          let raw = SecTaskCopyValueForEntitlement(task, "keychain-access-groups" as CFString, nil),
          let groups = raw as? [String] else {
        throw AgentPassNativeError.invalidConfiguration("Signed client keychain access-group entitlement is unavailable")
    }
    let approvalGroups = groups.filter { $0.range(of: "^[A-Z0-9]{10}\\.dev\\.agentpass\\.approval-keys$", options: .regularExpression) != nil }
    guard groups.count == 1, approvalGroups.count == 1, let group = approvalGroups.first else {
        throw AgentPassNativeError.invalidConfiguration("Signed client must have exactly one AgentPass approval keychain access group")
    }
    return group
}

private func emitBootstrapObject(_ object: [String: Any]) throws -> Never {
    let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    emit(Output(ok: true, version: nil, stdout_base64: data.base64EncodedString(), public_key: nil, error: nil))
}

// These commands intentionally run without XPC: the production service cannot start until all
// three generation-1 authorities exist. The signed client owns only the approval access group.
if CommandLine.arguments.count == 3, CommandLine.arguments[1] == "bootstrap-approval-create" {
    do {
        let tag = try bootstrapTag(CommandLine.arguments[2])
        let accessGroup = try approvalKeyAccessGroup()
        let key: SecureEnclaveKeyStore
        if try SecureEnclaveKeyStore.exists(applicationTag: tag, accessGroup: accessGroup) {
            key = try SecureEnclaveKeyStore.loadExisting(applicationTag: tag, accessGroup: accessGroup)
        } else {
            key = try SecureEnclaveKeyStore.create(applicationTag: tag, accessGroup: accessGroup, requiresUserPresence: true)
        }
        try emitBootstrapObject([
            "version": 1,
            "application_tag": tag,
            "public_key_base64": key.publicKeyX963.base64EncodedString(),
            "fingerprint": NativeKeyLifecycleStore.fingerprint(key.publicKeyX963),
            "authorized_key": try SSHSIG.authorizedKey(publicKeyX963: key.publicKeyX963)
        ])
    } catch {
        emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: error.localizedDescription), status: 1)
    }
}

if CommandLine.arguments.count == 3, CommandLine.arguments[1] == "bootstrap-sign" {
    do {
        let tag = try bootstrapTag(CommandLine.arguments[2])
        let statementData = FileHandle.standardInput.readDataToEndOfFile()
        let statement = try NativeKeyTransitionStatement.decodeCanonical(statementData)
        guard statement.continuity == .bootstrap, statement.newGeneration == 1,
              statement.reason == "initial-provisioning",
              statement.challengeID == "bootstrap-\(statement.role.rawValue)-g1",
              let createdAt = clientTimestamp(statement.createdAt),
              createdAt <= Date().addingTimeInterval(60), createdAt >= Date().addingTimeInterval(-600) else {
            throw AgentPassNativeError.invalidSignature("Bootstrap statement is stale or does not describe the exact generation-1 ceremony")
        }
        let key = try SecureEnclaveKeyStore.loadExisting(
            applicationTag: tag,
            accessGroup: try approvalKeyAccessGroup(),
            operationPrompt: "Bootstrap AgentPass \(statement.role.rawValue) g1, key \(statement.newFingerprint), head \(statement.previousLifecycleHead)"
        )
        let signerFingerprint = NativeKeyLifecycleStore.fingerprint(key.publicKeyX963)
        if statement.role == .sessionApproval, signerFingerprint != statement.newFingerprint {
            throw AgentPassNativeError.invalidKey("Bootstrap approval statement does not bind the selected approval key")
        }
        try emitBootstrapObject([
            "version": 1,
            "role": statement.role.rawValue,
            "generation": statement.newGeneration,
            "statement_base64": statementData.base64EncodedString(),
            "signature_base64": try key.sign(message: statementData).base64EncodedString(),
            "signer_public_key_base64": key.publicKeyX963.base64EncodedString(),
            "signer_fingerprint": signerFingerprint
        ])
    } catch {
        emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: error.localizedDescription), status: 1)
    }
}

guard CommandLine.arguments.count >= 3, CommandLine.arguments[1] == "--service" else {
    emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Usage: agentpass-native-client bootstrap-approval-create TAG | bootstrap-sign TAG | --service MACH_SERVICE COMMAND"), status: 2)
}
let serviceName = CommandLine.arguments[2]
let command = CommandLine.arguments.count > 3 ? CommandLine.arguments[3] : ""
let sessionApprovalKeyTag = "dev.agentpass.session-approval.v1"
if command == "host-control-close" {
    let request = FileHandle.standardInput.readDataToEndOfFile()
    do {
        guard request.count > 0, request.count <= 16 * 1024,
              let object = try JSONSerialization.jsonObject(with: request) as? [String: Any],
              Set(object.keys) == Set(["session_id", "operation_id", "reason"]),
              let sessionID = object["session_id"] as? String,
              let operationID = object["operation_id"] as? String,
              let reasonText = object["reason"] as? String,
              let reason = AgentPassHostXPCContract.CloseReason(rawValue: reasonText),
              let controlRequest = AgentPassHostControlCloseRequest(sessionID: sessionID, operationID: operationID, reason: reason) else {
            throw AgentPassNativeError.invalidConfiguration("Native Host control close request is invalid")
        }
        let client = NativeAgentAuthenticatedHostControlXPCClient(machServiceName: serviceName)
        let closed = try client.close(sessionID: controlRequest.sessionID, operationID: controlRequest.operationID, reason: reason)
        let data = try JSONSerialization.data(withJSONObject: [
            "status": "closed",
            "operation_id": closed.operationID,
            "session_id": closed.sessionID,
            "closed_at_ms": closed.closedAtMilliseconds
        ], options: [.sortedKeys])
        emit(Output(ok: true, version: nil, stdout_base64: data.base64EncodedString(), public_key: nil, error: nil))
    } catch {
        emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: error.localizedDescription), status: 1)
    }
}
if command == "approval-public-key" {
    do {
        let key = try SecureEnclaveKeyStore(applicationTag: sessionApprovalKeyTag, accessGroup: approvalKeyAccessGroup(), requiresUserPresence: true)
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

private func clientTimestamp(_ value: String) -> Date? {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.date(from: value)
}

private func validManagementReason(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.count <= 512 && value.unicodeScalars.allSatisfy { $0.value >= 0x20 && $0.value != 0x7f }
}

private func validateAbortStatement(_ data: Data, role: String, generation: Int, reason: String, challengeID: String, lifecycleHead: String) throws {
    let keys: Set<String> = ["version", "action", "role", "generation", "state_sequence", "reason", "challenge_id", "created_at", "previous_lifecycle_head", "externally_pinned_head_hash"]
    guard data.count > 0, data.count <= 16 * 1024,
          let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == keys,
          try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]) == data,
          object["version"] as? Int == 1, object["action"] as? String == "abort_intent",
          object["role"] as? String == role, object["generation"] as? Int == generation,
          let sequence = object["state_sequence"] as? Int, sequence > 0,
          object["reason"] as? String == reason, object["challenge_id"] as? String == challengeID,
          let createdAt = object["created_at"] as? String, clientTimestamp(createdAt) != nil,
          object["previous_lifecycle_head"] as? String == lifecycleHead,
          object["externally_pinned_head_hash"] as? String == lifecycleHead else {
        throw AgentPassNativeError.invalidSignature("Native key abort statement is not the exact displayed canonical operation")
    }
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
        let version = health["protocol_version"] as? Int
        let healthy = health["ok"] as? Bool == true
        let ok = healthy && version == 13
        let error = !healthy
            ? (health["error"] as? String ?? "Native service health check failed")
            : (ok ? nil : "Native service protocol 13 is required")
        result = Output(ok: ok, version: version, stdout_base64: nil, public_key: nil, error: error)
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
case "audit-rotate":
    proxy.rotateAudit { data, error in
        result = dataOutput(data, error: error)
        semaphore.signal()
    }
case "audit-evidence-rotate":
    proxy.rotateAuditEvidence { data, error in
        result = dataOutput(data, error: error)
        semaphore.signal()
    }
case "key-lifecycle-status":
    proxy.keyLifecycleStatus { data, error in
        result = dataOutput(data, error: error)
        semaphore.signal()
    }
case "key-stage":
    let request = FileHandle.standardInput.readDataToEndOfFile()
    guard request.count > 0, request.count <= 16 * 1024,
          let object = try? JSONSerialization.jsonObject(with: request) as? [String: Any],
          Set(object.keys) == ["role"], let role = object["role"] as? String else {
        emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Native key stage request is invalid"), status: 1)
    }
    if role == NativeKeyRole.sessionApproval.rawValue {
        proxy.approvalKeyStagePlan { planData, planError in
            guard planError == nil, let planData else {
                result = Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: planError?.localizedDescription ?? "Native service returned an empty approval-key stage plan")
                semaphore.signal()
                return
            }
            do {
                guard let plan = try JSONSerialization.jsonObject(with: planData as Data) as? [String: Any],
                      plan["role"] as? String == role,
                      let generation = plan["generation"] as? Int,
                      let applicationTag = plan["application_tag"] as? String else {
                    throw AgentPassNativeError.invalidConfiguration("Native service returned an invalid approval-key stage plan")
                }
                let accessGroup = try approvalKeyAccessGroup()
                let key = try SecureEnclaveKeyStore.create(applicationTag: applicationTag, accessGroup: accessGroup, requiresUserPresence: true)
                proxy.stageApprovalKey(generation: generation, applicationTag: applicationTag as NSString, publicKey: key.publicKeyX963 as NSData) { data, error in
                    if error != nil {
                        if let exact = try? SecureEnclaveKeyStore.loadExisting(applicationTag: applicationTag, accessGroup: accessGroup), exact.publicKeyX963 == key.publicKeyX963 {
                            _ = try? SecureEnclaveKeyStore.delete(applicationTag: applicationTag, accessGroup: accessGroup)
                        }
                    }
                    result = dataOutput(data, error: error)
                    semaphore.signal()
                }
            } catch {
                result = Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: error.localizedDescription)
                semaphore.signal()
            }
        }
    } else {
        proxy.stageKey(role: role as NSString) { data, error in
            result = dataOutput(data, error: error)
            semaphore.signal()
        }
    }
case "key-activate":
    let request = FileHandle.standardInput.readDataToEndOfFile()
    guard request.count > 0, request.count <= 16 * 1024,
          let object = try? JSONSerialization.jsonObject(with: request) as? [String: Any],
          Set(object.keys) == ["generation", "reason", "role"],
          let role = object["role"] as? String, let generation = object["generation"] as? Int,
          let reason = object["reason"] as? String, validManagementReason(reason) else {
        emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Native key activation request is invalid"), status: 1)
    }
    proxy.beginKeyActivation(role: role as NSString, generation: generation, reason: reason as NSString) { challengeData, beginError in
        guard beginError == nil, let challengeData else {
            result = Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: beginError?.localizedDescription ?? "Native service returned an empty key activation challenge")
            semaphore.signal()
            return
        }
        do {
            guard let challenge = try JSONSerialization.jsonObject(with: challengeData as Data) as? [String: Any],
                  challenge["role"] as? String == role, challenge["generation"] as? Int == generation,
                  challenge["reason"] as? String == reason,
                  let challengeID = challenge["challenge_id"] as? String,
                  let approvalTag = challenge["approval_application_tag"] as? String,
                  let approvalFingerprint = challenge["approval_fingerprint"] as? String,
                  let newFingerprint = challenge["new_fingerprint"] as? String,
                  let expiresAt = challenge["expires_at"] as? String,
                  let statementValue = challenge["statement_base64"] as? String,
                  let statement = Data(base64Encoded: statementValue), !statement.isEmpty,
                  let expiry = clientTimestamp(expiresAt), expiry >= Date() else {
                throw AgentPassNativeError.invalidConfiguration("Native service returned an invalid key activation challenge")
            }
            let decoded = try NativeKeyTransitionStatement.decodeCanonical(statement)
            guard decoded.role.rawValue == role, decoded.newGeneration == generation, decoded.reason == reason,
                  decoded.challengeID == challengeID, decoded.newFingerprint == newFingerprint,
                  decoded.continuity == .clean else {
                throw AgentPassNativeError.invalidSignature("Native service activation statement does not match the displayed operation")
            }
            let prompt = "AgentPass protocol 11 activation; seq \(decoded.stateSequence); challenge \(challengeID); created \(decoded.createdAt); expires \(expiresAt); \(role) g\(decoded.oldGeneration)→g\(generation); \(decoded.oldFingerprint)→\(newFingerprint); approval \(approvalFingerprint); head \(decoded.previousLifecycleHead); reason: \(reason)"
            let accessGroup = try approvalKeyAccessGroup()
            let approvalKey = try SecureEnclaveKeyStore.loadExisting(applicationTag: approvalTag, accessGroup: accessGroup, operationPrompt: prompt)
            let oldSignature = try approvalKey.sign(message: statement)
            if role == NativeKeyRole.sessionApproval.rawValue {
                guard let newTag = challenge["new_application_tag"] as? String else {
                    throw AgentPassNativeError.invalidConfiguration("Native service omitted the staged approval key tag")
                }
                let newKey = try SecureEnclaveKeyStore.loadExisting(applicationTag: newTag, accessGroup: accessGroup, operationPrompt: "AgentPass protocol 11 new approval-key proof; seq \(decoded.stateSequence); challenge \(challengeID); created \(decoded.createdAt); expires \(expiresAt); g\(generation); key \(newFingerprint)")
                let newSignature = try newKey.sign(message: statement)
                proxy.completeApprovalKeyActivation(challengeID: challengeID as NSString, oldSignature: oldSignature as NSData, newSignature: newSignature as NSData) { data, error in
                    result = dataOutput(data, error: error)
                    semaphore.signal()
                }
            } else {
                proxy.completeKeyActivation(challengeID: challengeID as NSString, approvalSignature: oldSignature as NSData) { data, error in
                    result = dataOutput(data, error: error)
                    semaphore.signal()
                }
            }
        } catch {
            result = Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: error.localizedDescription)
            semaphore.signal()
        }
    }
case "key-abort":
    let request = FileHandle.standardInput.readDataToEndOfFile()
    guard request.count > 0, request.count <= 16 * 1024,
          let object = try? JSONSerialization.jsonObject(with: request) as? [String: Any],
          Set(object.keys) == ["generation", "reason", "role"],
          let role = object["role"] as? String,
          role == NativeKeyRole.gitSigning.rawValue || role == NativeKeyRole.auditCheckpoint.rawValue,
          let generation = object["generation"] as? Int, generation > 0,
          let reason = object["reason"] as? String, validManagementReason(reason) else {
        emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Native key abort request is invalid"), status: 1)
    }
    proxy.beginKeyAbort(role: role as NSString, generation: generation, reason: reason as NSString) { challengeData, beginError in
        guard beginError == nil, let challengeData else {
            result = Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: beginError?.localizedDescription ?? "Native service returned an empty key abort challenge")
            semaphore.signal()
            return
        }
        do {
            guard let challenge = try JSONSerialization.jsonObject(with: challengeData as Data) as? [String: Any],
                  challenge["role"] as? String == role, challenge["generation"] as? Int == generation,
                  challenge["reason"] as? String == reason,
                  let challengeID = challenge["challenge_id"] as? String,
                  let expiresAt = challenge["expires_at"] as? String, let expiry = clientTimestamp(expiresAt), expiry >= Date(),
                  let approvalTag = challenge["approval_application_tag"] as? String,
                  let approvalFingerprint = challenge["approval_fingerprint"] as? String,
                  let stagedFingerprint = challenge["staged_fingerprint"] as? String,
                  let lifecycleHead = challenge["lifecycle_head_hash"] as? String,
                  let encoded = challenge["statement_base64"] as? String,
                  let statement = Data(base64Encoded: encoded), statement.base64EncodedString() == encoded else {
                throw AgentPassNativeError.invalidConfiguration("Native service returned an invalid key abort challenge")
            }
            try validateAbortStatement(statement, role: role, generation: generation, reason: reason, challengeID: challengeID, lifecycleHead: lifecycleHead)
            guard let statementObject = try JSONSerialization.jsonObject(with: statement) as? [String: Any],
                  let sequence = statementObject["state_sequence"] as? Int,
                  let createdAt = statementObject["created_at"] as? String else {
                throw AgentPassNativeError.invalidSignature("Native key abort prompt fields are missing")
            }
            let prompt = "AgentPass protocol 11 abort; seq \(sequence); challenge \(challengeID); created \(createdAt); expires \(expiresAt); \(role) g\(generation); key \(stagedFingerprint); approval \(approvalFingerprint); head \(lifecycleHead); reason: \(reason)"
            let approvalKey = try SecureEnclaveKeyStore.loadExisting(applicationTag: approvalTag, accessGroup: approvalKeyAccessGroup(), operationPrompt: prompt)
            proxy.completeKeyAbort(challengeID: challengeID as NSString, approvalSignature: try approvalKey.sign(message: statement) as NSData) { data, error in
                result = dataOutput(data, error: error)
                semaphore.signal()
            }
        } catch {
            result = Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: error.localizedDescription)
            semaphore.signal()
        }
    }
case "key-delete":
    let request = FileHandle.standardInput.readDataToEndOfFile()
    guard request.count > 0, request.count <= 32 * 1024,
          let object = try? JSONSerialization.jsonObject(with: request) as? [String: Any],
          Set(object.keys) == ["generation", "minimum_retention_seconds", "operation", "proof", "reason", "role"],
          object["operation"] as? String == "native.key.delete",
          let role = object["role"] as? String,
          role == NativeKeyRole.gitSigning.rawValue || role == NativeKeyRole.auditCheckpoint.rawValue,
          let generation = object["generation"] as? Int, generation > 0,
          let minimumRetention = object["minimum_retention_seconds"] as? Int,
          (86_400...31_536_000).contains(minimumRetention),
          let reason = object["reason"] as? String, validManagementReason(reason),
          let proofObject = object["proof"] as? [String: Any], JSONSerialization.isValidJSONObject(proofObject) else {
        emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Native key deletion request is invalid"), status: 1)
    }
    do {
        let proofData = try JSONSerialization.data(withJSONObject: proofObject, options: [.sortedKeys, .withoutEscapingSlashes])
        proxy.beginKeyDeletion(role: role as NSString, generation: generation, reason: reason as NSString, minimumRetentionSeconds: minimumRetention, proof: proofData as NSData) { challengeData, beginError in
            guard beginError == nil, let challengeData else {
                result = Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: beginError?.localizedDescription ?? "Native service returned an empty key deletion challenge")
                semaphore.signal()
                return
            }
            do {
                guard let challenge = try JSONSerialization.jsonObject(with: challengeData as Data) as? [String: Any],
                      challenge["version"] as? Int == 1, challenge["protocol_version"] as? Int == 11,
                      challenge["role"] as? String == role, challenge["generation"] as? Int == generation,
                      challenge["reason"] as? String == reason,
                      challenge["minimum_retention_seconds"] as? Int == minimumRetention,
                      let challengeID = challenge["challenge_id"] as? String,
                      let expiresAt = challenge["expires_at"] as? String,
                      let expiry = clientTimestamp(expiresAt), expiry >= Date(),
                      let fingerprint = challenge["fingerprint"] as? String,
                      let lifecycleHead = challenge["lifecycle_head_hash"] as? String,
                      let receiptHash = challenge["transition_receipt_hash"] as? String,
                      let approvalTag = challenge["approval_application_tag"] as? String,
                      let approvalFingerprint = challenge["approval_fingerprint"] as? String,
                      let statementText = challenge["statement_base64"] as? String,
                      let statement = Data(base64Encoded: statementText), statement.base64EncodedString() == statementText,
                      let statementObject = try JSONSerialization.jsonObject(with: statement) as? [String: Any],
                      statementObject["action"] as? String == "deletion_intent",
                      statementObject["challenge_id"] as? String == challengeID,
                      statementObject["previous_lifecycle_head"] as? String == lifecycleHead,
                      statementObject["externally_pinned_head_hash"] as? String == lifecycleHead,
                      statementObject["transition_archived"] as? Bool == true,
                      let sequence = statementObject["state_sequence"] as? Int,
                      let createdAt = statementObject["created_at"] as? String else {
                    throw AgentPassNativeError.invalidSignature("Native key deletion challenge does not match the displayed operation")
                }
                let prompt = "AgentPass protocol 11 PERMANENT KEY DELETE; seq \(sequence); challenge \(challengeID); created \(createdAt); expires \(expiresAt); \(role) g\(generation); key \(fingerprint); approval \(approvalFingerprint); lifecycle \(lifecycleHead); transition receipt \(receiptHash); retention \(minimumRetention)s; reason: \(reason)"
                let approval = try SecureEnclaveKeyStore.loadExisting(applicationTag: approvalTag, accessGroup: approvalKeyAccessGroup(), operationPrompt: prompt)
                guard NativeKeyLifecycleStore.fingerprint(approval.publicKeyX963) == approvalFingerprint else {
                    throw AgentPassNativeError.invalidKey("Key deletion approval signer was substituted")
                }
                proxy.completeKeyDeletion(challengeID: challengeID as NSString, approvalSignature: try approval.sign(message: statement) as NSData) { data, error in
                    result = dataOutput(data, error: error)
                    semaphore.signal()
                }
            } catch {
                result = Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: error.localizedDescription)
                semaphore.signal()
            }
        }
    } catch {
        result = Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: error.localizedDescription)
        semaphore.signal()
    }
case "recovery-request":
    let request = FileHandle.standardInput.readDataToEndOfFile()
    guard request.count > 0, request.count <= 16 * 1024,
          let object = try? JSONSerialization.jsonObject(with: request) as? [String: Any],
          Set(object.keys) == ["operation", "role"],
          object["operation"] as? String == "native.recovery.request",
          let role = object["role"] as? String,
          NativeKeyRole(rawValue: role) != nil else {
        emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Native recovery request is invalid"), status: 1)
    }
    proxy.beginRecovery(role: role as NSString) { data, error in
        result = dataOutput(data, error: error)
        semaphore.signal()
    }
case "recovery-install":
    let request = FileHandle.standardInput.readDataToEndOfFile()
    guard request.count > 0, request.count <= NativeRecoveryEvidenceBundle.maximumBytes * 2,
          let object = try? JSONSerialization.jsonObject(with: request) as? [String: Any],
          Set(object.keys) == ["evidence_base64", "operation"],
          object["operation"] as? String == "native.recovery.install",
          let encoded = object["evidence_base64"] as? String,
          let evidence = Data(base64Encoded: encoded), evidence.base64EncodedString() == encoded,
          evidence.count > 0, evidence.count <= NativeRecoveryEvidenceBundle.maximumBytes else {
        emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Native recovery evidence is invalid"), status: 1)
    }
    proxy.prepareRecoveryInstallation(evidence: evidence as NSData) { challengeData, prepareError in
        guard prepareError == nil, let challengeData else {
            result = Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: prepareError?.localizedDescription ?? "Native service returned an empty recovery challenge")
            semaphore.signal()
            return
        }
        do {
            guard let challenge = try JSONSerialization.jsonObject(with: challengeData as Data) as? [String: Any],
                  challenge["version"] as? Int == 1, challenge["protocol_version"] as? Int == 11,
                  let challengeID = challenge["challenge_id"] as? String,
                  let expiresAt = challenge["expires_at"] as? String,
                  let expiry = clientTimestamp(expiresAt), expiry >= Date(),
                  let role = challenge["role"] as? String,
                  let generation = challenge["generation"] as? Int,
                  let requestHash = challenge["request_hash"] as? String,
                  let statementText = challenge["statement_base64"] as? String,
                  let statementData = Data(base64Encoded: statementText), statementData.base64EncodedString() == statementText,
                  let signerKind = challenge["local_signer_kind"] as? String,
                  let signerTag = challenge["local_signer_application_tag"] as? String,
                  let signerFingerprint = challenge["local_signer_fingerprint"] as? String else {
                throw AgentPassNativeError.invalidConfiguration("Native recovery installation challenge is invalid")
            }
            let statement = try NativeKeyTransitionStatement.decodeCanonical(statementData)
            guard statement.continuity == .recovered,
                  statement.role.rawValue == role,
                  statement.newGeneration == generation,
                  statement.challengeID == challengeID,
                  statement.reason == "offline-threshold-recovery:\(requestHash)",
                  signerKind == "active_approval" || signerKind == "replacement_approval" else {
                throw AgentPassNativeError.invalidSignature("Native recovery statement does not match the displayed installation")
            }
            let prompt = "AgentPass protocol 11 RECOVERY; \(signerKind); seq \(statement.stateSequence); challenge \(challengeID); created \(statement.createdAt); expires \(expiresAt); \(role) g\(statement.oldGeneration)→g\(generation); \(statement.oldFingerprint)→\(statement.newFingerprint); request \(requestHash); signer \(signerFingerprint); head \(statement.previousLifecycleHead)"
            let signer = try SecureEnclaveKeyStore.loadExisting(applicationTag: signerTag, accessGroup: approvalKeyAccessGroup(), operationPrompt: prompt)
            guard NativeKeyLifecycleStore.fingerprint(signer.publicKeyX963) == signerFingerprint else {
                throw AgentPassNativeError.invalidKey("Recovery local-presence signer was substituted")
            }
            proxy.completeRecovery(challengeID: challengeID as NSString, localSignature: try signer.sign(message: statementData) as NSData) { data, error in
                result = dataOutput(data, error: error)
                semaphore.signal()
            }
        } catch {
            result = Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: error.localizedDescription)
            semaphore.signal()
        }
    }
case "recovery-prepare":
    let request = FileHandle.standardInput.readDataToEndOfFile()
    guard request.count > 0, request.count <= NativeRecoveryEvidenceBundle.maximumBytes * 2,
          let object = try? JSONSerialization.jsonObject(with: request) as? [String: Any],
          Set(object.keys) == ["evidence_base64", "operation"],
          object["operation"] as? String == "native.recovery.prepare",
          let encoded = object["evidence_base64"] as? String,
          let evidence = Data(base64Encoded: encoded), evidence.base64EncodedString() == encoded,
          evidence.count > 0, evidence.count <= NativeRecoveryEvidenceBundle.maximumBytes else {
        emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Native recovery preparation evidence is invalid"), status: 1)
    }
    proxy.prepareRecoveryInstallation(evidence: evidence as NSData) { data, error in
        result = dataOutput(data, error: error)
        semaphore.signal()
    }
case "recovery-anchor-install":
    let request = FileHandle.standardInput.readDataToEndOfFile()
    guard request.count > 0, request.count <= NativeAuditKeyRecoveryTransition.maximumEncodedBytes * 2,
          let object = try? JSONSerialization.jsonObject(with: request) as? [String: Any],
          Set(object.keys) == ["evidence_base64", "operation"],
          object["operation"] as? String == "native.recovery.anchor.install",
          let encoded = object["evidence_base64"] as? String,
          let evidenceData = Data(base64Encoded: encoded), evidenceData.base64EncodedString() == encoded,
          evidenceData.count > 0, evidenceData.count <= NativeAuditKeyRecoveryTransition.maximumEncodedBytes else {
        emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Native anchor recovery evidence is invalid"), status: 1)
    }
    proxy.prepareAuditRecoveryInstallation(evidence: evidenceData as NSData) { challengeData, prepareError in
        guard prepareError == nil, let challengeData else {
            result = Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: prepareError?.localizedDescription ?? "Native service returned an empty audit recovery challenge")
            semaphore.signal()
            return
        }
        do {
            guard let evidenceObject = try JSONSerialization.jsonObject(with: evidenceData) as? [String: Any],
                  Set(evidenceObject.keys) == ["approvals", "authorization", "policy", "version"],
                  let policyObject = evidenceObject["policy"] as? [String: Any],
                  let authorizationObject = evidenceObject["authorization"] as? [String: Any] else {
                throw AgentPassNativeError.invalidSignature("Anchor recovery evidence schema is invalid")
            }
            let policyData = try JSONSerialization.data(withJSONObject: policyObject, options: [.sortedKeys, .withoutEscapingSlashes])
            let authorizationData = try JSONSerialization.data(withJSONObject: authorizationObject, options: [.sortedKeys, .withoutEscapingSlashes])
            let policy = try NativeAuditKeyRecoveryPolicy.decodeCanonical(policyData)
            let authorization = try JSONDecoder().decode(NativeAuditKeyRecoveryAuthorization.self, from: authorizationData)
            guard try authorization.canonicalData() == authorizationData else {
                throw AgentPassNativeError.invalidSignature("Anchor recovery authorization is not canonical")
            }
            _ = try NativeAuditKeyRecoveryEvidence.decodeCanonical(
                evidenceData, pinnedPolicy: policy, expectedAuthorization: authorization,
                expectedInstallationID: authorization.installationID
            )
            guard let challenge = try JSONSerialization.jsonObject(with: challengeData as Data) as? [String: Any],
                  challenge["version"] as? Int == 1, challenge["protocol_version"] as? Int == 12,
                  challenge["role"] as? String == NativeKeyRole.auditCheckpoint.rawValue,
                  let challengeID = challenge["challenge_id"] as? String,
                  let expiresAt = challenge["expires_at"] as? String,
                  let expiry = clientTimestamp(expiresAt), expiry >= Date(),
                  let returnedAuthorizationText = challenge["anchor_authorization_base64"] as? String,
                  let returnedAuthorization = Data(base64Encoded: returnedAuthorizationText),
                  returnedAuthorization.base64EncodedString() == returnedAuthorizationText,
                  returnedAuthorization == authorizationData,
                  let statementText = challenge["statement_base64"] as? String,
                  let statementData = Data(base64Encoded: statementText), statementData.base64EncodedString() == statementText,
                  let predictedHead = challenge["predicted_lifecycle_head_hash"] as? String,
                  predictedHead == authorization.lifecycleHeadHash,
                  let requestHash = challenge["request_hash"] as? String,
                  requestHash == authorization.recoveryRequestID,
                  challenge["local_signer_kind"] as? String == "active_approval",
                  let signerTag = challenge["local_signer_application_tag"] as? String,
                  let signerFingerprint = challenge["local_signer_fingerprint"] as? String else {
                throw AgentPassNativeError.invalidConfiguration("Native audit recovery challenge is invalid")
            }
            let statement = try NativeKeyTransitionStatement.decodeCanonical(statementData)
            guard statement.role == .auditCheckpoint, statement.continuity == .recovered,
                  statement.challengeID == challengeID,
                  statement.newGeneration == authorization.toGeneration,
                  statement.oldFingerprint == authorization.oldKeyFingerprint,
                  statement.newFingerprint == authorization.newKeyFingerprint else {
                throw AgentPassNativeError.invalidSignature("Audit recovery lifecycle statement was substituted")
            }
            let prompt = "AgentPass protocol 12 AUDIT RECOVERY; seq \(statement.stateSequence); challenge \(challengeID); created \(statement.createdAt); expires \(expiresAt); audit_checkpoint g\(statement.oldGeneration)→g\(statement.newGeneration); \(statement.oldFingerprint)→\(statement.newFingerprint); request \(requestHash); signer \(signerFingerprint); head \(predictedHead)"
            let signer = try SecureEnclaveKeyStore.loadExisting(
                applicationTag: signerTag, accessGroup: approvalKeyAccessGroup(), operationPrompt: prompt
            )
            guard NativeKeyLifecycleStore.fingerprint(signer.publicKeyX963) == signerFingerprint else {
                throw AgentPassNativeError.invalidKey("Audit recovery local-presence signer was substituted")
            }
            proxy.completeAuditRecovery(
                challengeID: challengeID as NSString,
                localSignature: try signer.sign(message: statementData) as NSData
            ) { data, error in
                result = dataOutput(data, error: error)
                semaphore.signal()
            }
        } catch {
            result = Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: error.localizedDescription)
            semaphore.signal()
        }
    }
case "audit-anchor-status":
    proxy.auditAnchorStatus { data, error in
        result = dataOutput(data, error: error)
        semaphore.signal()
    }
case "audit-recovery-abort-expired":
    proxy.abortExpiredAuditRecovery { data, error in result = dataOutput(data, error: error); semaphore.signal() }
case "audit-recovery-status":
    proxy.auditRecoveryStatus { data, error in result = dataOutput(data, error: error); semaphore.signal() }
case "audit-anchor-push":
    proxy.pushAuditAnchor { data, error in
        result = dataOutput(data, error: error)
        semaphore.signal()
    }
case "audit-prune-prepare":
    let request = FileHandle.standardInput.readDataToEndOfFile()
    guard !request.isEmpty, request.count <= 4 * 1024 * 1024 else {
        emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Native audit prune prepare request size is invalid"), status: 1)
    }
    proxy.prepareAuditPrune(request: request as NSData) { data, error in
        result = dataOutput(data, error: error); semaphore.signal()
    }
case "audit-prune-submit":
    proxy.submitAuditPrune { data, error in result = dataOutput(data, error: error); semaphore.signal() }
case "audit-prune-execute":
    proxy.executeAuditPrune { data, error in result = dataOutput(data, error: error); semaphore.signal() }
case "audit-prune-status":
    proxy.auditPruneStatus { data, error in result = dataOutput(data, error: error); semaphore.signal() }
case "session-start":
    let request = FileHandle.standardInput.readDataToEndOfFile()
    guard request.count > 0, request.count <= 16 * 1024,
          let object = try? JSONSerialization.jsonObject(with: request) as? [String: Any],
          let agentID = object["agent_id"] as? String,
          let ttlSeconds = object["ttl_seconds"] as? Int else {
        emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Native session request is invalid"), status: 1)
    }
    let beginWithApprovalTag: (String) -> Void = { approvalTag in
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
                let key = try SecureEnclaveKeyStore.loadExisting(applicationTag: approvalTag, accessGroup: approvalKeyAccessGroup(), operationPrompt: reason)
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
    }
    proxy.keyLifecycleStatus { data, error in
        do {
            if let error { throw error }
            guard let data, let status = try JSONSerialization.jsonObject(with: data as Data) as? [String: Any] else {
                throw AgentPassNativeError.invalidConfiguration("Native service returned invalid lifecycle status")
            }
            if status["configured"] as? Bool == true {
                guard let active = status["active"] as? [String: Any], let approval = active["session_approval"] as? [String: Any], let tag = approval["application_tag"] as? String else {
                    throw AgentPassNativeError.invalidConfiguration("Active lifecycle approval key metadata is missing")
                }
                beginWithApprovalTag(tag)
            } else {
                beginWithApprovalTag(sessionApprovalKeyTag)
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
case "session-revoke-agent":
    let request = FileHandle.standardInput.readDataToEndOfFile()
    guard request.count > 0, request.count <= 16 * 1024,
          let object = try? JSONSerialization.jsonObject(with: request) as? [String: Any],
          Set(object.keys) == Set(["agent_id"]),
          let agentID = object["agent_id"] as? String,
          !agentID.isEmpty, agentID.utf8.count <= 128 else {
        emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Native Agent session revocation request is invalid"), status: 1)
    }
    proxy.revokeSessions(agentID: agentID as NSString) { data, error in
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
case "control-refresh":
    proxy.refreshControl { data, error in
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

// A manual control refresh may legitimately consume the complete 30-second
// long-poll allowance before verification, durable activation, and ACK. Keep
// the client deadline strictly outside that server-side bound.
let extendedTimeoutCommands: Set<String> = [
    "session-start",
    "recovery-anchor-install",
    "audit-prune-submit",
    "audit-prune-execute",
    "control-refresh"
]
let timeoutSeconds = extendedTimeoutCommands.contains(command) ? 120 : 30
let timeout: DispatchTime = .now() + .seconds(timeoutSeconds)
guard semaphore.wait(timeout: timeout) == .success, let result else {
    emit(Output(ok: false, version: nil, stdout_base64: nil, public_key: nil, error: "Native broker request timed out"), status: 1)
}
emit(result, status: result.ok ? 0 : 1)
