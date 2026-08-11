import AgentPassNativeCore
import CryptoKit
import Darwin
import Foundation

private func loadProtectedFile(path: String, label: String) throws -> Data {
    let original = URL(fileURLWithPath: path).standardizedFileURL
    guard original.path.hasPrefix("/"), original.resolvingSymlinksInPath().path == original.path else {
        throw AgentPassNativeError.invalidConfiguration("\(label) path must be absolute and contain no symbolic links")
    }
    var current = original
    while true {
        let attributes = try FileManager.default.attributesOfItem(atPath: current.path)
        let owner = (attributes[.ownerAccountID] as? NSNumber)?.uint32Value
        let permissions = (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? 0xffff
        guard owner == 0, permissions & 0o022 == 0 else {
            throw AgentPassNativeError.invalidConfiguration("\(label) and every parent must be root-owned and not group/world writable")
        }
        if current.path == "/" { break }
        current.deleteLastPathComponent()
    }
    let attributes = try FileManager.default.attributesOfItem(atPath: original.path)
    guard (attributes[.type] as? FileAttributeType) == .typeRegular else {
        throw AgentPassNativeError.invalidConfiguration("\(label) must be a regular file")
    }
    return try Data(contentsOf: original, options: .mappedIfSafe)
}

private func validateProtectedOutputPath(path: String, label: String) throws {
    let original = URL(fileURLWithPath: path).standardizedFileURL
    guard original.path.hasPrefix("/") else {
        throw AgentPassNativeError.invalidConfiguration("\(label) path must be absolute")
    }
    var info = stat()
    let exists = lstat(original.path, &info) == 0
    if !exists, errno != ENOENT { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    let first = exists ? original : original.deletingLastPathComponent()
    guard first.resolvingSymlinksInPath().path == first.path else {
        throw AgentPassNativeError.invalidConfiguration("\(label) path must contain no symbolic links")
    }
    var current = first
    while true {
        let attributes = try FileManager.default.attributesOfItem(atPath: current.path)
        let owner = (attributes[.ownerAccountID] as? NSNumber)?.uint32Value
        let permissions = (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? 0xffff
        guard owner == 0, permissions & 0o022 == 0 else {
            throw AgentPassNativeError.invalidConfiguration("\(label) and every existing parent must be root-owned and not group/world writable")
        }
        if current.path == "/" { break }
        current.deleteLastPathComponent()
    }
    if exists {
        let attributes = try FileManager.default.attributesOfItem(atPath: original.path)
        guard (info.st_mode & S_IFMT) == S_IFREG, (attributes[.type] as? FileAttributeType) == .typeRegular, permissions(attributes) & 0o077 == 0 else {
            throw AgentPassNativeError.invalidConfiguration("\(label) must be a private regular file")
        }
    }
}

private func permissions(_ attributes: [FileAttributeKey: Any]) -> UInt16 {
    (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? 0xffff
}

private struct ServiceConfiguration: Decodable {
    let machServiceName: String
    let keyTag: String
    let keychainAccessGroup: String?
    let policyPath: String
    let auditLogPath: String
    let auditCheckpointPath: String
    let auditKeyTag: String
    let sessionApprovalPublicKey: String?
    let clientCodeSigningRequirement: String
    let allowedClientUID: UInt32

    enum CodingKeys: String, CodingKey {
        case machServiceName = "mach_service_name"
        case keyTag = "key_tag"
        case keychainAccessGroup = "keychain_access_group"
        case policyPath = "policy_path"
        case auditLogPath = "audit_log_path"
        case auditCheckpointPath = "audit_checkpoint_path"
        case auditKeyTag = "audit_key_tag"
        case sessionApprovalPublicKey = "session_approval_public_key"
        case clientCodeSigningRequirement = "client_code_signing_requirement"
        case allowedClientUID = "allowed_client_uid"
    }

    static func load(path: String) throws -> Self {
        let value = try JSONDecoder().decode(Self.self, from: loadProtectedFile(path: path, label: "Native service configuration"))
        guard !value.machServiceName.isEmpty, !value.keyTag.isEmpty, !value.auditKeyTag.isEmpty, value.policyPath.hasPrefix("/"), value.auditLogPath.hasPrefix("/"), value.auditCheckpointPath.hasPrefix("/"),
              !value.clientCodeSigningRequirement.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw AgentPassNativeError.invalidConfiguration("Native service configuration contains empty trust parameters")
        }
        return value
    }
}

private final class ServiceEndpoint: NSObject, AgentPassNativeServiceProtocol {
    private let keyStore: SecureEnclaveKeyStore
    private let authorizer: NativeRequestAuthorizer
    private let auditLog: NativeAuditLog
    private let auditCheckpoints: NativeAuditCheckpoints
    private let auditSigner: SecureEnclaveKeyStore
    private let sessionManager: NativeSessionManager?
    private let authorizationLock = NSLock()

    init(keyStore: SecureEnclaveKeyStore, authorizer: NativeRequestAuthorizer, auditLog: NativeAuditLog, auditCheckpoints: NativeAuditCheckpoints, auditSigner: SecureEnclaveKeyStore, sessionManager: NativeSessionManager?) {
        self.keyStore = keyStore
        self.authorizer = authorizer
        self.auditLog = auditLog
        self.auditCheckpoints = auditCheckpoints
        self.auditSigner = auditSigner
        self.sessionManager = sessionManager
    }

    func health(withReply reply: @escaping (NSDictionary) -> Void) {
        do {
            let audit = try auditLog.verify()
            let checkpoints = try auditCheckpoints.verify()
            let session = sessionManager?.status()
            let approvalFingerprint: Any = sessionManager?.approvalKeyFingerprint ?? NSNull()
            reply(["ok": true, "protocol_version": 3, "key_backend": "secure-enclave", "audit_entries": audit.entries, "audit_checkpoints": checkpoints.count, "session_required": session?.required ?? false, "active_sessions": session?.active ?? 0, "session_generation": session?.generation ?? 0, "session_approval_key_fingerprint": approvalFingerprint])
        } catch {
            reply(["ok": false, "protocol_version": 3, "error": error.localizedDescription])
        }
    }

    func publicKey(withReply reply: @escaping (NSString?, NSError?) -> Void) {
        do { reply(try SSHSIG.authorizedKey(publicKeyX963: keyStore.publicKeyX963) as NSString, nil) }
        catch { reply(nil, error as NSError) }
    }

    func sign(request: NSData, withReply reply: @escaping (NSString?, NSError?) -> Void) {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        do { _ = try auditCheckpoints.verify() }
        catch { reply(nil, error as NSError); return }
        let authorized: AuthorizedSignRequest
        do {
            authorized = try authorizer.authorize(requestData: request as Data)
        } catch let authorizationError {
            do { try auditLog.append(NativeAuditEvent(operation: "git.commit.sign", decision: "deny", reason: authorizationError.localizedDescription)) }
            catch let auditError { reply(nil, auditError as NSError); return }
            reply(nil, authorizationError as NSError)
            return
        }
        do {
            let signature = try SSHSIG.sign(payload: authorized.payload, signer: keyStore)
            let payloadHash = SHA256.hash(data: authorized.payload).map { String(format: "%02x", $0) }.joined()
            try auditLog.append(NativeAuditEvent(operation: "git.commit.sign", decision: "allow", reason: "allowed", agentID: authorized.agentID, repository: authorized.repository, branch: authorized.branch, remote: authorized.remote, payloadSHA256: payloadHash))
            reply(signature as NSString, nil)
        } catch let signingError {
            do { try auditLog.append(NativeAuditEvent(operation: "git.commit.sign", decision: "error", reason: signingError.localizedDescription, agentID: authorized.agentID, repository: authorized.repository, branch: authorized.branch, remote: authorized.remote)) }
            catch let auditError { reply(nil, auditError as NSError); return }
            reply(nil, signingError as NSError)
        }
    }

    func auditStatus(withReply reply: @escaping (NSData?, NSError?) -> Void) {
        do {
            let audit = try auditLog.verify()
            let checkpoints = try auditCheckpoints.verify()
            let latest: Any = checkpoints.last?.checkpointHash ?? NSNull()
            let fingerprint = NativeAuditCheckpoints.fingerprint(auditSigner.publicKeyX963)
            let session = sessionManager?.status()
            let approvalFingerprint: Any = sessionManager?.approvalKeyFingerprint ?? NSNull()
            let data = try JSONSerialization.data(withJSONObject: ["valid": true, "entries": audit.entries, "head_hash": audit.headHash, "checkpoints": checkpoints.count, "latest_checkpoint": latest, "audit_key_fingerprint": fingerprint, "session_required": session?.required ?? false, "active_sessions": session?.active ?? 0, "session_generation": session?.generation ?? 0, "session_approval_key_fingerprint": approvalFingerprint], options: [.sortedKeys])
            reply(data as NSData, nil)
        } catch { reply(nil, error as NSError) }
    }

    func auditPublicKey(withReply reply: @escaping (NSString?, NSError?) -> Void) {
        do { reply(try SSHSIG.authorizedKey(publicKeyX963: auditSigner.publicKeyX963) as NSString, nil) }
        catch { reply(nil, error as NSError) }
    }

    func createAuditCheckpoint(withReply reply: @escaping (NSData?, NSError?) -> Void) {
        do { _ = try auditCheckpoints.verify() }
        catch { reply(nil, error as NSError); return }
        do {
            try auditLog.append(NativeAuditEvent(operation: "audit.checkpoint", decision: "allow"))
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            reply(try encoder.encode(auditCheckpoints.create()) as NSData, nil)
        } catch let checkpointError {
            do { try auditLog.append(NativeAuditEvent(operation: "audit.checkpoint", decision: "error", reason: checkpointError.localizedDescription)) }
            catch let auditError { reply(nil, auditError as NSError); return }
            reply(nil, checkpointError as NSError)
        }
    }

    func beginSession(agentID: NSString, ttlSeconds: Int, withReply reply: @escaping (NSData?, NSError?) -> Void) {
        guard let sessionManager else {
            reply(nil, AgentPassNativeError.invalidConfiguration("Protected native sessions are not configured") as NSError)
            return
        }
        do { _ = try auditCheckpoints.verify() }
        catch { reply(nil, error as NSError); return }
        do { reply(try sessionManager.beginSession(agentID: agentID as String, requestedTTLSeconds: ttlSeconds) as NSData, nil) }
        catch let sessionError {
            do { try auditLog.append(NativeAuditEvent(operation: "session.start", decision: "deny", reason: sessionError.localizedDescription, agentID: agentID as String)) }
            catch let auditError { reply(nil, auditError as NSError); return }
            reply(nil, sessionError as NSError)
        }
    }

    func completeSession(challenge: NSData, signature: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        guard let sessionManager else {
            reply(nil, AgentPassNativeError.invalidConfiguration("Protected native sessions are not configured") as NSError)
            return
        }
        do { _ = try auditCheckpoints.verify() }
        catch { reply(nil, error as NSError); return }
        do {
            let issued = try sessionManager.completeSession(challengeData: challenge as Data, signature: signature as Data)
            do { try auditLog.append(NativeAuditEvent(operation: "session.start", decision: "allow", agentID: issued.agentID, expiresAt: issued.expiresAt)) }
            catch let auditError {
                sessionManager.discardSession(token: issued.token)
                reply(nil, auditError as NSError)
                return
            }
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            reply(try encoder.encode(issued) as NSData, nil)
        } catch let sessionError {
            do { try auditLog.append(NativeAuditEvent(operation: "session.start", decision: "deny", reason: sessionError.localizedDescription)) }
            catch let auditError { reply(nil, auditError as NSError); return }
            reply(nil, sessionError as NSError)
        }
    }

    func revokeSessions(withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        guard let sessionManager else {
            reply(nil, AgentPassNativeError.invalidConfiguration("Protected native sessions are not configured") as NSError)
            return
        }
        do { _ = try auditCheckpoints.verify() }
        catch { reply(nil, error as NSError); return }
        let revoked = sessionManager.revokeAll()
        do {
            try auditLog.append(NativeAuditEvent(operation: "session.revoke-all", decision: "allow", reason: "generation=\(revoked.generation);revoked=\(revoked.revokedSessions)"))
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            reply(try encoder.encode(revoked) as NSData, nil)
        } catch { reply(nil, error as NSError) }
    }

    func validateSession(token: NSString?, agentID: NSString, withReply reply: @escaping (Bool, NSError?) -> Void) {
        do { _ = try auditCheckpoints.verify() }
        catch { reply(false, error as NSError); return }
        guard let sessionManager else { reply(true, nil); return }
        do {
            try sessionManager.validateSession(token: token as String?, agentID: agentID as String, nowMilliseconds: Int64(Date().timeIntervalSince1970 * 1000))
            reply(true, nil)
        } catch { reply(false, nil) }
    }
}

private final class ListenerDelegate: NSObject, NSXPCListenerDelegate {
    private let configuration: ServiceConfiguration
    private let endpoint: ServiceEndpoint

    init(configuration: ServiceConfiguration, endpoint: ServiceEndpoint) {
        self.configuration = configuration
        self.endpoint = endpoint
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard connection.effectiveUserIdentifier == configuration.allowedClientUID else { return false }
        connection.setCodeSigningRequirement(configuration.clientCodeSigningRequirement)
        connection.exportedInterface = NSXPCInterface(with: AgentPassNativeServiceProtocol.self)
        connection.exportedObject = endpoint
        connection.resume()
        return true
    }
}

do {
    guard CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--config" else {
        throw AgentPassNativeError.invalidConfiguration("Usage: agentpass-native-service --config /Library/Application Support/AgentPass/native-service.json")
    }
    let configuration = try ServiceConfiguration.load(path: CommandLine.arguments[2])
    try validateProtectedOutputPath(path: configuration.auditLogPath, label: "Native audit log")
    try validateProtectedOutputPath(path: configuration.auditCheckpointPath, label: "Native audit checkpoint log")
    let policyData = try loadProtectedFile(path: configuration.policyPath, label: "Native policy")
    let sessionManager = try configuration.sessionApprovalPublicKey.map { try NativeSessionManager(policyData: policyData, approvalPublicKey: $0) }
    let keyStore = try SecureEnclaveKeyStore(
        applicationTag: configuration.keyTag,
        accessGroup: configuration.keychainAccessGroup
    )
    let auditSigner = try SecureEnclaveKeyStore(applicationTag: configuration.auditKeyTag, accessGroup: configuration.keychainAccessGroup)
    let auditLog = try NativeAuditLog(path: configuration.auditLogPath)
    let auditCheckpoints = try NativeAuditCheckpoints(path: configuration.auditCheckpointPath, auditLog: auditLog, signer: auditSigner)
    _ = try auditLog.verify()
    _ = try auditCheckpoints.verify()
    let authorizer = try NativeRequestAuthorizer(policyData: policyData, sessionValidator: sessionManager)
    let listener = NSXPCListener(machServiceName: configuration.machServiceName)
    let delegate = ListenerDelegate(configuration: configuration, endpoint: ServiceEndpoint(keyStore: keyStore, authorizer: authorizer, auditLog: auditLog, auditCheckpoints: auditCheckpoints, auditSigner: auditSigner, sessionManager: sessionManager))
    listener.delegate = delegate
    listener.resume()
    RunLoop.current.run()
} catch {
    FileHandle.standardError.write(Data("agentpass-native-service: \(error.localizedDescription)\n".utf8))
    exit(1)
}
