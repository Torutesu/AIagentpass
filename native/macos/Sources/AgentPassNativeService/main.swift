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

private func validateProtectedDirectoryPath(path: String, label: String) throws {
    let original = URL(fileURLWithPath: path).standardizedFileURL
    guard original.path.hasPrefix("/"), original.resolvingSymlinksInPath().path == original.path else {
        throw AgentPassNativeError.invalidConfiguration("\(label) path must be absolute and contain no symbolic links")
    }
    var current = original
    while true {
        let attributes = try FileManager.default.attributesOfItem(atPath: current.path)
        let owner = (attributes[.ownerAccountID] as? NSNumber)?.uint32Value
        guard owner == 0, permissions(attributes) & 0o022 == 0 else {
            throw AgentPassNativeError.invalidConfiguration("\(label) and every parent must be root-owned and not group/world writable")
        }
        if current.path == "/" { break }
        current.deleteLastPathComponent()
    }
    let attributes = try FileManager.default.attributesOfItem(atPath: original.path)
    guard (attributes[.type] as? FileAttributeType) == .typeDirectory, permissions(attributes) & 0o077 == 0 else {
        throw AgentPassNativeError.invalidConfiguration("\(label) must be a private directory")
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
    let auditArchiveDirectory: String?
    let auditCheckpointPath: String
    let auditKeyTag: String
    let auditAnchorURL: String?
    let auditAnchorTenant: String?
    let auditAnchorPublicKey: String?
    let auditAnchorReceiptPath: String?
    let controlStatePath: String?
    let controlURL: String?
    let controlRefreshSeconds: Int?
    let sessionApprovalPublicKey: String?
    let clientCodeSigningRequirement: String
    let allowedClientUID: UInt32

    enum CodingKeys: String, CodingKey {
        case machServiceName = "mach_service_name"
        case keyTag = "key_tag"
        case keychainAccessGroup = "keychain_access_group"
        case policyPath = "policy_path"
        case auditLogPath = "audit_log_path"
        case auditArchiveDirectory = "audit_archive_directory"
        case auditCheckpointPath = "audit_checkpoint_path"
        case auditKeyTag = "audit_key_tag"
        case auditAnchorURL = "audit_anchor_url"
        case auditAnchorTenant = "audit_anchor_tenant"
        case auditAnchorPublicKey = "audit_anchor_public_key"
        case auditAnchorReceiptPath = "audit_anchor_receipt_path"
        case controlStatePath = "control_state_path"
        case controlURL = "control_url"
        case controlRefreshSeconds = "control_refresh_seconds"
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
        if value.controlURL != nil || value.controlRefreshSeconds != nil {
            guard value.controlStatePath != nil, let rawURL = value.controlURL, let interval = value.controlRefreshSeconds else {
                throw AgentPassNativeError.invalidConfiguration("Native control refresh requires protected state, URL, and interval")
            }
            _ = try NativeControlRefreshConfiguration(urlString: rawURL, refreshSeconds: interval)
        }
        let anchorValues: [Any?] = [value.auditAnchorURL, value.auditAnchorTenant, value.auditAnchorPublicKey, value.auditAnchorReceiptPath]
        if anchorValues.contains(where: { $0 != nil }) {
            guard let rawURL = value.auditAnchorURL, let url = URL(string: rawURL), let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
                  let tenant = value.auditAnchorTenant, let publicKey = value.auditAnchorPublicKey,
                  let receiptPath = value.auditAnchorReceiptPath else {
                throw AgentPassNativeError.invalidConfiguration("Native audit anchor requires URL, tenant, public key, and receipt path")
            }
            guard components.scheme?.lowercased() == "https", components.host?.isEmpty == false,
                  components.user == nil, components.password == nil, components.query == nil, components.fragment == nil else {
                throw AgentPassNativeError.invalidConfiguration("Native audit anchor requires a credential-free HTTPS URL")
            }
            _ = try NativeAuditAnchorReceipts(path: receiptPath, tenant: tenant, anchorPublicKeyPEM: publicKey)
        }
        return value
    }
}

private final class ServiceEndpoint: NSObject, AgentPassNativeServiceProtocol, @unchecked Sendable {
    private let keyStore: SecureEnclaveKeyStore
    private let authorizer: NativeRequestAuthorizer
    private let auditLog: NativeAuditLog
    private let auditCheckpoints: NativeAuditCheckpoints
    private let auditSigner: SecureEnclaveKeyStore
    private let auditAnchorReceipts: NativeAuditAnchorReceipts?
    private let auditAnchorClient: NativeAuditAnchorClient?
    private let sessionManager: NativeSessionManager?
    private let controlManager: NativeControlManager?
    private let authorizationLock = NSLock()
    private var controlFetcher: NativeControlFetcher?
    private var lastControlFetchAuditReason: String?
    private var lastControlFetchAuditAt: Date?

    init(keyStore: SecureEnclaveKeyStore, authorizer: NativeRequestAuthorizer, auditLog: NativeAuditLog, auditCheckpoints: NativeAuditCheckpoints, auditSigner: SecureEnclaveKeyStore, auditAnchorReceipts: NativeAuditAnchorReceipts?, auditAnchorClient: NativeAuditAnchorClient?, sessionManager: NativeSessionManager?, controlManager: NativeControlManager?) {
        self.keyStore = keyStore
        self.authorizer = authorizer
        self.auditLog = auditLog
        self.auditCheckpoints = auditCheckpoints
        self.auditSigner = auditSigner
        self.auditAnchorReceipts = auditAnchorReceipts
        self.auditAnchorClient = auditAnchorClient
        self.sessionManager = sessionManager
        self.controlManager = controlManager
    }

    func startControlRefresh(url: URL, refreshSeconds: Int) throws {
        let fetcher = try NativeControlFetcher(sourceURL: url, refreshSeconds: refreshSeconds) { [weak self] outcome in
            guard let self else { throw AgentPassNativeError.invalidConfiguration("Native control service is unavailable") }
            try self.handleControlFetch(outcome)
        }
        controlFetcher = fetcher
        fetcher.start()
    }

    func health(withReply reply: @escaping (NSDictionary) -> Void) {
        do {
            let audit = try auditLog.verify()
            let storage = try auditLog.storageStatus()
            let checkpoints = try auditCheckpoints.verify()
            let session = sessionManager?.status()
            let approvalFingerprint: Any = sessionManager?.approvalKeyFingerprint ?? NSNull()
            let control = controlManager?.status()
            let fetch = controlFetcher?.status()
            let anchor = try auditAnchorReceipts?.status(checkpoints: checkpoints)
            reply(["ok": true, "protocol_version": 8, "key_backend": "secure-enclave", "audit_entries": audit.entries, "audit_archive_configured": storage.configured, "audit_archive_segments": storage.segments, "audit_active_bytes": storage.activeBytes, "audit_rotation_ready": storage.rotationReady, "audit_checkpoints": checkpoints.count, "audit_anchor_configured": anchor != nil, "audit_anchor_receipts": anchor?.receipts ?? 0, "audit_anchor_pending": anchor?.pending ?? 0, "audit_anchor_latest_receipt": anchor?.latestReceiptHash ?? NSNull(), "session_required": session?.required ?? false, "active_sessions": session?.active ?? 0, "session_generation": session?.generation ?? 0, "session_approval_key_fingerprint": approvalFingerprint, "control_configured": control != nil, "control_sequence": control?.sequence ?? 0, "control_operational": control?.operational ?? true, "control_expired": control?.expired ?? false, "control_expires_at": control?.expiresAt ?? NSNull(), "control_refresh_configured": fetch != nil, "control_refresh_in_flight": fetch?.inFlight ?? false, "control_refresh_last_attempt_at": fetch?.lastAttemptAt ?? NSNull(), "control_refresh_last_success_at": fetch?.lastSuccessAt ?? NSNull(), "control_refresh_last_error": fetch?.lastError ?? NSNull(), "control_refresh_next_attempt_at": fetch?.nextAttemptAt ?? NSNull(), "control_refresh_consecutive_failures": fetch?.consecutiveFailures ?? 0])
        } catch {
            reply(["ok": false, "protocol_version": 8, "error": error.localizedDescription])
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
            catch let auditError {
                controlManager?.invalidate()
                reply(nil, auditError as NSError)
                return
            }
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
            catch let auditError {
                controlManager?.invalidate()
                reply(nil, auditError as NSError)
                return
            }
            reply(nil, signingError as NSError)
        }
    }

    func auditStatus(withReply reply: @escaping (NSData?, NSError?) -> Void) {
        do {
            let audit = try auditLog.verify()
            let storage = try auditLog.storageStatus()
            let checkpoints = try auditCheckpoints.verify()
            let latest: Any = checkpoints.last?.checkpointHash ?? NSNull()
            let fingerprint = NativeAuditCheckpoints.fingerprint(auditSigner.publicKeyX963)
            let session = sessionManager?.status()
            let approvalFingerprint: Any = sessionManager?.approvalKeyFingerprint ?? NSNull()
            let control = controlManager?.status()
            let fetch = controlFetcher?.status()
            let data = try JSONSerialization.data(withJSONObject: ["valid": true, "entries": audit.entries, "archive_configured": storage.configured, "archive_segments": storage.segments, "active_bytes": storage.activeBytes, "rotation_ready": storage.rotationReady, "head_hash": audit.headHash, "checkpoints": checkpoints.count, "latest_checkpoint": latest, "audit_key_fingerprint": fingerprint, "session_required": session?.required ?? false, "active_sessions": session?.active ?? 0, "session_generation": session?.generation ?? 0, "session_approval_key_fingerprint": approvalFingerprint, "control_configured": control != nil, "control_sequence": control?.sequence ?? 0, "control_operational": control?.operational ?? true, "control_expired": control?.expired ?? false, "control_expires_at": control?.expiresAt ?? NSNull(), "control_refresh_configured": fetch != nil, "control_refresh_last_attempt_at": fetch?.lastAttemptAt ?? NSNull(), "control_refresh_last_success_at": fetch?.lastSuccessAt ?? NSNull(), "control_refresh_last_error": fetch?.lastError ?? NSNull(), "control_refresh_next_attempt_at": fetch?.nextAttemptAt ?? NSNull(), "control_refresh_consecutive_failures": fetch?.consecutiveFailures ?? 0], options: [.sortedKeys])
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

    func rotateAudit(withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        do {
            guard try auditLog.canRotate() else {
                throw AgentPassNativeError.invalidConfiguration("Native audit log has not reached the 64 MiB rotation threshold")
            }
            _ = try auditCheckpoints.create()
            let rotation = try auditLog.rotate()
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            reply(try encoder.encode(rotation) as NSData, nil)
        } catch { reply(nil, error as NSError) }
    }

    func auditAnchorStatus(withReply reply: @escaping (NSData?, NSError?) -> Void) {
        guard let auditAnchorReceipts else {
            do { reply(try JSONSerialization.data(withJSONObject: ["configured": false], options: [.sortedKeys]) as NSData, nil) }
            catch { reply(nil, error as NSError) }
            return
        }
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            reply(try encoder.encode(auditAnchorReceipts.status(checkpoints: auditCheckpoints.verify())) as NSData, nil)
        } catch { reply(nil, error as NSError) }
    }

    func pushAuditAnchor(withReply reply: @escaping (NSData?, NSError?) -> Void) {
        guard let auditAnchorReceipts, let auditAnchorClient else {
            reply(nil, AgentPassNativeError.invalidConfiguration("Native audit anchor is not configured") as NSError)
            return
        }
        let checkpoint: NativeAuditCheckpoint
        authorizationLock.lock()
        do {
            var checkpoints = try auditCheckpoints.verify()
            if try auditAnchorReceipts.pendingCheckpoint(checkpoints: checkpoints) == nil {
                try auditLog.append(NativeAuditEvent(operation: "audit.anchor.push", decision: "allow", reason: "queued"))
                _ = try auditCheckpoints.create()
                checkpoints = try auditCheckpoints.verify()
            }
            guard let pending = try auditAnchorReceipts.pendingCheckpoint(checkpoints: checkpoints) else {
                throw AgentPassNativeError.invalidConfiguration("Native audit anchor has no pending checkpoint")
            }
            checkpoint = pending
            authorizationLock.unlock()
        } catch {
            authorizationLock.unlock()
            reply(nil, error as NSError)
            return
        }
        do {
            try auditAnchorClient.post(checkpoint: checkpoint) { [weak self] result in
                guard let self else {
                    reply(nil, AgentPassNativeError.invalidConfiguration("Native audit anchor service is unavailable") as NSError)
                    return
                }
                self.authorizationLock.lock()
                defer { self.authorizationLock.unlock() }
                do {
                    switch result {
                    case .success(let receiptData):
                        let checkpoints = try self.auditCheckpoints.verify()
                        let status = try auditAnchorReceipts.accept(receiptData: receiptData, checkpoint: checkpoint, checkpoints: checkpoints)
                        try self.auditLog.append(NativeAuditEvent(operation: "audit.anchor.push", decision: "allow", reason: "checkpoint=\(checkpoint.checkpointHash);receipt=\(status.latestReceiptHash ?? "")"))
                        let encoder = JSONEncoder()
                        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
                        reply(try encoder.encode(status) as NSData, nil)
                    case .failure(let pushError):
                        do { try self.auditLog.append(NativeAuditEvent(operation: "audit.anchor.push", decision: "error", reason: pushError.localizedDescription)) }
                        catch { reply(nil, error as NSError); return }
                        reply(nil, pushError as NSError)
                    }
                } catch { reply(nil, error as NSError) }
            }
        } catch {
            authorizationLock.lock()
            defer { authorizationLock.unlock() }
            do { try auditLog.append(NativeAuditEvent(operation: "audit.anchor.push", decision: "error", reason: error.localizedDescription)) }
            catch { reply(nil, error as NSError); return }
            reply(nil, error as NSError)
        }
    }

    func beginSession(agentID: NSString, ttlSeconds: Int, withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        guard let sessionManager else {
            reply(nil, AgentPassNativeError.invalidConfiguration("Protected native sessions are not configured") as NSError)
            return
        }
        do { _ = try auditCheckpoints.verify() }
        catch { reply(nil, error as NSError); return }
        do {
            try controlManager?.validateControl(agentID: agentID as String, nowMilliseconds: Int64(Date().timeIntervalSince1970 * 1000))
            reply(try sessionManager.beginSession(agentID: agentID as String, requestedTTLSeconds: ttlSeconds) as NSData, nil)
        }
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
            do { try controlManager?.validateControl(agentID: issued.agentID, nowMilliseconds: Int64(Date().timeIntervalSince1970 * 1000)) }
            catch {
                sessionManager.discardSession(token: issued.token)
                throw error
            }
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

    func applyControlBundle(bundle: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) {
        do {
            let status = try applyControlUpdate(bundleData: bundle as Data, operation: "control.apply")
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            reply(try encoder.encode(status) as NSData, nil)
        } catch { reply(nil, error as NSError) }
    }

    func controlStatus(withReply reply: @escaping (NSData?, NSError?) -> Void) {
        do { _ = try auditCheckpoints.verify() }
        catch { reply(nil, error as NSError); return }
        guard let controlManager else {
            do { reply(try JSONSerialization.data(withJSONObject: ["configured": false], options: [.sortedKeys]) as NSData, nil) }
            catch { reply(nil, error as NSError) }
            return
        }
        do {
            let encoder = JSONEncoder(), status = controlManager.status()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            var object = try JSONSerialization.jsonObject(with: encoder.encode(status)) as! [String: Any]
            let fetch = controlFetcher?.status()
            object["refresh_configured"] = fetch != nil
            object["refresh_source_url"] = fetch?.sourceURL ?? NSNull()
            object["refresh_in_flight"] = fetch?.inFlight ?? false
            object["refresh_last_attempt_at"] = fetch?.lastAttemptAt ?? NSNull()
            object["refresh_last_success_at"] = fetch?.lastSuccessAt ?? NSNull()
            object["refresh_last_error"] = fetch?.lastError ?? NSNull()
            object["refresh_next_attempt_at"] = fetch?.nextAttemptAt ?? NSNull()
            object["refresh_consecutive_failures"] = fetch?.consecutiveFailures ?? 0
            reply(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) as NSData, nil)
        } catch { reply(nil, error as NSError) }
    }

    func validateControl(agentID: NSString, withReply reply: @escaping (Bool, NSError?) -> Void) {
        do { _ = try auditCheckpoints.verify() }
        catch { reply(false, error as NSError); return }
        guard let controlManager else { reply(true, nil); return }
        do {
            try controlManager.validateControl(agentID: agentID as String, nowMilliseconds: Int64(Date().timeIntervalSince1970 * 1000))
            reply(true, nil)
        } catch { reply(false, nil) }
    }

    private func handleControlFetch(_ outcome: NativeControlFetchOutcome) throws {
        switch outcome {
        case .success(let data):
            _ = try applyControlUpdate(bundleData: data, operation: "control.fetch")
        case .failure(let reason):
            authorizationLock.lock()
            defer { authorizationLock.unlock() }
            guard let controlManager else { throw AgentPassNativeError.invalidConfiguration("Native remote control is not configured") }
            _ = try auditCheckpoints.verify()
            do { try appendControlFetchFailureIfNeeded(decision: "error", reason: reason) }
            catch {
                controlManager.invalidate()
                throw error
            }
        }
    }

    private func applyControlUpdate(bundleData: Data, operation: String) throws -> NativeControlStatus {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        guard let controlManager else { throw AgentPassNativeError.invalidConfiguration("Native remote control is not configured") }
        _ = try auditCheckpoints.verify()
        let requiresUpdate: Bool
        do { requiresUpdate = try controlManager.validateBundle(bundleData: bundleData) }
        catch let controlError {
            do {
                if operation == "control.fetch" { try appendControlFetchFailureIfNeeded(decision: "deny", reason: controlError.localizedDescription) }
                else { try auditLog.append(NativeAuditEvent(operation: operation, decision: "deny", reason: controlError.localizedDescription)) }
            }
            catch {
                controlManager.invalidate()
                throw error
            }
            throw controlError
        }
        if operation == "control.fetch" {
            lastControlFetchAuditReason = nil
            lastControlFetchAuditAt = nil
        }
        if !requiresUpdate { return controlManager.status() }
        try controlManager.beginAuditedUpdate()
        let status: NativeControlStatus
        do { status = try controlManager.apply(bundleData: bundleData) }
        catch {
            controlManager.invalidate()
            _ = try? auditLog.append(NativeAuditEvent(operation: operation, decision: "error", reason: error.localizedDescription))
            throw error
        }
        let revokedSessions = sessionManager?.revokeAll()
        do {
            let sessionReason = revokedSessions.map { ";session_generation=\($0.generation);sessions_revoked=\($0.revokedSessions)" } ?? ""
            try auditLog.append(NativeAuditEvent(operation: operation, decision: "allow", reason: "sequence=\(status.sequence);expires_at=\(status.expiresAt)\(sessionReason)"))
            try controlManager.completeAuditedUpdate()
        } catch {
            controlManager.invalidate()
            throw error
        }
        return status
    }

    private func appendControlFetchFailureIfNeeded(decision: String, reason: String) throws {
        let now = Date()
        let elapsed = lastControlFetchAuditAt.map { now.timeIntervalSince($0) }
        let key = "\(decision):\(reason)"
        let shouldAppend = elapsed.map { $0 >= 3600 || (lastControlFetchAuditReason != key && $0 >= 300) } ?? true
        guard shouldAppend else { return }
        try auditLog.append(NativeAuditEvent(operation: "control.fetch", decision: decision, reason: reason))
        lastControlFetchAuditReason = key
        lastControlFetchAuditAt = now
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
    if let archiveDirectory = configuration.auditArchiveDirectory {
        try validateProtectedDirectoryPath(path: archiveDirectory, label: "Native audit archive directory")
    }
    try validateProtectedOutputPath(path: configuration.auditCheckpointPath, label: "Native audit checkpoint log")
    if let controlStatePath = configuration.controlStatePath {
        try validateProtectedOutputPath(path: controlStatePath, label: "Native control state")
    }
    if let receiptPath = configuration.auditAnchorReceiptPath {
        try validateProtectedOutputPath(path: receiptPath, label: "Native audit anchor receipt log")
    }
    let policyData = try loadProtectedFile(path: configuration.policyPath, label: "Native policy")
    let sessionManager = try configuration.sessionApprovalPublicKey.map { try NativeSessionManager(policyData: policyData, approvalPublicKey: $0) }
    let controlManager = try configuration.controlStatePath.map { try NativeControlManager(policyData: policyData, statePath: $0) }
    let keyStore = try SecureEnclaveKeyStore(
        applicationTag: configuration.keyTag,
        accessGroup: configuration.keychainAccessGroup
    )
    let auditSigner = try SecureEnclaveKeyStore(applicationTag: configuration.auditKeyTag, accessGroup: configuration.keychainAccessGroup)
    let auditLog = try NativeAuditLog(path: configuration.auditLogPath, archiveDirectory: configuration.auditArchiveDirectory)
    let auditCheckpoints = try NativeAuditCheckpoints(path: configuration.auditCheckpointPath, auditLog: auditLog, signer: auditSigner)
    let auditAnchorReceipts: NativeAuditAnchorReceipts?
    let auditAnchorClient: NativeAuditAnchorClient?
    if let rawURL = configuration.auditAnchorURL, let url = URL(string: rawURL),
       let tenant = configuration.auditAnchorTenant, let publicKey = configuration.auditAnchorPublicKey,
       let receiptPath = configuration.auditAnchorReceiptPath {
        auditAnchorReceipts = try NativeAuditAnchorReceipts(path: receiptPath, tenant: tenant, anchorPublicKeyPEM: publicKey)
        auditAnchorClient = try NativeAuditAnchorClient(url: url, tenant: tenant)
    } else {
        auditAnchorReceipts = nil
        auditAnchorClient = nil
    }
    _ = try auditLog.verify()
    _ = try auditCheckpoints.verify()
    let authorizer = try NativeRequestAuthorizer(policyData: policyData, sessionValidator: sessionManager, controlValidator: controlManager)
    let listener = NSXPCListener(machServiceName: configuration.machServiceName)
    let endpoint = ServiceEndpoint(keyStore: keyStore, authorizer: authorizer, auditLog: auditLog, auditCheckpoints: auditCheckpoints, auditSigner: auditSigner, auditAnchorReceipts: auditAnchorReceipts, auditAnchorClient: auditAnchorClient, sessionManager: sessionManager, controlManager: controlManager)
    if let rawURL = configuration.controlURL, let interval = configuration.controlRefreshSeconds {
        let refresh = try NativeControlRefreshConfiguration(urlString: rawURL, refreshSeconds: interval)
        try endpoint.startControlRefresh(url: refresh.url, refreshSeconds: refresh.refreshSeconds)
    }
    let delegate = ListenerDelegate(configuration: configuration, endpoint: endpoint)
    listener.delegate = delegate
    listener.resume()
    RunLoop.current.run()
} catch {
    FileHandle.standardError.write(Data("agentpass-native-service: \(error.localizedDescription)\n".utf8))
    exit(1)
}
