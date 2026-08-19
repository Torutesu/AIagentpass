import AgentPassNativeCore
import AgentPassNativeServiceSupport
import CryptoKit
import Darwin
import Foundation
import Security

private struct NativeFixedProcessObservationSource: NativeProcessObservationSource {
    let observation: NativeProcessObservation

    func observe() throws -> NativeProcessObservation {
        observation
    }
}

private func nativeDigestData(_ value: String) -> Data? {
    guard value.utf8.count == 64 else { return nil }
    var result = Data(capacity: 32)
    var high: UInt8?
    for byte in value.utf8 {
        let nibble: UInt8?
        switch byte {
        case 48...57: nibble = byte - 48
        case 97...102: nibble = byte - 87
        case 65...70: nibble = byte - 55
        default: nibble = nil
        }
        guard let nibble else { return nil }
        if let high {
            result.append((high << 4) | nibble)
        } else {
            high = nibble
        }
    }
    return high == nil && result.count == 32 ? result : nil
}

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

private func verifyQualificationConfigurationFile(path: String, expectedData: Data) throws {
    let descriptor = Darwin.open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else {
        throw AgentPassNativeError.invalidConfiguration("Agent qualification configuration is unavailable")
    }
    defer { Darwin.close(descriptor) }

    var before = stat()
    guard fstat(descriptor, &before) == 0,
          (before.st_mode & S_IFMT) == S_IFREG,
          before.st_uid == 0,
          (before.st_mode & 0o7777) == 0o600,
          before.st_nlink == 1,
          before.st_size > 0,
          before.st_size <= 1 * 1024 * 1024 else {
        throw AgentPassNativeError.invalidConfiguration("Agent qualification configuration must be a root-owned 0600 single-link regular file")
    }

    var bytes = Data(count: Int(before.st_size))
    let readCount = bytes.withUnsafeMutableBytes { buffer -> Int in
        guard let base = buffer.baseAddress else { return -1 }
        var offset = 0
        while offset < buffer.count {
            let count = Darwin.read(descriptor, base.advanced(by: offset), buffer.count - offset)
            if count <= 0 { return -1 }
            offset += count
        }
        return offset
    }
    var after = stat()
    var pathState = stat()
    guard readCount == bytes.count,
          fstat(descriptor, &after) == 0,
          lstat(path, &pathState) == 0,
          before.st_dev == after.st_dev,
          before.st_ino == after.st_ino,
          before.st_size == after.st_size,
          before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
          before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
          before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
          before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec,
          after.st_dev == pathState.st_dev,
          after.st_ino == pathState.st_ino,
          bytes == expectedData else {
        throw AgentPassNativeError.invalidConfiguration("Agent qualification configuration changed while being verified")
    }
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

private func serviceTimestamp(_ date: Date) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: date)
}

private func serviceTimestamp(milliseconds: Int64?) -> String? {
    guard let milliseconds, milliseconds >= 0 else { return nil }
    return serviceTimestamp(Date(timeIntervalSince1970: Double(milliseconds) / 1_000))
}

private func serviceDate(_ value: String) -> Date? {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.date(from: value)
}

private func serviceExactInteger(_ value: Any?) -> Int? {
    guard let number = value as? NSNumber, String(cString: number.objCType) == "q" else { return nil }
    return number.intValue
}

private func recoveryLifecycleStatement(_ plan: NativeAuditKeyRecoveryPlan) throws -> NativeKeyTransitionStatement {
    try recoveryLifecycleStatement(transition: plan.transition, lifecycleRecordData: plan.lifecycleRecordData)
}

private func recoveryLifecycleStatement(
    transition: NativeAuditKeyRecoveryTransition,
    lifecycleRecordData: Data
) throws -> NativeKeyTransitionStatement {
    guard let object = try JSONSerialization.jsonObject(with: lifecycleRecordData) as? [String: Any],
          let sequenceNumber = object["sequence"] as? NSNumber,
          String(cString: sequenceNumber.objCType) == "q",
          let reason = object["reason"] as? String,
          let challengeID = object["challenge_id"] as? String,
          let previousHead = object["previous_record_hash"] as? String else {
        throw AgentPassNativeError.invalidSignature("Durable audit recovery lifecycle statement cannot be reconstructed exactly")
    }
    return NativeKeyTransitionStatement(
        role: .auditCheckpoint,
        oldGeneration: transition.fromGeneration,
        newGeneration: transition.toGeneration,
        oldFingerprint: transition.oldKeyFingerprint,
        newFingerprint: transition.newKeyFingerprint,
        stateSequence: sequenceNumber.intValue,
        reason: reason,
        challengeID: challengeID,
        createdAt: transition.createdAt,
        previousLifecycleHead: previousHead,
        continuity: .recovered
    )
}

private func validateManagementReason(_ value: String) throws {
    guard !value.isEmpty, value.utf8.count <= 512,
          value.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value != 0x7f }) else {
        throw AgentPassNativeError.invalidConfiguration("Management reason must be 1-512 UTF-8 bytes without control characters")
    }
}

private func verifiedAuditPruneBoundary(
    lifecycle: NativeKeyLifecycleSnapshot,
    checkpoints: [NativeAuditCheckpoint],
    receipts: [NativeAuditAnchorReceipt],
    transitions: NativeAuditKeyTransitionStoreStatus
) throws -> NativeAuditRetentionBoundary {
    guard let checkpointReceipt = receipts.last,
          checkpointReceipt.index > 0, checkpointReceipt.index <= checkpoints.count,
          let checkpointEventIndex = checkpointReceipt.eventIndex,
          let checkpointPreviousEventHash = checkpointReceipt.previousEventHash,
          checkpointEventIndex > 0,
          let checkpoint = checkpoints.dropFirst(checkpointReceipt.index - 1).first,
          checkpoint.checkpointHash == checkpointReceipt.checkpointHash,
          checkpoint.lifecycleHeadHash == lifecycle.headHash else {
        throw AgentPassNativeError.invalidSignature("Audit prune requires a checkpoint receipt bound to the active lifecycle head and global anchor chain")
    }
    var eventIndex = checkpointEventIndex
    var eventHash = checkpointReceipt.receiptHash
    if let transitionIndex = transitions.latestEventIndex, let transitionHash = transitions.latestEventHash {
        guard transitionIndex != checkpointEventIndex || transitionHash == checkpointReceipt.receiptHash else {
            throw AgentPassNativeError.invalidSignature("Audit prune anchor global event index equivocates")
        }
        if transitionIndex > eventIndex { eventIndex = transitionIndex; eventHash = transitionHash }
    }
    guard !checkpointPreviousEventHash.isEmpty else {
        throw AgentPassNativeError.invalidSignature("Audit prune checkpoint receipt lacks global-chain ancestry")
    }
    return NativeAuditRetentionBoundary(
        lifecycleHeadHash: lifecycle.headHash,
        auditKeyTransitionReceiptHash: transitions.latestReceipt?.receiptHash ?? NativeAuditLog.zeroHash,
        anchorEventIndex: eventIndex, anchorEventHash: eventHash,
        checkpointIndex: checkpointReceipt.index, checkpointHash: checkpoint.checkpointHash,
        checkpointReceiptHash: checkpointReceipt.receiptHash
    )
}

private func ed25519RecoveryPublicKey(_ pem: String) throws -> Data {
    let lines = pem.split(whereSeparator: \ .isNewline).map(String.init)
    guard lines.count >= 3, lines.first == "-----BEGIN PUBLIC KEY-----", lines.last == "-----END PUBLIC KEY-----",
          lines.dropFirst().dropLast().allSatisfy({ !$0.isEmpty && $0.range(of: "^[A-Za-z0-9+/=]+$", options: .regularExpression) != nil }),
          let der = Data(base64Encoded: lines.dropFirst().dropLast().joined()) else {
        throw AgentPassNativeError.invalidKey("Recovery authority must be an Ed25519 SPKI PEM public key")
    }
    let prefix = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])
    guard der.count == prefix.count + 32, der.starts(with: prefix) else {
        throw AgentPassNativeError.invalidKey("Recovery authority must be an Ed25519 SPKI PEM public key")
    }
    let raw = Data(der.dropFirst(prefix.count))
    _ = try Curve25519.Signing.PublicKey(rawRepresentation: raw)
    return raw
}

private struct ServiceRefreshHintKey: Decodable {
    let keyID: String
    let algorithm: String
    let publicKey: String

    enum CodingKeys: String, CodingKey, CaseIterable {
        case keyID = "key_id"
        case algorithm
        case publicKey = "public_key"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard Set(container.allKeys) == Set(CodingKeys.allCases) else {
            throw DecodingError.dataCorruptedError(forKey: .keyID, in: container, debugDescription: "refresh hint keyring entry contains unknown fields")
        }
        keyID = try container.decode(String.self, forKey: .keyID)
        algorithm = try container.decode(String.self, forKey: .algorithm)
        publicKey = try container.decode(String.self, forKey: .publicKey)
    }
}

private let dedicatedChildHelperBundleIdentifier = "dev.agentpass.git-sign-xpc"

/// Returns only the fixed Child-helper requirement provisioned by the signed
/// product configuration. The Host and management requirements are separate
/// principals and are never valid fallbacks for this listener.
internal func deriveDedicatedChildCodeSigningRequirement(
    configuredChildRequirement: String?,
    hostCodeSigningRequirement: String,
    managementCodeSigningRequirement: String
) throws -> String {
    guard let configuredChildRequirement else {
        throw AgentPassNativeError.invalidConfiguration(
            "Native service configuration is missing the dedicated Child helper code-signing requirement"
        )
    }
    let requirement = configuredChildRequirement.trimmingCharacters(in: .whitespacesAndNewlines)
    let hostRequirement = hostCodeSigningRequirement.trimmingCharacters(in: .whitespacesAndNewlines)
    let managementRequirement = managementCodeSigningRequirement.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !requirement.isEmpty,
          requirement == configuredChildRequirement,
          !hostRequirement.isEmpty,
          !managementRequirement.isEmpty,
          requirement != hostRequirement,
          requirement != managementRequirement,
          requirement.contains("anchor apple generic"),
          requirement.components(separatedBy: "identifier \"").count == 2,
          requirement.contains("identifier \"\(dedicatedChildHelperBundleIdentifier)\""),
          requirement.range(of: #"\bor\b"#, options: .regularExpression) == nil else {
        throw AgentPassNativeError.invalidConfiguration(
            "Native service configuration must contain one unambiguous dedicated Child helper code-signing requirement"
        )
    }
    var parsedRequirement: SecRequirement?
    guard SecRequirementCreateWithString(requirement as CFString, [], &parsedRequirement) == errSecSuccess,
          parsedRequirement != nil else {
        throw AgentPassNativeError.invalidConfiguration(
            "Native service configuration contains an invalid dedicated Child helper code-signing requirement"
        )
    }
    return requirement
}

private struct ServiceConfiguration: Decodable {
    let machServiceName: String
    let agentMachServiceName: String
    let hostMachServiceName: String
    let childMachServiceName: String
    let keyTag: String
    let keychainAccessGroup: String?
    let keyLifecycleDirectory: String?
    let keyLifecycleExpectedHeadHash: String?
    let keyLifecyclePinDirectory: String?
    let keyLifecycleMutationOutboxDirectory: String?
    let recoveryPublicKeys: [String]?
    let recoveryThreshold: Int?
    let recoveryPolicyPath: String?
    let installationID: String?
    let policyPath: String
    let auditLogPath: String
    let auditArchiveDirectory: String?
    let auditCheckpointPath: String
    let auditCheckpointArchiveDirectory: String?
    let auditKeyTag: String
    let auditAnchorURL: String?
    let auditAnchorTenant: String?
    let auditAnchorPublicKey: String?
    let auditAnchorReceiptPath: String?
    let auditAnchorReceiptArchiveDirectory: String?
    let auditKeyTransitionPath: String?
    let auditKeyRotationPlanDirectory: String?
    let auditKeyRecoveryPlanDirectory: String?
    let auditKeyRecoveryApprovalDirectory: String?
    let auditPruneJournalDirectory: String?
    let auditPruneTrustDirectory: String?
    let auditPruneEvidenceBundlePath: String?
    let auditKeyDeletionEvidenceBundlePath: String?
    let auditKeyDeletionArchiveDirectory: String?
    let auditRetentionAuthorizerPublicKey: String?
    let auditKeyDeletionMinimumRetentionSeconds: Int?
    let controlStatePath: String?
    let controlURL: String?
    let controlRefreshSeconds: Int?
    let controlV2StatePath: String?
    let controlV2CapabilityStatePath: String?
    let controlV2RequestEvidencePath: String?
    let controlV2APIBaseURL: String?
    let controlV2RefreshStatePath: String?
    let controlV2BundleStorePath: String?
    let controlV2PublicKey: String?
    let controlV2Issuer: String?
    let controlV2KeyID: String?
    let controlV2OrganizationID: String?
    let controlV2DeviceID: String?
    let controlV2DeviceKeyEpoch: Int64?
    let controlV2RefreshHintKeyring: [ServiceRefreshHintKey]?
    let controlV2DeviceKeyTag: String?
    let agentSigningIntentDirectory: String?
    let agentGlobalSessionLimit: Int?
    let agentPerAgentSessionLimit: Int?
    let agentPerWorktreeSessionLimit: Int?
    let agentBootstrapAttemptLimit: Int?
    let agentWorktreeObservationPolicyVersion: Int?
    let agentCapabilityPublicKey: String?
    let agentCapabilityKeyID: String?
    let hostChildCodeDirectoryHash: String?
    let qualificationMode: String?
    let qualificationMachServiceName: String?
    let qualificationCandidateSHA256: String?
    let qualificationSourceCommitSHA256: String?
    let qualificationCodeIdentitiesSHA256: String?
    let qualificationControllerCDHash: String?
    let qualificationRunIDSHA256: String?
    let qualificationExpiresAtEpochSeconds: UInt64?
    let qualificationScenario: String?
    let qualificationPhase: String?
    let sessionApprovalPublicKey: String?
    let sessionApprovalKeyTag: String?
    let clientCodeSigningRequirement: String
    let agentClientCodeSigningRequirement: String
    let childCodeSigningRequirement: String?
    let allowedClientUID: UInt32

    enum CodingKeys: String, CodingKey, CaseIterable {
        case machServiceName = "mach_service_name"
        case agentMachServiceName = "agent_mach_service_name"
        case hostMachServiceName = "host_mach_service_name"
        case childMachServiceName = "child_mach_service_name"
        case keyTag = "key_tag"
        case keychainAccessGroup = "keychain_access_group"
        case keyLifecycleDirectory = "key_lifecycle_directory"
        case keyLifecycleExpectedHeadHash = "key_lifecycle_expected_head_hash"
        case keyLifecyclePinDirectory = "key_lifecycle_pin_directory"
        case keyLifecycleMutationOutboxDirectory = "key_lifecycle_mutation_outbox_directory"
        case recoveryPublicKeys = "recovery_public_keys"
        case recoveryThreshold = "recovery_threshold"
        case recoveryPolicyPath = "recovery_policy_path"
        case installationID = "installation_id"
        case policyPath = "policy_path"
        case auditLogPath = "audit_log_path"
        case auditArchiveDirectory = "audit_archive_directory"
        case auditCheckpointPath = "audit_checkpoint_path"
        case auditCheckpointArchiveDirectory = "audit_checkpoint_archive_directory"
        case auditKeyTag = "audit_key_tag"
        case auditAnchorURL = "audit_anchor_url"
        case auditAnchorTenant = "audit_anchor_tenant"
        case auditAnchorPublicKey = "audit_anchor_public_key"
        case auditAnchorReceiptPath = "audit_anchor_receipt_path"
        case auditAnchorReceiptArchiveDirectory = "audit_anchor_receipt_archive_directory"
        case auditKeyTransitionPath = "audit_key_transition_path"
        case auditKeyRotationPlanDirectory = "audit_key_rotation_plan_directory"
        case auditKeyRecoveryPlanDirectory = "audit_key_recovery_plan_directory"
        case auditKeyRecoveryApprovalDirectory = "audit_key_recovery_approval_directory"
        case auditPruneJournalDirectory = "audit_prune_journal_directory"
        case auditPruneTrustDirectory = "audit_prune_trust_directory"
        case auditPruneEvidenceBundlePath = "audit_prune_evidence_bundle_path"
        case auditKeyDeletionEvidenceBundlePath = "audit_key_deletion_evidence_bundle_path"
        case auditKeyDeletionArchiveDirectory = "audit_key_deletion_archive_directory"
        case auditRetentionAuthorizerPublicKey = "audit_retention_authorizer_public_key"
        case auditKeyDeletionMinimumRetentionSeconds = "audit_key_deletion_minimum_retention_seconds"
        case controlStatePath = "control_state_path"
        case controlURL = "control_url"
        case controlRefreshSeconds = "control_refresh_seconds"
        case controlV2StatePath = "control_v2_state_path"
        case controlV2CapabilityStatePath = "control_v2_capability_state_path"
        case controlV2RequestEvidencePath = "control_v2_request_evidence_path"
        case controlV2APIBaseURL = "control_v2_api_base_url"
        case controlV2RefreshStatePath = "control_v2_refresh_state_path"
        case controlV2BundleStorePath = "control_v2_bundle_store_path"
        case controlV2PublicKey = "control_v2_public_key"
        case controlV2Issuer = "control_v2_issuer"
        case controlV2KeyID = "control_v2_key_id"
        case controlV2OrganizationID = "control_v2_organization_id"
        case controlV2DeviceID = "control_v2_device_id"
        case controlV2DeviceKeyEpoch = "control_v2_device_key_epoch"
        case controlV2RefreshHintKeyring = "control_v2_refresh_hint_keyring"
        case controlV2DeviceKeyTag = "control_v2_device_key_tag"
        case agentSigningIntentDirectory = "agent_signing_intent_directory"
        case agentGlobalSessionLimit = "agent_global_session_limit"
        case agentPerAgentSessionLimit = "agent_per_agent_session_limit"
        case agentPerWorktreeSessionLimit = "agent_per_worktree_session_limit"
        case agentBootstrapAttemptLimit = "agent_bootstrap_attempt_limit"
        case agentWorktreeObservationPolicyVersion = "agent_worktree_observation_policy_version"
        case agentCapabilityPublicKey = "agent_capability_public_key"
        case agentCapabilityKeyID = "agent_capability_key_id"
        case hostChildCodeDirectoryHash = "host_child_code_directory_hash"
        case qualificationMode = "qualification_mode"
        case qualificationMachServiceName = "qualification_mach_service_name"
        case qualificationCandidateSHA256 = "qualification_candidate_sha256"
        case qualificationSourceCommitSHA256 = "qualification_source_commit_sha256"
        case qualificationCodeIdentitiesSHA256 = "qualification_code_identities_sha256"
        case qualificationControllerCDHash = "qualification_controller_cdhash"
        case qualificationRunIDSHA256 = "qualification_run_id_sha256"
        case qualificationExpiresAtEpochSeconds = "qualification_expires_at_epoch_seconds"
        case qualificationScenario = "qualification_scenario"
        case qualificationPhase = "qualification_phase"
        case sessionApprovalPublicKey = "session_approval_public_key"
        case sessionApprovalKeyTag = "session_approval_key_tag"
        case clientCodeSigningRequirement = "client_code_signing_requirement"
        case agentClientCodeSigningRequirement = "agent_client_code_signing_requirement"
        case childCodeSigningRequirement = "child_code_signing_requirement"
        case allowedClientUID = "allowed_client_uid"
    }

    static func load(path: String) throws -> Self {
        let data = try loadProtectedFile(path: path, label: "Native service configuration")
        let object = try NativeStrictJSON.object(from: data, maxBytes: 1 * 1024 * 1024, maxDepth: 16)
        guard Set(object.keys).isSubset(of: Set(CodingKeys.allCases.map(\.rawValue))) else {
            throw AgentPassNativeError.invalidConfiguration("Native service configuration contains unknown fields")
        }
        let value = try JSONDecoder().decode(Self.self, from: data)
        guard !value.machServiceName.isEmpty,
              !value.agentMachServiceName.isEmpty,
              !value.hostMachServiceName.isEmpty,
              !value.childMachServiceName.isEmpty,
              value.machServiceName == "dev.agentpass.native-service",
              value.agentMachServiceName == "dev.agentpass.agent-session",
              value.hostMachServiceName == "dev.agentpass.agent-host",
              value.childMachServiceName == "dev.agentpass.child-git",
              value.machServiceName != value.agentMachServiceName,
              value.hostMachServiceName != value.machServiceName,
              value.hostMachServiceName != value.agentMachServiceName,
              value.childMachServiceName != value.machServiceName,
              value.childMachServiceName != value.agentMachServiceName,
              value.childMachServiceName != value.hostMachServiceName,
              !value.keyTag.isEmpty, !value.auditKeyTag.isEmpty, value.policyPath.hasPrefix("/"), value.auditLogPath.hasPrefix("/"), value.auditCheckpointPath.hasPrefix("/"),
              !value.clientCodeSigningRequirement.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !value.agentClientCodeSigningRequirement.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              value.clientCodeSigningRequirement != value.agentClientCodeSigningRequirement else {
            throw AgentPassNativeError.invalidConfiguration("Native service configuration contains empty trust parameters")
        }
        if let childHash = value.hostChildCodeDirectoryHash {
            guard childHash.range(of: "^[0-9a-fA-F]{64}$", options: .regularExpression) != nil else {
                throw AgentPassNativeError.invalidConfiguration("Host child code-directory hash is invalid")
            }
        }
        guard let serviceAccessGroup = value.keychainAccessGroup,
              value.clientCodeSigningRequirement == (try? NativeClientCodeRequirement.requirement(serviceAccessGroup: serviceAccessGroup)) else {
            throw AgentPassNativeError.invalidConfiguration("Native client code-signing requirement must bind the fixed Team ID, Developer ID identity, and approval-key entitlement")
        }
        guard value.agentClientCodeSigningRequirement == (try? NativeAgentCodeRequirement.requirement(serviceAccessGroup: serviceAccessGroup)) else {
            throw AgentPassNativeError.invalidConfiguration("Native Agent host code-signing requirement must bind its fixed Team ID, Developer ID identity, and dedicated entitlement")
        }
        _ = try deriveDedicatedChildCodeSigningRequirement(
            configuredChildRequirement: value.childCodeSigningRequirement,
            hostCodeSigningRequirement: value.agentClientCodeSigningRequirement,
            managementCodeSigningRequirement: value.clientCodeSigningRequirement
        )
        if value.controlURL != nil || value.controlRefreshSeconds != nil {
            guard let rawURL = value.controlURL, let interval = value.controlRefreshSeconds,
                  value.controlV2StatePath != nil ? value.controlV2DeviceKeyTag == NativeEnrollmentKeyMaterial.fixedApplicationTag : value.controlStatePath != nil else {
                throw AgentPassNativeError.invalidConfiguration("Native control refresh requires protected state, URL, and interval")
            }
            _ = try NativeControlRefreshConfiguration(urlString: rawURL, refreshSeconds: interval)
        }
        let v2Values: [Any?] = [value.controlV2StatePath, value.controlV2CapabilityStatePath, value.controlV2RequestEvidencePath, value.controlV2APIBaseURL, value.controlV2RefreshStatePath, value.controlV2BundleStorePath, value.controlV2PublicKey, value.controlV2Issuer, value.controlV2KeyID, value.controlV2OrganizationID, value.controlV2DeviceID, value.controlV2DeviceKeyEpoch, value.controlV2RefreshHintKeyring]
        let v2Count = v2Values.compactMap { $0 }.count
        if value.controlV2DeviceKeyTag != nil, v2Count == 0 { throw AgentPassNativeError.invalidConfiguration("ControlBundle v2 device key tag requires ControlBundle v2") }
        if v2Count != 0 {
            guard v2Count == v2Values.count,
                  value.controlV2StatePath?.hasPrefix("/") == true,
                  value.controlV2CapabilityStatePath?.hasPrefix("/") == true,
                  value.controlV2RequestEvidencePath?.hasPrefix("/") == true,
                  value.controlV2RefreshStatePath?.hasPrefix("/") == true,
                  value.controlV2BundleStorePath?.hasPrefix("/") == true,
                  let apiBaseText = value.controlV2APIBaseURL,
                  let apiBase = URL(string: apiBaseText), apiBase.absoluteString == apiBaseText,
                  apiBase.scheme == "https", apiBase.user == nil, apiBase.password == nil,
                  apiBase.query == nil, apiBase.fragment == nil, apiBase.path == "/v1",
                  let publicKey = value.controlV2PublicKey,
                  let issuer = value.controlV2Issuer, !issuer.isEmpty,
                  let keyID = value.controlV2KeyID, !keyID.isEmpty,
                  let organizationID = value.controlV2OrganizationID, UUID(uuidString: organizationID) != nil,
                  let deviceID = value.controlV2DeviceID, UUID(uuidString: deviceID) != nil,
                  let deviceKeyEpoch = value.controlV2DeviceKeyEpoch,
                  deviceKeyEpoch > 0, deviceKeyEpoch <= 9_007_199_254_740_991,
                  let refreshHintKeyring = value.controlV2RefreshHintKeyring,
                  !refreshHintKeyring.isEmpty, refreshHintKeyring.count <= NativeRefreshHintTrust.maximumKeys,
                  value.controlURL != nil, value.controlRefreshSeconds != nil,
                  value.controlV2DeviceKeyTag == NativeEnrollmentKeyMaterial.fixedApplicationTag else {
                throw AgentPassNativeError.invalidConfiguration("ControlBundle v2 requires complete pinned trust, API base, audience, device_key_epoch, refresh hint keyring, and protected state paths; reprovision the native service")
            }
            _ = try NativeControlBundleV2Trust(publicKeyPEM: publicKey, issuer: issuer, keyID: keyID, audience: NativeControlBundleV2Audience(organizationID: organizationID, deviceID: deviceID))
            var refreshKeys: [String: String] = [:]
            let controlDER = canonicalEd25519DER(publicKey)
            guard controlDER != nil else { throw AgentPassNativeError.invalidConfiguration("ControlBundle v2 public key is invalid") }
            for entry in refreshHintKeyring {
                guard entry.algorithm == "ed25519",
                      entry.keyID.range(of: "^[A-Za-z0-9][A-Za-z0-9._:~-]{0,63}$", options: .regularExpression) != nil,
                      refreshKeys[entry.keyID] == nil,
                      let refreshDER = canonicalEd25519DER(entry.publicKey),
                      refreshDER != controlDER else {
                    throw AgentPassNativeError.invalidConfiguration("ControlBundle v2 refresh hint keyring is invalid or reuses the bundle key")
                }
                refreshKeys[entry.keyID] = entry.publicKey
            }
            _ = try NativeRefreshHintTrust(organizationID: organizationID, deviceID: deviceID, publicKeysPEM: refreshKeys)
            if let tag = value.controlV2DeviceKeyTag {
                guard tag == NativeEnrollmentKeyMaterial.fixedApplicationTag,
                      tag != value.keyTag, tag != value.auditKeyTag, tag != value.sessionApprovalKeyTag else { throw AgentPassNativeError.invalidConfiguration("ControlBundle v2 device authentication requires the fixed dedicated enrollment Secure Enclave key tag") }
            }
        }
        let agentRuntimeValues: [Any?] = [
            value.agentSigningIntentDirectory,
            value.agentGlobalSessionLimit,
            value.agentPerAgentSessionLimit,
            value.agentPerWorktreeSessionLimit,
            value.agentBootstrapAttemptLimit,
            value.agentWorktreeObservationPolicyVersion,
            value.agentCapabilityPublicKey,
            value.agentCapabilityKeyID
        ]
        let agentRuntimeCount = agentRuntimeValues.compactMap { $0 }.count
        if agentRuntimeCount != 0 {
            guard agentRuntimeCount == agentRuntimeValues.count,
                  v2Count == v2Values.count,
                  value.controlV2DeviceKeyTag == NativeEnrollmentKeyMaterial.fixedApplicationTag,
                  let intentDirectory = value.agentSigningIntentDirectory,
                  intentDirectory.hasPrefix("/"),
                  URL(fileURLWithPath: intentDirectory, isDirectory: true).standardizedFileURL.path == intentDirectory,
                  let globalLimit = value.agentGlobalSessionLimit,
                  (1...NativeAgentSessionRegistry.maximumActiveSessions).contains(globalLimit),
                  let perAgentLimit = value.agentPerAgentSessionLimit,
                  (1...globalLimit).contains(perAgentLimit),
                  let perWorktreeLimit = value.agentPerWorktreeSessionLimit,
                  (1...globalLimit).contains(perWorktreeLimit),
                  let bootstrapLimit = value.agentBootstrapAttemptLimit,
                  (1...64).contains(bootstrapLimit),
                  value.agentWorktreeObservationPolicyVersion == NativeAgentWorktreeObservationPolicyVersion.v2.rawValue else {
                throw AgentPassNativeError.invalidConfiguration("Agent runtime requires complete bounded authority configuration and ControlBundle v2 device enrollment")
            }
        }
        do {
            _ = try value.agentRuntimeConfiguration()
        } catch {
            throw AgentPassNativeError.invalidConfiguration("Agent runtime authority configuration is invalid")
        }
        do {
            let qualification = try value.qualificationConfiguration()
            if qualification.isConfigured {
                try verifyQualificationConfigurationFile(path: path, expectedData: data)
            }
        } catch {
            throw AgentPassNativeError.invalidConfiguration("Agent qualification configuration is incomplete, expired, or invalid")
        }
        let deletionConfigurationCount: Int = [
            value.auditKeyDeletionEvidenceBundlePath != nil,
            value.auditKeyDeletionArchiveDirectory != nil,
            value.auditRetentionAuthorizerPublicKey != nil,
            value.auditKeyDeletionMinimumRetentionSeconds != nil
        ].filter { $0 }.count
        if deletionConfigurationCount != 0 {
            guard deletionConfigurationCount == 4,
                  value.auditKeyDeletionEvidenceBundlePath?.hasPrefix("/") == true,
                  value.auditKeyDeletionArchiveDirectory?.hasPrefix("/") == true,
                  let authorizer = value.auditRetentionAuthorizerPublicKey,
                  let retention = value.auditKeyDeletionMinimumRetentionSeconds,
                  (86_400...31_536_000).contains(retention),
                  value.keyLifecycleDirectory != nil,
                  value.auditAnchorTenant != nil,
                  value.auditAnchorPublicKey != nil,
                  value.auditAnchorReceiptPath != nil,
                  value.auditKeyTransitionPath != nil else {
                throw AgentPassNativeError.invalidConfiguration("Retired audit-key deletion requires the complete protected evidence, lifecycle, transition, and anchor configuration")
            }
            _ = try SSHSIG.p256PublicKey(fromAuthorizedKey: authorizer)
        }
        let pruneConfigurationCount = [value.auditPruneJournalDirectory, value.auditPruneTrustDirectory, value.auditPruneEvidenceBundlePath].compactMap { $0 }.count
        if pruneConfigurationCount != 0 {
            guard pruneConfigurationCount == 3,
                  let pruneJournal = value.auditPruneJournalDirectory, pruneJournal.hasPrefix("/"), URL(fileURLWithPath: pruneJournal).standardizedFileURL.path == pruneJournal,
                  let pruneTrust = value.auditPruneTrustDirectory, pruneTrust.hasPrefix("/"), URL(fileURLWithPath: pruneTrust).standardizedFileURL.path == pruneTrust,
                  let pruneEvidence = value.auditPruneEvidenceBundlePath, pruneEvidence.hasPrefix("/"), URL(fileURLWithPath: pruneEvidence).standardizedFileURL.path == pruneEvidence,
                  pruneJournal != pruneTrust,
                  URL(fileURLWithPath: pruneEvidence).deletingLastPathComponent().path != pruneJournal,
                  URL(fileURLWithPath: pruneEvidence).deletingLastPathComponent().path != pruneTrust,
                  value.auditKeyDeletionArchiveDirectory?.hasPrefix("/") == true,
                  value.auditRetentionAuthorizerPublicKey != nil,
                  value.auditKeyDeletionMinimumRetentionSeconds != nil,
                  value.keyLifecycleDirectory != nil,
                  value.auditAnchorURL != nil, value.auditAnchorTenant != nil,
                  value.auditAnchorPublicKey != nil, value.auditAnchorReceiptPath != nil,
                  value.auditKeyTransitionPath != nil else {
                throw AgentPassNativeError.invalidConfiguration("Audit prune requires complete journal, trust, evidence, archive, lifecycle, transition, and anchor configuration")
            }
        }
        if value.keyLifecycleDirectory != nil || value.keyLifecycleExpectedHeadHash != nil || value.keyLifecyclePinDirectory != nil || value.keyLifecycleMutationOutboxDirectory != nil || value.recoveryPublicKeys?.isEmpty == false {
            let journalPinIsValid = value.keyLifecyclePinDirectory?.hasPrefix("/") == true
            guard let directory = value.keyLifecycleDirectory, directory.hasPrefix("/"),
                  journalPinIsValid,
                  value.keyLifecycleMutationOutboxDirectory?.hasPrefix("/") == true,
                  value.sessionApprovalKeyTag?.isEmpty == false else {
                throw AgentPassNativeError.invalidConfiguration("Native key lifecycle requires absolute ledger, pin-journal, and mutation-outbox directories plus an approval key base tag")
            }
            for key in value.recoveryPublicKeys ?? [] { _ = try ed25519RecoveryPublicKey(key) }
            if let keys = value.recoveryPublicKeys, !keys.isEmpty {
                guard let threshold = value.recoveryThreshold, (1...keys.count).contains(threshold),
                      let policyPath = value.recoveryPolicyPath, policyPath.hasPrefix("/"),
                      let installationID = value.installationID,
                      installationID.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", options: .regularExpression) != nil else {
                    throw AgentPassNativeError.invalidConfiguration("Native recovery requires pinned authorities, threshold, protected policy path, and installation ID")
                }
                let policy = try loadProtectedFile(path: policyPath, label: "Native recovery policy")
                let metadata = try NativeRecoveryVerifier.policyMetadata(policy)
                let configuredFingerprints = try keys.map {
                    try NativeRecoveryVerifier.authorityFingerprint(rawEd25519PublicKey: ed25519RecoveryPublicKey($0))
                }.sorted()
                guard metadata.threshold == threshold,
                      metadata.authorityPublicKeyFingerprints == configuredFingerprints else {
                    throw AgentPassNativeError.invalidSignature("Recovery policy authorities or threshold disagree with lifecycle trust pins")
                }
            } else if value.recoveryThreshold != nil {
                throw AgentPassNativeError.invalidConfiguration("Native recovery threshold requires recovery authorities")
            } else if value.recoveryPolicyPath != nil || value.installationID != nil {
                throw AgentPassNativeError.invalidConfiguration("Native recovery policy and installation ID require recovery authorities")
            }
        }
        let anchorValues: [Any?] = [value.auditAnchorURL, value.auditAnchorTenant, value.auditAnchorPublicKey, value.auditAnchorReceiptPath, value.auditAnchorReceiptArchiveDirectory, value.auditKeyTransitionPath, value.auditKeyRotationPlanDirectory, value.auditKeyRecoveryPlanDirectory, value.auditKeyRecoveryApprovalDirectory]
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
            _ = try NativeAuditAnchorReceipts(path: receiptPath, tenant: tenant, anchorPublicKeyPEM: publicKey, archiveDirectory: value.auditAnchorReceiptArchiveDirectory)
            if value.auditKeyTransitionPath != nil || value.auditKeyRotationPlanDirectory != nil {
                guard let transitionPath = value.auditKeyTransitionPath, transitionPath.hasPrefix("/"),
                      let planDirectory = value.auditKeyRotationPlanDirectory, planDirectory.hasPrefix("/") else {
                    throw AgentPassNativeError.invalidConfiguration("Native audit key rotation requires absolute transition-log and plan-journal paths")
                }
                if let recoveryPolicyPath = value.recoveryPolicyPath,
                   let installationID = value.installationID {
                    let authorities = try loadProtectedFile(path: recoveryPolicyPath, label: "Native recovery policy")
                    let converted = try NativeAuditKeyRecoveryPolicy.convertingAuthoritiesPolicy(authorities)
                    _ = try NativeAuditKeyTransitionStore(
                        path: transitionPath, tenant: tenant, anchorPublicKeyPEM: publicKey,
                        recoveryPolicyData: converted.anchorPolicy.canonicalData(),
                        installationID: installationID
                    )
                } else {
                    _ = try NativeAuditKeyTransitionStore(path: transitionPath, tenant: tenant, anchorPublicKeyPEM: publicKey)
                }
                _ = try NativeAuditKeyRotationPlanJournal(rootPath: planDirectory, tenant: tenant)
            }
            if value.auditKeyRecoveryPlanDirectory != nil || value.auditKeyRecoveryApprovalDirectory != nil || (value.recoveryPolicyPath != nil && value.auditKeyTransitionPath != nil) {
                guard let recoveryPlanDirectory = value.auditKeyRecoveryPlanDirectory,
                      recoveryPlanDirectory.hasPrefix("/"),
                      let recoveryApprovalDirectory = value.auditKeyRecoveryApprovalDirectory,
                      recoveryApprovalDirectory.hasPrefix("/"),
                      let recoveryPolicyPath = value.recoveryPolicyPath,
                      let installationID = value.installationID,
                      value.auditKeyTransitionPath != nil else {
                    throw AgentPassNativeError.invalidConfiguration("Audit-key recovery requires transition storage, pinned authorities policy, installation ID, and an absolute recovery-plan journal directory")
                }
                let authorities = try loadProtectedFile(path: recoveryPolicyPath, label: "Native recovery policy")
                let converted = try NativeAuditKeyRecoveryPolicy.convertingAuthoritiesPolicy(authorities)
                _ = try NativeAuditKeyRecoveryPlanJournal(
                    rootPath: recoveryPlanDirectory, tenant: tenant,
                    pinnedPolicy: converted.anchorPolicy, installationID: installationID
                )
                _ = try NativeAuditRecoveryApprovalJournal(rootPath: recoveryApprovalDirectory)
            }
        }
        return value
    }

    func agentRuntimeConfiguration() throws -> NativeAgentRuntimeConfiguration {
        let configured = [
            agentSigningIntentDirectory != nil,
            agentGlobalSessionLimit != nil,
            agentPerAgentSessionLimit != nil,
            agentPerWorktreeSessionLimit != nil,
            agentBootstrapAttemptLimit != nil,
            agentWorktreeObservationPolicyVersion != nil,
            agentCapabilityPublicKey != nil,
            agentCapabilityKeyID != nil,
        ].contains(true)
        var origin: URL?
        if configured, let apiBaseText = controlV2APIBaseURL,
           let apiBase = URL(string: apiBaseText),
           var components = URLComponents(url: apiBase, resolvingAgainstBaseURL: false) {
            components.path = "/"
            components.query = nil
            components.fragment = nil
            origin = components.url
        }
        return try NativeAgentRuntimeConfiguration(
            deviceAPIOrigin: configured ? origin : nil,
            organizationID: configured ? controlV2OrganizationID : nil,
            deviceID: configured ? controlV2DeviceID : nil,
            deviceKeyTag: configured ? controlV2DeviceKeyTag : nil,
            signingIntentDirectory: configured ? agentSigningIntentDirectory : nil,
            globalSessionLimit: configured ? agentGlobalSessionLimit : nil,
            perAgentSessionLimit: configured ? agentPerAgentSessionLimit : nil,
            perWorktreeSessionLimit: configured ? agentPerWorktreeSessionLimit : nil,
            bootstrapAttemptLimit: configured ? agentBootstrapAttemptLimit : nil,
            worktreeObservationPolicyVersion: configured ? agentWorktreeObservationPolicyVersion : nil,
            capabilityPublicKeyPEM: configured ? agentCapabilityPublicKey : nil,
            capabilityKeyID: configured ? agentCapabilityKeyID : nil
        )
    }

    func qualificationConfiguration(
        wallTime: Date = Date()
    ) throws -> NativeAgentQualificationConfiguration {
        let rawValues: [Any?] = [
            qualificationMode,
            qualificationMachServiceName,
            qualificationCandidateSHA256,
            qualificationSourceCommitSHA256,
            qualificationCodeIdentitiesSHA256,
            qualificationControllerCDHash,
            qualificationRunIDSHA256,
            qualificationExpiresAtEpochSeconds,
            qualificationScenario,
            qualificationPhase,
        ]
        let configured = rawValues.contains { $0 != nil }
        let scenario: NativeAgentQualificationFaultScenario?
        let phase: NativeAgentQualificationFaultPhase?
        if let raw = qualificationScenario {
            guard let parsed = NativeAgentQualificationFaultScenario(rawValue: raw) else {
                throw NativeAgentQualificationConfigurationError.invalidPhaseScenarioPair
            }
            scenario = parsed
        } else {
            scenario = nil
        }
        if let raw = qualificationPhase {
            guard let parsed = NativeAgentQualificationFaultPhase(rawValue: raw) else {
                throw NativeAgentQualificationConfigurationError.invalidPhaseScenarioPair
            }
            phase = parsed
        } else {
            phase = nil
        }
        return try NativeAgentQualificationConfiguration(
            mode: qualificationMode,
            machServiceName: qualificationMachServiceName,
            candidateDigest: qualificationCandidateSHA256,
            sourceCommitDigest: qualificationSourceCommitSHA256,
            codeIdentityDigest: qualificationCodeIdentitiesSHA256,
            runBindingDigest: qualificationRunIDSHA256,
            controllerServiceAccessGroup: configured ? keychainAccessGroup : nil,
            controllerCodeDirectoryHash: qualificationControllerCDHash,
            expiresAtEpochSeconds: qualificationExpiresAtEpochSeconds,
            scenario: scenario,
            phase: phase,
            wallTime: wallTime
        )
    }
}

private func canonicalEd25519DER(_ pem: String) -> Data? {
    let prefix = "-----BEGIN PUBLIC KEY-----\n"
    let suffix = "\n-----END PUBLIC KEY-----\n"
    guard pem.hasPrefix(prefix), pem.hasSuffix(suffix) else { return nil }
    let body = String(pem.dropFirst(prefix.count).dropLast(suffix.count))
    guard !body.isEmpty, !body.contains("\n"), let der = Data(base64Encoded: body), der.count == 44,
          der.prefix(12) == Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]),
          body == der.base64EncodedString(),
          (try? Curve25519.Signing.PublicKey(rawRepresentation: der.suffix(32))) != nil else { return nil }
    return der
}

private final class ServiceDataReply: @unchecked Sendable {
    private let body: (NSData?, NSError?) -> Void
    init(_ body: @escaping (NSData?, NSError?) -> Void) { self.body = body }
    func call(_ data: NSData?, _ error: NSError?) { body(data, error) }
}

/// Projects the local audit record into the closed, redacted Device audit
/// contract.  A local audit record is deliberately allowed to be richer than
/// its Cloud projection; missing trusted fields therefore mean local-only
/// evidence, never guessed Cloud data.
internal enum NativeServiceDeviceAuditProjection {
    private static let stableReasons: Set<String> = [
        "allowed", "branch_denied", "branch_not_allowed", "capability_expired",
        "capability_missing", "operation_not_allowed", "policy_changed",
        "remote_control_stale", "remote_denied", "remote_not_allowed",
        "repository_not_allowed", "revoked", "session_required", "signer_failed",
        "tag_denied", "tag_not_allowed"
    ]

    static func stableReason(decision: String, rawReason: String?) -> String {
        guard decision != "allow" else { return "allowed" }
        let raw = rawReason?.lowercased() ?? ""
        if stableReasons.contains(raw) { return raw }
        let matches: [(String, String)] = [
            ("branch_denied", "branch_denied"),
            ("branch denied", "branch_denied"),
            ("branch_not_allowed", "branch_not_allowed"),
            ("branch not allowed", "branch_not_allowed"),
            ("capability_expired", "capability_expired"),
            ("capability_missing", "capability_missing"),
            ("short-lived cloud capability", "capability_missing"),
            ("operation_not_allowed", "operation_not_allowed"),
            ("unsupported native broker operation", "operation_not_allowed"),
            ("policy_changed", "policy_changed"),
            ("trusted git context changed", "policy_changed"),
            ("control_refresh_pending", "remote_control_stale"),
            ("remote_control_stale", "remote_control_stale"),
            ("remote_denied", "remote_denied"),
            ("remote_not_allowed", "remote_not_allowed"),
            ("repository_not_allowed", "repository_not_allowed"),
            ("repository path", "repository_not_allowed"),
            ("revoked", "revoked"),
            ("session_required", "session_required"),
            ("session is required", "session_required"),
            ("tag_denied", "tag_denied"),
            ("tag_not_allowed", "tag_not_allowed")
        ]
        if let match = matches.first(where: { raw.contains($0.0) }) { return match.1 }
        return decision == "error" ? "signer_failed" : "policy_changed"
    }

    static func project(
        local: NativeAuditEvent,
        eventID: String,
        policySequence: Int64?,
        capabilitySequence: Int64?,
        deviceTimestamp: String,
        previousHash: String
    ) -> NativeDeviceAuditEvent? {
        guard local.operation == "git.commit.sign",
              let requestID = local.requestID,
              let agentID = local.agentID,
              let repository = local.repository,
              let branch = local.branch,
              let remote = local.remote,
              let payloadDigest = local.payloadSHA256,
              let policySequence,
              let capabilitySequence else { return nil }
        return try? NativeDeviceAuditEvent(
            eventID: eventID,
            requestID: requestID,
            agentID: agentID,
            decision: local.decision,
            reason: stableReason(decision: local.decision, rawReason: local.reason),
            policySequence: policySequence,
            capabilitySequence: capabilitySequence,
            repository: repository,
            branch: branch,
            remote: remote,
            payloadDigest: payloadDigest,
            deviceTimestamp: deviceTimestamp,
            previousHash: previousHash
        )
    }
}

private final class ServiceEndpoint: NSObject, AgentPassNativeServiceProtocol, NativeAgentSessionAuditAppending, @unchecked Sendable {
    private struct PendingKeyActivation {
        let statement: NativeKeyTransitionStatement
        let expiresAt: Date
        let approvalPublicKey: Data
        let approvalApplicationTag: String
        let auditRotationBoundary: NativeAuditKeyRotationCheckpointBoundary?
    }
    private struct PendingKeyAbort {
        let role: NativeKeyRole
        let generation: Int
        let reason: String
        let statement: Data
        let lifecycleHead: String
        let expiresAt: Date
        let approvalPublicKey: Data
        let approvalApplicationTag: String
    }
    private struct PendingRecovery {
        let requestData: Data
        let runtimeState: NativeRecoveryRuntimeState
        let expiresAt: Date
        let challengeID: String
        var verification: NativeRecoveryVerification?
        var evidenceData: Data?
        var statement: NativeKeyTransitionStatement?
        var localSignerPublicKey: Data?
        var localSignerApplicationTag: String?
        var localSignerFingerprint: String?
        var auditPreparation: NativeRecoveredAuditActivationPreparation?
        var auditAuthorization: NativeAuditKeyRecoveryAuthorization?
        var auditEvidence: NativeAuditKeyRecoveryEvidence?
        var auditPlan: NativeAuditKeyRecoveryPlan?
        var auditSubmissionInFlight: Bool

        var freezesMutations: Bool { verification != nil }
    }
    private struct PendingKeyDeletion {
        let role: NativeKeyRole
        let generation: Int
        let reason: String
        let minimumRetentionSeconds: Int
        let proof: NativeLifecycleDeletionProof
        let challengeID: String
        let statement: Data
        let expiresAt: Date
        let approvalPublicKey: Data
    }
    private let keyStore: SecureEnclaveKeyStore
    private let authorizer: NativeRequestAuthorizer
    private let auditLog: NativeAuditLog
    private let auditCheckpoints: NativeAuditCheckpoints
    private let auditSigner: SecureEnclaveKeyStore
    private let auditAnchorReceipts: NativeAuditAnchorReceipts?
    private let auditAnchorClient: NativeAuditAnchorClient?
    private let auditKeyRotationCoordinator: NativeAuditKeyRotationCoordinator?
    private let auditKeyRecoveryCoordinator: NativeAuditKeyRecoveryCoordinator?
    private let auditKeyRecoveryPlanJournal: NativeAuditKeyRecoveryPlanJournal?
    private let auditKeyTransitionStore: NativeAuditKeyTransitionStore?
    private let auditKeyRecoveryPolicy: NativeAuditKeyRecoveryPolicy?
    private let auditKeyRecoveryApprovalJournal: NativeAuditRecoveryApprovalJournal?
    private let auditPruneCoordinator: NativeAuditPruneCoordinator?
    private let auditPruneTrustSource: NativeAuditPruneServiceTrustSource?
    private let auditPruneEvidenceBundlePath: String?
    private let auditAnchorTenant: String?
    private let keychainAccessGroup: String?
    private let recoveryPolicyData: Data?
    private let installationID: String?
    private let sessionManager: NativeSessionManager?
    private let controlManager: NativeControlManager?
    private let controlV2Manager: NativeControlBundleV2Manager?
    private let controlRefreshEvidenceStore: (any NativeControlRefreshEvidenceStoring)?
    private let signingTransactions: NativeSigningTransactionStore
    private let keyLifecycle: NativeKeyLifecycleStore?
    private let keyCoordinator: NativeKeyLifecycleCoordinator?
    private let loadedLifecycleHeadHash: String?
    private let authorizationLock = ServiceAuthorizationGate()
    private var controlFetcher: NativeControlFetcher?
    private var deviceSyncRunner: NativeDeviceSyncRunner?
    private var deviceSyncPublicKeyPEM: String?
    private var deviceAuditOutbox: NativeDeviceAuditOutbox?
    private var deviceAuditUploadCoordinator: NativeDeviceAuditUploadCoordinator?
    private var deviceAuditUploadTask: Task<Void, Never>?
    private var deviceAuditUploadOperational = true
    private var deviceSyncRequiresInitialConvergence = false
    private var lastControlFetchAuditReason: String?
    private var lastControlFetchAuditAt: Date?
    private var pendingKeyActivations: [String: PendingKeyActivation] = [:]
    private var pendingKeyAborts: [String: PendingKeyAbort] = [:]
    private var pendingRecovery: PendingRecovery?
    private var recoveryRequestAttempts: [Date] = []
    private var pendingKeyDeletions: [String: PendingKeyDeletion] = [:]
    private var auditAnchorPushInFlight = false
    private var auditPruneSubmissionInFlight = false
    private var auditPruneSubmissionOperationID: String?
    private var auditPruneLastStage: String?
    private var auditPruneLastDecision: String?
    private var auditPruneLastError: String?
    private var auditPruneLastUpdatedAt: String?

    private static func capabilitySequence(from requestData: Data) -> Int64? {
        guard let request = try? NativeStrictJSON.object(from: requestData, maxBytes: 12 * 1024 * 1024, maxDepth: 16),
              let capability = request["capability"] as? [String: Any],
              let capabilityData = try? NativeStrictJSON.data(capability),
              let parsed = try? NativeCapabilityCodec.parse(capabilityData) else {
            return nil
        }
        return parsed.sequence
    }

    private func currentPolicySequence() -> Int64? {
        controlV2Manager?.status().sequence ?? controlManager?.status().sequence
    }

    private static func deviceAuditEventID(recordHash: String) -> String? {
        guard recordHash.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else { return nil }
        // The local audit record hash survives segment rotation, unlike the
        // active-segment entry count. Derive a deterministic UUID-shaped ID
        // from its first 128 bits so retries cannot reuse an event ID for new
        // evidence after a rotation.
        let hex = Array(recordHash.prefix(32))
        guard hex.count == 32 else { return nil }
        let groups = [
            String(hex[0..<8]), String(hex[8..<12]),
            "4" + String(hex[13..<16]), "8" + String(hex[17..<20]),
            String(hex[20..<32])
        ]
        return groups.joined(separator: "-")
    }

    init(keyStore: SecureEnclaveKeyStore, authorizer: NativeRequestAuthorizer, auditLog: NativeAuditLog, auditCheckpoints: NativeAuditCheckpoints, auditSigner: SecureEnclaveKeyStore, auditAnchorReceipts: NativeAuditAnchorReceipts?, auditAnchorClient: NativeAuditAnchorClient?, auditKeyRotationCoordinator: NativeAuditKeyRotationCoordinator?, auditKeyRecoveryCoordinator: NativeAuditKeyRecoveryCoordinator?, auditKeyRecoveryPlanJournal: NativeAuditKeyRecoveryPlanJournal?, auditKeyTransitionStore: NativeAuditKeyTransitionStore?, auditKeyRecoveryPolicy: NativeAuditKeyRecoveryPolicy?, auditKeyRecoveryApprovalJournal: NativeAuditRecoveryApprovalJournal?, auditPruneCoordinator: NativeAuditPruneCoordinator?, auditPruneTrustSource: NativeAuditPruneServiceTrustSource?, auditPruneEvidenceBundlePath: String?, auditAnchorTenant: String?, keychainAccessGroup: String?, recoveryPolicyData: Data?, installationID: String?, sessionManager: NativeSessionManager?, controlManager: NativeControlManager?, controlV2Manager: NativeControlBundleV2Manager? = nil, signingTransactions: NativeSigningTransactionStore, keyLifecycle: NativeKeyLifecycleStore?, keyCoordinator: NativeKeyLifecycleCoordinator?, loadedLifecycleHeadHash: String?, controlRefreshEvidenceStore: (any NativeControlRefreshEvidenceStoring)? = nil) {
        self.keyStore = keyStore
        self.authorizer = authorizer
        self.auditLog = auditLog
        self.auditCheckpoints = auditCheckpoints
        self.auditSigner = auditSigner
        self.auditAnchorReceipts = auditAnchorReceipts
        self.auditAnchorClient = auditAnchorClient
        self.auditKeyRotationCoordinator = auditKeyRotationCoordinator
        self.auditKeyRecoveryCoordinator = auditKeyRecoveryCoordinator
        self.auditKeyRecoveryPlanJournal = auditKeyRecoveryPlanJournal
        self.auditKeyTransitionStore = auditKeyTransitionStore
        self.auditKeyRecoveryPolicy = auditKeyRecoveryPolicy
        self.auditKeyRecoveryApprovalJournal = auditKeyRecoveryApprovalJournal
        self.auditPruneCoordinator = auditPruneCoordinator
        self.auditPruneTrustSource = auditPruneTrustSource
        self.auditPruneEvidenceBundlePath = auditPruneEvidenceBundlePath
        self.auditAnchorTenant = auditAnchorTenant
        self.keychainAccessGroup = keychainAccessGroup
        self.recoveryPolicyData = recoveryPolicyData
        self.installationID = installationID
        self.sessionManager = sessionManager
        self.controlManager = controlManager
        self.controlV2Manager = controlV2Manager
        self.controlRefreshEvidenceStore = controlRefreshEvidenceStore
        self.signingTransactions = signingTransactions
        self.keyLifecycle = keyLifecycle
        self.keyCoordinator = keyCoordinator
        self.loadedLifecycleHeadHash = loadedLifecycleHeadHash
    }

    func startControlRefresh(url: URL, refreshSeconds: Int) throws {
        guard controlV2Manager == nil else {
            throw AgentPassNativeError.invalidConfiguration("Legacy control fetcher cannot serve ControlBundle v2")
        }
        let fetcher = try NativeControlFetcher(sourceURL: url, refreshSeconds: refreshSeconds) { [weak self] outcome in
            guard let self else { throw AgentPassNativeError.invalidConfiguration("Native control service is unavailable") }
            try self.handleControlFetch(outcome)
        }
        controlFetcher = fetcher
        fetcher.start()
    }

    func installDeviceSyncRunner(
        _ runner: NativeDeviceSyncRunner,
        devicePublicKeyPEM: String,
        initialState: NativeDeviceRefreshMachineState
    ) throws {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        guard controlV2Manager != nil, controlFetcher == nil, deviceSyncRunner == nil,
              !devicePublicKeyPEM.isEmpty else {
            throw AgentPassNativeError.invalidConfiguration("ControlBundle v2 device synchronization is already configured or unavailable")
        }
        deviceSyncRunner = runner
        self.deviceSyncPublicKeyPEM = devicePublicKeyPEM
        deviceSyncRequiresInitialConvergence = initialState != .idle
        runner.start()
    }

    func installDeviceAuditUploadCoordinator(
        _ coordinator: NativeDeviceAuditUploadCoordinator,
        outbox: NativeDeviceAuditOutbox
    ) throws {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        guard deviceAuditUploadCoordinator == nil,
              deviceAuditOutbox == nil else {
            throw AgentPassNativeError.invalidConfiguration("Device audit upload is already configured")
        }
        _ = try outbox.nextPreviousHash()
        deviceAuditOutbox = outbox
        deviceAuditUploadCoordinator = coordinator
        deviceAuditUploadOperational = true
        let task = Task { [weak self, coordinator] in
            while !Task.isCancelled {
                _ = try? await coordinator.flush()
                do {
                    try await Task.sleep(nanoseconds: 30_000_000_000)
                } catch {
                    return
                }
                guard self != nil else { return }
            }
        }
        deviceAuditUploadTask = task
    }

    func deviceSyncActivation() -> NativeDeviceSyncBundleActivation {
        NativeDeviceSyncBundleActivation { [weak self] bundle, nowMilliseconds in
            guard let self else { throw AgentPassNativeError.invalidConfiguration("Native control service is unavailable") }
            _ = try self.applyControlUpdate(
                bundleData: bundle,
                operation: "control.sync",
                nowMilliseconds: nowMilliseconds
            )
        }
    }

    func health(withReply reply: @escaping (NSDictionary) -> Void) {
        do {
            try verifyLifecycleTrust()
            let audit = try auditLog.verify()
            let storage = try auditLog.storageStatus()
            let checkpoints = try auditCheckpoints.verify()
            let checkpointStorage = try auditCheckpoints.storageStatus()
            let session = sessionManager?.status()
            let approvalFingerprint: Any = sessionManager?.approvalKeyFingerprint ?? NSNull()
            let control = controlManager?.status()
            let controlV2 = controlV2Manager?.status()
            let controlSequence = controlV2?.sequence ?? control?.sequence ?? 0
            let controlOperational = controlV2?.operational ?? control?.operational ?? true
            let controlExpired = controlV2?.expired ?? control?.expired ?? false
            let fetch = controlFetcher?.status()
            let sync = deviceSyncRunner?.status()
            let anchor = try auditAnchorReceipts?.status(checkpoints: checkpoints)
            let lifecycle = try keyLifecycle?.verify()
            let receiptStorage = try auditAnchorReceipts?.storageStatus(checkpoints: checkpoints)
            reply(["ok": true, "protocol_version": 13, "key_backend": "secure-enclave", "key_lifecycle_configured": lifecycle != nil, "key_lifecycle_sequence": lifecycle?.sequence ?? 0, "key_lifecycle_head_hash": lifecycle?.headHash ?? NSNull(), "audit_entries": audit.entries, "audit_archive_configured": storage.configured, "audit_archive_segments": storage.segments, "audit_active_bytes": storage.activeBytes, "audit_rotation_ready": storage.rotationReady, "audit_checkpoints": checkpoints.count, "audit_checkpoint_archive_configured": checkpointStorage.configured, "audit_checkpoint_archive_segments": checkpointStorage.segments, "audit_checkpoint_active_bytes": checkpointStorage.activeBytes, "audit_checkpoint_rotation_ready": checkpointStorage.rotationReady, "audit_anchor_configured": anchor != nil, "audit_anchor_receipts": anchor?.receipts ?? 0, "audit_anchor_pending": anchor?.pending ?? 0, "audit_anchor_latest_receipt": anchor?.latestReceiptHash ?? NSNull(), "audit_receipt_archive_configured": receiptStorage?.configured ?? false, "audit_receipt_archive_segments": receiptStorage?.segments ?? 0, "audit_receipt_active_bytes": receiptStorage?.activeBytes ?? 0, "audit_receipt_rotation_ready": receiptStorage?.rotationReady ?? false, "session_required": session?.required ?? false, "active_sessions": session?.active ?? 0, "session_generation": session?.generation ?? 0, "session_approval_key_fingerprint": approvalFingerprint, "control_configured": control != nil || controlV2 != nil, "control_format_epoch": controlV2?.minimumFormatEpoch ?? (control == nil ? 0 : 1), "control_sequence": controlSequence, "control_operational": controlOperational, "control_expired": controlExpired, "control_expires_at": control?.expiresAt ?? NSNull(), "control_refresh_configured": fetch != nil || sync != nil, "control_device_auth_public_key": fetch?.devicePublicKeyPEM ?? deviceSyncPublicKeyPEM ?? NSNull(), "control_refresh_in_flight": fetch?.inFlight ?? sync?.inFlight ?? false, "control_refresh_state": sync?.state.rawValue ?? NSNull(), "control_refresh_generation": sync?.generation ?? 0, "control_refresh_last_attempt_at": fetch?.lastAttemptAt ?? sync.flatMap { serviceTimestamp(milliseconds: $0.lastAttemptAtMilliseconds) } ?? NSNull(), "control_refresh_last_success_at": fetch?.lastSuccessAt ?? sync.flatMap { serviceTimestamp(milliseconds: $0.lastSuccessAtMilliseconds) } ?? NSNull(), "control_refresh_last_error": fetch?.lastError ?? (sync?.failureCount ?? 0 > 0 ? sync?.reason.rawValue : nil) ?? NSNull(), "control_refresh_next_attempt_at": fetch?.nextAttemptAt ?? sync.flatMap { serviceTimestamp(milliseconds: $0.nextAttemptAtMilliseconds) } ?? NSNull(), "control_refresh_consecutive_failures": fetch?.consecutiveFailures ?? sync?.failureCount ?? 0])
        } catch {
            reply(["ok": false, "protocol_version": 13, "error": error.localizedDescription])
        }
    }

    func publicKey(withReply reply: @escaping (NSString?, NSError?) -> Void) {
        do { try verifyLifecycleTrust(); reply(try SSHSIG.authorizedKey(publicKeyX963: keyStore.publicKeyX963) as NSString, nil) }
        catch { reply(nil, error as NSError) }
    }

    func sign(request: NSData, withReply reply: @escaping (NSString?, NSError?) -> Void) {
        if let sync = deviceSyncRunner?.status() {
            if (deviceSyncRequiresInitialConvergence && sync.lastAttemptAtMilliseconds == nil) || sync.state != .idle {
                reply(nil, AgentPassNativeError.unauthorizedClient("control_refresh_pending") as NSError)
                return
            }
        }
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        do { try verifyLifecycleTrustLocked() }
        catch { reply(nil, error as NSError); return }
        do { try rotateAuditIfReady(); _ = try auditCheckpoints.verify() }
        catch { reply(nil, error as NSError); return }
        let capabilitySequence = Self.capabilitySequence(from: request as Data)
        do {
            if let prior = try signingTransactions.lookup(requestData: request as Data) {
                switch prior.phase {
                case .completed:
                    reply(prior.signature! as NSString, nil)
                case .signedVerified:
                    try appendAudit(NativeAuditEvent(operation: "git.commit.sign", decision: "allow", requestID: prior.requestID, reason: "allowed_recovered", agentID: prior.agentID, repository: prior.repository, branch: prior.branch, remote: prior.remote, payloadSHA256: prior.payloadHash), deviceAuditCapabilitySequence: capabilitySequence)
                    let completed = try signingTransactions.complete(requestID: prior.requestID)
                    reply(completed.signature! as NSString, nil)
                case .intent:
                    _ = try signingTransactions.markOutcomeUnknown(requestID: prior.requestID)
                    throw AgentPassNativeError.unauthorizedClient("signing_outcome_unknown")
                case .uncertain:
                    throw AgentPassNativeError.unauthorizedClient("signing_outcome_unknown")
                case .admitted, .providerStarted:
                    _ = try signingTransactions.markOutcomeUnknown(requestID: prior.requestID)
                    throw AgentPassNativeError.unauthorizedClient("signing_outcome_unknown")
                }
                return
            }
        } catch { reply(nil, error as NSError); return }
        let authorized: AuthorizedSignRequest
        do {
            authorized = try authorizer.authorize(requestData: request as Data)
        } catch let authorizationError {
            do { try appendAudit(NativeAuditEvent(operation: "git.commit.sign", decision: "deny", reason: authorizationError.localizedDescription), deviceAuditCapabilitySequence: capabilitySequence) }
            catch let auditError {
                controlManager?.invalidate()
                controlV2Manager?.invalidate()
                reply(nil, auditError as NSError)
                return
            }
            reply(nil, authorizationError as NSError)
            return
        }
        var payloadHash: String?
        do {
            let computedPayloadHash = SHA256.hash(data: authorized.payload).map { String(format: "%02x", $0) }.joined()
            payloadHash = computedPayloadHash
            _ = try signingTransactions.begin(requestData: request as Data, authorized: authorized, payloadHash: computedPayloadHash)
            // Durable authorization intent is appended before the hardware key
            // is touched. A missing terminal result is therefore observable as
            // an unresolved outcome rather than silent key use.
            try appendAudit(NativeAuditEvent(operation: "git.commit.sign", decision: "allow", requestID: authorized.requestID, reason: "authorized_intent", agentID: authorized.agentID, repository: authorized.repository, branch: authorized.branch, remote: authorized.remote, payloadSHA256: computedPayloadHash), deviceAuditCapabilitySequence: capabilitySequence)
            try authorizer.revalidate(authorized)
            _ = try signingTransactions.markProviderStarted(requestID: authorized.requestID)
            let signature = try SSHSIG.sign(payload: authorized.payload, signer: keyStore)
            _ = try signingTransactions.recordSigned(requestID: authorized.requestID, signature: signature)
            try appendAudit(NativeAuditEvent(operation: "git.commit.sign", decision: "allow", requestID: authorized.requestID, reason: "allowed", agentID: authorized.agentID, repository: authorized.repository, branch: authorized.branch, remote: authorized.remote, payloadSHA256: computedPayloadHash), deviceAuditCapabilitySequence: capabilitySequence)
            let completed = try signingTransactions.complete(requestID: authorized.requestID)
            reply(completed.signature! as NSString, nil)
        } catch let signingError {
            // Once a signature is durably recorded, never append a contradictory
            // terminal error and never touch the key again. The exact retry path
            // above only repairs the missing final audit record.
            if let transaction = try? signingTransactions.lookup(requestData: request as Data), transaction.phase == .signedVerified {
                controlManager?.invalidate()
                controlV2Manager?.invalidate()
                reply(nil, signingError as NSError)
                return
            }
            // An intent without a durably recorded signature is deliberately
            // treated as ambiguous. This sacrifices availability after a crash
            // boundary rather than risking duplicate hardware-key use.
            if let transaction = try? signingTransactions.lookup(requestData: request as Data), transaction.phase == .intent || transaction.phase == .providerStarted {
                _ = try? signingTransactions.markOutcomeUnknown(requestID: authorized.requestID)
            }
            do { try appendAudit(NativeAuditEvent(operation: "git.commit.sign", decision: "error", requestID: authorized.requestID, reason: signingError.localizedDescription, agentID: authorized.agentID, repository: authorized.repository, branch: authorized.branch, remote: authorized.remote, payloadSHA256: payloadHash), deviceAuditCapabilitySequence: capabilitySequence) }
            catch let auditError {
                controlManager?.invalidate()
                controlV2Manager?.invalidate()
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
            let checkpointStorage = try auditCheckpoints.storageStatus()
            let receiptStorage = try auditAnchorReceipts?.storageStatus(checkpoints: checkpoints)
            let latest: Any = checkpoints.last?.checkpointHash ?? NSNull()
            let fingerprint = NativeAuditCheckpoints.fingerprint(auditSigner.publicKeyX963)
            let session = sessionManager?.status()
            let approvalFingerprint: Any = sessionManager?.approvalKeyFingerprint ?? NSNull()
            let control = controlManager?.status()
            let controlV2 = controlV2Manager?.status()
            let controlSequence = controlV2?.sequence ?? control?.sequence ?? 0
            let controlOperational = controlV2?.operational ?? control?.operational ?? true
            let controlExpired = controlV2?.expired ?? control?.expired ?? false
            let fetch = controlFetcher?.status()
            let data = try JSONSerialization.data(withJSONObject: ["valid": true, "entries": audit.entries, "archive_configured": storage.configured, "archive_segments": storage.segments, "active_bytes": storage.activeBytes, "rotation_ready": storage.rotationReady, "head_hash": audit.headHash, "checkpoints": checkpoints.count, "latest_checkpoint": latest, "audit_key_fingerprint": fingerprint, "checkpoint_archive_configured": checkpointStorage.configured, "checkpoint_archive_segments": checkpointStorage.segments, "checkpoint_active_records": checkpointStorage.activeRecords, "checkpoint_active_bytes": checkpointStorage.activeBytes, "checkpoint_rotation_ready": checkpointStorage.rotationReady, "receipt_archive_configured": receiptStorage?.configured ?? false, "receipt_archive_segments": receiptStorage?.segments ?? 0, "receipt_active_records": receiptStorage?.activeRecords ?? 0, "receipt_active_bytes": receiptStorage?.activeBytes ?? 0, "receipt_rotation_ready": receiptStorage?.rotationReady ?? false, "session_required": session?.required ?? false, "active_sessions": session?.active ?? 0, "session_generation": session?.generation ?? 0, "session_approval_key_fingerprint": approvalFingerprint, "control_configured": control != nil || controlV2 != nil, "control_format_epoch": controlV2?.minimumFormatEpoch ?? (control == nil ? 0 : 1), "control_sequence": controlSequence, "control_operational": controlOperational, "control_expired": controlExpired, "control_expires_at": control?.expiresAt ?? NSNull(), "control_refresh_configured": fetch != nil, "control_device_auth_public_key": fetch?.devicePublicKeyPEM ?? NSNull(), "control_refresh_last_attempt_at": fetch?.lastAttemptAt ?? NSNull(), "control_refresh_last_success_at": fetch?.lastSuccessAt ?? NSNull(), "control_refresh_last_error": fetch?.lastError ?? NSNull(), "control_refresh_next_attempt_at": fetch?.nextAttemptAt ?? NSNull(), "control_refresh_consecutive_failures": fetch?.consecutiveFailures ?? 0], options: [.sortedKeys])
            reply(data as NSData, nil)
        } catch { reply(nil, error as NSError) }
    }

    func auditPublicKey(withReply reply: @escaping (NSString?, NSError?) -> Void) {
        do { try verifyLifecycleTrust(); reply(try SSHSIG.authorizedKey(publicKeyX963: auditSigner.publicKeyX963) as NSString, nil) }
        catch { reply(nil, error as NSError) }
    }

    func createAuditCheckpoint(withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        do { try verifyLifecycleTrustLocked() }
        catch { reply(nil, error as NSError); return }
        do { _ = try auditCheckpoints.verify() }
        catch { reply(nil, error as NSError); return }
        do {
            try rotateEvidenceIfReady()
            try appendAudit(NativeAuditEvent(operation: "audit.checkpoint", decision: "allow"))
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            reply(try encoder.encode(auditCheckpoints.create()) as NSData, nil)
        } catch let checkpointError {
            do { try appendAudit(NativeAuditEvent(operation: "audit.checkpoint", decision: "error", reason: checkpointError.localizedDescription)) }
            catch let auditError { reply(nil, auditError as NSError); return }
            reply(nil, checkpointError as NSError)
        }
    }

    func rotateAudit(withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        do {
            try verifyLifecycleTrustLocked()
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

    func rotateAuditEvidence(withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        do {
            try verifyLifecycleTrustLocked()
            let checkpoints = try auditCheckpoints.verify()
            let checkpointStatus = try auditCheckpoints.storageStatus()
            let receiptStatus = try auditAnchorReceipts?.storageStatus(checkpoints: checkpoints)
            guard checkpointStatus.rotationReady || receiptStatus?.rotationReady == true else {
                throw AgentPassNativeError.invalidConfiguration("Native audit evidence has not reached the 64 MiB rotation threshold")
            }
            var object: [String: Any] = [:]
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            if receiptStatus?.rotationReady == true, let auditAnchorReceipts {
                object["receipts"] = try JSONSerialization.jsonObject(with: encoder.encode(auditAnchorReceipts.rotate(checkpoints: checkpoints)))
            }
            if checkpointStatus.rotationReady {
                object["checkpoints"] = try JSONSerialization.jsonObject(with: encoder.encode(auditCheckpoints.rotate()))
            }
            try appendAudit(NativeAuditEvent(operation: "audit.evidence.rotate", decision: "allow"))
            reply(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) as NSData, nil)
        } catch { reply(nil, error as NSError) }
    }

    func keyLifecycleStatus(withReply reply: @escaping (NSData?, NSError?) -> Void) {
        guard let keyLifecycle else {
            do { reply(try JSONSerialization.data(withJSONObject: ["configured": false], options: [.sortedKeys]) as NSData, nil) }
            catch { reply(nil, error as NSError) }
            return
        }
        do {
            let snapshot = try keyLifecycle.verify()
            let active = Dictionary(uniqueKeysWithValues: NativeKeyRole.allCases.map { role -> (String, Any) in
                guard let generation = snapshot.active(for: role) else { return (role.rawValue, NSNull()) }
                return (role.rawValue, ["generation": generation.generation, "application_tag": generation.applicationTag, "fingerprint": generation.fingerprint])
            })
            let object: [String: Any] = ["configured": true, "valid": true, "sequence": snapshot.sequence, "head_hash": snapshot.headHash, "active": active]
            reply(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) as NSData, nil)
        } catch { reply(nil, error as NSError) }
    }

    func stageKey(role: NSString, withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        guard let keyCoordinator, let role = NativeKeyRole(rawValue: role as String) else {
            reply(nil, AgentPassNativeError.invalidConfiguration("Native key lifecycle coordinator or role is invalid") as NSError)
            return
        }
        do {
            try verifyLifecycleTrustLocked()
            let staged = try keyCoordinator.stageServiceKey(role: role)
            try appendAudit(NativeAuditEvent(operation: "key.stage", decision: "allow", reason: "role=\(role.rawValue);generation=\(staged.generation);fingerprint=\(staged.fingerprint)"))
            let object: [String: Any] = ["role": role.rawValue, "generation": staged.generation, "application_tag": staged.applicationTag, "fingerprint": staged.fingerprint, "lifecycle_head_hash": staged.lifecycleHeadHash, "configuration_pin_update_required": true]
            reply(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) as NSData, nil)
        } catch { reply(nil, error as NSError) }
    }

    func approvalKeyStagePlan(withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        guard let keyCoordinator else {
            reply(nil, AgentPassNativeError.invalidConfiguration("Native key lifecycle coordinator is not configured") as NSError)
            return
        }
        do {
            try verifyLifecycleTrustLocked()
            let plan = try keyCoordinator.approvalKeyStagePlan()
            let object: [String: Any] = ["role": NativeKeyRole.sessionApproval.rawValue, "generation": plan.generation, "application_tag": plan.applicationTag]
            reply(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) as NSData, nil)
        } catch { reply(nil, error as NSError) }
    }

    func stageApprovalKey(generation: Int, applicationTag: NSString, publicKey: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        guard let keyCoordinator else {
            reply(nil, AgentPassNativeError.invalidConfiguration("Native key lifecycle coordinator is not configured") as NSError)
            return
        }
        do {
            try verifyLifecycleTrustLocked()
            let staged = try keyCoordinator.stageApprovalKey(generation: generation, applicationTag: applicationTag as String, publicKeyX963: publicKey as Data)
            try appendAudit(NativeAuditEvent(operation: "key.stage", decision: "allow", reason: "role=\(staged.role.rawValue);generation=\(staged.generation);fingerprint=\(staged.fingerprint)"))
            let object: [String: Any] = ["role": staged.role.rawValue, "generation": staged.generation, "application_tag": staged.applicationTag, "fingerprint": staged.fingerprint, "lifecycle_head_hash": staged.lifecycleHeadHash, "configuration_pin_update_required": true]
            reply(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) as NSData, nil)
        } catch { reply(nil, error as NSError) }
    }

    func beginKeyActivation(role: NSString, generation: Int, reason: NSString, withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        guard let keyCoordinator, let keyLifecycle, let role = NativeKeyRole(rawValue: role as String) else {
            reply(nil, AgentPassNativeError.invalidConfiguration("Native key activation role is invalid") as NSError)
            return
        }
        do {
            try verifyLifecycleTrustLocked()
            pendingKeyActivations = pendingKeyActivations.filter { $0.value.expiresAt > Date() }
            guard pendingKeyActivations.count < 8 else { throw AgentPassNativeError.invalidConfiguration("Too many pending key activation challenges") }
            guard pendingKeyActivations.values.filter({ $0.statement.role == role }).count < 2 else {
                throw AgentPassNativeError.invalidConfiguration("Too many pending key activation challenges for this role")
            }
            try validateManagementReason(reason as String)
            let state = try keyLifecycle.verify()
            guard let approval = state.active(for: .sessionApproval) else { throw AgentPassNativeError.invalidConfiguration("Active lifecycle approval key is missing") }
            let challengeID = UUID().uuidString.lowercased()
            let statement = try keyCoordinator.activationStatement(role: role, generation: generation, reason: reason as String, challengeID: challengeID)
            let expiresAt = Date().addingTimeInterval(60)
            let auditRotationBoundary = try role == .auditCheckpoint ? finalAuditKeyRotationBoundary(statement: statement) : nil
            pendingKeyActivations[challengeID] = PendingKeyActivation(statement: statement, expiresAt: expiresAt, approvalPublicKey: approval.publicKeyX963, approvalApplicationTag: approval.applicationTag, auditRotationBoundary: auditRotationBoundary)
            var object: [String: Any] = [
                "challenge_id": challengeID, "expires_at": serviceTimestamp(expiresAt),
                "role": role.rawValue, "generation": generation, "reason": reason as String,
                "approval_generation": approval.generation, "approval_application_tag": approval.applicationTag,
                "approval_fingerprint": approval.fingerprint, "statement_base64": try statement.canonicalData().base64EncodedString()
            ]
            if let staged = state.generation(generation, for: role) {
                object["new_application_tag"] = staged.applicationTag
                object["new_fingerprint"] = staged.fingerprint
            }
            reply(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) as NSData, nil)
        } catch { reply(nil, error as NSError) }
    }

    func completeKeyActivation(challengeID: NSString, approvalSignature: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        do { try verifyLifecycleTrustLocked() }
        catch { reply(nil, error as NSError); return }
        guard let keyCoordinator else {
            reply(nil, AgentPassNativeError.invalidConfiguration("Native key lifecycle coordinator is not configured") as NSError)
            return
        }
        let identifier = challengeID as String
        guard let pending = pendingKeyActivations.removeValue(forKey: identifier) else {
            reply(nil, AgentPassNativeError.invalidSignature("Key activation challenge is missing or already consumed") as NSError)
            return
        }
        do {
            guard pending.statement.role != .sessionApproval else { throw AgentPassNativeError.invalidConfiguration("Approval-key activation requires two key signatures") }
            guard pending.expiresAt >= Date(), approvalSignature.length == 64 else { throw AgentPassNativeError.invalidSignature("Key activation challenge expired or signature is invalid") }
            let state: NativeKeyLifecycleSnapshot
            if pending.statement.role == .auditCheckpoint {
                guard let boundary = pending.auditRotationBoundary,
                      let rotationCoordinator = auditKeyRotationCoordinator,
                      let keyLifecycle else {
                    throw AgentPassNativeError.invalidConfiguration("Audit-key activation requires durable anchor rotation configuration")
                }
                let lifecycle = try keyLifecycle.verify()
                guard let staged = lifecycle.generation(pending.statement.newGeneration, for: .auditCheckpoint), staged.status == .staged else {
                    throw AgentPassNativeError.invalidConfiguration("Staged audit key is missing")
                }
                let replacementSigner = try SecureEnclaveKeyStore.loadExisting(applicationTag: staged.applicationTag, accessGroup: keychainAccessGroup)
                state = try keyCoordinator.activateServiceKey(statement: pending.statement, approvalSignature: approvalSignature as Data, approvalPublicKeyX963: pending.approvalPublicKey) { preview in
                    guard preview.retiringPublicKeyX963 == self.auditSigner.publicKeyX963,
                          preview.replacementPublicKeyX963 == replacementSigner.publicKeyX963 else {
                        throw AgentPassNativeError.invalidKey("Audit-key activation preview does not match the loaded Secure Enclave keys")
                    }
                    let plan = try rotationCoordinator.prepare(
                        operationID: pending.statement.challengeID,
                        fromGeneration: pending.statement.oldGeneration,
                        lifecycleHeadHash: preview.lifecycleHeadHash,
                        checkpointBoundary: boundary,
                        retiringSigner: self.auditSigner,
                        replacementSigner: replacementSigner,
                        createdAt: pending.statement.createdAt,
                        lifecycleRecordData: preview.canonicalLifecycleRecord
                    )
                    _ = try rotationCoordinator.authorizeActivation(plan: plan, checkpointBoundary: boundary)
                }
            } else {
                state = try keyCoordinator.activateServiceKey(statement: pending.statement, approvalSignature: approvalSignature as Data, approvalPublicKeyX963: pending.approvalPublicKey)
            }
            let revoked = sessionManager?.revokeAll()
            if pending.statement.role != .auditCheckpoint {
                try appendAudit(NativeAuditEvent(operation: "key.activate", decision: "allow", reason: "role=\(pending.statement.role.rawValue);generation=\(pending.statement.newGeneration);lifecycle_head=\(state.headHash);sessions_revoked=\(revoked?.revokedSessions ?? 0)"))
            }
            let object: [String: Any] = ["activated": true, "role": pending.statement.role.rawValue, "generation": pending.statement.newGeneration, "lifecycle_head_hash": state.headHash, "restart_required": true, "configuration_pin_update_required": true]
            reply(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) as NSData, nil)
        } catch {
            if pending.statement.role != .auditCheckpoint {
                _ = try? appendAudit(NativeAuditEvent(operation: "key.activate", decision: "deny", reason: error.localizedDescription))
            }
            reply(nil, error as NSError)
        }
    }

    func completeApprovalKeyActivation(challengeID: NSString, oldSignature: NSData, newSignature: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        do { try verifyLifecycleTrustLocked() }
        catch { reply(nil, error as NSError); return }
        guard let keyCoordinator else {
            reply(nil, AgentPassNativeError.invalidConfiguration("Native key lifecycle coordinator is not configured") as NSError)
            return
        }
        let identifier = challengeID as String
        guard let pending = pendingKeyActivations.removeValue(forKey: identifier) else {
            reply(nil, AgentPassNativeError.invalidSignature("Key activation challenge is missing or already consumed") as NSError)
            return
        }
        do {
            guard pending.statement.role == .sessionApproval, pending.expiresAt >= Date(), oldSignature.length == 64, newSignature.length == 64 else {
                throw AgentPassNativeError.invalidSignature("Approval-key activation challenge or signatures are invalid")
            }
            let state = try keyCoordinator.activateApprovalKey(statement: pending.statement, oldApprovalSignature: oldSignature as Data, newApprovalSignature: newSignature as Data, oldApprovalPublicKeyX963: pending.approvalPublicKey)
            let revoked = sessionManager?.revokeAll()
            try appendAudit(NativeAuditEvent(operation: "key.activate", decision: "allow", reason: "role=session_approval;generation=\(pending.statement.newGeneration);lifecycle_head=\(state.headHash);sessions_revoked=\(revoked?.revokedSessions ?? 0)"))
            let object: [String: Any] = ["activated": true, "role": NativeKeyRole.sessionApproval.rawValue, "generation": pending.statement.newGeneration, "lifecycle_head_hash": state.headHash, "restart_required": true, "configuration_pin_update_required": true]
            reply(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) as NSData, nil)
        } catch {
            _ = try? appendAudit(NativeAuditEvent(operation: "key.activate", decision: "deny", reason: error.localizedDescription))
            reply(nil, error as NSError)
        }
    }

    func beginKeyAbort(role: NSString, generation: Int, reason: NSString, withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        guard let keyCoordinator, let keyLifecycle, let role = NativeKeyRole(rawValue: role as String),
              role == .gitSigning || role == .auditCheckpoint else {
            reply(nil, AgentPassNativeError.invalidConfiguration("Only service-owned staged keys can use this abort path") as NSError)
            return
        }
        do {
            try verifyLifecycleTrustLocked()
            let value = reason as String
            try validateManagementReason(value)
            pendingKeyAborts = pendingKeyAborts.filter { $0.value.expiresAt > Date() }
            guard pendingKeyAborts.count < 8 else { throw AgentPassNativeError.invalidConfiguration("Too many pending key abort challenges") }
            guard pendingKeyAborts.values.filter({ $0.role == role }).count < 2 else {
                throw AgentPassNativeError.invalidConfiguration("Too many pending key abort challenges for this role")
            }
            let state = try keyLifecycle.verify()
            guard let staged = state.generation(generation, for: role), staged.status == .staged,
                  let approval = state.active(for: .sessionApproval) else {
                throw AgentPassNativeError.invalidConfiguration("Staged key or approval authority is missing")
            }
            let challengeID = UUID().uuidString.lowercased()
            let statement = try keyCoordinator.abortStatement(role: role, generation: generation, reason: value, challengeID: challengeID, externallyPinnedHeadHash: state.headHash)
            let expiresAt = Date().addingTimeInterval(60)
            pendingKeyAborts[challengeID] = PendingKeyAbort(role: role, generation: generation, reason: value, statement: statement, lifecycleHead: state.headHash, expiresAt: expiresAt, approvalPublicKey: approval.publicKeyX963, approvalApplicationTag: approval.applicationTag)
            let object: [String: Any] = [
                "challenge_id": challengeID, "expires_at": serviceTimestamp(expiresAt),
                "role": role.rawValue, "generation": generation, "reason": value,
                "staged_application_tag": staged.applicationTag, "staged_fingerprint": staged.fingerprint,
                "approval_application_tag": approval.applicationTag, "approval_fingerprint": approval.fingerprint,
                "lifecycle_head_hash": state.headHash, "statement_base64": statement.base64EncodedString()
            ]
            reply(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) as NSData, nil)
        } catch { reply(nil, error as NSError) }
    }

    func completeKeyAbort(challengeID: NSString, approvalSignature: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        do { try verifyLifecycleTrustLocked() }
        catch { reply(nil, error as NSError); return }
        guard let keyCoordinator else {
            reply(nil, AgentPassNativeError.invalidConfiguration("Native key lifecycle coordinator is not configured") as NSError)
            return
        }
        let identifier = challengeID as String
        guard let pending = pendingKeyAborts.removeValue(forKey: identifier) else {
            reply(nil, AgentPassNativeError.invalidSignature("Key abort challenge is missing or already consumed") as NSError)
            return
        }
        do {
            guard pending.expiresAt >= Date(), approvalSignature.length == 64 else {
                throw AgentPassNativeError.invalidSignature("Key abort challenge expired or signature is invalid")
            }
            let state = try keyCoordinator.abortStagedServiceKey(role: pending.role, generation: pending.generation, reason: pending.reason, challengeID: identifier, externallyPinnedHeadHash: pending.lifecycleHead, approvalSignature: approvalSignature as Data, approvalPublicKeyX963: pending.approvalPublicKey)
            try appendAudit(NativeAuditEvent(operation: "key.abort", decision: "allow", reason: "role=\(pending.role.rawValue);generation=\(pending.generation);lifecycle_head=\(state.headHash)"))
            let object: [String: Any] = ["aborted": true, "role": pending.role.rawValue, "generation": pending.generation, "lifecycle_head_hash": state.headHash, "restart_required": true, "configuration_pin_update_required": true]
            reply(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) as NSData, nil)
        } catch {
            _ = try? appendAudit(NativeAuditEvent(operation: "key.abort", decision: "deny", reason: error.localizedDescription))
            reply(nil, error as NSError)
        }
    }

    func beginKeyDeletion(role: NSString, generation: Int, reason: NSString, minimumRetentionSeconds: Int, proof: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        guard let role = NativeKeyRole(rawValue: role as String),
              role == .auditCheckpoint,
              let keyCoordinator, let keyLifecycle else {
            reply(nil, AgentPassNativeError.invalidConfiguration("Only retired audit-checkpoint keys have an externally verifiable deletion proof") as NSError)
            return
        }
        do {
            try verifyLifecycleTrustLocked()
            try validateManagementReason(reason as String)
            guard (86_400...31_536_000).contains(minimumRetentionSeconds), generation > 0 else {
                throw AgentPassNativeError.invalidConfiguration("Key deletion retention or generation is invalid")
            }
            let proofData = proof as Data
            let keys: Set<String> = ["lifecycle_head_hash", "transition_archived_at", "transition_receipt_hash", "verified_at", "version"]
            guard proofData.count > 0, proofData.count <= 16 * 1024,
                  let object = try JSONSerialization.jsonObject(with: proofData) as? [String: Any],
                  Set(object.keys) == keys,
                  try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]) == proofData,
                  object["version"] as? Int == 1,
                  let lifecycleHead = object["lifecycle_head_hash"] as? String,
                  let receiptHash = object["transition_receipt_hash"] as? String,
                  let archivedAt = object["transition_archived_at"] as? String,
                  let verifiedAt = object["verified_at"] as? String,
                  lifecycleHead.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
                  receiptHash.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
                  serviceDate(archivedAt) != nil, serviceDate(verifiedAt) != nil else {
                throw AgentPassNativeError.invalidSignature("Key deletion proof is not exact canonical schema")
            }
            let deletionProof = NativeLifecycleDeletionProof(
                lifecycleHeadHash: lifecycleHead,
                transitionReceiptHash: receiptHash,
                transitionArchivedAt: archivedAt,
                verifiedAt: verifiedAt
            )
            pendingKeyDeletions = pendingKeyDeletions.filter { $0.value.expiresAt > Date() }
            guard pendingKeyDeletions.count < 4,
                  !pendingKeyDeletions.values.contains(where: { $0.role == role && $0.generation == generation }) else {
                throw AgentPassNativeError.invalidConfiguration("A matching key deletion challenge is already pending")
            }
            let lifecycle = try keyLifecycle.verify()
            guard let target = lifecycle.generation(generation, for: role), target.status == .retired,
                  let approval = lifecycle.active(for: .sessionApproval) else {
                throw AgentPassNativeError.invalidConfiguration("Retired deletion target or active approval key is missing")
            }
            let challengeID = UUID().uuidString.lowercased()
            let statement = try keyCoordinator.deletionStatement(
                role: role, generation: generation, reason: reason as String,
                challengeID: challengeID, minimumRetirementAgeSeconds: minimumRetentionSeconds,
                proof: deletionProof
            )
            let expires = Date().addingTimeInterval(60)
            pendingKeyDeletions[challengeID] = PendingKeyDeletion(
                role: role, generation: generation, reason: reason as String,
                minimumRetentionSeconds: minimumRetentionSeconds, proof: deletionProof,
                challengeID: challengeID, statement: statement, expiresAt: expires,
                approvalPublicKey: approval.publicKeyX963
            )
            let response: [String: Any] = [
                "version": 1, "protocol_version": 11,
                "challenge_id": challengeID, "expires_at": serviceTimestamp(expires),
                "role": role.rawValue, "generation": generation,
                "fingerprint": target.fingerprint, "reason": reason as String,
                "minimum_retention_seconds": minimumRetentionSeconds,
                "approval_application_tag": approval.applicationTag,
                "approval_fingerprint": approval.fingerprint,
                "lifecycle_head_hash": lifecycle.headHash,
                "transition_receipt_hash": receiptHash,
                "statement_base64": statement.base64EncodedString()
            ]
            reply(try JSONSerialization.data(withJSONObject: response, options: [.sortedKeys, .withoutEscapingSlashes]) as NSData, nil)
        } catch { reply(nil, error as NSError) }
    }

    func completeKeyDeletion(challengeID: NSString, approvalSignature: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        do { try verifyLifecycleTrustLocked() }
        catch { reply(nil, error as NSError); return }
        guard let keyCoordinator,
              let pending = pendingKeyDeletions.removeValue(forKey: challengeID as String) else {
            reply(nil, AgentPassNativeError.invalidSignature("Key deletion challenge is missing or already consumed") as NSError)
            return
        }
        do {
            guard pending.expiresAt >= Date(), approvalSignature.length == 64 else {
                throw AgentPassNativeError.invalidSignature("Key deletion challenge expired or signature is invalid")
            }
            let state = try keyCoordinator.deleteRetiredServiceKey(
                role: pending.role, generation: pending.generation, reason: pending.reason,
                challengeID: pending.challengeID, minimumRetirementAgeSeconds: pending.minimumRetentionSeconds,
                proof: pending.proof, approvalSignature: approvalSignature as Data,
                approvalPublicKeyX963: pending.approvalPublicKey
            )
            try appendAudit(NativeAuditEvent(operation: "key.delete", decision: "allow", reason: "role=\(pending.role.rawValue);generation=\(pending.generation);lifecycle_head=\(state.headHash)"))
            let response: [String: Any] = [
                "deleted": true, "role": pending.role.rawValue,
                "generation": pending.generation, "lifecycle_head_hash": state.headHash,
                "configuration_pin_update_required": true
            ]
            reply(try JSONSerialization.data(withJSONObject: response, options: [.sortedKeys]) as NSData, nil)
        } catch {
            _ = try? appendAudit(NativeAuditEvent(operation: "key.delete", decision: "deny", reason: error.localizedDescription))
            reply(nil, error as NSError)
        }
    }

    func beginRecovery(role: NSString, withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        guard let role = NativeKeyRole(rawValue: role as String),
              let recoveryPolicyData,
              let keyCoordinator,
              installationID != nil else {
            reply(nil, AgentPassNativeError.invalidConfiguration("Native recovery is not fully configured") as NSError)
            return
        }
        do {
            if role == .auditCheckpoint {
                guard auditKeyRecoveryCoordinator != nil, auditKeyTransitionStore != nil,
                      auditKeyRecoveryPolicy != nil, auditAnchorTenant != nil else {
                    throw AgentPassNativeError.invalidConfiguration("Audit-key recovery anchor transition is not fully configured")
                }
            }
            try verifyLifecycleTrustLocked()
            let now = Date()
            recoveryRequestAttempts.removeAll { now.timeIntervalSince($0) >= 60 }
            guard recoveryRequestAttempts.count < 4 else {
                throw AgentPassNativeError.invalidConfiguration("Recovery request rate limit exceeded")
            }
            if let existing = pendingRecovery, existing.expiresAt > now {
                throw AgentPassNativeError.invalidConfiguration("A recovery request is already pending")
            }
            pendingRecovery = nil
            recoveryRequestAttempts.append(now)
            let runtime = try currentRecoveryRuntime(role: role)
            var nonceBytes = Data(count: 32)
            let randomStatus = nonceBytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
            guard randomStatus == errSecSuccess else { throw AgentPassNativeError.invalidConfiguration("Recovery nonce generation failed") }
            let nonce = nonceBytes.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
            let issued = Date(), expires = issued.addingTimeInterval(10 * 60)
            let requestData = try NativeRecoveryVerifier.createRequest(
                state: runtime,
                policyData: recoveryPolicyData,
                nonce: nonce,
                issuedAt: serviceTimestamp(issued),
                expiresAt: serviceTimestamp(expires)
            )
            _ = keyCoordinator // Keep the request bound to a configured mutation coordinator.
            pendingRecovery = PendingRecovery(
                requestData: requestData, runtimeState: runtime, expiresAt: expires, challengeID: nonce,
                verification: nil, evidenceData: nil, statement: nil,
                localSignerPublicKey: nil, localSignerApplicationTag: nil, localSignerFingerprint: nil,
                auditPreparation: nil, auditAuthorization: nil, auditEvidence: nil,
                auditPlan: nil, auditSubmissionInFlight: false
            )
            let object: [String: Any] = [
                "version": 1, "protocol_version": 11, "challenge_id": nonce,
                "role": role.rawValue, "expires_at": serviceTimestamp(expires),
                "request_base64": requestData.base64EncodedString(),
                "request_hash": try NativeRecoveryVerifier.requestHash(requestData),
                "lifecycle_head_hash": runtime.lifecycleHeadHash
            ]
            reply(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]) as NSData, nil)
        } catch { reply(nil, error as NSError) }
    }

    func prepareRecoveryInstallation(evidence: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        guard var pending = pendingRecovery, let recoveryPolicyData, let keyCoordinator, let keyLifecycle else {
            reply(nil, AgentPassNativeError.invalidSignature("Recovery request is missing or no longer active") as NSError)
            return
        }
        do {
            guard pending.expiresAt >= Date() else { throw AgentPassNativeError.invalidSignature("Recovery request expired") }
            let evidenceData = evidence as Data
            let bundle = try NativeRecoveryEvidenceBundle.decode(evidenceData)
            guard bundle.requestData == pending.requestData,
                  try NativeRecoveryVerifier.policyHash(bundle.policyData) == NativeRecoveryVerifier.policyHash(recoveryPolicyData) else {
                throw AgentPassNativeError.invalidSignature("Recovery evidence does not contain the exact pending request and pinned policy")
            }
            let verification = try NativeRecoveryVerifier.verify(
                requestData: bundle.requestData,
                policyData: bundle.policyData,
                authorizationData: bundle.authorizationData
            )
            let runtime = try currentRecoveryRuntime(role: verification.request.role)
            guard runtime == pending.runtimeState else {
                throw AgentPassNativeError.invalidSignature("Recovery-bound runtime state changed after request generation")
            }
            try NativeRecoveryVerifier.validateRuntimeState(verification, state: runtime)
            if verification.request.role == .auditCheckpoint {
                guard let policy = auditKeyRecoveryPolicy else {
                    throw AgentPassNativeError.invalidConfiguration("Pinned audit-key recovery policy is unavailable")
                }
                let preparation = try keyCoordinator.prepareRecoveredAuditActivation(
                    verification: verification, evidenceData: evidenceData
                )
                let authorization = try makeAuditRecoveryAuthorization(
                    verification: verification, preparation: preparation, policy: policy
                )
                pending.verification = verification
                pending.evidenceData = evidenceData
                pending.statement = preparation.statement
                pending.auditPreparation = preparation
                pending.auditAuthorization = authorization
                pendingRecovery = pending
                let object: [String: Any] = [
                    "version": 1, "protocol_version": 12,
                    "challenge_id": pending.challengeID,
                    "expires_at": authorization.expiresAt,
                    "role": NativeKeyRole.auditCheckpoint.rawValue,
                    "request_hash": verification.requestHash,
                    "anchor_authorization_base64": try authorization.canonicalData().base64EncodedString(),
                    "anchor_policy_base64": try policy.canonicalData().base64EncodedString(),
                    "lifecycle_statement_base64": try preparation.statement.canonicalData().base64EncodedString(),
                    "predicted_lifecycle_head_hash": preparation.lifecycleHeadHash,
                    "next_step": "native recovery-anchor-install --evidence FILE"
                ]
                reply(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]) as NSData, nil)
                return
            }
            let statement = try keyCoordinator.recoveredActivationStatement(verification: verification)
            let lifecycle = try keyLifecycle.verify()
            let signer: NativeKeyGeneration
            let signerKind: String
            if verification.request.role == .sessionApproval {
                signer = try requiredGeneration(lifecycle, role: .sessionApproval, generation: verification.request.proposedGeneration, status: .staged)
                signerKind = "replacement_approval"
            } else {
                guard let active = lifecycle.active(for: .sessionApproval) else {
                    throw AgentPassNativeError.invalidConfiguration("Active local approval key is missing")
                }
                signer = active
                signerKind = "active_approval"
            }
            pending.verification = verification
            pending.evidenceData = evidenceData
            pending.statement = statement
            pending.localSignerPublicKey = signer.publicKeyX963
            pending.localSignerApplicationTag = signer.applicationTag
            pending.localSignerFingerprint = signer.fingerprint
            pendingRecovery = pending
            let object: [String: Any] = [
                "version": 1, "protocol_version": 11,
                "challenge_id": pending.challengeID, "expires_at": serviceTimestamp(pending.expiresAt),
                "role": verification.request.role.rawValue,
                "generation": verification.request.proposedGeneration,
                "request_hash": verification.requestHash,
                "statement_base64": try statement.canonicalData().base64EncodedString(),
                "local_signer_kind": signerKind,
                "local_signer_application_tag": signer.applicationTag,
                "local_signer_fingerprint": signer.fingerprint
            ]
            reply(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]) as NSData, nil)
        } catch { reply(nil, error as NSError) }
    }

    func completeRecovery(challengeID: NSString, localSignature: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        guard let pending = pendingRecovery,
              pending.challengeID == challengeID as String,
              let verification = pending.verification,
              let evidenceData = pending.evidenceData,
              let statement = pending.statement,
              let signerPublicKey = pending.localSignerPublicKey,
              let keyCoordinator else {
            reply(nil, AgentPassNativeError.invalidSignature("Prepared recovery installation is missing or already consumed") as NSError)
            return
        }
        do {
            guard verification.request.role != .auditCheckpoint,
                  pending.expiresAt >= Date(), localSignature.length == 64,
                  NativeP256LifecycleVerifier().isValid(signature: localSignature as Data, message: try statement.canonicalData(), publicKeyX963: signerPublicKey) else {
                throw AgentPassNativeError.invalidSignature("Recovery local-presence proof is expired or invalid")
            }
            let state = try keyCoordinator.activateRecoveredKey(
                verification: verification,
                evidenceData: evidenceData,
                clientNewKeySignature: verification.request.role == .sessionApproval ? localSignature as Data : nil
            )
            pendingRecovery = nil
            let revoked = sessionManager?.revokeAll()
            let object: [String: Any] = [
                "recovered": true, "role": verification.request.role.rawValue,
                "generation": verification.request.proposedGeneration,
                "lifecycle_head_hash": state.headHash,
                "sessions_revoked": revoked?.revokedSessions ?? 0,
                "restart_required": true, "fail_stopped": true,
                "configuration_pin_update_required": true
            ]
            reply(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]) as NSData, nil)
        } catch {
            pendingRecovery = nil
            reply(nil, error as NSError)
        }
    }

    func prepareAuditRecoveryInstallation(evidence: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        guard var pending = pendingRecovery,
              let verification = pending.verification,
              verification.request.role == .auditCheckpoint,
              let expectedPreparation = pending.auditPreparation,
              let expectedAuthorization = pending.auditAuthorization,
              let policy = auditKeyRecoveryPolicy,
              let keyLifecycle, let keyCoordinator,
              let lifecycleEvidenceData = pending.evidenceData else {
            reply(nil, AgentPassNativeError.invalidSignature("Prepared audit-key recovery authorization is missing") as NSError)
            return
        }
        do {
            let now = Date()
            guard pending.expiresAt >= now, evidence.length > 0,
                  evidence.length <= NativeAuditKeyRecoveryTransition.maximumEncodedBytes else {
                throw AgentPassNativeError.invalidSignature("Audit-key recovery authorization expired or evidence is oversized")
            }
            let decoded = try NativeAuditKeyRecoveryEvidence.decodeCanonical(
                evidence as Data, pinnedPolicy: policy,
                expectedAuthorization: expectedAuthorization,
                expectedInstallationID: verification.request.installationID,
                nowMilliseconds: Int64(now.timeIntervalSince1970 * 1_000)
            )
            let current = try currentRecoveryRuntime(role: .auditCheckpoint)
            guard current == pending.runtimeState else {
                throw AgentPassNativeError.invalidSignature("Audit-key recovery runtime drifted before local approval")
            }
            try NativeRecoveryVerifier.validateRuntimeState(verification, state: current)
            let repeated = try keyCoordinator.prepareRecoveredAuditActivation(
                verification: verification, evidenceData: lifecycleEvidenceData
            )
            try requireSameAuditPreparation(repeated, expectedPreparation)
            let repeatedAuthorization = try makeAuditRecoveryAuthorization(
                verification: verification, preparation: repeated, policy: policy,
                operationID: expectedAuthorization.operationID
            )
            guard repeatedAuthorization == expectedAuthorization else {
                throw AgentPassNativeError.invalidSignature("Audit-key recovery anchor boundary changed after offline approval")
            }
            let lifecycle = try keyLifecycle.verify()
            guard let approval = lifecycle.active(for: .sessionApproval) else {
                throw AgentPassNativeError.invalidConfiguration("Active local approval key is missing")
            }
            pending.auditEvidence = decoded
            pending.localSignerPublicKey = approval.publicKeyX963
            pending.localSignerApplicationTag = approval.applicationTag
            pending.localSignerFingerprint = approval.fingerprint
            pendingRecovery = pending
            let statementData = try expectedPreparation.statement.canonicalData()
            let object: [String: Any] = [
                "version": 1, "protocol_version": 12,
                "challenge_id": pending.challengeID,
                "expires_at": expectedAuthorization.expiresAt,
                "role": NativeKeyRole.auditCheckpoint.rawValue,
                "generation": verification.request.proposedGeneration,
                "request_hash": verification.requestHash,
                "anchor_authorization_base64": try expectedAuthorization.canonicalData().base64EncodedString(),
                "statement_base64": statementData.base64EncodedString(),
                "predicted_lifecycle_head_hash": expectedPreparation.lifecycleHeadHash,
                "local_signer_kind": "active_approval",
                "local_signer_application_tag": approval.applicationTag,
                "local_signer_fingerprint": approval.fingerprint
            ]
            reply(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]) as NSData, nil)
        } catch { reply(nil, error as NSError) }
    }

    func completeAuditRecovery(challengeID: NSString, localSignature: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock()
        guard var pending = pendingRecovery,
              pending.challengeID == challengeID as String,
              !pending.auditSubmissionInFlight,
              let verification = pending.verification,
              verification.request.role == .auditCheckpoint,
              let evidenceData = pending.evidenceData,
              let preparation = pending.auditPreparation,
              let authorization = pending.auditAuthorization,
              let anchorEvidence = pending.auditEvidence,
              let signerPublicKey = pending.localSignerPublicKey,
              let signerFingerprint = pending.localSignerFingerprint,
              let policy = auditKeyRecoveryPolicy,
              let recoveryCoordinator = auditKeyRecoveryCoordinator,
              let approvalJournal = auditKeyRecoveryApprovalJournal,
              let keyCoordinator, let keyLifecycle else {
            authorizationLock.unlock()
            reply(nil, AgentPassNativeError.invalidSignature("Prepared audit-key recovery installation is missing") as NSError)
            return
        }
        let plan: NativeAuditKeyRecoveryPlan
        do {
            let now = Date()
            let statementData = try preparation.statement.canonicalData()
            let authorizationData = try authorization.canonicalData()
            guard pending.expiresAt >= now, localSignature.length == 64,
                  NativeP256LifecycleVerifier().isValid(
                    signature: localSignature as Data,
                    message: statementData,
                    publicKeyX963: signerPublicKey
                  ) else {
                throw AgentPassNativeError.invalidSignature("Audit-key recovery local-presence proof is expired or invalid")
            }
            let current = try currentRecoveryRuntime(role: .auditCheckpoint)
            guard current == pending.runtimeState else {
                throw AgentPassNativeError.invalidSignature("Audit-key recovery runtime drifted before anchor submission")
            }
            try NativeRecoveryVerifier.validateRuntimeState(verification, state: current)
            let repeated = try keyCoordinator.prepareRecoveredAuditActivation(
                verification: verification, evidenceData: evidenceData
            )
            try requireSameAuditPreparation(repeated, preparation)
            let repeatedAuthorization = try makeAuditRecoveryAuthorization(
                verification: verification, preparation: repeated, policy: policy,
                operationID: authorization.operationID
            )
            guard repeatedAuthorization == authorization else {
                throw AgentPassNativeError.invalidSignature("Audit-key recovery authorization drifted before submission")
            }
            _ = try NativeAuditKeyRecoveryEvidence.decodeCanonical(
                try anchorEvidence.canonicalData(),
                pinnedPolicy: policy, expectedAuthorization: authorization,
                expectedInstallationID: verification.request.installationID,
                nowMilliseconds: Int64(now.timeIntervalSince1970 * 1_000)
            )
            let lifecycle = try keyLifecycle.verify()
            let staged = try requiredGeneration(
                lifecycle, role: .auditCheckpoint,
                generation: verification.request.proposedGeneration, status: .staged
            )
            let replacement = try SecureEnclaveKeyStore.loadExisting(
                applicationTag: staged.applicationTag, accessGroup: keychainAccessGroup
            )
            guard replacement.publicKeyX963 == preparation.replacementPublicKeyX963 else {
                throw AgentPassNativeError.invalidKey("Audit-key recovery replacement signer was substituted")
            }
            _ = try approvalJournal.append(
                operationID: authorization.operationID,
                signerFingerprint: signerFingerprint,
                signerPublicKeyX963: signerPublicKey,
                statementData: statementData,
                authorizationData: authorizationData,
                signature: localSignature as Data,
                createdAt: serviceTimestamp(now)
            )
            if let durable = try recoveryCoordinator.pendingPlan() {
                guard durable.transition.recoveryEvidence.authorization == authorization,
                      durable.lifecycleRecordData == preparation.lifecycleRecordData,
                      durable.retiringPublicKeyX963 == preparation.retiringPublicKeyX963 else {
                    throw AgentPassNativeError.invalidSignature("Durable audit recovery plan does not match the frozen authorization")
                }
                plan = durable
            } else {
                plan = try recoveryCoordinator.prepare(
                    authorization: authorization, approvals: anchorEvidence.approvals,
                    replacementSignature: try replacement.sign(message: authorizationData),
                    retiringPublicKeyX963: preparation.retiringPublicKeyX963,
                    lifecycleRecordData: preparation.lifecycleRecordData,
                    nowMilliseconds: Int64(now.timeIntervalSince1970 * 1_000)
                )
            }
            pending.auditPlan = plan
            pending.auditSubmissionInFlight = true
            pendingRecovery = pending
            authorizationLock.unlock()
        } catch {
            authorizationLock.unlock()
            reply(nil, error as NSError)
            return
        }

        let activation: NativeAuditKeyRecoveryActivationAuthorization
        do {
            activation = try recoveryCoordinator.authorizeActivation(plan: plan)
        } catch {
            authorizationLock.lock()
            if var current = pendingRecovery,
               current.challengeID == pending.challengeID,
               current.auditPlan == plan {
                current.auditSubmissionInFlight = false
                pendingRecovery = current
            }
            authorizationLock.unlock()
            reply(nil, error as NSError)
            return
        }

        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        do {
            guard let currentPending = pendingRecovery,
                  currentPending.challengeID == pending.challengeID,
                  currentPending.auditSubmissionInFlight,
                  currentPending.auditPlan == plan,
                  activation.transitionData == plan.transitionData,
                  activation.transition == plan.transition else {
                throw AgentPassNativeError.invalidSignature("Audit recovery pending state changed during anchor submission")
            }
            let current = try currentRecoveryRuntime(role: .auditCheckpoint)
            guard current == pending.runtimeState else {
                throw AgentPassNativeError.invalidSignature("Audit recovery runtime drifted during anchor submission")
            }
            let repeated = try keyCoordinator.prepareRecoveredAuditActivation(
                verification: verification, evidenceData: evidenceData
            )
            try requireSameAuditPreparation(repeated, preparation)
            _ = try approvalJournal.require(
                operationID: authorization.operationID,
                statementData: try preparation.statement.canonicalData(),
                authorizationData: try authorization.canonicalData(),
                expectedSignerFingerprint: signerFingerprint
            )
            let state = try keyCoordinator.commitAuthorizedAuditActivationRecord(preparation.lifecycleRecordData)
            pendingRecovery = nil
            let revoked = sessionManager?.revokeAll()
            let object: [String: Any] = [
                "recovered": true, "role": NativeKeyRole.auditCheckpoint.rawValue,
                "generation": verification.request.proposedGeneration,
                "lifecycle_head_hash": state.headHash,
                "sessions_revoked": revoked?.revokedSessions ?? 0,
                "restart_required": true, "fail_stopped": true,
                "configuration_pin_update_required": true
            ]
            reply(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]) as NSData, nil)
        } catch {
            if var current = pendingRecovery, current.challengeID == pending.challengeID {
                current.auditSubmissionInFlight = false
                pendingRecovery = current
            }
            reply(nil, error as NSError)
        }
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

    func abortExpiredAuditRecovery(withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock(); defer { authorizationLock.unlock() }
        guard let coordinator = auditKeyRecoveryCoordinator else {
            reply(nil, AgentPassNativeError.invalidConfiguration("Native audit-key recovery is not configured") as NSError); return
        }
        do {
            try verifyLifecycleTrustLocked(allowAuditRecoveryPending: true)
            let nowMilliseconds = Int64(Date().timeIntervalSince1970 * 1_000)
            let result = try coordinator.abortExpiredUnsubmittedPending(nowMilliseconds: nowMilliseconds)
            if pendingRecovery?.auditPlan?.transition.operationID == result.preparation.plan.transition.operationID { pendingRecovery = nil }
            let object: [String: Any] = [
                "version": 1, "aborted": true,
                "operation_id": result.preparation.plan.transition.operationID,
                "transition_hash": result.preparation.plan.transition.transitionHash,
                "authorization_expires_at": result.authorizationExpiresAt,
                "aborted_at": result.abortedAt,
                "abort_record_hash": result.abortRecordHash
            ]
            reply(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]) as NSData, nil)
        } catch { reply(nil, error as NSError) }
    }

    func auditRecoveryStatus(withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock(); defer { authorizationLock.unlock() }
        guard let journal = auditKeyRecoveryPlanJournal else {
            do { reply(try JSONSerialization.data(withJSONObject: ["configured": false], options: [.sortedKeys]) as NSData, nil) }
            catch { reply(nil, error as NSError) }; return
        }
        do {
            try verifyLifecycleTrustLocked(allowAuditRecoveryPending: true)
            let status = try journal.status()
            let object: [String: Any] = [
                "configured": true,
                "pending_operation_id": status.pending?.plan.transition.operationID ?? NSNull(),
                "pending_expires_at": status.pending?.plan.transition.expiresAt ?? NSNull(),
                "submission_intent_durable": status.pendingSubmissionIntent != nil,
                "completed_operations": status.completed.count,
                "aborted_operations": status.aborted.count
            ]
            reply(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]) as NSData, nil)
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
            try verifyLifecycleTrustLocked()
            guard !auditAnchorPushInFlight else { throw AgentPassNativeError.invalidConfiguration("Native audit anchor push is already in progress") }
            var checkpoints = try auditCheckpoints.verify()
            if try auditAnchorReceipts.pendingCheckpoint(checkpoints: checkpoints) == nil {
                try appendAudit(NativeAuditEvent(operation: "audit.anchor.push", decision: "allow", reason: "queued"))
                _ = try auditCheckpoints.create()
                checkpoints = try auditCheckpoints.verify()
            }
            guard let pending = try auditAnchorReceipts.pendingCheckpoint(checkpoints: checkpoints) else {
                throw AgentPassNativeError.invalidConfiguration("Native audit anchor has no pending checkpoint")
            }
            checkpoint = pending
            auditAnchorPushInFlight = true
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
                self.auditAnchorPushInFlight = false
                do {
                    try self.verifyLifecycleTrustLocked()
                    switch result {
                    case .success(let receiptData):
                        let checkpoints = try self.auditCheckpoints.verify()
                        let status = try auditAnchorReceipts.accept(receiptData: receiptData, checkpoint: checkpoint, checkpoints: checkpoints)
                        try self.appendAudit(NativeAuditEvent(operation: "audit.anchor.push", decision: "allow", reason: "checkpoint=\(checkpoint.checkpointHash);receipt=\(status.latestReceiptHash ?? "")"))
                        try self.rotateEvidenceIfReady()
                        let encoder = JSONEncoder()
                        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
                        reply(try encoder.encode(status) as NSData, nil)
                    case .failure(let pushError):
                        do { try self.appendAudit(NativeAuditEvent(operation: "audit.anchor.push", decision: "error", reason: pushError.localizedDescription)) }
                        catch { reply(nil, error as NSError); return }
                        reply(nil, pushError as NSError)
                    }
                } catch { reply(nil, error as NSError) }
            }
        } catch {
            authorizationLock.lock()
            defer { authorizationLock.unlock() }
            auditAnchorPushInFlight = false
            do { try appendAudit(NativeAuditEvent(operation: "audit.anchor.push", decision: "error", reason: error.localizedDescription)) }
            catch { reply(nil, error as NSError); return }
            reply(nil, error as NSError)
        }
    }

    private func fetchAuditPruneObservation(purpose: NativeAuditPruneExternalObservationPurpose, operationID: String? = nil) throws -> NativeAuditPruneExternalReceiptObservation {
        guard let auditAnchorClient, let trust = auditPruneTrustSource else {
            throw AgentPassNativeError.invalidConfiguration("Native audit prune external receipt observation is not configured")
        }
        return try NativeAuditPruneExternalObservationFetcher(provider: auditAnchorClient, trustSource: trust)
            .fetch(purpose: purpose, operationID: operationID)
    }

    private func finishAuditPruneObservation(_ observation: NativeAuditPruneExternalReceiptObservation, releaseRemote: Bool) throws {
        guard let trust = auditPruneTrustSource else { throw AgentPassNativeError.invalidConfiguration("Native audit prune observation completion is not configured") }
        try trust.finishAuditPruneExternalReceiptObservation(observation)
        if releaseRemote, let lease = observation.externalLease {
            guard let client = auditAnchorClient else { throw AgentPassNativeError.invalidConfiguration("Native audit prune lease release is not configured") }
            try client.releaseAuditPruneReceiptLease(lease)
        }
    }

    private func abandonAuditPruneObservation(_ observation: NativeAuditPruneExternalReceiptObservation, releaseRemote: Bool = true) {
        auditPruneTrustSource?.discardAuditPruneExternalReceiptObservation(observation)
        if releaseRemote, let lease = observation.externalLease { try? auditAnchorClient?.releaseAuditPruneReceiptLease(lease) }
    }

    func prepareAuditPrune(request: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void) {
        guard let coordinator = auditPruneCoordinator else {
            reply(nil, AgentPassNativeError.invalidConfiguration("Native audit prune is not configured") as NSError); return
        }
        var acquiredObservation: NativeAuditPruneExternalReceiptObservation?
        do {
            let data = request as Data
            guard !data.isEmpty, data.count <= 4 * 1024 * 1024,
                  let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  Set(object.keys) == ["version", "operation_id", "retention_seconds", "segments", "expected_next_retained"],
                  let version = serviceExactInteger(object["version"]), version == 1,
                  let operationID = object["operation_id"] as? String,
                  let retentionSeconds = serviceExactInteger(object["retention_seconds"]),
                  let segmentObjects = object["segments"] as? [[String: Any]], !segmentObjects.isEmpty else {
                throw AgentPassNativeError.invalidConfiguration("Native audit prune prepare request schema is invalid")
            }
            let decoder = JSONDecoder()
            let segments = try segmentObjects.map { try decoder.decode(NativeAuditRetentionSegment.self, from: JSONSerialization.data(withJSONObject: $0, options: [.sortedKeys, .withoutEscapingSlashes])) }
            let retained: NativeAuditRetentionSegment?
            if object["expected_next_retained"] is NSNull { retained = nil }
            else if let retainedObject = object["expected_next_retained"] as? [String: Any] {
                retained = try decoder.decode(NativeAuditRetentionSegment.self, from: JSONSerialization.data(withJSONObject: retainedObject, options: [.sortedKeys, .withoutEscapingSlashes]))
            } else { throw AgentPassNativeError.invalidConfiguration("Native audit prune retained boundary is invalid") }
            authorizationLock.lock()
            do {
                try verifyLifecycleTrustLocked(allowAuditPruneReservation: true); try refreshAuditPruneBoundaryLocked()
                guard !auditPruneSubmissionInFlight else { throw AgentPassNativeError.invalidConfiguration("Audit prune cannot prepare while anchor submission is in progress") }
                guard !auditAnchorPushInFlight else { throw AgentPassNativeError.invalidConfiguration("Audit anchor push is already in flight") }
                authorizationLock.unlock()
            } catch { authorizationLock.unlock(); throw error }
            let observation = try fetchAuditPruneObservation(purpose: .prepare, operationID: operationID)
            acquiredObservation = observation
            let prepared = try authorizationLock.withLock {
                try verifyLifecycleTrustLocked(allowAuditPruneReservation: true); try refreshAuditPruneBoundaryLocked()
                guard !auditPruneSubmissionInFlight, !auditAnchorPushInFlight else {
                    throw AgentPassNativeError.invalidConfiguration("Audit prune state changed during external head verification")
                }
                let prepared = try coordinator.prepare(operationID: operationID, retentionSeconds: retentionSeconds, segments: segments, expectedNextRetained: retained, observation: observation)
                recordAuditPruneStageLocked(stage: "prepare", decision: "success")
                return prepared
            }
            try finishAuditPruneObservation(observation, releaseRemote: true)
            acquiredObservation = nil
            reply(prepared.authorizationData as NSData, nil)
        } catch {
            if let acquiredObservation { abandonAuditPruneObservation(acquiredObservation) }
            authorizationLock.withLock { recordAuditPruneStageLocked(stage: "prepare", decision: "error", error: error) }
            reply(nil, error as NSError)
        }
    }

    func submitAuditPrune(withReply reply: @escaping (NSData?, NSError?) -> Void) {
        guard let coordinator = auditPruneCoordinator, let trust = auditPruneTrustSource else { reply(nil, AgentPassNativeError.invalidConfiguration("Native audit prune is not configured") as NSError); return }
        let frozen: NativeAuditPruneTrustSnapshot
        let operationID: String
        let observation: NativeAuditPruneExternalReceiptObservation
        do { observation = try fetchAuditPruneObservation(purpose: .submit) }
        catch { reply(nil, error as NSError); return }
        authorizationLock.lock()
        do {
            try verifyLifecycleTrustLocked(allowAuditPruneReservation: true); try refreshAuditPruneBoundaryLocked()
            guard !auditPruneSubmissionInFlight else { throw AgentPassNativeError.invalidConfiguration("Audit prune anchor submission is already in progress") }
            guard let boundOperationID = observation.operationID, let reservationID = observation.reservationID else {
                throw AgentPassNativeError.invalidConfiguration("Audit prune submission requires one prepared operation")
            }
            frozen = try trust.currentAuditPruneTrustSnapshot()
            guard frozen.revision == observation.trustRevision,
                  frozen.activeReservationID == reservationID else {
                throw AgentPassNativeError.invalidSignature("Audit prune submission reservation is not the exact durable preparation")
            }
            operationID = boundOperationID
            auditPruneSubmissionInFlight = true; auditPruneSubmissionOperationID = operationID
            recordAuditPruneStageLocked(stage: "submit", decision: "in_progress")
            authorizationLock.unlock()
        } catch {
            recordAuditPruneStageLocked(stage: "submit", decision: "error", error: error)
            authorizationLock.unlock(); abandonAuditPruneObservation(observation); reply(nil, error as NSError); return
        }
        var outcome: Result<NativeAuditPruneAcceptedOperation, Error>
        do {
            let accepted = try coordinator.submitPending(observation: observation)
            try finishAuditPruneObservation(observation, releaseRemote: false)
            if let lease = observation.externalLease { try? auditAnchorClient?.releaseAuditPruneReceiptLease(lease) }
            outcome = .success(accepted)
        } catch {
            abandonAuditPruneObservation(observation)
            outcome = .failure(error)
        }
        let statusObservation: Result<NativeAuditPruneExternalReceiptObservation, Error>
        switch outcome {
        case .success:
            do { statusObservation = .success(try fetchAuditPruneObservation(purpose: .status)) }
            catch { statusObservation = .failure(error) }
        case .failure(let error): statusObservation = .failure(error)
        }
        var acquiredStatusObservation: NativeAuditPruneExternalReceiptObservation?
        if case .success(let value) = statusObservation { acquiredStatusObservation = value }
        do {
            let accepted = try authorizationLock.withLock { () throws -> NativeAuditPruneAcceptedOperation in
                defer { auditPruneSubmissionInFlight = false; auditPruneSubmissionOperationID = nil }
                try verifyLifecycleTrustLocked(allowAuditPruneReservation: true)
                let current = try trust.currentAuditPruneTrustSnapshot()
                guard current == frozen else { throw AgentPassNativeError.invalidSignature("Audit prune trust changed across anchor submission") }
                let accepted = try outcome.get()
                let status = try coordinator.status(observation: statusObservation.get())
                guard status.pendingPreparation?.authorization.operationID == operationID,
                      status.pendingReceiptData == accepted.receiptData else {
                    throw AgentPassNativeError.invalidSignature("Audit prune durable receipt does not match the submitted operation")
                }
                recordAuditPruneStageLocked(stage: "submit", decision: "success")
                return accepted
            }
            if let statusObservationValue = acquiredStatusObservation {
                try finishAuditPruneObservation(statusObservationValue, releaseRemote: true)
                acquiredStatusObservation = nil
            }
            reply(accepted.receiptData as NSData, nil)
        } catch {
            if let acquiredStatusObservation { abandonAuditPruneObservation(acquiredStatusObservation) }
            authorizationLock.withLock {
                auditPruneSubmissionInFlight = false; auditPruneSubmissionOperationID = nil
                recordAuditPruneStageLocked(stage: "submit", decision: "error", error: error)
            }
            reply(nil, error as NSError)
        }
    }

    func executeAuditPrune(withReply reply: @escaping (NSData?, NSError?) -> Void) {
        guard let coordinator = auditPruneCoordinator, let evidencePath = auditPruneEvidenceBundlePath else { reply(nil, AgentPassNativeError.invalidConfiguration("Native audit prune is not configured") as NSError); return }
        var acquiredObservation: NativeAuditPruneExternalReceiptObservation?
        do {
            authorizationLock.lock()
            do {
                guard !auditPruneSubmissionInFlight else { throw AgentPassNativeError.invalidConfiguration("Audit prune cannot execute while anchor submission is in progress") }
                try verifyLifecycleTrustLocked(allowAuditPruneReservation: true); try refreshAuditPruneBoundaryLocked()
                authorizationLock.unlock()
            } catch { authorizationLock.unlock(); throw error }
            let observation = try fetchAuditPruneObservation(purpose: .execute)
            acquiredObservation = observation
            let completed = try authorizationLock.withLock {
                guard !auditPruneSubmissionInFlight else { throw AgentPassNativeError.invalidConfiguration("Audit prune cannot execute while anchor submission is in progress") }
                try verifyLifecycleTrustLocked(allowAuditPruneReservation: true); try refreshAuditPruneBoundaryLocked()
                let completed = try coordinator.executePending(observation: observation)
                try NativeAuditPruneEvidencePublisher.publish(completed.deletionEvidenceBundleData, path: evidencePath)
                recordAuditPruneStageLocked(stage: "execute", decision: "success")
                return completed
            }
            try finishAuditPruneObservation(observation, releaseRemote: true)
            acquiredObservation = nil
            reply(completed.deletionEvidenceBundleData as NSData, nil)
        } catch {
            if let acquiredObservation { abandonAuditPruneObservation(acquiredObservation) }
            authorizationLock.withLock { recordAuditPruneStageLocked(stage: "execute", decision: "error", error: error) }
            reply(nil, error as NSError)
        }
    }

    func auditPruneStatus(withReply reply: @escaping (NSData?, NSError?) -> Void) {
        guard let coordinator = auditPruneCoordinator, let trust = auditPruneTrustSource else {
            do { reply(try JSONSerialization.data(withJSONObject: ["configured": false], options: [.sortedKeys]) as NSData, nil) }
            catch { reply(nil, error as NSError) }; return
        }
        var acquiredObservation: NativeAuditPruneExternalReceiptObservation?
        do {
            authorizationLock.lock()
            if auditPruneSubmissionInFlight {
                defer { authorizationLock.unlock() }
                try verifyLifecycleTrustLocked(allowAuditPruneReservation: true)
                let snapshot = try trust.currentAuditPruneTrustSnapshot()
                let object = try auditPruneStatusObject(
                    completed: snapshot.chainState.sequence,
                    pendingOperationID: auditPruneSubmissionOperationID,
                    receiptDurable: false, snapshot: snapshot, trust: trust
                )
                reply(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]) as NSData, nil)
                return
            }
            authorizationLock.unlock()
            let observation = try fetchAuditPruneObservation(purpose: .status)
            acquiredObservation = observation
            let response = try authorizationLock.withLock { () throws -> (Data, Bool) in
                try verifyLifecycleTrustLocked(allowAuditPruneReservation: true)
                let snapshot = try trust.currentAuditPruneTrustSnapshot()
                if auditPruneSubmissionInFlight {
                    let object = try auditPruneStatusObject(
                        completed: snapshot.chainState.sequence,
                        pendingOperationID: auditPruneSubmissionOperationID,
                        receiptDurable: false, snapshot: snapshot, trust: trust
                    )
                    return (try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]), false)
                }
                let status = try coordinator.status(observation: observation)
                let object = try auditPruneStatusObject(
                    completed: status.completed.count,
                    pendingOperationID: status.pendingPreparation?.authorization.operationID,
                    receiptDurable: status.pendingReceiptData != nil, snapshot: snapshot, trust: trust
                )
                return (try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]), true)
            }
            if response.1 { try finishAuditPruneObservation(observation, releaseRemote: true) }
            else { abandonAuditPruneObservation(observation) }
            acquiredObservation = nil
            reply(response.0 as NSData, nil)
        } catch {
            if let acquiredObservation { abandonAuditPruneObservation(acquiredObservation) }
            reply(nil, error as NSError)
        }
    }

    private func auditPruneStatusObject(completed: Int, pendingOperationID: String?, receiptDurable: Bool, snapshot: NativeAuditPruneTrustSnapshot, trust: NativeAuditPruneServiceTrustSource) throws -> [String: Any] {
        ["configured": true, "completed_operations": completed,
         "pending_operation_id": pendingOperationID ?? NSNull(), "pending_receipt_durable": receiptDurable,
         "submission_in_flight": auditPruneSubmissionInFlight,
         "trust_revision": snapshot.revision, "trust_head_hash": try trust.currentTrustHeadHash(),
         "external_receipt_position_provider_configured": trust.externalReceiptPositionProviderConfigured,
         "active_reservation_id": snapshot.activeReservationID ?? NSNull(),
         "last_stage": auditPruneLastStage ?? NSNull(), "last_decision": auditPruneLastDecision ?? NSNull(),
         "last_error": auditPruneLastError ?? NSNull(), "last_updated_at": auditPruneLastUpdatedAt ?? NSNull()]
    }

    private func recordAuditPruneStageLocked(stage: String, decision: String, error: Error? = nil) {
        auditPruneLastStage = stage; auditPruneLastDecision = decision
        auditPruneLastError = error?.localizedDescription; auditPruneLastUpdatedAt = serviceTimestamp(Date())
    }

    private func refreshAuditPruneBoundaryLocked() throws {
        guard let trust = auditPruneTrustSource, let keyLifecycle,
              let auditAnchorReceipts, let auditKeyTransitionStore else {
            throw AgentPassNativeError.invalidConfiguration("Native audit prune trust dependencies are not configured")
        }
        let lifecycle = try keyLifecycle.verify()
        let checkpoints = try auditCheckpoints.verify()
        let receipts = try auditAnchorReceipts.verifiedReceipts(checkpoints: checkpoints)
        let boundary = try verifiedAuditPruneBoundary(lifecycle: lifecycle, checkpoints: checkpoints, receipts: receipts, transitions: auditKeyTransitionStore.status())
        try trust.refreshVerifiedBoundary(boundary)
    }

    func beginSession(agentID: NSString, ttlSeconds: Int, withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        guard let sessionManager else {
            reply(nil, AgentPassNativeError.invalidConfiguration("Protected native sessions are not configured") as NSError)
            return
        }
        do { try verifyLifecycleTrustLocked() }
        catch { reply(nil, error as NSError); return }
        do { _ = try auditCheckpoints.verify() }
        catch { reply(nil, error as NSError); return }
        do {
            try controlManager?.validateControl(agentID: agentID as String, nowMilliseconds: Int64(Date().timeIntervalSince1970 * 1000))
            try controlV2Manager?.validateControl(agentID: agentID as String, nowMilliseconds: Int64(Date().timeIntervalSince1970 * 1000))
            reply(try sessionManager.beginSession(agentID: agentID as String, requestedTTLSeconds: ttlSeconds) as NSData, nil)
        }
        catch let sessionError {
            do { try appendAudit(NativeAuditEvent(operation: "session.start", decision: "deny", reason: sessionError.localizedDescription, agentID: agentID as String)) }
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
        do { try verifyLifecycleTrustLocked() }
        catch { reply(nil, error as NSError); return }
        do { _ = try auditCheckpoints.verify() }
        catch { reply(nil, error as NSError); return }
        do {
            let issued = try sessionManager.completeSession(challengeData: challenge as Data, signature: signature as Data)
            do { try controlManager?.validateControl(agentID: issued.agentID, nowMilliseconds: Int64(Date().timeIntervalSince1970 * 1000)) }
            catch {
                sessionManager.discardSession(token: issued.token)
                throw error
            }
            do { try controlV2Manager?.validateControl(agentID: issued.agentID, nowMilliseconds: Int64(Date().timeIntervalSince1970 * 1000)) }
            catch {
                sessionManager.discardSession(token: issued.token)
                throw error
            }
            do { try appendAudit(NativeAuditEvent(operation: "session.start", decision: "allow", agentID: issued.agentID, expiresAt: issued.expiresAt)) }
            catch let auditError {
                sessionManager.discardSession(token: issued.token)
                reply(nil, auditError as NSError)
                return
            }
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            reply(try encoder.encode(issued) as NSData, nil)
        } catch let sessionError {
            do { try appendAudit(NativeAuditEvent(operation: "session.start", decision: "deny", reason: sessionError.localizedDescription)) }
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
        do { try verifyLifecycleTrustLocked() }
        catch { reply(nil, error as NSError); return }
        do { _ = try auditCheckpoints.verify() }
        catch { reply(nil, error as NSError); return }
        let revoked = sessionManager.revokeAll()
        do {
            try appendAudit(NativeAuditEvent(operation: "session.revoke-all", decision: "allow", reason: "generation=\(revoked.generation);revoked=\(revoked.revokedSessions)"))
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            reply(try encoder.encode(revoked) as NSData, nil)
        } catch { reply(nil, error as NSError) }
    }

    func revokeSessions(agentID: NSString, withReply reply: @escaping (NSData?, NSError?) -> Void) {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        guard let sessionManager else {
            reply(nil, AgentPassNativeError.invalidConfiguration("Protected native sessions are not configured") as NSError)
            return
        }
        do { try verifyLifecycleTrustLocked() }
        catch { reply(nil, error as NSError); return }
        do { _ = try auditCheckpoints.verify() }
        catch { reply(nil, error as NSError); return }
        do {
            let revoked = try sessionManager.revoke(agentID: agentID as String)
            try appendAudit(NativeAuditEvent(operation: "session.revoke-agent", decision: "allow", reason: "generation=\(revoked.generation);revoked=\(revoked.revokedSessions)", agentID: agentID as String))
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            reply(try encoder.encode(revoked) as NSData, nil)
        } catch { reply(nil, error as NSError) }
    }

    func validateSession(token: NSString?, agentID: NSString, withReply reply: @escaping (Bool, NSError?) -> Void) {
        do { try verifyLifecycleTrust() }
        catch { reply(false, error as NSError); return }
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
            reply(try JSONSerialization.data(withJSONObject: status, options: [.sortedKeys, .withoutEscapingSlashes]) as NSData, nil)
        } catch { reply(nil, error as NSError) }
    }

    func controlStatus(withReply reply: @escaping (NSData?, NSError?) -> Void) {
        do { _ = try auditCheckpoints.verify() }
        catch { reply(nil, error as NSError); return }
        guard controlManager != nil || controlV2Manager != nil else {
            do { reply(try JSONSerialization.data(withJSONObject: ["configured": false], options: [.sortedKeys]) as NSData, nil) }
            catch { reply(nil, error as NSError) }
            return
        }
        do {
            var object = try currentControlStatusObject()
            object.merge(refreshStatusObject(), uniquingKeysWith: { _, replacement in replacement })
            reply(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) as NSData, nil)
        } catch { reply(nil, error as NSError) }
    }

    func refreshControl(withReply reply: @escaping (NSData?, NSError?) -> Void) {
        if let runner = deviceSyncRunner {
            let reply = ServiceDataReply(reply)
            Task { [weak self] in
                guard let self else {
                    reply.call(nil, AgentPassNativeError.invalidConfiguration("Native control service is unavailable") as NSError)
                    return
                }
                let status = await runner.requestRefresh()
                guard status.lifecycle == .running, status.failureCount == 0 else {
                    reply.call(nil, AgentPassNativeError.invalidConfiguration(status.reason.rawValue) as NSError)
                    return
                }
                do {
                    guard let evidenceStore = self.controlRefreshEvidenceStore,
                          let evidence = try evidenceStore.load(),
                          evidence.isAcceptedApplied else {
                        throw AgentPassNativeError.invalidConfiguration("control_refresh_evidence_unavailable")
                    }
                    let object = try evidence.publicResponseObject()
                    reply.call(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]) as NSData, nil)
                } catch { reply.call(nil, error as NSError) }
            }
            return
        }
        guard let controlFetcher else { reply(nil, AgentPassNativeError.invalidConfiguration("Native control refresh is not configured") as NSError); return }
        controlFetcher.fetchNow { [weak self] failure in
            guard let self else { reply(nil, AgentPassNativeError.invalidConfiguration("Native control service is unavailable") as NSError); return }
            if let failure { reply(nil, AgentPassNativeError.invalidConfiguration(failure) as NSError); return }
            do {
                var object = try self.currentControlStatusObject()
                object["refreshed"] = true
                reply(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]) as NSData, nil)
            } catch { reply(nil, error as NSError) }
        }
    }

    func validateControl(agentID: NSString, withReply reply: @escaping (Bool, NSError?) -> Void) {
        do { _ = try auditCheckpoints.verify() }
        catch { reply(false, error as NSError); return }
        guard controlManager != nil || controlV2Manager != nil else { reply(true, nil); return }
        do {
            try controlManager?.validateControl(agentID: agentID as String, nowMilliseconds: Int64(Date().timeIntervalSince1970 * 1000))
            try controlV2Manager?.validateControl(agentID: agentID as String, nowMilliseconds: Int64(Date().timeIntervalSince1970 * 1000))
            reply(true, nil)
        } catch { reply(false, nil) }
    }

    private func handleControlFetch(_ outcome: NativeControlFetchOutcome) throws {
        guard controlV2Manager == nil else {
            throw AgentPassNativeError.invalidConfiguration("Legacy control fetcher cannot serve ControlBundle v2")
        }
        switch outcome {
        case .success(let data):
            _ = try applyControlUpdate(bundleData: data, operation: "control.fetch")
        case .failure(let reason):
            authorizationLock.lock()
            defer { authorizationLock.unlock() }
            guard controlManager != nil || controlV2Manager != nil else { throw AgentPassNativeError.invalidConfiguration("Native remote control is not configured") }
            try verifyLifecycleTrustLocked()
            _ = try auditCheckpoints.verify()
            do { try appendControlFetchFailureIfNeeded(decision: "error", reason: reason) }
            catch {
                controlManager?.invalidate()
                controlV2Manager?.invalidate()
                throw error
            }
        }
    }

    private func applyControlUpdate(
        bundleData: Data,
        operation: String,
        nowMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1_000)
    ) throws -> [String: Any] {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        if let controlV2Manager {
            try verifyLifecycleTrustLocked()
            _ = try auditCheckpoints.verify()
            let requiresUpdate: Bool
            do { requiresUpdate = try controlV2Manager.validateBundle(bundleData: bundleData, nowMilliseconds: nowMilliseconds) }
            catch let controlError {
                do { try appendAudit(NativeAuditEvent(operation: operation, decision: "deny", reason: controlError.localizedDescription)) }
                catch { controlV2Manager.invalidate(); throw error }
                throw controlError
            }
            if !requiresUpdate { return try currentControlStatusObject() }
            try controlV2Manager.beginAuditedUpdate()
            let status: NativeControlBundleV2Status
            do { status = try controlV2Manager.apply(bundleData: bundleData, nowMilliseconds: nowMilliseconds) }
            catch { controlV2Manager.invalidate(); _ = try? appendAudit(NativeAuditEvent(operation: operation, decision: "error", reason: error.localizedDescription)); throw error }
            let revokedSessions = sessionManager?.revokeAll()
            do {
                let sessionReason = revokedSessions.map { ";session_generation=\($0.generation);sessions_revoked=\($0.revokedSessions)" } ?? ""
                try appendAudit(NativeAuditEvent(operation: operation, decision: "allow", reason: "format_epoch=\(status.minimumFormatEpoch);sequence=\(status.sequence)\(sessionReason)"))
                try controlV2Manager.completeAuditedUpdate()
            } catch { controlV2Manager.invalidate(); throw error }
            return try currentControlStatusObject()
        }
        guard let controlManager else { throw AgentPassNativeError.invalidConfiguration("Native remote control is not configured") }
        try verifyLifecycleTrustLocked()
        _ = try auditCheckpoints.verify()
        let requiresUpdate: Bool
        do { requiresUpdate = try controlManager.validateBundle(bundleData: bundleData) }
        catch let controlError {
            do {
                if operation == "control.fetch" { try appendControlFetchFailureIfNeeded(decision: "deny", reason: controlError.localizedDescription) }
                else { try appendAudit(NativeAuditEvent(operation: operation, decision: "deny", reason: controlError.localizedDescription)) }
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
        if !requiresUpdate { return try currentControlStatusObject() }
        try controlManager.beginAuditedUpdate()
        let status: NativeControlStatus
        do { status = try controlManager.apply(bundleData: bundleData) }
        catch {
            controlManager.invalidate()
            _ = try? appendAudit(NativeAuditEvent(operation: operation, decision: "error", reason: error.localizedDescription))
            throw error
        }
        let revokedSessions = sessionManager?.revokeAll()
        do {
            let sessionReason = revokedSessions.map { ";session_generation=\($0.generation);sessions_revoked=\($0.revokedSessions)" } ?? ""
            try appendAudit(NativeAuditEvent(operation: operation, decision: "allow", reason: "sequence=\(status.sequence);expires_at=\(status.expiresAt)\(sessionReason)"))
            try controlManager.completeAuditedUpdate()
        } catch {
            controlManager.invalidate()
            throw error
        }
        return try currentControlStatusObject()
    }

    private func currentControlStatusObject() throws -> [String: Any] {
        if let controlV2Manager {
            let status = controlV2Manager.status()
            return ["configured": true, "format_epoch": status.minimumFormatEpoch, "sequence": status.sequence, "operational": status.operational, "global_revoked": status.globalRevoked, "expired": status.expired, "device_revoked": status.deviceRevoked, "revoked_agents": status.revokedAgents, "revoked_capabilities": status.revokedCapabilities]
        }
        guard let controlManager else { return ["configured": false] }
        let encoder = JSONEncoder(), status = controlManager.status()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var object = try JSONSerialization.jsonObject(with: encoder.encode(status)) as! [String: Any]
        object["format_epoch"] = 1
        object["configured"] = true
        return object
    }

    private func refreshStatusObject() -> [String: Any] {
        if let sync = deviceSyncRunner?.status() {
            return [
                "refresh_configured": true,
                "refresh_source_url": NSNull(),
                "refresh_in_flight": sync.inFlight,
                "refresh_state": sync.state.rawValue,
                "refresh_generation": sync.generation,
                "refresh_sequence": sync.sequence ?? NSNull(),
                "refresh_last_attempt_at": serviceTimestamp(milliseconds: sync.lastAttemptAtMilliseconds) ?? NSNull(),
                "refresh_last_success_at": serviceTimestamp(milliseconds: sync.lastSuccessAtMilliseconds) ?? NSNull(),
                "refresh_last_error": sync.failureCount > 0 ? sync.reason.rawValue : NSNull(),
                "refresh_next_attempt_at": serviceTimestamp(milliseconds: sync.nextAttemptAtMilliseconds) ?? NSNull(),
                "refresh_consecutive_failures": sync.failureCount,
                "device_auth_public_key": deviceSyncPublicKeyPEM ?? NSNull()
            ]
        }
        let fetch = controlFetcher?.status()
        return [
            "refresh_configured": fetch != nil,
            "refresh_source_url": fetch?.sourceURL ?? NSNull(),
            "refresh_in_flight": fetch?.inFlight ?? false,
            "refresh_last_attempt_at": fetch?.lastAttemptAt ?? NSNull(),
            "refresh_last_success_at": fetch?.lastSuccessAt ?? NSNull(),
            "refresh_last_error": fetch?.lastError ?? NSNull(),
            "refresh_next_attempt_at": fetch?.nextAttemptAt ?? NSNull(),
            "refresh_consecutive_failures": fetch?.consecutiveFailures ?? 0,
            "device_auth_public_key": fetch?.devicePublicKeyPEM ?? NSNull()
        ]
    }

    private func appendControlFetchFailureIfNeeded(decision: String, reason: String) throws {
        let now = Date()
        let elapsed = lastControlFetchAuditAt.map { now.timeIntervalSince($0) }
        let key = "\(decision):\(reason)"
        let shouldAppend = elapsed.map { $0 >= 3600 || (lastControlFetchAuditReason != key && $0 >= 300) } ?? true
        guard shouldAppend else { return }
        try appendAudit(NativeAuditEvent(operation: "control.fetch", decision: decision, reason: reason))
        lastControlFetchAuditReason = key
        lastControlFetchAuditAt = now
    }

    private func verifyLifecycleTrust() throws {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        try verifyLifecycleTrustLocked()
    }

    /// Requires `authorizationLock` to be held by the caller.
    private func verifyLifecycleTrustLocked(allowAuditRecoveryPending: Bool = false, allowAuditPruneReservation: Bool = false) throws {
        if let pendingRecovery, pendingRecovery.expiresAt <= Date() { self.pendingRecovery = nil }
        guard allowAuditRecoveryPending || pendingRecovery?.freezesMutations != true else {
            throw AgentPassNativeError.invalidConfiguration("Service operations are frozen while offline recovery is pending")
        }
        if !allowAuditPruneReservation,
           try auditPruneTrustSource?.currentAuditPruneTrustSnapshot().activeReservationID != nil {
            throw AgentPassNativeError.invalidConfiguration("Service mutations are frozen while an audit prune reservation is pending")
        }
        guard let keyLifecycle else { return }
        let state = try keyLifecycle.verify()
        guard state.headHash == loadedLifecycleHeadHash,
              state.active(for: .gitSigning)?.publicKeyX963 == keyStore.publicKeyX963,
              state.active(for: .auditCheckpoint)?.publicKeyX963 == auditSigner.publicKeyX963,
              state.active(for: .sessionApproval)?.fingerprint == sessionManager?.approvalKeyFingerprint else {
            throw AgentPassNativeError.invalidSignature("Active lifecycle keys changed; service is fail-stopped until the external pin is updated and the service restarts")
        }
    }

    private func requiredGeneration(_ state: NativeKeyLifecycleSnapshot, role: NativeKeyRole, generation: Int, status: NativeKeyGenerationStatus) throws -> NativeKeyGeneration {
        guard let value = state.generation(generation, for: role), value.status == status else {
            throw AgentPassNativeError.invalidConfiguration("Required recovery key generation is missing")
        }
        return value
    }

    private func currentRecoveryRuntime(role: NativeKeyRole) throws -> NativeRecoveryRuntimeState {
        guard let installationID, let keyLifecycle, let auditAnchorReceipts else {
            throw AgentPassNativeError.invalidConfiguration("Recovery runtime bindings are not fully configured")
        }
        let lifecycle = try keyLifecycle.verify()
        guard let active = lifecycle.active(for: role),
              let staged = lifecycle.generations.first(where: { $0.role == role && $0.status == .staged }),
              staged.generation == active.generation + 1 else {
            throw AgentPassNativeError.invalidConfiguration("Recovery requires exactly the next staged key generation")
        }
        let audit = try auditLog.verify()
        let checkpoints = try auditCheckpoints.verify()
        let anchorStatus = try auditAnchorReceipts.status(checkpoints: checkpoints)
        let receipts = try auditAnchorReceipts.verifiedReceipts(checkpoints: checkpoints)
        guard let checkpoint = checkpoints.last, let receipt = receipts.last,
              checkpoint.entries == audit.entries,
              checkpoint.headHash == audit.headHash,
              receipt.index == checkpoints.count,
              receipt.checkpointHash == checkpoint.checkpointHash,
              anchorStatus.pending == 0 else {
            throw AgentPassNativeError.invalidSignature("Recovery requires an exact fully anchored current audit boundary")
        }
        let rawControlSequence = controlV2Manager?.status().sequence ?? controlManager?.status().sequence ?? 0
        guard let controlSequence = Int(exactly: rawControlSequence) else {
            throw AgentPassNativeError.invalidConfiguration("Recovery control sequence exceeds the supported range")
        }
        return NativeRecoveryRuntimeState(
            installationID: installationID,
            role: role,
            activeGeneration: active.generation,
            activeFingerprint: active.fingerprint,
            stagedGeneration: staged.generation,
            stagedPublicKeyX963: staged.publicKeyX963,
            lifecycleHeadHash: lifecycle.headHash,
            auditEntries: audit.entries,
            auditHeadHash: audit.headHash,
            latestCheckpointHash: checkpoint.checkpointHash,
            latestReceiptHash: receipt.receiptHash,
            controlSequence: controlSequence
        )
    }

    private func requireSameAuditPreparation(
        _ observed: NativeRecoveredAuditActivationPreparation,
        _ expected: NativeRecoveredAuditActivationPreparation
    ) throws {
        guard observed.statement == expected.statement,
              observed.lifecycleRecordData == expected.lifecycleRecordData,
              observed.lifecycleHeadHash == expected.lifecycleHeadHash,
              observed.retiringPublicKeyX963 == expected.retiringPublicKeyX963,
              observed.replacementPublicKeyX963 == expected.replacementPublicKeyX963,
              observed.replacementSignature == expected.replacementSignature else {
            throw AgentPassNativeError.invalidSignature("Recovered audit lifecycle preparation changed")
        }
    }

    private func makeAuditRecoveryAuthorization(
        verification: NativeRecoveryVerification,
        preparation: NativeRecoveredAuditActivationPreparation,
        policy: NativeAuditKeyRecoveryPolicy,
        operationID: String? = nil
    ) throws -> NativeAuditKeyRecoveryAuthorization {
        guard let tenant = auditAnchorTenant,
              let transitionStore = auditKeyTransitionStore,
              let receiptsStore = auditAnchorReceipts else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key recovery anchor dependencies are unavailable")
        }
        let runtime = try currentRecoveryRuntime(role: .auditCheckpoint)
        guard runtime == pendingRecovery?.runtimeState,
              verification.request.installationID == installationID,
              verification.request.fromGeneration == preparation.statement.oldGeneration,
              verification.request.proposedGeneration == preparation.statement.newGeneration,
              preparation.statement.continuity == .recovered,
              preparation.statement.challengeID == verification.request.nonce,
              preparation.statement.previousLifecycleHead == verification.request.lifecycleHeadHash,
              preparation.lifecycleHeadHash != verification.request.lifecycleHeadHash else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery lifecycle authorization binding is invalid")
        }
        let audit = try auditLog.verify()
        let checkpoints = try auditCheckpoints.verify()
        let anchorStatus = try receiptsStore.status(checkpoints: checkpoints)
        let checkpointReceipts = try receiptsStore.verifiedReceipts(checkpoints: checkpoints)
        guard anchorStatus.pending == 0, anchorStatus.receipts == checkpoints.count,
              let checkpoint = checkpoints.last, let finalReceipt = checkpointReceipts.last,
              checkpoint.entries == audit.entries, checkpoint.headHash == audit.headHash,
              checkpoint.keyGeneration == verification.request.fromGeneration,
              checkpoint.lifecycleHeadHash == verification.request.lifecycleHeadHash,
              checkpoint.checkpointHash == verification.request.latestCheckpointHash,
              finalReceipt.version == 2, finalReceipt.index == checkpoints.count,
              finalReceipt.checkpointHash == checkpoint.checkpointHash,
              finalReceipt.receiptHash == verification.request.latestReceiptHash,
              let finalEventIndex = finalReceipt.eventIndex,
              let finalPreviousEventHash = finalReceipt.previousEventHash else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery requires a fully anchored final retiring-key checkpoint event")
        }
        let transitions = try transitionStore.status()
        let previousTransitionHash: String
        let previousTransitionReceiptHash: String
        if transitions.count == 0 {
            previousTransitionHash = NativeAuditLog.zeroHash
            previousTransitionReceiptHash = NativeAuditLog.zeroHash
        } else {
            guard let transitionReceipt = transitions.latestReceipt,
                  let latestEventIndex = transitions.latestEventIndex,
                  finalEventIndex > latestEventIndex else {
                throw AgentPassNativeError.invalidSignature("Final checkpoint is not newer than the exact latest audit-key transition")
            }
            if let latest = transitions.latestRecoveryTransition {
                previousTransitionHash = latest.transitionHash
            } else if let latest = transitions.latestTransition {
                previousTransitionHash = latest.transitionHash
            } else {
                throw AgentPassNativeError.invalidSignature("Latest audit-key transition is unavailable")
            }
            previousTransitionReceiptHash = transitionReceipt.receiptHash
        }
        let precedingCheckpointHash = checkpointReceipts.dropLast().last.flatMap { receipt -> String? in
            guard receipt.eventIndex == finalEventIndex - 1 else { return nil }
            return receipt.receiptHash
        }
        let precedingTransitionHash: String? = {
            guard transitions.latestEventIndex == finalEventIndex - 1 else { return nil }
            return transitions.latestEventHash
        }()
        let directPredecessors = [precedingCheckpointHash, precedingTransitionHash].compactMap { $0 }
        if finalEventIndex == 1 {
            guard finalPreviousEventHash == NativeAuditLog.zeroHash else {
                throw AgentPassNativeError.invalidSignature("Initial checkpoint receipt has a nonzero predecessor")
            }
        } else {
            guard directPredecessors.count == 1,
                  directPredecessors[0] == finalPreviousEventHash else {
                throw AgentPassNativeError.invalidSignature("Final checkpoint receipt does not directly continue the current global event tip")
            }
        }
        guard let created = serviceDate(verification.request.issuedAt),
              let expires = serviceDate(verification.request.expiresAt),
              let checkpointReceived = serviceDate(finalReceipt.receivedAt),
              created >= checkpointReceived, expires > Date() else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery authorization does not follow its final anchor receipt or has expired")
        }
        return try NativeAuditKeyRecoveryAuthorization(
            tenant: tenant, installationID: verification.request.installationID,
            operationID: operationID ?? UUID().uuidString.lowercased(),
            recoveryRequestID: verification.requestHash,
            policy: policy, fromGeneration: verification.request.fromGeneration,
            oldPublicKeyX963: preparation.retiringPublicKeyX963,
            newPublicKeyX963: preparation.replacementPublicKeyX963,
            lifecycleHeadHash: preparation.lifecycleHeadHash,
            createdAt: verification.request.issuedAt, expiresAt: verification.request.expiresAt,
            previousTransitionHash: previousTransitionHash,
            previousTransitionReceiptHash: previousTransitionReceiptHash,
            lastCheckpointIndex: finalReceipt.index,
            lastCheckpointHash: checkpoint.checkpointHash,
            lastCheckpointReceiptHash: finalReceipt.receiptHash,
            previousAnchorEventIndex: finalEventIndex,
            previousAnchorEventHash: finalReceipt.receiptHash,
            retiringGenerationPendingCheckpointCount: anchorStatus.pending
        )
    }

    private func finalAuditKeyRotationBoundary(statement: NativeKeyTransitionStatement) throws -> NativeAuditKeyRotationCheckpointBoundary {
        guard statement.continuity == .clean,
              let auditAnchorReceipts,
              auditKeyRotationCoordinator != nil else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key activation requires clean continuity and configured durable anchor rotation")
        }
        guard !pendingKeyActivations.values.contains(where: { $0.statement.role == .auditCheckpoint && $0.expiresAt > Date() }) else {
            throw AgentPassNativeError.invalidConfiguration("An audit-key activation challenge is already pending")
        }
        let audit = try auditLog.verify()
        let checkpoints = try auditCheckpoints.verify()
        guard let checkpoint = checkpoints.last,
              checkpoint.entries == audit.entries,
              checkpoint.headHash == audit.headHash,
              checkpoint.keyGeneration == statement.oldGeneration,
              checkpoint.lifecycleHeadHash == statement.previousLifecycleHead else {
            throw AgentPassNativeError.invalidSignature("Audit-key activation requires a final checkpoint for the exact current audit and lifecycle heads")
        }
        let anchorStatus = try auditAnchorReceipts.status(checkpoints: checkpoints)
        let receipts = try auditAnchorReceipts.verifiedReceipts(checkpoints: checkpoints)
        guard anchorStatus.pending == 0,
              anchorStatus.receipts == checkpoints.count,
              let receipt = receipts.last,
              receipt.index == checkpoints.count,
              receipt.checkpointHash == checkpoint.checkpointHash,
              receipt.eventIndex != nil else {
            throw AgentPassNativeError.invalidSignature("Audit-key activation requires the final checkpoint and version-2 anchor receipt with no pending evidence")
        }
        return NativeAuditKeyRotationCheckpointBoundary(anchorStatus: anchorStatus, finalReceipt: receipt)
    }

    @discardableResult
    private func appendAudit(
        _ event: NativeAuditEvent,
        timestamp: Date = Date(),
        deviceAuditCapabilitySequence: Int64? = nil
    ) throws -> NativeAuditStatus {
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        return try appendAuditLocked(
            event,
            timestamp: timestamp,
            deviceAuditCapabilitySequence: deviceAuditCapabilitySequence
        )
    }

    /// Caller must hold `authorizationLock`. Keeping reconciliation lookup and
    /// append under this same service-wide mutation gate makes verified absence
    /// and the subsequent durable append one serialized decision.
    private func appendAuditLocked(
        _ event: NativeAuditEvent,
        timestamp: Date,
        deviceAuditCapabilitySequence: Int64? = nil
    ) throws -> NativeAuditStatus {
        if let pendingRecovery, pendingRecovery.expiresAt <= timestamp { self.pendingRecovery = nil }
        guard pendingRecovery?.freezesMutations != true else {
            throw AgentPassNativeError.invalidConfiguration("Audit evidence is frozen while offline recovery is pending")
        }
        pendingKeyActivations = pendingKeyActivations.filter { $0.value.expiresAt > timestamp }
        guard !pendingKeyActivations.values.contains(where: { $0.statement.role == .auditCheckpoint }) else {
            throw AgentPassNativeError.invalidConfiguration("Audit evidence is frozen at the retiring-key checkpoint boundary")
        }
        let status = try auditLog.append(event, timestamp: timestamp, rotationCheckpointing: auditCheckpoints)
        // An automatic audit rotation creates a checkpoint. Keep checkpoint and receipt segments
        // bounded as part of the same service-level append path.
        try rotateEvidenceIfReady()
        if deviceAuditUploadOperational,
           let outbox = deviceAuditOutbox,
           let eventID = Self.deviceAuditEventID(recordHash: status.headHash),
           let previousHash = try? outbox.nextPreviousHash(),
           let redacted = NativeServiceDeviceAuditProjection.project(
               local: event,
               eventID: eventID,
               policySequence: currentPolicySequence(),
               capabilitySequence: deviceAuditCapabilitySequence,
               deviceTimestamp: serviceTimestamp(timestamp),
               previousHash: previousHash
           ) {
            do {
                _ = try outbox.enqueue(redacted)
            } catch {
                // Local audit durability is the existing signing/XPC boundary.
                // Cloud upload setup is secondary and never changes that result.
                deviceAuditUploadOperational = false
            }
        }
        return status
    }

    func appendAgentSessionAudit(_ evidence: NativeAgentSessionAuditEvidence) throws -> NativeAgentSessionAuditReceipt {
        let evidenceDigestData = try evidence.evidenceDigest()
        let evidenceDigest = evidenceDigestData.map { String(format: "%02x", $0) }.joined()
        let decision: String
        switch evidence.action {
        case .sessionDenied: decision = "deny"
        case .sessionActivationAborted: decision = "deny"
        case .signingOutcomeUnknown, .sessionActivationOutcomeUnknown: decision = "error"
        default: decision = "allow"
        }
        let status = try appendAudit(NativeAuditEvent(
            operation: "agent.session.\(evidence.action.rawValue)",
            decision: decision,
            requestID: evidence.requestID ?? evidence.sessionID,
            reason: evidence.reasonCode,
            agentID: evidence.binding.agentID,
            payloadSHA256: evidenceDigest
        ))
        guard let recordDigest = Self.lowercaseHexDigest(status.headHash) else {
            throw AgentPassNativeError.invalidSignature("Native Agent audit returned an invalid durable head")
        }
        return try NativeAgentSessionAuditReceipt(
            evidenceDigest: evidenceDigestData,
            recordDigest: recordDigest,
            recordIndex: status.entries
        )
    }

    func reconcileAgentSessionActivationAudit(_ evidence: NativeAgentSessionAuditEvidence) throws -> NativeAgentSessionAuditReceipt {
        guard evidence.action == .sessionActivated else {
            throw AgentPassNativeError.invalidSignature("Native Agent activation audit reconciliation input is invalid")
        }
        return try reconcileAgentSessionActivationOutcomeAudit(evidence)
    }

    func reconcileAgentSessionActivationOutcomeAudit(_ evidence: NativeAgentSessionAuditEvidence) throws -> NativeAgentSessionAuditReceipt {
        let decision: String
        switch evidence.action {
        case .sessionActivated: decision = "allow"
        case .sessionActivationAborted: decision = "deny"
        case .sessionActivationOutcomeUnknown: decision = "error"
        default:
            throw AgentPassNativeError.invalidSignature("Native Agent activation outcome audit reconciliation input is invalid")
        }
        guard
              let sessionIDString = evidence.sessionID,
              let sessionID = UUID(uuidString: sessionIDString),
              sessionID.uuidString.lowercased() == sessionIDString,
              let agentID = UUID(uuidString: evidence.binding.agentID),
              agentID.uuidString.lowercased() == evidence.binding.agentID else {
            throw AgentPassNativeError.invalidSignature("Native Agent activation audit reconciliation input is invalid")
        }
        let evidenceDigestData = try evidence.evidenceDigest()
        authorizationLock.lock()
        defer { authorizationLock.unlock() }

        switch try auditLog.lookupAgentSessionActivationOutcomeAudit(
            action: evidence.action,
            sessionID: sessionID,
            expectedAgentID: agentID,
            evidenceDigest: evidenceDigestData
        ) {
        case .exact(let receipt):
            guard let recordDigest = Self.lowercaseHexDigest(receipt.recordHash) else {
                throw AgentPassNativeError.invalidSignature("Native Agent activation audit receipt is invalid")
            }
            return try NativeAgentSessionAuditReceipt(
                evidenceDigest: evidenceDigestData,
                recordDigest: recordDigest,
                recordIndex: receipt.index
            )
        case .conflict:
            throw AgentPassNativeError.invalidSignature("Native Agent activation audit conflicts with durable evidence")
        case .missing:
            let evidenceDigest = evidenceDigestData.map { String(format: "%02x", $0) }.joined()
            let status = try appendAuditLocked(NativeAuditEvent(
                operation: "agent.session.\(evidence.action.rawValue)",
                decision: decision,
                requestID: sessionIDString,
                agentID: evidence.binding.agentID,
                payloadSHA256: evidenceDigest
            ), timestamp: Date())
            guard let recordDigest = Self.lowercaseHexDigest(status.headHash) else {
                throw AgentPassNativeError.invalidSignature("Native Agent audit returned an invalid durable head")
            }
            return try NativeAgentSessionAuditReceipt(
                evidenceDigest: evidenceDigestData,
                recordDigest: recordDigest,
                recordIndex: status.entries
            )
        }
    }

    func lookupAgentSessionActivationOutcomeAudit(
        _ evidence: NativeAgentSessionAuditEvidence
    ) throws -> NativeAgentSessionAuditReceipt? {
        guard evidence.action == .sessionActivated,
              let sessionIDString = evidence.sessionID,
              let sessionID = UUID(uuidString: sessionIDString),
              sessionID.uuidString.lowercased() == sessionIDString,
              let agentID = UUID(uuidString: evidence.binding.agentID),
              agentID.uuidString.lowercased() == evidence.binding.agentID else {
            throw AgentPassNativeError.invalidSignature("Native Agent activation lookup input is invalid")
        }
        let evidenceDigestData = try evidence.evidenceDigest()
        authorizationLock.lock()
        defer { authorizationLock.unlock() }
        switch try auditLog.lookupAgentSessionActivationOutcomeAudit(
            action: evidence.action,
            sessionID: sessionID,
            expectedAgentID: agentID,
            evidenceDigest: evidenceDigestData
        ) {
        case .missing:
            return nil
        case .conflict:
            throw AgentPassNativeError.invalidSignature("Native Agent activation audit conflicts with durable evidence")
        case .exact(let receipt):
            guard let recordDigest = Self.lowercaseHexDigest(receipt.recordHash) else {
                throw AgentPassNativeError.invalidSignature("Native Agent activation audit receipt is invalid")
            }
            return try NativeAgentSessionAuditReceipt(
                evidenceDigest: evidenceDigestData,
                recordDigest: recordDigest,
                recordIndex: receipt.index)
        }
    }

    private static func lowercaseHexDigest(_ value: String) -> Data? {
        guard value.utf8.count == 64,
              value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else { return nil }
        var result = Data(capacity: 32)
        var index = value.startIndex
        while index < value.endIndex {
            let next = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index..<next], radix: 16) else { return nil }
            result.append(byte)
            index = next
        }
        return result
    }

    private func rotateAuditIfReady() throws {
        let storage = try auditLog.storageStatus()
        guard storage.configured, storage.rotationReady else { return }
        _ = try auditCheckpoints.create()
        _ = try auditLog.rotate()
        try rotateEvidenceIfReady()
    }

    private func rotateEvidenceIfReady() throws {
        let checkpoints = try auditCheckpoints.verify()
        if let auditAnchorReceipts, try auditAnchorReceipts.storageStatus(checkpoints: checkpoints).rotationReady {
            _ = try auditAnchorReceipts.rotate(checkpoints: checkpoints)
        }
        if try auditCheckpoints.storageStatus().rotationReady { _ = try auditCheckpoints.rotate() }
    }
}

private final class ManagementListenerDelegate: NSObject, NSXPCListenerDelegate {
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

/// This helper is intentionally injectable so a token mismatch test can prove
/// both terminal closure and denial-before-operation without constructing a
/// live Mach service connection.
internal func authorizeAgentSessionConnectionToken(
    expected: NativeConnectionContext,
    current: () throws -> NativeConnectionContext,
    terminalClose: () -> Void
) throws {
    do {
        guard try current() == expected else {
            throw NativeAgentAuthenticatedHostAuditTokenError.invalidAuditToken
        }
    } catch {
        terminalClose()
        throw error
    }
}

private final class AgentSessionConnectionBox: @unchecked Sendable {
    let connection: NSXPCConnection

    init(_ connection: NSXPCConnection) {
        self.connection = connection
    }
}

/// Service-wide production dependencies for the process-bound Agent runtime.
/// Construction is all-or-none; an absent value means every Agent authority
/// method remains fail-closed while the separate Mach service stays observable.
private final class AgentRuntimeAuthorityState: @unchecked Sendable {
    struct Snapshot {
        let controlSequence: Int64
        let authorityGeneration: Int64
        let keyGeneration: Int64
    }

    private let control: NativeControlBundleV2Manager
    private let keyGeneration: Int64
    private let lock = NSLock()
    private var runner: NativeDeviceSyncRunner?

    init(control: NativeControlBundleV2Manager, keyGeneration: Int) throws {
        guard keyGeneration >= 1, let normalized = Int64(exactly: keyGeneration) else {
            throw NativeAgentSessionCoordinatorError.invalidConfiguration
        }
        self.control = control
        self.keyGeneration = normalized
    }

    func install(runner: NativeDeviceSyncRunner) {
        lock.withLock { self.runner = runner }
    }

    func snapshot(agentID: String) throws -> Snapshot {
        let controlBefore = control.status()
        try control.validateControl(agentID: agentID)
        guard let runner = lock.withLock({ runner }) else {
            throw NativeAgentSessionCoordinatorError.bindingDenied
        }
        let refresh = runner.status()
        let controlAfter = control.status()
        guard controlBefore == controlAfter,
              controlAfter.operational, !controlAfter.globalRevoked,
              !controlAfter.expired, !controlAfter.deviceRevoked,
              controlAfter.sequence >= 1,
              refresh.lifecycle == .running, refresh.state != .blocked,
              refresh.generation >= 1, refresh.sequence == controlAfter.sequence else {
            throw NativeAgentSessionCoordinatorError.bindingDenied
        }
        return Snapshot(
            controlSequence: controlAfter.sequence,
            authorityGeneration: refresh.generation,
            keyGeneration: keyGeneration
        )
    }
}

private struct AgentConnectionSessionBindingObserver: NativeAgentSessionBindingObserving, Sendable {
    let connectionGuard: NativeAgentConnectionGuard
    let processObserver: NativeDarwinProcessObservationSource
    let worktreeObserver: NativeDarwinGitWorktreeObserver
    let authority: AgentRuntimeAuthorityState
    let deviceID: String

    func observeSessionBinding(agentID: String) throws -> NativeAgentSessionBinding {
        let processBefore = try processObserver.observe(
            pid: connectionGuard.context.pid,
            expectedUserID: connectionGuard.context.effectiveUserID
        )
        try connectionGuard.revalidate(observation: processBefore)
        let worktree = try worktreeObserver.observe(
            pid: connectionGuard.context.pid,
            expectedUserID: connectionGuard.context.effectiveUserID
        ).binding
        guard worktree.headObjectID != nil, worktree.headTreeID != nil,
              let processDigest = Self.digest(connectionGuard.processBindingHash),
              let ancestryDigest = Self.digest(connectionGuard.ancestryBindingHash) else {
            throw NativeAgentSessionCoordinatorError.bindingDenied
        }
        let processAfter = try processObserver.observe(
            pid: connectionGuard.context.pid,
            expectedUserID: connectionGuard.context.effectiveUserID
        )
        try connectionGuard.revalidate(observation: processAfter)
        let state = try authority.snapshot(agentID: agentID)
        return try NativeAgentSessionBinding(
            agentID: agentID,
            deviceID: deviceID,
            processBindingDigest: processDigest,
            ancestryBindingDigest: ancestryDigest,
            worktreeBindingDigest: worktree.digest,
            controlSequence: state.controlSequence,
            authorityGeneration: state.authorityGeneration,
            keyGeneration: state.keyGeneration
        )
    }

    func observeSigningAuthority(
        request: NativeSigningTransactionRequest,
        agentID: String,
        keyLifecycleIdentity: String
    ) throws -> NativeSigningTransactionAuthority {
        let binding = try observeSessionBinding(agentID: agentID)
        let worktree = try worktreeObserver.observe(
            pid: connectionGuard.context.pid,
            expectedUserID: connectionGuard.context.effectiveUserID
        ).binding
        guard binding.worktreeBindingDigest == worktree.digest else {
            throw NativeAgentSessionCoordinatorError.bindingDenied
        }
        return try NativeSigningTransactionAuthority(
            request: request,
            binding: binding,
            worktree: worktree,
            keyLifecycleIdentity: keyLifecycleIdentity
        )
    }

    func consumeSigningCapability(
        request: AgentPassAgentSignRequest,
        agentID: String,
        verifier: NativeCapabilityVerifier,
        nowMilliseconds: Int64
    ) throws {
        let binding = try observeSessionBinding(agentID: agentID)
        let worktree = try worktreeObserver.observe(
            pid: connectionGuard.context.pid,
            expectedUserID: connectionGuard.context.effectiveUserID
        ).binding
        guard binding.worktreeBindingDigest == worktree.digest,
              case .branch(let branch) = worktree.head,
              !worktree.remotes.isEmpty else {
            throw NativeAgentSessionCoordinatorError.bindingDenied
        }
        let capability = try verifier.verifyAndConsume(
            request.capability,
            options: NativeCapabilityVerificationOptions(
                nowMilliseconds: nowMilliseconds,
                audience: NativeCapabilityAudience(
                    agentID: binding.agentID,
                    deviceID: binding.deviceID
                )
            ),
            operation: NativeSigningTransactionRequest.operation,
            repository: worktree.repositoryPath,
            branch: branch,
            remotes: worktree.remotes.map(\.url)
        )
        guard capability.capabilityID == request.capabilityID.lowercased() else {
            throw NativeAgentSessionCoordinatorError.bindingDenied
        }
    }

    private static func digest(_ value: String) -> Data? {
        guard value.count == 64 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(32)
        var index = value.startIndex
        while index < value.endIndex {
            let next = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        return Data(bytes)
    }
}

private typealias NativeAgentSessionQualificationFatalAction = @Sendable () -> Never

private func terminateCurrentDaemonForQualification() -> Never {
    if Darwin.kill(getpid(), SIGKILL) == 0 {
        fatalError("Qualification fault SIGKILL unexpectedly returned")
    }
    fatalError("Qualification fault SIGKILL failed")
}

private func qualificationReceiptBinding(
    values: NativeAgentQualificationConfiguration.Values
) throws -> NativeAgentQualificationDurableReceiptBinding {
    func digest(_ value: String) throws -> Data {
        guard value.utf8.count == 64 else {
            throw AgentPassNativeError.invalidConfiguration("Agent qualification digest is invalid")
        }
        var result = Data(capacity: 32)
        var index = value.startIndex
        for _ in 0..<32 {
            let next = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index..<next], radix: 16) else {
                throw AgentPassNativeError.invalidConfiguration("Agent qualification digest is invalid")
            }
            result.append(byte)
            index = next
        }
        return result
    }
    return try NativeAgentQualificationDurableReceiptBinding(
        candidateDigest: digest(values.candidateDigest),
        sourceCommitDigest: digest(values.sourceCommitDigest),
        codeIdentityDigest: digest(values.codeIdentityDigest),
        runIDDigest: digest(values.runBindingDigest),
        scenario: values.scenario,
        phase: values.phase)
}

/// Service-only bridge between the root-authorized qualification controller and
/// the process-local coordinator checkpoints.  The Agent protocol never sees
/// this object or any of its selectors.
private final class NativeAgentSessionQualificationFaultConsumerAdapter:
    NativeAgentSessionQualificationFaultConsuming, @unchecked Sendable
{
    private let controller: NativeAgentQualificationFaultController
    private let runBinding: NativeAgentQualificationRunBinding
    private let scenario: NativeAgentQualificationFaultScenario
    private let phase: NativeAgentQualificationFaultPhase
    private let intendedBoundary: NativeAgentSessionQualificationBoundary?
    private let expiresAtEpochSeconds: UInt64
    private let wallTime: @Sendable () -> Date
    private let fatalAction: NativeAgentSessionQualificationFatalAction
    private let durableReceiptStore: NativeAgentQualificationDurableReceiptStore
    private let durableBinding: NativeAgentQualificationDurableReceiptBinding

    init(
        controller: NativeAgentQualificationFaultController,
        values: NativeAgentQualificationConfiguration.Values,
        durableReceiptStore: NativeAgentQualificationDurableReceiptStore,
        wallTime: @escaping @Sendable () -> Date = Date.init,
        fatalAction: @escaping NativeAgentSessionQualificationFatalAction = terminateCurrentDaemonForQualification
    ) throws {
        guard values.phase == values.scenario.phase else {
            throw AgentPassNativeError.invalidConfiguration(
                "Agent qualification scenario and phase are not an exact pair")
        }
        self.controller = controller
        self.runBinding = try NativeAgentQualificationRunBinding(values.runBindingDigest)
        self.scenario = values.scenario
        self.phase = values.phase
        self.intendedBoundary = Self.boundary(for: values.scenario)
        self.expiresAtEpochSeconds = values.expiresAtEpochSeconds
        self.wallTime = wallTime
        self.fatalAction = fatalAction
        self.durableReceiptStore = durableReceiptStore
        self.durableBinding = try qualificationReceiptBinding(values: values)
    }

    func reach(_ boundary: NativeAgentSessionQualificationBoundary) throws {
        guard intendedBoundary == boundary else { return }
        let now = wallTime().timeIntervalSince1970
        guard now.isFinite, now >= 0, now < Double(expiresAtEpochSeconds) else {
            controller.disable()
            return
        }
        let receipt = controller.consume(
            runBinding: runBinding,
            scenario: scenario,
            phase: phase
        )
        guard receipt.outcome == .injected else { return }
        // This is deliberately the first side effect after consume. The
        // daemon may be terminated immediately after this call returns, so
        // the external controller must have durable fired evidence before any
        // kill/throw/drop action is reached.
        try durableReceiptStore.writeInjected(
            binding: durableBinding, generation: receipt.generation)
        fatalAction()
    }

    private static func boundary(
        for scenario: NativeAgentQualificationFaultScenario
    ) -> NativeAgentSessionQualificationBoundary? {
        switch scenario {
        case .preCloudKill:
            return .beforeCloudConsume
        case .postCloudPreLocalKill:
            return .afterCloudLeaseVerified
        case .postActivationPreAuditKill:
            return .afterHiddenCommit
        case .postAuditPreReplyLoss:
            return .afterResultEncoded
        case .auditFsyncFailure, .transportReplyLoss:
            // These are N3-E3c-3 writer/transport faults. They must not be
            // approximated by a coordinator checkpoint in this adapter.
            return nil
        }
    }

}

private final class NativeAgentAuditDurabilityQualificationFaultConsumerAdapter:
    NativeAuditDurabilityQualificationFaultConsuming, @unchecked Sendable
{
    private let controller: NativeAgentQualificationFaultController
    private let runBinding: NativeAgentQualificationRunBinding
    private let enabled: Bool
    private let expiresAtEpochSeconds: UInt64
    private let wallTime: @Sendable () -> Date
    private let durableReceiptStore: NativeAgentQualificationDurableReceiptStore
    private let durableBinding: NativeAgentQualificationDurableReceiptBinding

    init(
        controller: NativeAgentQualificationFaultController,
        values: NativeAgentQualificationConfiguration.Values,
        durableReceiptStore: NativeAgentQualificationDurableReceiptStore,
        wallTime: @escaping @Sendable () -> Date = Date.init
    ) throws {
        self.controller = controller
        runBinding = try NativeAgentQualificationRunBinding(values.runBindingDigest)
        enabled = values.scenario == .auditFsyncFailure && values.phase == .auditFsync
        expiresAtEpochSeconds = values.expiresAtEpochSeconds
        self.wallTime = wallTime
        self.durableReceiptStore = durableReceiptStore
        self.durableBinding = try qualificationReceiptBinding(values: values)
    }

    func reachBeforeAgentActivationFsync() throws {
        guard enabled else { return }
        let now = wallTime().timeIntervalSince1970
        guard now.isFinite, now >= 0, now < Double(expiresAtEpochSeconds) else {
            controller.disable()
            return
        }
        let receipt = controller.consume(
            runBinding: runBinding,
            scenario: .auditFsyncFailure,
            phase: .auditFsync
        )
        guard receipt.outcome == .injected else { return }
        try durableReceiptStore.writeInjected(
            binding: durableBinding, generation: receipt.generation)
        throw AgentPassNativeError.invalidConfiguration(
            "Agent qualification injected an audit durability failure")
    }
}

private final class NativeAgentTransportReplyQualificationFaultConsumerAdapter:
    NativeAgentSessionTransportReplyFaultConsuming, @unchecked Sendable
{
    private let controller: NativeAgentQualificationFaultController
    private let runBinding: NativeAgentQualificationRunBinding
    private let enabled: Bool
    private let expiresAtEpochSeconds: UInt64
    private let wallTime: @Sendable () -> Date
    private let durableReceiptStore: NativeAgentQualificationDurableReceiptStore
    private let durableBinding: NativeAgentQualificationDurableReceiptBinding

    init(
        controller: NativeAgentQualificationFaultController,
        values: NativeAgentQualificationConfiguration.Values,
        durableReceiptStore: NativeAgentQualificationDurableReceiptStore,
        wallTime: @escaping @Sendable () -> Date = Date.init
    ) throws {
        self.controller = controller
        runBinding = try NativeAgentQualificationRunBinding(values.runBindingDigest)
        enabled = values.scenario == .transportReplyLoss && values.phase == .transportReply
        expiresAtEpochSeconds = values.expiresAtEpochSeconds
        self.wallTime = wallTime
        self.durableReceiptStore = durableReceiptStore
        self.durableBinding = try qualificationReceiptBinding(values: values)
    }

    func shouldDropEncodedResult() -> Bool {
        guard enabled else { return false }
        let now = wallTime().timeIntervalSince1970
        guard now.isFinite, now >= 0, now < Double(expiresAtEpochSeconds) else {
            controller.disable()
            return false
        }
        let receipt = controller.consume(
            runBinding: runBinding,
            scenario: .transportReplyLoss,
            phase: .transportReply
        )
        guard receipt.outcome == .injected else { return false }
        do {
            try durableReceiptStore.writeInjected(
                binding: durableBinding, generation: receipt.generation)
        } catch {
            // A failed durable commit is not an injected transport fault. Do
            // not drop the reply when the evidence boundary is unavailable.
            return false
        }
        return true
    }
}

private final class AgentRuntimeDependencies: @unchecked Sendable {
    let authority: NativeAgentRuntimeAuthorityConfiguration
    let grantConsumer: NativeAgentGrantLeaseHTTPConsumer
    let registry = NativeAgentSessionRegistry()
    let consumeRecoveryStore: NativeAgentSessionConsumeRecoveryStore
    let activationRecoveryStore: NativeAgentSessionConsumeRecoveryV4Store
    let signingIntentStore: NativeAgentSigningIntentStore
    let signingTransactions: NativeSigningTransactionStore
    let gitCommitSigner: NativeAgentGitCommitSigner
    let capabilityVerifier: NativeCapabilityVerifier
    let cloudSigningCapabilityVerifier: NativeAgentSigningCapabilityVerifier
    let dedicatedSigningCapabilityIssuer: NativeAgentDedicatedSigningCapabilityRuntimeIssuer
    let dedicatedCapabilitySequenceAuthorities: NativeAgentDedicatedSigningCapabilitySequenceAuthorityRegistry
    let authorityState: AgentRuntimeAuthorityState
    let qualificationFaultConsumer: any NativeAgentSessionQualificationFaultConsuming

    init(
        authority: NativeAgentRuntimeAuthorityConfiguration,
        authorityState: AgentRuntimeAuthorityState,
        deviceSigner: SecureEnclaveKeyStore,
        gitSigner: SecureEnclaveKeyStore,
        capabilityVerifier: NativeCapabilityVerifier,
        qualificationFaultConsumer: any NativeAgentSessionQualificationFaultConsuming
    ) throws {
        try Self.validatePrivateDirectory(authority.signingIntentDirectory)
        self.authority = authority
        self.authorityState = authorityState
        self.capabilityVerifier = capabilityVerifier
        let trustedPublicKey = try NativeCapabilityTrust(
            publicKeyPEM: authority.capabilityPublicKeyPEM
        ).publicKey
        self.cloudSigningCapabilityVerifier = try NativeAgentSigningCapabilityVerifier(
            trustedPublicKey: trustedPublicKey,
            expectedIssuer: NativeAgentSigningCapabilityCodec.issuer,
            expectedKeyPurpose: NativeAgentSigningCapabilityCodec.operation,
            expectedKeyID: authority.capabilityKeyID,
            expectedDomain: NativeAgentSigningCapabilityCodec.signatureDomain
        )
        let capabilityVerifier = self.cloudSigningCapabilityVerifier
        let sequenceAuthorities = NativeAgentDedicatedSigningCapabilitySequenceAuthorityRegistry(
            persistenceDirectory: authority.signingIntentDirectory
        )
        self.dedicatedCapabilitySequenceAuthorities = sequenceAuthorities
        self.dedicatedSigningCapabilityIssuer = NativeAgentDedicatedSigningCapabilityRuntimeIssuer(
            makeConsumer: { sessionID in
                try NativeAgentSigningCapabilityHTTPConsumer(
                    baseURL: authority.deviceAPIOrigin,
                    organizationID: authority.organizationID,
                    deviceID: authority.deviceID,
                    sessionID: sessionID,
                    transport: NativeAgentURLSessionHTTPTransport(),
                    signer: deviceSigner
                )
            },
            verifier: capabilityVerifier,
            sequenceAuthority: { context in
                let binding = try NativeAgentDedicatedSigningCapabilitySequenceBinding(
                    coordinatorSessionID: context.sessionID,
                    agentID: context.agentID
                )
                return try sequenceAuthorities.authority(for: binding)
            }
        )
        self.qualificationFaultConsumer = qualificationFaultConsumer
        grantConsumer = try NativeAgentGrantLeaseHTTPConsumer(
            baseURL: authority.deviceAPIOrigin,
            organizationID: authority.organizationID,
            transport: NativeAgentURLSessionHTTPTransport(),
            signer: deviceSigner
        )
        signingIntentStore = try NativeAgentSigningIntentStore(
            path: authority.signingIntentDirectory + "/signing-intents.v1.json"
        )
        signingTransactions = try NativeSigningTransactionStore(
            path: authority.signingIntentDirectory + "/signing-transactions.v2.json"
        )
        consumeRecoveryStore = try NativeAgentSessionConsumeRecoveryStore(
            path: authority.signingIntentDirectory + "/session-consume-recovery.v1.json"
        )
        activationRecoveryStore = try NativeAgentSessionConsumeRecoveryV4Store(
            path: authority.signingIntentDirectory + "/session-activation-recovery.v4.json"
        )
        gitCommitSigner = try NativeAgentGitCommitSigner(signer: gitSigner)
    }

    private static func validatePrivateDirectory(_ path: String) throws {
        var info = stat()
        guard lstat(path, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == geteuid(),
              info.st_mode & 0o077 == 0,
              URL(fileURLWithPath: path, isDirectory: true).resolvingSymlinksInPath().path == path else {
            throw AgentPassNativeError.invalidConfiguration("Agent signing-intent directory is unavailable")
        }
        var current = URL(fileURLWithPath: path, isDirectory: true)
        while true {
            var ancestor = stat()
            guard lstat(current.path, &ancestor) == 0,
                  (ancestor.st_mode & S_IFMT) == S_IFDIR,
                  ancestor.st_uid == 0 || ancestor.st_uid == geteuid(),
                  ancestor.st_mode & 0o022 == 0 else {
                throw AgentPassNativeError.invalidConfiguration("Agent signing-intent directory ancestry is unavailable")
            }
            if current.path == "/" { break }
            current.deleteLastPathComponent()
        }
    }
}

/// One exported object is created per accepted Agent connection. It owns the
/// immutable peer guard and cannot expose or forward any management selector.
/// Bootstrap is connection-bound and one-time. All authority-bearing methods
/// continue to fail closed until the N3 lease registry is installed; there is
/// no compatibility fallback to the bearer-oriented management endpoint.
private final class AgentXPCReplyBox<Response>: @unchecked Sendable {
    private let callback: (Response?, NSError?) -> Void
    init(_ callback: @escaping (Response?, NSError?) -> Void) { self.callback = callback }
    func call(_ response: Response?, _ error: NSError?) { callback(response, error) }
}

private final class AgentConnectionEndpoint: NSObject, AgentPassAgentXPCProtocol, @unchecked Sendable {
    private let connectionGuard: NativeAgentConnectionGuard
    private let observer: NativeDarwinProcessObservationSource
    private let connection: NSXPCConnection
    private let auditTokenSource: any NativeAgentAuthenticatedHostAuditTokenSource
    private let runtime: AgentRuntimeDependencies?
    private let qualificationFaultConsumer: any NativeAgentSessionQualificationFaultConsuming
    private let transportReplyFaultConsumer: any NativeAgentSessionTransportReplyFaultConsuming
    private let bootstrapStore = NativeAgentBootstrapChallengeStore()
    private let clocks = NativeAgentSystemClocks()
    private let worker = DispatchQueue(label: "dev.agentpass.agent-session.connection")
    private let coordinator: NativeAgentSessionCoordinator?
    private let signingBindingObserver: AgentConnectionSessionBindingObserver?
    private let sessionAssociationRegistry: NativeAgentCoordinatorSessionAssociationRegistry?
    private let terminalCloseLock = NSLock()
    private var hasTerminallyClosed = false
    private var activeSessionBinding: NativeAgentSessionBinding?

    init(
        connection: NSXPCConnection,
        connectionGuard: NativeAgentConnectionGuard,
        observer: NativeDarwinProcessObservationSource,
        auditTokenSource: any NativeAgentAuthenticatedHostAuditTokenSource,
        runtime: AgentRuntimeDependencies?,
        auditAppender: any NativeAgentSessionAuditAppending,
        qualificationFaultConsumer: any NativeAgentSessionQualificationFaultConsuming,
        transportReplyFaultConsumer: any NativeAgentSessionTransportReplyFaultConsuming,
        sessionAssociationRegistry: NativeAgentCoordinatorSessionAssociationRegistry?
    ) {
        self.connection = connection
        self.connectionGuard = connectionGuard
        self.observer = observer
        self.auditTokenSource = auditTokenSource
        self.runtime = runtime
        self.qualificationFaultConsumer = qualificationFaultConsumer
        self.transportReplyFaultConsumer = transportReplyFaultConsumer
        self.sessionAssociationRegistry = sessionAssociationRegistry
        let connectionBox = AgentSessionConnectionBox(connection)
        if let runtime {
            let bindingObserver = AgentConnectionSessionBindingObserver(
                connectionGuard: connectionGuard,
                processObserver: observer,
                worktreeObserver: NativeDarwinGitWorktreeObserver(),
                authority: runtime.authorityState,
                deviceID: runtime.authority.deviceID
            )
            signingBindingObserver = bindingObserver
            coordinator = try? NativeAgentSessionCoordinator(
                connectionTokenIdentity: connectionGuard.context.tokenIdentity,
                connectionRevalidator: {
                    do {
                        let observation = try observer.observe(
                            pid: connectionGuard.context.pid,
                            expectedUserID: connectionGuard.context.effectiveUserID
                        )
                        try connectionGuard.revalidate(observation: observation)
                        let currentToken = try auditTokenSource.completeAuditToken(for: connectionBox.connection)
                        guard currentToken.pid == connectionGuard.context.pid,
                              currentToken.effectiveUserID == connectionGuard.context.effectiveUserID else {
                            throw NativeAgentAuthenticatedHostAuditTokenError.invalidAuditToken
                        }
                        let currentContext = try currentToken.context(matching: observation)
                        try authorizeAgentSessionConnectionToken(
                            expected: connectionGuard.context,
                            current: { currentContext },
                            terminalClose: {
                                connectionBox.connection.invalidate()
                            }
                        )
                    } catch {
                        connectionBox.connection.invalidate()
                        throw error
                    }
                },
                bootstrapStore: bootstrapStore,
                bindingObserver: bindingObserver,
                grantConsumer: runtime.grantConsumer,
                recoveryStore: runtime.consumeRecoveryStore,
                activationRecoveryStore: runtime.activationRecoveryStore,
                qualificationFaultConsumer: runtime.qualificationFaultConsumer,
                registry: runtime.registry,
                audit: auditAppender,
                wallClock: clocks.wallClock,
                monotonicClock: clocks.monotonicClock,
                authority: runtime.authority
            )
        } else {
            signingBindingObserver = nil
            coordinator = nil
        }
    }

    private func authorizeConnection() throws {
        do {
            let observation = try observer.observe(
                pid: connectionGuard.context.pid,
                expectedUserID: connectionGuard.context.effectiveUserID
            )
            try connectionGuard.revalidate(observation: observation)
            let currentToken = try auditTokenSource.completeAuditToken(for: connection)
            guard currentToken.pid == connectionGuard.context.pid,
                  currentToken.effectiveUserID == connectionGuard.context.effectiveUserID else {
                throw NativeAgentAuthenticatedHostAuditTokenError.invalidAuditToken
            }
            let currentContext = try currentToken.context(matching: observation)
            try authorizeAgentSessionConnectionToken(
                expected: connectionGuard.context,
                current: { currentContext },
                terminalClose: { [weak self] in self?.terminallyClose() }
            )
        } catch {
            terminallyClose()
            throw error
        }
    }

    private func terminallyClose() {
        let shouldClose = terminalCloseLock.withLock {
            guard !hasTerminallyClosed else { return false }
            hasTerminallyClosed = true
            return true
        }
        guard shouldClose else { return }
        let binding = terminalCloseLock.withLock {
            defer { activeSessionBinding = nil }
            return activeSessionBinding
        }
        if let binding {
            sessionAssociationRegistry?.invalidate(binding: binding)
        }
        coordinator?.invalidateConnection()
        bootstrapStore.invalidate()
        connection.invalidate()
    }

    private func unavailableAfterAuthorization() -> NSError {
        do {
            try authorizeConnection()
            return NativeAgentSessionDenialReason.unavailable.nsError
        } catch {
            bootstrapStore.invalidate()
            coordinator?.invalidateConnection()
            return NativeAgentSessionDenialReason.peerDenied.nsError
        }
    }

    func bootstrapAgent(_ request: AgentPassAgentBootstrapRequest, withReply reply: @escaping (AgentPassAgentBootstrapResponse?, NSError?) -> Void) {
        do {
            try authorizeConnection()
        } catch {
            bootstrapStore.invalidate()
            reply(nil, NativeAgentSessionDenialReason.peerDenied.nsError)
            return
        }
        guard runtime != nil else {
            bootstrapStore.invalidate()
            reply(nil, NativeAgentSessionDenialReason.unavailable.nsError)
            return
        }
        do {
            guard let adapterKind = AgentPassAgentAdapterKind(rawValue: request.adapterKind) else {
                throw NativeAgentBootstrapChallengeError.invalidInput
            }
            let bootIdentityHash = SHA256.hash(data: Data(connectionGuard.initialIdentity.bootIdentity.utf8))
                .map { String(format: "%02x", $0) }.joined()
            let binding = try NativeAgentBootstrapConnectionBinding(
                connectionTokenIdentity: connectionGuard.context.tokenIdentity,
                processBindingHash: connectionGuard.processBindingHash,
                ancestryBindingHash: connectionGuard.ancestryBindingHash,
                bootIdentityHash: bootIdentityHash
            )
            // Capture monotonic first so the challenge can only receive a
            // shorter authority window during sampling, never a longer one.
            let monotonic = try clocks.monotonicClock.sample()
            let wall = try clocks.wallClock.sample()
            let challenge = try bootstrapStore.begin(
                agentID: request.agentID,
                adapterKind: adapterKind,
                requestedTTLSeconds: request.requestedTTLSeconds,
                clientNonce: request.bootstrapNonce,
                connectionBinding: binding,
                nowMilliseconds: wall.millisecondsSinceUnixEpoch,
                nowMonotonicNanoseconds: monotonic.nanoseconds
            )
            guard let response = AgentPassAgentBootstrapResponse(
                bootstrapID: challenge.bootstrapID,
                challenge: challenge.challenge,
                expiresAtMilliseconds: challenge.expiresAtMilliseconds
            ) else {
                throw NativeAgentBootstrapChallengeError.invalidInput
            }
            reply(response, nil)
        } catch {
            bootstrapStore.invalidate()
            reply(nil, NativeAgentSessionDenialReason.challengeDenied.nsError)
        }
    }

    func startAgentSession(_ request: AgentPassAgentSessionRequest, withReply reply: @escaping (AgentPassAgentSessionResponse?, NSError?) -> Void) {
        let bootstrapID = request.bootstrapID
        let proof = request.proof
        let replyBox = AgentXPCReplyBox(reply)
        worker.async { [weak self] in
            guard let self, let coordinator = self.coordinator else {
                replyBox.call(nil, NativeAgentSessionDenialReason.unavailable.nsError)
                return
            }
            do {
                try self.authorizeConnection()
                let activation = try coordinator.start(bootstrapID: bootstrapID, proof: proof)
                if let runtime = self.runtime,
                   let registry = self.sessionAssociationRegistry {
                    let dedicatedAssociation = NativeAgentDedicatedSigningAssociation(
                        coordinator: coordinator,
                        transactionStore: runtime.signingTransactions)
                    _ = try registry.register(
                        sessionID: activation.status.sessionID,
                        binding: activation.binding,
                        coordinator: coordinator,
                        dedicatedSigningAssociation: dedicatedAssociation)
                    self.terminalCloseLock.withLock {
                        self.activeSessionBinding = activation.binding
                    }
                }
                guard let response = AgentPassAgentSessionResponse(
                    sessionID: activation.status.sessionID,
                    leaseID: activation.status.leaseID,
                    deviceID: activation.binding.deviceID,
                    processBindingDigest: activation.binding.processBindingDigest,
                    ancestryBindingDigest: activation.binding.ancestryBindingDigest,
                    worktreeBindingDigest: activation.binding.worktreeBindingDigest,
                    controlSequence: activation.binding.controlSequence,
                    authorityGeneration: activation.binding.authorityGeneration,
                    keyGeneration: activation.binding.keyGeneration,
                    expiresAtMilliseconds: activation.status.expiresAtMilliseconds,
                    maxSignatures: activation.status.maxSignatures
                ) else {
                    if let binding = self.terminalCloseLock.withLock({ self.activeSessionBinding }) {
                        self.sessionAssociationRegistry?.invalidate(binding: binding)
                        self.terminalCloseLock.withLock { self.activeSessionBinding = nil }
                    }
                    coordinator.abortActivation(sessionID: activation.status.sessionID)
                    replyBox.call(nil, NativeAgentSessionDenialReason.internalFailure.nsError)
                    return
                }
                do {
                    try self.qualificationFaultConsumer.reach(.afterResultEncoded)
                } catch {
                    // The production injected branch never returns after its
                    // atomic receipt. Any ordinary throwing implementation is
                    // therefore a local fault and must not strand reply-less
                    // authority.
                    coordinator.abortActivation(sessionID: activation.status.sessionID)
                    if let binding = self.terminalCloseLock.withLock({ self.activeSessionBinding }) {
                        self.sessionAssociationRegistry?.invalidate(binding: binding)
                        self.terminalCloseLock.withLock { self.activeSessionBinding = nil }
                    }
                    throw error
                }
                guard !self.transportReplyFaultConsumer.shouldDropEncodedResult() else { return }
                replyBox.call(response, nil)
            } catch {
                replyBox.call(nil, Self.denial(for: error).nsError)
            }
        }
    }

    func agentSessionStatus(_ request: AgentPassAgentSessionStatusRequest, withReply reply: @escaping (AgentPassAgentSessionStatusResponse?, NSError?) -> Void) {
        let sessionID = request.sessionID
        let replyBox = AgentXPCReplyBox(reply)
        worker.async { [weak self] in
            guard let self, let coordinator = self.coordinator else {
                replyBox.call(nil, NativeAgentSessionDenialReason.unavailable.nsError)
                return
            }
            do {
                try self.authorizeConnection()
                let status = try coordinator.status(sessionID: sessionID)
                guard let response = AgentPassAgentSessionStatusResponse(
                    sessionID: status.sessionID,
                    status: status.state.rawValue,
                    expiresAtMilliseconds: status.expiresAtMilliseconds,
                    maxSignatures: status.maxSignatures,
                    usedSignatures: status.usedSignatures
                ) else {
                    replyBox.call(nil, NativeAgentSessionDenialReason.internalFailure.nsError)
                    return
                }
                replyBox.call(response, nil)
            } catch {
                replyBox.call(nil, Self.denial(for: error).nsError)
            }
        }
    }

    func signGitCommit(_ request: AgentPassAgentSignRequest, withReply reply: @escaping (AgentPassAgentSignResponse?, NSError?) -> Void) {
        let replyBox = AgentXPCReplyBox(reply)
        worker.async { [weak self] in
            guard let self,
                  let runtime = self.runtime,
                  let coordinator = self.coordinator,
                  let bindingObserver = self.signingBindingObserver else {
                replyBox.call(nil, NativeAgentSessionDenialReason.unavailable.nsError)
                return
            }
            do {
                try self.authorizeConnection()
                let transactionRequest = try NativeSigningTransactionRequest(request)
                if let prior = try runtime.signingTransactions.lookup(request: transactionRequest) {
                    do {
                        switch prior.phase {
                        case .completed:
                            guard let priorAuthority = prior.authority,
                                  let remaining = prior.remainingSignatures else { throw NativeSigningTransactionError.invalidState }
                            _ = try coordinator.status(sessionID: request.sessionID)
                            let observed = try bindingObserver.observeSigningAuthority(
                                request: transactionRequest,
                                agentID: priorAuthority.agentID,
                                keyLifecycleIdentity: runtime.gitCommitSigner.keyLifecycleIdentity)
                            guard observed == priorAuthority,
                                  prior.remainingSignatures != nil,
                                  let signature = prior.signature?.data(using: .utf8),
                                  try runtime.gitCommitSigner.verifyGitCommitSignature(
                                      payload: request.commitPayload,
                                      signature: signature) == true else {
                                throw NativeAgentSessionCoordinatorError.bindingDenied
                            }
                            guard let response = AgentPassAgentSignResponse(
                                    requestID: request.requestID,
                                    signature: signature,
                                    remainingSignatures: remaining) else {
                                throw NativeSigningTransactionError.invalidState
                            }
                            replyBox.call(response, nil)
                        case .signedVerified:
                            guard let priorAuthority = prior.authority else { throw NativeSigningTransactionError.invalidState }
                            _ = try coordinator.status(sessionID: request.sessionID)
                            let observed = try bindingObserver.observeSigningAuthority(
                                request: transactionRequest,
                                agentID: priorAuthority.agentID,
                                keyLifecycleIdentity: runtime.gitCommitSigner.keyLifecycleIdentity)
                            guard observed == priorAuthority else { throw NativeAgentSessionCoordinatorError.bindingDenied }
                            guard let priorSignature = prior.signature?.data(using: .utf8),
                                  try runtime.gitCommitSigner.verifyGitCommitSignature(
                                      payload: request.commitPayload,
                                      signature: priorSignature) == true else {
                                throw NativeSigningTransactionError.invalidState
                            }
                            let (reservation, _) = try coordinator.recoverSigningReservation(
                                request,
                                budgetSequence: prior.budgetSequence)
                            let finalized = try coordinator.finalizeSigning(reservation)
                            let completed = try runtime.signingTransactions.complete(
                                requestID: transactionRequest.requestID,
                                remainingSignatures: finalized.remainingSignatures)
                            guard let signature = completed.signature?.data(using: .utf8),
                                  let response = AgentPassAgentSignResponse(
                                    requestID: request.requestID,
                                    signature: signature,
                                    remainingSignatures: finalized.remainingSignatures) else {
                                throw NativeSigningTransactionError.invalidState
                            }
                            replyBox.call(response, nil)
                        case .providerStarted:
                            throw NativeSigningTransactionError.uncertain
                        case .uncertain:
                            throw NativeSigningTransactionError.uncertain
                        case .admitted, .intent:
                            throw NativeSigningTransactionError.phaseConflict
                        }
                    } catch {
                        if prior.phase == .signedVerified {
                            do { _ = try runtime.signingTransactions.markUncertain(requestID: transactionRequest.requestID) }
                            catch { throw NativeSigningTransactionError.invalidState }
                        }
                        throw error
                    }
                    return
                }

                let now = try clocks.wallClock.sample().millisecondsSinceUnixEpoch
                let (requestAge, ageOverflow) = now.subtractingReportingOverflow(
                    request.createdAtMilliseconds)
                guard !ageOverflow, (-60_000...60_000).contains(requestAge) else {
                    throw NativeAgentSessionCoordinatorError.sessionDenied
                }

                let handoff = try coordinator.makeSigningHandoff(
                    request: request,
                    authorityProvider: { binding in
                        try bindingObserver.consumeSigningCapability(
                            request: request,
                            agentID: binding.agentID,
                            verifier: runtime.capabilityVerifier,
                            nowMilliseconds: now
                        )
                        return try bindingObserver.observeSigningAuthority(
                            request: transactionRequest,
                            agentID: binding.agentID,
                            keyLifecycleIdentity: runtime.gitCommitSigner.keyLifecycleIdentity)
                    })
                let adapter = try NativeAgentSessionCoordinatorSigningAdapter(
                    handoff: handoff,
                    coordinator: coordinator,
                    transactionStore: runtime.signingTransactions)
                let completed = try adapter.execute { payload in
                    let signature = try runtime.gitCommitSigner.signGitCommitPayload(payload)
                    guard try runtime.gitCommitSigner.verifyGitCommitSignature(
                        payload: payload,
                        signature: signature) else {
                        throw NativeAgentGitCommitSignerError.invalidSignature
                    }
                    return signature
                }
                guard let responseSignature = completed.signature?.data(using: .utf8),
                      let response = AgentPassAgentSignResponse(
                        requestID: request.requestID,
                        signature: responseSignature,
                        remainingSignatures: completed.remainingSignatures ?? 0) else {
                    throw NativeSigningTransactionError.invalidState
                }
                replyBox.call(response, nil)
            } catch {
                replyBox.call(nil, Self.denial(for: error).nsError)
            }
        }
    }

    func closeAgentSession(_ request: AgentPassAgentCloseSessionRequest, withReply reply: @escaping (AgentPassAgentCloseSessionResponse?, NSError?) -> Void) {
        let sessionID = request.sessionID
        let reason = AgentPassAgentSessionCloseReason(rawValue: request.reason)
        let replyBox = AgentXPCReplyBox(reply)
        worker.async { [weak self] in
            guard let self, let coordinator = self.coordinator, let reason else {
                replyBox.call(nil, NativeAgentSessionDenialReason.unavailable.nsError)
                return
            }
            do {
                try self.authorizeConnection()
                let status = try coordinator.close(sessionID: sessionID, reason: reason)
                let closedAt = try self.clocks.wallClock.sample().millisecondsSinceUnixEpoch
                guard let response = AgentPassAgentCloseSessionResponse(
                    sessionID: status.sessionID,
                    closedAtMilliseconds: closedAt
                ) else {
                    replyBox.call(nil, NativeAgentSessionDenialReason.internalFailure.nsError)
                    return
                }
                replyBox.call(response, nil)
            } catch {
                replyBox.call(nil, Self.denial(for: error).nsError)
            }
        }
    }

    func invalidateConnection() {
        coordinator?.invalidateConnection()
        bootstrapStore.invalidate()
    }

    private static func denial(for error: Error) -> NativeAgentSessionDenialReason {
        if let error = error as? NativeSigningTransactionError {
            switch error {
            case .invalidPath, .invalidRequest: return .malformedRequest
            case .invalidAuthority, .authorityConflict: return .controlDenied
            case .requestConflict: return .replayDetected
            case .capacityExceeded: return .budgetExceeded
            case .uncertain, .phaseConflict: return .signingOutcomeUnknown
            case .invalidState: return .internalFailure
            }
        }
        if let error = error as? NativeAgentGitCommitSignerError {
            switch error {
            case .invalidPayload: return .malformedRequest
            case .invalidSigner: return .keyUnavailable
            case .signingFailed, .invalidSignature: return .internalFailure
            }
        }
        guard let error = error as? NativeAgentSessionCoordinatorError else {
            return .internalFailure
        }
        switch error {
        case .invalidInput: return .malformedRequest
        case .connectionDenied: return .peerDenied
        case .challengeDenied: return .challengeDenied
        case .bindingDenied: return .worktreeDenied
        case .grantDenied: return .grantDenied
        case .leaseDenied, .activationDenied: return .leaseUnavailable
        case .sessionDenied, .invalidated: return .revoked
        case .invalidConfiguration: return .unavailable
        case .auditUnavailable: return .internalFailure
        }
    }
}

private final class AgentListenerDelegate: NSObject, NSXPCListenerDelegate {
    private let configuration: ServiceConfiguration
    private let runtime: AgentRuntimeDependencies?
    private let auditAppender: any NativeAgentSessionAuditAppending
    private let qualificationFaultConsumer: any NativeAgentSessionQualificationFaultConsuming
    private let transportReplyFaultConsumer: any NativeAgentSessionTransportReplyFaultConsuming
    private let auditTokenSource: any NativeAgentAuthenticatedHostAuditTokenSource
    private let observer = NativeDarwinProcessObservationSource()
    private let sessionAssociationRegistry: NativeAgentCoordinatorSessionAssociationRegistry

    init(
        configuration: ServiceConfiguration,
        runtime: AgentRuntimeDependencies?,
        auditAppender: any NativeAgentSessionAuditAppending,
        qualificationFaultConsumer: any NativeAgentSessionQualificationFaultConsuming,
        transportReplyFaultConsumer: any NativeAgentSessionTransportReplyFaultConsuming,
        auditTokenSource: any NativeAgentAuthenticatedHostAuditTokenSource = NativeAgentAuthenticatedHostUnavailableAuditTokenSource(),
        sessionAssociationRegistry: NativeAgentCoordinatorSessionAssociationRegistry
    ) {
        self.configuration = configuration
        self.runtime = runtime
        self.auditAppender = auditAppender
        self.qualificationFaultConsumer = qualificationFaultConsumer
        self.transportReplyFaultConsumer = transportReplyFaultConsumer
        self.auditTokenSource = auditTokenSource
        self.sessionAssociationRegistry = sessionAssociationRegistry
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        let initialToken: NativeAgentAuthenticatedHostCompleteAuditToken
        do {
            initialToken = try auditTokenSource.completeAuditToken(for: connection)
        } catch {
            return false
        }
        guard initialToken.effectiveUserID == configuration.allowedClientUID else { return false }
        connection.setCodeSigningRequirement(configuration.agentClientCodeSigningRequirement)
        do {
            let observation = try observer.observe(pid: initialToken.pid, expectedUserID: initialToken.effectiveUserID)
            let context = try initialToken.context(matching: observation)
            let guardValue = try NativeAgentConnectionGuard(context: context, observation: observation)
            connection.exportedInterface = AgentPassAgentXPCInterface.make()
            let endpoint = AgentConnectionEndpoint(
                connection: connection,
                connectionGuard: guardValue,
                observer: observer,
                auditTokenSource: auditTokenSource,
                runtime: runtime,
                auditAppender: auditAppender,
                qualificationFaultConsumer: qualificationFaultConsumer,
                transportReplyFaultConsumer: transportReplyFaultConsumer,
                sessionAssociationRegistry: sessionAssociationRegistry
            )
            connection.exportedObject = endpoint
            connection.invalidationHandler = { [weak endpoint] in
                endpoint?.invalidateConnection()
            }
            connection.resume()
            return true
        } catch {
            return false
        }
    }
}


private final class QualificationListenerDelegate: NSObject, NSXPCListenerDelegate {
    private let designatedRequirement: String
    private let endpoint: NativeAgentQualificationEndpoint
    private let lock = NSLock()
    private var hasConnection = false

    init(
        designatedRequirement: String,
        endpoint: NativeAgentQualificationEndpoint
    ) {
        self.designatedRequirement = designatedRequirement
        self.endpoint = endpoint
    }

    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection connection: NSXPCConnection
    ) -> Bool {
        guard connection.processIdentifier > 0,
              connection.effectiveUserIdentifier == 0,
              lock.withLock({
                  guard !hasConnection else { return false }
                  hasConnection = true
                  return true
              }) else { return false }
        connection.setCodeSigningRequirement(designatedRequirement)
        connection.exportedInterface = AgentPassQualificationXPCInterface.make()
        connection.exportedObject = endpoint
        connection.invalidationHandler = { [weak self] in
            guard let self else { return }
            self.endpoint.invalidate()
            self.lock.withLock { self.hasConnection = false }
        }
        connection.resume()
        return true
    }
}

private final class QualificationRuntime {
    let controller: NativeAgentQualificationFaultController
    let faultConsumer: any NativeAgentSessionQualificationFaultConsuming
    let auditDurabilityFaultConsumer: any NativeAuditDurabilityQualificationFaultConsuming
    let transportReplyFaultConsumer: any NativeAgentSessionTransportReplyFaultConsuming
    let endpoint: NativeAgentQualificationEndpoint
    let durableReceiptStore: NativeAgentQualificationDurableReceiptStore
    private let listener: NSXPCListener
    private let delegate: QualificationListenerDelegate

    init(values: NativeAgentQualificationConfiguration.Values) throws {
        let controller = NativeAgentQualificationFaultController(enabled: true)
        self.controller = controller
        let durableReceiptStore = try NativeAgentQualificationDurableReceiptStore()
        self.durableReceiptStore = durableReceiptStore
        faultConsumer = try NativeAgentSessionQualificationFaultConsumerAdapter(
            controller: controller,
            values: values,
            durableReceiptStore: durableReceiptStore
        )
        auditDurabilityFaultConsumer = try NativeAgentAuditDurabilityQualificationFaultConsumerAdapter(
            controller: controller,
            values: values,
            durableReceiptStore: durableReceiptStore
        )
        transportReplyFaultConsumer = try NativeAgentTransportReplyQualificationFaultConsumerAdapter(
            controller: controller,
            values: values,
            durableReceiptStore: durableReceiptStore
        )
        endpoint = try NativeAgentQualificationEndpoint(controller: controller, values: values)
        listener = NSXPCListener(machServiceName: values.machServiceName)
        delegate = QualificationListenerDelegate(
            designatedRequirement: values.controllerDesignatedRequirement,
            endpoint: endpoint
        )
        listener.delegate = delegate
    }

    func resume() {
        listener.resume()
    }

    deinit {
        endpoint.shutdown()
    }
}

private func bootstrapInput(expectedKeys: Set<String>) throws -> [String: Any] {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    let payload = data.last == 0x0a ? Data(data.dropLast()) : data
    guard let object = try? NativeStrictJSON.object(from: payload, maxBytes: 64 * 1024, maxDepth: 8),
          Set(object.keys) == expectedKeys,
          (try? NativeStrictJSON.data(object)) == payload else {
        throw AgentPassNativeError.invalidConfiguration("Native bootstrap input is not the exact expected schema")
    }
    return object
}

private func bootstrapData(_ object: [String: Any], key: String) throws -> Data {
    guard let value = object[key] as? String,
          value.count <= 32 * 1024,
          let data = Data(base64Encoded: value), data.base64EncodedString() == value else {
        throw AgentPassNativeError.invalidConfiguration("Native bootstrap \(key) is not canonical base64")
    }
    return data
}

private func emitBootstrap(_ plan: NativeBootstrapPlan, headHash: String) throws -> Never {
    let object: [String: Any] = [
        "version": 1,
        "role": plan.role.rawValue,
        "generation": plan.generation,
        "application_tag": plan.applicationTag,
        "fingerprint": plan.fingerprint,
        "statement_base64": try plan.statement.canonicalData().base64EncodedString(),
        "lifecycle_head_hash": headHash,
        "configuration_pin_update_required": true
    ]
    let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    FileHandle.standardOutput.write(data + Data("\n".utf8))
    exit(0)
}

private func emitBootstrapSnapshot(_ snapshot: NativeKeyLifecycleSnapshot) throws -> Never {
    let complete = NativeKeyRole.allCases.allSatisfy { snapshot.active(for: $0) != nil }
    var roles: [String: String] = [:]
    var fingerprints: [String: Any] = [:]
    for role in NativeKeyRole.allCases {
        let generation = snapshot.generation(1, for: role)
        roles[role.rawValue] = generation?.status.rawValue ?? "absent"
        fingerprints[role.rawValue] = generation?.fingerprint ?? NSNull()
    }
    let object: [String: Any] = [
        "version": 1,
        "sequence": snapshot.sequence,
        "lifecycle_head_hash": snapshot.headHash,
        "fingerprints": fingerprints,
        "roles": roles,
        "bootstrap_complete": complete,
        "configuration_pin_update_required": true
    ]
    let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    FileHandle.standardOutput.write(data + Data("\n".utf8))
    exit(0)
}

private func emitOfflineObject(_ object: [String: Any]) throws -> Never {
    let data = try NativeStrictJSON.data(object)
    FileHandle.standardOutput.write(data + Data("\n".utf8))
    exit(0)
}

private let qualificationSnapshotKeys: Set<String> = [
    "access_group",
    "application_tag",
    "key_class",
    "key_size_bits",
    "keychain_match_count",
    "private_exportable",
    "public_key_fingerprint",
    "secure_enclave",
    "sign_supported",
    "status",
    "token_id",
    "version"
]

private func emitQualificationSnapshot<T: Encodable>(_ snapshot: T) throws -> Never {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let encoded = try encoder.encode(snapshot)
    let object = try NativeStrictJSON.object(from: encoded, maxBytes: 64 * 1024, maxDepth: 4)

    // The snapshot is intentionally an allowlisted public binding. Rejecting
    // every extra field prevents private key material or provider-specific
    // Keychain attributes from crossing this process boundary if the snapshot
    // schema is ever extended.
    guard Set(object.keys) == qualificationSnapshotKeys else {
        throw AgentPassNativeError.invalidKey("Secure Enclave qualification snapshot contains an unsupported field")
    }
    let canonical = try NativeStrictJSON.data(object)
    guard canonical == encoded else {
        throw AgentPassNativeError.invalidKey("Secure Enclave qualification snapshot is not canonical JSON")
    }
    FileHandle.standardOutput.write(canonical + Data("\n".utf8))
    exit(0)
}

private func boundedDeviceProofInput() throws -> Data {
    var result = Data()
    while true {
        let remaining = NativeEnrollmentProof.maximumPreimageBytes - result.count
        let chunk = try FileHandle.standardInput.read(upToCount: min(4096, remaining + 1)) ?? Data()
        if chunk.isEmpty { return try NativeEnrollmentProof.validatedPreimage(result) }
        result.append(chunk)
        if result.count > NativeEnrollmentProof.maximumPreimageBytes {
            throw AgentPassNativeError.invalidSignature("Enrollment proof preimage exceeds the bounded stdin limit")
        }
    }
}

private func runOfflineDeviceAuthentication(action: String, configPath: String) throws -> Never {
    guard geteuid() == 0 else {
        throw AgentPassNativeError.invalidConfiguration("Offline device authentication must run as root")
    }
    let configuration = try ServiceConfiguration.load(path: configPath)
    guard let accessGroup = configuration.keychainAccessGroup, !accessGroup.isEmpty else {
        throw AgentPassNativeError.invalidConfiguration("Device authentication requires the service keychain access group")
    }
    switch action {
    case "key":
        let primitive = NativeEnrollmentKeyPrimitive(store: SecureEnclaveNativeEnrollmentKeyStore(accessGroup: accessGroup))
        let material = try primitive.loadOrCreate()
        try emitOfflineObject(["fingerprint": material.fingerprint, "public_key_pem": material.publicKeyPEM])
    case "sign":
        let primitive = NativeEnrollmentKeyPrimitive(store: SecureEnclaveNativeEnrollmentKeyStore(accessGroup: accessGroup))
        let signature = try primitive.signEnrollmentProof(preimage: boundedDeviceProofInput())
        try emitOfflineObject(["signature_base64": signature.base64EncodedString()])
    case "qualify":
        let snapshot = try SecureEnclaveNativeEnrollmentKeyStore(accessGroup: accessGroup).qualificationSnapshot()
        try emitQualificationSnapshot(snapshot)
    default:
        throw AgentPassNativeError.invalidConfiguration("Unknown offline device-auth action")
    }
}

private func runOfflineControlProvisioning(configPath: String) throws -> Never {
    guard geteuid() == 0 else {
        throw AgentPassNativeError.invalidConfiguration("Offline control provisioning must run as root")
    }
    let input = FileHandle.standardInput.readDataToEndOfFile()
    let result = try NativeControlProvisioning().provision(canonicalInput: input, at: configPath)
    try emitOfflineObject([
        "changed": result.changed,
        "new_fingerprint": result.newFingerprint,
        "old_fingerprint": result.oldFingerprint ?? NSNull()
    ])
}

private func runOfflineBootstrap(action: String, configPath: String) throws -> Never {
    guard geteuid() == 0 else {
        throw AgentPassNativeError.invalidConfiguration("Offline native bootstrap must run as root")
    }
    let configuration = try ServiceConfiguration.load(path: configPath)
    guard let lifecycleDirectory = configuration.keyLifecycleDirectory,
          let approvalTag = configuration.sessionApprovalKeyTag else {
        throw AgentPassNativeError.invalidConfiguration("Offline bootstrap requires lifecycle directory, external head pin, and approval tag")
    }
    try validateProtectedDirectoryPath(path: lifecycleDirectory, label: "Native key lifecycle directory")
    if let pinDirectory = configuration.keyLifecyclePinDirectory {
        try validateProtectedDirectoryPath(path: pinDirectory, label: "Native key lifecycle pin directory")
    }
    if let outboxDirectory = configuration.keyLifecycleMutationOutboxDirectory {
        try validateProtectedDirectoryPath(path: outboxDirectory, label: "Native key lifecycle mutation outbox directory")
    }
    let recoveryKeys = try (configuration.recoveryPublicKeys ?? []).map(ed25519RecoveryPublicKey)
    let pin = try configuration.keyLifecyclePinDirectory.map { try NativeLifecyclePinTransaction(rootPath: $0) }
    let store = try NativeKeyLifecycleStore(directory: lifecycleDirectory, recoveryPublicKeys: recoveryKeys, recoveryThreshold: configuration.recoveryThreshold, expectedHeadHash: pin == nil ? configuration.keyLifecycleExpectedHeadHash : nil)
    let observed = try store.verify()
    if let pin {
        if let pending = try pin.pending() {
            _ = try pin.recover(pending, observedOldLifecycleHead: pending.oldLifecycleHead, observedCurrentLifecycleHead: observed.headHash)
        }
        if let durable = try pin.current() {
            guard durable.newLifecycleHead == observed.headHash else { throw AgentPassNativeError.invalidSignature("Bootstrap ledger does not match its durable pin") }
        } else if observed.headHash != NativeKeyLifecycleStore.zeroHash {
            throw AgentPassNativeError.invalidSignature("Non-empty bootstrap ledger has no durable external pin")
        }
    }
    let coordinator = try NativeBootstrapCoordinator(
        store: store,
        serviceKeys: SecureEnclaveLifecycleKeyProvider(accessGroup: configuration.keychainAccessGroup),
        baseTags: [.gitSigning: configuration.keyTag, .auditCheckpoint: configuration.auditKeyTag, .sessionApproval: approvalTag],
        pinTransaction: pin
    )

    switch action {
    case "prepare-approval":
        let input = try bootstrapInput(expectedKeys: ["public_key_base64", "version"])
        guard input["version"] as? Int == 1 else { throw AgentPassNativeError.invalidConfiguration("Native bootstrap version is invalid") }
        let plan = try coordinator.prepareApproval(publicKeyX963: bootstrapData(input, key: "public_key_base64"))
        try emitBootstrap(plan, headHash: try store.verify().headHash)
    case "commit-approval":
        let input = try bootstrapInput(expectedKeys: ["signature_base64", "statement_base64", "version"])
        guard input["version"] as? Int == 1 else { throw AgentPassNativeError.invalidConfiguration("Native bootstrap version is invalid") }
        let statement = try NativeKeyTransitionStatement.decodeCanonical(bootstrapData(input, key: "statement_base64"))
        let state = try store.verify()
        guard let staged = state.generation(statement.newGeneration, for: .sessionApproval) else { throw AgentPassNativeError.invalidConfiguration("Bootstrap approval generation is not staged") }
        let plan = NativeBootstrapPlan(role: .sessionApproval, generation: staged.generation, applicationTag: staged.applicationTag, fingerprint: staged.fingerprint, statement: statement)
        try emitBootstrapSnapshot(try coordinator.commitApproval(plan: plan, signature: bootstrapData(input, key: "signature_base64")))
    case "prepare-service":
        let input = try bootstrapInput(expectedKeys: ["role", "version"])
        guard input["version"] as? Int == 1, let rawRole = input["role"] as? String,
              let role = NativeKeyRole(rawValue: rawRole), role != .sessionApproval else {
            throw AgentPassNativeError.invalidConfiguration("Native bootstrap service role is invalid")
        }
        let plan = try coordinator.prepareServiceRole(role)
        try emitBootstrap(plan, headHash: try store.verify().headHash)
    case "commit-service":
        let input = try bootstrapInput(expectedKeys: ["approval_public_key_base64", "approval_signature_base64", "statement_base64", "version"])
        guard input["version"] as? Int == 1 else { throw AgentPassNativeError.invalidConfiguration("Native bootstrap version is invalid") }
        let statement = try NativeKeyTransitionStatement.decodeCanonical(bootstrapData(input, key: "statement_base64"))
        let state = try store.verify()
        guard statement.role != .sessionApproval, let staged = state.generation(statement.newGeneration, for: statement.role) else {
            throw AgentPassNativeError.invalidConfiguration("Bootstrap service generation is not staged")
        }
        let plan = NativeBootstrapPlan(role: statement.role, generation: staged.generation, applicationTag: staged.applicationTag, fingerprint: staged.fingerprint, statement: statement)
        try emitBootstrapSnapshot(try coordinator.commitServiceRole(
            plan: plan,
            approvalSignature: bootstrapData(input, key: "approval_signature_base64"),
            approvalPublicKeyX963: bootstrapData(input, key: "approval_public_key_base64")
        ))
    case "status":
        try emitBootstrapSnapshot(try coordinator.bootstrapSnapshot())
    default:
        throw AgentPassNativeError.invalidConfiguration("Unknown offline bootstrap action")
    }
}

do {
    if CommandLine.arguments.count == 4,
       CommandLine.arguments[1] == "--provision-control",
       CommandLine.arguments[2] == "--config" {
        try runOfflineControlProvisioning(configPath: CommandLine.arguments[3])
    }
    if CommandLine.arguments.count == 5,
       CommandLine.arguments[1] == "--device-auth",
       CommandLine.arguments[3] == "--config" {
        try runOfflineDeviceAuthentication(action: CommandLine.arguments[2], configPath: CommandLine.arguments[4])
    }
    if CommandLine.arguments.count == 5,
       CommandLine.arguments[1] == "--bootstrap",
       CommandLine.arguments[3] == "--config" {
        try runOfflineBootstrap(action: CommandLine.arguments[2], configPath: CommandLine.arguments[4])
    }
    guard CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--config" else {
        throw AgentPassNativeError.invalidConfiguration("Usage: agentpass-native-service --config PATH | --bootstrap ACTION --config PATH | --device-auth key|sign|qualify --config PATH | --provision-control --config PATH")
    }
    let configuration = try ServiceConfiguration.load(path: CommandLine.arguments[2])
    // Fail before opening either Mach service if the compiled selectors, DTO
    // registrations, type encodings, or frozen fingerprint drifted.
    try AgentPassNativeXPCContract.verifyRuntimeSurface()
    try validateProtectedOutputPath(path: configuration.auditLogPath, label: "Native audit log")
    let signingTransactionPath = configuration.auditLogPath + ".signing-transactions.json"
    try validateProtectedOutputPath(path: signingTransactionPath, label: "Native signing transaction state")
    if let archiveDirectory = configuration.auditArchiveDirectory {
        try validateProtectedDirectoryPath(path: archiveDirectory, label: "Native audit archive directory")
    }
    if let lifecycleDirectory = configuration.keyLifecycleDirectory {
        try validateProtectedDirectoryPath(path: lifecycleDirectory, label: "Native key lifecycle directory")
    }
    if let pinDirectory = configuration.keyLifecyclePinDirectory {
        try validateProtectedDirectoryPath(path: pinDirectory, label: "Native key lifecycle pin directory")
    }
    if let outboxDirectory = configuration.keyLifecycleMutationOutboxDirectory {
        try validateProtectedDirectoryPath(path: outboxDirectory, label: "Native key lifecycle mutation outbox directory")
    }
    try validateProtectedOutputPath(path: configuration.auditCheckpointPath, label: "Native audit checkpoint log")
    if let archiveDirectory = configuration.auditCheckpointArchiveDirectory {
        try validateProtectedDirectoryPath(path: archiveDirectory, label: "Native audit checkpoint archive directory")
    }
    if let controlStatePath = configuration.controlStatePath {
        try validateProtectedOutputPath(path: controlStatePath, label: "Native control state")
    }
    for (path, label) in [
        (configuration.controlV2StatePath, "Native ControlBundle v2 state"),
        (configuration.controlV2CapabilityStatePath, "Native capability replay state"),
        (configuration.controlV2RequestEvidencePath, "Native request evidence state"),
        (configuration.controlV2RefreshStatePath, "Native device refresh state")
    ] {
        if let path { try validateProtectedOutputPath(path: path, label: label) }
    }
    if let bundleStorePath = configuration.controlV2BundleStorePath {
        try validateProtectedDirectoryPath(path: bundleStorePath, label: "Native ControlBundle store")
    }
    if let receiptPath = configuration.auditAnchorReceiptPath {
        try validateProtectedOutputPath(path: receiptPath, label: "Native audit anchor receipt log")
    }
    if let archiveDirectory = configuration.auditAnchorReceiptArchiveDirectory {
        try validateProtectedDirectoryPath(path: archiveDirectory, label: "Native audit anchor receipt archive directory")
    }
    if let transitionPath = configuration.auditKeyTransitionPath {
        try validateProtectedOutputPath(path: transitionPath, label: "Native audit key transition log")
    }
    if let planDirectory = configuration.auditKeyRotationPlanDirectory {
        try validateProtectedDirectoryPath(path: planDirectory, label: "Native audit key rotation plan journal")
    }
    if let planDirectory = configuration.auditKeyRecoveryPlanDirectory {
        try validateProtectedDirectoryPath(path: planDirectory, label: "Native audit key recovery plan journal")
    }
    if let directory = configuration.auditPruneJournalDirectory {
        try validateProtectedDirectoryPath(path: directory, label: "Native audit prune journal")
    }
    if let directory = configuration.auditPruneTrustDirectory {
        try validateProtectedDirectoryPath(path: directory, label: "Native audit prune trust state")
    }
    if let path = configuration.auditPruneEvidenceBundlePath {
        try validateProtectedOutputPath(path: path, label: "Native audit prune evidence bundle")
    }
    if let evidencePath = configuration.auditKeyDeletionEvidenceBundlePath {
        _ = try loadProtectedFile(path: evidencePath, label: "Native audit-key deletion evidence bundle")
    }
    if let archiveDirectory = configuration.auditKeyDeletionArchiveDirectory {
        try validateProtectedDirectoryPath(path: archiveDirectory, label: "Native audit-key deletion archive directory")
    }
    let policyData = try loadProtectedFile(path: configuration.policyPath, label: "Native policy")
    let recoveryPolicyData = try configuration.recoveryPolicyPath.map { try loadProtectedFile(path: $0, label: "Native recovery policy") }
    let auditKeyRecoveryPolicy = try recoveryPolicyData.map {
        try NativeAuditKeyRecoveryPolicy.convertingAuthoritiesPolicy($0).anchorPolicy
    }
    let recoveryKeys = try (configuration.recoveryPublicKeys ?? []).map(ed25519RecoveryPublicKey)
    let lifecyclePin = try configuration.keyLifecyclePinDirectory.map { try NativeLifecyclePinTransaction(rootPath: $0) }
    let lifecycleMutationOutbox = try configuration.keyLifecycleMutationOutboxDirectory.map { try NativeLifecycleMutationOutbox(rootPath: $0) }
    let keyLifecycle = try configuration.keyLifecycleDirectory.map {
        try NativeKeyLifecycleStore(directory: $0, recoveryPublicKeys: recoveryKeys, recoveryThreshold: configuration.recoveryThreshold, expectedHeadHash: lifecyclePin == nil ? configuration.keyLifecycleExpectedHeadHash : nil)
    }
    if lifecycleMutationOutbox == nil, let lifecyclePin, let observedLifecycle = try keyLifecycle?.verify() {
        if let pending = try lifecyclePin.pending() {
            _ = try lifecyclePin.recover(pending, observedOldLifecycleHead: pending.oldLifecycleHead, observedCurrentLifecycleHead: observedLifecycle.headHash)
        }
    }
    let deletionProofVerifierBox = ServiceLifecycleDeletionProofVerifierBox()
    let keyCoordinator = try keyLifecycle.map {
        try NativeKeyLifecycleCoordinator(store: $0, provider: SecureEnclaveLifecycleKeyProvider(accessGroup: configuration.keychainAccessGroup), baseTags: [.gitSigning: configuration.keyTag, .auditCheckpoint: configuration.auditKeyTag, .sessionApproval: configuration.sessionApprovalKeyTag!], deletionProofVerifier: deletionProofVerifierBox, pinTransaction: lifecyclePin, mutationOutbox: lifecycleMutationOutbox)
    }
    let observedLifecycle = try keyLifecycle?.verify()
    if let lifecyclePin, let observedLifecycle {
        guard let durable = try lifecyclePin.current(), durable.newLifecycleHead == observedLifecycle.headHash else {
            throw AgentPassNativeError.invalidSignature("Lifecycle ledger does not match the durable external pin transaction history")
        }
        if let staticHead = configuration.keyLifecycleExpectedHeadHash, staticHead != durable.newLifecycleHead {
            throw AgentPassNativeError.invalidSignature("Static lifecycle pin disagrees with the durable pin transaction history")
        }
    }
    let lifecycleSnapshot = try keyLifecycle?.verify(expectedHeadHash: lifecyclePin == nil ? configuration.keyLifecycleExpectedHeadHash : lifecyclePin?.current()?.newLifecycleHead)
    let activeSigning = lifecycleSnapshot?.active(for: .gitSigning)
    let activeAudit = lifecycleSnapshot?.active(for: .auditCheckpoint)
    let activeApproval = lifecycleSnapshot?.active(for: .sessionApproval)
    if lifecycleSnapshot != nil, activeSigning == nil || activeAudit == nil || activeApproval == nil {
        throw AgentPassNativeError.invalidConfiguration("Native key lifecycle must contain active signing, audit, and approval generations")
    }
    let approvalPublicKey = try activeApproval.map { try SSHSIG.authorizedKey(publicKeyX963: $0.publicKeyX963) } ?? configuration.sessionApprovalPublicKey
    let sessionManager = try approvalPublicKey.map { try NativeSessionManager(policyData: policyData, approvalPublicKey: $0) }
    let controlManager = try configuration.controlStatePath.map { try NativeControlManager(policyData: policyData, statePath: $0) }
    let controlV2Manager: NativeControlBundleV2Manager?
    let capabilityVerifier: NativeCapabilityVerifier?
    let requestEvidenceStore: NativeRequestEvidenceStore?
    if let statePath = configuration.controlV2StatePath,
       let capabilityStatePath = configuration.controlV2CapabilityStatePath,
       let requestEvidencePath = configuration.controlV2RequestEvidencePath,
       let publicKey = configuration.controlV2PublicKey,
       let issuer = configuration.controlV2Issuer,
       let keyID = configuration.controlV2KeyID,
       let organizationID = configuration.controlV2OrganizationID,
       let deviceID = configuration.controlV2DeviceID {
        let audience = NativeControlBundleV2Audience(organizationID: organizationID, deviceID: deviceID)
        let trust = try NativeControlBundleV2Trust(publicKeyPEM: publicKey, issuer: issuer, keyID: keyID, audience: audience)
        controlV2Manager = try NativeControlBundleV2Manager(trust: trust, statePath: statePath)
        capabilityVerifier = try NativeCapabilityVerifier(
            trust: NativeCapabilityTrust(publicKeyPEM: publicKey, issuer: issuer, keyID: keyID),
            statePath: capabilityStatePath
        )
        requestEvidenceStore = try NativeRequestEvidenceStore(path: requestEvidencePath)
    } else {
        controlV2Manager = nil
        capabilityVerifier = nil
        requestEvidenceStore = nil
    }
    let keyStore = try activeSigning.map { try SecureEnclaveKeyStore.loadExisting(applicationTag: $0.applicationTag, accessGroup: configuration.keychainAccessGroup) }
        ?? SecureEnclaveKeyStore(applicationTag: configuration.keyTag, accessGroup: configuration.keychainAccessGroup)
    if let activeSigning, keyStore.publicKeyX963 != activeSigning.publicKeyX963 { throw AgentPassNativeError.invalidKey("Active signing key does not match the lifecycle ledger") }
    let auditSigner = try activeAudit.map { try SecureEnclaveKeyStore.loadExisting(applicationTag: $0.applicationTag, accessGroup: configuration.keychainAccessGroup) }
        ?? SecureEnclaveKeyStore(applicationTag: configuration.auditKeyTag, accessGroup: configuration.keychainAccessGroup)
    if let activeAudit, auditSigner.publicKeyX963 != activeAudit.publicKeyX963 { throw AgentPassNativeError.invalidKey("Active audit key does not match the lifecycle ledger") }
    let qualificationRuntime: QualificationRuntime?
    let qualificationFaultConsumer: any NativeAgentSessionQualificationFaultConsuming
    let auditDurabilityFaultConsumer: any NativeAuditDurabilityQualificationFaultConsuming
    let transportReplyFaultConsumer: any NativeAgentSessionTransportReplyFaultConsuming
    switch try configuration.qualificationConfiguration().state {
    case .disabled:
        qualificationRuntime = nil
        qualificationFaultConsumer = NativeAgentSessionQualificationNoopFaultConsumer()
        auditDurabilityFaultConsumer = NativeAuditDurabilityQualificationNoopFaultConsumer()
        transportReplyFaultConsumer = NativeAgentSessionTransportReplyNoopFaultConsumer()
    case .configured(let values):
        let runtime = try QualificationRuntime(values: values)
        qualificationRuntime = runtime
        qualificationFaultConsumer = runtime.faultConsumer
        auditDurabilityFaultConsumer = runtime.auditDurabilityFaultConsumer
        transportReplyFaultConsumer = runtime.transportReplyFaultConsumer
    }
    let auditLog = try NativeAuditLog(
        path: configuration.auditLogPath,
        archiveDirectory: configuration.auditArchiveDirectory,
        durabilityQualificationFaultConsumer: auditDurabilityFaultConsumer
    )
    let signingTransactions = try NativeSigningTransactionStore(path: signingTransactionPath)
    let controlV2DeviceSigner = try configuration.controlV2DeviceKeyTag.map {
        try SecureEnclaveKeyStore(applicationTag: $0, accessGroup: configuration.keychainAccessGroup)
    }
    let auditGenerations = lifecycleSnapshot?.generations.filter { $0.role == .auditCheckpoint && $0.status != .staged } ?? []
    let auditVerificationKeys = auditGenerations.map(\.publicKeyX963)
    let auditVerificationGenerations = Dictionary(uniqueKeysWithValues: auditGenerations.map { ($0.fingerprint, $0.generation) })
    let auditCheckpoints = try NativeAuditCheckpoints(path: configuration.auditCheckpointPath, auditLog: auditLog, signer: auditSigner, archiveDirectory: configuration.auditCheckpointArchiveDirectory, verificationPublicKeys: auditVerificationKeys, verificationGenerations: auditVerificationGenerations, keyGeneration: activeAudit?.generation, lifecycleHeadHash: lifecycleSnapshot?.headHash, requireLifecycleBinding: lifecycleSnapshot != nil)
    let auditAnchorReceipts: NativeAuditAnchorReceipts?
    let auditAnchorClient: NativeAuditAnchorClient?
    let auditKeyRotationCoordinator: NativeAuditKeyRotationCoordinator?
    let auditKeyRecoveryCoordinator: NativeAuditKeyRecoveryCoordinator?
    let auditKeyRecoveryPlanJournal: NativeAuditKeyRecoveryPlanJournal?
    let auditKeyRecoveryApprovalJournal: NativeAuditRecoveryApprovalJournal?
    let auditKeyTransitionStore: NativeAuditKeyTransitionStore?
    let auditPruneCoordinator: NativeAuditPruneCoordinator?
    let auditPruneTrustSource: NativeAuditPruneServiceTrustSource?
    if let rawURL = configuration.auditAnchorURL, let url = URL(string: rawURL),
       let tenant = configuration.auditAnchorTenant, let publicKey = configuration.auditAnchorPublicKey,
       let receiptPath = configuration.auditAnchorReceiptPath {
        auditAnchorReceipts = try NativeAuditAnchorReceipts(path: receiptPath, tenant: tenant, anchorPublicKeyPEM: publicKey, archiveDirectory: configuration.auditAnchorReceiptArchiveDirectory)
        auditAnchorClient = try NativeAuditAnchorClient(url: url, tenant: tenant, anchorPublicKeyPEM: publicKey, auditSigner: auditSigner)
        auditKeyTransitionStore = try configuration.auditKeyTransitionPath.map { transitionPath in
            if let auditKeyRecoveryPolicy, let installationID = configuration.installationID {
                return try NativeAuditKeyTransitionStore(
                    path: transitionPath, tenant: tenant, anchorPublicKeyPEM: publicKey,
                    recoveryPolicyData: auditKeyRecoveryPolicy.canonicalData(),
                    installationID: installationID
                )
            }
            return try NativeAuditKeyTransitionStore(path: transitionPath, tenant: tenant, anchorPublicKeyPEM: publicKey)
        }
        if let transitionStore = auditKeyTransitionStore,
           let planDirectory = configuration.auditKeyRotationPlanDirectory,
           let auditAnchorClient {
            let planJournal = try NativeAuditKeyRotationPlanJournal(rootPath: planDirectory, tenant: tenant)
            auditKeyRotationCoordinator = try NativeAuditKeyRotationCoordinator(
                tenant: tenant,
                transitionStore: transitionStore,
                planJournal: planJournal,
                transport: NativeAuditKeyTransitionHTTPTransport(client: auditAnchorClient)
            )
        } else {
            auditKeyRotationCoordinator = nil
        }
        if let transitionStore = auditKeyTransitionStore,
           let planDirectory = configuration.auditKeyRecoveryPlanDirectory,
           let approvalDirectory = configuration.auditKeyRecoveryApprovalDirectory,
           let installationID = configuration.installationID,
           let auditKeyRecoveryPolicy,
           let auditAnchorClient,
           let keyLifecycle {
            let journal = try NativeAuditKeyRecoveryPlanJournal(
                rootPath: planDirectory, tenant: tenant,
                pinnedPolicy: auditKeyRecoveryPolicy, installationID: installationID
            )
            auditKeyRecoveryCoordinator = try NativeAuditKeyRecoveryCoordinator(
                tenant: tenant, installationID: installationID,
                pinnedPolicy: auditKeyRecoveryPolicy,
                transitionStore: transitionStore, planJournal: journal,
                transport: NativeAuditKeyTransitionHTTPTransport(client: auditAnchorClient),
                preparedRecordVerifier: keyLifecycle,
                lifecycleAncestryVerifier: keyLifecycle
            )
            auditKeyRecoveryPlanJournal = journal
            auditKeyRecoveryApprovalJournal = try NativeAuditRecoveryApprovalJournal(rootPath: approvalDirectory)
        } else {
            auditKeyRecoveryCoordinator = nil
            auditKeyRecoveryPlanJournal = nil
            auditKeyRecoveryApprovalJournal = nil
        }
    } else {
        auditAnchorReceipts = nil
        auditAnchorClient = nil
        auditKeyTransitionStore = nil
        auditKeyRotationCoordinator = nil
        auditKeyRecoveryCoordinator = nil
        auditKeyRecoveryPlanJournal = nil
        auditKeyRecoveryApprovalJournal = nil
    }
    if let journalDirectory = configuration.auditPruneJournalDirectory,
       let trustDirectory = configuration.auditPruneTrustDirectory,
       let archiveDirectory = configuration.auditKeyDeletionArchiveDirectory,
       let authorizerText = configuration.auditRetentionAuthorizerPublicKey,
       let minimumRetention = configuration.auditKeyDeletionMinimumRetentionSeconds,
       let tenant = configuration.auditAnchorTenant,
       let anchorPublicKey = configuration.auditAnchorPublicKey,
       let auditAnchorClient, let auditAnchorReceipts, let auditKeyTransitionStore,
       let lifecycleSnapshot {
        let authorizerKey = try SSHSIG.p256PublicKey(fromAuthorizedKey: authorizerText)
        guard authorizerKey == auditSigner.publicKeyX963 else {
            throw AgentPassNativeError.invalidConfiguration("Audit prune authorizer must be the active non-exportable audit Secure Enclave key")
        }
        let checkpoints = try auditCheckpoints.verify()
        let receipts = try auditAnchorReceipts.verifiedReceipts(checkpoints: checkpoints)
        let boundary = try verifiedAuditPruneBoundary(lifecycle: lifecycleSnapshot, checkpoints: checkpoints, receipts: receipts, transitions: auditKeyTransitionStore.status())
        let trust = try NativeAuditPruneServiceTrustSource(
            rootPath: trustDirectory, tenant: tenant, initialBoundary: boundary,
            externalReceiptObservationRequired: true
        )
        let startupObservationFetcher = NativeAuditPruneExternalObservationFetcher(provider: auditAnchorClient, trustSource: trust)
        func startupObservation(_ purpose: NativeAuditPruneExternalObservationPurpose) throws -> NativeAuditPruneExternalReceiptObservation {
            try startupObservationFetcher.fetch(purpose: purpose)
        }
        func finishStartupObservation(_ observation: NativeAuditPruneExternalReceiptObservation) throws {
            try trust.finishAuditPruneExternalReceiptObservation(observation)
            if let lease = observation.externalLease { try auditAnchorClient.releaseAuditPruneReceiptLease(lease) }
        }
        func abandonStartupObservation(_ observation: NativeAuditPruneExternalReceiptObservation) {
            trust.discardAuditPruneExternalReceiptObservation(observation)
            if let lease = observation.externalLease { try? auditAnchorClient.releaseAuditPruneReceiptLease(lease) }
        }
        let coordinator = try NativeAuditPruneCoordinator(
            tenant: tenant, archiveDirectory: archiveDirectory,
            journal: try NativeAuditPruneJournal(directory: journalDirectory, tenant: tenant),
            verifier: try NativeAuditRetentionVerifier(tenant: tenant, authorizerPublicKeyX963: authorizerKey, anchorPublicKeyPEM: anchorPublicKey, minimumRetentionSeconds: minimumRetention),
            signer: auditSigner, transport: NativeAuditKeyTransitionHTTPTransport(client: auditAnchorClient), trustSource: trust
        )
        let initialStatusObservation = try startupObservation(.status)
        let startupStatus: NativeAuditPruneJournalStatus
        do { startupStatus = try coordinator.status(observation: initialStatusObservation); try finishStartupObservation(initialStatusObservation) }
        catch { abandonStartupObservation(initialStatusObservation); throw error }
        if startupStatus.pendingPreparation == nil {
            let reconcileObservation = try startupObservation(.reconcile)
            do { _ = try coordinator.reconcile(observation: reconcileObservation); try finishStartupObservation(reconcileObservation) }
            catch { abandonStartupObservation(reconcileObservation); throw error }
        } else if startupStatus.pendingReceiptData != nil {
            let executionObservation = try startupObservation(.execute)
            do { _ = try coordinator.executePending(observation: executionObservation); try finishStartupObservation(executionObservation) }
            catch { abandonStartupObservation(executionObservation); throw error }
        }
        if let evidencePath = configuration.auditPruneEvidenceBundlePath {
            let finalStatusObservation = try startupObservation(.status)
            do {
                if let completed = try coordinator.status(observation: finalStatusObservation).completed.last {
                    try NativeAuditPruneEvidencePublisher.publish(completed.deletionEvidenceBundleData, path: evidencePath)
                }
                try finishStartupObservation(finalStatusObservation)
            } catch { abandonStartupObservation(finalStatusObservation); throw error }
        }
        auditPruneTrustSource = trust; auditPruneCoordinator = coordinator
    } else {
        auditPruneTrustSource = nil; auditPruneCoordinator = nil
    }
    if let evidencePath = configuration.auditKeyDeletionEvidenceBundlePath {
        guard let archiveDirectory = configuration.auditKeyDeletionArchiveDirectory,
              let authorizerPublicKey = configuration.auditRetentionAuthorizerPublicKey,
              let minimumRetention = configuration.auditKeyDeletionMinimumRetentionSeconds,
              let tenant = configuration.auditAnchorTenant,
              let anchorPublicKey = configuration.auditAnchorPublicKey,
              let keyLifecycle,
              let auditKeyTransitionStore,
              let auditAnchorReceipts else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key deletion proof verifier dependencies are not installed")
        }
        let provider = try ServiceAuditKeyDeletionEvidenceProvider(
            evidenceBundlePath: evidencePath,
            archiveDirectory: archiveDirectory,
            tenant: tenant,
            retentionAuthorizerPublicKeyX963: try SSHSIG.p256PublicKey(fromAuthorizedKey: authorizerPublicKey),
            anchorPublicKeyPEM: anchorPublicKey,
            minimumRetentionSeconds: minimumRetention,
            lifecycleStore: keyLifecycle,
            transitionStore: auditKeyTransitionStore,
            auditLog: auditLog,
            checkpoints: auditCheckpoints,
            anchorReceipts: auditAnchorReceipts
        )
        try provider.validate()
        try deletionProofVerifierBox.install(provider)
    }
    if let keyCoordinator, let keyLifecycle {
        let beforeRecovery = try keyLifecycle.verify()
        let afterRecovery = try keyCoordinator.recoverKeychainSideEffects()
        if afterRecovery.headHash != beforeRecovery.headHash {
            // Objects above were deliberately constructed against the pre-recovery lifecycle
            // boundary. Exit fail-closed so launchd restarts and rebuilds every dependent store
            // against the newly pinned terminal record.
            throw AgentPassNativeError.invalidConfiguration("Lifecycle key side-effect recovery completed; restart is required to bind service state to the recovered head")
        }
    }
    if let recoveryCoordinator = auditKeyRecoveryCoordinator,
       let approvalJournal = auditKeyRecoveryApprovalJournal,
       let transitionStore = auditKeyTransitionStore,
       let receiptsStore = auditAnchorReceipts,
       let keyCoordinator,
       let lifecycleSnapshot,
       let currentAudit = lifecycleSnapshot.active(for: .auditCheckpoint) {
        if try recoveryCoordinator.pendingPlan() != nil,
           try auditKeyRotationCoordinator?.pendingPlan() != nil {
            throw AgentPassNativeError.invalidSignature("Audit-key rotation and recovery journals cannot both be pending")
        }
        let recoveryJournalStatus = try auditKeyRecoveryPlanJournal?.status()
        let expiredUnsubmitted = recoveryJournalStatus?.pending != nil &&
            recoveryJournalStatus?.pendingSubmissionIntent == nil &&
            serviceDate(recoveryJournalStatus!.pending!.plan.transition.expiresAt).map { $0 <= Date() } == true
        if let pendingPlan = try recoveryCoordinator.pendingPlan(), !expiredUnsubmitted {
            guard let activeApproval = lifecycleSnapshot.active(for: .sessionApproval) else {
                throw AgentPassNativeError.invalidSignature("Pending audit recovery has no active local approval authority")
            }
            _ = try approvalJournal.require(
                operationID: pendingPlan.transition.operationID,
                statementData: try recoveryLifecycleStatement(pendingPlan).canonicalData(),
                authorizationData: try pendingPlan.transition.recoveryEvidence.authorization.canonicalData(),
                expectedSignerFingerprint: activeApproval.fingerprint
            )
            let audit = try auditLog.verify()
            let checkpoints = try auditCheckpoints.verify()
            let anchorStatus = try receiptsStore.status(checkpoints: checkpoints)
            let receipts = try receiptsStore.verifiedReceipts(checkpoints: checkpoints)
            guard lifecycleSnapshot.headHash != pendingPlan.transition.lifecycleHeadHash,
                  currentAudit.generation == pendingPlan.transition.fromGeneration,
                  currentAudit.publicKeyX963 == pendingPlan.retiringPublicKeyX963,
                  let checkpoint = checkpoints.last,
                  let receipt = receipts.last,
                  checkpoint.entries == audit.entries,
                  checkpoint.headHash == audit.headHash,
                  checkpoint.checkpointHash == pendingPlan.transition.lastCheckpointHash,
                  receipt.receiptHash == pendingPlan.transition.lastCheckpointReceiptHash,
                  receipt.checkpointHash == checkpoint.checkpointHash,
                  receipt.eventIndex == pendingPlan.transition.previousAnchorEventIndex,
                  receipt.receiptHash == pendingPlan.transition.previousAnchorEventHash,
                  anchorStatus.pending == 0 else {
                throw AgentPassNativeError.invalidSignature("Pending audit-key recovery no longer matches its frozen lifecycle and anchor boundary")
            }
            _ = try recoveryCoordinator.authorizeActivation(plan: pendingPlan)
        }
        if let payload = try recoveryCoordinator.recoverAuthorizedLifecycleRecord(
            currentLifecycleHeadHash: lifecycleSnapshot.headHash,
            currentAuditGeneration: currentAudit.generation
        ) {
            guard let activeApproval = lifecycleSnapshot.active(for: .sessionApproval),
                  let transition = try transitionStore.status().latestRecoveryTransition else {
                throw AgentPassNativeError.invalidSignature("Authorized audit recovery lacks its local approval or transition proof")
            }
            _ = try approvalJournal.require(
                operationID: transition.operationID,
                statementData: try recoveryLifecycleStatement(transition: transition, lifecycleRecordData: payload).canonicalData(),
                authorizationData: try transition.recoveryEvidence.authorization.canonicalData(),
                expectedSignerFingerprint: activeApproval.fingerprint
            )
            let recovered = try keyCoordinator.commitAuthorizedAuditActivationRecord(payload)
            throw AgentPassNativeError.invalidConfiguration("Recovered schema-v3 audit-key activation to lifecycle head \(recovered.headHash); restart the native service to load the replacement signer")
        }
    }
    if let rotationCoordinator = auditKeyRotationCoordinator,
       let receiptsStore = auditAnchorReceipts,
       let keyCoordinator,
       let lifecycleSnapshot,
       let currentAudit = lifecycleSnapshot.active(for: .auditCheckpoint) {
        if let pendingPlan = try rotationCoordinator.pendingPlan() {
            let audit = try auditLog.verify()
            let checkpoints = try auditCheckpoints.verify()
            let anchorStatus = try receiptsStore.status(checkpoints: checkpoints)
            let receipts = try receiptsStore.verifiedReceipts(checkpoints: checkpoints)
            guard let checkpoint = checkpoints.last,
                  let receipt = receipts.last,
                  checkpoint.entries == audit.entries,
                  checkpoint.headHash == audit.headHash,
                  checkpoint.checkpointHash == pendingPlan.transition.lastCheckpointHash,
                  receipt.receiptHash == pendingPlan.transition.lastCheckpointReceiptHash,
                  receipt.checkpointHash == checkpoint.checkpointHash,
                  anchorStatus.pending == 0 else {
                throw AgentPassNativeError.invalidSignature("Pending audit-key rotation no longer matches the frozen local anchor boundary")
            }
            _ = try rotationCoordinator.authorizeActivation(
                plan: pendingPlan,
                checkpointBoundary: NativeAuditKeyRotationCheckpointBoundary(anchorStatus: anchorStatus, finalReceipt: receipt)
            )
        }
        if let payload = try rotationCoordinator.recoverAuthorizedLifecycleRecord(
            currentLifecycleHeadHash: lifecycleSnapshot.headHash,
            currentAuditGeneration: currentAudit.generation
        ) {
            let recovered = try keyCoordinator.commitAuthorizedAuditActivationRecord(payload)
            throw AgentPassNativeError.invalidConfiguration("Recovered anchored audit-key activation to lifecycle head \(recovered.headHash); restart the native service to load the replacement signer")
        }
    }
    _ = try auditLog.verify()
    _ = try auditCheckpoints.verify()
    let authorizer = try NativeRequestAuthorizer(policyData: policyData, sessionValidator: sessionManager, controlValidator: controlManager, capabilityValidator: capabilityVerifier, v2ControlManager: controlV2Manager, requestEvidenceStore: requestEvidenceStore, controlV2Configured: configuration.controlV2StatePath != nil, v2DeviceID: configuration.controlV2DeviceID)
    let agentRuntime: AgentRuntimeDependencies?
    switch try configuration.agentRuntimeConfiguration() {
    case .disabled:
        agentRuntime = nil
    case .enabled(let authority):
        guard let deviceSigner = controlV2DeviceSigner,
              let controlV2Manager,
              let activeSigning else {
            throw AgentPassNativeError.invalidConfiguration("Agent runtime device and signing lifecycle authority is unavailable")
        }
        guard let capabilityVerifier else {
            throw AgentPassNativeError.invalidConfiguration("Agent runtime capability authority is unavailable")
        }
        let authorityState = try AgentRuntimeAuthorityState(
            control: controlV2Manager,
            keyGeneration: activeSigning.generation
        )
        agentRuntime = try AgentRuntimeDependencies(
            authority: authority,
            authorityState: authorityState,
            deviceSigner: deviceSigner,
            gitSigner: keyStore,
            capabilityVerifier: capabilityVerifier,
            qualificationFaultConsumer: qualificationFaultConsumer
        )
    }
    let managementListener = NSXPCListener(machServiceName: configuration.machServiceName)
    let agentListener = NSXPCListener(machServiceName: configuration.agentMachServiceName)
    let hostListener = NSXPCListener(machServiceName: configuration.hostMachServiceName)
    let childListener = NSXPCListener(machServiceName: configuration.childMachServiceName)
    let controlRefreshEvidenceStore = try configuration.controlV2RefreshStatePath.map {
        try NativeControlRefreshEvidencePOSIXStore(path: "\($0).control-ack")
    }
    let endpoint = ServiceEndpoint(keyStore: keyStore, authorizer: authorizer, auditLog: auditLog, auditCheckpoints: auditCheckpoints, auditSigner: auditSigner, auditAnchorReceipts: auditAnchorReceipts, auditAnchorClient: auditAnchorClient, auditKeyRotationCoordinator: auditKeyRotationCoordinator, auditKeyRecoveryCoordinator: auditKeyRecoveryCoordinator, auditKeyRecoveryPlanJournal: auditKeyRecoveryPlanJournal, auditKeyTransitionStore: auditKeyTransitionStore, auditKeyRecoveryPolicy: auditKeyRecoveryPolicy, auditKeyRecoveryApprovalJournal: auditKeyRecoveryApprovalJournal, auditPruneCoordinator: auditPruneCoordinator, auditPruneTrustSource: auditPruneTrustSource, auditPruneEvidenceBundlePath: configuration.auditPruneEvidenceBundlePath, auditAnchorTenant: configuration.auditAnchorTenant, keychainAccessGroup: configuration.keychainAccessGroup, recoveryPolicyData: recoveryPolicyData, installationID: configuration.installationID, sessionManager: sessionManager, controlManager: controlManager, controlV2Manager: controlV2Manager, signingTransactions: signingTransactions, keyLifecycle: keyLifecycle, keyCoordinator: keyCoordinator, loadedLifecycleHeadHash: lifecycleSnapshot?.headHash, controlRefreshEvidenceStore: controlRefreshEvidenceStore)
    if controlV2Manager != nil {
        guard let apiBaseText = configuration.controlV2APIBaseURL,
              let apiBaseURL = URL(string: apiBaseText),
              let organizationID = configuration.controlV2OrganizationID,
              let deviceID = configuration.controlV2DeviceID,
              let deviceKeyEpoch = configuration.controlV2DeviceKeyEpoch,
              let deviceSigner = controlV2DeviceSigner,
              let publicKey = configuration.controlV2PublicKey,
              let issuer = configuration.controlV2Issuer,
              let keyID = configuration.controlV2KeyID,
              let refreshEntries = configuration.controlV2RefreshHintKeyring,
              let refreshStatePath = configuration.controlV2RefreshStatePath,
              let bundleStorePath = configuration.controlV2BundleStorePath,
              let interval = configuration.controlRefreshSeconds else {
            throw AgentPassNativeError.invalidConfiguration("ControlBundle v2 device synchronization is incomplete; reprovision the native service")
        }
        let refreshKeys = Dictionary(uniqueKeysWithValues: refreshEntries.map { ($0.keyID, $0.publicKey) })
        let audience = NativeControlBundleV2Audience(organizationID: organizationID, deviceID: deviceID)
        let bundleTrust = try NativeControlBundleV2Trust(
            publicKeyPEM: publicKey,
            issuer: issuer,
            keyID: keyID,
            audience: audience
        )
        let refreshTrust = try NativeRefreshHintTrust(
            organizationID: organizationID,
            deviceID: deviceID,
            publicKeysPEM: refreshKeys
        )
        let transport = try NativeDeviceSyncHTTPTransport(
            baseURL: apiBaseURL,
            organizationID: organizationID,
            deviceID: deviceID,
            signer: deviceSigner
        )
        let deviceAuditOutboxPath = configuration.auditLogPath + ".device-audit-outbox"
        try validateProtectedOutputPath(path: deviceAuditOutboxPath, label: "Native device audit outbox")
        let deviceAuditOutbox = try NativeDeviceAuditOutbox(rootPath: deviceAuditOutboxPath)
        try endpoint.installDeviceAuditUploadCoordinator(
            NativeDeviceAuditUploadCoordinator(outbox: deviceAuditOutbox, transport: transport),
            outbox: deviceAuditOutbox
        )
        let snapshotStore = try NativeDeviceRefreshPOSIXSnapshotStore(path: refreshStatePath)
        guard let evidenceStore = controlRefreshEvidenceStore else {
            throw AgentPassNativeError.invalidConfiguration("ControlBundle v2 refresh evidence storage is unavailable; reprovision the native service")
        }
        let initialRefreshState: NativeDeviceRefreshMachineState
        if let snapshotData = try snapshotStore.load() {
            initialRefreshState = try NativeDeviceRefreshSnapshotCodec.decode(snapshotData).state
        } else {
            initialRefreshState = .idle
        }
        let coordinator = try NativeDeviceSyncCoordinator(
            organizationID: organizationID,
            deviceID: deviceID,
            deviceKeyEpoch: deviceKeyEpoch,
            transport: transport,
            hintVerifier: NativeRefreshHintVerifier(trust: refreshTrust),
            bundleTrust: bundleTrust,
            snapshotStore: snapshotStore,
            bundleStore: try NativeAtomicControlBundleStore(rootURL: URL(fileURLWithPath: bundleStorePath, isDirectory: true)),
            activator: endpoint.deviceSyncActivation(),
            acknowledgementSigner: deviceSigner,
            evidenceStore: evidenceStore
        )
        let runner = NativeDeviceSyncRunner(
            coordinator: coordinator,
            configuration: try NativeDeviceSyncRunnerConfiguration(
                intervalSeconds: interval,
                maximumBackoffSeconds: 3_600,
                pollWaitMilliseconds: 30_000,
                jitterFraction: 0.10
            )
        )
        agentRuntime?.authorityState.install(runner: runner)
        try endpoint.installDeviceSyncRunner(
            runner,
            devicePublicKeyPEM: try p256SubjectPublicKeyInfoPEM(x963: deviceSigner.publicKeyX963),
            initialState: initialRefreshState
        )
    } else if let rawURL = configuration.controlURL, let interval = configuration.controlRefreshSeconds {
        let refresh = try NativeControlRefreshConfiguration(urlString: rawURL, refreshSeconds: interval)
        try endpoint.startControlRefresh(url: refresh.url, refreshSeconds: refresh.refreshSeconds)
    }
    let auditTokenSource = NativeMacOSAuditTokenSource()
    let sessionAssociationRegistry = NativeAgentCoordinatorSessionAssociationRegistry()
    let managementDelegate = ManagementListenerDelegate(configuration: configuration, endpoint: endpoint)
    let agentDelegate = AgentListenerDelegate(
        configuration: configuration,
        runtime: agentRuntime,
        auditAppender: endpoint,
        qualificationFaultConsumer: qualificationFaultConsumer,
        transportReplyFaultConsumer: transportReplyFaultConsumer,
        auditTokenSource: auditTokenSource,
        sessionAssociationRegistry: sessionAssociationRegistry
    )
    let hostChildPolicy = try configuration.hostChildCodeDirectoryHash.map {
        try NativeProcessIdentityPolicy(
            expectedUID: configuration.allowedClientUID,
            expectedCodeDirectoryHash: $0.lowercased(),
            allowedSignatureKinds: [.developerID, .apple],
            rejectAdHocSignature: true,
            rejectUnknownAncestors: true
        )
    }
    let hostSigner = NativeAgentAuthenticatedHostClosureSigner { payload in
        guard let agentRuntime else {
            throw NativeAgentAuthenticatedHostEndpointError.signerFailed
        }
        return try agentRuntime.gitCommitSigner.signGitCommitPayload(payload.payload)
    }
    let childRegistry = NativeAgentAuthenticatedChildGitSessionRegistry()
    let worktreeObserver = NativeDarwinGitWorktreeObserver()
    let processObserver = NativeDarwinProcessObservationSource()
    let dedicatedContextProvider: NativeAgentDedicatedSigningServiceContextProvider?
    if let agentRuntime {
        dedicatedContextProvider = try NativeAgentDedicatedSigningServiceContextProvider(
            organizationID: agentRuntime.authority.organizationID,
            capabilityKeyID: agentRuntime.authority.capabilityKeyID,
            registry: sessionAssociationRegistry,
            observeState: { payload in
                guard payload.peerProcessID > 0, payload.peerProcessPIDVersion > 0 else {
                    throw NativeAgentDedicatedSigningServiceContextProviderError.observationUnavailable
                }
                let observation = try processObserver.observe(
                    pid: payload.peerProcessID,
                    expectedUserID: payload.peerEffectiveUserID
                )
                guard observation.process.pidVersion == payload.peerProcessPIDVersion else {
                    throw NativeAgentDedicatedSigningServiceContextProviderError.observationUnavailable
                }
                let identity = try NativeProcessIdentity.capture(
                    from: NativeFixedProcessObservationSource(observation: observation)
                )
                let worktree = try worktreeObserver.observe(
                    pid: payload.peerProcessID,
                    expectedUserID: payload.peerEffectiveUserID
                ).binding
                let reobserved = try processObserver.observe(
                    pid: payload.peerProcessID,
                    expectedUserID: payload.peerEffectiveUserID
                )
                let reobservedIdentity = try NativeProcessIdentity.capture(
                    from: NativeFixedProcessObservationSource(observation: reobserved)
                )
                guard reobservedIdentity.canonicalBindingHash == identity.canonicalBindingHash,
                      reobservedIdentity.canonicalAncestryBindingHash == identity.canonicalAncestryBindingHash,
                      reobservedIdentity.pidVersion == identity.pidVersion else {
                    throw NativeAgentDedicatedSigningServiceContextProviderError.observationUnavailable
                }
                func digest(_ value: String) -> Data? {
                    guard value.count == 64 else { return nil }
                    var result = Data(capacity: 32)
                    var high: UInt8?
                    for byte in value.utf8 {
                        let nibble: UInt8?
                        switch byte {
                        case 48...57: nibble = byte - 48
                        case 97...102: nibble = byte - 87
                        case 65...70: nibble = byte - 55
                        default: nibble = nil
                        }
                        guard let nibble else { return nil }
                        if let high {
                            result.append((high << 4) | nibble)
                        } else {
                            high = nibble
                        }
                    }
                    return high == nil && result.count == 32 ? result : nil
                }
                guard let processDigest = digest(identity.canonicalBindingHash),
                      let ancestryDigest = digest(identity.canonicalAncestryBindingHash),
                      let payloadDigest = digest(payload.peerProcessBindingHash),
                      processDigest == payloadDigest,
                      let association = sessionAssociationRegistry.lookup(
                          processBindingDigest: processDigest,
                          ancestryBindingDigest: ancestryDigest,
                          worktreeBindingDigest: worktree.digest) else {
                    throw NativeAgentDedicatedSigningServiceContextProviderError.associationMissing
                }
                return try NativeAgentDedicatedSigningObservedState(
                    binding: association.binding,
                    worktree: worktree
                )
            },
            sequence: { association in
                let sequenceBinding = try NativeAgentDedicatedSigningCapabilitySequenceBinding(
                    coordinatorSessionID: association.sessionID,
                    agentID: association.binding.agentID
                )
                let authority = try agentRuntime.dedicatedCapabilitySequenceAuthorities.authority(
                    for: sequenceBinding
                )
                return Int64(authority.snapshot().acceptedSequence ?? 1)
            },
            keyLifecycleIdentity: agentRuntime.gitCommitSigner.keyLifecycleIdentity
        )
    } else {
        dedicatedContextProvider = nil
    }
    let dedicatedHostSigner: (any NativeAgentAuthenticatedHostSigning)? = if let agentRuntime,
                                                                                let dedicatedContextProvider {
        NativeAgentDedicatedSigningServiceSignerAdapter(
            capabilityIssuer: agentRuntime.dedicatedSigningCapabilityIssuer,
            contextProvider: dedicatedContextProvider,
            provider: { payload in
                let signature = try agentRuntime.gitCommitSigner.signGitCommitPayload(payload)
                guard try agentRuntime.gitCommitSigner.verifyGitCommitSignature(
                    payload: payload,
                    signature: signature
                ) else {
                    throw NativeAgentGitCommitSignerError.invalidSignature
                }
                return signature
            }
        )
    } else {
        nil
    }
    let hostDelegate = NativeAgentAuthenticatedHostListenerDelegate(
        allowedClientUID: configuration.allowedClientUID,
        codeSigningRequirement: configuration.agentClientCodeSigningRequirement,
        peerPolicyFactory: { observation in
            try NativeProcessIdentityPolicy(
                expectedUID: observation.process.uid,
                expectedBootIdentity: observation.process.bootIdentity,
                expectedExecutableFileIdentity: observation.process.executableFileIdentity,
                expectedCodeDirectoryHash: observation.process.codeDirectoryHash,
                expectedBundleIdentifier: observation.process.bundleIdentifier,
                expectedTeamIdentifier: observation.process.teamIdentifier,
                expectedSignatureKind: observation.process.signatureKind,
                requiredEntitlements: observation.process.entitlements,
                expectedAncestry: observation.ancestry,
                rejectAdHocSignature: true,
                rejectUnknownAncestors: true
            )
        },
        childPolicy: hostChildPolicy,
        auditTokenSource: auditTokenSource,
        childFactory: { pid, expectedPIDVersion in
            let processObservation = try NativeDarwinProcessObservationSource().observe(pid: pid, expectedUserID: configuration.allowedClientUID)
            guard processObservation.process.pidVersion == expectedPIDVersion else {
                throw NativeAgentAuthenticatedHostEndpointError.childIdentityMismatch
            }
            let worktree = try worktreeObserver.observe(pid: pid, expectedUserID: configuration.allowedClientUID)
            return (processObservation, worktree.binding.digest)
        },
        signer: hostSigner,
        dedicatedSigner: dedicatedHostSigner,
        dedicatedChildRegistrar: { sessionID, hostIdentity, observation, signatureBudget in
            guard let hostProcessDigest = nativeDigestData(hostIdentity.canonicalBindingHash),
                  let hostAncestryDigest = nativeDigestData(hostIdentity.canonicalAncestryBindingHash),
                  let agentRuntime, let dedicatedContextProvider,
                  let association = sessionAssociationRegistry.lookup(
                      processBindingDigest: hostProcessDigest,
                      ancestryBindingDigest: hostAncestryDigest,
                      worktreeBindingDigest: observation.worktreeBindingDigest),
                  association.isActive else {
                throw NativeAgentAuthenticatedChildGitError.signerFailed
            }
            let childSigner = NativeAgentDedicatedSigningChildSigner(
                dedicatedSessionID: sessionID,
                coordinatorBinding: association.binding,
                contextProvider: dedicatedContextProvider,
                capabilityIssuer: agentRuntime.dedicatedSigningCapabilityIssuer,
                provider: { payload in
                    let signature = try agentRuntime.gitCommitSigner.signGitCommitPayload(payload)
                    guard try agentRuntime.gitCommitSigner.verifyGitCommitSignature(
                        payload: payload,
                        signature: signature
                    ) else {
                        throw NativeAgentGitCommitSignerError.invalidSignature
                    }
                    return signature
                },
                worktreeObserver: worktreeObserver
            )
            try childRegistry.register(
                sessionID: sessionID,
                identity: observation.identity,
                worktreeBindingDigest: observation.worktreeBindingDigest,
                signer: childSigner,
                signatureBudget: signatureBudget
            )
        },
        childUnregistrar: { bindingHash in
            childRegistry.unregister(identityBindingHash: bindingHash)
        }
    )
    let childDelegate = NativeAgentAuthenticatedChildGitListenerDelegate(
        allowedClientUID: configuration.allowedClientUID,
        codeSigningRequirement: try deriveDedicatedChildCodeSigningRequirement(
            configuredChildRequirement: configuration.childCodeSigningRequirement,
            hostCodeSigningRequirement: configuration.agentClientCodeSigningRequirement,
            managementCodeSigningRequirement: configuration.clientCodeSigningRequirement
        ),
        registry: childRegistry,
        worktreeObserver: worktreeObserver
    )
    managementListener.delegate = managementDelegate
    agentListener.delegate = agentDelegate
    hostListener.delegate = hostDelegate
    childListener.delegate = childDelegate
    managementListener.resume()
    agentListener.resume()
    hostListener.resume()
    childListener.resume()
    qualificationRuntime?.resume()
    RunLoop.current.run()
} catch {
    FileHandle.standardError.write(Data("agentpass-native-service: \(error.localizedDescription)\n".utf8))
    exit(1)
}
