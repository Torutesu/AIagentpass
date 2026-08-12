import CryptoKit
import Foundation

public enum NativeLegacyMigrationV017 {
    public static let approvalHelperBundleID = "dev.agentpass.legacy-approval-migration"
    public static let serviceHelperBundleID = "dev.agentpass.legacy-service-migration"
    public static let sourceAccessGroupSuffix = "dev.agentpass.keys"
    public static let approvalAccessGroupSuffix = "dev.agentpass.approval-keys"
    public static let serviceAccessGroupSuffix = "dev.agentpass.service-keys"
    public static let oldApplicationTags: [NativeKeyRole: String] = [
        .sessionApproval: "dev.agentpass.session-approval.v1",
        .gitSigning: "dev.agentpass.git-signing",
        .auditCheckpoint: "dev.agentpass.audit-checkpoint"
    ]
    public static let newApplicationTags: [NativeKeyRole: String] = [
        .sessionApproval: "dev.agentpass.session-approval.g1",
        .gitSigning: "dev.agentpass.git-signing.g1",
        .auditCheckpoint: "dev.agentpass.audit-checkpoint.g1"
    ]

    public static func helperBundleID(for role: NativeKeyRole) -> String {
        role == .sessionApproval ? approvalHelperBundleID : serviceHelperBundleID
    }
}

/// Public, code-signing identity of the one-shot migration helper. The normal service and client
/// must never instantiate this ceremony: release tooling is expected to compare these values with
/// the helper's SecCode identity before supplying them here.
public struct NativeLegacyMigrationHelperIdentity: Equatable, Sendable {
    public let bundleID: String
    public let teamID: String
    public let codeDirectoryHash: String

    public init(bundleID: String, teamID: String, codeDirectoryHash: String) {
        self.bundleID = bundleID
        self.teamID = teamID
        self.codeDirectoryHash = codeDirectoryHash
    }
}

public struct NativeLegacyMigrationRoleBinding: Equatable, Sendable {
    public let role: NativeKeyRole
    public let oldApplicationTag: String
    public let newApplicationTag: String
    public let oldPublicKeyX963: Data
    public let newPublicKeyX963: Data

    public init(role: NativeKeyRole, oldApplicationTag: String, newApplicationTag: String, oldPublicKeyX963: Data, newPublicKeyX963: Data) {
        self.role = role
        self.oldApplicationTag = oldApplicationTag
        self.newApplicationTag = newApplicationTag
        self.oldPublicKeyX963 = oldPublicKeyX963
        self.newPublicKeyX963 = newPublicKeyX963
    }
}

/// Exact phase-one document emitted by the separately signed migration helper. Only public keys
/// are represented; Secure Enclave private material is never accepted by this API.
public struct NativeLegacyMigrationPlan: Equatable, Sendable {
    public static let version = 1

    public let operationID: UUID
    public let nonce: String
    public let role: NativeKeyRole
    public let roleOrder: Int
    public let sourceAccessGroup: String
    public let targetAccessGroup: String
    public let helperIdentity: NativeLegacyMigrationHelperIdentity
    public let appVersion: String
    public let initialLifecycleHead: String
    public let previousLifecycleHead: String
    public let issuedAt: String
    public let expiresAt: String
    public let binding: NativeLegacyMigrationRoleBinding

    public init(operationID: UUID, nonce: String, role: NativeKeyRole, roleOrder: Int, sourceAccessGroup: String, targetAccessGroup: String, helperIdentity: NativeLegacyMigrationHelperIdentity, appVersion: String, initialLifecycleHead: String, previousLifecycleHead: String, issuedAt: String, expiresAt: String, binding: NativeLegacyMigrationRoleBinding) {
        self.operationID = operationID
        self.nonce = nonce
        self.role = role
        self.roleOrder = roleOrder
        self.sourceAccessGroup = sourceAccessGroup
        self.targetAccessGroup = targetAccessGroup
        self.helperIdentity = helperIdentity
        self.appVersion = appVersion
        self.initialLifecycleHead = initialLifecycleHead
        self.previousLifecycleHead = previousLifecycleHead
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.binding = binding
    }

    public func canonicalData() throws -> Data { try NativeAuditLog.canonical(canonicalObject()) }

    public func oldRoleSigningData() throws -> Data { try proofData(domain: "agentpass-legacy-migration-old-role-v1") }
    public func replacementProofData() throws -> Data { try proofData(domain: "agentpass-legacy-migration-replacement-pop-v1") }
    public func humanPresenceApprovalData() throws -> Data { try proofData(domain: "agentpass-legacy-migration-human-presence-v1") }

    public static func decodeCanonical(_ data: Data) throws -> Self {
        let keys: Set<String> = [
            "version", "operation_id", "nonce", "role", "role_order", "source_access_group",
            "target_access_group", "helper_bundle_id", "team_id", "helper_cdhash", "app_version",
            "initial_lifecycle_head", "previous_lifecycle_head", "issued_at", "expires_at",
            "old_application_tag", "new_application_tag", "old_public_key", "new_public_key"
        ]
        guard data.count > 0, data.count <= 32 * 1024,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == keys, try NativeAuditLog.canonical(object) == data,
              object["version"] as? Int == version,
              let operationText = object["operation_id"] as? String,
              let operationID = UUID(uuidString: operationText), operationID.uuidString.lowercased() == operationText,
              let nonce = strictString(object, "nonce", maximum: 256),
              let roleText = object["role"] as? String, let role = NativeKeyRole(rawValue: roleText),
              let roleOrder = object["role_order"] as? Int,
              let source = strictString(object, "source_access_group", maximum: 256),
              let target = strictString(object, "target_access_group", maximum: 256),
              let bundleID = strictString(object, "helper_bundle_id", maximum: 256),
              let teamID = strictString(object, "team_id", maximum: 64),
              let cdhash = object["helper_cdhash"] as? String, isHexHash(cdhash),
              let appVersion = strictString(object, "app_version", maximum: 64),
              let initialHead = object["initial_lifecycle_head"] as? String, isHash(initialHead),
              let previousHead = object["previous_lifecycle_head"] as? String, isHash(previousHead),
              let issuedAt = object["issued_at"] as? String, migrationDate(issuedAt) != nil,
              let expiresAt = object["expires_at"] as? String, migrationDate(expiresAt) != nil,
              let oldTag = strictString(object, "old_application_tag", maximum: 512),
              let newTag = strictString(object, "new_application_tag", maximum: 512),
              let oldKeyText = object["old_public_key"] as? String, let oldKey = canonicalBase64(oldKeyText), validP256(oldKey),
              let newKeyText = object["new_public_key"] as? String, let newKey = canonicalBase64(newKeyText), validP256(newKey) else {
            throw AgentPassNativeError.invalidSignature("Legacy migration plan is not exact canonical schema")
        }
        let binding = NativeLegacyMigrationRoleBinding(role: role, oldApplicationTag: oldTag, newApplicationTag: newTag, oldPublicKeyX963: oldKey, newPublicKeyX963: newKey)
        let plan = Self(operationID: operationID, nonce: nonce, role: role, roleOrder: roleOrder, sourceAccessGroup: source, targetAccessGroup: target, helperIdentity: .init(bundleID: bundleID, teamID: teamID, codeDirectoryHash: cdhash), appVersion: appVersion, initialLifecycleHead: initialHead, previousLifecycleHead: previousHead, issuedAt: issuedAt, expiresAt: expiresAt, binding: binding)
        guard try plan.canonicalData() == data else { throw AgentPassNativeError.invalidSignature("Legacy migration plan is not canonical") }
        return plan
    }

    fileprivate func canonicalObject() -> [String: Any] {
        [
            "version": Self.version, "operation_id": operationID.uuidString.lowercased(), "nonce": nonce,
            "role": role.rawValue, "role_order": roleOrder, "source_access_group": sourceAccessGroup,
            "target_access_group": targetAccessGroup, "helper_bundle_id": helperIdentity.bundleID,
            "team_id": helperIdentity.teamID, "helper_cdhash": helperIdentity.codeDirectoryHash,
            "app_version": appVersion, "initial_lifecycle_head": initialLifecycleHead,
            "previous_lifecycle_head": previousLifecycleHead, "issued_at": issuedAt, "expires_at": expiresAt,
            "old_application_tag": binding.oldApplicationTag, "new_application_tag": binding.newApplicationTag,
            "old_public_key": binding.oldPublicKeyX963.base64EncodedString(),
            "new_public_key": binding.newPublicKeyX963.base64EncodedString()
        ]
    }

    private func proofData(domain: String) throws -> Data {
        try NativeAuditLog.canonical([
            "domain": domain,
            "operation_id": operationID.uuidString.lowercased(),
            "plan_hash": migrationHash(try canonicalData())
        ])
    }
}

public struct NativeLegacyMigrationProofs: Equatable, Sendable {
    public let oldRoleSignature: Data
    public let replacementKeySignature: Data
    public let humanPresenceApprovalSignature: Data

    public init(oldRoleSignature: Data, replacementKeySignature: Data, humanPresenceApprovalSignature: Data) {
        self.oldRoleSignature = oldRoleSignature
        self.replacementKeySignature = replacementKeySignature
        self.humanPresenceApprovalSignature = humanPresenceApprovalSignature
    }
}

public struct NativeLegacyMigrationReceipt: Equatable, Sendable {
    public let operationID: UUID
    public let role: NativeKeyRole
    public let planHash: String
    public let previousLifecycleHead: String
    public let lifecycleHead: String
    public let oldFingerprint: String
    public let newFingerprint: String
    public let planData: Data
    public let oldRoleSignature: Data
    public let replacementKeySignature: Data
    public let humanPresenceApprovalSignature: Data
    public let committedAt: String

    public func canonicalData() throws -> Data {
        try NativeAuditLog.canonical([
            "version": 1, "operation_id": operationID.uuidString.lowercased(), "role": role.rawValue,
            "plan_hash": planHash, "previous_lifecycle_head": previousLifecycleHead,
            "lifecycle_head": lifecycleHead, "old_fingerprint": oldFingerprint,
            "new_fingerprint": newFingerprint, "old_role_signature": oldRoleSignature.base64EncodedString(),
            "plan": planData.base64EncodedString(),
            "replacement_key_signature": replacementKeySignature.base64EncodedString(),
            "human_presence_approval_signature": humanPresenceApprovalSignature.base64EncodedString(),
            "committed_at": committedAt
        ])
    }

    public static func decodeCanonical(_ data: Data) throws -> Self {
        let keys: Set<String> = ["version", "operation_id", "role", "plan_hash", "previous_lifecycle_head", "lifecycle_head", "old_fingerprint", "new_fingerprint", "plan", "old_role_signature", "replacement_key_signature", "human_presence_approval_signature", "committed_at"]
        guard data.count > 0, data.count <= 64 * 1024,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == keys,
              try NativeAuditLog.canonical(object) == data, object["version"] as? Int == 1,
              let idText = object["operation_id"] as? String, let id = UUID(uuidString: idText), id.uuidString.lowercased() == idText,
              let roleText = object["role"] as? String, let role = NativeKeyRole(rawValue: roleText),
              let planHash = object["plan_hash"] as? String, isHash(planHash),
              let previous = object["previous_lifecycle_head"] as? String, isHash(previous),
              let head = object["lifecycle_head"] as? String, isHash(head),
              let oldFingerprint = object["old_fingerprint"] as? String, isFingerprint(oldFingerprint),
              let newFingerprint = object["new_fingerprint"] as? String, isFingerprint(newFingerprint),
              let planText = object["plan"] as? String, let planData = canonicalBase64(planText),
              let oldText = object["old_role_signature"] as? String, let oldSignature = canonicalBase64(oldText), oldSignature.count == 64,
              let newText = object["replacement_key_signature"] as? String, let newSignature = canonicalBase64(newText), newSignature.count == 64,
              let approvalText = object["human_presence_approval_signature"] as? String, let approvalSignature = canonicalBase64(approvalText), approvalSignature.count == 64,
              let committedAt = object["committed_at"] as? String, migrationDate(committedAt) != nil else {
            throw AgentPassNativeError.invalidSignature("Legacy migration receipt is not exact canonical schema")
        }
        let receipt = Self(operationID: id, role: role, planHash: planHash, previousLifecycleHead: previous, lifecycleHead: head, oldFingerprint: oldFingerprint, newFingerprint: newFingerprint, planData: planData, oldRoleSignature: oldSignature, replacementKeySignature: newSignature, humanPresenceApprovalSignature: approvalSignature, committedAt: committedAt)
        guard try receipt.canonicalData() == data else { throw AgentPassNativeError.invalidSignature("Legacy migration receipt is not canonical") }
        return receipt
    }
}

public struct NativeLegacyMigrationCompletionManifest: Equatable, Sendable {
    public let initialLifecycleHead: String
    public let newLifecycleHead: String
    public let operationIDs: [UUID]
    public let roleReceiptHashes: [String]
    public let completedAt: String
    public let approvalPublicKeyX963: Data
    public let approvalSignature: Data

    public init(initialLifecycleHead: String, newLifecycleHead: String, operationIDs: [UUID], roleReceiptHashes: [String], completedAt: String, approvalPublicKeyX963: Data, approvalSignature: Data) {
        self.initialLifecycleHead = initialLifecycleHead
        self.newLifecycleHead = newLifecycleHead
        self.operationIDs = operationIDs
        self.roleReceiptHashes = roleReceiptHashes
        self.completedAt = completedAt
        self.approvalPublicKeyX963 = approvalPublicKeyX963
        self.approvalSignature = approvalSignature
    }

    public func unsignedCanonicalData() throws -> Data {
        try NativeAuditLog.canonical([
            "version": 1, "initial_lifecycle_head": initialLifecycleHead,
            "new_lifecycle_head": newLifecycleHead,
            "roles": NativeLegacyMigrationCoordinator.requiredOrder.map(\.rawValue),
            "operation_ids": operationIDs.map { $0.uuidString.lowercased() },
            "role_receipt_hashes": roleReceiptHashes, "completed_at": completedAt,
            "approval_public_key": approvalPublicKeyX963.base64EncodedString()
        ])
    }

    public func canonicalData() throws -> Data {
        var object = try JSONSerialization.jsonObject(with: unsignedCanonicalData()) as! [String: Any]
        object["approval_signature"] = approvalSignature.base64EncodedString()
        return try NativeAuditLog.canonical(object)
    }

    public static func decodeCanonical(_ data: Data, verifier: any NativeLifecycleSignatureVerifier = NativeP256LifecycleVerifier()) throws -> Self {
        let keys: Set<String> = ["version", "initial_lifecycle_head", "new_lifecycle_head", "roles", "operation_ids", "role_receipt_hashes", "completed_at", "approval_public_key", "approval_signature"]
        guard data.count > 0, data.count <= 32 * 1024,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == keys,
              try NativeAuditLog.canonical(object) == data, object["version"] as? Int == 1,
              let initial = object["initial_lifecycle_head"] as? String, isHash(initial),
              let head = object["new_lifecycle_head"] as? String, isHash(head), head != initial,
              let roles = object["roles"] as? [String], roles == NativeLegacyMigrationCoordinator.requiredOrder.map(\.rawValue),
              let ids = object["operation_ids"] as? [String], ids.count == 3,
              case let operations = ids.compactMap({ UUID(uuidString: $0) }), operations.count == 3,
              Set(ids).count == 3, zip(ids, operations).allSatisfy({ $0.1.uuidString.lowercased() == $0.0 }),
              let hashes = object["role_receipt_hashes"] as? [String], hashes.count == 3, hashes.allSatisfy(isHash),
              let completedAt = object["completed_at"] as? String, migrationDate(completedAt) != nil,
              let keyText = object["approval_public_key"] as? String, let key = canonicalBase64(keyText), validP256(key),
              let signatureText = object["approval_signature"] as? String, let signature = canonicalBase64(signatureText), signature.count == 64 else {
            throw AgentPassNativeError.invalidSignature("Legacy migration completion manifest is not exact canonical schema")
        }
        let manifest = Self(initialLifecycleHead: initial, newLifecycleHead: head, operationIDs: operations, roleReceiptHashes: hashes, completedAt: completedAt, approvalPublicKeyX963: key, approvalSignature: signature)
        guard verifier.isValid(signature: signature, message: try manifest.unsignedCanonicalData(), publicKeyX963: key) else {
            throw AgentPassNativeError.invalidSignature("Legacy migration completion approval is invalid")
        }
        return manifest
    }

    /// Verifies that this manifest is backed by all three exact, independently verifiable role
    /// receipts, rather than merely trusting the summary hashes in the manifest.
    public func verify(receipts: [NativeLegacyMigrationReceipt], historicalPublicKeysX963: [Data] = [], verifier: any NativeLifecycleSignatureVerifier = NativeP256LifecycleVerifier()) throws {
        guard receipts.count == 3, receipts.map(\.role) == NativeLegacyMigrationCoordinator.requiredOrder,
              receipts.map(\.operationID) == operationIDs,
              try receipts.map({ migrationHash(try $0.canonicalData()) }) == roleReceiptHashes,
              receipts.first?.previousLifecycleHead == initialLifecycleHead,
              receipts.last?.lifecycleHead == newLifecycleHead,
              NativeKeyLifecycleStore.fingerprint(approvalPublicKeyX963) == receipts.first?.newFingerprint else {
            throw AgentPassNativeError.invalidSignature("Legacy migration manifest does not match its complete role evidence")
        }
        var expectedHead = initialLifecycleHead
        var expectedIdentities: [NativeKeyRole: NativeLegacyMigrationHelperIdentity] = [:]
        var expectedTeamID: String?
        var expectedSourceGroup: String?
        var expectedAppVersion: String?
        var ceremonyFingerprints: Set<String> = []
        var historical = Set(historicalPublicKeysX963.map(NativeKeyLifecycleStore.fingerprint))
        guard historicalPublicKeysX963.allSatisfy(validP256), historical.count == historicalPublicKeysX963.count else {
            throw AgentPassNativeError.invalidKey("Legacy migration verification history is malformed or duplicated")
        }
        var previousCommit: Date?
        for (index, receipt) in receipts.enumerated() {
            let plan = try NativeLegacyMigrationPlan.decodeCanonical(receipt.planData)
            let derivedHead = try migrationLifecycleHead(plan: plan)
            let teamPrefix = "\(plan.helperIdentity.teamID)."
            let expectedTarget = plan.role == .sessionApproval
                ? teamPrefix + NativeLegacyMigrationV017.approvalAccessGroupSuffix
                : teamPrefix + NativeLegacyMigrationV017.serviceAccessGroupSuffix
            guard let issued = migrationDate(plan.issuedAt), let expires = migrationDate(plan.expiresAt),
                  let committed = migrationDate(receipt.committedAt), issued <= committed, committed < expires,
                  previousCommit.map({ committed >= $0 }) ?? true,
                  plan.roleOrder == index + 1, plan.initialLifecycleHead == initialLifecycleHead,
                  plan.helperIdentity.bundleID == NativeLegacyMigrationV017.helperBundleID(for: plan.role),
                  plan.sourceAccessGroup == teamPrefix + NativeLegacyMigrationV017.sourceAccessGroupSuffix,
                  plan.targetAccessGroup == expectedTarget,
                  plan.binding.oldApplicationTag == NativeLegacyMigrationV017.oldApplicationTags[plan.role],
                  plan.binding.newApplicationTag == NativeLegacyMigrationV017.newApplicationTags[plan.role],
                  expectedIdentities[plan.role].map({ $0 == plan.helperIdentity }) ?? true,
                  expectedTeamID.map({ $0 == plan.helperIdentity.teamID }) ?? true,
                  expectedSourceGroup.map({ $0 == plan.sourceAccessGroup }) ?? true,
                  expectedAppVersion.map({ $0 == plan.appVersion }) ?? true else {
                throw AgentPassNativeError.invalidSignature("Legacy migration receipt environment, order, or time binding is invalid")
            }
            guard receipt.operationID == plan.operationID, receipt.role == plan.role,
                  receipt.planHash == migrationHash(receipt.planData), receipt.previousLifecycleHead == expectedHead,
                  plan.previousLifecycleHead == expectedHead,
                  receipt.oldFingerprint == NativeKeyLifecycleStore.fingerprint(plan.binding.oldPublicKeyX963),
                  receipt.newFingerprint == NativeKeyLifecycleStore.fingerprint(plan.binding.newPublicKeyX963),
                  receipt.lifecycleHead == derivedHead,
                  verifier.isValid(signature: receipt.oldRoleSignature, message: try plan.oldRoleSigningData(), publicKeyX963: plan.binding.oldPublicKeyX963),
                  verifier.isValid(signature: receipt.replacementKeySignature, message: try plan.replacementProofData(), publicKeyX963: plan.binding.newPublicKeyX963) else {
                throw AgentPassNativeError.invalidSignature("Legacy migration receipt continuity evidence is invalid")
            }
            let humanKey = receipt.role == .sessionApproval ? plan.binding.oldPublicKeyX963 : approvalPublicKeyX963
            guard verifier.isValid(signature: receipt.humanPresenceApprovalSignature, message: try plan.humanPresenceApprovalData(), publicKeyX963: humanKey) else {
                throw AgentPassNativeError.invalidSignature("Legacy migration receipt human-presence evidence is invalid")
            }
            guard receipt.oldFingerprint != receipt.newFingerprint,
                  !ceremonyFingerprints.contains(receipt.oldFingerprint),
                  !ceremonyFingerprints.contains(receipt.newFingerprint),
                  !historical.contains(receipt.newFingerprint) else {
                throw AgentPassNativeError.invalidKey("Legacy migration evidence duplicates or reuses a historical key")
            }
            ceremonyFingerprints.insert(receipt.oldFingerprint); ceremonyFingerprints.insert(receipt.newFingerprint)
            historical.insert(receipt.oldFingerprint); historical.insert(receipt.newFingerprint)
            expectedIdentities[plan.role] = plan.helperIdentity; expectedTeamID = plan.helperIdentity.teamID
            expectedSourceGroup = plan.sourceAccessGroup
            expectedAppVersion = plan.appVersion; previousCommit = committed
            expectedHead = receipt.lifecycleHead
        }
        guard let completion = migrationDate(completedAt), previousCommit.map({ completion >= $0 }) ?? false else {
            throw AgentPassNativeError.invalidSignature("Legacy migration completion predates its role evidence")
        }
        guard verifier.isValid(signature: approvalSignature, message: try unsignedCanonicalData(), publicKeyX963: approvalPublicKeyX963) else {
            throw AgentPassNativeError.invalidSignature("Legacy migration completion signature is invalid")
        }
    }
}

/// In-memory ceremony state intended to sit behind a separately signed helper's durable journal.
/// A repeated commit with byte-identical evidence returns the original receipt, which makes a lost
/// XPC/CLI response safe. A reused operation UUID with different evidence is rejected.
public final class NativeLegacyMigrationCoordinator: @unchecked Sendable {
    public static let requiredOrder: [NativeKeyRole] = [.sessionApproval, .gitSigning, .auditCheckpoint]

    private let identities: [NativeKeyRole: NativeLegacyMigrationHelperIdentity]
    private let sourceAccessGroup: String
    private let targetAccessGroups: [NativeKeyRole: String]
    private let expectedOldTags: [NativeKeyRole: String]
    private let expectedNewTags: [NativeKeyRole: String]
    private let appVersion: String
    private let initialHead: String
    private let verifier: any NativeLifecycleSignatureVerifier
    private let now: @Sendable () -> Date
    private let lock = NSLock()
    private var receipts: [NativeLegacyMigrationReceipt] = []
    private var evidenceHashes: [UUID: String] = [:]
    private var usedNonces: Set<String> = []
    private var historicalFingerprints: Set<String>

    public init(helperIdentities: [NativeKeyRole: NativeLegacyMigrationHelperIdentity], sourceAccessGroup: String, targetAccessGroups: [NativeKeyRole: String], expectedOldTags: [NativeKeyRole: String], expectedNewTags: [NativeKeyRole: String], appVersion: String, initialLifecycleHead: String, historicalPublicKeysX963: [Data] = [], verifier: any NativeLifecycleSignatureVerifier = NativeP256LifecycleVerifier(), now: @escaping @Sendable () -> Date = Date.init) throws {
        guard let approvalIdentity = helperIdentities[.sessionApproval],
              let gitIdentity = helperIdentities[.gitSigning],
              let auditIdentity = helperIdentities[.auditCheckpoint] else {
            throw AgentPassNativeError.invalidConfiguration("Legacy migration requires approval and service helper identities")
        }
        let teamID = approvalIdentity.teamID
        let expectedSourceGroup = "\(teamID).\(NativeLegacyMigrationV017.sourceAccessGroupSuffix)"
        let expectedApprovalGroup = "\(teamID).\(NativeLegacyMigrationV017.approvalAccessGroupSuffix)"
        let expectedServiceGroup = "\(teamID).\(NativeLegacyMigrationV017.serviceAccessGroupSuffix)"
        guard helperIdentities.count == NativeKeyRole.allCases.count,
              approvalIdentity.bundleID == NativeLegacyMigrationV017.approvalHelperBundleID,
              gitIdentity.bundleID == NativeLegacyMigrationV017.serviceHelperBundleID,
              auditIdentity == gitIdentity,
              !teamID.isEmpty, helperIdentities.values.allSatisfy({ $0.teamID == teamID && isHexHash($0.codeDirectoryHash) }),
              approvalIdentity != gitIdentity, !sourceAccessGroup.isEmpty,
              NativeKeyRole.allCases.allSatisfy({ targetAccessGroups[$0]?.isEmpty == false && expectedOldTags[$0]?.isEmpty == false && expectedNewTags[$0]?.isEmpty == false }),
              Set(targetAccessGroups.values).count == 2, targetAccessGroups[.sessionApproval] != targetAccessGroups[.gitSigning],
              targetAccessGroups[.gitSigning] == targetAccessGroups[.auditCheckpoint],
              sourceAccessGroup == expectedSourceGroup,
              targetAccessGroups[.sessionApproval] == expectedApprovalGroup,
              targetAccessGroups[.gitSigning] == expectedServiceGroup,
              targetAccessGroups[.auditCheckpoint] == expectedServiceGroup,
              !targetAccessGroups.values.contains(sourceAccessGroup),
              expectedOldTags == NativeLegacyMigrationV017.oldApplicationTags,
              expectedNewTags == NativeLegacyMigrationV017.newApplicationTags,
              Set(expectedOldTags.values).count == NativeKeyRole.allCases.count,
              Set(expectedNewTags.values).count == NativeKeyRole.allCases.count,
              Set(expectedOldTags.values).isDisjoint(with: Set(expectedNewTags.values)),
              !appVersion.isEmpty, isHash(initialLifecycleHead),
              historicalPublicKeysX963.allSatisfy(validP256) else {
            throw AgentPassNativeError.invalidConfiguration("Legacy migration helper configuration is invalid")
        }
        let history = historicalPublicKeysX963.map(NativeKeyLifecycleStore.fingerprint)
        guard Set(history).count == history.count else { throw AgentPassNativeError.invalidKey("Legacy migration history contains duplicate keys") }
        self.identities = helperIdentities; self.sourceAccessGroup = sourceAccessGroup
        self.targetAccessGroups = targetAccessGroups; self.expectedOldTags = expectedOldTags
        self.expectedNewTags = expectedNewTags; self.appVersion = appVersion; self.initialHead = initialLifecycleHead
        self.verifier = verifier; self.now = now; self.historicalFingerprints = Set(history)
    }

    public var currentLifecycleHead: String {
        lock.lock(); defer { lock.unlock() }
        return receipts.last?.lifecycleHead ?? initialHead
    }

    public func validatePreparedPlan(_ data: Data) throws -> NativeLegacyMigrationPlan {
        lock.lock(); defer { lock.unlock() }
        return try validatePreparedPlanLocked(data)
    }

    @discardableResult
    public func commit(planData: Data, proofs: NativeLegacyMigrationProofs) throws -> NativeLegacyMigrationReceipt {
        lock.lock(); defer { lock.unlock() }
        let plan = try NativeLegacyMigrationPlan.decodeCanonical(planData)
        let proofHash = migrationHash(try NativeAuditLog.canonical([
            "plan": planData.base64EncodedString(), "old": proofs.oldRoleSignature.base64EncodedString(),
            "new": proofs.replacementKeySignature.base64EncodedString(), "approval": proofs.humanPresenceApprovalSignature.base64EncodedString()
        ]))
        if let existing = receipts.first(where: { $0.operationID == plan.operationID }) {
            guard evidenceHashes[plan.operationID] == proofHash else { throw AgentPassNativeError.invalidSignature("Migration operation UUID was replayed with different evidence") }
            return existing
        }
        _ = try validatePreparedPlanLocked(planData)
        try verifyProofsLocked(plan: plan, proofs: proofs)
        let committedAt = migrationTimestamp(now())
        let receipt = try makeReceipt(planData: planData, plan: plan, proofs: proofs, committedAt: committedAt)
        recordLocked(receipt: receipt, plan: plan, evidenceHash: proofHash)
        return receipt
    }

    /// Replays a canonical committed receipt from the helper's fsync'd journal after restart. Time
    /// is evaluated at the recorded commit instant, so recovery remains possible after plan expiry.
    @discardableResult
    public func restoreCommittedReceipt(_ data: Data) throws -> NativeLegacyMigrationReceipt {
        lock.lock(); defer { lock.unlock() }
        let receipt = try NativeLegacyMigrationReceipt.decodeCanonical(data)
        if let existing = receipts.first(where: { $0.operationID == receipt.operationID }) {
            guard try existing.canonicalData() == data else { throw AgentPassNativeError.invalidSignature("Migration receipt UUID was replayed with different evidence") }
            return existing
        }
        let plan = try NativeLegacyMigrationPlan.decodeCanonical(receipt.planData)
        guard let committedAt = migrationDate(receipt.committedAt) else { throw AgentPassNativeError.invalidSignature("Migration receipt commit time is invalid") }
        try validatePlanLocked(plan, evaluationDate: committedAt)
        let proofs = NativeLegacyMigrationProofs(oldRoleSignature: receipt.oldRoleSignature, replacementKeySignature: receipt.replacementKeySignature, humanPresenceApprovalSignature: receipt.humanPresenceApprovalSignature)
        try verifyProofsLocked(plan: plan, proofs: proofs)
        let expected = try makeReceipt(planData: receipt.planData, plan: plan, proofs: proofs, committedAt: receipt.committedAt)
        guard expected == receipt else { throw AgentPassNativeError.invalidSignature("Migration receipt does not match its plan or derived lifecycle head") }
        let evidenceHash = migrationHash(try NativeAuditLog.canonical([
            "plan": receipt.planData.base64EncodedString(), "old": receipt.oldRoleSignature.base64EncodedString(),
            "new": receipt.replacementKeySignature.base64EncodedString(), "approval": receipt.humanPresenceApprovalSignature.base64EncodedString()
        ]))
        recordLocked(receipt: receipt, plan: plan, evidenceHash: evidenceHash)
        return receipt
    }

    public func unsignedCompletionManifest(completedAt: String) throws -> NativeLegacyMigrationCompletionManifest {
        lock.lock(); defer { lock.unlock() }
        guard receipts.map(\.role) == Self.requiredOrder, let approvalKey = migratedApprovalPublicKeyLocked(), migrationDate(completedAt) != nil else {
            throw AgentPassNativeError.invalidConfiguration("Legacy migration is incomplete or completion time is invalid")
        }
        return NativeLegacyMigrationCompletionManifest(initialLifecycleHead: initialHead, newLifecycleHead: receipts.last!.lifecycleHead, operationIDs: receipts.map(\.operationID), roleReceiptHashes: try receipts.map { migrationHash(try $0.canonicalData()) }, completedAt: completedAt, approvalPublicKeyX963: approvalKey, approvalSignature: Data())
    }

    public func complete(completedAt: String, approvalSignature: Data) throws -> NativeLegacyMigrationCompletionManifest {
        let unsigned = try unsignedCompletionManifest(completedAt: completedAt)
        guard verifier.isValid(signature: approvalSignature, message: try unsigned.unsignedCanonicalData(), publicKeyX963: unsigned.approvalPublicKeyX963) else {
            throw AgentPassNativeError.invalidSignature("Completion manifest lacks valid human-presence approval")
        }
        return .init(initialLifecycleHead: unsigned.initialLifecycleHead, newLifecycleHead: unsigned.newLifecycleHead, operationIDs: unsigned.operationIDs, roleReceiptHashes: unsigned.roleReceiptHashes, completedAt: unsigned.completedAt, approvalPublicKeyX963: unsigned.approvalPublicKeyX963, approvalSignature: approvalSignature)
    }

    private func validatePreparedPlanLocked(_ data: Data) throws -> NativeLegacyMigrationPlan {
        let plan = try NativeLegacyMigrationPlan.decodeCanonical(data)
        try validatePlanLocked(plan, evaluationDate: now())
        return plan
    }

    private func validatePlanLocked(_ plan: NativeLegacyMigrationPlan, evaluationDate: Date) throws {
        guard receipts.count < Self.requiredOrder.count else {
            throw AgentPassNativeError.invalidConfiguration("Legacy migration is already complete")
        }
        let expectedRole = Self.requiredOrder[receipts.count]
        guard plan.role == expectedRole, plan.roleOrder == receipts.count + 1,
              plan.binding.role == plan.role, plan.helperIdentity == identities[plan.role],
              plan.sourceAccessGroup == sourceAccessGroup, plan.targetAccessGroup == targetAccessGroups[plan.role],
              plan.appVersion == appVersion, plan.initialLifecycleHead == initialHead,
              plan.previousLifecycleHead == (receipts.last?.lifecycleHead ?? initialHead),
              plan.binding.oldApplicationTag == expectedOldTags[plan.role], plan.binding.newApplicationTag == expectedNewTags[plan.role],
              plan.binding.oldApplicationTag != plan.binding.newApplicationTag else {
            throw AgentPassNativeError.invalidSignature("Legacy migration plan does not match the exact helper environment or role order")
        }
        guard let issued = migrationDate(plan.issuedAt), let expires = migrationDate(plan.expiresAt), issued < expires,
              evaluationDate >= issued, evaluationDate < expires, expires.timeIntervalSince(issued) <= 3600 else {
            throw AgentPassNativeError.invalidSignature("Legacy migration plan is expired, premature, or exceeds one hour")
        }
        let oldFingerprint = NativeKeyLifecycleStore.fingerprint(plan.binding.oldPublicKeyX963)
        let newFingerprint = NativeKeyLifecycleStore.fingerprint(plan.binding.newPublicKeyX963)
        let allCurrent = receipts.flatMap { [$0.oldFingerprint, $0.newFingerprint] }
        guard !usedNonces.contains(plan.nonce), oldFingerprint != newFingerprint, !allCurrent.contains(oldFingerprint),
              !allCurrent.contains(newFingerprint), !historicalFingerprints.contains(newFingerprint) else {
            throw AgentPassNativeError.invalidKey("Legacy migration replacement key is duplicated or reuses migration history")
        }
        guard !receipts.contains(where: { $0.operationID == plan.operationID }) else {
            throw AgentPassNativeError.invalidSignature("Legacy migration operation UUID is already committed")
        }
    }

    private func verifyProofsLocked(plan: NativeLegacyMigrationPlan, proofs: NativeLegacyMigrationProofs) throws {
        guard verifier.isValid(signature: proofs.oldRoleSignature, message: try plan.oldRoleSigningData(), publicKeyX963: plan.binding.oldPublicKeyX963) else {
            throw AgentPassNativeError.invalidSignature("Legacy role continuity signature is invalid")
        }
        guard verifier.isValid(signature: proofs.replacementKeySignature, message: try plan.replacementProofData(), publicKeyX963: plan.binding.newPublicKeyX963) else {
            throw AgentPassNativeError.invalidSignature("Replacement key proof-of-possession is invalid")
        }
        let approvalKey = plan.role == .sessionApproval ? plan.binding.oldPublicKeyX963 : approvalPublicKeyLocked()
        guard !approvalKey.isEmpty, verifier.isValid(signature: proofs.humanPresenceApprovalSignature, message: try plan.humanPresenceApprovalData(), publicKeyX963: approvalKey) else {
            throw AgentPassNativeError.invalidSignature("Human-presence migration approval is invalid")
        }
    }

    private func makeReceipt(planData: Data, plan: NativeLegacyMigrationPlan, proofs: NativeLegacyMigrationProofs, committedAt: String) throws -> NativeLegacyMigrationReceipt {
        NativeLegacyMigrationReceipt(operationID: plan.operationID, role: plan.role, planHash: migrationHash(try plan.canonicalData()), previousLifecycleHead: plan.previousLifecycleHead, lifecycleHead: try migrationLifecycleHead(plan: plan), oldFingerprint: NativeKeyLifecycleStore.fingerprint(plan.binding.oldPublicKeyX963), newFingerprint: NativeKeyLifecycleStore.fingerprint(plan.binding.newPublicKeyX963), planData: planData, oldRoleSignature: proofs.oldRoleSignature, replacementKeySignature: proofs.replacementKeySignature, humanPresenceApprovalSignature: proofs.humanPresenceApprovalSignature, committedAt: committedAt)
    }

    private func recordLocked(receipt: NativeLegacyMigrationReceipt, plan: NativeLegacyMigrationPlan, evidenceHash: String) {
        receipts.append(receipt); evidenceHashes[plan.operationID] = evidenceHash; usedNonces.insert(plan.nonce)
        if plan.role == .sessionApproval { committedApprovalPublicKey = plan.binding.newPublicKeyX963 }
        historicalFingerprints.insert(receipt.oldFingerprint); historicalFingerprints.insert(receipt.newFingerprint)
    }

    private func migratedApprovalPublicKeyLocked() -> Data? {
        guard let receipt = receipts.first, receipt.role == .sessionApproval else { return nil }
        // The receipt deliberately stores only public fingerprints. The exact key is recovered from
        // the committed approval plan in a real durable journal; this coordinator keeps it below.
        return committedApprovalPublicKey
    }

    private var committedApprovalPublicKey: Data?
    private func approvalPublicKeyLocked() -> Data { committedApprovalPublicKey ?? Data() }
}

// MARK: - Durable lifecycle-ledger adoption

/// The exact generation-1 Keychain observation made by the service before it adopts a completed
/// v0.17 migration. Callers must supply exactly one observation for every role. This makes a
/// pre-existing, substituted, or otherwise orphaned `.g1` key a hard failure rather than silently
/// treating whatever happens to be in Keychain as the migrated key.
public struct NativeLegacyMigrationObservedTargetKey: Equatable, Sendable {
    public let role: NativeKeyRole
    public let applicationTag: String
    public let publicKeyX963: Data

    public init(role: NativeKeyRole, applicationTag: String, publicKeyX963: Data) {
        self.role = role
        self.applicationTag = applicationTag
        self.publicKeyX963 = publicKeyX963
    }
}

/// Exact bytes which the replacement role key and the migrated approval key must sign. Adoption
/// is deliberately sequential: the next request depends on the signed activation record before
/// it. Persist each committed entry, then persist the final plan, before executing any mutation.
public struct NativeLegacyMigrationAdoptionSigningRequest: Equatable, Sendable {
    public let role: NativeKeyRole
    public let migrationOperationID: UUID
    public let receiptHash: String
    public let stageOperationID: UUID
    public let activationOperationID: UUID
    public let stageRecordData: Data
    public let transitionStatementData: Data

    public init(role: NativeKeyRole, migrationOperationID: UUID, receiptHash: String, stageOperationID: UUID, activationOperationID: UUID, stageRecordData: Data, transitionStatementData: Data) {
        self.role = role
        self.migrationOperationID = migrationOperationID
        self.receiptHash = receiptHash
        self.stageOperationID = stageOperationID
        self.activationOperationID = activationOperationID
        self.stageRecordData = stageRecordData
        self.transitionStatementData = transitionStatementData
    }
}

public struct NativeLegacyMigrationAdoptionSignatures: Equatable, Sendable {
    public let replacementSignature: Data
    public let approvalSignature: Data

    public init(replacementSignature: Data, approvalSignature: Data) {
        self.replacementSignature = replacementSignature
        self.approvalSignature = approvalSignature
    }
}

/// One immutable pair of exact lifecycle mutations. The migration receipt is bound by hash, while
/// the activation statement's reason binds that receipt into the lifecycle ledger itself.
public struct NativeLegacyMigrationAdoptionEntry: Equatable, Sendable {
    public let role: NativeKeyRole
    public let migrationOperationID: UUID
    public let receiptHash: String
    public let helperIdentity: NativeLegacyMigrationHelperIdentity
    public let stageOperationID: UUID
    public let activationOperationID: UUID
    public let stageRecordData: Data
    public let transitionStatementData: Data
    public let activationRecordData: Data

    public func canonicalData() throws -> Data {
        try NativeAuditLog.canonical([
            "version": 1,
            "role": role.rawValue,
            "migration_operation_id": migrationOperationID.uuidString.lowercased(),
            "receipt_hash": receiptHash,
            "helper_bundle_id": helperIdentity.bundleID,
            "helper_team_id": helperIdentity.teamID,
            "helper_cdhash": helperIdentity.codeDirectoryHash,
            "stage_operation_id": stageOperationID.uuidString.lowercased(),
            "activation_operation_id": activationOperationID.uuidString.lowercased(),
            "stage_record": stageRecordData.base64EncodedString(),
            "transition_statement": transitionStatementData.base64EncodedString(),
            "activation_record": activationRecordData.base64EncodedString()
        ])
    }

    public static func decodeCanonical(_ data: Data) throws -> Self {
        let keys: Set<String> = [
            "version", "role", "migration_operation_id", "receipt_hash", "helper_bundle_id",
            "helper_team_id", "helper_cdhash", "stage_operation_id", "activation_operation_id",
            "stage_record", "transition_statement", "activation_record"
        ]
        guard data.count > 0, data.count <= 256 * 1024,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == keys,
              try NativeAuditLog.canonical(object) == data, object["version"] as? Int == 1,
              let roleText = object["role"] as? String, let role = NativeKeyRole(rawValue: roleText),
              let migrationID = adoptionUUID(object["migration_operation_id"]),
              let receiptHash = object["receipt_hash"] as? String, isHash(receiptHash),
              let bundleID = strictString(object, "helper_bundle_id", maximum: 256),
              let teamID = strictString(object, "helper_team_id", maximum: 64),
              let cdhash = object["helper_cdhash"] as? String, isHexHash(cdhash),
              let stageID = adoptionUUID(object["stage_operation_id"]),
              let activationID = adoptionUUID(object["activation_operation_id"]), stageID != activationID,
              let stageText = object["stage_record"] as? String, let stage = canonicalBase64(stageText),
              let statementText = object["transition_statement"] as? String, let statement = canonicalBase64(statementText),
              let activationText = object["activation_record"] as? String, let activation = canonicalBase64(activationText) else {
            throw AgentPassNativeError.invalidSignature("Legacy migration adoption entry is not exact canonical schema")
        }
        return Self(role: role, migrationOperationID: migrationID, receiptHash: receiptHash, helperIdentity: .init(bundleID: bundleID, teamID: teamID, codeDirectoryHash: cdhash), stageOperationID: stageID, activationOperationID: activationID, stageRecordData: stage, transitionStatementData: statement, activationRecordData: activation)
    }
}

/// A fully signed, byte-exact adoption transaction. Its embedded manifest and receipts make the
/// plan independently re-verifiable after helper removal; its baseline is captured from the real
/// ledger, external pin, and mutation outbox rather than from the migration coordinator's
/// in-memory evidence chain.
public struct NativeLegacyMigrationAdoptionPlan: Equatable, Sendable {
    public static let version = 1

    public let completionManifestData: Data
    public let receiptData: [Data]
    public let initialLifecycleSequence: Int
    public let initialLifecycleHead: String
    public let initialPinSequence: Int
    public let initialPinHead: String
    public let initialOutboxPinSequence: Int
    public let initialOutboxLifecycleSequence: Int
    public let initialOutboxHead: String
    public let entries: [NativeLegacyMigrationAdoptionEntry]
    public let preparedAt: String

    public var finalLifecycleSequence: Int { initialLifecycleSequence + entries.count * 2 }

    public var finalLifecycleHead: String {
        (try? entries.last.map { try adoptionRecordView($0.activationRecordData).recordHash }) ?? initialLifecycleHead
    }

    public func canonicalData() throws -> Data {
        try NativeAuditLog.canonical([
            "version": Self.version,
            "completion_manifest": completionManifestData.base64EncodedString(),
            "receipts": receiptData.map { $0.base64EncodedString() },
            "initial_lifecycle_sequence": initialLifecycleSequence,
            "initial_lifecycle_head": initialLifecycleHead,
            "initial_pin_sequence": initialPinSequence,
            "initial_pin_head": initialPinHead,
            "initial_outbox_pin_sequence": initialOutboxPinSequence,
            "initial_outbox_lifecycle_sequence": initialOutboxLifecycleSequence,
            "initial_outbox_head": initialOutboxHead,
            "entries": try entries.map { try $0.canonicalData().base64EncodedString() },
            "prepared_at": preparedAt,
            "final_lifecycle_sequence": finalLifecycleSequence,
            "final_lifecycle_head": finalLifecycleHead
        ])
    }

    public static func decodeCanonical(_ data: Data, verifier: any NativeLifecycleSignatureVerifier = NativeP256LifecycleVerifier()) throws -> Self {
        let keys: Set<String> = [
            "version", "completion_manifest", "receipts", "initial_lifecycle_sequence",
            "initial_lifecycle_head", "initial_pin_sequence", "initial_pin_head",
            "initial_outbox_pin_sequence", "initial_outbox_lifecycle_sequence", "initial_outbox_head",
            "entries", "prepared_at", "final_lifecycle_sequence", "final_lifecycle_head"
        ]
        guard data.count > 0, data.count <= 1_048_576,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == keys,
              try NativeAuditLog.canonical(object) == data, object["version"] as? Int == version,
              let manifestText = object["completion_manifest"] as? String, let manifestData = canonicalBase64(manifestText),
              let receiptTexts = object["receipts"] as? [String], receiptTexts.count == 3,
              case let receipts = receiptTexts.compactMap(canonicalBase64), receipts.count == 3,
              let initialSequence = adoptionInt(object["initial_lifecycle_sequence"]), initialSequence >= 0,
              let initialHead = object["initial_lifecycle_head"] as? String, isHash(initialHead),
              let pinSequence = adoptionInt(object["initial_pin_sequence"]), pinSequence >= 0,
              let pinHead = object["initial_pin_head"] as? String,
              let outboxPinSequence = adoptionInt(object["initial_outbox_pin_sequence"]), outboxPinSequence >= 0,
              let outboxLifecycleSequence = adoptionInt(object["initial_outbox_lifecycle_sequence"]), outboxLifecycleSequence >= 0,
              let outboxHead = object["initial_outbox_head"] as? String,
              let entryTexts = object["entries"] as? [String], entryTexts.count == 3,
              let preparedAt = object["prepared_at"] as? String, migrationDate(preparedAt) != nil,
              let finalSequence = adoptionInt(object["final_lifecycle_sequence"]),
              let finalHead = object["final_lifecycle_head"] as? String, isHash(finalHead) else {
            throw AgentPassNativeError.invalidSignature("Legacy migration adoption plan is not exact canonical schema")
        }
        let entries = try entryTexts.map {
            guard let bytes = canonicalBase64($0) else { throw AgentPassNativeError.invalidSignature("Legacy migration adoption entry encoding is invalid") }
            return try NativeLegacyMigrationAdoptionEntry.decodeCanonical(bytes)
        }
        let plan = Self(completionManifestData: manifestData, receiptData: receipts, initialLifecycleSequence: initialSequence, initialLifecycleHead: initialHead, initialPinSequence: pinSequence, initialPinHead: pinHead, initialOutboxPinSequence: outboxPinSequence, initialOutboxLifecycleSequence: outboxLifecycleSequence, initialOutboxHead: outboxHead, entries: entries, preparedAt: preparedAt)
        guard plan.finalLifecycleSequence == finalSequence, plan.finalLifecycleHead == finalHead,
              try plan.canonicalData() == data else {
            throw AgentPassNativeError.invalidSignature("Legacy migration adoption plan summary or canonical bytes are inconsistent")
        }
        try plan.verify(verifier: verifier)
        return plan
    }

    public func verify(verifier: any NativeLifecycleSignatureVerifier = NativeP256LifecycleVerifier()) throws {
        let manifest = try NativeLegacyMigrationCompletionManifest.decodeCanonical(completionManifestData, verifier: verifier)
        let receipts = try receiptData.map(NativeLegacyMigrationReceipt.decodeCanonical)
        try manifest.verify(receipts: receipts, verifier: verifier)
        guard initialLifecycleSequence == 0, initialLifecycleHead == NativeKeyLifecycleStore.zeroHash,
              manifest.initialLifecycleHead == initialLifecycleHead,
              initialPinSequence == 0, initialPinHead.isEmpty,
              initialOutboxPinSequence == 0, initialOutboxLifecycleSequence == 0, initialOutboxHead.isEmpty,
              entries.count == 3, entries.map(\.role) == NativeLegacyMigrationCoordinator.requiredOrder,
              migrationDate(preparedAt) != nil else {
            throw AgentPassNativeError.invalidSignature("Legacy migration adoption baseline is not a pristine, real lifecycle state")
        }
        var expectedSequence = initialLifecycleSequence
        var expectedHead = initialLifecycleHead
        var expectedPinSequence = initialPinSequence
        var seenOperationIDs = Set<UUID>()
        for index in entries.indices {
            let entry = entries[index]
            let receipt = receipts[index]
            let migrationPlan = try NativeLegacyMigrationPlan.decodeCanonical(receipt.planData)
            let expectedReceiptHash = migrationHash(receiptData[index])
            guard entry.migrationOperationID == receipt.operationID,
                  entry.receiptHash == expectedReceiptHash,
                  entry.helperIdentity == migrationPlan.helperIdentity,
                  entry.helperIdentity.bundleID == NativeLegacyMigrationV017.helperBundleID(for: entry.role),
                  seenOperationIDs.insert(entry.stageOperationID).inserted,
                  seenOperationIDs.insert(entry.activationOperationID).inserted,
                  entry.stageOperationID == adoptionOperationID(receiptHash: expectedReceiptHash, action: "staged"),
                  entry.activationOperationID == adoptionOperationID(receiptHash: expectedReceiptHash, action: "activated") else {
                throw AgentPassNativeError.invalidSignature("Legacy migration adoption entry does not bind its exact helper proof")
            }
            let stage = try adoptionRecordView(entry.stageRecordData)
            expectedSequence += 1; expectedPinSequence += 1
            guard stage.sequence == expectedSequence, stage.previousRecordHash == expectedHead,
                  stage.action == "staged", stage.role == entry.role, stage.generation == 1,
                  stage.applicationTag == NativeLegacyMigrationV017.newApplicationTags[entry.role],
                  stage.publicKeyX963 == migrationPlan.binding.newPublicKeyX963,
                  stage.createdAt == preparedAt, stage.continuity == .clean,
                  stage.isEmptyTransition, stage.recordHash == adoptionRecordHash(entry.stageRecordData) else {
                throw AgentPassNativeError.invalidSignature("Legacy migration staged record is substituted or not byte-exact")
            }
            expectedHead = stage.recordHash
            let statement = try NativeKeyTransitionStatement.decodeCanonical(entry.transitionStatementData)
            let expectedReason = "legacy-v0.17-adoption:\(expectedReceiptHash)"
            let expectedChallenge = "legacy-migration:\(receipt.operationID.uuidString.lowercased())"
            guard statement.role == entry.role, statement.oldGeneration == 0, statement.newGeneration == 1,
                  statement.oldFingerprint.isEmpty, statement.newFingerprint == stage.fingerprint,
                  statement.stateSequence == expectedSequence + 1, statement.reason == expectedReason,
                  statement.challengeID == expectedChallenge, statement.createdAt == preparedAt,
                  statement.previousLifecycleHead == expectedHead, statement.continuity == .bootstrap else {
                throw AgentPassNativeError.invalidSignature("Legacy migration transition statement is not the exact adoption statement")
            }
            let activation = try adoptionRecordView(entry.activationRecordData)
            expectedSequence += 1; expectedPinSequence += 1
            guard activation.sequence == expectedSequence, activation.previousRecordHash == expectedHead,
                  activation.action == "activated", activation.role == entry.role, activation.generation == 1,
                  activation.applicationTag == stage.applicationTag, activation.publicKeyX963 == stage.publicKeyX963,
                  activation.createdAt == preparedAt, activation.continuity == .bootstrap,
                  activation.reason == statement.reason, activation.challengeID == statement.challengeID,
                  activation.oldGeneration == 0, activation.oldFingerprint.isEmpty,
                  activation.approvalPublicKeyX963 == manifest.approvalPublicKeyX963,
                  activation.minimumRetirementAgeSeconds == 0, !activation.transitionArchived,
                  activation.externallyPinnedHeadHash.isEmpty,
                  activation.recordHash == adoptionRecordHash(entry.activationRecordData),
                  verifier.isValid(signature: activation.newSignature, message: entry.transitionStatementData, publicKeyX963: stage.publicKeyX963),
                  verifier.isValid(signature: activation.approvalSignature, message: entry.transitionStatementData, publicKeyX963: manifest.approvalPublicKeyX963) else {
                throw AgentPassNativeError.invalidSignature("Legacy migration activation record or lifecycle signatures are invalid")
            }
            expectedHead = activation.recordHash
        }
        guard expectedSequence == finalLifecycleSequence, expectedHead == finalLifecycleHead,
              expectedPinSequence == initialPinSequence + entries.count * 2 else {
            throw AgentPassNativeError.invalidSignature("Legacy migration adoption chain summary is inconsistent")
        }
    }
}

public struct NativeLegacyMigrationAdoptionResult: Equatable, Sendable {
    public let planHash: String
    public let initialLifecycleHead: String
    public let finalLifecycleSequence: Int
    public let finalLifecycleHead: String
    public let finalPinSequence: Int
    public let finalOutboxPinSequence: Int
    public let completedAt: String

    public func canonicalData() throws -> Data {
        try NativeAuditLog.canonical([
            "version": 1, "plan_hash": planHash, "initial_lifecycle_head": initialLifecycleHead,
            "final_lifecycle_sequence": finalLifecycleSequence, "final_lifecycle_head": finalLifecycleHead,
            "final_pin_sequence": finalPinSequence, "final_outbox_pin_sequence": finalOutboxPinSequence,
            "completed_at": completedAt
        ])
    }

    public static func decodeCanonical(_ data: Data, plan: NativeLegacyMigrationAdoptionPlan) throws -> Self {
        let keys: Set<String> = [
            "version", "plan_hash", "initial_lifecycle_head", "final_lifecycle_sequence",
            "final_lifecycle_head", "final_pin_sequence", "final_outbox_pin_sequence", "completed_at"
        ]
        guard data.count > 0, data.count <= 32 * 1024,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == keys,
              try NativeAuditLog.canonical(object) == data, object["version"] as? Int == 1,
              let planHash = object["plan_hash"] as? String, isHash(planHash),
              let initialHead = object["initial_lifecycle_head"] as? String, isHash(initialHead),
              let finalSequence = adoptionInt(object["final_lifecycle_sequence"]), finalSequence > 0,
              let finalHead = object["final_lifecycle_head"] as? String, isHash(finalHead),
              let pinSequence = adoptionInt(object["final_pin_sequence"]), pinSequence > 0,
              let outboxSequence = adoptionInt(object["final_outbox_pin_sequence"]), outboxSequence > 0,
              let completedAt = object["completed_at"] as? String,
              let completed = migrationDate(completedAt), let prepared = migrationDate(plan.preparedAt), completed >= prepared else {
            throw AgentPassNativeError.invalidSignature("Legacy migration adoption result is not exact canonical schema")
        }
        let result = Self(planHash: planHash, initialLifecycleHead: initialHead, finalLifecycleSequence: finalSequence,
                          finalLifecycleHead: finalHead, finalPinSequence: pinSequence,
                          finalOutboxPinSequence: outboxSequence, completedAt: completedAt)
        guard planHash == migrationHash(try plan.canonicalData()), initialHead == plan.initialLifecycleHead,
              finalSequence == plan.finalLifecycleSequence, finalHead == plan.finalLifecycleHead,
              pinSequence == plan.initialPinSequence + plan.entries.count * 2,
              outboxSequence == plan.initialOutboxPinSequence + plan.entries.count * 2,
              try result.canonicalData() == data else {
            throw AgentPassNativeError.invalidSignature("Legacy migration adoption result does not match its exact plan")
        }
        return result
    }
}

/// Sequential builder for a final adoption plan. A caller may persist each entry's canonical bytes
/// and restore them after a crash. No lifecycle, pin, or outbox mutation occurs while building.
public final class NativeLegacyMigrationAdoptionBuilder: @unchecked Sendable {
    private let manifestData: Data
    private let receiptBytes: [Data]
    private let manifest: NativeLegacyMigrationCompletionManifest
    private let receipts: [NativeLegacyMigrationReceipt]
    private let observedTargets: [NativeKeyRole: NativeLegacyMigrationObservedTargetKey]
    private let preparedAt: String
    private let verifier: any NativeLifecycleSignatureVerifier
    private let lock = NSLock()
    private var committedEntries: [NativeLegacyMigrationAdoptionEntry] = []

    public init(store: NativeKeyLifecycleStore, pinTransaction: NativeLifecyclePinTransaction, mutationOutbox: NativeLifecycleMutationOutbox, completionManifestData: Data, receiptData: [Data], observedTargetKeys: [NativeLegacyMigrationObservedTargetKey], verifier: any NativeLifecycleSignatureVerifier = NativeP256LifecycleVerifier()) throws {
        let manifest = try NativeLegacyMigrationCompletionManifest.decodeCanonical(completionManifestData, verifier: verifier)
        let receipts = try receiptData.map(NativeLegacyMigrationReceipt.decodeCanonical)
        try manifest.verify(receipts: receipts, verifier: verifier)
        let state = try store.verify()
        let pin = try pinTransaction.current()
        let outbox = try mutationOutbox.current()
        guard try pinTransaction.pending() == nil, try mutationOutbox.pending() == nil,
              state.sequence == 0, state.headHash == NativeKeyLifecycleStore.zeroHash, state.generations.isEmpty,
              manifest.initialLifecycleHead == state.headHash,
              pin == nil, outbox == nil else {
            throw AgentPassNativeError.invalidSignature("Legacy migration adoption requires matching pristine ledger, pin, and outbox heads")
        }
        let observed = try Self.validateObservedTargets(observedTargetKeys, receipts: receipts)
        self.manifestData = completionManifestData; self.receiptBytes = receiptData
        self.manifest = manifest; self.receipts = receipts; self.observedTargets = observed
        self.preparedAt = manifest.completedAt; self.verifier = verifier
    }

    public var committedCount: Int {
        lock.lock(); defer { lock.unlock() }
        return committedEntries.count
    }

    public func nextSigningRequest() throws -> NativeLegacyMigrationAdoptionSigningRequest? {
        lock.lock(); defer { lock.unlock() }
        guard committedEntries.count < receipts.count else { return nil }
        return try nextSigningRequestLocked()
    }

    @discardableResult
    public func commit(_ request: NativeLegacyMigrationAdoptionSigningRequest, signatures: NativeLegacyMigrationAdoptionSignatures) throws -> NativeLegacyMigrationAdoptionEntry {
        lock.lock(); defer { lock.unlock() }
        if let existing = committedEntries.first(where: { $0.role == request.role }) {
            let existingActivation = try adoptionRecordView(existing.activationRecordData)
            guard try request == signingRequest(for: existing),
                  existingActivation.newSignature == signatures.replacementSignature,
                  existingActivation.approvalSignature == signatures.approvalSignature else {
                throw AgentPassNativeError.invalidSignature("Legacy migration adoption role was replayed with different bytes")
            }
            return existing
        }
        guard request == (try nextSigningRequestLocked()) else {
            throw AgentPassNativeError.invalidSignature("Legacy migration adoption signing request is stale or substituted")
        }
        let index = committedEntries.count
        let receipt = receipts[index]
        let migrationPlan = try NativeLegacyMigrationPlan.decodeCanonical(receipt.planData)
        guard verifier.isValid(signature: signatures.replacementSignature, message: request.transitionStatementData, publicKeyX963: migrationPlan.binding.newPublicKeyX963),
              verifier.isValid(signature: signatures.approvalSignature, message: request.transitionStatementData, publicKeyX963: manifest.approvalPublicKeyX963) else {
            throw AgentPassNativeError.invalidSignature("Legacy migration adoption lifecycle signatures are invalid")
        }
        let stage = try adoptionRecordView(request.stageRecordData)
        let statement = try NativeKeyTransitionStatement.decodeCanonical(request.transitionStatementData)
        let activation = try adoptionMakeLifecycleRecord(
            sequence: statement.stateSequence, previous: statement.previousLifecycleHead, action: "activated",
            role: request.role, generation: 1, applicationTag: stage.applicationTag,
            publicKey: stage.publicKeyX963, createdAt: preparedAt, continuity: .bootstrap,
            reason: statement.reason, challengeID: statement.challengeID,
            oldGeneration: 0, oldFingerprint: "", newSignature: signatures.replacementSignature,
            approvalSignature: signatures.approvalSignature, approvalPublicKey: manifest.approvalPublicKeyX963
        )
        let entry = NativeLegacyMigrationAdoptionEntry(
            role: request.role, migrationOperationID: receipt.operationID, receiptHash: request.receiptHash,
            helperIdentity: migrationPlan.helperIdentity, stageOperationID: request.stageOperationID,
            activationOperationID: request.activationOperationID, stageRecordData: request.stageRecordData,
            transitionStatementData: request.transitionStatementData, activationRecordData: activation
        )
        committedEntries.append(entry)
        return entry
    }

    /// Restores an fsync'd entry after restart. Only the exact next entry is accepted.
    @discardableResult
    public func restoreCommittedEntry(_ data: Data) throws -> NativeLegacyMigrationAdoptionEntry {
        let entry = try NativeLegacyMigrationAdoptionEntry.decodeCanonical(data)
        lock.lock(); defer { lock.unlock() }
        if let existing = committedEntries.first(where: { $0.role == entry.role }) {
            guard try existing.canonicalData() == data else {
                throw AgentPassNativeError.invalidSignature("Legacy migration adoption entry replay equivocates")
            }
            return existing
        }
        let request = try nextSigningRequestLocked()
        let activation = try adoptionRecordView(entry.activationRecordData)
        guard request == (try signingRequest(for: entry)) else {
            throw AgentPassNativeError.invalidSignature("Restored migration adoption entry is stale or out of order")
        }
        let signatures = NativeLegacyMigrationAdoptionSignatures(replacementSignature: activation.newSignature, approvalSignature: activation.approvalSignature)
        let index = committedEntries.count
        let migrationPlan = try NativeLegacyMigrationPlan.decodeCanonical(receipts[index].planData)
        guard verifier.isValid(signature: signatures.replacementSignature, message: request.transitionStatementData, publicKeyX963: migrationPlan.binding.newPublicKeyX963),
              verifier.isValid(signature: signatures.approvalSignature, message: request.transitionStatementData, publicKeyX963: manifest.approvalPublicKeyX963) else {
            throw AgentPassNativeError.invalidSignature("Restored migration adoption signatures are invalid")
        }
        let expectedActivation = try adoptionMakeLifecycleRecord(
            sequence: adoptionRecordView(request.stageRecordData).sequence + 1,
            previous: adoptionRecordView(request.stageRecordData).recordHash, action: "activated",
            role: request.role, generation: 1, applicationTag: observedTargets[request.role]!.applicationTag,
            publicKey: observedTargets[request.role]!.publicKeyX963, createdAt: preparedAt, continuity: .bootstrap,
            reason: try NativeKeyTransitionStatement.decodeCanonical(request.transitionStatementData).reason,
            challengeID: try NativeKeyTransitionStatement.decodeCanonical(request.transitionStatementData).challengeID,
            oldGeneration: 0, oldFingerprint: "", newSignature: signatures.replacementSignature,
            approvalSignature: signatures.approvalSignature, approvalPublicKey: manifest.approvalPublicKeyX963
        )
        guard expectedActivation == entry.activationRecordData else {
            throw AgentPassNativeError.invalidSignature("Restored migration adoption activation bytes were substituted")
        }
        committedEntries.append(entry)
        return entry
    }

    public func finalize() throws -> NativeLegacyMigrationAdoptionPlan {
        lock.lock(); defer { lock.unlock() }
        guard committedEntries.count == receipts.count else {
            throw AgentPassNativeError.invalidConfiguration("Legacy migration adoption signatures are incomplete")
        }
        let plan = NativeLegacyMigrationAdoptionPlan(
            completionManifestData: manifestData, receiptData: receiptBytes,
            initialLifecycleSequence: 0, initialLifecycleHead: NativeKeyLifecycleStore.zeroHash,
            initialPinSequence: 0, initialPinHead: "", initialOutboxPinSequence: 0,
            initialOutboxLifecycleSequence: 0, initialOutboxHead: "",
            entries: committedEntries, preparedAt: preparedAt
        )
        try plan.verify(verifier: verifier)
        return plan
    }

    private func nextSigningRequestLocked() throws -> NativeLegacyMigrationAdoptionSigningRequest {
        let index = committedEntries.count
        guard index < receipts.count else { throw AgentPassNativeError.invalidConfiguration("Legacy migration adoption is already complete") }
        let role = NativeLegacyMigrationCoordinator.requiredOrder[index]
        let receipt = receipts[index]
        let receiptHash = migrationHash(receiptBytes[index])
        let previousHead = try committedEntries.last.map { try adoptionRecordView($0.activationRecordData).recordHash } ?? NativeKeyLifecycleStore.zeroHash
        let sequence = index * 2 + 1
        let target = observedTargets[role]!
        let stage = try adoptionMakeLifecycleRecord(
            sequence: sequence, previous: previousHead, action: "staged", role: role,
            generation: 1, applicationTag: target.applicationTag, publicKey: target.publicKeyX963,
            createdAt: preparedAt, continuity: .clean
        )
        let stageView = try adoptionRecordView(stage)
        let statement = NativeKeyTransitionStatement(
            role: role, oldGeneration: 0, newGeneration: 1, oldFingerprint: "",
            newFingerprint: stageView.fingerprint, stateSequence: sequence + 1,
            reason: "legacy-v0.17-adoption:\(receiptHash)",
            challengeID: "legacy-migration:\(receipt.operationID.uuidString.lowercased())",
            createdAt: preparedAt, previousLifecycleHead: stageView.recordHash, continuity: .bootstrap
        )
        return .init(
            role: role, migrationOperationID: receipt.operationID, receiptHash: receiptHash,
            stageOperationID: adoptionOperationID(receiptHash: receiptHash, action: "staged"),
            activationOperationID: adoptionOperationID(receiptHash: receiptHash, action: "activated"),
            stageRecordData: stage, transitionStatementData: try statement.canonicalData()
        )
    }

    private func signingRequest(for entry: NativeLegacyMigrationAdoptionEntry) throws -> NativeLegacyMigrationAdoptionSigningRequest {
        .init(role: entry.role, migrationOperationID: entry.migrationOperationID, receiptHash: entry.receiptHash,
              stageOperationID: entry.stageOperationID, activationOperationID: entry.activationOperationID,
              stageRecordData: entry.stageRecordData, transitionStatementData: entry.transitionStatementData)
    }

    fileprivate static func validateObservedTargets(_ values: [NativeLegacyMigrationObservedTargetKey], receipts: [NativeLegacyMigrationReceipt]) throws -> [NativeKeyRole: NativeLegacyMigrationObservedTargetKey] {
        guard values.count == NativeLegacyMigrationCoordinator.requiredOrder.count,
              Set(values.map(\.role)).count == values.count else {
            throw AgentPassNativeError.invalidKey("Legacy migration requires exactly one observed generation-1 key per role")
        }
        var result: [NativeKeyRole: NativeLegacyMigrationObservedTargetKey] = [:]
        for (index, role) in NativeLegacyMigrationCoordinator.requiredOrder.enumerated() {
            let plan = try NativeLegacyMigrationPlan.decodeCanonical(receipts[index].planData)
            guard let observed = values.first(where: { $0.role == role }),
                  observed.applicationTag == NativeLegacyMigrationV017.newApplicationTags[role],
                  observed.publicKeyX963 == plan.binding.newPublicKeyX963,
                  validP256(observed.publicKeyX963) else {
                throw AgentPassNativeError.invalidKey("Orphaned or substituted legacy generation-1 key detected for \(role.rawValue)")
            }
            result[role] = observed
        }
        return result
    }
}

public extension NativeLegacyMigrationAdoptionPlan {
    /// Executes only a previously completed and durably stored plan. Every operation follows
    /// outbox -> pin preparation -> exact ledger append -> pin commit -> outbox completion.
    /// Restart recovery accepts only a prefix of this exact plan and permits the ledger to be at
    /// most one operation ahead of both durable commit chains.
    func execute(store: NativeKeyLifecycleStore, pinTransaction: NativeLifecyclePinTransaction, mutationOutbox: NativeLifecycleMutationOutbox, observedTargetKeys: [NativeLegacyMigrationObservedTargetKey], completedAt: String, verifier: any NativeLifecycleSignatureVerifier = NativeP256LifecycleVerifier()) throws -> NativeLegacyMigrationAdoptionResult {
        try verify(verifier: verifier)
        guard let completionDate = migrationDate(completedAt), let preparationDate = migrationDate(preparedAt),
              completionDate >= preparationDate else {
            throw AgentPassNativeError.invalidConfiguration("Legacy migration adoption completion time is invalid or predates its plan")
        }
        let receipts = try receiptData.map(NativeLegacyMigrationReceipt.decodeCanonical)
        _ = try NativeLegacyMigrationAdoptionBuilder.validateObservedTargets(observedTargetKeys, receipts: receipts)
        var state = try store.verify()
        let derivedHeads = try entries.flatMap { [try adoptionRecordView($0.stageRecordData).recordHash, try adoptionRecordView($0.activationRecordData).recordHash] }
        let heads = [initialLifecycleHead] + derivedHeads
        guard state.sequence >= initialLifecycleSequence,
              state.sequence <= finalLifecycleSequence,
              state.headHash == heads[state.sequence - initialLifecycleSequence] else {
            throw AgentPassNativeError.invalidSignature("Lifecycle ledger is not an exact prefix of the migration adoption plan")
        }
        let pinCurrent = try pinTransaction.current()
        let outboxCurrent = try mutationOutbox.current()
        let pinPrefix = (pinCurrent?.sequence ?? initialPinSequence) - initialPinSequence
        let outboxPrefix = (outboxCurrent?.pinSequence ?? initialOutboxPinSequence) - initialOutboxPinSequence
        let ledgerPrefix = state.sequence - initialLifecycleSequence
        guard (0...entries.count * 2).contains(pinPrefix), (0...entries.count * 2).contains(outboxPrefix),
              ledgerPrefix >= pinPrefix, ledgerPrefix - pinPrefix <= 1,
              ledgerPrefix >= outboxPrefix, ledgerPrefix - outboxPrefix <= 1,
              pinCurrent.map({ $0.newLifecycleHead == heads[pinPrefix] }) ?? (pinPrefix == 0),
              outboxCurrent.map({ $0.newLifecycleHead == heads[outboxPrefix] && $0.lifecycleSequence == initialLifecycleSequence + outboxPrefix }) ?? (outboxPrefix == 0) else {
            throw AgentPassNativeError.invalidSignature("Lifecycle ledger, pin, and outbox are divergent from the adoption plan")
        }

        let operations: [(UUID, NativeKeyRole, NativeLifecycleMutationKind, NativeLifecyclePinAction, Data)] = entries.flatMap {
            [($0.stageOperationID, $0.role, .staged, .staged, $0.stageRecordData),
             ($0.activationOperationID, $0.role, .activated, .activated, $0.activationRecordData)]
        }
        for (offset, operation) in operations.enumerated() {
            let lifecycleSequence = initialLifecycleSequence + offset + 1
            let pinSequence = initialPinSequence + offset + 1
            let oldHead = heads[offset], newHead = heads[offset + 1]
            let view = try adoptionRecordView(operation.4)
            guard view.sequence == lifecycleSequence, view.previousRecordHash == oldHead, view.recordHash == newHead else {
                throw AgentPassNativeError.invalidSignature("Adoption operation does not match its exact lifecycle position")
            }
            let outbox = try mutationOutbox.prepare(operationID: operation.0, pinSequence: pinSequence, role: operation.1, kind: operation.2, lifecycleSequence: lifecycleSequence, oldLifecycleHead: oldHead, newLifecycleHead: newHead, createdAt: view.createdAt, payload: operation.4)
            let pin = try pinTransaction.prepare(operationID: operation.0, sequence: pinSequence, role: operation.1, action: operation.3, oldLifecycleHead: oldHead, newLifecycleHead: newHead, preparedAt: view.createdAt)
            if state.sequence == lifecycleSequence - 1 {
                guard state.headHash == oldHead else { throw AgentPassNativeError.invalidSignature("Adoption lifecycle prefix changed during execution") }
                state = try store.appendPreparedRecordData(operation.4)
            } else {
                guard state.sequence >= lifecycleSequence,
                      state.headHash == heads[state.sequence - initialLifecycleSequence] else {
                    throw AgentPassNativeError.invalidSignature("Adoption retry observed a substituted lifecycle suffix")
                }
            }
            _ = try pinTransaction.commit(pin, observedOldLifecycleHead: oldHead, observedNewLifecycleHead: newHead)
            _ = try mutationOutbox.complete(outbox, observedNewLifecycleHead: newHead)
        }
        state = try store.verify(expectedHeadHash: finalLifecycleHead)
        guard state.sequence == finalLifecycleSequence,
              try pinTransaction.current()?.sequence == initialPinSequence + entries.count * 2,
              try pinTransaction.current()?.newLifecycleHead == finalLifecycleHead,
              try mutationOutbox.current()?.pinSequence == initialPinSequence + entries.count * 2,
              try mutationOutbox.current()?.newLifecycleHead == finalLifecycleHead else {
            throw AgentPassNativeError.invalidSignature("Legacy migration adoption did not converge all durable heads")
        }
        return .init(planHash: migrationHash(try canonicalData()), initialLifecycleHead: initialLifecycleHead,
                     finalLifecycleSequence: state.sequence, finalLifecycleHead: state.headHash,
                     finalPinSequence: initialPinSequence + entries.count * 2,
                     finalOutboxPinSequence: initialOutboxPinSequence + entries.count * 2,
                     completedAt: completedAt)
    }
}

private struct NativeLegacyAdoptionRecordView {
    let sequence: Int; let previousRecordHash: String; let action: String; let role: NativeKeyRole
    let generation: Int; let applicationTag: String; let publicKeyX963: Data; let fingerprint: String
    let createdAt: String; let continuity: NativeKeyContinuity; let reason: String; let challengeID: String
    let oldGeneration: Int; let oldFingerprint: String; let oldSignature: Data; let newSignature: Data
    let approvalSignature: Data; let approvalPublicKeyX963: Data; let minimumRetirementAgeSeconds: Int
    let transitionArchived: Bool; let externallyPinnedHeadHash: String; let recordHash: String
    var isEmptyTransition: Bool {
        reason.isEmpty && challengeID.isEmpty && oldGeneration == 0 && oldFingerprint.isEmpty && oldSignature.isEmpty &&
        newSignature.isEmpty && approvalSignature.isEmpty && approvalPublicKeyX963.isEmpty &&
        minimumRetirementAgeSeconds == 0 && !transitionArchived && externallyPinnedHeadHash.isEmpty
    }
}

private let adoptionLifecycleRecordKeys: Set<String> = [
    "version", "sequence", "previous_record_hash", "action", "role", "generation", "application_tag",
    "public_key", "fingerprint", "created_at", "continuity", "reason", "challenge_id", "old_generation",
    "old_fingerprint", "old_signature", "new_signature", "approval_signature", "approval_public_key",
    "minimum_retirement_age_seconds", "transition_archived", "externally_pinned_head_hash", "record_hash"
]

private func adoptionMakeLifecycleRecord(sequence: Int, previous: String, action: String, role: NativeKeyRole, generation: Int, applicationTag: String, publicKey: Data, createdAt: String, continuity: NativeKeyContinuity, reason: String = "", challengeID: String = "", oldGeneration: Int = 0, oldFingerprint: String = "", oldSignature: Data = Data(), newSignature: Data = Data(), approvalSignature: Data = Data(), approvalPublicKey: Data = Data()) throws -> Data {
    var object: [String: Any] = [
        "version": 1, "sequence": sequence, "previous_record_hash": previous, "action": action,
        "role": role.rawValue, "generation": generation, "application_tag": applicationTag,
        "public_key": publicKey.base64EncodedString(), "fingerprint": NativeKeyLifecycleStore.fingerprint(publicKey),
        "created_at": createdAt, "continuity": continuity.rawValue, "reason": reason,
        "challenge_id": challengeID, "old_generation": oldGeneration, "old_fingerprint": oldFingerprint,
        "old_signature": oldSignature.base64EncodedString(), "new_signature": newSignature.base64EncodedString(),
        "approval_signature": approvalSignature.base64EncodedString(), "approval_public_key": approvalPublicKey.base64EncodedString(),
        "minimum_retirement_age_seconds": 0, "transition_archived": false, "externally_pinned_head_hash": ""
    ]
    let unsigned = try NativeAuditLog.canonical(object)
    object["record_hash"] = migrationHash(unsigned)
    return try NativeAuditLog.canonical(object)
}

private func adoptionRecordView(_ data: Data) throws -> NativeLegacyAdoptionRecordView {
    guard data.count > 0, data.count <= 1_048_576,
          let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == adoptionLifecycleRecordKeys,
          try NativeAuditLog.canonical(object) == data, object["version"] as? Int == 1,
          let sequence = adoptionInt(object["sequence"]), sequence > 0,
          let previous = object["previous_record_hash"] as? String, isHash(previous),
          let action = object["action"] as? String, action == "staged" || action == "activated",
          let roleText = object["role"] as? String, let role = NativeKeyRole(rawValue: roleText),
          let generation = adoptionInt(object["generation"]), generation > 0,
          let applicationTag = strictString(object, "application_tag", maximum: 512),
          let publicText = object["public_key"] as? String, let publicKey = canonicalBase64(publicText), validP256(publicKey),
          let fingerprint = object["fingerprint"] as? String, fingerprint == NativeKeyLifecycleStore.fingerprint(publicKey),
          let createdAt = object["created_at"] as? String, migrationDate(createdAt) != nil,
          let continuityText = object["continuity"] as? String, let continuity = NativeKeyContinuity(rawValue: continuityText),
          let reason = object["reason"] as? String, let challengeID = object["challenge_id"] as? String,
          let oldGeneration = adoptionInt(object["old_generation"]), oldGeneration >= 0,
          let oldFingerprint = object["old_fingerprint"] as? String,
          let oldText = object["old_signature"] as? String, let oldSignature = canonicalBase64(oldText),
          let newText = object["new_signature"] as? String, let newSignature = canonicalBase64(newText),
          let approvalText = object["approval_signature"] as? String, let approvalSignature = canonicalBase64(approvalText),
          let approvalKeyText = object["approval_public_key"] as? String, let approvalKey = canonicalBase64(approvalKeyText),
          let minimumAge = adoptionInt(object["minimum_retirement_age_seconds"]), minimumAge >= 0,
          let archived = object["transition_archived"] as? Bool,
          let externalHead = object["externally_pinned_head_hash"] as? String,
          let recordHash = object["record_hash"] as? String, isHash(recordHash) else {
        throw AgentPassNativeError.invalidSignature("Legacy migration lifecycle record is not exact canonical schema")
    }
    return .init(sequence: sequence, previousRecordHash: previous, action: action, role: role,
                 generation: generation, applicationTag: applicationTag, publicKeyX963: publicKey,
                 fingerprint: fingerprint, createdAt: createdAt, continuity: continuity, reason: reason,
                 challengeID: challengeID, oldGeneration: oldGeneration, oldFingerprint: oldFingerprint,
                 oldSignature: oldSignature, newSignature: newSignature, approvalSignature: approvalSignature,
                 approvalPublicKeyX963: approvalKey, minimumRetirementAgeSeconds: minimumAge,
                 transitionArchived: archived, externallyPinnedHeadHash: externalHead, recordHash: recordHash)
}

private func adoptionRecordHash(_ data: Data) -> String {
    guard var object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return "" }
    object.removeValue(forKey: "record_hash")
    guard let unsigned = try? NativeAuditLog.canonical(object) else { return "" }
    return migrationHash(unsigned)
}

private func adoptionOperationID(receiptHash: String, action: String) -> UUID {
    var bytes = Array(SHA256.hash(data: Data("agentpass-v0.17-adoption-v1:\(receiptHash):\(action)".utf8)).prefix(16))
    bytes[6] = (bytes[6] & 0x0f) | 0x50
    bytes[8] = (bytes[8] & 0x3f) | 0x80
    return UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
}

private func adoptionUUID(_ value: Any?) -> UUID? {
    guard let text = value as? String, let id = UUID(uuidString: text), id.uuidString.lowercased() == text else { return nil }
    return id
}

private func adoptionInt(_ value: Any?) -> Int? {
    guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
    let result = number.intValue
    return number.stringValue == String(result) ? result : nil
}

private func migrationHash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
private func migrationLifecycleHead(plan: NativeLegacyMigrationPlan) throws -> String {
    migrationHash(try NativeAuditLog.canonical([
        "domain": "agentpass-legacy-migration-head-v1", "previous_lifecycle_head": plan.previousLifecycleHead,
        "plan_hash": migrationHash(try plan.canonicalData()), "operation_id": plan.operationID.uuidString.lowercased(),
        "role": plan.role.rawValue,
        "old_fingerprint": NativeKeyLifecycleStore.fingerprint(plan.binding.oldPublicKeyX963),
        "new_fingerprint": NativeKeyLifecycleStore.fingerprint(plan.binding.newPublicKeyX963)
    ]))
}
private func isHash(_ value: String) -> Bool { value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil }
private func isHexHash(_ value: String) -> Bool { value.range(of: "^[0-9a-f]{40,128}$", options: .regularExpression) != nil }
private func isFingerprint(_ value: String) -> Bool { value.range(of: "^SHA256:[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil }
private func validP256(_ data: Data) -> Bool { data.count == 65 && data.first == 0x04 && (try? P256.Signing.PublicKey(x963Representation: data)) != nil }
private func canonicalBase64(_ value: String) -> Data? { guard let data = Data(base64Encoded: value), data.base64EncodedString() == value else { return nil }; return data }
private func strictString(_ object: [String: Any], _ key: String, maximum: Int) -> String? { guard let value = object[key] as? String, !value.isEmpty, value.utf8.count <= maximum, !value.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7f }) else { return nil }; return value }
private func migrationDate(_ value: String) -> Date? { let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]; return formatter.date(from: value) }
private func migrationTimestamp(_ date: Date) -> String { let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]; return formatter.string(from: date) }
