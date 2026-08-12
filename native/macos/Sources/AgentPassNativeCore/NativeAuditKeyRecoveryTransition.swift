import CryptoKit
import Foundation

/// Canonical IEEE-P1363 encoding for P-256 signatures. ECDSA admits the
/// equivalent `(r, n-s)` form; schema-v3 hashes signature bytes, so accepting
/// both forms would make one authorization have two transition identities.
public enum NativeP256CanonicalSignature {
    private static let order = Data([
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
    ])
    private static let halfOrder = Data([
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42,
        0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8
    ])

    public static func canonicalized(_ signature: Data) throws -> Data {
        guard signature.count == 64,
              (try? P256.Signing.ECDSASignature(rawRepresentation: signature)) != nil else {
            throw AgentPassNativeError.invalidSignature("P-256 signature is not valid 64-byte IEEE-P1363")
        }
        let s = Data(signature.suffix(32))
        if compare(s, halfOrder) <= 0 { return signature }
        var result = Data(signature.prefix(32))
        result.append(subtract(order, s))
        guard isCanonicalLowS(result) else {
            throw AgentPassNativeError.invalidSignature("P-256 signature could not be canonicalized")
        }
        return result
    }

    public static func isCanonicalLowS(_ signature: Data) -> Bool {
        guard signature.count == 64,
              (try? P256.Signing.ECDSASignature(rawRepresentation: signature)) != nil else { return false }
        return compare(Data(signature.suffix(32)), halfOrder) <= 0
    }

    private static func compare(_ lhs: Data, _ rhs: Data) -> Int {
        for (left, right) in zip(lhs, rhs) {
            if left < right { return -1 }
            if left > right { return 1 }
        }
        return 0
    }

    private static func subtract(_ lhs: Data, _ rhs: Data) -> Data {
        var output = [UInt8](repeating: 0, count: lhs.count)
        let left = [UInt8](lhs), right = [UInt8](rhs)
        var borrow = 0
        for index in stride(from: lhs.count - 1, through: 0, by: -1) {
            var value = Int(left[index]) - Int(right[index]) - borrow
            if value < 0 { value += 256; borrow = 1 } else { borrow = 0 }
            output[index] = UInt8(value)
        }
        return Data(output)
    }
}

/// Node anchor schema-v3 recovery policy. The policy hash is SHA-256 over the
/// canonical policy object with `policy_hash` omitted.
public struct NativeAuditKeyRecoveryPolicyKey: Codable, Equatable, Sendable {
    public let id: String
    public let publicKey: String
    public let fingerprint: String

    enum CodingKeys: String, CodingKey, CaseIterable {
        case id, fingerprint
        case publicKey = "public_key"
    }

    public init(id: String, publicKey: Curve25519.Signing.PublicKey) throws {
        self.id = id
        let identity = NativeAuditKeyRecoveryTransitionCrypto.ed25519Identity(publicKey)
        self.publicKey = identity.pem
        fingerprint = identity.fingerprint
        try validate()
    }

    fileprivate func validate() throws {
        guard NativeAuditKeyRecoveryTransitionCrypto.isSlug(id) else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery policy key ID is invalid")
        }
        let identity = try NativeAuditKeyRecoveryTransitionCrypto.ed25519Identity(publicKey)
        guard publicKey == identity.pem, fingerprint == identity.fingerprint else {
            throw AgentPassNativeError.invalidKey("Audit-key recovery policy key is not canonical or has the wrong fingerprint")
        }
    }

    fileprivate func object() -> [String: Any] {
        ["id": id, "public_key": publicKey, "fingerprint": fingerprint]
    }
}

public struct NativeAuditKeyRecoveryPolicy: Codable, Equatable, Sendable {
    public static let version = 1
    public let version: Int
    public let policyID: String
    public let threshold: Int
    public let keys: [NativeAuditKeyRecoveryPolicyKey]
    public let policyHash: String

    enum CodingKeys: String, CodingKey, CaseIterable {
        case version, threshold, keys
        case policyID = "policy_id"
        case policyHash = "policy_hash"
    }

    public init(policyID: String, threshold: Int, keys: [NativeAuditKeyRecoveryPolicyKey]) throws {
        version = Self.version
        self.policyID = policyID
        self.threshold = threshold
        self.keys = keys.sorted { $0.id < $1.id }
        policyHash = NativeAuditLog.hash(try NativeAuditLog.canonical(Self.object(
            version: version, policyID: policyID, threshold: threshold, keys: self.keys, policyHash: nil
        )))
        try validate()
    }

    /// Converts AgentPass's offline `authorities` policy into the Node anchor's
    /// pinned `keys` policy. The two hashes intentionally cover different
    /// canonical schemas and must never be substituted for one another.
    public static func convertingAuthoritiesPolicy(_ data: Data) throws -> NativeAuditKeyRecoveryPolicyConversion {
        let metadata = try NativeRecoveryVerifier.policyMetadata(data)
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == ["version", "policy_id", "threshold", "authorities"],
              object["version"] as? Int == 1, object["policy_id"] as? String == metadata.id,
              object["threshold"] as? Int == metadata.threshold,
              let authorities = object["authorities"] as? [[String: Any]],
              try NativeAuditLog.canonical(object) == data else {
            throw AgentPassNativeError.invalidSignature("Offline recovery authorities policy is not canonical")
        }
        let keys = try authorities.map { authority -> NativeAuditKeyRecoveryPolicyKey in
            guard Set(authority.keys) == ["id", "public_key"], let id = authority["id"] as? String,
                  let pem = authority["public_key"] as? String else {
                throw AgentPassNativeError.invalidSignature("Offline recovery authority encoding is invalid")
            }
            let identity = try NativeAuditKeyRecoveryTransitionCrypto.ed25519IdentityFromAuthoritiesPEM(pem)
            return try NativeAuditKeyRecoveryPolicyKey(id: id, publicKey: identity.key)
        }
        let converted = try Self(policyID: metadata.id, threshold: metadata.threshold, keys: keys)
        guard converted.keys.map(\.fingerprint).sorted() == metadata.authorityPublicKeyFingerprints else {
            throw AgentPassNativeError.invalidSignature("Offline and anchor recovery policy identities diverge")
        }
        return NativeAuditKeyRecoveryPolicyConversion(
            authoritiesPolicyHash: metadata.hash,
            anchorPolicy: converted
        )
    }

    public func canonicalData() throws -> Data {
        let data = try NativeAuditLog.canonical(object(includeHash: true))
        guard data.count <= 256 * 1024 else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key recovery policy is too large")
        }
        return data
    }

    public static func decodeCanonical(_ data: Data) throws -> Self {
        guard !data.isEmpty, data.count <= 256 * 1024,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set(CodingKeys.allCases.map(\.stringValue)) else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery policy encoding is invalid")
        }
        let value = try JSONDecoder().decode(Self.self, from: data)
        try value.validate()
        guard try value.canonicalData() == data else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery policy is not canonically encoded")
        }
        return value
    }

    fileprivate func validate() throws {
        guard version == Self.version, NativeAuditKeyRecoveryTransitionCrypto.isSlug(policyID),
              !keys.isEmpty, keys.count <= 16, threshold > 0, threshold <= keys.count,
              keys.map(\.id) == keys.map(\.id).sorted(),
              Set(keys.map(\.id)).count == keys.count,
              Set(keys.map(\.fingerprint)).count == keys.count else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery policy is invalid")
        }
        try keys.forEach { try $0.validate() }
        let expected = NativeAuditLog.hash(try NativeAuditLog.canonical(object(includeHash: false)))
        guard policyHash == expected else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery policy hash is invalid")
        }
    }

    fileprivate func object(includeHash: Bool) -> [String: Any] {
        Self.object(version: version, policyID: policyID, threshold: threshold, keys: keys, policyHash: includeHash ? policyHash : nil)
    }

    private static func object(version: Int, policyID: String, threshold: Int, keys: [NativeAuditKeyRecoveryPolicyKey], policyHash: String?) -> [String: Any] {
        var result: [String: Any] = [
            "version": version, "policy_id": policyID, "threshold": threshold,
            "keys": keys.map { $0.object() }
        ]
        if let policyHash { result["policy_hash"] = policyHash }
        return result
    }
}

public struct NativeAuditKeyRecoveryPolicyConversion: Equatable, Sendable {
    /// SHA-256 of the canonical `{authorities:[...]}` source document.
    public let authoritiesPolicyHash: String
    /// Canonical anchor policy with sorted `keys`, fingerprints, and its own hash.
    public let anchorPolicy: NativeAuditKeyRecoveryPolicy
}

/// Exact schema-v3 authorization signed by every recovery authority and by the
/// replacement P-256 audit key.
public struct NativeAuditKeyRecoveryAuthorization: Codable, Equatable, Sendable {
    public static let version = 3
    public static let maximumAuthorizationMilliseconds: Int64 = 15 * 60 * 1_000
    public static let maximumClockSkewMilliseconds: Int64 = 5_000

    public let version: Int
    public let tenant: String
    public let installationID: String
    public let role: String
    public let operationID: String
    public let recoveryRequestID: String
    public let recoveryPolicyID: String
    public let recoveryPolicyHash: String
    public let fromGeneration: Int
    public let toGeneration: Int
    public let oldKeyFingerprint: String
    public let newKeyFingerprint: String
    public let newPublicKey: String
    public let lifecycleHeadHash: String
    public let createdAt: String
    public let expiresAt: String
    public let previousTransitionHash: String
    public let previousTransitionReceiptHash: String
    public let lastCheckpointIndex: Int
    public let lastCheckpointHash: String
    public let lastCheckpointReceiptHash: String
    public let previousAnchorEventIndex: Int
    public let previousAnchorEventHash: String
    public let retiringGenerationPendingCheckpointCount: Int

    enum CodingKeys: String, CodingKey, CaseIterable {
        case version, tenant, role
        case installationID = "installation_id"
        case operationID = "operation_id"
        case recoveryRequestID = "recovery_request_id"
        case recoveryPolicyID = "recovery_policy_id"
        case recoveryPolicyHash = "recovery_policy_hash"
        case fromGeneration = "from_generation"
        case toGeneration = "to_generation"
        case oldKeyFingerprint = "old_key_fingerprint"
        case newKeyFingerprint = "new_key_fingerprint"
        case newPublicKey = "new_public_key"
        case lifecycleHeadHash = "lifecycle_head_hash"
        case createdAt = "created_at"
        case expiresAt = "expires_at"
        case previousTransitionHash = "previous_transition_hash"
        case previousTransitionReceiptHash = "previous_transition_receipt_hash"
        case lastCheckpointIndex = "last_checkpoint_index"
        case lastCheckpointHash = "last_checkpoint_hash"
        case lastCheckpointReceiptHash = "last_checkpoint_receipt_hash"
        case previousAnchorEventIndex = "previous_anchor_event_index"
        case previousAnchorEventHash = "previous_anchor_event_hash"
        case retiringGenerationPendingCheckpointCount = "retiring_generation_pending_checkpoint_count"
    }

    public init(
        tenant: String, installationID: String, operationID: String, recoveryRequestID: String,
        policy: NativeAuditKeyRecoveryPolicy, fromGeneration: Int, oldPublicKeyX963: Data,
        newPublicKeyX963: Data, lifecycleHeadHash: String, createdAt: String, expiresAt: String,
        previousTransitionHash: String, previousTransitionReceiptHash: String,
        lastCheckpointIndex: Int, lastCheckpointHash: String, lastCheckpointReceiptHash: String,
        previousAnchorEventIndex: Int, previousAnchorEventHash: String,
        retiringGenerationPendingCheckpointCount: Int = 0
    ) throws {
        version = Self.version; self.tenant = tenant; self.installationID = installationID
        role = NativeKeyRole.auditCheckpoint.rawValue; self.operationID = operationID
        self.recoveryRequestID = recoveryRequestID; recoveryPolicyID = policy.policyID
        recoveryPolicyHash = policy.policyHash; self.fromGeneration = fromGeneration
        toGeneration = fromGeneration + 1
        oldKeyFingerprint = NativeAuditCheckpoints.fingerprint(oldPublicKeyX963)
        newKeyFingerprint = NativeAuditCheckpoints.fingerprint(newPublicKeyX963)
        newPublicKey = try SSHSIG.authorizedKey(publicKeyX963: newPublicKeyX963)
        self.lifecycleHeadHash = lifecycleHeadHash; self.createdAt = createdAt; self.expiresAt = expiresAt
        self.previousTransitionHash = previousTransitionHash
        self.previousTransitionReceiptHash = previousTransitionReceiptHash
        self.lastCheckpointIndex = lastCheckpointIndex; self.lastCheckpointHash = lastCheckpointHash
        self.lastCheckpointReceiptHash = lastCheckpointReceiptHash
        self.previousAnchorEventIndex = previousAnchorEventIndex; self.previousAnchorEventHash = previousAnchorEventHash
        self.retiringGenerationPendingCheckpointCount = retiringGenerationPendingCheckpointCount
        try validate()
    }

    public func canonicalData() throws -> Data {
        let data = try NativeAuditLog.canonical(object())
        guard data.count <= NativeAuditKeyTransitionStatement.maximumEncodedBytes else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key recovery authorization is too large")
        }
        return data
    }

    fileprivate func validate(nowMilliseconds: Int64? = nil) throws {
        guard version == Self.version, NativeAuditKeyRecoveryTransitionCrypto.isSlug(tenant),
              NativeAuditKeyRecoveryTransitionCrypto.isSlug(installationID), role == NativeKeyRole.auditCheckpoint.rawValue,
              NativeAuditKeyRecoveryTransitionCrypto.isSlug(operationID), NativeAuditKeyRecoveryTransitionCrypto.isSlug(recoveryRequestID),
              NativeAuditKeyRecoveryTransitionCrypto.isSlug(recoveryPolicyID), NativeAuditKeyRecoveryTransitionCrypto.isHash(recoveryPolicyHash),
              fromGeneration > 0, fromGeneration < NativeAuditKeyTransitionStatement.maximumSafeInteger,
              toGeneration == fromGeneration + 1, oldKeyFingerprint != newKeyFingerprint,
              NativeAuditKeyRecoveryTransitionCrypto.isFingerprint(oldKeyFingerprint),
              NativeAuditKeyRecoveryTransitionCrypto.isFingerprint(newKeyFingerprint),
              NativeAuditKeyRecoveryTransitionCrypto.isHash(lifecycleHeadHash),
              NativeAuditKeyRecoveryTransitionCrypto.isHash(previousTransitionHash),
              NativeAuditKeyRecoveryTransitionCrypto.isHash(previousTransitionReceiptHash),
              lastCheckpointIndex > 0, lastCheckpointIndex <= NativeAuditKeyTransitionStatement.maximumSafeInteger,
              NativeAuditKeyRecoveryTransitionCrypto.isHash(lastCheckpointHash),
              NativeAuditKeyRecoveryTransitionCrypto.isHash(lastCheckpointReceiptHash),
              previousAnchorEventIndex > 0, previousAnchorEventIndex <= NativeAuditKeyTransitionStatement.maximumSafeInteger,
              NativeAuditKeyRecoveryTransitionCrypto.isHash(previousAnchorEventHash),
              retiringGenerationPendingCheckpointCount == 0,
              let created = Self.canonicalTimestamp(createdAt), let expires = Self.canonicalTimestamp(expiresAt),
              expires > created,
              Int64((expires.timeIntervalSince(created) * 1_000).rounded()) <= Self.maximumAuthorizationMilliseconds else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery authorization statement is invalid")
        }
        let replacement = try SSHSIG.p256PublicKey(fromAuthorizedKey: newPublicKey)
        guard newPublicKey == (try SSHSIG.authorizedKey(publicKeyX963: replacement)),
              newKeyFingerprint == NativeAuditCheckpoints.fingerprint(replacement) else {
            throw AgentPassNativeError.invalidKey("Audit-key recovery replacement identity is invalid")
        }
        if let nowMilliseconds {
            let createdMS = Int64((created.timeIntervalSince1970 * 1_000).rounded())
            let expiresMS = Int64((expires.timeIntervalSince1970 * 1_000).rounded())
            let latestAllowedCreation = nowMilliseconds > Int64.max - Self.maximumClockSkewMilliseconds
                ? Int64.max : nowMilliseconds + Self.maximumClockSkewMilliseconds
            guard createdMS <= latestAllowedCreation,
                  nowMilliseconds <= expiresMS else {
                throw AgentPassNativeError.invalidSignature("Audit-key recovery authorization is expired or future-dated")
            }
        }
        _ = try canonicalData()
    }

    fileprivate func object() -> [String: Any] {
        [
            "version": version, "tenant": tenant, "installation_id": installationID, "role": role,
            "operation_id": operationID, "recovery_request_id": recoveryRequestID,
            "recovery_policy_id": recoveryPolicyID, "recovery_policy_hash": recoveryPolicyHash,
            "from_generation": fromGeneration, "to_generation": toGeneration,
            "old_key_fingerprint": oldKeyFingerprint, "new_key_fingerprint": newKeyFingerprint,
            "new_public_key": newPublicKey, "lifecycle_head_hash": lifecycleHeadHash,
            "created_at": createdAt, "expires_at": expiresAt,
            "previous_transition_hash": previousTransitionHash,
            "previous_transition_receipt_hash": previousTransitionReceiptHash,
            "last_checkpoint_index": lastCheckpointIndex, "last_checkpoint_hash": lastCheckpointHash,
            "last_checkpoint_receipt_hash": lastCheckpointReceiptHash,
            "previous_anchor_event_index": previousAnchorEventIndex,
            "previous_anchor_event_hash": previousAnchorEventHash,
            "retiring_generation_pending_checkpoint_count": retiringGenerationPendingCheckpointCount
        ]
    }

    fileprivate static func canonicalTimestamp(_ value: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard let date = formatter.date(from: value) else { return nil }
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        return formatter.string(from: date) == value ? date : nil
    }
}

public struct NativeAuditKeyRecoveryApproval: Codable, Equatable, Sendable {
    public let keyID: String
    public let signature: String
    enum CodingKeys: String, CodingKey, CaseIterable { case keyID = "key_id"; case signature }

    public init(keyID: String, signature: String) throws {
        guard NativeAuditKeyRecoveryTransitionCrypto.isSlug(keyID),
              NativeAuditKeyRecoveryTransitionCrypto.signature(signature) != nil else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery approval encoding is invalid")
        }
        self.keyID = keyID; self.signature = signature
    }

    public init(keyID: String, signature: Data) throws {
        guard signature.count == 64 else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery approval must be a 64-byte Ed25519 signature")
        }
        try self.init(keyID: keyID, signature: signature.base64EncodedString())
    }
    fileprivate func object() -> [String: Any] { ["key_id": keyID, "signature": signature] }
}

public struct NativeAuditKeyRecoveryEvidence: Codable, Equatable, Sendable {
    public let version: Int
    public let policy: NativeAuditKeyRecoveryPolicy
    public let authorization: NativeAuditKeyRecoveryAuthorization
    public let approvals: [NativeAuditKeyRecoveryApproval]
    enum CodingKeys: String, CodingKey, CaseIterable { case version, policy, authorization, approvals }
    fileprivate func object() -> [String: Any] {
        ["version": version, "policy": policy.object(includeHash: true),
         "authorization": authorization.object(), "approvals": approvals.map { $0.object() }]
    }

    public func canonicalData() throws -> Data {
        let data = try NativeAuditLog.canonical(object())
        guard !data.isEmpty, data.count <= NativeAuditKeyRecoveryTransition.maximumEncodedBytes else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key recovery evidence is too large")
        }
        return data
    }

    /// Decodes the offline anchor ceremony only against caller-pinned trust.
    /// The embedded policy is untrusted input and can never establish its own
    /// authority. Replacement-key possession is verified later when the exact
    /// transition is constructed inside the service.
    public static func decodeCanonical(
        _ data: Data,
        pinnedPolicy: NativeAuditKeyRecoveryPolicy,
        expectedAuthorization: NativeAuditKeyRecoveryAuthorization,
        expectedInstallationID: String,
        nowMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1_000)
    ) throws -> Self {
        guard !data.isEmpty, data.count <= NativeAuditKeyRecoveryTransition.maximumEncodedBytes,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set(CodingKeys.allCases.map(\.stringValue)) else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery evidence encoding is invalid")
        }
        let value = try JSONDecoder().decode(Self.self, from: data)
        guard value.version == 1, value.policy == pinnedPolicy,
              value.authorization == expectedAuthorization,
              value.authorization.installationID == expectedInstallationID,
              try NativeAuditLog.canonical(value.object()) == data else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery evidence crossed a pinned authorization boundary")
        }
        try pinnedPolicy.validate()
        try value.authorization.validate(nowMilliseconds: nowMilliseconds)
        guard value.approvals.count >= pinnedPolicy.threshold,
              value.approvals.count <= pinnedPolicy.keys.count else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery approval threshold is not satisfied")
        }
        let message = try value.authorization.canonicalData()
        let trusted = Dictionary(uniqueKeysWithValues: pinnedPolicy.keys.map { ($0.id, $0) })
        var previousID = ""
        var used = Set<String>()
        for approval in value.approvals {
            guard approval.keyID > previousID, used.insert(approval.keyID).inserted,
                  let key = trusted[approval.keyID],
                  let signature = NativeAuditKeyRecoveryTransitionCrypto.signature(approval.signature),
                  try NativeAuditKeyRecoveryTransitionCrypto.ed25519Identity(key.publicKey).key
                    .isValidSignature(signature, for: message) else {
                throw AgentPassNativeError.invalidSignature("Audit-key recovery approvals are duplicated, unsorted, untrusted, or invalid")
            }
            previousID = approval.keyID
        }
        return value
    }
}

/// Complete Node-compatible schema-v3 transition. It deliberately has no
/// retiring-key signature; recovery authority threshold replaces that proof.
public struct NativeAuditKeyRecoveryTransition: Codable, Equatable, Sendable {
    public static let version = 3
    public static let maximumEncodedBytes = 512 * 1024

    public let version: Int; public let tenant: String; public let installationID: String; public let role: String
    public let operationID: String; public let recoveryRequestID: String; public let recoveryPolicyID: String
    public let recoveryPolicyHash: String; public let fromGeneration: Int; public let toGeneration: Int
    public let oldKeyFingerprint: String; public let newKeyFingerprint: String; public let newPublicKey: String
    public let lifecycleHeadHash: String; public let createdAt: String; public let expiresAt: String
    public let previousTransitionHash: String; public let previousTransitionReceiptHash: String
    public let lastCheckpointIndex: Int; public let lastCheckpointHash: String; public let lastCheckpointReceiptHash: String
    public let previousAnchorEventIndex: Int; public let previousAnchorEventHash: String
    public let retiringGenerationPendingCheckpointCount: Int
    public let recoveryEvidence: NativeAuditKeyRecoveryEvidence
    public let newSignature: String; public let transitionHash: String

    enum CodingKeys: String, CodingKey, CaseIterable {
        case version, tenant, role
        case installationID = "installation_id"; case operationID = "operation_id"
        case recoveryRequestID = "recovery_request_id"; case recoveryPolicyID = "recovery_policy_id"
        case recoveryPolicyHash = "recovery_policy_hash"; case fromGeneration = "from_generation"
        case toGeneration = "to_generation"; case oldKeyFingerprint = "old_key_fingerprint"
        case newKeyFingerprint = "new_key_fingerprint"; case newPublicKey = "new_public_key"
        case lifecycleHeadHash = "lifecycle_head_hash"; case createdAt = "created_at"; case expiresAt = "expires_at"
        case previousTransitionHash = "previous_transition_hash"
        case previousTransitionReceiptHash = "previous_transition_receipt_hash"
        case lastCheckpointIndex = "last_checkpoint_index"; case lastCheckpointHash = "last_checkpoint_hash"
        case lastCheckpointReceiptHash = "last_checkpoint_receipt_hash"
        case previousAnchorEventIndex = "previous_anchor_event_index"; case previousAnchorEventHash = "previous_anchor_event_hash"
        case retiringGenerationPendingCheckpointCount = "retiring_generation_pending_checkpoint_count"
        case recoveryEvidence = "recovery_evidence"; case newSignature = "new_signature"; case transitionHash = "transition_hash"
    }

    /// Test/convenience constructor. Production code should use the public
    /// signature-only initializer below so offline private keys never enter the service.
    init(
        authorization: NativeAuditKeyRecoveryAuthorization,
        policy: NativeAuditKeyRecoveryPolicy,
        approvalSigners: [(id: String, key: Curve25519.Signing.PrivateKey)],
        replacementSigner: any P256MessageSigner
    ) throws {
        try authorization.validate()
        try policy.validate()
        let message = try authorization.canonicalData()
        let approvals = try approvalSigners.map { signer -> NativeAuditKeyRecoveryApproval in
            try NativeAuditKeyRecoveryApproval(keyID: signer.id, signature: signer.key.signature(for: message))
        }.sorted { $0.keyID < $1.keyID }
        let replacementRaw = try SSHSIG.p256PublicKey(fromAuthorizedKey: authorization.newPublicKey)
        guard replacementSigner.publicKeyX963 == replacementRaw else {
            throw AgentPassNativeError.invalidKey("Audit-key recovery replacement signer does not match the authorization")
        }
        try self.init(
            authorization: authorization, policy: policy, approvals: approvals,
            replacementSignature: replacementSigner.sign(message: message)
        )
    }

    /// Production construction boundary. Offline authority private keys and the
    /// Secure Enclave replacement private key remain outside this type; callers
    /// provide only their canonical signatures over `authorization.canonicalData()`.
    public init(
        authorization: NativeAuditKeyRecoveryAuthorization,
        policy: NativeAuditKeyRecoveryPolicy,
        approvals: [NativeAuditKeyRecoveryApproval],
        replacementSignature: Data
    ) throws {
        let canonicalReplacementSignature = try NativeP256CanonicalSignature.canonicalized(replacementSignature)
        let evidence = NativeAuditKeyRecoveryEvidence(
            version: 1, policy: policy, authorization: authorization, approvals: approvals
        )
        self.init(
            authorization: authorization,
            evidence: evidence,
            newSignature: canonicalReplacementSignature.base64EncodedString()
        )
        try verify(pinnedPolicy: policy, expectedInstallationID: authorization.installationID)
    }

    private init(authorization: NativeAuditKeyRecoveryAuthorization, evidence: NativeAuditKeyRecoveryEvidence, newSignature: String) {
        version = authorization.version; tenant = authorization.tenant; installationID = authorization.installationID
        role = authorization.role; operationID = authorization.operationID; recoveryRequestID = authorization.recoveryRequestID
        recoveryPolicyID = authorization.recoveryPolicyID; recoveryPolicyHash = authorization.recoveryPolicyHash
        fromGeneration = authorization.fromGeneration; toGeneration = authorization.toGeneration
        oldKeyFingerprint = authorization.oldKeyFingerprint; newKeyFingerprint = authorization.newKeyFingerprint
        newPublicKey = authorization.newPublicKey; lifecycleHeadHash = authorization.lifecycleHeadHash
        createdAt = authorization.createdAt; expiresAt = authorization.expiresAt
        previousTransitionHash = authorization.previousTransitionHash
        previousTransitionReceiptHash = authorization.previousTransitionReceiptHash
        lastCheckpointIndex = authorization.lastCheckpointIndex; lastCheckpointHash = authorization.lastCheckpointHash
        lastCheckpointReceiptHash = authorization.lastCheckpointReceiptHash
        previousAnchorEventIndex = authorization.previousAnchorEventIndex; previousAnchorEventHash = authorization.previousAnchorEventHash
        retiringGenerationPendingCheckpointCount = authorization.retiringGenerationPendingCheckpointCount
        recoveryEvidence = evidence; self.newSignature = newSignature
        var unhashed = authorization.object(); unhashed["recovery_evidence"] = evidence.object(); unhashed["new_signature"] = newSignature
        transitionHash = (try? NativeAuditLog.hash(NativeAuditLog.canonical(unhashed))) ?? ""
    }

    public func canonicalData() throws -> Data {
        let data = try NativeAuditLog.canonical(object(includeHash: true))
        guard data.count <= Self.maximumEncodedBytes else { throw AgentPassNativeError.invalidConfiguration("Audit-key recovery transition is too large") }
        return data
    }

    public static func decodeCanonical(
        _ data: Data,
        pinnedPolicy: NativeAuditKeyRecoveryPolicy,
        expectedInstallationID: String,
        nowMilliseconds: Int64? = nil
    ) throws -> Self {
        let value = try decodeCanonicalUntrusted(data)
        try value.verify(
            pinnedPolicy: pinnedPolicy,
            expectedInstallationID: expectedInstallationID,
            nowMilliseconds: nowMilliseconds
        )
        return value
    }

    /// Parsing boundary used only before an immediate pinned-trust verification.
    /// This is intentionally not public: an embedded policy is attacker input.
    fileprivate static func decodeCanonicalUntrusted(_ data: Data) throws -> Self {
        guard !data.isEmpty, data.count <= maximumEncodedBytes,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set(CodingKeys.allCases.map(\.stringValue)) else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery transition encoding is invalid")
        }
        let value = try JSONDecoder().decode(Self.self, from: data)
        guard try value.canonicalData() == data else { throw AgentPassNativeError.invalidSignature("Audit-key recovery transition is not canonical") }
        return value
    }

    public func verify(
        pinnedPolicy: NativeAuditKeyRecoveryPolicy,
        expectedInstallationID: String,
        nowMilliseconds: Int64? = nil
    ) throws {
        let authorization = try makeAuthorization()
        try authorization.validate(nowMilliseconds: nowMilliseconds)
        try pinnedPolicy.validate()
        guard installationID == expectedInstallationID,
              recoveryPolicyID == pinnedPolicy.policyID, recoveryPolicyHash == pinnedPolicy.policyHash,
              recoveryEvidence.version == 1, recoveryEvidence.policy == pinnedPolicy,
              recoveryEvidence.authorization == authorization,
              recoveryEvidence.approvals.count >= pinnedPolicy.threshold,
              recoveryEvidence.approvals.count <= pinnedPolicy.keys.count else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery evidence is not bound to pinned policy and exact authorization")
        }
        let message = try authorization.canonicalData()
        let policyKeys = Dictionary(uniqueKeysWithValues: pinnedPolicy.keys.map { ($0.id, $0) })
        var previousID = ""
        var used = Set<String>()
        for approval in recoveryEvidence.approvals {
            guard NativeAuditKeyRecoveryTransitionCrypto.isSlug(approval.keyID), approval.keyID > previousID,
                  used.insert(approval.keyID).inserted, let pinned = policyKeys[approval.keyID],
                  let signature = NativeAuditKeyRecoveryTransitionCrypto.signature(approval.signature),
                  try NativeAuditKeyRecoveryTransitionCrypto.ed25519Identity(pinned.publicKey).key.isValidSignature(signature, for: message) else {
                throw AgentPassNativeError.invalidSignature("Audit-key recovery approval signer, order, or signature is invalid")
            }
            previousID = approval.keyID
        }
        guard let replacementSignature = NativeAuditKeyRecoveryTransitionCrypto.signature(newSignature),
              NativeP256CanonicalSignature.isCanonicalLowS(replacementSignature),
              let replacementKey = try? P256.Signing.PublicKey(x963Representation: SSHSIG.p256PublicKey(fromAuthorizedKey: newPublicKey)),
              let ecdsa = try? P256.Signing.ECDSASignature(rawRepresentation: replacementSignature),
              replacementKey.isValidSignature(ecdsa, for: message) else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery replacement-key possession proof is invalid")
        }
        var unhashed = authorization.object(); unhashed["recovery_evidence"] = recoveryEvidence.object(); unhashed["new_signature"] = newSignature
        guard transitionHash == NativeAuditLog.hash(try NativeAuditLog.canonical(unhashed)) else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery transition hash is invalid")
        }
    }

    fileprivate func makeAuthorization() throws -> NativeAuditKeyRecoveryAuthorization {
        let data = try NativeAuditLog.canonical(authorizationObject())
        return try JSONDecoder().decode(NativeAuditKeyRecoveryAuthorization.self, from: data)
    }

    fileprivate func authorizationObject() -> [String: Any] {
        var value = object(includeHash: false); value.removeValue(forKey: "recovery_evidence"); value.removeValue(forKey: "new_signature"); return value
    }

    fileprivate func object(includeHash: Bool) -> [String: Any] {
        var value: [String: Any] = [
            "version": version, "tenant": tenant, "installation_id": installationID, "role": role,
            "operation_id": operationID, "recovery_request_id": recoveryRequestID,
            "recovery_policy_id": recoveryPolicyID, "recovery_policy_hash": recoveryPolicyHash,
            "from_generation": fromGeneration, "to_generation": toGeneration,
            "old_key_fingerprint": oldKeyFingerprint, "new_key_fingerprint": newKeyFingerprint,
            "new_public_key": newPublicKey, "lifecycle_head_hash": lifecycleHeadHash,
            "created_at": createdAt, "expires_at": expiresAt,
            "previous_transition_hash": previousTransitionHash, "previous_transition_receipt_hash": previousTransitionReceiptHash,
            "last_checkpoint_index": lastCheckpointIndex, "last_checkpoint_hash": lastCheckpointHash,
            "last_checkpoint_receipt_hash": lastCheckpointReceiptHash,
            "previous_anchor_event_index": previousAnchorEventIndex, "previous_anchor_event_hash": previousAnchorEventHash,
            "retiring_generation_pending_checkpoint_count": retiringGenerationPendingCheckpointCount,
            "recovery_evidence": recoveryEvidence.object(), "new_signature": newSignature
        ]
        if includeHash { value["transition_hash"] = transitionHash }
        return value
    }
}

fileprivate enum NativeAuditKeyRecoveryTransitionCrypto {
    static let spkiPrefix = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])

    static func ed25519Identity(_ key: Curve25519.Signing.PublicKey) -> (key: Curve25519.Signing.PublicKey, pem: String, fingerprint: String) {
        let der = spkiPrefix + key.rawRepresentation
        return (key, "-----BEGIN PUBLIC KEY-----\n\(der.base64EncodedString())\n-----END PUBLIC KEY-----\n", fingerprint(der))
    }

    static func ed25519Identity(_ pem: String) throws -> (key: Curve25519.Signing.PublicKey, pem: String, fingerprint: String) {
        guard pem.utf8.count <= 4 * 1024 else { throw AgentPassNativeError.invalidKey("Audit-key recovery public key is too large") }
        let lines = pem.split(whereSeparator: \.isNewline).map(String.init)
        guard lines.first == "-----BEGIN PUBLIC KEY-----", lines.last == "-----END PUBLIC KEY-----", lines.count == 3,
              pem == lines.joined(separator: "\n") + "\n", let der = Data(base64Encoded: lines[1]),
              der.count == 44, der.prefix(12) == spkiPrefix else {
            throw AgentPassNativeError.invalidKey("Audit-key recovery public key must be canonical Ed25519 SPKI PEM")
        }
        let key = try Curve25519.Signing.PublicKey(rawRepresentation: der.suffix(32))
        return (key, pem, fingerprint(der))
    }

    static func ed25519IdentityFromAuthoritiesPEM(_ pem: String) throws -> (key: Curve25519.Signing.PublicKey, pem: String, fingerprint: String) {
        guard pem.utf8.count <= 4 * 1024 else { throw AgentPassNativeError.invalidKey("Offline recovery authority key is too large") }
        let lines = pem.split(whereSeparator: \.isNewline).map(String.init)
        guard lines.count >= 3, lines.first == "-----BEGIN PUBLIC KEY-----", lines.last == "-----END PUBLIC KEY-----",
              let der = Data(base64Encoded: lines.dropFirst().dropLast().joined()), der.count == 44,
              der.prefix(12) == spkiPrefix else {
            throw AgentPassNativeError.invalidKey("Offline recovery authority key must be Ed25519 SPKI PEM")
        }
        return ed25519Identity(try Curve25519.Signing.PublicKey(rawRepresentation: der.suffix(32)))
    }

    static func signature(_ value: String) -> Data? {
        guard value.utf8.count <= 128, let data = Data(base64Encoded: value), data.count == 64,
              data.base64EncodedString() == value else { return nil }
        return data
    }

    static func isSlug(_ value: String) -> Bool {
        value.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", options: .regularExpression) != nil
    }

    static func isHash(_ value: String) -> Bool {
        value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
    }

    static func isFingerprint(_ value: String) -> Bool {
        value.range(of: "^SHA256:[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil
    }

    private static func fingerprint(_ der: Data) -> String {
        "SHA256:" + Data(SHA256.hash(data: der)).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

enum NativeAuditKeyRecoveryTransitionStoreValidation {
    static func isSlug(_ value: String) -> Bool {
        value.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", options: .regularExpression) != nil
    }
}

/// Verifies the unchanged anchor schema-v2 receipt emitted for a schema-v3
/// recovery transition. Kept separate from the v2 verifier so the established
/// v2 API and source remain untouched.
struct NativeAuditKeyRecoveryTransitionReceiptVerifier: Sendable {
    private let tenant: String
    private let anchorKey: Curve25519.Signing.PublicKey
    private let anchorFingerprint: String

    init(tenant: String, anchorPublicKeyPEM: String) throws {
        guard NativeAuditKeyRecoveryTransitionStoreValidation.isSlug(tenant) else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key recovery receipt tenant is invalid")
        }
        let parsed = try Self.key(anchorPublicKeyPEM)
        self.tenant = tenant; anchorKey = parsed.key
        anchorFingerprint = "SHA256:" + Data(SHA256.hash(data: parsed.der)).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    func verify(receiptData: Data, transition: NativeAuditKeyRecoveryTransition, expectedTransitionIndex: Int) throws -> NativeAuditKeyTransitionReceipt {
        guard !receiptData.isEmpty, receiptData.count <= NativeAuditKeyTransitionStatement.maximumEncodedBytes,
              expectedTransitionIndex > 0, expectedTransitionIndex <= NativeAuditKeyTransitionStatement.maximumSafeInteger,
              let object = try JSONSerialization.jsonObject(with: receiptData) as? [String: Any],
              Set(object.keys) == Set(NativeAuditKeyTransitionReceipt.CodingKeys.allCases.map(\.stringValue)) else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery receipt encoding is invalid")
        }
        let receipt = try JSONDecoder().decode(NativeAuditKeyTransitionReceipt.self, from: receiptData)
        guard try NativeAuditLog.canonical(receiptObject(receipt, includeHash: true)) == receiptData,
              receipt.version == 2, receipt.tenant == tenant, receipt.tenant == transition.tenant,
              receipt.index == expectedTransitionIndex, receipt.transitionHash == transition.transitionHash,
              receipt.previousReceiptHash == transition.previousTransitionReceiptHash,
              receipt.eventIndex == transition.previousAnchorEventIndex + 1,
              receipt.eventIndex <= NativeAuditKeyTransitionStatement.maximumSafeInteger,
              receipt.previousEventHash == transition.previousAnchorEventHash,
              receipt.lastCheckpointIndex == transition.lastCheckpointIndex,
              receipt.lastCheckpointHash == transition.lastCheckpointHash,
              receipt.lastCheckpointReceiptHash == transition.lastCheckpointReceiptHash,
              receipt.anchorKeyFingerprint == anchorFingerprint,
              NativeAuditKeyRecoveryTransitionCrypto.isHash(receipt.previousReceiptHash),
              NativeAuditKeyRecoveryTransitionCrypto.isHash(receipt.previousEventHash),
              NativeAuditKeyRecoveryTransitionCrypto.isHash(receipt.receiptHash),
              let received = NativeAuditKeyRecoveryAuthorization.canonicalTimestamp(receipt.receivedAt),
              let created = NativeAuditKeyRecoveryAuthorization.canonicalTimestamp(transition.createdAt),
              let expires = NativeAuditKeyRecoveryAuthorization.canonicalTimestamp(transition.expiresAt),
              received >= created, received <= expires,
              let signature = NativeAuditKeyRecoveryTransitionCrypto.signature(receipt.signature) else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery receipt statement or event boundary is invalid")
        }
        let statement = receiptObject(receipt, includeHash: false, includeSignature: false)
        guard anchorKey.isValidSignature(signature, for: try NativeAuditLog.canonical(statement)) else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery receipt signature is invalid")
        }
        guard receipt.receiptHash == NativeAuditLog.hash(try NativeAuditLog.canonical(receiptObject(receipt, includeHash: false))) else {
            throw AgentPassNativeError.invalidSignature("Audit-key recovery receipt hash is invalid")
        }
        return receipt
    }

    private func receiptObject(_ receipt: NativeAuditKeyTransitionReceipt, includeHash: Bool, includeSignature: Bool = true) -> [String: Any] {
        var object: [String: Any] = [
            "version": receipt.version, "tenant": receipt.tenant, "index": receipt.index,
            "transition_hash": receipt.transitionHash, "received_at": receipt.receivedAt,
            "previous_receipt_hash": receipt.previousReceiptHash, "event_index": receipt.eventIndex,
            "previous_event_hash": receipt.previousEventHash, "last_checkpoint_index": receipt.lastCheckpointIndex,
            "last_checkpoint_hash": receipt.lastCheckpointHash,
            "last_checkpoint_receipt_hash": receipt.lastCheckpointReceiptHash
        ]
        if includeSignature { object["anchor_key_fingerprint"] = receipt.anchorKeyFingerprint; object["signature"] = receipt.signature }
        if includeHash { object["receipt_hash"] = receipt.receiptHash }
        return object
    }

    private static func key(_ pem: String) throws -> (key: Curve25519.Signing.PublicKey, der: Data) {
        let lines = pem.split(whereSeparator: \.isNewline).map(String.init)
        let prefix = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])
        guard pem.utf8.count <= 4 * 1024, lines.first == "-----BEGIN PUBLIC KEY-----", lines.last == "-----END PUBLIC KEY-----",
              lines.count == 3, pem == lines.joined(separator: "\n") + "\n", let der = Data(base64Encoded: lines[1]),
              der.count == 44, der.prefix(12) == prefix else {
            throw AgentPassNativeError.invalidKey("Audit-key recovery anchor key must be canonical Ed25519 SPKI PEM")
        }
        return (try Curve25519.Signing.PublicKey(rawRepresentation: der.suffix(32)), der)
    }
}
