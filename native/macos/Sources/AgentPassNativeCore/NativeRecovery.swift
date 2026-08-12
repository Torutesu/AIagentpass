import CryptoKit
import Foundation

public struct NativeRecoveryRequest: Equatable, Sendable {
    public let installationID: String
    public let role: NativeKeyRole
    public let fromGeneration: Int
    public let fromFingerprint: String
    public let proposedGeneration: Int
    public let proposedPublicKey: String
    public let proposedPublicKeyX963: Data
    public let recoveryPolicyVersion: Int
    public let recoveryPolicyID: String
    public let recoveryPolicyHash: String
    public let lifecycleHeadHash: String
    public let auditEntries: Int
    public let auditHeadHash: String
    public let latestCheckpointHash: String
    public let latestReceiptHash: String
    public let controlSequence: Int
    public let nonce: String
    public let issuedAt: String
    public let expiresAt: String
    public let issuedAtMilliseconds: Int64
    public let expiresAtMilliseconds: Int64
}

public struct NativeRecoveryVerification: Equatable, Sendable {
    public let valid: Bool
    public let request: NativeRecoveryRequest
    public let requestHash: String
    public let policyVersion: Int
    public let policyID: String
    public let policyHash: String
    public let threshold: Int
    public let authorityPublicKeyFingerprints: [String]
    public let acceptedSignerIDs: [String]
    public let acceptedPublicKeyFingerprints: [String]
}

public struct NativeRecoveryEvidenceBundle: Equatable, Sendable {
    public static let maximumBytes = 900 * 1024
    public let requestData: Data
    public let policyData: Data
    public let authorizationData: [Data]

    public init(requestData: Data, policyData: Data, authorizationData: [Data]) {
        self.requestData = requestData
        self.policyData = policyData
        self.authorizationData = authorizationData
    }

    public func canonicalData() throws -> Data {
        let object: [String: Any] = [
            "version": 1,
            "request_base64": requestData.base64EncodedString(),
            "policy_base64": policyData.base64EncodedString(),
            "authorizations_base64": authorizationData.map { $0.base64EncodedString() }
        ]
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        guard data.count <= Self.maximumBytes else { throw AgentPassNativeError.invalidConfiguration("Recovery evidence bundle is too large") }
        return data
    }

    public static func decode(_ data: Data) throws -> Self {
        guard !data.isEmpty, data.count <= maximumBytes,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == ["authorizations_base64", "policy_base64", "request_base64", "version"],
              object["version"] as? Int == 1,
              let requestText = object["request_base64"] as? String,
              let policyText = object["policy_base64"] as? String,
              let authorizationTexts = object["authorizations_base64"] as? [String],
              !authorizationTexts.isEmpty,
              let request = canonicalBase64Data(requestText),
              let policy = canonicalBase64Data(policyText) else {
            throw AgentPassNativeError.invalidConfiguration("Recovery evidence bundle is invalid")
        }
        let authorizations = try authorizationTexts.map { value -> Data in
            guard let decoded = canonicalBase64Data(value) else { throw AgentPassNativeError.invalidConfiguration("Recovery evidence authorization is invalid") }
            return decoded
        }
        let bundle = Self(requestData: request, policyData: policy, authorizationData: authorizations)
        guard try bundle.canonicalData() == data else { throw AgentPassNativeError.invalidConfiguration("Recovery evidence bundle is not canonical") }
        return bundle
    }

    private static func canonicalBase64Data(_ value: String) -> Data? {
        guard let decoded = Data(base64Encoded: value), decoded.base64EncodedString() == value else { return nil }
        return decoded
    }
}

public struct NativeRecoveryRuntimeState: Equatable, Sendable {
    public let installationID: String
    public let role: NativeKeyRole
    public let activeGeneration: Int
    public let activeFingerprint: String
    public let stagedGeneration: Int
    public let stagedPublicKeyX963: Data
    public let lifecycleHeadHash: String
    public let auditEntries: Int
    public let auditHeadHash: String
    public let latestCheckpointHash: String
    public let latestReceiptHash: String
    public let controlSequence: Int

    public init(installationID: String, role: NativeKeyRole, activeGeneration: Int, activeFingerprint: String, stagedGeneration: Int, stagedPublicKeyX963: Data, lifecycleHeadHash: String, auditEntries: Int, auditHeadHash: String, latestCheckpointHash: String, latestReceiptHash: String, controlSequence: Int) {
        self.installationID = installationID; self.role = role; self.activeGeneration = activeGeneration
        self.activeFingerprint = activeFingerprint; self.stagedGeneration = stagedGeneration; self.stagedPublicKeyX963 = stagedPublicKeyX963
        self.lifecycleHeadHash = lifecycleHeadHash; self.auditEntries = auditEntries; self.auditHeadHash = auditHeadHash
        self.latestCheckpointHash = latestCheckpointHash; self.latestReceiptHash = latestReceiptHash; self.controlSequence = controlSequence
    }
}

public struct NativeRecoveryPolicyMetadata: Equatable, Sendable {
    public let version: Int
    public let id: String
    public let hash: String
    public let threshold: Int
    public let authorityPublicKeyFingerprints: [String]
}

/// Independently verifies the complete offline-recovery ceremony. Callers must pass
/// the original request, pinned policy, and every authorization; a CLI success result
/// is deliberately not accepted as evidence.
public enum NativeRecoveryVerifier {
    public static let maximumRequestBytes = 16 * 1024
    public static let maximumAuthorizationBytes = 16 * 1024
    public static let maximumPolicyBytes = 256 * 1024

    private static let requestKeys: Set<String> = [
        "audit_entries", "audit_head_hash", "control_sequence", "expires_at",
        "from_fingerprint", "from_generation", "installation_id", "issued_at",
        "latest_checkpoint_hash", "latest_receipt_hash", "lifecycle_head_hash",
        "nonce", "proposed_generation", "proposed_public_key",
        "recovery_policy_hash", "recovery_policy_id", "recovery_policy_version",
        "role", "version"
    ]
    private static let policyKeys: Set<String> = ["authorities", "policy_id", "threshold", "version"]
    private static let authorityKeys: Set<String> = ["id", "public_key"]
    private static let authorizationKeys: Set<String> = [
        "public_key_fingerprint", "request_hash", "signature", "signed_at", "signer_id", "version"
    ]
    private static let authorizationStatementKeys: Set<String> = [
        "public_key_fingerprint", "request_hash", "signed_at", "signer_id", "version"
    ]
    private static let maximumSafeInteger = 9_007_199_254_740_991

    public static func verify(
        requestData: Data,
        policyData: Data,
        authorizationData: [Data],
        nowMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1_000)
    ) throws -> NativeRecoveryVerification {
        let requestDocument = try RecoveryJSONDocument(data: requestData, maximumBytes: maximumRequestBytes, label: "Recovery request")
        let request = try validateRequest(document: requestDocument, nowMilliseconds: nowMilliseconds)
        let policyDocument = try RecoveryJSONDocument(data: policyData, maximumBytes: maximumPolicyBytes, label: "Recovery policy")
        let policy = try validatePolicy(document: policyDocument)

        guard request.recoveryPolicyVersion == policy.version,
              request.recoveryPolicyID == policy.id,
              request.recoveryPolicyHash == policy.hash else {
            throw AgentPassNativeError.invalidSignature("Recovery request is not bound to the supplied policy")
        }
        guard authorizationData.count >= policy.threshold else {
            throw AgentPassNativeError.invalidSignature("Recovery authorization threshold is not satisfied")
        }

        let requestHash = sha256(requestDocument.canonicalData)
        var acceptedIDs = Set<String>()
        var acceptedFingerprints = Set<String>()
        for encoded in authorizationData {
            let document = try RecoveryJSONDocument(data: encoded, maximumBytes: maximumAuthorizationBytes, label: "Recovery authorization")
            let object = try document.root.object(label: "Recovery authorization")
            try requireExactKeys(object, authorizationKeys, label: "Recovery authorization")
            let signerID = try requiredSlug(object, key: "signer_id", label: "Recovery authorization signer")
            guard acceptedIDs.insert(signerID).inserted else {
                throw AgentPassNativeError.invalidSignature("Duplicate recovery authorization signer")
            }
            guard let authority = policy.authorities[signerID] else {
                throw AgentPassNativeError.invalidSignature("Recovery authorization signer is not trusted")
            }
            let fingerprint = try verifyAuthorization(
                object: object,
                request: request,
                requestHash: requestHash,
                authority: authority,
                nowMilliseconds: nowMilliseconds
            )
            guard acceptedFingerprints.insert(fingerprint).inserted else {
                throw AgentPassNativeError.invalidSignature("Duplicate recovery authorization key")
            }
        }
        guard acceptedIDs.count >= policy.threshold, acceptedFingerprints.count >= policy.threshold else {
            throw AgentPassNativeError.invalidSignature("Recovery authorization threshold is not satisfied")
        }

        return NativeRecoveryVerification(
            valid: true,
            request: request,
            requestHash: requestHash,
            policyVersion: policy.version,
            policyID: policy.id,
            policyHash: policy.hash,
            threshold: policy.threshold,
            authorityPublicKeyFingerprints: policy.authorities.values.map(\.fingerprint).sorted(),
            acceptedSignerIDs: acceptedIDs.sorted(),
            acceptedPublicKeyFingerprints: acceptedFingerprints.sorted()
        )
    }

    /// Revalidates durable ceremony evidence during lifecycle replay. The historical
    /// request is evaluated at its own expiry boundary, never against wall-clock time.
    public static func verifyHistoricalEvidence(_ evidenceData: Data) throws -> NativeRecoveryVerification {
        let evidence = try NativeRecoveryEvidenceBundle.decode(evidenceData)
        let request = try validateRequest(
            document: RecoveryJSONDocument(data: evidence.requestData, maximumBytes: maximumRequestBytes, label: "Recovery request"),
            nowMilliseconds: 0,
            enforceTimeWindow: false
        )
        return try verify(requestData: evidence.requestData, policyData: evidence.policyData, authorizationData: evidence.authorizationData, nowMilliseconds: request.expiresAtMilliseconds)
    }

    public static func validateRuntimeState(_ verification: NativeRecoveryVerification, state: NativeRecoveryRuntimeState) throws {
        let request = verification.request
        guard verification.valid,
              request.installationID == state.installationID,
              request.role == state.role,
              request.fromGeneration == state.activeGeneration,
              request.fromFingerprint == state.activeFingerprint,
              request.proposedGeneration == state.stagedGeneration,
              request.proposedPublicKeyX963 == state.stagedPublicKeyX963,
              request.lifecycleHeadHash == state.lifecycleHeadHash,
              request.auditEntries == state.auditEntries,
              request.auditHeadHash == state.auditHeadHash,
              request.latestCheckpointHash == state.latestCheckpointHash,
              request.latestReceiptHash == state.latestReceiptHash,
              request.controlSequence == state.controlSequence else {
            throw AgentPassNativeError.invalidSignature("Recovery ceremony does not bind the exact live runtime state")
        }
    }

    public static func authorityFingerprint(rawEd25519PublicKey: Data) throws -> String {
        guard rawEd25519PublicKey.count == 32,
              (try? Curve25519.Signing.PublicKey(rawRepresentation: rawEd25519PublicKey)) != nil else {
            throw AgentPassNativeError.invalidKey("Recovery authority raw public key is invalid")
        }
        let prefix = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])
        return "SHA256:" + base64URL(Data(SHA256.hash(data: prefix + rawEd25519PublicKey)))
    }

    public static func validateRequest(
        _ data: Data,
        nowMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1_000)
    ) throws -> NativeRecoveryRequest {
        try validateRequest(
            document: RecoveryJSONDocument(data: data, maximumBytes: maximumRequestBytes, label: "Recovery request"),
            nowMilliseconds: nowMilliseconds
        )
    }

    public static func requestHash(_ data: Data) throws -> String {
        let document = try RecoveryJSONDocument(data: data, maximumBytes: maximumRequestBytes, label: "Recovery request")
        _ = try validateRequest(document: document, nowMilliseconds: Int64.min, enforceTimeWindow: false)
        return sha256(document.canonicalData)
    }

    public static func policyHash(_ data: Data) throws -> String {
        try validatePolicy(document: RecoveryJSONDocument(data: data, maximumBytes: maximumPolicyBytes, label: "Recovery policy")).hash
    }

    public static func policyMetadata(_ data: Data) throws -> NativeRecoveryPolicyMetadata {
        let policy = try validatePolicy(document: RecoveryJSONDocument(data: data, maximumBytes: maximumPolicyBytes, label: "Recovery policy"))
        return NativeRecoveryPolicyMetadata(
            version: policy.version,
            id: policy.id,
            hash: policy.hash,
            threshold: policy.threshold,
            authorityPublicKeyFingerprints: policy.authorities.values.map(\.fingerprint).sorted()
        )
    }

    /// Creates the exact host request that offline authorities inspect and sign.
    /// Re-validation is performed before bytes are returned, so callers cannot
    /// emit a request that the verifier would later interpret differently.
    public static func createRequest(
        state: NativeRecoveryRuntimeState,
        policyData: Data,
        nonce: String,
        issuedAt: String,
        expiresAt: String,
        nowMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1_000)
    ) throws -> Data {
        let policy = try policyMetadata(policyData)
        let object: [String: Any] = [
            "version": 1,
            "installation_id": state.installationID,
            "role": state.role.rawValue,
            "from_generation": state.activeGeneration,
            "from_fingerprint": state.activeFingerprint,
            "proposed_generation": state.stagedGeneration,
            "proposed_public_key": try SSHSIG.authorizedKey(publicKeyX963: state.stagedPublicKeyX963),
            "recovery_policy_version": policy.version,
            "recovery_policy_id": policy.id,
            "recovery_policy_hash": policy.hash,
            "lifecycle_head_hash": state.lifecycleHeadHash,
            "audit_entries": state.auditEntries,
            "audit_head_hash": state.auditHeadHash,
            "latest_checkpoint_hash": state.latestCheckpointHash,
            "latest_receipt_hash": state.latestReceiptHash,
            "control_sequence": state.controlSequence,
            "nonce": nonce,
            "issued_at": issuedAt,
            "expires_at": expiresAt
        ]
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        _ = try validateRequest(data, nowMilliseconds: nowMilliseconds)
        return data
    }

    private static func validateRequest(
        document: RecoveryJSONDocument,
        nowMilliseconds: Int64,
        enforceTimeWindow: Bool = true
    ) throws -> NativeRecoveryRequest {
        let object = try document.root.object(label: "Recovery request")
        try requireExactKeys(object, requestKeys, label: "Recovery request")
        guard try requiredInteger(object, key: "version", label: "Recovery request version") == 1 else {
            throw AgentPassNativeError.invalidConfiguration("Recovery request identity is invalid")
        }
        let installationID = try requiredSlug(object, key: "installation_id", label: "Recovery installation ID")
        guard let role = NativeKeyRole(rawValue: try requiredString(object, key: "role", label: "Recovery request role")) else {
            throw AgentPassNativeError.invalidConfiguration("Recovery request identity is invalid")
        }
        let fromGeneration = try requiredSafeInteger(object, key: "from_generation", minimum: 1, label: "Recovery request generation")
        let proposedGeneration = try requiredSafeInteger(object, key: "proposed_generation", minimum: 1, label: "Recovery request generation")
        guard fromGeneration < maximumSafeInteger, proposedGeneration == fromGeneration + 1 else {
            throw AgentPassNativeError.invalidConfiguration("Recovery request generation is invalid")
        }
        let fromFingerprint = try requiredString(object, key: "from_fingerprint", label: "Recovery request current fingerprint")
        guard isFingerprint(fromFingerprint) else {
            throw AgentPassNativeError.invalidConfiguration("Recovery request current fingerprint is invalid")
        }
        let proposedPublicKey = try requiredString(object, key: "proposed_public_key", label: "Recovery request proposed public key")
        guard proposedPublicKey.utf8.count <= 4_096 else {
            throw AgentPassNativeError.invalidKey("Recovery request proposed public key is invalid")
        }
        let proposedPublicKeyX963 = try p256PublicKey(proposedPublicKey)

        let recoveryPolicyVersion = try requiredSafeInteger(object, key: "recovery_policy_version", minimum: 1, label: "Recovery request policy version")
        let recoveryPolicyID = try requiredSlug(object, key: "recovery_policy_id", label: "Recovery request policy ID")
        let recoveryPolicyHash = try requiredHash(object, key: "recovery_policy_hash", label: "Recovery request policy binding")
        guard recoveryPolicyVersion == 1 else {
            throw AgentPassNativeError.invalidConfiguration("Recovery request policy binding is invalid")
        }

        let lifecycleHeadHash = try requiredHash(object, key: "lifecycle_head_hash", label: "Recovery request history binding")
        let auditHeadHash = try requiredHash(object, key: "audit_head_hash", label: "Recovery request history binding")
        let latestCheckpointHash = try requiredHash(object, key: "latest_checkpoint_hash", label: "Recovery request history binding")
        let latestReceiptHash = try requiredHash(object, key: "latest_receipt_hash", label: "Recovery request history binding")
        let auditEntries = try requiredSafeInteger(object, key: "audit_entries", minimum: 0, label: "Recovery request audit entries")
        let controlSequence = try requiredSafeInteger(object, key: "control_sequence", minimum: 0, label: "Recovery request control sequence")
        let nonce = try requiredString(object, key: "nonce", label: "Recovery request nonce")
        guard nonce.utf8.count == 43, nonce.unicodeScalars.allSatisfy({ base64URLCharacters.contains($0) }) else {
            throw AgentPassNativeError.invalidConfiguration("Recovery request state is invalid")
        }

        let issuedAt = try requiredString(object, key: "issued_at", label: "Recovery request issued-at")
        let expiresAt = try requiredString(object, key: "expires_at", label: "Recovery request expires-at")
        guard let issuedAtMilliseconds = timestampMilliseconds(issuedAt),
              let expiresAtMilliseconds = timestampMilliseconds(expiresAt),
              expiresAtMilliseconds > issuedAtMilliseconds,
              expiresAtMilliseconds - issuedAtMilliseconds <= 15 * 60_000 else {
            throw AgentPassNativeError.invalidConfiguration("Recovery request is expired or outside the allowed window")
        }
        if enforceTimeWindow {
            guard issuedAtMilliseconds <= addingClamped(nowMilliseconds, 5_000), expiresAtMilliseconds >= nowMilliseconds else {
                throw AgentPassNativeError.invalidConfiguration("Recovery request is expired or outside the allowed window")
            }
        }

        return NativeRecoveryRequest(
            installationID: installationID,
            role: role,
            fromGeneration: fromGeneration,
            fromFingerprint: fromFingerprint,
            proposedGeneration: proposedGeneration,
            proposedPublicKey: proposedPublicKey,
            proposedPublicKeyX963: proposedPublicKeyX963,
            recoveryPolicyVersion: recoveryPolicyVersion,
            recoveryPolicyID: recoveryPolicyID,
            recoveryPolicyHash: recoveryPolicyHash,
            lifecycleHeadHash: lifecycleHeadHash,
            auditEntries: auditEntries,
            auditHeadHash: auditHeadHash,
            latestCheckpointHash: latestCheckpointHash,
            latestReceiptHash: latestReceiptHash,
            controlSequence: controlSequence,
            nonce: nonce,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            issuedAtMilliseconds: issuedAtMilliseconds,
            expiresAtMilliseconds: expiresAtMilliseconds
        )
    }

    private struct Authority: Sendable {
        let id: String
        let key: Curve25519.Signing.PublicKey
        let fingerprint: String
    }

    private struct Policy: Sendable {
        let version: Int
        let id: String
        let threshold: Int
        let authorities: [String: Authority]
        let hash: String
    }

    private static func validatePolicy(document: RecoveryJSONDocument) throws -> Policy {
        let object = try document.root.object(label: "Recovery policy")
        try requireExactKeys(object, policyKeys, label: "Recovery policy")
        let version = try requiredSafeInteger(object, key: "version", minimum: 1, label: "Recovery policy version")
        let id = try requiredSlug(object, key: "policy_id", label: "Recovery policy ID")
        let threshold = try requiredSafeInteger(object, key: "threshold", minimum: 1, label: "Recovery policy threshold")
        guard version == 1, let authorityValues = object["authorities"]?.arrayValue,
              threshold <= authorityValues.count else {
            throw AgentPassNativeError.invalidConfiguration("Recovery policy is invalid")
        }
        var authorities: [String: Authority] = [:]
        var fingerprints = Set<String>()
        for value in authorityValues {
            let authorityObject = try value.object(label: "Recovery authority")
            try requireExactKeys(authorityObject, authorityKeys, label: "Recovery authority")
            let authorityID = try requiredSlug(authorityObject, key: "id", label: "Recovery authority ID")
            guard authorities[authorityID] == nil else {
                throw AgentPassNativeError.invalidConfiguration("Recovery policy authority IDs are invalid")
            }
            let pem = try requiredString(authorityObject, key: "public_key", label: "Recovery authority public key")
            let parsed = try ed25519PublicKey(pem)
            guard fingerprints.insert(parsed.fingerprint).inserted else {
                throw AgentPassNativeError.invalidConfiguration("Recovery policy contains duplicate authority keys")
            }
            authorities[authorityID] = Authority(id: authorityID, key: parsed.key, fingerprint: parsed.fingerprint)
        }
        return Policy(version: version, id: id, threshold: threshold, authorities: authorities, hash: sha256(document.canonicalData))
    }

    private static func verifyAuthorization(
        object: [String: RecoveryJSONValue],
        request: NativeRecoveryRequest,
        requestHash: String,
        authority: Authority,
        nowMilliseconds: Int64
    ) throws -> String {
        let version = try requiredSafeInteger(object, key: "version", minimum: 1, label: "Recovery authorization version")
        let signerID = try requiredSlug(object, key: "signer_id", label: "Recovery authorization signer")
        let statedRequestHash = try requiredHash(object, key: "request_hash", label: "Recovery authorization request hash")
        let signedAt = try requiredString(object, key: "signed_at", label: "Recovery authorization signed-at")
        let statedFingerprint = try requiredString(object, key: "public_key_fingerprint", label: "Recovery authorization key fingerprint")
        guard version == 1, signerID == authority.id, statedRequestHash == requestHash,
              statedFingerprint == authority.fingerprint,
              let signedAtMilliseconds = timestampMilliseconds(signedAt),
              signedAtMilliseconds >= request.issuedAtMilliseconds,
              signedAtMilliseconds <= min(addingClamped(nowMilliseconds, 5_000), request.expiresAtMilliseconds) else {
            throw AgentPassNativeError.invalidSignature("Recovery authorization statement is invalid")
        }

        let signatureText = try requiredString(object, key: "signature", label: "Recovery authorization signature")
        guard let signature = canonicalBase64(signatureText), signature.count == 64 else {
            throw AgentPassNativeError.invalidSignature("Recovery authorization signature is invalid")
        }
        var statement = object
        statement.removeValue(forKey: "signature")
        guard Set(statement.keys) == authorizationStatementKeys else {
            throw AgentPassNativeError.invalidSignature("Recovery authorization encoding is invalid")
        }
        let signedData = try RecoveryJSONValue.object(statement).canonicalData()
        guard authority.key.isValidSignature(signature, for: signedData) else {
            throw AgentPassNativeError.invalidSignature("Recovery authorization signature is invalid")
        }
        return authority.fingerprint
    }

    private static func p256PublicKey(_ value: String) throws -> Data {
        let fields = value.split(whereSeparator: \ .isWhitespace)
        guard fields.count >= 2, fields[0] == "ecdsa-sha2-nistp256",
              let blob = canonicalBase64(String(fields[1])) else {
            throw AgentPassNativeError.invalidKey("Recovery request proposed public key must be P-256")
        }
        var cursor = RecoverySSHCursor(data: blob)
        guard try cursor.readString() == Data("ecdsa-sha2-nistp256".utf8),
              try cursor.readString() == Data("nistp256".utf8) else {
            throw AgentPassNativeError.invalidKey("Recovery request proposed public key must be P-256")
        }
        let point = try cursor.readString()
        guard cursor.isAtEnd, point.count == 65, point.first == 0x04,
              (try? P256.Signing.PublicKey(x963Representation: point)) != nil else {
            throw AgentPassNativeError.invalidKey("Recovery request proposed public key must be P-256")
        }
        return point
    }

    private static func ed25519PublicKey(_ value: String) throws -> (key: Curve25519.Signing.PublicKey, fingerprint: String) {
        let lines = value.split(whereSeparator: \ .isNewline).map(String.init)
        let prefix = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])
        guard lines.count >= 3, lines.first == "-----BEGIN PUBLIC KEY-----", lines.last == "-----END PUBLIC KEY-----",
              let der = canonicalBase64(lines.dropFirst().dropLast().joined()), der.count == 44,
              der.prefix(prefix.count) == prefix,
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: der.suffix(32)) else {
            throw AgentPassNativeError.invalidKey("Recovery authority public key must be Ed25519 SPKI PEM")
        }
        return (key, "SHA256:" + base64URL(Data(SHA256.hash(data: der))))
    }

    private static func requiredString(_ object: [String: RecoveryJSONValue], key: String, label: String) throws -> String {
        guard case .string(let value)? = object[key] else {
            throw AgentPassNativeError.invalidConfiguration("\(label) is invalid")
        }
        return value
    }

    private static func requiredInteger(_ object: [String: RecoveryJSONValue], key: String, label: String) throws -> Int {
        guard case .integer(let value)? = object[key], let result = Int(exactly: value) else {
            throw AgentPassNativeError.invalidConfiguration("\(label) is invalid")
        }
        return result
    }

    private static func requiredSafeInteger(_ object: [String: RecoveryJSONValue], key: String, minimum: Int, label: String) throws -> Int {
        let value = try requiredInteger(object, key: key, label: label)
        guard value >= minimum, value <= maximumSafeInteger else {
            throw AgentPassNativeError.invalidConfiguration("\(label) is invalid")
        }
        return value
    }

    private static func requiredSlug(_ object: [String: RecoveryJSONValue], key: String, label: String) throws -> String {
        let value = try requiredString(object, key: key, label: label)
        guard isSlug(value) else { throw AgentPassNativeError.invalidConfiguration("\(label) is invalid") }
        return value
    }

    private static func requiredHash(_ object: [String: RecoveryJSONValue], key: String, label: String) throws -> String {
        let value = try requiredString(object, key: key, label: label)
        guard isHash(value) else { throw AgentPassNativeError.invalidConfiguration("\(label) is invalid") }
        return value
    }

    private static func requireExactKeys(_ object: [String: RecoveryJSONValue], _ keys: Set<String>, label: String) throws {
        guard Set(object.keys) == keys else {
            throw AgentPassNativeError.invalidConfiguration("\(label) encoding is invalid")
        }
    }

    private static func isSlug(_ value: String) -> Bool {
        guard (1...64).contains(value.utf8.count), let first = value.unicodeScalars.first,
              asciiAlphaNumeric.contains(first) else { return false }
        return value.unicodeScalars.dropFirst().allSatisfy { asciiAlphaNumeric.contains($0) || $0 == "." || $0 == "_" || $0 == "-" }
    }

    private static func isHash(_ value: String) -> Bool {
        value.utf8.count == 64 && value.unicodeScalars.allSatisfy { ("0"..."9").contains($0) || ("a"..."f").contains($0) }
    }

    private static func isFingerprint(_ value: String) -> Bool {
        guard value.hasPrefix("SHA256:") else { return false }
        let suffix = value.dropFirst(7)
        return suffix.utf8.count == 43 && suffix.unicodeScalars.allSatisfy { base64URLCharacters.contains($0) }
    }

    private static let asciiAlphaNumeric = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    private static let base64URLCharacters = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")

    private static func canonicalBase64(_ value: String) -> Data? {
        guard !value.isEmpty, value.utf8.count % 4 == 0,
              value.unicodeScalars.allSatisfy({ ("A"..."Z").contains($0) || ("a"..."z").contains($0) || ("0"..."9").contains($0) || $0 == "+" || $0 == "/" || $0 == "=" }),
              let firstPadding = value.firstIndex(of: "=") else {
            if value.isEmpty { return nil }
            guard let decoded = Data(base64Encoded: value), decoded.base64EncodedString() == value else { return nil }
            return decoded
        }
        let paddingCount = value.distance(from: firstPadding, to: value.endIndex)
        guard paddingCount <= 2, value[firstPadding...].allSatisfy({ $0 == "=" }),
              let decoded = Data(base64Encoded: value), decoded.base64EncodedString() == value else { return nil }
        return decoded
    }

    private static func timestampMilliseconds(_ value: String) -> Int64? {
        guard value.utf8.count <= 128 else { return nil }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let basic = ISO8601DateFormatter()
        basic.formatOptions = [.withInternetDateTime]
        guard let date = fractional.date(from: value) ?? basic.date(from: value) else { return nil }
        let milliseconds = date.timeIntervalSince1970 * 1_000
        guard milliseconds.isFinite, milliseconds >= Double(Int64.min), milliseconds <= Double(Int64.max) else { return nil }
        return Int64(milliseconds.rounded())
    }

    private static func addingClamped(_ value: Int64, _ addition: Int64) -> Int64 {
        let (result, overflow) = value.addingReportingOverflow(addition)
        return overflow ? Int64.max : result
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}

private enum RecoveryJSONValue: Equatable, Sendable {
    case object([String: RecoveryJSONValue])
    case array([RecoveryJSONValue])
    case string(String)
    case integer(Int64)
    case bool(Bool)
    case null

    var arrayValue: [RecoveryJSONValue]? {
        guard case .array(let value) = self else { return nil }
        return value
    }

    func object(label: String) throws -> [String: RecoveryJSONValue] {
        guard case .object(let value) = self else {
            throw AgentPassNativeError.invalidConfiguration("\(label) encoding is invalid")
        }
        return value
    }

    func canonicalData() throws -> Data { Data(try canonicalString().utf8) }

    private func canonicalString() throws -> String {
        switch self {
        case .object(let object):
            return "{" + (try object.keys.sorted().map { key in
                try Self.quoted(key) + ":" + object[key]!.canonicalString()
            }).joined(separator: ",") + "}"
        case .array(let array):
            return "[" + (try array.map { try $0.canonicalString() }).joined(separator: ",") + "]"
        case .string(let value): return try Self.quoted(value)
        case .integer(let value): return String(value)
        case .bool(let value): return value ? "true" : "false"
        case .null: return "null"
        }
    }

    private static func quoted(_ value: String) throws -> String {
        let encoded = try JSONSerialization.data(withJSONObject: [value], options: [.withoutEscapingSlashes])
        let text = String(decoding: encoded, as: UTF8.self)
        return String(text.dropFirst().dropLast())
    }
}

private struct RecoveryJSONDocument {
    let root: RecoveryJSONValue
    let canonicalData: Data

    init(data: Data, maximumBytes: Int, label: String) throws {
        guard !data.isEmpty, data.count <= maximumBytes, let text = String(data: data, encoding: .utf8) else {
            throw AgentPassNativeError.invalidConfiguration("\(label) must contain bounded UTF-8 canonical JSON")
        }
        let content = text.hasSuffix("\n") ? String(text.dropLast()) : text
        guard !content.isEmpty, !content.hasSuffix("\n") else {
            throw AgentPassNativeError.invalidConfiguration("\(label) must contain canonical JSON")
        }
        var parser = RecoveryJSONParser(text: content, label: label)
        root = try parser.parse()
        canonicalData = try root.canonicalData()
        guard Data(content.utf8) == canonicalData else {
            throw AgentPassNativeError.invalidConfiguration("\(label) must contain canonical JSON")
        }
    }
}

private struct RecoveryJSONParser {
    let scalars: [UnicodeScalar]
    let label: String
    var index = 0

    init(text: String, label: String) {
        scalars = Array(text.unicodeScalars)
        self.label = label
    }

    mutating func parse() throws -> RecoveryJSONValue {
        let value = try parseValue(depth: 0)
        guard index == scalars.count else { throw invalid() }
        return value
    }

    private mutating func parseValue(depth: Int) throws -> RecoveryJSONValue {
        guard depth <= 16 else { throw invalid() }
        guard index < scalars.count else { throw invalid() }
        switch scalars[index] {
        case "{": return try parseObject(depth: depth)
        case "[": return try parseArray(depth: depth)
        case "\"": return .string(try parseString())
        case "t": try consume("true"); return .bool(true)
        case "f": try consume("false"); return .bool(false)
        case "n": try consume("null"); return .null
        case "-", "0"..."9": return .integer(try parseInteger())
        default: throw invalid()
        }
    }

    private mutating func parseObject(depth: Int) throws -> RecoveryJSONValue {
        try expect("{")
        var result: [String: RecoveryJSONValue] = [:]
        if take("}") { return .object(result) }
        while true {
            guard index < scalars.count, scalars[index] == "\"" else { throw invalid() }
            let key = try parseString()
            guard result[key] == nil else {
                throw AgentPassNativeError.invalidConfiguration("\(label) contains a duplicate JSON key")
            }
            try expect(":")
            result[key] = try parseValue(depth: depth + 1)
            if take("}") { return .object(result) }
            try expect(",")
        }
    }

    private mutating func parseArray(depth: Int) throws -> RecoveryJSONValue {
        try expect("[")
        var result: [RecoveryJSONValue] = []
        if take("]") { return .array(result) }
        while true {
            result.append(try parseValue(depth: depth + 1))
            if take("]") { return .array(result) }
            try expect(",")
        }
    }

    private mutating func parseString() throws -> String {
        try expect("\"")
        var result = String.UnicodeScalarView()
        while index < scalars.count {
            let scalar = scalars[index]
            index += 1
            if scalar == "\"" { return String(result) }
            if scalar == "\\" {
                guard index < scalars.count else { throw invalid() }
                let escaped = scalars[index]
                index += 1
                switch escaped {
                case "\"", "\\", "/": result.append(escaped)
                case "b": result.append("\u{08}")
                case "f": result.append("\u{0c}")
                case "n": result.append("\n")
                case "r": result.append("\r")
                case "t": result.append("\t")
                case "u":
                    let first = try parseHex16()
                    if (0xD800...0xDBFF).contains(first) {
                        guard take("\\"), take("u") else { throw invalid() }
                        let second = try parseHex16()
                        guard (0xDC00...0xDFFF).contains(second),
                              let combined = UnicodeScalar(0x10000 + ((first - 0xD800) << 10) + second - 0xDC00) else { throw invalid() }
                        result.append(combined)
                    } else {
                        guard !(0xDC00...0xDFFF).contains(first), let decoded = UnicodeScalar(first) else { throw invalid() }
                        result.append(decoded)
                    }
                default: throw invalid()
                }
            } else {
                guard scalar.value >= 0x20 else { throw invalid() }
                result.append(scalar)
            }
        }
        throw invalid()
    }

    private mutating func parseHex16() throws -> UInt32 {
        guard index + 4 <= scalars.count else { throw invalid() }
        var value: UInt32 = 0
        for _ in 0..<4 {
            let scalar = scalars[index]
            index += 1
            let digit: UInt32
            switch scalar {
            case "0"..."9": digit = scalar.value - 48
            case "a"..."f": digit = scalar.value - 87
            case "A"..."F": digit = scalar.value - 55
            default: throw invalid()
            }
            value = value * 16 + digit
        }
        return value
    }

    private mutating func parseInteger() throws -> Int64 {
        let start = index
        _ = take("-")
        guard index < scalars.count else { throw invalid() }
        if take("0") {
            if index < scalars.count, ("0"..."9").contains(scalars[index]) { throw invalid() }
        } else {
            guard ("1"..."9").contains(scalars[index]) else { throw invalid() }
            while index < scalars.count, ("0"..."9").contains(scalars[index]) { index += 1 }
        }
        if index < scalars.count, scalars[index] == "." || scalars[index] == "e" || scalars[index] == "E" { throw invalid() }
        guard let value = Int64(String(String.UnicodeScalarView(scalars[start..<index]))) else { throw invalid() }
        return value
    }

    private mutating func consume(_ value: String) throws {
        for scalar in value.unicodeScalars { try expect(scalar) }
    }

    private mutating func expect(_ scalar: UnicodeScalar) throws {
        guard take(scalar) else { throw invalid() }
    }

    private mutating func take(_ scalar: UnicodeScalar) -> Bool {
        guard index < scalars.count, scalars[index] == scalar else { return false }
        index += 1
        return true
    }

    private func invalid() -> AgentPassNativeError {
        .invalidConfiguration("\(label) must contain valid canonical JSON")
    }
}

private struct RecoverySSHCursor {
    let data: Data
    var offset = 0
    var isAtEnd: Bool { offset == data.count }

    mutating func readString() throws -> Data {
        guard offset + 4 <= data.count else {
            throw AgentPassNativeError.invalidKey("Recovery request proposed public key must be P-256")
        }
        let length = data[offset..<(offset + 4)].reduce(0) { ($0 << 8) | Int($1) }
        offset += 4
        guard length >= 0, length <= data.count - offset else {
            throw AgentPassNativeError.invalidKey("Recovery request proposed public key must be P-256")
        }
        defer { offset += length }
        return data.subdata(in: offset..<(offset + length))
    }
}
