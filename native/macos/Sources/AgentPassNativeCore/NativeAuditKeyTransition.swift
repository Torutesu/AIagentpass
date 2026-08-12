import CryptoKit
import Foundation

/// The exact version-2 statement accepted by `POST /v1/key-transitions/:tenant`.
///
/// The retiring public key and algorithm are intentionally not duplicated in the
/// wire artifact: the anchor obtains them from its enrolled key-generation state.
/// `oldKeyFingerprint` plus the retiring-key signature bind that state, while
/// `newPublicKey` canonically carries the replacement P-256 key and algorithm.
public struct NativeAuditKeyTransitionStatement: Codable, Equatable, Sendable {
    public static let version = 2
    public static let checkpointAlgorithm = "p256-sha256"
    public static let maximumEncodedBytes = 64 * 1024
    public static let maximumSafeInteger = 9_007_199_254_740_991

    public let version: Int
    public let tenant: String
    public let operationID: String
    public let fromGeneration: Int
    public let toGeneration: Int
    public let oldKeyFingerprint: String
    public let newKeyFingerprint: String
    public let newPublicKey: String
    public let lifecycleHeadHash: String
    public let createdAt: String
    public let previousTransitionHash: String
    public let previousTransitionReceiptHash: String
    public let lastCheckpointIndex: Int
    public let lastCheckpointHash: String
    public let lastCheckpointReceiptHash: String
    public let previousAnchorEventIndex: Int
    public let previousAnchorEventHash: String
    public let retiringGenerationPendingCheckpointCount: Int

    enum CodingKeys: String, CodingKey, CaseIterable {
        case version, tenant
        case operationID = "operation_id"
        case fromGeneration = "from_generation"
        case toGeneration = "to_generation"
        case oldKeyFingerprint = "old_key_fingerprint"
        case newKeyFingerprint = "new_key_fingerprint"
        case newPublicKey = "new_public_key"
        case lifecycleHeadHash = "lifecycle_head_hash"
        case createdAt = "created_at"
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
        tenant: String,
        operationID: String,
        fromGeneration: Int,
        oldPublicKeyX963: Data,
        newPublicKeyX963: Data,
        lifecycleHeadHash: String,
        lastCheckpointIndex: Int,
        lastCheckpointHash: String,
        lastCheckpointReceiptHash: String,
        previousTransitionHash: String = NativeAuditLog.zeroHash,
        previousTransitionReceiptHash: String = NativeAuditLog.zeroHash,
        previousAnchorEventIndex: Int,
        previousAnchorEventHash: String,
        retiringGenerationPendingCheckpointCount: Int = 0,
        createdAt: String
    ) throws {
        self.version = Self.version
        self.tenant = tenant
        self.operationID = operationID
        self.fromGeneration = fromGeneration
        self.toGeneration = try Self.incremented(fromGeneration)
        self.oldKeyFingerprint = NativeAuditCheckpoints.fingerprint(oldPublicKeyX963)
        self.newKeyFingerprint = NativeAuditCheckpoints.fingerprint(newPublicKeyX963)
        self.newPublicKey = try SSHSIG.authorizedKey(publicKeyX963: newPublicKeyX963)
        self.lifecycleHeadHash = lifecycleHeadHash
        self.createdAt = createdAt
        self.previousTransitionHash = previousTransitionHash
        self.previousTransitionReceiptHash = previousTransitionReceiptHash
        self.lastCheckpointIndex = lastCheckpointIndex
        self.lastCheckpointHash = lastCheckpointHash
        self.lastCheckpointReceiptHash = lastCheckpointReceiptHash
        self.previousAnchorEventIndex = previousAnchorEventIndex
        self.previousAnchorEventHash = previousAnchorEventHash
        self.retiringGenerationPendingCheckpointCount = retiringGenerationPendingCheckpointCount
        try validate(retiringPublicKeyX963: oldPublicKeyX963)
    }

    public func canonicalData() throws -> Data {
        let data = try NativeAuditLog.canonical(canonicalObject())
        guard data.count <= Self.maximumEncodedBytes else {
            throw AgentPassNativeError.invalidConfiguration("Native audit key transition statement is too large")
        }
        return data
    }

    public func validate(retiringPublicKeyX963: Data? = nil) throws {
        guard version == Self.version,
              Self.isSlug(tenant), Self.isSlug(operationID),
              fromGeneration > 0, fromGeneration < Self.maximumSafeInteger,
              toGeneration == fromGeneration + 1, toGeneration <= Self.maximumSafeInteger,
              Self.isFingerprint(oldKeyFingerprint), Self.isFingerprint(newKeyFingerprint),
              oldKeyFingerprint != newKeyFingerprint,
              Self.isHash(lifecycleHeadHash), Self.isTimestamp(createdAt),
              Self.isHash(previousTransitionHash), Self.isHash(previousTransitionReceiptHash),
              lastCheckpointIndex > 0, lastCheckpointIndex <= Self.maximumSafeInteger,
              Self.isHash(lastCheckpointHash), Self.isHash(lastCheckpointReceiptHash),
              previousAnchorEventIndex > 0, previousAnchorEventIndex <= Self.maximumSafeInteger,
              Self.isHash(previousAnchorEventHash),
              retiringGenerationPendingCheckpointCount == 0 else {
            throw AgentPassNativeError.invalidSignature("Native audit key transition statement is invalid")
        }
        let newRaw = try SSHSIG.p256PublicKey(fromAuthorizedKey: newPublicKey)
        let canonicalNewPublicKey = try SSHSIG.authorizedKey(publicKeyX963: newRaw)
        guard newPublicKey.utf8.count <= 512,
              newPublicKey == canonicalNewPublicKey,
              newKeyFingerprint == NativeAuditCheckpoints.fingerprint(newRaw) else {
            throw AgentPassNativeError.invalidKey("Native audit key transition replacement key is invalid")
        }
        if let retiringPublicKeyX963 {
            _ = try P256.Signing.PublicKey(x963Representation: retiringPublicKeyX963)
            guard oldKeyFingerprint == NativeAuditCheckpoints.fingerprint(retiringPublicKeyX963) else {
                throw AgentPassNativeError.invalidKey("Native audit key transition retiring key does not match its fingerprint")
            }
        }
        _ = try canonicalData()
    }

    fileprivate func canonicalObject() -> [String: Any] {
        [
            "version": version, "tenant": tenant, "operation_id": operationID,
            "from_generation": fromGeneration, "to_generation": toGeneration,
            "old_key_fingerprint": oldKeyFingerprint, "new_key_fingerprint": newKeyFingerprint,
            "new_public_key": newPublicKey, "lifecycle_head_hash": lifecycleHeadHash,
            "created_at": createdAt, "previous_transition_hash": previousTransitionHash,
            "previous_transition_receipt_hash": previousTransitionReceiptHash,
            "last_checkpoint_index": lastCheckpointIndex, "last_checkpoint_hash": lastCheckpointHash,
            "last_checkpoint_receipt_hash": lastCheckpointReceiptHash,
            "previous_anchor_event_index": previousAnchorEventIndex,
            "previous_anchor_event_hash": previousAnchorEventHash,
            "retiring_generation_pending_checkpoint_count": retiringGenerationPendingCheckpointCount
        ]
    }

    fileprivate static func isHash(_ value: String) -> Bool {
        value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
    }

    fileprivate static func isFingerprint(_ value: String) -> Bool {
        value.range(of: "^SHA256:[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil
    }

    fileprivate static func isSlug(_ value: String) -> Bool {
        value.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", options: .regularExpression) != nil
    }

    fileprivate static func isTimestamp(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 64 else { return false }
        let withFractions = ISO8601DateFormatter()
        withFractions.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if withFractions.date(from: value) != nil { return true }
        let withoutFractions = ISO8601DateFormatter()
        withoutFractions.formatOptions = [.withInternetDateTime]
        return withoutFractions.date(from: value) != nil
    }

    private static func incremented(_ value: Int) throws -> Int {
        guard value > 0, value < maximumSafeInteger else {
            throw AgentPassNativeError.invalidConfiguration("Native audit key generation is invalid")
        }
        return value + 1
    }

}

public struct NativeAuditKeyTransition: Codable, Equatable, Sendable {
    public let version: Int
    public let tenant: String
    public let operationID: String
    public let fromGeneration: Int
    public let toGeneration: Int
    public let oldKeyFingerprint: String
    public let newKeyFingerprint: String
    public let newPublicKey: String
    public let lifecycleHeadHash: String
    public let createdAt: String
    public let previousTransitionHash: String
    public let previousTransitionReceiptHash: String
    public let lastCheckpointIndex: Int
    public let lastCheckpointHash: String
    public let lastCheckpointReceiptHash: String
    public let previousAnchorEventIndex: Int
    public let previousAnchorEventHash: String
    public let retiringGenerationPendingCheckpointCount: Int
    public let oldSignature: String
    public let newSignature: String
    public let transitionHash: String

    enum CodingKeys: String, CodingKey, CaseIterable {
        case version, tenant
        case operationID = "operation_id"
        case fromGeneration = "from_generation"
        case toGeneration = "to_generation"
        case oldKeyFingerprint = "old_key_fingerprint"
        case newKeyFingerprint = "new_key_fingerprint"
        case newPublicKey = "new_public_key"
        case lifecycleHeadHash = "lifecycle_head_hash"
        case createdAt = "created_at"
        case previousTransitionHash = "previous_transition_hash"
        case previousTransitionReceiptHash = "previous_transition_receipt_hash"
        case lastCheckpointIndex = "last_checkpoint_index"
        case lastCheckpointHash = "last_checkpoint_hash"
        case lastCheckpointReceiptHash = "last_checkpoint_receipt_hash"
        case previousAnchorEventIndex = "previous_anchor_event_index"
        case previousAnchorEventHash = "previous_anchor_event_hash"
        case retiringGenerationPendingCheckpointCount = "retiring_generation_pending_checkpoint_count"
        case oldSignature = "old_signature"
        case newSignature = "new_signature"
        case transitionHash = "transition_hash"
    }

    public init(statement: NativeAuditKeyTransitionStatement, retiringSigner: P256MessageSigner, replacementSigner: P256MessageSigner) throws {
        try statement.validate(retiringPublicKeyX963: retiringSigner.publicKeyX963)
        let replacementRaw = try SSHSIG.p256PublicKey(fromAuthorizedKey: statement.newPublicKey)
        guard replacementSigner.publicKeyX963 == replacementRaw else {
            throw AgentPassNativeError.invalidKey("Native audit key transition replacement signer does not match the statement")
        }
        let statementData = try statement.canonicalData()
        let oldRaw = try retiringSigner.sign(message: statementData)
        let newRaw = try replacementSigner.sign(message: statementData)
        guard oldRaw.count == 64, newRaw.count == 64 else {
            throw AgentPassNativeError.invalidSignature("Native audit key transition P-256 signatures must be 64-byte raw signatures")
        }
        try self.init(statement: statement, oldSignature: oldRaw.base64EncodedString(), newSignature: newRaw.base64EncodedString())
    }

    private init(statement: NativeAuditKeyTransitionStatement, oldSignature: String, newSignature: String) throws {
        version = statement.version
        tenant = statement.tenant
        operationID = statement.operationID
        fromGeneration = statement.fromGeneration
        toGeneration = statement.toGeneration
        oldKeyFingerprint = statement.oldKeyFingerprint
        newKeyFingerprint = statement.newKeyFingerprint
        newPublicKey = statement.newPublicKey
        lifecycleHeadHash = statement.lifecycleHeadHash
        createdAt = statement.createdAt
        previousTransitionHash = statement.previousTransitionHash
        previousTransitionReceiptHash = statement.previousTransitionReceiptHash
        lastCheckpointIndex = statement.lastCheckpointIndex
        lastCheckpointHash = statement.lastCheckpointHash
        lastCheckpointReceiptHash = statement.lastCheckpointReceiptHash
        previousAnchorEventIndex = statement.previousAnchorEventIndex
        previousAnchorEventHash = statement.previousAnchorEventHash
        retiringGenerationPendingCheckpointCount = statement.retiringGenerationPendingCheckpointCount
        self.oldSignature = oldSignature
        self.newSignature = newSignature
        var signed = statement.canonicalObject()
        signed["old_signature"] = oldSignature
        signed["new_signature"] = newSignature
        transitionHash = NativeAuditLog.hash(try NativeAuditLog.canonical(signed))
    }

    public func canonicalData() throws -> Data {
        let data = try NativeAuditLog.canonical(canonicalObject(includeHash: true))
        guard data.count <= NativeAuditKeyTransitionStatement.maximumEncodedBytes else {
            throw AgentPassNativeError.invalidSignature("Native audit key transition is too large")
        }
        return data
    }

    public static func decodeCanonical(_ data: Data) throws -> NativeAuditKeyTransition {
        let expectedKeys = Set(CodingKeys.allCases.map(\.stringValue))
        guard !data.isEmpty, data.count <= NativeAuditKeyTransitionStatement.maximumEncodedBytes,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == expectedKeys else {
            throw AgentPassNativeError.invalidSignature("Native audit key transition encoding is invalid")
        }
        let value = try JSONDecoder().decode(Self.self, from: data)
        guard try value.canonicalData() == data else {
            throw AgentPassNativeError.invalidSignature("Native audit key transition is not canonically encoded")
        }
        try value.validate()
        return value
    }

    public static func decodeCanonical(_ data: Data, retiringPublicKeyX963: Data) throws -> NativeAuditKeyTransition {
        let value = try decodeCanonical(data)
        try value.verify(retiringPublicKeyX963: retiringPublicKeyX963)
        return value
    }

    public func validate(retiringPublicKeyX963: Data? = nil) throws {
        let value = try makeStatement()
        try value.validate(retiringPublicKeyX963: retiringPublicKeyX963)
        guard let oldRaw = Self.canonicalSignature(oldSignature), let newRaw = Self.canonicalSignature(newSignature) else {
            throw AgentPassNativeError.invalidSignature("Native audit key transition signature encoding is invalid")
        }
        let newRawKey = try SSHSIG.p256PublicKey(fromAuthorizedKey: newPublicKey)
        let newKey = try P256.Signing.PublicKey(x963Representation: newRawKey)
        let message = try value.canonicalData()
        let newECDSA = try P256.Signing.ECDSASignature(rawRepresentation: newRaw)
        guard newKey.isValidSignature(newECDSA, for: message) else {
            throw AgentPassNativeError.invalidSignature("Native audit key transition replacement-key signature is invalid")
        }
        if let retiringPublicKeyX963 {
            let oldKey = try P256.Signing.PublicKey(x963Representation: retiringPublicKeyX963)
            let oldECDSA = try P256.Signing.ECDSASignature(rawRepresentation: oldRaw)
            guard oldKey.isValidSignature(oldECDSA, for: message) else {
                throw AgentPassNativeError.invalidSignature("Native audit key transition retiring-key signature is invalid")
            }
        }
        var unhashed = value.canonicalObject()
        unhashed["old_signature"] = oldSignature
        unhashed["new_signature"] = newSignature
        guard transitionHash == NativeAuditLog.hash(try NativeAuditLog.canonical(unhashed)) else {
            throw AgentPassNativeError.invalidSignature("Native audit key transition hash is invalid")
        }
    }

    public func verify(retiringPublicKeyX963: Data) throws {
        try validate(retiringPublicKeyX963: retiringPublicKeyX963)
    }

    fileprivate func makeStatement() throws -> NativeAuditKeyTransitionStatement {
        let encoded = try NativeAuditLog.canonical(statementObject())
        return try JSONDecoder().decode(NativeAuditKeyTransitionStatement.self, from: encoded)
    }

    fileprivate func statementObject() -> [String: Any] {
        var value = canonicalObject(includeHash: false)
        value.removeValue(forKey: "old_signature")
        value.removeValue(forKey: "new_signature")
        return value
    }

    fileprivate func canonicalObject(includeHash: Bool) -> [String: Any] {
        var value: [String: Any] = [
            "version": version, "tenant": tenant, "operation_id": operationID,
            "from_generation": fromGeneration, "to_generation": toGeneration,
            "old_key_fingerprint": oldKeyFingerprint, "new_key_fingerprint": newKeyFingerprint,
            "new_public_key": newPublicKey, "lifecycle_head_hash": lifecycleHeadHash,
            "created_at": createdAt, "previous_transition_hash": previousTransitionHash,
            "previous_transition_receipt_hash": previousTransitionReceiptHash,
            "last_checkpoint_index": lastCheckpointIndex, "last_checkpoint_hash": lastCheckpointHash,
            "last_checkpoint_receipt_hash": lastCheckpointReceiptHash,
            "previous_anchor_event_index": previousAnchorEventIndex,
            "previous_anchor_event_hash": previousAnchorEventHash,
            "retiring_generation_pending_checkpoint_count": retiringGenerationPendingCheckpointCount,
            "old_signature": oldSignature, "new_signature": newSignature
        ]
        if includeHash { value["transition_hash"] = transitionHash }
        return value
    }

    private static func canonicalSignature(_ value: String) -> Data? {
        guard value.utf8.count <= 128, let raw = Data(base64Encoded: value), raw.count == 64,
              raw.base64EncodedString() == value else { return nil }
        return raw
    }
}

public struct NativeAuditKeyTransitionReceipt: Codable, Equatable, Sendable {
    public let version: Int
    public let tenant: String
    public let index: Int
    public let transitionHash: String
    public let receivedAt: String
    public let previousReceiptHash: String
    public let eventIndex: Int
    public let previousEventHash: String
    public let lastCheckpointIndex: Int
    public let lastCheckpointHash: String
    public let lastCheckpointReceiptHash: String
    public let anchorKeyFingerprint: String
    public let signature: String
    public let receiptHash: String

    enum CodingKeys: String, CodingKey, CaseIterable {
        case version, tenant, index, signature
        case transitionHash = "transition_hash"
        case receivedAt = "received_at"
        case previousReceiptHash = "previous_receipt_hash"
        case eventIndex = "event_index"
        case previousEventHash = "previous_event_hash"
        case lastCheckpointIndex = "last_checkpoint_index"
        case lastCheckpointHash = "last_checkpoint_hash"
        case lastCheckpointReceiptHash = "last_checkpoint_receipt_hash"
        case anchorKeyFingerprint = "anchor_key_fingerprint"
        case receiptHash = "receipt_hash"
    }
}

public struct NativeAuditKeyTransitionReceiptVerifier: Sendable {
    private let tenant: String
    private let anchorKey: Curve25519.Signing.PublicKey
    private let anchorKeyFingerprint: String

    public init(tenant: String, anchorPublicKeyPEM: String) throws {
        guard NativeAuditKeyTransitionStatement.isSlug(tenant) else {
            throw AgentPassNativeError.invalidConfiguration("Native audit key transition receipt tenant is invalid")
        }
        let parsed = try Self.ed25519PublicKey(anchorPublicKeyPEM)
        self.tenant = tenant
        anchorKey = parsed.key
        anchorKeyFingerprint = "SHA256:" + Data(SHA256.hash(data: parsed.der)).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public func verify(
        receiptData: Data,
        transition: NativeAuditKeyTransition,
        expectedTransitionIndex: Int
    ) throws -> NativeAuditKeyTransitionReceipt {
        guard !receiptData.isEmpty, receiptData.count <= NativeAuditKeyTransitionStatement.maximumEncodedBytes,
              expectedTransitionIndex > 0, expectedTransitionIndex <= NativeAuditKeyTransitionStatement.maximumSafeInteger,
              let object = try JSONSerialization.jsonObject(with: receiptData) as? [String: Any],
              Set(object.keys) == Set(NativeAuditKeyTransitionReceipt.CodingKeys.allCases.map(\.stringValue)) else {
            throw AgentPassNativeError.invalidSignature("Native audit key transition receipt encoding is invalid")
        }
        let receipt = try JSONDecoder().decode(NativeAuditKeyTransitionReceipt.self, from: receiptData)
        let canonicalReceipt = try NativeAuditLog.canonical(receiptObject(receipt, includeHash: true))
        guard canonicalReceipt == receiptData else {
            throw AgentPassNativeError.invalidSignature("Native audit key transition receipt is not canonically encoded")
        }
        guard receipt.version == 2, receipt.tenant == tenant, receipt.tenant == transition.tenant,
              receipt.index == expectedTransitionIndex,
              receipt.transitionHash == transition.transitionHash,
              receipt.previousReceiptHash == transition.previousTransitionReceiptHash,
              receipt.eventIndex == transition.previousAnchorEventIndex + 1,
              receipt.eventIndex <= NativeAuditKeyTransitionStatement.maximumSafeInteger,
              receipt.previousEventHash == transition.previousAnchorEventHash,
              receipt.lastCheckpointIndex == transition.lastCheckpointIndex,
              receipt.lastCheckpointHash == transition.lastCheckpointHash,
              receipt.lastCheckpointReceiptHash == transition.lastCheckpointReceiptHash,
              receipt.anchorKeyFingerprint == anchorKeyFingerprint,
              NativeAuditKeyTransitionStatement.isTimestamp(receipt.receivedAt),
              Self.date(receipt.receivedAt) >= Self.date(transition.createdAt),
              NativeAuditKeyTransitionStatement.isHash(receipt.previousReceiptHash),
              NativeAuditKeyTransitionStatement.isHash(receipt.previousEventHash),
              NativeAuditKeyTransitionStatement.isHash(receipt.receiptHash),
              let signature = Data(base64Encoded: receipt.signature), signature.count == 64,
              signature.base64EncodedString() == receipt.signature else {
            throw AgentPassNativeError.invalidSignature("Native audit key transition receipt statement or event boundary is invalid")
        }
        let statement = receiptObject(receipt, includeHash: false, includeSignature: false)
        guard anchorKey.isValidSignature(signature, for: try NativeAuditLog.canonical(statement)) else {
            throw AgentPassNativeError.invalidSignature("Native audit key transition receipt signature is invalid")
        }
        let unhashed = receiptObject(receipt, includeHash: false)
        guard receipt.receiptHash == NativeAuditLog.hash(try NativeAuditLog.canonical(unhashed)) else {
            throw AgentPassNativeError.invalidSignature("Native audit key transition receipt hash is invalid")
        }
        return receipt
    }

    private func receiptObject(_ receipt: NativeAuditKeyTransitionReceipt, includeHash: Bool, includeSignature: Bool = true) -> [String: Any] {
        var value: [String: Any] = [
            "version": receipt.version, "tenant": receipt.tenant, "index": receipt.index,
            "transition_hash": receipt.transitionHash, "received_at": receipt.receivedAt,
            "previous_receipt_hash": receipt.previousReceiptHash, "event_index": receipt.eventIndex,
            "previous_event_hash": receipt.previousEventHash,
            "last_checkpoint_index": receipt.lastCheckpointIndex,
            "last_checkpoint_hash": receipt.lastCheckpointHash,
            "last_checkpoint_receipt_hash": receipt.lastCheckpointReceiptHash
        ]
        if includeSignature {
            value["anchor_key_fingerprint"] = receipt.anchorKeyFingerprint
            value["signature"] = receipt.signature
        }
        if includeHash { value["receipt_hash"] = receipt.receiptHash }
        return value
    }

    private static func date(_ value: String) -> Date {
        let withFractions = ISO8601DateFormatter()
        withFractions.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let result = withFractions.date(from: value) { return result }
        return ISO8601DateFormatter().date(from: value) ?? .distantPast
    }

    private static func ed25519PublicKey(_ pem: String) throws -> (key: Curve25519.Signing.PublicKey, der: Data) {
        guard pem.utf8.count <= 4 * 1024 else {
            throw AgentPassNativeError.invalidKey("Native audit anchor key is too large")
        }
        let lines = pem.split(whereSeparator: \.isNewline).map(String.init)
        guard lines.first == "-----BEGIN PUBLIC KEY-----", lines.last == "-----END PUBLIC KEY-----", lines.count >= 3,
              let der = Data(base64Encoded: lines.dropFirst().dropLast().joined()), der.count == 44,
              der.prefix(12) == Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) else {
            throw AgentPassNativeError.invalidKey("Native audit anchor key must be Ed25519 SPKI PEM")
        }
        return (try Curve25519.Signing.PublicKey(rawRepresentation: der.suffix(32)), der)
    }
}
