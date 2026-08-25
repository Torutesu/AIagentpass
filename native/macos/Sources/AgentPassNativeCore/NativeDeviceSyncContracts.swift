import CoreFoundation
import CryptoKit
import Foundation

public enum NativeDeviceSyncContractReason: String, Sendable {
    case invalidJSON = "invalid_json"
    case noncanonicalJSON = "noncanonical_json"
    case duplicateField = "duplicate_field"
    case unknownField = "unknown_field"
    case invalidType = "invalid_type"
    case invalidValue = "invalid_value"
    case invalidVersion = "invalid_version"
    case invalidIdentifier = "invalid_identifier"
    case invalidUUID = "invalid_uuid"
    case invalidGeneration = "invalid_generation"
    case invalidEpoch = "invalid_epoch"
    case invalidFormatEpoch = "invalid_format_epoch"
    case invalidSequence = "invalid_sequence"
    case invalidHash = "invalid_hash"
    case invalidTimestamp = "invalid_timestamp"
    case invalidWindow = "invalid_window"
    case invalidEncoding = "invalid_encoding"
    case invalidResult = "invalid_result"
    case invalidReason = "invalid_reason"
    case inconsistentReason = "inconsistent_reason"
    case invalidSignature = "invalid_signature"
}

public struct NativeDeviceSyncContractError: LocalizedError, Equatable, Sendable {
    public let reason: NativeDeviceSyncContractReason
    public let message: String

    public init(_ reason: NativeDeviceSyncContractReason, _ message: String? = nil) {
        self.reason = reason
        self.message = message ?? reason.rawValue
    }

    public var errorDescription: String? { "\(reason.rawValue): \(message)" }
}

public enum NativeBundleAcknowledgementResult: String, CaseIterable, Codable, Sendable {
    case applied
    case blocked
}

public enum NativeDeviceRefreshState: String, CaseIterable, Codable, Sendable {
    case pending
    case fetching
    case applied
    case blocked
    case stale
    case offline
    case revoked
}

public enum NativeBundleAcknowledgementReasonCode: String, CaseIterable, Codable, Sendable {
    case bundleExpired = "bundle_expired"
    case bundleNotYetValid = "bundle_not_yet_valid"
    case bundleSignatureInvalid = "bundle_signature_invalid"
    case bundleSignerUntrusted = "bundle_signer_untrusted"
    case bundleAudienceMismatch = "bundle_audience_mismatch"
    case bundleSequenceRollback = "bundle_sequence_rollback"
    case bundleSequenceConflict = "bundle_sequence_conflict"
    case bundleStorageFailed = "bundle_storage_failed"
    case deviceRevoked = "device_revoked"
    case emergencyStop = "emergency_stop"
    case internalError = "internal_error"
}

public struct NativeRefreshHint: Equatable, Sendable {
    public static let version = 1
    public static let type = "agentpass.refresh-hint"
    public static let signatureAlgorithm = "ed25519"

    public let version: Int
    public let type: String
    public let organizationID: String
    public let deviceID: String
    public let authorityGeneration: Int64
    public let publishedAt: String
    public let expiresAt: String
    public let nonce: String
    public let keyID: String
    public let signatureAlgorithm: String
    public let signature: String

    public init(
        version: Int = NativeRefreshHint.version,
        type: String = NativeRefreshHint.type,
        organizationID: String,
        deviceID: String,
        authorityGeneration: Int64,
        publishedAt: String,
        expiresAt: String,
        nonce: String,
        keyID: String,
        signatureAlgorithm: String = NativeRefreshHint.signatureAlgorithm,
        signature: String
    ) {
        self.version = version
        self.type = type
        self.organizationID = organizationID
        self.deviceID = deviceID
        self.authorityGeneration = authorityGeneration
        self.publishedAt = publishedAt
        self.expiresAt = expiresAt
        self.nonce = nonce
        self.keyID = keyID
        self.signatureAlgorithm = signatureAlgorithm
        self.signature = signature
    }
}

public struct NativeBundleAcknowledgement: Equatable, Sendable {
    public static let version = 1
    public static let type = "agentpass.bundle-ack"
    public static let signatureAlgorithm = "p256-sha256"

    public let version: Int
    public let type: String
    public let organizationID: String
    public let deviceID: String
    public let deviceKeyEpoch: Int64
    public let formatEpoch: Int
    public let sequence: Int64
    public let statementHash: String
    public let result: NativeBundleAcknowledgementResult
    public let reasonCode: NativeBundleAcknowledgementReasonCode?
    public let observedAt: String
    public let nonce: String
    public let signatureAlgorithm: String
    public let signature: String

    public init(
        version: Int = NativeBundleAcknowledgement.version,
        type: String = NativeBundleAcknowledgement.type,
        organizationID: String,
        deviceID: String,
        deviceKeyEpoch: Int64,
        formatEpoch: Int = 2,
        sequence: Int64,
        statementHash: String,
        result: NativeBundleAcknowledgementResult,
        reasonCode: NativeBundleAcknowledgementReasonCode? = nil,
        observedAt: String,
        nonce: String,
        signatureAlgorithm: String = NativeBundleAcknowledgement.signatureAlgorithm,
        signature: String
    ) {
        self.version = version
        self.type = type
        self.organizationID = organizationID
        self.deviceID = deviceID
        self.deviceKeyEpoch = deviceKeyEpoch
        self.formatEpoch = formatEpoch
        self.sequence = sequence
        self.statementHash = statementHash
        self.result = result
        self.reasonCode = reasonCode
        self.observedAt = observedAt
        self.nonce = nonce
        self.signatureAlgorithm = signatureAlgorithm
        self.signature = signature
    }
}

public enum NativeRefreshHintCodec {
    public static let signatureDomain = "AgentPass-Refresh-Hint-v1\0"
    public static let maxBytes = 16 * 1024

    public static func decode(_ data: Data) throws -> NativeRefreshHint {
        try parseObject(deviceSyncObject(from: data, maxBytes: maxBytes))
    }

    public static func parse(_ data: Data) throws -> NativeRefreshHint { try decode(data) }
    public static func normalize(_ data: Data) throws -> NativeRefreshHint { try decode(data) }

    public static func canonicalJSON(_ data: Data) throws -> Data {
        try canonicalJSON(decode(data))
    }

    public static func canonicalJSON(_ hint: NativeRefreshHint) throws -> Data {
        try NativeStrictJSON.data(object(hint, includeSignature: true))
    }

    public static func unsignedCanonicalJSON(_ hint: NativeRefreshHint) throws -> Data {
        try NativeStrictJSON.data(object(hint, includeSignature: false))
    }

    public static func signingData(_ data: Data) throws -> Data {
        try signingData(decode(data))
    }

    public static func signingData(_ hint: NativeRefreshHint) throws -> Data {
        let normalized = try parseObject(object(hint, includeSignature: true))
        return Data(signatureDomain.utf8) + (try unsignedCanonicalJSON(normalized))
    }

    public static func statementHash(_ hint: NativeRefreshHint) throws -> String {
        deviceSyncHex(Data(SHA256.hash(data: try signingData(hint))))
    }

    private static func parseObject(_ object: [String: Any]) throws -> NativeRefreshHint {
        try deviceSyncRejectUnknown(object, allowed: [
            "version", "type", "organization_id", "device_id", "authority_generation",
            "published_at", "expires_at", "nonce", "key_id", "signature_algorithm", "signature"
        ])
        guard let version = deviceSyncInt(object["version"]), version == 1 else {
            throw NativeDeviceSyncContractError(.invalidVersion, "refresh hint version must be 1")
        }
        guard let type = object["type"] as? String, type == NativeRefreshHint.type else {
            throw NativeDeviceSyncContractError(.invalidValue, "refresh hint type is invalid")
        }
        let organizationID = try deviceSyncUUID(object["organization_id"], field: "organization_id")
        let deviceID = try deviceSyncUUID(object["device_id"], field: "device_id")
        guard let generation = deviceSyncInt(object["authority_generation"]), generation > 0 else {
            throw NativeDeviceSyncContractError(.invalidGeneration, "authority generation must be a positive safe integer")
        }
        let published = try deviceSyncTimestamp(object["published_at"], field: "published_at")
        let expires = try deviceSyncTimestamp(object["expires_at"], field: "expires_at")
        guard expires.date > published.date,
              expires.date.timeIntervalSince(published.date) * 1_000 <= 5 * 60 * 1_000 else {
            throw NativeDeviceSyncContractError(.invalidWindow, "refresh hint lifetime must be greater than zero and at most five minutes")
        }
        let nonce = try deviceSyncBase64URL(object["nonce"], bytes: 16, field: "nonce")
        let keyID = try deviceSyncKeyID(object["key_id"])
        guard let signatureAlgorithm = object["signature_algorithm"] as? String,
              signatureAlgorithm == NativeRefreshHint.signatureAlgorithm else {
            throw NativeDeviceSyncContractError(.invalidValue, "refresh hint signature algorithm is invalid")
        }
        let signature = try deviceSyncBase64URL(object["signature"], bytes: 64, field: "signature")
        return NativeRefreshHint(
            organizationID: organizationID,
            deviceID: deviceID,
            authorityGeneration: generation,
            publishedAt: published.value,
            expiresAt: expires.value,
            nonce: nonce,
            keyID: keyID,
            signature: signature
        )
    }

    private static func object(_ hint: NativeRefreshHint, includeSignature: Bool) -> [String: Any] {
        var value: [String: Any] = [
            "version": hint.version,
            "type": hint.type,
            "organization_id": hint.organizationID,
            "device_id": hint.deviceID,
            "authority_generation": hint.authorityGeneration,
            "published_at": hint.publishedAt,
            "expires_at": hint.expiresAt,
            "nonce": hint.nonce,
            "key_id": hint.keyID,
            "signature_algorithm": hint.signatureAlgorithm
        ]
        if includeSignature { value["signature"] = hint.signature }
        return value
    }
}

public enum NativeBundleAcknowledgementCodec {
    public static let signatureDomain = "AgentPass-Bundle-Ack-v1\0"
    public static let maxBytes = 16 * 1024

    public static func decode(_ data: Data) throws -> NativeBundleAcknowledgement {
        try parseObject(deviceSyncObject(from: data, maxBytes: maxBytes))
    }

    public static func parse(_ data: Data) throws -> NativeBundleAcknowledgement { try decode(data) }
    public static func normalize(_ data: Data) throws -> NativeBundleAcknowledgement { try decode(data) }

    public static func canonicalJSON(_ data: Data) throws -> Data {
        try canonicalJSON(decode(data))
    }

    public static func canonicalJSON(_ acknowledgement: NativeBundleAcknowledgement) throws -> Data {
        try NativeStrictJSON.data(object(acknowledgement, includeSignature: true))
    }

    public static func unsignedCanonicalJSON(_ acknowledgement: NativeBundleAcknowledgement) throws -> Data {
        try NativeStrictJSON.data(object(acknowledgement, includeSignature: false))
    }

    public static func signingData(_ data: Data) throws -> Data {
        try signingData(decode(data))
    }

    public static func signingData(_ acknowledgement: NativeBundleAcknowledgement) throws -> Data {
        let normalized = try parseObject(object(acknowledgement, includeSignature: true))
        return Data(signatureDomain.utf8) + (try unsignedCanonicalJSON(normalized))
    }

    public static func statementHash(_ acknowledgement: NativeBundleAcknowledgement) throws -> String {
        deviceSyncHex(Data(SHA256.hash(data: try signingData(acknowledgement))))
    }

    private static func parseObject(_ object: [String: Any]) throws -> NativeBundleAcknowledgement {
        try deviceSyncRejectUnknown(object, allowed: [
            "version", "type", "organization_id", "device_id", "device_key_epoch", "format_epoch",
            "sequence", "statement_hash", "result", "reason_code", "observed_at", "nonce",
            "signature_algorithm", "signature"
        ])
        guard let version = deviceSyncInt(object["version"]), version == 1 else {
            throw NativeDeviceSyncContractError(.invalidVersion, "bundle acknowledgement version must be 1")
        }
        guard let type = object["type"] as? String, type == NativeBundleAcknowledgement.type else {
            throw NativeDeviceSyncContractError(.invalidValue, "bundle acknowledgement type is invalid")
        }
        let organizationID = try deviceSyncUUID(object["organization_id"], field: "organization_id")
        let deviceID = try deviceSyncUUID(object["device_id"], field: "device_id")
        guard let deviceKeyEpoch = deviceSyncInt(object["device_key_epoch"]), deviceKeyEpoch > 0 else {
            throw NativeDeviceSyncContractError(.invalidEpoch, "device key epoch must be a positive safe integer")
        }
        guard let formatEpoch = deviceSyncInt(object["format_epoch"]), formatEpoch == 2 else {
            throw NativeDeviceSyncContractError(.invalidFormatEpoch, "bundle acknowledgement format epoch must be 2")
        }
        guard let sequence = deviceSyncInt(object["sequence"]), sequence > 0 else {
            throw NativeDeviceSyncContractError(.invalidSequence, "bundle acknowledgement sequence must be a positive safe integer")
        }
        guard let statementHash = object["statement_hash"] as? String,
              statementHash.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
            throw NativeDeviceSyncContractError(.invalidHash, "statement hash must be 64 lowercase hexadecimal characters")
        }
        guard let resultValue = object["result"] as? String,
              let result = NativeBundleAcknowledgementResult(rawValue: resultValue) else {
            throw NativeDeviceSyncContractError(.invalidResult, "acknowledgement result must be applied or blocked")
        }
        let reasonCode: NativeBundleAcknowledgementReasonCode?
        if object.keys.contains("reason_code") {
            guard let value = object["reason_code"] as? String,
                  let parsed = NativeBundleAcknowledgementReasonCode(rawValue: value) else {
                throw NativeDeviceSyncContractError(.invalidReason, "acknowledgement reason code is invalid")
            }
            reasonCode = parsed
        } else {
            reasonCode = nil
        }
        if result == .blocked, reasonCode == nil {
            throw NativeDeviceSyncContractError(.invalidReason, "blocked acknowledgements require a reason code")
        }
        if result == .applied, reasonCode != nil {
            throw NativeDeviceSyncContractError(.inconsistentReason, "applied acknowledgements cannot include a reason code")
        }
        let observedAt = try deviceSyncTimestamp(object["observed_at"], field: "observed_at")
        let nonce = try deviceSyncBase64URL(object["nonce"], bytes: 16, field: "nonce")
        guard let signatureAlgorithm = object["signature_algorithm"] as? String,
              signatureAlgorithm == NativeBundleAcknowledgement.signatureAlgorithm else {
            throw NativeDeviceSyncContractError(.invalidValue, "bundle acknowledgement signature algorithm is invalid")
        }
        let signature = try deviceSyncP256Signature(object["signature"])
        return NativeBundleAcknowledgement(
            organizationID: organizationID,
            deviceID: deviceID,
            deviceKeyEpoch: deviceKeyEpoch,
            formatEpoch: Int(formatEpoch),
            sequence: sequence,
            statementHash: statementHash,
            result: result,
            reasonCode: reasonCode,
            observedAt: observedAt.value,
            nonce: nonce,
            signature: signature
        )
    }

    private static func object(_ acknowledgement: NativeBundleAcknowledgement, includeSignature: Bool) -> [String: Any] {
        var value: [String: Any] = [
            "version": acknowledgement.version,
            "type": acknowledgement.type,
            "organization_id": acknowledgement.organizationID,
            "device_id": acknowledgement.deviceID,
            "device_key_epoch": acknowledgement.deviceKeyEpoch,
            "format_epoch": acknowledgement.formatEpoch,
            "sequence": acknowledgement.sequence,
            "statement_hash": acknowledgement.statementHash,
            "result": acknowledgement.result.rawValue,
            "observed_at": acknowledgement.observedAt,
            "nonce": acknowledgement.nonce,
            "signature_algorithm": acknowledgement.signatureAlgorithm
        ]
        if let reasonCode = acknowledgement.reasonCode { value["reason_code"] = reasonCode.rawValue }
        if includeSignature { value["signature"] = acknowledgement.signature }
        return value
    }
}

public func decodeNativeRefreshHint(_ data: Data) throws -> NativeRefreshHint {
    try NativeRefreshHintCodec.decode(data)
}

public func normalizeNativeRefreshHint(_ data: Data) throws -> NativeRefreshHint {
    try NativeRefreshHintCodec.normalize(data)
}

public func decodeNativeBundleAcknowledgement(_ data: Data) throws -> NativeBundleAcknowledgement {
    try NativeBundleAcknowledgementCodec.decode(data)
}

public func normalizeNativeBundleAcknowledgement(_ data: Data) throws -> NativeBundleAcknowledgement {
    try NativeBundleAcknowledgementCodec.normalize(data)
}

private func deviceSyncObject(from data: Data, maxBytes: Int) throws -> [String: Any] {
    guard !data.isEmpty, data.count <= maxBytes else {
        throw NativeDeviceSyncContractError(.invalidJSON, "device sync contract JSON size is invalid")
    }
    let object: [String: Any]
    do {
        object = try NativeStrictJSON.object(from: data, maxBytes: maxBytes, maxDepth: 8)
    } catch {
        throw error
    }
    return object
}

private func deviceSyncRejectUnknown(_ object: [String: Any], allowed: Set<String>) throws {
    if let key = object.keys.first(where: { !allowed.contains($0) }) {
        throw NativeDeviceSyncContractError(.unknownField, "unknown field: \(key)")
    }
}

private func deviceSyncHex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

private func deviceSyncInt(_ value: Any?) -> Int64? {
    guard let number = value as? NSNumber,
          CFGetTypeID(number) != CFBooleanGetTypeID(),
          number.doubleValue.isFinite,
          number.doubleValue.rounded() == number.doubleValue,
          number.doubleValue >= 0,
          number.doubleValue <= 9_007_199_254_740_991 else { return nil }
    return number.int64Value
}

private func deviceSyncUUID(_ value: Any?, field: String) throws -> String {
    guard let value = value as? String,
          value.range(of: "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$", options: .regularExpression) != nil else {
        throw NativeDeviceSyncContractError(.invalidUUID, "\(field) must be a canonical RFC 4122 UUID")
    }
    return value.lowercased()
}

private struct NativeDeviceSyncTimestamp {
    let value: String
    let date: Date
}

private func deviceSyncTimestamp(_ value: Any?, field: String) throws -> NativeDeviceSyncTimestamp {
    guard let value = value as? String,
          value.range(of: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$", options: .regularExpression) != nil else {
        throw NativeDeviceSyncContractError(.invalidTimestamp, "\(field) must use canonical millisecond UTC timestamp form")
    }
    let parser = ISO8601DateFormatter()
    parser.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    guard let date = parser.date(from: value), dateSyncTimestamp(date) == value else {
        throw NativeDeviceSyncContractError(.invalidTimestamp, "\(field) is not a real canonical UTC instant")
    }
    return NativeDeviceSyncTimestamp(value: value, date: date)
}

private func dateSyncTimestamp(_ date: Date) -> String {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = TimeZone(secondsFromGMT: 0)
    formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
    return formatter.string(from: date)
}

private func deviceSyncKeyID(_ value: Any?) throws -> String {
    guard let value = value as? String,
          value.range(of: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$", options: .regularExpression) != nil else {
        throw NativeDeviceSyncContractError(.invalidIdentifier, "key_id must be a bounded identifier")
    }
    return value
}

private func deviceSyncBase64URL(_ value: Any?, bytes: Int, field: String) throws -> String {
    guard let value = value as? String,
          let decoded = deviceSyncDecodeBase64URL(value),
          decoded.count == bytes else {
        throw NativeDeviceSyncContractError(.invalidEncoding, "\(field) must be canonical unpadded base64url for exactly \(bytes) bytes")
    }
    return value
}

private func deviceSyncP256Signature(_ value: Any?) throws -> String {
    guard let value = value as? String,
          let decoded = deviceSyncDecodeBase64URL(value),
          decoded.count == 64,
          decoded.prefix(32).contains(where: { $0 != 0 }),
          decoded.suffix(32).contains(where: { $0 != 0 }),
          NativeP256CanonicalSignature.isCanonicalLowS(decoded) else {
        throw NativeDeviceSyncContractError(.invalidSignature, "ACK signature must be a nonzero canonical low-S IEEE-P1363 P-256 signature")
    }
    return value
}

private func deviceSyncDecodeBase64URL(_ value: String) -> Data? {
    let expectedLength = value.utf8.count == 22 ? 16 : value.utf8.count == 86 ? 64 : nil
    guard expectedLength != nil,
          value.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil else { return nil }
    var base64 = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    base64 += String(repeating: "=", count: (4 - base64.utf8.count % 4) % 4)
    guard let data = Data(base64Encoded: base64),
          deviceSyncEncodeBase64URL(data) == value else { return nil }
    return data
}

private func deviceSyncEncodeBase64URL(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}
