import CoreFoundation
import Foundation

public struct NativeOnboardingPreflight: Equatable, Sendable {
    public static let version = 1
    public let version: Int
    public let platform: String
    public let candidateID: String
    public let deviceKeyFingerprint: String
}

public struct NativeTrustInstallationAcknowledgement: Equatable, Sendable {
    public static let version = 1
    public static let type = "agentpass.browser-onboarding.trust-installation-ack"
    public let version: Int
    public let type: String
    public let organizationID: String
    public let deviceID: String
    public let enrollmentID: String
    public let deviceKeyEpoch: Int64
    public let controlFormatEpoch: Int
    public let controlSequence: Int64
    public let controlStatementHash: String
    public let trustFingerprint: String
    public let installedAt: String
    public let result: String
}

public enum NativeOnboardingPreflightCodec {
    public static let maxBytes = 16 * 1024

    public static func decode(_ data: Data) throws -> NativeOnboardingPreflight {
        try parse(try onboardingObject(data))
    }

    public static func parse(_ data: Data) throws -> NativeOnboardingPreflight { try decode(data) }
    public static func normalize(_ data: Data) throws -> NativeOnboardingPreflight { try decode(data) }

    public static func canonicalJSON(_ data: Data) throws -> Data {
        try NativeStrictJSON.data(try onboardingObject(data))
    }

    public static func canonicalJSON(_ value: NativeOnboardingPreflight) throws -> Data {
        try NativeStrictJSON.data([
            "version": value.version,
            "platform": value.platform,
            "candidate_id": value.candidateID,
            "device_key_fingerprint": value.deviceKeyFingerprint
        ])
    }

    private static func parse(_ object: [String: Any]) throws -> NativeOnboardingPreflight {
        try onboardingRejectUnknown(object, allowed: ["version", "platform", "candidate_id", "device_key_fingerprint"])
        guard let version = onboardingInt(object["version"]), version == 1 else { throw NativeDeviceSyncContractError(.invalidVersion) }
        guard let platform = object["platform"] as? String, platform == "macos" else { throw NativeDeviceSyncContractError(.invalidValue) }
        let candidateID = try onboardingPattern(object["candidate_id"], pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", reason: .invalidIdentifier)
        let fingerprint = try onboardingPattern(object["device_key_fingerprint"], pattern: "^SHA256:[A-Za-z0-9_-]{43}$", reason: .invalidEncoding)
        return NativeOnboardingPreflight(version: Int(version), platform: platform, candidateID: candidateID, deviceKeyFingerprint: fingerprint)
    }
}

public enum NativeTrustInstallationAcknowledgementCodec {
    public static let maxBytes = 16 * 1024

    public static func decode(_ data: Data) throws -> NativeTrustInstallationAcknowledgement {
        try parse(try onboardingObject(data))
    }

    public static func parse(_ data: Data) throws -> NativeTrustInstallationAcknowledgement { try decode(data) }
    public static func normalize(_ data: Data) throws -> NativeTrustInstallationAcknowledgement { try decode(data) }

    public static func canonicalJSON(_ data: Data) throws -> Data {
        try NativeStrictJSON.data(try onboardingObject(data))
    }

    public static func canonicalJSON(_ value: NativeTrustInstallationAcknowledgement) throws -> Data {
        try NativeStrictJSON.data([
            "version": value.version, "type": value.type, "organization_id": value.organizationID,
            "device_id": value.deviceID, "enrollment_id": value.enrollmentID, "device_key_epoch": value.deviceKeyEpoch,
            "control_format_epoch": value.controlFormatEpoch, "control_sequence": value.controlSequence,
            "control_statement_hash": value.controlStatementHash, "trust_fingerprint": value.trustFingerprint,
            "installed_at": value.installedAt, "result": value.result
        ])
    }

    private static func parse(_ object: [String: Any]) throws -> NativeTrustInstallationAcknowledgement {
        try onboardingRejectUnknown(object, allowed: [
            "version", "type", "organization_id", "device_id", "enrollment_id", "device_key_epoch",
            "control_format_epoch", "control_sequence", "control_statement_hash", "trust_fingerprint", "installed_at", "result"
        ])
        guard let version = onboardingInt(object["version"]), version == 1 else { throw NativeDeviceSyncContractError(.invalidVersion) }
        guard let type = object["type"] as? String, type == NativeTrustInstallationAcknowledgement.type else { throw NativeDeviceSyncContractError(.invalidValue) }
        let organizationID = try onboardingUUID(object["organization_id"])
        let deviceID = try onboardingUUID(object["device_id"])
        let enrollmentID = try onboardingUUID(object["enrollment_id"])
        guard let deviceKeyEpoch = onboardingInt(object["device_key_epoch"]), deviceKeyEpoch > 0 else { throw NativeDeviceSyncContractError(.invalidEpoch) }
        guard let formatEpoch = onboardingInt(object["control_format_epoch"]), formatEpoch == 2 else { throw NativeDeviceSyncContractError(.invalidFormatEpoch) }
        guard let sequence = onboardingInt(object["control_sequence"]), sequence > 0 else { throw NativeDeviceSyncContractError(.invalidSequence) }
        let statementHash = try onboardingPattern(object["control_statement_hash"], pattern: "^[0-9a-f]{64}$", reason: .invalidHash)
        let fingerprint = try onboardingPattern(object["trust_fingerprint"], pattern: "^SHA256:[A-Za-z0-9_-]{43}$", reason: .invalidEncoding)
        let installedAt = try onboardingTimestamp(object["installed_at"])
        guard let result = object["result"] as? String, ["installed", "already_installed"].contains(result) else { throw NativeDeviceSyncContractError(.invalidResult) }
        return NativeTrustInstallationAcknowledgement(version: Int(version), type: type, organizationID: organizationID, deviceID: deviceID, enrollmentID: enrollmentID, deviceKeyEpoch: deviceKeyEpoch, controlFormatEpoch: Int(formatEpoch), controlSequence: sequence, controlStatementHash: statementHash, trustFingerprint: fingerprint, installedAt: installedAt, result: result)
    }
}

private func onboardingObject(_ data: Data) throws -> [String: Any] {
    do { return try NativeStrictJSON.object(from: data, maxBytes: 16 * 1024, maxDepth: 8) }
    catch let error as NativeControlBundleV2Error {
        throw NativeDeviceSyncContractError(NativeDeviceSyncContractReason(rawValue: error.reason.rawValue) ?? .invalidJSON, error.message)
    } catch { throw NativeDeviceSyncContractError(.invalidJSON) }
}

private func onboardingRejectUnknown(_ object: [String: Any], allowed: Set<String>) throws {
    guard let key = object.keys.first(where: { !allowed.contains($0) }) else { return }
    throw NativeDeviceSyncContractError(.unknownField, "unknown field: \(key)")
}

private func onboardingInt(_ value: Any?) -> Int64? {
    guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(), number.doubleValue.isFinite, number.doubleValue.rounded() == number.doubleValue, number.doubleValue >= 0, number.doubleValue <= 9_007_199_254_740_991 else { return nil }
    return number.int64Value
}

private func onboardingPattern(_ value: Any?, pattern: String, reason: NativeDeviceSyncContractReason) throws -> String {
    guard let value = value as? String, value.range(of: pattern, options: .regularExpression) != nil else { throw NativeDeviceSyncContractError(reason) }
    return value
}

private func onboardingUUID(_ value: Any?) throws -> String {
    try onboardingPattern(value, pattern: "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$", reason: .invalidUUID).lowercased()
}

private func onboardingTimestamp(_ value: Any?) throws -> String {
    let value = try onboardingPattern(value, pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$", reason: .invalidTimestamp)
    let parser = ISO8601DateFormatter()
    parser.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    guard let date = parser.date(from: value) else { throw NativeDeviceSyncContractError(.invalidTimestamp) }
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    guard formatter.string(from: date) == value else { throw NativeDeviceSyncContractError(.invalidTimestamp) }
    return value
}
