import CoreFoundation
import CryptoKit
import Darwin
import Foundation

// This file deliberately does not use JSONDecoder for trust-boundary input.  JSONDecoder
// cannot tell the difference between a missing field and a duplicate field, while the
// cloud implementation treats that distinction as security-significant.

public enum NativeControlBundleV2Reason: String, Sendable {
    case invalidBundle = "invalid_bundle"
    case invalidJSON = "invalid_json"
    case jsonTooLarge = "json_too_large"
    case jsonTooDeep = "json_too_deep"
    case duplicateField = "duplicate_field"
    case unknownField = "unknown_field"
    case invalidFormatEpoch = "invalid_format_epoch"
    case legacyModeRequired = "legacy_mode_required"
    case legacyPermanentlyRejected = "legacy_permanently_rejected"
    case invalidIdentifier = "invalid_identifier"
    case invalidOrganizationID = "invalid_organization_id"
    case invalidDeviceID = "invalid_device_id"
    case invalidAgentID = "invalid_agent_id"
    case invalidAudience = "invalid_audience"
    case audienceMismatch = "audience_mismatch"
    case invalidScope = "invalid_scope"
    case issuedInFuture = "issued_in_future"
    case expired = "expired"
    case ttlExceeded = "ttl_exceeded"
    case invalidOfflineTTL = "invalid_offline_ttl"
    case offlineTTLExpired = "offline_ttl_expired"
    case invalidSequence = "invalid_sequence"
    case sequenceRollback = "sequence_rollback"
    case sequenceConflict = "sequence_conflict"
    case sequenceEvidenceRequired = "sequence_evidence_required"
    case invalidRevocation = "invalid_revocation"
    case duplicateRevocation = "duplicate_revocation"
    case revocationListTooLarge = "revocation_list_too_large"
    case invalidKey = "invalid_key"
    case keyIDNotTrusted = "key_id_not_trusted"
    case issuerNotTrusted = "issuer_not_trusted"
    case issuerKeyMismatch = "issuer_key_mismatch"
    case invalidSignatureEncoding = "invalid_signature_encoding"
    case invalidSignature = "invalid_signature"
    case globalRevoked = "global_revoked"
    case deviceRevoked = "device_revoked"
    case agentRevoked = "agent_revoked"
    case capabilityRevoked = "capability_revoked"
    case organizationMismatch = "organization_mismatch"
    case invalidCapability = "invalid_capability"
    case unsupportedCapabilityVersion = "unsupported_version"
    case invalidCapabilityID = "invalid_capability_id"
    case invalidNonce = "invalid_nonce"
    case capabilityNotYetValid = "capability_not_yet_valid"
    case capabilityExpired = "capability_expired"
    case capabilityTTLExceeded = "capability_ttl_exceeded"
    case capabilitySequenceRollback = "capability_sequence_rollback"
    case capabilitySequenceConflict = "capability_sequence_conflict"
    case capabilityConsumed = "capability_consumed"
    case allowed = "allowed"
}

public struct NativeControlBundleV2Error: LocalizedError, Equatable, Sendable {
    public let reason: NativeControlBundleV2Reason
    public let message: String

    public init(_ reason: NativeControlBundleV2Reason, _ message: String? = nil) {
        self.reason = reason
        self.message = message ?? reason.rawValue
    }

    public var errorDescription: String? { "\(reason.rawValue): \(message)" }
}

public struct NativeControlBundleV2Audience: Equatable, Sendable {
    public let organizationID: String
    public let deviceID: String

    public init(organizationID: String, deviceID: String) {
        self.organizationID = organizationID
        self.deviceID = deviceID
    }
}

public struct NativeScopeFilter: Equatable, Sendable {
    public let allow: [String]
    public let deny: [String]?

    public init(allow: [String], deny: [String]? = nil) {
        self.allow = allow
        self.deny = deny
    }
}

public struct NativePolicyScope: Equatable, Sendable {
    public let operations: [String]
    public let repositories: [String]
    public let branches: NativeScopeFilter
    public let remotes: NativeScopeFilter
    public let tags: NativeScopeFilter?

    public init(operations: [String], repositories: [String], branches: NativeScopeFilter, remotes: NativeScopeFilter, tags: NativeScopeFilter? = nil) {
        self.operations = operations
        self.repositories = repositories
        self.branches = branches
        self.remotes = remotes
        self.tags = tags
    }
}

public struct NativeControlBundleV2Bundle: Equatable, Sendable {
    public let formatEpoch: Int
    public let issuer: String
    public let organizationID: String
    public let deviceID: String
    public let audience: NativeControlBundleV2Audience
    public let issuedAt: String
    public let expiresAt: String
    public let sequence: Int64
    public let policyScope: NativePolicyScope
    public let globalRevoked: Bool
    public let revokedDevices: [String]
    public let revokedAgents: [String]
    public let revokedCapabilities: [String]
    public let offlineTTLMilliseconds: Int64
    public let keyID: String
    public let signature: String

    public init(formatEpoch: Int = 2, issuer: String, organizationID: String, deviceID: String, audience: NativeControlBundleV2Audience, issuedAt: String, expiresAt: String, sequence: Int64, policyScope: NativePolicyScope, globalRevoked: Bool, revokedDevices: [String], revokedAgents: [String], revokedCapabilities: [String], offlineTTLMilliseconds: Int64, keyID: String, signature: String) {
        self.formatEpoch = formatEpoch
        self.issuer = issuer
        self.organizationID = organizationID
        self.deviceID = deviceID
        self.audience = audience
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.sequence = sequence
        self.policyScope = policyScope
        self.globalRevoked = globalRevoked
        self.revokedDevices = revokedDevices
        self.revokedAgents = revokedAgents
        self.revokedCapabilities = revokedCapabilities
        self.offlineTTLMilliseconds = offlineTTLMilliseconds
        self.keyID = keyID
        self.signature = signature
    }
}

public struct NativeControlBundleV2Trust: Sendable {
    public let publicKey: Curve25519.Signing.PublicKey
    public let issuer: String?
    public let keyID: String?
    public let audience: NativeControlBundleV2Audience?

    public init(publicKey: Curve25519.Signing.PublicKey, issuer: String? = nil, keyID: String? = nil, audience: NativeControlBundleV2Audience? = nil) {
        self.publicKey = publicKey
        self.issuer = issuer
        self.keyID = keyID
        self.audience = audience
    }

    public init(publicKeyPEM: String, issuer: String? = nil, keyID: String? = nil, audience: NativeControlBundleV2Audience? = nil) throws {
        self.init(publicKey: try NativeV2Key.publicKey(fromPEM: publicKeyPEM), issuer: issuer, keyID: keyID, audience: audience)
    }
}

public final class NativeControlBundleV2SequenceState: @unchecked Sendable {
    public var highestSequence: Int64
    public var statementHash: String?

    public init(highestSequence: Int64 = 0, statementHash: String? = nil) {
        self.highestSequence = highestSequence
        self.statementHash = statementHash
    }
}

public struct NativeControlBundleV2VerificationOptions: Sendable {
    public let nowMilliseconds: Int64
    public let allowOffline: Bool
    public let audience: NativeControlBundleV2Audience?
    public let sequenceState: NativeControlBundleV2SequenceState?

    public init(nowMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1000), allowOffline: Bool = false, audience: NativeControlBundleV2Audience? = nil, sequenceState: NativeControlBundleV2SequenceState? = nil) {
        self.nowMilliseconds = nowMilliseconds
        self.allowOffline = allowOffline
        self.audience = audience
        self.sequenceState = sequenceState
    }
}

public enum NativeControlBundleV2Codec {
    public static let formatEpoch = 2
    public static let legacyFormatEpoch = 1
    public static let maxBytes = 256 * 1024
    public static let maxTTLMilliseconds: Int64 = 7 * 24 * 60 * 60 * 1000
    public static let maxOfflineTTLMilliseconds: Int64 = 7 * 24 * 60 * 60 * 1000
    public static let clockSkewMilliseconds: Int64 = 60 * 1000
    public static let maxRevocations = 256
    public static let maxDepth = 32

    public static func extractCloudResponse(_ data: Data) throws -> Data {
        let object = try NativeStrictJSON.object(from: data, maxBytes: maxBytes, maxDepth: maxDepth)
        if object["bundle"] == nil { return try NativeStrictJSON.data(object) }
        try nativeScopeUnknown(object, ["bundle", "request_id"])
        if let requestID = object["request_id"] {
            guard let requestID = requestID as? String, requestID.utf8.count <= 128 else { throw NativeControlBundleV2Error(.invalidBundle, "Cloud request ID is invalid") }
        }
        guard let bundle = object["bundle"] as? [String: Any] else { throw NativeControlBundleV2Error(.invalidBundle, "Cloud control response bundle is invalid") }
        return try NativeStrictJSON.data(bundle)
    }

    public static func parse(_ data: Data, nowMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1000), allowExpired: Bool = false, allowFuture: Bool = false) throws -> NativeControlBundleV2Bundle {
        let object = try NativeStrictJSON.object(from: data, maxBytes: maxBytes, maxDepth: maxDepth)
        return try parseObject(object, nowMilliseconds: nowMilliseconds, allowExpired: allowExpired, allowFuture: allowFuture)
    }

    public static func canonicalJSON(_ data: Data) throws -> Data {
        let object = try NativeStrictJSON.object(from: data, maxBytes: maxBytes, maxDepth: maxDepth)
        let bundle = try parseObject(object, nowMilliseconds: 0, allowExpired: true, allowFuture: true)
        return try NativeStrictJSON.data(bundleObject(bundle, includeSignature: false))
    }

    public static func statementHash(_ bundle: NativeControlBundleV2Bundle) throws -> String {
        nativeHex(Data(SHA256.hash(data: try NativeStrictJSON.data(bundleObject(bundle, includeSignature: false)))))
    }

    fileprivate static func bundleObjectForPersistence(_ bundle: NativeControlBundleV2Bundle) -> [String: Any] { bundleObject(bundle, includeSignature: true) }

    public static func verify(_ data: Data, trust: NativeControlBundleV2Trust, options: NativeControlBundleV2VerificationOptions = .init()) throws -> NativeControlBundleV2Bundle {
        let object = try NativeStrictJSON.object(from: data, maxBytes: maxBytes, maxDepth: maxDepth)
        let bundle = try parseObject(object, nowMilliseconds: options.nowMilliseconds, allowExpired: options.allowOffline, allowFuture: false)
        guard bundle.keyID == trust.keyID || trust.keyID == nil else { throw NativeControlBundleV2Error(.keyIDNotTrusted, "Control bundle key ID is not trusted") }
        guard bundle.issuer == trust.issuer || trust.issuer == nil else { throw NativeControlBundleV2Error(.issuerKeyMismatch, "Control bundle issuer is not trusted") }
        guard let signature = NativeV2Key.base64(bundle.signature), signature.count == 64 else { throw NativeControlBundleV2Error(.invalidSignatureEncoding, "Control bundle signature encoding is invalid") }
        guard trust.publicKey.isValidSignature(signature, for: try NativeStrictJSON.data(bundleObject(bundle, includeSignature: false))) else { throw NativeControlBundleV2Error(.invalidSignature, "Control bundle signature is invalid") }
        let expectedAudience = options.audience ?? trust.audience
        guard let expectedAudience else { throw NativeControlBundleV2Error(.invalidAudience, "Expected organization and device audience is required") }
        guard expectedAudience.organizationID == bundle.organizationID, expectedAudience.deviceID == bundle.deviceID else { throw NativeControlBundleV2Error(.audienceMismatch, "Control bundle audience does not match the device") }
        if options.allowOffline, bundleExpiry(bundle) <= options.nowMilliseconds, options.nowMilliseconds >= bundleExpiry(bundle) + bundle.offlineTTLMilliseconds {
            throw NativeControlBundleV2Error(.offlineTTLExpired, "Control bundle offline TTL has expired")
        }
        try enforceSequence(bundle, state: options.sequenceState)
        return bundle
    }

    public static func issue(unsignedJSON: Data, signingKey: Curve25519.Signing.PrivateKey, nowMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) throws -> Data {
        var object = try NativeStrictJSON.object(from: unsignedJSON, maxBytes: maxBytes, maxDepth: maxDepth)
        guard object["signature"] == nil else { throw NativeControlBundleV2Error(.unknownField, "Bundle input must not contain signature") }
        object["format_epoch"] = object["format_epoch"] ?? 2
        object["signature"] = ""
        let bundle = try parseObject(object, nowMilliseconds: nowMilliseconds, allowExpired: false, allowFuture: false)
        let signature = try signingKey.signature(for: NativeStrictJSON.data(bundleObject(bundle, includeSignature: false))).base64EncodedString()
        return try NativeStrictJSON.data(bundleObject(bundle, includeSignature: true, signature: signature))
    }

    public static func evaluate(_ bundle: NativeControlBundleV2Bundle, organizationID: String? = nil, deviceID: String? = nil, agentID: String? = nil) -> (allowed: Bool, reason: NativeControlBundleV2Reason) {
        if let organizationID, organizationID != bundle.organizationID { return (false, .organizationMismatch) }
        if let deviceID, deviceID != bundle.deviceID { return (false, .audienceMismatch) }
        if bundle.globalRevoked { return (false, .globalRevoked) }
        if let deviceID, bundle.revokedDevices.contains(deviceID) { return (false, .deviceRevoked) }
        if let agentID, bundle.revokedAgents.contains(agentID) { return (false, .agentRevoked) }
        return (true, .allowed)
    }

    public static func policyScopeAllows(_ scope: NativePolicyScope, operation: String, repository: String, branch: String, remote: String, tag: String? = nil) -> Bool {
        guard scope.operations.contains(where: { nativeGlobMatch(operation, $0) }), nativeGlobMatchAny(repository, scope.repositories), nativeFilterAllows(branch, scope.branches), nativeFilterAllows(remote, scope.remotes) else { return false }
        if let tags = scope.tags { guard let tag, nativeFilterAllows(tag, tags) else { return false } }
        return true
    }

    public static func intersect(_ left: NativePolicyScope, _ right: NativePolicyScope) -> NativePolicyScope {
        NativePolicyScope(operations: left.operations.filter { right.operations.contains($0) }, repositories: nativeIntersectPatterns(left.repositories, right.repositories), branches: nativeIntersectFilter(left.branches, right.branches), remotes: nativeIntersectFilter(left.remotes, right.remotes), tags: left.tags == nil && right.tags == nil ? nil : nativeIntersectFilter(left.tags ?? NativeScopeFilter(allow: ["*"], deny: []), right.tags ?? NativeScopeFilter(allow: ["*"], deny: [])))
    }

    private static func parseObject(_ object: [String: Any], nowMilliseconds: Int64, allowExpired: Bool, allowFuture: Bool) throws -> NativeControlBundleV2Bundle {
        try rejectUnknown(object, allowed: ["format_epoch", "issuer", "organization_id", "device_id", "audience", "issued_at", "expires_at", "sequence", "policy_scope", "global_revoked", "revoked_devices", "revoked_agents", "revoked_capabilities", "offline_ttl_ms", "key_id", "signature"])
        guard let epoch = nativeInt(object["format_epoch"]), epoch == 2 else { throw NativeControlBundleV2Error(.invalidFormatEpoch, "Control bundle format epoch must be 2") }
        let issuer = try identifier(object["issuer"], reason: .invalidIdentifier)
        let organizationID = try uuid(object["organization_id"], reason: .invalidOrganizationID)
        let deviceID = try uuid(object["device_id"], reason: .invalidDeviceID)
        let audienceObject = try nativeObject(object["audience"], reason: .invalidAudience)
        try rejectUnknown(audienceObject, allowed: ["organization_id", "device_id"])
        let audience = NativeControlBundleV2Audience(organizationID: try uuid(audienceObject["organization_id"], reason: .invalidOrganizationID), deviceID: try uuid(audienceObject["device_id"], reason: .invalidDeviceID))
        guard audience.organizationID == organizationID, audience.deviceID == deviceID else { throw NativeControlBundleV2Error(.audienceMismatch, "Control bundle audience does not match its subject") }
        let issuedAt = try canonicalTimestamp(object["issued_at"], reason: .invalidBundle)
        let expiresAt = try canonicalTimestamp(object["expires_at"], reason: .invalidBundle)
        let issued = try milliseconds(issuedAt), expires = try milliseconds(expiresAt)
        guard expires > issued else { throw NativeControlBundleV2Error(.invalidBundle, "Control bundle expiry must be after issuance") }
        guard expires - issued <= maxTTLMilliseconds else { throw NativeControlBundleV2Error(.ttlExceeded, "Control bundle lifetime exceeds the maximum TTL") }
        if !allowFuture, issued > nowMilliseconds + clockSkewMilliseconds { throw NativeControlBundleV2Error(.issuedInFuture, "Control bundle was issued in the future") }
        if !allowExpired, expires <= nowMilliseconds { throw NativeControlBundleV2Error(.expired, "Control bundle has expired") }
        guard let sequence = nativeInt(object["sequence"]), sequence >= 1 else { throw NativeControlBundleV2Error(.invalidSequence, "Control bundle sequence is invalid") }
        let policyScope = try nativePolicyScope(object["policy_scope"])
        guard let globalRevoked = object["global_revoked"] as? Bool else { throw NativeControlBundleV2Error(.invalidRevocation, "Global revocation must be boolean") }
        let revokedDevices = try nativeRevocations(object["revoked_devices"], reason: .invalidDeviceID)
        let revokedAgents = try nativeRevocations(object["revoked_agents"], reason: .invalidAgentID)
        let revokedCapabilities = try nativeRevocations(object["revoked_capabilities"], reason: .invalidCapabilityID)
        guard let offlineTTL = nativeInt(object["offline_ttl_ms"]), offlineTTL > 0, offlineTTL <= maxOfflineTTLMilliseconds else { throw NativeControlBundleV2Error(.invalidOfflineTTL, "Control bundle offline TTL is invalid") }
        let keyID = try identifier(object["key_id"], reason: .invalidIdentifier)
        guard let signature = object["signature"] as? String else { throw NativeControlBundleV2Error(.invalidSignatureEncoding, "Control bundle signature must be a string") }
        let bundle = NativeControlBundleV2Bundle(formatEpoch: Int(epoch), issuer: issuer, organizationID: organizationID, deviceID: deviceID, audience: audience, issuedAt: issuedAt, expiresAt: expiresAt, sequence: sequence, policyScope: policyScope, globalRevoked: globalRevoked, revokedDevices: revokedDevices, revokedAgents: revokedAgents, revokedCapabilities: revokedCapabilities, offlineTTLMilliseconds: offlineTTL, keyID: keyID, signature: signature)
        guard try NativeStrictJSON.data(bundleObject(bundle, includeSignature: false)).count <= maxBytes else { throw NativeControlBundleV2Error(.jsonTooLarge, "Control bundle exceeds the maximum JSON size") }
        return bundle
    }

    private static func enforceSequence(_ bundle: NativeControlBundleV2Bundle, state: NativeControlBundleV2SequenceState?) throws {
        guard let state else { return }
        let hash = try statementHash(bundle)
        guard bundle.sequence >= state.highestSequence else { throw NativeControlBundleV2Error(.sequenceRollback, "Control bundle sequence rolled back") }
        if bundle.sequence == state.highestSequence {
            guard let oldHash = state.statementHash else { throw NativeControlBundleV2Error(.sequenceEvidenceRequired, "Same-sequence bundle requires durable hash evidence") }
            guard oldHash == hash else { throw NativeControlBundleV2Error(.sequenceConflict, "Control bundle sequence conflicts with durable evidence") }
        }
        state.highestSequence = bundle.sequence
        state.statementHash = hash
    }

    private static func bundleExpiry(_ bundle: NativeControlBundleV2Bundle) -> Int64 { (try? milliseconds(bundle.expiresAt)) ?? Int64.max }
    private static func bundleObject(_ bundle: NativeControlBundleV2Bundle, includeSignature: Bool, signature: String? = nil) -> [String: Any] {
        var object: [String: Any] = ["format_epoch": bundle.formatEpoch, "issuer": bundle.issuer, "organization_id": bundle.organizationID, "device_id": bundle.deviceID, "audience": ["organization_id": bundle.audience.organizationID, "device_id": bundle.audience.deviceID], "issued_at": bundle.issuedAt, "expires_at": bundle.expiresAt, "sequence": bundle.sequence, "policy_scope": nativeScopeObject(bundle.policyScope), "global_revoked": bundle.globalRevoked, "revoked_devices": bundle.revokedDevices, "revoked_agents": bundle.revokedAgents, "revoked_capabilities": bundle.revokedCapabilities, "offline_ttl_ms": bundle.offlineTTLMilliseconds, "key_id": bundle.keyID]
        if includeSignature { object["signature"] = signature ?? bundle.signature }
        return object
    }
}

public typealias NativeControlBundle = NativeControlBundleV2Bundle

public func verifyControlBundleV2(_ data: Data, trust: NativeControlBundleV2Trust, options: NativeControlBundleV2VerificationOptions = .init()) throws -> NativeControlBundleV2Bundle { try NativeControlBundleV2Codec.verify(data, trust: trust, options: options) }
public func canonicalControlBundleV2(_ data: Data) throws -> Data { try NativeControlBundleV2Codec.canonicalJSON(data) }
public func controlBundleV2StatementHash(_ bundle: NativeControlBundleV2Bundle) throws -> String { try NativeControlBundleV2Codec.statementHash(bundle) }
public func policyScopeAllows(_ scope: NativePolicyScope, operation: String, repository: String, branch: String, remote: String, tag: String? = nil) -> Bool { NativeControlBundleV2Codec.policyScopeAllows(scope, operation: operation, repository: repository, branch: branch, remote: remote, tag: tag) }
public func intersectPolicyScopes(_ left: NativePolicyScope, _ right: NativePolicyScope) -> NativePolicyScope { NativeControlBundleV2Codec.intersect(left, right) }

private enum NativeV2Key {
    static let spkiPrefix = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])
    static func publicKey(fromPEM pem: String) throws -> Curve25519.Signing.PublicKey {
        let body = pem.components(separatedBy: .newlines).filter { !$0.hasPrefix("-----") }.joined()
        guard let der = Data(base64Encoded: body), der.count == 44, der.prefix(12) == spkiPrefix else { throw NativeControlBundleV2Error(.invalidKey, "Pinned control bundle key is not a valid Ed25519 public key") }
        return try Curve25519.Signing.PublicKey(rawRepresentation: der.suffix(32))
    }
    static func base64(_ value: String) -> Data? {
        guard value.range(of: "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$", options: .regularExpression) != nil, let data = Data(base64Encoded: value), data.base64EncodedString() == value else { return nil }
        return data
    }
}

private func nativeObject(_ value: Any?, reason: NativeControlBundleV2Reason) throws -> [String: Any] { guard let object = value as? [String: Any] else { throw NativeControlBundleV2Error(reason, "Expected JSON object") }; return object }
private func nativeArray(_ value: Any?, reason: NativeControlBundleV2Reason) throws -> [Any] { guard let array = value as? [Any] else { throw NativeControlBundleV2Error(reason, "Expected JSON array") }; return array }
func nativeInt(_ value: Any?) -> Int64? { guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(), number.doubleValue.rounded() == number.doubleValue, number.doubleValue >= 0, number.doubleValue <= 9_007_199_254_740_991 else { return nil }; return number.int64Value }
private func identifier(_ value: Any?, reason: NativeControlBundleV2Reason) throws -> String { guard let string = value as? String, string.utf8.count <= 128, string.range(of: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", options: .regularExpression) != nil else { throw NativeControlBundleV2Error(reason, "Identifier is invalid") }; return string }
private func uuid(_ value: Any?, reason: NativeControlBundleV2Reason) throws -> String { guard let string = value as? String, string.range(of: "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$", options: .regularExpression) != nil else { throw NativeControlBundleV2Error(reason, "UUID is invalid") }; return string }
private func canonicalTimestamp(_ value: Any?, reason: NativeControlBundleV2Reason) throws -> String { guard let string = value as? String, string.range(of: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$", options: .regularExpression) != nil, let date = nativeDate(string), nativeTimestamp(date) == string else { throw NativeControlBundleV2Error(.invalidBundle, "Timestamps must be canonical RFC 3339 UTC strings") }; return string }
private func nativeDate(_ string: String) -> Date? { let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]; return formatter.date(from: string) }
private func nativeTimestamp(_ date: Date) -> String { let formatter = DateFormatter(); formatter.locale = Locale(identifier: "en_US_POSIX"); formatter.timeZone = TimeZone(secondsFromGMT: 0); formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"; return formatter.string(from: date) }
private func milliseconds(_ string: String) throws -> Int64 { guard let date = nativeDate(string), date.timeIntervalSince1970.isFinite else { throw NativeControlBundleV2Error(.invalidBundle, "Timestamp is invalid") }; return Int64((date.timeIntervalSince1970 * 1000).rounded()) }
private func nativeRevocations(_ value: Any?, reason: NativeControlBundleV2Reason) throws -> [String] { let values = try nativeArray(value, reason: .invalidRevocation); guard values.count <= NativeControlBundleV2Codec.maxRevocations else { throw NativeControlBundleV2Error(.revocationListTooLarge, "Revocation list is too large") }; var result = [String](); for value in values { let id = try uuid(value, reason: reason); guard !result.contains(id) else { throw NativeControlBundleV2Error(.duplicateRevocation, "Revocation list contains a duplicate") }; result.append(id) }; guard result == result.sorted() else { throw NativeControlBundleV2Error(.invalidRevocation, "Revocation list is not canonical") }; return result }

private func nativePolicyScope(_ value: Any?) throws -> NativePolicyScope {
    let object = try nativeObject(value, reason: .invalidScope)
    try NativeControlBundleV2Codec.rejectUnknownForScope(object)
    let operations = try nativeStringList(object["operations"], allowEmpty: false, requireOperation: true)
    let repositories = try nativeStringList(object["repositories"], allowEmpty: false, requireRepositories: true)
    let branches = try nativeFilter(object["branches"], allowEmpty: false), remotes = try nativeFilter(object["remotes"], allowEmpty: false)
    let tags = object["tags"] == nil ? nil : try nativeFilter(object["tags"], allowEmpty: false)
    return NativePolicyScope(operations: operations, repositories: repositories, branches: branches, remotes: remotes, tags: tags)
}

private func nativeStringList(_ value: Any?, allowEmpty: Bool, requireOperation: Bool = false, requireRepositories: Bool = false) throws -> [String] { let values = try nativeArray(value, reason: .invalidScope); guard allowEmpty || !values.isEmpty, values.count <= 256 else { throw NativeControlBundleV2Error(.invalidScope, "Scope list is invalid") }; var result = [String](); for item in values { guard let string = item as? String, !string.isEmpty, string.utf8.count <= 2048, !result.contains(string) else { throw NativeControlBundleV2Error(.invalidScope, "Scope list is invalid") }; if requireOperation && string != "git.commit.sign" { throw NativeControlBundleV2Error(.invalidScope, "Only git.commit.sign is permitted") }; if requireRepositories && !nativeCanonicalRepositoryPattern(string) { throw NativeControlBundleV2Error(.invalidScope, "Repository pattern is not canonical") }; result.append(string) }; return result }
private func nativeFilter(_ value: Any?, allowEmpty: Bool) throws -> NativeScopeFilter { let object = try nativeObject(value, reason: .invalidScope); try NativeControlBundleV2Codec.rejectUnknownForFilter(object); return NativeScopeFilter(allow: try nativeStringList(object["allow"], allowEmpty: allowEmpty), deny: object["deny"] == nil ? nil : try nativeStringList(object["deny"], allowEmpty: true)) }
private func nativeCanonicalRepositoryPattern(_ value: String) -> Bool { guard value.hasPrefix("/"), value == URL(fileURLWithPath: value).standardizedFileURL.path else { return false }; return !value.split(separator: "/", omittingEmptySubsequences: false).contains(where: { $0 == "." || $0 == ".." }) }
private func nativeScopeObject(_ scope: NativePolicyScope) -> [String: Any] { var object: [String: Any] = ["operations": scope.operations, "repositories": scope.repositories, "branches": nativeFilterObject(scope.branches), "remotes": nativeFilterObject(scope.remotes)]; if let tags = scope.tags { object["tags"] = nativeFilterObject(tags) }; return object }
private func nativeFilterObject(_ filter: NativeScopeFilter) -> [String: Any] { var object: [String: Any] = ["allow": filter.allow]; if let deny = filter.deny { object["deny"] = deny }; return object }
private func nativeGlobMatch(_ value: String, _ pattern: String) -> Bool { let escaped = NSRegularExpression.escapedPattern(for: pattern).replacingOccurrences(of: "\\*", with: ".*"); return value.range(of: "^\(escaped)$", options: .regularExpression) != nil }
private func nativeGlobMatchAny(_ value: String, _ patterns: [String]) -> Bool { patterns.contains { nativeGlobMatch(value, $0) } }
private func nativeFilterAllows(_ value: String, _ filter: NativeScopeFilter) -> Bool { !(filter.deny ?? []).contains(where: { nativeGlobMatch(value, $0) }) && nativeGlobMatchAny(value, filter.allow) }
private func nativeGlobSubset(_ inner: String, _ outer: String) -> Bool { if inner == outer || outer == "*" { return true }; if !inner.contains("*") { return nativeGlobMatch(inner, outer) }; guard inner.firstIndex(of: "*") == inner.lastIndex(of: "*"), outer.firstIndex(of: "*") == outer.lastIndex(of: "*") else { return false }; let i = inner.firstIndex(of: "*")!, o = outer.firstIndex(of: "*")!; return inner[..<i].hasPrefix(outer[..<o]) && inner[inner.index(after: i)...].hasSuffix(outer[outer.index(after: o)...]) }
private func nativeNarrower(_ a: String, _ b: String) -> String? { if a == b { return a }; if nativeGlobSubset(a, b) { return a }; if nativeGlobSubset(b, a) { return b }; return nil }
private func nativeIntersectPatterns(_ left: [String], _ right: [String]) -> [String] { var output = [String](); for a in left { for b in right { if let value = nativeNarrower(a, b), !output.contains(value) { output.append(value) } } }; return output }
private func nativeIntersectFilter(_ left: NativeScopeFilter, _ right: NativeScopeFilter) -> NativeScopeFilter { var deny = [String](); for value in (left.deny ?? []) + (right.deny ?? []) where !deny.contains(value) { deny.append(value) }; return NativeScopeFilter(allow: nativeIntersectPatterns(left.allow, right.allow), deny: deny.isEmpty && left.deny == nil && right.deny == nil ? nil : deny) }
private func nativeHex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
func nativeScopeUnknown(_ object: [String: Any], _ allowed: Set<String>) throws { if object.keys.contains(where: { !allowed.contains($0) }) { throw NativeControlBundleV2Error(.unknownField, "Scope contains an unknown field") } }

private extension NativeControlBundleV2Codec {
    static func rejectUnknownForScope(_ object: [String: Any]) throws { try nativeScopeUnknown(object, ["operations", "repositories", "branches", "remotes", "tags"]) }
    static func rejectUnknownForFilter(_ object: [String: Any]) throws { try nativeScopeUnknown(object, ["allow", "deny"]) }
    static func rejectUnknown(_ object: [String: Any], allowed: Set<String>) throws { try nativeScopeUnknown(object, allowed) }
}

public enum NativeStrictJSON {
    public static func object(from data: Data, maxBytes: Int, maxDepth: Int) throws -> [String: Any] {
        guard !data.isEmpty, data.count <= maxBytes, let string = String(data: data, encoding: .utf8) else { throw NativeControlBundleV2Error(.invalidJSON, "JSON is invalid UTF-8 or the size is invalid") }
        let parser = Parser(string: string, maxDepth: maxDepth)
        try parser.read()
        guard parser.isAtEnd, let object = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) as? [String: Any] else { throw NativeControlBundleV2Error(.invalidJSON, "JSON must be an object") }
        return object
    }
    public static func data(_ object: [String: Any]) throws -> Data { guard JSONSerialization.isValidJSONObject(object) else { throw NativeControlBundleV2Error(.invalidBundle, "Value is not canonical JSON") }; return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]) }
    private final class Parser {
        let string: String
        let maxDepth: Int
        var index: String.Index
        init(string: String, maxDepth: Int) { self.string = string; self.maxDepth = maxDepth; self.index = string.startIndex }
        var isAtEnd: Bool { skip(); return index == string.endIndex }
        func read() throws { try value(depth: 0) }
        private func value(depth: Int) throws {
            skip(); guard index != string.endIndex else { throw NativeControlBundleV2Error(.invalidJSON, "Unexpected end of JSON") }
            switch string[index] {
            case "{": try object(depth: depth)
            case "[": try array(depth: depth)
            case "\"": _ = try quotedString()
            case "t": try literal("true")
            case "f": try literal("false")
            case "n": try literal("null")
            default: try number()
            }
        }
        private func object(depth: Int) throws {
            try enter(depth); advance(); var keys = Set<String>(); skip(); if consume("}") { return }
            while true { skip(); let key = try quotedString(); guard keys.insert(key).inserted else { throw NativeControlBundleV2Error(.duplicateField, "JSON contains a duplicate field") }; skip(); guard consume(":") else { throw NativeControlBundleV2Error(.invalidJSON, "Object separator is invalid") }; try value(depth: depth + 1); skip(); if consume("}") { return }; guard consume(",") else { throw NativeControlBundleV2Error(.invalidJSON, "Object separator is invalid") } }
        }
        private func array(depth: Int) throws { try enter(depth); advance(); skip(); if consume("]") { return }; while true { try value(depth: depth + 1); skip(); if consume("]") { return }; guard consume(",") else { throw NativeControlBundleV2Error(.invalidJSON, "Array separator is invalid") } } }
        private func enter(_ depth: Int) throws { guard depth < maxDepth else { throw NativeControlBundleV2Error(.jsonTooDeep, "JSON nesting exceeds the maximum depth") } }
        private func quotedString() throws -> String { let start = index; guard consume("\"") else { throw NativeControlBundleV2Error(.invalidJSON, "JSON string is invalid") }; var escaped = false; while index != string.endIndex { let character = string[index]; advance(); if character == "\\" { escaped.toggle(); continue }; if character == "\"" && !escaped { let raw = String(string[start..<index]); guard let value = try? JSONSerialization.jsonObject(with: Data(raw.utf8), options: [.fragmentsAllowed]) as? String else { throw NativeControlBundleV2Error(.invalidJSON, "JSON string is invalid") }; return value }; escaped = false }; throw NativeControlBundleV2Error(.invalidJSON, "Unterminated JSON string") }
        private func literal(_ value: String) throws { guard string[index...].hasPrefix(value) else { throw NativeControlBundleV2Error(.invalidJSON, "JSON literal is invalid") }; for _ in value { advance() } }
        private func number() throws { let start = index; if consume("-") {} ; guard consumeDigits(required: true) else { throw NativeControlBundleV2Error(.invalidJSON, "JSON number is invalid") }; if consume(".") { guard consumeDigits(required: true) else { throw NativeControlBundleV2Error(.invalidJSON, "JSON number is invalid") } }; if consume("e") || consume("E") { _ = consume("+"); _ = consume("-"); guard consumeDigits(required: true) else { throw NativeControlBundleV2Error(.invalidJSON, "JSON number is invalid") } }; guard start != index else { throw NativeControlBundleV2Error(.invalidJSON, "JSON number is invalid") } }
        private func consumeDigits(required: Bool) -> Bool { var count = 0; while index != string.endIndex && string[index].isNumber { count += 1; advance() }; return !required || count > 0 }
        private func consume(_ value: Character) -> Bool { guard index != string.endIndex, string[index] == value else { return false }; advance(); return true }
        private func skip() { while index != string.endIndex && string[index].isWhitespace { advance() } }
        private func advance() { index = string.index(after: index) }
    }
}

public struct NativeCapabilityAudience: Equatable, Sendable {
    public let agentID: String
    public let deviceID: String
    public init(agentID: String, deviceID: String) { self.agentID = agentID; self.deviceID = deviceID }
}

public struct NativeCapability: Equatable, Sendable {
    public let version: Int
    public let capabilityID: String
    public let nonce: String
    public let issuer: String
    public let keyID: String
    public let audience: NativeCapabilityAudience
    public let scope: NativePolicyScope
    public let notBefore: String
    public let expiresAt: String
    public let sequence: Int64
    public let signature: String
    public init(version: Int = 1, capabilityID: String, nonce: String, issuer: String, keyID: String, audience: NativeCapabilityAudience, scope: NativePolicyScope, notBefore: String, expiresAt: String, sequence: Int64, signature: String) {
        self.version = version; self.capabilityID = capabilityID; self.nonce = nonce; self.issuer = issuer; self.keyID = keyID; self.audience = audience; self.scope = scope; self.notBefore = notBefore; self.expiresAt = expiresAt; self.sequence = sequence; self.signature = signature
    }
}

public struct NativeCapabilityTrust: Sendable {
    public let publicKey: Curve25519.Signing.PublicKey
    public let issuer: String?
    public let keyID: String?
    public init(publicKey: Curve25519.Signing.PublicKey, issuer: String? = nil, keyID: String? = nil) { self.publicKey = publicKey; self.issuer = issuer; self.keyID = keyID }
    public init(publicKeyPEM: String, issuer: String? = nil, keyID: String? = nil) throws { self.init(publicKey: try NativeV2Key.publicKey(fromPEM: publicKeyPEM), issuer: issuer, keyID: keyID) }
}

public final class NativeCapabilitySequenceState: @unchecked Sendable {
    public var highestSequence: Int64
    public var highestCapabilityHash: String?
    public init(highestSequence: Int64 = 0, highestCapabilityHash: String? = nil) { self.highestSequence = highestSequence; self.highestCapabilityHash = highestCapabilityHash }
}

public struct NativeCapabilityVerificationOptions: Sendable {
    public let nowMilliseconds: Int64
    public let audience: NativeCapabilityAudience?
    public let sequenceState: NativeCapabilitySequenceState?
    public let maxTTLMilliseconds: Int64
    public init(nowMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1000), audience: NativeCapabilityAudience? = nil, sequenceState: NativeCapabilitySequenceState? = nil, maxTTLMilliseconds: Int64 = 15 * 60 * 1000) { self.nowMilliseconds = nowMilliseconds; self.audience = audience; self.sequenceState = sequenceState; self.maxTTLMilliseconds = maxTTLMilliseconds }
}

public final class NativeCapabilityVerifier: @unchecked Sendable {
    private let trust: NativeCapabilityTrust
    private let statePath: String?
    private var durableSequence = NativeCapabilitySequenceState()
    private var durableLoaded = false
    private var consumed = Set<String>()
    private let lock = NSLock()

    public init(trust: NativeCapabilityTrust, statePath: String? = nil) throws { self.trust = trust; self.statePath = statePath; if let statePath { try nativeCapabilityLoad(path: statePath, sequence: &durableSequence, consumed: &consumed); durableLoaded = true } }

    public func verify(_ data: Data, options: NativeCapabilityVerificationOptions = .init()) throws -> NativeCapability {
        let object = try NativeStrictJSON.object(from: data, maxBytes: NativeControlBundleV2Codec.maxBytes, maxDepth: NativeControlBundleV2Codec.maxDepth)
        let capability = try NativeCapabilityCodec.parseObject(object, nowMilliseconds: options.nowMilliseconds, maxTTLMilliseconds: options.maxTTLMilliseconds)
        guard capability.issuer == trust.issuer || trust.issuer == nil else { throw NativeControlBundleV2Error(.issuerKeyMismatch, "Capability key is not trusted for this issuer") }
        guard capability.keyID == trust.keyID || trust.keyID == nil else { throw NativeControlBundleV2Error(.keyIDNotTrusted, "Capability key ID is not trusted") }
        guard let signature = NativeV2Key.base64(capability.signature), signature.count == 64 else { throw NativeControlBundleV2Error(.invalidSignatureEncoding, "Capability signature encoding is invalid") }
        guard trust.publicKey.isValidSignature(signature, for: try NativeStrictJSON.data(NativeCapabilityCodec.object(capability, includeSignature: false))) else { throw NativeControlBundleV2Error(.invalidSignature, "Capability signature is invalid") }
        if let audience = options.audience, (audience.agentID != capability.audience.agentID || audience.deviceID != capability.audience.deviceID) { throw NativeControlBundleV2Error(.audienceMismatch, "Capability audience does not match the local agent and device") }
        if let state = options.sequenceState {
            let hash = try NativeCapabilityCodec.statementHash(capability)
            guard capability.sequence >= state.highestSequence else { throw NativeControlBundleV2Error(.capabilitySequenceRollback, "Capability sequence rolled back") }
            if capability.sequence == state.highestSequence {
                guard let oldHash = state.highestCapabilityHash else { throw NativeControlBundleV2Error(.capabilitySequenceConflict, "Capability sequence requires matching durable content evidence") }
                guard oldHash == hash else { throw NativeControlBundleV2Error(.capabilitySequenceConflict, "Capability sequence conflicts with previously verified content") }
            }
            state.highestSequence = capability.sequence
            state.highestCapabilityHash = hash
        } else if statePath != nil {
            let hash = try NativeCapabilityCodec.statementHash(capability)
            let previous = durableSequence
            guard capability.sequence >= durableSequence.highestSequence else { throw NativeControlBundleV2Error(.capabilitySequenceRollback, "Capability sequence rolled back") }
            if capability.sequence == durableSequence.highestSequence {
                guard let oldHash = durableSequence.highestCapabilityHash else { throw NativeControlBundleV2Error(.capabilitySequenceConflict, "Capability sequence requires matching durable content evidence") }
                guard oldHash == hash else { throw NativeControlBundleV2Error(.capabilitySequenceConflict, "Capability sequence conflicts with previously verified content") }
            }
            durableSequence.highestSequence = capability.sequence; durableSequence.highestCapabilityHash = hash
            do { try nativeCapabilityPersist(path: statePath!, sequence: durableSequence, consumed: consumed) } catch { durableSequence = previous; throw error }
        }
        return capability
    }

    @discardableResult
    public func verifyAndConsume(_ data: Data, options: NativeCapabilityVerificationOptions = .init(), operation: String? = nil, repository: String? = nil, branch: String? = nil, remote: String? = nil, tag: String? = nil) throws -> NativeCapability {
        let capability = try verify(data, options: options)
        if let operation, let repository, let branch, let remote, !policyScopeAllows(capability.scope, operation: operation, repository: repository, branch: branch, remote: remote, tag: tag) { throw NativeControlBundleV2Error(.invalidScope, "Capability scope denied the request") }
        lock.lock(); defer { lock.unlock() }
        guard !consumed.contains(capability.capabilityID) else { throw NativeControlBundleV2Error(.capabilityConsumed, "Cloud capability has already been consumed") }
        consumed.insert(capability.capabilityID)
        if let statePath { do { try nativeCapabilityPersist(path: statePath, sequence: durableSequence, consumed: consumed) } catch { consumed.remove(capability.capabilityID); throw error } }
        return capability
    }

    public func consume(_ capabilityID: String) throws { lock.lock(); defer { lock.unlock() }; guard !consumed.contains(capabilityID) else { throw NativeControlBundleV2Error(.capabilityConsumed, "Cloud capability has already been consumed") }; consumed.insert(capabilityID); if let statePath { do { try nativeCapabilityPersist(path: statePath, sequence: durableSequence, consumed: consumed) } catch { consumed.remove(capabilityID); throw error } } }
}

public enum NativeCapabilityCodec {
    public static let version = 1
    public static func parse(_ data: Data, nowMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1000), maxTTLMilliseconds: Int64 = 15 * 60 * 1000) throws -> NativeCapability { try parseObject(NativeStrictJSON.object(from: data, maxBytes: NativeControlBundleV2Codec.maxBytes, maxDepth: NativeControlBundleV2Codec.maxDepth), nowMilliseconds: nowMilliseconds, maxTTLMilliseconds: maxTTLMilliseconds) }
    public static func canonicalJSON(_ data: Data) throws -> Data { let value = try parseObject(NativeStrictJSON.object(from: data, maxBytes: NativeControlBundleV2Codec.maxBytes, maxDepth: NativeControlBundleV2Codec.maxDepth), nowMilliseconds: 0, maxTTLMilliseconds: Int64.max, allowExpired: true, allowFuture: true); return try NativeStrictJSON.data(object(value, includeSignature: false)) }
    public static func statementHash(_ capability: NativeCapability) throws -> String { nativeHex(Data(SHA256.hash(data: try NativeStrictJSON.data(object(capability, includeSignature: false))))) }

    fileprivate static func parseObject(_ object: [String: Any], nowMilliseconds: Int64, maxTTLMilliseconds: Int64, allowExpired: Bool = false, allowFuture: Bool = false) throws -> NativeCapability {
        try nativeScopeUnknown(object, ["version", "capability_id", "nonce", "issuer", "key_id", "audience", "scope", "not_before", "expires_at", "sequence", "signature"])
        guard nativeInt(object["version"]) == 1 else { throw NativeControlBundleV2Error(.unsupportedCapabilityVersion, "Unsupported capability version") }
        let capabilityID = try uuid(object["capability_id"], reason: .invalidCapabilityID)
        guard let nonce = object["nonce"] as? String, nonce.utf8.count >= 32, nonce.utf8.count <= 128, nonce.range(of: "^[A-Za-z0-9][A-Za-z0-9._:-]{31,127}$", options: .regularExpression) != nil else { throw NativeControlBundleV2Error(.invalidNonce, "Capability nonce is invalid") }
        let issuer = try identifier(object["issuer"], reason: .invalidIdentifier), keyID = try identifier(object["key_id"], reason: .invalidIdentifier)
        let audienceObject = try nativeObject(object["audience"], reason: .invalidAudience); try nativeScopeUnknown(audienceObject, ["agent_id", "device_id"])
        let audience = NativeCapabilityAudience(agentID: try uuid(audienceObject["agent_id"], reason: .invalidAudience), deviceID: try uuid(audienceObject["device_id"], reason: .invalidAudience))
        let scope = try nativeCapabilityScope(object["scope"])
        let notBefore = try canonicalTimestamp(object["not_before"], reason: .invalidBundle), expiresAt = try canonicalTimestamp(object["expires_at"], reason: .invalidBundle)
        let notBeforeMilliseconds = try milliseconds(notBefore), expiresMilliseconds = try milliseconds(expiresAt)
        guard expiresMilliseconds > notBeforeMilliseconds else { throw NativeControlBundleV2Error(.invalidBundle, "Capability expiry must be after not-before") }
        guard maxTTLMilliseconds > 0, expiresMilliseconds - notBeforeMilliseconds <= maxTTLMilliseconds else { throw NativeControlBundleV2Error(.capabilityTTLExceeded, "Capability lifetime exceeds the maximum TTL") }
        if !allowFuture, notBeforeMilliseconds > nowMilliseconds + 60_000 { throw NativeControlBundleV2Error(.capabilityNotYetValid, "Capability is not yet valid") }
        if !allowExpired, expiresMilliseconds <= nowMilliseconds { throw NativeControlBundleV2Error(.capabilityExpired, "Capability has expired") }
        guard let sequence = nativeInt(object["sequence"]), sequence >= 1 else { throw NativeControlBundleV2Error(.invalidSequence, "Capability sequence is invalid") }
        guard let signature = object["signature"] as? String else { throw NativeControlBundleV2Error(.invalidSignatureEncoding, "Capability signature must be a string") }
        return NativeCapability(version: 1, capabilityID: capabilityID, nonce: nonce, issuer: issuer, keyID: keyID, audience: audience, scope: scope, notBefore: notBefore, expiresAt: expiresAt, sequence: sequence, signature: signature)
    }
    fileprivate static func object(_ capability: NativeCapability, includeSignature: Bool) -> [String: Any] { var value: [String: Any] = ["version": capability.version, "capability_id": capability.capabilityID, "nonce": capability.nonce, "issuer": capability.issuer, "key_id": capability.keyID, "audience": ["agent_id": capability.audience.agentID, "device_id": capability.audience.deviceID], "scope": nativeScopeObject(capability.scope), "not_before": capability.notBefore, "expires_at": capability.expiresAt, "sequence": capability.sequence]; if includeSignature { value["signature"] = capability.signature }; return value }
}

private func nativeCapabilityScope(_ value: Any?) throws -> NativePolicyScope {
    let object = try nativeObject(value, reason: .invalidScope); try nativeScopeUnknown(object, ["operations", "repositories", "branches", "remotes", "tags"])
    return NativePolicyScope(operations: try nativeStringList(object["operations"], allowEmpty: false), repositories: try nativeStringList(object["repositories"], allowEmpty: false, requireRepositories: true), branches: try nativeFilter(object["branches"], allowEmpty: false), remotes: try nativeFilter(object["remotes"], allowEmpty: false), tags: object["tags"] == nil ? nil : try nativeFilter(object["tags"], allowEmpty: false))
}

public struct NativeControlBundleV2Status: Equatable, Sendable {
    public let minimumFormatEpoch: Int
    public let sequence: Int64
    public let operational: Bool
    public let globalRevoked: Bool
    public let expired: Bool
    public let deviceRevoked: Bool
    public let revokedAgents: Int
    public let revokedCapabilities: Int
    public init(minimumFormatEpoch: Int, sequence: Int64, operational: Bool, globalRevoked: Bool, expired: Bool, deviceRevoked: Bool, revokedAgents: Int, revokedCapabilities: Int) { self.minimumFormatEpoch = minimumFormatEpoch; self.sequence = sequence; self.operational = operational; self.globalRevoked = globalRevoked; self.expired = expired; self.deviceRevoked = deviceRevoked; self.revokedAgents = revokedAgents; self.revokedCapabilities = revokedCapabilities }
}

/// Durable native head for the v2 protocol.  The old NativeControlManager remains
/// untouched and continues to implement the legacy v1 service API.
public final class NativeControlBundleV2Manager: NativeControlValidating, @unchecked Sendable {
    private let trust: NativeControlBundleV2Trust
    private let statePath: String
    private let markerPath: String
    private var minimumEpoch = 1
    private var highestSequence: Int64 = 0
    private var statementHash: String?
    private var activeV2: NativeControlBundleV2Bundle?
    private var activeLegacy: NativeLegacyControlBundleV1?
    private var auditedUpdatePending = false
    private var operational = true
    private let lock = NSLock()

    public init(trust: NativeControlBundleV2Trust, statePath: String, nowMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1000), minimumFormatEpochPath: String? = nil) throws {
        guard statePath.hasPrefix("/"), URL(fileURLWithPath: statePath).lastPathComponent != "." else { throw NativeControlBundleV2Error(.invalidBundle, "State path must be an absolute file path") }
        self.trust = trust; self.statePath = URL(fileURLWithPath: statePath).standardizedFileURL.path; self.markerPath = minimumFormatEpochPath ?? (self.statePath + ".minimum-format-epoch")
        try loadState(nowMilliseconds: nowMilliseconds)
    }

    @discardableResult
    public func apply(bundleData: Data, nowMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1000), legacyMode: Bool = false) throws -> NativeControlBundleV2Status {
        lock.lock(); defer { lock.unlock() }; guard operational else { throw NativeControlBundleV2Error(.invalidSignature, "Native control integrity failure") }
        let object = try NativeStrictJSON.object(from: bundleData, maxBytes: NativeControlBundleV2Codec.maxBytes, maxDepth: NativeControlBundleV2Codec.maxDepth)
        if nativeInt(object["format_epoch"]) == 2 {
            let state = NativeControlBundleV2SequenceState(highestSequence: highestSequence, statementHash: statementHash)
            let verified = try NativeControlBundleV2Codec.verify(bundleData, trust: trust, options: .init(nowMilliseconds: nowMilliseconds, audience: trust.audience, sequenceState: state))
            let hash = try NativeControlBundleV2Codec.statementHash(verified)
            try nativeV2PersistMinimumEpoch(markerPath, epoch: 2)
            minimumEpoch = 2; highestSequence = verified.sequence; statementHash = hash; activeV2 = verified; activeLegacy = nil
            try persistState()
        } else {
            guard legacyMode else { throw NativeControlBundleV2Error(.legacyModeRequired, "Legacy control bundles require explicit legacy mode") }
            guard minimumEpoch < 2 else { throw NativeControlBundleV2Error(.legacyPermanentlyRejected, "Legacy control bundles are permanently disabled") }
            let legacy = try NativeLegacyControlBundleV1.parse(object, publicKey: trust.publicKey, nowMilliseconds: nowMilliseconds)
            guard legacy.sequence >= highestSequence else { throw NativeControlBundleV2Error(.sequenceRollback, "Legacy control bundle sequence rolled back") }
            if legacy.sequence == highestSequence, let statementHash, statementHash != legacy.statementHash { throw NativeControlBundleV2Error(.sequenceConflict, "Legacy control bundle sequence conflicts with durable evidence") }
            highestSequence = legacy.sequence; statementHash = legacy.statementHash; activeLegacy = legacy; activeV2 = nil
            try persistState()
        }
        return currentStatus(nowMilliseconds: nowMilliseconds)
    }

    public func validateBundle(bundleData: Data, nowMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1000), legacyMode: Bool = false) throws -> Bool {
        lock.lock(); defer { lock.unlock() }; guard operational else { throw NativeControlBundleV2Error(.invalidSignature, "Native control integrity failure") }
        let object = try NativeStrictJSON.object(from: bundleData, maxBytes: NativeControlBundleV2Codec.maxBytes, maxDepth: NativeControlBundleV2Codec.maxDepth)
        if nativeInt(object["format_epoch"]) == 2 { let state = NativeControlBundleV2SequenceState(highestSequence: highestSequence, statementHash: statementHash); let verified = try NativeControlBundleV2Codec.verify(bundleData, trust: trust, options: .init(nowMilliseconds: nowMilliseconds, audience: trust.audience, sequenceState: state)); return verified.sequence > highestSequence }
        guard legacyMode else { throw NativeControlBundleV2Error(.legacyModeRequired, "Legacy control bundles require explicit legacy mode") }
        guard minimumEpoch < 2 else { throw NativeControlBundleV2Error(.legacyPermanentlyRejected, "Legacy control bundles are permanently disabled") }
        let legacy = try NativeLegacyControlBundleV1.parse(object, publicKey: trust.publicKey, nowMilliseconds: nowMilliseconds); guard legacy.sequence >= highestSequence else { throw NativeControlBundleV2Error(.sequenceRollback, "Legacy control bundle sequence rolled back") }; if legacy.sequence == highestSequence, let statementHash, statementHash != legacy.statementHash { throw NativeControlBundleV2Error(.sequenceConflict, "Legacy control bundle sequence conflicts with durable evidence") }; return legacy.sequence > highestSequence
    }

    public func validateControl(agentID: String, nowMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) throws {
        lock.lock(); defer { lock.unlock() }; guard operational else { throw AgentPassNativeError.unauthorizedClient("Native remote control integrity failure") }
        if let bundle = activeV2 {
            let expiry = try milliseconds(bundle.expiresAt); guard nowMilliseconds < expiry || nowMilliseconds < expiry + bundle.offlineTTLMilliseconds else { throw AgentPassNativeError.unauthorizedClient("offline_ttl_expired") }; guard !bundle.globalRevoked else { throw AgentPassNativeError.unauthorizedClient("global_revoked") }; guard !bundle.revokedDevices.contains(bundle.deviceID) else { throw AgentPassNativeError.unauthorizedClient("device_revoked") }; guard !bundle.revokedAgents.contains(agentID) else { throw AgentPassNativeError.unauthorizedClient("agent_revoked") }
        } else if let legacy = activeLegacy { guard nowMilliseconds < legacy.expiresAtMilliseconds else { throw AgentPassNativeError.unauthorizedClient("expired") }; guard !legacy.globalRevoked else { throw AgentPassNativeError.unauthorizedClient("global_revoked") }; guard !legacy.revokedAgents.contains(agentID) else { throw AgentPassNativeError.unauthorizedClient("agent_revoked") }
        } else { throw AgentPassNativeError.unauthorizedClient("Control bundle state is missing") }
    }

    public func validateCapability(capabilityID: String) throws {
        lock.lock(); defer { lock.unlock() }
        guard operational, let bundle = activeV2 else { throw AgentPassNativeError.unauthorizedClient("Control bundle state is missing") }
        guard !bundle.revokedCapabilities.contains(capabilityID) else { throw AgentPassNativeError.unauthorizedClient("capability_revoked") }
    }

    public func currentPolicyScope() throws -> NativePolicyScope {
        lock.lock(); defer { lock.unlock() }; guard operational, let activeV2 else { throw NativeControlBundleV2Error(.invalidBundle, "Active v2 control bundle is missing") }; return activeV2.policyScope
    }

    public func beginAuditedUpdate() throws {
        lock.lock(); defer { lock.unlock() }
        guard operational, !auditedUpdatePending else { throw NativeControlBundleV2Error(.invalidBundle, "A control update is already pending audit") }
        auditedUpdatePending = true
        do { try persistState() }
        catch { auditedUpdatePending = false; throw error }
    }

    public func completeAuditedUpdate() throws {
        lock.lock(); defer { lock.unlock() }
        guard operational, auditedUpdatePending else { throw NativeControlBundleV2Error(.invalidBundle, "No control update is pending audit") }
        auditedUpdatePending = false
        try persistState()
    }

    public func status(nowMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) -> NativeControlBundleV2Status { lock.lock(); defer { lock.unlock() }; return currentStatus(nowMilliseconds: nowMilliseconds) }
    public func invalidate() { lock.lock(); operational = false; lock.unlock() }

    private func currentStatus(nowMilliseconds: Int64) -> NativeControlBundleV2Status { let expiry = activeV2.flatMap { try? milliseconds($0.expiresAt) } ?? activeLegacy?.expiresAtMilliseconds ?? 0; let revoked = activeV2?.revokedDevices.contains(activeV2?.deviceID ?? "") ?? false; return NativeControlBundleV2Status(minimumFormatEpoch: minimumEpoch, sequence: highestSequence, operational: operational, globalRevoked: activeV2?.globalRevoked ?? activeLegacy?.globalRevoked ?? false, expired: nowMilliseconds >= expiry, deviceRevoked: revoked, revokedAgents: activeV2?.revokedAgents.count ?? activeLegacy?.revokedAgents.count ?? 0, revokedCapabilities: activeV2?.revokedCapabilities.count ?? 0) }

    private func loadState(nowMilliseconds: Int64) throws {
        minimumEpoch = try nativeV2LoadEpoch(markerPath)
        guard FileManager.default.fileExists(atPath: statePath) else { return }
        let object = try NativeStrictJSON.object(from: nativeV2ReadFile(statePath, maxBytes: NativeControlBundleV2Codec.maxBytes), maxBytes: NativeControlBundleV2Codec.maxBytes, maxDepth: NativeControlBundleV2Codec.maxDepth)
        try nativeScopeUnknown(object, ["minimum_format_epoch", "highest_sequence", "statement_hash", "active_bundle", "audited_update_pending"])
        guard let epoch = nativeInt(object["minimum_format_epoch"]), epoch == 1 || epoch == 2, let sequence = nativeInt(object["highest_sequence"]), sequence >= 0 else { throw NativeControlBundleV2Error(.invalidBundle, "Control bundle state is invalid") }
        let pending = object["audited_update_pending"] as? Bool ?? false
        guard object["audited_update_pending"] == nil || object["audited_update_pending"] is Bool else { throw NativeControlBundleV2Error(.invalidBundle, "Control audit state is invalid") }
        minimumEpoch = max(minimumEpoch, Int(epoch)); highestSequence = sequence; statementHash = object["statement_hash"] as? String; auditedUpdatePending = pending; operational = !pending
        if let active = object["active_bundle"] as? [String: Any] {
            if nativeInt(active["format_epoch"]) == 2 { let data = try NativeStrictJSON.data(active); let bundle = try NativeControlBundleV2Codec.parse(data, nowMilliseconds: nowMilliseconds, allowExpired: true, allowFuture: true); guard bundle.sequence == highestSequence, try NativeControlBundleV2Codec.statementHash(bundle) == statementHash else { throw NativeControlBundleV2Error(.invalidBundle, "Control bundle state head evidence is invalid") }; activeV2 = bundle }
            else if minimumEpoch < 2 { activeLegacy = try NativeLegacyControlBundleV1.parse(active, publicKey: trust.publicKey, nowMilliseconds: nowMilliseconds, allowExpired: true) }
        }
    }
    private func persistState() throws { var object: [String: Any] = ["minimum_format_epoch": minimumEpoch, "highest_sequence": highestSequence, "statement_hash": statementHash ?? NSNull(), "active_bundle": NSNull(), "audited_update_pending": auditedUpdatePending]; if let bundle = activeV2 { object["active_bundle"] = try JSONSerialization.jsonObject(with: NativeStrictJSON.data(NativeControlBundleV2Codec.bundleObjectForPersistence(bundle)), options: []) }; if let legacy = activeLegacy { object["active_bundle"] = try JSONSerialization.jsonObject(with: legacy.data, options: []) }; try nativeV2AtomicWrite(statePath, data: try NativeStrictJSON.data(object) + Data("\n".utf8)) }
}

private struct NativeLegacyControlBundleV1 {
    let sequence: Int64; let expiresAtMilliseconds: Int64; let globalRevoked: Bool; let revokedAgents: [String]; let data: Data; let statementHash: String
    static func parse(_ object: [String: Any], publicKey: Curve25519.Signing.PublicKey, nowMilliseconds: Int64, allowExpired: Bool = false) throws -> NativeLegacyControlBundleV1 {
        try nativeScopeUnknown(object, ["version", "sequence", "issued_at", "expires_at", "global_revoked", "revoked_agents", "key_fingerprint", "signature"]); guard nativeInt(object["version"]) == 1, let sequence = nativeInt(object["sequence"]), sequence >= 1 else { throw NativeControlBundleV2Error(.invalidSequence, "Legacy control bundle sequence is invalid") }; let issued = try canonicalTimestamp(object["issued_at"], reason: .invalidBundle), expires = try canonicalTimestamp(object["expires_at"], reason: .invalidBundle); let issuedMilliseconds = try milliseconds(issued), expiresMilliseconds = try milliseconds(expires); guard expires > issued, expiresMilliseconds - issuedMilliseconds <= NativeControlBundleV2Codec.maxTTLMilliseconds, issuedMilliseconds <= nowMilliseconds + NativeControlBundleV2Codec.clockSkewMilliseconds, allowExpired || expiresMilliseconds > nowMilliseconds else { throw NativeControlBundleV2Error(.expired, "Legacy control bundle is expired") }; guard let globalRevoked = object["global_revoked"] as? Bool else { throw NativeControlBundleV2Error(.invalidRevocation, "Legacy revocation state is invalid") }; let agents = try nativeRevocations(object["revoked_agents"], reason: .invalidAgentID); guard let fingerprint = object["key_fingerprint"] as? String, fingerprint == nativeLegacyFingerprint(publicKey), let signatureString = object["signature"] as? String, let signature = NativeV2Key.base64(signatureString), signature.count == 64 else { throw NativeControlBundleV2Error(.invalidSignatureEncoding, "Legacy control key fingerprint or signature is invalid") }; let statement: [String: Any] = ["version": 1, "sequence": sequence, "issued_at": issued, "expires_at": expires, "global_revoked": globalRevoked, "revoked_agents": agents]; let statementData = try NativeStrictJSON.data(statement); guard publicKey.isValidSignature(signature, for: statementData) else { throw NativeControlBundleV2Error(.invalidSignature, "Legacy control bundle signature is invalid") }; let record = try NativeStrictJSON.data(["version": 1, "sequence": sequence, "issued_at": issued, "expires_at": expires, "global_revoked": globalRevoked, "revoked_agents": agents, "key_fingerprint": fingerprint, "signature": signatureString]); return NativeLegacyControlBundleV1(sequence: sequence, expiresAtMilliseconds: expiresMilliseconds, globalRevoked: globalRevoked, revokedAgents: agents, data: record, statementHash: nativeHex(Data(SHA256.hash(data: statementData)))) }
}

private func nativeLegacyFingerprint(_ key: Curve25519.Signing.PublicKey) -> String { let der = NativeV2Key.spkiPrefix + key.rawRepresentation; return "SHA256:" + Data(SHA256.hash(data: der)).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }

private func nativeV2LoadEpoch(_ path: String) throws -> Int {
    guard FileManager.default.fileExists(atPath: path) else { return 1 }
    let object = try NativeStrictJSON.object(from: nativeV2ReadFile(path, maxBytes: 1024), maxBytes: 1024, maxDepth: 8)
    try nativeScopeUnknown(object, ["minimum_format_epoch"])
    guard let epoch = nativeInt(object["minimum_format_epoch"]), epoch == 1 || epoch == 2 else { throw NativeControlBundleV2Error(.invalidBundle, "Minimum format epoch state is invalid") }
    return Int(epoch)
}

private func nativeV2PersistMinimumEpoch(_ path: String, epoch: Int) throws {
    guard epoch == 2 else { throw NativeControlBundleV2Error(.invalidFormatEpoch, "Only format epoch 2 may be persisted") }
    let existing = try nativeV2LoadEpoch(path); guard existing <= epoch else { throw NativeControlBundleV2Error(.legacyPermanentlyRejected, "Minimum format epoch cannot move backwards") }
    if existing == epoch { return }
    try nativeV2AtomicWrite(path, data: try NativeStrictJSON.data(["minimum_format_epoch": epoch]) + Data("\n".utf8))
}

func nativeV2AtomicWrite(_ path: String, data: Data) throws {
    let url = URL(fileURLWithPath: path).standardizedFileURL
    let parent = url.deletingLastPathComponent()
    try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    var info = stat()
    guard lstat(parent.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR, info.st_uid == getuid(), (info.st_mode & 0o022) == 0 else { throw NativeControlBundleV2Error(.invalidBundle, "State parent ownership or mode is unsafe") }
    if lstat(url.path, &info) == 0 {
        guard (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == getuid(), info.st_nlink == 1, (info.st_mode & 0o077) == 0 else { throw NativeControlBundleV2Error(.invalidBundle, "Existing state file is unsafe") }
    } else if errno != ENOENT {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    let temporary = parent.appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp")
    let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
    guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    var descriptorOpen = true
    defer {
        if descriptorOpen { close(descriptor) }
        try? FileManager.default.removeItem(at: temporary)
    }
    try data.withUnsafeBytes { rawBuffer in
        guard var base = rawBuffer.baseAddress else { return }
        var remaining = rawBuffer.count
        while remaining > 0 {
            let written = Darwin.write(descriptor, base, remaining)
            if written < 0 {
                if errno == EINTR { continue }
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            guard written > 0 else { throw POSIXError(.EIO) }
            remaining -= written
            base = base.advanced(by: written)
        }
    }
    guard fsync(descriptor) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    guard close(descriptor) == 0 else { descriptorOpen = false; throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    descriptorOpen = false
    guard rename(temporary.path, url.path) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    let parentDescriptor = open(parent.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    guard parentDescriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    defer { close(parentDescriptor) }
    guard fsync(parentDescriptor) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
}

func nativeV2ReadFile(_ path: String, maxBytes: Int) throws -> Data {
    guard path.hasPrefix("/"), maxBytes > 0 else { throw NativeControlBundleV2Error(.invalidBundle, "State read parameters are invalid") }
    let url = URL(fileURLWithPath: path).standardizedFileURL
    var parentInfo = stat()
    guard lstat(url.deletingLastPathComponent().path, &parentInfo) == 0, (parentInfo.st_mode & S_IFMT) == S_IFDIR, (parentInfo.st_mode & S_IFMT) != S_IFLNK else { throw NativeControlBundleV2Error(.invalidBundle, "State parent is unsafe") }
    let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw NativeControlBundleV2Error(.invalidBundle, "State file cannot be opened safely") }
    defer { close(descriptor) }
    var info = stat()
    guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_nlink == 1, info.st_uid == getuid(), (info.st_mode & 0o077) == 0, info.st_size >= 0, info.st_size <= maxBytes else { throw NativeControlBundleV2Error(.invalidBundle, "State file ownership, mode, links, or size are unsafe") }
    return try FileHandle(fileDescriptor: descriptor, closeOnDealloc: false).readToEnd() ?? Data()
}

public struct NativeCapabilityStateSnapshot: Equatable, Sendable {
    public let highestSequence: Int64
    public let highestCapabilityHash: String?
    public let consumedCapabilityIDs: [String]
    public init(highestSequence: Int64, highestCapabilityHash: String?, consumedCapabilityIDs: [String]) { self.highestSequence = highestSequence; self.highestCapabilityHash = highestCapabilityHash; self.consumedCapabilityIDs = consumedCapabilityIDs }
}

public final class NativeCapabilityStateStore: @unchecked Sendable {
    public let path: String
    public init(path: String) throws { guard path.hasPrefix("/") else { throw NativeControlBundleV2Error(.invalidBundle, "Capability state path must be absolute") }; self.path = URL(fileURLWithPath: path).standardizedFileURL.path }
    public func load() throws -> NativeCapabilityStateSnapshot { var sequence = NativeCapabilitySequenceState(); var consumed = Set<String>(); try nativeCapabilityLoad(path: path, sequence: &sequence, consumed: &consumed); return NativeCapabilityStateSnapshot(highestSequence: sequence.highestSequence, highestCapabilityHash: sequence.highestCapabilityHash, consumedCapabilityIDs: consumed.sorted()) }
}

private func nativeCapabilityLoad(path: String, sequence: inout NativeCapabilitySequenceState, consumed: inout Set<String>) throws {
    guard FileManager.default.fileExists(atPath: path) else { return }
    let object = try NativeStrictJSON.object(from: nativeV2ReadFile(path, maxBytes: 256 * 1024), maxBytes: 256 * 1024, maxDepth: 8)
    try nativeScopeUnknown(object, ["highest_sequence", "highest_capability_hash", "consumed_capability_ids"])
    guard let highest = nativeInt(object["highest_sequence"]), highest >= 0 else { throw NativeControlBundleV2Error(.invalidBundle, "Capability state sequence is invalid") }
    if let hash = object["highest_capability_hash"] as? String { guard hash.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else { throw NativeControlBundleV2Error(.invalidBundle, "Capability state hash is invalid") }; sequence.highestCapabilityHash = hash } else if !(object["highest_capability_hash"] is NSNull) { throw NativeControlBundleV2Error(.invalidBundle, "Capability state hash is invalid") }
    guard let ids = object["consumed_capability_ids"] as? [String], ids.count <= 10_000, Set(ids).count == ids.count else { throw NativeControlBundleV2Error(.invalidBundle, "Capability replay state is invalid") }
    for id in ids { guard id.range(of: "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$", options: .regularExpression) != nil else { throw NativeControlBundleV2Error(.invalidBundle, "Capability replay ID is invalid") } }
    sequence.highestSequence = highest; consumed = Set(ids)
}

private func nativeCapabilityPersist(path: String, sequence: NativeCapabilitySequenceState, consumed: Set<String>) throws {
    guard sequence.highestSequence >= 0, consumed.count <= 10_000 else { throw NativeControlBundleV2Error(.invalidBundle, "Capability state is too large") }
    let object: [String: Any] = ["highest_sequence": sequence.highestSequence, "highest_capability_hash": sequence.highestCapabilityHash ?? NSNull(), "consumed_capability_ids": consumed.sorted()]
    try nativeV2AtomicWrite(path, data: try NativeStrictJSON.data(object) + Data("\n".utf8))
}
