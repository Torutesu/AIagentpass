import CoreFoundation
import Foundation

/// Stable failures for the process-local Cloud Lease boundary.
///
/// The codec deliberately does not include an input key, value, or platform
/// diagnostic in an error.  Lease bytes are untrusted Cloud input and must not
/// become an XPC or audit side channel.
public enum NativeAgentLeaseCodecError: String, Error, Equatable, Sendable, LocalizedError {
    case invalidJSON = "invalid_json"
    case duplicateField = "duplicate_field"
    case nonCanonicalJSON = "non_canonical_json"
    case invalidShape = "invalid_shape"
    case unknownField = "unknown_field"
    case unsupportedVersion = "unsupported_version"
    case invalidType = "invalid_type"
    case invalidIdentifier = "invalid_identifier"
    case invalidAgentKind = "invalid_agent_kind"
    case invalidAdapterVersion = "invalid_adapter_version"
    case invalidDigest = "invalid_digest"
    case invalidBudget = "invalid_budget"
    case invalidTimestamp = "invalid_timestamp"
    case invalidGeneration = "invalid_generation"
    case bindingMismatch = "binding_mismatch"

    public var errorDescription: String? { rawValue }
}

/// The exact Cloud `agent-session-lease-v1` document after local structural
/// and binding verification.
///
/// This full document is the only verified Lease type accepted by the native
/// Grant-consumption boundary. A second reduced projection would risk dropping
/// Cloud authority or inventing a `lease_id` that the schema does not contain.
public struct NativeAgentVerifiedCloudLease: Equatable, Sendable {
    public let version: Int
    public let type: String
    public let sessionID: String
    public let grantID: String
    public let organizationID: String
    public let deviceID: String
    public let agentID: String
    public let agentKind: String
    public let adapterID: String
    public let adapterVersion: String
    public let processBindingSHA256: String
    public let ancestryBindingSHA256: String
    public let worktreeBindingSHA256: String
    public let maxSignatures: Int
    public let usedSignatures: Int
    public let notBefore: String
    public let expiresAt: String
    public let notBeforeMilliseconds: Int64
    public let expiresAtMilliseconds: Int64
    public let controlSequence: Int64
    public let authorityGeneration: Int64

    /// The six Cloud fields which have a direct representation in the native
    /// process-bound binding.  It is constructed from the verified Cloud
    /// fields, never accepted from the Cloud JSON as a second authority.
    public let binding: NativeAgentSessionBinding

    internal init(
        version: Int,
        type: String,
        sessionID: String,
        grantID: String,
        organizationID: String,
        deviceID: String,
        agentID: String,
        agentKind: String,
        adapterID: String,
        adapterVersion: String,
        processBindingSHA256: String,
        ancestryBindingSHA256: String,
        worktreeBindingSHA256: String,
        maxSignatures: Int,
        usedSignatures: Int,
        notBefore: String,
        expiresAt: String,
        notBeforeMilliseconds: Int64,
        expiresAtMilliseconds: Int64,
        controlSequence: Int64,
        authorityGeneration: Int64,
        binding: NativeAgentSessionBinding
    ) {
        self.version = version
        self.type = type
        self.sessionID = sessionID
        self.grantID = grantID
        self.organizationID = organizationID
        self.deviceID = deviceID
        self.agentID = agentID
        self.agentKind = agentKind
        self.adapterID = adapterID
        self.adapterVersion = adapterVersion
        self.processBindingSHA256 = processBindingSHA256
        self.ancestryBindingSHA256 = ancestryBindingSHA256
        self.worktreeBindingSHA256 = worktreeBindingSHA256
        self.maxSignatures = maxSignatures
        self.usedSignatures = usedSignatures
        self.notBefore = notBefore
        self.expiresAt = expiresAt
        self.notBeforeMilliseconds = notBeforeMilliseconds
        self.expiresAtMilliseconds = expiresAtMilliseconds
        self.controlSequence = controlSequence
        self.authorityGeneration = authorityGeneration
        self.binding = binding
    }
}

/// Names retained for callers that refer to the Cloud document as a Lease.
public typealias NativeAgentCloudLease = NativeAgentVerifiedCloudLease
public typealias NativeAgentLeaseDocument = NativeAgentVerifiedCloudLease

/// Strict codec for the Cloud `agent-session-lease-v1` document.
public enum NativeAgentLeaseCodec {
    public static let version = 1
    public static let documentType = "agentpass.agent-session-lease"
    public static let maximumDocumentBytes = 16 * 1024
    public static let maximumJSONDepth = 8
    public static let maximumSignatureBudget = 64
    public static let maximumSafeInteger: Int64 = 9_007_199_254_740_991

    private static let keys: Set<String> = [
        "version", "type", "session_id", "grant_id", "organization_id",
        "device_id", "agent_id", "agent_kind", "adapter_id",
        "adapter_version", "process_binding_sha256", "ancestry_binding_sha256",
        "worktree_binding_sha256", "max_signatures", "used_signatures",
        "not_before", "expires_at", "control_sequence", "authority_generation"
    ]

    /// Decodes only canonical JSON and verifies the Cloud fields against the
    /// authority captured locally for this connection.
    public static func decode(
        _ data: Data,
        expectedBinding: NativeAgentSessionBinding
    ) throws -> NativeAgentVerifiedCloudLease {
        let object = try strictObject(from: data)
        guard object.count == keys.count, Set(object.keys) == keys else {
            throw NativeAgentLeaseCodecError.invalidShape
        }
        guard try NativeStrictJSON.data(object) == data else {
            throw NativeAgentLeaseCodecError.nonCanonicalJSON
        }

        let parsed = try parse(object)
        guard parsed.agentID == expectedBinding.agentID,
              parsed.deviceID == expectedBinding.deviceID,
              (try? digestData(parsed.processBindingSHA256)) == expectedBinding.processBindingDigest,
              (try? digestData(parsed.ancestryBindingSHA256)) == expectedBinding.ancestryBindingDigest,
              (try? digestData(parsed.worktreeBindingSHA256)) == expectedBinding.worktreeBindingDigest,
              parsed.controlSequence == expectedBinding.controlSequence,
              parsed.authorityGeneration == expectedBinding.authorityGeneration else {
            throw NativeAgentLeaseCodecError.bindingMismatch
        }

        return NativeAgentVerifiedCloudLease(
            version: parsed.version,
            type: parsed.type,
            sessionID: parsed.sessionID,
            grantID: parsed.grantID,
            organizationID: parsed.organizationID,
            deviceID: parsed.deviceID,
            agentID: parsed.agentID,
            agentKind: parsed.agentKind,
            adapterID: parsed.adapterID,
            adapterVersion: parsed.adapterVersion,
            processBindingSHA256: parsed.processBindingSHA256,
            ancestryBindingSHA256: parsed.ancestryBindingSHA256,
            worktreeBindingSHA256: parsed.worktreeBindingSHA256,
            maxSignatures: parsed.maxSignatures,
            usedSignatures: parsed.usedSignatures,
            notBefore: parsed.notBefore,
            expiresAt: parsed.expiresAt,
            notBeforeMilliseconds: parsed.notBeforeMilliseconds,
            expiresAtMilliseconds: parsed.expiresAtMilliseconds,
            controlSequence: parsed.controlSequence,
            authorityGeneration: parsed.authorityGeneration,
            binding: expectedBinding
        )
    }

    public static func verify(
        _ data: Data,
        expectedBinding: NativeAgentSessionBinding
    ) throws -> NativeAgentVerifiedCloudLease {
        try decode(data, expectedBinding: expectedBinding)
    }

    public static func parse(
        _ data: Data,
        expectedBinding: NativeAgentSessionBinding
    ) throws -> NativeAgentVerifiedCloudLease {
        try decode(data, expectedBinding: expectedBinding)
    }

    /// Re-encodes a verified document using the sole canonical JSON form.
    public static func canonicalJSON(_ lease: NativeAgentVerifiedCloudLease) throws -> Data {
        try NativeStrictJSON.data(object(for: lease))
    }

    /// Validates and returns the canonical bytes of a Cloud Lease.
    public static func canonicalJSON(
        _ data: Data,
        expectedBinding: NativeAgentSessionBinding
    ) throws -> Data {
        let lease = try decode(data, expectedBinding: expectedBinding)
        return try canonicalJSON(lease)
    }

    private static func strictObject(from data: Data) throws -> [String: Any] {
        guard !data.isEmpty, data.count <= maximumDocumentBytes else {
            throw NativeAgentLeaseCodecError.invalidJSON
        }
        do {
            return try NativeStrictJSON.object(
                from: data,
                maxBytes: maximumDocumentBytes,
                maxDepth: maximumJSONDepth
            )
        } catch let error as NativeControlBundleV2Error {
            if error.reason == .duplicateField {
                throw NativeAgentLeaseCodecError.duplicateField
            }
            throw NativeAgentLeaseCodecError.invalidJSON
        } catch {
            throw NativeAgentLeaseCodecError.invalidJSON
        }
    }

    private static func parse(_ object: [String: Any]) throws -> ParsedLease {
        guard exactInteger(object["version"]) == Int64(version) else {
            if exactInteger(object["version"]) != nil {
                throw NativeAgentLeaseCodecError.unsupportedVersion
            }
            throw NativeAgentLeaseCodecError.invalidShape
        }
        guard object["type"] as? String == documentType else {
            throw NativeAgentLeaseCodecError.invalidType
        }

        let sessionID = try uuid(object["session_id"])
        let grantID = try uuid(object["grant_id"])
        let organizationID = try uuid(object["organization_id"])
        let deviceID = try uuid(object["device_id"])
        let agentID = try uuid(object["agent_id"])
        let adapterID = try uuid(object["adapter_id"])

        guard let agentKind = object["agent_kind"] as? String,
              agentKind == "claude-code" || agentKind == "cursor" else {
            throw NativeAgentLeaseCodecError.invalidAgentKind
        }
        guard let adapterVersion = object["adapter_version"] as? String,
              adapterVersion.utf8.count >= 5,
              adapterVersion.utf8.count <= 32,
              adapterVersion.range(
                of: "^(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})(?:-[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$",
                options: .regularExpression
              ) != nil else {
            throw NativeAgentLeaseCodecError.invalidAdapterVersion
        }

        let processBindingSHA256 = try digest(object["process_binding_sha256"])
        let ancestryBindingSHA256 = try digest(object["ancestry_binding_sha256"])
        let worktreeBindingSHA256 = try digest(object["worktree_binding_sha256"])

        let maxSignatures = try boundedInteger(object["max_signatures"], minimum: 1, maximum: Int64(maximumSignatureBudget), error: .invalidBudget)
        let usedSignatures = try boundedInteger(object["used_signatures"], minimum: 0, maximum: Int64(maximumSignatureBudget), error: .invalidBudget)
        guard usedSignatures <= maxSignatures else {
            throw NativeAgentLeaseCodecError.invalidBudget
        }

        let notBefore = try timestamp(object["not_before"])
        let expiresAt = try timestamp(object["expires_at"])
        guard expiresAt.milliseconds > notBefore.milliseconds else {
            throw NativeAgentLeaseCodecError.invalidTimestamp
        }

        let controlSequence = try boundedInteger(
            object["control_sequence"],
            minimum: 1,
            maximum: maximumSafeInteger,
            error: .invalidGeneration
        )
        let authorityGeneration = try boundedInteger(
            object["authority_generation"],
            minimum: 1,
            maximum: maximumSafeInteger,
            error: .invalidGeneration
        )

        return ParsedLease(
            version: version,
            type: documentType,
            sessionID: sessionID,
            grantID: grantID,
            organizationID: organizationID,
            deviceID: deviceID,
            agentID: agentID,
            agentKind: agentKind,
            adapterID: adapterID,
            adapterVersion: adapterVersion,
            processBindingSHA256: processBindingSHA256,
            ancestryBindingSHA256: ancestryBindingSHA256,
            worktreeBindingSHA256: worktreeBindingSHA256,
            maxSignatures: Int(maxSignatures),
            usedSignatures: Int(usedSignatures),
            notBefore: notBefore.text,
            expiresAt: expiresAt.text,
            notBeforeMilliseconds: notBefore.milliseconds,
            expiresAtMilliseconds: expiresAt.milliseconds,
            controlSequence: controlSequence,
            authorityGeneration: authorityGeneration
        )
    }

    private static func object(for lease: NativeAgentVerifiedCloudLease) -> [String: Any] {
        [
            "version": lease.version,
            "type": lease.type,
            "session_id": lease.sessionID,
            "grant_id": lease.grantID,
            "organization_id": lease.organizationID,
            "device_id": lease.deviceID,
            "agent_id": lease.agentID,
            "agent_kind": lease.agentKind,
            "adapter_id": lease.adapterID,
            "adapter_version": lease.adapterVersion,
            "process_binding_sha256": lease.processBindingSHA256,
            "ancestry_binding_sha256": lease.ancestryBindingSHA256,
            "worktree_binding_sha256": lease.worktreeBindingSHA256,
            "max_signatures": lease.maxSignatures,
            "used_signatures": lease.usedSignatures,
            "not_before": lease.notBefore,
            "expires_at": lease.expiresAt,
            "control_sequence": lease.controlSequence,
            "authority_generation": lease.authorityGeneration
        ]
    }

    private static func uuid(_ value: Any?) throws -> String {
        guard let value = value as? String,
              value.utf8.count == 36,
              value.range(of: "^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", options: .regularExpression) != nil,
              UUID(uuidString: value) != nil else {
            throw NativeAgentLeaseCodecError.invalidIdentifier
        }
        return value
    }

    private static func digest(_ value: Any?) throws -> String {
        guard let value = value as? String,
              value.utf8.count == NativeAgentSessionBinding.digestByteCount * 2,
              value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
            throw NativeAgentLeaseCodecError.invalidDigest
        }
        return value
    }

    private static func digestData(_ value: String) throws -> Data {
        var output = Data(capacity: NativeAgentSessionBinding.digestByteCount)
        let bytes = Array(value.utf8)
        for index in stride(from: 0, to: bytes.count, by: 2) {
            guard let high = hexNibble(bytes[index]), let low = hexNibble(bytes[index + 1]) else {
                throw NativeAgentLeaseCodecError.invalidDigest
            }
            output.append((high << 4) | low)
        }
        guard output.count == NativeAgentSessionBinding.digestByteCount else {
            throw NativeAgentLeaseCodecError.invalidDigest
        }
        return output
    }

    private static func hexNibble(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 48...57: return byte - 48
        case 97...102: return byte - 87
        default: return nil
        }
    }

    private static func exactInteger(_ value: Any?) -> Int64? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue.isFinite,
              number.doubleValue.rounded() == number.doubleValue,
              number.doubleValue >= Double(Int64.min),
              number.doubleValue <= Double(Int64.max) else {
            return nil
        }
        let integer = number.int64Value
        guard Double(integer) == number.doubleValue else { return nil }
        return integer
    }

    private static func boundedInteger(
        _ value: Any?,
        minimum: Int64,
        maximum: Int64,
        error: NativeAgentLeaseCodecError
    ) throws -> Int64 {
        guard let integer = exactInteger(value), (minimum...maximum).contains(integer) else {
            throw error
        }
        return integer
    }

    private static func timestamp(_ value: Any?) throws -> (text: String, milliseconds: Int64) {
        guard let text = value as? String,
              text.utf8.count == 24,
              text.range(of: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$", options: .regularExpression) != nil else {
            throw NativeAgentLeaseCodecError.invalidTimestamp
        }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard let date = formatter.date(from: text), formatter.string(from: date) == text else {
            throw NativeAgentLeaseCodecError.invalidTimestamp
        }
        let rawMilliseconds = date.timeIntervalSince1970 * 1_000
        guard rawMilliseconds.isFinite,
              rawMilliseconds >= Double(Int64.min),
              rawMilliseconds <= Double(Int64.max) else {
            throw NativeAgentLeaseCodecError.invalidTimestamp
        }
        // Canonical input has millisecond precision. Round to nearest to
        // remove binary floating representation noise introduced by Date.
        return (text, Int64(rawMilliseconds.rounded()))
    }

    private struct ParsedLease {
        let version: Int
        let type: String
        let sessionID: String
        let grantID: String
        let organizationID: String
        let deviceID: String
        let agentID: String
        let agentKind: String
        let adapterID: String
        let adapterVersion: String
        let processBindingSHA256: String
        let ancestryBindingSHA256: String
        let worktreeBindingSHA256: String
        let maxSignatures: Int
        let usedSignatures: Int
        let notBefore: String
        let expiresAt: String
        let notBeforeMilliseconds: Int64
        let expiresAtMilliseconds: Int64
        let controlSequence: Int64
        let authorityGeneration: Int64
    }
}
