import CryptoKit
import Foundation

/// Stable failures for the untrusted Agent signing-capability boundary.
public enum NativeAgentSigningCapabilityCodecError: String, Error, Equatable, Sendable, LocalizedError {
    case invalidJSON = "invalid_json"
    case duplicateField = "duplicate_field"
    case nonCanonicalJSON = "non_canonical_json"
    case invalidShape = "invalid_shape"
    case unknownField = "unknown_field"
    case unsupportedVersion = "unsupported_version"
    case invalidType = "invalid_type"
    case invalidIdentifier = "invalid_identifier"
    case invalidOperation = "invalid_operation"
    case invalidScope = "invalid_scope"
    case invalidKeyPurpose = "invalid_key_purpose"
    case invalidKeyIdentifier = "invalid_key_identifier"
    case invalidAlgorithm = "invalid_algorithm"
    case invalidBoolean = "invalid_boolean"
    case invalidBudget = "invalid_budget"
    case invalidTimestamp = "invalid_timestamp"
    case invalidSequence = "invalid_sequence"
    case invalidGeneration = "invalid_generation"
    case invalidDigest = "invalid_digest"
    case invalidSignatureEncoding = "invalid_signature_encoding"
    case invalidSignature = "invalid_signature"
    case statementHashMismatch = "statement_hash_mismatch"
    case authorityMismatch = "authority_mismatch"
    case keyIDMismatch = "key_id_mismatch"
    case invalidDomain = "invalid_domain"
    case invalidVerificationContext = "invalid_verification_context"
    case notYetValid = "not_yet_valid"
    case expired = "expired"
    case ttlExceeded = "ttl_exceeded"

    public var errorDescription: String? { rawValue }
}

public struct NativeAgentSigningCapabilityPatternSet: Equatable, Sendable {
    public let allow: [String]
    public let deny: [String]

    public init(allow: [String], deny: [String]) throws {
        try NativeAgentSigningCapabilityCodec.validatePatternList(allow, required: true)
        try NativeAgentSigningCapabilityCodec.validatePatternList(deny, required: false)
        guard Set(allow).count == allow.count, Set(deny).count == deny.count else {
            throw NativeAgentSigningCapabilityCodecError.invalidScope
        }
        self.allow = allow
        self.deny = deny
    }
}

public struct NativeAgentSigningCapabilityScope: Equatable, Sendable {
    public let operations: [String]
    public let repositories: [String]
    public let branches: NativeAgentSigningCapabilityPatternSet
    public let remotes: NativeAgentSigningCapabilityPatternSet
    public let tags: NativeAgentSigningCapabilityPatternSet?

    public init(
        operations: [String],
        repositories: [String],
        branches: NativeAgentSigningCapabilityPatternSet,
        remotes: NativeAgentSigningCapabilityPatternSet,
        tags: NativeAgentSigningCapabilityPatternSet? = nil
    ) throws {
        guard operations == ["git.commit.sign"],
              Set(operations).count == operations.count,
              operations.count <= NativeAgentSigningCapabilityCodec.maximumArrayItems,
              repositories.count >= 1,
              repositories.count <= NativeAgentSigningCapabilityCodec.maximumArrayItems,
              Set(repositories).count == repositories.count else {
            throw NativeAgentSigningCapabilityCodecError.invalidScope
        }
        for repository in repositories {
            guard NativeAgentSigningCapabilityCodec.isCanonicalRepositoryPath(repository) else {
                throw NativeAgentSigningCapabilityCodecError.invalidScope
            }
        }
        self.operations = operations
        self.repositories = repositories
        self.branches = branches
        self.remotes = remotes
        self.tags = tags
    }
}

/// The server-derived statement signed by the Cloud authority.
///
/// `organizationID` and `issuedAt` are intentionally part of this native DTO.
/// The F1 review finding requires both fields to remain signed; a contract
/// variant which omits either field is incompatible with this DTO.
public struct NativeAgentSigningCapabilityStatement: Equatable, Sendable {
    public let version: Int
    public let type: String
    public let capabilityID: String
    public let sessionID: String
    public let organizationID: String
    public let deviceID: String
    public let agentID: String
    public let oneUse: Bool
    public let operation: String
    public let scope: NativeAgentSigningCapabilityScope
    public let keyPurpose: String
    public let keyID: String
    public let algorithm: String
    public let maxSignatures: Int
    public let issuedAt: String
    public let notBefore: String
    public let expiresAt: String
    public let sequence: Int64
    public let controlSequence: Int64
    public let authorityGeneration: Int64
    public let issuer: String

    public init(
        version: Int = 1,
        type: String = NativeAgentSigningCapabilityCodec.documentType,
        capabilityID: String,
        sessionID: String,
        organizationID: String,
        deviceID: String,
        agentID: String,
        oneUse: Bool = true,
        operation: String = NativeAgentSigningCapabilityCodec.operation,
        scope: NativeAgentSigningCapabilityScope,
        keyPurpose: String = NativeAgentSigningCapabilityCodec.operation,
        keyID: String,
        algorithm: String = NativeAgentSigningCapabilityCodec.algorithm,
        maxSignatures: Int = 1,
        issuedAt: String,
        notBefore: String,
        expiresAt: String,
        sequence: Int64,
        controlSequence: Int64,
        authorityGeneration: Int64,
        issuer: String = NativeAgentSigningCapabilityCodec.issuer
    ) throws {
        guard version == 1 else { throw NativeAgentSigningCapabilityCodecError.unsupportedVersion }
        guard type == NativeAgentSigningCapabilityCodec.documentType else { throw NativeAgentSigningCapabilityCodecError.invalidType }
        try NativeAgentSigningCapabilityCodec.validateUUID(capabilityID)
        try NativeAgentSigningCapabilityCodec.validateUUID(sessionID)
        try NativeAgentSigningCapabilityCodec.validateUUID(organizationID)
        try NativeAgentSigningCapabilityCodec.validateUUID(deviceID)
        try NativeAgentSigningCapabilityCodec.validateUUID(agentID)
        guard oneUse else { throw NativeAgentSigningCapabilityCodecError.invalidBoolean }
        guard operation == NativeAgentSigningCapabilityCodec.operation else { throw NativeAgentSigningCapabilityCodecError.invalidOperation }
        guard keyPurpose == NativeAgentSigningCapabilityCodec.operation else { throw NativeAgentSigningCapabilityCodecError.invalidKeyPurpose }
        try NativeAgentSigningCapabilityCodec.validateKeyID(keyID)
        guard algorithm == NativeAgentSigningCapabilityCodec.algorithm else { throw NativeAgentSigningCapabilityCodecError.invalidAlgorithm }
        guard maxSignatures == 1 else { throw NativeAgentSigningCapabilityCodecError.invalidBudget }
        let issued = try NativeAgentSigningCapabilityCodec.timestamp(issuedAt)
        let notBeforeValue = try NativeAgentSigningCapabilityCodec.timestamp(notBefore)
        let expires = try NativeAgentSigningCapabilityCodec.timestamp(expiresAt)
        guard issued.milliseconds <= notBeforeValue.milliseconds,
              expires.milliseconds > notBeforeValue.milliseconds else {
            throw NativeAgentSigningCapabilityCodecError.invalidTimestamp
        }
        try NativeAgentSigningCapabilityCodec.validatePositiveSafeInteger(sequence, error: .invalidSequence)
        try NativeAgentSigningCapabilityCodec.validatePositiveSafeInteger(controlSequence, error: .invalidGeneration)
        try NativeAgentSigningCapabilityCodec.validatePositiveSafeInteger(authorityGeneration, error: .invalidGeneration)
        guard issuer == NativeAgentSigningCapabilityCodec.issuer else { throw NativeAgentSigningCapabilityCodecError.invalidType }

        self.version = version
        self.type = type
        self.capabilityID = capabilityID
        self.sessionID = sessionID
        self.organizationID = organizationID
        self.deviceID = deviceID
        self.agentID = agentID
        self.oneUse = oneUse
        self.operation = operation
        self.scope = scope
        self.keyPurpose = keyPurpose
        self.keyID = keyID
        self.algorithm = algorithm
        self.maxSignatures = maxSignatures
        self.issuedAt = issuedAt
        self.notBefore = notBefore
        self.expiresAt = expiresAt
        self.sequence = sequence
        self.controlSequence = controlSequence
        self.authorityGeneration = authorityGeneration
        self.issuer = issuer
    }
}

public struct NativeAgentSigningCapabilityEnvelope: Equatable, Sendable {
    public let version: Int
    public let type: String
    public let statement: NativeAgentSigningCapabilityStatement
    public let statementHash: String
    /// Canonical unpadded base64url Ed25519 signature bytes. The codec does
    /// not sign or verify; it only checks the public encoding and hash binding.
    public let signature: String

    public init(
        statement: NativeAgentSigningCapabilityStatement,
        statementHash: String,
        signature: String,
        version: Int = 1,
        type: String = NativeAgentSigningCapabilityCodec.documentType
    ) throws {
        guard version == 1 else { throw NativeAgentSigningCapabilityCodecError.unsupportedVersion }
        guard type == NativeAgentSigningCapabilityCodec.documentType else { throw NativeAgentSigningCapabilityCodecError.invalidType }
        try NativeAgentSigningCapabilityCodec.validateDigest(statementHash)
        try NativeAgentSigningCapabilityCodec.validateSignature(signature)
        let expectedStatementHash = try NativeAgentSigningCapabilityCodec.statementHash(statement)
        guard statementHash == expectedStatementHash else {
            throw NativeAgentSigningCapabilityCodecError.statementHashMismatch
        }
        self.version = version
        self.type = type
        self.statement = statement
        self.statementHash = statementHash
        self.signature = signature
    }

    public init(statement: NativeAgentSigningCapabilityStatement, signature: String) throws {
        try self.init(
            statement: statement,
            statementHash: NativeAgentSigningCapabilityCodec.statementHash(statement),
            signature: signature
        )
    }
}

/// The only public request shape a Device caller may submit. Authority fields
/// are deliberately absent and cannot be selected by this DTO.
public struct NativeAgentSigningCapabilityRequest: Equatable, Sendable {
    public let requestID: String

    public init(requestID: String) throws {
        try NativeAgentSigningCapabilityCodec.validateUUID(requestID)
        self.requestID = requestID
    }
}

public struct NativeAgentSigningCapabilityResponseMetadata: Equatable, Sendable {
    public let operation: String
    public let keyPurpose: String
    public let issuedAt: String
    public let expiresAt: String
    public let sequence: Int64
    public let remainingSessionSignatures: Int
    public let replayed: Bool

    public init(
        issuedAt: String,
        expiresAt: String,
        sequence: Int64,
        remainingSessionSignatures: Int,
        replayed: Bool,
        operation: String = NativeAgentSigningCapabilityCodec.operation,
        keyPurpose: String = NativeAgentSigningCapabilityCodec.operation
    ) throws {
        guard operation == NativeAgentSigningCapabilityCodec.operation else { throw NativeAgentSigningCapabilityCodecError.invalidOperation }
        guard keyPurpose == NativeAgentSigningCapabilityCodec.operation else { throw NativeAgentSigningCapabilityCodecError.invalidKeyPurpose }
        let issued = try NativeAgentSigningCapabilityCodec.timestamp(issuedAt)
        let expires = try NativeAgentSigningCapabilityCodec.timestamp(expiresAt)
        guard expires.milliseconds > issued.milliseconds else { throw NativeAgentSigningCapabilityCodecError.invalidTimestamp }
        try NativeAgentSigningCapabilityCodec.validatePositiveSafeInteger(sequence, error: .invalidSequence)
        guard (0...1).contains(remainingSessionSignatures) else { throw NativeAgentSigningCapabilityCodecError.invalidBudget }
        self.operation = operation
        self.keyPurpose = keyPurpose
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.sequence = sequence
        self.remainingSessionSignatures = remainingSessionSignatures
        self.replayed = replayed
    }
}

public struct NativeAgentSigningCapabilityResponse: Equatable, Sendable {
    public let capability: NativeAgentSigningCapabilityEnvelope
    public let metadata: NativeAgentSigningCapabilityResponseMetadata
    public let requestID: String

    public init(
        capability: NativeAgentSigningCapabilityEnvelope,
        metadata: NativeAgentSigningCapabilityResponseMetadata,
        requestID: String
    ) throws {
        try NativeAgentSigningCapabilityCodec.validateUUID(requestID)
        guard metadata.operation == capability.statement.operation,
              metadata.keyPurpose == capability.statement.keyPurpose,
              metadata.issuedAt == capability.statement.issuedAt,
              metadata.expiresAt == capability.statement.expiresAt,
              metadata.sequence == capability.statement.sequence else {
            throw NativeAgentSigningCapabilityCodecError.authorityMismatch
        }
        self.capability = capability
        self.metadata = metadata
        self.requestID = requestID
    }
}

/// Explicit runtime authority for one capability verification. All bindings
/// are required; there is no unbound or "verify with whatever the envelope
/// says" mode.
public struct NativeAgentSigningCapabilityVerificationContext: Sendable {
    public let nowMilliseconds: Int64
    public let allowedClockSkewMilliseconds: Int64
    public let maximumTTLMilliseconds: Int64
    public let organizationID: String
    public let sessionID: String
    public let deviceID: String
    public let agentID: String
    public let keyID: String
    public let sequence: Int64
    public let controlSequence: Int64
    public let authorityGeneration: Int64

    public init(
        nowMilliseconds: Int64,
        allowedClockSkewMilliseconds: Int64,
        maximumTTLMilliseconds: Int64,
        organizationID: String,
        sessionID: String,
        deviceID: String,
        agentID: String,
        keyID: String,
        sequence: Int64,
        controlSequence: Int64,
        authorityGeneration: Int64
    ) throws {
        guard nowMilliseconds > 0,
              allowedClockSkewMilliseconds >= 0,
              allowedClockSkewMilliseconds <= NativeAgentSigningCapabilityCodec.maximumSafeInteger,
              maximumTTLMilliseconds > 0,
              maximumTTLMilliseconds <= NativeAgentSigningCapabilityCodec.maximumSafeInteger else {
            throw NativeAgentSigningCapabilityCodecError.invalidVerificationContext
        }
        try NativeAgentSigningCapabilityCodec.validateUUID(organizationID)
        try NativeAgentSigningCapabilityCodec.validateUUID(sessionID)
        try NativeAgentSigningCapabilityCodec.validateUUID(deviceID)
        try NativeAgentSigningCapabilityCodec.validateUUID(agentID)
        try NativeAgentSigningCapabilityCodec.validateKeyID(keyID)
        try NativeAgentSigningCapabilityCodec.validatePositiveSafeInteger(sequence, error: .invalidVerificationContext)
        try NativeAgentSigningCapabilityCodec.validatePositiveSafeInteger(controlSequence, error: .invalidVerificationContext)
        try NativeAgentSigningCapabilityCodec.validatePositiveSafeInteger(authorityGeneration, error: .invalidVerificationContext)
        self.nowMilliseconds = nowMilliseconds
        self.allowedClockSkewMilliseconds = allowedClockSkewMilliseconds
        self.maximumTTLMilliseconds = maximumTTLMilliseconds
        self.organizationID = organizationID
        self.sessionID = sessionID
        self.deviceID = deviceID
        self.agentID = agentID
        self.keyID = keyID
        self.sequence = sequence
        self.controlSequence = controlSequence
        self.authorityGeneration = authorityGeneration
    }
}

public extension NativeAgentSigningCapabilityVerificationContext {
    /// Constructs the verifier context from the service's complete observed
    /// session binding.  The capability sequence remains an explicit input;
    /// it must come from service-owned state rather than the untrusted Cloud
    /// envelope being verified.
    init(
        nowMilliseconds: Int64,
        allowedClockSkewMilliseconds: Int64,
        maximumTTLMilliseconds: Int64,
        organizationID: String,
        sessionID: String,
        binding: NativeAgentSessionBinding,
        keyID: String,
        sequence: Int64
    ) throws {
        try self.init(
            nowMilliseconds: nowMilliseconds,
            allowedClockSkewMilliseconds: allowedClockSkewMilliseconds,
            maximumTTLMilliseconds: maximumTTLMilliseconds,
            organizationID: organizationID,
            sessionID: sessionID,
            deviceID: binding.deviceID,
            agentID: binding.agentID,
            keyID: keyID,
            sequence: sequence,
            controlSequence: binding.controlSequence,
            authorityGeneration: binding.authorityGeneration
        )
    }
}

/// Cryptographic verifier for the Cloud-signed capability envelope.
///
/// The trusted Ed25519 public key and all expected authority values are pinned
/// at construction. The codec below performs shape/hash validation only; this
/// type is the sole API that accepts a capability as authenticated authority.
public struct NativeAgentSigningCapabilityVerifier: Sendable {
    public let trustedPublicKey: Curve25519.Signing.PublicKey
    public let expectedIssuer: String
    public let expectedKeyPurpose: String
    public let expectedKeyID: String
    public let expectedDomain: String

    public init(
        trustedPublicKey: Curve25519.Signing.PublicKey,
        expectedIssuer: String,
        expectedKeyPurpose: String,
        expectedKeyID: String,
        expectedDomain: String
    ) throws {
        guard expectedIssuer == NativeAgentSigningCapabilityCodec.issuer else {
            throw NativeAgentSigningCapabilityCodecError.invalidType
        }
        guard expectedKeyPurpose == NativeAgentSigningCapabilityCodec.operation else {
            throw NativeAgentSigningCapabilityCodecError.invalidKeyPurpose
        }
        guard expectedDomain == NativeAgentSigningCapabilityCodec.signatureDomain else {
            throw NativeAgentSigningCapabilityCodecError.invalidDomain
        }
        try NativeAgentSigningCapabilityCodec.validateKeyID(expectedKeyID)
        self.trustedPublicKey = trustedPublicKey
        self.expectedIssuer = expectedIssuer
        self.expectedKeyPurpose = expectedKeyPurpose
        self.expectedKeyID = expectedKeyID
        self.expectedDomain = expectedDomain
    }

    /// Authenticates the exact domain || canonical statement bytes and then
    /// applies the explicit tenant, binding, TTL, and current-time context.
    public func verify(
        _ data: Data,
        context: NativeAgentSigningCapabilityVerificationContext
    ) throws -> NativeAgentSigningCapabilityEnvelope {
        let envelope = try NativeAgentSigningCapabilityCodec.decode(data)
        let statement = envelope.statement
        guard statement.issuer == expectedIssuer,
              statement.keyPurpose == expectedKeyPurpose,
              statement.keyID == expectedKeyID,
              statement.version == NativeAgentSigningCapabilityCodec.version,
              statement.type == NativeAgentSigningCapabilityCodec.documentType else {
            throw NativeAgentSigningCapabilityCodecError.authorityMismatch
        }
        guard statement.organizationID == context.organizationID,
              statement.sessionID == context.sessionID,
              statement.deviceID == context.deviceID,
              statement.agentID == context.agentID,
              statement.keyID == context.keyID,
              statement.sequence == context.sequence,
              statement.controlSequence == context.controlSequence,
              statement.authorityGeneration == context.authorityGeneration else {
            throw NativeAgentSigningCapabilityCodecError.authorityMismatch
        }

        let issuedAt = try NativeAgentSigningCapabilityCodec.timestamp(statement.issuedAt).milliseconds
        let notBefore = try NativeAgentSigningCapabilityCodec.timestamp(statement.notBefore).milliseconds
        let expiresAt = try NativeAgentSigningCapabilityCodec.timestamp(statement.expiresAt).milliseconds
        guard issuedAt > 0, notBefore > 0, expiresAt > 0,
              issuedAt <= notBefore, notBefore < expiresAt else {
            throw NativeAgentSigningCapabilityCodecError.invalidTimestamp
        }
        guard expiresAt - issuedAt <= context.maximumTTLMilliseconds else {
            throw NativeAgentSigningCapabilityCodecError.ttlExceeded
        }
        let lowerNow = context.nowMilliseconds >= context.allowedClockSkewMilliseconds
            ? context.nowMilliseconds - context.allowedClockSkewMilliseconds
            : 0
        let (upperNow, overflow) = context.nowMilliseconds.addingReportingOverflow(context.allowedClockSkewMilliseconds)
        guard !overflow else { throw NativeAgentSigningCapabilityCodecError.invalidVerificationContext }
        guard notBefore <= upperNow else { throw NativeAgentSigningCapabilityCodecError.notYetValid }
        // Expiry is exclusive. With zero skew, a capability is invalid at the
        // exact expires_at instant; configured skew only widens that boundary
        // deliberately.
        guard expiresAt > lowerNow else { throw NativeAgentSigningCapabilityCodecError.expired }

        guard let signature = NativeAgentSigningCapabilityCodec.signatureData(envelope.signature),
              trustedPublicKey.isValidSignature(signature, for: try NativeAgentSigningCapabilityCodec.signedStatementBytes(envelope)) else {
            throw NativeAgentSigningCapabilityCodecError.invalidSignature
        }
        return envelope
    }
}

public enum NativeAgentSigningCapabilityCodec {
    public static let version = 1
    public static let documentType = "agentpass.agent-signing-capability"
    public static let operation = "git.commit.sign"
    public static let algorithm = "ed25519"
    public static let issuer = "agentpass-cloud"
    public static let signatureDomain = "AgentPass-Agent-Signing-Capability-v1\0"
    public static let maximumDocumentBytes = 16 * 1024
    public static let maximumJSONDepth = 8
    public static let maximumArrayItems = 64
    public static let maximumPatternBytes = 2048
    public static let maximumRepositoryBytes = 4096
    public static let maximumSafeInteger: Int64 = 9_007_199_254_740_991

    private static let envelopeKeys: Set<String> = ["version", "type", "statement", "statement_hash", "signature"]
    // Includes organization_id and issued_at required by F1 authority binding.
    private static let statementKeys: Set<String> = [
        "version", "type", "capability_id", "session_id", "organization_id", "device_id", "agent_id", "one_use",
        "operation", "scope", "key_purpose", "key_id", "algorithm", "max_signatures", "issued_at", "not_before",
        "expires_at", "sequence", "control_sequence", "authority_generation", "issuer"
    ]
    private static let scopeKeys: Set<String> = ["operations", "repositories", "branches", "remotes", "tags"]
    private static let patternSetKeys: Set<String> = ["allow", "deny"]
    private static let requestKeys: Set<String> = ["request_id"]
    private static let responseKeys: Set<String> = ["capability", "metadata", "request_id"]
    private static let metadataKeys: Set<String> = ["operation", "key_purpose", "issued_at", "expires_at", "sequence", "remaining_session_signatures", "replayed"]

    public static func decode(_ data: Data) throws -> NativeAgentSigningCapabilityEnvelope {
        let object = try strictObject(data)
        try exactKeys(object, envelopeKeys, requiredCount: envelopeKeys.count)
        let statementObject = try objectValue(object["statement"])
        try exactKeys(statementObject, statementKeys, requiredCount: statementKeys.count)
        let statement = try parseStatement(statementObject)
        let statementBytes = try NativeStrictJSON.data(statementObject)
        let canonicalStatementBytes = try canonicalStatementJSON(statement)
        guard statementBytes == canonicalStatementBytes else {
            throw NativeAgentSigningCapabilityCodecError.nonCanonicalJSON
        }
        let statementHash = try stringValue(object["statement_hash"])
        try validateDigest(statementHash)
        guard statementHash == hex(SHA256.hash(data: statementBytes)) else {
            throw NativeAgentSigningCapabilityCodecError.statementHashMismatch
        }
        let signature = try stringValue(object["signature"])
        try validateSignature(signature)
        let envelope = try NativeAgentSigningCapabilityEnvelope(
            statement: statement,
            statementHash: statementHash,
            signature: signature,
            version: Int(try exactInteger(object["version"], error: .unsupportedVersion)),
            type: try stringValue(object["type"])
        )
        guard try NativeStrictJSON.data(Self.object(for: envelope)) == data else {
            throw NativeAgentSigningCapabilityCodecError.nonCanonicalJSON
        }
        return envelope
    }

    public static func validateShape(_ data: Data) throws -> NativeAgentSigningCapabilityEnvelope { try decode(data) }
    public static func parse(_ data: Data) throws -> NativeAgentSigningCapabilityEnvelope { try decode(data) }

    public static func decodeRequest(_ data: Data) throws -> NativeAgentSigningCapabilityRequest {
        let object = try strictObject(data)
        try exactKeys(object, requestKeys, requiredCount: requestKeys.count)
        let request = try NativeAgentSigningCapabilityRequest(requestID: try stringValue(object["request_id"]))
        guard try NativeStrictJSON.data(["request_id": request.requestID]) == data else {
            throw NativeAgentSigningCapabilityCodecError.nonCanonicalJSON
        }
        return request
    }

    public static func encodeRequest(_ request: NativeAgentSigningCapabilityRequest) throws -> Data {
        try NativeStrictJSON.data(["request_id": request.requestID])
    }

    public static func decodeResponse(_ data: Data) throws -> NativeAgentSigningCapabilityResponse {
        let object = try strictObject(data)
        try exactKeys(object, responseKeys, requiredCount: responseKeys.count)
        let capabilityObject = try objectValue(object["capability"])
        let capabilityData = try NativeStrictJSON.data(capabilityObject)
        let capability = try decode(capabilityData)
        let metadataObject = try objectValue(object["metadata"])
        try exactKeys(metadataObject, metadataKeys, requiredCount: metadataKeys.count)
        let metadata = try parseMetadata(metadataObject)
        let response = try NativeAgentSigningCapabilityResponse(
            capability: capability,
            metadata: metadata,
            requestID: try stringValue(object["request_id"])
        )
        guard try NativeStrictJSON.data(Self.object(for: response)) == data else {
            throw NativeAgentSigningCapabilityCodecError.nonCanonicalJSON
        }
        return response
    }

    public static func canonicalJSON(_ envelope: NativeAgentSigningCapabilityEnvelope) throws -> Data {
        try NativeStrictJSON.data(object(for: envelope))
    }

    public static func canonicalStatementJSON(_ statement: NativeAgentSigningCapabilityStatement) throws -> Data {
        try NativeStrictJSON.data(object(for: statement))
    }

    /// The exact Ed25519 preimage: UTF-8 domain, NUL included, then canonical
    /// UTF-8 JSON statement bytes. This method does not sign.
    public static func signedStatementBytes(_ statement: NativeAgentSigningCapabilityStatement) throws -> Data {
        Data(signatureDomain.utf8) + (try canonicalStatementJSON(statement))
    }

    public static func signedStatementBytes(_ envelope: NativeAgentSigningCapabilityEnvelope) throws -> Data {
        try signedStatementBytes(envelope.statement)
    }

    public static func statementHash(_ statement: NativeAgentSigningCapabilityStatement) throws -> String {
        hex(SHA256.hash(data: try canonicalStatementJSON(statement)))
    }

    private static func parseStatement(_ object: [String: Any]) throws -> NativeAgentSigningCapabilityStatement {
        try NativeAgentSigningCapabilityStatement(
            version: Int(try exactInteger(object["version"], error: .unsupportedVersion)),
            type: try stringValue(object["type"]),
            capabilityID: try stringValue(object["capability_id"]),
            sessionID: try stringValue(object["session_id"]),
            organizationID: try stringValue(object["organization_id"]),
            deviceID: try stringValue(object["device_id"]),
            agentID: try stringValue(object["agent_id"]),
            oneUse: try boolValue(object["one_use"]),
            operation: try stringValue(object["operation"]),
            scope: try parseScope(object["scope"]),
            keyPurpose: try stringValue(object["key_purpose"]),
            keyID: try stringValue(object["key_id"]),
            algorithm: try stringValue(object["algorithm"]),
            maxSignatures: Int(try exactInteger(object["max_signatures"], error: .invalidBudget)),
            issuedAt: try stringValue(object["issued_at"]),
            notBefore: try stringValue(object["not_before"]),
            expiresAt: try stringValue(object["expires_at"]),
            sequence: try exactInteger(object["sequence"], error: .invalidSequence),
            controlSequence: try exactInteger(object["control_sequence"], error: .invalidGeneration),
            authorityGeneration: try exactInteger(object["authority_generation"], error: .invalidGeneration),
            issuer: try stringValue(object["issuer"])
        )
    }

    private static func parseScope(_ value: Any?) throws -> NativeAgentSigningCapabilityScope {
        let object = try objectValue(value)
        let allowed = scopeKeys
        guard Set(object.keys).isSubset(of: allowed), Set(object.keys).contains("operations"), Set(object.keys).contains("repositories"), Set(object.keys).contains("branches"), Set(object.keys).contains("remotes") else {
            throw object.keys.contains(where: { !allowed.contains($0) }) ? NativeAgentSigningCapabilityCodecError.unknownField : .invalidScope
        }
        let tags: NativeAgentSigningCapabilityPatternSet? = object["tags"] == nil ? nil : try parsePatternSet(object["tags"])
        return try NativeAgentSigningCapabilityScope(
            operations: try stringArray(object["operations"], maximum: maximumArrayItems, required: true, operationOnly: true),
            repositories: try stringArray(object["repositories"], maximum: maximumArrayItems, required: true, repositoryOnly: true),
            branches: try parsePatternSet(object["branches"]),
            remotes: try parsePatternSet(object["remotes"]),
            tags: tags
        )
    }

    private static func parsePatternSet(_ value: Any?) throws -> NativeAgentSigningCapabilityPatternSet {
        let object = try objectValue(value)
        try exactKeys(object, patternSetKeys, requiredCount: patternSetKeys.count)
        return try NativeAgentSigningCapabilityPatternSet(
            allow: try stringArray(object["allow"], maximum: maximumArrayItems, required: true),
            deny: try stringArray(object["deny"], maximum: maximumArrayItems, required: false)
        )
    }

    private static func parseMetadata(_ object: [String: Any]) throws -> NativeAgentSigningCapabilityResponseMetadata {
        try NativeAgentSigningCapabilityResponseMetadata(
            issuedAt: try stringValue(object["issued_at"]),
            expiresAt: try stringValue(object["expires_at"]),
            sequence: try exactInteger(object["sequence"], error: .invalidSequence),
            remainingSessionSignatures: Int(try exactInteger(object["remaining_session_signatures"], error: .invalidBudget)),
            replayed: try boolValue(object["replayed"]),
            operation: try stringValue(object["operation"]),
            keyPurpose: try stringValue(object["key_purpose"])
        )
    }

    private static func object(for envelope: NativeAgentSigningCapabilityEnvelope) throws -> [String: Any] {
        [
            "version": envelope.version,
            "type": envelope.type,
            "statement": try object(for: envelope.statement),
            "statement_hash": envelope.statementHash,
            "signature": envelope.signature
        ]
    }

    private static func object(for statement: NativeAgentSigningCapabilityStatement) throws -> [String: Any] {
        [
            "version": statement.version,
            "type": statement.type,
            "capability_id": statement.capabilityID,
            "session_id": statement.sessionID,
            "organization_id": statement.organizationID,
            "device_id": statement.deviceID,
            "agent_id": statement.agentID,
            "one_use": statement.oneUse,
            "operation": statement.operation,
            "scope": try object(for: statement.scope),
            "key_purpose": statement.keyPurpose,
            "key_id": statement.keyID,
            "algorithm": statement.algorithm,
            "max_signatures": statement.maxSignatures,
            "issued_at": statement.issuedAt,
            "not_before": statement.notBefore,
            "expires_at": statement.expiresAt,
            "sequence": statement.sequence,
            "control_sequence": statement.controlSequence,
            "authority_generation": statement.authorityGeneration,
            "issuer": statement.issuer
        ]
    }

    private static func object(for scope: NativeAgentSigningCapabilityScope) throws -> [String: Any] {
        var value: [String: Any] = [
            "operations": scope.operations,
            "repositories": scope.repositories,
            "branches": object(for: scope.branches),
            "remotes": object(for: scope.remotes)
        ]
        if let tags = scope.tags { value["tags"] = object(for: tags) }
        return value
    }

    private static func object(for patternSet: NativeAgentSigningCapabilityPatternSet) -> [String: Any] {
        ["allow": patternSet.allow, "deny": patternSet.deny]
    }

    private static func object(for response: NativeAgentSigningCapabilityResponse) throws -> [String: Any] {
        [
            "capability": try object(for: response.capability),
            "metadata": [
                "operation": response.metadata.operation,
                "key_purpose": response.metadata.keyPurpose,
                "issued_at": response.metadata.issuedAt,
                "expires_at": response.metadata.expiresAt,
                "sequence": response.metadata.sequence,
                "remaining_session_signatures": response.metadata.remainingSessionSignatures,
                "replayed": response.metadata.replayed
            ],
            "request_id": response.requestID
        ]
    }

    private static func strictObject(_ data: Data) throws -> [String: Any] {
        do {
            return try NativeStrictJSON.object(from: data, maxBytes: maximumDocumentBytes, maxDepth: maximumJSONDepth)
        } catch let error as NativeControlBundleV2Error {
            if error.reason == .duplicateField { throw NativeAgentSigningCapabilityCodecError.duplicateField }
            throw NativeAgentSigningCapabilityCodecError.invalidJSON
        } catch {
            throw NativeAgentSigningCapabilityCodecError.invalidJSON
        }
    }

    private static func exactKeys(_ object: [String: Any], _ allowed: Set<String>, requiredCount: Int) throws {
        if object.keys.contains(where: { !allowed.contains($0) }) { throw NativeAgentSigningCapabilityCodecError.unknownField }
        guard object.count == requiredCount, Set(object.keys) == allowed else {
            throw NativeAgentSigningCapabilityCodecError.invalidShape
        }
    }

    private static func objectValue(_ value: Any?) throws -> [String: Any] {
        guard let object = value as? [String: Any] else { throw NativeAgentSigningCapabilityCodecError.invalidShape }
        return object
    }

    private static func stringValue(_ value: Any?) throws -> String {
        guard let value = value as? String else { throw NativeAgentSigningCapabilityCodecError.invalidShape }
        return value
    }

    private static func boolValue(_ value: Any?) throws -> Bool {
        guard let value = value as? Bool else { throw NativeAgentSigningCapabilityCodecError.invalidBoolean }
        return value
    }

    private static func exactInteger(_ value: Any?, error: NativeAgentSigningCapabilityCodecError) throws -> Int64 {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue.isFinite,
              number.doubleValue.rounded() == number.doubleValue,
              number.doubleValue >= 0,
              number.doubleValue <= Double(maximumSafeInteger),
              Double(number.int64Value) == number.doubleValue else { throw error }
        return number.int64Value
    }

    private static func stringArray(
        _ value: Any?,
        maximum: Int,
        required: Bool,
        operationOnly: Bool = false,
        repositoryOnly: Bool = false
    ) throws -> [String] {
        guard let values = value as? [Any], values.count <= maximum, required ? !values.isEmpty : true else {
            throw NativeAgentSigningCapabilityCodecError.invalidScope
        }
        var result = [String]()
        for item in values {
            guard let string = item as? String, !string.isEmpty, string.utf8.count <= (repositoryOnly ? maximumRepositoryBytes : maximumPatternBytes), isSafeString(string), !result.contains(string) else {
                throw NativeAgentSigningCapabilityCodecError.invalidScope
            }
            if operationOnly && string != operation { throw NativeAgentSigningCapabilityCodecError.invalidScope }
            if repositoryOnly && !isCanonicalRepositoryPath(string) { throw NativeAgentSigningCapabilityCodecError.invalidScope }
            result.append(string)
        }
        return result
    }

    fileprivate static func validatePatternList(_ values: [String], required: Bool) throws {
        guard values.count <= maximumArrayItems, required ? !values.isEmpty : true else { throw NativeAgentSigningCapabilityCodecError.invalidScope }
        guard values.allSatisfy({ !$0.isEmpty && $0.utf8.count <= maximumPatternBytes && isSafeString($0) }) else { throw NativeAgentSigningCapabilityCodecError.invalidScope }
    }

    fileprivate static func isCanonicalRepositoryPath(_ value: String) -> Bool {
        guard value.utf8.count <= maximumRepositoryBytes,
              value.hasPrefix("/"),
              isSafeString(value),
              value == URL(fileURLWithPath: value).standardizedFileURL.path else { return false }
        return !value.split(separator: "/", omittingEmptySubsequences: false).contains { $0 == "." || $0 == ".." }
    }

    fileprivate static func validateUUID(_ value: String) throws {
        guard value.utf8.count == 36,
              value.range(of: "^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", options: .regularExpression) != nil,
              UUID(uuidString: value) != nil else { throw NativeAgentSigningCapabilityCodecError.invalidIdentifier }
    }

    fileprivate static func validateKeyID(_ value: String) throws {
        guard value.utf8.count >= 1, value.utf8.count <= 64,
              value.range(of: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$", options: .regularExpression) != nil else {
            throw NativeAgentSigningCapabilityCodecError.invalidKeyIdentifier
        }
    }

    fileprivate static func validateDigest(_ value: String) throws {
        guard value.utf8.count == 64, value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
            throw NativeAgentSigningCapabilityCodecError.invalidDigest
        }
    }

    fileprivate static func validateSignature(_ value: String) throws {
        guard value.utf8.count == 86,
              value.range(of: "^[A-Za-z0-9_-]{86}$", options: .regularExpression) != nil,
              let decoded = signatureData(value), decoded.count == 64,
              base64URL(decoded) == value else {
            throw NativeAgentSigningCapabilityCodecError.invalidSignatureEncoding
        }
    }

    fileprivate static func signatureData(_ value: String) -> Data? {
        decodeBase64URL(value)
    }

    fileprivate static func validatePositiveSafeInteger(_ value: Int64, error: NativeAgentSigningCapabilityCodecError) throws {
        guard value >= 1, value <= maximumSafeInteger else { throw error }
    }

    fileprivate static func timestamp(_ value: String) throws -> (text: String, milliseconds: Int64) {
        guard value.utf8.count == 24,
              value.range(of: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$", options: .regularExpression) != nil else {
            throw NativeAgentSigningCapabilityCodecError.invalidTimestamp
        }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        guard let date = formatter.date(from: value), formatter.string(from: date) == value else {
            throw NativeAgentSigningCapabilityCodecError.invalidTimestamp
        }
        let raw = date.timeIntervalSince1970 * 1_000
        guard raw.isFinite, raw > 0, raw <= Double(Int64.max) else {
            throw NativeAgentSigningCapabilityCodecError.invalidTimestamp
        }
        return (value, Int64(raw.rounded()))
    }

    private static func isSafeString(_ value: String) -> Bool {
        !value.unicodeScalars.contains { $0.value <= 0x1f || $0.value == 0x7f }
    }

    fileprivate static func decodeBase64URL(_ value: String) -> Data? {
        var base64 = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        return Data(base64Encoded: base64)
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    private static func hex<T: Sequence>(_ digest: T) -> String where T.Element == UInt8 {
        digest.map { String(format: "%02x", $0) }.joined()
    }
}
