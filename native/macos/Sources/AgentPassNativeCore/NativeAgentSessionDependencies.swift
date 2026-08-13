import CryptoKit
import Foundation

/// Failures raised while constructing the internal M2 Agent authority boundary.
/// Cases deliberately carry no caller-controlled or OS diagnostic values.
public enum NativeAgentSessionBoundaryError: String, Error, Equatable, Sendable {
    case invalidIdentity = "invalid_identity"
    case invalidDigest = "invalid_digest"
    case invalidGeneration = "invalid_generation"
    case invalidExpiry = "invalid_expiry"
    case invalidBudget = "invalid_budget"
    case invalidBootstrapProof = "invalid_bootstrap_proof"
    case invalidAuditEvidence = "invalid_audit_evidence"
}

/// OS- and policy-derived authority that is fixed before a Cloud Grant is
/// consumed. None of these values may be populated from an Agent DTO.
public struct NativeAgentSessionBinding: Equatable, Sendable {
    public static let digestByteCount = 32

    public let agentID: String
    public let deviceID: String
    public let processBindingDigest: Data
    public let ancestryBindingDigest: Data
    public let worktreeBindingDigest: Data
    public let controlSequence: Int64
    public let authorityGeneration: Int64
    public let keyGeneration: Int64

    public init(
        agentID: String,
        deviceID: String,
        processBindingDigest: Data,
        ancestryBindingDigest: Data,
        worktreeBindingDigest: Data,
        controlSequence: Int64,
        authorityGeneration: Int64,
        keyGeneration: Int64
    ) throws {
        guard Self.uuid(agentID), Self.uuid(deviceID) else {
            throw NativeAgentSessionBoundaryError.invalidIdentity
        }
        guard Self.digest(processBindingDigest), Self.digest(ancestryBindingDigest),
              Self.digest(worktreeBindingDigest) else {
            throw NativeAgentSessionBoundaryError.invalidDigest
        }
        guard controlSequence >= 1, authorityGeneration >= 1, keyGeneration >= 1 else {
            throw NativeAgentSessionBoundaryError.invalidGeneration
        }
        self.agentID = agentID.lowercased()
        self.deviceID = deviceID.lowercased()
        self.processBindingDigest = processBindingDigest
        self.ancestryBindingDigest = ancestryBindingDigest
        self.worktreeBindingDigest = worktreeBindingDigest
        self.controlSequence = controlSequence
        self.authorityGeneration = authorityGeneration
        self.keyGeneration = keyGeneration
    }

    private static func uuid(_ value: String) -> Bool {
        value.utf8.count == 36 && UUID(uuidString: value) != nil
    }

    private static func digest(_ value: Data) -> Bool {
        value.count == digestByteCount
    }
}

/// Internal input to the Device API Grant-consumption adapter. The opaque
/// proof is transient and this type intentionally has no Codable or diagnostic
/// conformance.
public struct NativeAgentGrantConsumptionRequest: Equatable, Sendable {
    public static let minimumProofBytes = 16
    public static let maximumProofBytes = 4 * 1024

    public let bootstrapID: String
    public let proof: Data
    public let binding: NativeAgentSessionBinding

    public init(bootstrapID: String, proof: Data, binding: NativeAgentSessionBinding) throws {
        guard bootstrapID.utf8.count == 36, UUID(uuidString: bootstrapID) != nil else {
            throw NativeAgentSessionBoundaryError.invalidIdentity
        }
        guard (Self.minimumProofBytes...Self.maximumProofBytes).contains(proof.count) else {
            throw NativeAgentSessionBoundaryError.invalidBootstrapProof
        }
        self.bootstrapID = bootstrapID.lowercased()
        self.proof = proof
        self.binding = binding
    }
}

/// The only network boundary needed to turn a one-time bootstrap proof into a
/// locally verified Lease. Implementations must authenticate as the enrolled
/// device and perform exact-retry recovery; they must never return credentials.
public protocol NativeAgentGrantLeaseConsuming: Sendable {
    func consumeGrant(_ request: NativeAgentGrantConsumptionRequest) throws -> NativeAgentVerifiedCloudLease
}

/// Re-observes authority that can change independently of the XPC connection.
/// The service compares the complete result with the Lease binding before each
/// protected operation.
public protocol NativeAgentSessionBindingObserving: Sendable {
    func observeSessionBinding(agentID: String) throws -> NativeAgentSessionBinding
}

/// Fixed Git commit signing boundary. There is no operation, key selector,
/// namespace, hash algorithm, repository path, or signer argument parameter.
public protocol NativeAgentGitCommitSigning: Sendable {
    func signGitCommitPayload(_ payload: Data) throws -> Data
}

/// Stable, secret-free events emitted by the M2 session machine.
public enum NativeAgentSessionAuditAction: String, CaseIterable, Codable, Sendable {
    case challengeCreated = "challenge_created"
    case sessionActivated = "session_activated"
    case requestReserved = "request_reserved"
    case signingIntent = "signing_intent"
    case signingCompleted = "signing_completed"
    case signingOutcomeUnknown = "signing_outcome_unknown"
    case sessionDenied = "session_denied"
    case sessionInvalidated = "session_invalidated"
    case sessionClosed = "session_closed"
}

/// Audit evidence is restricted to public identifiers, fixed digests, numeric
/// authority versions, and a stable reason. Payloads and localized failures are
/// structurally impossible to attach.
public struct NativeAgentSessionAuditEvidence: Equatable, Sendable {
    public let action: NativeAgentSessionAuditAction
    public let sessionID: String?
    public let requestID: String?
    public let capabilityID: String?
    public let payloadDigest: Data?
    public let binding: NativeAgentSessionBinding
    public let reasonCode: String?

    public init(
        action: NativeAgentSessionAuditAction,
        sessionID: String? = nil,
        requestID: String? = nil,
        capabilityID: String? = nil,
        payloadDigest: Data? = nil,
        binding: NativeAgentSessionBinding,
        reasonCode: String? = nil
    ) throws {
        guard [sessionID, requestID, capabilityID].compactMap({ $0 }).allSatisfy({
            $0.utf8.count == 36 && UUID(uuidString: $0) != nil
        }) else {
            throw NativeAgentSessionBoundaryError.invalidAuditEvidence
        }
        guard payloadDigest == nil || payloadDigest?.count == NativeAgentSessionBinding.digestByteCount else {
            throw NativeAgentSessionBoundaryError.invalidAuditEvidence
        }
        guard reasonCode == nil || Self.reason(reasonCode!) else {
            throw NativeAgentSessionBoundaryError.invalidAuditEvidence
        }
        self.action = action
        self.sessionID = sessionID?.lowercased()
        self.requestID = requestID?.lowercased()
        self.capabilityID = capabilityID?.lowercased()
        self.payloadDigest = payloadDigest
        self.binding = binding
        self.reasonCode = reasonCode
    }

    private static func reason(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 64 else { return false }
        return value.unicodeScalars.allSatisfy {
            ($0.value >= 97 && $0.value <= 122) || ($0.value >= 48 && $0.value <= 57) || $0.value == 95
        }
    }

    /// Digest of the closed, secret-free evidence object embedded in the
    /// durable audit record. This deliberately excludes the audit timestamp
    /// and chain predecessor; the appender receipt binds those final bytes.
    public func evidenceDigest() throws -> Data {
        var object: [String: Any] = [
            "version": 1,
            "action": action.rawValue,
            "agent_id": binding.agentID,
            "device_id": binding.deviceID,
            "process_binding_sha256": Self.hex(binding.processBindingDigest),
            "ancestry_binding_sha256": Self.hex(binding.ancestryBindingDigest),
            "worktree_binding_sha256": Self.hex(binding.worktreeBindingDigest),
            "control_sequence": binding.controlSequence,
            "authority_generation": binding.authorityGeneration,
            "key_generation": binding.keyGeneration
        ]
        if let sessionID { object["session_id"] = sessionID }
        if let requestID { object["request_id"] = requestID }
        if let capabilityID { object["capability_id"] = capabilityID }
        if let payloadDigest { object["payload_sha256"] = Self.hex(payloadDigest) }
        if let reasonCode { object["reason_code"] = reasonCode }
        return Data(SHA256.hash(data: try NativeStrictJSON.data(object)))
    }

    private static func hex(_ value: Data) -> String {
        value.map { String(format: "%02x", $0) }.joined()
    }
}

/// Proof returned only after the concrete audit writer has durably appended
/// the event. `recordDigest` is the resulting chain head, not caller input.
public struct NativeAgentSessionAuditReceipt: Equatable, Sendable {
    public let evidenceDigest: Data
    public let recordDigest: Data
    public let recordIndex: Int

    public init(evidenceDigest: Data, recordDigest: Data, recordIndex: Int) throws {
        guard evidenceDigest.count == NativeAgentSessionBinding.digestByteCount,
              recordDigest.count == NativeAgentSessionBinding.digestByteCount,
              recordIndex >= 1 else {
            throw NativeAgentSessionBoundaryError.invalidAuditEvidence
        }
        self.evidenceDigest = evidenceDigest
        self.recordDigest = recordDigest
        self.recordIndex = recordIndex
    }
}

public protocol NativeAgentSessionAuditAppending: Sendable {
    @discardableResult
    func appendAgentSessionAudit(_ evidence: NativeAgentSessionAuditEvidence) throws
        -> NativeAgentSessionAuditReceipt

    /// Reconciles the one activation event identified by the exact session and
    /// canonical evidence digest. Implementations must return an existing
    /// durable record when present, append only after verified absence, and
    /// fail closed on duplicates or substitution.
    @discardableResult
    func reconcileAgentSessionActivationAudit(
        _ evidence: NativeAgentSessionAuditEvidence
    ) throws -> NativeAgentSessionAuditReceipt
}
