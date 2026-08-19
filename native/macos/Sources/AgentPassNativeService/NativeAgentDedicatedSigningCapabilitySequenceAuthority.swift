import Foundation

/// The service-owned identity for a Cloud capability sequence ledger.
///
/// This type intentionally contains only the two authenticated identifiers
/// that select a coordinator session. It has no Codable conformance because
/// the binding must be constructed from Service state, not from a Host,
/// Child, or Cloud envelope.
public struct NativeAgentDedicatedSigningCapabilitySequenceBinding: Equatable, Hashable, Sendable {
    public let coordinatorSessionID: String
    public let agentID: String

    public init(coordinatorSessionID: String, agentID: String) throws {
        guard Self.isCanonicalUUID(coordinatorSessionID) else {
            throw NativeAgentDedicatedSigningCapabilitySequenceAuthorityError.invalidCoordinatorSessionID
        }
        guard Self.isCanonicalUUID(agentID) else {
            throw NativeAgentDedicatedSigningCapabilitySequenceAuthorityError.invalidAgentID
        }
        self.coordinatorSessionID = coordinatorSessionID
        self.agentID = agentID
    }

    private static func isCanonicalUUID(_ value: String) -> Bool {
        value.utf8.count == 36
            && UUID(uuidString: value)?.uuidString.lowercased() == value
    }
}

/// A marker minted by Service code only after a response has been decoded and
/// cryptographically verified. The marker carries no response, payload, key,
/// or secret. Its internal initializer prevents an XPC/network-facing caller
/// from manufacturing bootstrap authority through this API.
public struct NativeAgentDedicatedSigningCapabilityTrustedBootstrap: Sendable {
    internal init() {}
}

/// Secret-free, stable failures for the sequence authority.
public enum NativeAgentDedicatedSigningCapabilitySequenceAuthorityError: String, Error, Equatable, Sendable, LocalizedError {
    case invalidCoordinatorSessionID = "invalid_coordinator_session_id"
    case invalidAgentID = "invalid_agent_id"
    case invalidMaximumSequence = "invalid_maximum_sequence"
    case invalidSequence = "invalid_sequence"
    case invalidStatementHash = "invalid_statement_hash"
    case overflow = "overflow"
    case bootstrapRequired = "bootstrap_required"
    case staleSequence = "stale_sequence"
    case statementHashConflict = "statement_hash_conflict"
    case invalidPreparation = "invalid_preparation"
    case invalidated = "invalidated"

    public var errorDescription: String? { rawValue }
}

/// The hash and sequence accepted by the Service. This is a typed projection
/// only; it deliberately contains no signed bytes, payload, or credential.
public struct NativeAgentDedicatedSigningCapabilitySequenceStatement: Equatable, Sendable {
    public static let statementHashCharacterCount = 64

    public let sequence: UInt64
    public let statementHash: String

    public init(sequence: UInt64, statementHash: String) throws {
        guard sequence >= 1 else {
            throw NativeAgentDedicatedSigningCapabilitySequenceAuthorityError.invalidSequence
        }
        guard Self.isCanonicalStatementHash(statementHash) else {
            throw NativeAgentDedicatedSigningCapabilitySequenceAuthorityError.invalidStatementHash
        }
        self.sequence = sequence
        self.statementHash = statementHash
    }

    private static func isCanonicalStatementHash(_ value: String) -> Bool {
        value.utf8.count == statementHashCharacterCount
            && value.unicodeScalars.allSatisfy { scalar in
                switch scalar.value {
                case 48...57, 97...102:
                    return true
                default:
                    return false
                }
            }
    }
}

/// A preparation is intentionally an object tied to its authority instance.
/// It cannot be decoded or transferred as an authority envelope, and a
/// preparation made by another session's authority is rejected on accept.
public final class NativeAgentDedicatedSigningCapabilitySequencePreparation: @unchecked Sendable {
    fileprivate let authority: NativeAgentDedicatedSigningCapabilitySequenceAuthority
    fileprivate let statement: NativeAgentDedicatedSigningCapabilitySequenceStatement

    fileprivate init(
        authority: NativeAgentDedicatedSigningCapabilitySequenceAuthority,
        statement: NativeAgentDedicatedSigningCapabilitySequenceStatement
    ) {
        self.authority = authority
        self.statement = statement
    }
}

public enum NativeAgentDedicatedSigningCapabilitySequenceAcceptanceDisposition: String, Equatable, Sendable {
    case bootstrapped = "bootstrapped"
    case advanced = "advanced"
    case replayed = "replayed"
}

/// The result of one atomic accept operation. It contains only the accepted
/// sequence and statement digest, never the capability or signing payload.
public struct NativeAgentDedicatedSigningCapabilitySequenceAcceptance: Equatable, Sendable {
    public let binding: NativeAgentDedicatedSigningCapabilitySequenceBinding
    public let sequence: UInt64
    public let statementHash: String
    public let disposition: NativeAgentDedicatedSigningCapabilitySequenceAcceptanceDisposition

    fileprivate init(
        binding: NativeAgentDedicatedSigningCapabilitySequenceBinding,
        statement: NativeAgentDedicatedSigningCapabilitySequenceStatement,
        disposition: NativeAgentDedicatedSigningCapabilitySequenceAcceptanceDisposition
    ) {
        self.binding = binding
        self.sequence = statement.sequence
        self.statementHash = statement.statementHash
        self.disposition = disposition
    }
}

/// A non-sensitive state projection for diagnostics and authorization checks.
public struct NativeAgentDedicatedSigningCapabilitySequenceAuthoritySnapshot: Equatable, Sendable {
    public let binding: NativeAgentDedicatedSigningCapabilitySequenceBinding
    public let acceptedSequence: UInt64?
    public let acceptedStatementHash: String?
    public let isInitialized: Bool
    public let isInvalidated: Bool

    fileprivate init(
        binding: NativeAgentDedicatedSigningCapabilitySequenceBinding,
        acceptedStatement: NativeAgentDedicatedSigningCapabilitySequenceStatement?,
        isInvalidated: Bool
    ) {
        self.binding = binding
        self.acceptedSequence = acceptedStatement?.sequence
        self.acceptedStatementHash = acceptedStatement?.statementHash
        self.isInitialized = acceptedStatement != nil
        self.isInvalidated = isInvalidated
    }
}

/// A thread-safe, service-owned monotonic sequence authority for one
/// coordinator session and Agent.
///
/// The authority begins uninitialized. A first statement can be accepted only
/// with a `NativeAgentDedicatedSigningCapabilityTrustedBootstrap` minted by
/// the Service after authenticating the Cloud response. Once initialized,
/// higher sequences advance the state, the same sequence is idempotent only
/// when its statement hash is identical, and lower or conflicting sequences
/// are rejected. The state is never inferred from an untrusted envelope.
public final class NativeAgentDedicatedSigningCapabilitySequenceAuthority: @unchecked Sendable {
    /// Cloud statement sequences are positive safe integers. Keeping the
    /// default bounded also makes conversion from the signed Int64 contract
    /// explicit and gives callers a deterministic overflow failure.
    public static let defaultMaximumSequence: UInt64 = 9_007_199_254_740_991

    public let binding: NativeAgentDedicatedSigningCapabilitySequenceBinding
    public let maximumSequence: UInt64

    private let lock = NSLock()
    private var acceptedStatement: NativeAgentDedicatedSigningCapabilitySequenceStatement?
    private var invalidated = false

    public init(
        binding: NativeAgentDedicatedSigningCapabilitySequenceBinding,
        maximumSequence: UInt64 = NativeAgentDedicatedSigningCapabilitySequenceAuthority.defaultMaximumSequence
    ) throws {
        guard maximumSequence >= 1,
              maximumSequence <= Self.defaultMaximumSequence else {
            throw NativeAgentDedicatedSigningCapabilitySequenceAuthorityError.invalidMaximumSequence
        }
        self.binding = binding
        self.maximumSequence = maximumSequence
    }

    public func snapshot() -> NativeAgentDedicatedSigningCapabilitySequenceAuthoritySnapshot {
        lock.lock()
        defer { lock.unlock() }
        return snapshotLocked()
    }

    /// Validates a candidate against the current state and returns an
    /// authority-bound preparation. This method does not mutate state; the
    /// check is repeated atomically by `accept` so a concurrent caller cannot
    /// bypass the monotonic boundary between prepare and accept.
    public func prepare(
        sequence: UInt64,
        statementHash: String
    ) throws -> NativeAgentDedicatedSigningCapabilitySequencePreparation {
        let statement = try NativeAgentDedicatedSigningCapabilitySequenceStatement(
            sequence: sequence,
            statementHash: statementHash
        )

        lock.lock()
        defer { lock.unlock() }
        try validateCandidateLocked(statement)
        return NativeAgentDedicatedSigningCapabilitySequencePreparation(
            authority: self,
            statement: statement
        )
    }

    /// Atomically accepts a previously prepared statement. The bootstrap
    /// marker is required only while the authority is uninitialized. It is
    /// intentionally separate from the statement so a decoded response
    /// cannot smuggle bootstrap authority through a Codable DTO.
    @discardableResult
    public func accept(
        _ preparation: NativeAgentDedicatedSigningCapabilitySequencePreparation,
        trustedBootstrap: NativeAgentDedicatedSigningCapabilityTrustedBootstrap? = nil
    ) throws -> NativeAgentDedicatedSigningCapabilitySequenceAcceptance {
        guard preparation.authority === self else {
            throw NativeAgentDedicatedSigningCapabilitySequenceAuthorityError.invalidPreparation
        }

        lock.lock()
        defer { lock.unlock() }
        guard !invalidated else {
            throw NativeAgentDedicatedSigningCapabilitySequenceAuthorityError.invalidated
        }

        let statement = preparation.statement
        try validateCandidateLocked(statement)
        if let current = acceptedStatement {
            let disposition: NativeAgentDedicatedSigningCapabilitySequenceAcceptanceDisposition
            if statement.sequence == current.sequence {
                // validateCandidateLocked already rejected a hash mismatch.
                disposition = .replayed
            } else {
                acceptedStatement = statement
                disposition = .advanced
            }
            return NativeAgentDedicatedSigningCapabilitySequenceAcceptance(
                binding: binding,
                statement: statement,
                disposition: disposition
            )
        }

        guard trustedBootstrap != nil else {
            throw NativeAgentDedicatedSigningCapabilitySequenceAuthorityError.bootstrapRequired
        }
        acceptedStatement = statement
        return NativeAgentDedicatedSigningCapabilitySequenceAcceptance(
            binding: binding,
            statement: statement,
            disposition: .bootstrapped
        )
    }

    /// Invalidates the authority permanently. Repeated invalidation is safe.
    public func invalidate() {
        lock.lock()
        defer { lock.unlock() }
        invalidated = true
    }

    private func validateCandidateLocked(
        _ statement: NativeAgentDedicatedSigningCapabilitySequenceStatement
    ) throws {
        guard !invalidated else {
            throw NativeAgentDedicatedSigningCapabilitySequenceAuthorityError.invalidated
        }
        guard statement.sequence <= maximumSequence else {
            throw NativeAgentDedicatedSigningCapabilitySequenceAuthorityError.overflow
        }
        guard let current = acceptedStatement else { return }
        if statement.sequence < current.sequence {
            throw NativeAgentDedicatedSigningCapabilitySequenceAuthorityError.staleSequence
        }
        if statement.sequence == current.sequence,
           statement.statementHash != current.statementHash {
            throw NativeAgentDedicatedSigningCapabilitySequenceAuthorityError.statementHashConflict
        }
    }

    private func snapshotLocked() -> NativeAgentDedicatedSigningCapabilitySequenceAuthoritySnapshot {
        NativeAgentDedicatedSigningCapabilitySequenceAuthoritySnapshot(
            binding: binding,
            acceptedStatement: acceptedStatement,
            isInvalidated: invalidated
        )
    }
}

/// Service-local authority index. It never accepts a binding from a network
/// or XPC decoder; callers must derive the binding from the verified
/// Coordinator context first.
public final class NativeAgentDedicatedSigningCapabilitySequenceAuthorityRegistry: @unchecked Sendable {
    private let lock = NSLock()
    private var authorities: [NativeAgentDedicatedSigningCapabilitySequenceBinding: NativeAgentDedicatedSigningCapabilitySequenceAuthority] = [:]

    public init() {}

    public func authority(
        for binding: NativeAgentDedicatedSigningCapabilitySequenceBinding
    ) throws -> NativeAgentDedicatedSigningCapabilitySequenceAuthority {
        lock.lock()
        defer { lock.unlock() }
        if let existing = authorities[binding] { return existing }
        let created = try NativeAgentDedicatedSigningCapabilitySequenceAuthority(binding: binding)
        authorities[binding] = created
        return created
    }

    public func invalidate(binding: NativeAgentDedicatedSigningCapabilitySequenceBinding) {
        lock.lock()
        let authority = authorities[binding]
        lock.unlock()
        authority?.invalidate()
    }
}
