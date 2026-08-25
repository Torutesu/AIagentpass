import Foundation

/// The complete set of states a process-bound Agent session may occupy.
///
/// The enum is intentionally closed. Adding a state is a protocol change and
/// requires updating the transition table and its exhaustive tests together.
public enum NativeAgentSessionState: String, CaseIterable, Codable, Equatable, Sendable {
    case none
    case challengePending = "challenge_pending"
    case active
    case requestReserved = "request_reserved"
    case signingIntent = "signing_intent"
    case signed
    case expired
    case revoked
    case processLost = "process_lost"
    case worktreeLost = "worktree_lost"
    case controlChanged = "control_changed"
    case keyChanged = "key_changed"
    case outcomeUnknown = "outcome_unknown"
    case closed

    /// States from which no further transition is permitted.
    public var isTerminal: Bool {
        switch self {
        case .expired, .revoked, .processLost, .worktreeLost, .controlChanged,
             .keyChanged, .outcomeUnknown, .closed:
            return true
        case .none, .challengePending, .active, .requestReserved, .signingIntent, .signed:
            return false
        }
    }
}

/// Stable, secret-free reasons used by the native boundary when a transition
/// or record operation is denied. The public boundary can map these values to
/// a small NSError code set without exposing OS diagnostics or input data.
public enum NativeAgentSessionTransitionDenialReason: String, CaseIterable, Codable, Equatable, Sendable {
    case invalidTransition = "invalid_transition"
    case terminalState = "terminal_state"
    case invalidRecord = "invalid_record"
    case expired = "expired"
    case revoked = "revoked"
    case processLost = "process_lost"
    case worktreeLost = "worktree_lost"
    case controlChanged = "control_changed"
    case keyChanged = "key_changed"
    case outcomeUnknown = "outcome_unknown"
    case closed = "closed"
}

/// A value describing one proposed state change. It contains no process,
/// audit-token, worktree, credential, payload, or key material.
public struct NativeAgentSessionTransition: Codable, Equatable, Sendable {
    public let from: NativeAgentSessionState
    public let to: NativeAgentSessionState

    public init(from: NativeAgentSessionState, to: NativeAgentSessionState) {
        self.from = from
        self.to = to
    }
}

/// The error returned by the pure transition validator.
public struct NativeAgentSessionTransitionError: Error, Equatable, Sendable {
    public let reason: NativeAgentSessionTransitionDenialReason

    public init(reason: NativeAgentSessionTransitionDenialReason) {
        self.reason = reason
    }
}

/// Pure, closed transition policy for the M2-C session state machine.
public enum NativeAgentSessionTransitionValidator {
    /// Returns the stable denial reason, or nil when the edge is allowed.
    public static func denialReason(
        from: NativeAgentSessionState,
        to: NativeAgentSessionState
    ) -> NativeAgentSessionTransitionDenialReason? {
        if from.isTerminal {
            return .terminalState
        }

        guard allowedSuccessors(for: from).contains(to) else {
            return .invalidTransition
        }
        return nil
    }

    public static func denialReason(
        for transition: NativeAgentSessionTransition
    ) -> NativeAgentSessionTransitionDenialReason? {
        denialReason(from: transition.from, to: transition.to)
    }

    public static func isAllowed(
        from: NativeAgentSessionState,
        to: NativeAgentSessionState
    ) -> Bool {
        denialReason(from: from, to: to) == nil
    }

    public static func validate(
        from: NativeAgentSessionState,
        to: NativeAgentSessionState
    ) throws {
        guard let reason = denialReason(from: from, to: to) else { return }
        throw NativeAgentSessionTransitionError(reason: reason)
    }

    public static func validate(
        _ transition: NativeAgentSessionTransition
    ) throws {
        try validate(from: transition.from, to: transition.to)
    }

    /// The table is deliberately explicit. No default edge is allowed.
    public static func allowedSuccessors(
        for state: NativeAgentSessionState
    ) -> Set<NativeAgentSessionState> {
        switch state {
        case .none:
            return [.challengePending]
        case .challengePending:
            return [.active, .expired, .revoked, .processLost, .worktreeLost, .controlChanged, .keyChanged, .closed]
        case .active:
            return [.requestReserved, .expired, .revoked, .processLost, .worktreeLost, .controlChanged, .keyChanged, .closed]
        case .requestReserved:
            return [.active, .signingIntent, .expired, .revoked, .processLost, .worktreeLost, .controlChanged, .keyChanged, .closed]
        case .signingIntent:
            return [.active, .signed, .expired, .revoked, .processLost, .worktreeLost, .controlChanged, .keyChanged, .outcomeUnknown]
        case .signed:
            return [.active, .closed]
        case .expired, .revoked, .processLost, .worktreeLost, .controlChanged, .keyChanged, .outcomeUnknown, .closed:
            return []
        }
    }
}

/// Construction failures for the bounded public session record.
public enum NativeAgentSessionRecordError: String, Error, Equatable, Sendable {
    case invalidIdentifier = "invalid_identifier"
    case invalidTimestamp = "invalid_timestamp"
    case invalidExpiry = "invalid_expiry"
    case invalidBudget = "invalid_budget"
    case invalidRevision = "invalid_revision"
}

/// Immutable, bounded, secret-free projection of session state.
///
/// Process identity, ancestry, worktree paths, audit tokens, credentials,
/// payloads, signatures, and key material intentionally do not appear here.
public struct NativeAgentSessionRecord: Codable, Equatable, Sendable {
    public static let maximumIdentifierBytes = 128
    public static let maximumSignatureBudget = 1_024

    public let sessionID: String
    public let state: NativeAgentSessionState
    public let createdAtMilliseconds: Int64
    public let updatedAtMilliseconds: Int64
    public let expiresAtMilliseconds: Int64
    public let signatureBudget: Int
    public let signaturesUsed: Int
    public let revision: UInt64

    public init(
        sessionID: String,
        state: NativeAgentSessionState = .none,
        createdAtMilliseconds: Int64,
        updatedAtMilliseconds: Int64,
        expiresAtMilliseconds: Int64,
        signatureBudget: Int,
        signaturesUsed: Int = 0,
        revision: UInt64 = 0
    ) throws {
        guard Self.isSafeIdentifier(sessionID) else {
            throw NativeAgentSessionRecordError.invalidIdentifier
        }
        guard createdAtMilliseconds >= 0, updatedAtMilliseconds >= createdAtMilliseconds else {
            throw NativeAgentSessionRecordError.invalidTimestamp
        }
        guard expiresAtMilliseconds > createdAtMilliseconds else {
            throw NativeAgentSessionRecordError.invalidExpiry
        }
        guard (1...Self.maximumSignatureBudget).contains(signatureBudget),
              (0...signatureBudget).contains(signaturesUsed) else {
            throw NativeAgentSessionRecordError.invalidBudget
        }

        self.sessionID = sessionID
        self.state = state
        self.createdAtMilliseconds = createdAtMilliseconds
        self.updatedAtMilliseconds = updatedAtMilliseconds
        self.expiresAtMilliseconds = expiresAtMilliseconds
        self.signatureBudget = signatureBudget
        self.signaturesUsed = signaturesUsed
        self.revision = revision
    }

    public var remainingSignatureBudget: Int {
        signatureBudget - signaturesUsed
    }

    /// Creates the next immutable record only after the closed transition
    /// table has accepted the proposed edge.
    public func transitioning(
        to nextState: NativeAgentSessionState,
        atMilliseconds timestamp: Int64
    ) throws -> NativeAgentSessionRecord {
        try NativeAgentSessionTransitionValidator.validate(from: state, to: nextState)
        guard timestamp >= updatedAtMilliseconds else {
            throw NativeAgentSessionRecordError.invalidTimestamp
        }
        guard revision < UInt64.max else {
            throw NativeAgentSessionRecordError.invalidRevision
        }
        return try NativeAgentSessionRecord(
            sessionID: sessionID,
            state: nextState,
            createdAtMilliseconds: createdAtMilliseconds,
            updatedAtMilliseconds: timestamp,
            expiresAtMilliseconds: expiresAtMilliseconds,
            signatureBudget: signatureBudget,
            signaturesUsed: signaturesUsed,
            revision: revision + 1
        )
    }

    private static func isSafeIdentifier(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= maximumIdentifierBytes else { return false }
        return value.unicodeScalars.allSatisfy { scalar in
            switch scalar.value {
            case 48...57, 65...90, 97...122, 45, 46, 95:
                return true
            default:
                return false
            }
        }
    }

    private enum CodingKeys: String, CodingKey {
        case sessionID = "session_id"
        case state
        case createdAtMilliseconds = "created_at_ms"
        case updatedAtMilliseconds = "updated_at_ms"
        case expiresAtMilliseconds = "expires_at_ms"
        case signatureBudget = "signature_budget"
        case signaturesUsed = "signatures_used"
        case revision
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self = try NativeAgentSessionRecord(
            sessionID: container.decode(String.self, forKey: .sessionID),
            state: container.decode(NativeAgentSessionState.self, forKey: .state),
            createdAtMilliseconds: container.decode(Int64.self, forKey: .createdAtMilliseconds),
            updatedAtMilliseconds: container.decode(Int64.self, forKey: .updatedAtMilliseconds),
            expiresAtMilliseconds: container.decode(Int64.self, forKey: .expiresAtMilliseconds),
            signatureBudget: container.decode(Int.self, forKey: .signatureBudget),
            signaturesUsed: container.decode(Int.self, forKey: .signaturesUsed),
            revision: container.decode(UInt64.self, forKey: .revision)
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(sessionID, forKey: .sessionID)
        try container.encode(state, forKey: .state)
        try container.encode(createdAtMilliseconds, forKey: .createdAtMilliseconds)
        try container.encode(updatedAtMilliseconds, forKey: .updatedAtMilliseconds)
        try container.encode(expiresAtMilliseconds, forKey: .expiresAtMilliseconds)
        try container.encode(signatureBudget, forKey: .signatureBudget)
        try container.encode(signaturesUsed, forKey: .signaturesUsed)
        try container.encode(revision, forKey: .revision)
    }
}
