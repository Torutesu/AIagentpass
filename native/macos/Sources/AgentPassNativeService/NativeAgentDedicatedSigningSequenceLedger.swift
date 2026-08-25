import Foundation

/// The service-owned identity to which a Dedicated Host/Child signing
/// sequence is bound.  This is intentionally a value type with no Codable
/// conformance: it must be constructed from already authenticated Service
/// state, never decoded from an XPC or network envelope.
public struct NativeAgentDedicatedSigningSequenceBinding: Equatable, Hashable, Sendable {
    public static let processBindingHashCharacterCount = 64

    public let sessionID: String
    public let processBindingHash: String

    /// Creates a canonical binding.  Session IDs are required to be lowercase
    /// canonical UUIDs and process hashes are required to be lowercase
    /// SHA-256-shaped hexadecimal strings.  The hash is an identity value,
    /// not a secret.
    public init(sessionID: String, processBindingHash: String) throws {
        guard Self.isCanonicalSessionID(sessionID) else {
            throw NativeAgentDedicatedSigningSequenceLedgerError.invalidSessionID
        }
        guard Self.isCanonicalProcessBindingHash(processBindingHash) else {
            throw NativeAgentDedicatedSigningSequenceLedgerError.invalidProcessBindingHash
        }
        self.sessionID = sessionID
        self.processBindingHash = processBindingHash
    }

    /// Allows Service code that already holds a verified digest to create the
    /// same canonical binding without introducing a network-facing decoder.
    public init(sessionID: String, processBindingHash: Data) throws {
        guard processBindingHash.count == Self.processBindingHashCharacterCount / 2 else {
            throw NativeAgentDedicatedSigningSequenceLedgerError.invalidProcessBindingHash
        }
        try self.init(
            sessionID: sessionID,
            processBindingHash: processBindingHash
                .map { String(format: "%02x", $0) }
                .joined()
        )
    }

    private static func isCanonicalSessionID(_ value: String) -> Bool {
        value.utf8.count == 36
            && UUID(uuidString: value)?.uuidString.lowercased() == value
    }

    private static func isCanonicalProcessBindingHash(_ value: String) -> Bool {
        value.utf8.count == processBindingHashCharacterCount
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

/// Stable, secret-free failures for the sequence boundary.  No associated
/// values are used so callers cannot reflect payloads, tokens, or OS details
/// through an error path.
public enum NativeAgentDedicatedSigningSequenceLedgerError: String, Error, Equatable, Sendable, LocalizedError {
    case invalidSessionID = "invalid_session_id"
    case invalidProcessBindingHash = "invalid_process_binding_hash"
    case invalidMaximumSequence = "invalid_maximum_sequence"
    case wrongSession = "wrong_session"
    case wrongProcessBindingHash = "wrong_process_binding_hash"
    case replay = "replay"
    case skipped = "skipped"
    case overflow = "overflow"
    case invalidated = "invalidated"

    public var errorDescription: String? { rawValue }
}

/// The result of one atomic sequence consumption.  The returned receipt is a
/// local typed projection; it contains no capability, payload, or credential.
public struct NativeAgentDedicatedSigningSequenceConsumption: Equatable, Sendable {
    public let binding: NativeAgentDedicatedSigningSequenceBinding
    public let sequence: UInt64
    public let isTerminal: Bool

    fileprivate init(
        binding: NativeAgentDedicatedSigningSequenceBinding,
        sequence: UInt64,
        isTerminal: Bool
    ) {
        self.binding = binding
        self.sequence = sequence
        self.isTerminal = isTerminal
    }
}

/// A bounded, in-memory sequence ledger owned by the native Service for one
/// Dedicated Host/Child session.
///
/// The ledger starts at sequence 1.  `consume(sequence:)` is the validation
/// boundary for a sequence supplied by already-authenticated Service state:
/// only the exact next sequence is accepted.  `consumeNext()` is the atomic
/// allocator used when the Service itself is the component assigning the
/// sequence.  Both operations share the same lock and state machine.
///
/// This type deliberately has no Codable or network input surface.  The
/// caller must retain the instance created by the Service and cannot select a
/// different session or process binding after initialization.
public final class NativeAgentDedicatedSigningSequenceLedger: @unchecked Sendable {
    public static let defaultMaximumSequence: UInt64 = UInt64(UInt32.max)

    public struct Snapshot: Equatable, Sendable {
        public let binding: NativeAgentDedicatedSigningSequenceBinding
        public let nextSequence: UInt64?
        public let maximumSequence: UInt64
        public let isInvalidated: Bool
        public let isExhausted: Bool

        fileprivate init(
            binding: NativeAgentDedicatedSigningSequenceBinding,
            nextSequence: UInt64?,
            maximumSequence: UInt64,
            isInvalidated: Bool,
            isExhausted: Bool
        ) {
            self.binding = binding
            self.nextSequence = nextSequence
            self.maximumSequence = maximumSequence
            self.isInvalidated = isInvalidated
            self.isExhausted = isExhausted
        }
    }

    private enum TerminalState {
        case invalidated
        case exhausted
    }

    public let binding: NativeAgentDedicatedSigningSequenceBinding
    public let maximumSequence: UInt64

    private let lock = NSLock()
    private var nextSequence: UInt64 = 1
    private var terminalState: TerminalState?

    public init(
        binding: NativeAgentDedicatedSigningSequenceBinding,
        maximumSequence: UInt64 = NativeAgentDedicatedSigningSequenceLedger.defaultMaximumSequence
    ) throws {
        guard maximumSequence >= 1 else {
            throw NativeAgentDedicatedSigningSequenceLedgerError.invalidMaximumSequence
        }
        self.binding = binding
        self.maximumSequence = maximumSequence
    }

    /// Returns a non-sensitive state projection under the same lock used for
    /// consumption and invalidation.
    public func snapshot() -> Snapshot {
        lock.lock()
        defer { lock.unlock() }
        return snapshotLocked()
    }

    /// Atomically consumes exactly `sequence` for the bound session and
    /// process.  A lower value is a replay; a higher value is a skip.
    @discardableResult
    public func consume(
        binding suppliedBinding: NativeAgentDedicatedSigningSequenceBinding,
        sequence: UInt64
    ) throws -> NativeAgentDedicatedSigningSequenceConsumption {
        lock.lock()
        defer { lock.unlock() }
        return try consumeLocked(binding: suppliedBinding, sequence: sequence)
    }

    /// Convenience overload for Service-local code that has not yet projected
    /// its identity into the typed binding value.  It still performs all
    /// canonical validation before entering the ledger state machine.
    @discardableResult
    public func consume(
        sessionID: String,
        processBindingHash: String,
        sequence: UInt64
    ) throws -> NativeAgentDedicatedSigningSequenceConsumption {
        let suppliedBinding = try NativeAgentDedicatedSigningSequenceBinding(
            sessionID: sessionID,
            processBindingHash: processBindingHash
        )
        return try consume(binding: suppliedBinding, sequence: sequence)
    }

    /// Atomically allocates and consumes the exact next sequence.  This is
    /// useful when sequence assignment is entirely Service-owned and avoids a
    /// caller having to observe and race on `snapshot().nextSequence`.
    @discardableResult
    public func consumeNext(
        binding suppliedBinding: NativeAgentDedicatedSigningSequenceBinding
    ) throws -> NativeAgentDedicatedSigningSequenceConsumption {
        lock.lock()
        defer { lock.unlock() }
        try validateBindingLocked(suppliedBinding)
        guard terminalState == nil else {
            throw terminalErrorLocked()
        }
        return try consumeLocked(binding: suppliedBinding, sequence: nextSequence)
    }

    /// Invalidates the ledger permanently.  Invalidation is idempotent and
    /// never reopens an exhausted or already invalidated ledger.
    public func invalidate() {
        lock.lock()
        defer { lock.unlock() }
        guard terminalState == nil else { return }
        terminalState = .invalidated
    }

    private func consumeLocked(
        binding suppliedBinding: NativeAgentDedicatedSigningSequenceBinding,
        sequence: UInt64
    ) throws -> NativeAgentDedicatedSigningSequenceConsumption {
        try validateBindingLocked(suppliedBinding)
        guard terminalState == nil else {
            throw terminalErrorLocked()
        }
        guard sequence <= maximumSequence else {
            throw NativeAgentDedicatedSigningSequenceLedgerError.overflow
        }
        if sequence < nextSequence {
            throw NativeAgentDedicatedSigningSequenceLedgerError.replay
        }
        guard sequence == nextSequence else {
            throw NativeAgentDedicatedSigningSequenceLedgerError.skipped
        }

        let consumedSequence = nextSequence
        let isTerminal = consumedSequence == maximumSequence
        if isTerminal {
            terminalState = .exhausted
        } else {
            nextSequence += 1
        }
        return NativeAgentDedicatedSigningSequenceConsumption(
            binding: binding,
            sequence: consumedSequence,
            isTerminal: isTerminal
        )
    }

    private func validateBindingLocked(
        _ suppliedBinding: NativeAgentDedicatedSigningSequenceBinding
    ) throws {
        guard suppliedBinding.sessionID == binding.sessionID else {
            throw NativeAgentDedicatedSigningSequenceLedgerError.wrongSession
        }
        guard suppliedBinding.processBindingHash == binding.processBindingHash else {
            throw NativeAgentDedicatedSigningSequenceLedgerError.wrongProcessBindingHash
        }
    }

    private func terminalErrorLocked() -> NativeAgentDedicatedSigningSequenceLedgerError {
        switch terminalState {
        case .invalidated:
            return .invalidated
        case .exhausted:
            return .overflow
        case .none:
            // The method is only called after a terminal-state guard.  This
            // fallback keeps the function total without exposing state.
            return .invalidated
        }
    }

    private func snapshotLocked() -> Snapshot {
        Snapshot(
            binding: binding,
            nextSequence: terminalState == nil ? nextSequence : nil,
            maximumSequence: maximumSequence,
            isInvalidated: terminalState == .invalidated,
            isExhausted: terminalState == .exhausted
        )
    }
}
