import Foundation

public enum NativeAgentConnectionGuardError: String, Error, Equatable, Sendable, LocalizedError {
    case connectionObservationMismatch = "connection_observation_mismatch"
    case processIdentityChanged = "process_identity_changed"

    public var errorDescription: String? { rawValue }
}

/// Immutable authorization context owned by one accepted Agent XPC
/// connection. It binds Foundation's OS-derived peer metadata to the full
/// kernel/Security observation captured for the same PID.
public struct NativeAgentConnectionGuard: Sendable {
    public let context: NativeConnectionContext
    public let initialIdentity: NativeProcessIdentity

    public init(context: NativeConnectionContext, observation: NativeProcessObservation) throws {
        let identity = NativeProcessIdentity(observation: observation)
        guard identity.pid == context.pid,
              identity.uid == context.effectiveUserID,
              identity.pidVersion == context.pidVersion else {
            throw NativeAgentConnectionGuardError.connectionObservationMismatch
        }
        self.context = context
        self.initialIdentity = identity
    }

    public var processBindingHash: String { initialIdentity.canonicalBindingHash }
    public var ancestryBindingHash: String { initialIdentity.canonicalAncestryBindingHash }

    /// Must run immediately before every protected key use. Any PID reuse,
    /// exec, code identity, entitlement, boot, or ancestry drift denies the
    /// operation; no request field can replace the captured identity.
    public func revalidate(observation: NativeProcessObservation) throws {
        let current = NativeProcessIdentity(observation: observation)
        guard current.pid == context.pid,
              current.uid == context.effectiveUserID,
              current.pidVersion == context.pidVersion else {
            throw NativeAgentConnectionGuardError.connectionObservationMismatch
        }
        guard initialIdentity.revalidate(against: current).denialReasons.isEmpty else {
            throw NativeAgentConnectionGuardError.processIdentityChanged
        }
    }
}
