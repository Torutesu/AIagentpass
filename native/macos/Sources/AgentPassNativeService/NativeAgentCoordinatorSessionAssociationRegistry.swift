import Foundation
import AgentPassNativeCore

/// Stable failures for the service-owned coordinator-session association
/// boundary. The registry intentionally does not expose a session-only lookup
/// or disclose whether a stale association was previously present.
internal enum NativeAgentCoordinatorSessionAssociationRegistryError: String, Error, Equatable, Sendable {
    case invalidSessionID = "invalid_session_id"
    case duplicateSession = "duplicate_session"
    case duplicateBinding = "duplicate_binding"
}

/// A marker for the coordinator object retained by the service-owned
/// association. The marker keeps this boundary typed without making the
/// registry depend on any coordinator implementation details.
internal protocol NativeAgentCoordinatorSessionReference: AnyObject, Sendable {}

extension NativeAgentSessionCoordinator: NativeAgentCoordinatorSessionReference {}

/// The complete identity used as the association index. Every component is
/// derived from the service-observed session binding; a caller-supplied
/// session ID is deliberately not part of the lookup API.
internal struct NativeAgentCoordinatorSessionAssociationKey: Hashable, Sendable {
    let agentID: String
    let deviceID: String
    let processBindingDigest: Data
    let ancestryBindingDigest: Data
    let worktreeBindingDigest: Data
    let controlSequence: Int64
    let authorityGeneration: Int64
    let keyGeneration: Int64

    init(binding: NativeAgentSessionBinding) {
        self.agentID = binding.agentID
        self.deviceID = binding.deviceID
        self.processBindingDigest = binding.processBindingDigest
        self.ancestryBindingDigest = binding.ancestryBindingDigest
        self.worktreeBindingDigest = binding.worktreeBindingDigest
        self.controlSequence = binding.controlSequence
        self.authorityGeneration = binding.authorityGeneration
        self.keyGeneration = binding.keyGeneration
    }
}

internal enum NativeAgentCoordinatorSessionAssociationState: String, Sendable {
    case active
    case removed
    case invalidated
}

/// An opaque service-owned association between a live Generic Agent
/// coordinator and the exact binding observed when its session was activated.
///
/// The coordinator reference and binding are internal implementation values;
/// this object is never encoded into an XPC DTO. Once removed or invalidated,
/// the association remains unusable even if a caller retained an earlier
/// lookup result.
internal final class NativeAgentCoordinatorSessionAssociation: @unchecked Sendable {
    let sessionID: String
    let binding: NativeAgentSessionBinding
    let coordinator: any NativeAgentCoordinatorSessionReference
    let dedicatedSigningAssociation: NativeAgentDedicatedSigningAssociation?

    private let stateLock = NSLock()
    private var state: NativeAgentCoordinatorSessionAssociationState = .active

    init(
        sessionID: String,
        binding: NativeAgentSessionBinding,
        coordinator: any NativeAgentCoordinatorSessionReference,
        dedicatedSigningAssociation: NativeAgentDedicatedSigningAssociation? = nil
    ) throws {
        guard Self.isCanonicalUUID(sessionID) else {
            throw NativeAgentCoordinatorSessionAssociationRegistryError.invalidSessionID
        }
        self.sessionID = sessionID
        self.binding = binding
        self.coordinator = coordinator
        self.dedicatedSigningAssociation = dedicatedSigningAssociation
    }

    var lifecycleState: NativeAgentCoordinatorSessionAssociationState {
        stateLock.withLock { state }
    }

    var isActive: Bool {
        lifecycleState == .active
    }

    fileprivate func markRemoved() {
        stateLock.withLock { state = .removed }
    }

    fileprivate func markInvalidated() {
        stateLock.withLock { state = .invalidated }
    }

    private static func isCanonicalUUID(_ value: String) -> Bool {
        value.utf8.count == 36 && UUID(uuidString: value)?.uuidString.lowercased() == value
    }
}

/// Thread-safe, service-owned index for Generic Agent coordinator sessions.
///
/// Registration and lifecycle changes are atomic with respect to lookup. The
/// primary index is the complete service-observed binding identity. The
/// session ID is only a uniqueness guard and is never accepted as a lookup,
/// removal, or invalidation authority by itself.
internal final class NativeAgentCoordinatorSessionAssociationRegistry: @unchecked Sendable {
    private let lock = NSLock()
    private var entries: [NativeAgentCoordinatorSessionAssociationKey: NativeAgentCoordinatorSessionAssociation] = [:]
    private var sessionIDs: [String: NativeAgentCoordinatorSessionAssociationKey] = [:]
    private var retiredSessionIDs: Set<String> = []

    @discardableResult
    func register(
        sessionID: String,
        binding: NativeAgentSessionBinding,
        coordinator: any NativeAgentCoordinatorSessionReference,
        dedicatedSigningAssociation: NativeAgentDedicatedSigningAssociation? = nil
    ) throws -> NativeAgentCoordinatorSessionAssociation {
        let association = try NativeAgentCoordinatorSessionAssociation(
            sessionID: sessionID,
            binding: binding,
            coordinator: coordinator,
            dedicatedSigningAssociation: dedicatedSigningAssociation
        )
        let key = NativeAgentCoordinatorSessionAssociationKey(binding: binding)

        return try lock.withLock {
            guard entries[key] == nil else {
                throw NativeAgentCoordinatorSessionAssociationRegistryError.duplicateBinding
            }
            guard sessionIDs[association.sessionID] == nil,
                  !retiredSessionIDs.contains(association.sessionID) else {
                throw NativeAgentCoordinatorSessionAssociationRegistryError.duplicateSession
            }
            entries[key] = association
            sessionIDs[association.sessionID] = key
            return association
        }
    }

    /// Looks up only by the complete service-observed binding identity.
    /// `nil` is the fail-closed result for missing, stale, or invalidated
    /// associations.
    func lookup(binding: NativeAgentSessionBinding) -> NativeAgentCoordinatorSessionAssociation? {
        let key = NativeAgentCoordinatorSessionAssociationKey(binding: binding)
        return lock.withLock {
            guard let association = entries[key], association.isActive else { return nil }
            return association
        }
    }

    /// Atomically removes a live association and retires its session ID so the
    /// same coordinator session cannot be registered again after cleanup.
    @discardableResult
    func remove(binding: NativeAgentSessionBinding) -> NativeAgentCoordinatorSessionAssociation? {
        let key = NativeAgentCoordinatorSessionAssociationKey(binding: binding)
        return lock.withLock {
            guard let association = entries.removeValue(forKey: key) else { return nil }
            sessionIDs.removeValue(forKey: association.sessionID)
            retiredSessionIDs.insert(association.sessionID)
            association.markRemoved()
            return association
        }
    }

    /// Atomically invalidates and removes a live association. Invalidation is
    /// terminal and also retires the session ID; a stale lookup result cannot
    /// become usable again.
    @discardableResult
    func invalidate(binding: NativeAgentSessionBinding) -> NativeAgentCoordinatorSessionAssociation? {
        let key = NativeAgentCoordinatorSessionAssociationKey(binding: binding)
        return lock.withLock {
            guard let association = entries.removeValue(forKey: key) else { return nil }
            sessionIDs.removeValue(forKey: association.sessionID)
            retiredSessionIDs.insert(association.sessionID)
            association.markInvalidated()
            return association
        }
    }

    /// Test and diagnostics projection that does not expose coordinator
    /// references or caller-controlled data.
    var activeCount: Int {
        lock.withLock { entries.values.reduce(into: 0) { count, association in
            if association.isActive { count += 1 }
        } }
    }
}
