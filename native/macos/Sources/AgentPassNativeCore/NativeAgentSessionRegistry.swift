import Foundation

public enum NativeAgentSessionRegistryError: String, Error, Equatable, Sendable {
    case invalidInput = "invalid_input"
    case sessionExists = "session_exists"
    case sessionMissing = "session_missing"
    case connectionMismatch = "connection_mismatch"
    case bindingMismatch = "binding_mismatch"
    case deadlineMismatch = "deadline_mismatch"
    case sessionNotActive = "session_not_active"
    case requestReplay = "request_replay"
    case requestConflict = "request_conflict"
    case capabilityReplay = "capability_replay"
    case nonceReplay = "nonce_replay"
    case budgetExhausted = "budget_exhausted"
    case reservationMissing = "reservation_missing"
    case reservationMismatch = "reservation_mismatch"
    case transitionDenied = "transition_denied"
    case sessionCapacityExceeded = "session_capacity_exceeded"
}
public struct NativeAgentSessionRegistryStatus: Equatable, Sendable {
    public let sessionID: String
    public let leaseID: String
    public let state: NativeAgentSessionState
    public let expiresAtMilliseconds: Int64
    public let maxSignatures: Int
    public let usedSignatures: Int

    public var remainingSignatures: Int { maxSignatures - usedSignatures }
}

public struct NativeAgentSessionReservation: Equatable, Sendable {
    public let sessionID: String
    public let requestID: String
    public let capabilityID: String
    public let payloadDigest: Data
    public let budgetSequence: Int
}

/// An in-memory, authority-free admission held while the coordinator makes its
/// activation intent durable. It is deliberately non-Codable and cannot be
/// constructed outside this file.
public struct NativeAgentSessionActivationReservation: Equatable, Sendable {
    public let plannedStatus: NativeAgentSessionRegistryStatus
    fileprivate let token: String

    public var sessionID: String { plannedStatus.sessionID }

    fileprivate init(plannedStatus: NativeAgentSessionRegistryStatus, token: String) {
        self.plannedStatus = plannedStatus
        self.token = token
    }
}

/// Service-wide, in-memory M2 authority owner. All session transitions and
/// replay/budget reservations are serialized by one lock. The registry is
/// intentionally not Codable: active authority never survives service restart.
public final class NativeAgentSessionRegistry: @unchecked Sendable {
    public static let maximumActiveSessions = 1_024

    private struct RequestIdentity: Equatable {
        let capabilityID: String
        let nonce: Data
        let payloadDigest: Data
    }

    private struct Entry {
        let lease: NativeAgentVerifiedCloudLease
        let leaseID: String
        let connectionTokenIdentity: String
        var deadline: NativeAgentSessionDeadline
        var state: NativeAgentSessionState
        var usedSignatures: Int
        var requests: [String: RequestIdentity]
        var consumedCapabilities: Set<String>
        var consumedNonces: Set<Data>
        var reservation: NativeAgentSessionReservation?
    }

    private struct PendingActivation {
        let reservation: NativeAgentSessionActivationReservation
        var entry: Entry
    }

    private let lock = NSLock()
    private var entries: [String: Entry] = [:]
    private var pendingActivations: [String: PendingActivation] = [:]
    private var committedActivations: [String: PendingActivation] = [:]

    public init() {}

    public func activate(
        lease: NativeAgentVerifiedCloudLease,
        localLeaseID: String,
        connectionTokenIdentity: String,
        deadline: NativeAgentSessionDeadline,
        globalLimit: Int = NativeAgentSessionRegistry.maximumActiveSessions,
        perAgentLimit: Int = NativeAgentSessionRegistry.maximumActiveSessions,
        perWorktreeLimit: Int = NativeAgentSessionRegistry.maximumActiveSessions
    ) throws -> NativeAgentSessionRegistryStatus {
        let reservation = try reserveActivation(
            lease: lease,
            localLeaseID: localLeaseID,
            connectionTokenIdentity: connectionTokenIdentity,
            deadline: deadline,
            globalLimit: globalLimit,
            perAgentLimit: perAgentLimit,
            perWorktreeLimit: perWorktreeLimit
        )
        do {
            _ = try commitActivation(
                reservation,
                connectionTokenIdentity: connectionTokenIdentity,
                wallClock: deadline.activationWallClock,
                monotonicClock: deadline.activationMonotonicClock
            )
            return try publishActivation(
                reservation,
                connectionTokenIdentity: connectionTokenIdentity,
                wallClock: deadline.activationWallClock,
                monotonicClock: deadline.activationMonotonicClock
            )
        } catch {
            _ = try? abortActivation(
                reservation,
                connectionTokenIdentity: connectionTokenIdentity
            )
            throw error
        }
    }

    /// Reserves capacity and the exact activation tuple without publishing a
    /// session into the authority-bearing registry. Status/signing operations
    /// cannot observe or use this reservation.
    public func reserveActivation(
        lease: NativeAgentVerifiedCloudLease,
        localLeaseID: String,
        connectionTokenIdentity: String,
        deadline: NativeAgentSessionDeadline,
        globalLimit: Int = NativeAgentSessionRegistry.maximumActiveSessions,
        perAgentLimit: Int = NativeAgentSessionRegistry.maximumActiveSessions,
        perWorktreeLimit: Int = NativeAgentSessionRegistry.maximumActiveSessions,
        wallClock: NativeAgentWallClockValue? = nil,
        monotonicClock: NativeAgentMonotonicClockValue? = nil
    ) throws -> NativeAgentSessionActivationReservation {
        guard Self.uuid(localLeaseID), Self.hash(connectionTokenIdentity),
              deadline.signedWallExpiryMilliseconds == lease.expiresAtMilliseconds,
              lease.usedSignatures <= lease.maxSignatures,
              (1...Self.maximumActiveSessions).contains(globalLimit),
              (1...globalLimit).contains(perAgentLimit),
              (1...globalLimit).contains(perWorktreeLimit) else {
            throw NativeAgentSessionRegistryError.invalidInput
        }
        lock.lock()
        defer { lock.unlock() }
        pruneExpiredUnpublished(
            wallClock: wallClock ?? deadline.activationWallClock,
            monotonicClock: monotonicClock ?? deadline.activationMonotonicClock
        )
        let activeEntries = entries.values.filter { !$0.state.isTerminal }
        let unpublishedEntries = pendingActivations.values.map(\.entry)
            + committedActivations.values.map(\.entry)
        guard activeEntries.count + unpublishedEntries.count < globalLimit,
              activeEntries.filter({ $0.lease.binding.agentID == lease.binding.agentID }).count
                + unpublishedEntries.filter({ $0.lease.binding.agentID == lease.binding.agentID }).count
                < perAgentLimit,
              activeEntries.filter({ $0.lease.binding.worktreeBindingDigest == lease.binding.worktreeBindingDigest }).count
                + unpublishedEntries.filter({ $0.lease.binding.worktreeBindingDigest == lease.binding.worktreeBindingDigest }).count
                < perWorktreeLimit else {
            throw NativeAgentSessionRegistryError.sessionCapacityExceeded
        }
        guard entries[lease.sessionID] == nil,
              pendingActivations[lease.sessionID] == nil,
              committedActivations[lease.sessionID] == nil else {
            throw NativeAgentSessionRegistryError.sessionExists
        }
        let state: NativeAgentSessionState = lease.usedSignatures == lease.maxSignatures ? .closed : .active
        let entry = Entry(
            lease: lease,
            leaseID: localLeaseID.lowercased(),
            connectionTokenIdentity: connectionTokenIdentity,
            deadline: deadline,
            state: state,
            usedSignatures: lease.usedSignatures,
            requests: [:],
            consumedCapabilities: [],
            consumedNonces: [],
            reservation: nil
        )
        let reservation = NativeAgentSessionActivationReservation(
            plannedStatus: Self.status(entry),
            token: UUID().uuidString.lowercased()
        )
        pendingActivations[lease.sessionID] = PendingActivation(
            reservation: reservation,
            entry: entry
        )
        return reservation
    }

    /// Commits the exact reserved entry into an in-memory hidden state. The
    /// status/signing APIs still cannot observe or use it until publication.
    public func commitActivation(
        _ reservation: NativeAgentSessionActivationReservation,
        connectionTokenIdentity: String,
        wallClock: NativeAgentWallClockValue,
        monotonicClock: NativeAgentMonotonicClockValue
    ) throws -> NativeAgentSessionRegistryStatus {
        guard Self.hash(connectionTokenIdentity) else {
            throw NativeAgentSessionRegistryError.invalidInput
        }
        return try lock.withLock {
            pruneExpiredUnpublished(wallClock: wallClock, monotonicClock: monotonicClock)
            let sessionID = reservation.plannedStatus.sessionID
            guard let pending = pendingActivations[sessionID] else {
                throw NativeAgentSessionRegistryError.reservationMissing
            }
            guard pending.entry.connectionTokenIdentity == connectionTokenIdentity else {
                throw NativeAgentSessionRegistryError.connectionMismatch
            }
            guard pending.reservation == reservation,
                  Self.status(pending.entry) == reservation.plannedStatus,
                  entries[sessionID] == nil,
                  committedActivations[sessionID] == nil else {
                throw NativeAgentSessionRegistryError.reservationMismatch
            }
            var entry = pending.entry
            try verifyDeadline(&entry, wallClock: wallClock, monotonicClock: monotonicClock)
            pendingActivations.removeValue(forKey: sessionID)
            committedActivations[sessionID] = PendingActivation(
                reservation: pending.reservation,
                entry: entry
            )
            return Self.status(entry)
        }
    }

    /// Publishes a committed activation. This is the only transition that
    /// makes the session visible to status, close, or signing-budget APIs.
    public func publishActivation(
        _ reservation: NativeAgentSessionActivationReservation,
        connectionTokenIdentity: String,
        wallClock: NativeAgentWallClockValue,
        monotonicClock: NativeAgentMonotonicClockValue
    ) throws -> NativeAgentSessionRegistryStatus {
        guard Self.hash(connectionTokenIdentity) else {
            throw NativeAgentSessionRegistryError.invalidInput
        }
        return try lock.withLock {
            pruneExpiredUnpublished(wallClock: wallClock, monotonicClock: monotonicClock)
            let sessionID = reservation.sessionID
            guard let committed = committedActivations[sessionID] else {
                throw NativeAgentSessionRegistryError.reservationMissing
            }
            guard committed.entry.connectionTokenIdentity == connectionTokenIdentity else {
                throw NativeAgentSessionRegistryError.connectionMismatch
            }
            guard committed.reservation == reservation,
                  Self.status(committed.entry) == reservation.plannedStatus,
                  entries[sessionID] == nil else {
                throw NativeAgentSessionRegistryError.reservationMismatch
            }
            var entry = committed.entry
            try verifyDeadline(&entry, wallClock: wallClock, monotonicClock: monotonicClock)
            committedActivations.removeValue(forKey: sessionID)
            entries[sessionID] = entry
            return Self.status(entry)
        }
    }

    /// Aborts an exact, unpublished activation owned by the supplied
    /// connection. Published entries are authority and can never be removed by
    /// this operation.
    @discardableResult
    public func abortActivation(
        _ reservation: NativeAgentSessionActivationReservation,
        connectionTokenIdentity: String
    ) throws -> Bool {
        guard Self.hash(connectionTokenIdentity) else {
            throw NativeAgentSessionRegistryError.invalidInput
        }
        return try lock.withLock {
            let sessionID = reservation.sessionID
            if let pending = pendingActivations[sessionID] {
                guard pending.entry.connectionTokenIdentity == connectionTokenIdentity else {
                    throw NativeAgentSessionRegistryError.connectionMismatch
                }
                guard pending.reservation == reservation else {
                    throw NativeAgentSessionRegistryError.reservationMismatch
                }
                pendingActivations.removeValue(forKey: sessionID)
                return true
            }
            if let committed = committedActivations[sessionID] {
                guard committed.entry.connectionTokenIdentity == connectionTokenIdentity else {
                    throw NativeAgentSessionRegistryError.connectionMismatch
                }
                guard committed.reservation == reservation else {
                    throw NativeAgentSessionRegistryError.reservationMismatch
                }
                committedActivations.removeValue(forKey: sessionID)
                return true
            }
            if entries[sessionID] != nil {
                throw NativeAgentSessionRegistryError.transitionDenied
            }
            return false
        }
    }

    /// Releases only an authority-free activation reservation. Exact repeated
    /// cancellation is reported as `false`; a substituted live reservation is
    /// rejected and committed authority is never removed here.
    @discardableResult
    public func cancelActivation(
        _ reservation: NativeAgentSessionActivationReservation
    ) throws -> Bool {
        try lock.withLock {
            let sessionID = reservation.plannedStatus.sessionID
            guard let pending = pendingActivations[sessionID] else {
                if committedActivations[sessionID] != nil || entries[sessionID] != nil {
                    throw NativeAgentSessionRegistryError.transitionDenied
                }
                return false
            }
            guard pending.reservation == reservation else {
                throw NativeAgentSessionRegistryError.reservationMismatch
            }
            pendingActivations.removeValue(forKey: sessionID)
            return true
        }
    }

    public func status(
        sessionID: String,
        connectionTokenIdentity: String,
        binding: NativeAgentSessionBinding,
        wallClock: NativeAgentWallClockValue,
        monotonicClock: NativeAgentMonotonicClockValue
    ) throws -> NativeAgentSessionRegistryStatus {
        try lock.withLock {
            var entry = try checkedEntry(sessionID: sessionID, connectionTokenIdentity: connectionTokenIdentity, binding: binding)
            if !entry.state.isTerminal {
                do { _ = try entry.deadline.revalidate(wallClock: wallClock, monotonicClock: monotonicClock) }
                catch { entry.state = .expired; entry.reservation = nil }
                entries[sessionID] = entry
            }
            return Self.status(entry)
        }
    }

    public func reserve(
        sessionID: String,
        requestID: String,
        capabilityID: String,
        nonce: Data,
        payloadDigest: Data,
        connectionTokenIdentity: String,
        binding: NativeAgentSessionBinding,
        wallClock: NativeAgentWallClockValue,
        monotonicClock: NativeAgentMonotonicClockValue
    ) throws -> NativeAgentSessionReservation {
        guard Self.uuid(requestID), Self.uuid(capabilityID), (16...64).contains(nonce.count), payloadDigest.count == 32 else {
            throw NativeAgentSessionRegistryError.invalidInput
        }
        return try lock.withLock {
            var entry = try checkedEntry(sessionID: sessionID, connectionTokenIdentity: connectionTokenIdentity, binding: binding)
            guard entry.state == .active else { throw NativeAgentSessionRegistryError.sessionNotActive }
            do { _ = try entry.deadline.revalidate(wallClock: wallClock, monotonicClock: monotonicClock) }
            catch {
                entry.state = .expired; entries[sessionID] = entry
                throw NativeAgentSessionRegistryError.sessionNotActive
            }
            let identity = RequestIdentity(capabilityID: capabilityID.lowercased(), nonce: nonce, payloadDigest: payloadDigest)
            if let prior = entry.requests[requestID.lowercased()] {
                throw prior == identity ? NativeAgentSessionRegistryError.requestReplay : NativeAgentSessionRegistryError.requestConflict
            }
            guard !entry.consumedCapabilities.contains(identity.capabilityID) else { throw NativeAgentSessionRegistryError.capabilityReplay }
            guard !entry.consumedNonces.contains(nonce) else { throw NativeAgentSessionRegistryError.nonceReplay }
            guard entry.usedSignatures < entry.lease.maxSignatures else { throw NativeAgentSessionRegistryError.budgetExhausted }
            try Self.transition(&entry, to: .requestReserved)
            entry.usedSignatures += 1 // reserve before authorizer or key access
            entry.requests[requestID.lowercased()] = identity
            entry.consumedCapabilities.insert(identity.capabilityID)
            entry.consumedNonces.insert(nonce)
            let reservation = NativeAgentSessionReservation(sessionID: sessionID, requestID: requestID.lowercased(), capabilityID: identity.capabilityID, payloadDigest: payloadDigest, budgetSequence: entry.usedSignatures)
            entry.reservation = reservation
            entries[sessionID] = entry
            return reservation
        }
    }

    public func beginSigningIntent(_ reservation: NativeAgentSessionReservation) throws {
        try mutateReservation(reservation, required: .requestReserved, next: .signingIntent)
    }

    public func recordSigned(_ reservation: NativeAgentSessionReservation) throws {
        try mutateReservation(reservation, required: .signingIntent, next: .signed)
    }

    public func complete(_ reservation: NativeAgentSessionReservation) throws -> NativeAgentSessionRegistryStatus {
        try lock.withLock {
            var entry = try reservationEntry(reservation, required: .signed)
            let next: NativeAgentSessionState = entry.usedSignatures == entry.lease.maxSignatures ? .closed : .active
            try Self.transition(&entry, to: next)
            entry.reservation = nil
            entries[reservation.sessionID] = entry
            return Self.status(entry)
        }
    }

    /// Releases only a reservation that has not crossed the durable intent/key
    /// boundary. Replay identities remain consumed, but the budget is refunded.
    public func releaseBeforeKey(_ reservation: NativeAgentSessionReservation) throws {
        try lock.withLock {
            var entry = try reservationEntry(reservation, required: .requestReserved)
            try Self.transition(&entry, to: .active)
            entry.usedSignatures -= 1
            entry.reservation = nil
            entries[reservation.sessionID] = entry
        }
    }

    public func markOutcomeUnknown(_ reservation: NativeAgentSessionReservation) throws {
        try mutateReservation(reservation, required: .signingIntent, next: .outcomeUnknown, clear: true)
    }

    public func invalidate(sessionID: String, connectionTokenIdentity: String, as terminalState: NativeAgentSessionState) throws {
        guard Self.hash(connectionTokenIdentity), terminalState.isTerminal, terminalState != .outcomeUnknown else { throw NativeAgentSessionRegistryError.invalidInput }
        try lock.withLock {
            if let pending = pendingActivations[sessionID] {
                guard pending.entry.connectionTokenIdentity == connectionTokenIdentity else {
                    throw NativeAgentSessionRegistryError.connectionMismatch
                }
                pendingActivations.removeValue(forKey: sessionID)
                return
            }
            if let committed = committedActivations[sessionID] {
                guard committed.entry.connectionTokenIdentity == connectionTokenIdentity else {
                    throw NativeAgentSessionRegistryError.connectionMismatch
                }
                committedActivations.removeValue(forKey: sessionID)
                return
            }
            guard var entry = entries[sessionID] else { throw NativeAgentSessionRegistryError.sessionMissing }
            guard entry.connectionTokenIdentity == connectionTokenIdentity else { throw NativeAgentSessionRegistryError.connectionMismatch }
            if entry.state == terminalState { return }
            guard !entry.state.isTerminal else { throw NativeAgentSessionRegistryError.transitionDenied }
            try Self.transition(&entry, to: terminalState)
            entry.reservation = nil
            entries[sessionID] = entry
        }
    }

    @discardableResult
    public func invalidateOwned(by connectionTokenIdentity: String, as terminalState: NativeAgentSessionState = .revoked) -> [NativeAgentSessionRegistryStatus] {
        guard Self.hash(connectionTokenIdentity), terminalState.isTerminal, terminalState != .outcomeUnknown else { return [] }
        return lock.withLock {
            pendingActivations = pendingActivations.filter {
                $0.value.entry.connectionTokenIdentity != connectionTokenIdentity
            }
            committedActivations = committedActivations.filter {
                $0.value.entry.connectionTokenIdentity != connectionTokenIdentity
            }
            var statuses: [NativeAgentSessionRegistryStatus] = []
            for id in entries.keys.sorted() {
                guard var entry = entries[id], entry.connectionTokenIdentity == connectionTokenIdentity else { continue }
                if !entry.state.isTerminal, (try? Self.transition(&entry, to: terminalState)) != nil {
                    entry.reservation = nil
                    entries[id] = entry
                    statuses.append(Self.status(entry))
                }
            }
            return statuses
        }
    }

    public func close(sessionID: String, connectionTokenIdentity: String) throws -> NativeAgentSessionRegistryStatus {
        try lock.withLock {
            guard var entry = entries[sessionID] else { throw NativeAgentSessionRegistryError.sessionMissing }
            guard entry.connectionTokenIdentity == connectionTokenIdentity else { throw NativeAgentSessionRegistryError.connectionMismatch }
            if entry.state == .closed { return Self.status(entry) }
            guard !entry.state.isTerminal else { throw NativeAgentSessionRegistryError.transitionDenied }
            try Self.transition(&entry, to: .closed)
            entry.reservation = nil
            entries[sessionID] = entry
            return Self.status(entry)
        }
    }

    public func invalidateAll(as terminalState: NativeAgentSessionState = .revoked) {
        guard terminalState.isTerminal, terminalState != .outcomeUnknown else { return }
        lock.withLock {
            pendingActivations.removeAll(keepingCapacity: false)
            committedActivations.removeAll(keepingCapacity: false)
            for id in entries.keys {
                guard var entry = entries[id], !entry.state.isTerminal,
                      (try? Self.transition(&entry, to: terminalState)) != nil else { continue }
                entry.reservation = nil
                entries[id] = entry
            }
        }
    }

    private func mutateReservation(_ reservation: NativeAgentSessionReservation, required: NativeAgentSessionState, next: NativeAgentSessionState, clear: Bool = false) throws {
        try lock.withLock {
            var entry = try reservationEntry(reservation, required: required)
            try Self.transition(&entry, to: next)
            if clear { entry.reservation = nil }
            entries[reservation.sessionID] = entry
        }
    }

    private func checkedEntry(sessionID: String, connectionTokenIdentity: String, binding: NativeAgentSessionBinding) throws -> Entry {
        guard let entry = entries[sessionID] else { throw NativeAgentSessionRegistryError.sessionMissing }
        guard entry.connectionTokenIdentity == connectionTokenIdentity else { throw NativeAgentSessionRegistryError.connectionMismatch }
        guard entry.lease.binding == binding else { throw NativeAgentSessionRegistryError.bindingMismatch }
        return entry
    }

    private func reservationEntry(_ reservation: NativeAgentSessionReservation, required: NativeAgentSessionState) throws -> Entry {
        guard let entry = entries[reservation.sessionID] else { throw NativeAgentSessionRegistryError.sessionMissing }
        guard entry.state == required else { throw NativeAgentSessionRegistryError.transitionDenied }
        guard entry.reservation == reservation else { throw NativeAgentSessionRegistryError.reservationMismatch }
        return entry
    }

    private static func transition(_ entry: inout Entry, to next: NativeAgentSessionState) throws {
        do { try NativeAgentSessionTransitionValidator.validate(from: entry.state, to: next) }
        catch { throw NativeAgentSessionRegistryError.transitionDenied }
        entry.state = next
    }

    private static func status(_ entry: Entry) -> NativeAgentSessionRegistryStatus {
        NativeAgentSessionRegistryStatus(sessionID: entry.lease.sessionID, leaseID: entry.leaseID, state: entry.state, expiresAtMilliseconds: entry.lease.expiresAtMilliseconds, maxSignatures: entry.lease.maxSignatures, usedSignatures: entry.usedSignatures)
    }

    private func verifyDeadline(
        _ entry: inout Entry,
        wallClock: NativeAgentWallClockValue,
        monotonicClock: NativeAgentMonotonicClockValue
    ) throws {
        do {
            _ = try entry.deadline.revalidate(
                wallClock: wallClock,
                monotonicClock: monotonicClock
            )
        } catch {
            throw NativeAgentSessionRegistryError.deadlineMismatch
        }
    }

    private func pruneExpiredUnpublished(
        wallClock: NativeAgentWallClockValue,
        monotonicClock: NativeAgentMonotonicClockValue
    ) {
        pendingActivations = pruneExpired(
            pendingActivations,
            wallClock: wallClock,
            monotonicClock: monotonicClock
        )
        committedActivations = pruneExpired(
            committedActivations,
            wallClock: wallClock,
            monotonicClock: monotonicClock
        )
    }

    private func pruneExpired(
        _ activations: [String: PendingActivation],
        wallClock: NativeAgentWallClockValue,
        monotonicClock: NativeAgentMonotonicClockValue
    ) -> [String: PendingActivation] {
        var retained: [String: PendingActivation] = [:]
        retained.reserveCapacity(activations.count)
        for (sessionID, var activation) in activations {
            do {
                _ = try activation.entry.deadline.revalidate(
                    wallClock: wallClock,
                    monotonicClock: monotonicClock
                )
                retained[sessionID] = activation
            } catch NativeAgentSessionDeadlineError.wallClockExpired,
                    NativeAgentSessionDeadlineError.monotonicDeadlineExpired {
                // Expired unpublished authority is discarded before capacity
                // accounting or the requested state transition proceeds.
                continue
            } catch {
                // A non-expiry clock failure is left for the operation's exact
                // deadline verification to report; it is not silently treated
                // as an expired reservation.
                retained[sessionID] = activation
            }
        }
        return retained
    }

    private static func uuid(_ value: String) -> Bool { value.utf8.count == 36 && UUID(uuidString: value) != nil }
    private static func hash(_ value: String) -> Bool { value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil }
}
