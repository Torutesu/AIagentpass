import Foundation

/// Stable failures for the Core-only signing coordinator adapter.
///
/// The adapter deliberately does not expose the underlying coordinator or
/// transaction-store errors. In particular, a missing or substituted handoff
/// is never turned into a caller-controlled authority error.
public enum NativeAgentSessionCoordinatorSigningAdapterError: String, Error, Equatable, Sendable {
    case authorityUnavailable = "authority_unavailable"
    case invalidHandoff = "invalid_handoff"
    case sessionUnavailable = "session_unavailable"
    case transactionConflict = "transaction_conflict"
    case transactionUnavailable = "transaction_unavailable"
    case budgetExhausted = "budget_exhausted"
    case invalidTransition = "invalid_transition"
    case outcomeUnknown = "outcome_unknown"
}

/// A service-issued, opaque signing handoff.
///
/// This is intentionally a class with no public fields or public initializer.
/// The only public issuance path requires the already-typed Core request,
/// binding, verified Cloud lease, and complete transaction authority. A Host or
/// Child payload can therefore be used as the bytes-to-sign identity only after
/// the service has supplied all of those independent authority values; it
/// cannot synthesize a handoff from its own DTO.
public final class NativeAgentSessionCoordinatorSigningHandoff: @unchecked Sendable {
    private let request: AgentPassAgentSignRequest
    private let transactionRequest: NativeSigningTransactionRequest
    private let binding: NativeAgentSessionBinding
    private let lease: NativeAgentVerifiedCloudLease
    private let authority: NativeSigningTransactionAuthority

    private init(
        request: AgentPassAgentSignRequest,
        transactionRequest: NativeSigningTransactionRequest,
        binding: NativeAgentSessionBinding,
        lease: NativeAgentVerifiedCloudLease,
        authority: NativeSigningTransactionAuthority
    ) {
        self.request = request
        self.transactionRequest = transactionRequest
        self.binding = binding
        self.lease = lease
        self.authority = authority
    }

    /// Issues one handoff from service-owned, already-verified Core values.
    ///
    /// `request` is retained only so the existing coordinator can perform its
    /// live-session reservation. It is not trusted for authority: every
    /// session, capability, lease, and process/worktree binding is compared
    /// against the supplied service-owned projections below.
    public static func issue(
        request: AgentPassAgentSignRequest,
        binding: NativeAgentSessionBinding,
        lease: NativeAgentVerifiedCloudLease,
        authority: NativeSigningTransactionAuthority
    ) throws -> Self {
        let transactionRequest: NativeSigningTransactionRequest
        do {
            transactionRequest = try NativeSigningTransactionRequest(request)
        } catch {
            throw NativeAgentSessionCoordinatorSigningAdapterError.invalidHandoff
        }

        guard lease.binding == binding,
              lease.sessionID == transactionRequest.sessionID,
              lease.agentID == binding.agentID,
              lease.deviceID == binding.deviceID,
              lease.processBindingSHA256 == Self.hex(binding.processBindingDigest),
              lease.ancestryBindingSHA256 == Self.hex(binding.ancestryBindingDigest),
              lease.worktreeBindingSHA256 == Self.hex(binding.worktreeBindingDigest),
              lease.controlSequence == binding.controlSequence,
              lease.authorityGeneration == binding.authorityGeneration,
              lease.usedSignatures <= lease.maxSignatures,
              authority.sessionID == transactionRequest.sessionID,
              authority.agentID == binding.agentID,
              authority.capabilityID == transactionRequest.capabilityID,
              authority.processBindingHash == Self.hex(binding.processBindingDigest),
              authority.ancestryBindingHash == Self.hex(binding.ancestryBindingDigest),
              authority.worktreeBindingHash == Self.hex(binding.worktreeBindingDigest),
              authority.controlSequence == binding.controlSequence,
              authority.authorityGeneration == binding.authorityGeneration,
              authority.keyGeneration == binding.keyGeneration,
              authority.repositoryIdentityHash.count == 64,
              authority.branchPolicyHash.count == 64,
              authority.remotePolicyHash.count == 64,
              authority.keyLifecycleIdentity.count == 64 else {
            throw NativeAgentSessionCoordinatorSigningAdapterError.invalidHandoff
        }

        return Self(
            request: request,
            transactionRequest: transactionRequest,
            binding: binding,
            lease: lease,
            authority: authority)
    }

    fileprivate var signingRequest: AgentPassAgentSignRequest { request }
    fileprivate var transactionIdentity: NativeSigningTransactionRequest { transactionRequest }
    fileprivate var sessionBinding: NativeAgentSessionBinding { binding }
    fileprivate var verifiedLease: NativeAgentVerifiedCloudLease { lease }
    fileprivate var transactionAuthority: NativeSigningTransactionAuthority { authority }

    private static func hex(_ value: Data) -> String {
        value.map { String(format: "%02x", $0) }.joined()
    }
}

/// The small state surface exposed by the adapter. The state is local to this
/// one handoff and is never an authority source; the coordinator and durable
/// transaction store remain authoritative.
public enum NativeAgentSessionCoordinatorSigningAdapterPhase: String, Equatable, Sendable {
    case ready
    case reserved
    case intent
    case providerStarted
    case recorded
    case finalized
    case released
    case unknown
}

/// Core-only orchestration for one service-issued signing handoff.
///
/// There is exactly one budget: the atomic budget in
/// `NativeAgentSessionRegistry`, reached through `NativeAgentSessionCoordinator`.
/// The transaction store records the same reservation's sequence; it does not
/// maintain or replenish a second budget.
public final class NativeAgentSessionCoordinatorSigningAdapter: @unchecked Sendable {
    private let handoff: NativeAgentSessionCoordinatorSigningHandoff
    private let coordinator: NativeAgentSessionCoordinator
    private let transactions: NativeSigningTransactionStore
    private let operationLock = NSLock()
    private let lock = NSLock()
    private var phase: NativeAgentSessionCoordinatorSigningAdapterPhase = .ready
    private var reservation: NativeAgentSessionReservation?
    private var record: NativeSigningTransactionRecord?

    public init(
        handoff: NativeAgentSessionCoordinatorSigningHandoff?,
        coordinator: NativeAgentSessionCoordinator,
        transactionStore: NativeSigningTransactionStore
    ) throws {
        guard let handoff else {
            throw NativeAgentSessionCoordinatorSigningAdapterError.authorityUnavailable
        }
        self.handoff = handoff
        self.coordinator = coordinator
        self.transactions = transactionStore
    }

    public var currentPhase: NativeAgentSessionCoordinatorSigningAdapterPhase {
        lock.withLock { phase }
    }

    /// Reserves one signature in the coordinator's atomic session budget and
    /// durably admits the exact transaction with the same budget sequence.
    @discardableResult
    public func reserve() throws -> NativeAgentSessionReservation {
        try operationLock.withLock {
            try reserveLocked()
        }
    }

    private func reserveLocked() throws -> NativeAgentSessionReservation {
        try lock.withLock {
            guard phase == .ready else { throw Self.transitionError() }

            let identity = handoff.transactionIdentity
            if let existing = try lookupExisting(identity) {
                _ = existing
                throw NativeAgentSessionCoordinatorSigningAdapterError.transactionConflict
            }

            try verifyLiveLeaseBeforeReserve()

            let reserved: (NativeAgentSessionReservation, NativeAgentSessionBinding)
            do {
                reserved = try coordinator.reserveSigningRequest(handoff.signingRequest)
            } catch {
                throw Self.mapCoordinator(error)
            }
            let (reservation, binding) = reserved
            guard binding == handoff.sessionBinding else {
                try? coordinator.releaseSigningBeforeKey(reservation)
                throw NativeAgentSessionCoordinatorSigningAdapterError.invalidHandoff
            }

            do {
                record = try transactions.admit(
                    request: identity,
                    authority: handoff.transactionAuthority,
                    budgetSequence: reservation.budgetSequence)
            } catch {
                try? coordinator.releaseSigningBeforeKey(reservation)
                throw Self.mapTransaction(error)
            }

            self.reservation = reservation
            phase = .reserved
            return reservation
        }
    }

    /// Crosses the durable signing-intent boundary. No provider invocation is
    /// allowed before this method succeeds.
    @discardableResult
    public func begin() throws -> NativeSigningTransactionRecord {
        try operationLock.withLock {
            try beginLocked()
        }
    }

    private func beginLocked() throws -> NativeSigningTransactionRecord {
        try lock.withLock {
            guard phase == .reserved, let reservation else {
                throw Self.transitionError()
            }

            let binding: NativeAgentSessionBinding
            do {
                binding = try coordinator.beginSigningIntent(reservation)
            } catch {
                failBeforeProvider(reservation: reservation)
                throw Self.mapCoordinator(error)
            }
            guard binding == handoff.sessionBinding else {
                failAfterProvider(reservation: reservation)
                throw NativeAgentSessionCoordinatorSigningAdapterError.invalidHandoff
            }

            do {
                record = try transactions.markIntent(
                    requestID: handoff.transactionIdentity.requestID,
                    authority: handoff.transactionAuthority)
            } catch {
                failAfterProvider(reservation: reservation)
                throw Self.mapTransaction(error)
            }
            phase = .intent
            return record!
        }
    }

    /// Runs one complete signing transaction. The provider receives only the
    /// already-bound commit payload and returns only signature bytes; all
    /// session, budget, binding, lease, and transaction authority remains
    /// inside this adapter and its Core dependencies.
    ///
    /// `provider_started` is persisted before the closure is invoked. Once the
    /// closure has been entered, every provider error or invalid result is
    /// terminalized as outcome-unknown: the reservation is never released and
    /// the provider is never retried.
    @discardableResult
    public func execute(
        provider: @escaping @Sendable (Data) throws -> Data
    ) throws -> NativeSigningTransactionRecord {
        try operationLock.withLock {
            _ = try reserveLocked()
            _ = try beginLocked()
            _ = try markProviderStartedLocked()

            let signature: Data
            do {
                signature = try provider(handoff.signingRequest.commitPayload)
            } catch {
                terminalizeProviderFailure()
                throw NativeAgentSessionCoordinatorSigningAdapterError.outcomeUnknown
            }

            do {
                _ = try recordLocked(signature: signature)
            } catch {
                // The provider boundary has already been crossed. Never
                // release or expose a retryable transaction after this point.
                terminalizeProviderFailure()
                throw NativeAgentSessionCoordinatorSigningAdapterError.outcomeUnknown
            }

            do {
                _ = try finalizeLocked()
            } catch {
                // Finalization failure after provider invocation is also
                // ambiguous to the caller, even if Core did consume the
                // reservation before the failure was observed.
                throw NativeAgentSessionCoordinatorSigningAdapterError.outcomeUnknown
            }
            return record!
        }
    }

    @discardableResult
    private func markProviderStartedLocked() throws -> NativeSigningTransactionRecord {
        try lock.withLock {
            guard phase == .intent, let reservation else {
                throw Self.transitionError()
            }
            do {
                record = try transactions.markProviderStarted(
                    requestID: handoff.transactionIdentity.requestID)
            } catch {
                failAfterProvider(reservation: reservation)
                throw Self.mapTransaction(error)
            }
            phase = .providerStarted
            return record!
        }
    }

    /// Records the provider's already-verified UTF-8 signature, then mirrors
    /// that transition into the coordinator's in-memory session state.
    @discardableResult
    public func record(signature: Data) throws -> NativeSigningTransactionRecord {
        try operationLock.withLock {
            try recordLocked(signature: signature)
        }
    }

    private func recordLocked(signature: Data) throws -> NativeSigningTransactionRecord {
        try lock.withLock {
            guard (phase == .intent || phase == .providerStarted), let reservation else {
                throw Self.transitionError()
            }

            // Keep the split Core API source-compatible, but the complete
            // execute(provider:) path marks this phase before entering the
            // provider. A caller using record() directly has already crossed
            // the provider boundary and is treated conservatively.
            if phase == .intent {
                do {
                    record = try transactions.markProviderStarted(
                        requestID: handoff.transactionIdentity.requestID)
                } catch {
                    failAfterProvider(reservation: reservation)
                    throw Self.mapTransaction(error)
                }
                phase = .providerStarted
            }

            guard !signature.isEmpty,
                  signature.count <= AgentPassAgentSignResponse.maximumSignatureBytes,
                  let text = String(data: signature, encoding: .utf8), !text.isEmpty else {
                failAfterProvider(reservation: reservation)
                throw NativeAgentSessionCoordinatorSigningAdapterError.transactionUnavailable
            }

            do {
                record = try transactions.recordVerified(
                    requestID: handoff.transactionIdentity.requestID,
                    signature: text)
            } catch {
                failAfterProvider(reservation: reservation)
                throw Self.mapTransaction(error)
            }

            do {
                try coordinator.recordSigning(reservation)
            } catch {
                _ = try? transactions.markUncertain(
                    requestID: handoff.transactionIdentity.requestID)
                _ = try? coordinator.markSigningOutcomeUnknown(reservation)
                phase = .unknown
                throw Self.mapCoordinator(error)
            }
            phase = .recorded
            return record!
        }
    }

    /// Finalizes the exact reservation and records the consumed budget left by
    /// the coordinator. A transaction-store failure after coordinator
    /// finalization is terminalized as uncertain and is never retried as a new
    /// signature.
    @discardableResult
    public func finalize() throws -> NativeAgentSessionRegistryStatus {
        try operationLock.withLock {
            try finalizeLocked()
        }
    }

    @discardableResult
    private func finalizeLocked() throws -> NativeAgentSessionRegistryStatus {
        try lock.withLock {
            guard phase == .recorded, let reservation else {
                throw Self.transitionError()
            }

            let status: NativeAgentSessionRegistryStatus
            do {
                status = try coordinator.finalizeSigning(reservation)
            } catch {
                _ = try? transactions.markUncertain(
                    requestID: handoff.transactionIdentity.requestID)
                phase = .unknown
                throw Self.mapCoordinator(error)
            }

            do {
                record = try transactions.complete(
                    requestID: handoff.transactionIdentity.requestID,
                    remainingSignatures: status.remainingSignatures)
            } catch {
                _ = try? transactions.markUncertain(
                    requestID: handoff.transactionIdentity.requestID)
                phase = .unknown
                throw Self.mapTransaction(error)
            }
            phase = .finalized
            return status
        }
    }

    /// Releases only a reservation which has not crossed the durable intent
    /// boundary. Replay identities remain in the transaction store as
    /// uncertain; the coordinator may refund this one pre-provider budget
    /// reservation atomically.
    @discardableResult
    public func release() throws -> NativeSigningTransactionRecord {
        try operationLock.withLock {
            try releaseLocked()
        }
    }

    @discardableResult
    private func releaseLocked() throws -> NativeSigningTransactionRecord {
        try lock.withLock {
            guard phase == .reserved, let reservation else {
                throw Self.transitionError()
            }
            do {
                record = try transactions.markUncertain(
                    requestID: handoff.transactionIdentity.requestID)
            } catch {
                phase = .unknown
                throw Self.mapTransaction(error)
            }
            do {
                try coordinator.releaseSigningBeforeKey(reservation)
            } catch {
                phase = .unknown
                throw Self.mapCoordinator(error)
            }
            phase = .released
            return record!
        }
    }

    /// Terminalizes an ambiguous provider boundary. Before a signature is
    /// recorded, the coordinator's outcome-unknown transition is used. After
    /// a signature is recorded, finalization consumes the already-reserved
    /// budget before the durable record is marked uncertain.
    @discardableResult
    public func unknown() throws -> NativeSigningTransactionRecord {
        try operationLock.withLock {
            try unknownLocked()
        }
    }

    @discardableResult
    private func unknownLocked() throws -> NativeSigningTransactionRecord {
        try lock.withLock {
            guard (phase == .intent || phase == .providerStarted || phase == .recorded), let reservation else {
                throw Self.transitionError()
            }

            if phase == .recorded {
                do {
                    _ = try coordinator.finalizeSigning(reservation)
                } catch {
                    _ = try? transactions.markUncertain(
                        requestID: handoff.transactionIdentity.requestID)
                    phase = .unknown
                    throw Self.mapCoordinator(error)
                }
            } else {
                do {
                    try coordinator.markSigningOutcomeUnknown(reservation)
                } catch {
                    _ = try? transactions.markUncertain(
                        requestID: handoff.transactionIdentity.requestID)
                    phase = .unknown
                    throw Self.mapCoordinator(error)
                }
            }

            do {
                record = try transactions.markUncertain(
                    requestID: handoff.transactionIdentity.requestID)
            } catch {
                phase = .unknown
                throw Self.mapTransaction(error)
            }
            phase = .unknown
            return record!
        }
    }

    public var transactionRecord: NativeSigningTransactionRecord? {
        lock.withLock { record }
    }

    private func lookupExisting(
        _ identity: NativeSigningTransactionRequest
    ) throws -> NativeSigningTransactionRecord? {
        do {
            return try transactions.lookup(request: identity)
        } catch {
            throw Self.mapTransaction(error)
        }
    }

    private func verifyLiveLeaseBeforeReserve() throws {
        let status: NativeAgentSessionRegistryStatus
        do {
            status = try coordinator.status(sessionID: handoff.transactionIdentity.sessionID)
        } catch {
            throw NativeAgentSessionCoordinatorSigningAdapterError.sessionUnavailable
        }
        guard status.state == .active,
              status.sessionID == handoff.verifiedLease.sessionID,
              status.expiresAtMilliseconds == handoff.verifiedLease.expiresAtMilliseconds,
              status.maxSignatures == handoff.verifiedLease.maxSignatures,
              status.usedSignatures == handoff.verifiedLease.usedSignatures else {
            if status.usedSignatures >= status.maxSignatures {
                throw NativeAgentSessionCoordinatorSigningAdapterError.budgetExhausted
            }
            throw NativeAgentSessionCoordinatorSigningAdapterError.invalidHandoff
        }
    }

    private func failBeforeProvider(reservation: NativeAgentSessionReservation) {
        _ = try? transactions.markUncertain(
            requestID: handoff.transactionIdentity.requestID)
        do {
            try coordinator.releaseSigningBeforeKey(reservation)
            phase = .released
        } catch {
            // If the intent boundary was crossed despite the failure being
            // observed before the closure could run, never claim that the
            // budget was released. Preserve the reservation as unknown.
            _ = try? coordinator.markSigningOutcomeUnknown(reservation)
            phase = .unknown
        }
    }

    private func failAfterProvider(reservation: NativeAgentSessionReservation) {
        _ = try? transactions.markUncertain(
            requestID: handoff.transactionIdentity.requestID)
        _ = try? coordinator.markSigningOutcomeUnknown(reservation)
        phase = .unknown
    }

    private func terminalizeProviderFailure() {
        lock.withLock {
            guard phase == .providerStarted, let reservation else { return }
            failAfterProvider(reservation: reservation)
        }
    }

    private static func transitionError() -> NativeAgentSessionCoordinatorSigningAdapterError {
        .invalidTransition
    }

    private static func mapTransaction(
        _ error: Error
    ) -> NativeAgentSessionCoordinatorSigningAdapterError {
        if let error = error as? NativeSigningTransactionError {
            switch error {
            case .capacityExceeded:
                return .transactionUnavailable
            case .requestConflict, .authorityConflict, .phaseConflict:
                return .transactionConflict
            case .invalidPath, .invalidRequest, .invalidAuthority, .invalidState, .uncertain:
                return .transactionUnavailable
            }
        }
        return .transactionUnavailable
    }

    private static func mapCoordinator(
        _ error: Error
    ) -> NativeAgentSessionCoordinatorSigningAdapterError {
        if let error = error as? NativeAgentSessionCoordinatorError {
            switch error {
            case .sessionDenied, .bindingDenied, .leaseDenied, .connectionDenied, .invalidated:
                return .sessionUnavailable
            case .activationDenied, .grantDenied, .challengeDenied, .auditUnavailable,
                 .invalidConfiguration, .invalidInput:
                return .transactionUnavailable
            }
        }
        if let error = error as? NativeAgentSessionRegistryError,
           error == .budgetExhausted {
            return .budgetExhausted
        }
        return .transactionUnavailable
    }
}

public typealias NativeAgentSigningCoordinatorAdapter =
    NativeAgentSessionCoordinatorSigningAdapter
public typealias NativeAgentSigningCoordinatorHandoff =
    NativeAgentSessionCoordinatorSigningHandoff
