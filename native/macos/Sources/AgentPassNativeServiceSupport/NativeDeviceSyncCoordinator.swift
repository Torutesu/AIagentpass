import AgentPassNativeCore
import CryptoKit
import Foundation

public protocol NativeDeviceSyncTransporting: Sendable {
    func pollRefresh(afterGeneration: Int64, waitMilliseconds: Int) async throws -> NativeDeviceSyncRefreshPollResponse
    func fetchBundle() async throws -> NativeDeviceSyncBundleFetchResponse
    func submitAcknowledgement(_ acknowledgement: NativeBundleAcknowledgement) async throws -> NativeDeviceSyncAcknowledgementResponse
}

extension NativeDeviceSyncHTTPTransport: NativeDeviceSyncTransporting {}

public protocol NativeDeviceSyncBundleInstalling: Sendable {
    func active() throws -> NativeAtomicControlBundleSnapshot?
    func install(descriptor: NativeAtomicControlBundleDescriptor, canonicalBytes: Data) throws -> NativeAtomicControlBundleSnapshot
}

extension NativeAtomicControlBundleStore: NativeDeviceSyncBundleInstalling {}

public protocol NativeDeviceSyncBundleActivating: Sendable {
    /// Must be exact-replay idempotent. A failure leaves the durable refresh
    /// state in `staging`, so restart retries activation instead of emitting a
    /// false blocked/applied acknowledgement.
    func activateVerifiedBundle(_ canonicalBundle: Data, nowMilliseconds: Int64) throws
}

public struct NativeDeviceSyncBundleActivation: NativeDeviceSyncBundleActivating, Sendable {
    private let body: @Sendable (Data, Int64) throws -> Void

    public init(_ body: @escaping @Sendable (Data, Int64) throws -> Void) {
        self.body = body
    }

    public func activateVerifiedBundle(_ canonicalBundle: Data, nowMilliseconds: Int64) throws {
        try body(canonicalBundle, nowMilliseconds)
    }
}

public enum NativeDeviceSyncCoordinatorError: Error, LocalizedError, Equatable, Sendable {
    case invalidConfiguration
    case transportUnavailable
    case generationChanged
    case verificationFailed
    case storageUnavailable
    case activationUnavailable
    case acknowledgementRejected
    case unrecoverableState
    case convergenceLimit

    public var errorDescription: String? { "device_sync_\(String(describing: self))" }
}

public enum NativeDeviceSyncRunResult: Equatable, Sendable {
    case noChange(generation: Int64)
    case applied(generation: Int64, sequence: Int64)
    case blocked(generation: Int64, sequence: Int64, reason: NativeBundleAcknowledgementReasonCode)
}

/// Serializes one complete G4.2 poll/fetch/verify/install/ACK cycle. Every
/// transition is persisted before the corresponding side effect begins. A
/// crash after a remote ACK, atomic pointer swap, or manager activation is
/// therefore repaired by an exact idempotent retry on the next invocation.
public actor NativeDeviceSyncCoordinator {
    private static let maximumConvergenceAttempts = 4

    public let organizationID: String
    public let deviceID: String
    public let deviceKeyEpoch: Int64

    private let transport: any NativeDeviceSyncTransporting
    private let hintVerifier: NativeRefreshHintVerifier
    private let bundleTrust: NativeControlBundleV2Trust
    private let snapshotStore: any NativeDeviceRefreshSnapshotStore
    private let bundleStore: any NativeDeviceSyncBundleInstalling
    private let activator: any NativeDeviceSyncBundleActivating
    private let acknowledgementSigner: any P256MessageSigner
    private let nowMilliseconds: @Sendable () -> Int64
    private var machine: NativeDeviceRefreshStateMachine
    private var inFlightSynchronization: Task<NativeDeviceSyncRunResult, Error>?

    public init(
        organizationID: String,
        deviceID: String,
        deviceKeyEpoch: Int64,
        transport: any NativeDeviceSyncTransporting,
        hintVerifier: NativeRefreshHintVerifier,
        bundleTrust: NativeControlBundleV2Trust,
        snapshotStore: any NativeDeviceRefreshSnapshotStore,
        bundleStore: any NativeDeviceSyncBundleInstalling,
        activator: any NativeDeviceSyncBundleActivating,
        acknowledgementSigner: any P256MessageSigner,
        nowMilliseconds: @escaping @Sendable () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1_000) }
    ) throws {
        guard deviceKeyEpoch > 0, deviceKeyEpoch <= 9_007_199_254_740_991,
              hintVerifier.trust.organizationID == organizationID.lowercased(),
              hintVerifier.trust.deviceID == deviceID.lowercased(),
              bundleTrust.audience?.organizationID.lowercased() == organizationID.lowercased(),
              bundleTrust.audience?.deviceID.lowercased() == deviceID.lowercased() else {
            throw NativeDeviceSyncCoordinatorError.invalidConfiguration
        }
        self.organizationID = organizationID.lowercased()
        self.deviceID = deviceID.lowercased()
        self.deviceKeyEpoch = deviceKeyEpoch
        self.transport = transport
        self.hintVerifier = hintVerifier
        self.bundleTrust = bundleTrust
        self.snapshotStore = snapshotStore
        self.bundleStore = bundleStore
        self.activator = activator
        self.acknowledgementSigner = acknowledgementSigner
        self.nowMilliseconds = nowMilliseconds
        self.machine = try NativeDeviceRefreshStateMachine.load(
            organizationID: organizationID,
            deviceID: deviceID,
            from: snapshotStore
        )
    }

    public func snapshot() -> NativeDeviceRefreshSnapshot { machine.snapshot }

    /// Accepts an optional push wake-up. It remains non-authoritative: only a
    /// later authenticated fetch and full ControlBundle verification can
    /// change the active authorization state.
    public func receiveRefreshHint(_ canonicalHint: Data) throws {
        let hint = try hintVerifier.verify(
            canonicalHint,
            afterGeneration: machine.binding.generation,
            nowMilliseconds: nowMilliseconds()
        )
        let binding = NativeDeviceRefreshBinding(
            organizationID: hint.organizationID,
            deviceID: hint.deviceID,
            generation: hint.authorityGeneration,
            refreshNonce: hint.nonce
        )
        _ = try machine.apply(.hint(binding), persistingTo: snapshotStore)
    }

    public func synchronize(waitMilliseconds: Int = 30_000) async throws -> NativeDeviceSyncRunResult {
        guard (0...NativeDeviceSyncHTTPTransport.maximumPollWaitMilliseconds).contains(waitMilliseconds) else {
            throw NativeDeviceSyncCoordinatorError.invalidConfiguration
        }

        // Actor isolation alone does not serialize across an `await`: another
        // caller can re-enter while a long poll or fetch is suspended. Share
        // one task for the complete cycle so manual, scheduled, and startup
        // callers cannot issue competing polls or mutate the durable machine
        // from interleaved responses.
        if let existing = inFlightSynchronization {
            return try await existing.value
        }
        let task = Task { [weak self] () throws -> NativeDeviceSyncRunResult in
            guard let self else { throw NativeDeviceSyncCoordinatorError.unrecoverableState }
            return try await self.performSynchronization(waitMilliseconds: waitMilliseconds)
        }
        inFlightSynchronization = task
        do {
            let result = try await withTaskCancellationHandler(
                operation: { try await task.value },
                onCancel: { task.cancel() }
            )
            inFlightSynchronization = nil
            return result
        } catch {
            inFlightSynchronization = nil
            throw error
        }
    }

    private func performSynchronization(waitMilliseconds: Int) async throws -> NativeDeviceSyncRunResult {

        for _ in 0..<Self.maximumConvergenceAttempts {
            if machine.state == .acknowledged {
                _ = try machine.apply(.resetForNextPoll, persistingTo: snapshotStore)
            }

            if machine.state == .idle || machine.state == .pollDue {
                if machine.state == .idle {
                    _ = try machine.apply(.pollDue, persistingTo: snapshotStore)
                }
                let response: NativeDeviceSyncRefreshPollResponse
                do {
                    response = try await transport.pollRefresh(
                        afterGeneration: machine.binding.generation,
                        waitMilliseconds: waitMilliseconds
                    )
                } catch {
                    throw NativeDeviceSyncCoordinatorError.transportUnavailable
                }
                guard let hint = response.hint else {
                    _ = try machine.apply(.pollCompletedNoChange, persistingTo: snapshotStore)
                    return .noChange(generation: machine.binding.generation)
                }
                do {
                    let canonical = try NativeRefreshHintCodec.canonicalJSON(hint)
                    let verified = try hintVerifier.verify(
                        canonical,
                        afterGeneration: machine.binding.generation,
                        nowMilliseconds: nowMilliseconds()
                    )
                    _ = try machine.apply(.hint(.init(
                        organizationID: verified.organizationID,
                        deviceID: verified.deviceID,
                        generation: verified.authorityGeneration,
                        refreshNonce: verified.nonce
                    )), persistingTo: snapshotStore)
                } catch {
                    throw NativeDeviceSyncCoordinatorError.verificationFailed
                }
            }

            if machine.state == .hinted {
                _ = try machine.apply(.fetchStarted, persistingTo: snapshotStore)
            }

            guard [.fetching, .verifying, .staging, .applied, .blocked].contains(machine.state) else {
                throw NativeDeviceSyncCoordinatorError.unrecoverableState
            }

            var canonicalBundle: Data?
            var verifiedBundle: NativeControlBundleV2Bundle?
            if [.fetching, .verifying, .staging].contains(machine.state) {
                let response: NativeDeviceSyncBundleFetchResponse
                do { response = try await transport.fetchBundle() }
                catch { throw NativeDeviceSyncCoordinatorError.transportUnavailable }

                guard response.desiredGeneration == machine.binding.generation else {
                    _ = try machine.apply(.refreshSuperseded, persistingTo: snapshotStore)
                    continue
                }

                do {
                    // Persist the exact fetched identity before signature
                    // verification. A rejected bundle must still be ACKed
                    // against the server-assigned sequence/hash/nonce, while
                    // these bytes remain unable to reach activation.
                    let fetchedStatementHash = try NativeControlBundleV2Codec.statementHash(response.bundle)
                    _ = try machine.apply(.fetched(.init(
                        organizationID: organizationID,
                        deviceID: deviceID,
                        generation: response.desiredGeneration,
                        sequence: response.bundle.sequence,
                        statementHash: fetchedStatementHash,
                        refreshNonce: machine.binding.refreshNonce
                    )), persistingTo: snapshotStore)
                    let sequenceState = NativeControlBundleV2SequenceState(
                        highestSequence: machine.sequenceWatermark,
                        statementHash: machine.binding.statementHash
                    )
                    let verified = try NativeControlBundleV2Codec.verify(
                        response.bundleData,
                        trust: bundleTrust,
                        options: .init(
                            nowMilliseconds: nowMilliseconds(),
                            audience: bundleTrust.audience,
                            sequenceState: sequenceState
                        )
                    )
                    let statementHash = try NativeControlBundleV2Codec.statementHash(verified)
                    guard statementHash == machine.binding.statementHash else {
                        throw NativeDeviceSyncCoordinatorError.verificationFailed
                    }
                    canonicalBundle = response.bundleData
                    verifiedBundle = verified
                } catch let error as NativeControlBundleV2Error {
                    let reason = Self.stateReason(error.reason)
                    _ = try machine.apply(.verificationBlocked(reason), persistingTo: snapshotStore)
                } catch {
                    throw NativeDeviceSyncCoordinatorError.verificationFailed
                }
            }

            if machine.state == .verifying {
                _ = try machine.apply(.verificationSucceeded, persistingTo: snapshotStore)
            }

            if machine.state == .staging {
                guard let bytes = canonicalBundle,
                      let bundle = verifiedBundle,
                      let statementHash = machine.binding.statementHash else {
                    throw NativeDeviceSyncCoordinatorError.unrecoverableState
                }
                do {
                    // Time can advance while the bundle is fetched, verified,
                    // and durably staged. Revalidate at the exact activation
                    // instant so a bundle that expires in that window is
                    // never published as active. The same timestamp is passed
                    // through to the manager activation transaction.
                    let activationNow = nowMilliseconds()
                    let activationState = NativeControlBundleV2SequenceState(
                        highestSequence: machine.sequenceWatermark,
                        statementHash: statementHash
                    )
                    _ = try NativeControlBundleV2Codec.verify(
                        bytes,
                        trust: bundleTrust,
                        options: .init(
                            nowMilliseconds: activationNow,
                            audience: bundleTrust.audience,
                            sequenceState: activationState
                        )
                    )
                    let contentHash = Data(SHA256.hash(data: bytes)).map { String(format: "%02x", $0) }.joined()
                    let descriptor = try NativeAtomicControlBundleDescriptor(
                        generation: machine.binding.generation,
                        sequence: bundle.sequence,
                        statementHash: statementHash,
                        contentHash: contentHash
                    )
                    do {
                        _ = try bundleStore.install(descriptor: descriptor, canonicalBytes: bytes)
                    } catch {
                        throw NativeDeviceSyncCoordinatorError.storageUnavailable
                    }
                    do {
                        try activator.activateVerifiedBundle(bytes, nowMilliseconds: activationNow)
                    } catch {
                        throw NativeDeviceSyncCoordinatorError.activationUnavailable
                    }
                    // Activation may include durable manager state, audit, and
                    // session revocation. If time crosses the expiry boundary
                    // before that transaction returns, authorization is
                    // already fail-closed in the manager and the Cloud must
                    // observe a blocked—not applied—result.
                    _ = try NativeControlBundleV2Codec.verify(
                        bytes,
                        trust: bundleTrust,
                        options: .init(
                            nowMilliseconds: nowMilliseconds(),
                            audience: bundleTrust.audience,
                            sequenceState: activationState
                        )
                    )
                    _ = try machine.apply(.stagingSucceeded, persistingTo: snapshotStore)
                } catch let error as NativeControlBundleV2Error {
                    _ = try machine.apply(.stagingBlocked(Self.stateReason(error.reason)), persistingTo: snapshotStore)
                }
            }

            if machine.state == .applied || machine.state == .blocked {
                return try await acknowledgeCurrentResult()
            }
        }
        throw NativeDeviceSyncCoordinatorError.convergenceLimit
    }

    private func acknowledgeCurrentResult() async throws -> NativeDeviceSyncRunResult {
        guard let sequence = machine.binding.sequence,
              let statementHash = machine.binding.statementHash,
              let nonce = machine.binding.refreshNonce else {
            throw NativeDeviceSyncCoordinatorError.unrecoverableState
        }
        let result: NativeBundleAcknowledgementResult = machine.state == .applied ? .applied : .blocked
        let reason = result == .blocked ? Self.ackReason(machine.blockedReason) : nil
        let acknowledgement = try NativeBundleAcknowledgementSigner.create(
            organizationID: organizationID,
            deviceID: deviceID,
            deviceKeyEpoch: deviceKeyEpoch,
            sequence: sequence,
            statementHash: statementHash,
            result: result,
            reasonCode: reason,
            observedAtMilliseconds: nowMilliseconds(),
            nonce: nonce,
            signer: acknowledgementSigner
        )
        let response: NativeDeviceSyncAcknowledgementResponse
        do { response = try await transport.submitAcknowledgement(acknowledgement) }
        catch { throw NativeDeviceSyncCoordinatorError.transportUnavailable }
        let expectedState: NativeDeviceRefreshState = result == .applied ? .applied : .blocked
        guard response.accepted, response.observedGeneration == machine.binding.generation,
              response.refreshState == expectedState else {
            throw NativeDeviceSyncCoordinatorError.acknowledgementRejected
        }
        let generation = machine.binding.generation
        _ = try machine.apply(.acknowledgementDurablyRecorded, persistingTo: snapshotStore)
        _ = try machine.apply(.resetForNextPoll, persistingTo: snapshotStore)
        if let reason { return .blocked(generation: generation, sequence: sequence, reason: reason) }
        return .applied(generation: generation, sequence: sequence)
    }

    private static func stateReason(_ reason: NativeControlBundleV2Reason) -> NativeDeviceRefreshStateMachineReasonCode {
        switch reason {
        case .expired, .offlineTTLExpired: return .bundleExpired
        case .issuedInFuture: return .bundleNotYetValid
        case .keyIDNotTrusted, .issuerNotTrusted, .issuerKeyMismatch: return .bundleSignerUntrusted
        case .invalidSignature, .invalidSignatureEncoding: return .bundleSignatureInvalid
        case .audienceMismatch, .invalidAudience, .organizationMismatch: return .bundleAudienceMismatch
        case .sequenceRollback: return .sequenceRollback
        case .sequenceConflict, .sequenceEvidenceRequired: return .sequenceConflict
        case .deviceRevoked: return .deviceRevoked
        case .globalRevoked: return .emergencyStop
        default: return .verificationFailed
        }
    }

    private static func ackReason(_ reason: NativeDeviceRefreshStateMachineReasonCode?) -> NativeBundleAcknowledgementReasonCode {
        switch reason {
        case .bundleExpired: return .bundleExpired
        case .bundleNotYetValid: return .bundleNotYetValid
        case .bundleSignatureInvalid: return .bundleSignatureInvalid
        case .bundleSignerUntrusted: return .bundleSignerUntrusted
        case .bundleAudienceMismatch, .audienceMismatch: return .bundleAudienceMismatch
        case .sequenceRollback: return .bundleSequenceRollback
        case .sequenceConflict, .statementHashConflict: return .bundleSequenceConflict
        case .bundleStorageFailed, .stagingFailed: return .bundleStorageFailed
        case .deviceRevoked: return .deviceRevoked
        case .emergencyStop: return .emergencyStop
        default: return .internalError
        }
    }
}
