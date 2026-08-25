import CoreFoundation
import Darwin
import Foundation

/// The durable refresh lifecycle. `pollDue` is deliberately distinct from
/// `hinted`: a hint is an untrusted wake-up observation, while `pollDue` is an
/// internal decision that authorizes a network poll. Neither state contains
/// policy or secret material.
public enum NativeDeviceRefreshMachineState: String, CaseIterable, Codable, Sendable {
    case idle
    case hinted
    case pollDue = "poll_due"
    case fetching
    case verifying
    case staging
    case applied
    case blocked
    case acknowledged
}

public typealias NativeDurableRefreshState = NativeDeviceRefreshMachineState

/// Fixed, serializable failure classes. The values are intentionally a closed
/// set so callers cannot accidentally persist attacker-controlled diagnostics.
public enum NativeDeviceRefreshStateMachineReasonCode: String, CaseIterable, Codable, Sendable {
    case invalidBinding = "invalid_binding"
    case invalidSnapshot = "invalid_snapshot"
    case noncanonicalSnapshot = "noncanonical_snapshot"
    case snapshotLoadFailed = "snapshot_load_failed"
    case snapshotSaveFailed = "snapshot_save_failed"
    case illegalTransition = "illegal_transition"
    case audienceMismatch = "audience_mismatch"
    case generationRollback = "generation_rollback"
    case generationConflict = "generation_conflict"
    case sequenceRollback = "sequence_rollback"
    case sequenceConflict = "sequence_conflict"
    case statementHashConflict = "statement_hash_conflict"
    case conflictingReplay = "conflicting_replay"
    case blockedReasonConflict = "blocked_reason_conflict"
    case verificationFailed = "verification_failed"
    case stagingFailed = "staging_failed"
    case bundleExpired = "bundle_expired"
    case bundleNotYetValid = "bundle_not_yet_valid"
    case bundleSignatureInvalid = "bundle_signature_invalid"
    case bundleSignerUntrusted = "bundle_signer_untrusted"
    case bundleAudienceMismatch = "bundle_audience_mismatch"
    case bundleStorageFailed = "bundle_storage_failed"
    case deviceRevoked = "device_revoked"
    case emergencyStop = "emergency_stop"
}

public struct NativeDeviceRefreshStateMachineError: LocalizedError, Equatable, Sendable {
    public let reasonCode: NativeDeviceRefreshStateMachineReasonCode
    public let isFailClosed: Bool

    public init(_ reasonCode: NativeDeviceRefreshStateMachineReasonCode, failClosed: Bool = false) {
        self.reasonCode = reasonCode
        self.isFailClosed = failClosed
    }

    /// Never include input values, hashes, identifiers, or storage errors in a
    /// user-visible description. The bounded code is sufficient for telemetry.
    public var errorDescription: String? { reasonCode.rawValue }
}

/// The identity carried through one refresh cycle. `sequence` and
/// `statementHash` are both absent before a bundle is received and are both
/// present thereafter. The refresh nonce is durably retained only until its
/// applied/blocked acknowledgement is accepted, so a crash cannot make the
/// exact ACK impossible to reconstruct. No bundle bytes, signature, policy,
/// or capability is persisted here.
public struct NativeDeviceRefreshBinding: Codable, Equatable, Sendable {
    public let organizationID: String
    public let deviceID: String
    public let generation: Int64
    public let sequence: Int64?
    public let statementHash: String?
    public let refreshNonce: String?

    public var authorityGeneration: Int64 { generation }

    public init(
        organizationID: String,
        deviceID: String,
        generation: Int64,
        sequence: Int64? = nil,
        statementHash: String? = nil,
        refreshNonce: String? = nil
    ) {
        self.organizationID = organizationID
        self.deviceID = deviceID
        self.generation = generation
        self.sequence = sequence
        self.statementHash = statementHash
        self.refreshNonce = refreshNonce
    }

    public init(
        organizationID: String,
        deviceID: String,
        authorityGeneration: Int64,
        sequence: Int64? = nil,
        statementHash: String? = nil,
        refreshNonce: String? = nil
    ) {
        self.init(
            organizationID: organizationID,
            deviceID: deviceID,
            generation: authorityGeneration,
            sequence: sequence,
            statementHash: statementHash,
            refreshNonce: refreshNonce
        )
    }

    public func withBundle(sequence: Int64, statementHash: String) -> Self {
        Self(
            organizationID: organizationID,
            deviceID: deviceID,
            generation: generation,
            sequence: sequence,
            statementHash: statementHash,
            refreshNonce: refreshNonce
        )
    }
}

/// Closed event vocabulary for the state machine. Every event is bounded and
/// contains no arbitrary diagnostic string.
public enum NativeDeviceRefreshEvent: Equatable, Sendable {
    case hint(NativeDeviceRefreshBinding)
    case pollDue
    case pollCompletedNoChange
    case fetchStarted
    case fetched(NativeDeviceRefreshBinding)
    case verificationSucceeded
    case verificationBlocked(NativeDeviceRefreshStateMachineReasonCode)
    case stagingSucceeded
    case stagingBlocked(NativeDeviceRefreshStateMachineReasonCode)
    case acknowledgementDurablyRecorded
    case refreshSuperseded
    case resetForNextPoll
}

public enum NativeDeviceRefreshTransitionResult: Equatable, Sendable {
    case changed(NativeDeviceRefreshSnapshot)
    case duplicate(NativeDeviceRefreshSnapshot)
}

/// A closed-schema durable representation. The `sequenceWatermark` survives
/// cycle resets so a restarted device cannot accept an older bundle sequence.
public struct NativeDeviceRefreshSnapshot: Codable, Equatable, Sendable {
    public static let version = 1

    public let version: Int
    public let state: NativeDeviceRefreshMachineState
    public let organizationID: String
    public let deviceID: String
    public let generation: Int64
    public let sequence: Int64?
    public let statementHash: String?
    public let refreshNonce: String?
    public let sequenceWatermark: Int64
    public let blockedReason: NativeDeviceRefreshStateMachineReasonCode?
    public let revision: Int64

    public var binding: NativeDeviceRefreshBinding {
        NativeDeviceRefreshBinding(
            organizationID: organizationID,
            deviceID: deviceID,
            generation: generation,
            sequence: sequence,
            statementHash: statementHash,
            refreshNonce: refreshNonce
        )
    }

    public init(
        version: Int = NativeDeviceRefreshSnapshot.version,
        state: NativeDeviceRefreshMachineState,
        organizationID: String,
        deviceID: String,
        generation: Int64,
        sequence: Int64? = nil,
        statementHash: String? = nil,
        refreshNonce: String? = nil,
        sequenceWatermark: Int64 = 0,
        blockedReason: NativeDeviceRefreshStateMachineReasonCode? = nil,
        revision: Int64 = 0
    ) {
        self.version = version
        self.state = state
        self.organizationID = organizationID
        self.deviceID = deviceID
        self.generation = generation
        self.sequence = sequence
        self.statementHash = statementHash
        self.refreshNonce = refreshNonce
        self.sequenceWatermark = sequenceWatermark
        self.blockedReason = blockedReason
        self.revision = revision
    }
}

/// The persistence boundary is deliberately an abstraction. Implementations
/// outside this pure core are responsible for atomic replacement, fsync, and
/// permissions; this component only supplies and validates canonical bytes.
public protocol NativeDeviceRefreshSnapshotStore: Sendable {
    func load() throws -> Data?
    func save(_ canonicalSnapshot: Data) throws
}

public enum NativeDeviceRefreshSnapshotCodec {
    public static let maximumBytes = 8 * 1024
    private static let keys: Set<String> = [
        "version", "state", "organization_id", "device_id", "generation",
        "sequence", "statement_hash", "refresh_nonce", "sequence_watermark", "blocked_reason", "revision"
    ]

    public static func encode(_ snapshot: NativeDeviceRefreshSnapshot) throws -> Data {
        try validate(snapshot)
        let object: [String: Any] = [
            "version": snapshot.version,
            "state": snapshot.state.rawValue,
            "organization_id": snapshot.organizationID,
            "device_id": snapshot.deviceID,
            "generation": snapshot.generation,
            "sequence": snapshot.sequence.map { NSNumber(value: $0) } ?? NSNull(),
            "statement_hash": snapshot.statementHash ?? NSNull(),
            "refresh_nonce": snapshot.refreshNonce ?? NSNull(),
            "sequence_watermark": snapshot.sequenceWatermark,
            "blocked_reason": snapshot.blockedReason?.rawValue ?? NSNull(),
            "revision": snapshot.revision
        ]
        do {
            let data = try NativeStrictJSON.data(object)
            guard data.count <= maximumBytes else { throw NativeDeviceRefreshStateMachineError(.invalidSnapshot) }
            return data
        } catch let error as NativeDeviceRefreshStateMachineError {
            throw error
        } catch {
            throw NativeDeviceRefreshStateMachineError(.invalidSnapshot)
        }
    }

    public static func canonicalData(_ snapshot: NativeDeviceRefreshSnapshot) throws -> Data {
        try encode(snapshot)
    }

    public static func decode(_ data: Data) throws -> NativeDeviceRefreshSnapshot {
        guard !data.isEmpty, data.count <= maximumBytes else {
            throw NativeDeviceRefreshStateMachineError(.invalidSnapshot)
        }

        let object: [String: Any]
        do {
            object = try NativeStrictJSON.object(from: data, maxBytes: maximumBytes, maxDepth: 8)
        } catch {
            throw NativeDeviceRefreshStateMachineError(.invalidSnapshot)
        }
        guard Set(object.keys) == keys else {
            throw NativeDeviceRefreshStateMachineError(.invalidSnapshot)
        }

        let snapshot = try parse(object)
        let canonical = try encode(snapshot)
        guard canonical == data else {
            throw NativeDeviceRefreshStateMachineError(.noncanonicalSnapshot)
        }
        return snapshot
    }

    private static func parse(_ object: [String: Any]) throws -> NativeDeviceRefreshSnapshot {
        guard let version = integer(object["version"]), version == Int64(NativeDeviceRefreshSnapshot.version),
              let stateValue = object["state"] as? String,
              let state = NativeDeviceRefreshMachineState(rawValue: stateValue),
              let organizationID = object["organization_id"] as? String,
              let deviceID = object["device_id"] as? String,
              let generation = integer(object["generation"]), generation >= 0,
              let sequenceWatermark = integer(object["sequence_watermark"]), sequenceWatermark >= 0,
              let revision = integer(object["revision"]), revision >= 0 else {
            throw NativeDeviceRefreshStateMachineError(.invalidSnapshot)
        }

        let sequence = try optionalInteger(object["sequence"])
        let statementHash = try optionalString(object["statement_hash"])
        let refreshNonce = try optionalNonce(object["refresh_nonce"])
        let blockedReason = try optionalReason(object["blocked_reason"])
        let snapshot = NativeDeviceRefreshSnapshot(
            version: Int(version),
            state: state,
            organizationID: organizationID,
            deviceID: deviceID,
            generation: generation,
            sequence: sequence,
            statementHash: statementHash,
            refreshNonce: refreshNonce,
            sequenceWatermark: sequenceWatermark,
            blockedReason: blockedReason,
            revision: revision
        )
        try validate(snapshot)
        return snapshot
    }

    private static func validate(_ snapshot: NativeDeviceRefreshSnapshot) throws {
        guard snapshot.version == NativeDeviceRefreshSnapshot.version,
              validUUID(snapshot.organizationID), validUUID(snapshot.deviceID),
              snapshot.generation >= 0, snapshot.generation <= maxSafeInteger,
              snapshot.sequenceWatermark >= 0, snapshot.sequenceWatermark <= maxSafeInteger,
              snapshot.revision >= 0, snapshot.revision <= maxSafeInteger else {
            throw NativeDeviceRefreshStateMachineError(.invalidSnapshot)
        }
        guard (snapshot.sequence == nil) == (snapshot.statementHash == nil) else {
            throw NativeDeviceRefreshStateMachineError(.invalidSnapshot)
        }
        if let sequence = snapshot.sequence {
            guard sequence > 0, sequence <= maxSafeInteger, sequence <= snapshot.sequenceWatermark else {
                throw NativeDeviceRefreshStateMachineError(.invalidSnapshot)
            }
        }
        if let statementHash = snapshot.statementHash, !validHash(statementHash) {
            throw NativeDeviceRefreshStateMachineError(.invalidSnapshot)
        }
        if snapshot.state == .blocked {
            guard snapshot.blockedReason != nil else { throw NativeDeviceRefreshStateMachineError(.invalidSnapshot) }
        } else if snapshot.state != .acknowledged, snapshot.blockedReason != nil {
            throw NativeDeviceRefreshStateMachineError(.invalidSnapshot)
        }

        switch snapshot.state {
        case .idle:
            guard snapshot.sequence == nil, snapshot.refreshNonce == nil else {
                throw NativeDeviceRefreshStateMachineError(.invalidSnapshot)
            }
        case .pollDue:
            guard snapshot.sequence == nil, snapshot.refreshNonce == nil else {
                throw NativeDeviceRefreshStateMachineError(.invalidSnapshot)
            }
        case .hinted, .fetching:
            guard snapshot.sequence == nil, snapshot.generation > 0, snapshot.refreshNonce != nil else {
                throw NativeDeviceRefreshStateMachineError(.invalidSnapshot)
            }
        case .verifying, .staging, .applied, .acknowledged:
            guard snapshot.generation > 0, snapshot.sequence != nil, snapshot.refreshNonce != nil else {
                throw NativeDeviceRefreshStateMachineError(.invalidSnapshot)
            }
        case .blocked:
            guard snapshot.generation >= 0,
                  (snapshot.sequence == nil || snapshot.refreshNonce != nil) else {
                throw NativeDeviceRefreshStateMachineError(.invalidSnapshot)
            }
        }
    }

    private static func optionalInteger(_ value: Any?) throws -> Int64? {
        if value is NSNull { return nil }
        guard let parsed = integer(value), parsed > 0 else {
            throw NativeDeviceRefreshStateMachineError(.invalidSnapshot)
        }
        return parsed
    }

    private static func optionalString(_ value: Any?) throws -> String? {
        if value is NSNull { return nil }
        guard let value = value as? String, validHash(value) else {
            throw NativeDeviceRefreshStateMachineError(.invalidSnapshot)
        }
        return value
    }

    private static func optionalReason(_ value: Any?) throws -> NativeDeviceRefreshStateMachineReasonCode? {
        if value is NSNull { return nil }
        guard let value = value as? String,
              let reason = NativeDeviceRefreshStateMachineReasonCode(rawValue: value) else {
            throw NativeDeviceRefreshStateMachineError(.invalidSnapshot)
        }
        return reason
    }

    private static func optionalNonce(_ value: Any?) throws -> String? {
        if value is NSNull { return nil }
        guard let value = value as? String, validNonce(value) else {
            throw NativeDeviceRefreshStateMachineError(.invalidSnapshot)
        }
        return value
    }

    private static func integer(_ value: Any?) -> Int64? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue.isFinite,
              number.doubleValue.rounded() == number.doubleValue,
              number.doubleValue >= 0,
              number.doubleValue <= Double(maxSafeInteger) else { return nil }
        return number.int64Value
    }

    private static let maxSafeInteger: Int64 = 9_007_199_254_740_991

    fileprivate static func validUUID(_ value: String) -> Bool {
        value.range(of: "^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", options: .regularExpression) != nil
    }

    fileprivate static func validHash(_ value: String) -> Bool {
        value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
    }

    fileprivate static func validNonce(_ value: String) -> Bool {
        guard value.range(of: "^[A-Za-z0-9_-]{22}$", options: .regularExpression) != nil else { return false }
        var padded = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        padded += "=="
        guard let decoded = Data(base64Encoded: padded), decoded.count == 16 else { return false }
        return decoded.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") == value
    }
}

/// A value-type state machine. Mutating operations are deterministic and
/// Sendable; persistence is opt-in through `NativeDeviceRefreshSnapshotStore`.
public struct NativeDeviceRefreshStateMachine: Equatable, Sendable {
    public static let schemaVersion = NativeDeviceRefreshSnapshot.version

    /// The only forward lifecycle transitions. Repeating an already applied
    /// event is handled separately as an idempotent duplicate; a conflict is
    /// a fail-closed transition to `blocked` and is therefore not listed as a
    /// normal lifecycle edge.
    public static let legalTransitions: [
        NativeDeviceRefreshMachineState: Set<NativeDeviceRefreshMachineState>
    ] = [
        .idle: [.hinted, .pollDue],
        .hinted: [.fetching, .idle],
        .pollDue: [.idle, .hinted],
        .fetching: [.verifying, .idle],
        .verifying: [.staging, .blocked, .idle],
        .staging: [.applied, .blocked, .idle],
        .applied: [.acknowledged],
        .blocked: [.acknowledged],
        .acknowledged: [.idle, .hinted]
    ]

    public let organizationID: String
    public let deviceID: String
    public private(set) var state: NativeDeviceRefreshMachineState
    public private(set) var binding: NativeDeviceRefreshBinding
    public private(set) var sequenceWatermark: Int64
    public private(set) var blockedReason: NativeDeviceRefreshStateMachineReasonCode?
    public private(set) var revision: Int64

    public var snapshot: NativeDeviceRefreshSnapshot {
        NativeDeviceRefreshSnapshot(
            state: state,
            organizationID: organizationID,
            deviceID: deviceID,
            generation: binding.generation,
            sequence: binding.sequence,
            statementHash: binding.statementHash,
            refreshNonce: binding.refreshNonce,
            sequenceWatermark: sequenceWatermark,
            blockedReason: blockedReason,
            revision: revision
        )
    }

    public init(organizationID: String, deviceID: String) throws {
        guard NativeDeviceRefreshSnapshotCodec.validUUID(organizationID.lowercased()),
              NativeDeviceRefreshSnapshotCodec.validUUID(deviceID.lowercased()) else {
            throw NativeDeviceSyncContractError(.invalidUUID)
        }
        self.organizationID = organizationID.lowercased()
        self.deviceID = deviceID.lowercased()
        self.state = .idle
        self.binding = NativeDeviceRefreshBinding(
            organizationID: organizationID.lowercased(),
            deviceID: deviceID.lowercased(),
            generation: 0
        )
        self.sequenceWatermark = 0
        self.blockedReason = nil
        self.revision = 0
    }

    public init(snapshot: NativeDeviceRefreshSnapshot) throws {
        let canonical = try NativeDeviceRefreshSnapshotCodec.decode(
            NativeDeviceRefreshSnapshotCodec.encode(snapshot)
        )
        self.organizationID = canonical.organizationID
        self.deviceID = canonical.deviceID
        self.state = canonical.state
        self.binding = canonical.binding
        self.sequenceWatermark = canonical.sequenceWatermark
        self.blockedReason = canonical.blockedReason
        self.revision = canonical.revision
    }

    public static func load(
        organizationID: String,
        deviceID: String,
        from store: any NativeDeviceRefreshSnapshotStore
    ) throws -> Self {
        let expected = try Self(organizationID: organizationID, deviceID: deviceID)
        let data: Data?
        do {
            data = try store.load()
        } catch {
            throw NativeDeviceRefreshStateMachineError(.snapshotLoadFailed)
        }
        guard let data else { return expected }
        let snapshot = try NativeDeviceRefreshSnapshotCodec.decode(data)
        guard snapshot.organizationID == expected.organizationID,
              snapshot.deviceID == expected.deviceID else {
            throw NativeDeviceRefreshStateMachineError(.audienceMismatch)
        }
        return try Self(snapshot: snapshot)
    }

    @discardableResult
    public func save(to store: any NativeDeviceRefreshSnapshotStore) throws -> Data {
        let data = try NativeDeviceRefreshSnapshotCodec.encode(snapshot)
        do {
            try store.save(data)
        } catch {
            throw NativeDeviceRefreshStateMachineError(.snapshotSaveFailed)
        }
        return data
    }

    @discardableResult
    public mutating func apply(_ event: NativeDeviceRefreshEvent) throws -> NativeDeviceRefreshTransitionResult {
        try applyInternal(event)
    }

    /// Apply and persist as one candidate operation. The in-memory value is
    /// replaced only after the canonical snapshot has been accepted by the
    /// store. A conflicting replay is persisted in the blocked state before
    /// its bounded error is rethrown.
    @discardableResult
    public mutating func apply(
        _ event: NativeDeviceRefreshEvent,
        persistingTo store: any NativeDeviceRefreshSnapshotStore
    ) throws -> NativeDeviceRefreshTransitionResult {
        let original = self
        var candidate = self
        do {
            let result = try candidate.applyInternal(event)
            _ = try candidate.save(to: store)
            self = candidate
            return result
        } catch let error as NativeDeviceRefreshStateMachineError where error.isFailClosed {
            do {
                _ = try candidate.save(to: store)
                self = candidate
            } catch {
                self = original
                throw NativeDeviceRefreshStateMachineError(.snapshotSaveFailed)
            }
            throw error
        } catch {
            self = original
            throw error
        }
    }

    public mutating func receiveHint(_ binding: NativeDeviceRefreshBinding) throws -> NativeDeviceRefreshTransitionResult {
        try apply(.hint(binding))
    }

    public mutating func markPollDue() throws -> NativeDeviceRefreshTransitionResult {
        try apply(.pollDue)
    }

    public mutating func recordPollCompletedNoChange() throws -> NativeDeviceRefreshTransitionResult {
        try apply(.pollCompletedNoChange)
    }

    public mutating func beginFetch() throws -> NativeDeviceRefreshTransitionResult {
        try apply(.fetchStarted)
    }

    public mutating func receiveFetchedBundle(_ binding: NativeDeviceRefreshBinding) throws -> NativeDeviceRefreshTransitionResult {
        try apply(.fetched(binding))
    }

    public mutating func markVerificationSucceeded() throws -> NativeDeviceRefreshTransitionResult {
        try apply(.verificationSucceeded)
    }

    public mutating func markVerificationBlocked(_ reason: NativeDeviceRefreshStateMachineReasonCode) throws -> NativeDeviceRefreshTransitionResult {
        try apply(.verificationBlocked(reason))
    }

    public mutating func markStagingSucceeded() throws -> NativeDeviceRefreshTransitionResult {
        try apply(.stagingSucceeded)
    }

    public mutating func markStagingBlocked(_ reason: NativeDeviceRefreshStateMachineReasonCode) throws -> NativeDeviceRefreshTransitionResult {
        try apply(.stagingBlocked(reason))
    }

    public mutating func recordAcknowledgement() throws -> NativeDeviceRefreshTransitionResult {
        try apply(.acknowledgementDurablyRecorded)
    }

    public mutating func resetForNextPoll() throws -> NativeDeviceRefreshTransitionResult {
        try apply(.resetForNextPoll)
    }

    private mutating func applyInternal(_ event: NativeDeviceRefreshEvent) throws -> NativeDeviceRefreshTransitionResult {
        switch event {
        case .hint(let incoming):
            return try handleHint(incoming)
        case .pollDue:
            switch state {
            case .idle:
                state = .pollDue
                return changed()
            case .pollDue:
                return duplicate()
            default:
                throw illegal()
            }
        case .pollCompletedNoChange:
            switch state {
            case .pollDue:
                state = .idle
                return changed()
            case .idle:
                return duplicate()
            default:
                throw illegal()
            }
        case .fetchStarted:
            switch state {
            case .hinted:
                state = .fetching
                return changed()
            case .fetching:
                return duplicate()
            default:
                throw illegal()
            }
        case .fetched(let incoming):
            return try handleFetched(incoming)
        case .verificationSucceeded:
            switch state {
            case .verifying:
                state = .staging
                return changed()
            case .staging, .applied, .acknowledged:
                return duplicate()
            case .blocked:
                throw failClosed(.conflictingReplay)
            default:
                throw illegal()
            }
        case .verificationBlocked(let reason):
            guard reason != .invalidSnapshot, reason != .snapshotLoadFailed, reason != .snapshotSaveFailed else {
                throw NativeDeviceRefreshStateMachineError(.invalidBinding)
            }
            switch state {
            case .verifying:
                return enterBlocked(reason)
            case .blocked:
                if blockedReason == reason { return duplicate() }
                throw failClosed(.blockedReasonConflict)
            case .acknowledged where blockedReason == reason:
                return duplicate()
            default:
                throw illegal()
            }
        case .stagingSucceeded:
            switch state {
            case .staging:
                state = .applied
                return changed()
            case .applied, .acknowledged:
                return duplicate()
            case .blocked:
                throw failClosed(.conflictingReplay)
            default:
                throw illegal()
            }
        case .stagingBlocked(let reason):
            guard reason != .invalidSnapshot, reason != .snapshotLoadFailed, reason != .snapshotSaveFailed else {
                throw NativeDeviceRefreshStateMachineError(.invalidBinding)
            }
            switch state {
            case .staging:
                return enterBlocked(reason)
            case .blocked:
                if blockedReason == reason { return duplicate() }
                throw failClosed(.blockedReasonConflict)
            case .acknowledged where blockedReason == reason:
                return duplicate()
            default:
                throw illegal()
            }
        case .acknowledgementDurablyRecorded:
            switch state {
            case .applied, .blocked:
                guard binding.sequence != nil, binding.statementHash != nil, binding.refreshNonce != nil else {
                    throw illegal()
                }
                state = .acknowledged
                return changed()
            case .acknowledged:
                return duplicate()
            default:
                throw illegal()
            }
        case .refreshSuperseded:
            switch state {
            case .hinted, .fetching, .verifying, .staging:
                binding = NativeDeviceRefreshBinding(
                    organizationID: organizationID,
                    deviceID: deviceID,
                    generation: binding.generation
                )
                blockedReason = nil
                state = .idle
                return changed()
            case .idle:
                return duplicate()
            default:
                throw illegal()
            }
        case .resetForNextPoll:
            switch state {
            case .acknowledged:
                state = .idle
                blockedReason = nil
                binding = NativeDeviceRefreshBinding(
                    organizationID: organizationID,
                    deviceID: deviceID,
                    generation: binding.generation
                )
                return changed()
            case .idle:
                return duplicate()
            default:
                throw illegal()
            }
        }
    }

    private mutating func handleHint(_ incoming: NativeDeviceRefreshBinding) throws -> NativeDeviceRefreshTransitionResult {
        try validateIncoming(incoming, requireBundle: false)
        guard incoming.sequence == nil, incoming.statementHash == nil,
              let nonce = incoming.refreshNonce, NativeDeviceRefreshSnapshotCodec.validNonce(nonce) else {
            throw NativeDeviceRefreshStateMachineError(.invalidBinding)
        }
        guard incoming.generation > 0 else {
            throw NativeDeviceRefreshStateMachineError(.invalidBinding)
        }
        guard incoming.generation >= binding.generation else {
            throw failClosed(.generationRollback)
        }
        guard incoming.generation <= Self.maxSafeInteger else {
            throw NativeDeviceRefreshStateMachineError(.invalidBinding)
        }

        if incoming.generation == binding.generation {
            guard state != .blocked || blockedReason == nil else {
                throw failClosed(.conflictingReplay)
            }
            if let currentNonce = binding.refreshNonce, currentNonce != nonce {
                throw failClosed(.conflictingReplay)
            }
            if state == .pollDue, binding.refreshNonce == nil {
                state = .idle
                return changed()
            }
            return duplicate()
        }
        guard state == .idle || state == .pollDue || state == .acknowledged else {
            throw failClosed(.generationConflict)
        }
        binding = NativeDeviceRefreshBinding(
            organizationID: organizationID,
            deviceID: deviceID,
            generation: incoming.generation,
            refreshNonce: nonce
        )
        state = .hinted
        blockedReason = nil
        return changed()
    }

    private mutating func handleFetched(_ incoming: NativeDeviceRefreshBinding) throws -> NativeDeviceRefreshTransitionResult {
        try validateIncoming(incoming, requireBundle: true)
        guard let sequence = incoming.sequence, let statementHash = incoming.statementHash else {
            throw NativeDeviceRefreshStateMachineError(.invalidBinding)
        }

        if incoming.generation < binding.generation {
            throw failClosed(.generationRollback)
        }
        if incoming.generation > binding.generation {
            guard state == .fetching, binding.generation == 0 else {
                throw failClosed(.generationConflict)
            }
            guard sequence > sequenceWatermark else {
                throw failClosed(.sequenceRollback)
            }
            binding = incoming
            sequenceWatermark = sequence
            state = .verifying
            blockedReason = nil
            return changed()
        }

        guard incoming.refreshNonce == binding.refreshNonce else {
            throw failClosed(.conflictingReplay)
        }

        if let currentSequence = binding.sequence, let currentHash = binding.statementHash {
            guard sequence == currentSequence else {
                throw failClosed(sequence < currentSequence ? .sequenceRollback : .sequenceConflict)
            }
            guard statementHash == currentHash else {
                throw failClosed(.statementHashConflict)
            }
            guard state == .verifying || state == .staging || state == .applied || state == .blocked || state == .acknowledged else {
                throw illegal()
            }
            return duplicate()
        }

        guard state == .fetching else {
            throw illegal()
        }
        guard sequence > sequenceWatermark else {
            throw failClosed(.sequenceRollback)
        }
        binding = binding.withBundle(sequence: sequence, statementHash: statementHash)
        sequenceWatermark = sequence
        state = .verifying
        return changed()
    }

    private mutating func enterBlocked(_ reason: NativeDeviceRefreshStateMachineReasonCode) -> NativeDeviceRefreshTransitionResult {
        state = .blocked
        blockedReason = reason
        return changed()
    }

    private mutating func changed() -> NativeDeviceRefreshTransitionResult {
        revision += 1
        return .changed(snapshot)
    }

    private func duplicate() -> NativeDeviceRefreshTransitionResult {
        .duplicate(snapshot)
    }

    private mutating func validateIncoming(_ incoming: NativeDeviceRefreshBinding, requireBundle: Bool) throws {
        guard NativeDeviceRefreshSnapshotCodec.validUUID(incoming.organizationID.lowercased()),
              NativeDeviceRefreshSnapshotCodec.validUUID(incoming.deviceID.lowercased()) else {
            throw NativeDeviceRefreshStateMachineError(.invalidBinding)
        }
        guard incoming.organizationID.lowercased() == organizationID,
              incoming.deviceID.lowercased() == deviceID else {
            throw failClosed(.audienceMismatch)
        }
        guard incoming.generation >= 0,
              incoming.generation <= Self.maxSafeInteger else {
            throw NativeDeviceRefreshStateMachineError(.invalidBinding)
        }
        if requireBundle, incoming.generation == 0 {
            throw NativeDeviceRefreshStateMachineError(.invalidBinding)
        }
        guard (incoming.sequence == nil) == (incoming.statementHash == nil) else {
            throw NativeDeviceRefreshStateMachineError(.invalidBinding)
        }
        if requireBundle {
            guard let sequence = incoming.sequence, let hash = incoming.statementHash,
                  let nonce = incoming.refreshNonce, NativeDeviceRefreshSnapshotCodec.validNonce(nonce),
                  sequence > 0, sequence <= Self.maxSafeInteger,
                  NativeDeviceRefreshSnapshotCodec.validHash(hash) else {
                throw NativeDeviceRefreshStateMachineError(.invalidBinding)
            }
        } else if let nonce = incoming.refreshNonce, !NativeDeviceRefreshSnapshotCodec.validNonce(nonce) {
            throw NativeDeviceRefreshStateMachineError(.invalidBinding)
        }
    }

    private func illegal() -> NativeDeviceRefreshStateMachineError {
        NativeDeviceRefreshStateMachineError(.illegalTransition)
    }

    private mutating func failClosed(_ reason: NativeDeviceRefreshStateMachineReasonCode) -> NativeDeviceRefreshStateMachineError {
        state = .blocked
        blockedReason = reason
        revision += 1
        return NativeDeviceRefreshStateMachineError(reason, failClosed: true)
    }

    private static let maxSafeInteger: Int64 = 9_007_199_254_740_991
}

/// Crash-safe 0600 persistence for the refresh snapshot. The shared native
/// atomic-write primitive performs exclusive temporary creation, file fsync,
/// rename, and parent-directory fsync; reads reject symlinks, hard links,
/// widened permissions, wrong ownership, and oversized files.
public final class NativeDeviceRefreshPOSIXSnapshotStore: NativeDeviceRefreshSnapshotStore, @unchecked Sendable {
    public let path: String
    private let lock = NSLock()

    public init(path: String) throws {
        guard path.hasPrefix("/"), URL(fileURLWithPath: path).standardizedFileURL.path == path else {
            throw NativeDeviceRefreshStateMachineError(.invalidSnapshot)
        }
        self.path = path
    }

    public func load() throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        var metadata = stat()
        if lstat(path, &metadata) != 0 {
            if errno == ENOENT { return nil }
            throw NativeDeviceRefreshStateMachineError(.snapshotLoadFailed)
        }
        do {
            return try nativeV2ReadFile(path, maxBytes: NativeDeviceRefreshSnapshotCodec.maximumBytes)
        } catch {
            throw NativeDeviceRefreshStateMachineError(.snapshotLoadFailed)
        }
    }

    public func save(_ canonicalSnapshot: Data) throws {
        guard !canonicalSnapshot.isEmpty,
              canonicalSnapshot.count <= NativeDeviceRefreshSnapshotCodec.maximumBytes,
              (try? NativeDeviceRefreshSnapshotCodec.decode(canonicalSnapshot)) != nil else {
            throw NativeDeviceRefreshStateMachineError(.snapshotSaveFailed)
        }
        lock.lock()
        defer { lock.unlock() }
        do {
            try nativeV2AtomicWrite(path, data: canonicalSnapshot)
        } catch {
            throw NativeDeviceRefreshStateMachineError(.snapshotSaveFailed)
        }
    }
}
