import AgentPassNativeCore
import Foundation

/// Stable failures for the cross-connection Host control boundary. These
/// values deliberately carry no session, PID, token, or filesystem detail.
public enum NativeAgentHostControlRegistryError: String, Error, Equatable, Sendable, LocalizedError {
    case controlUnavailable = "control_unavailable"
    case controlPeerMismatch = "control_peer_mismatch"
    case controlReplay = "control_replay"
    case controlInProgress = "control_in_progress"
    case controlSessionMissing = "control_session_missing"

    public var errorDescription: String? { rawValue }
}

/// Service-owned index for the narrow Host control surface.
///
/// The index is intentionally in-memory and connection-owned. It contains no
/// bearer credential and is never encoded, persisted, or passed through
/// argv/environment/file transport. A session ID is only a lookup label; the
/// caller must also have passed the dedicated control listener's signed
/// principal admission check.  The control caller is intentionally a
/// separate process from the Host owner, so the registry never compares the
/// controller principal hash with the Host owner hash.
/// The operation ledger makes a completed close replay-safe only for an exact
/// retry of the same operation fingerprint, which is required to converge
/// after a lost XPC response.
public final class NativeAgentHostControlRegistry: @unchecked Sendable {
    private static let maximumRegisteredSessions = 128
    private static let maximumRememberedOperations = 4_096
    private static let maximumInFlightWaitSeconds = 5
    private let authorizedControlBundleIdentifier: String?
    private let requireOwnerPrincipalMatch: Bool

    public init(
        authorizedControlBundleIdentifier: String? = nil,
        requireOwnerPrincipalMatch: Bool = true
    ) {
        self.authorizedControlBundleIdentifier = authorizedControlBundleIdentifier
        self.requireOwnerPrincipalMatch = requireOwnerPrincipalMatch
    }
    private struct Entry {
        weak var endpoint: NativeAgentAuthenticatedHostEndpoint?
        let ownerPrincipalHash: String
    }

    private struct OperationFingerprint: Equatable {
        let sessionID: String
        let reason: String
    }

    private final class InFlightOperation: @unchecked Sendable {
        let fingerprint: OperationFingerprint
        let group = DispatchGroup()

        init(fingerprint: OperationFingerprint) {
            self.fingerprint = fingerprint
            group.enter()
        }
    }

    private enum OperationRecord {
        case inFlight(InFlightOperation)
        case completed(OperationFingerprint, AgentPassHostControlCloseResponse)
    }

    private let lock = NSLock()
    private var entries: [String: Entry] = [:]
    private var operations: [String: OperationRecord] = [:]

    public func register(
        sessionID: String,
        endpoint: NativeAgentAuthenticatedHostEndpoint,
        ownerIdentity: NativeProcessIdentity
    ) throws {
        guard AgentPassHostXPCContract.canonicalUUID(sessionID) != nil else {
            throw NativeAgentHostControlRegistryError.controlSessionMissing
        }
        try lock.withLock {
            // A failed invalidation callback must not turn the service-wide
            // index into an unbounded retention surface. Live endpoints are
            // bounded by the native runtime session policy; dead weak entries
            // are removed before admitting a new session.
            entries = entries.filter { $0.value.endpoint != nil }
            guard entries[sessionID] == nil else {
                throw NativeAgentHostControlRegistryError.controlReplay
            }
            guard entries.count < Self.maximumRegisteredSessions else {
                throw NativeAgentHostControlRegistryError.controlUnavailable
            }
            entries[sessionID] = Entry(
                endpoint: endpoint,
                ownerPrincipalHash: ownerIdentity.canonicalControlPrincipalHash
            )
        }
    }

    public func unregister(endpoint: NativeAgentAuthenticatedHostEndpoint) {
        lock.withLock {
            entries = entries.filter { $0.value.endpoint !== endpoint }
        }
    }

    public func close(
        request: AgentPassHostControlCloseRequest,
        controllerIdentity: NativeProcessIdentity
    ) throws -> AgentPassHostControlCloseResponse {
        // The XPC listener has already enforced the Native Client's exact
        // designated requirement and revalidated it before calling here.
        // Do not require equality with the Host owner's principal: those are
        // deliberately different signed executables.
        if let authorizedControlBundleIdentifier,
           controllerIdentity.process.bundleIdentifier != authorizedControlBundleIdentifier {
            throw NativeAgentHostControlRegistryError.controlPeerMismatch
        }
        let principalHash = "control-principal"
        let key = principalHash + "\0" + request.operationID
        let fingerprint = OperationFingerprint(sessionID: request.sessionID, reason: request.reason)

        enum Decision {
            case completed(AgentPassHostControlCloseResponse)
            case wait(InFlightOperation)
            case start(InFlightOperation, NativeAgentAuthenticatedHostEndpoint)
        }

        let decision: Decision = try lock.withLock {
            if let record = operations[key] {
                switch record {
                case let .completed(previousFingerprint, response):
                    guard previousFingerprint == fingerprint else {
                        throw NativeAgentHostControlRegistryError.controlReplay
                    }
                    return .completed(response)
                case let .inFlight(inFlight):
                    guard inFlight.fingerprint == fingerprint else {
                        throw NativeAgentHostControlRegistryError.controlReplay
                    }
                    return .wait(inFlight)
                }
            }

            guard let entry = entries[request.sessionID],
                  let endpoint = entry.endpoint else {
                throw NativeAgentHostControlRegistryError.controlSessionMissing
            }
            if requireOwnerPrincipalMatch,
               entry.ownerPrincipalHash != controllerIdentity.canonicalControlPrincipalHash {
                throw NativeAgentHostControlRegistryError.controlPeerMismatch
            }
            while operations.count >= Self.maximumRememberedOperations {
                guard let evictableKey = operations.first(where: { _, record in
                    if case .completed = record { return true }
                    return false
                })?.key else {
                    throw NativeAgentHostControlRegistryError.controlInProgress
                }
                operations.removeValue(forKey: evictableKey)
            }
            let inFlight = InFlightOperation(fingerprint: fingerprint)
            operations[key] = .inFlight(inFlight)
            return .start(inFlight, endpoint)
        }

        switch decision {
        case let .completed(response):
            return response
        case let .wait(operation):
            guard operation.group.wait(timeout: .now() + .seconds(Self.maximumInFlightWaitSeconds)) == .success else {
                // A stuck endpoint must not turn the dedicated control
                // service into an unbounded waiter. The original in-flight
                // operation remains ledger-owned and may still complete; a
                // caller can retry the same operation ID after the service
                // has converged.
                throw NativeAgentHostControlRegistryError.controlUnavailable
            }
            lock.lock()
            defer { lock.unlock() }
            guard case let .completed(_, response) = operations[key] else {
                throw NativeAgentHostControlRegistryError.controlUnavailable
            }
            return response
        case let .start(operation, target):
            do {
                let response = try target.closeFromAuthorizedControl(request)
                lock.withLock {
                    operations[key] = .completed(fingerprint, response)
                    operation.group.leave()
                }
                return response
            } catch {
                lock.withLock {
                    operation.group.leave()
                    operations.removeValue(forKey: key)
                }
                throw error
            }
        }
    }
}
