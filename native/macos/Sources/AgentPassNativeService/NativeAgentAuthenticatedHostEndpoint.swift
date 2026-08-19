import CryptoKit
import Foundation
import AgentPassNativeCore

/// Stable, non-sensitive failures returned by the connection-owned Host
/// endpoint.  No associated values are used so a peer cannot cause an OS
/// error, path, token, or other sensitive value to be reflected over XPC.
public enum NativeAgentAuthenticatedHostEndpointError: String, Error, Equatable, Sendable, LocalizedError {
    case invalidRequest = "invalid_request"
    case invalidSessionState = "invalid_session_state"
    case peerIdentityMismatch = "peer_identity_mismatch"
    case processIdentityChanged = "process_identity_changed"
    case codeIdentityDenied = "code_identity_denied"
    case childIdentityMismatch = "child_identity_mismatch"
    case childObservationFailed = "child_observation_failed"
    case expired = "expired"
    case revoked = "revoked"
    case signerFailed = "signer_failed"
    case outcomeUnknown = "outcome_unknown"
    case endpointClosed = "endpoint_closed"

    public var errorDescription: String? { rawValue }
}

/// The only runtime dependency of this endpoint.  A production implementation
/// may call Secure Enclave, a local signer, or a cloud-backed signer, but the
/// endpoint itself never receives a key, key path, command, argv, or secret.
public protocol NativeAgentAuthenticatedHostSigning: Sendable {
    func sign(_ payload: NativeAgentAuthenticatedGitBridgeSession.AuthorizedPayload) throws -> Data
}

/// Closure adapter for small Service wiring and deterministic tests.
public struct NativeAgentAuthenticatedHostClosureSigner: NativeAgentAuthenticatedHostSigning {
    private let operation: @Sendable (NativeAgentAuthenticatedGitBridgeSession.AuthorizedPayload) throws -> Data

    public init(
        operation: @escaping @Sendable (NativeAgentAuthenticatedGitBridgeSession.AuthorizedPayload) throws -> Data
    ) {
        self.operation = operation
    }

    public func sign(_ payload: NativeAgentAuthenticatedGitBridgeSession.AuthorizedPayload) throws -> Data {
        try operation(payload)
    }
}

/// A child observation returned by the service-side OS adapter.
///
/// `NativeProcessIdentity` is constructed from an observation source, never
/// from the XPC request. The worktree digest is likewise supplied by an
/// independent OS/filesystem observer. The request's digest fields are only
/// compared with this independently obtained result.
public struct NativeAgentAuthenticatedHostChildObservation: Sendable {
    public let identity: NativeProcessIdentity
    public let worktreeBindingDigest: Data

    public init(
        observationSource: any NativeProcessObservationSource,
        worktreeBindingDigest: Data
    ) throws {
        guard AgentPassHostXPCContract.isDigest(worktreeBindingDigest) else {
            throw NativeAgentAuthenticatedHostEndpointError.invalidRequest
        }
        self.identity = try NativeProcessIdentity.capture(from: observationSource)
        self.worktreeBindingDigest = worktreeBindingDigest
    }

    /// The process binding hash is the canonical digest used by the Core
    /// authenticated bridge. It includes executable, code-signing, PID
    /// generation, entitlement, and process facts.
    public var executableIdentityDigest: Data {
        Self.decodeHex(identity.canonicalBindingHash)
    }

    public var ancestryBindingDigest: Data {
        Self.decodeHex(identity.canonicalAncestryBindingHash)
    }

    private static func decodeHex(_ value: String) -> Data {
        var result = Data(capacity: value.utf8.count / 2)
        var highNibble: UInt8?
        for scalar in value.utf8 {
            let nibble: UInt8
            switch scalar {
            case 48...57: nibble = scalar - 48
            case 65...70: nibble = scalar - 55
            case 97...102: nibble = scalar - 87
            default: return Data()
            }
            if let high = highNibble {
                result.append((high << 4) | nibble)
                highNibble = nil
            } else {
                highNibble = nibble
            }
        }
        return highNibble == nil ? result : Data()
    }
}

/// A connection-owned implementation of `AgentPassHostXPCProtocol`.
///
/// Construct one instance per accepted NSXPC connection. It owns exactly one
/// Core session and exposes no session identifier in request methods. The
/// expected lifecycle is:
///
///     prepare -> attach child -> sign (up to the Core budget) -> status/close
///
/// The endpoint does not install an NSXPC listener; the existing Service
/// listener can export this object on a dedicated Host connection in a later
/// wiring change. Keeping the adapter standalone makes its security state
/// machine testable without changing that listener.
public final class NativeAgentAuthenticatedHostEndpoint: NSObject, AgentPassHostXPCProtocol {
    public typealias ContextObserver = @Sendable () throws -> NativeConnectionContext
    public typealias ProcessObserver = @Sendable () throws -> NativeProcessObservation
    public typealias ChildObserver = @Sendable (_ pid: Int32, _ pidVersion: UInt64) throws -> NativeAgentAuthenticatedHostChildObservation
    public typealias ChildRegistrar = @Sendable (_ sessionID: String, _ observation: NativeAgentAuthenticatedHostChildObservation, _ signatureBudget: NativeAgentSignatureBudgetLedger) throws -> Void
    public typealias ChildUnregistrar = @Sendable (_ processBindingHash: String) -> Void
    public typealias SignatureBudgetProvider = @Sendable () throws -> NativeAgentSignatureBudget?
    public typealias MillisecondClock = @Sendable () -> Int64
    public typealias RequestIDFactory = @Sendable () -> String

    private struct ConsumedSignRequest: Equatable {
        let requestID: String
        let createdAtMilliseconds: Int64
        let requestSequence: UInt32
        let payloadDigest: Data
    }

    private static let errorDomain = "com.agentpass.native-authenticated-host"
    public static let defaultLifetimeMilliseconds: Int64 = 32 * 60 * 1_000

    private let peerBinding: NativeAgentAuthenticatedGitBridgePeerBinding
    private let peerContextObserver: ContextObserver
    private let peerProcessObserver: ProcessObserver
    private let childObserver: ChildObserver
    private let childRegistrar: ChildRegistrar?
    private let childUnregistrar: ChildUnregistrar?
    private let signatureBudgetProvider: SignatureBudgetProvider?
    private let signer: any NativeAgentAuthenticatedHostSigning
    private let nowMilliseconds: MillisecondClock
    private let requestIDFactory: RequestIDFactory
    private let sessionLifetimeMilliseconds: Int64
    private let childPolicy: NativeProcessIdentityPolicy
    private let stateLock = NSLock()

    private var session: NativeAgentAuthenticatedGitBridgeSession?
    private var expirationMilliseconds: Int64?
    private var terminalStatus: AgentPassHostXPCContract.SessionStatus?
    private var registeredChildBindingHash: String?
    private var signatureBudget: NativeAgentSignatureBudgetLedger?
    private var consumedSignRequests: [UInt32: ConsumedSignRequest] = [:]
    private var issuedRequestIDs: Set<String> = []

    /// `connectionContext` and `initialPeerObservation` must be captured from
    /// the accepted NSXPC connection. The observer closures must independently
    /// obtain fresh OS facts on every protected operation.
    public init(
        connectionContext: NativeConnectionContext,
        initialPeerObservation: NativeProcessObservation,
        peerProcessPolicy: NativeProcessIdentityPolicy,
        childProcessPolicy: NativeProcessIdentityPolicy,
        observeConnectionContext: @escaping ContextObserver,
        observePeerProcess: @escaping ProcessObserver,
        observeChild: @escaping ChildObserver,
        signer: any NativeAgentAuthenticatedHostSigning,
        nowMilliseconds: @escaping MillisecondClock = {
            Int64(Date().timeIntervalSince1970 * 1_000)
        },
        requestIDFactory: @escaping RequestIDFactory = {
            UUID().uuidString.lowercased()
        },
        sessionLifetimeMilliseconds: Int64 = NativeAgentAuthenticatedHostEndpoint.defaultLifetimeMilliseconds,
        childRegistrar: ChildRegistrar? = nil,
        childUnregistrar: ChildUnregistrar? = nil,
        signatureBudgetProvider: SignatureBudgetProvider? = nil
    ) throws {
        guard sessionLifetimeMilliseconds > 0 else {
            throw NativeAgentAuthenticatedHostEndpointError.invalidRequest
        }

        self.peerBinding = try NativeAgentAuthenticatedGitBridgePeerBinding(
            connectionContext: connectionContext,
            observation: initialPeerObservation,
            processPolicy: peerProcessPolicy
        )
        self.peerContextObserver = observeConnectionContext
        self.peerProcessObserver = observePeerProcess
        self.childObserver = observeChild
        self.childRegistrar = childRegistrar
        self.childUnregistrar = childUnregistrar
        self.signatureBudgetProvider = signatureBudgetProvider
        self.signer = signer
        self.nowMilliseconds = nowMilliseconds
        self.requestIDFactory = requestIDFactory
        self.sessionLifetimeMilliseconds = sessionLifetimeMilliseconds
        self.childPolicy = childProcessPolicy
        super.init()
    }

    public func prepareHostSession(
        _ request: AgentPassHostPrepareRequest,
        withReply reply: @escaping (AgentPassHostPrepareResponse?, NSError?) -> Void
    ) {
        stateLock.lock()
        defer { stateLock.unlock() }
        do {
            try revalidatePeerOrRevoke()
            guard session == nil else { throw NativeAgentAuthenticatedHostEndpointError.invalidSessionState }
            guard let budgetValue = try signatureBudgetProvider?(),
                  budgetValue.remainingSignatures > 0 else {
                throw NativeAgentAuthenticatedHostEndpointError.invalidSessionState
            }
            let budget = NativeAgentSignatureBudgetLedger(budgetValue)

            let sessionID = UUID().uuidString.lowercased()
            let newSession = try NativeAgentAuthenticatedGitBridgeSession(
                sessionID: sessionID,
                peer: peerBinding,
                childPolicy: childPolicy,
                signatureBudget: budget
            )
            let prepared = try newSession.prepare(launchNonce: request.launchNonce)
            let now = try validTimestamp(nowMilliseconds())
            let expiration = try validExpiration(now: now)

            session = newSession
            signatureBudget = budget
            expirationMilliseconds = expiration
            terminalStatus = nil
            consumedSignRequests.removeAll(keepingCapacity: true)
            issuedRequestIDs.removeAll(keepingCapacity: true)
            guard let response = AgentPassHostPrepareResponse(
                sessionID: prepared.sessionID,
                status: .prepared,
                expiresAtMilliseconds: expiration,
                maxSignatures: budgetValue.maxSignatures,
                usedSignatures: budgetValue.usedSignatures
            ) else {
                throw NativeAgentAuthenticatedHostEndpointError.invalidRequest
            }
            reply(response, nil)
        } catch {
            reply(nil, makeError(error))
        }
    }

    public func attachHostChild(
        _ request: AgentPassHostAttachChildRequest,
        withReply reply: @escaping (AgentPassHostAttachChildResponse?, NSError?) -> Void
    ) {
        stateLock.lock()
        defer { stateLock.unlock() }
        do {
            try revalidatePeerOrRevoke()
            try requireLiveSession()
            guard let session else { throw NativeAgentAuthenticatedHostEndpointError.invalidSessionState }

            let observation: NativeAgentAuthenticatedHostChildObservation
            do {
                observation = try childObserver(Int32(request.childPID), UInt64(request.childPIDVersion))
            } catch {
                closeSessionAndRevoke(session)
                throw NativeAgentAuthenticatedHostEndpointError.childObservationFailed
            }
            guard observation.identity.pid == Int32(request.childPID),
                  observation.identity.pidVersion == UInt64(request.childPIDVersion),
                  observation.executableIdentityDigest == request.executableIdentityDigest,
                  observation.ancestryBindingDigest == request.ancestryBindingDigest,
                  observation.worktreeBindingDigest == request.worktreeBindingDigest else {
                closeSessionAndRevoke(session)
                throw NativeAgentAuthenticatedHostEndpointError.childIdentityMismatch
            }

            let attached = try session.attach(childIdentity: observation.identity)
            guard let signatureBudget else {
                closeSessionAndRevoke(session)
                throw NativeAgentAuthenticatedHostEndpointError.invalidSessionState
            }
            do {
                try childRegistrar?(attached.sessionID, observation, signatureBudget)
                registeredChildBindingHash = observation.identity.canonicalBindingHash
            } catch {
                closeSessionAndRevoke(session)
                throw NativeAgentAuthenticatedHostEndpointError.childIdentityMismatch
            }
            guard let response = AgentPassHostAttachChildResponse(
                sessionID: attached.sessionID,
                attachedAtMilliseconds: try validTimestamp(nowMilliseconds()),
                maxSignatures: attached.maxSignatures,
                usedSignatures: attached.usedSignatures
            ) else {
                closeSessionAndRevoke(session)
                throw NativeAgentAuthenticatedHostEndpointError.invalidRequest
            }
            reply(response, nil)
        } catch {
            reply(nil, makeError(error))
        }
    }

    public func signHostPayload(
        _ request: AgentPassHostSignRequest,
        withReply reply: @escaping (AgentPassHostSignResponse?, NSError?) -> Void
    ) {
        stateLock.lock()
        defer { stateLock.unlock() }
        do {
            try revalidatePeerOrRevoke()
            try requireLiveSession()
            guard let session else {
                throw NativeAgentAuthenticatedHostEndpointError.invalidSessionState
            }

            let payloadDigest = Data(SHA256.hash(data: request.commitPayload))
            if let consumed = consumedSignRequests[request.requestSequence] {
                guard consumed.payloadDigest == payloadDigest,
                      requestCorrelationMatches(request, consumed: consumed) else {
                    closeSessionAndRevoke(session)
                    throw NativeAgentAuthenticatedHostEndpointError.invalidRequest
                }
                closeSessionAndRevoke(session)
                throw NativeAgentAuthenticatedHostEndpointError.outcomeUnknown
            }

            guard request.requestID.isEmpty,
                  request.createdAtMilliseconds == 0,
                  request.requestSequence == UInt32(consumedSignRequests.count + 1) else {
                closeSessionAndRevoke(session)
                throw NativeAgentAuthenticatedHostEndpointError.invalidRequest
            }

            let createdAtMilliseconds = try validTimestamp(nowMilliseconds())
            guard let requestID = AgentPassHostXPCContract.canonicalUUID(requestIDFactory()),
                  !issuedRequestIDs.contains(requestID) else {
                closeSessionAndRevoke(session)
                throw NativeAgentAuthenticatedHostEndpointError.invalidRequest
            }

            guard let bridgeRequest = session.makeRequest(
                requestSequence: request.requestSequence,
                payload: request.commitPayload
            ) else {
                throw NativeAgentAuthenticatedHostEndpointError.invalidSessionState
            }

            let authorized: NativeAgentAuthenticatedGitBridgeSession.AuthorizedPayload
            do {
                authorized = try session.authorizeAndConsume(
                    bridgeRequest,
                    reobservedConnectionContext: try peerContextObserver(),
                    reobservedObservation: try peerProcessObserver()
                )
            } catch let error as NativeAgentAuthenticatedGitBridgeError {
                throw mapCoreError(error)
            }

            issuedRequestIDs.insert(requestID)
            consumedSignRequests[request.requestSequence] = ConsumedSignRequest(
                requestID: requestID,
                createdAtMilliseconds: createdAtMilliseconds,
                requestSequence: request.requestSequence,
                payloadDigest: payloadDigest
            )

            let signature: Data
            do {
                signature = try signer.sign(authorized)
            } catch {
                closeSessionAndRevoke(session)
                throw NativeAgentAuthenticatedHostEndpointError.signerFailed
            }
            let snapshot = session.snapshot
            guard !signature.isEmpty,
                  signature.count <= AgentPassHostXPCContract.maximumSignatureBytes,
                  let response = AgentPassHostSignResponse(
                    responseSequence: request.requestSequence,
                    signature: signature,
                    maxSignatures: snapshot.maxSignatures,
                    usedSignatures: snapshot.usedSignatures,
                    remainingSignatures: snapshot.remainingSignatures,
                    requestID: requestID,
                    createdAtMilliseconds: createdAtMilliseconds
                  ) else {
                closeSessionAndRevoke(session)
                throw NativeAgentAuthenticatedHostEndpointError.signerFailed
            }
            reply(response, nil)
        } catch {
            reply(nil, makeError(error))
        }
    }

    public func hostSessionStatus(
        _ request: AgentPassHostStatusRequest,
        withReply reply: @escaping (AgentPassHostStatusResponse?, NSError?) -> Void
    ) {
        stateLock.lock()
        defer { stateLock.unlock() }
        do {
            try revalidatePeerOrRevoke()
            guard let session else { throw NativeAgentAuthenticatedHostEndpointError.invalidSessionState }
            let snapshot = try snapshotAndRefreshExpiration(for: session)
            let status = status(for: snapshot)
            let childAttached = snapshot.phase == .attached
            guard let expirationMilliseconds,
                  let response = AgentPassHostStatusResponse(
                    sessionID: snapshot.sessionID,
                    status: status,
                    expiresAtMilliseconds: expirationMilliseconds,
                    maxSignatures: snapshot.maxSignatures,
                    usedSignatures: snapshot.usedSignatures,
                    childAttached: childAttached
                  ) else {
                throw NativeAgentAuthenticatedHostEndpointError.invalidRequest
            }
            reply(response, nil)
        } catch {
            reply(nil, makeError(error))
        }
    }

    public func closeHostSession(
        _ request: AgentPassHostCloseRequest,
        withReply reply: @escaping (AgentPassHostCloseResponse?, NSError?) -> Void
    ) {
        stateLock.lock()
        defer { stateLock.unlock() }
        do {
            try revalidatePeerOrRevoke()
            guard let session else { throw NativeAgentAuthenticatedHostEndpointError.invalidSessionState }
            let snapshot = closeSessionAndRevoke(session, status: .closed)
            guard let response = AgentPassHostCloseResponse(
                sessionID: snapshot.sessionID,
                closedAtMilliseconds: try validTimestamp(nowMilliseconds())
            ) else {
                throw NativeAgentAuthenticatedHostEndpointError.invalidRequest
            }
            reply(response, nil)
        } catch {
            reply(nil, makeError(error))
        }
    }

    /// Called by the NSXPC invalidation handler. Connection loss is terminal
    /// for the child registration and must not leave a signing entry alive.
    public func invalidateConnection() {
        stateLock.lock()
        if let session {
            _ = closeSessionAndRevoke(session)
        } else {
            unregisterRegisteredChild()
        }
        stateLock.unlock()
    }

    /// Every terminal session transition revokes the child registry entry in
    /// the same critical section. Otherwise a child with an unchanged process
    /// identity could retain the remaining signing budget after Host expiry,
    /// signer failure, or peer drift.
    @discardableResult
    private func closeSessionAndRevoke(
        _ session: NativeAgentAuthenticatedGitBridgeSession,
        status: AgentPassHostXPCContract.SessionStatus = .revoked
    ) -> NativeAgentAuthenticatedGitBridgeSession.Snapshot {
        let snapshot = session.close()
        unregisterRegisteredChild()
        terminalStatus = status
        return snapshot
    }

    /// Peer drift is terminal for the connection-owned session. Revalidation
    /// failures must not merely become an XPC error while leaving the child
    /// registry entry usable by a still-running child.
    private func revalidatePeerOrRevoke() throws {
        do {
            try revalidatePeer()
        } catch {
            if let session {
                _ = closeSessionAndRevoke(session)
            } else {
                unregisterRegisteredChild()
            }
            throw error
        }
    }

    private func unregisterRegisteredChild() {
        guard let bindingHash = registeredChildBindingHash else { return }
        registeredChildBindingHash = nil
        childUnregistrar?(bindingHash)
    }

    private func revalidatePeer() throws {
        do {
            try peerBinding.revalidate(
                connectionContext: try peerContextObserver(),
                observation: try peerProcessObserver()
            )
        } catch NativeAgentAuthenticatedGitBridgeError.peerIdentityMismatch {
            throw NativeAgentAuthenticatedHostEndpointError.peerIdentityMismatch
        } catch NativeAgentAuthenticatedGitBridgeError.codeIdentityDenied {
            throw NativeAgentAuthenticatedHostEndpointError.codeIdentityDenied
        } catch {
            throw NativeAgentAuthenticatedHostEndpointError.processIdentityChanged
        }
    }

    private func requireLiveSession() throws {
        guard let session else { throw NativeAgentAuthenticatedHostEndpointError.invalidSessionState }
        let snapshot = try snapshotAndRefreshExpiration(for: session)
        if let terminalStatus {
            switch terminalStatus {
            case .expired: throw NativeAgentAuthenticatedHostEndpointError.expired
            case .revoked: throw NativeAgentAuthenticatedHostEndpointError.revoked
            case .closed: throw NativeAgentAuthenticatedHostEndpointError.endpointClosed
            default: break
            }
        }
        if snapshot.phase == .closed {
            throw NativeAgentAuthenticatedHostEndpointError.endpointClosed
        }
    }

    private func snapshotAndRefreshExpiration(
        for session: NativeAgentAuthenticatedGitBridgeSession
    ) throws -> NativeAgentAuthenticatedGitBridgeSession.Snapshot {
        guard let expirationMilliseconds else {
            throw NativeAgentAuthenticatedHostEndpointError.invalidSessionState
        }
        let now = try validTimestamp(nowMilliseconds())
        if now >= expirationMilliseconds {
            if terminalStatus == nil {
                _ = closeSessionAndRevoke(session, status: .expired)
            }
        }
        return session.snapshot
    }

    private func status(
        for snapshot: NativeAgentAuthenticatedGitBridgeSession.Snapshot
    ) -> AgentPassHostXPCContract.SessionStatus {
        switch snapshot.phase {
        case .new: return .prepared
        case .prepared: return .prepared
        case .attached: return snapshot.requestCount == 0 ? .attached : .active
        case .closed: return terminalStatus ?? .closed
        }
    }

    private func validTimestamp(_ value: Int64) throws -> Int64 {
        guard AgentPassHostXPCContract.isTimestamp(value) else {
            throw NativeAgentAuthenticatedHostEndpointError.invalidRequest
        }
        return value
    }

    private func validExpiration(now: Int64) throws -> Int64 {
        let (expiration, overflow) = now.addingReportingOverflow(sessionLifetimeMilliseconds)
        guard !overflow, AgentPassHostXPCContract.isTimestamp(expiration) else {
            throw NativeAgentAuthenticatedHostEndpointError.invalidRequest
        }
        return expiration
    }

    private func requestCorrelationMatches(
        _ request: AgentPassHostSignRequest,
        consumed: ConsumedSignRequest
    ) -> Bool {
        let requestIDMatches = request.requestID.isEmpty || request.requestID == consumed.requestID
        let createdAtMatches = request.createdAtMilliseconds == 0
            || request.createdAtMilliseconds == consumed.createdAtMilliseconds
        return requestIDMatches && createdAtMatches
    }

    private func mapCoreError(
        _ error: NativeAgentAuthenticatedGitBridgeError
    ) -> NativeAgentAuthenticatedHostEndpointError {
        switch error {
        case .invalidRequest: return .invalidRequest
        case .invalidSessionState: return .invalidSessionState
        case .peerIdentityMismatch: return .peerIdentityMismatch
        case .processIdentityChanged: return .processIdentityChanged
        case .codeIdentityDenied: return .codeIdentityDenied
        case .requestAuthenticationFailed, .requestReplay, .requestSequenceMismatch:
            return .invalidRequest
        case .budgetExhausted:
            return .invalidSessionState
        case .sessionClosed: return .endpointClosed
        }
    }

    private func makeError(_ error: Error) -> NSError {
        let stable: NativeAgentAuthenticatedHostEndpointError
        if let error = error as? NativeAgentAuthenticatedHostEndpointError {
            stable = error
        } else if let error = error as? NativeAgentAuthenticatedGitBridgeError {
            stable = mapCoreError(error)
        } else {
            stable = .invalidRequest
        }
        return NSError(
            domain: Self.errorDomain,
            code: Self.errorCode(stable),
            userInfo: [NSLocalizedDescriptionKey: stable.rawValue]
        )
    }

    private static func errorCode(_ error: NativeAgentAuthenticatedHostEndpointError) -> Int {
        switch error {
        case .invalidRequest: return 1
        case .invalidSessionState: return 2
        case .peerIdentityMismatch: return 3
        case .processIdentityChanged: return 4
        case .codeIdentityDenied: return 5
        case .childIdentityMismatch: return 6
        case .childObservationFailed: return 7
        case .expired: return 8
        case .signerFailed: return 9
        case .endpointClosed: return 10
        case .outcomeUnknown: return 11
        case .revoked: return 12
        }
    }
}
