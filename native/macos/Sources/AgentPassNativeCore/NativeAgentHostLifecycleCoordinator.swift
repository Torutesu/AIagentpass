import Foundation

/// The stable identity available before the service creates an Agent session.
/// It is supplied by the authenticated connection owner and contains no
/// session ID, device ID, proof, credential, process handle, or path.
public struct NativeAgentHostConnectionBinding: Equatable, Hashable, Sendable {
    public let connectionID: String
    public let agentID: String

    public init(connectionID: String, agentID: String) throws {
        guard Self.isSafeConnectionID(connectionID),
              Self.isCanonicalUUID(agentID) else {
            throw NativeAgentHostLifecycleError.invalidIdentity
        }
        self.connectionID = connectionID
        self.agentID = agentID
    }

    private static func isSafeConnectionID(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 128 else { return false }
        return value.unicodeScalars.allSatisfy { scalar in
            (scalar.value >= 48 && scalar.value <= 57)
                || (scalar.value >= 65 && scalar.value <= 90)
                || (scalar.value >= 97 && scalar.value <= 122)
                || scalar.value == 45 || scalar.value == 46
                || scalar.value == 95 || scalar.value == 58
        }
    }

    fileprivate static func isCanonicalUUID(_ value: String) -> Bool {
        value.utf8.count == 36
            && UUID(uuidString: value)?.uuidString.lowercased() == value
    }
}

/// The bounded activation returned by the bootstrap/startAgentSession hook.
/// The Host must not construct a session or device identity before receiving
/// this value from the service.
public struct NativeAgentHostQualifiedSessionActivation: Equatable, Sendable {
    public let sessionID: String
    public let binding: NativeAgentSessionBinding

    public init(sessionID: String, binding: NativeAgentSessionBinding) throws {
        guard NativeAgentHostConnectionBinding.isCanonicalUUID(sessionID) else {
            throw NativeAgentHostLifecycleError.invalidActivation
        }
        self.sessionID = sessionID
        self.binding = binding
    }
}

/// The result of the service-side bootstrap/startAgentSession operation.
/// `rollback` is the service-owned, one-shot cleanup for a session that was
/// created but failed Host-side activation validation. It is intentionally
/// not exposed as a selector or a session-close API; the coordinator can only
/// invoke the exact closure supplied with this receipt, and only on failure.
public final class NativeAgentHostLifecycleBootstrapReceipt: @unchecked Sendable {
    public let activation: NativeAgentHostQualifiedSessionActivation

    private let lock = NSLock()
    private let rollbackClosure: @Sendable () throws -> Void
    private var finalized = false

    public init(
        activation: NativeAgentHostQualifiedSessionActivation,
        rollback: @escaping @Sendable () throws -> Void
    ) {
        self.activation = activation
        self.rollbackClosure = rollback
    }

    fileprivate func finalizeSuccess() {
        lock.lock()
        finalized = true
        lock.unlock()
    }

    fileprivate func rollbackOnce() throws {
        lock.lock()
        guard !finalized else {
            lock.unlock()
            return
        }
        finalized = true
        lock.unlock()
        try rollbackClosure()
    }
}

/// The identity pinned from one validated activation. It has no public
/// initializer: callers cannot invent a session/device pair for lifecycle
/// operations; only the bootstrap return value can create it.
public struct NativeAgentHostQualifiedSessionIdentity: Equatable, Hashable, Sendable {
    public let sessionID: String
    public let agentID: String
    public let deviceID: String

    fileprivate init(
        activation: NativeAgentHostQualifiedSessionActivation,
        expectedAgentID: String
    ) throws {
        guard activation.binding.agentID == expectedAgentID,
              NativeAgentHostConnectionBinding.isCanonicalUUID(activation.binding.deviceID) else {
            throw NativeAgentHostLifecycleError.invalidActivation
        }
        self.sessionID = activation.sessionID
        self.agentID = activation.binding.agentID
        self.deviceID = activation.binding.deviceID
    }
}

/// Non-sensitive handoff metadata derived from the authenticated launch
/// authority. The proof itself never enters this public lifecycle context.
public struct NativeAgentHostLifecycleBootstrapContext: Equatable, Sendable {
    public let adapter: NativeAgentHostAdapterKind
    public let requestedTTLSeconds: Int

    fileprivate init(handoff: NativeAgentLaunchAuthorityHandoff) throws {
        switch handoff.agentKind {
        case .claudeCode:
            self.adapter = .claudeCode
        case .cursor:
            self.adapter = .cursor
        case .generic:
            throw NativeAgentHostLifecycleError.invalidHandoff
        }
        self.requestedTTLSeconds = handoff.requestedTTLSeconds
    }
}

public enum NativeAgentHostAuthorityObservation: String, Codable, Equatable, Sendable {
    case authorized
    case lost
}

public enum NativeAgentHostLifecycleCloseReason: String, Codable, Equatable, Sendable {
    case requested
    case childExited = "child_exited"
    case authorityLost = "authority_lost"
    case authorityUnavailable = "authority_unavailable"
    case startFailed = "start_failed"
}

public enum NativeAgentHostLifecycleState: String, Codable, Equatable, Sendable {
    case new
    case bootstrapping
    case bootstrapped
    case starting
    case running
    case checkingAuthority = "checking_authority"
    case waitingForChild = "waiting_for_child"
    case closing
    case closed
    case failed
}

/// Stable, secret-free public outcomes. Raw process exit codes, signal
/// numbers, errno values, paths, and injected hook errors do not cross this
/// boundary.
public enum NativeAgentHostLifecycleOutcome: String, Codable, Equatable, Sendable {
    case bootstrapped
    case started
    case authorityConfirmed = "authority_confirmed"
    case childExited = "child_exited"
    case closed
    case authorityLost = "authority_lost"
}

public struct NativeAgentHostLifecycleResult: Codable, Equatable, Sendable {
    public let outcome: NativeAgentHostLifecycleOutcome
    public let childExit: NativeAgentHostExitClassification?

    fileprivate init(
        outcome: NativeAgentHostLifecycleOutcome,
        childExit: NativeAgentHostExitClassification? = nil
    ) {
        self.outcome = outcome
        self.childExit = childExit
    }
}

/// All failures exposed by the coordinator are closed and stable. In
/// particular, no injected error description or OS diagnostic is forwarded.
public enum NativeAgentHostLifecycleError: String, Error, Codable, Equatable, Sendable {
    case invalidIdentity = "invalid_identity"
    case invalidHandoff = "invalid_handoff"
    case invalidActivation = "invalid_activation"
    case bootstrapCleanupFailed = "bootstrap_cleanup_failed"
    case bootstrapRequired = "bootstrap_required"
    case bootstrapAlreadyAttempted = "bootstrap_already_attempted"
    case operationInProgress = "operation_in_progress"
    case bootstrapDenied = "bootstrap_denied"
    case startAlreadyAttempted = "start_already_attempted"
    case authorityUnavailable = "authority_unavailable"
    case authorityDenied = "authority_denied"
    case invalidLaunchRequest = "invalid_launch_request"
    case launchFailed = "launch_failed"
    case signalFailed = "signal_failed"
    case waitFailed = "wait_failed"
    case sessionCloseFailed = "session_close_failed"
    case notRunning = "not_running"
    case alreadyClosed = "already_closed"
}

/// Stable failures for the Host-side private Git bridge boundary. The bridge
/// carries only the Git payload; the supplied signer closure remains the
/// authenticated same-connection Host operation that constructs the native
/// signing request.
public enum NativeAgentHostPrivateGitBridgeError: String, Error, Codable, Equatable, Sendable {
    case notRunning = "not_running"
    case alreadyAttempted = "already_attempted"
    case authorityLost = "authority_lost"
    case authorityUnavailable = "authority_unavailable"
    case transportFailed = "transport_failed"
    case cancelled
}

/// Injected side effects for the lifecycle boundary. The coordinator owns all
/// ordering and state transitions; hooks only observe or perform one bounded
/// external action. Callers that need to consume the private handoff may close
/// over it in `bootstrap`, but it is deliberately absent from this context and
/// from all public results/errors.
public struct NativeAgentHostLifecycleCoordinatorHooks: @unchecked Sendable {
    public let bootstrap: @Sendable (
        NativeAgentHostConnectionBinding,
        NativeAgentHostLifecycleBootstrapContext
    ) throws -> NativeAgentHostLifecycleBootstrapReceipt
    public let reobserveAuthority: @Sendable (
        NativeAgentHostQualifiedSessionIdentity
    ) throws -> NativeAgentHostAuthorityObservation
    public let close: @Sendable (
        NativeAgentHostQualifiedSessionIdentity,
        NativeAgentHostLifecycleCloseReason
    ) throws -> Void

    public init(
        bootstrap: @escaping @Sendable (
            NativeAgentHostConnectionBinding,
            NativeAgentHostLifecycleBootstrapContext
        ) throws -> NativeAgentHostLifecycleBootstrapReceipt,
        reobserveAuthority: @escaping @Sendable (
            NativeAgentHostQualifiedSessionIdentity
        ) throws -> NativeAgentHostAuthorityObservation,
        close: @escaping @Sendable (
            NativeAgentHostQualifiedSessionIdentity,
            NativeAgentHostLifecycleCloseReason
        ) throws -> Void
    ) {
        self.bootstrap = bootstrap
        self.reobserveAuthority = reobserveAuthority
        self.close = close
    }
}

/// In-memory coordinator for one Host child and one qualified session.
///
/// The coordinator has no persistence and no asynchronous worker. A caller
/// must explicitly call `waitForChild` or `close`; both paths close the
/// qualified session. `reobserveAndReconcileAuthority` is the explicit hook
/// for a Host event loop to react to authority loss while the child runs.
public final class NativeAgentHostLifecycleCoordinator: @unchecked Sendable {
    private enum StorageState {
        case new
        case bootstrapping
        case bootstrapped
        case starting
        case running(NativeAgentHostChildSession)
        case checkingAuthority(NativeAgentHostChildSession?)
        case waitingForChild(NativeAgentHostChildSession)
        case closing(NativeAgentHostChildSession?)
        case closed
        case failed
    }

    private enum AuthorityCheck: Equatable {
        case authorized
        case lost
        case unavailable
    }

    private let connectionBinding: NativeAgentHostConnectionBinding
    private let context: NativeAgentHostLifecycleBootstrapContext
    private let supervisor: NativeAgentHostChildSupervisor
    private let gitTransport: NativeAgentHostGitTransport
    private let hooks: NativeAgentHostLifecycleCoordinatorHooks
    private let lock = NSLock()
    private var storageState: StorageState = .new
    private var pinnedIdentity: NativeAgentHostQualifiedSessionIdentity?
    private var privateGitBridgeServer: NativeAgentPrivateGitBridgeServer?
    private var privateGitBridgeAttempted = false
    private var privateGitBridgeCancelRequested = false
    private var privateGitBridgeAuthorityFailure: NativeAgentHostPrivateGitBridgeError?

    public init(
        connectionBinding: NativeAgentHostConnectionBinding,
        handoff: NativeAgentLaunchAuthorityHandoff,
        supervisor: NativeAgentHostChildSupervisor,
        hooks: NativeAgentHostLifecycleCoordinatorHooks,
        gitTransport: NativeAgentHostGitTransport = .legacyFD3
    ) throws {
        guard handoff.agentID == connectionBinding.agentID else {
            throw NativeAgentHostLifecycleError.invalidHandoff
        }
        self.connectionBinding = connectionBinding
        self.context = try NativeAgentHostLifecycleBootstrapContext(handoff: handoff)
        self.supervisor = supervisor
        self.hooks = hooks
        self.gitTransport = gitTransport
    }

    public var state: NativeAgentHostLifecycleState {
        lock.lock()
        defer { lock.unlock() }
        switch storageState {
        case .new: return .new
        case .bootstrapping: return .bootstrapping
        case .bootstrapped: return .bootstrapped
        case .starting: return .starting
        case .running: return .running
        case .checkingAuthority: return .checkingAuthority
        case .waitingForChild: return .waitingForChild
        case .closing: return .closing
        case .closed: return .closed
        case .failed: return .failed
        }
    }

    public func bootstrap() throws -> NativeAgentHostLifecycleResult {
        lock.lock()
        switch storageState {
        case .new:
            storageState = .bootstrapping
            lock.unlock()
        case .bootstrapping:
            lock.unlock()
            throw NativeAgentHostLifecycleError.operationInProgress
        default:
            lock.unlock()
            throw NativeAgentHostLifecycleError.bootstrapAlreadyAttempted
        }

        let receipt: NativeAgentHostLifecycleBootstrapReceipt
        do {
            receipt = try hooks.bootstrap(connectionBinding, context)
        } catch {
            lock.lock()
            storageState = .failed
            lock.unlock()
            throw NativeAgentHostLifecycleError.bootstrapDenied
        }

        let validatedIdentity: NativeAgentHostQualifiedSessionIdentity
        do {
            validatedIdentity = try NativeAgentHostQualifiedSessionIdentity(
                activation: receipt.activation,
                expectedAgentID: connectionBinding.agentID
            )
        } catch {
            do {
                try receipt.rollbackOnce()
            } catch {
                lock.lock()
                storageState = .failed
                lock.unlock()
                throw NativeAgentHostLifecycleError.bootstrapCleanupFailed
            }
            lock.lock()
            storageState = .failed
            lock.unlock()
            throw NativeAgentHostLifecycleError.invalidActivation
        }

        lock.lock()
        pinnedIdentity = validatedIdentity
        receipt.finalizeSuccess()
        storageState = .bootstrapped
        lock.unlock()
        return NativeAgentHostLifecycleResult(outcome: .bootstrapped)
    }

    public func start(
        projectDirectory: NativeAgentHostProjectDirectory,
        trustedEnvironment: [String: String] = [:]
    ) throws -> NativeAgentHostLifecycleResult {
        lock.lock()
        switch storageState {
        case .bootstrapped:
            storageState = .starting
            lock.unlock()
        case .new:
            lock.unlock()
            throw NativeAgentHostLifecycleError.bootstrapRequired
        case .bootstrapping, .starting, .checkingAuthority, .waitingForChild, .closing:
            lock.unlock()
            throw NativeAgentHostLifecycleError.operationInProgress
        case .running, .closed, .failed:
            lock.unlock()
            throw NativeAgentHostLifecycleError.startAlreadyAttempted
        }

        let observation = observeAuthority()
        switch observation {
        case .lost:
            let cleanupError = finishStartingFailure(
                reason: .authorityLost,
                authorityAlreadyObserved: true
            )
            if let cleanupError { throw cleanupError }
            throw NativeAgentHostLifecycleError.authorityDenied
        case .unavailable:
            let cleanupError = finishStartingFailure(
                reason: .authorityUnavailable,
                authorityAlreadyObserved: true
            )
            if let cleanupError { throw cleanupError }
            throw NativeAgentHostLifecycleError.authorityUnavailable
        case .authorized:
            break
        }

        let request: NativeAgentHostChildLaunchRequest
        do {
            request = try NativeAgentHostChildLaunchRequest(
                adapter: context.adapter,
                projectDirectory: projectDirectory,
                trustedEnvironment: trustedEnvironment,
                gitTransport: gitTransport
            )
        } catch {
            let cleanupError = finishStartingFailure(
                reason: .startFailed,
                authorityAlreadyObserved: false
            )
            if let cleanupError { throw cleanupError }
            throw NativeAgentHostLifecycleError.invalidLaunchRequest
        }

        let child: NativeAgentHostChildSession
        do {
            child = try supervisor.start(request)
        } catch {
            let cleanupError = finishStartingFailure(
                reason: .startFailed,
                authorityAlreadyObserved: false
            )
            if let cleanupError { throw cleanupError }
            throw NativeAgentHostLifecycleError.launchFailed
        }

        lock.lock()
        storageState = .running(child)
        lock.unlock()
        return NativeAgentHostLifecycleResult(outcome: .started)
    }

    /// Serves one request from the child-side FD3 Git helper.
    ///
    /// The signer closure is the Host's already-authenticated same-connection
    /// operation. It receives only the bounded Git payload; callers cannot
    /// supply a session, capability, key, algorithm, repository, or policy
    /// selector through this bridge. Authority is re-observed immediately
    /// before serving and again immediately before signer invocation.
    ///
    /// A bridge failure is terminal for the lifecycle: the private transport
    /// is closed, the child is reaped, and the qualified native session is
    /// closed before this method returns an error.
    public func servePrivateGitBridge(
        signGitCommit: @escaping NativeAgentPrivateGitBridgeServer.Signer
    ) throws {
        switch observeAuthority() {
        case .authorized:
            break
        case .lost:
            closeForPrivateGitBridgeAuthorityFailure(.authorityLost)
            throw NativeAgentHostPrivateGitBridgeError.authorityLost
        case .unavailable:
            closeForPrivateGitBridgeAuthorityFailure(.authorityUnavailable)
            throw NativeAgentHostPrivateGitBridgeError.authorityUnavailable
        }

        let server: NativeAgentPrivateGitBridgeServer
        lock.lock()
        guard case .running(let child) = storageState else {
            let error: NativeAgentHostPrivateGitBridgeError = switch storageState {
            case .closed, .failed: .cancelled
            default: .notRunning
            }
            lock.unlock()
            throw error
        }
        guard !privateGitBridgeAttempted else {
            lock.unlock()
            throw NativeAgentHostPrivateGitBridgeError.alreadyAttempted
        }
        guard let transport = child.privateGitBridgeHostEndpoint else {
            lock.unlock()
            throw NativeAgentHostPrivateGitBridgeError.notRunning
        }
        privateGitBridgeAttempted = true
        privateGitBridgeCancelRequested = false
        privateGitBridgeAuthorityFailure = nil
        server = NativeAgentPrivateGitBridgeServer(
            transport: transport,
            signer: { [weak self] payload in
                guard let self else {
                    throw NativeAgentHostPrivateGitBridgeError.cancelled
                }
                try self.reobservePrivateGitBridgeAuthority()
                return try signGitCommit(payload)
            }
        )
        privateGitBridgeServer = server
        lock.unlock()

        var terminalError: Error?
        do {
            try server.serve()
        } catch {
            terminalError = error
        }

        if let terminalError {
            let (cancelled, authorityFailure) = clearPrivateGitBridgeServer(server)
            if !cancelled {
                if let authorityFailure {
                    closeForPrivateGitBridgeAuthorityFailure(authorityFailure)
                } else if let terminalError = terminalError as? NativeAgentHostPrivateGitBridgeError,
                          terminalError == .authorityLost {
                    closeForPrivateGitBridgeAuthorityFailure(.authorityLost)
                } else if let terminalError = terminalError as? NativeAgentHostPrivateGitBridgeError,
                          terminalError == .authorityUnavailable {
                    closeForPrivateGitBridgeAuthorityFailure(.authorityUnavailable)
                } else {
                    _ = try? close()
                }
            }
            if let authorityFailure {
                throw authorityFailure
            }
            if cancelled {
                throw NativeAgentHostPrivateGitBridgeError.cancelled
            }
            if let terminalError = terminalError as? NativeAgentHostPrivateGitBridgeError {
                throw terminalError
            }
            throw NativeAgentHostPrivateGitBridgeError.transportFailed
        }

        let (cancelled, authorityFailure) = clearPrivateGitBridgeServer(server)
        if let authorityFailure {
            closeForPrivateGitBridgeAuthorityFailure(authorityFailure)
            throw authorityFailure
        }
        if cancelled {
            throw NativeAgentHostPrivateGitBridgeError.cancelled
        }
    }

    private func reobservePrivateGitBridgeAuthority() throws {
        switch observeAuthority() {
        case .authorized:
            lock.lock()
            let running: Bool
            if case .running = storageState {
                running = true
            } else {
                running = false
            }
            let cancelled = privateGitBridgeCancelRequested || privateGitBridgeServer == nil
            let recordedFailure = privateGitBridgeAuthorityFailure
            lock.unlock()
            if let recordedFailure {
                throw recordedFailure
            }
            guard running, !cancelled else {
                throw NativeAgentHostPrivateGitBridgeError.cancelled
            }
        case .lost:
            lock.lock()
            privateGitBridgeAuthorityFailure = .authorityLost
            lock.unlock()
            throw NativeAgentHostPrivateGitBridgeError.authorityLost
        case .unavailable:
            lock.lock()
            privateGitBridgeAuthorityFailure = .authorityUnavailable
            lock.unlock()
            throw NativeAgentHostPrivateGitBridgeError.authorityUnavailable
        }
    }

    private func clearPrivateGitBridgeServer(
        _ server: NativeAgentPrivateGitBridgeServer
    ) -> (cancelled: Bool, authorityFailure: NativeAgentHostPrivateGitBridgeError?) {
        lock.lock()
        defer { lock.unlock() }
        guard privateGitBridgeServer === server else {
            return (true, nil)
        }
        privateGitBridgeServer = nil
        let cancelled = privateGitBridgeCancelRequested
            || !(ifRunning(storageState))
        return (cancelled, privateGitBridgeAuthorityFailure)
    }

    private func ifRunning(_ state: StorageState) -> Bool {
        if case .running = state { return true }
        return false
    }

    private func cancelPrivateGitBridge() {
        lock.lock()
        let server = privateGitBridgeServer
        if server != nil {
            privateGitBridgeCancelRequested = true
            privateGitBridgeServer = nil
        }
        lock.unlock()
        server?.cancel()
    }

    private func closeForPrivateGitBridgeAuthorityFailure(
        _ failure: NativeAgentHostPrivateGitBridgeError
    ) {
        let reason: NativeAgentHostLifecycleCloseReason
        let outcome: NativeAgentHostLifecycleOutcome
        switch failure {
        case .authorityLost:
            reason = .authorityLost
            outcome = .authorityLost
        case .authorityUnavailable:
            reason = .authorityUnavailable
            outcome = .childExited
        default:
            _ = try? close()
            return
        }

        guard let child = try? reserveClose() else { return }
        _ = try? finishReservedClose(
            child: child,
            reason: reason,
            authorityAlreadyObserved: true,
            terminateChild: true,
            resultOutcome: outcome
        )
    }

    /// Re-observes authority while the child is running. A lost or unavailable
    /// authority is fail-closed: terminate, reap, close the session, then
    /// report only a bounded outcome/error.
    public func reobserveAndReconcileAuthority() throws -> NativeAgentHostLifecycleResult {
        let child: NativeAgentHostChildSession?
        lock.lock()
        switch storageState {
        case .bootstrapped:
            child = nil
            storageState = .checkingAuthority(nil)
            lock.unlock()
        case .running(let runningChild):
            child = runningChild
            storageState = .checkingAuthority(runningChild)
            lock.unlock()
        case .new, .bootstrapping, .starting:
            lock.unlock()
            throw NativeAgentHostLifecycleError.notRunning
        case .checkingAuthority, .waitingForChild, .closing:
            lock.unlock()
            throw NativeAgentHostLifecycleError.operationInProgress
        case .closed, .failed:
            lock.unlock()
            throw NativeAgentHostLifecycleError.alreadyClosed
        }

        switch observeAuthority() {
        case .authorized:
            lock.lock()
            if let child {
                storageState = .running(child)
            } else {
                storageState = .bootstrapped
            }
            lock.unlock()
            return NativeAgentHostLifecycleResult(outcome: .authorityConfirmed)
        case .lost:
            cancelPrivateGitBridge()
            return try finishReservedClose(
                child: child,
                reason: .authorityLost,
                authorityAlreadyObserved: true,
                terminateChild: child != nil,
                resultOutcome: .authorityLost
            )
        case .unavailable:
            cancelPrivateGitBridge()
            let cleanup = try? finishReservedClose(
                child: child,
                reason: .authorityUnavailable,
                authorityAlreadyObserved: true,
                terminateChild: child != nil,
                resultOutcome: .authorityLost
            )
            _ = cleanup
            throw NativeAgentHostLifecycleError.authorityUnavailable
        }
    }

    /// Closes a bootstrapped or running session. Authority is re-observed
    /// before the close hook. A running child is terminated and reaped first.
    public func close() throws -> NativeAgentHostLifecycleResult {
        let child = try reserveClose()
        return try finishReservedClose(
            child: child,
            reason: .requested,
            authorityAlreadyObserved: false,
            terminateChild: child != nil,
            resultOutcome: .closed
        )
    }

    /// Waits for the child, then always closes the qualified session. No
    /// unbounded exit information crosses the API.
    public func waitForChild() throws -> NativeAgentHostLifecycleResult {
        let child: NativeAgentHostChildSession
        lock.lock()
        guard case .running(let runningChild) = storageState else {
            let error: NativeAgentHostLifecycleError = switch storageState {
            case .closed, .failed: .alreadyClosed
            case .checkingAuthority, .waitingForChild, .closing: .operationInProgress
            default: .notRunning
            }
            lock.unlock()
            throw error
        }
        child = runningChild
        storageState = .waitingForChild(runningChild)
        lock.unlock()

        cancelPrivateGitBridge()

        let exit: NativeAgentHostExitClassification?
        var waitFailed = false
        do {
            exit = try child.wait()
        } catch {
            exit = nil
            waitFailed = true
        }

        let closeResult: NativeAgentHostLifecycleResult
        do {
            closeResult = try finishWaitingChild(
                child: child,
                childExit: exit,
                authorityAlreadyObserved: false
            )
        } catch let error as NativeAgentHostLifecycleError {
            throw error
        } catch {
            throw NativeAgentHostLifecycleError.sessionCloseFailed
        }
        if waitFailed {
            throw NativeAgentHostLifecycleError.waitFailed
        }
        return closeResult
    }

    private func observeAuthority() -> AuthorityCheck {
        guard let identity = pinnedIdentitySnapshot() else {
            return .unavailable
        }
        do {
            switch try hooks.reobserveAuthority(identity) {
            case .authorized: return .authorized
            case .lost: return .lost
            }
        } catch {
            return .unavailable
        }
    }

    private func finishStartingFailure(
        reason: NativeAgentHostLifecycleCloseReason,
        authorityAlreadyObserved: Bool
    ) -> NativeAgentHostLifecycleError? {
        lock.lock()
        guard case .starting = storageState else {
            lock.unlock()
            return .operationInProgress
        }
        storageState = .closing(nil)
        lock.unlock()

        var effectiveReason = reason
        if !authorityAlreadyObserved {
            switch observeAuthority() {
            case .authorized: break
            case .lost: effectiveReason = .authorityLost
            case .unavailable: effectiveReason = .authorityUnavailable
            }
        }

        do {
            guard let identity = pinnedIdentitySnapshot() else {
                throw NativeAgentHostLifecycleError.invalidActivation
            }
            try hooks.close(identity, effectiveReason)
        } catch {
            lock.lock()
            storageState = .closed
            lock.unlock()
            return .sessionCloseFailed
        }
        lock.lock()
        storageState = .closed
        lock.unlock()
        return nil
    }

    private func reserveClose() throws -> NativeAgentHostChildSession? {
        lock.lock()
        switch storageState {
        case .bootstrapped:
            storageState = .closing(nil)
            lock.unlock()
            return nil
        case .running(let child):
            storageState = .closing(child)
            lock.unlock()
            return child
        case .new, .bootstrapping, .starting:
            lock.unlock()
            throw NativeAgentHostLifecycleError.notRunning
        case .checkingAuthority, .waitingForChild, .closing:
            lock.unlock()
            throw NativeAgentHostLifecycleError.operationInProgress
        case .closed, .failed:
            lock.unlock()
            throw NativeAgentHostLifecycleError.alreadyClosed
        }
    }

    private func finishWaitingChild(
        child: NativeAgentHostChildSession,
        childExit: NativeAgentHostExitClassification?,
        authorityAlreadyObserved: Bool
    ) throws -> NativeAgentHostLifecycleResult {
        switch observeForClose(alreadyObserved: authorityAlreadyObserved) {
        case .lost:
            return try closeSession(
                child: child,
                childExit: childExit,
                reason: .authorityLost,
                terminateChild: false,
                outcome: .authorityLost
            )
        case .unavailable:
            return try closeSession(
                child: child,
                childExit: childExit,
                reason: .authorityUnavailable,
                terminateChild: false,
                outcome: .childExited
            )
        case .authorized:
            return try closeSession(
                child: child,
                childExit: childExit,
                reason: .childExited,
                terminateChild: false,
                outcome: .childExited
            )
        }
    }

    private func finishReservedClose(
        child: NativeAgentHostChildSession?,
        reason: NativeAgentHostLifecycleCloseReason,
        authorityAlreadyObserved: Bool,
        terminateChild: Bool,
        resultOutcome: NativeAgentHostLifecycleOutcome
    ) throws -> NativeAgentHostLifecycleResult {
        let observation = observeForClose(alreadyObserved: authorityAlreadyObserved)
        let effectiveReason: NativeAgentHostLifecycleCloseReason
        switch observation {
        case .authorized: effectiveReason = reason
        case .lost: effectiveReason = .authorityLost
        case .unavailable: effectiveReason = .authorityUnavailable
        }
        return try closeSession(
            child: child,
            childExit: nil,
            reason: effectiveReason,
            terminateChild: terminateChild,
            outcome: observation == .lost ? .authorityLost : resultOutcome
        )
    }

    private func observeForClose(alreadyObserved: Bool) -> AuthorityCheck {
        alreadyObserved ? .authorized : observeAuthority()
    }

    private func pinnedIdentitySnapshot() -> NativeAgentHostQualifiedSessionIdentity? {
        lock.lock()
        defer { lock.unlock() }
        return pinnedIdentity
    }

    private func closeSession(
        child: NativeAgentHostChildSession?,
        childExit: NativeAgentHostExitClassification?,
        reason: NativeAgentHostLifecycleCloseReason,
        terminateChild: Bool,
        outcome: NativeAgentHostLifecycleOutcome
    ) throws -> NativeAgentHostLifecycleResult {
        cancelPrivateGitBridge()
        var cleanupError: NativeAgentHostLifecycleError?

        if terminateChild, let child {
            do {
                try child.forward(.terminate)
            } catch {
                cleanupError = .signalFailed
            }
            do {
                _ = try child.wait()
            } catch where cleanupError == nil {
                cleanupError = .waitFailed
            } catch {
                // A prior signal error is retained as the bounded cause.
            }
        }

        do {
            guard let identity = pinnedIdentitySnapshot() else {
                throw NativeAgentHostLifecycleError.invalidActivation
            }
            try hooks.close(identity, reason)
        } catch where cleanupError == nil {
            cleanupError = .sessionCloseFailed
        } catch {
            // Preserve the first bounded cleanup failure.
        }

        lock.lock()
        storageState = .closed
        lock.unlock()

        if let cleanupError { throw cleanupError }
        return NativeAgentHostLifecycleResult(outcome: outcome, childExit: childExit)
    }
}
