import Darwin
import Foundation

/// Stable, secret-free failures for the private Git bridge socket-pair
/// ownership boundary.
public enum NativeAgentPrivateGitBridgeSocketPairError: Error, Equatable, Sendable {
    case socketPairFailed(Int32)
    case invalidSocketPair
    case reviewedTargetCollision
    case descriptorFlagsFailed(Int32, Int32)
    case leaseAlreadyIssued
    case leaseAlreadyResolved
    case fileActionsNotInstalled
    case fileActionsAlreadyInstalled
    case leaseBusy
    case alreadyClosed
    case closeFailed(Int32)
}

/// The single-use child-side handoff specification.
///
/// The source descriptor is intentionally not a public property or a public
/// selector. A Host supervisor in the same native integration can pass it to
/// `posix_spawn_file_actions_adddup2` and
/// `posix_spawn_file_actions_addclose` through
/// `addToSpawnFileActions(addDuplicate:addClose:)`. The callback receives the
/// source only while those two file actions are being registered, and the
/// fixed target is always the reviewed descriptor 3.
///
/// The lease must be committed only after `posix_spawn` succeeds. If file
/// action construction or spawning fails, abort it. Neither operation can be
/// repeated.
public final class NativeAgentPrivateGitBridgeChildEndpointHandoff: @unchecked Sendable {
    public typealias FileActionClosure = @Sendable (Int32, Int32) throws -> Void
    public typealias CloseActionClosure = @Sendable (Int32) throws -> Void

    private enum State {
        case pending
        case installingFileActions
        case readyToCommit
        case resolving
        case resolved
    }

    private let sourceDescriptor: Int32
    private let fixedTargetDescriptor: Int32
    private let commitHandler: @Sendable () throws -> Void
    private let abortHandler: @Sendable () throws -> Void
    private let stateLock = NSLock()
    private var state: State = .pending

    fileprivate init(
        sourceDescriptor: Int32,
        fixedTargetDescriptor: Int32,
        commit: @escaping @Sendable () throws -> Void,
        abort: @escaping @Sendable () throws -> Void
    ) {
        self.sourceDescriptor = sourceDescriptor
        self.fixedTargetDescriptor = fixedTargetDescriptor
        self.commitHandler = commit
        self.abortHandler = abort
    }

    /// Registers exactly the two reviewed child-only file actions:
    /// `adddup2(source, 3)` followed by `addclose(source)`.
    ///
    /// The callbacks are supplied by the spawn supervisor because this
    /// disjoint Core primitive does not own the `posix_spawn_file_actions_t`.
    /// A callback failure immediately aborts the lease and closes both socket
    /// endpoints. If `addDuplicate` succeeded and `addClose` failed, the
    /// caller's file-actions object contains a partial action list; the caller
    /// must destroy/discard that object and must not call `posix_spawn`.
    /// This method never mutates the parent process's FD table.
    public func addToSpawnFileActions(
        addDuplicate: @escaping FileActionClosure,
        addClose: @escaping CloseActionClosure
    ) throws {
        stateLock.lock()
        guard state == .pending else {
            let error: NativeAgentPrivateGitBridgeSocketPairError =
                state == .readyToCommit || state == .installingFileActions
                    ? .fileActionsAlreadyInstalled
                    : .leaseAlreadyResolved
            stateLock.unlock()
            throw error
        }
        state = .installingFileActions
        stateLock.unlock()

        do {
            try addDuplicate(sourceDescriptor, fixedTargetDescriptor)
            try addClose(sourceDescriptor)
        } catch {
            stateLock.lock()
            state = .resolving
            stateLock.unlock()
            try? abortHandler()
            stateLock.lock()
            state = .resolved
            stateLock.unlock()
            throw error
        }

        stateLock.lock()
        state = .readyToCommit
        stateLock.unlock()
    }

    /// Commits a successful child spawn. The parent source is closed by the
    /// owning socket-pair session; the Host endpoint remains available.
    public func commit() throws {
        stateLock.lock()
        guard state == .readyToCommit else {
            let error: NativeAgentPrivateGitBridgeSocketPairError =
                state == .resolved || state == .resolving
                    ? .leaseAlreadyResolved
                    : .fileActionsNotInstalled
            stateLock.unlock()
            throw error
        }
        state = .resolving
        stateLock.unlock()

        do {
            try commitHandler()
        } catch {
            stateLock.lock()
            state = .resolved
            stateLock.unlock()
            throw error
        }

        stateLock.lock()
        state = .resolved
        stateLock.unlock()
    }

    /// Aborts the handoff and closes both the child and Host endpoints.
    /// Aborting a lease before file-action installation is valid and is the
    /// required cleanup path when preparing the spawn itself fails.
    public func abort() throws {
        stateLock.lock()
        guard state == .pending || state == .readyToCommit else {
            let error: NativeAgentPrivateGitBridgeSocketPairError =
                state == .installingFileActions
                    ? .leaseBusy
                    : .leaseAlreadyResolved
            stateLock.unlock()
            throw error
        }
        state = .resolving
        stateLock.unlock()

        do {
            try abortHandler()
        } catch {
            stateLock.lock()
            state = .resolved
            stateLock.unlock()
            throw error
        }

        stateLock.lock()
        state = .resolved
        stateLock.unlock()
    }
}

/// Owns one Host endpoint and one not-yet-inherited child endpoint of a
/// private, unnamed AF_UNIX stream socket pair.
///
/// Both descriptors are marked close-on-exec before this object becomes
/// visible. This type never calls `dup2` and never probes a parent fixed FD.
/// Instead it issues one opaque child endpoint lease whose file actions are
/// applied by the child side of `posix_spawn`. The parent source is closed
/// only by `commit()` after a successful spawn.
///
/// The type is intentionally independent from the Host lifecycle coordinator
/// and from the AgentHost executable. Its Host endpoint is directly reusable
/// with `NativeAgentPrivateFDTransport` consumers such as the private Git
/// bridge server.
public final class NativeAgentPrivateGitBridgeSocketPair: @unchecked Sendable {
    public static let reviewedChildFileDescriptor: Int32 = 3

    public typealias SocketPairClosure = @Sendable (
        Int32,
        Int32,
        Int32,
        UnsafeMutablePointer<Int32>
    ) -> Int32
    public typealias FcntlClosure = @Sendable (Int32, Int32, Int32) -> Int32
    public typealias CloseClosure = @Sendable (Int32) -> Int32

    /// Injected syscalls keep descriptor ownership deterministic in tests.
    /// There is deliberately no parent `dup2` hook and no fixed-target probe
    /// hook: those operations are forbidden by this primitive's contract.
    public struct Syscalls: Sendable {
        public let socketPair: SocketPairClosure
        public let fcntl: FcntlClosure
        public let close: CloseClosure

        public init(
            socketPair: @escaping SocketPairClosure,
            fcntl: @escaping FcntlClosure,
            close: @escaping CloseClosure
        ) {
            self.socketPair = socketPair
            self.fcntl = fcntl
            self.close = close
        }

        public static let live = Syscalls(
            socketPair: { domain, type, protocolNumber, descriptors in
                Darwin.socketpair(domain, type, protocolNumber, descriptors)
            },
            fcntl: { descriptor, command, argument in
                Darwin.fcntl(descriptor, command, argument)
            },
            close: { descriptor in
                Darwin.close(descriptor)
            })
    }

    /// The Host side of the pair. It owns this descriptor and can be passed
    /// directly to `NativeAgentPrivateGitBridgeServer`.
    public let hostEndpoint: NativeAgentPrivateFDTransport

    /// The raw Host descriptor is exposed only for Host integration; it is not
    /// a child endpoint selector.
    public let hostFileDescriptor: Int32

    private var childFileDescriptor: Int32?
    private let syscalls: Syscalls
    private let stateLock = NSLock()
    private var leaseIssued = false
    private var closed = false

    public convenience init() throws {
        try self.init(syscalls: .live)
    }

    /// Creates a socket pair using explicitly supplied syscalls. The socket
    /// has no filesystem pathname and no ancillary authority metadata.
    public init(syscalls: Syscalls) throws {
        var descriptors: [Int32] = [-1, -1]
        let result = descriptors.withUnsafeMutableBufferPointer { buffer in
            syscalls.socketPair(
                Int32(AF_UNIX),
                Int32(SOCK_STREAM),
                0,
                buffer.baseAddress!)
        }

        guard result == 0 else {
            let socketError = Self.currentErrno()
            // A failed socketpair call transfers no descriptor ownership.
            // Its output array is not an authority to close arbitrary FD
            // numbers, even if a test double or future platform mutates it.
            throw NativeAgentPrivateGitBridgeSocketPairError.socketPairFailed(
                socketError)
        }

        guard descriptors[0] >= 0,
              descriptors[1] >= 0,
              descriptors[0] != descriptors[1] else {
            Self.closeUnique(descriptors, using: syscalls.close)
            throw NativeAgentPrivateGitBridgeSocketPairError.invalidSocketPair
        }

        // The child endpoint is the source of the child-only adddup2 action.
        // If the kernel allocates it as FD 3, adddup2(3, 3) would be a no-op
        // followed by addclose(3), so reject the pair before issuing a lease.
        // This is an allocation result check, not a parent target probe.
        guard descriptors[1] != Self.reviewedChildFileDescriptor else {
            Self.closeUnique(descriptors, using: syscalls.close)
            throw NativeAgentPrivateGitBridgeSocketPairError.reviewedTargetCollision
        }

        do {
            try Self.setCloseOnExec(descriptor: descriptors[0], using: syscalls.fcntl)
            try Self.setCloseOnExec(descriptor: descriptors[1], using: syscalls.fcntl)
        } catch {
            Self.closeUnique(descriptors, using: syscalls.close)
            throw error
        }

        do {
            self.hostEndpoint = try NativeAgentPrivateFDTransport(
                fd: descriptors[0],
                ownership: .owned,
                read: { descriptor, buffer, count in
                    Darwin.read(descriptor, buffer, count)
                },
                write: { descriptor, buffer, count in
                    Darwin.write(descriptor, buffer, count)
                },
                close: syscalls.close,
                shutdownWrite: { descriptor in
                    Darwin.shutdown(descriptor, SHUT_WR)
                })
        } catch {
            Self.closeUnique(descriptors, using: syscalls.close)
            throw error
        }

        self.hostFileDescriptor = descriptors[0]
        self.childFileDescriptor = descriptors[1]
        self.syscalls = syscalls
    }

    /// Issues exactly one opaque child endpoint lease. No parent FD is
    /// duplicated or probed here. The supervisor must install the lease's
    /// child-only file actions before committing it after `posix_spawn`.
    public func prepareChildEndpointHandoff() throws
        -> NativeAgentPrivateGitBridgeChildEndpointHandoff
    {
        stateLock.lock()
        guard !closed else {
            stateLock.unlock()
            throw NativeAgentPrivateGitBridgeSocketPairError.alreadyClosed
        }
        guard !leaseIssued else {
            stateLock.unlock()
            throw NativeAgentPrivateGitBridgeSocketPairError.leaseAlreadyIssued
        }
        guard let child = childFileDescriptor else {
            stateLock.unlock()
            throw NativeAgentPrivateGitBridgeSocketPairError.leaseAlreadyIssued
        }
        leaseIssued = true
        stateLock.unlock()

        return NativeAgentPrivateGitBridgeChildEndpointHandoff(
            sourceDescriptor: child,
            fixedTargetDescriptor: Self.reviewedChildFileDescriptor,
            commit: { [self] in
                try commitChildEndpoint(source: child)
            },
            abort: { [self] in
                try abortChildEndpoint(source: child)
            })
    }

    /// Closes the Host endpoint and any child endpoint still owned by this
    /// object. It is idempotent, including after a cleanup error.
    public func close() throws {
        stateLock.lock()
        guard !closed else {
            stateLock.unlock()
            return
        }
        closed = true
        let child = childFileDescriptor
        childFileDescriptor = nil
        stateLock.unlock()

        if let closeError = closeOwnedDescriptors(child: child) {
            throw NativeAgentPrivateGitBridgeSocketPairError.closeFailed(closeError)
        }
    }

    deinit {
        try? close()
    }

    private func commitChildEndpoint(source: Int32) throws {
        stateLock.lock()
        guard !closed, childFileDescriptor == source else {
            stateLock.unlock()
            throw NativeAgentPrivateGitBridgeSocketPairError.alreadyClosed
        }
        childFileDescriptor = nil
        stateLock.unlock()

        guard syscalls.close(source) == 0 else {
            let closeError = Self.currentErrno()
            stateLock.lock()
            closed = true
            stateLock.unlock()
            _ = closeOwnedDescriptors(child: nil)
            throw NativeAgentPrivateGitBridgeSocketPairError.closeFailed(closeError)
        }
    }

    private func abortChildEndpoint(source: Int32) throws {
        stateLock.lock()
        guard !closed, childFileDescriptor == source else {
            stateLock.unlock()
            throw NativeAgentPrivateGitBridgeSocketPairError.alreadyClosed
        }
        closed = true
        childFileDescriptor = nil
        stateLock.unlock()

        if let closeError = closeOwnedDescriptors(child: source) {
            throw NativeAgentPrivateGitBridgeSocketPairError.closeFailed(closeError)
        }
    }

    @discardableResult
    private func closeOwnedDescriptors(child: Int32?) -> Int32? {
        var firstError: Int32?
        if let child, child >= 0, syscalls.close(child) == -1 {
            firstError = Self.currentErrno()
        }

        do {
            try hostEndpoint.close()
        } catch let error as NativeAgentPrivateFDTransportError {
            if firstError == nil {
                switch error {
                case .closeFailed(let errno): firstError = errno
                default: firstError = Int32(EIO)
                }
            }
        } catch {
            if firstError == nil { firstError = Int32(EIO) }
        }
        return firstError
    }

    private static func setCloseOnExec(
        descriptor: Int32,
        using fcntl: FcntlClosure
    ) throws {
        let existing = fcntl(descriptor, F_GETFD, 0)
        guard existing >= 0 else {
            throw NativeAgentPrivateGitBridgeSocketPairError.descriptorFlagsFailed(
                descriptor,
                currentErrno())
        }
        let flags = existing | Int32(FD_CLOEXEC)
        guard fcntl(descriptor, F_SETFD, flags) == 0 else {
            throw NativeAgentPrivateGitBridgeSocketPairError.descriptorFlagsFailed(
                descriptor,
                currentErrno())
        }
    }

    private static func closeUnique(
        _ descriptors: [Int32],
        using close: CloseClosure
    ) {
        var closed = Set<Int32>()
        for descriptor in descriptors where descriptor >= 0 {
            guard closed.insert(descriptor).inserted else { continue }
            _ = close(descriptor)
        }
    }

    private static func currentErrno() -> Int32 {
        errno
    }
}
