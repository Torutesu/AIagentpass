import Darwin
import Foundation

private let nativeAgentHostMinimumPrivateDescriptor: Int32 = 4

/// Fixed adapters that the signed Host is permitted to supervise.
///
/// This enum is intentionally closed. A launch request has no executable or
/// shell selector; adding an adapter requires a reviewed source change.
public enum NativeAgentHostAdapterKind: String, Codable, CaseIterable, Sendable {
    case claudeCode = "claude_code"
    case cursor
}

/// Explicit child Git transport. XPC mode never creates or inherits FD3.
public enum NativeAgentHostGitTransport: String, Codable, CaseIterable, Sendable {
    case legacyFD3 = "legacy_fd3"
    case versionedSessionV1 = "versioned_session_v1"
    case authenticatedXPC = "authenticated_xpc"
}

public enum NativeAgentHostProjectDirectoryError: Error, Equatable, Sendable {
    case notAbsolute
    case notCanonical
    case missing
    case notDirectory
    case invalidPath
    case ownerMismatch
    case identityChanged
    case descriptorOpenFailed
    case descriptorStatFailed
    case descriptorCloseFailed
    case invalidDescriptor
}

/// The identity observed through an opened directory descriptor.
///
/// `path` is never used as the authority for a child working directory. The
/// descriptor identity is captured once, then checked again when a launch
/// opens the binding. This makes a path substitution fail closed instead of
/// silently selecting a new inode.
public struct NativeAgentHostProjectDirectoryIdentity: Equatable, Hashable, Sendable {
    public let device: UInt64
    public let inode: UInt64
    public let ownerUserID: UInt32
    public let mode: UInt32

    public init(device: UInt64, inode: UInt64, ownerUserID: UInt32, mode: UInt32) {
        self.device = device
        self.inode = inode
        self.ownerUserID = ownerUserID
        self.mode = mode
    }

    fileprivate var isDirectory: Bool {
        mode & UInt32(S_IFMT) == UInt32(S_IFDIR)
    }
}

/// Deterministic hooks for opening, inspecting, and closing a project binding.
///
/// Production uses the `system` implementation below. The hook boundary keeps
/// the security-critical state machine testable without racing real filesystem
/// paths or depending on a particular process' open-file table.
public struct NativeAgentHostProjectDirectoryHooks: @unchecked Sendable {
    public typealias OpenClosure = @Sendable (String) throws -> Int32
    public typealias InspectClosure = @Sendable (Int32) throws -> NativeAgentHostProjectDirectoryIdentity
    public typealias CloseClosure = @Sendable (Int32) -> Int32
    public typealias EffectiveUserIDClosure = @Sendable () -> UInt32

    public let open: OpenClosure
    public let inspect: InspectClosure
    public let close: CloseClosure
    public let effectiveUserID: EffectiveUserIDClosure

    public init(
        open: @escaping OpenClosure,
        inspect: @escaping InspectClosure,
        close: @escaping CloseClosure,
        effectiveUserID: @escaping EffectiveUserIDClosure
    ) {
        self.open = open
        self.inspect = inspect
        self.close = close
        self.effectiveUserID = effectiveUserID
    }

    public static let system = Self(
        open: { path in try NativeAgentHostProjectDirectorySystem.open(path) },
        inspect: { descriptor in try NativeAgentHostProjectDirectorySystem.inspect(descriptor) },
        close: { descriptor in Darwin.close(descriptor) },
        effectiveUserID: { geteuid() }
    )
}

/// A canonical, existing project directory bound by the trusted Host caller.
///
/// Construction performs a no-follow descriptor walk and owner/type check.
/// A later launch repeats the walk and requires the same `(st_dev, st_ino)`;
/// the returned descriptor is the only working-directory authority passed to
/// `posix_spawn`. The path is retained for display/environment compatibility,
/// never for the child `chdir` operation.
public struct NativeAgentHostProjectDirectory: Equatable, Hashable, @unchecked Sendable {
    public let path: String

    private let identity: NativeAgentHostProjectDirectoryIdentity
    private let expectedUserID: UInt32
    private let hooks: NativeAgentHostProjectDirectoryHooks

    public init(path: String, fileManager _: FileManager = .default) throws {
        try self.init(path: path, hooks: .system)
    }

    public init(path: String, hooks: NativeAgentHostProjectDirectoryHooks) throws {
        try Self.validatePath(path)
        let expectedUserID = hooks.effectiveUserID()
        let identity = try Self.captureIdentity(
            path: path,
            hooks: hooks,
            expectedUserID: expectedUserID
        )
        self.path = path
        self.identity = identity
        self.expectedUserID = expectedUserID
        self.hooks = hooks
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.path == rhs.path
            && lhs.identity == rhs.identity
            && lhs.expectedUserID == rhs.expectedUserID
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(path)
        hasher.combine(identity)
        hasher.combine(expectedUserID)
    }

    fileprivate func openForSpawn() throws -> NativeAgentHostProjectDirectoryBinding {
        let descriptor = try Self.openDescriptor(path: path, hooks: hooks)
        let binding = NativeAgentHostProjectDirectoryBinding(
            descriptor: descriptor,
            close: hooks.close
        )

        do {
            let observed = try hooks.inspect(descriptor)
            guard observed.isDirectory else {
                try binding.close()
                throw NativeAgentHostProjectDirectoryError.notDirectory
            }
            guard hooks.effectiveUserID() == expectedUserID,
                  observed.ownerUserID == expectedUserID else {
                try binding.close()
                throw NativeAgentHostProjectDirectoryError.ownerMismatch
            }
            guard observed == identity else {
                try binding.close()
                throw NativeAgentHostProjectDirectoryError.identityChanged
            }
            return binding
        } catch {
            try? binding.close()
            throw error
        }
    }

    private static func captureIdentity(
        path: String,
        hooks: NativeAgentHostProjectDirectoryHooks,
        expectedUserID: UInt32
    ) throws -> NativeAgentHostProjectDirectoryIdentity {
        let descriptor = try openDescriptor(path: path, hooks: hooks)
        let binding = NativeAgentHostProjectDirectoryBinding(
            descriptor: descriptor,
            close: hooks.close
        )
        do {
            let observed = try hooks.inspect(descriptor)
            guard observed.isDirectory else {
                try binding.close()
                throw NativeAgentHostProjectDirectoryError.notDirectory
            }
            guard observed.ownerUserID == expectedUserID else {
                try binding.close()
                throw NativeAgentHostProjectDirectoryError.ownerMismatch
            }
            try binding.close()
            return observed
        } catch {
            try? binding.close()
            throw error
        }
    }

    private static func openDescriptor(
        path: String,
        hooks: NativeAgentHostProjectDirectoryHooks
    ) throws -> Int32 {
        let descriptor: Int32
        do {
            descriptor = try hooks.open(path)
        } catch let error as NativeAgentHostProjectDirectoryError {
            throw error
        } catch {
            throw NativeAgentHostProjectDirectoryError.descriptorOpenFailed
        }
        guard descriptor >= nativeAgentHostMinimumPrivateDescriptor else {
            _ = hooks.close(descriptor)
            throw NativeAgentHostProjectDirectoryError.invalidDescriptor
        }
        return descriptor
    }

    private static func validatePath(_ path: String) throws {
        guard !path.isEmpty,
              path.utf8.count <= 4_096,
              !path.contains("\0"),
              path.hasPrefix("/"),
              path != "/",
              !path.hasSuffix("/") else {
            throw NativeAgentHostProjectDirectoryError.notAbsolute
        }

        let components = path.split(separator: "/", omittingEmptySubsequences: false)
        guard components.first?.isEmpty == true,
              components.dropFirst().allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw NativeAgentHostProjectDirectoryError.notCanonical
        }

        // Do not use Foundation's path normalization as the security check:
        // macOS intentionally treats `/private/var` and `/var` as aliases.
        // The production descriptor walk below rejects every symlink with
        // O_NOFOLLOW, including parent components, while this lexical check
        // rejects dot components and empty path components before opening it.
    }
}

fileprivate final class NativeAgentHostProjectDirectoryBinding: @unchecked Sendable {
    let descriptor: Int32
    private let closeClosure: NativeAgentHostProjectDirectoryHooks.CloseClosure
    private let lock = NSLock()
    private var closed = false

    init(descriptor: Int32, close: @escaping NativeAgentHostProjectDirectoryHooks.CloseClosure) {
        self.descriptor = descriptor
        self.closeClosure = close
    }

    func close() throws {
        lock.lock()
        guard !closed else {
            lock.unlock()
            return
        }
        closed = true
        let result = closeClosure(descriptor)
        lock.unlock()
        guard result == 0 else {
            throw NativeAgentHostProjectDirectoryError.descriptorCloseFailed
        }
    }

    deinit {
        lock.lock()
        guard !closed else {
            lock.unlock()
            return
        }
        closed = true
        _ = closeClosure(descriptor)
        lock.unlock()
    }
}

private enum NativeAgentHostProjectDirectorySystem {
    static func open(_ path: String) throws -> Int32 {
        let components = path.split(separator: "/", omittingEmptySubsequences: false)
        guard components.first?.isEmpty == true else {
            throw NativeAgentHostProjectDirectoryError.notAbsolute
        }

        var current = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard current >= 0 else {
            throw NativeAgentHostProjectDirectoryError.descriptorOpenFailed
        }
        var ownsCurrent = true
        defer {
            if ownsCurrent {
                _ = Darwin.close(current)
            }
        }

        for component in components.dropFirst() {
            guard !component.isEmpty, component != ".", component != ".." else {
                throw NativeAgentHostProjectDirectoryError.notCanonical
            }
            let next = component.withCString {
                openat(current, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            }
            guard next >= 0 else {
                let errorNumber = errno
                if errorNumber == ENOTDIR,
                   component.withCString({ name in Self.isSymlink(parent: current, name: name) }) {
                    throw NativeAgentHostProjectDirectoryError.notCanonical
                }
                throw Self.mapOpenError(errorNumber)
            }
            let previous = current
            current = next
            guard Darwin.close(previous) == 0 else {
                _ = Darwin.close(current)
                ownsCurrent = false
                throw NativeAgentHostProjectDirectoryError.descriptorCloseFailed
            }
        }

        // Never let the directory binding occupy stdin/stdout/stderr. A
        // fixed lower bound also makes the explicit child close action
        // incapable of colliding with a standard stream.
        let privateDescriptor = fcntl(current, F_DUPFD_CLOEXEC, nativeAgentHostMinimumPrivateDescriptor)
        guard privateDescriptor >= nativeAgentHostMinimumPrivateDescriptor else {
            throw NativeAgentHostProjectDirectoryError.descriptorOpenFailed
        }
        guard Darwin.close(current) == 0 else {
            _ = Darwin.close(privateDescriptor)
            ownsCurrent = false
            throw NativeAgentHostProjectDirectoryError.descriptorCloseFailed
        }
        ownsCurrent = false
        return privateDescriptor
    }

    static func inspect(_ descriptor: Int32) throws -> NativeAgentHostProjectDirectoryIdentity {
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0 else {
            throw NativeAgentHostProjectDirectoryError.descriptorStatFailed
        }
        return NativeAgentHostProjectDirectoryIdentity(
            device: UInt64(metadata.st_dev),
            inode: UInt64(metadata.st_ino),
            ownerUserID: UInt32(metadata.st_uid),
            mode: UInt32(metadata.st_mode)
        )
    }

    private static func isSymlink(parent: Int32, name: UnsafePointer<CChar>) -> Bool {
        var metadata = stat()
        guard fstatat(parent, name, &metadata, AT_SYMLINK_NOFOLLOW) == 0 else {
            return false
        }
        return UInt32(metadata.st_mode) & UInt32(S_IFMT) == UInt32(S_IFLNK)
    }

    private static func mapOpenError(_ errorNumber: Int32) -> NativeAgentHostProjectDirectoryError {
        switch errorNumber {
        case ENOENT:
            return .missing
        case ELOOP:
            return .notCanonical
        case ENOTDIR:
            return .notDirectory
        default:
            return .descriptorOpenFailed
        }
    }
}

public enum NativeAgentHostChildLaunchRequestError: Error, Equatable, Sendable {
    case invalidEnvironment
    case environmentValueTooLong
}

/// Input accepted by the Host child supervisor.
///
/// `trustedEnvironment` is the environment captured by the already-qualified
/// Host process. The supervisor copies only its fixed allowlist and adds a
/// fixed PATH plus the validated project PWD. It never accepts an executable,
/// shell, or arbitrary argv selector from this request.
public struct NativeAgentHostChildLaunchRequest: Equatable, Sendable {
    public static let maximumEnvironmentEntries = 64
    public static let maximumEnvironmentValueBytes = 4_096

    public let adapter: NativeAgentHostAdapterKind
    public let gitTransport: NativeAgentHostGitTransport
    public let projectDirectory: NativeAgentHostProjectDirectory
    public let trustedEnvironment: [String: String]

    public init(
        adapter: NativeAgentHostAdapterKind,
        projectDirectory: NativeAgentHostProjectDirectory,
        trustedEnvironment: [String: String] = ProcessInfo.processInfo.environment,
        // The authenticated XPC boundary is the only production default.
        // Legacy FD3 remains available only when an explicit qualification
        // caller selects it; it must never be inherited accidentally.
        gitTransport: NativeAgentHostGitTransport = .authenticatedXPC
    ) throws {
        guard trustedEnvironment.count <= Self.maximumEnvironmentEntries else {
            throw NativeAgentHostChildLaunchRequestError.invalidEnvironment
        }
        for (key, value) in trustedEnvironment {
            guard !key.isEmpty,
                  key.utf8.count <= 256,
                  !key.contains("\0"),
                  value.utf8.count <= Self.maximumEnvironmentValueBytes,
                  !value.contains("\0"),
                  !value.contains("\r"),
                  !value.contains("\n") else {
                throw value.utf8.count > Self.maximumEnvironmentValueBytes
                    ? NativeAgentHostChildLaunchRequestError.environmentValueTooLong
                    : NativeAgentHostChildLaunchRequestError.invalidEnvironment
            }
        }
        self.adapter = adapter
        self.projectDirectory = projectDirectory
        self.trustedEnvironment = trustedEnvironment
        self.gitTransport = gitTransport
    }
}

public enum NativeAgentHostForwardedSignal: Equatable, Sendable {
    case terminate
    case interrupt

    fileprivate var rawValue: Int32 {
        switch self {
        case .terminate: return SIGTERM
        case .interrupt: return SIGINT
        }
    }
}

/// Bounded wait output. Raw exit codes, signal numbers, core-dump bits, and
/// errno values never cross the NativeCore public boundary.
public enum NativeAgentHostWaitOutcome: Equatable, Sendable {
    case exitedSuccessfully
    case exitedWithFailure
    case terminatedBySignal
}

public enum NativeAgentHostExitClassification: String, Codable, Equatable, Sendable {
    case success
    case failure
    case terminated
}

public enum NativeAgentHostChildSupervisorError: Error, Equatable, Sendable {
    case unsupportedAdapter
    case launchFailed
    case projectDirectoryCloseFailed
    case processGroupNotOwned
    case signalFailed
    case waitFailed
    case childAlreadyWaited
}

/// Opaque process identity used only by the injected operating-system hooks.
/// The supervisor requires the group to equal the child PID, which is the
/// invariant established by the production posix_spawn implementation.
public struct NativeAgentHostProcessHandle: Equatable, Sendable {
    public let processIdentifier: Int32
    public let processGroupIdentifier: Int32

    public init(processIdentifier: Int32, processGroupIdentifier: Int32) {
        self.processIdentifier = processIdentifier
        self.processGroupIdentifier = processGroupIdentifier
    }
}

/// Spawn input assembled only from the closed adapter map and validated
/// request. `useOwnedProcessGroup` is always true for supervisor launches.
public struct NativeAgentHostSpawnSpec: Equatable, Sendable {
    public let executablePath: String
    public let arguments: [String]
    public let environment: [String: String]
    public let workingDirectory: String
    /// Ephemeral, parent-owned descriptor for the validated project inode.
    /// The system spawn hook consumes it synchronously and closes it in the
    /// parent on every return path; it is never an argv or environment value.
    public let workingDirectoryFD: Int32
    public let useOwnedProcessGroup: Bool
    public let gitTransport: NativeAgentHostGitTransport

    /// The one-use child-only FD3 handoff. The source descriptor is never
    /// exposed as a field; the system spawn hook installs its reviewed
    /// `dup2(source, 3)`/`close(source)` actions through the method below.
    fileprivate let privateGitBridgeHandoff: NativeAgentPrivateGitBridgeChildEndpointHandoff?

    /// Whether this spawn carries the fixed private Git bridge to the child.
    /// This is metadata for diagnostics/tests, not a descriptor selector.
    public var hasPrivateGitBridgeHandoff: Bool {
        privateGitBridgeHandoff != nil
    }

    fileprivate init(
        executablePath: String,
        arguments: [String],
        environment: [String: String],
        workingDirectory: String,
        workingDirectoryFD: Int32,
        privateGitBridgeHandoff: NativeAgentPrivateGitBridgeChildEndpointHandoff?,
        gitTransport: NativeAgentHostGitTransport
    ) {
        self.executablePath = executablePath
        self.arguments = arguments
        self.environment = environment
        self.workingDirectory = workingDirectory
        self.workingDirectoryFD = workingDirectoryFD
        self.useOwnedProcessGroup = true
        self.gitTransport = gitTransport
        self.privateGitBridgeHandoff = privateGitBridgeHandoff
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.executablePath == rhs.executablePath
            && lhs.arguments == rhs.arguments
            && lhs.environment == rhs.environment
            && lhs.workingDirectory == rhs.workingDirectory
            && lhs.workingDirectoryFD == rhs.workingDirectoryFD
            && lhs.useOwnedProcessGroup == rhs.useOwnedProcessGroup
            && lhs.gitTransport == rhs.gitTransport
            && lhs.hasPrivateGitBridgeHandoff == rhs.hasPrivateGitBridgeHandoff
    }

    /// Installs the private Git bridge actions into the caller-owned
    /// `posix_spawn_file_actions_t`. The handoff object owns the source
    /// descriptor and aborts it if either action cannot be registered.
    public func installPrivateGitBridgeFileActions(
        addDuplicate: @escaping NativeAgentPrivateGitBridgeChildEndpointHandoff.FileActionClosure,
        addClose: @escaping NativeAgentPrivateGitBridgeChildEndpointHandoff.CloseActionClosure
    ) throws {
        try privateGitBridgeHandoff?.addToSpawnFileActions(
            addDuplicate: addDuplicate,
            addClose: addClose
        )
    }
}

public struct NativeAgentHostChildSupervisorHooks: @unchecked Sendable {
    public let spawn: @Sendable (NativeAgentHostSpawnSpec) throws -> NativeAgentHostProcessHandle
    public let signal: @Sendable (NativeAgentHostProcessHandle, NativeAgentHostForwardedSignal) throws -> Void
    /// Terminates the claimed child PID directly. This is used only when the
    /// process-group ownership invariant fails, because signaling an unknown
    /// negative PGID could affect an unrelated process group.
    public let terminateProcess: @Sendable (NativeAgentHostProcessHandle) throws -> Void
    public let wait: @Sendable (NativeAgentHostProcessHandle) throws -> NativeAgentHostWaitOutcome

    public init(
        spawn: @escaping @Sendable (NativeAgentHostSpawnSpec) throws -> NativeAgentHostProcessHandle,
        signal: @escaping @Sendable (NativeAgentHostProcessHandle, NativeAgentHostForwardedSignal) throws -> Void,
        terminateProcess: @escaping @Sendable (NativeAgentHostProcessHandle) throws -> Void,
        wait: @escaping @Sendable (NativeAgentHostProcessHandle) throws -> NativeAgentHostWaitOutcome
    ) {
        self.spawn = spawn
        self.signal = signal
        self.terminateProcess = terminateProcess
        self.wait = wait
    }

    public static let system = Self(
        spawn: NativeAgentHostSystemHooks.spawn,
        signal: NativeAgentHostSystemHooks.signal,
        terminateProcess: NativeAgentHostSystemHooks.terminateProcess,
        wait: NativeAgentHostSystemHooks.wait
    )
}

/// A running child owned by one supervisor session.
public final class NativeAgentHostChildSession: @unchecked Sendable {
    private enum State {
        case running
        case waiting
        case finished(NativeAgentHostExitClassification)
        case failed
    }

    private let process: NativeAgentHostProcessHandle
    private let hooks: NativeAgentHostChildSupervisorHooks
    private let privateGitBridge: NativeAgentPrivateGitBridgeSocketPair?
    private let authenticatedHostXPC: (any NativeAgentHostAuthenticatedXPCClientProtocol)?
    private let lock = NSLock()
    private var state: State = .running

    fileprivate init(
        process: NativeAgentHostProcessHandle,
        hooks: NativeAgentHostChildSupervisorHooks,
        privateGitBridge: NativeAgentPrivateGitBridgeSocketPair?,
        authenticatedHostXPC: (any NativeAgentHostAuthenticatedXPCClientProtocol)?
    ) {
        self.process = process
        self.hooks = hooks
        self.privateGitBridge = privateGitBridge
        self.authenticatedHostXPC = authenticatedHostXPC
    }

    /// Host-side endpoint for the fixed child FD3 Git bridge. The caller may
    /// wrap this endpoint in `NativeAgentPrivateGitBridgeServer`; it carries
    /// no session, key, capability, or policy selector.
    public var privateGitBridgeHostEndpoint: NativeAgentPrivateFDTransport? {
        privateGitBridge?.hostEndpoint
    }

    /// Forwards only TERM or INT to the owned process group.
    public func forward(_ signal: NativeAgentHostForwardedSignal) throws {
        lock.lock()
        guard case .running = state else {
            lock.unlock()
            throw NativeAgentHostChildSupervisorError.childAlreadyWaited
        }
        do {
            try hooks.signal(process, signal)
        } catch {
            lock.unlock()
            throw NativeAgentHostChildSupervisorError.signalFailed
        }
        lock.unlock()
    }

    /// Waits for and reaps the child exactly once. A repeated wait returns the
    /// cached bounded classification without invoking the injected wait hook.
    public func wait() throws -> NativeAgentHostExitClassification {
        lock.lock()
        switch state {
        case .finished(let result):
            lock.unlock()
            return result
        case .waiting, .failed:
            lock.unlock()
            throw NativeAgentHostChildSupervisorError.childAlreadyWaited
        case .running:
            state = .waiting
            lock.unlock()
        }

        let outcome: NativeAgentHostWaitOutcome
        do {
            outcome = try hooks.wait(process)
        } catch {
            try? privateGitBridge?.close()
            try? authenticatedHostXPC?.closeForChild(reason: .cancelled)
            lock.lock()
            state = .failed
            lock.unlock()
            throw NativeAgentHostChildSupervisorError.waitFailed
        }

        let result = Self.classification(for: outcome)
        do {
            try privateGitBridge?.close()
            try authenticatedHostXPC?.closeForChild(reason: .completed)
        } catch {
            lock.lock()
            state = .failed
            lock.unlock()
            throw NativeAgentHostChildSupervisorError.waitFailed
        }
        lock.lock()
        state = .finished(result)
        lock.unlock()
        return result
    }

    private static func classification(for outcome: NativeAgentHostWaitOutcome) -> NativeAgentHostExitClassification {
        switch outcome {
        case .exitedSuccessfully: return .success
        case .exitedWithFailure: return .failure
        case .terminatedBySignal: return .terminated
        }
    }

    deinit {
        lock.lock()
        guard case .running = state else {
            lock.unlock()
            return
        }
        state = .waiting
        lock.unlock()

        // Dropping a live session must not orphan an agent. This is a
        // best-effort cleanup path; normal callers should explicitly wait.
        try? hooks.signal(process, .terminate)
        _ = try? hooks.wait(process)
        try? privateGitBridge?.close()
        try? authenticatedHostXPC?.closeForChild(reason: .clientShutdown)
    }
}

/// Starts and supervises one fixed-adapter Host child.
public final class NativeAgentHostChildSupervisor: @unchecked Sendable {
    private let hooks: NativeAgentHostChildSupervisorHooks
    private let cursorExecutableResolver: @Sendable () throws -> NativeCursorAgentRuntimeSelection
    private let cursorExecutableRevalidator: @Sendable (NativeCursorAgentRuntimeSelection) throws -> Void
    private let authenticatedHostLaunchPreparationAdapter: any NativeAgentHostAuthenticatedLaunchPreparationAdapter
    private let childObserverFactory: @Sendable () -> any NativeAgentHostChildObserver
    private let launchNonceFactory: @Sendable () -> Data

    public init(hooks: NativeAgentHostChildSupervisorHooks = .system) {
        self.hooks = hooks
        self.cursorExecutableResolver = {
            try NativeAgentHostExecutableTrust.resolveCursorExecutable()
        }
        self.cursorExecutableRevalidator = { selection in
            try NativeAgentHostExecutableTrust.revalidate(selection)
        }
        self.authenticatedHostLaunchPreparationAdapter = NativeAgentAuthenticatedHostLaunchPreparationAdapter()
        self.childObserverFactory = { NativeAgentHostDarwinChildObserver() }
        self.launchNonceFactory = { NativeAgentHostLaunchNonce.make() }
    }

    /// Test-only injection seam. The public production initializer above has
    /// no executable selector or filesystem trust override.
    internal init(
        hooks: NativeAgentHostChildSupervisorHooks = .system,
        executableProbe: @escaping @Sendable (String) -> Bool,
        authenticatedHostXPCClientFactory: @escaping @Sendable () -> any NativeAgentHostAuthenticatedXPCClientProtocol = {
            NativeAgentAuthenticatedHostXPCClient()
        },
        childObserverFactory: @escaping @Sendable () -> any NativeAgentHostChildObserver = {
            NativeAgentHostDarwinChildObserver()
        },
        launchNonceFactory: @escaping @Sendable () -> Data = { NativeAgentHostLaunchNonce.make() }
    ) {
        self.hooks = hooks
        self.authenticatedHostLaunchPreparationAdapter = NativeAgentAuthenticatedHostLaunchPreparationAdapter(
            clientFactory: authenticatedHostXPCClientFactory
        )
        self.childObserverFactory = childObserverFactory
        self.launchNonceFactory = launchNonceFactory
        self.cursorExecutableResolver = {
            guard NativeCursorAgentRuntimeSpec.requiredPaths.allSatisfy(executableProbe) else {
                throw NativeAgentHostExecutableTrustError.noTrustedCandidate
            }
            let manifest = try NativeCursorAgentRuntimeManifest(entries: [
                try NativeCursorAgentRuntimeManifestEntry(
                    relativePath: NativeCursorAgentRuntimeSpec.nodeRelativePath,
                    sha256: String(repeating: "a", count: 64),
                    size: 1,
                    isExecutable: true
                ),
                try NativeCursorAgentRuntimeManifestEntry(
                    relativePath: NativeCursorAgentRuntimeSpec.indexRelativePath,
                    sha256: String(repeating: "b", count: 64),
                    size: 2,
                    isExecutable: false
                )
            ])
            return NativeCursorAgentRuntimeSelection(
                nodePath: NativeCursorAgentRuntimeSpec.nodePath,
                indexPath: NativeCursorAgentRuntimeSpec.indexPath,
                fileIdentities: [
                    NativeCursorAgentRuntimeFileIdentity(
                        relativePath: NativeCursorAgentRuntimeSpec.nodeRelativePath,
                        device: 0,
                        inode: 0,
                        size: 1
                    ),
                    NativeCursorAgentRuntimeFileIdentity(
                        relativePath: NativeCursorAgentRuntimeSpec.indexRelativePath,
                        device: 0,
                        inode: 0,
                        size: 2
                    )
                ],
                manifest: manifest
            )
        }
        // The probe is deliberately a test-only synthetic selector; its
        // result is not used by the production initializer or revalidation.
        self.cursorExecutableRevalidator = { _ in }
    }

    public func start(_ request: NativeAgentHostChildLaunchRequest) throws -> NativeAgentHostChildSession {
        let adapter = try NativeAgentHostFixedAdapter.command(
            for: request.adapter,
            cursorExecutableResolver: cursorExecutableResolver
        )
        var environment = try NativeAgentHostStrictEnvironment.make(
            from: request.trustedEnvironment,
            projectDirectory: request.projectDirectory.path,
            fixedEnvironment: adapter.fixedEnvironment
        )
        if request.gitTransport == .authenticatedXPC {
            environment.merge(NativeAgentHostGitConfiguration.authenticatedXPCEnvironment) { _, fixed in fixed }
        } else if request.gitTransport == .versionedSessionV1 {
            environment.merge(NativeAgentHostGitConfiguration.versionedSessionEnvironment) { _, fixed in fixed }
        }
        let privateGitBridge: NativeAgentPrivateGitBridgeSocketPair?
        let privateGitBridgeHandoff: NativeAgentPrivateGitBridgeChildEndpointHandoff?
        if request.gitTransport == .legacyFD3 || request.gitTransport == .versionedSessionV1 {
            do {
                let bridge = try NativeAgentPrivateGitBridgeSocketPair()
                privateGitBridge = bridge
                privateGitBridgeHandoff = try bridge.prepareChildEndpointHandoff()
            } catch {
                throw NativeAgentHostChildSupervisorError.launchFailed
            }
        } else {
            privateGitBridge = nil
            privateGitBridgeHandoff = nil
        }

        let authenticatedHostXPC: (any NativeAgentHostAuthenticatedXPCClientProtocol)?
        if request.gitTransport == .authenticatedXPC {
            do {
                // Prepare is deliberately connection-owned and must complete
                // before posix_spawn. There is no authenticatedXPC fallback.
                authenticatedHostXPC = try authenticatedHostLaunchPreparationAdapter.prepareForChild(
                    launchNonce: launchNonceFactory()
                )
            } catch {
                try? privateGitBridge?.close()
                throw NativeAgentHostChildSupervisorError.launchFailed
            }
        } else {
            authenticatedHostXPC = nil
        }

        let projectBinding: NativeAgentHostProjectDirectoryBinding
        do {
            projectBinding = try request.projectDirectory.openForSpawn()
        } catch {
            try? authenticatedHostXPC?.closeForChild(reason: .cancelled)
            try? privateGitBridge?.close()
            throw error
        }
        let spec = NativeAgentHostSpawnSpec(
            executablePath: adapter.executablePath,
            arguments: adapter.arguments,
            environment: environment,
            workingDirectory: request.projectDirectory.path,
            workingDirectoryFD: projectBinding.descriptor,
            privateGitBridgeHandoff: privateGitBridgeHandoff,
            gitTransport: request.gitTransport
        )

        do {
            if let executableSelection = adapter.executableSelection {
                // Keep the final trust check directly adjacent to spawn. This
                // detects path replacement during setup. The trust policy's
                // comment documents the remaining privileged/root TOCTOU gap.
                try cursorExecutableRevalidator(executableSelection)
            }
            let process = try hooks.spawn(spec)
            guard process.processIdentifier > 0,
                  process.processGroupIdentifier > 0,
                  process.processGroupIdentifier == process.processIdentifier else {
                // The group identity is not trusted, so do not signal a
                // negative PID. The system spawn hook establishes this
                // invariant; an injected violation is terminated through the
                // claimed child PID and then reaped to avoid an orphan.
                if process.processIdentifier > 0 {
                    try? hooks.terminateProcess(process)
                    _ = try? hooks.wait(process)
                }
                try? privateGitBridgeHandoff?.abort()
                try? projectBinding.close()
                throw NativeAgentHostChildSupervisorError.processGroupNotOwned
            }

            do {
                // The file actions have already been installed by the spawn
                // hook. Commit the child endpoint only after posix_spawn has
                // returned a process with an owned process group.
                try privateGitBridgeHandoff?.commit()
            } catch {
                try? hooks.signal(process, .terminate)
                _ = try? hooks.wait(process)
                throw NativeAgentHostChildSupervisorError.launchFailed
            }

            do {
                try projectBinding.close()
            } catch {
                // The child is already running, but the parent could not
                // prove descriptor cleanup. Terminate/reap it before the
                // caller sees the bounded failure.
                try? hooks.signal(process, .terminate)
                _ = try? hooks.wait(process)
                try? privateGitBridge?.close()
                throw NativeAgentHostChildSupervisorError.projectDirectoryCloseFailed
            }

            if let authenticatedHostXPC {
                do {
                    let observation = try childObserverFactory().observe(pid: process.processIdentifier)
                    guard let childPIDVersion = Int64(exactly: observation.identity.pidVersion) else {
                        throw NativeProcessIdentityError.invalidObservation("child PID version exceeds XPC range")
                    }
                    try authenticatedHostXPC.attachForChild(
                        childPID: Int(process.processIdentifier),
                        childPIDVersion: childPIDVersion,
                        executableIdentityDigest: try observation.identity.canonicalBindingDigestData,
                        ancestryBindingDigest: try observation.identity.canonicalAncestryBindingDigestData,
                        worktreeBindingDigest: observation.worktreeBindingDigest
                    )
                } catch {
                    try? hooks.signal(process, .terminate)
                    _ = try? hooks.wait(process)
                    throw NativeAgentHostChildSupervisorError.launchFailed
                }
            }
            return NativeAgentHostChildSession(
                process: process,
                hooks: hooks,
                privateGitBridge: privateGitBridge,
                authenticatedHostXPC: authenticatedHostXPC
            )
        } catch let error as NativeAgentHostChildSupervisorError {
            try? privateGitBridgeHandoff?.abort()
            try? privateGitBridge?.close()
            try? authenticatedHostXPC?.closeForChild(reason: .cancelled)
            try? projectBinding.close()
            throw error
        } catch {
            try? privateGitBridgeHandoff?.abort()
            try? privateGitBridge?.close()
            try? authenticatedHostXPC?.closeForChild(reason: .cancelled)
            try? projectBinding.close()
            throw NativeAgentHostChildSupervisorError.launchFailed
        }
    }
}

private struct NativeAgentHostFixedAdapter {
    let executablePath: String
    let arguments: [String]
    let fixedEnvironment: [String: String]
    let executableSelection: NativeCursorAgentRuntimeSelection?

    static func command(
        for kind: NativeAgentHostAdapterKind,
        cursorExecutableResolver: @escaping @Sendable () throws -> NativeCursorAgentRuntimeSelection
    ) throws -> Self {
        switch kind {
        case .claudeCode:
            // These are fixed, reviewed installation locations. The caller
            // cannot supply or override an executable path. The fallback is
            // deliberately allowed to reach posix_spawn so a missing install
            // becomes the bounded launchFailed result.
            #if arch(arm64)
            let preferred = "/opt/homebrew/bin/claude"
            #else
            let preferred = "/usr/local/bin/claude"
            #endif
            let candidates = [preferred, "/usr/local/bin/claude", "/opt/homebrew/bin/claude"]
            let executable = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) ?? preferred
            return Self(executablePath: executable, arguments: [], fixedEnvironment: [:], executableSelection: nil)
        case .cursor:
            do {
                let selection = try cursorExecutableResolver()
                return Self(
                    executablePath: selection.nodePath,
                    arguments: NativeCursorAgentRuntimeSpec.fixedArguments,
                    fixedEnvironment: NativeCursorAgentRuntimeSpec.fixedEnvironment,
                    executableSelection: selection
                )
            } catch {
                // Do not fall back to an arbitrary path, PATH lookup, or a
                // caller-provided command. The bounded error contains no
                // path, errno, or process detail that could disclose state.
                throw NativeAgentHostChildSupervisorError.launchFailed
            }
        }
    }
}

private enum NativeAgentHostStrictEnvironment {
    private static let copiedKeys: Set<String> = [
        "HOME", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "USER", "LOGNAME"
    ]
    private static let fixedPath = "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin"

    static func make(
        from input: [String: String],
        projectDirectory: String,
        fixedEnvironment: [String: String] = [:]
    ) throws -> [String: String] {
        guard input.count <= NativeAgentHostChildLaunchRequest.maximumEnvironmentEntries else {
            throw NativeAgentHostChildLaunchRequestError.invalidEnvironment
        }
        var output: [String: String] = [
            "PATH": fixedPath,
            "PWD": projectDirectory
        ]
        for key in copiedKeys {
            guard let value = input[key] else { continue }
            guard value.utf8.count <= NativeAgentHostChildLaunchRequest.maximumEnvironmentValueBytes,
                  !value.contains("\0"),
                  !value.contains("\r"),
                  !value.contains("\n") else {
                throw NativeAgentHostChildLaunchRequestError.invalidEnvironment
            }
            output[key] = value
        }
        // Git's SSH signer is a fixed Host policy. It is deliberately added
        // after the caller allowlist so a launch request cannot replace the
        // helper path, signing reference, or protocol through GIT_CONFIG_*.
        output.merge(NativeAgentHostGitConfiguration.environment) { _, fixed in fixed }
        output.merge(fixedEnvironment) { _, fixed in fixed }
        return output
    }
}

private final class NativeAgentHostSpawnFileActionsBox: @unchecked Sendable {
    var value: posix_spawn_file_actions_t?

    init() {
        value = nil
    }
}

private enum NativeAgentHostSystemHooks {
    static func spawn(_ spec: NativeAgentHostSpawnSpec) throws -> NativeAgentHostProcessHandle {
        let fileActions = NativeAgentHostSpawnFileActionsBox()
        guard posix_spawn_file_actions_init(&fileActions.value) == 0 else {
            throw NativeAgentHostChildSupervisorError.launchFailed
        }
        defer { posix_spawn_file_actions_destroy(&fileActions.value) }

        guard spec.workingDirectoryFD >= nativeAgentHostMinimumPrivateDescriptor,
              Self.addDirectoryChangeAction(&fileActions.value, descriptor: spec.workingDirectoryFD) == 0,
              // O_CLOEXEC is set at open time; this explicit action makes the
              // no-leak contract visible and robust across spawn/exec changes.
              posix_spawn_file_actions_addclose(&fileActions.value, spec.workingDirectoryFD) == 0,
              // FD3 is reserved for the one-use private Git bridge only. The
              // Host's authority handoff must never reach a supervised Agent.
              // The legacy bridge's dup2 action below intentionally recreates
              // FD3 after this close; authenticated-XPC children keep it
              // closed through exec.
              posix_spawn_file_actions_addclose(&fileActions.value, 3) == 0 else {
            throw NativeAgentHostChildSupervisorError.launchFailed
        }

        do {
            try spec.installPrivateGitBridgeFileActions(
                addDuplicate: { source, target in
                    guard posix_spawn_file_actions_adddup2(&fileActions.value, source, target) == 0 else {
                        throw NativeAgentHostChildSupervisorError.launchFailed
                    }
                },
                addClose: { source in
                    guard posix_spawn_file_actions_addclose(&fileActions.value, source) == 0 else {
                        throw NativeAgentHostChildSupervisorError.launchFailed
                    }
                }
            )
        } catch {
            throw NativeAgentHostChildSupervisorError.launchFailed
        }

        var attributes: posix_spawnattr_t? = nil
        guard posix_spawnattr_init(&attributes) == 0 else {
            throw NativeAgentHostChildSupervisorError.launchFailed
        }
        defer { posix_spawnattr_destroy(&attributes) }

        guard posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETPGROUP)) == 0,
              posix_spawnattr_setpgroup(&attributes, 0) == 0 else {
            throw NativeAgentHostChildSupervisorError.launchFailed
        }

        let argvStrings = [spec.executablePath] + spec.arguments
        let environmentStrings = spec.environment
            .keys
            .sorted()
            .compactMap { key in spec.environment[key].map { "\(key)=\($0)" } }
        var argv = argvStrings.map { strdup($0) } + [nil]
        var environment = environmentStrings.map { strdup($0) } + [nil]
        defer {
            for pointer in argv { free(pointer) }
            for pointer in environment { free(pointer) }
        }

        var processIdentifier: pid_t = 0
        let result: Int32 = spec.executablePath.withCString { executable in
            argv.withUnsafeMutableBufferPointer { argvBuffer in
                environment.withUnsafeMutableBufferPointer { environmentBuffer in
                    posix_spawn(
                        &processIdentifier,
                        executable,
                        &fileActions.value,
                        &attributes,
                        argvBuffer.baseAddress!,
                        environmentBuffer.baseAddress!
                    )
                }
            }
        }
        guard result == 0, processIdentifier > 0 else {
            throw NativeAgentHostChildSupervisorError.launchFailed
        }
        return NativeAgentHostProcessHandle(
            processIdentifier: processIdentifier,
            processGroupIdentifier: processIdentifier
        )
    }

    private static func addDirectoryChangeAction(
        _ actions: inout posix_spawn_file_actions_t?,
        descriptor: Int32
    ) -> Int32 {
        if #available(macOS 26.0, *) {
            return posix_spawn_file_actions_addfchdir(&actions, descriptor)
        }
        return posix_spawn_file_actions_addfchdir_np(&actions, descriptor)
    }

    static func signal(
        _ process: NativeAgentHostProcessHandle,
        _ signal: NativeAgentHostForwardedSignal
    ) throws {
        // Negative PID targets the process group owned by this child. The
        // equality invariant is checked before a session is returned.
        guard kill(-process.processGroupIdentifier, signal.rawValue) == 0 else {
            throw NativeAgentHostChildSupervisorError.signalFailed
        }
    }

    static func terminateProcess(_ process: NativeAgentHostProcessHandle) throws {
        guard process.processIdentifier > 0,
              kill(process.processIdentifier, SIGTERM) == 0 else {
            throw NativeAgentHostChildSupervisorError.signalFailed
        }
    }

    static func wait(_ process: NativeAgentHostProcessHandle) throws -> NativeAgentHostWaitOutcome {
        var status: Int32 = 0
        while true {
            let result = waitpid(process.processIdentifier, &status, 0)
            if result == process.processIdentifier {
                // POSIX wait status: low 7 bits are zero for normal exit;
                // the next byte is the bounded success/failure distinction.
                if status & 0x7f == 0 {
                    return ((status >> 8) & 0xff) == 0 ? .exitedSuccessfully : .exitedWithFailure
                }
                return .terminatedBySignal
            }
            if result == -1, errno == EINTR { continue }
            throw NativeAgentHostChildSupervisorError.waitFailed
        }
    }
}
