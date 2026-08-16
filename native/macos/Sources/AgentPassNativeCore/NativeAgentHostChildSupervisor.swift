import Darwin
import Foundation

/// Fixed adapters that the signed Host is permitted to supervise.
///
/// This enum is intentionally closed. A launch request has no executable or
/// shell selector; adding an adapter requires a reviewed source change.
public enum NativeAgentHostAdapterKind: String, Codable, CaseIterable, Sendable {
    case claudeCode = "claude_code"
    case cursor
}

public enum NativeAgentHostProjectDirectoryError: Error, Equatable, Sendable {
    case notAbsolute
    case notCanonical
    case missing
    case notDirectory
    case invalidPath
}

/// A canonical, existing project directory bound by the trusted Host caller.
///
/// The value is validated before it can enter a launch request. Symlinks and
/// path normalization are rejected instead of being silently followed so a
/// later working-directory lookup cannot change the project binding.
public struct NativeAgentHostProjectDirectory: Equatable, Hashable, Sendable {
    public let path: String

    public init(path: String, fileManager: FileManager = .default) throws {
        guard !path.isEmpty,
              path.utf8.count <= 4_096,
              !path.contains("\0"),
              path.hasPrefix("/"),
              path != "/",
              !path.hasSuffix("/") else {
            throw NativeAgentHostProjectDirectoryError.notAbsolute
        }

        let url = URL(fileURLWithPath: path, isDirectory: true)
        let standardized = url.standardizedFileURL.path
        let resolved = url.resolvingSymlinksInPath().standardizedFileURL.path
        guard standardized == path, resolved == path else {
            throw NativeAgentHostProjectDirectoryError.notCanonical
        }

        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: path, isDirectory: &isDirectory) else {
            throw NativeAgentHostProjectDirectoryError.missing
        }
        guard isDirectory.boolValue else {
            throw NativeAgentHostProjectDirectoryError.notDirectory
        }

        self.path = path
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
    public let projectDirectory: NativeAgentHostProjectDirectory
    public let trustedEnvironment: [String: String]

    public init(
        adapter: NativeAgentHostAdapterKind,
        projectDirectory: NativeAgentHostProjectDirectory,
        trustedEnvironment: [String: String] = ProcessInfo.processInfo.environment
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
    public let useOwnedProcessGroup: Bool

    fileprivate init(
        executablePath: String,
        arguments: [String],
        environment: [String: String],
        workingDirectory: String
    ) {
        self.executablePath = executablePath
        self.arguments = arguments
        self.environment = environment
        self.workingDirectory = workingDirectory
        self.useOwnedProcessGroup = true
    }
}

public struct NativeAgentHostChildSupervisorHooks: @unchecked Sendable {
    public let spawn: @Sendable (NativeAgentHostSpawnSpec) throws -> NativeAgentHostProcessHandle
    public let signal: @Sendable (NativeAgentHostProcessHandle, NativeAgentHostForwardedSignal) throws -> Void
    public let wait: @Sendable (NativeAgentHostProcessHandle) throws -> NativeAgentHostWaitOutcome

    public init(
        spawn: @escaping @Sendable (NativeAgentHostSpawnSpec) throws -> NativeAgentHostProcessHandle,
        signal: @escaping @Sendable (NativeAgentHostProcessHandle, NativeAgentHostForwardedSignal) throws -> Void,
        wait: @escaping @Sendable (NativeAgentHostProcessHandle) throws -> NativeAgentHostWaitOutcome
    ) {
        self.spawn = spawn
        self.signal = signal
        self.wait = wait
    }

    public static let system = Self(
        spawn: NativeAgentHostSystemHooks.spawn,
        signal: NativeAgentHostSystemHooks.signal,
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
    private let lock = NSLock()
    private var state: State = .running

    fileprivate init(process: NativeAgentHostProcessHandle, hooks: NativeAgentHostChildSupervisorHooks) {
        self.process = process
        self.hooks = hooks
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

        do {
            let outcome = try hooks.wait(process)
            let result = Self.classification(for: outcome)
            lock.lock()
            state = .finished(result)
            lock.unlock()
            return result
        } catch {
            lock.lock()
            state = .failed
            lock.unlock()
            throw NativeAgentHostChildSupervisorError.waitFailed
        }
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
    }
}

/// Starts and supervises one fixed-adapter Host child.
public final class NativeAgentHostChildSupervisor: @unchecked Sendable {
    private let hooks: NativeAgentHostChildSupervisorHooks

    public init(hooks: NativeAgentHostChildSupervisorHooks = .system) {
        self.hooks = hooks
    }

    public func start(_ request: NativeAgentHostChildLaunchRequest) throws -> NativeAgentHostChildSession {
        let adapter = try NativeAgentHostFixedAdapter.command(for: request.adapter)
        let environment = try NativeAgentHostStrictEnvironment.make(
            from: request.trustedEnvironment,
            projectDirectory: request.projectDirectory.path
        )
        let spec = NativeAgentHostSpawnSpec(
            executablePath: adapter.executablePath,
            arguments: adapter.arguments,
            environment: environment,
            workingDirectory: request.projectDirectory.path
        )

        let process: NativeAgentHostProcessHandle
        do {
            process = try hooks.spawn(spec)
        } catch {
            throw NativeAgentHostChildSupervisorError.launchFailed
        }
        guard process.processIdentifier > 0,
              process.processGroupIdentifier > 0,
              process.processGroupIdentifier == process.processIdentifier else {
            throw NativeAgentHostChildSupervisorError.processGroupNotOwned
        }
        return NativeAgentHostChildSession(process: process, hooks: hooks)
    }
}

private struct NativeAgentHostFixedAdapter {
    let executablePath: String
    let arguments: [String]

    static func command(for kind: NativeAgentHostAdapterKind) throws -> Self {
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
            return Self(executablePath: executable, arguments: [])
        case .cursor:
            throw NativeAgentHostChildSupervisorError.unsupportedAdapter
        }
    }
}

private enum NativeAgentHostStrictEnvironment {
    private static let copiedKeys: Set<String> = [
        "HOME", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "USER", "LOGNAME"
    ]
    private static let fixedPath = "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin"

    static func make(from input: [String: String], projectDirectory: String) throws -> [String: String] {
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
        return output
    }
}

private enum NativeAgentHostSystemHooks {
    static func spawn(_ spec: NativeAgentHostSpawnSpec) throws -> NativeAgentHostProcessHandle {
        var fileActions: posix_spawn_file_actions_t? = nil
        guard posix_spawn_file_actions_init(&fileActions) == 0 else {
            throw NativeAgentHostChildSupervisorError.launchFailed
        }
        defer { posix_spawn_file_actions_destroy(&fileActions) }

        guard posix_spawn_file_actions_addchdir_np(&fileActions, spec.workingDirectory) == 0 else {
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
                        &fileActions,
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
