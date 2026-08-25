import Foundation
import AgentPassApp
#if canImport(Security)
import Security
#endif
#if canImport(Darwin)
import Darwin
#endif

/// Reads setup status without granting the UI any setup-mutating capability.
public struct AgentPassOnboardingStatusProvider: Sendable {
    public static let executableCandidates = [
        URL(fileURLWithPath: "/usr/local/bin/agentpass"),
        URL(fileURLWithPath: "/opt/homebrew/bin/agentpass")
    ]
    public static var executableURL: URL {
        executableCandidates.first(where: { FileManager.default.isExecutableFile(atPath: $0.path) })
            ?? executableCandidates[0]
    }
    public static let arguments = ["setup", "status"]
    public static let doctorArguments = ["doctor"]
    public static let nativeStatusArguments = ["native", "status"]
    public static let defaultMaximumOutputBytes = 256 * 1024
    public static let defaultTimeout: TimeInterval = 5
    private static let trustedExecutableIdentifiers: Set<String> = ["dev.agentpass"]

    /// The command boundary is injectable only inside the module so UI tests
    /// never execute the production CLI and public callers cannot replace the
    /// trusted Process boundary with an arbitrary closure.
    internal typealias CommandRunner = @Sendable (URL, [String], Int, TimeInterval) async throws -> Data

    private let timeout: TimeInterval
    private let maximumOutputBytes: Int
    private let executableURL: URL
    private let commandRunner: CommandRunner
    public init(
        timeout: TimeInterval = Self.defaultTimeout,
        maximumOutputBytes: Int = Self.defaultMaximumOutputBytes,
        executableURL: URL = Self.executableURL
    ) {
        self.timeout = max(0.001, timeout)
        self.maximumOutputBytes = min(Self.defaultMaximumOutputBytes, max(1, maximumOutputBytes))
        self.executableURL = executableURL
        self.commandRunner = { executableURL, arguments, maximumOutputBytes, timeout in
            try await Self.runProcess(
                executableURL: executableURL,
                arguments: arguments,
                maximumOutputBytes: maximumOutputBytes,
                timeout: timeout,
                requireTrustedExecutable: true,
                // Doctor and native status deliberately use their exit status
                // to report degraded health. Their bounded JSON is still
                // validated before it reaches the view model.
                allowNonZeroExit: arguments == Self.doctorArguments || arguments == Self.nativeStatusArguments
            )
        }
    }

    /// Test seam for adapter/model tests. It is intentionally not part of the
    /// public API: production callers cannot replace the trusted Process
    /// boundary with an arbitrary closure.
    internal init(
        timeout: TimeInterval = Self.defaultTimeout,
        maximumOutputBytes: Int = Self.defaultMaximumOutputBytes,
        executableURL: URL = Self.executableURL,
        commandRunner: @escaping CommandRunner
    ) {
        self.timeout = max(0.001, timeout)
        self.maximumOutputBytes = min(Self.defaultMaximumOutputBytes, max(1, maximumOutputBytes))
        self.executableURL = executableURL
        self.commandRunner = commandRunner
    }

    /// Executes the fixed status command and validates its output through the app adapter.
    public func status() async throws -> AgentPassOnboardingViewModel {
        do {
            let data = try await runCommand(Self.arguments)
            let status: AgentPassOnboardingViewModel
            do {
                status = try AgentPassOnboardingStatusAdapter().viewModel(from: data)
            } catch {
                throw AgentPassOnboardingStatusProviderError.invalidStatus
            }
            return status.withDiagnostics(try await diagnostics())
        } catch let error as AgentPassOnboardingStatusProviderError {
            throw error
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            // Deliberately do not expose process output, stderr, paths, or command errors.
            throw AgentPassOnboardingStatusProviderError.commandUnavailable
        }
    }

    private func diagnostics() async throws -> AgentPassOnboardingDiagnostics {
        async let doctorData = optionalCommand(Self.doctorArguments)
        async let nativeData = optionalCommand(Self.nativeStatusArguments)

        let distributionData = try await doctorData
        let distribution = distributionData.flatMap {
            try? AgentPassDoctorStatusAdapter().distributionStatus(from: $0)
        } ?? .unavailable
        let nativeStatusData = try await nativeData
        let capability = nativeStatusData.flatMap {
            try? AgentPassNativeStatusAdapter().capabilityStatus(from: $0)
        } ?? .unavailable
        return AgentPassOnboardingDiagnostics(distribution: distribution, capability: capability)
    }

    private func optionalCommand(_ arguments: [String]) async throws -> Data? {
        do {
            return try await runCommand(arguments)
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as AgentPassOnboardingStatusProviderError {
            if error == .untrustedExecutable { throw error }
            return nil
        } catch {
            return nil
        }
    }

    private func runCommand(_ arguments: [String]) async throws -> Data {
        return try await commandRunner(executableURL, arguments, maximumOutputBytes, timeout)
    }

    private struct CapturedOutput: Sendable {
        let data: Data
        let exceededLimit: Bool
    }

    private static func runProcess(
        executableURL: URL,
        arguments: [String],
        maximumOutputBytes: Int,
        timeout: TimeInterval,
        requireTrustedExecutable: Bool,
        allowNonZeroExit: Bool
    ) async throws -> Data {
        // Open and validate once, then launch through the descriptor. A
        // path-based Process launch after lstat/signature checks would permit
        // a rename/symlink swap in the gap before posix_spawn.
        let executable = try OpenExecutable(
            url: executableURL,
            requireTrustedCode: requireTrustedExecutable
        )
        let process = Process()
        let outputPipe = Pipe()
        process.executableURL = executable.launchURL
        process.arguments = executable.launchArgumentsPrefix + arguments
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = outputPipe
        process.standardError = FileHandle.nullDevice
        let inherited = ProcessInfo.processInfo.environment
        var environment: [String: String] = [
            "PATH": "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        ]
        for key in ["HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL"] {
            if let value = inherited[key] { environment[key] = value }
        }
        process.environment = environment

        do {
            try process.run()
        } catch {
            throw AgentPassOnboardingStatusProviderError.commandUnavailable
        }

        // Keep draining stdout even after the limit is reached so a verbose child cannot
        // deadlock on a full pipe while the parent is waiting for its termination.
        let reader = Task.detached(priority: .userInitiated) {
            var data = Data()
            var exceededLimit = false
            while true {
                let chunk = try outputPipe.fileHandleForReading.read(upToCount: 16 * 1024) ?? Data()
                guard !chunk.isEmpty else { break }
                let remaining = max(0, maximumOutputBytes - data.count)
                if remaining > 0 {
                    data.append(chunk.prefix(remaining))
                }
                if chunk.count > remaining {
                    exceededLimit = true
                }
            }
            return CapturedOutput(data: data, exceededLimit: exceededLimit)
        }

        let timeoutNanoseconds = UInt64(min(timeout, Double(UInt64.max) / 1_000_000_000) * 1_000_000_000)
        let deadline = DispatchTime.now().uptimeNanoseconds &+ timeoutNanoseconds
        do {
            while process.isRunning {
                if Task.isCancelled {
                    await stop(process)
                    _ = try? await reader.value
                    throw CancellationError()
                }
                if DispatchTime.now().uptimeNanoseconds >= deadline {
                    await stop(process)
                    _ = try? await reader.value
                    throw AgentPassOnboardingStatusProviderError.timedOut
                }
                try await Task.sleep(nanoseconds: 10_000_000)
            }
            process.waitUntilExit()
            let captured = try await reader.value
            guard !captured.exceededLimit else {
                throw AgentPassOnboardingStatusProviderError.outputTooLarge
            }
            guard process.terminationReason == .exit, allowNonZeroExit || process.terminationStatus == 0 else {
                throw AgentPassOnboardingStatusProviderError.commandUnavailable
            }
            return captured.data
        } catch {
            if process.isRunning {
                await stop(process)
            }
            _ = try? await reader.value
            throw error
        }
    }

    /// Test-only access to the real Process runner. Production callers must
    /// arrive through `init` so the executable trust check remains mandatory.
    internal static func runProcessForTesting(
        executableURL: URL,
        arguments: [String],
        maximumOutputBytes: Int,
        timeout: TimeInterval
    ) async throws -> Data {
        try await runProcess(
            executableURL: executableURL,
            arguments: arguments,
            maximumOutputBytes: maximumOutputBytes,
            timeout: timeout,
            requireTrustedExecutable: false,
            allowNonZeroExit: false
        )
    }

    private static func stop(_ process: Process) async {
        guard process.isRunning else { return }
        process.terminate()
        for _ in 0..<20 where process.isRunning {
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
#if canImport(Darwin)
        if process.isRunning {
            _ = Darwin.kill(process.processIdentifier, SIGKILL)
        }
#endif
        process.waitUntilExit()
    }


    /// Owns the exact executable object used by Process. The descriptor is
    /// deliberately kept open until after `Process.run()` so `/dev/fd/N`
    /// resolves to the object that was checked, not to the current pathname.
    private final class OpenExecutable {
        let descriptor: Int32
        let launchURL: URL
        let launchArgumentsPrefix: [String]

        init(url: URL, requireTrustedCode: Bool) throws {
#if canImport(Darwin)
            if !requireTrustedCode {
                // This branch is reachable only through the internal test seam.
                // It intentionally avoids production trust policy so fixture
                // scripts can be exercised on macOS paths such as /var, whose
                // public alias may be symlinked. Public initialization always
                // takes the descriptor-pinned, no-follow path below.
                let descriptor = Darwin.open(url.path, O_RDONLY | O_CLOEXEC)
                guard descriptor >= 0 else {
                    throw AgentPassOnboardingStatusProviderError.untrustedExecutable
                }
                var opened = stat()
                guard fstat(descriptor, &opened) == 0,
                      (opened.st_mode & S_IFMT) == S_IFREG,
                      opened.st_size > 0 else {
                    Darwin.close(descriptor)
                    throw AgentPassOnboardingStatusProviderError.untrustedExecutable
                }
                let descriptorFlags = fcntl(descriptor, F_GETFD)
                guard descriptorFlags >= 0,
                      fcntl(descriptor, F_SETFD, descriptorFlags & ~FD_CLOEXEC) == 0 else {
                    Darwin.close(descriptor)
                    throw AgentPassOnboardingStatusProviderError.untrustedExecutable
                }
                self.descriptor = descriptor
                // Process/posix_spawn cannot reliably execute an interpreter
                // script through /dev/fd on every supported macOS version.
                // The internal fixture seam therefore delegates only scripts
                // to the system shell; production always uses the descriptor
                // pinned native executable path below.
                if let prefix = try? Data(contentsOf: url), prefix.starts(with: Data("#!".utf8)) {
                    self.launchURL = URL(fileURLWithPath: "/bin/sh")
                    self.launchArgumentsPrefix = [url.path]
                } else {
                    self.launchURL = URL(fileURLWithPath: "/dev/fd/\(descriptor)")
                    self.launchArgumentsPrefix = []
                }
                return
            }
            // macOS exposes /tmp and /var through symlinked ancestors. Resolve
            // those stable system aliases once, then traverse the resulting
            // path exclusively with openat(O_NOFOLLOW); no later pathname
            // lookup can redirect the descriptor we launch.
            let canonicalURL = url.resolvingSymlinksInPath()
            let descriptor = try Self.openExecutableDescriptor(url: canonicalURL, requireTrustedCode: requireTrustedCode)
            self.descriptor = descriptor
            self.launchURL = URL(fileURLWithPath: "/dev/fd/\(descriptor)")
            self.launchArgumentsPrefix = []
#else
            throw AgentPassOnboardingStatusProviderError.untrustedExecutable
#endif
        }

        deinit {
#if canImport(Darwin)
            Darwin.close(descriptor)
#endif
        }

#if canImport(Darwin)
        private static func openExecutableDescriptor(url: URL, requireTrustedCode: Bool) throws -> Int32 {
            guard let components = pathComponents(for: url), let leaf = components.last else {
                throw AgentPassOnboardingStatusProviderError.untrustedExecutable
            }

            let rootDescriptor = Darwin.open(
                "/",
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
            )
            guard rootDescriptor >= 0 else {
                throw AgentPassOnboardingStatusProviderError.untrustedExecutable
            }

            var parentDescriptor = rootDescriptor
            do {
                var root = stat()
                guard fstat(rootDescriptor, &root) == 0,
                      Self.isTrustedDirectory(root, required: requireTrustedCode) else {
                    throw AgentPassOnboardingStatusProviderError.untrustedExecutable
                }

                for component in components.dropLast() {
                    let next = Darwin.openat(
                        parentDescriptor,
                        component,
                        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
                    )
                    guard next >= 0 else {
                        throw AgentPassOnboardingStatusProviderError.untrustedExecutable
                    }
                    var parent = stat()
                    guard fstat(next, &parent) == 0,
                          Self.isTrustedDirectory(parent, required: requireTrustedCode) else {
                        Darwin.close(next)
                        throw AgentPassOnboardingStatusProviderError.untrustedExecutable
                    }
                    if parentDescriptor != rootDescriptor {
                        Darwin.close(parentDescriptor)
                    }
                    parentDescriptor = next
                }

                let descriptor = Darwin.openat(
                    parentDescriptor,
                    leaf,
                    O_RDONLY | O_NOFOLLOW | O_CLOEXEC
                )
                guard descriptor >= 0 else {
                    throw AgentPassOnboardingStatusProviderError.untrustedExecutable
                }

                var opened = stat()
                guard fstat(descriptor, &opened) == 0,
                      (opened.st_mode & S_IFMT) == S_IFREG,
                      opened.st_size > 0,
                      opened.st_nlink == 1,
                      Self.pathStillNames(url, opened) else {
                    Darwin.close(descriptor)
                    throw AgentPassOnboardingStatusProviderError.untrustedExecutable
                }

                if requireTrustedCode {
                    guard (opened.st_mode & 0o222) == 0,
                          opened.st_uid == 0 || opened.st_uid == getuid(),
                          Self.hasTrustedCodeSignature(at: url),
                          Self.pathStillNames(url, opened) else {
                        Darwin.close(descriptor)
                        throw AgentPassOnboardingStatusProviderError.untrustedExecutable
                    }
                }

                let descriptorFlags = fcntl(descriptor, F_GETFD)
                guard descriptorFlags >= 0,
                      fcntl(descriptor, F_SETFD, descriptorFlags & ~FD_CLOEXEC) == 0 else {
                    Darwin.close(descriptor)
                    throw AgentPassOnboardingStatusProviderError.untrustedExecutable
                }

                if parentDescriptor != rootDescriptor {
                    Darwin.close(parentDescriptor)
                }
                Darwin.close(rootDescriptor)
                return descriptor
            } catch {
                if parentDescriptor != rootDescriptor {
                    Darwin.close(parentDescriptor)
                }
                Darwin.close(rootDescriptor)
                throw error
            }
        }

        private static func pathComponents(for url: URL) -> [String]? {
            guard url.isFileURL,
                  url.path.hasPrefix("/"),
                  url.standardizedFileURL.path == url.path else {
                return nil
            }
            let components = url.path
                .split(separator: "/", omittingEmptySubsequences: true)
                .map(String.init)
            guard !components.isEmpty,
                  components.allSatisfy({ $0 != "." && $0 != ".." }) else {
                return nil
            }
            return components
        }

        private static func isTrustedDirectory(_ value: stat, required: Bool) -> Bool {
            guard (value.st_mode & S_IFMT) == S_IFDIR else { return false }
            guard required else { return true }
            return (value.st_mode & 0o222) == 0
                && (value.st_uid == 0 || value.st_uid == getuid())
        }

        private static func pathStillNames(_ url: URL, _ opened: stat) -> Bool {
            var named = stat()
            return lstat(url.path, &named) == 0
                && named.st_dev == opened.st_dev
                && named.st_ino == opened.st_ino
        }

        private static func hasTrustedCodeSignature(at url: URL) -> Bool {
            guard let expectedTeamID = currentTeamIdentifier() else { return false }
            let requirementText = "anchor apple generic and identifier \"dev.agentpass\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"\(expectedTeamID)\""
            var requirement: SecRequirement?
            guard SecRequirementCreateWithString(requirementText as CFString, [], &requirement) == errSecSuccess,
                  let requirement else {
                return false
            }
            var staticCode: SecStaticCode?
            guard SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode) == errSecSuccess,
                  let staticCode,
                  SecStaticCodeCheckValidity(staticCode, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else {
                return false
            }
            var information: CFDictionary?
            guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
                  let dictionary = information as? [String: Any],
                  let identifier = dictionary[kSecCodeInfoIdentifier as String] as? String,
                  let teamID = dictionary[kSecCodeInfoTeamIdentifier as String] as? String else {
                return false
            }
            return trustedExecutableIdentifiers.contains(identifier) && teamID == expectedTeamID
        }

        private static func currentTeamIdentifier() -> String? {
            guard let executableURL = Bundle.main.executableURL else { return nil }
            var staticCode: SecStaticCode?
            guard SecStaticCodeCreateWithPath(executableURL as CFURL, [], &staticCode) == errSecSuccess,
                  let staticCode,
                  SecStaticCodeCheckValidity(staticCode, SecCSFlags(rawValue: kSecCSStrictValidate), nil) == errSecSuccess else {
                return nil
            }
            var information: CFDictionary?
            guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
                  let dictionary = information as? [String: Any],
                  let teamID = dictionary[kSecCodeInfoTeamIdentifier as String] as? String,
                  teamID.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil else {
                return nil
            }
            return teamID
        }
#endif
    }
}

public enum AgentPassOnboardingStatusProviderError: Error, Equatable, Sendable {
    case commandUnavailable
    case untrustedExecutable
    case timedOut
    case outputTooLarge
    case invalidStatus
}

extension AgentPassOnboardingStatusProviderError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .commandUnavailable:
            return "AgentPass setup status is unavailable."
        case .untrustedExecutable:
            return "AgentPass setup status is unavailable until the signed CLI is verified."
        case .timedOut:
            return "AgentPass setup status timed out."
        case .outputTooLarge:
            return "AgentPass setup status exceeded its safe output limit."
        case .invalidStatus:
            return "AgentPass returned an invalid setup status."
        }
    }
}
