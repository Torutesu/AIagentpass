import Foundation
import AgentPassApp
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
    public static let defaultMaximumOutputBytes = 256 * 1024
    public static let defaultTimeout: TimeInterval = 5

    /// The command boundary is injectable so UI tests never execute the production CLI.
    public typealias CommandRunner = @Sendable (URL, [String], Int, TimeInterval) async throws -> Data

    private let timeout: TimeInterval
    private let maximumOutputBytes: Int
    private let executableURL: URL
    private let commandRunner: CommandRunner

    public init(
        timeout: TimeInterval = Self.defaultTimeout,
        maximumOutputBytes: Int = Self.defaultMaximumOutputBytes,
        executableURL: URL = Self.executableURL,
        commandRunner: CommandRunner? = nil
    ) {
        self.timeout = max(0.001, timeout)
        self.maximumOutputBytes = min(Self.defaultMaximumOutputBytes, max(1, maximumOutputBytes))
        self.executableURL = executableURL
        self.commandRunner = commandRunner ?? { executableURL, arguments, maximumOutputBytes, timeout in
            try await Self.runProcess(
                executableURL: executableURL,
                arguments: arguments,
                maximumOutputBytes: maximumOutputBytes,
                timeout: timeout
            )
        }
    }

    /// Executes the fixed status command and validates its output through the app adapter.
    public func status() async throws -> AgentPassOnboardingViewModel {
        do {
            let data = try await commandRunner(
                executableURL,
                Self.arguments,
                maximumOutputBytes,
                timeout
            )
            do {
                return try AgentPassOnboardingStatusAdapter().viewModel(from: data)
            } catch {
                throw AgentPassOnboardingStatusProviderError.invalidStatus
            }
        } catch let error as AgentPassOnboardingStatusProviderError {
            throw error
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            // Deliberately do not expose process output, stderr, paths, or command errors.
            throw AgentPassOnboardingStatusProviderError.commandUnavailable
        }
    }

    private struct CapturedOutput: Sendable {
        let data: Data
        let exceededLimit: Bool
    }

    private static func runProcess(
        executableURL: URL,
        arguments: [String],
        maximumOutputBytes: Int,
        timeout: TimeInterval
    ) async throws -> Data {
        let process = Process()
        let outputPipe = Pipe()
        process.executableURL = executableURL
        process.arguments = arguments
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
            guard process.terminationReason == .exit, process.terminationStatus == 0 else {
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
}

public enum AgentPassOnboardingStatusProviderError: Error, Equatable, Sendable {
    case commandUnavailable
    case timedOut
    case outputTooLarge
    case invalidStatus
}

extension AgentPassOnboardingStatusProviderError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .commandUnavailable:
            return "AgentPass setup status is unavailable."
        case .timedOut:
            return "AgentPass setup status timed out."
        case .outputTooLarge:
            return "AgentPass setup status exceeded its safe output limit."
        case .invalidStatus:
            return "AgentPass returned an invalid setup status."
        }
    }
}
