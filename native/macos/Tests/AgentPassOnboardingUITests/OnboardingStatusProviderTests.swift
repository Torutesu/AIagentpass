import Foundation
import Testing
@testable import AgentPassApp
@testable import AgentPassOnboardingUI

private let validStatus = #"{"version":1,"initialized":true,"journal_id":"123e4567-e89b-12d3-a456-426614174000","revision":1,"state":"app_verified","updated_at":"2030-01-01T00:00:00.000Z","setup_complete":false,"next_actions":[{"id":"initialize_local_config","target_state":"local_config_initialized","command":"agentpass setup continue"}],"history_length":2}"#
private let doctorReport = #"{"schema_version":1,"state":"healthy","ok":true,"generated_at":"2030-01-01T00:00:00.000Z","mode":"production-native","checks":[{"id":"app.code_identity","state":"healthy","severity":"info","summary":"ok"},{"id":"release.installed_receipt","state":"healthy","severity":"info","summary":"ok"}],"summary":{"healthy":2,"action_required":0,"degraded":0,"blocked":0},"host":{"platform":"darwin","architecture":"arm64"}}"#
private let nativeStatus = #"{"health":{"ok":true,"version":13},"audit":{"configured":true}}"#

@Test func providerUsesFixedExecutableAndArgumentsAndAdapter() async throws {
    let invocation = InvocationRecorder()
    let provider = AgentPassOnboardingStatusProvider(timeout: 2, maximumOutputBytes: 4096) { executable, arguments, maximumBytes, timeout in
        await invocation.record(executable: executable, arguments: arguments, maximumBytes: maximumBytes, timeout: timeout)
        return Data(validStatus.utf8)
    }

    let model = try await provider.status()
    let recorded = await invocation.value
    #expect(recorded?.executable == AgentPassOnboardingStatusProvider.executableURL)
    #expect(recorded?.arguments == ["setup", "status"])
    #expect(recorded?.maximumBytes == 4096)
    #expect(recorded?.timeout == 2)
    #expect(model.state == .appVerified)
    #expect(model.interaction == .readOnly)
}

@Test func providerBindsDoctorAndNativeDiagnosticsToTheValidatedViewModel() async throws {
    let recorder = ArgumentsRecorder()
    let provider = AgentPassOnboardingStatusProvider { executable, arguments, maximumBytes, timeout in
        await recorder.append(arguments)
        #expect(executable == AgentPassOnboardingStatusProvider.executableURL)
        #expect(maximumBytes == AgentPassOnboardingStatusProvider.defaultMaximumOutputBytes)
        #expect(timeout == AgentPassOnboardingStatusProvider.defaultTimeout)
        switch arguments {
        case AgentPassOnboardingStatusProvider.arguments:
            return Data(validStatus.utf8)
        case AgentPassOnboardingStatusProvider.doctorArguments:
            return Data(doctorReport.utf8)
        case AgentPassOnboardingStatusProvider.nativeStatusArguments:
            return Data(nativeStatus.utf8)
        default:
            Issue.record("Unexpected command arguments")
            return Data()
        }
    }

    let model = try await provider.status()
    let arguments = await recorder.values
    #expect(arguments.count == 3)
    #expect(arguments.contains(AgentPassOnboardingStatusProvider.arguments))
    #expect(arguments.contains(AgentPassOnboardingStatusProvider.doctorArguments))
    #expect(arguments.contains(AgentPassOnboardingStatusProvider.nativeStatusArguments))
    #expect(model.distribution.developerID == .verified)
    #expect(model.distribution.releaseReceipt == .verified)
    #expect(model.capability.secureEnclave == .verified)
    #expect(model.safeRecoveryActions.contains(where: { $0.id == .revoke }))
}

@Test func providerRejectsMalformedOutputWithoutSurfacingContents() async {
    let provider = AgentPassOnboardingStatusProvider { _, _, _, _ in
        throw FakeFailure.secret
    }
    do {
        _ = try await provider.status()
        Issue.record("Expected provider failure")
    } catch let error as AgentPassOnboardingStatusProviderError {
        #expect(error == .commandUnavailable)
        #expect(error.localizedDescription.contains("secret") == false)
    } catch {
        Issue.record("Unexpected error: \(error)")
    }
}

@Test func providerMapsAdapterFailureToSafeInvalidStatus() async {
    let provider = AgentPassOnboardingStatusProvider { _, _, _, _ in
        Data(#"{"version":1,"state":"secret-token"}"#.utf8)
    }
    do {
        _ = try await provider.status()
        Issue.record("Expected invalid status")
    } catch let error as AgentPassOnboardingStatusProviderError {
        #expect(error == .invalidStatus)
    } catch {
        Issue.record("Unexpected error: \(error)")
    }
}

@Test func providerPreservesBoundedOperationalErrorsAndCancellation() async {
    let timeoutProvider = AgentPassOnboardingStatusProvider { _, _, _, _ in
        throw AgentPassOnboardingStatusProviderError.timedOut
    }
    do {
        _ = try await timeoutProvider.status()
        Issue.record("Expected timeout")
    } catch let error as AgentPassOnboardingStatusProviderError {
        #expect(error == .timedOut)
    } catch {
        Issue.record("Unexpected error: \(error)")
    }

    let cancelledProvider = AgentPassOnboardingStatusProvider { _, _, _, _ in
        throw CancellationError()
    }
    do {
        _ = try await cancelledProvider.status()
        Issue.record("Expected cancellation")
    } catch is CancellationError {
        // Expected.
    } catch {
        Issue.record("Unexpected error: \(error)")
    }
}

@Test func productionRunnerClosesInputUsesExactArgumentsAndParsesBoundedOutput() async throws {
    let fixture = try executableFixture("""
    #!/bin/sh
    [ "$1" = "setup" ] && [ "$2" = "status" ] && [ "$#" -eq 2 ] || exit 41
    if read unexpected; then exit 42; fi
    printf '%s' '\(validStatus)'
    """)
    defer { try? FileManager.default.removeItem(at: fixture.directory) }

    let provider = AgentPassOnboardingStatusProvider(
        timeout: 2,
        maximumOutputBytes: 4096,
        executableURL: fixture.executable,
        commandRunner: fixtureRunner
    )
    let status = try await provider.status()
    #expect(status.state == .appVerified)
}

@Test func productionRunnerRejectsOversizedOutput() async {
    let fixture: ExecutableFixture
    do {
        fixture = try executableFixture("""
        #!/bin/sh
        i=0
        while [ "$i" -lt 5000 ]; do printf x; i=$((i + 1)); done
        """)
    } catch {
        Issue.record("Could not create fixture: \(error)")
        return
    }
    defer { try? FileManager.default.removeItem(at: fixture.directory) }

    let provider = AgentPassOnboardingStatusProvider(
        timeout: 2,
        maximumOutputBytes: 1024,
        executableURL: fixture.executable,
        commandRunner: fixtureRunner
    )
    do {
        _ = try await provider.status()
        Issue.record("Expected output limit failure")
    } catch let error as AgentPassOnboardingStatusProviderError {
        #expect(error == .outputTooLarge)
    } catch {
        Issue.record("Unexpected error: \(error)")
    }
}

@Test func productionRunnerForceStopsAChildThatIgnoresTermination() async {
    let fixture: ExecutableFixture
    do {
        fixture = try executableFixture("""
        #!/bin/sh
        trap '' TERM
        while :; do :; done
        """)
    } catch {
        Issue.record("Could not create fixture: \(error)")
        return
    }
    defer { try? FileManager.default.removeItem(at: fixture.directory) }

    let started = ContinuousClock.now
    let provider = AgentPassOnboardingStatusProvider(
        timeout: 0.05,
        maximumOutputBytes: 1024,
        executableURL: fixture.executable,
        commandRunner: fixtureRunner
    )
    do {
        _ = try await provider.status()
        Issue.record("Expected timeout")
    } catch let error as AgentPassOnboardingStatusProviderError {
        #expect(error == .timedOut)
        // Parallel CI can heavily delay the cooperative polling task; it must
        // still prove that an ignored SIGTERM is escalated instead of hanging.
        #expect(ContinuousClock.now - started < .seconds(15))
    } catch {
        Issue.record("Unexpected error: \(error)")
    }
}

@Test func productionRunnerRejectsAnUntrustedExecutableBeforeLaunchingIt() async throws {
    let fixture = try executableFixture("#!/bin/sh\nprintf '%s' '\(validStatus)'\n")
    defer { try? FileManager.default.removeItem(at: fixture.directory) }

    let provider = AgentPassOnboardingStatusProvider(
        executableURL: fixture.executable
    )
    do {
        _ = try await provider.status()
        Issue.record("Expected executable trust failure")
    } catch let error as AgentPassOnboardingStatusProviderError {
        #expect(error == .untrustedExecutable)
    } catch {
        Issue.record("Unexpected error: \(error)")
    }
}

private func fixtureRunner(
    executableURL: URL,
    arguments: [String],
    maximumOutputBytes: Int,
    timeout: TimeInterval
) async throws -> Data {
    try await AgentPassOnboardingStatusProvider.runProcessForTesting(
        executableURL: executableURL,
        arguments: arguments,
        maximumOutputBytes: maximumOutputBytes,
        timeout: timeout
    )
}

private enum FakeFailure: Error {
    case secret
}

private struct ExecutableFixture {
    let directory: URL
    let executable: URL
}

private func executableFixture(_ source: String) throws -> ExecutableFixture {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("agentpass-onboarding-tests-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    let executable = directory.appendingPathComponent("status-fixture")
    try Data(source.utf8).write(to: executable, options: .withoutOverwriting)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
    return ExecutableFixture(directory: directory, executable: executable)
}

private actor InvocationRecorder {
    struct Value: Sendable {
        let executable: URL
        let arguments: [String]
        let maximumBytes: Int
        let timeout: TimeInterval
    }

    private(set) var value: Value?

    func record(executable: URL, arguments: [String], maximumBytes: Int, timeout: TimeInterval) {
        if value == nil {
            value = Value(executable: executable, arguments: arguments, maximumBytes: maximumBytes, timeout: timeout)
        }
    }
}

private actor ArgumentsRecorder {
    private(set) var values: [[String]] = []

    func append(_ arguments: [String]) {
        values.append(arguments)
    }
}
