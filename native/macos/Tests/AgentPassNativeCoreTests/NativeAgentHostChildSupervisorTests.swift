import AgentPassNativeCore
import Foundation
import Testing

private final class HostSupervisorFixture: @unchecked Sendable {
    private let lock = NSLock()
    var spawnSpec: NativeAgentHostSpawnSpec?
    var signals: [(NativeAgentHostProcessHandle, NativeAgentHostForwardedSignal)] = []
    var waitCallCount = 0
    var spawnError = false
    var waitError = false
    var waitOutcome: NativeAgentHostWaitOutcome = .exitedSuccessfully

    func hooks(process: NativeAgentHostProcessHandle = .init(processIdentifier: 700, processGroupIdentifier: 700))
        -> NativeAgentHostChildSupervisorHooks
    {
        NativeAgentHostChildSupervisorHooks(
            spawn: { [self] spec in
                lock.lock()
                defer { lock.unlock() }
                if spawnError {
                    throw TestFixtureError.failed
                }
                spawnSpec = spec
                return process
            },
            signal: { [self] process, signal in
                lock.lock()
                signals.append((process, signal))
                lock.unlock()
            },
            wait: { [self] _ in
                lock.lock()
                waitCallCount += 1
                let shouldFail = waitError
                let outcome = waitOutcome
                lock.unlock()
                if shouldFail {
                    throw TestFixtureError.failed
                }
                return outcome
            }
        )
    }

    func snapshot() -> (
        spec: NativeAgentHostSpawnSpec?,
        signals: [(NativeAgentHostProcessHandle, NativeAgentHostForwardedSignal)],
        waitCallCount: Int
    ) {
        lock.lock()
        defer { lock.unlock() }
        return (spawnSpec, signals, waitCallCount)
    }
}

private enum TestFixtureError: Error {
    case failed
}

private func withTemporaryProjectDirectory<T>(
    _ body: (NativeAgentHostProjectDirectory) throws -> T
) throws -> T {
    let path = FileManager.default.temporaryDirectory
        .appendingPathComponent("agentpass-host-\(UUID().uuidString)", isDirectory: true)
        .path
    try FileManager.default.createDirectory(
        atPath: path,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    defer { try? FileManager.default.removeItem(atPath: path) }
    return try body(try NativeAgentHostProjectDirectory(path: path))
}

private func makeRequest(
    adapter: NativeAgentHostAdapterKind = .claudeCode,
    projectDirectory: NativeAgentHostProjectDirectory,
    environment: [String: String] = [
        "HOME": "/Users/tester",
        "TMPDIR": "/private/tmp/",
        "LANG": "en_US.UTF-8",
        "TERM": "dumb",
        "USER": "tester"
    ]
) throws -> NativeAgentHostChildLaunchRequest {
    try NativeAgentHostChildLaunchRequest(
        adapter: adapter,
        projectDirectory: projectDirectory,
        trustedEnvironment: environment
    )
}

@Test func projectDirectoryRequiresCanonicalAbsoluteExistingDirectory() throws {
    let base = FileManager.default.temporaryDirectory
        .appendingPathComponent("agentpass-host-path-\(UUID().uuidString)", isDirectory: true)
    let child = base.appendingPathComponent("project", isDirectory: true)
    try FileManager.default.createDirectory(at: child, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: base) }

    #expect(throws: NativeAgentHostProjectDirectoryError.notAbsolute) {
        _ = try NativeAgentHostProjectDirectory(path: "relative/project")
    }
    #expect(throws: NativeAgentHostProjectDirectoryError.notCanonical) {
        _ = try NativeAgentHostProjectDirectory(path: child.path + "/../project")
    }
    #expect(throws: NativeAgentHostProjectDirectoryError.missing) {
        _ = try NativeAgentHostProjectDirectory(path: base.appendingPathComponent("missing").path)
    }
    try #expect(NativeAgentHostProjectDirectory(path: child.path).path == child.path)
}

@Test func projectDirectoryRejectsSymlinkBindingAndRegularFile() throws {
    let base = FileManager.default.temporaryDirectory
        .appendingPathComponent("agentpass-host-symlink-\(UUID().uuidString)", isDirectory: true)
    let target = base.appendingPathComponent("target", isDirectory: true)
    let link = base.appendingPathComponent("link", isDirectory: true)
    let file = base.appendingPathComponent("file")
    try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
    try Data("not a directory".utf8).write(to: file)
    defer { try? FileManager.default.removeItem(at: base) }

    #expect(throws: NativeAgentHostProjectDirectoryError.notCanonical) {
        _ = try NativeAgentHostProjectDirectory(path: link.path)
    }
    #expect(throws: NativeAgentHostProjectDirectoryError.notDirectory) {
        _ = try NativeAgentHostProjectDirectory(path: file.path)
    }
}

@Test func fixedAdapterHasNoExecutableSelectorAndCursorIsNotYetLaunchable() throws {
    try withTemporaryProjectDirectory { project in
        let fixture = HostSupervisorFixture()
        let supervisor = NativeAgentHostChildSupervisor(hooks: fixture.hooks())
        let request = try makeRequest(projectDirectory: project)
        _ = try supervisor.start(request)

        let spec = fixture.snapshot().spec
        #expect(spec?.useOwnedProcessGroup == true)
        #expect(spec?.arguments.isEmpty == true)
        #expect(spec?.executablePath.hasPrefix("/") == true)
        #expect(spec?.executablePath == "/opt/homebrew/bin/claude"
            || spec?.executablePath == "/usr/local/bin/claude")

        let cursorRequest = try makeRequest(adapter: .cursor, projectDirectory: project)
        #expect(throws: NativeAgentHostChildSupervisorError.unsupportedAdapter) {
            _ = try supervisor.start(cursorRequest)
        }
    }
}

@Test func environmentIsStrictlyAllowlistedAndRemovesAgentPassAndNodeInjection() throws {
    try withTemporaryProjectDirectory { project in
        let fixture = HostSupervisorFixture()
        let supervisor = NativeAgentHostChildSupervisor(hooks: fixture.hooks())
        let request = try makeRequest(
            projectDirectory: project,
            environment: [
                "HOME": "/Users/tester",
                "TMPDIR": "/private/tmp/",
                "LANG": "en_US.UTF-8",
                "TERM": "dumb",
                "USER": "tester",
                "AGENTPASS_SESSION_PROOF": "secret",
                "AGENTPASS_TOKEN": "secret",
                "NODE_OPTIONS": "--require=/tmp/injected.js",
                "NODE_PATH": "/tmp/injected",
                "NODE_EXTRA_CA_CERTS": "/tmp/ca.pem",
                "ELECTRON_RUN_AS_NODE": "1",
                "DYLD_INSERT_LIBRARIES": "/tmp/injected.dylib",
                "GIT_CONFIG_COMMAND意": "injected",
                "UNTRUSTED_CUSTOM_VALUE": "discard me"
            ]
        )
        _ = try supervisor.start(request)

        let environment = try #require(fixture.snapshot().spec?.environment)
        #expect(environment["HOME"] == "/Users/tester")
        #expect(environment["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin")
        #expect(environment["PWD"] == project.path)
        #expect(environment["AGENTPASS_SESSION_PROOF"] == nil)
        #expect(environment["AGENTPASS_TOKEN"] == nil)
        #expect(environment["NODE_OPTIONS"] == nil)
        #expect(environment["NODE_PATH"] == nil)
        #expect(environment["NODE_EXTRA_CA_CERTS"] == nil)
        #expect(environment["ELECTRON_RUN_AS_NODE"] == nil)
        #expect(environment["DYLD_INSERT_LIBRARIES"] == nil)
        #expect(environment["GIT_CONFIG_COMMAND意"] == nil)
        #expect(environment["UNTRUSTED_CUSTOM_VALUE"] == nil)
    }
}

@Test func invalidEnvironmentControlCharactersAreRejectedBeforeSpawn() throws {
    _ = try withTemporaryProjectDirectory { project in
        #expect(throws: NativeAgentHostChildLaunchRequestError.invalidEnvironment) {
            _ = try makeRequest(projectDirectory: project, environment: ["TERM": "bad\nvalue"])
        }
    }
}

@Test func supervisorForwardsOnlyCooperativeSignalsToOwnedGroupAndReapsOnce() throws {
    try withTemporaryProjectDirectory { project in
        let fixture = HostSupervisorFixture()
        let supervisor = NativeAgentHostChildSupervisor(hooks: fixture.hooks())
        let session = try supervisor.start(try makeRequest(projectDirectory: project))

        try session.forward(.terminate)
        try session.forward(.interrupt)
        #expect(try session.wait() == .success)
        #expect(try session.wait() == .success)

        let snapshot = fixture.snapshot()
        #expect(snapshot.signals.count == 2)
        #expect(snapshot.signals.map { $0.0.processGroupIdentifier } == [700, 700])
        #expect(snapshot.signals.map { $0.1 } == [.terminate, .interrupt])
        #expect(snapshot.waitCallCount == 1)
        #expect(throws: NativeAgentHostChildSupervisorError.childAlreadyWaited) {
            try session.forward(.terminate)
        }
    }
}

@Test(arguments: [
    NativeAgentHostWaitOutcome.exitedSuccessfully,
    NativeAgentHostWaitOutcome.exitedWithFailure,
    NativeAgentHostWaitOutcome.terminatedBySignal
])
func waitOutcomeIsReducedToBoundedExitClassification(_ outcome: NativeAgentHostWaitOutcome) throws {
    try withTemporaryProjectDirectory { project in
        let fixture = HostSupervisorFixture()
        fixture.waitOutcome = outcome
        let supervisor = NativeAgentHostChildSupervisor(hooks: fixture.hooks())
        let session = try supervisor.start(try makeRequest(projectDirectory: project))

        let expected: NativeAgentHostExitClassification = switch outcome {
        case .exitedSuccessfully: .success
        case .exitedWithFailure: .failure
        case .terminatedBySignal: .terminated
        }
        #expect(try session.wait() == expected)
    }
}

@Test func launchAndWaitFailuresAreBoundedAndDoNotExposeErrno() throws {
    try withTemporaryProjectDirectory { project in
        let launchFixture = HostSupervisorFixture()
        launchFixture.spawnError = true
        let launchSupervisor = NativeAgentHostChildSupervisor(hooks: launchFixture.hooks())
        #expect(throws: NativeAgentHostChildSupervisorError.launchFailed) {
            _ = try launchSupervisor.start(try makeRequest(projectDirectory: project))
        }

        let waitFixture = HostSupervisorFixture()
        waitFixture.waitError = true
        let waitSupervisor = NativeAgentHostChildSupervisor(hooks: waitFixture.hooks())
        let session = try waitSupervisor.start(try makeRequest(projectDirectory: project))
        #expect(throws: NativeAgentHostChildSupervisorError.waitFailed) {
            _ = try session.wait()
        }
    }
}

@Test func childMustOwnItsOwnProcessGroup() throws {
    try withTemporaryProjectDirectory { project in
        let fixture = HostSupervisorFixture()
        let supervisor = NativeAgentHostChildSupervisor(
            hooks: fixture.hooks(process: .init(processIdentifier: 701, processGroupIdentifier: 702))
        )
        #expect(throws: NativeAgentHostChildSupervisorError.processGroupNotOwned) {
            _ = try supervisor.start(try makeRequest(projectDirectory: project))
        }
        #expect(fixture.snapshot().waitCallCount == 0)
        #expect(fixture.snapshot().signals.isEmpty)
    }
}

@Test func droppingLiveSessionRequestsCooperativeCleanupAndReap() throws {
    try withTemporaryProjectDirectory { project in
        let fixture = HostSupervisorFixture()
        let supervisor = NativeAgentHostChildSupervisor(hooks: fixture.hooks())
        var session: NativeAgentHostChildSession? = try supervisor.start(try makeRequest(projectDirectory: project))
        #expect(session != nil)
        session = nil

        let snapshot = fixture.snapshot()
        #expect(snapshot.signals.map { $0.1 } == [.terminate])
        #expect(snapshot.waitCallCount == 1)
    }
}
