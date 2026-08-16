import AgentPassNativeCore
import Darwin
import Foundation
import Testing

private final class HostSupervisorFixture: @unchecked Sendable {
    private let lock = NSLock()
    var spawnSpec: NativeAgentHostSpawnSpec?
    var signals: [(NativeAgentHostProcessHandle, NativeAgentHostForwardedSignal)] = []
    var terminatedProcesses: [NativeAgentHostProcessHandle] = []
    var waitCallCount = 0
    var spawnError = false
    var waitError = false
    var waitOutcome: NativeAgentHostWaitOutcome = .exitedSuccessfully
    var installPrivateBridgeActions = true
    var rejectPrivateBridgeActions = false
    var privateBridgeDuplicateCalls: [(Int32, Int32)] = []
    var privateBridgeCloseCalls: [Int32] = []

    func hooks(process: NativeAgentHostProcessHandle = .init(processIdentifier: 700, processGroupIdentifier: 700))
        -> NativeAgentHostChildSupervisorHooks
    {
        NativeAgentHostChildSupervisorHooks(
            spawn: { [self] spec in
                lock.lock()
                if spawnError {
                    lock.unlock()
                    throw TestFixtureError.failed
                }
                let installBridge = installPrivateBridgeActions
                let rejectBridge = rejectPrivateBridgeActions
                spawnSpec = spec
                lock.unlock()
                if installBridge {
                    try spec.installPrivateGitBridgeFileActions(
                        addDuplicate: { [self] source, target in
                            lock.lock()
                            privateBridgeDuplicateCalls.append((source, target))
                            lock.unlock()
                        },
                        addClose: { [self] source in
                            lock.lock()
                            privateBridgeCloseCalls.append(source)
                            lock.unlock()
                            if rejectBridge { throw TestFixtureError.failed }
                        }
                    )
                }
                return process
            },
            signal: { [self] process, signal in
                lock.lock()
                signals.append((process, signal))
                lock.unlock()
            },
            terminateProcess: { [self] process in
                lock.lock()
                terminatedProcesses.append(process)
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

    func terminationCallCount() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return terminatedProcesses.count
    }

    func privateBridgeActions() -> (duplicates: [(Int32, Int32)], closes: [Int32]) {
        lock.lock()
        defer { lock.unlock() }
        return (privateBridgeDuplicateCalls, privateBridgeCloseCalls)
    }
}

private final class ProjectDirectoryHookFixture: @unchecked Sendable {
    private let lock = NSLock()
    var openDescriptors: [Int32] = []
    var closedDescriptors: [Int32] = []
    var inspectedIdentities: [NativeAgentHostProjectDirectoryIdentity] = []
    var identityForOpen: [Int32: NativeAgentHostProjectDirectoryIdentity] = [:]
    var nextDescriptor: Int32 = 40
    var openError = false
    var inspectError = false
    var closeCallCount = 0
    var closeErrorOnCall: Int?

    let owner: UInt32 = 501
    let directoryIdentity = NativeAgentHostProjectDirectoryIdentity(
        device: 10,
        inode: 20,
        ownerUserID: 501,
        mode: UInt32(S_IFDIR) | 0o700
    )
    let substitutedIdentity = NativeAgentHostProjectDirectoryIdentity(
        device: 10,
        inode: 21,
        ownerUserID: 501,
        mode: UInt32(S_IFDIR) | 0o700
    )

    func hooks() -> NativeAgentHostProjectDirectoryHooks {
        NativeAgentHostProjectDirectoryHooks(
            open: { [self] _ in
                lock.lock()
                defer { lock.unlock() }
                if openError { throw TestFixtureError.failed }
                let descriptor = nextDescriptor
                nextDescriptor += 1
                openDescriptors.append(descriptor)
                return descriptor
            },
            inspect: { [self] descriptor in
                lock.lock()
                defer { lock.unlock() }
                if inspectError { throw TestFixtureError.failed }
                let identity = identityForOpen[descriptor] ?? directoryIdentity
                inspectedIdentities.append(identity)
                return identity
            },
            close: { [self] descriptor in
                lock.lock()
                closeCallCount += 1
                closedDescriptors.append(descriptor)
                let shouldFail = closeErrorOnCall == closeCallCount
                lock.unlock()
                return shouldFail ? -1 : 0
            },
            effectiveUserID: { [self] in owner }
        )
    }

    func closed() -> [Int32] {
        lock.lock()
        defer { lock.unlock() }
        return closedDescriptors
    }
}

private final class ExecutableProbeFixture: @unchecked Sendable {
    private let lock = NSLock()
    private let executablePaths: Set<String>
    private var probedPaths: [String] = []

    init(executablePaths: Set<String>) {
        self.executablePaths = executablePaths
    }

    func probe(_ path: String) -> Bool {
        lock.lock()
        probedPaths.append(path)
        let result = executablePaths.contains(path)
        lock.unlock()
        return result
    }

    func paths() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return probedPaths
    }
}

private enum TestFixtureError: Error {
    case failed
}

private func canonicalFilesystemPath(_ path: String) -> String {
    var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
    guard path.withCString({ realpath($0, &buffer) != nil }) else {
        return path
    }
    return String(cString: buffer)
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
    return try body(try NativeAgentHostProjectDirectory(path: canonicalFilesystemPath(path)))
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

private func makeHookedProjectDirectory(
    fixture: ProjectDirectoryHookFixture
) throws -> NativeAgentHostProjectDirectory {
    try NativeAgentHostProjectDirectory(
        path: "/Users/tester/project",
        hooks: fixture.hooks()
    )
}

@Test func projectDirectoryRequiresCanonicalAbsoluteExistingDirectory() throws {
    let base = FileManager.default.temporaryDirectory
        .appendingPathComponent("agentpass-host-path-\(UUID().uuidString)", isDirectory: true)
    let child = base.appendingPathComponent("project", isDirectory: true)
    try FileManager.default.createDirectory(at: child, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: base) }
    let canonicalBase = canonicalFilesystemPath(base.path)
    let canonicalChild = canonicalFilesystemPath(child.path)

    #expect(throws: NativeAgentHostProjectDirectoryError.notAbsolute) {
        _ = try NativeAgentHostProjectDirectory(path: "relative/project")
    }
    #expect(throws: NativeAgentHostProjectDirectoryError.notCanonical) {
        _ = try NativeAgentHostProjectDirectory(path: canonicalChild + "/../project")
    }
    #expect(throws: NativeAgentHostProjectDirectoryError.missing) {
        _ = try NativeAgentHostProjectDirectory(path: canonicalBase + "/missing")
    }
    try #expect(NativeAgentHostProjectDirectory(path: canonicalChild).path == canonicalChild)
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
    let canonicalBase = canonicalFilesystemPath(base.path)
    let canonicalLink = canonicalBase + "/link"
    let canonicalFile = canonicalBase + "/file"

    #expect(throws: NativeAgentHostProjectDirectoryError.notCanonical) {
        _ = try NativeAgentHostProjectDirectory(path: canonicalLink)
    }
    #expect(throws: NativeAgentHostProjectDirectoryError.notDirectory) {
        _ = try NativeAgentHostProjectDirectory(path: canonicalFile)
    }
}

@Test func projectDirectoryBindsSpawnToValidatedIdentityAfterPathSubstitution() throws {
    let directory = ProjectDirectoryHookFixture()
    let project = try makeHookedProjectDirectory(fixture: directory)
    let fixture = HostSupervisorFixture()
    let supervisor = NativeAgentHostChildSupervisor(hooks: fixture.hooks())

    // The path may be replaced after construction. The second open still
    // returns the captured inode identity, so the spawn hook receives the
    // opened descriptor rather than a path that could be re-resolved.
    let session = try supervisor.start(try makeRequest(projectDirectory: project))
    _ = try session.wait()

    let spec = try #require(fixture.snapshot().spec)
    #expect(spec.workingDirectory == project.path)
    #expect(spec.workingDirectoryFD >= 4)
    #expect(directory.closed().count == 2)
    #expect(directory.closed().allSatisfy { $0 >= 4 })
}

@Test func projectDirectoryRejectsIdentitySubstitutionAndClosesReopenedDescriptor() throws {
    let directory = ProjectDirectoryHookFixture()
    let project = try makeHookedProjectDirectory(fixture: directory)
    let reopenedDescriptor = directory.nextDescriptor
    directory.identityForOpen[reopenedDescriptor] = directory.substitutedIdentity

    let fixture = HostSupervisorFixture()
    let supervisor = NativeAgentHostChildSupervisor(hooks: fixture.hooks())
    #expect(throws: NativeAgentHostProjectDirectoryError.identityChanged) {
        _ = try supervisor.start(try makeRequest(projectDirectory: project))
    }
    #expect(directory.closed().count == 2)
}

@Test func projectDirectoryRequiresTheEffectiveUserAsOwner() throws {
    let directory = ProjectDirectoryHookFixture()
    directory.identityForOpen[40] = NativeAgentHostProjectDirectoryIdentity(
        device: 10,
        inode: 20,
        ownerUserID: 502,
        mode: UInt32(S_IFDIR) | 0o700
    )
    #expect(throws: NativeAgentHostProjectDirectoryError.ownerMismatch) {
        _ = try makeHookedProjectDirectory(fixture: directory)
    }
    #expect(directory.closed() == [40])
}

@Test func projectDirectoryClosesOpenedDescriptorWhenSpawnFails() throws {
    let directory = ProjectDirectoryHookFixture()
    let project = try makeHookedProjectDirectory(fixture: directory)
    let fixture = HostSupervisorFixture()
    fixture.spawnError = true
    let supervisor = NativeAgentHostChildSupervisor(hooks: fixture.hooks())

    #expect(throws: NativeAgentHostChildSupervisorError.launchFailed) {
        _ = try supervisor.start(try makeRequest(projectDirectory: project))
    }
    #expect(directory.closed().count == 2)
}

@Test func projectDirectoryClosesDescriptorWhenInspectionFails() throws {
    let directory = ProjectDirectoryHookFixture()
    directory.inspectError = true
    #expect(throws: TestFixtureError.failed) {
        _ = try makeHookedProjectDirectory(fixture: directory)
    }
    #expect(directory.closed().count == 1)
}

@Test func projectDirectoryCloseFailureIsBoundedAndChildIsReaped() throws {
    let directory = ProjectDirectoryHookFixture()
    let project = try makeHookedProjectDirectory(fixture: directory)
    directory.closeErrorOnCall = 2
    let fixture = HostSupervisorFixture()
    let supervisor = NativeAgentHostChildSupervisor(hooks: fixture.hooks())

    #expect(throws: NativeAgentHostChildSupervisorError.projectDirectoryCloseFailed) {
        _ = try supervisor.start(try makeRequest(projectDirectory: project))
    }
    let snapshot = fixture.snapshot()
    #expect(directory.closed().count == 2)
    #expect(snapshot.signals.map { $0.1 } == [.terminate])
    #expect(snapshot.waitCallCount == 1)
}

@Test func projectDirectoryRejectsDescriptorCollisionAndClosesIt() throws {
    for collision in [Int32(0), Int32(3)] {
        let directory = ProjectDirectoryHookFixture()
        directory.nextDescriptor = collision
        #expect(throws: NativeAgentHostProjectDirectoryError.invalidDescriptor) {
            _ = try makeHookedProjectDirectory(fixture: directory)
        }
        #expect(directory.closed() == [collision])
    }
}

@Test func fixedAdapterHasNoExecutableSelectorAndCursorFailsClosedWithoutAReviewedCLI() throws {
    try withTemporaryProjectDirectory { project in
        let fixture = HostSupervisorFixture()
        let supervisor = NativeAgentHostChildSupervisor(
            hooks: fixture.hooks(),
            executableProbe: { _ in false }
        )
        let request = try makeRequest(projectDirectory: project)
        _ = try supervisor.start(request)

        let spec = fixture.snapshot().spec
        #expect(spec?.useOwnedProcessGroup == true)
        #expect(spec?.hasPrivateGitBridgeHandoff == true)
        #expect(spec?.arguments.isEmpty == true)
        #expect(spec?.executablePath.hasPrefix("/") == true)
        #expect(spec?.executablePath == "/opt/homebrew/bin/claude"
            || spec?.executablePath == "/usr/local/bin/claude")

        let cursorRequest = try makeRequest(adapter: .cursor, projectDirectory: project)
        #expect(throws: NativeAgentHostChildSupervisorError.launchFailed) {
            _ = try supervisor.start(cursorRequest)
        }
    }
}

@Test func cursorAdapterUsesOnlyTheReviewedFixedCandidateSet() throws {
    let expectedCandidates = [
        "/Applications/Cursor.app/Contents/Resources/app/bin/code",
        "/Applications/Cursor.app/Contents/Resources/app/bin/cursor",
        "/opt/cursor-agent",
        "/opt/homebrew/bin/cursor-agent",
        "/usr/local/bin/cursor-agent"
    ]
    try withTemporaryProjectDirectory { project in
        let fixture = HostSupervisorFixture()
        let probe = ExecutableProbeFixture(executablePaths: [expectedCandidates[1]])
        let supervisor = NativeAgentHostChildSupervisor(
            hooks: fixture.hooks(),
            executableProbe: { [probe] path in probe.probe(path) }
        )

        _ = try supervisor.start(try makeRequest(adapter: .cursor, projectDirectory: project))

        let spec = try #require(fixture.snapshot().spec)
        #expect(spec.executablePath == expectedCandidates[1])
        #expect(spec.arguments.isEmpty)
        #expect(probe.paths() == Array(expectedCandidates.prefix(2)))
    }
}

@Test func cursorAdapterWithNoCandidateDoesNotCreateAChildOrExposeUnknownPath() throws {
    let expectedCandidates = [
        "/Applications/Cursor.app/Contents/Resources/app/bin/code",
        "/Applications/Cursor.app/Contents/Resources/app/bin/cursor",
        "/opt/cursor-agent",
        "/opt/homebrew/bin/cursor-agent",
        "/usr/local/bin/cursor-agent"
    ]
    try withTemporaryProjectDirectory { project in
        let fixture = HostSupervisorFixture()
        let probe = ExecutableProbeFixture(executablePaths: ["/tmp/attacker/cursor-agent"])
        let supervisor = NativeAgentHostChildSupervisor(
            hooks: fixture.hooks(),
            executableProbe: { [probe] path in probe.probe(path) }
        )

        #expect(throws: NativeAgentHostChildSupervisorError.launchFailed) {
            _ = try supervisor.start(try makeRequest(adapter: .cursor, projectDirectory: project))
        }
        #expect(probe.paths() == expectedCandidates)
        #expect(fixture.snapshot().spec == nil)
        #expect(fixture.snapshot().waitCallCount == 0)
        #expect(fixture.privateBridgeActions().duplicates.isEmpty)
    }
}

@Test func cursorAdapterReusesPrivateBridgeCwdAndOwnedProcessGroupConstraints() throws {
    let cursorBundleCLI = "/Applications/Cursor.app/Contents/Resources/app/bin/code"
    try withTemporaryProjectDirectory { project in
        let fixture = HostSupervisorFixture()
        let supervisor = NativeAgentHostChildSupervisor(
            hooks: fixture.hooks(),
            executableProbe: { path in path == cursorBundleCLI }
        )

        let session = try supervisor.start(
            try makeRequest(adapter: .cursor, projectDirectory: project)
        )
        let spec = try #require(fixture.snapshot().spec)
        let actions = fixture.privateBridgeActions()

        #expect(spec.executablePath == cursorBundleCLI)
        #expect(spec.arguments.isEmpty)
        #expect(spec.workingDirectory == project.path)
        #expect(spec.workingDirectoryFD >= 4)
        #expect(spec.useOwnedProcessGroup)
        #expect(spec.hasPrivateGitBridgeHandoff)
        #expect(actions.duplicates.count == 1)
        #expect(actions.duplicates[0].1 == NativeAgentPrivateGitBridgeSocketPair.reviewedChildFileDescriptor)
        #expect(actions.closes == [actions.duplicates[0].0])
        #expect(!spec.executablePath.hasSuffix("/sh"))
        #expect(!spec.arguments.contains("-c"))

        _ = try session.wait()
    }
}

@Test func cursorAdapterRejectsPathArgvShellAndGitOverrides() throws {
    let cursorBundleCLI = "/Applications/Cursor.app/Contents/Resources/app/bin/code"
    try withTemporaryProjectDirectory { project in
        let fixture = HostSupervisorFixture()
        let supervisor = NativeAgentHostChildSupervisor(
            hooks: fixture.hooks(),
            executableProbe: { path in path == cursorBundleCLI }
        )
        let request = try makeRequest(
            adapter: .cursor,
            projectDirectory: project,
            environment: [
                "PATH": "/tmp/attacker-bin",
                "CURSOR_CLI": "/tmp/attacker-cursor",
                "CURSOR_AGENT": "/tmp/attacker-agent",
                "SHELL": "/tmp/attacker-shell",
                "BASH_ENV": "/tmp/attacker-env",
                "GIT_CONFIG_COUNT": "99",
                "GIT_CONFIG_KEY_0": "core.sshCommand",
                "GIT_CONFIG_VALUE_0": "/tmp/attacker-ssh",
                "GIT_CONFIG_KEY_1": "user.signingkey",
                "GIT_CONFIG_VALUE_1": "/tmp/attacker-key"
            ]
        )

        _ = try supervisor.start(request)
        let spec = try #require(fixture.snapshot().spec)
        let environment = spec.environment

        #expect(spec.executablePath == cursorBundleCLI)
        #expect(spec.arguments.isEmpty)
        #expect(environment["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin")
        #expect(environment["CURSOR_CLI"] == nil)
        #expect(environment["CURSOR_AGENT"] == nil)
        #expect(environment["SHELL"] == nil)
        #expect(environment["BASH_ENV"] == nil)
        #expect(environment["GIT_CONFIG_COUNT"] == "4")
        #expect(environment["GIT_CONFIG_KEY_0"] == "gpg.format")
        #expect(environment["GIT_CONFIG_VALUE_0"] == "ssh")
        #expect(environment["GIT_CONFIG_KEY_1"] == "gpg.ssh.program")
        #expect(environment["GIT_CONFIG_VALUE_1"] == NativeAgentHostGitConfiguration.helperExecutablePath)
        #expect(environment["GIT_CONFIG_KEY_2"] == "user.signingkey")
        #expect(environment["GIT_CONFIG_VALUE_2"] == NativeAgentHostGitConfiguration.signerReference)
        #expect(environment["GIT_CONFIG_KEY_3"] == "commit.gpgsign")
        #expect(environment["GIT_CONFIG_VALUE_3"] == "true")
    }
}

@Test func claudeChildReceivesOnlyTheReviewedPrivateBridgeAtFD3() throws {
    try withTemporaryProjectDirectory { project in
        let fixture = HostSupervisorFixture()
        fixture.installPrivateBridgeActions = true
        let supervisor = NativeAgentHostChildSupervisor(hooks: fixture.hooks())

        let session = try supervisor.start(try makeRequest(projectDirectory: project))
        let spec = try #require(fixture.snapshot().spec)
        let actions = fixture.privateBridgeActions()

        #expect(spec.hasPrivateGitBridgeHandoff == true)
        #expect(actions.duplicates.count == 1)
        #expect(actions.duplicates[0].1 == NativeAgentPrivateGitBridgeSocketPair.reviewedChildFileDescriptor)
        #expect(actions.closes == [actions.duplicates[0].0])
        #expect(actions.duplicates[0].0 != NativeAgentPrivateGitBridgeSocketPair.reviewedChildFileDescriptor)

        let hostEndpoint = session.privateGitBridgeHostEndpoint
        _ = try session.wait()
        // The child lifecycle owns transport cleanup. Closing the borrowed
        // view again must be harmless and cannot resurrect the endpoint.
        try hostEndpoint.close()
    }
}

@Test func privateBridgeFileActionFailureStopsSpawnBeforeAChildIsReturned() throws {
    try withTemporaryProjectDirectory { project in
        let fixture = HostSupervisorFixture()
        fixture.installPrivateBridgeActions = true
        fixture.rejectPrivateBridgeActions = true
        let supervisor = NativeAgentHostChildSupervisor(hooks: fixture.hooks())

        #expect(throws: NativeAgentHostChildSupervisorError.launchFailed) {
            _ = try supervisor.start(try makeRequest(projectDirectory: project))
        }
        #expect(fixture.snapshot().waitCallCount == 0)
        let actions = fixture.privateBridgeActions()
        #expect(actions.duplicates.count == 1)
        #expect(actions.closes == [actions.duplicates[0].0])
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

@Test func supervisedClaudeChildReceivesOnlyTheFixedAgentPassGitConfiguration() throws {
    try withTemporaryProjectDirectory { project in
        let fixture = HostSupervisorFixture()
        let supervisor = NativeAgentHostChildSupervisor(hooks: fixture.hooks())
        let request = try makeRequest(
            projectDirectory: project,
            environment: [
                "GIT_CONFIG_COUNT": "99",
                "GIT_CONFIG_KEY_0": "core.sshCommand",
                "GIT_CONFIG_VALUE_0": "malicious",
                "GIT_CONFIG_KEY_1": "user.signingkey",
                "GIT_CONFIG_VALUE_1": "/tmp/attacker-key",
            ]
        )
        _ = try supervisor.start(request)

        let environment = try #require(fixture.snapshot().spec?.environment)
        #expect(environment["GIT_CONFIG_COUNT"] == "4")
        #expect(environment["GIT_CONFIG_KEY_0"] == "gpg.format")
        #expect(environment["GIT_CONFIG_VALUE_0"] == "ssh")
        #expect(environment["GIT_CONFIG_KEY_1"] == "gpg.ssh.program")
        #expect(environment["GIT_CONFIG_VALUE_1"] == NativeAgentHostGitConfiguration.helperExecutablePath)
        #expect(environment["GIT_CONFIG_KEY_2"] == "user.signingkey")
        #expect(environment["GIT_CONFIG_VALUE_2"] == NativeAgentHostGitConfiguration.signerReference)
        #expect(environment["GIT_CONFIG_KEY_3"] == "commit.gpgsign")
        #expect(environment["GIT_CONFIG_VALUE_3"] == "true")
        #expect(NativeAgentHostGitConfiguration.helperExecutablePath == "/Applications/AgentPass.app/Contents/Resources/bin/agentpass-git-sign")
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
        #expect(fixture.snapshot().waitCallCount == 1)
        #expect(fixture.snapshot().signals.isEmpty)
        #expect(fixture.terminationCallCount() == 1)
    }
}

@Test func invalidChildPIDIsRejectedWithoutSignalingOrWaitingForAnUnrelatedProcess() throws {
    try withTemporaryProjectDirectory { project in
        let fixture = HostSupervisorFixture()
        let supervisor = NativeAgentHostChildSupervisor(
            hooks: fixture.hooks(process: .init(processIdentifier: -1, processGroupIdentifier: -1))
        )
        #expect(throws: NativeAgentHostChildSupervisorError.processGroupNotOwned) {
            _ = try supervisor.start(try makeRequest(projectDirectory: project))
        }
        #expect(fixture.snapshot().waitCallCount == 0)
        #expect(fixture.snapshot().signals.isEmpty)
        #expect(fixture.terminationCallCount() == 0)
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
