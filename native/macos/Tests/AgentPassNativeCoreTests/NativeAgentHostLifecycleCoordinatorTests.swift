import AgentPassNativeCore
import Darwin
import Foundation
import Testing

private final class LifecycleFixture: @unchecked Sendable {
    private let lock = NSLock()
    var events: [String] = []
    var bootstrapBindings: [NativeAgentHostConnectionBinding] = []
    var observedIdentities: [NativeAgentHostQualifiedSessionIdentity] = []
    var closedIdentities: [NativeAgentHostQualifiedSessionIdentity] = []
    var closeReasons: [NativeAgentHostLifecycleCloseReason] = []
    var authorityResults: [NativeAgentHostAuthorityObservation] = []
    var activation: NativeAgentHostQualifiedSessionActivation!
    var activationOverride: NativeAgentHostQualifiedSessionActivation?
    var rollbackCount = 0
    var rollbackError = false
    var spawnCount = 0
    var signalCount = 0
    var waitCount = 0
    var waitError = false
    var waitOutcome: NativeAgentHostWaitOutcome = .exitedSuccessfully
    var closeError = false
    var capturePrivateBridgeClient = false
    private var capturedPrivateBridgeClientDescriptor: Int32?
    var privateBridgeAuthorityObserved: DispatchSemaphore?
    var spawnEntered: DispatchSemaphore?
    var releaseSpawn: DispatchSemaphore?
    var lastGitTransport: NativeAgentHostGitTransport?
    var lastHadPrivateGitBridgeHandoff = false

    func hooks() -> NativeAgentHostLifecycleCoordinatorHooks {
        NativeAgentHostLifecycleCoordinatorHooks(
            bootstrap: { [self] connection, _ in
                lock.lock()
                bootstrapBindings.append(connection)
                events.append("bootstrap")
                let returned = activationOverride ?? activation
                lock.unlock()
                return NativeAgentHostLifecycleBootstrapReceipt(
                    activation: returned!,
                    rollback: { [self] in
                        lock.lock()
                        rollbackCount += 1
                        events.append("rollback")
                        let shouldFail = rollbackError
                        lock.unlock()
                        if shouldFail { throw FixtureError.failed }
                    }
                )
            },
            reobserveAuthority: { [self] identity in
                lock.lock()
                observedIdentities.append(identity)
                events.append("observe")
                let result = authorityResults.isEmpty ? .authorized : authorityResults.removeFirst()
                let bridgeObservation = privateBridgeAuthorityObserved
                lock.unlock()
                bridgeObservation?.signal()
                return result
            },
            close: { [self] identity, reason in
                lock.lock()
                closedIdentities.append(identity)
                closeReasons.append(reason)
                events.append("close")
                let shouldFail = closeError
                lock.unlock()
                if shouldFail { throw FixtureError.failed }
            }
        )
    }

    func supervisorHooks() -> NativeAgentHostChildSupervisorHooks {
        NativeAgentHostChildSupervisorHooks(
            spawn: { [self] spec in
                lock.lock()
                lastGitTransport = spec.gitTransport
                lastHadPrivateGitBridgeHandoff = spec.hasPrivateGitBridgeHandoff
                lock.unlock()
                // The production spawn hook owns the reviewed FD3 file
                // actions. Test hooks must install the same lease before the
                // supervisor can commit a child endpoint.
                try spec.installPrivateGitBridgeFileActions(
                    addDuplicate: { [self] source, _ in
                        lock.lock()
                        let capture = capturePrivateBridgeClient
                        lock.unlock()
                        if capture {
                            let duplicate = Darwin.dup(source)
                            guard duplicate >= 0 else { throw FixtureError.failed }
                            lock.lock()
                            capturedPrivateBridgeClientDescriptor = duplicate
                            lock.unlock()
                        }
                    },
                    addClose: { _ in }
                )
                lock.lock()
                spawnCount += 1
                events.append("spawn")
                let entered = spawnEntered
                let release = releaseSpawn
                lock.unlock()
                entered?.signal()
                release?.wait()
                return .init(processIdentifier: 700, processGroupIdentifier: 700)
            },
            signal: { [self] _, _ in
                lock.lock()
                signalCount += 1
                events.append("signal")
                lock.unlock()
            },
            terminateProcess: { [self] _ in
                lock.lock()
                signalCount += 1
                events.append("terminate-process")
                lock.unlock()
            },
            wait: { [self] _ in
                lock.lock()
                waitCount += 1
                events.append("wait")
                let shouldFail = waitError
                let result = waitOutcome
                lock.unlock()
                if shouldFail { throw FixtureError.failed }
                return result
            }
        )
    }

    func takeCapturedPrivateBridgeClientDescriptor() -> Int32? {
        lock.lock()
        defer { lock.unlock() }
        let descriptor = capturedPrivateBridgeClientDescriptor
        capturedPrivateBridgeClientDescriptor = nil
        return descriptor
    }

    func snapshot() -> (
        events: [String],
        bootstrapBindings: [NativeAgentHostConnectionBinding],
        observed: [NativeAgentHostQualifiedSessionIdentity],
        closed: [NativeAgentHostQualifiedSessionIdentity],
        reasons: [NativeAgentHostLifecycleCloseReason],
        spawn: Int,
        signal: Int,
        wait: Int,
        gitTransport: NativeAgentHostGitTransport?,
        hadPrivateGitBridgeHandoff: Bool
    ) {
        lock.lock()
        defer { lock.unlock() }
        return (
            events,
            bootstrapBindings,
            observedIdentities,
            closedIdentities,
            closeReasons,
            spawnCount,
            signalCount,
            waitCount,
            lastGitTransport,
            lastHadPrivateGitBridgeHandoff
        )
    }
}

private final class ErrorBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Error?

    func set(_ error: Error?) {
        lock.lock()
        value = error
        lock.unlock()
    }

    func get() -> Error? {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

private final class LockedCounter: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var count = 0
    private(set) var payload: Data?

    func increment(_ payload: Data) {
        lock.lock()
        count += 1
        self.payload = payload
        lock.unlock()
    }
}

private final class LifecycleGitSigner: NativeAgentGitCommitSigning, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var calls = 0
    private(set) var payload: Data?

    func signGitCommitPayload(_ payload: Data) throws -> Data {
        lock.lock()
        calls += 1
        self.payload = payload
        lock.unlock()
        return Data("-----BEGIN SSH SIGNATURE-----\ncoordinator\n-----END SSH SIGNATURE-----\n".utf8)
    }
}

private enum FixtureError: Error {
    case failed
}

private let lifecycleAgentID = "11111111-1111-4111-8111-111111111111"
private let lifecycleDeviceID = "22222222-2222-4222-8222-222222222222"
private let lifecycleSessionID = "33333333-3333-4333-8333-333333333333"

private func lifecycleConnection() throws -> NativeAgentHostConnectionBinding {
    try NativeAgentHostConnectionBinding(
        connectionID: "xpc-connection-1",
        agentID: lifecycleAgentID
    )
}

private func lifecycleActivation(
    sessionID: String = lifecycleSessionID,
    agentID: String = lifecycleAgentID,
    deviceID: String = lifecycleDeviceID
) throws -> NativeAgentHostQualifiedSessionActivation {
    let binding = try NativeAgentSessionBinding(
        agentID: agentID,
        deviceID: deviceID,
        processBindingDigest: Data(repeating: 0x11, count: 32),
        ancestryBindingDigest: Data(repeating: 0x22, count: 32),
        worktreeBindingDigest: Data(repeating: 0x33, count: 32),
        controlSequence: 1,
        authorityGeneration: 1,
        keyGeneration: 1
    )
    return try NativeAgentHostQualifiedSessionActivation(sessionID: sessionID, binding: binding)
}

private func lifecycleHandoff() throws -> NativeAgentLaunchAuthorityHandoff {
    try NativeAgentLaunchAuthorityHandoff(
        agentID: lifecycleAgentID,
        agentKind: .claudeCode,
        requestedTTLSeconds: 60,
        proof: Data("{\"nonce\":\"1234567890123456\"}".utf8)
    )
}

private func withLifecycleProject<T>(
    _ body: (NativeAgentHostProjectDirectory) throws -> T
) throws -> T {
    let userID = geteuid()
    let hooks = NativeAgentHostProjectDirectoryHooks(
        open: { _ in 40 },
        inspect: { _ in
            NativeAgentHostProjectDirectoryIdentity(
                device: 1,
                inode: 2,
                ownerUserID: userID,
                mode: 0o40700
            )
        },
        close: { _ in 0 },
        effectiveUserID: { userID }
    )
    let project = try NativeAgentHostProjectDirectory(
        path: "/private/var/tmp/agentpass-lifecycle-project",
        hooks: hooks
    )
    return try body(project)
}

private func makeLifecycleCoordinator(
    fixture: LifecycleFixture,
    authority: [NativeAgentHostAuthorityObservation] = [.authorized],
    gitTransport: NativeAgentHostGitTransport = .legacyFD3
) throws -> NativeAgentHostLifecycleCoordinator {
    fixture.authorityResults = authority
    fixture.activation = try lifecycleActivation()
    return try NativeAgentHostLifecycleCoordinator(
        connectionBinding: try lifecycleConnection(),
        handoff: try lifecycleHandoff(),
        supervisor: NativeAgentHostChildSupervisor(hooks: fixture.supervisorHooks()),
        hooks: fixture.hooks(),
        gitTransport: gitTransport
    )
}

private func identityProjection(_ identity: NativeAgentHostQualifiedSessionIdentity) -> [String] {
    [identity.sessionID, identity.agentID, identity.deviceID]
}

private func activationProjection(_ activation: NativeAgentHostQualifiedSessionActivation) -> [String] {
    [activation.sessionID, activation.binding.agentID, activation.binding.deviceID]
}

@Test func bootstrapReceivesOnlyConnectionBindingAndPinsReturnedActivation() throws {
    let fixture = LifecycleFixture()
    let coordinator = try makeLifecycleCoordinator(fixture: fixture)
    let activation = fixture.activation!

    #expect(try coordinator.bootstrap().outcome == .bootstrapped)
    _ = try withLifecycleProject { project in
        _ = try coordinator.start(projectDirectory: project)
        _ = try coordinator.close()
    }

    let snapshot = fixture.snapshot()
    #expect(snapshot.bootstrapBindings == [try lifecycleConnection()])
    #expect(snapshot.observed.map(identityProjection) == [activationProjection(activation), activationProjection(activation)])
    #expect(snapshot.closed.map(identityProjection) == [activationProjection(activation)])
    #expect(snapshot.bootstrapBindings.first?.agentID == lifecycleAgentID)
    #expect(coordinator.state == .closed)
}

@Test func authenticatedXPCTransportDoesNotCreateFD3Handoff() throws {
    let fixture = LifecycleFixture()
    let coordinator = try makeLifecycleCoordinator(
        fixture: fixture,
        gitTransport: .authenticatedXPC
    )

    _ = try coordinator.bootstrap()
    _ = try withLifecycleProject { project in
        _ = try coordinator.start(projectDirectory: project)
        _ = try coordinator.close()
    }

    let snapshot = fixture.snapshot()
    #expect(snapshot.gitTransport == .authenticatedXPC)
    #expect(snapshot.hadPrivateGitBridgeHandoff == false)
}

@Test func bootstrapRejectsActivationSubstitutionForAnotherAgent() throws {
    let fixture = LifecycleFixture()
    fixture.activationOverride = try lifecycleActivation(
        agentID: "44444444-4444-4444-8444-444444444444"
    )
    let coordinator = try makeLifecycleCoordinator(fixture: fixture)
    #expect(throws: NativeAgentHostLifecycleError.invalidActivation) {
        _ = try coordinator.bootstrap()
    }
    #expect(coordinator.state == .failed)
    #expect(fixture.snapshot().observed.isEmpty)
    #expect(fixture.snapshot().closed.isEmpty)
    #expect(fixture.rollbackCount == 1)
}

@Test func invalidActivationWithRollbackFailureReturnsBoundedCleanupError() throws {
    let fixture = LifecycleFixture()
    fixture.activationOverride = try lifecycleActivation(
        agentID: "44444444-4444-4444-8444-444444444444"
    )
    fixture.rollbackError = true
    let coordinator = try makeLifecycleCoordinator(fixture: fixture)

    #expect(throws: NativeAgentHostLifecycleError.bootstrapCleanupFailed) {
        _ = try coordinator.bootstrap()
    }
    #expect(fixture.rollbackCount == 1)
    #expect(coordinator.state == .failed)
}

@Test func bootstrapStartAndCloseReuseOneQualifiedIdentityAndStartOnlyOnce() throws {
    let fixture = LifecycleFixture()
    let coordinator = try makeLifecycleCoordinator(fixture: fixture)

    #expect(try coordinator.bootstrap().outcome == .bootstrapped)
    _ = try withLifecycleProject { project in
        let startResult = try coordinator.start(projectDirectory: project)
        let closeResult = try coordinator.close()
        #expect(startResult.outcome == .started)
        #expect(closeResult.outcome == .closed)
    }

    let snapshot = fixture.snapshot()
    #expect(snapshot.reasons == [.requested])
    #expect(snapshot.signal == 1)
    #expect(snapshot.wait == 1)
    #expect(coordinator.state == .closed)

    #expect(throws: NativeAgentHostLifecycleError.bootstrapAlreadyAttempted) {
        _ = try coordinator.bootstrap()
    }
    _ = try withLifecycleProject { project in
        #expect(throws: NativeAgentHostLifecycleError.startAlreadyAttempted) {
            _ = try coordinator.start(projectDirectory: project)
        }
    }
    #expect(throws: NativeAgentHostLifecycleError.alreadyClosed) {
        _ = try coordinator.close()
    }
}

@Test func authorityIsReobservedBeforeSpawnAndBeforeClose() throws {
    let fixture = LifecycleFixture()
    let coordinator = try makeLifecycleCoordinator(fixture: fixture)
    _ = try coordinator.bootstrap()

    _ = try withLifecycleProject { project in
        _ = try coordinator.start(projectDirectory: project)
        _ = try coordinator.close()
    }

    #expect(fixture.snapshot().events == ["bootstrap", "observe", "spawn", "observe", "signal", "wait", "close"])
}

@Test func authorityLossBeforeSpawnClosesWithoutLaunchingAChild() throws {
    let fixture = LifecycleFixture()
    let coordinator = try makeLifecycleCoordinator(fixture: fixture, authority: [.lost])
    _ = try coordinator.bootstrap()

    _ = try withLifecycleProject { project in
        #expect(throws: NativeAgentHostLifecycleError.authorityDenied) {
            _ = try coordinator.start(projectDirectory: project)
        }
    }

    let snapshot = fixture.snapshot()
    #expect(snapshot.spawn == 0)
    #expect(snapshot.signal == 0)
    #expect(snapshot.wait == 0)
    #expect(snapshot.reasons == [.authorityLost])
    #expect(coordinator.state == .closed)
}

@Test func authorityLossTerminatesReapsThenClosesTheChild() throws {
    let fixture = LifecycleFixture()
    let coordinator = try makeLifecycleCoordinator(
        fixture: fixture,
        authority: [.authorized, .lost]
    )
    _ = try coordinator.bootstrap()

    _ = try withLifecycleProject { project in
        _ = try coordinator.start(projectDirectory: project)
        let result = try coordinator.reobserveAndReconcileAuthority()
        #expect(result.outcome == .authorityLost)
    }

    let snapshot = fixture.snapshot()
    #expect(snapshot.events == ["bootstrap", "observe", "spawn", "observe", "signal", "wait", "close"])
    #expect(snapshot.reasons == [.authorityLost])
    #expect(coordinator.state == .closed)
}

@Test func childExitAlwaysClosesTheSessionAndReturnsBoundedExit() throws {
    let fixture = LifecycleFixture()
    fixture.waitOutcome = .exitedWithFailure
    let coordinator = try makeLifecycleCoordinator(fixture: fixture)
    _ = try coordinator.bootstrap()

    _ = try withLifecycleProject { project in
        _ = try coordinator.start(projectDirectory: project)
        let result = try coordinator.waitForChild()
        #expect(result.outcome == .childExited)
        #expect(result.childExit == .failure)
    }

    let snapshot = fixture.snapshot()
    #expect(snapshot.signal == 0)
    #expect(snapshot.wait == 1)
    #expect(snapshot.reasons == [.childExited])
    #expect(coordinator.state == .closed)
}

@Test func lifecycleBridgeServesOneChildRequestThroughTheSupervisorEndpoint() throws {
    let fixture = LifecycleFixture()
    fixture.capturePrivateBridgeClient = true
    let coordinator = try makeLifecycleCoordinator(fixture: fixture)
    _ = try coordinator.bootstrap()

    try withLifecycleProject { project in
        _ = try coordinator.start(projectDirectory: project)
        let clientDescriptor = try #require(fixture.takeCapturedPrivateBridgeClientDescriptor())
        let clientTransport = try NativeAgentPrivateFDTransport(
            fd: clientDescriptor,
            ownership: .owned
        )
        let client = NativeAgentPrivateGitBridgeClient(transport: clientTransport)
        let payload = Data("tree abc\n\nmessage\n".utf8)
        let expectedSignature = Data("signature\n".utf8)
        let signer = LockedCounter()
        let serveError = ErrorBox()
        let serveFinished = DispatchSemaphore(value: 0)

        DispatchQueue.global().async {
            do {
                try coordinator.servePrivateGitBridge { received in
                    signer.increment(received)
                    return expectedSignature
                }
            } catch {
                serveError.set(error)
            }
            serveFinished.signal()
        }

        #expect(try client.sign(commitPayload: payload) == expectedSignature)
        #expect(serveFinished.wait(timeout: .now() + .seconds(2)) == .success)
        #expect(serveError.get() == nil)
        #expect(signer.count == 1)
        #expect(signer.payload == payload)
        #expect(throws: NativeAgentHostPrivateGitBridgeError.alreadyAttempted) {
            try coordinator.servePrivateGitBridge { _ in expectedSignature }
        }
    }

    _ = try coordinator.close()
}

@Test func fixedGitHelperInvocationReachesCoordinatorRunnerExactlyOnce() throws {
    let fixture = LifecycleFixture()
    fixture.capturePrivateBridgeClient = true
    let coordinator = try makeLifecycleCoordinator(fixture: fixture)
    _ = try coordinator.bootstrap()

    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("agentpass-coordinator-helper-" + UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let payloadPath = directory.appendingPathComponent("commit-payload").path
    let payload = Data("tree coordinator\n\nmessage\n".utf8)
    try payload.write(to: URL(fileURLWithPath: payloadPath))
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: payloadPath)

    try withLifecycleProject { project in
        _ = try coordinator.start(projectDirectory: project)
        let helperDescriptor = try #require(fixture.takeCapturedPrivateBridgeClientDescriptor())
        let signer = LifecycleGitSigner()
        let runner = NativeAgentHostGitBridgeRunner(coordinator: coordinator, signer: signer)
        let runnerError = ErrorBox()
        let runnerFinished = DispatchSemaphore(value: 0)

        DispatchQueue.global().async {
            do { try runner.serveOne() }
            catch { runnerError.set(error) }
            runnerFinished.signal()
        }

        try NativeAgentGitSigningHelper.run(
            arguments: [
                "-Y", "sign", "-n", "git", "-f",
                NativeAgentGitSigningInvocation.fixedSignerReference,
                payloadPath
            ],
            bridgeFileDescriptor: helperDescriptor
        )

        #expect(runnerFinished.wait(timeout: .now() + .seconds(2)) == .success)
        #expect(runnerError.get() == nil)
        #expect(signer.calls == 1)
        #expect(signer.payload == payload)
        #expect(FileManager.default.fileExists(atPath: payloadPath + ".sig"))
        #expect(throws: NativeAgentHostPrivateGitBridgeError.alreadyAttempted) {
            try runner.serveOne()
        }
    }

    _ = try coordinator.close()
}

@Test func authorityLossCancelsBlockedLifecycleBridgeBeforeSignerInvocation() throws {
    let fixture = LifecycleFixture()
    fixture.capturePrivateBridgeClient = true
    let coordinator = try makeLifecycleCoordinator(
        fixture: fixture,
        authority: [.authorized, .authorized, .lost]
    )
    _ = try coordinator.bootstrap()

    try withLifecycleProject { project in
        _ = try coordinator.start(projectDirectory: project)
        let bridgeAuthorityObserved = DispatchSemaphore(value: 0)
        fixture.privateBridgeAuthorityObserved = bridgeAuthorityObserved
        let clientDescriptor = try #require(fixture.takeCapturedPrivateBridgeClientDescriptor())
        let clientTransport = try NativeAgentPrivateFDTransport(
            fd: clientDescriptor,
            ownership: .owned
        )
        let signer = LockedCounter()
        let serveError = ErrorBox()
        let serveFinished = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            do {
                try coordinator.servePrivateGitBridge { received in
                    signer.increment(received)
                    return Data("signature\n".utf8)
                }
            } catch {
                serveError.set(error)
            }
            serveFinished.signal()
        }

        #expect(bridgeAuthorityObserved.wait(timeout: .now() + .seconds(2)) == .success)
        // Keep the request direction open after its bounded payload. The
        // Host must be waiting for EOF before signer invocation, which gives
        // the authority-loss cancellation a deterministic blocked boundary.
        try clientTransport.writeCommitPayload(Data("payload".utf8))
        #expect(try coordinator.reobserveAndReconcileAuthority().outcome == .authorityLost)
        #expect(serveFinished.wait(timeout: .now() + .seconds(2)) == .success)
        #expect((serveError.get() as? NativeAgentHostPrivateGitBridgeError) == .cancelled)
        #expect(signer.count == 0)
        try clientTransport.close()
    }

    #expect(coordinator.state == .closed)
    #expect(fixture.snapshot().reasons == [.authorityLost])
    #expect(fixture.snapshot().wait == 1)
}

@Test func waitFailureStillClosesTheSessionWithBoundedError() throws {
    let fixture = LifecycleFixture()
    fixture.waitError = true
    let coordinator = try makeLifecycleCoordinator(fixture: fixture)
    _ = try coordinator.bootstrap()

    _ = try withLifecycleProject { project in
        _ = try coordinator.start(projectDirectory: project)
        #expect(throws: NativeAgentHostLifecycleError.waitFailed) {
            _ = try coordinator.waitForChild()
        }
    }

    #expect(fixture.snapshot().reasons == [.childExited])
    #expect(coordinator.state == .closed)
}

@Test func concurrentStartIsDeniedWhileTheSingleStartIsInFlight() throws {
    let fixture = LifecycleFixture()
    let entered = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)
    fixture.spawnEntered = entered
    fixture.releaseSpawn = release
    let coordinator = try makeLifecycleCoordinator(fixture: fixture)
    _ = try coordinator.bootstrap()

    let group = DispatchGroup()
    let firstError = ErrorBox()
    group.enter()
    DispatchQueue.global().async {
        do {
            try withLifecycleProject { project in
                _ = try coordinator.start(projectDirectory: project)
            }
        } catch {
            firstError.set(error)
        }
        group.leave()
    }

    #expect(entered.wait(timeout: .now() + 2) == .success)
    _ = try withLifecycleProject { project in
        #expect(throws: NativeAgentHostLifecycleError.operationInProgress) {
            _ = try coordinator.start(projectDirectory: project)
        }
    }
    release.signal()
    #expect(group.wait(timeout: .now() + 2) == .success)
    #expect(firstError.get() == nil)
    _ = try coordinator.close()
}
