@testable import AgentPassNativeCore
import Foundation

/// Test-only implementation of the Supervisor's authenticated Host XPC seams.
///
/// The fixture intentionally owns no process or descriptor. The caller owns
/// the real `NativeAgentHostChildSession` returned by the Supervisor and must
/// terminate/reap it when an XPC phase fails. This keeps the assertions about
/// ownership and ordering visible at the test call site.
final class NativeAgentHostAuthenticatedXPCSupervisorFixture: @unchecked Sendable,
    NativeAgentHostAuthenticatedXPCClientProtocol,
    NativeAgentHostChildObserver
{
    enum Failure: Error, Equatable {
        case prepareFailed
        case identityObservationFailed
        case attachFailed
        case invalidOrdering
    }

    enum Event: Equatable {
        case prepare
        case identityObserved(pid: Int32, pidVersion: UInt64)
        case attach
        case clientClose
    }

    private enum Phase {
        case new
        case prepared
        case identityObserved
        case attached
        case closed
    }

    private let lock = NSLock()
    private var phase: Phase = .new
    private var recordedEvents: [Event] = []
    private let identity: NativeProcessIdentity
    private let worktreeBindingDigest = Data(repeating: 0x44, count: AgentPassHostXPCContract.digestBytes)
    private(set) var lastExecutableIdentityDigest: Data?
    private(set) var lastAncestryBindingDigest: Data?
    private(set) var lastWorktreeBindingDigest: Data?

    init() {
        let facts = try! NativeObservedProcessFacts(
            uid: 501,
            pid: 700,
            pidVersion: 1,
            bootIdentity: "authenticated-xpc-fixture-boot",
            executableFileIdentity: try! NativeExecutableFileIdentity(
                deviceID: 1,
                inode: 700,
                fileSize: 1,
                modificationTimeNanoseconds: 1
            ),
            codeDirectoryHash: String(repeating: "a", count: 64),
            bundleIdentifier: "dev.agentpass.agent-host",
            teamIdentifier: "ABCDE12345",
            signatureKind: .developerID,
            entitlements: [:]
        )
        self.identity = NativeProcessIdentity(observation: try! NativeProcessObservation(
            process: facts,
            ancestry: []
        ))
    }

    var failPrepare = false
    var failIdentityObservation = false
    var failAttach = false

    func prepare() throws {
        lock.lock()
        defer { lock.unlock() }
        guard phase == .new else { throw Failure.invalidOrdering }
        recordedEvents.append(.prepare)
        if failPrepare { throw Failure.prepareFailed }
        phase = .prepared
    }

    func observeChild(pid: Int32, pidVersion: UInt64) throws {
        lock.lock()
        defer { lock.unlock() }
        guard phase == .prepared else { throw Failure.invalidOrdering }
        recordedEvents.append(.identityObserved(pid: pid, pidVersion: pidVersion))
        if failIdentityObservation { throw Failure.identityObservationFailed }
        phase = .identityObserved
    }

    func attach() throws {
        lock.lock()
        defer { lock.unlock() }
        guard phase == .identityObserved else { throw Failure.invalidOrdering }
        recordedEvents.append(.attach)
        if failAttach { throw Failure.attachFailed }
        phase = .attached
    }

    func prepareForChild(launchNonce: Data) throws {
        try prepare()
    }

    func attachForChild(
        childPID: Int,
        childPIDVersion: Int64,
        executableIdentityDigest: Data,
        ancestryBindingDigest: Data,
        worktreeBindingDigest: Data
    ) throws {
        guard childPID == 700,
              childPIDVersion == 1 else {
            throw Failure.invalidOrdering
        }
        lastExecutableIdentityDigest = executableIdentityDigest
        lastAncestryBindingDigest = ancestryBindingDigest
        lastWorktreeBindingDigest = worktreeBindingDigest
        try attach()
    }

    var expectedExecutableIdentityDigest: Data {
        get throws { try identity.canonicalBindingDigestData }
    }

    var expectedAncestryBindingDigest: Data {
        get throws { try identity.canonicalAncestryBindingDigestData }
    }

    func closeForChild(reason: AgentPassHostXPCContract.CloseReason) throws {
        closeClient()
    }

    func observe(pid: Int32) throws -> NativeAgentHostChildObservation {
        guard pid == 700 else { throw Failure.invalidOrdering }
        try observeChild(pid: pid, pidVersion: identity.pidVersion)
        return try NativeAgentHostChildObservation(
            identity: identity,
            worktreeBindingDigest: worktreeBindingDigest
        )
    }

    /// Models the connection-owned client close. A close is terminal and is
    /// sent at most once even when cleanup is attempted from two error paths.
    func closeClient() {
        lock.lock()
        guard phase != .closed else {
            lock.unlock()
            return
        }
        recordedEvents.append(.clientClose)
        phase = .closed
        lock.unlock()
    }

    var events: [Event] {
        lock.lock()
        defer { lock.unlock() }
        return recordedEvents
    }
}
