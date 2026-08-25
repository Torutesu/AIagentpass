@testable import AgentPassNativeCore
import Darwin
import Foundation
import Testing

private final class SocketPairSyscallProbe: @unchecked Sendable {
    struct FcntlCall: Equatable {
        let descriptor: Int32
        let command: Int32
        let argument: Int32
    }

    var socketPairResult: Int32 = 0
    var socketPairErrno: Int32 = EIO
    var socketPairDescriptors: (Int32, Int32) = (41, 42)
    var fcntlResults: [Int32] = []
    var fcntlCalls: [FcntlCall] = []
    var closeCalls: [Int32] = []
    var closeResults: [Int32: Int32] = [:]
    var closeErrno: Int32 = EIO

    func socketPair(
        _ domain: Int32,
        _ type: Int32,
        _ protocolNumber: Int32,
        _ descriptors: UnsafeMutablePointer<Int32>
    ) -> Int32 {
        #expect(domain == Int32(AF_UNIX))
        #expect(type == Int32(SOCK_STREAM))
        #expect(protocolNumber == 0)
        descriptors[0] = socketPairDescriptors.0
        descriptors[1] = socketPairDescriptors.1
        if socketPairResult != 0 { errno = socketPairErrno }
        return socketPairResult
    }

    func fcntl(_ descriptor: Int32, _ command: Int32, _ argument: Int32) -> Int32 {
        fcntlCalls.append(.init(descriptor: descriptor, command: command, argument: argument))
        if !fcntlResults.isEmpty { return fcntlResults.removeFirst() }
        return command == F_GETFD ? 0 : 0
    }

    func close(_ descriptor: Int32) -> Int32 {
        closeCalls.append(descriptor)
        let result = closeResults[descriptor] ?? 0
        if result == -1 { errno = closeErrno }
        return result
    }

    func syscalls() -> NativeAgentPrivateGitBridgeSocketPair.Syscalls {
        .init(socketPair: socketPair, fcntl: fcntl, close: close)
    }
}

private enum SpawnActionTestError: Error {
    case rejected
}

private final class SpawnActionProbe: @unchecked Sendable {
    struct DuplicateCall: Equatable {
        let source: Int32
        let target: Int32
    }

    var duplicateCalls: [DuplicateCall] = []
    var closeCalls: [Int32] = []
    var rejectDuplicate = false
    var rejectClose = false

    func addDuplicate(_ source: Int32, _ target: Int32) throws {
        duplicateCalls.append(.init(source: source, target: target))
        if rejectDuplicate { throw SpawnActionTestError.rejected }
    }

    func addClose(_ source: Int32) throws {
        closeCalls.append(source)
        if rejectClose { throw SpawnActionTestError.rejected }
    }
}

private final class LockedOutcomeCounts: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var successes = 0
    private(set) var failures = 0

    func success() {
        lock.lock(); successes += 1; lock.unlock()
    }

    func failure() {
        lock.lock(); failures += 1; lock.unlock()
    }
}

@Test func createsUnnamedUnixStreamAndSetsCloexecOnBothEndpoints() throws {
    let probe = SocketPairSyscallProbe()
    let pair = try NativeAgentPrivateGitBridgeSocketPair(syscalls: probe.syscalls())

    #expect(probe.fcntlCalls == [
        .init(descriptor: 41, command: F_GETFD, argument: 0),
        .init(descriptor: 41, command: F_SETFD, argument: Int32(FD_CLOEXEC)),
        .init(descriptor: 42, command: F_GETFD, argument: 0),
        .init(descriptor: 42, command: F_SETFD, argument: Int32(FD_CLOEXEC)),
    ])
    #expect(pair.hostFileDescriptor == 41)
    try pair.close()
    #expect(probe.closeCalls == [42, 41])
}

@Test func factoryDoesNotCloseUnownedDescriptorValuesOnSocketPairFailure() {
    let probe = SocketPairSyscallProbe()
    probe.socketPairResult = -1
    probe.socketPairDescriptors = (51, 52)
    probe.socketPairErrno = EIO

    #expect(throws: NativeAgentPrivateGitBridgeSocketPairError.socketPairFailed(EIO)) {
        _ = try NativeAgentPrivateGitBridgeSocketPair(syscalls: probe.syscalls())
    }
    #expect(probe.closeCalls.isEmpty)
}

@Test func factoryClosesBothWhenCloexecSetupFails() {
    let probe = SocketPairSyscallProbe()
    probe.fcntlResults = [0, -1]
    errno = EPERM

    #expect(throws: NativeAgentPrivateGitBridgeSocketPairError.descriptorFlagsFailed(41, EPERM)) {
        _ = try NativeAgentPrivateGitBridgeSocketPair(syscalls: probe.syscalls())
    }
    #expect(probe.closeCalls == [41, 42])
}

@Test func factoryRejectsChildSourceAllocatedAsReviewedFD3BeforeLease() {
    let probe = SocketPairSyscallProbe()
    probe.socketPairDescriptors = (41, 3)

    #expect(throws: NativeAgentPrivateGitBridgeSocketPairError.reviewedTargetCollision) {
        _ = try NativeAgentPrivateGitBridgeSocketPair(syscalls: probe.syscalls())
    }
    #expect(probe.closeCalls == [41, 3])
    #expect(probe.fcntlCalls.isEmpty)
}

@Test func preparesExactlyOneOpaqueLeaseAndRegistersOnlyChildFileActions() throws {
    let syscalls = SocketPairSyscallProbe()
    let pair = try NativeAgentPrivateGitBridgeSocketPair(syscalls: syscalls.syscalls())
    let lease = try pair.prepareChildEndpointHandoff()
    let actions = SpawnActionProbe()

    try lease.addToSpawnFileActions(
        addDuplicate: actions.addDuplicate,
        addClose: actions.addClose)

    #expect(actions.duplicateCalls.count == 1)
    #expect(actions.duplicateCalls[0].source == 42)
    #expect(actions.duplicateCalls[0].target == NativeAgentPrivateGitBridgeSocketPair.reviewedChildFileDescriptor)
    #expect(actions.closeCalls == [42])

    // The only fcntl calls are the two endpoint CLOEXEC setup pairs. There is
    // no parent fixed-FD probe, and no parent duplication syscall exists.
    #expect(syscalls.fcntlCalls.count == 4)
    try lease.commit()
    #expect(syscalls.closeCalls == [42])
    try pair.close()
    #expect(syscalls.closeCalls == [42, 41])

    #expect(throws: NativeAgentPrivateGitBridgeSocketPairError.leaseAlreadyResolved) {
        try lease.commit()
    }
    #expect(throws: NativeAgentPrivateGitBridgeSocketPairError.leaseAlreadyResolved) {
        try lease.abort()
    }
}

@Test func repeatedPrepareIsDeniedAndConcurrentPrepareIssuesOneLease() throws {
    let probe = SocketPairSyscallProbe()
    let pair = try NativeAgentPrivateGitBridgeSocketPair(syscalls: probe.syscalls())
    _ = try pair.prepareChildEndpointHandoff()
    #expect(throws: NativeAgentPrivateGitBridgeSocketPairError.leaseAlreadyIssued) {
        _ = try pair.prepareChildEndpointHandoff()
    }

    let secondPairProbe = SocketPairSyscallProbe()
    let secondPair = try NativeAgentPrivateGitBridgeSocketPair(syscalls: secondPairProbe.syscalls())
    let group = DispatchGroup()
    let queue = DispatchQueue(label: "socket-pair-lease-test", attributes: .concurrent)
    let outcomes = LockedOutcomeCounts()

    for _ in 0..<16 {
        group.enter()
        queue.async {
            defer { group.leave() }
            do {
                let lease = try secondPair.prepareChildEndpointHandoff()
                try lease.abort()
                outcomes.success()
            } catch {
                outcomes.failure()
            }
        }
    }
    group.wait()
    #expect(outcomes.successes == 1)
    #expect(outcomes.failures == 15)
    #expect(secondPairProbe.closeCalls == [42, 41])
}

@Test func abortClosesBothEndpointsAndIsOneUse() throws {
    let probe = SocketPairSyscallProbe()
    let pair = try NativeAgentPrivateGitBridgeSocketPair(syscalls: probe.syscalls())
    let lease = try pair.prepareChildEndpointHandoff()

    try lease.abort()
    #expect(probe.closeCalls == [42, 41])
    #expect(throws: NativeAgentPrivateGitBridgeSocketPairError.leaseAlreadyResolved) {
        try lease.abort()
    }
    #expect(throws: NativeAgentPrivateGitBridgeSocketPairError.leaseAlreadyResolved) {
        try lease.commit()
    }
    try pair.close()
    #expect(probe.closeCalls == [42, 41])
}

@Test func fileActionFailureAutomaticallyAbortsAndClosesBothEndpoints() throws {
    let probe = SocketPairSyscallProbe()
    let pair = try NativeAgentPrivateGitBridgeSocketPair(syscalls: probe.syscalls())
    let lease = try pair.prepareChildEndpointHandoff()
    let actions = SpawnActionProbe()
    actions.rejectClose = true
    var spawnCalled = false
    let spawn = { spawnCalled = true }

    #expect(throws: SpawnActionTestError.rejected) {
        do {
            try lease.addToSpawnFileActions(
                addDuplicate: actions.addDuplicate,
                addClose: actions.addClose)
            spawn()
        } catch {
            // A real supervisor discards the partially populated
            // posix_spawn_file_actions_t here and never invokes posix_spawn.
            throw error
        }
    }
    #expect(actions.duplicateCalls == [.init(source: 42, target: 3)])
    #expect(actions.closeCalls == [42])
    #expect(!spawnCalled)
    #expect(probe.closeCalls == [42, 41])
    #expect(throws: NativeAgentPrivateGitBridgeSocketPairError.leaseAlreadyResolved) {
        try lease.commit()
    }
}

@Test func commitCloseFailureStillClosesHostAndIsTerminal() throws {
    let probe = SocketPairSyscallProbe()
    probe.closeResults[42] = -1
    probe.closeErrno = EIO
    let pair = try NativeAgentPrivateGitBridgeSocketPair(syscalls: probe.syscalls())
    let lease = try pair.prepareChildEndpointHandoff()
    let actions = SpawnActionProbe()
    try lease.addToSpawnFileActions(
        addDuplicate: actions.addDuplicate,
        addClose: actions.addClose)

    #expect(throws: NativeAgentPrivateGitBridgeSocketPairError.closeFailed(EIO)) {
        try lease.commit()
    }
    #expect(probe.closeCalls == [42, 41])
    try pair.close()
    #expect(probe.closeCalls == [42, 41])
    #expect(throws: NativeAgentPrivateGitBridgeSocketPairError.leaseAlreadyResolved) {
        try lease.commit()
    }
}

@Test func rejectsNegativeReturnedDescriptorsAndClosesOnlyValidEndpoint() {
    let probe = SocketPairSyscallProbe()
    probe.socketPairDescriptors = (-1, 72)

    #expect(throws: NativeAgentPrivateGitBridgeSocketPairError.invalidSocketPair) {
        _ = try NativeAgentPrivateGitBridgeSocketPair(syscalls: probe.syscalls())
    }
    #expect(probe.closeCalls == [72])
}

@Test func pairCloseIsIdempotentAndClosesPendingLeaseOwnership() throws {
    let probe = SocketPairSyscallProbe()
    let pair = try NativeAgentPrivateGitBridgeSocketPair(syscalls: probe.syscalls())
    let lease = try pair.prepareChildEndpointHandoff()

    try pair.close()
    try pair.close()
    #expect(probe.closeCalls == [42, 41])
    #expect(throws: NativeAgentPrivateGitBridgeSocketPairError.fileActionsNotInstalled) {
        try lease.commit()
    }
}
