import AgentPassNativeCore
import Foundation
import Testing
@testable import AgentPassNativeServiceSupport

private let runnerOrganization = "11111111-1111-4111-8111-111111111111"
private let runnerDevice = "22222222-2222-4222-8222-222222222222"

private final class RunnerClock: NativeDeviceSyncRunnerClock, @unchecked Sendable {
    private let lock = NSLock()
    private var value: Int64

    init(_ value: Int64 = 1_000_000) { self.value = value }

    func nowMilliseconds() -> Int64 {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

private final class RunnerRandom: NativeDeviceSyncRunnerRandomizing, @unchecked Sendable {
    private let value: Double
    init(_ value: Double) { self.value = value }
    func nextUnitInterval() -> Double { value }
}

private final class RunnerGate: @unchecked Sendable {
    private enum WaiterState {
        case reserved
        case waiting(CheckedContinuation<Void, Error>)
        case cancelled
    }

    private let lock = NSLock()
    private let beforeRegistration: (@Sendable () async -> Void)?
    private var permits = 0
    private var nextWaiterID: UInt64 = 0
    private var waiterOrder: [UInt64] = []
    private var waiterStates: [UInt64: WaiterState] = [:]

    init(beforeRegistration: (@Sendable () async -> Void)? = nil) {
        self.beforeRegistration = beforeRegistration
    }

    func wait() async throws {
        let waiterID = reserveWaiter()
        try await withTaskCancellationHandler(operation: {
            await beforeRegistration?()
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                register(continuation, waiterID: waiterID)
            }
        }, onCancel: {
            self.cancel(waiterID: waiterID)
        })
    }

    func releaseOne() {
        var continuation: CheckedContinuation<Void, Error>?
        lock.lock()
        while !waiterOrder.isEmpty, continuation == nil {
            let waiterID = waiterOrder.removeFirst()
            guard case let .waiting(waiter)? = waiterStates.removeValue(forKey: waiterID) else {
                continue
            }
            continuation = waiter
        }
        if continuation == nil {
            permits += 1
        }
        lock.unlock()
        continuation?.resume()
    }

    func pendingWaiterCountForTesting() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return waiterStates.values.reduce(into: 0) { count, state in
            if case .waiting = state { count += 1 }
        }
    }

    private func reserveWaiter() -> UInt64 {
        lock.lock()
        let waiterID = nextWaiterID
        nextWaiterID &+= 1
        waiterStates[waiterID] = .reserved
        lock.unlock()
        return waiterID
    }

    private func register(_ continuation: CheckedContinuation<Void, Error>, waiterID: UInt64) {
        enum Resume {
            case none
            case success
            case cancelled
        }

        let resume: Resume
        lock.lock()
        switch waiterStates[waiterID] {
        case .cancelled:
            waiterStates.removeValue(forKey: waiterID)
            resume = .cancelled
        case .reserved:
            if Task.isCancelled {
                waiterStates.removeValue(forKey: waiterID)
                resume = .cancelled
            } else if permits > 0 {
                permits -= 1
                waiterStates.removeValue(forKey: waiterID)
                resume = .success
            } else {
                waiterStates[waiterID] = .waiting(continuation)
                waiterOrder.append(waiterID)
                resume = .none
            }
        case .waiting, nil:
            waiterStates.removeValue(forKey: waiterID)
            resume = .cancelled
        }
        lock.unlock()

        switch resume {
        case .none:
            break
        case .success:
            continuation.resume()
        case .cancelled:
            continuation.resume(throwing: CancellationError())
        }
    }

    private func cancel(waiterID: UInt64) {
        let continuation: CheckedContinuation<Void, Error>?
        lock.lock()
        switch waiterStates[waiterID] {
        case .reserved:
            waiterStates[waiterID] = .cancelled
            continuation = nil
        case let .waiting(waiter):
            waiterStates.removeValue(forKey: waiterID)
            waiterOrder.removeAll { $0 == waiterID }
            continuation = waiter
        case .cancelled, nil:
            continuation = nil
        }
        lock.unlock()
        continuation?.resume(throwing: CancellationError())
    }
}

private actor RunnerRegistrationBarrier {
    private var entered = false
    private var released = false
    private var entryWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

    func pause() async {
        entered = true
        let observers = entryWaiters
        entryWaiters.removeAll(keepingCapacity: true)
        for observer in observers { observer.resume() }

        guard !released else { return }
        await withCheckedContinuation { continuation in
            if released {
                continuation.resume()
            } else {
                releaseWaiters.append(continuation)
            }
        }
    }

    func waitUntilEntered() async {
        guard !entered else { return }
        await withCheckedContinuation { entryWaiters.append($0) }
    }

    func release() {
        released = true
        let waiters = releaseWaiters
        releaseWaiters.removeAll(keepingCapacity: true)
        for waiter in waiters { waiter.resume() }
    }
}

private final class RunnerScheduler: NativeDeviceSyncRunnerScheduling, @unchecked Sendable {
    private let gate = RunnerGate()
    private let lock = NSLock()
    private var recordedSleeps: [UInt64] = []

    func sleep(nanoseconds: UInt64) async throws {
        record(nanoseconds)
        try await gate.wait()
    }

    func releaseNext() { gate.releaseOne() }

    func sleeps() -> [UInt64] {
        lock.lock()
        defer { lock.unlock() }
        return recordedSleeps
    }

    private func record(_ nanoseconds: UInt64) {
        lock.lock()
        recordedSleeps.append(nanoseconds)
        lock.unlock()
    }
}

private actor RunnerCoordinator: NativeDeviceSyncCoordinating {
    enum Outcome: Sendable {
        case noChange(Int64)
        case applied(Int64, Int64)
        case blocked(Int64, Int64)
        case transportFailure
        case unknownFailure
    }

    private var snapshotValue: NativeDeviceRefreshSnapshot
    private var outcomes: [Outcome]
    private var gate: RunnerGate?
    private var completionGate: RunnerGate?
    private var activeCount = 0
    private var maximumActiveCount = 0
    private var callCount = 0
    private var waitValues: [Int] = []

    init(initialState: NativeDeviceRefreshMachineState = .idle, generation: Int64 = 0, sequence: Int64? = nil, outcomes: [Outcome]) {
        snapshotValue = NativeDeviceRefreshSnapshot(
            state: initialState,
            organizationID: runnerOrganization,
            deviceID: runnerDevice,
            generation: generation,
            sequence: sequence,
            statementHash: sequence.map { _ in String(repeating: "a", count: 64) },
            refreshNonce: nil,
            sequenceWatermark: sequence ?? 0,
            revision: 0
        )
        self.outcomes = outcomes
    }

    func setGate(_ gate: RunnerGate?) { self.gate = gate }
    func setCompletionGate(_ gate: RunnerGate?) { self.completionGate = gate }

    func synchronize(waitMilliseconds: Int) async throws -> NativeDeviceSyncRunResult {
        callCount += 1
        waitValues.append(waitMilliseconds)
        activeCount += 1
        maximumActiveCount = max(maximumActiveCount, activeCount)
        let currentGate = gate
        gate = nil
        defer { activeCount -= 1 }
        if let currentGate { try await currentGate.wait() }

        let outcome = outcomes.isEmpty ? .noChange(snapshotValue.generation) : outcomes.removeFirst()
        let result: NativeDeviceSyncRunResult
        switch outcome {
        case let .noChange(generation):
            snapshotValue = idleSnapshot(generation: generation, sequence: nil)
            result = .noChange(generation: generation)
        case let .applied(generation, sequence):
            snapshotValue = idleSnapshot(generation: generation, sequence: sequence)
            result = .applied(generation: generation, sequence: sequence)
        case let .blocked(generation, sequence):
            snapshotValue = NativeDeviceRefreshSnapshot(
                state: .idle,
                organizationID: runnerOrganization,
                deviceID: runnerDevice,
                generation: generation,
                sequence: sequence,
                statementHash: String(repeating: "b", count: 64),
                sequenceWatermark: sequence,
                revision: 0
            )
            result = .blocked(generation: generation, sequence: sequence, reason: .internalError)
        case .transportFailure:
            throw NativeDeviceSyncCoordinatorError.transportUnavailable
        case .unknownFailure:
            throw RunnerUnknownError.secretPathAndMessage
        }
        if let completionGate {
            self.completionGate = nil
            try await completionGate.wait()
        }
        return result
    }

    func snapshot() async -> NativeDeviceRefreshSnapshot { snapshotValue }
    func calls() -> Int { callCount }
    func maximumActive() -> Int { maximumActiveCount }
    func waits() -> [Int] { waitValues }

    private func idleSnapshot(generation: Int64, sequence: Int64?) -> NativeDeviceRefreshSnapshot {
        NativeDeviceRefreshSnapshot(
            state: .idle,
            organizationID: runnerOrganization,
            deviceID: runnerDevice,
            generation: generation,
            sequence: sequence,
            statementHash: sequence.map { _ in String(repeating: "a", count: 64) },
            sequenceWatermark: sequence ?? 0,
            revision: 0
        )
    }
}

private enum RunnerUnknownError: Error, Sendable {
    case secretPathAndMessage
}

@Test func wakeSignalCancellationBeforeRegistrationCannotHangOrStealNextWake() async {
    let barrier = RunnerRegistrationBarrier()
    let wakeSignal = NativeDeviceSyncRunner.WakeSignal(
        beforeWaiterRegistration: { await barrier.pause() }
    )
    let cancelledWaiter = Task { await wakeSignal.wait() }

    await barrier.waitUntilEntered()
    cancelledWaiter.cancel()
    wakeSignal.signal()
    await barrier.release()

    #expect(await cancelledWaiter.value == false)
    // The signal belongs to the next live waiter because the cancelled
    // generation never installed a continuation.
    #expect(await wakeSignal.wait() == true)
    wakeSignal.close()
    #expect(await wakeSignal.wait() == false)
}

@Test func runnerGateCancellationBeforeRegistrationCannotLeakOrResumeTwice() async throws {
    let barrier = RunnerRegistrationBarrier()
    let gate = RunnerGate(beforeRegistration: { await barrier.pause() })
    let waiter = Task {
        do {
            try await gate.wait()
            return false
        } catch is CancellationError {
            return true
        } catch {
            return false
        }
    }

    await barrier.waitUntilEntered()
    waiter.cancel()
    gate.releaseOne()
    await barrier.release()

    #expect(await waiter.value)
    #expect(gate.pendingWaiterCountForTesting() == 0)
    // The release raced with a reserved-but-cancelled waiter and must remain
    // available for a genuinely new waiter, not revive the cancelled one.
    try await gate.wait()
    #expect(gate.pendingWaiterCountForTesting() == 0)
}

@Test func runnerGateCancellationTargetsOnlyItsOwnContinuation() async throws {
    let gate = RunnerGate()
    let first = Task {
        do {
            try await gate.wait()
            return true
        } catch {
            return false
        }
    }
    try await waitUntil { gate.pendingWaiterCountForTesting() == 1 }
    let second = Task {
        do {
            try await gate.wait()
            return true
        } catch {
            return false
        }
    }
    try await waitUntil { gate.pendingWaiterCountForTesting() == 2 }

    second.cancel()
    #expect(await second.value == false)
    gate.releaseOne()
    #expect(await first.value == true)
    #expect(gate.pendingWaiterCountForTesting() == 0)
}

@Test func runnerImmediatelyResumesDurableStateAndUsesOneBoundedLongPoll() async throws {
    let coordinator = RunnerCoordinator(
        initialState: .staging,
        generation: 7,
        sequence: 4,
        outcomes: [.applied(7, 4)]
    )
    let scheduler = RunnerScheduler()
    let runner = NativeDeviceSyncRunner(
        coordinator: coordinator,
        configuration: try NativeDeviceSyncRunnerConfiguration(
            intervalSeconds: 15,
            maximumBackoffSeconds: 60,
            pollWaitMilliseconds: 30_000,
            jitterFraction: 0
        ),
        clock: RunnerClock(),
        scheduler: scheduler,
        randomizer: RunnerRandom(0)
    )

    runner.start()
    try await waitUntil {
        let completed = await coordinator.calls() == 1
        return completed && runner.status().lastSuccessAtMilliseconds != nil && scheduler.sleeps().count == 1
    }
    #expect(await coordinator.waits() == [30_000])
    #expect(runner.status().state == .idle)
    #expect(runner.status().generation == 7)
    #expect(runner.status().sequence == 4)
    #expect(scheduler.sleeps() == [15_000_000_000])
    await runner.stop()
}

@Test func runnerCoalescesManualRefreshesDuringAnActiveCycle() async throws {
    let coordinator = RunnerCoordinator(outcomes: [.noChange(1), .noChange(1)])
    let activeGate = RunnerGate()
    await coordinator.setGate(activeGate)
    let runner = NativeDeviceSyncRunner(
        coordinator: coordinator,
        configuration: try NativeDeviceSyncRunnerConfiguration(intervalSeconds: 15, maximumBackoffSeconds: 60, jitterFraction: 0),
        clock: RunnerClock(),
        scheduler: RunnerScheduler(),
        randomizer: RunnerRandom(0)
    )

    runner.start()
    try await waitUntil {
        let calls = await coordinator.calls()
        let active = await coordinator.maximumActive()
        return calls == 1 && active == 1
    }
    let first = Task { await runner.requestRefresh() }
    let second = Task { await runner.requestRefresh() }
    try await waitUntil { runner.pendingManualRequestCountForTesting() == 2 }
    activeGate.releaseOne()
    let firstStatus = await first.value
    let secondStatus = await second.value
    #expect(firstStatus.reason == .noChange)
    #expect(secondStatus.reason == .noChange)
    #expect(await coordinator.calls() == 1)
    #expect(await coordinator.maximumActive() == 1)
    await runner.stop()
}

@Test func runnerCoalescesManualRefreshesWhileWaiting() async throws {
    let coordinator = RunnerCoordinator(outcomes: [.noChange(1), .noChange(2)])
    let scheduler = RunnerScheduler()
    let runner = NativeDeviceSyncRunner(
        coordinator: coordinator,
        configuration: try NativeDeviceSyncRunnerConfiguration(intervalSeconds: 15, maximumBackoffSeconds: 60, jitterFraction: 0),
        clock: RunnerClock(),
        scheduler: scheduler,
        randomizer: RunnerRandom(0)
    )

    runner.start()
    try await waitUntil { await coordinator.calls() == 1 && scheduler.sleeps().count == 1 }
    let secondGate = RunnerGate()
    await coordinator.setGate(secondGate)
    let first = Task { await runner.requestRefresh() }
    let second = Task { await runner.requestRefresh() }
    let third = Task { await runner.requestRefresh() }
    try await waitUntil { runner.pendingManualRequestCountForTesting() == 3 }
    try await waitUntil { await coordinator.calls() == 2 }
    // The second cycle is deliberately allowed to finish only after all
    // callers have had an opportunity to join it.
    for _ in 0..<20 { await Task.yield() }
    secondGate.releaseOne()
    _ = await first.value
    _ = await second.value
    _ = await third.value
    #expect(await coordinator.calls() == 2)
    #expect(await coordinator.maximumActive() == 1)
    await runner.stop()
}

@Test func runnerCoalescesManualRefreshesDuringCoordinatorCompletion() async throws {
    let coordinator = RunnerCoordinator(outcomes: [.noChange(1)])
    let completionGate = RunnerGate()
    await coordinator.setCompletionGate(completionGate)
    let runner = NativeDeviceSyncRunner(
        coordinator: coordinator,
        configuration: try NativeDeviceSyncRunnerConfiguration(intervalSeconds: 15, maximumBackoffSeconds: 60, jitterFraction: 0),
        clock: RunnerClock(),
        scheduler: RunnerScheduler(),
        randomizer: RunnerRandom(0)
    )

    runner.start()
    try await waitUntil {
        let calls = await coordinator.calls()
        let active = await coordinator.maximumActive()
        return calls == 1 && active == 1
    }
    let first = Task { await runner.requestRefresh() }
    let second = Task { await runner.requestRefresh() }
    try await waitUntil { runner.pendingManualRequestCountForTesting() == 2 }
    completionGate.releaseOne()

    #expect((await first.value).reason == .noChange)
    #expect((await second.value).reason == .noChange)
    #expect(await coordinator.calls() == 1)
    await runner.stop()
}

@Test func runnerSchedulesOneNewCycleForRefreshAfterCompletion() async throws {
    let coordinator = RunnerCoordinator(outcomes: [.noChange(1), .noChange(2)])
    let scheduler = RunnerScheduler()
    let runner = NativeDeviceSyncRunner(
        coordinator: coordinator,
        configuration: try NativeDeviceSyncRunnerConfiguration(intervalSeconds: 15, maximumBackoffSeconds: 60, jitterFraction: 0),
        clock: RunnerClock(),
        scheduler: scheduler,
        randomizer: RunnerRandom(0)
    )

    runner.start()
    try await waitUntil {
        await coordinator.calls() == 1 && scheduler.sleeps().count == 1 && !runner.status().inFlight
    }
    let secondGate = RunnerGate()
    await coordinator.setGate(secondGate)
    let waiter = Task { await runner.requestRefresh() }
    try await waitUntil {
        let calls = await coordinator.calls()
        return runner.pendingManualRequestCountForTesting() == 1 && calls == 2
    }
    secondGate.releaseOne()

    #expect((await waiter.value).reason == .noChange)
    #expect(await coordinator.calls() == 2)
    await runner.stop()
}

@Test func runnerCoalescesRefreshWithTimerWithoutLosingTheWake() async throws {
    let coordinator = RunnerCoordinator(outcomes: [.noChange(1), .noChange(2)])
    let scheduler = RunnerScheduler()
    let secondGate = RunnerGate()
    let runner = NativeDeviceSyncRunner(
        coordinator: coordinator,
        configuration: try NativeDeviceSyncRunnerConfiguration(intervalSeconds: 15, maximumBackoffSeconds: 60, jitterFraction: 0),
        clock: RunnerClock(),
        scheduler: scheduler,
        randomizer: RunnerRandom(0)
    )

    runner.start()
    try await waitUntil { await coordinator.calls() == 1 && scheduler.sleeps().count == 1 }
    await coordinator.setGate(secondGate)
    let waiter = Task { await runner.requestRefresh() }
    try await waitUntil { runner.pendingManualRequestCountForTesting() == 1 }
    scheduler.releaseNext()
    try await waitUntil { await coordinator.calls() == 2 }
    secondGate.releaseOne()

    #expect((await waiter.value).reason == .noChange)
    #expect(await coordinator.calls() == 2)
    #expect(await coordinator.maximumActive() == 1)
    await runner.stop()
}

@Test func runnerUsesBoundedExponentialBackoffWithOneSidedInjectedJitter() async throws {
    let coordinator = RunnerCoordinator(outcomes: [.transportFailure, .transportFailure, .noChange(1)])
    let scheduler = RunnerScheduler()
    let runner = NativeDeviceSyncRunner(
        coordinator: coordinator,
        configuration: try NativeDeviceSyncRunnerConfiguration(intervalSeconds: 15, maximumBackoffSeconds: 60, jitterFraction: 0.20),
        clock: RunnerClock(),
        scheduler: scheduler,
        randomizer: RunnerRandom(1)
    )

    runner.start()
    try await waitUntil { await coordinator.calls() == 1 && scheduler.sleeps().count == 1 }
    #expect(scheduler.sleeps()[0] == 36_000_000_000)
    #expect(runner.status().failureCount == 1)
    scheduler.releaseNext()
    try await waitUntil { await coordinator.calls() == 2 && scheduler.sleeps().count == 2 }
    #expect(scheduler.sleeps()[1] == 60_000_000_000)
    #expect(runner.status().failureCount == 2)
    await runner.stop()
}

@Test func runnerStopIsGracefulAndStatusDoesNotExposeUnknownErrors() async throws {
    let coordinator = RunnerCoordinator(outcomes: [.unknownFailure])
    let scheduler = RunnerScheduler()
    let runner = NativeDeviceSyncRunner(
        coordinator: coordinator,
        configuration: try NativeDeviceSyncRunnerConfiguration(intervalSeconds: 15, maximumBackoffSeconds: 60, jitterFraction: 0),
        clock: RunnerClock(),
        scheduler: scheduler,
        randomizer: RunnerRandom(0)
    )

    runner.start()
    try await waitUntil { await coordinator.calls() == 1 && runner.status().failureCount == 1 }
    #expect(runner.status().reason == .unknownFailure)
    let waiter = Task { await runner.requestRefresh() }
    await runner.stop()
    let waiterStatus = await waiter.value
    let status = runner.status()
    #expect(status.lifecycle == .stopped)
    #expect(status.reason == .cancelled)
    #expect(waiterStatus.lifecycle == .stopped)
    #expect(waiterStatus.reason == .cancelled)
    #expect(!String(describing: status).contains("secret"))
    #expect(!String(describing: status).contains("path"))
}

@Test func runnerStopResolvesRefreshWaitersDuringAnActiveCycle() async throws {
    let coordinator = RunnerCoordinator(outcomes: [.noChange(1)])
    let activeGate = RunnerGate()
    await coordinator.setGate(activeGate)
    let runner = NativeDeviceSyncRunner(
        coordinator: coordinator,
        configuration: try NativeDeviceSyncRunnerConfiguration(intervalSeconds: 15, maximumBackoffSeconds: 60, jitterFraction: 0),
        clock: RunnerClock(),
        scheduler: RunnerScheduler(),
        randomizer: RunnerRandom(0)
    )

    runner.start()
    try await waitUntil {
        let calls = await coordinator.calls()
        let active = await coordinator.maximumActive()
        return calls == 1 && active == 1
    }
    let first = Task { await runner.requestRefresh() }
    let second = Task { await runner.requestRefresh() }
    try await waitUntil { runner.pendingManualRequestCountForTesting() == 2 }

    await runner.stop()
    let firstStatus = await first.value
    let secondStatus = await second.value
    #expect(firstStatus.lifecycle == .stopped)
    #expect(secondStatus.lifecycle == .stopped)
    #expect(runner.status().lifecycle == .stopped)
    #expect(await coordinator.maximumActive() == 1)
}

@Test func stoppedRunnerCannotRestartItsClosedWakeBoundary() async throws {
    let coordinator = RunnerCoordinator(outcomes: [.noChange(1), .noChange(2)])
    let scheduler = RunnerScheduler()
    let runner = NativeDeviceSyncRunner(
        coordinator: coordinator,
        configuration: try NativeDeviceSyncRunnerConfiguration(intervalSeconds: 15, maximumBackoffSeconds: 60, jitterFraction: 0),
        clock: RunnerClock(),
        scheduler: scheduler,
        randomizer: RunnerRandom(0)
    )

    runner.start()
    try await waitUntil { await coordinator.calls() == 1 && scheduler.sleeps().count == 1 }
    await runner.stop()
    runner.start()
    for _ in 0..<20 { await Task.yield() }

    #expect(await coordinator.calls() == 1)
    #expect(runner.status().lifecycle == .stopped)
}

private func waitUntil(
    _ predicate: @escaping @Sendable () async -> Bool
) async throws {
    for _ in 0..<200 {
        if await predicate() { return }
        try await Task.sleep(nanoseconds: 1_000_000)
    }
    throw RunnerTestTimeout()
}

private struct RunnerTestTimeout: Error {}
