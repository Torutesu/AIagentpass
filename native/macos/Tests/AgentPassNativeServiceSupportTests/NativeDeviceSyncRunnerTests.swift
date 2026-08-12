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
    private let lock = NSLock()
    private var permits = 0
    private var waiters: [CheckedContinuation<Void, Error>] = []

    func wait() async throws {
        try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                var resumeNow = false
                lock.lock()
                if permits > 0 {
                    permits -= 1
                    resumeNow = true
                } else {
                    waiters.append(continuation)
                }
                lock.unlock()
                if resumeNow { continuation.resume() }
            }
        }, onCancel: {
            self.cancelOne()
        })
    }

    func releaseOne() {
        let continuation: CheckedContinuation<Void, Error>?
        lock.lock()
        if waiters.isEmpty {
            permits += 1
            continuation = nil
        } else {
            continuation = waiters.removeFirst()
        }
        lock.unlock()
        continuation?.resume()
    }

    private func cancelOne() {
        let continuation: CheckedContinuation<Void, Error>?
        lock.lock()
        continuation = waiters.isEmpty ? nil : waiters.removeFirst()
        lock.unlock()
        continuation?.resume(throwing: CancellationError())
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
        switch outcome {
        case let .noChange(generation):
            snapshotValue = idleSnapshot(generation: generation, sequence: nil)
            return .noChange(generation: generation)
        case let .applied(generation, sequence):
            snapshotValue = idleSnapshot(generation: generation, sequence: sequence)
            return .applied(generation: generation, sequence: sequence)
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
            return .blocked(generation: generation, sequence: sequence, reason: .internalError)
        case .transportFailure:
            throw NativeDeviceSyncCoordinatorError.transportUnavailable
        case .unknownFailure:
            throw RunnerUnknownError.secretPathAndMessage
        }
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
    for _ in 0..<20 { await Task.yield() }
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
    for _ in 0..<20 { await Task.yield() }
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
