import AgentPassNativeCore
import Foundation

/// The service-facing coordinator boundary.  Keeping this small protocol in
/// ServiceSupport makes the runner deterministic to test while the production
/// adapter below remains the concrete `NativeDeviceSyncCoordinator` actor.
public protocol NativeDeviceSyncCoordinating: Sendable {
    func synchronize(waitMilliseconds: Int) async throws -> NativeDeviceSyncRunResult
    func snapshot() async -> NativeDeviceRefreshSnapshot
}

extension NativeDeviceSyncCoordinator: NativeDeviceSyncCoordinating {}

public protocol NativeDeviceSyncRunnerClock: Sendable {
    func nowMilliseconds() -> Int64
}

public protocol NativeDeviceSyncRunnerScheduling: Sendable {
    func sleep(nanoseconds: UInt64) async throws
}

public protocol NativeDeviceSyncRunnerRandomizing: Sendable {
    /// Returns a value in the half-open interval [0, 1]. Implementations are
    /// treated as untrusted and are clamped by the runner.
    func nextUnitInterval() -> Double
}

public struct NativeDeviceSyncSystemClock: NativeDeviceSyncRunnerClock, Sendable {
    public init() {}

    public func nowMilliseconds() -> Int64 {
        let milliseconds = Date().timeIntervalSince1970 * 1_000
        guard milliseconds.isFinite else { return 0 }
        if milliseconds <= 0 { return 0 }
        return min(Int64(milliseconds), Int64.max)
    }
}

public struct NativeDeviceSyncTaskScheduler: NativeDeviceSyncRunnerScheduling, Sendable {
    public init() {}

    public func sleep(nanoseconds: UInt64) async throws {
        try await Task.sleep(nanoseconds: nanoseconds)
    }
}

public struct NativeDeviceSyncSystemRandom: NativeDeviceSyncRunnerRandomizing, Sendable {
    public init() {}

    public func nextUnitInterval() -> Double {
        Double(UInt64.random(in: 0...UInt64.max)) / Double(UInt64.max)
    }
}

public enum NativeDeviceSyncRunnerConfigurationError: Error, LocalizedError, Equatable, Sendable {
    case invalidInterval
    case invalidBackoff
    case invalidPollWait
    case invalidJitter

    public var errorDescription: String? {
        switch self {
        case .invalidInterval: return "device_sync_runner_invalid_interval"
        case .invalidBackoff: return "device_sync_runner_invalid_backoff"
        case .invalidPollWait: return "device_sync_runner_invalid_poll_wait"
        case .invalidJitter: return "device_sync_runner_invalid_jitter"
        }
    }
}

public struct NativeDeviceSyncRunnerConfiguration: Sendable, Equatable {
    public static let minimumIntervalSeconds = 15
    public static let maximumIntervalSeconds = 3_600
    public static let maximumPollWaitMilliseconds = 30_000
    public static let maximumJitterFraction = 0.25

    public let intervalSeconds: Int
    public let maximumBackoffSeconds: Int
    public let pollWaitMilliseconds: Int
    public let jitterFraction: Double

    public init(
        intervalSeconds: Int = 900,
        maximumBackoffSeconds: Int = 3_600,
        pollWaitMilliseconds: Int = 30_000,
        jitterFraction: Double = 0.10
    ) throws {
        guard (Self.minimumIntervalSeconds...Self.maximumIntervalSeconds).contains(intervalSeconds) else {
            throw NativeDeviceSyncRunnerConfigurationError.invalidInterval
        }
        guard (intervalSeconds...Self.maximumIntervalSeconds).contains(maximumBackoffSeconds) else {
            throw NativeDeviceSyncRunnerConfigurationError.invalidBackoff
        }
        guard (0...Self.maximumPollWaitMilliseconds).contains(pollWaitMilliseconds) else {
            throw NativeDeviceSyncRunnerConfigurationError.invalidPollWait
        }
        guard jitterFraction.isFinite,
              (0...Self.maximumJitterFraction).contains(jitterFraction) else {
            throw NativeDeviceSyncRunnerConfigurationError.invalidJitter
        }
        self.intervalSeconds = intervalSeconds
        self.maximumBackoffSeconds = maximumBackoffSeconds
        self.pollWaitMilliseconds = pollWaitMilliseconds
        self.jitterFraction = jitterFraction
    }
}

public enum NativeDeviceSyncRunnerLifecycle: String, Sendable, Equatable {
    case stopped
    case running
    case stopping
}

/// Stable, redacted reasons intended for health/status APIs. This enum is
/// deliberately closed: no underlying transport error, path, URL, secret,
/// hash, or server-provided text is ever copied into runner status.
public enum NativeDeviceSyncRunnerReason: String, Sendable, Equatable {
    case notStarted = "not_started"
    case starting
    case scheduled
    case manualRefresh = "manual_refresh"
    case waiting
    case success
    case noChange = "no_change"
    case blocked
    case transportFailure = "transport_failure"
    case verificationFailure = "verification_failure"
    case storageFailure = "storage_failure"
    case activationFailure = "activation_failure"
    case acknowledgementFailure = "acknowledgement_failure"
    case stateFailure = "state_failure"
    case cancelled
    case stopped
    case unknownFailure = "unknown_failure"
}

public struct NativeDeviceSyncRunnerStatus: Sendable, Equatable {
    public let lifecycle: NativeDeviceSyncRunnerLifecycle
    public let state: NativeDeviceRefreshMachineState
    public let generation: Int64
    public let sequence: Int64?
    public let inFlight: Bool
    public let lastAttemptAtMilliseconds: Int64?
    public let lastSuccessAtMilliseconds: Int64?
    public let nextAttemptAtMilliseconds: Int64?
    public let failureCount: Int
    public let reason: NativeDeviceSyncRunnerReason

    public init(
        lifecycle: NativeDeviceSyncRunnerLifecycle,
        state: NativeDeviceRefreshMachineState,
        generation: Int64,
        sequence: Int64?,
        inFlight: Bool = false,
        lastAttemptAtMilliseconds: Int64?,
        lastSuccessAtMilliseconds: Int64?,
        nextAttemptAtMilliseconds: Int64?,
        failureCount: Int,
        reason: NativeDeviceSyncRunnerReason
    ) {
        self.lifecycle = lifecycle
        self.state = state
        self.generation = max(0, generation)
        self.sequence = sequence.map { max(0, $0) }
        self.inFlight = inFlight
        self.lastAttemptAtMilliseconds = lastAttemptAtMilliseconds
        self.lastSuccessAtMilliseconds = lastSuccessAtMilliseconds
        self.nextAttemptAtMilliseconds = nextAttemptAtMilliseconds
        self.failureCount = max(0, failureCount)
        self.reason = reason
    }
}

/// A single serial background loop around the durable native coordinator.
/// `start()` performs one immediate synchronization, then waits for either a
/// bounded timer or a coalesced manual wake-up. There is never more than one
/// coordinator operation in flight.
public final class NativeDeviceSyncRunner: @unchecked Sendable {
    private enum Trigger {
        case startup
        case scheduled
        case manual
    }

    private enum WakeResult {
        case timer
        case manual
        case stopped
    }

    private final class WakeSignal: @unchecked Sendable {
        private let lock = NSLock()
        private var signaled = false
        private var closed = false
        private var waiter: CheckedContinuation<Bool, Never>?

        func signal() {
            let continuation: CheckedContinuation<Bool, Never>?
            lock.lock()
            if closed {
                continuation = nil
            } else if let existing = waiter {
                waiter = nil
                continuation = existing
            } else {
                signaled = true
                continuation = nil
            }
            lock.unlock()
            continuation?.resume(returning: true)
        }

        func consume() {
            lock.lock()
            signaled = false
            lock.unlock()
        }

        func close() {
            let continuation: CheckedContinuation<Bool, Never>?
            lock.lock()
            closed = true
            continuation = waiter
            waiter = nil
            lock.unlock()
            continuation?.resume(returning: false)
        }

        func wait() async -> Bool {
            await withTaskCancellationHandler(operation: {
                await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
                    var shouldResume = false
                    var value = false
                    lock.lock()
                    if Task.isCancelled || closed {
                        shouldResume = true
                    } else if signaled {
                        signaled = false
                        shouldResume = true
                        value = true
                    } else {
                        waiter = continuation
                    }
                    lock.unlock()
                    if shouldResume { continuation.resume(returning: value) }
                }
            }, onCancel: {
                self.cancelWaiter()
            })
        }

        private func cancelWaiter() {
            let continuation: CheckedContinuation<Bool, Never>?
            lock.lock()
            continuation = waiter
            waiter = nil
            lock.unlock()
            continuation?.resume(returning: false)
        }
    }

    private let coordinator: any NativeDeviceSyncCoordinating
    private let configuration: NativeDeviceSyncRunnerConfiguration
    private let clock: any NativeDeviceSyncRunnerClock
    private let scheduler: any NativeDeviceSyncRunnerScheduling
    private let randomizer: any NativeDeviceSyncRunnerRandomizing
    private let stateLock = NSLock()
    private let wakeSignal = WakeSignal()
    private var loopTask: Task<Void, Never>?
    private var hasStarted = false
    private var cycleInFlight = false
    private var manualWakePending = false
    private var scheduledDelayNanoseconds: UInt64?
    private var manualWaiters: [CheckedContinuation<NativeDeviceSyncRunnerStatus, Never>] = []
    private var statusValue: NativeDeviceSyncRunnerStatus

    public init(
        coordinator: any NativeDeviceSyncCoordinating,
        configuration: NativeDeviceSyncRunnerConfiguration,
        clock: any NativeDeviceSyncRunnerClock = NativeDeviceSyncSystemClock(),
        scheduler: any NativeDeviceSyncRunnerScheduling = NativeDeviceSyncTaskScheduler(),
        randomizer: any NativeDeviceSyncRunnerRandomizing = NativeDeviceSyncSystemRandom()
    ) {
        self.coordinator = coordinator
        self.configuration = configuration
        self.clock = clock
        self.scheduler = scheduler
        self.randomizer = randomizer
        self.statusValue = NativeDeviceSyncRunnerStatus(
            lifecycle: .stopped,
            state: .idle,
            generation: 0,
            sequence: nil,
            inFlight: false,
            lastAttemptAtMilliseconds: nil,
            lastSuccessAtMilliseconds: nil,
            nextAttemptAtMilliseconds: nil,
            failureCount: 0,
            reason: .notStarted
        )
    }

    public func status() -> NativeDeviceSyncRunnerStatus {
        stateLock.lock()
        defer { stateLock.unlock() }
        return statusValue
    }

    /// Test-only observability for synchronizing concurrent callers with the
    /// coalescing boundary. This is deliberately an internal count rather
    /// than a public status field: callers only need the resulting status,
    /// while deterministic tests must know that their requests were admitted
    /// before releasing an in-flight cycle.
    internal func pendingManualRequestCountForTesting() -> Int {
        withStateLock { manualWaiters.count }
    }

    /// Idempotently starts the only runner loop. The first synchronization is
    /// started immediately so a durable fetching/staging/ack state is resumed
    /// on service launch without waiting for the configured interval.
    public func start() {
        stateLock.lock()
        guard loopTask == nil, !hasStarted, statusValue.lifecycle == .stopped else {
            stateLock.unlock()
            return
        }
        hasStarted = true
        statusValue = statusValue.replacing(
            lifecycle: .running,
            nextAttemptAtMilliseconds: nil,
            reason: .starting
        )
        cycleInFlight = true
        let task = Task { [weak self] in
            guard let self else { return }
            await self.runLoop()
        }
        loopTask = task
        stateLock.unlock()
    }

    /// Requests one refresh and waits for the current or next cycle. Calls
    /// made while a cycle is active are attached to that cycle; calls made
    /// while waiting produce one shared wake-up regardless of their count.
    public func requestRefresh() async -> NativeDeviceSyncRunnerStatus {
        await withCheckedContinuation { (continuation: CheckedContinuation<NativeDeviceSyncRunnerStatus, Never>) in
            var immediate: NativeDeviceSyncRunnerStatus?
            withStateLock {
                if statusValue.lifecycle == .stopping {
                    // A request racing with stop is a waiter, not an
                    // observation of the intermediate stopping state. The
                    // loop's defer resolves it with the final stopped status.
                    manualWaiters.append(continuation)
                } else if statusValue.lifecycle != .running {
                    immediate = statusValue
                } else {
                    manualWaiters.append(continuation)
                    if !cycleInFlight && !manualWakePending {
                        manualWakePending = true
                        // Publish the wake while holding the same lock as the
                        // cycle transition. If a timer wins concurrently, it
                        // can consume this wake as part of that cycle; if the
                        // manual request wins, the loop observes the wake and
                        // starts exactly one manual cycle. Signaling after
                        // releasing this lock leaves a race where the timer
                        // consumes first and the delayed signal schedules an
                        // unnecessary second cycle.
                        wakeSignal.signal()
                    }
                }
            }
            if let immediate {
                continuation.resume(returning: immediate)
            }
        }
    }

    /// Cancels the loop, wakes any pending wait, and waits until no cycle can
    /// run. In-flight coordinator work receives task cancellation and pending
    /// manual callers receive the final redacted stopped status.
    public func stop() async {
        var task: Task<Void, Never>?
        var shouldReturn = false
        withStateLock {
            if statusValue.lifecycle == .stopped {
                shouldReturn = true
                return
            }
            statusValue = statusValue.replacing(
                lifecycle: .stopping,
                nextAttemptAtMilliseconds: nil,
                reason: .cancelled
            )
            task = loopTask
        }
        if shouldReturn {
            return
        }

        wakeSignal.close()
        task?.cancel()
        await task?.value
    }

    private func runLoop() async {
        defer { finishStopped() }
        await performCycle(trigger: .startup)

        while !Task.isCancelled {
            let delay = nextDelayNanoseconds()
            setWaiting(nextAttemptAtMilliseconds: scheduledTime(after: delay))
            switch await waitForNextWake(nanoseconds: delay) {
            case .timer:
                guard beginCycle(trigger: .scheduled) else { return }
                await performCycle(trigger: .scheduled, alreadyBegan: true)
            case .manual:
                guard beginCycle(trigger: .manual) else { return }
                await performCycle(trigger: .manual, alreadyBegan: true)
            case .stopped:
                return
            }
        }
    }

    private func performCycle(trigger: Trigger, alreadyBegan: Bool = false) async {
        if !alreadyBegan && trigger != .startup {
            guard beginCycle(trigger: trigger) else { return }
        }

        let attemptAt = clock.nowMilliseconds()
        let initialSnapshot = await coordinator.snapshot()
        publishAttempt(snapshot: initialSnapshot, at: attemptAt, trigger: trigger)

        do {
            let result = try await coordinator.synchronize(waitMilliseconds: configuration.pollWaitMilliseconds)
            if Task.isCancelled { return }
            let finalSnapshot = await coordinator.snapshot()
            let now = clock.nowMilliseconds()
            finishSuccessfulCycle(result: result, snapshot: finalSnapshot, at: now)
        } catch is CancellationError {
            return
        } catch {
            if Task.isCancelled { return }
            let finalSnapshot = await coordinator.snapshot()
            finishFailedCycle(snapshot: finalSnapshot, at: clock.nowMilliseconds(), reason: Self.reason(for: error))
        }
    }

    private func beginCycle(trigger: Trigger) -> Bool {
        stateLock.lock()
        guard statusValue.lifecycle == .running, !cycleInFlight else {
            stateLock.unlock()
            return false
        }
        cycleInFlight = true
        statusValue = statusValue.replacing(
            nextAttemptAtMilliseconds: nil,
            reason: Self.reason(for: trigger)
        )
        stateLock.unlock()
        // A manual signal which raced with the timer is part of this cycle,
        // not a second cycle.
        wakeSignal.consume()
        return true
    }

    private func publishAttempt(snapshot: NativeDeviceRefreshSnapshot, at time: Int64, trigger: Trigger) {
        stateLock.lock()
        statusValue = statusValue.replacing(
            state: snapshot.state,
            generation: snapshot.generation,
            sequence: snapshot.sequence,
            inFlight: true,
            lastAttemptAtMilliseconds: time,
            nextAttemptAtMilliseconds: nil,
            reason: Self.reason(for: trigger)
        )
        stateLock.unlock()
    }

    private func finishSuccessfulCycle(result: NativeDeviceSyncRunResult, snapshot: NativeDeviceRefreshSnapshot, at time: Int64) {
        let reason: NativeDeviceSyncRunnerReason
        switch result {
        case .noChange: reason = .noChange
        case .applied: reason = .success
        case .blocked: reason = .blocked
        }
        let delay = delayNanoseconds(failureCount: 0)
        stateLock.lock()
        scheduledDelayNanoseconds = delay
        statusValue = statusValue.replacing(
            state: snapshot.state,
            generation: snapshot.generation,
            sequence: snapshot.sequence,
            inFlight: false,
            lastSuccessAtMilliseconds: time,
            nextAttemptAtMilliseconds: Self.saturatingAdd(time, milliseconds(for: delay)),
            failureCount: 0,
            reason: reason
        )
        let waiters = finishCycleLocked()
        let status = statusValue
        stateLock.unlock()
        resume(waiters, with: status)
    }

    private func finishFailedCycle(snapshot: NativeDeviceRefreshSnapshot, at time: Int64, reason: NativeDeviceSyncRunnerReason) {
        stateLock.lock()
        let nextFailureCount = min(statusValue.failureCount + 1, 1_000_000)
        stateLock.unlock()
        let delay = delayNanoseconds(failureCount: nextFailureCount)
        stateLock.lock()
        scheduledDelayNanoseconds = delay
        statusValue = statusValue.replacing(
            state: snapshot.state,
            generation: snapshot.generation,
            sequence: snapshot.sequence,
            inFlight: false,
            nextAttemptAtMilliseconds: Self.saturatingAdd(time, milliseconds(for: delay)),
            failureCount: nextFailureCount,
            reason: reason
        )
        let waiters = finishCycleLocked()
        let status = statusValue
        stateLock.unlock()
        resume(waiters, with: status)
    }

    private func finishCycleLocked() -> [CheckedContinuation<NativeDeviceSyncRunnerStatus, Never>] {
        cycleInFlight = false
        manualWakePending = false
        scheduledDelayNanoseconds = nil
        // stop() promises that joined manual callers observe the terminal
        // stopped snapshot, never the transient stopping state published
        // while cancellation is unwinding an in-flight coordinator call.
        guard statusValue.lifecycle == .running else { return [] }
        let waiters = manualWaiters
        manualWaiters.removeAll(keepingCapacity: true)
        return waiters
    }

    private func setWaiting(nextAttemptAtMilliseconds: Int64) {
        stateLock.lock()
        guard statusValue.lifecycle == .running, !cycleInFlight else {
            stateLock.unlock()
            return
        }
        statusValue = statusValue.replacing(
            nextAttemptAtMilliseconds: nextAttemptAtMilliseconds
        )
        stateLock.unlock()
    }

    private func waitForNextWake(nanoseconds: UInt64) async -> WakeResult {
        await withTaskGroup(of: WakeResult.self) { group in
            group.addTask { [scheduler] in
                do {
                    try await scheduler.sleep(nanoseconds: nanoseconds)
                    return .timer
                } catch {
                    return .stopped
                }
            }
            group.addTask { [wakeSignal] in
                await wakeSignal.wait() ? .manual : .stopped
            }
            let result = await group.next() ?? .stopped
            group.cancelAll()
            return result
        }
    }

    private func finishStopped() {
        stateLock.lock()
        statusValue = statusValue.replacing(
            lifecycle: .stopped,
            inFlight: false,
            nextAttemptAtMilliseconds: nil,
            reason: statusValue.reason == .cancelled ? .cancelled : .stopped
        )
        cycleInFlight = false
        manualWakePending = false
        let waiters = manualWaiters
        manualWaiters.removeAll(keepingCapacity: true)
        loopTask = nil
        let status = statusValue
        stateLock.unlock()
        resume(waiters, with: status)
    }

    private func nextDelayNanoseconds() -> UInt64 {
        stateLock.lock()
        if let scheduled = scheduledDelayNanoseconds {
            scheduledDelayNanoseconds = nil
            stateLock.unlock()
            return scheduled
        }
        let failures = statusValue.failureCount
        stateLock.unlock()
        return delayNanoseconds(failureCount: failures)
    }

    private func delayNanoseconds(failureCount: Int) -> UInt64 {
        let exponent = min(max(failureCount, 0), 31)
        let multiplier = pow(2.0, Double(exponent))
        let exponential = min(
            Double(configuration.maximumBackoffSeconds),
            Double(configuration.intervalSeconds) * multiplier
        )
        let available = max(0, Double(configuration.maximumBackoffSeconds) - exponential)
        let jitterCeiling = min(available, exponential * configuration.jitterFraction)
        let unit = min(max(randomizer.nextUnitInterval(), 0), 1)
        let seconds = min(Double(configuration.maximumBackoffSeconds), exponential + jitterCeiling * unit)
        let nanoseconds = seconds * 1_000_000_000
        guard nanoseconds.isFinite, nanoseconds > 0 else { return 1 }
        return min(UInt64(nanoseconds), UInt64.max)
    }

    private func scheduledTime(after nanoseconds: UInt64) -> Int64 {
        Self.saturatingAdd(clock.nowMilliseconds(), milliseconds(for: nanoseconds))
    }

    private func milliseconds(for nanoseconds: UInt64) -> Int64 {
        let milliseconds = nanoseconds / 1_000_000
        return milliseconds > UInt64(Int64.max) ? Int64.max : Int64(milliseconds)
    }

    private func resume(
        _ waiters: [CheckedContinuation<NativeDeviceSyncRunnerStatus, Never>],
        with status: NativeDeviceSyncRunnerStatus
    ) {
        for waiter in waiters { waiter.resume(returning: status) }
    }

    private static func reason(for trigger: Trigger) -> NativeDeviceSyncRunnerReason {
        switch trigger {
        case .startup: return .starting
        case .scheduled: return .scheduled
        case .manual: return .manualRefresh
        }
    }

    private static func reason(for error: Error) -> NativeDeviceSyncRunnerReason {
        guard let error = error as? NativeDeviceSyncCoordinatorError else { return .unknownFailure }
        switch error {
        case .transportUnavailable: return .transportFailure
        case .verificationFailed: return .verificationFailure
        case .storageUnavailable: return .storageFailure
        case .activationUnavailable: return .activationFailure
        case .acknowledgementRejected: return .acknowledgementFailure
        case .invalidConfiguration, .generationChanged, .unrecoverableState, .convergenceLimit:
            return .stateFailure
        }
    }

    private static func saturatingAdd(_ left: Int64, _ right: Int64) -> Int64 {
        if right > 0, left > Int64.max - right { return Int64.max }
        if right < 0, left < Int64.min - right { return Int64.min }
        return left + right
    }

    private func withStateLock<T>(_ body: () -> T) -> T {
        stateLock.lock()
        defer { stateLock.unlock() }
        return body()
    }
}

private extension NativeDeviceSyncRunnerStatus {
    func replacing(
        lifecycle: NativeDeviceSyncRunnerLifecycle? = nil,
        state: NativeDeviceRefreshMachineState? = nil,
        generation: Int64? = nil,
        sequence: Int64?? = nil,
        inFlight: Bool? = nil,
        lastAttemptAtMilliseconds: Int64?? = nil,
        lastSuccessAtMilliseconds: Int64?? = nil,
        nextAttemptAtMilliseconds: Int64?? = nil,
        failureCount: Int? = nil,
        reason: NativeDeviceSyncRunnerReason? = nil
    ) -> Self {
        Self(
            lifecycle: lifecycle ?? self.lifecycle,
            state: state ?? self.state,
            generation: generation ?? self.generation,
            sequence: sequence ?? self.sequence,
            inFlight: inFlight ?? self.inFlight,
            lastAttemptAtMilliseconds: lastAttemptAtMilliseconds ?? self.lastAttemptAtMilliseconds,
            lastSuccessAtMilliseconds: lastSuccessAtMilliseconds ?? self.lastSuccessAtMilliseconds,
            nextAttemptAtMilliseconds: nextAttemptAtMilliseconds ?? self.nextAttemptAtMilliseconds,
            failureCount: failureCount ?? self.failureCount,
            reason: reason ?? self.reason
        )
    }
}
