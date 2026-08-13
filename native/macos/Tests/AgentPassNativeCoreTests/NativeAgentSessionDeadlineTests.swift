import Testing
@testable import AgentPassNativeCore

private struct FixedWallClock: NativeAgentWallClock {
    let value: NativeAgentWallClockValue

    func sample() throws -> NativeAgentWallClockValue { value }
}

private struct FixedMonotonicClock: NativeAgentMonotonicClock {
    let value: NativeAgentMonotonicClockValue

    init(nanoseconds: UInt64, bootIdentity: String = "boot-a") throws {
        value = try NativeAgentMonotonicClockValue(nanoseconds: nanoseconds, bootIdentity: bootIdentity)
    }

    func sample() throws -> NativeAgentMonotonicClockValue { value }
}

private struct ThrowingWallClock: NativeAgentWallClock {
    enum Failure: Error { case unavailable }

    func sample() throws -> NativeAgentWallClockValue { throw Failure.unavailable }
}

private struct ThrowingMonotonicClock: NativeAgentMonotonicClock {
    enum Failure: Error { case unavailable }

    func sample() throws -> NativeAgentMonotonicClockValue { throw Failure.unavailable }
}

private struct InvalidWallClock: NativeAgentWallClock {
    func sample() throws -> NativeAgentWallClockValue {
        throw NativeAgentSessionDeadlineError.invalidWallClockEvidence
    }
}

private func wall(_ milliseconds: Int64) -> NativeAgentWallClockValue {
    NativeAgentWallClockValue(millisecondsSinceUnixEpoch: milliseconds)
}

private func monotonic(_ nanoseconds: UInt64, bootIdentity: String = "boot-a") throws -> NativeAgentMonotonicClockValue {
    try NativeAgentMonotonicClockValue(nanoseconds: nanoseconds, bootIdentity: bootIdentity)
}

@Test func deadlineActivationUsesInjectableClocksAndCheckedIntersection() throws {
    let deadline = try NativeAgentSessionDeadline(
        signedWallExpiryMilliseconds: 1_000_010,
        wallClock: FixedWallClock(value: wall(1_000_000)),
        monotonicClock: try FixedMonotonicClock(nanoseconds: 500)
    )

    #expect(deadline.signedWallExpiryMilliseconds == 1_000_010)
    #expect(deadline.activationWallClock == wall(1_000_000))
    #expect(deadline.activationMonotonicClock == (try monotonic(500)))
    #expect(deadline.monotonicDeadlineNanoseconds == 10_000_500)

    var live = deadline
    let result = try live.revalidate(wallClock: wall(1_000_009), monotonicClock: try monotonic(9_000_500))
    #expect(result.wallMillisecondsRemaining == 1)
    #expect(result.monotonicNanosecondsRemaining == 1_000_000)
    #expect(live.monotonicDeadlineNanoseconds == deadline.monotonicDeadlineNanoseconds)
}

@Test func deadlineRejectsAtEitherExactBoundary() throws {
    let base = try NativeAgentSessionDeadline(
        signedWallExpiryMilliseconds: 1_000_010,
        wallClock: wall(1_000_000),
        monotonicClock: try monotonic(500)
    )

    var wallBoundary = base
    #expect(throws: NativeAgentSessionDeadlineError.wallClockExpired) {
        try wallBoundary.revalidate(wallClock: wall(1_000_010), monotonicClock: try monotonic(500))
    }

    var monotonicBoundary = base
    #expect(throws: NativeAgentSessionDeadlineError.monotonicDeadlineExpired) {
        try monotonicBoundary.revalidate(wallClock: wall(1_000_000), monotonicClock: try monotonic(10_000_500))
    }
}

@Test func deadlineRejectsSignedExpiryAtOrBeforeActivation() throws {
    #expect(throws: NativeAgentSessionDeadlineError.invalidWallClockEvidence) {
        _ = try NativeAgentSessionDeadline(signedWallExpiryMilliseconds: 1, wallClock: wall(-1), monotonicClock: try monotonic(1))
    }
    #expect(throws: NativeAgentSessionDeadlineError.invalidSignedWallExpiry) {
        _ = try NativeAgentSessionDeadline(
            signedWallExpiryMilliseconds: 1_000_000,
            wallClock: wall(1_000_000),
            monotonicClock: try monotonic(1)
        )
    }
    #expect(throws: NativeAgentSessionDeadlineError.invalidSignedWallExpiry) {
        _ = try NativeAgentSessionDeadline(
            signedWallExpiryMilliseconds: 999_999,
            wallClock: wall(1_000_000),
            monotonicClock: try monotonic(1)
        )
    }
}

@Test func deadlineRejectsWallRollbackIncludingRollbackAfterAnAdvance() throws {
    var deadline = try NativeAgentSessionDeadline(
        signedWallExpiryMilliseconds: 1_000_100,
        wallClock: wall(1_000_000),
        monotonicClock: try monotonic(10)
    )
    _ = try deadline.revalidate(wallClock: wall(1_000_050), monotonicClock: try monotonic(50_000_010))

    #expect(throws: NativeAgentSessionDeadlineError.wallClockRollback) {
        try deadline.revalidate(wallClock: wall(1_000_049), monotonicClock: try monotonic(50_000_011))
    }
    #expect(throws: NativeAgentSessionDeadlineError.wallClockRollback) {
        try deadline.revalidate(wallClock: wall(1_000_000), monotonicClock: try monotonic(50_000_012))
    }

    let afterRollback = try deadline.revalidate(wallClock: wall(1_000_051), monotonicClock: try monotonic(50_000_013))
    #expect(afterRollback.wallMillisecondsRemaining == 49)
}

@Test func deadlineRejectsMonotonicRollbackIncludingRollbackAfterAnAdvance() throws {
    var deadline = try NativeAgentSessionDeadline(
        signedWallExpiryMilliseconds: 1_000_100,
        wallClock: wall(1_000_000),
        monotonicClock: try monotonic(10)
    )
    _ = try deadline.revalidate(wallClock: wall(1_000_001), monotonicClock: try monotonic(20))

    #expect(throws: NativeAgentSessionDeadlineError.monotonicClockRollback) {
        try deadline.revalidate(wallClock: wall(1_000_002), monotonicClock: try monotonic(19))
    }
    #expect(throws: NativeAgentSessionDeadlineError.monotonicClockRollback) {
        try deadline.revalidate(wallClock: wall(1_000_003), monotonicClock: try monotonic(10))
    }
}

@Test func deadlineRejectsBootChangeBeforeNumericClockEvidenceCanWidenAuthority() throws {
    var deadline = try NativeAgentSessionDeadline(
        signedWallExpiryMilliseconds: 1_000_100,
        wallClock: wall(1_000_000),
        monotonicClock: try monotonic(99_999_900)
    )

    #expect(throws: NativeAgentSessionDeadlineError.monotonicBootChanged) {
        try deadline.revalidate(
            wallClock: wall(1_000_001),
            monotonicClock: try monotonic(1, bootIdentity: "boot-b")
        )
    }
}

@Test func deadlineNeverReanchorsAfterWallAdvanceOrSleepWake() throws {
    var deadline = try NativeAgentSessionDeadline(
        signedWallExpiryMilliseconds: 1_000_100,
        wallClock: wall(1_000_000),
        monotonicClock: try monotonic(100)
    )
    let fixedDeadline = deadline.monotonicDeadlineNanoseconds

    // A wall-clock advance can only consume authority; it does not move the
    // monotonic deadline toward the future.
    let first = try deadline.revalidate(wallClock: wall(1_000_090), monotonicClock: try monotonic(90_000_100))
    #expect(first.wallMillisecondsRemaining == 10)
    #expect(first.monotonicNanosecondsRemaining == fixedDeadline - 90_000_100)
    #expect(deadline.monotonicDeadlineNanoseconds == fixedDeadline)

    // A sleep/wake sample that crosses the monotonic boundary is expired,
    // even though a caller might otherwise be tempted to re-anchor at wake.
    #expect(throws: NativeAgentSessionDeadlineError.monotonicDeadlineExpired) {
        try deadline.revalidate(wallClock: wall(1_000_091), monotonicClock: try monotonic(fixedDeadline))
    }
    #expect(deadline.monotonicDeadlineNanoseconds == fixedDeadline)
}

@Test func deadlineWallAdvanceCanShortenAuthorityWhenMonotonicClockDoesNotAdvance() throws {
    var deadline = try NativeAgentSessionDeadline(
        signedWallExpiryMilliseconds: 1_000_010,
        wallClock: wall(1_000_000),
        monotonicClock: try monotonic(500)
    )

    #expect(throws: NativeAgentSessionDeadlineError.wallClockExpired) {
        try deadline.revalidate(wallClock: wall(1_000_010), monotonicClock: try monotonic(500))
    }
}

@Test func deadlineRejectsArithmeticOverflowAtActivation() throws {
    #expect(throws: NativeAgentSessionDeadlineError.deadlineOverflow) {
        _ = try NativeAgentSessionDeadline(
            signedWallExpiryMilliseconds: Int64.max,
            wallClock: wall(0),
            monotonicClock: try monotonic(0)
        )
    }
    #expect(throws: NativeAgentSessionDeadlineError.invalidWallClockEvidence) {
        _ = try NativeAgentSessionDeadline(
            signedWallExpiryMilliseconds: Int64.max,
            wallClock: wall(Int64.min),
            monotonicClock: try monotonic(0)
        )
    }
    #expect(throws: NativeAgentSessionDeadlineError.deadlineOverflow) {
        _ = try NativeAgentSessionDeadline(
            signedWallExpiryMilliseconds: 1,
            wallClock: wall(0),
            monotonicClock: try monotonic(UInt64.max)
        )
    }
}

@Test func deadlineRejectsInvalidMonotonicEvidence() throws {
    #expect(throws: NativeAgentSessionDeadlineError.invalidMonotonicEvidence) {
        _ = try NativeAgentMonotonicClockValue(nanoseconds: 1, bootIdentity: "")
    }
    #expect(throws: NativeAgentSessionDeadlineError.invalidMonotonicEvidence) {
        _ = try NativeAgentMonotonicClockValue(nanoseconds: 1, bootIdentity: "bad\0boot")
    }
    #expect(throws: NativeAgentSessionDeadlineError.invalidMonotonicEvidence) {
        _ = try NativeAgentMonotonicClockValue(
            nanoseconds: 1,
            bootIdentity: String(repeating: "x", count: NativeAgentMonotonicClockValue.maximumBootIdentityBytes + 1)
        )
    }
}

@Test func deadlineMapsClockFailuresToStableErrors() throws {
    #expect(throws: NativeAgentSessionDeadlineError.clockUnavailable) {
        _ = try NativeAgentSessionDeadline(
            signedWallExpiryMilliseconds: 1_000_010,
            wallClock: ThrowingWallClock(),
            monotonicClock: try FixedMonotonicClock(nanoseconds: 1)
        )
    }

    #expect(throws: NativeAgentSessionDeadlineError.invalidWallClockEvidence) {
        _ = try NativeAgentSessionDeadline(
            signedWallExpiryMilliseconds: 1_000_010,
            wallClock: InvalidWallClock(),
            monotonicClock: try FixedMonotonicClock(nanoseconds: 1)
        )
    }

    #expect(throws: NativeAgentSessionDeadlineError.clockUnavailable) {
        _ = try NativeAgentSessionDeadline(
            signedWallExpiryMilliseconds: 1_000_010,
            wallClock: FixedWallClock(value: wall(1_000_000)),
            monotonicClock: ThrowingMonotonicClock()
        )
    }

    var deadline = try NativeAgentSessionDeadline(
        signedWallExpiryMilliseconds: 1_000_010,
        wallClock: wall(1_000_000),
        monotonicClock: try monotonic(1)
    )
    #expect(throws: NativeAgentSessionDeadlineError.clockUnavailable) {
        try deadline.revalidate(wallClock: ThrowingWallClock(), monotonicClock: try FixedMonotonicClock(nanoseconds: 2))
    }
}

@Test func deadlineErrorsHaveStableNonAssociatedCodes() {
    #expect(NativeAgentSessionDeadlineError.allCases.map(\.rawValue).count == 10)
    #expect(NativeAgentSessionDeadlineError.wallClockRollback.localizedDescription == "wall_clock_rollback")
}
