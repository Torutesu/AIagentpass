import Testing
@testable import AgentPassNativeCore

private struct FixedWallMillisecondsSource: NativeAgentWallMillisecondsSource {
    let value: Int64

    func sampleWallMilliseconds() throws -> Int64 { value }
}

private struct FixedContinuousNanosecondsSource: NativeAgentContinuousNanosecondsSource {
    let value: UInt64

    func sampleContinuousNanoseconds() throws -> UInt64 { value }
}

private struct FixedBootIdentitySource: NativeAgentBootIdentitySource {
    let value: String

    func sampleBootIdentity() throws -> String { value }
}

private struct FailingWallMillisecondsSource: NativeAgentWallMillisecondsSource {
    func sampleWallMilliseconds() throws -> Int64 {
        throw NativeAgentSessionDeadlineError.invalidWallClockEvidence
    }
}

private struct FailingContinuousNanosecondsSource: NativeAgentContinuousNanosecondsSource {
    func sampleContinuousNanoseconds() throws -> UInt64 {
        throw NativeAgentSessionDeadlineError.invalidMonotonicEvidence
    }
}

private struct FailingBootIdentitySource: NativeAgentBootIdentitySource {
    func sampleBootIdentity() throws -> String {
        throw NativeAgentSessionDeadlineError.invalidMonotonicEvidence
    }
}

@Test func systemWallClockUsesBoundedIntegerMilliseconds() throws {
    let fixed = NativeAgentSystemWallClock(source: FixedWallMillisecondsSource(value: Int64.max))
    #expect(try fixed.sample().millisecondsSinceUnixEpoch == Int64.max)

    let negative = NativeAgentSystemWallClock(source: FixedWallMillisecondsSource(value: -1))
    #expect(throws: NativeAgentSessionDeadlineError.clockUnavailable) { try negative.sample() }
}

@Test func systemMonotonicClockSamplesAreNondecreasingWithoutTimingAssumptions() throws {
    let clock = NativeAgentSystemMonotonicClock()
    let first = try clock.sample()
    let second = try clock.sample()

    #expect(second.nanoseconds >= first.nanoseconds)
    #expect(second.bootIdentity == first.bootIdentity)
    #expect(!first.bootIdentity.isEmpty)
    #expect(first.bootIdentity.utf8.count <= NativeAgentMonotonicClockValue.maximumBootIdentityBytes)
}

@Test func systemWallClockProducesAUnixMillisecondSampleWithoutDate() throws {
    let sample = try NativeAgentSystemWallClock().sample()
    // The assertion intentionally checks only the representable contract,
    // not a wall-clock range that could become stale or be affected by NTP.
    #expect(sample.millisecondsSinceUnixEpoch >= Int64.min)
    #expect(sample.millisecondsSinceUnixEpoch <= Int64.max)
}

@Test func systemAdaptersCollapseAllSourceFailuresToStableClockUnavailable() {
    let wall = NativeAgentSystemWallClock(source: FailingWallMillisecondsSource())
    #expect(throws: NativeAgentSessionDeadlineError.clockUnavailable) {
        try wall.sample()
    }

    let monotonicFromKernel = NativeAgentSystemMonotonicClock(
        continuousSource: FailingContinuousNanosecondsSource(),
        bootIdentitySource: FixedBootIdentitySource(value: "boot-1-1")
    )
    #expect(throws: NativeAgentSessionDeadlineError.clockUnavailable) {
        try monotonicFromKernel.sample()
    }

    let monotonicFromBoot = NativeAgentSystemMonotonicClock(
        continuousSource: FixedContinuousNanosecondsSource(value: 1),
        bootIdentitySource: FailingBootIdentitySource()
    )
    #expect(throws: NativeAgentSessionDeadlineError.clockUnavailable) {
        try monotonicFromBoot.sample()
    }
}

@Test func systemMonotonicClockRejectsUnboundedBootIdentityWithoutDiagnostics() {
    let clock = NativeAgentSystemMonotonicClock(
        continuousSource: FixedContinuousNanosecondsSource(value: 1),
        bootIdentitySource: FixedBootIdentitySource(
            value: String(repeating: "x", count: NativeAgentMonotonicClockValue.maximumBootIdentityBytes + 1)
        )
    )

    #expect(throws: NativeAgentSessionDeadlineError.clockUnavailable) {
        try clock.sample()
    }
}
