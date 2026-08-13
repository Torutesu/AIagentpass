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

@Test func systemMonotonicClockPreservesBoundedNanosecondsAndIdentity() throws {
    let clock = NativeAgentSystemMonotonicClock(
        continuousSource: FixedContinuousNanosecondsSource(value: UInt64.max),
        bootIdentitySource: FixedBootIdentitySource(value: "boot-123-456")
    )

    let sample = try clock.sample()
    #expect(sample.nanoseconds == UInt64.max)
    #expect(sample.bootIdentity == "boot-123-456")
    #expect(sample.bootIdentity.utf8.count <= NativeAgentMonotonicClockValue.maximumBootIdentityBytes)
}

@Test func systemMonotonicClockExposesBootChangesToDeadlineContract() throws {
    let first = NativeAgentSystemMonotonicClock(
        continuousSource: FixedContinuousNanosecondsSource(value: 10),
        bootIdentitySource: FixedBootIdentitySource(value: "boot-1-1")
    )
    let afterBoot = NativeAgentSystemMonotonicClock(
        continuousSource: FixedContinuousNanosecondsSource(value: 10),
        bootIdentitySource: FixedBootIdentitySource(value: "boot-2-1")
    )

    let firstSample = try first.sample()
    let secondSample = try afterBoot.sample()
    #expect(firstSample.bootIdentity != secondSample.bootIdentity)

    var deadline = try NativeAgentSessionDeadline(
        signedWallExpiryMilliseconds: 1_000_100,
        wallClock: NativeAgentWallClockValue(millisecondsSinceUnixEpoch: 1_000_000),
        monotonicClock: firstSample
    )
    #expect(throws: NativeAgentSessionDeadlineError.monotonicBootChanged) {
        try deadline.revalidate(
            wallClock: NativeAgentWallClockValue(millisecondsSinceUnixEpoch: 1_000_001),
            monotonicClock: secondSample
        )
    }
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
