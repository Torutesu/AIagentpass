import Darwin
import Foundation

/// The only failure exposed by the system clock adapters.
///
/// The deadline boundary has its own stable error value.  The adapters map
/// every kernel, conversion, and validation failure to that value so that
/// errno, sysctl status, and other platform diagnostics never cross the
/// authority boundary.
private let nativeAgentClockUnavailable = NativeAgentSessionDeadlineError.clockUnavailable

/// A small injection point below the public deadline protocols.  Keeping the
/// kernel-facing values primitive makes deterministic tests possible without
/// replacing the production `NativeAgentWallClock` / `NativeAgentMonotonicClock`
/// contracts.
internal protocol NativeAgentWallMillisecondsSource: Sendable {
    func sampleWallMilliseconds() throws -> Int64
}

internal protocol NativeAgentContinuousNanosecondsSource: Sendable {
    func sampleContinuousNanoseconds() throws -> UInt64
}

internal protocol NativeAgentBootIdentitySource: Sendable {
    func sampleBootIdentity() throws -> String
}

private struct NativeAgentDarwinWallMillisecondsSource: NativeAgentWallMillisecondsSource {
    func sampleWallMilliseconds() throws -> Int64 {
        var value = timespec()
        guard clock_gettime(CLOCK_REALTIME, &value) == 0 else {
            throw nativeAgentClockUnavailable
        }

        guard let seconds = Int64(exactly: value.tv_sec),
              let nanoseconds = Int64(exactly: value.tv_nsec),
              (0..<1_000_000_000).contains(nanoseconds) else {
            throw nativeAgentClockUnavailable
        }

        // Convert without floating point.  Both operations are checked so a
        // malformed or future kernel value cannot wrap into an earlier time.
        let (wholeMilliseconds, secondsOverflow) = seconds.multipliedReportingOverflow(by: 1_000)
        guard !secondsOverflow else {
            throw nativeAgentClockUnavailable
        }
        let fractionMilliseconds = nanoseconds / 1_000_000
        let (milliseconds, fractionOverflow) = wholeMilliseconds.addingReportingOverflow(fractionMilliseconds)
        guard !fractionOverflow else {
            throw nativeAgentClockUnavailable
        }
        return milliseconds
    }
}

private struct NativeAgentDarwinContinuousNanosecondsSource: NativeAgentContinuousNanosecondsSource {
    func sampleContinuousNanoseconds() throws -> UInt64 {
        // mach_continuous_time is a kernel monotonic clock that continues
        // across system sleep.  This is important for a session deadline:
        // waking from sleep must not re-anchor or extend authority.
        let ticks = mach_continuous_time()
        var timebase = mach_timebase_info_data_t()
        guard mach_timebase_info(&timebase) == KERN_SUCCESS,
              timebase.numer > 0,
              timebase.denom > 0 else {
            throw nativeAgentClockUnavailable
        }

        let numerator = UInt64(timebase.numer)
        let denominator = UInt64(timebase.denom)

        // Compute floor(ticks * numer / denom) without an overflowing
        // intermediate multiplication.  The final result is deliberately
        // bounded by UInt64 and failure is treated as unavailable.
        let quotient = ticks / denominator
        let remainder = ticks % denominator
        let (wholeNanoseconds, wholeOverflow) = quotient.multipliedReportingOverflow(by: numerator)
        guard !wholeOverflow else {
            throw nativeAgentClockUnavailable
        }
        let (remainderProduct, remainderOverflow) = remainder.multipliedReportingOverflow(by: numerator)
        guard !remainderOverflow else {
            throw nativeAgentClockUnavailable
        }
        let fractionalNanoseconds = remainderProduct / denominator
        let (nanoseconds, resultOverflow) = wholeNanoseconds.addingReportingOverflow(fractionalNanoseconds)
        guard !resultOverflow else {
            throw nativeAgentClockUnavailable
        }
        return nanoseconds
    }
}

private struct NativeAgentDarwinBootIdentitySource: NativeAgentBootIdentitySource {
    func sampleBootIdentity() throws -> String {
        // Use the same kernel boot-session UUID as process observation. Unlike
        // a wall-derived boot timestamp, this identity is not shifted by time
        // correction and changes only when the boot session changes.
        var length = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &length, nil, 0) == 0,
              length > 1,
              length <= NativeAgentMonotonicClockValue.maximumBootIdentityBytes else {
            throw nativeAgentClockUnavailable
        }
        let capacity = length
        var bytes = [CChar](repeating: 0, count: capacity)
        guard sysctlbyname("kern.bootsessionuuid", &bytes, &length, nil, 0) == 0,
              length > 1,
              length <= capacity,
              bytes[length - 1] == 0 else {
            throw nativeAgentClockUnavailable
        }
        let identityBytes = bytes[..<(length - 1)].map { UInt8(bitPattern: $0) }
        let identity = String(decoding: identityBytes, as: UTF8.self).lowercased()
        guard identity.utf8.count == 36, UUID(uuidString: identity)?.uuidString.lowercased() == identity else {
            throw nativeAgentClockUnavailable
        }
        return identity
    }
}

/// A production wall clock backed directly by the Darwin realtime kernel
/// clock.  It captures only integer milliseconds; no `Date` is involved.
public struct NativeAgentSystemWallClock: NativeAgentWallClock, Sendable {
    private let source: any NativeAgentWallMillisecondsSource

    public init() {
        self.source = NativeAgentDarwinWallMillisecondsSource()
    }

    internal init(source: any NativeAgentWallMillisecondsSource) {
        self.source = source
    }

    public func sample() throws -> NativeAgentWallClockValue {
        do {
            let milliseconds = try source.sampleWallMilliseconds()
            guard milliseconds >= 0 else { throw nativeAgentClockUnavailable }
            return NativeAgentWallClockValue(millisecondsSinceUnixEpoch: milliseconds)
        } catch {
            throw nativeAgentClockUnavailable
        }
    }
}

/// A production monotonic clock backed by Darwin's continuous kernel clock and
/// a per-sample kernel boot identity.
public struct NativeAgentSystemMonotonicClock: NativeAgentMonotonicClock, Sendable {
    private let continuousSource: any NativeAgentContinuousNanosecondsSource
    private let bootIdentitySource: any NativeAgentBootIdentitySource

    public init() {
        self.continuousSource = NativeAgentDarwinContinuousNanosecondsSource()
        self.bootIdentitySource = NativeAgentDarwinBootIdentitySource()
    }

    internal init(
        continuousSource: any NativeAgentContinuousNanosecondsSource,
        bootIdentitySource: any NativeAgentBootIdentitySource
    ) {
        self.continuousSource = continuousSource
        self.bootIdentitySource = bootIdentitySource
    }

    public func sample() throws -> NativeAgentMonotonicClockValue {
        do {
            let nanoseconds = try continuousSource.sampleContinuousNanoseconds()
            let bootIdentity = try bootIdentitySource.sampleBootIdentity()
            return try NativeAgentMonotonicClockValue(
                nanoseconds: nanoseconds,
                bootIdentity: bootIdentity
            )
        } catch {
            throw nativeAgentClockUnavailable
        }
    }
}

/// Convenience pair for call sites that activate and revalidate a deadline.
public struct NativeAgentSystemClocks: Sendable {
    public let wallClock: NativeAgentSystemWallClock
    public let monotonicClock: NativeAgentSystemMonotonicClock

    public init() {
        self.wallClock = NativeAgentSystemWallClock()
        self.monotonicClock = NativeAgentSystemMonotonicClock()
    }
}
