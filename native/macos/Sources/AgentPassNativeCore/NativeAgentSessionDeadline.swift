import Foundation

/// Time primitives for a process-bound Agent session.
///
/// This file intentionally has no dependency on `Date`.  The wall-clock
/// value is captured as an integer at the trust boundary and the live
/// decision thereafter uses only the captured integer and monotonic samples.

public enum NativeAgentSessionDeadlineError: String, Error, Equatable, Sendable, Codable, CaseIterable {
    case invalidWallClockEvidence = "invalid_wall_clock_evidence"
    case invalidMonotonicEvidence = "invalid_monotonic_evidence"
    case clockUnavailable = "clock_unavailable"
    case invalidSignedWallExpiry = "invalid_signed_wall_expiry"
    case deadlineOverflow = "deadline_overflow"
    case wallClockRollback = "wall_clock_rollback"
    case monotonicClockRollback = "monotonic_clock_rollback"
    case monotonicBootChanged = "monotonic_boot_changed"
    case wallClockExpired = "wall_clock_expired"
    case monotonicDeadlineExpired = "monotonic_deadline_expired"
}

extension NativeAgentSessionDeadlineError: LocalizedError {
    public var errorDescription: String? { rawValue }
}

/// A wall-clock sample captured at the boundary where a signed expiry is
/// checked.  Milliseconds are used consistently with the native session and
/// capability contracts; no floating-point or Foundation `Date` conversion
/// is permitted in the decision path.
public struct NativeAgentWallClockValue: Codable, Equatable, Hashable, Sendable {
    public let millisecondsSinceUnixEpoch: Int64

    public init(millisecondsSinceUnixEpoch: Int64) {
        self.millisecondsSinceUnixEpoch = millisecondsSinceUnixEpoch
    }
}

/// A monotonic sample must carry a boot identity.  Numeric uptime alone is
/// insufficient because it can repeat after a reboot, which could otherwise
/// make a previously issued deadline appear live again.
public struct NativeAgentMonotonicClockValue: Codable, Equatable, Hashable, Sendable {
    public static let maximumBootIdentityBytes = 256

    public let nanoseconds: UInt64
    public let bootIdentity: String

    public init(nanoseconds: UInt64, bootIdentity: String) throws {
        let byteCount = bootIdentity.utf8.count
        guard !bootIdentity.isEmpty,
              byteCount <= Self.maximumBootIdentityBytes,
              !bootIdentity.unicodeScalars.contains(where: { $0.value == 0 }) else {
            throw NativeAgentSessionDeadlineError.invalidMonotonicEvidence
        }
        self.nanoseconds = nanoseconds
        self.bootIdentity = bootIdentity
    }
}

/// Production clocks and deterministic test clocks implement these small
/// interfaces.  Clock implementation failures are deliberately hidden behind
/// the stable `clockUnavailable` error by the deadline boundary.
public protocol NativeAgentWallClock: Sendable {
    func sample() throws -> NativeAgentWallClockValue
}

public protocol NativeAgentMonotonicClock: Sendable {
    func sample() throws -> NativeAgentMonotonicClockValue
}

/// The result of one successful live check.  Both remaining values are
/// strictly positive.  They are observations only; callers cannot use them
/// to extend the stored deadline.
public struct NativeAgentSessionDeadlineValidation: Codable, Equatable, Hashable, Sendable {
    public let wallMillisecondsRemaining: UInt64
    public let monotonicNanosecondsRemaining: UInt64

    internal init(wallMillisecondsRemaining: UInt64, monotonicNanosecondsRemaining: UInt64) {
        self.wallMillisecondsRemaining = wallMillisecondsRemaining
        self.monotonicNanosecondsRemaining = monotonicNanosecondsRemaining
    }
}

/// A session's time boundary captured at activation.
///
/// The monotonic deadline is derived once from the signed wall expiry and the
/// activation samples.  Revalidation only checks the two fixed boundaries and
/// records a high-water mark for rollback detection.  It never re-anchors or
/// recomputes a deadline from a later wall-clock reading.
public struct NativeAgentSessionDeadline: Equatable, Sendable {
    public let signedWallExpiryMilliseconds: Int64
    public let activationWallClock: NativeAgentWallClockValue
    public let activationMonotonicClock: NativeAgentMonotonicClockValue
    public let monotonicDeadlineNanoseconds: UInt64

    private var lastObservedWallClock: NativeAgentWallClockValue
    private var lastObservedMonotonicClock: NativeAgentMonotonicClockValue

    /// Activates a deadline from already-captured clock values.
    ///
    /// The signed expiry must be strictly after activation.  The wall-clock
    /// delta is converted with checked arithmetic and added to the monotonic
    /// sample with checked arithmetic; an unrepresentable deadline is denied.
    public init(
        signedWallExpiryMilliseconds: Int64,
        wallClock: NativeAgentWallClockValue,
        monotonicClock: NativeAgentMonotonicClockValue
    ) throws {
        guard wallClock.millisecondsSinceUnixEpoch >= 0 else {
            throw NativeAgentSessionDeadlineError.invalidWallClockEvidence
        }
        guard signedWallExpiryMilliseconds > wallClock.millisecondsSinceUnixEpoch else {
            throw NativeAgentSessionDeadlineError.invalidSignedWallExpiry
        }

        let (wallDeltaMilliseconds, subtractionOverflow) = signedWallExpiryMilliseconds.subtractingReportingOverflow(wallClock.millisecondsSinceUnixEpoch)
        guard !subtractionOverflow, wallDeltaMilliseconds > 0 else {
            throw NativeAgentSessionDeadlineError.deadlineOverflow
        }

        let (wallDeltaNanoseconds, multiplicationOverflow) = UInt64(wallDeltaMilliseconds).multipliedReportingOverflow(by: 1_000_000)
        guard !multiplicationOverflow, wallDeltaNanoseconds > 0 else {
            throw NativeAgentSessionDeadlineError.deadlineOverflow
        }

        let (deadline, additionOverflow) = monotonicClock.nanoseconds.addingReportingOverflow(wallDeltaNanoseconds)
        guard !additionOverflow, deadline > monotonicClock.nanoseconds else {
            throw NativeAgentSessionDeadlineError.deadlineOverflow
        }

        self.signedWallExpiryMilliseconds = signedWallExpiryMilliseconds
        self.activationWallClock = wallClock
        self.activationMonotonicClock = monotonicClock
        self.monotonicDeadlineNanoseconds = deadline
        self.lastObservedWallClock = wallClock
        self.lastObservedMonotonicClock = monotonicClock
    }

    /// Activates a deadline by sampling injectable clocks exactly once each.
    public init(
        signedWallExpiryMilliseconds: Int64,
        wallClock: any NativeAgentWallClock,
        monotonicClock: any NativeAgentMonotonicClock
    ) throws {
        do {
            // Capture monotonic time first and wall time second.  The fixed
            // deadline is therefore biased toward being shorter by the
            // capture interval, never longer.
            let monotonicSample = try monotonicClock.sample()
            let wallSample = try wallClock.sample()
            try self.init(
                signedWallExpiryMilliseconds: signedWallExpiryMilliseconds,
                wallClock: wallSample,
                monotonicClock: monotonicSample
            )
        } catch let error as NativeAgentSessionDeadlineError {
            throw error
        } catch {
            throw NativeAgentSessionDeadlineError.clockUnavailable
        }
    }

    /// Revalidates against already-captured values.  State is advanced only
    /// after every check succeeds, so a rejected rollback cannot be used as a
    /// new baseline.
    @discardableResult
    public mutating func revalidate(
        wallClock: NativeAgentWallClockValue,
        monotonicClock: NativeAgentMonotonicClockValue
    ) throws -> NativeAgentSessionDeadlineValidation {
        guard wallClock.millisecondsSinceUnixEpoch >= 0 else {
            throw NativeAgentSessionDeadlineError.invalidWallClockEvidence
        }
        guard monotonicClock.bootIdentity == activationMonotonicClock.bootIdentity else {
            throw NativeAgentSessionDeadlineError.monotonicBootChanged
        }
        guard wallClock.millisecondsSinceUnixEpoch >= lastObservedWallClock.millisecondsSinceUnixEpoch else {
            throw NativeAgentSessionDeadlineError.wallClockRollback
        }
        guard monotonicClock.nanoseconds >= lastObservedMonotonicClock.nanoseconds else {
            throw NativeAgentSessionDeadlineError.monotonicClockRollback
        }
        guard wallClock.millisecondsSinceUnixEpoch < signedWallExpiryMilliseconds else {
            throw NativeAgentSessionDeadlineError.wallClockExpired
        }
        guard monotonicClock.nanoseconds < monotonicDeadlineNanoseconds else {
            throw NativeAgentSessionDeadlineError.monotonicDeadlineExpired
        }

        let (wallRemaining, wallSubtractionOverflow) = signedWallExpiryMilliseconds.subtractingReportingOverflow(wallClock.millisecondsSinceUnixEpoch)
        let (monotonicRemaining, monotonicSubtractionOverflow) = monotonicDeadlineNanoseconds.subtractingReportingOverflow(monotonicClock.nanoseconds)
        guard !wallSubtractionOverflow, wallRemaining > 0,
              !monotonicSubtractionOverflow, monotonicRemaining > 0 else {
            throw NativeAgentSessionDeadlineError.deadlineOverflow
        }

        lastObservedWallClock = wallClock
        lastObservedMonotonicClock = monotonicClock
        return NativeAgentSessionDeadlineValidation(
            wallMillisecondsRemaining: UInt64(wallRemaining),
            monotonicNanosecondsRemaining: monotonicRemaining
        )
    }

    /// Revalidates by sampling injectable clocks exactly once each.
    @discardableResult
    public mutating func revalidate(
        wallClock: any NativeAgentWallClock,
        monotonicClock: any NativeAgentMonotonicClock
    ) throws -> NativeAgentSessionDeadlineValidation {
        do {
            // The fixed deadline makes either order safe during revalidation;
            // retain the same conservative sampling order as activation.
            let monotonicSample = try monotonicClock.sample()
            let wallSample = try wallClock.sample()
            return try revalidate(wallClock: wallSample, monotonicClock: monotonicSample)
        } catch let error as NativeAgentSessionDeadlineError {
            throw error
        } catch {
            throw NativeAgentSessionDeadlineError.clockUnavailable
        }
    }
}
