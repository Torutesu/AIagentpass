import Foundation

public struct NativeControlRetrySchedule: Equatable, Sendable {
    public let refreshSeconds: Int
    public private(set) var consecutiveFailures = 0

    public init(refreshSeconds: Int) throws {
        guard (15...3600).contains(refreshSeconds) else {
            throw AgentPassNativeError.invalidConfiguration("Native control retry schedule requires a 15-3600 second interval")
        }
        self.refreshSeconds = refreshSeconds
    }

    public mutating func successDelay(randomUnit: Double) -> TimeInterval {
        consecutiveFailures = 0
        let unit = Self.bounded(randomUnit)
        return Double(refreshSeconds) * (0.9 + (0.1 * unit))
    }

    public mutating func failureDelay(randomUnit: Double) -> TimeInterval {
        consecutiveFailures = min(consecutiveFailures + 1, 31)
        let exponent = min(consecutiveFailures - 1, 20)
        let backoff = min(refreshSeconds, 5 * (1 << exponent))
        let unit = Self.bounded(randomUnit)
        return max(1, Double(backoff) * (0.75 + (0.25 * unit)))
    }

    private static func bounded(_ value: Double) -> Double {
        guard value.isFinite else { return 0 }
        return min(1, max(0, value))
    }
}
