import Foundation

/// The only signature budget that may be used by the dedicated Host/Child
/// surfaces.  The values are a projection of the already verified Cloud
/// lease; they are never accepted from an XPC request.
public struct NativeAgentSignatureBudget: Equatable, Sendable {
    public static let minimumSignatures = 1
    public static let maximumSignatures = NativeAgentLeaseCodec.maximumSignatureBudget

    public let maxSignatures: Int
    public let usedSignatures: Int

    public init(maxSignatures: Int, usedSignatures: Int) throws {
        guard (Self.minimumSignatures...Self.maximumSignatures).contains(maxSignatures),
              (0...maxSignatures).contains(usedSignatures) else {
            throw NativeAgentSignatureBudgetError.invalidBudget
        }
        self.maxSignatures = maxSignatures
        self.usedSignatures = usedSignatures
    }

    public var remainingSignatures: Int { maxSignatures - usedSignatures }
}

public enum NativeAgentSignatureBudgetError: String, Error, Equatable, Sendable {
    case invalidBudget = "invalid_budget"
    case exhausted = "budget_exhausted"
}

/// Atomic local projection of the Cloud budget shared by the Host and Child
/// XPC endpoints for one authenticated session.  A reservation is consumed
/// before signer invocation and is never returned: a signer failure therefore
/// closes the session instead of permitting an ambiguous retry to exceed the
/// Cloud allowance.
public final class NativeAgentSignatureBudgetLedger: @unchecked Sendable {
    public struct Snapshot: Equatable, Sendable {
        public let maxSignatures: Int
        public let usedSignatures: Int
        public let remainingSignatures: Int
    }

    private let lock = NSLock()
    private let maxSignatures: Int
    private var usedSignatures: Int

    public init(_ budget: NativeAgentSignatureBudget) {
        self.maxSignatures = budget.maxSignatures
        self.usedSignatures = budget.usedSignatures
    }

    public func snapshot() -> Snapshot {
        lock.lock()
        defer { lock.unlock() }
        return snapshotUnlocked()
    }

    /// Atomically reserves exactly one Cloud-authorized signature.
    @discardableResult
    public func reserve() throws -> Snapshot {
        lock.lock()
        defer { lock.unlock() }
        guard usedSignatures < maxSignatures else {
            throw NativeAgentSignatureBudgetError.exhausted
        }
        usedSignatures += 1
        return snapshotUnlocked()
    }

    private func snapshotUnlocked() -> Snapshot {
        Snapshot(
            maxSignatures: maxSignatures,
            usedSignatures: usedSignatures,
            remainingSignatures: maxSignatures - usedSignatures
        )
    }
}
