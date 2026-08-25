import AgentPassNativeCore
import Foundation

/// Connection-owned lifecycle state for the Generic Agent endpoint.
///
/// The state transition is separate from actual Service cleanup so the NSXPC
/// invalidation callback and an in-flight authorization failure share one
/// idempotent terminal boundary without recursively invalidating the
/// connection. Installing a binding after termination is rejected.
internal final class NativeAgentConnectionTerminationState: @unchecked Sendable {
    internal struct CleanupPlan: Sendable {
        let shouldCleanup: Bool
        let binding: NativeAgentSessionBinding?
    }

    private let lock = NSLock()
    private var terminated = false
    private var binding: NativeAgentSessionBinding?

    @discardableResult
    internal func install(_ binding: NativeAgentSessionBinding) -> Bool {
        lock.withLock {
            guard !terminated, self.binding == nil else { return false }
            self.binding = binding
            return true
        }
    }

    internal func takeInstalledBinding() -> NativeAgentSessionBinding? {
        lock.withLock {
            defer { binding = nil }
            return binding
        }
    }

    internal func beginCleanup() -> CleanupPlan {
        lock.withLock {
            guard !terminated else {
                return CleanupPlan(shouldCleanup: false, binding: nil)
            }
            terminated = true
            defer { binding = nil }
            return CleanupPlan(shouldCleanup: true, binding: binding)
        }
    }
}
