import Foundation

/// One serialization boundary for ServiceEndpoint mutable authorization state.
/// Recursive acquisition is deliberate because audit/control helpers are called
/// both as top-level operations and from already-serialized mutation paths.
public final class ServiceAuthorizationGate: @unchecked Sendable {
    private let lockValue = NSRecursiveLock()

    public init() {}

    public func lock() { lockValue.lock() }
    public func unlock() { lockValue.unlock() }

    public func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lockValue.lock()
        defer { lockValue.unlock() }
        return try body()
    }
}
