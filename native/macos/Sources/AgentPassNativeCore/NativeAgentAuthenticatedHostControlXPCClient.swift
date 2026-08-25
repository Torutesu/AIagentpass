import Foundation

/// Client for the dedicated Host control Mach service. The client carries no
/// token, PID, file path, inherited descriptor, or signing authority. A
/// caller that loses the reply retries the same operation ID; the service
/// returns the recorded terminal response only for that exact operation
/// fingerprint.
public final class NativeAgentAuthenticatedHostControlXPCClient: @unchecked Sendable {
    public enum Error: Swift.Error, Equatable, Sendable {
        case invalidRequest
        case invalidResponse
        case connectionFailed
        case remoteRejected
        case controlUnavailable
        case controlPeerMismatch
        case controlReplay
        case controlInProgress
        case controlSessionMissing
        case timeout
    }

    public struct CloseResult: Equatable, Sendable {
        public let operationID: String
        public let sessionID: String
        public let closedAtMilliseconds: Int64

        fileprivate init(response: AgentPassHostControlCloseResponse) throws {
            guard response.status == AgentPassHostXPCContract.SessionStatus.closed.rawValue,
                  AgentPassHostXPCContract.canonicalUUID(response.operationID) != nil,
                  AgentPassHostXPCContract.canonicalUUID(response.sessionID) != nil,
                  AgentPassHostXPCContract.isTimestamp(response.closedAtMilliseconds) else {
                throw Error.invalidResponse
            }
            self.operationID = response.operationID
            self.sessionID = response.sessionID
            self.closedAtMilliseconds = response.closedAtMilliseconds
        }
    }

    public static let defaultMachServiceName = AgentPassHostControlXPCContract.machServiceName
    public static let defaultTimeout: DispatchTimeInterval = .seconds(5)

    private let connection: NSXPCConnection
    private let timeout: DispatchTimeInterval

    public init(
        machServiceName: String = NativeAgentAuthenticatedHostControlXPCClient.defaultMachServiceName,
        timeout: DispatchTimeInterval = NativeAgentAuthenticatedHostControlXPCClient.defaultTimeout
    ) {
        self.connection = NSXPCConnection(machServiceName: machServiceName, options: .privileged)
        self.timeout = timeout
        connection.remoteObjectInterface = AgentPassHostControlXPCInterface.make()
        connection.resume()
    }

    deinit {
        connection.invalidate()
    }

    /// Creates a fresh idempotency key in memory. It is not authority and
    /// must not be persisted or placed in process arguments/environment.
    public static func makeOperationID() -> String {
        UUID().uuidString.lowercased()
    }

    /// Closes a Host session from another process. On timeout, call this
    /// method again with the same `operationID` to converge safely.
    public func close(
        sessionID: String,
        operationID: String,
        reason: AgentPassHostXPCContract.CloseReason = .clientShutdown
    ) throws -> CloseResult {
        guard let request = AgentPassHostControlCloseRequest(
            sessionID: sessionID,
            operationID: operationID,
            reason: reason
        ) else {
            throw Error.invalidRequest
        }
        let response: AgentPassHostControlCloseResponse = try invoke { proxy, reply in
            proxy.closeHostSessionFromControl(request, withReply: reply)
        }
        guard response.operationID == request.operationID,
              response.sessionID == request.sessionID else {
            throw Error.invalidResponse
        }
        return try CloseResult(response: response)
    }

    private func invoke<T>(
        _ body: (AgentPassHostControlXPCProtocol, @escaping (T?, NSError?) -> Void) -> Void
    ) throws -> T {
        let lock = NSLock()
        let semaphore = DispatchSemaphore(value: 0)
        var result: T?
        var failed = false
        var remoteError: NSError?
        let proxy = connection.remoteObjectProxyWithErrorHandler { error in
            lock.lock()
            if result == nil {
                failed = true
                remoteError = error as NSError
                semaphore.signal()
            }
            lock.unlock()
        } as! AgentPassHostControlXPCProtocol
        body(proxy) { value, error in
            lock.lock()
            if result == nil {
                result = value
                failed = value == nil
                if value == nil { remoteError = error }
                semaphore.signal()
            }
            lock.unlock()
        }
        guard semaphore.wait(timeout: .now() + timeout) == .success else {
            connection.invalidate()
            throw Error.timeout
        }
        lock.lock()
        defer { lock.unlock() }
        if failed { throw Self.mapRemoteError(remoteError) }
        guard let result else { throw Error.remoteRejected }
        return result
    }

    private static func mapRemoteError(_ error: NSError?) -> Error {
        guard error?.domain == "com.agentpass.native-authenticated-host-control" else {
            return .remoteRejected
        }
        switch error?.code {
        case 1: return .controlUnavailable
        case 2: return .controlPeerMismatch
        case 3: return .controlReplay
        case 4: return .controlInProgress
        case 5: return .controlSessionMissing
        default: return .remoteRejected
        }
    }
}
