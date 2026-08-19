import Foundation

/// Connection-owned client for the dedicated Host XPC surface.
///
/// The client deliberately keeps the service-assigned session identity out of
/// every request. It is held only as connection state, so a request copied to
/// another connection cannot be replayed successfully. There is no FD3 or
/// local signing fallback in this type.
public final class NativeAgentAuthenticatedHostXPCClient: @unchecked Sendable {
    public enum Error: Swift.Error, Equatable, Sendable {
        case invalidState
        case invalidRequest
        case connectionFailed
        case remoteRejected
        case timeout
        case invalidResponse
    }

    public struct PreparedSession: Equatable, Sendable {
        public let sessionID: String
        public let expiresAtMilliseconds: Int64
        public let maxSignatures: Int

        fileprivate init(response: AgentPassHostPrepareResponse) throws {
            guard response.status == AgentPassHostXPCContract.SessionStatus.prepared.rawValue,
                  response.maxSignatures == AgentPassHostXPCContract.fixedSignatureBudget else {
                throw Error.invalidResponse
            }
            self.sessionID = response.sessionID
            self.expiresAtMilliseconds = response.expiresAtMilliseconds
            self.maxSignatures = response.maxSignatures
        }
    }

    public struct AttachedSession: Equatable, Sendable {
        public let sessionID: String
        public let attachedAtMilliseconds: Int64
        public let maxSignatures: Int

        fileprivate init(response: AgentPassHostAttachChildResponse) throws {
            guard response.status == AgentPassHostXPCContract.SessionStatus.attached.rawValue,
                  response.maxSignatures == AgentPassHostXPCContract.fixedSignatureBudget else {
                throw Error.invalidResponse
            }
            self.sessionID = response.sessionID
            self.attachedAtMilliseconds = response.attachedAtMilliseconds
            self.maxSignatures = response.maxSignatures
        }
    }

    public struct Status: Equatable, Sendable {
        public let sessionID: String
        public let status: String
        public let expiresAtMilliseconds: Int64
        public let maxSignatures: Int
        public let usedSignatures: Int
        public let childAttached: Bool

        fileprivate init(response: AgentPassHostStatusResponse) throws {
            guard response.maxSignatures == AgentPassHostXPCContract.fixedSignatureBudget,
                  (0...response.maxSignatures).contains(response.usedSignatures) else {
                throw Error.invalidResponse
            }
            self.sessionID = response.sessionID
            self.status = response.status
            self.expiresAtMilliseconds = response.expiresAtMilliseconds
            self.maxSignatures = response.maxSignatures
            self.usedSignatures = response.usedSignatures
            self.childAttached = response.childAttached
        }
    }

    public static let defaultMachServiceName = "dev.agentpass.agent-host"
    public static let defaultTimeout: DispatchTimeInterval = .seconds(5)

    private enum State {
        case new
        case prepared
        case attached
        case closed
    }

    private let connection: NSXPCConnection
    private let timeout: DispatchTimeInterval
    private let lock = NSLock()
    private var state: State = .new
    private var nextRequestSequence: UInt32 = 1

    public init(
        machServiceName: String = NativeAgentAuthenticatedHostXPCClient.defaultMachServiceName,
        timeout: DispatchTimeInterval = NativeAgentAuthenticatedHostXPCClient.defaultTimeout
    ) {
        self.connection = NSXPCConnection(machServiceName: machServiceName)
        self.timeout = timeout
        connection.remoteObjectInterface = AgentPassHostXPCInterface.make()
        connection.resume()
    }

    deinit {
        connection.invalidate()
    }

    public func prepare(launchNonce: Data) throws -> PreparedSession {
        lock.lock()
        guard state == .new else {
            lock.unlock()
            throw Error.invalidState
        }
        lock.unlock()
        guard let request = AgentPassHostPrepareRequest(launchNonce: launchNonce) else {
            throw Error.invalidRequest
        }
        let response: AgentPassHostPrepareResponse = try invoke { proxy, reply in
            proxy.prepareHostSession(request, withReply: reply)
        }
        let prepared = try PreparedSession(response: response)
        lock.lock()
        state = .prepared
        lock.unlock()
        return prepared
    }

    public func attach(
        childPID: Int,
        childPIDVersion: Int64,
        executableIdentityDigest: Data,
        ancestryBindingDigest: Data,
        worktreeBindingDigest: Data
    ) throws -> AttachedSession {
        lock.lock()
        guard state == .prepared else {
            lock.unlock()
            throw Error.invalidState
        }
        lock.unlock()
        guard let request = AgentPassHostAttachChildRequest(
            childPID: childPID,
            childPIDVersion: childPIDVersion,
            executableIdentityDigest: executableIdentityDigest,
            ancestryBindingDigest: ancestryBindingDigest,
            worktreeBindingDigest: worktreeBindingDigest
        ) else {
            throw Error.invalidRequest
        }
        let response: AgentPassHostAttachChildResponse = try invoke { proxy, reply in
            proxy.attachHostChild(request, withReply: reply)
        }
        let attached = try AttachedSession(response: response)
        lock.lock()
        state = .attached
        lock.unlock()
        return attached
    }

    public func sign(payload: Data) throws -> (signature: Data, remainingSignatures: Int) {
        lock.lock()
        guard state == .attached else {
            lock.unlock()
            throw Error.invalidState
        }
        let sequence = nextRequestSequence
        guard sequence <= UInt32(AgentPassHostXPCContract.fixedSignatureBudget) else {
            lock.unlock()
            throw Error.invalidState
        }
        nextRequestSequence += 1
        lock.unlock()
        guard let request = AgentPassHostSignRequest(requestSequence: sequence, commitPayload: payload) else {
            throw Error.invalidRequest
        }
        let response: AgentPassHostSignResponse = try invoke { proxy, reply in
            proxy.signHostPayload(request, withReply: reply)
        }
        guard response.responseSequence == sequence,
              response.remainingSignatures >= 0,
              response.remainingSignatures <= AgentPassHostXPCContract.fixedSignatureBudget,
              !response.signature.isEmpty,
              response.signature.count <= AgentPassHostXPCContract.maximumSignatureBytes else {
            throw Error.invalidResponse
        }
        return (response.signature, response.remainingSignatures)
    }

    public func status() throws -> Status {
        lock.lock()
        guard state == .attached || state == .prepared else {
            lock.unlock()
            throw Error.invalidState
        }
        lock.unlock()
        guard let request = AgentPassHostStatusRequest() else { throw Error.invalidRequest }
        let response: AgentPassHostStatusResponse = try invoke { proxy, reply in
            proxy.hostSessionStatus(request, withReply: reply)
        }
        return try Status(response: response)
    }

    public func close(reason: AgentPassHostXPCContract.CloseReason = .clientShutdown) throws {
        lock.lock()
        guard state != .closed else {
            lock.unlock()
            return
        }
        state = .closed
        lock.unlock()
        guard let request = AgentPassHostCloseRequest(reason: reason) else {
            throw Error.invalidRequest
        }
        _ = try invoke { proxy, reply in
            proxy.closeHostSession(request, withReply: reply)
        } as AgentPassHostCloseResponse
    }

    private func invoke<T>(
        _ body: (AgentPassHostXPCProtocol, @escaping (T?, NSError?) -> Void) -> Void
    ) throws -> T {
        let proxy = try proxy()
        let lock = NSLock()
        let semaphore = DispatchSemaphore(value: 0)
        var result: T?
        var failed = false
        body(proxy) { value, _ in
            lock.lock()
            if result == nil {
                result = value
                failed = value == nil
                semaphore.signal()
            }
            lock.unlock()
        }
        guard semaphore.wait(timeout: .now() + timeout) == .success else {
            throw Error.timeout
        }
        lock.lock()
        let value = result
        let didFail = failed
        lock.unlock()
        guard !didFail, let value else { throw Error.remoteRejected }
        return value
    }

    private func proxy() throws -> AgentPassHostXPCProtocol {
        connection.remoteObjectProxyWithErrorHandler { _ in } as! AgentPassHostXPCProtocol
    }
}
