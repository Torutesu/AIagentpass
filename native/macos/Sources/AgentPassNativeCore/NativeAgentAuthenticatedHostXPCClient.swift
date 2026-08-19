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
        public let usedSignatures: Int

        fileprivate init(response: AgentPassHostPrepareResponse) throws {
            guard response.status == AgentPassHostXPCContract.SessionStatus.prepared.rawValue,
                  (AgentPassHostXPCContract.minimumSignatureBudget...AgentPassHostXPCContract.maximumSignatureBudget).contains(response.maxSignatures),
                  (0...response.maxSignatures).contains(response.usedSignatures) else {
                throw Error.invalidResponse
            }
            self.sessionID = response.sessionID
            self.expiresAtMilliseconds = response.expiresAtMilliseconds
            self.maxSignatures = response.maxSignatures
            self.usedSignatures = response.usedSignatures
        }
    }

    public struct AttachedSession: Equatable, Sendable {
        public let sessionID: String
        public let attachedAtMilliseconds: Int64
        public let maxSignatures: Int
        public let usedSignatures: Int

        fileprivate init(response: AgentPassHostAttachChildResponse) throws {
            guard response.status == AgentPassHostXPCContract.SessionStatus.attached.rawValue,
                  (AgentPassHostXPCContract.minimumSignatureBudget...AgentPassHostXPCContract.maximumSignatureBudget).contains(response.maxSignatures),
                  (0...response.maxSignatures).contains(response.usedSignatures) else {
                throw Error.invalidResponse
            }
            self.sessionID = response.sessionID
            self.attachedAtMilliseconds = response.attachedAtMilliseconds
            self.maxSignatures = response.maxSignatures
            self.usedSignatures = response.usedSignatures
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
            guard (AgentPassHostXPCContract.minimumSignatureBudget...AgentPassHostXPCContract.maximumSignatureBudget).contains(response.maxSignatures),
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
    private var maxSignatures: Int?
    private var usedSignatures: Int?

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
        let prepared: PreparedSession
        do {
            prepared = try PreparedSession(response: response)
        } catch {
            lock.lock()
            state = .closed
            lock.unlock()
            throw error
        }
        lock.lock()
        state = .prepared
        maxSignatures = prepared.maxSignatures
        usedSignatures = prepared.usedSignatures
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
        let attached: AttachedSession
        do {
            attached = try AttachedSession(response: response)
        } catch {
            lock.lock()
            state = .closed
            lock.unlock()
            throw error
        }
        lock.lock()
        guard let maxSignatures,
              let usedSignatures,
              attached.maxSignatures == maxSignatures,
              attached.usedSignatures == usedSignatures else {
            state = .closed
            lock.unlock()
            throw Error.invalidResponse
        }
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
        guard let maxSignatures,
              let usedSignatures,
              usedSignatures < maxSignatures,
              sequence <= UInt32(maxSignatures) else {
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
        lock.lock()
        let priorUsedSignatures = usedSignatures
        let expectedMaxSignatures = maxSignatures
        lock.unlock()
        guard response.responseSequence == sequence,
              response.maxSignatures == expectedMaxSignatures,
              response.usedSignatures > priorUsedSignatures,
              response.usedSignatures <= response.maxSignatures,
              response.remainingSignatures == response.maxSignatures - response.usedSignatures,
              !response.signature.isEmpty,
              response.signature.count <= AgentPassHostXPCContract.maximumSignatureBytes else {
            lock.lock()
            state = .closed
            lock.unlock()
            throw Error.invalidResponse
        }
        lock.lock()
        self.usedSignatures = response.usedSignatures
        lock.unlock()
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
        let status: Status
        do {
            status = try Status(response: response)
        } catch {
            lock.lock()
            state = .closed
            lock.unlock()
            throw error
        }
        lock.lock()
        guard let maxSignatures,
              let usedSignatures,
              status.maxSignatures == maxSignatures,
              status.usedSignatures >= usedSignatures else {
            state = .closed
            lock.unlock()
            throw Error.invalidResponse
        }
        self.usedSignatures = status.usedSignatures
        lock.unlock()
        return status
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

extension NativeAgentAuthenticatedHostXPCClient: NativeAgentHostAuthenticatedXPCClientProtocol {
    func prepareForChild(launchNonce: Data) throws {
        _ = try prepare(launchNonce: launchNonce)
    }

    func attachForChild(
        childPID: Int,
        childPIDVersion: Int64,
        executableIdentityDigest: Data,
        ancestryBindingDigest: Data,
        worktreeBindingDigest: Data
    ) throws {
        _ = try attach(
            childPID: childPID,
            childPIDVersion: childPIDVersion,
            executableIdentityDigest: executableIdentityDigest,
            ancestryBindingDigest: ancestryBindingDigest,
            worktreeBindingDigest: worktreeBindingDigest
        )
    }

    func closeForChild(reason: AgentPassHostXPCContract.CloseReason) throws {
        try close(reason: reason)
    }
}
