import Foundation

/// One-shot child-side client. It admits the Git helper on the same XPC
/// connection that performs the sign. The service therefore gets one
/// connection-bound opportunity to issue an opaque ticket, and the ticket is
/// required on the following sign request.
public final class NativeAgentChildGitXPCClient: @unchecked Sendable {
    public enum Error: Swift.Error, Equatable, Sendable {
        case invalidPayload
        case connectionFailed
        case remoteRejected
        case timeout
        case invalidTicket
        case invalidSignature
    }

    public static let defaultMachServiceName = "dev.agentpass.child-git"
    public static let timeoutNanoseconds: UInt64 = 5_000_000_000

    private let machServiceName: String

    public init(machServiceName: String = NativeAgentChildGitXPCClient.defaultMachServiceName) {
        self.machServiceName = machServiceName
    }

    public func sign(payload: Data) throws -> Data {
        guard !payload.isEmpty,
              payload.count <= AgentPassChildGitXPCContract.maximumPayloadBytes else {
            throw Error.invalidPayload
        }
        let connection = NSXPCConnection(machServiceName: machServiceName)
        connection.remoteObjectInterface = AgentPassChildGitXPCInterface.make()
        connection.resume()

        guard let attachRequest = AgentPassChildGitAttachRequest() else {
            connection.invalidate()
            throw Error.invalidTicket
        }
        let attachResponse: AgentPassChildGitAttachResponse = try invoke(on: connection) { proxy, reply in
            proxy.attachChildGit(attachRequest, withReply: reply)
        }
        let nowMilliseconds = Int64(Date().timeIntervalSince1970 * 1_000)
        guard AgentPassHostXPCContract.isTimestamp(attachResponse.expiresAtMilliseconds),
              attachResponse.expiresAtMilliseconds > nowMilliseconds else {
            connection.invalidate()
            throw Error.invalidTicket
        }

        guard let request = AgentPassChildGitSignRequest(
            requestSequence: 1,
            commitPayload: payload,
            attachTicket: attachResponse.attachTicket
        ) else {
            connection.invalidate()
            throw Error.invalidTicket
        }
        let result: AgentPassChildGitSignResponse = try invoke(on: connection) { proxy, reply in
            proxy.signChildGitCommit(request, withReply: reply)
        }
        connection.invalidate()
        guard result.responseSequence == 1,
              !result.signature.isEmpty,
              result.signature.count <= AgentPassChildGitXPCContract.maximumSignatureBytes,
              (NativeAgentSignatureBudget.minimumSignatures...NativeAgentSignatureBudget.maximumSignatures).contains(result.maxSignatures),
              (0...result.maxSignatures).contains(result.usedSignatures),
              result.remainingSignatures == result.maxSignatures - result.usedSignatures else {
            throw Error.invalidSignature
        }
        return result.signature
    }

    private func invoke<T>(
        on connection: NSXPCConnection,
        body: (AgentPassChildGitXPCProtocol, @escaping (T?, NSError?) -> Void) -> Void
    ) throws -> T {
        let semaphore = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var response: T?
        var failed = false
        var completed = false
        connection.invalidationHandler = {
            lock.lock()
            if !completed {
                failed = true
                completed = true
                semaphore.signal()
            }
            lock.unlock()
        }
        let proxy = connection.remoteObjectProxyWithErrorHandler { _ in
            lock.lock()
            if !completed {
                failed = true
                completed = true
                semaphore.signal()
            }
            lock.unlock()
        } as! AgentPassChildGitXPCProtocol
        body(proxy) { value, _ in
            lock.lock()
            if !completed {
                response = value
                failed = value == nil
                completed = true
                semaphore.signal()
            }
            lock.unlock()
        }
        guard semaphore.wait(timeout: .now() + .nanoseconds(Int(Self.timeoutNanoseconds))) == .success else {
            connection.invalidate()
            throw Error.timeout
        }
        lock.lock()
        let result = response
        let wasFailed = failed
        lock.unlock()
        guard !wasFailed, let result else { throw Error.remoteRejected }
        return result
    }
}
