import Foundation

/// One-shot child-side client. It deliberately creates a fresh connection for
/// each Git helper invocation; the service binds the connection to the OS
/// process identity and limits the registered child session globally.
public final class NativeAgentChildGitXPCClient: @unchecked Sendable {
    public enum Error: Swift.Error, Equatable, Sendable {
        case invalidPayload
        case connectionFailed
        case remoteRejected
        case timeout
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
        let semaphore = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var response: AgentPassChildGitSignResponse?
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
        connection.resume()
        guard let request = AgentPassChildGitSignRequest(requestSequence: 1, commitPayload: payload) else {
            connection.invalidate()
            throw Error.invalidPayload
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
        proxy.signChildGitCommit(request) { value, _ in
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
        connection.invalidate()
        lock.lock()
        let result = response
        let wasFailed = failed
        lock.unlock()
        guard !wasFailed, let result else { throw Error.remoteRejected }
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
}
