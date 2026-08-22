import Foundation

/// Stable, secret-free failures for the versioned private Git session client.
public enum NativeAgentPrivateGitBridgeSessionClientError: Error, Equatable, Sendable {
    case alreadyUsed
    case incomplete
    case protocolViolation(NativeAgentPrivateGitSessionStateMachineError)
    case transport(NativeAgentPrivateGitSessionTransportError)
    case outcomeUnknown
}

/// Client for exactly two sequential private Git signing exchanges.
///
/// A call to `sign` reserves the next sequence in the state machine before
/// writing anything. A transport failure after that reservation is always
/// reported as `outcomeUnknown`: the peer may have accepted the request even
/// when no response was observed. This deliberately prevents a caller from
/// retrying an ambiguous signing operation.
public final class NativeAgentPrivateGitBridgeSessionClient: @unchecked Sendable {
    private let transport: NativeAgentPrivateGitSessionTransport
    private let stateMachine = NativeAgentPrivateGitSessionStateMachine(role: .client)
    private let lifecycleLock = NSLock()
    private var exchangeInFlight = false

    public init(transport: NativeAgentPrivateGitSessionTransport) {
        self.transport = transport
    }

    public var state: NativeAgentPrivateGitSessionState {
        stateMachine.state
    }

    /// Performs one of the two sequential request/response exchanges.
    /// A third exchange, a concurrent exchange, or any protocol violation is
    /// terminal and never sends another frame.
    public func sign(commitPayload: Data) throws -> Data {
        lifecycleLock.lock()
        guard !exchangeInFlight else {
            lifecycleLock.unlock()
            stateMachine.markOutcomeUnknown()
            transport.abort()
            throw NativeAgentPrivateGitBridgeSessionClientError.protocolViolation(.concurrentRequest)
        }
        exchangeInFlight = true
        lifecycleLock.unlock()
        defer {
            lifecycleLock.lock()
            exchangeInFlight = false
            lifecycleLock.unlock()
        }

        let request: Data
        do {
            request = try stateMachine.beginRequest(commitPayload: commitPayload)
        } catch let error as NativeAgentPrivateGitSessionStateMachineError {
            transport.abort()
            throw NativeAgentPrivateGitBridgeSessionClientError.protocolViolation(error)
        } catch {
            transport.abort()
            throw NativeAgentPrivateGitBridgeSessionClientError.outcomeUnknown
        }

        do {
            try transport.writeFrame(request)
        } catch is NativeAgentPrivateGitSessionTransportError {
            stateMachine.markOutcomeUnknown()
            transport.abort()
            throw NativeAgentPrivateGitBridgeSessionClientError.outcomeUnknown
        } catch {
            stateMachine.markOutcomeUnknown()
            transport.abort()
            throw NativeAgentPrivateGitBridgeSessionClientError.outcomeUnknown
        }

        let response: Data
        do {
            response = try transport.readFrame()
        } catch let error as NativeAgentPrivateGitSessionTransportError {
            _ = error
            stateMachine.markOutcomeUnknown()
            transport.abort()
            throw NativeAgentPrivateGitBridgeSessionClientError.outcomeUnknown
        } catch {
            stateMachine.markOutcomeUnknown()
            transport.abort()
            throw NativeAgentPrivateGitBridgeSessionClientError.outcomeUnknown
        }

        do {
            return try stateMachine.acceptResponse(response)
        } catch let error as NativeAgentPrivateGitSessionStateMachineError {
            transport.abort()
            throw NativeAgentPrivateGitBridgeSessionClientError.protocolViolation(error)
        } catch {
            transport.abort()
            throw NativeAgentPrivateGitBridgeSessionClientError.outcomeUnknown
        }
    }

    /// Performs the terminal close handshake after exactly two responses.
    /// Both directions must exchange a close frame and then observe EOF.
    public func close() throws {
        guard case .completed = stateMachine.state else {
            transport.abort()
            if case .ready = stateMachine.state {
                throw NativeAgentPrivateGitBridgeSessionClientError.incomplete
            }
            if case .awaitingResponse = stateMachine.state {
                throw NativeAgentPrivateGitBridgeSessionClientError.protocolViolation(.closeWhileOutstanding)
            }
            throw NativeAgentPrivateGitBridgeSessionClientError.protocolViolation(.terminal)
        }

        do {
            let closeFrame = try stateMachine.close()
            try transport.writeFrame(closeFrame)
            try transport.finishWriting()

            let peerClose = try transport.readFrame()
            try stateMachine.acceptClose(peerClose)
            try transport.readEOF()
            try stateMachine.acceptEOF()
            try transport.close()
        } catch let error as NativeAgentPrivateGitSessionStateMachineError {
            transport.abort()
            throw NativeAgentPrivateGitBridgeSessionClientError.protocolViolation(error)
        } catch let error as NativeAgentPrivateGitSessionTransportError {
            switch error {
            case .eof, .truncated:
                stateMachine.markUnexpectedEOF()
            case .extraBytes:
                stateMachine.markTrafficAfterClose()
            default:
                stateMachine.markOutcomeUnknown()
            }
            transport.abort()
            throw NativeAgentPrivateGitBridgeSessionClientError.transport(error)
        } catch {
            transport.abort()
            throw NativeAgentPrivateGitBridgeSessionClientError.transport(.closeFailed)
        }
    }
}
