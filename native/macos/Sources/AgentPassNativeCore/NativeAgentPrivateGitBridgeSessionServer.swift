import Foundation

/// Secret-free outcomes for the bounded v1 private Git session server.
///
/// This server is deliberately a different type from
/// `NativeAgentPrivateGitBridgeServer`. It never accepts the legacy frame
/// format and it never retries an operation after an ambiguous transport
/// failure.
public enum NativeAgentPrivateGitBridgeSessionServerError: Error, Equatable, Sendable {
    case alreadyUsed
    case invalidRequest
    case protocolViolation(NativeAgentPrivateGitSessionStateMachineError)
    case signerFailed
    case responseFailed
    case closeFailed
}

/// Serves exactly two versioned private Git signing requests on one stream.
///
/// The peer must send request sequence 1, request sequence 2, and then the
/// explicit close frame. The state machine and framed transport enforce the
/// sequence, protocol version, bounded payloads, and close/EOF handshake. A
/// missing response, signer failure, malformed frame, or unexpected EOF is
/// terminal; there is no one-shot fallback and no retry path.
public final class NativeAgentPrivateGitBridgeSessionServer: @unchecked Sendable {
    public typealias Signer = @Sendable (Data) throws -> Data

    public static let commitCount = NativeAgentPrivateGitSessionFrameCodec.maximumAcceptedSigns

    private let transport: NativeAgentPrivateGitSessionTransport
    private let signer: Signer
    private let stateMachine = NativeAgentPrivateGitSessionStateMachine(role: .server)
    private let stateLock = NSLock()
    private var used = false

    public init(
        transport: NativeAgentPrivateGitSessionTransport,
        signer: @escaping Signer
    ) {
        self.transport = transport
        self.signer = signer
    }

    /// The server's protocol state, exposed for the Host lifecycle boundary
    /// and focused tests without exposing the state machine itself.
    public var state: NativeAgentPrivateGitSessionState {
        stateMachine.state
    }

    /// Runs the complete two-commit session exactly once.
    public func serveTwoCommits() throws {
        try reserve()

        var outcome: Result<Void, NativeAgentPrivateGitBridgeSessionServerError> = .success(())
        do {
            for _ in 0..<Self.commitCount {
                let requestFrame: Data
                do {
                    requestFrame = try transport.readFrame()
                } catch NativeAgentPrivateGitSessionTransportError.eof {
                    // EOF before the first byte of a frame is a cleanly
                    // classifiable protocol failure, not an ambiguous sign
                    // result. Preserve that distinction for callers and
                    // lifecycle audit mapping.
                    stateMachine.markUnexpectedEOF()
                    outcome = .failure(.invalidRequest)
                    break
                } catch NativeAgentPrivateGitSessionTransportError.truncated {
                    stateMachine.markUnexpectedEOF()
                    outcome = .failure(.invalidRequest)
                    break
                } catch {
                    stateMachine.markOutcomeUnknown()
                    outcome = .failure(.invalidRequest)
                    break
                }

                let payload: Data
                do {
                    payload = try stateMachine.acceptRequest(requestFrame)
                } catch let error as NativeAgentPrivateGitSessionStateMachineError {
                    stateMachine.markOutcomeUnknown()
                    outcome = .failure(.protocolViolation(error))
                    break
                } catch {
                    stateMachine.markOutcomeUnknown()
                    outcome = .failure(.invalidRequest)
                    break
                }

                let signature: Data
                do {
                    signature = try signer(payload)
                } catch {
                    stateMachine.markOutcomeUnknown()
                    outcome = .failure(.signerFailed)
                    break
                }

                let responseFrame: Data
                do {
                    responseFrame = try stateMachine.makeResponse(signature: signature)
                    try transport.writeFrame(responseFrame)
                } catch {
                    // The signer may already have completed. The result is
                    // therefore unknown to the peer and must never be retried.
                    stateMachine.markOutcomeUnknown()
                    outcome = .failure(.responseFailed)
                    break
                }
            }

            if case .success = outcome {
                do {
                    let closeFrame = try transport.readFrame()
                    try stateMachine.acceptClose(closeFrame)
                    let closeAck = try stateMachine.acknowledgeClose()
                    try transport.writeFrame(closeAck)
                    try transport.finishWriting()
                    try transport.readEOF()
                    try stateMachine.acceptEOF()
                } catch let error as NativeAgentPrivateGitSessionStateMachineError {
                    outcome = .failure(.protocolViolation(error))
                } catch let error as NativeAgentPrivateGitSessionTransportError {
                    switch error {
                    case .eof, .truncated:
                        stateMachine.markUnexpectedEOF()
                    case .extraBytes:
                        stateMachine.markTrafficAfterClose()
                    default:
                        stateMachine.markOutcomeUnknown()
                    }
                    outcome = .failure(.invalidRequest)
                } catch {
                    stateMachine.markOutcomeUnknown()
                    outcome = .failure(.invalidRequest)
                }
            }
        }

        var closeFailed = false
        do {
            try transport.close()
        } catch {
            closeFailed = true
        }

        switch outcome {
        case .success:
            if closeFailed { throw NativeAgentPrivateGitBridgeSessionServerError.closeFailed }
        case .failure(let error):
            throw error
        }
    }

    /// Interrupts a blocked read and permanently consumes this server.
    public func cancel() {
        stateLock.lock()
        used = true
        stateLock.unlock()
        transport.abort()
    }

    private func reserve() throws {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard !used else { throw NativeAgentPrivateGitBridgeSessionServerError.alreadyUsed }
        used = true
    }
}
