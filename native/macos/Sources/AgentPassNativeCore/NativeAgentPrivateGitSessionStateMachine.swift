import Foundation

/// The only terminal/quarantine reasons exposed by the private Git session.
/// They contain no peer-controlled bytes or authority details.
public enum NativeAgentPrivateGitSessionQuarantineReason: String, Equatable, Sendable {
    case malformed
    case concurrentRequest = "concurrent_request"
    case replay
    case skippedSequence = "skipped_sequence"
    case excess
    case wrongResponse = "wrong_response"
    case wrongMessage = "wrong_message"
    case closeWhileOutstanding = "close_while_outstanding"
    case incomplete
    case unexpectedEOF = "unexpected_eof"
    case trafficAfterClose = "traffic_after_close"
    case duplicateClose = "duplicate_close"
    case outcomeUnknown = "outcome_unknown"
}

public enum NativeAgentPrivateGitSessionState: Equatable, Sendable {
    case ready(nextSequence: UInt32)
    case awaitingResponse(sequence: UInt32)
    case completed
    case closing
    case closed
    case quarantined(NativeAgentPrivateGitSessionQuarantineReason)
}

/// Stable failures for an attempted operation against the session state.
public enum NativeAgentPrivateGitSessionStateMachineError: Error, Equatable, Sendable {
    case malformed
    case concurrentRequest
    case replay
    case skippedSequence
    case excess
    case wrongResponse
    case wrongMessage
    case closeWhileOutstanding
    case incomplete
    case unexpectedEOF
    case trafficAfterClose
    case duplicateClose
    case alreadyClosed
    case terminal
    case outcomeUnknown
    case revoked
    case expired
    case policyDrift
    case processDrift
    case transportQuarantined

    /// Stable F1 lifecycle class for this operation, when one applies.
    /// Detailed protocol cases remain available to the local state machine,
    /// while callers can expose this bounded code across a lifecycle boundary.
    public var lifecycleError: NativeAgentPrivateGitSessionLifecycleError? {
        switch self {
        case .malformed, .concurrentRequest, .replay, .skippedSequence,
             .excess, .wrongResponse, .wrongMessage,
             .incomplete, .unexpectedEOF, .trafficAfterClose,
             .duplicateClose, .terminal:
            return .transportQuarantined
        case .closeWhileOutstanding:
            return .outcomeUnknown
        case .outcomeUnknown:
            return .outcomeUnknown
        case .alreadyClosed:
            return nil
        case .revoked:
            return .revoked
        case .expired:
            return .expired
        case .policyDrift:
            return .policyDrift
        case .processDrift:
            return .processDrift
        case .transportQuarantined:
            return .transportQuarantined
        }
    }
}

/// Contract-only state machine for a two-sign private Git session.
///
/// This type owns no descriptor, socket, process, XPC connection, signer, or
/// runtime callback. It only advances a serialized protocol state based on
/// canonical request/response frames. Any protocol violation transitions the
/// instance to a terminal quarantine state. The lock makes the one-outstanding
/// invariant hold even when callers race `beginRequest` from different threads.
public final class NativeAgentPrivateGitSessionStateMachine: @unchecked Sendable {
    public enum Role: Sendable {
        case client
        case server
    }

    private let stateLock = NSLock()
    private let role: Role
    private var currentState: NativeAgentPrivateGitSessionState = .ready(nextSequence: 1)
    private enum ClosePhase: Equatable {
        case notStarted
        case localCloseSentAwaitingPeer
        case peerCloseReceivedAwaitingAck
        case bothCloseFramesExchangedAwaitingEOF
        case ackSentAwaitingEOF
    }
    private var closePhase: ClosePhase = .notStarted

    public init(role: Role = .client) {
        self.role = role
    }

    public var state: NativeAgentPrivateGitSessionState {
        stateLock.lock()
        defer { stateLock.unlock() }
        return currentState
    }

    /// Creates the next canonical request and reserves its sequence number.
    /// A second call while a response is outstanding quarantines the session.
    public func beginRequest(commitPayload: Data) throws -> Data {
        stateLock.lock()
        defer { stateLock.unlock() }

        guard role == .client else {
            quarantine(.wrongMessage)
            throw Self.error(for: .wrongMessage)
        }

        switch currentState {
        case .ready(let nextSequence):
            do {
                let frame = try NativeAgentPrivateGitSessionFrameCodec.encode(
                    .request(sequence: nextSequence, commitPayload: commitPayload))
                currentState = .awaitingResponse(sequence: nextSequence)
                return frame
            } catch {
                quarantine(.malformed)
                throw Self.error(for: .malformed)
            }
        case .awaitingResponse:
            quarantine(.concurrentRequest)
            throw Self.error(for: .concurrentRequest)
        case .completed:
            quarantine(.excess)
            throw Self.error(for: .excess)
        case .closing:
            quarantine(.trafficAfterClose)
            throw Self.error(for: .trafficAfterClose)
        case .closed:
            throw NativeAgentPrivateGitSessionStateMachineError.alreadyClosed
        case .quarantined:
            throw NativeAgentPrivateGitSessionStateMachineError.terminal
        }
    }

    /// Validates and consumes one canonical response frame.
    ///
    /// A response must be the matching response for the single outstanding
    /// request. The matching response advances the session; all other decoded
    /// sequence/kind cases quarantine it. A malformed frame is quarantined
    /// before any signature bytes are returned to the caller.
    public func acceptResponse(_ frame: Data) throws -> Data {
        stateLock.lock()
        defer { stateLock.unlock() }

        guard role == .client else {
            quarantine(.wrongMessage)
            throw Self.error(for: .wrongMessage)
        }

        switch currentState {
        case .ready(let nextSequence):
            guard let message = tryDecodeOrQuarantine(frame) else {
                throw Self.error(for: .malformed)
            }
            guard case let .response(sequence, _) = message else {
                quarantine(.wrongResponse)
                throw Self.error(for: .wrongResponse)
            }
            if sequence < nextSequence {
                quarantine(.replay)
                throw Self.error(for: .replay)
            }
            if sequence > nextSequence {
                quarantine(sequence > NativeAgentPrivateGitSessionFrameCodec.maximumAcceptedSigns ? .excess : .skippedSequence)
                throw Self.error(for: sequence > NativeAgentPrivateGitSessionFrameCodec.maximumAcceptedSigns ? .excess : .skippedSequence)
            }
            quarantine(.wrongResponse)
            throw Self.error(for: .wrongResponse)

        case .awaitingResponse(let expectedSequence):
            guard let message = tryDecodeOrQuarantine(frame) else {
                throw Self.error(for: .malformed)
            }
            guard case let .response(sequence, signature) = message else {
                quarantine(.wrongResponse)
                throw Self.error(for: .wrongResponse)
            }
            if sequence < expectedSequence {
                quarantine(.replay)
                throw Self.error(for: .replay)
            }
            if sequence > expectedSequence {
                let reason: NativeAgentPrivateGitSessionQuarantineReason = sequence > NativeAgentPrivateGitSessionFrameCodec.maximumAcceptedSigns
                    ? .excess
                    : .skippedSequence
                quarantine(reason)
                throw Self.error(for: reason)
            }

            if sequence == NativeAgentPrivateGitSessionFrameCodec.maximumAcceptedSigns {
                currentState = .completed
            } else {
                currentState = .ready(nextSequence: expectedSequence + 1)
            }
            return signature

        case .completed:
            quarantine(.excess)
            throw Self.error(for: .excess)
        case .closing:
            quarantine(.trafficAfterClose)
            throw Self.error(for: .trafficAfterClose)
        case .closed:
            throw NativeAgentPrivateGitSessionStateMachineError.alreadyClosed
        case .quarantined:
            throw NativeAgentPrivateGitSessionStateMachineError.terminal
        }
    }

    /// Validates and consumes one request on a server-role session. The
    /// request is accepted only at the next exact sequence and reserves the
    /// single response slot before returning its payload to the signer.
    /// There is no server-side buffering or pipelining state: a second request
    /// while that slot is reserved is a terminal concurrent-request failure.
    public func acceptRequest(_ frame: Data) throws -> Data {
        stateLock.lock()
        defer { stateLock.unlock() }

        guard role == .server else {
            quarantine(.wrongMessage)
            throw Self.error(for: .wrongMessage)
        }

        switch currentState {
        case .ready(let nextSequence):
            guard let message = tryDecodeOrQuarantine(frame) else {
                throw Self.error(for: .malformed)
            }
            guard case let .request(sequence, payload) = message else {
                quarantine(.wrongMessage)
                throw Self.error(for: .wrongMessage)
            }
            if sequence < nextSequence {
                quarantine(.replay)
                throw Self.error(for: .replay)
            }
            if sequence > nextSequence {
                let reason: NativeAgentPrivateGitSessionQuarantineReason =
                    sequence > NativeAgentPrivateGitSessionFrameCodec.maximumAcceptedSigns
                        ? .excess
                        : .skippedSequence
                quarantine(reason)
                throw Self.error(for: reason)
            }
            currentState = .awaitingResponse(sequence: sequence)
            return payload

        case .awaitingResponse:
            quarantine(.concurrentRequest)
            throw Self.error(for: .concurrentRequest)
        case .completed:
            quarantine(.excess)
            throw Self.error(for: .excess)
        case .closing:
            quarantine(.trafficAfterClose)
            throw Self.error(for: .trafficAfterClose)
        case .closed:
            throw NativeAgentPrivateGitSessionStateMachineError.alreadyClosed
        case .quarantined:
            throw NativeAgentPrivateGitSessionStateMachineError.terminal
        }
    }

    /// Creates the exact response for the server's one outstanding request.
    /// The response sequence is taken from the state machine, never from a
    /// caller-supplied value, so a signer cannot accidentally skip or replay.
    public func makeResponse(signature: Data) throws -> Data {
        stateLock.lock()
        defer { stateLock.unlock() }

        guard role == .server else {
            quarantine(.wrongMessage)
            throw Self.error(for: .wrongMessage)
        }

        switch currentState {
        case .awaitingResponse(let sequence):
            do {
                let frame = try NativeAgentPrivateGitSessionFrameCodec.encode(
                    .response(sequence: sequence, signature: signature))
                if sequence == NativeAgentPrivateGitSessionFrameCodec.maximumAcceptedSigns {
                    currentState = .completed
                } else {
                    currentState = .ready(nextSequence: sequence + 1)
                }
                return frame
            } catch {
                quarantine(.malformed)
                throw Self.error(for: .malformed)
            }
        case .ready:
            quarantine(.wrongResponse)
            throw Self.error(for: .wrongResponse)
        case .completed:
            quarantine(.excess)
            throw Self.error(for: .excess)
        case .closing:
            quarantine(.trafficAfterClose)
            throw Self.error(for: .trafficAfterClose)
        case .closed:
            throw NativeAgentPrivateGitSessionStateMachineError.alreadyClosed
        case .quarantined:
            throw NativeAgentPrivateGitSessionStateMachineError.terminal
        }
    }

    /// Records that the result of the outstanding sign operation is unknown.
    /// This is used when the transport fails after a request was accepted; it
    /// is deliberately terminal and never permits a retry.
    public func markOutcomeUnknown() {
        stateLock.lock()
        defer { stateLock.unlock() }
        switch currentState {
        case .closed, .quarantined:
            return
        default:
            currentState = .quarantined(.outcomeUnknown)
        }
    }

    /// Produces the explicit terminal close frame and begins the local close
    /// handshake. EOF is required before the lifecycle becomes `closed`.
    /// Closing while a response is outstanding quarantines the transport so
    /// an ambiguous signing result cannot be mistaken for a clean close.
    @discardableResult
    public func close() throws -> Data {
        stateLock.lock()
        defer { stateLock.unlock() }

        switch currentState {
        case .ready:
            quarantine(.incomplete)
            throw Self.error(for: .incomplete)
        case .completed:
            guard role == .client else {
                quarantine(.wrongMessage)
                throw Self.error(for: .wrongMessage)
            }
            let frame = try NativeAgentPrivateGitSessionFrameCodec.encode(.close)
            currentState = .closing
            closePhase = .localCloseSentAwaitingPeer
            return frame
        case .awaitingResponse:
            quarantine(.closeWhileOutstanding)
            throw Self.error(for: .closeWhileOutstanding)
        case .closing, .closed:
            throw NativeAgentPrivateGitSessionStateMachineError.alreadyClosed
        case .quarantined:
            throw NativeAgentPrivateGitSessionStateMachineError.terminal
        }
    }

    /// Consumes a peer's terminal close frame. Parsing the frame only enters
    /// `closing`; `acceptEOF()` is required to commit terminal closure. A
    /// peer cannot close over an outstanding request because that would make
    /// the sign outcome unknowable.
    public func acceptClose(_ frame: Data) throws {
        stateLock.lock()
        defer { stateLock.unlock() }

        switch currentState {
        case .ready:
            try decodeClose(frame)
            if role == .server {
                quarantine(.incomplete)
                throw Self.error(for: .incomplete)
            }
            quarantine(.wrongMessage)
            throw Self.error(for: .wrongMessage)
        case .completed:
            try decodeClose(frame)
            guard role == .server else {
                quarantine(.wrongMessage)
                throw Self.error(for: .wrongMessage)
            }
            currentState = .closing
            closePhase = .peerCloseReceivedAwaitingAck
        case .awaitingResponse:
            try decodeClose(frame)
            quarantine(.closeWhileOutstanding)
            throw Self.error(for: .closeWhileOutstanding)
        case .closing:
            try decodeClose(frame)
            guard role == .client,
                  closePhase == .localCloseSentAwaitingPeer else {
                quarantine(.duplicateClose)
                throw Self.error(for: .duplicateClose)
            }
            closePhase = .bothCloseFramesExchangedAwaitingEOF
        case .closed:
            throw NativeAgentPrivateGitSessionStateMachineError.alreadyClosed
        case .quarantined:
            throw NativeAgentPrivateGitSessionStateMachineError.terminal
        }
    }

    /// Creates the peer's close acknowledgement after a valid close frame was
    /// consumed. The state remains `closing` until the transport observes EOF.
    /// This is intentionally separate from `close()`, which initiates the
    /// local side of the handshake.
    public func acknowledgeClose() throws -> Data {
        stateLock.lock()
        defer { stateLock.unlock() }

        guard role == .server else {
            switch currentState {
            case .closed:
                throw NativeAgentPrivateGitSessionStateMachineError.alreadyClosed
            case .quarantined:
                throw NativeAgentPrivateGitSessionStateMachineError.terminal
            default:
                quarantine(.wrongMessage)
                throw Self.error(for: .wrongMessage)
            }
        }

        guard case .closing = currentState,
              closePhase == .peerCloseReceivedAwaitingAck else {
            switch currentState {
            case .closed:
                throw NativeAgentPrivateGitSessionStateMachineError.alreadyClosed
            case .quarantined:
                throw NativeAgentPrivateGitSessionStateMachineError.terminal
            default:
                quarantine(.wrongMessage)
                throw Self.error(for: .wrongMessage)
            }
        }
        do {
            let frame = try NativeAgentPrivateGitSessionFrameCodec.encode(.close)
            closePhase = .ackSentAwaitingEOF
            return frame
        } catch {
            quarantine(.malformed)
            throw Self.error(for: .malformed)
        }
    }

    /// Commits a parsed terminal close only after the transport reports EOF.
    /// EOF without a prior valid close is never treated as a clean shutdown.
    public func acceptEOF() throws {
        stateLock.lock()
        defer { stateLock.unlock() }

        switch currentState {
        case .closing:
            switch (role, closePhase) {
            case (.client, .bothCloseFramesExchangedAwaitingEOF),
                 (.server, .ackSentAwaitingEOF):
                currentState = .closed
            default:
                quarantine(.unexpectedEOF)
                throw Self.error(for: .unexpectedEOF)
            }
        case .awaitingResponse:
            quarantine(.outcomeUnknown)
            throw NativeAgentPrivateGitSessionStateMachineError.outcomeUnknown
        case .ready, .completed:
            quarantine(.unexpectedEOF)
            throw NativeAgentPrivateGitSessionStateMachineError.unexpectedEOF
        case .closed:
            throw NativeAgentPrivateGitSessionStateMachineError.alreadyClosed
        case .quarantined:
            throw NativeAgentPrivateGitSessionStateMachineError.terminal
        }
    }

    /// Records EOF/truncation while a close frame was still expected. This is
    /// separate from `acceptEOF()`: calling `acceptEOF()` after both close
    /// frames have exchanged would incorrectly commit a clean close.
    public func markUnexpectedEOF() {
        stateLock.lock()
        defer { stateLock.unlock() }
        switch currentState {
        case .closed, .quarantined:
            return
        case .awaitingResponse:
            currentState = .quarantined(.outcomeUnknown)
        default:
            currentState = .quarantined(.unexpectedEOF)
        }
    }

    /// Records bytes observed after the close exchange. Such traffic is a
    /// terminal protocol violation and must never be mistaken for EOF.
    public func markTrafficAfterClose() {
        stateLock.lock()
        defer { stateLock.unlock() }
        switch currentState {
        case .closed, .quarantined:
            return
        default:
            currentState = .quarantined(.trafficAfterClose)
        }
    }

    private func tryDecodeOrQuarantine(_ frame: Data) -> NativeAgentPrivateGitSessionMessage? {
        do {
            return try NativeAgentPrivateGitSessionFrameCodec.decode(frame)
        } catch {
            quarantine(.malformed)
            return nil
        }
    }

    private func decodeClose(_ frame: Data) throws {
        do {
            guard case .close = try NativeAgentPrivateGitSessionFrameCodec.decode(frame) else {
                quarantine(.wrongMessage)
                throw Self.error(for: .wrongMessage)
            }
        } catch {
            if let error = error as? NativeAgentPrivateGitSessionStateMachineError {
                throw error
            }
            quarantine(.malformed)
            throw Self.error(for: .malformed)
        }
    }

    private func quarantine(_ reason: NativeAgentPrivateGitSessionQuarantineReason) {
        currentState = .quarantined(reason)
    }

    private static func error(
        for reason: NativeAgentPrivateGitSessionQuarantineReason
    ) -> NativeAgentPrivateGitSessionStateMachineError {
        switch reason {
        case .malformed: return .malformed
        case .concurrentRequest: return .concurrentRequest
        case .replay: return .replay
        case .skippedSequence: return .skippedSequence
        case .excess: return .excess
        case .wrongResponse: return .wrongResponse
        case .wrongMessage: return .wrongMessage
        case .closeWhileOutstanding: return .closeWhileOutstanding
        case .incomplete: return .incomplete
        case .unexpectedEOF: return .unexpectedEOF
        case .trafficAfterClose: return .trafficAfterClose
        case .duplicateClose: return .duplicateClose
        case .outcomeUnknown: return .outcomeUnknown
        }
    }

}
