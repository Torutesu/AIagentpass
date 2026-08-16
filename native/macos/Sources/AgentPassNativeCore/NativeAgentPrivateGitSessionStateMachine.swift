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
}

public enum NativeAgentPrivateGitSessionState: Equatable, Sendable {
    case ready(nextSequence: UInt32)
    case awaitingResponse(sequence: UInt32)
    case completed
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
    case terminal
}

/// Contract-only state machine for a two-sign private Git session.
///
/// This type owns no descriptor, socket, process, XPC connection, signer, or
/// runtime callback. It only advances a serialized protocol state based on
/// canonical request/response frames. Any protocol violation transitions the
/// instance to a terminal quarantine state. The lock makes the one-outstanding
/// invariant hold even when callers race `beginRequest` from different threads.
public final class NativeAgentPrivateGitSessionStateMachine: @unchecked Sendable {
    private let stateLock = NSLock()
    private var currentState: NativeAgentPrivateGitSessionState = .ready(nextSequence: 1)

    public init() {}

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

        case .completed, .quarantined:
            throw NativeAgentPrivateGitSessionStateMachineError.terminal
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
        }
    }

}
