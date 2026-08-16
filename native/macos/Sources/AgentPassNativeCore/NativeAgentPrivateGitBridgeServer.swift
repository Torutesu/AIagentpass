import Foundation

/// Stable, secret-free outcomes for a Host-side private Git bridge request.
///
/// The enum intentionally has no errno, payload, signature, path, identity,
/// capability, key, algorithm, or session data. Callers can safely expose the
/// case name to an untrusted helper or log sink.
public enum NativeAgentPrivateGitBridgeServerError: Error, Equatable, Sendable {
    case alreadyUsed
    case invalidRequest
    case signerFailed
    case responseFailed
    case closeFailed
}

/// A Host-side one-shot private Git bridge server.
///
/// The transport is the sole authority for bytes: it reads one bounded commit
/// payload frame (rejecting already-available trailing input), then the
/// injected signer is called exactly once, then one bounded signature frame is
/// written. The server owns one lifecycle reservation, so concurrent and
/// repeated calls fail before any I/O.
///
/// This API deliberately exposes no selector beyond the commit payload. In
/// particular, callers cannot choose a session, capability, key, algorithm,
/// repository, or path through this bridge.
public final class NativeAgentPrivateGitBridgeServer: @unchecked Sendable {
    public typealias Signer = @Sendable (Data) throws -> Data

    private let transport: NativeAgentPrivateFDTransport
    private let signer: Signer
    private let stateLock = NSLock()
    private var used = false

    public init(
        transport: NativeAgentPrivateFDTransport,
        signer: @escaping Signer
    ) {
        self.transport = transport
        self.signer = signer
    }

    /// Serves exactly one request and then closes the transport on every path.
    ///
    /// The signer is invoked only after the complete request frame has been
    /// validated. A failed signer or response write is terminal; this method
    /// never retries either operation.
    public func serve() throws {
        try reserveOneShot()

        var outcome: Result<Void, NativeAgentPrivateGitBridgeServerError>
        do {
            let payload: Data
            do {
                payload = try transport.readCommitPayload()
            } catch {
                outcome = .failure(.invalidRequest)
                return try finish(outcome)
            }

            let signature: Data
            do {
                signature = try signer(payload)
            } catch {
                outcome = .failure(.signerFailed)
                return try finish(outcome)
            }

            do {
                try transport.writeSignature(signature)
                outcome = .success(())
            } catch {
                outcome = .failure(.responseFailed)
            }
        }

        return try finish(outcome)
    }

    private func reserveOneShot() throws {
        stateLock.lock()
        defer { stateLock.unlock() }
        if used {
            throw NativeAgentPrivateGitBridgeServerError.alreadyUsed
        }
        used = true
    }

    private func finish(
        _ outcome: Result<Void, NativeAgentPrivateGitBridgeServerError>
    ) throws {
        var closeSucceeded = true
        do {
            try transport.close()
        } catch {
            closeSucceeded = false
        }

        switch outcome {
        case .success:
            guard closeSucceeded else { throw NativeAgentPrivateGitBridgeServerError.closeFailed }
        case .failure(let error):
            throw error
        }
    }
}
