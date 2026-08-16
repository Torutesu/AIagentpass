import Foundation

/// Stable errors exposed by the one-shot private Git bridge client.
public enum NativeAgentPrivateGitBridgeClientError: Error, Equatable, Sendable {
    case alreadyUsed
    case transport(NativeAgentPrivateFDTransportError)
    case unexpected
}

/// Performs exactly one helper-side private Git bridge transaction.
///
/// The caller supplies the already-connected fixed-descriptor transport. The
/// client deliberately accepts no authority, identity, path, or protocol
/// selectors: the only request input is the commit payload and the only
/// successful output is the signature bytes.
public final class NativeAgentPrivateGitBridgeClient: @unchecked Sendable {
    private let transport: NativeAgentPrivateFDTransport
    private let stateLock = NSLock()
    private var used = false

    public init(transport: NativeAgentPrivateFDTransport) {
        self.transport = transport
    }

    /// Writes one commit-payload frame, reads one signature frame, and closes
    /// the supplied transport regardless of the transaction outcome.
    ///
    /// The reservation is made before any I/O. Consequently a repeated or
    /// concurrent caller cannot cause a second write, retry a signing request,
    /// or close a transport still owned by the first transaction.
    public func sign(commitPayload: Data) throws -> Data {
        stateLock.lock()
        guard !used else {
            stateLock.unlock()
            throw NativeAgentPrivateGitBridgeClientError.alreadyUsed
        }
        used = true
        stateLock.unlock()

        var result: Result<Data, NativeAgentPrivateGitBridgeClientError>
        do {
            try transport.writeCommitPayload(commitPayload)
            result = .success(try transport.readSignature())
        } catch let error as NativeAgentPrivateFDTransportError {
            result = .failure(.transport(error))
        } catch {
            result = .failure(.unexpected)
        }

        // Preserve an I/O error if both the transaction and close fail, while
        // still making the close attempt on every transaction path. A close
        // failure is surfaced when no earlier transaction error exists.
        var closeError: NativeAgentPrivateGitBridgeClientError?
        do {
            try transport.close()
        } catch let error as NativeAgentPrivateFDTransportError {
            closeError = .transport(error)
        } catch {
            closeError = .unexpected
        }

        switch result {
        case .success(let signature):
            if let closeError {
                throw closeError
            }
            return signature
        case .failure(let error):
            throw error
        }
    }
}
