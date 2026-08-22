import Foundation

/// The only private Git session protocol the Host adapter is allowed to
/// select. Legacy one-shot FD3 is intentionally not represented here.
public enum NativeAgentHostPrivateGitSessionProtocol: String, Codable, CaseIterable, Sendable {
    case versionedSessionV1 = "versioned_session_v1"
}

/// Host-side errors for the unconnected, versioned private Git adapter.
public enum NativeAgentHostPrivateGitSessionAdapterError: Error, Equatable, Sendable {
    case unsupportedProtocol
    case alreadyUsed
    case invalidRequest
    case signerFailed
    case responseFailed
    case closeFailed
    case cancelled
}

/// Bounded Host adapter for the v1 two-commit private Git session.
///
/// The adapter accepts an already-created versioned session transport. It
/// does not create a child process, discover an endpoint, invoke the legacy
/// one-shot server, or fall back to another protocol. The caller is expected
/// to invoke it only after the existing Host/XPC child identity checks have
/// succeeded. `revalidateAuthority` is called immediately before each of the
/// two signer invocations so an integrated caller can preserve those checks.
public final class NativeAgentHostPrivateGitSessionAdapter: @unchecked Sendable {
    public static let requiredProtocol = NativeAgentHostPrivateGitSessionProtocol.versionedSessionV1

    public let selectedProtocol: NativeAgentHostPrivateGitSessionProtocol

    private let server: NativeAgentPrivateGitBridgeSessionServer

    public init(
        protocol: NativeAgentHostPrivateGitSessionProtocol,
        transport: NativeAgentPrivateGitSessionTransport,
        revalidateAuthority: @escaping @Sendable () throws -> Void,
        signer: @escaping NativeAgentPrivateGitBridgeSessionServer.Signer
    ) throws {
        guard `protocol` == Self.requiredProtocol else {
            throw NativeAgentHostPrivateGitSessionAdapterError.unsupportedProtocol
        }
        self.selectedProtocol = `protocol`
        self.server = NativeAgentPrivateGitBridgeSessionServer(
            transport: transport,
            signer: { payload in
                do {
                    try revalidateAuthority()
                    return try signer(payload)
                } catch {
                    throw NativeAgentHostPrivateGitSessionAdapterError.signerFailed
                }
            })
    }

    /// Serves two commits and then performs the explicit close/EOF handshake.
    public func serveTwoCommits() throws {
        do {
            try server.serveTwoCommits()
        } catch NativeAgentPrivateGitBridgeSessionServerError.alreadyUsed {
            throw NativeAgentHostPrivateGitSessionAdapterError.alreadyUsed
        } catch NativeAgentPrivateGitBridgeSessionServerError.invalidRequest {
            throw NativeAgentHostPrivateGitSessionAdapterError.invalidRequest
        } catch NativeAgentPrivateGitBridgeSessionServerError.signerFailed {
            throw NativeAgentHostPrivateGitSessionAdapterError.signerFailed
        } catch NativeAgentPrivateGitBridgeSessionServerError.responseFailed {
            throw NativeAgentHostPrivateGitSessionAdapterError.responseFailed
        } catch NativeAgentPrivateGitBridgeSessionServerError.closeFailed {
            throw NativeAgentHostPrivateGitSessionAdapterError.closeFailed
        } catch {
            throw NativeAgentHostPrivateGitSessionAdapterError.invalidRequest
        }
    }

    /// Cancels the session. Cancellation is terminal and cannot fall back to
    /// the legacy one-shot bridge.
    public func cancel() {
        server.cancel()
    }
}
