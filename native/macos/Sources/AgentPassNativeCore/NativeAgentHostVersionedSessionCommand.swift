import Foundation

/// Stable failures for construction of the explicit Agent-facing session
/// command. The caller never supplies an executable, protocol, or arbitrary
/// argv; only two already-created payload paths are accepted.
public enum NativeAgentHostVersionedSessionCommandError: Error, Equatable, Sendable {
    case invalidPayloads
}

/// The reviewed command contract for an Agent that wants to use the
/// two-request private Git session. This is deliberately not the argument
/// shape Git passes to `gpg.ssh.program`.
public struct NativeAgentHostVersionedSessionCommand: Equatable, Sendable {
    public static let executablePath = NativeAgentHostGitConfiguration.versionedSessionHelperExecutablePath

    public let executablePath: String
    public let arguments: [String]

    public init(payloadPaths: [String]) throws {
        guard payloadPaths.count == 2,
              payloadPaths[0] != payloadPaths[1] else {
            throw NativeAgentHostVersionedSessionCommandError.invalidPayloads
        }
        let arguments = [
            NativeAgentGitSessionSigningInvocation.protocolFlag,
            NativeAgentGitSessionSigningInvocation.versionedProtocol,
            NativeAgentGitSessionSigningInvocation.payloadFlag,
            payloadPaths[0],
            NativeAgentGitSessionSigningInvocation.payloadFlag,
            payloadPaths[1]
        ]
        guard (try? NativeAgentGitSessionSigningInvocation(arguments: arguments)) != nil else {
            throw NativeAgentHostVersionedSessionCommandError.invalidPayloads
        }
        self.executablePath = Self.executablePath
        self.arguments = arguments
    }
}
