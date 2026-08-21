import Foundation

/// The Git configuration injected into every supervised Claude child.
///
/// These values are Host-owned launch policy, not caller-provided environment
/// entries. Keeping them in one closed value object makes it impossible for a
/// launch request to select a different helper, signer reference, namespace,
/// or signing format. The installed path is a packaging contract; until the
/// signed/notarized distribution exists, a missing helper fails Git closed.
public enum NativeAgentHostGitConfiguration {
    public static let helperExecutablePath = "/Applications/AgentPass.app/Contents/Resources/bin/agentpass-git-sign"
    public static let authenticatedXPCHelperExecutablePath = "/Applications/AgentPass.app/Contents/Resources/bin/agentpass-git-sign-xpc"
    public static let signerReference = NativeAgentGitSigningInvocation.fixedSignerReference

    /// The exact environment entries consumed by Git's supported command-line
    /// config mechanism. The caller cannot override any key because the
    /// supervisor appends these after copying its small trusted allowlist.
    public static var environment: [String: String] {
        [
            "GIT_CONFIG_COUNT": "4",
            "GIT_CONFIG_KEY_0": "gpg.format",
            "GIT_CONFIG_VALUE_0": "ssh",
            "GIT_CONFIG_KEY_1": "gpg.ssh.program",
            "GIT_CONFIG_VALUE_1": helperExecutablePath,
            "GIT_CONFIG_KEY_2": "user.signingkey",
            "GIT_CONFIG_VALUE_2": signerReference,
            "GIT_CONFIG_KEY_3": "commit.gpgsign",
            "GIT_CONFIG_VALUE_3": "true",
        ]
    }

    /// The same closed Git configuration pointing at the child XPC helper.
    /// This is an explicit mode and never falls back to inherited FD3.
    public static var authenticatedXPCEnvironment: [String: String] {
        var values = environment
        values["GIT_CONFIG_VALUE_1"] = authenticatedXPCHelperExecutablePath
        return values
    }
}
