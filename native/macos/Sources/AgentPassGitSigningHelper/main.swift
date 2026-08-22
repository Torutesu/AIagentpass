import AgentPassNativeCore
import Foundation

private func failClosed() -> Never {
    FileHandle.standardError.write(Data("agentpass-git-sign: signing unavailable\n".utf8))
    exit(1)
}

#if !AGENTPASS_GIT_SIGNING_HELPER_TESTING
do {
    let arguments = Array(CommandLine.arguments.dropFirst())
    // This executable is Git's one-payload gpg.ssh.program. The versioned
    // two-payload protocol has a separate binary and must never be selected
    // by an overloaded or ambiguous Git invocation.
    try NativeAgentGitSigningHelper.run(arguments: arguments)
    exit(0)
} catch {
    failClosed()
}
#endif
