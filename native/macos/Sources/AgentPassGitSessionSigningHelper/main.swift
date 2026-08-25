import AgentPassNativeCore
import Foundation

private func failClosed() -> Never {
    FileHandle.standardError.write(Data("agentpass-git-session-sign: signing unavailable\n".utf8))
    exit(1)
}

#if !AGENTPASS_GIT_SIGNING_HELPER_TESTING
do {
    try NativeAgentGitSigningHelper.runVersionedSession(
        arguments: Array(CommandLine.arguments.dropFirst()))
    exit(0)
} catch {
    failClosed()
}
#endif
