import Foundation

/// The only Host launch input accepted by the runtime slice.
///
/// The authority handoff remains the existing private, one-use document. The
/// project path is carried separately and is immediately converted to the
/// descriptor-bound project directory before a child can be started. There is
/// no executable, argv, shell, or Git transport selector in this value.
public struct NativeAgentHostLaunchPlan: Equatable, Sendable {
    public static let maximumProjectPathBytes = 4_096

    public let projectPath: String
    public let authorityHandoff: NativeAgentLaunchAuthorityHandoff

    public init(
        projectPath: String,
        authorityHandoff: NativeAgentLaunchAuthorityHandoff
    ) throws {
        guard !projectPath.isEmpty,
              projectPath.utf8.count <= Self.maximumProjectPathBytes,
              !projectPath.contains("\0"),
              projectPath.hasPrefix("/"),
              projectPath != "/",
              !projectPath.hasSuffix("/") else {
            throw NativeAgentHostLaunchPlanError.invalidProjectPath
        }
        let components = projectPath.split(separator: "/", omittingEmptySubsequences: false)
        guard components.first?.isEmpty == true,
              components.dropFirst().allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw NativeAgentHostLaunchPlanError.invalidProjectPath
        }
        self.projectPath = projectPath
        self.authorityHandoff = authorityHandoff
    }

    /// Host policy is closed: every launch uses the authenticated XPC child
    /// signer. Callers cannot select legacy FD3 through the launch plan.
    public var gitTransport: NativeAgentHostGitTransport { .authenticatedXPC }

    public func projectDirectory(
        hooks: NativeAgentHostProjectDirectoryHooks = .system
    ) throws -> NativeAgentHostProjectDirectory {
        try NativeAgentHostProjectDirectory(path: projectPath, hooks: hooks)
    }
}

public enum NativeAgentHostLaunchPlanError: Error, Equatable, Sendable {
    case invalidProjectPath
}
