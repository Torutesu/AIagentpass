import Foundation

/// The complete service-side activation projection required by the Host
/// coordinator. This deliberately stays an adapter seam until the existing
/// Agent service XPC response carries the device binding as well as the
/// session correlation fields.
public protocol NativeAgentHostLifecycleAdapter: Sendable {
    func hooks(for plan: NativeAgentHostLaunchPlan) throws -> NativeAgentHostLifecycleCoordinatorHooks
}

public enum NativeAgentHostLifecycleAdapterError: Error, Equatable, Sendable {
    case unavailable
}

/// A Host-only runtime wrapper. It fixes the transport at authenticated XPC
/// and refuses to construct a lifecycle coordinator without a complete,
/// authenticated service adapter.
public final class NativeAgentHostRuntime: @unchecked Sendable {
    private let plan: NativeAgentHostLaunchPlan
    private let connection: NativeAgentHostConnectionBinding
    private let supervisor: NativeAgentHostChildSupervisor
    private let adapter: any NativeAgentHostLifecycleAdapter
    private let gitTransport: NativeAgentHostGitTransport

    public init(
        plan: NativeAgentHostLaunchPlan,
        connection: NativeAgentHostConnectionBinding,
        supervisor: NativeAgentHostChildSupervisor,
        adapter: any NativeAgentHostLifecycleAdapter,
        gitTransport: NativeAgentHostGitTransport = .authenticatedXPC
    ) throws {
        guard connection.agentID == plan.authorityHandoff.agentID else {
            throw NativeAgentHostLifecycleError.invalidHandoff
        }
        self.plan = plan
        self.connection = connection
        self.supervisor = supervisor
        self.adapter = adapter
        self.gitTransport = gitTransport
    }

    public func makeCoordinator() throws -> NativeAgentHostLifecycleCoordinator {
        try NativeAgentHostLifecycleCoordinator(
            connectionBinding: connection,
            handoff: plan.authorityHandoff,
            supervisor: supervisor,
            hooks: try adapter.hooks(for: plan),
            gitTransport: gitTransport
        )
    }

    /// Constructs the only Agent-facing command allowed to use the
    /// versioned two-payload session. Process execution remains owned by the
    /// supervised Host/Agent boundary; this method only returns the frozen
    /// executable and argv projection.
    public func makeVersionedSessionCommand(
        payloadPaths: [String]
    ) throws -> NativeAgentHostVersionedSessionCommand {
        try NativeAgentHostVersionedSessionCommand(payloadPaths: payloadPaths)
    }

    public func start() throws -> NativeAgentHostLifecycleCoordinator {
        let coordinator = try makeCoordinator()
        _ = try coordinator.bootstrap()
        _ = try coordinator.start(projectDirectory: try plan.projectDirectory())
        return coordinator
    }
}

/// Until the Service contract exposes the full `NativeAgentSessionBinding`,
/// production Host wiring must fail closed rather than inventing a device ID
/// or projecting a partial activation.
public struct NativeAgentHostUnavailableLifecycleAdapter: NativeAgentHostLifecycleAdapter {
    public init() {}

    public func hooks(for _: NativeAgentHostLaunchPlan) throws -> NativeAgentHostLifecycleCoordinatorHooks {
        throw NativeAgentHostLifecycleAdapterError.unavailable
    }
}
