import Foundation
import Testing
@testable import AgentPassNativeCore

private let planAgentID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

private func planHandoff() throws -> NativeAgentLaunchAuthorityHandoff {
    let proof = try NativeStrictJSON.data(["version": 1, "nonce": "AAAAAAAAAAAAAAAAAAAAAA"])
    return try NativeAgentLaunchAuthorityHandoff(
        agentID: planAgentID,
        agentKind: .claudeCode,
        requestedTTLSeconds: 600,
        proof: proof
    )
}

private struct FailingPlanAdapter: NativeAgentHostLifecycleAdapter {
    func hooks(for _: NativeAgentHostLaunchPlan) throws -> NativeAgentHostLifecycleCoordinatorHooks {
        throw NativeAgentHostLifecycleAdapterError.unavailable
    }
}

@Test func launchPlanBindsProjectPathAndForcesAuthenticatedXPC() throws {
    let plan = try NativeAgentHostLaunchPlan(projectPath: "/tmp/project", authorityHandoff: planHandoff())
    #expect(plan.projectPath == "/tmp/project")
    #expect(plan.gitTransport == .authenticatedXPC)
}

@Test func launchPlanRejectsPathEscapesAndOversizedInput() throws {
    #expect(throws: NativeAgentHostLaunchPlanError.invalidProjectPath) {
        try NativeAgentHostLaunchPlan(projectPath: "/tmp/../project", authorityHandoff: planHandoff())
    }
    #expect(throws: NativeAgentHostLaunchPlanError.invalidProjectPath) {
        try NativeAgentHostLaunchPlan(
            projectPath: "/" + String(repeating: "p", count: NativeAgentHostLaunchPlan.maximumProjectPathBytes),
            authorityHandoff: planHandoff()
        )
    }
}

@Test func unavailableServiceAdapterFailsBeforeCoordinatorBootstrap() throws {
    let plan = try NativeAgentHostLaunchPlan(projectPath: "/tmp/project", authorityHandoff: planHandoff())
    let connection = try NativeAgentHostConnectionBinding(connectionID: "host-test", agentID: planAgentID)
    let runtime = try NativeAgentHostRuntime(
        plan: plan,
        connection: connection,
        supervisor: NativeAgentHostChildSupervisor(hooks: .system),
        adapter: FailingPlanAdapter()
    )
    #expect(throws: NativeAgentHostLifecycleAdapterError.unavailable) {
        _ = try runtime.start()
    }
}
