import Foundation
import Testing
@testable import AgentPassNativeCore
@testable import AgentPassNativeService

private func scopeWorktree(
    head: NativeAgentGitHead = .branch("feature/native"),
    remotes: [NativeAgentGitRemote] = [try! NativeAgentGitRemote(name: "origin", url: "git@example.test:repo.git")]
) throws -> NativeAgentWorktreeBinding {
    let repository = try NativeAgentWorktreeDirectoryIdentity(
        device: 1, inode: 20, generation: 1, ownerUserID: 501, permissions: 0o755)
    let git = try NativeAgentWorktreeDirectoryIdentity(
        device: 1, inode: 21, generation: 1, ownerUserID: 501, permissions: 0o755)
    return try NativeAgentWorktreeBinding(
        layout: .embedded,
        repositoryPath: "/work/repo",
        gitDirectoryPath: "/work/repo/.git",
        commonDirectoryPath: "/work/repo/.git",
        repositoryIdentity: repository,
        gitDirectoryIdentity: git,
        commonDirectoryIdentity: git,
        objectFormat: .sha1,
        head: head,
        headObjectID: String(repeating: "a", count: 40),
        headTreeID: String(repeating: "b", count: 40),
        remotes: remotes)
}

private func scopedStatement(
    branches: NativeAgentSigningCapabilityPatternSet = try! NativeAgentSigningCapabilityPatternSet(allow: ["feature/*"], deny: []),
    remotes: NativeAgentSigningCapabilityPatternSet = try! NativeAgentSigningCapabilityPatternSet(allow: ["git@example.test:*"], deny: [])
) throws -> NativeAgentSigningCapabilityStatement {
    try NativeAgentSigningCapabilityStatement(
        capabilityID: "55555555-5555-4555-8555-555555555555",
        sessionID: "44444444-4444-4444-8444-444444444444",
        organizationID: "11111111-1111-4111-8111-111111111111",
        deviceID: "22222222-2222-4222-8222-222222222222",
        agentID: "33333333-3333-4333-8333-333333333333",
        scope: try NativeAgentSigningCapabilityScope(
            operations: ["git.commit.sign"],
            repositories: ["/work/repo"],
            branches: branches,
            remotes: remotes),
        keyID: "git-commit-signing-v1",
        issuedAt: "2026-08-20T00:00:00.000Z",
        notBefore: "2026-08-20T00:00:00.000Z",
        expiresAt: "2026-08-20T00:01:00.000Z",
        sequence: 1,
        controlSequence: 1,
        authorityGeneration: 1)
}

@Test("Dedicated scope evaluator accepts the observed repository, branch, and every remote")
func dedicatedScopeEvaluatorAcceptsObservedState() throws {
    try NativeAgentDedicatedSigningScopeEvaluator.evaluate(
        capability: scopedStatement(), worktree: try scopeWorktree())
}

@Test("Dedicated scope evaluator rejects repository, branch, and remote drift")
func dedicatedScopeEvaluatorRejectsScopeDrift() throws {
    #expect(throws: NativeAgentDedicatedSigningScopeEvaluatorError.repositoryDenied) {
        let statement = try scopedStatement()
        let worktree = try scopeWorktree()
        let changed = try NativeAgentWorktreeBinding(
            layout: worktree.layout,
            repositoryPath: "/work/other",
            gitDirectoryPath: "/work/other/.git",
            commonDirectoryPath: "/work/other/.git",
            repositoryIdentity: worktree.repositoryIdentity,
            gitDirectoryIdentity: worktree.gitDirectoryIdentity,
            commonDirectoryIdentity: worktree.commonDirectoryIdentity,
            objectFormat: worktree.objectFormat,
            head: worktree.head,
            headObjectID: worktree.headObjectID,
            headTreeID: worktree.headTreeID,
            remotes: worktree.remotes)
        try NativeAgentDedicatedSigningScopeEvaluator.evaluate(capability: statement, worktree: changed)
    }

    #expect(throws: NativeAgentDedicatedSigningScopeEvaluatorError.branchDenied) {
        try NativeAgentDedicatedSigningScopeEvaluator.evaluate(
            capability: scopedStatement(), worktree: try scopeWorktree(head: .branch("main")))
    }

    #expect(throws: NativeAgentDedicatedSigningScopeEvaluatorError.remoteDenied) {
        let remote = try NativeAgentGitRemote(name: "backup", url: "https://evil.example/repo.git")
        try NativeAgentDedicatedSigningScopeEvaluator.evaluate(
            capability: scopedStatement(), worktree: try scopeWorktree(remotes: [remote]))
    }
}

@Test("Dedicated scope evaluator rejects detached heads and repositories without remotes")
func dedicatedScopeEvaluatorRejectsMissingGitAuthority() throws {
    #expect(throws: NativeAgentDedicatedSigningScopeEvaluatorError.branchDenied) {
        try NativeAgentDedicatedSigningScopeEvaluator.evaluate(
            capability: scopedStatement(),
            worktree: try scopeWorktree(head: .detached(String(repeating: "a", count: 40))))
    }
    #expect(throws: NativeAgentDedicatedSigningScopeEvaluatorError.remoteUnavailable) {
        try NativeAgentDedicatedSigningScopeEvaluator.evaluate(
            capability: scopedStatement(), worktree: try scopeWorktree(remotes: []))
    }
}
