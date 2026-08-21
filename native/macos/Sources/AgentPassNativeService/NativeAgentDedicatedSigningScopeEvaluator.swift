import Foundation
import AgentPassNativeCore

/// Secret-free failures for the last-mile Git scope check.  The Cloud
/// signature proves what was issued; this evaluator proves that the current
/// OS-observed worktree is still inside that issued scope.
public enum NativeAgentDedicatedSigningScopeEvaluatorError: String, Error, Equatable, Sendable {
    case operationDenied = "operation_denied"
    case repositoryDenied = "repository_denied"
    case branchDenied = "branch_denied"
    case remoteDenied = "remote_denied"
    case remoteUnavailable = "remote_unavailable"
}

public enum NativeAgentDedicatedSigningScopeEvaluator {
    private static let operation = "git.commit.sign"

    /// Evaluates every observed remote, so an allowed `origin` cannot hide an
    /// additional unapproved remote in the same repository.
    public static func evaluate(
        capability: NativeAgentSigningCapabilityStatement,
        worktree: NativeAgentWorktreeBinding
    ) throws {
        guard capability.operation == operation,
              capability.keyPurpose == operation,
              capability.scope.operations == [operation] else {
            throw NativeAgentDedicatedSigningScopeEvaluatorError.operationDenied
        }

        let observedRepository = URL(fileURLWithPath: worktree.repositoryPath)
            .standardizedFileURL.path
        guard capability.scope.repositories.contains(where: { configured in
            URL(fileURLWithPath: configured).standardizedFileURL.path == observedRepository
        }) else {
            throw NativeAgentDedicatedSigningScopeEvaluatorError.repositoryDenied
        }

        guard case .branch(let branch) = worktree.head,
              allowed(branch, by: capability.scope.branches) else {
            throw NativeAgentDedicatedSigningScopeEvaluatorError.branchDenied
        }

        guard !worktree.remotes.isEmpty else {
            throw NativeAgentDedicatedSigningScopeEvaluatorError.remoteUnavailable
        }
        guard worktree.remotes.allSatisfy({ allowed($0.url, by: capability.scope.remotes) }) else {
            throw NativeAgentDedicatedSigningScopeEvaluatorError.remoteDenied
        }
    }

    private static func allowed(
        _ value: String,
        by rules: NativeAgentSigningCapabilityPatternSet
    ) -> Bool {
        !rules.deny.contains(where: { glob(value, matches: $0) })
            && rules.allow.contains(where: { glob(value, matches: $0) })
    }

    /// Bounded glob matching. Only `*` and `?` are metacharacters; every
    /// other character is matched literally, preventing regex injection.
    private static func glob(_ value: String, matches pattern: String) -> Bool {
        let value = Array(value.utf8)
        let pattern = Array(pattern.utf8)
        var row = Array(repeating: false, count: value.count + 1)
        row[0] = true
        for token in pattern {
            var next = Array(repeating: false, count: value.count + 1)
            if token == 42 { // '*'
                next[0] = row[0]
                for index in 1..<(value.count + 1) {
                    next[index] = row[index] || next[index - 1]
                }
            } else {
                for index in 1..<(value.count + 1) where row[index - 1]
                    && (token == 63 || token == value[index - 1]) {
                    next[index] = true
                }
            }
            row = next
        }
        return row[value.count]
    }
}
