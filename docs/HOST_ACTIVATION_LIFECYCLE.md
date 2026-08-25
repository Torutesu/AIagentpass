# Host activation projection and child lifecycle

This note records the native Host contract covered by the focused tests. It
does not claim a real launchd, notarized artifact, or production macOS gate.

## Activation projection

The service returns `NativeAgentHostQualifiedSessionActivation`. The Host-side
stable lifecycle projection is only:

```text
(sessionID, binding.agentID, binding.deviceID)
```

The projection does not carry process identity, ancestry, worktree digests,
proofs, credentials, authority counters, or a child process handle. The Host
must validate the returned agent/device binding before pinning it, and must
reuse the pinned identity for later observe, close, and rollback operations.

Coverage: `NativeAgentHostActivationProjectionTests.swift` and
`NativeAgentHostLifecycleCoordinatorTests.swift`.

## Authenticated child lifecycle

For `authenticatedXPC`, the required ordering is:

```text
prepare -> spawn -> independent observe(child PID) -> attach
```

Prepare is connection-owned and must complete before spawn. After spawn, the
Host independently observes the child process and worktree; it converts the
canonical identity projections to the exact digest bytes required by the XPC
attach DTO. Only then may it attach the child. Observation or attach failure
terminates and reaps the child and closes the XPC client; there is no fallback
to the legacy FD3 transport.

Coverage: `NativeAgentHostChildSupervisorTests.swift`, especially
`authenticatedXPCLifecycleIsPrepareSpawnIndependentObserveAttach` and the
negative prepare/observation/attach tests.

## Evidence boundary

These are focused contract tests using injected process/XPC seams. They prove
ordering, projection, digest forwarding, and bounded cleanup in the native
Core. They do not prove real Mach service registration, launchd behavior,
audit-token extraction, signed/notarized executable identity, or a real child
process.
