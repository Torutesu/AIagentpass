# Authenticated Host XPC bridge

AgentPass now has a dedicated Host Mach service, `dev.agentpass.agent-host`, separate from the existing Agent activation service.

The intended lifecycle is:

```text
prepare -> attach child -> sign payload (max 2) -> status/close
```

The service binds each accepted connection to the observed peer process and revalidates that process before every protected operation. Child attachment compares independently observed process identity, ancestry, and Git worktree binding against the request hints. The request itself is never treated as an authority source.

## Configuration

`host_mach_service_name` must be `dev.agentpass.agent-host` and must be present in the launchd `MachServices` dictionary.

`host_child_code_directory_hash` is the SHA-256 code-directory hash of the allowed child executable. It is intentionally `null` in the example configuration: when it is absent, the Host listener rejects connections rather than enabling an unqualified child signer.

Before enabling the Host path in production, provision this hash from an independently verified signed artifact and configure the corresponding worktree and runtime policy. Do not populate it from an XPC request, argv, or environment variable.

## Current security boundary

The listener and endpoint are fail-closed adapters. The existing inherited-FD3 Git bridge is still present for the legacy lifecycle and remains a migration blocker. It must not be considered replaced until the child supervisor and Git helper use this XPC path end-to-end and the FD3 fallback is removed.

The local proof currently covers the Core state machine, endpoint adapter, Host listener build, contract validation, and runtime materializer tests. It does not prove macOS audit-token extraction, Developer ID/notarization, real launchd behavior, or production child provisioning.
