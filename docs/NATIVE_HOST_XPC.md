# Authenticated Host XPC bridge

AgentPass now has a dedicated Host Mach service, `dev.agentpass.agent-host`, and a child signing service, `dev.agentpass.child-git`, separate from the existing Agent activation service.

The intended lifecycle is:

```text
prepare -> attach child -> sign payload (max 2) -> status/close
```

The service binds each accepted connection to the observed peer process and revalidates that process before every protected operation. Child attachment compares independently observed process identity, ancestry, and Git worktree binding against the request hints. The request itself is never treated as an authority source.

The child channel is registered only by a successful Host attach. A child connection with no matching process-binding hash and worktree digest is rejected. Each helper invocation uses a one-shot child connection; duplicate payload digests and attempts after the two-signature budget are rejected.

`NativeAgentAuthenticatedHostXPCClient` is the connection-owned Core client for
the Host Mach service. It exposes only `prepare`, `attach`, `sign`, `status`,
and `close`; the service-assigned session ID is retained as connection state
and is never accepted as a request field. The client has no FD3 or local
signing fallback.

## Configuration

`host_mach_service_name` must be `dev.agentpass.agent-host` and must be present in the launchd `MachServices` dictionary.

`child_mach_service_name` must be `dev.agentpass.child-git` and must also be present in `MachServices`.

`host_child_code_directory_hash` is the SHA-256 code-directory hash of the allowed child executable. It is intentionally `null` in the example configuration: when it is absent, the Host listener rejects connections rather than enabling an unqualified child signer.

Before enabling the Host path in production, provision this hash from an independently verified signed artifact and configure the corresponding worktree and runtime policy. Do not populate it from an XPC request, argv, or environment variable.

## Current security boundary

The listener, registry, and endpoint are fail-closed adapters. The Git helper has an authenticated-XPC client path, but the legacy inherited-FD3 path is still the default lifecycle path and remains a migration blocker. It must not be considered replaced until the child supervisor selects the XPC mode end-to-end and the FD3 fallback is removed.

The local proof currently covers the Core state machine, endpoint adapter,
Host client/listener builds, contract validation, and runtime materializer
tests. The client is now available for lifecycle wiring, but production still
defaults to the legacy path until a signed-artifact, real-launchd end-to-end
run proves Host prepare/attach and child Git signing together. Local tests do
not prove macOS audit-token extraction, Developer ID/notarization, real
launchd behavior, or production child provisioning.
