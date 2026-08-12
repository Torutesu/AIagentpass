# ADR-002: Headless-first macOS distribution

Status: accepted

## Decision

AgentPass is distributed as a CLI and headless native service. The primary human interface is the Web Console. A visible macOS application is not required for normal installation, policy management, agent use, or audit review.

The signed release may retain a background-only `.app` service host because `SMAppService` expects managed helpers inside a main application bundle. That bundle is packaging and code-identity infrastructure, not the product's primary UI. It must not appear in the Dock or become an independent policy authority.

Distribution channels are:

1. source/npm and a Homebrew formula for local OSS evaluation;
2. a Developer ID-signed and notarized flat PKG for production;
3. MDM installation of the same verified PKG for managed fleets.

The PKG installs the background-only service host, privileged service, and bounded XPC client. The CLI and Git signing bridge are installed through the source/npm/Homebrew channel and verify the complete signed release before invoking the PKG installer. The privileged installer does not download Node.js or mutable executable code.

## Security consequences

- The native service remains the final authorization boundary.
- Web Console and Cloud can narrow or revoke authority but cannot widen local policy.
- Homebrew/source installs are evaluation channels and cannot claim the production XPC/code-identity boundary.
- A browser-only implementation is insufficient because browser code cannot be the local Git signing boundary.
- A Cloud KMS signer is a separate deployment profile and does not satisfy the local non-exportable-key promise.
- Uninstall is split into application removal and separately confirmed protected-state/key destruction.

## Product consequences

- Onboarding is implemented first as `agentpass install`, `agentpass setup`, `agentpass doctor`, and Web Console setup states.
- A future SwiftUI assistant may call the same installation state machine, but cannot introduce alternate authorization or key-management logic.
- Release qualification targets the PKG bytes and nested service components, not the presence of a GUI.
