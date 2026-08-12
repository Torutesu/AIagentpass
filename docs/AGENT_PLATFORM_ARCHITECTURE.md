# AgentPass Agent Platform Architecture

Status: implementation contract for the local-first agent platform

The normative implementation-level specification is [DETAILED_DESIGN.md](DETAILED_DESIGN.md). This document remains the concise architecture overview.

## 1. Security objective

AgentPass lets an enrolled coding-agent process request narrowly scoped cryptographic operations without receiving private key material. The device remains the final enforcement point. Cloud services may distribute policy and revocation state, but cannot compel a device to use a key or export one.

The initial supported privileged operation is `git.commit.sign`. Agent integrations expose policy and health information and guide agents to the existing Git signing path; they do not add a second signing implementation.

## 2. Trust boundaries

1. **Hardware boundary** — Secure Enclave or TPM-backed private keys. Keys are non-exportable.
2. **Native service** — validates signed agent identity, session, local policy, remote-control state, trusted Git context, and payload before asking hardware to sign.
3. **Local integration layer** — protocol library, CLI, MCP server, and editor adapters. This layer is untrusted with respect to key material and can only submit requests.
4. **Cloud control plane** — manages organizations, devices, policies, capabilities, revocations, and audit ingestion. Signed bundles are inputs to local enforcement, never an authorization bypass.
5. **Web Console** — a human control surface over the cloud API. It never receives device private keys or agent identity private keys.

## 3. Local request flow

```text
Claude Code / Cursor
        | MCP or shell
        v
AgentPass integration adapter
        | canonical request envelope
        v
Local broker / native service
        | identity + session + policy + revocation + Git validation
        v
Secure Enclave / TPM signing operation
        |
        +--> append-only local audit event --> optional cloud ingestion
```

Every privileged request fails closed when its identity, session, capability, policy, trusted local context, or remote-control freshness requirement cannot be established.

## 4. Protocol v1

All integration messages use JSON objects. Unknown fields are rejected at security-sensitive boundaries. Time values are RFC 3339 UTC strings; identifiers are opaque UUIDs.

### Agent descriptor

Required fields: `version`, `agent_id`, `name`, `kind`, `public_key`, `created_at`. `kind` is one of `claude-code`, `cursor`, `mcp`, `cli`, or `custom`.

### Capability

A capability is a signed, short-lived authorization envelope containing:

- issuer, organization, subject agent, and target device identifiers;
- an explicit list of operations;
- repository, branch, remote, and tag constraints;
- `not_before`, `expires_at`, and monotonic `sequence`;
- a unique capability identifier and nonce;
- detached Ed25519 signature and signing-key identifier.

Capabilities can only narrow local policy. The effective decision is the intersection of local policy, per-agent scope, capability scope, active session, and remote-control state.

### Decision

A decision contains `allowed`, a stable machine-readable `reason`, `operation`, `request_id`, and `evaluated_at`. Denials do not disclose secret material. Stable reasons allow agents to distinguish retryable states such as `session_required` from permanent policy denials.

### Audit event

Audit events include the request and agent identifiers, operation, decision, reason, policy/capability sequence, trusted repository context, payload digest, device timestamp, and hash-chain fields. Raw payloads, private keys, session tokens, and capability bearer values are prohibited.

## 5. Agent integration contract

The MCP server uses stdio JSON-RPC and exposes only bounded tools:

- `agentpass_status`: local broker, policy, session, and revocation summary;
- `agentpass_check`: evaluate whether a Git signing operation is currently allowed;
- `agentpass_setup`: return editor-specific setup instructions and configuration fragments;
- `agentpass_audit_tail`: return redacted recent decisions with a strict maximum count.

Signing remains Git-native: Claude Code and Cursor run `git commit`; Git invokes `agentpass-git-sign`; the helper sends the signed request to the broker. MCP never accepts arbitrary bytes to sign.

Adapters generate configuration for Claude Code and Cursor but do not overwrite user files without an explicit install command. Install is idempotent, preserves unrelated settings, uses absolute executable paths, and supports a dry run.

## 6. Cloud control plane contract

The cloud API is tenant-scoped and versioned under `/v1`. Its minimum resources are organizations, memberships, devices, agents, policies, capabilities, revocations, and audit events. Mutations require idempotency keys. Device endpoints authenticate with device-bound keys; browser endpoints authenticate humans and enforce organization roles.

Policy and revocation downloads are signed canonical bundles. Devices pin the control-plane signing key, reject sequence rollback, reject expired bundles, retain the last valid bundle for a bounded offline TTL, and fail closed after TTL expiration for cloud-required policies.

Audit ingestion is append-only, deduplicated by `(device_id, event_id)`, validates hash-chain continuity, and records gaps. The cloud cannot edit device evidence.

## 7. Web Console information architecture

The console has five primary surfaces:

1. Setup — install local service, enroll device, connect Claude Code or Cursor, and verify a signed test commit.
2. Agents — identity, device, last seen, capability expiry, and revoke/rotate actions.
3. Policies — plain-language templates with an advanced exact-scope editor and effective-policy preview.
4. Activity — allow/deny timeline, filters, reason explanations, chain/ingestion health, and export.
5. Emergency stop — explicit scope, confirmation, immediate signed revocation publication, and propagation status.

High-risk actions require reauthentication and produce immutable administrative audit events.

## 8. Repository layout

```text
packages/protocol/       canonical schemas and validation
packages/capability/     capability signing, verification, narrowing, replay defense
adapters/mcp-server/     stdio MCP integration
adapters/claude-code/    Claude Code configuration
adapters/cursor/         Cursor configuration
apps/cloud-api/          tenant API, bundle issuing, audit ingestion
apps/web-console/        human control surface
native/macos/            protected enforcement and key use
```

The root package continues to ship the local CLI and Git helper. New packages use Node 20 ESM and the built-in test runner until a workspace build system is justified.

## 9. Delivery sequence and gates

1. Local agent platform: protocol, capability verification, MCP, Claude/Cursor setup, and end-to-end signed-commit tests.
2. Cloud foundation: tenant model, authenticated device enrollment, signed policy/revocation bundles, and audit ingestion.
3. Web Console: guided setup, agent/policy/activity views, and emergency stop.
4. Production hardening: WebAuthn/SSO, rate limits, retention/export, HA, key rotation, threat-model update, and independent audit.

Each phase must pass unit tests, integration tests, package validation, dependency/security review, and fail-closed negative tests before the next phase is considered complete.
