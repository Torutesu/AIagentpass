# AgentPass Detailed Design

Status: implementation-ready design baseline
Target release: `0.18.x` local platform, followed by the hosted control plane
Primary platform: macOS 14 or later; Windows TPM and Linux TPM follow the same protocol in later releases

## 1. Product definition

AgentPass is a local-first authorization and signing broker for coding agents. It allows an enrolled Claude Code, Cursor, or compatible MCP client to perform a narrowly defined cryptographic operation without receiving private key material and without requiring biometric confirmation for every operation.

The first supported privileged operation is intentionally limited to:

```text
git.commit.sign
```

Git push credentials, arbitrary SSH authentication, arbitrary byte signing, cloud API secrets, and general-purpose password retrieval are not part of v1. They have different exfiltration risks and must not be smuggled through the Git signing interface.

The product promise is therefore:

> An agent may sign an allowed Git commit while the human is away, but it cannot extract the key, use the signer for another protocol, exceed the repository policy, or hide the operation from the audit trail.

## 2. Design principles

1. **The endpoint decides.** Cloud policy can narrow or revoke access but cannot widen the local policy or force key use.
2. **No general signing oracle.** The native service parses and validates a Git commit before invoking the hardware key.
3. **Authority is short-lived.** Long-lived identity proves who the agent is; a short-lived session and capability prove what it may do now.
4. **Every layer may only narrow.** Effective access is the intersection of local policy, agent policy, cloud policy, capability, session state, and emergency controls.
5. **Offline behavior is explicit.** Local-only users continue safely. Cloud-required organizations fail closed after a bounded offline window.
6. **Audit is part of authorization.** The service durably records an authorization intent before key use and a result after key use. If the chain cannot be appended, privileged operations fail closed.
7. **Usability is a security control.** Setup, denial reasons, recovery, and emergency stop must be understandable without reading configuration files.

## 3. Security claim and non-claims

### 3.1 Claims

- The Git signing private key is generated in Secure Enclave and is non-exportable.
- AgentPass never writes the private key to a file, sends it to the cloud, or exposes a raw signing API.
- A valid request is restricted to a trusted repository, branch, remote, operation, agent, device, time window, and replay state.
- A cloud compromise cannot widen an endpoint's local authorization.
- A stolen cloud database does not contain endpoint signing keys or plaintext API tokens.
- Local and administrative decisions are recorded in append-only, hash-linked audit streams.

### 3.2 Non-claims

- v1 does not fully isolate an authorized coding agent from malicious code executing inside that same agent's process tree. Code run by the agent inherits the agent's authority for the session.
- Secure Enclave prevents key extraction; by itself it does not prevent unauthorized signing. Policy enforcement must happen before the hardware call.
- v1 does not defend a device after root compromise, native service replacement, or a compromised operating-system trust chain.
- MCP prompts, CLAUDE.md files, and model instructions are not trusted security boundaries.
- Commit signing does not prove that commit content is safe, reviewed, or free of secrets.

These limits must appear in the README and security documentation so “hardware-backed” is not interpreted as “immune to local malware.”

## 4. Threat model

### 4.1 Protected assets

- Git signing private key and key handle
- Agent identity and active session authority
- Local and cloud policy integrity
- Revocation freshness
- Audit completeness and ordering
- Organization and device separation
- Repository identity and commit payload integrity

### 4.2 Adversaries

| Adversary | Example | Required defense |
| --- | --- | --- |
| Malicious repository | prompt injection, poisoned hook, symlink tree | never trust repository config or paths; canonicalize from Git; no arbitrary command execution |
| Unenrolled local process | another tool under the same user | authenticated session, capability, peer/process checks, strict socket permissions |
| Compromised agent session | agent runs malicious dependency | narrow repo/branch/time scope, no push, audit, immediate revocation |
| Network attacker | TLS interception, replay, redirect | HTTPS, no redirects, signed bundles, device signatures, nonce/timestamp replay cache |
| Compromised cloud | malicious policy or database write | pinned signing key, local intersection, sequence/expiry checks |
| Malicious tenant | cross-organization identifiers | tenant-qualified lookups and non-disclosing authorization failures |
| Stolen laptop while locked | offline use attempt | OS data protection, service lifecycle rules, optional lock-triggered session invalidation |
| Rollback attacker | restores older bundle or state file | monotonic sequence plus persisted statement hash; same-sequence equivocation rejection |

### 4.3 Explicit abuse cases

The test suite must include at least these cases:

- replace a repository directory with a symlink after policy evaluation;
- supply `../` traversal or a non-canonical repository path;
- use a valid capability for another agent, device, organization, operation, or repository;
- replay a request, capability nonce, device nonce, or idempotency key with different content;
- provide a same-sequence bundle with a different hash;
- omit branch, remote, or tag data to bypass a deny rule;
- request `ssh`, `file`, `x509`, or another namespace through the Git signer;
- sign a payload that is not the exact Git commit object at the trusted repository's current index state;
- continue after emergency stop, device revocation, stale cloud state, audit append failure, or clock anomaly;
- poison PATH, MCP configuration, Git config, environment variables, or executable lookup;
- return oversized, deeply nested, duplicate-key, or unknown-field JSON.

## 5. Trust boundaries and components

```text
Human / Web Console
        |
        | authenticated administrative intent
        v
Cloud API ---- signed policy/revocation bundle ----+
        ^                                          |
        | device-signed redacted audit batches     |
        |                                          v
Claude Code / Cursor                         Local control cache
        | MCP status/setup                         |
        | git commit                               |
        v                                          v
Git -> agentpass-git-sign -> AgentPass client -> Native service
                                   |                  |
                                   | XPC/IPC          | policy + session + Git validation
                                   v                  v
                              OS process facts   Secure Enclave signing key
                                                      |
                                                      v
                                               hash-linked local audit
```

### 5.1 Native service

The native service is the final enforcement point. It owns or can access:

- Secure Enclave key references;
- trusted local configuration;
- session generation and revocation state;
- highest accepted cloud sequence and statement hash;
- replay caches;
- local audit chain head.

It must not load policy, helper executables, provider libraries, or Git from repository-relative paths. Executables and the SSH security-key provider use fixed absolute paths and are validated before execution.

### 5.2 Local client and Git helper

The helper translates Git's SSH signing invocation into the fixed `git.commit.sign` request. It never decides access and never receives key bytes. It must:

- accept only the exact Git SSH signing argument shape;
- reject unknown flags, namespaces other than `git`, and alternate signers;
- read a bounded payload;
- connect only to the configured local endpoint;
- avoid printing session or capability material;
- preserve Git-compatible stdout/stderr and exit behavior.

### 5.3 MCP adapter

MCP is a usability and observability integration, not the signing path. Its v1 tools are:

- `agentpass_status`
- `agentpass_check`
- `agentpass_setup`
- `agentpass_audit_tail`

MCP does not expose `sign`, shell execution, secret retrieval, policy mutation, or arbitrary file reads. Tool inputs and outputs are bounded and reject unknown fields.

### 5.4 Cloud control plane

The cloud stores organization metadata, human authorization, device/agent public identities, versioned policy, revocations, and redacted audit copies. It signs authorization data but does not hold endpoint signing keys.

### 5.5 Web Console

The console is a human control surface over the cloud API. Cloud API credentials remain server-side. Browser code receives only redacted resource data and uses same-origin routes.

## 6. Identity and session model

### 6.1 Identity types

| Identity | Key type | Lifetime | Storage |
| --- | --- | --- | --- |
| Device identity | Ed25519, or P-256 platform key | device lifetime | Dedicated Keychain/Secure Enclave/TPM binding; non-exportable where supported |
| Git signing identity | Secure Enclave P-256 | device lifetime | Secure Enclave only |
| Agent identity | Ed25519 | until rotated/revoked | protected local store; public key registered locally/cloud |
| Cloud bundle signer | Ed25519 | rotation epoch | offline/HSM-backed control-plane key |
| Human identity | WebAuthn/IdP; API token only for self-hosted bootstrap | account lifetime | identity provider; token hashes server-side |

Device identity and Git signing identity are separate keys. Rotation or compromise of one must not silently change the other.

### 6.2 Agent launch and process binding

The preferred autonomous launch path is:

```bash
agentpass run --agent <agent-id> -- claude
```

`agentpass run` requests a short-lived session from the native service and launches the agent as a child. Session authority is delivered through an inherited file descriptor or private per-session IPC channel, not a plaintext file or command-line argument. The service records the launcher PID, child process group, executable identity, start time, and session generation.

Requests are accepted only when all available platform facts agree:

- the request is signed by the enrolled agent identity;
- the active session belongs to that agent;
- the peer PID is in the enrolled process tree or uses a one-time delegated request token;
- the session generation has not been invalidated;
- the capability audience includes the agent and device.

Cursor GUI integration cannot reliably inherit a CLI file descriptor. It uses a locally enrolled MCP/client channel with a short-lived session issued after explicit setup. The console must label this as a broader “Cursor application session” rather than implying per-tab isolation.

### 6.3 Session lifecycle

```text
absent -> issued -> active -> expiring -> expired
                    |  |          |
                    |  +----------+-> renewed
                    +-> revoked
                    +-> invalidated by policy/key/service generation change
```

Defaults:

- session TTL: 8 hours;
- capability TTL: 15 minutes;
- renewal begins at 20% remaining lifetime;
- lock invalidation: configurable, on by default for interactive agents and optional for unattended sessions;
- restart behavior: sessions do not survive native service restart;
- idle timeout: 30 minutes by default, with an explicit unattended profile allowing up to 8 hours.

An unattended profile is a policy choice made before the human leaves. It does not mean unlimited device authority.

## 7. Authorization model

### 7.1 Effective policy

For request `r`:

```text
effective_scope =
  local_device_scope
  ∩ local_agent_scope
  ∩ cloud_policy_scope (when configured)
  ∩ capability_scope

allow(r) =
  service_healthy
  ∧ audit_writable
  ∧ agent_identity_valid
  ∧ session_valid
  ∧ capability_valid_and_unused
  ∧ remote_control_fresh
  ∧ not_revoked
  ∧ trusted_git_context
  ∧ effective_scope_matches(r)
  ∧ commit_payload_valid
```

Empty intersection means deny. Missing data required by any configured constraint means deny.

### 7.2 Scope fields

```json
{
  "operations": ["git.commit.sign"],
  "repositories": ["/absolute/canonical/path"],
  "branches": { "allow": ["feature/*"], "deny": ["main", "release/*"] },
  "remotes": { "allow": ["git@github.com:org/repo.git"], "deny": [] },
  "tags": { "allow": [], "deny": ["*"] }
}
```

Rules:

- Repository paths are absolute, canonical, and contain no traversal or unresolved symlink components.
- Pattern matching is anchored to the full value. No regular expressions are accepted from users.
- Deny wins inside one scope. Intersection then applies across scopes.
- The only v1 operation is `git.commit.sign`.
- Missing tags are denied when a tag rule exists.
- Remotes are normalized conservatively; ambiguous URL rewrites are not treated as equivalent.

### 7.3 Decision order

Checks run in an order that minimizes information disclosure and cost:

1. framing, size, and schema;
2. request timestamp and replay identifier;
3. agent identity and session;
4. global/device/agent revocation;
5. cloud freshness and sequence;
6. trusted repository context;
7. scope intersection;
8. commit object validation;
9. durable audit intent append;
10. hardware signing;
11. durable audit result append;
12. response.

The externally returned reason is stable but less detailed than the internal audit reason where disclosure would reveal tenant or policy information.

### 7.4 Authorization transaction

Authorization and hardware use cannot be one database transaction, so the audit protocol is explicitly two-phase:

1. Append and sync an `authorized_intent` event containing the request ID, trusted context digest, policy/capability sequence, and payload digest.
2. Invoke the hardware signer through a durable operation ledger. A provider
   with authoritative operation lookup may prove one accepted operation; a
   direct deterministic Ed25519 API may be called at least once after an
   ambiguous response, but every attempt is pinned to the same key and bytes.
3. Append and sync `allow`, `deny`, or `error` as a result event referencing the intent.
4. Return the signature only after the `allow` result is durable.

If step 1 fails, the key is not used. If step 3 fails, the signature is withheld
and the unresolved intent remains visible for recovery. Retrying the same
request ID first reconciles any persisted verified result. Where the provider
has no authoritative lookup, a retry may invoke deterministic Ed25519 signing
again only with the exact pinned key, purpose, key version, request digest, and
bytes; AgentPass still commits and returns only one verified result. On startup,
unresolved intents are surfaced as `outcome_unknown` incidents and do not
disappear through log rotation.

This protocol proves that key use was authorized or that its outcome is unknown. It cannot make an external hardware operation atomically roll back, so documentation must not claim stronger transactional semantics.

## 8. Git signing protocol

### 8.1 Trusted context

The service derives, rather than trusts from the caller:

- repository root via fixed-path Git invocation;
- current branch or detached state;
- origin remote;
- index tree hash;
- current HEAD and merge parents;
- worktree/common-directory relationship.

Caller-provided `cwd`, branch, remote, tree, or parent values are assertions to compare with trusted values, not authoritative inputs.

### 8.2 Commit validation

The payload must be one complete canonical Git commit object body with bounded size. The validator requires:

- exactly one `tree` line matching the trusted index tree;
- zero or more `parent` lines matching trusted HEAD/merge state in order;
- no existing `gpgsig` header;
- valid header continuation rules;
- a blank separator before the message;
- no NUL bytes or trailing second object;
- expected encoding and maximum byte count;
- no tag object or arbitrary SSH challenge.

The signer is invoked only as the equivalent of:

```text
/usr/bin/ssh-keygen -Y sign -n git -f <configured non-exportable key reference>
```

with the fixed platform provider. Caller-controlled environment variables are removed or replaced with an allowlist.

### 8.3 Time-of-check/time-of-use

Immediately before signing, the service re-reads the trusted Git context. If repository identity, index tree, HEAD, merge state, branch, or remote changed since validation, the request fails with `policy_changed` or `git_context_changed`. The audit records both request ID and trusted context digest.

## 9. Capability format

A capability is a signed authorization statement, not a secret value by itself. Possession is still sensitive because it enables a request during its lifetime.

Required statement fields:

```json
{
  "version": 1,
  "capability_id": "uuid",
  "issuer": "opaque-id",
  "organization_id": "uuid",
  "subject_agent_id": "uuid",
  "audience": { "device_id": "uuid" },
  "scope": {},
  "not_before": "RFC3339 UTC",
  "expires_at": "RFC3339 UTC",
  "sequence": 42,
  "nonce": "base64url-32-or-more-bytes",
  "key_id": "opaque-id"
}
```

The detached Ed25519 signature covers canonical JSON bytes. Verification rejects unknown fields, aliases, non-canonical timestamps, overlong TTLs, unknown keys, wrong audience, rollback, same-sequence different content, and replayed nonce/capability IDs.

Capabilities are transported in request framing or a protected local channel. They are never printed by `status`, MCP, logs, shell tracing, or Web Console responses.

## 10. Local storage

Default directory: `~/Library/Application Support/AgentPass` on macOS. Every directory is owned by the current user or root as appropriate and is not group/world writable.

| Artifact | Owner/mode | Durability | Notes |
| --- | --- | --- | --- |
| local policy | user, `0600` | atomic replace | schema-versioned; digest bound to service state |
| agent public records | user, `0600` | atomic replace | no private signing key |
| session state | native service | memory-first | token hashes only; invalid after restart |
| cloud bundle | user/service, `0600` | atomic replace + fsync | statement, signature, sequence, hash |
| replay state | native service | bounded persistent window | pruned after max TTL |
| audit log | user/service, append only | fsync policy configurable | hash linked; no raw payload |
| audit anchor | separate key/target | periodic | detects local truncation/rollback |

Writes use temporary files in the same directory, restrictive mode at creation, `fsync`, atomic rename, and parent-directory sync where supported. Final and parent symlinks are rejected.

## 11. Cloud control plane

### 11.1 Data model

Core tables or logical collections:

- `organizations(id, name, created_at, version)`
- `memberships(org_id, member_id, role, status, version)`
- `human_credentials(member_id, token_hash_or_webauthn_ref, created_at, revoked_at)`
- `devices(org_id, id, label, public_key, status, last_seen_at, version)`
- `agents(org_id, id, device_id, kind, name, public_key, status, last_seen_at, version)`
- `policies(org_id, id, sequence, scope_json, status, created_by, created_at)`
- `revocations(org_id, id, target_type, target_id, sequence, reason, created_by, created_at)`
- `capabilities(org_id, id, agent_id, device_id, sequence, statement_hash, expires_at, revoked_at)`
- `device_audit_events(org_id, device_id, event_id, previous_hash, event_hash, redacted_json, received_at)`
- `admin_audit_events(org_id, id, actor_id, action, target, previous_hash, event_hash, created_at)`
- `idempotency(org_id, principal_id, key, request_hash, response_ref, expires_at)`
- `bundle_heads(org_id, device_id, sequence, statement_hash, issued_at)`

Every tenant resource lookup includes `org_id`, even when IDs are globally unique. Database constraints enforce uniqueness for sequences, event IDs, and idempotency tuples.

### 11.2 Bundle generation

One bundle is generated per device and contains:

- organization and device audience;
- active policy scope;
- revoked device and agent IDs;
- global emergency-stop state;
- monotonically increasing sequence;
- issue/expiry timestamps and offline TTL;
- signer key ID and detached signature.

Policy edits, revocations, signer rotation, and emergency stop increment the effective sequence. A cached response may be reused only when its canonical statement hash is identical.

### 11.2.1 One control-bundle authority

The existing local remote-control bundle and the cloud policy bundle are consolidated into one `ControlBundle v2` schema. The same native verifier handles bundles fetched from a hosted API, a self-hosted API, or applied from a local file. Transport does not change authorization semantics.

`ControlBundle v2` adds the policy scope, organization/device audience, offline TTL, signer key ID, and format epoch to the existing revocation state. There is exactly one accepted active bundle head per device: `(format_epoch, sequence, statement_hash)`.

Migration rules:

- a legacy v1 bundle is accepted only when configuration explicitly remains in legacy mode and no v2 head has ever been accepted;
- accepting the first v2 bundle atomically persists `minimum_format_epoch = 2`;
- after that marker is durable, v1 is permanently rejected even if files are rolled back;
- cloud and self-hosted issuers may dual-publish during one migration release, but the endpoint evaluates only one format at a time;
- there is no local conversion of a signed v1 statement into v2 because conversion would destroy issuer authenticity.

This removes ambiguous precedence. Local device/agent policy remains a separate, always-narrowing input; all remotely supplied policy and revocation state comes from the single v2 bundle.

### 11.3 Device authentication

Device requests sign:

```text
UPPERCASE_METHOD\n
NORMALIZED_PATH_AND_QUERY\n
BODY_SHA256\n
RFC3339_TIMESTAMP\n
NONCE
```

The API checks body digest, key status, timestamp skew, and nonce replay before routing. Redirects are not followed by the client, and signatures are never forwarded to another origin.

### 11.4 Human authorization

Roles:

- `viewer`: read organization, devices, agents, and policies;
- `auditor`: viewer plus audit query/export;
- `admin`: enroll/disable devices, manage agents, publish policies, revoke agents;
- `owner`: admin plus organization emergency stop and membership ownership changes.

High-risk actions require recent authentication in the hosted version. Self-hosted bootstrap tokens are hashed with a memory-hard or deliberately expensive KDF, have an explicit role and expiry, and can be revoked.

### 11.5 Audit ingestion

The device uploads bounded ordered batches. The server:

1. authenticates the device;
2. validates every event schema and tenant/device binding;
3. verifies each event hash and intra-batch chain;
4. compares the first predecessor with the stored head;
5. accepts exact duplicates;
6. rejects event-ID conflicts;
7. records but never hides a missing-predecessor gap;
8. commits events and the new head atomically.

Raw commit content, environment variables, capability values, session tokens, and private key references are prohibited from cloud audit.

## 12. Web Console

### 12.1 Information architecture

1. **Overview** — device/agent status, policy freshness, denied actions, audit health.
2. **Setup** — install, device enrollment, agent connection, test commit, GitHub signing-key registration.
3. **Agents** — identity, device, session profile, last seen, capability expiry, revoke/rotate.
4. **Policies** — plain-language templates, advanced scope, effective-policy preview.
5. **Activity** — allow/deny timeline, reasons, filters, chain/gap state, export.
6. **Emergency Stop** — scope, consequence, strong confirmation, publication and propagation state.

### 12.2 Setup state machine

```text
not_started
 -> local_service_installed
 -> hardware_key_created
 -> github_signing_key_registered
 -> device_enrolled (optional for local-only)
 -> agent_connected
 -> policy_active
 -> test_commit_verified
 -> ready
```

Each step has one primary action, automatic verification, a copyable diagnostic command, and a rollback path. “Ready” is shown only after an actual signed test commit is verified.

### 12.3 Policy editor

The default editor asks in plain language:

- which repositories;
- which branches;
- how long unattended access lasts;
- whether screen lock invalidates it;
- whether cloud freshness is mandatory.

Before publication it renders the exact effective policy and highlights surprising effects such as “main is denied” or “access stops after 60 minutes offline.” The advanced JSON view is read/write only for administrators and validates before save.

### 12.4 Emergency stop

Emergency stop is not a decorative button. The flow requires:

- owner role and recent authentication;
- explicit scope: organization, device, or agent;
- typed or checkbox confirmation describing active agents affected;
- an idempotent API request;
- signed bundle publication;
- propagation status per online device;
- immutable admin audit event;
- a separately authorized resume action that creates a new sequence rather than deleting history.

## 13. Failure behavior

| Failure | Local behavior | User-visible action |
| --- | --- | --- |
| Cloud unreachable, local-only mode | continue under local policy | show offline informational state |
| Cloud unreachable, cloud-required and inside TTL | continue with cached narrowed policy | warning with deadline |
| Cloud state beyond offline TTL | deny | `remote_control_stale`; show reconnect steps |
| Expired session | deny | `session_required`; offer renewal |
| Emergency stop | deny immediately after accepted bundle | show stop scope and sequence |
| Audit append failure | deny | show storage/permission recovery |
| Clock moves backward/forward materially | deny time-sensitive authority | require time sync/session renewal |
| Secure Enclave unavailable | deny | hardware diagnostic; never software fallback silently |
| Policy bundle rollback/equivocation | quarantine new bundle, retain last valid only within TTL | security alert |
| Cloud audit upload fails | keep bounded local queue | warning; signing continues unless org requires upload freshness |
| Local disk queue reaches limit | configurable fail closed; default deny before evidence loss | storage remediation |

No automatic failure mode may switch to a plaintext key or bypass signing policy.

## 14. Platform integration

### 14.1 Claude Code

- Project or user MCP configuration points to an absolute `node` and AgentPass MCP entry path.
- A SessionStart hook may report AgentPass status, but hooks are advisory and are not the enforcement boundary.
- Git continues to invoke the configured AgentPass SSH signer.
- `agentpass integrate claude-code --install` modifies only the AgentPass-owned configuration fragment, preserves unrelated settings, rejects symlinked targets, and is idempotent.

### 14.2 Cursor

- `.cursor/mcp.json` or the supported user configuration receives the same bounded MCP server.
- Project installation resolves and checks the canonical project root and rejects a symlinked `.cursor` parent.
- The UI describes the broader Cursor application session accurately.
- Git signing remains independent of whether the model chooses to invoke an MCP tool.

### 14.3 Other agents

Other agents use stdio MCP for status/setup and the Git-native signing helper for signing. A future SDK may expose policy checks, but not raw cryptographic operations.

## 15. API conventions

- Versioned JSON under `/v1`.
- 1 MiB global body limit, lower endpoint-specific limits.
- UTF-8 only; duplicate JSON keys rejected at security boundaries.
- Unknown fields rejected for signed and mutating schemas.
- RFC 3339 UTC timestamps with canonical serialization.
- Opaque UUID resource IDs.
- `Idempotency-Key` required for human mutations; same key with different request hash returns conflict.
- Optimistic concurrency via integer version/`If-Match` where records are edited.
- Errors use stable machine codes and never echo secrets.
- Pagination uses opaque cursors before production scale; numeric limit alone is acceptable only in the initial local file-backed server.

## 16. Cryptography and key rotation

- Git signing: Secure Enclave ECDSA P-256 through the platform provider.
- Protocol/capability signatures: Ed25519. Device HTTP authentication: Ed25519 or the documented P-256/SHA-256 IEEE-P1363 profile. macOS uses a dedicated Secure Enclave P-256 key rather than exporting an Ed25519 private key; the cloud pins the enrolled public key and algorithm.
- Digests and audit chaining: SHA-256 in v1.
- Canonicalization: deterministic JSON implementation covered by cross-language test vectors.
- Randomness: operating-system CSPRNG; no user-provided nonce.

Bundle signer rotation publishes an overlap document signed by both the old trusted key and the new key. Devices accept the new key only while the old pin is valid, unless a human performs an explicit local recovery. Removing an old key increments state and is auditable.

Git signing key rotation creates a new Secure Enclave identity, publishes its public key, verifies a test signature, then retires the old identity. There is no private-key migration.

## 17. Observability and privacy

Metrics may include counts and latency histograms by operation/result, but never repository names by default. Logs use structured redaction and classify fields as:

- public operational metadata;
- organization-confidential identifiers;
- local-only repository metadata;
- prohibited secret material.

Default retention proposal:

- local audit: user controlled, 90 days or size cap with anchored rollover;
- cloud device audit: 90 days for hosted free/self-hosted default;
- admin audit: at least 1 year;
- replay nonces: maximum authorization TTL plus clock skew;
- idempotency records: 24 hours or endpoint-defined retention.

Retention deletion creates a signed/anchored checkpoint; it does not silently splice the chain.

## 18. Testing strategy

### 18.1 Unit and property tests

- canonical JSON and cross-language vectors;
- schema limits and unknown-field rejection;
- scope intersection never widens either input;
- glob/path normalization properties;
- capability signature, audience, time, sequence, replay;
- commit parser corpus and malformed payload fuzzing;
- audit hash and batch continuity;
- tenant lookup and role matrix.

### 18.2 Integration tests

- Git -> helper -> broker -> signer stub -> valid SSH signature;
- native service -> Secure Enclave on supported CI/manual hardware;
- Claude Code/Cursor config install, rerun, and uninstall preservation;
- device enrollment -> signed bundle -> local enforcement;
- emergency stop -> bundle refresh -> denied next request;
- offline TTL boundary using a controlled clock;
- audit upload retry, duplicate, conflict, and gap.

### 18.3 Security gates

- dependency and secret scan;
- static analysis for Swift and JavaScript;
- fuzzing for IPC framing, JSON, commit, capability, and bundle parsers;
- symlink/race harness around all security-sensitive files;
- local unprivileged-process attack tests;
- external review before claiming production-ready hosted security.

The test matrix includes positive behavior and fail-closed negative behavior. A release cannot pass solely because allowed requests work.

## 19. Delivery plan

### Phase A — local autonomous signing

Deliver protocol, capability verification, native enforcement, Git helper, sessions, Claude/Cursor integration, local audit, and end-to-end signed commit.

Exit criteria:

- no general signing path;
- hardware-backed commit signing works without per-commit biometrics;
- repo/branch/remote/session denials are proven by tests;
- all authority is revocable locally;
- clean install/uninstall and recovery documentation exist.

### Phase B — cloud control plane

Deliver organization/device/agent/policy/revocation resources, device authentication, signed bundles, local bundle consumption, and audit upload.

Exit criteria:

- cloud can narrow/revoke but cannot widen local access;
- rollback/equivocation/offline TTL tests pass end to end;
- tenant isolation and role matrix are tested;
- emergency stop reaches an online device and blocks the next request.

### Phase C — Web Console

Deliver guided setup, overview, agents, policies, activity, emergency stop, server-only API bridge, and accessible responsive UI.

Exit criteria:

- a non-engineer can reach a verified test commit from a clean machine using the UI and copyable commands;
- high-risk actions require recent auth and confirmation;
- no cloud credential appears in browser bundles or logs;
- every displayed status is backed by a real API or clearly labeled sample/offline data.

### Phase D — hosted production hardening

Deliver WebAuthn/SSO, HSM-backed signing, durable SQL storage, queues, rate limits, cursor pagination, backups, retention controls, multi-region/HA plan, operational alerts, key-rotation ceremony, and independent security audit.

## 20. Implementation work breakdown

Work may proceed in parallel only where interfaces are frozen:

1. Protocol and canonical test vectors.
2. Native session/process binding and capability verification.
3. Git parser and signer restriction hardening.
4. MCP and Claude/Cursor adapters.
5. Cloud persistence/auth/API and signed bundle issuer.
6. Local cloud client, sequence persistence, and effective-policy integration.
7. Audit uploader and cloud chain verifier.
8. Web Console API bridge and UI state machines.
9. Cross-component E2E and adversarial tests.
10. Documentation, packaging, migration, and release gates.

The integration owner is responsible for preventing duplicate policy engines. Native enforcement is canonical; Node and Web implementations may validate or preview policy but cannot become an alternate authorization path.

### 20.1 Current repository gap map

This table is the starting backlog for the next implementation run. “Present” means code exists, not that the production exit criteria are satisfied.

| Area | Current state | Required next work |
| --- | --- | --- |
| Protocol schemas/canonical JSON | present in `packages/protocol` | add cross-language Swift vectors, duplicate-key framing tests, fuzz target |
| Capability issue/verify/intersection | present in `packages/capability` | integrate into native authorization path; persist replay/sequence evidence safely |
| Claude Code/Cursor setup | present in `lib/integrations.mjs` and MCP adapter | E2E against supported client config versions; uninstall and migration flows |
| Git helper and Node broker | present | align request/result audit with two-phase design; prove no alternate signer path |
| macOS native service | substantial existing implementation | consume protocol-v1 capability/cloud policy in the native decision; process/session binding review |
| Local remote control | older signed control bundle exists | implement the fixed `ControlBundle v2` migration and permanent format-epoch floor |
| Cloud API | initial file-backed implementation in `apps/cloud-api` | durable SQL transaction model, pagination, rate limits, signer/HSM boundary, capability endpoint completion |
| Cloud bundle consumption | not connected end to end | authenticated fetch, pinning, atomic sequence/hash state, TTL enforcement in native service |
| Audit upload | server ingestion exists; client path incomplete | bounded queue, signed batches, retry cursor, gap recovery, privacy tests |
| Web Console | initial UI and server bridge present | wire every state to real API, strong auth/reauth, setup state machine, propagation status, accessibility E2E |
| Emergency stop | API publication path exists | native online refresh E2E and separately authorized resume sequence |
| Packaging/hosting | local packaging exists; hosted console not release-ready | exact-source deployment, environment/secret management, migrations, rollback and operations runbook |

The first integration task implements the fixed “one `ControlBundle v2` authority” decision above. Shipping the old and new bundles as independent authorization systems is prohibited.

## 21. Decisions fixed for implementation

- v1 ships commit signing only; push is postponed.
- macOS is the first complete hardware-backed platform.
- Secure Enclave key creation may omit per-use biometrics only when a narrow AgentPass policy and auditable session replace that control.
- MCP is never the signing transport.
- Cloud is optional for individuals and required only when organization policy explicitly says so.
- Emergency resume creates new signed state; it never deletes the stop event.
- Same-sequence different-content state is a security error.
- Local audit failure is fail closed.
- The Web Console uses a server-only API bridge.
- Hosted “production ready” is not claimed before durable storage, strong human authentication, HSM key protection, operational controls, and independent review.

## 22. Deferred decisions

These are intentionally deferred and must not block local v1:

- Windows TPM implementation and Windows process-attestation details;
- Linux TPM/systemd/LSM implementation;
- authorization for Git push or SSH login;
- organization billing and commercial packaging;
- remote attestation across all hardware vendors;
- EndpointSecurity-based containment of malicious code inside an authorized agent session;
- hosted region and data-residency choices.

Each deferred feature requires a new threat-model section and cannot reuse `git.commit.sign` authority implicitly.

## 23. Definition of done

The first complete product slice is done only when this scenario succeeds:

1. A new user installs AgentPass on a supported Mac.
2. AgentPass creates a non-exportable Git signing key and shows the public key.
3. The user enrolls Claude Code or Cursor and selects one repository/branch scope.
4. The user starts an unattended session and leaves the machine.
5. The agent creates a valid signed commit without biometric interaction.
6. A request from another repository, a denied branch, a replay, and an arbitrary signing payload all fail.
7. The local audit explains all five decisions without containing secret material.
8. When cloud mode is enabled, emergency stop blocks the next online request and stale control state fails according to the configured TTL.
9. The Web Console shows the real outcome and audit-chain state.
10. Uninstall/recovery does not export the key or leave an unprotected signer behind.

Passing isolated unit tests or rendering a dashboard is not sufficient.

## References

- [mizdra, “Secure Enclave で git commit の署名鍵を管理する”](https://www.mizdra.net/entry/2026/08/07/101542)
- [Apple, Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [Apple, CryptoTokenKit](https://developer.apple.com/documentation/cryptotokenkit)
- [Claude Code hooks reference](https://code.claude.com/docs/en/hooks)
- [Cursor MCP documentation](https://docs.cursor.com/context/model-context-protocol)
