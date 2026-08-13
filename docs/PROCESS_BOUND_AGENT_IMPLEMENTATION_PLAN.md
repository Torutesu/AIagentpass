# Process-bound Agent implementation plan

Status: approved implementation sequence after the M1 physical-qualification slice. The M2 contract/persistence foundation (three schemas, two API operations, migrations 0018–0020, and injectable native process-identity models) is implemented as of 2026-08-13. Runtime routes, live macOS observation, split XPC services, adapter qualification, and physical evidence remain open. Passing unit tests alone does not make a lane production-ready.

## 1. Security outcome

Claude Code or Cursor may request a bounded Git commit signature without recurring biometric approval, but neither the agent, Git, a child process, nor copied credentials receives a reusable signing authority. The native service authorizes only a live, OS-observed process chain, one worktree, one signed Cloud grant, a bounded number of operations, and the current ControlBundle generation.

The current v1 path authenticates the signed AgentPass XPC client and a bearer-like session token. It does not authenticate the originating Claude Code or Cursor process. M2 therefore ships as a separate native v2 path. There is no automatic fallback from v2 to the v1 bearer path.

## 2. Frozen boundaries

### 2.1 Separate XPC surfaces

- Management service `dev.agentpass.native-service`: setup, key lifecycle, recovery, audit administration, and ControlBundle administration.
- Agent session service `dev.agentpass.agent-session`: start, sign, status, and close only.
- The Agent surface cannot rotate/delete keys, recover authority, mutate control state, prune audit data, or invoke arbitrary signing primitives.
- Every accepted XPC connection receives a connection-scoped facade containing the immutable observed peer context. Request JSON cannot override that context.

### 2.2 Process identity

At connection acceptance the service derives a process binding from:

- XPC audit token and effective UID;
- PID plus kernel PID version, never PID alone;
- boot identity;
- executable file identity and CodeDirectory hash;
- bundle identifier, Team ID, Developer ID marker, and required entitlement;
- the allow-listed ancestor chain and each ancestor's PID version/code identity;
- adapter kind and version.

Immediately before a signature the service re-observes the process and ancestry. Exit, exec, PID reuse, identity drift, an unknown intermediary, or a changed ancestor closes the session and denies the request.

### 2.3 Worktree identity

The setup flow resolves the repository and worktree without trusting an agent-supplied path. The binding contains the repository device/inode identity, common Git directory identity, worktree identity, canonical remote, initial HEAD/tree, policy branch scope, and a digest of these public fields. Existing `NativeRequestAuthorizer` validation and pre-sign revalidation remain mandatory.

### 2.4 Authority material

- A Cloud-signed Agent Session Grant is authorization, not a bearer secret.
- A local Session Lease exposes only a correlation UUID; knowing it grants no authority without the matching live connection/process binding.
- Capability delivery uses a one-time inherited file descriptor or a private connection handoff. It is never placed in argv, environment variables, or a persistent user-readable file.
- Agent private PEM files and `AGENTPASS_SESSION` are forbidden in native v2 mode and remain available only behind an explicitly named legacy compatibility mode.

## 3. Contracts to implement first

Add strict, canonical schemas with `additionalProperties: false` and duplicate-key rejection:

1. `contracts/schemas/agent-session-grant-v1.schema.json`
   - organization/device/agent/adapter identity;
   - agent kind and process-binding policy ID;
   - worktree binding digest and operation scope;
   - `max_signatures`, not-before/expiry, ControlBundle sequence;
   - issuer, key ID, signature, and canonical statement hash.
2. `contracts/schemas/agent-session-lease-v1.schema.json`
   - session/grant/agent IDs;
   - process and worktree binding digests;
   - max/used signatures, expiry, and control sequence;
   - no token, PID, raw audit token, argv, path, or private material.
3. `contracts/schemas/agent-sign-request-v2.schema.json`
   - request/session UUIDs and fixed `git.commit.sign` operation;
   - bounded commit payload and capability;
   - timestamp and nonce;
   - no arbitrary `ssh-keygen` arguments, agent signature, or session bearer.

Human API adds idempotent, recent-WebAuthn-protected grant issuance. Device API adds device-authenticated one-time grant consumption and carries the native service's process and ancestry binding digests. Exact retries are identified by the grant statement hash plus both binding digests and return the same committed result; any changed digest returns conflict. Tenant, device, agent, candidate, generation, expiry, and scope substitutions fail before consumption.

## 4. Durable Cloud state

Migrations are deliberately separated so rollback and authority review remain understandable:

- `0018_agent_session_grants.sql`: immutable grant identity/hash, organization/device/agent composite references, issued/consumed/expired/revoked lifecycle, one active consumption, creator, expiry, and scope.
- `0019_agent_sessions.sql`: session/grant/process/worktree bindings, ancestry policy, control sequence, signature budget, status, expiry, and close/revoke timestamps.
- `0020_agent_audit_binding.sql`: nullable public grant/session/adapter/process/worktree/capability bindings on device audit events.

Transactions must atomically consume a grant, create the session record, increment any organization/device epoch, append admin/device audit, and enqueue refresh work. Database rollback must leave no observable session. Ambiguous commit is resolved by reading the immutable grant hash; it never issues a second grant or signature budget.

The Cloud session row is a durable coordination and audit mirror, not the per-sign authorization oracle. Once a valid lease is established, normal offline signing is authorized by the in-memory native state machine, the live process/worktree observations, and the latest locally verified ControlBundle. A signature must not require a Cloud round trip. Repositories accessing the new RLS-protected tables must set the organization context inside the same database transaction.

## 5. Native implementation slices

### Slice N1 — observation primitives

Add `NativeProcessIdentity`, `NativeProcessAncestry`, and `NativeConnectionContext`. Abstract kernel/Security observations behind injectable protocols so PID reuse, exec, parent death, boot change, and signature substitution can be tested deterministically. Do not log raw audit tokens, full requirements, argv, or environment values.

Exit: approved fixture passes; wrong Team ID, missing entitlement, ad-hoc identity, bundle spoof, PID-version change, exec, parent loss, and unknown ancestor all have stable denial codes.

### Slice N2 — connection-scoped Agent XPC

Add a narrow Agent protocol and signed `AgentPassNativeAgentHost`. Listener acceptance creates one facade from the observed audit token. All methods use that facade; no global exported object can be reached from the Agent service. Management and Agent code requirements and entitlements are distinct.

Exit: the negative-probe lane proves Agent callers cannot invoke any management selector and a management client cannot silently become an Agent session.

### Slice N3 — process-bound session state machine

Implement:

```text
none -> challenge_pending -> active -> request_reserved
request_reserved -> signing_intent -> signed -> active|closed
active -> expired|revoked|process_lost|closed
signing_intent -> outcome_unknown
```

Grant consumption is one-time. Request and capability IDs are replay-protected. `max_signatures` is reserved before key use. `outcome_unknown` forbids re-signing. Active sessions never survive service restart. Expiry uses a monotonic deadline paired with the signed wall-clock expiry, so clock changes cannot widen authority. Control update, key lifecycle change, emergency stop, device revoke, process loss, or worktree drift invalidates the lease.

### Slice N4 — fixed Git signing request

Route request v2 through existing capability, policy, control, Git context, transaction, and audit components. The service fixes the SSHSIG namespace and output format. The helper receives only the signature response. It cannot select a key or pass arbitrary signer arguments. Revalidate process, worktree, Git state, capability, control generation, and replay reservation immediately before Secure Enclave key use.

## 6. Adapter order

### Claude Code first

Build the signed native host and launcher before configuration UX. The launcher pins the supported Claude Code executable/package identity, opens the one-time bootstrap FD, establishes the observed ancestry, applies repository-local Git configuration, and starts documented non-interactive mode with an allow-listed environment. The first physical scenario creates two deterministic commits separated by an unattended interval.

### Cursor second

Cursor uses a separate versioned adapter policy. Qualification starts only when a stable, production-supported headless/auth contract is available and pinned. A GUI application session must be labeled as application-wide; the product must not claim tab-level isolation it cannot prove.

Both lanes must reject another repository/branch, changed executable, unknown child/ancestor, expired/revoked session, extra request, and reused capability.

## 7. Audit contract

Add stable events for grant issued/consumed, challenge created, session started/denied/expired/revoked/process-lost/closed, sign authorized/denied/intent/completed/outcome-unknown. Allow-listed metadata includes IDs, adapter kind, control/policy sequence, process/ancestry/worktree hashes, payload hash, capability ID/sequence, expiry, and stable reason code.

Prohibited fields include raw audit tokens, process arguments, environment values, repository content, commit payload, private/public key blobs, credentials, session/capability values, and localized Security/XPC errors.

## 8. Test and rollout gates

1. Contract gate: canonical schemas/OpenAPI, cross-tenant substitution, replay, concurrent consume, expiry boundaries, and PostgreSQL rollback/ambiguous-commit recovery.
2. Native gate: deterministic unit tests for every identity and lifecycle negative case, selector separation, service restart, max-signature reservation, and outcome-unknown behavior.
3. Adapter gate: install/update/uninstall preservation and pinned supported versions for each agent.
4. Physical gate: same notarized PKG on Apple silicon/Secure Enclave and Intel/T2, signed negative probes, real Device API, real unattended signed commits, revoke/expiry/restart tests, and retained redacted evidence.
5. Observe rollout: collect only hashed ancestry shapes while v1 signs; no automatic policy creation.
6. Claude Code block mode: one organization/device allow-list, v2 mandatory, no bearer fallback.
7. Cursor block mode: separate qualification and policy; no inheritance from Claude Code approval.
8. Production: no open P0/P1 findings, both hardware lanes pass, abuse/rate controls are shared in PostgreSQL, KMS/HSM receipt keys are active, and rollback/incident runbooks are exercised.

## 9. Ordered delivery backlog

1. Finish M1 on real infrastructure: qualification enrollment ticket/relay, native v2 proof, signed probe artifacts, and two hardware runs.
2. Freeze the three M2 schemas and Human/Device API operations.
3. Add migrations 0018–0020 and repository/transaction tests.
4. Implement native observation primitives.
5. Split Agent and management XPC surfaces.
6. Implement the process-bound session state machine and stable audit reasons.
7. Implement request v2 and disable bearer/private-PEM inputs in native v2 mode.
8. Build and qualify Claude Code adapter.
9. Build and qualify Cursor adapter.
10. Complete revoke, emergency-stop, crash/restart, sleep/wake, network/clock, upgrade, reinstall, and purge physical scenarios.
11. Run independent security review, notarized release qualification, staged production rollout, and recovery drill.

The critical path is N1 through N4. UI and adapter convenience work must not precede the process-bound enforcement boundary, because configuration alone cannot prove that an operation originated from the authorized coding agent.

## 10. Detailed next implementation waves

### Wave M2-A — Cloud runtime authority

Implement grant issuance and consumption repositories, transaction services, and the two frozen HTTP routes. Issuance must verify organization role, recent WebAuthn, CSRF, agent/device membership, policy scope, ControlBundle sequence, TTL, and idempotency before signing the canonical grant. Consumption must verify the device request signature over the exact path/body, the Cloud grant signature/hash, process and ancestry digests, expiry, generation, and one-time state. Exact retry returns the original lease; a different binding fails with conflict. Every repository transaction sets and verifies the PostgreSQL organization context required by RLS.

Exit gate: route-level integration tests cover cross-tenant/device/agent substitution, concurrent consumption, rollback, ambiguous commit recovery, stale generation, expiry boundaries, replay, and audit/outbox atomicity against real PostgreSQL.

### Wave M2-B — live macOS observation and Agent XPC split

Implement the Darwin observation source from the XPC audit token, `proc_pidinfo`/kernel PID version, boot identity, executable vnode identity, Security.framework code requirement and CodeDirectory data, entitlements, and bounded ancestry traversal. Introduce the separate Agent Mach service and connection-scoped facade; keep all management selectors unreachable. Raw observations remain transient and only canonical digests and stable reason codes may enter audit.

Exit gate: signed positive and negative probe binaries prove Team ID, entitlement, bundle, ad-hoc, PID reuse, exec, parent death, unknown ancestor, boot change, and cross-service selector denial. Test-only observation injection cannot be enabled in release builds.

### Wave M2-C — native lease and signing state machine

Implement one-time bootstrap handoff, grant verification, monotonic lease deadlines, signature-budget reservation, request/capability replay stores, crash-safe signing intent, `outcome_unknown`, and invalidation on process/worktree/control/key/device changes. Wire request v2 through the fixed Git SSHSIG path; reject arbitrary signer arguments, bearer sessions, and private PEM input in v2.

Exit gate: deterministic concurrency, restart, sleep/wake, clock rollback/advance, emergency stop, revoke, max-budget, duplicate request, duplicate capability, Secure Enclave failure, and ambiguous signer outcome tests all fail closed. Normal signing performs no Cloud call after lease establishment.

### Wave M2-D — Claude Code adapter and onboarding

Ship a signed launcher and repository-local Git integration that establish the intended process ancestry and pass the one-time capability through a private FD. Add CLI/Web Console onboarding that creates the agent policy, selects a repository/worktree, displays the exact scope and expiry, and provides copyable Claude Code launch instructions. Do not expose secrets in configuration, argv, environment, shell history, or logs.

Exit gate: a notarized candidate creates two unattended, verifiably signed commits on Apple silicon/Secure Enclave and Intel/T2; all wrong-repository, branch, executable, ancestry, expiry, revoke, and extra-signature cases are denied.

### Wave M2-E — Cursor, release, and production qualification

Add a separately versioned Cursor policy only after its supported headless contract is pinned. Complete installer/update/uninstall preservation, Developer ID signing and notarization, SBOM/provenance, staged deployment, observability, backup/restore, incident/revocation drills, and independent security review.

Exit gate: both hardware lanes and both adapters pass the retained physical evidence matrix; no open P0/P1 finding remains; rollback and emergency-stop exercises succeed; production enablement is allow-listed and reversible.
