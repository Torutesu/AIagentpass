# Process-bound Agent implementation plan

Status: active implementation sequence after the M1 physical-qualification slice. As of 2026-08-13, the M2 contract/persistence foundation, canonical Grant signing and verification, public Lease normalization, PostgreSQL Grant/Lease authority repositories, the atomic Human issuance orchestrator, framework-neutral Human/Device HTTP boundaries, and a live Darwin observation primitive are implemented. Production runtime route wiring, hosted signing, consumption audit/outbox completion, XPC audit-token peer observation, split XPC services, adapter qualification, and physical evidence remain open. Passing unit tests alone does not make a lane production-ready.

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

### 10.0 Current implementation ledger

| Component | State | What is proven | What remains before production use |
| --- | --- | --- | --- |
| Grant/Lease schemas and OpenAPI | Implemented | Closed shapes, canonical timestamps, bounded scope/TTL/budget, Human and Device operations | Compatibility fixtures and deployed-client negotiation |
| PostgreSQL migrations 0018–0022 | Implemented | Immutable Grant identity, one-way consumption, process-bound session rows, authority-generation binding, separate Cloud/device audit chains, RLS | Retain migration, rollback, and ambiguity evidence across supported PostgreSQL versions |
| Grant crypto | Runtime-composed | Purpose-domain-separated canonical Ed25519 signing, pinned public-key verification, strict output validation, hosted provider timeout/error boundary, purpose-key separation, continuous metadata readiness | Verification-key rotation set and production KMS/HSM provider |
| Human HTTP boundary | Runtime-composed and PostgreSQL-qualified | Origin, session, CSRF, role, recent WebAuthn, strict JSON, pre-WebAuthn exact replay, stable errors, exact route dispatch, restart-safe HTTP retry without duplicate signing/audit/outbox | External KMS rotation and physical drain qualification |
| Device HTTP boundary | Runtime-composed | Exact raw path/body device authentication, shared nonce and rate-limit authority, Grant verification, exact binding retry, stable errors, exact frozen route interception | Consumption audit/outbox and real-PostgreSQL route contention evidence |
| PostgreSQL session authority | Issuance implemented; consumption partial | Tenant-local transactions, canonical fingerprint re-derivation, deterministic Grant identity, current applied generation/bundle/ACK checks, one-time consume, binding conflict, issuance audit/outbox atomicity, rollback and exact response-loss recovery | Consumption-side device audit/outbox, cleanup, metrics, and route-level contention evidence |
| Darwin observation | Partial | Live current-process facts, executable file race checks, code identity, boot identity, bounded ancestry | Derive the XPC peer from its audit token; observe/re-observe that peer per connection |
| Agent XPC and native lease machine | Not started | Contracts and injectable identity model exist | N2–N4 implementation and release-only enforcement |

The Human issuance service deliberately depends on a higher-level repository contract than the low-level Grant/Lease persistence repository. That security boundary is now runtime-composed: it re-derives the canonical request fingerprint, reauthorizes the Human session and membership under lock, validates the agent/device/policy/current applied bundle authority, invokes the purpose-separated hosted signer once, and commits the immutable Grant, audit event, publication intent, and idempotency pointer atomically. A protected release-policy registry constrains the process-binding policy tuple, and signer metadata degradation now fails readiness closed. M2-A2 remains open until external KMS rotation and physical drain evidence are captured.

### Wave M2-A — Cloud runtime authority

Implement grant issuance and consumption repositories, transaction services, and the two frozen HTTP routes. Issuance must verify organization role, recent WebAuthn, CSRF, agent/device membership, policy scope, ControlBundle sequence, TTL, and idempotency before signing the canonical grant. Consumption must verify the device request signature over the exact path/body, the Cloud grant signature/hash, process and ancestry digests, expiry, generation, and one-time state. Exact retry returns the original lease; a different binding fails with conflict. Every repository transaction sets and verifies the PostgreSQL organization context required by RLS.

Exit gate: route-level integration tests cover cross-tenant/device/agent substitution, concurrent consumption, rollback, ambiguous commit recovery, stale generation, expiry boundaries, replay, and audit/outbox atomicity against real PostgreSQL.

#### M2-A1 — production issuance transaction (implemented 2026-08-13)

1. Add a PostgreSQL issuance orchestrator over `sharedControlRepository`, the control-plane tables, `agentSessionAuthorityRepository`, admin audit, and refresh/outbox facilities.
2. In one transaction, set and verify tenant context; lock the Human idempotency record; re-read active membership and `owner|admin` role; lock and validate active agent/device composite identity and agent kind; select the current non-superseded ControlBundle sequence; validate requested scope against effective policy; and reject stale/revoked authority.
3. Derive deterministic request/grant IDs from organization, actor, idempotency key, and canonical request hash. Call the Grant signer only for a new idempotency record. Persist the signed Grant, immutable audit event, publication intent, and completed idempotency response before commit.
4. On exact retry, return the stored response without signing. On changed input, return conflict. On ambiguous commit, read the immutable completed idempotency result. Never mint a second Grant.

Exit gate: a real-PostgreSQL test proves new issue, exact retry, changed-key conflict, simultaneous issue, inactive member/device/agent, kind mismatch, scope escalation, stale generation, signer failure rollback, audit/outbox failure rollback, and post-commit connection loss recovery.

Evidence: unit and real-PostgreSQL tests cover canonical-fingerprint tampering, exact retry without a second WebAuthn proof, changed-request conflict, simultaneous issue convergence with one signer call, inactive member/device/agent and kind mismatch, scope escalation, stale authority generation, signer rollback, audit rollback, outbox rollback, and exact retry after the committed response is lost. Runtime exposure remains gated on M2-A2 and does not inherit this milestone automatically.

#### M2-A2 — hosted signer and route composition (implementation complete; qualification open)

1. Add purpose-separated `AGENTPASS_CLOUD_AGENT_SESSION_*` key configuration. Hosted mode must reject reuse of bundle or refresh keys.
2. Implement the KMS/HSM signer adapter with pinned Ed25519 public metadata, timeout, bounded errors, and rotation-aware verification keys. Keep the local signer test/evaluation-only.
3. Construct the Human and Device APIs in the runtime and intercept only their exact frozen paths before generic JSON parsing. Reuse the shared PostgreSQL nonce consumer, admission/rate limiter, in-flight drain tracking, and operational metrics.
4. Add readiness checks for issuance storage, signing-key metadata, and verification-key freshness. A failed dependency disables issuance/consumption rather than falling back to bearer authority.

Exit gate: hosted runtime tests send real HTTP requests through the Node server, restart between retries, rotate verification keys, drain in-flight requests, and prove no route falls through to weaker authentication.

Implemented evidence: hosted mode requires purpose-separated Agent Session signer configuration and a protected process-policy registry; provider metadata is pinned to the configured Ed25519 public key; forged output, metadata substitution, timeout, and bundle/refresh key reuse fail closed; Human issuance and Device consumption are composed only on the frozen routes; Device authentication reuses PostgreSQL nonce and rate-limit authorities; and readiness becomes unavailable when signer metadata can no longer be verified. Unit and in-process HTTP tests cover exact-path interception and weaker-route non-fallthrough.

Qualification evidence added on 2026-08-13: the PostgreSQL 17 CI lane now executes atomic Human issuance tests plus real Human and Device HTTP qualifications. The Human test seeds session, CSRF, recent-WebAuthn, membership, policy, agent/device, and applied ControlBundle state; issues through the actual Node server; restarts it; and proves exact replay without a second signature, recent-auth authorization, audit event, or outbox event. The Device test applies and acknowledges a current ControlBundle, consumes through the actual Node server, restarts the server and proves exact retry, runs concurrent consumption through two servers and proves one durable Lease, accepts an unexpired retiring verification key, rejects changed process binding, and proves query/method variants do not fall through. In-process HTTP tests additionally prove Human/Device alias rejection and drain behavior. The remaining M2-A2Q gaps are an external KMS rotation exercise and physical drain evidence.

Qualification backlog, in dependency order:

1. Exercise active-to-retiring rotation against the production KMS/HSM provider and retain provider-version evidence; local and real-PostgreSQL tests already cover active-only signing, overlap verification, expiry, unknown keys, and provider/config disagreement.
2. Extend drain qualification from the in-process server boundary to real PostgreSQL issuance and consumption transactions.
3. Retain the complete hosted alias/query/trailing-slash/case/method substitution matrix as a CI artifact rather than only pass/fail output.

#### M2-A3 — consume/audit completion

1. Extend Grant consumption so device/agent/generation validity is re-read under lock immediately before session creation.
2. Atomically append a Cloud-origin consume event on a chain separate from `device_audit_events`, and enqueue any required publication with Grant consumption and Lease creation. Device-origin events retain their independent hash chain and correlate later through Grant/Session binding IDs.
3. Add expiry/revocation cleanup that only advances lifecycle states and never deletes forensic bindings during retention.
4. Export metrics for issue/consume outcome, replay, conflict, stale generation, signer latency/failure, and transaction rollback without labels containing tenant IDs or secret material.

Exit gate: concurrent real-PostgreSQL and route-level tests prove exactly one Lease, exact retry convergence, changed-process/ancestry conflict, revoke/expiry races, audit/outbox atomicity, and bounded telemetry.

Implemented evidence on 2026-08-13: migration 0022 introduces an append-only, tenant-isolated Cloud consume chain that is structurally independent from the device-origin chain. The hosted PostgreSQL runtime now composes Lease creation and Cloud event append in one transaction. Real PostgreSQL HTTP qualification proves restart and concurrent retries converge on one Lease and one event per Grant, the device chain remains untouched, and an injected audit failure rolls back the Session row and Grant lifecycle transition. Lifecycle cleanup, publication/outbox policy, revoke/expiry race qualification, and bounded outcome metrics remain open.

### Wave M2-B — live macOS observation and Agent XPC split

Implement the Darwin observation source from the XPC audit token, `proc_pidinfo`/kernel PID version, boot identity, executable vnode identity, Security.framework code requirement and CodeDirectory data, entitlements, and bounded ancestry traversal. Introduce the separate Agent Mach service and connection-scoped facade; keep all management selectors unreachable. Raw observations remain transient and only canonical digests and stable reason codes may enter audit.

Exit gate: signed positive and negative probe binaries prove Team ID, entitlement, bundle, ad-hoc, PID reuse, exec, parent death, unknown ancestor, boot change, and cross-service selector denial. Test-only observation injection cannot be enabled in release builds.

Implementation order: first add an audit-token adapter that extracts peer PID/effective UID from `NSXPCConnection`; then make observation explicitly PID-scoped; then capture an immutable `NativeConnectionContext` during listener acceptance; finally re-observe the same peer before each key use. The existing current-process Darwin source is a reusable primitive but is not evidence of peer authentication.

### Wave M2-C — native lease and signing state machine

Implement one-time bootstrap handoff, grant verification, monotonic lease deadlines, signature-budget reservation, request/capability replay stores, crash-safe signing intent, `outcome_unknown`, and invalidation on process/worktree/control/key/device changes. Wire request v2 through the fixed Git SSHSIG path; reject arbitrary signer arguments, bearer sessions, and private PEM input in v2.

Exit gate: deterministic concurrency, restart, sleep/wake, clock rollback/advance, emergency stop, revoke, max-budget, duplicate request, duplicate capability, Secure Enclave failure, and ambiguous signer outcome tests all fail closed. Normal signing performs no Cloud call after lease establishment.

### Wave M2-D — Claude Code adapter and onboarding

Ship a signed launcher and repository-local Git integration that establish the intended process ancestry and pass the one-time capability through a private FD. Add CLI/Web Console onboarding that creates the agent policy, selects a repository/worktree, displays the exact scope and expiry, and provides copyable Claude Code launch instructions. Do not expose secrets in configuration, argv, environment, shell history, or logs.

Exit gate: a notarized candidate creates two unattended, verifiably signed commits on Apple silicon/Secure Enclave and Intel/T2; all wrong-repository, branch, executable, ancestry, expiry, revoke, and extra-signature cases are denied.

### Wave M2-E — Cursor, release, and production qualification

Add a separately versioned Cursor policy only after its supported headless contract is pinned. Complete installer/update/uninstall preservation, Developer ID signing and notarization, SBOM/provenance, staged deployment, observability, backup/restore, incident/revocation drills, and independent security review.

Exit gate: both hardware lanes and both adapters pass the retained physical evidence matrix; no open P0/P1 finding remains; rollback and emergency-stop exercises succeed; production enablement is allow-listed and reversible.
