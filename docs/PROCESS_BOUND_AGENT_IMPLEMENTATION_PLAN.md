# Process-bound Agent implementation plan

Status: active implementation sequence after the M1 physical-qualification slice. As of 2026-08-13, the M2 contract/persistence foundation, hosted Grant/Lease authority, atomic consume audit/outbox and lifecycle revocation, audit-token-derived XPC peer metadata capture, PID-scoped Darwin process and Git worktree observation, split Agent XPC listener, connection-bound one-time bootstrap, strict native Cloud Lease decoder, monotonic deadline boundary, and linearizable in-memory lease/budget registry foundation are implemented. Session activation/signing coordinators, lifecycle invalidation wiring, signed-host physical qualification, adapters, external KMS exercises, and production evidence remain open. Passing unit tests alone does not make a lane production-ready.

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
| PostgreSQL session authority | Issuance and consumption implemented | Tenant-local transactions, canonical fingerprint re-derivation, deterministic Grant identity, current applied generation/bundle/ACK checks, one-time consume, binding conflict, separate Cloud audit chain, deterministic outbox, lifecycle cleanup, direct revocation composition, bounded metrics, rollback and exact response-loss recovery | Production expiry scheduling, external KMS rotation, physical drain qualification, and supported-version evidence |
| Darwin peer observation | Implemented foundation | Explicit peer PID/effective UID observation, full-width kernel generation, executable/code/ancestry binding, root-peer substitution checks, re-observation on every Agent RPC | Signed launchd probes for exec, PID reuse, parent/ancestor changes, and release-symbol inspection |
| Darwin Git worktree observation | Implemented foundation | OS-derived peer cwd, exact PID/cwd before-and-after snapshots, no-follow descriptor traversal, embedded and linked worktrees, bounded direct HEAD/config parsing without Git execution, stable domain-separated binding digest, branch/remote/path drift and substitution checks | Resolve and bind the current HEAD object/tree in N3 policy composition; signed launchd race probes and independent review |
| Agent XPC split | Implemented fail-closed foundation | Separate fixed Mach service, exact five-selector protocol, per-connection facade and immutable guard, distinct host requirement/entitlement, cross-service negative harness | Developer ID-signed physical positive/negative matrix and notarized-package evidence |
| Native lease/sign machine | Foundation implemented | Closed transition table, stable denial projection, OS clocks, wall/monotonic deadline intersection, one-time connection-bound challenge, strict 19-field Cloud Lease decoder, request/capability/nonce replay and atomic budget reservation, 100-way concurrency proof | Device API Grant consumption composition, durable intent/key coordinator, lifecycle event wiring, restart/fault and physical qualification |

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

Implemented evidence on 2026-08-13: migration 0022 introduces an append-only, tenant-isolated Cloud consume chain that is structurally independent from the device-origin chain. The hosted PostgreSQL runtime composes Lease creation, Cloud event append, and deterministic outbox publication in one transaction. Real PostgreSQL HTTP qualification proves restart and concurrent retries converge on one Lease/event/publication per Grant, the device chain remains untouched, and an injected audit failure rolls back the Session row and Grant lifecycle transition. Bounded lifecycle repositories advance due Grants/Sessions and explicit organization/device/agent/grant/session revocations without deleting forensic bindings; explicit revocation waits for concurrent consumption and retries the exact database expiry-boundary race. Control-plane revocation invokes the lifecycle transition in the same database transaction, so callback failure rolls back both authority reduction and session revocation. Real PostgreSQL qualification covers issued-Grant expiry, consumed-Session expiry, consume/revoke serialization, direct agent-revocation propagation, and terminal Lease replay denial. Fixed label-free metrics cover issue/consume/signer/audit/lifecycle outcomes and latency totals. Production scheduling of expiry batches, external KMS rotation, and physical drain evidence remain open.

### Wave M2-B — live macOS observation and Agent XPC split

Implement the Darwin observation source from the XPC audit token, `proc_pidinfo`/kernel PID version, boot identity, executable vnode identity, Security.framework code requirement and CodeDirectory data, entitlements, and bounded ancestry traversal. Introduce the separate Agent Mach service and connection-scoped facade; keep all management selectors unreachable. Raw observations remain transient and only canonical digests and stable reason codes may enter audit.

Exit gate: signed positive and negative probe binaries prove Team ID, entitlement, bundle, ad-hoc, PID reuse, exec, parent death, unknown ancestor, boot change, and cross-service selector denial. Test-only observation injection cannot be enabled in release builds.

Implementation order: first add an audit-token adapter that extracts peer PID/effective UID from `NSXPCConnection`; then make observation explicitly PID-scoped; then capture an immutable `NativeConnectionContext` during listener acceptance; finally re-observe the same peer before each key use. The existing current-process Darwin source is a reusable primitive but is not evidence of peer authentication.

Implemented foundation on 2026-08-13: the daemon registers fixed management and Agent Mach service names with distinct exact Developer ID requirements. The Agent listener uses only public OS-owned `NSXPCConnection` peer PID, effective UID, and audit-session metadata, combines them with the full-width kernel process-generation snapshot, and captures a connection-scoped immutable guard over the complete process and ancestry identity. Privileged-daemon observation accepts the connection-derived user UID explicitly and never falls back to the daemon's root EUID. The peer is re-observed on every Agent RPC. The Agent interface contains only bootstrap, start, status, fixed Git-sign, and close selectors; its per-connection facade has no management endpoint reference. Until Wave M2-C installs the durable lease and budget state machine, all five methods deliberately return a stable unavailable error after peer revalidation instead of falling back to the legacy bearer signing surface. Deterministic tests cover PID reuse, root exec drift, cross-user observation, context substitution, DTO bounds, secure-coding allowlists, and selector exclusion. The remaining M2-B exit evidence is the signed Agent host, real launchd positive/negative probes, release-symbol inspection, and physical code-signing/exec/ancestry cases.

### Wave M2-C — native lease and signing state machine

Implement one-time bootstrap handoff, grant verification, monotonic lease deadlines, signature-budget reservation, request/capability replay stores, crash-safe signing intent, `outcome_unknown`, and invalidation on process/worktree/control/key/device changes. Wire request v2 through the fixed Git SSHSIG path; reject arbitrary signer arguments, bearer sessions, and private PEM input in v2.

Exit gate: deterministic concurrency, restart, sleep/wake, clock rollback/advance, emergency stop, revoke, max-budget, duplicate request, duplicate capability, Secure Enclave failure, and ambiguous signer outcome tests all fail closed. Normal signing performs no Cloud call after lease establishment.

#### M2-C0 — freeze native boundaries and denial taxonomy

1. Add `NativeAgentSessionState`, `NativeAgentSessionRecord`, and a closed `NativeAgentSessionDenialReason` enum. The public XPC layer maps these to a small stable `NSError` domain/code set and never returns paths, audit tokens, code requirements, payloads, keychain errors, or localized Security.framework details.
2. Define injectable protocols for monotonic time, signed wall-clock verification, Grant verification/consumption, process/worktree/control observation, signing, audit append, and lifecycle invalidation. Production implementations are constructed only in `AgentPassNativeService`; tests receive deterministic fakes from the test target rather than release environment switches.
3. Keep one authority owner: the Agent connection endpoint owns a reference to a service-wide session registry, while the immutable `NativeAgentConnectionGuard` remains connection-local. No state-machine type accepts PID, UID, process digest, ancestry digest, or worktree path from an Agent DTO.

Exit: exhaustive transition-table tests prove every unspecified edge is denied without mutation; exported Agent selectors remain exactly five; release sources contain no test-observation switch.

#### M2-C1 — bootstrap challenge and one-time Grant handoff

1. `bootstrapAgent` creates a random, expiring challenge bound to connection token identity, complete process/ancestry binding hashes, boot identity, adapter policy, and a server nonce. At most one live challenge exists per connection and replacement invalidates the prior challenge.
2. `startAgentSession` consumes a Cloud Grant through the Device API using device authentication and exact process/ancestry/worktree digests. The Agent never receives the signed Grant or Device credential. The returned Cloud Lease is verified locally, normalized, and bound to the already captured connection and challenge before activation.
3. Persist only replay evidence required to prevent a consumed Grant/capability from being reused. Active lease authority stays in memory and is deliberately lost on service restart. Ambiguous Cloud consumption is recovered only by exact idempotent read using the immutable Grant and binding hashes.

Exit: tests cover challenge replay/replacement/expiry, connection substitution, changed binding, Cloud timeout before and after commit, exact retry, changed retry, Grant reuse, wrong tenant/device/agent/policy/generation, and restart between consume and activation.

#### M2-C2 — linearizable in-memory session registry

1. Implement transitions `none → challenge_pending → active → request_reserved → signing_intent → signed → active|closed`, plus terminal `expired|revoked|process_lost|worktree_lost|control_changed|key_changed|outcome_unknown|closed`.
2. Serialize each session by an actor or equivalent lock-isolated state cell. Reserve request ID, capability ID, nonce, and one signature-budget unit in a single critical section before authorizer or key access. Concurrent requests cannot both observe the same remaining unit.
3. Pair the signed wall-clock expiry with a monotonic deadline calculated at activation. Sleep/wake may shorten remaining authority but never extend it; wall-clock rollback, boot change, arithmetic overflow, or missing monotonic evidence closes the session.
4. `status` returns only bounded public counters/timestamps and terminal state. `close` is idempotent for the same session/connection and cannot close or inspect another connection's session.

Exit: model-based transition tests plus 100-way concurrency tests prove one reservation per budget unit, terminal-state monotonicity, exact status projection, and no authority after restart, sleep/wake drift, or clock manipulation.

#### M2-C3 — crash-safe signing intent and outcome discipline

1. Before Secure Enclave access, append and fsync a canonical signing intent containing only request/session/capability IDs, payload hash, binding hashes, key generation, control sequence, and reserved budget sequence. Use the existing atomic-file and signing-transaction primitives; reject symlink, hardlink, ownership, mode, truncation, rollback, and path-swap conditions.
2. After key use, append the exact signature-result hash and durable audit completion before releasing the reservation. A failure known to occur before key use may return to `active`; any interruption or ambiguous failure after intent reaches the key boundary becomes terminal `outcome_unknown` and the budget remains consumed.
3. Startup verifies the intent/result chain. Active sessions are not restored. Any intent without a provable matching result is retained as forensic evidence and cannot be retried under the same request or capability.

Exit: fault injection at every durability/key/audit boundary proves no duplicate signature, no budget refund after ambiguous key use, no forged completion, and fail-closed restart recovery.

#### M2-C4 — fixed Git commit signing composition

1. Convert `AgentPassAgentSignRequest` into the frozen `git.commit.sign` authorization input internally. Fix SSHSIG namespace/hash/output; reject arbitrary signer arguments, key selection, operation selection, bearer session, PEM, raw Grant, and caller-supplied repository path.
2. Immediately before intent and again immediately before key use, revalidate connection/process/ancestry, repository/worktree/Git state, request/capability replay, ControlBundle generation/revocations, device/key lifecycle, expiry, and emergency stop.
3. Compose existing `NativeRequestAuthorizer`, `NativeCapabilityVerifier`, `NativeSigningTransactionStore`, audit chain, and `SecureEnclaveKeyStore` behind a single production coordinator. The response contains only request ID, signature bytes in the fixed format, and remaining budget.

Exit: a deterministic end-to-end native test verifies a real Git commit signature and denies payload, branch, remote, repository, capability, process, control, and key-generation substitutions before key access.

#### M2-C5 — lifecycle invalidation and operational controls

1. Subscribe the registry to ControlBundle apply/revoke, device/agent revoke, key rotation/deletion, emergency stop, process exit, and worktree drift. Invalidation first prevents new reservations, then drains or marks an existing signing intent according to C3; it never silently preserves authority across generation changes.
2. Bound global/per-agent/per-repository active sessions and bootstrap attempts. Emit label-bounded metrics and stable audit events for challenge, activation, reserve, intent, complete, deny, invalidate, close, and outcome unknown.
3. Make service shutdown enter drain: reject bootstrap/start/new reservations, allow only already durable post-key completion to finish, then invalidate all in-memory sessions.

Exit: race tests cover revoke-versus-reserve, stop-versus-key-use, key rotation, process exit, control update, drain, and resource exhaustion without deadlock or post-revoke signing.

#### M2-C6 — signed integration and promotion gate

1. Extend the signed Agent host with fixed bootstrap/start/status/sign/close qualification scenarios while continuing to accept no secret, payload, repository path, or signer option through argv/environment/stdin.
2. Run the real launchd services from the same candidate bundle. Retain redacted evidence for positive host access; management-to-Agent and Agent-to-management denial; missing entitlement; wrong Team/bundle; ad-hoc binary; exec/PID reuse; ancestor death/substitution; expiry/revoke; restart; and budget exhaustion.
3. Promote Agent signing from stable unavailable to enabled only when all production dependencies are configured and healthy. Any absent Device API, verifier key, control state, audit store, Secure Enclave key, or signing-intent store leaves the five-selector service available but signing fail-closed.

Exit: unit, integration, bundle, installer-preservation, contract, PostgreSQL, and notarized physical gates pass from one immutable source commit. M2-D starts only after this evidence is retained.

Implementation order is C0 → C1 → C2 → C3 → C4 → C5 → C6. C1 protocol adapters and C3 durability primitives may be developed in parallel after C0, but neither is wired into the production endpoint until C2 owns all authority transitions. C6 is evidence collection, not a substitute for any prior deterministic gate.

Implementation evidence added 2026-08-13: C0 now has an exhaustive closed transition table, bounded secret-free public records, a stable 16-reason XPC denial taxonomy whose `NSError` projection rejects extra diagnostics, injectable clocks, and fixed authority/audit/signer protocols. Production clocks use integer `CLOCK_REALTIME`, sleep-counting `mach_continuous_time`, and the kernel boot-session UUID. Deadline activation intersects the signed wall expiry with one fixed monotonic deadline; rollback, overflow, boot change, and either expiry boundary fail closed. C1 now exposes a real connection-bound bootstrap response while all authority-bearing RPCs remain unavailable: each replacement invalidates the prior challenge, mismatched or expired attempts consume pending state, and only a bounded fixed binary challenge crosses XPC. The native Device API consumer accepts only a canonical closed Grant envelope, verifies its statement hash and local device/agent/worktree/control bindings before device-key use, signs the exact consume path/body with the enrolled P-256 key, rejects redirects and non-server-trust authentication challenges, bounds the response, and decodes the returned 19-field Lease against the complete local binding. The native Cloud Lease decoder rejects duplicate/unknown/substituted values, preserves used budget and all identity/version fields, and does not invent a Cloud `lease_id`. Cloud authority generation and local key generation remain separate bindings. C2 now has a non-Codable, lock-serialized in-memory registry: it binds status/close/reservation to the exact connection and Lease binding; consumes request, capability, nonce, and budget before key access; permits refund only before signing intent while retaining replay evidence; and makes ambiguous post-intent outcome terminal. A 100-way concurrent test proves a one-unit budget is reserved once. C3 now has a separate crash-safe canonical intent ledger containing only IDs, authority versions, budget sequence, and hashes. It rejects replay/equivocation and unsafe state files, permits only intent→signed/outcome-unknown and signed→complete, stores only a signature hash, and converts every unresolved intent to terminal outcome-unknown during initialization before lookup. C4 now has a fixed Git commit signer wrapper whose API has no operation, namespace, key selector, algorithm, or signer arguments; payload bounds are enforced before one serialized P-256 key invocation and output is fixed armored SSHSIG. The production endpoint does not yet activate the registry or signer because the OS-derived worktree observer, coordinator/audit composition, lifecycle invalidation subscriptions, and complete service configuration remain C1/C4/C5 work; fail-closed unavailability is retained rather than using the legacy bearer path.

#### Next execution queue after the native Device API consumer

The following slices are the concrete implementation order from the current fail-closed endpoint to an enabled Agent path. A later slice must not be exposed as production-ready before the earlier slice's exit evidence passes.

| Slice | Production change | Deterministic verification and exit condition | Depends on |
| --- | --- | --- | --- |
| N1 — complete native authority configuration | Add an all-or-none Agent runtime configuration containing the immutable Device API origin, organization/device IDs, enrolled device-key tag, signing-intent directory, agent-session limits, and worktree-observation policy version. Construct one service-wide dependency container and share the existing enrolled device signer; no key bytes, bearer token, Grant, repository path, or test override may enter configuration. Missing, mixed, non-HTTPS, credential-bearing, writable, or identity-mismatched configuration leaves Agent RPCs stably unavailable. | Configuration matrix tests cover every omitted/mixed/unknown field, unsafe URL/path, key-tag mismatch, wrong organization/device, and management/Agent dependency substitution. Release-symbol inspection finds no test injection switch. | C0, Device API consumer |
| N2 — OS-derived worktree and Git observation | Add a PID-scoped observer that obtains the peer's current directory from Darwin process metadata, opens the directory without following links, resolves the Git common directory/worktree through descriptor-relative checks, and derives canonical repository/worktree/branch/remote evidence. Hashes enter the binding; raw paths remain transient and never cross XPC or audit. Re-observe the root process after traversal to catch PID/exec replacement. | Tests deny symlink/hard-link/path-swap, changed cwd, nested repository substitution, linked worktree/common-dir substitution, bare repository, branch/remote drift, process death, PID reuse, and observation races. A real temporary Git repository produces the same stable binding across reads. | N1, M2-B peer guard |
| N3 — session activation coordinator | Implement a service-wide `NativeAgentSessionCoordinator` and wire `start/status/close`. `start` revalidates the peer, atomically consumes the matching bootstrap challenge, observes the complete local binding, performs exact-retry Grant consumption, intersects Lease wall expiry with the monotonic deadline, creates a random local correlation lease ID, activates the registry, and emits durable activation audit before returning. XPC invalidation removes pending challenges and invalidates every session owned by that connection. | Fault injection covers challenge consume, network pre/post-commit ambiguity, exact/conflicting retry, service restart between consume/activate, activation-audit failure, binding drift, expiry/boot change, cross-connection status/close, and response-construction failure. No active authority survives daemon restart. | N2, C1, C2 |
| N4 — fixed signing transaction coordinator | Wire `signGitCommit` through one sequence: peer/worktree/control/key/device re-observation; registry reservation; v2 capability and policy authorization; durable intent+fsync; second complete re-observation immediately before key use; one fixed Git SSHSIG call; durable signature hash and audit completion; registry completion; bounded response. A known pre-key failure refunds only budget, not replay identities. Any ambiguous post-intent/key result becomes terminal `outcome_unknown` and cannot invoke the signer again. | Inject a failure at every reserve/authorize/intent/fsync/re-observe/key/result/audit/reply boundary. Prove no duplicate signature, no post-revoke key use, exact budget accounting under 100-way contention, real `git verify-commit` success, and denial of payload/capability/request/nonce/process/worktree/branch/remote/control/key substitutions. | N3, C3, C4 |
| N5 — invalidation, drain, and resource controls | Subscribe the registry to ControlBundle activation/revocation, emergency stop, device/agent revoke, key lifecycle generation changes, process exit, worktree drift, XPC invalidation, and daemon shutdown. Add global/per-agent/per-worktree session and bootstrap ceilings, bounded terminal-entry retention, label-bounded metrics, and drain semantics that reject new authority while allowing only already durable post-key completion. | Race tests cover revoke/stop/rotation/exit/drain versus reserve, intent, and key use; capacity exhaustion and cleanup; terminal monotonicity; deadlock detection; and zero signing after invalidation becomes observable. | N4, C5 |
| N6 — Claude Code launcher and Git integration | Ship a signed Agent host/launcher that establishes the approved ancestry, connects to the Agent Mach service, obtains the one-time Grant through a private handoff, configures repository-local Git signing without placing credentials in files/argv/environment/stdin, and translates Git's signing protocol only into the fixed XPC DTO. Setup records the selected worktree and policy through the management path; unattended commits require no recurring biometric prompt. | Temporary-repository E2E creates two verified commits, including one after an unattended interval. Negative cases cover copied launcher, wrong parent, wrong repository/worktree, protected branch, remote substitution, expired/revoked session, extra signature, service restart, and secret scanning of config/history/logs/process environment. | N5, M2-D |
| N7 — Cursor adapter and signed physical qualification | Add a separately versioned Cursor adapter only against a pinned supported headless contract. Extend candidate-bound positive/negative XPC probes and run the exact signed/notarized package through clean install, enroll, sign, audit, revoke, upgrade, and uninstall on Apple silicon/Secure Enclave and Intel/T2 lanes. | Reports bind source commit, package digest, nested code identities, Team ID, notarization ticket, OS/hardware, Cloud schema, signer key versions, and every scenario result. Promotion requires both hardware lanes, no unresolved critical/high finding, and successful emergency-stop/rollback drills. | N6, C6, M2-E |

Parallelization rule: N1 configuration and N2 observation test fixtures may proceed in parallel once their immutable boundary is agreed; N3 owns activation and must land before N4 production signing; N5 invalidation adapters may be developed against the registry in parallel with N4 but cannot be connected after signing is enabled; N6/N7 may build harnesses early but cannot claim success against a stubbed or unavailable authority path.

N1 implementation evidence added 2026-08-13: the root configuration now has an exact all-or-none Agent group whose Device API origin and organization/device/key identity are derived from the already pinned ControlBundle v2 enrollment instead of introducing a second authority. The typed core boundary can represent only explicit disabled or one complete enabled authority; it rejects partial fields, credential-bearing/non-origin URLs, noncanonical IDs/paths, key-tag substitution, unbounded limits, and unknown worktree-observation versions with stable errors. Startup constructs one service-wide container containing the strict Grant consumer, in-memory registry, crash-safe intent store, and fixed Git signer only when the full authority and a protected root-owned intent directory exist. Otherwise even bootstrap returns stable unavailable after peer authentication. The installer creates and preserves the fixed private intent directory. Signing remains unavailable until N2/N3 provide an OS-derived worktree binding and activation coordinator.

N2 implementation evidence added 2026-08-13: `NativeDarwinGitWorktreeObserver` now derives cwd exclusively from `PROC_PIDVNODEPATHINFO`, binds it to device/inode/generation, and requires matching PID/UID/start-time and cwd snapshots before and after traversal. The filesystem adapter walks absolute components with `openat(O_DIRECTORY|O_NOFOLLOW)`, rejects writable or wrong-owner authority directories, rejects symlinked and hard-linked metadata, parses bounded UTF-8 `.git`, `commondir`, `HEAD`, and `config` files directly, and supports embedded and linked worktrees without executing Git. Includes, conditional includes, duplicate URLs, malformed remote sections, unbound `pushurl`, unsafe URL forms, bare repositories, path swaps, nested-repository substitution, branch/remote drift, process death, PID-version drift, and cwd drift fail closed in deterministic tests. Canonical device/inode values are decimal strings to preserve full-width identities across Swift/JavaScript codecs, and a fixed digest vector locks the representation. Raw paths remain process-local and the binding type is non-Codable. N3 must consume this observation and compare its digest with the Cloud Grant; N4 must re-observe immediately before key use.

#### N3 executable work packages

N3 is the next critical-path slice. It is divided so reviewable commits preserve a fail-closed production endpoint after every merge:

1. **N3-A — Git object authority completion.** Extend the worktree evidence with symbolic-ref file identity, resolved HEAD object ID, and tree ID. Resolve loose refs descriptor-relatively and parse a bounded `packed-refs` fallback; reject replace refs, alternates, grafts, shallow ambiguity, unsupported hash formats, and ref/config changes during observation. Freeze a new digest version and Node/Swift vector before using it in a Grant. Existing v1 digests must not be silently upgraded.
2. **N3-B — coordinator boundary.** Add `NativeAgentSessionCoordinator` as the only owner of challenge consumption, worktree observation, Grant consumption, Lease verification, deadline activation, registry activation, and activation audit. Its input is the connection-local guard plus the closed start DTO; no PID, UID, path, branch, remote, digest, Grant, or key selector is accepted from the DTO.
3. **N3-C — activation transaction.** Execute `peer reobserve → challenge reserve → worktree observe → Device API consume/exact retry → Lease verify → deadline derive → durable audit append → registry activate → response`. Before the Cloud call, failures consume the challenge but create no session. After a committed Cloud consume, retries use the exact immutable binding. Audit or response failure closes local authority and never mints a second Cloud session.
4. **N3-D — endpoint wiring.** Replace stable-unavailable only for `start`, `status`, and `close` when the complete runtime dependency graph is healthy. Keep `signGitCommit` unavailable until N4. XPC invalidation atomically removes challenges and closes all sessions owned by that connection. Status and close must revalidate the connection guard and expose only the bounded public record.
5. **N3-E — fault and restart gate.** Inject failures before/after every arrow in N3-C, including connection loss after Cloud commit, audit fsync failure, boot/clock change, worktree drift, daemon restart, and reply encoding failure. Prove exact retry convergence, no cross-connection visibility, no active session after restart, and no raw paths or authority material in XPC/audit/errors.

N3-A implementation evidence added 2026-08-13: worktree observation policy v2 now binds the declared Git object format, explicit unborn/resolved HEAD state, resolved commit object ID, and root tree ID. Loose refs and bounded `packed-refs` are parsed directly; linked-worktree backlinks are verified; SHA-1 and SHA-256 repositories are supported. A production object reader verifies loose-object hashes and pack/index checksums, resolves bounded OFS/REF deltas, validates commit headers and canonical root-tree structure, and confirms every direct non-gitlink root entry exists with the declared object type. Repositories using replace refs, alternates, grafts, shallow state, worktree config, promisor/partial-clone state, reftable, unknown extensions, malformed refs, or changing process/filesystem evidence fail closed. No Git subprocess is used in production. Swift and Node share a frozen v2 canonical fixture and digest. Policy v1 is rejected rather than reinterpreted: deployment must stop issuing v1 Grants, wait at least the maximum v1 Grant/Lease lifetime (currently one hour), revoke any residual sessions, and only then enable v2 issuance. Unborn branches may be observed deterministically but N3-B activation must reject them. N3-B is now the next implementation package; production signing remains unavailable.

Parallel work during N3 is restricted to three disjoint lanes: N3-A Git object/ref parsing, N3-B/C coordinator and deterministic fakes, and N5 event-adapter interfaces without production registration. N3-D integration starts only after N3-A and N3-C pass. N4 signing, N6 launcher, and UI may prepare harnesses but cannot enable signing or claim an unattended commit.

After N3, the release sequence is N4 fixed signing transaction, N5 invalidation/drain/resource limits, N6 Claude Code integration, then N7 Cursor and signed/notarized physical qualification. Each slice lands as its own commit series with focused tests, full Swift/Node/contract gates, and a retained threat-model delta. Production remains disabled until the N7 evidence matrix and independent review have no unresolved critical/high findings.

### Wave M2-D — Claude Code adapter and onboarding

Ship a signed launcher and repository-local Git integration that establish the intended process ancestry and pass the one-time capability through a private FD. Add CLI/Web Console onboarding that creates the agent policy, selects a repository/worktree, displays the exact scope and expiry, and provides copyable Claude Code launch instructions. Do not expose secrets in configuration, argv, environment, shell history, or logs.

Exit gate: a notarized candidate creates two unattended, verifiably signed commits on Apple silicon/Secure Enclave and Intel/T2; all wrong-repository, branch, executable, ancestry, expiry, revoke, and extra-signature cases are denied.

### Wave M2-E — Cursor, release, and production qualification

Add a separately versioned Cursor policy only after its supported headless contract is pinned. Complete installer/update/uninstall preservation, Developer ID signing and notarization, SBOM/provenance, staged deployment, observability, backup/restore, incident/revocation drills, and independent security review.

Exit gate: both hardware lanes and both adapters pass the retained physical evidence matrix; no open P0/P1 finding remains; rollback and emergency-stop exercises succeed; production enablement is allow-listed and reversible.
