# AgentPass next implementation plan

> Current execution order and release gates are maintained in
> [`V1_EXECUTION_PLAN.md`](./V1_EXECUTION_PLAN.md). This document retains the
> deeper historical work-package record.

Status: active  
Baseline: `codex/agent-platform`
Planning date: 2026-08-14

## 1. Target release

The first production release is a headless-first AgentPass distribution for Claude Code and Cursor. A user installs one signed and notarized macOS package, completes organization and device enrollment through the browser Console or CLI-guided browser flow, and then lets an approved agent perform policy-bound signing without repeated human prompts. Private signing keys remain non-exportable in Secure Enclave or the platform hardware boundary. Human operators can inspect, reduce, revoke, recover, and audit authority from the Console.

The primary macOS delivery is not a required menu-bar application. The release artifact is one immutable Developer ID-signed and notarized PKG containing the native broker, XPC services, launchd jobs, CLI, Git helper, and agent adapters. Direct download and a Homebrew bootstrap install the same PKG and verify the same manifest. A native onboarding application may be added later as a convenience client, but it must not become a second security or protocol implementation.

## 2. Current implemented boundary

The current branch has the versioned Core/OpenAPI/JSON Schema catalog, 38 forward-only PostgreSQL migrations, tenant-qualified hosted repositories, Human sessions and organization roles, WebAuthn registration/authentication and operation-bound recent authorization, Device API foundations, signed control bundles and ACK state, audit ingestion, emergency revocation, threshold-owner recovery, and a secret-free recovery-notification outbox with dead-letter management, durable uncertain-delivery quarantine, and bounded retention.

At the current checkpoint, recovery dead-letter redrive and suppression require
an exact resource-bound WebAuthn context. The repository recomputes that
context and consumes the proof in the same organization-locked transaction.
All 38 migrations apply against local PostgreSQL 16. The root suite now passes
1,860 tests (1,811 pass and 49 intentionally skipped), and the frozen catalog
validates 122 entries. The
authenticated P0-B Cloud/Console/PostgreSQL/browser journey also passes all 12
role, WebAuthn, wake, tenant-substitution, and revocation scenarios locally and
in the source-bound CI qualification.

Cycle B source work now includes a fail-closed `DELETE /api/auth/session`
journey from the Console through the Human BFF to the existing logout
authority, exact clear-cookie enforcement, a global Console sign-out action,
and an operation-blocking reauthentication surface for expired sessions. The
managed AWS/GCP signer composition now classifies throttling opaquely and wraps
each purpose in an isolated bounded closed/open/half-open circuit with no
queue or local fallback. The Console now consumes the strict bootstrap role as
an operational authorization boundary: Owner/Admin/Auditor/Viewer controls are
least-privilege, emergency stop is Owner-only, session metadata is authoritative,
and any BFF 401/403 clears all tenant data and requires reauthentication. Local
Console qualification passes 137 tests. Cloud
IAM/non-exportability evidence, all-purpose key provisioning, and protected
browser/PostgreSQL qualification remain open, so neither W2.2 nor W3.2 is yet
declared complete.

W3.3 now also has migration `0037` and a purpose-global PostgreSQL repository
for lifecycle transitions and signing idempotency. It serializes transitions,
stores only public key metadata, replays exact committed signature bytes across
replicas, and quarantines pending/uncertain provider outcomes against blind
re-signing. Runtime/KMS composition, real-PostgreSQL race qualification,
provider-side response-loss lookup, every hosted purpose, and real KMS
IAM/non-exportability evidence remain open.

W4.1 now requires the complete v2 candidate/challenge invitation, P-256 native
key binding, and a Cloud-published purpose-separated receipt verification key.
The client signs the Device receipt read, verifies the receipt before persisting
control trust, never replays a response-loss POST, and persists neither the
credential nor private material. Hosted possession-receipt signer composition,
interrupted physical-Mac qualification, and signed package installation remain
open, so W4.1 is still in progress.

The branch CI run `31791531512` passes all four jobs: PostgreSQL 16/W1.5,
browser E2E, P0-B live process, and the complete test/release gate. It retains
independently verified secret-free W1.5 and P0-B evidence. This is not yet a
production release: the staging W1.6 drill, complete Console operations, cloud
IAM qualification for managed signers, physical Mac qualification,
signed/notarized artifacts, deployment infrastructure, restore drills, and
independent security review remain open.

## 3. Delivery rules

1. Every authority-changing commit lands with negative tests for replay, tenant substitution, stale versions, actor substitution, malformed input, response loss, and concurrent execution where applicable.
2. OpenAPI, JSON Schema, SQL migrations, signing domains, XPC selectors, native durable state, entitlements, and release identities have one integration owner and change serially.
3. UI success means authoritative PostgreSQL state or a verified signed device ACK, not merely a successful browser request.
4. Browser storage, URLs, telemetry, logs, crash reports, argv, environment variables, shell history, and repository files must never contain reusable credentials, assertions, capability tokens, recovery material, or private keys.
5. Evaluation-mode file stores and file signers remain explicit and fail closed in hosted mode. They are never a production fallback.
6. A modeled, mocked, skipped, or simulator-only test is labeled as such and never promoted as physical or production evidence.
7. Each merge-sized slice updates relevant threat-model claims, operator documentation, and the evidence index in the same commit.

## 4. Critical path and merge-sized execution plan

### W0 — close recovery dead-letter operations

State: completed locally on 2026-08-14. All four slices are implemented and
verified, including the real-PostgreSQL race matrix, strict BFF/client,
Owner/Admin UI, and the full Playwright virtual-WebAuthn browser journey. The
implementation also fixed millisecond precision loss when PostgreSQL returns
`recent_auth_at` as a JavaScript `Date`; without that fix, the repository's
exact authorization revalidation could reject a valid proof.

Qualification evidence:

- 38 Chromium Playwright tests pass, including 12 recovery dead-letter tests
  covering list/loading/empty states, keyboard confirmation, redrive,
  suppression, stale-version refresh, one-use recent-auth, malformed and stale
  authorization, role denial, tenant substitution, unknown-event enumeration,
  CSRF rejection, and replay.
- The mutation journey uses a CDP virtual authenticator and verifies the exact
  canonical context hash for organization, event, action, and authoritative
  management version across WebAuthn options and verification.
- Browser checks cover DOM, local/session storage, IndexedDB, Cache Storage,
  console output, and bounded network metadata. Playwright traces are disabled
  for this sensitive suite because a retained trace can persist transient
  WebAuthn assertions or request bodies.
- Console unit tests and lint pass (122 tests), the frozen contract catalog
  validates (112 entries), and migration `0031` passes against real PostgreSQL.

This closes the local W0 browser qualification. A deployed Console + Cloud API
+ PostgreSQL end-to-end run remains a production/staging promotion gate under
W6; it is not represented as local W0 evidence.

Merge slices:

1. Add real-PostgreSQL qualification for context mismatch, cross-tenant access, consumed-proof replay, concurrent proof consumption, stale management-version races, and semantic idempotent retry with a fresh WebAuthn proof.
2. Add a strict Console/BFF client for dead-letter list, redrive, and suppress. Validate exact response shapes; forward only allow-listed session, Origin, CSRF, `If-Match`, idempotency, and recent-auth controls.
3. Add an Owner/Admin operations surface with loading, empty, error, pagination, conflict refresh, retry-attempt visibility, redrive confirmation, suppression reason, and injected WebAuthn step-up.
4. Add browser tests for role visibility, keyboard operation, stale-version recovery, one-use recent-auth, request retry, and absence of sensitive material in storage and rendered output.

Exit gate:

- unit, Console, contract, and real-PostgreSQL suites pass;
- two concurrent mutations produce one committed result and one stable conflict/replay result;
- another tenant receives the same not-found surface as an absent resource;
- an exact semantic retry can use a fresh WebAuthn authorization without duplicating the mutation;
- the UI never claims success before the returned authoritative version is accepted.

### W1 — finish recovery delivery and abuse resistance

Depends on W0.

State: in progress. Delivery/provider/retention slices 1–3 are implemented and
locally verified on 2026-08-14. The worker now isolates poison rows per event,
moves unknown outcomes into a durable non-claimable `uncertain` state, and runs
bounded retention maintenance.
The HTTPS provider accepts only the exact secret-free acknowledgement DTO and
rejects ambiguous framing, duplicate JSON keys, response-field echoes, and
oversized bodies. Migration `0032` enforces fixed 30-day published, 90-day
dead-letter, and 365-day suppression retention, archives each removed event in
an immutable secret-free ledger, and prunes at most 1,000 rows per transaction.

The shared PostgreSQL session ceiling is now atomic across API replicas: one
member advisory lock encloses active-session reduction and insertion, and a
real two-pool race holds 12 concurrent issuances to exactly three active
sessions. Fixed label-free metrics now cover suppression, redrive outcomes,
pruning, and recovery latency aggregates. Shared-control SQL hardening and
committed recovery state-latency wiring are complete. Remaining W1 closure work
is the complete two-instance fault matrix at every provider/commit/response-loss
boundary and the corresponding operational alerts/runbooks.

W1.4a application boundary is implemented: session bootstrap first consumes
one fixed anonymous PostgreSQL bucket before identity-provider work, then
consumes HMAC-derived provider-subject, member, and organization buckets after
immutable identity resolution. Signed Console JTI values are converted to a
keyed digest and consumed in the same PostgreSQL transaction as session
insertion and the cross-replica session ceiling. A denied limiter decision does
not consume replay state; a replay cannot revoke an existing session; and a
failed insert rolls the replay marker back.

W1.4a infrastructure closure is also implemented in migration `0033`: both
token-bucket functions sample time after their row lock and prevent timestamp
regression; all retention functions use bounded cooperative row locking; the
hosted transport limiter has no process-local allowance path; and an
independent maintenance worker prunes all shared-control classes under one
budget with fixed label-free metrics. Real PostgreSQL qualification covers a
delayed bucket locker, backward-clock protection, locked-row pruning, upgrade
to 33, and migrations 1–33 in an empty schema.

W1.4b is implemented. Every forward owner-recovery state update now compares
the source state at a fixed SQL parameter and queues a database-timestamp delta
on the transaction client. The queue is emitted only after confirmed `COMMIT`,
is discarded on rollback, and is also flushed by the caller-owned WebAuthn
transaction coordinator. Replays and same-state version updates do not create
observations; negative or malformed deltas are ignored; synchronous and
asynchronous metric sink failures cannot alter committed authority. A lost
`COMMIT` response or process death immediately after commit may omit this
non-authoritative in-memory metric, so authoritative recovery truth remains the
PostgreSQL state/outbox rather than the health counter.

Current verification baseline:

- the root suite passes 1,813 tests: 1,765 pass, 48 explicitly skipped, 0 fail;
- the frozen catalog validates 120 entries: 29 schemas, 55 OpenAPI operations,
  and 36 migrations;
- lint and whitespace/error checks pass;
- real PostgreSQL qualification passes for the cross-replica session ceiling,
  resource-bound recovery management, terminal-row retention, and outbox
  process-loss recovery.

W1 closure execution order:

| Slice | Implementation boundary | Required negative/concurrency evidence | Exit condition |
| --- | --- | --- | --- |
| W1.4a session bootstrap admission | Add fixed `human.session.bootstrap` policies to the shared PostgreSQL limiter; apply anonymous/global admission before identity-provider work, then subject/member/organization admission after verified identity resolution and before session insertion. Keep identifiers HMAC-derived and never persist the assertion or provider subject as a label. | Two API instances must share each bucket; unknown-subject floods must not create unbounded buckets; provider and limiter outages fail closed; identity replay and denied requests create no session. | The bootstrap route has no process-local allowance path, returns bounded `Retry-After`, and its atomic session ceiling still holds under concurrent accepted requests. |
| W1.4b recovery state latency — complete | Observe database timestamps only after confirmed committed recovery transitions and report fixed-key count/total aggregates through `recordOwnerRecoveryStateLatency`. Do not label by organization, member, request, state, or error. Metrics failures remain post-commit and non-authoritative. | Fixed source-state CAS, negative/malformed timestamp, rollback, WebAuthn caller-owned commit, exact-once flush, and sync/async metric-sink failure tests; real PostgreSQL proves commit and rollback outcomes. | Confirmed commits emit one bounded observation per forward transition in normal operation; retries do not observe another transition and no recovery identity appears in health output. |
| W1.5 delivery fault matrix — implementation and CI qualification complete | Durable `uncertain` quarantine, immutable provider binding, append-only transition ledger, Owner/Admin retry/suppress API, independent-process `SIGKILL`, durable provider acceptance, automatic exact-binding confirmation, 34→35 upgrade, prune/redrive CAS, secret-free evidence, the two-worker race matrix, authenticated HTTPS-provider/worker/PostgreSQL faults, and retention/confirmation races. Branch CI repairs also close stale schema fixtures, invalid inactive-session seeding, dependency ordering, P0-B hosted-composition drift, output-limit nondeterminism, and native-runner executor starvation. | Provider timeout/response loss, malformed/oversized/truncated/delayed lookup responses, binding/key substitution, stale publish/fail/uncertain/confirmation CAS, retry/suppress/prune races, duplicate-acceptance convergence, bounded lookup scheduling, and the complete P0-B browser journey against real PostgreSQL. | CI run `31791531512` passes the composed PostgreSQL 16 qualification and independently verifies/retains bounded W1.5 evidence; P0-B retains its source-bound report; every case converges to one logical delivery or an explicit uncertain/dead-letter state. |
| W1.6 operational closure — implementation complete, staging execution pending | The fixed ten-rule alert policy, five PostgreSQL-backed outbox gauges, prune-failure metric, closed policy validator, six-scenario evidence schema/verifier, runbook, threat-model update, package boundary, and CI gate are implemented. | The local 18-test W1.6 contract gate rejects unknown/duplicate/secret-bearing material, missing exported signals, comparison/window drift, and unsafe evidence files. The remaining staging drill covers provider outage, worker restart, limiter outage, uncertain adjudication, dead-letter redrive, and prune failure. | W1 closes only after one protected report from the exact deployed commit/image/policy passes the verifier; local tests alone do not satisfy this gate. |

#### W1.4a completed merge sequence

| Commit | Exact scope | Verification required before merge |
| --- | --- | --- |
| A — bootstrap admission and atomic replay | Two-stage shared admission, purpose-separated `AGENTPASS_HUMAN_AUTH_SECRET`, HMAC subject/global IDs, bounded anonymous subject slots, and replay consumption in `createSessionWithLimit`. | Unit ordering tests; two-pool global/identity/session-ceiling race; same-JTI concurrency gives one `201` and one `409`; limiter denial/outage creates neither replay row nor session; insert failure rolls both replay and ceiling changes back. |
| B — migration `0033` shared-control hardening | Replace token-bucket functions so the clock is sampled after row lock and cannot move `updated_at` backward. Change bounded pruning to `FOR UPDATE SKIP LOCKED`; add bounded replay-ledger pruning. | Migration checksum/order tests; real PostgreSQL contention with delayed lockers and clock assertions; two maintenance workers prune disjoint bounded sets; migration 1–33 on an empty database and upgrade from 32. |
| C — hosted transport admission | Remove the process-local hosted fallback. Invalid or unauthenticated transport scope maps to fixed HMAC global buckets; authenticated Device traffic keeps tenant/device buckets. | Restart and two-instance tests prove the allowance cannot reset locally; malformed identifiers cannot create rows; repository outage returns stable `503`; Device tenant isolation remains intact. |
| D — maintenance and observability | Start a dedicated shared-control maintenance worker independent of recovery delivery. Prune generic, anonymous, and replay rows with one total work budget and fixed label-free metrics. | Start/close/readiness tests, repeated-worker contention, sink failure, database outage/recovery, bounded transaction size, and health snapshots with no principal-derived labels. |

W1.4a, W1.4b, W1.5, and the W1.6 implementation/CI evidence gate are complete.
The real staging operator drill remains and is tracked as the external W1.6
exit gate. No synthetic report may be used to claim closure.
W2 Console work may continue in parallel only for read-only
screens; authority-changing UI remains gated on these W1 guarantees.

#### W1.5 detailed implementation sequence

1. Keep the closed fault controller entirely under test support. It may
   interrupt only at six named
   boundaries: after claim, before provider call, after provider acceptance,
   before terminal commit, after terminal commit, and after response encoding.
   Production constructors and runtime wiring expose no fault dependency, no
   no-op switch, and no HTTP, environment-variable, or payload-controlled arm.
2. Build a real-PostgreSQL two-worker harness with independent pools and worker
   identities. Seed one canonical outbox row, use one deterministic provider
   idempotency key, persist provider acceptance in a separate test ledger, and
   restart with a new worker identity after each injected loss.
3. Qualify claim/lease ownership: process loss after claim, lease expiry,
   concurrent reclaim, stale acknowledgement, duplicate acknowledgement, and a
   worker whose lease expires while the provider call is pending. Every terminal
   write must compare tenant, event, worker, lease token, state, and deadline.
4. Qualify provider ambiguity: timeout before acceptance, timeout after durable
   acceptance, duplicate provider response, malformed/oversized response,
   response truncation, and provider idempotency-key substitution. The result
   must converge to `published`, retryable pending, explicit uncertain, or
   dead-letter without fabricating acceptance.
5. Qualify management races: poison-row isolation, redrive ceiling, suppression,
   terminal retention, concurrent prune/redrive, and shutdown drain while a
   publish is in flight. One poisoned event must not starve unrelated tenants or
   consume an unbounded batch.
6. Add a machine-readable evidence summary containing only fixed scenario names,
   public event digests, final state classes, attempt counts, and timing bounds.
   Run it from CI against PostgreSQL 16 after migrations 1–36 and document a
   single reproduction command in the recovery operations runbook.

Implemented W1.5 foundation in migration `0034`:

- `uncertain` is a first-class durable state with a closed reason vocabulary,
  no lease, and no automatic claim path;
- expired claimed rows are quarantined as `process_interrupted` before any new
  pending row is claimed, including expired rows present during upgrade;
- provider responses must contain exactly the requested idempotency key;
- publish, retry, and uncertain acknowledgements are fenced by tenant, event,
  attempt, claim digest, pending state, and an unexpired database-clock lease;
- readiness reports only aggregate uncertain counts and fails closed while any
  uncertain delivery awaits an operator decision;
- uncertain rows are intentionally excluded from terminal retention.

Implemented W1.5 binding and operator-control slice in migration `0035`:

- every deliverable pending row carries an immutable secret-free provider tuple
  (`binding_id`, key version, namespace digest); existing unbound pending rows
  are quarantined and cannot be silently rebound;
- runtime workers claim only their exact provider binding and quarantine a
  mismatched event before any provider call;
- every durable outbox state transition is appended to a separate immutable,
  per-event hash chain while operator audit remains a distinct authority log;
- `listUncertain`, bounded `retryUncertain`, and `suppressUncertain` are wired
  through the Human API with tenant scope, Owner/Admin authorization, CSRF,
  operation/context-bound recent WebAuthn, idempotency, and `If-Match` CAS;
- legacy-unbound and provider-unconfigured rows cannot return to pending;
- the test-only child-process harness uses independent PostgreSQL pools and
  proves all six closed hard-`SIGKILL` boundaries converge after restart.

Implemented W1.5 provider-convergence slice in migration `0036`:

- hosted configuration requires explicit delivery and linearizable acceptance
  lookup endpoints plus an immutable random provider binding; no binding is
  derived from a destination URL;
- the provider adapter sends a minimal closed lookup DTO containing only the
  binding and public event idempotency key, and accepts only an exact echoed
  binding/key response under bounded HTTPS framing;
- bound uncertain rows receive a database-clock confirmation schedule;
  replicas claim due lookups with `SKIP LOCKED`, use a monotonic attempt fence,
  and publish only after an exact positive provider proof;
- a negative, malformed, timed-out, or lost lookup never retries notification
  content and leaves the row uncertain for a later bounded lookup;
- real PostgreSQL 16 tests prove durable provider acceptance across response
  loss, no second logical acceptance, automatic uncertain-to-published
  convergence, stale acknowledgement rejection, two-worker exclusion,
  retry/suppress CAS, and the 34→35 migration baseline chain;
- readiness now exports fixed aggregate oldest-uncertain age without tenant,
  member, event, destination, or provider-response labels, and fixed-key
  lookup/success/miss/failure counters expose confirmation behavior.

W1.5 release-gate status:

1. Complete: PostgreSQL 16 CI runs both `test:postgres:w15` and
   `test:postgres:w15:composed`, and retains the bounded race-matrix evidence
   artifact. An independent verifier requires a protected regular file and the
   exact fixed schema, public digests, zero pending claims, and zero active
   leases before upload. Tenant/member IDs, DSNs, provider diagnostics, message
   content, credentials, tokens, links, and broadly readable files are rejected.
2. Pending under W1.6: execute the operator drill in
   `OWNER_RECOVERY_DELIVERY_RUNBOOK.md` against a
   staging provider with a linearizable acceptance endpoint. This is an
   environment qualification, not an additional authority path in the product.

Post-W1.5 hardening, in order:

1. Composed authenticated-HTTPS-provider/worker/PostgreSQL qualification is implemented in
   `owner-recovery-https-provider-composed.integration.test.mjs` and is wired
   into the deterministic PostgreSQL 16 command; CI verification passes.
2. Retention/automatic-confirmation race coverage is implemented in
   `owner-recovery-retention-confirmation-races.integration.test.mjs` and is
   wired into the same command; CI verification passes. `uncertain` is
   non-terminal and therefore non-prunable by schema.
3. Complete in source: the fixed metrics, warning/critical alert-policy
   contract, validators, and runbook are wired to CI and retained in the
   published package. Pending in staging: install the exact policy in the
   deployment platform and retain one verifier-approved secret-free report.

W1.5 exits only when every scenario is repeatable, two workers cannot create two
logical provider deliveries, accepted-but-unconfirmed delivery is represented
explicitly rather than retried blindly, all leases converge after restart, and
the evidence artifact contains no notification content, member identifier,
token, DSN, or provider diagnostic.

Merge slices:

1. Run the recovery notification worker with PostgreSQL leases, bounded exponential backoff, deterministic idempotency, poison-message isolation, and crash-safe lease recovery.
2. Define provider adapters that accept only secret-free notification DTOs. Reject provider responses that echo credentials or unexpected payload fields.
3. Add dead-letter retention, suppression retention, redrive-attempt ceilings, bounded pruning, and immutable audit records for all operator actions.
4. Complete shared PostgreSQL throttles for login, WebAuthn, recovery creation/approval/exchange, and management mutations; add concurrent-session ceilings and organization session epochs.
5. Add metrics for queue age, attempts, dead-letter count, suppression, redrive success, rate denial, and recovery state latency without member PII or secret-bearing labels.

Exit gate:

- two workers cannot deliver the same logical notification twice;
- kill/restart at lease, provider-call, commit, and response-loss boundaries converges safely;
- provider outage cannot block authority transactions or widen authority;
- recovery enumeration, replay, race, and notification substitution tests pass across two API instances.

### W2 — production Console journey and browser qualification

Depends on W1 for recovery screens; read-only work may proceed in parallel.

Merge slices:

1. Remove remaining sample operational state. Every organization, member, session, credential, device, policy, agent, activity, recovery, and emergency state must come from an authenticated BFF response.
2. Complete the guided journey: sign in/passkey, organization selection/create, invitations and roles, device enrollment, repository policy, Claude Code/Cursor setup, sessions, activity, revoke, emergency stop, recovery, and purge.
3. Centralize strict DTO parsing, cursor handling, stale-version reconciliation, authorization visibility, no-store behavior, and stable localized error mapping.
4. Add Playwright virtual-WebAuthn matrices for Owner/Admin/Auditor/Viewer, session expiry/revocation, organization switch, CSRF/origin rejection, conflict refresh, recovery, and destructive confirmations.
5. Add accessibility and responsive gates: keyboard-only completion, focus restoration, dialog semantics, live-region behavior, reduced motion, 200% zoom, and mobile-safe recovery.
6. Inspect browser bundles, DOM, local/session storage, IndexedDB, Cache Storage, logs, traces, and screenshots for forbidden material.

Exit gate:

- all supported role journeys pass in Chromium and WebKit, with Firefox included where virtual-authenticator support permits;
- no production screen falls back to fixture/sample data;
- production browser requests contain no Cloud operator bearer token;
- CSP, HSTS, same-origin BFF, cookie, Origin, CSRF, redirect, and cache tests pass.

### W3 — purpose-separated managed signers

May prepare behind disabled hosted feature gates while W2 runs. Production enablement depends on W2.

Merge slices:

1. Freeze a provider-neutral signer interface for capability, ControlBundle, refresh hint, possession receipt, Agent Session Grant, qualification manifest, audit anchor, and promotion evidence purposes.
2. Give each purpose a separate workload identity and KMS/HSM key. The caller cannot select an arbitrary key, purpose, algorithm, or signing domain.
3. Persist immutable key ID/version metadata and implement active, retiring, revoked, and emergency-disabled states with bounded verification overlap.
4. Preserve exact committed signed bytes for idempotent response-loss retries; never re-sign the same authority mutation on retry.
5. Implement timeout, throttling, circuit-breaker, health, rotation, restore, compromise, and no-file-fallback behavior.

Exit gate:

- IAM tests prove cross-purpose and key-export denial;
- rotation preserves required historical verification and prevents new signing with retired keys;
- outage, malformed provider responses, partial rotation, database rollback, and response loss fail closed;
- hosted startup refuses file-backed signers or incomplete purpose mappings.

### W4 — headless macOS onboarding and agent adapters

Depends on stable hosted Device/Human APIs and signer contracts from W2–W3.

Merge slices:

1. Finish one resumable state machine shared by CLI and any future native UI: verify artifact, initialize broker, enroll device, bind organization, install policy, connect agent, run signed-commit self-test.
2. Complete `agentpass install`, `setup`, `doctor`, `launch`, `status`, `close`, `revoke`, `uninstall`, and explicit `purge` behavior with repair guidance and secret-free machine-readable output.
3. Complete the Claude Code adapter first. Pin executable identity/version, process ancestry, repository/worktree, branch/ref, operation, TTL, policy generation, and capability budget.
4. Add Cursor parity only after the same Claude Code authority lifecycle passes. Keep adapters thin and route signing through the same native broker transaction.
5. Complete refresh-hint/polling, atomic ControlBundle installation, applied/blocked ACK, offline expiry, audit upload, emergency stop, and crash recovery.
6. Test install, upgrade, rollback refusal, uninstall-preserve, reinstall-recover, and current-user purge across interruption points.

Exit gate:

- each adapter performs two unattended commits verified with `git verify-commit`;
- revocation, expiry, process death, executable substitution, PID reuse, ancestry substitution, repository/worktree substitution, and concurrent budget exhaustion fail closed;
- no private key or reusable authority crosses Secure Enclave/Keychain/XPC boundaries;
- secrets are absent from argv, environment, stdin, shell history, repository files, logs, and crash reports.

### W5 — immutable macOS distribution and hardware qualification

Depends on W4.

Merge slices:

1. Build one universal hardened-runtime PKG containing the broker, XPC services, launchd jobs, CLI, Git helper, and adapters.
2. Sign all nested code with the fixed Developer ID team and entitlements, notarize, staple, and independently verify the final archive.
3. Generate checksums, SBOM, provenance, nested code-identity manifest, and a signed release manifest. Direct download and Homebrew install the same immutable PKG.
4. Execute clean-machine install, enroll, Claude Code/Cursor commit, audit, revoke, offline expiry, recovery, upgrade, uninstall, reinstall, and purge journeys.
5. Run the protected fault/identity matrix on Apple silicon with Secure Enclave and Intel with T2 against the exact same artifact digest.

Exit gate:

- untouched signed reports from both hardware lanes bind source commit, PKG digest, Team ID, nested CodeDirectory identities, notarization ticket, OS/hardware, Cloud image/schema, and signer key versions;
- all required negative identities fail before the privileged selector;
- teardown proves no residual qualification listener, authority, grant, or mutable candidate remains;
- Homebrew and direct-download verification resolve to the same release manifest and PKG digest.

External requirements: Apple Developer Program credentials, Developer ID Application/Installer identities, notarization credentials, and physical Apple silicon and Intel/T2 machines. These gates cannot be replaced with mocks.

### W6 — hosted staging and production deployment

Infrastructure preparation may run beside W4–W5. Promotion depends on W3 and W5.

Merge slices:

1. Provision isolated development, staging, and production accounts; private PostgreSQL connectivity; workload identity; KMS/HSM; object storage; DNS/TLS; WAF/rate limits; and protected migration and release roles.
2. Build immutable Console, API, and worker images. Apply migrations as an explicit one-writer stage with compatibility preflight, canary, graceful drain, traffic rollback, and forward-fix procedure.
3. Configure encrypted backups, PITR, retention, cross-failure-domain copies, scheduled restore verification, and authority-manifest comparison.
4. Add SLO-derived metrics and alerts for authentication, WebAuthn, enrollment, signer latency/error, stale bundles, ACK lag, stop propagation, audit gaps, outbox lag, DB saturation, migration drift, and backup age.
5. Complete redaction review, dependency scanning, SAST, DAST, container/IaC scanning, load/failure tests, incident runbooks, on-call ownership, and disclosure procedures.
6. Commission an independent security review, remediate every critical/high finding, and record accepted lower findings with owner and deadline.

Exit gate:

- staging restore and rollback drills meet measured RPO/RTO;
- multi-instance race, region/provider outage, KMS rotation, DB failover, queue backlog, and emergency-disable exercises pass;
- one signed promotion record binds the commit, images, PKG, migrations, signer versions, SBOM/provenance, browser E2E, restore drill, security review, and both hardware reports;
- there are zero unresolved critical/high findings and no undocumented security exceptions.

## 5. Parallel work lanes

| Lane | May proceed now | Serialization boundary |
| --- | --- | --- |
| Recovery data/API | W0 PostgreSQL qualification and W1 worker design | migrations, recovery state machine, recent-auth context |
| Console | W0 client/UI and W2 read-only journeys | Human DTOs, BFF security policy, destructive enablement |
| Managed signers | W3 provider adapters behind disabled gates | signing domains, key metadata, hosted activation |
| Native | W4 CLI/adapter tests against frozen contracts | XPC selectors, entitlements, durable state, code identities |
| Release/operations | CI, SBOM, IaC, runbook preparation | artifact digest, production credentials, promotion record |

The integration owner reviews every serialized boundary before dependent lanes resume. Parallel agents use disjoint file ownership and return changes for central review; they do not merge, migrate, or widen a security contract independently.

### Ordered execution from the current checkpoint

The next implementation cycle is organized as small merge units. “Parallel”
below means implementation may proceed concurrently, but the listed authority
or release boundary still has one owner and one ordered merge queue.

| Order | Merge unit | Concrete output | Required verification | Unblocks |
| --- | --- | --- | --- | --- |
| 1 | W1.6 observability contract — complete | Fixed-name recovery/limiter metrics, ten fixed alert rules, runbook, and secret/PII label deny-list | Metric snapshot tests, sink-failure tests, alert-rule validation | Operational drill |
| 2 | W1.6 outage drills — source gate complete, staging run pending | Provider outage, worker restart, limiter outage, uncertain-delivery adjudication, dead-letter redrive, and prune-failure procedures | Protected staging drill report bound to commit/image/policy/schema and scrubbed by the evidence verifier | W1 exit |
| 3 | W2.1 Console data inventory | Delete remaining sample state; map every screen to a strict Human BFF DTO and authoritative version | Static fixture-fallback detector, DTO negative tests, no-store/header tests | Full Console work |
| 4 | W2.2 identity and organization journey | Passkey sign-in, organization create/select/switch, invitations, role changes, session expiry, and logout | PostgreSQL + virtual-WebAuthn role/tenant/replay matrix | Device enrollment UI |
| 5 | W2.3 device and policy journey | Enrollment, device list/detail, repository policy editor, agent connection instructions, wake/ACK status | Stale-version races, signed ACK proof, cross-tenant and malformed-response tests | Agent onboarding |
| 6 | W2.4 operations journey | Sessions, activity, revoke, emergency stop, recovery, dead-letter operations, and purge confirmations | Owner/Admin/Auditor/Viewer browser matrix and exact recent-auth context tests | Console release candidate |
| 7 | W2.5 browser hardening | CSP/HSTS/cookies/CSRF/origin/cache policy, keyboard/focus/live-region/zoom/reduced-motion, forbidden-material scan | Chromium + WebKit; Firefox where authenticator support permits | W2 exit |
| 8 | W3.1 signer contract freeze — parallel with 3–7 | One provider-neutral purpose map, immutable key metadata, fixed algorithms/domains, no caller key selection | Catalog/OpenAPI/schema compatibility and cross-purpose negative tests | Managed KMS qualification |
| 9 | W3.2 managed signer qualification | Separate AWS/GCP workload identities and keys for every purpose; provider timeout/throttle/circuit behavior | IAM denial, non-exportability, outage, malformed response, and no-file-fallback evidence | Hosted signer activation |
| 10 | W3.3 rotation and recovery — three-purpose runtime source complete, external qualification pending | Migration 0037, durable lifecycle operations, exact signature replay, pending/uncertain quarantine, PostgreSQL-first startup, and Agent Session/qualification/possession KMS composition | Attach AWS/GCP IAM and non-exportability evidence; complete forced-termination, rotation/restore, and restart-safe verification in protected staging | W3 exit |
| 11 | W4.1 headless setup state machine — v2 Device handoff and hosted possession signer composed | Strict v2 invitation, signed receipt recovery/read, verified receipt before trust persistence, no response-loss POST replay | Complete Console enrollment and interrupt/restart physical-Mac journey with machine-readable secret scan | Claude Code adapter |
| 12 | W4.2 Claude Code adapter | Identity/ancestry/repository/worktree/branch/TTL/generation/budget binding and Git signing self-test | Two unattended verified commits plus substitution, expiry, death, PID-reuse, and budget races | Primary native journey |
| 13 | W4.3 Cursor parity and lifecycle | Thin Cursor adapter plus revoke, close, uninstall-preserve, reinstall-recover, and explicit purge | Same authority matrix as Claude Code; no adapter-specific authority path | W4 exit |
| 14 | W5 release candidate | Universal hardened-runtime PKG, nested signatures, notarization/stapling, SBOM, provenance, release manifest, Homebrew bootstrap | Independent artifact verification and clean-machine journeys | Physical qualification |
| 15 | W5 hardware qualification | Exact-digest Apple silicon/Secure Enclave and Intel/T2 qualification reports | Protected P0-C gates, teardown proof, aggregate report verifier | W5 exit |
| 16 | W6 hosted promotion | IaC, immutable images, migration stage, backups/PITR, SLOs, restore/failover drills, independent review | Signed promotion record with zero open critical/high findings | AgentPass v1 |

The integration order is `1 → 2`, `3 → 4 → 5 → 6 → 7`,
`8 → 9 → 10`, `7 + 10 → 11 → 12 → 13`, and
`13 → 14 → 15 → 16`. Infrastructure preparation for unit 16 may proceed
earlier, but production credentials and promotion authority are introduced only
at the final gated stages.

### Next three implementation cycles from migration 0037

Migration 0037 and strict Device enrollment v2 are now the source baseline.
The durable lifecycle is now composed with the first three hosted KMS purposes
without a retry path that can issue two signatures for one authority mutation.
The immediate critical path moves to external KMS/IAM qualification and the
signed device-enrollment vertical slice. Work remains feature-gated until every
exit condition below passes.

#### Cycle C — hosted signer runtime composition

Three disjoint lanes may proceed in parallel, followed by one ordered integration
merge:

| Lane | Owned scope | Deliverable | Required negative evidence |
| --- | --- | --- | --- |
| Runtime composition | Cloud startup/composition, signer factory, readiness, configuration tests | Start PostgreSQL and verify schema 37 first; load immutable provider metadata; bind each purpose to exactly one lifecycle repository and KMS provider; publish readiness per purpose only after metadata and active-key agreement. | Missing/duplicate purpose, shared forbidden key, wrong algorithm/domain, database unavailability, metadata mismatch, file-backed hosted fallback, and partial initialization prevent the listener from becoming ready. |
| Durable signing | Managed signer wrapper and PostgreSQL integration tests | Implement `reserve -> provider sign once -> commit exact bytes -> reply`. A committed operation replays identical bytes; an ambiguous provider or commit result becomes `uncertain`; concurrent same-operation calls share one in-process promise. | Provider timeout before/after acceptance, process loss at every boundary, commit loss, two replicas racing, conflicting payload reuse, retired/emergency-disabled key, and malformed signature never trigger a blind re-sign. |
| Purpose wiring | Purpose-specific configuration and signer consumers | Wire Agent Session Grant and qualification first, then possession receipt, capability, ControlBundle, refresh hint, audit anchor, and promotion evidence. The caller supplies payload only and cannot select purpose, key, algorithm, version, or signing domain. | Cross-purpose substitution, key/version downgrade, caller-selected key, unknown provider metadata, and incomplete environment mapping fail closed. |
| Integration owner | Shared startup, contracts, catalog, CI, and release notes | Merge in the order runtime foundation, durable wrapper, then purpose consumers; keep production activation disabled; run root, real PostgreSQL, two-instance, and hosted-composition gates. | No public schema is widened and no purpose is activated until its durable and provider-failure matrices pass. |

Cycle C acceptance criteria:

1. Production mode has no in-memory or file-backed signer fallback.
2. Every enabled purpose reports provider key ID, immutable key version,
   fingerprint, algorithm, signing domain, lifecycle state, and readiness without
   exposing private material.
3. A repeated operation ID with the same canonical payload returns byte-identical
   output; a different payload is rejected as a conflict.
4. `uncertain` operations are quarantined. They may be reconciled only from
   provider-confirmed exact signature bytes; otherwise operator resolution is
   required.
5. Real PostgreSQL 16 tests pass with two API replicas and forced termination at
   reserve, provider acceptance, database commit, and response boundaries.

#### Cycle D — complete enrollment and Claude Code vertical slice

Cycle D starts when the possession-receipt purpose passes Cycle C. Console work
may begin earlier against the frozen v2 contract, but end-to-end enablement waits
for the hosted signer.

| Lane | Owned scope | Deliverable | Required verification |
| --- | --- | --- | --- |
| Console enrollment | Human BFF, browser enrollment views, strict invitation DTO | Owner/Admin creates a one-time invitation, sees expiry and target device constraints, copies or launches a redacted setup command, and observes pending/enrolled/recovery-proven states. | Virtual-WebAuthn role matrix, tenant isolation, expiry/replay, stale version, CSRF/origin, malformed receipt, response-loss, and forbidden browser-storage scan. |
| Headless setup | Shared onboarding state machine, CLI commands, local durable journal | `agentpass setup` verifies the invitation, creates a P-256 device key in the protected native boundary, performs v2 enrollment, verifies the signed receipt, resumes safely after interruption, installs trust atomically, and prints secret-free JSON status. | Interrupt before/after each durable transition, no POST replay after ambiguity, invitation substitution, endpoint downgrade, signer-key mismatch, receipt mismatch, and private-material scan of argv/env/stdin/logs/files. |
| Claude Code adapter | Adapter identity binding, capability request, Git signing path, doctor/self-test | Bind executable identity/version, parent ancestry, repository/worktree, branch/ref, operation, TTL, policy generation, and budget; route signing through the broker; add `doctor` and a signed-commit self-test. | Two unattended `git verify-commit` successes followed by revocation, expiry, process death, PID reuse, executable/ancestry/repository/worktree substitution, stale generation, and concurrent budget exhaustion failures. |
| Integration owner | Cloud/Console/native protocol boundary and E2E | Run one clean-machine-like journey: invitation -> setup -> session -> two commits -> activity -> revoke -> denied third commit. Preserve only redacted evidence bound to commit and schema version. | Any unverified trust persistence, reusable browser/operator token, private-key export, or adapter-specific privileged signing path fails the gate. |

Cycle D acceptance criteria:

1. A non-engineer can complete enrollment from the Console with one documented
   terminal command and actionable repair output.
2. An agent can make two unattended, policy-bound commits after setup without a
   biometric prompt, while revocation and expiry stop subsequent signing.
3. Response-loss recovery distinguishes `enrollment proven` from `control trust
   installed`; a receipt alone never fabricates missing control roots.
4. CLI and future native UI consume the same state machine and protocol types.

#### Cycle E — qualification, Cursor parity, and release candidate

1. Add the thin Cursor adapter only after the Claude Code authority matrix is
   green; it must reuse the broker transaction and all policy bindings.
2. Complete close, revoke, uninstall-preserve, reinstall-recover, and explicit
   purge journeys, including interruption and rollback-refusal tests.
3. Produce one universal hardened-runtime PKG, sign every nested binary, notarize,
   staple, generate SBOM/provenance/checksums, and make direct download and
   Homebrew consume the same immutable artifact.
4. Qualify that exact digest on Apple silicon/Secure Enclave and Intel/T2. Mocked
   CI remains useful but cannot close the hardware gate.
5. In parallel, provision isolated staging infrastructure and test-only AWS/GCP
   identities for all signer purposes. Record key non-exportability,
   cross-purpose IAM denial, outage/circuit behavior, rotation, restore, and
   emergency-disable evidence.
6. Promote only after restore/failover drills, independent security review, and a
   signed promotion record show zero unresolved critical/high findings.

Cycle E external dependencies are explicit: Apple Developer credentials,
physical qualification Macs, cloud KMS accounts, protected staging, and an
independent reviewer. Source work may continue without them, but AgentPass v1
must not be described as production-complete until these evidence gates close.

## 6. Commit and verification cadence

Each slice should be one reviewable commit or a short, ordered commit series. The minimum local gate is:

```text
npm run contracts:validate
npm run lint
npm test
npm run test:native
npm run test:native-app
npm run test:native-installer-preservation
npm test --prefix apps/web-console
npm run lint --prefix apps/web-console
git diff --check
```

Add real PostgreSQL, two-instance, Playwright, KMS/IAM, packaging/notarization, restore, and physical-hardware gates whenever the changed boundary requires them. A commit is pushed only after its applicable gates pass; a production claim is made only after the external evidence is attached.

## 7. Immediate commit queue

1. `feat: throttle session bootstrap across api replicas` (W1.4a, complete)
2. `feat: observe committed recovery transition latency` (W1.4b, complete)
3. `feat: bind recovery delivery and operator quarantine controls` (W1.5, merged)
4. `feat: confirm provider acceptance and qualify delivery races` (W1.5, complete in this change)
5. `test: compose https provider faults with worker and postgres` (W1.5 hardening and PostgreSQL 16 CI verification complete)
6. `ci: repair full qualification prerequisites` (W1.5 CI repair, complete)
7. `test: restore hosted p0b runtime composition` (W1.5 CI repair and source-bound external qualification complete)
8. `ops: implement the recovery operational gate` (W1.6 source implementation complete; exact-image staging execution pending)
9. `test: close the production console browser matrix` (W2; organization journey and fail-closed self-logout/expiry source paths implemented, protected browser/PostgreSQL matrix pending)
10. `feat: qualify purpose-separated managed signer providers` (W3; AWS/GCP adapters and isolated timeout/throttle/integrity circuit behavior implemented, all-purpose IAM/non-exportability/outage/rotation evidence pending)
11. `feat: add signer lifecycle and resumable onboarding` (W3.3/W4.1; source lifecycle, shared durable setup reader, redacted output, and Console role enforcement implemented; external durability/enrollment evidence pending)
12. `feat: persist signer lifecycle and require v2 device receipts` (W3.3/W4.1; migration/repositories and strict client/Cloud contract implemented; runtime composition and physical evidence pending)
13. `feat: compose durable hosted signer runtime` (W3.3/W3.4; source implementation complete for Agent Session, qualification, and possession receipt; protected AWS/GCP qualification pending)
14. `feat: complete signed device enrollment journey` (W4.1; Console plus resumable headless setup)
15. `feat: complete claude code headless onboarding` (W4.2)
16. `feat: add cursor adapter parity` (W4.3)
17. `build: produce signed notarized immutable pkg` (W5)
18. `ops: qualify and promote hosted production release` (W6)

Items 10, 11, 14, and 15 remain externally gated until the required Apple, cloud,
hardware, deployment, and independent-review resources are available.

## 8. Final definition of done

AgentPass v1 is complete only when a new user can install the verified PKG, enroll from the browser/CLI flow, configure Claude Code and Cursor, produce unattended policy-bound commits, inspect and revoke authority in the Console, recover access without a single-party takeover, and safely upgrade or remove the product. The exact production release must use PostgreSQL and purpose-separated managed keys, pass browser and two-lane physical qualification, survive restore and rollback drills, and have no unresolved critical/high security finding.
