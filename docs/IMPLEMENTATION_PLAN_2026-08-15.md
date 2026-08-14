# AgentPass production implementation plan

Status: active

Planning baseline: `codex/agent-platform` after the C1.4 provider-operation
maintenance and adjudication-contract checkpoint

Planning date: 2026-08-15

## 1. Release outcome

The first production release is a headless-first security product for Claude
Code and Cursor. The installed component is one immutable, Developer ID-signed
and notarized macOS PKG containing the broker, launchd services, CLI, Git
integration, and editor adapters. Direct download and Homebrew install the same
PKG digest. The web Console is the human control plane for organization,
membership, enrollment, policy, revocation, recovery, and audit. A separate
native GUI is optional and must not contain another protocol or authority
implementation.

Production completion means:

- private signing keys are non-exportable and no hosted file-key fallback exists;
- every authority change is organization-scoped, role-checked, recently
  authorized when required, idempotent, and audited;
- a supported coding agent can make unattended, policy-bound signed commits;
- revocation, provider/database failure, response loss, restart, upgrade, and
  rollback have measured and rehearsed behavior;
- staging, production, direct-download, and Homebrew artifacts all identify the
  same source and package digest.

## 2. Current trusted baseline

Implemented in the branch baseline; C1 is closed by the retained, independently
verified source-bound CI artifact described below:

- frozen Core/OpenAPI/JSON Schema contracts and 42 forward-only migrations;
- organization roles, Human sessions, WebAuthn, Device APIs, control state,
  audit, emergency revocation, owner recovery, and browser-assisted enrollment;
- managed signer registry for eight distinct signing purposes;
- AWS KMS and Google Cloud KMS adapters plus purpose-specific runtime signer
  boundaries for all eight hosted purposes, with no local fallback in hosted
  mode;
- PostgreSQL lifecycle/idempotency, signature verification before commit,
  response-loss quarantine, bounded signer leases, fencing tokens, lifecycle
  epoch checks, and emergency-disable commit fencing;
- provider-neutral `signOnce`/`lookup` reconciliation contract that binds exact
  signing bytes, request digest, purpose, protocol version, provider receipt,
  key version, and pinned public key;
- migration `0040` and a purpose/key-version-scoped PostgreSQL provider-operation
  ledger with database-clock leases, hashed fencing claims, restart recovery,
  exact output verification, and immutable terminal rows;
- PostgreSQL app/migrator/backup role contract and an opaque privilege checker;
- Console role boundaries, logout/reauthentication, recovery operations, and
  local browser qualification.

Not yet production evidence:

- all eight purposes provisioned and exercised against real managed keys;
- two-instance/provider-response-loss qualification under real contention;
- protected PostgreSQL cutover, backup, PITR, and restore measurements;
- immutable signed/notarized universal PKG on physical Apple silicon and Intel;
- Claude Code and Cursor physical end-to-end qualification;
- staging deployment, independent security review, and production promotion.

## 3. Execution order

```text
Q2A database authority ─┐
Q2B all-purpose KMS ────┼─> Q2C two-instance signing qualification ─┐
Q2D Console operations ─┘                                           │
Q3A immutable package ─> Q3B physical Mac qualification ────────────┼─> Q4 agent E2E
                                                                    │
Q1 browser enrollment qualification ────────────────────────────────┘

Q2 + Q3 + Q4 evidence -> Q5 staging drills -> security review -> exact-candidate production promotion
```

Only contract-compatible UI, documentation, and test work may run ahead of a
dependency. No modeled, mocked, skipped, simulator, or local test is promoted
as physical or production evidence.

## 4. Q2 — production data and signing authority

### Q2A. PostgreSQL authority boundary

Merge slices:

1. Catalog migrations 0038–0040, integrate the three-role SQL contract into cutover,
   and require the privilege checker before switching traffic.
2. Add a disposable PostgreSQL 16 integration test that creates the roles,
   applies migrations as `agentpass_migrator`, executes application repository
   smoke tests as `agentpass_app`, and proves DDL/function execution denial.
3. Add backup-role qualification, encrypted backup, point-in-time target,
   restore into an isolated database, checksum/row-count verification, and an
   authority-state comparison report.
4. Add transaction/statement/lock/idle deadlines, TLS `verify-full`, bounded
   pools, slow-query observability, migration advisory locking, and fail-closed
   readiness.

Required attacks and failure tests:

- app attempts schema creation, ownership change, truncate, trigger creation,
  arbitrary function execution, and role switching;
- backup attempts mutation, sequence consumption, function execution, and
  access outside the approved schema;
- two migrators race, migration execution is interrupted, checksum changes,
  restore is partial, TLS identity is wrong, and the database is read-only.

Exit gate: a protected environment passes cutover, least-privilege checks,
backup, PITR restore, and rollback rehearsal with measured RPO/RTO. Runtime
credentials cannot migrate or administer the database.

### Q2B. Complete managed-key composition

Provision one non-exportable Ed25519 authority for each frozen purpose:

1. `agentpass.capability`.
2. `agentpass.control-bundle`.
3. `agentpass.refresh-hint`.
4. `agentpass.possession-receipt`.
5. `agent-session-grant`.
6. `agentpass.qualification-grant-batch-manifest`.
7. `agentpass.audit-anchor`.
8. `agentpass.promotion-evidence`.

Console identity assertions and WebAuthn assertions are separate identity
boundaries. They must not reuse any of these eight keys or be silently modeled
as a ninth signer-registry purpose. If a future hosted Console assertion needs
a managed key, it receives a separately versioned identity contract before
implementation.

For each purpose, pin provider, project/account, region, key resource, public
key fingerprint, algorithm, protocol version, signing version, lifecycle
version, IAM principal, and rotation policy. Hosted startup fails if any
required purpose is missing, shared with another purpose, disabled, exportable,
wrong-algorithm, wrong-version, or resolved through a file/local fallback.

Merge slices:

1. Wire the provider-neutral reconciliation contract into the runtime signing
   coordinator and persist the validated provider receipt.
2. Compose ControlBundle and capability, then Human assertion and audit/promotion
   evidence, without changing the frozen purpose registry.
3. Add purpose-by-purpose readiness and fixed-cardinality metrics with no key
   material, request bytes, tenant identifiers, or provider diagnostics.
4. Add rotation overlap, drain, stale-version rejection, emergency disable,
   rollback prohibition, and independently signed rotation evidence.

Exit gate: all eight purposes sign and verify against real managed keys under
their production IAM principals, and an image/configuration scan proves there
is no hosted private-key fallback.

#### Q2B integration checkpoints

Implementation checkpoint (2026-08-15): Q2B-1 and the ControlBundle/capability
portion of Q2B-2 are implemented. Hosted configuration requires all eight
purpose mappings, rejects the legacy four-purpose set, and forbids the bundle
private-key path. Audit-anchor v1 and promotion-evidence v2 now have closed
canonical statements, schemas, purpose-specific signer/verifier boundaries,
and hosted runtime composition through the PostgreSQL managed-signer lifecycle
repository. The provider-operation reconciliation adapter is now wired into the
hosted runtime through migration `0040`; focused tests and a disposable real
PostgreSQL two-instance test prove contention convergence and restart recovery.
This is AgentPass ledger evidence, not an AWS/GCP acceptance receipt and not an
exactly-once KMS-call claim. The authoritative audit-export and
release-promotion producers, complete lifecycle/commit fault qualification,
eight-purpose readiness, and real-provider qualification remain open. Q2B-3
and Q2B as a whole are therefore not complete.

| Checkpoint | Code outcome | Required test/evidence | Merge gate |
| --- | --- | --- | --- |
| Q2B-1 complete provider set | Runtime constructs exactly eight purpose-bound providers from a closed public configuration. | Unit tests reject missing, duplicated, shared-resource, shared-fingerprint, alias, unversioned, local, file, and private-material configurations. | Hosted startup cannot construct a partial provider set. |
| Q2B-2 ControlBundle/capability | Both authorities use asynchronous durable managed signers; the HTTP layer receives only purpose-specific signer methods. | Exact canonical-byte, domain, purpose, version, forged-result, timeout, response-loss, restart, and idempotency tests. | Hosted code and configuration no longer read a bundle/capability private-key file. |
| Q2B-3 audit/promotion | Audit anchors and promotion evidence use separate providers and schemas; unsigned or locally signed production evidence is rejected. | Cross-purpose substitution, stale lifecycle, emergency-disable, and verifier compatibility tests. | Registry status and contract catalog reflect implemented producers and verifiers. |
| Q2B-4 runtime closure | Readiness reports every purpose with fixed-cardinality redacted metadata; shutdown drains all providers. | Two-instance real-provider qualification plus configuration/image secret scan. | Eight healthy providers are required before traffic readiness. |

Each checkpoint is one reviewable commit and push. A checkpoint may preserve a
local signer only in the explicit evaluation profile; hosted selection of that
path is a startup error and is covered by a negative test.

### Q2C. Durable signing and reconciliation qualification

Build a two-instance fault matrix around reserve, provider start, provider
acceptance, lookup, terminal commit, and response encoding. A claim that expires
before provider start may be reclaimed with a new fencing token. A claim that
crosses the provider boundary becomes uncertain and may converge only through
an exact provider lookup. Commit requires the original binding, valid signature,
pinned public key, active lifecycle epoch, and authoritative provider receipt.

Required scenarios:

- 100 concurrent exact requests across two API instances;
- operation ID reused with changed bytes, purpose, key, version, or protocol;
- process kill before provider start, during provider call, after acceptance,
  before commit, after commit, and before response;
- provider timeout, throttling, malformed receipt, wrong public key, invalid
  signature, unavailable lookup, and conflicting lookup result;
- rotation or emergency disable between reserve, provider start, and commit;
- database failover and lost `COMMIT` response.

Exit gate: every case produces exactly one verified committed result or one
explicit, durable, operator-actionable uncertain/rejected state. No case blindly
re-signs an ambiguous operation.

### Q2D. Console production operations

Implement the web Console as a strict BFF-backed control plane:

- organization/member/role/invitation management;
- device enrollment, inventory, trust state, revoke, and re-enroll;
- policy and Agent Session Grant inspection, narrowing, expiry, and revocation;
- managed-key health, rotation progress, and emergency stop;
- bounded audit search/export and security-event timelines;
- recovery, dead-letter, uncertain-signing adjudication, and operator evidence.

Authority-changing actions require role authorization, CSRF protection,
resource-bound recent WebAuthn authorization, `If-Match`, idempotency, exact
confirmation text where destructive, and authoritative post-commit state.
Viewer/Auditor/Admin/Owner visibility and actions are independently tested.

Exit gate: Playwright tests cover success, keyboard/accessibility, stale state,
tenant substitution, role denial, replay, concurrent mutation, expired session,
network response loss, and absence of reusable authority in browser storage,
URLs, logs, traces, and rendered errors.

## 5. Q3 — immutable macOS distribution

### Q3A. One immutable candidate

1. Produce a universal PKG with pinned component inventory, ownership,
   permissions, entitlements, launchd definitions, CLI/adapters, and receipt.
2. Sign nested code with Developer ID Application, sign the package with
   Developer ID Installer, notarize, staple, and verify Gatekeeper offline.
3. Bind source commit, build environment, SBOM, Team ID, signing identities,
   notarization ticket, package digest, and update metadata into manifest v4.
4. Publish direct download and a Homebrew cask/bootstrap that verify and install
   that exact digest. Neither path rebuilds or repackages the product.

### Q3B. Physical qualification

Run clean install, upgrade, failed upgrade, rollback, uninstall-preserve,
reinstall, explicit purge, launchd restart, reboot, sleep/wake, Secure Enclave
loss, and key rotation on current Apple silicon/Secure Enclave and supported
Intel/T2 hardware. Verify protected state is never included in the package or
removed unintentionally.

Exit gate: both physical lanes accept one candidate; every installed receipt,
download, Homebrew metadata, SBOM, notarization ticket, and evidence report
resolves to the same PKG digest.

## 6. Q4 — Claude Code and Cursor production E2E

Implement Claude Code first, then Cursor against the same adapter contract.
Bind repository identity, canonical worktree, branch, remote, operation, device,
agent process, executable identity, policy sequence, budget, expiry, request ID,
and commit bytes to each authorization and signature.

Qualification matrix:

- clean guided install and repair/remove for each editor;
- two unattended signed commits verified by `git verify-commit`;
- malicious sibling process, executable replacement, repository/worktree/remote
  substitution, symlink/path race, and stale adapter configuration;
- 100-request contention, budget exhaustion, expiry, revocation during signing,
  daemon/editor restart, network loss, Cloud response loss, and audit fsync
  failure;
- no reusable token/key/assertion in argv, environment, shell history, files,
  logs, browser state, editor telemetry, or crash reports.

Exit gate: both supported agents complete the physical journey; revocation
blocks the next operation within the documented bound; every accepted and
denied operation is durably attributable without exposing a reusable secret.

## 7. Q5 — staging, security review, and production promotion

### Q5A. Reproducible staging

Deploy immutable Console/API/worker images, PostgreSQL, all managed signers,
TLS/DNS, rate limits, fixed-cardinality telemetry, alerts, and operator access.
Configuration is reviewed, versioned, secret-scanned, and reproducible. No
production credential appears in source, image layers, CI logs, or evidence.

### Q5B. Operational drills

Rehearse canary, drain, rollback, forward migration, encrypted backup, PITR,
signer rotation, provider outage, database failover, network partition,
emergency stop, owner recovery, uncertain-signing adjudication, dead-letter
redrive, and audit/export retention. Record measured RPO, RTO, revocation bound,
and recovery ownership.

### Q5C. Independent security review

Review local/XPC privilege boundaries, loopback onboarding, WebAuthn, session
and organization authorization, tenant isolation, replay/idempotency, managed
keys/IAM, reconciliation/fencing, package/update supply chain, audit integrity,
recovery, privacy, and denial of service. Close all critical/high findings and
retest security-relevant medium findings.

### Q5D. Exact-candidate promotion

Promote the already-qualified staging image and PKG digests without rebuilding.
Verify production readiness, monitoring, support matrix, disclosure policy,
rollback owner, emergency contacts, and evidence index before DNS/traffic
promotion.

Exit gate: no unresolved critical/high issue remains; restore and rollback have
measured evidence; production, staging, package, SBOM, and release manifest all
bind the same source and artifact identities.

## 8. Executable implementation backlog

The merge queue below is ordered by authority and evidence dependencies. Every
item is independently reviewable and must leave the hosted runtime fail-closed.
Q2B-1 and the ControlBundle/capability portion of Q2B-2 are complete at this
planning checkpoint; the next commit starts at M1.

### Current execution board

The order below is the implementation sequence, not a claim of production
evidence. A work package advances only when its listed exit proof is checked in
and source-bound CI is green.

| Work package | State | Depends on | Concrete output | Exit proof |
| --- | --- | --- | --- | --- |
| M1a evidence contracts | implemented locally | Q2B-1 | Audit-anchor v1 and promotion-evidence v2 canonical statements, schemas, fixtures, signers, and verifiers. | Canonical round trips and binding/substitution tests; catalog validation. |
| M1b managed runtime binding | implemented locally | M1a, Q2B-2 | Both evidence signers bind to distinct managed lifecycle repositories and pinned public keys. | Hosted startup rejects a missing, stale, shared, substituted, or local authority. |
| M1c provider-operation convergence | complete (C1) | M1b | A durable operation adapter and PostgreSQL operation ledger for deterministic Ed25519 retry/reconciliation. | Source-bound PostgreSQL 17 CI evidence verifies six scenarios with zero skips. |
| M1d authoritative producers | in progress | M1c | Audit-export anchor issuance, platform promotion approval, and promotion-evidence v3 issuance in the real transaction flows. | Neither production flow can finish unsigned, locally signed, or without a committed receipt. |
| M1e operator/API surfaces | queued | M1d | Read-only retrieval, verification, bounded export, and adjudication APIs plus audit events. | Tenant/role/recent-auth/replay/stale-state negative matrix passes. |
| M2 eight-purpose runtime closure | queued | M1d | Fixed-cardinality readiness, metrics, drain, and secret/image scan for all eight purposes. | Any unhealthy purpose blocks readiness; shutdown leaves no unfenced operation. |
| M3 two-instance real KMS | blocked on protected infrastructure | M2 | AWS and GCP two-instance fault-matrix evidence bundle. | Every operation reaches one verified result or an explicit durable terminal/operator state. |
| M4 PostgreSQL production authority | can run parallel with M1–M2 | migrations 0038–0040 | Role-separated CI, TLS/deadline hardening, backup, PITR, restore, and rollback evidence. | App cannot administer/migrate; measured protected-environment RPO/RTO. |
| M5 Console production slices | can begin after each backing API | M1e, M2, M4 per slice | Organization, device, policy, signer, audit, and recovery vertical slices. | Real-BFF Playwright role/reauth/stale/replay/a11y matrix passes. |
| M6 immutable macOS candidate | can run parallel after contract freeze | release manifest v4 | Universal signed/notarized/stapled PKG and digest-identical Homebrew/direct delivery. | Gatekeeper and lifecycle matrix pass on Apple silicon and Intel/T2. |
| M7 agent E2E and promotion | queued | M3–M6 | Claude Code/Cursor physical E2E, staging drills, independent review, exact-digest promotion. | No open critical/high issue; qualified digests are promoted without rebuild. |

Immediate merge order is M1c qualification, M1d, M1e, then M2. M4 and M6 may
proceed in parallel because they do not change the frozen signer statement
contracts. M5 may consume only merged authoritative APIs; it must not invent
browser-side authority or duplicate signing logic.

### Immediate commit queue

The following queue is the detailed implementation order from this checkpoint.
Each row is intended to be one reviewable commit unless its protected or
physical evidence must be attached separately.

| ID | Scope and concrete output | Required proof before merge | Depends on |
| --- | --- | --- | --- |
| C1 | Complete provider-operation qualification and retain source-bound evidence. | Real PostgreSQL two-pool matrix plus canonical evidence bound to source, catalog, migration, command, scenarios, and zero skips. | complete at `36a9981`; CI run `31842646306` and independently verified artifact SHA-256 `34a1276aa276a452cf0f6a2bd3a7dfa40d161fbd95ba2c9effb42f179ff9d8c4` |
| C2 | Implement authoritative audit-export issuance. Reserve an export sequence and payload digest transactionally, sign the frozen audit-anchor statement, commit the receipt, and expose immutable retrieval/verification. | Cross-tenant, range/digest substitution, duplicate request, signer timeout, response loss, restart, stale lifecycle, unsigned export, and local-signer-in-hosted-mode tests. | C1 |
| C3 | Implement authoritative release-promotion issuance. Bind source commit, candidate/image/PKG/SBOM digests, environment, qualification report digests, signer lifecycle, and approval state; prohibit rebuild-on-promotion. | Candidate/environment/evidence substitution, partial evidence, replay, concurrent promotion, signer failure, emergency disable, and exact-digest verifier compatibility tests. | C1 |
| C4 | Add operator reconciliation surfaces for uncertain signer operations and evidence. Provide bounded list/detail/verify and explicit retry/reject controls through the Human BFF. | Owner/Admin/Auditor/Viewer matrix; recent WebAuthn, CSRF, `If-Match`, idempotency, tenant hiding, stale-state, concurrent adjudication, and audit-event tests. | C2, C3 |
| C5 | Close all-eight-purpose runtime health and shutdown. Add fixed-cardinality readiness, provider/lifecycle probes, drain ordering, operation backlog metrics, and a hosted image/configuration secret scan. | Missing/shared/stale/disabled/wrong-key providers fail readiness; shutdown leaves no unfenced call; logs and metrics contain no request bytes, tenant IDs, claims, raw receipts, or private material. | C2, C3 |
| C6 | Harden PostgreSQL production authority. Run migrations as migrator, runtime smoke tests as app, backup as backup role; add TLS/deadline/pool/cutover checks. | Negative privilege matrix, concurrent/interrupted migration, checksum drift, read-only DB, wrong TLS identity, encrypted backup, isolated PITR restore, authority comparison, and measured RPO/RTO. | C1; parallel with C2-C5 |
| C7 | Ship Console vertical slices in API dependency order: organization, device, policy/session, signer, audit/export, recovery/reconciliation. | Real-BFF Playwright success/error/loading/empty/offline/a11y tests plus role denial, stale version, replay, response loss, tenant substitution, and browser-secret scans. | corresponding C2-C6 APIs |
| C8 | Run protected AWS/GCP signer qualification with versioned non-exportable Ed25519 keys and production-shaped IAM. | Two API instances, real PostgreSQL, provider throttling/outage, public-key substitution, signature failure, rotation, disabled key, and image/IAM/non-exportability evidence for all eight purposes. | C5, C6 |
| C9 | Produce one immutable macOS candidate: universal broker/XPC/CLI/adapters PKG, Developer ID signatures, notarization/stapling, SBOM, manifest v4, direct download, and Homebrew verification of the same digest. | Gatekeeper, entitlement, ownership/permission, install/upgrade/rollback/uninstall/reinstall/reboot/sleep-wake tests on Apple silicon and Intel/T2. | frozen client protocol; parallel after C1 |
| C10 | Qualify Claude Code, then Cursor, through the same adapter contract. | Two unattended verified commits, hostile sibling/executable/path/repository substitution, contention, expiry, revocation, restart, network loss, and credential-leak scans. | C7-C9 |
| C11 | Deploy immutable staging candidates, run operational drills, commission independent security review, close findings, and promote exact qualified digests. | Canary/drain/rollback, failover, PITR, signer outage/rotation, emergency stop, recovery, reconciliation, no open critical/high finding, and signed promotion evidence. | C8-C10 |

Parallel execution lanes are deliberately limited: C6 and C9 may run beside
C2-C5; Console work in C7 may start only after its backing authoritative API is
merged; C8 cannot start until readiness and PostgreSQL authority are closed;
C11 cannot waive or replace protected, physical, or independent evidence.

#### C1 security checkpoint — 2026-08-15

Implemented and verified in this checkpoint:

- both the provider-operation and lifecycle/idempotency ledgers converge after
  a lost low-level or high-level PostgreSQL `COMMIT` response without another
  provider call;
- rotation and emergency disable between provider acceptance and the
  authoritative lifecycle commit return no signature and leave the high-level
  operation explicitly `uncertain`;
- the public key verified during hosted startup is now pinned into both the
  reconciliation adapter and durable signer, so later provider metadata cannot
  replace the verification authority for sign or reconcile;
- shutdown now drains HTTP/PostgreSQL-tracked signing work before closing AWS
  or GCP KMS clients;
- provider-operation health is fixed-shape and retention deletes only a
  correlated pair whose low-level and high-level rows are both committed.

The direct AWS/GCP path still intentionally permits an at-least-once provider
call after an ambiguous response. Its deterministic receipt is an AgentPass
ledger receipt, not provider-issued acceptance evidence. The safety claim is
one exact verified result committed and returned, not exactly-once KMS use.

C1 is closed. Its automatic maintenance and contention boundary is implemented.
Migration `0041` records closed uncertainty reasons and
provides bounded stale-operation quarantine. One deployment-wide repository
maintains every purpose and historical key version under a single budget, and
one runtime worker publishes aggregate-only readiness and fixed counters. The
worker starts only after migration, cannot overlap itself, stops scheduling on
drain, and finishes before PostgreSQL closes. Two independent pools converge
100 identical requests, and the real PostgreSQL 17 matrix passes three
consecutive runs. Public health contains no operation ID, receipt, signing
bytes, tenant identifier, purpose, key version, or provider diagnostic.

Retention/reconciliation race qualification, constructor-failure cleanup, the
bounded nonterminal index, and the frozen internal adjudication contract are
included in the closed checkpoint. A lifecycle-fenced result remains explicitly
uncertain and is never automatically converted into success.

#### C1 completion sequence after migration 0041

Migration `0041` now records one closed `uncertain_reason`, backfills prior
uncertain rows conservatively, indexes bounded maintenance reads, and provides
an aggregate-only `SKIP LOCKED` quarantine function for expired `started`
claims. A non-overlapping, drainable worker contract is also implemented. This
is a schema/worker checkpoint, not runtime or production completion.

The remaining work is split into reviewable commits with explicit gates:

| Step | Implementation | Required verification | Completion signal |
| --- | --- | --- | --- |
| C1.1 deployment-wide repository — implemented | `maintainProviderOperations({limit})` and aggregate health cover every purpose and key version. Expired started rows are quarantined, exact persisted output may be reconciled, and only correlated terminal low/high-level pairs are pruned under one total budget. | Exact-shape, budget, pending exclusion, terminal immutability, `SKIP LOCKED`, malformed-row, and opaque DB-failure tests pass. | Implemented in `9092bad`; repository exports aggregate counts only. |
| C1.2 runtime and observability — pushed | One deployment-wide worker is constructed after migration, performs an initial cycle, exposes aggregate readiness and six fixed counters, and drains before PostgreSQL closes. | Startup enabled/disabled, non-overlap, sink failure, readiness timeout/failure/privacy, shutdown timeout, and resource-order tests pass. | Runtime and maintenance composition are pushed through `c6ddcd0`. |
| C1.3 two-pool PostgreSQL qualification — pushed | 100 identical requests run through two independent pools; stale started and pending separation, bounded cooperative quarantine, closed reasons, and terminal immutability are exercised. | PostgreSQL 17 integration passes repeatedly; one exact result converges without blind high-level replay. | Provider-operation classification and maintenance are pushed through `9092bad` and `c6ddcd0`. |
| C1.4 retention and operator boundary — pushed | Prove retention under two workers and locked rows; define bounded read-only uncertainty summaries and a purpose-bound, deployment-internal adjudication command contract, without adding the Human API yet. Document that direct KMS invocation may be at-least-once after ambiguity. | Retention/reconciliation races, stale lifecycle, unsupported reason, recovery exhaustion, privacy snapshots, purpose-crossing verification denial, PostgreSQL bigint key bounds, and threat-model/runbook review. | Implemented in `a89f557`; automatic maintenance never invents provider acceptance and the internal contract is exposed to no Human/tenant route. |
| C1.5 closure gate — complete | Run lint, contract validation, complete root suite, real-PostgreSQL matrix, and source-bound CI; archive exact command/environment results. | Zero unexpected skips/failures, schema version 42 everywhere, source-bound catalog digest, pushed commit, and a verified retained artifact. | GitHub run `31842646306` passed all four jobs for `36a9981`; retained artifact SHA-256 is `34a1276aa276a452cf0f6a2bd3a7dfa40d161fbd95ba2c9effb42f179ff9d8c4`. |

Local checkpoint evidence for C1.1-C1.4:

- contract catalog: 129 entries, 32 schemas, 55 OpenAPI operations, 42 migrations;
- focused contract, maintenance, repository, readiness, runtime, and migration
  suite: 102 passed, 0 failed;
- PostgreSQL 17 qualification: six scenarios passed, including a 120k-row
  index-plan check and the complete two-pool provider-operation matrix; the
  race matrix also passed ten consecutive runs while stabilizing C1.4;
- root suite: 2,085 tests, 2,029 passed, 56 intentionally skipped because their
  declared external dependencies were absent, 0 failed;
- lint, syntax checks, and whitespace checks pass.

#### Next implementation order

The next work is deliberately split into small commits so database authority,
operator authority, and product UI do not change in one review boundary.

| Order | Commit boundary | Concrete implementation | Verification and exit gate |
| --- | --- | --- | --- |
| 1 | C1.4a maintenance query hardening — implemented locally | Migration `0042` adds partial indexes for deployment-wide nonterminal age, reconciliation, and committed expiry. Every maintenance selection remains bounded and cooperative. | PostgreSQL 17 `EXPLAIN (ANALYZE, BUFFERS)` uses the intended indexes over 120k mixed provider rows plus 20k correlated high-level rows with real matching reconcile/prune candidates. |
| 2 | C1.4b lifecycle/retention race matrix — implemented locally | Real PostgreSQL qualification now covers bounded two-worker reconcile/prune, locked-row `SKIP LOCKED`, pending preservation, stale/disabled lifecycle non-promotion, and correlated pair deletion. First-reservation insert races converge through `ON CONFLICT`; opaque base64url claim tokens accept every valid leading character. | The complete five-scenario provider-operation matrix passes ten consecutive runs; one exact history converges without duplicate maintenance or blind signing. |
| 3 | C1.4c runtime construction safety — implemented locally | Post-pool construction uses deterministic best-effort cleanup, preserves the original error, releases the migration client once, closes each constructed worker/notifier, and ends the pool once. All workers start only after every constructor succeeds. | Migration, late-constructor, and worker-start failure injections pass; no scheduled timer survives and runtime regressions remain green. |
| 4 | C1.4d operator contract — implemented locally | The tenant-neutral internal contract permits exact SQL reconciliation, exact-purpose provider verification when explicitly allow-listed, and non-terminal producer handoff. Generic retry, confirm/reject invention, caller output, and direct Human/Console exposure are forbidden. | Bounded/privacy/purpose-crossing/bigint/result-state tests and the adjudication/runbook documents pass. Human role/WebAuthn/CSRF tests intentionally wait for C2/C3 producer-ledger organization correlation. |
| 5 | C1.5 closure — complete | The dedicated workflow ran the six-scenario PostgreSQL 17 matrix on the exact source commit, generated a canonical private evidence file, independently verified it, and retained it for 30 days. | Run `31842646306` is green for `36a9981`; all four jobs succeeded and the artifact binds the exact source/catalog/migration/command/scenarios with zero skips. |
| 6 | C2 and C3 in parallel | Build authoritative audit-export and release-promotion issuance on the closed ledger, each with its own schema, sequence/idempotency repository, signer purpose, retrieval, and verifier. | Cross-purpose/tenant/digest/environment substitution, response loss, restart, rotation, emergency stop, concurrent issuance, and hosted-local-fallback rejection. |
| 7 | C4 and C7 vertical slice | Add Human BFF uncertainty/reconciliation APIs, then the Console queue/detail/adjudication UI. UI consumes only frozen BFF DTOs and authoritative post-commit state. | Playwright role/a11y/loading/empty/error/stale/offline/response-loss tests; browser storage, URL, logs, traces, and rendered-output secret scan. |
| 8 | C5 and C6 infrastructure closure | Complete eight-purpose provider/lifecycle readiness and deterministic shutdown; add PostgreSQL migrator/app/backup role CI, TLS/deadlines, backup/PITR restore, and cutover checks. | Partial/shared/stale/disabled signer sets fail readiness; negative DB privilege matrix passes; protected restore records measured RPO/RTO and authority comparison. |
| 9 | C8 protected managed-key qualification | Provision versioned non-exportable AWS/GCP keys with production-shaped IAM and run two API instances against real PostgreSQL. | All eight purposes pass throttling/outage/rotation/disable/signature/public-key tests; IAM, non-exportability, image, and redacted evidence are independently reviewable. |
| 10 | C9 immutable macOS candidate | Build one universal Developer ID-signed, notarized, stapled PKG; direct download and Homebrew install the same digest. | Gatekeeper, entitlement, SBOM/manifest, ownership, install/upgrade/rollback/uninstall/reboot/sleep-wake tests on Apple silicon and Intel/T2. |
| 11 | C10-C11 release qualification | Qualify Claude Code then Cursor, deploy unchanged candidates to staging, run drills, close independent security review findings, and promote exact digests. | Two unattended `git verify-commit` successes per agent; measured revocation; canary/rollback/failover/PITR/recovery drills; no open critical/high finding; no rebuild during promotion. |

Parallelization rule: after C1, C2 and C3 may run in parallel; C6 database work
and C9 packaging may run beside them. C4 waits for the producer contracts, C7
waits for each matching BFF authority, C8 waits for C5 and C6, and production
promotion waits for every protected, physical, staging, and review gate.

#### C2/C3 authoritative-producer execution plan

This is the active implementation plan after C1 closure. C2 is tenant-bound;
C3 is deployment/platform-operator scoped and must never derive authority from
Organization Owner/Admin membership. Promotion-evidence v1/v2 remain legacy
verification formats. New issuance uses v3 and cannot silently weaken itself to
v2.

| Step | C2 audit export | C3 release promotion | Merge/exit condition |
| --- | --- | --- | --- |
| 1. Domain contract | Accept only organization, export, environment, chain, and idempotency identity from the caller. Derive the frozen contiguous range, roots, count, payload digest, request digest, timestamps, and signer lifecycle from authoritative repositories. | Freeze platform approval v1 and promotion-evidence v3. Bind deployment, environment, candidate, source commit/tree, PKG/image/SBOM/manifest, qualification-report set, approval digest, lifecycle, and key version. | Closed fields, canonical bytes, domain separation, exact versions, strict arrays, unknown-field/accessor/prototype rejection, and substitution tests pass. |
| 2. Durable reservation | Add an organization-qualified export issuance ledger with unique request identity, immutable range/payload snapshot, database-clock lease, opaque fencing claim, and terminal committed/uncertain states. | Add platform approval and promotion ledgers keyed by deployment/environment/candidate/promotion. Persist immutable artifact and qualification bindings before signing. | Migration is forward-only; conflicting idempotency returns conflict; concurrent exact requests converge; caller cannot choose authoritative digest/range/approval state. |
| 3. Sign and commit | Sign only the repository-produced audit-anchor statement through the audit purpose signer. Verify the exact output against the pinned key before terminal commit. | Resolve a valid unexpired quorum approval, sign only v3 through the promotion purpose signer, verify exact bytes/key/lifecycle, then commit the evidence and deployment transition together or leave an explicit uncertain state. | No unsigned/local/cross-purpose/stale/disabled result commits. Accepted-but-response-lost and lost-commit paths replay one immutable result without blind re-signing. |
| 4. Historical verification | Resolve the exact historical public key by purpose/key ID/key version/fingerprint; committed evidence remains retrievable after expiry and reports `active` or `expired`. | Resolve both the historical promotion key and exact approval record. Verification proves approval/artifact/qualification bindings without exposing platform principal IDs or authorization evidence digests. | Rotation-safe replay passes; missing, private, diagnostic-leaking, wrong-purpose, wrong-version, or wrong-fingerprint resolver outputs fail closed. |
| 5. Narrow APIs | Device/Human BFF receives bounded export create/get/verify DTOs with tenant authorization and redacted errors. No claim token, provider receipt, raw signing bytes, or diagnostics cross the boundary. | Platform-operator service receives approve/promote/get/verify commands. Organization roles have no promotion authority. Public status exposes artifact identity, quorum count, timestamps, validity, and digest only. | OpenAPI/schema/catalog entries and role/tenant/privacy tests are green; browser-visible state contains no reusable authority. |
| 6. Fault qualification | Two instances exercise range contention, duplicate request, signer timeout, response loss, restart, rotation, disable, lifecycle fence, repository outage, and tampered historical rows. | Two instances exercise approval quorum races, artifact/report substitution, concurrent promotion, signer ambiguity, emergency disable, stale approval, expiry, and rebuild-on-promotion attempts. | Each operation ends in one verified committed result or one durable, bounded, operator-actionable state. No ambiguous success is returned. |
| 7. Documentation and evidence | Update threat model, operator export/replay runbook, retention behavior, privacy fields, and source-bound test artifact. | Update platform-operator trust model, approval ceremony, promotion rollback rule, evidence index, and source-bound qualification artifact. | Full contracts/lint/root/PostgreSQL suites pass on the pushed SHA; retained artifacts are independently verifiable. |

Planned commit sequence:

1. `C2/C3-contracts`: audit-export service boundary, platform approval v1,
   promotion-evidence v3, schema/fixture/catalog, and focused negative tests.
2. `C2-ledger`: migration and PostgreSQL repository for authoritative export
   snapshot/reserve/commit/replay/uncertain transitions.
3. `C3-ledgers`: migrations and repositories for platform approval and exact
   candidate promotion, including production quorum and immutable artifacts.
4. `C2-runtime`: compose audit export with managed signer, historical resolver,
   retrieval/verifier, readiness, and fault injection.
5. `C3-runtime`: compose approval resolution, v3 signer/verifier, deployment
   transition, historical verification, and fault injection.
6. `C2/C3-apis`: narrow BFF/platform APIs, schemas, authorization, privacy,
   audit events, and bounded operator read models.
7. `C2/C3-qualification`: real PostgreSQL two-instance matrix, full regression,
   threat-model/runbook updates, and source-bound retained evidence.

#### Persistence checkpoint after migrations 43-45

The contract checkpoint and the first persistence checkpoint are now
implemented. Migration 43 stores tenant-qualified audit-export reservations,
immutable evidence authority, database-clock claim leases, and terminal
committed/uncertain outcomes. Its repository owns reserve/reclaim/commit and
response-loss replay without persisting a clear claim token. Migration 44
stores immutable deployment-scoped platform approvals and derives a canonical
record digest that is byte-identical to the JavaScript contract. Migration 45
adds the organization-wide export ordering required to export device audit
events whose source chains remain per-device. All three migrations are in the
frozen catalog as versions 43-45.

The C2 snapshot-reader checkpoint is now implemented locally. Production code
derives the admin, cloud-agent, and organization-global device ranges inside
the reservation transaction, verifies source identity/sequence/linkage, folds
a domain-separated cumulative export root, binds the active audit-anchor
lifecycle, and exposes bounded public gap evidence for discontinuous per-device
chains. Two real PostgreSQL 17 pools prove all three sources, RLS isolation,
chunk-independent roots, gap disclosure, expired-claim authority reuse, replay,
and concurrent reservation exclusion. PostgreSQL and hosted Cloud runtimes now
compose the repository, audit signer, and a durable historical public-key
resolver. C2 is still not complete: immutable payload bytes/retrieval and the
Human BFF/API are intentionally not exposed yet. Admin v1 source hashes also
remain linkage-only because the legacy writer hashed `JSON.stringify` before
JSONB persistence; a versioned canonical writer/backfill is required before
claiming independent source-preimage recomputation. C3 has an approval authority
but does not yet have the promotion issuance ledger, managed-signer transaction,
or atomic deployment transition.

The next implementation commits, in dependency order, are:

1. `C2-snapshot-reader` — implemented locally: read admin and cloud-agent organization sequences and
   the migration-45 device export sequence in the reservation transaction;
   require a contiguous range and exact previous boundary; build one bounded,
   canonical payload; and return only repository-derived key/lifecycle data.
2. `C2-postgres-qualification` — implemented locally for the current ledger/reader: exercise reserve, expired-claim reclaim,
   concurrent range exclusion, exact replay, commit-response loss, RLS, and
   restart across two real PostgreSQL pools. The test must prove that a reader
   cannot re-snapshot frozen authority during reclaim.
3. `C2-runtime` — signer/repository/historical resolver composed locally; retrieval remains open: compose the ledger with the audit-purpose managed signer,
   exact output self-verification, historical key resolution, retrieval, and
   verification. Signer acceptance with an unknown commit outcome must become
   a durable uncertain state; no automatic second signature is allowed.
4. `C3-promotion-ledger`: persist candidate identity, artifact/manifest/SBOM
   digests, the exact qualification-report set, approval digest, signer
   lifecycle, opaque claim lease, provider operation, and deployment transition.
   Concurrent promotions for one deployment/environment are serialized.
5. `C3-runtime`: resolve an unexpired environment quorum, issue promotion
   evidence v3 through the promotion-only managed signer, self-verify it, and
   commit evidence plus deployment state atomically. Rebuild-on-promotion and
   v2 issuance are rejected.
6. `C2/C3-apis-console`: expose bounded Human-BFF audit export operations and a
   separate platform-operator promotion surface. Add role/recent-WebAuthn/CSRF/
   `If-Match`/idempotency enforcement, redacted DTOs, and Console loading,
   empty, conflict, uncertain, expired, and verification states.
7. `C2/C3-production-qualification`: run two-instance PostgreSQL and real KMS
   fault matrices, backup/PITR and rotation drills, browser/log/metric secret
   scans, independent security review, and source-bound retained evidence on
   the exact pushed SHA.

Before either producer is enabled for a runtime role, C6 must also revoke
direct `INSERT`/`UPDATE`/`DELETE`/`TRUNCATE` on the three authority ledgers,
revoke database `TEMP` and `CREATE ON SCHEMA public`, and expose only reviewed
purpose-specific stored procedures/views. Those procedures must prove the
previous committed boundary and derive authority rather than accepting it.
Migration 45 also requires a production preflight (row count, duplicate check,
estimated WAL/lock duration), a maintenance window or staged online backfill,
and an abort threshold before it is applied to a populated deployment.

Each commit exits only when focused unit tests, contract validation, lint, real
PostgreSQL tests, and the root regression suite pass. Steps 1-3 close C2; steps
4-5 close C3; step 6 depends on the matching producer; step 7 is the production
gate and cannot be replaced by mocks or a local successful demo.

After C1, C2 and C3 can proceed in parallel because their schemas and signer
purposes are disjoint. C6 PostgreSQL role/TLS/backup work and C9 packaging may
also run in parallel. C4 waits for both producer authorities; C5 waits for
their runtime bindings; protected real-KMS qualification C8 waits for C5 and
C6. External IAM, notarization, physical Mac, staging, and independent-review
evidence remain explicit release gates and cannot be satisfied by local tests.

### M1. Audit-anchor and promotion-evidence authorities (Q2B-3)

Current state: items 1 and 2 are implemented locally. Runtime lifecycle binding
and the PostgreSQL provider-operation portion of item 3 are implemented and
verified against a disposable real PostgreSQL instance. The combined
lifecycle/commit failure matrix, authoritative producer integration, and each
producer's durable issuance ledger are still required before this milestone
may be marked complete.

Deliverables:

1. Define canonical, domain-separated statements for audit anchors and
   promotion evidence, including organization/environment, sequence or
   candidate identity, payload digest, purpose, protocol/signing/lifecycle/key
   versions, issuance time, and expiry where applicable.
2. Add purpose-specific asynchronous signer and verifier modules. The HTTP and
   release layers receive only narrow `sign`/`verify` interfaces and never a
   provider client, private PEM, or generic cross-purpose signing primitive.
3. Bind both producers through the durable managed-signer repository, exact
   provider receipt reconciliation, lifecycle fencing, and emergency disable.
4. Catalog schemas and fixtures, wire the producers to authoritative audit and
   release-promotion flows, and reject unsigned, locally signed, stale, or
   cross-purpose production evidence.

Verification:

- canonical-vector and round-trip tests for both schemas;
- cross-purpose/key/version/environment/candidate substitution tests;
- timeout, accepted-but-response-lost, restart, idempotent replay, rotation,
  stale lifecycle, and emergency-disable tests;
- contract catalog validation and compatibility tests for existing evidence
  readers.

Exit gate: production audit export and promotion cannot complete without the
correct managed authority and a durably committed provider receipt. Evaluation
adapters remain explicitly profile-scoped and cannot be selected in hosted
mode.

### M2. Eight-purpose readiness and shutdown closure (Q2B-4)

Deliverables:

1. Probe all eight fixed purposes at startup and during operation using bounded
   provider metadata and pinned public-key fingerprints.
2. Expose only fixed-cardinality health states: configured, reachable,
   algorithm/version valid, lifecycle active, draining, disabled, or failed.
3. Require all mandatory purposes before traffic readiness; liveness remains
   separate so a failed signer does not create a restart storm.
4. Drain in-flight reservations and provider calls on shutdown, then close the
   database/provider resources in deterministic order.
5. Add a configuration/image scan proving that hosted artifacts contain no
   private key, private-key path, local signer selector, or shared-purpose key.

Exit gate: partial, duplicated, unhealthy, stale, or private-material-backed
provider sets cannot become ready, and logs/metrics expose no tenant, signing
bytes, key material, or raw provider diagnostics.

### M3. Real-provider and two-instance qualification (Q2C)

Run AWS KMS and Google Cloud KMS lanes against immutable versioned resources and
their production-shaped IAM principals. Execute the complete concurrency and
fault matrix from Q2C against two API instances and PostgreSQL 16. Persist a
machine-verifiable evidence bundle containing configuration fingerprints,
provider/key versions, scenario outcomes, committed operation IDs, redacted
receipts, timings, and tool/image/source digests.

Exit gate: all scenarios converge to exactly one verified result or one durable
operator-actionable uncertain/rejected state. Direct provider APIs that cannot
reconcile accepted-but-lost requests are not claimed as exactly-once; they must
use a provider operation service/ledger or remain blocked from production.

### M4. PostgreSQL production authority (Q2A)

Merge role-separated PostgreSQL CI first, followed by backup/PITR evidence and
cutover hardening. The CI lane creates the migrator, app, and backup roles from
scratch, applies all 45 current migrations, executes repository smoke tests as the app,
and proves the negative privilege matrix. The protected-environment lane then
records encrypted backup, point-in-time restore, row/checksum/authority
comparison, RPO, RTO, and rollback rehearsal.

Exit gate: runtime credentials cannot perform DDL, role changes, arbitrary
function execution, backup administration, or migration; restore evidence is
complete enough for an independent operator to repeat.

### M5. Console production slices (Q2D)

Implement the Console through one BFF and ship vertical slices in this order:

1. organization switcher, members, invitations, and role changes;
2. device enrollment, inventory, trust state, revoke, and re-enroll;
3. policy, Agent Session Grant, capability, expiry, and revocation inspection;
4. signer health, rotation, drain, and emergency stop;
5. bounded audit search/export and security-event timeline;
6. recovery, dead-letter, and uncertain-signing adjudication.

Every mutation is specified as UI state plus API preconditions: required role,
resource-bound recent WebAuthn context, CSRF, `If-Match`, idempotency key,
confirmation requirement, stable error mapping, audit event, and post-commit
refresh. Each slice includes loading/empty/error/stale/offline states, keyboard
and screen-reader behavior, tenant-substitution tests, response-loss recovery,
and proof that browser storage and URLs contain no reusable authority.

Exit gate: Owner/Admin/Auditor/Viewer matrices pass in Playwright against the
real BFF and PostgreSQL repositories; destructive actions are recoverable or
explicitly irreversible and never report success before authoritative commit.

### M6. Immutable macOS candidate and physical qualification (Q3)

Produce one universal Developer ID-signed, notarized, stapled PKG. Direct
download and Homebrew install that exact digest. Run the Q3B lifecycle matrix on
physical Apple silicon/Secure Enclave and Intel/T2 machines and bind every
result to source, SBOM, package, signing identity, notarization, and hardware
inventory.

Exit gate: both hardware lanes accept the same immutable candidate; install,
upgrade, rollback, uninstall-preserve, purge, reboot, sleep/wake, key loss, and
rotation have signed evidence and documented operator recovery.

### M7. Agent E2E, staging, review, and promotion (Q4-Q5)

Qualify Claude Code first and Cursor second through the same adapter contract,
including unattended signed commits, hostile sibling/process/path tests,
revocation, contention, restart, and response loss. Deploy the unchanged API,
Console, worker, schema, and PKG candidates to staging; execute operational
drills; commission an independent security review; close and retest findings;
then promote the exact qualified digests without rebuilding.

Exit gate: `git verify-commit` succeeds for supported unattended journeys, the
next operation is denied within the measured revocation bound, restore and
rollback meet recorded objectives, and no critical/high security finding is
open.

### Cross-cutting definition of done

Each merge checkpoint must include implementation, negative and failure tests,
contract/schema changes, threat-model delta, operator runbook, migration or
rollback notes, telemetry/privacy review, and evidence-index update. CI success
on mocks is implementation evidence only. Real KMS, protected PostgreSQL,
physical Mac, notarization, browser E2E, staging drills, and independent review
must be labeled separately and cannot be inferred from unit-test success.
