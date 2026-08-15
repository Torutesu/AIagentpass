# AgentPass production implementation plan

Status: active

Planning baseline: `codex/agent-platform` after the C2 immutable audit-export
download, verification, Human BFF, and Console checkpoint

Planning date: 2026-08-15; execution ledger refreshed 2026-08-16

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

- frozen Core/OpenAPI/JSON Schema contracts and 45 forward-only migrations;
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
| M1d authoritative producers | C2 complete; C3 queued | M1c | Audit-export anchor issuance, platform promotion approval, and promotion-evidence v3 issuance in the real transaction flows. | Neither production flow can finish unsigned, locally signed, or without a committed receipt. |
| M1e operator/API surfaces | C2 complete; C3/C4 queued | M1d | Read-only retrieval, verification, bounded export, and adjudication APIs plus audit events. | Tenant/role/recent-auth/replay/stale-state negative matrix passes. |
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

### Execution plan after the C2 checkpoint

C2 now has one immutable server-produced payload, canonical download bytes,
offline and server verification, historical-key resolution, Human-session BFF
operations, role-scoped Japanese Console controls, operation-bound WebAuthn,
and authenticated operation audit events. The next critical path is C3 -> C4 ->
C5/C6 -> C8 -> C10/C11. C9 packaging runs in parallel once the client protocol
remains frozen.

| Wave | Reviewable commits | Implementation detail | Mandatory verification | Completion gate |
| --- | --- | --- | --- | --- |
| W0 — C2 closure | `C2-download-verify-console` | Land the frozen download/verify contracts, canonical attachment, offline verifier, BFF/UI, sidebar viewport fix, README, and checkpoint evidence. | Contract/lint/root suites; fresh PostgreSQL 17 retrieval test; all Console unit/build tests; full Chromium E2E; digest/root/signature corruption matrix. | Pushed SHA has source-bound green CI; no unexpected skip or browser regression. |
| W1 — C3 persistence | `C3-contracts`, `C3-promotion-ledger` | Freeze platform approval consumption and promotion-evidence v3. Add deployment/environment/candidate reservation, immutable artifact and qualification bindings, database-clock claim/fence, terminal uncertain/committed state, and atomic deployment generation transition. | Fresh migration; two-pool PostgreSQL races; exact replay; approval quorum/expiry; candidate/environment/digest/report substitution; RLS/privilege negatives. | A caller cannot select an authoritative digest or promote a rebuilt candidate; one exact reservation survives restart and response loss. |
| W2 — C3 authority runtime | `C3-runtime`, `C3-historical-verifier` | Resolve the exact unexpired approval quorum, sign only v3 with `agentpass.promotion-evidence`, verify against the pinned lifecycle key, commit evidence and transition atomically, and retain historical verification across rotation. | Provider timeout/acceptance ambiguity/lookup; lost `COMMIT`; rotation and emergency disable between reserve/sign/commit; wrong purpose/key/version/fingerprint; restart and concurrency. | Every promotion ends as one verified committed result or an explicit durable uncertain/rejected state; no blind re-signing or v2 issuance. |
| W3 — operator and reconciliation plane | `C3-platform-api`, `C4-reconciliation-api`, `C4-console` | Add platform-operator approval/promote/get/verify commands separate from organization roles. Add producer-specific uncertain list/detail/verify/adjudicate APIs with bounded DTOs, version preconditions, exact confirmations, and authoritative post-action reads. | Platform-vs-organization authority separation; Owner/Admin/Auditor/Viewer denial matrix; recent WebAuthn, CSRF, `If-Match`, idempotency, replay, tenant hiding, stale and concurrent adjudication; Playwright a11y/offline/response-loss tests. | No generic signer/provider authority reaches a browser or Human API; every action emits a secret-free immutable audit event. |
| W4 — runtime and database closure | `C5-eight-purpose-readiness`, `C5-drain`, `C6-db-authority`, `C6-restore-tools` | Require all eight distinct purpose/lifecycle/key bindings for readiness, expose fixed-cardinality health, drain signer work before providers/DB, revoke runtime DML/DDL/TEMP/schema creation, add purpose-specific procedures/views, TLS `verify-full`, deadlines, bounded pools, backup and restore comparison. | Missing/shared/stale/disabled/wrong-algorithm providers; shutdown races; app/migrator/backup privilege attacks; concurrent/interrupted migration; checksum drift; read-only DB; wrong TLS identity; isolated PITR authority comparison. | Partial signer configuration cannot receive traffic; runtime credentials cannot bypass ledgers; protected restore has measured RPO/RTO. |
| W5 — protected cloud qualification | `C8-aws-qualification`, `C8-gcp-qualification`, `C8-evidence-verifier` | Provision eight versioned non-exportable Ed25519 authorities under production-shaped IAM. Run two API instances/workers against protected PostgreSQL and retain canonical source/image/config-bound evidence. | 100-request contention per purpose; throttling/outage; ambiguous provider response and lookup; public-key/signature substitution; rotation/disable; database failover; backup/PITR; image, IAM, logs, metrics, and secret scans. | Independent verifier accepts all eight purpose reports with zero skips; every operation has one verified result or bounded operator state. |
| W6 — immutable client distribution | `C9-manifest-v4`, `C9-universal-pkg`, `C9-homebrew-direct`, `C9-physical-lanes` | Build broker/XPC/CLI/adapters once; sign nested code and installer, notarize, staple, generate SBOM/provenance, and make direct download, Homebrew, and CLI bootstrap verify the same PKG digest. | Codesign/designated requirements/entitlements; Gatekeeper offline; ownership and permissions; clean install, upgrade, failed upgrade, rollback, preserve uninstall, purge, reinstall, reboot, sleep/wake, Secure Enclave loss/rotation on Apple silicon and Intel/T2. | Both hardware reports, package receipt, release manifest, SBOM, notarization ticket, and channels bind one source and PKG digest. |
| W7 — agent product E2E | `C10-claude-code`, `C10-cursor` | Complete Claude Code first and Cursor second through the same process/repository-bound adapter. Bind executable identity, canonical worktree, repository/remote/branch, policy generation, budget, expiry, request and commit bytes. | Two unattended `git verify-commit` successes; hostile sibling/executable/path/repository substitution; symlink race; contention; expiry/budget; revoke-during-sign; daemon/editor restart; network/Cloud response loss; audit fsync failure; credential-leak scans. | Both agents pass on the exact notarized candidate and revocation blocks the next operation within the measured bound. |
| W8 — staging and production | `C11-staging`, `C11-drills`, `C11-review-fixes`, `C11-promotion` | Deploy immutable Console/API/worker/schema/PKG candidates, rehearse canary/drain/rollback/failover/PITR/signer outage/recovery, close independent review findings, then issue v3 promotion evidence over exact qualified digests. | Reproducible deployment; alert and runbook exercises; independent retest; no secret in source/image/log/evidence; exact-candidate and no-rebuild checks. | No unresolved critical/high or P0/P1 finding; go/no-go evidence is complete and production promotion is reversible and digest exact. |

Parallel lanes after W0 are intentionally narrow:

- Lane A runs W1 -> W2 -> W3 and owns promotion/reconciliation contracts.
- Lane B begins W4 database privilege/TLS/restore work immediately, but merges
  migration/catalog edits serially with Lane A.
- Lane C begins W6 packaging and local verification against the frozen client
  protocol; Developer ID/notarization and physical reports remain protected
  external gates.
- W5 waits for W2 and W4. W7 waits for the matching W3 APIs, W5 cloud evidence,
  and W6 candidate. W8 waits for every prior protected and physical gate.

For every commit, definition of done is: closed schema/DTO boundaries, fail-
closed negative tests, focused unit and integration tests, contract validation,
lint, full affected regression suites, `git diff --check`, secret scan, updated
operator documentation, clean worktree after push, and green source-bound CI.
Mocks and local runs are development evidence only; they never satisfy KMS,
notarization, physical hardware, restore, independent-review, or production
promotion gates.

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

#### Persistence checkpoint after migrations 43-46

The contract checkpoint and the first persistence checkpoint are now
implemented. Migration 43 stores tenant-qualified audit-export reservations,
immutable evidence authority, database-clock claim leases, and terminal
committed/uncertain outcomes. Its repository owns reserve/reclaim/commit and
response-loss replay without persisting a clear claim token. Migration 44
stores immutable deployment-scoped platform approvals and derives a canonical
record digest that is byte-identical to the JavaScript contract. Migration 45
adds the organization-wide export ordering required to export device audit
events whose source chains remain per-device. Migration 46 adds immutable
canonical payload bytes, structural JSON, digest binding, committed-only
retrieval, RLS, and reservation-time completeness. All four migrations are in
the frozen catalog as versions 43-46.

The C2 snapshot-reader checkpoint is now implemented locally. Production code
derives the admin, cloud-agent, and organization-global device ranges inside
the reservation transaction, verifies source identity/sequence/linkage, folds
a domain-separated cumulative export root, binds the active audit-anchor
lifecycle, and exposes bounded public gap evidence for discontinuous per-device
chains. Two real PostgreSQL 17 pools prove all three sources, RLS isolation,
chunk-independent roots, gap disclosure, expired-claim authority reuse, replay,
and concurrent reservation exclusion. PostgreSQL and hosted Cloud runtimes now
compose the repository, audit signer, and a durable historical public-key
resolver. Immutable canonical payload bytes are captured in the reservation
transaction and, after commit, are retrieved without re-snapshotting, checked
against their stored SHA-256, rebound to the exact identity/range, root-folded,
and returned with the historical-key-verified anchor. New admin events use the
canonical v2 writer and are independently recomputed; legacy v1 remains
explicitly linkage-only. C2's remaining product surface is the Human BFF/API
and Console workflow. C3 now has a locally committed foundation in `4343b0f`:
promotion-evidence v3 signing and historical verification, migration 0047,
the deployment/promotion ledger repository, and a fail-closed issuance state
machine. It is not yet runtime-enabled. Commit-bound cryptographic
verification, historical lifecycle resolution, catalog/runtime composition,
the platform-operator API, and fresh-PostgreSQL qualification remain open.

The next implementation commits, in dependency order, are:

1. `C2-snapshot-reader` — implemented locally: read admin and cloud-agent organization sequences and
   the migration-45 device export sequence in the reservation transaction;
   require a contiguous range and exact previous boundary; build one bounded,
   canonical payload; and return only repository-derived key/lifecycle data.
2. `C2-postgres-qualification` — implemented locally for the current ledger/reader: exercise reserve, expired-claim reclaim,
   concurrent range exclusion, exact replay, commit-response loss, RLS, and
   restart across two real PostgreSQL pools. The test must prove that a reader
   cannot re-snapshot frozen authority during reclaim.
3. `C2-runtime` — implemented locally: the signer/repository/historical resolver
   composition retrieves the immutable payload only after commit, verifies its
   canonical digest, identity, range, cumulative root and historical anchor,
   and returns a deeply frozen public result. Signer acceptance with an unknown
   commit outcome becomes a durable uncertain state; replay never re-signs or
   re-snapshots.
4. `C3-promotion-ledger` — foundation committed locally in `4343b0f`: persist candidate identity, artifact/manifest/SBOM
   digests, the exact qualification-report set, approval digest, signer
   lifecycle, opaque claim lease, provider operation, and deployment transition.
   Concurrent promotions for one deployment/environment are serialized. The
   migration still requires catalog/authority-manifest registration and a
   fresh PostgreSQL privilege/race run before this item closes.
5. `C3-runtime` — signer/service primitives committed locally in `4343b0f`:
   resolve an unexpired environment quorum, issue promotion
   evidence v3 through the promotion-only managed signer, self-verify it, and
   commit evidence plus deployment state atomically. Rebuild-on-promotion and
   v2 issuance are rejected. The Cloud runtime and commit-bound independent
   verifier composition remain open.
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
PostgreSQL tests, and the root regression suite pass. Steps 1-3 close the C2
producer/runtime boundary; the Human API and Console portion closes in step 6.
Steps 4-5 close C3; step 6 depends on the matching producer; step 7 is the
production gate and cannot be replaced by mocks or a local successful demo.

After C1, C2 and C3 can proceed in parallel because their schemas and signer
purposes are disjoint. C6 PostgreSQL role/TLS/backup work and C9 packaging may
also run in parallel. C4 waits for both producer authorities; C5 waits for
their runtime bindings; protected real-KMS qualification C8 waits for C5 and
C6. External IAM, notarization, physical Mac, staging, and independent-review
evidence remain explicit release gates and cannot be satisfied by local tests.

#### Executable backlog after `b75c4f5`

The following backlog is the authoritative order after the snapshot-reader
checkpoint. A work package is complete only when its code, negative tests,
failure tests, contract/catalog changes, operator documentation, and relevant
real-system qualification land together. External credentials or hardware may
block qualification, but they must not block implementation of the verifier,
evidence schema, or fail-closed gate.

| Package | Deliverable | Dependencies | Required verification | Exit condition |
| --- | --- | --- | --- | --- |
| P0 — C2 immutable export payload | Migration 0046 stores canonical payload bytes, parsed JSON, digest, and issuance identity in the same transaction as the immutable reservation. Repository retrieval recomputes SHA-256, requires byte-for-byte canonical JSON, rejects private/accessor/prototype data, and returns payload only for a committed issuance. | `b75c4f5`; serialized migration/catalog lock | Fresh PostgreSQL 17 migration; two-pool reserve/reclaim/replay; missing, oversized, altered-byte, altered-JSON, wrong-digest, uncommitted, cross-tenant, and concurrent insertion tests | A committed export is independently retrievable after restart without re-reading mutable source rows. |
| P1 — C2 canonical source verification | Admin audit writer v2 hashes canonical JSON; the snapshot reader recomputes v2 hashes. Legacy v1 remains explicitly linkage-only and is never represented as independently recomputed. | P0 can run in parallel; admin writer and reader format are serialized | Nested-key-order vectors, mixed v1/v2 chain, tampered v2 preimage, boundary linkage, old-row compatibility, and root-stability tests | Every newly written admin event has a recoverable canonical preimage; the API states the verification level honestly. |
| P2 — C2 Human BFF and Console | Add create, get, download, and verify operations backed by immutable retrieval. Owner/Admin may create; Owner/Admin/Auditor may read and verify; Viewer is denied. Creation requires recent resource-bound WebAuthn, CSRF, idempotency, and optimistic state where applicable. Downloads use attachment headers, no-store caching, bounded bytes, and no browser persistence. | P0 and frozen DTO/schema; P1 before claiming full source verification | Role matrix, organization hiding, CSRF, stale/absent WebAuthn, response loss, duplicate request, digest mismatch, range gap, expiry, loading/empty/error/offline/a11y, URL/storage/log/trace secret scans | A non-engineer can create and verify an export in the Console, while replay returns the exact original bytes and never signs twice. |
| P3 — C3 promotion authority | Add deployment-scoped promotion reservation and exact candidate ledger. Resolve immutable platform approval quorum; bind source tree, image, PKG, SBOM, manifest, qualification set, migration set, signer lifecycle, and environment; sign v3 only; atomically commit evidence and deployment transition. | C1 provider ledger; contract/catalog and migration locks must serialize with P0/P2 | Candidate/environment/evidence substitution, expired approval, quorum race, concurrent promotion, signer timeout/ambiguity, emergency disable, rotation, restart, response loss, and rebuild-on-promotion tests | One exact candidate is either durably promoted with verifiable v3 evidence or remains in a bounded operator-actionable state. |
| P4 — reconciliation, readiness, and DB authority | Add producer-specific uncertain-operation list/detail/verify/adjudication BFF surfaces; probe all eight purpose/lifecycle pairs; drain deterministically; revoke runtime direct DML/TRUNCATE and public-schema/TEMP privileges; expose reviewed purpose procedures/views; add TLS/deadline/pool checks. | P2/P3 producer identity; database hardening can start earlier on disjoint SQL | Human role/WebAuthn/CSRF/If-Match matrix; eight-purpose missing/shared/stale/disabled/wrong-key tests; negative database privilege matrix; interrupted migration and shutdown race tests | No generic signing authority crosses the BFF, partial signer configuration cannot become ready, and runtime credentials cannot bypass authority repositories. |
| P5 — protected cloud qualification | Provision all eight non-exportable managed keys with production-shaped IAM; run two API instances and workers against protected PostgreSQL; perform encrypted backup/PITR restore, rotation/drain/disable, provider outage/throttling, and response-loss drills. | P3/P4; external AWS/GCP/PostgreSQL authority | Source/image/config-bound evidence, key metadata/non-exportability proof, exact committed operation IDs, authority-state restore comparison, measured RPO/RTO, secret scan | Every scenario converges to one verified result or one durable bounded state; no private/local fallback, cross-purpose IAM, or unverifiable success exists. |
| P6 — immutable macOS release candidate | Build one universal PKG containing broker, XPC services, launchd jobs, CLI, Git integration, and adapters; sign nested code and installer with Developer ID; notarize and staple; generate SBOM/provenance/manifest. Direct download, Homebrew, and CLI bootstrap must fetch and verify the same PKG digest. | Frozen client protocol; can run beside P2-P5 until final candidate binding | `codesign`, designated requirement, entitlements, `spctl`, `pkgutil`, stapler, ownership/permissions, install/upgrade/rollback/uninstall-preserve/purge/reinstall/reboot/sleep-wake | One immutable candidate is accepted on physical Apple silicon/Secure Enclave and Intel/T2; a browser or Homebrew process never replaces the privileged native boundary. |
| P7 — agent E2E and production promotion | Qualify Claude Code first, Cursor second. Deploy unchanged Cloud/Console/worker/schema/PKG candidates to staging, execute revoke/failover/restore/rollback/recovery drills, close independent-review findings, and issue one v3 promotion record over exact digests. | P2-P6 and two physical Mac lanes | Two unattended verified commits per adapter; hostile sibling/path/ancestry tests; measured revocation; canary and rollback; independent review with retest; no skipped production gate | Exact qualified artifacts are promoted without rebuilding; no open critical/high or P0/P1 finding remains; tenant enablement is explicit and reversible. |

##### Planned merge sequence

Current checkpoint on 2026-08-15:

- Items 1 and 2 are implemented and pushed in `11063f6`.
- Item 3 now has frozen create/get/download/verify contracts, exact four-field
  committed retrieval, canonical public-DTO attachments, historical-key,
  payload-digest, cumulative-root, anchor-binding, and signature verification,
  runtime composition, Owner/Admin/Auditor role enforcement, resource-bound
  recent WebAuthn, same-origin/CSRF/idempotency controls, opaque tenant-safe
  failures, a strict 256 KiB Console BFF, and authenticated success/denial/
  failure operation audit events. It remains open until fresh-PostgreSQL
  production-process qualification lands.
- Item 4 now has the end-user Japanese Audit Exports screen, role-scoped
  create/read/verify/download controls, explicit empty/loading/expired/corrupt/
  offline/response-loss states, accessible evidence details, and revocable
  Blob downloads without browser persistence or telemetry. Source-level UI,
  client, BFF, build, lint, and regression tests pass; real-browser WebAuthn
  role and reduced-motion qualification remains open.

1. `C2-payload-ledger`: migration 0046, immutable payload repository, service
   retrieval, catalog/manifest updates, and real PostgreSQL qualification.
2. `C2-canonical-admin-v2`: canonical writer and mixed-version reader with an
   explicit legacy verification label.
3. `C2-human-api`: create/get/download/verify schemas, OpenAPI operations,
   Human BFF authorization, privacy headers, and audit events.
4. `C2-console`: export workflow, verification result, download, recovery from
   response loss, and Playwright/browser-secret qualification.
5. `C3-promotion-ledger`: platform approval consumption, promotion reservation,
   atomic deployment transition, historical verifier, and PostgreSQL races.
6. `C3-operator-api`: platform-only approval/promotion/reconciliation surface;
   Organization membership never grants promotion authority.
7. `C5-C6-runtime-db`: all-eight readiness/drain plus least-privilege,
   TLS/deadline, cutover, backup/PITR, and authority-comparison tooling.
8. `C8-protected-qualification`: real KMS, two-instance PostgreSQL, retained
   evidence, and independent verification.
9. `C9-release-candidate`: exact universal signed/notarized PKG, direct and
   Homebrew delivery, two physical hardware reports.
10. `C10-C11-release`: Claude Code/Cursor E2E, staging drills, security review,
    exact-digest promotion, canary, and production rollback gate.

##### Next execution waves and acceptance gates

1. **C2 API closure.** Add explicit download and offline-verify operations over
   the same immutable committed payload. Download is an attachment with a
   deterministic filename, exact canonical bytes, `nosniff`, no-store, no
   redirect, and no browser cache persistence. Verify recomputes the payload
   digest, cumulative range root, anchor statement binding, signature, and
   historical signer lifecycle without issuing a new signature. Add creation,
   retrieval, download, verification, denial, and failure audit events. Exit:
   real PostgreSQL 17 plus the production Cloud process passes owner/admin/
   auditor/viewer, duplicate, response-loss, restart, corruption, expiry,
   cross-tenant, CSRF, stale/replayed/cross-operation WebAuthn, and 256 KiB
   boundary cases.
2. **C2 Console workflow.** Build an Audit Exports page with chain/environment
   selection, create confirmation, passkey reauthentication, progress,
   committed range and validity, local verification result, and safe download.
   Do not store payloads in localStorage, sessionStorage, IndexedDB, URLs,
   analytics, logs, or error traces. Exit: production-built BFF Playwright tests
   cover loading, empty, success, expired, corrupt, response-loss, offline,
   retry, keyboard-only, screen-reader, reduced-motion, and all four roles.
3. **C3 promotion authority.** Add forward-only PostgreSQL ledgers for exact
   candidate reservation, approval consumption, provider operation, uncertain
   outcome, committed promotion, and deployment generation. Promotion evidence
   v3 binds source tree, images, schema/migrations, PKG, SBOM/provenance,
   qualification reports, environment, approval quorum, and signer lifecycle.
   Exit: concurrency, quorum race, substitution, signer timeout/response-loss,
   restart, rotation/disable, and rebuild-on-promotion tests converge to one
   committed result or one bounded operator-actionable state.
4. **Reconciliation and production authority.** Expose producer-specific
   list/detail/verify/adjudicate operations with platform-only authority,
   recent WebAuthn, CSRF, idempotency, and `If-Match`. Remove runtime direct
   table mutation privileges, probe all eight purpose/lifecycle pairs, and
   prove deterministic drain. Exit: negative privilege tests, wrong/shared/
   stale key tests, interrupted migration, shutdown races, and secret-free
   metrics/logs all pass.
5. **Protected qualification and release.** Run two Cloud instances and workers
   against protected PostgreSQL and non-exportable KMS/HSM keys; prove encrypted
   backup/PITR, outage, throttling, rotation, disable, canary, and rollback.
   Build one universal Developer-ID-signed, notarized, stapled PKG and distribute
   that exact digest through direct download, Homebrew, and CLI bootstrap. Exit:
   Apple silicon/Secure Enclave and Intel/T2 lanes plus Claude Code then Cursor
   each complete two unattended verified commits and immediate revocation from
   one immutable candidate; independent review has no unresolved critical/high
   or P0/P1 finding.

The critical path is P0 -> P2 -> P4 -> P5 -> P7. P1 runs beside P0. P3 starts
as soon as its migration/catalog lock is free and joins the critical path at
P4. P6 can proceed beside hosted work once the client protocol is frozen, but
its final manifest cannot close before Cloud/Console image and migration
digests are fixed. Console UI work never invents state ahead of its BFF; real
KMS, notarization, protected restore, physical Mac, and independent-review
claims remain blocked until their corresponding evidence exists.

##### Checkpoint policy

Every merge sequence item receives a separate reviewable commit and is pushed
only from a clean tree after focused tests. Contract or migration changes also
require catalog validation and a fresh-database run. Runtime changes require
the root suite, Console tests/lint when browser-visible, and a secret scan.
Before tagging a candidate, CI must bind source SHA, catalog digest, migration
digest, image digests, package digest, SBOM/provenance, signer lifecycle/key
versions, test command set, scenario outcomes, and skip count. A skipped,
mocked, simulated, ad-hoc-signed, or locally asserted result is never promoted
to protected, physical, or production evidence.

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
scratch, applies all 46 current migrations, executes repository smoke tests as the app,
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

## 10. Forward execution ledger — 2026-08-16

This ledger is the short operational view of the remaining implementation. It
does not replace the security gates above. Source-complete means code and local
tests exist; qualified means the exact pushed source passed the named external
or physical evidence lane.

### N1 — source-bound regression closure

Current boundary: `6de3b1b` adds fail-closed hosted signer drain checkpoints;
`faf48e2` adds secret-free P0-B scenario diagnostics; `919974a` protects the
final active organization owner in Console. All changes are pushed to
`github/codex/agent-platform`. GitHub Actions run `31897993653` is the source
qualification run for this boundary.

Implementation steps:

1. Require terminal success from root tests, browser E2E, PostgreSQL integration,
   PostgreSQL 16 authority, PostgreSQL 17 authority, and P0-B live process.
2. If P0-B fails, retain only the stable scenario code; diagnose through the
   scenario's bounded harness without printing child output or credentials.
3. Fix any failure in a focused commit, rerun its local suite, push, and require
   a new all-green source-bound run.

Exit gate: the exact head has six terminal green jobs, no unexpected skip, a
clean worktree, and a matching remote branch SHA.

### N2 — Human authority and Console completion

Implementation order:

1. Finish last-owner and last-usable-passkey protection in both authoritative
   PostgreSQL races and browser UX. A partial page must never be treated as a
   complete member or credential set.
2. Complete invitation accept/revoke/reissue journeys with one-use tokens,
   idempotency, expiry, cross-tenant hiding, concurrent acceptance, and an
   authoritative post-mutation read. No token may enter a URL, durable browser
   storage, telemetry, or rendered error.
3. Complete passkey registration, rename, revoke, clone/sign-count response,
   recovery re-enrollment, session list, self/admin revoke, and session/epoch
   invalidation. Every high-risk action uses operation-bound recent WebAuthn.
4. Exercise Owner/Admin/Auditor/Viewer matrices for organization, membership,
   invitation, credential, session, recovery, Platform assignment, and policy
   changes, including stale `If-Match`, replay, lost response, and concurrent
   mutation.
5. Emit immutable, tenant-bound, secret-free audit events in the same
   transaction as every authority reduction.

Exit gate: two-connection PostgreSQL races and deployed-like Playwright tests
prove no last-owner/last-credential lockout, no caller-selected authority, no
cross-tenant disclosure, and immediate stale-session denial.

### N3 — browser-first onboarding and thin helper

Implementation order:

1. Freeze one resumable state machine: GitHub identity, first organization,
   WebAuthn, device enrollment, loopback helper handoff, Agent Session
   policy/scope/TTL, editor setup, and signed-commit verification.
2. Derive resume state from Cloud and the local setup journal; browser refresh,
   closure, listener expiry, Cloud timeout, CLI interruption, native restart,
   and a lost definitive enrollment response must not reuse an invitation or
   repeat a definitive POST.
3. Keep the loopback nonce and credential-bearing invitation memory-only. Add
   browser URL/DOM/storage/network-log and process argv/environment/log/crash
   leakage scans.
4. Qualify exact Origin/Host/nonce/candidate/fingerprint/ACK bindings and
   Private Network Access behavior in supported production browsers.
5. Complete Japanese loading, retryable, terminal, unsupported-hardware,
   expired-handoff, stale-control, and editor-drift guidance. The native app
   remains an optional status surface; the signed helper and CLI own local
   authority.

Exit gate: a non-engineer starts one command, completes the browser journey,
and reaches two verified unattended commits without manually copying an ID,
fingerprint, endpoint, or invitation in the normal path.

### N4 — immutable macOS distribution

Implementation order:

1. Freeze the helper/XPC/CLI/editor protocol and package inventory, then build
   one universal artifact for Apple silicon and Intel.
2. Verify nested identifiers, designated requirements, entitlements,
   provisioning profiles, launchd definitions, ownership, permissions, receipt,
   SBOM, and protected-state exclusions before signing.
3. Sign nested code with Developer ID Application, sign the PKG with Developer
   ID Installer, notarize, staple, and verify Gatekeeper offline.
4. Publish direct download and Homebrew metadata that install the exact same PKG
   digest; neither channel may rebuild or repackage.
5. Run clean install, upgrade, failed upgrade, rollback, uninstall-preserve,
   reinstall, purge, reboot, sleep/wake, Secure Enclave loss, and key rotation
   on Apple silicon/Secure Enclave and Intel/T2 lanes.

External inputs: protected Apple Developer identities, notarization API
credentials, and clean physical runners. Source work may complete without these
inputs, but release qualification cannot.

Exit gate: source, manifest, SBOM, Team ID, notarization ticket, package receipt,
download, Homebrew metadata, and both signed hardware reports bind one digest.

### N5 — PostgreSQL and eight-purpose managed signer productionization

Implementation order:

1. Complete all-eight-purpose readiness and fixed-cardinality redacted metrics;
   partial, shared, stale, disabled, wrong-algorithm, or fallback-backed signer
   configurations remain unready.
2. Close drain ordering across HTTP admission, reservation, database boundaries,
   provider invocation, reconciliation, maintenance workers, providers, and
   PostgreSQL. A race that crosses the provider boundary becomes durable
   uncertainty, never blind replay.
3. Qualify migrator/app/backup roles, TLS `verify-full`, statement/lock/idle
   deadlines, bounded pools, migration locks, encrypted backup, isolated PITR
   restore, authority comparison, rollback, RPO, and RTO.
4. Provision eight purpose-separated, version-pinned, non-exportable AWS/GCP
   managed keys with exact IAM and no local/file fallback.
5. Run two API instances through contention, throttling, outage, lost response,
   malformed receipt, signature/public-key substitution, rotation, emergency
   disable, database failover, and lost `COMMIT` response.

External inputs: protected AWS/GCP projects/accounts, IAM principals, managed
keys, and protected PostgreSQL. The repository harness must reject missing
inputs rather than silently simulate production evidence.

Exit gate: each operation converges to one verified committed result or one
bounded operator-actionable terminal state, and all eight purposes pass an
independently verifiable zero-skip evidence bundle.

### N6 — agent E2E, staging, review, and promotion

Implementation order:

1. Qualify Claude Code, then Cursor, against the same process/repository-bound
   adapter: two unattended signed commits, hostile sibling/executable/path/
   repository substitution, contention, expiry, budget, revocation, restart,
   network loss, Cloud response loss, and audit durability failure.
2. Deploy immutable Console/API/worker images, schema, PostgreSQL, TLS/DNS,
   managed signers, rate limits, telemetry, alerts, and the exact N4 package to
   staging.
3. Rehearse canary, drain, rollback, migration, failover, PITR, signer rotation
   and outage, emergency stop, owner recovery, uncertain-result adjudication,
   and incident response.
4. Commission independent review of local privilege/XPC, loopback handoff,
   WebAuthn/session/tenant isolation, replay/idempotency, KMS/IAM, package/update
   supply chain, audit/recovery, privacy, and denial of service. Close every
   critical/high and retest security-relevant medium finding.
5. Promote the exact staging image and PKG digests with signed promotion
   evidence; never rebuild between qualification and production.

Exit gate: production rollback and restore are measured, revocation bounds are
recorded, no critical/high finding remains, and every deployed artifact resolves
to the qualified source and digest.

### Parallel lanes and merge discipline

- Lane A: N2 Human authority, then the corresponding Console vertical slices.
- Lane B: N3 onboarding state machine and thin-helper browser qualification.
- Lane C: N5 source hardening; protected real-provider/restore evidence follows
  only after source-bound CI is green.
- Lane D: N4 packaging may advance against the frozen protocol, while signing,
  notarization, and physical qualification remain protected gates.
- N6 agent E2E waits for the matching N2/N3/N5 authority and the exact N4
  candidate. Production promotion waits for every prior gate.

Every merge unit must be independently reviewable, have focused negative tests,
pass affected regression suites, contract validation, lint, whitespace and
secret scans, update the relevant runbook, be committed and pushed, and receive
source-bound CI. External evidence is attached to the exact commit/artifact; a
mock, skipped test, simulator, or unsigned build never substitutes for it.
