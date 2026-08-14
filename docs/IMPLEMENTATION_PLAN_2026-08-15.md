# AgentPass production implementation plan

Status: active

Planning baseline: `codex/agent-platform` after the managed-signer fencing checkpoint

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

Implemented locally and covered by source-bound CI:

- frozen Core/OpenAPI/JSON Schema contracts and 39 forward-only migrations;
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

1. Catalog migrations 0038–0039, integrate the three-role SQL contract into cutover,
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
repository. The authoritative audit-export and release-promotion producers,
durable issuance ledgers, provider-operation reconciliation integration,
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
| M1c provider-operation convergence | in progress | M1b | A durable operation adapter and PostgreSQL operation ledger for deterministic Ed25519 retry/reconciliation. | Accepted-but-response-lost, restart, contention, receipt conflict, rotation, and disable tests converge without ambiguous success. |
| M1d authoritative producers | queued | M1c | Audit-export anchor issuance and release-promotion evidence issuance in the real transaction flows. | Neither production flow can finish unsigned, locally signed, or without a committed receipt. |
| M1e operator/API surfaces | queued | M1d | Read-only retrieval, verification, bounded export, and adjudication APIs plus audit events. | Tenant/role/recent-auth/replay/stale-state negative matrix passes. |
| M2 eight-purpose runtime closure | queued | M1d | Fixed-cardinality readiness, metrics, drain, and secret/image scan for all eight purposes. | Any unhealthy purpose blocks readiness; shutdown leaves no unfenced operation. |
| M3 two-instance real KMS | blocked on protected infrastructure | M2 | AWS and GCP two-instance fault-matrix evidence bundle. | Every operation reaches one verified result or an explicit durable terminal/operator state. |
| M4 PostgreSQL production authority | can run parallel with M1–M2 | migrations 0038–0039 | Role-separated CI, TLS/deadline hardening, backup, PITR, restore, and rollback evidence. | App cannot administer/migrate; measured protected-environment RPO/RTO. |
| M5 Console production slices | can begin after each backing API | M1e, M2, M4 per slice | Organization, device, policy, signer, audit, and recovery vertical slices. | Real-BFF Playwright role/reauth/stale/replay/a11y matrix passes. |
| M6 immutable macOS candidate | can run parallel after contract freeze | release manifest v4 | Universal signed/notarized/stapled PKG and digest-identical Homebrew/direct delivery. | Gatekeeper and lifecycle matrix pass on Apple silicon and Intel/T2. |
| M7 agent E2E and promotion | queued | M3–M6 | Claude Code/Cursor physical E2E, staging drills, independent review, exact-digest promotion. | No open critical/high issue; qualified digests are promoted without rebuild. |

Immediate merge order is M1a/M1b, M1c, M1d, M1e, then M2. M4 and M6 may
proceed in parallel because they do not change the frozen signer statement
contracts. M5 may consume only merged authoritative APIs; it must not invent
browser-side authority or duplicate signing logic.

### M1. Audit-anchor and promotion-evidence authorities (Q2B-3)

Current state: items 1 and 2 are implemented locally, and runtime lifecycle
binding from item 3 is implemented. Exact provider-operation reconciliation,
the durable issuance ledger, authoritative producer integration, and the
failure matrix are still required before this milestone may be marked complete.

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
scratch, applies all 39 migrations, executes repository smoke tests as the app,
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
