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
- AWS KMS and Google Cloud KMS adapters for the four currently composed hosted
  purposes, with no local fallback in hosted mode;
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

## 8. Near-term merge queue

The next merge-sized checkpoints are intentionally narrow:

1. Integrate migrations 0038–0039 and role separation into real PostgreSQL CI.
2. Wire the reconciliation contract and durable provider receipts into one
   currently composed signing purpose; pass the two-instance response-loss
   matrix.
3. Generalize that coordinator to ControlBundle and capability with real KMS
   readiness and negative configuration tests.
4. Add Human assertion and audit/promotion keys; complete the eight-purpose IAM
   and non-exportability evidence manifest.
5. Finish Console organization/device/session/policy/audit surfaces and their
   WebAuthn-bound authority mutations.
6. Build and qualify the immutable notarized PKG, then run Claude Code and
   Cursor physical E2E.
7. Deploy the exact candidate to staging, execute drills, commission the
   independent review, close findings, and promote unchanged artifacts.

Each checkpoint must update contracts, threat-model claims, runbooks, tests,
and the evidence index together. A checkpoint is not complete merely because
its implementation compiles or its mocked tests pass.
