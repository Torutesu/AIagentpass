# AgentPass post-C3 implementation plan

Status: active  
Baseline: `c1e1171` on `codex/agent-platform`  
Planning date: 2026-08-15

## 1. Release target

The first production release is headless-first. Claude Code and Cursor use the
AgentPass CLI, Git helper, broker, and native services; humans use the web
Console for enrollment, policy, revocation, audit, recovery, signer health, and
platform promotion. The macOS delivery unit is one Developer ID-signed,
notarized, and stapled PKG. Direct download, Homebrew, and CLI bootstrap must
all install and verify that same PKG digest. A native GUI is optional and may
not own authority, protocol, or signing logic.

Production completion requires all of the following:

- device keys remain non-exportable in Secure Enclave or the supported hardware
  boundary;
- hosted authority keys are versioned, non-exportable, purpose-separated managed
  keys with no file-key fallback;
- organization, role, Human session, WebAuthn, Device, Agent Session, and
  platform-operator authority are persisted and independently enforced;
- every mutation is scoped, idempotent, recently authorized when required,
  concurrency-safe, and audited;
- two real Cloud instances, protected PostgreSQL, and real managed signers pass
  the fault matrix;
- the exact qualified API, Console, database migration set, and PKG artifacts
  are deployed without rebuild;
- an independent security review has no unresolved critical/high or P0/P1
  finding.

## 2. Current checkpoint

The branch now contains:

- promotion-evidence v3 contracts, historical verification, exact candidate and
  approval binding, durable issuance state, and independent pre-commit
  verification;
- a narrow platform promotion HTTP boundary that is absent unless a dedicated
  platform-operator authorizer is supplied;
- an in-process strict authorizer contract that denies organization roles and
  requires an active, operation-bound platform-operator assignment;
- migration `0048`, whose five `SECURITY DEFINER` entry points derive promotion
  authority in PostgreSQL and whose role contract revokes direct application
  mutation of promotion and signer authority tables;
- repository code that uses the five reviewed database functions instead of
  direct promotion-table DML;
- 148 frozen contract-catalog entries: 39 schemas, 61 OpenAPI operations, and
  48 migrations.

This is not a production-complete boundary yet. Migration `0048` has static and
mocked repository coverage but has not been parsed or executed by a real
PostgreSQL server in the current environment. The platform-operator assignment
repository and Human/WebAuthn-backed platform session do not yet exist. The
Cloud runtime therefore leaves the route disabled by default. The current
managed-signer repositories also need a separately authenticated database
authority instead of sharing the generic application pool.

## 3. Non-negotiable invariants

1. Organization Owner/Admin/Auditor/Viewer membership never grants platform
   promotion authority.
2. Browser and agent processes never receive a generic signing primitive,
   managed-provider client, claim token, private key, or reusable WebAuthn
   assertion.
3. The caller supplies public operation identity only. Candidate, artifact,
   approval, lifecycle, key, canonical bytes, provider operation, and database
   time are authoritative derivations.
4. An ambiguous provider or commit result becomes durable `uncertain`; replay
   reconciles the exact operation and never blindly signs again.
5. Runtime, signer, migrator, backup, and operator database identities are
   separate. No runtime credential can create schema objects or mutate an
   authority ledger directly.
6. A mock, skipped test, local file signer, ad-hoc signature, simulated hardware,
   or unprotected database is development evidence only.
7. Every release claim binds the exact source SHA, catalog and migration
   digests, image digests, SBOM, qualification reports, approval, signer
   lifecycle, and PKG digest.

## 4. Dependency graph

```text
P0 real PostgreSQL proof + DB identity split
  -> P1 platform operator identity/session/WebAuthn persistence
    -> P2 runtime/API/audit closure
      -> P3 Console promotion and reconciliation workflow

P0 -> P4 eight-purpose signer readiness -> P5 protected cloud fault matrix

Frozen client protocol -> P6 immutable macOS distribution

P3 + P5 + P6 -> P7 Claude Code/Cursor physical E2E
P5 + P7 -> P8 staging, independent review, exact production promotion
```

P6 may run in parallel with P1-P4. Contract and migration edits merge serially.
Console work may start only after its backing BFF DTO and authorization contract
is frozen. Protected qualification cannot be replaced by local development
evidence.

## 5. Work packages

### P0 — prove and close the PostgreSQL authority boundary

Implementation:

1. Run migrations 1-48 on fresh PostgreSQL 16 and 17 databases and upgrade a
   seeded version-47 database to 48.
2. Execute reserve, replay, commit, uncertain, and get through
   `agentpass_app`; prove direct DML, helper execution, DDL, ownership change,
   `SET ROLE`, schema creation, trigger creation, truncate, and TEMP denial.
3. Verify exact function signatures and owners after `roles.sql`; reject any
   overload or PUBLIC/backup execution privilege.
4. Split runtime pools into `app`, `signer`, and `migration` authorities. The
   signer pool receives only reviewed signer-ledger procedures; it does not
   inherit application-table authority.
5. Add transaction, statement, lock, and idle-in-transaction deadlines; bounded
   pools; TLS `verify-full`; migration advisory locking; and fail-closed
   readiness.
6. Exercise two-pool promotion contention, claim expiry/reclaim, approval expiry,
   rotation/disable between reserve and commit, lost commit response, restart,
   and immutable terminal rows.

Primary files:

- `contracts/postgres/0048_platform_promotion_authority_boundary.sql`
- the next forward-only signer-authority migration
- `scripts/postgres/roles.sql`
- `scripts/postgres/role-privilege-check.mjs`
- `apps/cloud-api/src/postgres/runtime.mjs`
- PostgreSQL integration and qualification tests

Exit gate: fresh and upgrade databases pass with zero unexpected skips; the app,
signer, migrator, and backup negative privilege matrices are retained as
source-bound evidence. Runtime credentials cannot bypass either the promotion
or managed-signer ledgers.

### P1 — persist platform-operator identity, role, session, and WebAuthn

Implementation:

1. Add immutable platform principals and versioned assignments with exact
   capabilities such as `promotion.issue`, `promotion.verify`, and
   `promotion.reconcile`. Assignment suspension, expiry, replacement, and
   revocation increment an authority generation.
2. Add platform sessions separate from organization Human sessions. Persist
   only hashed session/JTI material, bind member, platform principal, authority
   generation, credential, authentication time, expiry, and revocation.
3. Register and authenticate WebAuthn credentials through the existing strict
   ceremony adapters, but bind platform mutations to operation, deployment,
   environment, candidate, approval, idempotency key, and request digest.
4. Consume recent authorization once in the same database transaction that
   starts the mutation. Stale generation, replay, credential removal, session
   revocation, or assignment expiry fails closed.
5. Implement `findActivePlatformOperatorAssignment` in a PostgreSQL repository
   and compose it into `platform-operator-authorizer.mjs`; remove all production
   reliance on caller-constructed assignment objects.
6. Add immutable platform authentication, assignment, denial, and revocation
   audit events without principal lists, assertions, credential IDs, or claim
   material in public DTOs.

Exit gate: every organization role alone is denied. Exact platform authority
succeeds only with an active assignment, current session generation, and
one-use operation-bound WebAuthn proof. Cross-operation, stale, replayed,
cross-principal, and concurrent proofs fail in real PostgreSQL tests.

### P2 — production runtime, Device API, and Cloud signer closure

Implementation:

1. Compose the production platform-operator repository, authorizer, promotion
   issuance service, historical resolver, signer, and PostgreSQL procedure
   repository in `apps/cloud-api/src/runtime.mjs`.
2. Keep `/v1/platform/promotions` and replay routes absent unless every required
   dependency is healthy. Startup rejects evaluation/file signers, partial
   configuration, shared key resources, shared fingerprints, stale lifecycle,
   wrong algorithm, and legacy promotion v2 issuance.
3. Freeze approve, issue, get, verify, uncertain list/detail, and producer-bound
   reconcile schemas and OpenAPI operations. Require same-origin, CSRF,
   idempotency, no-store, bounded payloads/pagination, and `If-Match` for
   adjudication.
4. Complete Device enrollment/inventory/trust/revoke/re-enroll APIs against the
   existing possession-receipt and control-plane authority, preserving exact
   tenant and device-key binding.
5. Emit append-only audit events for authorization, issuance, verification,
   uncertainty, reconciliation, and denial. Public errors remain stable and
   opaque.
6. Drain HTTP admission, promotion reservations, signer calls, maintenance
   workers, provider clients, and database pools in deterministic order.

Exit gate: hosted startup/readiness/drain tests and the complete authorization,
CSRF, replay, stale-state, tenant/resource-hiding, response-loss, and privacy
matrix pass. No generic provider or signer method is reachable from an HTTP
handler.

### P3 — Console production implementation

Vertical slices, in order:

1. authentication and organization switcher;
2. members, roles, invitations, and session management;
3. devices, enrollment, trust state, revoke, and re-enroll;
4. policies, capabilities, Agent Session grants, narrowing, expiry, and revoke;
5. signer health, lifecycle, rotation progress, and emergency stop;
6. audit activity, bounded export, download, and verification;
7. platform promotion queue/detail/verify/reconcile for platform operators only;
8. owner recovery, dead letters, and operator evidence.

Every slice implements loading, empty, success, validation, forbidden,
reauthentication, conflict, stale state, offline, response-loss, and recovery
states. Mutations use authoritative post-commit responses and accessible exact
confirmations. Reusable authority is forbidden from URLs, local/session
storage, IndexedDB, Cache Storage, analytics, console logs, traces, and rendered
errors.

Exit gate: production-built Playwright tests cover Owner/Admin/Auditor/Viewer
and platform-operator separation, keyboard-only use, focus restoration,
screen-reader semantics, reduced motion, stale/replayed WebAuthn, concurrent
mutation, tenant substitution, offline/response loss, and browser secret scans.

### P4 — all-eight-purpose managed signer readiness

For capability, control bundle, refresh hint, possession receipt, Agent Session
grant, qualification manifest, audit anchor, and promotion evidence:

- require a distinct versioned Ed25519 managed key and IAM principal;
- pin provider, account/project, region, resource, algorithm, key/version,
  lifecycle, public key, and fingerprint;
- expose only fixed-cardinality readiness and aggregate operation metrics;
- support rotation overlap, drain, stale-version rejection, emergency disable,
  and rollback prohibition;
- scan source, config, image layers, logs, metrics, and evidence for private or
  request material.

Exit gate: any missing, duplicated, shared, disabled, stale, exportable, or
wrong-algorithm purpose blocks readiness. All providers drain without an
unfenced operation.

### P5 — protected PostgreSQL and real KMS qualification

Run two API instances against protected PostgreSQL and real AWS KMS and GCP KMS
keys. For every purpose, exercise 100 concurrent exact requests, changed-byte
operation reuse, throttling, outage, malformed result, wrong public key,
invalid signature, ambiguous acceptance/lookup, process kill at every durable
boundary, rotation, emergency disable, database failover, lost commit response,
encrypted backup, PITR, and isolated restore comparison.

Exit gate: each operation reaches one verified committed result or one explicit
durable operator-actionable state. Evidence proves IAM/non-exportability,
contains zero secrets/skips, records measured RPO/RTO, and is independently
verifiable against the exact source and image digests.

### P6 — immutable macOS distribution without requiring a GUI app

1. Build one universal PKG containing the broker, XPC services, launchd jobs,
   CLI, Git helper, and Claude Code/Cursor adapters.
2. Sign nested code with Developer ID Application, sign the installer with
   Developer ID Installer, notarize, staple, and verify Gatekeeper offline.
3. Bind source, compiler/build identity, component inventory, entitlements,
   Team ID, SBOM, notarization ticket, and PKG digest into manifest v4.
4. Ship three entry paths to the identical artifact: direct PKG download,
   Homebrew cask/bootstrap, and CLI-guided browser onboarding.
5. Keep a native onboarding GUI optional. If added later, it calls the same
   local protocol and owns no key, policy, session, or Cloud authority.

Exit gate: clean install, upgrade, failed upgrade, rollback, preserve uninstall,
explicit purge, reinstall, launchd restart, reboot, sleep/wake, Secure Enclave
loss, and rotation pass on Apple silicon and supported Intel/T2 hardware. All
channels resolve to the same signed PKG digest.

### P7 — Claude Code and Cursor physical E2E

Qualify Claude Code first, then Cursor through the same adapter contract. Each
lane performs two unattended signed commits verified by `git verify-commit` and
tests malicious sibling processes, executable replacement, repository/worktree/
remote/branch substitution, symlink/path races, budget exhaustion, expiry,
revocation during signing, daemon/editor restart, network loss, Cloud response
loss, and audit fsync failure.

Exit gate: both agents pass on the exact notarized candidate; revocation blocks
the next operation within the measured bound; no reusable credential appears in
argv, environment, shell history, files, logs, browser state, editor telemetry,
or crash reports.

### P8 — staging, review, and exact production promotion

Deploy immutable Console/API/worker images, migration set, and PKG candidates.
Rehearse canary, drain, rollback, forward migration, failover, PITR, signer
outage/rotation, emergency stop, owner recovery, uncertain reconciliation,
dead-letter redrive, and retention. Commission an independent review of local
privilege boundaries, browser auth, tenant isolation, signer/IAM, database
authority, supply chain, audit/recovery, privacy, and denial of service. Fix and
retest findings, then promote the already-qualified digests without rebuilding.

Exit gate: alerts and runbooks are exercised, restore and revocation bounds are
measured, no critical/high or P0/P1 issue remains, and promotion is explicit,
digest-exact, monitored, and reversible.

## 6. Immediate commit queue

1. `test: execute promotion authority boundary on real postgres`
2. `feat: separate signer database authority and procedures`
3. `feat: persist platform operator assignments and generations`
4. `feat: add platform operator sessions and bound webauthn`
5. `feat: compose platform promotion runtime`
6. `feat: freeze promotion verification and reconciliation api`
7. `feat: add console platform promotion workflow`
8. `feat: close eight-purpose readiness and drain`
9. `test: qualify two-instance postgres and managed kms`
10. `release: publish immutable notarized macos package`
11. `test: qualify claude code and cursor physical journeys`
12. `release: deploy staging and promote exact candidate`

Each commit requires focused positive and negative tests, contract validation,
lint, affected regression suites, `git diff --check`, secret scanning, updated
operator documentation, a clean pushed tree, and source-bound CI. SQL commits
also require fresh and upgrade PostgreSQL runs plus privilege negatives. UI
commits require production BFF/browser E2E and accessibility checks. Native and
release claims require signed artifacts and physical hardware evidence.

## 7. Next action

Start with commit 1. Do not add more API or Console authority until migration
`0048` has executed on real PostgreSQL 16/17 and its negative privilege matrix
passes. In parallel, prepare the signer/app database identity split design and
the platform-operator schema, but merge migration numbers serially.
