# C3 forward implementation plan

Status date: 2026-08-15  
Starting point: local commits `a14b11a` and `4343b0f` on
`codex/agent-platform`  
Remote status: push pending because the current execution environment cannot
resolve `github.com`

## Goal

Close the platform promotion path without giving an organization role, browser,
or generic provider client signing authority. One exact release candidate must
end in either a cryptographically verified committed v3 promotion or an
explicit durable non-success state. A retry must never cause blind re-signing.

## Non-negotiable invariants

1. The caller supplies only promotion, deployment, environment, candidate, and
   idempotency identities. Source, artifact, manifest, qualification, approval,
   signer, lifecycle, key, and timestamps come from authoritative storage.
2. Promotion signs only `agentpass.promotion-evidence` v3 canonical bytes with
   the promotion-purpose managed key. v2, local-file, shared-key, and generic
   signer fallback are forbidden in hosted mode.
3. The service independently verifies the exact signature, statement, key,
   lifecycle, fingerprint, and approval/artifact context before the database
   may commit a deployment transition.
4. Provider acceptance ambiguity becomes `uncertain`; exact replay reconciles a
   known operation but never issues another signature.
5. Promotion and deployment generation advancement commit in one database
   transaction. Rebuilt or substituted candidates are rejected.
6. Organization Owner/Admin/Auditor/Viewer roles grant no platform promotion
   authority. Platform operator authority is separate and operation-bound.
7. Public APIs, Console state, logs, metrics, audit events, and retained evidence
   never expose claim tokens, private principal sets, authorization evidence,
   provider diagnostics, raw credentials, or private key material.

## Wave 1 — close the C3 cryptographic transaction

### C3.1 Historical key resolver

- Add a promotion-purpose resolver backed by immutable signer lifecycle history.
- Require exact purpose, algorithm, protocol/signing version, key ID/version,
  lifecycle version, and public-key fingerprint.
- Return only the bounded public verification metadata accepted by the v3
  verifier.
- Reject missing, disabled-at-issuance, cross-purpose, duplicate, malformed,
  private, accessor, prototype, and diagnostic-bearing results.

Acceptance: rotation-safe verification succeeds for the exact historical key;
all substitutions fail closed with stable opaque errors.

### C3.2 Independent pre-commit verification

- Inject the closed v3 verifier into the issuance service.
- Require the purpose-specific signer to return the complete exact v3 envelope;
  remove permissive raw-signature output handling from the hosted path.
- Verify all repository-derived context immediately after signing and before
  `commitPlatformPromotion`.
- Mark malformed, unverifiable, or ambiguous signer results durably uncertain.
- Preserve exact replay and lost-commit reconciliation without a second signer
  call.

Acceptance: a forged signature, wrong key/fingerprint/lifecycle, modified
statement, provider response loss, or commit response loss cannot produce an
unverified committed row or duplicate signature.

### C3.3 PostgreSQL ledger and privilege closure

- Register migration 0047 in the migration runner, frozen catalog, contract
  counters, authority manifest, and migration tests.
- Confirm every reservation joins the immutable release candidate, unexpired
  platform approval quorum, and active promotion lifecycle in one transaction.
- Verify deployment/environment serialization, opaque digest-only claims,
  database-clock leases, terminal immutability, exact replay conflicts, and
  monotonic generation.
- Replace runtime direct table mutation with reviewed purpose-specific
  procedures/views; revoke direct DML/TRUNCATE, public-schema CREATE, and TEMP
  where the production role model requires it.

Acceptance: a fresh PostgreSQL 17 database passes migration, RLS, negative
privilege, two-pool contention, lease reclaim, stale claim, quorum race,
rotation/disable, rollback, restart, and response-loss tests.

### C3.4 Cloud runtime composition

- Compose the migration-0047 repository, promotion-only KMS provider, v3
  signer, historical resolver, verifier, and issuance service.
- Change the promotion registry/runtime binding to v3 everywhere and reject
  partial, shared, stale, or legacy v2 configuration before readiness.
- Expose a narrow `platformPromotionIssuanceService`; do not expose the KMS
  provider or generic signing primitive.
- Drain in-flight reservations/provider calls before closing PostgreSQL and KMS
  resources in deterministic order.

Acceptance: hosted startup fails closed for every missing/wrong purpose setting;
evaluation adapters cannot be selected; shutdown and readiness tests pass.

## Wave 2 — platform operator product surface

### C3.5 Contracts and API

- Freeze schemas and OpenAPI operations for approval, promote, get, verify,
  uncertain list/detail, and producer-specific reconciliation.
- Introduce a platform-operator identity/session boundary separate from
  organization membership.
- Require WebAuthn recent authorization bound to operation, deployment,
  environment, candidate, approval, and request digest for mutations.
- Enforce same-origin/CSRF, idempotency, `If-Match` for adjudication, bounded
  pagination, no-store responses, and tenant/resource hiding.
- Emit immutable, secret-free success, denial, conflict, uncertain, verify, and
  adjudication audit events.

Acceptance: all organization roles are denied; platform role, stale/replayed/
cross-operation WebAuthn, CSRF, idempotency, concurrency, and privacy matrices
pass.

### C3.6 Console workflow

- Add a platform-only promotion queue and detail page consuming frozen BFF DTOs.
- Show exact candidate/artifact identity, approval quorum summary, signer
  lifecycle, validity, deployment generation, and verification result.
- Model loading, empty, conflict, in-progress, uncertain, expired, corrupt,
  response-loss, offline, stale-adjudication, and success states explicitly.
- Keep evidence and authority out of URLs, browser storage, analytics, logs, and
  error traces; use accessible confirmations and keyboard/screen-reader flows.

Acceptance: production-built Playwright tests cover authorization, WebAuthn,
response loss, reduced motion, keyboard-only, screen reader semantics, and
browser secret scans.

## Wave 3 — operational and production qualification

### C3.7 Two-instance protected fault matrix

- Run two Cloud instances/workers against protected PostgreSQL and one
  non-exportable versioned promotion key in AWS KMS or GCP KMS.
- Exercise 100-request contention, throttling, outage, accepted-but-response-
  lost lookup, database failover, lifecycle rotation/disable, approval expiry,
  process kill/restart, and backup/PITR restore.
- Compare restored deployment heads, promotion ledgers, lifecycle history,
  provider operation identity, and immutable audit heads.

Acceptance: every operation converges to one verified committed result or one
bounded operator-actionable state; retained evidence has no skips or secrets.

### C3.8 Release-candidate binding

- Bind source SHA/tree, migration/catalog digest, Cloud/Console image digests,
  universal PKG digest, SBOM/provenance, qualification reports, approval, and
  signer lifecycle into the v3 statement.
- Require the exact Developer ID-signed, notarized, stapled PKG distributed by
  direct download, Homebrew, and CLI bootstrap; promotion cannot rebuild it.
- Qualify Apple silicon/Secure Enclave and Intel/T2, then Claude Code and Cursor
  with unattended verified commits and measured immediate revocation.

Acceptance: staging drills, canary, rollback, failover, PITR, signer outage, and
recovery pass; an independent security review has no unresolved critical/high
or P0/P1 finding; production promotion is explicit and reversible.

## Parallel execution map

- Lane A: C3.1 and C3.2 cryptographic closure.
- Lane B: C3.3 migration/catalog/privilege work.
- Lane C: native XPC/full Swift regression and CI timeout confirmation.
- Merge gate 1: A + B + C, then C3.4 runtime composition and full regression.
- Lane D after gate 1: C3.5 API/security and C3.6 Console UX in parallel against
  the frozen DTO contract.
- Lane E beside D: protected infrastructure/IAM and physical release harnesses;
  no protected claim is made until real evidence exists.
- Merge gate 2: API + Console + operational controls, then C3.7 and C3.8.

## Required checks per merge

Every merge must have a clean tree, focused unit/negative tests, contract and
catalog validation, lint, root regression, secret scan, and source-bound test
record. SQL changes additionally require a fresh PostgreSQL run and negative
privilege matrix. Runtime changes require startup/readiness/drain tests. UI
changes require production BFF/browser E2E and accessibility checks. Native
changes require bounded Swift tests and the signed-artifact lane. A sandbox
failure, skipped real-system test, mock KMS, ad-hoc signature, or local-only
assertion is recorded honestly and cannot satisfy a production gate.

## Immediate next commits

1. `C3: verify promotion envelope before commit`
2. `C3: register migration 0047 and close PostgreSQL authority`
3. `C3: compose promotion issuance in hosted runtime`
4. `C3: add platform operator schemas and API`
5. `C3: add promotion and reconciliation Console workflow`
6. `C3: qualify two-instance PostgreSQL and managed KMS`
7. `release: bind and promote immutable signed candidate`
