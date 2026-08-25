# C3 Wave 1 security/completeness review

Disposition: repository-side/static review record only. This file does not claim
that an independent third party performed or completed a security review. Its
findings and local evidence remain subject to the production review gate in
[`INDEPENDENT_SECURITY_REVIEW_CONTRACT.md`](INDEPENDENT_SECURITY_REVIEW_CONTRACT.md)
and are not production approval.

Date: 2026-08-15  
Scope: C3 Wave 1 foundation at `fc64b99` in `codex/agent-platform`  
Reviewer: repository-side static read-only analysis; no independent third-party engagement is claimed

## Executive result

The v3 statement, signer, verifier, and fake-client repository tests pass, but Wave 1 is not yet an executable security boundary. The service cannot be composed with the PostgreSQL repository as currently written, the commit path has no mandatory independent cryptographic verification, and the database role contract permits direct mutation of platform approval and issuance authority. These are release-blocking findings for any hosted deployment.

## Findings

### C3-W1-01 — service/repository commit contract is incompatible (P0)

Evidence:

- `apps/cloud-api/src/platform-promotion-issuance.mjs:211` sends `promotion_evidence` to `commitPlatformPromotion`.
- `apps/cloud-api/src/postgres/platform-promotion-issuance-repository.mjs:22` accepts `evidence`, and `:182-187` reads `input.evidence`.
- The repository therefore rejects the service’s commit request as an unknown/missing field before it can commit.
- The repository returns `evidence` at `:370-375`, while the service requires `promotion_evidence` at `:357-358` and throughout `:222-245`.

Recommended patch:

- Freeze one interface in a shared contract module and use one field name end to end.
- Add a real service+PostgreSQL-repository integration test that exercises reserve → sign → commit → replay; do not use separate fake shapes for the two layers.
- Keep the public service DTO separate from the internal repository DTO, but map it explicitly in exactly one adapter.

### C3-W1-02 — repository reservation cannot satisfy the service’s required context (P0)

Evidence:

- The service requires `issued_at`, `expires_at`, and `signer_key_fingerprint` at `apps/cloud-api/src/platform-promotion-issuance.mjs:365-383`.
- `contracts/postgres/0047_platform_promotion_issuance.sql:68-123` has no `issued_at` or evidence expiry column.
- `ROW_SELECT` in `apps/cloud-api/src/postgres/platform-promotion-issuance-repository.mjs:24-31` does not select either time, nor a public-key fingerprint.
- `selectAuthority` at `:285-313` selects `key_id` and `key_version` but not `key.public_key_fingerprint`.
- Consequently, a real reservation result fails `normalizeRepositoryOutcome` before signing; the existing service test passes only because its fake reservation invents these fields.

Recommended patch:

- Decide whether the issuance reservation owns an evidence validity window. If it does, persist DB-clock `issued_at`/`expires_at` (or an equivalent bounded window) and return it.
- Return the canonical `SHA256:<base64url>` fingerprint derived from the stored key bytes, or make the service consume a documented internal fingerprint representation and convert once.
- Add a real PostgreSQL integration test using the exact service and repository objects.

### C3-W1-03 — independent signature verification is optional and not wired (P0)

Evidence:

- `apps/cloud-api/src/postgres/platform-promotion-issuance-repository.mjs:68-75` makes `verifyEvidence` optional.
- `:188-190` verifies only when that optional callback is supplied.
- `apps/cloud-api/src/platform-promotion-issuance.mjs:200-207` validates envelope shape and binding but never calls `verifyPromotionEvidenceV3` or an equivalent verifier.
- The current PostgreSQL integration fixture commits a zero/placeholder signature at `apps/cloud-api/test/postgres/platform-promotion-issuance.integration.test.mjs:96-99`, demonstrating that the current repository path accepts structurally valid but cryptographically invalid evidence when no verifier is injected.

Recommended patch:

- Make a purpose-specific verifier mandatory in the production issuance composition, and pass the complete reservation context to it.
- Verify after signer output and again at the repository commit boundary (or make the repository’s commit procedure the sole cryptographic boundary); do not rely on a signer’s self-check.
- Require a real Ed25519 signature in integration tests and assert forged/zero signatures never reach committed state.

### C3-W1-04 — verifier context is not mandatory enough for authority binding (P0)

Evidence:

- `apps/cloud-api/src/promotion-evidence-v3-verifier.mjs:182-213` requires only deployment/environment/candidate/artifact/approval identity fields.
- `source_commit`, `source_tree`, `release_manifest_schema_version`, `release_manifest_sha256`, qualification reports, purpose/protocol/signing versions, key identity, lifecycle version, and signer fingerprint are optional at `:191-213`.
- With those omitted, the verifier can validate a genuine signature over a statement that is not independently bound to the database-selected release and lifecycle context.

Recommended patch:

- Add a strict platform-promotion verification profile whose context requires every field copied from the reservation, including all release digests, report list, protocol/signing versions, key/lifecycle identity, and fingerprint.
- Keep any permissive/general verifier API separate and impossible to select from the hosted issuance path.
- Add adversarial tests that omit each mandatory field and assert configuration failure before resolver/signature acceptance.

### C3-W1-05 — uncertainty reasons do not match between service and repository (P1)

Evidence:

- The repository allow-list at `apps/cloud-api/src/postgres/platform-promotion-issuance-repository.mjs:17-20` excludes `signer_failure`, `signer_output`, and `commit_failure`.
- The service sends those exact reasons at `apps/cloud-api/src/platform-promotion-issuance.mjs:186-196`, `:204`, and `:232-246`.
- `markUncertainBestEffort` suppresses the rejection at `:152-159`; therefore provider ambiguity can return an uncertain public error while the durable row remains `reserved`.
- Once the lease expires, `reservePlatformPromotion` can reclaim the row at repository `:85-97`, allowing a second provider attempt for the same logical promotion.

Recommended patch:

- Define one shared enum for uncertainty reasons and test every service-to-repository transition.
- Treat a provider-boundary failure as terminal uncertain even if the claim lease has expired; reconciliation must not silently turn an ambiguous provider call into a fresh reservation.
- Add a response-loss/lease-expiry integration test with two callers and assert exactly one terminal outcome.

### C3-W1-06 — SQL state machine allows reserved-claim replacement and unauthenticated direct inserts (P0)

Evidence:

- `contracts/postgres/0047_platform_promotion_issuance.sql:159-205` installs the issuance guard only for `BEFORE UPDATE`, not `INSERT`.
- For `reserved → reserved`, the trigger checks identity fields but does not make `claim_token_digest` or `claim_expires_at` immutable. A caller with table UPDATE can replace the live claim digest.
- The table checks do not bind `evidence_digest` to `evidence_bytes`, do not bind a committed generation to the deployment head, and do not bind issuance `candidate_id` to the referenced approval’s candidate on INSERT.
- The generic role policy grants the application `SELECT, INSERT, UPDATE, DELETE` on every public table at `scripts/postgres/roles.sql:107-117`, including `platform_promotion_approvals`, `platform_promotion_issuances`, `platform_promotion_deployments`, and managed signer lifecycle tables.

Impact: a compromised or over-privileged `agentpass_app` connection can insert a quorum-satisfying approval, insert or alter an issuance, and advance the deployment projection without passing the service, WebAuthn/operator authorization, or cryptographic verifier.

Recommended patch:

- Revoke direct DML on platform approval, deployment, issuance, release-candidate authority, and signer-lifecycle tables from the application role.
- Expose only narrow `SECURITY DEFINER` procedures owned by the migrator/authority owner, with fixed `search_path`, strict arguments, and explicit transition checks; alternatively use a dedicated narrowly privileged promotion role.
- Add an INSERT trigger/procedure-level check for all cross-row invariants, including approval/candidate identity, evidence canonical bytes/digest, current generation + 1, and cryptographic verification.
- Make reserved claim material immutable except through the one claim-reclaim procedure, which must fence the provider boundary.
- Add a PostgreSQL role integration test that attempts direct INSERT/UPDATE/DELETE from `agentpass_app` and verifies every authority mutation is denied.

### C3-W1-07 — candidate/lifecycle authority is read without a locking fence (P1)

Evidence:

- `selectAuthority` at `apps/cloud-api/src/postgres/platform-promotion-issuance-repository.mjs:285-313` reads an active candidate, approval, and active key but does not lock the selected rows.
- A candidate can be retired by another transaction after this SELECT and before the issuance INSERT. The issuance then retains authority selected from a candidate that was no longer active at commit time.

Recommended patch:

- Lock the selected authority rows (`FOR SHARE`/`FOR KEY SHARE` on the candidate and approval as appropriate) or make reservation a stored procedure that holds the required row locks through insertion.
- Add a concurrent retirement/reservation integration test.

### C3-W1-08 — migration/catalog/authority-manifest/runtime integration is incomplete (P0)

Evidence:

- `apps/cloud-api/test/postgres/migration-runner.test.mjs:69-75` still expects migrations only through 0046.
- `contracts/catalog-v1.json:243-245` has no 0047 catalog entry.
- `scripts/postgres/authority-manifest.mjs:24-95` omits the new deployment/issuance tables and pins `REQUIRED_MIGRATION_VERSION` to `"46"`; `:252-255` rejects a database whose applied head is 47.
- `apps/cloud-api/src/postgres/runtime.mjs:291-327` does not construct or export a platform-promotion issuance repository.
- `apps/cloud-api/src/runtime.mjs:34-35` and `:189-207` still import/bind the v2 promotion signer, while the registry/KMS definitions at `apps/cloud-api/src/signer-purpose-registry.mjs:24` and `apps/cloud-api/src/kms-provider-runtime.mjs:65-73` describe promotion evidence as v3.
- The Cloud runtime does not compose `createPlatformPromotionIssuanceService` or the v3 historical verifier.

Impact: a hosted process can either fail startup/readiness at schema/authority-manifest checks or continue using the old promotion contract; the new C3 ledger is not on the production execution path.

Recommended patch:

- Register 0047 in the runner expectations, catalog, release migration manifest, authority-manifest table set, and deployment/readiness checks.
- Add the new tables to the authority snapshot and privilege qualification.
- Replace the runtime v2 signer binding with the v3 signer/verifier/issuance composition and make hosted readiness fail closed if any part is absent.
- Add a hosted runtime construction test with all eight KMS bindings, a real promotion repository, and a v3 verifier resolver.

## Verification performed

Passing focused tests:

```text
node --test \
  apps/cloud-api/test/promotion-evidence-v3-verifier.test.mjs \
  apps/cloud-api/test/promotion-evidence-v3-signer.test.mjs \
  apps/cloud-api/test/platform-promotion-issuance.test.mjs \
  apps/cloud-api/test/postgres/platform-promotion-issuance-repository.test.mjs \
  apps/cloud-api/test/postgres/platform-promotion-issuance-migration.test.mjs
```

Result: 50 passing tests. These cover the v3 primitives and isolated fake repository behavior, but not the service/repository composition or a real database authority boundary.

Additional checks:

- KMS registry/provider unit tests pass for the eight-purpose configuration.
- Authority-manifest tests fail because the expected migration head remains 46 while the migration directory now contains 0047.
- Runtime/PostgreSQL runtime tests could not start in this checkout because the nested clone has no installed `pg` dependency; this is an environment limitation, not evidence of correctness.
- No commit or push was performed; the worktree remained otherwise unchanged.

## Minimum exit criteria before C3 Wave 1 can be called complete

1. A real service → repository → PostgreSQL test commits one cryptographically valid v3 envelope and replays it without a second signing call.
2. The strict verifier requires and checks every DB-derived release, approval, key, lifecycle, and timestamp field.
3. Provider response loss and lease expiry converge to one durable committed or uncertain state.
4. `agentpass_app` cannot directly mutate promotion approvals, issuance rows, deployment heads, or signer lifecycle authority.
5. Migration 0047, catalog, authority manifest, readiness, and hosted runtime all agree on schema version 47 and the v3 execution path.
