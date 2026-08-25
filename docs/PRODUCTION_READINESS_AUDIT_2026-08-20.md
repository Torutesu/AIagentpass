# AgentPass production-readiness audit — 2026-08-20

Status: audit snapshot for the current checkout, reviewed 2026-08-21. This is
an evidence index and go/no-go checklist; it is not a production qualification
report.

Scope: `docs/IMPLEMENTATION_PLAN_2026-08-15.md`,
`docs/PRODUCTION_HARDENING_PLAN.md`, `docs/qualification/`, `README.md`,
release/security runbooks, and the implementation present in this checkout.
Existing uncommitted changes are part of the checkout under review. This audit
does not edit workflows or core/runtime implementation.

## Evidence vocabulary

Use one state for every row. A stronger state may be recorded only when the
corresponding evidence is retained and independently reproducible.

| State | Meaning | Acceptable evidence |
| --- | --- | --- |
| `implemented` | Source and focused tests express the contract. | Code path plus focused/static test output. |
| `locally-qualified` | A local or disposable integration run passed. | Exact command, checkout SHA, environment class, and redacted result. |
| `source-bound-ci` | Canonical CI passed against the exact source commit/tree. | Run/job IDs and retained artifact digest; no skipped or `not_proven` terminal result. |
| `externally-qualified` | Protected infrastructure, real provider, physical hardware, or independent reviewer supplied evidence. | Signed/immutable evidence bound to candidate SHA/tree and artifact digests. |
| `open` | Required implementation or evidence is missing, stale, or not independently verifiable. | A blocker and owner/action are required. |

Local tests never upgrade a row to `externally-qualified`. A configured
workflow, a fixture, a simulated provider, an ad-hoc signature, or a document
claim is not external evidence.

## External qualification gate disposition

The repository contains the external qualification contract, schema, verifier,
and producers, but this checkout does not retain an external qualification
envelope or signed child-gate artifact for the candidate under review. The
following is therefore the authoritative disposition for this audit: contract
implementation is recorded as evidence, while every protected external gate
remains `open` until its independently collected, source/tree/run/job/artifact-
bound evidence is verified.

| External gate | Current state | Current implementation / local evidence | Unverified external proof required |
| --- | --- | --- | --- |
| `github_actions` | `open` | `scripts/release/ci-preflight.mjs`, `scripts/release/ci-preflight.test.mjs`, `.github/workflows/ci.yml`, and the external qualification schema define the exact source/run/job/artifact checks. | A protected push run for this candidate, exact six lanes (`postgres-authority-16`, `postgres-authority-17`, `postgres-integration`, `browser-e2e`, `p0b-live-process`, `test`), per-job SHA/attempt, and retained artifact digests obtained from the GitHub API. |
| `postgresql` | `open` | `scripts/qualification/postgres-c3-migration-0047.mjs`, `scripts/qualification/backup-pitr-evidence.mjs`, C3 qualification tests, and the CI PostgreSQL 16/17 job definitions. | Independent PostgreSQL 16 and 17 protected runs covering migration/role/RLS, transaction/concurrency/rollback, backup/restore/PITR, TLS `verify-full`, HA/failover, and measured RPO/RTO, all bound to this candidate. |
| `kms` | `open` | `scripts/qualification/cloud-signer-kms.mjs`, `scripts/qualification/cloud-signer-kms.test.mjs`, and `docs/CLOUD_SIGNER_KMS_QUALIFICATION.md` define fail-closed typed evidence. | Real managed KMS/HSM identity, exact key-version binding, production IAM allow/deny matrix, rotation/disable, canary sign/verify, response-loss reconciliation, and non-exportability evidence from the protected provider account. |
| `webauthn` | `open` | `apps/cloud-api/test/postgres/webauthn-qualification.integration.test.mjs`, Platform Auth implementation/tests, and the external qualification schema cover the local contract. | Real authenticator against the deployed origin/RP and durable database path, including one-time consumption, replay/stale-context rejection, outage fail-closed behavior, and two-instance protected evidence. |
| `macos_hardware` | `open` | `scripts/release/p0c/`, `scripts/release/n3e/`, hardware qualification tests, and `docs/P0C_HARDWARE_QUALIFICATION.md` define the Apple Silicon and Intel/T2 evidence contracts. | Signed/notarized exact candidate on both hardware classes, Secure Enclave/device identity and negative entitlement tests, install/upgrade/rollback/revoke/sleep-wake/recovery results, and immutable report/artifact digests. |

No row in this gate table may be promoted to `source-bound-ci` or
`externally-qualified` by a local test run, a configured workflow, or a signed
claim alone. The evidence handoff must contain the required record described
below and must be independently re-read from the protected systems.

## Current checkout checklist

### A. Contract, authority, and hosted runtime

| Item | Current state | Code/test evidence | Missing external proof or action |
| --- | --- | --- | --- |
| Frozen contract catalog and schema/OpenAPI validation | `implemented` | `contracts/catalog-v1.json`, `scripts/validate-contracts.mjs`, `test/contract-catalog.test.mjs` | Run and retain the result for the exact candidate SHA. |
| Eight-purpose managed-signer configuration and fail-closed readiness | `implemented` | `apps/cloud-api/src/runtime.mjs`, `apps/cloud-api/test/runtime-readiness-contract.test.mjs`, `apps/cloud-api/test/postgres/runtime-readiness.test.mjs` | Real managed keys, IAM/non-exportability, rotation, and image/config secret scan. |
| Provider-operation ledger and response-loss/reconciliation contract | `locally-qualified` | `apps/cloud-api/src/postgres/provider-operation-repository.mjs`, `apps/cloud-api/src/provider-operation-reconciliation-adapter.mjs`, focused PostgreSQL tests | Two API instances and real AWS/GCP provider acceptance/lookup evidence. |
| PostgreSQL migration 0047 C3 schema, RLS, append-only guards, and role ACL contract | `implemented` | `contracts/postgres/0047_platform_promotion_issuance.sql`, `apps/cloud-api/test/postgres/c3-migration-0047-adversarial.test.mjs` | Protected PostgreSQL 16/17 execution, TLS `verify-full`, HA/failover, backup/PITR, restore comparison, and measured RPO/RTO. |
| C3 platform promotion repository and v3 verifier | `implemented` | `apps/cloud-api/src/postgres/promotion-issuance-repository.mjs`, `apps/cloud-api/src/promotion-evidence-v3-verifier.mjs`, `apps/cloud-api/test/postgres/promotion-issuance-repository.test.mjs`, `apps/cloud-api/test/promotion-evidence-v3-verifier.test.mjs` | Real transaction/process qualification, provider/KMS evidence, and atomic deployment transition in protected staging. |
| Platform Auth four-factor boundary | `implemented` | `apps/cloud-api/src/platform-auth.mjs`, `apps/cloud-api/src/platform-promotion-http-api.mjs`, `apps/cloud-api/test/platform-auth.test.mjs`, `apps/cloud-api/test/platform-promotion-http-api.test.mjs` | Deployment-owned principal, authenticated mTLS socket, workload identity, durable WebAuthn, rotation, and two-instance protected evidence. |
| Durable, secret-free operation audit | `implemented` | `apps/cloud-api/src/postgres/platform-promotion-audit-repository.mjs`, C3/Platform Auth tests | Protected database retention, monitoring, alert delivery, and incident drill evidence. |

### B. Enrollment, console, revoke, and recovery

| Item | Current state | Code/test evidence | Missing external proof or action |
| --- | --- | --- | --- |
| Browser/CLI enrollment handoff and candidate binding | `implemented` | `README.md`, `lib/device-enrollment-client.mjs`, enrollment contract tests | Real Console + Cloud + browser qualification with response loss and recovery. |
| Organization/member/device/policy/session control surfaces | `implemented` | `apps/web-console/app/`, `apps/cloud-api/src/human-auth/`, focused Console/API tests | Production-built Playwright matrix: all roles, accessibility, stale/replay, tenant substitution, offline, and response loss. |
| Local and native emergency revocation | `implemented` | `bin/agentpass.mjs`, `lib/control-bundle-v2.mjs`, native session/revoke tests | Physical and protected staging measurement of revocation bound and post-revoke denial. |
| Owner recovery and destructive-action authorization | `implemented` | `apps/cloud-api/src/human-auth/recovery/`, recovery tests, `docs/OWNER_RECOVERY_DELIVERY_RUNBOOK.md` | External delivery, alerting, retention, provider failure, and independent security review. |
| Incident/revoke procedure | `implemented` (documented) | [Incident and revoke runbook](INCIDENT_AND_REVOKE_RUNBOOK.md) | Tabletop and staging drill with retained sanitized timeline. |

### C. Release, supply chain, and promotion

| Item | Current state | Code/test evidence | Missing external proof or action |
| --- | --- | --- | --- |
| Exact six-lane CI terminal result and source binding | `implemented` | `scripts/release/ci-preflight.mjs`, `scripts/release/ci-preflight.test.mjs`, `test/ci-contract-gate.test.mjs` | A successful canonical run for the exact candidate, with all six lanes and retained run/job/artifact IDs. |
| Release artifact/archive secret scanning | `implemented` | `scripts/release/archive-secret-scan.mjs`, `scripts/release/archive-secret-scan.test.mjs` | Run against the actual candidate archives and retain the machine-readable result. |
| Signed release manifest, SBOM, notarization evidence contract | `implemented` | `docs/RELEASE.md`, `scripts/release/generate-sbom.mjs`, `scripts/release/verify-release.mjs`, release tests | Developer ID signing, Apple `Accepted`, stapler validation, Gatekeeper, exact post-staple digest, and protected credentials. |
| Promotion workflow stop conditions and exact-candidate binding | `implemented` | `.github/workflows/promote-qualified-release.yml`, `test/promote-qualified-release-workflow.test.mjs`, [release evidence](RELEASE.md) | Successful protected dispatch with exact release/qualification/CI run bindings; workflow execution itself is not proven by local tests. |
| Physical Apple silicon and Intel/T2 qualification | `open` | `docs/PRODUCTION_HARDENING_PLAN.md`, `scripts/release/n3e/`, hardware qualification tests | Signed reports for the same immutable PKG digest, including install/upgrade/rollback/revoke/sleep-wake scenarios. |
| Claude Code and Cursor physical E2E | `open` | Adapter and E2E test contracts | Two unattended verified commits per agent, hostile substitution/revoke/restart/network-loss matrix on the exact candidate. |
| Staging drills and independent security review | `open` | `docs/IMPLEMENTATION_PLAN_2026-08-15.md` Q5 gates | Canary/drain/rollback/failover/PITR/signer outage/recovery records; no unresolved critical/high findings and retest evidence. |

## Required evidence record

For every `source-bound-ci`, `externally-qualified`, or promotion decision,
retain a redacted record containing:

- candidate source commit and full tree hash;
- release manifest digest, product PKG digest, image digest, SBOM digest, and
  migration/catalog digest;
- workflow/run/job IDs, exact lane names, terminal results, and artifact
  digests;
- environment class and deployment digest, provider/key identifiers and key
  versions (never private material or raw provider responses);
- qualification command, start/end timestamps, operator identity, and result
  digest;
- incident/revoke actions, measured revocation bound, rollback target, and
  approving authority;
- independent verification result and retention location.

An evidence file with `not_run`, `failed`, `not_proven`, missing source/tree
binding, missing run/job binding, an unexpected lane, a skipped scenario, or an
unverified artifact is a blocker. Do not edit a failed report into a passing
report; rerun the qualification and retain both the failure and replacement
record.

## Go/no-go summary for this checkout

The checkout is implementation-ready for the next protected qualification
wave, but it is not production-ready. The local evidence supports the C3/
Platform Auth/0047 contracts and release-gate validators. It does not prove
real KMS, protected PostgreSQL, canonical GitHub execution for this candidate,
Apple signing/notarization, physical hardware, agent E2E, staging drills, or
independent review. Promotion therefore remains `STOP` until every open row
above has external evidence and the stop conditions in [RELEASE.md](RELEASE.md)
are satisfied.

## Re-audit command set

These commands are bounded repository checks and do not contact external
providers:

```sh
npm run contracts:validate
node --test \
  test/release-hardening.test.mjs \
  test/promote-qualified-release-workflow.test.mjs \
  test/production-readiness-audit-docs.test.mjs \
  scripts/release/ci-preflight.test.mjs \
  scripts/qualification/qualification-docs-contract.test.mjs \
  scripts/release/archive-secret-scan.test.mjs \
  apps/cloud-api/test/platform-auth.test.mjs \
  apps/cloud-api/test/platform-promotion-http-api.test.mjs \
  apps/cloud-api/test/postgres/c3-migration-0047-adversarial.test.mjs \
  apps/cloud-api/test/postgres/c3-migration-0047-qualification.test.mjs
git diff --check
```

The result of this command set is focused/static evidence only. It must not be
reported as external qualification or production approval.
