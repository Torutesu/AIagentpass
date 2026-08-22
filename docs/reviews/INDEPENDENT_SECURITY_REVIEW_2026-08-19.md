# Security-review gate record — 2026-08-19 (not a third-party review)

Status: `not_proven`. This document is a repository-side review record and a list
of required production gates. It does not claim that an independent third party
performed or completed a review. A real third-party engagement, reviewer identity,
signed source-bound record, expiry, and retest evidence remain outstanding.

This repository-side review records the remaining production gates after the current native
Host, Console, PostgreSQL repository, and release-preflight changes. A local
test result is not treated as proof of a production control.

## P0 — runtime database privilege qualification

The reviewed role policy is intended to make promotion and managed-signer
ledgers function-only for runtime roles, while reserving finalization for the
signer role. The remaining proof is a live PostgreSQL qualification, not a
source-level assumption.

- Evidence: `scripts/postgres/roles.sql:135-205`,
  `scripts/postgres/roles.sql:374-386`,
  `contracts/postgres/0054_platform_authorization.sql:1262-1281`.
- Run: `npm run test:postgres:platform-authorization` and
  `npm run postgres:platform-authorization-evidence` against the protected
  PostgreSQL qualification environment.
- Acceptance: app/signer/backup/maintenance roles have no direct DML on
  authority ledgers; only the reviewed SECURITY DEFINER entry points are
  executable; evidence is bound to the exact candidate and schema head.

## P1 — remote signer response and provenance

The repository now independently verifies committed promotion evidence on
commit, replay, uncertainty reconciliation, and committed reads. Remaining
production proof covers the real AWS/GCP KMS response contract and immutable
release provenance.

- Evidence: `apps/cloud-api/src/postgres/platform-promotion-issuance-repository.mjs:119-205`,
  `apps/cloud-api/src/aws-kms-provider.mjs`,
  `apps/cloud-api/src/gcp-kms-provider.mjs`.
- Run: `npm run test:kms:qualification` plus the protected provider
  qualification matrix, then `npm run test:postgres:g4` with real PostgreSQL.
- Acceptance: every provider response is checked for purpose, algorithm,
  key/version, public-key fingerprint, request digest, and signature; no
  mock-only or skipped provider lane is promoted.

## P1 — Host/Child identity boundary

The Host now retains the authenticated child session until child exit and the
listener re-reads public NSXPC connection attributes before later operations.
The raw live `audit_token_t` and real launchd/Mach-service qualification remain
unproven because the public Foundation API exposes only a projection.

- Evidence: `native/macos/Sources/AgentPassNativeAgentHost/main.swift`,
  `native/macos/Sources/AgentPassNativeService/NativeAgentAuthenticatedHostListener.swift`.
- Run on a real macOS release runner: signed Host/Child/Service, launchd
  registration, peer substitution, PID reuse, code-signing requirement, and
  child-specific identity denial matrix.
- Acceptance: candidate-bound live audit-token evidence, no PID-only fallback,
  and terminal revoke/close on every denial or response-loss path.

## P1 — Console/WebAuthn and Apple release gates

The Console correctly treats device-enrollment response loss as
`outcome-unknown` and does not replay the mutation. Browser tests cannot prove
real WebAuthn hardware, Cloud deployment, or accessibility in a signed
production artifact. Developer ID, notarization, stapling, Gatekeeper, and
Secure Enclave/T2 evidence remain external gates.

- Evidence: `apps/web-console/app/components/AgentPassConsole.tsx`,
  `scripts/release/validate-release-evidence.mjs`,
  `docs/RELEASE_QUALIFICATION_EVIDENCE_MATRIX.md`.
- Acceptance: real browser/WebAuthn E2E, exact signed PKG, accepted notary
  result, stapler validation, Gatekeeper assessment, and both hardware lanes
  all bind to one immutable candidate digest.

## Repository state gate

The protected release job must reject a dirty checkout and record the exact
source commit, tree digest, candidate digest, and evidence bundle digest. A
focused local test, an offline release-preflight result, or a skipped live
PostgreSQL/Apple test must remain `not_proven`. The security-review verifier also
requires an unexpired, separately keyed reviewer record before any production-ready
result can be returned; this contract does not supply that real-world record.
