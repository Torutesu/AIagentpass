# AgentPass production operator packet

This directory is the execution layer for the implementation and hardening
plans. It does not grant production approval. The dated audit and
[`docs/RELEASE.md`](../RELEASE.md) remain the evidence and stop-condition
authorities; these runbooks make the operator sequence and evidence record
explicit.

Runbooks:

- [`RELEASE_PROMOTION_RUNBOOK.md`](RELEASE_PROMOTION_RUNBOOK.md) — exact-source
  CI, evidence binding, stop conditions, and promotion.
- [`PROTECTED_OPERATOR_PREFLIGHT_RUNBOOK.md`](PROTECTED_OPERATOR_PREFLIGHT_RUNBOOK.md)
  — CA, backup/PITR, artifact, external-evidence, expiry, and rollback stop gate.
- [`OPERATIONS_EVIDENCE_BUNDLE_RUNBOOK.md`](OPERATIONS_EVIDENCE_BUNDLE_RUNBOOK.md)
  — structure-only readiness checks, independent qualification bundles, and
  fail-closed verification.
- [`INCIDENT_REVOKE_RUNBOOK.md`](INCIDENT_REVOKE_RUNBOOK.md) — containment,
  scoped revoke, uncertain operations, rollback, and closure evidence.
- [`KMS_POSTGRES_QUALIFICATION_RUNBOOK.md`](KMS_POSTGRES_QUALIFICATION_RUNBOOK.md)
  — managed signer/KMS and PostgreSQL 16/17 qualification.
- [`MACOS_RELEASE_NOTARIZATION_RUNBOOK.md`](MACOS_RELEASE_NOTARIZATION_RUNBOOK.md)
  — universal PKG, Developer ID, notarization, Gatekeeper, and hardware proof.
- [`MACOS_HOST_CONTROL_QUALIFICATION_HANDOFF.md`](MACOS_HOST_CONTROL_QUALIFICATION_HANDOFF.md)
  — protected probe provisioning, launchd installation, separate-process
  `agentpass close`, post-close signing denial, response-loss retry, and
  physical evidence handoff.
- [`STAGING_DRILL_SECURITY_REVIEW_RUNBOOK.md`](STAGING_DRILL_SECURITY_REVIEW_RUNBOOK.md)
  — staging deployment, failure drills, independent security review, and go/no-go.
- [`STAGING_DEPLOYMENT_READINESS_RUNBOOK.md`](STAGING_DEPLOYMENT_READINESS_RUNBOOK.md)
  — candidate-bound readiness, canary, drain, expiry, and fail-closed verification.
- [`STAGING_ROLLBACK_RUNBOOK.md`](STAGING_ROLLBACK_RUNBOOK.md)
  — immutable rollback target, execution proof, traffic restoration, expiry, and stop conditions.

For every run, retain a redacted canonical record with `status`, source commit,
source tree, exact `candidate_id`, candidate/artifact/deployment digests,
environment class, exact run/attempt/job IDs, command, UTC timestamps,
operator/reviewer ID, signed reviewer report digest, review `expires_at`,
rollback current/target revisions, rollback run/job and evidence digest, and
result digest.
Never retain private keys, tokens, cookies, database URLs, raw provider
responses, WebAuthn assertions, request payloads, or identity claims.

Evidence states are deliberately separate: `implemented`, `locally-qualified`,
`source-bound-ci`, and `externally-qualified`. `not_run`, `failed`,
`not_proven`, skipped, simulated, or ad-hoc results are blockers.
