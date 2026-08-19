# Staging operations readiness runbook

The machine-readable policy at
`ops/operations-readiness/staging-checklist.v1.json` is the source of truth for
the five required checks. Validate one canonical, candidate-bound evidence
envelope with:

```sh
node scripts/ops/operations-readiness.mjs verify \
  /secure/evidence/operations-readiness.json \
  release-pkg-sha256-v1-<64-hex> \
  <40-or-64-hex-source-commit>
```

The evidence path must be absolute and a regular file. It must be canonical
JSON with one trailing newline and must declare both `execution_mode` and
`evidence_origin` as `protected_external`. Local fixtures, mock providers, a
local PostgreSQL result, a copied status string, or an unbound report are not
production evidence. Missing, malformed, stale, fixture-origin,
unknown-field, duplicate-key, candidate-mismatched, or source-mismatched input
returns `status: "not_proven"` with a non-zero exit code.

## Audit of the existing readiness material

`docs/POSTGRES_BACKUP_RESTORE.md` and the existing observability runbooks are
valuable component-level procedures, but they do not by themselves close a
candidate-wide rollback, emergency-stop propagation, or tenant-isolation
exercise. `docs/PRODUCTION_EVIDENCE_BOUNDARY.md` correctly keeps AWS/GCP,
PostgreSQL, and macOS qualification external, but previously had no single
checklist envelope for these five staging controls. This runbook supplies that
missing boundary; the component validators remain authoritative for their own
evidence and are not replaced by this checklist.

## Before the drill

- Freeze the exact source commit and release candidate ID; bind both at the
  root and every check.
- Freeze the alert-policy and deployment configuration digests in the
  protected evidence system.
- Assign an incident commander and authority owner. If protected staging
  infrastructure is unavailable, stop and report `not_proven`.
- Never put credentials, URLs, tenant IDs, session IDs, request IDs, raw logs,
  provider responses, or private material in the evidence envelope.

## Required checks

1. **Rollback:** deploy the candidate, exercise the protected health gate, and
   rehearse rollback. Verify the prior revision rejection boundary, the
   candidate-bound rollback artifact, and that authority is not widened.
2. **Backup/PITR:** create a protected backup, restore it to a distinct target,
   recover to an explicit point-in-time, and verify backup/restore manifests,
   schema head, recovery target binding, and tenant-data integrity.
3. **Revoke/emergency stop:** revoke a capability/device/session and exercise
   the organization emergency stop. Observe propagation, durable terminal
   state, acknowledgement quorum, and denial of both new and already-issued
   capabilities.
4. **Alerting:** validate the frozen policy digest, safely exercise warning and
   critical paths, verify delivery/escalation, and verify exporter counter
   reset is fail-closed. Capture bounded aggregate evidence only.
5. **Tenant isolation:** execute real same-tenant allow and cross-tenant deny
   pairs, verify RLS and admin scope, confirm no cross-tenant rows, and prove
   a matrix covering at least two tenant pairs.

## Stop conditions

If rollback, PITR, revoke, emergency stop, alerting, or tenant isolation is
uncertain, stop new signing and preserve fail-closed state. Do not manually
update capabilities, bypass the control plane, replay an ambiguous provider
request, or mark an acknowledgement by hand. Quarantine a PITR mismatch and
keep the deployment blocked after alert delivery failure.

`closed` proves only that the supplied protected evidence is structurally
complete and bound to the requested candidate and source. It does not replace
the protected AWS/GCP, PostgreSQL, staging, or physical-device execution gates.
