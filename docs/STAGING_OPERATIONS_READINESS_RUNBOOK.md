# Staging operations readiness runbook

The machine-readable policy at
`ops/operations-readiness/staging-checklist.v1.json` is the source of truth for
the five structural checks. The checklist is not external qualification by
itself. The qualification gate validates the checklist and the independently
signed operations bundle together:

```sh
node scripts/ops/operations-readiness.mjs verify \
  /secure/evidence/operations-readiness.json \
  release-pkg-sha256-v1-<64-hex> <40-or-64-hex-source-commit> \
  /secure/evidence/operations/index.json \
  /secure/evidence/operations \
  sha256:<64-hex-image> \
  /secure/keys/operations-evidence-public.pem <64-hex-self-attested-key-fingerprint> \
  /secure/evidence/operations-qualification.json \
  /secure/keys/operations-qualification-public.pem <64-hex-qualification-key-fingerprint>
```

All paths must be absolute regular files/directories as required by the
verifiers. The checklist must be canonical JSON with one trailing newline and
must declare both `execution_mode` and `evidence_origin` as
`protected_external`, but those declarations are structural claims only.
The root must also contain `artifact_digest`; the verifier binds that digest,
the candidate ID, and the source commit to the command arguments and nested
operational record.
Local fixtures, mock providers, a local PostgreSQL result, a copied status
string, or an unbound report are not production evidence. Missing,
malformed, stale, fixture-origin, unknown-field, duplicate-key,
candidate-mismatched, source-mismatched, or qualification-missing input
returns `status: "not_proven"` with a non-zero exit code.

## Operational input contract

The `operational_controls` object is mandatory for the staging and production
gate. It is not a free-form status note: the verifier requires
the exact candidate ID, source commit, and deployed image/artifact digest used
by the command, plus a protected execution ID, observed timestamp, and
evidence digest. A missing or substituted binding returns `not_proven`.

The object must provide all of the following operational inputs. A checklist
without this object is rejected as incomplete; it is never downgraded to a
legacy structural pass:

- immutable, audited retention with deletion protection and a retention period
  of at least 90 days;
- an on-call owner, protected rotation reference, and a page test followed by
  an acknowledgement;
- distinct incident, on-call, revoke, and rollback owners, with a verified
  revoke runbook and timestamp;
- a review-only independent reviewer using a separate signing key;
- a verified, fail-closed rollback owner and target-bound rollback runbook;
- a verified kill-switch owned by incident command, denying both new and
  existing capabilities, with an observed propagation time no greater than the
  bound; and
- an expiry timestamp in the future and no more than 30 days after completion.

The operational input must use `execution_mode` and `evidence_origin` equal to
`protected_external`. Values such as `local`, `fixture`, `mock`, `test`, or
`unknown` are rejected. The checklist root must also contain the same
`artifact_digest`; the nested value is then cross-checked against the signed
operations archive image digest, while candidate and source must match the
root and every child record.

The complete `operational_controls` shape is:

```json
{
  "artifact_digest": "sha256:<64-hex>",
  "candidate_id": "release-pkg-sha256-v1-<64-hex>",
  "evidence_digest": "sha256:<64-hex>",
  "evidence_origin": "protected_external",
  "evidence_retention": {
    "access_audit_enabled": true,
    "delete_protection_enabled": true,
    "location_ref": "object-lock:operations-evidence-prod",
    "retention_days": 365,
    "storage_class": "immutable_worm"
  },
  "execution_id": "ops-run-prod-<opaque-id>",
  "execution_mode": "protected_external",
  "expiry": { "expires_at": "<ISO-UTC>" },
  "incident": {
    "incident_owner_ref": "incident-command-prod",
    "on_call_owner_ref": "oncall-primary-prod",
    "revoke_owner_ref": "revoke-owner-prod",
    "revoke_runbook_ref": "runbook:revoke:v1",
    "revoke_status": "verified",
    "revoke_verified_at": "<ISO-UTC>",
    "rollback_owner_ref": "rollback-owner-prod"
  },
  "kill_switch": {
    "fail_closed": true,
    "last_verified_at": "<ISO-UTC>",
    "operation": "deny_new_and_existing_capabilities",
    "owner_ref": "incident-command-prod",
    "propagation_bound_ms": 30000,
    "propagation_observed_ms": 125,
    "runbook_ref": "runbook:kill-switch:v1",
    "status": "verified"
  },
  "observed_at": "<ISO-UTC>",
  "on_call": {
    "acknowledged_at": "<ISO-UTC>",
    "owner_ref": "oncall-primary-prod",
    "page_tested_at": "<ISO-UTC>",
    "route_ref": "rotation:oncall-primary-prod",
    "status": "verified"
  },
  "reviewer": {
    "approval_authority": "review_only",
    "independent": true,
    "organization": "external-security-lab",
    "reviewer_id": "reviewer-external-001",
    "separate_signing_key": true
  },
  "rollback": {
    "fail_closed": true,
    "last_verified_at": "<ISO-UTC>",
    "owner_ref": "rollback-owner-prod",
    "runbook_ref": "runbook:rollback:v1",
    "status": "verified",
    "target_binding_verified": true
  },
  "source_commit": "<40-or-64-hex-source-commit>"
}
```

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

`structure_verified` proves only that the supplied checklist is structurally
complete and bound to the requested candidate and source. The complete command
returns success only after the separate operations verifier reports
`qualification_status: "independently_qualified"`; even then, local
verification does not replace the protected AWS/GCP, PostgreSQL, staging, or
physical-device execution gates.

## Cloud qualification bundle

The cloud production qualification workflow requires a signed operations
evidence archive in addition to deployment and KMS evidence. The archive must
contain `index.json` and exactly five source/image-bound child records:
rollback, backup/PITR, emergency stop, fleet propagation, and alert delivery.
Each child is a canonical `agentpass.operations.<check>.v1` record with
`execution_mode` and `evidence_origin` set to `protected_external`, exact
candidate/source/image binding, an `observed_at` timestamp, and a check-specific
set of boolean assertions. The workflow recomputes every child SHA-256,
rejects missing, duplicate, or extra files, checks the 24-hour freshness window,
requires every semantic assertion to be true, and verifies the Ed25519
signature before publishing the result. A caller-provided `qualified` flag or
digest without the corresponding downloaded file is not accepted.

The verifier is:

```sh
node scripts/ops/verify-operations-evidence-bundle.mjs verify \
  /secure/evidence/operations/index.json /secure/evidence/operations \
  release-pkg-sha256-v1-<64-hex> <40-hex-source-commit> sha256:<64-hex-image> \
  /secure/keys/operations-evidence-public.pem <64-hex-self-attested-key-fingerprint> \
  /secure/evidence/operations-qualification.json \
  /secure/keys/operations-qualification-public.pem <64-hex-qualification-key-fingerprint>
```

The verifier requires the independent qualification record, a distinct
qualification key, and a non-local protected-runner witness before returning
`qualification_status: "independently_qualified"`. This closes only the
repository-verifiable provenance boundary. It still does not turn a
self-attested provider run into independent external proof; the signing key,
protected runner, live PostgreSQL/PITR target, alert receiver, and fleet
instances must remain under the protected operations boundary.
