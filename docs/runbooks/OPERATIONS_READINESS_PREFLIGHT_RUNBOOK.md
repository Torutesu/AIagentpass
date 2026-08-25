# Operations readiness preflight

This is the operational-ownership gate for an AgentPass staging or production
release. It complements the five technical checks in the operations-readiness
checklist. A structurally valid checklist is not production approval, and a
legacy checklist without `operational_controls` is rejected rather than
treated as a partial pass.

## Required input

The canonical checklist must contain the exact candidate ID, source commit, and
deployed artifact/image digest at the root. Its `operational_controls` object
must contain the exact same candidate/source/artifact tuple plus a protected
execution ID, observed timestamp, evidence digest, and
`execution_mode`/`evidence_origin` set to `protected_external`.

The required operational fields are:

- `evidence_retention`: immutable or object-lock storage, deletion protection,
  access auditing, and at least 90 days of retention;
- `on_call`: protected rotation reference, page-test timestamp, acknowledgement
  timestamp, matching on-call owner, and `status: "verified"`;
- `incident`: distinct incident, on-call, revoke, and rollback owners, plus a
  verified revoke runbook and recent verification timestamp;
- `reviewer`: independent, review-only authority using a separate signing key;
- `rollback`: matching rollback owner, fail-closed status, target binding, and
  a recent verified runbook exercise;
- `kill_switch`: incident-owner binding, fail-closed denial of new and existing
  capabilities, measured propagation within its bound, and a recent verified
  runbook exercise; and
- `expiry`: a future timestamp no more than 30 days after checklist completion.

All owner, route, runbook, execution, and storage references are opaque
protected-resource references. Local, mock, fixture, fake, simulator,
emulator, test, unknown, and placeholder references are rejected. No secrets,
URLs, credentials, private contact details, tenant IDs, session IDs, or raw
provider output may be placed in the checklist.

## Verification command

The command requires the signed operations archive and independent
qualification inputs. The artifact argument is the same digest recorded in the
checklist root and `operational_controls`:

```sh
node scripts/ops/operations-readiness.mjs verify \
  /secure/evidence/operations-readiness.json \
  release-pkg-sha256-v1-<64-hex> <40-or-64-hex-source-commit> \
  /secure/evidence/operations/index.json \
  /secure/evidence/operations \
  sha256:<64-hex-artifact-or-image> \
  /secure/keys/operations-evidence-public.pem <64-hex-self-attested-key-fingerprint> \
  /secure/evidence/operations-qualification.json \
  /secure/keys/operations-qualification-public.pem <64-hex-qualification-key-fingerprint>
```

Missing, stale, noncanonical, fixture-origin, candidate/source/artifact-
mismatched, duplicate, or incomplete input returns `status: "not_proven"`
with a non-zero exit code. The checklist alone never closes the gate; the
independent signed operations qualification and security-review gates remain
separate requirements.

## Operator sequence

1. Freeze the exact candidate, source commit, artifact/image digest, and
   protected execution ID.
2. Confirm immutable retention and access-audit evidence before starting the
   drill.
3. Page the protected on-call route and record the acknowledgement; do not
   substitute a manually asserted status.
4. Assign distinct incident, on-call, revoke, and rollback owners, then assign
   an independent review-only reviewer with a separate key.
5. Execute rollback, revoke/emergency-stop, and kill-switch drills against the
   exact candidate. Record only bounded measurements and redacted digests.
6. Set the expiry window and verify with the protected current clock. Any
   expired or stale control is a stop condition.
7. Run the independent operations qualification and security-review gates.

If any input is uncertain, stop new signing and preserve fail-closed state. Do
not manually update capabilities, bypass the control plane, replay ambiguous
provider requests, or mark an acknowledgement by hand. This repository does
not claim that the external retention store, on-call rotation, live revoke,
rollback, kill-switch, or reviewer has actually been operated; those facts
remain `not_proven` until protected external evidence is collected.
