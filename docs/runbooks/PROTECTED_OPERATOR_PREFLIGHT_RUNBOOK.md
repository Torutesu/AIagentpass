# Protected operator preflight

This runbook is the operator stop gate for protected CI/staging qualification.
It does not create evidence and does not contact a CA, backup service, GitHub,
or a deployment provider. The operator must retain the real, redacted evidence
files from those systems. A fixture, local test, `not_run`, simulated result,
placeholder digest, or guessed identifier is never a pass.

## Required evidence

Prepare one canonical preflight packet and these independently retained files:

- the exact release manifest and final artifact; the CLI re-hashes both and
  checks `candidate_id`, source commit/tree, artifact name, and product digest;
- a CA verification record with the leaf and trust-anchor fingerprints,
  server name, protected trust store, verification time, and certificate
  expiry covering the whole review window;
- a backup/PITR record with a real backup ID, isolated restore target,
  recovery point, measured RPO/RTO, and equal source/restored authority
  digests. The restore must be isolated and must not restore over live data;
- the canonical external qualification aggregate and its independently
  collected binding file. All five external gates must be `passed` and
  `qualified: true`, with real runner, run, job, source, and child-artifact
  bindings;
- an executed staging rollback record proving the exact candidate was reused,
  the target revision became ready, traffic was restored, and the rollback was
  tested; and
- the signed/retained reviewer report whose digest is in the packet. The
  review must be current, expire in the future, be no more than 30 days long,
  and the CA must remain valid through its expiry.

All JSON evidence must be canonical JSON, single-link regular files, and pass
the protected secret scan. Never put private keys, credentials, tokens, raw
provider responses, database URLs, assertions, or raw logs in the evidence.

## Verification

Run this from the protected qualification checkout. The CLI always uses the
host's current UTC clock; it deliberately has no clock-override option, so an
operator cannot make expired evidence pass. Deterministic replay tests should
call the exported verifier directly with an injected clock:

```sh
node scripts/release/operator-preflight.mjs verify \
  /secure/evidence/operator-preflight.json \
  /secure/candidate/release-manifest.json \
  /secure/candidate/AgentPass-<version>.pkg \
  /secure/evidence/ca-verification.json \
  /secure/evidence/backup-pitr.json \
  /secure/evidence/external-qualification.json \
  /secure/evidence/external-binding.json \
  /secure/evidence/rollback.json \
  /secure/evidence/security-review-report.pdf \
  > /secure/evidence/operator-preflight.result.json
```

Only the command's `status: "passed"` and `qualified: true` result may be
used as the operator preflight result. The command exits non-zero for missing
files, noncanonical JSON, symlinks/hardlinks, secret markers, artifact or
source substitution, expired CA/review, missing PITR comparison, incomplete
external evidence, or an unexecuted rollback. It never fills a missing value
with a local timestamp or turns `not_run` into a pass.

The command validates the existing external qualification contract, but it
does not prove that a claimed external execution happened. Preserve the
authoritative provider/API records and the exact CI run/job/artifact lookups
alongside the result. Local focused tests are contract evidence only and do
not close the external, CA, backup/PITR, hardware, IAM, or deployment gates.

## STOP conditions

Stop promotion when any digest, source/tree, run/job, CA expiry, backup/PITR
authority comparison, external gate, review expiry, or rollback binding is
missing or differs. Keep failed and replacement evidence; do not edit a failed
record into a pass, rebuild a qualified artifact, or restore over live data.
