# Staging rollback contract

The shared schema, fixed scenario IDs, observer independence rules, and
SLO/RPO/RTO requirements are defined in
[STAGING_DRILL_EVIDENCE_CONTRACT.md](STAGING_DRILL_EVIDENCE_CONTRACT.md).
This runbook is the rollback projection of that contract.

Rollback is an executed safety test for the exact staging deployment. It is
not a rebuild, a down-migration, or an instruction to change Cloud API or
Console authentication. The operator reuses an immutable retained target and
records the provider-neutral result.

## Required proof

`staging-rollback.mjs` requires the current candidate and deployment identity
plus a rollback record containing:

- `executed: true` and `tested: true`;
- `reused_artifact: true`, with the current candidate binding unchanged;
- a target with a different revision and complete candidate/source/tree,
  artifact, manifest, image, deployment, and deployment-digest identity;
- `target_ready: true` after the target is activated;
- `traffic_restored: true` after the target receives traffic; and
- start/completion timestamps inside a current evidence window of at most 24
  hours, with no future-dated completion.

The rollback record must also bind its unique execution ID and independent
observer evidence digest to the exact current candidate/source/tree,
artifact/image/schema/catalog/database-schema digests and the immutable
rollback target. It must include measured rollback RTO (and any applicable
service SLO/RPO values). An observer assertion copied from the rollback
operator, a status-only provider response, or a self-reported `target_ready`
value is `not_proven`, not a pass.

The target deployment must remain in staging and use the same deployment ID
and service as the current deployment. A same-revision target, missing target,
target digest substitution, untested result, response-loss ambiguity, or
failure to restore traffic is not a qualified rollback.

Generate the record only after the rollback sequence has completed, then
verify it from the protected checkout:

```sh
node scripts/release/staging-rollback.mjs verify \
  /secure/evidence/staging-rollback.json \
  /secure/evidence/staging-binding.json \
  --now=2026-08-20T12:00:00.000Z
```

The command must exit zero and emit `status: "passed"` and
`qualified: true`. Any exception or non-zero exit is fail-closed `STOP`.
Retain failed and replacement records; never edit a failed record into a
pass, blindly retry an uncertain operation, delete state, or down-migrate a
live database.

## Operator stop conditions

Stop and page the rollback owner when the target cannot become ready, traffic
cannot be restored, the provider response is lost after acceptance, the
candidate/source/tree/deployment digest differs, the evidence is expired, or
the exact run/job and operator timeline cannot be retained. Capture only
redacted logs and stable reason codes; never place tokens, private keys,
cookies, database URLs, raw provider responses, or identity assertions in the
rollback record.

The focused contract tests prove parsing and fail-closed behavior only. They do
not prove real provider execution, database compatibility, alert delivery,
Cloud API/Console auth, or production rollback authority.

Rollback is one of seven required staging scenarios. A rollback record cannot
close the staging gate while `canary`, `drain`, `failover`, `pitr`,
`signer_outage`, or `recovery` is missing, `not_run`, `not_proven`, stale, or
self-reported. Preserve every failed or uncertain execution and allocate a
new execution ID for a rerun; never edit a failed record into a pass.

## Promotion handoff

Retain the canonical rollback record in
`AGENTPASS_STAGING_ROLLBACK_JSON`, together with the matching readiness record
and exact binding in `AGENTPASS_STAGING_READINESS_JSON` and
`AGENTPASS_STAGING_BINDING_JSON`. The protected promotion workflow verifies
both records against the same candidate/source/tree, final artifact and
manifest digests, current staging deployment/image/deployment digest, and
rollback target identity. It uses the current UTC clock, so an expired record
cannot be replayed as a promotion pass.

The workflow retains the verifier outputs as release integrity evidence only
after both commands return `status: "passed", qualified: true`; `not_run`,
`failed`, missing, substituted, non-canonical, or expired evidence stops the
promotion before draft release creation.
