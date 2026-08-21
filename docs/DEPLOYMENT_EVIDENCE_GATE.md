# Deployment evidence gate

`release:deployment-gate` is the provider-neutral boundary between a signed
candidate and staging/production traffic. It does not deploy anything and it
does not accept a caller's `qualified` flag as proof. A protected deployment
runner must first produce canonical evidence for the exact source, release
manifest, artifact, deployment digest, CI run, and job.

The evidence must contain typed readiness checks for the deployed service and a
successful rollback rehearsal. `not_run`, partial, failed, or substituted
evidence is rejected. Provider credentials, tokens, URLs, raw health bodies,
and unbounded diagnostics must remain in the deployment system and never enter
the evidence file.

The binding file is also closed and mandatory. It contains exactly
`sourceCommit`, `sourceTree`, `artifactSha256`, `releaseManifestSha256`,
`deploymentDigest`, `deploymentId`, `environment`, `revision`, `service`,
`imageDigest`, `schemaDigest`, `catalogDigest`, `runId`, `runAttempt`, and
`jobId`; an empty or extended
binding is rejected.

```sh
npm run release:cutover-evidence -- \
  staging-metadata.json cutover.json rollback.json console-readiness.json \
  > deployment-evidence.json
npm run release:deployment-gate -- deployment-evidence.json deployment-binding.json
```

`release:cutover-evidence` accepts the closed metadata envelope and the
`agentpass.cutover.v1` envelopes emitted by `scripts/postgres/cutover.mjs`.
It maps application readiness, traffic drain, combined cutover, and executed
traffic rollback into typed checks. A missing rollback is emitted as
`not_run`; it is never upgraded to `passed`. Failed cutover or rollback stays
failed evidence, so promotion remains fail-closed. The metadata envelope must
also contain the deployment identity (`deployment_id`, `revision`, and
`rollback_target_revision`) plus `source_commit`, `source_tree`, `image_digest`,
`schema_digest`, `catalog_digest`, and `database_schema_digest`, and `cutover_sha256` and
`rollback_sha256` (or 64 zeroes when rollback was not attempted). The cutover
probe and Console readiness identity must match these metadata fields exactly;
otherwise the corresponding check is failed. These fields digest-bind the input
envelopes and prevent cross-run file substitution. A passed rollback must also
prove its completion timestamp and post-rollback readiness.

The command prints a small canonical verification envelope containing the
candidate and deployment digests. It is suitable for a release artifact or
promotion evidence index. It is not a substitute for actually running the
staging drills, rollback, failover/PITR, independent review, or production
promotion workflow.
