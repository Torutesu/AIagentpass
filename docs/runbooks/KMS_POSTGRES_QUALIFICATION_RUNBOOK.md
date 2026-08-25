# KMS and PostgreSQL qualification

This runbook separates local contract validation from protected qualification.
The KMS runner is provider-neutral and accepts injected, typed projections; it
does not call AWS or GCP itself. The PostgreSQL runner requires a disposable
real database and must never be pointed at `AGENTPASS_DATABASE_URL`.

## Managed signer/KMS

The controlled environment must exercise all eight frozen purposes, eight
same-purpose IAM allows plus 56 cross-purpose denies, 40 ordered
purpose/scenario results, and two PostgreSQL instance records. Each purpose
must bind provider/resource, key version, algorithm, protocol/signing version,
public-key fingerprint, lifecycle version, and non-exportability. Exercise:

- provider contract and canary sign/verify;
- exact key-version binding and stale-version rejection;
- lifecycle fence and emergency disable;
- provider timeout/outage and response-loss lookup reconciliation; and
- two API instances under contention, with zero blind retries.

The report must be canonical JSON, redacted, `passed`/`qualified: true`, and
bound to source commit/tree, deployment digest, qualification run ID, and job
ID. Validate it with:

```sh
node scripts/release/ci-preflight.mjs kms-qualification \
  /secure/evidence/kms-qualification.json \
  <source-sha> <source-tree> <deployment-digest> <run-id> <job-id> \
  > /secure/evidence/kms-verification.json
```

Missing probes, `AGENTPASS_KMS_QUALIFICATION_ENABLED` not set to `true`,
`not_run`, failed scenarios, incomplete matrices, raw provider output, or
missing bindings are blockers. The local script's `not_run` output is useful
negative evidence only; it is not a qualification pass.

## PostgreSQL 0047 on versions 16 and 17

Use a fresh disposable instance for each major version. Supply only the test
URL and bind the exact source/tree/run/attempt:

```sh
export AGENTPASS_TEST_DATABASE_URL='postgresql://ADMIN:REDACTED@HOST/DB?sslmode=verify-full'
export AGENTPASS_C3_SOURCE_COMMIT='<40-char-source-sha>'
export AGENTPASS_C3_SOURCE_TREE='<40-char-source-tree>'
export AGENTPASS_C3_CI_RUN_ID='<run-id>'
export AGENTPASS_C3_CI_RUN_ATTEMPT='<attempt>'
export AGENTPASS_C3_EXPECTED_POSTGRES_MAJOR='16'  # use 17 on the second instance
node scripts/qualification/postgres-c3-migration-0047.mjs \
  > /secure/evidence/postgres-0047-pg16.json
```

The runner computes `artifact_sha256` from the raw bytes of the fixed C3 input
artifact `contracts/postgres/0047_platform_promotion_issuance.sql` (or an
explicit, controlled `AGENTPASS_C3_ARTIFACT_PATH`). A supplied
`AGENTPASS_C3_ARTIFACT_SHA256` is checked against those bytes and is never the
source of truth. Empty, all-zero, unknown, or substituted digests fail closed.

The command must reach version 47, verify migration checksum and catalog
objects, execute role/RLS/append-only/authority probes, prove one contention
winner, and prove transaction rollback. Run the `verify` subcommand against
the retained canonical file when the CI binding is available:

```sh
node scripts/qualification/postgres-c3-migration-0047.mjs verify \
  /secure/evidence/postgres-0047-pg16.json \
  <source-sha> <source-tree> <run-id> <attempt> 16 \
  > /secure/evidence/postgres-0047-pg16-verification.json
```

Repeat with `17`; both results are required. `database_url_missing`,
`database_unavailable`, migration/role/verification failure, wrong TLS
identity, pre-existing authority rows, `not_run`, or a single-version result
is not a pass. This qualification does not by itself prove HA, backup/PITR,
restore RPO/RTO, or production IAM; retain those records separately.

## Evidence checklist

- [ ] KMS report has 8 purposes, 64 IAM cells, 40 scenario results, and 2 PG
  instance records.
- [ ] Both PG16 and PG17 reports are passed, source/tree/run/attempt-bound, and
  canonical; no credentials or raw errors are present.
- [ ] Provider/KMS key versions, public fingerprints, deployment digests, and
  operator identity are recorded as public metadata only.
- [ ] Backup/PITR/restore, failover, TLS, image/IAM, and secret-scan evidence
  is attached; local/static tests are labeled separately.
- [ ] Any failure and replacement run are both retained; no failed report was
  edited or deleted.
