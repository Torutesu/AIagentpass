# PostgreSQL C3 migration 0047 qualification

`0047_platform_promotion_issuance.sql` must be qualified against a real PostgreSQL instance. Static SQL tests and a fake client do not prove that the migration can be committed, that the catalog objects exist, or that the transition, role boundary, RLS, and concurrency guards behave in PostgreSQL.

Focused static tests are explicitly `static-only`: they inspect the migration text and qualification contract, but they are not a PostgreSQL qualification result. A real database run is required before claiming that 0047 is qualified.

## Run

Use a disposable qualification database. The runner uses the same ordered migration loader and `createMigrationRunner` as the Cloud API. It accepts only the test database variables so an operator cannot accidentally point this qualification at the normal `AGENTPASS_DATABASE_URL`.

```sh
export AGENTPASS_TEST_DATABASE_URL='postgresql://ADMIN:REDACTED@HOST/DATABASE?sslmode=verify-full'
export AGENTPASS_C3_SOURCE_COMMIT='<40-char-commit-sha>'
export AGENTPASS_C3_SOURCE_TREE='<40-char-source-tree-sha>'
export AGENTPASS_C3_CI_RUN_ID='<github-run-id>'
export AGENTPASS_C3_CI_RUN_ATTEMPT='<github-run-attempt>'
export AGENTPASS_C3_CI_JOB_ID='postgres-authority-16-or-17'
export AGENTPASS_C3_EXPECTED_POSTGRES_MAJOR='16-or-17'
export AGENTPASS_C3_EXPECTED_DATABASE_NAME='agentpass_c3_16-or-17'
export AGENTPASS_C3_EXPECTED_SERVER_PORT='5432'
export AGENTPASS_C3_CA_CERT_FILE='/secure/qualification/postgres-ca.pem'
export AGENTPASS_C3_BACKUP_PITR_EVIDENCE='/secure/qualification/postgres-backup-pitr.json'
node scripts/qualification/postgres-c3-migration-0047.mjs > /secure/qualification/postgres-c3-migration-0047.json
```

`artifact_sha256` is the SHA-256 of the exact bytes of the C3 qualification
input artifact, `contracts/postgres/0047_platform_promotion_issuance.sql`.
It is not the digest of the output evidence JSON, a database URL, a migration
claim, or a caller-provided label. The runner opens that fixed regular file
with no-follow semantics, reads the bytes through the opened descriptor, checks
that the file identity and size did not change, and computes the digest in the
same CI process. `AGENTPASS_C3_ARTIFACT_PATH` may select an explicitly staged
copy for a controlled qualification run; its bytes must be the input actually
qualified. The default is the repository path above.

`AGENTPASS_C3_ARTIFACT_SHA256` and the legacy
`AGENTPASS_QUALIFICATION_ARTIFACT_SHA256` variables are optional compatibility
assertions only. If present, the runner rejects empty, `unknown`, all-zero, or
substituted values unless they exactly equal the digest it computed from the
input bytes. The `verify` subcommand independently recomputes the same digest
before accepting evidence, while binding it with source commit, source tree,
CI run ID/attempt, and canonical CI job ID. To inspect the computed value:

```sh
node scripts/qualification/postgres-c3-migration-0047.mjs artifact-digest
```

The URL must be a disposable qualification database administrator connection with exactly `sslmode=verify-full`. The CA path must be absolute, a regular non-world-writable file, and contain only public certificate PEM material; a missing or invalid CA fails before any connection attempt. The expected major, database name, and server port are mandatory target bindings for a real run. The canonical CI job must be `postgres-authority-16` or `postgres-authority-17` and must match the expected major. The URL is read only from the test variables; `AGENTPASS_DATABASE_URL` is never accepted.
When a database is configured, `AGENTPASS_C3_SOURCE_COMMIT` (or the CI-provided
`GITHUB_SHA`) is mandatory. CI also supplies the exact source tree, run ID,
attempt, canonical job ID, and the artifact path is fixed to the qualification
input described above. Passed evidence includes all six bindings; a missing,
malformed, or byte-mismatched artifact binding fails closed. The CI verifier recomputes the
source tree from `${GITHUB_SHA}^{tree}` and checks the evidence against the
same run, attempt, job, artifact bytes, and expected PostgreSQL major.

## GitHub Actions service TLS setup

The two authority jobs use the official `postgres:16` and `postgres:17` service
images. GitHub Actions starts those services before job steps, so each job then
creates a short-lived CA and a server certificate with `127.0.0.1` and
`localhost` SANs using the runner's OpenSSL. The public certificate and private
key are copied into the service container, PostgreSQL is restarted with
`ssl=on`, and a first `hostnossl ... reject` rule is inserted into
`pg_hba.conf`. The job probes the configured database with
`PGSSLMODE=verify-full` and the generated CA, and separately requires a
plaintext connection attempt to fail. The qualification runner receives the
same CA file through `AGENTPASS_C3_CA_CERT_FILE` and the URL contains exactly
`sslmode=verify-full`.

This is a real TLS PostgreSQL service and a real database connection, but the
ephemeral CI certificate is not production PKI evidence. A successful static
workflow test or a local Docker run does not prove that the protected
qualification job executed. The runner's independently produced backup/PITR
evidence remains a separate required gate; this service setup does not create
or substitute that evidence.

`AGENTPASS_C3_BACKUP_PITR_EVIDENCE` is also mandatory for a real run. It must
be an absolute, non-symlink, non-world-writable canonical JSON file whose
`source_commit`, `source_tree`, `ci_run_id`, `ci_run_attempt`, `ci_job_id`,
and `artifact_sha256` exactly match this run. It contains `backup_restore` and
`pitr_recovery` typed checks, each with `status: "passed"`, typed
`expected`/`observed` values, and a matching `evidence_sha256`. The qualification
runner consumes this independently produced backup/restore and PITR result; it
does not manufacture `not_run` checks. Missing, malformed, failed, or
substituted backup/PITR evidence is non-qualified.

`AGENTPASS_C3_ALLOW_TEST_POOL=true` is accepted only by injected test pools in
the Node test suite. The command-line runner always constructs the real `pg`
pool; a fake pool, absent database, or skipped integration test cannot produce
qualified evidence.

The role SQL is credential-free. Authentication for the three service roles remains an external deployment concern; this qualification proves their PostgreSQL attributes, memberships, ACLs, and effective role authorization. Use a fresh disposable database because the migration runner commits schema changes. Before behavior probes, the runner requires the five authority/provider tables to be empty; the committed winner from the unique-index contention probe remains as synthetic qualification data, and the runner never truncates or deletes it. A rerun therefore fails closed before it can touch pre-existing authority. Probe identifiers and values are random/redacted and are not emitted in evidence.

The command exits zero only when all of the following are true:

- migration 0047 is present in the ordered local migration set and its database checksum matches the local SQL;
- the URL, CA, expected PostgreSQL major, expected database/port, artifact, and canonical CI bindings are present and mutually consistent;
- migration history reaches version 47 without dirty or modified rows;
- the three migration tables, required columns, partial/index objects, trigger objects, functions, and validated constraints exist;
- all expected RLS policies exist, `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY` are enabled on the four platform tables, and the app/backup roles pass the negative privilege probes;
- `agentpass_app`, `agentpass_migrator`, and `agentpass_backup` are login-capable, non-privileged, non-inheriting, non-bypass roles with no cross-membership, and their ACLs match `roles.sql`;
- a valid approval → reserved issuance → committed issuance → promoted deployment transition commits under `agentpass_app` while `agentpass_backup` can read but cannot mutate;
- authority mutation, backup mutation, and generation rollback probes are rejected;
- two concurrent app sessions cannot commit two open issuances for one deployment/environment; and
- a transaction rollback removes both a synthetic row and a synthetic DDL object.
- the independently produced backup-restore and PITR checks are both passed and bound to the same qualification evidence.

The adversarial contract also requires that audit INSERTs verify `event_hash`, issuance INSERTs begin only in `reserved`, stale deployment generations cannot be replayed, deployment evidence is bound to the committed issuance, and the service-role ACLs are explicit in this migration rather than depending on a later `roles.sql` replay.

The JSON evidence contains only stable check IDs/statuses and normalized server/version plus `current_database()`/`inet_server_port()` metadata. It does not contain the database URL, credentials, UUIDs, row contents, SQL text, or PostgreSQL error text. The verifier binds the database name and port to the expected CI lane before upload. The uploaded artifact is only the independently verified `postgres-16.json` or `postgres-17.json` file; its artifact name is bound to the CI job, source SHA, run ID, and run attempt, and the upload fails if the file is absent.

## Database-enforced immutability added by 0047

Migration 0047 now closes the two direct-SQL gaps that cannot be covered by the application repository alone:

- `platform_promotion_audit_events` has a statement-level `BEFORE TRUNCATE` trigger. Its append-only guard rejects `TRUNCATE` in the same way it rejects `UPDATE` and `DELETE`. The runtime and backup roles also have `TRUNCATE` revoked. The migration owner remains an explicit maintenance boundary: an owner-level operation that removes or disables the trigger is outside the application-role contract and must be controlled by deployment policy.
- `event_hash` is checked on audit INSERT against the database implementation of the protocol canonical preimage. The preimage includes the logical event fields and redacted `details`, and intentionally excludes transport-generated `event_id` and `recorded_at`, matching the repository's retry/idempotency hash.
- `authority_digest` is checked on issuance INSERT against all immutable authority fields, including the ordered qualification digest array. A mismatch is rejected with a constraint violation; the database does not silently rewrite caller input.

The existing column types and INSERT shape remain unchanged. These checks are trigger-based rather than generated columns so the current repository and SQL parameter contract stays compatible. The static/adversarial tests assert the trigger, canonicalizer, digest binding, and ACL objects. A configured PostgreSQL 16/17 run is still required to prove the PL/pgSQL execution and role behavior; a local static pass is not production evidence.

## Fail-closed result when Docker or PostgreSQL is unavailable

No environment is treated as success. When the URL is absent, the command prints evidence with `status: "not_run"`, `qualified: false`, and `reason: "database_url_missing"`, then exits 1:

```json
{"schema_version":1,"qualification":"postgres-c3-migration-0047","status":"not_run","qualified":false,"reason":"database_url_missing","migration_version":47,"migration_name":"0047_platform_promotion_issuance.sql","migration_checksum":null,"migration_applied_this_run":false,"current_version":null,"server_version":null,"database_name":null,"server_port":null,"checks":[]}
```

An unreachable database is reported as `status: "failed"`, `qualified: false`, and `reason: "database_unavailable"`. Missing CA, missing backup/PITR evidence, an unexpected major, a target-binding omission, or a migration/role/catalog/probe mismatch is likewise non-zero with its typed diagnostic (`ca_cert_invalid`, `backup_pitr_not_run`, `server_version_unexpected`, `database_target_missing`, `migration_failed`, `role_failed`, or `verification_failed`). Do not replace these outcomes with a skipped or passing report.

## Scope and remaining external gates

This seam proves one configured PostgreSQL instance and the C3 0047 schema/transition, role, RLS, rollback, and bounded contention contract. The canonical CI runs this same qualification exactly once in each `postgres-authority-16` and `postgres-authority-17` lane, using port 5432 and isolated `agentpass_c3_16`/`agentpass_c3_17` databases. The separate `postgres-integration` lane retains its existing PostgreSQL 17/16 integration, C1.5, role, and W1.5 tests and is not used as a second C3 lane. A local or single-version run must not be presented as the complete version matrix. It does not by itself prove production TLS/IAM authentication, backup/restore, HA/failover, sustained load, or application/browser/hardware qualification. Those remain unverified until their independent environments produce evidence.
