# PostgreSQL hosted cutover runbook

This runbook describes the staged, forward-only cutover of the hosted AgentPass control plane to PostgreSQL. The operator tool is:

```sh
node scripts/postgres/cutover.mjs <command>
```

The tool emits exactly one JSON object on stdout. The object has the stable envelope:

```json
{
  "schema": "agentpass.cutover.v1",
  "ok": true,
  "command": "status",
  "phase": "status",
  "code": "OK",
  "result": {}
}
```

On a failed operation, `ok` is `false` and `code`, `message`, and `remediation` are stable operator-facing fields. The process exits non-zero. Error causes, SQL text, database URLs, row identifiers, credentials, bearer material, and drain-file contents are never emitted.

## Safety rules

1. Use `AGENTPASS_CLOUD_PROFILE=hosted`. The cutover tool refuses evaluation mode, mixed configuration, unknown `AGENTPASS_CUTOVER_*` variables, missing operational authentication, and unverified PostgreSQL TLS.
2. Put `AGENTPASS_DATABASE_URL`, `AGENTPASS_OPERATIONAL_PROBE_SECRET`, and `AGENTPASS_CUTOVER_DRAIN_SECRET` in the deployment environment or a secret manager. Do not put them in shell history, command arguments, CI logs, issue comments, or process arguments. Both secrets must decode from unpadded base64url to exactly 32 bytes. The database URL must use `postgresql://...?...sslmode=verify-full` exactly once and no other query parameter.
3. `preflight` and `status` are read-only. `migrate --apply` and `validate --apply` are mutating commands and require the explicit flag.
4. The migration runner is forward-only. Once a migration commits, rollback means sending application traffic to the previously known-good application revision and preserving the committed schema. This tool has no down-migration command by design.
5. Treat `ok: true` from `readiness` as a gate result, not as permission to skip deployment change control. Keep the current traffic path until both readiness and drain gates pass.
6. Drain evidence is an HMAC-authenticated, deployment-bound document. Store it as a short-lived mode `0600` regular file, never follow a symlink, keep it at or below 64 KiB, and remove it after the gate decision. The evidence nonce and signature are not printed.

## Approved environment

```sh
export AGENTPASS_CLOUD_PROFILE=hosted
export AGENTPASS_DATABASE_URL='postgresql://<user>:<password>@<private-host>/<database>?sslmode=verify-full'
export AGENTPASS_CUTOVER_APPLICATION_VERSION='release-<immutable-version>'
export AGENTPASS_CUTOVER_READINESS_URL='https://<private-health-host>/health/ready'
export AGENTPASS_CUTOVER_READINESS_ALLOWED_ORIGIN='https://<private-health-host>'
export AGENTPASS_OPERATIONAL_PROBE_SECRET='<43-character-base64url-32-byte-secret>'
export AGENTPASS_CUTOVER_DRAIN_SECRET='<43-character-base64url-32-byte-secret>'
export AGENTPASS_CUTOVER_TARGET_MANIFEST='{"schema":"agentpass.cutover.target.v1","target":{"id":"<immutable-db-target>","database_url_sha256":"<sha256-of-the-exact-database-url>","migrations":[{"version":1,"checksum":"<reviewed-sha256>"},{"version":2,"checksum":"<reviewed-sha256>"}]},"deployment":{"id":"<immutable-deployment-id>","revision":"<immutable-revision>","traffic_generation":"<exact-traffic-generation>","application_version":"release-<immutable-version>"}}'
```

`AGENTPASS_CUTOVER_TARGET_MANIFEST` is required for `migrate`, `drain`, and `cutover`. Its exact target hash must match the complete `AGENTPASS_DATABASE_URL`; `migrations` must contain every reviewed migration from version 1 through the exact release target with its file checksum; and its deployment revision, traffic generation, and application version are the only values accepted by the corresponding gates. Generate this manifest in the release pipeline from the reviewed migration inventory, sign the deployment manifest as release evidence, and inject the exact JSON through the secret/deployment environment. It is non-secret but integrity-sensitive. A migration fails closed if an extra future migration is bundled, a checksum differs, or any binding is absent/mismatched.

`AGENTPASS_CUTOVER_READINESS_URL` is required for a production readiness decision. It must be HTTPS, have no user information, query parameters, or fragments, and have the exact `AGENTPASS_CUTOVER_READINESS_ALLOWED_ORIGIN` origin. The CLI sends `AgentPass-Operational-Token` with the exact value of `AGENTPASS_OPERATIONAL_PROBE_SECRET` to that origin only. `/health/ready` and `/health/metrics` must require this header. The response is streamed and rejected above 64 KiB, and must contain JSON with `{"ready":true}`. The optional timeout is `AGENTPASS_CUTOVER_READINESS_TIMEOUT_MS` (250–30000 ms, default 5000). The drain freshness window is `AGENTPASS_CUTOVER_DRAIN_MAX_AGE_MS` (1000–300000 ms, default 30000).

No other `AGENTPASS_CUTOVER_*` variable is accepted. Do not add a variable for a password, token, private key, or connection string.

## 1. Read-only preflight and migration status

Run both against the database that will receive the cutover. These commands do not begin a write transaction.

```sh
node scripts/postgres/cutover.mjs preflight
node scripts/postgres/cutover.mjs status
```

The preflight checks the same-organization attribution required by migration `0011`. A successful preflight has `result.ok=true`, `result.validated=false`, and `result.violation_count=0`. A blocked result must be repaired or quarantined and checked again; do not bypass it by applying SQL manually.

The status result reports `expected_version`, `database_version`, applied/pending/modified versions, and dirty migration attempts. A dirty state, checksum drift, gap, newer history, or pending version is not ready for traffic cutover.

For an existing deployment, the expected starting point is the last supported schema before the hosted cutover. The tool intentionally does not treat an empty database as a valid hosted cutover target: bootstrap a new environment through the normal reviewed migration process and verify it independently.

## 2. Apply migrations and validate staged constraints

After change approval and a clean read-only preflight:

```sh
node scripts/postgres/cutover.mjs migrate --apply
```

`migrate --apply` requires the exact target/deployment manifest above before it runs preflight or SQL. It acquires the migration advisory lock, checks immutable checksums, applies SQL transactionally, records the pinned application version, and returns the post-run status. If the command fails, inspect the stable JSON code and database migration status. Do not edit `schema_migrations` by hand.

Migration `0011` installs tenant foreign keys as `NOT VALID` after its internal fail-closed attribution check. Once the data repair window is complete, validate them explicitly:

```sh
node scripts/postgres/cutover.mjs validate --apply
```

`validate --apply` is intentionally separate from `preflight`: it changes constraint validation state and must have its own approval. A validation failure rolls the validation transaction back and leaves the constraints `NOT VALID`.

## 3. Readiness gate

```sh
node scripts/postgres/cutover.mjs readiness
```

The gate checks, without changing authority:

- migration history has no pending, modified, or dirty versions;
- the tenant-attribution preflight is clean;
- PostgreSQL answers the health query;
- the configured application readiness endpoint returns `ready=true` and is configured;
- lock-wait and pool metrics are readable (`available=true`) and secret-free.

Missing or malformed application readiness is not treated as ready. A metrics read failure is reported as unavailable and is not treated as ready; every schema, preflight, database, metrics, and application check must pass. The output contains counts and booleans only.

## 4. Drain gate input

The traffic platform must produce a fresh, bounded, HMAC-authenticated drain document. The exact accepted shape is:

```json
{
  "schema": "agentpass.drain.v2",
  "deployment_id": "<manifest-deployment-id>",
  "revision": "<manifest-revision>",
  "traffic_generation": "<manifest-traffic-generation>",
  "nonce": "<fresh-base64url-nonce>",
  "drained": true,
  "active_requests": 0,
  "oldest_request_age_ms": 0,
  "observed_at": "2026-08-13T12:00:00.000Z",
  "signature": "<base64url-hmac-sha256>"
}
```

The signature is HMAC-SHA-256 over the canonical JSON of every field except `signature`, using `AGENTPASS_CUTOVER_DRAIN_SECRET`. It therefore authenticates the deployment ID, revision, traffic generation, and fresh nonce as well as the drain counters and timestamp. The timestamp must be canonical UTC and within the configured freshness window. Unknown fields, binding substitutions, invalid signatures, active requests, non-zero oldest request age, future observations, stale observations, malformed JSON, symlinks, non-regular files, oversized files, and secret-bearing input are rejected. Use a `0600` regular file and pass only its path:

```sh
node scripts/postgres/cutover.mjs drain --drain-file /secure/run/agentpass-drain.json
```

The path and file contents are not included in the JSON response.

## 5. Combined cutover gate

After the application revision is deployed but before changing traffic:

```sh
node scripts/postgres/cutover.mjs cutover --drain-file /secure/run/agentpass-drain.json
```

This is a decision gate only. It does not switch a load balancer, mutate PostgreSQL, or install a bundle. Change traffic only when the result is `ok=true`. If either gate fails, leave the current traffic path unchanged, resolve the failing condition, obtain a fresh drain document, and rerun the command.

## 6. Rollback and forward-only recovery

If the new application revision is unhealthy after traffic movement:

1. Stop new traffic to the new revision and route traffic to the previously known-good application revision using the reviewed deployment platform control.
2. Preserve the PostgreSQL schema and all committed authority rows. Do not run a down-migration, delete migration history, restore an old schema over the live database, or edit sequence/head values.
3. Re-run `status` and `readiness` against the preserved database. The previous application revision must be compatible with the committed schema before receiving traffic.
4. Investigate using deployment logs, audit events, migration attempts, cryptographic heads, and the immutable release digest. Keep credentials out of evidence and incident messages.

The CLI can produce or execute only an application-traffic rollback through an injected, reviewed deployment controller:

```sh
node scripts/postgres/cutover.mjs rollback --confirm
```

Without such a controller, the command fails with `AGENTPASS_CUTOVER_ROLLBACK_ACTION_REQUIRED` and explicitly reports that schema rollback is forbidden. With a controller, it calls only `rollbackApplicationTraffic({reason})`; it never receives a database client and never exposes a down-migration operation.

## 7. Backup/restore rehearsal evidence

Backups and point-in-time recovery are controlled by the database platform, not by this CLI. Before production cutover, record a restore rehearsal that proves more than service startup:

- restore the candidate backup into an isolated PostgreSQL instance;
- run `status`, the read-only `preflight`, and `readiness` against the restored instance;
- compare row counts for the control-plane tables by approved, non-secret metrics;
- compare `admin_audit_heads`, `device_audit_heads`, open `device_audit_gaps`, bundle-head sequences, active revocation counts, and the relevant statement/event hashes;
- prove that a restored instance cannot accept a stale sequence or a replayed nonce;
- retain the backup identifier, restore timestamp, source schema version, target schema version, artifact digest, and pass/fail result without retaining connection credentials.

A restore that only answers `SELECT 1` is not sufficient evidence. If cryptographic heads or migration checksums differ, keep production traffic on the known-good path and treat the restore as failed.

## 8. Evaluation-store transition

Do not point hosted at an evaluation JSON directory and do not copy its files into PostgreSQL. Evaluation bearer records, replay cache, idempotency responses, and file-lock metadata are not production identity or authority records. There is deliberately no generic JSON-to-SQL importer.

For a transition, keep evaluation read-only, create the organization and memberships through the hosted Human API, enroll every device again so hardware identity and trust are freshly bound, recreate policies through audited hosted mutations, and verify one signed commit plus uploaded audit evidence before retiring evaluation. Historical evaluation audit data may be retained as a separately labelled evidence archive; it must not be inserted into the hosted hash chain or used to seed bundle sequence, capability, session, nonce, or WebAuthn authority. Record the evaluation snapshot digest, hosted organization ID, recreated policy versions, device enrollment evidence, and operator approval without recording bearer or enrollment credentials.

If preservation of evaluation identifiers is a hard requirement, stop the cutover and design a versioned, reviewed import contract and migration with explicit collision, actor-attribution, chain-origin, and rollback semantics. Never improvise direct SQL or edit the authority manifest to make an import appear equivalent.

## Operator failure handling

Use the JSON `code` as the automation key. Never parse human messages or print the caught exception. The safe default for any unknown code, malformed JSON, unknown flag/environment, database error, timeout, or partial output is:

1. keep existing application traffic;
2. do not apply another migration or validation attempt;
3. do not down-migrate;
4. preserve the JSON result and deployment identifier without secrets;
5. ask the database/deployment owner to investigate and rerun the read-only checks.

## 9. Least-privilege PostgreSQL roles

Before hosted cutover, apply `scripts/postgres/roles.sql` from the approved
database-admin workflow. It is idempotent and contains no password, token, or
other credential. The migration set uses the `public` schema:

- `agentpass_app` has ordinary application DML and sequence consumption, but
  no direct mutation of migration, promotion, or managed-signer authority
  ledgers. It has no schema `CREATE`, database `CREATE`/`TEMP`, object ownership,
  or migration authority.
- `agentpass_signer` has no provider-operation table or sequence privileges. It
  can execute only the reviewed provider-operation and bounded-maintenance
  functions introduced by migrations `0049` and `0050`. Until migration `0051`,
  it retains temporary direct DML on the four lifecycle/signing ledger tables.
- `agentpass_migrator` owns migration objects and has schema `CREATE`; it is
  not a superuser, createdb role, createrole role, replication role, or RLS
  bypass role.
- `agentpass_backup` has table and sequence-state `SELECT` only. It cannot
  write, execute functions, alter schema, or consume sequences.

Hosted runtime receives three distinct URLs targeting the same database:
`AGENTPASS_DATABASE_URL` for `agentpass_app`,
`AGENTPASS_MIGRATION_DATABASE_URL` for `agentpass_migrator`, and
`AGENTPASS_SIGNER_DATABASE_URL` for `agentpass_signer`. Keep all credentials in
the deployment secret manager. For the fixed privilege checker only, set
`AGENTPASS_DATABASE_URL` to the migrator identity and run it using the
deployment environment:

```sh
node scripts/postgres/role-privilege-check.mjs
```

The checker reads `AGENTPASS_DATABASE_URL`, requires exactly one URL parameter
(`sslmode=verify-full`), rejects all command-line arguments, measures
`current_user` and the effective schema/table/sequence/function privileges,
and emits only an opaque evidence digest. Run the contract test before the
cutover approval:

```sh
node --test apps/cloud-api/test/postgres/least-privilege-role-contract.test.mjs
```
