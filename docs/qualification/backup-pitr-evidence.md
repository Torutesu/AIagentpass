# Backup/PITR evidence producer

`scripts/qualification/backup-pitr-evidence.mjs` is a fail-closed producer for
the protected PostgreSQL backup/restore and point-in-time-recovery evidence
consumed by the C3 qualification. Its `run` command performs a fixed
`pg_dump` -> `pg_restore` -> PostgreSQL probe sequence and independently
probes an isolated PITR target for WAL replay. It never accepts a CI result as
proof, and it creates no passing evidence unless all fixed commands complete
against real PostgreSQL endpoints.

The restore and PITR databases must be disposable, isolated targets prepared
by the operator or managed PostgreSQL provider. The runner does not create,
drop, or expose a production database. The PITR target must be the actual
PostgreSQL endpoint recovered to the selected restore point; the runner checks
that it reports a replayed WAL LSN and is either still recovering or promoted.

## Input boundary (`build` mode)

The input is a canonical JSON file with mode `0600`, one hard link, and no
symlink. Its top-level `kind` is
`agentpass-backup-pitr-execution-result`; it contains the exact source
commit/tree, CI run ID/attempt, job ID, artifact SHA-256, millisecond UTC
start/completion timestamps, `execution.real_execution: true`, an external
runner ID, and a `verification` block produced from three distinct live
PostgreSQL endpoints (`source`, `restore`, and `pitr`). Each endpoint must
report the exact local schema head over TLS as `agentpass_backup`, with
`read_only: true` and `dml_denied: true`. The `restore` and `pitr` endpoint
identity digests must differ. The block also contains a digest of a non-null
`pg_last_wal_replay_lsn()` and its recovery state. The two typed checks remain:

```json
{
  "backup_restore": { "expected": "passed", "observed": "passed", "status": "passed" },
  "pitr_recovery": { "expected": "passed", "observed": "passed", "status": "passed" }
}
```

The input is a typed projection, not a raw command log. Database URLs,
passwords, tokens, credentials, provider responses, stdout/stderr, and unknown
fields are rejected. The producer never copies input fields into the output;
it projects only the fixed redacted evidence keys. Failed or `not_run` checks
do not produce a passing evidence file.

## Build and verify

The expected binding must come from the protected runner environment or be
provided explicitly. All six binding values are required; values asserted only
inside the input result are not sufficient.

```sh
node scripts/qualification/backup-pitr-evidence.mjs build \
  /absolute/path/execution-result.json \
  /absolute/path/backup-pitr.json \
  --source-commit <40-hex-sha> \
  --source-tree <40-hex-tree-sha> \
  --run-id <positive-run-id> \
  --run-attempt <positive-attempt> \
  --job-id <job-id> \
  --artifact-sha256 <64-hex-digest>

node scripts/qualification/backup-pitr-evidence.mjs verify \
  /absolute/path/backup-pitr.json \
  --source-commit <40-hex-sha> \
  --source-tree <40-hex-tree-sha> \
  --run-id <positive-run-id> \
  --run-attempt <positive-attempt> \
  --job-id <job-id> \
  --artifact-sha256 <64-hex-digest>
```

The equivalent environment variables are
`AGENTPASS_BACKUP_PITR_SOURCE_COMMIT`,
`AGENTPASS_BACKUP_PITR_SOURCE_TREE`,
`AGENTPASS_BACKUP_PITR_CI_RUN_ID`,
`AGENTPASS_BACKUP_PITR_CI_RUN_ATTEMPT`,
`AGENTPASS_BACKUP_PITR_CI_JOB_ID`, and
`AGENTPASS_BACKUP_PITR_ARTIFACT_SHA256`. GitHub run ID, attempt, and job are
used only as fallbacks for the corresponding CI values.

The output is canonical JSON followed by one LF and mode `0600`. It is created
with exclusive creation, so an existing path is never overwritten. The output
is a regular single-link file and contains only the fixed redacted envelope:
`schema_version`, `redacted`, source/tree/run/attempt/job/artifact binding, and
the two typed checks with recomputable SHA-256 digests.

Passing the focused tests proves the producer's local contract, including
secret-field rejection, binding substitution, canonical encoding, and file
identity checks. It does not prove that a real PostgreSQL backup, restore, PITR,
external runner, CI run, artifact, or source-tree lookup occurred. Those are
separate protected external gates and must be independently verified.

## Protected-runner preflight

Run the PostgreSQL environment preflight before starting `pg_dump`,
`pg_restore`, or `psql`:

```sh
node scripts/postgres/require-live-qualification-env.mjs
```

The preflight is configuration-only: it does not load a PostgreSQL client,
open a socket, run a database command, or claim that a database was reached.
It requires all three endpoint URLs (`AGENTPASS_DATABASE_URL`,
`AGENTPASS_BACKUP_PITR_RESTORE_DATABASE_URL`, and
`AGENTPASS_BACKUP_PITR_PITR_DATABASE_URL`) to use exactly one query parameter,
`sslmode=verify-full`. The endpoint identities are compared without retaining
usernames or passwords; source, restore, and PITR must all be distinct.

It also requires an absolute, readable, regular CA file with one link and no
group/other permission bits; the two exact
`isolated-disposable` confirmations; a runner ID beginning with
`protected-postgresql/`; and explicit source commit, source tree, CI run ID,
run attempt, job ID, and artifact SHA-256 bindings. It never falls back to a
local/test DSN or a GitHub value for these protected bindings. If any required
value is absent or invalid, it emits only
`{"status":"not_proven","reason":"<stable-code>"}` and exits nonzero;
URLs, credentials, CA paths, and filesystem/provider error text are not
printed.

If any `AGENTPASS_TEST_*` role DSN is supplied, the complete existing
role-profile set is validated as well. Omitting that optional profile is the
recommended configuration for the isolated backup/PITR job.

## Real backup/restore/PITR run

For a protected run, provide the source, disposable restore target, and
already-recovered isolated PITR target through environment variables. URLs are
accepted only from the environment, must use exactly `sslmode=verify-full`,
and are converted to PostgreSQL `PG*` variables before invoking the fixed
utilities; no URL is passed as a command argument or copied into evidence.
The CA file must be an absolute, regular, non-world-writable file.

The two confirmations are deliberate operator acknowledgements that the
targets are isolated and disposable. Without them, the runner fails before
starting a database command.

```sh
export AGENTPASS_DATABASE_URL='postgresql://...?...sslmode=verify-full'
export AGENTPASS_BACKUP_PITR_RESTORE_DATABASE_URL='postgresql://...?...sslmode=verify-full'
export AGENTPASS_BACKUP_PITR_PITR_DATABASE_URL='postgresql://...?...sslmode=verify-full'
export AGENTPASS_BACKUP_PITR_CA_CERT_FILE='/secure/qualification/postgres-ca.pem'
export AGENTPASS_BACKUP_PITR_RESTORE_CONFIRMATION='isolated-disposable'
export AGENTPASS_BACKUP_PITR_PITR_CONFIRMATION='isolated-disposable'
export AGENTPASS_BACKUP_PITR_RUNNER_ID='protected-postgresql/backup-pitr'

node scripts/qualification/backup-pitr-evidence.mjs run \
  /secure/qualification/backup-pitr.json \
  --source-commit <40-hex-sha> \
  --source-tree <40-hex-tree-sha> \
  --run-id <positive-run-id> \
  --run-attempt <positive-attempt> \
  --job-id <job-id> \
  --artifact-sha256 <64-hex-digest>
```

The command uses only `pg_dump`, `pg_restore`, and `psql` with fixed arguments,
`shell: false`, bounded execution time, and discarded stdout/stderr. It runs a
schema/role probe against source, restore, and PITR, then a separate WAL probe
against PITR. The dump and probe files are private temporary files and are
removed on every exit. The role probe requires the exact schema head, TLS,
`agentpass_backup`, no DML privilege, and read-only database/schema access.
The WAL probe requires a non-null `pg_last_wal_replay_lsn()` and accepts either
`pg_is_in_recovery()` state, because providers differ on whether a recovered
target is left in recovery or promoted. Only SHA-256 digests of instance
identity, role evidence, and replay LSN are retained; raw probe output is never
written to evidence or stdout.

If PostgreSQL utilities, TLS, credentials, target isolation, backup, restore,
or WAL replay is unavailable, the command exits non-zero and does not create
an evidence file. It never emits a synthetic `not_run` or passing result.
