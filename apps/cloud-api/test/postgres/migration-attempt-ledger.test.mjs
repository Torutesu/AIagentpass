import assert from "node:assert/strict";
import test from "node:test";

import {
  MigrationDirtyError,
  migrationChecksum,
  runMigrations
} from "../../src/postgres/migration-runner.mjs";

const SQL_ONE = "CREATE TABLE example_one (id integer);";
const SQL_TWO = "CREATE TABLE example_two (id integer);";
const SQL_THREE = "CREATE TABLE example_three (id integer);";
const MIGRATIONS = [
  migration("0001_example_one.sql", SQL_ONE),
  migration("0002_example_two.sql", SQL_TWO),
  migration("0003_example_three.sql", SQL_THREE)
];
const APPLIED = MIGRATIONS.slice(0, 2).map(({ sql }, index) => ({ version: index + 1, checksum: migrationChecksum(sql) }));

test("persists a running attempt before SQL and marks it applied after commit", async () => {
  const state = createState();
  const client = new AttemptLedgerClient(state);

  const result = await runMigrations({ client, migrations: MIGRATIONS, applicationVersion: "ledger-success" });

  assert.deepEqual(result.applied.map(({ version }) => version), [3]);
  assert.deepEqual(state.applied.map(({ version }) => version), [1, 2, 3]);
  assert.equal(state.attempts.length, 1);
  assert.equal(state.attempts[0].status, "applied");
  assert.equal(state.attempts[0].version, 3);
  assert.equal(state.attempts[0].error_code, null);
  assert.ok(state.attempts[0].finished_at);
  assert.equal(client.sqlStartedBeforeRunning, false);

  const rerun = await runMigrations({ client: new AttemptLedgerClient(state), migrations: MIGRATIONS, applicationVersion: "ledger-success" });
  assert.deepEqual(rerun.applied, []);
  assert.equal(state.attempts.length, 1, "completed attempts are not duplicated on an idempotent rerun");
});

test("records a failed attempt with only a bounded error code and fails closed on restart", async () => {
  const state = createState();
  const client = new AttemptLedgerClient(state, { failMigration: true });

  await assert.rejects(
    runMigrations({ client, migrations: MIGRATIONS, applicationVersion: "ledger-failure" }),
    (error) => error.code === "ERR_MIGRATION_FAILED"
  );

  assert.equal(state.applied.length, 2, "failed migration SQL is rolled back");
  assert.equal(state.attempts.length, 1);
  assert.equal(state.attempts[0].status, "failed");
  assert.equal(state.attempts[0].error_code, "ERR_MIGRATION_FAILED");
  assert.ok(state.attempts[0].finished_at);
  assert.equal(Object.hasOwn(state.attempts[0], "message"), false);
  assert.equal(Object.hasOwn(state.attempts[0], "stack"), false);
  assert.doesNotMatch(JSON.stringify(state.attempts[0]), /do-not-persist-this-secret/u);

  await assert.rejects(
    runMigrations({ client: new AttemptLedgerClient(state), migrations: MIGRATIONS, applicationVersion: "ledger-restart" }),
    MigrationDirtyError
  );
});

test("leaves a durable running attempt when process loss prevents failure recording", async () => {
  const state = createState();
  const client = new AttemptLedgerClient(state, { failMigration: true, failAttemptUpdate: true });

  await assert.rejects(
    runMigrations({ client, migrations: MIGRATIONS, applicationVersion: "ledger-process-loss" }),
    (error) => error.code === "ERR_MIGRATION_ATTEMPT_RECORD"
  );

  assert.equal(state.applied.length, 2);
  assert.equal(state.attempts.length, 1);
  assert.equal(state.attempts[0].status, "running", "the committed running row survives the lost process boundary");
  assert.equal(state.attempts[0].error_code, null);

  await assert.rejects(
    runMigrations({ client: new AttemptLedgerClient(state), migrations: MIGRATIONS, applicationVersion: "ledger-restart" }),
    MigrationDirtyError
  );
});

class AttemptLedgerClient {
  constructor(state, { failMigration = false, failAttemptUpdate = false } = {}) {
    this.state = state;
    this.failMigration = failMigration;
    this.failAttemptUpdate = failAttemptUpdate;
    this.inTransaction = false;
    this.snapshot = null;
    this.sqlStartedBeforeRunning = false;
  }

  async query(text, params = []) {
    if (text === "BEGIN") {
      this.inTransaction = true;
      this.snapshot = cloneState(this.state);
      return result();
    }
    if (text === "COMMIT") {
      this.inTransaction = false;
      this.snapshot = null;
      return result();
    }
    if (text === "ROLLBACK") {
      if (this.snapshot) Object.assign(this.state, cloneState(this.snapshot));
      this.inTransaction = false;
      this.snapshot = null;
      return result();
    }
    if (text.startsWith("SELECT pg_advisory_xact_lock")) return { rows: [{ locked: true }], rowCount: 1 };
    if (text === "SELECT to_regclass($1) AS relation") return { rows: [{ relation: params[0] }], rowCount: 1 };
    if (text.startsWith("SELECT version, checksum FROM schema_migrations")) return { rows: clone(this.state.applied), rowCount: this.state.applied.length };
    if (text.startsWith("SELECT version, checksum, status, finished_at FROM schema_migration_attempts")) {
      const rows = this.state.attempts
        .filter((attempt) => attempt.status === "running" || attempt.status === "failed")
        .map(({ version, checksum, status, finished_at }) => ({ version, checksum, status, finished_at }));
      return { rows, rowCount: rows.length };
    }
    if (text.startsWith("INSERT INTO schema_migration_attempts")) {
      this.state.attempts.push({
        id: params[0],
        version: params[1],
        checksum: params[2],
        application_version: params[3],
        status: "running",
        started_at: "started",
        finished_at: null,
        error_code: null
      });
      return result(1);
    }
    if (text.startsWith("UPDATE schema_migration_attempts")) {
      if (this.failAttemptUpdate) throw Object.assign(new Error("connection lost after process termination"), { code: "ECONNRESET" });
      const attempt = this.state.attempts.find((candidate) => candidate.id === params[0] && candidate.status === "running");
      if (!attempt) return result(0);
      attempt.status = text.includes("status='applied'") ? "applied" : "failed";
      attempt.finished_at = "finished";
      attempt.error_code = attempt.status === "failed" ? params[1] : null;
      return result(1);
    }
    if (text.startsWith("INSERT INTO schema_migrations")) {
      this.state.applied.push({ version: params[0], checksum: params[1] });
      return result(1);
    }
    if (text.startsWith("CREATE TABLE") && this.failMigration) {
      this.sqlStartedBeforeRunning = this.state.attempts.every((attempt) => attempt.status !== "running");
      throw Object.assign(new Error("do-not-persist-this-secret"), { code: "ERR_TEST_MIGRATION_FAILURE" });
    }
    if (text.startsWith("CREATE TABLE")) return result();
    return result();
  }
}

function migration(name, sql) {
  return { name, sql };
}

function createState() {
  return { applied: clone(APPLIED), attempts: [] };
}

function clone(value) {
  return structuredClone(value);
}

function cloneState(state) {
  return clone(state);
}

function result(rowCount = 0) {
  return { rows: [], rowCount };
}
