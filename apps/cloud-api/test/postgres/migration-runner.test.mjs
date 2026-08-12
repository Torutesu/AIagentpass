import assert from "node:assert/strict";
import test from "node:test";

import {
  MigrationChecksumError,
  MigrationDirtyError,
  MigrationRunnerError,
  createMigrationRunner,
  defaultContractDirectory,
  loadSqlMigrations,
  migrationChecksum,
  runMigrations,
  stripTransactionEnvelope
} from "../../src/postgres/index.mjs";
import { FakePgClient } from "./fake-client.mjs";

const SQL_ONE = "BEGIN;\nCREATE TABLE example_one (id integer);\nCOMMIT;\n";
const SQL_TWO = "BEGIN;\nCREATE TABLE example_two (id integer);\nCOMMIT;\n";
const migrations = [
  { name: "0001_example_one.sql", sql: SQL_ONE },
  { name: "0002_example_two.sql", sql: SQL_TWO }
];

test("runs ordered migrations under one advisory-locked transaction and records exact checksums", async () => {
  const client = new FakePgClient({ schemaMigrationsExists: false });
  const result = await runMigrations({ client, migrations, applicationVersion: "test-1" });
  assert.deepEqual(result.applied.map(({ version, checksum }) => ({ version, checksum })), [
    { version: 1, checksum: migrationChecksum(SQL_ONE) },
    { version: 2, checksum: migrationChecksum(SQL_TWO) }
  ]);
  assert.equal(result.currentVersion, 2);
  assert.equal(client.calls[0].text, "BEGIN");
  assert.match(client.calls[1].text, /pg_advisory_xact_lock/);
  assert.deepEqual(client.calls.at(-1), { text: "COMMIT", params: [] });
  assert.equal(client.calls.filter(({ text }) => text.startsWith("CREATE TABLE")).length, 2);
  assert.deepEqual(client.calls.filter(({ text }) => text.startsWith("INSERT INTO schema_migrations")).map(({ params }) => params[2] ?? "legacy"), ["legacy", "test-1"]);
  assert.ok(client.calls.every(({ params }) => Array.isArray(params)), "every injected query receives params");
});

test("is idempotent for an unchanged history", async () => {
  const client = new FakePgClient({ applied: migrations.map((migration, index) => ({ version: index + 1, checksum: migrationChecksum(migration.sql) })) });
  const result = await runMigrations({ client, migrations });
  assert.deepEqual(result.applied, []);
  assert.equal(client.calls.filter(({ text }) => text.startsWith("CREATE TABLE")).length, 0);
});

test("fails closed on checksum drift and rolls back", async () => {
  const client = new FakePgClient({ applied: [{ version: 1, checksum: "a".repeat(64) }] });
  await assert.rejects(runMigrations({ client, migrations }), MigrationChecksumError);
  assert.equal(client.calls.at(-1).text, "ROLLBACK");
  assert.equal(client.calls.some(({ text }) => text.startsWith("CREATE TABLE")), false);
});

test("fails closed when migration attempts report dirty state", async () => {
  const client = new FakePgClient({ migrationAttemptsExists: true, dirty: [{ version: 1, checksum: migrationChecksum(SQL_ONE), status: "failed", finished_at: "now" }] });
  await assert.rejects(runMigrations({ client, migrations }), MigrationDirtyError);
  assert.equal(client.calls.at(-1).text, "ROLLBACK");
});

test("fails closed on an unknown or out-of-order applied version", async () => {
  const client = new FakePgClient({ applied: [{ version: 3, checksum: "b".repeat(64) }] });
  await assert.rejects(runMigrations({ client, migrations }), (error) => error.code === "ERR_MIGRATION_HISTORY");
  assert.equal(client.calls.at(-1).text, "ROLLBACK");
});

test("loads the reviewed contract migrations in contiguous order without rewriting their SQL", async () => {
  const loaded = await loadSqlMigrations(defaultContractDirectory());
  assert.deepEqual(loaded.map((migration) => migration.name), ["0001_control_plane.sql", "0002_webauthn_challenges.sql", "0003_webauthn_challenge_bindings.sql"]);
  assert.match(loaded[0].sql, /^BEGIN;/);
  assert.match(loaded[0].sql, /CREATE TABLE schema_migrations/);
  assert.match(loaded[0].sql.trim(), /COMMIT;$/);
});

test("fails closed when the database skips a migration version", async () => {
  const client = new FakePgClient({ applied: [{ version: 2, checksum: migrationChecksum(SQL_TWO) }] });
  await assert.rejects(runMigrations({ client, migrations }), (error) => error.code === "ERR_MIGRATION_HISTORY");
  assert.equal(client.calls.at(-1).text, "ROLLBACK");
});

test("rolls back a failed migration and does not leave an applied row", async () => {
  const client = new FakePgClient({ schemaMigrationsExists: false, failWhen: (text) => text.includes("example_two") ? new Error("statement failed") : undefined });
  await assert.rejects(runMigrations({ client, migrations }), (error) => error.code === "ERR_MIGRATION_FAILED");
  assert.deepEqual(client.applied, []);
  assert.equal(client.calls.at(-1).text, "ROLLBACK");
});

test("serializes concurrent calls on one runner", async () => {
  const client = new FakePgClient({ schemaMigrationsExists: false });
  const runner = createMigrationRunner({ client, migrations });
  const [first, second] = await Promise.all([runner.run(), runner.run()]);
  assert.deepEqual(first.applied.map((item) => item.version), [1, 2]);
  assert.deepEqual(second.applied.map((item) => item.version), [1, 2]);
  assert.equal(client.calls.filter(({ text }) => text === "BEGIN").length, 1);
});

test("removes only the outer transaction envelope", () => {
  assert.equal(stripTransactionEnvelope(SQL_ONE), "CREATE TABLE example_one (id integer);");
  assert.throws(() => stripTransactionEnvelope("BEGIN; SELECT 1; ROLLBACK; COMMIT;"), MigrationRunnerError);
});
