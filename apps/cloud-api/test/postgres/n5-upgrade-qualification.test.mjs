import assert from "node:assert/strict";
import test from "node:test";

import {
  N5_MIGRATION_NAME,
  N5_TARGET_VERSION,
  assertN5MigrationHistory,
  assertReviewedN5MigrationSet,
  runN5UpgradeQualification
} from "../../../../scripts/postgres/n5-upgrade-qualification.mjs";
import { loadSqlMigrations } from "../../src/postgres/migration-runner.mjs";

function history(migrations) {
  return migrations.slice(0, N5_TARGET_VERSION).map(({ version, checksum }) => ({ version, checksum }));
}

function status(rows) {
  return { currentVersion: N5_TARGET_VERSION, pending: [], modified: [], dirty: false, dirtyRows: [], applied: rows };
}

test("N5 reviewed migration set rejects missing, reordered, drifted, and wrong-headed history", async () => {
  const migrations = await loadSqlMigrations();
  assert.equal(assertReviewedN5MigrationSet(migrations), true);
  for (const mutate of [
    (value) => { value.splice(54, 1); },
    (value) => { value[53].version = 55; },
    (value) => { value[54].checksum = "0".repeat(64); },
    (value) => { value[54].name = "0055_unreviewed.sql"; },
    (value) => { value[53].name = "0053_wrong-source.sql"; }
  ]) {
    const candidate = structuredClone(migrations);
    mutate(candidate);
    assert.throws(() => assertReviewedN5MigrationSet(candidate));
  }
});

test("N5 history validator proves exact fresh/upgrade history, identity, and clean status", async () => {
  const migrations = await loadSqlMigrations();
  const rows = history(migrations);
  const result = assertN5MigrationHistory({
    migrations,
    bootstrap: { currentVersion: 54, applied: rows.slice(0, 54) },
    upgrade: { currentVersion: 55, applied: [migrations[54]] },
    fresh: { currentVersion: 55, applied: rows },
    upgradeRows: rows,
    freshRows: rows,
    upgradeStatus: status(rows),
    freshStatus: status(rows),
    upgradeIdentity: { session_user: "agentpass_migrator", current_user: "agentpass_migrator" },
    freshIdentity: { session_user: "agentpass_migrator", current_user: "agentpass_migrator" }
  });
  assert.equal(result.status, "clean");
  assert.equal(result.sourceVersion, 54);
  assert.equal(result.targetVersion, 55);
  assert.equal(result.migrationName, N5_MIGRATION_NAME);
  assert.match(result.migrationChecksum, /^[0-9a-f]{64}$/u);
  assert.deepEqual(result.appliedUpgradeVersions, [55]);
  assert.equal(result.historyRows, 55);
});

test("N5 validator rejects history, identity, path, and clean-status drift", async () => {
  const migrations = await loadSqlMigrations();
  const rows = history(migrations);
  const base = {
    migrations,
    bootstrap: { currentVersion: 54, applied: rows.slice(0, 54) },
    upgrade: { currentVersion: 55, applied: [migrations[54]] },
    fresh: { currentVersion: 55, applied: rows },
    upgradeRows: rows,
    freshRows: rows,
    upgradeStatus: status(rows),
    freshStatus: status(rows),
    upgradeIdentity: { session_user: "agentpass_migrator", current_user: "agentpass_migrator" },
    freshIdentity: { session_user: "agentpass_migrator", current_user: "agentpass_migrator" }
  };
  for (const mutate of [
    (value) => { value.sourceVersion = 53; },
    (value) => { value.targetVersion = 54; },
    (value) => { value.upgrade.applied = []; },
    (value) => { value.fresh.applied = rows.slice(0, 54); },
    (value) => { value.upgradeRows[54].checksum = "0".repeat(64); },
    (value) => { value.upgradeStatus.pending = [55]; },
    (value) => { value.freshStatus.dirty = true; },
    (value) => { value.upgradeIdentity.current_user = "postgres"; }
  ]) {
    const candidate = structuredClone(base);
    mutate(candidate);
    assert.throws(() => assertN5MigrationHistory(candidate));
  }
});

test("N5 qualification rejects non-TLS, non-admin, or non-migrator DSNs before opening a database", async () => {
  const databaseFactory = async () => { throw new Error("database factory must not be reached"); };
  await assert.rejects(
    () => runN5UpgradeQualification({
      adminUrl: "postgresql://postgres:secret@db.example.test/agentpass",
      migrationUrl: "postgresql://agentpass_migrator:secret@db.example.test/agentpass?sslmode=verify-full",
      databaseFactory
    }),
    /authenticated PostgreSQL TLS/u
  );
  await assert.rejects(
    () => runN5UpgradeQualification({
      adminUrl: "postgresql://postgres:secret@db.example.test/agentpass?sslmode=verify-full",
      migrationUrl: "postgresql://agentpass_app:secret@db.example.test/agentpass?sslmode=verify-full",
      databaseFactory
    }),
    /must use agentpass_migrator/u
  );
  await assert.rejects(
    () => runN5UpgradeQualification({
      adminUrl: "postgresql://agentpass_migrator:secret@db.example.test/agentpass?sslmode=verify-full",
      migrationUrl: "postgresql://agentpass_migrator:secret@db.example.test/agentpass?sslmode=verify-full",
      databaseFactory
    }),
    /must not use agentpass_migrator/u
  );
});
