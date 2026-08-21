import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  N2_APPLICATION_VERSION,
  N2_MIGRATION_NAME,
  N2_LEGACY_TABLE_SPECS,
  N2_PLATFORM_AUTHORITY_TABLE_SPECS,
  N2_SOURCE_VERSION,
  N2_TARGET_VERSION,
  assertN2MigrationHistory,
  assertLegacyRowsPreserved,
  assertReviewedN2MigrationSet,
  buildN2UpgradePlan,
  runN2UpgradeQualification
} from "../../../../scripts/postgres/n2-upgrade-qualification.mjs";
import { loadSqlMigrations, migrationChecksum } from "../../src/postgres/migration-runner.mjs";

const SCRIPT_PATH = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../scripts/postgres/n2-upgrade-qualification.mjs");
const INTEGRATION_PATH = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "./n2-upgrade-qualification.integration.test.mjs");

function cleanSeeds() {
  return N2_PLATFORM_AUTHORITY_TABLE_SPECS.map(({ name }) => ({ name, exists: true, row_count: 0 }));
}

function cleanLegacyRows() {
  return Object.fromEntries(N2_LEGACY_TABLE_SPECS.map(({ name }, index) => [name, [{ id: `legacy-${index}` }]]));
}

test("N2 plan is exactly 51→52 and names the reviewed migration head", async () => {
  const migrations = await loadSqlMigrations();
  const plan = buildN2UpgradePlan(migrations);
  assert.equal(N2_SOURCE_VERSION, 51);
  assert.equal(N2_TARGET_VERSION, 52);
  assert.equal(N2_APPLICATION_VERSION, "n2-postgres-upgrade-qualification");
  assert.deepEqual(plan.map(({ startVersion, targetVersion }) => ({ startVersion, targetVersion })), [{ startVersion: 51, targetVersion: 52 }]);
  assert.equal(plan[0].bootstrap.at(-1).version, 51);
  assert.equal(plan[0].upgrade.at(-1).name, N2_MIGRATION_NAME);
  assert.equal(plan[0].bootstrap.length, 51);
  assert.equal(plan[0].upgrade.length, 52);
  assert.ok(migrations.slice(0, 52).every(({ sql, checksum }) => migrationChecksum(sql) === checksum));
});

test("N2 reviewed migration set rejects a missing, reordered, drifted, or wrong-headed set", async () => {
  const migrations = await loadSqlMigrations();
  assert.equal(assertReviewedN2MigrationSet(migrations), true);
  for (const mutate of [
    (value) => { value.splice(51, 1); },
    (value) => { value[50].version = 52; },
    (value) => { value[51].checksum = "0".repeat(64); },
    (value) => { value[51].name = "0052_unreviewed.sql"; }
  ]) {
    const candidate = structuredClone(migrations);
    mutate(candidate);
    assert.throws(() => assertReviewedN2MigrationSet(candidate));
  }
});

test("N2 qualification rejects non-TLS or non-migrator DSNs before opening a database", async () => {
  const databaseFactory = async () => { throw new Error("database factory must not be reached"); };
  await assert.rejects(
    () => runN2UpgradeQualification({
      adminUrl: "postgresql://postgres:secret@db.example.test/agentpass",
      migrationUrl: "postgresql://agentpass_migrator:secret@db.example.test/agentpass?sslmode=verify-full",
      databaseFactory
    }),
    /authenticated PostgreSQL TLS/u
  );
  await assert.rejects(
    () => runN2UpgradeQualification({
      adminUrl: "postgresql://postgres:secret@db.example.test/agentpass?sslmode=verify-full",
      migrationUrl: "postgresql://agentpass_app:secret@db.example.test/agentpass?sslmode=verify-full",
      databaseFactory
    }),
    /must use agentpass_migrator/u
  );
  await assert.rejects(
    () => runN2UpgradeQualification({
      adminUrl: "postgresql://agentpass_migrator:secret@db.example.test/agentpass?sslmode=verify-full",
      migrationUrl: "postgresql://agentpass_migrator:secret@db.example.test/agentpass?sslmode=verify-full",
      databaseFactory
    }),
    /must not use agentpass_migrator/u
  );
});

test("N2 history validator proves exact checksums, clean status, identity, and no implicit seeds", async () => {
  const migrations = await loadSqlMigrations();
  const rows = migrations.slice(0, 52).map(({ version, checksum }) => ({ version, checksum }));
  const result = assertN2MigrationHistory({
    rows,
    migrations,
    upgrade: { applied: [migrations[51]] },
    status: { currentVersion: 52, pending: [], modified: [], dirty: false, dirtyRows: [], applied: rows },
    identity: { session_user: "agentpass_migrator", current_user: "agentpass_migrator" },
    seedsBefore: cleanSeeds(),
    seedsAfter: cleanSeeds(),
    legacyBefore: cleanLegacyRows(),
    legacyAfter: structuredClone(cleanLegacyRows())
  });
  assert.equal(result.status, "clean");
  assert.deepEqual(result.appliedUpgradeVersions, [52]);
  assert.deepEqual(result.migration_identity, { session_user: "agentpass_migrator", current_user: "agentpass_migrator" });
  assert.equal(result.history.length, 52);
  assert.equal(result.seeded_legacy_row_count, 4);
  assert.equal(result.legacy_preservation.exact, true);
});

test("N2 history validator rejects wrong source/head, history, status, identity, or seeds", async () => {
  const migrations = await loadSqlMigrations();
  const rows = migrations.slice(0, 52).map(({ version, checksum }) => ({ version, checksum }));
  const base = {
    rows,
    migrations,
    upgrade: { applied: [migrations[51]] },
    status: { currentVersion: 52, pending: [], modified: [], dirty: false, dirtyRows: [], applied: rows },
    identity: { session_user: "agentpass_migrator", current_user: "agentpass_migrator" },
    seedsBefore: cleanSeeds(),
    seedsAfter: cleanSeeds(),
    legacyBefore: cleanLegacyRows(),
    legacyAfter: structuredClone(cleanLegacyRows())
  };
  for (const mutate of [
    (value) => { value.startVersion = 50; },
    (value) => { value.targetVersion = 51; },
    (value) => { value.rows[51].checksum = "0".repeat(64); },
    (value) => { value.rows.splice(20, 1); },
    (value) => { value.upgrade.applied = []; },
    (value) => { value.status.pending = [52]; },
    (value) => { value.status.dirty = true; },
    (value) => { value.identity.current_user = "postgres"; },
    (value) => { value.seedsAfter[0].row_count = 1; }
  ]) {
    const candidate = structuredClone(base);
    mutate(candidate);
    assert.throws(() => assertN2MigrationHistory(candidate));
  }
  const changedLegacy = cleanLegacyRows();
  changedLegacy.memberships[0].id = "changed";
  assert.throws(() => assertLegacyRowsPreserved(cleanLegacyRows(), changedLegacy));
});

test("N2 qualification script and integration gate expose only the reviewed CI contract", async () => {
  const source = await readFile(SCRIPT_PATH, "utf8");
  assert.match(source, /createMigrationRunner/);
  assert.match(source, /loadSqlMigrations/);
  assert.match(source, /createDisposablePostgres/);
  assert.match(source, /agentpass_migrator/);
  assert.match(source, /schema_migrations/);
  assert.match(source, /migrationChecksum/);
  assert.match(source, /databaseName: `agentpass_n2_from_\$\{scenario\.startVersion\}`/);
  assert.match(source, /AGENTPASS_N2_POSTGRES_ADMIN_URL/);
  assert.match(source, /AGENTPASS_N2_POSTGRES_MIGRATION_URL/);
  assert.doesNotMatch(source, /\.github\/workflows/u);
  const integration = await readFile(INTEGRATION_PATH, "utf8");
  assert.match(integration, /const ADMIN_DATABASE_URL = process\.env\.AGENTPASS_N2_POSTGRES_ADMIN_URL \?\? process\.env\.AGENTPASS_TEST_POSTGRES_ADMIN_URL/u);
  assert.match(integration, /const MIGRATION_DATABASE_URL = process\.env\.AGENTPASS_N2_POSTGRES_MIGRATION_URL \?\? process\.env\.AGENTPASS_TEST_MIGRATION_DATABASE_URL/u);
  assert.match(integration, /skip: ADMIN_DATABASE_URL && MIGRATION_DATABASE_URL \? false :/u);
  assert.doesNotMatch(integration, /t\.skip\(|P0BSkip|postgres_unavailable|external_disabled/u);
});
