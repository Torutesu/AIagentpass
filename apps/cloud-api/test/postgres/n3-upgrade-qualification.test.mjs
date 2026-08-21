import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  N3_APPLICATION_VERSION,
  N3_MIGRATION_NAME,
  N3_LEGACY_TABLE_SPECS,
  N3_PLATFORM_AUTHORITY_TABLE_SPECS,
  N3_SOURCE_VERSION,
  N3_TARGET_VERSION,
  assertN3MigrationHistory,
  assertLegacyRowsPreserved,
  assertNoImplicitPlatformSessionSeeds,
  assertPlatformAuthorityRowsPreserved,
  assertReviewedN3MigrationSet,
  buildN3UpgradePlan,
  runN3UpgradeQualification
} from "../../../../scripts/postgres/n3-upgrade-qualification.mjs";
import { loadSqlMigrations, migrationChecksum } from "../../src/postgres/migration-runner.mjs";

const SCRIPT_PATH = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../scripts/postgres/n3-upgrade-qualification.mjs");
const INTEGRATION_PATH = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "./n3-upgrade-qualification.integration.test.mjs");

function cleanAuthority() {
  return {
    platform_principals: [{ principal_id: "principal" }, { principal_id: "approver" }],
    platform_operator_assignments: [{ assignment_id: "assignment" }],
    platform_operator_assignment_approvals: [{ approval_id: "approval" }]
  };
}

function cleanLegacy() {
  return Object.fromEntries(N3_LEGACY_TABLE_SPECS.map(({ name, orderBy }, index) => [
    name,
    Array.from({ length: name === "members" ? 2 : 1 }, (_, row) => ({ id: `${name}-${index}-${row}-${orderBy}` }))
  ]));
}

function cleanSessions() {
  return [
    { name: "platform_credentials", exists: false, row_count: 0 },
    { name: "platform_sessions", exists: false, row_count: 0 }
  ];
}

test("N3 plan is exactly 52→53 and names the reviewed migration head", async () => {
  const migrations = await loadSqlMigrations();
  const plan = buildN3UpgradePlan(migrations);
  assert.equal(N3_SOURCE_VERSION, 52);
  assert.equal(N3_TARGET_VERSION, 53);
  assert.equal(N3_APPLICATION_VERSION, "n3-postgres-upgrade-qualification");
  assert.deepEqual(plan.map(({ startVersion, targetVersion }) => ({ startVersion, targetVersion })), [{ startVersion: 52, targetVersion: 53 }]);
  assert.equal(plan[0].bootstrap.at(-1).version, 52);
  assert.equal(plan[0].upgrade.at(-1).name, N3_MIGRATION_NAME);
  assert.equal(plan[0].bootstrap.length, 52);
  assert.equal(plan[0].upgrade.length, 53);
  assert.ok(migrations.slice(0, 53).every(({ sql, checksum }) => migrationChecksum(sql) === checksum));
});

test("N3 reviewed migration set rejects missing, reordered, drifted, and wrong-headed history", async () => {
  const migrations = await loadSqlMigrations();
  assert.equal(assertReviewedN3MigrationSet(migrations), true);
  for (const mutate of [
    (value) => { value.splice(52, 1); },
    (value) => { value[51].version = 53; },
    (value) => { value[52].checksum = "0".repeat(64); },
    (value) => { value[52].name = "0053_unreviewed.sql"; }
  ]) {
    const candidate = structuredClone(migrations);
    mutate(candidate);
    assert.throws(() => assertReviewedN3MigrationSet(candidate));
  }
});

test("N3 qualification rejects non-TLS, non-admin, or non-migrator DSNs before opening a database", async () => {
  const databaseFactory = async () => { throw new Error("database factory must not be reached"); };
  await assert.rejects(
    () => runN3UpgradeQualification({
      adminUrl: "postgresql://postgres:secret@db.example.test/agentpass",
      migrationUrl: "postgresql://agentpass_migrator:secret@db.example.test/agentpass?sslmode=verify-full",
      databaseFactory
    }),
    /authenticated PostgreSQL TLS/u
  );
  await assert.rejects(
    () => runN3UpgradeQualification({
      adminUrl: "postgresql://postgres:secret@db.example.test/agentpass?sslmode=verify-full",
      migrationUrl: "postgresql://agentpass_app:secret@db.example.test/agentpass?sslmode=verify-full",
      databaseFactory
    }),
    /must use agentpass_migrator/u
  );
  await assert.rejects(
    () => runN3UpgradeQualification({
      adminUrl: "postgresql://agentpass_migrator:secret@db.example.test/agentpass?sslmode=verify-full",
      migrationUrl: "postgresql://agentpass_migrator:secret@db.example.test/agentpass?sslmode=verify-full",
      databaseFactory
    }),
    /must not use agentpass_migrator/u
  );
});

test("N3 history validator proves exact checksums, identity, preservation, and seed absence", async () => {
  const migrations = await loadSqlMigrations();
  const rows = migrations.slice(0, 53).map(({ version, checksum }) => ({ version, checksum }));
  const authority = cleanAuthority();
  const legacy = cleanLegacy();
  const result = assertN3MigrationHistory({
    rows,
    migrations,
    upgrade: { applied: [migrations[52]] },
    status: { currentVersion: 53, pending: [], modified: [], dirty: false, dirtyRows: [], applied: rows },
    identity: { session_user: "agentpass_migrator", current_user: "agentpass_migrator" },
    authorityBefore: authority,
    authorityAfter: structuredClone(authority),
    sessionsBefore: cleanSessions(),
    sessionsAfter: [
      { name: "platform_credentials", exists: true, row_count: 0 },
      { name: "platform_sessions", exists: true, row_count: 0 }
    ],
    legacyBefore: legacy,
    legacyAfter: structuredClone(legacy)
  });
  assert.equal(result.status, "clean");
  assert.deepEqual(result.appliedUpgradeVersions, [53]);
  assert.equal(result.history.length, 53);
  assert.equal(result.seeded_legacy_row_count, 5);
  assert.equal(result.platform_authority_preservation.exact, true);
  assert.equal(result.legacy_preservation.exact, true);
});

test("N3 validators reject history, identity, preservation, and implicit session seeds", async () => {
  const migrations = await loadSqlMigrations();
  const rows = migrations.slice(0, 53).map(({ version, checksum }) => ({ version, checksum }));
  const authority = cleanAuthority();
  const legacy = cleanLegacy();
  const base = {
    rows,
    migrations,
    upgrade: { applied: [migrations[52]] },
    status: { currentVersion: 53, pending: [], modified: [], dirty: false, dirtyRows: [], applied: rows },
    identity: { session_user: "agentpass_migrator", current_user: "agentpass_migrator" },
    authorityBefore: authority,
    authorityAfter: structuredClone(authority),
    sessionsBefore: cleanSessions(),
    sessionsAfter: [{ name: "platform_credentials", exists: true, row_count: 0 }, { name: "platform_sessions", exists: true, row_count: 0 }],
    legacyBefore: legacy,
    legacyAfter: structuredClone(legacy)
  };
  for (const mutate of [
    (value) => { value.startVersion = 51; },
    (value) => { value.targetVersion = 52; },
    (value) => { value.rows[52].checksum = "0".repeat(64); },
    (value) => { value.upgrade.applied = []; },
    (value) => { value.status.pending = [53]; },
    (value) => { value.identity.current_user = "postgres"; },
    (value) => { value.authorityAfter.platform_principals[0].principal_id = "changed"; },
    (value) => { value.legacyAfter.members[0].id = "changed"; },
    (value) => { value.sessionsAfter[1].row_count = 1; }
  ]) {
    const candidate = structuredClone(base);
    mutate(candidate);
    assert.throws(() => assertN3MigrationHistory(candidate));
  }
  assert.throws(() => assertLegacyRowsPreserved(legacy, { ...legacy, members: [{ id: "changed" }] }));
  assert.throws(() => assertPlatformAuthorityRowsPreserved(authority, { ...authority, platform_principals: [] }));
  assert.throws(() => assertNoImplicitPlatformSessionSeeds([{ name: "platform_sessions", exists: true, row_count: 1 }, { name: "platform_credentials", exists: true, row_count: 0 }], "post-upgrade"));
});

test("N3 qualification script and integration gate expose only the reviewed CI contract", async () => {
  const source = await readFile(SCRIPT_PATH, "utf8");
  assert.match(source, /createMigrationRunner/u);
  assert.match(source, /loadSqlMigrations/u);
  assert.match(source, /createDisposablePostgres/u);
  assert.match(source, /agentpass_migrator/u);
  assert.match(source, /schema_migrations/u);
  assert.match(source, /migrationChecksum/u);
  assert.match(source, /databaseName: `agentpass_n3_from_\$\{scenario\.startVersion\}`/u);
  assert.match(source, /AGENTPASS_N3_POSTGRES_ADMIN_URL/u);
  assert.match(source, /AGENTPASS_N3_POSTGRES_MIGRATION_URL/u);
  assert.match(source, /platform_operator_assignment_approvals/u);
  assert.match(source, /platform_credentials/u);
  assert.match(source, /platform_sessions/u);
  assert.doesNotMatch(source, /\.github\/workflows/u);
  const integration = await readFile(INTEGRATION_PATH, "utf8");
  assert.match(integration, /const ADMIN_DATABASE_URL = process\.env\.AGENTPASS_N3_POSTGRES_ADMIN_URL \?\? process\.env\.AGENTPASS_TEST_POSTGRES_ADMIN_URL/u);
  assert.match(integration, /const MIGRATION_DATABASE_URL = process\.env\.AGENTPASS_N3_POSTGRES_MIGRATION_URL \?\? process\.env\.AGENTPASS_TEST_MIGRATION_DATABASE_URL/u);
  assert.match(integration, /skip: ADMIN_DATABASE_URL && MIGRATION_DATABASE_URL \? false :/u);
  assert.doesNotMatch(integration, /t\.skip\(|P0BSkip|postgres_unavailable|external_disabled/u);
});
