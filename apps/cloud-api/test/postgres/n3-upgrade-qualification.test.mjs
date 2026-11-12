import assert from "node:assert/strict";
import test from "node:test";

import {
  N3_LEGACY_TABLE_SPECS,
  assertN3MigrationHistory,
  assertLegacyRowsPreserved,
  assertNoImplicitPlatformSessionSeeds,
  assertPlatformAuthorityRowsPreserved,
  assertReviewedN3MigrationSet,
  runN3UpgradeQualification
} from "../../../../scripts/postgres/n3-upgrade-qualification.mjs";
import { loadSqlMigrations } from "../../src/postgres/migration-runner.mjs";

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
