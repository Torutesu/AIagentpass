import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  N1_APPLICATION_VERSION,
  N1_AUTHORITY_TABLE_SPECS,
  N1_TARGET_VERSION,
  N1_UPGRADE_START_VERSIONS,
  assertAuthorityRowsPreserved,
  assertN1MigrationHistory,
  buildN1UpgradePlan
} from "../../../../scripts/postgres/n1-upgrade-qualification.mjs";
import { loadSqlMigrations, migrationChecksum } from "../../src/postgres/migration-runner.mjs";

const SCRIPT_PATH = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../scripts/postgres/n1-upgrade-qualification.mjs");
const INTEGRATION_PATH = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "./n1-upgrade-qualification.integration.test.mjs");

test("N1 plan is exactly 47→51 and 48→51 and uses the reviewed migration head", async () => {
  const migrations = await loadSqlMigrations();
  const plan = buildN1UpgradePlan(migrations);
  assert.deepEqual(N1_UPGRADE_START_VERSIONS, [47, 48]);
  assert.equal(N1_TARGET_VERSION, 51);
  assert.equal(N1_APPLICATION_VERSION, "n1-postgres-upgrade-qualification");
  assert.deepEqual(plan.map(({ startVersion, targetVersion }) => ({ startVersion, targetVersion })), [
    { startVersion: 47, targetVersion: 51 },
    { startVersion: 48, targetVersion: 51 }
  ]);
  assert.deepEqual(plan.map(({ bootstrap }) => bootstrap.at(-1).version), [47, 48]);
  assert.deepEqual(plan.map(({ upgrade }) => upgrade.at(-1).name), [
    "0051_managed_signer_lifecycle_signing_authority.sql",
    "0051_managed_signer_lifecycle_signing_authority.sql"
  ]);
  assert.ok(plan.every(({ upgrade }) => upgrade.length === 51));
  assert.ok(migrations.slice(0, 51).every(({ sql, checksum }) => migrationChecksum(sql) === checksum));
});

test("N1 history validator proves contiguous checksums, head, status, and exact upgrade set", async () => {
  const migrations = await loadSqlMigrations();
  for (const startVersion of N1_UPGRADE_START_VERSIONS) {
    const rows = migrations.slice(0, 51).map(({ version, checksum }) => ({ version, checksum, application_version: N1_APPLICATION_VERSION }));
    const upgrade = { applied: migrations.slice(startVersion, 51).map(({ version, checksum }) => ({ version, checksum })) };
    const status = {
      currentVersion: 51,
      pending: [],
      modified: [],
      dirty: false,
      dirtyRows: [],
      applied: rows
    };
    const report = assertN1MigrationHistory({ rows, migrations, startVersion, upgrade, status });
    assert.deepEqual(report.appliedUpgradeVersions, migrations.slice(startVersion, 51).map(({ version }) => version));
  }
});

test("N1 history validator rejects checksum drift, missing history, a wrong head, and an incomplete upgrade", async () => {
  const migrations = await loadSqlMigrations();
  const rows = migrations.slice(0, 51).map(({ version, checksum }) => ({ version, checksum, application_version: N1_APPLICATION_VERSION }));
  const base = {
    rows,
    migrations,
    startVersion: 47,
    upgrade: { applied: migrations.slice(47, 51).map(({ version, checksum }) => ({ version, checksum })) },
    status: { currentVersion: 51, pending: [], modified: [], dirty: false, dirtyRows: [], applied: rows }
  };
  for (const mutate of [
    (value) => { value.rows[50].checksum = "0".repeat(64); },
    (value) => { value.rows.splice(20, 1); },
    (value) => { value.rows[50].version = 52; },
    (value) => { value.upgrade.applied.pop(); },
    (value) => { value.status.pending = [51]; }
  ]) {
    const candidate = structuredClone(base);
    mutate(candidate);
    assert.throws(() => assertN1MigrationHistory(candidate), assert.AssertionError);
  }
});

test("N1 authority snapshot comparison is strict, including binary values", () => {
  const before = new Map([["managed_signer_keys", [{ key_id: "seed", fingerprint: Buffer.from([1, 2, 3]) }]]]);
  const after = new Map([["managed_signer_keys", [{ key_id: "seed", fingerprint: Buffer.from([1, 2, 3]) }]]]);
  assert.equal(assertAuthorityRowsPreserved(before, after), true);
  const changed = new Map([["managed_signer_keys", [{ key_id: "seed", fingerprint: Buffer.from([1, 2, 4]) }]]]);
  assert.throws(() => assertAuthorityRowsPreserved(before, changed), /authority rows changed/u);
});

test("N1 qualification owns its write set and exposes a direct deterministic CI command", async () => {
  const source = await readFile(SCRIPT_PATH, "utf8");
  assert.match(source, /createMigrationRunner/);
  assert.match(source, /loadSqlMigrations/);
  assert.match(source, /createDisposablePostgres/);
  assert.match(source, /roles\.sql/);
  assert.match(source, /schema_migrations/);
  assert.match(source, /migrationChecksum/);
  assert.match(source, /databaseName: `agentpass_n1_from_\$\{scenario\.startVersion\}`/);
  assert.match(source, /AGENTPASS_N1_POSTGRES_ADMIN_URL/);
  assert.match(source, /AGENTPASS_N1_POSTGRES_MIGRATION_URL/);
  assert.match(source, /session_user,?current_user/);
  assert.match(source, /managed_signer_signing_idempotency[\s\S]*reserved_lifecycle_version, expires_at\)[\s\S]*decode\(\$4, 'hex'\), 1,/u);
  assert.doesNotMatch(source, /\.github\/workflows/u);
  assert.deepEqual(N1_AUTHORITY_TABLE_SPECS.map(({ name }) => name), [
    "release_candidates",
    "platform_promotion_approvals",
    "platform_promotion_deployments",
    "platform_promotion_issuances",
    "managed_signer_key_lifecycles",
    "managed_signer_keys",
    "managed_signer_key_lifecycle_operations",
    "managed_signer_signing_idempotency",
    "managed_signer_provider_operations"
  ]);
});

test("N1 integration has exactly one skip gate requiring explicit admin and migrator DSNs", async () => {
  const source = await readFile(INTEGRATION_PATH, "utf8");
  assert.match(source, /const ADMIN_DATABASE_URL = process\.env\.AGENTPASS_N1_POSTGRES_ADMIN_URL \?\? process\.env\.AGENTPASS_TEST_POSTGRES_ADMIN_URL/u);
  assert.match(source, /const MIGRATION_DATABASE_URL = process\.env\.AGENTPASS_N1_POSTGRES_MIGRATION_URL \?\? process\.env\.AGENTPASS_TEST_MIGRATION_DATABASE_URL/u);
  assert.match(source, /skip: ADMIN_DATABASE_URL && MIGRATION_DATABASE_URL \? false :/u);
  assert.doesNotMatch(source, /t\.skip\(|P0BSkip|postgres_unavailable|external_disabled/u);
});
