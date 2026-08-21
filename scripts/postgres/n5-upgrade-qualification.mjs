import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";

import {
  createMigrationRunner,
  loadSqlMigrations,
  migrationChecksum
} from "../../apps/cloud-api/src/postgres/migration-runner.mjs";
import {
  createDisposablePostgres,
  createVerifiedPostgresPoolOptions,
  requireVerifiedPostgresUrl
} from "../../test/support/p0b/harness.mjs";

const { Pool } = pg;

export const N5_SOURCE_VERSION = 54;
export const N5_TARGET_VERSION = 55;
export const N5_APPLICATION_VERSION = "n5-postgres-upgrade-qualification";
export const N5_MIGRATION_NAME = "0055_platform_session_bootstrap.sql";
export const N5_REPORT_SCHEMA_VERSION = 1;

function normalizeMigrationRows(rows) {
  if (!Array.isArray(rows)) throw new TypeError("N5 migration history rows must be an array");
  return rows.map((row) => ({ version: Number(row?.version), checksum: row?.checksum }));
}

function expectedHistory(migrations) {
  return migrations.slice(0, N5_TARGET_VERSION).map(({ version, checksum }) => ({ version, checksum }));
}

function assertCleanStatus(status, expectedRows, label) {
  assert.equal(status?.currentVersion, N5_TARGET_VERSION, `${label} status must be at migration 0055`);
  assert.deepEqual(status?.pending, [], `${label} status must have no pending migrations`);
  assert.deepEqual(status?.modified, [], `${label} status must have no checksum drift`);
  assert.equal(status?.dirty, false, `${label} status must be clean`);
  assert.deepEqual(status?.dirtyRows, [], `${label} status must have no dirty rows`);
  assert.deepEqual(normalizeMigrationRows(status?.applied), expectedRows, `${label} status history must be exact`);
}

export function buildN5UpgradePlan(migrations) {
  assertReviewedN5MigrationSet(migrations);
  return Object.freeze([Object.freeze({
    startVersion: N5_SOURCE_VERSION,
    targetVersion: N5_TARGET_VERSION,
    bootstrap: Object.freeze(migrations.slice(0, N5_SOURCE_VERSION)),
    upgrade: Object.freeze(migrations.slice(0, N5_TARGET_VERSION)),
    fresh: Object.freeze(migrations.slice(0, N5_TARGET_VERSION))
  })]);
}

export function assertReviewedN5MigrationSet(migrations) {
  if (!Array.isArray(migrations) || migrations.length < N5_TARGET_VERSION) {
    throw new Error(`N5 requires migrations 1 through ${N5_TARGET_VERSION}`);
  }
  for (let index = 0; index < N5_TARGET_VERSION; index += 1) {
    const migration = migrations[index];
    if (!migration || migration.version !== index + 1) throw new Error(`N5 migration order is invalid at ${index + 1}`);
    if (migrationChecksum(migration.sql) !== migration.checksum) throw new Error(`N5 migration checksum is invalid at ${index + 1}`);
  }
  if (migrations[N5_SOURCE_VERSION - 1]?.name !== "0054_platform_authorization.sql") {
    throw new Error("N5 source head is not 0054_platform_authorization.sql");
  }
  if (migrations[N5_TARGET_VERSION - 1]?.name !== N5_MIGRATION_NAME) {
    throw new Error(`N5 migration head is not ${N5_MIGRATION_NAME}`);
  }
  return true;
}

export function assertN5MigrationHistory({
  migrations,
  bootstrap,
  upgrade,
  fresh,
  upgradeRows,
  freshRows,
  upgradeStatus,
  freshStatus,
  upgradeIdentity,
  freshIdentity,
  sourceVersion = N5_SOURCE_VERSION,
  targetVersion = N5_TARGET_VERSION
}) {
  if (sourceVersion !== N5_SOURCE_VERSION) throw new Error("N5 source version must be 54");
  if (targetVersion !== N5_TARGET_VERSION) throw new Error("N5 target version must be 55");
  assertReviewedN5MigrationSet(migrations);

  const expectedRows = expectedHistory(migrations);
  const expectedBootstrapRows = expectedRows.slice(0, N5_SOURCE_VERSION);
  const expectedTargetRow = expectedRows[N5_TARGET_VERSION - 1];
  assert.deepEqual(normalizeMigrationRows(bootstrap?.applied), expectedBootstrapRows, "fresh bootstrap must apply exactly 1..54");
  assert.equal(bootstrap?.currentVersion, N5_SOURCE_VERSION, "fresh bootstrap must stop at 0054");
  assert.deepEqual(upgrade?.applied?.map(({ version, checksum }) => ({ version, checksum })), [expectedTargetRow], "upgrade must apply exactly 0055");
  assert.equal(upgrade?.currentVersion, N5_TARGET_VERSION, "upgrade must end at 0055");
  assert.deepEqual(fresh?.applied?.map(({ version, checksum }) => ({ version, checksum })), expectedRows, "fresh path must apply exactly 1..55");
  assert.equal(fresh?.currentVersion, N5_TARGET_VERSION, "fresh path must end at 0055");
  assert.deepEqual(normalizeMigrationRows(upgradeRows), expectedRows, "upgrade history must be exact");
  assert.deepEqual(normalizeMigrationRows(freshRows), expectedRows, "fresh history must be exact");
  assertCleanStatus(upgradeStatus, expectedRows, "upgrade");
  assertCleanStatus(freshStatus, expectedRows, "fresh");
  assert.deepEqual(upgradeIdentity, { session_user: "agentpass_migrator", current_user: "agentpass_migrator" });
  assert.deepEqual(freshIdentity, { session_user: "agentpass_migrator", current_user: "agentpass_migrator" });

  return Object.freeze({
    sourceVersion: N5_SOURCE_VERSION,
    targetVersion: N5_TARGET_VERSION,
    migrationName: N5_MIGRATION_NAME,
    migrationChecksum: expectedTargetRow.checksum,
    status: "clean",
    historyRows: expectedRows.length,
    appliedUpgradeVersions: Object.freeze([N5_TARGET_VERSION]),
    migrationIdentity: Object.freeze({ session_user: "agentpass_migrator", current_user: "agentpass_migrator" })
  });
}

function requireN5AdminUrl(value) {
  const url = requireVerifiedPostgresUrl(value, "N5 PostgreSQL admin URL");
  if (decodeURIComponent(url.username) === "agentpass_migrator") throw new TypeError("N5 admin URL must not use agentpass_migrator");
  return url;
}

function requireN5MigrationUrl(value) {
  const url = requireVerifiedPostgresUrl(value, "N5 PostgreSQL migrator URL");
  if (decodeURIComponent(url.username) !== "agentpass_migrator") throw new TypeError("N5 migration URL must use agentpass_migrator");
  return url;
}

async function applyRolePolicy(pool) {
  const source = await readFile(new URL("./roles.sql", import.meta.url), "utf8");
  const executable = source.replace(/^\\set\s+ON_ERROR_STOP\s+on\s*$/mu, "").trim();
  assert.doesNotMatch(executable, /^\\/mu, "role policy contains an unsupported psql directive");
  await pool.query(executable);
}

async function readIdentity(client) {
  return (await client.query("SELECT session_user, current_user")).rows[0] ?? {};
}

async function readHistory(pool) {
  return (await pool.query("SELECT version::int AS version, checksum FROM schema_migrations ORDER BY version")).rows;
}

async function openMigrationPool(database, migrationUrl) {
  const databaseUrl = new URL(migrationUrl.toString());
  databaseUrl.pathname = new URL(database.url).pathname;
  return new Pool({
    ...createVerifiedPostgresPoolOptions(databaseUrl, { ca: database.caCertificate }),
    max: 2,
    connectionTimeoutMillis: 3_000,
    idleTimeoutMillis: 3_000
  });
}

async function readStatus(pool, migrations) {
  const client = await pool.connect();
  try {
    return await createMigrationRunner({
      client,
      migrations,
      applicationVersion: N5_APPLICATION_VERSION
    }).status();
  } finally {
    client.release();
  }
}

async function qualifyFreshPath({ database, migrationUrl, migrations, scenario }) {
  await applyRolePolicy(database.pool);
  const pool = await openMigrationPool(database, migrationUrl);
  try {
    const client = await pool.connect();
    let fresh;
    let identity;
    try {
      identity = await readIdentity(client);
      fresh = await createMigrationRunner({
        client,
        migrations: scenario.fresh,
        applicationVersion: N5_APPLICATION_VERSION
      }).run();
    } finally {
      client.release();
    }
    const rows = await readHistory(pool);
    const status = await readStatus(pool, scenario.fresh);
    return Object.freeze({ fresh, freshRows: rows, freshStatus: status, freshIdentity: identity });
  } finally {
    await pool.end().catch(() => {});
  }
}

async function qualifyUpgradePath({ database, migrationUrl, migrations, scenario }) {
  await applyRolePolicy(database.pool);
  const pool = await openMigrationPool(database, migrationUrl);
  try {
    const bootstrapClient = await pool.connect();
    let bootstrap;
    try {
      bootstrap = await createMigrationRunner({
        client: bootstrapClient,
        migrations: scenario.bootstrap,
        applicationVersion: N5_APPLICATION_VERSION
      }).run();
    } finally {
      bootstrapClient.release();
    }

    const upgradeClient = await pool.connect();
    let upgrade;
    let identity;
    try {
      identity = await readIdentity(upgradeClient);
      upgrade = await createMigrationRunner({
        client: upgradeClient,
        migrations: scenario.upgrade,
        applicationVersion: N5_APPLICATION_VERSION
      }).run();
    } finally {
      upgradeClient.release();
    }
    const rows = await readHistory(pool);
    const status = await readStatus(pool, scenario.upgrade);
    return Object.freeze({ bootstrap, upgrade, upgradeRows: rows, upgradeStatus: status, upgradeIdentity: identity });
  } finally {
    await pool.end().catch(() => {});
  }
}

function databaseName(label) {
  return `agentpass_n5_${label}_${crypto.randomBytes(6).toString("hex")}`;
}

export async function runN5UpgradeQualification({ adminUrl, migrationUrl, databaseFactory = createDisposablePostgres } = {}) {
  const admin = requireN5AdminUrl(adminUrl);
  const migration = requireN5MigrationUrl(migrationUrl);
  if (typeof databaseFactory !== "function") throw new TypeError("N5 database factory is invalid");
  const migrations = await loadSqlMigrations();
  const [scenario] = buildN5UpgradePlan(migrations);

  const freshDatabase = await databaseFactory({ adminUrl: admin.toString(), databaseName: databaseName("fresh") });
  let freshResult;
  try {
    freshResult = await qualifyFreshPath({ database: freshDatabase, migrationUrl: migration, migrations, scenario });
  } finally {
    await freshDatabase.close();
  }

  const upgradeDatabase = await databaseFactory({ adminUrl: admin.toString(), databaseName: databaseName("upgrade") });
  let upgradeResult;
  try {
    upgradeResult = await qualifyUpgradePath({ database: upgradeDatabase, migrationUrl: migration, migrations, scenario });
  } finally {
    await upgradeDatabase.close();
  }

  const history = assertN5MigrationHistory({
    migrations,
    ...freshResult,
    ...upgradeResult
  });
  return Object.freeze({
    qualification: "postgres-upgrade",
    report_schema_version: N5_REPORT_SCHEMA_VERSION,
    name: "N5",
    source_version: N5_SOURCE_VERSION,
    target_version: N5_TARGET_VERSION,
    migration_name: N5_MIGRATION_NAME,
    migration_checksum: history.migrationChecksum,
    migration_role: "agentpass_migrator",
    scenarios: Object.freeze([
      Object.freeze({
        name: "fresh",
        from_version: 0,
        to_version: N5_TARGET_VERSION,
        history: Object.freeze({ ...history, path: "fresh" })
      }),
      Object.freeze({
        name: "upgrade",
        from_version: N5_SOURCE_VERSION,
        to_version: N5_TARGET_VERSION,
        history: Object.freeze({ ...history, path: "upgrade" })
      })
    ])
  });
}

async function main() {
  const adminUrl = process.env.AGENTPASS_N5_POSTGRES_ADMIN_URL ?? process.env.AGENTPASS_TEST_POSTGRES_ADMIN_URL;
  const migrationUrl = process.env.AGENTPASS_N5_POSTGRES_MIGRATION_URL ?? process.env.AGENTPASS_TEST_MIGRATION_DATABASE_URL;
  if (!adminUrl || !migrationUrl) {
    console.error("N5 requires explicit admin and agentpass_migrator PostgreSQL URLs; no database was qualified");
    process.exitCode = 2;
    return;
  }
  const report = await runN5UpgradeQualification({ adminUrl, migrationUrl });
  console.log(JSON.stringify(report, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
