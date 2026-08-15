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
  requireVerifiedPostgresUrl,
} from "../../test/support/p0b/harness.mjs";

const { Pool } = pg;

export const N2_SOURCE_VERSION = 51;
export const N2_TARGET_VERSION = 52;
export const N2_APPLICATION_VERSION = "n2-postgres-upgrade-qualification";
export const N2_MIGRATION_NAME = "0052_platform_operator_authority.sql";
export const N2_REPORT_SCHEMA_VERSION = 1;

export const N2_PLATFORM_AUTHORITY_TABLE_SPECS = Object.freeze([
  Object.freeze({ name: "platform_principals", orderBy: "principal_id" }),
  Object.freeze({ name: "platform_operator_assignments", orderBy: "assignment_id" }),
  Object.freeze({ name: "platform_operator_assignment_approvals", orderBy: "assignment_id, approver_principal_id" })
]);

const LEGACY_ORGANIZATION_ID = "00000000-0000-4000-8000-000000000201";
const LEGACY_MEMBER_ID = "00000000-0000-4000-8000-000000000202";
const LEGACY_MEMBERSHIP_ID = "00000000-0000-4000-8000-000000000203";
const LEGACY_SESSION_ID = "00000000-0000-4000-8000-000000000204";
const LEGACY_CREATED_AT = "2099-01-01T00:00:00.000Z";
const LEGACY_UPDATED_AT = "2099-01-01T00:00:01.000Z";
const LEGACY_EXPIRES_AT = "2099-01-01T01:00:00.000Z";
const LEGACY_IDLE_EXPIRES_AT = "2099-01-01T00:30:00.000Z";
const LEGACY_TOKEN_HASH = "31".repeat(32);
const LEGACY_CSRF_HASH = "32".repeat(32);

export const N2_LEGACY_TABLE_SPECS = Object.freeze([
  Object.freeze({ name: "organizations", orderBy: "id" }),
  Object.freeze({ name: "members", orderBy: "id" }),
  Object.freeze({ name: "memberships", orderBy: "organization_id,id" }),
  Object.freeze({ name: "human_sessions", orderBy: "id" })
]);

/**
 * N2 has one deliberately narrow forward path. The target slice is kept
 * explicit so a CI invocation cannot silently qualify a future, unreviewed
 * migration head.
 */
export function buildN2UpgradePlan(migrations) {
  assertReviewedN2MigrationSet(migrations);
  return Object.freeze([Object.freeze({
    startVersion: N2_SOURCE_VERSION,
    targetVersion: N2_TARGET_VERSION,
    bootstrap: Object.freeze(migrations.slice(0, N2_SOURCE_VERSION)),
    upgrade: Object.freeze(migrations.slice(0, N2_TARGET_VERSION))
  })]);
}

export function assertReviewedN2MigrationSet(migrations) {
  if (!Array.isArray(migrations) || migrations.length < N2_TARGET_VERSION) {
    throw new Error(`N2 requires migrations 1 through ${N2_TARGET_VERSION}`);
  }
  for (let index = 0; index < N2_TARGET_VERSION; index += 1) {
    const migration = migrations[index];
    if (!migration || migration.version !== index + 1) throw new Error(`N2 migration order is invalid at ${index + 1}`);
    if (migrationChecksum(migration.sql) !== migration.checksum) throw new Error(`N2 migration checksum is invalid at ${index + 1}`);
  }
  if (migrations[N2_SOURCE_VERSION - 1].name !== "0051_managed_signer_lifecycle_signing_authority.sql") {
    throw new Error("N2 source head is not 0051_managed_signer_lifecycle_signing_authority.sql");
  }
  if (migrations[N2_TARGET_VERSION - 1].name !== N2_MIGRATION_NAME) {
    throw new Error(`N2 migration head is not ${N2_MIGRATION_NAME}`);
  }
  return true;
}

function normalizeMigrationRows(rows) {
  if (!Array.isArray(rows)) throw new TypeError("N2 migration history rows must be an array");
  return rows.map((row) => ({ version: Number(row?.version), checksum: row?.checksum }));
}

function assertNoImplicitPlatformAuthoritySeeds(state, label) {
  if (!Array.isArray(state)) throw new TypeError(`N2 ${label} platform authority state must be an array`);
  assert.deepEqual(state.map(({ name, exists, row_count }) => ({ name, exists, row_count })), N2_PLATFORM_AUTHORITY_TABLE_SPECS.map(({ name }) => ({
    name,
    exists: state.find((item) => item.name === name)?.exists ?? false,
    row_count: state.find((item) => item.name === name)?.row_count ?? 0
  })), `N2 ${label} platform authority state has an unexpected shape`);
  for (const item of state) {
    assert.equal(item.row_count, 0, `N2 must not create implicit ${item.name} seed rows during upgrade`);
  }
  return true;
}

/**
 * Prove immutable history, runner status, the actual database identity, and
 * the absence of migration-time platform authority seeds. Only stable fields
 * are returned so the result can be compared or hashed by CI.
 */
export function assertLegacyRowsPreserved(before, after) {
  assert.deepEqual(after, before, "0052 must preserve seeded legacy organization, member, membership, and human session rows exactly");
  const tableRows = N2_LEGACY_TABLE_SPECS.map(({ name }) => ({
    name,
    row_count: before?.[name]?.length ?? 0
  }));
  assert.deepEqual(tableRows.map(({ row_count }) => row_count), [1, 1, 1, 1], "N2 legacy fixture must contain exactly one row per table");
  return true;
}

function stableSnapshotDigest(snapshot) {
  return crypto.createHash("sha256").update(JSON.stringify(snapshot), "utf8").digest("hex");
}

export function assertN2MigrationHistory({ rows, migrations, upgrade, status, identity, seedsBefore, seedsAfter, legacyBefore, legacyAfter, startVersion = N2_SOURCE_VERSION, targetVersion = N2_TARGET_VERSION }) {
  if (startVersion !== N2_SOURCE_VERSION) throw new Error("N2 start version must be 0051");
  if (targetVersion !== N2_TARGET_VERSION) throw new Error("N2 target version must be 0052");
  assertReviewedN2MigrationSet(migrations);
  const expectedRows = migrations.slice(0, N2_TARGET_VERSION).map(({ version, checksum }) => ({ version, checksum }));
  const actualRows = normalizeMigrationRows(rows);
  assert.deepEqual(actualRows, expectedRows, "schema_migrations must contain the exact reviewed 1..52 history and checksums");
  assert.deepEqual(upgrade?.applied?.map(({ version, checksum }) => ({ version, checksum })), expectedRows.slice(N2_SOURCE_VERSION), "N2 must apply exactly migration 0052 from a 0051 database");
  assert.equal(status?.currentVersion, N2_TARGET_VERSION);
  assert.deepEqual(status?.pending, []);
  assert.deepEqual(status?.modified, []);
  assert.equal(status?.dirty, false);
  assert.deepEqual(status?.dirtyRows, []);
  assert.deepEqual(normalizeMigrationRows(status?.applied), expectedRows, "status must expose the exact applied history");
  assert.equal(identity?.session_user, "agentpass_migrator", "migration connection must use agentpass_migrator as session_user");
  assert.equal(identity?.current_user, "agentpass_migrator", "migration connection must use agentpass_migrator as current_user");
  assertLegacyRowsPreserved(legacyBefore, legacyAfter);
  assertNoImplicitPlatformAuthoritySeeds(seedsBefore, "pre-upgrade");
  assertNoImplicitPlatformAuthoritySeeds(seedsAfter, "post-upgrade");
  return Object.freeze({
    startVersion: N2_SOURCE_VERSION,
    targetVersion: N2_TARGET_VERSION,
    historyRows: expectedRows.length,
    history: Object.freeze(expectedRows.map(({ version, checksum }) => Object.freeze({ version, checksum }))),
    appliedUpgradeVersions: Object.freeze([N2_TARGET_VERSION]),
    status: "clean",
    migration_identity: Object.freeze({ session_user: "agentpass_migrator", current_user: "agentpass_migrator" }),
    seeded_legacy_row_count: N2_LEGACY_TABLE_SPECS.reduce((total, { name }) => total + legacyBefore[name].length, 0),
    legacy_preservation: Object.freeze({
      exact: true,
      tables: Object.freeze(N2_LEGACY_TABLE_SPECS.map(({ name }) => Object.freeze({ name, row_count: legacyBefore[name].length }))),
      snapshot_sha256: stableSnapshotDigest(legacyBefore)
    }),
    platform_authority_seeds: Object.freeze({
      before: Object.freeze(seedsBefore.map(({ name, exists, row_count }) => Object.freeze({ name, exists, row_count }))),
      after: Object.freeze(seedsAfter.map(({ name, exists, row_count }) => Object.freeze({ name, exists, row_count })))
    })
  });
}

function requireN2AdminUrl(value) {
  const url = requireVerifiedPostgresUrl(value, "N2 PostgreSQL admin URL");
  if (decodeURIComponent(url.username) === "agentpass_migrator") throw new TypeError("N2 admin URL must not use agentpass_migrator");
  return url;
}

function requireN2MigrationUrl(value) {
  const url = requireVerifiedPostgresUrl(value, "N2 PostgreSQL migrator URL");
  if (decodeURIComponent(url.username) !== "agentpass_migrator") throw new TypeError("N2 migration URL must use agentpass_migrator");
  return url;
}

/**
 * Qualify an isolated database with an admin lifecycle DSN and a separate,
 * actual agentpass_migrator DSN. The admin connection only creates/drops the
 * disposable database and installs the role policy; all migration SQL runs
 * through the migrator connection.
 */
export async function runN2UpgradeQualification({ adminUrl, migrationUrl, databaseFactory = createDisposablePostgres } = {}) {
  const admin = requireN2AdminUrl(adminUrl);
  const migration = requireN2MigrationUrl(migrationUrl);
  if (typeof databaseFactory !== "function") throw new TypeError("N2 database factory is invalid");
  const migrations = await loadSqlMigrations();
  const [scenario] = buildN2UpgradePlan(migrations);
  const database = await databaseFactory({
    adminUrl: admin.toString(),
    databaseName: `agentpass_n2_from_${scenario.startVersion}`
  });
  migration.pathname = new URL(database.url).pathname;
  const migrationPool = new Pool({
    ...createVerifiedPostgresPoolOptions(migration, { ca: database.caCertificate }),
    max: 2,
    connectionTimeoutMillis: 3_000,
    idleTimeoutMillis: 3_000
  });
  try {
    return await qualifyScenario({ database, migrationPool, migrations, scenario });
  } finally {
    await migrationPool.end().catch(() => {});
    await database.close();
  }
}

async function qualifyScenario({ database, migrationPool, migrations, scenario }) {
  await applyRolePolicy(database.pool);
  const bootstrapClient = await migrationPool.connect();
  try {
    assertMigratorIdentity(await readIdentity(bootstrapClient));
    const bootstrap = await createMigrationRunner({
      client: bootstrapClient,
      migrations: scenario.bootstrap,
      applicationVersion: N2_APPLICATION_VERSION
    }).run();
    assert.equal(bootstrap.currentVersion, N2_SOURCE_VERSION);
    assert.deepEqual(bootstrap.applied.map(({ version }) => version), Array.from({ length: N2_SOURCE_VERSION }, (_, index) => index + 1));
  } finally {
    bootstrapClient.release();
  }

  const seedsBefore = await snapshotN2PlatformAuthorityRows(database.pool);
  assertNoImplicitPlatformAuthoritySeeds(seedsBefore, "pre-upgrade");
  await seedN2LegacyRows(database.pool);
  const legacyBefore = await snapshotN2LegacyRows(database.pool);
  assert.equal(legacyRowCount(legacyBefore), 4);
  const upgradeClient = await migrationPool.connect();
  let upgrade;
  let identity;
  try {
    identity = await readIdentity(upgradeClient);
    assertMigratorIdentity(identity);
    upgrade = await createMigrationRunner({
      client: upgradeClient,
      migrations: scenario.upgrade,
      applicationVersion: N2_APPLICATION_VERSION
    }).run();
  } finally {
    upgradeClient.release();
  }

  await applyRolePolicy(database.pool);
  const legacyAfter = await snapshotN2LegacyRows(database.pool);
  assertLegacyRowsPreserved(legacyBefore, legacyAfter);
  const seedsAfter = await snapshotN2PlatformAuthorityRows(database.pool);
  assertNoImplicitPlatformAuthoritySeeds(seedsAfter, "post-upgrade");
  const history = await readMigrationHistory(database.pool);
  const statusClient = await migrationPool.connect();
  let status;
  try {
    assertMigratorIdentity(await readIdentity(statusClient));
    status = await createMigrationRunner({
      client: statusClient,
      migrations: scenario.upgrade,
      applicationVersion: N2_APPLICATION_VERSION
    }).status();
  } finally {
    statusClient.release();
  }
  const historyReport = assertN2MigrationHistory({
    rows: history,
    migrations,
    upgrade,
    status,
    identity,
    seedsBefore,
    seedsAfter,
    legacyBefore,
    legacyAfter
  });
  return Object.freeze({
    qualification: "postgres-upgrade",
    report_schema_version: N2_REPORT_SCHEMA_VERSION,
    name: "N2",
    source_version: N2_SOURCE_VERSION,
    target_version: N2_TARGET_VERSION,
    migration_role: "agentpass_migrator",
    scenarios: Object.freeze([Object.freeze({
      from_version: N2_SOURCE_VERSION,
      to_version: N2_TARGET_VERSION,
      seeded_legacy_row_count: historyReport.seeded_legacy_row_count,
      legacy_preservation: historyReport.legacy_preservation,
      history: historyReport
    })])
  });
}

function assertMigratorIdentity(identity) {
  assert.equal(identity.session_user, "agentpass_migrator");
  assert.equal(identity.current_user, "agentpass_migrator");
}

async function readIdentity(client) {
  const result = await client.query("SELECT session_user, current_user");
  return result.rows[0] ?? {};
}

async function readMigrationHistory(pool) {
  const result = await pool.query("SELECT version::int AS version, checksum FROM schema_migrations ORDER BY version");
  return result.rows;
}

async function applyRolePolicy(pool) {
  const source = await readFile(new URL("./roles.sql", import.meta.url), "utf8");
  const executable = source.replace(/^\\set\s+ON_ERROR_STOP\s+on\s*$/mu, "").trim();
  assert.doesNotMatch(executable, /^\\/mu, "the role fixture contains an unsupported psql directive");
  await pool.query(executable);
}

export async function snapshotN2PlatformAuthorityRows(pool) {
  const result = [];
  for (const { name } of N2_PLATFORM_AUTHORITY_TABLE_SPECS) {
    const relation = await pool.query("SELECT to_regclass($1) AS relation", [`public.${name}`]);
    if (relation.rows[0]?.relation === null) {
      result.push({ name, exists: false, row_count: 0 });
      continue;
    }
    const rows = await pool.query(`SELECT count(*)::int AS row_count FROM public.${name}`);
    result.push({ name, exists: true, row_count: Number(rows.rows[0]?.row_count ?? 0) });
  }
  return Object.freeze(result.map((item) => Object.freeze(item)));
}

function legacyRowCount(snapshot) {
  return N2_LEGACY_TABLE_SPECS.reduce((total, { name }) => total + (snapshot?.[name]?.length ?? 0), 0);
}

async function seedN2LegacyRows(pool) {
  await pool.query(`INSERT INTO organizations
    (id, name, version, created_at, updated_at, authority_epoch)
    VALUES ($1, 'N2 seeded legacy organization', 3, $2::timestamptz, $3::timestamptz, 1)`, [LEGACY_ORGANIZATION_ID, LEGACY_CREATED_AT, LEGACY_UPDATED_AT]);
  await pool.query(`INSERT INTO members
    (id, github_subject, display_name, created_at)
    VALUES ($1, 'n2-seeded-legacy-github-subject', 'N2 seeded legacy member', $2::timestamptz)`, [LEGACY_MEMBER_ID, LEGACY_CREATED_AT]);
  await pool.query(`INSERT INTO memberships
    (organization_id, id, member_id, role, status, version, created_at, updated_at, session_epoch)
    VALUES ($1, $2, $3, 'admin', 'active', 2, $4::timestamptz, $5::timestamptz, 4)`, [LEGACY_ORGANIZATION_ID, LEGACY_MEMBERSHIP_ID, LEGACY_MEMBER_ID, LEGACY_CREATED_AT, LEGACY_UPDATED_AT]);
  await pool.query(`INSERT INTO human_sessions
    (id, member_id, token_hash, created_at, expires_at, recent_auth_at, revoked_at,
     organization_id, membership_id, role, csrf_token_hash, last_seen_at, idle_expires_at,
     revoke_reason, recent_auth_challenge_id, recent_auth_organization_id,
     recent_auth_operation, recent_auth_consumed_at, version,
     organization_authority_epoch, membership_session_epoch, recent_auth_context_hash)
    VALUES ($1, $2, decode($3, 'hex'), $4::timestamptz, $5::timestamptz, NULL, NULL,
      $6, $7, 'admin', decode($8, 'hex'), $9::timestamptz, $10::timestamptz,
      NULL, NULL, NULL, NULL, NULL, 7, 1, 4, NULL)`, [
    LEGACY_SESSION_ID,
    LEGACY_MEMBER_ID,
    LEGACY_TOKEN_HASH,
    LEGACY_CREATED_AT,
    LEGACY_EXPIRES_AT,
    LEGACY_ORGANIZATION_ID,
    LEGACY_MEMBERSHIP_ID,
    LEGACY_CSRF_HASH,
    LEGACY_UPDATED_AT,
    LEGACY_IDLE_EXPIRES_AT
  ]);
}

export async function snapshotN2LegacyRows(pool) {
  const snapshot = {
    organizations: (await pool.query(`SELECT id::text, name, version::int AS version,
      authority_epoch::int AS authority_epoch, created_at::text, updated_at::text
      FROM organizations WHERE id = $1 ORDER BY id`, [LEGACY_ORGANIZATION_ID])).rows,
    members: (await pool.query(`SELECT id::text, github_subject, display_name, created_at::text
      FROM members WHERE id = $1 ORDER BY id`, [LEGACY_MEMBER_ID])).rows,
    memberships: (await pool.query(`SELECT organization_id::text, id::text, member_id::text, role,
      status, version::int AS version, session_epoch::int AS session_epoch,
      created_at::text, updated_at::text
      FROM memberships WHERE organization_id = $1 AND id = $2 ORDER BY organization_id,id`, [LEGACY_ORGANIZATION_ID, LEGACY_MEMBERSHIP_ID])).rows,
    human_sessions: (await pool.query(`SELECT id::text, member_id::text, encode(token_hash, 'hex') AS token_hash,
      created_at::text, expires_at::text, recent_auth_at::text, revoked_at::text,
      organization_id::text, membership_id::text, role,
      encode(csrf_token_hash, 'hex') AS csrf_token_hash, last_seen_at::text,
      idle_expires_at::text, revoke_reason, recent_auth_challenge_id::text,
      recent_auth_organization_id::text, recent_auth_operation, recent_auth_consumed_at::text,
      version::int AS version, organization_authority_epoch::int AS organization_authority_epoch,
      membership_session_epoch::int AS membership_session_epoch,
      encode(recent_auth_context_hash, 'hex') AS recent_auth_context_hash
      FROM human_sessions WHERE id = $1 ORDER BY id`, [LEGACY_SESSION_ID])).rows
  };
  return Object.freeze(Object.fromEntries(Object.entries(snapshot).map(([name, rows]) => [name, Object.freeze(rows.map((row) => Object.freeze(row)))])));
}

async function main() {
  const adminUrl = process.env.AGENTPASS_N2_POSTGRES_ADMIN_URL ?? process.env.AGENTPASS_TEST_POSTGRES_ADMIN_URL;
  const migrationUrl = process.env.AGENTPASS_N2_POSTGRES_MIGRATION_URL ?? process.env.AGENTPASS_TEST_MIGRATION_DATABASE_URL;
  if (!adminUrl || !migrationUrl) {
    console.error("N2 requires explicit admin and agentpass_migrator PostgreSQL URLs; no database was qualified");
    process.exitCode = 2;
    return;
  }
  const report = await runN2UpgradeQualification({ adminUrl, migrationUrl });
  console.log(JSON.stringify(report, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
