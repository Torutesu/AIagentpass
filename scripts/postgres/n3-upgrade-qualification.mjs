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

export const N3_SOURCE_VERSION = 52;
export const N3_TARGET_VERSION = 53;
export const N3_APPLICATION_VERSION = "n3-postgres-upgrade-qualification";
export const N3_MIGRATION_NAME = "0053_platform_sessions.sql";
export const N3_REPORT_SCHEMA_VERSION = 1;

export const N3_PLATFORM_AUTHORITY_TABLE_SPECS = Object.freeze([
  Object.freeze({ name: "platform_principals", orderBy: "principal_id" }),
  Object.freeze({ name: "platform_operator_assignments", orderBy: "assignment_id" }),
  Object.freeze({ name: "platform_operator_assignment_approvals", orderBy: "assignment_id, approver_principal_id" })
]);

export const N3_PLATFORM_SESSION_TABLE_SPECS = Object.freeze([
  Object.freeze({ name: "platform_credentials" }),
  Object.freeze({ name: "platform_sessions" })
]);

const LEGACY_ORGANIZATION_ID = "00000000-0000-4000-8000-000000000301";
const LEGACY_TARGET_MEMBER_ID = "00000000-0000-4000-8000-000000000302";
const LEGACY_APPROVER_MEMBER_ID = "00000000-0000-4000-8000-000000000303";
const LEGACY_MEMBERSHIP_ID = "00000000-0000-4000-8000-000000000304";
const LEGACY_SESSION_ID = "00000000-0000-4000-8000-000000000305";
const PLATFORM_TARGET_PRINCIPAL_ID = "00000000-0000-4000-8000-000000000311";
const PLATFORM_APPROVER_PRINCIPAL_ID = "00000000-0000-4000-8000-000000000312";
const PLATFORM_ASSIGNMENT_ID = "00000000-0000-4000-8000-000000000313";
const PLATFORM_APPROVAL_ID = "00000000-0000-4000-8000-000000000314";
const LEGACY_CREATED_AT = "2099-01-01T00:00:00.000Z";
const LEGACY_UPDATED_AT = "2099-01-01T00:00:01.000Z";
const LEGACY_EXPIRES_AT = "2099-01-01T01:00:00.000Z";
const LEGACY_IDLE_EXPIRES_AT = "2099-01-01T00:30:00.000Z";
const LEGACY_TOKEN_HASH = "41".repeat(32);
const LEGACY_CSRF_HASH = "42".repeat(32);
const PLATFORM_REQUEST_DIGEST = "43".repeat(32);

export const N3_LEGACY_TABLE_SPECS = Object.freeze([
  Object.freeze({ name: "organizations", orderBy: "id" }),
  Object.freeze({ name: "members", orderBy: "id" }),
  Object.freeze({ name: "memberships", orderBy: "organization_id,id" }),
  Object.freeze({ name: "human_sessions", orderBy: "id" })
]);

export function buildN3UpgradePlan(migrations) {
  assertReviewedN3MigrationSet(migrations);
  return Object.freeze([Object.freeze({
    startVersion: N3_SOURCE_VERSION,
    targetVersion: N3_TARGET_VERSION,
    bootstrap: Object.freeze(migrations.slice(0, N3_SOURCE_VERSION)),
    upgrade: Object.freeze(migrations.slice(0, N3_TARGET_VERSION))
  })]);
}

export function assertReviewedN3MigrationSet(migrations) {
  if (!Array.isArray(migrations) || migrations.length < N3_TARGET_VERSION) {
    throw new Error(`N3 requires migrations 1 through ${N3_TARGET_VERSION}`);
  }
  for (let index = 0; index < N3_TARGET_VERSION; index += 1) {
    const migration = migrations[index];
    if (!migration || migration.version !== index + 1) throw new Error(`N3 migration order is invalid at ${index + 1}`);
    if (migrationChecksum(migration.sql) !== migration.checksum) throw new Error(`N3 migration checksum is invalid at ${index + 1}`);
  }
  if (migrations[N3_SOURCE_VERSION - 1].name !== "0052_platform_operator_authority.sql") {
    throw new Error("N3 source head is not 0052_platform_operator_authority.sql");
  }
  if (migrations[N3_TARGET_VERSION - 1].name !== N3_MIGRATION_NAME) {
    throw new Error(`N3 migration head is not ${N3_MIGRATION_NAME}`);
  }
  return true;
}

function normalizeMigrationRows(rows) {
  if (!Array.isArray(rows)) throw new TypeError("N3 migration history rows must be an array");
  return rows.map((row) => ({ version: Number(row?.version), checksum: row?.checksum }));
}

function stableSnapshotDigest(snapshot) {
  return crypto.createHash("sha256").update(JSON.stringify(snapshot), "utf8").digest("hex");
}

export function assertLegacyRowsPreserved(before, after) {
  assert.deepEqual(after, before, "0053 must preserve seeded legacy organization, member, membership, and human session rows exactly");
  assert.deepEqual(N3_LEGACY_TABLE_SPECS.map(({ name }) => before?.[name]?.length ?? 0), [1, 2, 1, 1], "N3 legacy fixture must contain the reviewed tenant/session rows");
  return true;
}

export function assertPlatformAuthorityRowsPreserved(before, after) {
  assert.deepEqual(after, before, "0053 must preserve seeded 0052 principal, assignment, and approval rows exactly");
  assert.equal(before.platform_principals.length, 2);
  assert.equal(before.platform_operator_assignments.length, 1);
  assert.equal(before.platform_operator_assignment_approvals.length, 1);
  return true;
}

export function assertNoImplicitPlatformSessionSeeds(state, label) {
  if (!Array.isArray(state)) throw new TypeError(`N3 ${label} platform session state must be an array`);
  assert.deepEqual(state.map(({ name, exists, row_count }) => ({ name, exists, row_count })), [
    ...N3_PLATFORM_SESSION_TABLE_SPECS.map(({ name }) => ({
      name,
      exists: state.find((item) => item.name === name)?.exists ?? false,
      row_count: state.find((item) => item.name === name)?.row_count ?? 0
    }))
  ], `N3 ${label} platform session state has an unexpected shape`);
  for (const item of state) assert.equal(item.row_count, 0, `N3 must not create implicit ${item.name} rows during upgrade`);
  return true;
}

export function assertN3MigrationHistory({
  rows,
  migrations,
  upgrade,
  status,
  identity,
  authorityBefore,
  authorityAfter,
  sessionsBefore,
  sessionsAfter,
  legacyBefore,
  legacyAfter,
  startVersion = N3_SOURCE_VERSION,
  targetVersion = N3_TARGET_VERSION
}) {
  if (startVersion !== N3_SOURCE_VERSION) throw new Error("N3 start version must be 0052");
  if (targetVersion !== N3_TARGET_VERSION) throw new Error("N3 target version must be 0053");
  assertReviewedN3MigrationSet(migrations);
  const expectedRows = migrations.slice(0, N3_TARGET_VERSION).map(({ version, checksum }) => ({ version, checksum }));
  assert.deepEqual(normalizeMigrationRows(rows), expectedRows, "schema_migrations must contain the exact reviewed 1..53 history and checksums");
  assert.deepEqual(upgrade?.applied?.map(({ version, checksum }) => ({ version, checksum })), expectedRows.slice(N3_SOURCE_VERSION), "N3 must apply exactly migration 0053 from a 0052 database");
  assert.equal(status?.currentVersion, N3_TARGET_VERSION);
  assert.deepEqual(status?.pending, []);
  assert.deepEqual(status?.modified, []);
  assert.equal(status?.dirty, false);
  assert.deepEqual(status?.dirtyRows, []);
  assert.deepEqual(normalizeMigrationRows(status?.applied), expectedRows, "status must expose the exact applied history");
  assert.deepEqual(identity, { session_user: "agentpass_migrator", current_user: "agentpass_migrator" });
  assertPlatformAuthorityRowsPreserved(authorityBefore, authorityAfter);
  assertLegacyRowsPreserved(legacyBefore, legacyAfter);
  assertNoImplicitPlatformSessionSeeds(sessionsBefore, "pre-upgrade");
  assertNoImplicitPlatformSessionSeeds(sessionsAfter, "post-upgrade");
  return Object.freeze({
    startVersion: N3_SOURCE_VERSION,
    targetVersion: N3_TARGET_VERSION,
    historyRows: expectedRows.length,
    history: Object.freeze(expectedRows.map(({ version, checksum }) => Object.freeze({ version, checksum }))),
    appliedUpgradeVersions: Object.freeze([N3_TARGET_VERSION]),
    status: "clean",
    migration_identity: Object.freeze({ session_user: "agentpass_migrator", current_user: "agentpass_migrator" }),
    seeded_legacy_row_count: N3_LEGACY_TABLE_SPECS.reduce((total, { name }) => total + legacyBefore[name].length, 0),
    legacy_preservation: Object.freeze({
      exact: true,
      tables: Object.freeze(N3_LEGACY_TABLE_SPECS.map(({ name }) => Object.freeze({ name, row_count: legacyBefore[name].length }))),
      snapshot_sha256: stableSnapshotDigest(legacyBefore)
    }),
    platform_authority_preservation: Object.freeze({
      exact: true,
      tables: Object.freeze(N3_PLATFORM_AUTHORITY_TABLE_SPECS.map(({ name }) => Object.freeze({ name, row_count: authorityBefore[name].length }))),
      snapshot_sha256: stableSnapshotDigest(authorityBefore)
    }),
    platform_session_seeds: Object.freeze({
      before: Object.freeze(sessionsBefore.map(({ name, exists, row_count }) => Object.freeze({ name, exists, row_count }))),
      after: Object.freeze(sessionsAfter.map(({ name, exists, row_count }) => Object.freeze({ name, exists, row_count })))
    })
  });
}

function requireN3AdminUrl(value) {
  const url = requireVerifiedPostgresUrl(value, "N3 PostgreSQL admin URL");
  if (decodeURIComponent(url.username) === "agentpass_migrator") throw new TypeError("N3 admin URL must not use agentpass_migrator");
  return url;
}

function requireN3MigrationUrl(value) {
  const url = requireVerifiedPostgresUrl(value, "N3 PostgreSQL migrator URL");
  if (decodeURIComponent(url.username) !== "agentpass_migrator") throw new TypeError("N3 migration URL must use agentpass_migrator");
  return url;
}

export async function runN3UpgradeQualification({ adminUrl, migrationUrl, databaseFactory = createDisposablePostgres } = {}) {
  const admin = requireN3AdminUrl(adminUrl);
  const migration = requireN3MigrationUrl(migrationUrl);
  if (typeof databaseFactory !== "function") throw new TypeError("N3 database factory is invalid");
  const migrations = await loadSqlMigrations();
  const [scenario] = buildN3UpgradePlan(migrations);
  const database = await databaseFactory({
    adminUrl: admin.toString(),
    databaseName: `agentpass_n3_from_${scenario.startVersion}`
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
      applicationVersion: N3_APPLICATION_VERSION
    }).run();
    assert.equal(bootstrap.currentVersion, N3_SOURCE_VERSION);
    assert.deepEqual(bootstrap.applied.map(({ version }) => version), Array.from({ length: N3_SOURCE_VERSION }, (_, index) => index + 1));
  } finally {
    bootstrapClient.release();
  }

  await seedN3LegacyRows(database.pool);
  const legacyBefore = await snapshotN3LegacyRows(database.pool);
  assertLegacyRowsPreserved(legacyBefore, legacyBefore);

  await seedN3PlatformAuthorityRows(migrationPool);
  const authorityBefore = await snapshotN3PlatformAuthorityRows(database.pool);
  const sessionsBefore = await snapshotN3PlatformSessionRows(database.pool);
  assertNoImplicitPlatformSessionSeeds(sessionsBefore, "pre-upgrade");

  const upgradeClient = await migrationPool.connect();
  let upgrade;
  let identity;
  try {
    identity = await readIdentity(upgradeClient);
    assertMigratorIdentity(identity);
    upgrade = await createMigrationRunner({
      client: upgradeClient,
      migrations: scenario.upgrade,
      applicationVersion: N3_APPLICATION_VERSION
    }).run();
  } finally {
    upgradeClient.release();
  }

  await applyRolePolicy(database.pool);
  const legacyAfter = await snapshotN3LegacyRows(database.pool);
  const authorityAfter = await snapshotN3PlatformAuthorityRows(database.pool);
  const sessionsAfter = await snapshotN3PlatformSessionRows(database.pool);
  assertLegacyRowsPreserved(legacyBefore, legacyAfter);
  assertPlatformAuthorityRowsPreserved(authorityBefore, authorityAfter);
  assertNoImplicitPlatformSessionSeeds(sessionsAfter, "post-upgrade");
  const history = await readMigrationHistory(database.pool);
  const statusClient = await migrationPool.connect();
  let status;
  try {
    assertMigratorIdentity(await readIdentity(statusClient));
    status = await createMigrationRunner({
      client: statusClient,
      migrations: scenario.upgrade,
      applicationVersion: N3_APPLICATION_VERSION
    }).status();
  } finally {
    statusClient.release();
  }
  const historyReport = assertN3MigrationHistory({
    rows: history,
    migrations,
    upgrade,
    status,
    identity,
    authorityBefore,
    authorityAfter,
    sessionsBefore,
    sessionsAfter,
    legacyBefore,
    legacyAfter
  });
  return Object.freeze({
    qualification: "postgres-upgrade",
    report_schema_version: N3_REPORT_SCHEMA_VERSION,
    name: "N3",
    source_version: N3_SOURCE_VERSION,
    target_version: N3_TARGET_VERSION,
    migration_role: "agentpass_migrator",
    scenarios: Object.freeze([Object.freeze({
      from_version: N3_SOURCE_VERSION,
      to_version: N3_TARGET_VERSION,
      seeded_legacy_row_count: historyReport.seeded_legacy_row_count,
      seeded_platform_authority_row_count: 4,
      legacy_preservation: historyReport.legacy_preservation,
      platform_authority_preservation: historyReport.platform_authority_preservation,
      platform_session_seeds: historyReport.platform_session_seeds,
      history: historyReport
    })])
  });
}

function assertMigratorIdentity(identity) {
  assert.deepEqual(identity, { session_user: "agentpass_migrator", current_user: "agentpass_migrator" });
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

async function snapshotRelationCount(pool, name) {
  const relation = await pool.query("SELECT to_regclass($1) AS relation", [`public.${name}`]);
  if (relation.rows[0]?.relation === null) return { name, exists: false, row_count: 0 };
  const result = await pool.query(`SELECT count(*)::int AS row_count FROM public.${name}`);
  return { name, exists: true, row_count: Number(result.rows[0]?.row_count ?? 0) };
}

export async function snapshotN3PlatformSessionRows(pool) {
  const rows = await Promise.all(N3_PLATFORM_SESSION_TABLE_SPECS.map(({ name }) => snapshotRelationCount(pool, name)));
  return Object.freeze(rows.map((row) => Object.freeze(row)));
}

export async function snapshotN3PlatformAuthorityRows(pool) {
  const principals = (await pool.query(`SELECT principal_id::text, member_id::text, status, status_reason,
      authority_generation::int AS authority_generation, version::int AS version,
      created_at::text, updated_at::text
      FROM platform_principals ORDER BY principal_id`)).rows;
  const assignments = (await pool.query(`SELECT assignment_id::text, principal_id::text, member_id::text,
      organization_id::text, operation, capability, status, encode(request_digest, 'hex') AS request_digest,
      requested_authority_generation::int AS requested_authority_generation, version::int AS version,
      requested_at::text, issued_at::text, expires_at::text, activated_at::text,
      suspended_at::text, revoked_at::text, replaced_at::text, suspend_reason,
      revoke_reason, replace_reason, updated_at::text
      FROM platform_operator_assignments ORDER BY assignment_id`)).rows;
  const approvals = (await pool.query(`SELECT approval_id::text, assignment_id::text,
      approver_principal_id::text, encode(request_digest, 'hex') AS request_digest,
      approver_authority_generation::int AS approver_authority_generation, approved_at::text
      FROM platform_operator_assignment_approvals ORDER BY assignment_id, approver_principal_id`)).rows;
  return Object.freeze({
    platform_principals: Object.freeze(principals.map((row) => Object.freeze(row))),
    platform_operator_assignments: Object.freeze(assignments.map((row) => Object.freeze(row))),
    platform_operator_assignment_approvals: Object.freeze(approvals.map((row) => Object.freeze(row)))
  });
}

async function seedN3LegacyRows(pool) {
  await pool.query(`INSERT INTO organizations
    (id, name, version, created_at, updated_at, authority_epoch)
    VALUES ($1, 'N3 seeded legacy organization', 5, $2::timestamptz, $3::timestamptz, 2)`, [LEGACY_ORGANIZATION_ID, LEGACY_CREATED_AT, LEGACY_UPDATED_AT]);
  await pool.query(`INSERT INTO members
    (id, github_subject, display_name, created_at)
    VALUES ($1, 'n3-seeded-target-member', 'N3 seeded target member', $3::timestamptz),
           ($2, 'n3-seeded-approver-member', 'N3 seeded approver member', $3::timestamptz)`, [LEGACY_TARGET_MEMBER_ID, LEGACY_APPROVER_MEMBER_ID, LEGACY_CREATED_AT]);
  await pool.query(`INSERT INTO memberships
    (organization_id, id, member_id, role, status, version, created_at, updated_at, session_epoch)
    VALUES ($1, $2, $3, 'admin', 'active', 3, $4::timestamptz, $5::timestamptz, 6)`, [LEGACY_ORGANIZATION_ID, LEGACY_MEMBERSHIP_ID, LEGACY_TARGET_MEMBER_ID, LEGACY_CREATED_AT, LEGACY_UPDATED_AT]);
  await pool.query(`INSERT INTO human_sessions
    (id, member_id, token_hash, created_at, expires_at, recent_auth_at, revoked_at,
     organization_id, membership_id, role, csrf_token_hash, last_seen_at, idle_expires_at,
     revoke_reason, recent_auth_challenge_id, recent_auth_organization_id,
     recent_auth_operation, recent_auth_consumed_at, version,
     organization_authority_epoch, membership_session_epoch, recent_auth_context_hash)
    VALUES ($1, $2, decode($3, 'hex'), $4::timestamptz, $5::timestamptz, NULL, NULL,
      $6, $7, 'admin', decode($8, 'hex'), $9::timestamptz, $10::timestamptz,
      NULL, NULL, NULL, NULL, NULL, 9, 2, 6, NULL)`, [
    LEGACY_SESSION_ID, LEGACY_TARGET_MEMBER_ID, LEGACY_TOKEN_HASH, LEGACY_CREATED_AT,
    LEGACY_EXPIRES_AT, LEGACY_ORGANIZATION_ID, LEGACY_MEMBERSHIP_ID, LEGACY_CSRF_HASH,
    LEGACY_UPDATED_AT, LEGACY_IDLE_EXPIRES_AT
  ]);
}

export async function snapshotN3LegacyRows(pool) {
  const snapshot = {
    organizations: (await pool.query(`SELECT id::text, name, version::int AS version,
      authority_epoch::int AS authority_epoch, created_at::text, updated_at::text
      FROM organizations WHERE id = $1 ORDER BY id`, [LEGACY_ORGANIZATION_ID])).rows,
    members: (await pool.query(`SELECT id::text, github_subject, display_name, created_at::text
      FROM members WHERE id IN ($1, $2) ORDER BY id`, [LEGACY_TARGET_MEMBER_ID, LEGACY_APPROVER_MEMBER_ID])).rows,
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

async function seedN3PlatformAuthorityRows(migrationPool) {
  const client = await migrationPool.connect();
  try {
    await client.query("SELECT agentpass_platform_principal_provision($1::uuid, $2::uuid)", [PLATFORM_TARGET_PRINCIPAL_ID, LEGACY_TARGET_MEMBER_ID]);
    await client.query("SELECT agentpass_platform_principal_provision($1::uuid, $2::uuid)", [PLATFORM_APPROVER_PRINCIPAL_ID, LEGACY_APPROVER_MEMBER_ID]);
    await client.query(`SELECT agentpass_platform_operator_assignment_request(
      $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::text, $6::text,
      decode($7, 'hex'), $8::timestamptz)`, [
      PLATFORM_ASSIGNMENT_ID, PLATFORM_TARGET_PRINCIPAL_ID, LEGACY_TARGET_MEMBER_ID,
      LEGACY_ORGANIZATION_ID, "platform.promotion.issue", "platform.promotion.issue",
      PLATFORM_REQUEST_DIGEST, LEGACY_EXPIRES_AT
    ]);
    await client.query(`SELECT agentpass_platform_operator_assignment_approve(
      $1::uuid, $2::uuid, $3::uuid, decode($4, 'hex'))`, [
      PLATFORM_APPROVAL_ID, PLATFORM_ASSIGNMENT_ID, PLATFORM_APPROVER_PRINCIPAL_ID,
      PLATFORM_REQUEST_DIGEST
    ]);
  } finally {
    client.release();
  }
}

async function main() {
  const adminUrl = process.env.AGENTPASS_N3_POSTGRES_ADMIN_URL ?? process.env.AGENTPASS_TEST_POSTGRES_ADMIN_URL;
  const migrationUrl = process.env.AGENTPASS_N3_POSTGRES_MIGRATION_URL ?? process.env.AGENTPASS_TEST_MIGRATION_DATABASE_URL;
  if (!adminUrl || !migrationUrl) {
    console.error("N3 requires explicit admin and agentpass_migrator PostgreSQL URLs; no database was qualified");
    process.exitCode = 2;
    return;
  }
  const report = await runN3UpgradeQualification({ adminUrl, migrationUrl });
  console.log(JSON.stringify(report, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
