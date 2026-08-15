import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFileSync } from "node:fs";
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

export const N4_SOURCE_VERSION = 53;
export const N4_TARGET_VERSION = 54;
export const N4_APPLICATION_VERSION = "n4-postgres-upgrade-qualification";
export const N4_MIGRATION_NAME = "0054_platform_authorization.sql";
export const N4_REPORT_SCHEMA_VERSION = 1;
export const N4_AUTHORITY_TAP_LABEL = "0054";
export const N4_AUTHORITY_TEST_FILES = Object.freeze([
  "apps/cloud-api/test/postgres/platform-authorization-migration.test.mjs",
  "apps/cloud-api/test/postgres/platform-authorization.integration.test.mjs"
]);

export const N4_LEGACY_TABLE_SPECS = Object.freeze([
  Object.freeze({ name: "organizations", orderBy: "id" }),
  Object.freeze({ name: "members", orderBy: "id" }),
  Object.freeze({ name: "memberships", orderBy: "organization_id,id" }),
  Object.freeze({ name: "human_sessions", orderBy: "id" })
]);

export const N4_PLATFORM_AUTHORITY_TABLE_SPECS = Object.freeze([
  Object.freeze({ name: "platform_principals", orderBy: "principal_id" }),
  Object.freeze({ name: "platform_operator_assignments", orderBy: "assignment_id" }),
  Object.freeze({ name: "platform_operator_assignment_approvals", orderBy: "assignment_id, approver_principal_id" })
]);

const LEGACY_ORGANIZATION_ID = "00000000-0000-4000-8000-000000000401";
const LEGACY_TARGET_MEMBER_ID = "00000000-0000-4000-8000-000000000402";
const LEGACY_APPROVER_MEMBER_ID = "00000000-0000-4000-8000-000000000403";
const LEGACY_MEMBERSHIP_ID = "00000000-0000-4000-8000-000000000404";
const LEGACY_SESSION_ID = "00000000-0000-4000-8000-000000000405";
const PLATFORM_TARGET_PRINCIPAL_ID = "00000000-0000-4000-8000-000000000411";
const PLATFORM_APPROVER_PRINCIPAL_ID = "00000000-0000-4000-8000-000000000412";
const PLATFORM_ASSIGNMENT_ID = "00000000-0000-4000-8000-000000000413";
const PLATFORM_APPROVAL_ID = "00000000-0000-4000-8000-000000000414";
const PLATFORM_CREDENTIAL_ID = "00000000-0000-4000-8000-000000000415";
const PLATFORM_SESSION_ID = "00000000-0000-4000-8000-000000000416";
const PLATFORM_WEBAUTHN_ID = Buffer.alloc(32, 0x61);
const PLATFORM_SESSION_MATERIAL_HASH = Buffer.alloc(32, 0x62);
const PLATFORM_REQUEST_DIGEST = Buffer.alloc(32, 0x63);
const LEGACY_CREATED_AT = "2099-01-01T00:00:00.000Z";
const LEGACY_UPDATED_AT = "2099-01-01T00:00:01.000Z";
const LEGACY_EXPIRES_AT = "2099-01-01T01:00:00.000Z";
const LEGACY_IDLE_EXPIRES_AT = "2099-01-01T00:30:00.000Z";
const LEGACY_TOKEN_HASH = "71".repeat(32);
const LEGACY_CSRF_HASH = "72".repeat(32);
const PLATFORM_OPERATION = "platform.promotion.issue";

function stableSnapshotDigest(snapshot) {
  return crypto.createHash("sha256").update(JSON.stringify(snapshot), "utf8").digest("hex");
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function normalizeMigrationRows(rows) {
  if (!Array.isArray(rows)) throw new TypeError("N4 migration history rows must be an array");
  return rows.map((row) => ({ version: Number(row?.version), checksum: row?.checksum }));
}

export function buildN4UpgradePlan(migrations) {
  assertReviewedN4MigrationSet(migrations);
  return Object.freeze([Object.freeze({
    startVersion: N4_SOURCE_VERSION,
    targetVersion: N4_TARGET_VERSION,
    bootstrap: Object.freeze(migrations.slice(0, N4_SOURCE_VERSION)),
    upgrade: Object.freeze(migrations.slice(0, N4_TARGET_VERSION))
  })]);
}

export function assertReviewedN4MigrationSet(migrations) {
  if (!Array.isArray(migrations) || migrations.length < N4_TARGET_VERSION) {
    throw new Error(`N4 requires migrations 1 through ${N4_TARGET_VERSION}`);
  }
  for (let index = 0; index < N4_TARGET_VERSION; index += 1) {
    const migration = migrations[index];
    if (!migration || migration.version !== index + 1) throw new Error(`N4 migration order is invalid at ${index + 1}`);
    if (migrationChecksum(migration.sql) !== migration.checksum) throw new Error(`N4 migration checksum is invalid at ${index + 1}`);
  }
  if (migrations[N4_SOURCE_VERSION - 1]?.name !== "0053_platform_sessions.sql") {
    throw new Error("N4 source head is not 0053_platform_sessions.sql");
  }
  if (migrations[N4_TARGET_VERSION - 1]?.name !== N4_MIGRATION_NAME) {
    throw new Error(`N4 migration head is not ${N4_MIGRATION_NAME}`);
  }
  return true;
}

export function assertLegacyRowsPreserved(before, after) {
  assert.deepEqual(after, before, "0054 must preserve seeded legacy organization, member, membership, and human session rows exactly");
  assert.deepEqual(N4_LEGACY_TABLE_SPECS.map(({ name }) => before?.[name]?.length ?? 0), [1, 2, 1, 1], "N4 legacy fixture must contain the reviewed tenant/session rows");
  return true;
}

export function assertPlatformAuthorityRowsPreserved(before, after) {
  assert.deepEqual(after, before, "0054 must preserve seeded principal, assignment, and approval rows exactly");
  assert.equal(before.platform_principals.length, 2);
  assert.equal(before.platform_operator_assignments.length, 1);
  assert.equal(before.platform_operator_assignment_approvals.length, 1);
  return true;
}

export function assertPlatformCredentialsPreserved(before, after) {
  assert.deepEqual(after, before, "0054 must preserve seeded platform credential rows exactly");
  assert.equal(before.length, 1, "N4 must seed exactly one platform credential");
  return true;
}

export function assertPlatformSessionUpgrade(before, after) {
  assert.equal(before.length, 1, "N4 must seed exactly one platform session before upgrade");
  assert.equal(after.length, 1, "N4 must preserve exactly one platform session after upgrade");
  const beforeRow = before[0];
  const afterRow = after[0];
  for (const field of [
    "session_id", "principal_id", "member_id", "organization_id", "assignment_id", "credential_id",
    "operation", "capability", "principal_authority_generation", "assignment_version", "credential_version",
    "idle_timeout_seconds", "created_at", "authenticated_at", "expires_at"
  ]) assert.equal(afterRow[field], beforeRow[field], `0054 must preserve platform session ${field}`);
  assert.equal(beforeRow.status, "active");
  assert.equal(afterRow.status, "revoked");
  assert.equal(afterRow.version, beforeRow.version + 1);
  assert.equal(afterRow.revoke_reason, "request_binding_migration");
  assert.equal(afterRow.csrf_token_hash, sha256Hex(`agentpass:0054:csrf:${PLATFORM_SESSION_ID}`));
  assert.equal(afterRow.request_digest_sha256, sha256Hex(`agentpass:0054:request:${PLATFORM_SESSION_ID}`));
  assert.deepEqual(afterRow.allowed_credential_ids, [PLATFORM_WEBAUTHN_ID.toString("base64url")]);
  return true;
}

export function assertN4MigrationHistory({
  rows,
  migrations,
  upgrade,
  status,
  identity,
  authorityBefore,
  authorityAfter,
  credentialsBefore,
  credentialsAfter,
  sessionsBefore,
  sessionsAfter,
  legacyBefore,
  legacyAfter,
  startVersion = N4_SOURCE_VERSION,
  targetVersion = N4_TARGET_VERSION
}) {
  if (startVersion !== N4_SOURCE_VERSION) throw new Error("N4 start version must be 0053");
  if (targetVersion !== N4_TARGET_VERSION) throw new Error("N4 target version must be 0054");
  assertReviewedN4MigrationSet(migrations);
  const expectedRows = migrations.slice(0, N4_TARGET_VERSION).map(({ version, checksum }) => ({ version, checksum }));
  assert.deepEqual(normalizeMigrationRows(rows), expectedRows, "schema_migrations must contain the exact reviewed 1..54 history and checksums");
  assert.deepEqual(upgrade?.applied?.map(({ version, checksum }) => ({ version, checksum })), expectedRows.slice(N4_SOURCE_VERSION), "N4 must apply exactly migration 0054 from a 0053 database");
  assert.equal(status?.currentVersion, N4_TARGET_VERSION);
  assert.deepEqual(status?.pending, []);
  assert.deepEqual(status?.modified, []);
  assert.equal(status?.dirty, false);
  assert.deepEqual(status?.dirtyRows, []);
  assert.deepEqual(normalizeMigrationRows(status?.applied), expectedRows, "status must expose the exact applied history");
  assert.deepEqual(identity, { session_user: "agentpass_migrator", current_user: "agentpass_migrator" });
  assertPlatformAuthorityRowsPreserved(authorityBefore, authorityAfter);
  assertPlatformCredentialsPreserved(credentialsBefore, credentialsAfter);
  assertPlatformSessionUpgrade(sessionsBefore, sessionsAfter);
  assertLegacyRowsPreserved(legacyBefore, legacyAfter);
  return Object.freeze({
    startVersion: N4_SOURCE_VERSION,
    targetVersion: N4_TARGET_VERSION,
    historyRows: expectedRows.length,
    history: Object.freeze(expectedRows.map(({ version, checksum }) => Object.freeze({ version, checksum }))),
    appliedUpgradeVersions: Object.freeze([N4_TARGET_VERSION]),
    status: "clean",
    migration_identity: Object.freeze({ session_user: "agentpass_migrator", current_user: "agentpass_migrator" }),
    seeded_legacy_row_count: N4_LEGACY_TABLE_SPECS.reduce((total, { name }) => total + legacyBefore[name].length, 0),
    seeded_platform_credential_row_count: credentialsBefore.length,
    seeded_platform_session_row_count: sessionsBefore.length,
    legacy_preservation: Object.freeze({
      exact: true,
      tables: Object.freeze(N4_LEGACY_TABLE_SPECS.map(({ name }) => Object.freeze({ name, row_count: legacyBefore[name].length }))),
      snapshot_sha256: stableSnapshotDigest(legacyBefore)
    }),
    platform_authority_preservation: Object.freeze({
      exact: true,
      tables: Object.freeze(N4_PLATFORM_AUTHORITY_TABLE_SPECS.map(({ name }) => Object.freeze({ name, row_count: authorityBefore[name].length }))),
      snapshot_sha256: stableSnapshotDigest(authorityBefore)
    }),
    platform_credential_preservation: Object.freeze({
      exact: true,
      row_count: credentialsBefore.length,
      snapshot_sha256: stableSnapshotDigest(credentialsBefore)
    }),
    platform_session_upgrade: Object.freeze({
      immutable_binding_exact: true,
      before_status: sessionsBefore[0].status,
      after_status: sessionsAfter[0].status,
      invalidated_for_request_binding: true,
      before_snapshot_sha256: stableSnapshotDigest(sessionsBefore),
      after_snapshot_sha256: stableSnapshotDigest(sessionsAfter)
    })
  });
}

export function parseN4AuthorityTapEvidence(filePath) {
  if (!filePath) return Object.freeze({ required: true, present: false, label: N4_AUTHORITY_TAP_LABEL, test_files: N4_AUTHORITY_TEST_FILES });
  const output = readFileSync(filePath);
  const text = output.toString("utf8");
  if (/^Bail out!/mu.test(text) || /(^|[\t\r\n ])# (?:SKIP|TODO)([\t\r\n ]|$)/mu.test(text)) {
    throw new Error("N4 authority TAP contains an incomplete test");
  }
  const tests = [...text.matchAll(/^ok\s+/gmu)].length;
  if (tests < 1) throw new Error("N4 authority TAP contains no passing tests");
  return Object.freeze({
    required: true,
    present: true,
    label: N4_AUTHORITY_TAP_LABEL,
    test_files: N4_AUTHORITY_TEST_FILES,
    tests,
    tap_sha256: crypto.createHash("sha256").update(output).digest("hex")
  });
}

function requireN4AdminUrl(value) {
  const url = requireVerifiedPostgresUrl(value, "N4 PostgreSQL admin URL");
  if (decodeURIComponent(url.username) === "agentpass_migrator") throw new TypeError("N4 admin URL must not use agentpass_migrator");
  return url;
}

function requireN4MigrationUrl(value) {
  const url = requireVerifiedPostgresUrl(value, "N4 PostgreSQL migrator URL");
  if (decodeURIComponent(url.username) !== "agentpass_migrator") throw new TypeError("N4 migration URL must use agentpass_migrator");
  return url;
}

export async function runN4UpgradeQualification({ adminUrl, migrationUrl, databaseFactory = createDisposablePostgres, authorityTapPath } = {}) {
  const admin = requireN4AdminUrl(adminUrl);
  const migration = requireN4MigrationUrl(migrationUrl);
  if (typeof databaseFactory !== "function") throw new TypeError("N4 database factory is invalid");
  const migrations = await loadSqlMigrations();
  const [scenario] = buildN4UpgradePlan(migrations);
  const database = await databaseFactory({
    adminUrl: admin.toString(),
    databaseName: `agentpass_n4_from_${scenario.startVersion}`
  });
  migration.pathname = new URL(database.url).pathname;
  const migrationPool = new Pool({
    ...createVerifiedPostgresPoolOptions(migration, { ca: database.caCertificate }),
    max: 2,
    connectionTimeoutMillis: 3_000,
    idleTimeoutMillis: 3_000
  });
  try {
    const report = await qualifyScenario({ database, migrationPool, migrations, scenario });
    return Object.freeze({ ...report, authority_test_evidence: parseN4AuthorityTapEvidence(authorityTapPath ?? process.env.AGENTPASS_N4_AUTHORITY_TAP) });
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
      applicationVersion: N4_APPLICATION_VERSION
    }).run();
    assert.equal(bootstrap.currentVersion, N4_SOURCE_VERSION);
    assert.deepEqual(bootstrap.applied.map(({ version }) => version), Array.from({ length: N4_SOURCE_VERSION }, (_, index) => index + 1));
  } finally {
    bootstrapClient.release();
  }

  await seedN4LegacyRows(database.pool);
  const legacyBefore = await snapshotN4LegacyRows(database.pool);
  await seedN4PlatformRows(migrationPool, database.pool);
  const authorityBefore = await snapshotN4PlatformAuthorityRows(database.pool);
  const credentialsBefore = await snapshotN4PlatformCredentialRows(database.pool);
  const sessionsBefore = await snapshotN4PlatformSessionRows(database.pool, false);
  assert.equal(sessionsBefore[0]?.status, "active");

  const upgradeClient = await migrationPool.connect();
  let upgrade;
  let identity;
  try {
    identity = await readIdentity(upgradeClient);
    assertMigratorIdentity(identity);
    upgrade = await createMigrationRunner({
      client: upgradeClient,
      migrations: scenario.upgrade,
      applicationVersion: N4_APPLICATION_VERSION
    }).run();
  } finally {
    upgradeClient.release();
  }

  await applyRolePolicy(database.pool);
  const legacyAfter = await snapshotN4LegacyRows(database.pool);
  const authorityAfter = await snapshotN4PlatformAuthorityRows(database.pool);
  const credentialsAfter = await snapshotN4PlatformCredentialRows(database.pool);
  const sessionsAfter = await snapshotN4PlatformSessionRows(database.pool, true);
  const history = await readMigrationHistory(database.pool);
  const statusClient = await migrationPool.connect();
  let status;
  try {
    assertMigratorIdentity(await readIdentity(statusClient));
    status = await createMigrationRunner({ client: statusClient, migrations: scenario.upgrade, applicationVersion: N4_APPLICATION_VERSION }).status();
  } finally {
    statusClient.release();
  }
  const historyReport = assertN4MigrationHistory({
    rows: history, migrations, upgrade, status, identity,
    authorityBefore, authorityAfter, credentialsBefore, credentialsAfter,
    sessionsBefore, sessionsAfter, legacyBefore, legacyAfter
  });
  return Object.freeze({
    qualification: "postgres-upgrade",
    report_schema_version: N4_REPORT_SCHEMA_VERSION,
    name: "N4",
    source_version: N4_SOURCE_VERSION,
    target_version: N4_TARGET_VERSION,
    migration_name: N4_MIGRATION_NAME,
    migration_role: "agentpass_migrator",
    scenarios: Object.freeze([Object.freeze({
      from_version: N4_SOURCE_VERSION,
      to_version: N4_TARGET_VERSION,
      seeded_legacy_row_count: historyReport.seeded_legacy_row_count,
      seeded_platform_authority_row_count: 4,
      seeded_platform_credential_row_count: historyReport.seeded_platform_credential_row_count,
      seeded_platform_session_row_count: historyReport.seeded_platform_session_row_count,
      legacy_preservation: historyReport.legacy_preservation,
      platform_authority_preservation: historyReport.platform_authority_preservation,
      platform_credential_preservation: historyReport.platform_credential_preservation,
      platform_session_upgrade: historyReport.platform_session_upgrade,
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
  return (await pool.query("SELECT version::int AS version, checksum FROM schema_migrations ORDER BY version")).rows;
}

async function applyRolePolicy(pool) {
  const source = await readFile(new URL("./roles.sql", import.meta.url), "utf8");
  const executable = source.replace(/^\\set\s+ON_ERROR_STOP\s+on\s*$/mu, "").trim();
  assert.doesNotMatch(executable, /^\\/mu, "the role fixture contains an unsupported psql directive");
  await pool.query(executable);
}

async function seedN4LegacyRows(pool) {
  await pool.query(`INSERT INTO organizations
    (id, name, version, created_at, updated_at, authority_epoch)
    VALUES ($1, 'N4 seeded legacy organization', 7, $2::timestamptz, $3::timestamptz, 3)`, [LEGACY_ORGANIZATION_ID, LEGACY_CREATED_AT, LEGACY_UPDATED_AT]);
  await pool.query(`INSERT INTO members
    (id, github_subject, display_name, created_at)
    VALUES ($1, 'n4-seeded-target-member', 'N4 seeded target member', $3::timestamptz),
           ($2, 'n4-seeded-approver-member', 'N4 seeded approver member', $3::timestamptz)`, [LEGACY_TARGET_MEMBER_ID, LEGACY_APPROVER_MEMBER_ID, LEGACY_CREATED_AT]);
  await pool.query(`INSERT INTO memberships
    (organization_id, id, member_id, role, status, version, created_at, updated_at, session_epoch)
    VALUES ($1, $2, $3, 'admin', 'active', 4, $4::timestamptz, $5::timestamptz, 8)`, [LEGACY_ORGANIZATION_ID, LEGACY_MEMBERSHIP_ID, LEGACY_TARGET_MEMBER_ID, LEGACY_CREATED_AT, LEGACY_UPDATED_AT]);
  await pool.query(`INSERT INTO human_sessions
    (id, member_id, token_hash, created_at, expires_at, recent_auth_at, revoked_at,
     organization_id, membership_id, role, csrf_token_hash, last_seen_at, idle_expires_at,
     revoke_reason, recent_auth_challenge_id, recent_auth_organization_id,
     recent_auth_operation, recent_auth_consumed_at, version,
     organization_authority_epoch, membership_session_epoch, recent_auth_context_hash)
    VALUES ($1, $2, decode($3, 'hex'), $4::timestamptz, $5::timestamptz, NULL, NULL,
      $6, $7, 'admin', decode($8, 'hex'), $9::timestamptz, $10::timestamptz,
      NULL, NULL, NULL, NULL, NULL, 11, 3, 8, NULL)`, [
    LEGACY_SESSION_ID, LEGACY_TARGET_MEMBER_ID, LEGACY_TOKEN_HASH, LEGACY_CREATED_AT,
    LEGACY_EXPIRES_AT, LEGACY_ORGANIZATION_ID, LEGACY_MEMBERSHIP_ID, LEGACY_CSRF_HASH,
    LEGACY_UPDATED_AT, LEGACY_IDLE_EXPIRES_AT
  ]);
}

async function seedN4PlatformRows(migrationPool, adminPool) {
  await adminPool.query(`INSERT INTO webauthn_credentials
    (id, member_id, public_key, sign_count, transports, label, backup_eligible, backup_state)
    VALUES ($1, $2, $3, 0, ARRAY['internal']::text[], 'N4 platform credential', false, false)`, [PLATFORM_WEBAUTHN_ID, LEGACY_TARGET_MEMBER_ID, Buffer.alloc(32, 0x64)]);
  const client = await migrationPool.connect();
  try {
    await client.query("SELECT agentpass_platform_principal_provision($1::uuid, $2::uuid)", [PLATFORM_TARGET_PRINCIPAL_ID, LEGACY_TARGET_MEMBER_ID]);
    await client.query("SELECT agentpass_platform_principal_provision($1::uuid, $2::uuid)", [PLATFORM_APPROVER_PRINCIPAL_ID, LEGACY_APPROVER_MEMBER_ID]);
    await client.query(`SELECT agentpass_platform_operator_assignment_request(
      $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::text, $6::text,
      decode($7, 'hex'), $8::timestamptz)`, [
      PLATFORM_ASSIGNMENT_ID, PLATFORM_TARGET_PRINCIPAL_ID, LEGACY_TARGET_MEMBER_ID,
      LEGACY_ORGANIZATION_ID, PLATFORM_OPERATION, PLATFORM_OPERATION,
      PLATFORM_REQUEST_DIGEST.toString("hex"), LEGACY_EXPIRES_AT
    ]);
    await client.query(`SELECT agentpass_platform_operator_assignment_approve(
      $1::uuid, $2::uuid, $3::uuid, decode($4, 'hex'))`, [
      PLATFORM_APPROVAL_ID, PLATFORM_ASSIGNMENT_ID, PLATFORM_APPROVER_PRINCIPAL_ID,
      PLATFORM_REQUEST_DIGEST.toString("hex")
    ]);
    await client.query(`SELECT agentpass_platform_credential_provision(
      $1::uuid, $2::uuid, $3::uuid, $4::bytea, $5::text)`, [
      PLATFORM_CREDENTIAL_ID, PLATFORM_TARGET_PRINCIPAL_ID, LEGACY_TARGET_MEMBER_ID,
      PLATFORM_WEBAUTHN_ID, "N4 platform credential"
    ]);
    await client.query(`SELECT agentpass_platform_session_issue(
      $1::uuid, $2::bytea, $3::uuid, $4::uuid, $5::uuid, $6::uuid, $7::uuid,
      $8::text, $9::text, 900, 300)`, [
      PLATFORM_SESSION_ID, PLATFORM_SESSION_MATERIAL_HASH, PLATFORM_TARGET_PRINCIPAL_ID,
      LEGACY_TARGET_MEMBER_ID, LEGACY_ORGANIZATION_ID, PLATFORM_ASSIGNMENT_ID,
      PLATFORM_CREDENTIAL_ID, PLATFORM_OPERATION, PLATFORM_OPERATION
    ]);
  } finally {
    client.release();
  }
}

export async function snapshotN4LegacyRows(pool) {
  const snapshot = {
    organizations: (await pool.query(`SELECT id::text, name, version::int AS version, authority_epoch::int AS authority_epoch, created_at::text, updated_at::text FROM organizations WHERE id = $1 ORDER BY id`, [LEGACY_ORGANIZATION_ID])).rows,
    members: (await pool.query(`SELECT id::text, github_subject, display_name, created_at::text FROM members WHERE id IN ($1, $2) ORDER BY id`, [LEGACY_TARGET_MEMBER_ID, LEGACY_APPROVER_MEMBER_ID])).rows,
    memberships: (await pool.query(`SELECT organization_id::text, id::text, member_id::text, role, status, version::int AS version, session_epoch::int AS session_epoch, created_at::text, updated_at::text FROM memberships WHERE organization_id = $1 AND id = $2 ORDER BY organization_id,id`, [LEGACY_ORGANIZATION_ID, LEGACY_MEMBERSHIP_ID])).rows,
    human_sessions: (await pool.query(`SELECT id::text, member_id::text, encode(token_hash, 'hex') AS token_hash, created_at::text, expires_at::text, recent_auth_at::text, revoked_at::text, organization_id::text, membership_id::text, role, encode(csrf_token_hash, 'hex') AS csrf_token_hash, last_seen_at::text, idle_expires_at::text, revoke_reason, recent_auth_challenge_id::text, recent_auth_organization_id::text, recent_auth_operation, recent_auth_consumed_at::text, version::int AS version, organization_authority_epoch::int AS organization_authority_epoch, membership_session_epoch::int AS membership_session_epoch, encode(recent_auth_context_hash, 'hex') AS recent_auth_context_hash FROM human_sessions WHERE id = $1 ORDER BY id`, [LEGACY_SESSION_ID])).rows
  };
  return Object.freeze(Object.fromEntries(Object.entries(snapshot).map(([name, rows]) => [name, Object.freeze(rows.map((row) => Object.freeze(row)))])));
}

export async function snapshotN4PlatformAuthorityRows(pool) {
  const principals = (await pool.query(`SELECT principal_id::text, member_id::text, status, status_reason, authority_generation::int AS authority_generation, version::int AS version, created_at::text, updated_at::text FROM platform_principals ORDER BY principal_id`)).rows;
  const assignments = (await pool.query(`SELECT assignment_id::text, principal_id::text, member_id::text, organization_id::text, operation, capability, status, encode(request_digest, 'hex') AS request_digest, requested_authority_generation::int AS requested_authority_generation, version::int AS version, requested_at::text, issued_at::text, expires_at::text, activated_at::text, suspended_at::text, revoked_at::text, replaced_at::text, suspend_reason, revoke_reason, replace_reason, updated_at::text FROM platform_operator_assignments ORDER BY assignment_id`)).rows;
  const approvals = (await pool.query(`SELECT approval_id::text, assignment_id::text, approver_principal_id::text, encode(request_digest, 'hex') AS request_digest, approver_authority_generation::int AS approver_authority_generation, approved_at::text FROM platform_operator_assignment_approvals ORDER BY assignment_id, approver_principal_id`)).rows;
  return Object.freeze({ platform_principals: Object.freeze(principals), platform_operator_assignments: Object.freeze(assignments), platform_operator_assignment_approvals: Object.freeze(approvals) });
}

export async function snapshotN4PlatformCredentialRows(pool) {
  const rows = (await pool.query(`SELECT credential_id::text, principal_id::text, member_id::text, encode(webauthn_credential_id, 'hex') AS webauthn_credential_id, label, status, sign_count::int AS sign_count, sign_count_state, backup_eligible, backup_state, version::int AS version, created_at::text, updated_at::text, last_used_at::text, clone_detected_at::text, revoked_at::text, revoke_reason FROM platform_credentials ORDER BY credential_id`)).rows;
  return Object.freeze(rows.map((row) => Object.freeze(row)));
}

export async function snapshotN4PlatformSessionRows(pool, migrated) {
  const columns = migrated
    ? `session_id::text, session_material_hash, csrf_token_hash, request_digest_sha256, ARRAY(SELECT rtrim(translate(replace(encode(item, 'base64'), chr(10), ''), '+/', '-_'), '=') FROM unnest(allowed_webauthn_credential_ids) AS item) AS allowed_credential_ids, principal_id::text, member_id::text, organization_id::text, assignment_id::text, credential_id::text, operation, capability, principal_authority_generation::int AS principal_authority_generation, assignment_version::int AS assignment_version, credential_version::int AS credential_version, idle_timeout_seconds, status, version::int AS version, created_at::text, authenticated_at::text, last_seen_at::text, expires_at::text, idle_expires_at::text, expired_at::text, revoked_at::text, revoke_reason`
    : `session_id::text, session_material_hash, principal_id::text, member_id::text, organization_id::text, assignment_id::text, credential_id::text, operation, capability, principal_authority_generation::int AS principal_authority_generation, assignment_version::int AS assignment_version, credential_version::int AS credential_version, idle_timeout_seconds, status, version::int AS version, created_at::text, authenticated_at::text, last_seen_at::text, expires_at::text, idle_expires_at::text, expired_at::text, revoked_at::text, revoke_reason`;
  const result = await pool.query(`SELECT ${columns} FROM platform_sessions WHERE session_id = $1 ORDER BY session_id`, [PLATFORM_SESSION_ID]);
  return Object.freeze(result.rows.map((row) => Object.freeze({
    ...row,
    session_material_hash: Buffer.isBuffer(row.session_material_hash) ? row.session_material_hash.toString("hex") : row.session_material_hash,
    csrf_token_hash: Buffer.isBuffer(row.csrf_token_hash) ? row.csrf_token_hash.toString("hex") : row.csrf_token_hash,
    request_digest_sha256: Buffer.isBuffer(row.request_digest_sha256) ? row.request_digest_sha256.toString("hex") : row.request_digest_sha256,
    allowed_credential_ids: row.allowed_credential_ids ?? undefined
  })));
}

async function main() {
  const adminUrl = process.env.AGENTPASS_N4_POSTGRES_ADMIN_URL ?? process.env.AGENTPASS_TEST_POSTGRES_ADMIN_URL;
  const migrationUrl = process.env.AGENTPASS_N4_POSTGRES_MIGRATION_URL ?? process.env.AGENTPASS_TEST_MIGRATION_DATABASE_URL;
  if (!adminUrl || !migrationUrl) {
    console.error("N4 requires explicit admin and agentpass_migrator PostgreSQL URLs; no database was qualified");
    process.exitCode = 2;
    return;
  }
  const report = await runN4UpgradeQualification({ adminUrl, migrationUrl });
  console.log(JSON.stringify(report, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
