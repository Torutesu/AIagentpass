import assert from "node:assert/strict";
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

export const N1_TARGET_VERSION = 51;
export const N1_APPLICATION_VERSION = "n1-postgres-upgrade-qualification";
export const N1_UPGRADE_START_VERSIONS = Object.freeze([47, 48]);

const AUTHORITY_PURPOSE = "agentpass.promotion-evidence";
const AUTHORITY_KEY_ID = "n1-seeded-key-v1";
const AUTHORITY_FINGERPRINT_HEX = "11".repeat(32);
const AUTHORITY_PUBLIC_KEY_PEM = "-----BEGIN PUBLIC KEY-----\nN1 seeded public key metadata only\n-----END PUBLIC KEY-----";
const CANDIDATE_DIGEST = "aa".repeat(32);
const SOURCE_COMMIT = "bb".repeat(20);
const SOURCE_TREE = "cc".repeat(20);
const RELEASE_MANIFEST_DIGEST = "dd".repeat(32);
const IMAGE_DIGEST = `sha256:${"ee".repeat(32)}`;
const SBOM_DIGEST = "ff".repeat(32);
const QUALIFICATION_DIGEST = "12".repeat(32);
const EVIDENCE_DIGEST = "13".repeat(32);
const CANDIDATE_ID = `release-pkg-sha256-v1-${CANDIDATE_DIGEST}`;
const DEPLOYMENT_ID = "n1-seeded-deployment";
const ENVIRONMENT = "staging";
const APPROVAL_ID = "00000000-0000-4000-8000-000000000047";
const PROMOTION_ID = "00000000-0000-4000-8000-000000000051";

export const N1_AUTHORITY_TABLE_SPECS = Object.freeze([
  Object.freeze({ name: "release_candidates", orderBy: "candidate_id" }),
  Object.freeze({ name: "platform_promotion_approvals", orderBy: "approval_id" }),
  Object.freeze({ name: "platform_promotion_deployments", orderBy: "deployment_id, environment" }),
  Object.freeze({ name: "platform_promotion_issuances", orderBy: "promotion_id" }),
  Object.freeze({ name: "managed_signer_key_lifecycles", orderBy: "purpose" }),
  Object.freeze({ name: "managed_signer_keys", orderBy: "purpose, key_id" }),
  Object.freeze({ name: "managed_signer_key_lifecycle_operations", orderBy: "purpose, operation_id" }),
  Object.freeze({ name: "managed_signer_signing_idempotency", orderBy: "purpose, operation_id" }),
  Object.freeze({ name: "managed_signer_provider_operations", orderBy: "purpose, operation_id" })
]);

/**
 * Build the only upgrade paths accepted by N1. Keeping the source and target
 * slices here makes it impossible for the qualification command to silently
 * exercise a different starting point or a newer, unreviewed head.
 */
export function buildN1UpgradePlan(migrations) {
  assertReviewedMigrationSet(migrations);
  return Object.freeze(N1_UPGRADE_START_VERSIONS.map((startVersion) => Object.freeze({
    startVersion,
    targetVersion: N1_TARGET_VERSION,
    bootstrap: Object.freeze(migrations.slice(0, startVersion)),
    upgrade: Object.freeze(migrations.slice(0, N1_TARGET_VERSION))
  })));
}

export function assertReviewedMigrationSet(migrations) {
  if (!Array.isArray(migrations) || migrations.length < N1_TARGET_VERSION) {
    throw new Error(`N1 requires migrations 1 through ${N1_TARGET_VERSION}`);
  }
  for (let index = 0; index < N1_TARGET_VERSION; index += 1) {
    const migration = migrations[index];
    if (!migration || migration.version !== index + 1) throw new Error(`N1 migration order is invalid at ${index + 1}`);
    if (migrationChecksum(migration.sql) !== migration.checksum) throw new Error(`N1 migration checksum is invalid at ${index + 1}`);
  }
  if (migrations[N1_TARGET_VERSION - 1].name !== "0051_managed_signer_lifecycle_signing_authority.sql") {
    throw new Error("N1 migration head is not 0051_managed_signer_lifecycle_signing_authority.sql");
  }
  return true;
}

/**
 * Validate both the immutable migration history and the runner's status view.
 * This is deliberately independent from pg so the contract is unit-testable.
 */
export function assertN1MigrationHistory({ rows, migrations, startVersion, targetVersion = N1_TARGET_VERSION, upgrade, status }) {
  if (!Number.isInteger(startVersion) || !N1_UPGRADE_START_VERSIONS.includes(startVersion)) throw new Error("N1 start version is not an approved scenario");
  if (targetVersion !== N1_TARGET_VERSION) throw new Error("N1 target version is not 0051");
  assertReviewedMigrationSet(migrations);
  const expectedRows = migrations.slice(0, targetVersion);
  assert.equal(rows.length, expectedRows.length, "schema_migrations row count must equal the reviewed head");
  for (let index = 0; index < expectedRows.length; index += 1) {
    assert.equal(Number(rows[index].version), expectedRows[index].version, `schema_migrations version ${index + 1}`);
    assert.equal(rows[index].checksum, expectedRows[index].checksum, `schema_migrations checksum ${index + 1}`);
  }
  assert.equal(Number(rows.at(-1)?.version), targetVersion, "schema_migrations head must be 0051");
  assert.deepEqual(upgrade.applied.map(({ version, checksum }) => ({ version, checksum })), expectedRows
    .slice(startVersion)
    .map(({ version, checksum }) => ({ version, checksum })));
  assert.equal(status.currentVersion, targetVersion);
  assert.deepEqual(status.pending, []);
  assert.deepEqual(status.modified, []);
  assert.equal(status.dirty, false);
  assert.deepEqual(status.dirtyRows, []);
  assert.deepEqual(status.applied.map((row) => Number(row.version)), expectedRows.map(({ version }) => version));
  return Object.freeze({ startVersion, targetVersion, historyRows: rows.length, appliedUpgradeVersions: Object.freeze(upgrade.applied.map(({ version }) => version)) });
}

export function assertAuthorityRowsPreserved(before, after) {
  assert.deepEqual(after, before, "seeded authority rows changed during the upgrade");
  return true;
}

/**
 * Run both N1 scenarios against isolated disposable databases. The admin DSN
 * is intentionally explicit: a normal application DSN must never be used for
 * a destructive qualification database lifecycle.
 */
export async function runN1UpgradeQualification({ adminUrl, migrationUrl, databaseFactory = createDisposablePostgres } = {}) {
  if (typeof adminUrl !== "string" || adminUrl.trim().length === 0) {
    throw new TypeError("N1 requires an explicit PostgreSQL admin DSN");
  }
  if (typeof migrationUrl !== "string" || migrationUrl.trim().length === 0) {
    throw new TypeError("N1 requires an explicit agentpass_migrator DSN");
  }
  if (typeof databaseFactory !== "function") throw new TypeError("N1 database factory is invalid");
  const migrations = await loadSqlMigrations();
  const plan = buildN1UpgradePlan(migrations);
  const scenarios = [];
  for (const scenario of plan) {
    const database = await databaseFactory({
      adminUrl,
      databaseName: `agentpass_n1_from_${scenario.startVersion}`
    });
    const migrationDatabaseUrl = requireVerifiedPostgresUrl(migrationUrl, "N1 PostgreSQL migrator URL");
    migrationDatabaseUrl.pathname = new URL(database.url).pathname;
    const migrationPool = new Pool({
      ...createVerifiedPostgresPoolOptions(migrationDatabaseUrl, { ca: database.caCertificate }),
      max: 2,
      connectionTimeoutMillis: 3_000,
      idleTimeoutMillis: 3_000,
    });
    try {
      scenarios.push(await qualifyScenario({ database, migrationPool, migrations, scenario }));
    } finally {
      await migrationPool.end().catch(() => {});
      await database.close();
    }
  }
  return Object.freeze({
    qualification: "postgres-upgrade",
    name: "N1",
    target_version: N1_TARGET_VERSION,
    migration_role: "agentpass_migrator",
    scenarios: Object.freeze(scenarios)
  });
}

async function qualifyScenario({ database, migrationPool, migrations, scenario }) {
  const pool = database.pool;
  await applyRolePolicy(pool);
  const bootstrapClient = await migrationPool.connect();
  try {
    const principal = await bootstrapClient.query("SELECT session_user,current_user");
    assert.equal(principal.rows[0].session_user, "agentpass_migrator");
    assert.equal(principal.rows[0].current_user, "agentpass_migrator");
    const bootstrap = await createMigrationRunner({
      client: bootstrapClient,
      migrations: scenario.bootstrap,
      applicationVersion: N1_APPLICATION_VERSION
    }).run();
    assert.equal(bootstrap.currentVersion, scenario.startVersion);
    assert.deepEqual(bootstrap.applied.map(({ version }) => version), Array.from({ length: scenario.startVersion }, (_, index) => index + 1));
  } finally {
    bootstrapClient.release();
  }

  const beforeSeed = await readMigrationHistory(pool);
  assert.equal(beforeSeed.at(-1)?.version, scenario.startVersion);
  await seedN1AuthorityRows(pool);
  const before = await snapshotN1AuthorityRows(pool);

  const upgradeClient = await migrationPool.connect();
  let upgrade;
  try {
    upgrade = await createMigrationRunner({
      client: upgradeClient,
      migrations: scenario.upgrade,
      applicationVersion: N1_APPLICATION_VERSION
    }).run();
  } finally {
    upgradeClient.release();
  }

  await applyRolePolicy(pool);
  const after = await snapshotN1AuthorityRows(pool);
  assertAuthorityRowsPreserved(before, after);
  const history = await readMigrationHistory(pool);
  const statusClient = await pool.connect();
  let status;
  try {
    status = await createMigrationRunner({
      client: statusClient,
      migrations: scenario.upgrade,
      applicationVersion: N1_APPLICATION_VERSION
    }).status();
  } finally {
    statusClient.release();
  }
  const historyReport = assertN1MigrationHistory({
    rows: history,
    migrations,
    startVersion: scenario.startVersion,
    upgrade,
    status
  });
  return Object.freeze({
    from_version: scenario.startVersion,
    to_version: N1_TARGET_VERSION,
    seeded_authority_tables: N1_AUTHORITY_TABLE_SPECS.map(({ name }) => name),
    seeded_authority_row_count: before.reduce((total, rows) => total + rows.length, 0),
    history: historyReport
  });
}

async function readMigrationHistory(pool) {
  const result = await pool.query(`SELECT version::int AS version, checksum, application_version
    FROM schema_migrations ORDER BY version`);
  return result.rows;
}

async function applyRolePolicy(pool) {
  const source = await readFile(new URL("./roles.sql", import.meta.url), "utf8");
  const executable = source.replace(/^\\set\s+ON_ERROR_STOP\s+on\s*$/mu, "").trim();
  assert.doesNotMatch(executable, /^\\/mu, "the existing role fixture contains an unsupported psql directive");
  await pool.query(executable);
}

export async function snapshotN1AuthorityRows(pool) {
  const result = new Map();
  for (const { name, orderBy } of N1_AUTHORITY_TABLE_SPECS) {
    const rows = await pool.query(`SELECT * FROM public.${name} ORDER BY ${orderBy}`);
    result.set(name, rows.rows);
  }
  return result;
}

async function seedN1AuthorityRows(pool) {
  await pool.query(`INSERT INTO managed_signer_key_lifecycles
    (purpose, algorithm, version, max_keys, max_verification_overlap_ms)
    VALUES ($1, 'ed25519', 1, 4, 7776000000)`, [AUTHORITY_PURPOSE]);
  await pool.query(`INSERT INTO managed_signer_keys
    (purpose, key_id, key_version, algorithm, public_key_fingerprint, public_key_pem, state, state_version, key_position)
    VALUES ($1, $2, 1, 'ed25519', decode($3, 'hex'), $4, 'active', 1, 0)`, [
    AUTHORITY_PURPOSE,
    AUTHORITY_KEY_ID,
    AUTHORITY_FINGERPRINT_HEX,
    AUTHORITY_PUBLIC_KEY_PEM
  ]);
  await pool.query(`INSERT INTO managed_signer_key_lifecycle_operations
    (purpose, operation_id, request_digest, response_snapshot, expires_at)
    VALUES ($1, 'n1-seeded-lifecycle-operation', decode($2, 'hex'), $3::jsonb, clock_timestamp() + interval '1 hour')`, [
    AUTHORITY_PURPOSE,
    "21".repeat(32),
    JSON.stringify({ version: 1, purpose: AUTHORITY_PURPOSE, algorithm: "ed25519", keys: [] })
  ]);
  await pool.query(`INSERT INTO managed_signer_signing_idempotency
    (purpose, operation_id, request_digest, key_id, key_version, status, signature, expires_at)
    VALUES ($1, 'n1-seeded-signing-operation', decode($2, 'hex'), $3, 1, 'committed', decode($4, 'hex'), clock_timestamp() + interval '1 hour')`, [
    AUTHORITY_PURPOSE,
    "22".repeat(32),
    AUTHORITY_KEY_ID,
    "23".repeat(64)
  ]);
  await pool.query(`INSERT INTO managed_signer_provider_operations
    (purpose, operation_id, algorithm, bytes_length, request_digest, key_id, key_version, state,
     signature, public_key_der, provider_receipt_provider, provider_receipt_id, provider_started_at, expires_at)
    VALUES ($1, 'n1-seeded-provider-operation', 'ed25519', 32, decode($2, 'hex'), $3, 1, 'committed',
      decode($4, 'hex'), decode($5, 'hex'), 'n1-provider', 'n1-receipt', clock_timestamp(), clock_timestamp() + interval '1 hour')`, [
    AUTHORITY_PURPOSE,
    "24".repeat(32),
    AUTHORITY_KEY_ID,
    "25".repeat(64),
    "26".repeat(44)
  ]);
  await pool.query(`INSERT INTO release_candidates
    (candidate_id, source_commit, artifact_sha256, manifest_sha256, team_id, status)
    VALUES ($1, $2, $3, $4, 'N1QUALIFY0', 'active')`, [
    CANDIDATE_ID,
    SOURCE_COMMIT,
    CANDIDATE_DIGEST,
    RELEASE_MANIFEST_DIGEST
  ]);
  await pool.query(`INSERT INTO platform_promotion_deployments
    (deployment_id, environment, current_generation, current_candidate_id)
    VALUES ($1, $2, 1, $3)`, [DEPLOYMENT_ID, ENVIRONMENT, CANDIDATE_ID]);
  await pool.query(`INSERT INTO platform_promotion_approvals
    (approval_id, deployment_id, environment, candidate_id, source_commit, source_tree,
     product_pkg_sha256, image_digest, sbom_sha256, qualification_report_digests,
     release_manifest_schema_version, release_manifest_sha256, policy_id, policy_version,
     approval_version, decision, platform_principal_ids, authorization_evidence_digests,
     approved_at, expires_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, ARRAY[$10], 4, $11, 'n1-seeded-policy', 1,
      1, 'approved', ARRAY['n1-principal'], ARRAY[$12], clock_timestamp(), clock_timestamp() + interval '30 minutes')`, [
    APPROVAL_ID,
    DEPLOYMENT_ID,
    ENVIRONMENT,
    CANDIDATE_ID,
    SOURCE_COMMIT,
    SOURCE_TREE,
    CANDIDATE_DIGEST,
    IMAGE_DIGEST,
    SBOM_DIGEST,
    QUALIFICATION_DIGEST,
    RELEASE_MANIFEST_DIGEST,
    QUALIFICATION_DIGEST
  ]);
  const approval = await pool.query("SELECT record_digest, expires_at FROM platform_promotion_approvals WHERE approval_id = $1", [APPROVAL_ID]);
  assert.equal(approval.rows.length, 1);
  await pool.query(`INSERT INTO platform_promotion_issuances
    (promotion_id, deployment_id, environment, candidate_id, idempotency_key, state,
     approval_id, approval_digest, source_commit, source_tree, product_pkg_sha256,
     image_digest, sbom_sha256, qualification_report_digests, release_manifest_schema_version,
     release_manifest_sha256, approval_expires_at, issued_at, expires_at, purpose,
     protocol_version, signing_version, lifecycle_version, key_id, key_version,
     signer_key_fingerprint, provider_operation_id, request_digest, evidence_bytes,
     evidence_digest, deployment_generation)
    VALUES ($1, $2, $3, $4, 'n1-seeded-issuance', 'committed', $5, $6, $7, $8, $9, $10, $11,
      ARRAY[$12], 4, $13, $14, clock_timestamp(), clock_timestamp() + interval '15 minutes',
      $15, 3, 3, 1, $16, 1, decode($17, 'hex'), 'n1-seeded-provider-operation', decode($18, 'hex'),
      convert_to('n1 seeded evidence', 'UTF8'), sha256(convert_to('n1 seeded evidence', 'UTF8')), 1)`, [
    PROMOTION_ID,
    DEPLOYMENT_ID,
    ENVIRONMENT,
    CANDIDATE_ID,
    APPROVAL_ID,
    approval.rows[0].record_digest,
    SOURCE_COMMIT,
    SOURCE_TREE,
    CANDIDATE_DIGEST,
    IMAGE_DIGEST,
    SBOM_DIGEST,
    QUALIFICATION_DIGEST,
    RELEASE_MANIFEST_DIGEST,
    approval.rows[0].expires_at,
    AUTHORITY_PURPOSE,
    AUTHORITY_KEY_ID,
    AUTHORITY_FINGERPRINT_HEX,
    "27".repeat(32)
  ]);
}

async function main() {
  const adminUrl = process.env.AGENTPASS_N1_POSTGRES_ADMIN_URL ?? process.env.AGENTPASS_TEST_POSTGRES_ADMIN_URL;
  const migrationUrl = process.env.AGENTPASS_N1_POSTGRES_MIGRATION_URL ?? process.env.AGENTPASS_TEST_MIGRATION_DATABASE_URL;
  if (!adminUrl || !migrationUrl) {
    console.error("N1 requires explicit admin and agentpass_migrator PostgreSQL URLs; no database was qualified");
    process.exitCode = 2;
    return;
  }
  const report = await runN1UpgradeQualification({ adminUrl, migrationUrl });
  console.log(JSON.stringify(report, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
