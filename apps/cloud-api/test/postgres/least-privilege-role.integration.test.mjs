import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { Pool } from "pg";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const ROLE_NAMES = Object.freeze({ app: "agentpass_app", signer: "agentpass_signer", migrator: "agentpass_migrator", backup: "agentpass_backup" });
const SQLSTATE_PERMISSION_DENIED = new Set(["42501", "0LP01"]);
const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");
const ROLES_SQL_PATH = path.join(REPOSITORY_ROOT, "scripts/postgres/roles.sql");
const SMOKE_ORGANIZATION_ID = crypto.randomUUID();
const SMOKE_ROW_ID = crypto.randomUUID();
const SMOKE_TABLE_NAME = "q2a_role_dml_smoke";
const SEQUENCE_NAME = "q2a_least_privilege_role_sequence";

function parseDatabaseUrl(raw) {
  const parsed = new URL(raw);
  if (parsed.protocol !== "postgresql:" || !parsed.hostname || !parsed.username || !parsed.password
    || !parsed.pathname || parsed.pathname === "/" || parsed.hash) {
    throw new TypeError("integration database URL is invalid");
  }
  return parsed;
}

function psqlEnvironment(parsed) {
  const {
    AGENTPASS_DATABASE_URL: _databaseUrl,
    AGENTPASS_TEST_DATABASE_URL: _testDatabaseUrl,
    AGENTPASS_TEST_POSTGRES_URL: _testPostgresUrl,
    DATABASE_URL: _genericDatabaseUrl,
    ...inheritedEnvironment
  } = process.env;
  return {
    ...inheritedEnvironment,
    PGHOST: parsed.hostname,
    PGPORT: parsed.port || "5432",
    PGUSER: decodeURIComponent(parsed.username),
    PGPASSWORD: decodeURIComponent(parsed.password),
    PGDATABASE: decodeURIComponent(parsed.pathname.slice(1)),
    PGSSLMODE: parsed.searchParams.get("sslmode") ?? "disable",
  };
}

function applyRoles(parsed) {
  const result = spawnSync(
    "psql",
    ["--no-psqlrc", "--quiet", "--set=ON_ERROR_STOP=1", "--file", ROLES_SQL_PATH],
    { env: psqlEnvironment(parsed), encoding: "utf8", maxBuffer: 1024 * 1024 },
  );
  const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  const password = decodeURIComponent(parsed.password);
  const databaseUrl = parsed.toString();
  assert.equal(result.error, undefined, "psql role application could not start");
  assert.equal(result.status, 0, "psql role application failed closed");
  assert.equal(output.includes(password), false, "role application output leaked a password");
  assert.equal(output.includes(databaseUrl), false, "role application output leaked the database URL");
  const childArguments = Array.isArray(result.spawnargs) ? result.spawnargs : [];
  assert.equal(childArguments.some((argument) => argument.includes(password) || argument.includes(databaseUrl)), false,
    "role application passed credentials in argv");
}

async function withSessionAuthorization(pool, roleName, callback) {
  if (!Object.values(ROLE_NAMES).includes(roleName)) throw new TypeError("unsupported qualification role");
  const client = await pool.connect();
  try {
    // This connection starts as the database administrator, but session
    // authorization changes both session_user and current_user. The client
    // is destroyed afterwards so it can never regain or leak admin authority.
    await client.query(`SET SESSION AUTHORIZATION ${roleName}`);
    const principal = await client.query("SELECT session_user,current_user");
    assert.equal(principal.rows[0].session_user, roleName);
    assert.equal(principal.rows[0].current_user, roleName);
    return await callback(client);
  } finally {
    try {
      await client.query("RESET SESSION AUTHORIZATION");
    } finally {
      client.release(true);
    }
  }
}

async function expectPermissionDenied(callback) {
  await assert.rejects(callback, (error) => {
    assert.ok(SQLSTATE_PERMISSION_DENIED.has(error?.code), `unexpected denial SQLSTATE: ${error?.code ?? "unknown"}`);
    return true;
  });
}

test("qualifies PostgreSQL 16 least-privilege roles against real migrations and smoke operations", {
  skip: DATABASE_URL ? false : "set AGENTPASS_TEST_DATABASE_URL to run PostgreSQL role qualification",
  timeout: 120_000,
}, async (t) => {
  const parsed = parseDatabaseUrl(DATABASE_URL);
  const password = decodeURIComponent(parsed.password);
  assert.equal(process.argv.some((argument) => argument.includes(password) || argument.includes(parsed.toString())), false,
    "test credentials appeared in the test process argv");

  const pool = new Pool({
    connectionString: DATABASE_URL,
    max: 2,
    connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 2_000,
    statement_timeout: 10_000,
    query_timeout: 15_000,
  });
  let migrationApplied = false;
  let sequenceCreated = false;
  let smokeTableCreated = false;

  t.after(async () => {
    const cleanup = await pool.connect();
    try {
      // The full schema has audit-head foreign keys rooted at organizations;
      // this database is created solely for this qualification, so truncate
      // the root with its dependent rows during teardown.
      if (migrationApplied) await cleanup.query("TRUNCATE organizations CASCADE");
      if (smokeTableCreated) await cleanup.query(`DROP TABLE IF EXISTS public.${SMOKE_TABLE_NAME}`);
      if (sequenceCreated) await cleanup.query(`DROP SEQUENCE IF EXISTS public.${SEQUENCE_NAME}`);
    } finally {
      cleanup.release();
      await pool.end();
    }
  });

  // The database administrator applies the credential-free role policy. The
  // second application after migrations closes the same boundary for tables
  // created by migrations (including the migration attempt ledger).
  applyRoles(parsed);

  const migrationClient = await pool.connect();
  try {
    await migrationClient.query(`SET SESSION AUTHORIZATION ${ROLE_NAMES.migrator}`);
    const migrationPrincipal = await migrationClient.query("SELECT session_user,current_user");
    assert.equal(migrationPrincipal.rows[0].session_user, ROLE_NAMES.migrator);
    assert.equal(migrationPrincipal.rows[0].current_user, ROLE_NAMES.migrator);
    const migration = await createMigrationRunner({
      client: migrationClient,
      applicationVersion: "q2a-least-privilege-role-qualification",
    }).run();
    migrationApplied = true;
    assert.equal(migration.currentVersion >= 1, true);
    await migrationClient.query(`CREATE TABLE public.${SMOKE_TABLE_NAME} (id uuid PRIMARY KEY, value text NOT NULL)`);
    smokeTableCreated = true;
    await migrationClient.query("CREATE SEQUENCE public.q2a_least_privilege_role_sequence");
    sequenceCreated = true;
  } finally {
    try {
      await migrationClient.query("RESET SESSION AUTHORIZATION");
    } finally {
      migrationClient.release(true);
    }
  }

  // Reconcile grants after the full migration set has created its objects.
  applyRoles(parsed);

  await withSessionAuthorization(pool, ROLE_NAMES.app, async (client) => {
    await client.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [SMOKE_ORGANIZATION_ID, "q2a-role-organization"]);
    await client.query(`INSERT INTO ${SMOKE_TABLE_NAME} (id,value) VALUES ($1,$2)`, [SMOKE_ROW_ID, "q2a-role-smoke"]);
    await client.query(`UPDATE ${SMOKE_TABLE_NAME} SET value=$2 WHERE id=$1`, [SMOKE_ROW_ID, "q2a-role-smoke-updated"]);
    const selected = await client.query(`SELECT value FROM ${SMOKE_TABLE_NAME} WHERE id=$1`, [SMOKE_ROW_ID]);
    assert.equal(selected.rows[0].value, "q2a-role-smoke-updated");
    await client.query("SELECT nextval('public.q2a_least_privilege_role_sequence')");
    await client.query(`DELETE FROM ${SMOKE_TABLE_NAME} WHERE id=$1`, [SMOKE_ROW_ID]);

    await expectPermissionDenied(() => client.query("CREATE TABLE public.q2a_app_ddl_denied(id integer)"));
    await expectPermissionDenied(() => client.query("ALTER TABLE public.organizations ADD COLUMN q2a_app_ddl_denied integer"));
    await expectPermissionDenied(() => client.query("CREATE FUNCTION public.q2a_app_function_denied() RETURNS integer LANGUAGE SQL AS $$ SELECT 1 $$"));
    await expectPermissionDenied(() => client.query("SELECT agentpass_current_organization_id()"));
    await expectPermissionDenied(() => client.query("UPDATE schema_migrations SET checksum=checksum WHERE version=1"));
    await expectPermissionDenied(() => client.query("SET ROLE agentpass_migrator"));
  });

  await withSessionAuthorization(pool, ROLE_NAMES.backup, async (client) => {
    const selected = await client.query("SELECT name FROM organizations WHERE id=$1", [SMOKE_ORGANIZATION_ID]);
    assert.equal(selected.rows[0].name, "q2a-role-organization");
    const smokeRows = await client.query(`SELECT count(*)::int AS count FROM ${SMOKE_TABLE_NAME}`);
    assert.equal(smokeRows.rows[0].count, 0);
    const sequence = await client.query("SELECT last_value FROM public.q2a_least_privilege_role_sequence");
    assert.equal(sequence.rowCount, 1);

    await expectPermissionDenied(() => client.query(`INSERT INTO ${SMOKE_TABLE_NAME} (id,value) VALUES ($1,$2)`, [crypto.randomUUID(), "q2a-backup-write"]));
    await expectPermissionDenied(() => client.query(`UPDATE ${SMOKE_TABLE_NAME} SET value='q2a-backup-write' WHERE id=$1`, [SMOKE_ROW_ID]));
    await expectPermissionDenied(() => client.query(`DELETE FROM ${SMOKE_TABLE_NAME} WHERE id=$1`, [SMOKE_ROW_ID]));
    await expectPermissionDenied(() => client.query(`TRUNCATE ${SMOKE_TABLE_NAME}`));
    await expectPermissionDenied(() => client.query("CREATE TABLE public.q2a_backup_ddl_denied(id integer)"));
    await expectPermissionDenied(() => client.query("SELECT agentpass_current_organization_id()"));
    await expectPermissionDenied(() => client.query("SELECT nextval('public.q2a_least_privilege_role_sequence')"));
    await expectPermissionDenied(() => client.query("SELECT setval('public.q2a_least_privilege_role_sequence', 1)"));
    await expectPermissionDenied(() => client.query("ALTER SEQUENCE public.q2a_least_privilege_role_sequence INCREMENT BY 2"));
    await expectPermissionDenied(() => client.query("UPDATE schema_migrations SET checksum=checksum WHERE version=1"));
    await expectPermissionDenied(() => client.query("SET ROLE agentpass_migrator"));
  });

  await withSessionAuthorization(pool, ROLE_NAMES.signer, async (client) => {
    for (const table of [
      "managed_signer_key_lifecycles", "managed_signer_keys",
      "managed_signer_key_lifecycle_operations", "managed_signer_signing_idempotency",
      "managed_signer_provider_operations"
    ]) {
      const privileges = await client.query(
        "SELECT has_table_privilege(current_user,$1,'SELECT,INSERT,UPDATE,DELETE') AS allowed",
        [`public.${table}`]
      );
      assert.equal(privileges.rows[0].allowed, true, `signer ledger privilege missing for ${table}`);
    }
    await client.query("SELECT agentpass_quarantine_expired_managed_signer_provider_operations(1)");
    await expectPermissionDenied(() => client.query("SELECT name FROM organizations LIMIT 1"));
    await expectPermissionDenied(() => client.query(`SELECT count(*) FROM ${SMOKE_TABLE_NAME}`));
    await expectPermissionDenied(() => client.query("SELECT nextval('public.q2a_least_privilege_role_sequence')"));
    await expectPermissionDenied(() => client.query("SELECT agentpass_current_organization_id()"));
    await expectPermissionDenied(() => client.query("SET ROLE agentpass_migrator"));
    await expectPermissionDenied(() => client.query("SET ROLE agentpass_app"));
  });

  await withSessionAuthorization(pool, ROLE_NAMES.migrator, async (client) => {
    await expectPermissionDenied(() => client.query("SET ROLE postgres"));
  });
});
