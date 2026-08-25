import { POSTGRES_SCHEMA_HEAD } from "../../src/postgres/schema-head.mjs";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { Pool } from "pg";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";

const ADMIN_DATABASE_URL = process.env.AGENTPASS_TEST_POSTGRES_ADMIN_URL
  ?? process.env.AGENTPASS_TEST_DATABASE_URL
  ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const ROLE_DATABASE_URLS = Object.freeze({
  app: process.env.AGENTPASS_TEST_APP_DATABASE_URL,
  signer: process.env.AGENTPASS_TEST_SIGNER_DATABASE_URL,
  migrator: process.env.AGENTPASS_TEST_MIGRATION_DATABASE_URL,
  backup: process.env.AGENTPASS_TEST_BACKUP_DATABASE_URL,
});
const MISSING_ROLE_CONNECTIONS = [
  ["AGENTPASS_TEST_POSTGRES_ADMIN_URL", ADMIN_DATABASE_URL],
  ["AGENTPASS_TEST_APP_DATABASE_URL", ROLE_DATABASE_URLS.app],
  ["AGENTPASS_TEST_SIGNER_DATABASE_URL", ROLE_DATABASE_URLS.signer],
  ["AGENTPASS_TEST_MIGRATION_DATABASE_URL", ROLE_DATABASE_URLS.migrator],
  ["AGENTPASS_TEST_BACKUP_DATABASE_URL", ROLE_DATABASE_URLS.backup],
].filter(([, value]) => typeof value !== "string" || value.length === 0).map(([name]) => name);
const ROLE_NAMES = Object.freeze({ app: "agentpass_app", signer: "agentpass_signer", migrator: "agentpass_migrator", backup: "agentpass_backup" });
const SIGNER_FUNCTIONS = Object.freeze([
  "agentpass_managed_signer_provider_operation_reserve(text,text,text,integer,bytea,text,bigint,bytea,integer,integer)",
  "agentpass_managed_signer_provider_operation_reserve(text,text,text,integer,bytea,text,bigint,bytea,integer,bigint)",
  "agentpass_managed_signer_provider_operation_claim(text,text,text,integer,bytea,text,bigint,bytea,integer)",
  "agentpass_managed_signer_provider_operation_start(text,text,text,integer,bytea,text,bigint,bytea)",
  "agentpass_managed_signer_provider_operation_accept(text,text,text,integer,bytea,text,bigint,bytea,bytea,bytea,text,text,text,text,text)",
  "agentpass_managed_signer_provider_operation_commit(text,text,text,integer,bytea,text,bigint,bytea)",
  "agentpass_managed_signer_provider_operation_reconcile(text,text,text,integer,bytea,text,bigint)",
  "agentpass_managed_signer_provider_operation_uncertain(text,text,text,integer,bytea,text,bigint,bytea,text)",
  "agentpass_managed_signer_provider_operation_get(text,text,text,integer,bytea,text,bigint)",
  "agentpass_managed_signer_provider_operation_health(text,text,bigint,text)",
  "agentpass_managed_signer_provider_operation_prune(text,text,bigint,text,timestamptz,integer)",
  "agentpass_maintain_managed_signer_provider_operations(integer)",
  "agentpass_health_managed_signer_provider_operations()",
  "agentpass_managed_signer_lifecycle_snapshot(text)",
  "agentpass_managed_signer_lifecycle_initialize(text,text,jsonb,integer,bigint)",
  "agentpass_managed_signer_lifecycle_apply(text,text,bytea,bigint,jsonb,bigint)",
  "agentpass_managed_signer_signing_reserve(text,text,bytea,text,bigint,bytea,bigint,bigint)",
  "agentpass_managed_signer_signing_start(text,text,bytea,text,bigint,bytea)",
  "agentpass_managed_signer_signing_commit(text,text,bytea,text,bigint,bytea,bytea,text,text)",
  "agentpass_managed_signer_signing_uncertain(text,text,bytea,text,bigint,bytea)",
  "agentpass_managed_signer_signing_reconcile(text,text,bytea,text,bigint,bytea,text,text)",
  "agentpass_managed_signer_signing_lookup(text,text)",
  "agentpass_managed_signer_signing_prune(text,timestamptz,integer)",
  "agentpass_managed_signer_lifecycle_operation_prune(text,timestamptz,integer)"
]);
const PLATFORM_AUTHORITY_RELATIONS = Object.freeze([
  "platform_credentials",
  "platform_sessions",
  "platform_session_challenges",
  "platform_authorization_proofs",
  "platform_principals",
  "platform_operator_assignments",
  "platform_operator_assignment_approvals",
  "platform_promotion_approvals",
  "platform_promotion_deployments",
  "platform_promotion_issuances",
]);
const PLATFORM_APP_FUNCTIONS = Object.freeze([
  "agentpass_platform_operator_assignment_find_active(uuid,uuid,uuid,text,text)",
  "agentpass_platform_session_challenge_create(uuid,uuid,bytea,bytea,bytea,bytea,bytea[],uuid,uuid,uuid,uuid,bigint,text,text,text,text,text,integer)",
  "agentpass_platform_session_challenge_find(uuid)",
  "agentpass_platform_session_challenge_claim(uuid,bytea,bytea,bytea,bytea)",
  "agentpass_platform_session_challenge_fail(uuid,bytea,bytea,bytea,bytea,text)",
  "agentpass_platform_session_credential_find(uuid,bytea,bytea)",
  "agentpass_platform_credential_advance_verified(uuid,bytea,uuid,bytea,bigint,bigint,bigint,boolean,boolean)",
  "agentpass_platform_session_find_active(bytea,uuid,text,text)",
  "agentpass_platform_session_touch(bytea,bytea,uuid,text,text)",
  "agentpass_platform_session_revoke(bytea,bytea,text)",
  "agentpass_platform_session_complete_and_issue(uuid,bytea,bytea,uuid,bytea,bytea,bytea,bytea,bytea,integer,integer)",
  "agentpass_consume_platform_authorization_and_reserve(bytea,bytea,uuid,bytea,bytea,uuid,text,text,text,text,bytea,integer,integer,text,bigint,bigint)",
  "agentpass_platform_session_bootstrap_context(bytea,uuid,text,text)",
]);
const LEGACY_PLATFORM_PROMOTION_MUTATIONS = Object.freeze([
  {
    signature: "agentpass_platform_promotion_issuance_reserve(uuid,text,text,text,text,bytea,integer,integer,text,bigint,bigint)",
    call: "public.agentpass_platform_promotion_issuance_reserve(NULL::uuid,NULL::text,NULL::text,NULL::text,NULL::text,NULL::bytea,NULL::integer,NULL::integer,NULL::text,NULL::bigint,NULL::bigint)",
  },
  {
    signature: "agentpass_platform_promotion_issuance_replay(uuid,text,text,text,text)",
    call: "public.agentpass_platform_promotion_issuance_replay(NULL::uuid,NULL::text,NULL::text,NULL::text,NULL::text)",
  },
  {
    signature: "agentpass_platform_promotion_issuance_commit(uuid,text,text,text,text,bytea,bytea,bytea,bytea,bytea)",
    call: "public.agentpass_platform_promotion_issuance_commit(NULL::uuid,NULL::text,NULL::text,NULL::text,NULL::text,NULL::bytea,NULL::bytea,NULL::bytea,NULL::bytea,NULL::bytea)",
  },
  {
    signature: "agentpass_platform_promotion_issuance_uncertain(uuid,text,text,text,text,bytea,text)",
    call: "public.agentpass_platform_promotion_issuance_uncertain(NULL::uuid,NULL::text,NULL::text,NULL::text,NULL::text,NULL::bytea,NULL::text)",
  },
]);
const PLATFORM_SIGNER_FINALIZE_FUNCTIONS = Object.freeze([
  "agentpass_platform_promotion_issuance_commit(uuid,text,text,text,text,bytea,bytea,bytea,bytea,bytea)",
  "agentpass_platform_promotion_issuance_uncertain(uuid,text,text,text,text,bytea,text)",
]);
const ATOMIC_PLATFORM_AUTHORIZATION_CALL = "public.agentpass_consume_platform_authorization_and_reserve(NULL::bytea,NULL::bytea,NULL::uuid,NULL::bytea,NULL::bytea,NULL::uuid,NULL::text,NULL::text,NULL::text,NULL::text,NULL::bytea,NULL::integer,NULL::integer,NULL::text,NULL::bigint,NULL::bigint)";
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

async function withRoleConnection(roleName, callback) {
  const roleEntry = Object.entries(ROLE_NAMES).find(([, value]) => value === roleName);
  if (!roleEntry) throw new TypeError("unsupported qualification role");
  const connectionString = ROLE_DATABASE_URLS[roleEntry[0]];
  if (!connectionString) throw new Error(`missing connection for ${roleName}`);
  const pool = new Pool({
    connectionString,
    max: 1,
    connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 2_000,
    statement_timeout: 10_000,
    query_timeout: 15_000,
  });
  const client = await pool.connect();
  try {
    const principal = await client.query(`
      SELECT session_user, current_user,
             (SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()) AS ssl,
             (SELECT version FROM pg_stat_ssl WHERE pid = pg_backend_pid()) AS tls_version,
             (SELECT cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid()) AS cipher`);
    assert.deepEqual(principal.rows[0].session_user, roleName);
    assert.deepEqual(principal.rows[0].current_user, roleName);
    assert.equal(principal.rows[0].ssl, true, `${roleName} connection must use TLS`);
    assert.match(principal.rows[0].tls_version, /^TLSv[0-9.]+$/u, `${roleName} TLS version`);
    assert.ok(typeof principal.rows[0].cipher === "string" && principal.rows[0].cipher.length > 0, `${roleName} TLS cipher`);
    return await callback(client);
  } finally {
    client.release(true);
    await pool.end();
  }
}

async function expectPermissionDenied(callback) {
  await assert.rejects(callback, (error) => {
    assert.ok(SQLSTATE_PERMISSION_DENIED.has(error?.code), `unexpected denial SQLSTATE: ${error?.code ?? "unknown"}`);
    return true;
  });
}

async function expectPermissionDeniedInSavepoint(client, callback) {
  const savepoint = "q2a_least_privilege_probe";
  await client.query("BEGIN");
  await client.query(`SAVEPOINT ${savepoint}`);
  try {
    await expectPermissionDenied(callback);
  } finally {
    await client.query(`ROLLBACK TO SAVEPOINT ${savepoint}`);
    await client.query(`RELEASE SAVEPOINT ${savepoint}`);
    await client.query("COMMIT");
  }
}

function quoteIdentifier(identifier) {
  if (typeof identifier !== "string" || !/^[a-z_][a-z0-9_]*$/u.test(identifier)) throw new TypeError("unexpected PostgreSQL identifier");
  return `"${identifier}"`;
}

test("qualifies least-privilege roles against real PostgreSQL migrations and smoke operations", {
  skip: MISSING_ROLE_CONNECTIONS.length === 0
    ? false
    : `set independent PostgreSQL role URLs to run qualification; missing ${MISSING_ROLE_CONNECTIONS.join(", ")}`,
  timeout: 120_000,
}, async (t) => {
  const parsed = parseDatabaseUrl(ADMIN_DATABASE_URL);
  const password = decodeURIComponent(parsed.password);
  assert.equal(process.argv.some((argument) => argument.includes(password) || argument.includes(parsed.toString())), false,
    "test credentials appeared in the test process argv");

  const adminPool = new Pool({
    connectionString: ADMIN_DATABASE_URL,
    max: 2,
    connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 2_000,
    statement_timeout: 10_000,
    query_timeout: 15_000,
  });
  let migrationApplied = false;
  let sequenceCreated = false;
  let smokeTableCreated = false;
  const authorityUpdateColumns = new Map();

  t.after(async () => {
    const cleanup = await adminPool.connect();
    try {
      // The full schema has audit-head foreign keys rooted at organizations;
      // this database is created solely for this qualification, so truncate
      // the root with its dependent rows during teardown.
      if (migrationApplied) await cleanup.query("TRUNCATE organizations CASCADE");
      if (smokeTableCreated) await cleanup.query(`DROP TABLE IF EXISTS public.${SMOKE_TABLE_NAME}`);
      if (sequenceCreated) await cleanup.query(`DROP SEQUENCE IF EXISTS public.${SEQUENCE_NAME}`);
      if (migrationApplied) {
        const remaining = await cleanup.query(`
          SELECT (SELECT count(*) FROM public.organizations) AS organizations,
                 to_regclass($1) AS smoke_table,
                 to_regclass($2) AS smoke_sequence`,
        [`public.${SMOKE_TABLE_NAME}`, `public.${SEQUENCE_NAME}`]);
        assert.deepEqual(remaining.rows[0], {
          organizations: "0", smoke_table: null, smoke_sequence: null,
        }, "least-privilege qualification cleanup left rows or objects behind");
      }
    } finally {
      cleanup.release();
      await adminPool.end();
    }
  });

  const adminPrincipal = await adminPool.query(`
    SELECT session_user, current_user,
           (SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()) AS ssl,
           (SELECT version FROM pg_stat_ssl WHERE pid = pg_backend_pid()) AS tls_version,
           (SELECT cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid()) AS cipher`);
  assert.equal(adminPrincipal.rows[0].session_user, parsed.username ? decodeURIComponent(parsed.username) : "postgres");
  assert.equal(adminPrincipal.rows[0].current_user, adminPrincipal.rows[0].session_user);
  assert.equal(adminPrincipal.rows[0].ssl, true, "administrator connection must use TLS");
  assert.match(adminPrincipal.rows[0].tls_version, /^TLSv[0-9.]+$/u, "administrator TLS version");
  assert.ok(typeof adminPrincipal.rows[0].cipher === "string" && adminPrincipal.rows[0].cipher.length > 0, "administrator TLS cipher");

  // The database administrator applies the credential-free role policy. The
  // second application after migrations closes the same boundary for tables
  // created by migrations (including the migration attempt ledger).
  applyRoles(parsed);

  await withRoleConnection(ROLE_NAMES.migrator, async (migrationClient) => {
    const migration = await createMigrationRunner({
      client: migrationClient,
      applicationVersion: "q2a-least-privilege-role-qualification",
    }).run();
    migrationApplied = true;
    assert.equal(migration.currentVersion, POSTGRES_SCHEMA_HEAD.version);
    await migrationClient.query(`CREATE TABLE public.${SMOKE_TABLE_NAME} (id uuid PRIMARY KEY, value text NOT NULL)`);
    smokeTableCreated = true;
    await migrationClient.query("CREATE SEQUENCE public.q2a_least_privilege_role_sequence");
    sequenceCreated = true;
  });

  // Reconcile grants after the full migration set has created its objects.
  applyRoles(parsed);

  const metadataClient = await adminPool.connect();
  try {
    for (const relation of PLATFORM_AUTHORITY_RELATIONS) {
      const columns = await metadataClient.query(
        `SELECT column_name
           FROM information_schema.columns
          WHERE table_schema = 'public' AND table_name = $1
          ORDER BY ordinal_position
          LIMIT 1`,
        [relation],
      );
      assert.equal(columns.rowCount, 1, `authority relation has no column: ${relation}`);
      authorityUpdateColumns.set(relation, columns.rows[0].column_name);
    }
  } finally {
    metadataClient.release();
  }

  await adminPool.query(
    "INSERT INTO organizations (id,name) VALUES ($1,$2)",
    [SMOKE_ORGANIZATION_ID, "q2a-role-organization"],
  );

  await withRoleConnection(ROLE_NAMES.app, async (client) => {
    for (const relation of PLATFORM_AUTHORITY_RELATIONS) {
      const relationName = `public.${relation}`;
      const privileges = await client.query(
        `SELECT has_table_privilege(current_user,$1,'SELECT') AS can_select,
                has_table_privilege(current_user,$1,'INSERT') AS can_insert,
                has_table_privilege(current_user,$1,'UPDATE') AS can_update,
                has_table_privilege(current_user,$1,'DELETE') AS can_delete`,
        [relationName],
      );
      assert.deepEqual(privileges.rows[0], {
        can_select: false,
        can_insert: false,
        can_update: false,
        can_delete: false,
      }, `unexpected app privileges for ${relation}`);

      await expectPermissionDeniedInSavepoint(client, () => client.query(`SELECT * FROM public.${quoteIdentifier(relation)} LIMIT 0`));

      const table = quoteIdentifier(relation);
      const column = quoteIdentifier(authorityUpdateColumns.get(relation));
      await expectPermissionDeniedInSavepoint(client, () => client.query(`INSERT INTO public.${table} DEFAULT VALUES`));
      await expectPermissionDeniedInSavepoint(client, () => client.query(`UPDATE public.${table} SET ${column}=${column} WHERE false`));
      await expectPermissionDeniedInSavepoint(client, () => client.query(`DELETE FROM public.${table} WHERE false`));
    }

    for (const signature of PLATFORM_APP_FUNCTIONS) {
      const privilege = await client.query(
        "SELECT has_function_privilege(current_user,$1,'EXECUTE') AS allowed",
        [`public.${signature}`],
      );
      assert.equal(privilege.rows[0].allowed, true, `app reviewed function privilege missing for ${signature}`);
    }
    await assert.rejects(
      () => client.query(`SELECT ${ATOMIC_PLATFORM_AUTHORIZATION_CALL} AS result`),
      (error) => {
        assert.equal(error?.code, "22023", "reviewed atomic function did not reach its input-validation boundary");
        return true;
      },
    );

    for (const { signature, call } of LEGACY_PLATFORM_PROMOTION_MUTATIONS) {
      const privilege = await client.query(
        "SELECT has_function_privilege(current_user,$1,'EXECUTE') AS allowed",
        [`public.${signature}`],
      );
      assert.equal(privilege.rows[0].allowed, false, `legacy promotion mutation privilege leaked for ${signature}`);
      await expectPermissionDeniedInSavepoint(client, () => client.query(`SELECT ${call}`));
    }

    const organization = await client.query("SELECT name FROM organizations WHERE id=$1", [SMOKE_ORGANIZATION_ID]);
    assert.deepEqual(organization.rows, [{ name: "q2a-role-organization" }]);
    await expectPermissionDenied(() => client.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [crypto.randomUUID(), "q2a-app-write-denied"]));
    await expectPermissionDenied(() => client.query("UPDATE organizations SET name=name WHERE id=$1", [SMOKE_ORGANIZATION_ID]));
    await expectPermissionDenied(() => client.query("DELETE FROM organizations WHERE id=$1", [SMOKE_ORGANIZATION_ID]));
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
    for (const signature of [...SIGNER_FUNCTIONS, ...PLATFORM_SIGNER_FINALIZE_FUNCTIONS]) {
      const privilege = await client.query(
        "SELECT has_function_privilege(current_user,$1,'EXECUTE') AS allowed",
        ["public." + signature]
      );
      assert.equal(privilege.rows[0].allowed, false, "app signer function privilege leaked for " + signature);
    }
  });

  await withRoleConnection(ROLE_NAMES.backup, async (client) => {
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
    for (const signature of [...SIGNER_FUNCTIONS, ...PLATFORM_SIGNER_FINALIZE_FUNCTIONS]) {
      const privilege = await client.query(
        "SELECT has_function_privilege(current_user,$1,'EXECUTE') AS allowed",
        ["public." + signature]
      );
      assert.equal(privilege.rows[0].allowed, false, "backup signer function privilege leaked for " + signature);
    }
  });

  await withRoleConnection(ROLE_NAMES.signer, async (client) => {
    for (const relation of PLATFORM_AUTHORITY_RELATIONS) {
      const privilege = await client.query(
        "SELECT has_table_privilege(current_user,$1,'SELECT,INSERT,UPDATE,DELETE') AS allowed",
        [`public.${relation}`],
      );
      assert.equal(privilege.rows[0].allowed, false, `signer platform table privilege leaked for ${relation}`);
    }
    for (const table of [
      "managed_signer_key_lifecycles", "managed_signer_keys",
      "managed_signer_key_lifecycle_operations", "managed_signer_signing_idempotency",
      "managed_signer_provider_operations"
    ]) {
      const privileges = await client.query(
        "SELECT has_table_privilege(current_user,$1,'SELECT,INSERT,UPDATE,DELETE') AS allowed",
        [`public.${table}`]
      );
      assert.equal(privileges.rows[0].allowed, false, "signer ledger privilege leaked for " + table);
    }
    for (const signature of [...SIGNER_FUNCTIONS, ...PLATFORM_SIGNER_FINALIZE_FUNCTIONS]) {
      const privilege = await client.query("SELECT has_function_privilege(current_user,$1,'EXECUTE') AS allowed", [`public.${signature}`]);
      assert.equal(privilege.rows[0].allowed, true, `signer function privilege missing for ${signature}`);
    }
    for (const signature of PLATFORM_APP_FUNCTIONS) {
      const privilege = await client.query("SELECT has_function_privilege(current_user,$1,'EXECUTE') AS allowed", [`public.${signature}`]);
      assert.equal(privilege.rows[0].allowed, false, `platform function privilege leaked to signer for ${signature}`);
    }
    for (const { signature } of LEGACY_PLATFORM_PROMOTION_MUTATIONS) {
      const privilege = await client.query("SELECT has_function_privilege(current_user,$1,'EXECUTE') AS allowed", [`public.${signature}`]);
      assert.equal(privilege.rows[0].allowed, PLATFORM_SIGNER_FINALIZE_FUNCTIONS.includes(signature), `unexpected signer promotion privilege for ${signature}`);
    }
    await expectPermissionDenied(() => client.query("SELECT agentpass_quarantine_expired_managed_signer_provider_operations(1)"));
    await expectPermissionDenied(() => client.query("SELECT name FROM organizations LIMIT 1"));
    await expectPermissionDenied(() => client.query(`SELECT count(*) FROM ${SMOKE_TABLE_NAME}`));
    await expectPermissionDenied(() => client.query("SELECT nextval('public.q2a_least_privilege_role_sequence')"));
    await expectPermissionDenied(() => client.query("SELECT agentpass_current_organization_id()"));
    await expectPermissionDenied(() => client.query("SET ROLE agentpass_migrator"));
    await expectPermissionDenied(() => client.query("SET ROLE agentpass_app"));
  });

  await withRoleConnection(ROLE_NAMES.migrator, async (client) => {
    for (const relation of PLATFORM_AUTHORITY_RELATIONS) {
      const privilege = await client.query(
        "SELECT has_table_privilege(current_user,$1,'SELECT,INSERT,UPDATE,DELETE') AS allowed",
        [`public.${relation}`],
      );
      assert.equal(privilege.rows[0].allowed, true, `migrator authority privilege missing for ${relation}`);
    }
    for (const signature of PLATFORM_APP_FUNCTIONS) {
      const privilege = await client.query(
        "SELECT has_function_privilege(current_user,$1,'EXECUTE') AS allowed",
        [`public.${signature}`],
      );
      assert.equal(privilege.rows[0].allowed, true, `migrator function privilege missing for ${signature}`);
    }
    await expectPermissionDenied(() => client.query("SET ROLE postgres"));
  });
});
