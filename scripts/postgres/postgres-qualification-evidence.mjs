import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Pool } from "pg";

import { POSTGRES_SCHEMA_HEAD } from "../../apps/cloud-api/src/postgres/schema-head.mjs";

const SHA256 = /^[0-9a-f]{64}$/u;
const SHA1 = /^[0-9a-f]{40}$/u;
const ROLE_NAMES = ["agentpass_app", "agentpass_migrator", "agentpass_signer", "agentpass_backup", "agentpass_maintenance"];

function digest(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function read(file) { return fs.readFileSync(file); }
function fail(message) { throw new Error(message); }

export function validateTap(tap) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(tap);
  } catch {
    fail("PostgreSQL qualification TAP is not valid UTF-8");
  }

  const lines = text.split("\n").map((line) => line.endsWith("\r") ? line.slice(0, -1) : line);
  if (lines[0] !== "TAP version 13") fail("PostgreSQL qualification TAP is missing TAP version 13");

  let plan;
  let observedTests = 0;
  let okTests = 0;
  for (const [index, line] of lines.entries()) {
    if (index > 0 && /^[ \t]*TAP version\b/u.test(line)) fail("PostgreSQL qualification TAP has a duplicate TAP version");
    if (/^[ \t]*Bail out!/u.test(line)) fail("PostgreSQL qualification TAP contains a bailout");
    if (/^[ \t]*not ok(?:[ \t]|$)/u.test(line)) fail("PostgreSQL qualification TAP contains a failing test");
    if (/(^|[ \t])# (?:SKIP|TODO)(?:[ \t]|$)/u.test(line)) {
      fail("PostgreSQL qualification TAP contains a skipped or TODO test");
    }

    if (/^1\.\./u.test(line)) {
      const match = /^1\.\.([1-9][0-9]*)(?:[ \t]+#.*)?$/u.exec(line);
      if (!match) fail("PostgreSQL qualification TAP has an invalid plan");
      if (plan !== undefined) fail("PostgreSQL qualification TAP has multiple top-level plans");
      plan = Number(match[1]);
      if (!Number.isSafeInteger(plan)) fail("PostgreSQL qualification TAP plan is too large");
      continue;
    }

    // The outer plan describes only top-level test points; nested subtests
    // have their own indented plans and test points.
    if (/^(ok)(?:[ \t]|$)/u.test(line)) {
      observedTests += 1;
      okTests += 1;
    }
  }

  if (plan === undefined || plan !== observedTests || plan !== okTests || observedTests < 1) {
    fail("PostgreSQL qualification TAP has an incomplete or inconsistent envelope");
  }
  return { tests: observedTests, tap_sha256: digest(tap) };
}

async function queryIdentity(databaseUrl, expectedRole, connection) {
  if (!databaseUrl) fail(`database URL for ${connection} role assertion is required`);
  const pool = new Pool({ connectionString: databaseUrl, max: 1, connectionTimeoutMillis: 5_000, statement_timeout: 10_000 });
  try {
    const result = await pool.query("SELECT session_user, current_user, (SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()) AS ssl");
    assert.equal(result.rowCount, 1);
    const identity = result.rows[0];
    assert.deepEqual(identity, { session_user: expectedRole, current_user: expectedRole, ssl: true }, `${connection} PostgreSQL identity and TLS`);
    return {
      connection,
      expected_role: expectedRole,
      session_user: identity.session_user,
      current_user: identity.current_user,
      ssl: identity.ssl,
    };
  } finally {
    await pool.end();
  }
}

async function queryEvidence(databaseUrl, appDatabaseUrl, maintenanceDatabaseUrl) {
  if (!databaseUrl) fail("AGENTPASS_TEST_POSTGRES_ADMIN_URL is required");
  if (!maintenanceDatabaseUrl) fail("AGENTPASS_TEST_MAINTENANCE_DATABASE_URL is required");
  const pool = new Pool({ connectionString: databaseUrl, max: 1, connectionTimeoutMillis: 5_000, statement_timeout: 10_000 });
  try {
    const result = await pool.query(`
      SELECT current_setting('server_version') AS server_version,
             current_setting('server_version_num')::integer AS server_version_num,
             (SELECT max(version)::int FROM public.schema_migrations) AS schema_head,
             (SELECT count(*)::int FROM public.schema_migrations) AS migration_count,
             (SELECT array_agg(version::int ORDER BY version) FROM public.schema_migrations) AS migration_versions,
             (SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()) AS ssl,
             (SELECT version FROM pg_stat_ssl WHERE pid=pg_backend_pid()) AS tls_version,
             (SELECT cipher FROM pg_stat_ssl WHERE pid=pg_backend_pid()) AS cipher,
             (SELECT array_agg(rolname::text ORDER BY rolname)::text[] FROM pg_roles WHERE rolname = ANY($1::text[])) AS roles,
             (SELECT count(*)::int FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='public' AND c.relname IN ('device_audit_events','device_audit_heads','device_audit_gaps')
                  AND c.relrowsecurity AND c.relforcerowsecurity) AS forced_rls_relations,
             (SELECT jsonb_agg(jsonb_build_object('name', c.relname, 'enabled', c.relrowsecurity, 'forced', c.relforcerowsecurity) ORDER BY c.relname)
                FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='public' AND c.relname IN ('device_audit_events','device_audit_heads','device_audit_gaps')) AS device_audit_rls,
             (SELECT count(*)::int FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='public' AND t.tgenabled <> 'D' AND t.tgname IN ('device_audit_events_validate_insert','device_audit_events_record_head')) AS device_audit_triggers,
             (SELECT count(*)::int FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='public' AND c.relname='platform_device_audit_tenant_context') AS tenant_authority_relations,
             (SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                WHERE n.nspname='public'
                  AND p.oid IN (to_regprocedure('public.agentpass_authorize_device_audit_tenant(uuid,uuid)'), to_regprocedure('public.agentpass_authorize_device_audit_device(uuid,uuid)'), to_regprocedure('public.agentpass_device_audit_current_organization_id()'))
                  AND p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog, public']) AS tenant_authority_functions,
             has_table_privilege('agentpass_app', 'public.platform_device_audit_tenant_context', 'SELECT') AS app_can_select_tenant_authority,
             has_function_privilege('agentpass_app', 'public.agentpass_device_audit_inbox_enqueue(uuid,uuid,uuid,text,text,jsonb)', 'EXECUTE') AS app_can_enqueue_inbox,
             has_function_privilege('agentpass_app', 'public.agentpass_device_audit_inbox_claim(bytea,integer,integer)', 'EXECUTE') AS app_can_claim_inbox,
             has_function_privilege('agentpass_app', 'public.agentpass_device_audit_inbox_settle(uuid,uuid,integer,bytea,text,text)', 'EXECUTE') AS app_can_settle_inbox,
             has_function_privilege('agentpass_maintenance', 'public.agentpass_device_audit_inbox_claim(bytea,integer,integer)', 'EXECUTE') AS maintenance_can_claim_inbox,
             has_function_privilege('agentpass_maintenance', 'public.agentpass_device_audit_inbox_settle(uuid,uuid,integer,bytea,text,text)', 'EXECUTE') AS maintenance_can_settle_inbox,
             has_function_privilege('agentpass_maintenance', 'public.agentpass_device_audit_inbox_health()', 'EXECUTE') AS maintenance_can_health_inbox`, [ROLE_NAMES]);
    assert.equal(result.rowCount, 1);
    const row = result.rows[0];
    assert.equal(row.schema_head, POSTGRES_SCHEMA_HEAD.version);
    assert.equal(row.migration_count, POSTGRES_SCHEMA_HEAD.migration_count);
    assert.deepEqual(row.migration_versions, Array.from({ length: POSTGRES_SCHEMA_HEAD.migration_count }, (_, index) => index + 1));
    assert.equal(row.roles?.length, ROLE_NAMES.length);
    if (row.forced_rls_relations !== 3) throw new Error(`device audit RLS state: ${JSON.stringify(row.device_audit_rls)}`);
    assert.equal(row.device_audit_triggers, 2);
    assert.equal(row.tenant_authority_relations, 1);
    assert.equal(row.tenant_authority_functions, 3);
    assert.equal(row.app_can_select_tenant_authority, false);
    assert.equal(row.app_can_enqueue_inbox, true);
    assert.equal(row.app_can_claim_inbox, false);
    assert.equal(row.app_can_settle_inbox, false);
    assert.equal(row.maintenance_can_claim_inbox, true);
    assert.equal(row.maintenance_can_settle_inbox, true);
    assert.equal(row.maintenance_can_health_inbox, true);
    assert.equal(row.ssl, true);
    const adminRole = process.env.AGENTPASS_QUALIFICATION_ADMIN_ROLE ?? "postgres";
    const roleAssertions = [
      await queryIdentity(databaseUrl, adminRole, "admin"),
      await queryIdentity(appDatabaseUrl, "agentpass_app", "app"),
      await queryIdentity(maintenanceDatabaseUrl, "agentpass_maintenance", "maintenance"),
    ];
    return { ...row, roleAssertions };
  } finally {
    await pool.end();
  }
}

async function writeEvidence(output, tapFile) {
  const sourceCommit = process.env.AGENTPASS_QUALIFICATION_SOURCE_COMMIT;
  const candidateId = process.env.AGENTPASS_QUALIFICATION_CANDIDATE_ID;
  if (!SHA1.test(sourceCommit ?? "")) fail("qualification source commit must be a full SHA-1");
  if (typeof candidateId !== "string" || candidateId.length < 1 || candidateId.length > 256) fail("qualification candidate id is invalid");
  const tap = read(tapFile);
  const tapEvidence = validateTap(tap);
  const server = await queryEvidence(
    process.env.AGENTPASS_TEST_POSTGRES_ADMIN_URL,
    process.env.AGENTPASS_TEST_APP_DATABASE_URL,
    process.env.AGENTPASS_TEST_MAINTENANCE_DATABASE_URL,
  );
  const report = {
    schema_version: 1,
    kind: "agentpass.postgres.real-service.qualification",
    candidate_id: candidateId,
    source_commit: sourceCommit,
    postgres_image_id: process.env.AGENTPASS_QUALIFICATION_POSTGRES_IMAGE_ID ?? null,
    schema: {
      head: POSTGRES_SCHEMA_HEAD.version,
      migration_count: POSTGRES_SCHEMA_HEAD.migration_count,
      head_name: POSTGRES_SCHEMA_HEAD.name,
      head_checksum: POSTGRES_SCHEMA_HEAD.checksum,
      migrations_sha256: digest(JSON.stringify(POSTGRES_SCHEMA_HEAD.migrations))
    },
    service: {
      server_version: server.server_version,
      server_version_num: server.server_version_num,
      ssl: server.ssl,
      tls_version: server.tls_version,
      cipher: server.cipher,
      roles: server.roles,
      role_assertions: server.roleAssertions,
      forced_rls_relations: server.forced_rls_relations,
      device_audit_triggers: server.device_audit_triggers,
      tenant_authority: {
        relation: "platform_device_audit_tenant_context",
        security_definer_functions: server.tenant_authority_functions,
        app_can_select_relation: server.app_can_select_tenant_authority
      },
      device_audit_inbox_authority: {
        app_can_enqueue: server.app_can_enqueue_inbox,
        app_can_claim: server.app_can_claim_inbox,
        app_can_settle: server.app_can_settle_inbox,
        maintenance_can_claim: server.maintenance_can_claim_inbox,
        maintenance_can_settle: server.maintenance_can_settle_inbox,
        maintenance_can_health: server.maintenance_can_health_inbox
      }
    },
    suites: { tap: tapEvidence },
    skipped_tests: 0,
    status: "passed"
  };
  fs.mkdirSync(path.dirname(output), { recursive: true, mode: 0o700 });
  const canonical = `${JSON.stringify(report)}\n`;
  fs.writeFileSync(output, canonical, { mode: 0o600 });
  assert.equal(fs.readFileSync(output, "utf8"), canonical);
  return report;
}

export function verifyEvidence(file, sourceCommit) {
  const report = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.equal(report.kind, "agentpass.postgres.real-service.qualification");
  assert.equal(report.source_commit, sourceCommit);
  assert.equal(report.schema.head, POSTGRES_SCHEMA_HEAD.version);
  assert.equal(report.schema.migration_count, POSTGRES_SCHEMA_HEAD.migration_count);
  assert.equal(report.schema.head_name, POSTGRES_SCHEMA_HEAD.name);
  assert.equal(report.schema.head_checksum, POSTGRES_SCHEMA_HEAD.checksum);
  assert.equal(report.schema.migrations_sha256, digest(JSON.stringify(POSTGRES_SCHEMA_HEAD.migrations)));
  assert.equal(report.service.ssl, true);
  assert.equal(report.service.roles.length, ROLE_NAMES.length);
  assert.deepEqual(report.service.role_assertions, [
    { connection: "admin", expected_role: "postgres", session_user: "postgres", current_user: "postgres", ssl: true },
    { connection: "app", expected_role: "agentpass_app", session_user: "agentpass_app", current_user: "agentpass_app", ssl: true },
    { connection: "maintenance", expected_role: "agentpass_maintenance", session_user: "agentpass_maintenance", current_user: "agentpass_maintenance", ssl: true },
  ]);
  assert.equal(report.service.forced_rls_relations, 3);
  assert.equal(report.service.device_audit_triggers, 2);
  assert.deepEqual(report.service.tenant_authority, {
    relation: "platform_device_audit_tenant_context",
    security_definer_functions: 3,
    app_can_select_relation: false
  });
  assert.deepEqual(report.service.device_audit_inbox_authority, {
    app_can_enqueue: true,
    app_can_claim: false,
    app_can_settle: false,
    maintenance_can_claim: true,
    maintenance_can_settle: true,
    maintenance_can_health: true
  });
  assert.equal(report.skipped_tests, 0);
  assert.equal(report.status, "passed");
  assert.ok(SHA256.test(report.schema.head_checksum));
  assert.ok(SHA256.test(report.schema.migrations_sha256));
  assert.ok(SHA256.test(report.suites.tap.tap_sha256));
  return report;
}

const [command, output, tapFile, expectedSource] = process.argv.slice(2);
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (command === "write" && output && tapFile) await writeEvidence(output, tapFile);
  else if (command === "verify" && output && tapFile) verifyEvidence(output, tapFile);
  else fail(`usage: postgres-qualification-evidence.mjs write <evidence> <tap> | verify <evidence> <source-sha> (command=${String(command ?? "")}, output=${Boolean(output)}, tap=${Boolean(tapFile)}, source=${Boolean(expectedSource)})`);
}
