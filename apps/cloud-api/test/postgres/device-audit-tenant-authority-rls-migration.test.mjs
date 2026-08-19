import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { loadSqlMigrations } from "../../src/postgres/migration-runner.mjs";
import { derivePostgresSchemaHead } from "../../src/postgres/schema-head.mjs";

const migrationUrl = new URL("../../../../contracts/postgres/0081_device_audit_tenant_authority_rls.sql", import.meta.url);
const catalogUrl = new URL("../../../../contracts/catalog-v1.json", import.meta.url);
const TABLES = ["device_audit_events", "device_audit_heads", "device_audit_gaps"];

function compact(sql) {
  return sql.replace(/--[^\n]*/gu, "").replace(/\s+/gu, " ").trim();
}

test("0081 replaces caller-controlled tenant GUC RLS with transaction-bound membership authority", async () => {
  const sql = compact(await readFile(migrationUrl, "utf8"));
  assert.match(sql, /^BEGIN; .* COMMIT;$/u);
  assert.match(sql, /CREATE TABLE public\.platform_device_audit_tenant_context/u);
  assert.match(sql, /CREATE OR REPLACE FUNCTION public\.agentpass_authorize_device_audit_tenant\( p_organization_id uuid, p_member_id uuid \)[\s\S]*?SECURITY DEFINER SET search_path = pg_catalog, public/u);
  assert.match(sql, /membership\.organization_id = p_organization_id/u);
  assert.match(sql, /membership\.member_id = p_member_id/u);
  assert.match(sql, /membership\.status = 'active'/u);
  assert.match(sql, /CREATE OR REPLACE FUNCTION public\.agentpass_device_audit_current_organization_id\(\)[\s\S]*?SECURITY DEFINER SET search_path = pg_catalog, public/u);
  assert.doesNotMatch(sql, /current_setting\(/u);
  assert.doesNotMatch(sql, /agentpass\.organization_id/u);
  assert.doesNotMatch(sql, /SET LOCAL/u);

  for (const table of TABLES) {
    assert.match(sql, new RegExp(`DROP POLICY ${table}_tenant_select ON public\\.${table}`, "u"));
    for (const operation of ["select", "insert", "update", "delete"]) {
      assert.match(sql, new RegExp(`CREATE POLICY ${table}_tenant_${operation}[\\s\\S]*?ON public\\.${table} FOR ${operation.toUpperCase()}[\\s\\S]*?agentpass_device_audit_current_organization_id\\(\\)`, "u"));
    }
  }

  assert.match(sql, /REVOKE ALL PRIVILEGES ON TABLE public\.platform_device_audit_tenant_context[\s\S]*?agentpass_app/u);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_authorize_device_audit_tenant\(uuid, uuid\) TO agentpass_app/u);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_device_audit_current_organization_id\(\)[\s\S]*?agentpass_app, agentpass_backup, agentpass_migrator/u);
});

test("0081 is contiguous, catalog-registered, and included in the derived schema head", async () => {
  const [migrations, catalogBytes] = await Promise.all([
    loadSqlMigrations(),
    readFile(catalogUrl),
  ]);
  const catalog = JSON.parse(catalogBytes.toString("utf8"));
  const migration = migrations.find((entry) => entry.version === 81);
  const catalogEntry = catalog.entries.find((entry) => entry.kind === "postgres-migration" && entry.version === 81);
  assert.equal(migrations.at(-1)?.name, "0081_device_audit_tenant_authority_rls.sql");
  assert.equal(migrations.length, 81);
  assert.equal(migration?.name, "0081_device_audit_tenant_authority_rls.sql");
  assert.deepEqual(catalogEntry, {
    id: "migration.0081_device_audit_tenant_authority_rls",
    kind: "postgres-migration",
    source: "postgres/0081_device_audit_tenant_authority_rls.sql",
    version: 81,
    profile: "migration-tenant",
    purpose: "migration.0081.device-audit-tenant-authority-rls",
    implementation_status: "implemented",
    tenant_binding: {
      required: true,
      source: "database",
      paths: [
        "tables.device_audit_events.organization_id",
        "tables.device_audit_heads.organization_id",
        "tables.device_audit_gaps.organization_id",
        "tables.platform_device_audit_tenant_context.organization_id",
      ],
    },
    actor_binding: {
      required: true,
      paths: [
        "tables.platform_device_audit_tenant_context.member_id",
        "tables.memberships.member_id",
      ],
    },
    implementation_refs: [
      "contracts/postgres/0081_device_audit_tenant_authority_rls.sql",
      "scripts/postgres/device-audit-postgres-qualification.integration.test.mjs",
    ],
    compatibility_fixtures: ["apps/cloud-api/test/postgres/device-audit-tenant-authority-rls-migration.test.mjs"],
  });

  const head = derivePostgresSchemaHead({ catalog, migrations, catalogBytes });
  assert.equal(head.version, 81);
  assert.equal(head.migration_count, 81);
  assert.equal(head.name, migration.name);
  assert.equal(head.checksum, migration.checksum);
});
