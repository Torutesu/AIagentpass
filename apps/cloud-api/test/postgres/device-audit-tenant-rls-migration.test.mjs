import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { loadSqlMigrations } from "../../src/postgres/migration-runner.mjs";

const migrationUrl = new URL("../../../../contracts/postgres/0079_device_audit_tenant_rls.sql", import.meta.url);
const catalogUrl = new URL("../../../../contracts/catalog-v1.json", import.meta.url);
const TABLES = ["device_audit_events", "device_audit_heads", "device_audit_gaps"];

function compact(sql) {
  return sql.replace(/--[^\n]*/gu, "").replace(/\s+/gu, " ").trim();
}

test("0079 enables and forces tenant RLS on every device audit projection", async () => {
  const sql = compact(await readFile(migrationUrl, "utf8"));
  assert.match(sql, /^BEGIN; .* COMMIT;$/u);

  for (const table of TABLES) {
    assert.match(sql, new RegExp(`ALTER TABLE public\\.${table} ENABLE ROW LEVEL SECURITY`, "u"));
    assert.match(sql, new RegExp(`ALTER TABLE public\\.${table} FORCE ROW LEVEL SECURITY`, "u"));
    for (const operation of ["select", "insert", "update", "delete"]) {
      assert.match(sql, new RegExp(`CREATE POLICY ${table}_tenant_${operation}[\\s\\S]*?ON public\\.${table} FOR ${operation.toUpperCase()}`, "u"));
    }
  }

  assert.equal((sql.match(/public\.agentpass_current_organization_id\(\)/gu) ?? []).length, 15);
  assert.match(sql, /ALTER FUNCTION public\.agentpass_record_device_audit_head\(\) SECURITY DEFINER SET search_path = pg_catalog, public/u);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON TABLE public\.device_audit_events, public\.device_audit_heads, public\.device_audit_gaps FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup/u);
  assert.match(sql, /GRANT SELECT, INSERT ON TABLE public\.device_audit_events TO agentpass_app/u);
  assert.match(sql, /GRANT SELECT ON TABLE public\.device_audit_heads, public\.device_audit_gaps TO agentpass_app/u);
  assert.doesNotMatch(sql, /GRANT (?:SELECT, )?INSERT, UPDATE, DELETE ON TABLE[\s\S]*device_audit_/u);
});

test("0079 provides non-tenant policies for the migration trigger owner and backup reader", async () => {
  const sql = compact(await readFile(migrationUrl, "utf8"));
  for (const table of TABLES) {
    assert.match(sql, new RegExp(`CREATE POLICY ${table}_migrator_authority[\\s\\S]*?ON public\\.${table} FOR ALL TO agentpass_migrator USING \\(true\\) WITH CHECK \\(true\\)`, "u"));
    assert.match(sql, new RegExp(`CREATE POLICY ${table}_backup_select[\\s\\S]*?ON public\\.${table} FOR SELECT TO agentpass_backup USING \\(true\\)`, "u"));
  }
  assert.match(sql, /REVOKE ALL PRIVILEGES ON FUNCTION public\.agentpass_record_device_audit_head\(\) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup/u);
});

test("0079 is the discovered migration and has a matching catalog contract", async () => {
  const [migrations, catalog] = await Promise.all([
    loadSqlMigrations(),
    readFile(catalogUrl, "utf8").then(JSON.parse),
  ]);
  const migration = migrations.find((entry) => entry.version === 79);
  const catalogEntry = catalog.entries.find((entry) => entry.kind === "postgres-migration" && entry.version === 79);
  assert.equal(migration?.name, "0079_device_audit_tenant_rls.sql");
  assert.match(migration?.checksum ?? "", /^[0-9a-f]{64}$/u);
  assert.deepEqual(catalogEntry, {
    id: "migration.0079_device_audit_tenant_rls",
    kind: "postgres-migration",
    source: "postgres/0079_device_audit_tenant_rls.sql",
    version: 79,
    sha256: migration.checksum,
    profile: "migration-tenant",
    purpose: "migration.0079.device-audit-tenant-rls",
    implementation_status: "implemented",
    tenant_binding: {
      required: true,
      source: "database",
      paths: [
        "tables.device_audit_events.organization_id",
        "tables.device_audit_heads.organization_id",
        "tables.device_audit_gaps.organization_id",
      ],
    },
    actor_binding: { required: false, paths: [] },
    implementation_refs: ["contracts/postgres/0079_device_audit_tenant_rls.sql"],
    compatibility_fixtures: ["apps/cloud-api/test/postgres/device-audit-tenant-rls-migration.test.mjs"],
  });
});
