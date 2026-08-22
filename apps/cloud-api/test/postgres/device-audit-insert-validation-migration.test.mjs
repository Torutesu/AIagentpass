import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { loadSqlMigrations } from "../../src/postgres/migration-runner.mjs";

const migrationUrl = new URL("../../../../contracts/postgres/0080_device_audit_insert_validation.sql", import.meta.url);
const catalogUrl = new URL("../../../../contracts/catalog-v1.json", import.meta.url);

function compact(sql) {
  return sql.replace(/--[^\n]*/gu, "").replace(/\s+/gu, " ").trim();
}

test("0080 validates device audit evidence before the head trigger can run", async () => {
  const sql = compact(await readFile(migrationUrl, "utf8"));
  assert.match(sql, /^BEGIN; .* COMMIT;$/u);
  assert.match(sql, /CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public/u);
  assert.match(sql, /CREATE OR REPLACE FUNCTION public\.agentpass_canonical_audit_json\(value jsonb\)/u);
  assert.match(sql, /CREATE OR REPLACE FUNCTION public\.agentpass_validate_device_audit_event\(\) RETURNS trigger/u);
  assert.match(sql, /SECURITY DEFINER SET search_path = pg_catalog, public/u);
  assert.match(sql, /redacted_json->>'event_id' IS DISTINCT FROM NEW\.event_id::text/u);
  assert.match(sql, /redacted_json->>'previous_hash' IS DISTINCT FROM NEW\.previous_hash/u);
  assert.match(sql, /redacted_json->>'event_hash' IS DISTINCT FROM NEW\.event_hash/u);
  assert.match(sql, /digest\(convert_to\(public\.agentpass_canonical_audit_json\(NEW\.redacted_json - 'event_hash'\), 'UTF8'\), 'sha256'\)/u);
  assert.match(sql, /a\.organization_id = NEW\.organization_id/u);
  assert.match(sql, /a\.id = \(NEW\.redacted_json->>'agent_id'\)::uuid/u);
  assert.match(sql, /bound_device_id IS DISTINCT FROM NEW\.device_id/u);
  assert.match(sql, /BEFORE INSERT ON public\.device_audit_events/u);
  assert.match(sql, /EXECUTE FUNCTION public\.agentpass_validate_device_audit_event\(\)/u);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON FUNCTION public\.agentpass_validate_device_audit_event\(\) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup/u);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON FUNCTION public\.agentpass_canonical_audit_json\(jsonb\) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup/u);
});

test("0080 is the contiguous discovered migration and has a catalog contract", async () => {
  const [migrations, catalog] = await Promise.all([
    loadSqlMigrations(),
    readFile(catalogUrl, "utf8").then(JSON.parse),
  ]);
  const migration = migrations.find((entry) => entry.version === 80);
  const catalogEntry = catalog.entries.find((entry) => entry.kind === "postgres-migration" && entry.version === 80);
  assert.equal(migration?.name, "0080_device_audit_insert_validation.sql");
  assert.match(migration?.checksum ?? "", /^[0-9a-f]{64}$/u);
  assert.deepEqual(catalogEntry, {
    id: "migration.0080_device_audit_insert_validation",
    kind: "postgres-migration",
    source: "postgres/0080_device_audit_insert_validation.sql",
    version: 80,
    sha256: migration.checksum,
    profile: "migration-tenant",
    purpose: "migration.0080.device-audit-insert-validation",
    implementation_status: "implemented",
    tenant_binding: {
      required: true,
      source: "database",
      paths: ["tables.device_audit_events.organization_id", "tables.device_audit_events.device_id", "tables.device_audit_events.redacted_json"],
    },
    actor_binding: {
      required: true,
      paths: ["tables.device_audit_events.redacted_json.agent_id", "tables.agents.device_id"],
    },
    implementation_refs: ["contracts/postgres/0080_device_audit_insert_validation.sql"],
    compatibility_fixtures: ["apps/cloud-api/test/postgres/device-audit-insert-validation-migration.test.mjs"],
  });
});
