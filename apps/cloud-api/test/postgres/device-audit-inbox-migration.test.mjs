import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { loadSqlMigrations } from "../../src/postgres/migration-runner.mjs";

const migrationUrl = new URL("../../../../contracts/postgres/0082_device_audit_inbox.sql", import.meta.url);
const catalogUrl = new URL("../../../../contracts/catalog-v1.json", import.meta.url);

function compact(sql) { return sql.replace(/--[^\n]*/gu, "").replace(/\s+/gu, " ").trim(); }

test("0082 creates a tenant-bound lease inbox with fixed SECURITY DEFINER transitions", async () => {
  const sql = compact(await readFile(migrationUrl, "utf8"));
  assert.match(sql, /^BEGIN; .* COMMIT;$/u);
  assert.match(sql, /CREATE TABLE public\.device_audit_inbox/u);
  assert.match(sql, /UNIQUE \(organization_id, device_id, batch_id\)/u);
  assert.match(sql, /state IN \('pending','processing','accepted','uncertain','dead_letter'\)/u);
  assert.match(sql, /CREATE OR REPLACE FUNCTION public\.agentpass_device_audit_inbox_enqueue/u);
  assert.match(sql, /CREATE OR REPLACE FUNCTION public\.agentpass_device_audit_inbox_claim/u);
  assert.match(sql, /FOR UPDATE SKIP LOCKED/u);
  assert.match(sql, /CREATE OR REPLACE FUNCTION public\.agentpass_device_audit_inbox_settle/u);
  assert.match(sql, /claim_token_digest = p_claim_token_digest/u);
  assert.match(sql, /claim_expires_at > clock_timestamp\(\)/u);
  assert.match(sql, /ALTER TABLE public\.device_audit_inbox ENABLE ROW LEVEL SECURITY/u);
  assert.match(sql, /ALTER TABLE public\.device_audit_inbox FORCE ROW LEVEL SECURITY/u);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON TABLE public\.device_audit_inbox FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup/u);
});

test("0082 is the current contiguous catalog migration", async () => {
  const [migrations, catalog] = await Promise.all([
    loadSqlMigrations(),
    readFile(catalogUrl, "utf8").then(JSON.parse),
  ]);
  const migration = migrations.find((entry) => entry.version === 82);
  const catalogEntry = catalog.entries.find((entry) => entry.kind === "postgres-migration" && entry.version === 82);
  assert.equal(migrations.at(-1)?.name, "0082_device_audit_inbox.sql");
  assert.equal(migrations.length, 82);
  assert.equal(migration?.name, "0082_device_audit_inbox.sql");
  assert.equal(catalogEntry?.source, "postgres/0082_device_audit_inbox.sql");
  assert.equal(catalogEntry?.compatibility_fixtures?.[0], "apps/cloud-api/test/postgres/device-audit-inbox-migration.test.mjs");
});
