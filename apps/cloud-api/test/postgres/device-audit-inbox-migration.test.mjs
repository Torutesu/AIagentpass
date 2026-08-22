import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { loadSqlMigrations } from "../../src/postgres/migration-runner.mjs";
import { POSTGRES_SCHEMA_HEAD } from "../../src/postgres/schema-head.mjs";

const migrationUrl = new URL("../../../../contracts/postgres/0082_device_audit_inbox.sql", import.meta.url);
const recoveryMigrationUrl = new URL("../../../../contracts/postgres/0083_device_audit_inbox_lease_recovery.sql", import.meta.url);
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

test("0083 is the current contiguous catalog migration", async () => {
  const [migrations, catalog] = await Promise.all([
    loadSqlMigrations(),
    readFile(catalogUrl, "utf8").then(JSON.parse),
  ]);
  const migration = migrations.find((entry) => entry.version === 82);
  const catalogEntry = catalog.entries.find((entry) => entry.kind === "postgres-migration" && entry.version === 82);
  assert.equal(migrations.at(-1)?.name, POSTGRES_SCHEMA_HEAD.name);
  assert.equal(migrations.length, POSTGRES_SCHEMA_HEAD.migration_count);
  assert.equal(migration?.name, "0082_device_audit_inbox.sql");
  assert.equal(catalogEntry?.source, "postgres/0082_device_audit_inbox.sql");
  const recovery = migrations.find((item) => item.name === "0083_device_audit_inbox_lease_recovery.sql");
  const recoveryCatalogEntry = catalog.entries.find((entry) => entry.id === "migration.0083_device_audit_inbox_lease_recovery");
  assert.ok(recovery);
  assert.equal(recoveryCatalogEntry?.source, "postgres/0083_device_audit_inbox_lease_recovery.sql");
  assert.equal(catalogEntry?.compatibility_fixtures?.[0], "apps/cloud-api/test/postgres/device-audit-inbox-migration.test.mjs");
});

test("0083 bounds lease recovery and dead-letters rows at the attempt ceiling", async () => {
  const sql = compact(await readFile(recoveryMigrationUrl, "utf8"));
  assert.match(sql, /expired_candidates AS/u);
  assert.match(sql, /FOR UPDATE SKIP LOCKED LIMIT p_limit/u);
  assert.match(sql, /CASE WHEN i\.attempt >= 100 THEN 'dead_letter' ELSE 'pending' END/u);
  assert.match(sql, /lease_expired_attempt_limit/u);
  assert.match(sql, /state = 'processing' AND i\.claim_expires_at <= clock_timestamp\(\)/u);
});
