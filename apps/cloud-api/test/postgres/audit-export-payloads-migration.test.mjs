import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { loadSqlMigrations } from "../../src/postgres/migration-runner.mjs";

const migrationUrl = new URL("../../../../contracts/postgres/0046_audit_export_payloads.sql", import.meta.url);

function compact(sql) {
  return sql.replace(/--[^\n]*/gu, "").replace(/\s+/gu, " ").trim();
}

function tableDefinition(sql) {
  const start = sql.indexOf("CREATE TABLE audit_export_payloads");
  const end = sql.indexOf("CREATE FUNCTION agentpass_bind_audit_export_payload", start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  return sql.slice(start, end);
}

test("0046 is transactional, additive, and keyed to the exact issuance identity", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  const normalized = compact(sql);
  const definition = compact(tableDefinition(sql));

  assert.match(normalized, /^BEGIN; .* COMMIT;$/u);
  assert.doesNotMatch(normalized, /\b(?:DROP|TRUNCATE)\b/iu);
  assert.match(definition, /CREATE TABLE audit_export_payloads \(/u);
  assert.match(definition, /organization_id uuid NOT NULL/u);
  assert.match(definition, /PRIMARY KEY \(organization_id, export_id, environment, chain, idempotency_key\)/u);
  assert.match(definition, /FOREIGN KEY \(organization_id, export_id, environment, chain, idempotency_key\)[\s\S]*REFERENCES audit_export_issuances\s*\(organization_id, export_id, environment, chain, idempotency_key\)/u);
});

test("0046 stores bounded UTF-8 JSON with two-way digest and JSON binding", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  const definition = compact(tableDefinition(sql));

  assert.match(definition, /payload_bytes bytea NOT NULL/u);
  assert.match(definition, /octet_length\(payload_bytes\) BETWEEN 1 AND 262144/u);
  assert.match(definition, /payload_json jsonb NOT NULL/u);
  assert.match(definition, /convert_from\(payload_bytes, 'UTF8'\)::jsonb = payload_json/u);
  assert.match(definition, /payload_digest bytea NOT NULL/u);
  assert.match(definition, /payload_digest = sha256\(payload_bytes\)/u);
  assert.match(sql, /issuance_digest IS DISTINCT FROM NEW\.payload_digest/u);
  assert.match(sql, /issuance\.payload_digest = payload\.payload_digest/u);
  assert.match(sql, /jsonb_path_exists/u);
  assert.match(sql, /@\.key like_regex/u);
  assert.match(sql, /-----BEGIN \[\^-\]\*PRIVATE KEY-----/u);
});

test("0046 requires payload insertion during reservation and supports committed replay retrieval", async () => {
  const sql = compact(await readFile(migrationUrl, "utf8"));

  assert.match(sql, /issuance_state IS DISTINCT FROM 'reserved'/u);
  assert.match(sql, /CREATE CONSTRAINT TRIGGER audit_export_issuances_payload_required AFTER INSERT ON audit_export_issuances DEFERRABLE INITIALLY DEFERRED/u);
  assert.match(sql, /payload\.payload_digest = NEW\.payload_digest/u);
  assert.match(sql, /CREATE VIEW audit_export_committed_payloads WITH \(security_invoker = true\) AS/u);
  assert.match(sql, /WHERE issuance\.state = 'committed'/u);
});

test("0046 makes payloads immutable and tenant isolated with forced RLS", async () => {
  const sql = compact(await readFile(migrationUrl, "utf8"));

  assert.match(sql, /BEFORE INSERT OR UPDATE OR DELETE ON audit_export_payloads/u);
  assert.match(sql, /audit_export_payloads_immutable/u);
  assert.match(sql, /ALTER TABLE audit_export_payloads ENABLE ROW LEVEL SECURITY; ALTER TABLE audit_export_payloads FORCE ROW LEVEL SECURITY;/u);
  assert.match(sql, /CREATE POLICY audit_export_payloads_tenant_select ON audit_export_payloads FOR SELECT USING \(organization_id = agentpass_current_organization_id\(\)\)/u);
  assert.match(sql, /CREATE POLICY audit_export_payloads_tenant_insert ON audit_export_payloads FOR INSERT WITH CHECK \(organization_id = agentpass_current_organization_id\(\)\)/u);
  assert.doesNotMatch(tableDefinition(await readFile(migrationUrl, "utf8")), /(?:^|,)\s*(?:claim_token|private_key|private_material|credential|provider_response|signing_bytes)\s+(?:text|bytea|jsonb)\b/imu);
});

test("0046 is discovered as migration 46 with a content-derived checksum", async () => {
  const migration = (await loadSqlMigrations()).find((item) => item.version === 46);
  assert.equal(migration?.name, "0046_audit_export_payloads.sql");
  assert.match(migration?.checksum ?? "", /^[0-9a-f]{64}$/u);
});
