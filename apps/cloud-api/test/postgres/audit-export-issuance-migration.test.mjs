import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { loadSqlMigrations } from "../../src/postgres/migration-runner.mjs";

const migrationUrl = new URL("../../../../contracts/postgres/0043_audit_export_issuance.sql", import.meta.url);

function compact(sql) {
  return sql
    .replace(/--[^\n]*/gu, "")
    .replace(/\s+/gu, " ")
    .trim();
}

function tableDefinition(sql) {
  const start = sql.indexOf("CREATE TABLE audit_export_issuances");
  const end = sql.indexOf("ALTER TABLE audit_export_issuances", start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  return sql.slice(start, end);
}

test("0043 is transactional, forward-only, tenant-qualified, and non-destructive", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  const normalized = compact(sql);

  assert.match(normalized, /^BEGIN; .* COMMIT;$/u);
  assert.doesNotMatch(normalized, /\b(?:DROP|TRUNCATE)\s+(?:TABLE|audit_export_issuances)\b/iu);
  assert.match(normalized, /CREATE TABLE audit_export_issuances \(/u);
  assert.match(normalized, /organization_id uuid NOT NULL REFERENCES organizations\(id\)/u);
  assert.match(normalized, /PRIMARY KEY \(organization_id, export_id, environment, chain, idempotency_key\)/u);
  assert.match(normalized, /UNIQUE \(organization_id, export_id\)/u);
  assert.match(normalized, /UNIQUE \(organization_id, environment, chain, idempotency_key\)/u);
  assert.match(normalized, /record_count bigint NOT NULL CHECK \(record_count BETWEEN 1 AND 9007199254740991\)/u);
  assert.match(normalized, /record_count = to_audit_position - from_audit_position \+ 1/u);
  assert.match(normalized, /request_digest = sha256\(convert_to\(concat\(/u);
  assert.match(normalized, /payload_digest bytea NOT NULL CHECK \(octet_length\(payload_digest\) = 32 AND payload_digest <> decode\(repeat\('00', 32\), 'hex'\)\)/u);
});

test("0043 freezes authority, bounds public committed evidence, and retains uncertain state", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  const definition = compact(tableDefinition(sql));
  const normalized = compact(sql);

  assert.match(definition, /state text NOT NULL CHECK \(state IN \('reserved', 'uncertain', 'committed'\)\)/u);
  assert.match(definition, /claim_token_digest bytea CHECK \(claim_token_digest IS NULL OR octet_length\(claim_token_digest\) = 32\)/u);
  assert.doesNotMatch(definition, /\bclaim_token\s+(?:text|varchar|bytea)\b/iu);
  assert.match(definition, /state = 'reserved'[\s\S]*claim_token_digest IS NOT NULL[\s\S]*claim_expires_at IS NOT NULL/u);
  assert.match(definition, /state = 'uncertain'[\s\S]*claim_token_digest IS NULL[\s\S]*claim_expires_at IS NULL/u);
  assert.match(definition, /state = 'committed'[\s\S]*audit_anchor IS NOT NULL/u);
  assert.match(sql, /CREATE FUNCTION agentpass_jsonb_object_key_count\(p_value jsonb\)[\s\S]*jsonb_object_keys\(p_value\)/u);
  assert.match(definition, /agentpass_jsonb_object_key_count\(audit_anchor\) = 7/u);
  assert.match(definition, /agentpass_jsonb_object_key_count\(audit_anchor->'statement'\) = 20/u);
  assert.match(definition, /signature_algorithm.*ed25519/u);
  assert.match(definition, /private[^\n]*key/iu);
  assert.match(normalized, /CREATE FUNCTION agentpass_guard_audit_export_issuance\(\)/u);
  assert.match(normalized, /audit_export_issuances_authority_immutable/u);
  assert.match(normalized, /audit_export_issuances_committed_immutable/u);
  assert.match(normalized, /audit_export_issuances_transition/u);
  assert.match(normalized, /BEFORE INSERT OR UPDATE OR DELETE ON audit_export_issuances/u);
});

test("0043 serializes open exports and rejects authoritative range overlap without extensions", async () => {
  const sql = compact(await readFile(migrationUrl, "utf8"));

  assert.doesNotMatch(sql, /CREATE EXTENSION|EXCLUDE USING/iu);
  assert.match(sql, /CREATE UNIQUE INDEX audit_export_issuances_one_open_export ON audit_export_issuances \(organization_id, environment, chain\) WHERE state IN \('reserved', 'uncertain'\);/u);
  assert.match(sql, /pg_advisory_xact_lock\(hashtextextended\([\s\S]*agentpass:audit-export/u);
  assert.match(sql, /existing\.from_audit_position <= NEW\.to_audit_position[\s\S]*existing\.to_audit_position >= NEW\.from_audit_position/u);
  assert.match(sql, /audit_export_issuances_non_overlapping_ranges/u);
  assert.match(sql, /CREATE INDEX audit_export_issuances_lease ON audit_export_issuances \(\s*claim_expires_at,/u);
  assert.match(sql, /CREATE INDEX audit_export_issuances_retention ON audit_export_issuances \(\s*expires_at,/u);
});

test("0043 enables forced organization RLS with explicit CRUD policies", async () => {
  const sql = compact(await readFile(migrationUrl, "utf8"));

  assert.match(sql, /ALTER TABLE audit_export_issuances ENABLE ROW LEVEL SECURITY; ALTER TABLE audit_export_issuances FORCE ROW LEVEL SECURITY;/u);
  for (const action of ["SELECT", "INSERT", "UPDATE", "DELETE"]) {
    assert.match(sql, new RegExp(`CREATE POLICY audit_export_issuances_tenant_${action.toLowerCase()} ON audit_export_issuances FOR ${action}`, "u"));
  }
  assert.match(sql, /USING \(organization_id = agentpass_current_organization_id\(\)\)/u);
  assert.match(sql, /WITH CHECK \(organization_id = agentpass_current_organization_id\(\)\)/u);
  assert.match(sql, /audit_export_issuances_append_only/u);
});

test("0043 is discovered as migration 43 with a content-derived checksum", async () => {
  const migrations = await loadSqlMigrations();
  const migration = migrations.find((item) => item.version === 43);

  assert.equal(migration?.name, "0043_audit_export_issuance.sql");
  assert.match(migration?.checksum ?? "", /^[0-9a-f]{64}$/u);
});
