import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL(
  "../../../../contracts/postgres/0048_platform_promotion_authority_boundary.sql",
  import.meta.url
);

test("0048 exposes only fixed-search-path SECURITY DEFINER authority functions", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN|INDEX)|TRUNCATE\s+TABLE|DISABLE\s+TRIGGER/iu);
  assert.match(sql, /CREATE FUNCTION agentpass_platform_promotion_issuance_reserve\([\s\S]*SECURITY DEFINER[\s\S]*SET search_path = pg_catalog, public/u);
  assert.match(sql, /CREATE FUNCTION agentpass_platform_promotion_issuance_commit\([\s\S]*p_signing_bytes bytea[\s\S]*p_evidence_bytes bytea[\s\S]*SECURITY DEFINER[\s\S]*SET search_path = pg_catalog, public/u);
  assert.match(sql, /REVOKE ALL ON FUNCTION agentpass_platform_promotion_issuance_commit\([\s\S]*FROM PUBLIC/u);
  assert.match(sql, /REVOKE SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER[\s\S]*platform_promotion_deployments, platform_promotion_issuances FROM PUBLIC/u);
  assert.doesNotMatch(sql, /GRANT\s+(?:ALL|EXECUTE|SELECT|INSERT|UPDATE|DELETE)[\s\S]*\sTO\s+PUBLIC/iu);
  assert.match(sql, /managed_signer_provider_operations[\s\S]*FROM agentpass_app, agentpass_backup, PUBLIC/u);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION agentpass_platform_promotion_issuance_reserve[\s\S]*TO agentpass_app/u);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION agentpass_platform_promotion_issuance_commit[\s\S]*TO agentpass_app/u);
});

test("0048 binds exact domain-separated signing bytes to the stored row", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  const commit = sql.slice(sql.indexOf("CREATE FUNCTION agentpass_platform_promotion_issuance_commit"));
  assert.match(commit, /expected_signing_bytes := convert_to\('AgentPass-Promotion-Evidence-v3', 'UTF8'\) \|\| decode\('00', 'hex'\)[\s\S]*convert_to\(statement_text, 'UTF8'\)/u);
  assert.match(commit, /p_signing_bytes IS DISTINCT FROM expected_signing_bytes/u);
  assert.match(commit, /expected_request_digest := agentpass_platform_promotion_request_digest\([\s\S]*expected_signing_bytes[\s\S]*issuance_row\.key_id[\s\S]*issuance_row\.key_version[\s\S]*issuance_row\.purpose[\s\S]*issuance_row\.signing_version/u);
  assert.match(commit, /issuance_row\.provider_operation_id <> 'managed-signer-v1-' \|\| encode\(expected_request_digest, 'hex'\)/u);
  assert.match(commit, /issuance_row\.request_digest IS DISTINCT FROM expected_request_digest/u);
});

test("0048 proves evidence statement, signature, key epoch, and provider ledger agree", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  const commit = sql.slice(sql.indexOf("CREATE FUNCTION agentpass_platform_promotion_issuance_commit"));
  assert.match(commit, /convert_from\(p_evidence_bytes, 'UTF8'\)::jsonb/u);
  assert.match(commit, /expected_evidence_text :=[\s\S]*statement_text/u);
  assert.ok(commit.includes(`'{"signature":'`));
  assert.ok(commit.includes(`',"statement":' || statement_text`));
  assert.ok(commit.includes(`',"version":3}'`));
  assert.match(commit, /convert_to\(expected_evidence_text, 'UTF8'\) IS DISTINCT FROM p_evidence_bytes/u);
  assert.match(commit, /evidence_json->'statement' IS DISTINCT FROM statement_json/u);
  assert.match(commit, /evidence_json->>'statement_hash' <> encode\(sha256\(convert_to\(statement_text, 'UTF8'\)\), 'hex'\)/u);
  assert.match(commit, /evidence_json->>'signer_key_fingerprint' <> expected_fingerprint/u);
  assert.match(commit, /evidence_json->>'signature' <> expected_signature/u);
  assert.match(commit, /SELECT lifecycle\.version, key\.key_id, key\.key_version, key\.public_key_fingerprint[\s\S]*FROM managed_signer_key_lifecycles lifecycle[\s\S]*JOIN managed_signer_keys key[\s\S]*FOR SHARE OF lifecycle, key/u);
  assert.match(commit, /FROM managed_signer_signing_idempotency signing[\s\S]*signing\.operation_id = issuance_row\.provider_operation_id[\s\S]*FOR UPDATE/u);
  assert.match(commit, /signer_row\.status <> 'committed'[\s\S]*signer_row\.request_digest IS DISTINCT FROM expected_request_digest[\s\S]*signer_row\.key_id <> issuance_row\.key_id[\s\S]*signer_row\.key_version <> issuance_row\.key_version[\s\S]*signer_row\.reserved_lifecycle_version <> issuance_row\.lifecycle_version[\s\S]*signer_row\.signature IS DISTINCT FROM p_signature/u);
  assert.match(commit, /FROM managed_signer_provider_operations provider[\s\S]*provider\.operation_id = issuance_row\.provider_operation_id[\s\S]*FOR UPDATE/u);
  assert.match(commit, /provider_row\.state <> 'committed'[\s\S]*provider_row\.bytes_length <> octet_length\(expected_signing_bytes\)[\s\S]*provider_row\.request_digest IS DISTINCT FROM expected_request_digest/u);
  assert.match(commit, /provider_row\.signature IS DISTINCT FROM p_signature[\s\S]*sha256\(provider_row\.public_key_der\) IS DISTINCT FROM issuance_row\.signer_key_fingerprint/u);
  assert.match(commit, /provider_row\.provider_receipt_provider IS NULL[\s\S]*provider_row\.provider_receipt_id IS NULL[\s\S]*provider_row\.expires_at <= clock_timestamp\(\)/u);
});
