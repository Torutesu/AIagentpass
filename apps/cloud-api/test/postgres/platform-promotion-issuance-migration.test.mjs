import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0047_platform_promotion_issuance.sql", import.meta.url);

test("0047 defines immutable promotion authority, fenced leases, and monotonic deployment state", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /^BEGIN;/u);
  assert.match(sql.trim(), /COMMIT;$/u);
  assert.doesNotMatch(sql, /\bDROP\s+(?:TABLE|COLUMN|INDEX|FUNCTION|TRIGGER)\b/iu);
  assert.match(sql, /CREATE FUNCTION agentpass_promotion_digest_array_valid\(p_value jsonb\)/u);
  assert.match(sql, /jsonb_array_length\(p_value\) NOT BETWEEN 1 AND 16/u);
  assert.match(sql, /item !~ '\^\[0-9a-f\]\{64\}\$' OR item = ANY\(seen\)/u);
  assert.match(sql, /CREATE TABLE platform_promotion_issuances/u);
  assert.match(sql, /PRIMARY KEY \(deployment_id, environment, promotion_id\)/u);
  assert.match(sql, /UNIQUE \(deployment_id, environment, idempotency_key\)/u);
  assert.match(sql, /CREATE UNIQUE INDEX platform_promotion_approvals_issuance_binding/u);
  assert.match(sql, /candidate_id text NOT NULL/u);
  assert.match(sql, /approval_id uuid NOT NULL REFERENCES platform_promotion_approvals\(approval_id\)/u);
  assert.match(sql, /FOREIGN KEY \(\s*approval_id, deployment_id, environment, candidate_id, source_commit,\s*source_tree, product_pkg_sha256, release_manifest_sha256, sbom_sha256,\s*image_digest, approval_digest\s*\)\s*REFERENCES platform_promotion_approvals/su);
  assert.match(sql, /qualification_report_digests jsonb NOT NULL/u);
  assert.match(sql, /qualification_report_digests IS DISTINCT FROM to_jsonb\(approval_qualification_report_digests\)/u);
  assert.match(sql, /provider_operation_purpose text GENERATED ALWAYS/u);
  assert.match(sql, /FOREIGN KEY \(provider_operation_purpose, provider_operation_id\)\s*REFERENCES managed_signer_provider_operations \(purpose, operation_id\)/u);
  assert.match(sql, /provider_key_id IS DISTINCT FROM NEW\.signer_key_id/u);
  assert.match(sql, /provider_state <> 'committed' OR provider_expires_at <= clock_timestamp\(\)/u);
  assert.match(sql, /claim_token_digest bytea/u);
  assert.match(sql, /authority_digest bytea NOT NULL CHECK \(octet_length\(authority_digest\) = 32\)/u);
  assert.match(sql, /state IN \('reserved', 'committed', 'uncertain', 'rejected'\)/u);
  assert.match(sql, /state = 'reserved' AND provider_operation_id IS NOT NULL[\s\S]*?claim_token_digest IS NOT NULL/u);
  assert.match(sql, /state = 'uncertain' AND claim_token_digest IS NULL/u);
  assert.match(sql, /state = 'committed' AND claim_token_digest IS NULL AND claim_expires_at IS NULL[\s\S]*?provider_operation_id IS NOT NULL[\s\S]*?evidence IS NOT NULL/u);
  assert.match(sql, /platform_promotion_issuances_one_open/u);
  assert.match(sql, /WHERE state IN \('reserved', 'uncertain'\)/u);
  assert.match(sql, /platform_promotion_issuances_claims/u);
  assert.match(sql, /platform_promotion_issuances_immutable_authority/u);
  assert.match(sql, /platform_promotion_issuances_transition/u);
  assert.match(sql, /platform_promotion_issuances_terminal_immutable/u);
  assert.match(sql, /platform_promotion_issuances_claim_clock_fence/u);
  assert.match(sql, /platform_promotion_issuances_evidence_binding/u);
  assert.match(sql, /OLD\.state, NEW\.state.*reserved.*committed.*reserved.*uncertain.*reserved.*rejected.*uncertain.*committed.*uncertain.*rejected/su);
  assert.match(sql, /CREATE TRIGGER platform_promotion_issuances_guard\s+BEFORE INSERT OR UPDATE OR DELETE/u);
  assert.match(sql, /CREATE TABLE platform_deployment_state/u);
  assert.match(sql, /FOREIGN KEY \(deployment_id, environment, promotion_id\)\s+REFERENCES platform_promotion_issuances/u);
  assert.match(sql, /CHECK \(\(state = 'idle' AND generation = 0 AND promotion_id IS NULL AND evidence_digest IS NULL\)/u);
  assert.match(sql, /platform_deployment_generation_monotonic/u);
  assert.match(sql, /NEW\.generation < OLD\.generation/u);
  assert.match(sql, /NEW\.generation <> OLD\.generation \+ 1/u);
  assert.match(sql, /platform_deployment_state_committed_issuance_fk/u);
  assert.match(sql, /CREATE TRIGGER platform_deployment_generation_guard\s+BEFORE INSERT OR UPDATE/u);
  assert.match(sql, /CREATE FUNCTION agentpass_platform_promotion_json_canonical\(p_value jsonb\)/u);
  assert.match(sql, /CREATE FUNCTION agentpass_platform_promotion_authority_digest\([\s\S]*p_expected_deployment_generation bigint/u);
  assert.match(sql, /NEW\.authority_digest IS DISTINCT FROM agentpass_platform_promotion_authority_digest\(/u);
  assert.match(sql, /platform_promotion_issuances_authority_digest/u);
  assert.match(sql, /CREATE FUNCTION agentpass_platform_promotion_audit_event_hash\([\s\S]*p_details jsonb/u);
  assert.match(sql, /NEW\.event_hash IS DISTINCT FROM agentpass_platform_promotion_audit_event_hash\(/u);
  assert.match(sql, /platform_promotion_audit_events_event_hash/u);
  assert.match(sql, /CREATE TRIGGER platform_promotion_audit_events_guard\s+BEFORE INSERT OR UPDATE OR DELETE ON platform_promotion_audit_events/u);
  assert.match(sql, /CREATE TRIGGER platform_promotion_audit_events_truncate_guard\s+BEFORE TRUNCATE ON platform_promotion_audit_events\s+FOR EACH STATEMENT/u);
  assert.match(sql, /REVOKE TRUNCATE ON TABLE platform_promotion_audit_events FROM agentpass_app, agentpass_backup/u);
  assert.match(sql, /TG_OP = 'INSERT' AND NEW\.state <> 'reserved'/u);
  assert.match(sql, /platform_promotion_issuances_generation_fence/u);
  assert.match(sql, /NEW\.generation <> issuance_expected_generation \+ 1/u);
  assert.match(sql, /NEW\.evidence_digest IS DISTINCT FROM issuance_evidence_digest/u);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON TABLE\n  platform_promotion_approvals,[\s\S]*?FROM PUBLIC, agentpass_app, agentpass_backup/u);
  for (const table of ["platform_promotion_approvals", "platform_promotion_issuances", "platform_deployment_state"]) {
    assert.match(sql, new RegExp(`ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY`, "u"));
    assert.match(sql, new RegExp(`ALTER TABLE ${table} FORCE ROW LEVEL SECURITY`, "u"));
  }
  for (const policy of [
    "platform_promotion_approvals_runtime_select", "platform_promotion_approvals_migration_all",
    "platform_promotion_issuances_runtime_select", "platform_promotion_issuances_runtime_insert",
    "platform_promotion_issuances_runtime_update", "platform_promotion_issuances_migration_all",
    "platform_deployment_state_runtime_select", "platform_deployment_state_runtime_insert",
    "platform_deployment_state_runtime_update", "platform_deployment_state_migration_all"
  ]) assert.match(sql, new RegExp(`CREATE POLICY ${policy}`, "u"));
  for (const policy of [
    "platform_promotion_audit_events_runtime_select", "platform_promotion_audit_events_runtime_insert",
    "platform_promotion_audit_events_backup_select", "platform_promotion_audit_events_migration_all"
  ]) assert.match(sql, new RegExp(`CREATE POLICY ${policy}`, "u"));
});
