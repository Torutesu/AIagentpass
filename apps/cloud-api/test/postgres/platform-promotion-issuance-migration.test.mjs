import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0047_platform_promotion_issuance.sql", import.meta.url);

test("0047 is forward-only and creates the deployment head plus immutable issuance ledger", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN|INDEX)|TRUNCATE\s+TABLE/iu);
  assert.match(sql, /CREATE TABLE platform_promotion_deployments[\s\S]*current_generation bigint[\s\S]*current_candidate_id/u);
  assert.match(sql, /CREATE TABLE platform_promotion_issuances[\s\S]*promotion_id uuid PRIMARY KEY[\s\S]*deployment_id text NOT NULL[\s\S]*candidate_id text NOT NULL/u);
  assert.match(sql, /UNIQUE \(deployment_id, environment, candidate_id, idempotency_key\)/u);
  assert.match(sql, /provider_operation_id text NOT NULL[\s\S]*request_digest bytea NOT NULL[\s\S]*claim_token_digest bytea/u);
  assert.match(sql, /issued_at timestamptz NOT NULL[\s\S]*expires_at timestamptz NOT NULL[\s\S]*signer_key_fingerprint bytea NOT NULL/u);
});

test("0047 binds immutable approval/candidate identities and serializes one open deployment", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /approval_id uuid NOT NULL REFERENCES platform_promotion_approvals\(approval_id\)/u);
  assert.match(sql, /FOREIGN KEY \(current_candidate_id\) REFERENCES release_candidates\(candidate_id\)/u);
  assert.match(sql, /candidate_id = 'release-pkg-sha256-v1-' \|\| product_pkg_sha256/u);
  assert.match(sql, /CREATE UNIQUE INDEX platform_promotion_issuances_one_open[\s\S]*WHERE state IN \('reserved', 'uncertain'\)/u);
  assert.match(sql, /CREATE INDEX platform_promotion_issuances_expiry[\s\S]*claim_expires_at/u);
});

test("0047 fences claims, stores canonical evidence bytes, and atomically advances generation", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /evidence_bytes bytea[\s\S]*evidence_digest bytea[\s\S]*deployment_generation bigint/u);
  assert.match(sql, /state IN \('reserved', 'uncertain', 'committed'\)/u);
  assert.match(sql, /state = 'committed'[\s\S]*evidence_bytes IS NOT NULL[\s\S]*deployment_generation IS NOT NULL/u);
  assert.match(sql, /platform_promotion_issuances_terminal_immutable/u);
  assert.match(sql, /platform_promotion_deployments_forward_only/u);
  assert.match(sql, /evidence_digest = sha256\(evidence_bytes\)/u);
  assert.match(sql, /BEFORE INSERT OR UPDATE OR DELETE ON platform_promotion_issuances/u);
  assert.match(sql, /platform_promotion_issuances_approval_binding/u);
  assert.match(sql, /platform_promotion_issuances_candidate_binding/u);
  assert.match(sql, /platform_promotion_issuances_signer_binding/u);
  assert.match(sql, /FROM release_candidates candidate[\s\S]*FOR SHARE/u);
  assert.match(sql, /FOR SHARE OF lifecycle, key/u);
  assert.match(sql, /verification_failure/u);
  assert.match(sql, /CREATE VIEW platform_promotion_issuances_public[\s\S]*provider_operation_id[\s\S]*evidence_digest/u);
  assert.doesNotMatch(sql.slice(sql.indexOf("CREATE VIEW platform_promotion_issuances_public")), /platform_principal_ids|authorization_evidence_digests/iu);
});
