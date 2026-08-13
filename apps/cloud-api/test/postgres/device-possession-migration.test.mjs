import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0017_device_possession_verification.sql", import.meta.url);

test("0017 adds trusted candidate bindings and tenant-safe possession receipts", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN)|TRUNCATE/iu);
  assert.match(sql, /CREATE TABLE release_candidates \([\s\S]*source_commit text NOT NULL[\s\S]*artifact_sha256 text NOT NULL[\s\S]*manifest_sha256 text NOT NULL[\s\S]*team_id text NOT NULL/u);
  assert.match(sql, /release_candidates_forward_only[\s\S]*BEFORE UPDATE OR DELETE ON release_candidates/u);
  assert.match(sql, /ALTER TABLE device_enrollments[\s\S]*ADD COLUMN proof_version integer NOT NULL DEFAULT 1[\s\S]*ADD COLUMN candidate_id text[\s\S]*ADD COLUMN device_key_fingerprint text[\s\S]*ADD COLUMN challenge_nonce_digest bytea/u);
  assert.match(sql, /device_enrollments_v2_binding_complete[\s\S]*proof_version = 2[\s\S]*challenge_nonce_digest IS NOT NULL/u);
  assert.match(sql, /device_enrollments_candidate_fk[\s\S]*REFERENCES release_candidates\(candidate_id\)/u);
  assert.match(sql, /device_enrollments_tenant_identity[\s\S]*UNIQUE \(organization_id, id\)/u);
  assert.match(sql, /device_enrollments_possession_identity[\s\S]*UNIQUE \(organization_id, id, device_id, candidate_id,[\s\S]*device_key_fingerprint, challenge_nonce_digest\)/u);
  assert.match(sql, /device_enrollments_v2_binding_forward_only[\s\S]*BEFORE INSERT OR UPDATE OF proof_version, candidate_id/u);
  assert.match(sql, /candidate\.status = 'active'[\s\S]*FOR UPDATE/u);
  assert.match(sql, /CREATE TABLE device_enrollment_possession_receipts \([\s\S]*PRIMARY KEY \(organization_id, enrollment_id\)[\s\S]*UNIQUE \(organization_id, device_id, device_key_epoch\)/u);
  assert.match(sql, /FOREIGN KEY \(organization_id, enrollment_id\)[\s\S]*REFERENCES device_enrollments\(organization_id, id\)/u);
  assert.match(sql, /FOREIGN KEY \(organization_id, enrollment_id, device_id, candidate_id,[\s\S]*device_key_fingerprint, challenge_nonce_digest\)[\s\S]*REFERENCES device_enrollments\(organization_id, id, device_id, candidate_id,[\s\S]*device_key_fingerprint, challenge_nonce_digest\)/u);
  assert.match(sql, /FOREIGN KEY \(organization_id, device_id, device_key_epoch\)[\s\S]*REFERENCES device_key_epochs\(organization_id, device_id, key_epoch\)/u);
  assert.match(sql, /FOREIGN KEY \(candidate_id, source_commit, artifact_sha256, team_id\)[\s\S]*REFERENCES release_candidates\(candidate_id, source_commit, artifact_sha256, team_id\)/u);
  assert.match(sql, /CREATE INDEX device_enrollment_possession_receipts_device_lookup/u);
  assert.match(sql, /CREATE INDEX device_enrollment_possession_receipts_candidate_lookup/u);
});

test("0017 stores only challenge digests and rejects non-canonical or nested receipt material", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /challenge_nonce_digest bytea[\s\S]*octet_length\(challenge_nonce_digest\) = 32/u);
  assert.match(sql, /SELECT count\(\*\) INTO key_count FROM jsonb_object_keys\(statement_value\)/u);
  assert.match(sql, /jsonb_typeof\(item\.value\) NOT IN \('string', 'number'\)/u);
  assert.match(sql, /value->>'challenge_nonce_digest' ~ '\^\[0-9a-f\]\{64\}\$'/u);
  assert.doesNotMatch(sql, /\b(?:raw_nonce|nonce_value|credential_secret|private_key)\b/iu);
  assert.match(sql, /device_enrollment_possession_receipts_forward_only[\s\S]*BEFORE UPDATE OR DELETE ON device_enrollment_possession_receipts/u);
  assert.match(sql, /purpose text NOT NULL[\s\S]*device-enrollment-possession-receipt/u);
  assert.match(sql, /signature_algorithm text NOT NULL[\s\S]*ed25519[\s\S]*p256-sha256/u);
  assert.match(sql, /signature_base64url text NOT NULL[\s\S]*\^\[A-Za-z0-9_-\]\{86\}\$/u);
});
