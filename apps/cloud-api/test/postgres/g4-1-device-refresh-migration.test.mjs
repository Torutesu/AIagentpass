import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0012_device_refresh_authority.sql", import.meta.url);

test("G4.1 migration is forward-only and preserves tenant-qualified generation state", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN)|TRUNCATE/iu);
  assert.match(sql, /CREATE TABLE control_plane_authority_generations \([\s\S]*PRIMARY KEY \(organization_id, generation\)/);
  assert.match(sql, /FOREIGN KEY \(organization_id\) REFERENCES organizations\(id\)/);
  assert.match(sql, /control_plane_authority_current[\s\S]*WHERE superseded_at IS NULL/);
  assert.match(sql, /agentpass_guard_authority_generation_insert/);
  assert.match(sql, /generation <> COALESCE\(latest_generation, 0\) \+ 1/);
  assert.match(sql, /agentpass_advance_authority_generation/);

  assert.match(sql, /CREATE TABLE device_key_epochs \([\s\S]*PRIMARY KEY \(organization_id, device_id, key_epoch\)/);
  assert.match(sql, /FOREIGN KEY \(organization_id, device_id\) REFERENCES devices\(organization_id, id\)/);
  assert.match(sql, /device_key_epochs_current[\s\S]*WHERE status = 'active'/);
  assert.match(sql, /key_algorithm text NOT NULL CHECK \(key_algorithm IN \('p256-sha256', 'ed25519'\)\)/);
  assert.match(sql, /public_key_pem text NOT NULL/);
  assert.match(sql, /octet_length\(public_key_pem\) BETWEEN 64 AND 8192/);
  assert.match(sql, /public_key_pem !~ 'PRIVATE\[\[:space:\]\]\+KEY'/);
  assert.match(sql, /decode\([\s\S]*'base64'[\s\S]*BETWEEN 32 AND 4096/);
  assert.match(sql, /FROM devices[\s\S]*WHERE status = 'active' AND key_algorithm IS NOT NULL AND public_key_pem IS NOT NULL/);
  assert.match(sql, /device_key_epochs_monotonic/);
  assert.match(sql, /device_key_epochs_forward_only/);
  assert.match(sql, /device key epoch identity is immutable/);
  assert.match(sql, /device key epoch status only moves from active to retired/);
  assert.match(sql, /ELSIF OLD\.status = 'active' AND NEW\.status = 'retired' THEN[\s\S]*IF NEW\.retired_at IS NULL/);
  assert.match(sql, /ELSIF NEW\.status <> OLD\.status THEN/);

  assert.match(sql, /CREATE TABLE device_control_plane_state \([\s\S]*desired_generation bigint NOT NULL[\s\S]*observed_generation bigint/);
  assert.match(sql, /refresh_state text NOT NULL CHECK \(refresh_state IN \('pending', 'fetching', 'applied', 'blocked', 'stale', 'offline', 'revoked'\)\)/);
  assert.doesNotMatch(sql, /refresh_state[^\n]*delivered|refresh_state[^\n]*failed/iu);
  assert.match(sql, /FOREIGN KEY \(organization_id, desired_generation\)[\s\S]*REFERENCES control_plane_authority_generations\(organization_id, generation\)/);
  assert.match(sql, /FOREIGN KEY \(organization_id, observed_generation\)[\s\S]*REFERENCES control_plane_authority_generations\(organization_id, generation\)/);
  assert.match(sql, /device control-plane generations cannot move backwards/);
  assert.match(sql, /observed generation cannot exceed desired generation/);

  assert.match(sql, /CREATE TABLE control_bundle_statements \([\s\S]*authority_generation bigint NOT NULL[\s\S]*issued_at timestamptz NOT NULL[\s\S]*expires_at timestamptz NOT NULL/);
  assert.match(sql, /PRIMARY KEY \(organization_id, device_id, format_epoch, sequence, statement_hash\)/);
  assert.match(sql, /UNIQUE \(organization_id, device_id, format_epoch, sequence\)/);
  assert.match(sql, /INSERT INTO control_bundle_statements[\s\S]*FROM bundle_heads/);
  assert.match(sql, /DROP CONSTRAINT IF EXISTS bundle_acknowledgements_head_fk/);
  assert.match(sql, /ADD CONSTRAINT bundle_acknowledgements_statement_history_fk[\s\S]*REFERENCES control_bundle_statements\(organization_id, device_id, format_epoch, sequence, statement_hash\)[\s\S]*NOT VALID/);
  assert.match(sql, /VALIDATE CONSTRAINT bundle_acknowledgements_statement_history_fk/);
  assert.match(sql, /CREATE TRIGGER bundle_heads_record_statement[\s\S]*AFTER INSERT OR UPDATE ON bundle_heads/);
  assert.match(sql, /control bundle statement history is append-only/);

  assert.match(sql, /CREATE TABLE device_refresh_outbox \([\s\S]*refresh_nonce_digest bytea NOT NULL CHECK \(octet_length\(refresh_nonce_digest\) = 32\)/);
  assert.match(sql, /FOREIGN KEY \(organization_id, desired_generation\)[\s\S]*REFERENCES control_plane_authority_generations\(organization_id, generation\)/);
  assert.match(sql, /device_refresh_outbox_identity[\s\S]*desired_generation, refresh_nonce_digest/);
  assert.match(sql, /device_refresh_outbox_active_generation[\s\S]*WHERE status IN \('pending', 'delivered'\)/);
  assert.match(sql, /agentpass_request_device_refresh/);
  assert.match(sql, /raw nonce never enters SQL/);

  assert.match(sql, /CREATE TABLE device_refresh_delivery_attempts \([\s\S]*attempt_no integer NOT NULL CHECK \(attempt_no BETWEEN 1 AND 100\)/);
  assert.match(sql, /device_refresh_delivery_attempts_retention/);
  assert.match(sql, /device_refresh_outbox_retention/);

  assert.match(sql, /CREATE TABLE device_bundle_acknowledgements \([\s\S]*device_key_epoch bigint NOT NULL[\s\S]*ack_nonce_digest bytea NOT NULL CHECK \(octet_length\(ack_nonce_digest\) = 32\)/);
  assert.match(sql, /PRIMARY KEY \(organization_id, device_id, device_key_epoch, sequence\)/);
  assert.match(sql, /UNIQUE \(organization_id, device_id, device_key_epoch, sequence, statement_hash\)/);
  assert.match(sql, /UNIQUE \(organization_id, device_id, device_key_epoch, ack_nonce_digest\)/);
  assert.match(sql, /FOREIGN KEY \(organization_id, device_id, device_key_epoch\)[\s\S]*REFERENCES device_key_epochs\(organization_id, device_id, key_epoch\)/);
  assert.match(sql, /REFERENCES control_bundle_statements\(organization_id, device_id, format_epoch, sequence, statement_hash\)/);
  assert.doesNotMatch(sql, /device_bundle_acknowledgements[\s\S]*REFERENCES bundle_heads\(/);
  assert.doesNotMatch(sql, /device_bundle_acknowledgements[\s\S]*REFERENCES device_refresh_outbox\(/);
  assert.match(sql, /device ACK sequence cannot move backwards across key epochs/);
  assert.match(sql, /MAX\(sequence\)[\s\S]*FROM device_bundle_acknowledgements/);
  assert.match(sql, /agentpass_record_device_bundle_ack[\s\S]*ON CONFLICT \(organization_id, device_id, device_key_epoch, sequence\) DO NOTHING/);
  assert.match(sql, /ACK identity conflicts with existing evidence/);
  assert.match(sql, /device_bundle_acknowledgements_apply/);
  assert.match(sql, /reason_code IN \([\s\S]*bundle_expired[\s\S]*internal_error/);
  assert.doesNotMatch(sql, /raw_nonce|nonce text|nonce varchar|nonce character varying/iu);
});

test("G4.1 migration has same-transaction initialization for new organizations and devices", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /CREATE TRIGGER organizations_initialize_authority[\s\S]*AFTER INSERT ON organizations/);
  assert.match(sql, /CREATE TRIGGER devices_initialize_control_plane_state[\s\S]*AFTER INSERT OR UPDATE OF status, key_algorithm, public_key_pem ON devices/);
  assert.match(sql, /IF NEW\.status = 'active' AND NEW\.key_algorithm IS NOT NULL AND NEW\.public_key_pem IS NOT NULL/);
  assert.match(sql, /Pending reservations intentionally have no key material and no epoch/);
  assert.match(sql, /device key material must rotate through a new key epoch/);
  assert.match(sql, /AFTER INSERT OR UPDATE OF status, key_algorithm, public_key_pem ON devices/);
  assert.match(sql, /INSERT INTO device_key_epochs[\s\S]*key_algorithm, public_key_pem, status/);
  assert.match(sql, /INSERT INTO device_control_plane_state \(organization_id, device_id, desired_generation, refresh_state\)/);
});
