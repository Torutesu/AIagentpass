import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0013_refresh_nonce_key_id.sql", import.meta.url);

test("0013 is forward-only, agrees with the bounded codec key-id pattern, and visibly stales legacy deliveries", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN)|TRUNCATE/iu);
  assert.match(sql, /ADD COLUMN refresh_nonce_key_id text NOT NULL DEFAULT 'refresh-nonce-v1'/);
  assert.match(sql, /CHECK \(refresh_nonce_key_id ~ '\^refresh-nonce-v\[1-9\]\[0-9\]\{0,8\}\$'\)/);
  assert.match(sql, /WITH legacy_deliveries AS \([\s\S]*UPDATE device_refresh_outbox[\s\S]*status IN \('pending', 'delivered'\)/);
  assert.match(sql, /RETURNING organization_id, device_id, desired_generation/);
  assert.match(sql, /UPDATE device_control_plane_state state[\s\S]*refresh_state = CASE WHEN state\.refresh_state = 'revoked' THEN 'revoked' ELSE 'stale' END/);
  assert.match(sql, /last_error_code = 'refresh_nonce_rekey_required'/);
  assert.match(sql, /state\.desired_generation = legacy\.desired_generation/);
  assert.match(sql, /DROP FUNCTION IF EXISTS agentpass_request_device_refresh\(uuid, uuid, uuid, bigint, bytea, timestamptz\)/);
  assert.match(sql, /request_refresh_nonce_key_id !~ '\^refresh-nonce-v\[1-9\]\[0-9\]\{0,8\}\$'/);
  assert.match(sql, /refresh_nonce_key_id[\s\S]*refresh_nonce_digest[\s\S]*replayed/);
  assert.match(sql, /expected_nonce_digest IS DISTINCT FROM request_ack_nonce_digest/u);
  assert.match(sql, /ACK refresh nonce does not match/u);
  assert.match(sql, /observed_generation = GREATEST\(COALESCE\(state\.observed_generation, 0\), refresh\.desired_generation\)/u);
});
