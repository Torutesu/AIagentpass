import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0076_refresh_outbox_wall_clock_expiry.sql", import.meta.url);

test("0076 terminalizes wall-clock-expired active outboxes before replay", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.match(sql, /CREATE OR REPLACE FUNCTION public\.agentpass_request_device_refresh/u);
  assert.match(sql, /SELECT state\.\* INTO existing_state[\s\S]*FOR UPDATE/u);
  assert.match(sql, /SET status = CASE WHEN queued\.status = 'pending' THEN 'failed' ELSE 'expired' END/u);
  assert.match(sql, /queued\.status IN \('pending', 'delivered'\)[\s\S]*queued\.expires_at <= now_value/u);
  assert.match(sql, /queued\.status IN \('pending', 'delivered'\)[\s\S]*queued\.expires_at > now_value/u);
  assert.match(sql, /last_error_code = 'refresh_expired'/u);
  assert.match(sql, /RAISE EXCEPTION USING ERRCODE = 'serialization_failure'/u);
  assert.doesNotMatch(sql, /\b(?:DROP|TRUNCATE)\b/iu);
});

test("0076 preserves the closed nonce and replay return contract", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /request_refresh_nonce_key_id text/u);
  assert.match(sql, /request_refresh_nonce_digest bytea/u);
  assert.match(sql, /refresh_nonce_key_id text,[\s\S]*refresh_nonce_digest bytea,[\s\S]*replayed boolean/u);
  assert.match(sql, /octet_length\(request_refresh_nonce_digest\) <> 32/u);
  assert.match(sql, /request_expires_at <= now_value/u);
  assert.match(sql, /ON CONFLICT DO NOTHING/u);
  assert.doesNotMatch(sql, /refresh_nonce(?!_(?:key_id|digest))/u);
});
