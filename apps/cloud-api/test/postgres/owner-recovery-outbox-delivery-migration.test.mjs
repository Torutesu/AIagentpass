import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0029_owner_recovery_outbox_delivery.sql", import.meta.url);

test("0029 adds digest-only claims, dead-letter state, and bounded delivery diagnostics", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /ADD COLUMN claim_token_digest bytea/);
  assert.match(sql, /octet_length\(claim_token_digest\) = 32/);
  assert.match(sql, /status IN \('pending', 'published', 'dead_letter'\)/);
  assert.match(sql, /attempts = 100/);
  assert.match(sql, /last_error_code ~ '\^\[a-z\]\[a-z0-9_\]\*\$'/);
  assert.match(sql, /owner_recovery_outbox_claim_expiry/);
  assert.doesNotMatch(sql, /response_body|provider_message|raw_token|authorization|cookie|email/iu);
});
