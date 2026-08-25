import assert from "node:assert/strict";
import fs from "node:fs/promises";
import test from "node:test";

const migration = new URL("../../../../contracts/postgres/0027_owner_recovery_idempotency.sql", import.meta.url);

test("0027 creates a tenant-bound digest-only owner recovery idempotency ledger", async () => {
  const sql = await fs.readFile(migration, "utf8");
  assert.match(sql, /CREATE TABLE owner_recovery_idempotency_records/u);
  assert.match(sql, /organization_id uuid NOT NULL REFERENCES organizations\(id\)/u);
  assert.match(sql, /PRIMARY KEY \(organization_id, operation, principal_id, idempotency_key\)/u);
  assert.match(sql, /request_digest bytea NOT NULL CHECK \(octet_length\(request_digest\) = 32\)/u);
  assert.match(sql, /claim_token_digest bytea/u);
  assert.match(sql, /lifecycle IN \('in_progress', 'completed'\)/u);
  assert.doesNotMatch(sql, /exchange_value|recovery_session_token|raw_assertion|private_key/iu);
});
