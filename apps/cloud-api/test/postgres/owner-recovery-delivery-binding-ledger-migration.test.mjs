import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0035_owner_recovery_delivery_binding_ledger.sql", import.meta.url);
const readMigration = () => readFile(migrationUrl, "utf8");

test("0035 quarantines legacy pending rows and requires bound pending delivery", async () => {
  const sql = await readMigration();
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.match(sql, /provider_binding_state text NOT NULL DEFAULT 'legacy_unbound'/u);
  assert.match(sql, /provider_binding_id text/u);
  assert.match(sql, /provider_key_version integer/u);
  assert.match(sql, /provider_binding_digest bytea/u);
  assert.match(sql, /SET status = 'uncertain'[\s\S]*uncertain_reason = 'legacy_unbound'[\s\S]*WHERE status = 'pending'/u);
  assert.match(sql, /status <> 'pending' OR provider_binding_state = 'bound'/u);
  assert.doesNotMatch(sql, /authorization_secret|response_body|webhook_url\s+(?:text|jsonb)/iu);
});

test("0035 makes provider identity immutable and binds it into transition evidence", async () => {
  const sql = await readMigration();
  for (const column of ["provider_binding_state", "provider_binding_id", "provider_key_version", "provider_binding_digest"]) {
    assert.match(sql, new RegExp(`NEW\\.${column} IS DISTINCT FROM OLD\\.${column}`));
  }
  assert.match(sql, /owner recovery outbox identity and provider binding are immutable/u);
  assert.match(sql, /provider_binding_digest bytea/u);
  assert.match(sql, /encode\(sha256\(convert_to\(/u);
});

test("0035 creates an append-only hash-chained transition ledger", async () => {
  const sql = await readMigration();
  assert.match(sql, /CREATE TABLE owner_recovery_outbox_transition_heads/u);
  assert.match(sql, /CREATE TABLE owner_recovery_outbox_transition_ledger/u);
  assert.match(sql, /transition_sequence integer NOT NULL/u);
  assert.match(sql, /previous_hash text NOT NULL/u);
  assert.match(sql, /event_hash text NOT NULL/u);
  assert.match(sql, /floor\(extract\(epoch FROM transition_time\)\*1000000\)::bigint::text/u);
  assert.match(sql, /BEFORE UPDATE OR DELETE ON owner_recovery_outbox_transition_ledger/u);
  assert.match(sql, /CREATE TRIGGER owner_recovery_outbox_transition_appender/u);
  assert.match(sql, /FOR UPDATE;/u);
  assert.match(sql, /actor_type text NOT NULL CHECK \(actor_type IN \('migration', 'system', 'worker', 'operator'\)\)/u);
  assert.match(sql, /actor_type = 'operator'\) = \(actor_member_id IS NOT NULL/u);
});

test("0035 records a migration baseline before enabling live transition capture", async () => {
  const sql = await readMigration();
  const baseline = sql.indexOf("'migration_baseline'");
  const trigger = sql.indexOf("CREATE TRIGGER owner_recovery_outbox_transition_appender");
  assert.ok(baseline >= 0 && trigger > baseline);
  assert.match(sql, /INSERT INTO owner_recovery_outbox_transition_heads[\s\S]*FROM owner_recovery_outbox_transition_ledger/u);
});
