import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { loadSqlMigrations } from "../../src/postgres/migration-runner.mjs";

const migrationUrl = new URL("../../../../contracts/postgres/0045_device_audit_export_sequence.sql", import.meta.url);

test("0045 creates an additive organization-wide device export position", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN|INDEX)|TRUNCATE\s+TABLE|ALTER\s+TABLE\s+device_audit_events/iu);
  assert.match(sql, /CREATE TABLE device_audit_export_heads[\s\S]*organization_id uuid PRIMARY KEY REFERENCES organizations\(id\)[\s\S]*sequence bigint NOT NULL DEFAULT 0/u);
  assert.match(sql, /CREATE TABLE device_audit_export_entries[\s\S]*PRIMARY KEY \(organization_id, sequence\)[\s\S]*UNIQUE \(organization_id, device_id, event_id\)/u);
  assert.match(sql, /CREATE UNIQUE INDEX device_audit_events_export_identity[\s\S]*organization_id,device_id,event_id,event_hash/u);
  assert.match(sql, /FOREIGN KEY \(organization_id, device_id, event_id, event_hash\)[\s\S]*REFERENCES device_audit_events\(organization_id, device_id, event_id, event_hash\)/u);
  assert.doesNotMatch(sql, /^\s*(?:private_key|credential|claim_token|provider_receipt|signing_bytes)\s+/imu);
});

test("0045 backfills deterministically and serializes future inserts without wall-clock ordering", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /row_number\(\) OVER \([\s\S]*PARTITION BY organization_id[\s\S]*ORDER BY received_at,device_id,event_id/u);
  assert.match(sql, /SELECT sequence INTO current_sequence[\s\S]*FOR UPDATE/u);
  assert.match(sql, /current_sequence\+1,NEW\.device_id,NEW\.event_id,NEW\.event_hash/u);
  assert.match(sql, /WHERE organization_id=NEW\.organization_id AND sequence=current_sequence/u);
  assert.doesNotMatch(sql, /AFTER INSERT ON organizations/u);
  assert.doesNotMatch(sql, /ORDER BY NEW\.|extract\(epoch|clock_timestamp\(\).*sequence/iu);
});

test("0045 makes entries append-only, heads forward-only, and both tables tenant isolated", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /IF TG_OP = 'INSERT' AND pg_trigger_depth\(\) = 2/u);
  assert.match(sql, /BEFORE INSERT OR UPDATE OR DELETE ON device_audit_export_entries/u);
  assert.match(sql, /device_audit_export_heads_initial_state/u);
  assert.match(sql, /BEFORE INSERT OR UPDATE OR DELETE ON device_audit_export_heads/u);
  assert.match(sql, /NEW\.sequence <> OLD\.sequence \+ 1/u);
  assert.match(sql, /entry\.sequence=NEW\.sequence[\s\S]*entry\.event_hash=NEW\.last_event_hash/u);
  for (const table of ["device_audit_export_entries", "device_audit_export_heads"]) {
    assert.match(sql, new RegExp(`ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY`, "u"));
    assert.match(sql, new RegExp(`ALTER TABLE ${table} FORCE ROW LEVEL SECURITY`, "u"));
    assert.match(sql, new RegExp(`ON ${table} FOR SELECT[\\s\\S]*organization_id=agentpass_current_organization_id\\(\\)`, "u"));
  }
});

test("0045 is loaded in sequence with a content-derived checksum", async () => {
  const migration = (await loadSqlMigrations()).find((item) => item.version === 45);
  assert.equal(migration?.name, "0045_device_audit_export_sequence.sql");
  assert.match(migration?.checksum ?? "", /^[0-9a-f]{64}$/u);
});
