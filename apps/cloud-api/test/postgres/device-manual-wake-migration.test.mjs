import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0016_device_manual_wake.sql", import.meta.url);

test("0016 creates an append-only, tenant-qualified manual wake ledger", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN)|TRUNCATE/iu);
  assert.match(sql, /CREATE TABLE device_manual_wake_events \([\s\S]*PRIMARY KEY \(organization_id, device_id, desired_generation\)/u);
  assert.match(sql, /wake_count integer NOT NULL DEFAULT 1 CHECK \(wake_count BETWEEN 1 AND 1000\)/u);
  assert.match(sql, /active_outbox_id uuid/u);
  assert.match(sql, /CREATE TABLE device_manual_wake_requests \([\s\S]*body_digest bytea NOT NULL CHECK \(octet_length\(body_digest\) = 32\)/u);
  assert.match(sql, /PRIMARY KEY \(organization_id, actor_id, idempotency_key\)/u);
  assert.match(sql, /UNIQUE \(organization_id, request_id\)/u);
  assert.match(sql, /result text NOT NULL CHECK \(result IN \('accepted', 'coalesced', 'no_pending_refresh'\)\)/u);
  assert.match(sql, /FOREIGN KEY \(organization_id, device_id\) REFERENCES devices\(organization_id, id\)/u);
  assert.match(sql, /FOREIGN KEY \(organization_id, desired_generation\)[\s\S]*REFERENCES control_plane_authority_generations\(organization_id, generation\)/u);
  assert.match(sql, /FOREIGN KEY \(organization_id, actor_id\)[\s\S]*REFERENCES memberships\(organization_id, member_id\)/u);
  assert.doesNotMatch(sql, /UPDATE\s+(?:control_plane_authority_generations|device_control_plane_state|device_refresh_outbox|device_bundle_acknowledgements|control_bundle_statements)/iu);
  assert.doesNotMatch(sql, /INSERT\s+INTO\s+(?:control_plane_authority_generations|device_control_plane_state|device_refresh_outbox|device_bundle_acknowledgements|control_bundle_statements)/iu);
});

test("0016 retries only coalesced events and sends a post-commit-safe routing payload", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /CREATE TRIGGER device_manual_wake_events_notify\s+AFTER INSERT OR UPDATE OF wake_count, last_requested_at, last_actor_id, active_outbox_id/u);
  assert.match(sql, /PERFORM pg_notify\('agentpass_refresh_hint_v1', json_build_object\([\s\S]*'organization_id',[\s\S]*'device_id',[\s\S]*'desired_generation'/u);
  assert.match(sql, /observed_generation IS NULL OR state\.observed_generation < state\.desired_generation/u);
  assert.match(sql, /outbox\.status IN \('pending', 'delivered'\)/u);
  assert.match(sql, /PostgreSQL queues NOTIFY messages until[\s\S]*commits/u);
  assert.match(sql, /CREATE TRIGGER device_refresh_outbox_clear_manual_wake\s+AFTER UPDATE OF status OR DELETE/u);
  assert.match(sql, /wake_count integer NOT NULL DEFAULT 1 CHECK \(wake_count BETWEEN 1 AND 1000\)/u);
});
