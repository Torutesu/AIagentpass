import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { createPostgresAuditRepository } from "../../src/postgres/audit-repository.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL;
const TEST_PUBLIC_KEYS = [0, 1].map(() => crypto.generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString().trimEnd());

test("PostgreSQL activity keyset traverses more than 500 rows without duplicates when a newer row is inserted", { skip: !databaseUrl }, async (t) => {
  const pool = new Pool({ connectionString: databaseUrl, max: 8 });
  t.after(() => pool.end());
  const migrationClient = await pool.connect();
  try {
    await createMigrationRunner({ client: migrationClient, applicationVersion: "audit-pagination-integration" }).run();
  } finally {
    migrationClient.release();
  }

  const organizationId = crypto.randomUUID();
  const deviceId = crypto.randomUUID();
  const otherDeviceId = crypto.randomUUID();
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [organizationId, "Activity pagination integration"]);
  await pool.query(`INSERT INTO devices (organization_id,id,label,key_algorithm,public_key_pem,status)
    VALUES ($1,$2,'Activity device','ed25519',$3,'active'),($1,$4,'Other device','ed25519',$5,'active')`, [
    organizationId,
    deviceId,
    TEST_PUBLIC_KEYS[0],
    otherDeviceId,
    TEST_PUBLIC_KEYS[1]
  ]);

  const initial = [];
  const otherDeviceEvents = [];
  const base = Date.parse("2026-08-12T00:00:00.000Z");
  await pool.query("BEGIN");
  try {
    for (let index = 0; index < 600; index += 1) {
      const event = eventRecord(deviceId, new Date(base + index * 1_000).toISOString());
      initial.push(event.event_id);
      await insertEvent(pool, organizationId, deviceId, event, new Date(base + index * 1_000 + 500));
    }
    for (let index = 0; index < 7; index += 1) {
      const event = eventRecord(otherDeviceId, new Date(base + index * 1_000).toISOString());
      otherDeviceEvents.push(event.event_id);
      await insertEvent(pool, organizationId, otherDeviceId, event, new Date(base + index * 1_000 + 750));
    }
    await pool.query("COMMIT");
  } catch (error) {
    await pool.query("ROLLBACK");
    throw error;
  }

  const repository = createPostgresAuditRepository({ client: pool, cursorSecret: Buffer.alloc(32, 0x46) });
  const first = await repository.listDeviceAuditEvents({ organization_id: organizationId, device_id: deviceId, limit: 101 });
  assert.equal(first.events.length, 101);
  assert.ok(first.next_cursor);

  const newer = eventRecord(deviceId, new Date(base + 2_000_000).toISOString());
  const continuationPromise = repository.listDeviceAuditEvents({ organization_id: organizationId, device_id: deviceId, limit: 101, cursor: first.next_cursor });
  const insertPromise = insertEvent(pool, organizationId, deviceId, newer, new Date(base + 2_000_001));
  const [, second] = await Promise.all([insertPromise, continuationPromise]);

  const seen = [...first.events, ...second.events];
  let cursor = second.next_cursor;
  while (cursor !== null) {
    const page = await repository.listDeviceAuditEvents({ organization_id: organizationId, device_id: deviceId, limit: 101, cursor });
    seen.push(...page.events);
    cursor = page.next_cursor;
  }

  assert.equal(seen.length, 600);
  assert.equal(new Set(seen.map((record) => record.event_id)).size, 600);
  assert.deepEqual(new Set(seen.map((record) => record.event_id)), new Set(initial));
  assert.equal(seen.some((record) => record.event_id === newer.event_id), false, "a newer concurrent insert is outside the already-open traversal");
  assert.ok(seen.every((record) => Object.keys(record).sort().join(",") === "device_id,event,event_id,organization_id,received_at"));

  const fresh = await repository.listDeviceAuditEvents({ organization_id: organizationId, device_id: deviceId, limit: 1 });
  assert.equal(fresh.events[0].event_id, newer.event_id);
  await assert.rejects(() => repository.listDeviceAuditEvents({ organization_id: organizationId, device_id: otherDeviceId, cursor: first.next_cursor }), /invalid/);
  const otherDevicePage = await repository.listDeviceAuditEvents({ organization_id: organizationId, device_id: otherDeviceId, limit: 10 });
  assert.equal(otherDevicePage.next_cursor, null);
  assert.deepEqual(new Set(otherDevicePage.events.map((record) => record.event_id)), new Set(otherDeviceEvents));
  assert.ok(otherDevicePage.events.every((record) => record.device_id === otherDeviceId));
});

async function insertEvent(pool, organizationId, deviceId, event, receivedAt) {
  await pool.query(`INSERT INTO device_audit_events
    (organization_id,device_id,event_id,previous_hash,event_hash,redacted_json,received_at)
    VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7)`, [
    organizationId,
    deviceId,
    event.event_id,
    event.previous_hash,
    event.event_hash,
    JSON.stringify(event),
    receivedAt
  ]);
}

function eventRecord(deviceId, deviceTimestamp) {
  const eventId = crypto.randomUUID();
  const event = {
    version: 1,
    event_id: eventId,
    request_id: crypto.randomUUID(),
    agent_id: deviceId,
    operation: "git.commit.sign",
    decision: "allow",
    reason: "allowed",
    policy_sequence: 1,
    capability_sequence: 1,
    repository: "/work/repo",
    branch: "feature/activity",
    remote: "git@example.test:repo.git",
    payload_digest: "a".repeat(64),
    device_timestamp: deviceTimestamp,
    previous_hash: "0".repeat(64)
  };
  return { ...event, event_hash: crypto.createHash("sha256").update(canonicalJson(event), "utf8").digest("hex") };
}
