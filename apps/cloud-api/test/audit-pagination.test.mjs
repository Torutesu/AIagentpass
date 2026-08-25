import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { AuditCursorError, AUDIT_CURSOR_TTL_MS, auditCursorBinding, createAuditCursorCodec } from "../src/audit-pagination.mjs";
import { computeAuditEventHash, createCloudStore } from "../src/store.mjs";

const organizationId = "11111111-1111-4111-8111-111111111111";
const deviceA = "22222222-2222-4222-8222-222222222222";
const deviceB = "33333333-3333-4333-8333-333333333333";
const agentA = "44444444-4444-4444-8444-444444444444";
const agentB = "55555555-5555-4555-8555-555555555555";
const baseTimestamp = Date.parse("2026-08-12T00:00:00.000Z");

test("audit cursors are opaque, scope-bound, authenticated, and expire", () => {
  let clock = baseTimestamp;
  const codec = createAuditCursorCodec({ secret: Buffer.alloc(32, 0x41), now: () => clock });
  const eventId = crypto.randomUUID();
  const cursor = codec.encode({ organization_id: organizationId, device_id: deviceA, device_timestamp: new Date(clock).toISOString(), event_id: eventId });
  assert.match(cursor, /^[A-Za-z0-9_-]+$/u);
  assert.deepEqual(codec.decode(cursor, auditCursorBinding(organizationId, deviceA)), {
    version: 1,
    resource: "device_audit_events",
    organization_id: organizationId,
    device_id: deviceA,
    device_timestamp: new Date(clock).toISOString(),
    event_id: eventId,
    expires_at: new Date(clock + AUDIT_CURSOR_TTL_MS).toISOString()
  });
  assert.throws(() => codec.decode(cursor, auditCursorBinding(organizationId, deviceB)), AuditCursorError);
  assert.throws(() => codec.decode(`${cursor.slice(0, -1)}${cursor.endsWith("A") ? "B" : "A"}`, auditCursorBinding(organizationId, deviceA)), AuditCursorError);
  clock += AUDIT_CURSOR_TTL_MS;
  assert.throws(() => codec.decode(cursor, auditCursorBinding(organizationId, deviceA)), AuditCursorError);
});

test("file-store activity pages use the immutable cross-device keyset and survive a newer insert", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-audit-page-"));
  const store = await createCloudStore({ dataDir: directory, auditCursorSecret: Buffer.alloc(32, 0x42) });
  t.after(async () => { await store.close(); await fs.rm(directory, { recursive: true, force: true }); });

  await store.createOrganization({ organizationId, name: "Activity", idempotencyKey: "activity-org" });
  for (const [deviceId, suffix] of [[deviceA, "a"], [deviceB, "b"]]) {
    await store.createDevice({ organizationId, deviceId, name: `Device ${suffix}`, publicKey: `ssh-ed25519 AAAA${suffix}`, idempotencyKey: `activity-device-${suffix}` });
    await store.createAgent({ organizationId, deviceId, agentId: deviceId === deviceA ? agentA : agentB, name: `Agent ${suffix}`, kind: "cli", version: 1, publicKey: `-----BEGIN PUBLIC KEY-----\n${suffix}\n-----END PUBLIC KEY-----`, idempotencyKey: `activity-agent-${suffix}` });
  }

  const expected = [];
  const batches = new Map([[deviceA, []], [deviceB, []]]);
  const lastHash = new Map([[deviceA, "0".repeat(64)], [deviceB, "0".repeat(64)]]);
  for (let index = 0; index < 600; index += 1) {
    const deviceId = index % 2 === 0 ? deviceA : deviceB;
    const event = auditEvent(deviceId, index, lastHash.get(deviceId));
    lastHash.set(deviceId, event.event_hash);
    expected.push({ device_id: deviceId, event_id: event.event_id, device_timestamp: event.device_timestamp });
    batches.get(deviceId).push(event);
  }
  for (const [deviceId, events] of batches) {
    for (let offset = 0; offset < events.length; offset += 64) {
      await store.ingestDeviceAuditEvents({ organizationId, deviceId, events: events.slice(offset, offset + 64), idempotencyKey: `activity-event-${deviceId}-${offset}` });
    }
  }
  const extra = auditEvent(deviceA, 10_000, lastHash.get(deviceA));
  await store.ingestDeviceAuditEvents({ organizationId, deviceId: deviceA, events: [extra], idempotencyKey: "activity-event-extra" });
  expected.push({ device_id: deviceA, event_id: extra.event_id, device_timestamp: extra.device_timestamp });

  const seen = [];
  let cursor;
  let firstPage;
  do {
    const page = await store.listDeviceAuditEvents({ organizationId, device_id: deviceA, limit: 73, ...(cursor === undefined ? {} : { cursor }) });
    firstPage ??= page;
    seen.push(...page.events.map((record) => ({ device_id: record.device_id, event_id: record.event_id, device_timestamp: record.event.device_timestamp })));
    cursor = page.next_cursor ?? undefined;
    if (page.next_cursor === null) break;
  } while (true);

  assert.equal(seen.length, 301);
  assert.equal(new Set(seen.map((item) => item.event_id)).size, 301);
  assert.deepEqual(seen, [...seen].sort(comparePosition));
  assert.deepEqual(new Set(seen.map((item) => item.event_id)), new Set(expected.filter((item) => item.device_id === deviceA).map((item) => item.event_id)));
  assert.ok(firstPage.next_cursor);

  const devicePage = await store.listDeviceAuditEvents({ organizationId, device_id: deviceA, limit: 2 });
  await assert.rejects(() => store.listDeviceAuditEvents({ organizationId, device_id: deviceB, cursor: devicePage.next_cursor }), AuditCursorError);
  await assert.rejects(() => store.listDeviceAuditEvents({ organizationId, device_id: deviceA, cursor: firstPage.next_cursor.slice(0, -1) }), AuditCursorError);
});

function auditEvent(deviceId, index, previousHash) {
  const event = {
    version: 1,
    event_id: crypto.randomUUID(),
    request_id: crypto.randomUUID(),
    agent_id: deviceId === deviceA ? agentA : agentB,
    operation: "git.commit.sign",
    decision: "allow",
    reason: "allowed",
    policy_sequence: 1,
    capability_sequence: 1,
    repository: "/work/repo",
    branch: "feature/activity",
    remote: "git@example.test:repo.git",
    payload_digest: "a".repeat(64),
    device_timestamp: new Date(baseTimestamp + index * 1000).toISOString(),
    previous_hash: previousHash
  };
  return { ...event, event_hash: computeAuditEventHash(event) };
}

function comparePosition(left, right) {
  return -(left.device_timestamp.localeCompare(right.device_timestamp)
    || left.device_id.localeCompare(right.device_id)
    || left.event_id.localeCompare(right.event_id));
}
