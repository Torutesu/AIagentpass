import assert from "node:assert/strict";
import test from "node:test";

import {
  createPostgresDeviceManualWakeRepository,
  DeviceManualWakeRepositoryError
} from "../../src/postgres/device-manual-wake-repository.mjs";

const IDS = Object.freeze({
  organization: "11111111-1111-4111-8111-111111111111",
  device: "22222222-2222-4222-8222-222222222222",
  actor: "33333333-3333-4333-8333-333333333333",
  outbox: "44444444-4444-4444-8444-444444444444"
});
const NOW = "2026-08-13T00:00:00.000Z";

test("accepts the first wake and keeps authority/ACK tables out of the write path", async () => {
  const client = new ManualWakeFake({ activeOutbox: IDS.outbox });
  const repository = createPostgresDeviceManualWakeRepository({ client, now: () => NOW });
  const response = await repository.requestDeviceManualWake(request("wake-0001"));

  assert.equal(response.version, 1);
  assert.equal(response.device_id, IDS.device);
  assert.equal(response.desired_generation, 7);
  assert.equal(response.status, "accepted");
  assert.equal(response.requested_at, NOW);
  assert.equal(client.events.size, 1);
  assert.equal(client.requests.size, 1);
  assert.ok(client.calls.some(({ text }) => text.startsWith("INSERT INTO device_manual_wake_events")));
  assert.ok(client.calls.some(({ text }) => text.startsWith("INSERT INTO device_manual_wake_requests")));
  assert.equal(client.calls.some(({ text }) => /(?:UPDATE|INSERT INTO)\s+(?:control_plane_authority_generations|device_control_plane_state|device_refresh_outbox|device_bundle_acknowledgements|control_bundle_statements)/iu.test(text)), false);
});

test("exact replay returns the original response without updating the event or notifying again", async () => {
  const client = new ManualWakeFake({ activeOutbox: IDS.outbox });
  const repository = createPostgresDeviceManualWakeRepository({ client, now: () => NOW });
  const first = await repository.requestDeviceManualWake(request("wake-0001"));
  const callsBeforeReplay = client.calls.length;
  const replay = await repository.requestDeviceManualWake({ ...request("wake-0001"), requested_at: "2026-08-13T00:01:00.000Z" });

  assert.deepEqual(replay, first);
  assert.equal(client.events.get(eventKey()).wakeCount, 1);
  const replayCalls = client.calls.slice(callsBeforeReplay).map(({ text }) => text).join("\n");
  assert.doesNotMatch(replayCalls, /(?:INSERT INTO|UPDATE) device_manual_wake_events/u);
  assert.doesNotMatch(replayCalls, /INSERT INTO device_manual_wake_requests/u);
});

test("different idempotency keys coalesce one event, increment a bounded counter, and issue a fresh retry wake", async () => {
  const client = new ManualWakeFake({ activeOutbox: IDS.outbox });
  const repository = createPostgresDeviceManualWakeRepository({ client, now: () => NOW });
  const first = await repository.requestDeviceManualWake(request("wake-0001"));
  const second = await repository.requestDeviceManualWake({ ...request("wake-0002"), requested_at: "2026-08-13T00:02:00.000Z" });

  assert.equal(first.status, "accepted");
  assert.equal(second.status, "coalesced");
  assert.notEqual(second.request_id, first.request_id);
  assert.equal(client.events.size, 1);
  assert.equal(client.events.get(eventKey()).wakeCount, 2);
  assert.equal(client.events.get(eventKey()).lastRequestedAt, "2026-08-13T00:02:00.000Z");
  assert.equal(client.eventNotifications, 2);
  assert.equal(client.requests.size, 2);
  const update = client.calls.find(({ text }) => text.startsWith("UPDATE device_manual_wake_events"));
  assert.match(update.text, /LEAST\(wake_count\+1,\$5\)/u);
});

test("caps the wake counter while still updating last_requested_at for notification retry", async () => {
  const client = new ManualWakeFake({ activeOutbox: IDS.outbox });
  const repository = createPostgresDeviceManualWakeRepository({ client, now: () => NOW, maxWakeCount: 1 });
  await repository.requestDeviceManualWake(request("wake-0001"));
  await repository.requestDeviceManualWake({ ...request("wake-0002"), requested_at: "2026-08-13T00:03:00.000Z" });

  assert.equal(client.events.get(eventKey()).wakeCount, 1);
  assert.equal(client.events.get(eventKey()).lastRequestedAt, "2026-08-13T00:03:00.000Z");
  assert.equal(client.eventNotifications, 2);
});

test("records no_pending_refresh without creating a coalesced event", async () => {
  const client = new ManualWakeFake({ activeOutbox: null });
  const repository = createPostgresDeviceManualWakeRepository({ client, now: () => NOW });
  const response = await repository.requestDeviceManualWake(request("wake-0001"));

  assert.equal(response.status, "no_pending_refresh");
  assert.equal(response.desired_generation, 7);
  assert.equal(client.events.size, 0);
  assert.equal(client.eventNotifications, 0);
  assert.equal(client.requests.size, 1);
});

test("treats an already observed desired generation as no pending refresh even when an outbox row remains", async () => {
  const client = new ManualWakeFake({
    activeOutbox: IDS.outbox,
    stateRows: [{ device_status: "active", refresh_state: "applied", desired_generation: "7", observed_generation: "7", active_outbox_id: IDS.outbox }]
  });
  const repository = createPostgresDeviceManualWakeRepository({ client, now: () => NOW });
  const response = await repository.requestDeviceManualWake(request("wake-0001"));

  assert.equal(response.status, "no_pending_refresh");
  assert.equal(response.desired_generation, 7);
  assert.equal(client.events.size, 0);
  assert.equal(client.eventNotifications, 0);
  assert.equal(client.calls.some(({ text }) => text.startsWith("SELECT outbox_id")), false);
});

test("missing, cross-tenant, and revoked devices fail closed before recording evidence", async () => {
  for (const state of [[], [{ device_status: "revoked", refresh_state: "revoked", desired_generation: "7", observed_generation: "6", active_outbox_id: null }]]) {
    const client = new ManualWakeFake({ stateRows: state });
    const repository = createPostgresDeviceManualWakeRepository({ client, now: () => NOW });
    await assert.rejects(() => repository.requestDeviceManualWake(request("wake-0001")), (error) => {
      assert.ok(error instanceof DeviceManualWakeRepositoryError);
      assert.equal(error.code, "ERR_DEVICE_UNAVAILABLE");
      return true;
    });
    assert.equal(client.requests.size, 0);
    assert.equal(client.events.size, 0);
  }
});

test("caller-owned transaction path never emits BEGIN or COMMIT", async () => {
  const client = new ManualWakeFake({ activeOutbox: IDS.outbox });
  const repository = createPostgresDeviceManualWakeRepository({ client, now: () => NOW });
  const response = await repository.requestDeviceManualWakeInTransaction({ ...request("wake-0001"), tx: client });

  assert.equal(response.status, "accepted");
  assert.equal(client.calls.some(({ text }) => text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK"), false);
});

test("same key with an incompatible body digest is a conflict in the replay ledger", async () => {
  const client = new ManualWakeFake({ activeOutbox: IDS.outbox });
  const repository = createPostgresDeviceManualWakeRepository({ client, now: () => NOW });
  await repository.requestDeviceManualWake(request("wake-0001"));
  client.conflictingBodyDigest = true;
  await assert.rejects(() => repository.requestDeviceManualWake(request("wake-0001")), { code: "ERR_IDEMPOTENCY_CONFLICT" });
  assert.equal(client.events.size, 1);
});

function request(idempotencyKey) {
  return {
    organization_id: IDS.organization,
    device_id: IDS.device,
    actor_id: IDS.actor,
    idempotency_key: idempotencyKey
  };
}

function eventKey() {
  return `${IDS.organization}:${IDS.device}:7`;
}

class ManualWakeFake {
  constructor({ activeOutbox = IDS.outbox, stateRows, conflictingBodyDigest = false } = {}) {
    this.activeOutbox = activeOutbox;
    this.stateRows = stateRows ?? [{ device_status: "active", refresh_state: "pending", desired_generation: "7", observed_generation: "6", active_outbox_id: activeOutbox }];
    this.conflictingBodyDigest = conflictingBodyDigest;
    this.calls = [];
    this.events = new Map();
    this.requests = new Map();
    this.eventNotifications = 0;
  }

  async query(text, params = []) {
    this.calls.push({ text, params });
    if (text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK") return { rows: [], rowCount: 0 };
    if (text.startsWith("SELECT pg_advisory_xact_lock")) return { rows: [{ locked: true }], rowCount: 1 };
    if (text.includes("FROM devices AS d") && text.includes("device_control_plane_state")) return { rows: this.stateRows, rowCount: this.stateRows.length };
    if (text.startsWith("SELECT role") && text.includes("FROM memberships")) return { rows: [{ role: "admin" }], rowCount: 1 };
    if (text.startsWith("SELECT request_id") && text.includes("FROM device_manual_wake_requests")) {
      const key = `${params[0]}:${params[1]}:${params[2]}`;
      const stored = this.requests.get(key);
      return { rows: stored ? [{ ...stored, body_digest: this.conflictingBodyDigest ? Buffer.alloc(32, 9) : stored.body_digest }] : [], rowCount: stored ? 1 : 0 };
    }
    if (text.startsWith("SELECT outbox_id") && text.includes("FROM device_refresh_outbox")) {
      return this.activeOutbox ? { rows: [{ outbox_id: this.activeOutbox }], rowCount: 1 } : { rows: [], rowCount: 0 };
    }
    if (text.startsWith("INSERT INTO device_manual_wake_events")) {
      const key = `${params[0]}:${params[1]}:${params[2]}`;
      if (this.events.has(key)) return { rows: [], rowCount: 0 };
      this.events.set(key, { wakeCount: 1, lastRequestedAt: params[4], activeOutboxId: params[3] });
      this.eventNotifications += 1;
      return { rows: [{ desired_generation: params[2] }], rowCount: 1 };
    }
    if (text.startsWith("UPDATE device_manual_wake_events")) {
      const key = `${params[0]}:${params[1]}:${params[2]}`;
      const event = this.events.get(key);
      if (!event) return { rows: [], rowCount: 0 };
      event.wakeCount = Math.min(event.wakeCount + 1, params[4]);
      event.lastRequestedAt = params[5];
      event.activeOutboxId = params[3];
      this.eventNotifications += 1;
      return { rows: [{ desired_generation: params[2] }], rowCount: 1 };
    }
    if (text.startsWith("INSERT INTO device_manual_wake_requests")) {
      const key = `${params[0]}:${params[2]}:${params[3]}`;
      this.requests.set(key, {
        request_id: params[4], device_id: params[1], actor_id: params[2], idempotency_key: params[3],
        body_digest: Buffer.from(params[5]), desired_generation: params[6], active_outbox_id: params[7],
        result: params[8], requested_at: params[9], response_json: JSON.parse(params[10])
      });
      return { rows: [{ request_id: params[4] }], rowCount: 1 };
    }
    throw new Error(`unexpected SQL in fake: ${text}`);
  }
}
