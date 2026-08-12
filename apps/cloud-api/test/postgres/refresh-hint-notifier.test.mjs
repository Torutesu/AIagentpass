import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";

import {
  createPostgresRefreshHintNotifier,
  REFRESH_HINT_NOTIFICATION_CHANNEL,
  REFRESH_HINT_NOTIFIER_ERROR_CODES,
  RefreshHintNotifierError
} from "../../src/postgres/refresh-hint-notifier.mjs";

const ORG_A = "11111111-1111-4111-8111-111111111111";
const ORG_B = "22222222-2222-4222-8222-222222222222";
const DEVICE_A = "33333333-3333-4333-8333-333333333333";
const DEVICE_B = "44444444-4444-4444-8444-444444444444";

test("uses one dedicated client and a static LISTEN channel for concurrent waiters", async () => {
  const client = new FakeClient();
  const pool = new FakePool([client]);
  const notifier = createPostgresRefreshHintNotifier({ pool, reconnectCooldownMs: 0 });

  const first = notifier.waitForRefresh({ organization_id: ORG_A, device_id: DEVICE_A, after_generation: 4, timeout_ms: 500 });
  const second = notifier.waitForRefresh({ organization_id: ORG_A, device_id: DEVICE_A, after_generation: 5, timeout_ms: 500 });
  await pool.connected;
  assert.equal(pool.connectCalls, 1);
  assert.deepEqual(client.queries, [`LISTEN ${REFRESH_HINT_NOTIFICATION_CHANNEL}`]);

  client.emitNotification({ organization_id: ORG_A, device_id: DEVICE_A, desired_generation: 6 });
  assert.equal(await first, true);
  assert.equal(await second, true);
  assert.equal(notifier.snapshot().connected, true);

  await notifier.close();
  assert.deepEqual(client.queries, [
    `LISTEN ${REFRESH_HINT_NOTIFICATION_CHANNEL}`,
    `UNLISTEN ${REFRESH_HINT_NOTIFICATION_CHANNEL}`
  ]);
  assert.deepEqual(client.releaseCalls, [false]);
});

test("filters notifications by the complete organization/device/generation tuple", async () => {
  const client = new FakeClient();
  const notifier = createPostgresRefreshHintNotifier({ pool: new FakePool([client]), reconnectCooldownMs: 0 });
  const pending = notifier.waitForRefresh({ organization_id: ORG_A, device_id: DEVICE_A, after_generation: 8, timeout_ms: 500 });
  await tick();

  client.emitNotification({ organization_id: ORG_B, device_id: DEVICE_A, desired_generation: 9 });
  client.emitNotification({ organization_id: ORG_A, device_id: DEVICE_B, desired_generation: 9 });
  client.emitNotification({ organization_id: ORG_A, device_id: DEVICE_A, desired_generation: 8 });
  assert.equal(await Promise.race([pending.then(() => "settled"), delay(10).then(() => "pending")]), "pending");

  client.emitNotification({ organization_id: ORG_A, device_id: DEVICE_A, desired_generation: 9 });
  assert.equal(await pending, true);
  await notifier.close();
});

test("rejects malformed or secret-bearing payloads without waking a waiter", async () => {
  const client = new FakeClient();
  const notifier = createPostgresRefreshHintNotifier({ pool: new FakePool([client]), reconnectCooldownMs: 0 });
  const pending = notifier.waitForRefresh({ organization_id: ORG_A, device_id: DEVICE_A, after_generation: 1, timeout_ms: 500 });
  await tick();

  client.emitRawNotification(`{"organization_id":"${ORG_A}","device_id":"${DEVICE_A}","desired_generation":2,"nonce":"secret"}`);
  client.emitRawNotification("not-json");
  client.emitRawNotification(JSON.stringify({ organization_id: ORG_A, device_id: DEVICE_A, desired_generation: 2 }));
  assert.equal(await pending, true);
  await notifier.close();
});

test("bounds waiters and resolves a timed-out waiter for the authoritative fallback query", async () => {
  const client = new FakeClient();
  const notifier = createPostgresRefreshHintNotifier({ pool: new FakePool([client]), maxWaiters: 1, reconnectCooldownMs: 0 });
  const pending = notifier.waitForRefresh({ organization_id: ORG_A, device_id: DEVICE_A, after_generation: 1, timeout_ms: 15 });
  await assert.rejects(
    () => notifier.waitForRefresh({ organization_id: ORG_A, device_id: DEVICE_A, after_generation: 1, timeout_ms: 15 }),
    (error) => error instanceof RefreshHintNotifierError && error.code === REFRESH_HINT_NOTIFIER_ERROR_CODES.BUSY
  );
  assert.equal(await pending, false);
  await notifier.close();
});

test("supports abort without leaking a waiter", async () => {
  const client = new FakeClient();
  const notifier = createPostgresRefreshHintNotifier({ pool: new FakePool([client]), reconnectCooldownMs: 0 });
  const controller = new AbortController();
  const pending = notifier.waitForRefresh({ organization_id: ORG_A, device_id: DEVICE_A, after_generation: 1, timeout_ms: 500, signal: controller.signal });
  await tick();
  controller.abort();
  await assert.rejects(pending, (error) => error.name === "AbortError" && error.code === REFRESH_HINT_NOTIFIER_ERROR_CODES.ABORTED);
  assert.equal(notifier.snapshot().active_waiters, 0);
  await notifier.close();
});

test("abort and close remain prompt while pool connection establishment is stuck", async () => {
  const notifier = createPostgresRefreshHintNotifier({
    clientFactory: () => new Promise(() => {}),
    reconnectCooldownMs: 0
  });
  const controller = new AbortController();
  const pending = notifier.waitForRefresh({ organization_id: ORG_A, device_id: DEVICE_A, after_generation: 1, timeout_ms: 500, signal: controller.signal });
  controller.abort();
  await assert.rejects(pending, (error) => error.name === "AbortError");
  await Promise.race([
    notifier.close(),
    delay(50).then(() => { throw new Error("close did not return promptly"); })
  ]);
});

test("resolves pending waits safely on client failure and reconnects for a later wait", async () => {
  const first = new FakeClient();
  const second = new FakeClient();
  const pool = new FakePool([first, second]);
  const notifier = createPostgresRefreshHintNotifier({ pool, reconnectCooldownMs: 0 });
  const failed = notifier.waitForRefresh({ organization_id: ORG_A, device_id: DEVICE_A, after_generation: 1, timeout_ms: 500 });
  await tick();
  first.emit("error", new Error("connection reset"));
  assert.equal(await failed, false);
  assert.deepEqual(first.releaseCalls, [true]);

  const recovered = notifier.waitForRefresh({ organization_id: ORG_A, device_id: DEVICE_A, after_generation: 1, timeout_ms: 500 });
  await tick();
  assert.equal(pool.connectCalls, 2);
  second.emitNotification({ organization_id: ORG_A, device_id: DEVICE_A, desired_generation: 2 });
  assert.equal(await recovered, true);
  await notifier.close();
});

test("close drains all waiters and does not check out another client", async () => {
  const client = new FakeClient();
  const pool = new FakePool([client]);
  const notifier = createPostgresRefreshHintNotifier({ pool, reconnectCooldownMs: 0 });
  const pending = notifier.waitForRefresh({ organization_id: ORG_A, device_id: DEVICE_A, after_generation: 1, timeout_ms: 500 });
  await tick();
  await notifier.close();
  assert.equal(await pending, false);
  assert.equal(notifier.snapshot().draining, true);
  assert.equal(pool.connectCalls, 1);
  await assert.rejects(
    () => notifier.waitForRefresh({ organization_id: ORG_A, device_id: DEVICE_A, after_generation: 1, timeout_ms: 1 }),
    (error) => error.code === REFRESH_HINT_NOTIFIER_ERROR_CODES.CLOSED
  );
});

test("drain waits for existing waiters and prevents new ones", async () => {
  const client = new FakeClient();
  const notifier = createPostgresRefreshHintNotifier({ pool: new FakePool([client]), reconnectCooldownMs: 0 });
  const pending = notifier.waitForRefresh({ organization_id: ORG_A, device_id: DEVICE_A, after_generation: 1, timeout_ms: 500 });
  await tick();
  const draining = notifier.drain({ timeout_ms: 100 });
  await assert.rejects(
    () => notifier.waitForRefresh({ organization_id: ORG_A, device_id: DEVICE_A, after_generation: 1, timeout_ms: 1 }),
    (error) => error.code === REFRESH_HINT_NOTIFIER_ERROR_CODES.CLOSED
  );
  client.emitNotification({ organization_id: ORG_A, device_id: DEVICE_A, desired_generation: 2 });
  assert.equal(await pending, true);
  await draining;
  await notifier.close();
});

class FakePool {
  constructor(clients) {
    this.clients = [...clients];
    this.connectCalls = 0;
    this.connected = new Promise((resolve) => { this.resolveConnected = resolve; });
  }

  async connect() {
    this.connectCalls += 1;
    const client = this.clients.shift();
    if (!client) throw new Error("no fake client available");
    client.onQuery = () => this.resolveConnected();
    return client;
  }
}

class FakeClient extends EventEmitter {
  constructor() {
    super();
    this.queries = [];
    this.releaseCalls = [];
    this.onQuery = null;
  }

  async query(sql) {
    this.queries.push(sql);
    this.onQuery?.();
    return { rows: [], rowCount: 0 };
  }

  release(destroy = false) {
    this.releaseCalls.push(destroy);
  }

  emitNotification(payload) {
    this.emitRawNotification(JSON.stringify(payload));
  }

  emitRawNotification(payload) {
    this.emit("notification", { channel: REFRESH_HINT_NOTIFICATION_CHANNEL, payload });
  }
}

function tick() {
  return new Promise((resolve) => setImmediate(resolve));
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
