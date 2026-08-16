import assert from "node:assert/strict";
import test from "node:test";

import {
  AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_METRIC_HOOKS,
  createAgentSessionSigningCapabilityMaintenanceWorker
} from "../../src/postgres/agent-session-signing-capability-maintenance-worker.mjs";

const RESULT = Object.freeze({ expired: 2, uncertain: 3 });

test("runs the exact bounded recovery call and never overlaps concurrent cycles", async () => {
  let release;
  let active = 0;
  let maximumActive = 0;
  let calls = 0;
  const pending = new Promise((resolve) => { release = resolve; });
  const worker = createAgentSessionSigningCapabilityMaintenanceWorker({
    repository: {
      recoverExpiredReservations(input) {
        calls += 1;
        assert.deepEqual(input, { limit: 7 });
        active += 1;
        maximumActive = Math.max(maximumActive, active);
        return pending.finally(() => { active -= 1; });
      }
    },
    limit: 7
  });

  const first = worker.runOnce();
  const second = worker.runOnce();
  assert.strictEqual(first, second);
  assert.equal(calls, 1);
  release(RESULT);
  assert.deepEqual(await first, { ok: true, ...RESULT });
  assert.equal(maximumActive, 1);
  assert.equal(active, 0);
  assert.equal(worker.snapshot().active, 0);
});

test("start is idempotent and schedules one bounded first cycle followed by one interval", async () => {
  const timers = timerHarness();
  let calls = 0;
  const worker = createAgentSessionSigningCapabilityMaintenanceWorker({
    repository: {
      async recoverExpiredReservations(input) {
        calls += 1;
        assert.deepEqual(input, { limit: 4 });
        return { expired: 0, uncertain: 0 };
      }
    },
    firstCycleDelayMs: 3,
    intervalMs: 11,
    limit: 4,
    setTimeoutFn: timers.setTimeoutFn,
    clearTimeoutFn: timers.clearTimeoutFn
  });

  assert.equal(worker.start().state, "running");
  assert.equal(worker.start().state, "running");
  assert.equal(timers.pending(), 1);
  assert.equal(timers.last().delay, 3);
  assert.equal(timers.last().unrefCalled, true);
  await timers.fireNext();
  assert.equal(calls, 1);
  assert.equal(timers.pending(), 1);
  assert.equal(timers.last().delay, 11);
  await timers.fireNext();
  assert.equal(calls, 2);
  assert.equal(timers.pending(), 1);
  await worker.close();
  assert.equal(timers.pending(), 0);
});

test("close is idempotent and reports a bounded drain while the database call remains pending", async () => {
  const timers = timerHarness();
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  const worker = createAgentSessionSigningCapabilityMaintenanceWorker({
    repository: { recoverExpiredReservations() { return pending; } },
    setTimeoutFn: timers.setTimeoutFn,
    clearTimeoutFn: timers.clearTimeoutFn
  });

  const running = worker.runOnce();
  const firstClose = worker.close({ timeoutMs: 5 });
  const secondClose = worker.close({ timeoutMs: 5 });
  assert.strictEqual(firstClose, secondClose);
  assert.equal(timers.pending(), 1);
  await timers.fireNext();
  const timedOut = await firstClose;
  assert.equal(timedOut.drained, false);
  assert.equal(timedOut.state, "closing");
  assert.equal(worker.snapshot().state, "closing");

  release(RESULT);
  await running;
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(worker.snapshot().state, "closed");
  assert.equal(timers.pending(), 0);
  assert.strictEqual(await worker.close(), timedOut);
});

test("database errors and malformed results are contained without secret leakage", async () => {
  const repositoryResults = [
    Object.assign(new Error("password=top-secret reservation_id=private"), { code: "XX000" }),
    { expired: 1, uncertain: 0, response_json: "must-not-escape" },
    RESULT
  ];
  const metricCalls = [];
  const metrics = Object.fromEntries(Object.values(AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_METRIC_HOOKS).map((hook) => [
    hook,
    (amount) => metricCalls.push([hook, amount])
  ]));
  const worker = createAgentSessionSigningCapabilityMaintenanceWorker({
    repository: {
      async recoverExpiredReservations() {
        const value = repositoryResults.shift();
        if (value instanceof Error) throw value;
        return value;
      }
    },
    metrics
  });

  const failed = await worker.runOnce();
  const malformed = await worker.runOnce();
  const recovered = await worker.runOnce();
  assert.deepEqual(failed, { ok: false, failed: true, expired: 0, uncertain: 0 });
  assert.deepEqual(malformed, { ok: false, failed: true, expired: 0, uncertain: 0 });
  assert.deepEqual(recovered, { ok: true, ...RESULT });
  assert.equal(JSON.stringify(failed).includes("top-secret"), false);
  assert.equal(JSON.stringify(malformed).includes("must-not-escape"), false);
  assert.deepEqual(metricCalls, [
    [AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_METRIC_HOOKS.cycle, 1],
    [AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_METRIC_HOOKS.failure, 1],
    [AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_METRIC_HOOKS.cycle, 1],
    [AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_METRIC_HOOKS.failure, 1],
    [AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_METRIC_HOOKS.cycle, 1],
    [AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_METRIC_HOOKS.success, 1],
    [AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_METRIC_HOOKS.expired, 2],
    [AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_METRIC_HOOKS.uncertain, 3]
  ]);
});

test("metric sinks cannot crash recovery and receive only fixed aggregate hooks", async () => {
  const received = [];
  const metrics = Object.fromEntries(Object.values(AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_METRIC_HOOKS).map((hook) => [
    hook,
    (amount) => { received.push([hook, amount]); throw new Error("sink detail"); }
  ]));
  const worker = createAgentSessionSigningCapabilityMaintenanceWorker({
    repository: { async recoverExpiredReservations() { return RESULT; } },
    metrics
  });

  await assert.doesNotReject(async () => {
    assert.deepEqual(await worker.runOnce(), { ok: true, ...RESULT });
  });
  assert.deepEqual(received, [
    [AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_METRIC_HOOKS.cycle, 1],
    [AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_METRIC_HOOKS.success, 1],
    [AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_METRIC_HOOKS.expired, 2],
    [AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_METRIC_HOOKS.uncertain, 3]
  ]);
  assert.equal(received.some(([, amount]) => typeof amount !== "number"), false);
});

test("configuration and result cardinality are bounded", async () => {
  assert.throws(() => createAgentSessionSigningCapabilityMaintenanceWorker(), /configuration is invalid/u);
  assert.throws(() => createAgentSessionSigningCapabilityMaintenanceWorker({ repository: {} }), /configuration is invalid/u);
  for (const option of [
    { firstCycleDelayMs: -1 },
    { firstCycleDelayMs: 60_001 },
    { intervalMs: 9 },
    { intervalMs: 86_400_001 },
    { limit: 0 },
    { limit: 257 },
    { closeTimeoutMs: -1 },
    { closeTimeoutMs: 60_001 }
  ]) {
    assert.throws(() => createAgentSessionSigningCapabilityMaintenanceWorker({
      repository: { recoverExpiredReservations() {} },
      ...option
    }), /configuration is invalid/u);
  }

  for (const value of [
    { expired: 1 },
    { expired: 1, uncertain: 0, secret: "private" },
    { expired: 4, uncertain: 4 },
    { expired: -1, uncertain: 0 },
    { expired: 1.5, uncertain: 0 }
  ]) {
    const worker = createAgentSessionSigningCapabilityMaintenanceWorker({
      repository: { async recoverExpiredReservations() { return value; } },
      limit: 7
    });
    assert.deepEqual(await worker.runOnce(), { ok: false, failed: true, expired: 0, uncertain: 0 });
  }
});

function timerHarness() {
  let nextId = 0;
  const scheduled = new Map();
  return {
    setTimeoutFn(callback, delay) {
      const handle = {
        id: ++nextId,
        delay,
        unrefCalled: false,
        unref() { this.unrefCalled = true; }
      };
      scheduled.set(handle.id, { handle, callback });
      return handle;
    },
    clearTimeoutFn(handle) { scheduled.delete(handle?.id); },
    pending() { return scheduled.size; },
    last() { return Array.from(scheduled.values()).at(-1)?.handle; },
    async fireNext() {
      const next = scheduled.values().next().value;
      assert.ok(next, "expected a scheduled timer");
      scheduled.delete(next.handle.id);
      next.callback();
      await Promise.resolve();
      await Promise.resolve();
      await new Promise((resolve) => setImmediate(resolve));
    }
  };
}
