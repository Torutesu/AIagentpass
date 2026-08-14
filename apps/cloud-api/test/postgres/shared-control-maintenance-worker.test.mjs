import assert from "node:assert/strict";
import test from "node:test";

import {
  SHARED_CONTROL_MAINTENANCE_METHOD,
  createSharedControlRepository
} from "../../src/postgres/shared-control-repository.mjs";
import {
  SHARED_CONTROL_MAINTENANCE_METRIC_HOOKS,
  createSharedControlMaintenanceWorker
} from "../../src/postgres/shared-control-maintenance-worker.mjs";

const PRUNE_RESULT = Object.freeze({
  removed: 3,
  sharedRemoved: 1,
  anonymousRemoved: 1,
  replayRemoved: 1
});

test("start schedules one bounded first cycle and close is idempotent", async () => {
  const timers = timerHarness();
  let calls = 0;
  const worker = createSharedControlMaintenanceWorker({
    repository: { async pruneSharedControlMaintenance(input) { calls += 1; assert.deepEqual(input, { limit: 7 }); return PRUNE_RESULT; } },
    firstCycleDelayMs: 0,
    intervalMs: 1_000,
    pruneLimit: 7,
    setTimeoutFn: timers.setTimeoutFn,
    clearTimeoutFn: timers.clearTimeoutFn
  });

  assert.equal(worker.snapshot().state, "idle");
  assert.deepEqual(worker.start(), worker.start());
  assert.equal(timers.pending(), 1);
  await timers.fireNext();
  assert.equal(calls, 1);
  assert.equal(timers.pending(), 1);
  await timers.fireNext();
  assert.equal(calls, 2);
  assert.equal(timers.pending(), 1);

  const firstClose = worker.close();
  const secondClose = worker.close();
  assert.strictEqual(firstClose, secondClose);
  const closed = await firstClose;
  assert.equal(closed.state, "closed");
  assert.equal(closed.drained, true);
  assert.strictEqual(await worker.close(), closed);
  assert.equal(timers.pending(), 0);
  assert.equal(worker.start().state, "closed");
});

test("concurrent calls share the active cycle and never overlap database pruning", async () => {
  let release;
  let calls = 0;
  const pending = new Promise((resolve) => { release = resolve; });
  const worker = createSharedControlMaintenanceWorker({
    repository: { pruneSharedControlMaintenance() { calls += 1; return pending; } }
  });

  const first = worker.runOnce();
  const second = worker.runOnce();
  assert.strictEqual(first, second);
  assert.equal(calls, 1);
  release(PRUNE_RESULT);
  assert.deepEqual(await first, { ok: true, ...PRUNE_RESULT });
  assert.equal(worker.snapshot().active, 0);
});

test("database outage is contained and the next interval cycle recovers", async () => {
  const results = [new Error("driver password must not escape"), PRUNE_RESULT];
  const metricCalls = [];
  const metrics = {
    [SHARED_CONTROL_MAINTENANCE_METRIC_HOOKS.cycle](amount) { metricCalls.push(["cycle", amount]); },
    [SHARED_CONTROL_MAINTENANCE_METRIC_HOOKS.success](amount) { metricCalls.push(["success", amount]); },
    [SHARED_CONTROL_MAINTENANCE_METRIC_HOOKS.failure](amount) { metricCalls.push(["failure", amount]); },
    [SHARED_CONTROL_MAINTENANCE_METRIC_HOOKS.removed](amount) { metricCalls.push(["removed", amount]); }
  };
  const worker = createSharedControlMaintenanceWorker({
    repository: { async pruneSharedControlMaintenance() { const result = results.shift(); if (result instanceof Error) throw result; return result; } },
    metrics
  });

  const failed = await worker.runOnce();
  const recovered = await worker.runOnce();
  assert.equal(failed.ok, false);
  assert.equal(recovered.ok, true);
  assert.deepEqual(metricCalls, [["cycle", 1], ["failure", 1], ["cycle", 1], ["success", 1], ["removed", 3]]);
  assert.equal(JSON.stringify(failed).includes("password"), false);
});

test("metric sink failures cannot crash or change the maintenance result", async () => {
  const metrics = Object.fromEntries(Object.values(SHARED_CONTROL_MAINTENANCE_METRIC_HOOKS).map((hook) => [hook, () => { throw new Error("sink detail"); }]));
  const worker = createSharedControlMaintenanceWorker({
    repository: { async pruneSharedControlMaintenance() { return PRUNE_RESULT; } },
    metrics
  });
  await assert.doesNotReject(async () => {
    assert.deepEqual(await worker.runOnce(), { ok: true, ...PRUNE_RESULT });
  });
});

test("repository spends one total budget across generic, anonymous, and replay stores", async () => {
  const calls = [];
  const client = {
    async query(text, params) {
      calls.push({ text, params });
      if (text.includes("agentpass_prune_shared_control_expired")) return { rowCount: 1, rows: [{ removed: "3" }] };
      if (text.includes("agentpass_prune_anonymous_rate_limits")) return { rowCount: 1, rows: [{ removed: "2" }] };
      if (text.includes("agentpass_prune_human_identity_assertion_replays")) return { rowCount: 1, rows: [{ removed: "5" }] };
      throw new Error("unexpected SQL");
    }
  };
  const repository = createSharedControlRepository({ client });
  assert.equal(typeof repository[SHARED_CONTROL_MAINTENANCE_METHOD], "function");
  assert.deepEqual(await repository.pruneSharedControlMaintenance({ limit: 10 }), {
    removed: 10,
    sharedRemoved: 3,
    anonymousRemoved: 2,
    replayRemoved: 5
  });
  assert.deepEqual(calls.map((call) => call.params), [[10], [7], [5]]);
  assert.match(calls[2].text, /agentpass_prune_human_identity_assertion_replays/);
});

function timerHarness() {
  let nextId = 0;
  const scheduled = new Map();
  return {
    setTimeoutFn(callback, delay) {
      const handle = { id: ++nextId, delay, unref() {} };
      scheduled.set(handle.id, { handle, callback });
      return handle;
    },
    clearTimeoutFn(handle) { scheduled.delete(handle?.id); },
    pending() { return scheduled.size; },
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
