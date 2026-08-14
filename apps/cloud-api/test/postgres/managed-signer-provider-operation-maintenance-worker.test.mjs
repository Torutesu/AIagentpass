import assert from "node:assert/strict";
import test from "node:test";

import {
  MANAGED_SIGNER_PROVIDER_OPERATION_MAINTENANCE_METRIC_HOOKS,
  createManagedSignerProviderOperationMaintenanceWorker
} from "../../src/postgres/managed-signer-provider-operation-maintenance-worker.mjs";

const RESULT = Object.freeze({ quarantined: 2, reconciled: 3, pruned: 1, total: 6 });

test("runs one deployment-wide bounded cycle and never overlaps concurrent calls", async () => {
  let release;
  let active = 0;
  let maximumActive = 0;
  let calls = 0;
  const pending = new Promise((resolve) => { release = resolve; });
  const worker = createManagedSignerProviderOperationMaintenanceWorker({
    repository: {
      maintainProviderOperations(input) {
        calls += 1;
        assert.deepEqual(input, { limit: 7 });
        active += 1;
        maximumActive = Math.max(maximumActive, active);
        return pending.finally(() => { active -= 1; });
      }
    },
    maintenanceLimit: 7
  });

  const first = worker.runOnce();
  const second = worker.runOnce();
  assert.strictEqual(first, second);
  assert.equal(calls, 1);
  release(RESULT);
  assert.deepEqual(await first, { ok: true, ...RESULT });
  assert.equal(maximumActive, 1);
  assert.equal(active, 0);
});

test("contains malformed repository results and never exposes their fields", async () => {
  const malformed = [
    { quarantined: 1, reconciled: 0, pruned: 0 },
    { quarantined: 1, reconciled: 0, pruned: 0, total: 2 },
    { quarantined: 1, reconciled: 0, pruned: 0, total: 1, operation_id: "must-not-escape" },
    { quarantined: -1, reconciled: 0, pruned: 0, total: 0 }
  ];
  for (const value of malformed) {
    const worker = createManagedSignerProviderOperationMaintenanceWorker({
      repository: { async maintainProviderOperations() { return value; } }
    });
    const result = await worker.runOnce();
    assert.deepEqual(result, { ok: false, failed: true, quarantined: 0, reconciled: 0, pruned: 0, total: 0 });
    assert.equal(JSON.stringify(result).includes("must-not-escape"), false);
  }
});

test("snapshot exposes only aggregate cycle freshness and failure state", async () => {
  const times = [100, 200];
  let fail = true;
  const worker = createManagedSignerProviderOperationMaintenanceWorker({
    repository: {
      async maintainProviderOperations() {
        if (fail) throw new Error("database detail must stay private");
        return { quarantined: 0, reconciled: 0, pruned: 0, total: 0 };
      }
    },
    now: () => times.shift()
  });
  assert.deepEqual(await worker.runOnce(), { ok: false, failed: true, quarantined: 0, reconciled: 0, pruned: 0, total: 0 });
  assert.deepEqual(worker.snapshot(), {
    state: "idle",
    active: 0,
    scheduled: false,
    cycles: 1,
    consecutive_failures: 1,
    last_cycle_at: 100,
    last_success_at: null,
    config: worker.snapshot().config
  });
  fail = false;
  assert.equal((await worker.runOnce()).ok, true);
  assert.equal(worker.snapshot().cycles, 2);
  assert.equal(worker.snapshot().consecutive_failures, 0);
  assert.equal(worker.snapshot().last_cycle_at, 200);
  assert.equal(worker.snapshot().last_success_at, 200);
  assert.doesNotMatch(JSON.stringify(worker.snapshot()), /database|operation_id|receipt|request_bytes/u);
});

test("metric sink failures cannot affect maintenance or leak non-aggregate data", async () => {
  const calls = [];
  const metrics = Object.fromEntries(Object.values(MANAGED_SIGNER_PROVIDER_OPERATION_MAINTENANCE_METRIC_HOOKS).map((hook) => [
    hook,
    (amount) => { calls.push([hook, amount]); throw new Error("sink detail"); }
  ]));
  const worker = createManagedSignerProviderOperationMaintenanceWorker({
    repository: { async maintainProviderOperations() { return RESULT; } },
    metrics
  });
  await assert.doesNotReject(async () => {
    assert.deepEqual(await worker.runOnce(), { ok: true, ...RESULT });
  });
  assert.deepEqual(calls.map(([hook, amount]) => [hook, amount]), [
    [MANAGED_SIGNER_PROVIDER_OPERATION_MAINTENANCE_METRIC_HOOKS.cycle, 1],
    [MANAGED_SIGNER_PROVIDER_OPERATION_MAINTENANCE_METRIC_HOOKS.success, 1],
    [MANAGED_SIGNER_PROVIDER_OPERATION_MAINTENANCE_METRIC_HOOKS.quarantined, 2],
    [MANAGED_SIGNER_PROVIDER_OPERATION_MAINTENANCE_METRIC_HOOKS.reconciled, 3],
    [MANAGED_SIGNER_PROVIDER_OPERATION_MAINTENANCE_METRIC_HOOKS.pruned, 1]
  ]);
});

test("close stops scheduling, is idempotent, and reports a bounded drain timeout", async () => {
  const timers = timerHarness();
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  const worker = createManagedSignerProviderOperationMaintenanceWorker({
    repository: { maintainProviderOperations() { return pending; } },
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

test("start schedules an unref first cycle and then one interval at a time", async () => {
  const timers = timerHarness();
  let calls = 0;
  const worker = createManagedSignerProviderOperationMaintenanceWorker({
    repository: { async maintainProviderOperations(input) { calls += 1; assert.deepEqual(input, { limit: 4 }); return { quarantined: 0, reconciled: 0, pruned: 0, total: 0 }; } },
    firstCycleDelayMs: 3,
    intervalMs: 11,
    maintenanceLimit: 4,
    setTimeoutFn: timers.setTimeoutFn,
    clearTimeoutFn: timers.clearTimeoutFn
  });

  assert.equal(worker.start().state, "running");
  assert.equal(worker.start().state, "running");
  assert.equal(timers.pending(), 1);
  assert.equal(timers.last().unrefCalled, true);
  assert.equal(timers.last().delay, 3);
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

test("configuration and repository contract are bounded and deployment-wide", () => {
  assert.throws(() => createManagedSignerProviderOperationMaintenanceWorker(), /configuration is invalid/u);
  assert.throws(() => createManagedSignerProviderOperationMaintenanceWorker({ repository: {} }), /configuration is invalid/u);
  assert.throws(() => createManagedSignerProviderOperationMaintenanceWorker({
    repository: { maintainProviderOperations() {} },
    maintenanceLimit: 1_001
  }), /configuration is invalid/u);
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
