import assert from "node:assert/strict";
import test from "node:test";

import {
  discardOwnerRecoveryStateTransitions,
  flushOwnerRecoveryStateTransitions,
  observeOwnerRecoveryStateTransition
} from "../../src/postgres/owner-recovery-transition-observer.mjs";

test("queues bounded database-time deltas and flushes each observation once", () => {
  const tx = {};
  const recorded = [];
  const metrics = { recordOwnerRecoveryStateLatency(value) { recorded.push(value); } };
  assert.equal(observeOwnerRecoveryStateTransition({ tx, metrics, previousUpdatedAt: new Date(1_000), nextUpdatedAt: new Date(1_125) }), true);
  assert.deepEqual(recorded, []);
  assert.equal(flushOwnerRecoveryStateTransitions(tx), 1);
  assert.deepEqual(recorded, [125]);
  assert.equal(flushOwnerRecoveryStateTransitions(tx), 0);
  assert.deepEqual(recorded, [125]);
});

test("drops rolled-back and invalid deltas without affecting authority", () => {
  const tx = {};
  const recorded = [];
  const metrics = { recordOwnerRecoveryStateLatency(value) { recorded.push(value); } };
  assert.equal(observeOwnerRecoveryStateTransition({ tx, metrics, previousUpdatedAt: new Date(2_000), nextUpdatedAt: new Date(1_000) }), false);
  assert.equal(observeOwnerRecoveryStateTransition({ tx, metrics, previousUpdatedAt: "invalid", nextUpdatedAt: new Date(1_000) }), false);
  assert.equal(observeOwnerRecoveryStateTransition({ tx, metrics, previousUpdatedAt: new Date(1_000), nextUpdatedAt: new Date(1_010) }), true);
  assert.equal(discardOwnerRecoveryStateTransitions(tx), 1);
  assert.equal(flushOwnerRecoveryStateTransitions(tx), 0);
  assert.deepEqual(recorded, []);
});

test("contains synchronous and asynchronous metric sink failures", async () => {
  const throwingTx = {};
  observeOwnerRecoveryStateTransition({
    tx: throwingTx,
    metrics: { recordOwnerRecoveryStateLatency() { throw new Error("sink failed"); } },
    previousUpdatedAt: new Date(1_000),
    nextUpdatedAt: new Date(1_001)
  });
  assert.equal(flushOwnerRecoveryStateTransitions(throwingTx), 1);

  const rejectingTx = {};
  observeOwnerRecoveryStateTransition({
    tx: rejectingTx,
    metrics: { recordOwnerRecoveryStateLatency() { return Promise.reject(new Error("sink rejected")); } },
    previousUpdatedAt: new Date(1_000),
    nextUpdatedAt: new Date(1_001)
  });
  assert.equal(flushOwnerRecoveryStateTransitions(rejectingTx), 1);
  await new Promise((resolve) => setImmediate(resolve));
});
