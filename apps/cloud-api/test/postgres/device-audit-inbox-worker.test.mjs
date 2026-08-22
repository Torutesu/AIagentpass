import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createDeviceAuditInboxWorker } from "../../src/postgres/device-audit-inbox-worker.mjs";

const entry = Object.freeze({
  organization_id: "11111111-1111-4111-8111-111111111111",
  inbox_id: "22222222-2222-4222-8222-222222222222",
  device_id: "33333333-3333-4333-8333-333333333333",
  batch_id: `audit-${"a".repeat(64)}`,
  events: Object.freeze([]),
  attempt: 1,
});

function repositoryFor(token, settleCalls) {
  return {
    async claimBatch() { return { claim_token: token, events: [entry] }; },
    async settle(value) { settleCalls.push(value); return { state: value.outcome, attempt: entry.attempt }; },
  };
}

test("worker settles accepted processor output with a digest of the opaque claim token", async () => {
  const token = Buffer.alloc(32, 7).toString("base64url");
  const settleCalls = [];
  const worker = createDeviceAuditInboxWorker({ repository: repositoryFor(token, settleCalls), processor: { async process() { return { outcome: "accepted" }; } } });
  assert.deepEqual(await worker.runOnce(), { claimed: 1, accepted: 1, retryable_failure: 0, uncertain: 0 });
  assert.equal(settleCalls.length, 1);
  assert.equal(settleCalls[0].claim_token_digest, crypto.createHash("sha256").update(Buffer.alloc(32, 7)).digest("hex"));
});

test("worker quarantines processor exceptions instead of blindly retrying", async () => {
  const token = Buffer.alloc(32, 8).toString("base64url");
  const settleCalls = [];
  const worker = createDeviceAuditInboxWorker({ repository: repositoryFor(token, settleCalls), processor: { async process() { throw new Error("response lost"); } } });
  assert.deepEqual(await worker.runOnce(), { claimed: 1, accepted: 0, retryable_failure: 0, uncertain: 1 });
  assert.equal(settleCalls[0].outcome, "uncertain");
});

test("worker exposes bounded failure state for readiness without leaving the running state", async () => {
  const now = 1_700_000_000_000;
  const worker = createDeviceAuditInboxWorker({
    now: () => now,
    repository: { async claimBatch() { throw new Error("database unavailable"); }, async settle() {} },
    processor: { async process() { return { outcome: "accepted" }; } },
    setTimeoutFn: () => ({ unref() {} }),
    clearTimeoutFn: () => {}
  });
  worker.start();
  await assert.rejects(() => worker.runOnce(), { code: "ERR_DEVICE_AUDIT_INBOX_WORKER_UNAVAILABLE" });
  const snapshot = worker.snapshot();
  assert.equal(snapshot.state, "running");
  assert.equal(snapshot.cycles, 1);
  assert.equal(snapshot.consecutive_failures, 1);
  assert.equal(snapshot.last_cycle_at, now);
  assert.equal(snapshot.last_success_at, null);
  await worker.close();
});
