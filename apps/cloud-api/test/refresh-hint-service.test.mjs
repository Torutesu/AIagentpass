import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  REFRESH_HINT_SERVICE_ERROR_CODES,
  createRefreshHintService
} from "../src/refresh-hint-service.mjs";
import { createOperationalMetrics } from "../src/postgres/operational-health.mjs";
import { refreshHintSigningData } from "../../../packages/protocol/src/index.mjs";

const ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111";
const DEVICE_ID = "22222222-2222-4222-8222-222222222222";
const OUTBOX_ID = "33333333-3333-4333-8333-333333333333";
const NOW = Date.parse("2026-08-13T00:00:00.000Z");
const NONCE = Buffer.alloc(16, 0x41);
const NONCE_DIGEST = crypto.createHash("sha256").update(NONCE).digest("hex");

function refreshRow(generation = 7) {
  return {
    organization_id: ORGANIZATION_ID,
    device_id: DEVICE_ID,
    desired_generation: generation,
    refresh_state: "pending",
    outbox_id: OUTBOX_ID,
    refresh_nonce_key_id: "refresh-nonce-v3",
    refresh_nonce_digest: NONCE_DIGEST,
    published_at: "2026-08-13T00:00:00.000Z",
    expires_at: "2026-08-13T00:05:00.000Z"
  };
}

function fixture(overrides = {}) {
  const keys = crypto.generateKeyPairSync("ed25519");
  const calls = { polls: [], deliveries: [], waits: [], derives: [], signs: [] };
  const rows = overrides.rows ?? [refreshRow()];
  const service = createRefreshHintService({
    source: {
      async pollDeviceRefresh(input) { calls.polls.push(input); return rows.shift() ?? null; },
      async markDeviceRefreshDelivered(input) { calls.deliveries.push(input); }
    },
    nonceDeriver: overrides.nonceDeriver ?? {
      async derive(input) { calls.derives.push(input); return { nonce: NONCE, nonce_digest: NONCE_DIGEST }; },
      matchesDigest(derived, expected) { return derived.nonce_digest === expected; }
    },
    signer: overrides.signer ?? {
      async publicKeyMetadata() { return { key_id: "refresh-2026-08", algorithm: "ed25519", public_key: keys.publicKey }; },
      async signRefreshHint(bytes) { calls.signs.push(Buffer.from(bytes)); return crypto.sign(null, bytes, keys.privateKey); }
    },
    notifier: overrides.notifier ?? { async waitForRefresh(input) { calls.waits.push(input); } },
    metrics: overrides.metrics,
    now: () => NOW,
    maxWaiters: overrides.maxWaiters ?? 2
  });
  return { service, calls, keys };
}

test("issues a purpose-signed hint from committed metadata without copying authority", async () => {
  const f = fixture();
  const hint = await f.service.poll({ organization_id: ORGANIZATION_ID, device_id: DEVICE_ID, after_generation: 6, wait_ms: 0 });
  assert.deepEqual(Object.keys(hint), ["version", "type", "organization_id", "device_id", "authority_generation", "published_at", "expires_at", "nonce", "key_id", "signature_algorithm", "signature"]);
  assert.equal(hint.authority_generation, 7);
  assert.equal(hint.key_id, "refresh-2026-08");
  assert.equal(crypto.verify(null, refreshHintSigningData(hint), f.keys.publicKey, Buffer.from(hint.signature, "base64url")), true);
  assert.deepEqual(f.calls.derives[0], { organization_id: ORGANIZATION_ID, device_id: DEVICE_ID, authority_generation: 7, outbox_id: OUTBOX_ID, key_id: "refresh-nonce-v3" });
  assert.equal(f.calls.polls[0].wait_ms, 0);
  assert.deepEqual(f.calls.deliveries[0], { organization_id: ORGANIZATION_ID, device_id: DEVICE_ID, outbox_id: OUTBOX_ID, desired_generation: 7, delivered_at: "2026-08-13T00:00:00.000Z" });
  assert.equal(JSON.stringify(hint).includes("policy"), false);
});

test("records bounded refresh pipeline outcomes without labels", async () => {
  const metrics = createOperationalMetrics();
  const observed = fixture({ metrics });
  await observed.service.poll({ organization_id: ORGANIZATION_ID, device_id: DEVICE_ID, after_generation: 6, wait_ms: 0 });

  const timedOut = fixture({ metrics, rows: [null, null] });
  assert.equal(await timedOut.service.poll({ organization_id: ORGANIZATION_ID, device_id: DEVICE_ID, after_generation: 7, wait_ms: 1 }), null);

  const failed = fixture({ metrics, signer: {
    async publicKeyMetadata() { throw new Error("signer unavailable"); },
    async signRefreshHint() { throw new Error("signer unavailable"); }
  } });
  await assert.rejects(failed.service.poll({ organization_id: ORGANIZATION_ID, device_id: DEVICE_ID, after_generation: 6 }), { code: REFRESH_HINT_SERVICE_ERROR_CODES.UNAVAILABLE });

  const counters = metrics.snapshot().counters;
  assert.equal(counters.refresh_propagation_observation_total, 2);
  assert.equal(counters.refresh_propagation_timeout_total, 1);
  assert.equal(counters.refresh_delivery_failure_total, 1);
});

test("records waiter rejection and notifier failure while preserving fallback correctness", async () => {
  const metrics = createOperationalMetrics();
  let release;
  const waiting = fixture({
    metrics,
    rows: [null, null, null],
    notifier: { waitForRefresh: () => new Promise((resolve) => { release = resolve; }) },
    maxWaiters: 1
  });
  const first = waiting.service.poll({ organization_id: ORGANIZATION_ID, device_id: DEVICE_ID, after_generation: 7, wait_ms: 1_000 });
  await new Promise((resolve) => setImmediate(resolve));
  await assert.rejects(waiting.service.poll({ organization_id: ORGANIZATION_ID, device_id: DEVICE_ID, after_generation: 7, wait_ms: 1_000 }), { code: REFRESH_HINT_SERVICE_ERROR_CODES.BUSY });
  release();
  assert.equal(await first, null);

  const fallback = fixture({
    metrics,
    rows: [null, refreshRow(9)],
    notifier: { async waitForRefresh() { throw new Error("listener disconnected"); } }
  });
  assert.equal((await fallback.service.poll({ organization_id: ORGANIZATION_ID, device_id: DEVICE_ID, after_generation: 8, wait_ms: 10 })).authority_generation, 9);
  const counters = metrics.snapshot().counters;
  assert.equal(counters.refresh_waiter_rejection_total, 1);
  assert.equal(counters.refresh_notification_wake_failure_total, 1);
});

test("queries before and after one notification wait so notification loss is harmless", async () => {
  const f = fixture({ rows: [null, refreshRow(8)] });
  const hint = await f.service.poll({ organizationId: ORGANIZATION_ID, deviceId: DEVICE_ID, afterGeneration: 7, waitMs: 250 });
  assert.equal(hint.authority_generation, 8);
  assert.equal(f.calls.polls.length, 2);
  assert.equal(f.calls.waits.length, 1);
  assert.equal(f.service.snapshot().active_waiters, 0);
});

test("returns null after the final authoritative query and bounds concurrent waiters", async () => {
  let release;
  const notifier = { waitForRefresh: () => new Promise((resolve) => { release = resolve; }) };
  const f = fixture({ rows: [null, null, null], notifier, maxWaiters: 1 });
  const first = f.service.poll({ organization_id: ORGANIZATION_ID, device_id: DEVICE_ID, after_generation: 7, wait_ms: 1_000 });
  await new Promise((resolve) => setImmediate(resolve));
  await assert.rejects(f.service.poll({ organization_id: ORGANIZATION_ID, device_id: DEVICE_ID, after_generation: 7, wait_ms: 1_000 }), (error) => error.code === REFRESH_HINT_SERVICE_ERROR_CODES.BUSY);
  release();
  assert.equal(await first, null);
  assert.equal(f.service.snapshot().active_waiters, 0);
});

test("aborts without a final query and never exposes dependency errors", async () => {
  const controller = new AbortController();
  const f = fixture({ rows: [null], notifier: { waitForRefresh: () => new Promise(() => {}) } });
  const pending = f.service.poll({ organization_id: ORGANIZATION_ID, device_id: DEVICE_ID, after_generation: 7, wait_ms: 1_000, signal: controller.signal });
  controller.abort();
  await assert.rejects(pending, (error) => error.code === REFRESH_HINT_SERVICE_ERROR_CODES.ABORTED && !JSON.stringify(error).includes(ORGANIZATION_ID));
  assert.equal(f.calls.polls.length, 1);
});

test("fails closed on cross-device metadata, authority-bearing rows, stale expiry, and malformed signer output", async () => {
  for (const mutation of [
    { device_id: "44444444-4444-4444-8444-444444444444" },
    { policy_scope: { operations: ["git.commit.sign"] } },
    { expires_at: "2026-08-12T23:59:59.999Z" },
    { refresh_nonce_digest: "0".repeat(64) },
    { published_at: "2026-08-13T00:01:00.001Z", expires_at: "2026-08-13T00:05:00.000Z" }
  ]) {
    const base = refreshRow();
    const f = fixture({ rows: [{ ...base, ...mutation }] });
    await assert.rejects(f.service.poll({ organization_id: ORGANIZATION_ID, device_id: DEVICE_ID, after_generation: 6 }), (error) => error.code === REFRESH_HINT_SERVICE_ERROR_CODES.UNAVAILABLE);
  }
});

test("rejects a signer response that is well-shaped but not produced by the advertised public key", async () => {
  const keys = crypto.generateKeyPairSync("ed25519");
  const f = fixture({ signer: {
    async publicKeyMetadata() { return { key_id: "refresh-2026-08", algorithm: "ed25519", public_key: keys.publicKey }; },
    async signRefreshHint() { return Buffer.alloc(64, 0x55); }
  } });
  await assert.rejects(f.service.poll({ organization_id: ORGANIZATION_ID, device_id: DEVICE_ID, after_generation: 6 }), (error) => error.code === REFRESH_HINT_SERVICE_ERROR_CODES.UNAVAILABLE);
});
