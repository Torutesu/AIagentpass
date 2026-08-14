import assert from "node:assert/strict";
import test from "node:test";

import { createOperationalMetrics } from "../../src/postgres/operational-health.mjs";
import { createOwnerRecoveryOutboxWorker } from "../../src/postgres/owner-recovery-outbox-worker.mjs";

const NOW = Date.parse("2026-08-14T00:00:00.000Z");
const CLAIM = "C".repeat(43);
const DELIVERY_BINDING = Object.freeze({ binding_id: "test-owner-recovery", key_version: 1, binding_digest: "a".repeat(64) });
const EVENT = Object.freeze({
  organization_id: "11111111-1111-4111-8111-111111111111",
  event_id: "22222222-2222-4222-8222-222222222222",
  request_id: "33333333-3333-4333-8333-333333333333",
  subject_member_id: "44444444-4444-4444-8444-444444444444",
  event_type: "recovery.request.created",
  attempt: 1,
  claim_expires_at: new Date(NOW + 30_000).toISOString(),
  created_at: new Date(NOW - 500).toISOString()
});

test("publishes only the public event with event_id idempotency and marks exact claim", async () => {
  const calls = [];
  const metrics = createOperationalMetrics();
  const repository = fixtureRepository(calls);
  const publisher = { async publish(input) { calls.push(["publish", input]); return accepted(input.idempotency_key); } };
  const worker = createOwnerRecoveryOutboxWorker({ repository, publisher, metrics, now: () => NOW, random: () => 0 });
  const result = await worker.runOnce();
  assert.deepEqual(result, { claimed: 1, published: 1, retried: 0, dead_lettered: 0, claim_lost: 0, uncertain: 0 });
  const publish = calls.find(([name]) => name === "publish")[1];
  assert.equal(publish.idempotency_key, EVENT.event_id);
  assert.deepEqual(Object.keys(publish.event).sort(), ["created_at", "event_id", "event_type", "kind", "organization_id", "request_id", "schema_version", "subject_member_id"]);
  assert.equal(JSON.stringify(publish).includes(CLAIM), false);
  assert.deepEqual(calls.find(([name]) => name === "published")[1], { organization_id: EVENT.organization_id, event_id: EVENT.event_id, attempt: 1, claim_token: CLAIM });
  const counters = metrics.snapshot().counters;
  assert.equal(counters.owner_recovery_outbox_claim_total, 1);
  assert.equal(counters.owner_recovery_outbox_publish_total, 1);
  assert.equal(counters.owner_recovery_outbox_lag_count, 1);
  assert.equal(counters.owner_recovery_outbox_lag_total_ms, 500);
});

test("unknown provider outcomes become durable uncertain state and never persist diagnostics", async () => {
  const calls = [];
  const repository = fixtureRepository(calls);
  const worker = createOwnerRecoveryOutboxWorker({
    repository,
    publisher: { async publish() { throw new Error("provider diagnostic must-not-persist"); } },
    now: () => NOW,
    random: () => 0,
    baseRetryMs: 1_000
  });
  const result = await worker.runOnce();
  assert.equal(result.uncertain, 1);
  assert.equal(calls.some(([name]) => name === "failed"), false);
  assert.deepEqual(calls.find(([name]) => name === "uncertain")[1], { organization_id: EVENT.organization_id, event_id: EVENT.event_id, attempt: 1, claim_token: CLAIM });
  assert.equal(JSON.stringify(calls).includes("must-not-persist"), false);
});

test("provider binding mismatch is quarantined before any provider call", async () => {
  const calls = [];
  const repository = fixtureRepository(calls, { event: { ...EVENT, provider_binding: { ...DELIVERY_BINDING, binding_digest: "b".repeat(64) } }, binding: DELIVERY_BINDING });
  let providerCalls = 0;
  const worker = createOwnerRecoveryOutboxWorker({
    repository,
    publisher: { binding: DELIVERY_BINDING, async publish() { providerCalls += 1; return accepted(EVENT.event_id); } },
    now: () => NOW,
    random: () => 0
  });
  const result = await worker.runOnce();
  assert.equal(result.uncertain, 1);
  assert.equal(providerCalls, 0);
  assert.equal(calls.some(([name]) => name === "uncertain"), true);
});

test("repository and publisher binding configuration must match", () => {
  const repository = fixtureRepository([], { binding: DELIVERY_BINDING });
  assert.throws(() => createOwnerRecoveryOutboxWorker({
    repository,
    publisher: { binding: { ...DELIVERY_BINDING, key_version: 2 }, async publish() {} }
  }), /configuration is invalid/u);
});

test("automatically confirms exact-binding uncertain deliveries from provider lookup proof", async () => {
  const secondEvent = "55555555-5555-4555-8555-555555555555";
  const confirmed = [];
  const repository = {
    binding: DELIVERY_BINDING,
    async claimBatch() { return { claim_token: CLAIM, events: [] }; },
    async markPublished() {},
    async markFailed() {},
    async markUncertain() {},
    async claimConfirmationBatch() {
      return [EVENT.event_id, secondEvent].map((eventId, index) => ({
        organization_id: EVENT.organization_id,
        event_id: eventId,
        expected_management_version: 1,
        provider_confirmation_attempt: index + 1,
        provider_binding: DELIVERY_BINDING
      }));
    },
    async markProviderConfirmed(input) { confirmed.push(input); return { published: true }; }
  };
  const publisher = {
    binding: DELIVERY_BINDING,
    async publish() { throw new Error("no pending delivery expected"); },
    async lookupAcceptance({ idempotency_key }) { return { accepted: idempotency_key === EVENT.event_id, idempotency_key }; }
  };
  const metrics = createOperationalMetrics();
  const result = await createOwnerRecoveryOutboxWorker({ repository, publisher, metrics, now: () => NOW }).runOnce();
  assert.deepEqual(result, {
    claimed: 0,
    published: 0,
    retried: 0,
    dead_lettered: 0,
    claim_lost: 0,
    uncertain: 0,
    confirmation_checked: 2,
    confirmed: 1
  });
  assert.deepEqual(confirmed, [{
    organization_id: EVENT.organization_id,
    event_id: EVENT.event_id,
    expected_management_version: 1,
    provider_confirmation_attempt: 1
  }]);
  assert.equal(metrics.snapshot().counters.owner_recovery_outbox_confirmation_lookup_total, 2);
  assert.equal(metrics.snapshot().counters.owner_recovery_outbox_confirmation_success_total, 1);
  assert.equal(metrics.snapshot().counters.owner_recovery_outbox_confirmation_miss_total, 1);
  assert.equal(metrics.snapshot().counters.owner_recovery_outbox_confirmation_failure_total, 0);
});

test("rejects partial confirmation capability wiring", () => {
  const repository = { ...fixtureRepository([], { binding: DELIVERY_BINDING }), async claimConfirmationBatch() { return []; } };
  assert.throws(() => createOwnerRecoveryOutboxWorker({
    repository,
    publisher: { binding: DELIVERY_BINDING, async publish() {} }
  }), /configuration is invalid/u);
});

test("a malformed claimed event is isolated while valid events publish", async () => {
  const calls = [];
  const valid = { ...EVENT, event_id: "55555555-5555-4555-8555-555555555555" };
  const poison = { ...EVENT, event_id: "poison-event-with-secret", created_at: "not-a-timestamp" };
  const repository = fixtureRepository(calls, { events: [poison, valid] });
  const published = [];
  const worker = createOwnerRecoveryOutboxWorker({
    repository,
    publisher: { publish(input) { published.push(input.idempotency_key); return accepted(input.idempotency_key); } },
    metrics: createOperationalMetrics(),
    now: () => NOW,
    random: () => 0
  });

  const result = await worker.runOnce();

  assert.deepEqual(result, { claimed: 2, published: 1, retried: 0, dead_lettered: 0, claim_lost: 0, uncertain: 1 });
  assert.deepEqual(published, [valid.event_id]);
  assert.deepEqual(calls.filter(([name]) => name === "published").map(([, input]) => input.event_id), [valid.event_id]);
  assert.equal(JSON.stringify(calls).includes("poison-event-with-secret"), false);
});

test("invalid attempts and timestamps do not poison neighboring events", async () => {
  const calls = [];
  const valid = { ...EVENT, event_id: "66666666-6666-4666-8666-666666666666" };
  const invalidAttempt = { ...EVENT, event_id: "77777777-7777-4777-8777-777777777777", attempt: 0 };
  const invalidTimestamp = { ...EVENT, event_id: "88888888-8888-4888-8888-888888888888", created_at: "invalid" };
  const repository = fixtureRepository(calls, { events: [invalidAttempt, invalidTimestamp, valid] });
  const worker = createOwnerRecoveryOutboxWorker({
    repository,
    publisher: { publish(input) { return accepted(input.idempotency_key); } },
    now: () => NOW,
    random: () => 0
  });

  const result = await worker.runOnce();

  assert.equal(result.uncertain, 2);
  assert.equal(result.published, 1);
  assert.deepEqual(calls.filter(([name]) => name === "published").map(([, input]) => input.event_id), [valid.event_id]);
});

test("bad retry jitter is isolated from valid events", async () => {
  const calls = [];
  const rejected = { ...EVENT, event_id: "99999999-9999-4999-8999-999999999999" };
  const valid = { ...EVENT, event_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" };
  const repository = fixtureRepository(calls, { events: [rejected, valid] });
  const worker = createOwnerRecoveryOutboxWorker({
    repository,
    publisher: { publish(input) { return input.idempotency_key === rejected.event_id ? rejectedResponse(input.idempotency_key) : accepted(input.idempotency_key); } },
    now: () => NOW,
    random: () => Number.NaN
  });

  const result = await worker.runOnce();

  assert.equal(result.uncertain, 1);
  assert.equal(result.published, 1);
  assert.equal(calls.some(([name, input]) => name === "failed" && input.event_id === rejected.event_id), false);
  assert.equal(calls.some(([name, input]) => name === "published" && input.event_id === valid.event_id), true);
});

test("a synchronous publisher throw is isolated and does not expose its diagnostic", async () => {
  const calls = [];
  const poison = { ...EVENT, event_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" };
  const valid = { ...EVENT, event_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc" };
  const repository = fixtureRepository(calls, { events: [poison, valid] });
  const worker = createOwnerRecoveryOutboxWorker({
    repository,
    publisher: { publish(input) { if (input.idempotency_key === poison.event_id) throw new Error("secret publisher diagnostic"); return accepted(input.idempotency_key); } },
    now: () => NOW,
    random: () => 0
  });

  const result = await worker.runOnce();

  assert.equal(result.uncertain, 1);
  assert.equal(result.published, 1);
  assert.equal(JSON.stringify(calls).includes("secret publisher diagnostic"), false);
  assert.equal(calls.some(([name, input]) => name === "published" && input.event_id === valid.event_id), true);
});

test("an explicit provider rejection schedules bounded exponential retry", async () => {
  const calls = [];
  const repository = fixtureRepository(calls);
  const worker = createOwnerRecoveryOutboxWorker({ repository, publisher: { async publish(input) { return rejectedResponse(input.idempotency_key); } }, now: () => NOW, random: () => 0, baseRetryMs: 1_000 });
  const result = await worker.runOnce();
  assert.equal(result.retried, 1);
  const failure = calls.find(([name]) => name === "failed")[1];
  assert.equal(failure.error_code, "publisher_rejected");
  assert.equal(failure.retry_at, new Date(NOW + 1_000).toISOString());
});

test("a provider rejection for another idempotency key is quarantined instead of retried", async () => {
  const calls = [];
  const repository = fixtureRepository(calls);
  const worker = createOwnerRecoveryOutboxWorker({
    repository,
    publisher: { async publish() { return rejectedResponse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"); } },
    now: () => NOW,
    random: () => 0
  });

  const result = await worker.runOnce();

  assert.equal(result.uncertain, 1);
  assert.equal(result.retried, 0);
  assert.equal(calls.some(([name]) => name === "failed"), false);
  assert.equal(calls.some(([name]) => name === "uncertain"), true);
});

test("attempt 100 is dead-lettered and claim loss cannot acknowledge another worker", async () => {
  const calls = [];
  const repository = fixtureRepository(calls, { event: { ...EVENT, attempt: 100 }, failed: { dead_letter: true, retry_at: null } });
  const metrics = createOperationalMetrics();
  const worker = createOwnerRecoveryOutboxWorker({ repository, publisher: { async publish(input) { return rejectedResponse(input.idempotency_key); } }, metrics, now: () => NOW, random: () => 0 });
  const result = await worker.runOnce();
  assert.equal(result.dead_lettered, 1);
  assert.equal(metrics.snapshot().counters.owner_recovery_outbox_dead_letter_total, 1);

  const lost = fixtureRepository([], { publishError: Object.assign(new Error("stale"), { code: "owner_recovery_outbox_claim_lost" }), failedError: Object.assign(new Error("stale"), { code: "owner_recovery_outbox_claim_lost" }) });
  const lostWorker = createOwnerRecoveryOutboxWorker({ repository: lost, publisher: { async publish(input) { return accepted(input.idempotency_key); } }, now: () => NOW, random: () => 0 });
  assert.equal((await lostWorker.runOnce()).claim_lost, 1);
});

test("drain is bounded, prevents new work, and closes after active delivery settles", async () => {
  let resolvePublish;
  const pendingPublish = new Promise((resolve) => { resolvePublish = resolve; });
  const repository = fixtureRepository([]);
  const worker = createOwnerRecoveryOutboxWorker({ repository, publisher: { publish: () => pendingPublish }, now: () => NOW, random: () => 0 });
  const running = worker.runOnce();
  await new Promise((resolve) => setImmediate(resolve));
  const first = await worker.drain({ timeout_ms: 0 });
  assert.equal(first.drained, false);
  assert.equal(first.state, "draining");
  await assert.rejects(() => worker.runOnce(), (error) => error.code === "owner_recovery_outbox_worker_closed");
  resolvePublish(accepted(EVENT.event_id));
  await running;
  const second = await worker.drain({ timeout_ms: 100 });
  assert.equal(second.drained, true);
  assert.equal(second.state, "closed");
});

test("a claimed batch publishes concurrently so later leases cannot expire behind earlier timeouts", async () => {
  const events = [0, 1, 2].map((offset) => ({ ...EVENT, event_id: `${String(offset + 2).padStart(8, "0")}-2222-4222-8222-222222222222` }));
  const started = [];
  const resolvers = [];
  const repository = fixtureRepository([], { events });
  const worker = createOwnerRecoveryOutboxWorker({
    repository,
    publisher: { publish(input) { started.push(input.event.event_id); return new Promise((resolve) => resolvers.push(resolve)); } },
    now: () => NOW,
    random: () => 0
  });
  const running = worker.runOnce();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(started, events.map((event) => event.event_id));
  for (const [index, resolve] of resolvers.entries()) resolve(accepted(events[index].event_id));
  const result = await running;
  assert.equal(result.published, 3);
  assert.equal(result.uncertain, 0);
});

test("concurrent drain callers share one bounded outcome and never recreate the scheduler", async () => {
  let resolvePublish;
  const repository = fixtureRepository([]);
  const worker = createOwnerRecoveryOutboxWorker({ repository, publisher: { publish: () => new Promise((resolve) => { resolvePublish = resolve; }) }, now: () => NOW, random: () => 0 });
  const running = worker.runOnce();
  await new Promise((resolve) => setImmediate(resolve));
  const first = worker.drain({ timeout_ms: 100 });
  const second = worker.drain({ timeout_ms: 1 });
  resolvePublish(accepted(EVENT.event_id));
  await running;
  assert.deepEqual(await first, await second);
  assert.equal(worker.snapshot().state, "closed");
  assert.equal(worker.snapshot().scheduled, false);
});

test("runs bounded retention maintenance once per interval without blocking delivery on failure", async () => {
  let current = NOW;
  const pruneCalls = [];
  const repository = fixtureRepository([]);
  const worker = createOwnerRecoveryOutboxWorker({
    repository,
    publisher: { async publish(input) { return accepted(input.idempotency_key); } },
    retentionRepository: { async prune(input) { pruneCalls.push(input); } },
    now: () => current,
    random: () => 0,
    retentionPruneIntervalMs: 1_000,
    retentionPruneLimit: 7
  });
  await worker.runOnce();
  await worker.runOnce();
  assert.deepEqual(pruneCalls, [{ limit: 7 }]);
  current += 1_000;
  await worker.runOnce();
  assert.deepEqual(pruneCalls, [{ limit: 7 }, { limit: 7 }]);

  const failing = createOwnerRecoveryOutboxWorker({
    repository: fixtureRepository([]),
    publisher: { async publish(input) { return accepted(input.idempotency_key); } },
    retentionRepository: { async prune() { throw new Error("database detail must not escape"); } },
    now: () => NOW,
    random: () => 0
  });
  assert.equal((await failing.runOnce()).published, 1);
});

function fixtureRepository(calls, overrides = {}) {
  let claimed = false;
  return {
    ...(overrides.binding === undefined ? {} : { binding: overrides.binding }),
    async claimBatch(input) {
      calls.push(["claim", input]);
      if (claimed) return { claim_token: CLAIM, events: [] };
      claimed = true;
      return { claim_token: CLAIM, events: overrides.events ?? [overrides.event ?? EVENT] };
    },
    async markPublished(input) { calls.push(["published", input]); if (overrides.publishError) throw overrides.publishError; return { published: true }; },
    async markFailed(input) { calls.push(["failed", input]); if (overrides.failedError) throw overrides.failedError; return overrides.failed ?? { dead_letter: false, retry_at: input.retry_at }; },
    async markUncertain(input) { calls.push(["uncertain", input]); if (overrides.uncertainError) throw overrides.uncertainError; return { uncertain: true, uncertain_at: new Date(NOW).toISOString() }; }
  };
}

function accepted(idempotencyKey, duplicate = false) { return { accepted: true, duplicate, idempotency_key: idempotencyKey }; }
function rejectedResponse(idempotencyKey) { return { accepted: false, duplicate: false, idempotency_key: idempotencyKey }; }
