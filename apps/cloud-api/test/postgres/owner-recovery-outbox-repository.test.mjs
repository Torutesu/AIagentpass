import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  OWNER_RECOVERY_OUTBOX_ERROR_CODES,
  createPostgresOwnerRecoveryOutboxRepository
} from "../../src/postgres/owner-recovery-outbox-repository.mjs";

const ORG = "11111111-1111-4111-8111-111111111111";
const EVENT = "22222222-2222-4222-8222-222222222222";
const REQUEST = "33333333-3333-4333-8333-333333333333";
const MEMBER = "44444444-4444-4444-8444-444444444444";
const NOW = Date.parse("2026-08-14T00:00:00.000Z");
const CLAIM = Buffer.alloc(32, 7).toString("base64url");
const DELIVERY_BINDING = Object.freeze({ binding_id: "test-owner-recovery", key_version: 7, binding_digest: "a".repeat(64) });

test("claim uses SKIP LOCKED and sends only a claim digest to PostgreSQL", async () => {
  const client = new ScriptedClient((text) => {
    assert.match(text, /FOR UPDATE SKIP LOCKED/);
    assert.match(text, /SET status='uncertain'/);
    assert.match(text, /uncertain_reason='process_interrupted'/);
    assert.match(text, /attempts<=\$1/);
    assert.match(text, /attempts=LEAST\(outbox\.attempts\+1,\$1\)/);
    return { rowCount: 1, rows: [row()] };
  });
  const repository = createPostgresOwnerRecoveryOutboxRepository({ client, randomBytes: () => Buffer.alloc(32, 7), now: () => NOW });
  const result = await repository.claimBatch({ limit: 5, lease_ms: 30_000 });
  assert.equal(result.claim_token, CLAIM);
  assert.equal(result.events[0].event_id, EVENT);
  assert.deepEqual(client.calls[0].params.slice(0, 2), [100, 5]);
  assert.ok(Buffer.isBuffer(client.calls[0].params[2]));
  assert.equal(client.calls[0].params[2].toString("hex"), crypto.createHash("sha256").update(CLAIM).digest("hex"));
  assert.equal(client.calls[0].params.includes(CLAIM), false);
});

test("an expired attempt-100 lease is quarantined after process loss", async () => {
  const client = new ScriptedClient(() => ({ rowCount: 1, rows: [{ ...row(), attempts: 100 }] }));
  const repository = createPostgresOwnerRecoveryOutboxRepository({ client, randomBytes: () => Buffer.alloc(32, 7), now: () => NOW });
  const result = await repository.claimBatch({ limit: 1, lease_ms: 1_000 });
  assert.equal(result.events[0].attempt, 100);
  assert.match(client.calls[0].text, /LEAST\(outbox\.attempts\+1,\$1\)/);
});

test("claim filters and returns only the exact immutable provider binding", async () => {
  const client = new ScriptedClient((text, params) => {
    assert.match(text, /provider_binding_state='bound'/u);
    assert.match(text, /provider_binding_id=\$5/u);
    assert.deepEqual(params.slice(4), [DELIVERY_BINDING.binding_id, DELIVERY_BINDING.key_version, DELIVERY_BINDING.binding_digest]);
    return { rowCount: 1, rows: [{ ...row(), provider_binding_id: DELIVERY_BINDING.binding_id, provider_key_version: DELIVERY_BINDING.key_version, provider_binding_digest: DELIVERY_BINDING.binding_digest }] };
  });
  const repository = createPostgresOwnerRecoveryOutboxRepository({ client, deliveryBinding: DELIVERY_BINDING, randomBytes: () => Buffer.alloc(32, 7), now: () => NOW });
  const result = await repository.claimBatch({ limit: 1, lease_ms: 1_000 });
  assert.deepEqual(repository.binding, DELIVERY_BINDING);
  assert.deepEqual(result.events[0].provider_binding, DELIVERY_BINDING);
});

test("publish and retry are exact attempt plus claim-digest CAS operations", async () => {
  const client = new ScriptedClient((text) => {
    if (text.includes("status='published'")) return { rowCount: 1, rows: [{ published_at: new Date(NOW) }] };
    return { rowCount: 1, rows: [{ status: "pending", available_at: new Date(NOW + 2_000) }] };
  });
  const repository = createPostgresOwnerRecoveryOutboxRepository({ client, now: () => NOW });
  const published = await repository.markPublished({ organization_id: ORG, event_id: EVENT, attempt: 1, claim_token: CLAIM });
  assert.equal(published.published, true);
  assert.match(client.calls[0].text, /attempts=\$3 AND claim_token_digest=\$4/);
  assert.match(client.calls[0].text, /claim_expires_at>clock_timestamp\(\)/);
  const failed = await repository.markFailed({ organization_id: ORG, event_id: EVENT, attempt: 2, claim_token: CLAIM, error_code: "publish_timeout", retry_at: new Date(NOW + 2_000).toISOString() });
  assert.deepEqual(failed, { dead_letter: false, retry_at: new Date(NOW + 2_000).toISOString() });
  assert.equal(client.calls[1].params.includes("publish timeout secret"), false);
  assert.match(client.calls[1].text, /claim_expires_at>clock_timestamp\(\)/);
});

test("persists a fixed uncertain category and releases the live lease", async () => {
  const client = new ScriptedClient(() => ({ rowCount: 1, rows: [{ uncertain_at: new Date(NOW) }] }));
  const repository = createPostgresOwnerRecoveryOutboxRepository({ client, now: () => NOW });
  const result = await repository.markUncertain({ organization_id: ORG, event_id: EVENT, attempt: 1, claim_token: CLAIM });
  assert.deepEqual(result, { uncertain: true, uncertain_at: new Date(NOW).toISOString() });
  assert.match(client.calls[0].text, /SET status='uncertain'/);
  assert.match(client.calls[0].text, /uncertain_reason='delivery_unknown'/);
  assert.match(client.calls[0].text, /claim_token_digest=NULL,claim_expires_at=NULL/);
  assert.match(client.calls[0].text, /claim_expires_at>clock_timestamp\(\)/);
  assert.equal(client.calls[0].params.some((value) => typeof value === "string" && value.includes("provider")), false);
});

test("attempt 100 transitions to dead-letter without accepting a retry timestamp", async () => {
  const client = new ScriptedClient(() => ({ rowCount: 1, rows: [{ status: "dead_letter", available_at: new Date(NOW) }] }));
  const repository = createPostgresOwnerRecoveryOutboxRepository({ client, now: () => NOW });
  const result = await repository.markFailed({ organization_id: ORG, event_id: EVENT, attempt: 100, claim_token: CLAIM, error_code: "publisher_unavailable" });
  assert.deepEqual(result, { dead_letter: true, retry_at: null });
});

test("stale claims and database diagnostics become stable secret-free errors", async () => {
  const lost = createPostgresOwnerRecoveryOutboxRepository({ client: new ScriptedClient(() => ({ rowCount: 0, rows: [] })), now: () => NOW });
  await assert.rejects(() => lost.markPublished({ organization_id: ORG, event_id: EVENT, attempt: 1, claim_token: CLAIM }), (error) => error.code === OWNER_RECOVERY_OUTBOX_ERROR_CODES.CLAIM_LOST && !error.message.includes(CLAIM));
  const failed = createPostgresOwnerRecoveryOutboxRepository({ client: new ScriptedClient(() => { throw new Error("postgres password=secret"); }), now: () => NOW });
  await assert.rejects(() => failed.claimBatch(), (error) => error.code === OWNER_RECOVERY_OUTBOX_ERROR_CODES.UNAVAILABLE && !error.message.includes("password"));
});

test("health returns aggregate backlog only", async () => {
  const client = new ScriptedClient(() => ({ rowCount: 1, rows: [{ pending: "3", uncertain: "2", dead_letter: "1", oldest_pending_at: new Date(NOW) }] }));
  const repository = createPostgresOwnerRecoveryOutboxRepository({ client, now: () => NOW });
  assert.deepEqual(await repository.health(), { pending: 3, uncertain: 2, dead_letter: 1, oldest_pending_at: new Date(NOW).toISOString() });
});

function row() { return { organization_id: ORG, event_id: EVENT, request_id: REQUEST, subject_member_id: MEMBER, event_type: "recovery.request.created", attempts: 1, claim_expires_at: new Date(NOW + 30_000), created_at: new Date(NOW) }; }
class ScriptedClient {
  constructor(handler) { this.handler = handler; this.calls = []; }
  async query(text, params = []) { this.calls.push({ text, params }); return this.handler(text, params); }
}
