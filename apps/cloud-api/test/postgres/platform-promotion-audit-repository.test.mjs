import assert from "node:assert/strict";
import test from "node:test";

import { createPostgresPlatformPromotionAuditRepository } from "../../src/postgres/platform-promotion-audit-repository.mjs";

const requestId = "11111111-1111-4111-8111-111111111111";
const targetId = "22222222-2222-4222-8222-222222222222";
const recordedAt = new Date("2026-08-20T00:00:00.000Z");
const base = Object.freeze({
  request_id: requestId,
  event_type: "platform.promotion.commit.committed",
  actor_id: "member-1",
  platform_role: "platform_operator",
  target_type: "platform_promotion",
  target_id: targetId,
  idempotency_key: "platform-audit-test-001",
  details: { deployment_id: "deployment-1", source_commit: "a".repeat(40) }
});

test("appends secret-free audit event and returns only bounded metadata", async () => {
  const calls = [];
  const repository = createPostgresPlatformPromotionAuditRepository({
    client: { async query(sql, params) { calls.push({ sql, params }); return { rowCount: 1, rows: [{ event_id: params[0], recorded_at: recordedAt }] }; } },
    now: () => recordedAt
  });
  const result = await repository.appendPlatformAuditEvent(base);
  assert.match(result.event_id, /^[0-9a-f-]{36}$/u);
  assert.equal(result.recorded_at, recordedAt);
  assert.equal(calls.length, 1);
  assert.match(calls[0].sql, /ON CONFLICT \(idempotency_key\) DO NOTHING/u);
  assert.ok(Buffer.isBuffer(calls[0].params[9]));
  assert.equal(calls[0].params[9].length, 32);
  assert.doesNotMatch(JSON.stringify(calls[0].params), /secret|token|authorization/iu);
});

test("uses the supplied transaction client for an atomic promotion audit append", async () => {
  const calls = [];
  const pool = { async query() { throw new Error("pool client must not be used"); } };
  const tx = { async query(sql, params) { calls.push({ sql, params }); return { rowCount: 1, rows: [{ event_id: params[0], recorded_at: recordedAt }] }; } };
  const repository = createPostgresPlatformPromotionAuditRepository({ client: pool, now: () => recordedAt });
  const result = await repository.appendPlatformAuditEvent({ ...base, tx });
  assert.match(result.event_id, /^[0-9a-f-]{36}$/u);
  assert.equal(calls.length, 1);
  assert.match(calls[0].sql, /INSERT INTO platform_promotion_audit_events/u);
});

test("rejects sensitive audit keys before touching the database", async () => {
  let called = false;
  const repository = createPostgresPlatformPromotionAuditRepository({ client: { async query() { called = true; } } });
  await assert.rejects(repository.appendPlatformAuditEvent({ ...base, details: { token: "never-store" } }), { code: "ERR_PLATFORM_AUDIT_INPUT" });
  assert.equal(called, false);
});

test("rejects an idempotency conflict when the stored hash differs", async () => {
  let count = 0;
  const repository = createPostgresPlatformPromotionAuditRepository({
    client: { async query(sql) { count += 1; return count === 1 ? { rowCount: 0, rows: [] } : { rowCount: 1, rows: [{ event_id: targetId, event_hash: "00".repeat(32) }] }; } },
    now: () => recordedAt
  });
  await assert.rejects(repository.appendPlatformAuditEvent(base), { code: "ERR_PLATFORM_AUDIT_CONFLICT" });
});

test("replays the same logical event idempotently despite a new generated event id and timestamp", async () => {
  let firstHash;
  let count = 0;
  const repository = createPostgresPlatformPromotionAuditRepository({
    client: { async query(sql, params) {
      count += 1;
      if (count === 1) { firstHash = params[9].toString("hex"); return { rowCount: 1, rows: [{ event_id: params[0], recorded_at: recordedAt }] }; }
      return { rowCount: 0, rows: [] };
    } },
    now: () => recordedAt
  });
  const first = await repository.appendPlatformAuditEvent(base);
  const replayingClient = {
    async query(sql, params) {
      if (sql.includes("INSERT INTO")) return { rowCount: 0, rows: [] };
      return { rowCount: 1, rows: [{ event_id: first.event_id, event_hash: firstHash }] };
    }
  };
  const replay = createPostgresPlatformPromotionAuditRepository({ client: replayingClient, now: () => new Date(recordedAt.getTime() + 1_000) });
  assert.deepEqual(await replay.appendPlatformAuditEvent(base), { idempotent: true, event_id: first.event_id });
});
