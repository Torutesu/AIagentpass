import assert from "node:assert/strict";
import test from "node:test";

import {
  SHARED_CONTROL_REPOSITORY_METHODS,
  SHARED_CONTROL_SCHEMA,
  SharedControlRepositoryError,
  createSharedControlRepository,
  sha256
} from "../../src/postgres/shared-control-repository.mjs";

const organizationId = "11111111-1111-4111-8111-111111111111";
const memberId = "22222222-2222-4222-8222-222222222222";
const deviceId = "33333333-3333-4333-8333-333333333333";
const requestHash = "a".repeat(64);
const nonce = "N".repeat(32);

test("shared control repository exposes a stable, tenant-scoped wiring contract", () => {
  assert.deepEqual(SHARED_CONTROL_REPOSITORY_METHODS, [
    "withTransaction",
    "runIdempotent",
    "acquireIdempotency",
    "completeIdempotency",
    "abandonIdempotency",
    "consumeDeviceRequestNonce",
    "acquireRateLimit",
    "pruneExpired"
  ]);
  assert.deepEqual(SHARED_CONTROL_SCHEMA.tables, {
    idempotency: "idempotency_records",
    deviceRequestNonces: "device_request_nonces",
    rateLimitBuckets: "rate_limit_buckets"
  });
  assert.deepEqual(SHARED_CONTROL_SCHEMA.indexes, {
    idempotencyExpiry: "idempotency_records_expiry",
    deviceRequestNoncesExpiry: "device_request_nonces_expiry",
    rateLimitBucketsExpiry: "rate_limit_buckets_expiry"
  });
  assert.deepEqual(SHARED_CONTROL_SCHEMA.functions, {
    consumeDeviceRequestNonce: "agentpass_consume_device_request_nonce",
    acquireRateLimit: "agentpass_acquire_rate_limit",
    pruneExpired: "agentpass_prune_shared_control_expired"
  });
});

test("idempotency acquire is a transaction-safe insert/lock protocol and stores only safe response metadata", async () => {
  const client = new ScriptedClient((text) => {
    if (text.startsWith("DELETE FROM idempotency_records")) return { rowCount: 0, rows: [] };
    if (text.startsWith("INSERT INTO idempotency_records")) return { rowCount: 1, rows: [] };
    if (text.startsWith("SELECT request_hash,response_status")) return {
      rowCount: 1,
      rows: [{ request_hash: requestHash, response_status: 102, response_json: {}, expires_at: "2099-01-01T00:00:00.000Z" }]
    };
    if (text.startsWith("UPDATE idempotency_records")) return { rowCount: 1, rows: [] };
    throw new Error(`unexpected SQL: ${text}`);
  });
  const repository = createSharedControlRepository({ client });
  const acquired = await repository.acquireIdempotency({
    tx: client,
    organizationId,
    principalId: memberId,
    idempotencyKey: "mutation-0001",
    requestHash,
    ttlMs: 5_000
  });
  assert.deepEqual(acquired, { state: "new" });
  assert.match(client.calls[1].text, /ON CONFLICT \(organization_id,principal_id,idempotency_key\) DO NOTHING/);
  assert.match(client.calls[2].text, /FOR UPDATE/);
  assert.equal(client.calls[1].params[4], 5_000);

  const completed = await repository.completeIdempotency({
    tx: client,
    organizationId,
    principalId: memberId,
    idempotencyKey: "mutation-0001",
    requestHash,
    responseStatus: 201,
    response: { organization_id: organizationId, membership_id: memberId, session_id: "public-id-only" }
  });
  assert.deepEqual(completed, { completed: true });
  const update = client.calls.at(-1);
  assert.match(update.text, /response_status=\$4,response_json=\$5::jsonb/);
  assert.equal(update.params[4], JSON.stringify({ organization_id: organizationId, membership_id: memberId, session_id: "public-id-only" }));
  assert.equal(update.params.includes("mutation-0001"), true);
});

test("idempotency distinguishes replay, in-progress, and hash conflict without executing caller work", async () => {
  const cases = [
    { inserted: 0, row: { request_hash: requestHash, response_status: 201, response_json: { ok: true } }, expected: { state: "replay", responseStatus: 201, response: { ok: true } } },
    { inserted: 0, row: { request_hash: requestHash, response_status: 102, response_json: {} }, expected: { state: "in_progress" } },
    { inserted: 0, row: { request_hash: "b".repeat(64), response_status: 201, response_json: { ok: true } }, expected: { state: "conflict" } }
  ];
  for (const scenario of cases) {
    const client = new ScriptedClient((text) => {
      if (text.startsWith("DELETE FROM idempotency_records")) return { rowCount: 0, rows: [] };
      if (text.startsWith("INSERT INTO idempotency_records")) return { rowCount: scenario.inserted, rows: [] };
      if (text.startsWith("SELECT request_hash,response_status")) return { rowCount: 1, rows: [scenario.row] };
      throw new Error(`unexpected SQL: ${text}`);
    });
    const repository = createSharedControlRepository({ client });
    const result = await repository.acquireIdempotency({ tx: client, organizationId, principalId: memberId, idempotencyKey: "mutation-0002", requestHash });
    assert.deepEqual(result, scenario.expected);
  }
});

test("runIdempotent holds the idempotency record and mutation in one transaction across a pool", async () => {
  const tx = new ScriptedClient((text) => {
    if (text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK") return { rowCount: 0, rows: [] };
    if (text.startsWith("DELETE FROM idempotency_records")) return { rowCount: 0, rows: [] };
    if (text.startsWith("INSERT INTO idempotency_records")) return { rowCount: 1, rows: [] };
    if (text.startsWith("SELECT request_hash,response_status")) return { rowCount: 1, rows: [{ request_hash: requestHash, response_status: 102, response_json: {} }] };
    if (text.startsWith("UPDATE idempotency_records")) return { rowCount: 1, rows: [] };
    throw new Error(`unexpected SQL: ${text}`);
  });
  const pool = { async connect() { return { query: tx.query.bind(tx), release() { pool.released = true; } }; } };
  const repository = createSharedControlRepository({ client: pool });
  const result = await repository.runIdempotent({
    organizationId,
    principalId: memberId,
    idempotencyKey: "mutation-0003",
    requestHash,
    operation: async (transaction) => {
      assert.equal(typeof transaction.query, "function");
      return { responseStatus: 204, response: { accepted: true } };
    }
  });
  assert.deepEqual(result, { state: "committed", responseStatus: 204, response: { accepted: true } });
  assert.equal(pool.released, true);
  assert.deepEqual(tx.calls.map((call) => call.text === "BEGIN" ? "BEGIN" : call.text === "COMMIT" ? "COMMIT" : call.text.startsWith("UPDATE") ? "UPDATE" : call.text.startsWith("INSERT") ? "INSERT" : call.text.startsWith("SELECT") ? "SELECT" : call.text.startsWith("DELETE") ? "DELETE" : "other"), ["BEGIN", "DELETE", "INSERT", "SELECT", "UPDATE", "COMMIT"]);
});

test("runIdempotent rolls back when the mutation fails", async () => {
  const tx = new ScriptedClient((text) => {
    if (text === "BEGIN" || text === "ROLLBACK") return { rowCount: 0, rows: [] };
    if (text.startsWith("DELETE FROM idempotency_records")) return { rowCount: 0, rows: [] };
    if (text.startsWith("INSERT INTO idempotency_records")) return { rowCount: 1, rows: [] };
    if (text.startsWith("SELECT request_hash,response_status")) return { rowCount: 1, rows: [{ request_hash: requestHash, response_status: 102, response_json: {} }] };
    throw new Error(`unexpected SQL: ${text}`);
  });
  const repository = createSharedControlRepository({ client: tx });
  await assert.rejects(() => repository.runIdempotent({ organizationId, principalId: memberId, idempotencyKey: "mutation-0004", requestHash, operation: async () => { throw new Error("mutation failed"); } }), /mutation failed/);
  assert.equal(tx.calls.at(-1).text, "ROLLBACK");
});

test("device nonce consumption hashes the nonce and delegates one-shot atomicity to PostgreSQL", async () => {
  const client = new ScriptedClient((text) => {
    assert.match(text, /agentpass_consume_device_request_nonce/);
    return { rowCount: 1, rows: [{ accepted: true }] };
  });
  const repository = createSharedControlRepository({ client });
  const result = await repository.consumeDeviceRequestNonce({ organizationId, deviceId, nonce, ttlMs: 120_000 });
  assert.deepEqual(result, { accepted: true });
  assert.ok(Buffer.isBuffer(client.calls[0].params[2]));
  assert.equal(client.calls[0].params[2].toString("hex"), sha256(nonce).toString("hex"));
  assert.equal(client.calls[0].params.includes(nonce), false);
  assert.equal(client.calls[0].params[3], 120_000);
});

test("rate-limit acquisition is a distributed DB decision with stable response metadata", async () => {
  const resetAt = "2026-08-13T00:00:01.250Z";
  const client = new ScriptedClient((text) => {
    assert.match(text, /agentpass_acquire_rate_limit/);
    return { rowCount: 1, rows: [{ allowed: false, rate_limit: 120, remaining: 0, retry_after_ms: 1_250, reset_at: resetAt }] };
  });
  const repository = createSharedControlRepository({ client });
  const result = await repository.acquireRateLimit({ organizationId, principalType: "human", principalId: memberId, capacity: 120, refillPerSecond: 2, cost: 1, idleTtlMs: 900_000 });
  assert.deepEqual(result, { allowed: false, limit: 120, remaining: 0, retryAfterMs: 1_250, retryAfterSeconds: 2, resetAt: Date.parse(resetAt) });
  assert.deepEqual(client.calls[0].params, [organizationId, "human", memberId, 120, 2, 1, 900_000]);
});

test("expiry pruning is bounded and delegated to one shared maintenance function", async () => {
  const client = new ScriptedClient((text) => {
    assert.match(text, /agentpass_prune_shared_control_expired/);
    return { rowCount: 1, rows: [{ removed: "17" }] };
  });
  const repository = createSharedControlRepository({ client });
  assert.deepEqual(await repository.pruneExpired({ limit: 17 }), { removed: 17 });
  assert.deepEqual(client.calls[0].params, [17]);
});

test("database failures become constant public failures and never expose driver details", async () => {
  const client = new ScriptedClient(() => { throw new Error("password=top-secret relation details"); });
  const repository = createSharedControlRepository({ client });
  await assert.rejects(
    () => repository.consumeDeviceRequestNonce({ organizationId, deviceId, nonce }),
    (error) => {
      assert.ok(error instanceof SharedControlRepositoryError);
      assert.equal(error.code, "shared_control_unavailable");
      assert.equal(error.status, 503);
      assert.equal(error.message, "Shared control is temporarily unavailable");
      assert.equal(Object.keys(error).includes("cause"), false);
      assert.doesNotMatch(error.message, /top-secret|password/);
      return true;
    }
  );
});

test("input and idempotency response guards reject unscoped or sensitive material before SQL", async () => {
  const client = new ScriptedClient(() => ({ rowCount: 0, rows: [] }));
  const repository = createSharedControlRepository({ client });
  await assert.rejects(() => repository.consumeDeviceRequestNonce({ organizationId: "not-a-uuid", deviceId, nonce }), { code: "shared_control_invalid_request", status: 400 });
  await assert.rejects(() => repository.consumeDeviceRequestNonce({ organizationId, deviceId, nonce: "short" }), { code: "shared_control_invalid_request", status: 400 });
  await assert.rejects(() => repository.acquireRateLimit({ organizationId, principalType: "device", principalId: "not-a-uuid", capacity: 1, refillPerSecond: 1 }), { code: "shared_control_invalid_request", status: 400 });
  await assert.rejects(() => repository.completeIdempotency({ tx: client, organizationId, principalId: memberId, idempotencyKey: "mutation-0005", requestHash, responseStatus: 200, response: { access_token: "bearer" } }), { code: "shared_control_invalid_request", status: 400 });
  assert.equal(client.calls.length, 0);
});

test("sensitive data cannot be smuggled through a custom response object's prototype", async () => {
  const client = new ScriptedClient(() => ({ rowCount: 1, rows: [] }));
  const repository = createSharedControlRepository({ client });
  const response = Object.create(null);
  response.ok = true;
  await assert.rejects(repository.completeIdempotency({ tx: client, organizationId, principalId: memberId, idempotencyKey: "mutation-0006", requestHash, responseStatus: 200, response }), { code: "shared_control_invalid_request" });
});

class ScriptedClient {
  constructor(handler) {
    this.handler = handler;
    this.calls = [];
  }

  async query(text, params = []) {
    this.calls.push({ text, params });
    return this.handler(text, params);
  }
}
