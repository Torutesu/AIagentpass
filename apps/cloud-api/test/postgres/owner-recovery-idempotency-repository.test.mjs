import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  OwnerRecoveryIdempotencyRepositoryError,
  createPostgresOwnerRecoveryIdempotencyRepository,
  sha256Digest
} from "../../src/postgres/owner-recovery-idempotency-repository.mjs";

const ORG = "11111111-1111-4111-8111-111111111111";
const MEMBER = "22222222-2222-4222-8222-222222222222";
const NOW = new Date("2026-08-14T12:00:00.000Z");
const KEY = "owner-recovery-idempotency-0001";
const DIGEST = sha256Digest("canonical-request");
const OWNER_TOKEN = Buffer.alloc(32, 0x41).toString("base64url");

class Client {
  constructor(handler) { this.handler = handler; this.calls = []; }
  async query(text, params = []) { this.calls.push({ text, params }); return this.handler(text, params, this.calls) ?? { rows: [], rowCount: 0 }; }
}

function input(overrides = {}) {
  return { organization_id: ORG, operation: "human.recovery.create", principal_id: MEMBER, idempotency_key: KEY, request_digest: DIGEST, ...overrides };
}

test("claims a durable digest-only record and never sends raw request material to PostgreSQL", async () => {
  const client = new Client((text) => text.startsWith("INSERT INTO owner_recovery_idempotency_records")
    ? { rows: [{ created_at: NOW, updated_at: NOW, expires_at: new Date(NOW.getTime() + 60_000) }], rowCount: 1 }
    : { rows: [], rowCount: 0 });
  const repository = createPostgresOwnerRecoveryIdempotencyRepository({ client, now: () => NOW, randomBytes: () => Buffer.alloc(32, 0x41), ttlMs: 60_000 });
  const result = await repository.claim(input());
  assert.equal(result.state, "claimed");
  assert.equal(result.owner_token, OWNER_TOKEN);
  const insert = client.calls.find(({ text }) => text.startsWith("INSERT INTO owner_recovery_idempotency_records"));
  assert.equal(Buffer.isBuffer(insert.params[4]), true);
  assert.equal(insert.params[4].toString("hex"), DIGEST);
  assert.equal(insert.params.includes("canonical-request"), false);
  assert.equal(insert.params.includes(OWNER_TOKEN), false);
});

test("classifies exact replay, payload conflict, and active in-progress claims", async () => {
  const responses = [
    { request_digest: Buffer.from(DIGEST, "hex"), lifecycle: "completed", response_status: 201, response_body: { request_id: ORG }, created_at: NOW, updated_at: NOW, expires_at: new Date(NOW.getTime() + 60_000) },
    { request_digest: crypto.randomBytes(32), lifecycle: "completed", response_status: 201, response_body: {}, created_at: NOW, updated_at: NOW, expires_at: new Date(NOW.getTime() + 60_000) },
    { request_digest: Buffer.from(DIGEST, "hex"), lifecycle: "in_progress", response_status: null, response_body: null, created_at: NOW, updated_at: NOW, expires_at: new Date(NOW.getTime() + 60_000) }
  ];
  for (const [index, expected] of ["replay", "conflict", "in_progress"].entries()) {
    const client = new Client((text) => text.startsWith("SELECT request_digest") ? { rows: [responses[index]], rowCount: 1 } : { rows: [], rowCount: 0 });
    const repository = createPostgresOwnerRecoveryIdempotencyRepository({ client, now: () => NOW, randomBytes: () => Buffer.alloc(32, 0x41), ttlMs: 60_000 });
    assert.equal((await repository.claim(input())).state, expected);
  }
});

test("completion is owner-token CAS and rejects secret-bearing response fields before SQL", async () => {
  const client = new Client((text) => text.startsWith("UPDATE owner_recovery_idempotency_records")
    ? { rows: [{ response_status: 200, response_body: { request_id: ORG }, created_at: NOW, updated_at: NOW, expires_at: new Date(NOW.getTime() + 60_000) }], rowCount: 1 }
    : { rows: [], rowCount: 0 });
  const repository = createPostgresOwnerRecoveryIdempotencyRepository({ client, now: () => NOW, ttlMs: 60_000 });
  const completed = await repository.complete({ ...input(), owner_token: OWNER_TOKEN, response_status: 200, response_body: { request_id: ORG } });
  assert.equal(completed.state, "completed");
  const update = client.calls.find(({ text }) => text.startsWith("UPDATE owner_recovery_idempotency_records"));
  assert.match(update.text, /claim_token_digest=\$9/u);
  assert.equal(Buffer.isBuffer(update.params[8]), true);
  await assert.rejects(
    repository.complete({ ...input(), owner_token: OWNER_TOKEN, response_status: 200, response_body: { recovery_session_token: "x".repeat(43) } }),
    (error) => error instanceof OwnerRecoveryIdempotencyRepositoryError && error.code === "secret_material"
  );
  assert.equal(client.calls.filter(({ text }) => text.startsWith("UPDATE owner_recovery_idempotency_records")).length, 1);
});

test("expired rows are reclaimable but active rows cannot be overwritten", async () => {
  const client = new Client((text) => text.startsWith("INSERT INTO owner_recovery_idempotency_records")
    ? { rows: [], rowCount: 0 }
    : text.startsWith("SELECT request_digest")
      ? { rows: [{ request_digest: Buffer.from(DIGEST, "hex"), lifecycle: "in_progress", response_status: null, response_body: null, created_at: NOW, updated_at: NOW, expires_at: new Date(NOW.getTime() + 60_000) }], rowCount: 1 }
      : { rows: [], rowCount: 0 });
  const repository = createPostgresOwnerRecoveryIdempotencyRepository({ client, now: () => NOW, randomBytes: () => Buffer.alloc(32, 0x41), ttlMs: 60_000 });
  assert.equal((await repository.claim(input())).state, "in_progress");
  const insert = client.calls.find(({ text }) => text.startsWith("INSERT INTO owner_recovery_idempotency_records"));
  assert.match(insert.text, /WHERE owner_recovery_idempotency_records\.expires_at <= EXCLUDED\.updated_at/u);
});
