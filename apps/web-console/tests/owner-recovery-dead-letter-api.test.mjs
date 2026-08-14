import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createHumanAuthBridge } from "../lib/human-auth-api.mjs";
import {
  createOwnerRecoveryDeadLetterClient,
  ownerRecoveryDeadLetterContextHash,
  OwnerRecoveryDeadLetterApiError,
} from "../lib/owner-recovery-dead-letter-api.mjs";

const ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111";
const EVENT_ID = "22222222-2222-4222-8222-222222222222";
const REQUEST_ID = "33333333-3333-4333-8333-333333333333";
const MEMBER_ID = "44444444-4444-4444-8444-444444444444";
const SESSION_ID = "55555555-5555-4555-8555-555555555555";
const RECENT_AUTH = "66666666-6666-4666-8666-666666666666";
const CSRF = "c".repeat(43);
const DATE = "2099-01-01T00:00:00.000Z";
const COOKIE = `__Host-agentpass_session=${"s".repeat(43)}`;

test("resource context hash matches the Cloud canonical binding", async () => {
  const canonical = JSON.stringify({
    action: "redrive",
    event_id: EVENT_ID,
    expected_management_version: 3,
    organization_id: ORGANIZATION_ID,
    version: 1,
  });
  const expected = crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
  assert.equal(await ownerRecoveryDeadLetterContextHash({
    organizationId: ORGANIZATION_ID,
    eventId: EVENT_ID,
    action: "redrive",
    expectedManagementVersion: 3,
  }), expected);
});

function session() {
  return {
    session: {
      session_id: SESSION_ID,
      member_id: MEMBER_ID,
      organization_id: ORGANIZATION_ID,
      role: "owner",
      created_at: DATE,
      expires_at: DATE,
      recent_auth_at: null,
    },
    csrf_token: CSRF,
  };
}

function deadLetter(overrides = {}) {
  return {
    organization_id: ORGANIZATION_ID,
    event_id: EVENT_ID,
    request_id: REQUEST_ID,
    subject_member_id: MEMBER_ID,
    event_type: "recovery.session.issued",
    status: "dead_letter",
    attempts: 5,
    total_attempts: 5,
    management_version: 3,
    redrive_count: 1,
    last_error_code: "provider_timeout",
    created_at: DATE,
    updated_at: DATE,
    suppressed_at: null,
    suppression_reason: null,
    ...overrides,
  };
}

function mutation(status = "pending", overrides = {}) {
  return {
    organization_id: ORGANIZATION_ID,
    event_id: EVENT_ID,
    status,
    attempts: status === "pending" ? 0 : 5,
    total_attempts: 5,
    management_version: 4,
    redrive_count: 2,
    suppressed_at: status === "suppressed" ? DATE : null,
    suppression_reason: status === "suppressed" ? "manual review" : null,
    ...overrides,
  };
}

function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json; charset=utf-8" } });
}

test("client lists dead letters with bounded pagination, session CSRF, and secret-free parsing", async () => {
  const calls = [];
  const client = createOwnerRecoveryDeadLetterClient({
    fetchImpl: async (path, init) => {
      calls.push({ path: String(path), init });
      if (String(path) === "/api/auth/session") return json(session(), 201);
      return json({ dead_letters: [deadLetter()], next_cursor: "next_cursor_1" });
    },
  });

  const result = await client.listDeadLetters(ORGANIZATION_ID, { limit: 10, cursor: "cursor_1" });
  assert.equal(result.items[0].eventId, EVENT_ID);
  assert.equal(result.items[0].lastErrorCode, "provider_timeout");
  assert.equal(result.nextCursor, "next_cursor_1");
  assert.equal(calls[1].path, `/api/auth/organizations/${ORGANIZATION_ID}/recovery-outbox/dead-letters?limit=10&cursor=cursor_1`);
  assert.equal(calls[1].init.method, "GET");
  assert.equal(calls[1].init.headers.get("agentpass-csrf"), CSRF);
  assert.equal(calls[1].init.headers.get("cookie"), null);
  assert.equal(calls[1].init.credentials, "same-origin");
  assert.equal(calls[1].init.body, undefined);
  assert.doesNotMatch(JSON.stringify(result), /token|private|secret|credential/i);
});

test("client sends operation-bound recent auth, If-Match, idempotency, and exact mutation bodies", async () => {
  const calls = [];
  const client = createOwnerRecoveryDeadLetterClient({
    fetchImpl: async (path, init) => {
      calls.push({ path: String(path), init });
      if (String(path) === "/api/auth/session") return json(session(), 201);
      if (String(path).endsWith("/redrive")) return json({ dead_letter: mutation("pending") });
      return json({ dead_letter: mutation("suppressed") });
    },
  });

  await client.redriveDeadLetter(ORGANIZATION_ID, EVENT_ID, 3, RECENT_AUTH, { idempotencyKey: "redrive-key-1" });
  await client.suppressDeadLetter(ORGANIZATION_ID, EVENT_ID, 4, "manual review", RECENT_AUTH, { idempotencyKey: "suppress-key-1" });

  assert.equal(calls[1].init.headers.get("agentpass-recent-auth"), RECENT_AUTH);
  assert.equal(calls[1].init.headers.get("if-match"), '"3"');
  assert.equal(calls[1].init.headers.get("idempotency-key"), "redrive-key-1");
  assert.deepEqual(JSON.parse(calls[1].init.body), {});
  assert.equal(calls[2].init.headers.get("if-match"), '"4"');
  assert.equal(calls[2].init.headers.get("idempotency-key"), "suppress-key-1");
  assert.deepEqual(JSON.parse(calls[2].init.body), { reason: "manual review" });
});

test("client rejects invalid bounds, unknown response fields, and cross-organization responses", async () => {
  const baseFetch = async (path) => String(path) === "/api/auth/session" ? json(session(), 201) : json({ dead_letters: [deadLetter({ extra: "secret" })], next_cursor: null });
  const client = createOwnerRecoveryDeadLetterClient({ fetchImpl: baseFetch });
  await assert.rejects(() => client.listDeadLetters(ORGANIZATION_ID, { limit: 101 }), (error) => error instanceof OwnerRecoveryDeadLetterApiError && error.code === "invalid_request");
  await assert.rejects(() => client.listDeadLetters(ORGANIZATION_ID, { cursor: "x".repeat(513) }), (error) => error instanceof OwnerRecoveryDeadLetterApiError && error.code === "invalid_request");
  await assert.rejects(() => client.listDeadLetters(ORGANIZATION_ID), (error) => error instanceof OwnerRecoveryDeadLetterApiError && error.code === "invalid_response");

  const crossTenant = createOwnerRecoveryDeadLetterClient({ fetchImpl: async (path) => String(path) === "/api/auth/session" ? json(session(), 201) : json({ dead_letters: [deadLetter({ organization_id: "77777777-7777-4777-8777-777777777777" })], next_cursor: null }) });
  await assert.rejects(() => crossTenant.listDeadLetters(ORGANIZATION_ID), (error) => error instanceof OwnerRecoveryDeadLetterApiError && error.code === "invalid_response");
});

test("client maps stable server errors without exposing upstream messages", async () => {
  const client = createOwnerRecoveryDeadLetterClient({ fetchImpl: async (path) => String(path) === "/api/auth/session" ? json(session(), 201) : json({ error: { code: "owner_recovery_outbox_management_version_conflict", message: "secret=must-not-leak" } }, 409) });
  await assert.rejects(() => client.redriveDeadLetter(ORGANIZATION_ID, EVENT_ID, 3, RECENT_AUTH, { idempotencyKey: "redrive-key-1" }), (error) => {
    assert.equal(error.code, "conflict");
    assert.equal(error.serverCode, "owner_recovery_outbox_management_version_conflict");
    assert.equal(error.message, "The recovery outbox item could not be changed");
    assert.doesNotMatch(error.message, /secret/);
    return true;
  });
});

test("Human BFF forwards the dead-letter routes with strict Origin, CSRF, recent auth, If-Match, and query validation", async () => {
  const calls = [];
  const bridge = createHumanAuthBridge({
    env: { AGENTPASS_CLOUD_API_URL: "https://cloud.example.test" },
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init });
      return json({ dead_letters: [], next_cursor: null });
    },
  });
  const headers = { origin: "https://console.example.test", cookie: COOKIE, "agentpass-csrf": CSRF };
  const list = await bridge.handle(new Request(`https://console.example.test/api/auth/organizations/${ORGANIZATION_ID}/recovery-outbox/dead-letters?limit=10&cursor=abc`, { headers }));
  assert.equal(list.status, 200);
  assert.equal(calls[0].url, `https://cloud.example.test/api/auth/organizations/${ORGANIZATION_ID}/recovery-outbox/dead-letters?limit=10&cursor=abc`);
  assert.equal(calls[0].init.headers.get("cookie"), COOKIE);
  assert.equal(calls[0].init.headers.get("agentpass-csrf"), CSRF);

  const mutation = await bridge.handle(new Request(`https://console.example.test/api/auth/organizations/${ORGANIZATION_ID}/recovery-outbox/dead-letters/${EVENT_ID}/redrive`, {
    method: "POST", headers: { ...headers, "content-type": "application/json", "content-length": "2", "idempotency-key": "redrive-key-1", "if-match": '"3"', "agentpass-recent-auth": RECENT_AUTH }, body: "{}",
  }));
  assert.equal(mutation.status, 200);
  assert.equal(calls[1].init.headers.get("agentpass-recent-auth"), RECENT_AUTH);
  assert.equal(calls[1].init.headers.get("if-match"), '"3"');
  assert.equal(calls[1].init.headers.get("idempotency-key"), "redrive-key-1");

  const suppress = await bridge.handle(new Request(`https://console.example.test/api/auth/organizations/${ORGANIZATION_ID}/recovery-outbox/dead-letters/${EVENT_ID}/suppress`, {
    method: "POST", headers: { ...headers, "content-type": "application/json", "idempotency-key": "suppress-key-1", "if-match": '"4"', "agentpass-recent-auth": RECENT_AUTH }, body: JSON.stringify({ reason: "manual review" }),
  }));
  assert.equal(suppress.status, 200);
  assert.equal(calls[2].init.headers.get("agentpass-recent-auth"), RECENT_AUTH);
  assert.equal(calls[2].init.headers.get("if-match"), '"4"');
  assert.equal(calls[2].init.headers.get("idempotency-key"), "suppress-key-1");
  assert.deepEqual(JSON.parse(new TextDecoder().decode(calls[2].init.body)), { reason: "manual review" });

  const badQuery = await bridge.handle(new Request(`https://console.example.test/api/auth/organizations/${ORGANIZATION_ID}/recovery-outbox/dead-letters?limit=101`, { headers }));
  assert.equal(badQuery.status, 400);
  const badOrigin = await bridge.handle(new Request(`https://console.example.test/api/auth/organizations/${ORGANIZATION_ID}/recovery-outbox/dead-letters`, { headers: { ...headers, origin: "https://evil.example" } }));
  assert.equal(badOrigin.status, 403);
});
