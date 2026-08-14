import assert from "node:assert/strict";
import test from "node:test";

import {
  HUMAN_AUTH_ABUSE_ERROR_CODES,
  HUMAN_AUTH_ABUSE_METRIC_KEYS,
  HUMAN_AUTH_RATE_LIMIT_OPERATIONS,
  HumanAuthAbuseControlError,
  createHumanAuthAbuseControls
} from "../src/human-auth/rate-limit.mjs";

const session = Object.freeze({
  session_id: "11111111-1111-4111-8111-111111111111",
  member_id: "22222222-2222-4222-8222-222222222222",
  organization_id: "33333333-3333-4333-8333-333333333333"
});

test("Human auth admission control consumes independent session/member/org PostgreSQL buckets", async () => {
  const calls = [];
  const controls = createHumanAuthAbuseControls({
    repository: {
      async acquireRateLimit(input) {
        calls.push(input);
        return { allowed: true, limit: input.capacity, remaining: input.capacity - 1, retryAfterMs: 0, resetAt: Date.now() };
      }
    }
  });

  const result = await controls.authorize({ operation: HUMAN_AUTH_RATE_LIMIT_OPERATIONS.webauthnBegin, session });
  assert.equal(result.allowed, true);
  assert.equal(calls.length, 3);
  assert.deepEqual(calls.map((call) => call.organizationId), [session.organization_id, session.organization_id, session.organization_id]);
  assert.deepEqual(calls.map((call) => call.principalType), ["human", "human", "human"]);
  assert.equal(new Set(calls.map((call) => call.principalId)).size, 3);
  assert.equal(calls.every((call) => call.principalId !== session.session_id && call.principalId !== session.member_id), true);
});

test("rate-limit denial is fail-closed with bounded Retry-After and no provider cause", async () => {
  const metrics = [];
  const controls = createHumanAuthAbuseControls({
    metrics: { increment(key, amount) { metrics.push([key, amount]); } },
    repository: {
      async acquireRateLimit() {
        return { allowed: false, limit: 8, remaining: 0, retryAfterMs: 9_999_999, resetAt: "2099-01-01T00:00:00.000Z" };
      }
    }
  });

  await assert.rejects(
    () => controls.authorize({ operation: HUMAN_AUTH_RATE_LIMIT_OPERATIONS.invitationAccept, session }),
    (error) => {
      assert.ok(error instanceof HumanAuthAbuseControlError);
      assert.equal(error.code, HUMAN_AUTH_ABUSE_ERROR_CODES.RATE_LIMITED);
      assert.equal(error.status, 429);
      assert.deepEqual(error.headers, { "Retry-After": "60", "Cache-Control": "no-store, max-age=0" });
      assert.equal(error.cause, undefined);
      assert.doesNotMatch(error.message, /password|top-secret|relation/i);
      assert.deepEqual(Object.keys(error).sort(), ["code", "headers", "name", "status"]);
      return true;
    }
  );
  assert.deepEqual(metrics, [[HUMAN_AUTH_ABUSE_METRIC_KEYS.rateLimitDenial, 1]]);
});

test("limiter outage fails closed and never falls back to process-local allowance", async () => {
  const metrics = [];
  const controls = createHumanAuthAbuseControls({
    metrics: { increment(key, amount) { metrics.push([key, amount]); } },
    repository: {
      async acquireRateLimit() {
        throw new Error("password=top-secret relation=private_rate_limit_buckets");
      }
    }
  });

  await assert.rejects(
    () => controls.authorize({ operation: HUMAN_AUTH_RATE_LIMIT_OPERATIONS.webauthnVerify, session }),
    (error) => {
      assert.equal(error.code, HUMAN_AUTH_ABUSE_ERROR_CODES.CONTROL_UNAVAILABLE);
      assert.equal(error.status, 503);
      assert.equal(error.cause, undefined);
      assert.doesNotMatch(error.message, /password|top-secret|private_rate_limit/i);
      return true;
    }
  );
  assert.deepEqual(metrics, [[HUMAN_AUTH_ABUSE_METRIC_KEYS.controlUnavailable, 1]]);
});

test("cross-tenant scope is denied before PostgreSQL and emits only an aggregate metric", async () => {
  let calls = 0;
  const metrics = [];
  const controls = createHumanAuthAbuseControls({
    metrics: { increment(key, amount) { metrics.push([key, amount]); } },
    repository: { async acquireRateLimit() { calls += 1; return { allowed: true }; } }
  });
  await assert.rejects(
    () => controls.authorize({ operation: HUMAN_AUTH_RATE_LIMIT_OPERATIONS.invitationList, session, organizationId: "44444444-4444-4444-8444-444444444444" }),
    (error) => error.code === HUMAN_AUTH_ABUSE_ERROR_CODES.TENANT_DENIED && error.status === 403
  );
  assert.equal(calls, 0);
  assert.deepEqual(metrics, [[HUMAN_AUTH_ABUSE_METRIC_KEYS.tenantDenial, 1]]);
});
