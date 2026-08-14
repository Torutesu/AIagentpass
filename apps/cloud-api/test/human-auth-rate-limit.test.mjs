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
  subject_bucket_id: "44444444-4444-4444-8444-444444444444",
  member_id: "22222222-2222-4222-8222-222222222222",
  organization_id: "33333333-3333-4333-8333-333333333333"
});
const BUCKET_SECRET = Buffer.alloc(32, 0x51);

test("Human auth admission control consumes independent session/member/org PostgreSQL buckets", async () => {
  const calls = [];
  const controls = createHumanAuthAbuseControls({
    bucketSecret: BUCKET_SECRET,
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
    bucketSecret: BUCKET_SECRET,
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
    bucketSecret: BUCKET_SECRET,
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
    bucketSecret: BUCKET_SECRET,
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

test("recovery exposes one stable limiter operation per route and check preserves fail-closed behavior", async () => {
  const recoveryOperations = [
    ["recoveryCreate", "human.recovery.create"],
    ["recoveryStatus", "human.recovery.status"],
    ["recoveryApprove", "human.recovery.approve"],
    ["recoveryCancel", "human.recovery.cancel"],
    ["recoveryExchange", "human.recovery.exchange"],
    ["recoveryRegistrationOptions", "human.recovery.registration.options"],
    ["recoveryRegistrationVerify", "human.recovery.registration.verify"],
    ["recoveryActivate", "human.recovery.activate"]
  ];
  assert.deepEqual(recoveryOperations.map(([name]) => HUMAN_AUTH_RATE_LIMIT_OPERATIONS[name]), recoveryOperations.map(([, operation]) => operation));

  const calls = [];
  const metricKeys = [];
  const controls = createHumanAuthAbuseControls({
    bucketSecret: BUCKET_SECRET,
    metrics: { increment(key, amount) { metricKeys.push([key, amount]); } },
    repository: {
      async acquireRateLimit(input) {
        calls.push(input);
        return { allowed: true, limit: input.capacity, remaining: input.capacity - 1, retryAfterMs: 0 };
      }
    }
  });
  const result = await controls.check({ operation: HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryRegistrationVerify, session });
  assert.equal(result.operation, "human.recovery.registration.verify");
  assert.equal(calls.length, 3);
  assert.deepEqual(metricKeys, [["human_recovery_registration_verify_total", 1]]);
  assert.strictEqual(controls.authorize, controls.check);
  assert.equal(controls.policies[HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryStatus].capacity, 60);
});

test("recovery operation counters are fixed-key and limiter outages remain fail-closed", async () => {
  const metrics = [];
  const controls = createHumanAuthAbuseControls({
    bucketSecret: BUCKET_SECRET,
    metrics: { increment(key, amount) { metrics.push([key, amount]); } },
    repository: { async acquireRateLimit() { throw new Error("provider secret must not escape"); } }
  });
  await assert.rejects(
    () => controls.check({ operation: HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryActivate, session }),
    (error) => error.code === HUMAN_AUTH_ABUSE_ERROR_CODES.CONTROL_UNAVAILABLE && error.cause === undefined
  );
  assert.deepEqual(metrics, [
    ["human_recovery_activate_total", 1],
    [HUMAN_AUTH_ABUSE_METRIC_KEYS.controlUnavailable, 1]
  ]);
  await assert.rejects(() => controls.check({ operation: "human.recovery.activate?organization_id=secret", session }), TypeError);
});

test("anonymous recovery exchange uses global then digest buckets without a tenant identifier", async () => {
  const calls = [];
  const controls = createHumanAuthAbuseControls({
    bucketSecret: BUCKET_SECRET,
    repository: {
      async acquireRateLimit() { throw new Error("tenant limiter must not be used"); },
      async acquireAnonymousRateLimit(input) {
        calls.push(input);
        return { allowed: true, limit: input.capacity, remaining: input.capacity - 1, retryAfterMs: 0 };
      }
    }
  });
  const principalId = "44444444-4444-4444-8444-444444444444";
  const result = await controls.checkAnonymous({ operation: HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryExchange, principalId });
  assert.equal(result.allowed, true);
  assert.equal(calls.length, 2);
  assert.match(calls[1].principalId, /^[0-9a-f-]{36}$/u);
  assert.notEqual(calls[1].principalId, principalId);
  assert.equal(calls.every((call) => !Object.hasOwn(call, "organizationId")), true);
  assert.equal(calls[0].capacity > calls[1].capacity, true);
});

test("anonymous global denial stops attacker-controlled bucket creation", async () => {
  const calls = [];
  const controls = createHumanAuthAbuseControls({
    bucketSecret: BUCKET_SECRET,
    repository: {
      async acquireRateLimit() { throw new Error("tenant limiter must not be used"); },
      async acquireAnonymousRateLimit(input) {
        calls.push(input);
        return { allowed: false, limit: input.capacity, remaining: 0, retryAfterMs: 1_000 };
      }
    }
  });
  await assert.rejects(
    () => controls.checkAnonymous({ operation: HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryExchange, principalId: "44444444-4444-4444-8444-444444444444" }),
    (error) => error.code === HUMAN_AUTH_ABUSE_ERROR_CODES.RATE_LIMITED
  );
  assert.equal(calls.length, 1);
});

test("session bootstrap uses one fixed anonymous global bucket before verified member and organization buckets", async () => {
  const anonymous = [];
  const identified = [];
  const controls = createHumanAuthAbuseControls({
    bucketSecret: BUCKET_SECRET,
    repository: {
      async acquireAnonymousRateLimit(input) {
        anonymous.push(input);
        return { allowed: true, limit: input.capacity, remaining: input.capacity - 1, retryAfterMs: 0 };
      },
      async acquireRateLimit(input) {
        identified.push(input);
        return { allowed: true, limit: input.capacity, remaining: input.capacity - 1, retryAfterMs: 0 };
      }
    }
  });
  const operation = HUMAN_AUTH_RATE_LIMIT_OPERATIONS.sessionBootstrap;
  assert.equal(operation, "human.session.bootstrap");
  await controls.checkAnonymousGlobal({ operation });
  await controls.checkAnonymousGlobal({ operation });
  await controls.checkIdentity({ operation, identity: session });
  assert.equal(anonymous.length, 2);
  assert.equal(new Set(anonymous.map(({ principalId }) => principalId)).size, 1);
  assert.equal(anonymous.every(({ operation: value }) => value === operation), true);
  assert.equal(identified.length, 3);
  assert.deepEqual(identified.map(({ organizationId }) => organizationId), [session.organization_id, session.organization_id, session.organization_id]);
  assert.equal(new Set(identified.map(({ principalId }) => principalId)).size, 3);
  assert.equal(identified.every(({ principalId }) => ![session.member_id, session.organization_id].includes(principalId)), true);
});

test("session bootstrap global denial prevents attacker-controlled bucket growth and identity work", async () => {
  const calls = [];
  const controls = createHumanAuthAbuseControls({
    bucketSecret: BUCKET_SECRET,
    repository: {
      async acquireAnonymousRateLimit(input) {
        calls.push(input);
        return { allowed: false, limit: input.capacity, remaining: 0, retryAfterMs: 2_000 };
      },
      async acquireRateLimit() { throw new Error("identity buckets must not be reached"); }
    }
  });
  await assert.rejects(
    () => controls.checkAnonymousGlobal({ operation: HUMAN_AUTH_RATE_LIMIT_OPERATIONS.sessionBootstrap }),
    (error) => error.code === HUMAN_AUTH_ABUSE_ERROR_CODES.RATE_LIMITED && error.headers["Retry-After"] === "2"
  );
  assert.equal(calls.length, 1);
  await assert.rejects(() => controls.checkAnonymousGlobal({ operation: HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryExchange }), TypeError);
  await assert.rejects(() => controls.checkIdentity({ operation: HUMAN_AUTH_RATE_LIMIT_OPERATIONS.webauthnBegin, identity: session }), TypeError);
});
