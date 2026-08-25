import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  PLATFORM_SESSION_RATE_LIMIT_ERROR_CODES,
  PLATFORM_SESSION_RATE_LIMIT_KEY_SLOTS,
  PlatformSessionRateLimitError,
  createPlatformSessionRateLimiter,
  derivePlatformSessionRateLimitKeys
} from "../src/platform-session-rate-limit.mjs";

const BUCKET_SECRET = Buffer.alloc(32, 0x71);
const RAW_COOKIE = "platform-cookie-value-that-must-never-reach-the-backend";
const RAW_CSRF = "csrf-value-that-must-never-reach-the-backend";
const RAW_JTI = "jti-value-that-must-never-reach-the-backend";
const HASH = (value) => crypto.createHash("sha256").update(value, "utf8").digest("hex");

test("Platform Session limiter allows a request through bounded anonymous buckets for every phase", async () => {
  const calls = [];
  const limiter = createPlatformSessionRateLimiter({
    bucketSecret: BUCKET_SECRET,
    repository: {
      async acquireAnonymousRateLimit(input) {
        calls.push(input);
        return { allowed: true, limit: input.capacity, remaining: input.capacity - 1, retryAfterMs: 0, resetAt: Date.now() };
      }
    }
  });

  const result = await limiter.acquire({
    phase: "assertion",
    transportIdentity: "198.51.100.42",
    sessionMaterialHash: HASH(RAW_COOKIE),
    csrfTokenHash: HASH(RAW_CSRF),
    jtiHash: HASH(RAW_JTI),
    proofId: "11111111-1111-4111-8111-111111111111"
  });

  assert.equal(result.allowed, true);
  assert.equal(result.retryAfterSeconds, 0);
  assert.deepEqual(result.headers, {});
  assert.equal(calls.length, 6);
  assert.equal(new Set(calls.map(({ principalId }) => principalId)).size, calls.length);
  assert.equal(calls.every((input) => input.operation === "platform.session.assertion"), true);
  assert.equal(calls.every((input) => input.principalId.match(/^[0-9a-f-]{36}$/iu)), true);
  assert.equal(calls.every((input) => !Object.hasOwn(input, "organizationId")), true);
});

test("denial fails closed with bounded Retry-After and stops before attacker-selected dimensions", async () => {
  const calls = [];
  const limiter = createPlatformSessionRateLimiter({
    bucketSecret: BUCKET_SECRET,
    repository: {
      async acquireAnonymousRateLimit(input) {
        calls.push(input);
        return { allowed: false, limit: input.capacity, remaining: 0, retryAfterMs: 9_999_999, resetAt: Date.now() };
      }
    }
  });

  await assert.rejects(
    () => limiter.check({ phase: "challenge", transportIdentity: "untrusted-input", sessionMaterialHash: HASH(RAW_COOKIE) }),
    (error) => {
      assert.ok(error instanceof PlatformSessionRateLimitError);
      assert.equal(error.code, PLATFORM_SESSION_RATE_LIMIT_ERROR_CODES.RATE_LIMITED);
      assert.equal(error.status, 429);
      assert.deepEqual(error.headers, { "Retry-After": "60", "Cache-Control": "no-store, max-age=0" });
      assert.equal(error.cause, undefined);
      assert.doesNotMatch(error.message, /untrusted-input|platform-cookie|secret/i);
      return true;
    }
  );
  assert.equal(calls.length, 1);
});

test("limiter backend failure is a secret-free 503 and never falls back to process-local allowance", async () => {
  const limiter = createPlatformSessionRateLimiter({
    bucketSecret: BUCKET_SECRET,
    repository: {
      async acquireAnonymousRateLimit() {
        throw new Error(`password=${RAW_COOKIE} relation=private_rate_limit_buckets`);
      }
    }
  });

  await assert.rejects(
    () => limiter.acquire({ phase: "revoke", transportIdentity: "203.0.113.8" }),
    (error) => {
      assert.equal(error.code, PLATFORM_SESSION_RATE_LIMIT_ERROR_CODES.CONTROL_UNAVAILABLE);
      assert.equal(error.status, 503);
      assert.deepEqual(error.headers, { "Retry-After": "1", "Cache-Control": "no-store, max-age=0" });
      assert.equal(error.cause, undefined);
      assert.doesNotMatch(error.message, /password|private_rate_limit|platform-cookie/i);
      return true;
    }
  );
});

test("key derivation has a fixed upper bound and ignores arbitrary organization/challenge fields", () => {
  const maximum = 1 + Object.values(PLATFORM_SESSION_RATE_LIMIT_KEY_SLOTS).reduce((sum, count) => sum + count, 0);
  const ids = new Set();
  for (let index = 0; index < 2_000; index += 1) {
    const keys = derivePlatformSessionRateLimitKeys({
      bucketSecret: BUCKET_SECRET,
      phase: "assertion",
      transportIdentity: `transport-${index}`,
      sessionMaterialHash: HASH(`session-${index}`),
      csrfTokenHash: HASH(`csrf-${index}`),
      jtiHash: HASH(`jti-${index}`),
      proofId: `11111111-1111-4111-8111-${String(index % 10_000).padStart(12, "0")}`,
      organizationId: `organization-${index}`,
      challengeId: `challenge-${index}`
    });
    for (const key of keys) ids.add(key.principalId);
  }
  assert.equal(ids.size <= maximum, true);
  assert.equal(maximum, 321);
});

test("raw bearer, CSRF, and JTI material never appears in repository input", async () => {
  const calls = [];
  const limiter = createPlatformSessionRateLimiter({
    bucketSecret: BUCKET_SECRET,
    repository: {
      async acquireAnonymousRateLimit(input) {
        calls.push(input);
        return { allowed: true, limit: input.capacity, remaining: input.capacity - 1, retryAfterMs: 0, resetAt: Date.now() };
      }
    }
  });

  await limiter.acquire({
    phase: "revoke",
    transportIdentity: RAW_COOKIE,
    sessionMaterialHash: HASH(RAW_COOKIE),
    csrfTokenHash: HASH(RAW_CSRF),
    jtiHash: HASH(RAW_JTI),
    proofId: "22222222-2222-4222-8222-222222222222"
  });

  const backendText = JSON.stringify(calls);
  assert.doesNotMatch(backendText, new RegExp(RAW_COOKIE, "u"));
  assert.doesNotMatch(backendText, new RegExp(RAW_CSRF, "u"));
  assert.doesNotMatch(backendText, new RegExp(RAW_JTI, "u"));
  assert.equal(calls.every((input) => !Object.hasOwn(input, "sessionMaterialHash")), true);
  assert.equal(calls.every((input) => !Object.hasOwn(input, "csrfTokenHash")), true);
  assert.equal(calls.every((input) => !Object.hasOwn(input, "jtiHash")), true);
});
