import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import test from "node:test";

import { PLATFORM_SESSION_COOKIE_NAME, PLATFORM_SESSION_CSRF_HEADER } from "../src/platform-session-transport.mjs";
import { PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES, PlatformPromotionIssuanceError } from "../src/platform-promotion-issuance.mjs";
import { PLATFORM_SESSION_RATE_LIMIT_ERROR_CODES, PlatformSessionRateLimitError } from "../src/platform-session-rate-limit.mjs";

// W0-02 contract tests for the future createPlatformPromotionHttpApi.
//
// Expected constructor:
//   createPlatformPromotionHttpApi({ promotionService, rateLimiter, origin, maxBodyBytes })
//
// Expected request adapter:
//   api.handle({ method, url, headers, body })
//
// The service is the existing createPlatformAuthorizedPromotionService seam.
// It receives the exact ten-key object asserted below.  The HTTP boundary is
// responsible for transport parsing and must not become an authority source.
import { createPlatformPromotionHttpApi } from "../src/platform-promotion-http-api.mjs";

const ORIGIN = "https://console.agentpass.test";
const PATH = "/api/platform/v1/promotions";
const EVIDENCE = JSON.parse(fs.readFileSync(new URL("../../../contracts/fixtures/promotion-evidence-v3.valid.json", import.meta.url), "utf8"));
const IDS = Object.freeze({
  organization: "33333333-3333-4333-8333-333333333333",
  promotion: "11111111-1111-4111-8111-111111111111",
  proof: "55555555-5555-4555-8555-555555555555",
  jti: "77777777-7777-4777-8777-777777777777"
});
const PLATFORM_TOKEN = Buffer.alloc(32, 0x11).toString("base64url");
const CSRF_TOKEN = Buffer.alloc(32, 0x22).toString("base64url");
const IDEMPOTENCY_KEY = "platform-intent-1";
const CANDIDATE_ID = `release-pkg-sha256-v1-${"a".repeat(64)}`;
const RAW_ERROR_SECRET = "raw-internal-secret-must-not-cross-http";

const BODY = Object.freeze({
  operation: "platform.promotion.issue",
  organization_id: IDS.organization,
  promotion_id: IDS.promotion,
  deployment_id: "cloud-prod-2026-08",
  environment: "production",
  candidate_id: CANDIDATE_ID
});

const SERVICE_RESULT = Object.freeze({
  promotion_id: IDS.promotion,
  deployment_id: BODY.deployment_id,
  environment: BODY.environment,
  candidate_id: BODY.candidate_id,
  promotion_evidence: EVIDENCE,
  replayed: false
});

function sha256(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function platformCookie(token = PLATFORM_TOKEN) {
  return `${PLATFORM_SESSION_COOKIE_NAME}=${token}`;
}

function headers(overrides = {}) {
  return {
    Origin: ORIGIN,
    "Content-Type": "application/json",
    Cookie: platformCookie(),
    [PLATFORM_SESSION_CSRF_HEADER]: CSRF_TOKEN,
    "agentpass-platform-proof-id": IDS.proof,
    "agentpass-platform-jti": IDS.jti,
    "Idempotency-Key": IDEMPOTENCY_KEY,
    ...overrides
  };
}

function request({ method = "POST", url = PATH, body = BODY, requestHeaders = {}, omitHeaders = [] } = {}) {
  const requestHeadersValue = headers(requestHeaders);
  for (const name of omitHeaders) {
    for (const key of Object.keys(requestHeadersValue)) {
      if (key.toLowerCase() === name.toLowerCase()) delete requestHeadersValue[key];
    }
  }
  return {
    method,
    url,
    headers: requestHeadersValue,
    body: typeof body === "string" ? body : JSON.stringify(body)
  };
}

function fixture({ result = SERVICE_RESULT, serviceError = undefined, maxBodyBytes = 64 * 1024, rateLimiter = undefined } = {}) {
  const calls = [];
  const promotionService = {
    async issuePlatformPromotion(input) {
      calls.push(input);
      if (serviceError !== undefined) throw serviceError;
      return result;
    }
  };
  const api = createPlatformPromotionHttpApi({
    promotionService,
    rateLimiter: rateLimiter ?? { async acquire() { return { allowed: true }; } },
    origin: ORIGIN,
    maxBodyBytes
  });
  return { api, calls };
}

function assertSafeError(response, expectedStatus) {
  assert.equal(response.status, expectedStatus);
  assert.ok(response.body && typeof response.body === "object");
  assert.deepEqual(Object.keys(response.body), ["error"]);
  assert.ok(response.body.error && typeof response.body.error === "object");
  assert.deepEqual(Object.keys(response.body.error).sort(), ["code", "message"]);
  assert.equal(typeof response.body.error.code, "string");
  assert.equal(typeof response.body.error.message, "string");
  assert.equal(JSON.stringify(response.body).includes(RAW_ERROR_SECRET), false);
  assert.equal(JSON.stringify(response.body).includes(PLATFORM_TOKEN), false);
  assert.equal(JSON.stringify(response.body).includes(CSRF_TOKEN), false);
  assert.equal(JSON.stringify(response.body).includes(IDS.jti), false);
}

test("valid issue maps the exact browser envelope to the authorized service", async () => {
  const { api, calls } = fixture();
  const response = await api.handle(request());

  assert.equal(response.status, 201);
  assert.match(response.body.request_id, /^[0-9a-f-]{36}$/u);
  assert.deepEqual(response.body.promotion, SERVICE_RESULT);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0], {
    promotion_id: BODY.promotion_id,
    deployment_id: BODY.deployment_id,
    environment: BODY.environment,
    candidate_id: BODY.candidate_id,
    idempotency_key: IDEMPOTENCY_KEY,
    organization_id: BODY.organization_id,
    session_material_hash: sha256(PLATFORM_TOKEN),
    csrf_token: CSRF_TOKEN,
    proof_id: IDS.proof,
    jti: IDS.jti
  });
  assert.equal(JSON.stringify(calls[0]).includes(PLATFORM_TOKEN), false);
  assert.equal(Object.hasOwn(calls[0], "operation"), false);
});

test("successful issue is no-store and never returns transport authorization material", async () => {
  const { api } = fixture();
  const response = await api.handle(request());

  assert.equal(response.status, 201);
  assert.equal(response.headers["Cache-Control"], "no-store, max-age=0");
  assert.equal(JSON.stringify(response.body).includes(PLATFORM_TOKEN), false);
  assert.equal(JSON.stringify(response.body).includes(CSRF_TOKEN), false);
  assert.equal(JSON.stringify(response.body).includes(IDS.proof), false);
  assert.equal(JSON.stringify(response.body).includes(IDS.jti), false);
});

test("an exact durable retry returns 200 with the same safe projection", async () => {
  const replayed = Object.freeze({ ...SERVICE_RESULT, replayed: true });
  const { api } = fixture({ result: replayed });
  const response = await api.handle(request());
  assert.equal(response.status, 200);
  assert.deepEqual(response.body.promotion, replayed);
});

test("promotion admission uses only hashed transport dimensions and fails closed", async () => {
  const acquired = [];
  const allowed = fixture({
    rateLimiter: { async acquire(input) { acquired.push(input); return { allowed: true }; } }
  });
  assert.equal((await allowed.api.handle(request())).status, 201);
  assert.equal(acquired.length, 1);
  assert.equal(acquired[0].phase, "promotion");
  assert.equal(acquired[0].sessionMaterialHash, sha256(PLATFORM_TOKEN));
  assert.equal(acquired[0].csrfTokenHash, sha256(CSRF_TOKEN));
  assert.equal(acquired[0].jtiHash, sha256(IDS.jti));
  assert.equal(acquired[0].proofId, IDS.proof);
  assert.equal(JSON.stringify(acquired).includes(PLATFORM_TOKEN), false);
  assert.equal(JSON.stringify(acquired).includes(CSRF_TOKEN), false);
  assert.equal(JSON.stringify(acquired).includes(IDS.jti), false);

  const denied = fixture({
    rateLimiter: {
      async acquire() {
        throw new PlatformSessionRateLimitError(PLATFORM_SESSION_RATE_LIMIT_ERROR_CODES.RATE_LIMITED, { retryAfterSeconds: 9 });
      }
    }
  });
  const limited = await denied.api.handle(request());
  assertSafeError(limited, 429);
  assert.equal(limited.headers["Retry-After"], "9");
  assert.equal(denied.calls.length, 0);

  const failed = fixture({ rateLimiter: { async acquire() { throw new Error(RAW_ERROR_SECRET); } } });
  const unavailable = await failed.api.handle(request());
  assertSafeError(unavailable, 503);
  assert.equal(unavailable.headers["Retry-After"], "1");
  assert.equal(failed.calls.length, 0);
});

test("Human Session cookies cannot authenticate the promotion endpoint", async () => {
  const { api, calls } = fixture();
  const response = await api.handle(request({
    requestHeaders: {
      Cookie: "__Host-agentpass_session=human-session-token",
    }
  }));
  assertSafeError(response, 401);
  assert.equal(calls.length, 0);
});

test("a co-sent Human cookie is ignored when the Platform cookie is valid", async () => {
  const { api, calls } = fixture();
  const response = await api.handle(request({
    requestHeaders: {
      Cookie: `__Host-agentpass_session=${Buffer.alloc(32, 0x33).toString("base64url")}; ${platformCookie()}`
    }
  }));
  assert.equal(response.status, 201);
  assert.equal(calls.length, 1);
});

test("Authorization and authority headers are rejected before the service", async () => {
  const forbiddenHeaders = [
    "Authorization",
    "agentpass-principal-id",
    "agentpass-member-id",
    "agentpass-organization-id",
    "agentpass-assignment-id",
    "agentpass-authority-generation",
    "x-agentpass-principal-id",
    "x-agentpass-member-id",
    "x-agentpass-organization-id",
    "x-agentpass-assignment-id",
    "x-agentpass-authority-generation"
  ];

  for (const name of forbiddenHeaders) {
    const { api, calls } = fixture();
    const response = await api.handle(request({ requestHeaders: { [name]: "attacker-controlled" } }));
    assertSafeError(response, 400);
    assert.equal(calls.length, 0, name);
  }
});

test("the body is exactly six public fields and cannot carry authority or replay input", async () => {
  const invalidBodies = [
    { ...BODY, unexpected: true },
    { ...BODY, principal_id: "11111111-1111-4111-8111-111111111111" },
    { ...BODY, assignment_id: "44444444-4444-4444-8444-444444444444" },
    { ...BODY, authority_generation: 55 },
    { ...BODY, operation: "platform.promotion.replay" },
    { ...BODY, organization_id: undefined }
  ];

  for (const body of invalidBodies) {
    const { api, calls } = fixture();
    const response = await api.handle(request({ body }));
    assertSafeError(response, 400);
    assert.equal(calls.length, 0);
  }
});

test("duplicate JSON keys are rejected instead of being last-write-wins", async () => {
  const { api, calls } = fixture();
  const duplicate = JSON.stringify(BODY).replace(
    `"operation":"${BODY.operation}"`,
    `"operation":"${BODY.operation}","operation":"platform.promotion.replay"`
  );
  const response = await api.handle(request({ body: duplicate }));
  assertSafeError(response, 400);
  assert.equal(calls.length, 0);
});

test("duplicate platform cookies are rejected fail-closed", async () => {
  const { api, calls } = fixture();
  const response = await api.handle(request({
    requestHeaders: { Cookie: `${platformCookie()}; ${platformCookie()}` }
  }));
  assertSafeError(response, 400);
  assert.equal(calls.length, 0);
});

test("duplicate security headers are rejected before authentication", async () => {
  const { api, calls } = fixture();
  const duplicateHeaders = {
    forEach(callback) {
      for (const [name, value] of Object.entries(headers())) callback(value, name);
      callback(ORIGIN, "Origin");
    }
  };
  const response = await api.handle({
    method: "POST",
    url: PATH,
    headers: duplicateHeaders,
    body: JSON.stringify(BODY)
  });
  assertSafeError(response, 400);
  assert.equal(calls.length, 0);
});

test("query strings and replay paths are never accepted as issue requests", async () => {
  const { api, calls } = fixture();
  const query = await api.handle(request({ url: `${PATH}?replay=true` }));
  assertSafeError(query, 400);

  const replay = await api.handle(request({ url: `${PATH}/replay` }));
  assert.equal(replay.status, 404);
  assert.equal(calls.length, 0);
});

test("wrong, missing, and null origins are rejected", async () => {
  for (const origin of ["https://evil.example", "null"]) {
    const { api, calls } = fixture();
    const response = await api.handle(request({ requestHeaders: { Origin: origin } }));
    assertSafeError(response, 403);
    assert.equal(calls.length, 0);
  }
  const { api, calls } = fixture();
  const missing = await api.handle(request({ omitHeaders: ["Origin"] }));
  assertSafeError(missing, 403);
  assert.equal(calls.length, 0);
});

test("non-JSON content types and missing content types are rejected", async () => {
  for (const contentType of ["text/plain", "application/json-patch+json"]) {
    const { api, calls } = fixture();
    const requestHeaders = { "Content-Type": contentType };
    const response = await api.handle(request({ requestHeaders }));
    assertSafeError(response, 400);
    assert.equal(calls.length, 0);
  }
  const { api, calls } = fixture();
  const missing = await api.handle(request({ omitHeaders: ["Content-Type"] }));
  assertSafeError(missing, 400);
  assert.equal(calls.length, 0);
});

test("oversized bodies are rejected before the service", async () => {
  const { api, calls } = fixture({ maxBodyBytes: 128 });
  const response = await api.handle(request({ body: JSON.stringify({ ...BODY, deployment_id: "x".repeat(128) }) }));
  assertSafeError(response, 413);
  assert.equal(calls.length, 0);
});

test("missing or malformed proof transport cannot fall back to authority headers", async () => {
  for (const [name, value] of [
    ["agentpass-platform-proof-id", undefined],
    ["agentpass-platform-proof-id", "not-a-uuid"],
    ["agentpass-platform-jti", undefined],
    ["agentpass-platform-jti", "not-a-uuid"],
    [PLATFORM_SESSION_CSRF_HEADER, undefined],
    [PLATFORM_SESSION_CSRF_HEADER, "short-csrf"]
  ]) {
    const { api, calls } = fixture();
    const response = await api.handle(request({
      requestHeaders: value === undefined ? {} : { [name]: value },
      omitHeaders: value === undefined ? [name] : []
    }));
    assertSafeError(response, name === PLATFORM_SESSION_CSRF_HEADER ? 403 : 401);
    assert.equal(calls.length, 0);
  }
});

test("idempotency key is header-only and is not accepted in the body", async () => {
  const { api, calls } = fixture();
  const response = await api.handle(request({
    body: { ...BODY, idempotency_key: IDEMPOTENCY_KEY },
    omitHeaders: ["Idempotency-Key"]
  }));
  assertSafeError(response, 400);
  assert.equal(calls.length, 0);
});

test("service failures become safe HTTP errors without leaking internal messages", async () => {
  const { api, calls } = fixture({ serviceError: new Error(`database failure ${RAW_ERROR_SECRET}`) });
  const response = await api.handle(request());
  assertSafeError(response, 503);
  assert.equal(calls.length, 1);
});

test("stable issuance states map to conflict, in-progress, and no-blind-retry uncertainty errors", async () => {
  for (const [code, expectedCode] of [
    [PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.CONFLICT, "platform_promotion_http_idempotency_conflict"],
    [PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.IN_PROGRESS, "platform_promotion_http_in_progress"],
    [PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.UNCERTAIN, "platform_promotion_http_uncertain"]
  ]) {
    const { api } = fixture({ serviceError: new PlatformPromotionIssuanceError(code) });
    const response = await api.handle(request());
    assertSafeError(response, 409);
    assert.equal(response.body.error.code, expectedCode);
  }
});

test("a malformed service result is not serialized as a successful HTTP response", async () => {
  const { api, calls } = fixture({ result: { ...SERVICE_RESULT, claim_token: RAW_ERROR_SECRET } });
  const response = await api.handle(request());
  assertSafeError(response, 503);
  assert.equal(calls.length, 1);
});
