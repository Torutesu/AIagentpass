import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

import { createPlatformPromotionHttpApi } from "../src/platform-promotion-http-api.mjs";
import { PLATFORM_AUTHORIZED_PROMOTION_ISSUE_PATH, PLATFORM_PROMOTION_ISSUE_PATH } from "../src/platform-promotion-http-contract.mjs";
import { PLATFORM_SESSION_COOKIE_NAME, PLATFORM_SESSION_CSRF_HEADER } from "../src/platform-session-transport.mjs";
import { createCloudApi } from "../src/server.mjs";
import { startInMemoryHttpServer } from "../../../test/support/http-test-transport.mjs";

const ORIGIN = "https://console.agentpass.test";
const SESSION_COOKIE = `${PLATFORM_SESSION_COOKIE_NAME}=${"A".repeat(43)}`;
const CSRF = "B".repeat(43);
const PROOF_ID = "55555555-5555-4555-8555-555555555555";
const JTI = "77777777-7777-4777-8777-777777777777";
const ORGANIZATION_ID = "99999999-9999-4999-8999-999999999999";
const INPUT = {
  promotion_id: "11111111-1111-4111-8111-111111111111",
  deployment_id: "cloud-prod-2026-08",
  environment: "production",
  candidate_id: `release-pkg-sha256-v1-${"a".repeat(64)}`
};
const EVIDENCE = JSON.parse(fs.readFileSync(new URL("../../../contracts/fixtures/promotion-evidence-v3.valid.json", import.meta.url), "utf8"));
const LIMIT = { allowed: true, limit: 20, remaining: 19, retryAfterSeconds: 0, resetAt: 1_800_000_000_000 };

function publicPromotion(replayed = false) {
  return { ...INPUT, promotion_evidence: structuredClone(EVIDENCE), replayed };
}

async function start(t, options = {}) {
  const calls = { service: [] };
  const service = options.service ?? {
    async issuePlatformPromotion(input) { calls.service.push(["issue", input]); return publicPromotion(false); },
  };
  const platformPromotionHttpApi = createPlatformPromotionHttpApi({
    promotionService: service,
    rateLimiter: { acquire: () => ({ ...LIMIT }) },
    origin: ORIGIN,
    randomUUID: () => "88888888-8888-4888-8888-888888888888"
  });
  const server = createCloudApi({
    store: {},
    now: () => 1_800_000_000_000,
    platformPromotionHttpApi
  });
  startInMemoryHttpServer(server);
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => new Promise((resolve) => server.close(resolve)));
  return { base, calls };
}

function headers() {
  return {
    origin: ORIGIN,
    cookie: SESSION_COOKIE,
    [PLATFORM_SESSION_CSRF_HEADER]: CSRF,
    "agentpass-platform-proof-id": PROOF_ID,
    "agentpass-platform-jti": JTI,
    "idempotency-key": "platform-promotion-0001",
    "content-type": "application/json"
  };
}

test("issues through the authorized Platform promotion route and never the legacy route", async (t) => {
  const fixture = await start(t);
  const issue = await fetch(`${fixture.base}${PLATFORM_AUTHORIZED_PROMOTION_ISSUE_PATH}`, { method: "POST", headers: headers(), body: JSON.stringify({ operation: "platform.promotion.issue", organization_id: ORGANIZATION_ID, ...INPUT }) });
  assert.equal(issue.status, 201);
  const issued = await issue.json();
  assert.equal(issued.promotion.promotion_id, INPUT.promotion_id);
  assert.equal(issued.promotion.replayed, false);
  assert.equal(Object.hasOwn(issued, "claim_token"), false);
  assert.equal(Object.hasOwn(issued.promotion, "provider_diagnostics"), false);
  assert.equal(fixture.calls.service[0][1].idempotency_key, "platform-promotion-0001");
  assert.equal(fixture.calls.service[0][1].organization_id, ORGANIZATION_ID);

  const legacy = await fetch(`${fixture.base}${PLATFORM_PROMOTION_ISSUE_PATH}`, { method: "POST", headers: headers(), body: JSON.stringify(INPUT) });
  assert.equal(legacy.status, 404);
});

test("fails closed for malformed requests and private service responses", async (t) => {
  const malformed = await start(t, { service: { async issuePlatformPromotion() { return { ...publicPromotion(false), provider_diagnostics: { message: "secret" } }; }, async replayPlatformPromotion() { return null; } } });
  const malformedResponse = await fetch(`${malformed.base}${PLATFORM_AUTHORIZED_PROMOTION_ISSUE_PATH}`, { method: "POST", headers: headers(), body: JSON.stringify({ operation: "platform.promotion.issue", organization_id: ORGANIZATION_ID, ...INPUT, unexpected: true }) });
  assert.equal(malformedResponse.status, 400);
  assert.equal((await malformedResponse.json()).error.code, "platform_promotion_http_invalid_request");
  const privateResponse = await fetch(`${malformed.base}${PLATFORM_AUTHORIZED_PROMOTION_ISSUE_PATH}`, { method: "POST", headers: headers(), body: JSON.stringify({ operation: "platform.promotion.issue", organization_id: ORGANIZATION_ID, ...INPUT }) });
  assert.equal(privateResponse.status, 503);
  assert.equal((await privateResponse.json()).error.code, "platform_promotion_http_unavailable");
});

test("does not expose the authorized route without the exact injected boundary", () => {
  assert.throws(() => createCloudApi({ store: {}, platformPromotionHttpApi: { handle() {}, paths: { issue: "/v1/platform/promotions" } } }), /platformPromotionHttpApi must expose handle\(\) and paths\.issue/);
});
