import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

import { createCloudApi } from "../src/server.mjs";

const ORIGIN = "https://console.agentpass.test";
const SESSION_COOKIE = `__Host-agentpass_session=${"A".repeat(43)}`;
const CSRF = "B".repeat(43);
const RECENT_AUTH = "55555555-5555-4555-8555-555555555555";
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
  const calls = { auth: [], recent: [], operator: [], service: [] };
  const service = options.service ?? {
    async issuePlatformPromotion(input) { calls.service.push(["issue", input]); return publicPromotion(false); },
    async replayPlatformPromotion(input) { calls.service.push(["replay", input]); return publicPromotion(true); }
  };
  const server = createCloudApi({
    store: {},
    now: () => 1_800_000_000_000,
    humanAuthOrigin: ORIGIN,
    humanSession: {
      async authenticateRequest(input) {
        calls.auth.push(input);
        if (input.headers.cookie !== SESSION_COOKIE) Object.assign(new Error("invalid"), { code: "invalid_session_cookie" });
        return { session: { session_id: "22222222-2222-4222-8222-222222222222", member_id: "33333333-3333-4333-8333-333333333333", organization_id: ORGANIZATION_ID, role: options.sessionRole ?? "viewer" } };
      }
    },
    recentAuthService: {
      async authorize(input) {
        calls.recent.push(input);
        return { verified: true, consumed: true, challenge_id: input.proof, member_id: input.principal.member_id, organization_id: input.organization_id, operation: input.operation, authenticated_at: 1_800_000_000_000, context_hash: input.context_hash };
      }
    },
    platformPromotionIssuanceService: service,
    platformOperatorAuthorizer: async (input) => {
      calls.operator.push(input);
      return options.operatorDecision ?? { allowed: true, role: "platform_operator", capability: input.capability };
    },
    rateLimiter: { acquire: () => ({ ...LIMIT }) },
    admissionRateLimiter: { acquire: () => ({ ...LIMIT }) }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => new Promise((resolve) => server.close(resolve)));
  return { base, calls };
}

function headers() {
  return {
    origin: ORIGIN,
    cookie: SESSION_COOKIE,
    "agentpass-csrf": CSRF,
    "agentpass-recent-auth": RECENT_AUTH,
    "idempotency-key": "platform-promotion-0001",
    "content-type": "application/json"
  };
}

test("issues and replays through the bounded platform-operator API", async (t) => {
  const fixture = await start(t);
  const issue = await fetch(`${fixture.base}/v1/platform/promotions`, { method: "POST", headers: headers(), body: JSON.stringify(INPUT) });
  assert.equal(issue.status, 201);
  const issued = await issue.json();
  assert.equal(issued.promotion.promotion_id, INPUT.promotion_id);
  assert.equal(issued.promotion.replayed, false);
  assert.equal(Object.hasOwn(issued, "claim_token"), false);
  assert.equal(Object.hasOwn(issued.promotion, "provider_diagnostics"), false);
  assert.equal(fixture.calls.auth[0].method, "POST");
  assert.equal(fixture.calls.auth[0].csrfToken, CSRF);
  assert.equal(fixture.calls.operator[0].capability, "platform.promotion.issue");
  assert.equal(fixture.calls.recent[0].operation, "platform.promotion.issue");
  assert.equal(fixture.calls.service[0][1].idempotency_key, "platform-promotion-0001");

  const replay = await fetch(`${fixture.base}/v1/platform/promotions/replay`, { method: "POST", headers: headers(), body: JSON.stringify(INPUT) });
  assert.equal(replay.status, 200);
  assert.equal((await replay.json()).promotion.replayed, true);
  assert.equal(fixture.calls.operator[1].capability, "platform.promotion.replay");
  assert.equal(fixture.calls.recent[1].operation, "platform.promotion.replay");
});

test("fails closed for organization roles and malformed or private responses", async (t) => {
  const denied = await start(t, { operatorDecision: { allowed: false, role: "platform_operator", capability: "platform.promotion.issue" } });
  const deniedResponse = await fetch(`${denied.base}/v1/platform/promotions`, { method: "POST", headers: headers(), body: JSON.stringify(INPUT) });
  assert.equal(deniedResponse.status, 403);
  assert.equal((await deniedResponse.json()).error.code, "platform_operator_denied");

  const malformed = await start(t, { service: { async issuePlatformPromotion() { return { ...publicPromotion(false), provider_diagnostics: { message: "secret" } }; }, async replayPlatformPromotion() { return null; } } });
  const malformedResponse = await fetch(`${malformed.base}/v1/platform/promotions`, { method: "POST", headers: headers(), body: JSON.stringify({ ...INPUT, unexpected: true }) });
  assert.equal(malformedResponse.status, 400);
  assert.equal((await malformedResponse.json()).error.code, "err_platform_promotion_http_request");
  const privateResponse = await fetch(`${malformed.base}/v1/platform/promotions`, { method: "POST", headers: headers(), body: JSON.stringify(INPUT) });
  assert.equal(privateResponse.status, 503);
  assert.equal((await privateResponse.json()).error.code, "platform_promotion_unavailable");
});

test("does not expose the route without an explicit platform operator authorizer", () => {
  assert.throws(() => createCloudApi({ store: {}, platformPromotionIssuanceService: { issuePlatformPromotion() {}, replayPlatformPromotion() {} } }), /platformOperatorAuthorizer is required/);
});
