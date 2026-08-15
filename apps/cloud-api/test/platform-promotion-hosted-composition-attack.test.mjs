import assert from "node:assert/strict";
import fs from "node:fs";
import { Readable } from "node:stream";
import test from "node:test";

import { createCloudApi } from "../src/server.mjs";

const ISSUE_PATH = "/api/platform/v1/promotions";
const LEGACY_ISSUE_PATH = "/v1/platform/promotions";
const LEGACY_REPLAY_PATH = "/v1/platform/promotions/replay";

async function dispatch(server, url) {
  const request = Readable.from([Buffer.from("{}")]);
  request.method = "POST";
  request.url = url;
  request.headers = { origin: "https://console.agentpass.test", "content-type": "application/json" };
  return new Promise((resolve, reject) => {
    const response = {
      headersSent: false,
      statusCode: 200,
      headers: {},
      writeHead(status, values = {}) { this.statusCode = status; this.headers = { ...values }; this.headersSent = true; },
      setHeader(name, value) { this.headers[name] = value; },
      end(value) { this.body = value; resolve(this); },
      destroy(error) { reject(error ?? new Error("response destroyed")); }
    };
    server.emit("request", request, response);
  });
}

function authorizedApi(calls) {
  return {
    paths: { issue: ISSUE_PATH },
    async handle(request, response) {
      calls.push({ method: request.method, url: request.url });
      for await (const _chunk of request) {}
      response.writeHead(201, { "cache-control": "no-store" });
      response.end(JSON.stringify({ request_id: "authorized-boundary" }));
    }
  };
}

test("Hosted-style composition exposes only the authorized Platform boundary", async () => {
  const calls = [];
  const humanCalls = [];
  const recentAuthCalls = [];
  const server = createCloudApi({
    store: {},
    platformPromotionHttpApi: authorizedApi(calls),
    humanSession: {
      async authenticateRequest(input) { humanCalls.push(input); return { session: {} }; }
    },
    recentAuthService: {
      async authorize(input) { recentAuthCalls.push(input); return { verified: true }; }
    }
  });

  const authorized = await dispatch(server, ISSUE_PATH);
  const legacyIssue = await dispatch(server, LEGACY_ISSUE_PATH);
  const legacyReplay = await dispatch(server, LEGACY_REPLAY_PATH);

  assert.equal(authorized.statusCode, 201);
  assert.equal(legacyIssue.statusCode, 404);
  assert.equal(legacyReplay.statusCode, 404);
  assert.deepEqual(calls, [{ method: "POST", url: ISSUE_PATH }]);
  assert.deepEqual(humanCalls, []);
  assert.deepEqual(recentAuthCalls, []);
});

test("Human Session and recent-auth availability cannot resurrect Hosted legacy promotion routes", async () => {
  const humanCalls = [];
  const recentAuthCalls = [];
  const server = createCloudApi({
    store: {},
    humanSession: {
      async authenticateRequest(input) { humanCalls.push(input); return { session: { organization_id: "org" } }; }
    },
    recentAuthService: {
      async authorize(input) { recentAuthCalls.push(input); return { verified: true }; }
    }
  });

  for (const path of [ISSUE_PATH, LEGACY_ISSUE_PATH, LEGACY_REPLAY_PATH]) {
    const response = await dispatch(server, path);
    assert.equal(response.statusCode, 404, path);
  }
  assert.deepEqual(humanCalls, []);
  assert.deepEqual(recentAuthCalls, []);
});

test("evaluation-only legacy composition remains explicit and separate from the new route", async () => {
  const serviceCalls = [];
  const server = createCloudApi({
    store: {},
    platformPromotionIssuanceService: {
      async issuePlatformPromotion(input) { serviceCalls.push(["issue", input]); return { promotion_id: input.promotion_id, replayed: false }; },
      async replayPlatformPromotion(input) { serviceCalls.push(["replay", input]); return { promotion_id: input.promotion_id, replayed: true }; }
    },
    platformOperatorAuthorizer: async () => ({ allowed: true, role: "platform_operator", capability: "platform.promotion.issue" }),
    humanAuthOrigin: "https://console.agentpass.test",
    humanSession: { async authenticateRequest() { return { session: { member_id: "member", organization_id: "org", role: "owner" } }; } },
    recentAuthService: { async authorize() { return { verified: true, consumed: true }; } },
    rateLimiter: { acquire: () => ({ allowed: true, remaining: 1, limit: 2, retryAfterSeconds: 0, resetAt: Date.now() }) },
    admissionRateLimiter: { acquire: () => ({ allowed: true, remaining: 1, limit: 2, retryAfterSeconds: 0, resetAt: Date.now() }) }
  });

  const newRoute = await dispatch(server, ISSUE_PATH);
  assert.equal(newRoute.statusCode, 404);
  assert.equal(serviceCalls.length, 0);
});

test("Hosted runtime source declares the authorized HTTP composition seam", () => {
  const source = fs.readFileSync(new URL("../src/runtime.mjs", import.meta.url), "utf8");
  assert.ok(source.includes("createPlatformPromotionHttpApi"), "runtime must compose createPlatformPromotionHttpApi");
  assert.ok(source.includes("platformPromotionHttpApi"), "runtime must pass the authorized HTTP API to createCloudApi");
  assert.ok(source.includes("platformAuthorizationRepository"), "Hosted runtime must use the PostgreSQL authorized promotion repository");
});
