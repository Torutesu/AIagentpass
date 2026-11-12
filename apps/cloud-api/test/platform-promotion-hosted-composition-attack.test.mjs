import assert from "node:assert/strict";
import { Readable } from "node:stream";
import test from "node:test";

import { createCloudApi } from "../src/server.mjs";

const ISSUE_PATH = "/api/platform/v1/promotions";

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
