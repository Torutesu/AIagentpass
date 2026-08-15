import assert from "node:assert/strict";
import { Readable } from "node:stream";
import test from "node:test";

import { createCloudApi } from "../src/server.mjs";

const ISSUE_PATH = "/api/platform/v1/promotions";
const LEGACY_PATH = "/v1/platform/promotions";
const ORIGIN = "https://console.agentpass.test";

async function dispatch(server, { method = "POST", url = ISSUE_PATH, headers = {}, body = "" } = {}) {
  const request = Readable.from([Buffer.from(body)]);
  request.method = method;
  request.url = url;
  request.headers = headers;
  request.socket = { remoteAddress: "203.0.113.9" };
  return new Promise((resolve, reject) => {
    const response = {
      headersSent: false,
      statusCode: 200,
      headers: {},
      writeHead(status, values = {}) {
        this.statusCode = status;
        this.headers = { ...values };
        this.headersSent = true;
      },
      setHeader(name, value) { this.headers[name] = value; },
      end(value) { this.body = value; resolve(this); },
      destroy(error) { reject(error ?? new Error("response destroyed")); }
    };
    server.emit("request", request, response);
  });
}

function platformApi(calls, status = 218) {
  return {
    paths: { issue: ISSUE_PATH },
    async handle(request, response) {
      const chunks = [];
      for await (const chunk of request) chunks.push(Buffer.from(chunk));
      calls.push({
        method: request.method,
        url: request.url,
        headers: request.headers,
        body: Buffer.concat(chunks).toString("utf8")
      });
      response.writeHead(status, { "X-AgentPass-Platform": "authorized-boundary" });
      response.end(JSON.stringify({ ok: true }));
    }
  };
}

test("authorized Platform promotion API intercepts the raw request before Human auth", async () => {
  const platformCalls = [];
  const humanCalls = [];
  const server = createCloudApi({
    store: {},
    humanSession: {
      async authenticateRequest(input) {
        humanCalls.push(input);
        throw new Error("Human auth must not run for the authorized Platform boundary");
      }
    },
    platformPromotionHttpApi: platformApi(platformCalls),
    platformPromotionIssuanceService: {
      async issuePlatformPromotion() { throw new Error("legacy service must not run"); },
      async replayPlatformPromotion() { throw new Error("legacy service must not run"); }
    },
    platformOperatorAuthorizer: async () => ({ allowed: true, role: "platform_operator" })
  });
  const response = await dispatch(server, {
    url: `${ISSUE_PATH}?probe=raw-boundary`,
    headers: {
      origin: ORIGIN,
      cookie: "__Host-agentpass_platform_session=raw-platform-token",
      "content-type": "application/json"
    },
    body: '{"opaque":"body-preserved"}'
  });

  assert.equal(response.statusCode, 218);
  assert.equal(response.headers["X-AgentPass-Platform"], "authorized-boundary");
  assert.deepEqual(humanCalls, []);
  assert.equal(platformCalls.length, 1);
  assert.equal(platformCalls[0].method, "POST");
  assert.equal(platformCalls[0].url, `${ISSUE_PATH}?probe=raw-boundary`);
  assert.equal(platformCalls[0].headers.cookie, "__Host-agentpass_platform_session=raw-platform-token");
  assert.equal(platformCalls[0].body, '{"opaque":"body-preserved"}');
});

test("the authorized Platform promotion route is absent unless its HTTP API is injected", async () => {
  const humanCalls = [];
  const server = createCloudApi({
    store: {},
    humanSession: {
      async authenticateRequest(input) { humanCalls.push(input); return { session: {} }; }
    },
    recentAuthService: { async authorize() { throw new Error("recent auth must not run"); } }
  });
  const response = await dispatch(server, { url: ISSUE_PATH, body: "{}" });

  assert.equal(response.statusCode, 404);
  assert.deepEqual(JSON.parse(response.body).error, { code: "not_found", message: "Resource not found" });
  assert.deepEqual(humanCalls, []);
});

test("the injected boundary owns only paths.issue and does not widen the route surface", async () => {
  const calls = [];
  const server = createCloudApi({ store: {}, platformPromotionHttpApi: platformApi(calls) });

  const issue = await dispatch(server, { url: ISSUE_PATH, body: "{}" });
  const legacy = await dispatch(server, { url: LEGACY_PATH, body: "{}" });
  const unrelated = await dispatch(server, { url: "/api/platform/v1/promotions/replay", body: "{}" });

  assert.equal(issue.statusCode, 218);
  assert.equal(legacy.statusCode, 404);
  assert.equal(unrelated.statusCode, 404);
  assert.equal(calls.length, 1);
});

test("malformed authorized Platform HTTP API injection fails closed at construction", () => {
  for (const value of [
    null,
    [],
    {},
    { handle() {}, paths: {} },
    { handle() {}, paths: null },
    { handle() {}, paths: [] },
    { handle() {}, paths: { issue: "" } },
    { handle() {}, paths: { issue: "/v1/platform/promotions" } },
    { handle() {}, paths: { issue: `${ISSUE_PATH}/` } },
    { handle() {}, paths: { issue: `${ISSUE_PATH}?alternate=1` } },
    { handle() {}, paths: { issue: `https://evil.example${ISSUE_PATH}` } },
    { paths: { issue: ISSUE_PATH } }
  ]) {
    assert.throws(
      () => createCloudApi({ store: {}, platformPromotionHttpApi: value }),
      /platformPromotionHttpApi must expose handle\(\) and paths\.issue/u
    );
  }
});
