import assert from "node:assert/strict";
import test from "node:test";

import { createCloudApi } from "../src/server.mjs";

const OPTIONS_PATH = "/api/auth/webauthn/options";
const VERIFY_PATH = "/api/auth/webauthn/verify";
const SESSION_PATH = "/api/auth/session";
const REGISTRATION_OPTIONS_PATH = "/api/auth/webauthn/registration/options";
const REGISTRATION_VERIFY_PATH = "/api/auth/webauthn/registration/verify";
const decision = { allowed: true, limit: 20, remaining: 19, retryAfterSeconds: 0, resetAt: 1_800_000_000_000 };

async function startServer(t, options = {}) {
  const server = createCloudApi({
    store: {},
    now: () => 1_800_000_000_000,
    rateLimiter: options.rateLimiter ?? { acquire: () => ({ ...decision }) },
    admissionRateLimiter: options.admissionRateLimiter ?? { acquire: () => ({ ...decision }) },
    ...(options.humanAuthApi === undefined ? {} : { humanAuthApi: options.humanAuthApi })
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  options.assertServer?.(server);
  t.after(async () => new Promise((resolve) => server.close(resolve)));
  return `http://127.0.0.1:${server.address().port}`;
}

test("delegates only exact WebAuthn paths and preserves the adapter response contract", async (t) => {
  const calls = [];
  const base = await startServer(t, {
    humanAuthApi: {
      async handle(input) {
        calls.push(input);
        return {
          status: 201,
          body: { authorization_id: "99999999-9999-4999-8999-999999999999" },
          headers: { "X-Human-Auth": "forwarded", "Cache-Control": "no-store, max-age=0" }
        };
      }
    }
  });
  const headers = {
    cookie: "__Host-agentpass_session=session-token-value",
    origin: "https://console.agentpass.test",
    "agentpass-csrf": "csrf-token-value",
    "content-type": "application/json"
  };
  const requestBody = JSON.stringify({ organization_id: "11111111-1111-4111-8111-111111111111", operation: "device.enrollment.issue" });
  const response = await fetch(`${base}${OPTIONS_PATH}`, { method: "POST", headers, body: requestBody });
  assert.equal(response.status, 201);
  const responseText = await response.text();
  assert.deepEqual(JSON.parse(responseText), { authorization_id: "99999999-9999-4999-8999-999999999999" });
  assert.equal(response.headers.get("x-human-auth"), "forwarded");
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(responseText.includes(requestBody), false);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, "POST");
  assert.equal(calls[0].url, OPTIONS_PATH);
  assert.equal(calls[0].headers.cookie, headers.cookie);
  assert.equal(calls[0].headers.origin, headers.origin);
  assert.equal(calls[0].headers["agentpass-csrf"], headers["agentpass-csrf"]);
  assert.deepEqual(Buffer.from(calls[0].body).toString(), requestBody);

  const verifyResponse = await fetch(`${base}${VERIFY_PATH}`, { method: "POST", headers, body: requestBody });
  assert.equal(verifyResponse.status, 201);
  for (const path of [REGISTRATION_OPTIONS_PATH, REGISTRATION_VERIFY_PATH]) {
    const registrationResponse = await fetch(`${base}${path}`, { method: "POST", headers, body: requestBody });
    assert.equal(registrationResponse.status, 201);
  }
  assert.deepEqual(calls.map((call) => call.url), [OPTIONS_PATH, VERIFY_PATH, REGISTRATION_OPTIONS_PATH, REGISTRATION_VERIFY_PATH]);

  for (const suffix of ["/", "?ignored=1"]) {
    const rejected = await fetch(`${base}${OPTIONS_PATH}${suffix}`, { method: "POST", headers, body: requestBody });
    assert.equal(rejected.status, 404);
  }
  assert.equal(calls.length, 4);
});

test("routes the exact paths without a bearer token and retains human-auth rate limiting", async (t) => {
  const calls = [];
  const rateCalls = [];
  const base = await startServer(t, {
    humanAuthApi: { handle: async () => { calls.push(true); return { status: 200, body: { ok: true }, headers: {} }; } },
    rateLimiter: { acquire: (input) => { rateCalls.push(["principal", input]); return { ...decision }; } },
    admissionRateLimiter: { acquire: (input) => { rateCalls.push(["admission", input]); return { ...decision }; } }
  });
  const response = await fetch(`${base}${OPTIONS_PATH}`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { ok: true });
  assert.equal(calls.length, 1);
  assert.deepEqual(rateCalls.map(([kind]) => kind), ["admission", "principal"]);
  assert.equal(rateCalls[0][1].principalType, "human");
  assert.equal(rateCalls[1][1].principalType, "human");
  assert.equal(typeof rateCalls[0][1].principalId, "string");
  assert.equal(rateCalls[0][1].principalId, rateCalls[1][1].principalId);
});

test("delegates the exact session bootstrap path and preserves Set-Cookie", async (t) => {
  const calls = [];
  const cookie = `__Host-agentpass_session=${"A".repeat(43)}; Path=/; HttpOnly; Secure; SameSite=Strict`;
  const base = await startServer(t, { humanAuthApi: { async handle(input) { calls.push(input); return { status: 201, body: { session: { version: 1 }, csrf_token: "B".repeat(43) }, headers: { "Set-Cookie": cookie } }; } } });
  const response = await fetch(`${base}${SESSION_PATH}`, { method: "POST", headers: { origin: "https://console.agentpass.test", authorization: "Bearer server-only", "content-type": "application/json" }, body: "{}" });
  assert.equal(response.status, 201);
  assert.equal(response.headers.get("set-cookie"), cookie);
  assert.equal(calls[0].url, SESSION_PATH);
  assert.equal(calls[0].headers.authorization, "Bearer server-only");
});

test("bounds the human-auth body before invoking the adapter", async (t) => {
  let calls = 0;
  const base = await startServer(t, { humanAuthApi: { handle: async () => { calls += 1; return { status: 200, body: { ok: true }, headers: {} }; } } });
  const response = await fetch(`${base}${OPTIONS_PATH}`, { method: "POST", headers: { "content-type": "application/json" }, body: "x".repeat(64 * 1024 + 1) });
  assert.equal(response.status, 413);
  assert.equal((await response.json()).error.code, "request_too_large");
  assert.equal(calls, 0);
});

test("fails closed on adapter exceptions and malformed responses", async (t) => {
  for (const humanAuthApi of [
    { handle: async () => { throw new Error("request body should never be exposed"); } },
    { handle: async () => ({ status: "200", body: { ok: true }, headers: {} }) },
    { handle: async () => ({ status: 200, body: { ok: true }, headers: { "content-length": "3" } }) },
    { handle: async () => ({ status: 200, body: { ok: true }, headers: { "content-type": "text/html" } }) }
  ]) {
    const base = await startServer(t, { humanAuthApi });
    const response = await fetch(`${base}${VERIFY_PATH}`, { method: "POST", headers: { "content-type": "application/json" }, body: "sensitive-request-body" });
    assert.equal(response.status, 503);
    const body = await response.json();
    assert.deepEqual(body.error, { code: "human_auth_unavailable", message: "Human authentication is temporarily unavailable" });
    assert.equal(JSON.stringify(body).includes("sensitive-request-body"), false);
  }
});

test("keeps the existing server timeouts and does not expose the route when the adapter is absent", async (t) => {
  const base = await startServer(t, { assertServer: (server) => {
    assert.equal(server.requestTimeout, 15_000);
    assert.equal(server.headersTimeout, 10_000);
    assert.equal(server.keepAliveTimeout, 5_000);
  } });
  const response = await fetch(`${base}${OPTIONS_PATH}`, { method: "POST", headers: { authorization: "Bearer ap_owner_token_abcdefghijklmnopqrstuvwxyz" }, body: "{}" });
  assert.equal(response.status, 404);
  assert.equal((await response.json()).error.code, "not_found");
});
