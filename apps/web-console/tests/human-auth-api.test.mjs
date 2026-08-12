import assert from "node:assert/strict";
import test from "node:test";
import { createHumanAuthBridge } from "../lib/human-auth-api.mjs";

const env = Object.freeze({
  AGENTPASS_CLOUD_API_URL: "https://cloud.example.test",
  AGENTPASS_CLOUD_TOKEN: "server-only-token",
  AGENTPASS_OPERATOR_USER_IDS: "operator-1",
});
const csrf = "csrf-token-in-browser-memory";
const sessionCookie = "__Host-agentpass_session=" + "A".repeat(43);

function request(path, { body = {}, headers = {}, method = "POST" } = {}) {
  return new Request(`https://console.example.test${path}`, { method, headers: { origin: "https://console.example.test", "content-type": "application/json", ...headers }, body: method === "POST" ? JSON.stringify(body) : undefined });
}

function bridge(fetchImpl, user = { userId: "operator-1" }) {
  return createHumanAuthBridge({ env, fetchImpl, getSiwcUser: async () => user });
}

test("bootstraps a Cloud session without exposing the service credential", async () => {
  const calls = [];
  const api = bridge(async (url, init) => {
    calls.push({ url: String(url), init });
    return new Response(JSON.stringify({ session: { version: 1 }, csrf_token: "B".repeat(43) }), { status: 201, headers: { "content-type": "application/json", "set-cookie": `${sessionCookie}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600` } });
  });
  const response = await api.handle(request("/api/auth/session"));
  assert.equal(response.status, 201);
  assert.equal(response.headers.get("set-cookie"), `${sessionCookie}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600`);
  assert.equal(calls[0].url, "https://cloud.example.test/api/auth/session");
  assert.equal(calls[0].init.headers.get("authorization"), "Bearer server-only-token");
  assert.equal(calls[0].init.headers.get("agentpass-console-user-id"), "operator-1");
  assert.doesNotMatch(await response.text(), /server-only-token/);
});

test("forwards only the session cookie and CSRF token to WebAuthn", async () => {
  const calls = [];
  const api = bridge(async (url, init) => {
    calls.push({ url: String(url), init });
    return new Response(JSON.stringify({ challenge_id: "11111111-1111-4111-8111-111111111111", options: {} }), { headers: { "content-type": "application/json" } });
  });
  const response = await api.handle(request("/api/auth/webauthn/options", { body: { organization_id: "org", operation: "device.enrollment.issue" }, headers: { cookie: sessionCookie, "agentpass-csrf": csrf } }));
  assert.equal(response.status, 200);
  assert.equal(calls[0].init.headers.get("cookie"), sessionCookie);
  assert.equal(calls[0].init.headers.get("agentpass-csrf"), csrf);
  assert.equal(calls[0].init.headers.has("oai-authenticated-user-email"), false);
  assert.equal(response.headers.get("cache-control"), "no-store, max-age=0");
});

test("rejects cross-origin, missing SIWC, non-operators, and missing CSRF before Cloud", async () => {
  let calls = 0;
  const fetchImpl = async () => { calls += 1; return new Response("{}"); };
  const crossOrigin = request("/api/auth/session", { headers: { origin: "https://evil.test" } });
  assert.equal((await bridge(fetchImpl).handle(crossOrigin)).status, 403);
  assert.equal((await bridge(fetchImpl, null).handle(request("/api/auth/session"))).status, 401);
  assert.equal((await bridge(fetchImpl, { userId: "other" }).handle(request("/api/auth/session"))).status, 403);
  assert.equal((await bridge(fetchImpl).handle(request("/api/auth/webauthn/verify", { headers: { cookie: sessionCookie } }))).status, 403);
  assert.equal(calls, 0);
});

test("rejects redirects, malformed cookies, oversized responses, and unexpected Set-Cookie", async () => {
  const badCookie = await bridge(async () => new Response("{}", { headers: { "content-type": "application/json" } })).handle(request("/api/auth/webauthn/options", { headers: { cookie: "x".repeat(8193), "agentpass-csrf": csrf } }));
  assert.equal(badCookie.status, 400);
  const badSetCookie = await bridge(async () => new Response("{}", { headers: { "content-type": "application/json", "set-cookie": "other=value" } })).handle(request("/api/auth/session"));
  assert.equal(badSetCookie.status, 502);
  const oversized = await bridge(async () => new Response(JSON.stringify({ value: "x".repeat(300_000) }), { headers: { "content-type": "application/json" } })).handle(request("/api/auth/session"));
  assert.equal(oversized.status, 502);
});
