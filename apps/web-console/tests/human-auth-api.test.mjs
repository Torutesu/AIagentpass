import assert from "node:assert/strict";
import test from "node:test";
import { createHumanAuthBridge } from "../lib/human-auth-api.mjs";

const env = Object.freeze({
  AGENTPASS_CLOUD_API_URL: "https://cloud.example.test",
});
const legacyEnv = Object.freeze({
  ...env,
  NODE_ENV: "test",
  AGENTPASS_ALLOW_LEGACY_SESSION_BOOTSTRAP: "true",
  AGENTPASS_CLOUD_TOKEN: "server-only-token",
  AGENTPASS_OPERATOR_USER_IDS: "operator-1",
});
const csrf = "B".repeat(43);
const sessionCookie = "__Host-agentpass_session=" + "A".repeat(43);

function request(path, { body = {}, headers = {}, method = "POST" } = {}) {
  return new Request(`https://console.example.test${path}`, { method, headers: { origin: "https://console.example.test", "content-type": "application/json", ...headers }, body: method === "POST" ? JSON.stringify(body) : undefined });
}

function bridge(fetchImpl, user = { userId: "operator-1" }, bridgeEnv = env) {
  return createHumanAuthBridge({ env: bridgeEnv, fetchImpl, getSiwcUser: async () => user });
}

test("bootstraps a Cloud session without exposing the service credential", async () => {
  const calls = [];
  const api = bridge(async (url, init) => {
    calls.push({ url: String(url), init });
    return new Response(JSON.stringify({ session: { version: 1 }, csrf_token: "B".repeat(43) }), { status: 201, headers: { "content-type": "application/json", "set-cookie": `${sessionCookie}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600` } });
  }, undefined, legacyEnv);
  const response = await api.handle(request("/api/auth/session"));
  assert.equal(response.status, 201);
  assert.equal(response.headers.get("set-cookie"), `${sessionCookie}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600`);
  assert.equal(calls[0].url, "https://cloud.example.test/api/auth/session");
  assert.equal(calls[0].init.headers.get("authorization"), "Bearer server-only-token");
  assert.equal(calls[0].init.headers.get("agentpass-console-user-id"), "operator-1");
  assert.doesNotMatch(await response.text(), /server-only-token/);
});

test("does not reuse a stale browser session cookie during bootstrap", async () => {
  const calls = [];
  const replacement = "__Host-agentpass_session=" + "C".repeat(43);
  const api = bridge(async (url, init) => {
    calls.push({ url: String(url), init });
    return new Response(JSON.stringify({ session: { version: 1 }, csrf_token: csrf }), { status: 201, headers: { "content-type": "application/json", "set-cookie": `${replacement}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600` } });
  }, undefined, legacyEnv);
  const response = await api.handle(request("/api/auth/session", { headers: { cookie: sessionCookie } }));
  assert.equal(response.status, 201);
  assert.equal(calls[0].init.headers.has("cookie"), false);
  assert.equal(response.headers.get("set-cookie"), `${replacement}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600`);
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
  assert.equal(calls[0].init.headers.has("authorization"), false);
  assert.equal(calls[0].init.headers.has("agentpass-console-user-id"), false);
  assert.equal(calls[0].init.headers.has("oai-authenticated-user-email"), false);
  assert.equal(response.headers.get("cache-control"), "no-store, max-age=0");
  assert.equal(calls[0].init.cache, "no-store");
  assert.equal(calls[0].init.redirect, "error");
});

test("uses the Cloud human session as the sole membership binding for protected routes", async () => {
  const calls = [];
  const api = createHumanAuthBridge({
    env,
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init });
      return new Response(JSON.stringify({ credentials: [] }), { headers: { "content-type": "application/json" } });
    },
    getSiwcUser: async () => { throw new Error("SIWC must not be consulted after session bootstrap"); }
  });
  const response = await api.handle(request("/api/auth/security/passkeys", { method: "GET", headers: { cookie: sessionCookie, "agentpass-csrf": csrf } }));
  assert.equal(response.status, 200);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].init.headers.has("authorization"), false);
  assert.equal(calls[0].init.headers.has("agentpass-console-user-id"), false);
});

test("forwards passkey registration through the same-origin BFF without exposing the Cloud token", async () => {
  const calls = [];
  const api = bridge(async (url, init) => {
    calls.push({ url: String(url), init });
    return new Response(JSON.stringify({ credential_id: "A".repeat(22), registered_at: "2026-08-12T10:00:00.000Z" }), { status: 201, headers: { "content-type": "application/json" } });
  });
  const response = await api.handle(request("/api/auth/webauthn/registration/verify", {
    body: { organization_id: "org", challenge_id: "challenge-id", credential: { id: "opaque-to-bff" } },
    headers: { cookie: sessionCookie, "agentpass-csrf": csrf },
  }));
  assert.equal(response.status, 201);
  const responseText = await response.text();
  assert.deepEqual(JSON.parse(responseText), { credential_id: "A".repeat(22), registered_at: "2026-08-12T10:00:00.000Z" });
  assert.equal(calls[0].url, "https://cloud.example.test/api/auth/webauthn/registration/verify");
  assert.equal(calls[0].init.headers.has("authorization"), false);
  assert.equal(calls[0].init.headers.get("cookie"), sessionCookie);
  assert.equal(calls[0].init.headers.get("agentpass-csrf"), csrf);
  assert.equal(calls[0].init.headers.has("agentpass-console-user-id"), false);
  assert.doesNotMatch(responseText, /server-only-token|opaque-to-bff/);
});

test("rejects cross-origin, missing SIWC, non-operators, and missing CSRF before Cloud", async () => {
  let calls = 0;
  const fetchImpl = async () => { calls += 1; return new Response("{}"); };
  const crossOrigin = request("/api/auth/session", { headers: { origin: "https://evil.test" } });
  assert.equal((await bridge(fetchImpl).handle(crossOrigin)).status, 403);
  assert.equal((await bridge(fetchImpl, null, legacyEnv).handle(request("/api/auth/session"))).status, 401);
  assert.equal((await bridge(fetchImpl, { userId: "other" }, legacyEnv).handle(request("/api/auth/session"))).status, 403);
  assert.equal((await bridge(fetchImpl).handle(request("/api/auth/webauthn/verify", { headers: { cookie: sessionCookie } }))).status, 403);
  assert.equal(calls, 0);
});

test("requires an exact Origin and opaque CSRF token before forwarding", async () => {
  let calls = 0;
  const api = bridge(async () => { calls += 1; return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } }); });
  const base = { body: { organization_id: "org", operation: "device.enrollment.issue" }, headers: { cookie: sessionCookie, "agentpass-csrf": csrf } };
  assert.equal((await api.handle(request("/api/auth/webauthn/options", { ...base, headers: { ...base.headers, origin: "null" } }))).status, 403);
  const missingOrigin = new Request("https://console.example.test/api/auth/webauthn/options", { method: "POST", headers: { "content-type": "application/json", cookie: sessionCookie, "agentpass-csrf": csrf }, body: JSON.stringify(base.body) });
  assert.equal((await api.handle(missingOrigin)).status, 403);
  assert.equal((await api.handle(request("/api/auth/webauthn/options", { ...base, headers: { ...base.headers, "agentpass-csrf": "short" } }))).status, 403);
  assert.equal(calls, 0);
});

test("rejects redirects, malformed cookies, oversized responses, and unexpected Set-Cookie", async () => {
  const badCookie = await bridge(async () => new Response("{}", { headers: { "content-type": "application/json" } })).handle(request("/api/auth/webauthn/options", { headers: { cookie: "x".repeat(8193), "agentpass-csrf": csrf } }));
  assert.equal(badCookie.status, 400);
  const badSetCookie = await bridge(async () => new Response("{}", { headers: { "content-type": "application/json", "set-cookie": "other=value" } }), undefined, legacyEnv).handle(request("/api/auth/session"));
  assert.equal(badSetCookie.status, 502);
  const oversized = await bridge(async () => new Response(JSON.stringify({ value: "x".repeat(300_000) }), { headers: { "content-type": "application/json" } }), undefined, legacyEnv).handle(request("/api/auth/session"));
  assert.equal(oversized.status, 502);
});

test("does not forward unrelated or duplicate session cookies and rejects upstream redirects", async () => {
  const calls = [];
  const api = bridge(async (url, init) => {
    calls.push({ url: String(url), init });
    return new Response(JSON.stringify({ session: {} }), { status: 200, headers: { "content-type": "application/json" } });
  });
  const forwarded = await api.handle(request("/api/auth/webauthn/options", {
    body: { organization_id: "org", operation: "device.enrollment.issue" },
    headers: { cookie: `tracking=secret; ${sessionCookie}`, "agentpass-csrf": csrf }
  }));
  assert.equal(forwarded.status, 200);
  assert.equal(calls[0].init.headers.get("cookie"), sessionCookie);

  const duplicate = await api.handle(request("/api/auth/webauthn/options", {
    body: { organization_id: "org", operation: "device.enrollment.issue" },
    headers: { cookie: `${sessionCookie}; ${sessionCookie}`, "agentpass-csrf": csrf }
  }));
  assert.equal(duplicate.status, 400);

  const redirected = await bridge(async () => new Response("{}", { status: 302, headers: { "content-type": "application/json", location: "https://evil.example" } })).handle(request("/api/auth/webauthn/options", {
    body: { organization_id: "org", operation: "device.enrollment.issue" },
    headers: { cookie: sessionCookie, "agentpass-csrf": csrf }
  }));
  assert.equal(redirected.status, 502);
});

test("fails closed for legacy bootstrap in production", async () => {
  let calls = 0;
  const production = { ...legacyEnv, NODE_ENV: "production" };
  const response = await bridge(async () => { calls += 1; return new Response("{}", { headers: { "content-type": "application/json" } }); }, undefined, production).handle(request("/api/auth/session"));
  assert.equal(response.status, 503);
  assert.equal(calls, 0);
  assert.match(await response.text(), /legacy_session_bootstrap_disabled/);
});

test("does not enable legacy bootstrap when the deployment environment is unspecified", async () => {
  const response = await bridge(async () => new Response("{}", { headers: { "content-type": "application/json" } }), undefined, { ...legacyEnv, NODE_ENV: undefined }).handle(request("/api/auth/session"));
  assert.equal(response.status, 503);
});
