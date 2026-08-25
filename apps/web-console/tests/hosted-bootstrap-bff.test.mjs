import assert from "node:assert/strict";
import { test } from "node:test";

import { createHostedBootstrapBff, handleHostedBootstrapRequest } from "../lib/hosted-bootstrap-bff.mjs";

const env = Object.freeze({
  AGENTPASS_CLOUD_API_URL: "https://cloud.example.test",
  AGENTPASS_CONSOLE_ORIGIN: "https://console.example.test"
});
const state = "S".repeat(43);
const bootstrap = "B".repeat(43);
const csrf = "C".repeat(43);
const session = "E".repeat(43);
const githubCookie = `__Host-agentpass_github_state=${state}`;
const bootstrapCookie = `__Host-agentpass_bootstrap=${bootstrap}`;
const idem = "organization-create-1";

function request(path, { method = "GET", headers = {}, body } = {}) {
  return new Request(`https://console.example.test${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
}

function response(body, status = 200, headers = {}) {
  return new Response(body === null ? null : JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}

function fetcher(fn) {
  const calls = [];
  return { calls, fetchImpl: async (url, init) => { calls.push({ url: String(url), init }); return fn(url, init); } };
}

test("forwards the six exact routes with only the minimum trust-boundary headers", async () => {
  const { calls, fetchImpl } = fetcher(async (url) => {
    if (String(url).endsWith("/github/start")) return new Response(null, { status: 302, headers: { location: "https://github.com/login/oauth/authorize?client_id=x&response_type=code&redirect_uri=https%3A%2F%2Fconsole.example.test%2Fapi%2Fauth%2Fbootstrap%2Fgithub%2Fcallback&scope=read%3Auser&state=${state}&code_challenge=x&code_challenge_method=S256", "set-cookie": `__Host-agentpass_github_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300` } });
    if (String(url).endsWith("/github/callback?code=code&state=state")) return new Response(null, { status: 303, headers: { location: "https://console.example.test/onboarding", "set-cookie": `__Host-agentpass_github_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0, __Host-agentpass_bootstrap=${bootstrap}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=900` } });
    return response({ version: 1, state: "organization_required", csrf_token: csrf, organization_count: 0, webauthn_required: false, can_create_first_organization: true, expires_at: "2026-08-15T00:00:00.000Z" });
  });
  const start = await handleHostedBootstrapRequest(request("/api/auth/bootstrap/github/start"), { env, fetchImpl });
  assert.equal(start.status, 302);
  assert.match(start.headers.get("location"), /^https:\/\/github\.com\//u);
  const status = await handleHostedBootstrapRequest(request("/api/auth/bootstrap/status", { headers: { origin: "https://console.example.test", cookie: `${bootstrapCookie}; browser=ignored` } }), { env, fetchImpl });
  assert.equal(status.status, 200);
  assert.equal(calls[1].init.headers.get("cookie"), bootstrapCookie);
  assert.equal(calls[1].init.headers.get("origin"), "https://console.example.test");
  assert.equal(calls[1].init.headers.has("authorization"), false);
  assert.equal(calls[1].init.headers.has("agentpass-bootstrap-csrf"), false);
});

test("preserves callback multiple Set-Cookie values and rejects open redirects", async () => {
  const cookieValues = [
    `__Host-agentpass_github_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
    `__Host-agentpass_bootstrap=${bootstrap}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=900`
  ];
  const callback = await handleHostedBootstrapRequest(request(`/api/auth/bootstrap/github/callback?code=abc&state=def`, { headers: { cookie: githubCookie } }), {
    env,
    fetchImpl: async () => new Response(null, { status: 303, headers: new Headers([["location", "https://console.example.test/onboarding"], ...cookieValues.map((value) => ["set-cookie", value])]) })
  });
  assert.equal(callback.status, 303);
  assert.deepEqual(callback.headers.getSetCookie(), cookieValues);
  const malicious = await handleHostedBootstrapRequest(request("/api/auth/bootstrap/github/start"), { env, fetchImpl: async () => new Response(null, { status: 302, headers: { location: "https://evil.example.test/steal" } }) });
  assert.equal(malicious.status, 502);
  assert.equal(malicious.headers.get("location"), null);
});

test("preserves the exact two cookies returned by successful WebAuthn verify", async () => {
  const cookies = [
    `__Host-agentpass_session=${session}; Path=/; HttpOnly; Secure; SameSite=Strict`,
    "__Host-agentpass_bootstrap=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"
  ];
  const verified = await handleHostedBootstrapRequest(request("/api/auth/bootstrap/webauthn/registration/verify", {
    method: "POST",
    headers: { origin: env.AGENTPASS_CONSOLE_ORIGIN, cookie: bootstrapCookie, "content-type": "application/json", "agentpass-bootstrap-csrf": csrf },
    body: { challenge_id: "challenge", credential: { id: "credential" } }
  }), {
    env,
    fetchImpl: async () => new Response(JSON.stringify({ version: 1, state: "completed", session: {}, csrf_token: csrf }), { status: 201, headers: new Headers([["content-type", "application/json"], ...cookies.map((value) => ["set-cookie", value])]) })
  });
  assert.equal(verified.status, 201);
  assert.deepEqual(verified.headers.getSetCookie(), cookies);
});

test("relays the callback error clear-state cookie while rejecting cookie injection elsewhere", async () => {
  const clearState = "__Host-agentpass_github_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
  const callbackError = await handleHostedBootstrapRequest(request("/api/auth/bootstrap/github/callback?code=bad&state=bad", { headers: { cookie: githubCookie } }), {
    env,
    fetchImpl: async () => new Response(JSON.stringify({ error: { code: "github_oauth_state_invalid", message: "ignored by BFF" } }), { status: 401, headers: new Headers([["content-type", "application/json"], ["set-cookie", clearState]]) })
  });
  assert.equal(callbackError.status, 401);
  assert.deepEqual(callbackError.headers.getSetCookie(), [clearState]);
  assert.deepEqual(await callbackError.json(), { error: { code: "github_oauth_state_invalid", message: "The GitHub OAuth attempt is invalid" } });

  const statusCookie = await handleHostedBootstrapRequest(request("/api/auth/bootstrap/status", { headers: { origin: env.AGENTPASS_CONSOLE_ORIGIN, cookie: bootstrapCookie } }), {
    env,
    fetchImpl: async () => new Response(JSON.stringify({ error: { code: "bootstrap_unavailable", message: "ignored" } }), { status: 503, headers: new Headers([["content-type", "application/json"], ["set-cookie", clearState]]) })
  });
  assert.equal(statusCookie.status, 502);
});

test("enforces exact methods, queries, origins, cookies, CSRF and idempotency", async () => {
  let calls = 0;
  let lastInit;
  const fetchImpl = async (_url, init) => { calls += 1; lastInit = init; return response({ ok: true }); };
  assert.equal((await handleHostedBootstrapRequest(request("/api/auth/bootstrap/status?extra=1", { headers: { origin: env.AGENTPASS_CONSOLE_ORIGIN, cookie: bootstrapCookie } }), { env, fetchImpl })).status, 400);
  assert.equal((await handleHostedBootstrapRequest(request("/api/auth/bootstrap/status", { method: "POST", headers: { origin: env.AGENTPASS_CONSOLE_ORIGIN, cookie: bootstrapCookie } }), { env, fetchImpl })).status, 405);
  assert.equal((await handleHostedBootstrapRequest(request("/api/auth/bootstrap/status", { headers: { origin: "https://evil.example.test", cookie: bootstrapCookie } }), { env, fetchImpl })).status, 403);
  const withoutBrowserOrigin = await handleHostedBootstrapRequest(request("/api/auth/bootstrap/status", { headers: { cookie: bootstrapCookie } }), { env, fetchImpl });
  assert.equal(withoutBrowserOrigin.status, 200);
  assert.equal(calls, 1);
  assert.equal(lastInit.headers.get("origin"), env.AGENTPASS_CONSOLE_ORIGIN);
  assert.equal((await handleHostedBootstrapRequest(request("/api/auth/bootstrap/organization", { method: "POST", headers: { cookie: bootstrapCookie, "content-type": "application/json", "agentpass-bootstrap-csrf": csrf, "idempotency-key": idem }, body: { name: "x" } }), { env, fetchImpl })).status, 403);
  assert.equal((await handleHostedBootstrapRequest(request("/api/auth/bootstrap/organization", { method: "POST", headers: { origin: env.AGENTPASS_CONSOLE_ORIGIN, cookie: bootstrapCookie, "content-type": "application/json", "agentpass-bootstrap-csrf": csrf } , body: { name: "x" } }), { env, fetchImpl })).status, 400);
  assert.equal((await handleHostedBootstrapRequest(request("/api/auth/bootstrap/organization", { method: "POST", headers: { origin: env.AGENTPASS_CONSOLE_ORIGIN, cookie: bootstrapCookie, "content-type": "application/json", "agentpass-bootstrap-csrf": csrf, "idempotency-key": idem }, body: { name: "x" } }), { env, fetchImpl })).status, 200);
  assert.equal(calls, 2);
});

test("rejects browser authority headers and strips unrelated cookies", async () => {
  let seen;
  const result = await createHostedBootstrapBff({ env, fetchImpl: async (url, init) => { seen = { url: String(url), init }; return response({ ok: true }); } }).handle(request("/api/auth/bootstrap/status", { headers: { origin: env.AGENTPASS_CONSOLE_ORIGIN, cookie: `${bootstrapCookie}; __Host-agentpass_session=${session}`, authorization: "Bearer attacker" } }));
  assert.equal(result.status, 400);
  assert.equal(seen, undefined);
  const accepted = await handleHostedBootstrapRequest(request("/api/auth/bootstrap/status", { headers: { origin: env.AGENTPASS_CONSOLE_ORIGIN, cookie: `${bootstrapCookie}; __Host-agentpass_session=${session}` } }), { env, fetchImpl: async (url, init) => { seen = { url: String(url), init }; return response({ ok: true }); } });
  assert.equal(accepted.status, 200);
  assert.equal(seen.init.headers.get("cookie"), bootstrapCookie);
  assert.equal(seen.init.headers.has("authorization"), false);
});

test("bounds body and response, uses no-store/manual redirect, and returns stable errors", async () => {
  let seen;
  const oversizedBody = await handleHostedBootstrapRequest(request("/api/auth/bootstrap/organization", { method: "POST", headers: { origin: env.AGENTPASS_CONSOLE_ORIGIN, cookie: bootstrapCookie, "content-type": "application/json", "agentpass-bootstrap-csrf": csrf, "idempotency-key": idem }, body: { name: "x".repeat(70_000) } }), { env, fetchImpl: async () => { throw new Error("must not call"); } });
  assert.equal(oversizedBody.status, 413);
  const oversizedResponse = await handleHostedBootstrapRequest(request("/api/auth/bootstrap/status", { headers: { origin: env.AGENTPASS_CONSOLE_ORIGIN, cookie: bootstrapCookie } }), { env, fetchImpl: async (url, init) => { seen = { url, init }; return new Response(JSON.stringify({ ok: "x".repeat(300_000) }), { headers: { "content-type": "application/json" } }); } });
  assert.equal(oversizedResponse.status, 502);
  assert.equal(seen.init.cache, "no-store");
  assert.equal(seen.init.redirect, "manual");
  assert.equal(oversizedResponse.headers.get("cache-control"), "no-store, max-age=0");
  const timeout = await handleHostedBootstrapRequest(request("/api/auth/bootstrap/status", { headers: { origin: env.AGENTPASS_CONSOLE_ORIGIN, cookie: bootstrapCookie } }), { env, timeoutMs: 1_000, fetchImpl: async (_url, init) => await new Promise((_resolve, reject) => init.signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")))) });
  assert.equal(timeout.status, 504);
  assert.deepEqual(await timeout.json(), { error: { code: "cloud_api_timeout", message: "Cloud API request timed out" } });
});
