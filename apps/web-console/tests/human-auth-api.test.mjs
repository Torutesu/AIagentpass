import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { createHumanAuthBridge } from "../lib/human-auth-api.mjs";
import { assertCompactIdentityAssertion, IDENTITY_ASSERTION_HEADER } from "../lib/identity-assertion.mjs";

const identityKeys = crypto.generateKeyPairSync("ed25519");
const identityPrivateKey = identityKeys.privateKey.export({ type: "pkcs8", format: "pem" });

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
const productionEnv = Object.freeze({
  ...env,
  AGENTPASS_CLOUD_API_URL: "https://cloud.example.test",
  AGENTPASS_CONSOLE_ORIGIN: "https://console.example.test",
  AGENTPASS_ORGANIZATION_ID: "11111111-1111-4111-8111-111111111111",
  AGENTPASS_IDENTITY_ASSERTION_PRIVATE_KEY: identityPrivateKey,
  AGENTPASS_IDENTITY_ASSERTION_ISSUER: "agentpass-console",
  AGENTPASS_IDENTITY_ASSERTION_AUDIENCE: "agentpass-cloud",
  AGENTPASS_IDENTITY_ASSERTION_KID: "console-2026-08",
  AGENTPASS_IDENTITY_PROVIDER: "chatgpt",
  NODE_ENV: "production",
});
const csrf = "B".repeat(43);
const sessionCookie = "__Host-agentpass_session=" + "A".repeat(43);
const organizationId = productionEnv.AGENTPASS_ORGANIZATION_ID;

function sessionResponse(cookie = sessionCookie) {
  return {
    session: {
      version: 1,
      session_id: "11111111-1111-4111-8111-111111111111",
      member_id: "22222222-2222-4222-8222-222222222222",
      organization_id: organizationId,
      role: "owner",
      created_at: "2026-08-12T00:00:00.000Z",
      expires_at: "2026-08-12T01:00:00.000Z",
      recent_auth_at: null,
    },
    csrf_token: csrf,
    cookie,
  };
}

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
    const result = sessionResponse();
    return new Response(JSON.stringify({ session: result.session, csrf_token: result.csrf_token }), { status: 201, headers: { "content-type": "application/json", "set-cookie": `${sessionCookie}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600` } });
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
    const result = sessionResponse(replacement);
    return new Response(JSON.stringify({ session: result.session, csrf_token: result.csrf_token }), { status: 201, headers: { "content-type": "application/json", "set-cookie": `${replacement}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600` } });
  }, undefined, legacyEnv);
  const response = await api.handle(request("/api/auth/session", { headers: { cookie: sessionCookie } }));
  assert.equal(response.status, 201);
  assert.equal(calls[0].init.headers.has("cookie"), false);
  assert.equal(response.headers.get("set-cookie"), `${replacement}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600`);
});

test("resumes a Hosted session with only the same-origin cookie and canonical empty body", async () => {
  const calls = [];
  const api = createHumanAuthBridge({
    env,
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init });
      const result = sessionResponse();
      return new Response(JSON.stringify({ session: result.session, csrf_token: result.csrf_token }), {
        status: 200,
        headers: {
          "content-type": "application/json",
          "set-cookie": `${sessionCookie}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600`
        }
      });
    },
    getSiwcUser: async () => { throw new Error("SIWC must not be consulted for resume"); }
  });
  const response = await api.handle(request("/api/auth/session/resume", {
    body: {},
    headers: {
      cookie: `tracking=ignored; ${sessionCookie}`,
      authorization: "Bearer browser-must-not-forward",
      "agentpass-csrf": csrf,
      "agentpass-console-user-id": "spoofed"
    }
  }));

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { session: sessionResponse().session, csrf_token: csrf });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://cloud.example.test/api/auth/session/resume");
  assert.equal(calls[0].init.method, "POST");
  assert.equal(new TextDecoder().decode(calls[0].init.body), "{}");
  assert.equal(calls[0].init.headers.get("origin"), "https://console.example.test");
  assert.equal(calls[0].init.headers.get("cookie"), sessionCookie);
  assert.equal(calls[0].init.headers.has("authorization"), false);
  assert.equal(calls[0].init.headers.has("agentpass-csrf"), false);
  assert.equal(calls[0].init.headers.has("agentpass-console-user-id"), false);
  assert.equal(calls[0].init.cache, "no-store");
  assert.equal(calls[0].init.redirect, "error");
  assert.equal(response.headers.get("set-cookie"), `${sessionCookie}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600`);
  assert.equal(response.headers.get("cache-control"), "no-store, max-age=0");
});

test("resume requires the exact empty request, session cookie, and strict session DTO", async () => {
  let calls = 0;
  const api = createHumanAuthBridge({
    env,
    fetchImpl: async () => { calls += 1; return new Response(JSON.stringify({ session: sessionResponse().session, csrf_token: csrf }), { headers: { "content-type": "application/json" } }); }
  });
  assert.equal((await api.handle(request("/api/auth/session/resume", { body: { extra: true }, headers: { cookie: sessionCookie } }))).status, 400);
  assert.equal((await api.handle(request("/api/auth/session/resume"))).status, 401);
  assert.equal((await api.handle(request("/api/auth/session/resume", { headers: { cookie: sessionCookie, origin: "https://evil.test" } }))).status, 403);
  assert.equal(calls, 0);

  const malformedDto = await createHumanAuthBridge({
    env,
    fetchImpl: async () => new Response(JSON.stringify({ session: sessionResponse().session }), { status: 200, headers: { "content-type": "application/json", "set-cookie": `${sessionCookie}; Path=/; HttpOnly; Secure; SameSite=Strict` } })
  }).handle(request("/api/auth/session/resume", { headers: { cookie: sessionCookie } }));
  assert.equal(malformedDto.status, 502);

  const malformedCookie = await createHumanAuthBridge({
    env,
    fetchImpl: async () => new Response(JSON.stringify({ session: sessionResponse().session, csrf_token: csrf }), { status: 200, headers: { "content-type": "application/json", "set-cookie": "other=value" } })
  }).handle(request("/api/auth/session/resume", { headers: { cookie: sessionCookie } }));
  assert.equal(malformedCookie.status, 502);
});

test("resume relays the Cloud human_session_session_required code without invoking SIWC", async () => {
  let calls = 0;
  const api = createHumanAuthBridge({
    env,
    fetchImpl: async (url) => {
      calls += 1;
      assert.equal(String(url), "https://cloud.example.test/api/auth/session/resume");
      return new Response(JSON.stringify({ error: { code: "human_session_session_required", message: "A valid human session is required" } }), { status: 401, headers: { "content-type": "application/json" } });
    },
    getSiwcUser: async () => { throw new Error("SIWC must not be consulted"); }
  });
  const response = await api.handle(request("/api/auth/session/resume", { headers: { cookie: sessionCookie } }));
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: { code: "human_session_session_required", message: "A valid human session is required" } });
  assert.equal(calls, 1);
});

test("self-logout forwards only the session cookie and CSRF, then relays the exact clear cookie", async () => {
  const calls = [];
  const api = bridge(async (url, init) => {
    calls.push({ url: String(url), init });
    return new Response(JSON.stringify({ session: null }), {
      status: 200,
      headers: {
        "content-type": "application/json",
        "set-cookie": "__Host-agentpass_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"
      }
    });
  });
  const response = await api.handle(request("/api/auth/session", { method: "DELETE", headers: { cookie: sessionCookie, "agentpass-csrf": csrf } }));

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { session: null });
  assert.equal(response.headers.get("set-cookie"), "__Host-agentpass_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://cloud.example.test/api/auth/session");
  assert.equal(calls[0].init.method, "DELETE");
  assert.equal(calls[0].init.headers.get("cookie"), sessionCookie);
  assert.equal(calls[0].init.headers.get("agentpass-csrf"), csrf);
  assert.equal(calls[0].init.headers.has("authorization"), false);
  assert.equal(calls[0].init.body, undefined);
  assert.equal(calls[0].init.cache, "no-store");
});

test("self-logout fails closed before Cloud when cookie, CSRF, origin, or clear cookie is invalid", async () => {
  let calls = 0;
  const api = bridge(async () => { calls += 1; return new Response(JSON.stringify({ session: null }), { headers: { "content-type": "application/json" } }); });
  assert.equal((await api.handle(request("/api/auth/session", { method: "DELETE", headers: { "agentpass-csrf": csrf } }))).status, 401);
  assert.equal((await api.handle(request("/api/auth/session", { method: "DELETE", headers: { cookie: sessionCookie } }))).status, 403);
  assert.equal((await api.handle(request("/api/auth/session", { method: "DELETE", headers: { cookie: sessionCookie, "agentpass-csrf": "short" } }))).status, 403);
  assert.equal((await api.handle(request("/api/auth/session", { method: "DELETE", headers: { cookie: "__Host-agentpass_session=short", "agentpass-csrf": csrf } }))).status, 400);
  assert.equal((await api.handle(request("/api/auth/session", { method: "DELETE", headers: { cookie: sessionCookie, "agentpass-csrf": csrf, origin: "https://evil.test" } }))).status, 403);
  const nonEmptyBody = new Request("https://console.example.test/api/auth/session", { method: "DELETE", headers: { origin: "https://console.example.test", "content-type": "application/json", cookie: sessionCookie, "agentpass-csrf": csrf }, body: "{}" });
  assert.equal((await api.handle(nonEmptyBody)).status, 400);
  const wrongMethod = new Request("https://console.example.test/api/auth/session", { method: "PUT", headers: { origin: "https://console.example.test" } });
  const wrongMethodResponse = await api.handle(wrongMethod);
  assert.equal(wrongMethodResponse.status, 405);
  assert.equal(wrongMethodResponse.headers.get("allow"), "POST, DELETE");
  assert.equal(calls, 0);

  const malformedClear = await bridge(async () => new Response(JSON.stringify({ session: null }), {
    headers: { "content-type": "application/json", "set-cookie": "other=value" }
  })).handle(request("/api/auth/session", { method: "DELETE", headers: { cookie: sessionCookie, "agentpass-csrf": csrf } }));
  assert.equal(malformedClear.status, 502);
  const malformedBody = await bridge(async () => new Response(JSON.stringify({ session: {} }), {
    headers: { "content-type": "application/json", "set-cookie": "__Host-agentpass_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" }
  })).handle(request("/api/auth/session", { method: "DELETE", headers: { cookie: sessionCookie, "agentpass-csrf": csrf } }));
  assert.equal(malformedBody.status, 502);
});

test("production bootstrap sends only the compact server identity header and exact empty JSON body", async () => {
  assert.equal(Object.hasOwn(productionEnv, "AGENTPASS_CLOUD_TOKEN"), false);
  assert.equal(Object.hasOwn(productionEnv, "AGENTPASS_OPERATOR_USER_IDS"), false);
  const calls = [];
  const api = bridge(async (url, init) => {
    calls.push({ url: String(url), init });
    const result = sessionResponse();
    return new Response(JSON.stringify({ session: result.session, csrf_token: result.csrf_token }), { status: 201, headers: { "content-type": "application/json", "set-cookie": `${sessionCookie}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600` } });
  }, { userId: "siwc-subject-1" }, productionEnv);
  const response = await api.handle(request("/api/auth/session"));
  assert.equal(response.status, 201);
  assert.equal(new TextDecoder().decode(calls[0].init.body), "{}");
  const compact = calls[0].init.headers.get(IDENTITY_ASSERTION_HEADER);
  assert.equal(typeof compact, "string");
  const parsed = assertCompactIdentityAssertion(compact, { expected: {
    issuer: productionEnv.AGENTPASS_IDENTITY_ASSERTION_ISSUER,
    audience: productionEnv.AGENTPASS_IDENTITY_ASSERTION_AUDIENCE,
    keyId: productionEnv.AGENTPASS_IDENTITY_ASSERTION_KID,
    provider: productionEnv.AGENTPASS_IDENTITY_PROVIDER,
  } });
  assert.deepEqual(Object.keys(parsed.header).sort(), ["alg", "kid", "typ", "version"]);
  assert.deepEqual(Object.keys(parsed.payload).sort(), ["aud", "exp", "iat", "iss", "jti", "nbf", "org", "origin", "provider", "sub"]);
  assert.equal(parsed.header.alg, "EdDSA");
  assert.equal(parsed.header.typ, "agentpass.console.identity");
  assert.equal(parsed.payload.sub, "siwc-subject-1");
  assert.equal(parsed.payload.kid, undefined);
  assert.equal(parsed.payload.redirect_uri, undefined);
  const compactParts = compact.split(".");
  assert.equal(crypto.verify(null, Buffer.from(`${compactParts[0]}.${compactParts[1]}`, "ascii"), identityKeys.publicKey, Buffer.from(compactParts[2], "base64url")), true);
  assert.equal(calls[0].init.headers.has("authorization"), false);
  assert.equal(calls[0].init.headers.has("agentpass-console-user-id"), false);
  assert.doesNotMatch(await response.text(), /agentpass-console-identity|siwc-subject-1|EdDSA/);
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

test("fails closed when production assertion signing is not configured", async () => {
  let calls = 0;
  const production = { ...legacyEnv, NODE_ENV: "production" };
  const response = await bridge(async () => { calls += 1; return new Response("{}", { headers: { "content-type": "application/json" } }); }, undefined, production).handle(request("/api/auth/session"));
  assert.equal(response.status, 503);
  assert.equal(calls, 0);
  assert.match(await response.text(), /identity_unavailable/);
});

test("does not enable legacy bootstrap when the deployment environment is unspecified", async () => {
  const response = await bridge(async () => new Response("{}", { headers: { "content-type": "application/json" } }), undefined, { ...legacyEnv, NODE_ENV: undefined }).handle(request("/api/auth/session"));
  assert.equal(response.status, 503);
});
