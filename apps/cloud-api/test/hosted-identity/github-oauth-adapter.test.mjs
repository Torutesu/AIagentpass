import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  GITHUB_OAUTH_ERROR_CODES,
  GithubOAuthError,
  createGithubOAuthConfig,
  createGithubOAuthIdentityAdapter,
  normalizeGithubUserResponse
} from "../../src/hosted-identity/index.mjs";

const ENV = Object.freeze({
  AGENTPASS_CLOUD_PROFILE: "hosted",
  AGENTPASS_GITHUB_CLIENT_ID: "client-123",
  AGENTPASS_GITHUB_CLIENT_SECRET: "secret-value",
  AGENTPASS_GITHUB_REDIRECT_URI: "https://console.example.test/api/auth/bootstrap/github/callback",
  AGENTPASS_GITHUB_TIMEOUT_MS: "500",
  AGENTPASS_GITHUB_MAX_RESPONSE_BYTES: "4096"
});

function config(overrides = {}) {
  return createGithubOAuthConfig({ ...ENV, ...overrides });
}

function response(body, { status = 200, contentType = "application/json" } = {}) {
  const bytes = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === "string" ? body : JSON.stringify(body));
  return new Response(bytes, {
    status,
    headers: { "content-type": contentType, "content-length": String(bytes.length) }
  });
}

function stateFixture({ now = 1_800_000_000_000, fetchImpl, overrides = {} } = {}) {
  const stored = new Map();
  const stateStore = {
    async create(record) { stored.set(record.stateHash, record); },
    async consume(stateHash) {
      const record = stored.get(stateHash);
      stored.delete(stateHash);
      return record;
    }
  };
  const randomValues = [Buffer.alloc(32, 1), Buffer.alloc(32, 2)];
  const adapter = createGithubOAuthIdentityAdapter({
    config: config(overrides),
    stateStore,
    fetchImpl,
    randomBytes(size) { const value = randomValues.shift(); assert.equal(value?.length, size); return value; },
    now: () => now
  });
  return { adapter, stored, stateStore, now };
}

test("config requires hosted profile and exact HTTPS endpoints with bounded defaults", () => {
  const parsed = createGithubOAuthConfig(ENV);
  assert.equal(parsed.authorizationEndpoint, "https://github.com/login/oauth/authorize");
  assert.equal(parsed.tokenEndpoint, "https://github.com/login/oauth/access_token");
  assert.equal(parsed.userEndpoint, "https://api.github.com/user");
  assert.equal(parsed.timeoutMs, 500);
  assert.equal(parsed.maxResponseBytes, 4096);

  for (const overrides of [
    { AGENTPASS_CLOUD_PROFILE: "local" },
    { AGENTPASS_GITHUB_REDIRECT_URI: "http://console.example.test/callback" },
    { AGENTPASS_GITHUB_TOKEN_ENDPOINT: "https://github.example.test/token" },
    { AGENTPASS_GITHUB_TIMEOUT_MS: "99" },
    { AGENTPASS_GITHUB_MAX_RESPONSE_BYTES: "1048577" }
  ]) {
    assert.throws(() => createGithubOAuthConfig({ ...ENV, ...overrides }), (error) => error.code === "github_oauth_config_invalid");
  }
});

test("adapter rejects a hand-built config that bypasses secure URL or limit validation", () => {
  const valid = config();
  for (const patch of [
    { tokenEndpoint: "http://github.example.test/token" },
    { userEndpoint: "https://github.example.test/user?redirect=https://evil.test" },
    { scope: "user:email" },
    { timeoutMs: 31_000 },
    { maxResponseBytes: 1_023 }
  ]) {
    assert.throws(
      () => createGithubOAuthIdentityAdapter({ config: { ...valid, ...patch }, stateStore: { create() {}, consume() {} }, fetchImpl: async () => response({}) }),
      (error) => error.code === GITHUB_OAUTH_ERROR_CODES.CONFIG_INVALID
    );
  }
});

test("start creates hashed state and S256 PKCE against the exact configured redirect", async () => {
  const fixture = stateFixture({ fetchImpl: async () => response({}) });
  const started = await fixture.adapter.start();
  const url = new URL(started.authorizationUrl);
  const stored = [...fixture.stored.values()][0];

  assert.equal(url.origin + url.pathname, "https://github.com/login/oauth/authorize");
  assert.equal(url.searchParams.get("client_id"), "client-123");
  assert.equal(url.searchParams.get("response_type"), "code");
  assert.equal(url.searchParams.get("redirect_uri"), ENV.AGENTPASS_GITHUB_REDIRECT_URI);
  assert.equal(url.searchParams.get("scope"), "read:user");
  assert.equal(url.searchParams.get("state"), started.state);
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
  assert.equal(url.searchParams.get("code_challenge"), crypto.createHash("sha256").update(stored.pkceVerifier).digest("base64url"));
  assert.equal(stored.stateHash, crypto.createHash("sha256").update(started.state).digest("hex"));
  assert.notEqual(stored.stateHash, started.state);
  assert.equal(stored.redirectUri, ENV.AGENTPASS_GITHUB_REDIRECT_URI);
});

test("callback exchanges code server-side, calls /user, and returns only immutable numeric subject", async () => {
  const calls = [];
  const fixture = stateFixture({
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      if (url.endsWith("/access_token")) return response({ access_token: "ghs_secret_token", token_type: "bearer", scope: "read:user" });
      return response({ id: 123456789, login: "ignored", email: "ignored@example.test", name: "ignored" });
    }
  });
  const started = await fixture.adapter.start();
  const result = await fixture.adapter.callback({ code: "oauth-code", state: started.state, stateCookie: started.state });

  assert.deepEqual(result, { provider: "github", subject: "123456789" });
  assert.equal(calls.length, 2);
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.headers["Content-Type"], "application/x-www-form-urlencoded");
  assert.equal(calls[0].init.headers.Authorization, undefined);
  assert.equal(calls[0].init.redirect, "error");
  assert.deepEqual(Object.fromEntries(new URLSearchParams(calls[0].init.body)), {
    client_id: ENV.AGENTPASS_GITHUB_CLIENT_ID,
    client_secret: ENV.AGENTPASS_GITHUB_CLIENT_SECRET,
    code: "oauth-code",
    redirect_uri: ENV.AGENTPASS_GITHUB_REDIRECT_URI,
    code_verifier: Buffer.alloc(32, 2).toString("base64url")
  });
  assert.equal(calls[1].init.method, "GET");
  assert.equal(calls[1].init.headers.Accept, "application/json");
  assert.equal(calls[1].init.headers.Authorization, "Bearer ghs_secret_token");
  assert.equal(calls[1].init.redirect, "error");
  assert.equal(JSON.stringify(result).includes("ghs_secret_token"), false);
});

test("accepts the provider's JSON UTF-8 media type without treating parameters as another format", async () => {
  const fixture = stateFixture({
    fetchImpl: async (url) => url.endsWith("/access_token")
      ? response({ access_token: "token" }, { contentType: "application/json; charset=utf-8" })
      : response({ id: 7 }, { contentType: "application/json; charset=utf-8" })
  });
  const started = await fixture.adapter.start();
  assert.equal((await fixture.adapter.callback({ code: "code", state: started.state, stateCookie: started.state })).subject, "7");
});

test("wrong state, wrong PKCE record, and replay fail with one stable redacted state error", async () => {
  const fixture = stateFixture({ fetchImpl: async () => response({ access_token: "never-used" }) });
  const started = await fixture.adapter.start();
  await assert.rejects(
    fixture.adapter.callback({ code: "code", state: started.state, stateCookie: "wrong-state" }),
    (error) => error instanceof GithubOAuthError && error.code === GITHUB_OAUTH_ERROR_CODES.STATE_INVALID
  );
  const record = [...fixture.stored.values()][0];
  fixture.stored.set(record.stateHash, Object.freeze({ ...record, pkceVerifier: "wrong" }));
  await assert.rejects(
    fixture.adapter.callback({ code: "code", state: started.state, stateCookie: started.state }),
    (error) => error.code === GITHUB_OAUTH_ERROR_CODES.STATE_INVALID
  );
  assert.equal(fixture.stored.size, 0);
  await assert.rejects(
    fixture.adapter.callback({ code: "code", state: started.state, stateCookie: started.state }),
    (error) => error.code === GITHUB_OAUTH_ERROR_CODES.STATE_INVALID && !String(error).includes("wrong")
  );
});

test("provider failures, malformed/oversized/duplicate JSON, invalid id, and wrong content type are bounded and redacted", async (t) => {
  const cases = [
    ["non-2xx", async () => response({ error: "token-body-secret" }, { status: 500 }), GITHUB_OAUTH_ERROR_CODES.PROVIDER_UNAVAILABLE],
    ["malformed JSON", async () => response("{not-json"), GITHUB_OAUTH_ERROR_CODES.PROVIDER_UNAVAILABLE],
    ["oversized JSON", async () => response(JSON.stringify({ access_token: "x".repeat(5000) }), { status: 200 }), GITHUB_OAUTH_ERROR_CODES.PROVIDER_UNAVAILABLE],
    ["duplicate JSON", async () => response('{"access_token":"one","access_token":"two"}'), GITHUB_OAUTH_ERROR_CODES.PROVIDER_UNAVAILABLE],
    ["wrong content type", async () => response({ access_token: "token" }, { contentType: "text/plain" }), GITHUB_OAUTH_ERROR_CODES.PROVIDER_UNAVAILABLE]
  ];
  for (const [name, tokenResponse, expected] of cases) {
    await t.test(name, async () => {
      const fixture = stateFixture({ fetchImpl: tokenResponse });
      const started = await fixture.adapter.start();
      await assert.rejects(
        fixture.adapter.callback({ code: "code", state: started.state, stateCookie: started.state }),
        (error) => error.code === expected && !String(error).includes("secret") && !String(error).includes("token")
      );
    });
  }

  const invalidIdFixture = stateFixture({
    fetchImpl: async (url) => url.endsWith("/access_token") ? response({ access_token: "token" }) : response({ id: "123", email: "authority@example.test" })
  });
  const invalidIdStart = await invalidIdFixture.adapter.start();
  await assert.rejects(
    invalidIdFixture.adapter.callback({ code: "code", state: invalidIdStart.state, stateCookie: invalidIdStart.state }),
    (error) => error.code === GITHUB_OAUTH_ERROR_CODES.SUBJECT_UNVERIFIED
  );
});

test("timeout aborts a hanging provider request", async () => {
  let signal;
  const fixture = stateFixture({
    fetchImpl: async (_url, init) => {
      signal = init.signal;
      return new Promise(() => {});
    },
    overrides: { AGENTPASS_GITHUB_TIMEOUT_MS: "100" }
  });
  const started = await fixture.adapter.start();
  await assert.rejects(
    fixture.adapter.callback({ code: "code", state: started.state, stateCookie: started.state }),
    (error) => error.code === GITHUB_OAUTH_ERROR_CODES.PROVIDER_UNAVAILABLE
  );
  assert.equal(signal.aborted, true);
});

test("normalization ignores email and name and rejects unsafe numeric ids", () => {
  assert.deepEqual(normalizeGithubUserResponse({ id: 42, email: "not-authority", name: "not-authority" }), { provider: "github", subject: "42" });
  for (const id of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, "42", null]) {
    assert.throws(() => normalizeGithubUserResponse({ id }), (error) => error.code === GITHUB_OAUTH_ERROR_CODES.SUBJECT_UNVERIFIED);
  }
});
