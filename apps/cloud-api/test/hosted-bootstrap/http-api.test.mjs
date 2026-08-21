import assert from "node:assert/strict";
import test from "node:test";

import {
  createHostedBootstrapHttpApi,
  HOSTED_BOOTSTRAP_COOKIE_NAMES,
  HOSTED_BOOTSTRAP_HTTP_ERROR_CODES,
  HOSTED_BOOTSTRAP_HTTP_PATHS
} from "../../src/hosted-bootstrap/http-api.mjs";
import { createGithubOAuthIdentityAdapter } from "../../src/hosted-identity/github-oauth-adapter.mjs";

const ORIGIN = "https://console.agentpass.test";
const RP_ID = "console.agentpass.test";
const ONBOARDING = "https://console.agentpass.test/onboarding";
const AUTH_ENDPOINT = "https://github.com/login/oauth/authorize";
const CALLBACK_ENDPOINT = "https://api.agentpass.test/callback";
const BOOTSTRAP_TOKEN = "b".repeat(43);
const CSRF_TOKEN = "c".repeat(43);
const SESSION_TOKEN = "s".repeat(43);
const STATE = "t".repeat(43);
const ATTEMPT_ID = "77777777-7777-4777-8777-777777777777";
const OAUTH_STATE_ID = "88888888-8888-4888-8888-888888888888";
const CHALLENGE_ID = "11111111-1111-4111-8111-111111111111";
const SESSION = {
  version: 1,
  session_id: "22222222-2222-4222-8222-222222222222",
  member_id: "33333333-3333-4333-8333-333333333333",
  organization_id: "44444444-4444-4444-8444-444444444444",
  role: "owner",
  created_at: "2026-08-15T00:00:00.000Z",
  expires_at: "2026-08-15T01:00:00.000Z",
  recent_auth_at: null
};

const NOW = Date.parse("2026-08-15T00:00:00.000Z");

function fixture(overrides = {}) {
  const calls = { githubStart: [], githubCallback: [], identity: [], status: [], csrf: [], organization: [], options: [], verify: [], rate: [] };
  const githubService = overrides.githubService ?? {
    async start(input) { calls.githubStart.push(input); return overrides.githubStart ?? { authorizationUrl: `${AUTH_ENDPOINT}?client_id=github-client-id&response_type=code&redirect_uri=${encodeURIComponent(CALLBACK_ENDPOINT)}&scope=read%3Auser&state=${STATE}&code_challenge=${"Q".repeat(43)}&code_challenge_method=S256`, state: STATE, stateCookie: STATE, expiresAt: NOW + 600_000 }; },
    async callback(input) { calls.githubCallback.push(input); if (overrides.githubCallback instanceof Error) throw overrides.githubCallback; return overrides.githubCallback ?? { identity: { provider: "github", subject: "123456789" }, context: { attempt_id: ATTEMPT_ID, oauth_state_id: OAUTH_STATE_ID } }; }
  };
  const identityBootstrapService = overrides.identityBootstrapService ?? {
    async createBootstrapSession(input) { calls.identity.push(input); return overrides.identity ?? { bootstrapToken: BOOTSTRAP_TOKEN, expiresAt: NOW + 900_000 }; }
  };
  const bootstrapService = {
    async status(input) {
      calls.status.push(input);
      return overrides.status ?? { state: "organization_required", webauthn_required: false, can_create_first_organization: true, organization_count: 0, csrf_token: CSRF_TOKEN, expires_at: "2026-08-15T00:15:00.000Z" };
    },
    async verifyCsrf(input) { calls.csrf.push(input); if (overrides.csrfError) throw overrides.csrfError; return overrides.csrf ?? true; },
    async createOrganization(input) {
      calls.organization.push(input);
      if (overrides.organizationError) throw overrides.organizationError;
      return overrides.organization ?? { replayed: false, organization: { organization_id: "55555555-5555-4555-8555-555555555555", name: input.name, version: 1, created_at: "2026-08-15T00:00:00.000Z", updated_at: "2026-08-15T00:00:00.000Z" } };
    }
  };
  const webauthnService = {
    async options(input) {
      calls.options.push(input);
      return overrides.options ?? { challenge_id: CHALLENGE_ID, options: { challenge: "Q".repeat(43), rp: { id: RP_ID, name: "AgentPass" }, user: { id: "dXNlcg", name: "verified-user", displayName: "Verified User" }, pubKeyCredParams: [{ type: "public-key", alg: -7 }], authenticatorSelection: { userVerification: "required" } } };
    },
    async verify(input) { calls.verify.push(input); if (overrides.verifyError) throw overrides.verifyError; return overrides.verify ?? { session_token: SESSION_TOKEN, csrf_token: CSRF_TOKEN, session: SESSION }; }
  };
  const api = createHostedBootstrapHttpApi({
    githubService,
    identityBootstrapService,
    bootstrapService,
    webauthnService,
    rateLimiter: { async authorize(input) { calls.rate.push(input); if (overrides.rateError) throw overrides.rateError; return overrides.rate ?? { allowed: true }; } },
    origin: ORIGIN,
    rpId: RP_ID,
    consoleOnboardingUrl: ONBOARDING,
    now: () => NOW
  });
  return { api, calls };
}

function cookie(name, value) { return `${name}=${value}`; }
function bootstrapCookie() { return cookie(HOSTED_BOOTSTRAP_COOKIE_NAMES.bootstrap, BOOTSTRAP_TOKEN); }
function stateCookie() { return cookie(HOSTED_BOOTSTRAP_COOKIE_NAMES.githubState, STATE); }
function jsonRequest(url, body, headers = {}) {
  return { method: "POST", url, headers: { Origin: ORIGIN, "Content-Type": "application/json", Cookie: bootstrapCookie(), "agentpass-bootstrap-csrf": CSRF_TOKEN, ...headers }, body: JSON.stringify(body) };
}
function assertSafe(result) {
  assert.match(result.headers["Cache-Control"], /no-store/u);
  assert.equal(result.headers["X-Content-Type-Options"], "nosniff");
  assert.equal(JSON.stringify(result.body).includes(BOOTSTRAP_TOKEN), false);
}

test("all six routes use exact paths and only server-derived service DTOs", async () => {
  const { api, calls } = fixture();
  const start = await api.handle({ method: "GET", url: HOSTED_BOOTSTRAP_HTTP_PATHS.githubStart, headers: {}, body: undefined });
  assert.equal(start.status, 302);
  assert.equal(start.body, null);
  assert.match(start.headers.Location, /^https:\/\/github\.com\/login\/oauth\/authorize\?/u);
  assert.match(start.headers["Set-Cookie"], /^__Host-agentpass_github_state=[A-Za-z0-9_-]+; Path=\/; HttpOnly; Secure; SameSite=Lax; Max-Age=600$/u);
  assert.equal(new URL(start.headers.Location).searchParams.get("client_id"), "github-client-id");
  assert.equal(new URL(start.headers.Location).searchParams.get("redirect_uri"), CALLBACK_ENDPOINT);
  assert.equal(calls.githubStart[0], undefined);

  const callback = await api.handle({ method: "GET", url: `${HOSTED_BOOTSTRAP_HTTP_PATHS.githubCallback}?code=oauth-code&state=${STATE}`, headers: { Cookie: stateCookie() } });
  assert.equal(callback.status, 303);
  assert.equal(callback.headers.Location, ONBOARDING);
  assert.equal(new URL(callback.headers.Location).search, "");
  assert.equal(new URL(callback.headers.Location).hash, "");
  assert.deepEqual(calls.githubCallback[0], { code: "oauth-code", state: STATE, stateCookie: STATE });
  assert.deepEqual(calls.identity[0], { identity: { provider: "github", subject: "123456789" }, context: { attempt_id: ATTEMPT_ID, oauth_state_id: OAUTH_STATE_ID } });

  const status = await api.handle({ method: "GET", url: HOSTED_BOOTSTRAP_HTTP_PATHS.status, headers: { Origin: ORIGIN, Cookie: bootstrapCookie() } });
  assert.deepEqual(Object.keys(status.body).sort(), ["can_create_first_organization", "csrf_token", "expires_at", "organization_count", "state", "version", "webauthn_required"].sort());
  assert.deepEqual(calls.status[0], { bootstrap_token: BOOTSTRAP_TOKEN });

  const create = await api.handle(jsonRequest(HOSTED_BOOTSTRAP_HTTP_PATHS.organizationCreate, { name: "First Organization" }, { "Idempotency-Key": "bootstrap-1" }));
  assert.equal(create.status, 201);
  assert.equal(create.body.onboarding.state, "webauthn_required");
  assert.deepEqual(calls.organization[0], { bootstrap_token: BOOTSTRAP_TOKEN, name: "First Organization", idempotency_key: "bootstrap-1", request_hash: calls.organization[0]?.request_hash });
  assert.equal(Object.hasOwn(calls.organization[0], "organization_id"), false);

  const options = await api.handle(jsonRequest(HOSTED_BOOTSTRAP_HTTP_PATHS.webauthnOptions, {}));
  assert.equal(options.status, 200);
  assert.equal(options.body.options.rp.id, RP_ID);
  assert.equal(options.body.options.authenticatorSelection.userVerification, "required");
  assert.deepEqual(calls.options[0], { bootstrap_token: BOOTSTRAP_TOKEN, rp_id: RP_ID, origin: ORIGIN, user_verification: "required" });

  const credential = { id: "A".repeat(22), rawId: "A".repeat(22), type: "public-key", clientExtensionResults: {}, response: { clientDataJSON: "YQ", attestationObject: "Yg" } };
  const verify = await api.handle(jsonRequest(HOSTED_BOOTSTRAP_HTTP_PATHS.webauthnVerify, { challenge_id: CHALLENGE_ID, credential }));
  assert.equal(verify.status, 201);
  assert.equal(verify.body.state, "completed");
  assert.deepEqual(Object.keys(verify.body).sort(), ["csrf_token", "session", "state", "version"].sort());
  assert.deepEqual(calls.verify[0], { bootstrap_token: BOOTSTRAP_TOKEN, challenge_id: CHALLENGE_ID, credential: { credential_id: credential.id, client_data_json: "YQ", attestation_object: "Yg" }, rp_id: RP_ID, origin: ORIGIN, user_verification: "required" });
  assert.equal(JSON.stringify(verify.body).includes(SESSION_TOKEN), false);
  assertSafe(verify);
});

test("composes with the sibling GitHub adapter without taking ownership of state or PKCE", async () => {
  const records = new Map();
  const githubService = createGithubOAuthIdentityAdapter({
    config: { provider: "github", clientId: "github-client-id", clientSecret: "secret-value", redirectUri: CALLBACK_ENDPOINT, authorizationEndpoint: AUTH_ENDPOINT, tokenEndpoint: "https://github.com/login/oauth/access_token", userEndpoint: "https://api.github.com/user", timeoutMs: 500, maxResponseBytes: 4096, scope: "read:user" },
    stateStore: {
      async create(record) { records.set(record.oauthStateId, record); return { attemptId: record.attemptId, oauthStateId: record.oauthStateId, expiresAt: record.expiresAt }; },
      async consume(input) {
        const record = records.get(input.oauthStateId);
        records.delete(input.oauthStateId);
        if (!record || record.stateHash !== input.stateHash) return null;
        return { attemptId: record.attemptId, oauthStateId: record.oauthStateId, pkceVerifier: record.pkceVerifier, pkceChallenge: record.pkceChallenge, redirectUri: record.redirectUri, expiresAt: record.expiresAt };
      },
      async fail() { return true; }
    },
    randomBytes: (size) => Buffer.alloc(size, 9),
    randomUUID: (() => { const values = [ATTEMPT_ID, OAUTH_STATE_ID]; return () => values.shift(); })(),
    fetchImpl: async (url) => {
      const body = url.endsWith("/access_token") ? { access_token: "provider-secret" } : { id: 123456789, email: "ignored@example.test", name: "ignored" };
      const bytes = Buffer.from(JSON.stringify(body));
      return new Response(bytes, { status: 200, headers: { "content-type": "application/json", "content-length": String(bytes.length) } });
    },
    now: () => NOW
  });
  const { api, calls } = fixture({ githubService, identityBootstrapService: { async createBootstrapSession(input) { calls?.identity?.push(input); return { bootstrapToken: BOOTSTRAP_TOKEN, expiresAt: NOW + 900_000 }; } } });
  const start = await api.handle({ method: "GET", url: HOSTED_BOOTSTRAP_HTTP_PATHS.githubStart, headers: {} });
  const startUrl = new URL(start.headers.Location);
  const state = startUrl.searchParams.get("state");
  const stateCookie = start.headers["Set-Cookie"].split(";", 1)[0];
  const callback = await api.handle({ method: "GET", url: `${HOSTED_BOOTSTRAP_HTTP_PATHS.githubCallback}?code=oauth-code&state=${state}`, headers: { Cookie: stateCookie } });
  assert.equal(callback.status, 303);
  assert.equal(JSON.stringify(callback.body).includes("provider-secret"), false);
  assert.equal(records.size, 0);
  assert.deepEqual(calls.identity[0], { identity: { provider: "github", subject: "123456789" }, context: { attempt_id: ATTEMPT_ID, oauth_state_id: OAUTH_STATE_ID } });
});

test("requires exact Console Origin, forbids Authorization and caller authority headers, and fails closed on rate-limit outage", async () => {
  const { api, calls } = fixture();
  const wrongOrigin = await api.handle({ method: "GET", url: HOSTED_BOOTSTRAP_HTTP_PATHS.status, headers: { Origin: "https://console.agentpass.test/", Cookie: bootstrapCookie() } });
  assert.equal(wrongOrigin.status, 403);
  assert.equal(wrongOrigin.body.error.code, HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED);
  assert.equal(calls.status.length, 0);

  const authorization = await api.handle({ method: "GET", url: HOSTED_BOOTSTRAP_HTTP_PATHS.status, headers: { Origin: ORIGIN, Cookie: bootstrapCookie(), Authorization: "Bearer secret" } });
  assert.equal(authorization.status, 400);
  assert.equal(calls.status.length, 0);

  const denied = fixture({ rate: { allowed: false } });
  const failClosed = await denied.api.handle({ method: "GET", url: HOSTED_BOOTSTRAP_HTTP_PATHS.githubStart, headers: {} });
  assert.equal(failClosed.status, 503);
  assert.equal(failClosed.body.error.code, HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.UNAVAILABLE);
  assert.equal(denied.calls.githubStart.length, 0);
});

test("rejects query, cookies, methods, content type/size, duplicate keys, unknown fields, and missing idempotency before services", async () => {
  const { api, calls } = fixture();
  const cases = [
    { request: { method: "GET", url: `${HOSTED_BOOTSTRAP_HTTP_PATHS.status}?x=1`, headers: { Origin: ORIGIN, Cookie: bootstrapCookie() } }, status: 400 },
    { request: { method: "GET", url: HOSTED_BOOTSTRAP_HTTP_PATHS.githubStart, headers: { Cookie: "other=value" } }, status: 400 },
    { request: { method: "PUT", url: HOSTED_BOOTSTRAP_HTTP_PATHS.status, headers: { Origin: ORIGIN, Cookie: bootstrapCookie() } }, status: 405 },
    { request: jsonRequest(HOSTED_BOOTSTRAP_HTTP_PATHS.organizationCreate, { name: "x" }, { "Idempotency-Key": "short" }), status: 400 },
    { request: { ...jsonRequest(HOSTED_BOOTSTRAP_HTTP_PATHS.organizationCreate, { name: "x" }, { "Idempotency-Key": "bootstrap-1", "Content-Type": "text/plain" }), body: '{"name":"x"}' }, status: 400 },
    { request: { ...jsonRequest(HOSTED_BOOTSTRAP_HTTP_PATHS.organizationCreate, { name: "x" }, { "Idempotency-Key": "bootstrap-1", "Content-Length": "999999" }), body: '{"name":"x"}' }, status: 413 },
    { request: { ...jsonRequest(HOSTED_BOOTSTRAP_HTTP_PATHS.organizationCreate, {}, { "Idempotency-Key": "bootstrap-1" }), body: '{"name":"x","name":"y"}' }, status: 400 },
    { request: jsonRequest(HOSTED_BOOTSTRAP_HTTP_PATHS.organizationCreate, { name: "x", role: "owner" }, { "Idempotency-Key": "bootstrap-1" }), status: 400 },
    { request: jsonRequest(HOSTED_BOOTSTRAP_HTTP_PATHS.organizationCreate, { name: "x" }), status: 400 }
  ];
  for (const item of cases) {
    const result = await api.handle(item.request);
    assert.equal(result.status, item.status, JSON.stringify(item.request));
    assertSafe(result);
  }
  assert.equal(calls.organization.length, 0);
  assert.equal(calls.status.length, 0);
});

test("clears OAuth state on every terminal callback and maps service failures without raw details", async () => {
  const { api } = fixture({ githubCallback: undefined });
  const invalid = await api.handle({ method: "GET", url: `${HOSTED_BOOTSTRAP_HTTP_PATHS.githubCallback}?code=x&state=y&extra=z`, headers: { Cookie: stateCookie() } });
  assert.equal(invalid.status, 401);
  assert.equal(invalid.body.error.code, HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.OAUTH_STATE_INVALID);
  assert.match(invalid.headers["Set-Cookie"], /^__Host-agentpass_github_state=; Path=\/; HttpOnly; Secure; SameSite=Lax; Max-Age=0$/u);

  const unavailable = fixture({ githubCallback: new Error("access_token=secret") });
  const result = await unavailable.api.handle({ method: "GET", url: `${HOSTED_BOOTSTRAP_HTTP_PATHS.githubCallback}?code=x&state=y`, headers: { Cookie: stateCookie() } });
  assert.equal(result.status, 503);
  assert.equal(result.body.error.code, HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.PROVIDER_UNAVAILABLE);
  assert.equal(JSON.stringify(result.body).includes("secret"), false);
  assert.match(result.headers["Set-Cookie"], /^__Host-agentpass_github_state=;/u);
});

test("writes a redirect or JSON response through a response fake", async () => {
  const { api } = fixture();
  const written = { headers: {}, end(value) { this.body = value; }, writeHead(status, headers) { this.status = status; this.headers = headers; } };
  const result = await api.handle({ method: "GET", url: HOSTED_BOOTSTRAP_HTTP_PATHS.githubStart, headers: {} }, written);
  assert.equal(result.status, 302);
  assert.equal(written.status, 302);
  assert.equal(written.body, "");
  assert.equal(written.headers["X-Content-Type-Options"], "nosniff");
});
