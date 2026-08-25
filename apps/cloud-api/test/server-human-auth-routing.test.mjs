import assert from "node:assert/strict";
import nodeTest from "node:test";

import { createCloudApi } from "../src/server.mjs";
import { createHumanManagementHttpApi } from "../src/human-auth/management/http-api.mjs";
import { createLoopbackAwareTest } from "./support/loopback-test.mjs";

const test = createLoopbackAwareTest(nodeTest);

const OPTIONS_PATH = "/api/auth/webauthn/options";
const VERIFY_PATH = "/api/auth/webauthn/verify";
const SESSION_PATH = "/api/auth/session";
const SESSION_RESUME_PATH = "/api/auth/session/resume";
const REGISTRATION_OPTIONS_PATH = "/api/auth/webauthn/registration/options";
const REGISTRATION_VERIFY_PATH = "/api/auth/webauthn/registration/verify";
const MANAGEMENT_CREDENTIALS_PATH = "/api/auth/management/credentials";
const MANAGEMENT_SESSIONS_PATH = "/api/auth/management/sessions";
const MANAGEMENT_REVOKE_OTHER_SESSIONS_PATH = `${MANAGEMENT_SESSIONS_PATH}/revoke-others`;
const ORGANIZATIONS_PATH = "/api/auth/organizations";
const ACCEPT_INVITATION_PATH = "/api/auth/invitations/accept";
const MANAGEMENT_CREDENTIAL_ID = Buffer.alloc(16).toString("base64url");
const MEMBER_ID = "11111111-1111-4111-8111-111111111111";
const ORGANIZATION_ID = "22222222-2222-4222-8222-222222222222";
const CURRENT_SESSION_ID = "33333333-3333-4333-8333-333333333333";
const OTHER_SESSION_ID = "44444444-4444-4444-8444-444444444444";
const ORIGIN = "https://console.agentpass.test";
const SESSION_COOKIE = `__Host-agentpass_session=${"A".repeat(43)}; Path=/; HttpOnly; Secure; SameSite=Strict`;
const CSRF_TOKEN = "B".repeat(43);
const RECENT_AUTH_PROOF = "55555555-5555-4555-8555-555555555555";
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

function managementApi({ calls, repositoryOverrides = {}, sessionId = CURRENT_SESSION_ID } = {}) {
  const repository = {
    async listCredentials(input) {
      calls?.listCredentials.push(input);
      return repositoryOverrides.listCredentials ?? { items: [], next_cursor: null };
    },
    async renameCredential(input) {
      calls?.renameCredential.push(input);
      return repositoryOverrides.renameCredential ?? {};
    },
    async revokeCredential(input) {
      calls?.revokeCredential.push(input);
      return repositoryOverrides.revokeCredential ?? {};
    },
    async listSessions(input) {
      calls?.listSessions.push(input);
      return repositoryOverrides.listSessions ?? { items: [], next_cursor: null };
    },
    async revokeSession(input) {
      calls?.revokeSession.push(input);
      return repositoryOverrides.revokeSession ?? {
        session_id: input.target_session_id,
        member_id: MEMBER_ID,
        organization_id: ORGANIZATION_ID,
        role: "owner",
        version: input.expected_version + 1,
        status: "revoked",
        created_at: "2026-08-12T00:00:00.000Z",
        expires_at: "2026-08-12T08:00:00.000Z",
        last_seen_at: "2026-08-12T00:00:00.000Z",
        recent_auth_at: null,
        revoked_at: "2026-08-12T01:00:00.000Z"
      };
    },
    async revokeOtherSessions(input) {
      calls?.revokeOtherSessions.push(input);
      return repositoryOverrides.revokeOtherSessions ?? [];
    }
  };
  return createHumanManagementHttpApi({
    humanSession: {
      expectedOrigin: ORIGIN,
      async authenticateRequest() {
        return { session: { session_id: sessionId, member_id: MEMBER_ID, organization_id: ORGANIZATION_ID, role: "owner" } };
      }
    },
    recentAuthService: {
      async authorize({ proof, operation }) {
        return {
          authenticated_at: 1_800_000_000_000,
          challenge_id: proof,
          consumed: true,
          member_id: MEMBER_ID,
          operation,
          organization_id: ORGANIZATION_ID,
          verified: true
        };
      }
    },
    now: () => 1_800_000_000_000,
    repository,
    origin: ORIGIN
  });
}

function managementHeaders() {
  return { origin: ORIGIN, cookie: SESSION_COOKIE, "agentpass-csrf": CSRF_TOKEN, "agentpass-recent-auth": RECENT_AUTH_PROOF, "content-type": "application/json" };
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

test("preserves management list queries and fails closed on mutation query strings", async (t) => {
  const calls = { listCredentials: [], renameCredential: [], revokeCredential: [], listSessions: [], revokeSession: [], revokeOtherSessions: [] };
  const base = await startServer(t, { humanAuthApi: managementApi({ calls }) });

  const listResponse = await fetch(`${base}${MANAGEMENT_CREDENTIALS_PATH}?limit=10&cursor=next_cursor`, { method: "GET", headers: managementHeaders() });
  assert.equal(listResponse.status, 200);
  assert.deepEqual(calls.listCredentials[0], {
    session_id: "33333333-3333-4333-8333-333333333333",
    member_id: MEMBER_ID,
    organization_id: ORGANIZATION_ID,
    limit: 10,
    cursor: "next_cursor"
  });

  const sessionsResponse = await fetch(`${base}${MANAGEMENT_SESSIONS_PATH}?limit=5`, { method: "GET", headers: managementHeaders() });
  assert.equal(sessionsResponse.status, 200);
  assert.deepEqual(calls.listSessions[0], {
    session_id: CURRENT_SESSION_ID,
    member_id: MEMBER_ID,
    organization_id: ORGANIZATION_ID,
    limit: 5
  });

  for (const [method, path, body, callName] of [
    ["PATCH", `${MANAGEMENT_CREDENTIALS_PATH}/${MANAGEMENT_CREDENTIAL_ID}?unexpected=1`, { label: "renamed", expected_version: 1 }, "renameCredential"],
    ["POST", `${MANAGEMENT_CREDENTIALS_PATH}/${MANAGEMENT_CREDENTIAL_ID}/revoke?unexpected=1`, { expected_version: 1 }, "revokeCredential"],
    ["POST", `${MANAGEMENT_SESSIONS_PATH}/${OTHER_SESSION_ID}/revoke?unexpected=1`, { expected_version: 1 }, "revokeSession"],
    ["POST", `${MANAGEMENT_REVOKE_OTHER_SESSIONS_PATH}?unexpected=1`, {}, "revokeOtherSessions"]
  ]) {
    const mutationResponse = await fetch(`${base}${path}`, { method, headers: managementHeaders(), body: JSON.stringify(body) });
    assert.equal(mutationResponse.status, 400, path);
    assert.equal((await mutationResponse.json()).error.code, "human_management_invalid_request", path);
    assert.equal(calls[callName].length, 0, path);
  }
});

test("does not delegate malformed management paths", async (t) => {
  const calls = [];
  const base = await startServer(t, { humanAuthApi: { handle: async (input) => { calls.push(input); return { status: 200, body: { ok: true }, headers: {} }; } } });
  for (const path of [
    `${MANAGEMENT_CREDENTIALS_PATH}/`,
    `${MANAGEMENT_CREDENTIALS_PATH}/${MANAGEMENT_CREDENTIAL_ID}/revoke/`,
    `${MANAGEMENT_SESSIONS_PATH}/not-a-uuid/revoke`,
    `${MANAGEMENT_SESSIONS_PATH}/33333333-3333-4333-8333-333333333333/extra`,
    `${MANAGEMENT_REVOKE_OTHER_SESSIONS_PATH}/`
  ]) {
    const response = await fetch(`${base}${path}`, { method: "POST", headers: managementHeaders(), body: "{}" });
    assert.equal(response.status, 404, path);
  }
  assert.equal(calls.length, 0);
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

test("allows the exact session resume route through the human-auth boundary", async (t) => {
  const calls = [];
  const cookie = `__Host-agentpass_session=${"R".repeat(43)}; Path=/; HttpOnly; Secure; SameSite=Strict`;
  const base = await startServer(t, { humanAuthApi: { async handle(input) { calls.push(input); return { status: 201, body: { session: { version: 1 }, csrf_token: "C".repeat(43) }, headers: { "Set-Cookie": cookie } }; } } });
  const response = await fetch(`${base}${SESSION_RESUME_PATH}`, {
    method: "POST",
    headers: { origin: ORIGIN, cookie, "content-type": "application/json" },
    body: "{}"
  });
  assert.equal(response.status, 201);
  assert.equal(response.headers.get("set-cookie"), cookie);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, SESSION_RESUME_PATH);
  assert.equal(calls[0].method, "POST");

  for (const suffix of ["/", "?unexpected=1"]) {
    const rejected = await fetch(`${base}${SESSION_RESUME_PATH}${suffix}`, { method: "POST", headers: { origin: ORIGIN, cookie, "content-type": "application/json" }, body: "{}" });
    assert.equal(rejected.status, 404, suffix);
  }
  assert.equal(calls.length, 1);
});

test("routes exact organization and invitation paths, forwarding queries only for lists", async (t) => {
  const calls = [];
  const base = await startServer(t, {
    humanAuthApi: {
      async handle(input) {
        calls.push(input);
        return { status: 200, body: { ok: true }, headers: { "Cache-Control": "no-store, max-age=0" } };
      }
    }
  });
  const headers = { origin: ORIGIN, cookie: SESSION_COOKIE, "agentpass-csrf": CSRF_TOKEN, "content-type": "application/json" };
  const memberList = `${ORGANIZATIONS_PATH}/${ORGANIZATION_ID}/members?limit=10&cursor=next`;
  const listResponse = await fetch(`${base}${memberList}`, { headers });
  assert.equal(listResponse.status, 200);
  assert.equal(calls.at(-1).url, memberList);

  const createBody = JSON.stringify({ name: "Acme" });
  const createResponse = await fetch(`${base}${ORGANIZATIONS_PATH}`, { method: "POST", headers: { ...headers, "idempotency-key": "organization-create-1" }, body: createBody });
  assert.equal(createResponse.status, 200);
  assert.equal(calls.at(-1).url, ORGANIZATIONS_PATH);
  assert.equal(Buffer.from(calls.at(-1).body).toString(), createBody);

  const acceptResponse = await fetch(`${base}${ACCEPT_INVITATION_PATH}`, { method: "POST", headers, body: JSON.stringify({ one_time_token: "A".repeat(43) }) });
  assert.equal(acceptResponse.status, 200);
  assert.equal(calls.at(-1).url, ACCEPT_INVITATION_PATH);

  const before = calls.length;
  for (const path of [
    `${ORGANIZATIONS_PATH}/?limit=1`,
    `${ORGANIZATIONS_PATH}/${ORGANIZATION_ID}?unexpected=1`,
    `${ORGANIZATIONS_PATH}/${ORGANIZATION_ID}/members/`,
    `${ACCEPT_INVITATION_PATH}?unexpected=1`
  ]) {
    const method = path.endsWith("members/") ? "GET" : "POST";
    const response = await fetch(`${base}${path}`, { method, headers, ...(method === "GET" ? {} : { body: "{}" }) });
    assert.equal(response.status, 404, path);
  }
  assert.equal(calls.length, before);
});

test("passes the session-clearing cookie only when the current session is revoked", async (t) => {
  const calls = { listCredentials: [], renameCredential: [], revokeCredential: [], listSessions: [], revokeSession: [] };
  const base = await startServer(t, { humanAuthApi: managementApi({ calls }) });
  const headers = managementHeaders();
  const body = JSON.stringify({ expected_version: 1 });

  const currentResponse = await fetch(`${base}${MANAGEMENT_SESSIONS_PATH}/${CURRENT_SESSION_ID}/revoke`, { method: "POST", headers, body });
  assert.equal(currentResponse.status, 200);
  assert.equal(currentResponse.headers.get("set-cookie"), "__Host-agentpass_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0");

  const otherResponse = await fetch(`${base}${MANAGEMENT_SESSIONS_PATH}/${OTHER_SESSION_ID}/revoke`, { method: "POST", headers, body });
  assert.equal(otherResponse.status, 200);
  assert.equal(otherResponse.headers.get("set-cookie"), null);
  assert.deepEqual(calls.revokeSession.map((input) => input.target_session_id), [CURRENT_SESSION_ID, OTHER_SESSION_ID]);
});

test("bounds the human-auth body before invoking the adapter", async (t) => {
  let calls = 0;
  const base = await startServer(t, { humanAuthApi: { handle: async () => { calls += 1; return { status: 200, body: { ok: true }, headers: {} }; } } });
  const accepted = await fetch(`${base}${OPTIONS_PATH}`, { method: "POST", headers: { "content-type": "application/json" }, body: "x".repeat(64 * 1024) });
  assert.equal(accepted.status, 200);
  assert.equal(calls, 1);
  const rejected = await fetch(`${base}${OPTIONS_PATH}`, { method: "POST", headers: { "content-type": "application/json" }, body: "x".repeat(64 * 1024 + 1) });
  assert.equal(rejected.status, 413);
  assert.equal((await rejected.json()).error.code, "request_too_large");
  assert.equal(calls, 1);
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
