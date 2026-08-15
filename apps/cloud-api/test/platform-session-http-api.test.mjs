import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  createPlatformSessionHttpApi,
  PLATFORM_SESSION_HTTP_ERROR_CODES,
  PLATFORM_SESSION_HTTP_PATHS
} from "../src/platform-session-http-api.mjs";
import {
  PLATFORM_SESSION_COOKIE_NAME,
  PLATFORM_SESSION_CSRF_HEADER,
  hashPlatformSessionToken
} from "../src/platform-session-transport.mjs";

const ORIGIN = "https://console.agentpass.test";
const IDS = Object.freeze({
  principal: "11111111-1111-4111-8111-111111111111",
  member: "22222222-2222-4222-8222-222222222222",
  organization: "33333333-3333-4333-8333-333333333333",
  assignment: "44444444-4444-4444-8444-444444444444",
  challenge: "55555555-5555-4555-8555-555555555555",
  session: "66666666-6666-4666-8666-666666666666",
  jti: "77777777-7777-4777-8777-777777777777"
});
const CREDENTIAL_ID = Buffer.alloc(32, 7).toString("base64url");
const BEARER = Buffer.alloc(32, 1).toString("base64url");
const CSRF = Buffer.alloc(32, 2).toString("base64url");
const AUTHORITY = Object.freeze({
  principal_id: IDS.principal,
  member_id: IDS.member,
  organization_id: IDS.organization,
  assignment_id: IDS.assignment,
  authority_generation: 4,
  operation: "platform.promotion.issue",
  capability: "platform.promotion.issue",
  rp_id: "console.agentpass.test",
  origin: ORIGIN,
  request_digest_sha256: "ab".repeat(32),
  allowed_credential_ids: [CREDENTIAL_ID],
  user_verification: "required"
});

function jsonRequest(path, body, headers = {}) {
  return {
    method: "POST",
    url: path,
    headers: {
      Origin: ORIGIN,
      "Content-Type": "application/json",
      ...headers
    },
    body: JSON.stringify(body)
  };
}

function serviceFixture(overrides = {}) {
  const calls = { bootstrap: [], authority: [], begin: [], verify: [], revoke: [] };
  const ceremony = {
    async begin(context) {
      calls.begin.push(context);
      return {
        version: 1,
        type: "agentpass.platform-session-challenge",
        challenge_id: IDS.challenge,
        challenge: Buffer.alloc(32, 3).toString("base64url"),
        jti: IDS.jti,
        platform_session_id: IDS.session,
        ...AUTHORITY,
        issued_at: "2026-08-15T00:00:00.000Z",
        expires_at: "2026-08-15T00:02:00.000Z",
        one_use: true
      };
    },
    async verify(input) {
      calls.verify.push(input);
      return {
        session: {
          session_id: IDS.session,
          principal_id: IDS.principal,
          credential_id: "internal-credential-id",
          status: "active"
        },
        session_bearer: BEARER,
        csrf_token: CSRF,
        challenge_id: IDS.challenge,
        authenticated_at: "2026-08-15T00:00:00.000Z"
      };
    }
  };
  const api = createPlatformSessionHttpApi({
    webauthnService: ceremony,
    authenticateBootstrap: async (input) => {
      calls.bootstrap.push(input);
      return { user_id: IDS.member };
    },
    resolveAuthorityContext: async (input) => {
      calls.authority.push(input);
      return AUTHORITY;
    },
    revokeService: {
      bearerBound: true,
      acceptsSessionMaterialHash: true,
      async revokeSelf(input) {
        calls.revoke.push(input);
        return { revoked: true };
      }
    },
    origin: ORIGIN,
    ...overrides
  });
  return { api, calls };
}

test("challenge endpoint supplies only trusted server authority and rejects body fields", async () => {
  const { api, calls } = serviceFixture();
  const result = await api.handle(jsonRequest(PLATFORM_SESSION_HTTP_PATHS.challenge, {}));

  assert.equal(result.status, 201);
  assert.equal(result.body.challenge_id, IDS.challenge);
  assert.equal(calls.bootstrap.length, 1);
  assert.deepEqual(calls.begin[0], AUTHORITY);
  assert.equal(calls.authority[0].phase, "challenge");
  assert.equal("body" in calls.authority[0].request, false);

  const rejected = await api.handle(jsonRequest(PLATFORM_SESSION_HTTP_PATHS.challenge, { principal_id: IDS.principal }));
  assert.equal(rejected.status, 400);
  assert.equal(rejected.body.error.code, PLATFORM_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST);
  assert.equal(calls.begin.length, 1);
});

test("assertion endpoint keeps bearer in HttpOnly cookie and projects no internal secrets", async () => {
  const { api, calls } = serviceFixture();
  const body = {
    version: 1,
    type: "agentpass.platform-session-assertion",
    challenge_id: IDS.challenge,
    jti: IDS.jti,
    credential_id: CREDENTIAL_ID,
    client_data_json: Buffer.from("client-data").toString("base64url"),
    authenticator_data: Buffer.from("authenticator-data").toString("base64url"),
    signature: Buffer.from("signature").toString("base64url")
  };
  const result = await api.handle(jsonRequest(PLATFORM_SESSION_HTTP_PATHS.assertion, body));

  assert.equal(result.status, 201);
  assert.equal(result.body.session.session_id, IDS.session);
  assert.equal(result.body.session.credential_id, undefined);
  assert.equal(result.body.csrf_token, CSRF);
  assert.equal(JSON.stringify(result.body).includes(BEARER), false);
  assert.match(result.headers["Set-Cookie"], new RegExp(`^${PLATFORM_SESSION_COOKIE_NAME}=${BEARER}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=900$`));
  assert.equal(calls.verify[0].principal_id, IDS.principal);
  assert.equal(calls.verify[0].request_digest_sha256, AUTHORITY.request_digest_sha256);
  assert.deepEqual(calls.verify[0].allowed_credential_ids, [CREDENTIAL_ID]);

  const duplicate = await api.handle({
    ...jsonRequest(PLATFORM_SESSION_HTTP_PATHS.assertion, body),
    body: `{"version":1,"type":"agentpass.platform-session-assertion","challenge_id":"${IDS.challenge}","jti":"${IDS.jti}","credential_id":"${CREDENTIAL_ID}","client_data_json":"YQ","authenticator_data":"Yg","signature":"Yw","signature":"ZA"}`
  });
  assert.equal(duplicate.status, 400);
  assert.equal(calls.verify.length, 1);
});

test("origin, forbidden identity headers, and ambiguous cookies fail closed", async () => {
  const { api } = serviceFixture();
  const base = jsonRequest(PLATFORM_SESSION_HTTP_PATHS.challenge, {});
  assert.equal((await api.handle({ ...base, headers: { ...base.headers, Origin: "https://evil.test" } })).status, 403);
  assert.equal((await api.handle({ ...base, headers: { "Content-Type": "application/json" } })).status, 403);
  assert.equal((await api.handle({ ...base, headers: { ...base.headers, Authorization: "Bearer nope" } })).status, 400);
  assert.equal((await api.handle({ ...base, headers: { ...base.headers, Cookie: `${PLATFORM_SESSION_COOKIE_NAME}=bad` } })).status, 400);
  assert.equal((await api.handle({ ...base, headers: { ...base.headers, Cookie: `${PLATFORM_SESSION_COOKIE_NAME}=${BEARER}; ${PLATFORM_SESSION_COOKIE_NAME}=${BEARER}` } })).status, 400);
  assert.equal((await api.handle({ ...base, url: `${PLATFORM_SESSION_HTTP_PATHS.challenge}?alias=1` })).status, 400);
  assert.equal((await api.handle({ ...base, url: `${PLATFORM_SESSION_HTTP_PATHS.challenge}#alias` })).status, 400);
  assert.equal((await api.handle({ ...base, headers: { ...base.headers, "Content-Type": "text/plain" } })).status, 400);
});

test("self-revoke requires bearer-bound service and passes only the transport hash", async () => {
  const { api, calls } = serviceFixture();
  const result = await api.handle({
    method: "POST",
    url: PLATFORM_SESSION_HTTP_PATHS.revoke,
    headers: {
      Origin: ORIGIN,
      Cookie: `${PLATFORM_SESSION_COOKIE_NAME}=${BEARER}`,
      [PLATFORM_SESSION_CSRF_HEADER]: CSRF
    },
    body: ""
  });

  assert.equal(result.status, 200);
  assert.deepEqual(calls.revoke[0].session_material_hash, hashPlatformSessionToken(BEARER));
  assert.equal(calls.revoke[0].csrf_token, CSRF);
  assert.equal("session_material" in calls.revoke[0], false);
  assert.match(result.headers["Set-Cookie"], new RegExp(`^${PLATFORM_SESSION_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0$`));

  const missingCsrf = await api.handle({
    method: "POST",
    url: PLATFORM_SESSION_HTTP_PATHS.revoke,
    headers: { Origin: ORIGIN, Cookie: `${PLATFORM_SESSION_COOKIE_NAME}=${BEARER}` },
    body: ""
  });
  assert.equal(missingCsrf.status, 403);
});

test("self-revoke is not exposed when no safe injected service exists", async () => {
  const { api } = serviceFixture({ revokeService: undefined });
  const result = await api.handle({
    method: "POST",
    url: PLATFORM_SESSION_HTTP_PATHS.revoke,
    headers: { Origin: ORIGIN, Cookie: `${PLATFORM_SESSION_COOKIE_NAME}=${BEARER}`, [PLATFORM_SESSION_CSRF_HEADER]: CSRF },
    body: ""
  });
  assert.equal(result.status, 503);
  assert.equal(result.body.error.code, PLATFORM_SESSION_HTTP_ERROR_CODES.REVOKE_UNAVAILABLE);
  assert.equal(result.headers["Cache-Control"], "no-store, max-age=0");
});

test("the boundary rejects unsafe cookie output from a ceremony implementation", async () => {
  const { api } = serviceFixture({
    webauthnService: {
      begin: async () => ({
        version: 1,
        type: "agentpass.platform-session-challenge",
        challenge_id: IDS.challenge,
        challenge: Buffer.alloc(32, 3).toString("base64url"),
        jti: IDS.jti,
        platform_session_id: IDS.session,
        ...AUTHORITY,
        issued_at: "2026-08-15T00:00:00.000Z",
        expires_at: "2026-08-15T00:02:00.000Z",
        one_use: true
      }),
      verify: async () => ({
        session: { session_id: IDS.session },
        session_bearer: BEARER,
        csrf_token: CSRF,
        cookie: "platform=unsafe; Domain=evil.test"
      })
    }
  });
  const body = {
    version: 1,
    type: "agentpass.platform-session-assertion",
    challenge_id: IDS.challenge,
    jti: IDS.jti,
    credential_id: CREDENTIAL_ID,
    client_data_json: "YQ",
    authenticator_data: "Yg",
    signature: "Yw"
  };
  const result = await api.handle(jsonRequest(PLATFORM_SESSION_HTTP_PATHS.assertion, body));
  assert.equal(result.status, 503);
  assert.equal(result.body.error.code, PLATFORM_SESSION_HTTP_ERROR_CODES.ASSERTION_FAILED);
  assert.equal(result.headers["Set-Cookie"], undefined);
});

test("request body and content limits are bounded before the ceremony", async () => {
  const { api, calls } = serviceFixture({ maxBodyBytes: 1_024 });
  const result = await api.handle({
    ...jsonRequest(PLATFORM_SESSION_HTTP_PATHS.challenge, {}),
    headers: { Origin: ORIGIN, "Content-Type": "application/json", "Content-Length": "1025" }
  });
  assert.equal(result.status, 413);
  assert.equal(calls.begin.length, 0);
  assert.equal(crypto.createHash("sha256").update(BEARER).digest("hex").length, 64);
});
