import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  createHumanAuthHttpApi,
  HUMAN_AUTH_HTTP_ERROR_CODES,
  HUMAN_AUTH_HTTP_PATHS
} from "../src/human-auth/http-api.mjs";
import { WebAuthnCeremonyError, WEBAUTHN_ERROR_CODES } from "../src/human-auth/webauthn/ceremony.mjs";
import { HumanAuthAbuseControlError, HUMAN_AUTH_ABUSE_ERROR_CODES } from "../src/human-auth/rate-limit.mjs";

const ORIGIN = "https://console.agentpass.test";
const RP_ID = "console.agentpass.test";
const ORGANIZATION_ID = "33333333-3333-4333-8333-333333333333";
const SESSION_ID = "11111111-1111-4111-8111-111111111111";
const MEMBER_ID = "22222222-2222-4222-8222-222222222222";
const CHALLENGE_ID = "44444444-4444-4444-8444-444444444444";
const CREDENTIAL_ID = Buffer.from("credential-01").toString("base64url");
const CHALLENGE = Buffer.alloc(32, 9).toString("base64url");
const NOW = Date.parse("2026-08-12T00:00:00.000Z");
const abuseControls = Object.freeze({ async authorize() { return { allowed: true }; } });

function session() {
  return {
    version: 1,
    session_id: SESSION_ID,
    member_id: MEMBER_ID,
    organization_id: ORGANIZATION_ID,
    role: "owner",
    created_at: "2026-08-12T00:00:00.000Z",
    expires_at: "2026-08-12T08:00:00.000Z",
    recent_auth_at: null
  };
}

function fixture(overrides = {}) {
  const calls = { authenticate: [], begin: [], verify: [], allowList: [] };
  const services = {
    humanSession: {
      expectedOrigin: ORIGIN,
      async authenticateRequest(input) {
        calls.authenticate.push(input);
        if (overrides.sessionError) throw overrides.sessionError;
        return { session: session() };
      }
    },
    recentAuthService: {
      begin(input) {
        calls.begin.push(input);
        if (overrides.beginError) throw overrides.beginError;
        return {
          challenge_id: CHALLENGE_ID,
          challenge: CHALLENGE,
          challenge_expires_at: new Date(NOW + 120_000).toISOString(),
          rp_id: RP_ID,
          origin: ORIGIN,
          user_verification: "required"
        };
      },
      async verify(input) {
        calls.verify.push(input);
        if (overrides.verifyError) throw overrides.verifyError;
        return {
          authorization_id: CHALLENGE_ID,
          authenticated_at: NOW,
          operation: input.operation
        };
      }
    },
    credentialAllowList: {
      async listCredentials(input) {
        calls.allowList.push(input);
        if (overrides.allowListError) throw overrides.allowListError;
        return overrides.allowList ?? [{ id: CREDENTIAL_ID, transports: ["internal"] }];
      }
    }
  };
  return {
    calls,
    api: createHumanAuthHttpApi({ ...services, abuseControls: overrides.abuseControls ?? abuseControls, rpId: RP_ID, now: () => NOW, ...(overrides.api ?? {}) })
  };
}

function request(path, body, headers = {}) {
  return {
    method: "POST",
    url: path,
    headers: {
      origin: ORIGIN,
      cookie: "__Host-agentpass_session=" + "a".repeat(43),
      "agentpass-csrf": "b".repeat(43),
      "content-type": "application/json",
      ...headers
    },
    body: JSON.stringify(body)
  };
}

function clientData(challenge = CHALLENGE, origin = ORIGIN, extra = {}) {
  return Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin, crossOrigin: false, ...extra })).toString("base64url");
}

function browserCredential(overrides = {}) {
  return {
    type: "public-key",
    id: CREDENTIAL_ID,
    rawId: CREDENTIAL_ID,
    response: {
      clientDataJSON: clientData(),
      authenticatorData: Buffer.concat([crypto.createHash("sha256").update(RP_ID).digest(), Buffer.from([5, 0, 0, 0, 1])]).toString("base64url"),
      signature: Buffer.alloc(64, 7).toString("base64url"),
      userHandle: null
    },
    clientExtensionResults: {},
    ...overrides
  };
}

function optionsBody(overrides = {}) {
  return { organization_id: ORGANIZATION_ID, operation: "device.enrollment.issue", ...overrides };
}

function verifyBody(overrides = {}) {
  return { organization_id: ORGANIZATION_ID, operation: "device.enrollment.issue", challenge_id: CHALLENGE_ID, credential: browserCredential(), ...overrides };
}

test("creates authentication options from the session-bound server allow list", async () => {
  const { api, calls } = fixture();
  const result = await api.handle(request(HUMAN_AUTH_HTTP_PATHS.authenticationOptions, optionsBody()));

  assert.equal(result.status, 200);
  assert.equal(result.headers["Cache-Control"], "no-store, max-age=0");
  assert.equal(result.headers["Pragma"], "no-cache");
  assert.deepEqual(result.body, {
    challenge_id: CHALLENGE_ID,
    options: {
      challenge: CHALLENGE,
      rpId: RP_ID,
      userVerification: "required",
      allowCredentials: [{ id: CREDENTIAL_ID, type: "public-key", transports: ["internal"] }]
    }
  });
  assert.equal(calls.authenticate.length, 1);
  assert.equal(calls.begin[0].session.session_id, SESSION_ID);
  assert.equal(calls.begin[0].organization_id, ORGANIZATION_ID);
  assert.equal(calls.allowList[0].operation, "device.enrollment.issue");
});

test("maps shared limiter denial to a bounded, secret-free HTTP response", async () => {
  const { api } = fixture({
    abuseControls: { async authorize() { throw new HumanAuthAbuseControlError(HUMAN_AUTH_ABUSE_ERROR_CODES.RATE_LIMITED, { retryAfterSeconds: 60 }); } }
  });
  const result = await api.handle(request(HUMAN_AUTH_HTTP_PATHS.authenticationOptions, optionsBody()));
  assert.equal(result.status, 429);
  assert.equal(result.headers["Retry-After"], "60");
  assert.deepEqual(result.body.error, { code: HUMAN_AUTH_ABUSE_ERROR_CODES.RATE_LIMITED, message: "Human authentication rate limit exceeded" });
  assert.equal(JSON.stringify(result.body).includes("password"), false);
});

test("requires an exact browser origin and session-bound CSRF authentication", async () => {
  const missingOrigin = fixture();
  const noOrigin = request(HUMAN_AUTH_HTTP_PATHS.authenticationOptions, optionsBody());
  delete noOrigin.headers.origin;
  const noOriginResult = await missingOrigin.api.handle(noOrigin);
  assert.equal(noOriginResult.status, 403);
  assert.equal(noOriginResult.body.error.code, HUMAN_AUTH_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED);

  const csrf = fixture({ sessionError: { code: "csrf_token_required" } });
  const csrfResult = await csrf.api.handle(request(HUMAN_AUTH_HTTP_PATHS.authenticationOptions, optionsBody()));
  assert.equal(csrfResult.status, 403);
  assert.equal(csrfResult.body.error.code, HUMAN_AUTH_HTTP_ERROR_CODES.CSRF_FAILED);
});

test("rejects unknown fields, cross-organization requests, and non-POST methods", async () => {
  const { api } = fixture();
  const unknown = await api.handle(request(HUMAN_AUTH_HTTP_PATHS.authenticationOptions, { ...optionsBody(), extra: true }));
  assert.equal(unknown.status, 400);
  assert.equal(unknown.body.error.code, HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST);

  const crossTenant = await api.handle(request(HUMAN_AUTH_HTTP_PATHS.authenticationOptions, optionsBody({ organization_id: "55555555-5555-4555-8555-555555555555" })));
  assert.equal(crossTenant.status, 400);
  assert.equal(crossTenant.body.error.code, HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST);

  const get = await api.handle({ method: "GET", url: HUMAN_AUTH_HTTP_PATHS.authenticationOptions, headers: {} });
  assert.equal(get.status, 405);
  assert.equal(get.headers.Allow, "POST");
  assert.equal(get.headers["Cache-Control"], "no-store, max-age=0");
});

test("fails closed when the credential allow list is unavailable, empty, or malformed", async () => {
  const unavailable = fixture({ allowListError: new Error("database down") });
  const unavailableResult = await unavailable.api.handle(request(HUMAN_AUTH_HTTP_PATHS.authenticationOptions, optionsBody()));
  assert.equal(unavailableResult.status, 503);
  assert.equal(unavailableResult.body.error.code, HUMAN_AUTH_HTTP_ERROR_CODES.CREDENTIAL_ALLOW_LIST_UNAVAILABLE);
  assert.equal(unavailable.calls.begin.length, 0);

  const empty = fixture({ allowList: [] });
  const emptyResult = await empty.api.handle(request(HUMAN_AUTH_HTTP_PATHS.authenticationOptions, optionsBody()));
  assert.equal(emptyResult.status, 409);
  assert.equal(emptyResult.body.error.code, HUMAN_AUTH_HTTP_ERROR_CODES.CREDENTIAL_ALLOW_LIST_EMPTY);

  const malformed = fixture({ allowList: [{ id: CREDENTIAL_ID, public_key: "must-not-cross-boundary" }] });
  const malformedResult = await malformed.api.handle(request(HUMAN_AUTH_HTTP_PATHS.authenticationOptions, optionsBody()));
  assert.equal(malformedResult.status, 503);
  assert.equal(malformedResult.body.error.code, HUMAN_AUTH_HTTP_ERROR_CODES.CREDENTIAL_ALLOW_LIST_INVALID);
});

test("extracts the WebAuthn challenge from clientDataJSON and binds verify to session, operation, and credential", async () => {
  const { api, calls } = fixture();
  const result = await api.handle(request(HUMAN_AUTH_HTTP_PATHS.authenticationVerify, verifyBody()));

  assert.equal(result.status, 200);
  assert.deepEqual(result.body, { authorization_id: CHALLENGE_ID });
  assert.equal(calls.verify.length, 1);
  assert.equal(calls.verify[0].session.session_id, SESSION_ID);
  assert.equal(calls.verify[0].assertion.challenge, CHALLENGE);
  assert.equal(calls.verify[0].assertion.challenge_id, CHALLENGE_ID);
  assert.equal(calls.verify[0].assertion.credential_id, CREDENTIAL_ID);
  assert.equal(calls.verify[0].assertion.origin, ORIGIN);
});

test("accepts signed WebAuthn clientData extension members from real browsers", async () => {
  const { api } = fixture();
  const credential = browserCredential();
  credential.response.clientDataJSON = clientData(CHALLENGE, ORIGIN, { other_keys_can_be_added_here: "do not compare clientDataJSON against a template" });
  assert.equal((await api.handle(request(HUMAN_AUTH_HTTP_PATHS.authenticationVerify, verifyBody({ credential })))).status, 200);
});

test("rejects challenge substitution, wrong origin, and credentials outside the fresh allow list", async () => {
  const challenge = fixture({ verifyError: new WebAuthnCeremonyError(WEBAUTHN_ERROR_CODES.CHALLENGE_MISMATCH) });
  const substituted = await challenge.api.handle(request(HUMAN_AUTH_HTTP_PATHS.authenticationVerify, verifyBody({ credential: browserCredential({ response: { ...browserCredential().response, clientDataJSON: clientData(Buffer.alloc(32, 8).toString("base64url")) } }) })));
  assert.equal(substituted.status, 409);
  assert.equal(substituted.body.error.code, HUMAN_AUTH_HTTP_ERROR_CODES.CHALLENGE_INVALID);
  assert.equal(challenge.calls.verify.length, 1);

  const wrongOrigin = fixture();
  const badOrigin = await wrongOrigin.api.handle(request(HUMAN_AUTH_HTTP_PATHS.authenticationVerify, verifyBody({ credential: browserCredential({ response: { ...browserCredential().response, clientDataJSON: clientData(CHALLENGE, "https://evil.test") } }) })));
  assert.equal(badOrigin.status, 400);
  assert.equal(badOrigin.body.error.code, HUMAN_AUTH_HTTP_ERROR_CODES.CHALLENGE_INVALID);

  const notAllowed = fixture({ allowList: [{ id: Buffer.from("other-credential").toString("base64url") }] });
  const notAllowedResult = await notAllowed.api.handle(request(HUMAN_AUTH_HTTP_PATHS.authenticationVerify, verifyBody()));
  assert.equal(notAllowedResult.status, 401);
  assert.equal(notAllowedResult.body.error.code, HUMAN_AUTH_HTTP_ERROR_CODES.CREDENTIAL_NOT_ALLOWED);
  assert.equal(notAllowed.calls.verify.length, 0);
});

test("maps one-time challenge failures to a stable public error and never leaks verifier details", async () => {
  const fixtureValue = fixture({ verifyError: new WebAuthnCeremonyError(WEBAUTHN_ERROR_CODES.CHALLENGE_REPLAYED, "internal detail") });
  const result = await fixtureValue.api.handle(request(HUMAN_AUTH_HTTP_PATHS.authenticationVerify, verifyBody()));
  assert.equal(result.status, 409);
  assert.deepEqual(result.body.error, {
    code: HUMAN_AUTH_HTTP_ERROR_CODES.CHALLENGE_INVALID,
    message: "The WebAuthn challenge is invalid"
  });
  assert.equal(JSON.stringify(result.body).includes("internal detail"), false);
});

test("supports Request-like JSON input and Node-style response output", async () => {
  const { api } = fixture();
  const requestLike = {
    method: "POST",
    url: HUMAN_AUTH_HTTP_PATHS.authenticationOptions,
    headers: new Headers(request(HUMAN_AUTH_HTTP_PATHS.authenticationOptions, optionsBody()).headers),
    async json() { return optionsBody(); }
  };
  const result = await api.handle(requestLike);
  assert.equal(result.status, 200);
  assert.deepEqual(await result.json(), result.body);
  assert.match(await result.text(), /challenge_id/);

  let written;
  const nodeResponse = {
    setHeader(name, value) { written ??= { headers: {} }; written.headers[name] = value; },
    end(body) { written ??= { headers: {} }; written.body = JSON.parse(body); },
    statusCode: 0
  };
  const nodeResult = await api.handle(request(HUMAN_AUTH_HTTP_PATHS.authenticationOptions, optionsBody()), nodeResponse);
  assert.equal(nodeResult.status, 200);
  assert.equal(nodeResponse.statusCode, 200);
  assert.equal(written.body.challenge_id, CHALLENGE_ID);
  assert.equal(written.headers["Cache-Control"], "no-store, max-age=0");
});

test("parses Buffer and Uint8Array JSON bodies from the real Node server adapter", async () => {
  for (const encode of [Buffer.from, (value) => new Uint8Array(Buffer.from(value))]) {
    const { api } = fixture();
    const input = request(HUMAN_AUTH_HTTP_PATHS.authenticationOptions, optionsBody());
    input.body = encode(input.body);
    const result = await api.handle(input);
    assert.equal(result.status, 200);
    assert.equal(result.body.challenge_id, CHALLENGE_ID);
  }
});

test("basePath /api/auth produces the frontend's canonical default routes", async () => {
  const { api } = fixture({ api: { basePath: "/api/auth" } });
  const result = await api.handle(request("/api/auth/webauthn/options", optionsBody()));
  assert.equal(result.status, 200);
  assert.deepEqual(Object.keys(result.body).sort(), ["challenge_id", "options"]);
  assert.equal(api.paths.authenticationOptions, "/webauthn/options");
  assert.equal(api.paths.authenticationVerify, "/webauthn/verify");
});

test("returns no-store for unknown and malformed responses too", async () => {
  const { api } = fixture();
  const notFound = await api.handle({ method: "GET", url: "/not-a-route", headers: {} });
  assert.equal(notFound.status, 404);
  assert.equal(notFound.headers["Cache-Control"], "no-store, max-age=0");

  const malformed = await api.handle(request(HUMAN_AUTH_HTTP_PATHS.authenticationOptions, "not-json"));
  assert.equal(malformed.status, 400);
  assert.equal(malformed.body.error.code, HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST);
  assert.equal(malformed.headers["Cache-Control"], "no-store, max-age=0");
});
