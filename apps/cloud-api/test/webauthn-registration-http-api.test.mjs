import assert from "node:assert/strict";
import test from "node:test";

import {
  createWebAuthnRegistrationHttpApi,
  WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES,
  WEBAUTHN_REGISTRATION_HTTP_PATHS
} from "../src/human-auth/registration-http-api.mjs";
import { WebAuthnRegistrationError, WEBAUTHN_REGISTRATION_ERROR_CODES } from "../src/human-auth/webauthn/registration.mjs";

const ORIGIN = "https://console.agentpass.test";
const SESSION_ID = "11111111-1111-4111-8111-111111111111";
const MEMBER_ID = "22222222-2222-4222-8222-222222222222";
const ORGANIZATION_ID = "33333333-3333-4333-8333-333333333333";
const CHALLENGE_ID = "44444444-4444-4444-8444-444444444444";
const CREDENTIAL_ID = Buffer.alloc(16, 1).toString("base64url");
const CHALLENGE = Buffer.alloc(32, 9).toString("base64url");
const RECENT_AUTH_ID = "55555555-5555-4555-8555-555555555555";
const abuseControls = Object.freeze({ async authorize() { return { allowed: true }; } });

function session() {
  return { version: 1, session_id: SESSION_ID, member_id: MEMBER_ID, organization_id: ORGANIZATION_ID, role: "owner", created_at: "2026-08-12T00:00:00.000Z", expires_at: "2026-08-12T08:00:00.000Z", recent_auth_at: null };
}

function fixture(overrides = {}) {
  const calls = { authenticate: [], begin: [], verify: [] };
  const service = {
    async begin(input) { calls.begin.push(input); if (overrides.beginError) throw overrides.beginError; return { challenge_id: CHALLENGE_ID, options: { challenge: CHALLENGE, rp: { id: "console.agentpass.test", name: "AgentPass" }, user: { id: "user", name: "owner@example.test", displayName: "Owner" }, pubKeyCredParams: [{ type: "public-key", alg: -7 }], authenticatorSelection: { userVerification: "required" }, extensions: { credProps: true }, hints: [], excludeCredentials: [] } }; },
    async verify(input) { calls.verify.push(input); if (overrides.verifyError) throw overrides.verifyError; return { credential_id: CREDENTIAL_ID, registered_at: "2026-08-12T00:00:00.000Z" }; }
  };
  const api = createWebAuthnRegistrationHttpApi({
    origin: ORIGIN,
    humanSession: {
      expectedOrigin: ORIGIN,
      async authenticateRequest(input) { calls.authenticate.push(input); if (overrides.sessionError) throw overrides.sessionError; return { session: session() }; }
    },
    registrationService: service,
    abuseControls,
    basePath: "/api/auth"
  });
  return { api, calls };
}

function request(path, body, headers = {}) {
  return { method: "POST", url: path, headers: { origin: ORIGIN, cookie: "__Host-agentpass_session=" + "a".repeat(43), "agentpass-csrf": "b".repeat(43), "content-type": "application/json", ...headers }, body: JSON.stringify(body) };
}

function browserCredential(overrides = {}) {
  return {
    type: "public-key",
    id: CREDENTIAL_ID,
    rawId: CREDENTIAL_ID,
    response: {
      clientDataJSON: Buffer.from(JSON.stringify({ type: "webauthn.create", challenge: CHALLENGE, origin: ORIGIN, crossOrigin: false })).toString("base64url"),
      attestationObject: Buffer.alloc(96, 7).toString("base64url"),
      transports: ["internal"]
    },
    clientExtensionResults: {},
    ...overrides
  };
}

test("registration options enforce exact origin/session CSRF and return no-store options", async () => {
  const { api, calls } = fixture();
  const result = await api.handle(request("/api/auth/webauthn/registration/options", { organization_id: ORGANIZATION_ID }));
  assert.equal(result.status, 200);
  assert.equal(result.headers["Cache-Control"], "no-store, max-age=0");
  assert.equal(result.body.challenge_id, CHALLENGE_ID);
  assert.equal(result.body.options.authenticatorSelection.userVerification, "required");
  assert.equal(calls.authenticate.length, 1);
  assert.equal(calls.authenticate[0].origin, ORIGIN);
  assert.equal(calls.authenticate[0].csrfToken, "b".repeat(43));
  assert.equal(calls.begin[0].session.session_id, SESSION_ID);
  assert.equal(calls.begin[0].organization_id, ORGANIZATION_ID);
});

test("registration forwards the recent-auth header only as a service authorization input", async () => {
  const { api, calls } = fixture();
  const optionsResult = await api.handle(request("/api/auth/webauthn/registration/options", { organization_id: ORGANIZATION_ID }, { "agentpass-recent-auth": RECENT_AUTH_ID }));
  assert.equal(optionsResult.status, 200);
  assert.equal(calls.begin[0].recent_auth, RECENT_AUTH_ID);

  const verifyResult = await api.handle(request("/api/auth/webauthn/registration/verify", { organization_id: ORGANIZATION_ID, challenge_id: CHALLENGE_ID, credential: browserCredential() }, { "agentpass-recent-auth": RECENT_AUTH_ID }));
  assert.equal(verifyResult.status, 201);
  assert.equal(calls.verify[0].recent_auth, RECENT_AUTH_ID);
  assert.equal(Object.hasOwn(calls.verify[0].credential, "recent_auth"), false);
});

test("registration parses Buffer and Uint8Array JSON bodies from the real Node server adapter", async () => {
  for (const encode of [Buffer.from, (value) => new Uint8Array(Buffer.from(value))]) {
    const { api } = fixture();
    const input = request("/api/auth/webauthn/registration/options", { organization_id: ORGANIZATION_ID });
    input.body = encode(input.body);
    const result = await api.handle(input);
    assert.equal(result.status, 200);
    assert.equal(result.body.challenge_id, CHALLENGE_ID);
  }
});
test("registration verify accepts only the exact browser credential schema and never forwards unknown fields", async () => {
  const { api, calls } = fixture();
  const result = await api.handle(request("/api/auth/webauthn/registration/verify", { organization_id: ORGANIZATION_ID, challenge_id: CHALLENGE_ID, credential: browserCredential() }));
  assert.equal(result.status, 201);
  assert.deepEqual(result.body, { credential_id: CREDENTIAL_ID, registered_at: "2026-08-12T00:00:00.000Z" });
  assert.deepEqual(Object.keys(calls.verify[0].credential).sort(), ["attestation_object", "client_data_json", "credential_id", "transports"]);
  assert.equal(calls.verify[0].credential.client_data_json.includes(CHALLENGE), false);

  const unknown = await api.handle(request("/api/auth/webauthn/registration/verify", { organization_id: ORGANIZATION_ID, challenge_id: CHALLENGE_ID, credential: { ...browserCredential(), unexpected: "reject" } }));
  assert.equal(unknown.status, 400);
  assert.equal(unknown.body.error.code, WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST);
});

test("registration accepts signed clientData extension members from real browsers", async () => {
  const { api } = fixture();
  const credential = browserCredential();
  credential.response.clientDataJSON = Buffer.from(JSON.stringify({ type: "webauthn.create", challenge: CHALLENGE, origin: ORIGIN, crossOrigin: false, other_keys_can_be_added_here: "do not compare clientDataJSON against a template" })).toString("base64url");
  assert.equal((await api.handle(request("/api/auth/webauthn/registration/verify", { organization_id: ORGANIZATION_ID, challenge_id: CHALLENGE_ID, credential }))).status, 201);
});

test("registration HTTP boundary rejects origin, CSRF, tenant mismatch, malformed bodies, and wrong methods", async () => {
  const noOrigin = fixture();
  const noOriginRequest = request("/api/auth/webauthn/registration/options", { organization_id: ORGANIZATION_ID });
  delete noOriginRequest.headers.origin;
  const originResult = await noOrigin.api.handle(noOriginRequest);
  assert.equal(originResult.status, 403);
  assert.equal(originResult.body.error.code, WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED);

  const csrf = fixture({ sessionError: { code: "csrf_token_required" } });
  const csrfResult = await csrf.api.handle(request("/api/auth/webauthn/registration/options", { organization_id: ORGANIZATION_ID }));
  assert.equal(csrfResult.status, 403);
  assert.equal(csrfResult.body.error.code, WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.CSRF_FAILED);

  const crossTenant = fixture();
  const crossResult = await crossTenant.api.handle(request("/api/auth/webauthn/registration/options", { organization_id: "55555555-5555-4555-8555-555555555555" }));
  assert.equal(crossResult.status, 400);
  assert.equal(crossResult.body.error.code, WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST);

  const get = await fixture().api.handle({ method: "GET", url: "/api/auth/webauthn/registration/options", headers: {} });
  assert.equal(get.status, 405);
  assert.equal(get.headers.Allow, "POST");

  const malformed = await fixture().api.handle(request("/api/auth/webauthn/registration/options", { organization_id: ORGANIZATION_ID, extra: true }));
  assert.equal(malformed.status, 400);
  assert.equal(malformed.body.error.code, WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST);
});

test("registration HTTP errors are stable and redact verifier details", async () => {
  const { api } = fixture({ verifyError: new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.VERIFICATION_FAILED, "attestation secret and challenge") });
  const result = await api.handle(request("/api/auth/webauthn/registration/verify", { organization_id: ORGANIZATION_ID, challenge_id: CHALLENGE_ID, credential: browserCredential() }));
  assert.equal(result.status, 422);
  assert.deepEqual(result.body.error, { code: WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.ATTESTATION_INVALID, message: "The WebAuthn registration response is invalid" });
  assert.equal(JSON.stringify(result.body).includes("attestation secret"), false);
  assert.equal(JSON.stringify(result.body).includes(CHALLENGE), false);
});

test("registration HTTP maps challenge replay and credential conflicts without exposing service errors", async () => {
  const challenge = fixture({ verifyError: new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_REPLAYED, "raw challenge") });
  const challengeResult = await challenge.api.handle(request("/api/auth/webauthn/registration/verify", { organization_id: ORGANIZATION_ID, challenge_id: CHALLENGE_ID, credential: browserCredential() }));
  assert.equal(challengeResult.status, 409);
  assert.equal(challengeResult.body.error.code, WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.CHALLENGE_INVALID);

  const conflict = fixture({ verifyError: new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.CREDENTIAL_EXISTS) });
  const conflictResult = await conflict.api.handle(request("/api/auth/webauthn/registration/verify", { organization_id: ORGANIZATION_ID, challenge_id: CHALLENGE_ID, credential: browserCredential() }));
  assert.equal(conflictResult.status, 409);
  assert.equal(conflictResult.body.error.code, WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.CREDENTIAL_EXISTS);
});

test("registration HTTP maps step-up failures to stable authentication responses", async () => {
  const required = fixture({ beginError: new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.RECENT_AUTH_REQUIRED) });
  const requiredResult = await required.api.handle(request("/api/auth/webauthn/registration/options", { organization_id: ORGANIZATION_ID }));
  assert.equal(requiredResult.status, 428);
  assert.equal(requiredResult.body.error.code, WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.RECENT_AUTH_REQUIRED);

  const unavailable = fixture({ verifyError: new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.RECENT_AUTH_UNAVAILABLE) });
  const unavailableResult = await unavailable.api.handle(request("/api/auth/webauthn/registration/verify", { organization_id: ORGANIZATION_ID, challenge_id: CHALLENGE_ID, credential: browserCredential() }));
  assert.equal(unavailableResult.status, 503);
  assert.equal(unavailableResult.body.error.code, WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.RECENT_AUTH_UNAVAILABLE);
});
