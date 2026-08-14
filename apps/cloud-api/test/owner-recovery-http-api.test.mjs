import test from "node:test";
import assert from "node:assert/strict";

import { OWNER_RECOVERY_OPERATIONS } from "../src/human-auth/recovery/service.mjs";
import {
  OWNER_RECOVERY_HTTP_ERROR_CODES,
  OWNER_RECOVERY_HTTP_PATHS,
  createOwnerRecoveryHttpApi
} from "../src/human-auth/recovery/http-api.mjs";
import { HumanAuthAbuseControlError, HUMAN_AUTH_ABUSE_ERROR_CODES, HUMAN_AUTH_RATE_LIMIT_OPERATIONS } from "../src/human-auth/rate-limit.mjs";

const ORIGIN = "https://console.example.test";
const ORG = "11111111-1111-4111-8111-111111111111";
const SUBJECT = "22222222-2222-4222-8222-222222222222";
const REQUEST = "44444444-4444-4444-8444-444444444444";
const SESSION = "55555555-5555-4555-8555-555555555555";
const CHALLENGE = "77777777-7777-4777-8777-777777777777";
const AUTHORIZATION = "88888888-8888-4888-8888-888888888888";
const SESSION_TOKEN = "R".repeat(43);
const NORMAL_TOKEN = "N".repeat(43);
const CSRF = "C".repeat(43);

const actor = { session_id: SESSION, member_id: SUBJECT, organization_id: ORG, role: "owner" };
const recoverySession = { recovery_session_id: "66666666-6666-4666-8666-666666666666", request_id: REQUEST, member_id: SUBJECT, organization_id: ORG, stage: "session_issued", issued_at: "2026-08-14T00:00:00.000Z", expires_at: "2026-08-15T00:00:00.000Z", idle_expires_at: "2026-08-14T12:00:00.000Z" };
const recovery = { schema_version: 1, kind: "threshold-owner-recovery", request_id: REQUEST, organization_id: ORG, subject_member_id: SUBJECT, state: "pending", threshold: 2, approved_owner_count: 0, approved_at: null, delay_until: null, session_issued_at: null, credential_enrolled_at: null, activated_at: null, expires_at: "2026-08-15T00:00:00.000Z", terminal_reason: null, version: 1, created_at: "2026-08-14T00:00:00.000Z" };

function envelope(overrides = {}) { return { request_id: REQUEST, recovery: { ...recovery, ...overrides } }; }

function makeApi({ abuseControls = undefined } = {}) {
  const calls = [];
  const service = {
    async create(input) { calls.push(["create", input]); return envelope(); },
    async get(input) { calls.push(["get", input]); return envelope(); },
    async approve(input) { calls.push(["approve", input]); return envelope({ state: "approved", approved_owner_count: 1, version: 2 }); },
    async cancel(input) { calls.push(["cancel", input]); return envelope({ state: "cancelled", terminal_reason: "owner_cancelled", version: 2 }); },
    async exchange(input) { calls.push(["exchange", input]); return { request_id: REQUEST, recovery_session: recoverySession, recovery_session_token: SESSION_TOKEN }; },
    async authenticateRecoverySession(input) { calls.push(["authenticateRecoverySession", input]); return { ...recoverySession, stage: input.required_stage }; },
    async registrationOptions(input) { calls.push(["registrationOptions", input]); return { request_id: REQUEST, challenge_id: CHALLENGE, options: { challenge: "registration" } }; },
    async registrationVerify(input) { calls.push(["registrationVerify", input]); return { request_id: REQUEST, recovery: { ...recovery, state: "credential_enrolled", credential_enrolled_at: "2026-08-14T01:00:00.000Z", version: 3 }, registered: true, activation: { challenge_id: CHALLENGE, options: { challenge: "activation" } } }; },
    async activate(input) { calls.push(["activate", input]); return { request_id: REQUEST, recovery: { ...recovery, state: "activated", activated_at: "2026-08-14T02:00:00.000Z", version: 4 }, activated: true }; }
  };
  const humanSession = {
    expectedOrigin: ORIGIN,
    async authenticateRequest() { calls.push(["humanSession"]); return { session: actor }; }
  };
  const recentAuthService = {
    async authorize(input) { calls.push(["recentAuth", input]); return { verified: true, consumed: true, challenge_id: AUTHORIZATION, authorization_id: AUTHORIZATION, member_id: SUBJECT, organization_id: ORG, operation: OWNER_RECOVERY_OPERATIONS.approve, authenticated_at: Date.now() }; }
  };
  return { calls, api: createOwnerRecoveryHttpApi({ humanSession, recentAuthService, recoveryService: service, abuseControls, origin: ORIGIN, now: () => Date.parse("2026-08-14T00:00:00.000Z") }) };
}

function request(path, { method = "POST", body = undefined, headers = {} } = {}) {
  return { method, url: path, headers: { origin: ORIGIN, ...headers }, ...(body === undefined ? {} : { body }) };
}

const normalHeaders = { cookie: `__Host-agentpass_session=${NORMAL_TOKEN}`, "agentpass-csrf": CSRF };
const recoveryHeaders = { cookie: `__Host-agentpass_recovery_session=${SESSION_TOKEN}` };

test("optional abuse control must expose check", () => {
  assert.throws(() => makeApi({ abuseControls: {} }), /abuseControls must expose check/);
});

test("normal lanes enforce exact origin, human session/CSRF, closed create body, and idempotency", async () => {
  const { api, calls } = makeApi();
  const result = await api.handle(request(OWNER_RECOVERY_HTTP_PATHS.requests(ORG), { body: { threshold: 2 }, headers: { ...normalHeaders, "content-type": "application/json", "idempotency-key": "create-123" } }));
  assert.equal(result.status, 201);
  assert.equal(calls.find(([name]) => name === "create")[1].subject_member_id, SUBJECT);
  const badSubject = await api.handle(request(OWNER_RECOVERY_HTTP_PATHS.requests(ORG), { body: { subject_member_id: REQUEST }, headers: { ...normalHeaders, "content-type": "application/json", "idempotency-key": "create-123" } }));
  assert.equal(badSubject.body.error.code, OWNER_RECOVERY_HTTP_ERROR_CODES.INVALID_REQUEST);
  const noCsrf = await api.handle(request(OWNER_RECOVERY_HTTP_PATHS.requests(ORG), { body: {}, headers: { cookie: `__Host-agentpass_session=${NORMAL_TOKEN}`, "content-type": "application/json", "idempotency-key": "create-123" } }));
  assert.equal(noCsrf.body.error.code, OWNER_RECOVERY_HTTP_ERROR_CODES.CSRF_FAILED);
});

test("approval and cancellation use If-Match, recent-auth operation binding, and no-store closed responses", async () => {
  const { api, calls } = makeApi();
  const approved = await api.handle(request(OWNER_RECOVERY_HTTP_PATHS.approve(ORG, REQUEST), { body: {}, headers: { ...normalHeaders, "content-type": "application/json", "idempotency-key": "approve-123", "if-match": '"1"', "agentpass-recent-auth": AUTHORIZATION } }));
  assert.equal(approved.status, 200);
  assert.equal(calls.find(([name]) => name === "approve")[1].recent_authorization.operation, OWNER_RECOVERY_OPERATIONS.approve);
  assert.match(approved.headers["Cache-Control"], /no-store/);
  const cancelled = await api.handle(request(OWNER_RECOVERY_HTTP_PATHS.cancel(ORG, REQUEST), { body: {}, headers: { ...normalHeaders, "content-type": "application/json", "idempotency-key": "cancel-123", "if-match": '"1"' } }));
  assert.equal(cancelled.status, 200);
});

test("exchange strips the raw token from JSON and emits only a strict recovery cookie", async () => {
  const { api } = makeApi();
  const result = await api.handle(request(OWNER_RECOVERY_HTTP_PATHS.exchange, { body: { exchange: "E".repeat(43) }, headers: { "content-type": "application/json" } }));
  assert.equal(result.status, 200);
  assert.equal(result.body.request_id, REQUEST);
  assert.equal(Object.hasOwn(result.body, "recovery_session_token"), false);
  assert.match(result.headers["Set-Cookie"], /^__Host-agentpass_recovery_session=R{43}; Path=\/; HttpOnly; Secure; SameSite=Strict$/u);
  assert.equal(JSON.stringify(result.body).includes(SESSION_TOKEN), false);
});

test("restricted registration and activation require the recovery cookie, reject Authorization, and bind activation assertion", async () => {
  const { api, calls } = makeApi();
  const missingCookie = await api.handle(request(OWNER_RECOVERY_HTTP_PATHS.registrationOptions, { body: { request_id: REQUEST }, headers: { "content-type": "application/json" } }));
  assert.equal(missingCookie.body.error.code, OWNER_RECOVERY_HTTP_ERROR_CODES.RECOVERY_SESSION_REQUIRED);
  const authorizationHeader = await api.handle(request(OWNER_RECOVERY_HTTP_PATHS.registrationOptions, { body: { request_id: REQUEST }, headers: { "content-type": "application/json", authorization: `Bearer ${SESSION_TOKEN}` } }));
  assert.equal(authorizationHeader.body.error.code, OWNER_RECOVERY_HTTP_ERROR_CODES.INVALID_REQUEST);
  const options = await api.handle(request(OWNER_RECOVERY_HTTP_PATHS.registrationOptions, { body: { request_id: REQUEST }, headers: { ...recoveryHeaders, "content-type": "application/json" } }));
  assert.equal(options.body.challenge_id, CHALLENGE);
  const registered = await api.handle(request(OWNER_RECOVERY_HTTP_PATHS.registrationVerify, { body: { organization_id: ORG, challenge_id: CHALLENGE, credential: { id: "credential" } }, headers: { ...recoveryHeaders, "content-type": "application/json" } }));
  assert.equal(registered.body.activation.challenge_id, CHALLENGE);
  const activation = await api.handle(request(OWNER_RECOVERY_HTTP_PATHS.activate, { body: { organization_id: ORG, challenge_id: CHALLENGE, assertion: { client_data_json: "assertion" } }, headers: { ...recoveryHeaders, "content-type": "application/json" } }));
  assert.equal(activation.status, 200);
  assert.deepEqual(calls.find(([name]) => name === "activate")[1], { session_token: SESSION_TOKEN, organization_id: ORG, challenge_id: CHALLENGE, assertion: { client_data_json: "assertion" } });
});

test("restricted lanes enforce exact origin and never expose service causes", async () => {
  const { api } = makeApi();
  const result = await api.handle({ method: "POST", url: OWNER_RECOVERY_HTTP_PATHS.activate, headers: { origin: "https://evil.example.test", cookie: `__Host-agentpass_recovery_session=${SESSION_TOKEN}`, "content-type": "application/json" }, body: { organization_id: ORG, challenge_id: CHALLENGE, assertion: {} } });
  assert.equal(result.body.error.code, OWNER_RECOVERY_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED);
  assert.equal(JSON.stringify(result.body).includes(SESSION_TOKEN), false);
});

test("checks every fixed recovery operation before service work and keeps exchange identity secret-free", async () => {
  const checks = [];
  const { api } = makeApi({ abuseControls: { async check(input) { checks.push(input); return { allowed: true }; } } });
  await api.handle(request(OWNER_RECOVERY_HTTP_PATHS.requests(ORG), { body: {}, headers: { ...normalHeaders, "content-type": "application/json", "idempotency-key": "create-123" } }));
  await api.handle(request(OWNER_RECOVERY_HTTP_PATHS.request(ORG, REQUEST), { method: "GET", headers: normalHeaders }));
  await api.handle(request(OWNER_RECOVERY_HTTP_PATHS.approve(ORG, REQUEST), { body: {}, headers: { ...normalHeaders, "content-type": "application/json", "idempotency-key": "approve-123", "if-match": '"1"', "agentpass-recent-auth": AUTHORIZATION } }));
  await api.handle(request(OWNER_RECOVERY_HTTP_PATHS.cancel(ORG, REQUEST), { body: {}, headers: { ...normalHeaders, "content-type": "application/json", "idempotency-key": "cancel-123", "if-match": '"1"' } }));
  await api.handle(request(OWNER_RECOVERY_HTTP_PATHS.exchange, { body: { exchange: "E".repeat(43) }, headers: { "content-type": "application/json" } }));
  await api.handle(request(OWNER_RECOVERY_HTTP_PATHS.registrationOptions, { body: { request_id: REQUEST }, headers: { ...recoveryHeaders, "content-type": "application/json" } }));
  await api.handle(request(OWNER_RECOVERY_HTTP_PATHS.registrationVerify, { body: { organization_id: ORG, challenge_id: CHALLENGE, credential: { id: "credential" } }, headers: { ...recoveryHeaders, "content-type": "application/json" } }));
  await api.handle(request(OWNER_RECOVERY_HTTP_PATHS.activate, { body: { organization_id: ORG, challenge_id: CHALLENGE, assertion: { client_data_json: "assertion" } }, headers: { ...recoveryHeaders, "content-type": "application/json" } }));
  assert.deepEqual(new Set(checks.map((input) => input.operation)), new Set([
    HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryCreate,
    HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryStatus,
    HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryApprove,
    HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryCancel,
    HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryExchange,
    HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryRegistrationOptions,
    HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryRegistrationVerify,
    HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryActivate
  ]));
  const exchangeCheck = checks.find((input) => input.operation === HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryExchange);
  assert.equal(JSON.stringify(exchangeCheck.session).includes("E".repeat(43)), false);
  assert.match(exchangeCheck.session.session_id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
  assert.notEqual(exchangeCheck.session.session_id, exchangeCheck.session.member_id);
  assert.notEqual(exchangeCheck.session.member_id, exchangeCheck.session.organization_id);
});

test("maps shared abuse denial to 429 with Retry-After and outage to stable 503", async () => {
  const denied = makeApi({ abuseControls: { async check() { throw new HumanAuthAbuseControlError(HUMAN_AUTH_ABUSE_ERROR_CODES.RATE_LIMITED, { retryAfterSeconds: 7, cause: new Error("secret provider detail") }); } } });
  const deniedResult = await denied.api.handle(request(OWNER_RECOVERY_HTTP_PATHS.requests(ORG), { body: {}, headers: { ...normalHeaders, "content-type": "application/json", "idempotency-key": "create-123" } }));
  assert.equal(deniedResult.status, 429);
  assert.equal(deniedResult.headers["Retry-After"], "7");
  assert.equal(denied.calls.some(([name]) => name === "create"), false);
  assert.equal(JSON.stringify(deniedResult.body).includes("secret"), false);
  const unavailable = makeApi({ abuseControls: { async check() { throw new Error("database password=secret"); } } });
  const unavailableResult = await unavailable.api.handle(request(OWNER_RECOVERY_HTTP_PATHS.exchange, { body: { exchange: "E".repeat(43) }, headers: { "content-type": "application/json" } }));
  assert.equal(unavailableResult.status, 503);
  assert.equal(unavailableResult.body.error.code, HUMAN_AUTH_ABUSE_ERROR_CODES.CONTROL_UNAVAILABLE);
  assert.equal(JSON.stringify(unavailableResult.body).includes("password"), false);
});
