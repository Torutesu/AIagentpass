import test from "node:test";
import assert from "node:assert/strict";

import {
  OWNER_RECOVERY_ERROR_CODES,
  OWNER_RECOVERY_OPERATIONS,
  OwnerRecoveryError,
  createOwnerRecoveryService
} from "../src/human-auth/recovery/service.mjs";

const ORG = "11111111-1111-4111-8111-111111111111";
const OTHER_ORG = "99999999-9999-4999-8999-999999999999";
const SUBJECT = "22222222-2222-4222-8222-222222222222";
const OWNER = "33333333-3333-4333-8333-333333333333";
const REQUEST = "44444444-4444-4444-8444-444444444444";
const SESSION = "55555555-5555-4555-8555-555555555555";
const RECOVERY_SESSION = "66666666-6666-4666-8666-666666666666";
const CHALLENGE = "77777777-7777-4777-8777-777777777777";
const AUTHORIZATION = "88888888-8888-4888-8888-888888888888";
const EXCHANGE = "A".repeat(43);
const NOW = Date.parse("2026-08-14T00:00:00.000Z");

const actor = (memberId = SUBJECT, role = "owner", organizationId = ORG) => ({ session_id: SESSION, member_id: memberId, organization_id: organizationId, role });
const iso = (offset = 0) => new Date(NOW + offset).toISOString();

function recovery(state = "pending", overrides = {}) {
  return {
    schema_version: 1,
    kind: "threshold-owner-recovery",
    request_id: REQUEST,
    organization_id: ORG,
    subject_member_id: SUBJECT,
    state,
    threshold: 2,
    approved_owner_count: state === "pending" ? 0 : 2,
    approved_at: state === "pending" ? null : iso(1),
    delay_until: state === "pending" ? null : iso(86_400_001),
    session_issued_at: ["session_issued", "credential_enrolled", "activated"].includes(state) ? iso(86_400_002) : null,
    credential_enrolled_at: ["credential_enrolled", "activated"].includes(state) ? iso(86_400_003) : null,
    activated_at: state === "activated" ? iso(86_400_004) : null,
    expires_at: iso(172_800_000),
    terminal_reason: ["cancelled", "expired", "failed"].includes(state) ? "test" : null,
    version: state === "pending" ? 1 : 2,
    created_at: iso(),
    ...overrides
  };
}

function recoverySession(stage = "session_issued") {
  return { recovery_session_id: RECOVERY_SESSION, request_id: REQUEST, member_id: SUBJECT, organization_id: ORG, stage, issued_at: iso(), expires_at: iso(86_400_000), idle_expires_at: iso(43_200_000) };
}

function authorization(operation = OWNER_RECOVERY_OPERATIONS.approve) {
  return { verified: true, consumed: true, authorization_id: AUTHORIZATION, member_id: OWNER, organization_id: ORG, operation, authenticated_at: NOW };
}

function fixtures({ repository = {}, ceremony = {} } = {}) {
  const calls = [];
  const baseRepository = {
    async createRecoveryRequest(input) { calls.push(["create", input]); return { request: recovery("pending", { request_id: input.request_id, subject_member_id: input.subject_member_id }) }; },
    async getRecoveryRequest() { return { request: recovery() }; },
    async approveRecoveryRequest() { return { request: recovery("approved", { version: 2 }) }; },
    async cancelRecoveryRequest() { return { request: recovery("cancelled", { version: 2 }) }; },
    async consumeRecoveryExchange() { return { request_id: REQUEST, recovery_session: recoverySession() }; },
    async authenticateRecoverySession(input) { return recoverySession(input.required_stage ?? "session_issued"); },
    async enrollRecoveryCredentialInTransaction(input) { calls.push(["enroll", input]); return { committed: true, mutation: { request: recovery("credential_enrolled", { version: 3 }), recovery_session: recoverySession("credential_enrolled") } }; },
    async activateRecoveryInTransaction(input) { calls.push(["activate", input]); return { committed: true, mutation: { request: recovery("activated", { version: 4 }), recovery_session: recoverySession("activated") } }; },
    ...repository
  };
  const baseCeremony = {
    async beginRegistration() { return { challenge_id: CHALLENGE, options: { challenge: "registration-challenge" } }; },
    async verifyRegistration(input) {
      const result = await input.complete({ query() {} }, { challenge_id: CHALLENGE }, { credential_id: "credential-id" });
      return result;
    },
    async beginActivation() { return { challenge_id: CHALLENGE, options: { challenge: "activation-challenge" } }; },
    async verifyActivation(input) {
      const result = await input.complete({ query() {} }, { challenge_id: CHALLENGE }, { authorization_id: AUTHORIZATION });
      return { verified: true, consumed: true, authorization: { ...authorization(OWNER_RECOVERY_OPERATIONS.activate), member_id: SUBJECT, authorization_id: AUTHORIZATION }, mutation: result.mutation };
    },
    ...ceremony
  };
  return { calls, service: createOwnerRecoveryService({ repository: baseRepository, ceremony: baseCeremony, now: () => NOW, uuid: () => REQUEST, randomBytes: () => Buffer.alloc(32), delayMs: 86_400_000 }) };
}

test("creation is bound to the authenticated subject and never trusts another subject", async () => {
  const { service } = fixtures();
  await assert.rejects(() => service.create({ actor: actor(), organization_id: ORG, subject_member_id: OWNER, idempotency_key: "create-1" }), (error) => error.code === OWNER_RECOVERY_ERROR_CODES.FORBIDDEN);
  const created = await service.create({ actor: actor(), organization_id: ORG, subject_member_id: SUBJECT, idempotency_key: "create-1" });
  assert.equal(created.recovery.subject_member_id, SUBJECT);
});

test("approval enforces owner role, exact operation, and maps stale versions", async () => {
  const { service } = fixtures();
  await assert.rejects(() => service.approve({ actor: actor(SUBJECT, "admin"), organization_id: ORG, request_id: REQUEST, expected_version: 1, idempotency_key: "approve-1", recent_authorization: authorization() }), (error) => error.code === OWNER_RECOVERY_ERROR_CODES.FORBIDDEN);
  await assert.rejects(() => service.approve({ actor: actor(OWNER), organization_id: ORG, request_id: REQUEST, expected_version: 1, idempotency_key: "approve-1", recent_authorization: authorization("wrong.operation") }), (error) => error.code === OWNER_RECOVERY_ERROR_CODES.APPROVAL_INVALID);
  const stale = fixtures({ repository: { async approveRecoveryRequest() { throw Object.assign(new Error("secret database detail"), { code: "stale_version" }); } } });
  await assert.rejects(() => stale.service.approve({ actor: actor(OWNER), organization_id: ORG, request_id: REQUEST, expected_version: 1, idempotency_key: "approve-1", recent_authorization: authorization() }), (error) => error.code === OWNER_RECOVERY_ERROR_CODES.VERSION_CONFLICT && error.cause === undefined && !error.message.includes("secret"));
});

test("tenant substitution and repository outage fail closed without carrying provider details", async () => {
  const { service } = fixtures();
  await assert.rejects(() => service.get({ actor: actor(SUBJECT, "owner", OTHER_ORG), organization_id: ORG, request_id: REQUEST }), (error) => error.code === OWNER_RECOVERY_ERROR_CODES.NOT_FOUND);
  const outage = fixtures({ repository: { async createRecoveryRequest() { throw Object.assign(new Error("postgres password=secret"), { code: "connection_failure" }); } } });
  await assert.rejects(() => outage.service.create({ actor: actor(), organization_id: ORG, subject_member_id: SUBJECT, idempotency_key: "create-1" }), (error) => error.code === OWNER_RECOVERY_ERROR_CODES.UNAVAILABLE && error.cause === undefined && !error.message.includes("password"));
});

test("exchange replay is stable and recovery sessions are digest-backed", async () => {
  const replay = fixtures({ repository: { async consumeRecoveryExchange() { throw Object.assign(new Error("raw exchange A"), { code: "exchange_replayed" }); } } });
  await assert.rejects(() => replay.service.exchange({ exchange_value: EXCHANGE }), (error) => error.code === OWNER_RECOVERY_ERROR_CODES.EXCHANGE_REPLAYED && error.cause === undefined && !error.message.includes(EXCHANGE));
  const { service, calls } = fixtures();
  const result = await service.exchange({ exchange_value: EXCHANGE });
  assert.equal(result.recovery_session_token.length, 43);
  assert.notEqual(calls.find(([name]) => name === "create")?.[1]?.session_digest, EXCHANGE);
});

test("registration uses one ceremony completion callback and immediately issues activation challenge", async () => {
  const { service, calls } = fixtures();
  const options = await service.registrationOptions({ session_token: EXCHANGE, request_id: REQUEST });
  assert.equal(options.options.challenge, "registration-challenge");
  const result = await service.registrationVerify({ session_token: EXCHANGE, request_id: REQUEST, challenge_id: CHALLENGE, credential: { id: "browser-credential" } });
  assert.equal(result.registered, true);
  assert.equal(result.activation.challenge_id, CHALLENGE);
  assert.equal(calls.filter(([name]) => name === "enroll").length, 1);
  assert.equal(calls.find(([name]) => name === "enroll")[1].tx.query instanceof Function, true);
});

test("activation requires the exact recovery operation and commits through the ceremony callback", async () => {
  const bad = fixtures({ ceremony: { async verifyActivation() { throw Object.assign(new Error("wrong operation"), { code: "binding_mismatch" }); } } });
  await assert.rejects(() => bad.service.activate({ session_token: EXCHANGE, request_id: REQUEST, challenge_id: CHALLENGE, assertion: { client_data_json: "assertion" } }), (error) => error.code === OWNER_RECOVERY_ERROR_CODES.ACTIVATION_INVALID);
  const { service, calls } = fixtures();
  const result = await service.activate({ session_token: EXCHANGE, request_id: REQUEST, challenge_id: CHALLENGE, assertion: { client_data_json: "assertion" } });
  assert.equal(result.activated, true);
  assert.equal(calls.find(([name]) => name === "activate")[1].challenge_id, CHALLENGE);
});
