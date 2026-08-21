import assert from "node:assert/strict";
import test from "node:test";

import {
  HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES,
  HostedIdentityBootstrapServiceError,
  createHostedIdentityBootstrapService
} from "../../src/hosted-identity/index.mjs";

const NOW = Date.parse("2026-08-15T00:00:00.000Z");
const ATTEMPT_ID = "11111111-1111-4111-8111-111111111111";
const OAUTH_STATE_ID = "22222222-2222-4222-8222-222222222222";
const CANDIDATE_MEMBER_ID = "33333333-3333-4333-8333-333333333333";
const SUBJECT = "123456789";
const BOOTSTRAP_BYTES = Buffer.alloc(32, 0xab);

function validResult(overrides = {}) {
  return {
    attempt_id: ATTEMPT_ID,
    state: "organization_required",
    organization_count: 0,
    expires_at: new Date(NOW + 900_000).toISOString(),
    ...overrides
  };
}

function fixture(overrides = {}) {
  const calls = [];
  const repository = overrides.repository ?? {
    async completeOAuthStateV2(input) {
      calls.push(input);
      return validResult();
    }
  };
  const service = createHostedIdentityBootstrapService({
    repository,
    randomUUID: overrides.randomUUID ?? (() => CANDIDATE_MEMBER_ID),
    randomBytes: overrides.randomBytes ?? (() => Buffer.from(BOOTSTRAP_BYTES)),
    now: overrides.now ?? (() => NOW)
  });
  return { calls, service };
}

function input(overrides = {}) {
  return {
    identity: { provider: "github", subject: SUBJECT, ...(overrides.identity ?? {}) },
    context: { attempt_id: ATTEMPT_ID, oauth_state_id: OAUTH_STATE_ID, ...(overrides.context ?? {}) },
    ...(overrides.extra ?? {})
  };
}

function assertServiceError(error, code, forbidden = []) {
  assert.ok(error instanceof HostedIdentityBootstrapServiceError);
  assert.equal(error.code, code);
  assert.equal(error.message, code === HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.CONFIG
    ? "Hosted identity bootstrap service configuration is invalid"
    : code === HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.INPUT
      ? "Hosted identity bootstrap request is invalid"
      : "Hosted identity bootstrap service is unavailable");
  for (const secret of forbidden) assert.equal(error.message.includes(secret), false);
  assert.equal(Object.hasOwn(error, "cause"), false);
}

test("creates the exact HTTP DTO and passes only the generated selector/member to the repository", async () => {
  const { calls, service } = fixture();
  const result = await service.createBootstrapSession(input());
  const token = BOOTSTRAP_BYTES.toString("base64url");

  assert.deepEqual(result, { bootstrapToken: token, expiresAt: NOW + 900_000 });
  assert.deepEqual(Object.keys(result).sort(), ["bootstrapToken", "expiresAt"]);
  assert.equal(Object.isFrozen(result), true);
  assert.deepEqual(calls, [{
    oauth_state_id: OAUTH_STATE_ID,
    attempt_id: ATTEMPT_ID,
    bootstrap_cookie: token,
    candidate_member_id: CANDIDATE_MEMBER_ID,
    provider: "github",
    subject: SUBJECT
  }]);
});

test("rejects invalid configuration with stable redacted errors", () => {
  const cases = [
    {},
    { repository: {} },
    { repository: { completeOAuthStateV2() {} }, randomUUID: null },
    { repository: { completeOAuthStateV2() {} }, randomBytes: null },
    { repository: { completeOAuthStateV2() {} }, now: null }
  ];
  for (const options of cases) {
    assert.throws(() => createHostedIdentityBootstrapService(options), (error) => {
      assertServiceError(error, HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.CONFIG);
      return true;
    });
  }
});

test("rejects malformed or caller-expanded identity bootstrap input", async () => {
  const { service, calls } = fixture();
  const invalidInputs = [
    input({ identity: { provider: "google" } }),
    input({ identity: { subject: "0" } }),
    input({ identity: { subject: "0001" } }),
    input({ identity: { subject: 123 } }),
    input({ identity: { subject: "" } }),
    input({ identity: { subject: "1".repeat(21) } }),
    input({ identity: { subject: "123\n" } }),
    input({ identity: { subject: "1".repeat(21) } }),
    input({ context: { attempt_id: "not-a-uuid" } }),
    input({ context: { oauth_state_id: "not-a-uuid" } }),
    input({ extra: { member_id: CANDIDATE_MEMBER_ID } }),
    { identity: input().identity, context: input().context, extra: true, unexpected: true }
  ];

  for (const invalid of invalidInputs) {
    await assert.rejects(service.createBootstrapSession(invalid), (error) => {
      assertServiceError(error, HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.INPUT, [SUBJECT]);
      return true;
    });
  }
  assert.equal(calls.length, 0);
});

test("maps random-source and repository failures to unavailable without leaking token or subject", async () => {
  const token = BOOTSTRAP_BYTES.toString("base64url");
  const cases = [
    { randomUUID: () => "not-a-uuid" },
    { randomBytes: () => Buffer.alloc(31) },
    { repository: { async completeOAuthStateV2() { throw new Error(`database ${token} ${SUBJECT}`); } } }
  ];
  for (const overrides of cases) {
    const { service } = fixture(overrides);
    await assert.rejects(service.createBootstrapSession(input()), (error) => {
      assertServiceError(error, HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE, [token, SUBJECT]);
      return true;
    });
  }
});

test("rejects non-exact, mismatched, and unsafe repository completion results", async () => {
  const invalidResults = [
    null,
    { ...validResult(), extra: true },
    validResult({ attempt_id: CANDIDATE_MEMBER_ID }),
    validResult({ state: "completed" }),
    validResult({ organization_count: -1 }),
    validResult({ organization_count: 1.5 }),
    validResult({ state: "identity_verified", organization_count: 0 }),
    validResult({ state: "no_membership", organization_count: 1 }),
    validResult({ expires_at: "not-a-timestamp" }),
    validResult({ expires_at: new Date(NOW - 1).toISOString() }),
    validResult({ expires_at: new Date(NOW + 900_001).toISOString() })
  ];
  for (const result of invalidResults) {
    const { service } = fixture({ repository: { async completeOAuthStateV2() { return result; } } });
    await assert.rejects(service.createBootstrapSession(input()), (error) => {
      assertServiceError(error, HOSTED_IDENTITY_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
      return true;
    });
  }
});

test("accepts one- and nine-hundred-second database-relative expiries", async () => {
  for (const seconds of [1, 900]) {
    const { service } = fixture({ repository: { async completeOAuthStateV2() { return validResult({ expires_at: new Date(NOW + seconds * 1_000).toISOString() }); } } });
    const result = await service.createBootstrapSession(input());
    assert.equal(result.expiresAt, NOW + seconds * 1_000);
  }
});
