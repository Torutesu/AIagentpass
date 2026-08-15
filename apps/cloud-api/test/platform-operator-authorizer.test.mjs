import assert from "node:assert/strict";
import test from "node:test";

import {
  createPlatformOperatorAuthorizer,
  PLATFORM_OPERATOR_AUTHORIZER_ERROR_CODES,
  PLATFORM_OPERATOR_AUTHORIZER_REPOSITORY_METHODS,
  PlatformOperatorAuthorizationError
} from "../src/platform-operator-authorizer.mjs";

const NOW = Date.parse("2026-08-15T12:00:00.000Z");
const SESSION_ID = "11111111-1111-4111-8111-111111111111";
const MEMBER_ID = "22222222-2222-4222-8222-222222222222";
const ORGANIZATION_ID = "33333333-3333-4333-8333-333333333333";
const ASSIGNMENT_ID = "44444444-4444-4444-8444-444444444444";
const OPERATION = "platform.promotion.issue";
const CAPABILITY = "platform.promotion.issue";

function principal(role = "viewer") {
  return {
    version: 1,
    session_id: SESSION_ID,
    member_id: MEMBER_ID,
    organization_id: ORGANIZATION_ID,
    role,
    created_at: "2026-08-15T11:00:00.000Z",
    expires_at: "2026-08-15T20:00:00.000Z",
    recent_auth_at: null
  };
}

function principalWith(overrides = {}) {
  return { ...principal(), ...overrides };
}

function assignment(overrides = {}) {
  return {
    assignment_id: ASSIGNMENT_ID,
    session_id: SESSION_ID,
    member_id: MEMBER_ID,
    organization_id: ORGANIZATION_ID,
    role: "platform_operator",
    operation: OPERATION,
    capability: CAPABILITY,
    status: "active",
    issued_at: "2026-08-15T11:00:00.000Z",
    expires_at: "2026-08-15T13:00:00.000Z",
    ...overrides
  };
}

function input(overrides = {}) {
  return {
    principal: principal(),
    operation: OPERATION,
    capability: CAPABILITY,
    ...overrides
  };
}

function repository(result = assignment(), calls = []) {
  return {
    async findActivePlatformOperatorAssignment(request) {
      calls.push(request);
      return typeof result === "function" ? result(request) : result;
    }
  };
}

test("requires the narrow injected repository contract and exposes a callable authorizer", () => {
  assert.deepEqual(PLATFORM_OPERATOR_AUTHORIZER_REPOSITORY_METHODS, ["findActivePlatformOperatorAssignment"]);
  assert.throws(() => createPlatformOperatorAuthorizer(), /repository is required/);
  assert.throws(() => createPlatformOperatorAuthorizer({ repository: {} }), /findActivePlatformOperatorAssignment/);
  assert.throws(() => createPlatformOperatorAuthorizer({ repository: repository(), now: "not-a-clock" }), /now must be a function/);

  const authorizer = createPlatformOperatorAuthorizer({ repository: repository(), now: () => NOW });
  assert.equal(typeof authorizer, "function");
  assert.equal(authorizer.authorize, authorizer);
  assert.equal(typeof authorizer.assertAuthorized, "function");
});

test("allows an active exact assignment independently of the organization role", async () => {
  const calls = [];
  const authorizer = createPlatformOperatorAuthorizer({ repository: repository(assignment(), calls), now: () => NOW });
  const result = await authorizer(input({ principal: principal("owner") }));

  assert.deepEqual(result, { allowed: true, role: "platform_operator", capability: CAPABILITY });
  assert.deepEqual(calls, [{
    capability: CAPABILITY,
    member_id: MEMBER_ID,
    operation: OPERATION,
    organization_id: ORGANIZATION_ID,
    session_id: SESSION_ID,
    now: "2026-08-15T12:00:00.000Z"
  }]);
  assert.equal(Object.hasOwn(result, "assignment_id"), false);
  assert.equal(Object.hasOwn(result, "session_id"), false);
});

test("does not grant authority from any organization role without an active platform assignment", async () => {
  for (const role of ["owner", "admin", "auditor", "viewer", "platform_operator"]) {
    const authorizer = createPlatformOperatorAuthorizer({ repository: repository(null), now: () => NOW });
    assert.deepEqual(await authorizer(input({ principal: principal(role) })), { allowed: false });
  }
});

test("fails closed for absent, inactive, wrong-role, expired, and future assignments", async () => {
  const cases = [
    null,
    assignment({ status: "revoked" }),
    assignment({ role: "admin" }),
    assignment({ expires_at: "2026-08-15T12:00:00.000Z" }),
    assignment({ issued_at: "2026-08-15T12:00:00.001Z" })
  ];
  for (const value of cases) {
    const authorizer = createPlatformOperatorAuthorizer({ repository: repository(value), now: () => NOW });
    if (value?.status === "revoked" || value?.role === "admin") {
      // These rows are intentionally malformed as a repository projection:
      // the authorizer must reject the projection rather than reinterpret it.
      await assert.rejects(() => authorizer(input()), (error) => error.code === PLATFORM_OPERATOR_AUTHORIZER_ERROR_CODES.REPOSITORY_INVALID);
    } else {
      assert.deepEqual(await authorizer(input()), { allowed: false });
    }
  }
});

test("requires exact session, member, organization, operation, and capability binding", async () => {
  const mismatches = [
    { assignment: { session_id: "55555555-5555-4555-8555-555555555555" } },
    { assignment: { member_id: "66666666-6666-4666-8666-666666666666" } },
    { assignment: { organization_id: "77777777-7777-4777-8777-777777777777" } },
    { assignment: { operation: "platform.promotion.replay" } },
    { assignment: { capability: "platform.promotion.replay" } }
  ];
  for (const mismatch of mismatches) {
    const authorizer = createPlatformOperatorAuthorizer({ repository: repository(assignment(mismatch.assignment)), now: () => NOW });
    assert.deepEqual(await authorizer(input()), { allowed: false });
  }
});

test("requires the authenticated principal session itself to be current", async () => {
  const calls = [];
  const authorizer = createPlatformOperatorAuthorizer({ repository: repository(assignment(), calls), now: () => NOW });
  assert.deepEqual(await authorizer(input({ principal: principalWith({ expires_at: "2026-08-15T12:00:00.000Z" }) })), { allowed: false });
  assert.deepEqual(await authorizer(input({ principal: principalWith({ created_at: "2026-08-15T12:00:00.001Z" }) })), { allowed: false });
  assert.equal(calls.length, 0);
});

test("rejects malformed caller input before consulting the repository", async () => {
  const calls = [];
  const authorizer = createPlatformOperatorAuthorizer({ repository: repository(assignment(), calls), now: () => NOW });
  const invalidInputs = [
    {},
    input({ operation: "Platform.Promotion.Issue" }),
    input({ capability: "platform.promotion.issue " }),
    input({ principal: { ...principal(), token_hash: "secret" } }),
    input({ request: "not-an-object" }),
    { ...input(), unexpected: true }
  ];
  for (const value of invalidInputs) assert.deepEqual(await authorizer(value), { allowed: false });
  assert.equal(calls.length, 0);
});

test("sanitizes repository failures and malformed rows into fail-closed errors", async () => {
  const secret = "database password and provider credential";
  const authorizer = createPlatformOperatorAuthorizer({
    repository: { async findActivePlatformOperatorAssignment() { throw new Error(secret); } },
    now: () => NOW
  });
  await assert.rejects(() => authorizer(input()), (error) => {
    assert(error instanceof PlatformOperatorAuthorizationError);
    assert.equal(error.code, PLATFORM_OPERATOR_AUTHORIZER_ERROR_CODES.REPOSITORY_UNAVAILABLE);
    assert.equal(error.status, 503);
    assert.doesNotMatch(error.message, /password|credential|database/iu);
    assert.equal("cause" in error, false);
    return true;
  });

  const malformed = createPlatformOperatorAuthorizer({ repository: repository({ ...assignment(), provider_diagnostics: secret }), now: () => NOW });
  await assert.rejects(() => malformed(input()), (error) => {
    assert.equal(error.code, PLATFORM_OPERATOR_AUTHORIZER_ERROR_CODES.REPOSITORY_INVALID);
    assert.doesNotMatch(error.message, /password|credential|database/iu);
    return true;
  });
});

test("fails closed when the injected clock is invalid and assertAuthorized rejects a denial", async () => {
  const authorizer = createPlatformOperatorAuthorizer({ repository: repository(), now: () => Number.NaN });
  await assert.rejects(() => authorizer(input()), (error) => error.code === PLATFORM_OPERATOR_AUTHORIZER_ERROR_CODES.INVALID_CONFIGURATION);

  const denied = createPlatformOperatorAuthorizer({ repository: repository(null), now: () => NOW });
  await assert.rejects(() => denied.assertAuthorized(input()), (error) => {
    assert.equal(error.code, PLATFORM_OPERATOR_AUTHORIZER_ERROR_CODES.DENIED);
    assert.equal(error.status, 403);
    return true;
  });
});
