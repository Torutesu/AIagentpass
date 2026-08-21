import assert from "node:assert/strict";
import test from "node:test";

import {
  createPostgresPlatformOperatorAssignmentRepository,
  PLATFORM_OPERATOR_ASSIGNMENT_FIND_ACTIVE_SQL,
  PLATFORM_OPERATOR_ASSIGNMENT_REPOSITORY_ERROR_CODES as CODES,
  PlatformOperatorAssignmentRepositoryError
} from "../../src/postgres/platform-operator-assignment-repository.mjs";

const ORGANIZATION_ID = "33333333-3333-4333-8333-333333333333";
const MEMBER_ID = "22222222-2222-4222-8222-222222222222";
const PRINCIPAL_ID = "66666666-6666-4666-8666-666666666666";
const SESSION_ID = "11111111-1111-4111-8111-111111111111";
const ASSIGNMENT_ID = "44444444-4444-4444-8444-444444444444";
const OPERATION = "platform.promotion.issue";
const CAPABILITY = "platform.promotion.issue";
const NOW = "2026-08-15T12:00:00.000Z";

function input(overrides = {}) {
  return {
    capability: CAPABILITY,
    member_id: MEMBER_ID,
    now: NOW,
    operation: OPERATION,
    organization_id: ORGANIZATION_ID,
    session_id: SESSION_ID,
    ...overrides
  };
}

function assignment(overrides = {}) {
  return {
    assignment_id: ASSIGNMENT_ID,
    capability: CAPABILITY,
    expires_at: "2026-08-15T13:00:00.000Z",
    issued_at: "2026-08-15T11:00:00.000Z",
    member_id: MEMBER_ID,
    principal_id: PRINCIPAL_ID,
    operation: OPERATION,
    organization_id: ORGANIZATION_ID,
    role: "platform_operator",
    session_id: SESSION_ID,
    status: "active",
    authority_generation: 7,
    assignment_version: 3,
    ...overrides
  };
}

function response(value = assignment(), overrides = {}) {
  return { rowCount: 1, rows: [{ assignment: value, ...overrides }] };
}

class FakeClient {
  constructor({ result = response(), error = undefined } = {}) {
    this.result = result;
    this.error = error;
    this.calls = [];
  }

  async query(text, params) {
    this.calls.push({ text, params: structuredClone(params) });
    if (this.error) throw this.error;
    return this.result;
  }
}

test("requires a database client and exposes only the narrow authorizer method", () => {
  assert.throws(() => createPostgresPlatformOperatorAssignmentRepository(), {
    code: CODES.CONFIG,
    message: "platform operator assignment repository configuration is invalid"
  });
  const repository = createPostgresPlatformOperatorAssignmentRepository({ client: new FakeClient() });
  assert.deepEqual(Object.keys(repository), ["findActivePlatformOperatorAssignment"]);
  assert.equal(Object.isFrozen(repository), true);
});

test("uses exactly one parameterized authority function call and returns a frozen exact assignment", async () => {
  const client = new FakeClient();
  const repository = createPostgresPlatformOperatorAssignmentRepository({ client });

  const result = await repository.findActivePlatformOperatorAssignment(input());

  assert.deepEqual(result, assignment());
  assert.equal(Object.isFrozen(result), true);
  assert.deepEqual(client.calls, [{
    text: PLATFORM_OPERATOR_ASSIGNMENT_FIND_ACTIVE_SQL,
    params: [ORGANIZATION_ID, MEMBER_ID, SESSION_ID, OPERATION, CAPABILITY]
  }]);
  assert.equal(client.calls[0].params.includes(NOW), false);
  assert.equal(client.calls[0].params.length, 5);
  assert.match(client.calls[0].text, /^SELECT agentpass_platform_operator_assignment_find_active\(/u);
  assert.doesNotMatch(client.calls[0].text, /(?:INSERT|UPDATE|DELETE|FROM|JOIN|role)/iu);
});

test("returns null for an authority denial without consulting organization roles", async () => {
  const client = new FakeClient({ result: response(null) });
  const repository = createPostgresPlatformOperatorAssignmentRepository({ client });

  assert.equal(await repository.findActivePlatformOperatorAssignment(input()), null);
  assert.equal(client.calls.length, 1);
  assert.equal(client.calls[0].params.includes("owner"), false);
});

test("rejects missing, extra, malformed, or role-bearing input before any query", async () => {
  const client = new FakeClient();
  const repository = createPostgresPlatformOperatorAssignmentRepository({ client });
  const invalidInputs = [
    undefined,
    {},
    { ...input(), role: "platform_operator" },
    { ...input(), unexpected: true },
    { ...input(), organization_id: "not-a-uuid" },
    { ...input(), operation: "Platform.Promotion.Issue" },
    { ...input(), capability: "platform.promotion.issue " },
    { ...input(), now: "not-a-timestamp" },
    (() => {
      const value = input();
      Object.defineProperty(value, "operation", {
        enumerable: true,
        get() { throw new Error("secret input accessor"); }
      });
      return value;
    })()
  ];

  for (const value of invalidInputs) {
    await assert.rejects(repository.findActivePlatformOperatorAssignment(value), (error) => {
      assert(error instanceof PlatformOperatorAssignmentRepositoryError);
      assert.equal(error.code, CODES.INPUT);
      assert.equal(error.message, "platform operator assignment request is invalid");
      assert.equal("cause" in error, false);
      return true;
    });
  }
  assert.equal(client.calls.length, 0);
});

test("rejects malformed authority result shapes, role substitution, and inactive assignments", async () => {
  const cases = [
    response({ ...assignment(), extra: "secret" }),
    response({ ...assignment(), role: "owner" }),
    response({ ...assignment(), status: "revoked" }),
    response({ ...assignment(), assignment_id: "not-a-uuid" }),
    response({ ...assignment(), expires_at: "2026-08-15T11:00:00.000Z" }),
    response({ ...assignment(), organization_id: "55555555-5555-4555-8555-555555555555" }),
    response({ ...assignment(), session_id: "55555555-5555-4555-8555-555555555555" }),
    response({ ...assignment(), operation: "platform.promotion.replay" }),
    response({ ...assignment(), principal_id: "not-a-uuid" }),
    response({ ...assignment(), authority_generation: 0 }),
    response({ ...assignment(), authority_generation: Number.MAX_SAFE_INTEGER + 1 }),
    response({ ...assignment(), authority_generation: "7" }),
    response({ ...assignment(), assignment_version: 0 }),
    response({ ...assignment(), assignment_version: Number.MAX_SAFE_INTEGER + 1 }),
    response({ ...assignment(), assignment_version: "3" }),
    response({ ...assignment(), issued_at: "2026-08-15T12:00:00.001Z" }),
    response({ ...assignment(), expires_at: "2026-08-15T12:00:00.000Z" }),
    response((({ principal_id, ...withoutPrincipalId }) => withoutPrincipalId)(assignment())),
    { rowCount: 1, rows: [{ assignment: assignment() }, { assignment: assignment() }] },
    { rowCount: 0, rows: [] },
    { rowCount: 1, rows: [{ assignment: assignment(), diagnostic: "secret" }] }
  ];

  for (const result of cases) {
    const repository = createPostgresPlatformOperatorAssignmentRepository({ client: new FakeClient({ result }) });
    await assert.rejects(repository.findActivePlatformOperatorAssignment(input()), (error) => {
      assert.equal(error.code, CODES.RESULT);
      assert.equal(error.message, "platform operator assignment returned an invalid database result");
      assert.equal("cause" in error, false);
      return true;
    });
  }
});

test("validates the database generation and version without accepting caller-controlled time", async () => {
  const client = new FakeClient({ result: response(assignment({
    issued_at: "2026-08-15T11:59:59.999Z",
    expires_at: "2026-08-15T12:00:00.001Z",
    authority_generation: 1,
    assignment_version: Number.MAX_SAFE_INTEGER
  })) });
  const repository = createPostgresPlatformOperatorAssignmentRepository({ client });

  const result = await repository.findActivePlatformOperatorAssignment(input({ now: NOW }));

  assert.equal(result.authority_generation, 1);
  assert.equal(result.assignment_version, Number.MAX_SAFE_INTEGER);
  assert.deepEqual(client.calls[0].params, [ORGANIZATION_ID, MEMBER_ID, SESSION_ID, OPERATION, CAPABILITY]);
});

test("contains database failures behind one stable opaque error", async () => {
  const driverError = new Error("relation platform_operator_assignments exposes credential=secret");
  const client = new FakeClient({ error: driverError });
  const repository = createPostgresPlatformOperatorAssignmentRepository({ client });

  await assert.rejects(repository.findActivePlatformOperatorAssignment(input()), (error) => {
    assert(error instanceof PlatformOperatorAssignmentRepositoryError);
    assert.equal(error.code, CODES.DATABASE);
    assert.equal(error.message, "platform operator assignment storage is unavailable");
    assert.equal("cause" in error, false);
    assert.doesNotMatch(JSON.stringify(error), /credential|secret|relation/iu);
    return true;
  });
  assert.equal(client.calls.length, 1);
});

test("rejects a non-single-row function result as a stable database-result error", async () => {
  const repository = createPostgresPlatformOperatorAssignmentRepository({
    client: new FakeClient({ result: { rowCount: 1, rows: [] } })
  });

  await assert.rejects(repository.findActivePlatformOperatorAssignment(input()), {
    code: CODES.RESULT,
    message: "platform operator assignment returned an invalid database result"
  });
});
