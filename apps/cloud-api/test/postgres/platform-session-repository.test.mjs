import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  createPostgresPlatformSessionRepository,
  PLATFORM_SESSION_FIND_ACTIVE_SQL,
  PLATFORM_SESSION_REPOSITORY_ERROR_CODES as CODES,
  PLATFORM_SESSION_TOUCH_SQL,
  PlatformSessionRepositoryError
} from "../../src/postgres/platform-session-repository.mjs";

const ORGANIZATION_ID = "33333333-3333-4333-8333-333333333333";
const OTHER_ORGANIZATION_ID = "55555555-5555-4555-8555-555555555555";
const MEMBER_ID = "22222222-2222-4222-8222-222222222222";
const PRINCIPAL_ID = "66666666-6666-4666-8666-666666666666";
const SESSION_ID = "11111111-1111-4111-8111-111111111111";
const ASSIGNMENT_ID = "44444444-4444-4444-8444-444444444444";
const CREDENTIAL_ID = "77777777-7777-4777-8777-777777777777";
const OPERATION = "platform.promotion.issue";
const MATERIAL = "A".repeat(43);
const MATERIAL_DIGEST = crypto.createHash("sha256").update(MATERIAL).digest();

function session(overrides = {}) {
  return {
    assignment_id: ASSIGNMENT_ID,
    assignment_version: 3,
    authenticated_at: "2026-08-15T11:00:00.000Z",
    capability: OPERATION,
    created_at: "2026-08-15T11:00:00.000Z",
    credential_id: CREDENTIAL_ID,
    credential_version: 4,
    expired_at: null,
    expires_at: "2026-08-15T13:00:00.000Z",
    idle_expires_at: "2026-08-15T12:00:00.000Z",
    last_seen_at: "2026-08-15T11:05:00.000Z",
    member_id: MEMBER_ID,
    operation: OPERATION,
    organization_id: ORGANIZATION_ID,
    principal_authority_generation: 7,
    principal_id: PRINCIPAL_ID,
    revoke_reason: null,
    revoked_at: null,
    session_id: SESSION_ID,
    status: "active",
    version: 2,
    ...overrides
  };
}

function response(sessionValue = session()) {
  return { rowCount: 1, rows: [{ session: sessionValue }] };
}

function lookupInput(overrides = {}) {
  return {
    capability: OPERATION,
    operation: OPERATION,
    organization_id: ORGANIZATION_ID,
    session_material: MATERIAL,
    ...overrides
  };
}

class FakeClient {
  constructor({ result = response(), error = undefined } = {}) {
    this.result = result;
    this.error = error;
    this.calls = [];
  }

  async query(text, params) {
    this.calls.push({ text, params });
    if (this.error) throw this.error;
    return this.result;
  }
}

function assertOpaque(error, code) {
  assert(error instanceof PlatformSessionRepositoryError);
  assert.equal(error.code, code);
  assert.equal("cause" in error, false);
  assert.doesNotMatch(JSON.stringify(error), /raw-session|secret|private|signature|token/iu);
}

test("requires a client and exposes only the reviewed lifecycle methods", () => {
  assert.throws(() => createPostgresPlatformSessionRepository(), { code: CODES.CONFIG });
  const repository = createPostgresPlatformSessionRepository({ client: new FakeClient() });
  assert.deepEqual(Object.keys(repository), [
    "findActivePlatformSession",
    "touchPlatformSession"
  ]);
  assert.equal(Object.isFrozen(repository), true);
  assert.equal("agentpass_platform_session_issue" in repository, false);
  assert.equal("agentpass_platform_credential_provision" in repository, false);
  assert.equal("agentpass_platform_credential_advance_sign_count" in repository, false);
  assert.equal("revokePlatformSession" in repository, false);
});

test("findActive hashes raw material locally, uses one parameterized call, and returns bindings", async () => {
  const client = new FakeClient();
  const repository = createPostgresPlatformSessionRepository({ client });
  const result = await repository.findActivePlatformSession(lookupInput());

  assert.deepEqual(result, session());
  assert.equal(Object.isFrozen(result), true);
  assert.deepEqual(client.calls, [{
    text: PLATFORM_SESSION_FIND_ACTIVE_SQL,
    params: [MATERIAL_DIGEST, ORGANIZATION_ID, OPERATION, OPERATION]
  }]);
  assert.equal(client.calls[0].params.includes(MATERIAL), false);
  assert.equal(Buffer.isBuffer(client.calls[0].params[0]), true);
  assert.equal(client.calls[0].params[0].toString("hex"), MATERIAL_DIGEST.toString("hex"));
  assert.doesNotMatch(client.calls[0].text, /INSERT|UPDATE|DELETE|session_material[^_]/iu);
});

test("returns null for a denied canonical bearer lookup", async () => {
  const client = new FakeClient({ result: response(null) });
  const repository = createPostgresPlatformSessionRepository({ client });
  assert.equal(await repository.findActivePlatformSession(lookupInput()), null);
  assert.equal(client.calls.length, 1);
  assert.equal(client.calls[0].params[0].toString("hex"), MATERIAL_DIGEST.toString("hex"));
});

test("touch uses its dedicated function and accepts an active or terminal lifecycle result", async () => {
  const client = new FakeClient();
  const repository = createPostgresPlatformSessionRepository({ client });
  const result = await repository.touchPlatformSession(lookupInput());
  assert.deepEqual(result, session());
  assert.equal(client.calls[0].text, PLATFORM_SESSION_TOUCH_SQL);
  assert.deepEqual(client.calls[0].params.slice(1), [ORGANIZATION_ID, OPERATION, OPERATION]);

  const terminalClient = new FakeClient({ result: response(session({
    status: "expired",
    expired_at: "2026-08-15T13:00:00.001Z",
    idle_expires_at: "2026-08-15T12:00:00.000Z"
  })) });
  const terminalRepository = createPostgresPlatformSessionRepository({ client: terminalClient });
  assert.equal((await terminalRepository.touchPlatformSession(lookupInput())).status, "expired");
});

test("rejects missing, extra, malformed, role-bearing, and secret-bearing inputs before querying", async () => {
  const client = new FakeClient();
  const repository = createPostgresPlatformSessionRepository({ client });
  const invalid = [
    undefined,
    {},
    { ...lookupInput(), role: "platform_operator" },
    { ...lookupInput(), unexpected: true },
    { ...lookupInput(), organization_id: "not-a-uuid" },
    { ...lookupInput(), operation: "Platform.Promotion.Issue" },
    { ...lookupInput(), capability: "platform.promotion.issue " },
    { ...lookupInput(), operation: "platform.promotion.issue", capability: "platform.promotion.verify" },
    { ...lookupInput(), session_material: "" },
    { ...lookupInput(), session_material: "A".repeat(42) },
    { ...lookupInput(), session_material: Uint8Array.from([1, 2, 3]) },
    { ...lookupInput(), session_material: { token: MATERIAL } }
  ];

  for (const value of invalid) {
    await assert.rejects(repository.findActivePlatformSession(value), (error) => {
      assertOpaque(error, CODES.INPUT);
      return true;
    });
  }
  assert.equal(client.calls.length, 0);
});

test("rejects malformed and binding-conflicting session results", async () => {
  const cases = [
    response({ ...session(), extra: "secret" }),
    response({ ...session(), organization_id: OTHER_ORGANIZATION_ID }),
    response({ ...session(), operation: "platform.promotion.verify", capability: "platform.promotion.verify" }),
    response({ ...session(), principal_id: "not-a-uuid" }),
    response({ ...session(), principal_authority_generation: 0 }),
    response({ ...session(), assignment_version: "3" }),
    response({ ...session(), status: "revoked", revoked_at: null }),
    response({ ...session(), status: "active", expired_at: "2026-08-15T12:00:00.000Z" }),
    response({ ...session(), idle_expires_at: "2026-08-15T14:00:00.000Z" }),
    { rowCount: 0, rows: [] },
    { rowCount: 1, rows: [{ session: session(), diagnostic: "secret" }] },
    { rowCount: 1, rows: [{ session: session() }, { session: session() }] }
  ];
  for (const result of cases) {
    const repository = createPostgresPlatformSessionRepository({ client: new FakeClient({ result }) });
    await assert.rejects(repository.touchPlatformSession(lookupInput()), (error) => {
      assertOpaque(error, CODES.RESULT);
      return true;
    });
  }
});

test("contains database failures behind an opaque error and never attaches the driver cause", async () => {
  const client = new FakeClient({ error: new Error("raw-session-material relation and signature secret") });
  const repository = createPostgresPlatformSessionRepository({ client });
  await assert.rejects(repository.findActivePlatformSession(lookupInput()), (error) => {
    assertOpaque(error, CODES.DATABASE);
    assert.equal(error.message, "platform session storage is unavailable");
    return true;
  });
  assert.equal(client.calls.length, 1);
});

test("converts hostile result accessors into a stable result error", async () => {
  const row = {};
  Object.defineProperty(row, "session", {
    enumerable: true,
    get() { throw new Error("secret result accessor"); }
  });
  const repository = createPostgresPlatformSessionRepository({
    client: new FakeClient({ result: { rowCount: 1, rows: [row] } })
  });
  await assert.rejects(repository.touchPlatformSession(lookupInput()), (error) => {
    assertOpaque(error, CODES.RESULT);
    return true;
  });
});
