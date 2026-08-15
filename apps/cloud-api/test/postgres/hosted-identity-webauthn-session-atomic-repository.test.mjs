import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_ERROR_CODES as CODES,
  createPostgresHostedIdentityBootstrapRepository
} from "../../src/postgres/hosted-identity-bootstrap-repository.mjs";

const IDS = Object.freeze({
  attempt: "11111111-1111-4111-8111-111111111111",
  challenge: "22222222-2222-4222-8222-222222222222",
  session: "33333333-3333-4333-8333-333333333333"
});
const COOKIE = "bootstrap-cookie-never-sent-to-postgres";
const CHALLENGE = "webauthn-challenge-never-sent-to-postgres";
const SESSION_TOKEN = "A".repeat(43);
const CSRF_TOKEN = "B".repeat(43);
const PUBLIC_CREDENTIAL_ID = Buffer.alloc(32, 7).toString("base64url");
const PUBLIC_KEY = Buffer.alloc(65, 8);

class FakeClient {
  constructor(handler) {
    this.handler = handler;
    this.calls = [];
  }

  async query(text, params) {
    this.calls.push({ text, params });
    return this.handler(text, params, this.calls);
  }
}

function digest(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest();
}

function verified(overrides = {}) {
  return {
    id: PUBLIC_CREDENTIAL_ID,
    public_key: PUBLIC_KEY,
    sign_count: 0,
    transports: ["internal"],
    label: "Mac passkey",
    backup_eligible: true,
    backup_state: false,
    ...overrides
  };
}

function input(overrides = {}) {
  return {
    attempt_id: IDS.attempt,
    challenge_id: IDS.challenge,
    bootstrap_cookie: COOKIE,
    challenge: CHALLENGE,
    session: {
      token: SESSION_TOKEN,
      csrf_token: CSRF_TOKEN
    },
    credential: verified(),
    ...overrides
  };
}

function databaseRow(overrides = {}) {
  return {
    attempt_id: IDS.attempt,
    session_id: IDS.session,
    member_id: "66666666-6666-4666-8666-666666666666",
    organization_id: "77777777-7777-4777-8777-777777777777",
    membership_id: "55555555-5555-4555-8555-555555555555",
    role: "owner",
    created_at: "2026-08-15T00:00:00.000Z",
    expires_at: "2026-08-15T00:30:00.000Z",
    replayed: false,
    ...overrides
  };
}

function output(overrides = {}) {
  return {
    attempt_id: IDS.attempt,
    membership_id: "55555555-5555-4555-8555-555555555555",
    replayed: false,
    session: {
      version: 1,
      session_id: IDS.session,
      member_id: "66666666-6666-4666-8666-666666666666",
      organization_id: "77777777-7777-4777-8777-777777777777",
      role: "owner",
      created_at: "2026-08-15T00:00:00.000Z",
      expires_at: "2026-08-15T00:30:00.000Z",
      recent_auth_at: null
    },
    ...overrides
  };
}

function makeRepository(result = databaseRow()) {
  const client = new FakeClient(() => ({ rows: [result], rowCount: 1 }));
  const value = createPostgresHostedIdentityBootstrapRepository({ client });
  assert.equal(typeof value.completeWebAuthnRegistrationV2, "function", "0062 repository method is not implemented yet");
  return { client, repository: value };
}

test("the repository exposes one atomic completion method and no lower-level completion escape hatch", () => {
  const { repository } = makeRepository();
  assert.equal(Object.isFrozen(repository), true);
  assert.equal("completeWebAuthnRegistrationV2" in repository, true);
  assert.equal("completeWebAuthnAndIssueSession" in repository, false);
});

test("atomic completion hashes every browser selector and returns a secret-free result", async () => {
  const fixture = makeRepository();
  const result = await fixture.repository.completeWebAuthnRegistrationV2(input());
  const call = fixture.client.calls.at(-1);

  assert.deepEqual(result, output());
  assert.ok(call, "the atomic SQL boundary was not called");
  assert.equal(call.params.includes(COOKIE), false);
  assert.equal(call.params.includes(CHALLENGE), false);
  assert.equal(call.params.includes(SESSION_TOKEN), false);
  assert.equal(call.params.includes(CSRF_TOKEN), false);
  for (const raw of [COOKIE, CHALLENGE, SESSION_TOKEN, CSRF_TOKEN]) {
    assert.equal(call.params.some((value) => Buffer.isBuffer(value) && value.equals(digest(raw))), true, `${raw} must be hashed`);
  }
  assert.equal(call.params.includes(IDS.session), false, "session id must be generated inside the atomic database boundary");
  assert.equal(Object.keys(result).some((key) => /raw|token|cookie|csrf|secret|assertion/iu.test(key)), false);
  assert.equal(JSON.stringify(result).includes(SESSION_TOKEN), false);
});

test("atomic completion rejects caller-selected session ids, tenant bindings, epochs, and unverified assertions", async () => {
  const fixture = makeRepository();
  for (const invalid of [
    { ...input(), session: { ...input().session, session_id: IDS.session } },
    { ...input(), member_id: "55555555-5555-4555-8555-555555555555" },
    { ...input(), organization_id: "66666666-6666-4666-8666-666666666666" },
    { ...input(), membership_id: "77777777-7777-4777-8777-777777777777" },
    { ...input(), organization_authority_epoch: 99 },
    { ...input(), membership_session_epoch: 99 },
    { ...input(), credential: { ...verified(), verified: false } },
    { ...input(), credential: { ...verified(), assertion: "raw assertion" } }
  ]) {
    await assert.rejects(fixture.repository.completeWebAuthnRegistrationV2(invalid), (error) => error.code === CODES.INPUT);
  }
  assert.equal(fixture.client.calls.length, 0, "invalid boundary must not reach PostgreSQL");
});

test("same completion request recovers the exact session after response loss and never issues twice", async () => {
  const calls = [];
  const client = new FakeClient(() => {
    calls.push(true);
    return { rows: [databaseRow({ replayed: calls.length > 1 })], rowCount: 1 };
  });
  const repositoryValue = createPostgresHostedIdentityBootstrapRepository({ client });
  assert.equal(typeof repositoryValue.completeWebAuthnRegistrationV2, "function");

  const first = await repositoryValue.completeWebAuthnRegistrationV2(input());
  const replay = await repositoryValue.completeWebAuthnRegistrationV2(input());
  assert.deepEqual(replay, { ...first, replayed: true });
  assert.equal(calls.length, 2, "response-loss recovery is a second lookup of the same durable receipt");
  assert.equal(replay.session.session_id, first.session.session_id);
});

test("a changed request under the same idempotency key is a stable conflict and leaks no database detail", async () => {
  const database = new Error(`raw cookie ${COOKIE} challenge ${CHALLENGE} private key`);
  database.code = "23505";
  const client = new FakeClient(() => { throw database; });
  const repositoryValue = createPostgresHostedIdentityBootstrapRepository({ client });
  assert.equal(typeof repositoryValue.completeWebAuthnRegistrationV2, "function");

  await assert.rejects(repositoryValue.completeWebAuthnRegistrationV2(input()), (error) => {
    assert.equal(error.code, CODES.CONFLICT);
    assert.doesNotMatch(error.message, /cookie|challenge|private|secret/iu);
    assert.doesNotMatch(JSON.stringify(error), /cookie|challenge|private|secret/iu);
    return true;
  });
});
