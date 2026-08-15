import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_ERROR_CODES as CODES,
  HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_SQL as SQL,
  createPostgresHostedIdentityBootstrapRepository
} from "../../src/postgres/hosted-identity-bootstrap-repository.mjs";

const IDS = Object.freeze({
  attempt: "11111111-1111-4111-8111-111111111111",
  challenge: "22222222-2222-4222-8222-222222222222",
  member: "33333333-3333-4333-8333-333333333333",
  organization: "44444444-4444-4444-8444-444444444444",
  membership: "55555555-5555-4555-8555-555555555555",
  session: "66666666-6666-4666-8666-666666666666"
});
const COOKIE = "bootstrap-cookie-never-sent-to-postgres";
const CHALLENGE = "challenge-never-sent-to-postgres";
const CLAIM = "C".repeat(43);
const SESSION = "S".repeat(43);
const CSRF = "X".repeat(43);
const CREDENTIAL_ID = Buffer.alloc(32, 0x22).toString("base64url");

function digest(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest();
}

function claimRow() {
  return {
    attempt_id: IDS.attempt,
    member_id: IDS.member,
    organization_id: IDS.organization,
    rp_id: "console.example.test",
    origin: "https://console.example.test",
    user_verification: "required",
    claim_generation: 7,
    claim_expires_at: "2026-08-15T00:00:30.000Z"
  };
}

function completionRow() {
  return {
    attempt_id: IDS.attempt,
    session_id: IDS.session,
    member_id: IDS.member,
    organization_id: IDS.organization,
    membership_id: IDS.membership,
    role: "owner",
    created_at: "2026-08-15T00:00:00.000Z",
    expires_at: "2026-08-15T08:00:00.000Z",
    replayed: false
  };
}

function repository() {
  const calls = [];
  const client = {
    async query(text, params) {
      calls.push({ text, params });
      if (text === SQL.claimChallengeV2) return { rows: [claimRow()], rowCount: 1 };
      if (text === SQL.completeWebAuthnRegistrationV3) return { rows: [completionRow()], rowCount: 1 };
      if (text === SQL.failChallengeV3) return { rows: [{ result: null }], rowCount: 1 };
      throw new Error("unexpected query");
    }
  };
  return { calls, value: createPostgresHostedIdentityBootstrapRepository({ client }) };
}

function completionInput(overrides = {}) {
  return {
    attempt_id: IDS.attempt,
    bootstrap_cookie: COOKIE,
    challenge_id: IDS.challenge,
    challenge: CHALLENGE,
    claim_token: CLAIM,
    claim_generation: 7,
    credential: {
      id: CREDENTIAL_ID,
      public_key: Buffer.alloc(65, 0x33),
      sign_count: 0,
      transports: ["internal"],
      label: "Passkey",
      backup_eligible: false,
      backup_state: false
    },
    session: { token: SESSION, csrf_token: CSRF },
    ...overrides
  };
}

test("claim V2 hashes every selector and exposes only the database lease", async () => {
  const fixture = repository();
  const result = await fixture.value.claimChallengeV2({
    bootstrap_cookie: COOKIE,
    challenge_id: IDS.challenge,
    challenge: CHALLENGE,
    claim_token: CLAIM
  });
  const call = fixture.calls[0];

  assert.equal(call.text, SQL.claimChallengeV2);
  assert.deepEqual(call.params, [digest(COOKIE), IDS.challenge, digest(CHALLENGE), digest(CLAIM)]);
  assert.equal(JSON.stringify(call.params).includes(CLAIM), false);
  assert.equal(result.claim_expires_at, claimRow().claim_expires_at);
  assert.equal(result.claim_generation, 7);
  assert.equal(Object.keys(result).some((key) => /token|cookie|secret/iu.test(key)), false);
});

test("claim-bound V3 completion hashes claim/session authority before SQL", async () => {
  const fixture = repository();
  const result = await fixture.value.completeWebAuthnRegistrationV3(completionInput());
  const call = fixture.calls[0];

  assert.equal(call.text, SQL.completeWebAuthnRegistrationV3);
  assert.equal(call.params.length, 16);
  assert.equal(call.params[5], 7);
  for (const [raw, position] of [[COOKIE, 1], [CHALLENGE, 3], [CLAIM, 4], [SESSION, 14], [CSRF, 15]]) {
    assert.equal(call.params.includes(raw), false);
    assert.deepEqual(call.params[position], digest(raw));
  }
  assert.equal(result.session.session_id, IDS.session);
  assert.equal(JSON.stringify(result).includes(CLAIM), false);
});

test("claim-bound failure hashes its claim and rejects open input", async () => {
  const fixture = repository();
  await fixture.value.failChallengeV3({
    bootstrap_cookie: COOKIE,
    challenge_id: IDS.challenge,
    challenge: CHALLENGE,
    claim_token: CLAIM,
    claim_generation: 7,
    failure_code: "verification_failed"
  });
  assert.deepEqual(fixture.calls[0].params, [digest(COOKIE), IDS.challenge, digest(CHALLENGE), digest(CLAIM), 7, "verification_failed"]);

  await assert.rejects(
    fixture.value.claimChallengeV2({ bootstrap_cookie: COOKIE, challenge_id: IDS.challenge, challenge: CHALLENGE, claim_token: CLAIM, lease_seconds: 600 }),
    (error) => error.code === CODES.INPUT
  );
  await assert.rejects(
    fixture.value.completeWebAuthnRegistrationV3({ ...completionInput(), claim_token: "short" }),
    (error) => error.code === CODES.INPUT
  );
  assert.equal(fixture.calls.length, 1);
});

test("a fenced stale generation is a stable conflict without database detail", async () => {
  const database = new Error(`stale claim ${CLAIM} cookie ${COOKIE}`);
  database.code = "28000";
  const value = createPostgresHostedIdentityBootstrapRepository({ client: { async query() { throw database; } } });
  await assert.rejects(value.completeWebAuthnRegistrationV3(completionInput()), (error) => {
    assert.equal(error.code, CODES.CONFLICT);
    assert.doesNotMatch(error.message, /claim|cookie|stale/iu);
    return true;
  });
});
