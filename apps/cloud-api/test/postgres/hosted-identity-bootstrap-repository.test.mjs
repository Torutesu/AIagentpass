import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_ERROR_CODES as CODES,
  HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_SQL as SQL,
  HostedIdentityBootstrapRepositoryError,
  createPostgresHostedIdentityBootstrapRepository
} from "../../src/postgres/hosted-identity-bootstrap-repository.mjs";

const IDS = Object.freeze({
  attempt: "11111111-1111-4111-8111-111111111111",
  oauth: "22222222-2222-4222-8222-222222222222",
  member: "33333333-3333-4333-8333-333333333333",
  organization: "44444444-4444-4444-8444-444444444444",
  membership: "55555555-5555-4555-8555-555555555555",
  challenge: "66666666-6666-4666-8666-666666666666"
});
const REDIRECT = "https://console.example.test/api/auth/bootstrap/github/callback";
const ORIGIN = "https://console.example.test";
const RP_ID = "console.example.test";
const NOW = "2026-08-15T00:00:00.000Z";
const LATER = "2026-08-15T00:10:00.000Z";
const STATE = "state-secret-that-never-reaches-postgresql";
const CODE = "oauth-code-that-never-reaches-postgresql";
const COOKIE = "bootstrap-cookie-that-never-reaches-postgresql";
const CSRF = "csrf-token-that-never-reaches-postgresql";
const CHALLENGE = "webauthn-challenge-that-never-reaches-postgresql";

class FakeClient {
  constructor(handler = () => ({ rows: [{ ok: true }], rowCount: 1 })) { this.handler = handler; this.calls = []; }
  async query(text, params) { this.calls.push({ text, params }); return this.handler(text, params, this.calls); }
}

function repo(handler) { const client = new FakeClient(handler); return { client, repository: createPostgresHostedIdentityBootstrapRepository({ client }) }; }
function digest(value) { return crypto.createHash("sha256").update(value, "utf8").digest(); }
function publicResponse() { return { version: 1, organization: { organization_id: IDS.organization, name: "Acme", version: 1, created_at: NOW, updated_at: NOW }, onboarding: { state: "webauthn_required" } }; }
function startRow() { return { attempt_id: IDS.attempt, oauth_state_id: IDS.oauth, state_expires_at: NOW, attempt_expires_at: LATER }; }
function challengeRow() { return { challenge_id: IDS.challenge, member_id: IDS.member, organization_id: IDS.organization, rp_id: RP_ID, origin: ORIGIN, expires_at: LATER }; }

test("uses exact SQL signatures and hashes every raw selector before query", async () => {
  const { client, repository } = repo((text) => {
    if (text === SQL.start) return { rows: [startRow()], rowCount: 1 };
    if (text === SQL.consumeOAuthState) return { rows: [{ attempt_id: IDS.attempt, pkce_challenge: "A".repeat(43), pkce_method: "S256", client_id: "github-client", redirect_uri: REDIRECT }], rowCount: 1 };
    if (text === SQL.completeOAuthState) return { rows: [{ result: IDS.attempt }], rowCount: 1 };
    if (text === SQL.issueCsrf) return { rows: [{ result: true }], rowCount: 1 };
    if (text === SQL.createChallenge) return { rows: [challengeRow()], rowCount: 1 };
    if (text === SQL.consumeChallenge) return { rows: [{ attempt_id: IDS.attempt, member_id: IDS.member, organization_id: IDS.organization, rp_id: RP_ID, origin: ORIGIN, user_verification: "required" }], rowCount: 1 };
    if (text === SQL.completeChallenge) return { rows: [{ result: IDS.attempt }], rowCount: 1 };
    if (text === SQL.commitOrganization) return { rows: [{ response_status: 201, response_json: publicResponse(), replayed: false }], rowCount: 1 };
    return { rows: [{ result: null }], rowCount: 1 };
  });
  await repository.start({ attempt_id: IDS.attempt, oauth_state_id: IDS.oauth, state: STATE, pkce_challenge: "A".repeat(43), client_id: "github-client", redirect_uri: REDIRECT });
  await repository.consumeOAuthState({ oauth_state_id: IDS.oauth, code: CODE, redirect_uri: REDIRECT });
  await repository.completeOAuthState({ oauth_state_id: IDS.oauth, bootstrap_cookie: COOKIE, member_id: IDS.member, subject: "12345" });
  await repository.issueCsrf({ bootstrap_cookie: COOKIE, csrf_token: CSRF });
  await repository.commitOrganization({ bootstrap_cookie: COOKIE, idempotency_key: "bootstrap-0001", request_hash: digest("request"), organization_id: IDS.organization, membership_id: IDS.membership, public_response: publicResponse() });
  await repository.createChallenge({ bootstrap_cookie: COOKIE, challenge_id: IDS.challenge, challenge: CHALLENGE, rp_id: RP_ID, origin: ORIGIN, expires_at: LATER });
  await repository.consumeChallenge({ bootstrap_cookie: COOKIE, challenge_id: IDS.challenge, challenge: CHALLENGE });
  await repository.completeChallenge({ bootstrap_cookie: COOKIE, challenge_id: IDS.challenge, challenge: CHALLENGE });
  const allParams = client.calls.flatMap((call) => call.params);
  for (const raw of [STATE, CODE, COOKIE, CSRF, CHALLENGE]) {
    assert.equal(allParams.includes(raw), false, `${raw} must not be sent to SQL`);
    assert.equal(allParams.some((value) => Buffer.isBuffer(value) && value.equals(digest(raw))), true, `${raw} must be hashed`);
  }
  assert.deepEqual(client.calls[0], { text: SQL.start, params: [IDS.attempt, IDS.oauth, digest(STATE), "A".repeat(43), "github-client", REDIRECT] });
  const completion = client.calls.find((call) => call.text === SQL.completeOAuthState);
  assert.deepEqual(completion.params, [IDS.oauth, digest(COOKIE), IDS.member, "12345", digest("12345")]);
  assert.match(SQL.completeOAuthState, /\$3::uuid,\$4::text,\$5::bytea/u);
});

test("0058 start and claim keep PKCE plaintext out of PostgreSQL parameters", async () => {
  const envelope = { key_id: "pkce-key-v1", nonce: Buffer.alloc(12, 1), ciphertext: Buffer.alloc(43, 2), auth_tag: Buffer.alloc(16, 3), expires_at: LATER };
  const pkceVerifier = "V".repeat(43);
  const { client, repository } = repo((text) => {
    if (text === SQL.startOAuthV2) return { rows: [startRow()], rowCount: 1 };
    if (text === SQL.claimOAuthStateV2) return { rows: [{
      attempt_id: IDS.attempt,
      oauth_state_id: IDS.oauth,
      pkce_challenge: "A".repeat(43),
      client_id: "github-client",
      redirect_uri: REDIRECT,
      key_id: envelope.key_id,
      nonce: envelope.nonce,
      ciphertext: envelope.ciphertext,
      auth_tag: envelope.auth_tag,
      expires_at: new Date(LATER)
    }], rowCount: 1 };
    throw new Error("unexpected query");
  });
  await repository.startOAuthV2({ attempt_id: IDS.attempt, oauth_state_id: IDS.oauth, state: STATE, pkce_challenge: "A".repeat(43), client_id: "github-client", redirect_uri: REDIRECT, envelope });
  const claimed = await repository.claimOAuthStateV2({ oauth_state_id: IDS.oauth, state: STATE, code: CODE, redirect_uri: REDIRECT });
  assert.deepEqual(client.calls[0].params, [IDS.attempt, IDS.oauth, digest(STATE), "A".repeat(43), "github-client", REDIRECT, envelope.key_id, envelope.nonce, envelope.ciphertext, envelope.auth_tag, LATER]);
  assert.deepEqual(client.calls[1].params, [IDS.oauth, digest(STATE), digest(CODE), REDIRECT]);
  assert.equal(client.calls.flatMap(({ params }) => params).includes(pkceVerifier), false);
  assert.deepEqual(claimed.envelope, { key_id: envelope.key_id, nonce: envelope.nonce, ciphertext: envelope.ciphertext, auth_tag: envelope.auth_tag });
  assert.equal(claimed.expires_at, LATER);
  assert.match(SQL.startOAuthV2, /bootstrap_start_v2/u);
  assert.match(SQL.claimOAuthStateV2, /oauth_state_claim_v2/u);
});

test("H2 completes OAuth through the exact V2 SQL boundary and normalizes the durable result", async () => {
  const subject = "12345";
  const { client, repository } = repo((text) => text === SQL.completeOAuthStateV2
    ? { rows: [{ attempt_id: IDS.attempt, state: "organization_required", organization_count: "0", expires_at: new Date("2026-08-15T09:10:11+09:00") }], rowCount: 1 }
    : { rows: [], rowCount: 0 });
  const result = await repository.completeOAuthStateV2({
    oauth_state_id: IDS.oauth,
    attempt_id: IDS.attempt,
    bootstrap_cookie: COOKIE,
    candidate_member_id: IDS.member,
    provider: "github",
    subject
  });

  assert.deepEqual(result, {
    attempt_id: IDS.attempt,
    state: "organization_required",
    organization_count: 0,
    expires_at: "2026-08-15T00:10:11.000Z"
  });
  assert.equal(SQL.completeOAuthStateV2, "SELECT * FROM public.agentpass_hosted_identity_oauth_complete_v2($1::uuid,$2::uuid,$3::bytea,$4::uuid,$5::text,$6::text,$7::bytea)");
  assert.deepEqual(client.calls, [{
    text: SQL.completeOAuthStateV2,
    params: [IDS.oauth, IDS.attempt, digest(COOKIE), IDS.member, "github", subject, digest(subject)]
  }]);
});

test("H2 treats a missing completion row as null and rejects unsafe identity/result boundaries", async () => {
  const empty = repo(() => ({ rows: [], rowCount: 0 }));
  const input = { oauth_state_id: IDS.oauth, attempt_id: IDS.attempt, bootstrap_cookie: COOKIE, candidate_member_id: IDS.member, provider: "github", subject: "12345" };
  assert.equal(await empty.repository.completeOAuthStateV2(input), null);

  for (const invalid of [
    { ...input, provider: "google" },
    { ...input, subject: "0" },
    { ...input, subject: "0001" },
    { ...input, subject: "12x" },
    { ...input, subject: "1".repeat(21) },
    { ...input, extra: true }
  ]) {
    await assert.rejects(empty.repository.completeOAuthStateV2(invalid), (error) => error.code === CODES.INPUT);
  }

  for (const row of [
    { attempt_id: IDS.member, state: "identity_verified", organization_count: 0, expires_at: LATER },
    { attempt_id: IDS.attempt, state: "completed", organization_count: 0, expires_at: LATER },
    { attempt_id: IDS.attempt, state: "no_membership", organization_count: -1, expires_at: LATER },
    { attempt_id: IDS.attempt, state: "no_membership", organization_count: Number.MAX_SAFE_INTEGER + 1, expires_at: LATER },
    { attempt_id: IDS.attempt, state: "no_membership", organization_count: null, expires_at: LATER },
    { attempt_id: IDS.attempt, state: "no_membership", organization_count: "", expires_at: LATER },
    { attempt_id: IDS.attempt, state: "identity_verified", organization_count: 0, expires_at: LATER },
    { attempt_id: IDS.attempt, state: "organization_required", organization_count: 1, expires_at: LATER },
    { attempt_id: IDS.attempt, state: "no_membership", organization_count: 1, expires_at: LATER },
    { attempt_id: IDS.attempt, state: "no_membership", organization_count: 0, expires_at: "not-a-timestamp" },
    { attempt_id: IDS.attempt, state: "no_membership", organization_count: 0, expires_at: LATER, extra: true }
  ]) {
    const invalidResult = repo((text) => text === SQL.completeOAuthStateV2 ? { rows: [row], rowCount: 1 } : { rows: [], rowCount: 0 });
    await assert.rejects(invalidResult.repository.completeOAuthStateV2(input), (error) => error.code === CODES.RESULT);
  }
});

test("covers OAuth failure, challenge failure, and empty transition results", async () => {
  const { client, repository } = repo((text) => text === SQL.consumeOAuthState || text === SQL.consumeChallenge ? { rows: [], rowCount: 0 } : { rows: [{ result: null }], rowCount: 1 });
  assert.equal(await repository.consumeOAuthState({ oauth_state_id: IDS.oauth, code: CODE, redirect_uri: REDIRECT }), null);
  assert.equal(await repository.consumeChallenge({ bootstrap_cookie: COOKIE, challenge_id: IDS.challenge, challenge: CHALLENGE }), null);
  assert.equal(await repository.failOAuthState({ oauth_state_id: IDS.oauth, failure_code: "provider_failed" }), true);
  assert.equal(await repository.failChallenge({ bootstrap_cookie: COOKIE, challenge_id: IDS.challenge, challenge: CHALLENGE, failure_code: "verification_failed" }), true);
  assert.equal(client.calls.filter(({ text }) => text === SQL.failOAuthState).length, 1);
  assert.equal(client.calls.filter(({ text }) => text === SQL.failChallenge).length, 1);
});

test("enforces closed input and output contracts before exposing durable state", async () => {
  const { client, repository } = repo(() => ({ rows: [{ result: true, extra: "reject" }], rowCount: 1 }));
  await assert.rejects(repository.issueCsrf({ bootstrap_cookie: COOKIE, csrf_token: CSRF, extra: true }), (error) => error.code === CODES.INPUT);
  await assert.rejects(repository.issueCsrf({ bootstrap_cookie: COOKIE, csrf_token: CSRF }), (error) => error.code === CODES.RESULT);
  assert.equal(client.calls.length, 1);
  await assert.rejects(repository.createChallenge({ bootstrap_cookie: COOKIE, challenge_id: IDS.challenge, challenge: CHALLENGE, rp_id: RP_ID, origin: REDIRECT, expires_at: LATER, extra: true }), (error) => error.code === CODES.INPUT);
  await assert.rejects(repository.failChallenge({ bootstrap_cookie: COOKIE, challenge_id: IDS.challenge, challenge: CHALLENGE, failure_code: "Bad-Code" }), (error) => error.code === CODES.INPUT);

  const invalidResult = repo((text) => text === SQL.consumeOAuthState
    ? { rows: [{ attempt_id: IDS.attempt, pkce_challenge: "short", pkce_method: "S256", client_id: "github-client", redirect_uri: REDIRECT }], rowCount: 1 }
    : { rows: [{ result: null }], rowCount: 1 });
  await assert.rejects(invalidResult.repository.consumeOAuthState({ oauth_state_id: IDS.oauth, code: CODE, redirect_uri: REDIRECT }), (error) => error.code === CODES.RESULT);
  await assert.rejects(invalidResult.repository.completeChallenge({ bootstrap_cookie: COOKIE, challenge_id: IDS.challenge, challenge: CHALLENGE }), (error) => error.code === CODES.RESULT);
});

test("does not leak database messages and classifies only stable SQL states", async () => {
  const database = new Error("raw selector=secret and password=do-not-leak");
  database.code = "XX000";
  const { repository } = repo(() => { throw database; });
  await assert.rejects(repository.issueCsrf({ bootstrap_cookie: COOKIE, csrf_token: CSRF }), (error) => {
    assert.ok(error instanceof HostedIdentityBootstrapRepositoryError);
    assert.equal(error.code, CODES.DATABASE);
    assert.equal(error.message, "Hosted identity bootstrap storage is unavailable");
    assert.equal(error.message.includes("secret"), false);
    return true;
  });
  const retry = repo(() => { const error = new Error("serialization details"); error.code = "40001"; throw error; });
  await assert.rejects(retry.repository.issueCsrf({ bootstrap_cookie: COOKIE, csrf_token: CSRF }), (error) => error.code === CODES.RETRYABLE && !error.message.includes("serialization"));
  const conflict = repo(() => { const error = new Error("duplicate selector"); error.code = "23505"; throw error; });
  await assert.rejects(conflict.repository.issueCsrf({ bootstrap_cookie: COOKIE, csrf_token: CSRF }), (error) => error.code === CODES.CONFLICT && !error.message.includes("duplicate"));
});

test("uses DB-clock outputs and does not add client-side timestamps or expiry calculations", async () => {
  const { client, repository } = repo((text) => text === SQL.start ? { rows: [startRow()], rowCount: 1 } : { rows: [challengeRow()], rowCount: 1 });
  const started = await repository.start({ attempt_id: IDS.attempt, oauth_state_id: IDS.oauth, state: STATE, pkce_challenge: "A".repeat(43), client_id: "github-client", redirect_uri: REDIRECT });
  assert.deepEqual(started, startRow());
  await repository.createChallenge({ bootstrap_cookie: COOKIE, challenge_id: IDS.challenge, challenge: CHALLENGE, rp_id: RP_ID, origin: ORIGIN, expires_at: LATER });
  assert.equal(client.calls[0].params.includes(NOW), false);
  assert.equal(client.calls[0].params.includes(LATER), false);
  assert.equal(client.calls[1].params.includes(LATER), true);
});
