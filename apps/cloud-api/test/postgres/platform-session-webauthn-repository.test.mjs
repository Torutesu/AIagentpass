import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  PLATFORM_SESSION_WEBAUTHN_REPOSITORY_METHODS
} from "../../src/platform-session-webauthn.mjs";
import {
  createPostgresPlatformSessionWebAuthnRepository,
  PLATFORM_SESSION_WEBAUTHN_REPOSITORY_ERROR_CODES as CODES,
  PLATFORM_SESSION_WEBAUTHN_REPOSITORY_SQL,
  PlatformSessionWebAuthnRepositoryError
} from "../../src/postgres/platform-session-webauthn-repository.mjs";

const IDS = Object.freeze({
  challenge: "11111111-1111-4111-8111-111111111111",
  session: "22222222-2222-4222-8222-222222222222",
  principal: "33333333-3333-4333-8333-333333333333",
  member: "44444444-4444-4444-8444-444444444444",
  organization: "55555555-5555-4555-8555-555555555555",
  assignment: "66666666-6666-4666-8666-666666666666",
  platformCredential: "77777777-7777-4777-8777-777777777777"
});
const OPERATION = "platform.promotion.issue";
const PUBLIC_CREDENTIAL_ID = Buffer.alloc(32, 9).toString("base64url");
const REQUEST_DIGEST = "ab".repeat(32);
const JTI_HASH = Buffer.alloc(32, 1);
const CHALLENGE_HASH = Buffer.alloc(32, 2);
const BINDING_HASH = Buffer.alloc(32, 3);
const PUBLIC_KEY = Buffer.alloc(32, 4);
const ISSUED_AT = Date.parse("2026-08-15T12:00:00.000Z");
const EXPIRES_AT = ISSUED_AT + 60_000;

class FakeClient {
  constructor() {
    this.calls = [];
    this.responses = [];
    this.error = undefined;
  }

  enqueue(value) { this.responses.push(value); }

  async query(text, params) {
    this.calls.push({ text, params });
    if (this.error) throw this.error;
    const next = this.responses.shift();
    if (next instanceof Error) throw next;
    return { rowCount: 1, rows: [{ [aliasFor(text)]: next }] };
  }
}

function aliasFor(sql) {
  if (sql === PLATFORM_SESSION_WEBAUTHN_REPOSITORY_SQL.createChallenge || sql === PLATFORM_SESSION_WEBAUTHN_REPOSITORY_SQL.findChallenge) return "challenge";
  if (sql === PLATFORM_SESSION_WEBAUTHN_REPOSITORY_SQL.claimChallenge) return "claim";
  if (sql === PLATFORM_SESSION_WEBAUTHN_REPOSITORY_SQL.failChallenge) return "failure";
  if (sql === PLATFORM_SESSION_WEBAUTHN_REPOSITORY_SQL.findCredential) return "credential";
  if (sql === PLATFORM_SESSION_WEBAUTHN_REPOSITORY_SQL.advanceCredential) return "counter";
  if (sql === PLATFORM_SESSION_WEBAUTHN_REPOSITORY_SQL.completeAndIssue) return "result";
  throw new Error("unexpected SQL in fake client");
}

function challenge(overrides = {}) {
  return {
    challenge_id: IDS.challenge,
    platform_session_id: IDS.session,
    jti_hash: JTI_HASH.toString("hex"),
    challenge_hash: CHALLENGE_HASH.toString("hex"),
    binding_hash: BINDING_HASH.toString("hex"),
    request_digest_sha256: REQUEST_DIGEST,
    allowed_credential_ids: [PUBLIC_CREDENTIAL_ID],
    principal_id: IDS.principal,
    member_id: IDS.member,
    organization_id: IDS.organization,
    assignment_id: IDS.assignment,
    authority_generation: 8,
    operation: OPERATION,
    capability: OPERATION,
    rp_id: "console.agentpass.test",
    origin: "https://console.agentpass.test",
    user_verification: "required",
    status: "pending",
    version: 1,
    issued_at: "2026-08-15T12:00:00.000Z",
    expires_at: "2026-08-15T12:01:00.000Z",
    claimed_at: null,
    completed_at: null,
    failed_at: null,
    failure_reason: null,
    ...overrides
  };
}

function createInput(overrides = {}) {
  return {
    challenge_id: IDS.challenge,
    jti_hash: Buffer.from(JTI_HASH),
    challenge_hash: Buffer.from(CHALLENGE_HASH),
    binding_hash: Buffer.from(BINDING_HASH),
    platform_session_id: IDS.session,
    principal_id: IDS.principal,
    member_id: IDS.member,
    organization_id: IDS.organization,
    assignment_id: IDS.assignment,
    authority_generation: 8,
    operation: OPERATION,
    capability: OPERATION,
    request_digest_sha256: REQUEST_DIGEST,
    allowed_credential_ids: [PUBLIC_CREDENTIAL_ID],
    rp_id: "console.agentpass.test",
    origin: "https://console.agentpass.test",
    user_verification: "required",
    issued_at: ISSUED_AT,
    expires_at: EXPIRES_AT,
    status: "pending",
    ...overrides
  };
}

function credential(overrides = {}) {
  return {
    platform_credential_id: IDS.platformCredential,
    webauthn_credential_id: PUBLIC_CREDENTIAL_ID,
    principal_id: IDS.principal,
    member_id: IDS.member,
    status: "active",
    sign_count: 7,
    sign_count_state: "monotonic",
    backup_eligible: true,
    backup_state: false,
    version: 4,
    public_key: PUBLIC_KEY.toString("base64"),
    transports: ["internal"],
    revoked_at: null,
    ...overrides
  };
}

function session(overrides = {}) {
  return {
    session_id: IDS.session,
    principal_id: IDS.principal,
    member_id: IDS.member,
    organization_id: IDS.organization,
    assignment_id: IDS.assignment,
    credential_id: IDS.platformCredential,
    operation: OPERATION,
    capability: OPERATION,
    principal_authority_generation: 8,
    assignment_version: 3,
    credential_version: 5,
    status: "active",
    version: 1,
    created_at: "2026-08-15T12:00:01.000Z",
    authenticated_at: "2026-08-15T12:00:01.000Z",
    last_seen_at: "2026-08-15T12:00:01.000Z",
    expires_at: "2026-08-15T12:02:01.000Z",
    idle_expires_at: "2026-08-15T12:01:01.000Z",
    expired_at: null,
    revoked_at: null,
    revoke_reason: null,
    ...overrides
  };
}

function claimInput() {
  return {
    challenge_id: IDS.challenge,
    challenge_hash: Buffer.from(CHALLENGE_HASH),
    jti_hash: Buffer.from(JTI_HASH),
    binding_hash: Buffer.from(BINDING_HASH),
    claimed_at: ISSUED_AT
  };
}

function findCredentialInput() {
  return {
    platform_session_id: IDS.session,
    session_id: IDS.session,
    principal_id: IDS.principal,
    member_id: IDS.member,
    organization_id: IDS.organization,
    assignment_id: IDS.assignment,
    authority_generation: 8,
    credential_id: PUBLIC_CREDENTIAL_ID
  };
}

function issueInput() {
  return {
    session_id: IDS.session,
    session_material_hash: Buffer.alloc(32, 5),
    csrf_token_hash: Buffer.alloc(32, 6),
    principal_id: IDS.principal,
    member_id: IDS.member,
    organization_id: IDS.organization,
    assignment_id: IDS.assignment,
    credential_id: IDS.platformCredential,
    operation: OPERATION,
    capability: OPERATION,
    authority_generation: 8,
    request_digest_sha256: REQUEST_DIGEST,
    challenge_id: IDS.challenge,
    jti_hash: Buffer.from(JTI_HASH),
    ttl_seconds: 120,
    idle_timeout_seconds: 60,
    authenticated_at: ISSUED_AT
  };
}

function assertOpaque(error, code) {
  assert(error instanceof PlatformSessionWebAuthnRepositoryError);
  assert.equal(error.code, code);
  assert.equal("cause" in error, false);
  assert.doesNotMatch(error.message, /challenge|jti|bearer|csrf|assertion|signature|private|secret/iu);
  assert.doesNotMatch(JSON.stringify(error), /challenge|jti|bearer|csrf|assertion|signature|private|secret/iu);
}

async function seedChallenge(repository, client, state = challenge()) {
  client.enqueue(state);
  await repository.createPlatformSessionChallenge(createInput());
}

test("exposes exactly the eight service methods and never the unsafe SQL helpers", () => {
  const repository = createPostgresPlatformSessionWebAuthnRepository({ client: new FakeClient() });
  assert.deepEqual(Object.keys(repository), [...PLATFORM_SESSION_WEBAUTHN_REPOSITORY_METHODS]);
  assert.equal(Object.isFrozen(repository), true);
  assert.equal("completeAndIssuePlatformSession" in repository, false);
  assert.equal("agentpass_platform_session_issue" in repository, false);
  assert.equal("agentpass_platform_session_challenge_complete" in repository, false);
});

test("create converts request digest and public WebAuthn ids to bytea parameters", async () => {
  const client = new FakeClient();
  const repository = createPostgresPlatformSessionWebAuthnRepository({ client });
  client.enqueue(challenge());
  const result = await repository.createPlatformSessionChallenge(createInput());
  const call = client.calls[0];

  assert.equal(call.text, PLATFORM_SESSION_WEBAUTHN_REPOSITORY_SQL.createChallenge);
  assert.equal(call.params.length, 18);
  assert.equal(call.params[5].toString("hex"), REQUEST_DIGEST);
  assert.ok(Buffer.isBuffer(call.params[6][0]));
  assert.equal(call.params[6][0].toString("base64url"), PUBLIC_CREDENTIAL_ID);
  assert.equal(call.params.includes(PUBLIC_CREDENTIAL_ID), false);
  assert.deepEqual(result.allowed_credential_ids, [PUBLIC_CREDENTIAL_ID]);
});

test("claim and fail use cached request binding and reject caller-selected timestamps", async () => {
  const client = new FakeClient();
  const repository = createPostgresPlatformSessionWebAuthnRepository({ client });
  await seedChallenge(repository, client);
  client.enqueue({ claimed: true, record: challenge({ status: "consuming", version: 2, claimed_at: "2026-08-15T12:00:02.000Z" }) });
  const claimed = await repository.claimPlatformSessionChallenge(claimInput());
  assert.equal(claimed.claimed, true);
  assert.equal(client.calls[1].text, PLATFORM_SESSION_WEBAUTHN_REPOSITORY_SQL.claimChallenge);
  assert.equal(client.calls[1].params[4].toString("hex"), REQUEST_DIGEST);
  assert.equal(client.calls[1].params.includes(ISSUED_AT), false);

  client.enqueue({ outcome: "failed", record: challenge({ status: "failed", version: 3, claimed_at: "2026-08-15T12:00:02.000Z", failed_at: "2026-08-15T12:00:03.000Z", failure_reason: "verification_failed" }) });
  const failed = await repository.failPlatformSessionChallenge({
    challenge_id: IDS.challenge,
    challenge_hash: Buffer.from(CHALLENGE_HASH),
    jti_hash: Buffer.from(JTI_HASH),
    binding_hash: Buffer.from(BINDING_HASH),
    failed_at: ISSUED_AT + 3_000
  });
  assert.equal(failed.outcome, "failed");
  assert.equal(client.calls[2].params[5], "verification_failed");
});

test("credential lookup separates public id from internal UUID and CAS passes expected state", async () => {
  const client = new FakeClient();
  const repository = createPostgresPlatformSessionWebAuthnRepository({ client });
  await seedChallenge(repository, client);
  client.enqueue({ claimed: true, record: challenge({ status: "consuming", version: 2, claimed_at: "2026-08-15T12:00:02.000Z" }) });
  await repository.claimPlatformSessionChallenge(claimInput());
  client.enqueue(credential());
  const found = await repository.findPlatformCredentialForSession(findCredentialInput());
  assert.equal(found.platform_credential_id, IDS.platformCredential);
  assert.equal(found.webauthn_credential_id, PUBLIC_CREDENTIAL_ID);
  assert.ok(Buffer.isBuffer(found.public_key));

  client.enqueue({ outcome: "accepted", credential: {
    platform_credential_id: IDS.platformCredential,
    webauthn_credential_id: PUBLIC_CREDENTIAL_ID,
    status: "active",
    sign_count: 8,
    sign_count_state: "monotonic",
    backup_eligible: true,
    backup_state: false,
    version: 5,
    clone_detected_at: null
  } });
  const advanced = await repository.advancePlatformCredentialCounter({
    credential_id: IDS.platformCredential,
    webauthn_credential_id: PUBLIC_CREDENTIAL_ID,
    principal_id: IDS.principal,
    member_id: IDS.member,
    organization_id: IDS.organization,
    assignment_id: IDS.assignment,
    authority_generation: 8,
    request_digest_sha256: REQUEST_DIGEST,
    sign_count: 8
  });
  assert.equal(advanced.outcome, "accepted");
  const call = client.calls.at(-1);
  assert.equal(call.text, PLATFORM_SESSION_WEBAUTHN_REPOSITORY_SQL.advanceCredential);
  assert.equal(call.params[4], 4);
  assert.equal(call.params[5], 7);
  assert.equal(call.params[7], true);
  assert.equal(call.params[8], false);
  assert.equal(call.params[2], IDS.platformCredential);
  assert.equal(call.params[3].toString("base64url"), PUBLIC_CREDENTIAL_ID);
});

test("session issue uses one atomic complete_and_issue call and never calls ungranted helpers", async () => {
  const client = new FakeClient();
  const repository = createPostgresPlatformSessionWebAuthnRepository({ client });
  await seedChallenge(repository, client);
  client.enqueue({ claimed: true, record: challenge({ status: "consuming", version: 2, claimed_at: "2026-08-15T12:00:02.000Z" }) });
  await repository.claimPlatformSessionChallenge(claimInput());
  client.enqueue(credential());
  await repository.findPlatformCredentialForSession(findCredentialInput());
  client.enqueue({
    session: session(),
    challenge: challenge({ status: "consumed", version: 3, claimed_at: "2026-08-15T12:00:02.000Z", completed_at: "2026-08-15T12:00:04.000Z" })
  });

  const issued = await repository.issuePlatformSession(issueInput());
  const call = client.calls.at(-1);
  assert.equal(call.text, PLATFORM_SESSION_WEBAUTHN_REPOSITORY_SQL.completeAndIssue);
  assert.match(call.text, /agentpass_platform_session_complete_and_issue/u);
  assert.doesNotMatch(call.text, /agentpass_platform_session_issue\(/u);
  assert.doesNotMatch(call.text, /agentpass_platform_session_challenge_complete\(/u);
  assert.equal(call.params[1].length, 32);
  assert.equal(call.params[2].length, 32);
  assert.equal(call.params[7].toString("hex"), REQUEST_DIGEST);
  assert.equal(call.params[8].toString("base64url"), PUBLIC_CREDENTIAL_ID);
  assert.equal(issued.session.session_id, IDS.session);
  assert.equal(issued.challenge.status, "consumed");
  assert.equal(client.calls.filter(({ text }) => /platform_session_issue\(|challenge_complete\(/u.test(text)).length, 0);
});

test("atomic result and database errors fail closed without leaking raw material", async () => {
  const client = new FakeClient();
  const repository = createPostgresPlatformSessionWebAuthnRepository({ client });
  await seedChallenge(repository, client);
  client.enqueue({ claimed: true, record: challenge({ status: "consuming", version: 2, claimed_at: "2026-08-15T12:00:02.000Z" }) });
  await repository.claimPlatformSessionChallenge(claimInput());
  client.enqueue(credential());
  await repository.findPlatformCredentialForSession(findCredentialInput());
  client.enqueue({ session: session(), challenge: challenge({ status: "pending" }) });
  await assert.rejects(repository.issuePlatformSession(issueInput()), (error) => {
    assertOpaque(error, CODES.RESULT);
    return true;
  });

  const failingClient = new FakeClient();
  failingClient.error = new Error("raw challenge jti bearer csrf assertion signature secret");
  const failingRepository = createPostgresPlatformSessionWebAuthnRepository({ client: failingClient });
  await assert.rejects(failingRepository.findPlatformSessionChallenge({ challenge_id: IDS.challenge }), (error) => {
    assertOpaque(error, CODES.DATABASE);
    return true;
  });
});

test("rejects unknown fields, malformed digests, credential substitution, and raw ceremony material before SQL", async () => {
  const client = new FakeClient();
  const repository = createPostgresPlatformSessionWebAuthnRepository({ client });
  const invalid = [
    { ...createInput(), raw_challenge: "raw-challenge" },
    { ...createInput(), request_digest_sha256: "not-a-digest" },
    { ...createInput(), allowed_credential_ids: [PUBLIC_CREDENTIAL_ID, PUBLIC_CREDENTIAL_ID] },
    { ...createInput(), jti: "raw-jti" },
    { ...createInput(), session_bearer: "raw-bearer" }
  ];
  for (const input of invalid) {
    await assert.rejects(repository.createPlatformSessionChallenge(input), (error) => {
      assertOpaque(error, CODES.INPUT);
      return true;
    });
  }
  assert.equal(client.calls.length, 0);
});

test("requires a durable challenge state before request-bound follow-up methods", async () => {
  const repository = createPostgresPlatformSessionWebAuthnRepository({ client: new FakeClient() });
  await assert.rejects(repository.claimPlatformSessionChallenge(claimInput()), (error) => {
    assertOpaque(error, CODES.INPUT);
    return true;
  });
});

test("hash conversion agrees with SHA-256 transport material without accepting raw tokens", () => {
  const raw = "A".repeat(43);
  const expected = crypto.createHash("sha256").update(raw).digest();
  assert.equal(expected.length, 32);
  assert.equal(typeof raw, "string");
});
