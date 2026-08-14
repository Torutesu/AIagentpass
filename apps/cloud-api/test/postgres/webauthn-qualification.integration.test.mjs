import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { createPostgresWebAuthnCeremony } from "../../src/human-auth/webauthn/postgres-ceremony.mjs";
import { WEBAUTHN_ERROR_CODES } from "../../src/human-auth/webauthn/ceremony.mjs";
import { createSimpleWebAuthnAssertionVerifier } from "../../src/human-auth/webauthn/simplewebauthn-adapter.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createPostgresHumanRepository } from "../../src/postgres/human-repository.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL;
const RP_ID = "console.example.test";
const ORIGIN = "https://console.example.test";
const EVIL_RP_ID = "evil.example.test";
const EVIL_ORIGIN = "https://evil.example.test";
const SESSION_LIFETIME = "2099-01-01T00:00:00.000Z";

test("real PostgreSQL WebAuthn qualification enforces binding, replay, tenancy, expiry, and counter CAS", {
  skip: !DATABASE_URL,
  timeout: 45_000
}, async (t) => {
  const pool = new Pool({ connectionString: DATABASE_URL, max: 8 });
  t.after(() => pool.end());

  const migrationClient = await pool.connect();
  try {
    const migration = await createMigrationRunner({
      client: migrationClient,
      applicationVersion: "webauthn-qualification"
    }).run();
    assert.equal(migration.currentVersion, 45);
  } finally {
    migrationClient.release();
  }

  const ids = {
    organization: crypto.randomUUID(),
    otherOrganization: crypto.randomUUID(),
    member: crypto.randomUUID(),
    otherMember: crypto.randomUUID(),
    otherOrganizationMember: crypto.randomUUID(),
    membership: crypto.randomUUID(),
    otherMembership: crypto.randomUUID(),
    otherOrganizationMembership: crypto.randomUUID(),
    session: crypto.randomUUID(),
    otherSession: crypto.randomUUID(),
    otherOrganizationSession: crypto.randomUUID()
  };
  const createdAt = new Date(Date.now() - 1_000).toISOString();

  await pool.query(
    `INSERT INTO organizations (id,name) VALUES ($1,$2),($3,$4)`,
    [ids.organization, "WebAuthn qualification organization", ids.otherOrganization, "WebAuthn qualification other organization"]
  );
  await pool.query(
    `INSERT INTO members (id,github_subject,display_name) VALUES
      ($1,$2,'WebAuthn qualification member'),
      ($3,$4,'WebAuthn qualification other member'),
      ($5,$6,'WebAuthn qualification other organization member')`,
    [
      ids.member, `webauthn-qualification-${ids.member}`,
      ids.otherMember, `webauthn-qualification-${ids.otherMember}`,
      ids.otherOrganizationMember, `webauthn-qualification-${ids.otherOrganizationMember}`
    ]
  );
  await pool.query(
    `INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES
      ($1,$2,$3,'owner','active'),
      ($1,$4,$5,'viewer','active'),
      ($6,$7,$8,'owner','active')`,
    [
      ids.organization, ids.membership, ids.member,
      ids.otherMembership, ids.otherMember,
      ids.otherOrganization, ids.otherOrganizationMembership, ids.otherOrganizationMember
    ]
  );

  const repository = createPostgresHumanRepository({ client: pool });
  for (const session of [
    { id: ids.session, member: ids.member, organization: ids.organization, membership: ids.membership, role: "owner" },
    { id: ids.otherSession, member: ids.otherMember, organization: ids.organization, membership: ids.otherMembership, role: "viewer" },
    { id: ids.otherOrganizationSession, member: ids.otherOrganizationMember, organization: ids.otherOrganization, membership: ids.otherOrganizationMembership, role: "owner" }
  ]) {
    await repository.createSession({
      session_id: session.id,
      member_id: session.member,
      organization_id: session.organization,
      membership_id: session.membership,
      role: session.role,
      token_hash: digest(session.id),
      csrf_token_hash: digest(`csrf:${session.id}`),
      created_at: createdAt,
      expires_at: SESSION_LIFETIME,
      last_seen_at: createdAt,
      idle_expires_at: SESSION_LIFETIME
    });
  }

  const credentialId = Buffer.from(crypto.randomUUID().replaceAll("-", ""), "hex").toString("base64url");
  await repository.insertCredential({
    session_id: ids.session,
    member_id: ids.member,
    organization_id: ids.organization,
    credential_id: credentialId,
    public_key: Buffer.alloc(32, 0x41),
    sign_count: 0,
    transports: ["internal"],
    label: "WebAuthn qualification credential",
    backup_eligible: false,
    backup_state: false
  });

  const expectedCounters = new Map();
  const barriers = new Map();
  const observedVerifications = [];
  const verify = async (input) => {
    observedVerifications.push({
      challenge: input.expectedChallenge,
      origin: input.expectedOrigin,
      rpId: input.expectedRPID
    });
    const barrier = barriers.get(input.expectedChallenge);
    if (barrier) await barrier.promise;
    const newCounter = expectedCounters.get(input.expectedChallenge);
    if (!Number.isSafeInteger(newCounter)) throw new Error("test verifier counter is not configured");
    return {
      verified: true,
      authenticationInfo: {
        credentialID: input.response.id,
        newCounter,
        userVerified: true,
        origin: input.expectedOrigin,
        rpID: input.expectedRPID,
        credentialDeviceType: "singleDevice",
        credentialBackedUp: false
      }
    };
  };
  const assertionVerifier = createSimpleWebAuthnAssertionVerifier({
    credentialRepository: repository,
    verify
  });
  let clock = Date.now();
  const ceremony = createPostgresWebAuthnCeremony({
    client: pool,
    verifyAssertion: assertionVerifier,
    now: () => clock,
    ttlMs: 30_000
  });

  const begin = (operation, sessionId = ids.session, organizationId = ids.organization, ttlMs = undefined) => ceremony.begin({
    session_id: sessionId,
    organization_id: organizationId,
    operation,
    rp_id: RP_ID,
    origin: ORIGIN,
    user_verification: "required",
    ...(ttlMs === undefined ? {} : { ttlMs })
  });

  const makeAssertion = (issued, operation, overrides = {}) => {
    const sessionId = overrides.session_id ?? ids.session;
    const organizationId = overrides.organization_id ?? ids.organization;
    const rpId = overrides.rp_id ?? RP_ID;
    const origin = overrides.origin ?? ORIGIN;
    const clientDataOrigin = overrides.clientDataOrigin ?? origin;
    const authenticatorRpId = overrides.authenticatorRpId ?? rpId;
    const flags = Buffer.from([0x05]);
    const signCount = Buffer.alloc(4);
    signCount.writeUInt32BE(overrides.authenticatorSignCount ?? 0);
    return {
      challenge_id: issued.challenge_id,
      challenge: issued.challenge,
      session_id: sessionId,
      organization_id: organizationId,
      operation,
      rp_id: rpId,
      origin,
      user_verification: "required",
      credential_id: credentialId,
      client_data_json: Buffer.from(JSON.stringify({
        type: "webauthn.get",
        challenge: issued.challenge,
        origin: clientDataOrigin,
        crossOrigin: false
      })).toString("base64url"),
      authenticator_data: Buffer.concat([
        crypto.createHash("sha256").update(authenticatorRpId).digest(),
        flags,
        signCount
      ]).toString("base64url"),
      signature: Buffer.alloc(64, 0x42).toString("base64url")
    };
  };

  const bindingOperation = "qualification.webauthn.binding";
  const binding = await begin(bindingOperation);
  expectedCounters.set(binding.challenge, 1);
  const verificationCountBeforeBindingDenials = observedVerifications.length;

  await assert.rejects(
    () => ceremony.consume(makeAssertion(binding, bindingOperation, { clientDataOrigin: EVIL_ORIGIN })),
    (error) => error.code === WEBAUTHN_ERROR_CODES.INVALID_RESPONSE
  );
  await assert.rejects(
    () => ceremony.consume(makeAssertion(binding, bindingOperation, { authenticatorRpId: EVIL_RP_ID })),
    (error) => error.code === WEBAUTHN_ERROR_CODES.INVALID_RESPONSE
  );
  await assert.rejects(
    () => ceremony.consume(makeAssertion(binding, bindingOperation, { origin: EVIL_ORIGIN, clientDataOrigin: EVIL_ORIGIN })),
    (error) => error.code === WEBAUTHN_ERROR_CODES.BINDING_MISMATCH
  );
  assert.equal(observedVerifications.length, verificationCountBeforeBindingDenials);

  await assert.rejects(
    () => ceremony.consume(makeAssertion(binding, bindingOperation, { session_id: ids.otherSession })),
    (error) => error.code === WEBAUTHN_ERROR_CODES.BINDING_MISMATCH
  );
  await assert.rejects(
    () => ceremony.consume(makeAssertion(binding, bindingOperation, {
      session_id: ids.otherOrganizationSession,
      organization_id: ids.otherOrganization
    })),
    (error) => error.code === WEBAUTHN_ERROR_CODES.BINDING_MISMATCH
  );

  const bindingResult = await ceremony.consume(makeAssertion(binding, bindingOperation));
  assert.equal(bindingResult.verified, true);
  assert.equal(observedVerifications.at(-1).origin, ORIGIN);
  assert.equal(observedVerifications.at(-1).rpId, RP_ID);
  await assert.rejects(
    () => ceremony.consume(makeAssertion(binding, bindingOperation)),
    (error) => error.code === WEBAUTHN_ERROR_CODES.CHALLENGE_REPLAYED
  );
  const bindingStatus = await pool.query("SELECT status FROM webauthn_challenges WHERE id=$1", [binding.challenge_id]);
  assert.deepEqual(bindingStatus.rows, [{ status: "consumed" }]);

  assert.equal(await repository.findCredentialForSession({
    session_id: ids.otherSession,
    organization_id: ids.organization,
    credential_id: credentialId
  }), null);
  assert.equal(await repository.findCredentialForSession({
    session_id: ids.otherOrganizationSession,
    organization_id: ids.otherOrganization,
    credential_id: credentialId
  }), null);
  assert.equal(await repository.updateCredentialCounter({
    session_id: ids.otherSession,
    organization_id: ids.organization,
    credential_id: credentialId,
    expected_sign_count: 1,
    sign_count: 2
  }), false);

  const concurrentOperation = "qualification.webauthn.concurrent";
  const concurrent = await begin(concurrentOperation);
  expectedCounters.set(concurrent.challenge, 2);
  const concurrentRequest = makeAssertion(concurrent, concurrentOperation, { authenticatorSignCount: 1 });
  const concurrentResults = await Promise.allSettled([
    ceremony.consume(concurrentRequest),
    ceremony.consume(concurrentRequest)
  ]);
  assert.equal(concurrentResults.filter((result) => result.status === "fulfilled").length, 1);
  const concurrentRejection = concurrentResults.find((result) => result.status === "rejected");
  assert.ok([WEBAUTHN_ERROR_CODES.CHALLENGE_BUSY, WEBAUTHN_ERROR_CODES.CHALLENGE_REPLAYED].includes(concurrentRejection?.reason?.code));
  await assert.rejects(
    () => ceremony.consume(concurrentRequest),
    (error) => error.code === WEBAUTHN_ERROR_CODES.CHALLENGE_REPLAYED
  );

  const expiryClock = { value: clock };
  const expiryCeremony = createPostgresWebAuthnCeremony({
    client: pool,
    verifyAssertion: assertionVerifier,
    now: () => expiryClock.value,
    ttlMs: 1_000
  });
  const expiryOperation = "qualification.webauthn.expiry";
  const expiry = await expiryCeremony.begin({
    session_id: ids.session,
    organization_id: ids.organization,
    operation: expiryOperation,
    rp_id: RP_ID,
    origin: ORIGIN,
    user_verification: "required"
  });
  expectedCounters.set(expiry.challenge, 3);
  expiryClock.value += 1_001;
  await assert.rejects(
    () => expiryCeremony.consume(makeAssertion(expiry, expiryOperation, { authenticatorSignCount: 2 })),
    (error) => error.code === WEBAUTHN_ERROR_CODES.CHALLENGE_EXPIRED
  );
  const expiryStatus = await pool.query("SELECT status FROM webauthn_challenges WHERE id=$1", [expiry.challenge_id]);
  assert.deepEqual(expiryStatus.rows, [{ status: "pending" }]);

  const counterOperations = [
    "qualification.webauthn.counter.a",
    "qualification.webauthn.counter.b"
  ];
  const counterChallenges = await Promise.all(counterOperations.map((operation) => begin(operation)));
  for (const issued of counterChallenges) {
    expectedCounters.set(issued.challenge, 3);
    barriers.set(issued.challenge, deferred());
  }
  const counterRequests = counterChallenges.map((issued, index) => makeAssertion(issued, counterOperations[index], { authenticatorSignCount: 2 }));
  const counterConsumes = counterRequests.map((request) => ceremony.consume(request));
  await waitUntil(() => counterChallenges.every((issued) => observedVerifications.some((item) => item.challenge === issued.challenge)));
  for (const issued of counterChallenges) barriers.get(issued.challenge).resolve();
  const counterResults = await Promise.allSettled(counterConsumes);
  assert.equal(counterResults.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(counterResults.filter((result) => result.status === "rejected").length, 1);
  const rejectedCounterResult = counterResults.find((result) => result.status === "rejected");
  assert.equal(rejectedCounterResult.reason.code, WEBAUTHN_ERROR_CODES.VERIFICATION_FAILED);

  const storedCounter = await pool.query("SELECT sign_count FROM webauthn_credentials WHERE id=$1", [Buffer.from(credentialId, "base64url")]);
  assert.deepEqual(storedCounter.rows, [{ sign_count: "3" }]);
  const counterStatuses = await pool.query("SELECT status FROM webauthn_challenges WHERE id=ANY($1::uuid[]) ORDER BY id", [counterChallenges.map((issued) => issued.challenge_id)]);
  assert.deepEqual(new Set(counterStatuses.rows.map((row) => row.status)), new Set(["consumed", "failed"]));
});

function digest(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function deferred() {
  let resolve;
  const promise = new Promise((nextResolve) => { resolve = nextResolve; });
  return { promise, resolve };
}

async function waitUntil(predicate) {
  for (let attempt = 0; attempt < 500; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("WebAuthn qualification synchronization timed out");
}
