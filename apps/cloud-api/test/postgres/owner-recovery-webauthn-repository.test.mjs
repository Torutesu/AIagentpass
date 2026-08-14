import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  OWNER_RECOVERY_WEBAUTHN_OPERATIONS,
  OwnerRecoveryWebAuthnRepositoryError,
  createPostgresOwnerRecoveryWebAuthnRepository
} from "../../src/postgres/owner-recovery-webauthn-repository.mjs";

const ORG = "11111111-1111-4111-8111-111111111111";
const SESSION = "22222222-2222-4222-8222-222222222222";
const REQUEST = "33333333-3333-4333-8333-333333333333";
const MEMBER = "44444444-4444-4444-8444-444444444444";
const CHALLENGE_ID = "55555555-5555-4555-8555-555555555555";
const CREDENTIAL = Buffer.alloc(32, 0x61).toString("base64url");
const CHALLENGE_BYTES = Buffer.alloc(32, 0x62);
const CHALLENGE = CHALLENGE_BYTES.toString("base64url");
const NOW = Date.parse("2026-08-14T12:00:00.000Z");

class ScriptedClient {
  constructor(handler) { this.handler = handler; this.calls = []; }
  async query(text, params = []) { this.calls.push({ text, params }); return this.handler(text, params, this.calls); }
}

function registration(overrides = {}) {
  return {
    organization_id: ORG,
    recovery_session_id: SESSION,
    request_id: REQUEST,
    member_id: MEMBER,
    ceremony: "registration",
    operation: OWNER_RECOVERY_WEBAUTHN_OPERATIONS.registration,
    rp_id: "console.example.test",
    origin: "https://console.example.test",
    ...overrides
  };
}

function pendingRow() {
  return {
    organization_id: ORG, challenge_id: CHALLENGE_ID, recovery_session_id: SESSION,
    request_id: REQUEST, member_id: MEMBER, ceremony: "registration",
    operation: OWNER_RECOVERY_WEBAUTHN_OPERATIONS.registration,
    challenge_digest: crypto.createHash("sha256").update(CHALLENGE_BYTES).digest(),
    rp_id: "console.example.test", origin: "https://console.example.test",
    user_verification: "required", status: "pending",
    created_at: new Date(NOW - 1_000), expires_at: new Date(NOW + 60_000),
    consume_started_at: null, consumed_at: null, failed_at: null,
    verified_credential_id: null, authorization_consumed_at: null
  };
}

test("issues only a raw in-memory challenge while PostgreSQL receives its digest", async () => {
  const client = new ScriptedClient((text) => {
    if (text.startsWith("SELECT s.stage")) return { rows: [{ stage: "session_issued", credential_id: null, state: "session_issued" }] };
    if (text.startsWith("INSERT INTO owner_recovery_webauthn_challenges")) return { rows: [{ challenge_id: CHALLENGE_ID }] };
    return { rows: [] };
  });
  const repository = createPostgresOwnerRecoveryWebAuthnRepository({ client, now: () => NOW, randomUUID: () => CHALLENGE_ID, randomBytes: () => CHALLENGE_BYTES });
  const result = await repository.begin(registration());
  assert.equal(result.challenge, CHALLENGE);
  assert.equal(result.challenge_id, CHALLENGE_ID);
  const insert = client.calls.find(({ text }) => text.startsWith("INSERT INTO owner_recovery_webauthn_challenges"));
  assert.ok(Buffer.isBuffer(insert.params[7]));
  assert.deepEqual(insert.params[7], crypto.createHash("sha256").update(CHALLENGE_BYTES).digest());
  assert.equal(insert.params.includes(CHALLENGE), false);
  assert.deepEqual(client.calls.map(({ text }) => text === "BEGIN" || text === "COMMIT" ? text : null).filter(Boolean), ["BEGIN", "COMMIT"]);
});

test("claims and completes registration with the credential mutation in one transaction", async () => {
  let claimed = false;
  const client = new ScriptedClient((text) => {
    if (text.startsWith("SELECT organization_id,challenge_id")) return { rows: [pendingRow()] };
    if (text.startsWith("UPDATE owner_recovery_webauthn_challenges\n        SET status='consuming'")) { claimed = true; return { rows: [{ consume_started_at: new Date(NOW) }] }; }
    if (text.startsWith("SELECT status,expires_at")) return { rows: [{ status: "consuming", expires_at: new Date(NOW + 60_000), consume_started_at: new Date(NOW) }] };
    if (text.startsWith("UPDATE owner_recovery_webauthn_challenges\n        SET status='consumed'")) return { rows: [{ consumed_at: new Date(NOW + 1) }] };
    if (text === "SELECT mutation") return { rows: [{ ok: true }] };
    return { rows: [] };
  });
  let current = NOW;
  const repository = createPostgresOwnerRecoveryWebAuthnRepository({ client, now: () => current });
  const claim = await repository.claim(registration({ challenge_id: CHALLENGE_ID, challenge: CHALLENGE, credential_id: CREDENTIAL }));
  assert.equal(claimed, true);
  assert.equal(claim.already_consumed, false);
  current += 1;
  let callbackTx;
  const completed = await repository.complete({ ...registration(), challenge_id: CHALLENGE_ID, credential_id: CREDENTIAL, claim_started_at: claim.claim_started_at, async mutate(tx, binding) {
    callbackTx = tx;
    await tx.query("SELECT mutation");
    assert.equal(binding.challenge_id, CHALLENGE_ID);
    return { committed: true, stage: "credential_enrolled" };
  } });
  assert.equal(callbackTx, client);
  assert.equal(completed.committed, true);
  const texts = client.calls.map(({ text }) => text);
  const mutationIndex = texts.indexOf("SELECT mutation");
  const consumeIndex = texts.findIndex((text) => text.startsWith("UPDATE owner_recovery_webauthn_challenges\n        SET status='consumed'"));
  assert.ok(mutationIndex > -1 && consumeIndex > mutationIndex);
});

test("returns the same public result after response loss without invoking another mutation", async () => {
  const row = { ...pendingRow(), status: "consumed", consume_started_at: new Date(NOW - 100), consumed_at: new Date(NOW - 50), verified_credential_id: Buffer.from(CREDENTIAL, "base64url") };
  const client = new ScriptedClient((text) => text.startsWith("SELECT organization_id,challenge_id") ? { rows: [row] } : { rows: [] });
  const repository = createPostgresOwnerRecoveryWebAuthnRepository({ client, now: () => NOW });
  const result = await repository.claim(registration({ challenge_id: CHALLENGE_ID, challenge: CHALLENGE, credential_id: CREDENTIAL }));
  assert.equal(result.already_consumed, true);
  assert.equal(result.credential_id, CREDENTIAL);
  assert.equal(client.calls.some(({ text }) => text.includes("SET status='consuming'")), false);
});

test("burn is claim-owner bound so a stale verifier cannot burn a reclaimed challenge", async () => {
  const client = new ScriptedClient((text) => text.startsWith("UPDATE owner_recovery_webauthn_challenges")
    ? { rows: [], rowCount: 0 }
    : { rows: [], rowCount: 0 });
  const repository = createPostgresOwnerRecoveryWebAuthnRepository({ client, now: () => NOW + 20_001 });
  const burned = await repository.burn({ organization_id: ORG, challenge_id: CHALLENGE_ID, claim_started_at: new Date(NOW).toISOString() });
  assert.equal(burned, false);
  assert.match(client.calls[0].text, /consume_started_at=\$4/u);
  assert.deepEqual(client.calls[0].params, [ORG, CHALLENGE_ID, new Date(NOW + 20_001).toISOString(), new Date(NOW).toISOString()]);
});

test("authentication consumes its activation authorization only after the authority mutation", async () => {
  const authentication = (overrides = {}) => registration({ ceremony: "authentication", operation: OWNER_RECOVERY_WEBAUTHN_OPERATIONS.authentication, credential_id: CREDENTIAL, ...overrides });
  const client = new ScriptedClient((text) => {
    if (text.startsWith("SELECT status,expires_at")) return { rows: [{ status: "consuming", expires_at: new Date(NOW + 60_000), consume_started_at: new Date(NOW) }] };
    if (text.startsWith("UPDATE owner_recovery_webauthn_challenges\n        SET status='consumed'")) return { rows: [{ consumed_at: new Date(NOW + 1) }] };
    if (text === "SELECT activation_mutation") return { rows: [{ ok: true }] };
    return { rows: [] };
  });
  const repository = createPostgresOwnerRecoveryWebAuthnRepository({ client, now: () => NOW + 1 });
  await repository.complete({ ...authentication(), challenge_id: CHALLENGE_ID, credential_id: CREDENTIAL, claim_started_at: new Date(NOW).toISOString(), async mutate(tx) {
    await tx.query("SELECT activation_mutation");
    return { committed: true };
  } });
  const update = client.calls.find(({ text }) => text.startsWith("UPDATE owner_recovery_webauthn_challenges\n        SET status='consumed'"));
  assert.match(update.text, /authorization_consumed_at=CASE WHEN ceremony='authentication' THEN \$8 ELSE NULL END/u);
  assert.ok(client.calls.findIndex(({ text }) => text === "SELECT activation_mutation") < client.calls.indexOf(update));
});

test("rejects cross-binding, replay substitution, and storage diagnostics with stable secret-free errors", async () => {
  const client = new ScriptedClient((text) => {
    if (text.startsWith("SELECT organization_id,challenge_id")) return { rows: [pendingRow()] };
    return { rows: [] };
  });
  const repository = createPostgresOwnerRecoveryWebAuthnRepository({ client, now: () => NOW });
  await assert.rejects(repository.claim(registration({ request_id: "66666666-6666-4666-8666-666666666666", challenge_id: CHALLENGE_ID, challenge: CHALLENGE, credential_id: CREDENTIAL })), (error) => error.code === "owner_recovery_webauthn_denied");

  const diagnostic = "postgresql://admin:password@db/private";
  const failing = createPostgresOwnerRecoveryWebAuthnRepository({ client: new ScriptedClient(() => { throw new Error(diagnostic); }), now: () => NOW, randomUUID: () => CHALLENGE_ID, randomBytes: () => CHALLENGE_BYTES });
  await assert.rejects(failing.begin(registration()), (error) => {
    assert.ok(error instanceof OwnerRecoveryWebAuthnRepositoryError);
    assert.equal(error.code, "owner_recovery_webauthn_unavailable");
    assert.equal(JSON.stringify(error).includes(diagnostic), false);
    assert.equal("cause" in error, false);
    return true;
  });
});

test("fails closed when the transactional credential callback does not confirm its mutation", async () => {
  const client = new ScriptedClient((text) => {
    if (text.startsWith("SELECT status,expires_at")) return { rows: [{ status: "consuming", expires_at: new Date(NOW + 60_000), consume_started_at: new Date(NOW) }] };
    return { rows: [] };
  });
  const repository = createPostgresOwnerRecoveryWebAuthnRepository({ client, now: () => NOW + 1 });
  await assert.rejects(repository.complete({ ...registration(), challenge_id: CHALLENGE_ID, credential_id: CREDENTIAL, claim_started_at: new Date(NOW).toISOString(), async mutate() { return { committed: false }; } }), (error) => error.code === "owner_recovery_webauthn_unavailable");
  assert.equal(client.calls.some(({ text }) => text === "ROLLBACK"), true);
  assert.equal(client.calls.some(({ text }) => text.includes("SET status='consumed'")), false);
});
