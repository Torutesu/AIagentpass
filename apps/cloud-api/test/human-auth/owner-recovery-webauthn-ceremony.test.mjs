import assert from "node:assert/strict";
import test from "node:test";

import { createOwnerRecoveryWebAuthnCeremony } from "../../src/human-auth/recovery/webauthn-ceremony.mjs";

const organizationId = "11111111-1111-4111-8111-111111111111";
const memberId = "22222222-2222-4222-8222-222222222222";
const requestId = "33333333-3333-4333-8333-333333333333";
const sessionId = "44444444-4444-4444-8444-444444444444";
const challengeId = "55555555-5555-4555-8555-555555555555";
const credentialId = Buffer.alloc(16, 7).toString("base64url");
const rawChallenge = Buffer.alloc(32, 9).toString("base64url");
const base = Object.freeze({
  recovery_session: Object.freeze({ organization_id: organizationId, member_id: memberId, request_id: requestId, recovery_session_id: sessionId }),
  organization_id: organizationId,
  member_id: memberId,
  request_id: requestId,
  rp_id: "console.agentpass.test",
  origin: "https://console.agentpass.test"
});

test("registration consumes the durable challenge in the credential mutation transaction", async () => {
  const calls = [];
  const fixture = createFixture({ calls });
  const result = await fixture.ceremony.verifyRegistration({ ...base, operation: "human.recovery.credential.register", challenge_id: challengeId, credential: registrationCredential(), complete: async (tx, binding, credential) => {
    calls.push(["mutate", tx, binding, credential]);
    return { committed: true, request: { request_id: requestId } };
  } });
  assert.equal(result.committed, true);
  assert.deepEqual(calls.map((call) => call[0]), ["claim", "verify-attestation", "complete", "mutate"]);
  assert.equal(calls[3][1], fixture.tx);
  assert.equal(calls[3][3].credential_id, credentialId);
  assert.equal(calls.some((call) => call[0] === "burn"), false);
});

test("registration verification failure burns the claimed challenge without retaining a cause", async () => {
  const calls = [];
  const fixture = createFixture({ calls, registrationResult: { verified: false } });
  await assert.rejects(() => fixture.ceremony.verifyRegistration({ ...base, operation: "human.recovery.credential.register", challenge_id: challengeId, credential: registrationCredential(), complete: async () => ({ committed: true }) }), (error) => {
    assert.equal(error.name, "OwnerRecoveryWebAuthnCeremonyError");
    assert.equal(Object.hasOwn(error, "cause"), false);
    return true;
  });
  assert.deepEqual(calls.map((call) => call[0]), ["claim", "verify-attestation", "burn"]);
});

test("activation updates the signature counter and activates in the same completion transaction", async () => {
  const calls = [];
  const fixture = createFixture({ calls });
  const result = await fixture.ceremony.authorizeActivation({ ...base, operation: "human.recovery.activate", challenge_id: challengeId, assertion: assertionCredential(), complete: async (tx, binding, proof) => {
    calls.push(["activate", tx, binding, proof]);
    return { committed: true, request: { request_id: requestId } };
  } });
  assert.equal(result.verified, true);
  assert.equal(result.consumed, true);
  assert.deepEqual(calls.map((call) => call[0]), ["claim", "find", "verify-authentication", "complete", "activate"]);
  assert.equal(calls[4][1], fixture.tx);
  assert.equal(calls[4][3].authorization_id, challengeId);
});

test("activation options bind the newly enrolled credential", async () => {
  const calls = [];
  const fixture = createFixture({ calls });
  const result = await fixture.ceremony.beginActivation({ ...base, operation: "human.recovery.activate" });
  assert.equal(result.challenge_id, challengeId);
  assert.equal(result.options.challenge, rawChallenge);
  assert.equal(result.options.allowCredentials[0].id, credentialId);
  assert.deepEqual(calls.map((call) => call[0]), ["find", "begin"]);
  assert.equal(calls[1][1].ceremony, "authentication");
  assert.equal(calls[1][1].credential_id, credentialId);
});

function createFixture({ calls, registrationResult = undefined } = {}) {
  const tx = Object.freeze({ query() {} });
  const coordinator = {
    async begin(input) { calls.push(["begin", input]); return { challenge_id: challengeId, challenge: rawChallenge, expires_at: "2099-01-01T00:00:00.000Z" }; },
    async claim(input) { calls.push(["claim", input]); return { claim_started_at: "2026-08-14T00:00:00.000Z" }; },
    async complete(input) { calls.push(["complete", input]); const mutation = await input.mutate(tx, { challenge_id: challengeId }); return { committed: true, consumed_at: "2026-08-14T00:00:01.000Z", mutation }; },
    async burn(input) { calls.push(["burn", input]); return true; }
  };
  const recoveryRepository = {
    async findRecoveryCredential(input) { calls.push(["find", input]); return { credential_id: credentialId, public_key: Buffer.alloc(32, 3), sign_count: 1, transports: ["internal"], credential_device_type: "singleDevice", credential_backed_up: false, backup_eligible: false, backup_state: false }; }
  };
  const registrationVerifier = {
    async generateOptions(input) { return { challenge: input.challenge, rp: { id: input.rp.id }, user: input.user }; },
    async verifyAttestation(input) { calls.push(["verify-attestation", input]); return registrationResult ?? { verified: true, credential_id: credentialId, public_key: Buffer.alloc(32, 3), sign_count: 0, transports: ["internal"], credential_device_type: "singleDevice", credential_backed_up: false, user_verified: true }; }
  };
  const verifyAuthentication = async (input) => { calls.push(["verify-authentication", input]); return { verified: true, authenticationInfo: { credentialID: credentialId, userVerified: true, origin: base.origin, rpID: base.rp_id, newCounter: 2, credentialDeviceType: "singleDevice", credentialBackedUp: false } }; };
  return { tx, ceremony: createOwnerRecoveryWebAuthnCeremony({ coordinator, recoveryRepository, registrationVerifier, verifyAuthentication }) };
}

function registrationCredential() {
  return { id: credentialId, rawId: credentialId, type: "public-key", clientExtensionResults: {}, response: { clientDataJSON: clientData("webauthn.create"), attestationObject: Buffer.alloc(32, 4).toString("base64url"), transports: ["internal"] } };
}

function assertionCredential() {
  return { id: credentialId, rawId: credentialId, type: "public-key", clientExtensionResults: {}, response: { clientDataJSON: clientData("webauthn.get"), authenticatorData: Buffer.alloc(37, 5).toString("base64url"), signature: Buffer.alloc(64, 6).toString("base64url"), userHandle: null } };
}

function clientData(type) {
  return Buffer.from(JSON.stringify({ type, challenge: rawChallenge, origin: base.origin, crossOrigin: false }), "utf8").toString("base64url");
}
