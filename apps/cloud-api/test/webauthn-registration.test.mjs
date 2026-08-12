import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  createSimpleWebAuthnRegistrationVerifier,
  createWebAuthnRegistrationCeremony,
  createWebAuthnRegistrationService,
  WebAuthnRegistrationError,
  WEBAUTHN_REGISTRATION_ERROR_CODES,
  WEBAUTHN_REGISTRATION_OPERATION
} from "../src/human-auth/webauthn/registration.mjs";

const ORIGIN = "https://console.agentpass.test";
const RP_ID = "console.agentpass.test";
const SESSION_ID = "11111111-1111-4111-8111-111111111111";
const MEMBER_ID = "22222222-2222-4222-8222-222222222222";
const ORGANIZATION_ID = "33333333-3333-4333-8333-333333333333";
const CHALLENGE_ID = "44444444-4444-4444-8444-444444444444";
const CREDENTIAL_ID = Buffer.alloc(16, 1).toString("base64url");
const OTHER_CREDENTIAL_ID = Buffer.alloc(16, 2).toString("base64url");
const NOW = 1_900_000_000_000;

function clock() {
  let value = NOW;
  return { now: () => value, advance: (milliseconds) => { value += milliseconds; } };
}

function context(overrides = {}) {
  return {
    session_id: SESSION_ID,
    member_id: MEMBER_ID,
    organization_id: ORGANIZATION_ID,
    operation: WEBAUTHN_REGISTRATION_OPERATION,
    rp_id: RP_ID,
    origin: ORIGIN,
    user_verification: "required",
    ...overrides
  };
}

function clientData(challenge, overrides = {}) {
  return Buffer.from(JSON.stringify({ type: "webauthn.create", challenge, origin: ORIGIN, crossOrigin: false, ...overrides })).toString("base64url");
}

function attestation(challenge, overrides = {}) {
  return {
    ...context(),
    challenge,
    challenge_id: CHALLENGE_ID,
    credential_id: CREDENTIAL_ID,
    client_data_json: clientData(challenge),
    attestation_object: Buffer.alloc(96, 7).toString("base64url"),
    ...overrides
  };
}

function options(challenge, user, excludeCredentials = []) {
  return {
    challenge,
    rp: { name: "AgentPass", id: RP_ID },
    user: { id: user.id, name: user.name, displayName: user.displayName },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
    timeout: 60_000,
    attestation: "none",
    excludeCredentials,
    authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
    extensions: { credProps: true },
    hints: []
  };
}

function user() {
  return { id: Buffer.from(MEMBER_ID.replaceAll("-", ""), "hex").toString("base64url"), name: "owner@example.test", displayName: "Owner" };
}

function verifier(overrides = {}) {
  const calls = [];
  return {
    calls,
    async verifyAttestation(input) {
      calls.push(input);
      if (overrides.verify) return overrides.verify(input);
      return {
        verified: true,
        user_verified: true,
        credential_id: input.attestation.credential_id,
        public_key: Buffer.alloc(65, 8),
        sign_count: 0,
        transports: ["internal"]
      };
    }
  };
}

test("registration ceremony binds member/session/org/RP/origin, requires UV, and stores no raw challenge", async () => {
  const time = clock();
  const verification = verifier();
  const ceremony = createWebAuthnRegistrationCeremony({ verifyAttestation: verification.verifyAttestation, now: time.now, randomUUID: () => CHALLENGE_ID, randomBytes: () => Buffer.alloc(32, 9) });
  const issued = ceremony.begin(context());
  assert.match(issued.challenge, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(JSON.stringify(ceremony.snapshot()).includes(issued.challenge), false);
  assert.equal(JSON.stringify(ceremony.snapshot()).includes("challenge_digest"), false);

  const result = await ceremony.consume(attestation(issued.challenge));
  assert.deepEqual({
    verified: result.verified,
    registration_id: result.registration_id,
    session_id: result.session_id,
    member_id: result.member_id,
    organization_id: result.organization_id,
    operation: result.operation,
    credential_id: result.credential_id
  }, {
    verified: true,
    registration_id: CHALLENGE_ID,
    session_id: SESSION_ID,
    member_id: MEMBER_ID,
    organization_id: ORGANIZATION_ID,
    operation: WEBAUTHN_REGISTRATION_OPERATION,
    credential_id: CREDENTIAL_ID
  });
  assert.equal(verification.calls[0].ceremony.rp_id, RP_ID);
  assert.equal(verification.calls[0].ceremony.origin, ORIGIN);
  assert.equal(verification.calls[0].ceremony.user_verification, "required");
  assert.equal(verification.calls[0].parsed.client_data.type, "webauthn.create");
  assert.equal(verification.calls[0].attestation.attestation_object, attestation(issued.challenge).attestation_object);
});

test("registration ceremony rejects binding changes, missing UV, and replay", async () => {
  const verification = verifier();
  const ceremony = createWebAuthnRegistrationCeremony({ verifyAttestation: verification.verifyAttestation, randomUUID: () => CHALLENGE_ID, randomBytes: () => Buffer.alloc(32, 9) });
  const issued = ceremony.begin(context());
  const wrongValues = {
    session_id: "55555555-5555-4555-8555-555555555555",
    member_id: "66666666-6666-4666-8666-666666666666",
    organization_id: "77777777-7777-4777-8777-777777777777",
    rp_id: "other.example.test",
    origin: "https://other.example.test",
    operation: "other.operation"
  };
  for (const field of Object.keys(wrongValues)) {
    await assert.rejects(() => ceremony.consume(attestation(issued.challenge, { [field]: wrongValues[field] })), (error) => error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.BINDING_MISMATCH);
  }
  await assert.rejects(() => ceremony.consume(attestation(issued.challenge, { user_verification: "preferred" })), (error) => error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_CONTEXT);
  const valid = await ceremony.consume(attestation(issued.challenge));
  assert.equal(valid.verified, true);
  await assert.rejects(() => ceremony.consume(attestation(issued.challenge)), (error) => error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_REPLAYED);
  assert.equal(verification.calls.length, 1);
});

test("registration ceremony burns a challenge after verifier failure", async () => {
  const verification = verifier({ verify: async () => { throw new Error("attestation signature must not cross the boundary"); } });
  const ceremony = createWebAuthnRegistrationCeremony({ verifyAttestation: verification.verifyAttestation, randomUUID: () => CHALLENGE_ID, randomBytes: () => Buffer.alloc(32, 9) });
  const issued = ceremony.begin(context());
  await assert.rejects(() => ceremony.consume(attestation(issued.challenge)), (error) => error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.VERIFICATION_FAILED);
  await assert.rejects(() => ceremony.consume(attestation(issued.challenge)), (error) => error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_REPLAYED);
  assert.equal(JSON.stringify(ceremony.snapshot()).includes("attestation signature"), false);
});

test("registration service generates strict options and excludes credentials from the exact member session", async () => {
  const time = clock();
  const verification = verifier();
  const ceremony = createWebAuthnRegistrationCeremony({ verifyAttestation: verification.verifyAttestation, now: time.now, randomUUID: () => CHALLENGE_ID, randomBytes: () => Buffer.alloc(32, 9) });
  const calls = { user: [], list: [], options: [] };
  const repository = {
    async getRegistrationUser(input) { calls.user.push(input); return user(); },
    async listCredentialsForSession(input) { calls.list.push(input); return [{ id: OTHER_CREDENTIAL_ID, type: "public-key", transports: ["internal"] }]; },
    async createCredential() { return { created: true }; }
  };
  const registrationVerifier = {
    async generateOptions(input) { calls.options.push(input); return options(input.challenge, input.user, input.excludeCredentials); }
  };
  const service = createWebAuthnRegistrationService({ ceremony, credentialRepository: repository, registrationVerifier, rpId: RP_ID, origin: ORIGIN, now: time.now });
  const result = await service.begin({ session: { session_id: SESSION_ID, member_id: MEMBER_ID, organization_id: ORGANIZATION_ID }, organization_id: ORGANIZATION_ID });
  assert.equal(result.challenge_id, CHALLENGE_ID);
  assert.equal(result.options.authenticatorSelection.userVerification, "required");
  assert.deepEqual(result.options.excludeCredentials, [{ id: OTHER_CREDENTIAL_ID, type: "public-key", transports: ["internal"] }]);
  assert.deepEqual(calls.user[0], { session_id: SESSION_ID, member_id: MEMBER_ID, organization_id: ORGANIZATION_ID });
  assert.deepEqual(calls.list[0], calls.user[0]);
  assert.equal(calls.options[0].rp.id, RP_ID);
  assert.equal(calls.options[0].user.id, user().id);
});

test("registration service persists only verified public credential material and rejects storage ambiguity", async () => {
  const time = clock();
  const verification = verifier();
  const ceremony = createWebAuthnRegistrationCeremony({ verifyAttestation: verification.verifyAttestation, now: time.now, randomUUID: () => CHALLENGE_ID, randomBytes: () => Buffer.alloc(32, 9) });
  const stored = [];
  const repository = {
    async getRegistrationUser() { return user(); },
    async listCredentialsForSession() { return []; },
    async createCredential(input) { stored.push(input); return true; }
  };
  const registrationVerifier = { async generateOptions(input) { return options(input.challenge, input.user); } };
  const service = createWebAuthnRegistrationService({ ceremony, credentialRepository: repository, registrationVerifier, rpId: RP_ID, origin: ORIGIN, now: time.now });
  const issued = await service.begin({ session: { session_id: SESSION_ID, member_id: MEMBER_ID, organization_id: ORGANIZATION_ID }, organization_id: ORGANIZATION_ID });
  const wire = attestation(issued.options.challenge);
  const result = await service.verify({ session: { session_id: SESSION_ID, member_id: MEMBER_ID, organization_id: ORGANIZATION_ID }, organization_id: ORGANIZATION_ID, challenge_id: issued.challenge_id, credential: { credential_id: wire.credential_id, client_data_json: wire.client_data_json, attestation_object: wire.attestation_object, transports: ["internal"] } });
  assert.equal(result.credential_id, CREDENTIAL_ID);
  assert.equal(stored.length, 1);
  assert.deepEqual(Object.keys(stored[0]).sort(), ["credential_id", "member_id", "organization_id", "public_key", "session_id", "sign_count", "transports"]);
  assert.equal(Buffer.isBuffer(stored[0].public_key), true);
  assert.equal(Object.hasOwn(stored[0], "client_data_json"), false);
  assert.equal(Object.hasOwn(stored[0], "attestation_object"), false);
  assert.equal(JSON.stringify(stored).includes(wire.client_data_json), false);
});

test("simple verifier adapter passes exact RP/origin/UV requirements and returns public key only", async () => {
  const calls = [];
  const adapter = createSimpleWebAuthnRegistrationVerifier({
    generateOptions: async (input) => ({ challenge: input.challenge, rp: { name: input.rpName, id: input.rpID }, user: { id: "AA", name: input.userName, displayName: input.userDisplayName }, pubKeyCredParams: [{ type: "public-key", alg: -7 }], authenticatorSelection: { userVerification: "required" }, extensions: { credProps: true }, hints: [], excludeCredentials: [] }),
    verify: async (input) => {
      calls.push(input);
      return { verified: true, registrationInfo: { userVerified: true, origin: ORIGIN, rpID: RP_ID, credential: { id: CREDENTIAL_ID, publicKey: Buffer.alloc(65, 6), counter: 0, transports: ["internal"] }, credentialDeviceType: "singleDevice", credentialBackedUp: false } };
    }
  });
  const result = await adapter.verifyAttestation({ ceremony: { expected_challenge: Buffer.alloc(32, 9).toString("base64url"), origin: ORIGIN, rp_id: RP_ID }, attestation: { credential_id: CREDENTIAL_ID, client_data_json: "AA", attestation_object: "AQ", transports: ["internal"] } });
  assert.equal(result.verified, true);
  assert.equal(result.user_verified, true);
  assert.equal(result.credential_id, CREDENTIAL_ID);
  assert.equal(calls[0].expectedRPID, RP_ID);
  assert.equal(calls[0].expectedOrigin, ORIGIN);
  assert.equal(calls[0].requireUserVerification, true);
});

test("invalid verifier output is rejected and does not become a stored credential", async () => {
  const verification = verifier({ verify: async (input) => ({ verified: true, user_verified: false, credential_id: input.attestation.credential_id, public_key: Buffer.alloc(65), sign_count: 0 }) });
  const ceremony = createWebAuthnRegistrationCeremony({ verifyAttestation: verification.verifyAttestation, randomUUID: () => CHALLENGE_ID, randomBytes: () => Buffer.alloc(32, 9) });
  const issued = ceremony.begin(context());
  await assert.rejects(() => ceremony.consume(attestation(issued.challenge)), (error) => error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT);
});
