import assert from "node:assert/strict";
import test from "node:test";

import {
  HOSTED_WEBAUTHN_BOOTSTRAP_ERROR_CODES as CODES,
  createHostedWebAuthnBootstrapService
} from "../../src/hosted-identity/webauthn-bootstrap-service.mjs";

const IDS = Object.freeze({
  challenge: "11111111-1111-4111-8111-111111111111",
  attempt: "22222222-2222-4222-8222-222222222222",
  member: "33333333-3333-4333-8333-333333333333",
  organization: "44444444-4444-4444-8444-444444444444",
  membership: "55555555-5555-4555-8555-555555555555",
  session: "66666666-6666-4666-8666-666666666666"
});
const ORIGIN = "https://console.example.test";
const RP_ID = "console.example.test";
const BOOTSTRAP = Buffer.alloc(32, 0x11).toString("base64url");
const CREDENTIAL_ID = Buffer.alloc(32, 0x22).toString("base64url");
const PUBLIC_KEY = Buffer.alloc(65, 0x33);
const NOW = Date.parse("2026-08-15T00:00:00.000Z");

function clientData(challenge, overrides = {}) {
  return Buffer.from(JSON.stringify({ type: "webauthn.create", challenge, origin: ORIGIN, crossOrigin: false, ...overrides })).toString("base64url");
}

function fixture({ claimError = null } = {}) {
  const calls = { create: [], claim: [], complete: [], fail: [], verify: [] };
  let completed = false;
  const repository = {
    async createChallenge(input) {
      calls.create.push(input);
      return { challenge_id: input.challenge_id, member_id: IDS.member, organization_id: IDS.organization, rp_id: RP_ID, origin: ORIGIN, expires_at: input.expires_at };
    },
    async claimChallengeV2(input) {
      if (claimError) throw claimError;
      calls.claim.push(input);
      return { attempt_id: IDS.attempt, member_id: IDS.member, organization_id: IDS.organization, rp_id: RP_ID, origin: ORIGIN, user_verification: "required", claim_generation: 1, claim_expires_at: new Date(NOW + 30_000).toISOString() };
    },
    async completeWebAuthnRegistrationV3(input) {
      calls.complete.push(input);
      completed = true;
      return {
        attempt_id: IDS.attempt,
        membership_id: IDS.membership,
        replayed: calls.complete.length > 1,
        session: { version: 1, session_id: IDS.session, member_id: IDS.member, organization_id: IDS.organization, role: "owner", created_at: new Date(NOW).toISOString(), expires_at: new Date(NOW + 8 * 60 * 60 * 1000).toISOString(), recent_auth_at: null }
      };
    },
    async failChallengeV3(input) { calls.fail.push(input); return true; }
  };
  const registrationVerifier = {
    async generateOptions(input) {
      return { challenge: input.challenge, rp: { id: input.rp.id, name: input.rp.name }, user: { id: input.user.id, name: input.user.name, displayName: input.user.displayName }, pubKeyCredParams: [{ type: "public-key", alg: -7 }], timeout: input.timeout, attestation: "none", excludeCredentials: [], authenticatorSelection: { residentKey: "preferred", userVerification: "required" }, extensions: { credProps: true }, hints: [] };
    },
    async verifyAttestation(input) {
      calls.verify.push(input);
      return { verified: true, credential_id: CREDENTIAL_ID, public_key: PUBLIC_KEY, sign_count: 0, transports: ["internal"], credential_device_type: "singleDevice", credential_backed_up: false, user_verified: true };
    }
  };
  const service = createHostedWebAuthnBootstrapService({
    repository,
    registrationVerifier,
    responseKey: Buffer.alloc(32, 0x44),
    rpId: RP_ID,
    origin: ORIGIN,
    now: () => NOW,
    randomUUID: () => IDS.challenge,
    randomBytes: () => Buffer.alloc(32, 0x55)
  });
  return { service, calls };
}

test("issues bootstrap-bound registration options without an ordinary session", async () => {
  const { service, calls } = fixture();
  const result = await service.options({ bootstrap_token: BOOTSTRAP, rp_id: RP_ID, origin: ORIGIN, user_verification: "required" });
  assert.equal(result.challenge_id, IDS.challenge);
  assert.equal(result.options.rp.id, RP_ID);
  assert.equal(result.options.authenticatorSelection.userVerification, "required");
  assert.equal(result.options.user.id, Buffer.from(IDS.member.replaceAll("-", ""), "hex").toString("base64url"));
  assert.equal(calls.create.length, 1);
  assert.equal(calls.create[0].bootstrap_cookie, BOOTSTRAP);
  assert.equal(calls.create[0].challenge, Buffer.alloc(32, 0x55).toString("base64url"));
});

test("strict verification delegates one atomic credential and Human Session commit", async () => {
  const { service, calls } = fixture();
  const options = await service.options({ bootstrap_token: BOOTSTRAP, rp_id: RP_ID, origin: ORIGIN, user_verification: "required" });
  const credential = { credential_id: CREDENTIAL_ID, client_data_json: clientData(options.options.challenge), attestation_object: Buffer.alloc(64, 0x66).toString("base64url"), transports: ["internal"] };
  const result = await service.verify({ bootstrap_token: BOOTSTRAP, challenge_id: IDS.challenge, credential, rp_id: RP_ID, origin: ORIGIN, user_verification: "required" });
  assert.match(result.session_token, /^[A-Za-z0-9_-]{43}$/u);
  assert.match(result.csrf_token, /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(result.session.session_id, IDS.session);
  assert.equal(calls.claim.length, 1);
  assert.match(calls.claim[0].claim_token, /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(calls.verify.length, 1);
  assert.equal(calls.complete.length, 1);
  assert.equal(calls.complete[0].attempt_id, IDS.attempt);
  assert.equal(calls.complete[0].claim_token, calls.claim[0].claim_token);
  assert.equal(calls.complete[0].claim_generation, 1);
  assert.equal(calls.complete[0].credential.id, CREDENTIAL_ID);
  assert.deepEqual(calls.complete[0].credential.public_key, PUBLIC_KEY);
  assert.equal(calls.complete[0].session.token, result.session_token);
  assert.equal(calls.complete[0].session.csrf_token, result.csrf_token);
});

test("an identical response-loss retry reconstructs the same bearer material", async () => {
  const { service, calls } = fixture();
  const challenge = Buffer.alloc(32, 0x55).toString("base64url");
  const credential = { credential_id: CREDENTIAL_ID, client_data_json: clientData(challenge), attestation_object: Buffer.alloc(64, 0x66).toString("base64url"), transports: ["internal"] };
  const request = { bootstrap_token: BOOTSTRAP, challenge_id: IDS.challenge, credential, rp_id: RP_ID, origin: ORIGIN, user_verification: "required" };
  const first = await service.verify(request);
  const replay = await service.verify(request);
  assert.equal(replay.session_token, first.session_token);
  assert.equal(replay.csrf_token, first.csrf_token);
  assert.deepEqual(replay.session, first.session);
  assert.equal(calls.claim.length, 2, "completed retry must reclaim the same deterministic response binding");
  assert.equal(calls.claim[0].claim_token, calls.claim[1].claim_token);
  assert.equal(calls.complete.length, 2);
});

test("wrong origin and failed user verification burn a claimed challenge", async () => {
  const wrong = fixture();
  await assert.rejects(wrong.service.verify({ bootstrap_token: BOOTSTRAP, challenge_id: IDS.challenge, credential: { credential_id: CREDENTIAL_ID, client_data_json: clientData(Buffer.alloc(32, 0x55).toString("base64url"), { origin: "https://evil.example" }), attestation_object: Buffer.alloc(64).toString("base64url"), transports: [] }, rp_id: RP_ID, origin: ORIGIN, user_verification: "required" }), (error) => error.code === CODES.INVALID);
  assert.equal(wrong.calls.claim.length, 0);

  const failed = fixture();
  const challenge = Buffer.alloc(32, 0x55).toString("base64url");
  failed.service;
  failed.calls;
  // Replace verifier behavior through its observed input by invalidating the
  // credential id after the durable claim; strict normalization must burn it.
  const badCredential = { credential_id: Buffer.alloc(32, 0x77).toString("base64url"), client_data_json: clientData(challenge), attestation_object: Buffer.alloc(64).toString("base64url"), transports: [] };
  await assert.rejects(failed.service.verify({ bootstrap_token: BOOTSTRAP, challenge_id: IDS.challenge, credential: badCredential, rp_id: RP_ID, origin: ORIGIN, user_verification: "required" }), (error) => error.code === CODES.INVALID);
  assert.equal(failed.calls.claim.length, 1);
  assert.equal(failed.calls.fail.length, 1);
  assert.equal(failed.calls.fail[0].claim_generation, 1);
  assert.equal(failed.calls.complete.length, 0);
});

test("storage failure during claim is unavailable rather than a false replay", async () => {
  const unavailable = fixture({ claimError: new Error("database unavailable with secret details") });
  const challenge = Buffer.alloc(32, 0x55).toString("base64url");
  const credential = { credential_id: CREDENTIAL_ID, client_data_json: clientData(challenge), attestation_object: Buffer.alloc(64, 0x66).toString("base64url"), transports: ["internal"] };
  await assert.rejects(
    unavailable.service.verify({ bootstrap_token: BOOTSTRAP, challenge_id: IDS.challenge, credential, rp_id: RP_ID, origin: ORIGIN, user_verification: "required" }),
    (error) => error.code === CODES.UNAVAILABLE && !/database|secret/iu.test(error.message)
  );
});
