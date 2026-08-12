import assert from "node:assert/strict";
import test from "node:test";
import { createSimpleWebAuthnAssertionVerifier } from "../src/human-auth/webauthn/simplewebauthn-adapter.mjs";

const assertion = { credential_id: "Y3JlZGVudGlhbC0x", client_data_json: "YQ", authenticator_data: "Yg", signature: "Yw" };
const ceremony = { session_id: "session-1", organization_id: "org-1", expected_challenge: "challenge", origin: "https://console.example.test", rp_id: "console.example.test" };

test("binds the maintained verifier to exact RP/origin/challenge and atomically advances the counter", async () => {
  const calls = [];
  const repository = {
    async findCredentialForSession(input) { calls.push(["find", input]); return { public_key: Buffer.alloc(64, 1), sign_count: 7, transports: ["internal"] }; },
    async updateCredentialCounter(input) { calls.push(["update", input]); return true; }
  };
  const verifier = createSimpleWebAuthnAssertionVerifier({ credentialRepository: repository, verify: async (input) => {
    calls.push(["verify", input]);
    return { verified: true, authenticationInfo: { credentialID: assertion.credential_id, newCounter: 8, userVerified: true, origin: ceremony.origin, rpID: ceremony.rp_id, credentialDeviceType: "singleDevice", credentialBackedUp: false } };
  } });
  assert.deepEqual(await verifier({ ceremony, assertion }), { verified: true, credential_id: assertion.credential_id, sign_count: 8 });
  assert.equal(calls[1][1].expectedChallenge, "challenge");
  assert.equal(calls[1][1].requireUserVerification, true);
  assert.equal(calls[2][1].expected_sign_count, 7);
  assert.equal(calls[2][1].sign_count, 8);
});

test("fails closed on wrong verifier binding and counter races", async () => {
  const baseRepository = { async findCredentialForSession() { return { public_key: Buffer.alloc(64, 1), sign_count: 0 }; }, async updateCredentialCounter() { return true; } };
  const wrongOrigin = createSimpleWebAuthnAssertionVerifier({ credentialRepository: baseRepository, verify: async () => ({ verified: true, authenticationInfo: { credentialID: assertion.credential_id, newCounter: 1, userVerified: true, origin: "https://evil.test", rpID: ceremony.rp_id } }) });
  await assert.rejects(() => wrongOrigin({ ceremony, assertion }), /verification failed/);
  const conflict = createSimpleWebAuthnAssertionVerifier({ credentialRepository: { ...baseRepository, async updateCredentialCounter() { return false; } }, verify: async () => ({ verified: true, authenticationInfo: { credentialID: assertion.credential_id, newCounter: 1, userVerified: true, origin: ceremony.origin, rpID: ceremony.rp_id } }) });
  await assert.rejects(() => conflict({ ceremony, assertion }), /counter conflict/);
});
