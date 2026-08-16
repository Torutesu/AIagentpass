import assert from "node:assert/strict";
import test from "node:test";
import { createSimpleWebAuthnAssertionVerifier } from "../src/human-auth/webauthn/simplewebauthn-adapter.mjs";

const assertion = { credential_id: "Y3JlZGVudGlhbC0x", client_data_json: "YQ", authenticator_data: "Yg", signature: "Yw" };
const ceremony = { session_id: "session-1", organization_id: "org-1", expected_challenge: "challenge", origin: "https://console.example.test", rp_id: "console.example.test" };

function authenticationInfo(overrides = {}) {
  return {
    credentialID: assertion.credential_id,
    newCounter: 1,
    userVerified: true,
    origin: ceremony.origin,
    rpID: ceremony.rp_id,
    credentialDeviceType: "singleDevice",
    credentialBackedUp: false,
    ...overrides
  };
}

test("binds the maintained verifier to exact RP/origin/challenge and atomically advances the counter", async () => {
  const calls = [];
  const repository = {
    async findCredentialForSession(input) { calls.push(["find", input]); return { public_key: Buffer.alloc(64, 1), sign_count: 7, transports: ["internal"] }; },
    async updateCredentialCounter(input) { calls.push(["update", input]); return true; }
  };
  const verifier = createSimpleWebAuthnAssertionVerifier({ credentialRepository: repository, verify: async (input) => {
    calls.push(["verify", input]);
    return { verified: true, authenticationInfo: authenticationInfo({ newCounter: 8 }) };
  } });
  assert.deepEqual(await verifier({ ceremony, assertion }), { verified: true, credential_id: assertion.credential_id, sign_count: 8 });
  assert.equal(calls[1][1].expectedChallenge, "challenge");
  assert.equal(calls[1][1].expectedOrigin, ceremony.origin);
  assert.equal(calls[1][1].expectedRPID, ceremony.rp_id);
  assert.equal(calls[1][1].expectedType, "webauthn.get");
  assert.equal(calls[1][1].requireUserVerification, true);
  assert.equal(calls[2][1].expected_sign_count, 7);
  assert.equal(calls[2][1].sign_count, 8);
});

test("fails closed on wrong verifier binding and counter races", async () => {
  const baseRepository = { async findCredentialForSession() { return { public_key: Buffer.alloc(64, 1), sign_count: 0 }; }, async updateCredentialCounter() { return true; } };
  const wrongOrigin = createSimpleWebAuthnAssertionVerifier({ credentialRepository: baseRepository, verify: async () => ({ verified: true, authenticationInfo: authenticationInfo({ origin: "https://evil.test" }) }) });
  await assert.rejects(() => wrongOrigin({ ceremony, assertion }), /verification failed/);
  const conflict = createSimpleWebAuthnAssertionVerifier({ credentialRepository: { ...baseRepository, async updateCredentialCounter() { return false; } }, verify: async () => ({ verified: true, authenticationInfo: authenticationInfo() }) });
  await assert.rejects(() => conflict({ ceremony, assertion }), /counter conflict/);
});

test("allows zero counters only as the explicitly ambiguous zero/zero case", async () => {
  const updates = [];
  const repository = {
    async findCredentialForSession() { return { public_key: Buffer.alloc(64, 1), sign_count: 0, backup_eligible: false, backup_state: false }; },
    async updateCredentialCounter(input) { updates.push(input); return true; }
  };
  const verifier = createSimpleWebAuthnAssertionVerifier({ credentialRepository: repository, verify: async () => ({ verified: true, authenticationInfo: authenticationInfo({ newCounter: 0 }) }) });
  assert.deepEqual(await verifier({ ceremony, assertion }), { verified: true, credential_id: assertion.credential_id, sign_count: 0 });
  assert.equal(updates[0].expected_sign_count, 0);
  assert.equal(updates[0].sign_count, 0);
  assert.equal(updates[0].expected_backup_eligible, false);
  assert.equal(updates[0].expected_backup_state, false);
  assert.equal(updates[0].backup_eligible, false);
});

test("fails closed on non-zero counter rollback or equality, including an alternate verifier that bypasses the provider check", async () => {
  for (const newCounter of [5, 6, 0]) {
    let updates = 0;
    const quarantines = [];
    const verifier = createSimpleWebAuthnAssertionVerifier({
      credentialRepository: {
        async findCredentialForSession() { return { public_key: Buffer.alloc(64, 1), sign_count: 6 }; },
        async updateCredentialCounter() { updates += 1; return true; },
        async quarantineCredentialClone(input) { quarantines.push(input); return true; }
      },
      verify: async () => ({ verified: true, authenticationInfo: authenticationInfo({ newCounter }) })
    });
    await assert.rejects(() => verifier({ ceremony, assertion }), /verification failed/);
    assert.equal(updates, 0);
    assert.deepEqual(quarantines, [{
      credential_id: assertion.credential_id,
      session_id: ceremony.session_id,
      organization_id: ceremony.organization_id,
      expected_sign_count: 6,
      observed_sign_count: newCounter
    }]);
  }
});

test("fails closed when durable clone quarantine cannot commit", async () => {
  for (const quarantine of [async () => false, async () => { throw new Error("database detail"); }]) {
    const verifier = createSimpleWebAuthnAssertionVerifier({
      credentialRepository: {
        async findCredentialForSession() { return { public_key: Buffer.alloc(64, 1), sign_count: 6 }; },
        async updateCredentialCounter() { throw new Error("must not update"); },
        quarantineCredentialClone: quarantine
      },
      verify: async () => ({ verified: true, authenticationInfo: authenticationInfo({ newCounter: 6 }) })
    });
    await assert.rejects(() => verifier({ ceremony, assertion }), (error) => error.message === "WebAuthn assertion verification failed" && !error.message.includes("database detail"));
  }
});

test("allows backup state transitions but never allows backup eligibility or device type to change", async () => {
  const transitions = [
    { stored: { backup_eligible: true, backup_state: false, credential_device_type: "multiDevice" }, current: { credentialDeviceType: "multiDevice", credentialBackedUp: true } },
    { stored: { backup_eligible: true, backup_state: true, credential_device_type: "multiDevice" }, current: { credentialDeviceType: "multiDevice", credentialBackedUp: false } }
  ];
  for (const transition of transitions) {
    let update;
    const verifier = createSimpleWebAuthnAssertionVerifier({
      credentialRepository: {
        async findCredentialForSession() { return { public_key: Buffer.alloc(64, 1), sign_count: 0, ...transition.stored }; },
        async updateCredentialCounter(input) { update = input; return true; }
      },
      verify: async () => ({ verified: true, authenticationInfo: authenticationInfo({ newCounter: 0, ...transition.current }) })
    });
    await verifier({ ceremony, assertion });
    assert.equal(update.expected_backup_eligible, true);
    assert.equal(update.expected_backup_state, transition.stored.backup_state);
    assert.equal(update.backup_eligible, true);
    assert.equal(update.backup_state, transition.current.credentialBackedUp);
  }

  for (const current of [
    { credentialDeviceType: "multiDevice", credentialBackedUp: false },
    { credentialDeviceType: "singleDevice", credentialBackedUp: true }
  ]) {
    const verifier = createSimpleWebAuthnAssertionVerifier({
      credentialRepository: {
        async findCredentialForSession() { return { public_key: Buffer.alloc(64, 1), sign_count: 0, backup_eligible: false, backup_state: false, credential_device_type: "singleDevice" }; },
        async updateCredentialCounter() { throw new Error("must not update"); }
      },
      verify: async () => ({ verified: true, authenticationInfo: authenticationInfo({ newCounter: 0, ...current }) })
    });
    await assert.rejects(() => verifier({ ceremony, assertion }), /verification failed/);
  }
});

test("fails closed on malformed backup metadata, provider errors, and repository errors without exposing details", async () => {
  const secret = "private-key-secret";
  const malformed = createSimpleWebAuthnAssertionVerifier({
    credentialRepository: {
      async findCredentialForSession() { return { public_key: Buffer.alloc(64, 1), sign_count: 0, backup_eligible: false, backup_state: true }; },
      async updateCredentialCounter() { throw new Error(secret); }
    },
    verify: async () => ({ verified: true, authenticationInfo: authenticationInfo({ newCounter: 0 }) })
  });
  await assert.rejects(() => malformed({ ceremony, assertion }), (error) => error.message === "WebAuthn assertion verification failed" && !error.message.includes(secret));

  const updateFailure = createSimpleWebAuthnAssertionVerifier({
    credentialRepository: { async findCredentialForSession() { return { public_key: Buffer.alloc(64, 1), sign_count: 0 }; }, async updateCredentialCounter() { throw new Error(secret); } },
    verify: async () => ({ verified: true, authenticationInfo: authenticationInfo({ newCounter: 0 }) })
  });
  await assert.rejects(() => updateFailure({ ceremony, assertion }), (error) => error.message === "WebAuthn credential counter update failed" && !error.message.includes(secret));

  const providerFailure = createSimpleWebAuthnAssertionVerifier({
    credentialRepository: { async findCredentialForSession() { return { public_key: Buffer.alloc(64, 1), sign_count: 0 }; }, async updateCredentialCounter() { return true; } },
    verify: async () => { throw new Error(secret); }
  });
  await assert.rejects(() => providerFailure({ ceremony, assertion }), (error) => error.message === "WebAuthn assertion verification failed" && !error.message.includes(secret));

  const lookupFailure = createSimpleWebAuthnAssertionVerifier({
    credentialRepository: { async findCredentialForSession() { throw new Error(secret); }, async updateCredentialCounter() { return true; } },
    verify: async () => ({ verified: true, authenticationInfo: authenticationInfo() })
  });
  await assert.rejects(() => lookupFailure({ ceremony, assertion }), (error) => error.message === "WebAuthn credential is unavailable" && !error.message.includes(secret));
});

test("requires exact assertion encodings before invoking the verifier", async () => {
  let called = false;
  const verifier = createSimpleWebAuthnAssertionVerifier({ credentialRepository: { async findCredentialForSession() { return { public_key: Buffer.alloc(64, 1), sign_count: 0 }; }, async updateCredentialCounter() { return true; } }, verify: async () => { called = true; return { verified: true, authenticationInfo: authenticationInfo() }; } });
  await assert.rejects(() => verifier({ ceremony, assertion: { ...assertion, signature: "not base64?" } }), /input is invalid/);
  assert.equal(called, false);
});
