import crypto from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";

import {
  canonicalControlBundle,
  controlBundleStatementHash,
  verifyControlBundle
} from "../../../lib/control-bundle-v2.mjs";
import {
  CONTROL_BUNDLE_MANAGED_SIGNER_ALGORITHM,
  CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES,
  CONTROL_BUNDLE_MANAGED_SIGNER_PROTOCOL_VERSION,
  CONTROL_BUNDLE_MANAGED_SIGNER_PURPOSE,
  CONTROL_BUNDLE_MANAGED_SIGNER_VERSION,
  CONTROL_BUNDLE_SIGNATURE_DOMAIN,
  ControlBundleManagedSignerError,
  createHostedControlBundleSigner,
  createLocalControlBundleProvider
} from "../src/control-bundle-managed-signer.mjs";

const NOW = Date.parse("2026-08-12T00:00:00.000Z");
const organizationId = "11111111-1111-4111-8111-111111111111";
const deviceId = "22222222-2222-4222-8222-222222222222";
const keys = crypto.generateKeyPairSync("ed25519");
const otherKeys = crypto.generateKeyPairSync("ed25519");
const keyId = "control-bundle-2026-08";

function statement(overrides = {}) {
  return {
    format_epoch: 2,
    issuer: "agentpass-cloud",
    organization_id: organizationId,
    device_id: deviceId,
    audience: { organization_id: organizationId, device_id: deviceId },
    issued_at: new Date(NOW).toISOString(),
    expires_at: new Date(NOW + 60_000).toISOString(),
    sequence: 7,
    policy_scope: {
      operations: ["git.commit.sign"],
      repositories: ["/work/project"],
      branches: { allow: ["main"], deny: [] },
      remotes: { allow: ["git@github.com:example/project.git"] }
    },
    global_revoked: false,
    revoked_devices: [],
    revoked_agents: [],
    revoked_capabilities: [],
    offline_ttl_ms: 30_000,
    key_id: keyId,
    ...overrides
  };
}

function providerFor({ signingKeys = keys, metadata = undefined, sign = undefined } = {}) {
  const local = createLocalControlBundleProvider({ privateKey: signingKeys.privateKey, keyId });
  return Object.freeze({
    ...local,
    async publicKeyMetadata(input) {
      return metadata === undefined ? local.publicKeyMetadata(input) : metadata;
    },
    async sign(input) {
      return sign === undefined ? local.sign(input) : sign(input);
    }
  });
}

function signer(options = {}) {
  return createHostedControlBundleSigner({
    provider: providerFor(options),
    keyId,
    publicKey: keys.publicKey,
    now: () => NOW
  });
}

test("uses the exact v2 canonical statement bytes and verifies the returned bundle", async () => {
  let seen;
  const provider = providerFor({
    sign: async (input) => {
      seen = input;
      return crypto.sign(null, input.bytes, keys.privateKey);
    }
  });
  const value = createHostedControlBundleSigner({ provider, keyId, publicKey: keys.publicKey, now: () => NOW });
  const bundle = await value.signControlBundle(statement());

  assert.deepEqual(seen, {
    algorithm: CONTROL_BUNDLE_MANAGED_SIGNER_ALGORITHM,
    bytes: Buffer.from(canonicalControlBundle(statement())),
    key_id: keyId,
    purpose: CONTROL_BUNDLE_MANAGED_SIGNER_PURPOSE,
    version: CONTROL_BUNDLE_MANAGED_SIGNER_VERSION
  });
  assert.equal(bundle.signature.length > 0, true);
  assert.equal(controlBundleStatementHash(bundle), controlBundleStatementHash(statement()));
  assert.equal(verifyControlBundle(bundle, { public_key: keys.publicKey, issuer: "agentpass-cloud", key_id: keyId }, {
    now: NOW + 1_000,
    audience: { organization_id: organizationId, device_id: deviceId }
  }).sequence, 7);
});
test("publishes the fixed purpose/domain/version contract without private key material", async () => {
  const value = signer();
  const metadata = await value.publicKeyMetadata();
  assert.deepEqual(metadata, {
    algorithm: "ed25519",
    domain: CONTROL_BUNDLE_SIGNATURE_DOMAIN,
    key_id: keyId,
    protocol_version: CONTROL_BUNDLE_MANAGED_SIGNER_PROTOCOL_VERSION,
    public_key: keys.publicKey.export({ type: "spki", format: "pem" }).toString(),
    purpose: CONTROL_BUNDLE_MANAGED_SIGNER_PURPOSE,
    signing_version: CONTROL_BUNDLE_MANAGED_SIGNER_VERSION,
    version: CONTROL_BUNDLE_MANAGED_SIGNER_VERSION
  });
  assert.equal(Object.keys(value).some((key) => /private|secret|credential|pem/i.test(key)), false);
  assert.equal(JSON.stringify(value).includes("PRIVATE KEY"), false);
});

test("rejects provider purpose, algorithm, version, key substitution, and malformed public metadata", async () => {
  for (const patch of [
    { purpose: "other-purpose" },
    { algorithm: "rsa" },
    { version: 1 },
    { key_id: "other-key" }
  ]) {
    assert.throws(() => createHostedControlBundleSigner({
      provider: { ...providerFor(), ...patch }, keyId, publicKey: keys.publicKey, now: () => NOW
    }), (error) => error instanceof ControlBundleManagedSignerError && error.code === CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.CONFIG);
  }

  for (const metadata of [
    { key_id: keyId, algorithm: "rsa", public_key: keys.publicKey },
    { key_id: keyId, algorithm: "ed25519", public_key: otherKeys.publicKey },
    { key_id: keyId, algorithm: "ed25519", public_key: keys.privateKey },
    { key_id: keyId, algorithm: "ed25519", public_key: keys.publicKey, extra: true }
  ]) {
    const value = signer({ metadata });
    await assert.rejects(value.publicKeyMetadata(), (error) => error.code === CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.METADATA);
  }
});

test("fails closed on forged, malformed, and wrong-type provider output", async () => {
  for (const output of [
    Buffer.alloc(64),
    Buffer.alloc(63),
    "not-a-signature",
    { signature: Buffer.alloc(64) },
    crypto.sign(null, Buffer.from("different bytes"), keys.privateKey)
  ]) {
    const value = signer({ sign: async () => output });
    await assert.rejects(value.signControlBundle(statement()), (error) => {
      assert.ok(error instanceof ControlBundleManagedSignerError);
      assert.ok([
        CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.OUTPUT,
        CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.VERIFICATION
      ].includes(error.code));
      return true;
    });
  }
});

test("passes only the normalized statement and rejects malformed statements before provider use", async () => {
  let calls = 0;
  const value = signer({ sign: async () => { calls += 1; return crypto.sign(null, Buffer.from("unused"), keys.privateKey); } });
  for (const malformed of [
    { ...statement(), signature: undefined },
    { ...statement(), unknown: true },
    { ...statement(), sequence: 0 },
    { ...statement(), policy_scope: { operations: ["git.push"] } }
  ]) {
    await assert.rejects(value.signControlBundle(malformed), (error) => error.code === CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.INPUT);
  }
  assert.equal(calls, 0);
});

test("local development provider signs through the same hosted boundary", async () => {
  const provider = createLocalControlBundleProvider({ privateKey: keys.privateKey, keyId });
  const value = createHostedControlBundleSigner({ provider, keyId, publicKey: keys.publicKey, now: () => NOW });
  const bundle = await value.sign(statement());
  assert.equal(verifyControlBundle(bundle, { public_key: keys.publicKey, issuer: "agentpass-cloud", key_id: keyId }, {
    now: NOW + 1_000,
    audience: { organization_id: organizationId, device_id: deviceId }
  }).key_id, keyId);
  assert.equal(Object.prototype.hasOwnProperty.call(provider, "privateKey"), false);
});
