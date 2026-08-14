import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  POSSESSION_RECEIPT_SIGNER_ALGORITHM,
  POSSESSION_RECEIPT_SIGNER_ERROR_CODES,
  POSSESSION_RECEIPT_SIGNER_MAX_RETIRING_KEYS,
  createHostedPossessionReceiptSigner,
  parsePossessionReceiptSignerConfig
} from "../src/possession-receipt-signer-config.mjs";
import { POSSESSION_RECEIPT_PURPOSE, possessionReceiptSigningData } from "../src/possession-receipt-signer.mjs";

const NOW = Date.parse("2026-08-14T00:00:00.000Z");
const STATEMENT = Object.freeze({
  version: 1,
  enrollment_id: "11111111-1111-4111-8111-111111111111",
  organization_id: "22222222-2222-4222-8222-222222222222",
  device_id: "33333333-3333-4333-8333-333333333333",
  candidate_id: "release-2026-08-14-01",
  artifact_sha256: "a".repeat(64),
  source_commit: "b".repeat(40),
  team_id: "ABCDE12345",
  device_key_fingerprint: `SHA256:${"C".repeat(43)}`,
  device_key_epoch: 3,
  challenge_nonce_digest: "d".repeat(64),
  issued_at: "2026-08-14T00:00:00.000Z"
});

function publicPem(key) {
  return key.export({ type: "spki", format: "pem" }).toString();
}

function fixture(overrides = {}) {
  const keys = crypto.generateKeyPairSync("ed25519");
  const pem = publicPem(keys.publicKey);
  const env = {
    AGENTPASS_CLOUD_PROFILE: "hosted",
    AGENTPASS_CLOUD_POSSESSION_RECEIPT_KEY_ID: "possession-2026-08",
    AGENTPASS_CLOUD_POSSESSION_RECEIPT_PUBLIC_KEY: pem,
    AGENTPASS_CLOUD_POSSESSION_RECEIPT_TIMEOUT_MS: "5000",
    ...overrides
  };
  const provider = {
    async publicKeyMetadata({ key_id, algorithm, purpose, version }) {
      assert.equal(key_id, "possession-2026-08");
      assert.equal(algorithm, POSSESSION_RECEIPT_SIGNER_ALGORITHM);
      assert.equal(purpose, POSSESSION_RECEIPT_PURPOSE);
      assert.equal(version, 1);
      return { key_id, algorithm, public_key: pem };
    },
    async sign({ bytes, key_id, algorithm, purpose, version }) {
      assert.equal(key_id, "possession-2026-08");
      assert.equal(algorithm, POSSESSION_RECEIPT_SIGNER_ALGORITHM);
      assert.equal(purpose, POSSESSION_RECEIPT_PURPOSE);
      assert.equal(version, 1);
      assert.deepEqual(bytes, possessionReceiptSigningData(STATEMENT));
      return crypto.sign(null, bytes, keys.privateKey);
    }
  };
  return { keys, pem, env, provider };
}

test("parses hosted Ed25519 configuration and signs a pinned receipt", async () => {
  const value = fixture();
  const signer = createHostedPossessionReceiptSigner({ provider: value.provider, env: value.env, now: () => NOW });
  const metadata = await signer.publicKeyMetadata();
  assert.deepEqual(metadata, {
    version: 1,
    purpose: POSSESSION_RECEIPT_PURPOSE,
    key_id: "possession-2026-08",
    algorithm: "ed25519",
    public_key: value.pem
  });
  const receipt = await signer.signPossessionReceipt(STATEMENT);
  assert.equal(receipt.key_id, "possession-2026-08");
  assert.equal(receipt.algorithm, "ed25519");
  assert.equal(receipt.purpose, POSSESSION_RECEIPT_PURPOSE);
  assert.equal(Buffer.from(receipt.signature, "base64url").length, 64);
  assert.equal((await signer.health()).ready, true);
  assert.deepEqual((await signer.verificationKeyMetadata()).keys.map((key) => ({
    key_id: key.key_id,
    algorithm: key.algorithm,
    status: key.status
  })), [{ key_id: "possession-2026-08", algorithm: "ed25519", status: "active" }]);
  assert.equal(signer.key_id, "possession-2026-08");
  assert.equal(signer.algorithm, "ed25519");
  assert.equal(Object.hasOwn(signer, "provider"), false);
  assert.equal(JSON.stringify(signer).includes("PRIVATE KEY"), false);
});

test("health and metadata readiness independently reject provider key substitution", async () => {
  const value = fixture();
  const other = crypto.generateKeyPairSync("ed25519");
  const provider = {
    ...value.provider,
    async publicKeyMetadata({ key_id, algorithm }) {
      return { key_id, algorithm, public_key: publicPem(other.publicKey) };
    }
  };
  const signer = createHostedPossessionReceiptSigner({ provider, env: value.env, now: () => NOW });
  for (const operation of [() => signer.health(), () => signer.publicKeyMetadata(), () => signer.verificationKeyMetadata()]) {
    await assert.rejects(operation, (error) => error.code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.METADATA);
  }
});

test("rejects cross-purpose key and fingerprint reuse", () => {
  const value = fixture();
  assert.throws(
    () => parsePossessionReceiptSignerConfig(value.env, { agentSession: { keyId: "possession-2026-08" } }, { now: () => NOW }),
    (error) => error.code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.KEY_REUSE
  );
  assert.throws(
    () => parsePossessionReceiptSignerConfig(value.env, { qualification: { publicKey: value.pem } }, { now: () => NOW }),
    (error) => error.code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.KEY_REUSE
  );
  assert.doesNotThrow(() => parsePossessionReceiptSignerConfig(value.env, {
    agentSession: { keyId: "agent-session-2026-08", publicKey: crypto.generateKeyPairSync("ed25519").publicKey }
  }, { now: () => NOW }));
});

test("accepts only a bounded retiring verification ring", async () => {
  const value = fixture();
  const retiring = crypto.generateKeyPairSync("ed25519");
  const env = {
    ...value.env,
    AGENTPASS_CLOUD_POSSESSION_RECEIPT_VERIFICATION_KEYS_JSON: JSON.stringify([{
      key_id: "possession-2026-07",
      public_key: publicPem(retiring.publicKey),
      not_after: new Date(NOW + 60_000).toISOString()
    }])
  };
  const signer = createHostedPossessionReceiptSigner({ provider: value.provider, env, now: () => NOW });
  const ring = await signer.verificationKeyMetadata();
  assert.equal(ring.keys.length, 2);
  assert.equal((await signer.verificationKeyMetadata("possession-2026-07")).status, "retiring");
  await assert.rejects(() => signer.verificationKeyMetadata("possession-2026-07", { at: NOW + 60_000 }),
    (error) => error.code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.KEY_NOT_TRUSTED);
  assert.throws(() => parsePossessionReceiptSignerConfig({
    ...value.env,
    AGENTPASS_CLOUD_POSSESSION_RECEIPT_VERIFICATION_KEYS_JSON: JSON.stringify(Array.from({ length: POSSESSION_RECEIPT_SIGNER_MAX_RETIRING_KEYS + 1 }, (_, index) => ({
      key_id: `retiring-${index}`,
      public_key: publicPem(crypto.generateKeyPairSync("ed25519").publicKey),
      not_after: new Date(NOW + 60_000).toISOString()
    })))
  }, {}, { now: () => NOW }), (error) => error.code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
});

test("fails closed on missing, unsafe, malformed, oversized, or wrong-curve configuration", () => {
  const value = fixture();
  const invalid = [
    { ...value.env, AGENTPASS_CLOUD_PROFILE: "evaluation" },
    { ...value.env, AGENTPASS_CLOUD_POSSESSION_RECEIPT_KEY_ID: undefined },
    { ...value.env, AGENTPASS_CLOUD_POSSESSION_RECEIPT_PUBLIC_KEY: undefined },
    { ...value.env, AGENTPASS_CLOUD_POSSESSION_RECEIPT_PUBLIC_KEY: value.keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString() },
    { ...value.env, AGENTPASS_CLOUD_POSSESSION_RECEIPT_PUBLIC_KEY: publicPem(crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey) },
    { ...value.env, AGENTPASS_CLOUD_POSSESSION_RECEIPT_PUBLIC_KEY: `${value.pem}x` },
    { ...value.env, AGENTPASS_CLOUD_POSSESSION_RECEIPT_PUBLIC_KEY: `${value.pem}${"x".repeat(8192)}` },
    { ...value.env, AGENTPASS_CLOUD_POSSESSION_RECEIPT_TIMEOUT_MS: "0" },
    { ...value.env, AGENTPASS_CLOUD_POSSESSION_RECEIPT_PRIVATE_KEY_PATH: "/tmp/forbidden" }
  ];
  for (const env of invalid) {
    assert.throws(() => parsePossessionReceiptSignerConfig(env, {}, { now: () => NOW }), (error) => error.code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
  }
});

test("redacts provider failures and distinguishes timeout from malformed output", async () => {
  const value = fixture();
  const secret = "super-secret-provider-detail";
  const failed = createHostedPossessionReceiptSigner({
    env: value.env,
    now: () => NOW,
    provider: {
      async publicKeyMetadata() { throw new Error(secret); },
      async sign() { throw new Error(secret); }
    }
  });
  await assert.rejects(() => failed.health(), (error) => error.code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.PROVIDER
    && !String(error).includes(secret) && !Object.hasOwn(error, "cause"));

  const timedOut = createHostedPossessionReceiptSigner({
    env: { ...value.env, AGENTPASS_CLOUD_POSSESSION_RECEIPT_TIMEOUT_MS: "10" },
    now: () => NOW,
    provider: {
      async publicKeyMetadata() { return new Promise(() => {}); },
      async sign() { return Buffer.alloc(64); }
    }
  });
  await assert.rejects(() => timedOut.publicKeyMetadata(), (error) => error.code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.TIMEOUT);

  const signTimedOut = createHostedPossessionReceiptSigner({
    env: { ...value.env, AGENTPASS_CLOUD_POSSESSION_RECEIPT_TIMEOUT_MS: "10" },
    now: () => NOW,
    provider: {
      ...value.provider,
      async sign() { return new Promise(() => {}); }
    }
  });
  await assert.rejects(() => signTimedOut.signPossessionReceipt(STATEMENT), (error) => error.code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.TIMEOUT);

  const malformed = createHostedPossessionReceiptSigner({
    env: value.env,
    now: () => NOW,
    provider: { ...value.provider, async sign() { return Buffer.alloc(65); } }
  });
  await assert.rejects(() => malformed.signPossessionReceipt(STATEMENT), (error) => error.code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.OUTPUT);

  const invalidSignature = createHostedPossessionReceiptSigner({
    env: value.env,
    now: () => NOW,
    provider: { ...value.provider, async sign() { return Buffer.alloc(64); } }
  });
  await assert.rejects(() => invalidSignature.signPossessionReceipt(STATEMENT), (error) => error.code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.VERIFICATION);
});

test("does not retain or accept private-key and file-path material", () => {
  const value = fixture();
  assert.throws(() => createHostedPossessionReceiptSigner({
    provider: value.provider,
    env: value.env,
    privateKey: value.keys.privateKey,
    now: () => NOW
  }), (error) => error.code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
  assert.throws(() => parsePossessionReceiptSignerConfig({
    ...value.env,
    AGENTPASS_CLOUD_POSSESSION_RECEIPT_PRIVATE_KEY: value.keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString()
  }, {}, { now: () => NOW }), (error) => error.code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
});
