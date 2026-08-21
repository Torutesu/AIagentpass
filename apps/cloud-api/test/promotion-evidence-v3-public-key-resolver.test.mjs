import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  PROMOTION_EVIDENCE_V3_ALGORITHM,
  PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
  PROMOTION_EVIDENCE_V3_PURPOSE,
  PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
  promotionEvidenceV3PublicKeyFingerprint,
} from "../src/promotion-evidence-v3-statement.mjs";
import {
  PROMOTION_EVIDENCE_V3_PUBLIC_KEY_RESOLVER_ERROR_CODE,
  PromotionEvidenceV3PublicKeyResolverError,
  createPromotionEvidenceV3PublicKeyResolver,
} from "../src/promotion-evidence-v3-public-key-resolver.mjs";

const KEY_ID = "promotion-evidence-production-v3";
const KEY_VERSION = 7;
const LIFECYCLE_VERSION = 3;

function fixture({ state = "active", snapshotOverrides = {}, keyOverrides = {} } = {}) {
  const pair = crypto.generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
  const rawFingerprint = crypto.createHash("sha256")
    .update(pair.publicKey.export({ type: "spki", format: "der" }))
    .digest("hex");
  const snapshot = {
    version: 5,
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
    algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
    keys: [{
      key_id: KEY_ID,
      key_version: KEY_VERSION,
      purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
      algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
      public_key: publicKey,
      public_key_fingerprint: rawFingerprint,
      state,
      state_version: 5,
      ...keyOverrides,
    }],
    ...snapshotOverrides,
  };
  return {
    pair,
    publicKey,
    rawFingerprint,
    fingerprint: promotionEvidenceV3PublicKeyFingerprint(pair.publicKey),
    snapshot,
    repository: { async snapshot() { return snapshot; } },
  };
}

function input(overrides = {}) {
  return {
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
    algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
    protocol_version: PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
    signing_version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
    key_id: KEY_ID,
    key_version: KEY_VERSION,
    lifecycle_version: LIFECYCLE_VERSION,
    signer_key_fingerprint: "SHA256:" + "A".repeat(43),
    ...overrides,
  };
}

function validInput(value = fixture()) {
  return input({ signer_key_fingerprint: value.fingerprint });
}

function expectUnavailable(promise) {
  return assert.rejects(promise, (error) => error instanceof PromotionEvidenceV3PublicKeyResolverError
    && error.code === PROMOTION_EVIDENCE_V3_PUBLIC_KEY_RESOLVER_ERROR_CODE
    && !String(error).includes("secret"));
}

test("resolves exact v3 historical metadata from the durable snapshot", async () => {
  const value = fixture();
  const calls = [];
  const resolver = createPromotionEvidenceV3PublicKeyResolver({
    repository: { async snapshot(...args) { calls.push(args); return value.snapshot; } },
  });
  const metadata = await resolver(validInput(value));
  assert.deepEqual(metadata, {
    version: 3,
    type: "agentpass.promotion-evidence",
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
    domain: "AgentPass-Promotion-Evidence-v3\0",
    protocol_version: 3,
    signing_version: 3,
    algorithm: "ed25519",
    key_id: KEY_ID,
    key_version: KEY_VERSION,
    lifecycle_version: LIFECYCLE_VERSION,
    public_key: value.publicKey,
    public_key_fingerprint: value.fingerprint,
  });
  assert.deepEqual(calls, [[]]);
  assert(Object.isFrozen(metadata));
  assert.equal(JSON.stringify(metadata).includes("PRIVATE KEY"), false);
});

test("requires the exact fingerprint-bearing v3 request", async () => {
  const value = fixture();
  const resolver = createPromotionEvidenceV3PublicKeyResolver({ repository: value.repository });
  const invalid = [
    { ...validInput(value), extra: true },
    { ...validInput(value), purpose: "agentpass.audit-anchor" },
    { ...validInput(value), algorithm: "rsa" },
    { ...validInput(value), protocol_version: 2 },
    { ...validInput(value), signing_version: 2 },
    { ...validInput(value), key_id: "other-key" },
    { ...validInput(value), key_version: KEY_VERSION + 1 },
    { ...validInput(value), lifecycle_version: 0 },
    { ...validInput(value), signer_key_fingerprint: "SHA256:" + "A".repeat(42) },
    { ...validInput(value), signer_key_fingerprint: "SHA256:" + "!".repeat(43) },
    { ...validInput(value), signal: new AbortController().signal },
  ];
  for (const candidate of invalid) await expectUnavailable(resolver(candidate));

  const accessor = validInput(value);
  Object.defineProperty(accessor, "key_id", { enumerable: true, get() { return KEY_ID; } });
  await expectUnavailable(resolver(accessor));
  const customPrototype = validInput(value);
  Object.setPrototypeOf(customPrototype, { forged: true });
  await expectUnavailable(resolver(customPrototype));
  const cycle = validInput(value);
  cycle.cycle = cycle;
  await expectUnavailable(resolver(cycle));
  await expectUnavailable(resolver({ ...validInput(value), private_key: "-----BEGIN PRIVATE KEY-----" }));
});

test("fails closed for missing, malformed, cross-purpose, stale, disabled, duplicate, and mismatched snapshots", async (t) => {
  const base = fixture();
  const cases = [
    ["missing snapshot", { snapshotOverrides: { keys: undefined } }],
    ["cross-purpose snapshot", { snapshotOverrides: { purpose: "agentpass.audit-anchor" } }],
    ["wrong algorithm snapshot", { snapshotOverrides: { algorithm: "rsa" } }],
    ["old lifecycle snapshot", { snapshotOverrides: { version: LIFECYCLE_VERSION - 1 } }],
    ["revoked key", { state: "revoked" }],
    ["emergency disabled key", { state: "emergency-disabled" }],
    ["missing public key", { keyOverrides: { public_key: undefined } }],
    ["wrong key fingerprint", { keyOverrides: { public_key_fingerprint: "f".repeat(64) } }],
    ["cross-purpose key", { keyOverrides: { purpose: "agentpass.audit-anchor" } }],
    ["cross-algorithm key", { keyOverrides: { algorithm: "rsa" } }],
  ];
  for (const [name, options] of cases) {
    await t.test(name, async () => {
      const value = fixture(options);
      const resolver = createPromotionEvidenceV3PublicKeyResolver({ repository: value.repository });
      await expectUnavailable(resolver(validInput(value)));
    });
  }

  await t.test("duplicate lifecycle records", async () => {
    const value = fixture();
    value.snapshot.keys.push({ ...value.snapshot.keys[0] });
    await expectUnavailable(createPromotionEvidenceV3PublicKeyResolver({ repository: value.repository })(validInput(value)));
  });
  await t.test("malformed snapshot and unknown/private fields", async () => {
    const value = fixture();
    value.snapshot.unknown = true;
    await expectUnavailable(createPromotionEvidenceV3PublicKeyResolver({ repository: value.repository })(validInput(value)));
    const privateSnapshot = fixture();
    privateSnapshot.snapshot.private_key = "secret";
    await expectUnavailable(createPromotionEvidenceV3PublicKeyResolver({ repository: privateSnapshot.repository })(validInput(privateSnapshot)));
  });
  await t.test("storage failure is opaque", async () => {
    const resolver = createPromotionEvidenceV3PublicKeyResolver({ repository: { async snapshot() { throw new Error("database-secret"); } } });
    await expectUnavailable(resolver(validInput(base)));
  });
});

test("rejects repository configuration escapes and never accepts private key material", async () => {
  assert.throws(() => createPromotionEvidenceV3PublicKeyResolver(), TypeError);
  assert.throws(() => createPromotionEvidenceV3PublicKeyResolver({ repository: { snapshot() {}, extra: true } }), TypeError);
  const value = fixture();
  const privateSnapshot = fixture();
  privateSnapshot.snapshot.keys[0].public_key = value.pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  await expectUnavailable(createPromotionEvidenceV3PublicKeyResolver({ repository: privateSnapshot.repository })(validInput(privateSnapshot)));
});
