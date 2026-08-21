import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { deriveReleaseCandidateId } from "../../../lib/release-candidate-identity.mjs";
import {
  PROMOTION_EVIDENCE_V3_ALGORITHM,
  PROMOTION_EVIDENCE_V3_ERROR_CODES,
  PROMOTION_EVIDENCE_V3_PURPOSE,
  PROMOTION_EVIDENCE_V3_SIGNATURE_DOMAIN,
  PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
  PROMOTION_EVIDENCE_V3_TYPE,
  PROMOTION_EVIDENCE_V3_VERSION,
  normalizePromotionEvidenceV3Statement,
  promotionEvidenceV3SigningData,
  promotionEvidenceV3StatementHash,
} from "../src/promotion-evidence-v3-statement.mjs";
import {
  PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES,
  createHostedPromotionEvidenceV3Signer,
} from "../src/promotion-evidence-v3-signer.mjs";

const NOW = Date.parse("2026-08-15T00:00:00.000Z");
const PRODUCT = "a".repeat(64);
const CANDIDATE = deriveReleaseCandidateId(PRODUCT);
const KEY_ID = "promotion-evidence-production-v3";
const KEY_VERSION = 7;
const LIFECYCLE_VERSION = 3;

function statement(overrides = {}) {
  return {
    version: PROMOTION_EVIDENCE_V3_VERSION,
    type: PROMOTION_EVIDENCE_V3_TYPE,
    promotion_id: "11111111-1111-4111-8111-111111111111",
    deployment_id: "cloud-prod-2026-08",
    environment: "production",
    candidate_id: CANDIDATE,
    source_commit: "1".repeat(40),
    source_tree: "2".repeat(40),
    product_pkg_sha256: PRODUCT,
    image_digest: `sha256:${"b".repeat(64)}`,
    sbom_sha256: "c".repeat(64),
    qualification_report_digests: ["0".repeat(63) + "1", "1".repeat(64)],
    release_manifest_schema_version: 4,
    release_manifest_sha256: "d".repeat(64),
    platform_approval_id: "22222222-2222-4222-8222-222222222222",
    platform_approval_digest: "e".repeat(64),
    approval_state: "approved",
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
    protocol_version: 3,
    signing_version: 3,
    lifecycle_version: LIFECYCLE_VERSION,
    key_id: KEY_ID,
    key_version: KEY_VERSION,
    issued_at: new Date(NOW).toISOString(),
    expires_at: new Date(NOW + 5 * 60 * 1_000).toISOString(),
    ...overrides,
  };
}

function fixture({ providerOverrides = {}, signerOverrides = {} } = {}) {
  const keys = crypto.generateKeyPairSync("ed25519");
  const publicKey = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
  const calls = [];
  const provider = {
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
    algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
    version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
    key_id: KEY_ID,
    key_version: KEY_VERSION,
    async publicKeyMetadata(input) {
      calls.push({ kind: "metadata", input });
      return { algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM, key_id: KEY_ID, public_key: publicKey };
    },
    async sign(input) {
      calls.push({ kind: "sign", input });
      return crypto.sign(null, input.bytes, keys.privateKey);
    },
    ...providerOverrides,
  };
  const signer = createHostedPromotionEvidenceV3Signer({
    provider,
    keyId: KEY_ID,
    keyVersion: KEY_VERSION,
    lifecycleVersion: LIFECYCLE_VERSION,
    publicKey,
    now: () => NOW,
    ...signerOverrides,
  });
  return { keys, publicKey, provider, signer, calls };
}

test("signs the exact v3 domain-separated canonical bytes and returns a frozen envelope", async () => {
  const value = fixture();
  const signed = await value.signer.signPromotionEvidenceV3(statement());
  assert.equal(signed.version, 3);
  assert.equal(signed.signature_algorithm, "ed25519");
  assert.equal(value.calls.length, 2);
  assert.equal(value.calls[0].input.purpose, PROMOTION_EVIDENCE_V3_PURPOSE);
  assert.deepEqual(Object.keys(value.calls[1].input).sort(), ["algorithm", "bytes", "key_id", "purpose", "version"]);
  assert.equal(value.calls[1].input.version, 3);
  assert.equal(value.calls[1].input.bytes.subarray(0, Buffer.byteLength(PROMOTION_EVIDENCE_V3_SIGNATURE_DOMAIN)).toString(), PROMOTION_EVIDENCE_V3_SIGNATURE_DOMAIN);
  assert.equal(crypto.verify(null, value.calls[1].input.bytes, value.keys.publicKey, Buffer.from(signed.signature, "base64url")), true);
  assert(Object.isFrozen(signed));
  assert(Object.isFrozen(signed.statement));
  assert(Object.isFrozen(signed.statement.qualification_report_digests));
  assert.equal(JSON.stringify(value.signer).includes("PRIVATE KEY"), false);
});

test("pins purpose, version, lifecycle, public key, and provider shape", async () => {
  const value = fixture();
  assert.equal((await value.signer.publicKeyMetadata()).key_version, KEY_VERSION);
  for (const [field, replacement] of [
    ["purpose", "agentpass.audit-anchor"],
    ["algorithm", "rsa"],
    ["version", 2],
    ["key_id", "other-key"],
    ["key_version", KEY_VERSION + 1],
  ]) {
    assert.throws(() => createHostedPromotionEvidenceV3Signer({
      ...value.signer,
      provider: { ...value.provider, [field]: replacement },
      publicKey: value.publicKey,
      keyId: KEY_ID,
      keyVersion: KEY_VERSION,
      lifecycleVersion: LIFECYCLE_VERSION,
      now: () => NOW,
    }), { code: PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.CONFIG });
  }
  assert.throws(() => createHostedPromotionEvidenceV3Signer({
    provider: { ...value.provider, genericSign() {} },
    publicKey: value.publicKey,
    keyId: KEY_ID,
    keyVersion: KEY_VERSION,
    lifecycleVersion: LIFECYCLE_VERSION,
    now: () => NOW,
  }), { code: PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.CONFIG });
  assert.throws(() => createHostedPromotionEvidenceV3Signer({
    provider: { ...value.provider, privateKey: "secret" },
    publicKey: value.publicKey,
    keyId: KEY_ID,
    keyVersion: KEY_VERSION,
    lifecycleVersion: LIFECYCLE_VERSION,
    now: () => NOW,
  }), { code: PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.CONFIG });
  assert.throws(() => createHostedPromotionEvidenceV3Signer({
    provider: value.provider,
    publicKey: value.keys.privateKey,
    keyId: KEY_ID,
    keyVersion: KEY_VERSION,
    lifecycleVersion: LIFECYCLE_VERSION,
    now: () => NOW,
  }), { code: PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.CONFIG });
});

test("rejects substituted metadata, forged signatures, output objects, and stale statements", async () => {
  const value = fixture();
  const other = crypto.generateKeyPairSync("ed25519");
  const cases = [
    {
      providerOverrides: {
        async publicKeyMetadata() { return { algorithm: "ed25519", key_id: KEY_ID, public_key: other.publicKey.export({ type: "spki", format: "pem" }).toString() }; },
      },
      code: PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.OUTPUT,
    },
    {
      providerOverrides: { async sign() { return crypto.randomBytes(64); } },
      code: PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.SIGNATURE,
    },
    {
      providerOverrides: { async sign() { return { signature: "secret" }; } },
      code: PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.OUTPUT,
    },
  ];
  for (const item of cases) {
    const candidate = fixture(item);
    await assert.rejects(() => candidate.signer.signPromotionEvidenceV3(statement()), { code: item.code });
  }
  await assert.rejects(() => value.signer.signPromotionEvidenceV3(statement({ key_version: KEY_VERSION + 1 })), { code: PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.BINDING });
  await assert.rejects(() => value.signer.signPromotionEvidenceV3({ ...statement(), private_key: "-----BEGIN PRIVATE KEY-----" }), { code: PROMOTION_EVIDENCE_V3_ERROR_CODES.UNKNOWN_FIELD });
  const accessor = statement();
  Object.defineProperty(accessor, "deployment_id", { enumerable: true, get() { return "cloud-prod-2026-08"; } });
  await assert.rejects(() => value.signer.signPromotionEvidenceV3(accessor), { code: PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT });
  const cycle = statement();
  cycle.cycle = cycle;
  await assert.rejects(() => value.signer.signPromotionEvidenceV3(cycle), { code: PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT });
});

test("does not accept caller-selected operation options or private key configuration", async () => {
  const value = fixture();
  await assert.rejects(() => value.signer.signPromotionEvidenceV3(statement(), { privateKey: value.keys.privateKey }), { code: PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.INPUT });
  await assert.rejects(() => value.signer.signPromotionEvidenceV3(statement(), { signal: "not-an-abort-signal" }), { code: PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.INPUT });
  assert.throws(() => createHostedPromotionEvidenceV3Signer({
    provider: value.provider,
    publicKey: value.publicKey,
    publicKeyFingerprint: "SHA256:" + "A".repeat(43),
    keyId: KEY_ID,
    keyVersion: KEY_VERSION,
    lifecycleVersion: LIFECYCLE_VERSION,
    now: () => NOW,
  }), { code: PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.CONFIG });
  const wrongClock = fixture({ signerOverrides: { now: () => "later" } });
  await assert.rejects(() => wrongClock.signer.signPromotionEvidenceV3(statement()), { code: PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.CONFIG });
});

test("normalizes statements before signing, preserving exact canonical identity", async () => {
  const value = fixture();
  const input = statement();
  const normalized = normalizePromotionEvidenceV3Statement(input, { now: NOW, allowExpired: false, allowFuture: false });
  const signed = await value.signer.sign(input);
  assert.deepEqual(signed.statement, normalized);
  assert.equal(signed.statement_hash, promotionEvidenceV3StatementHash(normalized));
  assert.equal(promotionEvidenceV3SigningData(signed.statement).subarray(0, 32).toString(), PROMOTION_EVIDENCE_V3_SIGNATURE_DOMAIN);
});
