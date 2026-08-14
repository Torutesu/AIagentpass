import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { deriveReleaseCandidateId } from "../../../lib/release-candidate-identity.mjs";
import {
  PROMOTION_EVIDENCE_ERROR_CODES,
  PROMOTION_EVIDENCE_PROTOCOL_VERSION,
  PROMOTION_EVIDENCE_PURPOSE,
  PROMOTION_EVIDENCE_SIGNATURE_DOMAIN,
  PROMOTION_EVIDENCE_SIGNING_VERSION,
  PROMOTION_EVIDENCE_VERSION,
  canonicalizePromotionEvidence,
  canonicalizePromotionEvidenceStatement,
  normalizePromotionEvidenceStatement,
  parseCanonicalPromotionEvidence,
  promotionEvidenceSigningData,
} from "../src/promotion-evidence-statement.mjs";
import { createHostedPromotionEvidenceSigner } from "../src/promotion-evidence-signer.mjs";
import { verifyPromotionEvidence } from "../src/promotion-evidence-verifier.mjs";

const NOW = Date.parse("2026-08-15T00:00:00.000Z");
const ARTIFACT = "1".repeat(64);
const CANDIDATE = deriveReleaseCandidateId(ARTIFACT);
const KEY_ID = "promotion-kms-2026-08";
const KEY_VERSION = 7;
const LIFECYCLE_VERSION = 3;

function statement(overrides = {}) {
  return {
    version: PROMOTION_EVIDENCE_VERSION,
    type: "agentpass.promotion-evidence",
    environment: "production",
    candidate_id: CANDIDATE,
    source_commit: "2".repeat(40),
    source_tree: "3".repeat(40),
    artifact_sha256: ARTIFACT,
    release_manifest_schema_version: 4,
    release_manifest_sha256: "4".repeat(64),
    purpose: PROMOTION_EVIDENCE_PURPOSE,
    protocol_version: PROMOTION_EVIDENCE_PROTOCOL_VERSION,
    signing_version: PROMOTION_EVIDENCE_SIGNING_VERSION,
    lifecycle_version: LIFECYCLE_VERSION,
    key_id: KEY_ID,
    key_version: KEY_VERSION,
    issued_at: new Date(NOW).toISOString(),
    expires_at: new Date(NOW + 5 * 60 * 1_000).toISOString(),
    ...overrides,
  };
}

function fixture() {
  const keys = crypto.generateKeyPairSync("ed25519");
  const publicKey = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
  const calls = [];
  const provider = {
    purpose: PROMOTION_EVIDENCE_PURPOSE,
    algorithm: "ed25519",
    version: PROMOTION_EVIDENCE_SIGNING_VERSION,
    key_id: KEY_ID,
    key_version: KEY_VERSION,
    async publicKeyMetadata(input) {
      calls.push({ kind: "metadata", input });
      return { key_id: KEY_ID, algorithm: "ed25519", public_key: publicKey };
    },
    async sign(input) {
      calls.push({ kind: "sign", input });
      return crypto.sign(null, input.bytes, keys.privateKey);
    },
  };
  const signer = createHostedPromotionEvidenceSigner({
    provider,
    keyId: KEY_ID,
    keyVersion: KEY_VERSION,
    lifecycleVersion: LIFECYCLE_VERSION,
    publicKey,
    now: () => NOW,
  });
  return { keys, publicKey, provider, signer, calls };
}

function expectedBinding() {
  return {
    environment: "production",
    candidateId: CANDIDATE,
    sourceCommit: "2".repeat(40),
    sourceTree: "3".repeat(40),
    artifactSha256: ARTIFACT,
    releaseManifestSha256: "4".repeat(64),
    releaseManifestSchemaVersion: 4,
    purpose: PROMOTION_EVIDENCE_PURPOSE,
    protocolVersion: PROMOTION_EVIDENCE_PROTOCOL_VERSION,
    signingVersion: PROMOTION_EVIDENCE_SIGNING_VERSION,
    lifecycleVersion: LIFECYCLE_VERSION,
    keyId: KEY_ID,
    keyVersion: KEY_VERSION,
  };
}

test("canonical statement binds v4 candidate identity, release digests, and managed versions", () => {
  const first = canonicalizePromotionEvidenceStatement(statement());
  const reordered = { ...statement() };
  const keys = Object.keys(reordered);
  const second = canonicalizePromotionEvidenceStatement(Object.fromEntries(keys.reverse().map((key) => [key, reordered[key]])));
  assert.equal(first, second);
  const normalized = normalizePromotionEvidenceStatement(statement(), { now: NOW, allowExpired: false, allowFuture: false });
  assert.equal(normalized.release_manifest_schema_version, 4);
  assert.equal(normalized.candidate_id, CANDIDATE);
  assert.ok(promotionEvidenceSigningData(normalized).subarray(0, Buffer.byteLength(PROMOTION_EVIDENCE_SIGNATURE_DOMAIN)).equals(Buffer.from(PROMOTION_EVIDENCE_SIGNATURE_DOMAIN)));
  assert.throws(() => normalizePromotionEvidenceStatement({ ...statement(), candidate_id: deriveReleaseCandidateId("f".repeat(64)) }), { code: PROMOTION_EVIDENCE_ERROR_CODES.BINDING });
  assert.throws(() => normalizePromotionEvidenceStatement({ ...statement(), release_manifest_schema_version: 3 }), { code: PROMOTION_EVIDENCE_ERROR_CODES.INPUT });
});

test("hosted signer signs only the exact purpose/domain and verifier checks every binding", async () => {
  const value = fixture();
  const signed = await value.signer.signPromotionEvidence(statement());
  const verified = verifyPromotionEvidence(signed, { publicKey: value.publicKey, ...expectedBinding(), now: NOW });
  assert.deepEqual(verified.statement, statement());
  assert.equal(signed.signature_algorithm, "ed25519");
  assert.equal(value.calls[0].input.purpose, PROMOTION_EVIDENCE_PURPOSE);
  assert.equal(value.calls[1].input.purpose, PROMOTION_EVIDENCE_PURPOSE);
  assert.equal(value.calls[1].input.version, PROMOTION_EVIDENCE_SIGNING_VERSION);
  assert.equal(value.calls[1].input.bytes.subarray(0, Buffer.byteLength(PROMOTION_EVIDENCE_SIGNATURE_DOMAIN)).toString(), PROMOTION_EVIDENCE_SIGNATURE_DOMAIN);
  assert.equal((await value.signer.publicKeyMetadata()).key_version, KEY_VERSION);
  assert.equal(JSON.stringify(value.signer).includes("PRIVATE KEY"), false);
});

test("verifier rejects environment, candidate, digest, purpose, and version substitution", async () => {
  const value = fixture();
  const signed = await value.signer.signPromotionEvidence(statement());
  for (const [field, replacement] of [
    ["environment", "staging"],
    ["candidateId", deriveReleaseCandidateId("f".repeat(64))],
    ["sourceCommit", "a".repeat(40)],
    ["sourceTree", "b".repeat(40)],
    ["artifactSha256", "c".repeat(64)],
    ["releaseManifestSha256", "d".repeat(64)],
    ["purpose", "agentpass.audit-anchor"],
    ["protocolVersion", PROMOTION_EVIDENCE_PROTOCOL_VERSION + 1],
    ["signingVersion", PROMOTION_EVIDENCE_SIGNING_VERSION + 1],
    ["lifecycleVersion", LIFECYCLE_VERSION + 1],
    ["keyId", "other-key"],
    ["keyVersion", KEY_VERSION + 1],
  ]) {
    await assert.rejects(
      Promise.resolve().then(() => verifyPromotionEvidence(signed, { publicKey: value.publicKey, ...expectedBinding(), [field]: replacement, now: NOW })),
      { code: PROMOTION_EVIDENCE_ERROR_CODES.BINDING },
    );
  }
});

test("unknown fields, unsigned envelopes, private keys, and noncanonical bytes fail closed", async () => {
  const value = fixture();
  assert.throws(() => normalizePromotionEvidenceStatement({ ...statement(), private_key: "-----BEGIN PRIVATE KEY-----" }), { code: PROMOTION_EVIDENCE_ERROR_CODES.UNKNOWN_FIELD });
  assert.throws(() => canonicalizePromotionEvidence({ ...statement() }), { code: PROMOTION_EVIDENCE_ERROR_CODES.UNKNOWN_FIELD });
  await assert.rejects(() => value.signer.signPromotionEvidence({ ...statement(), signing_key: "secret" }), { code: PROMOTION_EVIDENCE_ERROR_CODES.UNKNOWN_FIELD });
  await assert.rejects(() => value.signer.signPromotionEvidence(statement(), { privateKey: value.keys.privateKey }), { code: PROMOTION_EVIDENCE_ERROR_CODES.INPUT });
  const signed = await value.signer.signPromotionEvidence(statement());
  const canonical = canonicalizePromotionEvidence(signed);
  assert.deepEqual(parseCanonicalPromotionEvidence(Buffer.from(canonical), { now: NOW, allowExpired: false, allowFuture: false }), signed);
  assert.throws(() => parseCanonicalPromotionEvidence(Buffer.from(JSON.stringify(signed)), { now: NOW, allowExpired: false, allowFuture: false }), { code: PROMOTION_EVIDENCE_ERROR_CODES.NONCANONICAL });
  assert.throws(() => verifyPromotionEvidence(signed, { publicKey: value.keys.privateKey, ...expectedBinding(), now: NOW }), { code: PROMOTION_EVIDENCE_ERROR_CODES.CONFIG });
  const unsigned = { ...signed, signature: undefined };
  delete unsigned.signature;
  assert.throws(() => verifyPromotionEvidence(unsigned, { publicKey: value.publicKey, ...expectedBinding(), now: NOW }), { code: PROMOTION_EVIDENCE_ERROR_CODES.UNKNOWN_FIELD });
});

test("issuance is current and expiry is strictly bounded", async () => {
  const value = fixture();
  assert.throws(() => normalizePromotionEvidenceStatement(statement({ expires_at: new Date(NOW + 60 * 60 * 1_000 + 1).toISOString() }), { now: NOW, allowExpired: false, allowFuture: false }), { code: PROMOTION_EVIDENCE_ERROR_CODES.INPUT });
  assert.throws(() => normalizePromotionEvidenceStatement(statement({ issued_at: new Date(NOW + 1).toISOString() }), { now: NOW, allowExpired: false, allowFuture: false }), { code: PROMOTION_EVIDENCE_ERROR_CODES.NOT_YET_VALID });
  const expired = await value.signer.signPromotionEvidence(statement({ expires_at: new Date(NOW + 1_000).toISOString() }));
  assert.throws(() => verifyPromotionEvidence(expired, { publicKey: value.publicKey, ...expectedBinding(), now: NOW + 1_000 }), { code: PROMOTION_EVIDENCE_ERROR_CODES.EXPIRED });
});

test("hosted signer rejects provider key and purpose substitution", () => {
  const value = fixture();
  assert.throws(() => createHostedPromotionEvidenceSigner({
    provider: { ...value.provider, purpose: "agentpass.audit-anchor" },
    keyId: KEY_ID,
    keyVersion: KEY_VERSION,
    lifecycleVersion: LIFECYCLE_VERSION,
    now: () => NOW,
  }), { code: PROMOTION_EVIDENCE_ERROR_CODES.CONFIG });
  assert.throws(() => createHostedPromotionEvidenceSigner({
    provider: value.provider,
    keyId: KEY_ID,
    keyVersion: KEY_VERSION,
    lifecycleVersion: LIFECYCLE_VERSION,
    privateKey: value.keys.privateKey,
    now: () => NOW,
  }), { code: PROMOTION_EVIDENCE_ERROR_CODES.CONFIG });
});
