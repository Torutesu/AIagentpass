import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { deriveReleaseCandidateId } from "../../../lib/release-candidate-identity.mjs";
import {
  PROMOTION_EVIDENCE_V3_PURPOSE,
  PROMOTION_EVIDENCE_V3_SIGNATURE_DOMAIN,
  PROMOTION_EVIDENCE_V3_TYPE,
  PROMOTION_EVIDENCE_V3_VERSION,
  normalizePromotionEvidenceV3Statement,
  promotionEvidenceV3SigningData,
  promotionEvidenceV3StatementHash,
} from "../src/promotion-evidence-v3-statement.mjs";
import { createHostedPromotionEvidenceV3Signer } from "../src/promotion-evidence-v3-signer.mjs";
import {
  PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES,
  createPromotionEvidenceV3Verifier,
  verifyPromotionEvidenceV3,
  verifyPromotionEvidenceV3Expired,
  verifyPromotionEvidenceV3Result,
} from "../src/promotion-evidence-v3-verifier.mjs";

const NOW = Date.parse("2026-08-15T00:00:00.000Z");
const PRODUCT = "a".repeat(64);
const CANDIDATE = deriveReleaseCandidateId(PRODUCT);
const KEY_ID = "promotion-evidence-production-v3";
const KEY_VERSION = 7;
const LIFECYCLE_VERSION = 3;

function statement(overrides = {}) {
  return {
    version: 3,
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

function context(overrides = {}) {
  return {
    deploymentId: "cloud-prod-2026-08",
    environment: "production",
    candidateId: CANDIDATE,
    sourceCommit: "1".repeat(40),
    sourceTree: "2".repeat(40),
    productPkgSha256: PRODUCT,
    imageDigest: `sha256:${"b".repeat(64)}`,
    sbomSha256: "c".repeat(64),
    qualificationReportDigests: ["0".repeat(63) + "1", "1".repeat(64)],
    releaseManifestSchemaVersion: 4,
    releaseManifestSha256: "d".repeat(64),
    platformApprovalId: "22222222-2222-4222-8222-222222222222",
    platformApprovalDigest: "e".repeat(64),
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
    protocolVersion: 3,
    signingVersion: 3,
    lifecycleVersion: LIFECYCLE_VERSION,
    keyId: KEY_ID,
    keyVersion: KEY_VERSION,
    signerKeyFingerprint: overrides.signerKeyFingerprint,
    ...overrides,
  };
}

function fixture() {
  const keys = crypto.generateKeyPairSync("ed25519");
  const publicKey = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
  const signer = createHostedPromotionEvidenceV3Signer({
    provider: {
      purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
      algorithm: "ed25519",
      version: 3,
      key_id: KEY_ID,
      key_version: KEY_VERSION,
      async publicKeyMetadata() { return { algorithm: "ed25519", key_id: KEY_ID, public_key: publicKey }; },
      async sign({ bytes }) { return crypto.sign(null, bytes, keys.privateKey); },
    },
    publicKey,
    keyId: KEY_ID,
    keyVersion: KEY_VERSION,
    lifecycleVersion: LIFECYCLE_VERSION,
    now: () => NOW,
  });
  return { keys, publicKey, signer };
}

async function signedFixture(value = fixture(), input = statement()) {
  const envelope = await value.signer.sign(input);
  const metadata = await value.signer.publicKeyMetadata();
  const requests = [];
  const resolver = async (request) => {
    requests.push(request);
    return metadata;
  };
  return { ...value, envelope, metadata, resolver, requests };
}

function options(value, overrides = {}) {
  return { publicKeyResolver: value.resolver, now: NOW, ...context({ signerKeyFingerprint: value.envelope.signer_key_fingerprint }), ...overrides };
}

test("resolves the exact historical v3 key identity and verifies the signature", async () => {
  const value = await signedFixture();
  const verified = await verifyPromotionEvidenceV3(value.envelope, options(value));
  assert.deepEqual(verified, value.envelope);
  assert(Object.isFrozen(verified));
  assert(Object.isFrozen(verified.statement));
  assert.deepEqual(value.requests[0], {
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
    algorithm: "ed25519",
    protocol_version: 3,
    signing_version: 3,
    key_id: KEY_ID,
    key_version: KEY_VERSION,
    lifecycle_version: LIFECYCLE_VERSION,
    signer_key_fingerprint: value.envelope.signer_key_fingerprint,
  });
  assert(Object.isFrozen(value.requests[0]));
});

test("requires every authoritative deployment, artifact, approval, and signer context field", async () => {
  const value = await signedFixture();
  for (const [field, replacement] of [
    ["deploymentId", "cloud-staging-2026-08"],
    ["environment", "staging"],
    ["candidateId", deriveReleaseCandidateId("f".repeat(64))],
    ["sourceCommit", "f".repeat(40)],
    ["sourceTree", "f".repeat(40)],
    ["productPkgSha256", "f".repeat(64)],
    ["imageDigest", `sha256:${"f".repeat(64)}`],
    ["sbomSha256", "f".repeat(64)],
    ["qualificationReportDigests", ["f".repeat(64)]],
    ["releaseManifestSha256", "f".repeat(64)],
    ["platformApprovalId", "33333333-3333-4333-8333-333333333333"],
    ["platformApprovalDigest", "f".repeat(64)],
    ["keyVersion", KEY_VERSION + 1],
    ["lifecycleVersion", LIFECYCLE_VERSION + 1],
    ["signerKeyFingerprint", `SHA256:${"A".repeat(43)}`],
  ]) {
    await assert.rejects(() => verifyPromotionEvidenceV3(value.envelope, options(value, { [field]: replacement })), { code: PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.CONTEXT });
  }
  const complete = options(value);
  for (const field of [
    "deploymentId", "environment", "candidateId", "sourceCommit", "sourceTree", "productPkgSha256",
    "imageDigest", "sbomSha256", "qualificationReportDigests", "releaseManifestSchemaVersion",
    "releaseManifestSha256", "platformApprovalId", "platformApprovalDigest", "purpose", "protocolVersion",
    "signingVersion", "lifecycleVersion", "keyId", "keyVersion", "signerKeyFingerprint",
  ]) {
    const missing = { ...complete };
    delete missing[field];
    await assert.rejects(() => verifyPromotionEvidenceV3(value.envelope, missing), { code: PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.CONFIG });
  }
  await assert.rejects(() => verifyPromotionEvidenceV3(value.envelope, { publicKeyResolver: value.resolver, now: NOW }), { code: PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.CONFIG });
});

test("rejects cross-purpose, stale, substituted, and v2 material", async () => {
  const value = await signedFixture();
  for (const [field, replacement] of [
    ["purpose", "agentpass.audit-anchor"],
    ["protocol_version", 2],
    ["signing_version", 2],
    ["key_id", "other-key"],
    ["key_version", 8],
    ["lifecycle_version", 4],
  ]) {
    const input = structuredClone(value.envelope);
    input.statement[field] = replacement;
    await assert.rejects(() => verifyPromotionEvidenceV3(input, options(value)), { code: /ERR_PROMOTION_EVIDENCE_V3_/ });
  }
  const v2 = structuredClone(value.envelope);
  v2.version = 2;
  await assert.rejects(() => verifyPromotionEvidenceV3(v2, options(value)), { code: /ERR_PROMOTION_EVIDENCE_V3_/ });
  await assert.rejects(() => verifyPromotionEvidenceV3(value.envelope, options(value, { keyVersion: KEY_VERSION + 1 })), { code: PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.CONTEXT });
});

test("supports expired evidence only through explicit historical expiry verification", async () => {
  const value = fixture();
  const expiredStatement = normalizePromotionEvidenceV3Statement(statement({
    expires_at: new Date(NOW + 1_000).toISOString(),
  }), { now: NOW, allowExpired: false, allowFuture: false });
  const envelope = {
    version: 3,
    type: PROMOTION_EVIDENCE_V3_TYPE,
    statement: expiredStatement,
    statement_hash: promotionEvidenceV3StatementHash(expiredStatement),
    signature_algorithm: "ed25519",
    signer_key_fingerprint: (await value.signer.publicKeyMetadata()).public_key_fingerprint,
    signature: crypto.sign(null, promotionEvidenceV3SigningData(expiredStatement), value.keys.privateKey).toString("base64url"),
  };
  const valueWithExpired = await signedFixture(value, statement({ expires_at: new Date(NOW + 1_000).toISOString() }));
  valueWithExpired.envelope = envelope;
  await assert.rejects(() => verifyPromotionEvidenceV3(envelope, options(valueWithExpired, { now: NOW + 1_000 })), { code: "ERR_PROMOTION_EVIDENCE_V3_EXPIRED" });
  const verified = await verifyPromotionEvidenceV3Expired(envelope, options(valueWithExpired, { now: NOW + 1_000 }));
  assert.deepEqual(verified, envelope);
  const result = await verifyPromotionEvidenceV3Result(envelope, options(valueWithExpired, { now: NOW + 1_000, allowExpired: true }));
  assert.deepEqual(result, { valid: true, historical_key: true, expired: true, version: 3, purpose: PROMOTION_EVIDENCE_V3_PURPOSE });
  assert(Object.isFrozen(result));
});

test("fails closed on resolver output and input fault classes without leaking provider data", async () => {
  const value = await signedFixture();
  const faults = [
    () => ({ ...value.metadata, purpose: "agentpass.audit-anchor" }),
    () => ({ ...value.metadata, public_key_fingerprint: "SHA256:" + "A".repeat(43) }),
    () => ({ ...value.metadata, private_key: "-----BEGIN PRIVATE KEY-----" }),
    () => ({ ...value.metadata, diagnostic: "provider-secret" }),
  ];
  for (const make of faults) {
    await assert.rejects(() => verifyPromotionEvidenceV3(value.envelope, { ...options(value), publicKeyResolver: async () => make() }), { code: PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.HISTORICAL_KEY });
  }
  const unknown = structuredClone(value.envelope);
  unknown.extra = true;
  await assert.rejects(() => verifyPromotionEvidenceV3(unknown, options(value)), { code: "ERR_PROMOTION_EVIDENCE_V3_UNKNOWN_FIELD" });
  const accessor = structuredClone(value.envelope);
  Object.defineProperty(accessor, "type", { enumerable: true, get() { return PROMOTION_EVIDENCE_V3_TYPE; } });
  await assert.rejects(() => verifyPromotionEvidenceV3(accessor, options(value)), { code: PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.CONFIG });
  const prototype = structuredClone(value.envelope);
  Object.setPrototypeOf(prototype, { forged: true });
  await assert.rejects(() => verifyPromotionEvidenceV3(prototype, options(value)), { code: PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.CONFIG });
  const cycle = structuredClone(value.envelope);
  cycle.statement.cycle = cycle.statement;
  await assert.rejects(() => verifyPromotionEvidenceV3(cycle, options(value)), { code: PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.CONFIG });
  assert.equal(JSON.stringify(value.envelope).includes("PRIVATE KEY"), false);
});

test("exposes a closed verifier object and keeps canonical v3 bytes independent of input key order", async () => {
  const value = await signedFixture();
  const verifier = createPromotionEvidenceV3Verifier(options(value));
  const reordered = Object.fromEntries(Object.entries(value.envelope).reverse());
  const verified = await verifier.verify(reordered);
  assert.equal(verified.statement_hash, value.envelope.statement_hash);
  assert.equal(promotionEvidenceV3SigningData(verified.statement).subarray(0, Buffer.byteLength(PROMOTION_EVIDENCE_V3_SIGNATURE_DOMAIN)).toString(), PROMOTION_EVIDENCE_V3_SIGNATURE_DOMAIN);
  assert.deepEqual(Object.keys(verifier).sort(), ["verify", "verifyExpired", "verifyPromotionEvidenceV3"]);
});
