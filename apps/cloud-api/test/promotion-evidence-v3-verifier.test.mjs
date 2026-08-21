import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { deriveReleaseCandidateId } from "../../../lib/release-candidate-identity.mjs";
import {
  PROMOTION_EVIDENCE_V3_ERROR_CODES,
  PROMOTION_EVIDENCE_V3_ALGORITHM, PROMOTION_EVIDENCE_V3_PURPOSE, PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
  PROMOTION_EVIDENCE_V3_SIGNING_VERSION, PROMOTION_EVIDENCE_V3_TYPE, PROMOTION_EVIDENCE_V3_VERSION,
  normalizePromotionEvidenceV3Statement, promotionEvidenceV3PublicKeyFingerprint,
  promotionEvidenceV3SigningData, promotionEvidenceV3StatementHash
} from "../src/promotion-evidence-v3-statement.mjs";
import { verifyPromotionEvidenceV3 } from "../src/promotion-evidence-v3-verifier.mjs";

const now = Date.parse("2026-08-15T00:00:00.000Z");
const keys = crypto.generateKeyPairSync("ed25519");
const product = "a".repeat(64);
const authority = {
  promotion_id: "11111111-1111-4111-8111-111111111111", deployment_id: "cloud-prod", environment: "production",
  candidate_id: deriveReleaseCandidateId(product), source_commit: "1".repeat(40), source_tree: "2".repeat(40),
  product_pkg_sha256: product, image_digest: `sha256:${"3".repeat(64)}`, sbom_sha256: "4".repeat(64),
  qualification_report_digests: ["0".repeat(64), "1".repeat(64)], release_manifest_sha256: "5".repeat(64),
  approval_id: "22222222-2222-4222-8222-222222222222", approval_digest: "6".repeat(64),
  signer_key_id: "promotion-evidence-production-v3", signer_key_version: 7, signer_lifecycle_version: 3
};

function envelope(overrides = {}) {
  const statement = normalizePromotionEvidenceV3Statement({
    version: PROMOTION_EVIDENCE_V3_VERSION, type: PROMOTION_EVIDENCE_V3_TYPE,
    promotion_id: authority.promotion_id, deployment_id: authority.deployment_id, environment: authority.environment,
    candidate_id: authority.candidate_id, source_commit: authority.source_commit, source_tree: authority.source_tree,
    product_pkg_sha256: authority.product_pkg_sha256, image_digest: authority.image_digest, sbom_sha256: authority.sbom_sha256,
    qualification_report_digests: authority.qualification_report_digests, release_manifest_sha256: authority.release_manifest_sha256,
    platform_approval_id: authority.approval_id, platform_approval_digest: authority.approval_digest,
    approval_state: "approved", purpose: PROMOTION_EVIDENCE_V3_PURPOSE, protocol_version: PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
    signing_version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION, lifecycle_version: authority.signer_lifecycle_version,
    key_id: authority.signer_key_id, key_version: authority.signer_key_version,
    release_manifest_schema_version: 4, issued_at: new Date(now).toISOString(), expires_at: new Date(now + 300_000).toISOString()
  });
  const signature = crypto.sign(null, promotionEvidenceV3SigningData(statement, { now, allowExpired: false, allowFuture: false }), keys.privateKey).toString("base64url");
  return { version: 3, type: PROMOTION_EVIDENCE_V3_TYPE, statement, statement_hash: promotionEvidenceV3StatementHash(statement), signature_algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM, signer_key_fingerprint: promotionEvidenceV3PublicKeyFingerprint(keys.publicKey), signature, ...overrides };
}

test("verifies the real v3 signature and every authority binding", () => {
  assert.deepEqual(verifyPromotionEvidenceV3(envelope(), { publicKey: keys.publicKey, authority, now }).statement, envelope().statement);
  assert.throws(() => verifyPromotionEvidenceV3(envelope({ signature: "A".repeat(86) }), { publicKey: keys.publicKey, authority, now }));
  assert.throws(() => verifyPromotionEvidenceV3(envelope(), { publicKey: keys.publicKey, authority: { ...authority, image_digest: `sha256:${"9".repeat(64)}` }, now }));
});

test("rejects incomplete authority instead of leaving evidence fields unbound", () => {
  for (const field of [
    "promotion_id", "deployment_id", "environment", "candidate_id", "source_commit", "source_tree",
    "product_pkg_sha256", "image_digest", "sbom_sha256", "qualification_report_digests",
    "release_manifest_sha256", "approval_id", "approval_digest", "signer_lifecycle_version",
    "signer_key_id", "signer_key_version"
  ]) {
    const incomplete = { ...authority };
    delete incomplete[field];
    assert.throws(
      () => verifyPromotionEvidenceV3(envelope(), { publicKey: keys.publicKey, authority: incomplete, now }),
      (error) => error.code === PROMOTION_EVIDENCE_V3_ERROR_CODES.BINDING
    );
  }
});
