import crypto from "node:crypto";

import {
  PROMOTION_EVIDENCE_V3_ERROR_CODES,
  PROMOTION_EVIDENCE_V3_MAX_TTL_MS,
  canonicalSignatureV3,
  normalizePromotionEvidenceV3,
  parsePromotionEvidenceV3PublicKey,
  promotionEvidenceV3PublicKeyFingerprint,
  promotionEvidenceV3SigningData,
  PromotionEvidenceV3Error
} from "./promotion-evidence-v3-statement.mjs";

const REQUIRED_AUTHORITY_BINDINGS = Object.freeze([
  "promotion_id", "deployment_id", "environment", "candidate_id", "source_commit", "source_tree",
  "product_pkg_sha256", "image_digest", "sbom_sha256", "qualification_report_digests",
  "release_manifest_sha256", "approval_id", "approval_digest", "signer_lifecycle_version",
  "signer_key_id", "signer_key_version"
]);

export function verifyPromotionEvidenceV3(input, { publicKey, authority, now = Date.now(), maxTtlMs = PROMOTION_EVIDENCE_V3_MAX_TTL_MS } = {}) {
  try {
    const envelope = normalizePromotionEvidenceV3(input, { now, allowExpired: false, allowFuture: false, maxTtlMs });
    if (!authority || typeof authority !== "object") fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.CONFIG);
    // Every field below is required by the promotion authority contract. An
    // omitted field must not silently become an unbound evidence field.
    if (REQUIRED_AUTHORITY_BINDINGS.some((field) => !Object.hasOwn(authority, field) || authority[field] === undefined)) {
      fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.BINDING);
    }
    const statement = envelope.statement;
    const expected = {
      promotion_id: authority.promotion_id, deployment_id: authority.deployment_id, environment: authority.environment,
      candidate_id: authority.candidate_id, source_commit: authority.source_commit, source_tree: authority.source_tree,
      product_pkg_sha256: authority.product_pkg_sha256, image_digest: authority.image_digest, sbom_sha256: authority.sbom_sha256,
      qualification_report_digests: authority.qualification_report_digests, release_manifest_sha256: authority.release_manifest_sha256,
      platform_approval_id: authority.approval_id, platform_approval_digest: authority.approval_digest,
      lifecycle_version: authority.signer_lifecycle_version, key_id: authority.signer_key_id, key_version: authority.signer_key_version
    };
    for (const [field, value] of Object.entries(expected)) {
      if (value !== undefined && JSON.stringify(statement[field]) !== JSON.stringify(value)) fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.BINDING);
    }
    const key = parsePromotionEvidenceV3PublicKey(publicKey, PROMOTION_EVIDENCE_V3_ERROR_CODES.CONFIG);
    if (envelope.signer_key_fingerprint !== promotionEvidenceV3PublicKeyFingerprint(key)) fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.BINDING);
    if (!crypto.verify(null, promotionEvidenceV3SigningData(statement, { now, allowExpired: false, allowFuture: false, maxTtlMs }), key, canonicalSignatureV3(envelope.signature))) {
      fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.SIGNATURE);
    }
    return envelope;
  } catch (error) {
    if (error instanceof PromotionEvidenceV3Error) throw error;
    throw new PromotionEvidenceV3Error(PROMOTION_EVIDENCE_V3_ERROR_CODES.SIGNATURE);
  }
}

export const verifyPromotionEvidenceV3Envelope = verifyPromotionEvidenceV3;

function fail(code) { throw new PromotionEvidenceV3Error(code); }
