import crypto from "node:crypto";

import {
  PROMOTION_EVIDENCE_ERROR_CODES,
  PROMOTION_EVIDENCE_MAX_TTL_MS,
  PROMOTION_EVIDENCE_TYPE,
  PROMOTION_EVIDENCE_VERSION,
  canonicalSignature,
  normalizePromotionEvidence,
  parsePromotionEvidencePublicKey,
  promotionEvidencePublicKeyFingerprint,
  promotionEvidenceSigningData,
  PromotionEvidenceError,
} from "./promotion-evidence-statement.mjs";

/**
 * Verify a promotion-evidence envelope against the exact release and hosted
 * signer binding expected by the caller. Expected bindings are deliberately
 * explicit so a verifier cannot silently accept another environment,
 * candidate, lifecycle, or key version.
 */
export function verifyPromotionEvidence(input, {
  publicKey,
  environment,
  candidateId,
  candidate_id: candidateIdAlias,
  sourceCommit,
  source_commit: sourceCommitAlias,
  sourceTree,
  source_tree: sourceTreeAlias,
  artifactSha256,
  artifact_sha256: artifactSha256Alias,
  releaseManifestSha256,
  release_manifest_sha256: releaseManifestSha256Alias,
  releaseManifestSchemaVersion,
  release_manifest_schema_version: releaseManifestSchemaVersionAlias,
  purpose,
  protocolVersion,
  signingVersion,
  lifecycleVersion,
  keyId,
  key_id: keyIdAlias,
  keyVersion,
  key_version: keyVersionAlias,
  signerKeyFingerprint,
  signer_key_fingerprint: signerKeyFingerprintAlias,
  now = Date.now(),
  maxTtlMs = PROMOTION_EVIDENCE_MAX_TTL_MS,
} = {}) {
  try {
    const envelope = normalizePromotionEvidence(input, {
      allowExpired: false,
      allowFuture: false,
      now,
      maxTtlMs,
    });
    if (envelope.version !== PROMOTION_EVIDENCE_VERSION || envelope.type !== PROMOTION_EVIDENCE_TYPE) fail(PROMOTION_EVIDENCE_ERROR_CODES.SIGNATURE);
    const statement = envelope.statement;
    const expected = {
      environment,
      candidate_id: candidateId ?? candidateIdAlias,
      source_commit: sourceCommit ?? sourceCommitAlias,
      source_tree: sourceTree ?? sourceTreeAlias,
      artifact_sha256: artifactSha256 ?? artifactSha256Alias,
      release_manifest_sha256: releaseManifestSha256 ?? releaseManifestSha256Alias,
      release_manifest_schema_version: releaseManifestSchemaVersion ?? releaseManifestSchemaVersionAlias,
      purpose,
      protocol_version: protocolVersion,
      signing_version: signingVersion,
      lifecycle_version: lifecycleVersion,
      key_id: keyId ?? keyIdAlias,
      key_version: keyVersion ?? keyVersionAlias,
    };
    for (const [field, value] of Object.entries(expected)) {
      if (value !== undefined && statement[field] !== value) fail(PROMOTION_EVIDENCE_ERROR_CODES.BINDING);
    }

    if (publicKey === undefined) fail(PROMOTION_EVIDENCE_ERROR_CODES.CONFIG);
    const key = parsePromotionEvidencePublicKey(publicKey, PROMOTION_EVIDENCE_ERROR_CODES.CONFIG);
    const fingerprint = promotionEvidencePublicKeyFingerprint(key);
    const expectedFingerprint = signerKeyFingerprint ?? signerKeyFingerprintAlias;
    if (envelope.signer_key_fingerprint !== fingerprint || (expectedFingerprint !== undefined && expectedFingerprint !== fingerprint)) {
      fail(PROMOTION_EVIDENCE_ERROR_CODES.BINDING);
    }
    const valid = crypto.verify(
      null,
      promotionEvidenceSigningData(statement),
      key,
      canonicalSignature(envelope.signature),
    );
    if (!valid) fail(PROMOTION_EVIDENCE_ERROR_CODES.SIGNATURE);
    return envelope;
  } catch (error) {
    if (error instanceof PromotionEvidenceError) throw error;
    throw new PromotionEvidenceError(PROMOTION_EVIDENCE_ERROR_CODES.SIGNATURE);
  }
}

export const verifyPromotionEvidenceSignature = verifyPromotionEvidence;
export const verifyPromotionEvidenceEnvelope = verifyPromotionEvidence;

function fail(code) {
  throw new PromotionEvidenceError(code);
}
