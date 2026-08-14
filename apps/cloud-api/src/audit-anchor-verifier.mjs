import crypto from "node:crypto";

import {
  AUDIT_ANCHOR_ALGORITHM,
  AUDIT_ANCHOR_ERROR_CODES,
  AUDIT_ANCHOR_MAX_TTL_MS,
  AUDIT_ANCHOR_PURPOSE,
  AUDIT_ANCHOR_PROTOCOL_VERSION,
  AUDIT_ANCHOR_SIGNING_VERSION,
  AUDIT_ANCHOR_ZERO_DIGEST,
  auditAnchorPublicKeyFingerprint,
  auditAnchorSigningData,
  normalizeAuditAnchor,
  parseAuditAnchorPublicKey,
  AuditAnchorError
} from "./audit-anchor-statement.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const ENVIRONMENT = /^(?:staging|production)$/u;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;

/**
 * Verify one complete Audit Anchor envelope against the caller's trusted
 * tenant/environment/chain/lifecycle context. All context bindings are
 * required; a caller cannot accidentally downgrade this to signature-only
 * verification.
 */
export function verifyAuditAnchor(input, {
  publicKey,
  organizationId,
  environment,
  chain,
  exportId,
  auditPosition,
  rootDigest,
  exportDigest,
  recordCount,
  keyId,
  keyVersion,
  lifecycleVersion,
  previousAuditPosition,
  previousRootDigest,
  now = Date.now(),
  maxTtlMs = AUDIT_ANCHOR_MAX_TTL_MS
} = {}) {
  try {
    validateContext({ publicKey, organizationId, environment, chain, exportId, auditPosition, rootDigest, exportDigest, recordCount, keyId, keyVersion, lifecycleVersion, previousAuditPosition, previousRootDigest, now, maxTtlMs });
    const normalized = normalizeAuditAnchor(input, { now, allowExpired: false, allowFuture: false, maxTtlMs });
    const statement = normalized.statement;
    if (statement.organization_id !== organizationId || statement.environment !== environment
      || statement.chain !== chain || statement.export_id !== exportId
      || statement.audit_position !== auditPosition || statement.root_digest !== rootDigest
      || statement.export_digest !== exportDigest || statement.record_count !== recordCount
      || statement.key_id !== keyId || statement.key_version !== keyVersion
      || statement.lifecycle_version !== lifecycleVersion
      || statement.purpose !== AUDIT_ANCHOR_PURPOSE
      || statement.protocol_version !== AUDIT_ANCHOR_PROTOCOL_VERSION
      || statement.signing_version !== AUDIT_ANCHOR_SIGNING_VERSION) {
      fail(AUDIT_ANCHOR_ERROR_CODES.BINDING);
    }
    if (statement.previous_audit_position !== previousAuditPosition || statement.previous_root_digest !== previousRootDigest) {
      fail(AUDIT_ANCHOR_ERROR_CODES.ROLLBACK);
    }

    const key = parseAuditAnchorPublicKey(publicKey, AUDIT_ANCHOR_ERROR_CODES.CONFIG);
    if (normalized.signer_key_fingerprint !== auditAnchorPublicKeyFingerprint(key)) fail(AUDIT_ANCHOR_ERROR_CODES.SIGNATURE);
    const signature = Buffer.from(normalized.signature, "base64url");
    let valid = false;
    try { valid = crypto.verify(null, auditAnchorSigningData(statement), key, signature); }
    catch { valid = false; }
    if (!valid) fail(AUDIT_ANCHOR_ERROR_CODES.SIGNATURE);
    return normalized;
  } catch (error) {
    if (error instanceof AuditAnchorError) throw error;
    throw new AuditAnchorError(AUDIT_ANCHOR_ERROR_CODES.INPUT);
  }
}

export const verifyAuditAnchorSignature = verifyAuditAnchor;

function validateContext({ publicKey, organizationId, environment, chain, exportId, auditPosition, rootDigest, exportDigest, recordCount, keyId, keyVersion, lifecycleVersion, previousAuditPosition, previousRootDigest, now, maxTtlMs }) {
  parseAuditAnchorPublicKey(publicKey, AUDIT_ANCHOR_ERROR_CODES.CONFIG);
  if (typeof organizationId !== "string" || !UUID.test(organizationId)
    || typeof environment !== "string" || !ENVIRONMENT.test(environment)
    || !["admin", "device", "cloud_agent"].includes(chain)
    || typeof exportId !== "string" || !UUID.test(exportId)
    || !Number.isSafeInteger(auditPosition) || auditPosition < 1
    || typeof rootDigest !== "string" || !DIGEST.test(rootDigest) || rootDigest === AUDIT_ANCHOR_ZERO_DIGEST
    || typeof exportDigest !== "string" || !DIGEST.test(exportDigest)
    || !Number.isSafeInteger(recordCount) || recordCount < 1 || recordCount > auditPosition
    || typeof keyId !== "string" || !KEY_ID.test(keyId)
    || !Number.isSafeInteger(keyVersion) || keyVersion < 1
    || !Number.isSafeInteger(lifecycleVersion) || lifecycleVersion < 1
    || !Number.isSafeInteger(previousAuditPosition) || previousAuditPosition < 0
    || typeof previousRootDigest !== "string" || !DIGEST.test(previousRootDigest)
    || (previousAuditPosition === 0 && previousRootDigest !== AUDIT_ANCHOR_ZERO_DIGEST)
    || (previousAuditPosition > 0 && previousRootDigest === AUDIT_ANCHOR_ZERO_DIGEST)
    || !Number.isSafeInteger(maxTtlMs) || maxTtlMs < 1 || maxTtlMs > AUDIT_ANCHOR_MAX_TTL_MS
    || !Number.isSafeInteger(now instanceof Date ? now.getTime() : now) || (now instanceof Date ? now.getTime() : now) < 0) {
    fail(AUDIT_ANCHOR_ERROR_CODES.CONFIG);
  }
}

function fail(code) {
  throw new AuditAnchorError(code);
}
