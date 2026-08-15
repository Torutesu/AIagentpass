import crypto from "node:crypto";

import {
  PROMOTION_EVIDENCE_V3_ALGORITHM,
  PROMOTION_EVIDENCE_V3_ERROR_CODES,
  PROMOTION_EVIDENCE_V3_MAX_TTL_MS,
  PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
  PROMOTION_EVIDENCE_V3_PURPOSE,
  PROMOTION_EVIDENCE_V3_SIGNATURE_DOMAIN,
  PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
  PROMOTION_EVIDENCE_V3_TYPE,
  PROMOTION_EVIDENCE_V3_VERSION,
  canonicalSignatureV3,
  normalizePromotionEvidenceV3,
  parsePromotionEvidenceV3PublicKey,
  promotionEvidenceV3PublicKeyFingerprint,
  promotionEvidenceV3SigningData,
  PromotionEvidenceV3Error,
} from "./promotion-evidence-v3-statement.mjs";

export const PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES = Object.freeze({
  ...PROMOTION_EVIDENCE_V3_ERROR_CODES,
  CONTEXT: "ERR_PROMOTION_EVIDENCE_V3_CONTEXT",
  HISTORICAL_KEY: "ERR_PROMOTION_EVIDENCE_V3_HISTORICAL_KEY",
});

const OPTION_KEYS = Object.freeze([
  "allowExpired", "artifactSha256", "artifact_sha256", "candidateId", "candidate_id", "deploymentId",
  "deployment_id", "environment", "historicalKeyResolver", "historicalPublicKeyResolver", "keyId", "key_id",
  "keyVersion", "key_version", "lifecycleVersion", "lifecycle_version", "imageDigest", "image_digest",
  "maxTtlMs", "now", "platformApprovalDigest", "platform_approval_digest", "platformApprovalId",
  "platform_approval_id", "approvalId", "approval_id", "approvalDigest", "approval_digest", "productPkgSha256", "product_pkg_sha256", "protocolVersion", "protocol_version",
  "publicKeyResolver", "qualificationReportDigests", "qualification_report_digests", "releaseManifestSchemaVersion",
  "release_manifest_schema_version", "releaseManifestSha256", "release_manifest_sha256", "sbomSha256", "sbom_sha256",
  "signerKeyFingerprint", "signer_key_fingerprint", "signingVersion", "signing_version", "sourceCommit", "source_commit",
  "sourceTree", "source_tree", "purpose",
]);
const METADATA_KEYS = Object.freeze([
  "version", "type", "purpose", "domain", "protocol_version", "signing_version", "algorithm", "key_id",
  "key_version", "lifecycle_version", "public_key", "public_key_fingerprint",
]);
const REQUEST_KEYS = Object.freeze([
  "purpose", "algorithm", "protocol_version", "signing_version", "key_id", "key_version", "lifecycle_version",
  "signer_key_fingerprint",
]);
const PRIVATE_FIELD = /(?:private(?:[_ -]?key|[_ -]?material)?|secret|password|credential|authorization|bearer|cookie|token|diagnostic|debug|trace|pem)/iu;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const IMAGE_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const ENVIRONMENT = /^(?:staging|production)$/u;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;

/**
 * Verify v3 promotion evidence against an exact platform context and a
 * historical public-key resolver. The resolver never receives caller bytes
 * or a generic provider; it receives only the fixed v3 key identity.
 */
export async function verifyPromotionEvidenceV3(input, options = {}) {
  let config;
  try {
    config = normalizeOptions(options);
  } catch (error) {
    if (error instanceof PromotionEvidenceV3Error) throw error;
    throw verifierError(PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.CONFIG);
  }
  return verifyPromotionEvidenceV3WithConfig(input, config);
}

async function verifyPromotionEvidenceV3WithConfig(input, config) {
  try {
    assertDataTree(input);
  } catch {
    throw verifierError(PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.CONFIG);
  }
  let envelope;
  try {
    envelope = normalizePromotionEvidenceV3(input, {
      now: config.now,
      allowExpired: config.allowExpired,
      allowFuture: false,
      maxTtlMs: config.maxTtlMs,
    });
  } catch (error) {
    if (error instanceof PromotionEvidenceV3Error) throw error;
    throw verifierError(PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.SIGNATURE);
  }

  assertContext(envelope, config.context);
  const request = Object.freeze({
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
    algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
    protocol_version: PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
    signing_version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
    key_id: envelope.statement.key_id,
    key_version: envelope.statement.key_version,
    lifecycle_version: envelope.statement.lifecycle_version,
    signer_key_fingerprint: envelope.signer_key_fingerprint,
  });

  let metadata;
  try {
    metadata = await config.resolver(request);
    metadata = normalizeHistoricalMetadata(metadata, request);
  } catch (error) {
    if (error instanceof PromotionEvidenceV3Error) throw error;
    throw verifierError(PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.HISTORICAL_KEY);
  }

  let valid = false;
  try {
    valid = crypto.verify(
      null,
      promotionEvidenceV3SigningData(envelope.statement, { allowExpired: true, allowFuture: true, maxTtlMs: config.maxTtlMs }),
      metadata.publicKey,
      canonicalSignatureV3(envelope.signature),
    );
  } catch {
    valid = false;
  }
  if (!valid) throw verifierError(PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.SIGNATURE);
  return deepFreeze(envelope);
}

export const verifyPromotionEvidenceV3Signature = verifyPromotionEvidenceV3;
export const verifyPromotionEvidenceV3Envelope = verifyPromotionEvidenceV3;
export const verifyHistoricalPromotionEvidenceV3 = verifyPromotionEvidenceV3;
export const verifyPromotionEvidence = verifyPromotionEvidenceV3;

/** Explicit historical-expiry entry point; expiry is never implicit. */
export async function verifyPromotionEvidenceV3Expired(input, options = {}) {
  const config = normalizeOptions(options);
  return verifyPromotionEvidenceV3WithConfig(input, Object.freeze({ ...config, allowExpired: true }));
}

/** Return a deliberately small, frozen verification summary when a summary is desired. */
export async function verifyPromotionEvidenceV3Result(input, options = {}) {
  const envelope = await verifyPromotionEvidenceV3(input, options);
  const now = normalizeNow(options.now === undefined ? Date.now() : options.now);
  return Object.freeze({
    valid: true,
    historical_key: true,
    expired: now >= Date.parse(envelope.statement.expires_at),
    version: PROMOTION_EVIDENCE_V3_VERSION,
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
  });
}

export function createPromotionEvidenceV3Verifier(options = {}) {
  const config = normalizeOptions(options);
  const historicalConfig = Object.freeze({ ...config, allowExpired: true });
  return Object.freeze({
    verify: (input) => verifyPromotionEvidenceV3WithConfig(input, config),
    verifyPromotionEvidenceV3: (input) => verifyPromotionEvidenceV3WithConfig(input, config),
    verifyExpired: (input) => verifyPromotionEvidenceV3WithConfig(input, historicalConfig),
  });
}

function normalizeOptions(value) {
  exactRecord(value, OPTION_KEYS, PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.CONFIG, true);
  const resolver = firstAlias(value, ["publicKeyResolver", "historicalPublicKeyResolver", "historicalKeyResolver"]);
  if (typeof resolver !== "function") throw verifierError(PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.CONFIG);
  const now = normalizeNow(value.now === undefined ? Date.now() : value.now);
  const maxTtlMs = value.maxTtlMs === undefined ? PROMOTION_EVIDENCE_V3_MAX_TTL_MS : value.maxTtlMs;
  if (!Number.isSafeInteger(maxTtlMs) || maxTtlMs < 1 || maxTtlMs > PROMOTION_EVIDENCE_V3_MAX_TTL_MS) {
    throw verifierError(PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.CONFIG);
  }
  const allowExpired = value.allowExpired === undefined ? false : value.allowExpired;
  if (typeof allowExpired !== "boolean") throw verifierError(PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.CONFIG);
  const context = normalizeContext(value);
  return Object.freeze({ resolver, now, maxTtlMs, allowExpired, context });
}

function normalizeContext(value) {
  const context = {
    deployment_id: requiredAlias(value, ["deployment_id", "deploymentId"], "deployment_id", IDENTIFIER),
    environment: requiredAlias(value, ["environment"], "environment", ENVIRONMENT),
    candidate_id: requiredAlias(value, ["candidate_id", "candidateId"], "candidate_id", /^release-pkg-sha256-v1-[0-9a-f]{64}$/u),
    source_commit: requiredAlias(value, ["source_commit", "sourceCommit"], "source_commit", /^[0-9a-f]{40}$/u),
    source_tree: requiredAlias(value, ["source_tree", "sourceTree"], "source_tree", /^[0-9a-f]{40}$/u),
    product_pkg_sha256: requiredAlias(value, ["product_pkg_sha256", "productPkgSha256", "artifact_sha256", "artifactSha256"], "product_pkg_sha256", DIGEST),
    image_digest: requiredAlias(value, ["image_digest", "imageDigest"], "image_digest", IMAGE_DIGEST),
    sbom_sha256: requiredAlias(value, ["sbom_sha256", "sbomSha256"], "sbom_sha256", DIGEST),
    qualification_report_digests: requiredDigestArray(value, ["qualification_report_digests", "qualificationReportDigests"]),
    release_manifest_schema_version: requiredIntegerAlias(value, ["release_manifest_schema_version", "releaseManifestSchemaVersion"], 4),
    release_manifest_sha256: requiredAlias(value, ["release_manifest_sha256", "releaseManifestSha256"], "release_manifest_sha256", DIGEST),
    platform_approval_id: requiredAlias(value, ["platform_approval_id", "platformApprovalId", "approval_id", "approvalId"], "platform_approval_id", UUID),
    platform_approval_digest: requiredAlias(value, ["platform_approval_digest", "platformApprovalDigest", "approval_digest", "approvalDigest"], "platform_approval_digest", DIGEST),
    purpose: requiredExactAlias(value, ["purpose"], PROMOTION_EVIDENCE_V3_PURPOSE),
    protocol_version: requiredIntegerAlias(value, ["protocol_version", "protocolVersion"], PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION),
    signing_version: requiredIntegerAlias(value, ["signing_version", "signingVersion"], PROMOTION_EVIDENCE_V3_SIGNING_VERSION),
    lifecycle_version: requiredPositiveIntegerAlias(value, ["lifecycle_version", "lifecycleVersion"]),
    key_id: requiredAlias(value, ["key_id", "keyId"], "key_id", IDENTIFIER),
    key_version: requiredPositiveIntegerAlias(value, ["key_version", "keyVersion"]),
    signer_key_fingerprint: requiredAlias(value, ["signer_key_fingerprint", "signerKeyFingerprint"], "signer_key_fingerprint", FINGERPRINT),
  };
  return deepFreeze(context);
}

function assertContext(envelope, expected) {
  for (const [field, value] of Object.entries(expected)) {
    const actual = field === "signer_key_fingerprint"
      ? envelope.signer_key_fingerprint
      : envelope.statement[field];
    if (Array.isArray(value)) {
      if (!Array.isArray(actual) || value.length !== actual.length
        || value.some((item, index) => item !== actual[index])) {
        throw verifierError(PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.CONTEXT);
      }
    } else if (actual !== value) {
      throw verifierError(PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.CONTEXT);
    }
  }
}

function normalizeHistoricalMetadata(value, request) {
  assertDataTree(value);
  exactRecord(value, METADATA_KEYS, PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.HISTORICAL_KEY);
  if (value.version !== PROMOTION_EVIDENCE_V3_VERSION || value.type !== PROMOTION_EVIDENCE_V3_TYPE
    || value.purpose !== PROMOTION_EVIDENCE_V3_PURPOSE || value.domain !== PROMOTION_EVIDENCE_V3_SIGNATURE_DOMAIN
    || value.protocol_version !== PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION
    || value.signing_version !== PROMOTION_EVIDENCE_V3_SIGNING_VERSION
    || value.algorithm !== PROMOTION_EVIDENCE_V3_ALGORITHM || value.key_id !== request.key_id
    || value.key_version !== request.key_version || value.lifecycle_version !== request.lifecycle_version
    || value.public_key_fingerprint !== request.signer_key_fingerprint
    || !FINGERPRINT.test(value.public_key_fingerprint)) {
    throw verifierError(PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.HISTORICAL_KEY);
  }
  const publicKey = parsePromotionEvidenceV3PublicKey(value.public_key, PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.HISTORICAL_KEY);
  if (promotionEvidenceV3PublicKeyFingerprint(publicKey) !== value.public_key_fingerprint) {
    throw verifierError(PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.HISTORICAL_KEY);
  }
  return Object.freeze({ publicKey });
}

function requiredAlias(value, aliases, field, expression) {
  const actual = firstAlias(value, aliases);
  if (actual === undefined || typeof actual !== "string" || !expression.test(actual)) {
    throw verifierError(PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.CONFIG);
  }
  return actual;
}

function requiredDigestArray(value, aliases) {
  const actual = firstAlias(value, aliases);
  try { assertDataTree(actual); } catch { throw verifierError(PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.CONFIG); }
  if (!Array.isArray(actual) || actual.length < 1 || actual.length > 16
    || actual.some((item) => typeof item !== "string" || !DIGEST.test(item))
    || actual.some((item, index) => index > 0 && actual[index - 1] >= item)) {
    throw verifierError(PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.CONFIG);
  }
  return Object.freeze([...actual]);
}

function requiredPositiveIntegerAlias(value, aliases) {
  const actual = firstAlias(value, aliases);
  if (!Number.isSafeInteger(actual) || actual < 1) {
    throw verifierError(PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.CONFIG);
  }
  return actual;
}

function requiredIntegerAlias(value, aliases, expected) {
  const actual = firstAlias(value, aliases);
  if (!Number.isSafeInteger(actual) || actual !== expected) {
    throw verifierError(PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.CONFIG);
  }
  return actual;
}

function requiredExactAlias(value, aliases, expected) {
  const actual = firstAlias(value, aliases);
  if (actual !== expected) throw verifierError(PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.CONFIG);
  return actual;
}

function firstAlias(value, aliases) {
  let selected;
  for (const alias of aliases) {
    if (!Object.hasOwn(value, alias)) continue;
    const descriptor = Object.getOwnPropertyDescriptor(value, alias);
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) {
      throw verifierError(PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.CONFIG);
    }
    if (selected !== undefined && !sameValue(selected, descriptor.value)) {
      throw verifierError(PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.CONFIG);
    }
    selected = descriptor.value;
  }
  return selected;
}

function sameValue(left, right) {
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left) && Array.isArray(right) && left.length === right.length
      && left.every((item, index) => item === right[index]);
  }
  return left === right;
}

function assertDataTree(value, seen = new Set()) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0)) throw new Error("number");
    return;
  }
  if (typeof value !== "object" || seen.has(value)) throw new Error("tree");
  const array = Array.isArray(value);
  if (array ? Object.getPrototypeOf(value) !== Array.prototype : Object.getPrototypeOf(value) !== Object.prototype) throw new Error("prototype");
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) {
    if (array && key === "length") continue;
    if (typeof key !== "string" || PRIVATE_FIELD.test(key) || key === "__proto__" || key === "constructor" || key === "prototype") throw new Error("field");
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !("value" in descriptor)) throw new Error("descriptor");
    assertDataTree(descriptor.value, seen);
  }
  seen.delete(value);
}

function exactRecord(value, keys, code, allowSubset = false) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw verifierError(code);
  }
  const actual = Reflect.ownKeys(value);
  if ((!allowSubset && actual.length !== keys.length) || actual.some((key) => typeof key !== "string" || PRIVATE_FIELD.test(key) || !keys.includes(key))) throw verifierError(code);
  for (const key of actual) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !("value" in descriptor)) throw verifierError(code);
  }
}

function normalizeNow(value) {
  const result = value instanceof Date ? value.getTime() : value;
  if (!Number.isSafeInteger(result) || result < 0) throw verifierError(PROMOTION_EVIDENCE_V3_VERIFIER_ERROR_CODES.CONFIG);
  return result;
}

function deepFreeze(value, seen = new Set()) {
  if (value && typeof value === "object" && !seen.has(value)) {
    seen.add(value);
    for (const child of Object.values(value)) deepFreeze(child, seen);
    Object.freeze(value);
  }
  return value;
}

function verifierError(code) {
  return new PromotionEvidenceV3Error(code);
}
