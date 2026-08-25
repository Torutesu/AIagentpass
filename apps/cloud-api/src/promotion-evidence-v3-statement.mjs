import crypto from "node:crypto";

import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import {
  assertReleaseCandidateIdMatchesProduct,
  RELEASE_MANIFEST_SCHEMA_VERSION,
} from "../../../lib/release-candidate-identity.mjs";

/**
 * Deployment/platform-operator scoped promotion evidence v3.
 *
 * This is intentionally a new contract.  v2 remains frozen and is not
 * imported here: changing the v2 implementation would make an old envelope
 * appear to have the stronger v3 binding set.  This module contains only the
 * canonical statement/envelope primitives; signer and issuance services are
 * separate boundaries.
 */
export const PROMOTION_EVIDENCE_V3_VERSION = 3;
export const PROMOTION_EVIDENCE_V3_TYPE = "agentpass.promotion-evidence";
export const PROMOTION_EVIDENCE_V3_PURPOSE = "agentpass.promotion-evidence";
export const PROMOTION_EVIDENCE_V3_SIGNATURE_DOMAIN = "AgentPass-Promotion-Evidence-v3\0";
export const PROMOTION_EVIDENCE_V3_ALGORITHM = "ed25519";
export const PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION = 3;
export const PROMOTION_EVIDENCE_V3_SIGNING_VERSION = 3;
export const PROMOTION_EVIDENCE_V3_RELEASE_MANIFEST_SCHEMA_VERSION = RELEASE_MANIFEST_SCHEMA_VERSION;
export const PROMOTION_EVIDENCE_V3_MAX_TTL_MS = 60 * 60 * 1_000;
export const PROMOTION_EVIDENCE_V3_MAX_SIGNING_BYTES = 128 * 1024;
export const PROMOTION_EVIDENCE_V3_MIN_QUALIFICATION_REPORT_DIGESTS = 1;
export const PROMOTION_EVIDENCE_V3_MAX_QUALIFICATION_REPORT_DIGESTS = 16;

export const PROMOTION_EVIDENCE_V3_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_PROMOTION_EVIDENCE_V3_CONFIG",
  INPUT: "ERR_PROMOTION_EVIDENCE_V3_INPUT",
  UNKNOWN_FIELD: "ERR_PROMOTION_EVIDENCE_V3_UNKNOWN_FIELD",
  NONCANONICAL: "ERR_PROMOTION_EVIDENCE_V3_NONCANONICAL",
  OUTPUT: "ERR_PROMOTION_EVIDENCE_V3_OUTPUT",
  EXPIRED: "ERR_PROMOTION_EVIDENCE_V3_EXPIRED",
  NOT_YET_VALID: "ERR_PROMOTION_EVIDENCE_V3_NOT_YET_VALID",
  BINDING: "ERR_PROMOTION_EVIDENCE_V3_BINDING",
  ORDERING: "ERR_PROMOTION_EVIDENCE_V3_ORDERING",
  SIGNATURE: "ERR_PROMOTION_EVIDENCE_V3_SIGNATURE",
});

export const PROMOTION_EVIDENCE_V3_STATEMENT_KEYS = Object.freeze([
  "version",
  "type",
  "promotion_id",
  "deployment_id",
  "environment",
  "candidate_id",
  "source_commit",
  "source_tree",
  "product_pkg_sha256",
  "image_digest",
  "sbom_sha256",
  "qualification_report_digests",
  "release_manifest_schema_version",
  "release_manifest_sha256",
  "platform_approval_id",
  "platform_approval_digest",
  "approval_state",
  "purpose",
  "protocol_version",
  "signing_version",
  "lifecycle_version",
  "key_id",
  "key_version",
  "issued_at",
  "expires_at",
]);

export const PROMOTION_EVIDENCE_V3_ENVELOPE_KEYS = Object.freeze([
  "version",
  "type",
  "statement",
  "statement_hash",
  "signature_algorithm",
  "signer_key_fingerprint",
  "signature",
]);

const DOMAIN = Buffer.from(PROMOTION_EVIDENCE_V3_SIGNATURE_DOMAIN, "utf8");
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const SOURCE_COMMIT = /^[0-9a-f]{40}$/u;
const ENVIRONMENT = /^(?:staging|production)$/u;
const IMAGE_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const KEY_FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/u;
const VALIDATION_OPTION_KEYS = Object.freeze(["allowExpired", "allowFuture", "now", "maxTtlMs"]);

export class PromotionEvidenceV3Error extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "PromotionEvidenceV3Error";
    this.code = code;
  }
}

/**
 * Normalize the complete v3 statement.  This statement is deployment-wide:
 * it deliberately has no organization/tenant binding, while still binding
 * the deployment identity and every release/approval digest required by the
 * platform promotion policy.
 */
export function normalizePromotionEvidenceV3Statement(input, options = {}) {
  try {
    assertDataTree(input);
    const validation = normalizeValidationOptions(options);
    exactObject(input, PROMOTION_EVIDENCE_V3_STATEMENT_KEYS);

    const value = {
      version: exact(input.version, PROMOTION_EVIDENCE_V3_VERSION),
      type: exact(input.type, PROMOTION_EVIDENCE_V3_TYPE),
      promotion_id: pattern(input.promotion_id, UUID),
      deployment_id: pattern(input.deployment_id, IDENTIFIER),
      environment: pattern(input.environment, ENVIRONMENT),
      candidate_id: pattern(input.candidate_id, /^release-pkg-sha256-v1-[0-9a-f]{64}$/u),
      source_commit: pattern(input.source_commit, SOURCE_COMMIT),
      source_tree: pattern(input.source_tree, SOURCE_COMMIT),
      product_pkg_sha256: pattern(input.product_pkg_sha256, SHA256),
      image_digest: pattern(input.image_digest, IMAGE_DIGEST),
      sbom_sha256: pattern(input.sbom_sha256, SHA256),
      qualification_report_digests: normalizeQualificationReportDigests(input.qualification_report_digests),
      release_manifest_schema_version: exact(input.release_manifest_schema_version, PROMOTION_EVIDENCE_V3_RELEASE_MANIFEST_SCHEMA_VERSION),
      release_manifest_sha256: pattern(input.release_manifest_sha256, SHA256),
      platform_approval_id: pattern(input.platform_approval_id, UUID),
      platform_approval_digest: pattern(input.platform_approval_digest, SHA256),
      approval_state: exact(input.approval_state, "approved"),
      purpose: exact(input.purpose, PROMOTION_EVIDENCE_V3_PURPOSE),
      protocol_version: exact(input.protocol_version, PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION),
      signing_version: exact(input.signing_version, PROMOTION_EVIDENCE_V3_SIGNING_VERSION),
      lifecycle_version: positiveInteger(input.lifecycle_version),
      key_id: pattern(input.key_id, IDENTIFIER),
      key_version: positiveInteger(input.key_version),
      issued_at: timestamp(input.issued_at),
      expires_at: timestamp(input.expires_at),
    };

    try {
      assertReleaseCandidateIdMatchesProduct(value.candidate_id, value.product_pkg_sha256);
    } catch {
      fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.BINDING);
    }

    const issuedAtMs = Date.parse(value.issued_at);
    const expiresAtMs = Date.parse(value.expires_at);
    if (expiresAtMs <= issuedAtMs || expiresAtMs - issuedAtMs > validation.maxTtlMs) {
      fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
    }
    if (!validation.allowFuture && (validation.nowMs === undefined || validation.nowMs < issuedAtMs)) {
      fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.NOT_YET_VALID);
    }
    if (!validation.allowExpired && (validation.nowMs === undefined || validation.nowMs >= expiresAtMs)) {
      fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.EXPIRED);
    }

    const bytes = Buffer.from(canonicalJson(value), "utf8");
    if (bytes.length > PROMOTION_EVIDENCE_V3_MAX_SIGNING_BYTES) fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
    return deepFreeze(value);
  } catch (error) {
    if (error instanceof PromotionEvidenceV3Error) throw error;
    throw new PromotionEvidenceV3Error(PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
  }
}

export function canonicalizePromotionEvidenceV3Statement(statement, options = {}) {
  return canonicalJson(normalizePromotionEvidenceV3Statement(statement, options));
}

export function promotionEvidenceV3StatementBytes(statement, options = {}) {
  return Buffer.from(canonicalizePromotionEvidenceV3Statement(statement, options), "utf8");
}

export function promotionEvidenceV3SigningData(statement, options = {}) {
  const bytes = Buffer.concat([DOMAIN, promotionEvidenceV3StatementBytes(statement, options)]);
  if (bytes.length > PROMOTION_EVIDENCE_V3_MAX_SIGNING_BYTES) fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
  return bytes;
}

export function promotionEvidenceV3StatementHash(statement, options = {}) {
  return crypto.createHash("sha256").update(promotionEvidenceV3StatementBytes(statement, options)).digest("hex");
}

export function normalizePromotionEvidenceV3(input, options = {}) {
  try {
    assertDataTree(input);
    exactObject(input, PROMOTION_EVIDENCE_V3_ENVELOPE_KEYS);
    const statement = normalizePromotionEvidenceV3Statement(input.statement, options);
    if (input.version !== PROMOTION_EVIDENCE_V3_VERSION || input.type !== PROMOTION_EVIDENCE_V3_TYPE) {
      fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
    }
    if (typeof input.statement_hash !== "string" || !SHA256.test(input.statement_hash)
      || input.statement_hash !== promotionEvidenceV3StatementHash(statement)) {
      fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.SIGNATURE);
    }
    if (input.signature_algorithm !== PROMOTION_EVIDENCE_V3_ALGORITHM) fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.OUTPUT);
    if (typeof input.signer_key_fingerprint !== "string" || !KEY_FINGERPRINT.test(input.signer_key_fingerprint)) {
      fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.OUTPUT);
    }
    canonicalSignatureV3(input.signature);
    return deepFreeze({
      version: PROMOTION_EVIDENCE_V3_VERSION,
      type: PROMOTION_EVIDENCE_V3_TYPE,
      statement,
      statement_hash: input.statement_hash,
      signature_algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
      signer_key_fingerprint: input.signer_key_fingerprint,
      signature: input.signature,
    });
  } catch (error) {
    if (error instanceof PromotionEvidenceV3Error) throw error;
    throw new PromotionEvidenceV3Error(PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
  }
}

export function canonicalizePromotionEvidenceV3(input, options = {}) {
  return canonicalJson(normalizePromotionEvidenceV3(input, options));
}

export function parseCanonicalPromotionEvidenceV3(input, options = {}) {
  const bytes = Buffer.isBuffer(input) || input instanceof Uint8Array
    ? Buffer.from(input)
    : typeof input === "string" ? Buffer.from(input, "utf8") : fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.NONCANONICAL);
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.NONCANONICAL);
  }
  let value;
  try { value = JSON.parse(text); } catch { fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.NONCANONICAL); }
  const normalized = normalizePromotionEvidenceV3(value, options);
  if (canonicalJson(normalized) !== text) fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.NONCANONICAL);
  return normalized;
}

export function canonicalSignatureV3(value) {
  if (typeof value !== "string" || !SIGNATURE.test(value)) fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.OUTPUT);
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 64 || bytes.toString("base64url") !== value) fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.OUTPUT);
  return bytes;
}

export function parsePromotionEvidenceV3PublicKey(value, code = PROMOTION_EVIDENCE_V3_ERROR_CODES.CONFIG) {
  try {
    if (value?.type === "private" || (typeof value === "string" && /PRIVATE\s+KEY/iu.test(value))) fail(code);
    const key = value?.type === "public" ? value : crypto.createPublicKey(value);
    if (key.type !== "public" || key.asymmetricKeyType !== PROMOTION_EVIDENCE_V3_ALGORITHM) fail(code);
    return key;
  } catch (error) {
    if (error instanceof PromotionEvidenceV3Error) throw error;
    throw new PromotionEvidenceV3Error(code);
  }
}

export function promotionEvidenceV3PublicKeyFingerprint(value) {
  const key = parsePromotionEvidenceV3PublicKey(value);
  return `SHA256:${crypto.createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("base64url")}`;
}

function normalizeQualificationReportDigests(value) {
  if (!Array.isArray(value)
    || Object.getPrototypeOf(value) !== Array.prototype
    || value.length < PROMOTION_EVIDENCE_V3_MIN_QUALIFICATION_REPORT_DIGESTS
    || value.length > PROMOTION_EVIDENCE_V3_MAX_QUALIFICATION_REPORT_DIGESTS) {
    fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
  }
  assertArrayData(value);
  let previous;
  const seen = new Set();
  const normalized = value.map((digest) => {
    const result = pattern(digest, SHA256);
    if (seen.has(result)) fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.ORDERING);
    if (previous !== undefined && previous >= result) fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.ORDERING);
    previous = result;
    seen.add(result);
    return result;
  });
  return Object.freeze(normalized);
}

function normalizeValidationOptions(value) {
  if (!plainObject(value)) fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.CONFIG);
  const actual = Reflect.ownKeys(value);
  if (actual.some((key) => typeof key !== "string" || !VALIDATION_OPTION_KEYS.includes(key))) {
    fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.CONFIG);
  }
  for (const key of actual) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.CONFIG);
  }
  const allowExpired = value.allowExpired ?? true;
  const allowFuture = value.allowFuture ?? true;
  if (typeof allowExpired !== "boolean" || typeof allowFuture !== "boolean") fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.CONFIG);
  const maxTtlMs = value.maxTtlMs ?? PROMOTION_EVIDENCE_V3_MAX_TTL_MS;
  if (!Number.isSafeInteger(maxTtlMs) || maxTtlMs < 1 || maxTtlMs > PROMOTION_EVIDENCE_V3_MAX_TTL_MS) {
    fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.CONFIG);
  }
  const nowMs = value.now === undefined ? undefined : exactNow(value.now);
  return Object.freeze({ allowExpired, allowFuture, maxTtlMs, nowMs });
}

function exactObject(value, keys) {
  if (!plainObject(value)) fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) {
    fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.UNKNOWN_FIELD);
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
  }
}

function assertArrayData(value) {
  const actual = Reflect.ownKeys(value).filter((key) => key !== "length");
  if (actual.length !== value.length || actual.some((key, index) => key !== String(index))) {
    fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
  }
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || descriptor.enumerable !== true || !("value" in descriptor)) fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
  }
}

function assertDataTree(value, seen = new Set()) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
    return;
  }
  if (typeof value !== "object") fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
  if (seen.has(value) || (!plainObject(value) && !Array.isArray(value))) fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
  seen.add(value);
  if (Array.isArray(value)) assertArrayData(value);
  const keys = Array.isArray(value) ? Reflect.ownKeys(value).filter((key) => key !== "length") : Reflect.ownKeys(value);
  for (const key of keys) {
    if (typeof key !== "string") fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.UNKNOWN_FIELD);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
    assertDataTree(descriptor.value, seen);
  }
  seen.delete(value);
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exact(value, expected) {
  if (value !== expected) fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
  return expected;
}

function pattern(value, expression) {
  if (typeof value !== "string" || !expression.test(value)) fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
  return value;
}

function positiveInteger(value) {
  if (!Number.isSafeInteger(value) || value < 1) fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
  return value;
}

function timestamp(value) {
  if (typeof value !== "string" || !TIMESTAMP.test(value) || new Date(value).toISOString() !== value) {
    fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
  }
  return value;
}

function exactNow(value) {
  const result = value instanceof Date ? value.getTime() : value;
  if (!Number.isSafeInteger(result) || result < 0) fail(PROMOTION_EVIDENCE_V3_ERROR_CODES.CONFIG);
  return result;
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function fail(code) {
  throw new PromotionEvidenceV3Error(code);
}
