import crypto from "node:crypto";

import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import {
  assertReleaseCandidateIdMatchesProduct,
  RELEASE_MANIFEST_SCHEMA_VERSION,
} from "../../../lib/release-candidate-identity.mjs";
import { SIGNER_PURPOSE_REGISTRY } from "./signer-purpose-registry.mjs";

const REGISTRY_ENTRY = SIGNER_PURPOSE_REGISTRY.promotion_evidence;

// v1 is a frozen, schema-only pre-production envelope for release-manifest v3.
// The first implemented managed authority is v2 and binds release-manifest v4
// plus the immutable candidate identity.
export const PROMOTION_EVIDENCE_VERSION = 2;
export const PROMOTION_EVIDENCE_TYPE = "agentpass.promotion-evidence";
export const PROMOTION_EVIDENCE_PURPOSE = REGISTRY_ENTRY.purpose;
export const PROMOTION_EVIDENCE_SIGNATURE_DOMAIN = REGISTRY_ENTRY.domain;
export const PROMOTION_EVIDENCE_ALGORITHM = REGISTRY_ENTRY.managed_algorithm;
export const PROMOTION_EVIDENCE_PROTOCOL_VERSION = REGISTRY_ENTRY.protocol_version;
export const PROMOTION_EVIDENCE_SIGNING_VERSION = REGISTRY_ENTRY.signing_version;
export const PROMOTION_EVIDENCE_RELEASE_MANIFEST_VERSION = RELEASE_MANIFEST_SCHEMA_VERSION;
export const PROMOTION_EVIDENCE_MAX_TTL_MS = 60 * 60 * 1_000;
export const PROMOTION_EVIDENCE_MAX_SIGNING_BYTES = 128 * 1024;

export const PROMOTION_EVIDENCE_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_PROMOTION_EVIDENCE_CONFIG",
  INPUT: "ERR_PROMOTION_EVIDENCE_INPUT",
  UNKNOWN_FIELD: "ERR_PROMOTION_EVIDENCE_UNKNOWN_FIELD",
  NONCANONICAL: "ERR_PROMOTION_EVIDENCE_NONCANONICAL",
  PROVIDER: "ERR_PROMOTION_EVIDENCE_PROVIDER",
  OUTPUT: "ERR_PROMOTION_EVIDENCE_OUTPUT",
  SIGNATURE: "ERR_PROMOTION_EVIDENCE_SIGNATURE",
  EXPIRED: "ERR_PROMOTION_EVIDENCE_EXPIRED",
  NOT_YET_VALID: "ERR_PROMOTION_EVIDENCE_NOT_YET_VALID",
  BINDING: "ERR_PROMOTION_EVIDENCE_BINDING",
});

export const PROMOTION_EVIDENCE_STATEMENT_KEYS = Object.freeze([
  "version",
  "type",
  "environment",
  "candidate_id",
  "source_commit",
  "source_tree",
  "artifact_sha256",
  "release_manifest_schema_version",
  "release_manifest_sha256",
  "purpose",
  "protocol_version",
  "signing_version",
  "lifecycle_version",
  "key_id",
  "key_version",
  "issued_at",
  "expires_at",
]);

export const PROMOTION_EVIDENCE_ENVELOPE_KEYS = Object.freeze([
  "version",
  "type",
  "statement",
  "statement_hash",
  "signature_algorithm",
  "signer_key_fingerprint",
  "signature",
]);

const DOMAIN = Buffer.from(PROMOTION_EVIDENCE_SIGNATURE_DOMAIN, "utf8");
const SHA256 = /^[0-9a-f]{64}$/u;
const SOURCE_COMMIT = /^[0-9a-f]{40}$/u;
const ENVIRONMENT = /^(?:staging|production)$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const KEY_FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/u;

export class PromotionEvidenceError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "PromotionEvidenceError";
    this.code = code;
  }
}

/**
 * Normalize the exact signed statement. The release candidate ID is not an
 * opaque caller-selected label: it is derived from the product artifact
 * digest by the release-candidate-identity contract.
 */
export function normalizePromotionEvidenceStatement(input, {
  allowExpired = true,
  allowFuture = true,
  now,
  maxTtlMs = PROMOTION_EVIDENCE_MAX_TTL_MS,
} = {}) {
  try {
    assertDataTree(input);
    exactObject(input, PROMOTION_EVIDENCE_STATEMENT_KEYS);
    if (!Number.isSafeInteger(maxTtlMs) || maxTtlMs < 1 || maxTtlMs > PROMOTION_EVIDENCE_MAX_TTL_MS) {
      fail(PROMOTION_EVIDENCE_ERROR_CODES.CONFIG);
    }

    const value = {
      version: exact(input.version, PROMOTION_EVIDENCE_VERSION),
      type: exact(input.type, PROMOTION_EVIDENCE_TYPE),
      environment: pattern(input.environment, ENVIRONMENT),
      candidate_id: pattern(input.candidate_id, /^release-pkg-sha256-v1-[0-9a-f]{64}$/u),
      source_commit: pattern(input.source_commit, SOURCE_COMMIT),
      source_tree: pattern(input.source_tree, SOURCE_COMMIT),
      artifact_sha256: pattern(input.artifact_sha256, SHA256),
      release_manifest_schema_version: exact(input.release_manifest_schema_version, PROMOTION_EVIDENCE_RELEASE_MANIFEST_VERSION),
      release_manifest_sha256: pattern(input.release_manifest_sha256, SHA256),
      purpose: exact(input.purpose, PROMOTION_EVIDENCE_PURPOSE),
      protocol_version: exact(input.protocol_version, PROMOTION_EVIDENCE_PROTOCOL_VERSION),
      signing_version: exact(input.signing_version, PROMOTION_EVIDENCE_SIGNING_VERSION),
      lifecycle_version: positiveInteger(input.lifecycle_version),
      key_id: pattern(input.key_id, IDENTIFIER),
      key_version: positiveInteger(input.key_version),
      issued_at: timestamp(input.issued_at),
      expires_at: timestamp(input.expires_at),
    };

    try {
      assertReleaseCandidateIdMatchesProduct(value.candidate_id, value.artifact_sha256);
    } catch {
      fail(PROMOTION_EVIDENCE_ERROR_CODES.BINDING);
    }

    const issuedAtMs = Date.parse(value.issued_at);
    const expiresAtMs = Date.parse(value.expires_at);
    if (expiresAtMs <= issuedAtMs || expiresAtMs - issuedAtMs > maxTtlMs) {
      fail(PROMOTION_EVIDENCE_ERROR_CODES.INPUT);
    }
    const nowMs = now === undefined ? undefined : exactNow(now);
    if (!allowFuture && (nowMs === undefined || nowMs < issuedAtMs)) {
      fail(PROMOTION_EVIDENCE_ERROR_CODES.NOT_YET_VALID);
    }
    if (!allowExpired && (nowMs === undefined || nowMs >= expiresAtMs)) {
      fail(PROMOTION_EVIDENCE_ERROR_CODES.EXPIRED);
    }
    const bytes = Buffer.from(canonicalJson(value), "utf8");
    if (bytes.length > PROMOTION_EVIDENCE_MAX_SIGNING_BYTES) fail(PROMOTION_EVIDENCE_ERROR_CODES.INPUT);
    return deepFreeze(value);
  } catch (error) {
    if (error instanceof PromotionEvidenceError) throw error;
    throw new PromotionEvidenceError(PROMOTION_EVIDENCE_ERROR_CODES.INPUT);
  }
}

export function canonicalizePromotionEvidenceStatement(statement, options = {}) {
  return canonicalJson(normalizePromotionEvidenceStatement(statement, options));
}

export function promotionEvidenceStatementBytes(statement, options = {}) {
  return Buffer.from(canonicalizePromotionEvidenceStatement(statement, options), "utf8");
}

export function promotionEvidenceSigningData(statement, options = {}) {
  const bytes = Buffer.concat([DOMAIN, promotionEvidenceStatementBytes(statement, options)]);
  if (bytes.length > PROMOTION_EVIDENCE_MAX_SIGNING_BYTES) fail(PROMOTION_EVIDENCE_ERROR_CODES.INPUT);
  return bytes;
}

export function promotionEvidenceStatementHash(statement, options = {}) {
  return crypto.createHash("sha256").update(promotionEvidenceStatementBytes(statement, options)).digest("hex");
}

export function normalizePromotionEvidence(input, {
  allowExpired = true,
  allowFuture = true,
  now,
  maxTtlMs = PROMOTION_EVIDENCE_MAX_TTL_MS,
} = {}) {
  try {
    assertDataTree(input);
    exactObject(input, PROMOTION_EVIDENCE_ENVELOPE_KEYS);
    const statement = normalizePromotionEvidenceStatement(input.statement, { allowExpired, allowFuture, now, maxTtlMs });
    if (input.version !== PROMOTION_EVIDENCE_VERSION || input.type !== PROMOTION_EVIDENCE_TYPE) {
      fail(PROMOTION_EVIDENCE_ERROR_CODES.INPUT);
    }
    if (typeof input.statement_hash !== "string" || !SHA256.test(input.statement_hash)
      || input.statement_hash !== promotionEvidenceStatementHash(statement)) {
      fail(PROMOTION_EVIDENCE_ERROR_CODES.SIGNATURE);
    }
    if (input.signature_algorithm !== PROMOTION_EVIDENCE_ALGORITHM) fail(PROMOTION_EVIDENCE_ERROR_CODES.OUTPUT);
    if (typeof input.signer_key_fingerprint !== "string" || !KEY_FINGERPRINT.test(input.signer_key_fingerprint)) {
      fail(PROMOTION_EVIDENCE_ERROR_CODES.OUTPUT);
    }
    canonicalSignature(input.signature);
    return deepFreeze({
      version: PROMOTION_EVIDENCE_VERSION,
      type: PROMOTION_EVIDENCE_TYPE,
      statement,
      statement_hash: input.statement_hash,
      signature_algorithm: PROMOTION_EVIDENCE_ALGORITHM,
      signer_key_fingerprint: input.signer_key_fingerprint,
      signature: input.signature,
    });
  } catch (error) {
    if (error instanceof PromotionEvidenceError) throw error;
    throw new PromotionEvidenceError(PROMOTION_EVIDENCE_ERROR_CODES.INPUT);
  }
}

export function canonicalizePromotionEvidence(input, options = {}) {
  return canonicalJson(normalizePromotionEvidence(input, options));
}

export function parseCanonicalPromotionEvidence(input, options = {}) {
  const bytes = Buffer.isBuffer(input) || input instanceof Uint8Array ? Buffer.from(input) : Buffer.from(String(input), "utf8");
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail(PROMOTION_EVIDENCE_ERROR_CODES.NONCANONICAL);
  }
  let value;
  try { value = JSON.parse(text); } catch { fail(PROMOTION_EVIDENCE_ERROR_CODES.NONCANONICAL); }
  const normalized = normalizePromotionEvidence(value, options);
  if (canonicalJson(normalized) !== text) fail(PROMOTION_EVIDENCE_ERROR_CODES.NONCANONICAL);
  return normalized;
}

export function canonicalSignature(value) {
  if (typeof value !== "string" || !SIGNATURE.test(value)) fail(PROMOTION_EVIDENCE_ERROR_CODES.OUTPUT);
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 64 || bytes.toString("base64url") !== value) fail(PROMOTION_EVIDENCE_ERROR_CODES.OUTPUT);
  return bytes;
}

export function parsePromotionEvidencePublicKey(value, code = PROMOTION_EVIDENCE_ERROR_CODES.CONFIG) {
  try {
    if (value?.type === "private" || (typeof value === "string" && /PRIVATE\s+KEY/iu.test(value))) fail(code);
    const key = value?.type === "public" ? value : crypto.createPublicKey(value);
    if (key.type !== "public" || key.asymmetricKeyType !== PROMOTION_EVIDENCE_ALGORITHM) fail(code);
    return key;
  } catch (error) {
    if (error instanceof PromotionEvidenceError) throw error;
    throw new PromotionEvidenceError(code);
  }
}

export function promotionEvidencePublicKeyFingerprint(value) {
  const key = parsePromotionEvidencePublicKey(value);
  return `SHA256:${crypto.createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("base64url")}`;
}

function exactObject(value, keys) {
  if (!plainObject(value)) fail(PROMOTION_EVIDENCE_ERROR_CODES.INPUT);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) {
    fail(PROMOTION_EVIDENCE_ERROR_CODES.UNKNOWN_FIELD);
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) fail(PROMOTION_EVIDENCE_ERROR_CODES.INPUT);
  }
}

function assertDataTree(value, seen = new Set()) {
  if (value === null || typeof value !== "object") return;
  if (seen.has(value) || (!plainObject(value) && !Array.isArray(value))) fail(PROMOTION_EVIDENCE_ERROR_CODES.INPUT);
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") fail(PROMOTION_EVIDENCE_ERROR_CODES.UNKNOWN_FIELD);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) fail(PROMOTION_EVIDENCE_ERROR_CODES.INPUT);
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
  if (value !== expected) fail(PROMOTION_EVIDENCE_ERROR_CODES.INPUT);
  return expected;
}

function pattern(value, expression) {
  if (typeof value !== "string" || !expression.test(value)) fail(PROMOTION_EVIDENCE_ERROR_CODES.INPUT);
  return value;
}

function positiveInteger(value) {
  if (!Number.isSafeInteger(value) || value < 1) fail(PROMOTION_EVIDENCE_ERROR_CODES.INPUT);
  return value;
}

function timestamp(value) {
  if (typeof value !== "string" || !TIMESTAMP.test(value) || new Date(value).toISOString() !== value) {
    fail(PROMOTION_EVIDENCE_ERROR_CODES.INPUT);
  }
  return value;
}

function exactNow(value) {
  const result = value instanceof Date ? value.getTime() : value;
  if (!Number.isSafeInteger(result) || result < 0) fail(PROMOTION_EVIDENCE_ERROR_CODES.CONFIG);
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
  throw new PromotionEvidenceError(code);
}
