import crypto from "node:crypto";

import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import {
  assertReleaseCandidateIdMatchesProduct,
  RELEASE_MANIFEST_SCHEMA_VERSION,
} from "../../../lib/release-candidate-identity.mjs";

/**
 * Immutable, deployment-scoped approval record for a platform operator.
 *
 * This is deliberately separate from organization membership and from the
 * promotion-evidence statement.  In particular, an organization_id is not a
 * valid field in this contract and platform principals are not public data.
 */
export const PLATFORM_PROMOTION_APPROVAL_VERSION = 1;
export const PLATFORM_PROMOTION_APPROVAL_TYPE = "agentpass.platform-promotion-approval";
export const PLATFORM_PROMOTION_APPROVAL_DIGEST_DOMAIN = "AgentPass-Platform-Promotion-Approval-v1\0";
export const PLATFORM_PROMOTION_APPROVAL_MAX_TTL_MS = 60 * 60 * 1_000;
export const PLATFORM_PROMOTION_APPROVAL_MAX_SIGNING_BYTES = 128 * 1024;
export const PLATFORM_PROMOTION_APPROVAL_MIN_QUALIFICATION_REPORT_DIGESTS = 1;
export const PLATFORM_PROMOTION_APPROVAL_MAX_QUALIFICATION_REPORT_DIGESTS = 16;
export const PLATFORM_PROMOTION_APPROVAL_MIN_PLATFORM_PRINCIPAL_IDS = 1;
export const PLATFORM_PROMOTION_APPROVAL_MAX_PLATFORM_PRINCIPAL_IDS = 16;
export const PLATFORM_PROMOTION_APPROVAL_MIN_AUTHORIZATION_EVIDENCE_DIGESTS = 1;
export const PLATFORM_PROMOTION_APPROVAL_MAX_AUTHORIZATION_EVIDENCE_DIGESTS = 16;
export const PLATFORM_PROMOTION_APPROVAL_RELEASE_MANIFEST_SCHEMA_VERSION = RELEASE_MANIFEST_SCHEMA_VERSION;
export const PLATFORM_PROMOTION_APPROVAL_QUORUM = Object.freeze({
  staging: 1,
  production: 2,
});

export const PLATFORM_PROMOTION_APPROVAL_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_PLATFORM_PROMOTION_APPROVAL_CONFIG",
  INPUT: "ERR_PLATFORM_PROMOTION_APPROVAL_INPUT",
  UNKNOWN_FIELD: "ERR_PLATFORM_PROMOTION_APPROVAL_UNKNOWN_FIELD",
  NONCANONICAL: "ERR_PLATFORM_PROMOTION_APPROVAL_NONCANONICAL",
  BINDING: "ERR_PLATFORM_PROMOTION_APPROVAL_BINDING",
  ORDERING: "ERR_PLATFORM_PROMOTION_APPROVAL_ORDERING",
  QUORUM: "ERR_PLATFORM_PROMOTION_APPROVAL_QUORUM",
  TTL: "ERR_PLATFORM_PROMOTION_APPROVAL_TTL",
});

export const PLATFORM_PROMOTION_APPROVAL_RECORD_KEYS = Object.freeze([
  "version",
  "type",
  "approval_id",
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
  "policy_id",
  "policy_version",
  "approval_version",
  "decision",
  "platform_principal_ids",
  "quorum",
  "authorization_evidence_digests",
  "approved_at",
  "expires_at",
]);

export const PLATFORM_PROMOTION_APPROVAL_QUORUM_KEYS = Object.freeze(["required", "satisfied"]);
export const PLATFORM_PROMOTION_APPROVAL_PUBLIC_SUMMARY_KEYS = Object.freeze([
  "approval_id",
  "deployment_id",
  "environment",
  "candidate_id",
  "policy_id",
  "policy_version",
  "approval_version",
  "quorum",
  "approved_at",
  "expires_at",
  "record_digest",
]);

const DOMAIN = Buffer.from(PLATFORM_PROMOTION_APPROVAL_DIGEST_DOMAIN, "utf8");
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const SOURCE_GIT_OBJECT = /^[0-9a-f]{40}$/u;
const CANDIDATE_ID = /^release-pkg-sha256-v1-[0-9a-f]{64}$/u;
const IMAGE_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const ENVIRONMENT = /^(?:staging|production)$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const VALIDATION_OPTION_KEYS = Object.freeze(["allowExpired", "allowFuture", "now", "maxTtlMs"]);

export class PlatformPromotionApprovalRecordError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "PlatformPromotionApprovalRecordError";
    this.code = code;
  }
}

/**
 * Normalize a complete, closed approval record.  The returned value is a
 * deeply frozen internal value; no caller-owned object is retained.
 */
export function normalizePlatformPromotionApprovalRecord(input, options = {}) {
  try {
    assertDataTree(input);
    const validation = normalizeValidationOptions(options);
    exactObject(input, PLATFORM_PROMOTION_APPROVAL_RECORD_KEYS);

    const environment = pattern(input.environment, ENVIRONMENT);
    const platformPrincipalIds = normalizeSortedIdentifiers(
      input.platform_principal_ids,
      PLATFORM_PROMOTION_APPROVAL_MIN_PLATFORM_PRINCIPAL_IDS,
      PLATFORM_PROMOTION_APPROVAL_MAX_PLATFORM_PRINCIPAL_IDS
    );

    const value = {
      version: exact(input.version, PLATFORM_PROMOTION_APPROVAL_VERSION),
      type: exact(input.type, PLATFORM_PROMOTION_APPROVAL_TYPE),
      approval_id: pattern(input.approval_id, UUID),
      deployment_id: pattern(input.deployment_id, IDENTIFIER),
      environment,
      candidate_id: pattern(input.candidate_id, CANDIDATE_ID),
      source_commit: pattern(input.source_commit, SOURCE_GIT_OBJECT),
      source_tree: pattern(input.source_tree, SOURCE_GIT_OBJECT),
      product_pkg_sha256: pattern(input.product_pkg_sha256, SHA256),
      image_digest: pattern(input.image_digest, IMAGE_DIGEST),
      sbom_sha256: pattern(input.sbom_sha256, SHA256),
      qualification_report_digests: normalizeSortedDigests(
        input.qualification_report_digests,
        PLATFORM_PROMOTION_APPROVAL_MIN_QUALIFICATION_REPORT_DIGESTS,
        PLATFORM_PROMOTION_APPROVAL_MAX_QUALIFICATION_REPORT_DIGESTS
      ),
      release_manifest_schema_version: exact(
        input.release_manifest_schema_version,
        PLATFORM_PROMOTION_APPROVAL_RELEASE_MANIFEST_SCHEMA_VERSION
      ),
      release_manifest_sha256: pattern(input.release_manifest_sha256, SHA256),
      policy_id: pattern(input.policy_id, IDENTIFIER),
      policy_version: positiveInteger(input.policy_version),
      approval_version: positiveInteger(input.approval_version),
      decision: exact(input.decision, "approved"),
      platform_principal_ids: platformPrincipalIds,
      quorum: normalizeQuorum(input.quorum, environment, platformPrincipalIds),
      authorization_evidence_digests: normalizeSortedDigests(
        input.authorization_evidence_digests,
        PLATFORM_PROMOTION_APPROVAL_MIN_AUTHORIZATION_EVIDENCE_DIGESTS,
        PLATFORM_PROMOTION_APPROVAL_MAX_AUTHORIZATION_EVIDENCE_DIGESTS
      ),
      approved_at: timestamp(input.approved_at),
      expires_at: timestamp(input.expires_at),
    };

    try {
      assertReleaseCandidateIdMatchesProduct(value.candidate_id, value.product_pkg_sha256);
    } catch {
      fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.BINDING);
    }

    if (value.authorization_evidence_digests.length !== value.platform_principal_ids.length) {
      fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.BINDING);
    }

    const approvedAtMs = Date.parse(value.approved_at);
    const expiresAtMs = Date.parse(value.expires_at);
    if (expiresAtMs <= approvedAtMs || expiresAtMs - approvedAtMs > validation.maxTtlMs) {
      fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.TTL);
    }
    if (!validation.allowFuture && (validation.nowMs === undefined || validation.nowMs < approvedAtMs)) {
      fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.TTL);
    }
    if (!validation.allowExpired && (validation.nowMs === undefined || validation.nowMs >= expiresAtMs)) {
      fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.TTL);
    }

    const bytes = Buffer.from(canonicalJson(value), "utf8");
    if (bytes.length > PLATFORM_PROMOTION_APPROVAL_MAX_SIGNING_BYTES) {
      fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);
    }
    return deepFreeze(value);
  } catch (error) {
    if (error instanceof PlatformPromotionApprovalRecordError) throw error;
    throw new PlatformPromotionApprovalRecordError(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);
  }
}

/** Return the stable RFC-8785-like JSON used by this repository's protocol. */
export function canonicalizePlatformPromotionApprovalRecord(record, options = {}) {
  return canonicalJson(normalizePlatformPromotionApprovalRecord(record, options));
}

/** Return the exact domain-separated bytes whose hash identifies the record. */
export function platformPromotionApprovalRecordSigningData(record, options = {}) {
  const bytes = Buffer.concat([
    DOMAIN,
    Buffer.from(canonicalizePlatformPromotionApprovalRecord(record, options), "utf8"),
  ]);
  if (bytes.length > PLATFORM_PROMOTION_APPROVAL_MAX_SIGNING_BYTES) {
    fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);
  }
  return bytes;
}

/** SHA-256 over the fixed domain plus the normalized canonical record. */
export function platformPromotionApprovalRecordDigest(record, options = {}) {
  return crypto.createHash("sha256")
    .update(platformPromotionApprovalRecordSigningData(record, options))
    .digest("hex");
}

/**
 * Return the only DTO allowed across a public/read-model boundary.  Principal
 * identities and authorization evidence digests are intentionally omitted.
 */
export function summarizePlatformPromotionApprovalRecord(record, options = {}) {
  const normalized = normalizePlatformPromotionApprovalRecord(record, options);
  return deepFreeze({
    approval_id: normalized.approval_id,
    deployment_id: normalized.deployment_id,
    environment: normalized.environment,
    candidate_id: normalized.candidate_id,
    policy_id: normalized.policy_id,
    policy_version: normalized.policy_version,
    approval_version: normalized.approval_version,
    quorum: normalized.quorum,
    approved_at: normalized.approved_at,
    expires_at: normalized.expires_at,
    record_digest: digestNormalized(normalized),
  });
}

/** Parse only a byte/string representation that is already canonical JSON. */
export function parseCanonicalPlatformPromotionApprovalRecord(input, options = {}) {
  let bytes;
  if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
    bytes = Buffer.from(input);
  } else if (typeof input === "string") {
    bytes = Buffer.from(input, "utf8");
  } else {
    fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.NONCANONICAL);
  }

  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.NONCANONICAL);
  }

  let value;
  try {
    value = JSON.parse(text);
  } catch {
    fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.NONCANONICAL);
  }
  const normalized = normalizePlatformPromotionApprovalRecord(value, options);
  if (canonicalJson(normalized) !== text) fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.NONCANONICAL);
  return normalized;
}

// Short aliases make the internal contract convenient without exposing a
// second, differently-shaped record API.
export const canonicalizePlatformPromotionApproval = canonicalizePlatformPromotionApprovalRecord;
export const platformPromotionApprovalDigest = platformPromotionApprovalRecordDigest;
export const publicPlatformPromotionApprovalSummary = summarizePlatformPromotionApprovalRecord;

function digestNormalized(normalized) {
  return crypto.createHash("sha256")
    .update(DOMAIN)
    .update(Buffer.from(canonicalJson(normalized), "utf8"))
    .digest("hex");
}

function normalizeQuorum(value, environment, principals) {
  exactObject(value, PLATFORM_PROMOTION_APPROVAL_QUORUM_KEYS);
  const required = positiveInteger(value.required);
  const expected = PLATFORM_PROMOTION_APPROVAL_QUORUM[environment];
  if (expected === undefined || required !== expected || value.satisfied !== true) {
    fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.QUORUM);
  }
  if (!Array.isArray(principals) || principals.length < expected) {
    fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.QUORUM);
  }
  return { required: expected, satisfied: true };
}

function normalizeSortedDigests(value, minimum, maximum) {
  if (!Array.isArray(value)
    || Object.getPrototypeOf(value) !== Array.prototype
    || value.length < minimum
    || value.length > maximum) {
    fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);
  }
  assertArrayData(value);
  return normalizeSortedValues(value, SHA256);
}

function normalizeSortedIdentifiers(value, minimum, maximum) {
  if (!Array.isArray(value)
    || Object.getPrototypeOf(value) !== Array.prototype
    || value.length < minimum
    || value.length > maximum) {
    fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);
  }
  assertArrayData(value);
  return normalizeSortedValues(value, IDENTIFIER);
}

function normalizeSortedValues(value, expression) {
  let previous;
  const seen = new Set();
  const normalized = value.map((item) => {
    const result = pattern(item, expression);
    if (seen.has(result) || (previous !== undefined && previous >= result)) {
      fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.ORDERING);
    }
    previous = result;
    seen.add(result);
    return result;
  });
  return Object.freeze(normalized);
}

function normalizeValidationOptions(value) {
  assertDataTree(value);
  if (!plainObject(value)) fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.CONFIG);
  const actual = Reflect.ownKeys(value);
  if (actual.some((key) => typeof key !== "string" || !VALIDATION_OPTION_KEYS.includes(key))) {
    fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.CONFIG);
  }
  for (const key of actual) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !("value" in descriptor)) {
      fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.CONFIG);
    }
  }
  const allowExpired = value.allowExpired ?? true;
  const allowFuture = value.allowFuture ?? true;
  if (typeof allowExpired !== "boolean" || typeof allowFuture !== "boolean") {
    fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.CONFIG);
  }
  const maxTtlMs = value.maxTtlMs ?? PLATFORM_PROMOTION_APPROVAL_MAX_TTL_MS;
  if (!Number.isSafeInteger(maxTtlMs) || maxTtlMs < 1 || maxTtlMs > PLATFORM_PROMOTION_APPROVAL_MAX_TTL_MS) {
    fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.CONFIG);
  }
  const nowMs = value.now === undefined ? undefined : exactNow(value.now);
  return Object.freeze({ allowExpired, allowFuture, maxTtlMs, nowMs });
}

function exactObject(value, keys) {
  if (!plainObject(value)) fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) {
    fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.UNKNOWN_FIELD);
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) {
      fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);
    }
  }
}

function assertArrayData(value) {
  const actual = Reflect.ownKeys(value).filter((key) => key !== "length");
  if (actual.length !== value.length || actual.some((key, index) => key !== String(index))) {
    fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);
  }
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || descriptor.enumerable !== true || !("value" in descriptor)) {
      fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);
    }
  }
}

/** Reject every non-data, non-plain value before any field is read. */
function assertDataTree(value, seen = new Set()) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);
    return;
  }
  if (typeof value !== "object") fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);
  if (seen.has(value)) fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);

  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);
    assertArrayData(value);
  } else if (Object.getPrototypeOf(value) !== Object.prototype) {
    // Null/custom prototypes are rejected as prototype-poisoned input.
    fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);
  }

  seen.add(value);
  const keys = Array.isArray(value) ? Reflect.ownKeys(value).filter((key) => key !== "length") : Reflect.ownKeys(value);
  for (const key of keys) {
    if (typeof key !== "string") fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.UNKNOWN_FIELD);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) {
      fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);
    }
    assertDataTree(descriptor.value, seen);
  }
  seen.delete(value);
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function exact(value, expected) {
  if (value !== expected) fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);
  return expected;
}

function pattern(value, expression) {
  if (typeof value !== "string" || !expression.test(value)) fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);
  return value;
}

function positiveInteger(value) {
  if (!Number.isSafeInteger(value) || value < 1) fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);
  return value;
}

function timestamp(value) {
  if (typeof value !== "string" || !TIMESTAMP.test(value) || new Date(value).toISOString() !== value) {
    fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);
  }
  return value;
}

function exactNow(value) {
  const result = value instanceof Date ? value.getTime() : value;
  if (!Number.isSafeInteger(result) || result < 0) fail(PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.CONFIG);
  return result;
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function fail(code, message = code) {
  throw new PlatformPromotionApprovalRecordError(code, message);
}
