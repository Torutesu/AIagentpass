import crypto from "node:crypto";

import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import { SIGNER_PURPOSE_REGISTRY } from "./signer-purpose-registry.mjs";

const REGISTRY_ENTRY = SIGNER_PURPOSE_REGISTRY.audit_anchor;

export const AUDIT_ANCHOR_VERSION = 1;
export const AUDIT_ANCHOR_TYPE = "agentpass.audit-anchor";
export const AUDIT_ANCHOR_PURPOSE = REGISTRY_ENTRY.purpose;
export const AUDIT_ANCHOR_SIGNATURE_DOMAIN = REGISTRY_ENTRY.domain;
export const AUDIT_ANCHOR_ALGORITHM = REGISTRY_ENTRY.managed_algorithm;
export const AUDIT_ANCHOR_PROTOCOL_VERSION = REGISTRY_ENTRY.protocol_version;
export const AUDIT_ANCHOR_SIGNING_VERSION = REGISTRY_ENTRY.signing_version;
export const AUDIT_ANCHOR_MAX_TTL_MS = 60 * 60 * 1_000;
export const AUDIT_ANCHOR_MAX_SIGNING_BYTES = 128 * 1024;
export const AUDIT_ANCHOR_ZERO_DIGEST = "0".repeat(64);
export const AUDIT_ANCHOR_CHAINS = Object.freeze(["admin", "device", "cloud_agent"]);

export const AUDIT_ANCHOR_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_AUDIT_ANCHOR_CONFIG",
  INPUT: "ERR_AUDIT_ANCHOR_INPUT",
  UNKNOWN_FIELD: "ERR_AUDIT_ANCHOR_UNKNOWN_FIELD",
  NONCANONICAL: "ERR_AUDIT_ANCHOR_NONCANONICAL",
  PROVIDER: "ERR_AUDIT_ANCHOR_PROVIDER",
  OUTPUT: "ERR_AUDIT_ANCHOR_OUTPUT",
  SIGNATURE: "ERR_AUDIT_ANCHOR_SIGNATURE",
  EXPIRED: "ERR_AUDIT_ANCHOR_EXPIRED",
  NOT_YET_VALID: "ERR_AUDIT_ANCHOR_NOT_YET_VALID",
  BINDING: "ERR_AUDIT_ANCHOR_BINDING",
  ROLLBACK: "ERR_AUDIT_ANCHOR_ROLLBACK"
});

export const AUDIT_ANCHOR_STATEMENT_KEYS = Object.freeze([
  "version",
  "type",
  "organization_id",
  "environment",
  "chain",
  "export_id",
  "audit_position",
  "previous_audit_position",
  "root_digest",
  "previous_root_digest",
  "export_digest",
  "record_count",
  "purpose",
  "protocol_version",
  "signing_version",
  "lifecycle_version",
  "key_id",
  "key_version",
  "issued_at",
  "expires_at"
]);

export const AUDIT_ANCHOR_ENVELOPE_KEYS = Object.freeze([
  "version",
  "type",
  "statement",
  "statement_hash",
  "signature_algorithm",
  "signer_key_fingerprint",
  "signature"
]);

const DOMAIN = Buffer.from(AUDIT_ANCHOR_SIGNATURE_DOMAIN, "utf8");
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const ENVIRONMENT = /^(?:staging|production)$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/u;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;

export class AuditAnchorError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "AuditAnchorError";
    this.code = code;
  }
}

export function normalizeAuditAnchorStatement(input, {
  allowExpired = true,
  allowFuture = true,
  now,
  maxTtlMs = AUDIT_ANCHOR_MAX_TTL_MS
} = {}) {
  try {
    assertDataTree(input);
    exactObject(input, AUDIT_ANCHOR_STATEMENT_KEYS);
    if (!Number.isSafeInteger(maxTtlMs) || maxTtlMs < 1 || maxTtlMs > AUDIT_ANCHOR_MAX_TTL_MS) fail(AUDIT_ANCHOR_ERROR_CODES.CONFIG);

    const statement = {
      version: exact(input.version, AUDIT_ANCHOR_VERSION),
      type: exact(input.type, AUDIT_ANCHOR_TYPE),
      organization_id: pattern(input.organization_id, UUID),
      environment: pattern(input.environment, ENVIRONMENT),
      chain: enumeration(input.chain, AUDIT_ANCHOR_CHAINS),
      export_id: pattern(input.export_id, UUID),
      audit_position: positiveInteger(input.audit_position),
      previous_audit_position: nonNegativeInteger(input.previous_audit_position),
      root_digest: pattern(input.root_digest, DIGEST),
      previous_root_digest: pattern(input.previous_root_digest, DIGEST),
      export_digest: pattern(input.export_digest, DIGEST),
      record_count: positiveInteger(input.record_count),
      purpose: exact(input.purpose, AUDIT_ANCHOR_PURPOSE),
      protocol_version: exact(input.protocol_version, AUDIT_ANCHOR_PROTOCOL_VERSION),
      signing_version: exact(input.signing_version, AUDIT_ANCHOR_SIGNING_VERSION),
      lifecycle_version: positiveInteger(input.lifecycle_version),
      key_id: pattern(input.key_id, IDENTIFIER),
      key_version: positiveInteger(input.key_version),
      issued_at: timestamp(input.issued_at),
      expires_at: timestamp(input.expires_at)
    };

    if (statement.audit_position <= statement.previous_audit_position) fail(AUDIT_ANCHOR_ERROR_CODES.ROLLBACK);
    if (statement.record_count > statement.audit_position) fail(AUDIT_ANCHOR_ERROR_CODES.BINDING);
    if (statement.previous_audit_position === 0 && statement.previous_root_digest !== AUDIT_ANCHOR_ZERO_DIGEST) fail(AUDIT_ANCHOR_ERROR_CODES.BINDING);
    if (statement.previous_audit_position > 0 && statement.previous_root_digest === AUDIT_ANCHOR_ZERO_DIGEST) fail(AUDIT_ANCHOR_ERROR_CODES.BINDING);
    if (statement.root_digest === AUDIT_ANCHOR_ZERO_DIGEST) fail(AUDIT_ANCHOR_ERROR_CODES.BINDING);

    const issuedAtMs = Date.parse(statement.issued_at);
    const expiresAtMs = Date.parse(statement.expires_at);
    if (expiresAtMs <= issuedAtMs || expiresAtMs - issuedAtMs > maxTtlMs) fail(AUDIT_ANCHOR_ERROR_CODES.INPUT);
    const nowMs = now === undefined ? undefined : exactNow(now);
    if (!allowFuture && (nowMs === undefined || nowMs < issuedAtMs)) fail(AUDIT_ANCHOR_ERROR_CODES.NOT_YET_VALID);
    if (!allowExpired && (nowMs === undefined || nowMs >= expiresAtMs)) fail(AUDIT_ANCHOR_ERROR_CODES.EXPIRED);

    if (Buffer.byteLength(canonicalJson(statement), "utf8") > AUDIT_ANCHOR_MAX_SIGNING_BYTES) fail(AUDIT_ANCHOR_ERROR_CODES.INPUT);
    return deepFreeze(statement);
  } catch (error) {
    if (error instanceof AuditAnchorError) throw error;
    throw new AuditAnchorError(AUDIT_ANCHOR_ERROR_CODES.INPUT);
  }
}

export function canonicalizeAuditAnchorStatement(statement, options = {}) {
  return canonicalJson(normalizeAuditAnchorStatement(statement, options));
}

export function auditAnchorStatementBytes(statement, options = {}) {
  return Buffer.from(canonicalizeAuditAnchorStatement(statement, options), "utf8");
}

export function auditAnchorSigningData(statement, options = {}) {
  const bytes = Buffer.concat([DOMAIN, auditAnchorStatementBytes(statement, options)]);
  if (bytes.length > AUDIT_ANCHOR_MAX_SIGNING_BYTES) fail(AUDIT_ANCHOR_ERROR_CODES.INPUT);
  return bytes;
}

export function auditAnchorStatementHash(statement, options = {}) {
  return crypto.createHash("sha256").update(auditAnchorStatementBytes(statement, options)).digest("hex");
}

export function normalizeAuditAnchor(input, {
  allowExpired = true,
  allowFuture = true,
  now,
  maxTtlMs = AUDIT_ANCHOR_MAX_TTL_MS
} = {}) {
  try {
    assertDataTree(input);
    exactObject(input, AUDIT_ANCHOR_ENVELOPE_KEYS);
    if (input.version !== AUDIT_ANCHOR_VERSION || input.type !== AUDIT_ANCHOR_TYPE) fail(AUDIT_ANCHOR_ERROR_CODES.INPUT);
    const statement = normalizeAuditAnchorStatement(input.statement, { allowExpired, allowFuture, now, maxTtlMs });
    if (typeof input.statement_hash !== "string" || !DIGEST.test(input.statement_hash)
      || input.statement_hash !== auditAnchorStatementHash(statement)) fail(AUDIT_ANCHOR_ERROR_CODES.SIGNATURE);
    if (input.signature_algorithm !== AUDIT_ANCHOR_ALGORITHM) fail(AUDIT_ANCHOR_ERROR_CODES.OUTPUT);
    if (typeof input.signer_key_fingerprint !== "string" || !FINGERPRINT.test(input.signer_key_fingerprint)) fail(AUDIT_ANCHOR_ERROR_CODES.OUTPUT);
    canonicalSignature(input.signature);
    return deepFreeze({
      version: AUDIT_ANCHOR_VERSION,
      type: AUDIT_ANCHOR_TYPE,
      statement,
      statement_hash: input.statement_hash,
      signature_algorithm: AUDIT_ANCHOR_ALGORITHM,
      signer_key_fingerprint: input.signer_key_fingerprint,
      signature: input.signature
    });
  } catch (error) {
    if (error instanceof AuditAnchorError) throw error;
    throw new AuditAnchorError(AUDIT_ANCHOR_ERROR_CODES.INPUT);
  }
}

export function canonicalizeAuditAnchor(input, options = {}) {
  return canonicalJson(normalizeAuditAnchor(input, options));
}

export function parseCanonicalAuditAnchor(input, options = {}) {
  const bytes = Buffer.isBuffer(input) || input instanceof Uint8Array ? Buffer.from(input) : Buffer.from(String(input), "utf8");
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { fail(AUDIT_ANCHOR_ERROR_CODES.NONCANONICAL); }
  let value;
  try { value = JSON.parse(text); } catch { fail(AUDIT_ANCHOR_ERROR_CODES.NONCANONICAL); }
  const normalized = normalizeAuditAnchor(value, options);
  if (canonicalJson(normalized) !== text) fail(AUDIT_ANCHOR_ERROR_CODES.NONCANONICAL);
  return normalized;
}

export function canonicalSignature(value) {
  if (typeof value !== "string" || !SIGNATURE.test(value)) fail(AUDIT_ANCHOR_ERROR_CODES.OUTPUT);
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 64 || bytes.toString("base64url") !== value) fail(AUDIT_ANCHOR_ERROR_CODES.OUTPUT);
  return bytes;
}

export function parseAuditAnchorPublicKey(value, code = AUDIT_ANCHOR_ERROR_CODES.CONFIG) {
  try {
    if (value?.type === "private" || (typeof value === "string" && /PRIVATE\s+KEY/iu.test(value))) fail(code);
    const key = value?.type === "public" ? value : crypto.createPublicKey(value);
    if (key.type !== "public" || key.asymmetricKeyType !== AUDIT_ANCHOR_ALGORITHM) fail(code);
    return key;
  } catch (error) {
    if (error instanceof AuditAnchorError) throw error;
    throw new AuditAnchorError(code);
  }
}

export function auditAnchorPublicKeyFingerprint(value) {
  const key = parseAuditAnchorPublicKey(value);
  return `SHA256:${crypto.createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("base64url")}`;
}

function exactObject(value, keys) {
  if (!plainObject(value)) fail(AUDIT_ANCHOR_ERROR_CODES.INPUT);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) fail(AUDIT_ANCHOR_ERROR_CODES.UNKNOWN_FIELD);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) fail(AUDIT_ANCHOR_ERROR_CODES.INPUT);
  }
}

function assertDataTree(value, seen = new Set()) {
  if (value === null || typeof value !== "object") return;
  if (seen.has(value) || (!plainObject(value) && !Array.isArray(value))) fail(AUDIT_ANCHOR_ERROR_CODES.INPUT);
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") fail(AUDIT_ANCHOR_ERROR_CODES.UNKNOWN_FIELD);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) fail(AUDIT_ANCHOR_ERROR_CODES.INPUT);
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
  if (value !== expected) fail(AUDIT_ANCHOR_ERROR_CODES.INPUT);
  return expected;
}

function pattern(value, expression) {
  if (typeof value !== "string" || !expression.test(value)) fail(AUDIT_ANCHOR_ERROR_CODES.INPUT);
  return value;
}

function enumeration(value, allowed) {
  if (!allowed.includes(value)) fail(AUDIT_ANCHOR_ERROR_CODES.INPUT);
  return value;
}

function positiveInteger(value) {
  if (!Number.isSafeInteger(value) || value < 1) fail(AUDIT_ANCHOR_ERROR_CODES.INPUT);
  return value;
}

function nonNegativeInteger(value) {
  if (!Number.isSafeInteger(value) || value < 0) fail(AUDIT_ANCHOR_ERROR_CODES.INPUT);
  return value;
}

function timestamp(value) {
  if (typeof value !== "string" || !TIMESTAMP.test(value) || new Date(value).toISOString() !== value) fail(AUDIT_ANCHOR_ERROR_CODES.INPUT);
  return value;
}

function exactNow(value) {
  const result = value instanceof Date ? value.getTime() : value;
  if (!Number.isSafeInteger(result) || result < 0) fail(AUDIT_ANCHOR_ERROR_CODES.CONFIG);
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
  throw new AuditAnchorError(code);
}
