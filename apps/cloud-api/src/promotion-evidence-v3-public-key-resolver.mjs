import crypto from "node:crypto";

import {
  PROMOTION_EVIDENCE_V3_ALGORITHM,
  PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
  PROMOTION_EVIDENCE_V3_PURPOSE,
  PROMOTION_EVIDENCE_V3_SIGNATURE_DOMAIN,
  PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
  PROMOTION_EVIDENCE_V3_TYPE,
  PROMOTION_EVIDENCE_V3_VERSION,
  parsePromotionEvidenceV3PublicKey,
  promotionEvidenceV3PublicKeyFingerprint,
} from "./promotion-evidence-v3-statement.mjs";
import { parseManagedSignerKeyLifecycleSnapshot } from "./managed-signer-key-lifecycle.mjs";

const INPUT_KEYS = Object.freeze([
  "purpose",
  "algorithm",
  "protocol_version",
  "signing_version",
  "key_id",
  "key_version",
  "lifecycle_version",
  "signer_key_fingerprint",
]);
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const RAW_FINGERPRINT = /^[0-9a-f]{64}$/u;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const PRIVATE_FIELD = /(?:private(?:[_ -]?key|[_ -]?material)?|secret|password|credential|authorization|bearer|cookie|token|diagnostic|debug|trace|pem)/iu;

export const PROMOTION_EVIDENCE_V3_PUBLIC_KEY_RESOLVER_ERROR_CODE = "ERR_PROMOTION_EVIDENCE_V3_HISTORICAL_KEY";

export class PromotionEvidenceV3PublicKeyResolverError extends Error {
  constructor() {
    super("historical promotion evidence v3 key is unavailable");
    this.name = "PromotionEvidenceV3PublicKeyResolverError";
    this.code = PROMOTION_EVIDENCE_V3_PUBLIC_KEY_RESOLVER_ERROR_CODE;
  }
}

/**
 * Resolve v3 public verification material from the durable purpose-specific
 * lifecycle. The resolver never accepts a public key from the caller and
 * never exposes provider or private-key material.
 */
export function createPromotionEvidenceV3PublicKeyResolver(options = {}) {
  if (!plainRecord(options) || !hasAllowedKeys(options, ["repository", "now"]) || !plainRecord(options.repository)
    || !hasExactKeys(options.repository, ["snapshot"]) || typeof options.repository.snapshot !== "function") {
    throw new TypeError("promotion evidence v3 lifecycle repository is invalid");
  }
  const { repository, now = () => Date.now() } = options;
  if (typeof now !== "function") throw new TypeError("promotion evidence v3 lifecycle clock is invalid");
  readNow(now);

  return async function resolvePromotionEvidenceV3PublicKey(input = {}) {
    const values = normalizeInput(input);
    const currentNow = readNow(now);
    let snapshot;
    try { snapshot = await repository.snapshot(); } catch { fail(); }
    snapshot = validateSnapshot(snapshot, values);

    const matches = snapshot.keys.filter((key) => key?.key_id === values.key_id && key?.key_version === values.key_version);
    if (matches.length !== 1) fail();
    const key = matches[0];
    if (!["active", "retiring"].includes(key.state) || !plainRecord(key)
      || key.purpose !== PROMOTION_EVIDENCE_V3_PURPOSE
      || key.algorithm !== PROMOTION_EVIDENCE_V3_ALGORITHM
      || !Number.isSafeInteger(key.key_version) || key.key_version < 1
      || typeof key.public_key !== "string"
      || typeof key.public_key_fingerprint !== "string" || !RAW_FINGERPRINT.test(key.public_key_fingerprint)) fail();
    if (key.state === "retiring"
      && (typeof key.verification_until !== "string" || !validIso(key.verification_until)
        || Date.parse(key.verification_until) <= currentNow)) fail();
    let publicKey;
    try { publicKey = parsePromotionEvidenceV3PublicKey(key.public_key, "ERR_PROMOTION_EVIDENCE_V3_HISTORICAL_KEY"); } catch { fail(); }
    const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const rawFingerprint = crypto.createHash("sha256")
      .update(publicKey.export({ type: "spki", format: "der" }))
      .digest("hex");
    const protocolFingerprint = promotionEvidenceV3PublicKeyFingerprint(publicKey);
    if (pem !== key.public_key || rawFingerprint !== key.public_key_fingerprint
      || protocolFingerprint !== values.signer_key_fingerprint) fail();

    return Object.freeze({
      version: PROMOTION_EVIDENCE_V3_VERSION,
      type: PROMOTION_EVIDENCE_V3_TYPE,
      purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
      domain: PROMOTION_EVIDENCE_V3_SIGNATURE_DOMAIN,
      protocol_version: PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
      signing_version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
      algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
      key_id: values.key_id,
      key_version: values.key_version,
      lifecycle_version: values.lifecycle_version,
      public_key: pem,
      public_key_fingerprint: protocolFingerprint,
    });
  };
}

function normalizeInput(value) {
  if (!plainRecord(value)) fail();
  exactKeys(value, INPUT_KEYS);
  if (value.purpose !== PROMOTION_EVIDENCE_V3_PURPOSE
    || value.algorithm !== PROMOTION_EVIDENCE_V3_ALGORITHM
    || value.protocol_version !== PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION
    || value.signing_version !== PROMOTION_EVIDENCE_V3_SIGNING_VERSION
    || typeof value.key_id !== "string" || !KEY_ID.test(value.key_id)
    || !Number.isSafeInteger(value.key_version) || value.key_version < 1
    || !Number.isSafeInteger(value.lifecycle_version) || value.lifecycle_version < 1
    || !canonicalFingerprint(value.signer_key_fingerprint)) fail();
  return value;
}

function validateSnapshot(snapshot, values) {
  try { assertDataTree(snapshot); } catch { fail(); }
  if (!plainRecord(snapshot) || !exactKeys(snapshot, ["algorithm", "keys", "purpose", "version"])
    || snapshot.purpose !== PROMOTION_EVIDENCE_V3_PURPOSE
    || snapshot.algorithm !== PROMOTION_EVIDENCE_V3_ALGORITHM
    || !Number.isSafeInteger(snapshot.version) || snapshot.version < values.lifecycle_version
    || !Array.isArray(snapshot.keys)) fail();
  let normalized;
  try {
    normalized = parseManagedSignerKeyLifecycleSnapshot(snapshot, {
      purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
      algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
    });
  } catch { fail(); }
  const ids = new Set();
  const versions = new Set();
  const fingerprints = new Set();
  for (const key of normalized.keys) {
    if (ids.has(key.key_id) || versions.has(key.key_version) || fingerprints.has(key.public_key_fingerprint)) fail();
    ids.add(key.key_id);
    versions.add(key.key_version);
    fingerprints.add(key.public_key_fingerprint);
  }
  return normalized;
}

function exactKeys(value, expected) {
  const actual = Reflect.ownKeys(value);
  if (actual.length !== expected.length || actual.some((key) => typeof key !== "string" || !expected.includes(key))) fail();
  for (const key of expected) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !("value" in descriptor)) fail();
  }
  return true;
}

function hasExactKeys(value, expected) {
  const actual = Reflect.ownKeys(value);
  if (actual.length !== expected.length || actual.some((key) => typeof key !== "string" || !expected.includes(key))) return false;
  return expected.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && "value" in descriptor;
  });
}

function hasAllowedKeys(value, allowed) {
  const actual = Reflect.ownKeys(value);
  return actual.every((key) => typeof key === "string" && allowed.includes(key))
    && actual.every((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor?.enumerable === true && "value" in descriptor;
    });
}

function canonicalFingerprint(value) {
  if (typeof value !== "string" || !FINGERPRINT.test(value)) return false;
  const encoded = value.slice("SHA256:".length);
  try {
    const bytes = Buffer.from(encoded, "base64url");
    return bytes.length === 32 && bytes.toString("base64url") === encoded;
  } catch {
    return false;
  }
}

function readNow(clock) {
  let value;
  try { value = clock(); } catch { fail(); }
  const result = value instanceof Date ? value.getTime() : value;
  if (!Number.isSafeInteger(result) || result < 0) fail();
  return result;
}

function validIso(value) {
  return ISO.test(value) && Number.isFinite(Date.parse(value)) && new Date(Date.parse(value)).toISOString() === value;
}

function plainRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype) return false;
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !("value" in descriptor)) return false;
  }
  return true;
}

function assertDataTree(value, seen = new Set()) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0)) fail();
    return;
  }
  if (typeof value !== "object" || seen.has(value)) fail();
  const array = Array.isArray(value);
  if (array ? Object.getPrototypeOf(value) !== Array.prototype : Object.getPrototypeOf(value) !== Object.prototype) fail();
  if (array) {
    const keys = Reflect.ownKeys(value);
    if (keys.length !== value.length + 1 || !keys.includes("length")
      || keys.some((key) => key !== "length" && (typeof key !== "string" || !/^\d+$/u.test(key) || Number(key) >= value.length))) fail();
  }
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) {
    if (array && key === "length") continue;
    if (typeof key !== "string" || PRIVATE_FIELD.test(key) || key === "__proto__" || key === "constructor" || key === "prototype") fail();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !("value" in descriptor)) fail();
    assertDataTree(descriptor.value, seen);
  }
  seen.delete(value);
}

function fail() { throw new PromotionEvidenceV3PublicKeyResolverError(); }

export default createPromotionEvidenceV3PublicKeyResolver;
