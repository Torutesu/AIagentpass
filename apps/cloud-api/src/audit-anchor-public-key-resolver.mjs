import crypto from "node:crypto";

import {
  AUDIT_ANCHOR_ALGORITHM,
  AUDIT_ANCHOR_PROTOCOL_VERSION,
  AUDIT_ANCHOR_PURPOSE,
  AUDIT_ANCHOR_SIGNATURE_DOMAIN,
  AUDIT_ANCHOR_SIGNING_VERSION,
  AUDIT_ANCHOR_TYPE,
  AUDIT_ANCHOR_VERSION,
  auditAnchorPublicKeyFingerprint,
  parseAuditAnchorPublicKey
} from "./audit-anchor-statement.mjs";

const INPUT_KEYS = Object.freeze([
  "purpose", "algorithm", "protocol_version", "signing_version", "key_id", "key_version", "lifecycle_version"
]);
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;

export class AuditAnchorPublicKeyResolverError extends Error {
  constructor() {
    super("historical audit anchor key is unavailable");
    this.name = "AuditAnchorPublicKeyResolverError";
    this.code = "ERR_AUDIT_ANCHOR_HISTORICAL_KEY";
  }
}

/** Resolve public verification material from the durable lifecycle only. */
export function createAuditAnchorPublicKeyResolver({ repository } = {}) {
  if (!repository || typeof repository.snapshot !== "function") throw new TypeError("audit anchor lifecycle repository is invalid");

  return async function resolveAuditAnchorPublicKey(input = {}) {
    const values = normalizeInput(input);
    let snapshot;
    try { snapshot = await repository.snapshot(); }
    catch { fail(); }
    if (!plainObject(snapshot) || snapshot.purpose !== AUDIT_ANCHOR_PURPOSE
      || snapshot.algorithm !== AUDIT_ANCHOR_ALGORITHM || !Number.isSafeInteger(snapshot.version)
      || snapshot.version < values.lifecycle_version || !Array.isArray(snapshot.keys)) fail();
    const matches = snapshot.keys.filter((key) => key?.key_id === values.key_id && key?.key_version === values.key_version);
    if (matches.length !== 1 || matches[0].state === "emergency-disabled" || typeof matches[0].public_key !== "string") fail();
    const key = matches[0];
    let publicKey;
    try { publicKey = parseAuditAnchorPublicKey(key.public_key); } catch { fail(); }
    const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const rawFingerprint = crypto.createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
    if (key.purpose !== AUDIT_ANCHOR_PURPOSE || key.algorithm !== AUDIT_ANCHOR_ALGORITHM
      || key.public_key_fingerprint !== rawFingerprint) fail();
    return Object.freeze({
      version: AUDIT_ANCHOR_VERSION,
      type: AUDIT_ANCHOR_TYPE,
      purpose: AUDIT_ANCHOR_PURPOSE,
      domain: AUDIT_ANCHOR_SIGNATURE_DOMAIN,
      protocol_version: AUDIT_ANCHOR_PROTOCOL_VERSION,
      signing_version: AUDIT_ANCHOR_SIGNING_VERSION,
      algorithm: AUDIT_ANCHOR_ALGORITHM,
      key_id: values.key_id,
      key_version: values.key_version,
      lifecycle_version: values.lifecycle_version,
      public_key: pem,
      public_key_fingerprint: auditAnchorPublicKeyFingerprint(publicKey)
    });
  };
}

function normalizeInput(value) {
  if (!plainObject(value)) fail();
  const keys = Reflect.ownKeys(value).filter((key) => key !== "signal");
  if (keys.length !== INPUT_KEYS.length || keys.some((key) => typeof key !== "string" || !INPUT_KEYS.includes(key))
    || (Object.hasOwn(value, "signal") && !(value.signal instanceof AbortSignal))) fail();
  if (value.purpose !== AUDIT_ANCHOR_PURPOSE || value.algorithm !== AUDIT_ANCHOR_ALGORITHM
    || value.protocol_version !== AUDIT_ANCHOR_PROTOCOL_VERSION || value.signing_version !== AUDIT_ANCHOR_SIGNING_VERSION
    || typeof value.key_id !== "string" || !KEY_ID.test(value.key_id)
    || !Number.isSafeInteger(value.key_version) || value.key_version < 1
    || !Number.isSafeInteger(value.lifecycle_version) || value.lifecycle_version < 1) fail();
  return value;
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function fail() { throw new AuditAnchorPublicKeyResolverError(); }

export default createAuditAnchorPublicKeyResolver;
