import crypto from "node:crypto";

import {
  AUDIT_ANCHOR_ALGORITHM,
  AUDIT_ANCHOR_ERROR_CODES,
  AUDIT_ANCHOR_MAX_TTL_MS,
  AUDIT_ANCHOR_PROTOCOL_VERSION,
  AUDIT_ANCHOR_PURPOSE,
  AUDIT_ANCHOR_SIGNATURE_DOMAIN,
  AUDIT_ANCHOR_SIGNING_VERSION,
  AUDIT_ANCHOR_TYPE,
  AUDIT_ANCHOR_VERSION,
  auditAnchorPublicKeyFingerprint,
  auditAnchorSigningData,
  auditAnchorStatementHash,
  canonicalSignature,
  normalizeAuditAnchorStatement,
  parseAuditAnchorPublicKey,
  AuditAnchorError
} from "./audit-anchor-statement.mjs";

const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const MAX_SIGNATURE_TIMEOUT_MS = 30_000;
const DEFAULT_SIGNATURE_TIMEOUT_MS = 5_000;
const HOSTED_OPTION_KEYS = Object.freeze([
  "keyId", "keyVersion", "lifecycleVersion", "maxTtlMs", "now", "provider", "publicKey", "timeoutMs"
]);

/**
 * Purpose-specific hosted signing boundary for audit anchors.
 *
 * The adapter accepts only a public verification key and a provider with the
 * fixed audit-anchor metadata/sign methods. It never accepts a private key,
 * arbitrary signing bytes, or a caller-selected purpose/version.
 */
export function createHostedAuditAnchorSigner(options = {}) {
  if (!plainObject(options) || !sameKeys(options, HOSTED_OPTION_KEYS.filter((key) => Object.hasOwn(options, key)))) {
    throw signerError(AUDIT_ANCHOR_ERROR_CODES.CONFIG);
  }
  const {
    provider,
    keyId,
    keyVersion,
    lifecycleVersion,
    publicKey,
    timeoutMs = DEFAULT_SIGNATURE_TIMEOUT_MS,
    maxTtlMs = AUDIT_ANCHOR_MAX_TTL_MS,
    now = () => Date.now()
  } = options;
  const pinned = validateConfiguration({ provider, keyId, keyVersion, lifecycleVersion, publicKey, timeoutMs, maxTtlMs, now });
  let metadataPin;

  async function publicKeyMetadata(options = {}) {
    const signal = normalizeSignOptions(options);
    let value;
    try {
      value = await deadline(provider.publicKeyMetadata({
        algorithm: AUDIT_ANCHOR_ALGORITHM,
        key_id: keyId,
        purpose: AUDIT_ANCHOR_PURPOSE,
        version: AUDIT_ANCHOR_SIGNING_VERSION,
        ...(signal === undefined ? {} : { signal })
      }), timeoutMs);
    } catch (error) {
      if (error instanceof AuditAnchorError) throw error;
      throw signerError(AUDIT_ANCHOR_ERROR_CODES.PROVIDER);
    }

    try {
      if (!plainObject(value) || !sameKeys(value, ["algorithm", "key_id", "public_key"])
        || value.algorithm !== AUDIT_ANCHOR_ALGORITHM || value.key_id !== keyId) {
        throw new Error("invalid provider metadata");
      }
      const received = parseAuditAnchorPublicKey(value.public_key, AUDIT_ANCHOR_ERROR_CODES.OUTPUT);
      const receivedPem = received.export({ type: "spki", format: "pem" }).toString();
      const receivedFingerprint = auditAnchorPublicKeyFingerprint(received);
      if (receivedFingerprint !== pinned.fingerprint || receivedPem !== pinned.publicKeyPem) {
        throw new Error("provider key does not match pinned key");
      }
      if (metadataPin && (metadataPin.public_key_fingerprint !== receivedFingerprint || metadataPin.public_key !== receivedPem)) {
        throw new Error("provider key changed");
      }
      metadataPin = Object.freeze({ public_key: receivedPem, public_key_fingerprint: receivedFingerprint });
      return Object.freeze({
        version: AUDIT_ANCHOR_VERSION,
        type: AUDIT_ANCHOR_TYPE,
        purpose: AUDIT_ANCHOR_PURPOSE,
        domain: AUDIT_ANCHOR_SIGNATURE_DOMAIN,
        protocol_version: AUDIT_ANCHOR_PROTOCOL_VERSION,
        signing_version: AUDIT_ANCHOR_SIGNING_VERSION,
        algorithm: AUDIT_ANCHOR_ALGORITHM,
        key_id: keyId,
        key_version: keyVersion,
        lifecycle_version: lifecycleVersion,
        public_key: receivedPem,
        public_key_fingerprint: receivedFingerprint
      });
    } catch (error) {
      if (error instanceof AuditAnchorError) throw error;
      throw signerError(AUDIT_ANCHOR_ERROR_CODES.OUTPUT);
    }
  }

  async function signAuditAnchor(statement, options = {}) {
    const signal = normalizeSignOptions(options);
    let current;
    try { current = normalizeNow(now()); }
    catch { throw signerError(AUDIT_ANCHOR_ERROR_CODES.CONFIG); }
    const normalized = normalizeAuditAnchorStatement(statement, {
      now: current,
      allowExpired: false,
      allowFuture: false,
      maxTtlMs
    });
    if (normalized.key_id !== keyId || normalized.key_version !== keyVersion || normalized.lifecycle_version !== lifecycleVersion) {
      throw signerError(AUDIT_ANCHOR_ERROR_CODES.BINDING);
    }

    const metadata = await publicKeyMetadata({ ...(signal === undefined ? {} : { signal }) });
    const signingBytes = auditAnchorSigningData(normalized);
    let output;
    try {
      output = await deadline(provider.sign({
        algorithm: AUDIT_ANCHOR_ALGORITHM,
        bytes: Buffer.from(signingBytes),
        key_id: keyId,
        purpose: AUDIT_ANCHOR_PURPOSE,
        version: AUDIT_ANCHOR_SIGNING_VERSION,
        ...(signal === undefined ? {} : { signal })
      }), timeoutMs);
    } catch (error) {
      if (error instanceof AuditAnchorError) throw error;
      throw signerError(AUDIT_ANCHOR_ERROR_CODES.PROVIDER);
    }

    let signature;
    try { signature = Buffer.isBuffer(output) || output instanceof Uint8Array ? Buffer.from(output) : canonicalSignature(output); }
    catch { throw signerError(AUDIT_ANCHOR_ERROR_CODES.OUTPUT); }
    if (signature.length !== 64) throw signerError(AUDIT_ANCHOR_ERROR_CODES.OUTPUT);
    let valid = false;
    try { valid = crypto.verify(null, signingBytes, parseAuditAnchorPublicKey(metadata.public_key), signature); }
    catch { valid = false; }
    if (!valid) throw signerError(AUDIT_ANCHOR_ERROR_CODES.SIGNATURE);

    return Object.freeze({
      version: AUDIT_ANCHOR_VERSION,
      type: AUDIT_ANCHOR_TYPE,
      statement: normalized,
      statement_hash: auditAnchorStatementHash(normalized),
      signature_algorithm: AUDIT_ANCHOR_ALGORITHM,
      signer_key_fingerprint: metadata.public_key_fingerprint,
      signature: signature.toString("base64url")
    });
  }

  return Object.freeze({
    purpose: AUDIT_ANCHOR_PURPOSE,
    algorithm: AUDIT_ANCHOR_ALGORITHM,
    version: AUDIT_ANCHOR_SIGNING_VERSION,
    protocol_version: AUDIT_ANCHOR_PROTOCOL_VERSION,
    signing_version: AUDIT_ANCHOR_SIGNING_VERSION,
    lifecycle_version: lifecycleVersion,
    key_id: keyId,
    publicKeyMetadata,
    signAuditAnchor,
    sign: signAuditAnchor
  });
}

export const createAuditAnchorSigner = createHostedAuditAnchorSigner;

function validateConfiguration({ provider, keyId, keyVersion, lifecycleVersion, publicKey, timeoutMs, maxTtlMs, now }) {
  if (!plainObject(provider) || typeof provider.publicKeyMetadata !== "function" || typeof provider.sign !== "function"
    || Object.hasOwn(provider, "privateKey") || Object.hasOwn(provider, "private_key")
    || Object.hasOwn(provider, "secret") || Object.hasOwn(provider, "private_key_pem")
    || !KEY_ID.test(keyId ?? "") || !Number.isSafeInteger(keyVersion) || keyVersion < 1
    || !Number.isSafeInteger(lifecycleVersion) || lifecycleVersion < 1
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_SIGNATURE_TIMEOUT_MS
    || !Number.isSafeInteger(maxTtlMs) || maxTtlMs < 1 || maxTtlMs > AUDIT_ANCHOR_MAX_TTL_MS
    || typeof now !== "function") {
    throw signerError(AUDIT_ANCHOR_ERROR_CODES.CONFIG);
  }
  let key;
  try { key = parseAuditAnchorPublicKey(publicKey, AUDIT_ANCHOR_ERROR_CODES.CONFIG); }
  catch { throw signerError(AUDIT_ANCHOR_ERROR_CODES.CONFIG); }
  return Object.freeze({
    key,
    publicKeyPem: key.export({ type: "spki", format: "pem" }).toString(),
    fingerprint: auditAnchorPublicKeyFingerprint(key)
  });
}

function normalizeSignOptions(value) {
  if (!plainObject(value) || !sameKeys(value, Object.hasOwn(value, "signal") ? ["signal"] : [])) throw signerError(AUDIT_ANCHOR_ERROR_CODES.INPUT);
  if (value.signal !== undefined && (typeof AbortSignal === "undefined" || !(value.signal instanceof AbortSignal))) throw signerError(AUDIT_ANCHOR_ERROR_CODES.INPUT);
  return value.signal;
}

function normalizeNow(value) {
  const result = value instanceof Date ? value.getTime() : value;
  if (!Number.isSafeInteger(result) || result < 0) throw new Error("invalid clock");
  return result;
}

function deadline(promise, timeoutMs) {
  let timer;
  return Promise.race([
    Promise.resolve(promise),
    new Promise((_, reject) => { timer = setTimeout(() => reject(signerError(AUDIT_ANCHOR_ERROR_CODES.PROVIDER)), timeoutMs); })
  ]).finally(() => clearTimeout(timer));
}

function sameKeys(value, keys) {
  const actual = Reflect.ownKeys(value);
  return actual.every((key) => typeof key === "string") && actual.sort().join("\0") === [...keys].sort().join("\0");
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function signerError(code) {
  return new AuditAnchorError(code);
}
