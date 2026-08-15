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
  normalizePromotionEvidenceV3Statement,
  parsePromotionEvidenceV3PublicKey,
  promotionEvidenceV3PublicKeyFingerprint,
  promotionEvidenceV3SigningData,
  promotionEvidenceV3StatementHash,
  PromotionEvidenceV3Error,
} from "./promotion-evidence-v3-statement.mjs";

export const PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES = Object.freeze({
  ...PROMOTION_EVIDENCE_V3_ERROR_CODES,
  PROVIDER: "ERR_PROMOTION_EVIDENCE_V3_PROVIDER",
  TIMEOUT: "ERR_PROMOTION_EVIDENCE_V3_PROVIDER",
});

const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const MAX_SIGNATURE_TIMEOUT_MS = 30_000;
const DEFAULT_SIGNATURE_TIMEOUT_MS = 5_000;
const OPTION_KEYS = Object.freeze([
  "keyId", "keyVersion", "lifecycleVersion", "maxTtlMs", "now", "provider", "publicKey",
  "publicKeyFingerprint", "timeoutMs",
]);
const PROVIDER_KEYS = Object.freeze([
  "algorithm", "key_id", "key_version", "purpose", "publicKeyMetadata", "sign", "version",
]);
const METADATA_KEYS = Object.freeze(["algorithm", "key_id", "public_key"]);
const SIGNAL_KEYS = Object.freeze(["signal"]);
const PRIVATE_NAME = /(?:private|secret|password|credential|token|diagnostic|debug|trace|pem)/iu;

/**
 * Hosted-only v3 signer. The caller supplies a statement, while purpose,
 * domain, protocol, signing version, key identity, and public key are fixed
 * at construction. The provider has only two purpose-specific operations.
 */
export function createHostedPromotionEvidenceV3Signer(options = {}) {
  exactRecord(options, OPTION_KEYS, PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.CONFIG, true);
  const {
    provider,
    keyId,
    keyVersion,
    lifecycleVersion,
    publicKey,
    publicKeyFingerprint,
    timeoutMs = DEFAULT_SIGNATURE_TIMEOUT_MS,
    maxTtlMs = PROMOTION_EVIDENCE_V3_MAX_TTL_MS,
    now = () => Date.now(),
  } = options;

  const configured = validateConfiguration({
    provider, keyId, keyVersion, lifecycleVersion, publicKey, publicKeyFingerprint, timeoutMs, maxTtlMs, now,
  });
  let metadataPin;

  async function publicKeyMetadata(signOptions = {}) {
    const signal = normalizeSignalOptions(signOptions);
    let value;
    try {
      value = await deadline(provider.publicKeyMetadata({
        algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
        key_id: keyId,
        purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
        version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
        ...(signal === undefined ? {} : { signal }),
      }), timeoutMs);
    } catch {
      throw signerError(PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.PROVIDER);
    }

    try {
      exactRecord(value, METADATA_KEYS, PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.OUTPUT);
      if (value.algorithm !== PROMOTION_EVIDENCE_V3_ALGORITHM || value.key_id !== keyId) {
        throw new Error("metadata binding");
      }
      const key = parsePromotionEvidenceV3PublicKey(value.public_key, PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.OUTPUT);
      const pem = key.export({ type: "spki", format: "pem" }).toString();
      const fingerprint = promotionEvidenceV3PublicKeyFingerprint(key);
      if (pem !== configured.publicKeyPem || fingerprint !== configured.fingerprint) throw new Error("pinned key");
      if (metadataPin && (metadataPin.public_key !== pem || metadataPin.public_key_fingerprint !== fingerprint)) {
        throw new Error("rotated key");
      }
      metadataPin = Object.freeze({ public_key: pem, public_key_fingerprint: fingerprint });
      return deepFreeze({
        version: PROMOTION_EVIDENCE_V3_VERSION,
        type: PROMOTION_EVIDENCE_V3_TYPE,
        purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
        domain: PROMOTION_EVIDENCE_V3_SIGNATURE_DOMAIN,
        protocol_version: PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
        signing_version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
        algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
        key_id: keyId,
        key_version: keyVersion,
        lifecycle_version: lifecycleVersion,
        public_key: pem,
        public_key_fingerprint: fingerprint,
      });
    } catch (error) {
      if (error instanceof PromotionEvidenceV3Error) throw error;
      throw signerError(PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.OUTPUT);
    }
  }

  async function signPromotionEvidenceV3(statement, signOptions = {}) {
    const signal = normalizeSignalOptions(signOptions);
    let current;
    try {
      current = normalizeNow(now());
    } catch {
      throw signerError(PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.CONFIG);
    }
    const normalized = normalizePromotionEvidenceV3Statement(statement, {
      now: current,
      allowExpired: false,
      allowFuture: false,
      maxTtlMs,
    });
    if (normalized.key_id !== keyId || normalized.key_version !== keyVersion
      || normalized.lifecycle_version !== lifecycleVersion) {
      throw signerError(PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.BINDING);
    }

    const metadata = await publicKeyMetadata(signal === undefined ? {} : { signal });
    const signingBytes = promotionEvidenceV3SigningData(normalized, {
      now: current,
      allowExpired: false,
      allowFuture: false,
      maxTtlMs,
    });
    let output;
    try {
      output = await deadline(provider.sign({
        algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
        bytes: Buffer.from(signingBytes),
        key_id: keyId,
        purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
        version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
        ...(signal === undefined ? {} : { signal }),
      }), timeoutMs);
    } catch {
      throw signerError(PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.PROVIDER);
    }

    let signature;
    try {
      signature = normalizeProviderSignature(output);
    } catch {
      throw signerError(PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.OUTPUT);
    }
    if (signature.length !== 64) throw signerError(PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.OUTPUT);
    let valid = false;
    try {
      valid = crypto.verify(null, signingBytes, configured.key, signature);
    } catch {
      valid = false;
    }
    if (!valid) throw signerError(PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.SIGNATURE);

    return deepFreeze({
      version: PROMOTION_EVIDENCE_V3_VERSION,
      type: PROMOTION_EVIDENCE_V3_TYPE,
      statement: normalized,
      statement_hash: promotionEvidenceV3StatementHash(normalized, {
        now: current,
        allowExpired: false,
        allowFuture: false,
        maxTtlMs,
      }),
      signature_algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
      signer_key_fingerprint: metadata.public_key_fingerprint,
      signature: signature.toString("base64url"),
    });
  }

  return Object.freeze({
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
    algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
    version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
    protocol_version: PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
    signing_version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
    lifecycle_version: lifecycleVersion,
    key_id: keyId,
    key_version: keyVersion,
    public_key_fingerprint: configured.fingerprint,
    publicKeyMetadata,
    signPromotionEvidenceV3,
    signPromotionEvidence: signPromotionEvidenceV3,
    sign: signPromotionEvidenceV3,
  });
}

export const createPromotionEvidenceV3Signer = createHostedPromotionEvidenceV3Signer;
export const createHostedPromotionEvidenceSignerV3 = createHostedPromotionEvidenceV3Signer;
export const createHostedPromotionEvidenceSigner = createHostedPromotionEvidenceV3Signer;
export const createPromotionEvidenceSigner = createHostedPromotionEvidenceV3Signer;

function validateConfiguration({ provider, keyId, keyVersion, lifecycleVersion, publicKey, publicKeyFingerprint, timeoutMs, maxTtlMs, now }) {
  exactRecord(provider, PROVIDER_KEYS, PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.CONFIG, true);
  if (typeof provider.publicKeyMetadata !== "function" || typeof provider.sign !== "function"
    || !KEY_ID.test(keyId ?? "") || !Number.isSafeInteger(keyVersion) || keyVersion < 1
    || !Number.isSafeInteger(lifecycleVersion) || lifecycleVersion < 1
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_SIGNATURE_TIMEOUT_MS
    || !Number.isSafeInteger(maxTtlMs) || maxTtlMs < 1 || maxTtlMs > PROMOTION_EVIDENCE_V3_MAX_TTL_MS
    || typeof now !== "function") {
    throw signerError(PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.CONFIG);
  }
  for (const [field, expected] of [
    ["purpose", PROMOTION_EVIDENCE_V3_PURPOSE],
    ["algorithm", PROMOTION_EVIDENCE_V3_ALGORITHM],
    ["version", PROMOTION_EVIDENCE_V3_SIGNING_VERSION],
    ["key_id", keyId],
    ["key_version", keyVersion],
  ]) {
    if (provider[field] !== undefined && provider[field] !== expected) throw signerError(PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.CONFIG);
  }
  let key;
  try {
    key = parsePromotionEvidenceV3PublicKey(publicKey, PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.CONFIG);
  } catch {
    throw signerError(PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.CONFIG);
  }
  const publicKeyPem = key.export({ type: "spki", format: "pem" }).toString();
  const fingerprint = promotionEvidenceV3PublicKeyFingerprint(key);
  if (publicKeyFingerprint !== undefined && publicKeyFingerprint !== fingerprint) {
    throw signerError(PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.CONFIG);
  }
  return Object.freeze({ key, publicKeyPem, fingerprint });
}

function normalizeSignalOptions(value) {
  exactRecord(value, SIGNAL_KEYS, PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.INPUT, true);
  if (value.signal !== undefined && (typeof AbortSignal === "undefined" || !(value.signal instanceof AbortSignal))) {
    throw signerError(PROMOTION_EVIDENCE_V3_SIGNER_ERROR_CODES.INPUT);
  }
  return value.signal;
}

function normalizeNow(value) {
  const result = value instanceof Date ? value.getTime() : value;
  if (!Number.isSafeInteger(result) || result < 0) throw new Error("clock");
  return result;
}

function normalizeProviderSignature(value) {
  if (typeof value === "string") return canonicalSignatureV3(value);
  if (!(Buffer.isBuffer(value) || value instanceof Uint8Array)) throw new Error("signature shape");
  const prototype = Object.getPrototypeOf(value);
  if (Buffer.isBuffer(value) ? prototype !== Buffer.prototype : prototype !== Uint8Array.prototype) throw new Error("signature prototype");
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => key !== "length" && (typeof key !== "string" || !/^\d+$/u.test(key)))) throw new Error("signature fields");
  for (const key of keys) {
    if (key === "length") continue;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) throw new Error("signature descriptor");
  }
  return Buffer.from(value);
}

function deadline(promise, timeoutMs) {
  let timer;
  return Promise.race([
    Promise.resolve(promise),
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("timeout")), timeoutMs); }),
  ]).finally(() => clearTimeout(timer));
}

function exactRecord(value, keys, code, allowSubset = false) {
  if (!plainObject(value)) throw signerError(code);
  const actual = Reflect.ownKeys(value);
  if (actual.some((key) => typeof key !== "string" || PRIVATE_NAME.test(key))) throw signerError(code);
  if ((!allowSubset && (actual.length !== keys.length || actual.some((key) => !keys.includes(key))))
    || (allowSubset && actual.some((key) => !keys.includes(key)))) throw signerError(code);
  for (const key of actual) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !("value" in descriptor)) throw signerError(code);
  }
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function deepFreeze(value, seen = new Set()) {
  if (value && typeof value === "object" && !seen.has(value)) {
    seen.add(value);
    for (const child of Object.values(value)) deepFreeze(child, seen);
    Object.freeze(value);
  }
  return value;
}

function signerError(code) {
  return new PromotionEvidenceV3Error(code);
}
