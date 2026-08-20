import crypto from "node:crypto";

import {
  PROMOTION_EVIDENCE_V3_ALGORITHM,
  PROMOTION_EVIDENCE_V3_ERROR_CODES,
  PROMOTION_EVIDENCE_V3_MAX_TTL_MS,
  PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
  PROMOTION_EVIDENCE_V3_PURPOSE,
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

const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const MAX_SIGNATURE_TIMEOUT_MS = 30_000;
const DEFAULT_SIGNATURE_TIMEOUT_MS = 5_000;

export function createHostedPromotionEvidenceV3Signer(options = {}) {
  const optionKeys = ["provider", "keyId", "keyVersion", "lifecycleVersion", "publicKey", "timeoutMs", "maxTtlMs", "now"];
  if (!plainObject(options) || Reflect.ownKeys(options).some((key) => typeof key !== "string" || !optionKeys.includes(key))) throw signerError(PROMOTION_EVIDENCE_V3_ERROR_CODES.CONFIG);
  const { provider, keyId, keyVersion, lifecycleVersion, publicKey, timeoutMs = DEFAULT_SIGNATURE_TIMEOUT_MS, maxTtlMs = PROMOTION_EVIDENCE_V3_MAX_TTL_MS, now = () => Date.now() } = options;
  const configuredKey = validateConfiguration({ provider, keyId, keyVersion, lifecycleVersion, publicKey, timeoutMs, maxTtlMs, now });
  let pinned;

  async function publicKeyMetadata() {
    let value;
    try { value = await deadline(provider.publicKeyMetadata({ algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM, key_id: keyId, purpose: PROMOTION_EVIDENCE_V3_PURPOSE, version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION }), timeoutMs); }
    catch (error) { if (error instanceof PromotionEvidenceV3Error) throw error; throw signerError(PROMOTION_EVIDENCE_V3_ERROR_CODES.CONFIG); }
    try {
      if (!plainObject(value) || !sameKeys(value, ["algorithm", "key_id", "public_key"]) || value.algorithm !== PROMOTION_EVIDENCE_V3_ALGORITHM || value.key_id !== keyId) throw new Error("metadata shape");
      const key = parsePromotionEvidenceV3PublicKey(value.public_key, PROMOTION_EVIDENCE_V3_ERROR_CODES.OUTPUT);
      const publicKeyPem = key.export({ type: "spki", format: "pem" }).toString();
      const fingerprint = promotionEvidenceV3PublicKeyFingerprint(key);
      if (configuredKey.publicKeyPem !== publicKeyPem || configuredKey.fingerprint !== fingerprint || (pinned && (pinned.publicKeyPem !== publicKeyPem || pinned.fingerprint !== fingerprint))) throw new Error("metadata changed");
      pinned = Object.freeze({ publicKeyPem, fingerprint, key });
      return Object.freeze({ key_id: keyId, key_version: keyVersion, algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM, purpose: PROMOTION_EVIDENCE_V3_PURPOSE, protocol_version: PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION, signing_version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION, lifecycle_version: lifecycleVersion, public_key: publicKeyPem, public_key_fingerprint: fingerprint });
    } catch (error) { if (error instanceof PromotionEvidenceV3Error) throw error; throw signerError(PROMOTION_EVIDENCE_V3_ERROR_CODES.OUTPUT); }
  }

  async function signPromotionEvidence(statement, options = {}) {
    const signal = normalizeSignOptions(options);
    let current;
    try { current = normalizeNow(now()); } catch { throw signerError(PROMOTION_EVIDENCE_V3_ERROR_CODES.CONFIG); }
    const normalized = normalizePromotionEvidenceV3Statement(statement, { now: current, allowExpired: false, allowFuture: false, maxTtlMs });
    if (normalized.key_id !== keyId || normalized.key_version !== keyVersion || normalized.lifecycle_version !== lifecycleVersion) throw signerError(PROMOTION_EVIDENCE_V3_ERROR_CODES.BINDING);
    const metadata = await publicKeyMetadata();
    const signingBytes = promotionEvidenceV3SigningData(normalized, { now: current, allowExpired: false, allowFuture: false, maxTtlMs });
    let output;
    try { output = await deadline(provider.sign({ algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM, bytes: Buffer.from(signingBytes), key_id: keyId, purpose: PROMOTION_EVIDENCE_V3_PURPOSE, version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION, ...(signal === undefined ? {} : { signal }) }), timeoutMs); }
    catch (error) { if (error instanceof PromotionEvidenceV3Error) throw error; throw signerError(PROMOTION_EVIDENCE_V3_ERROR_CODES.CONFIG); }
    let signature;
    try { signature = output instanceof Uint8Array || Buffer.isBuffer(output) ? Buffer.from(output) : canonicalSignatureV3(output); } catch { throw signerError(PROMOTION_EVIDENCE_V3_ERROR_CODES.OUTPUT); }
    if (signature.length !== 64) throw signerError(PROMOTION_EVIDENCE_V3_ERROR_CODES.OUTPUT);
    let valid = false;
    try { valid = crypto.verify(null, signingBytes, parsePromotionEvidenceV3PublicKey(metadata.public_key), signature); } catch { valid = false; }
    if (!valid) throw signerError(PROMOTION_EVIDENCE_V3_ERROR_CODES.SIGNATURE);
    return Object.freeze({ version: PROMOTION_EVIDENCE_V3_VERSION, type: PROMOTION_EVIDENCE_V3_TYPE, statement: normalized, statement_hash: promotionEvidenceV3StatementHash(normalized, { now: current, allowExpired: false, allowFuture: false, maxTtlMs }), signature_algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM, signer_key_fingerprint: metadata.public_key_fingerprint, signature: signature.toString("base64url") });
  }
  return Object.freeze({ purpose: PROMOTION_EVIDENCE_V3_PURPOSE, algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM, version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION, protocol_version: PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION, signing_version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION, lifecycle_version: lifecycleVersion, key_id: keyId, key_version: keyVersion, publicKeyMetadata, signPromotionEvidence, sign: signPromotionEvidence });
}

export const createPromotionEvidenceV3Signer = createHostedPromotionEvidenceV3Signer;

function validateConfiguration({ provider, keyId, keyVersion, lifecycleVersion, publicKey, timeoutMs, maxTtlMs, now }) {
  if (!plainObject(provider) || typeof provider.publicKeyMetadata !== "function" || typeof provider.sign !== "function" || !KEY_ID.test(keyId ?? "") || !Number.isSafeInteger(keyVersion) || keyVersion < 1 || !Number.isSafeInteger(lifecycleVersion) || lifecycleVersion < 1 || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_SIGNATURE_TIMEOUT_MS || !Number.isSafeInteger(maxTtlMs) || maxTtlMs < 1 || maxTtlMs > PROMOTION_EVIDENCE_V3_MAX_TTL_MS || typeof now !== "function" || Object.hasOwn(provider, "privateKey") || Object.hasOwn(provider, "private_key") || Object.hasOwn(provider, "secret") || Object.hasOwn(provider, "private_key_pem")) throw signerError(PROMOTION_EVIDENCE_V3_ERROR_CODES.CONFIG);
  for (const [field, expected] of [["purpose", PROMOTION_EVIDENCE_V3_PURPOSE], ["algorithm", PROMOTION_EVIDENCE_V3_ALGORITHM], ["version", PROMOTION_EVIDENCE_V3_SIGNING_VERSION], ["key_id", keyId], ["key_version", keyVersion]]) if (provider[field] !== undefined && provider[field] !== expected) throw signerError(PROMOTION_EVIDENCE_V3_ERROR_CODES.CONFIG);
  try { const key = parsePromotionEvidenceV3PublicKey(publicKey, PROMOTION_EVIDENCE_V3_ERROR_CODES.CONFIG); return Object.freeze({ publicKeyPem: key.export({ type: "spki", format: "pem" }).toString(), fingerprint: promotionEvidenceV3PublicKeyFingerprint(key) }); } catch { throw signerError(PROMOTION_EVIDENCE_V3_ERROR_CODES.CONFIG); }
}

function normalizeSignOptions(value) { if (!plainObject(value) || !sameKeys(value, Object.hasOwn(value, "signal") ? ["signal"] : []) || (value.signal !== undefined && (typeof AbortSignal === "undefined" || !(value.signal instanceof AbortSignal)))) throw signerError(PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT); return value.signal; }
function normalizeNow(value) { const result = value instanceof Date ? value.getTime() : value; if (!Number.isSafeInteger(result) || result < 0) throw new Error("invalid clock"); return result; }
function deadline(promise, timeoutMs) { let timer; return Promise.race([Promise.resolve(promise), new Promise((_, reject) => { timer = setTimeout(() => reject(signerError(PROMOTION_EVIDENCE_V3_ERROR_CODES.CONFIG)), timeoutMs); })]).finally(() => clearTimeout(timer)); }
function sameKeys(value, keys) { const actual = Reflect.ownKeys(value); return actual.every((key) => typeof key === "string") && actual.sort().join("\0") === [...keys].sort().join("\0"); }
function plainObject(value) { if (value === null || typeof value !== "object" || Array.isArray(value)) return false; const prototype = Object.getPrototypeOf(value); return prototype === Object.prototype || prototype === null; }
function signerError(code) { return new PromotionEvidenceV3Error(code); }
