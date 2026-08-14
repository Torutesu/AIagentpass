import crypto from "node:crypto";

import { parseBoundedJson } from "../../../lib/control-bundle-v2.mjs";
import {
  POSSESSION_RECEIPT_PURPOSE,
  POSSESSION_RECEIPT_VERSION,
  POSSESSION_RECEIPT_SIGNER_ERROR_CODES as PRIMITIVE_ERROR_CODES,
  createPossessionReceiptSigner,
  verifyPossessionReceiptSignature
} from "./possession-receipt-signer.mjs";

export const POSSESSION_RECEIPT_SIGNER_PROFILE = "hosted";
export const POSSESSION_RECEIPT_SIGNER_ALGORITHM = "ed25519";
export const POSSESSION_RECEIPT_SIGNER_KEY_ID_ENV = "AGENTPASS_CLOUD_POSSESSION_RECEIPT_KEY_ID";
export const POSSESSION_RECEIPT_SIGNER_PUBLIC_KEY_ENV = "AGENTPASS_CLOUD_POSSESSION_RECEIPT_PUBLIC_KEY";
export const POSSESSION_RECEIPT_SIGNER_TIMEOUT_ENV = "AGENTPASS_CLOUD_POSSESSION_RECEIPT_TIMEOUT_MS";
export const POSSESSION_RECEIPT_SIGNER_VERIFICATION_KEYS_ENV = "AGENTPASS_CLOUD_POSSESSION_RECEIPT_VERIFICATION_KEYS_JSON";

export const POSSESSION_RECEIPT_SIGNER_ENV = Object.freeze([
  POSSESSION_RECEIPT_SIGNER_KEY_ID_ENV,
  POSSESSION_RECEIPT_SIGNER_PUBLIC_KEY_ENV,
  POSSESSION_RECEIPT_SIGNER_TIMEOUT_ENV,
  POSSESSION_RECEIPT_SIGNER_VERIFICATION_KEYS_ENV
]);

// These names are intentionally rejected if present. A hosted signer must
// never acquire a private key or a key path through a configuration fallback.
export const POSSESSION_RECEIPT_SIGNER_FORBIDDEN_ENV = Object.freeze([
  "AGENTPASS_CLOUD_POSSESSION_RECEIPT_PRIVATE_KEY",
  "AGENTPASS_CLOUD_POSSESSION_RECEIPT_PRIVATE_KEY_PATH",
  "AGENTPASS_CLOUD_POSSESSION_RECEIPT_PUBLIC_KEY_PATH",
  "AGENTPASS_CLOUD_POSSESSION_RECEIPT_KEY_PATH"
]);

export const POSSESSION_RECEIPT_SIGNER_MAX_RETIRING_KEYS = 3;
export const POSSESSION_RECEIPT_SIGNER_MAX_RETIRING_KEY_LIFETIME_MS = 90 * 24 * 60 * 60 * 1000;

export const POSSESSION_RECEIPT_SIGNER_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_POSSESSION_RECEIPT_SIGNER_CONFIG",
  INPUT: "ERR_POSSESSION_RECEIPT_SIGNER_INPUT",
  PROVIDER: "ERR_POSSESSION_RECEIPT_SIGNER_PROVIDER",
  TIMEOUT: "ERR_POSSESSION_RECEIPT_SIGNER_TIMEOUT",
  METADATA: "ERR_POSSESSION_RECEIPT_SIGNER_METADATA",
  KEY_REUSE: "ERR_POSSESSION_RECEIPT_SIGNER_KEY_REUSE",
  DUPLICATE_KEY: "ERR_POSSESSION_RECEIPT_SIGNER_DUPLICATE_KEY",
  AMBIGUOUS_KEY: "ERR_POSSESSION_RECEIPT_SIGNER_AMBIGUOUS_KEY",
  KEY_NOT_TRUSTED: "ERR_POSSESSION_RECEIPT_SIGNER_KEY_NOT_TRUSTED",
  OUTPUT: "ERR_POSSESSION_RECEIPT_SIGNER_OUTPUT",
  VERIFICATION: "ERR_POSSESSION_RECEIPT_SIGNER_VERIFICATION"
});

const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const MAX_KEY_ID_BYTES = 64;
const MAX_PUBLIC_KEY_BYTES = 8 * 1024;
const MAX_VERIFICATION_DOCUMENT_BYTES = 32 * 1024;
const DEFAULT_TIMEOUT_MS = 5_000;
const MAX_TIMEOUT_MS = 30_000;
const PUBLIC_KEY_PEM = /^-----BEGIN PUBLIC KEY-----\n[\s\S]+\n-----END PUBLIC KEY-----\n$/u;
const PUBLIC_METADATA_KEYS = Object.freeze(["algorithm", "key_id", "public_key"]);
const VERIFICATION_KEY_KEYS = Object.freeze(["key_id", "not_after", "public_key"]);
const PUBLIC_KEY_HASH_ALGORITHM = "sha256";

const ERROR_MESSAGES = Object.freeze({
  [POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG]: "possession receipt signer configuration is invalid",
  [POSSESSION_RECEIPT_SIGNER_ERROR_CODES.INPUT]: "possession receipt signing input is invalid",
  [POSSESSION_RECEIPT_SIGNER_ERROR_CODES.PROVIDER]: "possession receipt signer provider failed",
  [POSSESSION_RECEIPT_SIGNER_ERROR_CODES.TIMEOUT]: "possession receipt signer provider timed out",
  [POSSESSION_RECEIPT_SIGNER_ERROR_CODES.METADATA]: "possession receipt signer metadata is invalid",
  [POSSESSION_RECEIPT_SIGNER_ERROR_CODES.KEY_REUSE]: "possession receipt signer key is not purpose separated",
  [POSSESSION_RECEIPT_SIGNER_ERROR_CODES.DUPLICATE_KEY]: "possession receipt signer verification keys contain a duplicate",
  [POSSESSION_RECEIPT_SIGNER_ERROR_CODES.AMBIGUOUS_KEY]: "possession receipt signer active and retiring keys are ambiguous",
  [POSSESSION_RECEIPT_SIGNER_ERROR_CODES.KEY_NOT_TRUSTED]: "possession receipt signer verification key is not trusted",
  [POSSESSION_RECEIPT_SIGNER_ERROR_CODES.OUTPUT]: "possession receipt signer output is invalid",
  [POSSESSION_RECEIPT_SIGNER_ERROR_CODES.VERIFICATION]: "possession receipt signer output could not be verified"
});

export class PossessionReceiptSignerConfigError extends Error {
  constructor(code) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG]);
    this.name = "PossessionReceiptSignerConfigError";
    this.code = code;
  }
}

/**
 * Parse only the public, non-secret Hosted signer configuration.
 *
 * `references` may contain public or private KeyObjects from other already
 * configured purposes. Private references are converted to a fingerprint and
 * discarded immediately; they are never retained in the returned config.
 */
export function parsePossessionReceiptSignerConfig(env = process.env, references = {}, options = {}) {
  try {
    if (!plainObject(options) || Reflect.ownKeys(options).some((key) => typeof key !== "string" || key !== "now")) {
      fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
    }
    const now = options.now ?? (() => Date.now());
    if (!plainObject(env) || env.AGENTPASS_CLOUD_PROFILE !== POSSESSION_RECEIPT_SIGNER_PROFILE || typeof now !== "function") {
      fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
    }
    if (POSSESSION_RECEIPT_SIGNER_FORBIDDEN_ENV.some((name) => env[name] !== undefined)) {
      fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
    }

    const keyId = requiredKeyId(env[POSSESSION_RECEIPT_SIGNER_KEY_ID_ENV]);
    const publicKey = parseConfiguredPublicKey(env[POSSESSION_RECEIPT_SIGNER_PUBLIC_KEY_ENV]);
    const timeoutMs = parseTimeout(env[POSSESSION_RECEIPT_SIGNER_TIMEOUT_ENV]);
    const currentNow = readNow(now);
    const retiring = parseRetiringKeys(env[POSSESSION_RECEIPT_SIGNER_VERIFICATION_KEYS_ENV], currentNow);
    const keys = [
      publicVerificationKey({ keyId, publicKey, status: "active" }),
      ...retiring
    ];

    rejectRotationDuplicates(keys);
    rejectPurposeKeyReuse(keys, references);

    const safeKeys = Object.freeze(keys.map((key) => Object.freeze({ ...key })));
    return deepFreeze({
      profile: POSSESSION_RECEIPT_SIGNER_PROFILE,
      purpose: POSSESSION_RECEIPT_PURPOSE,
      algorithm: POSSESSION_RECEIPT_SIGNER_ALGORITHM,
      keyId,
      timeoutMs,
      publicKeyPem: publicKey.pem,
      publicKeyFingerprint: publicKey.fingerprint,
      keys: safeKeys
    });
  } catch (error) {
    if (error instanceof PossessionReceiptSignerConfigError) throw error;
    throw new PossessionReceiptSignerConfigError(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
  }
}

export const parseHostedPossessionReceiptSignerConfig = parsePossessionReceiptSignerConfig;

/**
 * Create the production-only Hosted boundary around the primitive receipt
 * signer. The injected provider is the sole signing authority; this module
 * accepts no private key, path, credential blob, or local fallback.
 */
export function createHostedPossessionReceiptSigner(options = {}) {
  try {
    if (!plainObject(options)) fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
    const optionKeys = new Set(["provider", "env", "references", "now"]);
    if (Reflect.ownKeys(options).some((key) => typeof key !== "string" || !optionKeys.has(key))) {
      fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
    }
  } catch (error) {
    if (error instanceof PossessionReceiptSignerConfigError) throw error;
    throw new PossessionReceiptSignerConfigError(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
  }

  const {
    provider,
    env = process.env,
    references = {},
    now = () => Date.now()
  } = options;
  const config = parsePossessionReceiptSignerConfig(env, references, { now });
  if (!provider || typeof provider.publicKeyMetadata !== "function" || typeof provider.sign !== "function" || typeof now !== "function") {
    throw new PossessionReceiptSignerConfigError(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
  }

  let primitive;
  try {
    primitive = createPossessionReceiptSigner({
      provider,
      keyId: config.keyId,
      algorithm: POSSESSION_RECEIPT_SIGNER_ALGORITHM,
      timeoutMs: config.timeoutMs
    });
  } catch {
    throw new PossessionReceiptSignerConfigError(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
  }

  async function assertProviderMetadata() {
    let metadata;
    try {
      metadata = await primitive.publicKeyMetadata();
    } catch (error) {
      throw mapPrimitiveError(error, { metadata: true });
    }
    try {
      if (!plainObject(metadata) || !sameKeys(metadata, ["algorithm", "key_id", "public_key", "purpose", "version"])
        || metadata.version !== POSSESSION_RECEIPT_VERSION
        || metadata.purpose !== POSSESSION_RECEIPT_PURPOSE
        || metadata.key_id !== config.keyId
        || metadata.algorithm !== POSSESSION_RECEIPT_SIGNER_ALGORITHM
        || typeof metadata.public_key !== "string"
        || metadata.public_key !== config.publicKeyPem) {
        fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.METADATA);
      }
      const parsed = parsePublicKey(metadata.public_key, false, POSSESSION_RECEIPT_SIGNER_ERROR_CODES.METADATA);
      if (parsed.fingerprint !== config.publicKeyFingerprint) fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.METADATA);
    } catch (error) {
      if (error instanceof PossessionReceiptSignerConfigError) throw error;
      throw new PossessionReceiptSignerConfigError(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.METADATA);
    }
    return Object.freeze({
      version: POSSESSION_RECEIPT_VERSION,
      purpose: POSSESSION_RECEIPT_PURPOSE,
      key_id: config.keyId,
      algorithm: POSSESSION_RECEIPT_SIGNER_ALGORITHM,
      public_key: config.publicKeyPem
    });
  }

  async function publicKeyMetadata() {
    await assertProviderMetadata();
    return Object.freeze({
      version: POSSESSION_RECEIPT_VERSION,
      purpose: POSSESSION_RECEIPT_PURPOSE,
      key_id: config.keyId,
      algorithm: POSSESSION_RECEIPT_SIGNER_ALGORITHM,
      public_key: config.publicKeyPem
    });
  }

  async function verificationKeyMetadata(keyId, options = {}) {
    await assertProviderMetadata();
    if (!plainObject(options) || Reflect.ownKeys(options).some((key) => typeof key !== "string" || key !== "at")) {
      throw new PossessionReceiptSignerConfigError(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.INPUT);
    }
    const { at = undefined } = options;
    const currentNow = readNow(at === undefined ? now : at);
    const activeKeys = config.keys.filter((key) => key.status === "active" || Date.parse(key.not_after) > currentNow);
    if (keyId !== undefined) {
      const key = activeKeys.find((candidate) => candidate.key_id === keyId);
      if (!key) throw new PossessionReceiptSignerConfigError(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.KEY_NOT_TRUSTED);
      return key;
    }
    return Object.freeze({
      version: POSSESSION_RECEIPT_VERSION,
      purpose: POSSESSION_RECEIPT_PURPOSE,
      active_key_id: config.keyId,
      keys: Object.freeze(activeKeys)
    });
  }

  async function signPossessionReceipt(statement) {
    // This check is deliberately independent of the primitive's signature
    // verification. A provider key substitution must fail even if the
    // substituted provider can produce a valid signature of its own.
    await assertProviderMetadata();
    let receipt;
    try {
      receipt = await primitive.signPossessionReceipt(statement);
    } catch (error) {
      throw mapPrimitiveError(error);
    }
    await assertProviderMetadata();
    try {
      if (!plainObject(receipt)
        || receipt.version !== POSSESSION_RECEIPT_VERSION
        || receipt.purpose !== POSSESSION_RECEIPT_PURPOSE
        || receipt.key_id !== config.keyId
        || receipt.algorithm !== POSSESSION_RECEIPT_SIGNER_ALGORITHM
        || !verifyPossessionReceiptSignature({
          statement: receipt.statement,
          signature: receipt.signature,
          publicKey: config.publicKeyPem,
          algorithm: POSSESSION_RECEIPT_SIGNER_ALGORITHM
        })) {
        fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.VERIFICATION);
      }
    } catch (error) {
      if (error instanceof PossessionReceiptSignerConfigError) throw error;
      throw new PossessionReceiptSignerConfigError(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.VERIFICATION);
    }
    return receipt;
  }

  async function health() {
    await assertProviderMetadata();
    const currentNow = readNow(now);
    return Object.freeze({
      ready: true,
      purpose: POSSESSION_RECEIPT_PURPOSE,
      algorithm: POSSESSION_RECEIPT_SIGNER_ALGORITHM,
      key_id: config.keyId,
      public_key_fingerprint: config.publicKeyFingerprint,
      verification_key_ids: Object.freeze(config.keys
        .filter((key) => key.status === "active" || Date.parse(key.not_after) > currentNow)
        .map((key) => key.key_id))
    });
  }

  return Object.freeze({
    key_id: config.keyId,
    algorithm: POSSESSION_RECEIPT_SIGNER_ALGORITHM,
    config,
    publicKeyMetadata,
    verificationKeyMetadata,
    signPossessionReceipt,
    health,
    readiness: health
  });
}

export const createHostedPossessionReceiptSignerConfig = createHostedPossessionReceiptSigner;

function parseRetiringKeys(raw, currentNow) {
  if (raw === undefined) return [];
  if (typeof raw !== "string" || Buffer.byteLength(raw, "utf8") < 1 || Buffer.byteLength(raw, "utf8") > MAX_VERIFICATION_DOCUMENT_BYTES) {
    fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
  }
  let value;
  try { value = parseBoundedJson(Buffer.from(raw, "utf8"), { maxBytes: MAX_VERIFICATION_DOCUMENT_BYTES, maxDepth: 8 }); }
  catch { fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG); }
  if (!Array.isArray(value) || value.length > POSSESSION_RECEIPT_SIGNER_MAX_RETIRING_KEYS) fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
  return value.map((entry) => {
    if (!plainObject(entry) || !sameKeys(entry, VERIFICATION_KEY_KEYS)) fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
    const keyId = requiredKeyId(entry.key_id);
    const notAfter = exactFutureTimestamp(entry.not_after, currentNow);
    const publicKey = parseConfiguredPublicKey(entry.public_key);
    return publicVerificationKey({ keyId, publicKey, status: "retiring", notAfter });
  });
}

function publicVerificationKey({ keyId, publicKey, status, notAfter } = {}) {
  return Object.freeze({
    key_id: keyId,
    algorithm: POSSESSION_RECEIPT_SIGNER_ALGORITHM,
    public_key: publicKey.pem,
    public_key_fingerprint: publicKey.fingerprint,
    status,
    ...(notAfter === undefined ? {} : { not_after: notAfter })
  });
}

function rejectRotationDuplicates(keys) {
  const ids = new Set();
  const fingerprints = new Set();
  for (const key of keys) {
    const activeCollision = ids.has(key.key_id) || fingerprints.has(key.public_key_fingerprint);
    if (activeCollision && key.status === "retiring") fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.AMBIGUOUS_KEY);
    if (activeCollision) fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.DUPLICATE_KEY);
    ids.add(key.key_id);
    fingerprints.add(key.public_key_fingerprint);
  }
}

function rejectPurposeKeyReuse(keys, references) {
  const forbidden = referenceKeys(references);
  if (keys.some((key) => forbidden.some((reference) => reference.keyId === key.key_id || reference.fingerprint === key.public_key_fingerprint))) {
    fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.KEY_REUSE);
  }
}

function referenceKeys(references) {
  if (references === undefined) return [];
  if (!plainObject(references)) fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
  const output = [];
  const visited = new Set();

  function visit(value, depth) {
    if (value === undefined || value === null) return;
    if (depth > 8) fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
    if (value?.type === "public" || value?.type === "private") {
      output.push({ fingerprint: parseReferencePublicKey(value).fingerprint });
      return;
    }
    if (Array.isArray(value)) {
      if (visited.has(value)) fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
      visited.add(value);
      for (const item of value) visit(item, depth + 1);
      return;
    }
    if (!plainObject(value)) return;
    if (visited.has(value)) fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
    visited.add(value);

    const keyId = value.keyId ?? value.key_id;
    const publicKeyValue = value.publicKey ?? value.public_key;
    if (keyId !== undefined) {
      if (typeof keyId !== "string" || Buffer.byteLength(keyId, "utf8") > MAX_KEY_ID_BYTES || !KEY_ID.test(keyId)) {
        fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
      }
      output.push({ keyId });
    }
    if (publicKeyValue !== undefined) {
      output.push({ fingerprint: parseReferencePublicKey(publicKeyValue).fingerprint });
    }
    for (const [name, child] of Object.entries(value)) {
      if (!["keyId", "key_id", "publicKey", "public_key"].includes(name)) visit(child, depth + 1);
    }
  }

  visit(references, 0);
  return output;
}

function parseConfiguredPublicKey(value) {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") < 1 || Buffer.byteLength(value, "utf8") > MAX_PUBLIC_KEY_BYTES
    || !PUBLIC_KEY_PEM.test(value) || /PRIVATE\s+KEY/iu.test(value)) {
    fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
  }
  const parsed = parsePublicKey(value, false, POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
  const canonical = parsed.key.export({ type: "spki", format: "pem" }).toString();
  if (canonical !== value) fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
  return { pem: canonical, fingerprint: parsed.fingerprint };
}

function parseReferencePublicKey(value) {
  return parsePublicKey(value, true, POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
}

function parsePublicKey(value, allowPrivate, errorCode) {
  try {
    if (value?.type === "private" || (typeof value === "string" && /PRIVATE\s+KEY/iu.test(value))) {
      if (!allowPrivate) fail(errorCode);
    }
    const key = value?.type === "private"
      ? crypto.createPublicKey(value)
      : value?.type === "public" ? value : crypto.createPublicKey(value);
    if (key.type !== "public" || key.asymmetricKeyType !== POSSESSION_RECEIPT_SIGNER_ALGORITHM) fail(errorCode);
    const der = key.export({ type: "spki", format: "der" });
    if (!Buffer.isBuffer(der) || der.length < 1 || der.length > MAX_PUBLIC_KEY_BYTES) fail(errorCode);
    return {
      key,
      fingerprint: crypto.createHash(PUBLIC_KEY_HASH_ALGORITHM).update(der).digest("hex")
    };
  } catch (error) {
    if (error instanceof PossessionReceiptSignerConfigError) throw error;
    throw new PossessionReceiptSignerConfigError(errorCode);
  }
}

function mapPrimitiveError(error, { metadata = false } = {}) {
  const code = error?.code;
  const mapped = code === PRIMITIVE_ERROR_CODES.TIMEOUT ? POSSESSION_RECEIPT_SIGNER_ERROR_CODES.TIMEOUT
    : code === PRIMITIVE_ERROR_CODES.PROVIDER ? POSSESSION_RECEIPT_SIGNER_ERROR_CODES.PROVIDER
      : code === PRIMITIVE_ERROR_CODES.OUTPUT ? (metadata ? POSSESSION_RECEIPT_SIGNER_ERROR_CODES.METADATA : POSSESSION_RECEIPT_SIGNER_ERROR_CODES.OUTPUT)
        : code === PRIMITIVE_ERROR_CODES.VERIFICATION ? POSSESSION_RECEIPT_SIGNER_ERROR_CODES.VERIFICATION
          : code === PRIMITIVE_ERROR_CODES.INPUT ? POSSESSION_RECEIPT_SIGNER_ERROR_CODES.INPUT
            : POSSESSION_RECEIPT_SIGNER_ERROR_CODES.PROVIDER;
  return new PossessionReceiptSignerConfigError(mapped);
}

function requiredKeyId(value) {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > MAX_KEY_ID_BYTES || !KEY_ID.test(value)) fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
  return value;
}

function parseTimeout(value) {
  if (value === undefined) return DEFAULT_TIMEOUT_MS;
  if (typeof value !== "string" || !/^\d+$/u.test(value)) fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > MAX_TIMEOUT_MS) fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
  return parsed;
}

function exactFutureTimestamp(value, currentNow) {
  if (typeof value !== "string") fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
  let milliseconds;
  try { milliseconds = Date.parse(value); } catch { milliseconds = Number.NaN; }
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value
    || milliseconds <= currentNow || milliseconds > currentNow + POSSESSION_RECEIPT_SIGNER_MAX_RETIRING_KEY_LIFETIME_MS) {
    fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
  }
  return value;
}

function readNow(value) {
  let observed;
  try { observed = typeof value === "function" ? value() : value; } catch { fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG); }
  const resolved = observed instanceof Date ? observed.getTime() : observed;
  if (!Number.isSafeInteger(resolved) || resolved < 0) fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
  return resolved;
}

function sameKeys(value, expected) {
  const actual = Reflect.ownKeys(value);
  return actual.every((key) => typeof key === "string") && actual.sort().join("\0") === expected.slice().sort().join("\0");
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function deepFreeze(value) {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function fail(code) { throw new PossessionReceiptSignerConfigError(code); }
