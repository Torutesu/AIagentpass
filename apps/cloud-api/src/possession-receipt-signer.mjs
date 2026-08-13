import crypto from "node:crypto";

import { canonicalJson } from "../../../packages/protocol/src/index.mjs";

export const POSSESSION_RECEIPT_VERSION = 1;
export const POSSESSION_RECEIPT_PURPOSE = "device-enrollment-possession-receipt";
export const POSSESSION_RECEIPT_SIGNATURE_DOMAIN = "AgentPass-Cloud-Possession-Receipt-v1\0";
export const POSSESSION_RECEIPT_SIGNATURE_ALGORITHMS = Object.freeze(["ed25519", "p256-sha256"]);

export const POSSESSION_RECEIPT_SIGNER_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_POSSESSION_RECEIPT_SIGNER_CONFIG",
  INPUT: "ERR_POSSESSION_RECEIPT_SIGNER_INPUT",
  PROVIDER: "ERR_POSSESSION_RECEIPT_SIGNER_PROVIDER",
  TIMEOUT: "ERR_POSSESSION_RECEIPT_SIGNER_TIMEOUT",
  OUTPUT: "ERR_POSSESSION_RECEIPT_SIGNER_OUTPUT",
  VERIFICATION: "ERR_POSSESSION_RECEIPT_SIGNER_VERIFICATION"
});

const DOMAIN = Buffer.from(POSSESSION_RECEIPT_SIGNATURE_DOMAIN, "utf8");
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CANDIDATE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const SOURCE_COMMIT = /^[0-9a-f]{40}$/u;
const TEAM_ID = /^[A-Z0-9]{10}$/u;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const STATEMENT_KEYS = Object.freeze([
  "version",
  "enrollment_id",
  "organization_id",
  "device_id",
  "candidate_id",
  "artifact_sha256",
  "source_commit",
  "team_id",
  "device_key_fingerprint",
  "device_key_epoch",
  "challenge_nonce_digest",
  "issued_at"
]);
const METADATA_KEYS = Object.freeze(["key_id", "algorithm", "public_key"]);
const MAX_STATEMENT_BYTES = 16 * 1024;
const DEFAULT_TIMEOUT_MS = 5_000;
const MAX_TIMEOUT_MS = 30_000;
const P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const P256_HALF_ORDER = P256_ORDER / 2n;

export class PossessionReceiptSignerError extends Error {
  constructor(code) {
    super(code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG ? "possession receipt signer configuration is invalid"
      : code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.INPUT ? "possession receipt signing input is invalid"
        : code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.TIMEOUT ? "possession receipt signing timed out"
          : code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.OUTPUT ? "possession receipt signer output is invalid"
            : code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.VERIFICATION ? "possession receipt signature verification failed"
              : "possession receipt signer provider failed");
    this.name = "PossessionReceiptSignerError";
    this.code = code;
  }
}

/**
 * Normalize the exact public statement that is signed into a receipt.
 * No aliases or optional fields are accepted: the canonical bytes are part of
 * the receipt contract and must not depend on caller object ordering.
 */
export function normalizePossessionReceiptStatement(input) {
  try {
    if (!plainObject(input) || Reflect.ownKeys(input).some((key) => typeof key !== "string")) fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.INPUT);
    const keys = Object.keys(input);
    if (keys.length !== STATEMENT_KEYS.length || keys.some((key) => !STATEMENT_KEYS.includes(key))) fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.INPUT);
    const value = {
      version: exactInteger(input.version, 1),
      enrollment_id: exactPattern(input.enrollment_id, UUID),
      organization_id: exactPattern(input.organization_id, UUID),
      device_id: exactPattern(input.device_id, UUID),
      candidate_id: exactPattern(input.candidate_id, CANDIDATE_ID),
      artifact_sha256: exactPattern(input.artifact_sha256, SHA256),
      source_commit: exactPattern(input.source_commit, SOURCE_COMMIT),
      team_id: exactPattern(input.team_id, TEAM_ID),
      device_key_fingerprint: exactPattern(input.device_key_fingerprint, FINGERPRINT),
      device_key_epoch: positiveInteger(input.device_key_epoch),
      challenge_nonce_digest: exactPattern(input.challenge_nonce_digest, SHA256),
      issued_at: canonicalTimestamp(input.issued_at)
    };
    const encoded = canonicalJson(value);
    if (Buffer.byteLength(encoded, "utf8") > MAX_STATEMENT_BYTES) fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.INPUT);
    return Object.freeze(value);
  } catch (error) {
    if (error instanceof PossessionReceiptSignerError) throw error;
    throw new PossessionReceiptSignerError(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.INPUT);
  }
}

export function possessionReceiptSigningData(statement) {
  const normalized = normalizePossessionReceiptStatement(statement);
  return Buffer.concat([DOMAIN, Buffer.from(canonicalJson(normalized), "utf8")]);
}

/**
 * Create a signer around a KMS/HSM/local provider.
 *
 * Provider contract:
 *   publicKeyMetadata() -> { key_id, algorithm, public_key }
 *   sign({ bytes, key_id, algorithm, purpose, version, signal }) -> raw bytes
 *
 * A provider never receives a private-key export from this module and its
 * result is never returned without independent local verification.
 */
export function createPossessionReceiptSigner({ provider, keyId, algorithm, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  validateSignerConfig({ provider, keyId, algorithm, timeoutMs });
  const normalizedKeyId = keyId;
  const normalizedAlgorithm = algorithm;

  async function loadPublicMetadata() {
    let metadata;
    try {
      metadata = await withTimeout(
        (signal) => provider.publicKeyMetadata({ key_id: normalizedKeyId, algorithm: normalizedAlgorithm, purpose: POSSESSION_RECEIPT_PURPOSE, version: POSSESSION_RECEIPT_VERSION, signal }),
        timeoutMs
      );
    } catch (error) {
      if (error instanceof PossessionReceiptSignerError) throw error;
      throw new PossessionReceiptSignerError(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.PROVIDER);
    }
    const publicKey = parseProviderMetadata(metadata, normalizedKeyId, normalizedAlgorithm);
    return Object.freeze({
      version: POSSESSION_RECEIPT_VERSION,
      purpose: POSSESSION_RECEIPT_PURPOSE,
      key_id: normalizedKeyId,
      algorithm: normalizedAlgorithm,
      public_key: publicKey.export({ type: "spki", format: "pem" }).toString()
    });
  }

  async function signPossessionReceipt(statement) {
    const normalized = normalizePossessionReceiptStatement(statement);
    const bytes = possessionReceiptSigningData(normalized);
    const metadata = await loadPublicMetadata();
    const publicKey = crypto.createPublicKey(metadata.public_key);
    let signature;
    try {
      signature = await withTimeout((signal) => provider.sign({
        bytes: Buffer.from(bytes),
        key_id: normalizedKeyId,
        algorithm: normalizedAlgorithm,
        purpose: POSSESSION_RECEIPT_PURPOSE,
        version: POSSESSION_RECEIPT_VERSION,
        signal
      }), timeoutMs);
    } catch (error) {
      if (error instanceof PossessionReceiptSignerError) throw error;
      throw new PossessionReceiptSignerError(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.PROVIDER);
    }
    const signatureBytes = normalizeSignature(signature, normalizedAlgorithm);
    let valid = false;
    try {
      valid = verifySignature(bytes, signatureBytes, publicKey, normalizedAlgorithm);
    } catch {
      valid = false;
    }
    if (!valid) throw new PossessionReceiptSignerError(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.VERIFICATION);
    return Object.freeze({
      version: POSSESSION_RECEIPT_VERSION,
      purpose: POSSESSION_RECEIPT_PURPOSE,
      key_id: normalizedKeyId,
      algorithm: normalizedAlgorithm,
      statement: normalized,
      statement_hash: crypto.createHash("sha256").update(canonicalJson(normalized), "utf8").digest("hex"),
      signature: signatureBytes.toString("base64url")
    });
  }

  return Object.freeze({
    publicKeyMetadata: loadPublicMetadata,
    signPossessionReceipt
  });
}

/** Local conformance provider; production deployments can replace it with KMS/HSM. */
export function createLocalPossessionReceiptSigner({ privateKey, keyId, algorithm, timeoutMs } = {}) {
  let key;
  try {
    key = privateKey?.type === "private" ? privateKey : crypto.createPrivateKey(privateKey);
  } catch {
    throw new PossessionReceiptSignerError(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
  }
  if (key.type !== "private" || !isSupportedKey(key, algorithm) || !KEY_ID.test(keyId ?? "")) {
    throw new PossessionReceiptSignerError(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
  }
  const publicKey = crypto.createPublicKey(key);
  const provider = {
    async publicKeyMetadata() {
      return { key_id: keyId, algorithm, public_key: publicKey };
    },
    async sign({ bytes }) {
      return signWithKey(bytes, key, algorithm);
    }
  };
  return createPossessionReceiptSigner({ provider, keyId, algorithm, timeoutMs });
}

export function verifyPossessionReceiptSignature({ statement, signature, publicKey, algorithm } = {}) {
  const bytes = possessionReceiptSigningData(statement);
  const key = parsePublicKey(publicKey, algorithm, POSSESSION_RECEIPT_SIGNER_ERROR_CODES.INPUT);
  const signatureBytes = decodeSignature(signature, algorithm, POSSESSION_RECEIPT_SIGNER_ERROR_CODES.INPUT);
  return verifySignature(bytes, signatureBytes, key, algorithm);
}

function validateSignerConfig({ provider, keyId, algorithm, timeoutMs }) {
  if (!provider || typeof provider.publicKeyMetadata !== "function" || typeof provider.sign !== "function"
    || !KEY_ID.test(keyId ?? "") || !POSSESSION_RECEIPT_SIGNATURE_ALGORITHMS.includes(algorithm)
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new PossessionReceiptSignerError(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
  }
}

function parseProviderMetadata(value, expectedKeyId, expectedAlgorithm) {
  try {
    if (!plainObject(value) || Reflect.ownKeys(value).some((key) => typeof key !== "string")
      || Object.keys(value).length !== METADATA_KEYS.length || Object.keys(value).some((key) => !METADATA_KEYS.includes(key))
      || value.key_id !== expectedKeyId || value.algorithm !== expectedAlgorithm) fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.OUTPUT);
    return parsePublicKey(value.public_key, expectedAlgorithm, POSSESSION_RECEIPT_SIGNER_ERROR_CODES.OUTPUT);
  } catch (error) {
    if (error instanceof PossessionReceiptSignerError) throw error;
    throw new PossessionReceiptSignerError(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.OUTPUT);
  }
}

function parsePublicKey(value, algorithm, errorCode) {
  let key;
  try {
    if (value?.type === "private" || (typeof value === "string" && /PRIVATE\s+KEY/iu.test(value))) fail(errorCode);
    key = value?.type === "public" ? value : crypto.createPublicKey(value);
  } catch {
    throw new PossessionReceiptSignerError(errorCode);
  }
  if (key.type !== "public" || !isSupportedKey(key, algorithm)) throw new PossessionReceiptSignerError(errorCode);
  return key;
}

function isSupportedKey(key, algorithm) {
  if (algorithm === "ed25519") return key.asymmetricKeyType === "ed25519";
  return key.asymmetricKeyType === "ec" && key.asymmetricKeyDetails?.namedCurve === "prime256v1";
}

function signWithKey(bytes, key, algorithm) {
  if (algorithm === "ed25519") return crypto.sign(null, bytes, key);
  const signature = crypto.sign("sha256", bytes, { key, dsaEncoding: "ieee-p1363" });
  const s = BigInt(`0x${signature.subarray(32).toString("hex")}`);
  if (s <= P256_HALF_ORDER) return signature;
  const lowS = Buffer.alloc(32);
  lowS.writeBigUInt64BE((P256_ORDER - s) >> 192n, 0);
  lowS.writeBigUInt64BE((P256_ORDER - s) >> 128n & 0xffffffffffffffffn, 8);
  lowS.writeBigUInt64BE((P256_ORDER - s) >> 64n & 0xffffffffffffffffn, 16);
  lowS.writeBigUInt64BE((P256_ORDER - s) & 0xffffffffffffffffn, 24);
  return Buffer.concat([signature.subarray(0, 32), lowS]);
}

function verifySignature(bytes, signature, publicKey, algorithm) {
  return algorithm === "ed25519"
    ? crypto.verify(null, bytes, publicKey, signature)
    : crypto.verify("sha256", bytes, { key: publicKey, dsaEncoding: "ieee-p1363" }, signature);
}

function normalizeSignature(value, algorithm) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) throw new PossessionReceiptSignerError(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.OUTPUT);
  const signature = Buffer.from(value);
  if (signature.length !== 64 || (algorithm === "p256-sha256" && !isCanonicalP256Signature(signature))) throw new PossessionReceiptSignerError(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.OUTPUT);
  return signature;
}

function decodeSignature(value, algorithm, errorCode) {
  if (typeof value !== "string" || value.length === 0 || value !== Buffer.from(value, "base64url").toString("base64url")) throw new PossessionReceiptSignerError(errorCode);
  try { return normalizeSignature(Buffer.from(value, "base64url"), algorithm); }
  catch { throw new PossessionReceiptSignerError(errorCode); }
}

function isCanonicalP256Signature(signature) {
  const r = BigInt(`0x${signature.subarray(0, 32).toString("hex")}`);
  const s = BigInt(`0x${signature.subarray(32).toString("hex")}`);
  return r > 0n && r < P256_ORDER && s > 0n && s <= P256_HALF_ORDER;
}

function withTimeout(operation, timeoutMs) {
  const controller = new AbortController();
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      controller.abort();
      reject(new PossessionReceiptSignerError(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.TIMEOUT));
    }, timeoutMs);
    Promise.resolve().then(() => operation(controller.signal)).then((value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    }, () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new PossessionReceiptSignerError(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.PROVIDER));
    });
  });
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactPattern(value, pattern) {
  if (typeof value !== "string" || !pattern.test(value)) fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.INPUT);
  return value;
}

function exactInteger(value, expected) {
  if (value !== expected) fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.INPUT);
  return value;
}

function positiveInteger(value) {
  if (!Number.isSafeInteger(value) || value < 1) fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.INPUT);
  return value;
}

function canonicalTimestamp(value) {
  if (typeof value !== "string" || !TIMESTAMP.test(value) || new Date(value).toISOString() !== value) fail(POSSESSION_RECEIPT_SIGNER_ERROR_CODES.INPUT);
  return value;
}

function fail(code) { throw new PossessionReceiptSignerError(code); }

export default createPossessionReceiptSigner;
