import crypto from "node:crypto";

export const PKCE_VERIFIER_CODEC_VERSION = 1;
export const PKCE_VERIFIER_CODEC_NONCE_BYTES = 12;
export const PKCE_VERIFIER_CODEC_TAG_BYTES = 16;
export const PKCE_VERIFIER_CODEC_MIN_VERIFIER_BYTES = 43;
export const PKCE_VERIFIER_CODEC_MAX_VERIFIER_BYTES = 128;
export const PKCE_VERIFIER_CODEC_MAX_SERIALIZED_BYTES = 2_048;
export const PKCE_VERIFIER_CODEC_ERROR_CODES = Object.freeze({
  CONFIG_INVALID: "pkce_verifier_codec_config_invalid",
  INPUT_INVALID: "pkce_verifier_codec_input_invalid",
  RANDOMNESS_UNAVAILABLE: "pkce_verifier_codec_randomness_unavailable",
  KEY_UNAVAILABLE: "pkce_verifier_codec_key_unavailable",
  ENCRYPTION_FAILED: "pkce_verifier_codec_encryption_failed",
  ENVELOPE_INVALID: "pkce_verifier_codec_envelope_invalid",
  EXPIRED: "pkce_verifier_codec_expired",
  CLOCK_UNAVAILABLE: "pkce_verifier_codec_clock_unavailable"
});

const DOMAIN = "agentpass/hosted-identity/pkce-verifier/v1";
const AES_ALGORITHM = "aes-256-gcm";
const KEY_BYTES = 32;
const MIN_KEY_ID_LENGTH = 1;
const MAX_KEY_ID_LENGTH = 64;
const MAX_ATTEMPT_ID_BYTES = 256;
const MAX_OAUTH_STATE_ID_BYTES = 256;
const MAX_REDIRECT_URI_BYTES = 2_048;
const MAX_SERIALIZED_BYTES = PKCE_VERIFIER_CODEC_MAX_SERIALIZED_BYTES;
const MAX_ENVELOPE_KEY_LENGTH = 64;
const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const PKCE_VERIFIER_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/u;
const PRINTABLE_ASCII_PATTERN = /^[\x21-\x7e]+$/u;
const ENVELOPE_KEYS = Object.freeze(["version", "key_id", "nonce", "ciphertext", "tag"]);
const CONFIG_KEYS = Object.freeze(["keyResolver", "activeKeyId", "randomBytes", "now", "maxSerializedBytes"]);
const SEAL_INPUT_KEYS = Object.freeze(["verifier", "attemptId", "oauthStateId", "redirectUri", "expiresAt"]);
const BINDING_KEYS = Object.freeze(["attemptId", "oauthStateId", "redirectUri", "expiresAt"]);
const ERROR_MESSAGES = Object.freeze({
  [PKCE_VERIFIER_CODEC_ERROR_CODES.CONFIG_INVALID]: "PKCE verifier codec configuration is invalid",
  [PKCE_VERIFIER_CODEC_ERROR_CODES.INPUT_INVALID]: "PKCE verifier codec input is invalid",
  [PKCE_VERIFIER_CODEC_ERROR_CODES.RANDOMNESS_UNAVAILABLE]: "PKCE verifier codec randomness is unavailable",
  [PKCE_VERIFIER_CODEC_ERROR_CODES.KEY_UNAVAILABLE]: "PKCE verifier codec key is unavailable",
  [PKCE_VERIFIER_CODEC_ERROR_CODES.ENCRYPTION_FAILED]: "PKCE verifier encryption failed",
  [PKCE_VERIFIER_CODEC_ERROR_CODES.ENVELOPE_INVALID]: "PKCE verifier envelope is invalid",
  [PKCE_VERIFIER_CODEC_ERROR_CODES.EXPIRED]: "PKCE verifier envelope is expired",
  [PKCE_VERIFIER_CODEC_ERROR_CODES.CLOCK_UNAVAILABLE]: "PKCE verifier codec clock is unavailable"
});

export class PkceVerifierCodecError extends Error {
  constructor(code) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[PKCE_VERIFIER_CODEC_ERROR_CODES.ENVELOPE_INVALID]);
    this.name = "PkceVerifierCodecError";
    this.code = code;
  }
}

/**
 * Encrypts a short-lived RFC 7636 verifier for a restart-safe OAuth callback.
 *
 * The serialized value contains only a closed envelope.  The OAuth attempt,
 * state, redirect URI, and expiry are deliberately kept out of that envelope
 * and authenticated as an exact, versioned AAD tuple instead.  The callback
 * must supply the same tuple before the verifier can be released.
 */
export function createPkceVerifierCodec(options = {}) {
  assertAllowedKeys(options, CONFIG_KEYS, PKCE_VERIFIER_CODEC_ERROR_CODES.CONFIG_INVALID);
  const keyResolver = options.keyResolver;
  const activeKeyId = normalizeKeyId(options.activeKeyId, PKCE_VERIFIER_CODEC_ERROR_CODES.CONFIG_INVALID);
  const randomBytes = options.randomBytes ?? crypto.randomBytes;
  const now = options.now ?? (() => Date.now());
  const maxSerializedBytes = options.maxSerializedBytes ?? MAX_SERIALIZED_BYTES;

  if (typeof keyResolver !== "function" || typeof randomBytes !== "function" || typeof now !== "function"
    || !Number.isSafeInteger(maxSerializedBytes) || maxSerializedBytes < 512 || maxSerializedBytes > MAX_SERIALIZED_BYTES) {
    throw codecError(PKCE_VERIFIER_CODEC_ERROR_CODES.CONFIG_INVALID);
  }

  // Fail fast on a missing active key, while still making the resolver's
  // contents and error details impossible to expose through this boundary.
  const configuredKey = resolveKey(keyResolver, activeKeyId, PKCE_VERIFIER_CODEC_ERROR_CODES.KEY_UNAVAILABLE);
  if (Buffer.isBuffer(configuredKey)) configuredKey.fill(0);

  function seal(input) {
    const tuple = normalizeSealInput(input);
    const currentTime = readClock(now);
    if (tuple.expiresAt <= currentTime) throw codecError(PKCE_VERIFIER_CODEC_ERROR_CODES.EXPIRED);

    const key = resolveKey(keyResolver, activeKeyId, PKCE_VERIFIER_CODEC_ERROR_CODES.KEY_UNAVAILABLE);
    let nonce;
    let plaintext;
    let ciphertext;
    let tag;
    try {
      nonce = makeNonce(randomBytes);
      plaintext = Buffer.from(tuple.verifier, "ascii");
      const cipher = crypto.createCipheriv(AES_ALGORITHM, key, nonce);
      cipher.setAAD(buildAssociatedData({ keyId: activeKeyId, ...tuple }), { plaintextLength: plaintext.length });
      ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      tag = cipher.getAuthTag();
      if (tag.length !== PKCE_VERIFIER_CODEC_TAG_BYTES
        || ciphertext.length < PKCE_VERIFIER_CODEC_MIN_VERIFIER_BYTES
        || ciphertext.length > PKCE_VERIFIER_CODEC_MAX_VERIFIER_BYTES) {
        throw codecError(PKCE_VERIFIER_CODEC_ERROR_CODES.ENCRYPTION_FAILED);
      }
    } catch (error) {
      if (error instanceof PkceVerifierCodecError) throw error;
      throw codecError(PKCE_VERIFIER_CODEC_ERROR_CODES.ENCRYPTION_FAILED);
    } finally {
      plaintext?.fill(0);
      if (Buffer.isBuffer(key)) key.fill(0);
    }

    const envelope = {
      version: PKCE_VERIFIER_CODEC_VERSION,
      key_id: activeKeyId,
      nonce: encodeBase64Url(nonce),
      ciphertext: encodeBase64Url(ciphertext),
      tag: encodeBase64Url(tag)
    };
    const serialized = JSON.stringify(envelope);
    if (Buffer.byteLength(serialized, "utf8") > maxSerializedBytes) {
      throw codecError(PKCE_VERIFIER_CODEC_ERROR_CODES.ENCRYPTION_FAILED);
    }
    return serialized;
  }

  function open(serialized, binding) {
    const tuple = normalizeBinding(binding);
    const envelope = parseEnvelope(serialized, maxSerializedBytes);
    let key;
    let plaintext;
    try {
      key = resolveKey(keyResolver, envelope.key_id, PKCE_VERIFIER_CODEC_ERROR_CODES.ENVELOPE_INVALID);
      const nonce = decodeBase64Url(envelope.nonce, PKCE_VERIFIER_CODEC_NONCE_BYTES, PKCE_VERIFIER_CODEC_NONCE_BYTES);
      const ciphertext = decodeBase64Url(
        envelope.ciphertext,
        PKCE_VERIFIER_CODEC_MIN_VERIFIER_BYTES,
        PKCE_VERIFIER_CODEC_MAX_VERIFIER_BYTES
      );
      const tag = decodeBase64Url(envelope.tag, PKCE_VERIFIER_CODEC_TAG_BYTES, PKCE_VERIFIER_CODEC_TAG_BYTES);
      const aad = buildAssociatedData({ keyId: envelope.key_id, ...tuple });
      const decipher = crypto.createDecipheriv(AES_ALGORITHM, key, nonce);
      decipher.setAAD(aad, { plaintextLength: ciphertext.length });
      decipher.setAuthTag(tag);
      plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      if (plaintext.length < PKCE_VERIFIER_CODEC_MIN_VERIFIER_BYTES
        || plaintext.length > PKCE_VERIFIER_CODEC_MAX_VERIFIER_BYTES) throw envelopeError();
      const verifier = plaintext.toString("ascii");
      if (!PKCE_VERIFIER_PATTERN.test(verifier) || Buffer.byteLength(verifier, "ascii") !== plaintext.length) {
        throw envelopeError();
      }
      const currentTime = readClock(now);
      if (tuple.expiresAt <= currentTime) throw codecError(PKCE_VERIFIER_CODEC_ERROR_CODES.EXPIRED);
      return Object.freeze({ verifier });
    } catch (error) {
      if (error instanceof PkceVerifierCodecError) throw error;
      throw envelopeError();
    } finally {
      plaintext?.fill(0);
      if (Buffer.isBuffer(key)) key.fill(0);
    }
  }

  return Object.freeze({
    seal,
    open,
    encrypt: seal,
    decrypt: open,
    encode: seal,
    decode: open,
    activeKeyId,
    version: PKCE_VERIFIER_CODEC_VERSION
  });
}

function normalizeSealInput(value) {
  assertExactKeys(value, SEAL_INPUT_KEYS, PKCE_VERIFIER_CODEC_ERROR_CODES.INPUT_INVALID);
  return Object.freeze({
    verifier: normalizeVerifier(value.verifier),
    attemptId: normalizeUuid(value.attemptId, MAX_ATTEMPT_ID_BYTES),
    oauthStateId: normalizeUuid(value.oauthStateId, MAX_OAUTH_STATE_ID_BYTES),
    redirectUri: normalizeRedirectUri(value.redirectUri),
    expiresAt: normalizeExpiry(value.expiresAt)
  });
}

function normalizeBinding(value) {
  assertExactKeys(value, BINDING_KEYS, PKCE_VERIFIER_CODEC_ERROR_CODES.INPUT_INVALID);
  return Object.freeze({
    attemptId: normalizeUuid(value.attemptId, MAX_ATTEMPT_ID_BYTES),
    oauthStateId: normalizeUuid(value.oauthStateId, MAX_OAUTH_STATE_ID_BYTES),
    redirectUri: normalizeRedirectUri(value.redirectUri),
    expiresAt: normalizeExpiry(value.expiresAt)
  });
}

function normalizeVerifier(value) {
  if (typeof value !== "string" || !PKCE_VERIFIER_PATTERN.test(value)
    || Buffer.byteLength(value, "ascii") < PKCE_VERIFIER_CODEC_MIN_VERIFIER_BYTES
    || Buffer.byteLength(value, "ascii") > PKCE_VERIFIER_CODEC_MAX_VERIFIER_BYTES) {
    throw codecError(PKCE_VERIFIER_CODEC_ERROR_CODES.INPUT_INVALID);
  }
  return value;
}

function normalizeBindingText(value, maxBytes) {
  if (typeof value !== "string" || !PRINTABLE_ASCII_PATTERN.test(value)
    || Buffer.byteLength(value, "utf8") > maxBytes) {
    throw codecError(PKCE_VERIFIER_CODEC_ERROR_CODES.INPUT_INVALID);
  }
  return value;
}

function normalizeUuid(value, maxBytes) {
  const normalized = normalizeBindingText(value, maxBytes);
  if (!UUID_V4.test(normalized)) throw codecError(PKCE_VERIFIER_CODEC_ERROR_CODES.INPUT_INVALID);
  return normalized.toLowerCase();
}

function normalizeRedirectUri(value) {
  const normalized = normalizeBindingText(value, MAX_REDIRECT_URI_BYTES);
  if (/\s/u.test(normalized)) throw codecError(PKCE_VERIFIER_CODEC_ERROR_CODES.INPUT_INVALID);
  try {
    const url = new URL(normalized);
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) throw new Error("invalid");
  } catch {
    throw codecError(PKCE_VERIFIER_CODEC_ERROR_CODES.INPUT_INVALID);
  }
  return normalized;
}

function normalizeExpiry(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw codecError(PKCE_VERIFIER_CODEC_ERROR_CODES.INPUT_INVALID);
  return value;
}

function normalizeKeyId(value, errorCode) {
  if (typeof value !== "string" || value.length < MIN_KEY_ID_LENGTH || value.length > MAX_KEY_ID_LENGTH || !KEY_ID_PATTERN.test(value)) {
    throw codecError(errorCode);
  }
  return value;
}

function resolveKey(keyResolver, keyId, errorCode) {
  let resolved;
  try {
    resolved = keyResolver(keyId);
    if (resolved && typeof resolved.then === "function") throw new Error("async key resolver is unsupported");
    if (Buffer.isBuffer(resolved) || resolved instanceof Uint8Array) {
      if (resolved.byteLength !== KEY_BYTES) throw new Error("invalid key length");
      return Buffer.from(resolved);
    }
    if (resolved?.type === "secret" && resolved.symmetricKeySize === KEY_BYTES) return resolved;
  } catch {
    throw codecError(errorCode);
  }
  throw codecError(errorCode);
}

function makeNonce(randomBytes) {
  let value;
  try {
    value = randomBytes(PKCE_VERIFIER_CODEC_NONCE_BYTES);
  } catch {
    throw codecError(PKCE_VERIFIER_CODEC_ERROR_CODES.RANDOMNESS_UNAVAILABLE);
  }
  if (!(Buffer.isBuffer(value) || value instanceof Uint8Array) || value.byteLength !== PKCE_VERIFIER_CODEC_NONCE_BYTES) {
    throw codecError(PKCE_VERIFIER_CODEC_ERROR_CODES.RANDOMNESS_UNAVAILABLE);
  }
  return Buffer.from(value);
}

function buildAssociatedData({ keyId, attemptId, oauthStateId, redirectUri, expiresAt }) {
  return Buffer.from(JSON.stringify({
    domain: DOMAIN,
    version: PKCE_VERIFIER_CODEC_VERSION,
    key_id: keyId,
    attempt_id: attemptId,
    oauth_state_id: oauthStateId,
    redirect_uri: redirectUri,
    expires_at: expiresAt
  }), "utf8");
}

function parseEnvelope(serialized, maxSerializedBytes) {
  if (typeof serialized !== "string" || serialized.length === 0 || Buffer.byteLength(serialized, "utf8") > maxSerializedBytes) {
    throw envelopeError();
  }
  let envelope;
  try {
    envelope = JSON.parse(serialized);
  } catch {
    throw envelopeError();
  }
  if (!isPlainObject(envelope) || !sameOrderedKeys(envelope, ENVELOPE_KEYS) || JSON.stringify(envelope) !== serialized) {
    throw envelopeError();
  }
  if (envelope.version !== PKCE_VERIFIER_CODEC_VERSION
    || typeof envelope.key_id !== "string"
    || envelope.key_id.length > MAX_ENVELOPE_KEY_LENGTH
    || !KEY_ID_PATTERN.test(envelope.key_id)
    || !isCanonicalBase64Url(envelope.nonce)
    || !isCanonicalBase64Url(envelope.ciphertext)
    || !isCanonicalBase64Url(envelope.tag)) {
    throw envelopeError();
  }
  return envelope;
}

function decodeBase64Url(value, minBytes, maxBytes) {
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length < minBytes || decoded.length > maxBytes || decoded.toString("base64url") !== value) throw envelopeError();
  return decoded;
}

function encodeBase64Url(value) {
  return Buffer.from(value).toString("base64url");
}

function isCanonicalBase64Url(value) {
  return typeof value === "string" && value.length > 0 && /^[A-Za-z0-9_-]+$/u.test(value)
    && Buffer.from(value, "base64url").toString("base64url") === value;
}

function assertExactKeys(value, expectedKeys, code) {
  if (!isPlainObject(value)) throw codecError(code);
  const keys = Reflect.ownKeys(value);
  if (keys.length !== expectedKeys.length || keys.some((key) => typeof key !== "string" || !expectedKeys.includes(key))) throw codecError(code);
}

function assertAllowedKeys(value, allowedKeys, code) {
  if (!isPlainObject(value)) throw codecError(code);
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string" || !allowedKeys.includes(key))) throw codecError(code);
}

function sameOrderedKeys(value, expectedKeys) {
  const keys = Object.keys(value);
  return keys.length === expectedKeys.length && keys.every((key, index) => key === expectedKeys[index]);
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function readClock(now) {
  let value;
  try { value = now(); } catch { throw codecError(PKCE_VERIFIER_CODEC_ERROR_CODES.CLOCK_UNAVAILABLE); }
  if (!Number.isSafeInteger(value) || value < 0) throw codecError(PKCE_VERIFIER_CODEC_ERROR_CODES.CLOCK_UNAVAILABLE);
  return value;
}

function codecError(code) {
  return new PkceVerifierCodecError(code);
}

function envelopeError() {
  return codecError(PKCE_VERIFIER_CODEC_ERROR_CODES.ENVELOPE_INVALID);
}
