import crypto from "node:crypto";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const KEY_ID_PATTERN = /^refresh-nonce-v[1-9][0-9]{0,8}$/u;
const NONCE_BYTES = 16;
const MIN_KEY_BYTES = 32;
const MAX_KEY_BYTES = 128;

/**
 * This domain is part of the wire-compatible nonce derivation contract.
 * Changing it requires a new codec version and a new persisted key id.
 */
export const REFRESH_NONCE_DOMAIN = "agentpass/refresh-nonce/v1";
export const REFRESH_NONCE_KEY_ID_PATTERN = KEY_ID_PATTERN;
export const REFRESH_NONCE_BYTES = NONCE_BYTES;

/**
 * Derive the refresh-hint nonce from an immutable outbox identity.
 *
 * The returned object's raw `nonce` and `nonce_bytes` fields are deliberately
 * non-enumerable.  Cloud signing code may explicitly read `nonce`, but JSON,
 * structured logging, and ordinary object inspection contain only metadata and
 * the digest.  The repository passes `nonce_digest_bytes` to SQL; it never
 * passes either raw field.
 */
export function createRefreshNonceCodec({ keys, activeKeyId } = {}) {
  const keyRing = normalizeKeyRing(keys);
  const normalizedActiveKeyId = normalizeKeyId(activeKeyId, "active_key_id");
  if (!keyRing.has(normalizedActiveKeyId)) throw new RefreshNonceCodecError("ERR_REFRESH_NONCE_KEY_UNAVAILABLE", "active refresh nonce key is unavailable");

  function derive(input = {}) {
    const tuple = normalizeTuple(input);
    const keyId = normalizeKeyId(input.key_id ?? input.keyId ?? normalizedActiveKeyId, "key_id");
    const key = keyRing.get(keyId);
    if (key === undefined) throw new RefreshNonceCodecError("ERR_REFRESH_NONCE_KEY_UNAVAILABLE", "refresh nonce key is unavailable");

    const preimage = Buffer.from([
      `${REFRESH_NONCE_DOMAIN}\0`,
      `organization_id\0${tuple.organization_id}\0`,
      `device_id\0${tuple.device_id}\0`,
      `authority_generation\0${tuple.authority_generation}\0`,
      `outbox_id\0${tuple.outbox_id}\0`
    ].join(""), "utf8");
    const nonce = crypto.createHmac("sha256", key).update(preimage).digest().subarray(0, NONCE_BYTES);
    const digest = crypto.createHash("sha256").update(nonce).digest();
    const result = {
      version: 1,
      key_id: keyId,
      organization_id: tuple.organization_id,
      device_id: tuple.device_id,
      authority_generation: tuple.authority_generation,
      outbox_id: tuple.outbox_id,
      nonce_digest: digest.toString("hex")
    };
    defineHidden(result, "nonce", Buffer.from(nonce));
    defineHidden(result, "nonce_bytes", Buffer.from(nonce));
    defineHidden(result, "nonce_digest_bytes", Buffer.from(digest));
    defineHidden(result, "nonce_base64url", nonce.toString("base64url"));
    return Object.freeze(result);
  }

  return Object.freeze({
    activeKeyId: normalizedActiveKeyId,
    derive,
    deriveMetadata(input = {}) {
      const derived = derive(input);
      return Object.freeze({
        version: derived.version,
        key_id: derived.key_id,
        organization_id: derived.organization_id,
        device_id: derived.device_id,
        authority_generation: derived.authority_generation,
        outbox_id: derived.outbox_id,
        nonce_digest: derived.nonce_digest
      });
    },
    hasKey(keyId) {
      return keyRing.has(normalizeKeyId(keyId, "key_id"));
    },
    matchesDigest(derived, expectedDigest) {
      return timingSafeRefreshNonceDigestEqual(derived?.nonce_digest_bytes, expectedDigest);
    }
  });
}

/**
 * Compare a reconstructed digest with the database metadata without using a
 * variable-length string comparison.  Malformed values fail closed.  This is
 * intended for the Cloud hint boundary before it signs a refresh hint.
 */
export function timingSafeRefreshNonceDigestEqual(actualDigest, expectedDigest) {
  const actual = normalizeDigestBytes(actualDigest);
  const expected = normalizeDigestBytes(expectedDigest);
  if (actual === null || expected === null || actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(actual, expected);
}

export class RefreshNonceCodecError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = "RefreshNonceCodecError";
    this.code = code;
    this.details = details;
  }
}

function normalizeKeyRing(keys) {
  if (keys instanceof Map) {
    if (keys.size === 0) throw new RefreshNonceCodecError("ERR_REFRESH_NONCE_KEY_UNAVAILABLE", "at least one refresh nonce key is required");
    return new Map([...keys.entries()].map(([keyId, secret]) => [normalizeKeyId(keyId, "key_id"), normalizeSecret(secret, keyId)]));
  }
  if (keys === null || typeof keys !== "object" || Array.isArray(keys)) throw new RefreshNonceCodecError("ERR_REFRESH_NONCE_KEY_UNAVAILABLE", "refresh nonce keys must be a non-empty map or object");
  const entries = Object.entries(keys);
  if (entries.length === 0) throw new RefreshNonceCodecError("ERR_REFRESH_NONCE_KEY_UNAVAILABLE", "at least one refresh nonce key is required");
  return new Map(entries.map(([keyId, secret]) => [normalizeKeyId(keyId, "key_id"), normalizeSecret(secret, keyId)]));
}

function normalizeSecret(secret, keyId) {
  if (!(Buffer.isBuffer(secret) || secret instanceof Uint8Array)) throw new RefreshNonceCodecError("ERR_REFRESH_NONCE_KEY_INVALID", `refresh nonce key ${String(keyId)} must be bytes`);
  if (secret.length < MIN_KEY_BYTES || secret.length > MAX_KEY_BYTES) throw new RefreshNonceCodecError("ERR_REFRESH_NONCE_KEY_INVALID", `refresh nonce key ${String(keyId)} has an invalid length`);
  return Buffer.from(secret);
}

function normalizeTuple(input) {
  if (input === null || typeof input !== "object" || Array.isArray(input)) throw new RefreshNonceCodecError("ERR_REFRESH_NONCE_INPUT", "refresh nonce input must be an object");
  return Object.freeze({
    organization_id: normalizeUuid(input.organization_id, "organization_id"),
    device_id: normalizeUuid(input.device_id, "device_id"),
    authority_generation: normalizeGeneration(input.authority_generation),
    outbox_id: normalizeUuid(input.outbox_id, "outbox_id")
  });
}

function normalizeUuid(value, field) {
  if (typeof value !== "string" || !UUID.test(value)) throw new RefreshNonceCodecError("ERR_REFRESH_NONCE_INPUT", `${field} must be a UUID`);
  return value.toLowerCase();
}

function normalizeGeneration(value) {
  const normalized = typeof value === "string" && /^[0-9]+$/u.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(normalized) || normalized < 1) throw new RefreshNonceCodecError("ERR_REFRESH_NONCE_INPUT", "authority_generation must be a positive safe integer");
  return String(normalized);
}

function normalizeKeyId(value, field) {
  if (typeof value !== "string" || !KEY_ID_PATTERN.test(value)) throw new RefreshNonceCodecError("ERR_REFRESH_NONCE_KEY_ID", `${field} is not an exact canonical refresh nonce key id`);
  return value;
}

function normalizeDigestBytes(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return value.length === 32 ? Buffer.from(value) : null;
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) return null;
  return Buffer.from(value, "hex");
}

function defineHidden(target, property, value) {
  Object.defineProperty(target, property, { configurable: false, enumerable: false, writable: false, value });
}
