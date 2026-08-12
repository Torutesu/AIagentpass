import { createHmac, timingSafeEqual } from "node:crypto";

export const HUMAN_CURSOR_CODEC_VERSION = 1;
export const HUMAN_CURSOR_MAX_LENGTH = 512;
export const HUMAN_CURSOR_MIN_SECRET_BYTES = 32;
export const HUMAN_CURSOR_DIRECTIONS = Object.freeze(["asc", "desc"]);

export const HUMAN_CURSOR_ERROR_CODES = Object.freeze({
  INVALID_CURSOR: "human_cursor_invalid"
});

const INVALID_CURSOR_MESSAGE = "The pagination cursor is invalid";
const MAC_BYTES = 32;
const MAC_LENGTH = 43;
const HMAC_DOMAIN = "agentpass:human-api-cursor:v1\u0000";
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const RESOURCE = /^[A-Za-z][A-Za-z0-9._-]{0,63}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u;
const ENVELOPE_KEYS = Object.freeze([
  "version",
  "resource",
  "tenant_id",
  "member_id",
  "created_at",
  "id",
  "direction",
  "mac"
]);
const PAYLOAD_KEYS = Object.freeze(ENVELOPE_KEYS.slice(0, -1));
const INPUT_KEYS = Object.freeze(PAYLOAD_KEYS.slice(1));

export class HumanCursorCodecError extends Error {
  constructor() {
    super(INVALID_CURSOR_MESSAGE);
    this.name = "HumanCursorCodecError";
    this.code = HUMAN_CURSOR_ERROR_CODES.INVALID_CURSOR;
  }
}

/**
 * Creates an authenticated, opaque cursor codec for Human API keyset pages.
 *
 * The caller supplies a server-side HMAC secret. The secret is copied into the
 * codec and is never included in a cursor or an error. A cursor is bound to a
 * resource, tenant, member, and traversal direction, and contains only the
 * immutable keyset tuple (created_at, id).
 */
export function createHumanCursorCodec({ secret, maxLength = HUMAN_CURSOR_MAX_LENGTH } = {}) {
  const hmacSecret = normalizeSecret(secret);
  if (!Number.isSafeInteger(maxLength) || maxLength < 64 || maxLength > HUMAN_CURSOR_MAX_LENGTH) {
    throw new TypeError("maxLength must be an integer between 64 and 512");
  }

  return Object.freeze({ encode, decode });

  function encode(input) {
    try {
      const payload = normalizePayload(input, { includeVersion: false });
      const payloadText = JSON.stringify(payload);
      const mac = sign(payloadText, hmacSecret);
      const cursor = encodeBase64Url(JSON.stringify({ ...payload, mac: encodeBase64Url(mac) }));
      if (cursor.length > maxLength) throw invalidCursor();
      return cursor;
    } catch (error) {
      if (error instanceof HumanCursorCodecError) throw error;
      throw invalidCursor();
    }
  }

  function decode(cursor, binding) {
    try {
      if (typeof cursor !== "string" || cursor.length < 1 || cursor.length > maxLength || !BASE64URL.test(cursor)) {
        throw invalidCursor();
      }

      const encoded = decodeBase64Url(cursor);
      const text = decodeUtf8Strict(encoded);
      const envelope = parseExactEnvelope(text);
      const payload = normalizePayload(payloadFromEnvelope(envelope));
      const expectedMac = sign(JSON.stringify(payload), hmacSecret);
      const suppliedMac = decodeMac(envelope.mac);

      // Always compare fixed-size buffers. The length check is kept separate
      // so malformed MAC lengths do not make timingSafeEqual throw early.
      const macMatches = constantTimeMacEqual(expectedMac, suppliedMac);
      if (!macMatches) throw invalidCursor();

      assertBinding(payload, binding);
      return Object.freeze({ ...payload });
    } catch (error) {
      if (error instanceof HumanCursorCodecError) throw error;
      throw invalidCursor();
    }
  }
}

// Short aliases keep the module convenient for adapters while retaining the
// explicit Human API names used by the cloud application.
export const createCursorCodec = createHumanCursorCodec;
export const CursorCodecError = HumanCursorCodecError;
export const CURSOR_CODEC_ERROR_CODES = HUMAN_CURSOR_ERROR_CODES;

function normalizeSecret(value) {
  let bytes;
  if (typeof value === "string" && value.length > 0) bytes = Buffer.from(value, "utf8");
  else if (Buffer.isBuffer(value) && value.length > 0) bytes = Buffer.from(value);
  else if (value instanceof Uint8Array && value.byteLength > 0) bytes = Buffer.from(value);
  else throw new TypeError("secret must be a non-empty string or byte array");
  if (bytes.length < HUMAN_CURSOR_MIN_SECRET_BYTES) throw new TypeError("secret must contain at least 32 bytes");
  if (bytes.length > 4 * 1024) throw new TypeError("secret is too long");
  return bytes;
}

function normalizePayload(value, { includeVersion = true } = {}) {
  if (!isObject(value)) throw invalidCursor();
  const keys = Object.keys(value);
  const expectedKeys = includeVersion ? PAYLOAD_KEYS : INPUT_KEYS;
  if (keys.length !== expectedKeys.length || keys.some((key) => !expectedKeys.includes(key))) throw invalidCursor();
  return Object.freeze({
    version: includeVersion ? requiredVersion(value.version) : HUMAN_CURSOR_CODEC_VERSION,
    resource: requiredResource(value.resource),
    tenant_id: requiredUuid(value.tenant_id),
    member_id: requiredUuid(value.member_id),
    created_at: requiredTimestamp(value.created_at),
    id: requiredUuid(value.id),
    direction: requiredDirection(value.direction)
  });
}

function parseExactEnvelope(text) {
  let envelope;
  try {
    envelope = JSON.parse(text);
  } catch {
    throw invalidCursor();
  }
  if (!isObject(envelope)) throw invalidCursor();
  const keys = Object.keys(envelope);
  if (keys.length !== ENVELOPE_KEYS.length || keys.some((key, index) => key !== ENVELOPE_KEYS[index])) throw invalidCursor();
  if (JSON.stringify(envelope) !== text) throw invalidCursor();
  return envelope;
}

function payloadFromEnvelope(envelope) {
  const payload = {};
  for (const key of PAYLOAD_KEYS) payload[key] = envelope[key];
  return payload;
}

function assertBinding(payload, binding) {
  if (!isObject(binding)) throw invalidCursor();
  const keys = Object.keys(binding);
  const allowed = new Set(["resource", "tenant_id", "member_id", "direction"]);
  if (keys.some((key) => !allowed.has(key))) throw invalidCursor();
  if (payload.resource !== requiredResource(binding.resource)) throw invalidCursor();
  if (payload.tenant_id !== requiredUuid(binding.tenant_id)) throw invalidCursor();
  if (payload.member_id !== requiredUuid(binding.member_id)) throw invalidCursor();
  if (binding.direction !== undefined && payload.direction !== requiredDirection(binding.direction)) throw invalidCursor();
}

function requiredVersion(value) {
  if (value !== HUMAN_CURSOR_CODEC_VERSION) throw invalidCursor();
  return value;
}

function requiredResource(value) {
  if (typeof value !== "string" || !RESOURCE.test(value)) throw invalidCursor();
  return value;
}

function requiredUuid(value) {
  if (typeof value !== "string" || !UUID.test(value)) throw invalidCursor();
  return value.toLowerCase();
}

function requiredTimestamp(value) {
  if (typeof value !== "string" || !RFC3339.test(value) || !validCalendarTimestamp(value)) throw invalidCursor();
  return value;
}

function validCalendarTimestamp(value) {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/u.exec(value);
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const zone = match[8];
  const daysInMonth = [31, isLeapYear(year) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
  if (!Number.isInteger(daysInMonth) || day < 1 || day > daysInMonth || hour > 23 || minute > 59 || second > 59) return false;
  if (zone !== "Z" && (Number(zone.slice(1, 3)) > 23 || Number(zone.slice(4, 6)) > 59)) return false;
  return Number.isFinite(Date.parse(value));
}

function isLeapYear(year) {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function requiredDirection(value) {
  if (!HUMAN_CURSOR_DIRECTIONS.includes(value)) throw invalidCursor();
  return value;
}

function sign(payloadText, secret) {
  return createHmac("sha256", secret).update(HMAC_DOMAIN, "utf8").update(payloadText, "utf8").digest();
}

function decodeMac(value) {
  if (typeof value !== "string" || !BASE64URL.test(value)) return Buffer.alloc(0);
  if (value.length !== MAC_LENGTH) return Buffer.alloc(0);
  let bytes;
  try {
    bytes = Buffer.from(value, "base64url");
  } catch {
    return Buffer.alloc(0);
  }
  if (bytes.toString("base64url") !== value) return Buffer.alloc(0);
  return bytes;
}

function constantTimeMacEqual(expected, supplied) {
  const candidate = Buffer.alloc(MAC_BYTES);
  supplied.copy(candidate, 0, 0, Math.min(supplied.length, candidate.length));
  const equal = timingSafeEqual(expected, candidate);
  return supplied.length === MAC_BYTES && expected.length === MAC_BYTES && equal;
}

function encodeBase64Url(value) {
  return Buffer.from(value).toString("base64url");
}

function decodeBase64Url(value) {
  if (!BASE64URL.test(value)) throw invalidCursor();
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length < 1 || bytes.toString("base64url") !== value) throw invalidCursor();
  return bytes;
}

function decodeUtf8Strict(bytes) {
  const text = bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(bytes)) throw invalidCursor();
  return text;
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function invalidCursor() {
  return new HumanCursorCodecError();
}

export default createHumanCursorCodec;
