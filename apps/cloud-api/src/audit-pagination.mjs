import { createHmac, timingSafeEqual } from "node:crypto";

export const AUDIT_CURSOR_VERSION = 1;
export const AUDIT_CURSOR_RESOURCE = "device_audit_events";
export const AUDIT_CURSOR_MAX_LENGTH = 512;
export const AUDIT_CURSOR_TTL_MS = 24 * 60 * 60 * 1000;
export const AUDIT_PAGE_DEFAULT_LIMIT = 100;
export const AUDIT_PAGE_MAX_LIMIT = 500;
export const AUDIT_CURSOR_ERROR_CODE = "ERR_AUDIT_CURSOR_INVALID";

const MAC_BYTES = 32;
const MAC_LENGTH = 43;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u;
const HMAC_DOMAIN = "agentpass:cloud-audit-cursor:v1\u0000";
const ENVELOPE_KEYS = Object.freeze([
  "version",
  "resource",
  "organization_id",
  "device_id",
  "device_timestamp",
  "event_id",
  "expires_at",
  "mac"
]);
const PAYLOAD_KEYS = Object.freeze(ENVELOPE_KEYS.slice(0, -1));

export class AuditCursorError extends Error {
  constructor() {
    super("The audit pagination cursor is invalid");
    this.name = "AuditCursorError";
    this.code = AUDIT_CURSOR_ERROR_CODE;
  }
}

/**
 * Creates an authenticated opaque cursor for the Cloud device-audit stream.
 * The cursor contains only a scope-bound immutable keyset position and an
 * expiry. Its HMAC secret must stay server-side.
 */
export function createAuditCursorCodec({ secret, now = () => Date.now(), ttlMs = AUDIT_CURSOR_TTL_MS, maxLength = AUDIT_CURSOR_MAX_LENGTH } = {}) {
  const hmacSecret = normalizeSecret(secret);
  if (typeof now !== "function") throw new TypeError("now must be a function");
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1_000 || ttlMs > 7 * 24 * 60 * 60 * 1000) throw new TypeError("ttlMs is invalid");
  if (!Number.isSafeInteger(maxLength) || maxLength < 256 || maxLength > AUDIT_CURSOR_MAX_LENGTH) throw new TypeError("maxLength is invalid");

  return Object.freeze({ encode, decode });

  function encode(input = {}) {
    try {
      const issuedAt = finiteNow(now());
      const payload = normalizePayload({
        ...input,
        version: AUDIT_CURSOR_VERSION,
        resource: AUDIT_CURSOR_RESOURCE,
        expires_at: input.expires_at ?? new Date(issuedAt + ttlMs).toISOString()
      });
      const payloadText = JSON.stringify(payload);
      const mac = sign(payloadText, hmacSecret);
      const cursor = encodeBase64Url(JSON.stringify({ ...payload, mac: encodeBase64Url(mac) }));
      if (cursor.length > maxLength) throw invalidCursor();
      return cursor;
    } catch (error) {
      if (error instanceof AuditCursorError) throw error;
      throw invalidCursor();
    }
  }

  function decode(cursor, binding = {}) {
    try {
      if (typeof cursor !== "string" || cursor.length < 1 || cursor.length > maxLength || !BASE64URL.test(cursor)) throw invalidCursor();
      const text = decodeUtf8Strict(decodeBase64Url(cursor));
      const envelope = parseExactEnvelope(text);
      const payload = normalizePayload(Object.fromEntries(PAYLOAD_KEYS.map((key) => [key, envelope[key]])));
      const suppliedMac = decodeMac(envelope.mac);
      if (!constantTimeMacEqual(sign(JSON.stringify(payload), hmacSecret), suppliedMac)) throw invalidCursor();
      assertBinding(payload, binding);
      if (Date.parse(payload.expires_at) <= finiteNow(now())) throw invalidCursor();
      return Object.freeze({ ...payload });
    } catch (error) {
      if (error instanceof AuditCursorError) throw error;
      throw invalidCursor();
    }
  }
}

export function normalizeAuditPageInput(input = {}) {
  if (!isObject(input)) throw new TypeError("audit page input must be an object");
  const limit = input.limit === undefined ? AUDIT_PAGE_DEFAULT_LIMIT : input.limit;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > AUDIT_PAGE_MAX_LIMIT) throw new TypeError("audit page limit is invalid");
  if (input.cursor !== undefined && (typeof input.cursor !== "string" || input.cursor.length < 1 || input.cursor.length > AUDIT_CURSOR_MAX_LENGTH || !BASE64URL.test(input.cursor))) throw invalidCursor();
  const deviceId = input.device_id ?? input.deviceId;
  if (deviceId === undefined) throw new TypeError("device_id is required");
  const normalizedDeviceId = requiredUuid(deviceId);
  return Object.freeze({ limit, ...(input.cursor === undefined ? {} : { cursor: input.cursor }), device_id: normalizedDeviceId });
}

export function auditCursorBinding(organizationId, deviceId) {
  return Object.freeze({ resource: AUDIT_CURSOR_RESOURCE, organization_id: requiredUuid(organizationId), device_id: requiredUuid(deviceId) });
}

function normalizePayload(value) {
  if (!isObject(value)) throw invalidCursor();
  const keys = Object.keys(value);
  if (keys.length !== PAYLOAD_KEYS.length || keys.some((key) => !PAYLOAD_KEYS.includes(key))) throw invalidCursor();
  return Object.freeze({
    version: requiredVersion(value.version),
    resource: requiredResource(value.resource),
    organization_id: requiredUuid(value.organization_id),
    device_id: requiredUuid(value.device_id),
    device_timestamp: requiredTimestamp(value.device_timestamp),
    event_id: requiredUuid(value.event_id),
    expires_at: requiredTimestamp(value.expires_at)
  });
}

function parseExactEnvelope(text) {
  let envelope;
  try { envelope = JSON.parse(text); } catch { throw invalidCursor(); }
  if (!isObject(envelope)) throw invalidCursor();
  const keys = Object.keys(envelope);
  if (keys.length !== ENVELOPE_KEYS.length || keys.some((key, index) => key !== ENVELOPE_KEYS[index]) || JSON.stringify(envelope) !== text) throw invalidCursor();
  return envelope;
}

function assertBinding(payload, binding) {
  if (!isObject(binding)) throw invalidCursor();
  const expected = auditCursorBinding(binding.organization_id, binding.device_id);
  if (payload.resource !== expected.resource || payload.organization_id !== expected.organization_id || payload.device_id !== expected.device_id) throw invalidCursor();
}

function normalizeSecret(value) {
  let bytes;
  if (typeof value === "string" && value.length > 0) bytes = Buffer.from(value, "utf8");
  else if (Buffer.isBuffer(value) && value.length > 0) bytes = Buffer.from(value);
  else if (value instanceof Uint8Array && value.byteLength > 0) bytes = Buffer.from(value);
  else throw new TypeError("secret must be a non-empty string or byte array");
  if (bytes.length < 32 || bytes.length > 4 * 1024) throw new TypeError("secret length is invalid");
  return bytes;
}

function requiredVersion(value) { if (value !== AUDIT_CURSOR_VERSION) throw invalidCursor(); return value; }
function requiredResource(value) { if (value !== AUDIT_CURSOR_RESOURCE) throw invalidCursor(); return value; }
function requiredUuid(value) { if (typeof value !== "string" || !UUID.test(value)) throw invalidCursor(); return value.toLowerCase(); }
function requiredTimestamp(value) {
  if (typeof value !== "string" || !RFC3339.test(value) || !Number.isFinite(Date.parse(value))) throw invalidCursor();
  return new Date(value).toISOString();
}
function finiteNow(value) {
  const result = typeof value === "number" ? value : value instanceof Date ? value.getTime() : Date.parse(value);
  if (!Number.isFinite(result)) throw new TypeError("clock returned an invalid time");
  return result;
}
function sign(payloadText, secret) { return createHmac("sha256", secret).update(HMAC_DOMAIN, "utf8").update(payloadText, "utf8").digest(); }
function decodeMac(value) {
  if (typeof value !== "string" || !BASE64URL.test(value) || value.length !== MAC_LENGTH) return Buffer.alloc(0);
  try { const bytes = Buffer.from(value, "base64url"); return bytes.toString("base64url") === value ? bytes : Buffer.alloc(0); }
  catch { return Buffer.alloc(0); }
}
function constantTimeMacEqual(expected, supplied) {
  const candidate = Buffer.alloc(MAC_BYTES);
  supplied.copy(candidate, 0, 0, Math.min(supplied.length, candidate.length));
  return supplied.length === MAC_BYTES && timingSafeEqual(expected, candidate);
}
function encodeBase64Url(value) { return Buffer.from(value).toString("base64url"); }
function decodeBase64Url(value) { const bytes = Buffer.from(value, "base64url"); if (bytes.length < 1 || bytes.toString("base64url") !== value) throw invalidCursor(); return bytes; }
function decodeUtf8Strict(bytes) { const text = bytes.toString("utf8"); if (!Buffer.from(text, "utf8").equals(bytes)) throw invalidCursor(); return text; }
function isObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function invalidCursor() { return new AuditCursorError(); }

export default createAuditCursorCodec;
