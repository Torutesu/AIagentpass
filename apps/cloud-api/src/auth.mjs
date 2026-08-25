import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const CLOCK_WINDOW_MS = 60_000;
const DEFAULT_REPLAY_LIMIT = 10_000;
const REPLAY_RETENTION_MS = CLOCK_WINDOW_MS * 2;
const TOKEN_KEY_BYTES = 32;
const TOKEN_SALT_BYTES = 16;
const SCRYPT_N = 16_384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_MAXMEM = 32 * 1024 * 1024;
const DEVICE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const NONCE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{31,127}$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const TOKEN_HASH_PATTERN = /^scrypt\$N=(\d+),r=(\d+),p=(\d+)\$([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/;
const ROLES = Object.freeze(["owner", "admin", "auditor", "viewer"]);
const ROLE_LEVEL = Object.freeze({ owner: 4, admin: 3, auditor: 2, viewer: 1 });

export const DEVICE_HEADERS = Object.freeze([
  "AgentPass-Device",
  "AgentPass-Timestamp",
  "AgentPass-Nonce",
  "AgentPass-Content-SHA256",
  "AgentPass-Signature"
]);

export const AUTH_ERROR_CODES = Object.freeze({
  INVALID_HEADERS: "invalid_auth_headers",
  INVALID_REQUEST: "invalid_auth_request",
  DEVICE_AUTH_FAILED: "device_auth_failed",
  DEVICE_DISABLED: "device_disabled",
  CLOCK_SKEW: "auth_clock_skew",
  REPLAY_DETECTED: "auth_replay_detected",
  REPLAY_CACHE_FULL: "auth_replay_cache_full",
  BODY_DIGEST_MISMATCH: "auth_body_digest_mismatch",
  INVALID_SIGNATURE: "invalid_device_signature",
  INVALID_TOKEN: "invalid_api_token",
  TOKEN_RECORD: "invalid_token_record",
  ORGANIZATION_MISMATCH: "organization_mismatch",
  ROLE_DENIED: "role_denied"
});

const AUTH_MESSAGES = Object.freeze({
  [AUTH_ERROR_CODES.INVALID_HEADERS]: "Authentication headers are invalid",
  [AUTH_ERROR_CODES.INVALID_REQUEST]: "Authentication request is invalid",
  [AUTH_ERROR_CODES.DEVICE_AUTH_FAILED]: "Device authentication failed",
  [AUTH_ERROR_CODES.DEVICE_DISABLED]: "Device authentication is disabled",
  [AUTH_ERROR_CODES.CLOCK_SKEW]: "Authentication timestamp is outside the allowed window",
  [AUTH_ERROR_CODES.REPLAY_DETECTED]: "Authentication request replay detected",
  [AUTH_ERROR_CODES.REPLAY_CACHE_FULL]: "Authentication replay cache is full",
  [AUTH_ERROR_CODES.BODY_DIGEST_MISMATCH]: "Authentication body digest does not match",
  [AUTH_ERROR_CODES.INVALID_SIGNATURE]: "Device signature is invalid",
  [AUTH_ERROR_CODES.INVALID_TOKEN]: "API token is invalid",
  [AUTH_ERROR_CODES.TOKEN_RECORD]: "API token record is invalid",
  [AUTH_ERROR_CODES.ORGANIZATION_MISMATCH]: "Organization authorization failed",
  [AUTH_ERROR_CODES.ROLE_DENIED]: "Organization role is insufficient"
});

export class AuthError extends Error {
  constructor(code) {
    super(AUTH_MESSAGES[code] ?? "Authentication failed");
    this.name = "AuthError";
    this.code = code;
  }
}

export const AuthenticationError = AuthError;
export { ROLES };

/**
 * The signed bytes are six newline-delimited fields. Query parameters are
 * sorted and RFC3986-encoded; the body itself is represented only by its
 * lowercase SHA-256 digest.
 */
export function canonicalDeviceRequest(input, pathArg, queryArg, digestArg, timestampArg, nonceArg) {
  const request = typeof input === "object" && input !== null
    ? input
    : { method: input, path: pathArg, query: queryArg, body_digest: digestArg, timestamp: timestampArg, nonce: nonceArg };
  const method = canonicalMethod(request.method);
  const target = canonicalTarget(request.path ?? request.url ?? request.target, request.query);
  const digest = request.body_digest ?? request.bodyDigest ?? request.content_sha256 ?? request.contentDigest;
  let bodyDigest;
  if (digest !== undefined) {
    if (typeof digest !== "string" || !DIGEST_PATTERN.test(digest)) fail(AUTH_ERROR_CODES.INVALID_REQUEST);
    bodyDigest = digest;
  } else {
    bodyDigest = sha256(request.body ?? Buffer.alloc(0));
  }
  const timestamp = canonicalTimestamp(request.timestamp ?? request.timestamp_ms);
  const nonce = canonicalNonce(request.nonce);
  return [method, target.path, target.query, bodyDigest, timestamp, nonce].join("\n");
}

export const canonicalRequest = canonicalDeviceRequest;

export function sha256(value) {
  return crypto.createHash("sha256").update(toBodyBytes(value)).digest("hex");
}

export const bodyDigest = sha256;

export function createReplayCache(maxEntries = DEFAULT_REPLAY_LIMIT) {
  if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) throw new TypeError("Replay cache limit is invalid");
  const cache = new Map();
  Object.defineProperty(cache, "maxEntries", { value: maxEntries, writable: false, enumerable: false });
  return cache;
}

/** A restart-safe replay cache for the single-process reference runtime. */
export function createPersistentReplayCache(file, maxEntries = DEFAULT_REPLAY_LIMIT) {
  if (typeof file !== "string" || !path.isAbsolute(file)) throw new TypeError("Replay cache path must be absolute");
  const parent = path.dirname(file);
  const parentStat = fs.lstatSync(parent);
  const uid = process.getuid?.();
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink() || (parentStat.mode & 0o077) !== 0 || (uid !== undefined && parentStat.uid !== uid)) throw new TypeError("Replay cache directory is unsafe");
  const cache = createReplayCache(maxEntries);
  if (fs.existsSync(file)) {
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 4 * 1024 * 1024 || (stat.mode & 0o077) !== 0 || (uid !== undefined && stat.uid !== uid)) throw new TypeError("Replay cache file is unsafe");
    let parsed;
    try { parsed = JSON.parse(fs.readFileSync(file, "utf8")); } catch { throw new TypeError("Replay cache file is invalid"); }
    if (!parsed || parsed.version !== 1 || !Array.isArray(parsed.entries) || parsed.entries.length > maxEntries) throw new TypeError("Replay cache file is invalid");
    for (const entry of parsed.entries) {
      if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== "string" || entry[0].length > 512 || !Number.isSafeInteger(entry[1]) || entry[1] < 0) throw new TypeError("Replay cache entry is invalid");
      Map.prototype.set.call(cache, entry[0], entry[1]);
    }
  }
  const persist = () => atomicReplayWrite(file, JSON.stringify({ version: 1, entries: [...cache] }));
  cache.set = function set(key, value) { Map.prototype.set.call(this, key, value); persist(); return this; };
  cache.delete = function remove(key) { const changed = Map.prototype.delete.call(this, key); if (changed) persist(); return changed; };
  cache.clear = function clear() { if (this.size > 0) { Map.prototype.clear.call(this); persist(); } };
  return cache;
}

function atomicReplayWrite(file, content) {
  const temporary = `${file}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  let descriptor;
  try {
    descriptor = fs.openSync(temporary, "wx", 0o600);
    fs.writeFileSync(descriptor, content);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor); descriptor = undefined;
    fs.renameSync(temporary, file);
    const parent = fs.openSync(path.dirname(file), fs.constants.O_RDONLY);
    try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
  } catch (error) {
    if (descriptor !== undefined) try { fs.closeSync(descriptor); } catch {}
    try { fs.unlinkSync(temporary); } catch {}
    throw error;
  }
}

/** Verify a device request against the currently enrolled device records. */
export function verifyDeviceRequest(request, enrolled, options = {}) {
  if (!request || typeof request !== "object" || Array.isArray(request)) fail(AUTH_ERROR_CODES.INVALID_REQUEST);
  if (Object.keys(options).length === 0 && enrolled && typeof enrolled === "object" && !Array.isArray(enrolled) && !(enrolled instanceof Map) && Array.isArray(enrolled.devices)) {
    options = enrolled;
    enrolled = enrolled.devices;
  }
  const headers = parseDeviceHeaders(request.headers ?? request);
  const method = request.method;
  const path = request.path ?? request.url ?? request.target;
  const body = request.body ?? Buffer.alloc(0);
  const now = options.now ?? Date.now();
  if (!Number.isSafeInteger(now)) fail(AUTH_ERROR_CODES.INVALID_REQUEST);
  const timestamp = parseTimestamp(headers["AgentPass-Timestamp"]);
  const nonce = parseNonce(headers["AgentPass-Nonce"]);
  if (Math.abs(now - timestamp) > CLOCK_WINDOW_MS) fail(AUTH_ERROR_CODES.CLOCK_SKEW);

  const device = findDevice(enrolled, headers["AgentPass-Device"]);
  if (!device) fail(AUTH_ERROR_CODES.DEVICE_AUTH_FAILED);
  if (device.disabled === true || device.revoked === true || device.status === "disabled" || device.status === "revoked") {
    fail(AUTH_ERROR_CODES.DEVICE_DISABLED);
  }
  const expectedOrganization = options.organizationId ?? options.organization_id;
  const deviceOrganization = device.organization_id ?? device.organizationId;
  if (expectedOrganization !== undefined && deviceOrganization !== expectedOrganization) {
    fail(AUTH_ERROR_CODES.DEVICE_AUTH_FAILED);
  }

  const digest = sha256(body);
  constantTimeHexEqual(digest, headers["AgentPass-Content-SHA256"], AUTH_ERROR_CODES.BODY_DIGEST_MISMATCH);
  const signature = parseSignature(headers["AgentPass-Signature"]);
  const signed = canonicalDeviceRequest({ method, path, body_digest: digest, timestamp, nonce });
  const publicKey = devicePublicKey(device);
  let valid = false;
  try {
    valid = publicKey.asymmetricKeyType === "ed25519"
      ? crypto.verify(null, Buffer.from(signed, "utf8"), publicKey, signature)
      : crypto.verify("sha256", Buffer.from(signed, "utf8"), { key: publicKey, dsaEncoding: "ieee-p1363" }, signature);
  } catch {
    valid = false;
  }
  if (!valid) fail(AUTH_ERROR_CODES.DEVICE_AUTH_FAILED);

  if (options.deferReplayConsumption !== true) {
    const replayCache = options.replayCache ?? options.replay ?? createReplayCache();
    purgeReplayCache(replayCache, now);
    const replayKey = `${headers["AgentPass-Device"]}:${nonce}`;
    if (replayCache.has(replayKey)) fail(AUTH_ERROR_CODES.REPLAY_DETECTED);
    const limit = replayCache.maxEntries ?? options.maxReplayEntries ?? DEFAULT_REPLAY_LIMIT;
    if (!Number.isSafeInteger(limit) || limit < 1) fail(AUTH_ERROR_CODES.INVALID_REQUEST);
    if (replayCache.size >= limit) fail(AUTH_ERROR_CODES.REPLAY_CACHE_FULL);
    replayCache.set(replayKey, now + REPLAY_RETENTION_MS);
  }

  return publicDevice(device, headers["AgentPass-Device"], options.includeAuthenticationMetadata === true);
}

/** Create the detached signature used by an AgentPass device request. */
export function createDeviceSignature(request, privateKey) {
  let key;
  try { key = privateKey?.type === "private" ? privateKey : crypto.createPrivateKey(privateKey); }
  catch { fail(AUTH_ERROR_CODES.INVALID_REQUEST); }
  if (!deviceKeyTypeAllowed(key)) fail(AUTH_ERROR_CODES.INVALID_REQUEST);
  const bytes = Buffer.from(canonicalDeviceRequest(request), "utf8");
  return (key.asymmetricKeyType === "ed25519"
    ? crypto.sign(null, bytes, key)
    : crypto.sign("sha256", bytes, { key, dsaEncoding: "ieee-p1363" })).toString("base64");
}

/** Build the five exact authentication headers for a raw HTTP request. */
export function signDeviceRequest(request, privateKey) {
  if (!request || typeof request !== "object" || typeof request.device_id !== "string") fail(AUTH_ERROR_CODES.INVALID_REQUEST);
  const timestamp = request.timestamp ?? request.timestamp_ms ?? Date.now();
  const nonce = request.nonce ?? randomNonce();
  const digest = sha256(request.body ?? Buffer.alloc(0));
  const signature = createDeviceSignature({ ...request, body_digest: digest, timestamp, nonce }, privateKey);
  return {
    "AgentPass-Device": request.device_id,
    "AgentPass-Timestamp": String(timestamp),
    "AgentPass-Nonce": nonce,
    "AgentPass-Content-SHA256": digest,
    "AgentPass-Signature": signature
  };
}

export function generateApiToken() {
  return `ap_${crypto.randomBytes(TOKEN_KEY_BYTES).toString("base64url")}`;
}

/** Return a PHC-like scrypt record; the bearer token is never part of it. */
export function hashApiToken(token) {
  assertToken(token);
  const salt = crypto.randomBytes(TOKEN_SALT_BYTES);
  const digest = crypto.scryptSync(token, salt, TOKEN_KEY_BYTES, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: SCRYPT_MAXMEM
  });
  return `scrypt$N=${SCRYPT_N},r=${SCRYPT_R},p=${SCRYPT_P}$${salt.toString("base64url")}.${digest.toString("base64url")}`;
}

export function verifyApiToken(token, stored) {
  if (typeof token !== "string" || typeof stored !== "string") return false;
  const match = TOKEN_HASH_PATTERN.exec(stored);
  if (!match) return false;
  const [, nText, rText, pText, saltText, digestText] = match;
  const n = Number(nText);
  const r = Number(rText);
  const p = Number(pText);
  if (n !== SCRYPT_N || r !== SCRYPT_R || p !== SCRYPT_P) return false;
  let salt;
  let expected;
  try {
    salt = decodeBase64Url(saltText, TOKEN_SALT_BYTES);
    expected = decodeBase64Url(digestText, TOKEN_KEY_BYTES);
  } catch {
    return false;
  }
  let actual;
  try {
    actual = crypto.scryptSync(token, salt, TOKEN_KEY_BYTES, { N: n, r, p, maxmem: SCRYPT_MAXMEM });
  } catch {
    return false;
  }
  return crypto.timingSafeEqual(actual, expected);
}

/** Store only a token verifier and non-sensitive principal metadata. */
export function createApiTokenRecord({ token, tokenId = crypto.randomUUID(), organizationId, memberId, role, ...extra } = {}) {
  if (Object.keys(extra).length > 0 || typeof tokenId !== "string" || tokenId.length === 0) fail(AUTH_ERROR_CODES.TOKEN_RECORD);
  if (typeof organizationId !== "string" || organizationId.length === 0 || typeof memberId !== "string" || memberId.length === 0) fail(AUTH_ERROR_CODES.TOKEN_RECORD);
  assertRole(role);
  return {
    token_id: tokenId,
    organization_id: organizationId,
    member_id: memberId,
    role,
    token_hash: hashApiToken(token)
  };
}

export const storeApiToken = createApiTokenRecord;

/** Find a token record without returning its hash or the bearer token. */
export function authenticateApiToken(token, records) {
  if (typeof token !== "string") fail(AUTH_ERROR_CODES.INVALID_TOKEN);
  const candidates = tokenRecords(records);
  let match = null;
  for (const record of candidates) {
    if (!record || record.revoked === true || record.disabled === true || record.revoked_at !== undefined) continue;
    const hash = record.token_hash ?? record.tokenHash ?? record.hash;
    if (verifyApiToken(token, hash) && match === null) match = record;
  }
  if (!match) fail(AUTH_ERROR_CODES.INVALID_TOKEN);
  return principalOf(match);
}

export const authenticateHuman = authenticateApiToken;
export const hashToken = hashApiToken;
export const verifyToken = verifyApiToken;
export const verifyHumanApiToken = authenticateApiToken;

export function roleAllows(actualRole, requiredRole) {
  return ROLES.includes(actualRole) && ROLES.includes(requiredRole) && ROLE_LEVEL[actualRole] >= ROLE_LEVEL[requiredRole];
}

export const hasRole = roleAllows;

export function requireOrganizationRole(principal, organizationId, requiredRole) {
  if (!principal || typeof principal !== "object" || principal.organization_id !== organizationId) fail(AUTH_ERROR_CODES.ORGANIZATION_MISMATCH);
  if (!roleAllows(principal.role, requiredRole)) fail(AUTH_ERROR_CODES.ROLE_DENIED);
  return principalOf(principal);
}

export const authorizeOrganizationRole = requireOrganizationRole;

export function requireRole(principal, organizationId, requiredRole) {
  if (requiredRole === undefined) {
    requiredRole = organizationId;
    organizationId = undefined;
  }
  if (organizationId === undefined) {
    if (!principal || typeof principal !== "object" || !roleAllows(principal.role, requiredRole)) fail(AUTH_ERROR_CODES.ROLE_DENIED);
    return principalOf(principal);
  }
  return requireOrganizationRole(principal, organizationId, requiredRole);
}

export const checkOrganizationRole = roleAllows;
export const verifyDeviceSignature = verifyDeviceRequest;

function parseDeviceHeaders(input) {
  if (!input || typeof input !== "object") fail(AUTH_ERROR_CODES.INVALID_HEADERS);
  const values = Object.create(null);
  const entries = input instanceof Headers
    ? [...input.entries()]
    : input instanceof Map
      ? [...input.entries()]
      : Object.entries(input);
  for (const [name, value] of entries) {
    const canonical = DEVICE_HEADERS.find((header) => header.toLowerCase() === String(name).toLowerCase());
    if (!canonical) {
      if (String(name).toLowerCase().startsWith("agentpass-")) fail(AUTH_ERROR_CODES.INVALID_HEADERS);
      continue;
    }
    if (values[canonical] !== undefined || Array.isArray(value) || typeof value !== "string" || value.length === 0 || value !== value.trim() || value.includes(",")) {
      fail(AUTH_ERROR_CODES.INVALID_HEADERS);
    }
    values[canonical] = value;
  }
  if (DEVICE_HEADERS.some((header) => values[header] === undefined)) fail(AUTH_ERROR_CODES.INVALID_HEADERS);
  if (!DEVICE_ID_PATTERN.test(values["AgentPass-Device"])) fail(AUTH_ERROR_CODES.INVALID_HEADERS);
  if (!DIGEST_PATTERN.test(values["AgentPass-Content-SHA256"])) fail(AUTH_ERROR_CODES.INVALID_HEADERS);
  if (!BASE64_PATTERN.test(values["AgentPass-Signature"])) fail(AUTH_ERROR_CODES.INVALID_HEADERS);
  return values;
}

function canonicalMethod(method) {
  if (typeof method !== "string" || !/^[A-Za-z]+$/.test(method)) fail(AUTH_ERROR_CODES.INVALID_REQUEST);
  return method.toUpperCase();
}

function canonicalTarget(path, query) {
  if (typeof path !== "string" || path.length === 0 || path[0] !== "/" || /[\u0000-\u0020\u007f#\\]/.test(path)) fail(AUTH_ERROR_CODES.INVALID_REQUEST);
  const question = path.indexOf("?");
  if (question >= 0) {
    if (query !== undefined) fail(AUTH_ERROR_CODES.INVALID_REQUEST);
    query = path.slice(question + 1);
    path = path.slice(0, question);
  }
  if (path.length === 0) path = "/";
  let normalizedPath;
  try {
    normalizedPath = new URL(path, "https://agentpass.invalid").pathname;
  } catch {
    fail(AUTH_ERROR_CODES.INVALID_REQUEST);
  }
  return { path: normalizedPath, query: canonicalQuery(query) };
}

function canonicalQuery(query) {
  if (query === undefined || query === "") return "";
  if (query instanceof URLSearchParams) query = query.toString();
  if (typeof query !== "string" || query.startsWith("?") || /[\u0000-\u0020\u007f#]/.test(query)) fail(AUTH_ERROR_CODES.INVALID_REQUEST);
  const pairs = query.split("&").map((part) => {
    const separator = part.indexOf("=");
    const rawKey = separator < 0 ? part : part.slice(0, separator);
    const rawValue = separator < 0 ? "" : part.slice(separator + 1);
    return [encodeQueryComponent(decodeQueryComponent(rawKey)), encodeQueryComponent(decodeQueryComponent(rawValue))];
  });
  pairs.sort((left, right) => compareAscii(left[0], right[0]) || compareAscii(left[1], right[1]));
  return pairs.map(([key, value]) => `${key}=${value}`).join("&");
}

function decodeQueryComponent(value) {
  try { return decodeURIComponent(value.replaceAll("+", " ")); }
  catch { fail(AUTH_ERROR_CODES.INVALID_REQUEST); }
}

function encodeQueryComponent(value) {
  return encodeURIComponent(value).replace(/[!'()*]/g, (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
}

function compareAscii(left, right) {
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

function canonicalTimestamp(value) {
  if (!Number.isSafeInteger(value)) value = parseTimestamp(value);
  if (!Number.isSafeInteger(value) || value < 0) fail(AUTH_ERROR_CODES.INVALID_HEADERS);
  return String(value);
}

function parseTimestamp(value) {
  if (typeof value !== "string" || !/^(?:0|[1-9]\d{0,15})$/.test(value)) fail(AUTH_ERROR_CODES.INVALID_HEADERS);
  const timestamp = Number(value);
  if (!Number.isSafeInteger(timestamp)) fail(AUTH_ERROR_CODES.INVALID_HEADERS);
  return timestamp;
}

function canonicalNonce(value) {
  if (!NONCE_PATTERN.test(value)) fail(AUTH_ERROR_CODES.INVALID_HEADERS);
  return value;
}

function parseNonce(value) {
  return canonicalNonce(value);
}

function parseSignature(value) {
  if (!BASE64_PATTERN.test(value)) fail(AUTH_ERROR_CODES.INVALID_HEADERS);
  const bytes = Buffer.from(value, "base64");
  if (bytes.length !== 64 || bytes.toString("base64") !== value) fail(AUTH_ERROR_CODES.INVALID_HEADERS);
  return bytes;
}

function constantTimeHexEqual(actual, supplied, code) {
  const left = Buffer.from(actual, "ascii");
  const right = Buffer.from(supplied, "ascii");
  if (left.length !== right.length || !crypto.timingSafeEqual(left, right)) fail(code);
}

function findDevice(enrolled, id) {
  if (enrolled instanceof Map) return enrolled.get(id);
  if (Array.isArray(enrolled)) return enrolled.find((device) => device?.device_id === id || device?.deviceId === id || device?.id === id);
  if (enrolled && typeof enrolled === "object") {
    if (Array.isArray(enrolled.devices)) return findDevice(enrolled.devices, id);
    return enrolled[id];
  }
  return undefined;
}

function devicePublicKey(device) {
  const value = device?.public_key ?? device?.publicKey ?? device?.device_public_key ?? device?.devicePublicKey;
  if (value === undefined || (typeof value === "string" && /PRIVATE KEY/.test(value))) fail(AUTH_ERROR_CODES.DEVICE_AUTH_FAILED);
  try {
    const key = value?.type === "public" ? value : crypto.createPublicKey(value);
    if (!deviceKeyTypeAllowed(key)) fail(AUTH_ERROR_CODES.DEVICE_AUTH_FAILED);
    return key;
  } catch {
    fail(AUTH_ERROR_CODES.DEVICE_AUTH_FAILED);
  }
}

function deviceKeyTypeAllowed(key) {
  return key.asymmetricKeyType === "ed25519"
    || (key.asymmetricKeyType === "ec" && key.asymmetricKeyDetails?.namedCurve === "prime256v1");
}

function publicDevice(device, fallbackId, includeAuthenticationMetadata = false) {
  const result = { device_id: device.device_id ?? device.deviceId ?? device.id ?? fallbackId };
  const organizationId = device.organization_id ?? device.organizationId;
  if (organizationId !== undefined) result.organization_id = organizationId;
  if (includeAuthenticationMetadata) {
    const keyEpoch = device.key_epoch ?? device.keyEpoch ?? device.device_key_epoch ?? device.deviceKeyEpoch;
    Object.defineProperties(result, {
      authentication_public_key: { value: devicePublicKey(device), enumerable: false },
      key_epoch: { value: keyEpoch, enumerable: false }
    });
  }
  return result;
}

function tokenRecords(records) {
  if (records instanceof Map) return [...records.values()];
  if (Array.isArray(records)) return records;
  if (records && typeof records === "object") return Array.isArray(records.tokens) ? records.tokens : Object.values(records);
  return [];
}

function principalOf(record) {
  const principal = {};
  for (const [from, to] of [["token_id", "token_id"], ["organization_id", "organization_id"], ["member_id", "member_id"], ["role", "role"]]) {
    if (record[from] !== undefined) principal[to] = record[from];
  }
  return principal;
}

function assertToken(token) {
  if (typeof token !== "string" || token.length < 16 || token.length > 512 || /[\u0000-\u001f\u007f]/.test(token)) fail(AUTH_ERROR_CODES.INVALID_TOKEN);
}

function assertRole(role) {
  if (!ROLES.includes(role)) fail(AUTH_ERROR_CODES.TOKEN_RECORD);
}

function decodeBase64Url(value, expectedLength) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("invalid encoding");
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== expectedLength || bytes.toString("base64url") !== value) throw new Error("invalid encoding");
  return bytes;
}

function purgeReplayCache(cache, now) {
  if (!cache || typeof cache.has !== "function" || typeof cache.set !== "function" || typeof cache[Symbol.iterator] !== "function") fail(AUTH_ERROR_CODES.INVALID_REQUEST);
  for (const [nonce, expiresAt] of cache) {
    if (typeof expiresAt === "number" && expiresAt <= now) cache.delete(nonce);
  }
}

function randomNonce() {
  return `A${crypto.randomBytes(32).toString("base64url")}`;
}

function toBodyBytes(value) {
  if (value === undefined || value === null) return Buffer.alloc(0);
  if (Buffer.isBuffer(value)) return value;
  if (typeof value === "string") return Buffer.from(value, "utf8");
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (value instanceof ArrayBuffer) return Buffer.from(value);
  fail(AUTH_ERROR_CODES.INVALID_REQUEST);
}

function fail(code) {
  throw new AuthError(code);
}
