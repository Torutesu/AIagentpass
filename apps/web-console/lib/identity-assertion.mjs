const MAX_TTL_SECONDS = 60;
const CLOCK_SKEW_SECONDS = 5;
const MAX_PRIVATE_KEY_BYTES = 16 * 1024;
const MAX_COMPACT_BYTES = 16 * 1024;
const MAX_HEADER_BYTES = 1_024;
const MAX_PAYLOAD_BYTES = 8 * 1024;
const MAX_TEXT_BYTES = 2_048;
const MAX_SUBJECT_BYTES = 512;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const PROVIDER = /^[a-z][a-z0-9._-]{0,63}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const ASSERTION_TYPE = "agentpass.console.identity";
const HEADER_KEYS = Object.freeze(["alg", "kid", "typ", "version"]);
const PAYLOAD_KEYS = Object.freeze(["aud", "exp", "iat", "iss", "jti", "nbf", "org", "origin", "provider", "sub"]);

export const IDENTITY_ASSERTION_HEADER = "agentpass-console-identity";
export const IDENTITY_ASSERTION_HEADER_KEYS = HEADER_KEYS;
export const IDENTITY_ASSERTION_PAYLOAD_KEYS = PAYLOAD_KEYS;

/**
 * Signs the compact assertion consumed by Cloud:
 *
 *   b64url(canonical protected header).b64url(canonical payload).b64url(sig)
 *
 * The browser never sees this value. It is created only after the platform
 * has verified SIWC and is placed in one server-to-server request header.
 */
export function createIdentityAssertionSigner(options = {}) {
  const config = normalizeSignerConfig(options);
  let importedKey;

  return Object.freeze({
    sign: async (input = {}) => {
      const payload = createPayload(input, config);
      const header = { alg: "EdDSA", kid: config.keyId, typ: ASSERTION_TYPE, version: 1 };
      const encodedHeader = encodeJson(header);
      const encodedPayload = encodeJson(payload);
      const signingInput = `${encodedHeader}.${encodedPayload}`;
      if (importedKey === undefined) importedKey = await importPrivateKey(config.privateKeyPem);
      const signature = await signEd25519(signingInput, importedKey);
      const compact = `${signingInput}.${signature}`;
      assertCompactIdentityAssertion(compact, { now: input.now ?? Date.now(), expected: config });
      return compact;
    },
  });
}

/** Validate both compact syntax and the exact common header/payload schema. */
export function assertCompactIdentityAssertion(compact, { now = Date.now(), expected = undefined } = {}) {
  if (typeof compact !== "string" || compact.length < 1 || new TextEncoder().encode(compact).byteLength > MAX_COMPACT_BYTES) throw new TypeError("identity assertion is invalid");
  const parts = compact.split(".");
  if (parts.length !== 3 || parts.some((part) => !BASE64URL.test(part))) throw new TypeError("identity assertion is invalid");
  const header = parseCanonicalJson(parts[0], MAX_HEADER_BYTES, HEADER_KEYS);
  if (header.alg !== "EdDSA" || header.typ !== ASSERTION_TYPE || header.version !== 1 || !IDENTIFIER.test(header.kid)) throw new TypeError("identity assertion header is invalid");
  const payload = parseCanonicalJson(parts[1], MAX_PAYLOAD_BYTES, PAYLOAD_KEYS);
  if (expected !== undefined && header.kid !== expected.keyId) throw new TypeError("identity assertion key id is invalid");
  validatePayload(payload, { now, expected });
  const signature = decodeBase64Url(parts[2], 64, 64);
  if (signature.length !== 64) throw new TypeError("identity assertion signature is invalid");
  return Object.freeze({ header, payload, signature: parts[2], compact });
}

function normalizeSignerConfig(options) {
  const source = options.env;
  const privateKeyPem = options.privateKeyPem ?? options.privateKey ?? source?.AGENTPASS_IDENTITY_ASSERTION_PRIVATE_KEY;
  const issuer = options.issuer ?? source?.AGENTPASS_IDENTITY_ASSERTION_ISSUER;
  const audience = options.audience ?? source?.AGENTPASS_IDENTITY_ASSERTION_AUDIENCE;
  const keyId = options.kid ?? options.keyId ?? source?.AGENTPASS_IDENTITY_ASSERTION_KID;
  const provider = options.provider ?? source?.AGENTPASS_IDENTITY_PROVIDER ?? "chatgpt";
  if (!safeText(issuer, 256) || !safeText(audience, 256) || !IDENTIFIER.test(keyId) || !PROVIDER.test(provider)) throw new TypeError("identity assertion configuration is invalid");
  if (typeof privateKeyPem !== "string" || privateKeyPem.length < 32 || privateKeyPem.length > MAX_PRIVATE_KEY_BYTES || hasControlExceptNewline(privateKeyPem)) throw new TypeError("identity assertion private key is invalid");
  decodePem(privateKeyPem);
  return Object.freeze({ privateKeyPem, issuer, audience, keyId, provider });
}

function createPayload(input, config) {
  const now = normalizeNow(input.now ?? Date.now());
  const iat = Math.floor(now / 1_000);
  const subject = input.subject ?? input.sub;
  const organizationId = input.organizationId ?? input.org;
  if (!safeText(subject, MAX_SUBJECT_BYTES) || !UUID.test(organizationId) || !isOrigin(input.origin)) throw new TypeError("identity assertion input is invalid");
  const jti = input.jti ?? randomBase64Url(16);
  if (!BASE64URL.test(jti) || jti.length < 22 || jti.length > 256) throw new TypeError("identity assertion jti is invalid");
  const payload = {
    aud: config.audience,
    exp: iat + MAX_TTL_SECONDS,
    iat,
    iss: config.issuer,
    jti,
    nbf: iat,
    org: organizationId.toLowerCase(),
    origin: input.origin,
    provider: config.provider,
    sub: subject,
  };
  validatePayload(payload, { now, expected: config });
  return payload;
}

function validatePayload(payload, { now, expected }) {
  if (!safeText(payload.iss, 256) || !safeText(payload.aud, 256) || !PROVIDER.test(payload.provider) || !safeText(payload.sub, MAX_SUBJECT_BYTES) || !UUID.test(payload.org) || !isOrigin(payload.origin) || !BASE64URL.test(payload.jti) || payload.jti.length < 22 || payload.jti.length > 256) throw new TypeError("identity assertion payload is invalid");
  if (expected !== undefined && (payload.iss !== expected.issuer || payload.aud !== expected.audience || payload.provider !== expected.provider)) throw new TypeError("identity assertion binding is invalid");
  if (!Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.nbf) || !Number.isSafeInteger(payload.exp) || payload.iat < 0 || payload.nbf > payload.iat || payload.exp <= payload.iat || payload.exp - payload.iat > MAX_TTL_SECONDS) throw new TypeError("identity assertion lifetime is invalid");
  const nowSeconds = Math.floor(normalizeNow(now) / 1_000);
  if (payload.iat > nowSeconds + CLOCK_SKEW_SECONDS || payload.nbf > nowSeconds + CLOCK_SKEW_SECONDS || payload.exp <= nowSeconds - CLOCK_SKEW_SECONDS || payload.iat < nowSeconds - MAX_TTL_SECONDS - CLOCK_SKEW_SECONDS) throw new TypeError("identity assertion lifetime is invalid");
}

async function importPrivateKey(pem) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle || typeof subtle.importKey !== "function") throw new TypeError("Ed25519 key import is unavailable");
  return subtle.importKey("pkcs8", decodePem(pem), { name: "Ed25519" }, false, ["sign"]);
}

async function signEd25519(signingInput, key) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle || typeof subtle.sign !== "function") throw new TypeError("Ed25519 signing is unavailable");
  const signature = await subtle.sign("Ed25519", key, new TextEncoder().encode(signingInput));
  return encodeBase64Url(new Uint8Array(signature));
}

function parseCanonicalJson(segment, maxBytes, keys) {
  const bytes = decodeBase64Url(segment, 1, maxBytes);
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch { throw new TypeError("identity JSON is invalid"); }
  let value;
  try { value = JSON.parse(text); } catch { throw new TypeError("identity JSON is invalid"); }
  if (!isPlainObject(value) || !exactKeys(value, keys) || canonicalJson(value) !== text) throw new TypeError("identity JSON schema is invalid");
  return value;
}

function decodePem(pem) {
  const match = /^-----BEGIN PRIVATE KEY-----\n([A-Za-z0-9+/\n]+)\n-----END PRIVATE KEY-----\n?$/u.exec(pem);
  if (!match) throw new TypeError("identity assertion private key must be PKCS#8 PEM");
  const compact = match[1].replaceAll("\n", "");
  if (compact.length % 4 === 1) throw new TypeError("identity assertion private key is invalid");
  let bytes;
  try { bytes = Uint8Array.from(atob(compact), (character) => character.charCodeAt(0)); } catch { throw new TypeError("identity assertion private key is invalid"); }
  if (bytes.length < 32 || bytes.length > MAX_PRIVATE_KEY_BYTES) throw new TypeError("identity assertion private key is invalid");
  return bytes;
}

function encodeJson(value) { return encodeBase64Url(new TextEncoder().encode(canonicalJson(value))); }
function encodeBase64Url(bytes) { let binary = ""; for (const byte of bytes) binary += String.fromCharCode(byte); return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", ""); }
function decodeBase64Url(value, minBytes, maxBytes) {
  if (typeof value !== "string" || !BASE64URL.test(value)) throw new TypeError("identity base64url is invalid");
  let bytes;
  try { bytes = Uint8Array.from(atob(value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (value.length % 4)) % 4)), (character) => character.charCodeAt(0)); } catch { throw new TypeError("identity base64url is invalid"); }
  if (bytes.length < minBytes || bytes.length > maxBytes || encodeBase64Url(bytes) !== value) throw new TypeError("identity base64url is invalid");
  return bytes;
}
function canonicalJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") { if (!Number.isSafeInteger(value)) throw new TypeError("identity number is invalid"); return JSON.stringify(value); }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (!isPlainObject(value)) throw new TypeError("identity value is invalid");
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}
function exactKeys(value, expected) { const actual = Object.keys(value).sort(); const wanted = [...expected].sort(); return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]); }
function safeText(value, maxBytes) { return typeof value === "string" && value.length > 0 && new TextEncoder().encode(value).byteLength <= maxBytes && value.trim() === value && !hasControl(value); }
function hasControl(value) {
  if (typeof value !== "string") return true;
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}
function hasControlExceptNewline(value) {
  if (typeof value !== "string") return true;
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if ((code <= 0x1f && code !== 0x0a) || code === 0x7f) return true;
  }
  return false;
}
function isOrigin(value) {
  if (!safeText(value, MAX_TEXT_BYTES) || value === "null" || value.endsWith("/")) return false;
  try { const url = new URL(value); return url.origin === value && (url.protocol === "https:" || (url.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(url.hostname))) && !url.username && !url.password && !url.search && !url.hash; } catch { return false; }
}
function normalizeNow(value) { const now = value instanceof Date ? value.getTime() : value; if (!Number.isSafeInteger(now)) throw new TypeError("clock value is invalid"); return now; }
function randomBase64Url(byteLength) { const bytes = new Uint8Array(byteLength); const random = globalThis.crypto?.getRandomValues; if (typeof random !== "function") throw new TypeError("secure randomness is unavailable"); random.call(globalThis.crypto, bytes); return encodeBase64Url(bytes); }
function isPlainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
