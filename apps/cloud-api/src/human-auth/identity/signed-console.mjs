import crypto from "node:crypto";

const ASSERTION_HEADER = "agentpass-console-identity";
const ASSERTION_PARTS = 3;
const MAX_ASSERTION_BYTES = 16 * 1024;
const MAX_HEADER_BYTES = 1_024;
const MAX_PAYLOAD_BYTES = 8 * 1024;
const MAX_SUBJECT_BYTES = 512;
const MAX_JTI_BYTES = 256;
const MAX_TTL_SECONDS = 60;
const DEFAULT_CLOCK_SKEW_SECONDS = 5;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const PROVIDER = /^[a-z][a-z0-9._-]{0,63}$/u;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/u;
const HEADER_KEYS = ["alg", "kid", "typ", "version"];
const PAYLOAD_KEYS = ["aud", "exp", "iat", "iss", "jti", "nbf", "org", "origin", "provider", "sub"];
const ASSERTION_TYPE = "agentpass.console.identity";

export const SIGNED_CONSOLE_IDENTITY_HEADER = ASSERTION_HEADER;
export const SIGNED_CONSOLE_IDENTITY_ERROR_CODES = Object.freeze({
  INVALID_ASSERTION: "signed_console_identity_invalid",
  REPLAY: "signed_console_identity_replay",
  UNAVAILABLE: "signed_console_identity_unavailable"
});

const PUBLIC_FAILURE_MESSAGE = "Signed console identity could not be verified";

export class SignedConsoleIdentityError extends Error {
  constructor(code = SIGNED_CONSOLE_IDENTITY_ERROR_CODES.INVALID_ASSERTION) {
    super(PUBLIC_FAILURE_MESSAGE);
    this.name = "SignedConsoleIdentityError";
    this.code = code;
    this.status = 401;
  }
}

/**
 * Verify the identity assertion emitted by the platform-verified Console.
 *
 * The assertion is a compact, three-part envelope:
 *   base64url(canonical header).base64url(canonical payload).base64url(signature)
 *
 * It is deliberately not a generic JWT/OIDC parser. The key, schema, issuer,
 * audience, origin, and identity provider are all pinned by the
 * caller. A valid assertion consumes its namespaced jti in PostgreSQL before
 * the immutable provider/subject mapping is queried.
 */
export function createSignedConsoleIdentityAdapter({
  identityResolver,
  replayRepository,
  issuer,
  audience,
  provider,
  origin,
  keyId,
  publicKey,
  now = () => Date.now(),
  clockSkewSeconds = DEFAULT_CLOCK_SKEW_SECONDS
} = {}) {
  if (!identityResolver || typeof identityResolver.resolveIdentity !== "function" || !identityResolver.identityAdapter || typeof identityResolver.identityAdapter.verify !== "function") throw new TypeError("identityResolver is required");
  if (!replayRepository || typeof replayRepository.consumeConsoleIdentityJti !== "function") throw new TypeError("replayRepository is required");
  const config = normalizeConfig({ issuer, audience, provider, origin, keyId, publicKey, now, clockSkewSeconds });

  async function verifyIdentityRequest(request) {
    try {
      const compact = readAssertionHeader(request?.headers);
      const claims = verifyCompactAssertion(compact, config);
      const digest = consoleIdentityJtiDigest(claims);
      let consumed;
      try {
        consumed = await replayRepository.consumeConsoleIdentityJti({
          jti_digest: digest,
          expires_at: new Date(claims.exp * 1000).toISOString()
        });
      } catch {
        throw new SignedConsoleIdentityError(SIGNED_CONSOLE_IDENTITY_ERROR_CODES.UNAVAILABLE);
      }
      if (consumed !== true) throw new SignedConsoleIdentityError(SIGNED_CONSOLE_IDENTITY_ERROR_CODES.REPLAY);

      try {
        // Only cryptographically verified claims reach this resolver. The
        // resolver itself reads member/role/membership from PostgreSQL.
        const resolved = await identityResolver.resolveIdentity({
          provider: claims.provider,
          subject: claims.sub,
          organization_id: claims.org
        });
        if (!isOpaqueResolverAssertion(resolved)) throw new Error("resolver output is invalid");
        return resolved;
      } catch {
        throw new SignedConsoleIdentityError(SIGNED_CONSOLE_IDENTITY_ERROR_CODES.UNAVAILABLE);
      }
    } catch (error) {
      if (error instanceof SignedConsoleIdentityError) throw error;
      throw new SignedConsoleIdentityError();
    }
  }

  return Object.freeze({
    verifyIdentityRequest,
    // HumanSession consumes the resolver's opaque one-use assertion. It never
    // receives the signed envelope or any provider credential.
    identityAdapter: identityResolver.identityAdapter,
    provider,
    keyId,
    assertionHeader: ASSERTION_HEADER,
    clockSkewSeconds,
    maxTtlSeconds: MAX_TTL_SECONDS
  });
}

/** Namespaced digest used by the PostgreSQL replay ledger. */
export function consoleIdentityJtiDigest({ iss, aud, jti } = {}) {
  if (!exactText(iss, 256) || !exactText(aud, 256) || !boundedJti(jti)) throw new TypeError("identity jti is invalid");
  return crypto.createHash("sha256").update(`${iss}\u0000${aud}\u0000${jti}`, "utf8").digest("hex");
}

function verifyCompactAssertion(compact, config) {
  const parts = splitCompact(compact);
  const header = parseCanonicalJson(parts[0], MAX_HEADER_BYTES, HEADER_KEYS);
  if (header.version !== 1 || header.alg !== "EdDSA" || header.typ !== ASSERTION_TYPE || header.kid !== config.keyId) throw new Error("header binding is invalid");
  const signature = decodeBase64Url(parts[2], 64, 64);
  let valid = false;
  try { valid = crypto.verify(null, Buffer.from(`${parts[0]}.${parts[1]}`, "ascii"), config.publicKey, signature); } catch { valid = false; }
  if (!valid) throw new Error("signature is invalid");

  const payload = parseCanonicalJson(parts[1], MAX_PAYLOAD_BYTES, PAYLOAD_KEYS);
  validateClaims(payload, config);
  return payload;
}

function validateClaims(payload, config) {
  if (!exactText(payload.iss, 256) || payload.iss !== config.issuer) throw new Error("issuer is invalid");
  if (!exactText(payload.aud, 256) || payload.aud !== config.audience) throw new Error("audience is invalid");
  if (!PROVIDER.test(payload.provider) || payload.provider !== config.provider) throw new Error("provider is invalid");
  if (!UUID.test(payload.org)) throw new Error("organization is invalid");
  if (!boundedSubject(payload.sub)) throw new Error("subject is invalid");
  if (!exactText(payload.origin, 2_048) || payload.origin !== config.origin) throw new Error("origin is invalid");
  if (!boundedJti(payload.jti)) throw new Error("jti is invalid");
  for (const value of [payload.iat, payload.nbf, payload.exp]) {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error("time claim is invalid");
  }
  if (payload.nbf > payload.iat || payload.exp <= payload.iat || payload.exp - payload.iat > MAX_TTL_SECONDS) throw new Error("time relationship is invalid");

  const nowSeconds = Math.floor(config.now() / 1_000);
  if (!Number.isSafeInteger(nowSeconds) || payload.iat > nowSeconds + config.clockSkewSeconds || payload.nbf > nowSeconds + config.clockSkewSeconds || payload.exp <= nowSeconds - config.clockSkewSeconds || payload.iat < nowSeconds - MAX_TTL_SECONDS - config.clockSkewSeconds) {
    throw new Error("assertion lifetime is invalid");
  }
}

function normalizeConfig({ issuer, audience, provider, origin, keyId, publicKey, now, clockSkewSeconds }) {
  if (!exactText(issuer, 256) || !exactText(audience, 256) || !PROVIDER.test(provider) || !exactText(origin, 2_048) || !IDENTIFIER.test(keyId)) throw new TypeError("signed console identity configuration is invalid");
  if (typeof now !== "function") throw new TypeError("now must be a function");
  if (!Number.isSafeInteger(clockSkewSeconds) || clockSkewSeconds < 0 || clockSkewSeconds > 10) throw new TypeError("clock skew is invalid");
  let key;
  try { key = publicKey?.type === "public" ? publicKey : crypto.createPublicKey(publicKey); } catch { throw new TypeError("pinned public key is invalid"); }
  if (key.asymmetricKeyType !== "ed25519") throw new TypeError("pinned public key must be Ed25519");
  return Object.freeze({ issuer, audience, provider, origin, keyId, publicKey: key, now, clockSkewSeconds });
}

function readAssertionHeader(headers) {
  const values = [];
  if (headers && typeof headers.get === "function") {
    const value = headers.get(ASSERTION_HEADER);
    if (value !== null && value !== undefined) values.push(value);
  } else if (headers && typeof headers === "object" && !Array.isArray(headers)) {
    for (const [name, value] of Object.entries(headers)) if (name.toLowerCase() === ASSERTION_HEADER) values.push(value);
  }
  if (values.length !== 1 || typeof values[0] !== "string" || values[0].length < 1 || Buffer.byteLength(values[0], "utf8") > MAX_ASSERTION_BYTES) throw new Error("identity assertion header is invalid");
  return values[0];
}

function splitCompact(value) {
  const parts = value.split(".");
  if (parts.length !== ASSERTION_PARTS || parts.some((part) => !BASE64URL.test(part))) throw new Error("compact identity assertion is invalid");
  // Validate the exact base64url spelling before parsing any JSON.
  decodeBase64Url(parts[0], 1, MAX_HEADER_BYTES);
  decodeBase64Url(parts[1], 1, MAX_PAYLOAD_BYTES);
  return parts;
}

function parseCanonicalJson(segment, maxBytes, keys) {
  const bytes = decodeBase64Url(segment, 1, maxBytes);
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); } catch { throw new Error("identity JSON is invalid"); }
  if (!plain(value) || !exactKeys(value, keys) || canonicalJson(value) !== bytes.toString("utf8")) throw new Error("identity JSON schema is invalid");
  return value;
}

function decodeBase64Url(value, minBytes, maxBytes) {
  if (typeof value !== "string" || !BASE64URL.test(value)) throw new Error("base64url is invalid");
  let bytes;
  try { bytes = Buffer.from(value, "base64url"); } catch { throw new Error("base64url is invalid"); }
  if (bytes.length < minBytes || bytes.length > maxBytes || bytes.toString("base64url") !== value) throw new Error("base64url is invalid");
  return bytes;
}

function boundedSubject(value) { return typeof value === "string" && value.length > 0 && Buffer.byteLength(value, "utf8") <= MAX_SUBJECT_BYTES && value.trim() === value && !CONTROL_CHARACTERS.test(value); }
function boundedJti(value) { return typeof value === "string" && value.length > 0 && Buffer.byteLength(value, "utf8") <= MAX_JTI_BYTES && BASE64URL.test(value); }
function exactText(value, maxBytes) { return typeof value === "string" && value.length > 0 && Buffer.byteLength(value, "utf8") <= maxBytes && !CONTROL_CHARACTERS.test(value); }
function isOpaqueResolverAssertion(value) {
  return plain(value) && exactKeys(value, ["version", "issued_at", "expires_at"]) && value.version === 1 && Number.isSafeInteger(value.issued_at) && Number.isSafeInteger(value.expires_at) && value.issued_at >= 0 && value.expires_at > value.issued_at && Object.isFrozen(value);
}
function plain(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exactKeys(value, expected) { const actual = Object.keys(value).sort(); const wanted = [...expected].sort(); return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]); }
function canonicalJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number") {
    if (typeof value === "number" && (!Number.isFinite(value) || !Number.isSafeInteger(value))) throw new Error("identity number is invalid");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (!plain(value)) throw new Error("identity value is invalid");
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}
