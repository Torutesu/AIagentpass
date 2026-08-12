import crypto from "node:crypto";

const DEFAULT_TTL_MS = 120_000;
const MAX_TTL_MS = 300_000;
const MAX_PENDING = 10_000;
const CHALLENGE_BYTES = 32;
const MAX_CLIENT_DATA_BYTES = 16 * 1024;
const MAX_AUTHENTICATOR_DATA_BYTES = 4 * 1024;
const MAX_SIGNATURE_BYTES = 1024;
const MAX_CREDENTIAL_ID_BYTES = 1024;
const MAX_USER_HANDLE_BYTES = 64;
const MAX_CLOCK_SKEW_MS = 30_000;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const VERIFIER_RESULT_KEYS = new Set(["verified", "credential_id", "sign_count", "authenticated_at"]);
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const OPERATION = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const ORIGIN_SCHEMES = new Set(["https:", "http:"]);
const CLIENT_DATA_KEYS = new Set(["type", "challenge", "origin", "crossOrigin", "tokenBinding"]);

export const WEBAUTHN_ERROR_CODES = Object.freeze({
  INVALID_REQUEST: "webauthn_invalid_request",
  INVALID_CONTEXT: "webauthn_invalid_context",
  CHALLENGE_NOT_FOUND: "webauthn_challenge_not_found",
  CHALLENGE_EXPIRED: "webauthn_challenge_expired",
  CHALLENGE_REPLAYED: "webauthn_challenge_replayed",
  CHALLENGE_BUSY: "webauthn_challenge_busy",
  CHALLENGE_MISMATCH: "webauthn_challenge_mismatch",
  BINDING_MISMATCH: "webauthn_binding_mismatch",
  INVALID_RESPONSE: "webauthn_invalid_response",
  VERIFICATION_FAILED: "webauthn_verification_failed",
  VERIFIER_UNAVAILABLE: "webauthn_verifier_unavailable",
  INVALID_VERIFIER_RESULT: "webauthn_invalid_verifier_result",
  CAPACITY_EXCEEDED: "webauthn_capacity_exceeded"
});

const ERROR_MESSAGES = Object.freeze({
  [WEBAUTHN_ERROR_CODES.INVALID_REQUEST]: "WebAuthn ceremony request is invalid",
  [WEBAUTHN_ERROR_CODES.INVALID_CONTEXT]: "WebAuthn ceremony context is invalid",
  [WEBAUTHN_ERROR_CODES.CHALLENGE_NOT_FOUND]: "WebAuthn challenge was not found",
  [WEBAUTHN_ERROR_CODES.CHALLENGE_EXPIRED]: "WebAuthn challenge has expired",
  [WEBAUTHN_ERROR_CODES.CHALLENGE_REPLAYED]: "WebAuthn challenge has already been consumed",
  [WEBAUTHN_ERROR_CODES.CHALLENGE_BUSY]: "WebAuthn challenge is already being consumed",
  [WEBAUTHN_ERROR_CODES.CHALLENGE_MISMATCH]: "WebAuthn challenge does not match",
  [WEBAUTHN_ERROR_CODES.BINDING_MISMATCH]: "WebAuthn challenge binding does not match",
  [WEBAUTHN_ERROR_CODES.INVALID_RESPONSE]: "WebAuthn assertion response is invalid",
  [WEBAUTHN_ERROR_CODES.VERIFICATION_FAILED]: "WebAuthn assertion verification failed",
  [WEBAUTHN_ERROR_CODES.VERIFIER_UNAVAILABLE]: "WebAuthn assertion verifier is unavailable",
  [WEBAUTHN_ERROR_CODES.INVALID_VERIFIER_RESULT]: "WebAuthn assertion verifier result is invalid",
  [WEBAUTHN_ERROR_CODES.CAPACITY_EXCEEDED]: "WebAuthn ceremony capacity is exhausted"
});

export class WebAuthnCeremonyError extends Error {
  constructor(code, details = undefined) {
    super(ERROR_MESSAGES[code] ?? "WebAuthn ceremony failed");
    this.name = "WebAuthnCeremonyError";
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

/**
 * In-memory recent-auth ceremony coordinator.
 *
 * The store deliberately contains only challenge digests and public context.
 * Raw challenges, assertions, signatures, and credential identifiers are never
 * written to a persistence boundary by this module. A future durable adapter
 * must preserve the same record shape and implement an atomic compare-and-set
 * from `pending` to `consuming`.
 */
export function createWebAuthnCeremony({
  verifyAssertion,
  now = () => Date.now(),
  ttlMs = DEFAULT_TTL_MS,
  maxPending = MAX_PENDING
} = {}) {
  if (typeof verifyAssertion !== "function") throw new TypeError("verifyAssertion must be a function");
  assertClock(now());
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1_000 || ttlMs > MAX_TTL_MS) throw new TypeError("ttlMs is invalid");
  if (!Number.isSafeInteger(maxPending) || maxPending < 1 || maxPending > MAX_PENDING) throw new TypeError("maxPending is invalid");

  const records = new Map();

  const begin = (input = {}) => {
    const context = normalizeContext(input);
    const issuedAt = assertClock(now());
    purge(records, issuedAt);
    if (pendingCount(records) >= maxPending) fail(WEBAUTHN_ERROR_CODES.CAPACITY_EXCEEDED);

    const challengeId = crypto.randomUUID();
    const challenge = crypto.randomBytes(CHALLENGE_BYTES).toString("base64url");
    const requestedTtl = input.ttlMs ?? ttlMs;
    if (!Number.isSafeInteger(requestedTtl) || requestedTtl < 1_000 || requestedTtl > ttlMs) fail(WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, "ttl_ms");
    const expiresAt = issuedAt + requestedTtl;
    const record = {
      challenge_digest: sha256(challenge),
      session_id: context.session_id,
      organization_id: context.organization_id,
      operation: context.operation,
      rp_id: context.rp_id,
      origin: context.origin,
      user_verification: context.user_verification,
      issued_at: issuedAt,
      expires_at: expiresAt,
      status: "pending"
    };
    records.set(challengeId, record);
    return Object.freeze({
      challenge_id: challengeId,
      challenge,
      challenge_expires_at: new Date(expiresAt).toISOString(),
      rp_id: context.rp_id,
      origin: context.origin,
      user_verification: context.user_verification
    });
  };

  const consume = async (input = {}) => {
    const request = normalizeConsumeInput(input);
    const currentTime = assertClock(now());
    purge(records, currentTime);
    const record = records.get(request.challenge_id);
    if (!record) fail(WEBAUTHN_ERROR_CODES.CHALLENGE_NOT_FOUND);
    if (record.status === "consuming") fail(WEBAUTHN_ERROR_CODES.CHALLENGE_BUSY);
    if (record.status === "consumed" || record.status === "failed") fail(WEBAUTHN_ERROR_CODES.CHALLENGE_REPLAYED);
    if (currentTime >= record.expires_at) {
      record.status = "expired";
      fail(WEBAUTHN_ERROR_CODES.CHALLENGE_EXPIRED);
    }
    if (!sameBinding(record, request)) fail(WEBAUTHN_ERROR_CODES.BINDING_MISMATCH);
    if (!constantTimeHexEqual(record.challenge_digest, sha256(request.challenge))) {
      fail(WEBAUTHN_ERROR_CODES.CHALLENGE_MISMATCH);
    }

    // Validate assertion structure before claiming the one-time record. Wire
    // errors must not be able to burn a valid challenge.
    const verifierInput = buildVerifierInput(record, request);

    // This synchronous transition happens before the first await. In a
    // single process it is the atomic claim; a durable implementation must
    // use an equivalent conditional UPDATE/compare-and-set.
    record.status = "consuming";
    record.consume_started_at = currentTime;

    let verification;
    try {
      verification = await verifyAssertion(verifierInput);
      validateVerifierResult(verification, request, currentTime);
    } catch (error) {
      record.status = "failed";
      record.failed_at = assertClock(now());
      if (error instanceof WebAuthnCeremonyError && error.code === WEBAUTHN_ERROR_CODES.INVALID_VERIFIER_RESULT) throw error;
      fail(WEBAUTHN_ERROR_CODES.VERIFICATION_FAILED);
    }

    record.status = "consumed";
    record.consumed_at = assertClock(now());
    const authenticatedAt = record.consumed_at;
    return Object.freeze({
      verified: true,
      assertion_id: request.challenge_id,
      session_id: record.session_id,
      organization_id: record.organization_id,
      operation: record.operation,
      authenticated_at: authenticatedAt,
      credential_id_digest: sha256(request.credential_id)
    });
  };

  const snapshot = () => {
    purge(records, assertClock(now()));
    return [...records].map(([challengeId, record]) => ({ challenge_id: challengeId, ...publicRecord(record) }));
  };

  return Object.freeze({ begin, consume, snapshot });
}

function buildVerifierInput(record, request) {
  const clientData = decodeClientData(request.client_data_json, request.challenge, record.origin);
  const authenticatorData = decodeAuthenticatorData(request.authenticator_data, record.rp_id, record.user_verification);
  return Object.freeze({
    ceremony: Object.freeze({
      challenge_id: request.challenge_id,
      session_id: record.session_id,
      organization_id: record.organization_id,
      operation: record.operation,
      rp_id: record.rp_id,
      origin: record.origin,
      user_verification: record.user_verification,
      expected_challenge: request.challenge
    }),
    assertion: Object.freeze({
      credential_id: request.credential_id,
      client_data_json: request.client_data_json,
      authenticator_data: request.authenticator_data,
      signature: request.signature,
      ...(request.user_handle === undefined ? {} : { user_handle: request.user_handle })
    }),
    parsed: Object.freeze({
      client_data: Object.freeze(clientData),
      authenticator_data: Object.freeze(authenticatorData)
    })
  });
}

function normalizeContext(input) {
  if (!isObject(input)) fail(WEBAUTHN_ERROR_CODES.INVALID_CONTEXT);
  const session_id = requiredIdentifier(input.session_id ?? input.sessionId, "session_id");
  const organization_id = requiredIdentifier(input.organization_id ?? input.organizationId, "organization_id");
  const operation = requiredOperation(input.operation);
  const rp_id = requiredRpId(input.rp_id ?? input.rpId);
  const origin = requiredOrigin(input.origin);
  const user_verification = input.user_verification ?? input.userVerification ?? "required";
  if (user_verification !== "required") fail(WEBAUTHN_ERROR_CODES.INVALID_CONTEXT);
  return Object.freeze({ session_id, organization_id, operation, rp_id, origin, user_verification });
}

function normalizeConsumeInput(input) {
  if (!isObject(input)) fail(WEBAUTHN_ERROR_CODES.INVALID_REQUEST);
  const challenge_id = requiredUuid(input.challenge_id ?? input.challengeId, "challenge_id");
  const challenge = requiredBase64Url(input.challenge, CHALLENGE_BYTES, "challenge");
  const credential_id = requiredBase64Url(input.credential_id ?? input.credentialId, [1, MAX_CREDENTIAL_ID_BYTES], "credential_id");
  const client_data_json = requiredBase64Url(input.client_data_json ?? input.clientDataJSON, [1, MAX_CLIENT_DATA_BYTES], "client_data_json");
  const authenticator_data = requiredBase64Url(input.authenticator_data ?? input.authenticatorData, [37, MAX_AUTHENTICATOR_DATA_BYTES], "authenticator_data");
  const signature = requiredBase64Url(input.signature, [64, MAX_SIGNATURE_BYTES], "signature");
  let user_handle;
  if (input.user_handle !== undefined || input.userHandle !== undefined) user_handle = requiredBase64Url(input.user_handle ?? input.userHandle, [1, MAX_USER_HANDLE_BYTES], "user_handle");
  const context = normalizeContext(input);
  return Object.freeze({ challenge_id, challenge, credential_id, client_data_json, authenticator_data, signature, ...(user_handle === undefined ? {} : { user_handle }), ...context });
}

function decodeClientData(encoded, expectedChallenge, expectedOrigin) {
  const bytes = decodeBase64Url(encoded, [1, MAX_CLIENT_DATA_BYTES], "client_data_json");
  const text = Buffer.from(bytes).toString("utf8");
  if (Buffer.from(text, "utf8").compare(bytes) !== 0) fail(WEBAUTHN_ERROR_CODES.INVALID_RESPONSE);
  let value;
  try { value = JSON.parse(text); } catch { fail(WEBAUTHN_ERROR_CODES.INVALID_RESPONSE); }
  if (!isObject(value) || Object.keys(value).some((key) => !CLIENT_DATA_KEYS.has(key)) || value.type !== "webauthn.get" || value.challenge !== expectedChallenge || value.origin !== expectedOrigin) fail(WEBAUTHN_ERROR_CODES.INVALID_RESPONSE);
  if (value.crossOrigin !== undefined && value.crossOrigin !== false) fail(WEBAUTHN_ERROR_CODES.INVALID_RESPONSE);
  if (value.tokenBinding !== undefined && (!isObject(value.tokenBinding) || typeof value.tokenBinding.status !== "string")) fail(WEBAUTHN_ERROR_CODES.INVALID_RESPONSE);
  return { type: value.type, challenge: value.challenge, origin: value.origin, ...(value.crossOrigin === undefined ? {} : { cross_origin: value.crossOrigin }) };
}

function decodeAuthenticatorData(encoded, rpId, userVerification) {
  const bytes = decodeBase64Url(encoded, [37, MAX_AUTHENTICATOR_DATA_BYTES], "authenticator_data");
  const expectedRpIdHash = crypto.createHash("sha256").update(rpId).digest();
  if (!crypto.timingSafeEqual(Buffer.from(bytes.subarray(0, 32)), expectedRpIdHash)) fail(WEBAUTHN_ERROR_CODES.INVALID_RESPONSE);
  const flags = bytes[32];
  if ((flags & 0x01) === 0 || (userVerification === "required" && (flags & 0x04) === 0)) fail(WEBAUTHN_ERROR_CODES.INVALID_RESPONSE);
  return { rp_id_hash: Buffer.from(bytes.subarray(0, 32)).toString("base64url"), flags, user_present: true, user_verified: (flags & 0x04) !== 0, sign_count: Buffer.from(bytes.subarray(33, 37)).readUInt32BE(0) };
}

function validateVerifierResult(result, request, now) {
  if (!isObject(result) || result.verified !== true || typeof result.credential_id !== "string" || result.credential_id !== request.credential_id || Object.keys(result).some((key) => !VERIFIER_RESULT_KEYS.has(key))) fail(WEBAUTHN_ERROR_CODES.INVALID_VERIFIER_RESULT);
  if (result.sign_count !== undefined && (!Number.isSafeInteger(result.sign_count) || result.sign_count < 0 || result.sign_count > 0xffffffff)) fail(WEBAUTHN_ERROR_CODES.INVALID_VERIFIER_RESULT);
  if (result.authenticated_at !== undefined) {
    if (!Number.isSafeInteger(result.authenticated_at) || result.authenticated_at > now + MAX_CLOCK_SKEW_MS || result.authenticated_at < 0) fail(WEBAUTHN_ERROR_CODES.INVALID_VERIFIER_RESULT);
  }
}

function sameBinding(record, request) {
  return record.session_id === request.session_id && record.organization_id === request.organization_id && record.operation === request.operation && record.rp_id === request.rp_id && record.origin === request.origin && record.user_verification === request.user_verification;
}

function publicRecord(record) {
  return { session_id: record.session_id, organization_id: record.organization_id, operation: record.operation, rp_id: record.rp_id, origin: record.origin, user_verification: record.user_verification, issued_at: record.issued_at, expires_at: record.expires_at, status: record.status, ...(record.consume_started_at === undefined ? {} : { consume_started_at: record.consume_started_at }), ...(record.consumed_at === undefined ? {} : { consumed_at: record.consumed_at }), ...(record.failed_at === undefined ? {} : { failed_at: record.failed_at }) };
}

function purge(records, now) {
  for (const [id, record] of records) {
    if (record.status === "pending" && now >= record.expires_at) record.status = "expired";
    if (record.status !== "pending" && record.status !== "consuming" && now - record.expires_at > MAX_TTL_MS) records.delete(id);
  }
}

function pendingCount(records) { return [...records.values()].filter((record) => record.status === "pending" || record.status === "consuming").length; }
function sha256(value) { return crypto.createHash("sha256").update(value, "utf8").digest("hex"); }
function constantTimeHexEqual(left, right) { const a = Buffer.from(left, "hex"); const b = Buffer.from(right, "hex"); return a.length === b.length && crypto.timingSafeEqual(a, b); }
function isObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function assertClock(value) { if (!Number.isSafeInteger(value) || value < 0) throw new TypeError("clock value is invalid"); return value; }
function requiredUuid(value, field) { if (typeof value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) fail(WEBAUTHN_ERROR_CODES.INVALID_REQUEST, field); return value.toLowerCase(); }
function requiredIdentifier(value, field) { if (typeof value !== "string" || !IDENTIFIER.test(value) || /[\u0000-\u001f\u007f]/.test(value)) fail(WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, field); return value; }
function requiredOperation(value) { if (typeof value !== "string" || !OPERATION.test(value) || /[\u0000-\u001f\u007f]/.test(value)) fail(WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, "operation"); return value; }
function requiredRpId(value) { if (typeof value !== "string" || value.length < 1 || value.length > 253 || !/^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(value) || value.includes("..")) fail(WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, "rp_id"); return value.toLowerCase(); }
function requiredOrigin(value) { if (typeof value !== "string" || value.length > 512 || /[\u0000-\u001f\u007f]/.test(value)) fail(WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, "origin"); let url; try { url = new URL(value); } catch { fail(WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, "origin"); } if (!ORIGIN_SCHEMES.has(url.protocol) || url.username || url.password || url.pathname !== "/" || url.search || url.hash || (url.protocol === "http:" && url.hostname !== "localhost" && url.hostname !== "127.0.0.1" && url.hostname !== "[::1]")) fail(WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, "origin"); return url.origin; }
function requiredBase64Url(value, length, field) { if (typeof value !== "string" || !BASE64URL.test(value)) fail(WEBAUTHN_ERROR_CODES.INVALID_REQUEST, field); decodeBase64Url(value, length, field); return value; }
function decodeBase64Url(value, length, field) { if (typeof value !== "string" || !BASE64URL.test(value)) fail(WEBAUTHN_ERROR_CODES.INVALID_RESPONSE, field); let bytes; try { bytes = Buffer.from(value, "base64url"); } catch { fail(WEBAUTHN_ERROR_CODES.INVALID_RESPONSE, field); } const [minimum, maximum] = Array.isArray(length) ? length : [length, length]; if (bytes.length < minimum || bytes.length > maximum || bytes.toString("base64url") !== value) fail(WEBAUTHN_ERROR_CODES.INVALID_RESPONSE, field); return bytes; }
function fail(code, details) { throw new WebAuthnCeremonyError(code, details); }
