import crypto from "node:crypto";

import {
  normalizeHostedOrganizationName
} from "./organization-name.mjs";

const TOKEN = /^[A-Za-z0-9._~-]{16,4096}$/u;
const DIGEST = /^[0-9a-f]{64}$/iu;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._~-]{8,255}$/u;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u;
const CSRF_FRAME = Buffer.from("agentpass/hosted-identity-bootstrap\0v1\0csrf\0", "utf8");
const STATES = new Set([
  "oauth_started",
  "identity_verified",
  "organization_required",
  "webauthn_required",
  "ready",
  "no_membership",
  "completed",
  "expired"
]);
const PUBLIC_ERROR_CODES = new Set([
  "bootstrap_service_config_invalid",
  "bootstrap_invalid_request",
  "bootstrap_session_required",
  "bootstrap_session_expired",
  "bootstrap_csrf_failed",
  "bootstrap_idempotency_conflict",
  "bootstrap_unavailable"
]);

export const HOSTED_BOOTSTRAP_SERVICE_ERROR_CODES = Object.freeze({
  CONFIG: "bootstrap_service_config_invalid",
  INPUT: "bootstrap_invalid_request",
  SESSION_REQUIRED: "bootstrap_session_required",
  SESSION_EXPIRED: "bootstrap_session_expired",
  CSRF_FAILED: "bootstrap_csrf_failed",
  IDEMPOTENCY_CONFLICT: "bootstrap_idempotency_conflict",
  UNAVAILABLE: "bootstrap_unavailable"
});

// The shorter alias is kept for callers that name the facade by its Hosted
// bootstrap HTTP role rather than by the identity package name.
const ERROR_MESSAGES = Object.freeze({
  [HOSTED_BOOTSTRAP_SERVICE_ERROR_CODES.CONFIG]: "Hosted bootstrap service configuration is invalid",
  [HOSTED_BOOTSTRAP_SERVICE_ERROR_CODES.INPUT]: "The bootstrap request is invalid",
  [HOSTED_BOOTSTRAP_SERVICE_ERROR_CODES.SESSION_REQUIRED]: "A valid bootstrap session is required",
  [HOSTED_BOOTSTRAP_SERVICE_ERROR_CODES.SESSION_EXPIRED]: "The bootstrap session has expired",
  [HOSTED_BOOTSTRAP_SERVICE_ERROR_CODES.CSRF_FAILED]: "The bootstrap CSRF token is invalid",
  [HOSTED_BOOTSTRAP_SERVICE_ERROR_CODES.IDEMPOTENCY_CONFLICT]: "The idempotency key conflicts with an earlier request",
  [HOSTED_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE]: "The bootstrap service is temporarily unavailable"
});

export class HostedBootstrapServiceError extends Error {
  constructor(code) {
    const safeCode = PUBLIC_ERROR_CODES.has(code)
      ? code
      : HOSTED_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE;
    super(ERROR_MESSAGES[safeCode]);
    this.name = "HostedBootstrapServiceError";
    this.code = safeCode;
  }
}

/**
 * Facade for the browser-facing Hosted bootstrap boundary.
 *
 * The CSRF value is a deterministic, restart-safe projection of the opaque
 * bootstrap cookie. Only its digest is persisted by the repository; this
 * facade never logs or returns the dedicated key.
 */
export function createHostedBootstrapService(options = {}) {
  if (!isPlainObject(options)) {
    throw serviceError(HOSTED_BOOTSTRAP_SERVICE_ERROR_CODES.CONFIG);
  }
  try { exactKeys(options, ["repository", "organizationService", "csrfKey"]); }
  catch { throw serviceError(HOSTED_BOOTSTRAP_SERVICE_ERROR_CODES.CONFIG); }

  const { repository, organizationService, csrfKey } = options;
  if (!repository || typeof repository.getBootstrapStatus !== "function"
    || typeof repository.verifyBootstrapCsrf !== "function"
    || !organizationService || typeof organizationService.createOrganization !== "function"
    || !isExactly32Bytes(csrfKey)) {
    throw serviceError(HOSTED_BOOTSTRAP_SERVICE_ERROR_CODES.CONFIG);
  }

  // Copy the caller's key so later mutation of a Uint8Array cannot change the
  // derivation. The copy is closure-private and is never part of an error or
  // returned DTO.
  const key = Buffer.from(csrfKey);

  async function status(input = {}) {
    let request;
    try {
      request = normalizeBootstrapInput(input);
    } catch {
      throw serviceError(HOSTED_BOOTSTRAP_SERVICE_ERROR_CODES.INPUT);
    }

    const csrfToken = deriveCsrfToken(key, request.bootstrap_token);
    let result;
    try {
      result = await repository.getBootstrapStatus(Object.freeze({
        bootstrap_cookie: request.bootstrap_token,
        csrf_token: csrfToken
      }));
    } catch (error) {
      throw mapDependencyError(error);
    }
    if (result === null) throw serviceError(HOSTED_BOOTSTRAP_SERVICE_ERROR_CODES.SESSION_REQUIRED);

    let normalized;
    try {
      normalized = normalizeStatusResult(result);
    } catch {
      throw serviceError(HOSTED_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
    }
    // PostgreSQL status_v2 owns expiry using its database clock. The
    // application must not reinterpret expires_at with a local wall clock.
    if (normalized.state === "expired") {
      throw serviceError(HOSTED_BOOTSTRAP_SERVICE_ERROR_CODES.SESSION_EXPIRED);
    }

    return Object.freeze({
      state: normalized.state,
      webauthn_required: normalized.webauthn_required,
      can_create_first_organization: normalized.can_create_first_organization,
      organization_count: normalized.organization_count,
      csrf_token: csrfToken,
      expires_at: normalized.expires_at
    });
  }

  async function verifyCsrf(input = {}) {
    let request;
    try {
      request = normalizeCsrfInput(input);
    } catch {
      throw serviceError(HOSTED_BOOTSTRAP_SERVICE_ERROR_CODES.INPUT);
    }

    const expected = deriveCsrfToken(key, request.bootstrap_token);
    // Compare before invoking the repository. Padding keeps the comparison
    // length constant for malformed-but-bounded candidates while the final
    // length check preserves the exact 43-character public token contract.
    const supplied = Buffer.from(request.csrf_token, "utf8");
    const padded = Buffer.alloc(expected.length);
    supplied.copy(padded, 0, 0, Math.min(supplied.length, padded.length));
    const sameBytes = crypto.timingSafeEqual(Buffer.from(expected, "utf8"), padded);
    if (!sameBytes || supplied.length !== Buffer.byteLength(expected, "utf8")) return false;

    let result;
    try {
      result = await repository.verifyBootstrapCsrf(Object.freeze({
        bootstrap_cookie: request.bootstrap_token,
        csrf_token: request.csrf_token
      }));
    } catch (error) {
      throw mapDependencyError(error);
    }
    if (typeof result !== "boolean") throw serviceError(HOSTED_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
    return result;
  }

  async function createOrganization(input = {}) {
    let request;
    try {
      request = normalizeOrganizationInput(input);
    } catch {
      throw serviceError(HOSTED_BOOTSTRAP_SERVICE_ERROR_CODES.INPUT);
    }

    let result;
    try {
      // request_hash is accepted only as a server-produced HTTP binding. It
      // is deliberately not forwarded: the organization service derives its
      // canonical request digest and owns the durable transaction.
      result = await organizationService.createOrganization(Object.freeze({
        bootstrap_token: request.bootstrap_token,
        name: request.name,
        idempotency_key: request.idempotency_key
      }));
    } catch (error) {
      throw mapDependencyError(error);
    }

    try {
      return normalizeOrganizationResult(result);
    } catch {
      throw serviceError(HOSTED_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
    }
  }

  return Object.freeze({ status, verifyCsrf, createOrganization });
}

function deriveCsrfToken(key, bootstrapToken) {
  return crypto.createHmac("sha256", key)
    .update(CSRF_FRAME)
    .update(Buffer.from(bootstrapToken, "utf8"))
    .digest("base64url");
}

function normalizeBootstrapInput(value) {
  exactKeys(value, ["bootstrap_token"]);
  return Object.freeze({ bootstrap_token: token(value.bootstrap_token) });
}

function normalizeCsrfInput(value) {
  exactKeys(value, ["bootstrap_token", "csrf_token"]);
  const bootstrapToken = token(value.bootstrap_token);
  if (typeof value.csrf_token !== "string" || value.csrf_token.length < 1 || value.csrf_token.length > 4096 || /[\u0000-\u001f\u007f]/u.test(value.csrf_token)) throw new TypeError("csrf token is invalid");
  return Object.freeze({ bootstrap_token: bootstrapToken, csrf_token: value.csrf_token });
}

function normalizeOrganizationInput(value) {
  exactKeys(value, ["bootstrap_token", "name", "idempotency_key"], ["request_hash"]);
  const bootstrapToken = token(value.bootstrap_token);
  let name;
  try { name = normalizeHostedOrganizationName(value.name); } catch { throw new TypeError("organization name is invalid"); }
  if (typeof value.idempotency_key !== "string" || !IDEMPOTENCY_KEY.test(value.idempotency_key)) throw new TypeError("idempotency key is invalid");
  if (Object.hasOwn(value, "request_hash") && (typeof value.request_hash !== "string" || !DIGEST.test(value.request_hash))) throw new TypeError("request hash is invalid");
  return Object.freeze({
    bootstrap_token: bootstrapToken,
    name,
    idempotency_key: value.idempotency_key,
    ...(Object.hasOwn(value, "request_hash") ? { request_hash: value.request_hash.toLowerCase() } : {})
  });
}

function normalizeStatusResult(value) {
  if (!isPlainObject(value) || !exactKeys(value, ["state", "organization_count", "webauthn_required", "can_create_first_organization", "expires_at"])) throw new TypeError("status result is invalid");
  if (typeof value.state !== "string" || !STATES.has(value.state)
    || !Number.isSafeInteger(value.organization_count) || value.organization_count < 0
    || typeof value.webauthn_required !== "boolean"
    || typeof value.can_create_first_organization !== "boolean"
    || typeof value.expires_at !== "string" || !RFC3339.test(value.expires_at)) throw new TypeError("status result is invalid");
  const expiresAt = Date.parse(value.expires_at);
  if (!Number.isFinite(expiresAt)) throw new TypeError("status result is invalid");
  return Object.freeze({ ...value });
}

function normalizeOrganizationResult(value) {
  if (!isPlainObject(value) || !exactKeys(value, ["response_json", "replayed"], ["response_status"]) || typeof value.replayed !== "boolean" || !isPlainObject(value.response_json)) throw new TypeError("organization result is invalid");
  if (!Object.hasOwn(value, "response_status")
    || (value.response_status !== 200 && value.response_status !== 201)
    || value.replayed !== (value.response_status === 200)) throw new TypeError("organization result is invalid");
  const response = value.response_json;
  if (!Object.hasOwn(response, "organization") || !isPlainObject(response.organization)) throw new TypeError("organization result is invalid");
  return Object.freeze({ organization: response.organization, replayed: value.replayed });
}

function mapDependencyError(error) {
  const code = error?.code;
  if (PUBLIC_ERROR_CODES.has(code)) return serviceError(code);
  return serviceError(HOSTED_BOOTSTRAP_SERVICE_ERROR_CODES.UNAVAILABLE);
}

function token(value) {
  if (typeof value !== "string" || !TOKEN.test(value)) throw new TypeError("bootstrap token is invalid");
  return value;
}

function exactKeys(value, required, optional = []) {
  if (!isPlainObject(value)) throw new TypeError("object is invalid");
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(value);
  if (keys.some((key) => !allowed.has(key)) || required.some((key) => !Object.hasOwn(value, key))) throw new TypeError("object keys are invalid");
  return true;
}

function isExactly32Bytes(value) {
  return (Buffer.isBuffer(value) || value instanceof Uint8Array) && value.length === 32;
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function serviceError(code) {
  return new HostedBootstrapServiceError(code);
}

export default createHostedBootstrapService;
