import crypto from "node:crypto";

import {
  HUMAN_SESSION_CSRF_HEADER,
  HUMAN_SESSION_ERROR_CODES,
  isOpaqueToken,
  parseSessionCookie
} from "../../human-session.mjs";
import {
  OWNER_RECOVERY_ERROR_CODES,
  OWNER_RECOVERY_OPERATIONS,
  OwnerRecoveryError
} from "./service.mjs";
import {
  HumanAuthAbuseControlError,
  HUMAN_AUTH_ABUSE_ERROR_CODES,
  HUMAN_AUTH_RATE_LIMIT_OPERATIONS
} from "../rate-limit.mjs";

const ROOT = "/api/auth/organizations";
const RECOVERY_ROOT = "/api/auth/recovery";
const MAX_BODY_BYTES = 64 * 1024;
const MAX_HEADER_BYTES = 8 * 1024;
const MAX_URL_LENGTH = 8 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const OPAQUE = /^[A-Za-z0-9_-]{43}$/u;
const IF_MATCH = /^"([1-9][0-9]*)"$/u;
const MAX_THRESHOLD = 32;
const SESSION_FAILURES = new Set([
  HUMAN_SESSION_ERROR_CODES.INVALID_COOKIE,
  HUMAN_SESSION_ERROR_CODES.SESSION_NOT_FOUND,
  HUMAN_SESSION_ERROR_CODES.SESSION_REVOKED,
  HUMAN_SESSION_ERROR_CODES.SESSION_EXPIRED
]);
const CSRF_FAILURES = new Set([HUMAN_SESSION_ERROR_CODES.CSRF_REQUIRED, HUMAN_SESSION_ERROR_CODES.CSRF_INVALID]);
const ALLOWED_HEADERS = new Set(["origin", "cookie", "content-type", "content-length", "accept", "cache-control", "pragma", "idempotency-key", HUMAN_SESSION_CSRF_HEADER, "agentpass-recent-auth", "if-match"]);
const FORBIDDEN_IDENTITY_HEADERS = new Set(["agentpass-member-id", "agentpass-organization-id", "agentpass-role", "agentpass-console-identity", "x-agentpass-identity", "x-csrf-token"]);

export const OWNER_RECOVERY_HTTP_PATHS = Object.freeze({
  requests: (organizationId) => `${ROOT}/${encodeURIComponent(organizationId)}/recovery-requests`,
  request: (organizationId, requestId) => `${ROOT}/${encodeURIComponent(organizationId)}/recovery-requests/${encodeURIComponent(requestId)}`,
  approve: (organizationId, requestId) => `${ROOT}/${encodeURIComponent(organizationId)}/recovery-requests/${encodeURIComponent(requestId)}/approve`,
  cancel: (organizationId, requestId) => `${ROOT}/${encodeURIComponent(organizationId)}/recovery-requests/${encodeURIComponent(requestId)}/cancel`,
  exchange: `${RECOVERY_ROOT}/exchange`,
  registrationOptions: `${RECOVERY_ROOT}/webauthn/registration/options`,
  registrationVerify: `${RECOVERY_ROOT}/webauthn/registration/verify`,
  activate: `${RECOVERY_ROOT}/activate`
});

// Names used by callers that prefer the route names from the design document.
export const HUMAN_OWNER_RECOVERY_HTTP_PATHS = OWNER_RECOVERY_HTTP_PATHS;

export const OWNER_RECOVERY_HTTP_ERROR_CODES = Object.freeze({
  INVALID_REQUEST: "owner_recovery_http_invalid_request",
  METHOD_NOT_ALLOWED: "owner_recovery_http_method_not_allowed",
  ORIGIN_NOT_ALLOWED: "owner_recovery_http_origin_not_allowed",
  SESSION_REQUIRED: "owner_recovery_http_session_required",
  CSRF_FAILED: "owner_recovery_http_csrf_failed",
  RECOVERY_SESSION_REQUIRED: "owner_recovery_http_recovery_session_required",
  FORBIDDEN: "owner_recovery_http_forbidden",
  NOT_FOUND: "owner_recovery_http_not_found",
  STALE_VERSION: "owner_recovery_http_stale_version",
  APPROVAL_REPLAYED: "owner_recovery_http_approval_replayed",
  THRESHOLD_UNAVAILABLE: "owner_recovery_http_threshold_unavailable",
  DELAY_NOT_ELAPSED: "owner_recovery_http_delay_not_elapsed",
  EXCHANGE_INVALID: "owner_recovery_http_exchange_invalid",
  EXCHANGE_REPLAYED: "owner_recovery_http_exchange_replayed",
  REGISTRATION_INVALID: "owner_recovery_http_registration_invalid",
  CREDENTIAL_EXISTS: "owner_recovery_http_credential_exists",
  ACTIVATION_INVALID: "owner_recovery_http_activation_invalid",
  ACTIVATION_REPLAYED: "owner_recovery_http_activation_replayed",
  RECENT_AUTH_REQUIRED: "owner_recovery_http_recent_auth_required",
  RECENT_AUTH_FAILED: "owner_recovery_http_recent_auth_failed",
  RECENT_AUTH_STALE: "owner_recovery_http_recent_auth_stale",
  RECENT_AUTH_UNAVAILABLE: "owner_recovery_http_recent_auth_unavailable",
  RECOVERY_UNAVAILABLE: "owner_recovery_http_unavailable",
  INTERNAL_ERROR: "owner_recovery_http_internal_error"
});

const HCODE = OWNER_RECOVERY_HTTP_ERROR_CODES;
const MESSAGES = Object.freeze({
  [HCODE.INVALID_REQUEST]: "The recovery request is invalid",
  [HCODE.METHOD_NOT_ALLOWED]: "The HTTP method is not allowed",
  [HCODE.ORIGIN_NOT_ALLOWED]: "The request origin is not allowed",
  [HCODE.SESSION_REQUIRED]: "A valid human session is required",
  [HCODE.CSRF_FAILED]: "The CSRF token is invalid",
  [HCODE.RECOVERY_SESSION_REQUIRED]: "A valid recovery session is required",
  [HCODE.FORBIDDEN]: "The recovery operation is not allowed",
  [HCODE.NOT_FOUND]: "The recovery request was not found",
  [HCODE.STALE_VERSION]: "The recovery request was changed by another request",
  [HCODE.APPROVAL_REPLAYED]: "The recovery approval is no longer valid",
  [HCODE.THRESHOLD_UNAVAILABLE]: "The organization cannot satisfy the recovery threshold",
  [HCODE.DELAY_NOT_ELAPSED]: "The recovery delay has not elapsed",
  [HCODE.EXCHANGE_INVALID]: "The recovery exchange is invalid",
  [HCODE.EXCHANGE_REPLAYED]: "The recovery exchange is no longer valid",
  [HCODE.REGISTRATION_INVALID]: "The recovery registration is invalid",
  [HCODE.CREDENTIAL_EXISTS]: "The recovery credential already exists",
  [HCODE.ACTIVATION_INVALID]: "The recovery activation is invalid",
  [HCODE.ACTIVATION_REPLAYED]: "The recovery activation is no longer valid",
  [HCODE.RECENT_AUTH_REQUIRED]: "Recent WebAuthn authentication is required",
  [HCODE.RECENT_AUTH_FAILED]: "Recent WebAuthn authentication failed",
  [HCODE.RECENT_AUTH_STALE]: "Recent WebAuthn authentication is stale",
  [HCODE.RECENT_AUTH_UNAVAILABLE]: "Recent WebAuthn verification is unavailable",
  [HCODE.RECOVERY_UNAVAILABLE]: "The recovery service is unavailable",
  [HCODE.INTERNAL_ERROR]: "The request could not be completed"
});

const STATUS = Object.freeze({
  [HCODE.INVALID_REQUEST]: 400, [HCODE.METHOD_NOT_ALLOWED]: 405, [HCODE.ORIGIN_NOT_ALLOWED]: 403,
  [HCODE.SESSION_REQUIRED]: 401, [HCODE.CSRF_FAILED]: 403, [HCODE.RECOVERY_SESSION_REQUIRED]: 401,
  [HCODE.FORBIDDEN]: 403, [HCODE.NOT_FOUND]: 404, [HCODE.STALE_VERSION]: 409,
  [HCODE.APPROVAL_REPLAYED]: 409, [HCODE.THRESHOLD_UNAVAILABLE]: 409, [HCODE.DELAY_NOT_ELAPSED]: 409,
  [HCODE.EXCHANGE_INVALID]: 401, [HCODE.EXCHANGE_REPLAYED]: 409, [HCODE.REGISTRATION_INVALID]: 422,
  [HCODE.CREDENTIAL_EXISTS]: 409, [HCODE.ACTIVATION_INVALID]: 422, [HCODE.ACTIVATION_REPLAYED]: 409,
  [HCODE.RECENT_AUTH_REQUIRED]: 401, [HCODE.RECENT_AUTH_FAILED]: 401, [HCODE.RECENT_AUTH_STALE]: 401,
  [HCODE.RECENT_AUTH_UNAVAILABLE]: 503, [HCODE.RECOVERY_UNAVAILABLE]: 503, [HCODE.INTERNAL_ERROR]: 500
});

export class OwnerRecoveryHttpError extends Error {
  constructor(code, { status = STATUS[code] ?? 500, allow = undefined, cause = undefined } = {}) {
    void cause;
    super(MESSAGES[code] ?? MESSAGES[HCODE.INTERNAL_ERROR]);
    this.name = "OwnerRecoveryHttpError";
    this.code = code;
    this.status = status;
    this.allow = allow;
  }
}

/**
 * Framework-neutral boundary. Normal-session lanes use the injected human
 * session only for browser authentication. Exchange and all subsequent lanes
 * use the recovery service's digest-backed bearer authentication and never
 * consult normal human_sessions.
 */
export function createOwnerRecoveryHttpApi({
  humanSession,
  recentAuthService,
  recoveryService,
  service = undefined,
  abuseControls = undefined,
  origin,
  basePath = "",
  maxBodyBytes = MAX_BODY_BYTES,
  now = () => Date.now()
} = {}) {
  if (!humanSession || typeof humanSession.authenticateRequest !== "function") throw new TypeError("humanSession must expose authenticateRequest()");
  if (!recentAuthService || typeof recentAuthService.authorize !== "function") throw new TypeError("recentAuthService must expose authorize()");
  const injected = recoveryService ?? service;
  assertService(injected);
  if (abuseControls !== undefined && typeof abuseControls?.check !== "function") throw new TypeError("abuseControls must expose check()");
  const expectedOrigin = origin ?? humanSession.expectedOrigin;
  assertOrigin(expectedOrigin);
  if (typeof now !== "function") throw new TypeError("now must be a function");
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1_024 || maxBodyBytes > 1_024 * 1_024) throw new TypeError("maxBodyBytes is invalid");
  const normalizedBasePath = normalizeBasePath(basePath);

  async function handle(input, nodeResponse = undefined) {
    const result = await dispatch(input);
    if (nodeResponse !== undefined) writeNodeResponse(nodeResponse, result);
    return result;
  }

  async function dispatch(input) {
    try {
      const request = normalizeRequest(input);
      const route = resolveRoute(request.url, normalizedBasePath);
      if (!route) return response(404, { error: { code: "not_found", message: "Resource not found" } });
      if (request.query !== "") throw invalidRequest();
      if (route.normal) {
        const actor = await authenticateNormalSession(request);
        if (request.method !== route.method) throw methodNotAllowed(route.allow);
        await checkAbuse(route.operation, actor, route.organizationId);
        if (route.name === "get") {
          if (hasBody(request)) throw invalidRequest();
          return response(200, await callService(injected, "get", { actor, organization_id: route.organizationId, request_id: route.requestId }));
        }
        const body = route.name === "create" ? await readJsonBody(request, maxBodyBytes) : await readJsonBody(request, maxBodyBytes);
        const idempotencyKey = requiredIdempotencyKey(request);
        if (route.name === "create") return response(201, await callService(injected, "create", { actor, organization_id: route.organizationId, subject_member_id: actor.member_id, idempotency_key: idempotencyKey, ...parseCreateBody(body) }));
        const expectedVersion = parseExpectedVersion(request, body);
        if (route.name === "approve") {
          if (actor.organization_id !== route.organizationId || actor.role !== "owner") throw new OwnerRecoveryHttpError(HCODE.FORBIDDEN);
          const recentAuthorization = await requireRecentAuth(actor, route.organizationId, request);
          return response(200, await callService(injected, "approve", { actor, organization_id: route.organizationId, request_id: route.requestId, expected_version: expectedVersion, idempotency_key: idempotencyKey, recent_authorization: recentAuthorization }));
        }
        if (actor.organization_id !== route.organizationId || actor.role !== "owner") throw new OwnerRecoveryHttpError(HCODE.FORBIDDEN);
        return response(200, await callService(injected, "cancel", { actor, organization_id: route.organizationId, request_id: route.requestId, expected_version: expectedVersion, idempotency_key: idempotencyKey }));
      }

      assertRecoveryOrigin(request, expectedOrigin);
      if (request.method !== "POST") throw methodNotAllowed("POST");
      if (route.name === "exchange") {
        const body = await readJsonBody(request, maxBodyBytes);
        const exchange = parseExchangeBody(body);
        const principal = anonymousExchangePrincipal(exchange.exchange);
        await checkAbuse(route.operation, principal, principal.organization_id);
        const exchanged = await callService(injected, "exchange", exchange);
        const token = exchanged?.recovery_session_token;
        if (typeof token !== "string" || !OPAQUE.test(token) || !plainObject(exchanged?.recovery_session)) throw new OwnerRecoveryHttpError(HCODE.EXCHANGE_INVALID);
        const metadata = { request_id: exchanged.request_id, recovery_session: publicRecoverySession(exchanged.recovery_session) };
        return response(200, metadata, { "Set-Cookie": serializeRecoveryCookie(token) });
      }
      const token = recoveryCookie(request);
      const recoveryPrincipal = await authenticateRecoveryForAbuse(injected, token, route.name);
      await checkAbuse(route.operation, recoveryPrincipal, recoveryPrincipal.organization_id);
      const body = await readJsonBody(request, maxBodyBytes);
      if (route.name === "registrationOptions") {
        assertExactKeys(body, ["request_id"]);
        const requestId = requiredUuid(body.request_id);
        return response(200, await callService(injected, "registrationOptions", { session_token: token, request_id: requestId }));
      }
      if (route.name === "registrationVerify") {
        assertExactKeys(body, ["organization_id", "challenge_id", "credential"]);
        const organizationId = requiredUuid(body.organization_id);
        const challengeId = requiredUuid(body.challenge_id);
        if (!plainObject(body.credential)) throw invalidRequest();
        return response(201, await callService(injected, "registrationVerify", { session_token: token, organization_id: organizationId, challenge_id: challengeId, credential: body.credential }));
      }
      assertExactKeys(body, ["organization_id", "challenge_id", "assertion"]);
      const organizationId = requiredUuid(body.organization_id);
      const challengeId = requiredUuid(body.challenge_id);
      if (!plainObject(body.assertion)) throw invalidRequest();
      return response(200, await callService(injected, "activate", { session_token: token, organization_id: organizationId, challenge_id: challengeId, assertion: body.assertion }));
    } catch (error) { return mapError(error); }
  }

  async function authenticateNormalSession(request) {
    assertNormalOrigin(request, expectedOrigin);
    const cookie = header(request.headers, "cookie");
    try { parseSessionCookie(cookie); } catch (error) { throw new OwnerRecoveryHttpError(HCODE.SESSION_REQUIRED, { cause: error }); }
    const csrfToken = header(request.headers, HUMAN_SESSION_CSRF_HEADER);
    if (!isOpaqueToken(csrfToken)) throw new OwnerRecoveryHttpError(HCODE.CSRF_FAILED);
    try {
      const authenticated = await humanSession.authenticateRequest({ method: "POST", headers: request.headers, origin: expectedOrigin, cookie, csrfToken });
      return normalizeActor(authenticated?.session);
    } catch (error) {
      if (error?.code === HUMAN_SESSION_ERROR_CODES.INVALID_ORIGIN) throw new OwnerRecoveryHttpError(HCODE.ORIGIN_NOT_ALLOWED, { cause: error });
      if (CSRF_FAILURES.has(error?.code)) throw new OwnerRecoveryHttpError(HCODE.CSRF_FAILED, { cause: error });
      if (SESSION_FAILURES.has(error?.code)) throw new OwnerRecoveryHttpError(HCODE.SESSION_REQUIRED, { cause: error });
      throw new OwnerRecoveryHttpError(HCODE.SESSION_REQUIRED, { cause: error });
    }
  }

  async function requireRecentAuth(actor, organizationId, request) {
    const proof = header(request.headers, "agentpass-recent-auth");
    if (typeof proof !== "string" || !UUID.test(proof)) throw new OwnerRecoveryHttpError(HCODE.RECENT_AUTH_REQUIRED);
    let result;
    try {
      result = await recentAuthService.authorize({ proof, principal: actor, organization_id: organizationId, operation: OWNER_RECOVERY_OPERATIONS.approve, now: now() });
    } catch (error) { throw new OwnerRecoveryHttpError(HCODE.RECENT_AUTH_UNAVAILABLE, { cause: error }); }
    if (!result || result.verified !== true || result.consumed !== true) throw new OwnerRecoveryHttpError(HCODE.RECENT_AUTH_FAILED);
    if (result.operation !== OWNER_RECOVERY_OPERATIONS.approve || result.organization_id !== organizationId || result.member_id !== actor.member_id) throw new OwnerRecoveryHttpError(HCODE.RECENT_AUTH_FAILED);
    if (!Number.isSafeInteger(result.authenticated_at)) throw new OwnerRecoveryHttpError(HCODE.RECENT_AUTH_FAILED);
    return result;
  }

  async function authenticateRecoveryForAbuse(service, token, routeName) {
    if (typeof service.authenticateRecoverySession !== "function") throw new OwnerRecoveryHttpError(HCODE.RECOVERY_UNAVAILABLE);
    const requiredStage = routeName === "activate" ? "credential_enrolled" : "session_issued";
    try {
      const session = await service.authenticateRecoverySession({ session_token: token, required_stage: requiredStage });
      if (!session || typeof session !== "object") throw new Error("recovery session is invalid");
      return session;
    } catch (error) { throw mapServiceError(error); }
  }

  async function checkAbuse(operation, session, organizationId, cost = 1) {
    if (abuseControls === undefined) return;
    try {
      await abuseControls.check({ operation, session, organizationId, cost });
    } catch (error) {
      if (error instanceof HumanAuthAbuseControlError) throw error;
      throw new HumanAuthAbuseControlError(HUMAN_AUTH_ABUSE_ERROR_CODES.CONTROL_UNAVAILABLE, { cause: error });
    }
  }

  return Object.freeze({ handle, paths: OWNER_RECOVERY_HTTP_PATHS, expectedOrigin, basePath: normalizedBasePath });
}

function anonymousExchangePrincipal(exchange) {
  // Exchange values have 256 bits of entropy. Derive unlinkable UUID-shaped
  // bucket IDs so an unauthenticated caller cannot exhaust one process-wide
  // recovery bucket, while the raw exchange value never leaves this boundary.
  const derive = (scope) => {
    const bytes = crypto.createHash("sha256").update(`agentpass:recovery-exchange:v1:${scope}:`, "utf8").update(exchange, "utf8").digest().subarray(0, 16);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = bytes.toString("hex");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  };
  return Object.freeze({ session_id: derive("session"), member_id: derive("member"), organization_id: derive("organization"), role: "anonymous" });
}

function assertService(service) {
  if (!service || typeof service.create !== "function" || typeof service.get !== "function" || typeof service.approve !== "function" || typeof service.cancel !== "function" || typeof service.exchange !== "function" || typeof service.registrationOptions !== "function" || typeof service.registrationVerify !== "function" || typeof service.activate !== "function") throw new TypeError("recoveryService is incomplete");
}

async function callService(service, method, input) {
  try { return await service[method](input); }
  catch (error) { throw mapServiceError(error); }
}

function mapServiceError(error) {
  if (error instanceof OwnerRecoveryHttpError) return error;
  const code = String(error?.code ?? error?.reason ?? error?.name ?? "").toLowerCase();
  const mappings = new Map([
    [OWNER_RECOVERY_ERROR_CODES.INVALID_REQUEST, HCODE.INVALID_REQUEST], [OWNER_RECOVERY_ERROR_CODES.FORBIDDEN, HCODE.FORBIDDEN], [OWNER_RECOVERY_ERROR_CODES.NOT_FOUND, HCODE.NOT_FOUND],
    [OWNER_RECOVERY_ERROR_CODES.VERSION_CONFLICT, HCODE.STALE_VERSION], [OWNER_RECOVERY_ERROR_CODES.APPROVAL_REPLAYED, HCODE.APPROVAL_REPLAYED], [OWNER_RECOVERY_ERROR_CODES.THRESHOLD_UNAVAILABLE, HCODE.THRESHOLD_UNAVAILABLE],
    [OWNER_RECOVERY_ERROR_CODES.DELAY_NOT_ELAPSED, HCODE.DELAY_NOT_ELAPSED], [OWNER_RECOVERY_ERROR_CODES.EXCHANGE_INVALID, HCODE.EXCHANGE_INVALID], [OWNER_RECOVERY_ERROR_CODES.EXCHANGE_REPLAYED, HCODE.EXCHANGE_REPLAYED],
    [OWNER_RECOVERY_ERROR_CODES.SESSION_REQUIRED, HCODE.RECOVERY_SESSION_REQUIRED], [OWNER_RECOVERY_ERROR_CODES.SESSION_REPLAYED, HCODE.RECOVERY_SESSION_REQUIRED], [OWNER_RECOVERY_ERROR_CODES.REGISTRATION_INVALID, HCODE.REGISTRATION_INVALID],
    [OWNER_RECOVERY_ERROR_CODES.CREDENTIAL_EXISTS, HCODE.CREDENTIAL_EXISTS], [OWNER_RECOVERY_ERROR_CODES.ACTIVATION_INVALID, HCODE.ACTIVATION_INVALID], [OWNER_RECOVERY_ERROR_CODES.ACTIVATION_REPLAYED, HCODE.ACTIVATION_REPLAYED],
    [OWNER_RECOVERY_ERROR_CODES.UNAVAILABLE, HCODE.RECOVERY_UNAVAILABLE]
  ]);
  if (mappings.has(code)) return new OwnerRecoveryHttpError(mappings.get(code), { cause: error });
  if (["stale_version", "version_conflict", "expected_version_mismatch"].includes(code)) return new OwnerRecoveryHttpError(HCODE.STALE_VERSION, { cause: error });
  if (["not_found", "request_not_found", "tenant_not_found"].includes(code)) return new OwnerRecoveryHttpError(HCODE.NOT_FOUND, { cause: error });
  if (["forbidden", "owner_required", "wrong_member", "wrong_organization"].includes(code)) return new OwnerRecoveryHttpError(HCODE.FORBIDDEN, { cause: error });
  return new OwnerRecoveryHttpError(HCODE.RECOVERY_UNAVAILABLE, { cause: error });
}

function mapError(error) {
  if (error instanceof HumanAuthAbuseControlError) return response(error.status, { error: { code: error.code, message: error.message } }, error.headers);
  if (error instanceof OwnerRecoveryHttpError) return response(error.status, { error: { code: error.code, message: MESSAGES[error.code] ?? MESSAGES[HCODE.INTERNAL_ERROR] } }, error.status === 405 ? { Allow: error.allow ?? "POST" } : undefined);
  if (error instanceof OwnerRecoveryError) return response(503, { error: { code: HCODE.RECOVERY_UNAVAILABLE, message: MESSAGES[HCODE.RECOVERY_UNAVAILABLE] } });
  return response(500, { error: { code: HCODE.INTERNAL_ERROR, message: MESSAGES[HCODE.INTERNAL_ERROR] } });
}

function resolveRoute(rawUrl, basePath) {
  let url;
  try { url = new URL(rawUrl, "https://agentpass.invalid"); } catch { return undefined; }
  const prefix = `${basePath}${ROOT}/`;
  if (url.pathname.startsWith(prefix)) {
    const parts = url.pathname.slice(prefix.length).split("/");
    if (parts.length === 2 && parts[1] === "recovery-requests") return { name: "create", operation: HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryCreate, method: "POST", allow: "POST", organizationId: decodeUuid(parts[0]), normal: true, query: "" };
    if (parts.length === 3 && parts[1] === "recovery-requests") return { name: "get", operation: HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryStatus, method: "GET", allow: "GET", organizationId: decodeUuid(parts[0]), requestId: decodeUuid(parts[2]), normal: true, query: "" };
    if (parts.length === 4 && parts[1] === "recovery-requests" && ["approve", "cancel"].includes(parts[3])) return { name: parts[3], operation: parts[3] === "approve" ? HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryApprove : HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryCancel, method: "POST", allow: "POST", organizationId: decodeUuid(parts[0]), requestId: decodeUuid(parts[2]), normal: true, query: "" };
  }
  const recovery = `${basePath}${RECOVERY_ROOT}`;
  const names = new Map([[`${recovery}/exchange`, "exchange"], [`${recovery}/webauthn/registration/options`, "registrationOptions"], [`${recovery}/webauthn/registration/verify`, "registrationVerify"], [`${recovery}/activate`, "activate"]]);
  if (names.has(url.pathname)) {
    const name = names.get(url.pathname);
    const operation = {
      exchange: HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryExchange,
      registrationOptions: HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryRegistrationOptions,
      registrationVerify: HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryRegistrationVerify,
      activate: HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryActivate
    }[name];
    return { name, operation, normal: false, query: "" };
  }
  return undefined;
}

function normalizeRequest(input) {
  if (!input || typeof input !== "object") throw invalidRequest();
  const method = String(input.method ?? "").toUpperCase();
  const url = String(input.url ?? input.originalUrl ?? input.path ?? "");
  if (!method || !url || url.length > MAX_URL_LENGTH) throw invalidRequest();
  return Object.freeze({ input, method, url, headers: normalizeHeaders(input.headers ?? {}), body: input.body, query: new URL(url, "https://agentpass.invalid").search || new URL(url, "https://agentpass.invalid").hash ? "?" : "" });
}

function normalizeHeaders(input) {
  const result = {};
  if (input && typeof input.get === "function") {
    for (const name of ["authorization", ...FORBIDDEN_IDENTITY_HEADERS]) if (input.get(name) !== null) throw invalidRequest();
    for (const name of ALLOWED_HEADERS) { const value = input.get(name); if (value !== null) setHeader(result, name, value); }
    return result;
  }
  if (!input || typeof input !== "object" || Array.isArray(input)) throw invalidRequest();
  for (const [name, value] of Object.entries(input)) {
    const normalized = name.toLowerCase();
    if (FORBIDDEN_IDENTITY_HEADERS.has(normalized)) throw invalidRequest();
    if (!ALLOWED_HEADERS.has(normalized)) throw invalidRequest();
    setHeader(result, normalized, value);
  }
  return result;
}

function setHeader(target, name, value) { if (Array.isArray(value) || value === undefined || typeof value === "object" || target[name.toLowerCase()] !== undefined) throw invalidRequest(); target[name.toLowerCase()] = String(value); }
function header(headers, name) { const value = headers[name.toLowerCase()]; if (value === undefined) return undefined; if (typeof value !== "string" || value.length > MAX_HEADER_BYTES || /[\u0000-\u001f\u007f]/u.test(value)) throw invalidRequest(); return value; }
function assertNormalOrigin(request, expectedOrigin) { if (header(request.headers, "origin") !== expectedOrigin) throw new OwnerRecoveryHttpError(HCODE.ORIGIN_NOT_ALLOWED); }
function assertRecoveryOrigin(request, expectedOrigin) { if (header(request.headers, "origin") !== expectedOrigin) throw new OwnerRecoveryHttpError(HCODE.ORIGIN_NOT_ALLOWED); }
function recoveryCookie(request) {
  const cookie = header(request.headers, "cookie");
  if (typeof cookie !== "string" || cookie.length > 8_192) throw new OwnerRecoveryHttpError(HCODE.RECOVERY_SESSION_REQUIRED);
  let found;
  for (const part of cookie.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 1) continue;
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (name !== "__Host-agentpass_recovery_session") continue;
    if (found !== undefined || !OPAQUE.test(value)) throw new OwnerRecoveryHttpError(HCODE.RECOVERY_SESSION_REQUIRED);
    found = value;
  }
  if (found === undefined) throw new OwnerRecoveryHttpError(HCODE.RECOVERY_SESSION_REQUIRED);
  return found;
}
function normalizeActor(value) { if (!plainObject(value) || !isUuid(value.session_id) || !isUuid(value.member_id) || !isUuid(value.organization_id) || typeof value.role !== "string") throw new OwnerRecoveryHttpError(HCODE.SESSION_REQUIRED); return Object.freeze({ session_id: value.session_id.toLowerCase(), member_id: value.member_id.toLowerCase(), organization_id: value.organization_id.toLowerCase(), role: value.role }); }
function parseCreateBody(body) { if (!plainObject(body)) throw invalidRequest(); assertExactKeys(body, body.threshold === undefined ? [] : ["threshold"]); if (body.threshold === undefined) return {}; if (!Number.isSafeInteger(body.threshold) || body.threshold < 2 || body.threshold > MAX_THRESHOLD) throw invalidRequest(); return { threshold: body.threshold }; }
function parseExchangeBody(body) { if (!plainObject(body)) throw invalidRequest(); assertExactKeys(body, ["exchange"]); if (!OPAQUE.test(body.exchange)) throw invalidRequest(); return { exchange: body.exchange }; }
function parseExpectedVersion(request, body) { if (!plainObject(body)) throw invalidRequest(); assertExactKeys(body, []); const value = header(request.headers, "if-match"); if (value === undefined) throw invalidRequest(); return parseIfMatch(value); }
function parseIfMatch(value) { const match = IF_MATCH.exec(value); if (!match || !Number.isSafeInteger(Number(match[1]))) throw invalidRequest(); return Number(match[1]); }
function requiredIdempotencyKey(request) { const value = header(request.headers, "idempotency-key"); if (typeof value !== "string" || !/^[A-Za-z0-9._~-]{8,255}$/u.test(value)) throw invalidRequest(); return value; }
function publicRecoverySession(value) { const output = { recovery_session_id: value.recovery_session_id, request_id: value.request_id, member_id: value.member_id, stage: value.stage, expires_at: value.expires_at, idle_expires_at: value.idle_expires_at }; if (!isUuid(output.recovery_session_id) || !isUuid(output.request_id) || !isUuid(output.member_id) || !new Set(["session_issued", "credential_enrolled", "activated", "revoked", "expired"]).has(output.stage) || !timestamp(output.expires_at) || !timestamp(output.idle_expires_at)) throw new OwnerRecoveryHttpError(HCODE.EXCHANGE_INVALID); return Object.freeze(output); }
function serializeRecoveryCookie(token) { if (!OPAQUE.test(token)) throw new OwnerRecoveryHttpError(HCODE.EXCHANGE_INVALID); return `__Host-agentpass_recovery_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict`; }
function timestamp(value) { return typeof value === "string" && Number.isFinite(Date.parse(value)); }
function requiredUuid(value) { if (!isUuid(value)) throw invalidRequest(); return value.toLowerCase(); }
function decodeUuid(value) { try { const decoded = decodeURIComponent(value); return requiredUuid(decoded); } catch { throw invalidRequest(); } }
function assertAllowedKeys(value, allowed) { for (const key of Object.keys(value)) if (!allowed.has(key)) throw invalidRequest(); }
function assertExactKeys(value, keys) { if (!plainObject(value) || Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key))) throw invalidRequest(); }
function hasBody(request) { return request.body !== undefined && request.body !== null && (!(typeof request.body === "string") || request.body.length > 0); }
function invalidRequest() { return new OwnerRecoveryHttpError(HCODE.INVALID_REQUEST); }
function methodNotAllowed(allow) { return new OwnerRecoveryHttpError(HCODE.METHOD_NOT_ALLOWED, { status: 405, allow }); }
function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function isUuid(value) { return typeof value === "string" && UUID.test(value); }
function assertOrigin(value) { if (typeof value !== "string" || value.length > 512) throw new TypeError("origin is invalid"); let parsed; try { parsed = new URL(value); } catch { throw new TypeError("origin is invalid"); } if (parsed.protocol !== "https:" || parsed.origin !== value || parsed.pathname !== "/" || parsed.username || parsed.password || parsed.search || parsed.hash) throw new TypeError("origin is invalid"); }
function normalizeBasePath(value) { if (value === "") return ""; if (typeof value !== "string" || !value.startsWith("/") || value.endsWith("/") || value.includes("?") || value.includes("#") || /[\u0000-\u001f\u007f]/u.test(value)) throw new TypeError("basePath is invalid"); return value; }

async function readOptionalJsonBody(request, maxBytes) { return hasBody(request) ? readJsonBody(request, maxBytes) : {}; }
async function readJsonBody(request, maxBytes) {
  const contentType = header(request.headers, "content-type");
  if (typeof contentType !== "string" || !/^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(contentType)) throw invalidRequest();
  const contentLength = header(request.headers, "content-length");
  if (contentLength !== undefined && (!/^\d+$/u.test(contentLength) || !Number.isSafeInteger(Number(contentLength)) || Number(contentLength) > maxBytes)) throw new OwnerRecoveryHttpError(HCODE.INVALID_REQUEST, { status: 413 });
  const input = request.input;
  let raw = input.body;
  if (typeof input.arrayBuffer === "function") raw = Buffer.from(await input.arrayBuffer());
  else if (typeof input.text === "function") raw = await input.text();
  else if (isReadable(input)) raw = await readStream(input, maxBytes);
  else if (isReadable(raw)) raw = await readStream(raw, maxBytes);
  if (plainObject(raw)) { assertSerializedSize(raw, maxBytes); return raw; }
  const bytes = Buffer.isBuffer(raw) ? raw : raw instanceof Uint8Array ? Buffer.from(raw) : Buffer.from(String(raw ?? ""), "utf8");
  if (bytes.length > maxBytes || contentLength !== undefined && Number(contentLength) !== bytes.length) throw new OwnerRecoveryHttpError(HCODE.INVALID_REQUEST, { status: 413 });
  try { return parseJsonNoDuplicateKeys(bytes.toString("utf8")); } catch (error) { throw new OwnerRecoveryHttpError(HCODE.INVALID_REQUEST, { cause: error }); }
}
function assertSerializedSize(value, maxBytes) { let serialized; try { serialized = JSON.stringify(value); } catch { throw invalidRequest(); } if (typeof serialized !== "string" || Buffer.byteLength(serialized, "utf8") > maxBytes) throw new OwnerRecoveryHttpError(HCODE.INVALID_REQUEST, { status: 413 }); }
function isReadable(value) { return Boolean(value && typeof value === "object" && (typeof value.on === "function" || typeof value[Symbol.asyncIterator] === "function")); }
async function readStream(stream, maxBytes) { const chunks = []; let total = 0; for await (const chunk of stream) { const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk); total += bytes.length; if (total > maxBytes) throw new OwnerRecoveryHttpError(HCODE.INVALID_REQUEST, { status: 413 }); chunks.push(bytes); } return Buffer.concat(chunks); }

class StrictJsonParser {
  constructor(text) { this.text = text; this.index = 0; this.depth = 0; }
  parse() { this.skipWhitespace(); const result = this.value(); this.skipWhitespace(); if (this.index !== this.text.length) throw new Error("trailing JSON data"); return result; }
  value() { if (++this.depth > 64) throw new Error("JSON nesting is too deep"); this.skipWhitespace(); const c = this.text[this.index]; let result; if (c === "{") result = this.object(); else if (c === "[") result = this.array(); else if (c === '"') result = this.string(); else if (c === "t" && this.literal("true")) result = true; else if (c === "f" && this.literal("false")) result = false; else if (c === "n" && this.literal("null")) result = null; else result = this.number(); this.depth -= 1; return result; }
  object() { this.index += 1; const output = Object.create(null); const keys = new Set(); this.skipWhitespace(); if (this.text[this.index] === "}") { this.index += 1; return output; } for (;;) { this.skipWhitespace(); if (this.text[this.index] !== '"') throw new Error("JSON object key is invalid"); const key = this.string(); if (keys.has(key)) throw new Error("duplicate JSON object key"); keys.add(key); this.skipWhitespace(); if (this.text[this.index] !== ":") throw new Error("JSON object separator is invalid"); this.index += 1; output[key] = this.value(); this.skipWhitespace(); if (this.text[this.index] === "}") { this.index += 1; return output; } if (this.text[this.index] !== ",") throw new Error("JSON object delimiter is invalid"); this.index += 1; } }
  array() { this.index += 1; const output = []; this.skipWhitespace(); if (this.text[this.index] === "]") { this.index += 1; return output; } for (;;) { output.push(this.value()); this.skipWhitespace(); if (this.text[this.index] === "]") { this.index += 1; return output; } if (this.text[this.index] !== ",") throw new Error("JSON array delimiter is invalid"); this.index += 1; } }
  string() { const start = this.index; this.index += 1; while (this.index < this.text.length) { const c = this.text[this.index]; if (c === "\\") this.index += 2; else if (c === '"') { this.index += 1; return JSON.parse(this.text.slice(start, this.index)); } else { if (c < " ") throw new Error("JSON string control character is invalid"); this.index += 1; } } throw new Error("unterminated JSON string"); }
  number() { const match = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y; match.lastIndex = this.index; const found = match.exec(this.text); if (!found) throw new Error("JSON value is invalid"); this.index += found[0].length; const value = Number(found[0]); if (!Number.isFinite(value)) throw new Error("JSON number is invalid"); return value; }
  literal(value) { if (this.text.startsWith(value, this.index)) { this.index += value.length; return true; } return false; }
  skipWhitespace() { while ([0x20, 0x09, 0x0a, 0x0d].includes(this.text.charCodeAt(this.index))) this.index += 1; }
}
function parseJsonNoDuplicateKeys(text) { return new StrictJsonParser(text).parse(); }
function response(status, body, extraHeaders = undefined) { const headers = { "Cache-Control": "no-store, max-age=0", Pragma: "no-cache", Expires: "0", "Content-Type": "application/json; charset=utf-8", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", ...(extraHeaders ?? {}) }; const json = JSON.stringify(body); return Object.freeze({ status, ok: status >= 200 && status < 300, headers: Object.freeze(headers), body: Object.freeze(body), text: async () => json, json: async () => body, toResponse: () => new Response(json, { status, headers }) }); }
function writeNodeResponse(target, result) { if (!target || typeof target.writeHead !== "function" || typeof target.end !== "function") throw new TypeError("node response is invalid"); target.writeHead(result.status, result.headers); target.end(JSON.stringify(result.body)); }
