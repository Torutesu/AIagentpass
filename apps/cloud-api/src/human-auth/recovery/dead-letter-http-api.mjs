import crypto from "node:crypto";

import { canonicalJson } from "../../../../../packages/protocol/src/index.mjs";
import {
  HUMAN_SESSION_CSRF_HEADER,
  HUMAN_SESSION_ERROR_CODES,
  isOpaqueToken,
  parseSessionCookie
} from "../../human-session.mjs";
import { HumanAuthAbuseControlError, HUMAN_AUTH_ABUSE_ERROR_CODES } from "../rate-limit.mjs";

const ROOT = "/api/auth/organizations";
const DEAD_LETTER_ROOT = "recovery-outbox/dead-letters";
const MAX_BODY_BYTES = 16 * 1024;
const MAX_HEADER_BYTES = 8 * 1024;
const MAX_URL_LENGTH = 8 * 1024;
const MAX_CURSOR_LENGTH = 512;
const MAX_REASON_BYTES = 128;
const MAX_IDEMPOTENCY_KEY_LENGTH = 255;
const DEFAULT_PAGE_SIZE = 25;
const MAX_PAGE_SIZE = 100;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const OPAQUE_CURSOR = /^[A-Za-z0-9_-]+$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:~-]{7,254}$/u;
const CONTROL = /[\u0000-\u001f\u007f]/u;
const EVENT_TYPE = /^[A-Za-z][A-Za-z0-9._:-]{0,127}$/u;
const ERROR_CODE = /^[a-z][a-z0-9_]{0,127}$/u;
const MANAGEMENT_ROLES = new Set(["owner", "admin"]);
const ALLOWED_HEADERS = new Set([
  "origin",
  "cookie",
  "accept",
  "cache-control",
  "pragma",
  "content-type",
  "content-length",
  "idempotency-key",
  "if-match",
  HUMAN_SESSION_CSRF_HEADER,
  "agentpass-recent-auth"
]);
const MUTATION_ONLY_HEADERS = new Set(["content-type", "content-length", "idempotency-key", "if-match", "agentpass-recent-auth"]);
const SESSION_FAILURES = new Set([
  HUMAN_SESSION_ERROR_CODES.INVALID_COOKIE,
  HUMAN_SESSION_ERROR_CODES.SESSION_NOT_FOUND,
  HUMAN_SESSION_ERROR_CODES.SESSION_REVOKED,
  HUMAN_SESSION_ERROR_CODES.SESSION_EXPIRED
]);
const CSRF_FAILURES = new Set([
  HUMAN_SESSION_ERROR_CODES.CSRF_REQUIRED,
  HUMAN_SESSION_ERROR_CODES.CSRF_INVALID
]);

export const OWNER_RECOVERY_DEAD_LETTER_HTTP_PATHS = Object.freeze({
  list: (organizationId) => `${ROOT}/${encodeURIComponent(organizationId)}/${DEAD_LETTER_ROOT}`,
  redrive: (organizationId, eventId) => `${ROOT}/${encodeURIComponent(organizationId)}/${DEAD_LETTER_ROOT}/${encodeURIComponent(eventId)}/redrive`,
  suppress: (organizationId, eventId) => `${ROOT}/${encodeURIComponent(organizationId)}/${DEAD_LETTER_ROOT}/${encodeURIComponent(eventId)}/suppress`
});

export const OWNER_RECOVERY_DEAD_LETTER_OPERATIONS = Object.freeze({
  list: "human.recovery.outbox.list",
  redrive: "human.recovery.outbox.redrive",
  suppress: "human.recovery.outbox.suppress"
});

export const OWNER_RECOVERY_DEAD_LETTER_RECENT_AUTH_OPERATIONS = Object.freeze({
  redrive: OWNER_RECOVERY_DEAD_LETTER_OPERATIONS.redrive,
  suppress: OWNER_RECOVERY_DEAD_LETTER_OPERATIONS.suppress
});

export const OWNER_RECOVERY_DEAD_LETTER_HTTP_ERROR_CODES = Object.freeze({
  INVALID_REQUEST: "recovery_outbox_invalid_request",
  INVALID_PAGINATION: "recovery_outbox_invalid_pagination",
  INVALID_CURSOR: "recovery_outbox_invalid_cursor",
  METHOD_NOT_ALLOWED: "recovery_outbox_method_not_allowed",
  ORIGIN_NOT_ALLOWED: "recovery_outbox_origin_not_allowed",
  SESSION_REQUIRED: "recovery_outbox_session_required",
  CSRF_FAILED: "recovery_outbox_csrf_failed",
  NOT_FOUND: "not_found",
  FORBIDDEN: "recovery_outbox_forbidden",
  VERSION_CONFLICT: "recovery_outbox_version_conflict",
  IDEMPOTENCY_CONFLICT: "idempotency_key_reused",
  MUTATION_IN_PROGRESS: "recovery_outbox_mutation_in_progress",
  RECENT_AUTH_REQUIRED: "recovery_outbox_recent_auth_required",
  RECENT_AUTH_FAILED: "recovery_outbox_recent_auth_failed",
  RECENT_AUTH_UNAVAILABLE: "recovery_outbox_recent_auth_unavailable",
  UNAVAILABLE: "recovery_outbox_unavailable",
  INTERNAL_ERROR: "recovery_outbox_internal_error"
});

const HCODE = OWNER_RECOVERY_DEAD_LETTER_HTTP_ERROR_CODES;
const MESSAGES = Object.freeze({
  [HCODE.INVALID_REQUEST]: "The recovery outbox request is invalid",
  [HCODE.INVALID_PAGINATION]: "The recovery outbox pagination is invalid",
  [HCODE.INVALID_CURSOR]: "The recovery outbox cursor is invalid",
  [HCODE.METHOD_NOT_ALLOWED]: "The HTTP method is not allowed",
  [HCODE.ORIGIN_NOT_ALLOWED]: "The request origin is not allowed",
  [HCODE.SESSION_REQUIRED]: "A valid human session is required",
  [HCODE.CSRF_FAILED]: "The CSRF token is invalid",
  [HCODE.NOT_FOUND]: "Resource not found",
  [HCODE.FORBIDDEN]: "The recovery outbox operation is not allowed",
  [HCODE.VERSION_CONFLICT]: "The recovery outbox item was changed by another request",
  [HCODE.IDEMPOTENCY_CONFLICT]: "The idempotency key was already used for another request",
  [HCODE.MUTATION_IN_PROGRESS]: "The recovery outbox operation is already in progress",
  [HCODE.RECENT_AUTH_REQUIRED]: "Recent WebAuthn authentication is required",
  [HCODE.RECENT_AUTH_FAILED]: "Recent WebAuthn authentication failed",
  [HCODE.RECENT_AUTH_UNAVAILABLE]: "Recent WebAuthn verification is unavailable",
  [HCODE.UNAVAILABLE]: "The recovery outbox service is unavailable",
  [HCODE.INTERNAL_ERROR]: "The request could not be completed"
});

const STATUS = Object.freeze({
  [HCODE.INVALID_REQUEST]: 400,
  [HCODE.INVALID_PAGINATION]: 400,
  [HCODE.INVALID_CURSOR]: 400,
  [HCODE.METHOD_NOT_ALLOWED]: 405,
  [HCODE.ORIGIN_NOT_ALLOWED]: 403,
  [HCODE.SESSION_REQUIRED]: 401,
  [HCODE.CSRF_FAILED]: 403,
  [HCODE.NOT_FOUND]: 404,
  [HCODE.FORBIDDEN]: 403,
  [HCODE.VERSION_CONFLICT]: 409,
  [HCODE.IDEMPOTENCY_CONFLICT]: 409,
  [HCODE.MUTATION_IN_PROGRESS]: 409,
  [HCODE.RECENT_AUTH_REQUIRED]: 401,
  [HCODE.RECENT_AUTH_FAILED]: 401,
  [HCODE.RECENT_AUTH_UNAVAILABLE]: 503,
  [HCODE.UNAVAILABLE]: 503,
  [HCODE.INTERNAL_ERROR]: 500
});

export class OwnerRecoveryDeadLetterHttpError extends Error {
  constructor(code, { status = STATUS[code] ?? 500, allow = undefined } = {}) {
    super(MESSAGES[code] ?? MESSAGES[HCODE.INTERNAL_ERROR]);
    this.name = "OwnerRecoveryDeadLetterHttpError";
    this.code = code;
    this.status = status;
    this.allow = allow;
  }
}

/**
 * Standalone Human API for operator management of owner-recovery dead letters.
 *
 * This module intentionally has no router, runtime, or database construction
 * side effects. The caller supplies an authenticated Human-session service,
 * recent-auth service, limiter, and management repository.
 */
export function createOwnerRecoveryDeadLetterHttpApi({
  humanSession,
  recentAuthService,
  repository,
  managementRepository,
  abuseControls,
  origin,
  basePath = "",
  maxBodyBytes = MAX_BODY_BYTES,
  now = () => Date.now()
} = {}) {
  if (!humanSession || typeof humanSession.authenticateRequest !== "function") throw new TypeError("humanSession must expose authenticateRequest()");
  if (!recentAuthService || typeof recentAuthService.authorize !== "function") throw new TypeError("recentAuthService must expose authorize()");
  const injectedRepository = repository ?? managementRepository;
  assertRepository(injectedRepository);
  const authorizeRateLimit = abuseControls?.authorize ?? abuseControls?.check;
  if (typeof authorizeRateLimit !== "function") throw new TypeError("abuseControls must expose authorize() or check()");
  assertOriginConfiguration(origin ?? humanSession.expectedOrigin);
  const expectedOrigin = origin ?? humanSession.expectedOrigin;
  const normalizedBasePath = normalizeBasePath(basePath);
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1_024 || maxBodyBytes > 1_024 * 1_024) throw new TypeError("maxBodyBytes is invalid");
  if (typeof now !== "function") throw new TypeError("now must be a function");

  async function handle(input, nodeResponse = undefined) {
    const result = await dispatch(input);
    if (nodeResponse !== undefined) writeNodeResponse(nodeResponse, result);
    return result;
  }

  async function dispatch(input) {
    try {
      const request = normalizeRequest(input);
      const route = resolveRoute(request.url, normalizedBasePath);
      if (!route) return response(404, errorBody(HCODE.NOT_FOUND));
      if (route.name !== "list" && route.url.search) throw invalidRequest();

      assertRequestOrigin(request, expectedOrigin);
      const actor = await authenticateSession(request);

      // This comparison deliberately occurs before any limiter call. A route
      // organization mismatch is indistinguishable from a missing resource.
      if (actor.organization_id !== route.organizationId) throw notFound();
      requireManagementRole(actor);

      if (request.method !== route.method) throw methodNotAllowed(route.allow);
      if (route.name === "list") {
        if (hasBody(request)) throw invalidRequest();
        const page = parseListQuery(route.url);
        assertRouteHeaders(request, route);
        await authorizeRateLimitRequest(authorizeRateLimit, { operation: route.operation, session: actor, organizationId: route.organizationId });
        const result = await callRepository(() => injectedRepository.listDeadLetters({ actor, ...page }));
        return response(200, {
          dead_letters: normalizeList(result, route.organizationId, page.limit),
          next_cursor: normalizeNextCursor(result)
        });
      }

      if (route.url.search !== "") throw invalidRequest();
      assertRouteHeaders(request, route);
      const body = await readJsonBody(request, maxBodyBytes);
      const expectedManagementVersion = requiredExpectedVersion(request);
      const idempotencyKey = requiredIdempotencyKey(request);
      if (route.name === "suppress") parseSuppressionBody(body);
      else assertExactKeys(body, []);
      await authorizeRateLimitRequest(authorizeRateLimit, { operation: route.operation, session: actor, organizationId: route.organizationId });
      const contextHash = ownerRecoveryDeadLetterContextHash({
        organization_id: route.organizationId,
        event_id: route.eventId,
        action: route.name,
        expected_management_version: expectedManagementVersion
      });
      const recentAuthorization = await authorizeRecentAuth({ request, actor, route, contextHash });
      const repositoryInput = {
        actor,
        event_id: route.eventId,
        expected_management_version: expectedManagementVersion,
        idempotency_key: idempotencyKey,
        recent_authorization: recentAuthorization,
        context_hash: contextHash
      };
      if (route.name === "suppress") repositoryInput.reason = body.reason;

      const result = await callRepository(() => injectedRepository[route.name === "redrive" ? "redriveDeadLetter" : "suppressDeadLetter"](repositoryInput));
      return response(200, { dead_letter: normalizeMutation(result, route.organizationId, route.eventId) });
    } catch (error) {
      return mapError(error);
    }
  }

  async function authenticateSession(request) {
    const cookie = header(request.headers, "cookie");
    try { parseSessionCookie(cookie); }
    catch (error) { throw new OwnerRecoveryDeadLetterHttpError(HCODE.SESSION_REQUIRED, { status: 401 }); }
    const csrfToken = header(request.headers, HUMAN_SESSION_CSRF_HEADER);
    if (!isOpaqueToken(csrfToken)) throw new OwnerRecoveryDeadLetterHttpError(HCODE.CSRF_FAILED, { status: 403 });
    try {
      // POST is intentional: this endpoint requires CSRF even for GET.
      const authenticated = await humanSession.authenticateRequest({
        method: "POST",
        headers: request.headers,
        origin: expectedOrigin,
        cookie,
        csrfToken
      });
      return normalizeSession(authenticated?.session);
    } catch (error) {
      if (error?.code === HUMAN_SESSION_ERROR_CODES.INVALID_ORIGIN) throw new OwnerRecoveryDeadLetterHttpError(HCODE.ORIGIN_NOT_ALLOWED, { status: 403 });
      if (CSRF_FAILURES.has(error?.code)) throw new OwnerRecoveryDeadLetterHttpError(HCODE.CSRF_FAILED, { status: 403 });
      if (SESSION_FAILURES.has(error?.code)) throw new OwnerRecoveryDeadLetterHttpError(HCODE.SESSION_REQUIRED, { status: 401 });
      throw new OwnerRecoveryDeadLetterHttpError(HCODE.SESSION_REQUIRED, { status: 401 });
    }
  }

  async function authorizeRecentAuth({ request, actor, route, contextHash }) {
    const proof = header(request.headers, "agentpass-recent-auth");
    if (typeof proof !== "string" || !UUID.test(proof)) throw new OwnerRecoveryDeadLetterHttpError(HCODE.RECENT_AUTH_REQUIRED, { status: 401 });
    let authenticatedAt;
    try {
      authenticatedAt = now();
      if (!Number.isSafeInteger(authenticatedAt) || authenticatedAt < 0) throw new Error("invalid clock");
    } catch (error) {
      throw new OwnerRecoveryDeadLetterHttpError(HCODE.RECENT_AUTH_UNAVAILABLE, { status: 503 });
    }

    let authorization;
    try {
      authorization = await recentAuthService.authorize({
        proof,
        principal: actor,
        organization_id: route.organizationId,
        operation: route.recentAuthOperation,
        context_hash: contextHash,
        now: authenticatedAt
      });
    } catch (error) {
      throw new OwnerRecoveryDeadLetterHttpError(HCODE.RECENT_AUTH_UNAVAILABLE, { status: 503 });
    }

    if (!validAuthorization(authorization, actor, route, proof, contextHash)) {
      throw new OwnerRecoveryDeadLetterHttpError(HCODE.RECENT_AUTH_FAILED, { status: 401 });
    }
    if (authorization.authenticated_at > authenticatedAt + 30_000 || authenticatedAt - authorization.authenticated_at > 5 * 60_000) {
      throw new OwnerRecoveryDeadLetterHttpError(HCODE.RECENT_AUTH_FAILED, { status: 401 });
    }
    return Object.freeze({
      session_id: actor.session_id,
      challenge_id: authorization.challenge_id.toLowerCase(),
      operation: authorization.operation,
      authenticated_at: authorization.authenticated_at
    });
  }

  return Object.freeze({
    handle,
    paths: OWNER_RECOVERY_DEAD_LETTER_HTTP_PATHS,
    expectedOrigin,
    basePath: normalizedBasePath
  });
}

export function ownerRecoveryDeadLetterContextHash({ organization_id, event_id, action, expected_management_version } = {}) {
  const organizationId = requiredUuid(organization_id);
  const eventId = requiredUuid(event_id);
  if (action !== "redrive" && action !== "suppress") throw new TypeError("action is invalid");
  if (!Number.isSafeInteger(expected_management_version) || expected_management_version < 1) throw new TypeError("expected_management_version is invalid");
  return crypto.createHash("sha256").update(canonicalJson({
    version: 1,
    organization_id: organizationId,
    event_id: eventId,
    action,
    expected_management_version
  }), "utf8").digest("hex");
}

function assertRepository(value) {
  if (!value || typeof value.listDeadLetters !== "function" || typeof value.redriveDeadLetter !== "function" || typeof value.suppressDeadLetter !== "function") throw new TypeError("management repository is incomplete");
}

function resolveRoute(rawUrl, basePath) {
  let url;
  try { url = new URL(rawUrl, "https://agentpass.invalid"); } catch { return undefined; }
  if (url.hash) return undefined;
  const prefix = `${basePath}${ROOT}/`;
  if (!url.pathname.startsWith(prefix)) return undefined;
  const parts = url.pathname.slice(prefix.length).split("/");
  if (parts.length !== 3 && parts.length !== 5) return undefined;
  const organizationId = decodeUuid(parts[0]);
  if (organizationId === undefined) return undefined;
  if (parts[1] !== "recovery-outbox" || parts[2] !== "dead-letters") return undefined;
  if (parts.length === 3) {
    return { name: "list", method: "GET", allow: "GET", operation: OWNER_RECOVERY_DEAD_LETTER_OPERATIONS.list, organizationId, url };
  }
  const eventId = decodeUuid(parts[3]);
  if (eventId === undefined) return undefined;
  if (parts[4] !== "redrive" && parts[4] !== "suppress") return undefined;
  return {
    name: parts[4],
    method: "POST",
    allow: "POST",
    operation: OWNER_RECOVERY_DEAD_LETTER_OPERATIONS[parts[4]],
    recentAuthOperation: OWNER_RECOVERY_DEAD_LETTER_RECENT_AUTH_OPERATIONS[parts[4]],
    organizationId,
    eventId,
    url
  };
}

function normalizeRequest(input) {
  if (!input || typeof input !== "object") throw invalidRequest();
  const method = String(input.method ?? "").toUpperCase();
  const rawUrl = String(input.url ?? input.originalUrl ?? input.path ?? "");
  if (!method || !rawUrl || rawUrl.length > MAX_URL_LENGTH) throw invalidRequest();
  try { new URL(rawUrl, "https://agentpass.invalid"); } catch { throw invalidRequest(); }
  return Object.freeze({ input, method, url: rawUrl, headers: normalizeHeaders(input.headers ?? {}), body: input.body });
}

function normalizeHeaders(input) {
  const result = Object.create(null);
  if (input && typeof input.get === "function" && typeof input.forEach === "function") {
    input.forEach((value, name) => {
      const normalized = String(name).toLowerCase();
      if (!ALLOWED_HEADERS.has(normalized)) throw invalidRequest();
      setHeader(result, normalized, value);
    });
    return result;
  }
  if (!input || typeof input !== "object" || Array.isArray(input)) throw invalidRequest();
  for (const [name, value] of Object.entries(input)) {
    const normalized = name.toLowerCase();
    if (!ALLOWED_HEADERS.has(normalized)) throw invalidRequest();
    setHeader(result, normalized, value);
  }
  return result;
}

function setHeader(target, name, value) {
  if (target[name] !== undefined || Array.isArray(value) || value === undefined || value === null || typeof value === "object") throw invalidRequest();
  target[name] = String(value);
}

function header(headers, name) {
  const value = headers[name.toLowerCase()];
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length > MAX_HEADER_BYTES || CONTROL.test(value)) throw invalidRequest();
  return value;
}

function assertRequestOrigin(request, expectedOrigin) {
  if (header(request.headers, "origin") !== expectedOrigin) throw new OwnerRecoveryDeadLetterHttpError(HCODE.ORIGIN_NOT_ALLOWED, { status: 403 });
}

function assertRouteHeaders(request, route) {
  for (const name of MUTATION_ONLY_HEADERS) {
    if (route.name === "list" && request.headers[name] !== undefined) throw invalidRequest();
  }
  if (route.name !== "list") {
    const contentType = header(request.headers, "content-type");
    if (contentType === undefined || !/^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(contentType)) throw invalidRequest();
  }
}

function parseListQuery(url) {
  const allowed = new Set(["limit", "cursor"]);
  for (const key of url.searchParams.keys()) if (!allowed.has(key)) throw new OwnerRecoveryDeadLetterHttpError(HCODE.INVALID_PAGINATION, { status: 400 });
  const limits = url.searchParams.getAll("limit");
  const cursors = url.searchParams.getAll("cursor");
  if (limits.length > 1 || cursors.length > 1) throw new OwnerRecoveryDeadLetterHttpError(HCODE.INVALID_PAGINATION, { status: 400 });
  const limit = limits.length === 0 ? DEFAULT_PAGE_SIZE : parsePageSize(limits[0]);
  const cursor = cursors.length === 0 ? undefined : parseCursor(cursors[0]);
  return Object.freeze({ limit, ...(cursor === undefined ? {} : { cursor }) });
}

function parsePageSize(value) {
  if (typeof value !== "string" || !/^(?:[1-9]|[1-9][0-9]|100)$/u.test(value)) throw new OwnerRecoveryDeadLetterHttpError(HCODE.INVALID_PAGINATION, { status: 400 });
  return Number(value);
}

function parseCursor(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > MAX_CURSOR_LENGTH || !OPAQUE_CURSOR.test(value)) throw new OwnerRecoveryDeadLetterHttpError(HCODE.INVALID_CURSOR, { status: 400 });
  return value;
}

function requiredExpectedVersion(request) {
  const value = header(request.headers, "if-match");
  const match = typeof value === "string" ? /^"([1-9][0-9]*)"$/u.exec(value) : null;
  if (!match) throw invalidRequest();
  const parsed = Number(match[1]);
  if (!Number.isSafeInteger(parsed)) throw invalidRequest();
  return parsed;
}

function requiredIdempotencyKey(request) {
  const value = header(request.headers, "idempotency-key");
  if (typeof value !== "string" || value.length > MAX_IDEMPOTENCY_KEY_LENGTH || !IDEMPOTENCY_KEY.test(value)) throw invalidRequest();
  return value;
}

function parseSuppressionBody(body) {
  assertExactKeys(body, ["reason"]);
  if (typeof body.reason !== "string" || body.reason.length < 1 || Buffer.byteLength(body.reason, "utf8") > MAX_REASON_BYTES || CONTROL.test(body.reason) || body.reason.trim() !== body.reason) throw invalidRequest();
  return body.reason;
}

function validAuthorization(value, actor, route, proof, contextHash) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Object.keys(value).sort();
  const required = ["authenticated_at", "challenge_id", "consumed", "member_id", "operation", "organization_id", "verified"];
  const withContext = [...required, "context_hash"].sort();
  if (keys.join(",") !== required.sort().join(",") && keys.join(",") !== withContext.join(",")) return false;
  return value.verified === true
    && value.consumed === true
    && value.member_id === actor.member_id
    && value.organization_id === route.organizationId
    && value.operation === route.recentAuthOperation
    && typeof value.challenge_id === "string"
    && UUID.test(value.challenge_id)
    && value.challenge_id.toLowerCase() === proof.toLowerCase()
    && Number.isSafeInteger(value.authenticated_at)
    && value.authenticated_at >= 0
    && value.context_hash === contextHash;
}

function normalizeList(result, organizationId, limit) {
  if (!result || typeof result !== "object" || Array.isArray(result) || !Array.isArray(result.items) || result.items.length > limit) throw unavailable();
  return Object.freeze(result.items.map((item) => normalizeDeadLetter(item, organizationId)));
}

function normalizeNextCursor(result) {
  if (!result || typeof result !== "object" || Array.isArray(result)) throw unavailable();
  if (result.next_cursor === undefined || result.next_cursor === null) return null;
  try { return parseCursor(result.next_cursor); } catch { throw unavailable(); }
}

function normalizeDeadLetter(value, organizationId) {
  if (!value || typeof value !== "object" || Array.isArray(value) || value.status !== "dead_letter") throw unavailable();
  const output = {
    organization_id: boundUuid(value.organization_id, organizationId),
    event_id: requiredUuid(value.event_id),
    request_id: requiredUuid(value.request_id),
    subject_member_id: requiredUuid(value.subject_member_id),
    event_type: safeEventType(value.event_type),
    status: "dead_letter",
    attempts: nonNegativeInteger(value.attempts),
    total_attempts: nonNegativeInteger(value.total_attempts),
    management_version: positiveInteger(value.management_version),
    redrive_count: nonNegativeInteger(value.redrive_count),
    last_error_code: safeErrorCode(value.last_error_code),
    created_at: timestamp(value.created_at),
    updated_at: timestamp(value.updated_at),
    suppressed_at: nullableTimestamp(value.suppressed_at),
    suppression_reason: nullableReason(value.suppression_reason)
  };
  return Object.freeze(output);
}

function normalizeMutation(value, organizationId, eventId) {
  if (!value || typeof value !== "object" || Array.isArray(value) || (value.status !== "pending" && value.status !== "suppressed")) throw unavailable();
  return Object.freeze({
    organization_id: boundUuid(value.organization_id, organizationId),
    event_id: boundUuid(value.event_id, eventId),
    status: value.status,
    attempts: nonNegativeInteger(value.attempts),
    total_attempts: nonNegativeInteger(value.total_attempts),
    management_version: positiveInteger(value.management_version),
    redrive_count: nonNegativeInteger(value.redrive_count),
    suppressed_at: nullableTimestamp(value.suppressed_at),
    suppression_reason: nullableReason(value.suppression_reason)
  });
}

async function callRepository(operation) {
  try { return await operation(); }
  catch (error) { throw mapRepositoryError(error); }
}

function mapRepositoryError(error) {
  const code = String(error?.code ?? error?.reason ?? error?.name ?? "").toLowerCase();
  if (["owner_recovery_outbox_management_invalid_input", "invalid_input"].includes(code)) return invalidRequest();
  if (["owner_recovery_outbox_management_forbidden", "forbidden", "owner_required"].includes(code)) return forbidden();
  if (["owner_recovery_outbox_management_invalid_cursor", "invalid_cursor"].includes(code)) return new OwnerRecoveryDeadLetterHttpError(HCODE.INVALID_CURSOR, { status: 400 });
  if (["owner_recovery_outbox_management_version_conflict", "version_conflict", "stale_version", "expected_version_mismatch"].includes(code)) return new OwnerRecoveryDeadLetterHttpError(HCODE.VERSION_CONFLICT, { status: 409 });
  if (["owner_recovery_outbox_management_idempotency_conflict", "idempotency_conflict", "idempotency_key_reused"].includes(code)) return new OwnerRecoveryDeadLetterHttpError(HCODE.IDEMPOTENCY_CONFLICT, { status: 409 });
  if (["owner_recovery_outbox_management_idempotency_in_progress", "idempotency_in_progress"].includes(code)) return new OwnerRecoveryDeadLetterHttpError(HCODE.MUTATION_IN_PROGRESS, { status: 409 });
  return unavailable();
}

function mapError(error) {
  if (error instanceof HumanAuthAbuseControlError) {
    if (error.code === HUMAN_AUTH_ABUSE_ERROR_CODES.RATE_LIMITED) return response(error.status, errorBody(error.code), error.headers);
    return response(503, errorBody(HCODE.UNAVAILABLE));
  }
  if (error instanceof OwnerRecoveryDeadLetterHttpError) {
    const headers = error.status === 405 ? { Allow: error.allow ?? "GET, POST" } : undefined;
    return response(error.status, errorBody(error.code), headers);
  }
  return response(500, errorBody(HCODE.INTERNAL_ERROR));
}

async function authorizeRateLimitRequest(authorizeRateLimit, input) {
  try { await authorizeRateLimit(input); }
  catch (error) {
    if (error instanceof HumanAuthAbuseControlError) throw error;
    throw unavailable();
  }
}

function errorBody(code) {
  return { error: { code, message: MESSAGES[code] ?? MESSAGES[HCODE.INTERNAL_ERROR] } };
}

function requireManagementRole(actor) {
  if (!MANAGEMENT_ROLES.has(actor.role)) throw forbidden();
}

function normalizeSession(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new OwnerRecoveryDeadLetterHttpError(HCODE.SESSION_REQUIRED, { status: 401 });
  const role = value.role;
  if (!MANAGEMENT_ROLES.has(role)) return Object.freeze({
    session_id: requiredUuid(value.session_id),
    member_id: requiredUuid(value.member_id),
    organization_id: requiredUuid(value.organization_id),
    role
  });
  return Object.freeze({
    session_id: requiredUuid(value.session_id),
    member_id: requiredUuid(value.member_id),
    organization_id: requiredUuid(value.organization_id),
    role
  });
}

function decodeUuid(value) {
  try {
    const decoded = decodeURIComponent(value);
    if (decoded.includes("/") || decoded.includes("\\")) throw new Error("invalid segment");
    return requiredUuid(decoded);
  } catch { return undefined; }
}

function requiredUuid(value) {
  if (typeof value !== "string" || !UUID.test(value)) throw unavailable();
  return value.toLowerCase();
}

function boundUuid(value, expected) {
  const normalized = requiredUuid(value);
  if (normalized !== expected) throw unavailable();
  return normalized;
}

function safeEventType(value) {
  if (typeof value !== "string" || !EVENT_TYPE.test(value)) throw unavailable();
  return value;
}

function safeErrorCode(value) {
  if (typeof value !== "string" || !ERROR_CODE.test(value)) throw unavailable();
  return value;
}

function timestamp(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw unavailable();
  return date.toISOString();
}

function nullableTimestamp(value) { return value === null || value === undefined ? null : timestamp(value); }

function nullableReason(value) {
  if (value === null || value === undefined) return null;
  if (typeof value !== "string" || value.length < 1 || Buffer.byteLength(value, "utf8") > MAX_REASON_BYTES || CONTROL.test(value)) throw unavailable();
  return value;
}

function positiveInteger(value) {
  const parsed = typeof value === "string" ? Number(value) : value;
  if (!Number.isSafeInteger(parsed) || parsed < 1) throw unavailable();
  return parsed;
}

function nonNegativeInteger(value) {
  const parsed = typeof value === "string" ? Number(value) : value;
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw unavailable();
  return parsed;
}

function assertExactKeys(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key))) throw invalidRequest();
}

function hasBody(request) {
  return request.body !== undefined && request.body !== null && (!(typeof request.body === "string") || request.body.length > 0);
}

async function readJsonBody(request, maxBytes) {
  const contentLength = header(request.headers, "content-length");
  if (contentLength !== undefined && (!/^\d+$/u.test(contentLength) || !Number.isSafeInteger(Number(contentLength)) || Number(contentLength) > maxBytes)) throw new OwnerRecoveryDeadLetterHttpError(HCODE.INVALID_REQUEST, { status: 413 });
  const input = request.input;
  let raw = input.body;
  if (typeof input.arrayBuffer === "function") raw = Buffer.from(await input.arrayBuffer());
  else if (typeof input.text === "function") raw = await input.text();
  else if (isReadable(raw)) raw = await readStream(raw, maxBytes);
  if (raw && typeof raw === "object" && !Buffer.isBuffer(raw) && !(raw instanceof Uint8Array) && !Array.isArray(raw)) {
    assertSerializedSize(raw, maxBytes, contentLength);
    return raw;
  }
  const bytes = Buffer.isBuffer(raw) ? raw : raw instanceof Uint8Array ? Buffer.from(raw) : Buffer.from(String(raw ?? ""), "utf8");
  if (bytes.length > maxBytes || contentLength !== undefined && Number(contentLength) !== bytes.length) throw new OwnerRecoveryDeadLetterHttpError(HCODE.INVALID_REQUEST, { status: 413 });
  try { return parseJsonNoDuplicateKeys(bytes.toString("utf8")); }
  catch { throw invalidRequest(); }
}

function assertSerializedSize(value, maxBytes, contentLength) {
  let serialized;
  try { serialized = JSON.stringify(value); } catch { throw invalidRequest(); }
  if (typeof serialized !== "string" || Buffer.byteLength(serialized, "utf8") > maxBytes || contentLength !== undefined && Number(contentLength) !== Buffer.byteLength(serialized, "utf8")) throw new OwnerRecoveryDeadLetterHttpError(HCODE.INVALID_REQUEST, { status: 413 });
}

function isReadable(value) { return Boolean(value && typeof value === "object" && (typeof value.on === "function" || typeof value[Symbol.asyncIterator] === "function")); }

async function readStream(stream, maxBytes) {
  const chunks = [];
  let total = 0;
  for await (const chunk of stream) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += bytes.length;
    if (total > maxBytes) throw new OwnerRecoveryDeadLetterHttpError(HCODE.INVALID_REQUEST, { status: 413 });
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

class StrictJsonParser {
  constructor(text) { this.text = text; this.index = 0; this.depth = 0; }
  parse() { this.skipWhitespace(); const value = this.value(); this.skipWhitespace(); if (this.index !== this.text.length) throw new Error("trailing JSON"); return value; }
  value() {
    if (++this.depth > 64) throw new Error("JSON nesting is too deep");
    this.skipWhitespace();
    const character = this.text[this.index];
    let result;
    if (character === "{") result = this.object();
    else if (character === "[") result = this.array();
    else if (character === '"') result = this.string();
    else if (character === "t" && this.literal("true")) result = true;
    else if (character === "f" && this.literal("false")) result = false;
    else if (character === "n" && this.literal("null")) result = null;
    else result = this.number();
    this.depth -= 1;
    return result;
  }
  object() {
    this.index += 1;
    const output = Object.create(null);
    const keys = new Set();
    this.skipWhitespace();
    if (this.text[this.index] === "}") { this.index += 1; return output; }
    for (;;) {
      this.skipWhitespace();
      if (this.text[this.index] !== '"') throw new Error("object key");
      const key = this.string();
      if (keys.has(key)) throw new Error("duplicate object key");
      keys.add(key);
      this.skipWhitespace();
      if (this.text[this.index] !== ":") throw new Error("object separator");
      this.index += 1;
      output[key] = this.value();
      this.skipWhitespace();
      if (this.text[this.index] === "}") { this.index += 1; return output; }
      if (this.text[this.index] !== ",") throw new Error("object delimiter");
      this.index += 1;
    }
  }
  array() {
    this.index += 1;
    const output = [];
    this.skipWhitespace();
    if (this.text[this.index] === "]") { this.index += 1; return output; }
    for (;;) {
      output.push(this.value());
      this.skipWhitespace();
      if (this.text[this.index] === "]") { this.index += 1; return output; }
      if (this.text[this.index] !== ",") throw new Error("array delimiter");
      this.index += 1;
    }
  }
  string() {
    const start = this.index;
    this.index += 1;
    while (this.index < this.text.length) {
      const character = this.text[this.index];
      if (character === "\\") this.index += 2;
      else if (character === '"') { this.index += 1; return JSON.parse(this.text.slice(start, this.index)); }
      else { if (character < " ") throw new Error("control character"); this.index += 1; }
    }
    throw new Error("unterminated string");
  }
  number() {
    const pattern = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
    pattern.lastIndex = this.index;
    const found = pattern.exec(this.text);
    if (!found) throw new Error("number");
    this.index += found[0].length;
    const value = Number(found[0]);
    if (!Number.isFinite(value)) throw new Error("number range");
    return value;
  }
  literal(value) { if (!this.text.startsWith(value, this.index)) return false; this.index += value.length; return true; }
  skipWhitespace() { while ([0x20, 0x09, 0x0a, 0x0d].includes(this.text.charCodeAt(this.index))) this.index += 1; }
}

function parseJsonNoDuplicateKeys(text) { return new StrictJsonParser(text).parse(); }

function invalidRequest() { return new OwnerRecoveryDeadLetterHttpError(HCODE.INVALID_REQUEST, { status: 400 }); }
function notFound() { return new OwnerRecoveryDeadLetterHttpError(HCODE.NOT_FOUND, { status: 404 }); }
function forbidden() { return new OwnerRecoveryDeadLetterHttpError(HCODE.FORBIDDEN, { status: 403 }); }
function unavailable() { return new OwnerRecoveryDeadLetterHttpError(HCODE.UNAVAILABLE, { status: 503 }); }
function methodNotAllowed(allow) { return new OwnerRecoveryDeadLetterHttpError(HCODE.METHOD_NOT_ALLOWED, { status: 405, allow }); }

function assertOriginConfiguration(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > MAX_URL_LENGTH || !/^https:\/\/[^/]+$/u.test(value)) throw new TypeError("origin is invalid");
  let parsed;
  try { parsed = new URL(value); } catch { throw new TypeError("origin is invalid"); }
  if (parsed.origin !== value || parsed.username || parsed.password || parsed.search || parsed.hash) throw new TypeError("origin is invalid");
}

function normalizeBasePath(value) {
  if (value === "") return "";
  if (typeof value !== "string" || !value.startsWith("/") || value.endsWith("/") || value.includes("?") || value.includes("#") || CONTROL.test(value)) throw new TypeError("basePath is invalid");
  return value;
}

function response(status, body, extraHeaders = undefined) {
  const headers = {
    "Cache-Control": "no-store, max-age=0",
    Pragma: "no-cache",
    Expires: "0",
    "Content-Type": "application/json; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    ...(extraHeaders ?? {})
  };
  const json = JSON.stringify(body);
  return Object.freeze({
    status,
    ok: status >= 200 && status < 300,
    headers: Object.freeze(headers),
    body: Object.freeze(body),
    text: async () => json,
    json: async () => body,
    toResponse: () => new Response(json, { status, headers })
  });
}

function writeNodeResponse(nodeResponse, result) {
  if (!nodeResponse || typeof nodeResponse.writeHead !== "function" || typeof nodeResponse.end !== "function") throw new TypeError("node response is invalid");
  nodeResponse.writeHead(result.status, result.headers);
  nodeResponse.end(JSON.stringify(result.body));
}
