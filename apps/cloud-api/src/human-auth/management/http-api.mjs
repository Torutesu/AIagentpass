import {
  HUMAN_SESSION_CSRF_HEADER,
  HUMAN_SESSION_ERROR_CODES,
  parseSessionCookie,
  serializeClearedSessionCookie
} from "../../human-session.mjs";

const CREDENTIALS_PATH = "/api/auth/management/credentials";
const SESSIONS_PATH = "/api/auth/management/sessions";
const DEFAULT_PAGE_SIZE = 25;
const MAX_PAGE_SIZE = 100;
const MAX_BODY_BYTES = 16 * 1024;
const MAX_HEADER_BYTES = 8 * 1024;
const MAX_URL_LENGTH = 8 * 1024;
const MAX_CURSOR_LENGTH = 512;
const MAX_LABEL_LENGTH = 128;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CREDENTIAL_ID = /^[A-Za-z0-9_-]+$/;
const OPAQUE_TOKEN = /^[A-Za-z0-9_-]{43}$/;
const RECENT_AUTH_HEADER = "agentpass-recent-auth";
const ROLES = new Set(["owner", "admin", "auditor", "viewer"]);
const TRANSPORTS = new Set(["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"]);
const METHODS = Object.freeze({
  listCredentials: "GET",
  renameCredential: "PATCH",
  revokeCredential: "POST",
  listSessions: "GET",
  revokeSession: "POST"
});

export const HUMAN_MANAGEMENT_HTTP_PATHS = Object.freeze({
  credentials: CREDENTIALS_PATH,
  credential: (credentialId) => `${CREDENTIALS_PATH}/${encodeURIComponent(credentialId)}`,
  credentialRevoke: (credentialId) => `${CREDENTIALS_PATH}/${encodeURIComponent(credentialId)}/revoke`,
  sessions: SESSIONS_PATH,
  session: (sessionId) => `${SESSIONS_PATH}/${encodeURIComponent(sessionId)}`,
  sessionRevoke: (sessionId) => `${SESSIONS_PATH}/${encodeURIComponent(sessionId)}/revoke`
});

export const HUMAN_MANAGEMENT_REPOSITORY_METHODS = Object.freeze([
  "listCredentials",
  "renameCredential",
  "revokeCredential",
  "listSessions",
  "revokeSession"
]);

export const HUMAN_MANAGEMENT_RECENT_AUTH_OPERATIONS = Object.freeze({
  revokeCredential: "human.management.credential.revoke",
  revokeCurrentSession: "human.management.session.revoke"
});

export const HUMAN_MANAGEMENT_HTTP_ERROR_CODES = Object.freeze({
  INVALID_REQUEST: "human_management_invalid_request",
  METHOD_NOT_ALLOWED: "human_management_method_not_allowed",
  ORIGIN_NOT_ALLOWED: "human_management_origin_not_allowed",
  SESSION_REQUIRED: "human_management_session_required",
  CSRF_FAILED: "human_management_csrf_failed",
  INVALID_PAGINATION: "human_management_invalid_pagination",
  CREDENTIAL_NOT_FOUND: "human_management_credential_not_found",
  SESSION_NOT_FOUND: "human_management_session_not_found",
  VERSION_CONFLICT: "human_management_version_conflict",
  LAST_ACTIVE_CREDENTIAL: "human_management_last_active_credential",
  RECENT_AUTH_REQUIRED: "human_management_recent_auth_required",
  RECENT_AUTH_FAILED: "human_management_recent_auth_failed",
  RECENT_AUTH_STALE: "human_management_recent_auth_stale",
  RECENT_AUTH_UNAVAILABLE: "human_management_recent_auth_unavailable",
  MANAGEMENT_UNAVAILABLE: "human_management_unavailable",
  INTERNAL_ERROR: "human_management_internal_error"
});

const ERROR_MESSAGES = Object.freeze({
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST]: "The management request is invalid",
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.METHOD_NOT_ALLOWED]: "The HTTP method is not allowed",
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED]: "The request origin is not allowed",
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.SESSION_REQUIRED]: "A valid human session is required",
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.CSRF_FAILED]: "The CSRF token is invalid",
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_PAGINATION]: "The pagination parameters are invalid",
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.CREDENTIAL_NOT_FOUND]: "The credential was not found",
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.SESSION_NOT_FOUND]: "The session was not found",
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.VERSION_CONFLICT]: "The resource was changed by another request",
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.LAST_ACTIVE_CREDENTIAL]: "The last active credential cannot be revoked",
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.RECENT_AUTH_REQUIRED]: "Recent WebAuthn authentication is required",
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.RECENT_AUTH_FAILED]: "Recent WebAuthn authentication failed",
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.RECENT_AUTH_STALE]: "Recent WebAuthn authentication is stale",
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.RECENT_AUTH_UNAVAILABLE]: "Recent WebAuthn verification is unavailable",
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.MANAGEMENT_UNAVAILABLE]: "The management service is unavailable",
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INTERNAL_ERROR]: "The request could not be completed"
});

const ERROR_STATUS = Object.freeze({
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST]: 400,
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.METHOD_NOT_ALLOWED]: 405,
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED]: 403,
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.SESSION_REQUIRED]: 401,
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.CSRF_FAILED]: 403,
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_PAGINATION]: 400,
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.CREDENTIAL_NOT_FOUND]: 404,
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.SESSION_NOT_FOUND]: 404,
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.VERSION_CONFLICT]: 409,
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.LAST_ACTIVE_CREDENTIAL]: 409,
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.RECENT_AUTH_REQUIRED]: 401,
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.RECENT_AUTH_FAILED]: 401,
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.RECENT_AUTH_STALE]: 401,
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.RECENT_AUTH_UNAVAILABLE]: 503,
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.MANAGEMENT_UNAVAILABLE]: 503,
  [HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INTERNAL_ERROR]: 500
});

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

export class HumanManagementHttpError extends Error {
  constructor(code, { status = ERROR_STATUS[code] ?? 500, cause = undefined } = {}) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INTERNAL_ERROR], { cause });
    this.name = "HumanManagementHttpError";
    this.code = code;
    this.status = status;
  }
}

/**
 * Framework-neutral management boundary.
 *
 * The repository is deliberately injected. Every repository call receives
 * the authenticated session's member and organization IDs; neither value is
 * accepted from the URL or request body. Repository records are treated as
 * untrusted internal data and are projected into allow-listed public shapes.
 * In particular, public keys and all bearer-token digests are never emitted.
 *
 * Repository contract:
 * - listCredentials(input) -> { items: CredentialRecord[], next_cursor?: string|null }
 * - renameCredential(input) -> CredentialRecord
 * - revokeCredential(input) -> CredentialRecord. The adapter must honor
 *   protect_last_active=true atomically while holding its member/org lock.
 * - listSessions(input) -> { items: SessionRecord[], next_cursor?: string|null }
 * - revokeSession(input) -> SessionRecord
 *
 * All mutation methods must enforce the supplied expected_version atomically.
 */
export function createHumanManagementHttpApi({
  humanSession,
  recentAuthService,
  repository,
  origin,
  basePath = "",
  maxBodyBytes = MAX_BODY_BYTES,
  now = () => Date.now()
} = {}) {
  if (!humanSession || typeof humanSession.authenticateRequest !== "function") {
    throw new TypeError("humanSession must expose authenticateRequest()");
  }
  if (recentAuthService !== undefined && typeof recentAuthService?.authorize !== "function") {
    throw new TypeError("recentAuthService must expose authorize()");
  }
  assertRepository(repository);
  const expectedOrigin = origin ?? humanSession.expectedOrigin;
  assertOriginConfiguration(expectedOrigin);
  const normalizedBasePath = normalizeBasePath(basePath);
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1_024 || maxBodyBytes > 1_024 * 1_024) {
    throw new TypeError("maxBodyBytes is invalid");
  }
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
      if (!route) return response(404, { error: { code: "not_found", message: "Resource not found" } });
      if (request.method !== METHODS[route.name]) {
        throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.METHOD_NOT_ALLOWED, { status: 405 });
      }
      if (route.name !== "listCredentials" && route.name !== "listSessions" && route.query.size !== 0) {
        throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
      }
      const session = await authenticateSession(request);
      if (route.name === "listCredentials") return await listCredentials(session, request);
      if (route.name === "listSessions") return await listSessions(session, request);
      const body = await readJsonBody(request, maxBodyBytes);
      if (route.name === "renameCredential") return await renameCredential(session, route.id, body);
      if (route.name === "revokeCredential") return await revokeCredential(session, route.id, body, request);
      return await revokeSession(session, route.id, body, request);
    } catch (error) {
      return mapError(error);
    }
  }

  async function authenticateSession(request) {
    const requestOrigin = header(request.headers, "origin");
    if (requestOrigin !== expectedOrigin || requestOrigin === "null") {
      throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED, { status: 403 });
    }

    const cookie = header(request.headers, "cookie");
    try {
      parseSessionCookie(cookie);
    } catch (error) {
      throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.SESSION_REQUIRED, { status: 401, cause: error });
    }

    const csrfToken = header(request.headers, HUMAN_SESSION_CSRF_HEADER);
    if (!isOpaqueToken(csrfToken)) {
      throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.CSRF_FAILED, { status: 403 });
    }

    try {
      // Use an unsafe method for every management request so that the
      // injected session service verifies the CSRF token even for GET lists.
      const authenticated = await humanSession.authenticateRequest({
        method: "POST",
        headers: request.headers,
        origin: requestOrigin,
        cookie,
        csrfToken
      });
      return normalizeAuthenticatedSession(authenticated?.session);
    } catch (error) {
      if (error?.code === HUMAN_SESSION_ERROR_CODES.INVALID_ORIGIN) {
        throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED, { status: 403, cause: error });
      }
      if (CSRF_FAILURES.has(error?.code)) {
        throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.CSRF_FAILED, { status: 403, cause: error });
      }
      if (SESSION_FAILURES.has(error?.code)) {
        throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.SESSION_REQUIRED, { status: 401, cause: error });
      }
      throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.MANAGEMENT_UNAVAILABLE, { status: 503, cause: error });
    }
  }

  async function listCredentials(session, request) {
    const page = parsePagination(request.url);
    try {
      const result = await repository.listCredentials(scope(session, page));
      return response(200, {
        credentials: normalizeCredentialPage(result, session, page.limit),
        next_cursor: normalizeNextCursor(result)
      });
    } catch (error) {
      throw mapRepositoryError(error, "credential");
    }
  }

  async function listSessions(session, request) {
    const page = parsePagination(request.url);
    try {
      const result = await repository.listSessions(scope(session, page));
      return response(200, {
        sessions: normalizeSessionPage(result, session, page.limit),
        next_cursor: normalizeNextCursor(result)
      });
    } catch (error) {
      throw mapRepositoryError(error, "session");
    }
  }

  async function renameCredential(session, rawId, body) {
    const credentialId = requiredRouteCredentialId(rawId);
    const input = parseBody(body, new Set(["label", "expected_version"]));
    const label = requiredLabel(input.label);
    const expectedVersion = requiredVersion(input.expected_version);
    try {
      const record = await repository.renameCredential({
        ...scope(session),
        credential_id: credentialId,
        label,
        expected_version: expectedVersion
      });
      if (!record) throw repositoryNotFound();
      return response(200, { credential: normalizeCredential(record, session) });
    } catch (error) {
      throw mapRepositoryError(error, "credential");
    }
  }

  async function revokeCredential(session, rawId, body, request) {
    const credentialId = requiredRouteCredentialId(rawId);
    const input = parseBody(body, new Set(["expected_version"]));
    const expectedVersion = requiredVersion(input.expected_version);
    await requireRecentAuth(session, request, HUMAN_MANAGEMENT_RECENT_AUTH_OPERATIONS.revokeCredential);
    try {
      const record = await repository.revokeCredential({
        ...scope(session),
        credential_id: credentialId,
        expected_version: expectedVersion,
        protect_last_active: true,
        reason: "human_management"
      });
      if (!record) throw repositoryNotFound();
      return response(200, { credential: normalizeCredential(record, session) });
    } catch (error) {
      throw mapRepositoryError(error, "credential");
    }
  }

  async function revokeSession(session, rawId, body, request) {
    const sessionId = requiredRouteUuid(rawId);
    const input = parseBody(body, new Set(["expected_version"]));
    const expectedVersion = requiredVersion(input.expected_version);
    if (session.session_id === sessionId) {
      await requireRecentAuth(session, request, HUMAN_MANAGEMENT_RECENT_AUTH_OPERATIONS.revokeCurrentSession);
    }
    try {
      const record = await repository.revokeSession({
        ...scope(session),
        target_session_id: sessionId,
        expected_version: expectedVersion,
        reason: "human_management"
      });
      if (!record) throw repositoryNotFound();
      const publicRecord = normalizeSession({ ...record, session_id: record.session_id ?? sessionId }, session);
      const extraHeaders = session.session_id === sessionId
        ? { "Set-Cookie": serializeClearedSessionCookie() }
        : undefined;
      return response(200, { session: publicRecord }, extraHeaders);
    } catch (error) {
      throw mapRepositoryError(error, "session");
    }
  }

  return Object.freeze({
    handle,
    paths: HUMAN_MANAGEMENT_HTTP_PATHS,
    expectedOrigin,
    basePath: normalizedBasePath
  });

  function scope(session, page = undefined) {
    return {
      session_id: session.session_id,
      member_id: session.member_id,
      organization_id: session.organization_id,
      ...(page ?? {})
    };
  }

  async function requireRecentAuth(session, request, operation) {
    if (!recentAuthService) {
      throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.RECENT_AUTH_UNAVAILABLE, { status: 503 });
    }
    const proof = header(request.headers, RECENT_AUTH_HEADER);
    if (typeof proof !== "string" || proof.length < 32 || proof.length > 4_096) {
      throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.RECENT_AUTH_REQUIRED, { status: 401 });
    }

    let authenticatedAt;
    try {
      authenticatedAt = now();
      if (!Number.isSafeInteger(authenticatedAt) || authenticatedAt < 0) throw new Error("recent-auth clock is invalid");
    } catch (error) {
      throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.RECENT_AUTH_UNAVAILABLE, { status: 503, cause: error });
    }

    let authorization;
    try {
      authorization = await recentAuthService.authorize({
        proof,
        principal: session,
        organization_id: session.organization_id,
        operation,
        now: authenticatedAt
      });
    } catch (error) {
      throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.RECENT_AUTH_UNAVAILABLE, { status: 503, cause: error });
    }

    const expectedKeys = ["authenticated_at", "challenge_id", "consumed", "member_id", "operation", "organization_id", "verified"];
    const exactShape = authorization && typeof authorization === "object" && !Array.isArray(authorization)
      && Object.keys(authorization).sort().join(",") === expectedKeys.sort().join(",")
      && authorization.verified === true
      && authorization.consumed === true
      && authorization.member_id === session.member_id
      && authorization.organization_id === session.organization_id
      && authorization.operation === operation
      && typeof authorization.challenge_id === "string"
      && UUID.test(authorization.challenge_id)
      && authorization.challenge_id.toLowerCase() === proof.toLowerCase()
      && Number.isSafeInteger(authorization.authenticated_at)
      && authorization.authenticated_at >= 0;
    if (!exactShape) {
      throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.RECENT_AUTH_FAILED, { status: 401 });
    }
    if (authorization.authenticated_at > authenticatedAt + 30_000 || authenticatedAt - authorization.authenticated_at > 5 * 60_000) {
      throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.RECENT_AUTH_STALE, { status: 401 });
    }
  }
}

function assertRepository(repository) {
  if (!repository || typeof repository !== "object") throw new TypeError("management repository is invalid");
  for (const method of HUMAN_MANAGEMENT_REPOSITORY_METHODS) {
    if (typeof repository[method] !== "function") throw new TypeError(`management repository is missing ${method}()`);
  }
}

function assertOriginConfiguration(origin) {
  if (typeof origin !== "string" || origin.length < 1 || origin.length > MAX_URL_LENGTH || origin.endsWith("/") || !/^https:\/\/[^/]+$/u.test(origin)) {
    throw new TypeError("origin is invalid");
  }
}

function normalizeBasePath(value) {
  if (value === "") return "";
  if (typeof value !== "string" || !value.startsWith("/") || value.endsWith("/") || value.includes("?")) throw new TypeError("basePath is invalid");
  return value;
}

function normalizeAuthenticatedSession(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("authenticated session is invalid");
  const sessionId = requiredUuid(value.session_id, "session_id");
  const memberId = requiredUuid(value.member_id, "member_id");
  const organizationId = requiredUuid(value.organization_id, "organization_id");
  if (!ROLES.has(value.role)) throw new Error("authenticated session role is invalid");
  return Object.freeze({ session_id: sessionId, member_id: memberId, organization_id: organizationId, role: value.role });
}

function resolveRoute(rawUrl, basePath) {
  let url;
  try { url = new URL(rawUrl, "https://agentpass.invalid"); } catch { return undefined; }
  if (url.hash) return undefined;
  const prefix = basePath;
  const path = url.pathname;
  if (path === `${prefix}${CREDENTIALS_PATH}`) return { name: "listCredentials", query: url.searchParams };
  if (path === `${prefix}${SESSIONS_PATH}`) return { name: "listSessions", query: url.searchParams };
  const credentialPrefix = `${prefix}${CREDENTIALS_PATH}/`;
  if (path.startsWith(credentialPrefix)) {
    const id = path.slice(credentialPrefix.length);
    if (id.endsWith("/revoke")) return { name: "revokeCredential", id: id.slice(0, -"/revoke".length), query: url.searchParams };
    return { name: "renameCredential", id, query: url.searchParams };
  }
  const sessionPrefix = `${prefix}${SESSIONS_PATH}/`;
  if (path.startsWith(sessionPrefix)) {
    const id = path.slice(sessionPrefix.length);
    if (id.endsWith("/revoke")) return { name: "revokeSession", id: id.slice(0, -"/revoke".length), query: url.searchParams };
  }
  return undefined;
}

function parsePagination(rawUrl) {
  const url = new URL(rawUrl, "https://agentpass.invalid");
  const allowed = new Set(["limit", "cursor"]);
  for (const key of url.searchParams.keys()) if (!allowed.has(key)) throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_PAGINATION, { status: 400 });
  const limits = url.searchParams.getAll("limit");
  const cursors = url.searchParams.getAll("cursor");
  if (limits.length > 1 || cursors.length > 1) throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_PAGINATION, { status: 400 });
  const rawLimit = limits[0];
  const limit = rawLimit === undefined ? DEFAULT_PAGE_SIZE : parsePageSize(rawLimit);
  const cursor = cursors[0] === undefined ? undefined : parseCursor(cursors[0]);
  return Object.freeze({ limit, ...(cursor === undefined ? {} : { cursor }) });
}

function parsePageSize(value) {
  if (typeof value !== "string" || !/^(?:[1-9]|[1-9][0-9]|100)$/u.test(value)) throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_PAGINATION, { status: 400 });
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > MAX_PAGE_SIZE) throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_PAGINATION, { status: 400 });
  return parsed;
}

function parseCursor(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > MAX_CURSOR_LENGTH || !CREDENTIAL_ID.test(value) || value.includes("=")) throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_PAGINATION, { status: 400 });
  return value;
}

function normalizeCredentialPage(result, session, limit) {
  const items = pageItems(result);
  if (items.length > limit) throw new Error("credential repository exceeded page bound");
  return items.map((item) => normalizeCredential(item, session));
}

function normalizeSessionPage(result, session, limit) {
  const items = pageItems(result);
  if (items.length > limit) throw new Error("session repository exceeded page bound");
  return items.map((item) => normalizeSession(item, session));
}

function pageItems(result) {
  if (!result || typeof result !== "object" || Array.isArray(result) || !Array.isArray(result.items)) throw new Error("repository page is invalid");
  return result.items;
}

function normalizeNextCursor(result) {
  if (!result || typeof result !== "object" || Array.isArray(result)) throw new Error("repository page is invalid");
  if (result.next_cursor === undefined || result.next_cursor === null) return null;
  return parseCursor(result.next_cursor);
}

function normalizeCredential(value, session) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("credential record is invalid");
  const memberId = value.member_id === undefined ? session.member_id : requiredUuid(value.member_id, "member_id");
  const organizationId = value.organization_id === undefined ? session.organization_id : requiredUuid(value.organization_id, "organization_id");
  if (memberId !== session.member_id || organizationId !== session.organization_id) throw new Error("credential binding is invalid");
  const credentialId = requiredCredentialId(value.credential_id ?? value.id);
  const version = outputVersion(value.version);
  const label = outputLabel(value.label);
  const status = value.status ?? (value.revoked_at ? "revoked" : "active");
  if (status !== "active" && status !== "revoked") throw new Error("credential status is invalid");
  const transports = normalizeTransports(value.transports);
  const output = {
    credential_id: credentialId,
    version,
    label,
    transports,
    backup_eligible: strictBoolean(value.backup_eligible, "backup_eligible"),
    backup_state: strictBoolean(value.backup_state, "backup_state"),
    status,
    created_at: requiredDate(value.created_at, "created_at"),
    last_used_at: nullableDate(value.last_used_at, "last_used_at"),
    revoked_at: nullableDate(value.revoked_at, "revoked_at")
  };
  if (output.backup_state && !output.backup_eligible) throw new Error("credential backup state is invalid");
  return output;
}

function normalizeSession(value, current) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("session record is invalid");
  const sessionId = requiredUuid(value.session_id ?? value.id, "session_id");
  const memberId = value.member_id === undefined ? current.member_id : requiredUuid(value.member_id, "member_id");
  const organizationId = value.organization_id === undefined ? current.organization_id : requiredUuid(value.organization_id, "organization_id");
  if (memberId !== current.member_id || organizationId !== current.organization_id) throw new Error("session binding is invalid");
  const role = value.role ?? current.role;
  if (!ROLES.has(role)) throw new Error("session role is invalid");
  const version = outputVersion(value.version);
  const status = value.status ?? (value.revoked_at ? "revoked" : "active");
  if (!["active", "revoked", "expired"].includes(status)) throw new Error("session status is invalid");
  return {
    session_id: sessionId,
    version,
    member_id: memberId,
    organization_id: organizationId,
    role,
    status,
    is_current: sessionId === current.session_id,
    created_at: requiredDate(value.created_at, "created_at"),
    expires_at: requiredDate(value.expires_at, "expires_at"),
    last_seen_at: nullableDate(value.last_seen_at, "last_seen_at"),
    recent_auth_at: nullableDate(value.recent_auth_at, "recent_auth_at"),
    revoked_at: nullableDate(value.revoked_at, "revoked_at")
  };
}

function parseBody(body, keys) {
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  for (const key of Object.keys(body)) if (!keys.has(key)) throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  return body;
}

function requiredLabel(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > MAX_LABEL_LENGTH || value.trim() !== value || /[\u0000-\u001f\u007f]/u.test(value)) throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  return value;
}

function requiredVersion(value) {
  if (!Number.isSafeInteger(value) || value < 1) throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  return value;
}

function outputVersion(value) {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error("resource version is invalid");
  return value;
}

function outputLabel(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > MAX_LABEL_LENGTH || value.trim() !== value || /[\u0000-\u001f\u007f]/u.test(value)) throw new Error("credential label is invalid");
  return value;
}

function requiredUuid(value, field = "id") {
  if (typeof value !== "string" || !UUID.test(value)) throw new Error(`${field} is invalid`);
  return value.toLowerCase();
}

function requiredRouteUuid(value) {
  try {
    return requiredUuid(decodePathSegment(value), "session_id");
  } catch (error) {
    throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400, cause: error });
  }
}

function requiredCredentialId(value) {
  if (typeof value !== "string" || value.length < 16 || value.length > 1_024 || !CREDENTIAL_ID.test(value) || value.includes("=")) throw new Error("credential id is invalid");
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length < 16 || bytes.length > 1_024 || bytes.toString("base64url") !== value) throw new Error("credential id is invalid");
  return value;
}

function requiredRouteCredentialId(value) {
  try {
    return requiredCredentialId(decodePathSegment(value));
  } catch (error) {
    throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400, cause: error });
  }
}

function decodePathSegment(value) {
  if (typeof value !== "string" || value.length < 1 || value.includes("/")) throw new Error("path segment is invalid");
  const decoded = decodeURIComponent(value);
  if (!decoded || decoded.includes("/") || decoded.includes("\\")) throw new Error("path segment is invalid");
  return decoded;
}

function normalizeTransports(value) {
  if (!Array.isArray(value) || value.length > 7 || new Set(value).size !== value.length || value.some((item) => typeof item !== "string" || !TRANSPORTS.has(item))) throw new Error("credential transports are invalid");
  return [...value];
}

function strictBoolean(value, field) {
  if (typeof value !== "boolean") throw new Error(`${field} is invalid`);
  return value;
}

function requiredDate(value, field) {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) throw new Error(`${field} is invalid`);
  return value;
}

function nullableDate(value, field) {
  if (value === undefined || value === null) return null;
  return requiredDate(value, field);
}

function isOpaqueToken(value) {
  return typeof value === "string" && OPAQUE_TOKEN.test(value);
}

function mapRepositoryError(error, resource) {
  if (error instanceof HumanManagementHttpError) return error;
  const code = String(error?.code ?? error?.name ?? "").toLowerCase();
  if (["human_cursor_invalid", "invalid_cursor", "cursor_invalid"].includes(code)) {
    return new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_PAGINATION, { status: 400, cause: error });
  }
  if (["not_found", "credential_not_found", "session_not_found", "resource_not_found"].includes(code)) {
    return new HumanManagementHttpError(resource === "credential" ? HUMAN_MANAGEMENT_HTTP_ERROR_CODES.CREDENTIAL_NOT_FOUND : HUMAN_MANAGEMENT_HTTP_ERROR_CODES.SESSION_NOT_FOUND, { status: 404, cause: error });
  }
  if (["version_conflict", "err_version_conflict", "expected_version_mismatch", "stale_version"].includes(code)) {
    return new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.VERSION_CONFLICT, { status: 409, cause: error });
  }
  if (["last_active_credential", "sole_active_credential", "last_credential", "err_last_active_credential", "err_sole_active_credential"].includes(code)) {
    return new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.LAST_ACTIVE_CREDENTIAL, { status: 409, cause: error });
  }
  if (["invalid_input", "invalid_scope", "tenant_scope_error"].includes(code)) {
    return new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400, cause: error });
  }
  return new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.MANAGEMENT_UNAVAILABLE, { status: 503, cause: error });
}

function repositoryNotFound() {
  const error = new Error("management resource not found");
  error.code = "not_found";
  return error;
}

function mapError(error) {
  if (error instanceof HumanManagementHttpError) {
    return response(error.status, { error: { code: error.code, message: ERROR_MESSAGES[error.code] ?? ERROR_MESSAGES[HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INTERNAL_ERROR] } }, error.status === 405 ? { Allow: "GET, PATCH, POST" } : undefined);
  }
  return response(500, { error: { code: HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INTERNAL_ERROR, message: ERROR_MESSAGES[HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INTERNAL_ERROR] } });
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

function normalizeRequest(input) {
  if (!input || typeof input !== "object") throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  const method = String(input.method ?? "").toUpperCase();
  const url = String(input.url ?? input.originalUrl ?? input.path ?? "");
  if (!method || !url || url.length > MAX_URL_LENGTH) throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  return Object.freeze({ input, method, url, headers: normalizeHeaders(input.headers ?? {}), body: input.body });
}

function normalizeHeaders(input) {
  const result = {};
  const names = ["origin", "cookie", "content-type", "content-length", HUMAN_SESSION_CSRF_HEADER, RECENT_AUTH_HEADER];
  if (input && typeof input.get === "function") {
    for (const name of names) {
      const value = input.get(name);
      if (value !== null) setHeader(result, name, value);
    }
    return result;
  }
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  for (const [name, value] of Object.entries(input)) {
    if (names.includes(name.toLowerCase())) setHeader(result, name, value);
  }
  return result;
}

function setHeader(target, name, value) {
  if (typeof name !== "string" || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u.test(name) || Array.isArray(value) || typeof value === "object" || value === undefined) throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  const normalized = name.toLowerCase();
  if (target[normalized] !== undefined) throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  target[normalized] = String(value);
}

function header(headers, name) {
  const value = headers[name.toLowerCase()];
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length > MAX_HEADER_BYTES || /[\u0000-\u001f\u007f]/u.test(value)) throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  return value;
}

async function readJsonBody(request, maxBytes) {
  const contentType = header(request.headers, "content-type");
  if (typeof contentType !== "string" || !/^application\/json(?:\s*;|$)/iu.test(contentType)) throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  const contentLength = header(request.headers, "content-length");
  if (contentLength !== undefined && (!/^\d+$/u.test(contentLength) || !Number.isSafeInteger(Number(contentLength)) || Number(contentLength) > maxBytes)) throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
  const input = request.input;
  let raw = input.body;
  if (raw === undefined || isReadable(raw)) {
    if (typeof input.arrayBuffer === "function") raw = Buffer.from(await input.arrayBuffer());
    else if (typeof input.text === "function") raw = await input.text();
    else if (isReadable(input)) raw = await readStream(input, maxBytes);
    else if (isReadable(input.body)) raw = await readStream(input.body, maxBytes);
  }
  if (raw && typeof raw === "object" && !Buffer.isBuffer(raw) && !(raw instanceof Uint8Array) && !Array.isArray(raw)) {
    assertSerializedSize(raw, maxBytes);
    return raw;
  }
  const bytes = Buffer.isBuffer(raw) ? raw : raw instanceof Uint8Array ? Buffer.from(raw) : Buffer.from(String(raw ?? ""), "utf8");
  if (bytes.length > maxBytes) throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400, cause: error });
  }
}

function assertSerializedSize(value, maxBytes) {
  let serialized;
  try { serialized = JSON.stringify(value); } catch (error) { throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400, cause: error }); }
  if (typeof serialized !== "string" || Buffer.byteLength(serialized, "utf8") > maxBytes) throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
}

function isReadable(value) {
  return Boolean(value && typeof value === "object" && (typeof value.getReader === "function" || typeof value[Symbol.asyncIterator] === "function"));
}

async function readStream(stream, maxBytes) {
  if (typeof stream.getReader === "function") {
    const reader = stream.getReader();
    const chunks = [];
    let total = 0;
    try {
      for (;;) {
        const next = await reader.read();
        if (next.done) break;
        const bytes = next.value instanceof Uint8Array ? Buffer.from(next.value) : Buffer.from(String(next.value), "utf8");
        total += bytes.length;
        if (total > maxBytes) throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
        chunks.push(bytes);
      }
    } finally {
      reader.releaseLock?.();
    }
    return Buffer.concat(chunks);
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of stream) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += bytes.length;
    if (total > maxBytes) throw new HumanManagementHttpError(HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

function writeNodeResponse(nodeResponse, result) {
  if (!nodeResponse || typeof nodeResponse.writeHead !== "function" || typeof nodeResponse.end !== "function") throw new TypeError("node response is invalid");
  nodeResponse.writeHead(result.status, result.headers);
  nodeResponse.end(JSON.stringify(result.body));
}
