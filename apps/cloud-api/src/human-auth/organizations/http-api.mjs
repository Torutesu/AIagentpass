import {
  HUMAN_SESSION_CSRF_HEADER,
  HUMAN_SESSION_ERROR_CODES,
  isOpaqueToken,
  parseSessionCookie
} from "../../human-session.mjs";
import { HumanAuthAbuseControlError, HUMAN_AUTH_RATE_LIMIT_OPERATIONS } from "../rate-limit.mjs";

const ORGANIZATIONS_PATH = "/api/auth/organizations";
const ACCEPT_INVITATION_PATH = "/api/auth/invitations/accept";
const DEFAULT_PAGE_SIZE = 50;
const MAX_PAGE_SIZE = 100;
const MAX_BODY_BYTES = 16 * 1024;
const MAX_HEADER_BYTES = 8 * 1024;
const MAX_URL_LENGTH = 8 * 1024;
const MAX_CURSOR_LENGTH = 512;
const MAX_IDEMPOTENCY_KEY_LENGTH = 255;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._~-]{8,255}$/u;
const MAX_NAME_LENGTH = 128;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const PATH_SEGMENT = /^[A-Za-z0-9._~-]+$/u;
const CURSOR = /^[A-Za-z0-9_-]+$/u;
const ROLES = new Set(["owner", "admin", "auditor", "viewer"]);
const INVITABLE_ROLES = new Set(["admin", "auditor", "viewer"]);
const AUDITOR_OR_ABOVE = new Set(["owner", "admin", "auditor"]);
const ADMIN_OR_OWNER = new Set(["owner", "admin"]);
const RECENT_AUTH_HEADER = "agentpass-recent-auth";
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

export const HUMAN_ORGANIZATIONS_HTTP_PATHS = Object.freeze({
  organizations: ORGANIZATIONS_PATH,
  organization: (organizationId) => `${ORGANIZATIONS_PATH}/${encodeURIComponent(organizationId)}`,
  members: (organizationId) => `${ORGANIZATIONS_PATH}/${encodeURIComponent(organizationId)}/members`,
  memberRole: (organizationId, memberId) => `${ORGANIZATIONS_PATH}/${encodeURIComponent(organizationId)}/members/${encodeURIComponent(memberId)}/role`,
  memberRemove: (organizationId, memberId) => `${ORGANIZATIONS_PATH}/${encodeURIComponent(organizationId)}/members/${encodeURIComponent(memberId)}/remove`,
  invitations: (organizationId) => `${ORGANIZATIONS_PATH}/${encodeURIComponent(organizationId)}/invitations`,
  invitationRevoke: (organizationId, invitationId) => `${ORGANIZATIONS_PATH}/${encodeURIComponent(organizationId)}/invitations/${encodeURIComponent(invitationId)}/revoke`,
  acceptInvitation: ACCEPT_INVITATION_PATH
});

export const HUMAN_ORGANIZATION_SERVICE_METHODS = Object.freeze([
  "listOrganizations",
  "createOrganization",
  "renameOrganization",
  "listMembers",
  "updateMemberRole",
  "removeMember",
  "listInvitations",
  "createInvitation",
  "revokeInvitation",
  "acceptInvitation"
]);

export const HUMAN_ORGANIZATIONS_RECENT_AUTH_OPERATIONS = Object.freeze({
  updateMemberRole: "human.organizations.member.role.update",
  removeMember: "human.organizations.member.remove"
});

export const HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES = Object.freeze({
  INVALID_REQUEST: "human_organizations_invalid_request",
  METHOD_NOT_ALLOWED: "human_organizations_method_not_allowed",
  ORIGIN_NOT_ALLOWED: "human_organizations_origin_not_allowed",
  SESSION_REQUIRED: "human_organizations_session_required",
  CSRF_FAILED: "human_organizations_csrf_failed",
  FORBIDDEN: "human_organizations_forbidden",
  ROLE_NOT_ALLOWED: "human_organizations_role_not_allowed",
  LAST_OWNER_PROTECTED: "human_organizations_last_owner_protected",
  ORGANIZATION_NOT_FOUND: "human_organizations_organization_not_found",
  MEMBER_NOT_FOUND: "human_organizations_member_not_found",
  INVITATION_NOT_FOUND: "human_organizations_invitation_not_found",
  VERSION_CONFLICT: "human_organizations_version_conflict",
  IDEMPOTENCY_REQUIRED: "human_organizations_idempotency_required",
  IDEMPOTENCY_CONFLICT: "human_organizations_idempotency_conflict",
  INVITATION_REPLAYED: "human_organizations_invitation_replayed",
  RECENT_AUTH_REQUIRED: "human_organizations_recent_auth_required",
  RECENT_AUTH_FAILED: "human_organizations_recent_auth_failed",
  RECENT_AUTH_STALE: "human_organizations_recent_auth_stale",
  RECENT_AUTH_UNAVAILABLE: "human_organizations_recent_auth_unavailable",
  ORGANIZATIONS_UNAVAILABLE: "human_organizations_unavailable",
  INTERNAL_ERROR: "human_organizations_internal_error"
});

const ERROR_MESSAGES = Object.freeze({
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INVALID_REQUEST]: "The organization request is invalid",
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.METHOD_NOT_ALLOWED]: "The HTTP method is not allowed",
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED]: "The request origin is not allowed",
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.SESSION_REQUIRED]: "A valid human session is required",
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.CSRF_FAILED]: "The CSRF token is invalid",
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.FORBIDDEN]: "The operation is not allowed",
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.ROLE_NOT_ALLOWED]: "The requested role transition is not allowed",
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.LAST_OWNER_PROTECTED]: "The organization must retain an active owner",
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.ORGANIZATION_NOT_FOUND]: "The organization was not found",
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.MEMBER_NOT_FOUND]: "The member was not found",
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INVITATION_NOT_FOUND]: "The invitation was not found",
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.VERSION_CONFLICT]: "The resource was changed by another request",
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.IDEMPOTENCY_REQUIRED]: "An Idempotency-Key is required",
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.IDEMPOTENCY_CONFLICT]: "The idempotency key conflicts with another request",
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INVITATION_REPLAYED]: "The invitation token is no longer valid",
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.RECENT_AUTH_REQUIRED]: "Recent WebAuthn authentication is required",
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.RECENT_AUTH_FAILED]: "Recent WebAuthn authentication failed",
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.RECENT_AUTH_STALE]: "Recent WebAuthn authentication is stale",
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.RECENT_AUTH_UNAVAILABLE]: "Recent WebAuthn verification is unavailable",
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.ORGANIZATIONS_UNAVAILABLE]: "The organization service is unavailable",
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INTERNAL_ERROR]: "The request could not be completed"
});

const ERROR_STATUS = Object.freeze({
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INVALID_REQUEST]: 400,
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.METHOD_NOT_ALLOWED]: 405,
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED]: 403,
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.SESSION_REQUIRED]: 401,
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.CSRF_FAILED]: 403,
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.FORBIDDEN]: 403,
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.ROLE_NOT_ALLOWED]: 403,
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.LAST_OWNER_PROTECTED]: 409,
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.ORGANIZATION_NOT_FOUND]: 404,
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.MEMBER_NOT_FOUND]: 404,
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INVITATION_NOT_FOUND]: 404,
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.VERSION_CONFLICT]: 409,
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.IDEMPOTENCY_REQUIRED]: 400,
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.IDEMPOTENCY_CONFLICT]: 409,
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INVITATION_REPLAYED]: 409,
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.RECENT_AUTH_REQUIRED]: 401,
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.RECENT_AUTH_FAILED]: 401,
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.RECENT_AUTH_STALE]: 401,
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.RECENT_AUTH_UNAVAILABLE]: 503,
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.ORGANIZATIONS_UNAVAILABLE]: 503,
  [HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INTERNAL_ERROR]: 500
});

export class HumanOrganizationsHttpError extends Error {
  constructor(code, { status = ERROR_STATUS[code] ?? 500, cause = undefined, allow = undefined } = {}) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INTERNAL_ERROR], { cause });
    this.name = "HumanOrganizationsHttpError";
    this.code = code;
    this.status = status;
    this.allow = allow;
  }
}

/**
 * Framework-neutral organization HTTP boundary.
 *
 * The injected service has this concise interface. Every method receives an
 * immutable, server-derived `actor`; organization/member/invitation IDs come
 * from validated path parameters; and mutation calls receive the validated
 * Idempotency-Key. Implementations must authorize the actor again in their
 * transaction and must not return bearer hashes, public keys, or raw tokens
 * except `createInvitation`, which may return `raw_token` once.
 *
 * - listOrganizations({ actor, limit, cursor }) -> page
 * - createOrganization({ actor, name, idempotency_key }) -> organization
 * - renameOrganization({ actor, organization_id, name, expected_version, idempotency_key }) -> organization
 * - listMembers/listInvitations({ actor, organization_id, limit, cursor }) -> page
 * - updateMemberRole({ actor, organization_id, member_id, role, expected_version, idempotency_key }) -> member
 * - removeMember({ actor, organization_id, member_id, expected_version, idempotency_key }) -> member
 * - createInvitation({ actor, organization_id, role, expires_at, idempotency_key }) -> { invitation, raw_token }
 * - revokeInvitation({ actor, organization_id, invitation_id, expected_version, idempotency_key }) -> invitation
 * - acceptInvitation({ actor, one_time_token, idempotency_key }) -> member
 */
export function createHumanOrganizationsHttpApi({
  humanSession,
  recentAuthService,
  organizationService,
  abuseControls,
  origin,
  basePath = "",
  maxBodyBytes = MAX_BODY_BYTES,
  now = () => Date.now()
} = {}) {
  assertHumanSession(humanSession);
  if (recentAuthService !== undefined && typeof recentAuthService?.authorize !== "function") throw new TypeError("recentAuthService must expose authorize()");
  assertOrganizationService(organizationService);
  const expectedOrigin = origin ?? humanSession.expectedOrigin;
  assertOriginConfiguration(expectedOrigin);
  const normalizedBasePath = normalizeBasePath(basePath);
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1_024 || maxBodyBytes > 1_024 * 1_024) throw new TypeError("maxBodyBytes is invalid");
  if (typeof now !== "function") throw new TypeError("now must be a function");
  if (!abuseControls || typeof abuseControls.authorize !== "function") throw new TypeError("abuseControls must expose authorize()");

  async function handle(input, nodeResponse = undefined) {
    const result = await dispatch(input);
    if (nodeResponse !== undefined) writeNodeResponse(nodeResponse, result);
    return result;
  }

  async function dispatch(input) {
    try {
      const request = normalizeRequest(input);
      let route = resolveRoute(request.url, normalizedBasePath);
      if (!route) return response(404, { error: { code: "not_found", message: "Resource not found" } });
      if (route.name === "listOrganizations" && request.method === "POST") route = { ...route, name: "createOrganization", method: "POST", allow: "GET, POST", read: false };
      if (route.name === "listInvitations" && request.method === "POST") route = { ...route, name: "createInvitation", method: "POST", allow: "GET, POST", read: false };
      const session = await authenticateSession(request);
      if (request.method !== route.method) {
        throw new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.METHOD_NOT_ALLOWED, { status: 405, allow: route.allow });
      }
      if (route.read && hasBody(request)) throw invalidRequest();
      if (!route.read && route.query.size !== 0) throw invalidRequest();
      if (route.name === "listOrganizations") return await listOrganizations(session, request);
      if (route.name === "listMembers") return await listMembers(session, route, request);
      if (route.name === "listInvitations") return await listInvitations(session, route, request);

      const idempotencyKey = requiredIdempotencyKey(request);
      const noBodyMutation = route.name === "removeMember" || route.name === "revokeInvitation";
      if (noBodyMutation && hasBody(request)) throw invalidRequest();
      const body = noBodyMutation ? {} : await readJsonBody(request, maxBodyBytes);
      if (route.name === "createOrganization") return await createOrganization(session, body, idempotencyKey);
      if (route.name === "renameOrganization") return await renameOrganization(session, route, body, idempotencyKey, request);
      if (route.name === "updateMemberRole") return await updateMemberRole(session, route, body, idempotencyKey, request);
      if (route.name === "removeMember") return await removeMember(session, route, body, idempotencyKey, request);
      if (route.name === "createInvitation") return await createInvitation(session, route, body, idempotencyKey);
      if (route.name === "revokeInvitation") return await revokeInvitation(session, route, body, idempotencyKey, request);
      return await acceptInvitation(session, body, idempotencyKey);
    } catch (error) {
      return mapError(error);
    }
  }

  async function authenticateSession(request) {
    const requestOrigin = header(request.headers, "origin");
    if (requestOrigin !== expectedOrigin || requestOrigin === "null") {
      throw new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED, { status: 403 });
    }
    const cookie = header(request.headers, "cookie");
    try {
      parseSessionCookie(cookie);
    } catch (error) {
      throw new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.SESSION_REQUIRED, { status: 401, cause: error });
    }
    const csrfToken = header(request.headers, HUMAN_SESSION_CSRF_HEADER);
    if (!isOpaqueToken(csrfToken)) throw new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.CSRF_FAILED, { status: 403 });
    try {
      // POST is intentional: the boundary requires CSRF even for read routes.
      const authenticated = await humanSession.authenticateRequest({
        method: "POST",
        headers: request.headers,
        origin: requestOrigin,
        cookie,
        csrfToken
      });
      return normalizeSession(authenticated?.session);
    } catch (error) {
      if (error?.code === HUMAN_SESSION_ERROR_CODES.INVALID_ORIGIN) throw new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED, { status: 403, cause: error });
      if (CSRF_FAILURES.has(error?.code)) throw new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.CSRF_FAILED, { status: 403, cause: error });
      if (SESSION_FAILURES.has(error?.code)) throw new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.SESSION_REQUIRED, { status: 401, cause: error });
      throw new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.ORGANIZATIONS_UNAVAILABLE, { status: 503, cause: error });
    }
  }

  async function listOrganizations(actor, request) {
    const page = parsePagination(request.url);
    try {
      const result = await organizationService.listOrganizations({ actor, ...page });
      return response(200, { organizations: normalizePage(result, page.limit, (item) => normalizeOrganization(item)), next_cursor: normalizeNextCursor(result) });
    } catch (error) {
      throw mapServiceError(error, "organization");
    }
  }

  async function createOrganization(actor, body, idempotencyKey) {
    const input = parseBody(body, new Set(["name"]));
    const name = requiredName(input.name);
    try {
      const result = await organizationService.createOrganization({ actor, name, idempotency_key: idempotencyKey });
      return response(201, { organization: normalizeOrganization(result?.organization ?? result) });
    } catch (error) {
      throw mapServiceError(error, "organization");
    }
  }

  async function renameOrganization(actor, route, body, idempotencyKey, request) {
    requireOrganization(actor, route.organizationId);
    requireRole(actor, ADMIN_OR_OWNER);
    const input = parseBody(body, new Set(["name"]));
    const name = requiredName(input.name);
    const expectedVersion = requiredExpectedVersion(request);
    try {
      const result = await organizationService.renameOrganization({ actor, organization_id: route.organizationId, name, expected_version: expectedVersion, idempotency_key: idempotencyKey });
      return response(200, { organization: normalizeOrganization(result?.organization ?? result, route.organizationId) });
    } catch (error) {
      throw mapServiceError(error, "organization");
    }
  }

  async function listMembers(actor, route, request) {
    requireOrganization(actor, route.organizationId);
    requireRole(actor, AUDITOR_OR_ABOVE);
    const page = parsePagination(request.url);
    try {
      const result = await organizationService.listMembers({ actor, organization_id: route.organizationId, ...page });
      return response(200, { members: normalizePage(result, page.limit, (item) => normalizeMember(item, route.organizationId)), next_cursor: normalizeNextCursor(result) });
    } catch (error) {
      throw mapServiceError(error, "member");
    }
  }

  async function updateMemberRole(actor, route, body, idempotencyKey, request) {
    requireOrganization(actor, route.organizationId);
    requireRole(actor, ADMIN_OR_OWNER);
    const input = parseBody(body, new Set(["role"]));
    if (typeof input.role !== "string" || !ROLES.has(input.role)) throw invalidRequest();
    if (input.role === "owner" && actor.role !== "owner") throw roleNotAllowed();
    const expectedVersion = requiredExpectedVersion(request);
    const recentAuthorization = await requireRecentAuth(actor, route.organizationId, request, HUMAN_ORGANIZATIONS_RECENT_AUTH_OPERATIONS.updateMemberRole);
    try {
      const result = await organizationService.updateMemberRole({ actor, organization_id: route.organizationId, member_id: route.memberId, role: input.role, expected_version: expectedVersion, idempotency_key: idempotencyKey, recent_authorization: recentAuthorization });
      return response(200, { member: normalizeMember(result?.member ?? result, route.organizationId, route.memberId) });
    } catch (error) {
      throw mapServiceError(error, "member");
    }
  }

  async function removeMember(actor, route, body, idempotencyKey, request) {
    requireOrganization(actor, route.organizationId);
    requireRole(actor, ADMIN_OR_OWNER);
    parseBody(body, new Set());
    const expectedVersion = requiredExpectedVersion(request);
    const recentAuthorization = await requireRecentAuth(actor, route.organizationId, request, HUMAN_ORGANIZATIONS_RECENT_AUTH_OPERATIONS.removeMember);
    try {
      const result = await organizationService.removeMember({ actor, organization_id: route.organizationId, member_id: route.memberId, expected_version: expectedVersion, idempotency_key: idempotencyKey, recent_authorization: recentAuthorization });
      return response(200, { member: normalizeMember(result?.member ?? result, route.organizationId, route.memberId) });
    } catch (error) {
      throw mapServiceError(error, "member");
    }
  }

  async function listInvitations(actor, route, request) {
    await abuseControls.authorize({ operation: HUMAN_AUTH_RATE_LIMIT_OPERATIONS.invitationList, session: actor, organizationId: route.organizationId });
    requireOrganization(actor, route.organizationId);
    requireRole(actor, AUDITOR_OR_ABOVE);
    const page = parsePagination(request.url);
    try {
      const result = await organizationService.listInvitations({ actor, organization_id: route.organizationId, ...page });
      return response(200, { invitations: normalizePage(result, page.limit, (item) => normalizeInvitation(item, route.organizationId)), next_cursor: normalizeNextCursor(result) });
    } catch (error) {
      throw mapServiceError(error, "invitation");
    }
  }

  async function createInvitation(actor, route, body, idempotencyKey) {
    await abuseControls.authorize({ operation: HUMAN_AUTH_RATE_LIMIT_OPERATIONS.invitationCreate, session: actor, organizationId: route.organizationId });
    requireOrganization(actor, route.organizationId);
    requireRole(actor, ADMIN_OR_OWNER);
    const input = parseBody(body, new Set(["role", "expires_at"]));
    if (typeof input.role !== "string" || !INVITABLE_ROLES.has(input.role)) throw invalidRequest();
    const expiresAt = requiredDate(input.expires_at, "expires_at");
    try {
      const result = await organizationService.createInvitation({ actor, organization_id: route.organizationId, role: input.role, expires_at: expiresAt, idempotency_key: idempotencyKey });
      const invitation = normalizeInvitation(result?.invitation ?? result, route.organizationId);
      const rawToken = result?.replayed === true ? undefined : result?.raw_token ?? result?.invitation_token ?? result?.token;
      if (result?.replayed !== true && !isOpaqueToken(rawToken)) throw new Error("invitation service did not return one raw token");
      return response(201, { invitation, ...(rawToken === undefined ? {} : { one_time_token: rawToken }) });
    } catch (error) {
      throw mapServiceError(error, "invitation");
    }
  }

  async function revokeInvitation(actor, route, body, idempotencyKey, request) {
    await abuseControls.authorize({ operation: HUMAN_AUTH_RATE_LIMIT_OPERATIONS.invitationRevoke, session: actor, organizationId: route.organizationId });
    requireOrganization(actor, route.organizationId);
    requireRole(actor, ADMIN_OR_OWNER);
    parseBody(body, new Set());
    const expectedVersion = requiredExpectedVersion(request);
    try {
      const result = await organizationService.revokeInvitation({ actor, organization_id: route.organizationId, invitation_id: route.invitationId, expected_version: expectedVersion, idempotency_key: idempotencyKey });
      return response(200, { invitation: normalizeInvitation(result?.invitation ?? result, route.organizationId, route.invitationId) });
    } catch (error) {
      throw mapServiceError(error, "invitation");
    }
  }

  async function acceptInvitation(actor, body, idempotencyKey) {
    await abuseControls.authorize({ operation: HUMAN_AUTH_RATE_LIMIT_OPERATIONS.invitationAccept, session: actor, organizationId: actor.organization_id });
    const input = parseBody(body, new Set(["one_time_token"]));
    if (!isOpaqueToken(input.one_time_token)) throw invalidRequest();
    try {
      const result = await organizationService.acceptInvitation({ actor, one_time_token: input.one_time_token, idempotency_key: idempotencyKey });
      return response(201, { member: normalizeMember(result) });
    } catch (error) {
      throw mapServiceError(error, "invitation");
    }
  }

  return Object.freeze({
    handle,
    paths: HUMAN_ORGANIZATIONS_HTTP_PATHS,
    expectedOrigin,
    basePath: normalizedBasePath
  });

  async function requireRecentAuth(actor, organizationId, request, operation) {
    if (!recentAuthService) {
      throw new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.RECENT_AUTH_UNAVAILABLE, { status: 503 });
    }
    const proof = header(request.headers, RECENT_AUTH_HEADER);
    if (typeof proof !== "string" || proof.length < 32 || proof.length > 4_096) {
      throw new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.RECENT_AUTH_REQUIRED, { status: 401 });
    }

    let authenticatedAt;
    try {
      authenticatedAt = now();
      if (!Number.isSafeInteger(authenticatedAt) || authenticatedAt < 0) throw new Error("recent-auth clock is invalid");
    } catch (error) {
      throw new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.RECENT_AUTH_UNAVAILABLE, { status: 503, cause: error });
    }

    let authorization;
    try {
      authorization = await recentAuthService.authorize({
        proof,
        principal: actor,
        organization_id: organizationId,
        operation,
        now: authenticatedAt
      });
    } catch (error) {
      throw new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.RECENT_AUTH_UNAVAILABLE, { status: 503, cause: error });
    }

    const expectedKeys = ["authenticated_at", "challenge_id", "consumed", "member_id", "operation", "organization_id", "verified"];
    const exactShape = authorization && typeof authorization === "object" && !Array.isArray(authorization)
      && Object.keys(authorization).sort().join(",") === expectedKeys.sort().join(",")
      && authorization.verified === true
      && authorization.consumed === true
      && authorization.member_id === actor.member_id
      && authorization.organization_id === organizationId
      && authorization.operation === operation
      && typeof authorization.challenge_id === "string"
      && UUID.test(authorization.challenge_id)
      && authorization.challenge_id.toLowerCase() === proof.toLowerCase()
      && Number.isSafeInteger(authorization.authenticated_at)
      && authorization.authenticated_at >= 0;
    if (!exactShape) {
      throw new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.RECENT_AUTH_FAILED, { status: 401 });
    }
    if (authorization.authenticated_at > authenticatedAt + 30_000 || authenticatedAt - authorization.authenticated_at > 5 * 60_000) {
      throw new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.RECENT_AUTH_STALE, { status: 401 });
    }
    return Object.freeze({
      session_id: actor.session_id,
      challenge_id: authorization.challenge_id,
      operation: authorization.operation,
      authenticated_at: authorization.authenticated_at
    });
  }
}

function assertHumanSession(value) {
  if (!value || typeof value.authenticateRequest !== "function") throw new TypeError("humanSession must expose authenticateRequest()");
}

function assertOrganizationService(value) {
  if (!value || typeof value !== "object") throw new TypeError("organizationService is invalid");
  for (const method of HUMAN_ORGANIZATION_SERVICE_METHODS) if (typeof value[method] !== "function") throw new TypeError(`organizationService is missing ${method}()`);
}

function assertOriginConfiguration(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > MAX_URL_LENGTH || value.endsWith("/") || !/^https:\/\/[^/]+$/u.test(value)) throw new TypeError("origin is invalid");
}

function normalizeBasePath(value) {
  if (value === "") return "";
  if (typeof value !== "string" || !value.startsWith("/") || value.endsWith("/") || value.includes("?")) throw new TypeError("basePath is invalid");
  return value;
}

function normalizeSession(value) {
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
  const path = url.pathname;
  const prefix = basePath;
  if (path === `${prefix}${ORGANIZATIONS_PATH}`) return { name: "listOrganizations", method: "GET", allow: "GET, POST", read: true, query: url.searchParams };
  if (path === `${prefix}${ACCEPT_INVITATION_PATH}`) return { name: "acceptInvitation", method: "POST", allow: "POST", query: url.searchParams };
  if (path === `${prefix}${ORGANIZATIONS_PATH}`) return undefined;
  const root = `${prefix}${ORGANIZATIONS_PATH}/`;
  if (!path.startsWith(root)) return undefined;
  const parts = path.slice(root.length).split("/");
  if (parts.length === 1 && parts[0] !== "") return { name: "renameOrganization", method: "PATCH", allow: "PATCH", organizationId: decodeSegment(parts[0]), query: url.searchParams };
  if (parts.length === 2 && parts[1] === "members") return { name: "listMembers", method: "GET", allow: "GET", organizationId: decodeSegment(parts[0]), read: true, query: url.searchParams };
  if (parts.length === 2 && parts[1] === "invitations") return { name: "listInvitations", method: "GET", allow: "GET, POST", organizationId: decodeSegment(parts[0]), read: true, query: url.searchParams };
  if (parts.length === 4 && parts[1] === "members" && parts[3] === "role") return { name: "updateMemberRole", method: "PATCH", allow: "PATCH", organizationId: decodeSegment(parts[0]), memberId: decodeSegment(parts[2]), query: url.searchParams };
  if (parts.length === 4 && parts[1] === "members" && parts[3] === "remove") return { name: "removeMember", method: "POST", allow: "POST", organizationId: decodeSegment(parts[0]), memberId: decodeSegment(parts[2]), query: url.searchParams };
  if (parts.length === 4 && parts[1] === "invitations" && parts[3] === "revoke") return { name: "revokeInvitation", method: "POST", allow: "POST", organizationId: decodeSegment(parts[0]), invitationId: decodeSegment(parts[2]), query: url.searchParams };
  if (parts.length === 3 && parts[1] === "invitations") return { name: "createInvitation", method: "POST", allow: "POST", organizationId: decodeSegment(parts[0]), query: url.searchParams };
  return undefined;
}

function requireOrganization(actor, organizationId) {
  if (actor.organization_id !== organizationId) throw new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.ORGANIZATION_NOT_FOUND, { status: 404 });
}

function requireRole(actor, allowed) {
  if (!allowed.has(actor.role)) throw new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.FORBIDDEN, { status: 403 });
}

function parsePagination(rawUrl) {
  const url = new URL(rawUrl, "https://agentpass.invalid");
  const allowed = new Set(["limit", "cursor"]);
  for (const key of url.searchParams.keys()) if (!allowed.has(key)) throw invalidRequest();
  const limits = url.searchParams.getAll("limit");
  const cursors = url.searchParams.getAll("cursor");
  if (limits.length > 1 || cursors.length > 1) throw invalidRequest();
  const limit = limits.length === 0 ? DEFAULT_PAGE_SIZE : parsePageSize(limits[0]);
  const cursor = cursors.length === 0 ? undefined : parseCursor(cursors[0]);
  return Object.freeze({ limit, ...(cursor === undefined ? {} : { cursor }) });
}

function parsePageSize(value) {
  if (typeof value !== "string" || !/^(?:[1-9]|[1-9][0-9]|100)$/u.test(value)) throw invalidRequest();
  return Number(value);
}

function parseCursor(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > MAX_CURSOR_LENGTH || !CURSOR.test(value)) throw invalidRequest();
  return value;
}

function parseBody(body, keys) {
  if (!body || typeof body !== "object" || Array.isArray(body)) throw invalidRequest();
  for (const key of Object.keys(body)) if (!keys.has(key)) throw invalidRequest();
  return body;
}

function requiredName(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > MAX_NAME_LENGTH || value.trim() !== value || /[\u0000-\u001f\u007f]/u.test(value)) throw invalidRequest();
  return value;
}

function requiredVersion(value) {
  if (!Number.isSafeInteger(value) || value < 1) throw invalidRequest();
  return value;
}

function requiredUuid(value, field = "id") {
  if (typeof value !== "string" || !UUID.test(value)) throw new Error(`${field} is invalid`);
  return value.toLowerCase();
}

function decodeSegment(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 256 || value.includes("/")) throw invalidRequest();
  let decoded;
  try { decoded = decodeURIComponent(value); } catch { throw invalidRequest(); }
  if (!decoded || decoded.includes("/") || decoded.includes("\\") || !PATH_SEGMENT.test(decoded)) throw invalidRequest();
  try { return requiredUuid(decoded); } catch (error) { throw invalidRequest(); }
}

function normalizePage(result, limit, normalizer) {
  if (!result || typeof result !== "object" || Array.isArray(result) || !Array.isArray(result.items) || result.items.length > limit) throw new Error("service page is invalid");
  return result.items.map(normalizer);
}

function normalizeNextCursor(result) {
  if (!result || typeof result !== "object" || Array.isArray(result)) throw new Error("service page is invalid");
  return result.next_cursor === undefined || result.next_cursor === null ? null : parseCursor(result.next_cursor);
}

function normalizeOrganization(value, expectedOrganizationId = undefined) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("organization record is invalid");
  const organizationId = requiredUuid(value.organization_id ?? value.id, "organization_id");
  if (expectedOrganizationId !== undefined && organizationId !== expectedOrganizationId) throw new Error("organization binding is invalid");
  const output = { organization_id: organizationId, version: outputVersion(value.version), name: requiredName(value.name) };
  if (value.created_at !== undefined) output.created_at = requiredDate(value.created_at, "created_at");
  if (value.updated_at !== undefined) output.updated_at = requiredDate(value.updated_at, "updated_at");
  return output;
}

function normalizeMember(value, expectedOrganizationId = undefined, expectedMemberId = undefined) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("member record is invalid");
  const organizationId = requiredUuid(value.organization_id, "organization_id");
  const memberId = requiredUuid(value.member_id ?? value.id, "member_id");
  if (expectedOrganizationId !== undefined && organizationId !== expectedOrganizationId) throw new Error("member binding is invalid");
  if (expectedMemberId !== undefined && memberId !== expectedMemberId) throw new Error("member binding is invalid");
  if (!ROLES.has(value.role)) throw new Error("member role is invalid");
  if (typeof value.status !== "string" || !new Set(["active", "revoked"]).has(value.status)) throw new Error("member status is invalid");
  const output = { member_id: memberId, organization_id: organizationId, version: outputVersion(value.version), role: value.role, status: value.status };
  for (const field of ["created_at", "updated_at", "removed_at"]) if (value[field] !== undefined) output[field] = nullableDate(value[field], field);
  return output;
}

function normalizeInvitation(value, expectedOrganizationId = undefined, expectedInvitationId = undefined) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invitation record is invalid");
  const organizationId = requiredUuid(value.organization_id, "organization_id");
  const invitationId = requiredUuid(value.invitation_id ?? value.id, "invitation_id");
  if (expectedOrganizationId !== undefined && organizationId !== expectedOrganizationId) throw new Error("invitation binding is invalid");
  if (expectedInvitationId !== undefined && invitationId !== expectedInvitationId) throw new Error("invitation binding is invalid");
  if (!new Set(["admin", "auditor", "viewer"]).has(value.role)) throw new Error("invitation role is invalid");
  if (typeof value.status !== "string" || !new Set(["pending", "accepted", "revoked", "expired"]).has(value.status)) throw new Error("invitation status is invalid");
  const output = { invitation_id: invitationId, organization_id: organizationId, version: outputVersion(value.version), role: value.role, status: value.status };
  for (const field of ["created_at", "expires_at"]) if (value[field] !== undefined) output[field] = requiredDate(value[field], field);
  for (const field of ["accepted_at", "consumed_at", "revoked_at"]) if (value[field] !== undefined) output[field === "consumed_at" ? "accepted_at" : field] = nullableDate(value[field], field);
  return output;
}

function outputVersion(value) {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error("resource version is invalid");
  return value;
}

function requiredDate(value, field) {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) throw new Error(`${field} is invalid`);
  return value;
}

function nullableDate(value, field) {
  if (value === null) return null;
  return requiredDate(value, field);
}

function requiredIdempotencyKey(request) {
  const value = header(request.headers, "idempotency-key");
  if (typeof value !== "string" || value.length > MAX_IDEMPOTENCY_KEY_LENGTH || !IDEMPOTENCY_KEY.test(value)) throw new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.IDEMPOTENCY_REQUIRED, { status: 400 });
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

function mapServiceError(error, resource) {
  if (error instanceof HumanOrganizationsHttpError) return error;
  const code = String(error?.code ?? error?.name ?? "").toLowerCase();
  if (["not_found", "organization_not_found", "resource_not_found", "tenant_not_found"].includes(code)) return new HumanOrganizationsHttpError(resourceCode(resource), { status: 404, cause: error });
  if (["member_not_found", "membership_not_found"].includes(code)) return new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.MEMBER_NOT_FOUND, { status: 404, cause: error });
  if (["invitation_not_found"].includes(code)) return new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INVITATION_NOT_FOUND, { status: 404, cause: error });
  if (error?.reason === "last_owner" || ["last_owner", "err_last_owner", "owner_constraint", "cannot_remove_owner"].includes(code)) return new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.LAST_OWNER_PROTECTED, { status: 409, cause: error });
  if (error?.reason === "role_not_allowed" || ["role_not_allowed", "err_role_not_allowed", "role_downgrade_forbidden"].includes(code)) return new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.ROLE_NOT_ALLOWED, { status: 403, cause: error });
  if (error?.reason === "stale_session" || ["stale_session", "err_stale_session", "actor_session_required", "err_actor_session_required"].includes(code)) return new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.RECENT_AUTH_STALE, { status: 401, cause: error });
  if (["forbidden", "err_forbidden", "not_authorized", "owner_required", "err_actor"].includes(code)) return new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.FORBIDDEN, { status: 403, cause: error });
  if (["version_conflict", "err_version_conflict", "expected_version_mismatch", "err_expected_version_mismatch", "stale_version"].includes(code)) return new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.VERSION_CONFLICT, { status: 409, cause: error });
  if (["idempotency_conflict", "err_idempotency_conflict", "idempotency_key_reused"].includes(code)) return new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.IDEMPOTENCY_CONFLICT, { status: 409, cause: error });
  if (["invitation_replayed", "invitation_token_replayed", "token_replayed", "already_used", "invitation_expired"].includes(code)) return new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INVITATION_REPLAYED, { status: 409, cause: error });
  if (["invalid_input", "invalid_scope", "tenant_scope_error"].includes(code)) return invalidRequest();
  return new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.ORGANIZATIONS_UNAVAILABLE, { status: 503, cause: error });
}

function resourceCode(resource) {
  return resource === "member" ? HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.MEMBER_NOT_FOUND : resource === "invitation" ? HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INVITATION_NOT_FOUND : HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.ORGANIZATION_NOT_FOUND;
}

function invalidRequest() {
  return new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
}

function roleNotAllowed() {
  return new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.ROLE_NOT_ALLOWED, { status: 403 });
}

function mapError(error) {
  if (error instanceof HumanAuthAbuseControlError) return response(error.status, { error: { code: error.code, message: error.message } }, error.headers);
  if (error instanceof HumanOrganizationsHttpError) {
    const headers = error.status === 405 ? { Allow: error.allow ?? "GET, POST, PATCH" } : undefined;
    return response(error.status, { error: { code: error.code, message: ERROR_MESSAGES[error.code] ?? ERROR_MESSAGES[HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INTERNAL_ERROR] } }, headers);
  }
  return response(500, { error: { code: HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INTERNAL_ERROR, message: ERROR_MESSAGES[HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INTERNAL_ERROR] } });
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
  if (!input || typeof input !== "object") throw invalidRequest();
  const method = String(input.method ?? "").toUpperCase();
  const url = String(input.url ?? input.originalUrl ?? input.path ?? "");
  if (!method || !url || url.length > MAX_URL_LENGTH) throw invalidRequest();
  return Object.freeze({ input, method, url, headers: normalizeHeaders(input.headers ?? {}), body: input.body });
}

function normalizeHeaders(input) {
  const result = {};
  const names = ["origin", "cookie", "content-type", "content-length", "idempotency-key", "if-match", HUMAN_SESSION_CSRF_HEADER, RECENT_AUTH_HEADER];
  if (input && typeof input.get === "function") {
    for (const name of names) {
      const value = input.get(name);
      if (value !== null) setHeader(result, name, value);
    }
    return result;
  }
  if (!input || typeof input !== "object" || Array.isArray(input)) throw invalidRequest();
  for (const [name, value] of Object.entries(input)) if (names.includes(name.toLowerCase())) setHeader(result, name, value);
  return result;
}

function setHeader(target, name, value) {
  if (Array.isArray(value) || typeof value === "object" || value === undefined) throw invalidRequest();
  const normalized = name.toLowerCase();
  if (target[normalized] !== undefined) throw invalidRequest();
  target[normalized] = String(value);
}

function header(headers, name) {
  const value = headers[name.toLowerCase()];
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length > MAX_HEADER_BYTES || /[\u0000-\u001f\u007f]/u.test(value)) throw invalidRequest();
  return value;
}

function hasBody(request) {
  return request.body !== undefined && request.body !== null && (!(typeof request.body === "string") || request.body.length > 0);
}

async function readJsonBody(request, maxBytes) {
  const contentType = header(request.headers, "content-type");
  if (typeof contentType !== "string" || !/^application\/json(?:\s*;|$)/iu.test(contentType)) throw invalidRequest();
  const contentLength = header(request.headers, "content-length");
  if (contentLength !== undefined && (!/^\d+$/u.test(contentLength) || !Number.isSafeInteger(Number(contentLength)) || Number(contentLength) > maxBytes)) throw new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
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
  if (bytes.length > maxBytes) throw new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
  try { return JSON.parse(bytes.toString("utf8")); } catch (error) { throw new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400, cause: error }); }
}

function assertSerializedSize(value, maxBytes) {
  let serialized;
  try { serialized = JSON.stringify(value); } catch (error) { throw new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400, cause: error }); }
  if (typeof serialized !== "string" || Buffer.byteLength(serialized, "utf8") > maxBytes) throw new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
}

function isReadable(value) {
  return Boolean(value && typeof value === "object" && (typeof value.getReader === "function" || typeof value[Symbol.asyncIterator] === "function"));
}

async function readStream(stream, maxBytes) {
  const chunks = [];
  let total = 0;
  if (typeof stream.getReader === "function") {
    const reader = stream.getReader();
    try {
      for (;;) {
        const next = await reader.read();
        if (next.done) break;
        const bytes = next.value instanceof Uint8Array ? Buffer.from(next.value) : Buffer.from(String(next.value), "utf8");
        total += bytes.length;
        if (total > maxBytes) throw new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
        chunks.push(bytes);
      }
    } finally { reader.releaseLock?.(); }
  } else {
    for await (const chunk of stream) {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += bytes.length;
      if (total > maxBytes) throw new HumanOrganizationsHttpError(HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
      chunks.push(bytes);
    }
  }
  return Buffer.concat(chunks);
}

function writeNodeResponse(nodeResponse, result) {
  if (!nodeResponse || typeof nodeResponse.writeHead !== "function" || typeof nodeResponse.end !== "function") throw new TypeError("node response is invalid");
  nodeResponse.writeHead(result.status, result.headers);
  nodeResponse.end(JSON.stringify(result.body));
}
