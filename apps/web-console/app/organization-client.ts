import { authenticateRecentAuth, type AuthorizationResult } from "./webauthn-client.ts";

const SESSION_PATH = "/api/auth/session";
const SWITCH_ORGANIZATION_PATH = "/api/auth/session/organization-switch";
const ORGANIZATIONS_PATH = "/api/auth/organizations";
const ACCEPT_INVITATION_PATH = "/api/auth/invitations/accept";
const CSRF_HEADER = "agentpass-csrf";
const RECENT_AUTH_HEADER = "agentpass-recent-auth";
const MAX_RESPONSE_BYTES = 256 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TOKEN = /^[A-Za-z0-9_-]{43,512}$/;
const CSRF = /^[A-Za-z0-9_-]{43,512}$/;
const IDempotency = /^[A-Za-z0-9._~-]{8,255}$/;
const CURSOR = /^[A-Za-z0-9_-]{1,512}$/;
const ISO_DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const ROLES = ["owner", "admin", "auditor", "viewer"] as const;
const INVITE_ROLES = ["admin", "auditor", "viewer"] as const;

export type OrganizationRole = (typeof ROLES)[number];
export type InvitationRole = (typeof INVITE_ROLES)[number];
export type OrganizationStatus = "active" | "revoked";
export type InvitationStatus = "pending" | "accepted" | "revoked" | "expired";

export type Organization = Readonly<{
  id: string;
  name: string;
  version: number;
  createdAt: string;
  updatedAt: string;
}>;

export type OrganizationMember = Readonly<{
  membershipId: string;
  organizationId: string;
  memberId: string;
  displayName: string | null;
  role: OrganizationRole;
  status: OrganizationStatus;
  version: number;
  createdAt: string;
  updatedAt: string;
}>;

export type OrganizationInvitation = Readonly<{
  id: string;
  organizationId: string;
  role: InvitationRole;
  status: InvitationStatus;
  version: number;
  createdAt: string;
  expiresAt: string;
  acceptedAt: string | null;
  acceptedMemberId: string | null;
}>;

export type OrganizationSession = Readonly<{
  version: number;
  sessionId: string;
  memberId: string;
  organizationId: string;
  role: OrganizationRole;
  createdAt: string;
  expiresAt: string;
  recentAuthAt: string | null;
  csrfToken: string;
}>;

export type Page<T> = Readonly<{ items: readonly T[]; nextCursor: string | null; requestId: string }>;
export type OrganizationPage = Page<Organization>;
export type MemberPage = Page<OrganizationMember>;
export type InvitationPage = Page<OrganizationInvitation>;

export type OrganizationClientErrorCode =
  | "http_failed"
  | "invalid_response"
  | "transport_failed"
  | "aborted"
  | "conflict"
  | "expired"
  | "recent_auth_required"
  | "forbidden"
  | "unauthorized"
  | "validation_failed";

export class OrganizationClientError extends Error {
  readonly code: OrganizationClientErrorCode;
  readonly status?: number;
  readonly serverCode?: string;

  constructor(code: OrganizationClientErrorCode, message: string, status?: number, serverCode?: string) {
    super(message);
    this.name = "OrganizationClientError";
    this.code = code;
    this.status = status;
    this.serverCode = serverCode;
  }
}

export type RequestOptions = Readonly<{
  signal?: AbortSignal;
}>;

export type MutationOptions = RequestOptions & Readonly<{
  idempotencyKey?: string;
  recentAuth?: string;
}>;

export type RecentAuthInput = Readonly<{
  operation: string;
  organizationId: string;
  csrfToken: string;
  signal?: AbortSignal;
  fetchImpl: typeof fetch;
}>;

export type OrganizationClientOptions = Readonly<{
  fetchImpl?: typeof fetch;
  authorizeRecentAuthImpl?: (input: RecentAuthInput) => Promise<string | AuthorizationResult>;
}>;

export type OrganizationClient = Readonly<{
  getSession(options?: RequestOptions): Promise<OrganizationSession>;
  refreshSession?: (options?: RequestOptions) => Promise<OrganizationSession>;
  switchOrganization(input: Readonly<{ organizationId: string }> & RequestOptions): Promise<OrganizationSession>;
  listOrganizations(options?: RequestOptions & Readonly<{ limit?: number; cursor?: string }>): Promise<OrganizationPage>;
  createOrganization(input: Readonly<{ name: string }> & MutationOptions): Promise<Readonly<{ requestId: string; organization: Organization }>>;
  renameOrganization(input: Readonly<{ organizationId: string; name: string; expectedVersion: number }> & MutationOptions): Promise<Readonly<{ requestId: string; organization: Organization }>>;
  listMembers(organizationId: string, options?: RequestOptions & Readonly<{ limit?: number; cursor?: string }>): Promise<MemberPage>;
  updateMemberRole(input: Readonly<{ organizationId: string; memberId: string; role: OrganizationRole; expectedVersion: number }> & MutationOptions): Promise<Readonly<{ requestId: string; member: OrganizationMember }>>;
  removeMember(input: Readonly<{ organizationId: string; memberId: string; expectedVersion: number }> & MutationOptions): Promise<Readonly<{ requestId: string; member: OrganizationMember }>>;
  listInvitations(organizationId: string, options?: RequestOptions & Readonly<{ limit?: number; cursor?: string }>): Promise<InvitationPage>;
  createInvitation(input: Readonly<{ organizationId: string; role: InvitationRole; expiresAt: string }> & MutationOptions): Promise<Readonly<{ requestId: string; invitation: OrganizationInvitation; oneTimeToken: string }>>;
  revokeInvitation(input: Readonly<{ organizationId: string; invitationId: string; expectedVersion: number }> & MutationOptions): Promise<Readonly<{ requestId: string; invitation: OrganizationInvitation }>>;
  acceptInvitation(input: Readonly<{ oneTimeToken: string }> & MutationOptions): Promise<Readonly<{ requestId: string; member: OrganizationMember }>>;
}>;

export type OrganizationVisibility = Readonly<{
  canViewOrganization: boolean;
  canViewMembers: boolean;
  canViewInvitations: boolean;
  canManageOrganization: boolean;
  canManageMembers: boolean;
  canAssignOwner: boolean;
  canInvite: boolean;
  canRevokeInvitations: boolean;
}>;

export function getOrganizationVisibility(role: OrganizationRole): OrganizationVisibility {
  assertRole(role);
  const canViewAdminData = role === "owner" || role === "admin" || role === "auditor";
  const canManage = role === "owner" || role === "admin";
  return Object.freeze({
    canViewOrganization: true,
    canViewMembers: canViewAdminData,
    canViewInvitations: canViewAdminData,
    canManageOrganization: canManage,
    canManageMembers: canManage,
    canAssignOwner: role === "owner",
    canInvite: canManage,
    canRevokeInvitations: canManage,
  });
}

export function createOrganizationClient(options: OrganizationClientOptions = {}): OrganizationClient {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") throw new OrganizationClientError("transport_failed", "Organization transport is unavailable");

  let session: OrganizationSession | undefined;
  let pendingSession: Promise<OrganizationSession> | undefined;
  let switchSequence = 0;

  const invalidateSession = (): void => {
    session = undefined;
    pendingSession = undefined;
  };

  const getSession = async (requestOptions: RequestOptions = {}): Promise<OrganizationSession> => {
    if (session !== undefined) {
      assertSessionActive(session);
      return session;
    }
    if (pendingSession === undefined) {
      const pending = bootstrapSession(fetchImpl, requestOptions.signal).then((value) => {
        assertSessionActive(value);
        // A request that was invalidated by a 401, refresh, or replacement may
        // still settle. It must never repopulate the cache with stale identity.
        if (pendingSession === pending) session = value;
        return value;
      });
      pendingSession = pending;
      void pending.catch(() => {
        if (pendingSession === pending) pendingSession = undefined;
      });
    }
    return pendingSession;
  };

  const refreshSession = async (requestOptions: RequestOptions = {}): Promise<OrganizationSession> => {
    invalidateSession();
    return getSession(requestOptions);
  };

  const getRequestContext = async (requestOptions: RequestOptions): Promise<OrganizationSession> => getSession(requestOptions);

  const switchOrganization = async (input: Readonly<{ organizationId: string }> & RequestOptions): Promise<OrganizationSession> => {
    const organizationId = requiredUuid(input?.organizationId, "organizationId");
    const sequence = ++switchSequence;
    const context = await getRequestContext(input);
    if (context.organizationId === organizationId) throw new OrganizationClientError("validation_failed", "organizationId is already active");
    const payload = await requestOrganizationJson(fetchImpl, SWITCH_ORGANIZATION_PATH, "POST", { organization_id: organizationId }, context, input, { idempotencyKey: null });
    const next = parseSessionResponse(payload);
    assertSessionActive(next);
    if (next.organizationId !== organizationId || next.memberId !== context.memberId) {
      throw invalidResponse("Organization switch response is not bound to the requested tenant");
    }
    if (sequence !== switchSequence || session !== context) {
      throw new OrganizationClientError("conflict", "Organization switch was superseded by a newer session change");
    }
    session = next;
    pendingSession = undefined;
    return next;
  };

  const listOrganizations = async (requestOptions: RequestOptions & Readonly<{ limit?: number; cursor?: string }> = {}): Promise<OrganizationPage> => {
    const context = await getRequestContext(requestOptions);
    const query = buildPageQuery(requestOptions);
    const payload = await requestOrganizationJson(fetchImpl, `${ORGANIZATIONS_PATH}${query}`, "GET", undefined, context, requestOptions);
    return parsePage(payload, "organizations", parseOrganization);
  };

  const createOrganization = async (input: Readonly<{ name: string }> & MutationOptions): Promise<Readonly<{ requestId: string; organization: Organization }>> => {
    const name = requiredName(input?.name);
    const context = await getRequestContext(input);
    const payload = await requestOrganizationJson(fetchImpl, ORGANIZATIONS_PATH, "POST", { name }, context, input, { idempotencyKey: input.idempotencyKey });
    return parseOrganizationEnvelope(payload);
  };

  const renameOrganization = async (input: Readonly<{ organizationId: string; name: string; expectedVersion: number }> & MutationOptions): Promise<Readonly<{ requestId: string; organization: Organization }>> => {
    const organizationId = requiredUuid(input?.organizationId, "organizationId");
    const name = requiredName(input?.name);
    const expectedVersion = requiredVersion(input?.expectedVersion);
    const context = await getRequestContext(input);
    const payload = await requestOrganizationJson(fetchImpl, `${ORGANIZATIONS_PATH}/${organizationId}`, "PATCH", { name }, context, input, { idempotencyKey: input.idempotencyKey, expectedVersion });
    return parseOrganizationEnvelope(payload, organizationId);
  };

  const listMembers = async (organizationId: string, requestOptions: RequestOptions & Readonly<{ limit?: number; cursor?: string }> = {}): Promise<MemberPage> => {
    const id = requiredUuid(organizationId, "organizationId");
    const context = await getRequestContext(requestOptions);
    const payload = await requestOrganizationJson(fetchImpl, `${ORGANIZATIONS_PATH}/${id}/members${buildPageQuery(requestOptions)}`, "GET", undefined, context, requestOptions);
    return parsePage(payload, "members", (value) => parseMember(value, id));
  };

  const updateMemberRole = async (input: Readonly<{ organizationId: string; memberId: string; role: OrganizationRole; expectedVersion: number }> & MutationOptions): Promise<Readonly<{ requestId: string; member: OrganizationMember }>> => {
    const organizationId = requiredUuid(input?.organizationId, "organizationId");
    const memberId = requiredUuid(input?.memberId, "memberId");
    const role = requiredRole(input?.role);
    const expectedVersion = requiredVersion(input?.expectedVersion);
    const context = await getRequestContext(input);
    const recentAuth = await resolveRecentAuth(context, organizationId, input?.recentAuth, "human.organizations.member.role.update", input?.signal);
    const payload = await requestOrganizationJson(fetchImpl, `${ORGANIZATIONS_PATH}/${organizationId}/members/${memberId}/role`, "PATCH", { role }, context, input, { idempotencyKey: input.idempotencyKey, expectedVersion, recentAuth });
    return parseMemberEnvelope(payload, organizationId, memberId);
  };

  const removeMember = async (input: Readonly<{ organizationId: string; memberId: string; expectedVersion: number }> & MutationOptions): Promise<Readonly<{ requestId: string; member: OrganizationMember }>> => {
    const organizationId = requiredUuid(input?.organizationId, "organizationId");
    const memberId = requiredUuid(input?.memberId, "memberId");
    const expectedVersion = requiredVersion(input?.expectedVersion);
    const context = await getRequestContext(input);
    const recentAuth = await resolveRecentAuth(context, organizationId, input?.recentAuth, "human.organizations.member.remove", input?.signal);
    const payload = await requestOrganizationJson(fetchImpl, `${ORGANIZATIONS_PATH}/${organizationId}/members/${memberId}/remove`, "POST", undefined, context, input, { idempotencyKey: input.idempotencyKey, expectedVersion, recentAuth });
    return parseMemberEnvelope(payload, organizationId, memberId);
  };

  const listInvitations = async (organizationId: string, requestOptions: RequestOptions & Readonly<{ limit?: number; cursor?: string }> = {}): Promise<InvitationPage> => {
    const id = requiredUuid(organizationId, "organizationId");
    const context = await getRequestContext(requestOptions);
    const payload = await requestOrganizationJson(fetchImpl, `${ORGANIZATIONS_PATH}/${id}/invitations${buildPageQuery(requestOptions)}`, "GET", undefined, context, requestOptions);
    return parsePage(payload, "invitations", (value) => parseInvitation(value, id));
  };

  const createInvitation = async (input: Readonly<{ organizationId: string; role: InvitationRole; expiresAt: string }> & MutationOptions): Promise<Readonly<{ requestId: string; invitation: OrganizationInvitation; oneTimeToken: string }>> => {
    const organizationId = requiredUuid(input?.organizationId, "organizationId");
    const role = requiredInviteRole(input?.role);
    const expiresAt = requiredDate(input?.expiresAt, "expiresAt");
    const context = await getRequestContext(input);
    const payload = await requestOrganizationJson(fetchImpl, `${ORGANIZATIONS_PATH}/${organizationId}/invitations`, "POST", { role, expires_at: expiresAt }, context, input, { idempotencyKey: input.idempotencyKey });
    return parseInvitationCreated(payload, organizationId);
  };

  const revokeInvitation = async (input: Readonly<{ organizationId: string; invitationId: string; expectedVersion: number }> & MutationOptions): Promise<Readonly<{ requestId: string; invitation: OrganizationInvitation }>> => {
    const organizationId = requiredUuid(input?.organizationId, "organizationId");
    const invitationId = requiredUuid(input?.invitationId, "invitationId");
    const expectedVersion = requiredVersion(input?.expectedVersion);
    const context = await getRequestContext(input);
    const recentAuth = await resolveRecentAuth(context, organizationId, input?.recentAuth, "human.organizations.invitation.revoke", input?.signal);
    const payload = await requestOrganizationJson(fetchImpl, `${ORGANIZATIONS_PATH}/${organizationId}/invitations/${invitationId}/revoke`, "POST", undefined, context, input, { idempotencyKey: input.idempotencyKey, expectedVersion, recentAuth });
    return parseInvitationEnvelope(payload, organizationId, invitationId);
  };

  const acceptInvitation = async (input: Readonly<{ oneTimeToken: string }> & MutationOptions): Promise<Readonly<{ requestId: string; invitation: OrganizationInvitation; member: OrganizationMember }>> => {
    const oneTimeToken = requiredToken(input?.oneTimeToken);
    const context = await getRequestContext(input);
    const payload = await requestOrganizationJson(fetchImpl, ACCEPT_INVITATION_PATH, "POST", { one_time_token: oneTimeToken }, context, input, { idempotencyKey: input.idempotencyKey });
    return parseInvitationAccepted(payload);
  };

  async function resolveRecentAuth(context: OrganizationSession, organizationId: string, supplied: string | undefined, operation: string, signal: AbortSignal | undefined): Promise<string> {
    if (supplied !== undefined) return requiredUuid(supplied, "recentAuth");
    const authorize = options.authorizeRecentAuthImpl ?? ((input: RecentAuthInput) => authenticateRecentAuth(input));
    let result: string | AuthorizationResult;
    try {
      result = await authorize({ operation, organizationId, csrfToken: context.csrfToken, signal, fetchImpl });
    } catch (error) {
      if (signal?.aborted || error instanceof DOMException && error.name === "AbortError") throw new OrganizationClientError("aborted", "Recent authentication was cancelled");
      if (error instanceof OrganizationClientError && (error.code === "unauthorized" || error.code === "forbidden" || error.code === "expired")) throw error;
      throw new OrganizationClientError("recent_auth_required", "Recent authentication is required to complete this action");
    }
    const authorizationId = typeof result === "string" ? result : result?.authorization_id;
    return requiredUuid(authorizationId, "recentAuth");
  }

  async function requestOrganizationJson(requestFetch: typeof fetch, path: string, method: "GET" | "POST" | "PATCH", body: Record<string, unknown> | undefined, context: OrganizationSession, requestOptions: RequestOptions, controls: Readonly<{ idempotencyKey?: string | null; expectedVersion?: number; recentAuth?: string }> = {}): Promise<unknown> {
    try {
      return await requestJson(requestFetch, path, method, body, context, requestOptions, controls);
    } catch (error) {
      if (error instanceof OrganizationClientError && error.code === "unauthorized") {
        if (session === context) invalidateSession();
      } else if (error instanceof OrganizationClientError && error.code === "expired") {
        if (session === context) invalidateSession();
      }
      throw error;
    }
  }

  return Object.freeze({ getSession, refreshSession, switchOrganization, listOrganizations, createOrganization, renameOrganization, listMembers, updateMemberRole, removeMember, listInvitations, createInvitation, revokeInvitation, acceptInvitation });
}

export async function getOrganizations(options: OrganizationClientOptions & RequestOptions & Readonly<{ limit?: number; cursor?: string }> = {}): Promise<OrganizationPage> {
  return createOrganizationClient(options).listOrganizations(options);
}

function buildPageQuery(options: Readonly<{ limit?: number; cursor?: string }>): string {
  if (options.limit !== undefined && (!Number.isSafeInteger(options.limit) || options.limit < 1 || options.limit > 100)) throw new OrganizationClientError("validation_failed", "limit is invalid");
  if (options.cursor !== undefined && !CURSOR.test(options.cursor)) throw new OrganizationClientError("validation_failed", "cursor is invalid");
  const query = new URLSearchParams();
  if (options.limit !== undefined) query.set("limit", String(options.limit));
  if (options.cursor !== undefined) query.set("cursor", options.cursor);
  const value = query.toString();
  return value ? `?${value}` : "";
}

async function bootstrapSession(fetchImpl: typeof fetch, signal: AbortSignal | undefined): Promise<OrganizationSession> {
  const payload = await requestRawJson(fetchImpl, SESSION_PATH, "POST", {}, undefined, signal);
  return parseSessionResponse(payload);
}

function parseSessionResponse(payload: unknown): OrganizationSession {
  if (!isRecord(payload) || !hasExactKeys(payload, ["session", "csrf_token"]) || !isRecord(payload.session) || !hasExactKeys(payload.session, ["version", "session_id", "member_id", "organization_id", "role", "created_at", "expires_at", "recent_auth_at"]) || !isVersion(payload.session.version) || !UUID.test(payload.session.session_id as string) || !UUID.test(payload.session.member_id as string) || !UUID.test(payload.session.organization_id as string) || !isRole(payload.session.role) || !isDateTime(payload.session.created_at) || !isDateTime(payload.session.expires_at) || !isNullableDateTime(payload.session.recent_auth_at) || typeof payload.csrf_token !== "string" || !CSRF.test(payload.csrf_token)) {
    throw invalidResponse("Session response is invalid");
  }
  return Object.freeze({ version: payload.session.version, sessionId: String(payload.session.session_id).toLowerCase(), memberId: String(payload.session.member_id).toLowerCase(), organizationId: String(payload.session.organization_id).toLowerCase(), role: payload.session.role, createdAt: String(payload.session.created_at), expiresAt: String(payload.session.expires_at), recentAuthAt: payload.session.recent_auth_at === null ? null : String(payload.session.recent_auth_at), csrfToken: payload.csrf_token });
}

function assertSessionActive(value: OrganizationSession): void {
  if (Date.parse(value.expiresAt) <= Date.now()) {
    throw new OrganizationClientError("expired", "The organization session has expired", 401, "session_expired");
  }
}

async function requestJson(fetchImpl: typeof fetch, path: string, method: "GET" | "POST" | "PATCH", body: Record<string, unknown> | undefined, context: OrganizationSession, options: RequestOptions, controls: Readonly<{ idempotencyKey?: string | null; expectedVersion?: number; recentAuth?: string }> = {}): Promise<unknown> {
  const idempotencyKey = controls.idempotencyKey === null ? undefined : controls.idempotencyKey ?? (method === "GET" ? undefined : makeIdempotencyKey());
  if (method !== "GET" && idempotencyKey !== undefined) assertIdempotencyKey(idempotencyKey);
  const headers = new Headers({ accept: "application/json", "cache-control": "no-store", pragma: "no-cache", [CSRF_HEADER]: context.csrfToken });
  if (body !== undefined) headers.set("content-type", "application/json");
  if (idempotencyKey !== undefined) headers.set("idempotency-key", idempotencyKey);
  if (controls.expectedVersion !== undefined) headers.set("If-Match", `"${controls.expectedVersion}"`);
  if (controls.recentAuth !== undefined) headers.set(RECENT_AUTH_HEADER, controls.recentAuth);
  return requestRawJson(fetchImpl, path, method, body, headers, options.signal);
}

async function requestRawJson(fetchImpl: typeof fetch, path: string, method: "GET" | "POST" | "PATCH", body: Record<string, unknown> | undefined, extraHeaders: Headers | undefined, signal: AbortSignal | undefined): Promise<unknown> {
  let response: Response;
  try {
    const headers = new Headers(extraHeaders ?? { accept: "application/json", "cache-control": "no-store", "content-type": "application/json", pragma: "no-cache" });
    if (!headers.has("accept")) headers.set("accept", "application/json");
    if (!headers.has("cache-control")) headers.set("cache-control", "no-store");
    response = await fetchImpl(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), cache: "no-store", credentials: "same-origin", redirect: "error", signal });
  } catch (error) {
    if (signal?.aborted || error instanceof DOMException && error.name === "AbortError") throw new OrganizationClientError("aborted", "The organization request was cancelled");
    throw new OrganizationClientError("transport_failed", "The organization service is unavailable");
  }
  if (!response || typeof response.status !== "number" || !response.headers || !response.headers.get) throw invalidResponse("Organization response is invalid");
  const contentType = response.headers.get("content-type") ?? "";
  if (!/^application\/json(?:\s*;|\s*$)/i.test(contentType)) throw invalidResponse("Organization response is invalid", response.status);
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null && (!/^\d+$/.test(contentLength) || Number(contentLength) > MAX_RESPONSE_BYTES)) throw invalidResponse("Organization response is invalid", response.status);
  let bytes: Uint8Array;
  try { bytes = new Uint8Array(await response.arrayBuffer()); } catch { throw invalidResponse("Organization response is invalid", response.status); }
  if (bytes.byteLength > MAX_RESPONSE_BYTES) throw invalidResponse("Organization response is invalid", response.status);
  let payload: unknown;
  try { payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch { throw invalidResponse("Organization response is invalid", response.status); }
  if (!response.ok || response.status < 200 || response.status >= 300) throw parseHttpError(response.status, payload);
  return payload;
}

function parseHttpError(status: number, payload: unknown): OrganizationClientError {
  if (!isRecord(payload) || !hasAllowedKeys(payload, ["error"]) || !isRecord(payload.error) || !hasAllowedKeys(payload.error, ["code", "message", "details"]) || typeof payload.error.code !== "string" || !/^[A-Za-z0-9_.-]{1,128}$/.test(payload.error.code) || typeof payload.error.message !== "string" || payload.error.message.length < 1 || payload.error.message.length > 512 || payload.error.details !== undefined && !isRecord(payload.error.details)) return invalidResponse("Organization error response is invalid", status);
  const code = payload.error.code;
  if (status === 401) return new OrganizationClientError("unauthorized", payload.error.message, status, code);
  if (status === 403) return new OrganizationClientError("forbidden", payload.error.message, status, code);
  if (status === 428 || /recent[_-]?auth|reauth|webauthn/i.test(code)) return new OrganizationClientError("recent_auth_required", payload.error.message, status, code);
  if (/(?:^|[._-])session(?:[._-]|$)/i.test(code)) return new OrganizationClientError("unauthorized", payload.error.message, status, code);
  if (status === 410 || /expired|expiration/i.test(code)) return new OrganizationClientError("expired", payload.error.message, status, code);
  if (status === 409 || code.includes("conflict") || code.includes("version") || code.includes("reused") || code.includes("last_owner")) return new OrganizationClientError("conflict", payload.error.message, status, code);
  if (status === 400 || status === 422) return new OrganizationClientError("validation_failed", payload.error.message, status, code);
  return new OrganizationClientError("http_failed", payload.error.message, status, code);
}

function parseOrganizationEnvelope(value: unknown, expectedId?: string): Readonly<{ requestId: string; organization: Organization }> {
  if (!isRecord(value) || !hasExactKeys(value, ["request_id", "organization"]) || typeof value.request_id !== "string" || !UUID.test(value.request_id) || !isRecord(value.organization)) throw invalidResponse("Organization response is invalid");
  return Object.freeze({ requestId: value.request_id.toLowerCase(), organization: parseOrganization(value.organization, expectedId) });
}

function parseMemberEnvelope(value: unknown, organizationId: string, memberId: string): Readonly<{ requestId: string; member: OrganizationMember }> {
  if (!isRecord(value) || !hasExactKeys(value, ["request_id", "member"]) || typeof value.request_id !== "string" || !UUID.test(value.request_id) || !isRecord(value.member)) throw invalidResponse("Member response is invalid");
  return Object.freeze({ requestId: value.request_id.toLowerCase(), member: parseMember(value.member, organizationId, memberId) });
}

function parseInvitationEnvelope(value: unknown, organizationId: string, invitationId: string): Readonly<{ requestId: string; invitation: OrganizationInvitation }> {
  if (!isRecord(value) || !hasExactKeys(value, ["request_id", "invitation"]) || typeof value.request_id !== "string" || !UUID.test(value.request_id) || !isRecord(value.invitation)) throw invalidResponse("Invitation response is invalid");
  return Object.freeze({ requestId: value.request_id.toLowerCase(), invitation: parseInvitation(value.invitation, organizationId, invitationId) });
}

function parseInvitationCreated(value: unknown, organizationId: string): Readonly<{ requestId: string; invitation: OrganizationInvitation; oneTimeToken: string }> {
  if (!isRecord(value) || !hasExactKeys(value, ["request_id", "invitation", "one_time_token"]) || typeof value.request_id !== "string" || !UUID.test(value.request_id) || typeof value.one_time_token !== "string" || !TOKEN.test(value.one_time_token) || !isRecord(value.invitation)) throw invalidResponse("Invitation creation response is invalid");
  return Object.freeze({ requestId: value.request_id.toLowerCase(), invitation: parseInvitation(value.invitation, organizationId), oneTimeToken: value.one_time_token });
}

function parseInvitationAccepted(value: unknown): Readonly<{ requestId: string; member: OrganizationMember }> {
  if (!isRecord(value) || !hasExactKeys(value, ["request_id", "member"]) || typeof value.request_id !== "string" || !UUID.test(value.request_id) || !isRecord(value.member)) throw invalidResponse("Invitation acceptance response is invalid");
  const member = parseMember(value.member);
  return Object.freeze({ requestId: value.request_id.toLowerCase(), member });
}

function parsePage<T>(value: unknown, key: string, parseItem: (value: unknown) => T): Page<T> {
  if (!isRecord(value) || !hasAllowedKeys(value, ["request_id", key, "next_cursor"]) || typeof value.request_id !== "string" || !UUID.test(value.request_id) || !Array.isArray(value[key]) || value[key].length > 100 || value.next_cursor !== undefined && value.next_cursor !== null && (typeof value.next_cursor !== "string" || !CURSOR.test(value.next_cursor))) throw invalidResponse("Organization list response is invalid");
  const nextCursor: string | null = value.next_cursor === undefined || value.next_cursor === null ? null : value.next_cursor as string;
  return Object.freeze({ items: Object.freeze(value[key].map((item) => parseItem(item))), nextCursor, requestId: value.request_id.toLowerCase() });
}

function parseOrganization(value: unknown, expectedId?: string): Organization {
  if (!isRecord(value) || !hasExactKeys(value, ["organization_id", "name", "version", "created_at", "updated_at"]) || typeof value.organization_id !== "string" || !UUID.test(value.organization_id) || expectedId !== undefined && value.organization_id.toLowerCase() !== expectedId || !isName(value.name) || !isVersion(value.version) || !isDateTime(value.created_at) || !isDateTime(value.updated_at)) throw invalidResponse("Organization record is invalid");
  return Object.freeze({ id: value.organization_id.toLowerCase(), name: value.name, version: value.version, createdAt: value.created_at, updatedAt: value.updated_at });
}

function parseMember(value: unknown, expectedOrganizationId?: string, expectedMemberId?: string): OrganizationMember {
  if (!isRecord(value) || !hasAllowedKeys(value, ["membership_id", "organization_id", "member_id", "display_name", "role", "status", "version", "created_at", "updated_at"]) || typeof value.membership_id !== "string" || !UUID.test(value.membership_id) || typeof value.organization_id !== "string" || !UUID.test(value.organization_id) || typeof value.member_id !== "string" || !UUID.test(value.member_id) || expectedOrganizationId !== undefined && value.organization_id.toLowerCase() !== expectedOrganizationId || expectedMemberId !== undefined && value.member_id.toLowerCase() !== expectedMemberId || value.display_name !== undefined && value.display_name !== null && !isName(value.display_name) || !isRole(value.role) || (value.status !== "active" && value.status !== "revoked") || !isVersion(value.version) || !isDateTime(value.created_at) || !isDateTime(value.updated_at)) throw invalidResponse("Member record is invalid");
  const displayName: string | null = value.display_name === undefined || value.display_name === null ? null : value.display_name as string;
  return Object.freeze({ membershipId: value.membership_id.toLowerCase(), organizationId: value.organization_id.toLowerCase(), memberId: value.member_id.toLowerCase(), displayName, role: value.role, status: value.status, version: value.version, createdAt: value.created_at, updatedAt: value.updated_at });
}

function parseInvitation(value: unknown, expectedOrganizationId?: string, expectedInvitationId?: string): OrganizationInvitation {
  if (!isRecord(value) || !hasAllowedKeys(value, ["invitation_id", "organization_id", "role", "status", "version", "created_at", "expires_at", "accepted_at", "accepted_member_id"]) || typeof value.invitation_id !== "string" || !UUID.test(value.invitation_id) || typeof value.organization_id !== "string" || !UUID.test(value.organization_id) || expectedOrganizationId !== undefined && value.organization_id.toLowerCase() !== expectedOrganizationId || expectedInvitationId !== undefined && value.invitation_id.toLowerCase() !== expectedInvitationId || !isInviteRole(value.role) || !["pending", "accepted", "revoked", "expired"].includes(String(value.status)) || !isVersion(value.version) || !isDateTime(value.created_at) || !isDateTime(value.expires_at) || value.accepted_at !== undefined && !isNullableDateTime(value.accepted_at) || value.accepted_member_id !== undefined && value.accepted_member_id !== null && (typeof value.accepted_member_id !== "string" || !UUID.test(value.accepted_member_id))) throw invalidResponse("Invitation record is invalid");
  const acceptedAt: string | null = value.accepted_at === undefined || value.accepted_at === null ? null : value.accepted_at as string;
  return Object.freeze({ id: value.invitation_id.toLowerCase(), organizationId: value.organization_id.toLowerCase(), role: value.role, status: value.status as InvitationStatus, version: value.version, createdAt: value.created_at, expiresAt: value.expires_at, acceptedAt, acceptedMemberId: value.accepted_member_id === undefined || value.accepted_member_id === null ? null : String(value.accepted_member_id).toLowerCase() });
}

function requiredUuid(value: unknown, field: string): string { if (typeof value !== "string" || !UUID.test(value)) throw new OrganizationClientError("validation_failed", `${field} is invalid`); return value.toLowerCase(); }
function requiredName(value: unknown): string { if (!isName(value)) throw new OrganizationClientError("validation_failed", "name is invalid"); return value; }
function requiredVersion(value: unknown): number { if (!isVersion(value)) throw new OrganizationClientError("validation_failed", "expectedVersion is invalid"); return value; }
function requiredRole(value: unknown): OrganizationRole { if (!isRole(value)) throw new OrganizationClientError("validation_failed", "role is invalid"); return value; }
function requiredInviteRole(value: unknown): InvitationRole { if (!isInviteRole(value)) throw new OrganizationClientError("validation_failed", "invitation role is invalid"); return value; }
function requiredDate(value: unknown, field: string): string { if (!isDateTime(value)) throw new OrganizationClientError("validation_failed", `${field} is invalid`); return value; }
function requiredToken(value: unknown): string { if (typeof value !== "string" || !TOKEN.test(value)) throw new OrganizationClientError("validation_failed", "oneTimeToken is invalid"); return value; }
function assertRole(value: unknown): asserts value is OrganizationRole { if (!isRole(value)) throw new OrganizationClientError("validation_failed", "role is invalid"); }
function assertIdempotencyKey(value: unknown): asserts value is string { if (typeof value !== "string" || !IDempotency.test(value)) throw new OrganizationClientError("validation_failed", "idempotencyKey is invalid"); }
function makeIdempotencyKey(): string { const value = globalThis.crypto?.randomUUID?.(); if (typeof value !== "string" || !IDempotency.test(value)) throw new OrganizationClientError("transport_failed", "Idempotency key generation is unavailable"); return value; }
function isRole(value: unknown): value is OrganizationRole { return typeof value === "string" && (ROLES as readonly string[]).includes(value); }
function isInviteRole(value: unknown): value is InvitationRole { return typeof value === "string" && (INVITE_ROLES as readonly string[]).includes(value); }
function isName(value: unknown): value is string { return typeof value === "string" && value.length >= 1 && value.length <= 128 && value.trim() === value && !hasControl(value); }
function isVersion(value: unknown): value is number { return typeof value === "number" && Number.isSafeInteger(value) && value >= 1; }
function isDateTime(value: unknown): value is string { return typeof value === "string" && value.length <= 64 && ISO_DATE_TIME.test(value) && Number.isFinite(Date.parse(value)); }
function isNullableDateTime(value: unknown): value is string | null { return value === null || isDateTime(value); }
function hasControl(value: string): boolean { for (const character of value) { const code = character.codePointAt(0) ?? 0; if (code <= 0x1f || code === 0x7f) return true; } return false; }
function hasExactKeys(value: Record<string, unknown>, expected: string[]): boolean { const actual = Object.keys(value).sort(); const keys = [...expected].sort(); return actual.length === keys.length && actual.every((key, index) => key === keys[index]); }
function hasAllowedKeys(value: Record<string, unknown>, allowed: string[]): boolean { return Object.keys(value).every((key) => allowed.includes(key)); }
function isRecord(value: unknown): value is Record<string, unknown> { return Boolean(value) && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function invalidResponse(message: string, status?: number): OrganizationClientError { return new OrganizationClientError("invalid_response", message, status); }
