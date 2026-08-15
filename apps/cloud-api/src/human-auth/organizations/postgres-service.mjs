import { createHash, randomBytes as nodeRandomBytes, randomUUID as nodeRandomUUID } from "node:crypto";

const DEFAULT_PAGE_SIZE = 50;
const MAX_PAGE_SIZE = 100;
const MAX_CURSOR_LENGTH = 512;
const MAX_IDEMPOTENCY_KEY_LENGTH = 255;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._~-]{8,255}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const CURSOR = /^[A-Za-z0-9_-]+$/u;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u;
const ROLES = new Set(["owner", "admin", "auditor", "viewer"]);
const INVITABLE_ROLES = new Set(["admin", "auditor", "viewer"]);
const SECRET_FIELDS = new Set(["token_hash", "raw_token", "one_time_token", "invitation_token"]);
const SECRET_FIELD_NAMES = new Set(["assertion", "bearer", "credentialkey", "csrftoken", "invitationtoken", "onetimetoken", "password", "privatekey", "publickey", "rawtoken", "secret", "sessiontoken", "token", "tokenhash"]);

export const ORGANIZATION_SERVICE_ERROR_CODES = Object.freeze({
  INVALID_INPUT: "invalid_input",
  NOT_FOUND: "not_found",
  MEMBER_NOT_FOUND: "member_not_found",
  INVITATION_NOT_FOUND: "invitation_not_found",
  FORBIDDEN: "forbidden",
  VERSION_CONFLICT: "version_conflict",
  STALE_SESSION: "stale_session",
  IDEMPOTENCY_CONFLICT: "idempotency_conflict",
  INVITATION_REPLAYED: "invitation_replayed",
  UNAVAILABLE: "organization_service_unavailable"
});

const ERROR_MESSAGES = Object.freeze({
  [ORGANIZATION_SERVICE_ERROR_CODES.INVALID_INPUT]: "The organization input is invalid",
  [ORGANIZATION_SERVICE_ERROR_CODES.NOT_FOUND]: "The organization resource was not found",
  [ORGANIZATION_SERVICE_ERROR_CODES.MEMBER_NOT_FOUND]: "The organization member was not found",
  [ORGANIZATION_SERVICE_ERROR_CODES.INVITATION_NOT_FOUND]: "The invitation was not found",
  [ORGANIZATION_SERVICE_ERROR_CODES.FORBIDDEN]: "The organization operation is not allowed",
  [ORGANIZATION_SERVICE_ERROR_CODES.VERSION_CONFLICT]: "The organization resource was changed by another request",
  [ORGANIZATION_SERVICE_ERROR_CODES.IDEMPOTENCY_CONFLICT]: "The idempotency key conflicts with another request",
  [ORGANIZATION_SERVICE_ERROR_CODES.INVITATION_REPLAYED]: "The invitation token is no longer valid",
  [ORGANIZATION_SERVICE_ERROR_CODES.UNAVAILABLE]: "The organization service is unavailable"
});

export class OrganizationServiceError extends Error {
  constructor(code, reason = undefined) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[ORGANIZATION_SERVICE_ERROR_CODES.UNAVAILABLE]);
    this.name = "OrganizationServiceError";
    this.code = ERROR_MESSAGES[code] === undefined ? ORGANIZATION_SERVICE_ERROR_CODES.UNAVAILABLE : code;
    if (reason !== undefined) this.reason = reason;
  }
}

/**
 * Adapts the PostgreSQL organization repository to the HTTP organization
 * service contract. The repository remains responsible for authorization,
 * transactions, and idempotency replay.
 */
export function createPostgresOrganizationService({
  repository,
  cursorCodec,
  now = () => new Date().toISOString(),
  randomBytes = nodeRandomBytes,
  randomUUID = nodeRandomUUID
} = {}) {
  assertRepository(repository);
  if (cursorCodec !== undefined) assertCursorCodec(cursorCodec);
  if (typeof now !== "function") throw new TypeError("now must be a function");
  if (typeof randomBytes !== "function") throw new TypeError("randomBytes must be a function");
  if (typeof randomUUID !== "function") throw new TypeError("randomUUID must be a function");

  return Object.freeze({
    listOrganizations,
    createOrganization,
    renameOrganization,
    listMembers,
    updateMemberRole,
    removeMember,
    listInvitations,
    createInvitation,
    revokeInvitation,
    reissueInvitation,
    acceptInvitation
  });

  async function listOrganizations(input = {}) {
    const actor = requiredActor(input);
    const pageInput = pagination(input);
    const cursorPosition = decodeCursor(pageInput.cursor, actor, cursorCodec, "organizations");
    const records = await invoke("listOrganizationsForMember", {
      member_id: actor.member_id,
      limit: pageInput.limit,
      ...(cursorPosition ? { after_created_at: cursorPosition.created_at, after_id: cursorPosition.id } : {}),
      // Keep the raw cursor for legacy constructor tests and non-production
      // adapters. The production runtime always supplies cursorCodec.
      ...(cursorCodec === undefined && pageInput.cursor !== undefined ? { cursor: pageInput.cursor } : {})
    }, ORGANIZATION_SERVICE_ERROR_CODES.NOT_FOUND);
    return page(records, pageInput.limit, "organizations", { actor, cursorCodec });
  }

  async function createOrganization(input = {}) {
    const actor = requiredActor(input);
    const idempotency_key = idempotencyKey(input.idempotency_key);
    const result = await invoke("createOrganizationWithOwner", {
      owner_member_id: actor.member_id,
      actor_member_id: actor.member_id,
      name: input.name,
      created_at: currentTimestamp(),
      idempotency_key
    }, ORGANIZATION_SERVICE_ERROR_CODES.NOT_FOUND);
    return sanitize(result);
  }

  async function renameOrganization(input = {}) {
    const actor = requiredActor(input);
    const idempotency_key = idempotencyKey(input.idempotency_key);
    const expected_version = requiredVersion(input.expected_version);
    const result = await invoke("renameOrganization", {
      organization_id: requiredOrganizationId(input.organization_id),
      actor_member_id: actor.member_id,
      name: input.name,
      expected_version,
      idempotency_key
    }, ORGANIZATION_SERVICE_ERROR_CODES.NOT_FOUND);
    return sanitize(result);
  }

  async function listMembers(input = {}) {
    const actor = requiredActor(input);
    const organization_id = requiredOrganizationId(input.organization_id);
    const pageInput = pagination(input);
    const cursorPosition = decodeCursor(pageInput.cursor, actor, cursorCodec, "members");
    const records = await invoke("listMembers", {
      organization_id,
      actor_member_id: actor.member_id,
      limit: pageInput.limit,
      ...(cursorPosition ? { after_created_at: cursorPosition.created_at, after_id: cursorPosition.id } : {}),
      ...(cursorCodec === undefined && pageInput.cursor !== undefined ? { cursor: pageInput.cursor } : {})
    }, ORGANIZATION_SERVICE_ERROR_CODES.MEMBER_NOT_FOUND);
    return page(records, pageInput.limit, "members", { actor, cursorCodec });
  }

  async function updateMemberRole(input = {}) {
    const actor = requiredActor(input);
    const idempotency_key = idempotencyKey(input.idempotency_key);
    const role = requiredRole(input.role);
    const expected_version = requiredVersion(input.expected_version);
    const recentAuthorization = optionalRecentAuthorization(input.recent_authorization, actor);
    const result = await invoke("updateMemberRole", {
      organization_id: requiredOrganizationId(input.organization_id),
      actor_member_id: actor.member_id,
      actor_session_id: actor.session_id,
      member_id: requiredMemberId(input.member_id),
      role,
      expected_version,
      revoked_at: currentTimestamp(),
      ...(recentAuthorization ? {
        recent_auth_challenge_id: recentAuthorization.challenge_id,
        recent_auth_operation: recentAuthorization.operation,
        recent_auth_authenticated_at: recentAuthorization.authenticated_at
      } : {}),
      idempotency_key
    }, ORGANIZATION_SERVICE_ERROR_CODES.MEMBER_NOT_FOUND);
    return sanitize(result);
  }

  async function removeMember(input = {}) {
    const actor = requiredActor(input);
    const idempotency_key = idempotencyKey(input.idempotency_key);
    const expected_version = requiredVersion(input.expected_version);
    const recentAuthorization = optionalRecentAuthorization(input.recent_authorization, actor);
    const result = await invoke("removeMember", {
      organization_id: requiredOrganizationId(input.organization_id),
      actor_member_id: actor.member_id,
      actor_session_id: actor.session_id,
      member_id: requiredMemberId(input.member_id),
      expected_version,
      removed_at: currentTimestamp(),
      ...(recentAuthorization ? {
        recent_auth_challenge_id: recentAuthorization.challenge_id,
        recent_auth_operation: recentAuthorization.operation,
        recent_auth_authenticated_at: recentAuthorization.authenticated_at
      } : {}),
      idempotency_key
    }, ORGANIZATION_SERVICE_ERROR_CODES.MEMBER_NOT_FOUND);
    return sanitize(result);
  }

  async function listInvitations(input = {}) {
    const actor = requiredActor(input);
    const organization_id = requiredOrganizationId(input.organization_id);
    const pageInput = pagination(input);
    const cursorPosition = decodeCursor(pageInput.cursor, actor, cursorCodec, "invitations");
    const records = await invoke("listInvitations", {
      organization_id,
      actor_member_id: actor.member_id,
      limit: pageInput.limit,
      ...(cursorPosition ? { after_created_at: cursorPosition.created_at, after_id: cursorPosition.id } : {}),
      ...(cursorCodec === undefined && pageInput.cursor !== undefined ? { cursor: pageInput.cursor } : {})
    }, ORGANIZATION_SERVICE_ERROR_CODES.INVITATION_NOT_FOUND);
    return page(records, pageInput.limit, "invitations", { actor, cursorCodec });
  }

  async function createInvitation(input = {}) {
    const actor = requiredActor(input);
    const idempotency_key = idempotencyKey(input.idempotency_key);
    const role = requiredInvitableRole(input.role);
    const created_at = currentTimestamp();
    const raw_token = generateToken(randomBytes);
    const result = await invoke("createInvitation", {
      organization_id: requiredOrganizationId(input.organization_id),
      actor_member_id: actor.member_id,
      invitation_id: generatedUuid(randomUUID),
      role,
      token_hash: hashToken(raw_token),
      expires_at: input.expires_at,
      created_at,
      idempotency_key
    }, ORGANIZATION_SERVICE_ERROR_CODES.NOT_FOUND);
    const invitation = sanitize(unwrapInvitation(result));
    if (isReplay(result)) return Object.freeze({ invitation: reconcileReplayInvitation(invitation, created_at), replayed: true });
    return Object.freeze({ invitation, raw_token });
  }

  async function revokeInvitation(input = {}) {
    const actor = requiredActor(input);
    const idempotency_key = idempotencyKey(input.idempotency_key);
    const expected_version = requiredVersion(input.expected_version);
    const result = await invoke("revokeInvitation", {
      organization_id: requiredOrganizationId(input.organization_id),
      actor_member_id: actor.member_id,
      invitation_id: requiredInvitationId(input.invitation_id),
      expected_version,
      revoked_at: currentTimestamp(),
      idempotency_key
    }, ORGANIZATION_SERVICE_ERROR_CODES.INVITATION_NOT_FOUND);
    return sanitize(result);
  }

  async function reissueInvitation(input = {}) {
    const actor = requiredActor(input);
    const idempotency_key = idempotencyKey(input.idempotency_key);
    const expected_version = requiredVersion(input.expected_version);
    const recentAuthorization = requiredRecentAuthorization(input.recent_authorization, actor);
    const reissued_at = currentTimestamp();
    const expires_at = futureTimestamp(input.expires_at, reissued_at);
    const raw_token = generateToken(randomBytes);
    const result = await invoke("reissueInvitation", {
      organization_id: requiredOrganizationId(input.organization_id),
      actor_member_id: actor.member_id,
      actor_session_id: actor.session_id,
      invitation_id: requiredInvitationId(input.invitation_id),
      token_hash: hashToken(raw_token),
      expires_at,
      reissued_at,
      expected_version,
      recent_auth_challenge_id: recentAuthorization.challenge_id,
      recent_auth_operation: recentAuthorization.operation,
      recent_auth_authenticated_at: recentAuthorization.authenticated_at,
      idempotency_key
    }, ORGANIZATION_SERVICE_ERROR_CODES.INVITATION_NOT_FOUND);
    const invitation = sanitize(unwrapInvitation(result));
    if (isReplay(result)) return Object.freeze({ invitation: reconcileReplayInvitation(invitation, reissued_at), replayed: true });
    return Object.freeze({ invitation, raw_token });
  }

  async function acceptInvitation(input = {}) {
    const actor = requiredActor(input);
    const idempotency_key = idempotencyKey(input.idempotency_key);
    const one_time_token = requiredToken(input.one_time_token);
    const result = await invoke("acceptInvitation", {
      token_hash: hashToken(one_time_token),
      actor_member_id: actor.member_id,
      organization_id: actor.organization_id,
      accepted_at: currentTimestamp(),
      idempotency_key
    }, ORGANIZATION_SERVICE_ERROR_CODES.INVITATION_REPLAYED);
    return sanitize(result);
  }

  async function invoke(method, input, nullCode) {
    let result;
    try {
      result = await repository[method](input);
    } catch (error) {
      throw mapRepositoryError(error);
    }
    if (result === null || result === undefined) throw serviceError(nullCode);
    return result;
  }

  function currentTimestamp() {
    let value;
    try { value = now(); }
    catch (error) { throw error instanceof OrganizationServiceError ? error : serviceError(ORGANIZATION_SERVICE_ERROR_CODES.UNAVAILABLE); }
    if (value instanceof Date) {
      if (!Number.isFinite(value.getTime())) throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.INVALID_INPUT);
      return value.toISOString();
    }
    if (Number.isSafeInteger(value) && value >= 0) {
      const date = new Date(value);
      if (!Number.isFinite(date.getTime())) throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.INVALID_INPUT);
      return date.toISOString();
    }
    if (typeof value === "string" && RFC3339.test(value) && Number.isFinite(Date.parse(value))) return value;
    throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.INVALID_INPUT);
  }
}

function assertRepository(repository) {
  const methods = [
    "listOrganizationsForMember", "createOrganizationWithOwner", "renameOrganization", "listMembers",
    "updateMemberRole", "removeMember", "listInvitations", "createInvitation", "revokeInvitation", "reissueInvitation", "acceptInvitation"
  ];
  if (!repository || typeof repository !== "object") throw new TypeError("PostgreSQL organization repository is invalid");
  for (const method of methods) if (typeof repository[method] !== "function") throw new TypeError(`PostgreSQL organization repository is missing ${method}()`);
}

function assertCursorCodec(cursorCodec) {
  if (!cursorCodec || typeof cursorCodec !== "object" || typeof cursorCodec.encode !== "function" || typeof cursorCodec.decode !== "function") {
    throw new TypeError("cursorCodec must expose encode() and decode()");
  }
}

function decodeCursor(cursor, actor, cursorCodec, resource) {
  if (cursor === undefined || cursorCodec === undefined) return undefined;
  try {
    return cursorCodec.decode(cursor, {
      resource,
      tenant_id: actor.organization_id,
      member_id: actor.member_id,
      direction: "asc"
    });
  } catch {
    throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.INVALID_INPUT);
  }
}

function page(records, limit, resource, { actor = undefined, cursorCodec = undefined } = {}) {
  if (records && !Array.isArray(records) && Array.isArray(records.items)) {
    const items = records.items;
    const next_cursor = records.next_cursor ?? null;
    return boundedPage(items, limit, next_cursor, resource, { actor, cursorCodec });
  }
  return boundedPage(records, limit, null, resource, { actor, cursorCodec });
}

function boundedPage(records, limit, next_cursor, resource, { actor = undefined, cursorCodec = undefined } = {}) {
  if (!Array.isArray(records)) throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.UNAVAILABLE);
  if (next_cursor !== null && (typeof next_cursor !== "string" || next_cursor.length < 1 || next_cursor.length > MAX_CURSOR_LENGTH || !CURSOR.test(next_cursor))) {
    throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.UNAVAILABLE);
  }
  const hasMore = next_cursor === null && records.length > limit;
  const items = records.slice(0, limit).map((record) => sanitize(record));
  let pageCursor = next_cursor;
  if (hasMore && cursorCodec !== undefined) {
    const last = items.at(-1);
    try {
      pageCursor = cursorCodec.encode({
        resource,
        tenant_id: actor.organization_id,
        member_id: actor.member_id,
        created_at: last.created_at,
        id: cursorRecordId(last, resource),
        direction: "asc"
      });
    } catch {
      throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.UNAVAILABLE);
    }
  }
  return Object.freeze({ items: Object.freeze(items), next_cursor: pageCursor });
}

function cursorRecordId(record, resource) {
  const value = resource === "organizations" ? record.organization_id
    : resource === "members" ? record.membership_id
      : resource === "invitations" ? record.invitation_id
        : undefined;
  if (typeof value !== "string" || !UUID.test(value)) throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.UNAVAILABLE);
  return value.toLowerCase();
}

function pagination(input) {
  const limit = input.limit === undefined ? DEFAULT_PAGE_SIZE : input.limit;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_PAGE_SIZE) throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.INVALID_INPUT);
  const cursor = input.cursor;
  if (cursor !== undefined && (typeof cursor !== "string" || cursor.length < 1 || cursor.length > MAX_CURSOR_LENGTH || !CURSOR.test(cursor))) {
    throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.INVALID_INPUT);
  }
  return Object.freeze({ limit, ...(cursor === undefined ? {} : { cursor }) });
}

function requiredActor(input) {
  const actor = input?.actor;
  if (!actor || typeof actor !== "object" || Array.isArray(actor) || typeof actor.session_id !== "string" || typeof actor.member_id !== "string" || typeof actor.organization_id !== "string" || !UUID.test(actor.session_id) || !UUID.test(actor.member_id) || !UUID.test(actor.organization_id) || !ROLES.has(actor.role)) {
    throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.INVALID_INPUT);
  }
  return actor;
}

function requiredOrganizationId(value) { return requiredUuid(value, "organization_id"); }
function requiredMemberId(value) { return requiredUuid(value, "member_id"); }
function requiredInvitationId(value) { return requiredUuid(value, "invitation_id"); }
function requiredUuid(value, field) {
  if (typeof value !== "string" || !UUID.test(value)) throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.INVALID_INPUT);
  return value.toLowerCase();
}

function requiredVersion(value) {
  if (!Number.isSafeInteger(value) || value < 1) throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.INVALID_INPUT);
  return value;
}

function requiredRole(value) {
  if (typeof value !== "string" || !ROLES.has(value)) throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.INVALID_INPUT);
  return value;
}

function optionalRecentAuthorization(value, actor) {
  if (value === undefined) return undefined;
  if (!value || typeof value !== "object" || Array.isArray(value)
    || value.session_id !== actor.session_id
    || typeof value.challenge_id !== "string" || !UUID.test(value.challenge_id)
    || typeof value.operation !== "string" || value.operation.length < 1 || value.operation.length > 128
    || !Number.isSafeInteger(value.authenticated_at) || value.authenticated_at < 0) {
    throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.INVALID_INPUT);
  }
  return Object.freeze({
    session_id: value.session_id.toLowerCase(),
    challenge_id: value.challenge_id.toLowerCase(),
    operation: value.operation,
    authenticated_at: value.authenticated_at
  });
}

function requiredRecentAuthorization(value, actor) {
  if (value === undefined) throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.INVALID_INPUT);
  return optionalRecentAuthorization(value, actor);
}

function requiredInvitableRole(value) {
  if (typeof value !== "string" || !INVITABLE_ROLES.has(value)) throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.INVALID_INPUT);
  return value;
}

function futureTimestamp(value, evaluatedAt) {
  if (typeof value !== "string" || !RFC3339.test(value) || !Number.isFinite(Date.parse(value)) || Date.parse(value) <= Date.parse(evaluatedAt)) {
    throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.INVALID_INPUT);
  }
  return value;
}

function reconcileReplayInvitation(invitation, evaluatedAt) {
  if (!invitation || typeof invitation !== "object" || Array.isArray(invitation)) {
    throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.UNAVAILABLE);
  }
  if (!["pending", "expired", "accepted", "revoked"].includes(invitation.status)) {
    throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.UNAVAILABLE);
  }
  if (invitation.status === "accepted" || invitation.status === "revoked") return invitation;
  if (typeof invitation.expires_at !== "string" || !RFC3339.test(invitation.expires_at) || !Number.isFinite(Date.parse(invitation.expires_at))) {
    throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.UNAVAILABLE);
  }
  return { ...invitation, status: Date.parse(invitation.expires_at) <= Date.parse(evaluatedAt) ? "expired" : "pending" };
}

function idempotencyKey(value) {
  if (typeof value !== "string" || value.length > MAX_IDEMPOTENCY_KEY_LENGTH || !IDEMPOTENCY_KEY.test(value)) {
    throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.INVALID_INPUT);
  }
  return value;
}

function requiredToken(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43,512}$/u.test(value)) throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.INVALID_INPUT);
  return value;
}

function generateToken(randomBytes) {
  let bytes;
  try { bytes = randomBytes(32); }
  catch (error) { throw error instanceof OrganizationServiceError ? error : serviceError(ORGANIZATION_SERVICE_ERROR_CODES.UNAVAILABLE); }
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.UNAVAILABLE);
  if (bytes.byteLength !== 32) throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.UNAVAILABLE);
  return Buffer.from(bytes).toString("base64url");
}

function hashToken(value) { return createHash("sha256").update(value, "utf8").digest("hex"); }

function generatedUuid(randomUUID) {
  let value;
  try { value = randomUUID(); }
  catch (error) { throw error instanceof OrganizationServiceError ? error : serviceError(ORGANIZATION_SERVICE_ERROR_CODES.UNAVAILABLE); }
  if (typeof value !== "string" || !UUID.test(value)) throw serviceError(ORGANIZATION_SERVICE_ERROR_CODES.UNAVAILABLE);
  return value.toLowerCase();
}

function unwrapInvitation(result) {
  let candidate = result;
  if (result && typeof result === "object" && !Array.isArray(result)) candidate = result.invitation ?? result.record ?? result.result ?? result;
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return candidate;
  const output = { ...candidate };
  for (const field of ["replayed", "idempotency_replayed", "is_replay", "replay"]) delete output[field];
  return output;
}

function isReplay(result) {
  return Boolean(result && typeof result === "object" && (
    result.replayed === true || result.idempotency_replayed === true || result.is_replay === true || result.replay === true
  ));
}

function sanitize(value) {
  if (Array.isArray(value)) return value.map(sanitize);
  if (!value || typeof value !== "object") return value;
  const result = {};
  for (const [key, item] of Object.entries(value)) {
    const normalizedKey = key.replace(/[-_]/gu, "").toLowerCase();
    if (!SECRET_FIELDS.has(key) && !isSecretFieldName(normalizedKey)) result[key] = sanitize(item);
  }
  return result;
}

function isSecretFieldName(normalizedKey) {
  return SECRET_FIELD_NAMES.has(normalizedKey)
    || /(?:token|secret|password|credential|privatekey|publickey|apikey|accesskey)$/u.test(normalizedKey)
    || /^(?:secret|password)/u.test(normalizedKey);
}

function mapRepositoryError(error) {
  if (error instanceof OrganizationServiceError) return error;
  const code = String(error?.code ?? error?.name ?? "").toLowerCase();
  if (["invalid_input", "invalid_scope", "tenant_scope_error"].includes(code) || error instanceof TypeError) return serviceError(ORGANIZATION_SERVICE_ERROR_CODES.INVALID_INPUT);
  if (["last_owner", "err_last_owner", "owner_constraint", "cannot_remove_owner"].includes(code)) return serviceError(ORGANIZATION_SERVICE_ERROR_CODES.FORBIDDEN, "last_owner");
  if (["role_not_allowed", "err_role_not_allowed", "role_downgrade_forbidden"].includes(code)) return serviceError(ORGANIZATION_SERVICE_ERROR_CODES.FORBIDDEN, "role_not_allowed");
  if (["forbidden", "err_forbidden", "not_authorized", "owner_required", "err_actor"].includes(code)) return serviceError(ORGANIZATION_SERVICE_ERROR_CODES.FORBIDDEN);
  if (["stale_session", "err_stale_session", "actor_session_required", "err_actor_session_required"].includes(code)) return serviceError(ORGANIZATION_SERVICE_ERROR_CODES.STALE_SESSION, "stale_session");
  if (["version_conflict", "err_version_conflict", "expected_version_mismatch", "stale_version"].includes(code)) return serviceError(ORGANIZATION_SERVICE_ERROR_CODES.VERSION_CONFLICT);
  if (["idempotency_conflict", "err_idempotency_conflict", "idempotency_key_reused"].includes(code)) return serviceError(ORGANIZATION_SERVICE_ERROR_CODES.IDEMPOTENCY_CONFLICT);
  if (["invitation_replayed", "err_invitation_replayed", "invitation_token_replayed", "token_replayed", "already_used", "invitation_expired"].includes(code)) return serviceError(ORGANIZATION_SERVICE_ERROR_CODES.INVITATION_REPLAYED);
  if (["member_not_found", "err_member_not_found", "membership_not_found", "err_membership_not_found"].includes(code)) return serviceError(ORGANIZATION_SERVICE_ERROR_CODES.MEMBER_NOT_FOUND);
  if (["invitation_not_found"].includes(code)) return serviceError(ORGANIZATION_SERVICE_ERROR_CODES.INVITATION_NOT_FOUND);
  if (["not_found", "organization_not_found", "resource_not_found", "tenant_not_found"].includes(code)) return serviceError(ORGANIZATION_SERVICE_ERROR_CODES.NOT_FOUND);
  return serviceError(ORGANIZATION_SERVICE_ERROR_CODES.UNAVAILABLE);
}

function serviceError(code, reason = undefined) { return new OrganizationServiceError(code, reason); }

export default createPostgresOrganizationService;
