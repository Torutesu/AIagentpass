import { canonicalDigest } from "../../../../packages/small-software-contracts/src/index.mjs";
import { SmallSoftwareError, SMALL_SOFTWARE_ERROR_CODES } from "./errors.mjs";
import { smallSoftwareAuthorizationRepository, smallSoftwareClock, smallSoftwareUuid, isTestOnlyDependency } from "./interfaces.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const IDEMPOTENCY = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,255}$/u;
const ROLES = Object.freeze(["owner", "admin", "member", "viewer"]);
const ROLE_RANK = Object.freeze({ viewer: 1, member: 2, admin: 3, owner: 4 });
const ACTION_MINIMUM = Object.freeze({
  read: "viewer", open: "viewer", view: "viewer", invoke: "member", write: "member",
  manage_access: "admin", share: "admin", invite: "admin", revoke: "admin",
  approve: "owner", activate: "owner", suspend: "owner", rollback: "owner", delete: "owner",
});
const MAX_LIFETIME_SECONDS = 60 * 60 * 24 * 31;
const SECRET_FIELD = /(secret|token|password|private.?key|api.?key|authorization|cookie|credential|assertion)/iu;
const fail = (code, details) => { throw new SmallSoftwareError(code, details); };

/**
 * Provider-neutral app authorization boundary.
 *
 * The repository is the authority for membership, access rules, invitations,
 * routes and shares. This module only accepts public identity/session metadata
 * (never cookies, bearer material or WebAuthn assertions), and never calls a
 * runtime provider. A public share id is a non-secret locator: it is revocable
 * and expiry-bound, and contains no access token or embedded authority.
 */
export function createSmallSoftwareAuthorizationService({ repository, clock, uuid, origin = "https://share.agentpass.app", profile = "hosted" } = {}) {
  if (!["hosted", "test"].includes(profile) || !clock || typeof clock.now !== "function" || !uuid || typeof uuid.randomUUID !== "function") fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_CONFIGURATION);
  if (profile === "hosted" && [repository, clock, uuid].some(isTestOnlyDependency)) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_CONFIGURATION);
  const repo = smallSoftwareAuthorizationRepository(repository);
  const time = smallSoftwareClock(clock);
  const ids = smallSoftwareUuid(uuid);
  assertOrigin(origin);

  return Object.freeze({
    getRole: (input) => getRole(input),
    authorizeRoute: (input) => authorizeRoute(input),
    authorize: (input) => authorizeRoute(input),
    grantAccess: (input) => grantAccess(input),
    createAccessRule: (input) => grantAccess(input),
    invite: (input) => invite(input),
    createInvitation: (input) => invite(input),
    acceptInvitation: (input) => acceptInvitation(input),
    revokeAccess: (input) => revokeAccess(input),
    revokeInvitation: (input) => revokeInvitation(input),
    createShareLink: (input) => createShareLink(input),
    createShare: (input) => createShareLink(input),
    revokeShareLink: (input) => revokeShareLink(input),
    revokeShare: (input) => revokeShareLink(input),
  });

  async function getRole(input = {}) {
    const request = normalizeIdentityRequest(input);
    const app = await application(request);
    if (app.lifecycle_state && !["active", "private_preview"].includes(app.lifecycle_state)) return null;
    const rules = await accessRules(request);
    return effectiveRole(app, rules, request.member_id, time.now());
  }

  async function authorizeRoute(input = {}) {
    const request = normalizeRouteRequest(input);
    let app;
    try { app = await application(request); }
    catch (error) { if (error?.code === SMALL_SOFTWARE_ERROR_CODES.NOT_FOUND) return denied(SMALL_SOFTWARE_ERROR_CODES.FORBIDDEN, "tenant_or_app_mismatch"); throw error; }
    if (!["active", "private_preview"].includes(app.lifecycle_state ?? "active")) return denied(SMALL_SOFTWARE_ERROR_CODES.FORBIDDEN, "app_inactive");
    let share;
    if (request.share_id !== undefined) {
      share = await getShare(request.share_id);
      if (!share || share.organization_id !== request.organization_id || share.app_id !== request.app_id || share.route !== request.route || share.state !== "active" || expired(share.expires_at, time.now())) return denied(SMALL_SOFTWARE_ERROR_CODES.SHARE_REVOKED, "share_inactive");
    }
    const route = await callRepo("getRoute", request);
    if (!route || route.organization_id !== request.organization_id || route.app_id !== request.app_id || route.route !== request.route || route.state !== "active") return denied(SMALL_SOFTWARE_ERROR_CODES.FORBIDDEN, "route_inactive");
    const requiredRole = ACTION_MINIMUM[request.action] ?? "viewer";
    if (!request.member_id) {
      if (!share?.public_access) return denied(SMALL_SOFTWARE_ERROR_CODES.AUTHENTICATION_REQUIRED, "session_required");
      if (requiredRole !== "viewer") return denied(SMALL_SOFTWARE_ERROR_CODES.FORBIDDEN, "anonymous_read_only");
      return Object.freeze({ allowed: true, anonymous: true, role: "viewer", required_role: requiredRole, organization_id: request.organization_id, app_id: request.app_id, route: request.route, ...(share ? { share_id: share.share_id } : {}) });
    }
    const rules = await accessRules(request);
    const role = effectiveRole(app, rules, request.member_id, time.now());
    if (!role || ROLE_RANK[role] < ROLE_RANK[requiredRole]) return denied(SMALL_SOFTWARE_ERROR_CODES.FORBIDDEN, "insufficient_role");
    return Object.freeze({ allowed: true, anonymous: false, role, required_role: requiredRole, organization_id: request.organization_id, app_id: request.app_id, member_id: request.member_id, route: request.route, ...(share ? { share_id: share.share_id } : {}) });
  }

  async function grantAccess(input = {}) {
    const request = normalizeMutation(input, ["member_id", "role"]);
    const role = assertRole(request.role);
    const actor = await actorRole(request);
    if (ROLE_RANK[actor] < ROLE_RANK.admin || (role === "owner" && actor !== "owner")) fail(SMALL_SOFTWARE_ERROR_CODES.FORBIDDEN, "grant_not_allowed");
    const digest = requestDigest("grant", request, { member_id: request.member_id, role });
    const replay = await idempotent(request, digest);
    if (replay) return replay;
    const rules = await accessRules(request);
    const existing = findMemberRule(rules, request.member_id);
    if (existing && existing.state === "active" && existing.app_role === role) return commit(request, digest, projection(existing, request, role), "grant");
    if (existing && existing.state === "active" && existing.app_role === "owner" && role !== "owner") fail(SMALL_SOFTWARE_ERROR_CODES.ROLE_CONFLICT, "owner_downgrade");
    const value = await callRepo("saveAccessRule", {
      id: existing?.id ?? ids.randomUUID(), organization_id: request.organization_id, app_id: request.app_id,
      subject_kind: "member", subject_id: request.member_id, member_id: request.member_id, app_role: role,
      state: "active", created_by_member_id: request.actor_member_id, created_at: time.now(),
    });
    return commit(request, digest, projection(value ?? { id: existing?.id, app_role: role, state: "active" }, request, role), "grant");
  }

  async function invite(input = {}) {
    const request = normalizeMutation(input, ["member_id", "role"]);
    const role = assertRole(request.role);
    const actor = await actorRole(request);
    if (ROLE_RANK[actor] < ROLE_RANK.admin || (role === "owner" && actor !== "owner")) fail(SMALL_SOFTWARE_ERROR_CODES.FORBIDDEN, "invite_not_allowed");
    const digest = requestDigest("invite", request, { member_id: request.member_id, role });
    const replay = await idempotent(request, digest);
    if (replay) return replay;
    const invitation = await callRepo("saveInvitation", {
      invitation_id: ids.randomUUID(), organization_id: request.organization_id, app_id: request.app_id,
      invited_member_id: request.member_id, member_id: request.member_id, role, state: "pending",
      created_by_member_id: request.actor_member_id, created_at: time.now(),
      ...(request.expires_at ? { expires_at: request.expires_at } : {}),
    });
    const result = invitationProjection(invitation ?? {}, request, role);
    return commit(request, digest, result, "invite");
  }

  async function acceptInvitation(input = {}) {
    const request = normalizeMutation(input, ["invitation_id"]);
    const invitationId = request.invitation_id;
    const invitation = await callRepo("getInvitation", { organization_id: request.organization_id, app_id: request.app_id, invitation_id: invitationId });
    if (!invitation || invitation.organization_id !== request.organization_id || invitation.app_id !== request.app_id) fail(SMALL_SOFTWARE_ERROR_CODES.NOT_FOUND);
    if (invitation.invited_member_id !== request.actor_member_id && invitation.member_id !== request.actor_member_id) fail(SMALL_SOFTWARE_ERROR_CODES.FORBIDDEN, "invitation_recipient");
    if (invitation.state !== "pending" || expired(invitation.expires_at, time.now())) fail(SMALL_SOFTWARE_ERROR_CODES.INVITATION_REVOKED);
    const digest = requestDigest("accept", request, { invitation_id: invitationId });
    const replay = await idempotent(request, digest);
    if (replay) return replay;
    const role = assertRole(invitation.role ?? invitation.app_role);
    const rule = await callRepo("saveAccessRule", {
      id: ids.randomUUID(), organization_id: request.organization_id, app_id: request.app_id,
      subject_kind: "member", subject_id: request.actor_member_id, member_id: request.actor_member_id,
      app_role: role, state: "active", created_by_member_id: request.actor_member_id, created_at: time.now(),
    });
    await callRepo("saveInvitation", { ...invitation, state: "accepted", accepted_at: time.now() });
    return commit(request, digest, Object.freeze({ invitation_id: invitationId, access_rule_id: rule?.id ?? undefined, state: "accepted", role, organization_id: request.organization_id, app_id: request.app_id, member_id: request.actor_member_id }), "accept");
  }

  async function revokeAccess(input = {}) {
    const request = normalizeMutation(input, ["member_id"]);
    const actor = await actorRole(request);
    if (ROLE_RANK[actor] < ROLE_RANK.admin) fail(SMALL_SOFTWARE_ERROR_CODES.FORBIDDEN, "revoke_not_allowed");
    const digest = requestDigest("revoke", request, { member_id: request.member_id });
    const replay = await idempotent(request, digest);
    if (replay) return replay;
    const rules = await accessRules(request);
    const existing = findMemberRule(rules, request.member_id);
    if (!existing || existing.state === "revoked") return commit(request, digest, Object.freeze({ organization_id: request.organization_id, app_id: request.app_id, member_id: request.member_id, state: "revoked" }), "revoke");
    if (existing.app_role === "owner") fail(SMALL_SOFTWARE_ERROR_CODES.ROLE_CONFLICT, "owner_revoke");
    const owners = [request.actor_member_id, ...rules.filter((x) => x.state === "active" && (x.app_role === "owner" || x.role === "owner")).map((x) => x.member_id ?? x.subject_id)];
    if (owners.filter(Boolean).length < 1) fail(SMALL_SOFTWARE_ERROR_CODES.ROLE_CONFLICT, "last_owner");
    await callRepo("revokeAccessRule", { organization_id: request.organization_id, app_id: request.app_id, rule_id: existing.id, member_id: request.member_id, revoked_by_member_id: request.actor_member_id, revoked_at: time.now() });
    return commit(request, digest, Object.freeze({ id: existing.id, organization_id: request.organization_id, app_id: request.app_id, member_id: request.member_id, state: "revoked" }), "revoke");
  }

  async function revokeInvitation(input = {}) {
    const request = normalizeMutation(input, ["invitation_id"]);
    const actor = await actorRole(request);
    if (ROLE_RANK[actor] < ROLE_RANK.admin) fail(SMALL_SOFTWARE_ERROR_CODES.FORBIDDEN, "revoke_invitation_not_allowed");
    const digest = requestDigest("revoke_invitation", request, { invitation_id: request.invitation_id });
    const replay = await idempotent(request, digest);
    if (replay) return replay;
    await callRepo("revokeInvitation", { organization_id: request.organization_id, app_id: request.app_id, invitation_id: request.invitation_id, revoked_by_member_id: request.actor_member_id, revoked_at: time.now() });
    return commit(request, digest, Object.freeze({ invitation_id: request.invitation_id, organization_id: request.organization_id, app_id: request.app_id, state: "revoked" }), "revoke_invitation");
  }

  async function createShareLink(input = {}) {
    const request = normalizeMutation(input, ["route"]);
    const actor = await actorRole(request);
    if (ROLE_RANK[actor] < ROLE_RANK.admin) fail(SMALL_SOFTWARE_ERROR_CODES.FORBIDDEN, "share_not_allowed");
    const route = await callRepo("getRoute", request);
    if (!route || route.organization_id !== request.organization_id || route.app_id !== request.app_id || route.route !== request.route || route.state !== "active") fail(SMALL_SOFTWARE_ERROR_CODES.FORBIDDEN, "route_inactive");
    const seconds = input.lifetime_seconds === undefined ? 86400 : input.lifetime_seconds;
    if (!Number.isSafeInteger(seconds) || seconds < 1 || seconds > MAX_LIFETIME_SECONDS) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT, "share_lifetime");
    const digest = requestDigest("share", request, { route: request.route, lifetime_seconds: seconds, public_access: input.public_access !== false });
    const replay = await idempotent(request, digest);
    if (replay) return replay;
    const shareId = ids.randomUUID();
    const created = time.now();
    const expiresAt = new Date(Date.parse(created) + seconds * 1000).toISOString();
    if (input.public_access !== undefined && typeof input.public_access !== "boolean") fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT, "public_access");
    const value = await callRepo("saveShare", { share_id: shareId, organization_id: request.organization_id, app_id: request.app_id, route: request.route, state: "active", public_access: input.public_access !== false, created_by_member_id: request.actor_member_id, created_at: created, expires_at: expiresAt });
    const result = shareProjection(value ?? { share_id: shareId, organization_id: request.organization_id, app_id: request.app_id, route: request.route, state: "active", public_access: input.public_access !== false, created_at: created, expires_at: expiresAt }, origin);
    return commit(request, digest, result, "share");
  }

  async function revokeShareLink(input = {}) {
    const request = normalizeMutation(input, ["share_id"]);
    const actor = await actorRole(request);
    if (ROLE_RANK[actor] < ROLE_RANK.admin) fail(SMALL_SOFTWARE_ERROR_CODES.FORBIDDEN, "revoke_share_not_allowed");
    const digest = requestDigest("revoke_share", request, { share_id: request.share_id });
    const replay = await idempotent(request, digest);
    if (replay) return replay;
    const share = await getShare(request.share_id);
    if (!share || share.organization_id !== request.organization_id || share.app_id !== request.app_id) fail(SMALL_SOFTWARE_ERROR_CODES.NOT_FOUND);
    await callRepo("revokeShare", { organization_id: request.organization_id, app_id: request.app_id, share_id: request.share_id, revoked_by_member_id: request.actor_member_id, revoked_at: time.now() });
    return commit(request, digest, Object.freeze({ share_id: request.share_id, organization_id: request.organization_id, app_id: request.app_id, state: "revoked" }), "revoke_share");
  }

  async function actorRole(request) {
    const role = await getRole({ organization_id: request.organization_id, app_id: request.app_id, member_id: request.actor_member_id });
    if (!role) fail(SMALL_SOFTWARE_ERROR_CODES.FORBIDDEN, "actor_not_app_member");
    return role;
  }
  async function application(request) {
    const app = await callRepo("getApplication", { organization_id: request.organization_id, app_id: request.app_id });
    if (!app || app.organization_id !== request.organization_id || app.id !== undefined && app.id !== request.app_id) fail(SMALL_SOFTWARE_ERROR_CODES.NOT_FOUND);
    return app;
  }
  async function accessRules(request) {
    const rows = await callRepo("listAccessRules", { organization_id: request.organization_id, app_id: request.app_id });
    if (!Array.isArray(rows)) return [];
    return rows.filter((row) => row && row.organization_id === request.organization_id && (row.app_id === undefined || row.app_id === request.app_id));
  }
  async function getShare(shareId) { return callRepo("getShare", { share_id: shareId }); }
  async function idempotent(request, digest) {
    const row = await callRepo("getAuthorizationOperation", { organization_id: request.organization_id, app_id: request.app_id, actor_member_id: request.actor_member_id, idempotency_key: request.idempotency_key });
    if (!row) return null;
    if (row.request_digest !== digest) fail(SMALL_SOFTWARE_ERROR_CODES.IDEMPOTENCY_CONFLICT, { field: "idempotency_key" });
    return row.result ?? row.response ?? row;
  }
  async function commit(request, digest, result, operation) {
    const value = Object.freeze({ operation, request_digest: digest, result });
    await callRepo("saveAuthorizationOperation", { organization_id: request.organization_id, app_id: request.app_id, actor_member_id: request.actor_member_id, idempotency_key: request.idempotency_key, request_digest: digest, operation, result });
    return result;
  }
  async function callRepo(method, value) { try { return await repo[method](value); } catch { fail(SMALL_SOFTWARE_ERROR_CODES.DEPENDENCY_UNAVAILABLE); } }
}

function normalizeIdentityRequest(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT);
  rejectSecrets(input);
  const organization_id = uuid(input.organization_id), app_id = uuid(input.app_id), member_id = uuid(input.member_id);
  return { ...input, organization_id, app_id, member_id };
}
function normalizeMutation(input, fields) {
  if (!input || typeof input !== "object" || Array.isArray(input)) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT);
  rejectSecrets(input);
  const organization_id = uuid(input.organization_id), app_id = uuid(input.app_id), actor_member_id = uuid(input.actor_member_id);
  if (typeof input.idempotency_key !== "string" || !IDEMPOTENCY.test(input.idempotency_key)) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT, "idempotency_key");
  const value = { ...input, organization_id, app_id, actor_member_id, idempotency_key: input.idempotency_key };
  for (const field of fields) {
    if (field.endsWith("_id")) value[field] = uuid(input[field]);
    else if (typeof input[field] !== "string" || input[field].length === 0 || input[field].length > 256 || /[\u0000-\u001f\u007f]/u.test(input[field])) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT, field);
  }
  if (input.lifetime_seconds !== undefined && (!Number.isSafeInteger(input.lifetime_seconds) || input.lifetime_seconds < 1 || input.lifetime_seconds > MAX_LIFETIME_SECONDS)) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT, "lifetime_seconds");
  if (input.expires_at !== undefined && (typeof input.expires_at !== "string" || !Number.isFinite(Date.parse(input.expires_at)))) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT, "expires_at");
  return value;
}
function normalizeRouteRequest(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT);
  rejectSecrets(input);
  const value = { ...input, organization_id: uuid(input.organization_id), app_id: uuid(input.app_id) };
  if (input.member_id !== undefined) value.member_id = uuid(input.member_id);
  if (typeof input.route !== "string" || !/^(?:\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{1,255}|[A-Za-z0-9][A-Za-z0-9._:-]{0,255})$/u.test(input.route)) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT, "route");
  const action = input.action ?? "read";
  if (typeof action !== "string" || !ACTION_MINIMUM[action]) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT, "action");
  if (input.share_id !== undefined) value.share_id = uuid(input.share_id);
  value.route = input.route; value.action = action;
  return value;
}
function uuid(value) { if (typeof value !== "string" || !UUID.test(value)) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT, "identity"); return value; }
function assertRole(role) { if (!ROLES.includes(role)) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT, "role"); return role; }
function assertOrigin(value) { try { const url = new URL(value); if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash) throw new Error(); } catch { fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_CONFIGURATION, "origin"); } }
function rejectSecrets(value) { if (!value || typeof value !== "object") return; for (const [key, child] of Object.entries(value)) { if (SECRET_FIELD.test(key)) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT, "secret_like_input"); if (child && typeof child === "object") rejectSecrets(child); } }
function effectiveRole(app, rules, memberId, organizationId) {
  if (app.owner_member_id === memberId) return "owner";
  const eligible = rules.filter((row) => row.state === "active" && !expired(row.expires_at) && ((row.subject_kind === "member" || row.member_id) && (row.subject_id === memberId || row.member_id === memberId) || row.subject_kind === "organization"));
  return eligible.map((row) => row.app_role ?? row.role).filter((role) => ROLES.includes(role)).sort((a, b) => ROLE_RANK[b] - ROLE_RANK[a])[0] ?? null;
}
function findMemberRule(rules, memberId) { return rules.find((row) => row.state !== "expired" && row.state !== "revoked" && ((row.subject_id ?? row.member_id) === memberId)); }
function expired(value, now = undefined) { return value !== undefined && value !== null && Date.parse(value) <= (now ? Date.parse(now) : Date.now()); }
function requestDigest(operation, request, extra) { return canonicalDigest({ operation, organization_id: request.organization_id, app_id: request.app_id, actor_member_id: request.actor_member_id, idempotency_key: request.idempotency_key, ...extra }); }
function projection(value, request, role) { return Object.freeze({ access_rule_id: value?.id, organization_id: request.organization_id, app_id: request.app_id, member_id: request.member_id, role, state: "active" }); }
function invitationProjection(value, request, role) { return Object.freeze({ invitation_id: value.invitation_id ?? value.id, organization_id: request.organization_id, app_id: request.app_id, member_id: request.member_id, role, state: "pending", ...(value.expires_at ? { expires_at: value.expires_at } : {}) }); }
function shareProjection(value, shareOrigin = "https://share.agentpass.app") { return Object.freeze({ share_id: value.share_id ?? value.id, organization_id: value.organization_id, app_id: value.app_id, route: value.route, state: value.state, public_access: value.public_access === true, created_at: value.created_at, expires_at: value.expires_at, share_url: `${shareOrigin}/share/${value.share_id ?? value.id}` }); }
function denied(code, reason) { return Object.freeze({ allowed: false, code, reason }); }

export const SMALL_SOFTWARE_APP_ROLES = ROLES;
export const SMALL_SOFTWARE_ROUTE_ACTIONS = Object.freeze(Object.keys(ACTION_MINIMUM));
export const createSmallSoftwareAccessService = createSmallSoftwareAuthorizationService;
export const createSmallSoftwareAuthService = createSmallSoftwareAuthorizationService;
