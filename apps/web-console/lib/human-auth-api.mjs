import { assertCompactIdentityAssertion, createIdentityAssertionSigner, IDENTITY_ASSERTION_HEADER } from "./identity-assertion.mjs";

const MAX_BODY_BYTES = 128 * 1024;
const MAX_RESPONSE_BYTES = 256 * 1024;
const DEFAULT_TIMEOUT_MS = 8_000;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const OPAQUE_TOKEN = /^[A-Za-z0-9_-]{43}$/;
const SESSION_COOKIE_NAME = "__Host-agentpass_session";
const RECENT_AUTH_CONTEXT_HEADER = "agentpass-recent-auth-context";
const SESSION_KEYS = Object.freeze(["version", "session_id", "member_id", "organization_id", "role", "created_at", "expires_at", "recent_auth_at"]);
const SESSION_ROLES = new Set(["owner", "admin", "auditor", "viewer"]);
const ROUTES = new Map([
  ["/api/auth/session", Object.freeze({ cloudPath: "/api/auth/session", methods: ["POST", "DELETE"], session: "bootstrap", bodies: { POST: "session-bootstrap", DELETE: "none" }, requireSetCookie: true, delete: Object.freeze({ session: "human", requireCookie: true, requireCsrf: true, allowSetCookie: true, clearCookieOnly: true, requireClearedSessionBody: true }) })],
  ["/api/auth/session/resume", Object.freeze({ cloudPath: "/api/auth/session/resume", methods: ["POST"], session: "resume", body: "session-resume", requireCookie: true, forwardSessionCookie: true, allowSetCookie: true, allowClearedSessionCookieOnError: true, requireSetCookie: true, normalizeSessionResponse: true })],
  ["/api/auth/session/organization-switch", Object.freeze({ cloudPath: "/api/auth/session/organization-switch", methods: ["POST"], session: "human", body: "organization-switch", requireCookie: true, requireCsrf: true, forwardSessionCookie: true, allowSetCookie: true, requireSetCookie: true, normalizeSessionResponse: true })],
  ["/api/auth/webauthn/options", Object.freeze({ cloudPath: "/api/auth/webauthn/options", session: "human", requireCookie: true, requireCsrf: true })],
  ["/api/auth/webauthn/verify", Object.freeze({ cloudPath: "/api/auth/webauthn/verify", session: "human", requireCookie: true, requireCsrf: true })],
  ["/api/auth/webauthn/registration/options", Object.freeze({ cloudPath: "/api/auth/webauthn/registration/options", session: "human", requireCookie: true, requireCsrf: true, allowRecentAuth: true })],
  ["/api/auth/webauthn/registration/verify", Object.freeze({ cloudPath: "/api/auth/webauthn/registration/verify", session: "human", requireCookie: true, requireCsrf: true, allowRecentAuth: true })],
  ["/api/auth/security/passkeys", Object.freeze({ cloudPath: "/api/auth/management/credentials", session: "human", methods: ["GET"], requireCookie: true, requireCsrf: true, body: "none" })],
  ["/api/auth/security/sessions", Object.freeze({ cloudPath: "/api/auth/management/sessions", session: "human", methods: ["GET"], requireCookie: true, requireCsrf: true, body: "none" })],
  ["/api/auth/security/sessions/revoke-others", Object.freeze({ cloudPath: "/api/auth/management/sessions/revoke-others", session: "human", methods: ["POST"], requireCookie: true, requireCsrf: true, requireRecentAuth: true, body: "empty" })],
]);

export class HumanAuthBridgeError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "HumanAuthBridgeError";
    this.status = status;
    this.code = code;
  }
}

export function createHumanAuthBridge(options = {}) {
  return Object.freeze({ handle: (request) => handleHumanAuthRequest(request, options) });
}

export async function handleHumanAuthRequest(request, options = {}) {
  try {
    const url = new URL(request.url);
    let route = resolveRoute(url.pathname);
    if (!route || url.hash) fail(404, "not_found", "Resource not found");
    if (!(route.methods ?? ["POST"]).includes(request.method)) {
      return json(405, { error: { code: "method_not_allowed", message: "Method not allowed" } }, { allow: (route.methods ?? ["POST"]).join(", ") });
    }
    if (url.search && !(route.queryMethods ?? []).includes(request.method)) fail(400, "invalid_request", "The request query is invalid");
    const query = (route.queryMethods ?? []).includes(request.method) ? normalizeListQuery(url.searchParams) : "";
    if (route.delete && request.method === "DELETE") route = { ...route, ...route.delete };
    route = { ...route, session: route.session ?? "human", cloudPath: `${route.cloudPath}${query}`, body: route.bodies?.[request.method] ?? route.body, requireIdempotency: route.requireIdempotency === true || (route.idempotencyMethods ?? []).includes(request.method) };
    const origin = request.headers.get("origin");
    if (origin !== url.origin || origin === "null") fail(403, "origin_not_allowed", "The request origin is not allowed");

    const config = readConfig(options.env, { bootstrap: route.session === "bootstrap" });
    if (route.session === "bootstrap" && config.origin !== undefined && origin !== config.origin) fail(403, "origin_not_allowed", "The request origin is not allowed");
    const user = route.session === "bootstrap" ? await requireBootstrapUser(request, options, config) : undefined;
    const body = route.body === "none" ? await readNoBody(request) : await readBody(request, route);
    if (route.body === "invitation-create" && isInvitationReissueBody(body)) {
      route = { ...route, requireRecentAuth: true, requireIfMatch: true };
    }
    const fetchImpl = options.fetchImpl ?? options.fetch ?? globalThis.fetch;
    if (typeof fetchImpl !== "function") fail(503, "cloud_api_unavailable", "Cloud API is unavailable");

    const headers = new Headers({
      accept: "application/json",
      "cache-control": "no-store",
      "content-type": "application/json",
      origin,
      pragma: "no-cache",
    });
    const cookie = normalizeSessionCookie(request.headers.get("cookie"), { required: route.requireCookie === true });
    if ((route.session === "human" || route.forwardSessionCookie === true) && cookie !== null) headers.set("cookie", cookie);
    let upstreamBody = body;
    if (route.body === "session-resume") upstreamBody = new TextEncoder().encode("{}");
    if (route.session === "bootstrap" && user !== undefined) {
      if (config.mode === "legacy") {
        headers.set("authorization", `Bearer ${config.token}`);
        headers.set("agentpass-console-user-id", user.userId);
      } else {
        const signer = options.signIdentityAssertion ?? createIdentityAssertionSigner(config.assertion);
        const compact = await signer.sign({
          subject: user.userId,
          organizationId: config.organizationId,
          origin,
          now: options.now?.() ?? Date.now(),
        });
        assertCompactIdentityAssertion(compact, { now: options.now?.() ?? Date.now(), expected: config.assertion });
        headers.set(IDENTITY_ASSERTION_HEADER, compact);
        // The assertion is transport metadata. The Cloud session endpoint has
        // one exact request body for this flow and never parses browser data.
        upstreamBody = new TextEncoder().encode("{}");
      }
    }
    const csrf = request.headers.get("agentpass-csrf");
    if (route.requireCsrf) {
      if (!isOpaqueToken(csrf)) fail(403, "csrf_required", "CSRF authentication is required");
      headers.set("agentpass-csrf", csrf);
    }
    const recentAuth = request.headers.get("agentpass-recent-auth");
    if (route.requireRecentAuth && recentAuth === null) fail(401, "recent_auth_required", "Recent WebAuthn authentication is required");
    if (recentAuth !== null) {
      if (!(route.requireRecentAuth || route.allowRecentAuth) || !isUuid(recentAuth)) fail(400, "invalid_recent_auth", "Recent WebAuthn authentication is invalid");
      headers.set("agentpass-recent-auth", recentAuth.toLowerCase());
    }
    const recentAuthContext = request.headers.get(RECENT_AUTH_CONTEXT_HEADER);
    if (route.requireRecentAuthContext && (recentAuthContext === null || !isContextHash(recentAuthContext))) fail(401, "recent_auth_failed", "Recent WebAuthn context is invalid");
    if (!route.requireRecentAuthContext && recentAuthContext !== null) fail(400, "invalid_recent_auth_context", "Recent WebAuthn context is not allowed");
    if (recentAuthContext !== null) headers.set(RECENT_AUTH_CONTEXT_HEADER, recentAuthContext.toLowerCase());
    const idempotencyKey = request.headers.get("idempotency-key");
    if (route.requireIdempotency && !isIdempotencyKey(idempotencyKey)) fail(400, "idempotency_required", "A valid Idempotency-Key is required");
    if (!route.requireIdempotency && idempotencyKey !== null) fail(400, "invalid_idempotency", "The Idempotency-Key is not allowed");
    if (idempotencyKey !== null) headers.set("idempotency-key", idempotencyKey);
    const ifMatch = request.headers.get("if-match");
    if (route.requireIfMatch && ifMatch === null) fail(400, "if_match_required", "A valid If-Match is required");
    if (ifMatch !== null) {
      if (!(route.allowIfMatch || route.requireIfMatch) || !isIfMatch(ifMatch)) fail(400, "invalid_if_match", "If-Match is not allowed or invalid");
      headers.set("if-match", ifMatch);
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), config.timeoutMs);
    let upstream;
    try {
      const init = {
        method: "POST",
        headers,
        cache: "no-store",
        redirect: "error",
        signal: controller.signal,
      };
      init.method = request.method;
      if (upstreamBody !== undefined) init.body = upstreamBody;
      upstream = await fetchImpl(new URL(route.cloudPath, config.url), init);
    } catch {
      fail(503, "cloud_api_unavailable", "Cloud API is unavailable");
    } finally {
      clearTimeout(timeout);
    }
    return await relayResponse(upstream, { allowSetCookie: route.session === "bootstrap" || route.allowSetCookie === true, allowClearedSessionCookieOnError: route.allowClearedSessionCookieOnError === true, clearCookieOnly: route.clearCookieOnly === true, requireSetCookie: route.requireSetCookie === true, requireClearedSessionBody: route.requireClearedSessionBody === true, bootstrap: route.session === "bootstrap", normalizeSessionResponse: route.normalizeSessionResponse === true, passkeyMutation: route.passkeyMutation });
  } catch (error) {
    const mapped = error instanceof HumanAuthBridgeError
      ? error
      : new HumanAuthBridgeError(500, "human_auth_bridge_failed", "Authentication is unavailable");
    return json(mapped.status, { error: { code: mapped.code, message: mapped.message } }, mapped.status === 405 ? { allow: "POST" } : undefined);
  }
}

async function requireBootstrapUser(request, options, config) {
  const getUser = options.getSiwcUser ?? options.getUser;
  if (typeof getUser !== "function") fail(503, "identity_unavailable", "Identity verification is unavailable");
  let user;
  try { user = await getUser(request); } catch { fail(401, "authentication_required", "Authentication is required"); }
  if (!user || typeof user.userId !== "string" || !ID.test(user.userId)) fail(401, "authentication_required", "Authentication is required");
  if (config.mode === "legacy" && !config.operatorUserIds.has(user.userId)) fail(403, "operator_access_denied", "Operator access is denied");
  return user;
}

async function readBody(request, route = {}) {
  const type = request.headers.get("content-type") ?? "";
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(type)) fail(415, "unsupported_media_type", "Content-Type must be application/json");
  const declared = request.headers.get("content-length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAX_BODY_BYTES)) fail(413, "request_too_large", "Request body is too large");
  let bytes;
  try { bytes = new Uint8Array(await request.arrayBuffer()); } catch { fail(400, "invalid_request", "The authentication request is invalid"); }
  if (bytes.byteLength < 2 || bytes.byteLength > MAX_BODY_BYTES) fail(bytes.byteLength > MAX_BODY_BYTES ? 413 : 400, bytes.byteLength > MAX_BODY_BYTES ? "request_too_large" : "invalid_request", bytes.byteLength > MAX_BODY_BYTES ? "Request body is too large" : "The authentication request is invalid");
  let value;
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch { fail(400, "invalid_request", "The authentication request is invalid"); }
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(400, "invalid_request", "The authentication request is invalid");
  validateBody(value, route.body);
  return bytes;
}

async function readNoBody(request) {
  const declared = request.headers.get("content-length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) !== 0)) fail(400, "invalid_request", "The request body is invalid");
  let bytes;
  try { bytes = new Uint8Array(await request.arrayBuffer()); } catch { fail(400, "invalid_request", "The request body is invalid"); }
  if (bytes.byteLength !== 0) fail(400, "invalid_request", "The request body is invalid");
  return undefined;
}

function validateBody(value, shape) {
  if (!shape) return;
  if (shape === "session-bootstrap") {
    if (!isExactObject(value, [])) fail(400, "invalid_request", "The session request is invalid");
    return;
  }
  if (shape === "session-resume") {
    if (!isExactObject(value, [])) fail(400, "invalid_request", "The session request is invalid");
    return;
  }
  if (shape === "organization-switch") {
    if (!isExactObject(value, ["organization_id"]) || !isUuid(value.organization_id)) fail(400, "invalid_request", "The session request is invalid");
    return;
  }
  if (shape === "empty") {
    if (!isExactObject(value, [])) fail(400, "invalid_request", "The security request is invalid");
    return;
  }
  if (shape === "rename-passkey") {
    if (!isExactObject(value, ["label"]) || !isSafeLabel(value.label)) {
      fail(400, "invalid_request", "The security request is invalid");
    }
    return;
  }
  if (shape === "version") {
    if (!isExactObject(value, ["expected_version"]) || !isVersion(value.expected_version)) fail(400, "invalid_request", "The security request is invalid");
    return;
  }
  if (shape === "organization-create") {
    if (!isExactObject(value, ["name"]) || !isSafeName(value.name)) fail(400, "invalid_request", "The organization request is invalid");
    return;
  }
  if (shape === "organization-rename") {
    if (!isExactObject(value, ["name"]) || !isSafeName(value.name)) fail(400, "invalid_request", "The organization request is invalid");
    return;
  }
  if (shape === "member-role") {
    if (!isExactObject(value, ["role"]) || !["owner", "admin", "auditor", "viewer"].includes(value.role)) fail(400, "invalid_request", "The organization request is invalid");
    return;
  }
  if (shape === "invitation-create") {
    const create = isExactObject(value, ["role", "expires_at"])
      && ["admin", "auditor", "viewer"].includes(value.role)
      && isRfc3339(value.expires_at);
    const reissue = isExactObject(value, ["reissue_invitation_id", "expires_at"])
      && isUuid(value.reissue_invitation_id)
      && isRfc3339(value.expires_at);
    if (!create && !reissue) fail(400, "invalid_request", "The invitation request is invalid");
    return;
  }
  if (shape === "invitation-accept") {
    if (!isExactObject(value, ["one_time_token"]) || !isOpaqueInvitationToken(value.one_time_token)) fail(400, "invalid_request", "The invitation request is invalid");
    return;
  }
  if (shape === "recovery-outbox-suppress") {
    if (!isExactObject(value, ["reason"]) || !isSafeReason(value.reason)) fail(400, "invalid_request", "The recovery outbox request is invalid");
    return;
  }
  fail(500, "human_auth_bridge_failed", "Authentication is unavailable");
}

function isInvitationReissueBody(bytes) {
  if (!(bytes instanceof Uint8Array)) return false;
  try {
    const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    return Boolean(value && typeof value === "object" && !Array.isArray(value) && Object.hasOwn(value, "reissue_invitation_id"));
  } catch {
    return false;
  }
}

async function relayResponse(response, { allowSetCookie = false, allowClearedSessionCookieOnError = false, clearCookieOnly = false, requireSetCookie = false, requireClearedSessionBody = false, bootstrap = false, normalizeSessionResponse = false, passkeyMutation = undefined } = {}) {
  if (!response || typeof response.status !== "number" || response.status < 200 || response.status > 599 || (response.status >= 300 && response.status < 400)) fail(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  const type = response.headers?.get("content-type") ?? "";
  if (!/^application\/json(?:\s*;|\s*$)/i.test(type)) fail(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAX_RESPONSE_BYTES)) fail(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength > MAX_RESPONSE_BYTES) fail(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  let value;
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch { fail(502, "cloud_api_invalid_response", "Cloud API response was invalid"); }
  if (bootstrap || normalizeSessionResponse) value = normalizeBootstrapResponse(value, response.status >= 200 && response.status < 300);
  if (passkeyMutation !== undefined && response.status >= 200 && response.status < 300) validatePasskeyMutationResponse(value, passkeyMutation);
  if (requireClearedSessionBody && (response.status < 200 || response.status >= 300 || !isExactObject(value, ["session"]) || value.session !== null)) fail(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  const headers = new Headers({ "content-type": "application/json; charset=utf-8", "cache-control": "no-store, max-age=0", pragma: "no-cache", expires: "0", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer" });
  // Preserve the already-public bounded Cloud error code in a response header
  // so browser qualification can classify a 5xx without consuming the body.
  const errorCode = value?.error?.code;
  if (response.status >= 400 && typeof errorCode === "string" && /^[a-z][a-z0-9_]{0,127}$/u.test(errorCode)) headers.set("x-agentpass-error-code", errorCode);
  const setCookie = response.headers.get("set-cookie");
  if (setCookie !== null && !allowSetCookie) fail(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  if (requireSetCookie && response.status >= 200 && response.status < 300 && setCookie === null) fail(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  if (allowSetCookie && setCookie !== null) {
    const clearCookiePattern = /^__Host-agentpass_session=; Path=\/; HttpOnly; Secure; SameSite=Strict; Max-Age=0$/;
    const sessionCookiePattern = /^__Host-agentpass_session=[A-Za-z0-9_-]{43}; Path=\/; HttpOnly; Secure; SameSite=Strict(?:; Max-Age=(?:0|[1-9]\d*))?$/;
    const cookiePattern = clearCookieOnly ? clearCookiePattern : sessionCookiePattern;
    const clearedOnError = allowClearedSessionCookieOnError && response.status >= 400 && clearCookiePattern.test(setCookie);
    if (!cookiePattern.test(setCookie) && !clearedOnError) fail(502, "cloud_api_invalid_response", "Cloud API response was invalid");
    headers.set("set-cookie", setCookie);
  }
  return new Response(JSON.stringify(value), { status: response.status, headers });
}

function validatePasskeyMutationResponse(value, mutation) {
  if (!isExactObject(value, ["credential"]) || !isExactObject(value.credential, ["credential_id", "version", "label", "transports", "backup_eligible", "backup_state", "status", "created_at", "last_used_at", "revoked_at"])) fail(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  const credential = value.credential;
  if (credential.credential_id !== mutation.id || !isCredentialId(credential.credential_id) || !isVersion(credential.version) || !isSafeManagementLabel(credential.label) || !Array.isArray(credential.transports) || credential.transports.length > 7 || new Set(credential.transports).size !== credential.transports.length || credential.transports.some((item) => !["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"].includes(item)) || typeof credential.backup_eligible !== "boolean" || typeof credential.backup_state !== "boolean" || (credential.backup_state && !credential.backup_eligible) || credential.status !== (mutation.kind === "revoke" ? "revoked" : "active") || !isRfc3339(credential.created_at) || !isNullableRfc3339(credential.last_used_at) || !isNullableRfc3339(credential.revoked_at) || mutation.kind === "revoke" && credential.revoked_at === null || mutation.kind === "rename" && credential.revoked_at !== null) {
    fail(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  }
}

function isSafeManagementLabel(value) { return typeof value === "string" && value.length >= 1 && value.length <= 128 && value.trim() === value && !hasControl(value); }
function isNullableRfc3339(value) { return value === null || isRfc3339(value); }

function normalizeBootstrapResponse(value, success) {
  if (!success) {
    const exactError = isExactObject(value, ["error"]);
    const cloudError = isExactObject(value, ["error", "request_id"]) && isUuid(value.request_id);
    if ((!exactError && !cloudError) || !isExactObject(value.error, ["code", "message"]) || typeof value.error.code !== "string" || typeof value.error.message !== "string" || value.error.code.length > 128 || value.error.message.length > 512 || hasControl(value.error.code) || hasControl(value.error.message)) fail(502, "cloud_api_invalid_response", "Cloud API response was invalid");
    return { error: { code: value.error.code, message: value.error.message } };
  }
  if (!isExactObject(value, ["session", "csrf_token"]) || !isExactObject(value.session, SESSION_KEYS)) fail(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  const session = value.session;
  if (session.version !== 1 || !isUuid(session.session_id) || !isUuid(session.member_id) || !isUuid(session.organization_id) || !SESSION_ROLES.has(session.role) || !isRfc3339(session.created_at) || !isRfc3339(session.expires_at) || (session.recent_auth_at !== null && !isRfc3339(session.recent_auth_at)) || !isOpaqueToken(value.csrf_token)) {
    fail(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  }
  return { session: { ...session }, csrf_token: value.csrf_token };
}

function isConfiguredOrigin(value) {
  if (typeof value !== "string" || value.length === 0 || value.endsWith("/") || value === "null") return false;
  try {
    const url = new URL(value);
    return url.origin === value && (url.protocol === "https:" || (url.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(url.hostname))) && !url.username && !url.password && !url.search && !url.hash;
  } catch {
    return false;
  }
}

function readConfig(injected, { bootstrap = false } = {}) {
  const source = injected ?? (typeof process === "undefined" ? undefined : process.env);
  const urlValue = source?.AGENTPASS_CLOUD_API_URL;
  const legacy = bootstrap && source?.AGENTPASS_ALLOW_LEGACY_SESSION_BOOTSTRAP === "true" && ["development", "test"].includes(source?.NODE_ENV);
  const token = legacy ? source?.AGENTPASS_CLOUD_TOKEN : undefined;
  const operators = legacy && typeof source?.AGENTPASS_OPERATOR_USER_IDS === "string" ? source.AGENTPASS_OPERATOR_USER_IDS.split(",").map((item) => item.trim()).filter(Boolean) : [];
  let url;
  try { url = new URL(urlValue); } catch { fail(503, "cloud_api_unavailable", "Cloud API is unavailable"); }
  const insecureLoopback = source?.AGENTPASS_ALLOW_INSECURE_LOOPBACK_CLOUD_API === "true" && url.protocol === "http:" && ["127.0.0.1", "::1", "localhost"].includes(url.hostname);
  if ((url.protocol !== "https:" && !insecureLoopback) || url.username || url.password || url.search || url.hash || url.pathname !== "/") fail(503, "cloud_api_unavailable", "Cloud API is unavailable");
  const rawTimeout = source?.AGENTPASS_CLOUD_TIMEOUT_MS;
  const timeoutMs = typeof rawTimeout === "string" && /^\d+$/.test(rawTimeout) ? Math.max(1000, Math.min(30_000, Number(rawTimeout))) : DEFAULT_TIMEOUT_MS;
  if (bootstrap && legacy) {
    if (typeof token !== "string" || token.length < 1 || token.length > 8192 || hasControl(token) || operators.length < 1 || operators.length > 100 || new Set(operators).size !== operators.length || operators.some((item) => !ID.test(item))) fail(503, "cloud_api_unavailable", "Cloud API is unavailable");
    return { url, mode: "legacy", token, operatorUserIds: new Set(operators), timeoutMs };
  }
  if (bootstrap) {
    const organizationId = source?.AGENTPASS_ORGANIZATION_ID;
    const consoleOrigin = source?.AGENTPASS_CONSOLE_ORIGIN;
    if (!isUuid(organizationId) || !isConfiguredOrigin(consoleOrigin)) fail(503, "identity_unavailable", "Identity verification is unavailable");
    const assertion = {
      privateKeyPem: source?.AGENTPASS_IDENTITY_ASSERTION_PRIVATE_KEY,
      issuer: source?.AGENTPASS_IDENTITY_ASSERTION_ISSUER,
      audience: source?.AGENTPASS_IDENTITY_ASSERTION_AUDIENCE,
      keyId: source?.AGENTPASS_IDENTITY_ASSERTION_KID,
      provider: source?.AGENTPASS_IDENTITY_PROVIDER ?? "chatgpt",
    };
    try { createIdentityAssertionSigner(assertion); } catch { fail(503, "identity_unavailable", "Identity verification is unavailable"); }
    return { url, mode: "assertion", organizationId: organizationId.toLowerCase(), origin: consoleOrigin, assertion, timeoutMs };
  }
  return { url, timeoutMs };
}

function json(status, body, extra) {
  const headers = new Headers({ "content-type": "application/json; charset=utf-8", "cache-control": "no-store, max-age=0", pragma: "no-cache", "x-content-type-options": "nosniff", ...(extra ?? {}) });
  return new Response(JSON.stringify(body), { status, headers });
}

function hasControl(value) {
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}
function normalizeSessionCookie(cookie, { required = false } = {}) {
  if (cookie === null) {
    if (required) fail(401, "session_required", "An active session is required");
    return null;
  }
  if (typeof cookie !== "string" || cookie.length < 1 || cookie.length > 8192 || hasControl(cookie)) fail(400, "invalid_cookie", "The session cookie is invalid");
  let token;
  for (const part of cookie.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 1) {
      if (part.trim() !== "") fail(400, "invalid_cookie", "The session cookie is invalid");
      continue;
    }
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (name !== SESSION_COOKIE_NAME) continue;
    if (token !== undefined || !isOpaqueToken(value)) fail(400, "invalid_cookie", "The session cookie is invalid");
    token = value;
  }
  if (token === undefined) {
    if (required) fail(401, "session_required", "An active session is required");
    return null;
  }
  return `${SESSION_COOKIE_NAME}=${token}`;
}
function isOpaqueToken(value) { return typeof value === "string" && OPAQUE_TOKEN.test(value); }
function resolveRoute(pathname) {
  const exact = ROUTES.get(pathname);
  if (exact) return exact;
  const organizationRoute = resolveOrganizationRoute(pathname);
  if (organizationRoute) return organizationRoute;
  const match = /^\/api\/auth\/security\/(passkeys|sessions)\/([^/]+)(?:\/(revoke))?$/.exec(pathname);
  if (!match) return undefined;
  let id;
  try { id = decodeURIComponent(match[2]); } catch { return undefined; }
  if (id !== match[2]) return undefined;
  if (match[1] === "passkeys" && isCredentialId(id) && !match[3]) return { cloudPath: `/api/auth/management/credentials/${id}`, methods: ["PATCH"], requireCookie: true, requireCsrf: true, requireIdempotency: true, requireIfMatch: true, body: "rename-passkey", passkeyMutation: { kind: "rename", id } };
  if (match[1] === "passkeys" && isCredentialId(id) && match[3]) return { cloudPath: `/api/auth/management/credentials/${id}/revoke`, methods: ["POST"], requireCookie: true, requireCsrf: true, requireIdempotency: true, requireIfMatch: true, requireRecentAuth: true, requireRecentAuthContext: true, body: "empty", passkeyMutation: { kind: "revoke", id } };
  if (match[1] === "sessions" && isUuid(id) && match[3]) return { cloudPath: `/api/auth/management/sessions/${id.toLowerCase()}/revoke`, methods: ["POST"], requireCookie: true, requireCsrf: true, allowRecentAuth: true, body: "version", allowIfMatch: true, allowSetCookie: true, clearCookieOnly: true };
  return undefined;
}
function resolveOrganizationRoute(pathname) {
  if (pathname === "/api/auth/organizations") return { cloudPath: pathname, methods: ["GET", "POST"], queryMethods: ["GET"], idempotencyMethods: ["POST"], bodies: { GET: "none", POST: "organization-create" }, requireCookie: true, requireCsrf: true };
  if (pathname === "/api/auth/invitations/accept") return { cloudPath: pathname, methods: ["POST"], body: "invitation-accept", requireCookie: true, requireCsrf: true, requireIdempotency: true };
  const segments = pathname.split("/");
  if (segments.length < 5 || segments[1] !== "api" || segments[2] !== "auth" || segments[3] !== "organizations" || !isUuid(segments[4])) return undefined;
  const organizationId = segments[4].toLowerCase();
  if (segments.length === 5) return { cloudPath: `/api/auth/organizations/${organizationId}`, methods: ["PATCH"], body: "organization-rename", requireCookie: true, requireCsrf: true, requireIdempotency: true, requireIfMatch: true };
  if (segments[5] === "recovery-outbox" && segments[6] === "dead-letters") {
    if (segments.length === 7) return { cloudPath: `/api/auth/organizations/${organizationId}/recovery-outbox/dead-letters`, methods: ["GET"], queryMethods: ["GET"], body: "none", requireCookie: true, requireCsrf: true };
    if (segments.length === 9 && isUuid(segments[7]) && (segments[8] === "redrive" || segments[8] === "suppress")) return { cloudPath: `/api/auth/organizations/${organizationId}/recovery-outbox/dead-letters/${segments[7].toLowerCase()}/${segments[8]}`, methods: ["POST"], body: segments[8] === "suppress" ? "recovery-outbox-suppress" : "empty", requireCookie: true, requireCsrf: true, requireIdempotency: true, requireRecentAuth: true, requireIfMatch: true };
    return undefined;
  }
  if (segments[5] === "members") {
    if (segments.length === 6) return { cloudPath: `/api/auth/organizations/${organizationId}/members`, methods: ["GET"], queryMethods: ["GET"], body: "none", requireCookie: true, requireCsrf: true };
    if (segments.length === 8 && isUuid(segments[6]) && segments[7] === "role") return { cloudPath: `/api/auth/organizations/${organizationId}/members/${segments[6].toLowerCase()}/role`, methods: ["PATCH"], body: "member-role", requireCookie: true, requireCsrf: true, requireIdempotency: true, requireRecentAuth: true, requireIfMatch: true };
    if (segments.length === 8 && isUuid(segments[6]) && segments[7] === "remove") return { cloudPath: `/api/auth/organizations/${organizationId}/members/${segments[6].toLowerCase()}/remove`, methods: ["POST"], body: "none", requireCookie: true, requireCsrf: true, requireIdempotency: true, requireRecentAuth: true, requireIfMatch: true };
    return undefined;
  }
  if (segments[5] === "invitations") {
    if (segments.length === 6) return { cloudPath: `/api/auth/organizations/${organizationId}/invitations`, methods: ["GET", "POST"], queryMethods: ["GET"], idempotencyMethods: ["POST"], bodies: { GET: "none", POST: "invitation-create" }, requireCookie: true, requireCsrf: true };
    if (segments.length === 8 && isUuid(segments[6]) && segments[7] === "revoke") return { cloudPath: `/api/auth/organizations/${organizationId}/invitations/${segments[6].toLowerCase()}/revoke`, methods: ["POST"], body: "none", requireCookie: true, requireCsrf: true, requireIdempotency: true, requireRecentAuth: true, requireIfMatch: true };
  }
  return undefined;
}
function normalizeListQuery(searchParams) {
  const allowed = new Set(["limit", "cursor"]);
  for (const key of searchParams.keys()) if (!allowed.has(key) || searchParams.getAll(key).length !== 1) fail(400, "invalid_request", "The request query is invalid");
  const limit = searchParams.get("limit");
  if (limit !== null && (!/^\d{1,3}$/.test(limit) || Number(limit) < 1 || Number(limit) > 100)) fail(400, "invalid_request", "The request query is invalid");
  const cursor = searchParams.get("cursor");
  if (cursor !== null && (!/^[A-Za-z0-9_-]{1,512}$/.test(cursor))) fail(400, "invalid_request", "The request query is invalid");
  const output = new URLSearchParams();
  if (limit !== null) output.set("limit", limit);
  if (cursor !== null) output.set("cursor", cursor);
  const encoded = output.toString();
  return encoded ? `?${encoded}` : "";
}
function isExactObject(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}
function isVersion(value) { return Number.isSafeInteger(value) && value > 0; }
function isCredentialId(value) { return typeof value === "string" && /^[A-Za-z0-9_-]{22,1366}$/.test(value); }
function isUuid(value) { return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value); }
function isSafeLabel(value) { return typeof value === "string" && value.length >= 1 && value.length <= 80 && value.trim() === value && !hasControl(value); }
function isSafeName(value) { return typeof value === "string" && value.length >= 1 && value.length <= 128 && value.trim() === value && !hasControl(value); }
function isSafeReason(value) { return typeof value === "string" && value.length >= 1 && value.length <= 128 && value.trim() === value && new TextEncoder().encode(value).byteLength <= 128 && !hasControl(value); }
function isRfc3339(value) { return typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value)); }
function isOpaqueInvitationToken(value) { return typeof value === "string" && /^[A-Za-z0-9_-]{43,512}$/.test(value); }
function isIdempotencyKey(value) { return typeof value === "string" && /^[A-Za-z0-9._~-]{8,255}$/.test(value); }
function isIfMatch(value) { return typeof value === "string" && /^"[1-9][0-9]*"$/.test(value); }
function isContextHash(value) { return typeof value === "string" && /^[0-9a-f]{64}$/i.test(value); }
function fail(status, code, message) { throw new HumanAuthBridgeError(status, code, message); }
