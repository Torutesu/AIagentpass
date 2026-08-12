const MAX_BODY_BYTES = 128 * 1024;
const MAX_RESPONSE_BYTES = 256 * 1024;
const DEFAULT_TIMEOUT_MS = 8_000;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ROUTES = new Map([
  ["/api/auth/session", Object.freeze({ cloudPath: "/api/auth/session", session: true })],
  ["/api/auth/webauthn/options", Object.freeze({ cloudPath: "/api/auth/webauthn/options", session: false })],
  ["/api/auth/webauthn/verify", Object.freeze({ cloudPath: "/api/auth/webauthn/verify", session: false })],
  ["/api/auth/webauthn/registration/options", Object.freeze({ cloudPath: "/api/auth/webauthn/registration/options", session: false })],
  ["/api/auth/webauthn/registration/verify", Object.freeze({ cloudPath: "/api/auth/webauthn/registration/verify", session: false })],
  ["/api/auth/security/passkeys", Object.freeze({ cloudPath: "/api/auth/management/credentials", methods: ["GET"], requireCookie: true, requireCsrf: true, body: "none" })],
  ["/api/auth/security/sessions", Object.freeze({ cloudPath: "/api/auth/management/sessions", methods: ["GET"], requireCookie: true, requireCsrf: true, body: "none" })],
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
    if (!(route.methods ?? ["POST"]).includes(request.method)) fail(405, "method_not_allowed", "Method not allowed");
    if (url.search && !(route.queryMethods ?? []).includes(request.method)) fail(400, "invalid_request", "The request query is invalid");
    const query = (route.queryMethods ?? []).includes(request.method) ? normalizeListQuery(url.searchParams) : "";
    route = { ...route, cloudPath: `${route.cloudPath}${query}`, body: route.bodies?.[request.method] ?? route.body, requireIdempotency: route.requireIdempotency === true || (route.idempotencyMethods ?? []).includes(request.method) };
    const origin = request.headers.get("origin");
    if (origin !== url.origin || origin === "null") fail(403, "origin_not_allowed", "The request origin is not allowed");

    const user = await requireUser(request, options);
    const config = readConfig(options.env);
    if (!config.operatorUserIds.has(user.userId)) fail(403, "operator_access_denied", "Operator access is denied");
    const body = route.body === "none" ? await readNoBody(request) : await readBody(request, route);
    const fetchImpl = options.fetchImpl ?? options.fetch ?? globalThis.fetch;
    if (typeof fetchImpl !== "function") fail(503, "cloud_api_unavailable", "Cloud API is unavailable");

    const headers = new Headers({
      accept: "application/json",
      authorization: `Bearer ${config.token}`,
      "cache-control": "no-store",
      "content-type": "application/json",
      origin,
      pragma: "no-cache",
      "agentpass-console-user-id": user.userId,
    });
    const cookie = request.headers.get("cookie");
    const csrf = request.headers.get("agentpass-csrf");
    if (cookie !== null) {
      if (cookie.length < 1 || cookie.length > 8192 || hasControl(cookie)) fail(400, "invalid_cookie", "The session cookie is invalid");
      headers.set("cookie", cookie);
    }
    if (route.requireCookie && cookie === null) fail(401, "session_required", "An active session is required");
    if (route.requireCsrf || !route.session) {
      if (csrf === null || csrf.length < 1 || csrf.length > 512 || hasControl(csrf)) fail(403, "csrf_required", "CSRF authentication is required");
      headers.set("agentpass-csrf", csrf);
    }
    const recentAuth = request.headers.get("agentpass-recent-auth");
    if (route.requireRecentAuth && recentAuth === null) fail(401, "recent_auth_required", "Recent WebAuthn authentication is required");
    if (recentAuth !== null) {
      if (!(route.requireRecentAuth || route.allowRecentAuth) || !isUuid(recentAuth)) fail(400, "invalid_recent_auth", "Recent WebAuthn authentication is invalid");
      headers.set("agentpass-recent-auth", recentAuth.toLowerCase());
    }
    const idempotencyKey = request.headers.get("idempotency-key");
    if (route.requireIdempotency && !isIdempotencyKey(idempotencyKey)) fail(400, "idempotency_required", "A valid Idempotency-Key is required");
    if (!route.requireIdempotency && idempotencyKey !== null) fail(400, "invalid_idempotency", "The Idempotency-Key is not allowed");
    if (idempotencyKey !== null) headers.set("idempotency-key", idempotencyKey);

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
      if (body !== undefined) init.body = body;
      upstream = await fetchImpl(new URL(route.cloudPath, config.url), init);
    } catch {
      fail(503, "cloud_api_unavailable", "Cloud API is unavailable");
    } finally {
      clearTimeout(timeout);
    }
    return await relayResponse(upstream, route.session === true || route.allowSetCookie === true);
  } catch (error) {
    const mapped = error instanceof HumanAuthBridgeError
      ? error
      : new HumanAuthBridgeError(500, "human_auth_bridge_failed", "Authentication is unavailable");
    return json(mapped.status, { error: { code: mapped.code, message: mapped.message } }, mapped.status === 405 ? { allow: "POST" } : undefined);
  }
}

async function requireUser(request, options) {
  const getUser = options.getSiwcUser ?? options.getUser;
  if (typeof getUser !== "function") fail(503, "identity_unavailable", "Identity verification is unavailable");
  let user;
  try { user = await getUser(request); } catch { fail(401, "authentication_required", "Authentication is required"); }
  if (!user || typeof user.userId !== "string" || !ID.test(user.userId)) fail(401, "authentication_required", "Authentication is required");
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
  if (shape === "empty") {
    if (!isExactObject(value, [])) fail(400, "invalid_request", "The security request is invalid");
    return;
  }
  if (shape === "rename") {
    if (!isExactObject(value, ["label", "expected_version"]) || !isSafeLabel(value.label) || !isVersion(value.expected_version)) {
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
    if (!isExactObject(value, ["name", "expected_version"]) || !isSafeName(value.name) || !isVersion(value.expected_version)) fail(400, "invalid_request", "The organization request is invalid");
    return;
  }
  if (shape === "member-role") {
    if (!isExactObject(value, ["role", "expected_version"]) || !["owner", "admin", "auditor", "viewer"].includes(value.role) || !isVersion(value.expected_version)) fail(400, "invalid_request", "The organization request is invalid");
    return;
  }
  if (shape === "invitation-create") {
    if (!isExactObject(value, ["role", "expires_at"]) || !["admin", "auditor", "viewer"].includes(value.role) || !isRfc3339(value.expires_at)) fail(400, "invalid_request", "The invitation request is invalid");
    return;
  }
  if (shape === "invitation-accept") {
    if (!isExactObject(value, ["one_time_token"]) || !isOpaqueInvitationToken(value.one_time_token)) fail(400, "invalid_request", "The invitation request is invalid");
    return;
  }
  fail(500, "human_auth_bridge_failed", "Authentication is unavailable");
}

async function relayResponse(response, allowSetCookie) {
  if (!response || typeof response.status !== "number" || response.status < 200 || response.status > 599) fail(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  const type = response.headers?.get("content-type") ?? "";
  if (!/^application\/json(?:\s*;|\s*$)/i.test(type)) fail(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAX_RESPONSE_BYTES)) fail(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength > MAX_RESPONSE_BYTES) fail(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  let value;
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch { fail(502, "cloud_api_invalid_response", "Cloud API response was invalid"); }
  const headers = new Headers({ "content-type": "application/json; charset=utf-8", "cache-control": "no-store, max-age=0", pragma: "no-cache", "x-content-type-options": "nosniff" });
  const setCookie = response.headers.get("set-cookie");
  if (setCookie !== null && !allowSetCookie) fail(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  if (allowSetCookie && setCookie !== null) {
    if (!/^__Host-agentpass_session=(?:[A-Za-z0-9_-]{43}|); Path=\/; HttpOnly; Secure; SameSite=Strict(?:; Max-Age=(?:0|[1-9]\d*))?$/.test(setCookie)) fail(502, "cloud_api_invalid_response", "Cloud API response was invalid");
    headers.set("set-cookie", setCookie);
  }
  return new Response(JSON.stringify(value), { status: response.status, headers });
}

function readConfig(injected) {
  const source = injected ?? (typeof process === "undefined" ? undefined : process.env);
  const urlValue = source?.AGENTPASS_CLOUD_API_URL;
  const token = source?.AGENTPASS_CLOUD_TOKEN;
  const operators = typeof source?.AGENTPASS_OPERATOR_USER_IDS === "string" ? source.AGENTPASS_OPERATOR_USER_IDS.split(",").map((item) => item.trim()).filter(Boolean) : [];
  let url;
  try { url = new URL(urlValue); } catch { fail(503, "cloud_api_unavailable", "Cloud API is unavailable"); }
  const insecureLoopback = source?.AGENTPASS_ALLOW_INSECURE_LOOPBACK_CLOUD_API === "true" && url.protocol === "http:" && ["127.0.0.1", "::1", "localhost"].includes(url.hostname);
  if ((url.protocol !== "https:" && !insecureLoopback) || url.username || url.password || url.search || url.hash || url.pathname !== "/" || typeof token !== "string" || token.length < 1 || token.length > 8192 || hasControl(token) || operators.length < 1 || operators.length > 100 || new Set(operators).size !== operators.length || operators.some((item) => !ID.test(item))) fail(503, "cloud_api_unavailable", "Cloud API is unavailable");
  const rawTimeout = source?.AGENTPASS_CLOUD_TIMEOUT_MS;
  const timeoutMs = typeof rawTimeout === "string" && /^\d+$/.test(rawTimeout) ? Math.max(1000, Math.min(30_000, Number(rawTimeout))) : DEFAULT_TIMEOUT_MS;
  return { url, token, timeoutMs, operatorUserIds: new Set(operators) };
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
  if (match[1] === "passkeys" && isCredentialId(id) && !match[3]) return { cloudPath: `/api/auth/management/credentials/${id}`, methods: ["PATCH"], requireCookie: true, requireCsrf: true, body: "rename" };
  if (match[1] === "passkeys" && isCredentialId(id) && match[3]) return { cloudPath: `/api/auth/management/credentials/${id}/revoke`, methods: ["POST"], requireCookie: true, requireCsrf: true, requireRecentAuth: true, body: "version" };
  if (match[1] === "sessions" && isUuid(id) && match[3]) return { cloudPath: `/api/auth/management/sessions/${id.toLowerCase()}/revoke`, methods: ["POST"], requireCookie: true, requireCsrf: true, allowRecentAuth: true, body: "version", allowSetCookie: true };
  return undefined;
}
function resolveOrganizationRoute(pathname) {
  if (pathname === "/api/auth/organizations") return { cloudPath: pathname, methods: ["GET", "POST"], queryMethods: ["GET"], idempotencyMethods: ["POST"], bodies: { GET: "none", POST: "organization-create" }, requireCookie: true, requireCsrf: true };
  if (pathname === "/api/auth/invitations/accept") return { cloudPath: pathname, methods: ["POST"], body: "invitation-accept", requireCookie: true, requireCsrf: true, requireIdempotency: true };
  const segments = pathname.split("/");
  if (segments.length < 5 || segments[1] !== "api" || segments[2] !== "auth" || segments[3] !== "organizations" || !isUuid(segments[4])) return undefined;
  const organizationId = segments[4].toLowerCase();
  if (segments.length === 5) return { cloudPath: `/api/auth/organizations/${organizationId}`, methods: ["PATCH"], body: "organization-rename", requireCookie: true, requireCsrf: true, requireIdempotency: true };
  if (segments[5] === "members") {
    if (segments.length === 6) return { cloudPath: `/api/auth/organizations/${organizationId}/members`, methods: ["GET"], queryMethods: ["GET"], body: "none", requireCookie: true, requireCsrf: true };
    if (segments.length === 8 && isUuid(segments[6]) && segments[7] === "role") return { cloudPath: `/api/auth/organizations/${organizationId}/members/${segments[6].toLowerCase()}/role`, methods: ["PATCH"], body: "member-role", requireCookie: true, requireCsrf: true, requireIdempotency: true, requireRecentAuth: true };
    if (segments.length === 8 && isUuid(segments[6]) && segments[7] === "remove") return { cloudPath: `/api/auth/organizations/${organizationId}/members/${segments[6].toLowerCase()}/remove`, methods: ["POST"], body: "version", requireCookie: true, requireCsrf: true, requireIdempotency: true, requireRecentAuth: true };
    return undefined;
  }
  if (segments[5] === "invitations") {
    if (segments.length === 6) return { cloudPath: `/api/auth/organizations/${organizationId}/invitations`, methods: ["GET", "POST"], queryMethods: ["GET"], idempotencyMethods: ["POST"], bodies: { GET: "none", POST: "invitation-create" }, requireCookie: true, requireCsrf: true };
    if (segments.length === 8 && isUuid(segments[6]) && segments[7] === "revoke") return { cloudPath: `/api/auth/organizations/${organizationId}/invitations/${segments[6].toLowerCase()}/revoke`, methods: ["POST"], body: "version", requireCookie: true, requireCsrf: true, requireIdempotency: true };
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
function isRfc3339(value) { return typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value)); }
function isOpaqueInvitationToken(value) { return typeof value === "string" && /^[A-Za-z0-9_-]{43,512}$/.test(value); }
function isIdempotencyKey(value) { return typeof value === "string" && /^[A-Za-z0-9._~-]{8,255}$/.test(value); }
function fail(status, code, message) { throw new HumanAuthBridgeError(status, code, message); }
