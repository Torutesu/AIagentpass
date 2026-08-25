const MAX_BODY_BYTES = 64 * 1024;
const MAX_RESPONSE_BYTES = 256 * 1024;
const MAX_COOKIE_BYTES = 4 * 1024;
const DEFAULT_TIMEOUT_MS = 8_000;
const OPAQUE = /^[A-Za-z0-9_-]{16,4096}$/u;
const CSRF = /^[A-Za-z0-9_-]{43,512}$/u;
const IDEMPOTENCY = /^[A-Za-z0-9._~-]{8,255}$/u;
const COOKIE_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u;
const FORBIDDEN_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "agentpass-console-user-id",
  "agentpass-member-id",
  "agentpass-organization-id",
  "agentpass-role",
  "agentpass-identity-assertion",
  "agentpass-cloud-token",
  "oai-authenticated-user-id",
  "oai-authenticated-user-email",
  "oai-authenticated-user-name",
  "x-agentpass-identity",
  "x-agentpass-authorization"
]);

export const HOSTED_BOOTSTRAP_ROUTES = Object.freeze({
  githubStart: Object.freeze({ path: "/api/auth/bootstrap/github/start", method: "GET", query: "none", cookie: "none", redirect: "github" }),
  githubCallback: Object.freeze({ path: "/api/auth/bootstrap/github/callback", method: "GET", query: "github", cookie: "github_state", redirect: "onboarding" }),
  status: Object.freeze({ path: "/api/auth/bootstrap/status", method: "GET", query: "none", cookie: "bootstrap", origin: true }),
  organization: Object.freeze({ path: "/api/auth/bootstrap/organization", method: "POST", query: "none", cookie: "bootstrap", origin: true, csrf: true, idempotency: true }),
  webauthnOptions: Object.freeze({ path: "/api/auth/bootstrap/webauthn/registration/options", method: "POST", query: "none", cookie: "bootstrap", origin: true, csrf: true }),
  webauthnVerify: Object.freeze({ path: "/api/auth/bootstrap/webauthn/registration/verify", method: "POST", query: "none", cookie: "bootstrap", origin: true, csrf: true })
});

const ROUTES_BY_KEY = new Map(Object.entries(HOSTED_BOOTSTRAP_ROUTES).map(([key, route]) => [route.path, Object.freeze({ key, ...route })]));
const UPSTREAM_ERROR_MESSAGES = Object.freeze({
  bootstrap_origin_not_allowed: "The request origin is not allowed",
  bootstrap_csrf_failed: "The bootstrap CSRF token is invalid",
  bootstrap_session_required: "A valid bootstrap session is required",
  bootstrap_session_expired: "The bootstrap session has expired",
  github_oauth_state_invalid: "The GitHub OAuth attempt is invalid",
  github_subject_unverified: "The GitHub identity could not be verified",
  github_provider_unavailable: "The GitHub provider is temporarily unavailable",
  bootstrap_invalid_request: "The bootstrap request is invalid",
  bootstrap_idempotency_required: "An Idempotency-Key is required",
  bootstrap_idempotency_conflict: "The idempotency key conflicts with an earlier request",
  bootstrap_already_completed: "Bootstrap has already completed",
  bootstrap_no_membership: "An eligible membership is required",
  bootstrap_webauthn_required: "WebAuthn registration is required",
  bootstrap_webauthn_invalid: "The WebAuthn registration is invalid",
  bootstrap_webauthn_replayed: "The WebAuthn registration has already been used",
  bootstrap_unavailable: "The bootstrap service is temporarily unavailable"
});
const FORBIDDEN_PAYLOAD_KEYS = new Set([
  "authorization",
  "access_token",
  "refresh_token",
  "client_secret",
  "github_access_token",
  "pkce_verifier",
  "private_key",
  "secret",
  "session_token",
  "bootstrap_token"
]);

export class HostedBootstrapBffError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "HostedBootstrapBffError";
    this.status = status;
    this.code = code;
  }
}

export function createHostedBootstrapBff(options = {}) {
  return Object.freeze({ handle: (request) => handleHostedBootstrapRequest(request, options) });
}

export async function handleHostedBootstrapRequest(request, options = {}) {
  try {
    const config = readConfig(options);
    const parsed = parseRequestUrl(request, config);
    const route = ROUTES_BY_KEY.get(parsed.url.pathname);
    if (!route) throw bffError(404, "not_found", "Resource not found");
    assertMethodAndQuery(parsed.url, request.method, route);
    assertNoForbiddenHeaders(request.headers);
    assertOrigin(request, parsed.url, route, config);
    const body = await readRequestBody(request, route);
    const headers = createUpstreamHeaders(request, parsed.url, route, config);
    const upstreamUrl = new URL(route.path, config.cloudApiUrl);
    if (route.query === "github") upstreamUrl.search = parsed.url.search;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), config.timeoutMs);
    let upstream;
    try {
      upstream = await (options.fetchImpl ?? globalThis.fetch)(upstreamUrl, {
        method: route.method,
        headers,
        body,
        cache: "no-store",
        redirect: "manual",
        signal: controller.signal
      });
    } catch {
      if (controller.signal.aborted) throw bffError(504, "cloud_api_timeout", "Cloud API request timed out");
      throw bffError(503, "cloud_api_unavailable", "Cloud API is unavailable");
    } finally {
      clearTimeout(timeout);
    }
    return await relayResponse(upstream, route, parsed.url.origin, config);
  } catch (error) {
    const mapped = error instanceof HostedBootstrapBffError
      ? error
      : new HostedBootstrapBffError(503, "cloud_api_unavailable", "Cloud API is unavailable");
    return errorResponse(mapped.status, mapped.code, mapped.message, mapped.status === 405 ? "GET, POST" : undefined);
  }
}

function readConfig(options) {
  const env = options.env ?? (typeof process === "undefined" ? undefined : process.env);
  const rawCloudUrl = options.cloudApiUrl ?? env?.AGENTPASS_CLOUD_API_URL;
  let cloudApiUrl;
  try { cloudApiUrl = new URL(rawCloudUrl); } catch { throw bffError(503, "cloud_api_unavailable", "Cloud API is unavailable"); }
  const insecureLoopback = env?.AGENTPASS_ALLOW_INSECURE_LOOPBACK_CLOUD_API === "true"
    && cloudApiUrl.protocol === "http:"
    && ["localhost", "127.0.0.1", "::1"].includes(cloudApiUrl.hostname);
  if ((cloudApiUrl.protocol !== "https:" && !insecureLoopback) || cloudApiUrl.username || cloudApiUrl.password || cloudApiUrl.search || cloudApiUrl.hash || cloudApiUrl.pathname !== "/") {
    throw bffError(503, "cloud_api_unavailable", "Cloud API is unavailable");
  }
  const configuredOrigin = options.consoleOrigin ?? env?.AGENTPASS_CONSOLE_ORIGIN;
  if (configuredOrigin !== undefined && !isOrigin(configuredOrigin)) throw bffError(503, "configuration", "Hosted bootstrap is unavailable");
  const rawTimeout = options.timeoutMs ?? env?.AGENTPASS_CLOUD_TIMEOUT_MS;
  const timeoutMs = typeof rawTimeout === "number" && Number.isSafeInteger(rawTimeout)
    ? Math.max(1_000, Math.min(30_000, rawTimeout))
    : typeof rawTimeout === "string" && /^\d+$/u.test(rawTimeout)
      ? Math.max(1_000, Math.min(30_000, Number(rawTimeout)))
      : DEFAULT_TIMEOUT_MS;
  return Object.freeze({ cloudApiUrl, configuredOrigin, timeoutMs });
}

function parseRequestUrl(request, config) {
  if (!request || typeof request !== "object" || typeof request.url !== "string" || typeof request.method !== "string") throw bffError(400, "invalid_request", "The bootstrap request is invalid");
  let url;
  try { url = new URL(request.url); } catch { throw bffError(400, "invalid_request", "The bootstrap request is invalid"); }
  if (!/^https?:$/u.test(url.protocol) || url.hash) throw bffError(400, "invalid_request", "The bootstrap request is invalid");
  if (config.configuredOrigin !== undefined && url.origin !== config.configuredOrigin) throw bffError(403, "origin_not_allowed", "The request origin is not allowed");
  return { url };
}

function assertMethodAndQuery(url, method, route) {
  if (method !== route.method) throw bffError(405, "method_not_allowed", "Method not allowed");
  if (route.query === "none" && url.search) throw bffError(400, "invalid_request", "The bootstrap request query is invalid");
  if (route.query === "github") {
    const keys = [...url.searchParams.keys()];
    if (keys.length !== 2 || keys.sort().join("\0") !== "code\0state" || url.searchParams.getAll("code").length !== 1 || url.searchParams.getAll("state").length !== 1) throw bffError(400, "github_oauth_state_invalid", "The GitHub OAuth attempt is invalid");
    for (const value of [url.searchParams.get("code"), url.searchParams.get("state")]) if (!value || value.length > 4096 || hasControl(value)) throw bffError(400, "github_oauth_state_invalid", "The GitHub OAuth attempt is invalid");
  }
}

function assertNoForbiddenHeaders(headers) {
  if (!headers || typeof headers.get !== "function") throw bffError(400, "invalid_request", "The bootstrap request is invalid");
  for (const name of FORBIDDEN_HEADERS) if (headers.has(name)) throw bffError(400, "invalid_request", "The bootstrap request is invalid");
}

function assertOrigin(request, url, route, config) {
  const origin = request.headers.get("origin");
  if (origin !== null && (origin === "null" || origin !== url.origin)) throw bffError(403, "origin_not_allowed", "The request origin is not allowed");
  if (route.origin && route.method === "POST" && (origin === null || origin !== (config.configuredOrigin ?? url.origin))) throw bffError(403, "origin_not_allowed", "The request origin is not allowed");
}

async function readRequestBody(request, route) {
  const contentType = request.headers.get("content-type");
  const contentLength = request.headers.get("content-length");
  if (contentLength !== null && (!/^\d+$/u.test(contentLength) || Number(contentLength) > MAX_BODY_BYTES)) throw bffError(413, "request_too_large", "Request body is too large");
  if (route.method === "GET") {
    if (contentType !== null || (contentLength !== null && contentLength !== "0")) throw bffError(400, "invalid_request", "The bootstrap request body is invalid");
    const bytes = new Uint8Array(await request.arrayBuffer());
    if (bytes.byteLength !== 0) throw bffError(400, "invalid_request", "The bootstrap request body is invalid");
    return undefined;
  }
  if (contentType === null || !/^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(contentType)) throw bffError(415, "unsupported_media_type", "Content-Type must be application/json");
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.byteLength < 2) throw bffError(400, "invalid_request", "The bootstrap request body is invalid");
  if (bytes.byteLength > MAX_BODY_BYTES) throw bffError(413, "request_too_large", "Request body is too large");
  return bytes;
}

function createUpstreamHeaders(request, url, route, config) {
  const headers = new Headers({
    accept: "application/json",
    "cache-control": "no-store",
    pragma: "no-cache"
  });
  if (route.origin) headers.set("origin", config.configuredOrigin ?? url.origin);
  const cookie = selectCookie(request.headers.get("cookie"), route.cookie);
  if (cookie !== null) headers.set("cookie", cookie);
  if (route.method === "POST") headers.set("content-type", "application/json");
  if (route.csrf) {
    const csrf = request.headers.get("agentpass-bootstrap-csrf");
    if (csrf === null || !CSRF.test(csrf)) throw bffError(403, "bootstrap_csrf_failed", "The bootstrap CSRF token is invalid");
    headers.set("agentpass-bootstrap-csrf", csrf);
  } else if (request.headers.has("agentpass-bootstrap-csrf")) {
    throw bffError(400, "invalid_request", "The bootstrap request is invalid");
  }
  if (route.idempotency) {
    const key = request.headers.get("idempotency-key");
    if (key === null || !IDEMPOTENCY.test(key)) throw bffError(400, "bootstrap_idempotency_required", "An Idempotency-Key is required");
    headers.set("idempotency-key", key);
  } else if (request.headers.has("idempotency-key")) {
    throw bffError(400, "invalid_request", "The bootstrap request is invalid");
  }
  void url;
  void config;
  return headers;
}

function selectCookie(header, kind) {
  if (header === null || header === "") return null;
  if (typeof header !== "string" || header.length > MAX_COOKIE_BYTES || hasControl(header)) throw bffError(400, "invalid_cookie", "The bootstrap cookie is invalid");
  const allowed = kind === "github_state" ? "__Host-agentpass_github_state" : kind === "bootstrap" ? "__Host-agentpass_bootstrap" : null;
  if (allowed === null) return null;
  let selected = null;
  for (const part of header.split(";")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const separator = trimmed.indexOf("=");
    if (separator <= 0) continue;
    const name = trimmed.slice(0, separator);
    const value = trimmed.slice(separator + 1);
    if (name !== allowed) continue;
    if (!COOKIE_NAME.test(name) || !value || !OPAQUE.test(value) || selected !== null) throw bffError(400, "invalid_cookie", "The bootstrap cookie is invalid");
    selected = `${name}=${value}`;
  }
  return selected;
}

async function relayResponse(response, route, requestOrigin) {
  if (!response || !Number.isSafeInteger(response.status) || response.status < 200 || response.status > 599) throw bffError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  if (response.status >= 300 && response.status < 400) return relayRedirect(response, route, requestOrigin);
  const cookies = readSetCookies(response.headers);
  if (response.headers.get("location") !== null) throw bffError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  const payload = await readJsonResponse(response);
  if (response.status >= 400) {
    if (route.key !== "githubCallback" && cookies.length > 0) throw bffError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
    const output = errorResponse(response.status, payload.error.code, UPSTREAM_ERROR_MESSAGES[payload.error.code]);
    if (route.key === "githubCallback") {
      if (cookies.length !== 1 || !validCallbackErrorCookie(cookies[0])) throw bffError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
      appendSetCookies(output.headers, cookies);
    }
    return output;
  }
  if (!isSafePayload(payload)) throw bffError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  const expectedStatus = route.key === "organization" ? new Set([200, 201]) : route.key === "webauthnVerify" ? new Set([201]) : new Set([200]);
  if (!expectedStatus.has(response.status)) throw bffError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  if (route.key !== "webauthnVerify" && cookies.length > 0) throw bffError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  const output = jsonResponse(response.status, payload);
  if (route.key === "webauthnVerify") {
    if (cookies.length !== 2 || !validVerifyCookies(cookies)) throw bffError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
    appendSetCookies(output.headers, cookies);
  }
  return output;
}

async function relayRedirect(response, route, requestOrigin) {
  await readResponseBytes(response);
  const location = response.headers.get("location");
  const cookies = readSetCookies(response.headers);
  if (location === null || !Number.isSafeInteger(response.status) || !((route.key === "githubStart" && response.status === 302) || (route.key === "githubCallback" && response.status === 303))) throw bffError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  if (route.key === "githubStart") {
    let target;
    try { target = new URL(location); } catch { throw bffError(502, "cloud_api_invalid_response", "Cloud API response was invalid"); }
    const queryKeys = [...target.searchParams.keys()];
    if (target.protocol !== "https:" || target.hostname !== "github.com" || target.username || target.password || target.hash || target.pathname !== "/login/oauth/authorize" || JSON.stringify(queryKeys) !== JSON.stringify(["client_id", "response_type", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method"]) || cookies.length !== 1 || !validCookieForRoute(cookies[0], route)) throw bffError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  } else {
    let target;
    try { target = new URL(location); } catch { throw bffError(502, "cloud_api_invalid_response", "Cloud API response was invalid"); }
    if (target.origin !== requestOrigin || target.pathname !== "/onboarding" || target.search || target.hash || target.username || target.password || cookies.length !== 2 || !cookies.every((cookie) => validCookieForRoute(cookie, route))) throw bffError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  }
  const headers = baseHeaders();
  headers.set("location", location);
  appendSetCookies(headers, cookies);
  return new Response(null, { status: response.status, headers });
}

async function readJsonResponse(response) {
  const contentType = response.headers.get("content-type") ?? "";
  if (!/^application\/json(?:\s*;|\s*$)/iu.test(contentType)) throw bffError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  const length = response.headers.get("content-length");
  if (length !== null && (!/^\d+$/u.test(length) || Number(length) > MAX_RESPONSE_BYTES)) throw bffError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  const bytes = await readResponseBytes(response);
  let payload;
  try { payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch { throw bffError(502, "cloud_api_invalid_response", "Cloud API response was invalid"); }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw bffError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  if (response.status >= 400 && (!isErrorEnvelope(payload) || !UPSTREAM_ERROR_MESSAGES[payload.error.code])) throw bffError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  return payload;
}

async function readResponseBytes(response) {
  const length = response.headers.get("content-length");
  if (length !== null && (!/^\d+$/u.test(length) || Number(length) > MAX_RESPONSE_BYTES)) throw bffError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  let bytes;
  try { bytes = new Uint8Array(await response.arrayBuffer()); } catch { throw bffError(502, "cloud_api_invalid_response", "Cloud API response was invalid"); }
  if (bytes.byteLength > MAX_RESPONSE_BYTES) throw bffError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  return bytes;
}

function isErrorEnvelope(value) {
  return Object.keys(value).length === 1 && value.error && typeof value.error === "object" && !Array.isArray(value.error) && Object.keys(value.error).length === 2 && typeof value.error.code === "string" && typeof value.error.message === "string" && value.error.code.length <= 128 && value.error.message.length <= 512 && !hasControl(value.error.code) && !hasControl(value.error.message);
}

function isSafePayload(value, depth = 0) {
  if (depth > 12) return false;
  if (typeof value === "string") return !hasControl(value) && !/-----BEGIN [A-Z ]+ KEY-----/u.test(value);
  if (Array.isArray(value)) return value.length <= 512 && value.every((item) => isSafePayload(item, depth + 1));
  if (!value || typeof value !== "object") return true;
  for (const [key, child] of Object.entries(value)) if (FORBIDDEN_PAYLOAD_KEYS.has(key.toLowerCase()) || !isSafePayload(child, depth + 1)) return false;
  return Object.keys(value).length <= 128;
}

function validCookieForRoute(value, route) {
  if (typeof value !== "string" || hasControl(value)) return false;
  const state = /^__Host-agentpass_github_state=([A-Za-z0-9._~-]{16,4096}); Path=\/; HttpOnly; Secure; SameSite=Lax; Max-Age=(\d+)$/u;
  const clearState = /^__Host-agentpass_github_state=; Path=\/; HttpOnly; Secure; SameSite=Lax; Max-Age=0$/u;
  const bootstrap = /^__Host-agentpass_bootstrap=([A-Za-z0-9._~-]{16,4096}); Path=\/; HttpOnly; Secure; SameSite=Strict; Max-Age=(\d+)$/u;
  const clearBootstrap = /^__Host-agentpass_bootstrap=; Path=\/; HttpOnly; Secure; SameSite=Strict; Max-Age=0$/u;
  const session = /^__Host-agentpass_session=([A-Za-z0-9._~-]{16,4096}); Path=\/; HttpOnly; Secure; SameSite=Strict(?:; Max-Age=(\d+))?$/u;
  if (route.key === "githubStart") return state.test(value);
  if (route.key === "githubCallback") return clearState.test(value) || bootstrap.test(value);
  return session.test(value) || clearBootstrap.test(value);
}

function validVerifyCookies(cookies) {
  return /^__Host-agentpass_session=/.test(cookies[0]) && validCookieForRoute(cookies[0], { key: "webauthnVerify" })
    && /^__Host-agentpass_bootstrap=;/.test(cookies[1]) && validCookieForRoute(cookies[1], { key: "webauthnVerify" });
}

function validCallbackErrorCookie(value) {
  return /^__Host-agentpass_github_state=; Path=\/; HttpOnly; Secure; SameSite=Lax; Max-Age=0$/u.test(value);
}

function readSetCookies(headers) {
  if (typeof headers.getSetCookie === "function") return headers.getSetCookie();
  const raw = headers.get("set-cookie");
  if (raw === null) return [];
  return splitSetCookieHeader(raw);
}

function splitSetCookieHeader(value) {
  const result = [];
  let start = 0;
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] === "," && /\s*[!#$%&'*+.^_`|~0-9A-Za-z-]+=/.test(value.slice(index + 1))) {
      result.push(value.slice(start, index).trim());
      start = index + 1;
    }
  }
  result.push(value.slice(start).trim());
  return result.filter(Boolean);
}

function appendSetCookies(headers, cookies) { for (const cookie of cookies) headers.append("set-cookie", cookie); }

function baseHeaders() {
  return new Headers({ "cache-control": "no-store, max-age=0", pragma: "no-cache", expires: "0", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer" });
}

function jsonResponse(status, payload) {
  const headers = baseHeaders();
  headers.set("content-type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(payload), { status, headers });
}

function errorResponse(status, code, message, allow = undefined) {
  const headers = baseHeaders();
  headers.set("content-type", "application/json; charset=utf-8");
  if (allow !== undefined) headers.set("allow", allow);
  return new Response(JSON.stringify({ error: { code, message } }), { status, headers });
}

function isOrigin(value) {
  if (typeof value !== "string" || value === "null" || hasControl(value)) return false;
  try {
    const url = new URL(value);
    return url.origin === value && url.protocol === "https:" && !url.username && !url.password && !url.search && !url.hash && url.pathname === "/";
  } catch { return false; }
}

function bffError(status, code, message) { return new HostedBootstrapBffError(status, code, message); }

function hasControl(value) {
  for (const character of value) {
    const code = character.codePointAt(0);
    if (code <= 31 || code === 127) return true;
  }
  return false;
}
