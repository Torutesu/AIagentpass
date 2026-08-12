const MAX_BODY_BYTES = 128 * 1024;
const MAX_RESPONSE_BYTES = 256 * 1024;
const DEFAULT_TIMEOUT_MS = 8_000;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ROUTES = new Map([
  ["/api/auth/session", "/api/auth/session"],
  ["/api/auth/webauthn/options", "/api/auth/webauthn/options"],
  ["/api/auth/webauthn/verify", "/api/auth/webauthn/verify"],
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
    const cloudPath = ROUTES.get(url.pathname);
    if (!cloudPath || url.search || url.hash) fail(404, "not_found", "Resource not found");
    if (request.method !== "POST") fail(405, "method_not_allowed", "Only POST is allowed");
    const origin = request.headers.get("origin");
    if (origin !== url.origin || origin === "null") fail(403, "origin_not_allowed", "The request origin is not allowed");

    const user = await requireUser(request, options);
    const config = readConfig(options.env);
    if (!config.operatorUserIds.has(user.userId)) fail(403, "operator_access_denied", "Operator access is denied");
    const body = await readBody(request);
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
    if (cloudPath !== "/api/auth/session") {
      if (csrf === null || csrf.length < 1 || csrf.length > 512 || hasControl(csrf)) fail(403, "csrf_required", "CSRF authentication is required");
      headers.set("agentpass-csrf", csrf);
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), config.timeoutMs);
    let upstream;
    try {
      upstream = await fetchImpl(new URL(cloudPath, config.url), {
        method: "POST",
        headers,
        body,
        cache: "no-store",
        redirect: "error",
        signal: controller.signal,
      });
    } catch {
      fail(503, "cloud_api_unavailable", "Cloud API is unavailable");
    } finally {
      clearTimeout(timeout);
    }
    return await relayResponse(upstream, cloudPath === "/api/auth/session");
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

async function readBody(request) {
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
  return bytes;
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
  if (allowSetCookie && setCookie !== null) {
    if (!/^__Host-agentpass_session=[A-Za-z0-9_-]{43}; Path=\/; HttpOnly; Secure; SameSite=Strict(?:; Max-Age=\d+)?$/.test(setCookie)) fail(502, "cloud_api_invalid_response", "Cloud API response was invalid");
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
function fail(status, code, message) { throw new HumanAuthBridgeError(status, code, message); }
