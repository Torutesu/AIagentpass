const MAX_BODY_BYTES = 128 * 1024;
const MAX_RESPONSE_BYTES = 256 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const OPAQUE = /^[A-Za-z0-9_-]{43,512}$/;
const CSRF = /^[A-Za-z0-9_-]{43,512}$/;
const IDEMPOTENCY = /^[A-Za-z0-9._~-]{8,255}$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const RECOVERY_STATES = new Set(["pending", "approved", "delayed", "session_issued", "credential_enrolled", "activated", "cancelled", "expired", "failed"]);
const RECOVERY_STAGES = new Set(["session_issued", "credential_enrolled", "activated", "revoked", "expired"]);
const ROLES = new Set(["owner", "admin", "auditor", "viewer"]);

export class OwnerRecoveryApiError extends Error {
  constructor(code, message, status, serverCode) {
    super(message);
    this.name = "OwnerRecoveryApiError";
    this.code = code;
    this.status = status;
    this.serverCode = serverCode;
  }
}

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function exact(value, keys) {
  return isRecord(value) && Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}

function optionalExact(value, keys) {
  if (!isRecord(value)) return false;
  return Object.keys(value).every((key) => keys.includes(key));
}

function uuid(value) { return typeof value === "string" && UUID.test(value); }
function timestamp(value) { return typeof value === "string" && RFC3339.test(value) && Number.isFinite(Date.parse(value)); }
function opaque(value) { return typeof value === "string" && OPAQUE.test(value); }
function idempotency(value) { return typeof value === "string" && IDEMPOTENCY.test(value); }

function parseRecovery(value) {
  const fields = ["schema_version", "kind", "request_id", "organization_id", "subject_member_id", "state", "threshold", "approved_owner_count", "approved_at", "delay_until", "session_issued_at", "credential_enrolled_at", "activated_at", "expires_at", "terminal_reason", "version", "created_at", "updated_at"];
  if (!optionalExact(value, fields) || !["schema_version", "kind", "request_id", "organization_id", "subject_member_id", "state", "threshold", "approved_owner_count", "expires_at", "version", "created_at"].every((key) => Object.hasOwn(value, key))) throw invalidResponse();
  if (value.schema_version !== 1 || value.kind !== "threshold-owner-recovery" || !uuid(value.request_id) || !uuid(value.organization_id) || !uuid(value.subject_member_id) || !RECOVERY_STATES.has(value.state) || !Number.isSafeInteger(value.threshold) || value.threshold < 2 || value.threshold > 32 || !Number.isSafeInteger(value.approved_owner_count) || value.approved_owner_count < 0 || value.approved_owner_count > 32 || !timestamp(value.expires_at) || !Number.isSafeInteger(value.version) || value.version < 1 || !timestamp(value.created_at)) throw invalidResponse();
  for (const key of ["approved_at", "delay_until", "session_issued_at", "credential_enrolled_at", "activated_at"]) if (value[key] !== null && value[key] !== undefined && !timestamp(value[key])) throw invalidResponse();
  if (value.terminal_reason !== null && value.terminal_reason !== undefined && (typeof value.terminal_reason !== "string" || value.terminal_reason.length > 128)) throw invalidResponse();
  if (value.updated_at !== undefined && !timestamp(value.updated_at)) throw invalidResponse();
  return Object.freeze({ ...value });
}

function parseEnvelope(value, { allowExchange = false } = {}) {
  const keys = allowExchange ? ["request_id", "recovery", "exchange_value", "eligibility", "replayed"] : ["request_id", "recovery", "eligibility", "replayed"];
  if (!optionalExact(value, keys) || !uuid(value.request_id) || !isRecord(value.recovery)) throw invalidResponse();
  const recovery = parseRecovery(value.recovery);
  let exchangeValue;
  if (allowExchange && value.exchange_value !== undefined) {
    if (!opaque(value.exchange_value)) throw invalidResponse();
    exchangeValue = value.exchange_value;
  }
  let eligibility;
  if (value.eligibility !== undefined) {
    if (!exact(value.eligibility, ["eligible_owner_count", "threshold", "recoverable"]) || !Number.isSafeInteger(value.eligibility.eligible_owner_count) || value.eligibility.eligible_owner_count < 0 || !Number.isSafeInteger(value.eligibility.threshold) || value.eligibility.threshold < 2 || typeof value.eligibility.recoverable !== "boolean") throw invalidResponse();
    eligibility = Object.freeze({ ...value.eligibility });
  }
  if (value.replayed !== undefined && value.replayed !== true) throw invalidResponse();
  return Object.freeze({ requestId: value.request_id, recovery, ...(exchangeValue === undefined ? {} : { exchangeValue }), ...(eligibility === undefined ? {} : { eligibility }), ...(value.replayed === undefined ? {} : { replayed: true }) });
}

function parseSession(value) {
  if (!exact(value, ["session", "csrf_token"]) || !isRecord(value.session) || !uuid(value.session.session_id) || !uuid(value.session.member_id) || !uuid(value.session.organization_id) || !ROLES.has(value.session.role) || !timestamp(value.session.created_at) || !timestamp(value.session.expires_at) || (value.session.recent_auth_at !== null && !timestamp(value.session.recent_auth_at)) || typeof value.csrf_token !== "string" || !CSRF.test(value.csrf_token)) throw invalidResponse();
  return Object.freeze({ organizationId: value.session.organization_id, memberId: value.session.member_id, role: value.session.role, csrfToken: value.csrf_token });
}

function parseRecoverySession(value) {
  if (!exact(value, ["request_id", "recovery_session"]) || !uuid(value.request_id) || !isRecord(value.recovery_session) || !exact(value.recovery_session, ["recovery_session_id", "request_id", "member_id", "stage", "expires_at", "idle_expires_at"]) || !uuid(value.recovery_session.recovery_session_id) || value.recovery_session.request_id !== value.request_id || !uuid(value.recovery_session.member_id) || !RECOVERY_STAGES.has(value.recovery_session.stage) || !timestamp(value.recovery_session.expires_at) || !timestamp(value.recovery_session.idle_expires_at)) throw invalidResponse();
  return Object.freeze({ requestId: value.request_id, recoverySession: Object.freeze({ ...value.recovery_session }) });
}

function parseCeremony(value) {
  if (!exact(value, ["request_id", "challenge_id", "options"]) || !uuid(value.request_id) || !uuid(value.challenge_id) || !isRecord(value.options)) throw invalidResponse();
  return Object.freeze({ requestId: value.request_id, challengeId: value.challenge_id, options: value.options });
}

function parseMutation(value, field) {
  if (!exact(value, ["request_id", "recovery", field]) || !uuid(value.request_id) || !isRecord(value.recovery) || value[field] !== true) throw invalidResponse();
  return Object.freeze({ requestId: value.request_id, recovery: parseRecovery(value.recovery), [field]: true });
}

function parseRegistrationVerified(value) {
  if (!exact(value, ["request_id", "recovery", "registered", "activation"]) || !uuid(value.request_id) || !isRecord(value.recovery) || value.registered !== true || !isRecord(value.activation)) throw invalidResponse();
  const activation = value.activation;
  if (!exact(activation, ["challenge_id", "options"]) || !uuid(activation.challenge_id) || !isRecord(activation.options)) throw invalidResponse();
  return Object.freeze({ requestId: value.request_id, recovery: parseRecovery(value.recovery), registered: true, activation: Object.freeze({ challengeId: activation.challenge_id, options: activation.options }) });
}

function invalidResponse() { return new OwnerRecoveryApiError("invalid_response", "Recovery response was invalid"); }

async function readJson(response) {
  const type = response.headers?.get("content-type") ?? "";
  if (!/^application\/json(?:\s*;|\s*$)/i.test(type)) throw invalidResponse();
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null && (!/^\d+$/.test(contentLength) || Number(contentLength) > MAX_RESPONSE_BYTES)) throw invalidResponse();
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength > MAX_RESPONSE_BYTES) throw invalidResponse();
  try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch { throw invalidResponse(); }
}

function safeError(value, status) {
  if (isRecord(value) && isRecord(value.error) && typeof value.error.code === "string" && typeof value.error.message === "string") return new OwnerRecoveryApiError(status === 401 || status === 403 ? "forbidden" : status === 409 ? "conflict" : "http_failed", value.error.message, status, value.error.code);
  return new OwnerRecoveryApiError("http_failed", "Recovery request was rejected", status);
}

function makeKey() {
  if (typeof globalThis.crypto?.randomUUID === "function") return globalThis.crypto.randomUUID();
  return `recovery-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

export function getOwnerRecoveryVisibility(role) {
  if (role === "owner") return Object.freeze({ canView: true, canCreate: true, canApprove: true, canCancel: true, canExchange: true, canEnroll: true, canActivate: true });
  return Object.freeze({ canView: false, canCreate: false, canApprove: false, canCancel: false, canExchange: false, canEnroll: false, canActivate: false });
}

export function createOwnerRecoveryClient({ fetchImpl = globalThis.fetch, sessionPath = "/api/auth/session" } = {}) {
  if (typeof fetchImpl !== "function") throw new TypeError("fetchImpl must be a function");
  let session;
  let sessionPromise;

  async function getSession({ signal } = {}) {
    if (session) return session;
    if (!sessionPromise) {
      sessionPromise = requestRaw(sessionPath, { method: "POST", body: {}, signal, csrfToken: undefined }).then((value) => {
        session = parseSession(value);
        sessionPromise = undefined;
        return session;
      }, (error) => { sessionPromise = undefined; throw error; });
    }
    return sessionPromise;
  }

  function clearSession() { session = undefined; }

  async function requestRaw(path, { method = "GET", body, signal, csrfToken, recentAuth, idempotencyKey, ifMatch, credentials = "same-origin" } = {}) {
    const headers = new Headers({ accept: "application/json", "cache-control": "no-store", pragma: "no-cache" });
    if (body !== undefined) {
      headers.set("content-type", "application/json");
      if (JSON.stringify(body).length > MAX_BODY_BYTES) throw new OwnerRecoveryApiError("invalid_request", "Recovery request is too large");
    }
    if (csrfToken !== undefined) headers.set("agentpass-csrf", csrfToken);
    if (recentAuth !== undefined) headers.set("agentpass-recent-auth", recentAuth);
    if (idempotencyKey !== undefined) headers.set("idempotency-key", idempotencyKey);
    if (ifMatch !== undefined) headers.set("if-match", `"${ifMatch}"`);
    let response;
    try {
      response = await fetchImpl(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), cache: "no-store", credentials, redirect: "error", signal });
    } catch (error) {
      if (signal?.aborted || error instanceof DOMException && error.name === "AbortError") throw new OwnerRecoveryApiError("aborted", "Recovery request was cancelled");
      throw new OwnerRecoveryApiError("transport_failed", "Recovery service is unavailable");
    }
    const payload = await readJson(response);
    if (!response.ok) throw safeError(payload, response.status);
    return payload;
  }

  async function withSession(path, options = {}) {
    const current = await getSession({ signal: options.signal });
    const payload = await requestRaw(path, { ...options, csrfToken: options.csrf === false ? undefined : current.csrfToken });
    if (options.parse) return options.parse(payload);
    return payload;
  }

  const api = {
    getSession,
    clearSession,
    getStatus: (organizationId, requestId, options = {}) => withSession(`/api/auth/organizations/${encodeURIComponent(organizationId)}/recovery-requests/${encodeURIComponent(requestId)}`, { ...options, parse: (value) => parseEnvelope(value, { allowExchange: true }) }),
    createRequest: (organizationId, options = {}) => withSession(`/api/auth/organizations/${encodeURIComponent(organizationId)}/recovery-requests`, { ...options, method: "POST", body: options.threshold === undefined ? {} : { threshold: options.threshold }, idempotencyKey: options.idempotencyKey ?? makeKey(), parse: (value) => parseEnvelope(value, { allowExchange: true }) }),
    approve: (organizationId, requestId, version, authorizationId, options = {}) => withSession(`/api/auth/organizations/${encodeURIComponent(organizationId)}/recovery-requests/${encodeURIComponent(requestId)}/approve`, { ...options, method: "POST", body: {}, ifMatch: version, recentAuth: authorizationId, idempotencyKey: options.idempotencyKey ?? makeKey(), parse: (value) => parseEnvelope(value) }),
    cancel: (organizationId, requestId, version, options = {}) => withSession(`/api/auth/organizations/${encodeURIComponent(organizationId)}/recovery-requests/${encodeURIComponent(requestId)}/cancel`, { ...options, method: "POST", body: {}, ifMatch: version, idempotencyKey: options.idempotencyKey ?? makeKey(), parse: (value) => parseEnvelope(value) }),
    exchange: async (exchangeValue, options = {}) => {
      if (!opaque(exchangeValue)) throw new OwnerRecoveryApiError("invalid_request", "The one-time exchange value is invalid");
      return parseRecoverySession(await requestRaw("/api/auth/recovery/exchange", { ...options, method: "POST", body: { exchange: exchangeValue }, csrfToken: undefined, credentials: "same-origin" }));
    },
    registrationOptions: (requestId, options = {}) => withSession("/api/auth/recovery/webauthn/registration/options", { ...options, method: "POST", body: { request_id: requestId }, idempotencyKey: options.idempotencyKey ?? makeKey(), parse: parseCeremony }),
    registrationVerify: (organizationId, challengeId, credential, options = {}) => withSession("/api/auth/recovery/webauthn/registration/verify", { ...options, method: "POST", body: { organization_id: organizationId, challenge_id: challengeId, credential }, idempotencyKey: options.idempotencyKey ?? makeKey(), parse: parseRegistrationVerified }),
    activate: (organizationId, challengeId, assertion, options = {}) => withSession("/api/auth/recovery/activate", { ...options, method: "POST", body: { organization_id: organizationId, challenge_id: challengeId, assertion }, idempotencyKey: options.idempotencyKey ?? makeKey(), parse: (value) => parseMutation(value, "activated") }),
  };
  return Object.freeze(api);
}

const ROUTES = new Map([
  ["POST /api/auth/organizations/:organizationId/recovery-requests", { session: "human", body: "create", idempotency: true }],
  ["GET /api/auth/organizations/:organizationId/recovery-requests/:requestId", { session: "human", body: "none" }],
  ["POST /api/auth/organizations/:organizationId/recovery-requests/:requestId/approve", { session: "human", body: "empty", idempotency: true, recentAuth: true, ifMatch: true }],
  ["POST /api/auth/organizations/:organizationId/recovery-requests/:requestId/cancel", { session: "human", body: "empty", idempotency: true, ifMatch: true }],
  ["POST /api/auth/recovery/exchange", { session: "none", body: "exchange" }],
  ["POST /api/auth/recovery/webauthn/registration/options", { session: "recovery", body: "registration-options", idempotency: true }],
  ["POST /api/auth/recovery/webauthn/registration/verify", { session: "recovery", body: "registration-verify", idempotency: true }],
  ["POST /api/auth/recovery/activate", { session: "recovery", body: "activate", idempotency: true }],
]);

function routeKey(pathname, method) {
  const parts = pathname.split("/").filter(Boolean);
  if (parts.length === 6 && parts[0] === "api" && parts[1] === "auth" && parts[2] === "organizations" && parts[4] === "recovery-requests") return `${method} /api/auth/organizations/:organizationId/recovery-requests`;
  if (parts.length === 7 && parts[0] === "api" && parts[1] === "auth" && parts[2] === "organizations" && parts[4] === "recovery-requests" && parts[6] === "approve") return `${method} /api/auth/organizations/:organizationId/recovery-requests/:requestId/approve`;
  if (parts.length === 7 && parts[0] === "api" && parts[1] === "auth" && parts[2] === "organizations" && parts[4] === "recovery-requests" && parts[6] === "cancel") return `${method} /api/auth/organizations/:organizationId/recovery-requests/:requestId/cancel`;
  if (parts.length === 7 && parts[0] === "api" && parts[1] === "auth" && parts[2] === "organizations" && parts[4] === "recovery-requests") return `${method} /api/auth/organizations/:organizationId/recovery-requests/:requestId`;
  if (pathname === "/api/auth/recovery/exchange") return `${method} /api/auth/recovery/exchange`;
  if (pathname === "/api/auth/recovery/webauthn/registration/options") return `${method} /api/auth/recovery/webauthn/registration/options`;
  if (pathname === "/api/auth/recovery/webauthn/registration/verify") return `${method} /api/auth/recovery/webauthn/registration/verify`;
  if (pathname === "/api/auth/recovery/activate") return `${method} /api/auth/recovery/activate`;
  return undefined;
}

function parseConfig(options) {
  const env = options.env ?? (typeof process === "undefined" ? undefined : process.env);
  const cloudUrl = options.cloudApiUrl ?? env?.AGENTPASS_CLOUD_API_URL;
  if (typeof cloudUrl !== "string" || cloudUrl.length === 0) throw new OwnerRecoveryApiError("configuration", "Recovery service is unavailable", 503);
  let url;
  try { url = new URL(cloudUrl); } catch { throw new OwnerRecoveryApiError("configuration", "Recovery service is unavailable", 503); }
  if (!/^https?:$/.test(url.protocol) || url.username || url.password || url.search || url.hash) throw new OwnerRecoveryApiError("configuration", "Recovery service is unavailable", 503);
  return { env, url };
}

async function readRequestBody(request, shape) {
  if (shape === "none") {
    const bytes = new Uint8Array(await request.arrayBuffer());
    if (bytes.byteLength !== 0) throw new OwnerRecoveryApiError("invalid_request", "The recovery request body is invalid", 400);
    return undefined;
  }
  const type = request.headers.get("content-type") ?? "";
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(type)) throw new OwnerRecoveryApiError("invalid_request", "Content-Type must be application/json", 415);
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.byteLength < 2 || bytes.byteLength > MAX_BODY_BYTES) throw new OwnerRecoveryApiError("invalid_request", "The recovery request body is invalid", 400);
  let value;
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch { throw new OwnerRecoveryApiError("invalid_request", "The recovery request body is invalid", 400); }
  if (!isRecord(value)) throw new OwnerRecoveryApiError("invalid_request", "The recovery request body is invalid", 400);
  const valid = shape === "create" && optionalExact(value, ["threshold"]) && (value.threshold === undefined || Number.isSafeInteger(value.threshold) && value.threshold >= 2 && value.threshold <= 32)
    || shape === "empty" && exact(value, [])
    || shape === "exchange" && exact(value, ["exchange"]) && opaque(value.exchange)
    || shape === "registration-options" && exact(value, ["request_id"]) && uuid(value.request_id)
    || shape === "registration-verify" && exact(value, ["organization_id", "challenge_id", "credential"]) && uuid(value.organization_id) && uuid(value.challenge_id) && isRecord(value.credential)
    || shape === "activate" && exact(value, ["organization_id", "challenge_id", "assertion"]) && uuid(value.organization_id) && uuid(value.challenge_id) && isRecord(value.assertion);
  if (!valid) throw new OwnerRecoveryApiError("invalid_request", "The recovery request body is invalid", 400);
  return value;
}

function cookieHeader(request, session) {
  const cookie = request.headers.get("cookie") ?? "";
  if (session === "none") return undefined;
  const cookieName = session === "recovery" ? "__Host-agentpass_recovery_session" : "__Host-agentpass_session";
  const allowed = cookie.split(";").map((part) => part.trim()).filter((part) => part.startsWith(`${cookieName}=`));
  if (allowed.length === 0) throw new OwnerRecoveryApiError("authentication_required", "Authentication is required", 401);
  return allowed.join("; ");
}

function jsonError(error) {
  const status = error instanceof OwnerRecoveryApiError && Number.isInteger(error.status) ? error.status : 500;
  const code = error instanceof OwnerRecoveryApiError && /^[A-Za-z0-9._-]+$/.test(error.code) ? error.code : "recovery_unavailable";
  const message = error instanceof OwnerRecoveryApiError ? error.message : "Recovery service is unavailable";
  return new Response(JSON.stringify({ error: { code, message } }), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store, max-age=0", pragma: "no-cache", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer" } });
}

function assertSecretFreePayload(value, { allowExchange = false } = {}) {
  if (Array.isArray(value)) {
    for (const item of value) assertSecretFreePayload(item, { allowExchange });
    return;
  }
  if (!isRecord(value)) return;
  for (const [key, child] of Object.entries(value)) {
    if (key === "recovery_session_token" || key === "session_token" || key === "raw_session_token" || key === "private_key" || key === "raw_assertion" || key === "attestation_object" || key === "credential_secret" || key === "bearer_token" || key === "access_token") throw new OwnerRecoveryApiError("invalid_upstream", "Recovery response was invalid", 502);
    if (!allowExchange && key === "exchange") throw new OwnerRecoveryApiError("invalid_upstream", "Recovery response was invalid", 502);
    assertSecretFreePayload(child, { allowExchange });
  }
}

export async function handleOwnerRecoveryRequest(request, options = {}) {
  try {
    const url = new URL(request.url);
    if (url.hash || url.search) throw new OwnerRecoveryApiError("invalid_request", "The recovery request URL is invalid", 400);
    const method = request.method.toUpperCase();
    const key = routeKey(url.pathname, method);
    const route = key === undefined ? undefined : ROUTES.get(key);
    if (!route) throw new OwnerRecoveryApiError("not_found", "Resource not found", 404);
    if (url.origin !== new URL(request.url).origin) throw new OwnerRecoveryApiError("origin_not_allowed", "The request origin is not allowed", 403);
    const config = parseConfig(options);
    const origin = request.headers.get("origin");
    if (origin !== url.origin || origin === "null") throw new OwnerRecoveryApiError("origin_not_allowed", "The request origin is not allowed", 403);
    const body = await readRequestBody(request, route.body);
    const headers = new Headers({ accept: "application/json", "cache-control": "no-store", origin, pragma: "no-cache" });
    const cookie = cookieHeader(request, route.session);
    if (cookie !== undefined) headers.set("cookie", cookie);
    const csrf = request.headers.get("agentpass-csrf");
    if (route.session === "human" && (!csrf || !CSRF.test(csrf))) throw new OwnerRecoveryApiError("csrf_required", "CSRF authentication is required", 403);
    if (csrf !== null && csrf !== undefined && route.session !== "none") headers.set("agentpass-csrf", csrf);
    const recentAuth = request.headers.get("agentpass-recent-auth");
    if (route.recentAuth && (!recentAuth || !uuid(recentAuth))) throw new OwnerRecoveryApiError("recent_auth_required", "Recent WebAuthn authentication is required", 401);
    if (recentAuth) headers.set("agentpass-recent-auth", recentAuth.toLowerCase());
    const idem = request.headers.get("idempotency-key");
    if (route.idempotency && !idempotency(idem)) throw new OwnerRecoveryApiError("idempotency_required", "A valid Idempotency-Key is required", 400);
    if (route.idempotency) headers.set("idempotency-key", idem);
    const ifMatch = request.headers.get("if-match");
    if (route.ifMatch && !/^"[1-9][0-9]*"$/.test(ifMatch ?? "")) throw new OwnerRecoveryApiError("if_match_required", "A valid If-Match is required", 400);
    if (route.ifMatch) headers.set("if-match", ifMatch);
    if (body !== undefined) headers.set("content-type", "application/json");
    const upstreamPath = url.pathname.replace(/^\/api\/auth/, "/api/auth");
    const response = await (options.fetchImpl ?? globalThis.fetch)(new URL(upstreamPath, config.url), { method, headers, body: body === undefined ? undefined : JSON.stringify(body), cache: "no-store", redirect: "error" });
    const payload = await readJson(response);
    assertSecretFreePayload(payload, { allowExchange: route.session === "human" });
    const outHeaders = new Headers({ "content-type": "application/json; charset=utf-8", "cache-control": "no-store, max-age=0", pragma: "no-cache", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer" });
    const setCookie = response.headers.get("set-cookie");
    if (setCookie !== null) {
      if (!/^__Host-agentpass_recovery_session=[A-Za-z0-9_-]{43,512}; Path=\/; HttpOnly; Secure; SameSite=Strict(?:; Max-Age=(?:0|[1-9][0-9]*))?$/.test(setCookie)) throw new OwnerRecoveryApiError("invalid_upstream", "Recovery response was invalid", 502);
      outHeaders.set("set-cookie", setCookie);
    }
    return new Response(JSON.stringify(payload), { status: response.status, headers: outHeaders });
  } catch (error) {
    return jsonError(error);
  }
}
