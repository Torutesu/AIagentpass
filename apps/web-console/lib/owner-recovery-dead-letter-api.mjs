const MAX_RESPONSE_BYTES = 256 * 1024;
const MAX_BODY_BYTES = 16 * 1024;
const DEFAULT_LIMIT = 25;
const MAX_LIMIT = 100;
const MAX_CURSOR_LENGTH = 512;
const MAX_REASON_BYTES = 128;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const OPAQUE = /^[A-Za-z0-9_-]{1,512}$/;
const CSRF = /^[A-Za-z0-9_-]{43,512}$/;
const IDEMPOTENCY = /^[A-Za-z0-9][A-Za-z0-9._~-]{7,254}$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const EVENT_TYPE = /^[A-Za-z][A-Za-z0-9._:-]{0,127}$/;
const ERROR_CODE = /^[a-z][a-z0-9_]{0,127}$/;
const DEAD_LETTER_KEYS = ["organization_id", "event_id", "request_id", "subject_member_id", "event_type", "status", "attempts", "total_attempts", "management_version", "redrive_count", "last_error_code", "created_at", "updated_at", "suppressed_at", "suppression_reason"];
const MUTATION_KEYS = ["organization_id", "event_id", "status", "attempts", "total_attempts", "management_version", "redrive_count", "suppressed_at", "suppression_reason"];

export const OWNER_RECOVERY_DEAD_LETTER_PATHS = Object.freeze({
  list: (organizationId) => `/api/auth/organizations/${encodeURIComponent(organizationId)}/recovery-outbox/dead-letters`,
  redrive: (organizationId, eventId) => `/api/auth/organizations/${encodeURIComponent(organizationId)}/recovery-outbox/dead-letters/${encodeURIComponent(eventId)}/redrive`,
  suppress: (organizationId, eventId) => `/api/auth/organizations/${encodeURIComponent(organizationId)}/recovery-outbox/dead-letters/${encodeURIComponent(eventId)}/suppress`,
});

export class OwnerRecoveryDeadLetterApiError extends Error {
  constructor(code, message, status, serverCode) {
    super(message);
    this.name = "OwnerRecoveryDeadLetterApiError";
    this.code = code;
    this.status = status;
    this.serverCode = serverCode;
  }
}

function isRecord(value) { return Boolean(value) && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) {
  if (!isRecord(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}
function uuid(value) { return typeof value === "string" && UUID.test(value); }
function requiredUuid(value, name) {
  if (!uuid(value)) throw new OwnerRecoveryDeadLetterApiError("invalid_request", `The ${name} is invalid`);
  return value.toLowerCase();
}
function timestamp(value) { return typeof value === "string" && RFC3339.test(value) && Number.isFinite(Date.parse(value)); }
function boundedInteger(value, name, { min = 0 } = {}) {
  if (!Number.isSafeInteger(value) || value < min) throw new OwnerRecoveryDeadLetterApiError("invalid_request", `The ${name} is invalid`);
  return value;
}
function validCursor(value) { return typeof value === "string" && value.length <= MAX_CURSOR_LENGTH && OPAQUE.test(value); }
function byteLength(value) { return new TextEncoder().encode(value).byteLength; }
function hasControl(value) { return [...value].some((character) => { const code = character.codePointAt(0) ?? 0; return code <= 0x1f || code === 0x7f; }); }
function validReason(value) { return typeof value === "string" && value.length >= 1 && value.trim() === value && byteLength(value) <= MAX_REASON_BYTES && !hasControl(value); }

function invalidResponse() { return new OwnerRecoveryDeadLetterApiError("invalid_response", "Recovery outbox response was invalid"); }

function parseDeadLetter(value, organizationId, { mutation = false } = {}) {
  const keys = mutation ? MUTATION_KEYS : DEAD_LETTER_KEYS;
  if (!exact(value, keys)) throw invalidResponse();
  if (!uuid(value.organization_id) || value.organization_id.toLowerCase() !== organizationId || !uuid(value.event_id)) throw invalidResponse();
  if (!mutation && (!uuid(value.request_id) || !uuid(value.subject_member_id) || !EVENT_TYPE.test(value.event_type) || value.status !== "dead_letter" || !ERROR_CODE.test(value.last_error_code) || !timestamp(value.created_at) || !timestamp(value.updated_at))) throw invalidResponse();
  if (mutation && value.status !== "pending" && value.status !== "suppressed") throw invalidResponse();
  if (!Number.isSafeInteger(value.attempts) || value.attempts < 0 || !Number.isSafeInteger(value.total_attempts) || value.total_attempts < 0 || !Number.isSafeInteger(value.management_version) || value.management_version < 1 || !Number.isSafeInteger(value.redrive_count) || value.redrive_count < 0) throw invalidResponse();
  if (value.suppressed_at !== null && !timestamp(value.suppressed_at)) throw invalidResponse();
  if (value.suppression_reason !== null && (!validReason(value.suppression_reason))) throw invalidResponse();
  if (mutation && value.status === "pending" && (value.suppressed_at !== null || value.suppression_reason !== null)) throw invalidResponse();
  return Object.freeze({
    organizationId: value.organization_id.toLowerCase(), eventId: value.event_id.toLowerCase(),
    ...(mutation ? {} : { requestId: value.request_id.toLowerCase(), subjectMemberId: value.subject_member_id.toLowerCase(), eventType: value.event_type }),
    status: value.status, attempts: value.attempts, totalAttempts: value.total_attempts, managementVersion: value.management_version, redriveCount: value.redrive_count,
    ...(mutation ? {} : { lastErrorCode: value.last_error_code, createdAt: value.created_at, updatedAt: value.updated_at }),
    suppressedAt: value.suppressed_at, suppressionReason: value.suppression_reason,
  });
}

function parseList(value, organizationId, limit) {
  if (!exact(value, ["dead_letters", "next_cursor"]) || !Array.isArray(value.dead_letters) || value.dead_letters.length > limit || (value.next_cursor !== null && !validCursor(value.next_cursor))) throw invalidResponse();
  return Object.freeze({ items: Object.freeze(value.dead_letters.map((item) => parseDeadLetter(item, organizationId))), nextCursor: value.next_cursor });
}
function parseMutation(value, organizationId, eventId) {
  if (!exact(value, ["dead_letter"])) throw invalidResponse();
  const parsed = parseDeadLetter(value.dead_letter, organizationId, { mutation: true });
  if (parsed.eventId !== eventId) throw invalidResponse();
  return Object.freeze({ deadLetter: parsed });
}
function parseSession(value) {
  if (!exact(value, ["session", "csrf_token"]) || !isRecord(value.session)) throw invalidResponse();
  const keys = ["session_id", "member_id", "organization_id", "role", "created_at", "expires_at", "recent_auth_at"];
  if (!exact(value.session, keys) || !uuid(value.session.session_id) || !uuid(value.session.member_id) || !uuid(value.session.organization_id) || !["owner", "admin", "auditor", "viewer"].includes(value.session.role) || !timestamp(value.session.created_at) || !timestamp(value.session.expires_at) || (value.session.recent_auth_at !== null && !timestamp(value.session.recent_auth_at)) || !CSRF.test(value.csrf_token)) throw invalidResponse();
  return Object.freeze({ csrfToken: value.csrf_token, organizationId: value.session.organization_id.toLowerCase() });
}

async function readJson(response) {
  const type = response.headers?.get("content-type") ?? "";
  if (!/^application\/json(?:\s*;|\s*$)/i.test(type)) throw invalidResponse();
  const length = response.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_RESPONSE_BYTES)) throw invalidResponse();
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength > MAX_RESPONSE_BYTES) throw invalidResponse();
  try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch { throw invalidResponse(); }
}
function safeError(value, status) {
  if (!exact(value, ["error"]) || !isRecord(value.error) || !exact(value.error, ["code", "message"]) || typeof value.error.code !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(value.error.code) || typeof value.error.message !== "string" || value.error.message.length > 512 || hasControl(value.error.message)) return invalidResponse();
  const code = status === 409 ? "conflict" : status === 401 ? "authentication_required" : status === 403 ? "forbidden" : status === 404 ? "not_found" : status === 429 ? "rate_limited" : status >= 500 ? "service_unavailable" : "http_failed";
  const message = code === "conflict" ? "The recovery outbox item could not be changed" : code === "authentication_required" ? "Authentication is required" : code === "forbidden" ? "The recovery outbox operation is not allowed" : code === "not_found" ? "Resource not found" : code === "rate_limited" ? "Too many requests" : code === "service_unavailable" ? "Recovery outbox service is unavailable" : "The recovery outbox request was rejected";
  return new OwnerRecoveryDeadLetterApiError(code, message, status, value.error.code);
}
function makeKey() { return typeof globalThis.crypto?.randomUUID === "function" ? globalThis.crypto.randomUUID() : `recovery-outbox-${Date.now()}-${Math.random().toString(36).slice(2)}`; }

export async function ownerRecoveryDeadLetterContextHash({ organizationId, eventId, action, expectedManagementVersion, cryptoImpl = globalThis.crypto } = {}) {
  const organization = requiredUuid(organizationId, "organizationId");
  const event = requiredUuid(eventId, "eventId");
  if (action !== "redrive" && action !== "suppress") throw new OwnerRecoveryDeadLetterApiError("invalid_request", "The recovery outbox action is invalid");
  const version = boundedInteger(expectedManagementVersion, "expectedManagementVersion", { min: 1 });
  if (!cryptoImpl?.subtle || typeof cryptoImpl.subtle.digest !== "function") throw new OwnerRecoveryDeadLetterApiError("crypto_unavailable", "Recovery outbox authentication is unavailable");
  const canonical = JSON.stringify({
    action,
    event_id: event,
    expected_management_version: version,
    organization_id: organization,
    version: 1
  });
  const digest = new Uint8Array(await cryptoImpl.subtle.digest("SHA-256", new TextEncoder().encode(canonical)));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function createOwnerRecoveryDeadLetterClient({ fetchImpl = globalThis.fetch, sessionPath = "/api/auth/session" } = {}) {
  if (typeof fetchImpl !== "function") throw new TypeError("fetchImpl must be a function");
  let session;
  let sessionPromise;
  async function getSession({ signal } = {}) {
    if (session) return session;
    if (!sessionPromise) {
      sessionPromise = requestRaw(sessionPath, { method: "POST", body: {}, signal }).then((value) => {
        session = parseSession(value);
        sessionPromise = undefined;
        return session;
      }, (error) => { sessionPromise = undefined; throw error; });
    }
    return sessionPromise;
  }
  function clearSession() { session = undefined; }
  async function requestRaw(path, { method = "GET", body, signal, csrfToken, recentAuth, idempotencyKey, ifMatch } = {}) {
    const headers = new Headers({ accept: "application/json", "cache-control": "no-store", pragma: "no-cache" });
    if (body !== undefined) {
      const serialized = JSON.stringify(body);
      if (byteLength(serialized) > MAX_BODY_BYTES) throw new OwnerRecoveryDeadLetterApiError("invalid_request", "The recovery outbox request is too large");
      headers.set("content-type", "application/json");
    }
    if (csrfToken !== undefined) headers.set("agentpass-csrf", csrfToken);
    if (recentAuth !== undefined) headers.set("agentpass-recent-auth", recentAuth.toLowerCase());
    if (idempotencyKey !== undefined) headers.set("idempotency-key", idempotencyKey);
    if (ifMatch !== undefined) headers.set("if-match", `"${ifMatch}"`);
    let response;
    try { response = await fetchImpl(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), cache: "no-store", credentials: "same-origin", redirect: "error", signal }); }
    catch (error) {
      if (signal?.aborted || error instanceof DOMException && error.name === "AbortError") throw new OwnerRecoveryDeadLetterApiError("aborted", "Recovery outbox request was cancelled");
      throw new OwnerRecoveryDeadLetterApiError("transport_failed", "Recovery outbox service is unavailable");
    }
    const payload = await readJson(response);
    if (!response.ok) throw safeError(payload, response.status);
    return payload;
  }
  async function withSession(path, options = {}) {
    const current = await getSession({ signal: options.signal });
    return requestRaw(path, { ...options, csrfToken: current.csrfToken });
  }
  async function listDeadLetters(organizationId, options = {}) {
    const organization = requiredUuid(organizationId, "organizationId");
    const limit = options.limit === undefined ? DEFAULT_LIMIT : boundedInteger(options.limit, "limit", { min: 1 });
    if (limit > MAX_LIMIT) throw new OwnerRecoveryDeadLetterApiError("invalid_request", "The limit is invalid");
    if (options.cursor !== undefined && !validCursor(options.cursor)) throw new OwnerRecoveryDeadLetterApiError("invalid_request", "The cursor is invalid");
    const query = new URLSearchParams({ limit: String(limit) });
    if (options.cursor !== undefined) query.set("cursor", options.cursor);
    return parseList(await withSession(`${OWNER_RECOVERY_DEAD_LETTER_PATHS.list(organization)}?${query}`, { method: "GET", signal: options.signal }), organization, limit);
  }
  async function redriveDeadLetter(organizationId, eventId, expectedManagementVersion, recentAuth, options = {}) {
    const organization = requiredUuid(organizationId, "organizationId");
    const event = requiredUuid(eventId, "eventId");
    const version = boundedInteger(expectedManagementVersion, "expectedManagementVersion", { min: 1 });
    if (!uuid(recentAuth)) throw new OwnerRecoveryDeadLetterApiError("invalid_request", "The recent authentication is invalid");
    const idempotencyKey = options.idempotencyKey ?? makeKey();
    if (!IDEMPOTENCY.test(idempotencyKey)) throw new OwnerRecoveryDeadLetterApiError("invalid_request", "The idempotency key is invalid");
    return parseMutation(await withSession(OWNER_RECOVERY_DEAD_LETTER_PATHS.redrive(organization, event), { method: "POST", body: {}, signal: options.signal, recentAuth, idempotencyKey, ifMatch: version }), organization, event);
  }
  async function suppressDeadLetter(organizationId, eventId, expectedManagementVersion, reason, recentAuth, options = {}) {
    const organization = requiredUuid(organizationId, "organizationId");
    const event = requiredUuid(eventId, "eventId");
    const version = boundedInteger(expectedManagementVersion, "expectedManagementVersion", { min: 1 });
    if (!validReason(reason)) throw new OwnerRecoveryDeadLetterApiError("invalid_request", "The suppression reason is invalid");
    if (!uuid(recentAuth)) throw new OwnerRecoveryDeadLetterApiError("invalid_request", "The recent authentication is invalid");
    const idempotencyKey = options.idempotencyKey ?? makeKey();
    if (!IDEMPOTENCY.test(idempotencyKey)) throw new OwnerRecoveryDeadLetterApiError("invalid_request", "The idempotency key is invalid");
    return parseMutation(await withSession(OWNER_RECOVERY_DEAD_LETTER_PATHS.suppress(organization, event), { method: "POST", body: { reason }, signal: options.signal, recentAuth, idempotencyKey, ifMatch: version }), organization, event);
  }
  return Object.freeze({ getSession, clearSession, listDeadLetters, redriveDeadLetter, suppressDeadLetter, list: listDeadLetters, redrive: redriveDeadLetter, suppress: suppressDeadLetter });
}
