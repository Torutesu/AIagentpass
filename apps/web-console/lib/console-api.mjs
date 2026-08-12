const MAX_BYTES = 256 * 1024;
const DEFAULT_TIMEOUT_MS = 8_000;
const MAX_TIMEOUT_MS = 30_000;
const MAX_CURSOR_LENGTH = 512;
// This is the size of one Cloud page, not a completeness limit. A page that
// returns this many events is still traversable when next_cursor is present.
const ACTIVITY_PAGE_LIMIT = 500;
const ACTIVITY_MAX_UPSTREAM_REQUESTS = 64;
const ACTIVITY_MAX_ACCUMULATED_RECORDS = 8_192;
const UPSTREAM_CURSOR_PATTERN = /^[A-Za-z0-9_-]{1,512}$/;
const ACTIVITY_CURSOR_VERSION = 1;
const ACTIVITY_CURSOR_PATTERN = /^[A-Za-z0-9_-]{1,512}\.[A-Za-z0-9_-]{1,512}\.[A-Za-z0-9_-]{1,512}$/;
const UUID_OR_OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SESSION_COOKIE_NAME = "__Host-agentpass_session";
const OPAQUE_TOKEN = /^[A-Za-z0-9_-]{43}$/;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const SAFE_ERROR_CODE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const SENSITIVE_KEY = /(?:authorization|bearer|cookie|credential|password|private[_-]?key|refresh[_-]?token|secret|session[_-]?token|access[_-]?token|api[_-]?token)/i;
const SIWC_HEADERS = [
  "oai-authenticated-user-id",
  "oai-authenticated-user-email",
  "oai-authenticated-user-full-name",
  "oai-authenticated-user-full-name-encoding",
];

export class ConsoleApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "ConsoleApiError";
    this.status = status;
    this.code = code;
  }
}

class CloudResponseError extends Error {
  constructor(status, body, secrets) {
    super("Cloud API request failed");
    this.name = "CloudResponseError";
    this.status = status;
    this.body = body;
    this.secrets = secrets;
  }
}

/**
 * The route uses this factory in production and tests use the same entry point
 * with a fake fetch and an explicit server environment.
 */
export function createConsoleApi(options = {}) {
  return Object.freeze({
    handle(request) {
      return handleConsoleRequest(request, options);
    },
  });
}

export async function handleConsoleRequest(request, options = {}) {
  try {
    ensureSameOrigin(request);
    let config = await readConfig(options.env);
    if (config.authMode === "human-session") {
      const authorization = requireHumanSessionAuthorization(request);
      config = { ...config, authorization, secrets: [...config.secrets, authorization.cookie] };
    } else {
      const user = await requireAuthenticatedUser(request, options);
      if (!config.operatorUserIds.has(user.userId)) {
        throw new ConsoleApiError(403, "operator_access_denied", "Operator access is denied");
      }
    }
    const fetchImpl = options.fetchImpl ?? options.fetch ?? globalThis.fetch;
    if (typeof fetchImpl !== "function") {
      throw new ConsoleApiError(503, "cloud_api_unavailable", "Cloud API is unavailable");
    }

    if (request.method === "GET") {
      const query = parseQuery(new URL(request.url).searchParams, "GET");
      const result = await getResource(query, config, fetchImpl, options);
      const status = result?.__consoleStatus ?? 200;
      const payload = result?.__consoleBody ?? result;
      return makeJsonResponse(status, payload, config);
    }

    if (request.method === "POST") {
      const query = parseQuery(new URL(request.url).searchParams, "POST");
      const idempotencyKey = request.headers.get("idempotency-key");
      if (!idempotencyKey || !IDEMPOTENCY_KEY.test(idempotencyKey)) {
        throw new ConsoleApiError(400, "idempotency_key_required", "A valid Idempotency-Key is required");
      }
      const body = await readJsonBody(request);
      const recentAuth = request.headers.get("agentpass-recent-auth");
      const payload = await postOperation(query, body, idempotencyKey, config, fetchImpl, options, recentAuth);
      return payload.oneTimeEnrollment
        ? makeOneTimeEnrollmentResponse(payload.status, payload.body)
        : makeJsonResponse(payload.status, payload.body, config);
    }

    throw new ConsoleApiError(405, "method_not_allowed", "Method not allowed");
  } catch (error) {
    return errorResponse(error);
  }
}

async function requireAuthenticatedUser(request, options) {
  if (typeof options.getSiwcUser !== "function") {
    throw new ConsoleApiError(401, "authentication_required", "Authentication is required");
  }

  let user;
  try {
    user = await options.getSiwcUser(request);
  } catch {
    user = null;
  }
  if (!user || typeof user !== "object" || typeof user.userId !== "string" || !user.userId || typeof user.email !== "string" || !user.email) {
    throw new ConsoleApiError(401, "authentication_required", "Authentication is required");
  }
  return user;
}

function requireHumanSessionAuthorization(request) {
  const cookie = normalizeSessionCookie(request.headers.get("cookie"));
  const requestOrigin = new URL(request.url).origin;
  const csrf = request.headers.get("agentpass-csrf");
  if (request.method === "POST") {
    if (request.headers.get("origin") !== requestOrigin) throw new ConsoleApiError(403, "same_origin_required", "Same-origin request required");
    if (!OPAQUE_TOKEN.test(csrf ?? "")) throw new ConsoleApiError(403, "csrf_required", "CSRF authentication is required");
  } else if (csrf !== null) {
    throw new ConsoleApiError(400, "invalid_csrf", "CSRF authentication is not allowed");
  }
  return Object.freeze({ cookie, origin: requestOrigin, ...(csrf === null ? {} : { csrf }) });
}

function normalizeSessionCookie(cookieHeader) {
  if (typeof cookieHeader !== "string" || cookieHeader.length < 1 || cookieHeader.length > 8192 || hasControlCharacters(cookieHeader)) {
    throw new ConsoleApiError(401, "session_required", "An active session is required");
  }
  let token;
  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 1) {
      if (part.trim() !== "") throw new ConsoleApiError(400, "invalid_cookie", "The session cookie is invalid");
      continue;
    }
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (name !== SESSION_COOKIE_NAME) continue;
    if (token !== undefined || !OPAQUE_TOKEN.test(value)) throw new ConsoleApiError(400, "invalid_cookie", "The session cookie is invalid");
    token = value;
  }
  if (token === undefined) throw new ConsoleApiError(401, "session_required", "An active session is required");
  return `${SESSION_COOKIE_NAME}=${token}`;
}

export function hasForwardedSiwcHeaders(request) {
  return SIWC_HEADERS.some((name) => request.headers.has(name));
}

function ensureSameOrigin(request) {
  const requestOrigin = new URL(request.url).origin;
  const origin = request.headers.get("origin");
  if (origin !== null && origin !== requestOrigin) {
    throw new ConsoleApiError(403, "same_origin_required", "Same-origin request required");
  }

  const referer = request.headers.get("referer");
  if (referer !== null) {
    let refererOrigin;
    try {
      refererOrigin = new URL(referer).origin;
    } catch {
      refererOrigin = null;
    }
    if (refererOrigin !== requestOrigin) {
      throw new ConsoleApiError(403, "same_origin_required", "Same-origin request required");
    }
  }

  const fetchSite = request.headers.get("sec-fetch-site");
  if (fetchSite !== null && fetchSite !== "same-origin") {
    throw new ConsoleApiError(403, "same_origin_required", "Same-origin request required");
  }
}

function parseQuery(params, method) {
  const allowed = new Set(["resource", "operation", "device_id", "limit", "cursor"]);
  const seen = new Set();
  for (const [key] of params) {
    if (!allowed.has(key) || seen.has(key)) {
      throw new ConsoleApiError(400, "invalid_query", "Query parameters are invalid");
    }
    seen.add(key);
  }

  const resource = params.get("resource");
  const operation = params.get("operation");
  if (method === "GET" && operation !== null) {
    throw new ConsoleApiError(400, "invalid_query", "Query parameters are invalid");
  }
  if (method === "POST" && resource !== null && operation !== null) {
    throw new ConsoleApiError(400, "invalid_query", "Query parameters are invalid");
  }

  const limitValue = params.get("limit");
  let limit = 100;
  if (limitValue !== null) {
    if (!/^[1-9]\d{0,2}$/.test(limitValue) || Number(limitValue) > 500) {
      throw new ConsoleApiError(400, "invalid_query", "Query parameters are invalid");
    }
    limit = Number(limitValue);
  }

  const deviceId = params.get("device_id");
  if (deviceId !== null && !UUID_OR_OPAQUE_ID.test(deviceId)) {
    throw new ConsoleApiError(400, "invalid_query", "Query parameters are invalid");
  }

  const cursor = params.get("cursor");
  if (cursor !== null && (!ACTIVITY_CURSOR_PATTERN.test(cursor) || cursor.length > MAX_CURSOR_LENGTH)) {
    throw new ConsoleApiError(400, "invalid_query", "Query parameters are invalid");
  }

  return { resource, operation, deviceId, limit, cursor };
}

async function getResource(query, config, fetchImpl, options) {
  const resource = normalizeResource(query.resource);
  if (query.cursor !== null && !["summary", "audit", "activity"].includes(resource)) {
    throw new ConsoleApiError(400, "invalid_query", "Query parameters are invalid");
  }
  if (resource === "summary") return getSummary(query, config, fetchImpl, options);
  if (resource === "organization") return getSimple(query, "organization", config, fetchImpl, options);
  if (resource === "devices") return getSimple(query, "devices", config, fetchImpl, options);
  if (resource === "agents") return getSimple(query, "agents", config, fetchImpl, options);
  if (resource === "policies") return getSimple(query, "policies", config, fetchImpl, options);
  if (resource === "capabilities") return getSimple(query, "capabilities", config, fetchImpl, options);
  if (resource === "revocations") return getSimple(query, "revocations", config, fetchImpl, options);
  if (resource === "admin-audit") return getSimple(query, "admin-audit", config, fetchImpl, options);
  if (resource === "audit-health") return getSimple(query, "audit-health", config, fetchImpl, options);

  if (resource === "audit" || resource === "activity" || resource === "health") {
    if (resource === "health" && query.cursor !== null) {
      throw new ConsoleApiError(400, "invalid_query", "Query parameters are invalid");
    }
    const audit = await getAudit(query, config, fetchImpl, options, undefined, resource);
    if (resource === "activity") return { activity: audit.activity, next_cursor: audit.next_cursor };
    if (resource === "health") return { health: audit.health };
    return audit;
  }

  throw new ConsoleApiError(400, "invalid_resource", "Resource is invalid");
}

async function getSummary(query, config, fetchImpl, options) {
  const [organization, devices, agents, policies] = await Promise.all([
    cloudRequest("GET", "", undefined, config, fetchImpl, options),
    cloudRequest("GET", "/devices", undefined, config, fetchImpl, options),
    cloudRequest("GET", "/agents", undefined, config, fetchImpl, options),
    cloudRequest("GET", "/policies", undefined, config, fetchImpl, options),
  ]);
  const audit = await getAudit({ ...query, deviceId: query.deviceId }, config, fetchImpl, options, devices, "summary");

  return {
    organization: organization.organization,
    devices: devices.devices,
    agents: agents.agents,
    policies: policies.policies,
    audit: {
      health: audit.health,
      activity: audit.activity,
      next_cursor: audit.next_cursor,
    },
  };
}

async function getSimple(query, resource, config, fetchImpl, options) {
  const paths = {
    organization: "",
    devices: "/devices",
    agents: "/agents",
    policies: "/policies",
    capabilities: "/capabilities",
    revocations: "/revocations",
    "admin-audit": "/audit/admin-events",
    "audit-health": "/audit/health",
  };
  const suffix = resource === "capabilities" || resource === "revocations" || resource === "admin-audit"
    ? `${paths[resource]}?limit=${queryLimit(query)}`
    : paths[resource];
  const result = await cloudRequest("GET", suffix, undefined, config, fetchImpl, options, undefined, true);
  return { __consoleStatus: result.status, __consoleBody: result.body };
}

function queryLimit(query) {
  return Number.isSafeInteger(query?.limit) && query.limit >= 1 && query.limit <= 500 ? query.limit : 100;
}

async function getAudit(query, config, fetchImpl, options, devicesPayload = undefined, cursorResource = "audit") {
  const cursor = query.cursor === null ? null : await decodeActivityCursor(query.cursor, config, cursorResource, query.deviceId);
  let devices = devicesPayload;
  if (!devices) {
    devices = await cloudRequest("GET", "/devices", undefined, config, fetchImpl, options);
  }

  const deviceIds = query.deviceId
    ? [query.deviceId]
    : Array.isArray(devices.devices)
      ? devices.devices.map((device) => device?.device_id).filter((id) => typeof id === "string").sort()
      : [];

  const requestedScope = query.deviceId ?? "all";
  if (cursor && cursor.scope !== requestedScope) {
    throw new ConsoleApiError(400, "invalid_cursor", "Cursor is invalid");
  }
  if (cursor) {
    const scopeDigest = await digestText(JSON.stringify({ scope: requestedScope, device_ids: [...deviceIds].sort() }));
    if (scopeDigest !== cursor.scope_digest) {
      throw new ConsoleApiError(409, "activity_cursor_stale", "Activity cursor is no longer valid");
    }
  }

  const [streams, healthPayload] = await Promise.all([
    loadActivityStreams({
      deviceIds,
      position: cursor?.position ?? null,
      config,
      fetchImpl,
      options,
      limit: query.limit,
    }),
    cloudRequest("GET", "/audit/health", undefined, config, fetchImpl, options),
  ]);
  const records = mergeActivityRecords(streams);
  const visibleRecords = cursor
    ? records.filter((record) => compareActivityTuple(record.tuple, cursor.position) < 0)
    : records;
  visibleRecords.sort((left, right) => compareActivityTuple(right.tuple, left.tuple));
  const pageRecords = visibleRecords.slice(0, query.limit + 1);
  const hasMore = pageRecords.length > query.limit;
  const activity = pageRecords.slice(0, query.limit).map((record) => record.value);
  const nextCursor = hasMore
    ? await encodeActivityCursor({
      config,
      resource: cursorResource,
      scope: requestedScope,
      scopeDigest: await digestText(JSON.stringify({ scope: requestedScope, device_ids: [...deviceIds].sort() })),
      position: pageRecords[query.limit - 1].tuple,
    })
    : null;

  const authoritativeHealth = new Map((Array.isArray(healthPayload.health) ? healthPayload.health : []).map((item) => [item.device_id, item]));
  const health = deviceIds.map((deviceId, index) => {
    const events = streams[index].records;
    const last = events.at(-1)?.value ?? null;
    return {
      device_id: deviceId,
      ...(authoritativeHealth.get(deviceId) ?? { chain_status: "unknown", gap_count: 0, last_event_id: null, last_hash: null }),
      event_count: events.length,
      last_event_id: authoritativeHealth.get(deviceId)?.last_event_id ?? last?.event_id ?? last?.event?.event_id ?? null,
      last_hash: authoritativeHealth.get(deviceId)?.last_hash ?? last?.event_hash ?? last?.event?.event_hash ?? null,
    };
  });

  return { health, activity, next_cursor: nextCursor };
}

async function loadActivityStreams({ deviceIds, position, config, fetchImpl, options, limit }) {
  const budget = { requests: 0, records: 0 };
  const streams = deviceIds.map((deviceId) => ({
    deviceId,
    records: [],
    nextCursor: null,
    terminal: false,
    requestedCursors: new Set(),
  }));

  await Promise.all(streams.map((stream) => loadNextActivityPage(stream, { config, fetchImpl, options, budget })));

  // A k-way merge is complete once we have limit + 1 candidates and every
  // non-terminal stream has reached at least the current cutoff. If the
  // requested page has fewer candidates, all streams must be exhausted. This
  // is what removes the old "exactly 500 means unsafe" assumption.
  while (true) {
    const records = mergeActivityRecords(streams);
    const candidates = position === null
      ? records
      : records.filter((record) => compareActivityTuple(record.tuple, position) < 0);
    candidates.sort((left, right) => compareActivityTuple(right.tuple, left.tuple));
    const cutoff = candidates.length > limit ? candidates[limit].tuple : null;
    const pending = streams.filter((stream) => {
      if (stream.terminal) return false;
      if (cutoff === null) return true;
      const oldest = stream.records[0]?.tuple;
      return oldest === undefined || compareActivityTuple(oldest, cutoff) > 0;
    });
    if (pending.length === 0) return streams.map((stream) => Object.freeze({
      deviceId: stream.deviceId,
      records: stream.records,
    }));
    await Promise.all(pending.map((stream) => loadNextActivityPage(stream, { config, fetchImpl, options, budget })));
  }
}

async function loadNextActivityPage(stream, { config, fetchImpl, options, budget }) {
  if (stream.terminal) return;
  const requestedCursor = stream.nextCursor;
  if (requestedCursor !== null) {
    if (stream.requestedCursors.has(requestedCursor)) {
      throw new ConsoleApiError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
    }
    stream.requestedCursors.add(requestedCursor);
  }
  if (budget.requests >= ACTIVITY_MAX_UPSTREAM_REQUESTS) {
    throw new ConsoleApiError(502, "activity_pagination_budget_exceeded", "Activity pagination budget exceeded");
  }
  budget.requests += 1;
  const cursorQuery = requestedCursor === null ? "" : `&cursor=${encodeURIComponent(requestedCursor)}`;
  const payload = await cloudRequest(
    "GET",
    `/audit/events?device_id=${encodeURIComponent(stream.deviceId)}&limit=${ACTIVITY_PAGE_LIMIT}${cursorQuery}`,
    undefined,
    config,
    fetchImpl,
    options,
  );
  const page = normalizeActivityStream(payload, stream.deviceId);
  if (budget.records + page.records.length > ACTIVITY_MAX_ACCUMULATED_RECORDS) {
    throw new ConsoleApiError(502, "activity_pagination_budget_exceeded", "Activity pagination budget exceeded");
  }
  budget.records += page.records.length;
  stream.records.push(...page.records);
  stream.records.sort((left, right) => compareActivityTuple(left.tuple, right.tuple));
  stream.nextCursor = page.nextCursor;
  stream.terminal = page.nextCursor === null;
}

function normalizeActivityStream(payload, deviceId) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload) || !Array.isArray(payload.events)) {
    throw new ConsoleApiError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  }
  const events = payload.events;
  if (events.length > ACTIVITY_PAGE_LIMIT) {
    throw new ConsoleApiError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  }
  const nextCursor = payload.next_cursor === undefined || payload.next_cursor === null ? null : payload.next_cursor;
  if (nextCursor !== null && (typeof nextCursor !== "string" || !UPSTREAM_CURSOR_PATTERN.test(nextCursor))) {
    throw new ConsoleApiError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  }
  const seen = new Set();
  const records = events.map((event) => {
    if (!event || typeof event !== "object" || Array.isArray(event)) {
      throw new ConsoleApiError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
    }
    const source = event.event && typeof event.event === "object" && !Array.isArray(event.event) ? event.event : event;
    const eventDeviceId = event.device_id ?? source.device_id ?? deviceId;
    const eventId = event.event_id ?? source.event_id;
    const timestamp = normalizeActivityTimestamp(source.device_timestamp ?? event.device_timestamp);
    if (eventDeviceId !== deviceId || typeof eventDeviceId !== "string" || !UUID_OR_OPAQUE_ID.test(eventDeviceId)
      || typeof eventId !== "string" || !UUID_OR_OPAQUE_ID.test(eventId)) {
      throw new ConsoleApiError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
    }
    const tuple = { t: timestamp, d: eventDeviceId, e: eventId };
    const key = JSON.stringify(tuple);
    if (seen.has(key)) throw new ConsoleApiError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
    seen.add(key);
    return { value: { ...event, device_id: eventDeviceId }, tuple };
  });
  records.sort((left, right) => compareActivityTuple(left.tuple, right.tuple));
  return Object.freeze({ deviceId, records, nextCursor });
}

function mergeActivityRecords(streams) {
  const recordsByIdentity = new Map();
  for (const stream of streams) {
    for (const record of stream.records) {
      const identity = `${record.tuple.d}\u0000${record.tuple.e}`;
      const previous = recordsByIdentity.get(identity);
      if (previous !== undefined) {
        if (compareActivityTuple(previous.tuple, record.tuple) !== 0) {
          throw new ConsoleApiError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
        }
        continue;
      }
      recordsByIdentity.set(identity, record);
    }
  }
  return [...recordsByIdentity.values()].sort((left, right) => compareActivityTuple(left.tuple, right.tuple));
}

function normalizeActivityTimestamp(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value)) {
    throw new ConsoleApiError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  }
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) throw new ConsoleApiError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  return new Date(timestamp).toISOString();
}

function compareActivityTuple(left, right) {
  const timestamp = left.t.localeCompare(right.t);
  if (timestamp !== 0) return timestamp;
  const device = left.d.localeCompare(right.d);
  if (device !== 0) return device;
  return left.e.localeCompare(right.e);
}

async function encodeActivityCursor({ config, resource, scope, scopeDigest, position }) {
  const payload = JSON.stringify({ v: ACTIVITY_CURSOR_VERSION, r: resource, o: config.organizationId, s: scope, d: scopeDigest, p: position });
  const encodedPayload = base64UrlEncode(new TextEncoder().encode(payload));
  const signature = await signActivityCursor(encodedPayload, config);
  const cursor = `v1.${encodedPayload}.${signature}`;
  if (cursor.length > MAX_CURSOR_LENGTH) throw new ConsoleApiError(502, "activity_cursor_unavailable", "Activity cursor is unavailable");
  return cursor;
}

async function decodeActivityCursor(cursor, config, resource, deviceId) {
  if (cursor === null) return null;
  if (typeof cursor !== "string" || !ACTIVITY_CURSOR_PATTERN.test(cursor) || cursor.length > MAX_CURSOR_LENGTH) {
    throw new ConsoleApiError(400, "invalid_cursor", "Cursor is invalid");
  }
  const [version, encodedPayload, signature] = cursor.split(".");
  if (version !== "v1" || !(await verifyActivityCursor(encodedPayload, signature, config))) {
    throw new ConsoleApiError(400, "invalid_cursor", "Cursor is invalid");
  }
  let payload;
  try {
    const bytes = base64UrlDecode(encodedPayload);
    if (bytes.byteLength > 2048) throw new Error("cursor payload too large");
    payload = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new ConsoleApiError(400, "invalid_cursor", "Cursor is invalid");
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)
    || Object.keys(payload).sort().join(",") !== "d,o,p,r,s,v"
    || Object.keys(payload.p ?? {}).sort().join(",") !== "d,e,t"
    || !Number.isInteger(payload.v) || payload.v !== ACTIVITY_CURSOR_VERSION
    || typeof payload.r !== "string" || typeof payload.o !== "string" || typeof payload.s !== "string"
    || typeof payload.d !== "string" || !payload.p || typeof payload.p !== "object" || Array.isArray(payload.p)
    || typeof payload.p.t !== "string" || typeof payload.p.d !== "string" || typeof payload.p.e !== "string"
    || !UUID_OR_OPAQUE_ID.test(payload.o) || !UUID_OR_OPAQUE_ID.test(payload.p.d) || !UUID_OR_OPAQUE_ID.test(payload.p.e)
    || (payload.s !== "all" && !UUID_OR_OPAQUE_ID.test(payload.s))
    || !/^[A-Za-z0-9_-]{43}$/.test(payload.d)
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(payload.p.t)) {
    throw new ConsoleApiError(400, "invalid_cursor", "Cursor is invalid");
  }
  if (payload.r !== resource || payload.o !== config.organizationId || (deviceId !== null && payload.s !== deviceId)) {
    throw new ConsoleApiError(400, "invalid_cursor", "Cursor is invalid");
  }
  return { resource: payload.r, scope: payload.s, scope_digest: payload.d, position: payload.p };
}

async function signActivityCursor(encodedPayload, config) {
  const key = await importActivityCursorKey(config);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(encodedPayload));
  return base64UrlEncode(new Uint8Array(signature));
}

async function verifyActivityCursor(encodedPayload, encodedSignature, config) {
  try {
    const key = await importActivityCursorKey(config);
    return await crypto.subtle.verify("HMAC", key, base64UrlDecode(encodedSignature), new TextEncoder().encode(encodedPayload));
  } catch {
    return false;
  }
}

async function importActivityCursorKey(config) {
  if (!globalThis.crypto?.subtle) throw new ConsoleApiError(503, "activity_cursor_unavailable", "Activity cursor is unavailable");
  const material = base64UrlDecode(config.cursorSecret);
  return crypto.subtle.importKey("raw", material, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

async function digestText(value) {
  if (!globalThis.crypto?.subtle) throw new ConsoleApiError(503, "activity_cursor_unavailable", "Activity cursor is unavailable");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return base64UrlEncode(new Uint8Array(digest));
}

function base64UrlEncode(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecode(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("invalid base64url");
  if (value.length % 4 === 1) throw new Error("invalid base64url length");
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function postOperation(query, body, idempotencyKey, config, fetchImpl, options, recentAuth) {
  const operation = normalizeOperation(query.operation ?? query.resource);
  if (operation === "create-policy") {
    const policy = validatePolicyBody(body);
    const result = await cloudRequest("POST", "/policies", policy, config, fetchImpl, options, idempotencyKey, true);
    return {
      status: result.status,
      body: result.body,
    };
  }
  if (operation === "emergency-stop") {
    const stop = validateEmergencyStopBody(body);
    const result = await cloudRequest("POST", "/emergency-stop", stop, config, fetchImpl, options, idempotencyKey, true);
    return {
      status: result.status,
      body: result.body,
    };
  }
  if (operation === "create-device") {
    const device = validateDeviceBody(body);
    const result = await cloudRequest("POST", "/devices", device, config, fetchImpl, options, idempotencyKey, true);
    return { status: result.status, body: result.body };
  }
  if (operation === "issue-device-enrollment") {
    const input = validateDeviceEnrollmentBody(body);
    if (typeof recentAuth !== "string" || recentAuth.length < 32 || recentAuth.length > 4096 || hasControlCharacters(recentAuth)) {
      throw new ConsoleApiError(401, "recent_auth_required", "Recent WebAuthn authentication is required");
    }
    const enrollmentId = crypto.randomUUID();
    const deviceId = crypto.randomUUID();
    const result = await cloudRequest("POST", "/device-enrollments", {
      enrollment_id: enrollmentId,
      device_id: deviceId,
      label: input.label,
      platform: input.platform,
      ttl_ms: input.ttl_ms,
    }, config, fetchImpl, options, idempotencyKey, true, { "agentpass-recent-auth": recentAuth }, true);
    return { status: result.status, body: allowOneTimeEnrollment(result.body, input, config), oneTimeEnrollment: true };
  }
  if (operation === "create-agent") {
    const agent = validateAgentBody(body);
    const result = await cloudRequest("POST", "/agents", agent, config, fetchImpl, options, idempotencyKey, true);
    return { status: result.status, body: result.body };
  }
  if (operation === "disable-policy") {
    const input = validatePolicyDisableBody(body);
    const result = await cloudRequest("POST", `/policies/${encodeURIComponent(input.policy_id)}/disable`, { expected_version: input.expected_version, ...(input.reason ? { reason: input.reason } : {}) }, config, fetchImpl, options, idempotencyKey, true);
    return { status: result.status, body: result.body };
  }
  if (operation === "revoke-agent" || operation === "revoke-device" || operation === "revoke-capability") {
    const input = validateRevocationBody(body, operation);
    const path = operation === "revoke-agent" ? `/agents/${input.target_id}/revoke` : operation === "revoke-device" ? `/devices/${input.target_id}/revoke` : `/capabilities/${input.target_id}/revoke`;
    const result = await cloudRequest("POST", path, { reason: input.reason }, config, fetchImpl, options, idempotencyKey, true);
    return { status: result.status, body: result.body };
  }
  if (operation === "issue-capability") {
    const capability = validateCapabilityBody(body);
    const result = await cloudRequest("POST", "/capabilities", capability, config, fetchImpl, options, idempotencyKey, true);
    return { status: result.status, body: result.body };
  }
  throw new ConsoleApiError(400, "invalid_operation", "Operation is invalid");
}

function normalizeResource(value) {
  if (value === null || value === "" || value === "summary") return "summary";
  const aliases = { org: "organization", organization: "organization", devices: "devices", agents: "agents", policies: "policies", capabilities: "capabilities", revocations: "revocations", "admin-audit": "admin-audit", "audit-health": "audit-health", audit: "audit", activity: "activity", health: "health" };
  if (aliases[value]) return aliases[value];
  throw new ConsoleApiError(400, "invalid_resource", "Resource is invalid");
}

function normalizeOperation(value) {
  const aliases = {
    policy: "create-policy",
    policies: "create-policy",
    create_policy: "create-policy",
    "create-policy": "create-policy",
    "policy.create": "create-policy",
    "create-device": "create-device",
    device: "create-device",
    "device.create": "create-device",
    "issue-device-enrollment": "issue-device-enrollment",
    "device.enrollment.issue": "issue-device-enrollment",
    "create-agent": "create-agent",
    agent: "create-agent",
    "agent.create": "create-agent",
    "disable-policy": "disable-policy",
    "policy.disable": "disable-policy",
    "revoke-agent": "revoke-agent",
    "agent.revoke": "revoke-agent",
    "revoke-device": "revoke-device",
    "device.revoke": "revoke-device",
    "issue-capability": "issue-capability",
    capability: "issue-capability",
    "capability.issue": "issue-capability",
    "revoke-capability": "revoke-capability",
    "capability.revoke": "revoke-capability",
    "emergency-stop": "emergency-stop",
    emergency_stop: "emergency-stop",
    "emergency.stop": "emergency-stop",
  };
  if (typeof value === "string" && aliases[value]) return aliases[value];
  throw new ConsoleApiError(400, "invalid_operation", "Operation is invalid");
}

function validatePolicyBody(value) {
  const body = plainObject(value);
  exactKeys(body, ["name", "scope", "sequence"], "policy");
  const name = boundedString(body.name, "policy.name", 128, true);
  const scope = validateScope(body.scope);
  const policy = { name, scope };
  if (body.sequence !== undefined) {
    if (!Number.isSafeInteger(body.sequence) || body.sequence < 1) {
      throw new ConsoleApiError(400, "invalid_json_schema", "Request JSON does not match the schema");
    }
    policy.sequence = body.sequence;
  }
  return policy;
}

function validateScope(value) {
  const scope = plainObject(value);
  exactKeys(scope, ["operations", "repositories", "branches", "remotes", "tags"], "policy.scope");
  const result = {
    operations: stringArray(scope.operations, "policy.scope.operations", 64, true, (item) => item === "git.commit.sign"),
    repositories: stringArray(scope.repositories, "policy.scope.repositories", 64, true, (item) => item.startsWith("/") && !item.startsWith("//")),
    branches: validatePatternSet(scope.branches, "policy.scope.branches", true),
    remotes: validatePatternSet(scope.remotes, "policy.scope.remotes", true),
  };
  if (scope.tags !== undefined) result.tags = validatePatternSet(scope.tags, "policy.scope.tags", false);
  return result;
}

function validatePatternSet(value, path, required) {
  const patternSet = plainObject(value);
  exactKeys(patternSet, ["allow", "deny"], path);
  return {
    allow: stringArray(patternSet.allow, `${path}.allow`, 64, required),
    deny: stringArray(patternSet.deny, `${path}.deny`, 64, false),
  };
}

function validateEmergencyStopBody(value) {
  const body = plainObject(value);
  exactKeys(body, ["reason"], "emergency_stop");
  return { reason: boundedString(body.reason, "emergency_stop.reason", 128, true) };
}

function validateDeviceBody(value) {
  const body = plainObject(value);
  exactKeys(body, ["device_id", "name", "public_key", "metadata"], "device");
  const result = { name: boundedString(body.name, "device.name", 128, true), public_key: validatePublicKey(body.public_key, "device.public_key") };
  if (body.device_id !== undefined) result.device_id = validateIdentifier(body.device_id, "device.device_id");
  if (body.metadata !== undefined) result.metadata = plainObject(body.metadata);
  return result;
}

function validateDeviceEnrollmentBody(value) {
  const body = plainObject(value);
  exactKeys(body, ["label", "platform", "ttl_ms"], "device_enrollment");
  const platform = body.platform === undefined ? "macos" : boundedString(body.platform, "device_enrollment.platform", 32, true);
  if (platform !== "macos" || !Number.isSafeInteger(body.ttl_ms) || body.ttl_ms < 60_000 || body.ttl_ms > 24 * 60 * 60 * 1000) {
    throw new ConsoleApiError(400, "invalid_json_schema", "Request JSON does not match the schema");
  }
  return { label: boundedString(body.label, "device_enrollment.label", 128, true), platform, ttl_ms: body.ttl_ms };
}

function validateAgentBody(value) {
  const body = plainObject(value);
  exactKeys(body, ["agent_id", "name", "kind", "public_key", "device_id"], "agent");
  const result = { name: boundedString(body.name, "agent.name", 128, true), kind: boundedString(body.kind, "agent.kind", 64, true), public_key: validatePublicKey(body.public_key, "agent.public_key") };
  for (const key of ["agent_id", "device_id"]) if (body[key] !== undefined) result[key] = validateIdentifier(body[key], `agent.${key}`);
  return result;
}

function validatePolicyDisableBody(value) {
  const body = plainObject(value);
  exactKeys(body, ["policy_id", "expected_version", "reason"], "policy_disable");
  const policyId = validateIdentifier(body.policy_id, "policy_disable.policy_id");
  if (!Number.isSafeInteger(body.expected_version) || body.expected_version < 1) throw new ConsoleApiError(400, "invalid_json_schema", "Request JSON does not match the schema");
  return { policy_id: policyId, expected_version: body.expected_version, ...(body.reason === undefined ? {} : { reason: boundedString(body.reason, "policy_disable.reason", 128, true) }) };
}

function validateRevocationBody(value, operation) {
  const body = plainObject(value);
  exactKeys(body, ["target_id", "reason"], operation);
  return { target_id: validateIdentifier(body.target_id, `${operation}.target_id`), reason: boundedString(body.reason, `${operation}.reason`, 128, true) };
}

function validateCapabilityBody(value) {
  const body = plainObject(value);
  exactKeys(body, ["capability_id", "agent_id", "device_id", "scope", "ttl_ms", "sequence"], "capability");
  const result = { agent_id: validateIdentifier(body.agent_id, "capability.agent_id"), device_id: validateIdentifier(body.device_id, "capability.device_id"), scope: validateScope(body.scope) };
  if (body.capability_id !== undefined) result.capability_id = validateIdentifier(body.capability_id, "capability.capability_id");
  if (body.ttl_ms !== undefined && (!Number.isSafeInteger(body.ttl_ms) || body.ttl_ms < 1_000 || body.ttl_ms > 15 * 60 * 1000)) throw new ConsoleApiError(400, "invalid_json_schema", "Request JSON does not match the schema");
  if (body.sequence !== undefined && (!Number.isSafeInteger(body.sequence) || body.sequence < 0)) throw new ConsoleApiError(400, "invalid_json_schema", "Request JSON does not match the schema");
  if (body.ttl_ms !== undefined) result.ttl_ms = body.ttl_ms;
  if (body.sequence !== undefined) result.sequence = body.sequence;
  return result;
}

function validateIdentifier(value, path) {
  return boundedString(value, path, 128, true).match(UUID_OR_OPAQUE_ID)?.[0] === value ? value : (() => { throw new ConsoleApiError(400, "invalid_json_schema", "Request JSON does not match the schema"); })();
}

function validatePublicKey(value, path) {
  const key = boundedString(value, path, 8192, true, true);
  if (/PRIVATE\s+KEY|BEGIN\s+RSA|BEGIN\s+EC/i.test(key)) throw new ConsoleApiError(400, "invalid_json_schema", "Request JSON does not match the schema");
  return key;
}

function stringArray(value, path, maxItems, required, predicate = () => true) {
  if (!Array.isArray(value) || value.length > maxItems || (required && value.length === 0)) {
    throw new ConsoleApiError(400, "invalid_json_schema", "Request JSON does not match the schema");
  }
  return value.map((item) => {
    const text = boundedString(item, path, 4096, true);
    if (!predicate(text)) throw new ConsoleApiError(400, "invalid_json_schema", "Request JSON does not match the schema");
    return text;
  });
}

function boundedString(value, path, maxBytes, nonEmpty, allowNewlines = false) {
  if (typeof value !== "string" || (nonEmpty && value.length === 0) || hasControlCharacters(value, allowNewlines) || new TextEncoder().encode(value).byteLength > maxBytes) {
    throw new ConsoleApiError(400, "invalid_json_schema", "Request JSON does not match the schema");
  }
  return value;
}

function hasControlCharacters(value, allowNewlines = false) {
  for (const character of value) {
    const code = character.codePointAt(0);
    if (code !== undefined && ((code <= 0x1f && !(allowNewlines && (code === 0x0a || code === 0x0d))) || code === 0x7f)) return true;
  }
  return false;
}

function plainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ConsoleApiError(400, "invalid_json_schema", "Request JSON does not match the schema");
  }
  return value;
}

function exactKeys(value, allowed, path) {
  const allowedSet = new Set(allowed);
  if (Object.keys(value).some((key) => !allowedSet.has(key))) {
    throw new ConsoleApiError(400, "invalid_json_schema", `Invalid fields in ${path}`);
  }
}

async function readJsonBody(request) {
  const contentType = request.headers.get("content-type") ?? "";
  if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
    throw new ConsoleApiError(415, "json_required", "JSON request body required");
  }
  const contentLength = request.headers.get("content-length");
  if (contentLength !== null && (!/^\d+$/.test(contentLength) || Number(contentLength) > MAX_BYTES)) {
    throw new ConsoleApiError(413, "request_too_large", "Request body is too large");
  }
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.byteLength > MAX_BYTES) {
    throw new ConsoleApiError(413, "request_too_large", "Request body is too large");
  }
  try {
    return plainObject(JSON.parse(new TextDecoder().decode(bytes)));
  } catch (error) {
    if (error instanceof ConsoleApiError) throw error;
    throw new ConsoleApiError(400, "invalid_json", "Request body must be a JSON object");
  }
}

async function cloudRequest(method, suffix, body, config, fetchImpl, options, idempotencyKey = undefined, includeStatus = false, extraHeaders = undefined, preserveOneTimeCredential = false) {
  const url = buildCloudUrl(config.url, config.organizationId, suffix, config.allowInsecureLoopback);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.timeoutMs);
  const headers = new Headers({ accept: "application/json" });
  if (config.authMode === "human-session") {
    headers.set("cookie", config.authorization.cookie);
    headers.set("origin", config.authorization.origin);
    if (method !== "GET" && method !== "HEAD" && config.authorization.csrf !== undefined) headers.set("agentpass-csrf", config.authorization.csrf);
  } else {
    headers.set("authorization", `Bearer ${config.token}`);
  }
  const init = {
    method,
    headers,
    redirect: "error",
    cache: "no-store",
    signal: controller.signal,
  };
  if (body !== undefined) {
    const encoded = JSON.stringify(body);
    if (new TextEncoder().encode(encoded).byteLength > MAX_BYTES) {
      clearTimeout(timeoutId);
      throw new ConsoleApiError(413, "request_too_large", "Request body is too large");
    }
    headers.set("content-type", "application/json");
    init.body = encoded;
  }
  if (idempotencyKey !== undefined) headers.set("idempotency-key", idempotencyKey);
  if (extraHeaders) for (const [name, value] of Object.entries(extraHeaders)) headers.set(name, value);

  let response;
  try {
    response = await fetchImpl(url, init);
  } catch {
    clearTimeout(timeoutId);
    if (controller.signal.aborted) {
      throw new ConsoleApiError(504, "cloud_api_timeout", "Cloud API request timed out");
    }
    throw new ConsoleApiError(502, "cloud_api_unavailable", "Cloud API is unavailable");
  }
  clearTimeout(timeoutId);

  const raw = await readCloudResponse(response);
  let parsed;
  try {
    parsed = raw.length === 0 ? {} : JSON.parse(raw);
  } catch {
    throw new ConsoleApiError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  }
  const safe = sanitizeValue(parsed, config.secrets);
  if (!response.ok) throw new CloudResponseError(response.status, safe, config.secrets);
  const successBody = preserveOneTimeCredential ? parsed : safe;
  return includeStatus ? { status: response.status, body: successBody } : successBody;
}

function buildCloudUrl(baseValue, organizationId, suffix, allowInsecureLoopback = false) {
  let base;
  try {
    base = new URL(baseValue);
  } catch {
    throw new ConsoleApiError(503, "cloud_api_unavailable", "Cloud API is unavailable");
  }
  const isLoopback = base.hostname === "localhost" || base.hostname === "127.0.0.1" || base.hostname === "::1";
  if ((base.protocol !== "https:" && !(base.protocol === "http:" && allowInsecureLoopback && isLoopback)) || base.username || base.password || base.search || base.hash) {
    throw new ConsoleApiError(503, "cloud_api_unavailable", "Cloud API is unavailable");
  }
  const root = `${base.origin}${base.pathname.replace(/\/$/, "")}`;
  return `${root}/v1/organizations/${encodeURIComponent(organizationId)}${suffix}`;
}

async function readCloudResponse(response) {
  const contentLength = response.headers?.get("content-length");
  if (contentLength !== null && contentLength !== undefined && /^\d+$/.test(contentLength) && Number(contentLength) > MAX_BYTES) {
    throw new ConsoleApiError(502, "cloud_api_response_too_large", "Cloud API response is too large");
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength > MAX_BYTES) {
    throw new ConsoleApiError(502, "cloud_api_response_too_large", "Cloud API response is too large");
  }
  return new TextDecoder().decode(bytes);
}

async function readConfig(injected) {
  let source = injected;
  if (source === undefined) {
    try {
      const workers = await import("cloudflare:workers");
      source = workers.env;
    } catch {
      source = undefined;
    }
    if (typeof process !== "undefined") source = { ...process.env, ...(source ?? {}) };
  }
  if (source === undefined && typeof process !== "undefined") source = process.env;
  const url = source?.AGENTPASS_CLOUD_API_URL;
  const organizationId = source?.AGENTPASS_ORGANIZATION_ID;
  const cursorSecret = source?.AGENTPASS_CONSOLE_CURSOR_SECRET;
  if (typeof url !== "string" || typeof organizationId !== "string" || typeof cursorSecret !== "string" || !url || !UUID_OR_OPAQUE_ID.test(organizationId) || !/^[A-Za-z0-9_-]{43}$/.test(cursorSecret) || base64UrlDecode(cursorSecret).byteLength !== 32) {
    throw new ConsoleApiError(503, "cloud_api_unavailable", "Cloud API is unavailable");
  }
  const legacy = source?.AGENTPASS_ALLOW_LEGACY_OPERATOR_BRIDGE === "true" && ["development", "test"].includes(source?.NODE_ENV);
  let token;
  let operatorUserIds;
  if (legacy) {
    token = source?.AGENTPASS_CLOUD_TOKEN;
    const rawOperatorUserIds = source?.AGENTPASS_OPERATOR_USER_IDS;
    const operators = typeof rawOperatorUserIds === "string" ? rawOperatorUserIds.split(",").map((value) => value.trim()).filter(Boolean) : [];
    if (typeof token !== "string" || !token || token.length > 8192 || hasControlCharacters(token) || operators.length < 1 || operators.length > 100 || new Set(operators).size !== operators.length || operators.some((value) => !UUID_OR_OPAQUE_ID.test(value))) throw new ConsoleApiError(503, "cloud_api_unavailable", "Cloud API is unavailable");
    operatorUserIds = new Set(operators);
  }
  const timeoutValue = source?.AGENTPASS_CLOUD_TIMEOUT_MS;
  const timeoutMs = typeof timeoutValue === "string" && /^\d+$/.test(timeoutValue)
    ? Math.min(MAX_TIMEOUT_MS, Math.max(1_000, Number(timeoutValue)))
    : DEFAULT_TIMEOUT_MS;
  const allowInsecureLoopback = source?.AGENTPASS_ALLOW_INSECURE_LOOPBACK_CLOUD_API === "true";
  return {
    url,
    organizationId,
    authMode: legacy ? "legacy-operator" : "human-session",
    ...(legacy ? { token, operatorUserIds } : {}),
    cursorSecret,
    timeoutMs,
    allowInsecureLoopback,
    secrets: [url, organizationId, cursorSecret, ...(legacy ? [token] : [])],
  };
}

function sanitizeValue(value, secrets, key = "", seen = new WeakSet()) {
  if (SENSITIVE_KEY.test(key)) return "[redacted]";
  if (typeof value === "string") {
    return secrets.reduce((result, secret) => secret ? result.split(secret).join("[redacted]") : result, value);
  }
  if (Array.isArray(value)) return value.map((item) => sanitizeValue(item, secrets, "", seen));
  if (!value || typeof value !== "object") return value;
  if (seen.has(value)) return "[redacted]";
  seen.add(value);
  const result = {};
  for (const [childKey, childValue] of Object.entries(value)) {
    result[childKey] = sanitizeValue(childValue, secrets, childKey, seen);
  }
  return result;
}

function makeJsonResponse(status, body, config) {
  const safeBody = sanitizeValue(body, config.secrets);
  const encoded = JSON.stringify(safeBody);
  if (new TextEncoder().encode(encoded).byteLength > MAX_BYTES) {
    return jsonResponse(502, { error: { code: "response_too_large", message: "Response is too large" } });
  }
  return jsonResponse(status, safeBody);
}

function allowOneTimeEnrollment(body, input, config) {
  const source = plainObject(body);
  const enrollment = plainObject(source.enrollment);
  const allowed = ["enrollment_id", "organization_id", "device_id", "label", "platform", "created_at", "expires_at", "credential", "endpoint"];
  if (Object.keys(enrollment).some((key) => !allowed.includes(key))) throw new ConsoleApiError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  for (const key of ["enrollment_id", "organization_id", "device_id", "label", "platform", "expires_at", "credential", "endpoint"]) {
    if (typeof enrollment[key] !== "string" || !enrollment[key]) throw new ConsoleApiError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  }
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  if (!uuid.test(enrollment.enrollment_id) || !uuid.test(enrollment.device_id)
    || enrollment.organization_id !== config.organizationId || enrollment.label !== input.label
    || enrollment.platform !== input.platform || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(enrollment.expires_at)
    || (enrollment.created_at !== undefined && (typeof enrollment.created_at !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(enrollment.created_at)))
    || !/^[A-Za-z0-9_-]{43}$/.test(enrollment.credential)
    || enrollment.endpoint !== `/v1/enrollments/${enrollment.enrollment_id}`) {
    throw new ConsoleApiError(502, "cloud_api_invalid_response", "Cloud API response was invalid");
  }
  return { enrollment: Object.fromEntries(allowed.filter((key) => enrollment[key] !== undefined).map((key) => [key, enrollment[key]])) };
}

function makeOneTimeEnrollmentResponse(status, body) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store, max-age=0", pragma: "no-cache", "x-content-type-options": "nosniff" } });
}

function errorResponse(error) {
  if (error instanceof CloudResponseError) {
    const source = error.body && typeof error.body === "object" ? error.body : {};
    const sourceError = source.error && typeof source.error === "object" ? source.error : {};
    const code = typeof sourceError.code === "string" && SAFE_ERROR_CODE.test(sourceError.code)
      ? sourceError.code
      : "cloud_api_error";
    const responseBody = { error: { code, message: "Cloud API request failed" } };
    if (typeof source.request_id === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(source.request_id)) responseBody.request_id = source.request_id;
    return jsonResponse(error.status, responseBody);
  }
  if (error instanceof ConsoleApiError) {
    return jsonResponse(error.status, { error: { code: error.code, message: error.message } });
  }
  return jsonResponse(500, { error: { code: "internal_error", message: "Internal error" } });
}

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
      pragma: "no-cache",
    },
  });
}
