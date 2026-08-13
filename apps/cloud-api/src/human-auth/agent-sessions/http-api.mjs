import {
  HUMAN_SESSION_CSRF_HEADER,
  HUMAN_SESSION_ERROR_CODES,
  isOpaqueToken,
  parseSessionCookie
} from "../../human-session.mjs";
import {
  AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES,
  AgentSessionGrantIssuanceError,
  createAgentSessionGrantIssuanceService,
  normalizeAgentSessionGrantIssueIntent
} from "./issuance-service.mjs";
import {
  AGENT_SESSION_GRANT_TYPE,
  agentSessionGrantStatementHash,
  normalizeAgentSessionGrantStatement
} from "../../agent-session-grant.mjs";
import { canonicalJson } from "../../../../../packages/protocol/src/index.mjs";

const ROOT_PATH = "/api/v1/organizations";
const MAX_BODY_BYTES = 64 * 1024;
const MAX_HEADER_BYTES = 8 * 1024;
const MAX_URL_LENGTH = 8 * 1024;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._~-]{8,255}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const PATH_SEGMENT = /^[A-Za-z0-9._~-]+$/u;
const RECENT_AUTH_HEADER = "agentpass-recent-auth";
const OPERATION = "agent.session_grant.issue";
const ADMIN_ROLES = new Set(["owner", "admin"]);
const ALLOWED_HEADERS = new Set([
  "origin",
  "cookie",
  "content-type",
  "content-length",
  "idempotency-key",
  HUMAN_SESSION_CSRF_HEADER,
  RECENT_AUTH_HEADER
]);
const FORBIDDEN_IDENTITY_HEADERS = new Set([
  "authorization",
  "agentpass-console-identity",
  "agentpass-console-user-id",
  "agentpass-member-id",
  "agentpass-role",
  "agentpass-organization-id",
  "agentpass-agent-id",
  "x-agentpass-identity",
  "x-agentpass-organization-id",
  "x-agentpass-agent-id",
  "x-csrf-token"
]);
const RECENT_AUTH_FAILURES = new Set(["recent_auth_failed", "recent_auth_invalid", "invalid_recent_auth"]);
const SESSION_FAILURES = new Set([
  HUMAN_SESSION_ERROR_CODES.INVALID_COOKIE,
  HUMAN_SESSION_ERROR_CODES.SESSION_NOT_FOUND,
  HUMAN_SESSION_ERROR_CODES.SESSION_REVOKED,
  HUMAN_SESSION_ERROR_CODES.SESSION_EXPIRED
]);
const CSRF_FAILURES = new Set([HUMAN_SESSION_ERROR_CODES.CSRF_REQUIRED, HUMAN_SESSION_ERROR_CODES.CSRF_INVALID]);

export const HUMAN_AGENT_SESSION_GRANT_HTTP_PATHS = Object.freeze({
  issue: (organizationId, agentId) => `${ROOT_PATH}/${encodeURIComponent(organizationId)}/agents/${encodeURIComponent(agentId)}/session-grants`
});

export const HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES = Object.freeze({
  INVALID_REQUEST: "human_agent_session_grant_invalid_request",
  METHOD_NOT_ALLOWED: "human_agent_session_grant_method_not_allowed",
  ORIGIN_NOT_ALLOWED: "human_agent_session_grant_origin_not_allowed",
  SESSION_REQUIRED: "human_agent_session_grant_session_required",
  CSRF_FAILED: "human_agent_session_grant_csrf_failed",
  FORBIDDEN: "human_agent_session_grant_forbidden",
  NOT_FOUND: "human_agent_session_grant_not_found",
  IDEMPOTENCY_REQUIRED: "human_agent_session_grant_idempotency_required",
  IDEMPOTENCY_CONFLICT: "human_agent_session_grant_idempotency_conflict",
  RECENT_AUTH_REQUIRED: "human_agent_session_grant_recent_auth_required",
  RECENT_AUTH_FAILED: "human_agent_session_grant_recent_auth_failed",
  RECENT_AUTH_STALE: "human_agent_session_grant_recent_auth_stale",
  RECENT_AUTH_UNAVAILABLE: "human_agent_session_grant_recent_auth_unavailable",
  GRANT_UNAVAILABLE: "human_agent_session_grant_unavailable",
  INTERNAL_ERROR: "human_agent_session_grant_internal_error"
});

const ERROR_MESSAGES = Object.freeze({
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.INVALID_REQUEST]: "The agent session grant request is invalid",
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.METHOD_NOT_ALLOWED]: "Only POST is allowed",
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED]: "The request origin is not allowed",
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.SESSION_REQUIRED]: "A valid human session is required",
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.CSRF_FAILED]: "The CSRF token is invalid",
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.FORBIDDEN]: "The authenticated human is not allowed to issue this grant",
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.NOT_FOUND]: "The requested agent session resource was not found",
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.IDEMPOTENCY_REQUIRED]: "An Idempotency-Key is required",
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.IDEMPOTENCY_CONFLICT]: "The idempotency key conflicts with another request",
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.RECENT_AUTH_REQUIRED]: "Recent WebAuthn authentication is required",
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.RECENT_AUTH_FAILED]: "Recent WebAuthn authentication failed",
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.RECENT_AUTH_STALE]: "Recent WebAuthn authentication is stale",
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.RECENT_AUTH_UNAVAILABLE]: "Recent WebAuthn verification is unavailable",
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.GRANT_UNAVAILABLE]: "The agent session grant service is unavailable",
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.INTERNAL_ERROR]: "The request could not be completed"
});

const ERROR_STATUS = Object.freeze({
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.INVALID_REQUEST]: 400,
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.METHOD_NOT_ALLOWED]: 405,
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED]: 403,
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.SESSION_REQUIRED]: 401,
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.CSRF_FAILED]: 403,
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.FORBIDDEN]: 403,
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.NOT_FOUND]: 404,
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.IDEMPOTENCY_REQUIRED]: 400,
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.IDEMPOTENCY_CONFLICT]: 409,
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.RECENT_AUTH_REQUIRED]: 401,
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.RECENT_AUTH_FAILED]: 401,
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.RECENT_AUTH_STALE]: 401,
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.RECENT_AUTH_UNAVAILABLE]: 503,
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.GRANT_UNAVAILABLE]: 503,
  [HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.INTERNAL_ERROR]: 500
});

export class HumanAgentSessionGrantHttpError extends Error {
  constructor(code, { status = ERROR_STATUS[code] ?? 500, cause = undefined, allow = undefined } = {}) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.INTERNAL_ERROR], { cause });
    this.name = "HumanAgentSessionGrantHttpError";
    this.code = code;
    this.status = status;
    this.allow = allow;
  }
}

/**
 * Framework-neutral Human API boundary for the frozen grant-issuance route.
 *
 * The injected issuance service is called only after the browser security
 * boundary and recent-auth proof have passed. Its repository must still
 * authorize the actor and tenant inside its transaction.
 */
export function createHumanAgentSessionGrantHttpApi({
  humanSession,
  recentAuthService,
  issuanceService = undefined,
  repository = undefined,
  signer = undefined,
  signerKeyId = undefined,
  keyId = undefined,
  clock = { now: () => Date.now() },
  now = undefined,
  uuid = undefined,
  origin,
  basePath = "",
  maxBodyBytes = MAX_BODY_BYTES
} = {}) {
  assertHumanSession(humanSession);
  if (!recentAuthService || typeof recentAuthService.authorize !== "function") throw new TypeError("recentAuthService must expose authorize()");
  const service = issuanceService ?? createAgentSessionGrantIssuanceService({ repository, signer, signerKeyId, keyId, clock, now, uuid: uuid ?? undefined });
  assertIssuanceService(service);
  const expectedOrigin = origin ?? humanSession.expectedOrigin;
  assertOrigin(expectedOrigin);
  const readClock = normalizeClock(clock, now);
  const normalizedBasePath = normalizeBasePath(basePath);
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1_024 || maxBodyBytes > 1_024 * 1_024) throw new TypeError("maxBodyBytes is invalid");

  async function handle(input, nodeResponse = undefined) {
    const result = await dispatch(input);
    if (nodeResponse !== undefined) writeNodeResponse(nodeResponse, result);
    return result;
  }

  async function dispatch(input) {
    try {
      const request = normalizeRequest(input);
      const route = resolveRoute(request.url, normalizedBasePath);
      if (!route) return response(404, { error: { code: "not_found", message: "Resource not found" } });
      const actor = await authenticateSession(request);
      if (request.method !== "POST") throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.METHOD_NOT_ALLOWED, { status: 405, allow: "POST" });
      if (route.query !== "") throw invalidRequest();
      const idempotencyKey = requiredIdempotencyKey(request);
      let intent;
      try { intent = normalizeAgentSessionGrantIssueIntent(await readJsonBody(request, maxBodyBytes)); }
      catch (error) { throw mapIssuanceError(error); }
      if (actor.organization_id !== route.organizationId) throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.NOT_FOUND, { status: 404 });
      if (!ADMIN_ROLES.has(actor.role)) throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.FORBIDDEN, { status: 403 });
      const recentAuthorization = await requireRecentAuth({ actor, organizationId: route.organizationId, request });
      let issued;
      try {
        issued = await service[serviceIssueMethod(service)]({
          actor,
          organization_id: route.organizationId,
          agent_id: route.agentId,
          intent,
          idempotency_key: idempotencyKey,
          recent_authorization: recentAuthorization
        });
      } catch (error) {
        throw mapIssuanceError(error);
      }
      return response(201, normalizeIssuedResponse(issued, { organizationId: route.organizationId, agentId: route.agentId, intent }));
    } catch (error) {
      return mapError(error);
    }
  }

  async function authenticateSession(request) {
    const requestOrigin = header(request.headers, "origin");
    if (requestOrigin !== expectedOrigin || requestOrigin === "null") throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED, { status: 403 });
    const cookie = header(request.headers, "cookie");
    try { parseSessionCookie(cookie); } catch (error) { throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.SESSION_REQUIRED, { status: 401, cause: error }); }
    const csrfToken = header(request.headers, HUMAN_SESSION_CSRF_HEADER);
    if (!isOpaqueToken(csrfToken)) throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.CSRF_FAILED, { status: 403 });
    try {
      const authenticated = await humanSession.authenticateRequest({ method: "POST", headers: request.headers, origin: requestOrigin, cookie, csrfToken });
      return normalizeActor(authenticated?.session);
    } catch (error) {
      if (error instanceof HumanAgentSessionGrantHttpError) throw error;
      if (error?.code === HUMAN_SESSION_ERROR_CODES.INVALID_ORIGIN) throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED, { status: 403, cause: error });
      if (CSRF_FAILURES.has(error?.code)) throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.CSRF_FAILED, { status: 403, cause: error });
      if (SESSION_FAILURES.has(error?.code)) throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.SESSION_REQUIRED, { status: 401, cause: error });
      throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.SESSION_REQUIRED, { status: 401, cause: error });
    }
  }

  async function requireRecentAuth({ actor, organizationId, request }) {
    const proof = header(request.headers, RECENT_AUTH_HEADER);
    if (!isUuid(proof)) throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.RECENT_AUTH_REQUIRED, { status: 401 });
    const authenticatedAt = readNow(readClock);
    let authorization;
    try {
      authorization = await recentAuthService.authorize({ proof, principal: actor, organization_id: organizationId, operation: OPERATION, now: authenticatedAt });
    } catch (error) {
      if (RECENT_AUTH_FAILURES.has(String(error?.code ?? "").toLowerCase())) throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.RECENT_AUTH_FAILED, { status: 401, cause: error });
      throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.RECENT_AUTH_UNAVAILABLE, { status: 503, cause: error });
    }
    const expectedKeys = ["authenticated_at", "challenge_id", "consumed", "member_id", "operation", "organization_id", "verified"];
    const exactShape = authorization && typeof authorization === "object" && !Array.isArray(authorization)
      && Object.keys(authorization).sort().join(",") === expectedKeys.sort().join(",")
      && authorization.verified === true
      && authorization.consumed === true
      && authorization.member_id === actor.member_id
      && authorization.organization_id === organizationId
      && authorization.operation === OPERATION
      && isUuid(authorization.challenge_id)
      && authorization.challenge_id.toLowerCase() === proof.toLowerCase()
      && Number.isSafeInteger(authorization.authenticated_at)
      && authorization.authenticated_at >= 0;
    if (!exactShape) throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.RECENT_AUTH_FAILED, { status: 401 });
    if (authorization.authenticated_at > authenticatedAt + 30_000) throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.RECENT_AUTH_STALE, { status: 401 });
    if (authenticatedAt - authorization.authenticated_at > 5 * 60_000) throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.RECENT_AUTH_STALE, { status: 401 });
    return Object.freeze({ authorization_id: authorization.challenge_id.toLowerCase(), authenticated_at: authorization.authenticated_at });
  }

  return Object.freeze({
    handle,
    paths: HUMAN_AGENT_SESSION_GRANT_HTTP_PATHS,
    expectedOrigin,
    basePath: normalizedBasePath
  });
}

export const createHumanAgentSessionGrantApi = createHumanAgentSessionGrantHttpApi;

function assertHumanSession(value) {
  if (!value || typeof value.authenticateRequest !== "function") throw new TypeError("humanSession must expose authenticateRequest()");
}

function assertIssuanceService(value) {
  if (!value || typeof value !== "object" || (typeof value.issue !== "function" && typeof value.issueGrant !== "function" && typeof value.issueAgentSessionGrant !== "function")) throw new TypeError("issuanceService must expose issue()");
}

function serviceIssueMethod(service) {
  return ["issue", "issueGrant", "issueAgentSessionGrant"].find((method) => typeof service[method] === "function");
}

function normalizeActor(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("session is invalid");
  const actor = {
    session_id: requiredUuid(value.session_id, "session_id"),
    member_id: requiredUuid(value.member_id, "member_id"),
    organization_id: requiredUuid(value.organization_id, "organization_id"),
    role: value.role
  };
  if (!["owner", "admin", "auditor", "viewer"].includes(actor.role)) throw new Error("session role is invalid");
  return Object.freeze(actor);
}

function resolveRoute(rawUrl, basePath) {
  let url;
  try { url = new URL(rawUrl, "https://agentpass.invalid"); } catch { return undefined; }
  if (url.hash) return undefined;
  const root = `${basePath}${ROOT_PATH}/`;
  if (!url.pathname.startsWith(root)) return undefined;
  const parts = url.pathname.slice(root.length).split("/");
  if (parts.length !== 4 || parts[1] !== "agents" || parts[3] !== "session-grants") return undefined;
  return {
    organizationId: decodePathUuid(parts[0]),
    agentId: decodePathUuid(parts[2]),
    query: url.search
  };
}

function decodePathUuid(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 256 || !PATH_SEGMENT.test(value)) throw invalidRequest();
  let decoded;
  try { decoded = decodeURIComponent(value); } catch { throw invalidRequest(); }
  if (!decoded || decoded.includes("/") || decoded.includes("\\") || !PATH_SEGMENT.test(decoded) || !isUuid(decoded)) throw invalidRequest();
  return decoded.toLowerCase();
}

function requiredIdempotencyKey(request) {
  const value = header(request.headers, "idempotency-key");
  if (typeof value !== "string" || !IDEMPOTENCY_KEY.test(value)) throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.IDEMPOTENCY_REQUIRED, { status: 400 });
  return value;
}

function normalizeIssuedResponse(value, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value) || !value.grant || !isUuid(value.request_id)) throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.GRANT_UNAVAILABLE, { status: 503 });
  const grant = value.grant;
  if (!grant || typeof grant !== "object" || Array.isArray(grant) || Reflect.ownKeys(grant).some((key) => typeof key !== "string") || Object.keys(grant).sort().join(",") !== "signature,statement,statement_hash,type,version" || grant.version !== 1 || grant.type !== AGENT_SESSION_GRANT_TYPE || !isSha256(grant.statement_hash) || typeof grant.signature !== "string" || !/^[A-Za-z0-9_-]{86}$/u.test(grant.signature) || Buffer.from(grant.signature, "base64url").length !== 64 || Buffer.from(grant.signature, "base64url").toString("base64url") !== grant.signature) throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.GRANT_UNAVAILABLE, { status: 503 });
  let statement;
  try { statement = normalizeAgentSessionGrantStatement(grant.statement); } catch (error) { throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.GRANT_UNAVAILABLE, { status: 503, cause: error }); }
  if (grant.statement_hash !== agentSessionGrantStatementHash(statement)
    || statement.organization_id !== expected.organizationId
    || statement.agent_id !== expected.agentId
    || statement.device_id !== expected.intent.device_id
    || statement.agent_kind !== expected.intent.agent_kind
    || statement.adapter_id !== expected.intent.adapter_id
    || statement.adapter_version !== expected.intent.adapter_version
    || statement.worktree_binding_sha256 !== expected.intent.worktree_binding_sha256
    || statement.process_binding_policy_id !== expected.intent.process_binding_policy_id
    || statement.max_signatures !== expected.intent.max_signatures
    || canonicalJson(statement.scope) !== canonicalJson(expected.intent.scope)) throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.GRANT_UNAVAILABLE, { status: 503 });
  return { grant, request_id: value.request_id.toLowerCase() };
}

function mapIssuanceError(error) {
  if (error instanceof HumanAgentSessionGrantHttpError) return error;
  const code = error instanceof AgentSessionGrantIssuanceError ? error.code : String(error?.code ?? error?.name ?? "").toLowerCase();
  if ([AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.INVALID_REQUEST, "invalid_input", "validation_error"].includes(code)) return invalidRequest();
  if ([AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.FORBIDDEN, "forbidden", "not_authorized"].includes(code)) return new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.FORBIDDEN, { status: 403, cause: error });
  if ([AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.NOT_FOUND, "not_found", "agent_not_found", "device_not_found", "tenant_not_found"].includes(code)) return new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.NOT_FOUND, { status: 404, cause: error });
  if ([AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.IDEMPOTENCY_CONFLICT, "idempotency_conflict", "idempotency_key_reused"].includes(code)) return new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.IDEMPOTENCY_CONFLICT, { status: 409, cause: error });
  return new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.GRANT_UNAVAILABLE, { status: 503, cause: error });
}

function mapError(error) {
  if (error instanceof HumanAgentSessionGrantHttpError) {
    const headers = error.status === 405 ? { Allow: error.allow ?? "POST" } : undefined;
    return response(error.status, { error: { code: error.code, message: ERROR_MESSAGES[error.code] ?? ERROR_MESSAGES[HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.INTERNAL_ERROR] } }, headers);
  }
  return response(500, { error: { code: HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.INTERNAL_ERROR, message: ERROR_MESSAGES[HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.INTERNAL_ERROR] } });
}

function invalidRequest() { return new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 }); }

function normalizeClock(clock, now) {
  const candidate = now ?? (typeof clock === "function" ? clock : clock?.now);
  if (typeof candidate !== "function") throw new TypeError("clock must expose now()");
  return candidate;
}

function readNow(clock) {
  let result;
  try { result = clock(); } catch (error) { throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.RECENT_AUTH_UNAVAILABLE, { status: 503, cause: error }); }
  if (!Number.isSafeInteger(result) || result < 0) throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.RECENT_AUTH_UNAVAILABLE, { status: 503 });
  return result;
}

function assertOrigin(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > MAX_URL_LENGTH || value.endsWith("/") || !/^https:\/\/[^/]+$/u.test(value)) throw new TypeError("origin is invalid");
}

function normalizeBasePath(value) {
  if (value === "") return "";
  if (typeof value !== "string" || !value.startsWith("/") || value.endsWith("/") || value.includes("?")) throw new TypeError("basePath is invalid");
  return value;
}

function normalizeRequest(input) {
  if (!input || typeof input !== "object") throw invalidRequest();
  const method = String(input.method ?? "").toUpperCase();
  const url = String(input.url ?? input.originalUrl ?? input.path ?? "");
  if (!method || !url || url.length > MAX_URL_LENGTH) throw invalidRequest();
  return Object.freeze({ input, method, url, headers: normalizeHeaders(input.headers ?? {}), body: input.body });
}

function normalizeHeaders(input) {
  const result = {};
  if (input && typeof input.get === "function") {
    for (const name of [...ALLOWED_HEADERS, ...FORBIDDEN_IDENTITY_HEADERS]) {
      const value = input.get(name);
      if (value !== null) setHeader(result, name, value);
    }
    return result;
  }
  if (!input || typeof input !== "object" || Array.isArray(input)) throw invalidRequest();
  for (const [rawName, value] of Object.entries(input)) {
    const name = rawName.toLowerCase();
    if (FORBIDDEN_IDENTITY_HEADERS.has(name)) throw invalidRequest();
    if (!ALLOWED_HEADERS.has(name)) continue;
    setHeader(result, name, value);
  }
  return result;
}

function setHeader(target, name, value) {
  if (Array.isArray(value) || value === undefined || typeof value === "object") throw invalidRequest();
  const normalized = name.toLowerCase();
  if (target[normalized] !== undefined) throw invalidRequest();
  target[normalized] = String(value);
}

function header(headers, name) {
  const value = headers[name.toLowerCase()];
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length > MAX_HEADER_BYTES || /[\u0000-\u001f\u007f]/u.test(value)) throw invalidRequest();
  return value;
}

async function readJsonBody(request, maxBytes) {
  const contentType = header(request.headers, "content-type");
  if (typeof contentType !== "string" || !/^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(contentType)) throw invalidRequest();
  const contentLength = header(request.headers, "content-length");
  if (contentLength !== undefined && (!/^\d+$/u.test(contentLength) || !Number.isSafeInteger(Number(contentLength)) || Number(contentLength) > maxBytes)) throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
  const input = request.input;
  let raw = input.body;
  if (typeof input.arrayBuffer === "function") raw = Buffer.from(await input.arrayBuffer());
  else if (typeof input.text === "function") raw = await input.text();
  else if (isReadable(input)) raw = await readStream(input, maxBytes);
  else if (isReadable(raw)) raw = await readStream(raw, maxBytes);
  if (isPlainObject(raw)) {
    assertSerializedSize(raw, maxBytes);
    return raw;
  }
  const bytes = Buffer.isBuffer(raw) ? raw : raw instanceof Uint8Array ? Buffer.from(raw) : Buffer.from(String(raw ?? ""), "utf8");
  if (bytes.length > maxBytes) throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
  if (contentLength !== undefined && Number(contentLength) !== bytes.length) throw invalidRequest();
  try { return parseJsonNoDuplicateKeys(bytes.toString("utf8")); } catch (error) { throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400, cause: error }); }
}

function assertSerializedSize(value, maxBytes) {
  let serialized;
  try { serialized = JSON.stringify(value); } catch { throw invalidRequest(); }
  if (typeof serialized !== "string" || Buffer.byteLength(serialized, "utf8") > maxBytes) throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
}

function isReadable(value) { return value && typeof value.on === "function"; }

async function readStream(stream, maxBytes) {
  const chunks = [];
  let total = 0;
  for await (const chunk of stream) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += bytes.length;
    if (total > maxBytes) throw new HumanAgentSessionGrantHttpError(HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

class StrictJsonParser {
  constructor(text) { this.text = text; this.index = 0; this.depth = 0; }
  parse() { this.skipWhitespace(); const value = this.value(); this.skipWhitespace(); if (this.index !== this.text.length) throw new Error("trailing JSON data"); return value; }
  value() {
    if (++this.depth > 64) throw new Error("JSON nesting is too deep");
    this.skipWhitespace();
    const character = this.text[this.index];
    let result;
    if (character === "{") result = this.object();
    else if (character === "[") result = this.array();
    else if (character === '"') result = this.string();
    else if (character === "t" && this.literal("true")) result = true;
    else if (character === "f" && this.literal("false")) result = false;
    else if (character === "n" && this.literal("null")) result = null;
    else result = this.number();
    this.depth -= 1;
    return result;
  }
  object() {
    this.index += 1;
    const output = Object.create(null);
    const keys = new Set();
    this.skipWhitespace();
    if (this.text[this.index] === "}") { this.index += 1; return output; }
    while (true) {
      this.skipWhitespace();
      if (this.text[this.index] !== '"') throw new Error("JSON object key is invalid");
      const key = this.string();
      if (keys.has(key)) throw new Error("duplicate JSON object key");
      keys.add(key);
      this.skipWhitespace();
      if (this.text[this.index] !== ":") throw new Error("JSON object separator is invalid");
      this.index += 1;
      output[key] = this.value();
      this.skipWhitespace();
      if (this.text[this.index] === "}") { this.index += 1; return output; }
      if (this.text[this.index] !== ",") throw new Error("JSON object delimiter is invalid");
      this.index += 1;
    }
  }
  array() {
    this.index += 1;
    const output = [];
    this.skipWhitespace();
    if (this.text[this.index] === "]") { this.index += 1; return output; }
    while (true) {
      output.push(this.value());
      this.skipWhitespace();
      if (this.text[this.index] === "]") { this.index += 1; return output; }
      if (this.text[this.index] !== ",") throw new Error("JSON array delimiter is invalid");
      this.index += 1;
    }
  }
  string() {
    const start = this.index;
    this.index += 1;
    while (this.index < this.text.length) {
      const character = this.text[this.index];
      if (character === "\\") this.index += 2;
      else if (character === '"') { this.index += 1; return JSON.parse(this.text.slice(start, this.index)); }
      else { if (character < " ") throw new Error("JSON string control character is invalid"); this.index += 1; }
    }
    throw new Error("unterminated JSON string");
  }
  number() {
    const match = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
    match.lastIndex = this.index;
    const found = match.exec(this.text);
    if (!found) throw new Error("JSON value is invalid");
    this.index += found[0].length;
    const value = Number(found[0]);
    if (!Number.isFinite(value)) throw new Error("JSON number is invalid");
    return value;
  }
  literal(value) { if (this.text.startsWith(value, this.index)) { this.index += value.length; return true; } return false; }
  skipWhitespace() { while ([0x20, 0x09, 0x0a, 0x0d].includes(this.text.charCodeAt(this.index))) this.index += 1; }
}

function parseJsonNoDuplicateKeys(text) { return new StrictJsonParser(text).parse(); }
function isPlainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null); }
function isUuid(value) { return typeof value === "string" && UUID.test(value); }
function isSha256(value) { return typeof value === "string" && /^[0-9a-f]{64}$/u.test(value); }
function requiredUuid(value) { if (!isUuid(value)) throw new Error("uuid is invalid"); return value.toLowerCase(); }

function response(status, body, extraHeaders = undefined) {
  const headers = {
    "Cache-Control": "no-store, max-age=0",
    Pragma: "no-cache",
    Expires: "0",
    "Content-Type": "application/json; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    ...(extraHeaders ?? {})
  };
  const json = JSON.stringify(body);
  return Object.freeze({ status, ok: status >= 200 && status < 300, headers: Object.freeze(headers), body: Object.freeze(body), text: async () => json, json: async () => body, toResponse: () => new Response(json, { status, headers }) });
}

function writeNodeResponse(target, result) {
  if (!target || typeof target.writeHead !== "function" || typeof target.end !== "function") throw new TypeError("node response is invalid");
  target.writeHead(result.status, result.headers);
  target.end(JSON.stringify(result.body));
}
