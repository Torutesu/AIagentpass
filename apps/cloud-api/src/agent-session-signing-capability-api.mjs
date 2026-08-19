import crypto from "node:crypto";

import { parseBoundedJson } from "../../../lib/control-bundle-v2.mjs";
import { canonicalJson, validateScope } from "../../../packages/protocol/src/index.mjs";
import {
  AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES,
  AGENT_SIGNING_CAPABILITY_KEY_PURPOSE,
  AGENT_SIGNING_CAPABILITY_MAX_TTL_MS,
  AGENT_SIGNING_CAPABILITY_OPERATION,
  createAgentSessionSigningCapabilityIssuanceService
} from "./human-auth/agent-sessions/signing-capability-issuance-service.mjs";

const SIGNING_CAPABILITY_ROUTE = "/v1/organizations/{organization_id}/devices/{device_id}/agent-sessions/{session_id}/signing-capabilities";
const METHOD = "POST";
const DEFAULT_MAX_BODY_BYTES = 64 * 1024;
const MAX_URL_BYTES = 8 * 1024;
const MAX_JSON_DEPTH = 16;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const REQUEST_KEYS = new Set(["request_id"]);
const RESPONSE_KEYS = new Set(["capability", "metadata", "request_id"]);
const CAPABILITY_KEYS = new Set(["version", "type", "statement", "statement_hash", "signature"]);
const STATEMENT_KEYS = new Set([
  "version", "type", "capability_id", "organization_id", "session_id", "device_id", "agent_id",
  "one_use", "operation", "scope", "key_purpose", "key_id", "algorithm", "max_signatures",
  "issued_at", "not_before", "expires_at", "sequence", "control_sequence", "authority_generation", "issuer"
]);
const METADATA_KEYS = new Set([
  "operation", "key_purpose", "issued_at", "expires_at", "sequence", "remaining_session_signatures", "replayed"
]);
const FORBIDDEN_BEARER_HEADERS = new Set(["authorization", "proxy-authorization"]);
const RESPONSE_HEADERS = Object.freeze({
  "Cache-Control": "no-store, max-age=0",
  "Pragma": "no-cache",
  "Expires": "0",
  "Content-Type": "application/json; charset=utf-8",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer"
});

export const AGENT_SESSION_SIGNING_CAPABILITY_HTTP_PATHS = Object.freeze({
  issue: SIGNING_CAPABILITY_ROUTE
});

export const AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES = Object.freeze({
  INVALID_REQUEST: "invalid_request",
  DEVICE_AUTH_FAILED: "device_auth_failed",
  AUDIENCE_MISMATCH: "audience_mismatch",
  SESSION_NOT_AUTHORIZED: "session_not_authorized",
  NOT_FOUND: "not_found",
  REPLAY: "replay",
  CONFLICT: "conflict",
  IN_PROGRESS: "in_progress",
  RATE_LIMITED: "rate_limited",
  OUTCOME_UNKNOWN: "outcome_unknown",
  UNAVAILABLE: "agent_session_signing_capability_unavailable"
});

const ERROR_MESSAGES = Object.freeze({
  [AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.INVALID_REQUEST]: "The Agent Session signing-capability request is invalid",
  [AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.DEVICE_AUTH_FAILED]: "Device authentication failed",
  [AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.AUDIENCE_MISMATCH]: "The authenticated Device cannot use this Agent Session",
  [AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.SESSION_NOT_AUTHORIZED]: "The Agent Session is not authorized",
  [AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.NOT_FOUND]: "Resource not found",
  [AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.REPLAY]: "The request was already processed",
  [AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.CONFLICT]: "The signing-capability request conflicts with prior state",
  [AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.IN_PROGRESS]: "The signing-capability request is already in progress",
  [AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.RATE_LIMITED]: "Rate limit exceeded",
  [AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.OUTCOME_UNKNOWN]: "The signing-capability issuance outcome is unknown",
  [AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.UNAVAILABLE]: "The Agent Session signing-capability service is unavailable"
});

export class AgentSessionSigningCapabilityHttpError extends Error {
  constructor(code, { status = statusFor(code), retryAfterSeconds = undefined, cause = undefined } = {}) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.UNAVAILABLE], { cause });
    this.name = "AgentSessionSigningCapabilityHttpError";
    this.code = code;
    this.status = status;
    if (retryAfterSeconds !== undefined) this.retryAfterSeconds = retryAfterSeconds;
  }
}

/**
 * Framework-neutral Device API boundary for F2c.
 *
 * The Device verifier receives the exact method, path, headers, and raw body
 * bytes. The body is not interpreted until that verifier succeeds. The
 * session binder is a trusted server seam: it must validate the active
 * organization/device/session relationship and current authority state. The
 * issuance service is then called with exactly `{ request_id }`.
 */
export function createAgentSessionSigningCapabilityApi({
  deviceRequestVerifier,
  deviceRequestAuthenticator,
  verifyDeviceRequest,
  issuanceService = undefined,
  issuanceServiceFactory = undefined,
  createIssuanceService = undefined,
  sessionBinder = undefined,
  agentSessionBinder = undefined,
  authorizeAgentSession = undefined,
  sessionAuthorizer = undefined,
  rateLimiter = undefined,
  now = () => Date.now(),
  requestIdFactory = () => crypto.randomUUID(),
  maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
  repository = undefined,
  signer = undefined,
  signerKeyId = undefined,
  keyId = undefined
} = {}) {
  const deviceVerifier = resolveVerifier(deviceRequestVerifier ?? deviceRequestAuthenticator ?? verifyDeviceRequest, "deviceRequestVerifier");
  const bindSession = resolveSessionBinder(sessionBinder ?? agentSessionBinder ?? authorizeAgentSession ?? sessionAuthorizer);
  const serviceFactory = issuanceServiceFactory ?? createIssuanceService;
  if (serviceFactory !== undefined && typeof serviceFactory !== "function") throw new TypeError("issuanceServiceFactory must be a function");
  if (issuanceService === undefined && serviceFactory === undefined && (repository === undefined || signer === undefined)) {
    throw new TypeError("issuanceService, issuanceServiceFactory, or repository and signer are required");
  }
  const service = issuanceService ?? (serviceFactory === undefined
    ? createAgentSessionSigningCapabilityIssuanceService({ repository, signer, signerKeyId, keyId, now })
    : undefined);
  const issue = service === undefined ? undefined : resolveIssueMethod(service);
  if (rateLimiter !== undefined && (!rateLimiter || typeof rateLimiter.acquire !== "function")) throw new TypeError("rateLimiter must expose acquire()");
  if (typeof now !== "function") throw new TypeError("now must be a function");
  if (typeof requestIdFactory !== "function") throw new TypeError("requestIdFactory must be a function");
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1_024 || maxBodyBytes > DEFAULT_MAX_BODY_BYTES) throw new TypeError("maxBodyBytes is invalid");

  async function handle(input, nodeResponse = undefined) {
    const result = await dispatch(input);
    if (nodeResponse !== undefined) writeNodeResponse(nodeResponse, result);
    return result;
  }

  async function handleAuthenticated(input, trustedContext = {}) {
    const correlationId = makeRequestId(requestIdFactory);
    try {
      const request = await normalizeRequest(input, maxBodyBytes);
      const route = resolveRoute(request.path);
      if (!route) return response(404, errorBody(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.NOT_FOUND, correlationId));
      if (request.method !== METHOD) throw invalidRequest();
      rejectBearerOrRedirect(request);
      const context = normalizeAuthenticatedContext(trustedContext, route, readClock(now));
      return await issueAuthenticatedRequest(request, route, context.authenticatedDevice, context.now, false);
    } catch (error) {
      return errorResponse(error, correlationId);
    }
  }

  async function dispatch(input) {
    const correlationId = makeRequestId(requestIdFactory);
    try {
      const request = await normalizeRequest(input, maxBodyBytes);
      const route = resolveRoute(request.path);
      if (!route) return response(404, errorBody(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.NOT_FOUND, correlationId));
      if (request.method !== METHOD) throw invalidRequest();
      rejectBearerOrRedirect(request);
      const clock = readClock(now);

      let authenticated;
      try {
        // This is intentionally the first operation involving the body. The
        // verifier authenticates the exact bytes and exact route target.
        authenticated = await deviceVerifier({
          method: request.method,
          path: request.path,
          body: Buffer.from(request.body),
          headers: request.headers
        }, {
          organization_id: route.organizationId,
          organizationId: route.organizationId,
          device_id: route.deviceId,
          deviceId: route.deviceId,
          session_id: route.sessionId,
          sessionId: route.sessionId,
          now: clock,
          includeAuthenticationMetadata: true
        });
      } catch (error) {
        throw mapDeviceAuthenticationError(error);
      }
      assertAuthenticatedDevice(authenticated, route);
      return await issueAuthenticatedRequest(request, route, authenticated, clock, true);
    } catch (error) {
      return errorResponse(error, correlationId);
    }
  }

  async function issueAuthenticatedRequest(request, route, authenticated, clock, applyRateLimit) {
    assertAuthenticatedDevice(authenticated, route);
    if (applyRateLimit && rateLimiter) await enforceRateLimit(rateLimiter, route);

    const body = parseCanonicalRequest(request.body, request.headers, maxBodyBytes);
    let binding;
    try {
      binding = await bindSession({
        organization_id: route.organizationId,
        device_id: route.deviceId,
        session_id: route.sessionId,
        authenticated_device: publicDeviceIdentity(authenticated),
        now: clock
      });
    } catch (error) {
      throw mapSessionBindingError(error);
    }
    const boundSession = assertSessionBinding(binding, route);

    let issued;
    try {
      const requestIssue = issue ?? resolveIssueMethod(await serviceFactory(Object.freeze({
        organization_id: route.organizationId,
        device_id: route.deviceId,
        session_id: route.sessionId,
        binding
      })));
      // Do not add route, authority, caller, or authentication fields here.
      issued = await requestIssue({ request_id: body.request_id });
    } catch (error) {
      throw mapIssuanceError(error);
    }
    const normalized = normalizePublicResponse(issued, route, body.request_id, boundSession.agent_id);
    return response(201, normalized);
  }

  return Object.freeze({
    handle,
    handleAuthenticated,
    paths: AGENT_SESSION_SIGNING_CAPABILITY_HTTP_PATHS,
    route: SIGNING_CAPABILITY_ROUTE
  });
}

export const createAgentSigningCapabilityHttpApi = createAgentSessionSigningCapabilityApi;

function resolveVerifier(value, label) {
  if (typeof value === "function") return value;
  if (value && typeof value.verify === "function") return value.verify.bind(value);
  if (value && typeof value.authenticate === "function") return value.authenticate.bind(value);
  throw new TypeError(`${label} must be a function or expose verify()/authenticate()`);
}

function resolveSessionBinder(value) {
  if (typeof value === "function") return value;
  if (value && typeof value.bindAgentSession === "function") return value.bindAgentSession.bind(value);
  if (value && typeof value.authorizeAgentSession === "function") return value.authorizeAgentSession.bind(value);
  if (value && typeof value.assertActiveAgentSession === "function") return value.assertActiveAgentSession.bind(value);
  throw new TypeError("sessionBinder must be a function or expose bindAgentSession()/authorizeAgentSession()/assertActiveAgentSession()");
}

function normalizeAuthenticatedContext(value, route, fallbackNow) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw unavailable();
  const organizationId = value.organization_id ?? value.organizationId;
  const deviceId = value.device_id ?? value.deviceId;
  const sessionId = value.session_id ?? value.sessionId;
  if (organizationId !== route.organizationId || deviceId !== route.deviceId || sessionId !== route.sessionId) {
    throw new AgentSessionSigningCapabilityHttpError(
      AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.AUDIENCE_MISMATCH,
      { status: 403 }
    );
  }
  const authenticatedDevice = value.authenticated_device ?? value.authenticatedDevice;
  assertAuthenticatedDevice(authenticatedDevice, route);
  return Object.freeze({
    authenticatedDevice,
    now: value.now === undefined ? fallbackNow : readClock(() => value.now)
  });
}

function errorResponse(error, correlationId) {
  const mapped = error instanceof AgentSessionSigningCapabilityHttpError
    ? error
    : new AgentSessionSigningCapabilityHttpError(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.UNAVAILABLE, { cause: error });
  const headers = mapped.retryAfterSeconds === undefined ? undefined : { "Retry-After": String(mapped.retryAfterSeconds) };
  return response(mapped.status, errorBody(mapped.code, correlationId), headers);
}

function resolveIssueMethod(service) {
  if (!service || typeof service !== "object") throw new TypeError("issuanceService is invalid");
  const method = ["issue", "issueAgentSessionSigningCapability", "issueSigningCapability"].find((name) => typeof service[name] === "function");
  if (!method) throw new TypeError("issuanceService must expose issue()");
  return service[method].bind(service);
}

async function enforceRateLimit(rateLimiter, route) {
  let decision;
  try {
    decision = await rateLimiter.acquire({
      tenantId: route.organizationId,
      principalType: "device",
      principalId: route.deviceId,
      sessionId: route.sessionId
    });
  } catch (error) {
    if (isRateLimitCode(error?.code) || error?.status === 429) throw mapRateLimitError(error);
    throw unavailable(error);
  }
  if (!decision || typeof decision !== "object" || typeof decision.allowed !== "boolean"
    || !Number.isSafeInteger(decision.limit) || decision.limit < 1
    || !Number.isSafeInteger(decision.remaining) || decision.remaining < 0 || decision.remaining > decision.limit
    || !Number.isSafeInteger(decision.retryAfterSeconds) || decision.retryAfterSeconds < 0) throw unavailable();
  if (!decision.allowed) throw new AgentSessionSigningCapabilityHttpError(
    AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.RATE_LIMITED,
    { status: 429, retryAfterSeconds: boundedRetryAfter(decision.retryAfterSeconds) }
  );
}

async function normalizeRequest(input, maxBodyBytes) {
  if (!input || typeof input !== "object") throw invalidRequest();
  const method = typeof input.method === "string" ? input.method.toUpperCase() : "";
  const path = typeof input.url === "string" ? input.url : typeof input.originalUrl === "string" ? input.originalUrl : input.path;
  if (!method || typeof path !== "string" || path.length === 0 || Buffer.byteLength(path, "utf8") > MAX_URL_BYTES) throw invalidRequest();
  if (!path.startsWith("/") || containsControlCharacter(path, true) || path.includes("#") || path.includes("?") || path.includes("\\")) throw invalidRequest();
  if (input.redirected === true || input.redirect_count !== undefined || input.redirectCount !== undefined) throw invalidRequest();
  const headers = input.headers ?? {};
  const contentLength = readHeader(headers, "content-length");
  if (contentLength !== undefined && (!/^\d+$/u.test(contentLength) || !Number.isSafeInteger(Number(contentLength)))) throw invalidRequest();
  if (contentLength !== undefined && Number(contentLength) > maxBodyBytes) throw payloadTooLarge();
  let body;
  try {
    body = await readRawBody(input, maxBodyBytes);
  } catch (error) {
    if (error instanceof AgentSessionSigningCapabilityHttpError) throw error;
    throw invalidRequest();
  }
  if (contentLength !== undefined && Number(contentLength) !== body.length) throw invalidRequest();
  return Object.freeze({ input, method, path, headers, body });
}

async function readRawBody(input, maxBodyBytes) {
  let raw = input.body;
  if (raw === undefined && typeof input.arrayBuffer === "function") raw = Buffer.from(await input.arrayBuffer());
  else if (raw === undefined && typeof input.text === "function") raw = await input.text();
  else if (raw === undefined && isAsyncIterable(input)) raw = await readStream(input, maxBodyBytes);
  else if (isAsyncIterable(raw)) raw = await readStream(raw, maxBodyBytes);
  const bytes = toBytes(raw);
  if (bytes.length > maxBodyBytes) throw payloadTooLarge();
  return bytes;
}

async function readStream(stream, maxBodyBytes) {
  const chunks = [];
  let total = 0;
  for await (const chunk of stream) {
    const bytes = toBytes(chunk);
    total += bytes.length;
    if (total > maxBodyBytes) throw payloadTooLarge();
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

function toBytes(value) {
  if (value === undefined || value === null) return Buffer.alloc(0);
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (typeof value === "string") return Buffer.from(value, "utf8");
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (value instanceof ArrayBuffer) return Buffer.from(value);
  throw invalidRequest();
}

function resolveRoute(path) {
  const match = /^\/v1\/organizations\/([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\/devices\/([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\/agent-sessions\/([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\/signing-capabilities$/u.exec(path);
  return match ? Object.freeze({ organizationId: match[1], deviceId: match[2], sessionId: match[3] }) : undefined;
}

function rejectBearerOrRedirect(request) {
  if (request.input?.redirected === true) throw invalidRequest();
  for (const name of headerNames(request.headers)) {
    if (FORBIDDEN_BEARER_HEADERS.has(name.toLowerCase())) throw invalidRequest();
  }
}

function parseCanonicalRequest(bytes, headers, maxBodyBytes) {
  if (bytes.length === 0) throw invalidRequest();
  const contentType = readHeader(headers, "content-type");
  if (typeof contentType !== "string" || !/^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(contentType)) throw invalidRequest();
  let value;
  try { value = parseBoundedJson(bytes, { maxBytes: maxBodyBytes, maxDepth: MAX_JSON_DEPTH }); }
  catch { throw invalidRequest(); }
  try {
    if (!isPlainObject(value)) throw new Error("object");
    assertExactKeys(value, REQUEST_KEYS);
    if (!UUID.test(value.request_id ?? "")) throw new Error("request_id");
    const canonical = canonicalJson(value);
    if (Buffer.compare(Buffer.from(canonical, "utf8"), bytes) !== 0) throw new Error("canonical");
    return Object.freeze({ request_id: value.request_id });
  } catch {
    throw invalidRequest();
  }
}

function assertAuthenticatedDevice(value, route) {
  const principal = value?.principal ?? value?.device ?? value;
  const deviceId = principal?.device_id ?? principal?.deviceId;
  const organizationId = principal?.organization_id ?? principal?.organizationId;
  if (typeof deviceId !== "string" || typeof organizationId !== "string") throw new AgentSessionSigningCapabilityHttpError(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.DEVICE_AUTH_FAILED, { status: 401 });
  if (deviceId !== route.deviceId || organizationId !== route.organizationId) throw new AgentSessionSigningCapabilityHttpError(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.AUDIENCE_MISMATCH, { status: 403 });
  const authenticatedSession = principal?.session_id ?? principal?.sessionId;
  if (authenticatedSession !== undefined && authenticatedSession !== route.sessionId) throw new AgentSessionSigningCapabilityHttpError(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.AUDIENCE_MISMATCH, { status: 403 });
}

function publicDeviceIdentity(value) {
  const principal = value?.principal ?? value?.device ?? value;
  return Object.freeze({
    organization_id: principal?.organization_id ?? principal?.organizationId,
    device_id: principal?.device_id ?? principal?.deviceId,
    ...(principal?.session_id ?? principal?.sessionId ? { session_id: principal.session_id ?? principal.sessionId } : {})
  });
}

function assertSessionBinding(value, route) {
  // A boolean success result cannot prove which tenant/device/session was
  // authorized. Accepting it would turn a miswired binder into a fail-open
  // path from Device authentication directly to capability issuance.
  // `agent_id` is required as well: the route is Session-scoped, while the
  // signed capability carries the Agent audience that the caller will use.
  if (!value || typeof value !== "object" || Array.isArray(value) || value.authorized === false || value.active === false || value.verified === false) throw new AgentSessionSigningCapabilityHttpError(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.SESSION_NOT_AUTHORIZED, { status: 403 });
  if (value.authorized !== true && value.verified !== true && value.active !== true) throw new AgentSessionSigningCapabilityHttpError(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.SESSION_NOT_AUTHORIZED, { status: 403 });
  const bound = {};
  for (const [key, expected] of [["organization_id", route.organizationId], ["device_id", route.deviceId], ["session_id", route.sessionId]]) {
    const camel = key.replace(/_([a-z])/gu, (_, character) => character.toUpperCase());
    const candidates = [value[key], value[camel]].filter((candidate) => candidate !== undefined);
    if (candidates.length === 0) throw new AgentSessionSigningCapabilityHttpError(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.SESSION_NOT_AUTHORIZED, { status: 403 });
    if (candidates.some((candidate) => candidate !== expected) || new Set(candidates).size !== 1) {
      throw new AgentSessionSigningCapabilityHttpError(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.AUDIENCE_MISMATCH, { status: 403 });
    }
    bound[key] = expected;
  }
  const agentId = value.agent_id ?? value.agentId;
  if (typeof agentId !== "string" || !UUID.test(agentId)) throw new AgentSessionSigningCapabilityHttpError(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.SESSION_NOT_AUTHORIZED, { status: 403 });
  if (value.agent_id !== undefined && value.agentId !== undefined && value.agent_id !== value.agentId) throw new AgentSessionSigningCapabilityHttpError(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.AUDIENCE_MISMATCH, { status: 403 });
  bound.agent_id = agentId;
  return Object.freeze(bound);
}

function normalizePublicResponse(value, route, expectedRequestId, expectedAgentId) {
  try {
    if (!isPlainObject(value)) throw new Error("response");
    assertExactKeys(value, RESPONSE_KEYS);
    if (!UUID.test(value.request_id ?? "") || value.request_id !== expectedRequestId) throw new Error("request_id");
    const capability = normalizeCapability(value.capability, route, expectedAgentId);
    const metadata = normalizeMetadata(value.metadata, capability.statement);
    return deepFreeze({ capability, metadata, request_id: value.request_id });
  } catch (error) {
    if (error instanceof AgentSessionSigningCapabilityHttpError) throw error;
    throw unavailable(error);
  }
}

function normalizeCapability(value, route, expectedAgentId) {
  if (!isPlainObject(value)) throw new Error("capability");
  assertExactKeys(value, CAPABILITY_KEYS);
  if (value.version !== 1 || value.type !== "agentpass.agent-signing-capability" || !SHA256.test(value.statement_hash ?? "") || !validSignature(value.signature)) throw new Error("capability envelope");
  const statement = value.statement;
  if (!isPlainObject(statement)) throw new Error("statement");
  assertExactKeys(statement, STATEMENT_KEYS);
  if (statement.version !== 1 || statement.type !== value.type || !UUID.test(statement.capability_id ?? "")
    || statement.organization_id !== route.organizationId || statement.device_id !== route.deviceId || statement.session_id !== route.sessionId
    || statement.agent_id !== expectedAgentId
    || statement.one_use !== true || statement.operation !== AGENT_SIGNING_CAPABILITY_OPERATION
    || statement.key_purpose !== AGENT_SIGNING_CAPABILITY_KEY_PURPOSE || statement.algorithm !== "ed25519"
    || statement.max_signatures !== 1 || statement.issuer !== "agentpass-cloud"
    || !safeIdentifier(statement.key_id) || !positiveInteger(statement.sequence)
    || !positiveInteger(statement.control_sequence) || !positiveInteger(statement.authority_generation)
    || !canonicalTimestamp(statement.issued_at) || !canonicalTimestamp(statement.not_before) || !canonicalTimestamp(statement.expires_at)) throw new Error("statement fields");
  validateScope(statement.scope);
  const issuedAt = Date.parse(statement.issued_at);
  const notBefore = Date.parse(statement.not_before);
  const expiresAt = Date.parse(statement.expires_at);
  if (issuedAt > notBefore || expiresAt <= notBefore || expiresAt - issuedAt > AGENT_SIGNING_CAPABILITY_MAX_TTL_MS) throw new Error("statement lifetime");
  if (sha256(canonicalJson(statement)) !== value.statement_hash) throw new Error("statement hash");
  return deepFreeze({ version: value.version, type: value.type, statement: clonePublicValue(statement), statement_hash: value.statement_hash, signature: value.signature });
}

function normalizeMetadata(value, statement) {
  if (!isPlainObject(value)) throw new Error("metadata");
  assertExactKeys(value, METADATA_KEYS);
  if (value.operation !== AGENT_SIGNING_CAPABILITY_OPERATION || value.key_purpose !== AGENT_SIGNING_CAPABILITY_KEY_PURPOSE
    || value.issued_at !== statement.issued_at || value.expires_at !== statement.expires_at || value.sequence !== statement.sequence
    || !Number.isSafeInteger(value.remaining_session_signatures) || value.remaining_session_signatures < 0 || value.remaining_session_signatures > 1
    || typeof value.replayed !== "boolean") throw new Error("metadata fields");
  return clonePublicValue(value);
}

function mapDeviceAuthenticationError(error) {
  const code = String(error?.code ?? error?.name ?? "").toLowerCase();
  if (error?.status === 503 || ["err_database", "err_db_client", "err_db_unavailable", "err_unavailable", "err_service_unavailable", "etimedout"].includes(code)
    || code.includes("unavailable") || code.includes("provider")) return unavailable(error);
  if (code.includes("organization") || code.includes("audience")) return new AgentSessionSigningCapabilityHttpError(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.AUDIENCE_MISMATCH, { status: 403, cause: error });
  return new AgentSessionSigningCapabilityHttpError(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.DEVICE_AUTH_FAILED, { status: 401, cause: error });
}

function mapSessionBindingError(error) {
  const code = String(error?.code ?? error?.name ?? "").toLowerCase();
  if (["not_found", "session_not_found", "session_expired", "session_revoked", "device_not_found"].some((value) => code.includes(value))) return new AgentSessionSigningCapabilityHttpError(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.NOT_FOUND, { status: 404, cause: error });
  if (isConflictCode(code)) return new AgentSessionSigningCapabilityHttpError(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.CONFLICT, { status: 409, cause: error });
  if (code.includes("forbidden") || code.includes("unauthorized") || code.includes("revoked")) return new AgentSessionSigningCapabilityHttpError(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.SESSION_NOT_AUTHORIZED, { status: 403, cause: error });
  throw unavailable(error);
}

function mapIssuanceError(error) {
  if (error instanceof AgentSessionSigningCapabilityHttpError) return error;
  const code = String(error?.code ?? error?.name ?? "").toUpperCase();
  if (code === AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.INPUT || code.includes("INVALID") || code.includes("VALIDATION")) return invalidRequest();
  if (code === AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.CONFLICT || code.includes("CONFLICT") || code.includes("REUSED")) return new AgentSessionSigningCapabilityHttpError(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.CONFLICT, { status: 409, cause: error });
  if (code === AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.IN_PROGRESS || code.includes("IN_PROGRESS")) return new AgentSessionSigningCapabilityHttpError(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.IN_PROGRESS, { status: 409, cause: error });
  if (code === AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.OUTCOME_UNKNOWN || code.includes("OUTCOME_UNKNOWN")) return new AgentSessionSigningCapabilityHttpError(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.OUTCOME_UNKNOWN, { status: 503, cause: error });
  if (code.includes("REPLAY")) return new AgentSessionSigningCapabilityHttpError(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.REPLAY, { status: 409, cause: error });
  if (code.includes("RATE_LIMIT")) return mapRateLimitError(error);
  return unavailable(error);
}

function mapRateLimitError(error) {
  return new AgentSessionSigningCapabilityHttpError(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.RATE_LIMITED, { status: 429, retryAfterSeconds: boundedRetryAfter(error?.retryAfterSeconds ?? error?.retry_after_seconds), cause: error });
}

function isRateLimitCode(code) { return ["ERR_RATE_LIMITED", "RATE_LIMITED", "ERR_RATE_LIMITER_CAPACITY_EXHAUSTED"].includes(String(code).toUpperCase()); }
function isConflictCode(code) { return ["ERR_CONFLICT", "CONFLICT", "ERR_SESSION_CONFLICT", "ERR_IDEMPOTENCY_CONFLICT", "IDEMPOTENCY_CONFLICT", "40001"].includes(String(code).toUpperCase()); }
function boundedRetryAfter(value) { return Number.isSafeInteger(value) && value >= 0 && value <= 3600 ? value : 1; }

function readClock(now) {
  let value;
  try { value = now(); } catch (error) { throw unavailable(error); }
  const milliseconds = value instanceof Date ? value.getTime() : value;
  if (!Number.isSafeInteger(milliseconds) || milliseconds <= 0) throw unavailable();
  return milliseconds;
}

function readHeader(headers, name) {
  if (headers && typeof headers.get === "function") {
    const value = headers.get(name);
    return value === null ? undefined : headerValue(value);
  }
  if (!headers || typeof headers !== "object" || Array.isArray(headers)) throw invalidRequest();
  const found = Object.entries(headers).filter(([key]) => key.toLowerCase() === name.toLowerCase());
  if (found.length > 1) throw invalidRequest();
  return found.length === 0 ? undefined : headerValue(found[0][1]);
}

function headerValue(value) {
  if (Array.isArray(value) || typeof value !== "string" || value.length > 8 * 1024 || containsControlCharacter(value)) throw invalidRequest();
  return value;
}

function headerNames(headers) {
  if (headers && typeof headers.keys === "function") return [...headers.keys()];
  if (!headers || typeof headers !== "object" || Array.isArray(headers)) throw invalidRequest();
  return Object.keys(headers);
}

function validSignature(value) {
  if (typeof value !== "string" || !SIGNATURE.test(value)) return false;
  const bytes = Buffer.from(value, "base64url");
  return bytes.length === 64 && bytes.toString("base64url") === value;
}

function canonicalTimestamp(value) { return typeof value === "string" && TIMESTAMP.test(value) && Number.isFinite(Date.parse(value)) && Date.parse(value) > 0 && new Date(value).toISOString() === value; }
function safeIdentifier(value) { return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u.test(value); }
function positiveInteger(value) { return Number.isSafeInteger(value) && value >= 1; }
function sha256(value) { return crypto.createHash("sha256").update(value, "utf8").digest("hex"); }
function makeRequestId(factory) { try { const value = factory(); if (typeof value === "string" && UUID.test(value)) return value; } catch { return crypto.randomUUID(); } return crypto.randomUUID(); }
function invalidRequest() { return new AgentSessionSigningCapabilityHttpError(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 }); }
function payloadTooLarge() { return new AgentSessionSigningCapabilityHttpError(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 }); }
function unavailable(cause = undefined) { return new AgentSessionSigningCapabilityHttpError(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.UNAVAILABLE, { status: 503, cause }); }
function statusFor(code) { return code === AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.INVALID_REQUEST ? 400 : code === AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.DEVICE_AUTH_FAILED ? 401 : code === AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.AUDIENCE_MISMATCH || code === AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.SESSION_NOT_AUTHORIZED ? 403 : code === AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.NOT_FOUND ? 404 : code === AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.REPLAY || code === AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.CONFLICT || code === AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.IN_PROGRESS ? 409 : code === AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.RATE_LIMITED ? 429 : 503; }
function errorBody(code, requestId) { return { error: { code, message: ERROR_MESSAGES[code] ?? ERROR_MESSAGES[AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.UNAVAILABLE] }, request_id: requestId }; }
function response(status, body, extraHeaders = undefined) { const headers = Object.freeze({ ...RESPONSE_HEADERS, ...(extraHeaders ?? {}) }); const json = JSON.stringify(body); return Object.freeze({ status, ok: status >= 200 && status < 300, headers, body: deepFreeze(body), text: async () => json, json: async () => body, toResponse: () => new Response(json, { status, headers }) }); }
function writeNodeResponse(target, result) { if (!target || typeof target.end !== "function") throw new TypeError("node response is invalid"); if (typeof target.writeHead === "function") target.writeHead(result.status, result.headers); else if (typeof target.setHeader === "function") for (const [name, value] of Object.entries(result.headers)) target.setHeader(name, value); target.statusCode = result.status; target.end(JSON.stringify(result.body)); }
function assertExactKeys(value, allowed) { const keys = Reflect.ownKeys(value); if (keys.some((key) => typeof key !== "string") || keys.length !== allowed.size || keys.some((key) => !allowed.has(key))) throw new Error("unknown field"); }
function isPlainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null); }
function clonePublicValue(value) { if (Array.isArray(value)) return value.map(clonePublicValue); if (isPlainObject(value)) return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, clonePublicValue(child)])); return value; }
function deepFreeze(value) { if (!value || typeof value !== "object" || Object.isFrozen(value)) return value; for (const child of Object.values(value)) deepFreeze(child); return Object.freeze(value); }
function isAsyncIterable(value) { return value !== null && value !== undefined && typeof value[Symbol.asyncIterator] === "function"; }
function containsControlCharacter(value, includeSpace = false) {
  const maximum = includeSpace ? 0x20 : 0x1f;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= maximum || code === 0x7f) return true;
  }
  return false;
}
