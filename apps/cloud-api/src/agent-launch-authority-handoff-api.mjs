import crypto from "node:crypto";

import { parseBoundedJson } from "../../../lib/control-bundle-v2.mjs";
import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import {
  AgentLaunchAuthorityHandoffContractError,
  createAgentLaunchAuthorityHandoffBinding,
  normalizeAgentLaunchAuthorityHandoffRequest,
  normalizeAgentLaunchAuthoritySessionBinding
} from "./agent-launch-authority-handoff-contract.mjs";
import {
  AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES,
  createPostgresAgentLaunchAuthorityHandoffRepository
} from "./postgres/agent-launch-authority-handoff-repository.mjs";

const ROUTE = "/v1/organizations/{organization_id}/devices/{device_id}/agent-sessions/{session_id}/launch-authority-handoff";
const METHOD = "POST";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MAX_BODY_BYTES = 16 * 1024;
const MAX_URL_BYTES = 8 * 1024;
const MAX_JSON_DEPTH = 16;
const FORBIDDEN_BEARER_HEADERS = new Set(["authorization", "proxy-authorization"]);
const RESPONSE_HEADERS = Object.freeze({
  "Cache-Control": "no-store, max-age=0",
  "Pragma": "no-cache",
  Expires: "0",
  "Content-Type": "application/json; charset=utf-8",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer"
});

export const AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_PATHS = Object.freeze({ prepare: ROUTE });

export const AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES = Object.freeze({
  INVALID_REQUEST: "agent_launch_authority_handoff_invalid_request",
  DEVICE_AUTH_FAILED: "agent_launch_authority_handoff_device_auth_failed",
  AUDIENCE_MISMATCH: "agent_launch_authority_handoff_audience_mismatch",
  SESSION_NOT_AUTHORIZED: "agent_launch_authority_handoff_session_not_authorized",
  NOT_FOUND: "agent_launch_authority_handoff_not_found",
  RATE_LIMITED: "agent_launch_authority_handoff_rate_limited",
  NATIVE_PROOF_UNAVAILABLE: "agent_launch_authority_handoff_native_proof_unavailable",
  UNAVAILABLE: "agent_launch_authority_handoff_unavailable"
});

const ERROR_MESSAGES = Object.freeze({
  [AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.INVALID_REQUEST]: "The Agent launch authority handoff request is invalid",
  [AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.DEVICE_AUTH_FAILED]: "Device authentication failed",
  [AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.AUDIENCE_MISMATCH]: "The authenticated Device cannot use this Agent Session",
  [AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.SESSION_NOT_AUTHORIZED]: "The Agent Session is not authorized",
  [AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.NOT_FOUND]: "Resource not found",
  [AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.RATE_LIMITED]: "Rate limit exceeded",
  [AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.NATIVE_PROOF_UNAVAILABLE]: "Native Agent launch authority proof is unavailable",
  [AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.UNAVAILABLE]: "The Agent launch authority handoff service is unavailable"
});

export class AgentLaunchAuthorityHandoffHttpError extends Error {
  constructor(code, { status = statusFor(code), retryAfterSeconds, cause } = {}) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.UNAVAILABLE], { cause });
    this.name = "AgentLaunchAuthorityHandoffHttpError";
    this.code = code;
    this.status = status;
    if (retryAfterSeconds !== undefined) this.retryAfterSeconds = retryAfterSeconds;
  }
}

/**
 * Device-authenticated launch-handoff boundary. It validates the full public
 * Lease binding, then delegates to a repository that must own an atomic,
 * one-time native-proof handoff. The shipped repository is deliberately
 * unavailable until that native authority boundary exists.
 */
export function createAgentLaunchAuthorityHandoffApi({
  deviceRequestVerifier,
  deviceRequestAuthenticator,
  verifyDeviceRequest,
  sessionBinder,
  agentSessionBinder,
  authorizeAgentSession,
  sessionAuthorizer,
  repository = createPostgresAgentLaunchAuthorityHandoffRepository(),
  rateLimiter = undefined,
  now = () => Date.now(),
  requestIdFactory = () => crypto.randomUUID(),
  maxBodyBytes = MAX_BODY_BYTES
} = {}) {
  const deviceVerifier = resolveVerifier(deviceRequestVerifier ?? deviceRequestAuthenticator ?? verifyDeviceRequest);
  const bindSession = resolveSessionBinder(sessionBinder ?? agentSessionBinder ?? authorizeAgentSession ?? sessionAuthorizer);
  if (!repository || typeof repository.issueAgentLaunchAuthorityHandoff !== "function") throw new TypeError("repository must expose issueAgentLaunchAuthorityHandoff()");
  if (rateLimiter !== undefined && (!rateLimiter || typeof rateLimiter.acquire !== "function")) throw new TypeError("rateLimiter must expose acquire()");
  if (typeof now !== "function") throw new TypeError("now must be a function");
  if (typeof requestIdFactory !== "function") throw new TypeError("requestIdFactory must be a function");
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1_024 || maxBodyBytes > MAX_BODY_BYTES) throw new TypeError("maxBodyBytes is invalid");

  async function handle(input, nodeResponse = undefined) {
    const result = await dispatch(input);
    if (nodeResponse !== undefined) writeNodeResponse(nodeResponse, result);
    return result;
  }

  async function dispatch(input) {
    const requestId = makeRequestId(requestIdFactory);
    try {
      const request = await normalizeRequest(input, maxBodyBytes);
      const route = resolveRoute(request.path);
      if (!route) return response(404, errorBody(AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.NOT_FOUND, requestId));
      if (request.method !== METHOD) throw invalidRequest();
      rejectBearerOrRedirect(request);
      const clock = readClock(now);

      let authenticated;
      try {
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
      if (rateLimiter) await enforceRateLimit(rateLimiter, route);

      const body = parseRequestBody(request.body, request.headers, maxBodyBytes);
      try { normalizeAgentLaunchAuthorityHandoffRequest(body); }
      catch (error) {
        if (error instanceof AgentLaunchAuthorityHandoffContractError) throw invalidRequest();
        throw error;
      }
      let bound;
      try {
        bound = await bindSession({
          organization_id: route.organizationId,
          device_id: route.deviceId,
          session_id: route.sessionId,
          authenticated_device: publicDeviceIdentity(authenticated),
          now: clock
        });
      } catch (error) {
        throw mapSessionBindingError(error);
      }
      const binding = normalizeAgentLaunchAuthoritySessionBinding(bound, {
        organizationId: route.organizationId,
        deviceId: route.deviceId,
        sessionId: route.sessionId,
        now: clock
      });
      const repositoryInput = createAgentLaunchAuthorityHandoffBinding({
        request: body,
        lease: binding.lease,
        organizationId: route.organizationId,
        deviceId: route.deviceId,
        sessionId: route.sessionId,
        now: clock
      });

      try {
        await repository.issueAgentLaunchAuthorityHandoff(repositoryInput);
      } catch (error) {
        throw mapRepositoryError(error);
      }
      // No current Cloud component can safely validate and issue the native
      // opaque proof. Treat every repository result as unavailable until a
      // future version defines that cryptographic boundary explicitly.
      throw new AgentLaunchAuthorityHandoffHttpError(
        AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.NATIVE_PROOF_UNAVAILABLE
      );
    } catch (error) {
      const mapped = error instanceof AgentLaunchAuthorityHandoffHttpError
        ? error
        : new AgentLaunchAuthorityHandoffHttpError(AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.UNAVAILABLE, { cause: error });
      const headers = mapped.retryAfterSeconds === undefined ? undefined : { "Retry-After": String(mapped.retryAfterSeconds) };
      return response(mapped.status, errorBody(mapped.code, requestId), headers);
    }
  }

  return Object.freeze({ handle, paths: AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_PATHS, route: ROUTE });
}

function resolveVerifier(value) {
  if (typeof value === "function") return value;
  if (value && typeof value.verify === "function") return value.verify.bind(value);
  if (value && typeof value.authenticate === "function") return value.authenticate.bind(value);
  throw new TypeError("deviceRequestVerifier must be a function or expose verify()/authenticate()");
}

function resolveSessionBinder(value) {
  if (typeof value === "function") return value;
  if (value && typeof value.bindAgentSession === "function") return value.bindAgentSession.bind(value);
  if (value && typeof value.authorizeAgentSession === "function") return value.authorizeAgentSession.bind(value);
  if (value && typeof value.assertActiveAgentSession === "function") return value.assertActiveAgentSession.bind(value);
  throw new TypeError("sessionBinder must expose a full Agent Session Lease binding");
}

async function enforceRateLimit(rateLimiter, route) {
  let decision;
  try {
    decision = await rateLimiter.acquire({ tenantId: route.organizationId, principalType: "device", principalId: route.deviceId, sessionId: route.sessionId });
  } catch (error) {
    if (isRateLimitCode(error?.code) || error?.status === 429) throw new AgentLaunchAuthorityHandoffHttpError(AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.RATE_LIMITED, { status: 429, retryAfterSeconds: boundedRetryAfter(error), cause: error });
    throw new AgentLaunchAuthorityHandoffHttpError(AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.UNAVAILABLE, { cause: error });
  }
  if (!decision || typeof decision !== "object" || typeof decision.allowed !== "boolean"
    || !Number.isSafeInteger(decision.limit) || decision.limit < 1
    || !Number.isSafeInteger(decision.remaining) || decision.remaining < 0 || decision.remaining > decision.limit
    || !Number.isSafeInteger(decision.retryAfterSeconds) || decision.retryAfterSeconds < 0) throw new AgentLaunchAuthorityHandoffHttpError(AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.UNAVAILABLE);
  if (!decision.allowed) throw new AgentLaunchAuthorityHandoffHttpError(AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.RATE_LIMITED, { status: 429, retryAfterSeconds: decision.retryAfterSeconds });
}

async function normalizeRequest(input, maxBodyBytes) {
  if (!input || typeof input !== "object") throw invalidRequest();
  const method = typeof input.method === "string" ? input.method.toUpperCase() : "";
  const path = typeof input.url === "string" ? input.url : typeof input.originalUrl === "string" ? input.originalUrl : input.path;
  if (!method || typeof path !== "string" || path.length === 0 || Buffer.byteLength(path, "utf8") > MAX_URL_BYTES
    || !path.startsWith("/") || /[\u0000-\u0020\u007f#?\\]/u.test(path)) throw invalidRequest();
  const headers = input.headers ?? {};
  const contentLength = readHeader(headers, "content-length");
  if (contentLength !== undefined && (!/^\d+$/u.test(contentLength) || !Number.isSafeInteger(Number(contentLength)))) throw invalidRequest();
  if (contentLength !== undefined && Number(contentLength) > maxBodyBytes) throw new AgentLaunchAuthorityHandoffHttpError(AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
  const body = await readRawBody(input, maxBodyBytes);
  if (contentLength !== undefined && Number(contentLength) !== body.length) throw invalidRequest();
  return Object.freeze({ method, path, headers, body, input });
}

async function readRawBody(input, maxBodyBytes) {
  let raw = input.body;
  if (raw === undefined && typeof input.arrayBuffer === "function") raw = Buffer.from(await input.arrayBuffer());
  else if (raw === undefined && typeof input.text === "function") raw = await input.text();
  else if (raw === undefined && isAsyncIterable(input)) raw = await readStream(input, maxBodyBytes);
  else if (isAsyncIterable(raw)) raw = await readStream(raw, maxBodyBytes);
  const bytes = toBytes(raw);
  if (bytes.length > maxBodyBytes) throw new AgentLaunchAuthorityHandoffHttpError(AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
  return bytes;
}

async function readStream(stream, maxBodyBytes) {
  const chunks = [];
  let total = 0;
  for await (const chunk of stream) {
    const bytes = toBytes(chunk);
    total += bytes.length;
    if (total > maxBodyBytes) throw new AgentLaunchAuthorityHandoffHttpError(AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
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

function parseRequestBody(bytes, headers, maxBodyBytes) {
  if (!/^application\/json(?:\s*;|$)/iu.test(readHeader(headers, "content-type") ?? "")) throw invalidRequest();
  let value;
  try { value = parseBoundedJson(bytes, { maxBytes: maxBodyBytes, maxDepth: MAX_JSON_DEPTH }); }
  catch { throw invalidRequest(); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw invalidRequest();
  try {
    if (!Buffer.from(canonicalJson(value), "utf8").equals(bytes)) throw new Error("noncanonical JSON");
  } catch {
    throw invalidRequest();
  }
  return value;
}

function resolveRoute(path) {
  const match = /^\/v1\/organizations\/([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\/devices\/([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\/agent-sessions\/([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\/launch-authority-handoff$/u.exec(path);
  return match ? Object.freeze({ organizationId: match[1], deviceId: match[2], sessionId: match[3] }) : undefined;
}

function assertAuthenticatedDevice(value, route) {
  const principal = value?.principal ?? value?.device ?? value;
  const organizationId = principal?.organization_id ?? principal?.organizationId;
  const deviceId = principal?.device_id ?? principal?.deviceId;
  if (!UUID.test(deviceId ?? "") || (organizationId !== undefined && organizationId !== route.organizationId)) throw new AgentLaunchAuthorityHandoffHttpError(AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.AUDIENCE_MISMATCH, { status: 403 });
  if (deviceId !== route.deviceId) throw new AgentLaunchAuthorityHandoffHttpError(AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.AUDIENCE_MISMATCH, { status: 403 });
}

function publicDeviceIdentity(value) {
  const principal = value?.principal ?? value?.device ?? value;
  return Object.freeze({ organization_id: principal?.organization_id ?? principal?.organizationId, device_id: principal?.device_id ?? principal?.deviceId });
}

function rejectBearerOrRedirect(request) {
  if (Object.keys(request.headers).some((key) => FORBIDDEN_BEARER_HEADERS.has(key.toLowerCase())) || request.input?.redirected === true || request.input?.redirect_count !== undefined || request.input?.redirectCount !== undefined) throw invalidRequest();
}

function mapDeviceAuthenticationError(error) {
  if (error?.status === 503 || String(error?.code ?? "").toUpperCase().includes("UNAVAILABLE")) throw new AgentLaunchAuthorityHandoffHttpError(AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.UNAVAILABLE, { cause: error });
  throw new AgentLaunchAuthorityHandoffHttpError(AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.DEVICE_AUTH_FAILED, { status: 401, cause: error });
}

function mapSessionBindingError(error) {
  const code = String(error?.code ?? "").toUpperCase();
  if (code.includes("NOT_FOUND")) return new AgentLaunchAuthorityHandoffHttpError(AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.NOT_FOUND, { status: 404, cause: error });
  if (code.includes("CONFLICT") || error?.status === 409) return new AgentLaunchAuthorityHandoffHttpError(AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.SESSION_NOT_AUTHORIZED, { status: 403, cause: error });
  return new AgentLaunchAuthorityHandoffHttpError(AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.UNAVAILABLE, { cause: error });
}

function mapRepositoryError(error) {
  if (error?.code === AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.NATIVE_PROOF_UNAVAILABLE) return new AgentLaunchAuthorityHandoffHttpError(AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.NATIVE_PROOF_UNAVAILABLE, { status: 503, cause: error });
  if (error?.code === AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.INVALID_INPUT) return invalidRequest();
  return new AgentLaunchAuthorityHandoffHttpError(AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.UNAVAILABLE, { cause: error });
}

function invalidRequest() { return new AgentLaunchAuthorityHandoffHttpError(AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 }); }
function readClock(now) { const value = now(); if (!Number.isSafeInteger(value) || value < 0) throw new AgentLaunchAuthorityHandoffHttpError(AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.UNAVAILABLE); return value; }
function makeRequestId(factory) { const value = factory(); if (typeof value !== "string" || !UUID.test(value)) return crypto.randomUUID(); return value.toLowerCase(); }
function errorBody(code, requestId) { return Object.freeze({ error: Object.freeze({ code, message: ERROR_MESSAGES[code] ?? ERROR_MESSAGES[AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.UNAVAILABLE] }), request_id: requestId }); }
function response(status, body, headers = {}) { return Object.freeze({ status, body: Object.freeze(body), headers: Object.freeze({ ...RESPONSE_HEADERS, ...headers }) }); }
function statusFor(code) { return code === AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.RATE_LIMITED ? 429 : code === AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.INVALID_REQUEST ? 400 : code === AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.DEVICE_AUTH_FAILED ? 401 : code === AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.AUDIENCE_MISMATCH || code === AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.SESSION_NOT_AUTHORIZED ? 403 : code === AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.NOT_FOUND ? 404 : 503; }
function boundedRetryAfter(error) { const value = Number(error?.retryAfterSeconds); return Number.isSafeInteger(value) && value >= 0 && value <= 86_400 ? value : 1; }
function isRateLimitCode(code) { return ["ERR_RATE_LIMITED", "RATE_LIMITED", "RATE_LIMITER_CAPACITY_EXHAUSTED"].includes(String(code).toUpperCase()); }
function readHeader(headers, name) { const target = name.toLowerCase(); const key = Object.keys(headers ?? {}).find((candidate) => candidate.toLowerCase() === target); const value = key === undefined ? undefined : headers[key]; return typeof value === "string" ? value : undefined; }
function isAsyncIterable(value) { return value && typeof value[Symbol.asyncIterator] === "function"; }
function writeNodeResponse(nodeResponse, result) { nodeResponse.writeHead(result.status, result.headers); nodeResponse.end(JSON.stringify(result.body)); }
