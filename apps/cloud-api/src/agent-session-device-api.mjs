import crypto from "node:crypto";

import { parseBoundedJson } from "../../../lib/control-bundle-v2.mjs";
import { validateScope } from "../../../packages/capability/src/index.mjs";
import { canonicalJson } from "../../../packages/protocol/src/index.mjs";

const DEVICE_ROUTE = "/v1/organizations/{organization_id}/devices/{device_id}/agent-session-grants/{grant_id}/consume";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const BASE64URL_SIGNATURE = /^[A-Za-z0-9_-]{86}$/u;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const ADAPTER_VERSION = /^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const METHOD = "POST";
const MAX_URL_BYTES = 8 * 1024;
const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;
const MAX_JSON_DEPTH = 32;
const ALLOWED_AGENT_KINDS = new Set(["claude-code", "cursor"]);
const RESPONSE_HEADERS = Object.freeze({
  "Cache-Control": "no-store, max-age=0",
  "Pragma": "no-cache",
  "Expires": "0",
  "Content-Type": "application/json; charset=utf-8",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer"
});

const BODY_KEYS = new Set(["grant", "process_binding_sha256", "ancestry_binding_sha256"]);
const GRANT_KEYS = new Set(["version", "type", "statement", "statement_hash", "signature"]);
const STATEMENT_KEYS = new Set([
  "version", "grant_id", "organization_id", "device_id", "agent_id", "agent_kind",
  "adapter_id", "adapter_version", "worktree_binding_sha256", "process_binding_policy_id",
  "scope", "max_signatures", "not_before", "expires_at", "control_sequence", "issuer", "key_id"
]);
const LEASE_KEYS = new Set([
  "version", "type", "session_id", "grant_id", "organization_id", "device_id", "agent_id",
  "agent_kind", "adapter_id", "adapter_version", "process_binding_sha256",
  "ancestry_binding_sha256", "worktree_binding_sha256", "max_signatures", "used_signatures",
  "not_before", "expires_at", "control_sequence"
]);

export const AGENT_SESSION_DEVICE_HTTP_PATHS = Object.freeze({ consume: DEVICE_ROUTE });

export const AGENT_SESSION_DEVICE_HTTP_ERROR_CODES = Object.freeze({
  INVALID_REQUEST: "invalid_request",
  DEVICE_AUTH_FAILED: "device_auth_failed",
  GRANT_NOT_AUTHORIZED: "grant_not_authorized",
  AUDIENCE_MISMATCH: "audience_mismatch",
  NOT_FOUND: "not_found",
  GRANT_CONFLICT: "grant_conflict",
  RATE_LIMITED: "rate_limited",
  UNAVAILABLE: "agent_session_unavailable"
});

const ERROR_MESSAGES = Object.freeze({
  [AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.INVALID_REQUEST]: "The Agent Session Grant request is invalid",
  [AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.DEVICE_AUTH_FAILED]: "Device authentication failed",
  [AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.GRANT_NOT_AUTHORIZED]: "The Agent Session Grant is not authorized",
  [AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.AUDIENCE_MISMATCH]: "The authenticated device cannot use this grant",
  [AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.NOT_FOUND]: "Resource not found",
  [AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.GRANT_CONFLICT]: "The Agent Session Grant conflicts with prior consumption",
  [AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.RATE_LIMITED]: "Rate limit exceeded",
  [AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.UNAVAILABLE]: "The Agent Session Grant service is unavailable"
});

export class AgentSessionDeviceHttpError extends Error {
  constructor(code, { status, retryAfterSeconds, cause } = {}) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.UNAVAILABLE], { cause });
    this.name = "AgentSessionDeviceHttpError";
    this.code = code;
    this.status = status ?? statusFor(code);
    if (retryAfterSeconds !== undefined) this.retryAfterSeconds = retryAfterSeconds;
  }
}

/**
 * Framework-neutral M2-A Device API boundary.
 *
 * The device verifier receives the exact method, path, headers, and raw body
 * bytes before JSON parsing. The grant verifier authenticates the public
 * Cloud-signed envelope. The repository is the sole owner of one-time
 * consumption and exact retry semantics:
 *
 * consumeAgentSessionGrant({
 *   organization_id, device_id, grant_id, agent_id, grant_hash,
 *   statement_hash, grant, process_binding_sha256, ancestry_binding_sha256,
 *   retry_identity_sha256, observed_at
 * }) -> { lease } | lease
 *
 * Repository input intentionally contains no headers, raw body, audit token,
 * PID, process path, ancestry record, or secret material.
 */
export function createAgentSessionDeviceApi({
  deviceRequestVerifier,
  deviceRequestAuthenticator,
  verifyDeviceRequest,
  grantVerifier,
  repository,
  now = () => Date.now(),
  requestIdFactory = () => crypto.randomUUID(),
  maxBodyBytes = DEFAULT_MAX_BODY_BYTES
} = {}) {
  const deviceVerifier = resolveVerifier(deviceRequestVerifier ?? deviceRequestAuthenticator ?? verifyDeviceRequest, "deviceRequestVerifier");
  const signedGrantVerifier = resolveVerifier(grantVerifier, "grantVerifier");
  if (!repository || typeof repository.consumeAgentSessionGrant !== "function") {
    throw new TypeError("repository must expose consumeAgentSessionGrant()");
  }
  if (typeof now !== "function") throw new TypeError("now must be a function");
  if (typeof requestIdFactory !== "function") throw new TypeError("requestIdFactory must be a function");
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1_024 || maxBodyBytes > DEFAULT_MAX_BODY_BYTES) {
    throw new TypeError("maxBodyBytes is invalid");
  }

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
      if (!route) return response(404, { error: { code: AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.NOT_FOUND, message: ERROR_MESSAGES[AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.NOT_FOUND] }, request_id: requestId });
      if (request.method !== METHOD) throw invalidRequest();

      const clock = readClock(now);
      let authenticated;
      try {
        // This is deliberately the first operation involving the body. A
        // verifier may hash/sign these exact bytes and the exact raw path.
        authenticated = await deviceVerifier({
          method: request.method,
          path: request.path,
          body: Buffer.from(request.body),
          headers: request.headers
        }, {
          organization_id: route.organizationId,
          organizationId: route.organizationId,
          now: clock,
          includeAuthenticationMetadata: true
        });
      } catch (error) {
        throw mapDeviceAuthenticationError(error);
      }
      assertAuthenticatedDevice(authenticated, route);

      const body = parseBody(request.body, maxBodyBytes);
      assertExactKeys(body, BODY_KEYS, "consume request");
      if (!SHA256.test(body.process_binding_sha256 ?? "") || !SHA256.test(body.ancestry_binding_sha256 ?? "")) {
        throw invalidRequest();
      }

      const grant = validateGrantEnvelope(body.grant);
      assertGrantPathBinding(grant.statement, route);

      let verification;
      try {
        verification = await signedGrantVerifier(grant, {
          organization_id: route.organizationId,
          device_id: route.deviceId,
          grant_id: route.grantId,
          now: clock,
          statement_hash: grant.statement_hash
        });
      } catch (error) {
        throw mapGrantVerificationError(error);
      }
      assertGrantVerification(verification, grant);

      const statement = grant.statement;
      const grantHash = sha256(canonicalJson(grant));
      const retryIdentityHash = sha256(canonicalJson({
        version: 1,
        statement_hash: grant.statement_hash,
        process_binding_sha256: body.process_binding_sha256,
        ancestry_binding_sha256: body.ancestry_binding_sha256
      }));
      let stored;
      try {
        stored = await repository.consumeAgentSessionGrant(Object.freeze({
          organization_id: route.organizationId,
          device_id: route.deviceId,
          grant_id: route.grantId,
          agent_id: statement.agent_id,
          agent_kind: statement.agent_kind,
          adapter_id: statement.adapter_id,
          adapter_version: statement.adapter_version,
          worktree_binding_sha256: statement.worktree_binding_sha256,
          process_binding_policy_id: statement.process_binding_policy_id,
          scope: deepFreeze(clonePublicValue(statement.scope)),
          max_signatures: statement.max_signatures,
          not_before: statement.not_before,
          expires_at: statement.expires_at,
          control_sequence: statement.control_sequence,
          issuer: statement.issuer,
          key_id: statement.key_id,
          grant: deepFreeze(clonePublicValue(grant)),
          grant_hash: grantHash,
          statement_hash: grant.statement_hash,
          process_binding_sha256: body.process_binding_sha256,
          ancestry_binding_sha256: body.ancestry_binding_sha256,
          retry_identity_sha256: retryIdentityHash,
          observed_at: new Date(clock).toISOString()
        }));
      } catch (error) {
        throw mapRepositoryError(error);
      }

      const lease = normalizeLease(stored?.lease ?? stored, statement, body.process_binding_sha256, body.ancestry_binding_sha256);
      return response(201, { lease, request_id: requestId });
    } catch (error) {
      const mapped = error instanceof AgentSessionDeviceHttpError ? error : new AgentSessionDeviceHttpError(AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.UNAVAILABLE, { cause: error });
      const headers = mapped.retryAfterSeconds === undefined ? undefined : { "Retry-After": String(mapped.retryAfterSeconds) };
      return response(mapped.status, { error: { code: mapped.code, message: ERROR_MESSAGES[mapped.code] ?? ERROR_MESSAGES[AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.UNAVAILABLE] }, request_id: requestId }, headers);
    }
  }

  return Object.freeze({
    handle,
    paths: AGENT_SESSION_DEVICE_HTTP_PATHS,
    route: DEVICE_ROUTE
  });
}

function resolveVerifier(value, label) {
  if (typeof value === "function") return value;
  if (value && typeof value.verify === "function") return value.verify.bind(value);
  if (value && typeof value.verifyGrant === "function") return value.verifyGrant.bind(value);
  if (value && typeof value.authenticate === "function") return value.authenticate.bind(value);
  throw new TypeError(`${label} must be a function or expose verify()/authenticate()`);
}

async function normalizeRequest(input, maxBodyBytes) {
  if (!input || typeof input !== "object") throw invalidRequest();
  const method = typeof input.method === "string" ? input.method.toUpperCase() : "";
  const path = typeof input.url === "string" ? input.url : typeof input.originalUrl === "string" ? input.originalUrl : input.path;
  if (!method || typeof path !== "string" || path.length === 0 || Buffer.byteLength(path, "utf8") > MAX_URL_BYTES) throw invalidRequest();
  if (!path.startsWith("/") || /[\u0000-\u0020\u007f#?\\]/u.test(path)) throw invalidRequest();
  const headers = input.headers ?? {};
  const body = await readRawBody(input, maxBodyBytes);
  return Object.freeze({ method, path, headers, body });
}

async function readRawBody(input, maxBodyBytes) {
  let raw = input.body;
  if (raw === undefined && typeof input.arrayBuffer === "function") raw = Buffer.from(await input.arrayBuffer());
  else if (raw === undefined && typeof input.text === "function") raw = await input.text();
  else if (raw === undefined && isAsyncIterable(input)) raw = await readStream(input, maxBodyBytes);
  else if (isAsyncIterable(raw)) raw = await readStream(raw, maxBodyBytes);
  const bytes = toBytes(raw);
  if (bytes.length > maxBodyBytes) throw invalidRequest();
  return bytes;
}

async function readStream(stream, maxBodyBytes) {
  const chunks = [];
  let total = 0;
  for await (const chunk of stream) {
    const bytes = toBytes(chunk);
    total += bytes.length;
    if (total > maxBodyBytes) throw invalidRequest();
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
  const match = /^\/v1\/organizations\/([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\/devices\/([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\/agent-session-grants\/([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\/consume$/u.exec(path);
  return match ? Object.freeze({ organizationId: match[1], deviceId: match[2], grantId: match[3] }) : undefined;
}

function parseBody(bytes, maxBodyBytes) {
  let value;
  try { value = parseBoundedJson(bytes, { maxBytes: maxBodyBytes, maxDepth: MAX_JSON_DEPTH }); }
  catch { throw invalidRequest(); }
  if (!isObject(value)) throw invalidRequest();
  return value;
}

function validateGrantEnvelope(value) {
  if (!isObject(value)) throw invalidRequest();
  assertExactKeys(value, GRANT_KEYS, "grant");
  if (value.version !== 1 || value.type !== "agentpass.agent-session-grant") throw invalidRequest();
  if (!SHA256.test(value.statement_hash ?? "") || !BASE64URL_SIGNATURE.test(value.signature ?? "")) throw invalidRequest();
  const signatureBytes = Buffer.from(value.signature, "base64url");
  if (signatureBytes.length !== 64 || signatureBytes.toString("base64url") !== value.signature) throw invalidRequest();
  const statement = validateGrantStatement(value.statement);
  let expectedHash;
  try { expectedHash = sha256(canonicalJson(statement)); } catch { throw invalidRequest(); }
  if (expectedHash !== value.statement_hash) throw invalidRequest();
  return deepFreeze(clonePublicValue({ ...value, statement }));
}

function validateGrantStatement(value) {
  if (!isObject(value)) throw invalidRequest();
  assertExactKeys(value, STATEMENT_KEYS, "grant statement");
  if (value.version !== 1 || !UUID.test(value.grant_id ?? "") || !UUID.test(value.organization_id ?? "")
    || !UUID.test(value.device_id ?? "") || !UUID.test(value.agent_id ?? "") || !ALLOWED_AGENT_KINDS.has(value.agent_kind)
    || !UUID.test(value.adapter_id ?? "") || !ADAPTER_VERSION.test(value.adapter_version ?? "")
    || !SHA256.test(value.worktree_binding_sha256 ?? "") || !SAFE_IDENTIFIER.test(value.process_binding_policy_id ?? "")
    || !Number.isSafeInteger(value.max_signatures) || value.max_signatures < 1 || value.max_signatures > 64
    || !TIMESTAMP.test(value.not_before ?? "") || !TIMESTAMP.test(value.expires_at ?? "")
    || !Number.isSafeInteger(value.control_sequence) || value.control_sequence < 1
    || value.issuer !== "agentpass-cloud" || !SAFE_IDENTIFIER.test(value.key_id ?? "")) {
    throw invalidRequest();
  }
  const notBefore = parseCanonicalTimestamp(value.not_before);
  const expiresAt = parseCanonicalTimestamp(value.expires_at);
  if (expiresAt <= notBefore) throw invalidRequest();
  try { validateScope(value.scope); } catch { throw invalidRequest(); }
  return value;
}

function assertGrantPathBinding(statement, route) {
  if (statement.organization_id !== route.organizationId || statement.device_id !== route.deviceId || statement.grant_id !== route.grantId) {
    throw invalidRequest();
  }
}

function assertAuthenticatedDevice(value, route) {
  const principal = value?.principal ?? value?.device ?? value;
  const deviceId = principal?.device_id ?? principal?.deviceId;
  const organizationId = principal?.organization_id ?? principal?.organizationId;
  if (typeof deviceId !== "string") throw new AgentSessionDeviceHttpError(AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.DEVICE_AUTH_FAILED, { status: 401 });
  if (deviceId !== route.deviceId || (organizationId !== undefined && organizationId !== route.organizationId)) {
    throw new AgentSessionDeviceHttpError(AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.AUDIENCE_MISMATCH, { status: 403 });
  }
}

function assertGrantVerification(value, grant) {
  if (value === true) return;
  if (!value || typeof value !== "object" || Array.isArray(value) || value.verified === false) {
    throw new AgentSessionDeviceHttpError(AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.GRANT_NOT_AUTHORIZED, { status: 403 });
  }
  if (value.verified === true && value.grant === undefined && value.verified_grant === undefined) return;
  const verifiedGrant = value.grant ?? value.verified_grant ?? (value.statement && value.signature ? value : undefined);
  if (!verifiedGrant || !isObject(verifiedGrant)) throw new AgentSessionDeviceHttpError(AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.GRANT_NOT_AUTHORIZED, { status: 403 });
  try {
    if (canonicalJson(validateGrantEnvelope(verifiedGrant)) !== canonicalJson(grant)) throw new Error("grant mismatch");
  } catch {
    throw new AgentSessionDeviceHttpError(AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.GRANT_NOT_AUTHORIZED, { status: 403 });
  }
}

function normalizeLease(value, statement, processBinding, ancestryBinding) {
  if (!isObject(value)) throw new AgentSessionDeviceHttpError(AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.UNAVAILABLE, { status: 503 });
  assertExactKeys(value, LEASE_KEYS, "repository lease", unavailable);
  if (value.version !== 1 || value.type !== "agentpass.agent-session-lease"
    || !UUID.test(value.session_id ?? "") || value.grant_id !== statement.grant_id
    || value.organization_id !== statement.organization_id || value.device_id !== statement.device_id
    || value.agent_id !== statement.agent_id || value.agent_kind !== statement.agent_kind
    || value.adapter_id !== statement.adapter_id || value.adapter_version !== statement.adapter_version
    || value.process_binding_sha256 !== processBinding || value.ancestry_binding_sha256 !== ancestryBinding
    || value.worktree_binding_sha256 !== statement.worktree_binding_sha256
    || value.max_signatures !== statement.max_signatures || !Number.isSafeInteger(value.used_signatures)
    || value.used_signatures < 0 || value.used_signatures > value.max_signatures
    || value.not_before !== statement.not_before || value.expires_at !== statement.expires_at
    || value.control_sequence !== statement.control_sequence) throw unavailable();
  try {
    parseCanonicalTimestamp(value.not_before);
    parseCanonicalTimestamp(value.expires_at);
  } catch {
    throw unavailable();
  }
  return deepFreeze(clonePublicValue(value));
}

function assertExactKeys(value, allowed, label, failure = invalidRequest) {
  const keys = Object.keys(value);
  if (keys.length !== allowed.size || keys.some((key) => !allowed.has(key))) throw failure(`invalid ${label}`);
}

function mapDeviceAuthenticationError(error) {
  const code = String(error?.code ?? "");
  if (isUnavailableCode(code) || error?.status === 503) return unavailable();
  if (error?.status === 403 || code === "organization_mismatch") return new AgentSessionDeviceHttpError(AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.AUDIENCE_MISMATCH, { status: 403, cause: error });
  return new AgentSessionDeviceHttpError(AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.DEVICE_AUTH_FAILED, { status: 401, cause: error });
}

function mapGrantVerificationError(error) {
  const code = String(error?.code ?? "").toLowerCase();
  if (isUnavailableCode(code) || error?.status === 503) return unavailable();
  if (isConflictCode(code) || code === "err_agent_session_grant_expired" || code === "err_agent_session_grant_not_yet_valid" || error?.status === 409) {
    return new AgentSessionDeviceHttpError(AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.GRANT_CONFLICT, { status: 409, cause: error });
  }
  if (code === "err_agent_session_grant_input" || code.includes("invalid_input")) return invalidRequest();
  return new AgentSessionDeviceHttpError(AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.GRANT_NOT_AUTHORIZED, { status: 403, cause: error });
}

function mapRepositoryError(error) {
  const code = String(error?.code ?? "").toUpperCase();
  if (error instanceof AgentSessionDeviceHttpError) return error;
  if (isRateLimitCode(code) || error?.status === 429) return new AgentSessionDeviceHttpError(AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.RATE_LIMITED, { status: 429, retryAfterSeconds: boundedRetryAfter(error), cause: error });
  if (isNotFoundCode(code) || error?.status === 404) return new AgentSessionDeviceHttpError(AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.NOT_FOUND, { status: 404, cause: error });
  if (isForbiddenCode(code) || error?.status === 403) return new AgentSessionDeviceHttpError(AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.AUDIENCE_MISMATCH, { status: 403, cause: error });
  if (isConflictCode(code) || error?.status === 409) return new AgentSessionDeviceHttpError(AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.GRANT_CONFLICT, { status: 409, cause: error });
  if (isInputCode(code) || error?.status === 400) return invalidRequest();
  return unavailable();
}

function isUnavailableCode(code) {
  const normalized = String(code).toUpperCase();
  return normalized === "ERR_DATABASE" || normalized === "ERR_DB_CLIENT" || normalized === "ERR_DB_UNAVAILABLE" || normalized === "ERR_UNAVAILABLE"
    || normalized === "ERR_SERVICE_UNAVAILABLE" || normalized === "ERR_REPOSITORY_UNAVAILABLE" || normalized === "ETIMEDOUT"
    || normalized === "ERR_CLOCK" || normalized === "ERR_AGENT_SESSION_GRANT_CONFIG" || normalized === "ERR_AGENT_SESSION_GRANT_OUTPUT"
    || normalized.includes("UNAVAILABLE") || normalized.includes("PROVIDER");
}

function isNotFoundCode(code) {
  const normalized = String(code).toUpperCase();
  return normalized === "ERR_NOT_FOUND" || normalized === "ERR_ORGANIZATION_NOT_FOUND" || normalized === "ERR_DEVICE_NOT_FOUND"
    || normalized === "ERR_AGENT_NOT_FOUND" || normalized === "ERR_GRANT_NOT_FOUND";
}

function isForbiddenCode(code) {
  const normalized = String(code).toUpperCase();
  return normalized === "ERR_FORBIDDEN" || normalized === "ERR_AUTHORIZATION_DENIED" || normalized === "ERR_TENANT_SCOPE" || normalized === "ERR_TENANT_DRIFT";
}

function isConflictCode(code) {
  const normalized = String(code).toUpperCase();
  return normalized === "ERR_CONFLICT" || normalized === "ERR_GRANT_CONFLICT" || normalized === "ERR_GRANT_CONSUMED"
    || normalized === "ERR_GRANT_EXPIRED" || normalized === "ERR_GRANT_REVOKED" || normalized === "ERR_SESSION_CONFLICT"
    || normalized === "ERR_BINDING_CONFLICT" || normalized === "ERR_GRANT_NOT_YET_VALID" || normalized === "ERR_IDEMPOTENCY_CONFLICT" || normalized === "ERR_UNIQUE_CONSTRAINT"
    || normalized === "ERR_SERIALIZATION_FAILURE" || normalized === "ERR_VERSION_CONFLICT" || normalized === "40001";
}

function isRateLimitCode(code) {
  const normalized = String(code).toUpperCase();
  return normalized === "ERR_RATE_LIMITED" || normalized === "RATE_LIMITED" || normalized === "RATE_LIMITER_CAPACITY_EXHAUSTED";
}

function isInputCode(code) {
  const normalized = String(code).toUpperCase();
  return normalized === "ERR_INPUT" || normalized === "ERR_INVALID_INPUT" || normalized === "ERR_INVALID_UUID" || normalized === "ERR_PROTOCOL_VALIDATION" || normalized === "ERR_HASH_MISMATCH";
}

function boundedRetryAfter(error) {
  const value = error?.retryAfterSeconds ?? error?.retry_after_seconds;
  return Number.isSafeInteger(value) && value >= 0 && value <= 3600 ? value : 1;
}

function invalidRequest() {
  return new AgentSessionDeviceHttpError(AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
}

function unavailable() {
  return new AgentSessionDeviceHttpError(AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.UNAVAILABLE, { status: 503 });
}

function readClock(now) {
  let value;
  try { value = now(); } catch (error) { throw unavailableWithCause(error); }
  if (!Number.isSafeInteger(value) || value < 0 || value > 8_640_000_000_000_000) throw unavailable();
  return value;
}

function unavailableWithCause(cause) {
  return new AgentSessionDeviceHttpError(AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.UNAVAILABLE, { status: 503, cause });
}

function parseCanonicalTimestamp(value) {
  const parsed = Date.parse(value);
  if (!TIMESTAMP.test(value) || !Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) throw invalidRequest();
  return parsed;
}

function sha256(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function makeRequestId(factory) {
  try {
    const value = factory();
    if (typeof value === "string" && UUID.test(value)) return value;
  } catch { /* Use a fresh local correlation ID below. */ }
  return crypto.randomUUID();
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function clonePublicValue(value) {
  if (Array.isArray(value)) return value.map(clonePublicValue);
  if (isObject(value)) return Object.fromEntries(Object.entries(value).map(([key, nested]) => [key, clonePublicValue(nested)]));
  return value;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const nested of Object.values(value)) deepFreeze(nested);
  return Object.freeze(value);
}

function statusFor(code) {
  return code === AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.INVALID_REQUEST ? 400
    : code === AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.DEVICE_AUTH_FAILED ? 401
      : code === AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.GRANT_NOT_AUTHORIZED || code === AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.AUDIENCE_MISMATCH ? 403
        : code === AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.NOT_FOUND ? 404
          : code === AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.GRANT_CONFLICT ? 409
            : code === AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.RATE_LIMITED ? 429 : 503;
}

function response(status, body, extraHeaders = undefined) {
  const headers = Object.freeze({ ...RESPONSE_HEADERS, ...(extraHeaders ?? {}) });
  const json = JSON.stringify(body);
  return Object.freeze({
    status,
    ok: status >= 200 && status < 300,
    headers,
    body: Object.freeze(body),
    text: async () => json,
    json: async () => body,
    toResponse: () => new Response(json, { status, headers })
  });
}

function writeNodeResponse(nodeResponse, result) {
  if (!nodeResponse || typeof nodeResponse.end !== "function") throw new TypeError("nodeResponse is invalid");
  if (typeof nodeResponse.writeHead === "function") nodeResponse.writeHead(result.status, result.headers);
  else if (typeof nodeResponse.setHeader === "function") for (const [name, value] of Object.entries(result.headers)) nodeResponse.setHeader(name, value);
  nodeResponse.statusCode = result.status;
  nodeResponse.end(JSON.stringify(result.body));
}

function isAsyncIterable(value) {
  return value !== null && value !== undefined && typeof value[Symbol.asyncIterator] === "function";
}
