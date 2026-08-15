import crypto from "node:crypto";

import {
  PLATFORM_AUTHORIZED_PROMOTION_ISSUE_PATH,
  normalizePlatformAuthorizedPromotionRequest,
  normalizePlatformPromotionResult
} from "./platform-promotion-http-contract.mjs";
import { PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES } from "./platform-promotion-issuance.mjs";
import {
  PLATFORM_SESSION_COOKIE_NAME,
  PLATFORM_SESSION_CSRF_HEADER,
  hashPlatformSessionToken,
  isPlatformSessionToken,
  parsePlatformSessionCookie
} from "./platform-session-transport.mjs";
import {
  PLATFORM_SESSION_RATE_LIMIT_ERROR_CODES,
  PlatformSessionRateLimitError
} from "./platform-session-rate-limit.mjs";
import { DuplicateJsonKeyError, parseJsonNoDuplicateKeys } from "./strict-json.mjs";

const DEFAULT_MAX_BODY_BYTES = 64 * 1024;
const MAX_URL_BYTES = 8 * 1024;
const MAX_HEADER_BYTES = 8 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const JSON_CONTENT_TYPE = /^application\/json(?:\s*;\s*(?:charset\s*=\s*)?[^;]+)*$/iu;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/u;
const FORBIDDEN_HEADERS = new Set([
  "authorization",
  "agentpass-csrf",
  "x-csrf-token",
  "agentpass-recent-auth",
  "agentpass-console-identity",
  "agentpass-console-user-id",
  "agentpass-principal-id",
  "agentpass-member-id",
  "agentpass-organization-id",
  "agentpass-assignment-id",
  "agentpass-authority-generation",
  "x-agentpass-identity",
  "x-agentpass-principal-id",
  "x-agentpass-member-id",
  "x-agentpass-organization-id",
  "x-agentpass-assignment-id",
  "x-agentpass-authority-generation"
]);

export const PLATFORM_PROMOTION_PROOF_ID_HEADER = "agentpass-platform-proof-id";
export const PLATFORM_PROMOTION_JTI_HEADER = "agentpass-platform-jti";
export const PLATFORM_PROMOTION_HTTP_PATHS = Object.freeze({ issue: PLATFORM_AUTHORIZED_PROMOTION_ISSUE_PATH });

export const PLATFORM_PROMOTION_HTTP_ERROR_CODES = Object.freeze({
  INVALID_REQUEST: "platform_promotion_http_invalid_request",
  METHOD_NOT_ALLOWED: "platform_promotion_http_method_not_allowed",
  ORIGIN_NOT_ALLOWED: "platform_promotion_http_origin_not_allowed",
  AUTHORIZATION_REQUIRED: "platform_promotion_http_authorization_required",
  CSRF_FAILED: "platform_promotion_http_csrf_failed",
  IDEMPOTENCY_CONFLICT: "platform_promotion_http_idempotency_conflict",
  IN_PROGRESS: "platform_promotion_http_in_progress",
  UNCERTAIN: "platform_promotion_http_uncertain",
  UNAVAILABLE: "platform_promotion_http_unavailable"
});

const ERROR_MESSAGES = Object.freeze({
  [PLATFORM_PROMOTION_HTTP_ERROR_CODES.INVALID_REQUEST]: "The Platform promotion request is invalid",
  [PLATFORM_PROMOTION_HTTP_ERROR_CODES.METHOD_NOT_ALLOWED]: "The HTTP method is not allowed",
  [PLATFORM_PROMOTION_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED]: "The request origin is not allowed",
  [PLATFORM_PROMOTION_HTTP_ERROR_CODES.AUTHORIZATION_REQUIRED]: "Valid Platform promotion authorization is required",
  [PLATFORM_PROMOTION_HTTP_ERROR_CODES.CSRF_FAILED]: "The Platform promotion CSRF token is invalid",
  [PLATFORM_PROMOTION_HTTP_ERROR_CODES.IDEMPOTENCY_CONFLICT]: "The Platform promotion request conflicts with prior state",
  [PLATFORM_PROMOTION_HTTP_ERROR_CODES.IN_PROGRESS]: "The Platform promotion request is already in progress",
  [PLATFORM_PROMOTION_HTTP_ERROR_CODES.UNCERTAIN]: "The Platform promotion outcome is uncertain",
  [PLATFORM_PROMOTION_HTTP_ERROR_CODES.UNAVAILABLE]: "Platform promotion issuance is unavailable"
});

class PlatformPromotionHttpError extends Error {
  constructor(code, status, { headers = undefined, cause = undefined } = {}) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[PLATFORM_PROMOTION_HTTP_ERROR_CODES.UNAVAILABLE], { cause });
    this.name = "PlatformPromotionHttpError";
    this.code = code;
    this.status = status;
    this.headers = headers;
  }
}

/** Issue-only HTTP boundary for an already WebAuthn-authorized Platform Session. */
export function createPlatformPromotionHttpApi({
  promotionService,
  rateLimiter,
  origin,
  maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
  randomUUID = crypto.randomUUID
} = {}) {
  if (!promotionService || typeof promotionService.issuePlatformPromotion !== "function") {
    throw new TypeError("authorized Platform promotion service is required");
  }
  if (!rateLimiter || typeof rateLimiter.acquire !== "function") {
    throw new TypeError("Platform promotion rate limiter is required");
  }
  assertOrigin(origin);
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 128 || maxBodyBytes > 1024 * 1024) {
    throw new TypeError("maxBodyBytes is invalid");
  }
  if (typeof randomUUID !== "function") throw new TypeError("randomUUID is invalid");

  async function handle(input, nodeResponse = undefined) {
    const result = await dispatch(input);
    if (nodeResponse !== undefined) writeNodeResponse(nodeResponse, result);
    return result;
  }

  async function dispatch(input) {
    try {
      const request = normalizeRequest(input);
      const route = resolveRoute(request.url);
      if (route === undefined) return response(404, { error: { code: "not_found", message: "Resource not found" } });
      if (route.invalid) throw httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.INVALID_REQUEST, 400);
      if (request.method !== "POST") {
        throw httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.METHOD_NOT_ALLOWED, 405, { headers: { Allow: "POST" } });
      }
      for (const name of Object.keys(request.headers)) if (FORBIDDEN_HEADERS.has(name)) throw httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.INVALID_REQUEST, 400);
      const requestOrigin = header(request.headers, "origin");
      if (requestOrigin === undefined || requestOrigin === "null" || requestOrigin !== origin) {
        throw httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED, 403);
      }

      const token = requirePlatformSession(request.headers);
      const csrfToken = requireCsrfToken(request.headers);
      const proofId = requireUuidHeader(request.headers, PLATFORM_PROMOTION_PROOF_ID_HEADER);
      const jti = requireUuidHeader(request.headers, PLATFORM_PROMOTION_JTI_HEADER);
      const body = await readJsonBody(request, maxBodyBytes);
      let intent;
      try { intent = normalizePlatformAuthorizedPromotionRequest(body, header(request.headers, "idempotency-key")); }
      catch (error) { throw httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.INVALID_REQUEST, 400, { cause: error }); }

      const sessionMaterialHash = hashPlatformSessionToken(token);
      await acquireRateLimit(rateLimiter, request, {
        phase: "promotion",
        sessionMaterialHash,
        csrfTokenHash: sha256Text(csrfToken),
        jtiHash: sha256Text(jti),
        proofId
      });

      let issued;
      try {
        issued = await promotionService.issuePlatformPromotion({
          promotion_id: intent.promotion_id,
          deployment_id: intent.deployment_id,
          environment: intent.environment,
          candidate_id: intent.candidate_id,
          idempotency_key: intent.idempotency_key,
          organization_id: intent.organization_id,
          session_material_hash: sessionMaterialHash,
          csrf_token: csrfToken,
          proof_id: proofId,
          jti
        });
      } catch (error) {
        throw mapServiceError(error);
      }

      let promotion;
      try { promotion = normalizePlatformPromotionResult(issued, intent); }
      catch (error) { throw httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.UNAVAILABLE, 503, { cause: error }); }
      const requestId = safeUuid(randomUUID());
      return response(promotion.replayed ? 200 : 201, { request_id: requestId, promotion });
    } catch (error) {
      return mapError(error);
    }
  }

  return Object.freeze({ handle, paths: PLATFORM_PROMOTION_HTTP_PATHS, expectedOrigin: origin, maxBodyBytes });
}

function resolveRoute(rawUrl) {
  let parsed;
  try {
    if (typeof rawUrl !== "string" || Buffer.byteLength(rawUrl, "utf8") > MAX_URL_BYTES) return undefined;
    parsed = new URL(rawUrl, "https://agentpass.invalid");
  } catch { return undefined; }
  if (parsed.pathname !== PLATFORM_AUTHORIZED_PROMOTION_ISSUE_PATH) return undefined;
  return parsed.search || parsed.hash ? { invalid: true } : { invalid: false };
}

function normalizeRequest(input) {
  if (!input || typeof input !== "object") throw httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.INVALID_REQUEST, 400);
  const method = String(input.method ?? "").toUpperCase();
  const url = String(input.url ?? input.originalUrl ?? input.path ?? "");
  if (!method || !url || Buffer.byteLength(url, "utf8") > MAX_URL_BYTES) throw httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.INVALID_REQUEST, 400);
  return Object.freeze({ input, method, url, headers: normalizeHeaders(input.headers ?? {}) });
}

function normalizeHeaders(input) {
  const result = Object.create(null);
  if (input && typeof input.forEach === "function") {
    input.forEach((value, name) => setHeader(result, name, value));
    return result;
  }
  if (!input || typeof input !== "object" || Array.isArray(input)) throw httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.INVALID_REQUEST, 400);
  for (const [name, value] of Object.entries(input)) setHeader(result, name, value);
  return result;
}

function setHeader(target, name, value) {
  if (typeof name !== "string" || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u.test(name)
    || typeof value !== "string" || value.length > MAX_HEADER_BYTES || CONTROL_CHARACTERS.test(value)) {
    throw httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.INVALID_REQUEST, 400);
  }
  const normalized = name.toLowerCase();
  if (Object.hasOwn(target, normalized)) throw httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.INVALID_REQUEST, 400);
  target[normalized] = value;
}

function requirePlatformSession(headers) {
  const cookie = header(headers, "cookie");
  if (cookie === undefined) throw httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.AUTHORIZATION_REQUIRED, 401);
  try { return parsePlatformSessionCookie(cookie); }
  catch {
    const count = cookie.split(";").filter((part) => part.slice(0, part.indexOf("=")).trim() === PLATFORM_SESSION_COOKIE_NAME).length;
    throw httpError(count > 1 ? PLATFORM_PROMOTION_HTTP_ERROR_CODES.INVALID_REQUEST : PLATFORM_PROMOTION_HTTP_ERROR_CODES.AUTHORIZATION_REQUIRED, count > 1 ? 400 : 401);
  }
}

function requireCsrfToken(headers) {
  const value = header(headers, PLATFORM_SESSION_CSRF_HEADER);
  if (!isPlatformSessionToken(value)) throw httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.CSRF_FAILED, 403);
  return value;
}

function requireUuidHeader(headers, name) {
  const value = header(headers, name);
  if (typeof value !== "string" || !UUID.test(value)) throw httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.AUTHORIZATION_REQUIRED, 401);
  return value.toLowerCase();
}

async function acquireRateLimit(rateLimiter, request, dimensions) {
  try {
    const decision = await rateLimiter.acquire(Object.freeze({
      ...dimensions,
      transportIdentity: transportIdentity(request.input)
    }));
    if (!decision || decision.allowed !== true) throw new PlatformSessionRateLimitError(PLATFORM_SESSION_RATE_LIMIT_ERROR_CODES.CONTROL_UNAVAILABLE);
  } catch (error) {
    if (error instanceof PlatformSessionRateLimitError) throw error;
    throw new PlatformSessionRateLimitError(PLATFORM_SESSION_RATE_LIMIT_ERROR_CODES.CONTROL_UNAVAILABLE, { cause: error });
  }
}

function transportIdentity(input) {
  const value = input?.socket?.remoteAddress ?? input?.connection?.remoteAddress ?? input?.remoteAddress;
  if (typeof value !== "string" || value.length === 0 || value.length > 256 || CONTROL_CHARACTERS.test(value)) return "unknown";
  return value;
}

async function readJsonBody(request, maxBytes) {
  const contentType = header(request.headers, "content-type");
  if (contentType === undefined || !JSON_CONTENT_TYPE.test(contentType)) throw httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.INVALID_REQUEST, 400);
  const contentLength = header(request.headers, "content-length");
  if (contentLength !== undefined && (!/^\d+$/u.test(contentLength) || !Number.isSafeInteger(Number(contentLength)))) {
    throw httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.INVALID_REQUEST, 400);
  }
  if (contentLength !== undefined && Number(contentLength) > maxBytes) throw httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.INVALID_REQUEST, 413);
  const bytes = await readRawBody(request.input, maxBytes);
  try { return parseJsonNoDuplicateKeys(bytes.toString("utf8")); }
  catch (error) {
    if (error instanceof DuplicateJsonKeyError || error instanceof SyntaxError) throw httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.INVALID_REQUEST, 400, { cause: error });
    throw error;
  }
}

async function readRawBody(input, maxBytes) {
  let raw;
  if (typeof input.arrayBuffer === "function") raw = Buffer.from(await input.arrayBuffer());
  else if (input.body !== undefined && !isReadable(input.body)) raw = input.body;
  else if (typeof input.text === "function") raw = await input.text();
  else if (typeof input.json === "function") throw httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.INVALID_REQUEST, 400);
  else if (isReadable(input)) raw = await readStream(input, maxBytes);
  else if (isReadable(input.body)) raw = await readStream(input.body, maxBytes);
  else throw httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.INVALID_REQUEST, 400);
  if (raw !== null && typeof raw === "object" && !Buffer.isBuffer(raw) && !(raw instanceof Uint8Array)) {
    try { raw = JSON.stringify(raw); } catch (error) { throw httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.INVALID_REQUEST, 400, { cause: error }); }
  }
  const bytes = Buffer.isBuffer(raw) ? Buffer.from(raw) : raw instanceof Uint8Array ? Buffer.from(raw) : Buffer.from(String(raw ?? ""), "utf8");
  if (bytes.length > maxBytes) throw httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.INVALID_REQUEST, 413);
  return bytes;
}

async function readStream(stream, maxBytes) {
  const chunks = [];
  let total = 0;
  for await (const chunk of stream) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : chunk instanceof Uint8Array ? Buffer.from(chunk) : Buffer.from(String(chunk), "utf8");
    total += bytes.length;
    if (total > maxBytes) throw httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.INVALID_REQUEST, 413);
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

function mapServiceError(error) {
  const code = String(error?.code ?? "");
  if ([PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.INPUT, PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.BINDING].includes(code)
    || /(?:_INPUT|_BINDING)$/u.test(code)) return httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.INVALID_REQUEST, 400);
  if (code === PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.CONFLICT || /CONFLICT/u.test(code)) return httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.IDEMPOTENCY_CONFLICT, 409);
  if (code === PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.IN_PROGRESS || /IN_PROGRESS/u.test(code)) return httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.IN_PROGRESS, 409, { headers: { "Retry-After": "1" } });
  if (code === PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.UNCERTAIN || /UNCERTAIN/u.test(code)) return httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.UNCERTAIN, 409);
  return httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.UNAVAILABLE, 503);
}

function mapError(error) {
  if (error instanceof PlatformSessionRateLimitError) {
    return response(error.status, { error: { code: error.code, message: error.message } }, error.headers);
  }
  if (error instanceof PlatformPromotionHttpError) {
    return response(error.status, { error: { code: error.code, message: ERROR_MESSAGES[error.code] } }, error.headers);
  }
  return response(503, { error: { code: PLATFORM_PROMOTION_HTTP_ERROR_CODES.UNAVAILABLE, message: ERROR_MESSAGES[PLATFORM_PROMOTION_HTTP_ERROR_CODES.UNAVAILABLE] } });
}

function response(status, body, extraHeaders = undefined) {
  const headers = {
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
    "Content-Type": "application/json; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    ...(extraHeaders ?? {})
  };
  return Object.freeze({
    status,
    ok: status >= 200 && status < 300,
    headers: Object.freeze(headers),
    body: Object.freeze(body),
    text: async () => JSON.stringify(body),
    json: async () => body,
    toResponse: () => new Response(JSON.stringify(body), { status, headers })
  });
}

function writeNodeResponse(target, result) {
  if (!target || typeof target.end !== "function") throw new TypeError("nodeResponse is invalid");
  if (typeof target.writeHead === "function") target.writeHead(result.status, result.headers);
  else if (typeof target.setHeader === "function") for (const [name, value] of Object.entries(result.headers)) target.setHeader(name, value);
  target.statusCode = result.status;
  target.end(JSON.stringify(result.body));
}

function header(headers, name) {
  const value = headers[name.toLowerCase()];
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length > MAX_HEADER_BYTES || CONTROL_CHARACTERS.test(value)) throw httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.INVALID_REQUEST, 400);
  return value;
}

function assertOrigin(value) {
  if (typeof value !== "string" || value.length > 512 || CONTROL_CHARACTERS.test(value)) throw new TypeError("origin is invalid");
  let parsed;
  try { parsed = new URL(value); } catch { throw new TypeError("origin is invalid"); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash || parsed.origin !== value) throw new TypeError("origin is invalid");
}

function safeUuid(value) {
  if (typeof value !== "string" || !UUID.test(value)) throw httpError(PLATFORM_PROMOTION_HTTP_ERROR_CODES.UNAVAILABLE, 503);
  return value.toLowerCase();
}

function sha256Text(value) { return crypto.createHash("sha256").update(value, "utf8").digest("hex"); }
function isReadable(value) { return value !== null && typeof value === "object" && typeof value[Symbol.asyncIterator] === "function"; }
function httpError(code, status, options = {}) { return new PlatformPromotionHttpError(code, status, options); }
