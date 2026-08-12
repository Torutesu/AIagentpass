import {
  HUMAN_SESSION_CSRF_HEADER,
  HUMAN_SESSION_ERROR_CODES
} from "../human-session.mjs";
import {
  WebAuthnRegistrationError,
  WEBAUTHN_REGISTRATION_ERROR_CODES,
  normalizeBrowserRegistrationCredential
} from "./webauthn/registration.mjs";

const OPTIONS_PATH = "/webauthn/registration/options";
const VERIFY_PATH = "/webauthn/registration/verify";
const DEFAULT_MAX_BODY_BYTES = 64 * 1024;
const MAX_HEADER_BYTES = 8 * 1024;
const MAX_URL_LENGTH = 8 * 1024;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export const WEBAUTHN_REGISTRATION_HTTP_PATHS = Object.freeze({
  options: OPTIONS_PATH,
  verify: VERIFY_PATH
});

export const WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES = Object.freeze({
  INVALID_REQUEST: "webauthn_registration_http_invalid_request",
  METHOD_NOT_ALLOWED: "webauthn_registration_http_method_not_allowed",
  SESSION_REQUIRED: "webauthn_registration_http_session_required",
  ORIGIN_NOT_ALLOWED: "webauthn_registration_http_origin_not_allowed",
  CSRF_FAILED: "webauthn_registration_http_csrf_failed",
  SESSION_UNAVAILABLE: "webauthn_registration_http_session_unavailable",
  REGISTRATION_UNAVAILABLE: "webauthn_registration_http_unavailable",
  CHALLENGE_INVALID: "webauthn_registration_http_challenge_invalid",
  ATTESTATION_INVALID: "webauthn_registration_http_attestation_invalid",
  CREDENTIAL_EXISTS: "webauthn_registration_http_credential_exists",
  CREDENTIAL_STORAGE_UNAVAILABLE: "webauthn_registration_http_credential_storage_unavailable",
  INTERNAL_ERROR: "webauthn_registration_http_internal_error"
});

const ERROR_MESSAGES = Object.freeze({
  [WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST]: "The WebAuthn registration request is invalid",
  [WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.METHOD_NOT_ALLOWED]: "Only POST is allowed",
  [WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.SESSION_REQUIRED]: "A valid human session is required",
  [WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED]: "The request origin is not allowed",
  [WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.CSRF_FAILED]: "The CSRF token is invalid",
  [WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.SESSION_UNAVAILABLE]: "The human session service is unavailable",
  [WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.REGISTRATION_UNAVAILABLE]: "WebAuthn registration is unavailable",
  [WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.CHALLENGE_INVALID]: "The WebAuthn registration challenge is invalid",
  [WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.ATTESTATION_INVALID]: "The WebAuthn registration response is invalid",
  [WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.CREDENTIAL_EXISTS]: "The WebAuthn credential is already registered",
  [WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.CREDENTIAL_STORAGE_UNAVAILABLE]: "The WebAuthn credential could not be stored",
  [WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INTERNAL_ERROR]: "The request could not be completed"
});

const ERROR_STATUS = Object.freeze({
  [WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST]: 400,
  [WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.METHOD_NOT_ALLOWED]: 405,
  [WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.SESSION_REQUIRED]: 401,
  [WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED]: 403,
  [WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.CSRF_FAILED]: 403,
  [WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.SESSION_UNAVAILABLE]: 503,
  [WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.REGISTRATION_UNAVAILABLE]: 503,
  [WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.CHALLENGE_INVALID]: 409,
  [WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.ATTESTATION_INVALID]: 422,
  [WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.CREDENTIAL_EXISTS]: 409,
  [WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.CREDENTIAL_STORAGE_UNAVAILABLE]: 503,
  [WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INTERNAL_ERROR]: 500
});

const SESSION_FAILURES = new Set([
  HUMAN_SESSION_ERROR_CODES.INVALID_COOKIE,
  HUMAN_SESSION_ERROR_CODES.SESSION_NOT_FOUND,
  HUMAN_SESSION_ERROR_CODES.SESSION_REVOKED,
  HUMAN_SESSION_ERROR_CODES.SESSION_EXPIRED
]);
const CSRF_FAILURES = new Set([HUMAN_SESSION_ERROR_CODES.CSRF_REQUIRED, HUMAN_SESSION_ERROR_CODES.CSRF_INVALID]);
const CHALLENGE_FAILURES = new Set([
  WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_NOT_FOUND,
  WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_EXPIRED,
  WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_REPLAYED,
  WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_BUSY,
  WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_MISMATCH,
  WEBAUTHN_REGISTRATION_ERROR_CODES.BINDING_MISMATCH
]);

export class WebAuthnRegistrationHttpError extends Error {
  constructor(code, { status = ERROR_STATUS[code] ?? 500, cause = undefined } = {}) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INTERNAL_ERROR], { cause });
    this.name = "WebAuthnRegistrationHttpError";
    this.code = code;
    this.status = status;
  }
}

/**
 * Framework-free HTTP boundary for registration. It authenticates the
 * session before parsing the body, requires the exact Console origin and
 * CSRF header, and only passes normalized public registration fields to the
 * service.
 */
export function createWebAuthnRegistrationHttpApi({
  humanSession,
  registrationService,
  origin,
  basePath = "",
  maxBodyBytes = DEFAULT_MAX_BODY_BYTES
} = {}) {
  if (!humanSession || typeof humanSession.authenticateRequest !== "function") throw new TypeError("humanSession must expose authenticateRequest()");
  if (!registrationService || typeof registrationService.begin !== "function" || typeof registrationService.verify !== "function") throw new TypeError("registrationService must expose begin() and verify()");
  const expectedOrigin = origin ?? humanSession.expectedOrigin;
  assertOrigin(expectedOrigin);
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
      if (request.method !== "POST") throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.METHOD_NOT_ALLOWED, { status: 405 });
      const session = await authenticateSession(request);
      const body = await readJsonBody(request, maxBodyBytes);
      if (route === "options") return await issueOptions(session, parseOptionsBody(body, session));
      return await verifyCredential(session, parseVerifyBody(body, session));
    } catch (error) {
      return mapError(error);
    }
  }

  async function authenticateSession(request) {
    const requestOrigin = header(request.headers, "origin");
    if (requestOrigin === undefined || requestOrigin !== expectedOrigin) throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED, { status: 403 });
    try {
      const authenticated = await humanSession.authenticateRequest({
        method: request.method,
        headers: request.headers,
        origin: requestOrigin,
        csrfToken: header(request.headers, HUMAN_SESSION_CSRF_HEADER)
      });
      if (!authenticated?.session || typeof authenticated.session !== "object") throw new Error("session result is invalid");
      if (!isUuid(authenticated.session.session_id) || !isUuid(authenticated.session.member_id) || !isUuid(authenticated.session.organization_id)) throw new Error("session result is incomplete");
      return authenticated.session;
    } catch (error) {
      if (error instanceof WebAuthnRegistrationHttpError) throw error;
      if (error?.code === HUMAN_SESSION_ERROR_CODES.INVALID_ORIGIN) throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED, { status: 403, cause: error });
      if (CSRF_FAILURES.has(error?.code)) throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.CSRF_FAILED, { status: 403, cause: error });
      if (SESSION_FAILURES.has(error?.code)) throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.SESSION_REQUIRED, { status: 401, cause: error });
      throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.SESSION_UNAVAILABLE, { status: 503, cause: error });
    }
  }

  async function issueOptions(session, input) {
    try {
      return response(200, await registrationService.begin({ session, organization_id: input.organization_id }));
    } catch (error) {
      throw mapServiceError(error, "begin");
    }
  }

  async function verifyCredential(session, input) {
    try {
      return response(201, await registrationService.verify({ session, organization_id: input.organization_id, challenge_id: input.challenge_id, credential: input.credential }));
    } catch (error) {
      throw mapServiceError(error, "verify");
    }
  }

  return Object.freeze({ handle, paths: WEBAUTHN_REGISTRATION_HTTP_PATHS, expectedOrigin, basePath: normalizedBasePath });
}

function parseOptionsBody(body, session) {
  assertObjectBody(body, new Set(["organization_id"]));
  const organization_id = requiredUuid(body.organization_id);
  if (organization_id !== session.organization_id.toLowerCase()) throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  return Object.freeze({ organization_id });
}

function parseVerifyBody(body, session) {
  assertObjectBody(body, new Set(["organization_id", "challenge_id", "credential"]));
  const organization_id = requiredUuid(body.organization_id);
  if (organization_id !== session.organization_id.toLowerCase()) throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  const challenge_id = requiredUuid(body.challenge_id);
  return Object.freeze({ organization_id, challenge_id, credential: normalizeBrowserCredential(body.credential) });
}

function normalizeBrowserCredential(value) {
  try {
    return normalizeBrowserRegistrationCredential(value);
  } catch (error) {
    if (error instanceof WebAuthnRegistrationError) throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400, cause: error });
    throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400, cause: error });
  }
}

function mapServiceError(error, phase) {
  if (error instanceof WebAuthnRegistrationHttpError) return error;
  if (error instanceof WebAuthnRegistrationError || error?.name === "WebAuthnRegistrationError") {
    if (CHALLENGE_FAILURES.has(error.code)) return new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.CHALLENGE_INVALID, { status: 409, cause: error });
    if (error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_REQUEST || error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_CONTEXT || error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_RESPONSE) return new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400, cause: error });
    if (error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.CREDENTIAL_EXISTS) return new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.CREDENTIAL_EXISTS, { status: 409, cause: error });
    if (error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.CREDENTIAL_STORAGE_UNAVAILABLE) return new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.CREDENTIAL_STORAGE_UNAVAILABLE, { status: 503, cause: error });
    if (error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.VERIFICATION_FAILED || error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT) return new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.ATTESTATION_INVALID, { status: 422, cause: error });
    return new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.REGISTRATION_UNAVAILABLE, { status: phase === "begin" ? 503 : 422, cause: error });
  }
  return new WebAuthnRegistrationHttpError(phase === "begin" ? WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.REGISTRATION_UNAVAILABLE : WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.ATTESTATION_INVALID, { status: phase === "begin" ? 503 : 422, cause: error });
}

function mapError(error) {
  if (error instanceof WebAuthnRegistrationHttpError) return response(error.status, { error: { code: error.code, message: ERROR_MESSAGES[error.code] ?? ERROR_MESSAGES[WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INTERNAL_ERROR] } });
  return response(500, { error: { code: WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INTERNAL_ERROR, message: ERROR_MESSAGES[WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INTERNAL_ERROR] } });
}

function response(status, body, extraHeaders = undefined) {
  const headers = {
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
    "Content-Type": "application/json; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    ...(status === 405 ? { Allow: "POST" } : {}),
    ...(extraHeaders ?? {})
  };
  const json = JSON.stringify(body);
  return Object.freeze({ status, ok: status >= 200 && status < 300, headers: Object.freeze(headers), body: Object.freeze(body), text: async () => json, json: async () => body, toResponse: () => new Response(json, { status, headers }) });
}

function normalizeRequest(input) {
  if (!input || typeof input !== "object") throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  const method = String(input.method ?? "").toUpperCase();
  const url = String(input.url ?? input.originalUrl ?? input.path ?? "");
  if (!method || !url || url.length > MAX_URL_LENGTH) throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  return Object.freeze({ input, method, url, headers: normalizeHeaders(input.headers ?? {}), body: input.body });
}

function resolveRoute(rawUrl, basePath) {
  let url;
  try { url = new URL(rawUrl, "https://agentpass.invalid"); } catch { return undefined; }
  if (url.search || url.hash) return undefined;
  if (url.pathname === `${basePath}${OPTIONS_PATH}`) return "options";
  if (url.pathname === `${basePath}${VERIFY_PATH}`) return "verify";
  return undefined;
}

async function readJsonBody(request, maxBytes) {
  const contentType = header(request.headers, "content-type");
  if (typeof contentType !== "string" || !/^application\/json(?:\s*;|$)/i.test(contentType)) throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  const contentLength = header(request.headers, "content-length");
  if (contentLength !== undefined && (!/^\d+$/.test(contentLength) || !Number.isSafeInteger(Number(contentLength)) || Number(contentLength) > maxBytes)) throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
  const input = request.input;
  let raw;
  if (input.body !== undefined && !isReadable(input.body)) raw = input.body;
  else if (typeof input.arrayBuffer === "function") raw = Buffer.from(await input.arrayBuffer());
  else if (typeof input.text === "function") raw = await input.text();
  else if (typeof input.json === "function") { try { raw = await input.json(); } catch (error) { throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400, cause: error }); } }
  else if (isReadable(input)) raw = await readStream(input, maxBytes);
  else if (isReadable(input.body)) raw = await readStream(input.body, maxBytes);
  else throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  if (isObject(raw) || Array.isArray(raw)) {
    assertSerializedSize(raw, maxBytes);
    return raw;
  }
  const bytes = Buffer.isBuffer(raw) ? raw : raw instanceof Uint8Array ? Buffer.from(raw) : Buffer.from(String(raw ?? ""), "utf8");
  if (bytes.length > maxBytes) throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
  try { return JSON.parse(bytes.toString("utf8")); } catch (error) { throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400, cause: error }); }
}

function assertSerializedSize(value, maxBytes) {
  let serialized;
  try { serialized = JSON.stringify(value); } catch (error) { throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400, cause: error }); }
  if (typeof serialized !== "string" || Buffer.byteLength(serialized, "utf8") > maxBytes) throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
}

function normalizeHeaders(input) {
  const result = {};
  if (input && typeof input.get === "function") {
    for (const name of ["origin", "cookie", "content-type", "content-length", HUMAN_SESSION_CSRF_HEADER]) {
      const value = input.get(name);
      if (value !== null) result[name] = value;
    }
    return result;
  }
  if (Array.isArray(input)) {
    if (input.length % 2 !== 0) throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
    for (let index = 0; index < input.length; index += 2) setHeader(result, input[index], input[index + 1]);
    return result;
  }
  if (!input || typeof input !== "object") throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  for (const [name, value] of Object.entries(input)) setHeader(result, name, value);
  return result;
}

function setHeader(target, name, value) {
  if (typeof name !== "string" || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || Array.isArray(value) || typeof value === "object" || value === undefined) throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  const normalized = name.toLowerCase();
  if (target[normalized] !== undefined) throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  target[normalized] = String(value);
}

function header(headers, name) {
  const value = headers[name.toLowerCase()];
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length > MAX_HEADER_BYTES || /[\u0000-\u001f\u007f]/.test(value)) throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  return value;
}

async function readStream(stream, maxBytes) {
  const chunks = [];
  let total = 0;
  for await (const chunk of stream) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += bytes.length;
    if (total > maxBytes) throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

function assertObjectBody(value, allowedKeys) {
  if (!isObject(value) || Object.keys(value).some((key) => !allowedKeys.has(key))) throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
}

function requiredUuid(value) {
  if (typeof value !== "string" || !UUID_V4.test(value)) throw new WebAuthnRegistrationHttpError(WEBAUTHN_REGISTRATION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  return value.toLowerCase();
}

function isUuid(value) { return typeof value === "string" && UUID_V4.test(value); }
function isObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function isReadable(value) { return value !== null && typeof value === "object" && typeof value[Symbol.asyncIterator] === "function"; }
function assertOrigin(value) { if (typeof value !== "string" || value.length > 512 || /[\u0000-\u001f\u007f]/.test(value)) throw new TypeError("origin is invalid"); let url; try { url = new URL(value); } catch { throw new TypeError("origin is invalid"); } if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash || url.origin !== value) throw new TypeError("origin is invalid"); }
function normalizeBasePath(value) { if (value === "") return ""; if (typeof value !== "string" || !value.startsWith("/") || value.endsWith("/") || value.includes("?") || value.includes("#") || /[\u0000-\u001f\u007f]/.test(value)) throw new TypeError("basePath is invalid"); return value; }

function writeNodeResponse(nodeResponse, result) {
  if (!nodeResponse || typeof nodeResponse.end !== "function") throw new TypeError("nodeResponse is invalid");
  if (typeof nodeResponse.writeHead === "function") nodeResponse.writeHead(result.status, result.headers);
  else if (typeof nodeResponse.setHeader === "function") for (const [name, value] of Object.entries(result.headers)) nodeResponse.setHeader(name, value);
  nodeResponse.statusCode = result.status;
  nodeResponse.end(JSON.stringify(result.body));
}
