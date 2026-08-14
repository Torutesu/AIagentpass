import crypto from "node:crypto";

import {
  HUMAN_SESSION_ERROR_CODES,
  HUMAN_SESSION_CSRF_HEADER,
} from "../human-session.mjs";
import { WebAuthnCeremonyError, WEBAUTHN_ERROR_CODES } from "./webauthn/ceremony.mjs";
import { HumanAuthAbuseControlError, HUMAN_AUTH_RATE_LIMIT_OPERATIONS } from "./rate-limit.mjs";

const AUTHENTICATION_OPTIONS_PATH = "/webauthn/options";
const AUTHENTICATION_VERIFY_PATH = "/webauthn/verify";
const DEFAULT_MAX_BODY_BYTES = 64 * 1024;
const MAX_CREDENTIALS = 64;
const MAX_OPERATION_LENGTH = 128;
const MAX_CHALLENGE_BYTES = 128;
const MAX_CREDENTIAL_ID_BYTES = 1024;
const MAX_CLIENT_DATA_BYTES = 16 * 1024;
const MAX_AUTHENTICATOR_DATA_BYTES = 4 * 1024;
const MAX_SIGNATURE_BYTES = 1024;
const MAX_USER_HANDLE_BYTES = 64;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const RP_ID = /^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/;
const ALLOWED_TRANSPORTS = new Set(["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"]);
const ALLOWED_CREDENTIAL_KEYS = new Set(["id", "rawId", "response", "type", "clientExtensionResults", "authenticatorAttachment"]);

export const HUMAN_AUTH_HTTP_PATHS = Object.freeze({
  authenticationOptions: AUTHENTICATION_OPTIONS_PATH,
  authenticationVerify: AUTHENTICATION_VERIFY_PATH
});

export const HUMAN_AUTH_HTTP_ERROR_CODES = Object.freeze({
  INVALID_REQUEST: "human_auth_invalid_request",
  METHOD_NOT_ALLOWED: "human_auth_method_not_allowed",
  SESSION_REQUIRED: "human_auth_session_required",
  ORIGIN_NOT_ALLOWED: "human_auth_origin_not_allowed",
  CSRF_FAILED: "human_auth_csrf_failed",
  SESSION_UNAVAILABLE: "human_auth_session_unavailable",
  CREDENTIAL_ALLOW_LIST_UNAVAILABLE: "human_auth_credential_allow_list_unavailable",
  CREDENTIAL_ALLOW_LIST_INVALID: "human_auth_credential_allow_list_invalid",
  CREDENTIAL_NOT_ALLOWED: "human_auth_credential_not_allowed",
  CREDENTIAL_ALLOW_LIST_EMPTY: "human_auth_credential_allow_list_empty",
  CHALLENGE_INVALID: "human_auth_challenge_invalid",
  WEBAUTHN_VERIFICATION_FAILED: "human_auth_webauthn_verification_failed",
  WEBAUTHN_UNAVAILABLE: "human_auth_webauthn_unavailable",
  INTERNAL_ERROR: "human_auth_internal_error"
});

const ERROR_MESSAGES = Object.freeze({
  [HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST]: "The WebAuthn request is invalid",
  [HUMAN_AUTH_HTTP_ERROR_CODES.METHOD_NOT_ALLOWED]: "Only POST is allowed",
  [HUMAN_AUTH_HTTP_ERROR_CODES.SESSION_REQUIRED]: "A valid human session is required",
  [HUMAN_AUTH_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED]: "The request origin is not allowed",
  [HUMAN_AUTH_HTTP_ERROR_CODES.CSRF_FAILED]: "The CSRF token is invalid",
  [HUMAN_AUTH_HTTP_ERROR_CODES.SESSION_UNAVAILABLE]: "The human session service is unavailable",
  [HUMAN_AUTH_HTTP_ERROR_CODES.CREDENTIAL_ALLOW_LIST_UNAVAILABLE]: "The WebAuthn credential allow list is unavailable",
  [HUMAN_AUTH_HTTP_ERROR_CODES.CREDENTIAL_ALLOW_LIST_INVALID]: "The WebAuthn credential allow list is invalid",
  [HUMAN_AUTH_HTTP_ERROR_CODES.CREDENTIAL_NOT_ALLOWED]: "The WebAuthn credential is not allowed",
  [HUMAN_AUTH_HTTP_ERROR_CODES.CREDENTIAL_ALLOW_LIST_EMPTY]: "No WebAuthn credential is registered for this session",
  [HUMAN_AUTH_HTTP_ERROR_CODES.CHALLENGE_INVALID]: "The WebAuthn challenge is invalid",
  [HUMAN_AUTH_HTTP_ERROR_CODES.WEBAUTHN_VERIFICATION_FAILED]: "WebAuthn verification failed",
  [HUMAN_AUTH_HTTP_ERROR_CODES.WEBAUTHN_UNAVAILABLE]: "WebAuthn verification is unavailable",
  [HUMAN_AUTH_HTTP_ERROR_CODES.INTERNAL_ERROR]: "The request could not be completed"
});

const ERROR_STATUS = Object.freeze({
  [HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST]: 400,
  [HUMAN_AUTH_HTTP_ERROR_CODES.METHOD_NOT_ALLOWED]: 405,
  [HUMAN_AUTH_HTTP_ERROR_CODES.SESSION_REQUIRED]: 401,
  [HUMAN_AUTH_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED]: 403,
  [HUMAN_AUTH_HTTP_ERROR_CODES.CSRF_FAILED]: 403,
  [HUMAN_AUTH_HTTP_ERROR_CODES.SESSION_UNAVAILABLE]: 503,
  [HUMAN_AUTH_HTTP_ERROR_CODES.CREDENTIAL_ALLOW_LIST_UNAVAILABLE]: 503,
  [HUMAN_AUTH_HTTP_ERROR_CODES.CREDENTIAL_ALLOW_LIST_INVALID]: 503,
  [HUMAN_AUTH_HTTP_ERROR_CODES.CREDENTIAL_NOT_ALLOWED]: 401,
  [HUMAN_AUTH_HTTP_ERROR_CODES.CREDENTIAL_ALLOW_LIST_EMPTY]: 409,
  [HUMAN_AUTH_HTTP_ERROR_CODES.CHALLENGE_INVALID]: 409,
  [HUMAN_AUTH_HTTP_ERROR_CODES.WEBAUTHN_VERIFICATION_FAILED]: 401,
  [HUMAN_AUTH_HTTP_ERROR_CODES.WEBAUTHN_UNAVAILABLE]: 503,
  [HUMAN_AUTH_HTTP_ERROR_CODES.INTERNAL_ERROR]: 500
});

const SESSION_FAILURES = new Set([
  HUMAN_SESSION_ERROR_CODES.INVALID_COOKIE,
  HUMAN_SESSION_ERROR_CODES.SESSION_NOT_FOUND,
  HUMAN_SESSION_ERROR_CODES.SESSION_REVOKED,
  HUMAN_SESSION_ERROR_CODES.SESSION_EXPIRED
]);

const CSRF_FAILURES = new Set([
  HUMAN_SESSION_ERROR_CODES.CSRF_REQUIRED,
  HUMAN_SESSION_ERROR_CODES.CSRF_INVALID
]);

const CHALLENGE_FAILURES = new Set([
  WEBAUTHN_ERROR_CODES.CHALLENGE_NOT_FOUND,
  WEBAUTHN_ERROR_CODES.CHALLENGE_EXPIRED,
  WEBAUTHN_ERROR_CODES.CHALLENGE_REPLAYED,
  WEBAUTHN_ERROR_CODES.CHALLENGE_BUSY,
  WEBAUTHN_ERROR_CODES.CHALLENGE_MISMATCH,
  WEBAUTHN_ERROR_CODES.BINDING_MISMATCH
]);

export class HumanAuthHttpError extends Error {
  constructor(code, { status = ERROR_STATUS[code] ?? 500, headers = undefined, cause = undefined } = {}) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[HUMAN_AUTH_HTTP_ERROR_CODES.INTERNAL_ERROR], { cause });
    this.name = "HumanAuthHttpError";
    this.code = code;
    this.status = status;
    if (headers !== undefined) this.headers = headers;
  }
}

/**
 * Framework-free Human API boundary for the authentication ceremony.
 *
 * `handle` accepts a Fetch Request, a Request-like object, or a Node-style
 * request object (`method`, `url`, `headers`, and `body`). It returns a small
 * response object with a JSON `body`; when a Node ServerResponse is supplied
 * as the second argument it also writes that response to the socket.
 */
export function createHumanAuthHttpApi({
  humanSession,
  recentAuthService,
  credentialAllowList,
  rpId,
  origin,
  basePath = "",
  allowedOperations,
  abuseControls,
  maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
  now = () => Date.now()
} = {}) {
  assertServices({ humanSession, recentAuthService, credentialAllowList });
  const expectedOrigin = origin ?? humanSession.expectedOrigin;
  assertOrigin(expectedOrigin);
  const expectedRpId = normalizeRpId(rpId);
  const normalizedBasePath = normalizeBasePath(basePath);
  const operationSet = normalizeOperations(allowedOperations);
  if (typeof now !== "function") throw new TypeError("now must be a function");
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1_024 || maxBodyBytes > 1_024 * 1_024) throw new TypeError("maxBodyBytes is invalid");
  if (!abuseControls || typeof abuseControls.authorize !== "function") throw new TypeError("abuseControls must expose authorize()");

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
      if (request.method !== "POST") {
        return response(405, { error: { code: HUMAN_AUTH_HTTP_ERROR_CODES.METHOD_NOT_ALLOWED, message: ERROR_MESSAGES[HUMAN_AUTH_HTTP_ERROR_CODES.METHOD_NOT_ALLOWED] } }, { Allow: "POST" });
      }
      const session = await authenticateSession(request);
      const body = await readJsonBody(request, maxBodyBytes);
      if (route === "options") return await createOptions({ request, session, body });
      return await verifyAuthentication({ request, session, body });
    } catch (error) {
      return mapError(error);
    }
  }

  async function authenticateSession(request) {
    const requestOrigin = header(request.headers, "origin");
    if (requestOrigin === undefined) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED, { status: 403 });
    try {
      const authenticated = await humanSession.authenticateRequest({
        method: request.method,
        headers: request.headers,
        origin: requestOrigin,
        csrfToken: header(request.headers, HUMAN_SESSION_CSRF_HEADER)
      });
      if (!authenticated?.session || typeof authenticated.session !== "object") throw new Error("session result is invalid");
      if (authenticated.session.organization_id === undefined || authenticated.session.member_id === undefined || authenticated.session.session_id === undefined) throw new Error("session result is incomplete");
      return authenticated.session;
    } catch (error) {
      if (error instanceof HumanAuthHttpError) throw error;
      if (error?.code === HUMAN_SESSION_ERROR_CODES.INVALID_ORIGIN) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED, { cause: error });
      if (CSRF_FAILURES.has(error?.code)) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.CSRF_FAILED, { cause: error });
      if (SESSION_FAILURES.has(error?.code)) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.SESSION_REQUIRED, { cause: error });
      if (error?.code === HUMAN_SESSION_ERROR_CODES.REPOSITORY_INVALID) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.SESSION_UNAVAILABLE, { cause: error });
      throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.SESSION_UNAVAILABLE, { cause: error });
    }
  }

  async function createOptions({ request, session, body }) {
    const input = parseOptionsBody(body, session, expectedRpId, expectedOrigin, operationSet);
    await abuseControls.authorize({ operation: HUMAN_AUTH_RATE_LIMIT_OPERATIONS.webauthnBegin, session, organizationId: input.organization_id });
    if (input.organization_id !== session.organization_id) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST);
    const credentials = await loadAllowList({ session, organization_id: input.organization_id, operation: input.operation });
    if (credentials.length === 0) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.CREDENTIAL_ALLOW_LIST_EMPTY, { status: 409 });

    let issued;
    try {
      issued = await recentAuthService.begin({
        session,
        organization_id: input.organization_id,
        operation: input.operation,
        rp_id: expectedRpId,
        origin: expectedOrigin
      });
    } catch (error) {
      throw mapServiceError(error, "begin");
    }
    if (!isObject(issued) || !isUuid(issued.challenge_id) || !isBase64Url(issued.challenge, 1, MAX_CHALLENGE_BYTES) || typeof issued.challenge_expires_at !== "string") {
      throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.WEBAUTHN_UNAVAILABLE);
    }
    const expiresAt = parseDateTime(issued.challenge_expires_at);
    if (expiresAt <= now() || expiresAt - now() > 5 * 60 * 1000) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.WEBAUTHN_UNAVAILABLE);
    return response(200, {
      challenge_id: issued.challenge_id,
      options: {
        challenge: issued.challenge,
        rpId: expectedRpId,
        userVerification: "required",
        allowCredentials: credentials
      }
    });
  }

  async function verifyAuthentication({ session, body }) {
    const input = parseVerifyBody(body, session, expectedRpId, expectedOrigin, operationSet);
    await abuseControls.authorize({ operation: HUMAN_AUTH_RATE_LIMIT_OPERATIONS.webauthnVerify, session, organizationId: input.organization_id });
    if (input.organization_id !== session.organization_id) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST);
    const credentials = await loadAllowList({ session, organization_id: input.organization_id, operation: input.operation });
    if (credentials.length === 0) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.CREDENTIAL_ALLOW_LIST_EMPTY, { status: 409 });
    if (!credentials.some((credential) => sameCredentialId(credential.id, input.assertion.credential_id))) {
      throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.CREDENTIAL_NOT_ALLOWED, { status: 401 });
    }

    let verified;
    try {
      verified = await recentAuthService.verify({
        session,
        organization_id: input.organization_id,
        operation: input.operation,
        assertion: {
          challenge_id: input.challenge_id,
          challenge: input.challenge,
          credential_id: input.assertion.credential_id,
          client_data_json: input.assertion.client_data_json,
          authenticator_data: input.assertion.authenticator_data,
          signature: input.assertion.signature,
          ...(input.assertion.user_handle === undefined ? {} : { user_handle: input.assertion.user_handle }),
          rp_id: expectedRpId,
          origin: expectedOrigin,
          user_verification: "required"
        }
      });
    } catch (error) {
      throw mapServiceError(error, "verify");
    }
    if (!isObject(verified) || !isUuid(verified.authorization_id) || verified.operation !== input.operation || !Number.isSafeInteger(verified.authenticated_at)) {
      throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.WEBAUTHN_UNAVAILABLE);
    }
    return response(200, { authorization_id: verified.authorization_id });
  }

  async function loadAllowList(input) {
    let raw;
    try {
      raw = await callAllowList(credentialAllowList, input);
    } catch (error) {
      throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.CREDENTIAL_ALLOW_LIST_UNAVAILABLE, { status: 503, cause: error });
    }
    try {
      return normalizeAllowList(raw);
    } catch (error) {
      if (error instanceof HumanAuthHttpError) throw error;
      throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.CREDENTIAL_ALLOW_LIST_INVALID, { status: 503, cause: error });
    }
  }

  return Object.freeze({
    handle,
    paths: HUMAN_AUTH_HTTP_PATHS,
    expectedOrigin,
    rpId: expectedRpId,
    basePath: normalizedBasePath
  });
}

function assertServices({ humanSession, recentAuthService, credentialAllowList }) {
  if (!humanSession || typeof humanSession.authenticateRequest !== "function") throw new TypeError("humanSession must expose authenticateRequest()");
  if (!recentAuthService || typeof recentAuthService.begin !== "function" || typeof recentAuthService.verify !== "function") throw new TypeError("recentAuthService must expose begin() and verify()");
  if (!credentialAllowList || typeof credentialAllowList !== "object") throw new TypeError("credentialAllowList is required");
  if (!["listCredentials", "list", "forSession"].some((method) => typeof credentialAllowList[method] === "function")) throw new TypeError("credentialAllowList must expose listCredentials()");
}

async function callAllowList(adapter, input) {
  const method = ["listCredentials", "list", "forSession"].find((candidate) => typeof adapter[candidate] === "function");
  return adapter[method](input);
}

function normalizeAllowList(raw) {
  if (!Array.isArray(raw) || raw.length > MAX_CREDENTIALS) throw new TypeError("credential allow list must be an array");
  const seen = [];
  return raw.map((entry) => {
    const value = typeof entry === "string" ? { id: entry } : entry;
    if (!isObject(value)) throw new TypeError("credential descriptor is invalid");
    const unknown = Object.keys(value).filter((key) => !new Set(["id", "credential_id", "credentialId", "type", "transports"]).has(key));
    if (unknown.length > 0) throw new TypeError("credential descriptor contains unknown fields");
    const id = value.id ?? value.credential_id ?? value.credentialId;
    if (!isBase64Url(id, 1, MAX_CREDENTIAL_ID_BYTES)) throw new TypeError("credential id is invalid");
    if (seen.some((existing) => sameCredentialId(existing, id))) throw new TypeError("credential ids must be unique");
    seen.push(id);
    const type = value.type ?? "public-key";
    if (type !== "public-key") throw new TypeError("credential type is invalid");
    const transports = value.transports === undefined ? undefined : normalizeTransports(value.transports);
    return Object.freeze({ id, type, ...(transports === undefined ? {} : { transports }) });
  });
}

function normalizeTransports(value) {
  if (!Array.isArray(value) || value.length > 7 || value.some((item) => typeof item !== "string" || !ALLOWED_TRANSPORTS.has(item))) throw new TypeError("credential transports are invalid");
  return Object.freeze([...new Set(value)]);
}

function parseOptionsBody(body, session, expectedRpId, expectedOrigin, operationSet) {
  assertObjectBody(body, new Set(["organization_id", "operation"]));
  const organization_id = requiredUuid(body.organization_id, "organization_id");
  const operation = requiredOperation(body.operation, operationSet);
  void expectedRpId;
  void expectedOrigin;
  return { organization_id, operation };
}

function parseVerifyBody(body, session, expectedRpId, expectedOrigin, operationSet) {
  assertObjectBody(body, new Set(["organization_id", "operation", "challenge_id", "credential"]));
  const organization_id = requiredUuid(body.organization_id, "organization_id");
  const operation = requiredOperation(body.operation, operationSet);
  const challenge_id = requiredUuid(body.challenge_id, "challenge_id");
  const assertion = parseBrowserCredential(body.credential);
  const challenge = extractChallenge(assertion.client_data_json, expectedOrigin);
  if (!isBase64Url(challenge, 1, MAX_CHALLENGE_BYTES)) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.CHALLENGE_INVALID);
  void expectedRpId;
  return { organization_id, operation, challenge_id, challenge, assertion };
}

function parseBrowserCredential(value) {
  assertObjectBody(value, ALLOWED_CREDENTIAL_KEYS);
  if (value.type !== "public-key" || typeof value.id !== "string" || value.id.length < 1 || value.id.length > MAX_CREDENTIAL_ID_BYTES || /[\u0000-\u001f\u007f]/.test(value.id) || typeof value.rawId !== "string" || value.id !== value.rawId || !isBase64Url(value.rawId, 1, MAX_CREDENTIAL_ID_BYTES) || !Object.hasOwn(value, "clientExtensionResults") || !isObject(value.clientExtensionResults)) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST);
  if (value.authenticatorAttachment !== undefined && value.authenticatorAttachment !== "platform" && value.authenticatorAttachment !== "cross-platform") throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST);
  if (!isObject(value.response)) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST);
  assertObjectBody(value.response, new Set(["clientDataJSON", "authenticatorData", "signature", "userHandle"]));
  const assertion = {
    credential_id: value.rawId,
    client_data_json: requiredBase64Url(value.response.clientDataJSON, 1, MAX_CLIENT_DATA_BYTES, "clientDataJSON"),
    authenticator_data: requiredBase64Url(value.response.authenticatorData, 37, MAX_AUTHENTICATOR_DATA_BYTES, "authenticatorData"),
    signature: requiredBase64Url(value.response.signature, 64, MAX_SIGNATURE_BYTES, "signature")
  };
  if (value.response.userHandle !== undefined && value.response.userHandle !== null) assertion.user_handle = requiredBase64Url(value.response.userHandle, 1, MAX_USER_HANDLE_BYTES, "userHandle");
  return assertion;
}

function extractChallenge(encoded, expectedOrigin) {
  let bytes;
  try { bytes = decodeBase64Url(encoded, 1, MAX_CLIENT_DATA_BYTES); } catch { throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.CHALLENGE_INVALID, { status: 400 }); }
  const text = Buffer.from(bytes).toString("utf8");
  if (Buffer.from(text, "utf8").compare(bytes) !== 0) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.CHALLENGE_INVALID, { status: 400 });
  let data;
  try { data = JSON.parse(text); } catch { throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.CHALLENGE_INVALID, { status: 400 }); }
  if (!isObject(data) || data.type !== "webauthn.get" || data.origin !== expectedOrigin || data.crossOrigin !== false || !isBase64Url(data.challenge, 1, MAX_CHALLENGE_BYTES)) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.CHALLENGE_INVALID, { status: 400 });
  return data.challenge;
}

function mapServiceError(error, phase) {
  if (error instanceof HumanAuthHttpError) return error;
  if (error instanceof WebAuthnCeremonyError || error?.name === "WebAuthnCeremonyError") {
    if (CHALLENGE_FAILURES.has(error.code)) return new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.CHALLENGE_INVALID, { status: 409, cause: error });
    if (error.code === WEBAUTHN_ERROR_CODES.INVALID_REQUEST || error.code === WEBAUTHN_ERROR_CODES.INVALID_CONTEXT || error.code === WEBAUTHN_ERROR_CODES.INVALID_RESPONSE) return new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400, cause: error });
    if (error.code === WEBAUTHN_ERROR_CODES.CAPACITY_EXCEEDED) return new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.WEBAUTHN_UNAVAILABLE, { status: 503, cause: error });
    return new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.WEBAUTHN_VERIFICATION_FAILED, { status: 401, cause: error });
  }
  return new HumanAuthHttpError(phase === "begin" ? HUMAN_AUTH_HTTP_ERROR_CODES.WEBAUTHN_UNAVAILABLE : HUMAN_AUTH_HTTP_ERROR_CODES.WEBAUTHN_VERIFICATION_FAILED, { status: phase === "begin" ? 503 : 401, cause: error });
}

function mapError(error) {
  if (error instanceof HumanAuthAbuseControlError) return response(error.status, { error: { code: error.code, message: error.message } }, error.headers);
  if (error instanceof HumanAuthHttpError) return response(error.status, { error: { code: error.code, message: ERROR_MESSAGES[error.code] ?? ERROR_MESSAGES[HUMAN_AUTH_HTTP_ERROR_CODES.INTERNAL_ERROR] } }, error.headers);
  if (error?.code === HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST) return response(400, { error: { code: HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST, message: ERROR_MESSAGES[HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST] } });
  return response(500, { error: { code: HUMAN_AUTH_HTTP_ERROR_CODES.INTERNAL_ERROR, message: ERROR_MESSAGES[HUMAN_AUTH_HTTP_ERROR_CODES.INTERNAL_ERROR] } });
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
  return Object.freeze({
    status,
    ok: status >= 200 && status < 300,
    headers: Object.freeze(headers),
    body: Object.freeze(body),
    text: async () => json,
    json: async () => body,
    toResponse: () => new Response(json, { status, headers })
  });
}

function writeNodeResponse(nodeResponse, result) {
  if (!nodeResponse || typeof nodeResponse.end !== "function") throw new TypeError("nodeResponse is invalid");
  const headers = result.headers;
  if (typeof nodeResponse.writeHead === "function") nodeResponse.writeHead(result.status, headers);
  else if (typeof nodeResponse.setHeader === "function") for (const [name, value] of Object.entries(headers)) nodeResponse.setHeader(name, value);
  nodeResponse.statusCode = result.status;
  nodeResponse.end(JSON.stringify(result.body));
}

function normalizeRequest(input) {
  if (!input || typeof input !== "object") throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  const method = String(input.method ?? "").toUpperCase();
  if (!method) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  const url = String(input.url ?? input.originalUrl ?? input.path ?? "");
  if (!url || url.length > 8192) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  return { input, method, url, headers: normalizeHeaders(input.headers ?? {}), body: input.body };
}

function resolveRoute(rawUrl, basePath) {
  let url;
  try { url = new URL(rawUrl, "https://agentpass.invalid"); } catch { return undefined; }
  if (url.search || url.hash) return undefined;
  const path = url.pathname;
  if (path === `${basePath}${AUTHENTICATION_OPTIONS_PATH}`) return "options";
  if (path === `${basePath}${AUTHENTICATION_VERIFY_PATH}`) return "verify";
  return undefined;
}

async function readJsonBody(request, maxBytes) {
  const contentType = header(request.headers, "content-type");
  if (typeof contentType !== "string" || !/^application\/json(?:\s*;|$)/i.test(contentType)) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  const contentLength = header(request.headers, "content-length");
  if (contentLength !== undefined && (!/^\d+$/.test(contentLength) || Number(contentLength) > maxBytes)) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
  let raw;
  const input = request.input;
  if (input.body !== undefined && !isReadable(input.body)) raw = input.body;
  else if (typeof input.arrayBuffer === "function") raw = Buffer.from(await input.arrayBuffer());
  else if (typeof input.text === "function") raw = await input.text();
  else if (typeof input.json === "function") {
    try { raw = await input.json(); } catch (error) { throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400, cause: error }); }
  } else if (isReadable(input)) raw = await readStream(input, maxBytes);
  else if (isReadable(input.body)) raw = await readStream(input.body, maxBytes);
  else throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  if ((isObject(raw) && !Buffer.isBuffer(raw) && !(raw instanceof Uint8Array)) || Array.isArray(raw)) return raw;
  const bytes = Buffer.isBuffer(raw) ? raw : raw instanceof Uint8Array ? Buffer.from(raw) : Buffer.from(String(raw), "utf8");
  if (bytes.length > maxBytes) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); } catch (error) { throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400, cause: error }); }
  return value;
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
    if (input.length % 2 !== 0) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
    for (let index = 0; index < input.length; index += 2) setHeader(result, input[index], input[index + 1]);
    return result;
  }
  if (!input || typeof input !== "object") throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  for (const [name, value] of Object.entries(input)) setHeader(result, name, value);
  return result;
}

function setHeader(target, name, value) {
  if (typeof name !== "string" || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || Array.isArray(value) || typeof value === "object" || value === undefined) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  const normalized = name.toLowerCase();
  if (target[normalized] !== undefined) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  target[normalized] = String(value);
}

function header(headers, name) {
  const value = headers[name.toLowerCase()];
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length > 8192 || /[\u0000-\u001f\u007f]/.test(value)) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  return value;
}

async function readStream(stream, maxBytes) {
  const chunks = [];
  let total = 0;
  for await (const chunk of stream) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += bytes.length;
    if (total > maxBytes) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

function assertObjectBody(value, allowedKeys) {
  if (!isObject(value) || Object.keys(value).some((key) => !allowedKeys.has(key))) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
}

function requiredUuid(value) {
  if (typeof value !== "string" || !UUID_V4.test(value)) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  return value.toLowerCase();
}

function requiredOperation(value, operationSet) {
  if (typeof value !== "string" || !IDENTIFIER.test(value) || value.length > MAX_OPERATION_LENGTH || (operationSet && !operationSet.has(value))) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  return value;
}

function requiredBase64Url(value, min, max) {
  if (!isBase64Url(value, min, max)) throw new HumanAuthHttpError(HUMAN_AUTH_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  return value;
}

function isBase64Url(value, min, max) {
  if (typeof value !== "string" || !BASE64URL.test(value)) return false;
  const bytes = Buffer.from(value, "base64url");
  return bytes.length >= min && bytes.length <= max && bytes.toString("base64url") === value;
}

function decodeBase64Url(value, min, max) {
  if (!isBase64Url(value, min, max)) throw new TypeError("base64url is invalid");
  return Buffer.from(value, "base64url");
}

function sameCredentialId(left, right) {
  try {
    const a = decodeBase64Url(left, 1, MAX_CREDENTIAL_ID_BYTES);
    const b = decodeBase64Url(right, 1, MAX_CREDENTIAL_ID_BYTES);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function normalizeRpId(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 253 || !RP_ID.test(value) || value.includes("..")) throw new TypeError("rpId is invalid");
  return value.toLowerCase();
}

function assertOrigin(value) {
  normalizeOrigin(value);
}

function normalizeOrigin(value) {
  if (typeof value !== "string" || value.length > 512 || /[\u0000-\u001f\u007f]/.test(value)) throw new TypeError("origin is invalid");
  let parsed;
  try { parsed = new URL(value); } catch { throw new TypeError("origin is invalid"); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash || parsed.origin !== value) throw new TypeError("origin is invalid");
  return parsed.origin;
}

function normalizeBasePath(value) {
  if (value === "") return "";
  if (typeof value !== "string" || !value.startsWith("/") || value.endsWith("/") || value.includes("?") || value.includes("#") || /[\u0000-\u001f\u007f]/.test(value)) throw new TypeError("basePath is invalid");
  return value;
}

function normalizeOperations(value) {
  if (value === undefined) return undefined;
  if (!(value instanceof Set) && !Array.isArray(value)) throw new TypeError("allowedOperations is invalid");
  const values = value instanceof Set ? [...value] : value;
  if (values.length === 0 || values.length > 256) throw new TypeError("allowedOperations is invalid");
  return new Set(values.map((item) => {
    if (typeof item !== "string" || !IDENTIFIER.test(item) || item.length > MAX_OPERATION_LENGTH) throw new TypeError("allowed operation is invalid");
    return item;
  }));
}

function parseDateTime(value) {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return NaN;
  return parsed;
}

function isUuid(value) { return typeof value === "string" && UUID_V4.test(value); }
function isObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function isReadable(value) { return value !== null && typeof value === "object" && typeof value[Symbol.asyncIterator] === "function"; }
