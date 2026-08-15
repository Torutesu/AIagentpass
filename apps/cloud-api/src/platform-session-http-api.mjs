import {
  PLATFORM_SESSION_COOKIE_NAME,
  PLATFORM_SESSION_CSRF_HEADER,
  hashPlatformSessionToken,
  isPlatformSessionToken,
  parsePlatformSessionCookie,
  serializeClearedPlatformSessionCookie,
  serializePlatformSessionCookie
} from "./platform-session-transport.mjs";
import {
  PLATFORM_SESSION_WEBAUTHN_ERROR_CODES,
  PlatformSessionWebAuthnError
} from "./platform-session-webauthn.mjs";
import { hashOpaqueToken, parseSessionCookie } from "./human-session.mjs";
import { platformPromotionAuthorizationRequestDigest } from "./platform-promotion-http-contract.mjs";

const ROOT_PATH = "/api/platform/v1/sessions";
const DEFAULT_MAX_BODY_BYTES = 64 * 1024;
const MAX_URL_BYTES = 8 * 1024;
const MAX_HEADER_BYTES = 8 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/u;
const JSON_CONTENT_TYPE = /^application\/json(?:\s*;\s*(?:charset\s*=\s*)?[^;]+)*$/iu;
const SAFE_SET_COOKIE = new RegExp(`^${escapeRegExp(PLATFORM_SESSION_COOKIE_NAME)}=[A-Za-z0-9_-]{43}; Path=/; HttpOnly; Secure; SameSite=Strict(?:; Max-Age=[0-9]+)?$`, "u");
const AUTHORITY_FIELDS = new Set([
  "principal_id", "member_id", "organization_id", "assignment_id", "authority_generation",
  "operation", "capability", "rp_id", "origin", "user_verification",
  "request_digest_sha256", "allowed_credential_ids"
]);
const ASSERTION_FIELDS = new Set([
  "version", "type", "challenge_id", "jti", "credential_id",
  "client_data_json", "authenticator_data", "signature", "user_handle"
]);
const PUBLIC_INTENT_FIELDS = new Set([
  "operation", "organization_id", "promotion_id", "deployment_id", "environment", "candidate_id"
]);
const PUBLIC_INTENT_OPERATION = "platform.promotion.issue";
const PUBLIC_INTENT_DEPLOYMENT_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const PUBLIC_INTENT_CANDIDATE_ID = /^release-pkg-sha256-v1-[0-9a-f]{64}$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._~:-]{7,127}$/u;
const CHALLENGE_RESPONSE_FIELDS = new Set([
  "version", "type", "challenge_id", "challenge", "jti", "platform_session_id",
  "principal_id", "member_id", "organization_id", "assignment_id", "authority_generation",
  "operation", "capability", "request_digest_sha256", "allowed_credential_ids",
  "challenge_expires_at", "issued_at", "expires_at", "one_use", "rp_id", "origin",
  "user_verification"
]);
const FORBIDDEN_HEADERS = new Set([
  "authorization",
  "agentpass-csrf",
  "x-csrf-token",
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
  "x-agentpass-assignment-id"
]);

export const PLATFORM_SESSION_HTTP_PATHS = Object.freeze({
  challenge: `${ROOT_PATH}/challenges`,
  begin: `${ROOT_PATH}/challenges`,
  assertion: ROOT_PATH,
  verify: ROOT_PATH,
  revoke: `${ROOT_PATH}/revoke`
});

export const PLATFORM_SESSION_HTTP_ERROR_CODES = Object.freeze({
  INVALID_REQUEST: "platform_session_http_invalid_request",
  METHOD_NOT_ALLOWED: "platform_session_http_method_not_allowed",
  ORIGIN_NOT_ALLOWED: "platform_session_http_origin_not_allowed",
  BOOTSTRAP_REQUIRED: "platform_session_http_bootstrap_required",
  AUTHORITY_UNAVAILABLE: "platform_session_http_authority_unavailable",
  CHALLENGE_FAILED: "platform_session_http_challenge_failed",
  ASSERTION_FAILED: "platform_session_http_assertion_failed",
  SESSION_REQUIRED: "platform_session_http_session_required",
  CSRF_FAILED: "platform_session_http_csrf_failed",
  REVOKE_UNAVAILABLE: "platform_session_http_revoke_unavailable",
  INTERNAL_ERROR: "platform_session_http_internal_error"
});

const ERROR_MESSAGES = Object.freeze({
  [PLATFORM_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST]: "The platform session request is invalid",
  [PLATFORM_SESSION_HTTP_ERROR_CODES.METHOD_NOT_ALLOWED]: "The HTTP method is not allowed",
  [PLATFORM_SESSION_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED]: "The request origin is not allowed",
  [PLATFORM_SESSION_HTTP_ERROR_CODES.BOOTSTRAP_REQUIRED]: "An authenticated bootstrap is required",
  [PLATFORM_SESSION_HTTP_ERROR_CODES.AUTHORITY_UNAVAILABLE]: "Platform session authority is unavailable",
  [PLATFORM_SESSION_HTTP_ERROR_CODES.CHALLENGE_FAILED]: "The platform session challenge could not be created",
  [PLATFORM_SESSION_HTTP_ERROR_CODES.ASSERTION_FAILED]: "The platform session assertion could not be verified",
  [PLATFORM_SESSION_HTTP_ERROR_CODES.SESSION_REQUIRED]: "A valid platform session is required",
  [PLATFORM_SESSION_HTTP_ERROR_CODES.CSRF_FAILED]: "The platform session CSRF token is invalid",
  [PLATFORM_SESSION_HTTP_ERROR_CODES.REVOKE_UNAVAILABLE]: "Platform session revocation is unavailable",
  [PLATFORM_SESSION_HTTP_ERROR_CODES.INTERNAL_ERROR]: "The request could not be completed"
});

const ERROR_STATUS = Object.freeze({
  [PLATFORM_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST]: 400,
  [PLATFORM_SESSION_HTTP_ERROR_CODES.METHOD_NOT_ALLOWED]: 405,
  [PLATFORM_SESSION_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED]: 403,
  [PLATFORM_SESSION_HTTP_ERROR_CODES.BOOTSTRAP_REQUIRED]: 401,
  [PLATFORM_SESSION_HTTP_ERROR_CODES.AUTHORITY_UNAVAILABLE]: 503,
  [PLATFORM_SESSION_HTTP_ERROR_CODES.CHALLENGE_FAILED]: 503,
  [PLATFORM_SESSION_HTTP_ERROR_CODES.ASSERTION_FAILED]: 401,
  [PLATFORM_SESSION_HTTP_ERROR_CODES.SESSION_REQUIRED]: 401,
  [PLATFORM_SESSION_HTTP_ERROR_CODES.CSRF_FAILED]: 403,
  [PLATFORM_SESSION_HTTP_ERROR_CODES.REVOKE_UNAVAILABLE]: 503,
  [PLATFORM_SESSION_HTTP_ERROR_CODES.INTERNAL_ERROR]: 500
});

export class PlatformSessionHttpError extends Error {
  constructor(code, { status = ERROR_STATUS[code] ?? 500, allow = undefined, cause = undefined } = {}) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[PLATFORM_SESSION_HTTP_ERROR_CODES.INTERNAL_ERROR], { cause });
    this.name = "PlatformSessionHttpError";
    this.code = code;
    this.status = status;
    this.allow = allow;
  }
}

/**
 * Framework-free HTTP boundary for platform sessions.
 *
 * The authority resolver and bootstrap authenticator are trusted server-side
 * dependencies. Browser JSON is reduced to a public, canonical intent before
 * either dependency sees it, so caller-supplied authority cannot become an
 * authority input by accident.
 * Revoke services must advertise `bearerBound: true` and receive only the
 * transport hash of the platform cookie.
 */
export function createPlatformSessionHttpApi({
  platformSessionWebAuthn,
  webauthnService,
  authenticateBootstrap,
  authenticatedBootstrap,
  resolveAuthorityContext,
  trustedAuthorityResolver,
  revokeService,
  origin,
  maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
  sessionMaxAgeSeconds = 900
} = {}) {
  const ceremony = platformSessionWebAuthn ?? webauthnService;
  if (!ceremony || typeof ceremony.begin !== "function" || typeof ceremony.verify !== "function") {
    throw new TypeError("platformSessionWebAuthn must expose begin() and verify()");
  }
  const bootstrap = authenticatedBootstrap ?? authenticateBootstrap;
  const authority = trustedAuthorityResolver ?? resolveAuthorityContext;
  if (typeof bootstrap !== "function" || typeof authority !== "function") {
    throw new TypeError("authenticated bootstrap and trusted authority resolver are required");
  }
  assertOrigin(origin);
  assertBodyLimit(maxBodyBytes);
  if (!Number.isSafeInteger(sessionMaxAgeSeconds) || sessionMaxAgeSeconds < 1 || sessionMaxAgeSeconds > 86_400) {
    throw new TypeError("sessionMaxAgeSeconds is invalid");
  }

  async function handle(input, nodeResponse = undefined) {
    const result = await dispatch(input);
    if (nodeResponse !== undefined) writeNodeResponse(nodeResponse, result);
    return result;
  }

  async function dispatch(input) {
    try {
      const request = normalizeRequest(input);
      const route = resolveRoute(request.url);
      if (!route) return response(404, { error: { code: "not_found", message: "Resource not found" } });
      if (route.invalidUrl) throw invalidRequest();
      if (request.method !== "POST") {
        throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.METHOD_NOT_ALLOWED, { status: 405, allow: "POST" });
      }
      assertSecurityHeaders(request, route.kind);
      const requestOrigin = header(request.headers, "origin");
      if (requestOrigin === undefined || requestOrigin !== origin || requestOrigin === "null") {
        throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED, { status: 403 });
      }
      rejectAmbiguousPlatformCookie(request.headers, route.kind);

      if (route.kind === "challenge") return await dispatchChallenge(request);
      if (route.kind === "assertion") return await dispatchAssertion(request);
      return await dispatchRevoke(request);
    } catch (error) {
      return mapError(error);
    }
  }

  async function dispatchChallenge(request) {
    const body = await readJsonBody(request, maxBodyBytes);
    const intent = normalizePublicIntent(body, header(request.headers, "idempotency-key"));
    const context = await resolveContext(request, "challenge", { intent });
    let issued;
    try {
      issued = await ceremony.begin(context);
    } catch (error) {
      throw mapCeremonyError(error, PLATFORM_SESSION_HTTP_ERROR_CODES.CHALLENGE_FAILED);
    }
    const challenge = normalizeChallengeResponse(issued);
    return response(201, challenge);
  }

  async function dispatchAssertion(request) {
    const body = await readJsonBody(request, maxBodyBytes);
    assertExactKeys(body, ASSERTION_FIELDS);
    if (header(request.headers, "idempotency-key") !== undefined) throw invalidRequest();
    const assertion = normalizeAssertionBody(body);
    const context = await resolveContext(request, "assertion", { challenge_id: assertion.challenge_id });
    let issued;
    try {
      issued = await ceremony.verify({ ...assertion, ...context });
    } catch (error) {
      throw mapCeremonyError(error, PLATFORM_SESSION_HTTP_ERROR_CODES.ASSERTION_FAILED);
    }
    if (!isObject(issued) || Object.hasOwn(issued, "setCookie") || Object.hasOwn(issued, "cookie")) {
      throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.ASSERTION_FAILED, { status: 503 });
    }
    const bearer = issued?.session_bearer;
    if (!isPlatformSessionToken(bearer)) {
      throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.ASSERTION_FAILED, { status: 503 });
    }
    const csrfToken = issued?.csrf_token ?? issued?.csrfToken;
    if (!isPlatformSessionToken(csrfToken)) {
      throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.ASSERTION_FAILED, { status: 503 });
    }
    const session = projectSession(issued?.session);
    const safeBody = {
      session,
      challenge_id: assertion.challenge_id,
      csrf_token: csrfToken
    };
    const authenticatedAt = safeTimestamp(issued?.authenticated_at);
    if (authenticatedAt !== undefined) safeBody.authenticated_at = authenticatedAt;
    const setCookie = serializePlatformSessionCookie(bearer, { maxAgeSeconds: sessionMaxAgeSeconds });
    if (!SAFE_SET_COOKIE.test(setCookie)) {
      throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.ASSERTION_FAILED, { status: 503 });
    }
    return response(201, safeBody, { "Set-Cookie": setCookie });
  }

  async function dispatchRevoke(request) {
    if (!isSafeRevokeService(revokeService)) {
      throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.REVOKE_UNAVAILABLE, { status: 503 });
    }
    await readNoBody(request);
    const cookieHeader = header(request.headers, "cookie");
    if (cookieHeader === undefined) throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.SESSION_REQUIRED, { status: 401 });
    let token;
    try {
      token = parsePlatformSessionCookie(cookieHeader);
    } catch {
      throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.SESSION_REQUIRED, { status: 401 });
    }
    const csrfToken = header(request.headers, PLATFORM_SESSION_CSRF_HEADER);
    if (!isPlatformSessionToken(csrfToken)) {
      throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.CSRF_FAILED, { status: 403 });
    }
    let revoked;
    try {
      revoked = await revokeService.revokeSelf({
        session_material_hash: hashPlatformSessionToken(token),
        csrf_token: csrfToken
      });
    } catch (error) {
      throw mapRevokeError(error);
    }
    if (revoked !== true && (!revoked || revoked.revoked !== true)) {
      throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.REVOKE_UNAVAILABLE, { status: 503 });
    }
    return response(200, { session: null }, { "Set-Cookie": serializeClearedPlatformSessionCookie() });
  }

  async function resolveContext(request, phase, extra = {}) {
    const sessionMaterialHash = humanSessionMaterialHash(request.headers, phase);
    const resolverInput = Object.freeze({
      phase,
      ...(extra.challenge_id === undefined ? {} : { challenge_id: extra.challenge_id }),
      intent: extra.intent ?? null,
      session_material_hash: sessionMaterialHash
    });
    let bootstrapValue = null;
    if (phase === "challenge") {
      try {
        bootstrapValue = await bootstrap(resolverInput);
      } catch (error) {
        throw mapBootstrapError(error);
      }
      if (bootstrapValue === undefined || bootstrapValue === null || bootstrapValue === false) {
        throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.BOOTSTRAP_REQUIRED, { status: 401 });
      }
    }
    let context;
    try {
      context = await authority(Object.freeze({ ...resolverInput, bootstrap: bootstrapValue }));
    } catch (error) {
      throw mapAuthorityError(error);
    }
    try {
      return normalizeAuthorityContext(context, origin, extra.intent);
    } catch (error) {
      if (error instanceof PlatformSessionHttpError) throw error;
      throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.AUTHORITY_UNAVAILABLE, { status: 503, cause: error });
    }
  }

  return Object.freeze({
    handle,
    paths: PLATFORM_SESSION_HTTP_PATHS,
    expectedOrigin: origin,
    maxBodyBytes
  });
}

function resolveRoute(rawUrl) {
  let parsed;
  try {
    if (Buffer.byteLength(rawUrl, "utf8") > MAX_URL_BYTES) return undefined;
    parsed = new URL(rawUrl, "https://agentpass.invalid");
  } catch {
    return undefined;
  }
  const path = parsed.pathname;
  const known = path === ROOT_PATH || path === `${ROOT_PATH}/challenges` || path === `${ROOT_PATH}/revoke`;
  if (!known) return undefined;
  if (parsed.search || parsed.hash) return { invalidUrl: true };
  if (path === `${ROOT_PATH}/challenges`) return { kind: "challenge" };
  if (path === ROOT_PATH) return { kind: "assertion" };
  return { kind: "revoke" };
}

function normalizeRequest(input) {
  if (!input || typeof input !== "object") throw invalidRequest();
  const method = String(input.method ?? "").toUpperCase();
  const url = String(input.url ?? input.originalUrl ?? input.path ?? "");
  if (!method || !url || Buffer.byteLength(url, "utf8") > MAX_URL_BYTES) throw invalidRequest();
  const headers = normalizeHeaders(input.headers ?? {});
  return Object.freeze({
    input,
    method,
    url,
    headers,
    body: input.body,
    safe: Object.freeze({
      method,
      url,
      headers: Object.freeze({ ...headers })
    })
  });
}

function normalizeHeaders(input) {
  const result = Object.create(null);
  if (input && typeof input.forEach === "function") {
    input.forEach((value, name) => setHeader(result, name, value));
    return result;
  }
  if (!input || typeof input !== "object" || Array.isArray(input)) throw invalidRequest();
  for (const [name, value] of Object.entries(input)) setHeader(result, name, value);
  return result;
}

function setHeader(target, name, value) {
  if (typeof name !== "string" || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u.test(name) || typeof value !== "string" || CONTROL_CHARACTERS.test(value) || value.length > MAX_HEADER_BYTES) throw invalidRequest();
  const normalized = name.toLowerCase();
  if (Object.hasOwn(target, normalized)) throw invalidRequest();
  target[normalized] = value;
}

function assertSecurityHeaders(request, routeKind) {
  for (const name of Object.keys(request.headers)) if (FORBIDDEN_HEADERS.has(name)) throw invalidRequest();
  if (routeKind !== "revoke" && Object.hasOwn(request.headers, PLATFORM_SESSION_CSRF_HEADER)) throw invalidRequest();
  if (routeKind === "revoke" && Object.hasOwn(request.headers, "idempotency-key")) throw invalidRequest();
  if (Object.hasOwn(request.headers, "cookie")) {
    const cookie = request.headers.cookie;
    if (cookie.length > MAX_HEADER_BYTES) throw invalidRequest();
  }
}

function rejectAmbiguousPlatformCookie(headers, routeKind) {
  const cookie = headers.cookie;
  if (cookie === undefined || !hasPlatformCookie(cookie)) return;
  try {
    parsePlatformSessionCookie(cookie);
  } catch {
    if (routeKind === "revoke" && countPlatformCookies(cookie) < 2) {
      throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.SESSION_REQUIRED, { status: 401 });
    }
    throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  }
}

function hasPlatformCookie(cookieHeader) {
  return cookieHeader.split(";").some((part) => part.slice(0, part.indexOf("=")).trim() === PLATFORM_SESSION_COOKIE_NAME);
}

function countPlatformCookies(cookieHeader) {
  return cookieHeader.split(";").filter((part) => part.slice(0, part.indexOf("=")).trim() === PLATFORM_SESSION_COOKIE_NAME).length;
}

function redactedTransportRequest(request) {
  const headers = { ...request.headers };
  delete headers.cookie;
  delete headers[PLATFORM_SESSION_CSRF_HEADER];
  return Object.freeze({ ...request, headers: Object.freeze(headers) });
}

async function readJsonBody(request, maxBytes) {
  const contentType = header(request.headers, "content-type");
  if (contentType === undefined || !JSON_CONTENT_TYPE.test(contentType)) throw invalidRequest();
  assertContentLength(request.headers, maxBytes);
  const raw = await readRawBody(request, maxBytes);
  if (raw.length > maxBytes) throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
  try {
    return parseJsonNoDuplicateKeys(raw.toString("utf8"));
  } catch (error) {
    if (error instanceof DuplicateJsonKeyError || error instanceof SyntaxError) throw invalidRequest({ cause: error });
    throw error;
  }
}

async function readNoBody(request) {
  const contentType = header(request.headers, "content-type");
  if (contentType !== undefined && !JSON_CONTENT_TYPE.test(contentType)) throw invalidRequest();
  assertContentLength(request.headers, 0);
  const raw = await readRawBody(request, 0, true);
  if (raw.length !== 0) throw invalidRequest();
}

async function readRawBody(request, maxBytes, allowAbsent = false) {
  const input = request.input;
  if (input.body === undefined && typeof input.arrayBuffer !== "function" && typeof input.text !== "function" && typeof input.json !== "function" && !isReadable(input) && !isReadable(input.body)) {
    if (allowAbsent) return Buffer.alloc(0);
    if (input.body === undefined && input.body !== null && input.body !== "") throw invalidRequest();
    if (input.body === undefined) throw invalidRequest();
  }
  let raw;
  if (typeof input.arrayBuffer === "function") raw = Buffer.from(await input.arrayBuffer());
  else if (input.body !== undefined && !isReadable(input.body)) raw = input.body;
  else if (typeof input.text === "function") raw = await input.text();
  else if (typeof input.json === "function") {
    // Request.json() loses duplicate-key information; refuse it for this
    // boundary rather than weakening the exact JSON contract.
    throw invalidRequest();
  } else if (isReadable(input)) raw = await readStream(input, maxBytes);
  else if (isReadable(input.body)) raw = await readStream(input.body, maxBytes);
  else raw = "";
  if (isObject(raw) || Array.isArray(raw)) {
    let serialized;
    try { serialized = JSON.stringify(raw); } catch (error) { throw invalidRequest({ cause: error }); }
    raw = serialized;
  }
  const bytes = toBytes(raw);
  if (bytes.length > maxBytes) throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
  return bytes;
}

async function readStream(stream, maxBytes) {
  const chunks = [];
  let total = 0;
  for await (const chunk of stream) {
    const bytes = toBytes(chunk);
    total += bytes.length;
    if (total > maxBytes) throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

function assertContentLength(headers, maxBytes) {
  const value = header(headers, "content-length");
  if (value === undefined) return;
  if (!/^\d+$/u.test(value) || !Number.isSafeInteger(Number(value)) || Number(value) > maxBytes) {
    throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: Number(value) > maxBytes ? 413 : 400 });
  }
}

function normalizeAuthorityContext(value, expectedOrigin, expectedIntent = undefined) {
  if (!isObject(value)) throw new Error("authority context is unavailable");
  const keys = Object.keys(value);
  if (keys.some((key) => !AUTHORITY_FIELDS.has(key))) throw new Error("authority context contains unexpected fields");
  const result = {
    principal_id: requiredUuid(value.principal_id),
    member_id: requiredUuid(value.member_id),
    organization_id: requiredUuid(value.organization_id),
    assignment_id: requiredUuid(value.assignment_id),
    authority_generation: requiredPositiveInteger(value.authority_generation),
    operation: requiredString(value.operation),
    capability: requiredString(value.capability),
    rp_id: requiredString(value.rp_id),
    origin: requiredString(value.origin),
    request_digest_sha256: requiredDigestHex(value.request_digest_sha256),
    allowed_credential_ids: requiredCredentialIds(value.allowed_credential_ids),
    user_verification: value.user_verification
  };
  if (result.origin !== expectedOrigin || result.user_verification !== "required") throw new Error("authority context is not trusted");
  if (expectedIntent !== undefined) {
    if (result.operation !== expectedIntent.operation
      || result.capability !== expectedIntent.operation
      || result.organization_id !== expectedIntent.organization_id
      || result.request_digest_sha256 !== expectedIntent.request_digest_sha256) {
      throw new Error("authority context does not match public intent");
    }
  }
  return Object.freeze(result);
}

function normalizePublicIntent(value, idempotencyKey) {
  assertExactKeys(value, PUBLIC_INTENT_FIELDS);
  if (value.operation !== PUBLIC_INTENT_OPERATION
    || !UUID.test(value.organization_id ?? "")
    || !UUID.test(value.promotion_id ?? "")
    || typeof value.deployment_id !== "string"
    || !PUBLIC_INTENT_DEPLOYMENT_ID.test(value.deployment_id)
    || !["staging", "production"].includes(value.environment)
    || typeof value.candidate_id !== "string"
    || !PUBLIC_INTENT_CANDIDATE_ID.test(value.candidate_id)
    || typeof idempotencyKey !== "string"
    || !IDEMPOTENCY_KEY.test(idempotencyKey)) {
    throw invalidRequest();
  }
  const intent = {
    operation: PUBLIC_INTENT_OPERATION,
    organization_id: value.organization_id.toLowerCase(),
    promotion_id: value.promotion_id.toLowerCase(),
    deployment_id: value.deployment_id,
    environment: value.environment,
    candidate_id: value.candidate_id,
    idempotency_key: idempotencyKey
  };
  const digestInput = {
    promotion_id: intent.promotion_id,
    deployment_id: intent.deployment_id,
    environment: intent.environment,
    candidate_id: intent.candidate_id,
    idempotency_key: intent.idempotency_key
  };
  return Object.freeze({
    ...intent,
    request_digest_sha256: platformPromotionAuthorizationRequestDigest(digestInput, { organizationId: intent.organization_id })
  });
}

function humanSessionMaterialHash(headers, phase) {
  // Assertion context is challenge-owned. It is resolved by the trusted
  // authority resolver from challenge_id and must not depend on either a
  // human or platform cookie. Revoke has its own platform-cookie path.
  if (phase === "assertion") return null;
  const cookie = header(headers, "cookie");
  if (cookie === undefined) {
    throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.BOOTSTRAP_REQUIRED, { status: 401 });
  }
  let token;
  try {
    token = parseSessionCookie(cookie);
  } catch {
    throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.BOOTSTRAP_REQUIRED, { status: 401 });
  }
  return hashOpaqueToken(token);
}

function normalizeAssertionBody(value) {
  if (!isObject(value)) throw invalidRequest();
  const result = { ...value };
  if (result.version !== 1 || result.type !== "agentpass.platform-session-assertion") throw invalidRequest();
  if (!UUID_V4.test(result.challenge_id ?? "")) throw invalidRequest();
  for (const field of ["credential_id", "client_data_json", "authenticator_data", "signature"]) {
    if (typeof result[field] !== "string" || !BASE64URL.test(result[field])) throw invalidRequest();
  }
  if (typeof result.jti !== "string" || !UUID_V4.test(result.jti)) throw invalidRequest();
  if (result.user_handle !== undefined && (typeof result.user_handle !== "string" || !BASE64URL.test(result.user_handle))) throw invalidRequest();
  return Object.freeze(result);
}

function normalizeChallengeResponse(value) {
  if (!isObject(value)) throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.CHALLENGE_FAILED, { status: 503 });
  for (const key of Object.keys(value)) {
    if (!CHALLENGE_RESPONSE_FIELDS.has(key)) {
      throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.CHALLENGE_FAILED, { status: 503 });
    }
    if (/(bearer|token|secret|assertion|signature|private|session_material_hash)/iu.test(key)) {
      throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.CHALLENGE_FAILED, { status: 503 });
    }
  }
  if (value.version !== 1 || value.type !== "agentpass.platform-session-challenge" || !UUID_V4.test(value.challenge_id ?? "")) throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.CHALLENGE_FAILED, { status: 503 });
  if (typeof value.challenge !== "string" || !BASE64URL.test(value.challenge) || typeof value.jti !== "string" || !UUID_V4.test(value.jti) || !Array.isArray(value.allowed_credential_ids) || value.allowed_credential_ids.length < 1 || typeof value.issued_at !== "string" || typeof value.expires_at !== "string" || value.one_use !== true || typeof value.operation !== "string" || typeof value.rp_id !== "string" || typeof value.origin !== "string" || value.user_verification !== "required") throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.CHALLENGE_FAILED, { status: 503 });
  return Object.freeze({
    version: 1,
    type: "agentpass.platform-session-challenge",
    challenge_id: value.challenge_id,
    jti: value.jti,
    challenge: value.challenge,
    allowed_credential_ids: Object.freeze([...value.allowed_credential_ids]),
    operation: value.operation,
    rp_id: value.rp_id,
    origin: value.origin,
    user_verification: value.user_verification,
    issued_at: value.issued_at,
    expires_at: value.expires_at,
    one_use: true
  });
}

function projectSession(value) {
  if (!isObject(value)) throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.ASSERTION_FAILED, { status: 503 });
  try {
    const operation = requiredString(value.operation);
    const capability = requiredString(value.capability);
    const status = value.status;
    if (operation !== PUBLIC_INTENT_OPERATION || capability !== operation
      || !["active", "expired", "revoked"].includes(status)) throw new Error("session scope is invalid");
    return Object.freeze({
      version: 1,
      type: "agentpass.platform-session",
      session_id: requiredUuid(value.session_id ?? value.id),
      principal_id: requiredUuid(value.principal_id),
      assignment_id: requiredUuid(value.assignment_id),
      authority_generation: requiredPositiveInteger(value.authority_generation ?? value.principal_authority_generation),
      operation,
      capability,
      request_digest_sha256: requiredDigestHex(value.request_digest_sha256),
      authenticated_at: requiredTimestamp(value.authenticated_at),
      issued_at: requiredTimestamp(value.issued_at ?? value.created_at),
      expires_at: requiredTimestamp(value.expires_at),
      status
    });
  } catch (error) {
    if (error instanceof PlatformSessionHttpError) throw error;
    throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.ASSERTION_FAILED, { status: 503, cause: error });
  }
}

function safeTimestamp(value) {
  if (value === undefined) return undefined;
  if (typeof value === "string" && value.length <= 64 && !CONTROL_CHARACTERS.test(value)) return value;
  if (Number.isSafeInteger(value) && value >= 0) return value;
  throw new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.ASSERTION_FAILED, { status: 503 });
}

function assertExactKeys(value, allowed) {
  if (!isObject(value)) throw invalidRequest();
  assertAllowedKeys(value, allowed);
}

function assertAllowedKeys(value, allowed) {
  if (Object.keys(value).some((key) => !allowed.has(key))) throw invalidRequest();
}

function isSafeRevokeService(service) {
  return Boolean(service && service.bearerBound === true && service.acceptsSessionMaterialHash === true && typeof service.revokeSelf === "function");
}

function mapCeremonyError(error, fallbackCode) {
  if (error instanceof PlatformSessionHttpError) return error;
  if (error instanceof PlatformSessionWebAuthnError) {
    const code = error.code;
    if ([PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CHALLENGE_REPLAYED, PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CHALLENGE_EXPIRED, PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CHALLENGE_BUSY].includes(code)) {
      return new PlatformSessionHttpError(fallbackCode, { status: 409, cause: error });
    }
    if ([PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.REPOSITORY_UNAVAILABLE, PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_REPOSITORY_RESULT, PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.SESSION_ISSUANCE_FAILED].includes(code)) {
      return new PlatformSessionHttpError(fallbackCode, { status: 503, cause: error });
    }
  }
  return new PlatformSessionHttpError(fallbackCode, { status: fallbackCode === PLATFORM_SESSION_HTTP_ERROR_CODES.CHALLENGE_FAILED ? 503 : 401, cause: error });
}

function mapBootstrapError(error) {
  if (error instanceof PlatformSessionHttpError) return error;
  if (error?.status === 503) return new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.AUTHORITY_UNAVAILABLE, { status: 503, cause: error });
  return new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.BOOTSTRAP_REQUIRED, { status: 401, cause: error });
}

function mapAuthorityError(error) {
  if (error instanceof PlatformSessionHttpError) return error;
  if (error?.status === 401) return new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.BOOTSTRAP_REQUIRED, { status: 401, cause: error });
  return new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.AUTHORITY_UNAVAILABLE, { status: 503, cause: error });
}

function mapRevokeError(error) {
  if (error instanceof PlatformSessionHttpError) return error;
  if (error?.status === 401) return new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.SESSION_REQUIRED, { status: 401, cause: error });
  if (error?.status === 403) return new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.CSRF_FAILED, { status: 403, cause: error });
  return new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.REVOKE_UNAVAILABLE, { status: 503, cause: error });
}

function mapError(error) {
  if (error instanceof PlatformSessionHttpError) {
    const headers = error.status === 405 ? { Allow: error.allow ?? "POST" } : undefined;
    return response(error.status, { error: { code: error.code, message: ERROR_MESSAGES[error.code] ?? ERROR_MESSAGES[PLATFORM_SESSION_HTTP_ERROR_CODES.INTERNAL_ERROR] } }, headers);
  }
  return response(500, { error: { code: PLATFORM_SESSION_HTTP_ERROR_CODES.INTERNAL_ERROR, message: ERROR_MESSAGES[PLATFORM_SESSION_HTTP_ERROR_CODES.INTERNAL_ERROR] } });
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
  if (typeof value !== "string" || value.length > MAX_HEADER_BYTES || CONTROL_CHARACTERS.test(value)) throw invalidRequest();
  return value;
}

function invalidRequest(options = {}) {
  return new PlatformSessionHttpError(PLATFORM_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400, ...options });
}

function assertOrigin(value) {
  if (typeof value !== "string" || value.length > 512 || CONTROL_CHARACTERS.test(value)) throw new TypeError("origin is invalid");
  let parsed;
  try { parsed = new URL(value); } catch { throw new TypeError("origin is invalid"); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash || parsed.origin !== value) throw new TypeError("origin is invalid");
}

function assertBodyLimit(value) {
  if (!Number.isSafeInteger(value) || value < 1_024 || value > 1024 * 1024) throw new TypeError("maxBodyBytes is invalid");
}

function requiredUuid(value) {
  if (typeof value !== "string" || !UUID.test(value)) throw new Error("authority uuid is invalid");
  return value.toLowerCase();
}

function requiredPositiveInteger(value) {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error("authority generation is invalid");
  return value;
}

function requiredString(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 512 || CONTROL_CHARACTERS.test(value)) throw new Error("authority string is invalid");
  return value;
}

function requiredDigestHex(value) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/iu.test(value)) throw new Error("authority digest is invalid");
  return value.toLowerCase();
}

function requiredTimestamp(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    || !Number.isFinite(Date.parse(value))) throw new Error("session timestamp is invalid");
  return value;
}

function requiredCredentialIds(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 16) throw new Error("authority credential allowlist is invalid");
  const result = value.map((item) => {
    if (typeof item !== "string" || !BASE64URL.test(item) || item.length > 1_400) throw new Error("authority credential id is invalid");
    return item;
  });
  if (new Set(result).size !== result.length) throw new Error("authority credential allowlist is duplicated");
  return Object.freeze([...result].sort());
}

function toBytes(value) {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (typeof value === "string") return Buffer.from(value, "utf8");
  if (value === undefined || value === null) return Buffer.alloc(0);
  return Buffer.from(String(value), "utf8");
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && !Buffer.isBuffer(value) && !(value instanceof Uint8Array);
}

function isReadable(value) {
  return value !== null && typeof value === "object" && typeof value[Symbol.asyncIterator] === "function";
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

class DuplicateJsonKeyError extends Error {}

function parseJsonNoDuplicateKeys(text) {
  if (typeof text !== "string" || text.length === 0) throw new SyntaxError("empty JSON");
  const parser = new JsonParser(text);
  const value = parser.parseValue();
  parser.skipWhitespace();
  if (parser.position !== parser.text.length) throw new SyntaxError("trailing JSON");
  return value;
}

class JsonParser {
  constructor(text) { this.text = text; this.position = 0; }
  parseValue() {
    this.skipWhitespace();
    const character = this.text[this.position];
    if (character === "{") return this.parseObject();
    if (character === "[") return this.parseArray();
    if (character === '"') return this.parseString();
    if (this.text.startsWith("true", this.position)) { this.position += 4; return true; }
    if (this.text.startsWith("false", this.position)) { this.position += 5; return false; }
    if (this.text.startsWith("null", this.position)) { this.position += 4; return null; }
    return this.parseNumber();
  }
  parseObject() {
    this.position++;
    const result = Object.create(null);
    const keys = new Set();
    this.skipWhitespace();
    if (this.text[this.position] === "}") { this.position++; return result; }
    while (true) {
      this.skipWhitespace();
      if (this.text[this.position] !== '"') throw new SyntaxError("object key expected");
      const key = this.parseString();
      if (keys.has(key)) throw new DuplicateJsonKeyError(key);
      keys.add(key);
      this.skipWhitespace();
      if (this.text[this.position++] !== ":") throw new SyntaxError("colon expected");
      result[key] = this.parseValue();
      this.skipWhitespace();
      const delimiter = this.text[this.position++];
      if (delimiter === "}") return result;
      if (delimiter !== ",") throw new SyntaxError("object delimiter expected");
    }
  }
  parseArray() {
    this.position++;
    const result = [];
    this.skipWhitespace();
    if (this.text[this.position] === "]") { this.position++; return result; }
    while (true) {
      result.push(this.parseValue());
      this.skipWhitespace();
      const delimiter = this.text[this.position++];
      if (delimiter === "]") return result;
      if (delimiter !== ",") throw new SyntaxError("array delimiter expected");
    }
  }
  parseString() {
    const start = this.position;
    this.position++;
    while (this.position < this.text.length) {
      const character = this.text[this.position++];
      if (character === "\\") { if (this.position >= this.text.length) throw new SyntaxError("invalid escape"); this.position++; continue; }
      if (character === '"') {
        try { return JSON.parse(this.text.slice(start, this.position)); } catch { throw new SyntaxError("invalid string"); }
      }
      if (character < " ") throw new SyntaxError("control character in string");
    }
    throw new SyntaxError("unterminated string");
  }
  parseNumber() {
    const match = this.text.slice(this.position).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u);
    if (!match) throw new SyntaxError("value expected");
    this.position += match[0].length;
    const number = Number(match[0]);
    if (!Number.isFinite(number)) throw new SyntaxError("number is invalid");
    return number;
  }
  skipWhitespace() { while (/[\u0020\u0009\u000a\u000d]/u.test(this.text[this.position] ?? "")) this.position++; }
}
