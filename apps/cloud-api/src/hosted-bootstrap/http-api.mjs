import crypto from "node:crypto";

import { parseJsonNoDuplicateKeys, DuplicateJsonKeyError } from "../strict-json.mjs";
import { normalizeBrowserRegistrationCredential } from "../human-auth/webauthn/registration.mjs";

const MAX_URL_BYTES = 8 * 1024;
const MAX_HEADER_BYTES = 8 * 1024;
const DEFAULT_MAX_BODY_BYTES = 64 * 1024;
const MAX_COOKIE_BYTES = 4 * 1024;
const MAX_TOKEN_BYTES = 512;
const MAX_QUERY_VALUE_BYTES = 4 * 1024;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/u;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._~-]{8,255}$/u;
const COOKIE_TOKEN = /^[A-Za-z0-9._~-]{16,4096}$/u;

export const HOSTED_BOOTSTRAP_HTTP_PATHS = Object.freeze({
  githubStart: "/api/auth/bootstrap/github/start",
  githubCallback: "/api/auth/bootstrap/github/callback",
  status: "/api/auth/bootstrap/status",
  organizationCreate: "/api/auth/bootstrap/organization",
  webauthnOptions: "/api/auth/bootstrap/webauthn/registration/options",
  webauthnVerify: "/api/auth/bootstrap/webauthn/registration/verify"
});

export const HOSTED_BOOTSTRAP_COOKIE_NAMES = Object.freeze({
  githubState: "__Host-agentpass_github_state",
  bootstrap: "__Host-agentpass_bootstrap",
  session: "__Host-agentpass_session"
});

export const HOSTED_BOOTSTRAP_HTTP_ERROR_CODES = Object.freeze({
  ORIGIN_NOT_ALLOWED: "bootstrap_origin_not_allowed",
  CSRF_FAILED: "bootstrap_csrf_failed",
  SESSION_REQUIRED: "bootstrap_session_required",
  SESSION_EXPIRED: "bootstrap_session_expired",
  OAUTH_STATE_INVALID: "github_oauth_state_invalid",
  SUBJECT_UNVERIFIED: "github_subject_unverified",
  PROVIDER_UNAVAILABLE: "github_provider_unavailable",
  INVALID_REQUEST: "bootstrap_invalid_request",
  IDEMPOTENCY_REQUIRED: "bootstrap_idempotency_required",
  IDEMPOTENCY_CONFLICT: "bootstrap_idempotency_conflict",
  ALREADY_COMPLETED: "bootstrap_already_completed",
  NO_MEMBERSHIP: "bootstrap_no_membership",
  WEBAUTHN_REQUIRED: "bootstrap_webauthn_required",
  WEBAUTHN_INVALID: "bootstrap_webauthn_invalid",
  WEBAUTHN_REPLAYED: "bootstrap_webauthn_replayed",
  UNAVAILABLE: "bootstrap_unavailable"
});

export const HOSTED_BOOTSTRAP_OPERATIONS = Object.freeze({
  githubStart: "hosted.bootstrap.github.start",
  githubCallback: "hosted.bootstrap.github.callback",
  status: "hosted.bootstrap.status",
  organizationCreate: "hosted.bootstrap.organization.create",
  webauthnOptions: "hosted.bootstrap.webauthn.options",
  webauthnVerify: "hosted.bootstrap.webauthn.verify"
});

const ERROR_STATUS = Object.freeze({
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED]: 403,
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.CSRF_FAILED]: 403,
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.SESSION_REQUIRED]: 401,
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.SESSION_EXPIRED]: 401,
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.OAUTH_STATE_INVALID]: 401,
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.SUBJECT_UNVERIFIED]: 401,
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.PROVIDER_UNAVAILABLE]: 503,
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST]: 400,
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.IDEMPOTENCY_REQUIRED]: 400,
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.IDEMPOTENCY_CONFLICT]: 409,
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.ALREADY_COMPLETED]: 409,
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.NO_MEMBERSHIP]: 403,
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.WEBAUTHN_REQUIRED]: 428,
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.WEBAUTHN_INVALID]: 422,
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.WEBAUTHN_REPLAYED]: 409,
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.UNAVAILABLE]: 503
});

const ERROR_MESSAGES = Object.freeze({
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED]: "The request origin is not allowed",
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.CSRF_FAILED]: "The bootstrap CSRF token is invalid",
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.SESSION_REQUIRED]: "A valid bootstrap session is required",
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.SESSION_EXPIRED]: "The bootstrap session has expired",
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.OAUTH_STATE_INVALID]: "The GitHub OAuth attempt is invalid",
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.SUBJECT_UNVERIFIED]: "The GitHub identity could not be verified",
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.PROVIDER_UNAVAILABLE]: "The GitHub provider is temporarily unavailable",
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST]: "The bootstrap request is invalid",
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.IDEMPOTENCY_REQUIRED]: "An Idempotency-Key is required",
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.IDEMPOTENCY_CONFLICT]: "The idempotency key conflicts with an earlier request",
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.ALREADY_COMPLETED]: "Bootstrap has already completed",
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.NO_MEMBERSHIP]: "An eligible membership is required",
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.WEBAUTHN_REQUIRED]: "WebAuthn registration is required",
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.WEBAUTHN_INVALID]: "The WebAuthn registration is invalid",
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.WEBAUTHN_REPLAYED]: "The WebAuthn registration has already been used",
  [HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.UNAVAILABLE]: "The bootstrap service is temporarily unavailable"
});

const SERVICE_ERROR_CODES = new Set(Object.values(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES));
const FORBIDDEN_HEADERS = new Set([
  "authorization",
  "agentpass-console-user-id",
  "agentpass-member-id",
  "agentpass-role",
  "agentpass-organization-id"
]);

export class HostedBootstrapHttpError extends Error {
  constructor(code, { status = ERROR_STATUS[code] ?? 500, headers = undefined, cause = undefined } = {}) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.UNAVAILABLE]);
    this.name = "HostedBootstrapHttpError";
    this.code = code;
    this.status = status;
    if (headers !== undefined) this.headers = headers;
    void cause;
  }
}

/**
 * Framework-free Hosted bootstrap boundary.
 *
 * The five service arguments are deliberately narrow. The identity service
 * receives a closed provider/subject identity plus server-generated OAuth
 * attempt context after the injected GitHub adapter verifies them; no service
 * receives caller-supplied member, organization, membership, or role.
 * `handle(request)` returns a small response object; `handle(request, res)`
 * also writes a Node ServerResponse-compatible response.
 */
export function createHostedBootstrapHttpApi({
  githubService,
  identityBootstrapService,
  bootstrapService,
  webauthnService,
  rateLimiter,
  origin,
  rpId,
  consoleOnboardingUrl,
  maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
  now = () => Date.now(),
  github,
  identityBootstrap,
  bootstrap,
  webauthn,
  abuseControls
} = {}) {
  githubService ??= github;
  identityBootstrapService ??= identityBootstrap;
  bootstrapService ??= bootstrap;
  webauthnService ??= webauthn;
  rateLimiter ??= abuseControls;
  assertServices({ githubService, bootstrapService, webauthnService, rateLimiter });
  assertIdentityBootstrapService(identityBootstrapService);
  assertOrigin(origin);
  assertRpId(rpId);
  assertHttpsUrl(consoleOnboardingUrl, "consoleOnboardingUrl", { noQueryOrFragment: true });
  if (typeof now !== "function") throw new TypeError("now must be a function");
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1_024 || maxBodyBytes > 1_024 * 1_024) throw new TypeError("maxBodyBytes is invalid");

  async function handle(input, nodeResponse = undefined) {
    const result = await dispatch(input);
    if (nodeResponse !== undefined) writeNodeResponse(nodeResponse, result);
    return result;
  }

  async function dispatch(input) {
    let route;
    try {
      const request = normalizeRequest(input);
      route = resolveRoute(request.url);
      if (route === undefined) return response(404, { error: { code: "not_found", message: "Resource not found" } });
      if (request.method !== route.method) {
        throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 405, headers: { Allow: route.method } });
      }
      assertRouteHeaders(request, route.name, origin);
      assertRouteCookies(request, route.name);
      assertRouteQuery(request.url, route.name);
      if (route.method === "GET") await readNoBody(request, maxBodyBytes);
      if (route.name === "githubStart") return await startGithub(request);
      if (route.name === "githubCallback") return await callbackGithub(request);
      if (route.name === "status") return await readStatus(request);
      const body = await readJsonBody(request, maxBodyBytes, route.name === "organizationCreate" ? ["name"] : route.name === "webauthnVerify" ? ["challenge_id", "credential"] : []);
      if (route.name === "organizationCreate") return await createOrganization(request, body.value, body.raw);
      if (route.name === "webauthnOptions") return await createWebAuthnOptions(request, body.value);
      return await verifyWebAuthn(request, body.value);
    } catch (error) {
      const mapped = mapError(error);
      if (route?.name === "githubCallback") {
        return withSetCookie(mapped, clearCookie(HOSTED_BOOTSTRAP_COOKIE_NAMES.githubState, "Lax"));
      }
      return mapped;
    }
  }

  async function startGithub(request) {
    await admit(HOSTED_BOOTSTRAP_OPERATIONS.githubStart, request);
    const result = await callService(githubService.start, githubService, undefined, HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.PROVIDER_UNAVAILABLE);
    const dto = normalizeGithubStartResult(result, now);
    return response(302, null, {
      Location: dto.authorizationUrl,
      "Set-Cookie": setCookie(HOSTED_BOOTSTRAP_COOKIE_NAMES.githubState, dto.stateCookie, "Lax", dto.maxAge)
    });
  }

  async function callbackGithub(request) {
    await admit(HOSTED_BOOTSTRAP_OPERATIONS.githubCallback, request);
    const query = exactCallbackQuery(request.url);
    const stateCookie = request.cookies[HOSTED_BOOTSTRAP_COOKIE_NAMES.githubState];
    const result = await callService(githubService.callback, githubService, {
      code: query.code,
      state: query.state,
      stateCookie
    }, HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.PROVIDER_UNAVAILABLE);
    const verified = normalizeGithubCallbackResult(result);
    const bootstrapResult = await callService(identityBootstrapService.createBootstrapSession, identityBootstrapService, {
      identity: verified.identity,
      context: verified.context
    }, HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.UNAVAILABLE);
    const dto = normalizeBootstrapSessionResult(bootstrapResult, now);
    return response(303, null, {
      Location: consoleOnboardingUrl,
      "Set-Cookie": [
        clearCookie(HOSTED_BOOTSTRAP_COOKIE_NAMES.githubState, "Lax"),
        setCookie(HOSTED_BOOTSTRAP_COOKIE_NAMES.bootstrap, dto.bootstrapToken, "Strict", dto.maxAge)
      ]
    });
  }

  async function readStatus(request) {
    await admit(HOSTED_BOOTSTRAP_OPERATIONS.status, request);
    const token = request.cookies[HOSTED_BOOTSTRAP_COOKIE_NAMES.bootstrap];
    const result = await callService(bootstrapService.status, bootstrapService, { bootstrap_token: token }, HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.UNAVAILABLE);
    return response(200, normalizeStatusResult(result));
  }

  async function createOrganization(request, body, rawBody) {
    const token = request.cookies[HOSTED_BOOTSTRAP_COOKIE_NAMES.bootstrap];
    const csrfToken = request.headers["agentpass-bootstrap-csrf"];
    const idempotencyKey = request.headers["idempotency-key"];
    await admit(HOSTED_BOOTSTRAP_OPERATIONS.organizationCreate, request);
    await verifyCsrf(token, csrfToken);
    const result = await callService(bootstrapService.createOrganization, bootstrapService, {
      bootstrap_token: token,
      name: body.name,
      idempotency_key: idempotencyKey,
      request_hash: sha256(rawBody)
    }, HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.UNAVAILABLE);
    const dto = normalizeOrganizationResult(result);
    return response(dto.replayed ? 200 : 201, {
      version: 1,
      organization: dto.organization,
      onboarding: { state: "webauthn_required" }
    });
  }

  async function createWebAuthnOptions(request, body) {
    assertEmptyObject(body);
    const token = request.cookies[HOSTED_BOOTSTRAP_COOKIE_NAMES.bootstrap];
    await admit(HOSTED_BOOTSTRAP_OPERATIONS.webauthnOptions, request);
    await verifyCsrf(token, request.headers["agentpass-bootstrap-csrf"]);
    const result = await callService(webauthnService.options, webauthnService, {
      bootstrap_token: token,
      rp_id: rpId,
      origin,
      user_verification: "required"
    }, HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.UNAVAILABLE);
    return response(200, normalizeOptionsResult(result, rpId));
  }

  async function verifyWebAuthn(request, body) {
    const parsed = parseVerifyBody(body);
    const token = request.cookies[HOSTED_BOOTSTRAP_COOKIE_NAMES.bootstrap];
    await admit(HOSTED_BOOTSTRAP_OPERATIONS.webauthnVerify, request);
    await verifyCsrf(token, request.headers["agentpass-bootstrap-csrf"]);
    const result = await callService(webauthnService.verify, webauthnService, {
      bootstrap_token: token,
      challenge_id: parsed.challenge_id,
      credential: parsed.credential,
      rp_id: rpId,
      origin,
      user_verification: "required"
    }, HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.UNAVAILABLE);
    const dto = normalizeVerifyResult(result);
    return response(201, {
      version: 1,
      state: "completed",
      session: dto.session,
      csrf_token: dto.csrf_token
    }, {
      "Set-Cookie": [
        setCookie(HOSTED_BOOTSTRAP_COOKIE_NAMES.session, dto.session_token, "Strict"),
        clearCookie(HOSTED_BOOTSTRAP_COOKIE_NAMES.bootstrap, "Strict")
      ]
    });
  }

  async function verifyCsrf(token, csrfToken) {
    let valid;
    try {
      valid = await bootstrapService.verifyCsrf({ bootstrap_token: token, csrf_token: csrfToken });
    } catch (error) {
      if (error?.code === HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.CSRF_FAILED) throw error;
      throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.UNAVAILABLE, { cause: error });
    }
    if (valid !== true && valid?.valid !== true) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.CSRF_FAILED);
  }

  async function admit(operation, request) {
    let decision;
    try {
      decision = await rateLimiter.authorize({ operation, method: request.method, path: request.path });
    } catch (error) {
      throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.UNAVAILABLE, { cause: error });
    }
    if (decision?.allowed !== true) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.UNAVAILABLE);
  }

  return Object.freeze({
    handle,
    paths: HOSTED_BOOTSTRAP_HTTP_PATHS,
    cookies: HOSTED_BOOTSTRAP_COOKIE_NAMES,
    expectedOrigin: origin,
    rpId
  });
}

function assertServices({ githubService, bootstrapService, webauthnService, rateLimiter }) {
  if (!githubService || typeof githubService.start !== "function" || typeof githubService.callback !== "function") throw new TypeError("githubService must expose start() and callback()");
  if (!bootstrapService || typeof bootstrapService.status !== "function" || typeof bootstrapService.verifyCsrf !== "function" || typeof bootstrapService.createOrganization !== "function") throw new TypeError("bootstrapService must expose status(), verifyCsrf(), and createOrganization()");
  if (!webauthnService || typeof webauthnService.options !== "function" || typeof webauthnService.verify !== "function") throw new TypeError("webauthnService must expose options() and verify()");
  if (!rateLimiter || typeof rateLimiter.authorize !== "function") throw new TypeError("rateLimiter must expose authorize()");
}

function assertIdentityBootstrapService(service) {
  if (!service || typeof service.createBootstrapSession !== "function") throw new TypeError("identityBootstrapService must expose createBootstrapSession()");
}

function assertOrigin(value) {
  if (typeof value !== "string" || CONTROL_CHARACTERS.test(value)) throw new TypeError("origin is invalid");
  const parsed = new URL(value);
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash || parsed.origin !== value) throw new TypeError("origin is invalid");
}

function assertRpId(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 253 || !/^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/u.test(value)) throw new TypeError("rpId is invalid");
}

function assertHttpsUrl(value, name, { noQueryOrFragment = false } = {}) {
  if (typeof value !== "string" || value.length > MAX_URL_BYTES || CONTROL_CHARACTERS.test(value)) throw new TypeError(`${name} is invalid`);
  const parsed = new URL(value);
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.href !== value || (noQueryOrFragment && (parsed.search || parsed.hash))) throw new TypeError(`${name} is invalid`);
}

function normalizeRequest(input) {
  if (!input || typeof input !== "object") throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
  const method = input.method;
  const rawUrl = input.url ?? input.originalUrl ?? input.path;
  if (typeof method !== "string" || !/^[A-Z]+$/u.test(method) || typeof rawUrl !== "string" || rawUrl.length < 1 || rawUrl.length > MAX_URL_BYTES || !rawUrl.startsWith("/")) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
  return { input, method, url: rawUrl, path: rawUrl.split(/[?#]/u)[0], headers: normalizeHeaders(input.headers ?? {}), body: input.body };
}

function resolveRoute(rawUrl) {
  let parsed;
  try { parsed = new URL(rawUrl, "https://agentpass.invalid"); } catch { return undefined; }
  if (parsed.hash) return undefined;
  const entries = [
    ["githubStart", "GET", HOSTED_BOOTSTRAP_HTTP_PATHS.githubStart],
    ["githubCallback", "GET", HOSTED_BOOTSTRAP_HTTP_PATHS.githubCallback],
    ["status", "GET", HOSTED_BOOTSTRAP_HTTP_PATHS.status],
    ["organizationCreate", "POST", HOSTED_BOOTSTRAP_HTTP_PATHS.organizationCreate],
    ["webauthnOptions", "POST", HOSTED_BOOTSTRAP_HTTP_PATHS.webauthnOptions],
    ["webauthnVerify", "POST", HOSTED_BOOTSTRAP_HTTP_PATHS.webauthnVerify]
  ];
  const match = entries.find(([, , path]) => path === parsed.pathname);
  if (!match) return undefined;
  return Object.freeze({ name: match[0], method: match[1], path: match[2] });
}

function exactCallbackQuery(rawUrl) {
  const parsed = new URL(rawUrl, "https://agentpass.invalid");
  const codeValues = parsed.searchParams.getAll("code");
  const stateValues = parsed.searchParams.getAll("state");
  if (codeValues.length !== 1 || stateValues.length !== 1 || !isQueryValue(codeValues[0]) || !isQueryValue(stateValues[0])) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.OAUTH_STATE_INVALID);
  return { code: codeValues[0], state: stateValues[0] };
}

function hasExactCallbackKeys(searchParams) {
  const keys = [...searchParams.keys()];
  return keys.length === 2 && keys.includes("code") && keys.includes("state") && searchParams.getAll("code").length === 1 && searchParams.getAll("state").length === 1 && isQueryValue(searchParams.get("code")) && isQueryValue(searchParams.get("state"));
}

function isQueryValue(value) {
  return typeof value === "string" && value.length > 0 && value.length <= MAX_QUERY_VALUE_BYTES && !CONTROL_CHARACTERS.test(value);
}

function assertRouteQuery(rawUrl, route) {
  const parsed = new URL(rawUrl, "https://agentpass.invalid");
  if (route === "githubCallback") {
    if (!hasExactCallbackKeys(parsed.searchParams)) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.OAUTH_STATE_INVALID);
    return;
  }
  if (parsed.search) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
}

function assertRouteHeaders(request, route, expectedOrigin) {
  const headers = request.headers;
  for (const name of FORBIDDEN_HEADERS) if (Object.hasOwn(headers, name)) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
  if (route === "status" || route === "organizationCreate" || route === "webauthnOptions" || route === "webauthnVerify") {
    if (headers.origin === undefined || headers.origin !== expectedOrigin) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED);
  }
  if (route === "organizationCreate" || route === "webauthnOptions" || route === "webauthnVerify") {
    if (headers["agentpass-bootstrap-csrf"] === undefined) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.CSRF_FAILED);
    if (headers["content-type"] !== "application/json") throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
  }
  if (route === "organizationCreate") {
    if (headers["idempotency-key"] === undefined) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.IDEMPOTENCY_REQUIRED);
    if (!IDEMPOTENCY_KEY.test(headers["idempotency-key"])) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
  }
  if (route === "githubStart" || route === "githubCallback" || route === "status") {
    if (headers["content-type"] !== undefined || headers["content-length"] !== undefined && headers["content-length"] !== "0") {
      if (headers["content-type"] !== undefined || headers["content-length"] !== "0") throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
    }
  }
}

function assertRouteCookies(request, route) {
  const cookies = parseCookies(request.headers.cookie);
  const allowed = route === "githubStart" ? [] : route === "githubCallback" ? [HOSTED_BOOTSTRAP_COOKIE_NAMES.githubState] : [HOSTED_BOOTSTRAP_COOKIE_NAMES.bootstrap];
  for (const name of Object.keys(cookies)) if (!allowed.includes(name)) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
  if (route === "githubCallback" && cookies[HOSTED_BOOTSTRAP_COOKIE_NAMES.githubState] === undefined) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.OAUTH_STATE_INVALID);
  if (route !== "githubStart" && route !== "githubCallback" && cookies[HOSTED_BOOTSTRAP_COOKIE_NAMES.bootstrap] === undefined) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.SESSION_REQUIRED);
  request.cookies = cookies;
}

function normalizeHeaders(input) {
  const result = Object.create(null);
  const add = (name, value) => {
    if (typeof name !== "string" || typeof value !== "string" || name.length < 1 || name.length > 256 || CONTROL_CHARACTERS.test(name) || value.length > MAX_HEADER_BYTES || CONTROL_CHARACTERS.test(value)) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
    const normalized = name.toLowerCase();
    if (Object.hasOwn(result, normalized)) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
    result[normalized] = value;
  };
  if (input && typeof input.forEach === "function") input.forEach((value, name) => add(name, value));
  else if (Array.isArray(input)) {
    if (input.length % 2 !== 0) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
    for (let index = 0; index < input.length; index += 2) add(input[index], input[index + 1]);
  } else if (input && typeof input === "object") for (const [name, value] of Object.entries(input)) {
    if (Array.isArray(value)) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
    add(name, value);
  } else throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
  return result;
}

function parseCookies(header) {
  if (header === undefined || header === "") return Object.create(null);
  if (typeof header !== "string" || header.length > MAX_COOKIE_BYTES || CONTROL_CHARACTERS.test(header)) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
  const result = Object.create(null);
  for (const part of header.split(";")) {
    const trimmed = part.trim();
    const separator = trimmed.indexOf("=");
    if (separator <= 0) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
    const name = trimmed.slice(0, separator);
    const value = trimmed.slice(separator + 1);
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u.test(name) || value.length < 1 || !COOKIE_TOKEN.test(value)) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
    if (Object.hasOwn(result, name)) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
    result[name] = value;
  }
  return result;
}

async function readJsonBody(request, maxBytes, expectedKeys) {
  const raw = await readRawBody(request, maxBytes, false);
  if (request.headers["content-type"] !== "application/json") throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
  let value;
  try { value = parseJsonNoDuplicateKeys(raw.toString("utf8")); }
  catch (error) { if (error instanceof DuplicateJsonKeyError || error instanceof SyntaxError) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST, { cause: error }); throw error; }
  if (!isObject(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expectedKeys].sort())) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
  return { value, raw };
}

async function readRawBody(request, maxBytes, allowAbsent) {
  const input = request.input;
  assertContentLength(request.headers, maxBytes);
  if (input.body === undefined && typeof input.arrayBuffer !== "function" && typeof input.text !== "function" && !isReadable(input) && !isReadable(input.body)) {
    if (allowAbsent) return Buffer.alloc(0);
    throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
  }
  let raw;
  if (typeof input.arrayBuffer === "function") raw = Buffer.from(await input.arrayBuffer());
  else if (input.body !== undefined && !isReadable(input.body)) raw = input.body;
  else if (typeof input.text === "function") raw = await input.text();
  else if (typeof input.json === "function") throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
  else if (isReadable(input)) raw = await readStream(input, maxBytes);
  else if (isReadable(input.body)) raw = await readStream(input.body, maxBytes);
  else raw = "";
  if (typeof raw === "object" && !Buffer.isBuffer(raw) && !(raw instanceof Uint8Array)) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
  const bytes = Buffer.isBuffer(raw) ? raw : raw instanceof Uint8Array ? Buffer.from(raw) : Buffer.from(String(raw ?? ""), "utf8");
  if (bytes.length === 0 && !allowAbsent) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
  if (bytes.length > maxBytes) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
  return bytes;
}

async function readNoBody(request, maxBytes) {
  const raw = await readRawBody(request, maxBytes, true);
  if (raw.length !== 0) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
}

function assertContentLength(headers, maxBytes) {
  if (headers["content-length"] === undefined) return;
  if (!/^\d+$/u.test(headers["content-length"]) || !Number.isSafeInteger(Number(headers["content-length"]))) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
  if (Number(headers["content-length"]) > maxBytes) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
}

function parseVerifyBody(body) {
  if (!isObject(body) || !UUID_V4.test(body.challenge_id)) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
  let credential;
  try { credential = normalizeBrowserRegistrationCredential(body.credential); }
  catch (error) { throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST, { cause: error }); }
  return { challenge_id: body.challenge_id.toLowerCase(), credential };
}

function assertEmptyObject(value) {
  if (!isObject(value) || Object.keys(value).length !== 0) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST);
}

function normalizeGithubStartResult(value, now) {
  if (!isObject(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(["authorizationUrl", "expiresAt", "state", "stateCookie"].sort()) || typeof value.authorizationUrl !== "string" || typeof value.state !== "string" || value.state !== value.stateCookie || !COOKIE_TOKEN.test(value.stateCookie) || !Number.isSafeInteger(value.expiresAt)) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.PROVIDER_UNAVAILABLE);
  const url = new URL(value.authorizationUrl);
  const allowedQuery = ["client_id", "response_type", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method"];
  if (url.protocol !== "https:" || url.username || url.password || url.hash || JSON.stringify([...url.searchParams.keys()]) !== JSON.stringify(allowedQuery) || url.searchParams.get("state") !== value.state || url.searchParams.get("code_challenge_method") !== "S256") throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.PROVIDER_UNAVAILABLE);
  const maxAge = Math.ceil((value.expiresAt - now()) / 1_000);
  if (!Number.isSafeInteger(maxAge) || maxAge < 1 || maxAge > 600) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.PROVIDER_UNAVAILABLE);
  return { authorizationUrl: value.authorizationUrl, stateCookie: value.stateCookie, maxAge };
}

function normalizeGithubCallbackResult(value) {
  if (!isObject(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(["context", "identity"])
    || !isObject(value.identity) || JSON.stringify(Object.keys(value.identity).sort()) !== JSON.stringify(["provider", "subject"])
    || value.identity.provider !== "github" || typeof value.identity.subject !== "string" || !/^\d{1,20}$/u.test(value.identity.subject) || value.identity.subject === "0"
    || !isObject(value.context) || JSON.stringify(Object.keys(value.context).sort()) !== JSON.stringify(["attempt_id", "oauth_state_id"])
    || !UUID_V4.test(value.context.attempt_id) || !UUID_V4.test(value.context.oauth_state_id)) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.SUBJECT_UNVERIFIED);
  return Object.freeze({
    identity: Object.freeze({ provider: "github", subject: value.identity.subject }),
    context: Object.freeze({ attempt_id: value.context.attempt_id.toLowerCase(), oauth_state_id: value.context.oauth_state_id.toLowerCase() })
  });
}

function normalizeBootstrapSessionResult(value, now) {
  if (!isObject(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(["bootstrapToken", "expiresAt"].sort()) || !COOKIE_TOKEN.test(value.bootstrapToken) || !Number.isSafeInteger(value.expiresAt)) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.UNAVAILABLE);
  const maxAge = Math.ceil((value.expiresAt - now()) / 1_000);
  if (!Number.isSafeInteger(maxAge) || maxAge < 1 || maxAge > 900) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.UNAVAILABLE);
  return { bootstrapToken: value.bootstrapToken, maxAge };
}

function normalizeStatusResult(value) {
  const allowed = ["state", "webauthn_required", "can_create_first_organization", "organization_count", "csrf_token", "expires_at"];
  if (!isObject(value) || Object.keys(value).some((key) => !allowed.includes(key)) || !["oauth_started", "identity_verified", "organization_required", "webauthn_required", "ready", "no_membership", "completed", "expired"].includes(value.state) || typeof value.webauthn_required !== "boolean" || typeof value.can_create_first_organization !== "boolean" || !Number.isSafeInteger(value.organization_count) || value.organization_count < 0 || !COOKIE_TOKEN.test(value.csrf_token) || typeof value.expires_at !== "string" || !Number.isFinite(Date.parse(value.expires_at))) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.UNAVAILABLE);
  return { version: 1, state: value.state, webauthn_required: value.webauthn_required, can_create_first_organization: value.can_create_first_organization, organization_count: value.organization_count, csrf_token: value.csrf_token, expires_at: value.expires_at };
}

function normalizeOrganizationResult(value) {
  if (!isObject(value) || Object.keys(value).some((key) => !["organization", "replayed"].includes(key)) || typeof value.replayed !== "boolean" || !isObject(value.organization)) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.UNAVAILABLE);
  const organization = value.organization;
  const keys = ["organization_id", "name", "version", "created_at", "updated_at"];
  if (Object.keys(organization).some((key) => !keys.includes(key)) || typeof organization.organization_id !== "string" || !UUID_V4.test(organization.organization_id) || typeof organization.name !== "string" || organization.name.length < 1 || organization.name.length > 128 || CONTROL_CHARACTERS.test(organization.name) || !Number.isSafeInteger(organization.version) || organization.version < 1 || !isTimestamp(organization.created_at) || !isTimestamp(organization.updated_at)) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.UNAVAILABLE);
  return { replayed: value.replayed, organization: { organization_id: organization.organization_id.toLowerCase(), name: organization.name, version: organization.version, created_at: organization.created_at, updated_at: organization.updated_at } };
}

function normalizeOptionsResult(value, expectedRpId) {
  if (!isObject(value) || Object.keys(value).some((key) => !["challenge_id", "options"].includes(key)) || !UUID_V4.test(value.challenge_id) || !isObject(value.options)) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.UNAVAILABLE);
  const options = value.options;
  const allowed = new Set(["challenge", "rp", "user", "pubKeyCredParams", "timeout", "attestation", "excludeCredentials", "authenticatorSelection", "extensions", "hints"]);
  if (Object.keys(options).some((key) => !allowed.has(key)) || typeof options.challenge !== "string" || !BASE64URL.test(options.challenge) || !isObject(options.rp) || options.rp.id !== expectedRpId || typeof options.rp.id !== "string" || !isObject(options.user) || !Array.isArray(options.pubKeyCredParams) || options.pubKeyCredParams.length < 1 || !isObject(options.authenticatorSelection) || options.authenticatorSelection.userVerification !== "required") throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.UNAVAILABLE);
  return { challenge_id: value.challenge_id.toLowerCase(), options };
}

function normalizeVerifyResult(value) {
  if (!isObject(value) || Object.keys(value).some((key) => !["session_token", "csrf_token", "session"].includes(key)) || !COOKIE_TOKEN.test(value.session_token) || !COOKIE_TOKEN.test(value.csrf_token) || !isPublicSession(value.session)) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.UNAVAILABLE);
  return value;
}

function isPublicSession(value) {
  if (!isObject(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(["created_at", "expires_at", "member_id", "organization_id", "recent_auth_at", "role", "session_id", "version"].sort())) return false;
  return value.version === 1 && UUID_V4.test(value.session_id) && UUID_V4.test(value.member_id) && UUID_V4.test(value.organization_id) && ["owner", "admin", "auditor", "viewer"].includes(value.role) && isTimestamp(value.created_at) && isTimestamp(value.expires_at) && (value.recent_auth_at === null || isTimestamp(value.recent_auth_at));
}

function isTimestamp(value) {
  return typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) && Number.isFinite(Date.parse(value));
}

async function callService(method, receiver, input, fallbackCode) {
  try { return await method.call(receiver, input); }
  catch (error) { throw mapServiceError(error, fallbackCode); }
}

function mapServiceError(error, fallbackCode) {
  if (error instanceof HostedBootstrapHttpError) return error;
  const code = error?.code;
  if (SERVICE_ERROR_CODES.has(code)) return new HostedBootstrapHttpError(code, { cause: error });
  if (code === "github_oauth_state_invalid" || code === "oauth_state_invalid" || code === "state_invalid") return new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.OAUTH_STATE_INVALID, { cause: error });
  if (code === "github_subject_unverified" || code === "subject_unverified") return new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.SUBJECT_UNVERIFIED, { cause: error });
  if (code === "bootstrap_session_expired" || code === "session_expired") return new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.SESSION_EXPIRED, { cause: error });
  if (code === "bootstrap_session_required" || code === "session_required") return new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.SESSION_REQUIRED, { cause: error });
  if (code === "bootstrap_csrf_failed" || code === "csrf_failed") return new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.CSRF_FAILED, { cause: error });
  if (code === "bootstrap_webauthn_replayed" || code === "challenge_replayed") return new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.WEBAUTHN_REPLAYED, { cause: error });
  if (code === "bootstrap_webauthn_invalid" || code === "verification_failed" || code === "webauthn_registration_invalid_request" || code === "webauthn_registration_invalid_context" || code === "webauthn_registration_invalid_response" || code === "webauthn_registration_challenge_not_found" || code === "webauthn_registration_challenge_expired" || code === "webauthn_registration_challenge_mismatch" || code === "webauthn_registration_binding_mismatch" || code === "webauthn_registration_verification_failed" || code === "webauthn_registration_invalid_verifier_result") return new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.WEBAUTHN_INVALID, { cause: error });
  if (code === "webauthn_registration_challenge_replayed" || code === "webauthn_registration_challenge_busy") return new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.WEBAUTHN_REPLAYED, { cause: error });
  return new HostedBootstrapHttpError(fallbackCode, { cause: error });
}

function mapError(error) {
  const mapped = error instanceof HostedBootstrapHttpError ? error : new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.UNAVAILABLE, { cause: error });
  return response(mapped.status, { error: { code: mapped.code, message: ERROR_MESSAGES[mapped.code] ?? ERROR_MESSAGES[HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.UNAVAILABLE] } }, mapped.headers);
}

function response(status, body, extraHeaders = undefined) {
  const headers = {
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    ...(body === null ? {} : { "Content-Type": "application/json; charset=utf-8" }),
    ...(status === 405 ? { Allow: "GET, POST" } : {}),
    ...(extraHeaders ?? {})
  };
  const json = body === null ? "" : JSON.stringify(body);
  return Object.freeze({ status, ok: status >= 200 && status < 300, headers: Object.freeze(headers), body, text: async () => json, json: async () => body, toResponse: () => new Response(json, { status, headers }) });
}

function withSetCookie(result, cookie) {
  return response(result.status, result.body, { ...result.headers, "Set-Cookie": result.headers["Set-Cookie"] === undefined ? cookie : [result.headers["Set-Cookie"], cookie] });
}

function setCookie(name, value, sameSite, maxAge = undefined) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=${sameSite}${maxAge === undefined ? "" : `; Max-Age=${maxAge}`}`;
}

function clearCookie(name, sameSite) { return setCookie(name, "", sameSite, 0); }

function writeNodeResponse(target, result) {
  if (!target || typeof target.end !== "function") throw new TypeError("nodeResponse is invalid");
  if (typeof target.writeHead === "function") target.writeHead(result.status, result.headers);
  else if (typeof target.setHeader === "function") for (const [name, value] of Object.entries(result.headers)) target.setHeader(name, value);
  target.statusCode = result.status;
  if (result.headers.Location !== undefined && typeof target.setHeader === "function" && typeof target.writeHead !== "function") target.setHeader("Location", result.headers.Location);
  target.end(result.body === null ? "" : JSON.stringify(result.body));
}

function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }

function isObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }

function isReadable(value) {
  return value !== null && typeof value === "object" && typeof value[Symbol.asyncIterator] === "function";
}

async function readStream(stream, maxBytes) {
  const chunks = [];
  let total = 0;
  for await (const chunk of stream) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : chunk instanceof Uint8Array ? Buffer.from(chunk) : Buffer.from(String(chunk), "utf8");
    total += bytes.length;
    if (total > maxBytes) throw new HostedBootstrapHttpError(HOSTED_BOOTSTRAP_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

export default createHostedBootstrapHttpApi;
