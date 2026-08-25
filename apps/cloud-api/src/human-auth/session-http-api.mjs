import {
  HUMAN_SESSION_ERROR_CODES,
  isOpaqueToken,
  parseSessionCookie,
} from "../human-session.mjs";
import {
  HUMAN_AUTH_ABUSE_ERROR_CODES,
  HUMAN_AUTH_RATE_LIMIT_OPERATIONS,
  HumanAuthAbuseControlError
} from "./rate-limit.mjs";

const SESSION_PATH = "/session";
const SESSION_RESUME_PATH = "/session/resume";
const SESSION_ORGANIZATION_SWITCH_PATH = "/session/organization-switch";
const DEFAULT_MAX_BODY_BYTES = 16 * 1024;
const MAX_HEADER_BYTES = 8 * 1024;
const MAX_URL_LENGTH = 8 * 1024;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;
const TOKEN_HEADER = /^[^\r\n]+$/;
const UUID_VALUE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const CLEAR_SESSION_COOKIE = "__Host-agentpass_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
const FORBIDDEN_RESUME_HEADERS = new Set([
  "authorization",
  "agentpass-csrf",
  "agentpass-csrf-token",
  "csrf-token",
  "x-csrf-token",
  "x-xsrf-token",
  "idempotency-key",
  "agentpass-recent-auth",
  "agentpass-console-identity",
  "agentpass-console-user-id",
  "agentpass-member-id",
  "agentpass-role",
  "agentpass-organization-id",
  "agentpass-agent-id",
  "x-agentpass-identity",
  "x-agentpass-principal-id",
  "x-agentpass-member-id",
  "x-agentpass-organization-id",
  "x-agentpass-agent-id",
  "x-agentpass-assignment-id",
  "x-agentpass-authority-generation",
  "x-user-id",
  "x-member-id",
  "x-organization-id",
  "x-role",
  "x-authority",
  "x-identity",
  "x-principal-id"
]);

export const HUMAN_SESSION_HTTP_PATHS = Object.freeze({
  session: SESSION_PATH,
  resume: SESSION_RESUME_PATH,
  switchOrganization: SESSION_ORGANIZATION_SWITCH_PATH
});

export const HUMAN_SESSION_HTTP_ERROR_CODES = Object.freeze({
  INVALID_REQUEST: "human_session_invalid_request",
  METHOD_NOT_ALLOWED: "human_session_method_not_allowed",
  ORIGIN_NOT_ALLOWED: "human_session_origin_not_allowed",
  SESSION_REQUIRED: "human_session_session_required",
  CSRF_FAILED: "human_session_csrf_failed",
  IDENTITY_VERIFICATION_FAILED: "human_session_identity_verification_failed",
  IDENTITY_REPLAY: "human_session_identity_replay",
  SESSION_UNAVAILABLE: "human_session_unavailable",
  INTERNAL_ERROR: "human_session_internal_error"
});

const ERROR_MESSAGES = Object.freeze({
  [HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST]: "The session request is invalid",
  [HUMAN_SESSION_HTTP_ERROR_CODES.METHOD_NOT_ALLOWED]: "Only POST or DELETE is allowed",
  [HUMAN_SESSION_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED]: "The request origin is not allowed",
  [HUMAN_SESSION_HTTP_ERROR_CODES.SESSION_REQUIRED]: "A valid human session is required",
  [HUMAN_SESSION_HTTP_ERROR_CODES.CSRF_FAILED]: "The CSRF token is invalid",
  [HUMAN_SESSION_HTTP_ERROR_CODES.IDENTITY_VERIFICATION_FAILED]: "The identity request could not be verified",
  [HUMAN_SESSION_HTTP_ERROR_CODES.IDENTITY_REPLAY]: "The identity request was already consumed",
  [HUMAN_SESSION_HTTP_ERROR_CODES.SESSION_UNAVAILABLE]: "The session service is unavailable",
  [HUMAN_SESSION_HTTP_ERROR_CODES.INTERNAL_ERROR]: "The request could not be completed"
});

const ERROR_STATUS = Object.freeze({
  [HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST]: 400,
  [HUMAN_SESSION_HTTP_ERROR_CODES.METHOD_NOT_ALLOWED]: 405,
  [HUMAN_SESSION_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED]: 403,
  [HUMAN_SESSION_HTTP_ERROR_CODES.SESSION_REQUIRED]: 401,
  [HUMAN_SESSION_HTTP_ERROR_CODES.CSRF_FAILED]: 403,
  [HUMAN_SESSION_HTTP_ERROR_CODES.IDENTITY_VERIFICATION_FAILED]: 401,
  [HUMAN_SESSION_HTTP_ERROR_CODES.IDENTITY_REPLAY]: 409,
  [HUMAN_SESSION_HTTP_ERROR_CODES.SESSION_UNAVAILABLE]: 503,
  [HUMAN_SESSION_HTTP_ERROR_CODES.INTERNAL_ERROR]: 500
});

export class HumanSessionHttpError extends Error {
  constructor(code, { status = ERROR_STATUS[code] ?? 500, cause = undefined } = {}) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[HUMAN_SESSION_HTTP_ERROR_CODES.INTERNAL_ERROR], { cause });
    this.name = "HumanSessionHttpError";
    this.code = code;
    this.status = status;
  }
}

/**
 * Framework-free identity-to-session boundary.
 *
 * The identity adapter is deliberately the only provider-specific dependency:
 * it verifies the incoming request and returns an opaque assertion. This
 * boundary never decodes, accepts, or verifies bearer credentials itself.
 *
 * `handle` accepts a Fetch Request, a Request-like object, or a Node-style
 * request (`method`, `url`, `headers`, and `body`). Passing a Node
 * ServerResponse as the second argument writes the same response to it.
 */
export function createHumanSessionHttpApi({
  humanSession,
  verifyIdentityRequest,
  abuseControls,
  origin,
  maxBodyBytes = DEFAULT_MAX_BODY_BYTES
} = {}) {
  if (!humanSession || typeof humanSession.issueSession !== "function") {
    throw new TypeError("humanSession must expose issueSession()");
  }
  if (typeof verifyIdentityRequest !== "function") {
    throw new TypeError("verifyIdentityRequest must be a function");
  }
  if (!abuseControls || typeof abuseControls.checkAnonymousGlobal !== "function") {
    throw new TypeError("abuseControls must expose checkAnonymousGlobal()");
  }

  const expectedOrigin = origin ?? humanSession.expectedOrigin;
  assertOrigin(expectedOrigin);
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 2 || maxBodyBytes > 1024 * 1024) {
    throw new TypeError("maxBodyBytes is invalid");
  }

  async function handle(input, nodeResponse = undefined) {
    const result = await dispatch(input);
    if (nodeResponse !== undefined) writeNodeResponse(nodeResponse, result);
    return result;
  }

  async function dispatch(input) {
    try {
      const request = normalizeRequest(input);
      const resolvedRoute = resolveRoute(request.url);
      if (!resolvedRoute) return response(404, { error: { code: "not_found", message: "Resource not found" } });
      if (!resolvedRoute.methods.includes(request.method)) {
        return response(405, {
          error: {
            code: HUMAN_SESSION_HTTP_ERROR_CODES.METHOD_NOT_ALLOWED,
            message: ERROR_MESSAGES[HUMAN_SESSION_HTTP_ERROR_CODES.METHOD_NOT_ALLOWED]
          }
        }, { Allow: resolvedRoute.methods.join(", ") });
      }

      const requestOrigin = header(request.headers, "origin");
      if (requestOrigin === undefined || requestOrigin !== expectedOrigin) {
        throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED, { status: 403 });
      }

      if (resolvedRoute.kind === "session" && request.method === "DELETE") return await dispatchLogout(request, requestOrigin);
      if (resolvedRoute.kind === "resume") return await dispatchResume(request, requestOrigin);
      if (resolvedRoute.kind === "organization-switch") return await dispatchOrganizationSwitch(request, requestOrigin);

      const body = await readJsonBody(request, maxBodyBytes);
      assertEmptyJsonObject(body);

      try {
        await abuseControls.checkAnonymousGlobal({ operation: HUMAN_AUTH_RATE_LIMIT_OPERATIONS.sessionBootstrap });
      } catch (error) {
        if (error instanceof HumanAuthAbuseControlError) throw error;
        throw new HumanAuthAbuseControlError(HUMAN_AUTH_ABUSE_ERROR_CODES.CONTROL_UNAVAILABLE);
      }

      let identityAssertion;
      try {
        // Deliberately pass the original request so an identity provider can
        // inspect its authenticated transport state without this boundary
        // interpreting provider-specific credentials.
        identityAssertion = await verifyIdentityRequest(request.input);
      } catch (error) {
        if (error?.status === 409) throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.IDENTITY_REPLAY, { status: 409, cause: error });
        if (error?.status === 503) throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.SESSION_UNAVAILABLE, { status: 503, cause: error });
        throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.IDENTITY_VERIFICATION_FAILED, { cause: error });
      }
      if (!isValidOpaqueAssertion(identityAssertion)) {
        throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.IDENTITY_VERIFICATION_FAILED);
      }

      let issued;
      try {
        issued = await humanSession.issueSession({
          identityAssertion,
          origin: requestOrigin
        });
      } catch (error) {
        throw mapSessionError(error);
      }

      return sessionResponse(issued);
    } catch (error) {
      return mapError(error);
    }
  }

  async function dispatchLogout(request, requestOrigin) {
    const cookie = header(request.headers, "cookie");
    if (cookie === undefined) throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.SESSION_REQUIRED, { status: 401 });
    try {
      // Do not turn an absent or malformed cookie into an idempotent local
      // clear. The authenticated logout authority must see a valid session.
      parseSessionCookie(cookie);
    } catch (error) {
      throw mapLogoutError(error);
    }
    const csrfToken = header(request.headers, "agentpass-csrf");
    if (!isOpaqueToken(csrfToken)) throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.CSRF_FAILED, { status: 403 });
    await readNoBody(request);

    let loggedOut;
    try {
      loggedOut = await humanSession.logout({ cookie, origin: requestOrigin, csrfToken });
    } catch (error) {
      throw mapLogoutError(error);
    }
    if (!isObject(loggedOut) || loggedOut.setCookie !== CLEAR_SESSION_COOKIE || loggedOut.clearCookie !== CLEAR_SESSION_COOKIE) {
      throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.SESSION_UNAVAILABLE, { status: 503 });
    }
    return response(200, { session: null }, { "Set-Cookie": CLEAR_SESSION_COOKIE });
  }

  async function dispatchResume(request, requestOrigin) {
    if (typeof humanSession.rotateSession !== "function") {
      throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.SESSION_UNAVAILABLE, { status: 503 });
    }
    assertNoCallerSuppliedResumeHeaders(request.headers);
    const body = await readJsonBody(request, maxBodyBytes);
    assertEmptyJsonObject(body);

    try {
      await abuseControls.checkAnonymousGlobal({ operation: HUMAN_AUTH_RATE_LIMIT_OPERATIONS.sessionBootstrap });
    } catch (error) {
      if (error instanceof HumanAuthAbuseControlError) throw error;
      throw new HumanAuthAbuseControlError(HUMAN_AUTH_ABUSE_ERROR_CODES.CONTROL_UNAVAILABLE);
    }

    const cookie = header(request.headers, "cookie");
    if (cookie === undefined) throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.SESSION_REQUIRED, { status: 401 });
    try {
      // Validate the transport cookie before entering the rotation authority.
      // The service receives the original header so it can atomically revoke
      // exactly the session represented by it.
      parseSessionCookie(cookie);
    } catch (error) {
      throw mapResumeError(error);
    }

    let rotated;
    try {
      // GET is intentional here: the session service authenticates the
      // existing SameSite=Strict cookie without requiring a caller-supplied
      // CSRF token. rotateSession still performs the mutating, atomic
      // old-session revoke/new-session insert in its repository transaction.
      rotated = await humanSession.rotateSession({ method: "GET", cookie, origin: requestOrigin });
    } catch (error) {
      throw mapResumeError(error);
    }
    return sessionResponse(rotated, { requireStrictSessionCookie: true });
  }

  async function dispatchOrganizationSwitch(request, requestOrigin) {
    if (typeof humanSession.switchOrganization !== "function") throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.SESSION_UNAVAILABLE, { status: 503 });
    const cookie = header(request.headers, "cookie");
    const csrfToken = header(request.headers, "agentpass-csrf");
    if (cookie === undefined) throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.SESSION_REQUIRED, { status: 401 });
    if (!isOpaqueToken(csrfToken)) throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.CSRF_FAILED, { status: 403 });
    try { parseSessionCookie(cookie); } catch (error) { throw mapSessionError(error); }
    const body = await readJsonBody(request, maxBodyBytes);
    if (!isObject(body) || Object.keys(body).length !== 1 || typeof body.organization_id !== "string" || !UUID_VALUE.test(body.organization_id)) {
      throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
    }
    let switched;
    try {
      switched = await humanSession.switchOrganization({ organization_id: body.organization_id.toLowerCase(), cookie, csrfToken, origin: requestOrigin });
    } catch (error) {
      throw mapSessionError(error);
    }
    return sessionResponse(switched, { status: 200, requireStrictSessionCookie: true });
  }

  return Object.freeze({
    handle,
    paths: HUMAN_SESSION_HTTP_PATHS,
    expectedOrigin,
    maxBodyBytes
  });
}

function sessionResponse(issued, { status = 201, requireStrictSessionCookie = false } = {}) {
  if (!isObject(issued) || !isObject(issued.session)) {
    throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.SESSION_UNAVAILABLE);
  }
  const csrfToken = issued.csrf_token ?? issued.csrfToken;
  if (!isOpaqueToken(csrfToken)) {
    throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.SESSION_UNAVAILABLE);
  }

  const setCookie = issued.setCookie ?? issued.cookie;
  if (!isSetCookieValue(setCookie) || (requireStrictSessionCookie && !isStrictSessionCookie(setCookie))) {
    throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.SESSION_UNAVAILABLE);
  }

  return response(status, {
    session: issued.session,
    csrf_token: csrfToken
  }, { "Set-Cookie": setCookie });
}

function mapSessionError(error) {
  if (error instanceof HumanAuthAbuseControlError) return error;
  if (error instanceof HumanSessionHttpError) return error;
  if (error?.code === HUMAN_SESSION_ERROR_CODES.INVALID_ORIGIN) {
    return new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED, { status: 403, cause: error });
  }
  if (error?.code === HUMAN_SESSION_ERROR_CODES.IDENTITY_VERIFICATION_FAILED) {
    return new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.IDENTITY_VERIFICATION_FAILED, { status: 401, cause: error });
  }
  if (error?.code === HUMAN_SESSION_ERROR_CODES.IDENTITY_REPLAY) {
    return new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.IDENTITY_REPLAY, { status: 409, cause: error });
  }
  if ([HUMAN_SESSION_ERROR_CODES.INVALID_COOKIE, HUMAN_SESSION_ERROR_CODES.SESSION_NOT_FOUND, HUMAN_SESSION_ERROR_CODES.SESSION_REVOKED, HUMAN_SESSION_ERROR_CODES.SESSION_EXPIRED].includes(error?.code)) {
    return new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.SESSION_REQUIRED, { status: 401, cause: error });
  }
  if (error?.code === HUMAN_SESSION_ERROR_CODES.INVALID_INPUT) {
    return new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400, cause: error });
  }
  if (error?.code === HUMAN_SESSION_ERROR_CODES.INVALID_CONFIGURATION || error?.code === HUMAN_SESSION_ERROR_CODES.REPOSITORY_INVALID) {
    return new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.SESSION_UNAVAILABLE, { status: 503, cause: error });
  }
  return new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INTERNAL_ERROR, { status: 500, cause: error });
}

function mapLogoutError(error) {
  if (error instanceof HumanSessionHttpError) return error;
  if (error?.code === HUMAN_SESSION_ERROR_CODES.INVALID_ORIGIN) {
    return new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED, { status: 403, cause: error });
  }
  if ([
    HUMAN_SESSION_ERROR_CODES.INVALID_COOKIE,
    HUMAN_SESSION_ERROR_CODES.SESSION_NOT_FOUND,
    HUMAN_SESSION_ERROR_CODES.SESSION_REVOKED,
    HUMAN_SESSION_ERROR_CODES.SESSION_EXPIRED
  ].includes(error?.code)) {
    return new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.SESSION_REQUIRED, { status: 401, cause: error });
  }
  if ([HUMAN_SESSION_ERROR_CODES.CSRF_REQUIRED, HUMAN_SESSION_ERROR_CODES.CSRF_INVALID].includes(error?.code)) {
    return new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.CSRF_FAILED, { status: 403, cause: error });
  }
  if ([HUMAN_SESSION_ERROR_CODES.INVALID_CONFIGURATION, HUMAN_SESSION_ERROR_CODES.REPOSITORY_INVALID].includes(error?.code)) {
    return new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.SESSION_UNAVAILABLE, { status: 503, cause: error });
  }
  if (error?.code === HUMAN_SESSION_ERROR_CODES.INVALID_INPUT) {
    return new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400, cause: error });
  }
  return new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INTERNAL_ERROR, { status: 500, cause: error });
}

function mapResumeError(error) {
  if (error instanceof HumanAuthAbuseControlError) return error;
  if (error instanceof HumanSessionHttpError) return error;
  if (error?.code === HUMAN_SESSION_ERROR_CODES.INVALID_ORIGIN) {
    return new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED, { status: 403, cause: error });
  }
  if ([
    HUMAN_SESSION_ERROR_CODES.INVALID_COOKIE,
    HUMAN_SESSION_ERROR_CODES.SESSION_NOT_FOUND,
    HUMAN_SESSION_ERROR_CODES.SESSION_REVOKED,
    HUMAN_SESSION_ERROR_CODES.SESSION_EXPIRED
  ].includes(error?.code)) {
    return new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.SESSION_REQUIRED, { status: 401, cause: error });
  }
  if ([HUMAN_SESSION_ERROR_CODES.INVALID_CONFIGURATION, HUMAN_SESSION_ERROR_CODES.REPOSITORY_INVALID].includes(error?.code)) {
    return new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.SESSION_UNAVAILABLE, { status: 503, cause: error });
  }
  if (error?.code === HUMAN_SESSION_ERROR_CODES.INVALID_INPUT) {
    return new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400, cause: error });
  }
  return new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INTERNAL_ERROR, { status: 500, cause: error });
}

function mapError(error) {
  if (error instanceof HumanAuthAbuseControlError) {
    const code = error.code === HUMAN_AUTH_ABUSE_ERROR_CODES.RATE_LIMITED
      ? HUMAN_AUTH_ABUSE_ERROR_CODES.RATE_LIMITED
      : HUMAN_AUTH_ABUSE_ERROR_CODES.CONTROL_UNAVAILABLE;
    const status = code === HUMAN_AUTH_ABUSE_ERROR_CODES.RATE_LIMITED ? 429 : 503;
    return response(status, { error: { code, message: error.message } }, error.headers);
  }
  if (error instanceof HumanSessionHttpError) {
    return response(error.status, {
      error: {
        code: error.code,
        message: ERROR_MESSAGES[error.code] ?? ERROR_MESSAGES[HUMAN_SESSION_HTTP_ERROR_CODES.INTERNAL_ERROR]
      }
    }, error.status === 405 ? { Allow: "POST, DELETE" } : undefined);
  }
  return response(500, {
    error: {
      code: HUMAN_SESSION_HTTP_ERROR_CODES.INTERNAL_ERROR,
      message: ERROR_MESSAGES[HUMAN_SESSION_HTTP_ERROR_CODES.INTERNAL_ERROR]
    }
  });
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
  if (typeof nodeResponse.writeHead === "function") nodeResponse.writeHead(result.status, result.headers);
  else if (typeof nodeResponse.setHeader === "function") {
    for (const [name, value] of Object.entries(result.headers)) nodeResponse.setHeader(name, value);
  }
  nodeResponse.statusCode = result.status;
  nodeResponse.end(JSON.stringify(result.body));
}

function normalizeRequest(input) {
  if (!input || typeof input !== "object") {
    throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  }
  const method = String(input.method ?? "").toUpperCase();
  const url = String(input.url ?? input.originalUrl ?? input.path ?? "");
  if (!method || !url || url.length > MAX_URL_LENGTH) {
    throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  }
  return Object.freeze({
    input,
    method,
    url,
    headers: normalizeHeaders(input.headers ?? {}),
    body: input.body
  });
}

function resolveRoute(rawUrl) {
  let url;
  try {
    url = new URL(rawUrl, "https://agentpass.invalid");
  } catch {
    return undefined;
  }
  if (url.search || url.hash) return undefined;
  if (url.pathname === SESSION_PATH) return { kind: "session", methods: ["POST", "DELETE"] };
  if (url.pathname === SESSION_RESUME_PATH) return { kind: "resume", methods: ["POST"] };
  if (url.pathname === SESSION_ORGANIZATION_SWITCH_PATH) return { kind: "organization-switch", methods: ["POST"] };
  return undefined;
}

async function readJsonBody(request, maxBytes) {
  const contentType = header(request.headers, "content-type");
  if (typeof contentType !== "string" || !/^application\/json(?:\s*;|$)/i.test(contentType)) {
    throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  }

  const contentLength = header(request.headers, "content-length");
  if (contentLength !== undefined && (!/^\d+$/.test(contentLength) || !Number.isSafeInteger(Number(contentLength)) || Number(contentLength) > maxBytes)) {
    throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
  }

  const input = request.input;
  let raw;
  if (typeof input.arrayBuffer === "function") raw = Buffer.from(await input.arrayBuffer());
  else if (input.body !== undefined && !isReadable(input.body)) raw = input.body;
  else if (typeof input.text === "function") raw = await input.text();
  else if (typeof input.json === "function") {
    try {
      raw = await input.json();
    } catch (error) {
      throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400, cause: error });
    }
  } else if (isReadable(input)) raw = await readStream(input, maxBytes);
  else if (isReadable(input.body)) raw = await readStream(input.body, maxBytes);
  else {
    throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  }

  if ((isObject(raw) && !Buffer.isBuffer(raw) && !(raw instanceof Uint8Array)) || Array.isArray(raw)) {
    assertSerializedSize(raw, maxBytes);
    return raw;
  }

  const bytes = toBytes(raw);
  if (bytes.length > maxBytes) {
    throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
  }
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400, cause: error });
  }
  return value;
}

function assertSerializedSize(value, maxBytes) {
  let serialized;
  try {
    serialized = JSON.stringify(value);
  } catch (error) {
    throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400, cause: error });
  }
  if (typeof serialized !== "string" || Buffer.byteLength(serialized, "utf8") > maxBytes) {
    throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
  }
}

function toBytes(value) {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (typeof value === "string") return Buffer.from(value, "utf8");
  return Buffer.from(String(value ?? ""), "utf8");
}

async function readStream(stream, maxBytes) {
  const chunks = [];
  let total = 0;
  for await (const chunk of stream) {
    const bytes = toBytes(chunk);
    total += bytes.length;
    if (total > maxBytes) throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 413 });
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

function normalizeHeaders(input) {
  const result = {};
  if (input && typeof input.entries === "function") {
    for (const [name, value] of input.entries()) {
      setHeader(result, name, value);
    }
    return result;
  }
  if (input && typeof input.get === "function") {
    const names = new Set(["origin", "content-type", "content-length", "cookie", "agentpass-csrf", ...FORBIDDEN_RESUME_HEADERS]);
    for (const name of names) {
      const value = input.get(name);
      if (value !== null && value !== undefined) setHeader(result, name, value);
    }
    return result;
  }
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  }
  for (const [name, value] of Object.entries(input)) setHeader(result, name, value);
  return result;
}

function setHeader(target, name, value) {
  if (typeof name !== "string" || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || Array.isArray(value) || typeof value === "object" || value === undefined) {
    throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  }
  const normalized = name.toLowerCase();
  if (target[normalized] !== undefined) {
    throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  }
  target[normalized] = String(value);
}

function header(headers, name) {
  const value = headers[name.toLowerCase()];
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length > MAX_HEADER_BYTES || CONTROL_CHARACTERS.test(value)) {
    throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  }
  return value;
}

function assertNoCallerSuppliedResumeHeaders(headers) {
  for (const name of Object.keys(headers)) {
    if (FORBIDDEN_RESUME_HEADERS.has(name)
      || /^agentpass-(?:identity|principal|authority)(?:-|$)/u.test(name)
      || /^x-agentpass-(?:identity|principal|authority)(?:-|$)/u.test(name)) {
      throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
    }
  }
}

function assertEmptyJsonObject(value) {
  if (!isObject(value) || Object.keys(value).length !== 0) {
    throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  }
}

async function readNoBody(request) {
  const input = request.input;
  const contentLength = header(request.headers, "content-length");
  if (contentLength !== undefined && (!/^\d+$/.test(contentLength) || Number(contentLength) !== 0)) {
    throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
  }
  let raw;
  if (typeof input.arrayBuffer === "function") raw = Buffer.from(await input.arrayBuffer());
  else if (input.body !== undefined && !isReadable(input.body)) raw = input.body;
  else if (typeof input.text === "function") raw = await input.text();
  else if (isReadable(input)) raw = await readStream(input, 0);
  else if (isReadable(input.body)) raw = await readStream(input.body, 0);
  else raw = undefined;
  if (raw === undefined) return;
  if (toBytes(raw).length !== 0) throw new HumanSessionHttpError(HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
}

function isValidOpaqueAssertion(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === "string") return value.length > 0 && value.length <= 64 * 1024;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return value.length > 0 && value.length <= 64 * 1024;
  if (typeof value === "object") {
    if (Array.isArray(value)) return value.length > 0;
    try {
      return Object.keys(value).length > 0;
    } catch {
      return false;
    }
  }
  return false;
}

function isSetCookieValue(value) {
  if (Array.isArray(value)) return value.length > 0 && value.every(isSetCookieValue);
  return typeof value === "string" && value.length > 0 && value.length <= MAX_HEADER_BYTES && TOKEN_HEADER.test(value);
}

function isStrictSessionCookie(value) {
  if (typeof value !== "string" || value.includes(",")) return false;
  const parts = value.split(";").map((part) => part.trim());
  if (parts.length < 5 || !/^__Host-agentpass_session=[A-Za-z0-9_-]{43}$/u.test(parts[0])) return false;
  const attributes = new Set(parts.slice(1).map((part) => part.toLowerCase()));
  return attributes.has("path=/")
    && attributes.has("httponly")
    && attributes.has("secure")
    && attributes.has("samesite=strict")
    && !parts.slice(1).some((part) => /^domain=/iu.test(part));
}

function assertOrigin(value) {
  if (typeof value !== "string" || value.length > 512 || CONTROL_CHARACTERS.test(value)) throw new TypeError("origin is invalid");
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError("origin is invalid");
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash || parsed.origin !== value) {
    throw new TypeError("origin is invalid");
  }
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isReadable(value) {
  return value !== null && typeof value === "object" && typeof value[Symbol.asyncIterator] === "function";
}
