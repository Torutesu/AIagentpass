import crypto from "node:crypto";
import http from "node:http";

import { parseEnrollmentInvitation } from "./headless-onboarding.mjs";
import { canonicalJson } from "./identity.mjs";
import { ONBOARDING_INVITATION_DELIVERY_TYPE, parseOnboardingInvitationDeliveryJson } from "./onboarding-contract.mjs";

/**
 * The browser/CLI handoff deliberately has no persistence layer.  A handle
 * owns one in-memory challenge and is destroyed after one successful consume,
 * expiry, abort, or explicit close.
 */
export const BROWSER_CLI_HANDOFF_VERSION = 1;
export const BROWSER_CLI_HANDOFF_PREFLIGHT_VERSION = 1;
export const BROWSER_CLI_HANDOFF_MAX_TTL_MS = 5 * 60 * 1000;
export const BROWSER_CLI_HANDOFF_MAX_BODY_BYTES = 128 * 1024;
export const BROWSER_CLI_HANDOFF_MAX_REQUEST_TIMEOUT_MS = 30 * 1000;

export const BROWSER_CLI_HANDOFF_ERRORS = Object.freeze({
  INVALID_CONFIG: "ERR_BROWSER_CLI_HANDOFF_CONFIG",
  INVALID_PREFLIGHT: "ERR_BROWSER_CLI_HANDOFF_PREFLIGHT",
  INVALID_REQUEST: "ERR_BROWSER_CLI_HANDOFF_REQUEST",
  INVALID_INVITATION: "ERR_BROWSER_CLI_HANDOFF_INVITATION",
  ORIGIN: "ERR_BROWSER_CLI_HANDOFF_ORIGIN",
  HOST: "ERR_BROWSER_CLI_HANDOFF_HOST",
  CONTENT_TYPE: "ERR_BROWSER_CLI_HANDOFF_CONTENT_TYPE",
  BODY_TOO_LARGE: "ERR_BROWSER_CLI_HANDOFF_BODY_TOO_LARGE",
  REQUEST_TIMEOUT: "ERR_BROWSER_CLI_HANDOFF_REQUEST_TIMEOUT",
  TIMEOUT: "ERR_BROWSER_CLI_HANDOFF_TIMEOUT",
  REPLAY: "ERR_BROWSER_CLI_HANDOFF_REPLAY",
  CLOSED: "ERR_BROWSER_CLI_HANDOFF_CLOSED",
  ABORTED: "ERR_BROWSER_CLI_HANDOFF_ABORTED",
  LISTENER: "ERR_BROWSER_CLI_HANDOFF_LISTENER"
});

const METHOD_POST = "POST";
const METHOD_GET = "GET";
const METHOD_OPTIONS = "OPTIONS";
const LOOPBACK_HOST = "127.0.0.1";
const HANDOFF_PATH_PREFIX = "/v1/browser-cli-handoffs/";
const SAFE_TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const CONTROL = /[\u0000-\u001f\u007f]/u;
const PREFLIGHT_KEYS = Object.freeze(["version", "platform", "candidate_id", "device_key_fingerprint"]);
const HANDOFF_KEYS = Object.freeze(["version", "type", "correlation_id", "nonce", "invitation"]);

export class BrowserCliHandoffError extends Error {
  constructor(code, message, { status = undefined, cause = undefined } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "BrowserCliHandoffError";
    this.code = code;
    if (status !== undefined) this.status = status;
  }
}

/**
 * Validate the only public data that crosses from local setup into the
 * browser flow.  It contains no credential, URL, path, or private key.
 */
export function normalizeBrowserCliHandoffPreflight(value = {}) {
  try {
    exactKeys(value, PREFLIGHT_KEYS, "handoff preflight");
    if (value.version !== BROWSER_CLI_HANDOFF_PREFLIGHT_VERSION || value.platform !== "macos") invalidPreflight();
    if (typeof value.candidate_id !== "string" || !SAFE_ID.test(value.candidate_id)) invalidPreflight();
    if (typeof value.device_key_fingerprint !== "string" || !FINGERPRINT.test(value.device_key_fingerprint)) invalidPreflight();
    return Object.freeze({
      version: BROWSER_CLI_HANDOFF_PREFLIGHT_VERSION,
      platform: "macos",
      candidate_id: value.candidate_id,
      device_key_fingerprint: value.device_key_fingerprint
    });
  } catch (error) {
    if (error instanceof BrowserCliHandoffError && error.code === BROWSER_CLI_HANDOFF_ERRORS.INVALID_PREFLIGHT) throw error;
    invalidPreflight();
  }
}

/**
 * Parse and canonicalize a v2 invitation using the shared headless parser.
 * This function additionally binds the candidate and public-key fingerprint
 * to the local public preflight, preventing a browser-side substitution.
 */
export function canonicalizeBrowserCliInvitation(value, preflight) {
  const expected = normalizeBrowserCliHandoffPreflight(preflight);
  let invitation;
  try {
    if (!plainObject(value) || Object.hasOwn(value, "enrollment")) throw new Error("only the canonical invitation object is accepted");
    invitation = parseEnrollmentInvitation(value);
  } catch (error) {
    throw new BrowserCliHandoffError(BROWSER_CLI_HANDOFF_ERRORS.INVALID_INVITATION, "The enrollment invitation is invalid", { status: 422, cause: error });
  }
  if (invitation.candidate_binding.candidate_id !== expected.candidate_id
    || invitation.candidate_binding.device_key_fingerprint !== expected.device_key_fingerprint
    || invitation.platform !== expected.platform) {
    throw new BrowserCliHandoffError(BROWSER_CLI_HANDOFF_ERRORS.INVALID_INVITATION, "The enrollment invitation does not match the local preflight", { status: 422 });
  }
  // The parser returns the exact accepted v2 shape.  Re-encoding it here is
  // the canonical response consumed by the waiting CLI and rejects no hidden
  // fields or alternate aliases at this boundary.
  const canonical = canonicalJson(invitation);
  return Object.freeze({ invitation, canonical_json: canonical });
}

/**
 * Start a same-device handoff listener.  The returned handle is safe for a
 * future CLI adapter:
 *
 *   const handoff = await createBrowserCliHandoff({ allowedOrigins, preflight });
 *   // open handoff.url in the browser, then:
 *   const invitation = await handoff.waitForInvitation();
 *
 * `handoff.url` contains only a random correlation identifier in its path.
 * The nonce is delivered by the no-store public preflight response and the
 * credential-bearing invitation is accepted only in the POST body.
 */
export async function createBrowserCliHandoff(options = {}) {
  const config = normalizeOptions(options);
  const preflight = normalizeBrowserCliHandoffPreflight(config.preflight);
  const correlationId = randomToken();
  const nonce = randomToken();
  const handoffPath = `${HANDOFF_PATH_PREFIX}${correlationId}`;
  const preflightPath = `${handoffPath}/preflight`;
  const server = http.createServer();
  const sockets = new Set();
  let expectedHost;
  let state = "pending";
  let closePromise;
  let timeoutTimer;
  let resolveInvitation;
  let rejectInvitation;
  let abortListener;
  const invitationPromise = new Promise((resolve, reject) => {
    resolveInvitation = resolve;
    rejectInvitation = reject;
  });

  server.requestTimeout = config.requestTimeoutMs;
  server.headersTimeout = Math.min(config.requestTimeoutMs, 10_000);
  server.keepAliveTimeout = 1_000;
  server.maxHeadersCount = 32;
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    // Binding to IPv4 loopback is necessary but not sufficient: validate the
    // peer on every request as well, including test/custom HTTP clients.
    socket.setTimeout(config.requestTimeoutMs);
  });
  server.on("request", (request, response) => {
    void handleRequest(request, response);
  });

  try {
    await listen(server);
    const address = server.address();
    if (!address || typeof address !== "object" || address.address !== LOOPBACK_HOST || !Number.isSafeInteger(address.port) || address.port < 1) {
      throw handoffError(BROWSER_CLI_HANDOFF_ERRORS.LISTENER, "The loopback listener did not bind safely");
    }
    expectedHost = `${LOOPBACK_HOST}:${address.port}`;
    clearTimeout(timeoutTimer);
    timeoutTimer = setTimeout(() => expire(), config.ttlMs);
    timeoutTimer.unref?.();
    if (config.signal) {
      abortListener = () => abort();
      config.signal.addEventListener("abort", abortListener, { once: true });
      if (config.signal.aborted) abort();
    }
  } catch (error) {
    await closeServer();
    if (error instanceof BrowserCliHandoffError) throw error;
    throw new BrowserCliHandoffError(BROWSER_CLI_HANDOFF_ERRORS.LISTENER, "The loopback listener could not be started", { cause: error });
  }

  const handle = Object.freeze({
    version: BROWSER_CLI_HANDOFF_VERSION,
    correlation_id: correlationId,
    url: `http://${expectedHost}${handoffPath}`,
    preflight_url: `http://${expectedHost}${preflightPath}`,
    port: server.address().port,
    getPublicPreflight: () => publicPreflight(),
    waitForInvitation: async () => {
      return invitationPromise;
    },
    close: () => close(BROWSER_CLI_HANDOFF_ERRORS.CLOSED, "The browser/CLI handoff was closed")
  });

  return handle;

  function publicPreflight() {
    return Object.freeze({
      version: BROWSER_CLI_HANDOFF_PREFLIGHT_VERSION,
      correlation_id: correlationId,
      nonce,
      platform: preflight.platform,
      candidate_id: preflight.candidate_id,
      device_key_fingerprint: preflight.device_key_fingerprint
    });
  }

  async function handleRequest(request, response) {
    const origin = request.headers.origin;
    try {
      assertPeer(request);
      assertHeaderMultiplicity(request);
      assertHost(request);
      assertOrigin(origin, config.allowedOrigins);
      const requestUrl = parseRequestUrl(request.url);
      if (requestUrl.pathname !== handoffPath && requestUrl.pathname !== preflightPath) failRequest("unknown handoff path", BROWSER_CLI_HANDOFF_ERRORS.INVALID_REQUEST, 404);
      if (request.method === METHOD_OPTIONS) {
        if (requestUrl.pathname !== preflightPath && requestUrl.pathname !== handoffPath) failRequest("unknown handoff path", BROWSER_CLI_HANDOFF_ERRORS.INVALID_REQUEST, 404);
        const privateNetwork = assertCorsPreflight(request, requestUrl.pathname);
        writeJson(response, 204, null, origin, true, privateNetwork);
        return;
      }
      if (request.method === METHOD_GET && requestUrl.pathname === preflightPath) {
        if (state !== "pending") failRequest("handoff is no longer available", BROWSER_CLI_HANDOFF_ERRORS.REPLAY, 410);
        assertNoBodyHeaders(request);
        writeJson(response, 200, publicPreflight(), origin);
        return;
      }
      if (request.method !== METHOD_POST || requestUrl.pathname !== handoffPath) failRequest("handoff request method is invalid", BROWSER_CLI_HANDOFF_ERRORS.INVALID_REQUEST, 405);
      if (state === "consumed") failRequest("handoff was already consumed", BROWSER_CLI_HANDOFF_ERRORS.REPLAY, 409);
      if (state !== "pending") failRequest("handoff is not available", BROWSER_CLI_HANDOFF_ERRORS.CLOSED, 410);
      assertJsonRequest(request);
      let body;
      try {
        body = await readBoundedBody(request, config.maxBodyBytes, config.requestTimeoutMs, Number(request.headers["content-length"]));
        const parsed = parseHandoffBody(body);
        if (parsed.correlation_id !== correlationId || parsed.nonce !== nonce) failRequest("handoff binding is invalid", BROWSER_CLI_HANDOFF_ERRORS.REPLAY, 409);
        const result = canonicalizeBrowserCliInvitation(parsed.invitation, preflight);
        if (state !== "pending") failRequest("handoff was already consumed", BROWSER_CLI_HANDOFF_ERRORS.REPLAY, 409);
        state = "consumed";
        resolveInvitation(result.invitation);
        writeJson(response, 200, { version: BROWSER_CLI_HANDOFF_VERSION, ok: true, consumed: true }, origin);
        // Stop accepting new connections but let already accepted requests
        // finish so a concurrent replay receives a deterministic 409 instead
        // of being silently reset by teardown.
        void closeServer({ destroySockets: false });
      } finally {
        body?.fill(0);
      }
    } catch (error) {
      if (response.headersSent || response.destroyed) return;
      const mapped = mapRequestError(error);
      // Never reflect an unapproved Origin in an error response.  A browser
      // cannot read this response unless its exact Origin is allowlisted.
      const responseOrigin = config.allowedOrigins.includes(origin) ? origin : undefined;
      writeJson(response, mapped.status, { version: BROWSER_CLI_HANDOFF_VERSION, ok: false, error: { code: mapped.code } }, responseOrigin);
      if (mapped.close) response.shouldKeepAlive = false;
    }
  }

  function assertPeer(request) {
    const socket = request.socket;
    if (!socket || socket.remoteAddress !== LOOPBACK_HOST || socket.remoteFamily !== "IPv4") {
      failRequest("non-loopback peer", BROWSER_CLI_HANDOFF_ERRORS.HOST, 403);
    }
  }

  function assertHost(request) {
    const host = request.headers.host;
    if (typeof host !== "string" || host !== expectedHost) failRequest("host is not the bound loopback host", BROWSER_CLI_HANDOFF_ERRORS.HOST, 400);
  }

  function assertHeaderMultiplicity(request) {
    const counts = new Map();
    for (let index = 0; index < request.rawHeaders.length; index += 2) {
      const name = request.rawHeaders[index].toLowerCase();
      if (["host", "origin", "content-type", "content-length", "transfer-encoding", "access-control-request-method", "access-control-request-headers", "access-control-request-private-network"].includes(name)) counts.set(name, (counts.get(name) ?? 0) + 1);
    }
    for (const [name, count] of counts) if (count !== 1) {
      const code = name === "origin" ? BROWSER_CLI_HANDOFF_ERRORS.ORIGIN : name === "host" ? BROWSER_CLI_HANDOFF_ERRORS.HOST : BROWSER_CLI_HANDOFF_ERRORS.INVALID_REQUEST;
      failRequest("duplicate security-sensitive header", code, 400);
    }
  }

  function assertOrigin(originValue, allowedOrigins) {
    if (typeof originValue !== "string" || !allowedOrigins.includes(originValue)) failRequest("origin is not allowed", BROWSER_CLI_HANDOFF_ERRORS.ORIGIN, 403);
  }

  function parseRequestUrl(raw) {
    if (typeof raw !== "string" || raw.length > 2048 || raw.includes("#")) failRequest("request URL is invalid", BROWSER_CLI_HANDOFF_ERRORS.INVALID_REQUEST, 400);
    let parsed;
    try { parsed = new URL(raw, `http://${expectedHost}`); } catch { failRequest("request URL is invalid", BROWSER_CLI_HANDOFF_ERRORS.INVALID_REQUEST, 400); }
    if (parsed.origin !== `http://${expectedHost}` || parsed.search) failRequest("query parameters are not accepted", BROWSER_CLI_HANDOFF_ERRORS.INVALID_REQUEST, 400);
    return parsed;
  }

  function assertCorsPreflight(request, pathname) {
    const requestedMethod = request.headers["access-control-request-method"];
    const expectedMethod = pathname === preflightPath ? METHOD_GET : METHOD_POST;
    if (requestedMethod !== expectedMethod) failRequest("CORS method is invalid", BROWSER_CLI_HANDOFF_ERRORS.INVALID_REQUEST, 400);
    const requestedHeaders = request.headers["access-control-request-headers"];
    const normalizedHeaders = typeof requestedHeaders === "string" ? requestedHeaders.split(",").map((value) => value.trim().toLowerCase()).filter(Boolean).join(",") : "";
    if ((requestedMethod === METHOD_POST && normalizedHeaders !== "content-type") || (requestedMethod === METHOD_GET && normalizedHeaders !== "")) {
      failRequest("CORS headers are invalid", BROWSER_CLI_HANDOFF_ERRORS.INVALID_REQUEST, 400);
    }
    const privateNetwork = request.headers["access-control-request-private-network"];
    if (privateNetwork !== undefined && privateNetwork !== "true") failRequest("private network preflight is invalid", BROWSER_CLI_HANDOFF_ERRORS.INVALID_REQUEST, 400);
    assertNoBodyHeaders(request);
    return privateNetwork === "true";
  }

  function assertNoBodyHeaders(request) {
    const length = request.headers["content-length"];
    const transferEncoding = request.headers["transfer-encoding"];
    if ((length !== undefined && length !== "0") || transferEncoding !== undefined) failRequest("request body is not allowed", BROWSER_CLI_HANDOFF_ERRORS.INVALID_REQUEST, 400);
  }

  function assertJsonRequest(request) {
    if (request.headers["content-type"] !== "application/json") failRequest("content type must be application/json", BROWSER_CLI_HANDOFF_ERRORS.CONTENT_TYPE, 415);
    if (request.headers["transfer-encoding"] !== undefined) failRequest("chunked request bodies are not accepted", BROWSER_CLI_HANDOFF_ERRORS.INVALID_REQUEST, 400);
    const length = request.headers["content-length"];
    if (typeof length !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(length) || Number(length) < 1 || Number(length) > config.maxBodyBytes) {
      if (typeof length === "string" && Number.isFinite(Number(length)) && Number(length) > config.maxBodyBytes) failRequest("request body is too large", BROWSER_CLI_HANDOFF_ERRORS.BODY_TOO_LARGE, 413);
      failRequest("content length is invalid", BROWSER_CLI_HANDOFF_ERRORS.INVALID_REQUEST, 400);
    }
  }

  function parseHandoffBody(bytes) {
    let value;
    try {
      value = parseOnboardingInvitationDeliveryJson(bytes);
    } catch (error) {
      const invitationError = Array.isArray(error?.issues) && error.issues.length > 0 && error.issues.every((item) => {
        const path = String(item.path);
        return path === "onboarding_invitation_delivery.invitation"
          || path.startsWith("onboarding_invitation_delivery.onboarding_invitation.")
          || path === "onboarding_invitation_delivery_v1.invitation"
          || path.startsWith("onboarding_invitation_delivery_v1.invitation.");
      });
      failRequest(invitationError ? "handoff invitation is invalid" : "request body JSON is invalid", invitationError ? BROWSER_CLI_HANDOFF_ERRORS.INVALID_INVITATION : BROWSER_CLI_HANDOFF_ERRORS.INVALID_REQUEST, invitationError ? 422 : 400);
    }
    exactKeys(value, HANDOFF_KEYS, "handoff request");
    if (value.version !== BROWSER_CLI_HANDOFF_VERSION || value.type !== ONBOARDING_INVITATION_DELIVERY_TYPE || typeof value.correlation_id !== "string" || !SAFE_TOKEN.test(value.correlation_id) || typeof value.nonce !== "string" || !SAFE_TOKEN.test(value.nonce)) {
      failRequest("handoff request binding is invalid", BROWSER_CLI_HANDOFF_ERRORS.INVALID_REQUEST, 400);
    }
    if (value.invitation === null || typeof value.invitation !== "object" || Array.isArray(value.invitation)) failRequest("handoff invitation is invalid", BROWSER_CLI_HANDOFF_ERRORS.INVALID_INVITATION, 422);
    return value;
  }

  function expire() {
    if (state !== "pending") return;
    state = "expired";
    rejectInvitation(handoffError(BROWSER_CLI_HANDOFF_ERRORS.TIMEOUT, "The browser/CLI handoff expired"));
    void closeServer();
  }

  function abort() {
    if (state !== "pending") return;
    state = "aborted";
    rejectInvitation(handoffError(BROWSER_CLI_HANDOFF_ERRORS.ABORTED, "The browser/CLI handoff was interrupted"));
    void closeServer();
  }

  function close(code, message) {
    if (state === "pending") {
      state = "closed";
      rejectInvitation(handoffError(code, message));
    }
    return closeServer();
  }

  async function closeServer({ destroySockets = true } = {}) {
    if (closePromise) return closePromise;
    clearTimeout(timeoutTimer);
    if (config.signal && abortListener) config.signal.removeEventListener("abort", abortListener);
    if (destroySockets) for (const socket of sockets) socket.destroy();
    closePromise = new Promise((resolve) => {
      if (!server.listening) { resolve(); return; }
      server.close(() => resolve());
    });
    return closePromise;
  }
}

function normalizeOptions(options) {
  if (!plainObject(options)) throw handoffError(BROWSER_CLI_HANDOFF_ERRORS.INVALID_CONFIG, "handoff options must be an object");
  const allowed = new Set(["allowedOrigins", "origin", "preflight", "ttlMs", "maxBodyBytes", "requestTimeoutMs", "signal"]);
  if (Object.keys(options).some((key) => !allowed.has(key))) throw handoffError(BROWSER_CLI_HANDOFF_ERRORS.INVALID_CONFIG, "handoff options contain unknown fields");
  const origins = options.allowedOrigins ?? (options.origin === undefined ? undefined : [options.origin]);
  if (!Array.isArray(origins) || origins.length < 1 || origins.length > 8 || origins.some((origin) => !validOrigin(origin)) || new Set(origins).size !== origins.length) {
    throw handoffError(BROWSER_CLI_HANDOFF_ERRORS.INVALID_CONFIG, "handoff Origin allowlist is invalid");
  }
  const ttlMs = boundedInteger(options.ttlMs ?? 120_000, 1_000, BROWSER_CLI_HANDOFF_MAX_TTL_MS, "handoff TTL");
  const maxBodyBytes = boundedInteger(options.maxBodyBytes ?? 64 * 1024, 1, BROWSER_CLI_HANDOFF_MAX_BODY_BYTES, "handoff body limit");
  const requestTimeoutMs = boundedInteger(options.requestTimeoutMs ?? 5_000, 100, BROWSER_CLI_HANDOFF_MAX_REQUEST_TIMEOUT_MS, "handoff request timeout");
  if (options.signal !== undefined && (typeof options.signal !== "object" || typeof options.signal.addEventListener !== "function")) throw handoffError(BROWSER_CLI_HANDOFF_ERRORS.INVALID_CONFIG, "handoff abort signal is invalid");
  return { allowedOrigins: origins.slice(), preflight: options.preflight, ttlMs, maxBodyBytes, requestTimeoutMs, signal: options.signal };
}

function validOrigin(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 512 || CONTROL.test(value) || value === "*") return false;
  let parsed;
  try { parsed = new URL(value); } catch { return false; }
  const loopback = new Set(["localhost", "127.0.0.1", "[::1]"]).has(parsed.hostname.toLowerCase());
  return (parsed.protocol === "https:" || (parsed.protocol === "http:" && loopback))
    && value === parsed.origin
    && !parsed.username && !parsed.password && !parsed.search && !parsed.hash && parsed.pathname === "/";
}

function boundedInteger(value, minimum, maximum, label) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw handoffError(BROWSER_CLI_HANDOFF_ERRORS.INVALID_CONFIG, `${label} is invalid`);
  return value;
}

function randomToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function exactKeys(value, keys, label) {
  if (!plainObject(value)) throw handoffError(BROWSER_CLI_HANDOFF_ERRORS.INVALID_REQUEST, `${label} must be an object`, { status: 400 });
  const actual = Object.keys(value);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) throw handoffError(BROWSER_CLI_HANDOFF_ERRORS.INVALID_REQUEST, `${label} contains unknown fields`, { status: 400 });
}

function invalidPreflight() {
  throw handoffError(BROWSER_CLI_HANDOFF_ERRORS.INVALID_PREFLIGHT, "handoff preflight is invalid", { status: 400 });
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function handoffError(code, message, options = {}) {
  return new BrowserCliHandoffError(code, message, options);
}

function failRequest(message, code, status) {
  throw handoffError(code, message, { status });
}

function mapRequestError(error) {
  if (error instanceof BrowserCliHandoffError && Number.isSafeInteger(error.status)) return { code: error.code, status: error.status, close: false };
  if (error?.code === BROWSER_CLI_HANDOFF_ERRORS.BODY_TOO_LARGE) return { code: error.code, status: 413, close: true };
  if (error?.code === BROWSER_CLI_HANDOFF_ERRORS.REQUEST_TIMEOUT) return { code: error.code, status: 408, close: true };
  return { code: BROWSER_CLI_HANDOFF_ERRORS.INVALID_REQUEST, status: 400, close: false };
}

function writeJson(response, status, value, origin, noBody = false, privateNetwork = false) {
  const body = value === null || noBody ? Buffer.alloc(0) : Buffer.from(canonicalJson(value), "utf8");
  const headers = {
    "access-control-allow-headers": "content-type",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "cache-control": "no-store",
    "content-type": "application/json",
    "content-length": body.length,
    "vary": "Origin",
    "x-content-type-options": "nosniff"
  };
  if (typeof origin === "string") headers["access-control-allow-origin"] = origin;
  if (privateNetwork) headers["access-control-allow-private-network"] = "true";
  response.writeHead(status, headers);
  response.end(body);
}

function listen(server) {
  return new Promise((resolve, reject) => {
    const onError = (error) => { server.off("listening", onListening); reject(error); };
    const onListening = () => { server.off("error", onError); resolve(); };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen({ host: LOOPBACK_HOST, port: 0, exclusive: true });
  });
}

function readBoundedBody(request, maximum, timeoutMs, expectedLength) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      request.setTimeout(0);
      if (error) {
        for (const chunk of chunks) chunk.fill(0);
        reject(error);
      } else {
        resolve(value);
      }
    };
    request.setTimeout(timeoutMs, () => {
      request.destroy();
      finish(handoffError(BROWSER_CLI_HANDOFF_ERRORS.REQUEST_TIMEOUT, "The handoff request timed out", { status: 408 }));
    });
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > maximum) {
        request.destroy();
        finish(handoffError(BROWSER_CLI_HANDOFF_ERRORS.BODY_TOO_LARGE, "The handoff request body is too large", { status: 413 }));
        return;
      }
      chunks.push(chunk);
    });
    request.once("end", () => {
      if (size !== expectedLength) {
        for (const chunk of chunks) chunk.fill(0);
        finish(handoffError(BROWSER_CLI_HANDOFF_ERRORS.INVALID_REQUEST, "The handoff request body length is invalid", { status: 400 }));
        return;
      }
      const value = Buffer.concat(chunks, size);
      for (const chunk of chunks) chunk.fill(0);
      finish(null, value);
    });
    request.once("aborted", () => finish(handoffError(BROWSER_CLI_HANDOFF_ERRORS.REQUEST_TIMEOUT, "The handoff request was interrupted", { status: 408 })));
    request.once("error", () => finish(handoffError(BROWSER_CLI_HANDOFF_ERRORS.REQUEST_TIMEOUT, "The handoff request was interrupted", { status: 408 })));
  });
}

/**
 * Strict JSON parser used only at this small public boundary.  JSON.parse
 * alone cannot detect duplicate object keys, which would make a signed or
 * canonical shape ambiguous.  It intentionally returns no source text.
 */
function parseJsonWithoutDuplicateKeys(text) {
  if (typeof text !== "string" || text.length === 0) throw new Error("invalid JSON");
  let index = 0;
  const value = parseValue(0);
  skipWhitespace();
  if (index !== text.length) throw new Error("trailing JSON");
  return value;

  function parseValue(depth) {
    if (depth > 16) throw new Error("JSON is too deep");
    skipWhitespace();
    const character = text[index];
    if (character === "{") return parseObject(depth + 1);
    if (character === "[") return parseArray(depth + 1);
    if (character === '"') return parseString();
    if (text.startsWith("true", index)) { index += 4; return true; }
    if (text.startsWith("false", index)) { index += 5; return false; }
    if (text.startsWith("null", index)) { index += 4; return null; }
    const match = text.slice(index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u);
    if (match) {
      index += match[0].length;
      const number = Number(match[0]);
      if (!Number.isFinite(number)) throw new Error("invalid number");
      return number;
    }
    throw new Error("invalid JSON value");
  }

  function parseObject(depth) {
    index++;
    skipWhitespace();
    const result = {};
    const keys = new Set();
    if (text[index] === "}") { index++; return result; }
    while (true) {
      skipWhitespace();
      if (text[index] !== '"') throw new Error("object key required");
      const key = parseString();
      if (keys.has(key)) throw new Error("duplicate object key");
      keys.add(key);
      skipWhitespace();
      if (text[index++] !== ":") throw new Error("object colon required");
      const parsedValue = parseValue(depth);
      Object.defineProperty(result, key, { value: parsedValue, enumerable: true, writable: true, configurable: true });
      skipWhitespace();
      if (text[index] === "}") { index++; return result; }
      if (text[index++] !== ",") throw new Error("object comma required");
    }
  }

  function parseArray(depth) {
    index++;
    skipWhitespace();
    const result = [];
    if (text[index] === "]") { index++; return result; }
    while (true) {
      result.push(parseValue(depth));
      skipWhitespace();
      if (text[index] === "]") { index++; return result; }
      if (text[index++] !== ",") throw new Error("array comma required");
    }
  }

  function parseString() {
    const start = index;
    index++;
    while (index < text.length) {
      const character = text[index++];
      if (character === "\\") {
        if (index >= text.length) throw new Error("invalid escape");
        if (text[index] === "u") {
          if (!/^[0-9a-f]{4}$/iu.test(text.slice(index + 1, index + 5))) throw new Error("invalid unicode escape");
          index += 5;
        } else if (!/["\\/bfnrt]/u.test(text[index++])) throw new Error("invalid escape");
      } else if (character === '"') {
        const raw = text.slice(start, index);
        return JSON.parse(raw);
      } else if (character < " ") throw new Error("control character in string");
    }
    throw new Error("unterminated string");
  }

  function skipWhitespace() {
    while (index < text.length && /[\u0020\u0009\u000a\u000d]/u.test(text[index])) index++;
  }
}
