import crypto from "node:crypto";

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const MAX_COOKIE_HEADER_BYTES = 8 * 1024;

export const PLATFORM_SESSION_COOKIE_NAME = "__Host-agentpass_platform_session";
export const PLATFORM_SESSION_CSRF_HEADER = "agentpass-platform-csrf";

export const PLATFORM_SESSION_TRANSPORT_ERROR_CODES = Object.freeze({
  INVALID_TOKEN: "platform_session_invalid_token",
  INVALID_COOKIE: "platform_session_invalid_cookie",
  INVALID_MAX_AGE: "platform_session_invalid_max_age"
});

export class PlatformSessionTransportError extends Error {
  constructor(code) {
    super(code === PLATFORM_SESSION_TRANSPORT_ERROR_CODES.INVALID_COOKIE
      ? "Platform session cookie is invalid"
      : "Platform session transport value is invalid");
    this.name = "PlatformSessionTransportError";
    this.code = code;
  }
}

export function isPlatformSessionToken(value) {
  return typeof value === "string" && TOKEN_PATTERN.test(value);
}

export function hashPlatformSessionToken(token) {
  assertToken(token);
  return crypto.createHash("sha256").update(token, "utf8").digest("hex");
}

export function serializePlatformSessionCookie(token, { maxAgeSeconds } = {}) {
  assertToken(token);
  const parts = [
    `${PLATFORM_SESSION_COOKIE_NAME}=${token}`,
    // The __Host- prefix requires Path=/ and forbids Domain. Isolation from
    // the human session is provided by a distinct name and CSRF namespace.
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Strict"
  ];
  if (maxAgeSeconds !== undefined) {
    if (!Number.isSafeInteger(maxAgeSeconds) || maxAgeSeconds < 0) {
      fail(PLATFORM_SESSION_TRANSPORT_ERROR_CODES.INVALID_MAX_AGE);
    }
    parts.push(`Max-Age=${maxAgeSeconds}`);
  }
  return parts.join("; ");
}

export function serializeClearedPlatformSessionCookie() {
  return `${PLATFORM_SESSION_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

/** Parse exactly one platform bearer without accepting ambiguous cookies. */
export function parsePlatformSessionCookie(cookieHeader) {
  if (typeof cookieHeader !== "string" || Buffer.byteLength(cookieHeader, "utf8") > MAX_COOKIE_HEADER_BYTES) {
    fail(PLATFORM_SESSION_TRANSPORT_ERROR_CODES.INVALID_COOKIE);
  }

  let found;
  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 1) continue;
    const name = part.slice(0, separator).trim();
    if (name !== PLATFORM_SESSION_COOKIE_NAME) continue;
    const value = part.slice(separator + 1).trim();
    if (found !== undefined || !isPlatformSessionToken(value)) {
      fail(PLATFORM_SESSION_TRANSPORT_ERROR_CODES.INVALID_COOKIE);
    }
    found = value;
  }
  if (found === undefined) fail(PLATFORM_SESSION_TRANSPORT_ERROR_CODES.INVALID_COOKIE);
  return found;
}

function assertToken(token) {
  if (!isPlatformSessionToken(token)) fail(PLATFORM_SESSION_TRANSPORT_ERROR_CODES.INVALID_TOKEN);
}

function fail(code) {
  throw new PlatformSessionTransportError(code);
}
