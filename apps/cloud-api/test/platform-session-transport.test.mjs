import assert from "node:assert/strict";
import test from "node:test";

import {
  PLATFORM_SESSION_COOKIE_NAME,
  PLATFORM_SESSION_CSRF_HEADER,
  PLATFORM_SESSION_TRANSPORT_ERROR_CODES,
  hashPlatformSessionToken,
  isPlatformSessionToken,
  parsePlatformSessionCookie,
  serializeClearedPlatformSessionCookie,
  serializePlatformSessionCookie
} from "../src/platform-session-transport.mjs";

const TOKEN = "A".repeat(43);

test("serializes an isolated __Host- platform cookie", () => {
  const value = serializePlatformSessionCookie(TOKEN, { maxAgeSeconds: 900 });
  assert.equal(value, `${PLATFORM_SESSION_COOKIE_NAME}=${TOKEN}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=900`);
  assert.equal(value.includes("Domain="), false);
  assert.equal(PLATFORM_SESSION_CSRF_HEADER, "agentpass-platform-csrf");
  assert.equal(serializeClearedPlatformSessionCookie(), `${PLATFORM_SESSION_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
});

test("parses one platform cookie while ignoring unrelated cookies", () => {
  assert.equal(parsePlatformSessionCookie(`human=value; ${PLATFORM_SESSION_COOKIE_NAME}=${TOKEN}; theme=dark`), TOKEN);
  assert.equal(isPlatformSessionToken(TOKEN), true);
  assert.match(hashPlatformSessionToken(TOKEN), /^[0-9a-f]{64}$/);
});

test("rejects missing, malformed, duplicate, and oversized cookies", () => {
  const invalid = [
    "human=value",
    `${PLATFORM_SESSION_COOKIE_NAME}=short`,
    `${PLATFORM_SESSION_COOKIE_NAME}=${TOKEN}; ${PLATFORM_SESSION_COOKIE_NAME}=${TOKEN}`,
    `${PLATFORM_SESSION_COOKIE_NAME}=${TOKEN}; padding=${"x".repeat(8192)}`
  ];
  for (const value of invalid) {
    assert.throws(
      () => parsePlatformSessionCookie(value),
      (error) => error.code === PLATFORM_SESSION_TRANSPORT_ERROR_CODES.INVALID_COOKIE
    );
  }
});

test("rejects non-canonical bearer material and invalid max-age", () => {
  for (const value of ["", "A".repeat(42), "A".repeat(44), `${"A".repeat(42)}+`]) {
    assert.equal(isPlatformSessionToken(value), false);
    assert.throws(
      () => hashPlatformSessionToken(value),
      (error) => error.code === PLATFORM_SESSION_TRANSPORT_ERROR_CODES.INVALID_TOKEN
    );
  }
  for (const maxAgeSeconds of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(
      () => serializePlatformSessionCookie(TOKEN, { maxAgeSeconds }),
      (error) => error.code === PLATFORM_SESSION_TRANSPORT_ERROR_CODES.INVALID_MAX_AGE
    );
  }
});
