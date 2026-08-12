import assert from "node:assert/strict";
import test from "node:test";

import {
  createHumanSessionHttpApi,
  HUMAN_SESSION_HTTP_ERROR_CODES,
  HUMAN_SESSION_HTTP_PATHS
} from "../src/human-auth/session-http-api.mjs";

const ORIGIN = "https://console.agentpass.test";
const CSRF_TOKEN = "c".repeat(43);
const SESSION_COOKIE = "__Host-agentpass_session=" + "s".repeat(43) + "; Path=/; HttpOnly; Secure; SameSite=Strict";
const IDENTITY_ASSERTION = Object.freeze({ provider: "opaque", assertion: "must-not-be-decoded-here" });

function session() {
  return {
    version: 1,
    session_id: "11111111-1111-4111-8111-111111111111",
    member_id: "22222222-2222-4222-8222-222222222222",
    organization_id: "33333333-3333-4333-8333-333333333333",
    role: "owner",
    created_at: "2026-08-12T00:00:00.000Z",
    expires_at: "2026-08-12T08:00:00.000Z",
    recent_auth_at: null
  };
}

function fixture(overrides = {}) {
  const calls = { verify: [], issue: [] };
  const humanSession = {
    expectedOrigin: ORIGIN,
    async issueSession(input) {
      calls.issue.push(input);
      if (overrides.issueError) throw overrides.issueError;
      return overrides.issued ?? { session: session(), csrf_token: CSRF_TOKEN, setCookie: SESSION_COOKIE };
    }
  };
  const api = createHumanSessionHttpApi({
    humanSession,
    verifyIdentityRequest: async (request) => {
      calls.verify.push(request);
      if (overrides.verifyError) throw overrides.verifyError;
      return Object.hasOwn(overrides, "assertion") ? overrides.assertion : IDENTITY_ASSERTION;
    },
    ...(overrides.api ?? {})
  });
  return { api, calls };
}

function request(body = "{}", headers = {}) {
  return {
    method: "POST",
    url: HUMAN_SESSION_HTTP_PATHS.session,
    headers: {
      origin: ORIGIN,
      "content-type": "application/json",
      ...headers
    },
    body
  };
}

function assertNoStore(result) {
  assert.match(result.headers["Cache-Control"], /\bno-store\b/);
}

test("issues a session from an opaque adapter assertion with an exact response contract", async () => {
  const { api, calls } = fixture();
  const input = request();
  const result = await api.handle(input);

  assert.equal(result.status, 201);
  assert.deepEqual(result.body, { session: session(), csrf_token: CSRF_TOKEN });
  assert.equal(result.headers["Set-Cookie"], SESSION_COOKIE);
  assertNoStore(result);
  assert.equal(calls.verify[0], input);
  assert.deepEqual(calls.issue[0], { identityAssertion: IDENTITY_ASSERTION, origin: ORIGIN });
  assert.equal(Object.hasOwn(result.body, "setCookie"), false);
});

test("requires an exact empty JSON object and never uses identity fields from the body", async () => {
  for (const body of ["[]", "null", "\"identity\"", '{"identity":"attacker"}', '{"x":1}']) {
    const { api, calls } = fixture();
    const result = await api.handle(request(body));
    assert.equal(result.status, 400, body);
    assert.equal(result.body.error.code, HUMAN_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST);
    assert.equal(calls.verify.length, 0);
    assert.equal(calls.issue.length, 0);
    assertNoStore(result);
  }
});

test("enforces a strict HTTPS Origin before invoking the identity adapter", async () => {
  for (const origin of [undefined, "null", "https://console.agentpass.test/", "https://evil.test"]) {
    const { api, calls } = fixture();
    const headers = origin === undefined ? {} : { origin };
    const input = request("{}", headers);
    if (origin === undefined) delete input.headers.origin;
    const result = await api.handle(input);
    assert.equal(result.status, 403, origin);
    assert.equal(result.body.error.code, HUMAN_SESSION_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED);
    assert.equal(calls.verify.length, 0);
    assertNoStore(result);
  }
});

test("rejects oversized and non-JSON bodies before identity verification", async () => {
  const { api, calls } = fixture({ api: { maxBodyBytes: 8 } });
  const oversized = await api.handle(request("{}", { "content-length": "9" }));
  assert.equal(oversized.status, 413);
  assert.equal(calls.verify.length, 0);

  const notJson = await api.handle(request("{}", { "content-type": "text/plain" }));
  assert.equal(notJson.status, 400);
  assert.equal(calls.verify.length, 0);

  const actualOversized = await api.handle(request(" { } ", { "content-length": "9" }));
  assert.equal(actualOversized.status, 413);
  assert.equal(calls.verify.length, 0);
  assertNoStore(actualOversized);
});

test("fails closed for adapter errors and malformed adapter output without leaking details", async () => {
  for (const verifyError of [new Error("authorization=super-secret"), undefined, null, ""]) {
    const { api, calls } = fixture({ verifyError: verifyError instanceof Error ? verifyError : undefined, assertion: verifyError });
    const result = await api.handle(request());
    assert.equal(result.status, 401);
    assert.deepEqual(result.body, {
      error: {
        code: HUMAN_SESSION_HTTP_ERROR_CODES.IDENTITY_VERIFICATION_FAILED,
        message: "The identity request could not be verified"
      }
    });
    assert.equal(JSON.stringify(result.body).includes("super-secret"), false);
    assert.equal(calls.issue.length, 0);
    assertNoStore(result);
  }
});

test("preserves replay and identity-store availability semantics without leaking adapter details", async () => {
  const replay = fixture({ verifyError: Object.assign(new Error("raw-jti-secret"), { status: 409 }) });
  const replayResult = await replay.api.handle(request());
  assert.equal(replayResult.status, 409);
  assert.equal(replayResult.body.error.code, HUMAN_SESSION_HTTP_ERROR_CODES.IDENTITY_REPLAY);
  assert.equal(JSON.stringify(replayResult.body).includes("raw-jti-secret"), false);
  assert.equal(replay.calls.issue.length, 0);

  const unavailable = fixture({ verifyError: Object.assign(new Error("database-password"), { status: 503 }) });
  const unavailableResult = await unavailable.api.handle(request());
  assert.equal(unavailableResult.status, 503);
  assert.equal(unavailableResult.body.error.code, HUMAN_SESSION_HTTP_ERROR_CODES.SESSION_UNAVAILABLE);
  assert.equal(JSON.stringify(unavailableResult.body).includes("database-password"), false);
  assert.equal(unavailable.calls.issue.length, 0);
});

test("maps service failures to stable redacted errors and validates issued credentials", async () => {
  const unavailable = fixture({ issueError: new Error("database password") });
  const failed = await unavailable.api.handle(request());
  assert.equal(failed.status, 500);
  assert.equal(failed.body.error.code, HUMAN_SESSION_HTTP_ERROR_CODES.INTERNAL_ERROR);
  assert.equal(JSON.stringify(failed.body).includes("database password"), false);
  assertNoStore(failed);

  const malformed = fixture({ issued: { session: session(), csrf_token: "not-a-token", setCookie: SESSION_COOKIE } });
  const malformedResult = await malformed.api.handle(request());
  assert.equal(malformedResult.status, 503);
  assert.equal(malformedResult.body.error.code, HUMAN_SESSION_HTTP_ERROR_CODES.SESSION_UNAVAILABLE);
  assertNoStore(malformedResult);
});

test("supports a Fetch Request and a Node-style response writer", async () => {
  const fetchFixture = fixture();
  const fetchRequest = new Request(`https://api.agentpass.test${HUMAN_SESSION_HTTP_PATHS.session}`, {
    method: "POST",
    headers: { Origin: ORIGIN, "Content-Type": "application/json" },
    body: "{}"
  });
  const fetchResult = await fetchFixture.api.handle(fetchRequest);
  assert.equal(fetchResult.status, 201);
  assert.deepEqual(fetchResult.body, { session: session(), csrf_token: CSRF_TOKEN });

  const nodeFixture = fixture();
  const written = {};
  const nodeResponse = {
    writeHead(status, headers) { written.status = status; written.headers = headers; },
    end(body) { written.body = JSON.parse(body); }
  };
  const nodeResult = await nodeFixture.api.handle(request(), nodeResponse);
  assert.equal(nodeResult.status, 201);
  assert.equal(written.status, 201);
  assert.deepEqual(written.body, nodeResult.body);
  assert.equal(written.headers["Set-Cookie"], SESSION_COOKIE);
  assertNoStore(nodeResult);
});

test("returns no-store redacted responses for routing and method failures", async () => {
  const { api } = fixture();
  const notFound = await api.handle({ method: "GET", url: "/unknown", headers: {} });
  assert.equal(notFound.status, 404);
  assertNoStore(notFound);

  const method = await api.handle({ method: "GET", url: HUMAN_SESSION_HTTP_PATHS.session, headers: {} });
  assert.equal(method.status, 405);
  assert.equal(method.headers.Allow, "POST");
  assertNoStore(method);
});
