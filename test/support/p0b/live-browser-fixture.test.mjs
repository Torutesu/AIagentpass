import assert from "node:assert/strict";
import test from "node:test";

import {
  awaitConsoleSessionRotation,
  classifySessionBootstrap502,
  classifySessionBootstrap503,
  classifyStoredSessionState,
  P0BLiveBrowserFixtureError,
  startP0BLiveBrowserFixture
} from "./live-browser-fixture.mjs";
import { P0BSkip } from "./harness.mjs";

test("live browser fixture preserves the harness skip contract without exposing configuration", async () => {
  await assert.rejects(
    startP0BLiveBrowserFixture({ env: { P0B_DISABLE_EXTERNAL: "true" } }),
    (error) => error instanceof P0BSkip && error.code === "external_disabled"
  );
});

test("live browser fixture rejects an invalid preparation hook before startup", async () => {
  await assert.rejects(
    startP0BLiveBrowserFixture({ prepareDatabase: true }),
    (error) => error instanceof TypeError && error.message === "P0-B database preparation must be a function"
  );
});

test("fixture errors have stable, secret-free public shape", () => {
  const error = new P0BLiveBrowserFixtureError("startup_failed", "P0-B live browser fixture startup failed");
  assert.deepEqual({ name: error.name, code: error.code, message: error.message }, {
    name: "P0BLiveBrowserFixtureError",
    code: "startup_failed",
    message: "P0-B live browser fixture startup failed"
  });
  assert.equal(Object.hasOwn(error, "cause"), false);
});

test("bootstrap 502 classification exposes only fixed failure classes", () => {
  assert.equal(classifySessionBootstrap502(null, "exited", "unavailable"), "cloud_exited");
  assert.equal(classifySessionBootstrap502(null, "running", "unavailable"), "proxy_unavailable");
  assert.equal(classifySessionBootstrap502({ error: { code: "cloud_api_invalid_response", message: "ignored" } }, "running", "ready"), "bff_invalid_response");
  assert.equal(classifySessionBootstrap502({ error: { code: "some_other_code" } }, "running", "ready"), "proxy_unavailable");
  assert.equal(classifySessionBootstrap502({ error: { code: "cloud_api_invalid_response" } }, "unknown", "ready"), "proxy_unavailable");
});

test("bootstrap 503 classification exposes only fixed Cloud boundary classes", () => {
  assert.equal(classifySessionBootstrap503({ error: { code: "human_session_unavailable", message: "ignored" } }), "session_unavailable");
  assert.equal(classifySessionBootstrap503({ error: { code: "human_auth_unavailable", message: "ignored" } }), "human_auth_unavailable");
  assert.equal(classifySessionBootstrap503({ error: { code: "rate_limiter_unavailable", message: "ignored" } }), "rate_limiter_unavailable");
  assert.equal(classifySessionBootstrap503({ error: { code: "cloud_api_unavailable", message: "ignored" } }), "cloud_api_unavailable");
  assert.equal(classifySessionBootstrap503({ error: { code: "identity_unavailable", message: "ignored" } }), "identity_unavailable");
  assert.equal(classifySessionBootstrap503({ error: { code: "unknown" } }), "other");
  assert.equal(classifySessionBootstrap503(null), "other");
});

test("stored session diagnostics expose only fixed authoritative state codes", async () => {
  const sessionId = "11111111-1111-4111-8111-111111111111";
  for (const [row, expected] of [
    [undefined, "missing"],
    [{ revoked: true, revoke_reason: "expired", absolute_expired: false, idle_expired: false }, "revoked_expired"],
    [{ revoked: true, revoke_reason: "concurrent_session_limit", absolute_expired: false, idle_expired: false }, "revoked_concurrent_session_limit"],
    [{ revoked: true, revoke_reason: "unexpected", absolute_expired: false, idle_expired: false }, "revoked_other"],
    [{ revoked: false, absolute_expired: true, idle_expired: false }, "absolute_expired"],
    [{ revoked: false, absolute_expired: false, idle_expired: true }, "idle_expired"],
    [{ revoked: false, absolute_expired: false, idle_expired: false }, "active"]
  ]) {
    const pool = { query: async () => ({ rows: row === undefined ? [] : [row] }) };
    assert.equal(await classifyStoredSessionState(pool, sessionId), expected);
  }
  assert.equal(await classifyStoredSessionState({ query: async () => { throw new Error("secret"); } }, sessionId), "unavailable");
});

test("live bootstrap adopts the Console-owned rotation before navigation completes", async () => {
  const organizationId = "11111111-1111-4111-8111-111111111111";
  const descriptor = Object.freeze({
    role: "owner",
    memberId: "22222222-2222-4222-8222-222222222222"
  });
  const expected = Object.freeze({
    sessionId: "33333333-3333-4333-8333-333333333333",
    csrfToken: "A".repeat(43)
  });
  const events = [];
  let matchResponse;
  let resolveResponse;
  const responsePromise = new Promise((resolve) => { resolveResponse = resolve; });
  const response = {
    ok: () => true,
    request: () => ({ method: () => "POST" }),
    url: () => "https://console.example.test/api/auth/session/resume",
    json: async () => ({
      csrf_token: expected.csrfToken,
      session: {
        session_id: expected.sessionId,
        organization_id: organizationId,
        member_id: descriptor.memberId,
        role: descriptor.role
      }
    })
  };
  const page = {
    waitForResponse(predicate, options) {
      events.push(["wait", options.timeout]);
      matchResponse = predicate;
      return responsePromise;
    },
    async goto(target, options) {
      events.push(["goto", target, options.waitUntil]);
      assert.equal(matchResponse({
        ok: () => true,
        request: () => ({ method: () => "GET" }),
        url: () => "https://console.example.test/api/auth/session/resume"
      }), false);
      assert.equal(matchResponse(response), true);
      resolveResponse(response);
    }
  };

  const rotated = await awaitConsoleSessionRotation(
    page,
    new URL("https://console.example.test/"),
    descriptor,
    organizationId
  );

  assert.deepEqual(events, [
    ["wait", 15_000],
    ["goto", "https://console.example.test/", "domcontentloaded"]
  ]);
  assert.deepEqual(rotated, expected);
});
