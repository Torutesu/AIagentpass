import assert from "node:assert/strict";
import test from "node:test";

import {
  classifySessionBootstrap502,
  classifySessionBootstrap503,
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
