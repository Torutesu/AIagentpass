import assert from "node:assert/strict";
import test from "node:test";

import { isLoopbackListenerUnavailable, loopbackTestsAreRequired, LOOPBACK_UNAVAILABLE_MESSAGE } from "./support/loopback-test.mjs";

test("classifies only loopback permission failures as sandbox-dependent HTTP evidence", () => {
  assert.equal(isLoopbackListenerUnavailable(Object.assign(new Error("listen EPERM: operation not permitted 127.0.0.1"), { code: "EPERM" })), true);
  assert.equal(isLoopbackListenerUnavailable(Object.assign(new Error("listen EACCES: operation not permitted /tmp/private.sock"), { code: "EACCES" })), false);
  assert.equal(isLoopbackListenerUnavailable(Object.assign(new Error("listen EPERM: operation not permitted 10.0.0.4"), { code: "EPERM", address: "10.0.0.4" })), false);
  assert.match(LOOPBACK_UNAVAILABLE_MESSAGE, /not_proven/u);
});

test("loopback qualification can be made mandatory for CI or a real runner", () => {
  assert.equal(loopbackTestsAreRequired({ AGENTPASS_REQUIRE_LOOPBACK_TESTS: "1" }), true);
  assert.equal(loopbackTestsAreRequired({ AGENTPASS_REQUIRE_LOOPBACK_TESTS: "0" }), false);
  assert.equal(loopbackTestsAreRequired({}), false);
});
