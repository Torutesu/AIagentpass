import assert from "node:assert/strict";
import test from "node:test";
import { revokeOperations } from "../bin/revoke-command.mjs";

const NATIVE_CONFIG = Object.freeze({
  native_broker: Object.freeze({ enabled: true, mach_service: "dev.agentpass.native-service" }),
});

test("universal revoke dispatches native mode to the protected broker and never writes legacy state", async () => {
  const calls = [];
  let loaded = 0;
  let saved = 0;
  let audited = 0;
  const result = await revokeOperations({
    config: NATIVE_CONFIG,
    configDir: "/private/agentpass",
    loadState: () => { loaded += 1; return { revoked: false, generation: 4 }; },
    saveState: () => { saved += 1; },
    audit: () => { audited += 1; },
    brokerRequest: async (...args) => { calls.push(args); return { ok: true }; },
  });

  assert.deepEqual(result, { version: 1, mode: "native", revoked: true });
  assert.deepEqual(calls, [[
    { operation: "native.session.revoke" },
    { native: NATIVE_CONFIG.native_broker },
  ]]);
  assert.equal(loaded, 0);
  assert.equal(saved, 0);
  assert.equal(audited, 0);
});

test("universal revoke preserves the audited local-state path when native mode is absent", async () => {
  const saved = [];
  const audited = [];
  const result = await revokeOperations({
    config: {},
    configDir: "/private/agentpass",
    loadState: () => ({ revoked: false, generation: 4 }),
    saveState: (state, directory) => saved.push({ state, directory }),
    audit: (event, directory) => audited.push({ event, directory }),
    now: () => "2026-08-21T00:00:00.000Z",
  });

  assert.deepEqual(result, { version: 1, mode: "local", revoked: true, generation: 5 });
  assert.deepEqual(saved, [{
    state: { revoked: true, generation: 5, revoked_at: "2026-08-21T00:00:00.000Z" },
    directory: "/private/agentpass",
  }]);
  assert.deepEqual(audited, [{
    event: { operation: "control.revoke", decision: "allow", generation: 5 },
    directory: "/private/agentpass",
  }]);
});
