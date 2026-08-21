import assert from "node:assert/strict";
import test from "node:test";

import { createCloudApi } from "../src/server.mjs";

const ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111";
const DEVICE_ID = "22222222-2222-4222-8222-222222222222";
const GRANT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SESSION_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const PATH = `/v1/organizations/${ORGANIZATION_ID}/devices/${DEVICE_ID}/agent-session-grants/${GRANT_ID}/consume`;
const SIGNING_CAPABILITY_PATH = `/v1/organizations/${ORGANIZATION_ID}/devices/${DEVICE_ID}/agent-sessions/${SESSION_ID}/signing-capabilities`;
const RESPONSE = { request_id: "33333333-3333-4333-8333-333333333333", accepted: true };

async function startServer(t, options = {}) {
  const server = createCloudApi({ store: options.store ?? {}, ...options });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return `http://127.0.0.1:${server.address().port}`;
}

test("intercepts only the frozen Device API path before JSON/auth and preserves raw input", async (t) => {
  const calls = [];
  const trackCalls = [];
  const rawBody = Buffer.from('{"grant":', "utf8");
  const headers = {
    "agentpass-nonce": "nonce-that-is-preserved-exactly",
    "agentpass-signature": "signature-that-is-preserved-exactly",
    "content-type": "application/json"
  };
  const base = await startServer(t, {
    store: {
      listDevices: async () => { throw new Error("generic device auth must not run"); }
    },
    trackInFlight: async (operation) => {
      trackCalls.push("entered");
      return operation();
    },
    agentSessionDeviceApi: {
      async handle(input) {
        calls.push(input);
        return { status: 202, body: RESPONSE, headers: { "X-AgentPass-Route": "device" } };
      }
    }
  });

  const response = await fetch(`${base}${PATH}`, { method: "POST", headers, body: rawBody });
  assert.equal(response.status, 202);
  assert.deepEqual(await response.json(), RESPONSE);
  assert.equal(response.headers.get("x-agentpass-route"), "device");
  assert.equal(trackCalls.length, 1);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, "POST");
  assert.equal(calls[0].url, PATH);
  assert.deepEqual(Buffer.from(calls[0].body), rawBody);
  assert.equal(calls[0].headers["agentpass-nonce"], headers["agentpass-nonce"]);
  assert.equal(calls[0].headers["agentpass-signature"], headers["agentpass-signature"]);
});

test("does not expose or fall through the Device API path when the adapter is absent", async (t) => {
  const calls = [];
  const base = await startServer(t, {
    store: {
      listDevices: async () => { calls.push("generic"); return []; }
    }
  });

  const response = await fetch(`${base}${PATH}`, { method: "POST", body: "not-json" });
  assert.equal(response.status, 404);
  assert.equal((await response.json()).error.code, "not_found");
  assert.deepEqual(calls, []);
});

test("routes the exact signing-capability path through the same raw Device boundary", async (t) => {
  const calls = [];
  const rawBody = Buffer.from(`{"request_id":"${GRANT_ID}"}`, "utf8");
  const base = await startServer(t, {
    agentSessionDeviceApi: {
      async handle(input) {
        calls.push(input);
        return { status: 201, body: RESPONSE, headers: { "Cache-Control": "no-store" } };
      }
    }
  });
  const response = await fetch(`${base}${SIGNING_CAPABILITY_PATH}`, { method: "POST", body: rawBody });
  assert.equal(response.status, 201);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, SIGNING_CAPABILITY_PATH);
  assert.deepEqual(Buffer.from(calls[0].body), rawBody);
});

test("does not intercept missing grant IDs, query/trailing slash, case, substitution, or method variants", async (t) => {
  const calls = [];
  const base = await startServer(t, {
    agentSessionDeviceApi: {
      async handle(input) {
        calls.push(input);
        return { status: 200, body: RESPONSE, headers: {} };
      }
    }
  });

  for (const [method, path] of [
    ["POST", `${PATH}?unexpected=1`],
    ["POST", `${PATH}/`],
    ["POST", PATH.replace(`/${GRANT_ID}/consume`, "/consume")],
    ["POST", PATH.replace("agent-session-grants", "Agent-Session-Grants")],
    ["POST", PATH.replace("agent-session-grants", "agent-session-grant")],
    ["POST", PATH.replace(GRANT_ID, "AAAAAAAa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")],
    ["GET", PATH]
  ]) {
    const response = await fetch(`${base}${path}`, { method, body: method === "POST" ? "not-json" : undefined });
    assert.equal(response.status, 404, `${method} ${path}`);
    assert.equal((await response.json()).error.code, "not_found");
  }
  assert.equal(calls.length, 0);
});
