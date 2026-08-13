import assert from "node:assert/strict";
import test from "node:test";

import { createCloudApi } from "../src/server.mjs";
import { createDrainController } from "../src/postgres/operational-health.mjs";

const IDS = Object.freeze({
  organization: "11111111-1111-4111-8111-111111111111",
  agent: "22222222-2222-4222-8222-222222222222",
  device: "33333333-3333-4333-8333-333333333333",
  grant: "44444444-4444-4444-8444-444444444444"
});
const HUMAN_PATH = `/api/v1/organizations/${IDS.organization}/agents/${IDS.agent}/session-grants`;
const DEVICE_PATH = `/v1/organizations/${IDS.organization}/devices/${IDS.device}/agent-session-grants/${IDS.grant}/consume`;
const DECISION = Object.freeze({ allowed: true, limit: 100, remaining: 99, retryAfterSeconds: 0, resetAt: 1_800_000_000_000 });

function genericStore(calls) {
  return {
    async getOrganization(input) { calls.push(["getOrganization", input]); return { organization_id: input.organizationId }; },
    async listDeviceReadModels(input) { calls.push(["listDeviceReadModels", input]); return []; },
    async listDevices(input) { calls.push(["listDevices", input]); return []; },
    async requestDeviceWake(input) { calls.push(["requestDeviceWake", input]); return { status: "queued" }; }
  };
}

async function startServer(t, options = {}) {
  const server = createCloudApi({
    store: options.store ?? {},
    rateLimiter: options.rateLimiter ?? { acquire: async () => DECISION },
    admissionRateLimiter: options.admissionRateLimiter ?? { acquire: async () => DECISION },
    ...(options.humanAuthApi === undefined ? {} : { humanAuthApi: options.humanAuthApi }),
    ...(options.agentSessionDeviceApi === undefined ? {} : { agentSessionDeviceApi: options.agentSessionDeviceApi }),
    ...(options.trackInFlight === undefined ? {} : { trackInFlight: options.trackInFlight })
  });
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

async function fetchWithin(url, init, timeoutMs = 5_000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function jsonResponse(response) {
  return response.json();
}

function deferred() {
  let resolve;
  const promise = new Promise((settle) => { resolve = settle; });
  return { promise, resolve };
}

test("qualifies the Human Agent Session route over HTTP and rejects aliases without weaker-auth fallthrough", async (t) => {
  const adapterCalls = [];
  const genericCalls = [];
  const body = Buffer.from('{"intent":"commit-signature"}');
  const server = await startServer(t, {
    store: genericStore(genericCalls),
    humanAuthApi: {
      async handle(input) {
        adapterCalls.push({ ...input, body: Buffer.from(input.body) });
        const url = new URL(input.url, "https://agentpass.invalid");
        if (input.method !== "POST") return { status: 405, body: { error: { code: "human_agent_session_grant_method_not_allowed" } }, headers: { Allow: "POST" } };
        if (url.search !== "") return { status: 400, body: { error: { code: "human_agent_session_grant_invalid_request" } }, headers: {} };
        return { status: 201, body: { accepted: true, boundary: "human-agent-session" }, headers: { "X-AgentPass-Boundary": "human" } };
      }
    }
  });
  const hostileHeaders = {
    authorization: "Bearer attacker-controlled-token-that-must-not-be-used",
    "agentpass-console-identity": "attacker-controlled-identity",
    "content-type": "application/json"
  };

  const exact = await fetchWithin(`${server}${HUMAN_PATH}`, { method: "POST", headers: hostileHeaders, body });
  assert.equal(exact.status, 201);
  assert.deepEqual(await jsonResponse(exact), { accepted: true, boundary: "human-agent-session" });
  assert.equal(adapterCalls.length, 1);
  assert.equal(adapterCalls[0].method, "POST");
  assert.equal(adapterCalls[0].url, HUMAN_PATH);
  assert.deepEqual(adapterCalls[0].body, body);

  const query = await fetchWithin(`${server}${HUMAN_PATH}?unexpected=1`, { method: "POST", headers: hostileHeaders, body });
  assert.equal(query.status, 400);
  assert.equal((await jsonResponse(query)).error.code, "human_agent_session_grant_invalid_request");
  assert.equal(adapterCalls.length, 2);
  assert.equal(adapterCalls[1].url, `${HUMAN_PATH}?unexpected=1`);

  const get = await fetchWithin(`${server}${HUMAN_PATH}`, { method: "GET", headers: hostileHeaders });
  assert.equal(get.status, 405);
  assert.equal((await jsonResponse(get)).error.code, "human_agent_session_grant_method_not_allowed");
  assert.equal(get.headers.get("allow"), "POST");
  assert.equal(adapterCalls.length, 3);
  assert.equal(adapterCalls[2].method, "GET");

  for (const path of [
    `${HUMAN_PATH}/`,
    `${HUMAN_PATH}/extra`,
    HUMAN_PATH.replace("session-grants", "session-grant"),
    HUMAN_PATH.replace("/api/v1/", "/api/V1/"),
    HUMAN_PATH.replace("/agents/", "/Agents/"),
    HUMAN_PATH.replace("/session-grants", "/Session-Grants")
  ]) {
    const response = await fetchWithin(`${server}${path}`, { method: "POST", headers: hostileHeaders, body });
    assert.equal(response.status, 404, path);
    assert.equal((await jsonResponse(response)).error.code, "not_found", path);
  }

  assert.equal(adapterCalls.length, 3, "aliases must not reach the Human Agent Session adapter");
  assert.deepEqual(genericCalls, [], "aliases must not reach generic routes or mutate generic stores");
});

test("qualifies the Device Agent Session route over HTTP with exact raw URL matching", async (t) => {
  const adapterCalls = [];
  const genericCalls = [];
  const rawBody = Buffer.from('{"not-json":"to-the-generic-parser"}');
  const headers = {
    authorization: "Bearer attacker-controlled-token-that-must-not-be-used",
    "agentpass-nonce": "nonce-preserved-by-the-frozen-route",
    "agentpass-signature": "signature-preserved-by-the-frozen-route",
    "content-type": "application/octet-stream"
  };
  const server = await startServer(t, {
    store: genericStore(genericCalls),
    agentSessionDeviceApi: {
      async handle(input) {
        adapterCalls.push({ ...input, body: Buffer.from(input.body) });
        return { status: 201, body: { accepted: true, boundary: "device-agent-session" }, headers: { "X-AgentPass-Boundary": "device" } };
      }
    }
  });

  const exact = await fetchWithin(`${server}${DEVICE_PATH}`, { method: "POST", headers, body: rawBody });
  assert.equal(exact.status, 201);
  assert.deepEqual(await jsonResponse(exact), { accepted: true, boundary: "device-agent-session" });
  assert.equal(adapterCalls.length, 1);
  assert.equal(adapterCalls[0].method, "POST");
  assert.equal(adapterCalls[0].url, DEVICE_PATH);
  assert.deepEqual(adapterCalls[0].body, rawBody);
  assert.equal(adapterCalls[0].headers["agentpass-nonce"], headers["agentpass-nonce"]);
  assert.equal(adapterCalls[0].headers["agentpass-signature"], headers["agentpass-signature"]);

  for (const [method, path] of [
    ["POST", `${DEVICE_PATH}?unexpected=1`],
    ["POST", `${DEVICE_PATH}/`],
    ["POST", DEVICE_PATH.replace("agent-session-grants", "agent-session-grant")],
    ["POST", DEVICE_PATH.replace("agent-session-grants", "Agent-Session-Grants")],
    ["POST", DEVICE_PATH.replace("/consume", "")],
    ["POST", DEVICE_PATH.replace(IDS.grant, "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA")],
    ["GET", DEVICE_PATH],
    ["PUT", DEVICE_PATH]
  ]) {
    const response = await fetchWithin(`${server}${path}`, { method, headers, body: method === "GET" ? undefined : rawBody });
    assert.equal(response.status, 404, `${method} ${path}`);
    assert.equal((await jsonResponse(response)).error.code, "not_found", `${method} ${path}`);
  }

  assert.equal(adapterCalls.length, 1, "aliases and method substitutions must not reach the Device adapter");
  assert.deepEqual(genericCalls, [], "aliases must not reach generic routes or mutate generic stores");
});

test("drain lets one in-flight Human Agent Session request finish and rejects subsequent work before adapter mutation", async (t) => {
  const drain = createDrainController({ defaultTimeoutMs: 100, maxTimeoutMs: 200 });
  const started = deferred();
  const release = deferred();
  let adapterCalls = 0;
  let adapterMutations = 0;
  const server = await startServer(t, {
    trackInFlight: drain.track,
    humanAuthApi: {
      async handle(input) {
        adapterCalls += 1;
        started.resolve();
        await release.promise;
        adapterMutations += 1;
        return { status: 201, body: { accepted: true, mutation_count: adapterMutations }, headers: {} };
      }
    }
  });
  const init = { method: "POST", headers: { "content-type": "application/json" }, body: "{}" };

  const firstRequest = fetchWithin(`${server}${HUMAN_PATH}`, init);
  await Promise.race([started.promise, new Promise((_, reject) => setTimeout(() => reject(new Error("first Agent Session request did not enter the adapter")), 500))]);
  assert.deepEqual(drain.snapshot(), { state: "running", accepting: true, in_flight: 1 });

  assert.deepEqual(drain.beginDrain(), { state: "draining", accepting: false, in_flight: 1 });
  const subsequent = await fetchWithin(`${server}${HUMAN_PATH}`, init);
  assert.equal(subsequent.status, 503);
  assert.equal((await jsonResponse(subsequent)).error.code, "draining");
  assert.equal(adapterCalls, 1, "draining work must not enter the Agent Session adapter");
  assert.equal(adapterMutations, 0, "the in-flight adapter operation must not mutate before completion");

  release.resolve();
  const first = await firstRequest;
  assert.equal(first.status, 201);
  assert.deepEqual(await jsonResponse(first), { accepted: true, mutation_count: 1 });
  assert.equal(adapterCalls, 1);
  assert.equal(adapterMutations, 1);
  assert.deepEqual(drain.snapshot(), { state: "draining", accepting: false, in_flight: 0 });
});
