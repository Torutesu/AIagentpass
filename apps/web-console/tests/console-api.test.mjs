import assert from "node:assert/strict";
import test from "node:test";
import { createConsoleApi } from "../lib/console-api.mjs";

const env = Object.freeze({
  AGENTPASS_CLOUD_API_URL: "https://cloud.example.test",
  AGENTPASS_ORGANIZATION_ID: "11111111-1111-4111-8111-111111111111",
  AGENTPASS_CLOUD_TOKEN: "test-server-token-abcdefghijklmnopqrstuvwxyz",
  AGENTPASS_OPERATOR_USER_IDS: "user-1",
});
const deviceId = "22222222-2222-4222-8222-222222222222";
const authenticatedUser = Object.freeze({ userId: "user-1", email: "user@example.test" });

function authenticatedApi(options = {}) {
  return createConsoleApi({
    env,
    getSiwcUser: async () => authenticatedUser,
    ...options,
  });
}

function request(path, init = {}) {
  return new Request(`https://console.example.test${path}`, init);
}

function response(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

test("GET summary aggregates tenant resources and bounded audit activity", async () => {
  const calls = [];
  const api = authenticatedApi({
    env,
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init });
      const parsed = new URL(url);
      if (parsed.pathname.endsWith("/devices")) {
        return response({ devices: [{ device_id: deviceId, name: "Build Mac" }] });
      }
      if (parsed.pathname.endsWith("/agents")) return response({ agents: [{ agent_id: "agent-1" }] });
      if (parsed.pathname.endsWith("/policies")) return response({ policies: [{ policy_id: "policy-1" }] });
      if (parsed.pathname.endsWith("/audit/events")) {
        return response({ events: [{ event_id: "event-1", device_timestamp: "2026-08-12T00:00:00.000Z", event_hash: "a".repeat(64) }] });
      }
      if (parsed.pathname.endsWith("/audit/health")) return response({ health: [{ device_id: deviceId, chain_status: "continuous", gap_count: 0, last_event_id: "event-1", last_hash: "a".repeat(64) }] });
      return response({ organization: { organization_id: env.AGENTPASS_ORGANIZATION_ID, name: "Acme" } });
    },
  });

  const result = await api.handle(request("/api/console?resource=summary"));
  assert.equal(result.status, 200);
  assert.equal(result.headers.get("cache-control"), "no-store");
  const body = await result.json();
  assert.equal(body.organization.name, "Acme");
  assert.equal(body.devices.length, 1);
  assert.equal(body.agents.length, 1);
  assert.equal(body.policies.length, 1);
  assert.equal(body.audit.activity.length, 1);
  assert.equal(body.audit.health[0].chain_status, "continuous");
  assert.equal(calls.length, 6);
  for (const call of calls) {
    assert.equal(call.init.redirect, "error");
    assert.equal(call.init.cache, "no-store");
    assert.equal(call.init.headers.get("authorization"), `Bearer ${env.AGENTPASS_CLOUD_TOKEN}`);
  }
  assert.doesNotMatch(JSON.stringify(body), new RegExp(env.AGENTPASS_CLOUD_TOKEN));
});

test("POST policy forwards the idempotency key and preserves Cloud API status", async () => {
  let forwarded;
  const api = authenticatedApi({
    env,
    fetchImpl: async (url, init) => {
      forwarded = { url: String(url), init };
      return response({ policy: { policy_id: "policy-1" } }, 202);
    },
  });
  const body = {
    name: "default",
    scope: {
      operations: ["git.commit.sign"],
      repositories: ["/work/repo"],
      branches: { allow: ["feature/*"], deny: ["main"] },
      remotes: { allow: ["git@example.test:repo.git"], deny: [] },
    },
  };
  const result = await api.handle(request("/api/console?operation=create-policy", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "idempotency-key": "policy-create-001",
    },
    body: JSON.stringify(body),
  }));
  assert.equal(result.status, 202);
  assert.equal(forwarded.init.headers.get("idempotency-key"), "policy-create-001");
  assert.equal(forwarded.init.headers.get("content-type"), "application/json");
  assert.deepEqual(await result.json(), { policy: { policy_id: "policy-1" } });
});

test("operator mutations keep tenant paths, strict schemas, and idempotency", async () => {
  const calls = [];
  const api = authenticatedApi({
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init });
      return response({ device: { device_id: deviceId }, capability: { capability_id: "33333333-3333-4333-8333-333333333333" } }, 201);
    },
  });
  const operations = [
    ["create-device", { name: "Build Mac", public_key: "-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----" }],
    ["issue-capability", { agent_id: "33333333-3333-4333-8333-333333333333", device_id: deviceId, scope: { operations: ["git.commit.sign"], repositories: ["/work/repo"], branches: { allow: ["feature/*"], deny: [] }, remotes: { allow: ["*"], deny: [] } }, ttl_ms: 1000 }],
  ];
  for (const [operation, body] of operations) {
    const result = await api.handle(request(`/api/console?operation=${operation}`, { method: "POST", headers: { "content-type": "application/json", "idempotency-key": `${operation}-0001` }, body: JSON.stringify(body) }));
    assert.equal(result.status, 201);
  }
  assert.match(calls[0].url, new RegExp(`/v1/organizations/${env.AGENTPASS_ORGANIZATION_ID}/devices$`));
  assert.match(calls[1].url, new RegExp(`/v1/organizations/${env.AGENTPASS_ORGANIZATION_ID}/capabilities$`));
  assert.equal(calls[1].init.headers.get("idempotency-key"), "issue-capability-0001");

  const invalid = await api.handle(request("/api/console?operation=revoke-device", { method: "POST", headers: { "content-type": "application/json", "idempotency-key": "revoke-device-0001" }, body: JSON.stringify({ target_id: deviceId, reason: "lost", extra: true }) }));
  assert.equal(invalid.status, 400);
});

test("mutations reject unknown JSON fields and forwarded unauthenticated SIWC", async () => {
  let fetchCount = 0;
  const api = createConsoleApi({
    env,
    getSiwcUser: async () => null,
    fetchImpl: async () => {
      fetchCount += 1;
      return response({});
    },
  });
  const unauthenticated = await api.handle(request("/api/console?operation=emergency-stop", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "idempotency-key": "stop-0001",
      "oai-authenticated-user-id": "forwarded-user",
    },
    body: JSON.stringify({ reason: "incident" }),
  }));
  assert.equal(unauthenticated.status, 401);

  const invalid = await authenticatedApi({ fetchImpl: async () => {
    fetchCount += 1;
    return response({});
  } }).handle(request("/api/console?operation=emergency-stop", {
    method: "POST",
    headers: { "content-type": "application/json", "idempotency-key": "stop-0002" },
    body: JSON.stringify({ reason: "incident", token: "must-not-pass" }),
  }));
  assert.equal(invalid.status, 400);
  assert.equal(fetchCount, 0);
});

test("same-origin and output limits are enforced without leaking configuration", async () => {
  const crossOrigin = authenticatedApi({ fetchImpl: async () => response({}) });
  const rejected = await crossOrigin.handle(request("/api/console?resource=devices", {
    headers: { origin: "https://attacker.example.test" },
  }));
  assert.equal(rejected.status, 403);

  const oversized = authenticatedApi({
    fetchImpl: async () => response({ value: "x".repeat(256 * 1024) }),
  });
  const result = await oversized.handle(request("/api/console?resource=devices"));
  assert.equal(result.status, 502);
  const text = await result.text();
  assert.doesNotMatch(text, new RegExp(env.AGENTPASS_CLOUD_TOKEN));
  assert.doesNotMatch(text, new RegExp(env.AGENTPASS_CLOUD_API_URL.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

test("Cloud API error status is preserved while its message is redacted", async () => {
  const api = authenticatedApi({
    env,
    fetchImpl: async () => response({
      error: { code: "version_conflict", message: `token=${env.AGENTPASS_CLOUD_TOKEN}` },
      request_id: "request-1",
    }, 409),
  });
  const result = await api.handle(request("/api/console?operation=emergency-stop", {
    method: "POST",
    headers: { "content-type": "application/json", "idempotency-key": "stop-0003" },
    body: JSON.stringify({ reason: "incident" }),
  }));
  assert.equal(result.status, 409);
  assert.deepEqual(await result.json(), {
    error: { code: "version_conflict", message: "Cloud API request failed" },
    request_id: "request-1",
  });
});

test("unauthenticated GET is rejected before reading tenant data", async () => {
  let fetchCount = 0;
  const api = createConsoleApi({
    env,
    fetchImpl: async () => {
      fetchCount += 1;
      return response({ organization: {} });
    },
  });

  const result = await api.handle(request("/api/console?resource=summary"));
  assert.equal(result.status, 401);
  assert.deepEqual(await result.json(), {
    error: { code: "authentication_required", message: "Authentication is required" },
  });
  assert.equal(fetchCount, 0);
});

test("unauthenticated emergency-stop is rejected before mutation", async () => {
  let fetchCount = 0;
  const api = createConsoleApi({
    env,
    fetchImpl: async () => {
      fetchCount += 1;
      return response({ stopped: true });
    },
  });

  const result = await api.handle(request("/api/console?operation=emergency-stop", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "idempotency-key": "stop-unauth-01",
    },
    body: JSON.stringify({ reason: "incident" }),
  }));
  assert.equal(result.status, 401);
  assert.equal(fetchCount, 0);
});

test("authenticated non-operators cannot use the privileged Cloud token", async () => {
  let fetchCount = 0;
  const api = createConsoleApi({
    env,
    getSiwcUser: async () => ({ userId: "user-2", email: "other@example.test" }),
    fetchImpl: async () => { fetchCount += 1; return response({}); },
  });
  const result = await api.handle(request("/api/console?resource=organization"));
  assert.equal(result.status, 403);
  assert.equal(fetchCount, 0);
});

test("non-loopback HTTP cloud URLs are rejected even with the explicit test flag", async () => {
  let fetchCount = 0;
  const api = authenticatedApi({
    env: {
      ...env,
      AGENTPASS_CLOUD_API_URL: "http://cloud.example.test",
      AGENTPASS_ALLOW_INSECURE_LOOPBACK_CLOUD_API: "true",
    },
    fetchImpl: async () => {
      fetchCount += 1;
      return response({ organization: {} });
    },
  });

  const result = await api.handle(request("/api/console?resource=organization"));
  assert.equal(result.status, 503);
  assert.deepEqual(await result.json(), {
    error: { code: "cloud_api_unavailable", message: "Cloud API is unavailable" },
  });
  assert.equal(fetchCount, 0);
});
