import assert from "node:assert/strict";
import test from "node:test";
import { createConsoleApi } from "../lib/console-api.mjs";

const env = Object.freeze({
  NODE_ENV: "test",
  AGENTPASS_ALLOW_LEGACY_OPERATOR_BRIDGE: "true",
  AGENTPASS_CLOUD_API_URL: "https://cloud.example.test",
  AGENTPASS_ORGANIZATION_ID: "11111111-1111-4111-8111-111111111111",
  AGENTPASS_CLOUD_TOKEN: "test-server-token-abcdefghijklmnopqrstuvwxyz",
  AGENTPASS_CONSOLE_CURSOR_SECRET: "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE",
  AGENTPASS_OPERATOR_USER_IDS: "user-1",
});
const humanEnv = Object.freeze({
  AGENTPASS_CLOUD_API_URL: env.AGENTPASS_CLOUD_API_URL,
  AGENTPASS_ORGANIZATION_ID: env.AGENTPASS_ORGANIZATION_ID,
  AGENTPASS_CONSOLE_CURSOR_SECRET: env.AGENTPASS_CONSOLE_CURSOR_SECRET,
});
const PROBE_SECRET = Buffer.alloc(32, 0x51).toString("base64url");
const sessionCookie = `__Host-agentpass_session=${"s".repeat(43)}`;
const deviceId = "22222222-2222-4222-8222-222222222222";
const agentId = "33333333-3333-4333-8333-333333333333";
const authenticatedUser = Object.freeze({ userId: "user-1", email: "user@example.test" });
const auditTimestamps = [
  "2026-08-12T00:00:00.000Z",
  "2026-08-12T00:00:01.000Z",
  "2026-08-12T00:00:02.000Z",
  "2026-08-12T00:00:03.000Z",
];

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

function auditEvent(eventId, timestamp, extra = {}) {
  return {
    version: 1,
    event_id: eventId,
    request_id: `request-${eventId}`,
    agent_id: "33333333-3333-4333-8333-333333333333",
    operation: "git.commit.sign",
    decision: "allow",
    reason: "allowed-audit-detail",
    repository: "/work/private-repository",
    branch: "feature/activity",
    payload_digest: "b".repeat(64),
    device_timestamp: timestamp,
    previous_hash: "0".repeat(64),
    ...extra,
  };
}

function activityFixture({ events = [], onEventRequest = () => events, apiEnv = env, deviceIds = [deviceId] } = {}) {
  const calls = [];
  const api = authenticatedApi({
    env: apiEnv,
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init });
      const parsed = new URL(url);
      if (parsed.pathname.endsWith("/devices")) return response({ devices: deviceIds.map((id) => ({ device_id: id, name: "Build Mac" })) });
      if (parsed.pathname.endsWith("/audit/events")) {
        const page = onEventRequest(parsed);
        return response(Array.isArray(page) ? { events: page, next_cursor: null } : page);
      }
      if (parsed.pathname.endsWith("/audit/health")) return response({ health: deviceIds.map((id) => ({ device_id: id, chain_status: "continuous", gap_count: 0, last_event_id: "event-3", last_hash: "a".repeat(64) })) });
      return response({});
    },
  });
  return { api, calls };
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
  assert.equal(body.organization.organization_id, env.AGENTPASS_ORGANIZATION_ID);
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

test("deployment readiness is fetched server-side and exposes only the verified public identity", async () => {
  const probe = PROBE_SECRET;
  const api = authenticatedApi({
    env: { ...env, AGENTPASS_OPERATIONAL_PROBE_SECRET: probe },
    fetchImpl: async (url, init) => {
      const pathname = new URL(url).pathname;
      if (pathname.endsWith(`/v1/organizations/${env.AGENTPASS_ORGANIZATION_ID}`)) return response({ organization: { organization_id: env.AGENTPASS_ORGANIZATION_ID } });
      assert.equal(pathname, "/health/ready");
      assert.equal(init.headers.get("agentpass-operational-token"), probe);
      assert.equal(init.headers.get("authorization"), null);
      const readiness = {
        version: 1,
        ready: true,
        status: "ready",
        code: "ready",
        deployment_identity: {
          version: 1, configured: true, ready: true,
          source_commit: "a".repeat(40), source_tree: "b".repeat(40), image_digest: `sha256:${"c".repeat(64)}`,
          deployment_id: "deployment-123", revision: "revision-1", schema_digest: "d".repeat(64), catalog_digest: "e".repeat(64), database_schema_digest: "f".repeat(64),
        },
        checks: { secret: "must-not-reach-browser" },
      };
      return new Response(JSON.stringify(readiness), { status: 200, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
    },
  });
  const result = await api.handle(request("/api/console?resource=deployment-readiness"));
  assert.equal(result.status, 200);
  assert.deepEqual(await result.json(), {
    version: 1, ready: true, status: "ready", code: "ready",
    deployment_identity: {
      version: 1, configured: true, ready: true,
      source_commit: "a".repeat(40), source_tree: "b".repeat(40), image_digest: `sha256:${"c".repeat(64)}`,
      deployment_id: "deployment-123", revision: "revision-1", schema_digest: "d".repeat(64), catalog_digest: "e".repeat(64), database_schema_digest: "f".repeat(64),
    },
  });
});

test("deployment readiness fails closed when the probe secret or identity is unavailable", async () => {
  const missingSecret = authenticatedApi({ fetchImpl: async () => { throw new Error("must not fetch"); } });
  assert.equal((await missingSecret.handle(request("/api/console?resource=deployment-readiness"))).status, 503);
  const nonCanonical = authenticatedApi({
    env: { ...env, AGENTPASS_OPERATIONAL_PROBE_SECRET: "q".repeat(43) },
    fetchImpl: async () => { throw new Error("must not fetch with a non-canonical token"); },
  });
  assert.equal((await nonCanonical.handle(request("/api/console?resource=deployment-readiness"))).status, 503);
  const malformed = authenticatedApi({
    env: { ...env, AGENTPASS_OPERATIONAL_PROBE_SECRET: PROBE_SECRET },
    fetchImpl: async (url) => new URL(url).pathname.startsWith("/v1/")
      ? response({ organization: { organization_id: env.AGENTPASS_ORGANIZATION_ID } })
      : new Response(JSON.stringify({ version: 1, ready: true, status: "ready", code: "ready" }), { status: 200, headers: { "content-type": "application/json", "cache-control": "no-store" } }),
  });
  assert.equal((await malformed.handle(request("/api/console?resource=deployment-readiness"))).status, 502);
});

test("deployment readiness validates the Human session before using the server-only probe", async () => {
  let probeCalls = 0;
  const api = createConsoleApi({
    env: { ...humanEnv, AGENTPASS_OPERATIONAL_PROBE_SECRET: PROBE_SECRET },
    fetchImpl: async (url) => {
      if (new URL(url).pathname === "/health/ready") probeCalls += 1;
      return response({ error: { code: "session_required", message: "session required" } }, 401);
    },
  });
  const result = await api.handle(request("/api/console?resource=deployment-readiness", { headers: { cookie: sessionCookie } }));
  assert.equal(result.status, 401);
  assert.equal(probeCalls, 0);
});

test("deployment readiness rejects degraded upstream state and production loopback configuration", async () => {
  const degraded = authenticatedApi({
    env: { ...env, AGENTPASS_OPERATIONAL_PROBE_SECRET: "t".repeat(43) },
    fetchImpl: async (url) => new URL(url).pathname.startsWith("/v1/")
      ? response({ organization: { organization_id: env.AGENTPASS_ORGANIZATION_ID } })
      : new Response(JSON.stringify({ version: 1, ready: false, status: "degraded", code: "database_unavailable", deployment_identity: { version: 1, configured: true, ready: true, source_commit: "a".repeat(40), source_tree: "b".repeat(40), image_digest: `sha256:${"c".repeat(64)}`, deployment_id: "deployment-1", revision: "revision-1", schema_digest: "d".repeat(64), catalog_digest: "e".repeat(64), database_schema_digest: "f".repeat(64) } }), { status: 200, headers: { "content-type": "application/json", "cache-control": "no-store" } }),
  });
  assert.equal((await degraded.handle(request("/api/console?resource=deployment-readiness"))).status, 503);
  const productionLoopback = authenticatedApi({
    env: { ...env, NODE_ENV: "production", AGENTPASS_OPERATIONAL_PROBE_SECRET: PROBE_SECRET, AGENTPASS_ALLOW_INSECURE_LOOPBACK_CLOUD_API: "true", AGENTPASS_CLOUD_API_URL: "http://127.0.0.1:8787" },
    fetchImpl: async () => { throw new Error("must not fetch insecure production cloud"); },
  });
  assert.equal((await productionLoopback.handle(request("/api/console?resource=deployment-readiness", { headers: { cookie: sessionCookie } }))).status, 503);
  for (const nodeEnv of [undefined, "prod", "staging"]) {
    const unknownEnvironment = authenticatedApi({
      env: { ...env, NODE_ENV: nodeEnv, AGENTPASS_OPERATIONAL_PROBE_SECRET: PROBE_SECRET, AGENTPASS_ALLOW_INSECURE_LOOPBACK_CLOUD_API: "true", AGENTPASS_CLOUD_API_URL: "http://127.0.0.1:8787" },
      fetchImpl: async () => { throw new Error("must not fetch insecure cloud in unknown environment"); },
    });
    assert.equal((await unknownEnvironment.handle(request("/api/console?resource=deployment-readiness", { headers: { cookie: sessionCookie } }))).status, 503);
  }
});

test("deployment readiness rejects redirects, Set-Cookie, and non-JSON upstream responses", async () => {
  for (const upstream of [
    new Response("", { status: 302, headers: { location: "https://attacker.example" } }),
    new Response("{}", { status: 200, headers: { "content-type": "application/json", "cache-control": "no-store", "set-cookie": "leak=1" } }),
    new Response("{}", { status: 200, headers: { "content-type": "text/plain", "cache-control": "no-store" } }),
  ]) {
    const api = authenticatedApi({
    env: { ...env, AGENTPASS_OPERATIONAL_PROBE_SECRET: PROBE_SECRET },
      fetchImpl: async (url) => new URL(url).pathname.startsWith("/v1/")
        ? response({ organization: { organization_id: env.AGENTPASS_ORGANIZATION_ID } }) : upstream,
    });
    assert.equal((await api.handle(request("/api/console?resource=deployment-readiness"))).status, 503);
  }
});

test("GET summary keeps viewer resources visible when audit access is role denied", async () => {
  const calls = [];
  const api = authenticatedApi({
    env,
    fetchImpl: async (url) => {
      calls.push(String(url));
      const parsed = new URL(url);
      if (parsed.pathname.endsWith("/devices")) return response({ devices: [{ device_id: deviceId, name: "Build Mac" }] });
      if (parsed.pathname.endsWith("/agents")) return response({ agents: [{ agent_id: "agent-1" }] });
      if (parsed.pathname.endsWith("/policies")) return response({ policies: [{ policy_id: "policy-1" }] });
      if (parsed.pathname.endsWith("/audit/events") || parsed.pathname.endsWith("/audit/health")) {
        return response({ error: { code: "role_denied", message: "Authorization denied" } }, 403);
      }
      return response({ organization: { organization_id: env.AGENTPASS_ORGANIZATION_ID, name: "Acme" } });
    },
  });

  const result = await api.handle(request("/api/console?resource=summary"));
  assert.equal(result.status, 200);
  const body = await result.json();
  assert.equal(body.organization.name, "Acme");
  assert.equal(body.devices[0].device_id, deviceId);
  assert.deepEqual(body.audit, { health: [], activity: [], next_cursor: null });
  assert.ok(calls.some((url) => new URL(url).pathname.endsWith("/audit/events")));
});

test("GET summary does not suppress non-role audit failures", async () => {
  const api = authenticatedApi({
    env,
    fetchImpl: async (url) => {
      const parsed = new URL(url);
      if (parsed.pathname.endsWith("/devices")) return response({ devices: [{ device_id: deviceId, name: "Build Mac" }] });
      if (parsed.pathname.endsWith("/agents")) return response({ agents: [] });
      if (parsed.pathname.endsWith("/policies")) return response({ policies: [] });
      if (parsed.pathname.endsWith("/audit/events") || parsed.pathname.endsWith("/audit/health")) {
        return response({ error: { code: "audit_unavailable", message: "Unavailable" } }, 503);
      }
      return response({ organization: { organization_id: env.AGENTPASS_ORGANIZATION_ID, name: "Acme" } });
    },
  });

  const result = await api.handle(request("/api/console?resource=summary"));
  assert.equal(result.status, 503);
  assert.deepEqual(await result.json(), {
    error: { code: "audit_unavailable", message: "Cloud API request failed" },
  });
});

test("direct audit access still preserves role denial", async () => {
  const api = authenticatedApi({
    env,
    fetchImpl: async (url) => {
      const parsed = new URL(url);
      if (parsed.pathname.endsWith("/devices")) return response({ devices: [{ device_id: deviceId }] });
      return response({ error: { code: "role_denied", message: "Authorization denied" } }, 403);
    },
  });

  const result = await api.handle(request("/api/console?resource=audit"));
  assert.equal(result.status, 403);
  assert.deepEqual(await result.json(), {
    error: { code: "role_denied", message: "Cloud API request failed" },
  });
});

test("production control-plane reads use only the Human session and never require the legacy operator bearer", async () => {
  const calls = [];
  let siwcCalls = 0;
  const api = createConsoleApi({
    env: humanEnv,
    getSiwcUser: async () => { siwcCalls += 1; throw new Error("SIWC must not authorize an established Human session"); },
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init });
      return response({ organization: { organization_id: env.AGENTPASS_ORGANIZATION_ID, name: "Acme" } });
    },
  });
  const result = await api.handle(request("/api/console?resource=organization", { headers: { cookie: `${sessionCookie}; unrelated=value` } }));
  assert.equal(result.status, 200);
  assert.equal(siwcCalls, 0);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].init.headers.get("cookie"), sessionCookie);
  assert.equal(calls[0].init.headers.get("origin"), "https://console.example.test");
  assert.equal(calls[0].init.headers.get("authorization"), null);
  assert.equal(calls[0].init.headers.get("agentpass-csrf"), null);
});

test("production control-plane mutations require exact origin and CSRF and forward no unrelated cookie", async () => {
  const calls = [];
  const api = createConsoleApi({ env: humanEnv, fetchImpl: async (url, init) => { calls.push({ url: String(url), init }); return response({ stopped: true }, 201); } });
  const body = JSON.stringify({ reason: "incident" });
  const base = { method: "POST", headers: { cookie: `${sessionCookie}; analytics=other`, origin: "https://console.example.test", "content-type": "application/json", "idempotency-key": "human-stop-0001" }, body };
  const missingCsrf = await api.handle(request("/api/console?operation=emergency-stop", base));
  assert.equal(missingCsrf.status, 403);
  assert.equal(calls.length, 0);
  const accepted = await api.handle(request("/api/console?operation=emergency-stop", { ...base, headers: { ...base.headers, "agentpass-csrf": "c".repeat(43) } }));
  assert.equal(accepted.status, 201);
  assert.equal(calls[0].init.headers.get("authorization"), null);
  assert.equal(calls[0].init.headers.get("cookie"), sessionCookie);
  assert.equal(calls[0].init.headers.get("agentpass-csrf"), "c".repeat(43));
  const duplicate = await api.handle(request("/api/console?resource=organization", { headers: { cookie: `${sessionCookie}; ${sessionCookie}` } }));
  assert.equal(duplicate.status, 400);
});

test("activity merges a deterministic cross-device page and resumes without duplicates", async () => {
  const { api, calls } = activityFixture({
    events: [
      auditEvent("event-1", auditTimestamps[0]),
      auditEvent("event-2", auditTimestamps[1]),
      auditEvent("event-3", auditTimestamps[2]),
    ],
  });

  const first = await api.handle(request("/api/console?resource=activity&limit=2"));
  assert.equal(first.status, 200);
  const firstBody = await first.json();
  assert.deepEqual(firstBody.activity.map((event) => event.event_id), ["event-3", "event-2"]);
  assert.equal(typeof firstBody.next_cursor, "string");
  assert.match(firstBody.next_cursor, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  const firstEventRequest = calls.find((call) => new URL(call.url).pathname.endsWith("/audit/events"));
  assert.equal(new URL(firstEventRequest.url).searchParams.get("limit"), "500");

  const second = await api.handle(request(`/api/console?resource=activity&limit=2&cursor=${encodeURIComponent(firstBody.next_cursor)}`));
  assert.equal(second.status, 200);
  const secondBody = await second.json();
  assert.deepEqual(secondBody.activity.map((event) => event.event_id), ["event-1"]);
  assert.equal(secondBody.next_cursor, null);
  for (const call of calls.filter((item) => new URL(item.url).pathname.endsWith("/audit/events"))) {
    const upstreamQuery = new URL(call.url).searchParams;
    assert.equal(upstreamQuery.has("cursor"), false);
    assert.equal(upstreamQuery.get("limit"), "500");
  }
});

test("activity follows authoritative Cloud next_cursor pages and deduplicates page overlap", async () => {
  const pages = new Map([
    ["", { events: [auditEvent("event-5", auditTimestamps[3]), auditEvent("event-4", auditTimestamps[2])], next_cursor: "page-2" }],
    ["page-2", { events: [auditEvent("event-4", auditTimestamps[2]), auditEvent("event-3", auditTimestamps[1])], next_cursor: "page-3" }],
    ["page-3", { events: [auditEvent("event-2", auditTimestamps[0]), auditEvent("event-1", "2026-08-11T23:59:59.000Z")], next_cursor: null }],
  ]);
  const { api, calls } = activityFixture({ onEventRequest: (url) => pages.get(url.searchParams.get("cursor") ?? "") ?? { events: [], next_cursor: null } });

  const first = await api.handle(request("/api/console?resource=activity&limit=2"));
  assert.equal(first.status, 200);
  const firstBody = await first.json();
  assert.deepEqual(firstBody.activity.map((event) => event.event_id), ["event-5", "event-4"]);
  assert.notEqual(firstBody.next_cursor, null);
  assert.deepEqual(calls.filter((call) => new URL(call.url).pathname.endsWith("/audit/events")).map((call) => new URL(call.url).searchParams.get("cursor")), [null, "page-2"]);

  const second = await api.handle(request(`/api/console?resource=activity&limit=2&cursor=${encodeURIComponent(firstBody.next_cursor)}`));
  assert.equal(second.status, 200);
  const secondBody = await second.json();
  assert.deepEqual(secondBody.activity.map((event) => event.event_id), ["event-3", "event-2"]);
  assert.notEqual(secondBody.next_cursor, null);
  assert.deepEqual(calls.filter((call) => new URL(call.url).pathname.endsWith("/audit/events")).map((call) => new URL(call.url).searchParams.get("cursor")), [null, "page-2", null, "page-2", "page-3"]);

  const third = await api.handle(request(`/api/console?resource=activity&limit=2&cursor=${encodeURIComponent(secondBody.next_cursor)}`));
  assert.equal(third.status, 200);
  const thirdBody = await third.json();
  assert.deepEqual(thirdBody.activity.map((event) => event.event_id), ["event-1"]);
  assert.equal(thirdBody.next_cursor, null);
});

test("activity ordering is stable across devices with equal timestamps", async () => {
  const secondDeviceId = "44444444-4444-4444-8444-444444444444";
  const eventsByDevice = new Map([
    [deviceId, [auditEvent("device-1-new", auditTimestamps[3]), auditEvent("device-1-old", auditTimestamps[1])]],
    [secondDeviceId, [auditEvent("device-2-new", auditTimestamps[2], { device_id: secondDeviceId }), auditEvent("device-2-old", auditTimestamps[0], { device_id: secondDeviceId })]],
  ]);
  const { api } = activityFixture({
    deviceIds: [deviceId, secondDeviceId],
    onEventRequest: (url) => ({ events: eventsByDevice.get(url.searchParams.get("device_id")), next_cursor: null }),
  });
  const first = await api.handle(request("/api/console?resource=activity&limit=2"));
  assert.equal(first.status, 200);
  const firstBody = await first.json();
  assert.deepEqual(firstBody.activity.map((event) => event.event_id), ["device-1-new", "device-2-new"]);
  const second = await api.handle(request(`/api/console?resource=activity&limit=2&cursor=${encodeURIComponent(firstBody.next_cursor)}`));
  assert.equal(second.status, 200);
  assert.deepEqual((await second.json()).activity.map((event) => event.event_id), ["device-1-old", "device-2-old"]);
});

test("activity cursors reject tampering and resource or device-scope substitution", async () => {
  const { api } = activityFixture({
    events: [auditEvent("event-1", auditTimestamps[0]), auditEvent("event-2", auditTimestamps[1]), auditEvent("event-3", auditTimestamps[2])],
  });
  const first = await api.handle(request("/api/console?resource=activity&limit=2"));
  const cursor = (await first.json()).next_cursor;
  const parts = cursor.split(".");
  const last = parts[2][0] === "A" ? "B" : "A";
  const tampered = [parts[0], parts[1], `${last}${parts[2].slice(1)}`].join(".");

  const tamperedResponse = await api.handle(request(`/api/console?resource=activity&cursor=${encodeURIComponent(tampered)}`));
  assert.equal(tamperedResponse.status, 400);
  assert.deepEqual(await tamperedResponse.json(), { error: { code: "invalid_cursor", message: "Cursor is invalid" } });

  const resourceSubstitution = await api.handle(request(`/api/console?resource=audit&cursor=${encodeURIComponent(cursor)}`));
  assert.equal(resourceSubstitution.status, 400);
  assert.deepEqual(await resourceSubstitution.json(), { error: { code: "invalid_cursor", message: "Cursor is invalid" } });

  const scopeSubstitution = await api.handle(request(`/api/console?resource=activity&device_id=${deviceId}&cursor=${encodeURIComponent(cursor)}`));
  assert.equal(scopeSubstitution.status, 400);
  assert.deepEqual(await scopeSubstitution.json(), { error: { code: "invalid_cursor", message: "Cursor is invalid" } });
});

test("activity cursor authority is independent from the legacy Cloud bearer", async () => {
  const events = [auditEvent("event-1", auditTimestamps[0]), auditEvent("event-2", auditTimestamps[1]), auditEvent("event-3", auditTimestamps[2])];
  const first = activityFixture({ events }).api;
  const issued = await first.handle(request("/api/console?resource=activity&limit=2"));
  const cursor = (await issued.json()).next_cursor;

  const rotated = activityFixture({ events, apiEnv: { ...env, AGENTPASS_CLOUD_TOKEN: "rotated-server-token-abcdefghijklmnopqrstuvwxyz" } }).api;
  const accepted = await rotated.handle(request(`/api/console?resource=activity&limit=2&cursor=${encodeURIComponent(cursor)}`));
  assert.equal(accepted.status, 200);

  const otherSecretApi = authenticatedApi({
    env: { ...env, AGENTPASS_CONSOLE_CURSOR_SECRET: "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI" },
    fetchImpl: async (url) => {
      const parsed = new URL(url);
      if (parsed.pathname.endsWith("/devices")) return response({ devices: [{ device_id: deviceId }] });
      if (parsed.pathname.endsWith("/audit/events")) return response({ events });
      return response({ health: [] });
    },
  });
  const rejected = await otherSecretApi.handle(request(`/api/console?resource=activity&limit=2&cursor=${encodeURIComponent(cursor)}`));
  assert.equal(rejected.status, 400);
  assert.deepEqual(await rejected.json(), { error: { code: "invalid_cursor", message: "Cursor is invalid" } });

  const unavailable = authenticatedApi({ env: { ...env, AGENTPASS_CONSOLE_CURSOR_SECRET: undefined }, fetchImpl: async () => response({}) });
  const missing = await unavailable.handle(request("/api/console?resource=activity&limit=2"));
  assert.equal(missing.status, 503);
});

test("activity cursors remain traversable when a newer concurrent insert sorts before the position", async () => {
  let currentEvents = [
    auditEvent("event-1", auditTimestamps[0]),
    auditEvent("event-2", auditTimestamps[1]),
    auditEvent("event-3", auditTimestamps[2]),
  ];
  const { api } = activityFixture({ onEventRequest: () => currentEvents });
  const first = await api.handle(request("/api/console?resource=activity&limit=2"));
  const cursor = (await first.json()).next_cursor;
  currentEvents = [...currentEvents, auditEvent("event-4", auditTimestamps[3])];

  const second = await api.handle(request(`/api/console?resource=activity&limit=2&cursor=${encodeURIComponent(cursor)}`));
  assert.equal(second.status, 200);
  const secondBody = await second.json();
  assert.deepEqual(secondBody.activity.map((event) => event.event_id), ["event-1"]);
  assert.equal(secondBody.next_cursor, null);
});

test("activity cursors contain no audit content or secrets and never touch browser storage or logging", async () => {
  const { api } = activityFixture({
    events: [auditEvent("event-1", auditTimestamps[0]), auditEvent("event-2", auditTimestamps[1]), auditEvent("event-3", auditTimestamps[2])],
  });
  const originalLog = console.log;
  const storageDescriptor = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
  let logCalls = 0;
  console.log = () => { logCalls += 1; };
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    get() {
      throw new Error("browser storage must not be accessed");
    },
  });
  try {
    const result = await api.handle(request("/api/console?resource=activity&limit=2"));
    assert.equal(result.status, 200);
    const body = await result.json();
    const cursor = body.next_cursor;
    const payload = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(cursor.split(".")[1].replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - cursor.split(".")[1].length % 4) % 4)), (character) => character.charCodeAt(0))));
    assert.deepEqual(Object.keys(payload).sort(), ["d", "o", "p", "r", "s", "v"]);
    assert.doesNotMatch(JSON.stringify(payload), /allowed-audit-detail|private-repository|payload_digest|secret|token/i);
    assert.doesNotMatch(JSON.stringify(body), new RegExp(env.AGENTPASS_CLOUD_TOKEN));
  } finally {
    console.log = originalLog;
    if (storageDescriptor) Object.defineProperty(globalThis, "localStorage", storageDescriptor);
    else delete globalThis.localStorage;
  }
  assert.equal(logCalls, 0);
});

test("activity no longer treats an exactly full Cloud page as an incomplete window", async () => {
  const saturated = Array.from({ length: 500 }, (_, index) => auditEvent(`event-${index + 1}`, `2026-08-12T00:${String(Math.floor(index / 60)).padStart(2, "0")}:${String(index % 60).padStart(2, "0")}.000Z`));
  const { api } = activityFixture({ events: saturated });
  const result = await api.handle(request("/api/console?resource=activity&limit=2"));
  assert.equal(result.status, 200);
  const body = await result.json();
  assert.deepEqual(body.activity.map((event) => event.event_id), ["event-500", "event-499"]);
  assert.notEqual(body.next_cursor, null);
});

test("activity fails closed when a Cloud stream exceeds the upstream request budget", async () => {
  const event = auditEvent("budget-event", "2026-08-12T00:00:00.000Z");
  const { api, calls } = activityFixture({
    onEventRequest: (url) => {
      const cursor = url.searchParams.get("cursor");
      const page = cursor === null ? 2 : Number(cursor.slice(5)) + 1;
      return { events: [event], next_cursor: `page-${page}` };
    },
  });
  const result = await api.handle(request("/api/console?resource=activity&limit=2"));
  assert.equal(result.status, 502);
  assert.deepEqual(await result.json(), { error: { code: "activity_pagination_budget_exceeded", message: "Activity pagination budget exceeded" } });
  assert.equal(calls.filter((call) => new URL(call.url).pathname.endsWith("/audit/events")).length, 64);
});

test("activity fails closed when accumulated Cloud records exceed the memory bound", async () => {
  const page = Array.from({ length: 500 }, (_, index) => auditEvent(`repeated-${index + 1}`, `2026-08-12T00:${String(Math.floor(index / 60)).padStart(2, "0")}:${String(index % 60).padStart(2, "0")}.000Z`));
  const { api, calls } = activityFixture({
    onEventRequest: (url) => {
      const cursor = url.searchParams.get("cursor");
      const pageNumber = cursor === null ? 2 : Number(cursor.slice(5)) + 1;
      return { events: page, next_cursor: `page-${pageNumber}` };
    },
  });
  const result = await api.handle(request("/api/console?resource=activity&limit=500"));
  assert.equal(result.status, 502);
  assert.deepEqual(await result.json(), { error: { code: "activity_pagination_budget_exceeded", message: "Activity pagination budget exceeded" } });
  assert.equal(calls.filter((call) => new URL(call.url).pathname.endsWith("/audit/events")).length, 17);
});

test("activity derives the immutable position from the Cloud audit record envelope", async () => {
  const wrappedEvent = auditEvent("event-wrapped", auditTimestamps[0]);
  const { api } = activityFixture({
    events: [{ organization_id: env.AGENTPASS_ORGANIZATION_ID, device_id: deviceId, event_id: wrappedEvent.event_id, event: wrappedEvent }],
  });
  const result = await api.handle(request("/api/console?resource=activity&limit=1"));
  assert.equal(result.status, 200);
  const body = await result.json();
  assert.equal(body.activity[0].event.event_id, "event-wrapped");
  assert.equal(body.next_cursor, null);
});

test("bounded list limits are forwarded to Cloud API resources", async () => {
  const calls = [];
  const api = authenticatedApi({
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init });
      const path = new URL(url).pathname;
      if (path.endsWith("/capabilities")) return response({ capabilities: [] });
      if (path.endsWith("/revocations")) return response({ revocations: [] });
      return response({ events: [] });
    },
  });

  for (const [resource, limit, expectedPath] of [
    ["capabilities", "7", "/capabilities"],
    ["revocations", "13", "/revocations"],
    ["admin-audit", "29", "/audit/admin-events"],
  ]) {
    const result = await api.handle(request(`/api/console?resource=${resource}&limit=${limit}`));
    assert.equal(result.status, 200);
    const cloudUrl = new URL(calls.at(-1).url);
    assert.equal(cloudUrl.pathname, `/v1/organizations/${env.AGENTPASS_ORGANIZATION_ID}${expectedPath}`);
    assert.equal(cloudUrl.search, `?limit=${limit}`);
    assert.equal(calls.at(-1).init.cache, "no-store");
  }
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

test("device enrollment requires and forwards recent auth while returning the credential once", async () => {
  let forwarded;
  const credential = "a".repeat(43);
  const api = authenticatedApi({ fetchImpl: async (url, init) => {
    forwarded = { url: String(url), init };
    const input = JSON.parse(init.body);
    return response({ enrollment: { enrollment_id: input.enrollment_id, device_id: input.device_id, label: input.label, platform: input.platform, organization_id: env.AGENTPASS_ORGANIZATION_ID, expires_at: "2026-08-12T00:10:00.000Z", credential, endpoint: `/v1/enrollments/${input.enrollment_id}` } }, 201);
  } });
  const body = JSON.stringify({ label: "Build Mac", platform: "macos", ttl_ms: 600_000 });
  const denied = await api.handle(request("/api/console?operation=issue-device-enrollment", { method: "POST", headers: { "content-type": "application/json", "idempotency-key": "device-enrollment-denied" }, body }));
  assert.equal(denied.status, 401);
  assert.equal(forwarded, undefined);

  const proof = "webauthn-proof-abcdefghijklmnopqrstuvwxyz";
  const result = await api.handle(request("/api/console?operation=issue-device-enrollment", { method: "POST", headers: { "content-type": "application/json", "idempotency-key": "device-enrollment-0001", "agentpass-recent-auth": proof }, body }));
  assert.equal(result.status, 201);
  assert.equal(result.headers.get("cache-control"), "no-store, max-age=0");
  assert.equal(forwarded.init.headers.get("agentpass-recent-auth"), proof);
  assert.match(forwarded.url, /\/device-enrollments$/);
  const payload = await result.json();
  assert.equal(payload.enrollment.credential, credential);
  assert.match(payload.enrollment.enrollment_id, /^[0-9a-f-]{36}$/);
  assert.match(payload.enrollment.device_id, /^[0-9a-f-]{36}$/);
});

test("v2 device enrollment forwards the exact candidate/key binding and returns a strict one-time invitation", async () => {
  const enrollmentId = "78888888-8888-4888-8888-888888888888";
  const deviceId = "41111111-1111-4111-8111-111111111111";
  const candidateId = "candidate-2026-08";
  const fingerprint = `SHA256:${"f".repeat(43)}`;
  const nonce = "b".repeat(43);
  const credential = "a".repeat(43);
  const candidateBinding = {
    version: 1,
    enrollment_id: enrollmentId,
    organization_id: env.AGENTPASS_ORGANIZATION_ID,
    device_id: deviceId,
    candidate_id: candidateId,
    artifact_sha256: "c".repeat(64),
    source_commit: "d".repeat(40),
    team_id: "APPLETEAM1",
    device_key_fingerprint: fingerprint,
    expires_at: "2099-01-01T00:10:00.000Z",
  };
  const challenge = { challenge_id: enrollmentId, nonce, expires_at: candidateBinding.expires_at, candidate_id: candidateId, device_key_fingerprint: fingerprint };
  const invitation = {
    version: 2,
    proof_version: 2,
    enrollment_id: enrollmentId,
    organization_id: env.AGENTPASS_ORGANIZATION_ID,
    device_id: deviceId,
    label: "Build Mac v2",
    platform: "macos",
    candidate_binding: candidateBinding,
    challenge_id: enrollmentId,
    nonce,
    expires_at: candidateBinding.expires_at,
    challenge,
    credential,
    possession_receipt_verification: {
      key_id: "possession-v1",
      algorithm: "ed25519",
      public_key: "-----BEGIN PUBLIC KEY-----\npublic\n-----END PUBLIC KEY-----",
    },
    endpoint: `/v1/enrollments/${enrollmentId}`,
  };
  let forwarded;
  const api = authenticatedApi({ fetchImpl: async (url, init) => {
    forwarded = { url: String(url), init };
    return response({ enrollment: invitation }, 201);
  } });
  const body = { proof_version: 2, candidate_id: candidateId, device_key_fingerprint: fingerprint, label: "Build Mac v2", platform: "macos", ttl_ms: 600_000 };
  const result = await api.handle(request("/api/console?operation=device.enrollment.issue", {
    method: "POST",
    headers: { "content-type": "application/json", "cookie": sessionCookie, "agentpass-csrf": "c".repeat(43), "idempotency-key": "device-enrollment-v2-01", "agentpass-recent-auth": "webauthn-proof-abcdefghijklmnopqrstuvwxyz" },
    body: JSON.stringify(body),
  }));
  assert.equal(result.status, 201);
  assert.equal(result.headers.get("cache-control"), "no-store, max-age=0");
  assert.equal(forwarded.url, `https://cloud.example.test/v1/organizations/${env.AGENTPASS_ORGANIZATION_ID}/device-enrollments`);
  assert.deepEqual(JSON.parse(forwarded.init.body), body);
  assert.equal(forwarded.init.headers.get("agentpass-recent-auth"), "webauthn-proof-abcdefghijklmnopqrstuvwxyz");
  assert.deepEqual(await result.json(), { enrollment: invitation });
});

test("v2 device enrollment rejects tenant drift, unknown receipt fields, and replay without forwarding secrets", async () => {
  const credential = "a".repeat(43);
  const fingerprint = `SHA256:${"f".repeat(43)}`;
  const base = {
    version: 2,
    proof_version: 2,
    enrollment_id: "78888888-8888-4888-8888-888888888888",
    organization_id: env.AGENTPASS_ORGANIZATION_ID,
    device_id: "41111111-1111-4111-8111-111111111111",
    label: "Build Mac v2",
    platform: "macos",
    candidate_binding: {
      version: 1,
      enrollment_id: "78888888-8888-4888-8888-888888888888",
      organization_id: env.AGENTPASS_ORGANIZATION_ID,
      device_id: "41111111-1111-4111-8111-111111111111",
      candidate_id: "candidate-2026-08",
      artifact_sha256: "c".repeat(64),
      source_commit: "d".repeat(40),
      team_id: "APPLETEAM1",
      device_key_fingerprint: fingerprint,
      expires_at: "2099-01-01T00:10:00.000Z",
    },
    challenge_id: "78888888-8888-4888-8888-888888888888",
    nonce: "b".repeat(43),
    expires_at: "2099-01-01T00:10:00.000Z",
    challenge: { challenge_id: "78888888-8888-4888-8888-888888888888", nonce: "b".repeat(43), expires_at: "2099-01-01T00:10:00.000Z", candidate_id: "candidate-2026-08", device_key_fingerprint: fingerprint },
    credential,
    possession_receipt_verification: { key_id: "possession-v1", algorithm: "ed25519", public_key: "-----BEGIN PUBLIC KEY-----\npublic\n-----END PUBLIC KEY-----" },
    endpoint: "/v1/enrollments/78888888-8888-4888-8888-888888888888",
  };
  for (const mutate of [
    (value) => ({ ...value, organization_id: "99999999-9999-4999-8999-999999999999" }),
    (value) => ({ ...value, possession_receipt_verification: { ...value.possession_receipt_verification, secret: "must-not-leak" } }),
    (value) => ({ ...value, candidate_binding: { ...value.candidate_binding, device_key_fingerprint: `SHA256:${"x".repeat(43)}` } }),
    (value) => ({
      ...value,
      candidate_binding: { ...value.candidate_binding, candidate_id: "attacker-release", device_key_fingerprint: `SHA256:${"x".repeat(43)}` },
      challenge: { ...value.challenge, candidate_id: "attacker-release", device_key_fingerprint: `SHA256:${"x".repeat(43)}` },
    }),
  ]) {
    const api = authenticatedApi({ fetchImpl: async () => response({ enrollment: mutate(base) }, 201) });
    const result = await api.handle(request("/api/console?operation=device.enrollment.issue", {
      method: "POST",
      headers: { "content-type": "application/json", "cookie": sessionCookie, "agentpass-csrf": "c".repeat(43), "idempotency-key": "device-enrollment-v2-invalid", "agentpass-recent-auth": "webauthn-proof-abcdefghijklmnopqrstuvwxyz" },
      body: JSON.stringify({ proof_version: 2, candidate_id: "candidate-2026-08", device_key_fingerprint: fingerprint, label: "Build Mac v2", platform: "macos", ttl_ms: 600_000 }),
    }));
    assert.equal(result.status, 502);
    const text = await result.text();
    assert.match(text, /cloud_api_invalid_response/);
    assert.doesNotMatch(text, /must-not-leak|credential|nonce/);
  }
});

test("device enrollment upstream uncertainty remains no-store and never exposes credential material", async () => {
  const secret = "a".repeat(43);
  const api = authenticatedApi({ fetchImpl: async () => response({ error: { code: "upstream_timeout", credential: secret } }, 503) });
  const result = await api.handle(request("/api/console?operation=device.enrollment.issue", {
    method: "POST",
    headers: { "content-type": "application/json", "cookie": sessionCookie, "agentpass-csrf": "c".repeat(43), "idempotency-key": "device-enrollment-uncertain-01", "agentpass-recent-auth": "webauthn-proof-abcdefghijklmnopqrstuvwxyz" },
    body: JSON.stringify({ proof_version: 2, candidate_id: "candidate-2026-08", device_key_fingerprint: `SHA256:${"f".repeat(43)}`, label: "Response Loss Mac", platform: "macos", ttl_ms: 600_000 }),
  }));
  assert.equal(result.status, 503);
  assert.equal(result.headers.get("cache-control"), "no-store");
  const text = await result.text();
  assert.doesNotMatch(text, new RegExp(secret));
  assert.match(text, /upstream_timeout/);
});

test("capability reads expose only tenant-bound lifecycle metadata, never signed authority", async () => {
  const capability = {
    version: 1,
    capability_id: "44444444-4444-4444-8444-444444444444",
    organization_id: env.AGENTPASS_ORGANIZATION_ID,
    issuer: "agentpass-cloud",
    key_id: "capability-key-1",
    agent_id: agentId,
    device_id: deviceId,
    operations: ["git.commit.sign"],
    scope: { operations: ["git.commit.sign"], repositories: ["/work/repo"], branches: { allow: ["main"], deny: [] }, remotes: { allow: ["origin"], deny: [] } },
    nonce: "nonce-must-not-reach-browser",
    capability_hash: "a".repeat(64),
    not_before: "2026-08-12T00:00:00.000Z",
    expires_at: "2026-08-12T00:15:00.000Z",
    sequence: 7,
    issued_at: "2026-08-12T00:00:00.000Z",
    status: "active",
    signature: "signed-authority-must-not-reach-browser",
  };
  const api = authenticatedApi({ fetchImpl: async () => response({ capabilities: [capability] }) });
  const result = await api.handle(request("/api/console?resource=capabilities&limit=100"));
  assert.equal(result.status, 200);
  const resultText = await result.text();
  assert.deepEqual(JSON.parse(resultText), {
    capabilities: [{
      version: 1,
      capability_id: capability.capability_id,
      agent_id: agentId,
      device_id: deviceId,
      expires_at: capability.expires_at,
      sequence: 7,
    }],
  });
  assert.doesNotMatch(resultText, /nonce-must-not-reach-browser|signed-authority/);
});

test("capability reads fail closed on tenant drift, version drift, and unknown fields", async () => {
  const base = {
    version: 1,
    capability_id: "44444444-4444-4444-8444-444444444444",
    organization_id: env.AGENTPASS_ORGANIZATION_ID,
    agent_id: agentId,
    device_id: deviceId,
    expires_at: "2026-08-12T00:15:00.000Z",
    sequence: 1,
  };
  for (const capability of [
    { ...base, organization_id: "55555555-5555-4555-8555-555555555555" },
    { ...base, version: 2 },
    { ...base, unexpected: "must-not-cross-boundary" },
  ]) {
    const api = authenticatedApi({ fetchImpl: async () => response({ capabilities: [capability] }) });
    const result = await api.handle(request("/api/console?resource=capabilities"));
    assert.equal(result.status, 502);
    assert.deepEqual(await result.json(), { error: { code: "cloud_api_invalid_response", message: "Cloud API response was invalid" } });
  }
});

test("capability issuance binds the audience and returns no bearer authority to the UI", async () => {
  const signed = {
    version: 1,
    capability_id: "44444444-4444-4444-8444-444444444444",
    nonce: "nonce-must-not-reach-browser",
    issuer: "agentpass-cloud",
    key_id: "capability-key-1",
    audience: { agent_id: agentId, device_id: deviceId },
    scope: { operations: ["git.commit.sign"], repositories: ["/work/repo"], branches: { allow: ["main"], deny: [] }, remotes: { allow: ["origin"], deny: [] } },
    not_before: "2026-08-12T00:00:00.000Z",
    expires_at: "2026-08-12T00:15:00.000Z",
    sequence: 8,
    signature: "signed-authority-must-not-reach-browser",
  };
  const body = {
    agent_id: agentId,
    device_id: deviceId,
    scope: signed.scope,
    ttl_ms: 900_000,
    sequence: 8,
  };
  const api = authenticatedApi({ fetchImpl: async () => response({ capability: signed }, 201) });
  const result = await api.handle(request("/api/console?operation=issue-capability", {
    method: "POST",
    headers: { "content-type": "application/json", "idempotency-key": "capability-issue-001" },
    body: JSON.stringify(body),
  }));
  assert.equal(result.status, 201);
  const resultText = await result.text();
  assert.deepEqual(JSON.parse(resultText), {
    capability: {
      version: 1,
      capability_id: signed.capability_id,
      agent_id: agentId,
      device_id: deviceId,
      expires_at: signed.expires_at,
      sequence: 8,
    },
  });
  assert.doesNotMatch(resultText, /nonce-must-not-reach-browser|signed-authority/);

  const driftApi = authenticatedApi({ fetchImpl: async () => response({ capability: { ...signed, audience: { agent_id: "55555555-5555-4555-8555-555555555555", device_id: deviceId } } }, 201) });
  const drift = await driftApi.handle(request("/api/console?operation=issue-capability", {
    method: "POST",
    headers: { "content-type": "application/json", "idempotency-key": "capability-issue-002" },
    body: JSON.stringify(body),
  }));
  assert.equal(drift.status, 502);
});

test("operator mutations keep tenant paths, strict schemas, and idempotency", async () => {
  const calls = [];
  const api = authenticatedApi({
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init });
      const path = new URL(url).pathname;
      if (path.endsWith("/capabilities")) {
        return response({ capability: {
          version: 1,
          capability_id: "44444444-4444-4444-8444-444444444444",
          nonce: "nonce",
          issuer: "agentpass-cloud",
          key_id: "capability-key-1",
          audience: { agent_id: agentId, device_id: deviceId },
          scope: { operations: ["git.commit.sign"], repositories: ["/work/repo"], branches: { allow: ["*"], deny: [] }, remotes: { allow: ["*"], deny: [] } },
          not_before: "2026-08-12T00:00:00.000Z",
          expires_at: "2026-08-12T00:15:00.000Z",
          sequence: 1,
          signature: "signature",
        } }, 201);
      }
      return response({ device: { device_id: deviceId } }, 201);
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
