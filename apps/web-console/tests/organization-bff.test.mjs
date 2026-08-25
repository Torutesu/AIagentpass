import assert from "node:assert/strict";
import test from "node:test";

import { createHumanAuthBridge } from "../lib/human-auth-api.mjs";

const env = Object.freeze({ AGENTPASS_CLOUD_API_URL: "https://cloud.example.test" });
const organizationId = "11111111-1111-4111-8111-111111111111";
const memberId = "22222222-2222-4222-8222-222222222222";
const invitationId = "33333333-3333-4333-8333-333333333333";
const recentAuth = "44444444-4444-4444-8444-444444444444";
const cookie = `__Host-agentpass_session=${"A".repeat(43)}`;
const csrf = "B".repeat(43);
const idempotency = "organization-operation-1";
const token = "C".repeat(43);

function request(path, { method = "GET", body, headers = {} } = {}) {
  return new Request(`https://console.example.test${path}`, {
    method,
    headers: { origin: "https://console.example.test", "content-type": "application/json", cookie, "agentpass-csrf": csrf, ...headers },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
}

function bridge(fetchImpl) {
  return createHumanAuthBridge({ env, fetchImpl, getSiwcUser: async () => ({ userId: "operator-1" }) });
}

test("forwards only the exact Organization API allow-list with bounded query and mutation controls", async () => {
  const calls = [];
  const api = bridge(async (url, init) => {
    calls.push({ url: String(url), init });
    return new Response(JSON.stringify({ ok: true }), { status: init.method === "POST" ? 201 : 200, headers: { "content-type": "application/json" } });
  });
  const mutation = { "idempotency-key": idempotency };
  const protectedMutation = { ...mutation, "agentpass-recent-auth": recentAuth };
  const cases = [
    ["/api/auth/organizations?cursor=next_page&limit=25", "GET", undefined, {}, "https://cloud.example.test/api/auth/organizations?limit=25&cursor=next_page"],
    ["/api/auth/organizations", "POST", { name: "AgentPass Team" }, mutation, "https://cloud.example.test/api/auth/organizations"],
    [`/api/auth/organizations/${organizationId}`, "PATCH", { name: "Renamed" }, { ...mutation, "if-match": '"2"' }, `https://cloud.example.test/api/auth/organizations/${organizationId}`],
    [`/api/auth/organizations/${organizationId}/members?limit=10`, "GET", undefined, {}, `https://cloud.example.test/api/auth/organizations/${organizationId}/members?limit=10`],
    [`/api/auth/organizations/${organizationId}/members/${memberId}/role`, "PATCH", { role: "admin" }, { ...protectedMutation, "if-match": '"3"' }, `https://cloud.example.test/api/auth/organizations/${organizationId}/members/${memberId}/role`],
    [`/api/auth/organizations/${organizationId}/members/${memberId}/remove`, "POST", undefined, { ...protectedMutation, "if-match": '"4"' }, `https://cloud.example.test/api/auth/organizations/${organizationId}/members/${memberId}/remove`],
    [`/api/auth/organizations/${organizationId}/invitations`, "GET", undefined, {}, `https://cloud.example.test/api/auth/organizations/${organizationId}/invitations`],
    [`/api/auth/organizations/${organizationId}/invitations`, "POST", { role: "viewer", expires_at: "2026-08-19T00:00:00.000Z" }, mutation, `https://cloud.example.test/api/auth/organizations/${organizationId}/invitations`],
    [`/api/auth/organizations/${organizationId}/invitations/${invitationId}/revoke`, "POST", undefined, { ...protectedMutation, "if-match": '"1"' }, `https://cloud.example.test/api/auth/organizations/${organizationId}/invitations/${invitationId}/revoke`],
    ["/api/auth/invitations/accept", "POST", { one_time_token: token }, mutation, "https://cloud.example.test/api/auth/invitations/accept"]
  ];
  for (const [path, method, body, headers, cloudUrl] of cases) {
    const response = await api.handle(request(path, { method, body, headers }));
    assert.ok(response.status === 200 || response.status === 201, `${method} ${path}`);
    const call = calls.at(-1);
    assert.equal(call.url, cloudUrl);
    assert.equal(call.init.method, method);
    assert.equal(call.init.headers.has("authorization"), false);
    assert.equal(call.init.headers.has("agentpass-console-user-id"), false);
    assert.equal(call.init.headers.get("cookie"), cookie);
    assert.equal(call.init.headers.get("agentpass-csrf"), csrf);
    assert.equal(call.init.headers.get("idempotency-key"), headers["idempotency-key"] ?? null);
    assert.equal(call.init.headers.get("agentpass-recent-auth"), headers["agentpass-recent-auth"] ?? null);
  }
});

test("fails closed before Cloud for route, query, schema, idempotency, and recent-auth substitution", async () => {
  let calls = 0;
  const api = bridge(async () => { calls += 1; return new Response("{}", { headers: { "content-type": "application/json" } }); });
  const invalid = [
    request("/api/auth/organizations/not-a-uuid/members"),
    request("/api/auth/organizations?limit=101"),
    request(`/api/auth/organizations?organization_id=${organizationId}`),
    request("/api/auth/organizations?cursor=a&cursor=b"),
    request(`/api/auth/organizations/${organizationId}?limit=1`, { method: "PATCH", body: { name: "x", expected_version: 1 }, headers: { "idempotency-key": idempotency } }),
    request("/api/auth/organizations", { method: "POST", body: { name: "x" } }),
    request(`/api/auth/organizations/${organizationId}/members/${memberId}/role`, { method: "PATCH", body: { role: "owner", expected_version: 1 }, headers: { "idempotency-key": idempotency } }),
    request(`/api/auth/organizations/${organizationId}/invitations/${invitationId}/revoke`, { method: "POST", headers: { "idempotency-key": idempotency, "if-match": '"1"' } }),
    request(`/api/auth/organizations/${organizationId}/invitations`, { method: "POST", body: { role: "owner", expires_at: "2026-08-19T00:00:00.000Z" }, headers: { "idempotency-key": idempotency } }),
    request("/api/auth/invitations/accept", { method: "POST", body: { one_time_token: "short" }, headers: { "idempotency-key": idempotency } }),
    request("/api/auth/organizations", { headers: { "agentpass-recent-auth": recentAuth } }),
    request("/api/auth/organizations", { headers: { "idempotency-key": idempotency } })
  ];
  for (const item of invalid) assert.ok((await api.handle(item)).status >= 400);
  assert.equal(calls, 0);
});

test("forwards If-Match only for versioned Organization mutations", async () => {
  const calls = [];
  const api = bridge(async (url, init) => {
    calls.push({ url: String(url), init });
    return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
  });
  const path = `/api/auth/organizations/${organizationId}`;
  const response = await api.handle(request(path, {
    method: "PATCH",
    body: { name: "Renamed" },
    headers: { "idempotency-key": idempotency, "if-match": '"2"' },
  }));
  assert.equal(response.status, 200);
  assert.equal(calls[0].init.headers.get("if-match"), '"2"');

  const rejected = await api.handle(request("/api/auth/organizations", {
    headers: { "if-match": '"1"' },
  }));
  assert.equal(rejected.status, 400);
  assert.equal(calls.length, 1);

  const malformed = await api.handle(request(path, {
    method: "PATCH",
    body: { name: "Renamed" },
    headers: { "idempotency-key": idempotency, "if-match": "2" },
  }));
  assert.equal(malformed.status, 400);
  assert.equal(calls.length, 1);
});

test("never relays invitation or session cookies from Organization responses", async () => {
  const api = bridge(async () => new Response(JSON.stringify({ invitation: {}, one_time_token: token }), { status: 201, headers: { "content-type": "application/json", "set-cookie": "unexpected=value" } }));
  const response = await api.handle(request(`/api/auth/organizations/${organizationId}/invitations`, { method: "POST", body: { role: "viewer", expires_at: "2026-08-19T00:00:00.000Z" }, headers: { "idempotency-key": idempotency } }));
  assert.equal(response.status, 502);
  assert.equal(response.headers.get("set-cookie"), null);
  assert.doesNotMatch(await response.text(), new RegExp(token));
});
