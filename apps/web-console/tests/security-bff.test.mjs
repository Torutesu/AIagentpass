import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { createHumanAuthBridge } from "../lib/human-auth-api.mjs";

const env = Object.freeze({ AGENTPASS_CLOUD_API_URL: "https://cloud.example.test" });
const cookie = "__Host-agentpass_session=" + "A".repeat(43);
const csrf = "B".repeat(43);
const credentialId = "A".repeat(22);
const sessionId = "11111111-1111-4111-8111-111111111111";
const authorizationId = "55555555-5555-4555-8555-555555555555";

function request(path, { method = "GET", body, headers = {} } = {}) {
  return new Request(`https://console.example.test${path}`, { method, headers: { origin: "https://console.example.test", "content-type": "application/json", ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
}

function bridge(fetchImpl) { return createHumanAuthBridge({ env, fetchImpl, getSiwcUser: async () => ({ userId: "operator-1" }) }); }
function credentialMutation(status = "active", version = 3, label = "仕事用") { return { credential: { credential_id: credentialId, version, label, transports: ["internal"], backup_eligible: false, backup_state: false, status, created_at: "2026-08-12T00:00:00.000Z", last_used_at: null, revoked_at: status === "revoked" ? "2026-08-12T01:00:00.000Z" : null } }; }
function contextHash(version) { return createHash("sha256").update(`{"credential_id":${JSON.stringify(credentialId)},"expected_version":${version},"operation":"human.management.credential.revoke","version":1}`, "utf8").digest("hex"); }

test("maps Security BFF paths to Cloud management paths and forwards session controls", async () => {
  const calls = [];
  const api = bridge(async (url, init) => {
    calls.push({ url: String(url), init });
    return new Response(JSON.stringify(String(url).includes(`/credentials/${credentialId}`) ? credentialMutation() : { credentials: [], next_cursor: null }), { headers: { "content-type": "application/json" } });
  });
  const response = await api.handle(request("/api/auth/security/passkeys", { headers: { cookie, "agentpass-csrf": csrf } }));
  assert.equal(response.status, 200);
  assert.equal(calls[0].url, "https://cloud.example.test/api/auth/management/credentials");
  assert.equal(calls[0].init.method, "GET");
  assert.equal(calls[0].init.headers.has("authorization"), false);
  assert.equal(calls[0].init.headers.has("agentpass-console-user-id"), false);
  assert.equal(calls[0].init.headers.get("cookie"), cookie);
  assert.equal(calls[0].init.headers.get("agentpass-csrf"), csrf);

  await api.handle(request(`/api/auth/security/passkeys/${credentialId}`, { method: "PATCH", body: { label: "仕事用" }, headers: { cookie, "agentpass-csrf": csrf, "if-match": '"2"', "idempotency-key": "rename-bff-01" } }));
  assert.equal(calls[1].url, `https://cloud.example.test/api/auth/management/credentials/${credentialId}`);
  assert.equal(calls[1].init.method, "PATCH");
  assert.equal(calls[1].init.headers.get("if-match"), '"2"');
  assert.deepEqual(JSON.parse(new TextDecoder().decode(calls[1].init.body)), { label: "仕事用" });
  assert.equal(calls[1].init.headers.get("idempotency-key"), "rename-bff-01");

  await api.handle(request(`/api/auth/security/sessions/${sessionId}/revoke`, { method: "POST", body: { expected_version: 4 }, headers: { cookie, "agentpass-csrf": csrf } }));
  assert.equal(calls[2].url, `https://cloud.example.test/api/auth/management/sessions/${sessionId}/revoke`);
  assert.equal(calls[2].init.method, "POST");

  await api.handle(request("/api/auth/security/sessions/revoke-others", { method: "POST", body: {}, headers: { cookie, "agentpass-csrf": csrf, "agentpass-recent-auth": authorizationId } }));
  assert.equal(calls[3].url, "https://cloud.example.test/api/auth/management/sessions/revoke-others");
  assert.equal(calls[3].init.method, "POST");
  assert.equal(calls[3].init.headers.get("agentpass-recent-auth"), authorizationId);
  assert.deepEqual(JSON.parse(new TextDecoder().decode(calls[3].init.body)), {});
});

test("fails closed before Cloud for missing session controls or malformed management input", async () => {
  let calls = 0;
  const api = bridge(async () => { calls += 1; return new Response("{}", { headers: { "content-type": "application/json" } }); });
  assert.equal((await api.handle(request("/api/auth/security/sessions", { headers: { "agentpass-csrf": csrf } }))).status, 401);
  assert.equal((await api.handle(request(`/api/auth/security/passkeys/${credentialId}`, { method: "PATCH", body: { label: "x" }, headers: { cookie, "agentpass-csrf": csrf } }))).status, 400);
  assert.equal((await api.handle(request(`/api/auth/security/passkeys/${credentialId}/revoke`, { method: "POST", body: {}, headers: { cookie, "agentpass-csrf": csrf } }))).status, 401);
  assert.equal((await api.handle(request("/api/auth/security/sessions/revoke-others", { method: "POST", body: {}, headers: { cookie, "agentpass-csrf": csrf } }))).status, 401);
  assert.equal((await api.handle(request("/api/auth/security/sessions/revoke-others", { method: "POST", body: { session_ids: [sessionId] }, headers: { cookie, "agentpass-csrf": csrf, "agentpass-recent-auth": authorizationId } }))).status, 400);
  assert.equal(calls, 0);
});

test("forwards only an allow-listed session clear cookie", async () => {
  const api = bridge(async () => new Response(JSON.stringify({ session: {} }), { headers: { "content-type": "application/json", "set-cookie": "__Host-agentpass_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" } }));
  const response = await api.handle(request(`/api/auth/security/sessions/${sessionId}/revoke`, { method: "POST", body: { expected_version: 1 }, headers: { cookie, "agentpass-csrf": csrf } }));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("set-cookie"), "__Host-agentpass_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0");
});

test("rejects session replacement cookies from a revoke response", async () => {
  const api = bridge(async () => new Response(JSON.stringify({ session: {} }), { headers: { "content-type": "application/json", "set-cookie": `__Host-agentpass_session=${"C".repeat(43)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600` } }));
  const response = await api.handle(request(`/api/auth/security/sessions/${sessionId}/revoke`, { method: "POST", body: { expected_version: 1 }, headers: { cookie, "agentpass-csrf": csrf } }));
  assert.equal(response.status, 502);
  assert.equal(response.headers.get("set-cookie"), null);
});

test("forwards recent auth only to protected Security mutations", async () => {
  const calls = [];
  const api = bridge(async (url, init) => {
    calls.push({ url: String(url), init });
    return new Response(JSON.stringify(credentialMutation("revoked", 2)), { headers: { "content-type": "application/json" } });
  });
  const path = `/api/auth/security/passkeys/${credentialId}/revoke`;
  const missing = await api.handle(request(path, { method: "POST", body: {}, headers: { cookie, "agentpass-csrf": csrf, "idempotency-key": "revoke-bff-02", "if-match": '"1"' } }));
  assert.equal(missing.status, 401);
  assert.equal(calls.length, 0);

  const response = await api.handle(request(path, { method: "POST", body: {}, headers: { cookie, "agentpass-csrf": csrf, "idempotency-key": "revoke-bff-01", "if-match": '"1"', "agentpass-recent-auth": authorizationId, "agentpass-recent-auth-context": contextHash(1) } }));
  assert.equal(response.status, 200);
  assert.equal(calls[0].init.headers.get("agentpass-recent-auth"), authorizationId);

  const leaked = await api.handle(request("/api/auth/security/passkeys", { headers: { cookie, "agentpass-csrf": csrf, "agentpass-recent-auth": authorizationId } }));
  assert.equal(leaked.status, 400);
  assert.equal(calls.length, 1);
});

test("does not treat revoke-others as a per-session UUID route", async () => {
  const calls = [];
  const api = bridge(async (url, init) => {
    calls.push({ url: String(url), init });
    return new Response(JSON.stringify({ revoked_sessions: [], revoked_count: 0, truncated: false }), { headers: { "content-type": "application/json" } });
  });

  const response = await api.handle(request("/api/auth/security/sessions/revoke-others", { method: "POST", body: {}, headers: { cookie, "agentpass-csrf": csrf, "agentpass-recent-auth": authorizationId } }));
  assert.equal(response.status, 200);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://cloud.example.test/api/auth/management/sessions/revoke-others");
});
