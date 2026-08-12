import assert from "node:assert/strict";
import test from "node:test";
import { createConsoleApi } from "../lib/console-api.mjs";

const organizationId = "11111111-1111-4111-8111-111111111111";
const deviceId = "22222222-2222-4222-8222-222222222222";
const env = Object.freeze({
  AGENTPASS_CLOUD_API_URL: "https://cloud.example.test",
  AGENTPASS_ORGANIZATION_ID: organizationId,
  AGENTPASS_CONSOLE_CURSOR_SECRET: "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE",
});
const sessionCookie = `__Host-agentpass_session=${"s".repeat(43)}`;
const csrf = "c".repeat(43);
const recentAuth = "55555555-5555-4555-8555-555555555555";

function request(path, { method = "GET", body, headers = {} } = {}) {
  return new Request(`https://console.example.test${path}`, {
    method,
    headers: { origin: "https://console.example.test", "content-type": "application/json", ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

function response(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function humanApi(fetchImpl) {
  return createConsoleApi({ env, fetchImpl });
}

test("normalizes the minimal Cloud device state contract", async () => {
  const api = humanApi(async () => response({
    request_id: "request-1",
    devices: [{
      device_id: deviceId,
      name: "Build Mac",
      status: "active",
      created_at: "2026-08-12T00:00:00.000Z",
      version: 4,
      desired_generation: 3,
      observed_generation: 2,
      refresh_state: "applied",
      bundle_sequence: 9,
      bundle_expires_at: "2026-08-12T01:00:00.000Z",
      last_ack_at: "2026-08-12T00:00:05.000Z",
      blocked_reason: null,
    }],
  }));

  const result = await api.handle(request("/api/console?resource=devices", { headers: { cookie: sessionCookie } }));
  assert.equal(result.status, 200);
  assert.deepEqual(await result.json(), {
    devices: [{
      device_id: deviceId,
      name: "Build Mac",
      status: "active",
      created_at: "2026-08-12T00:00:00.000Z",
      version: 4,
      desired_generation: 3,
      observed_generation: 2,
      refresh_state: "applied",
      bundle_sequence: 9,
      bundle_expires_at: "2026-08-12T01:00:00.000Z",
      last_ack_at: "2026-08-12T00:00:05.000Z",
      blocked_reason: null,
    }],
  });
});

test("rejects unknown or secret-bearing device-state shapes before Console output", async () => {
  for (const device of [
    { device_id: deviceId, nonce: "refresh-nonce" },
    { device_id: deviceId, signature: "signed-payload" },
    { device_id: deviceId, policy: { operations: ["git.commit.sign"] } },
    { device_id: deviceId, metadata: { environment: "prod" } },
    { device_id: deviceId, device_public_key: "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----" },
  ]) {
    let calls = 0;
    const api = humanApi(async () => { calls += 1; return response({ devices: [device] }); });
    const result = await api.handle(request("/api/console?resource=devices", { headers: { cookie: sessionCookie } }));
    assert.equal(result.status, 502);
    assert.deepEqual(await result.json(), { error: { code: "cloud_api_invalid_response", message: "Cloud API response was invalid" } });
    assert.equal(calls, 1);
  }
});

test("revoke-device forwards CSRF, idempotency, and recent WebAuthn without widening the body", async () => {
  const calls = [];
  const api = humanApi(async (url, init) => {
    calls.push({ url: String(url), init });
    return response({
      request_id: "request-revoke-1",
      revocation: {
        revocation_id: "33333333-3333-4333-8333-333333333333",
        organization_id: organizationId,
        target_type: "device",
        target_id: deviceId,
        reason: "lost",
        status: "active",
        version: 1,
      },
    }, 201);
  });
  const key = "revoke-device-replay-safe-01";
  const result = await api.handle(request("/api/console?operation=revoke-device", {
    method: "POST",
    headers: { cookie: sessionCookie, "agentpass-csrf": csrf, "idempotency-key": key, "agentpass-recent-auth": recentAuth },
    body: { target_id: deviceId, reason: "lost" },
  }));
  assert.equal(result.status, 201);
  assert.deepEqual(await result.json(), { revocation: { revocation_id: "33333333-3333-4333-8333-333333333333", target_type: "device", target_id: deviceId, reason: "lost", status: "active", version: 1 } });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, `https://cloud.example.test/v1/organizations/${organizationId}/devices/${deviceId}/revoke`);
  assert.equal(calls[0].init.headers.get("cookie"), sessionCookie);
  assert.equal(calls[0].init.headers.get("agentpass-csrf"), csrf);
  assert.equal(calls[0].init.headers.get("idempotency-key"), key);
  assert.equal(calls[0].init.headers.get("agentpass-recent-auth"), recentAuth);
  assert.equal(calls[0].init.headers.has("authorization"), false);
  assert.deepEqual(JSON.parse(calls[0].init.body), { reason: "lost" });
});

test("revoke-device fails closed without recent WebAuthn or valid CSRF", async () => {
  let calls = 0;
  const api = humanApi(async () => { calls += 1; return response({}); });
  const missingAuth = await api.handle(request("/api/console?operation=revoke-device", {
    method: "POST",
    headers: { cookie: sessionCookie, "agentpass-csrf": csrf, "idempotency-key": "revoke-device-auth-01" },
    body: { target_id: deviceId, reason: "lost" },
  }));
  assert.equal(missingAuth.status, 401);
  const missingCsrf = await api.handle(request("/api/console?operation=revoke-device", {
    method: "POST",
    headers: { cookie: sessionCookie, "idempotency-key": "revoke-device-csrf-01", "agentpass-recent-auth": recentAuth },
    body: { target_id: deviceId, reason: "lost" },
  }));
  assert.equal(missingCsrf.status, 403);
  assert.equal(calls, 0);
});

test("request-refresh forwards only an empty Cloud body and normalizes the 202 wake response", async () => {
  const calls = [];
  const api = humanApi(async (url, init) => {
    calls.push({ url: String(url), init });
    return response({
      request_id: "request-refresh-1",
      refresh_request: {
        version: 1,
        request_id: "refresh-request-1",
        device_id: deviceId,
        desired_generation: null,
        status: "accepted",
        requested_at: "2026-08-13T00:00:00.000Z",
      },
    }, 202);
  });
  const result = await api.handle(request("/api/console?operation=device.request-refresh", {
    method: "POST",
    headers: { cookie: sessionCookie, "agentpass-csrf": csrf, "idempotency-key": "request-refresh-01", "agentpass-recent-auth": recentAuth },
    body: { target_id: deviceId },
  }));
  assert.equal(result.status, 202);
  assert.deepEqual(await result.json(), {
    request_id: "request-refresh-1",
    refresh_request: {
      version: 1,
      request_id: "refresh-request-1",
      device_id: deviceId,
      desired_generation: null,
      status: "accepted",
      requested_at: "2026-08-13T00:00:00.000Z",
    },
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, `https://cloud.example.test/v1/organizations/${organizationId}/devices/${deviceId}/refresh-requests`);
  assert.equal(calls[0].init.headers.get("idempotency-key"), "request-refresh-01");
  assert.equal(calls[0].init.headers.get("agentpass-recent-auth"), recentAuth);
  assert.equal(calls[0].init.headers.get("cookie"), sessionCookie);
  assert.equal(calls[0].init.headers.get("agentpass-csrf"), csrf);
  assert.deepEqual(JSON.parse(calls[0].init.body), {});
});

test("request-refresh requires operation-bound WebAuthn and rejects authority or secret fields", async () => {
  let calls = 0;
  const api = humanApi(async () => { calls += 1; return response({}); });
  for (const body of [
    {},
    { target_id: deviceId, generation: 4 },
    { target_id: deviceId, outbox: true },
    { target_id: deviceId, nonce: "refresh-nonce" },
    { target_id: deviceId, bundle: { sequence: 1 } },
    { target_id: deviceId, policy: { operations: ["git.commit.sign"] } },
    { target_id: deviceId, secret: "must-not-forward" },
  ]) {
    const result = await api.handle(request("/api/console?operation=device.refresh.request", {
      method: "POST",
      headers: { cookie: sessionCookie, "agentpass-csrf": csrf, "idempotency-key": `request-refresh-${calls + 10}`, "agentpass-recent-auth": recentAuth },
      body,
    }));
    assert.equal(result.status, 400);
  }
  const missingAuth = await api.handle(request("/api/console?operation=device.refresh.request", {
    method: "POST",
    headers: { cookie: sessionCookie, "agentpass-csrf": csrf, "idempotency-key": "request-refresh-no-auth" },
    body: { target_id: deviceId },
  }));
  assert.equal(missingAuth.status, 401);
  assert.equal(calls, 0);
});

test("request-refresh rejects a non-202 or secret-bearing Cloud response", async () => {
  const api = humanApi(async () => response({
    request_id: "request-refresh-2",
    refresh_request: {
      version: 1,
      request_id: "refresh-request-2",
      device_id: deviceId,
      desired_generation: 4,
      status: "accepted",
      requested_at: "2026-08-13T00:00:00.000Z",
      nonce: "must-not-leak",
    },
  }, 200));
  const result = await api.handle(request("/api/console?operation=request-refresh", {
    method: "POST",
    headers: { cookie: sessionCookie, "agentpass-csrf": csrf, "idempotency-key": "request-refresh-response-01", "agentpass-recent-auth": recentAuth },
    body: { target_id: deviceId },
  }));
  assert.equal(result.status, 502);
  const body = await result.text();
  assert.match(body, /cloud_api_invalid_response/);
  assert.doesNotMatch(body, /must-not-leak|nonce/);
});

test("revoke-device rejects malformed or secret-bearing Cloud action responses", async () => {
  const api = humanApi(async () => response({
    revocation: { target_id: deviceId, nonce: "must-not-leak", status: "active" },
  }, 201));
  const result = await api.handle(request("/api/console?operation=revoke-device", {
    method: "POST",
    headers: { cookie: sessionCookie, "agentpass-csrf": csrf, "idempotency-key": "revoke-device-response-01", "agentpass-recent-auth": recentAuth },
    body: { target_id: deviceId, reason: "lost" },
  }));
  assert.equal(result.status, 502);
  const body = await result.text();
  assert.match(body, /cloud_api_invalid_response/);
  assert.doesNotMatch(body, /must-not-leak|nonce/);
});
