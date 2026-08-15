import assert from "node:assert/strict";
import test from "node:test";

import {
  createHostedBootstrapClient,
  HostedBootstrapClientError,
  HOSTED_BOOTSTRAP_CLIENT_PATHS,
} from "../lib/hosted-bootstrap-client.mjs";

const csrfToken = "C".repeat(43);
const challengeId = "11111111-1111-4111-8111-111111111111";
const organizationId = "22222222-2222-4222-8222-222222222222";
const memberId = "33333333-3333-4333-8333-333333333333";
const sessionId = "44444444-4444-4444-8444-444444444444";
const timestamp = "2026-08-15T00:00:00.000Z";
const credential = Object.freeze({
  id: "A".repeat(22), rawId: "A".repeat(22), type: "public-key", clientExtensionResults: {},
  response: { clientDataJSON: "Y2xpZW50LWRhdGE", attestationObject: "YXR0ZXN0YXRpb24" },
});
const options = Object.freeze({
  rp: { id: "console.example.test", name: "AgentPass Console" },
  user: { id: "dXNlci0x", name: "operator@example.test", displayName: "Operator" },
  challenge: "B".repeat(43), pubKeyCredParams: [{ type: "public-key", alg: -7 }],
  authenticatorSelection: { userVerification: "required" }, attestation: "none", excludeCredentials: [],
});

function jsonResponse(body, status = 200) { return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }); }
function statusBody(overrides = {}) {
  return { version: 1, state: "organization_required", webauthn_required: false, can_create_first_organization: true, organization_count: 0, csrf_token: csrfToken, expires_at: timestamp, ...overrides };
}
function sessionBody() {
  return { version: 1, state: "completed", csrf_token: csrfToken, session: { version: 1, session_id: sessionId, member_id: memberId, organization_id: organizationId, role: "owner", created_at: timestamp, expires_at: "2026-08-15T01:00:00.000Z", recent_auth_at: null } };
}
function organizationBody() {
  return { version: 1, organization: { organization_id: organizationId, name: "First Org", version: 1, created_at: timestamp, updated_at: timestamp }, onboarding: { state: "webauthn_required" } };
}

test("returns only the public camelCase status DTO while retaining CSRF in the closure", async () => {
  const calls = [];
  const client = createHostedBootstrapClient({ fetchImpl: async (url, init) => { calls.push({ url: String(url), init }); return jsonResponse(statusBody()); } });
  const result = await client.status({ signal: new AbortController().signal });
  assert.deepEqual(result, { state: "organization_required", webauthnRequired: false, canCreateFirstOrganization: true, organizationCount: 0, expiresAt: timestamp });
  assert.deepEqual(Object.keys(result).sort(), ["canCreateFirstOrganization", "expiresAt", "organizationCount", "state", "webauthnRequired"].sort());
  assert.equal(Object.hasOwn(result, "csrf_token"), false);
  assert.equal(calls[0].init.credentials, "include");
  assert.equal(calls[0].init.redirect, "error");
  assert.equal(Object.hasOwn(client, "csrfToken"), false);
  assert.equal(Object.hasOwn(globalThis, "localStorage"), false);
});

test("posts organization creation with in-memory CSRF and returns only the organization DTO", async () => {
  const calls = [];
  const client = createHostedBootstrapClient({ fetchImpl: async (url, init) => { calls.push({ url: String(url), init }); return String(url) === HOSTED_BOOTSTRAP_CLIENT_PATHS.status ? jsonResponse(statusBody()) : jsonResponse(organizationBody(), 201); } });
  await client.status();
  const result = await client.createOrganization({ name: "First Org", idempotencyKey: "bootstrap-create-1" });
  assert.deepEqual(result, organizationBody().organization);
  assert.deepEqual(JSON.parse(calls[1].init.body), { name: "First Org" });
  assert.equal(calls[1].init.credentials, "include");
  assert.equal(calls[1].init.headers.get("agentpass-bootstrap-csrf"), csrfToken);
  assert.equal(calls[1].init.headers.get("idempotency-key"), "bootstrap-create-1");
});

test("registerPasskey runs options, WebAuthn, and verify and returns only the public session DTO", async () => {
  const calls = [];
  const registrationCalls = [];
  const client = createHostedBootstrapClient({
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init });
      const path = new URL(String(url), "https://console.example.test").pathname;
      if (path === HOSTED_BOOTSTRAP_CLIENT_PATHS.status) return jsonResponse(statusBody({ state: "webauthn_required", can_create_first_organization: false, webauthn_required: true }));
      if (path === HOSTED_BOOTSTRAP_CLIENT_PATHS.webauthnOptions) return jsonResponse({ challenge_id: challengeId, options });
      return jsonResponse(sessionBody(), 201);
    },
    startRegistrationImpl: async (input) => { registrationCalls.push(input); return credential; },
  });
  await client.status();
  const result = await client.registerPasskey();
  assert.deepEqual(result, sessionBody().session);
  assert.deepEqual(registrationCalls, [{ optionsJSON: options }]);
  assert.deepEqual(JSON.parse(calls[2].init.body), { challenge_id: challengeId, credential });
  assert.equal(calls[1].init.headers.get("agentpass-bootstrap-csrf"), csrfToken);
  assert.equal(calls[2].init.headers.get("agentpass-bootstrap-csrf"), csrfToken);
});

test("serializes a native WebAuthn credential's ArrayBuffers to base64url", async () => {
  const nativeCredential = {
    id: "AAAAAAAAAAAAAAAAAAAAAA", rawId: Uint8Array.from(new Array(16).fill(0)).buffer, type: "public-key",
    response: { clientDataJSON: Uint8Array.from([99, 108, 105, 101, 110, 116, 45, 100, 97, 116, 97]).buffer, attestationObject: Uint8Array.from([97, 116, 116, 101, 115, 116, 97, 116, 105, 111, 110]).buffer, getTransports: () => ["internal"] },
    getClientExtensionResults: () => ({}), authenticatorAttachment: null,
  };
  const client = createHostedBootstrapClient({
    fetchImpl: async (url, init) => {
      const path = new URL(String(url), "https://console.example.test").pathname;
      if (path === HOSTED_BOOTSTRAP_CLIENT_PATHS.status) return jsonResponse(statusBody());
      if (path === HOSTED_BOOTSTRAP_CLIENT_PATHS.webauthnOptions) return jsonResponse({ challenge_id: challengeId, options });
      const posted = JSON.parse(init.body).credential;
      assert.equal(posted.id, nativeCredential.id); assert.equal(posted.rawId, posted.id);
      assert.equal(posted.response.clientDataJSON, "Y2xpZW50LWRhdGE"); assert.equal(posted.response.attestationObject, "YXR0ZXN0YXRpb24");
      return jsonResponse(sessionBody(), 201);
    },
    startRegistrationImpl: async () => nativeCredential,
  });
  await client.status();
  await client.registerPasskey();
});

test("requires status before mutating and rejects strict response violations including duplicate JSON keys", async () => {
  const client = createHostedBootstrapClient({ fetchImpl: async () => jsonResponse(statusBody()) });
  await assert.rejects(() => client.createOrganization({ name: "x" }), (error) => error instanceof HostedBootstrapClientError && error.code === "csrf_required");
  const malformed = createHostedBootstrapClient({ fetchImpl: async () => new Response('{"version":1,"state":"organization_required","webauthn_required":false,"can_create_first_organization":true,"organization_count":0,"csrf_token":"' + csrfToken + '","expires_at":"' + timestamp + '","state":"expired"}', { headers: { "content-type": "application/json" } }) });
  await assert.rejects(() => malformed.status(), (error) => error instanceof HostedBootstrapClientError && error.code === "invalid_response");
});

test("validates GitHub redirects without exposing cookies to JavaScript", async () => {
  const calls = [];
  const client = createHostedBootstrapClient({ fetchImpl: async (url, init) => { calls.push({ url: String(url), init }); return new Response(null, { status: 302, headers: { location: "https://github.com/login/oauth/authorize?client_id=client&response_type=code&redirect_uri=https%3A%2F%2Fconsole.example.test%2Fapi%2Fauth%2Fbootstrap%2Fgithub%2Fcallback&scope=read%3Auser&state=" + "S".repeat(16) + "&code_challenge=" + "C".repeat(43) + "&code_challenge_method=S256", "set-cookie": "__Host-agentpass_github_state=secret; HttpOnly" } }); } });
  const result = await client.githubStart();
  assert.match(result.location, /^https:\/\/github\.com\//u); assert.equal(calls[0].init.credentials, "include"); assert.equal(calls[0].init.redirect, "manual"); assert.equal(Object.hasOwn(result, "setCookie"), false);
});

test("exposes known server error codes through serverCode without exposing raw details", async () => {
  const client = createHostedBootstrapClient({ fetchImpl: async () => jsonResponse({ error: { code: "bootstrap_session_required", message: "A valid bootstrap session is required" } }, 401) });
  await assert.rejects(() => client.status(), (error) => error instanceof HostedBootstrapClientError && error.code === "server_rejected" && error.serverCode === "bootstrap_session_required" && error.status === 401);
});

test("propagates aborts as a stable client error", async () => {
  const controller = new AbortController(); controller.abort();
  const client = createHostedBootstrapClient({ fetchImpl: async () => { throw new DOMException("aborted", "AbortError"); } });
  await assert.rejects(() => client.status({ signal: controller.signal }), (error) => error instanceof HostedBootstrapClientError && error.code === "aborted");
});
