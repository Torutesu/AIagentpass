import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  createOwnerRecoveryClient,
  getOwnerRecoveryVisibility,
  handleOwnerRecoveryRequest,
} from "../lib/owner-recovery-api.mjs";

const ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111";
const MEMBER_ID = "22222222-2222-4222-8222-222222222222";
const REQUEST_ID = "33333333-3333-4333-8333-333333333333";
const SESSION_ID = "44444444-4444-4444-8444-444444444444";
const CHALLENGE_ID = "55555555-5555-4555-8555-555555555555";
const ACTIVATION_CHALLENGE_ID = "66666666-6666-4666-8666-666666666666";
const CSRF = "c".repeat(43);
const EXCHANGE = "e".repeat(43);
const SESSION_COOKIE = `__Host-agentpass_session=${"s".repeat(43)}`;
const RECOVERY_COOKIE = `__Host-agentpass_recovery_session=${"r".repeat(43)}`;
const DATE = "2099-01-01T00:00:00.000Z";

function recovery(state = "pending") {
  return {
    schema_version: 1,
    kind: "threshold-owner-recovery",
    request_id: REQUEST_ID,
    organization_id: ORGANIZATION_ID,
    subject_member_id: MEMBER_ID,
    state,
    threshold: 2,
    approved_owner_count: 0,
    approved_at: null,
    delay_until: null,
    session_issued_at: null,
    credential_enrolled_at: null,
    activated_at: null,
    expires_at: DATE,
    terminal_reason: null,
    version: 1,
    created_at: DATE,
    updated_at: DATE,
  };
}

function sessionResponse() {
  return {
    session: {
      version: 1,
      session_id: SESSION_ID,
      member_id: MEMBER_ID,
      organization_id: ORGANIZATION_ID,
      role: "owner",
      created_at: DATE,
      expires_at: DATE,
      recent_auth_at: null,
    },
    csrf_token: CSRF,
  };
}

function request(path, { method = "POST", body = {}, headers = {} } = {}) {
  return new Request(`https://console.example.test${path}`, {
    method,
    headers: {
      origin: "https://console.example.test",
      "content-type": "application/json",
      cookie: SESSION_COOKIE,
      "agentpass-csrf": CSRF,
      ...headers,
    },
    body: method === "GET" ? undefined : JSON.stringify(body),
  });
}

function json(value, status = 200, headers = {}) {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json", ...headers } });
}

test("recovery visibility has no non-owner action or view role", () => {
  assert.deepEqual(getOwnerRecoveryVisibility("owner"), {
    canView: true,
    canCreate: true,
    canApprove: true,
    canCancel: true,
    canExchange: true,
    canEnroll: true,
    canActivate: true,
  });
  for (const role of ["admin", "auditor", "viewer", "support", ""]) {
    assert.equal(getOwnerRecoveryVisibility(role).canView, false);
    assert.equal(getOwnerRecoveryVisibility(role).canApprove, false);
  }
});

test("client emits the canonical recovery bodies and consumes the registration activation challenge", async () => {
  const calls = [];
  const fetchImpl = async (path, init) => {
    calls.push({ path: String(path), init });
    const url = new URL(String(path), "https://console.example.test");
    if (url.pathname === "/api/auth/session") return json(sessionResponse());
    if (url.pathname.endsWith("/recovery-requests")) return json({ request_id: REQUEST_ID, recovery: recovery(), eligibility: { eligible_owner_count: 2, threshold: 2, recoverable: true } }, 201);
    if (url.pathname.endsWith("/registration/options")) return json({ request_id: REQUEST_ID, challenge_id: CHALLENGE_ID, options: { challenge: "registration-options" } });
    if (url.pathname.endsWith("/registration/verify")) return json({ request_id: REQUEST_ID, recovery: recovery("credential_enrolled"), registered: true, activation: { challenge_id: ACTIVATION_CHALLENGE_ID, options: { challenge: "activation-options" } } }, 201);
    if (url.pathname.endsWith("/activate")) return json({ request_id: REQUEST_ID, recovery: recovery("activated"), activated: true });
    throw new Error(`unexpected ${url.pathname}`);
  };
  const client = createOwnerRecoveryClient({ fetchImpl });

  await client.createRequest(ORGANIZATION_ID);
  await client.registrationOptions(REQUEST_ID);
  await client.registrationVerify(ORGANIZATION_ID, CHALLENGE_ID, { id: "credential" });
  await client.activate(ORGANIZATION_ID, ACTIVATION_CHALLENGE_ID, { id: "assertion" });

  const bodies = calls.slice(1).map(({ init }) => JSON.parse(init.body));
  assert.deepEqual(bodies[0], {});
  assert.deepEqual(bodies[1], { request_id: REQUEST_ID });
  assert.deepEqual(bodies[2], { organization_id: ORGANIZATION_ID, challenge_id: CHALLENGE_ID, credential: { id: "credential" } });
  assert.deepEqual(bodies[3], { organization_id: ORGANIZATION_ID, challenge_id: ACTIVATION_CHALLENGE_ID, assertion: { id: "assertion" } });
  assert.equal(bodies.some((body) => Object.hasOwn(body, "subject_member_id")), false);
});

test("BFF binds ceremony calls to the recovery cookie and never relays a raw session token", async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url: String(url), init });
    return json({ request_id: REQUEST_ID, challenge_id: CHALLENGE_ID, options: { challenge: "transport-only" } });
  };
  const response = await handleOwnerRecoveryRequest(request("https://invalid"), { env: { AGENTPASS_CLOUD_API_URL: "https://cloud.example.test" }, fetchImpl });
  assert.equal(response.status, 404);

  const ceremonyRequest = new Request(`https://console.example.test/api/auth/recovery/webauthn/registration/options`, {
    method: "POST",
    headers: {
      origin: "https://console.example.test",
      "content-type": "application/json",
      cookie: `${SESSION_COOKIE}; ${RECOVERY_COOKIE}`,
      "idempotency-key": "recovery-options-1",
    },
    body: JSON.stringify({ request_id: REQUEST_ID }),
  });
  const ceremonyResponse = await handleOwnerRecoveryRequest(ceremonyRequest, { env: { AGENTPASS_CLOUD_API_URL: "https://cloud.example.test" }, fetchImpl });
  assert.equal(ceremonyResponse.status, 200);
  assert.equal(calls[0].init.headers.get("cookie"), RECOVERY_COOKIE);
  assert.deepEqual(JSON.parse(calls[0].init.body), { request_id: REQUEST_ID });
  assert.doesNotMatch(await ceremonyResponse.text(), /session_token|recovery_session_token/);
});

test("BFF exchange accepts only the one-time input and forwards the restricted cookie", async () => {
  const setCookie = `__Host-agentpass_recovery_session=${"t".repeat(43)}; Path=/; HttpOnly; Secure; SameSite=Strict`;
  const calls = [];
  const response = await handleOwnerRecoveryRequest(new Request("https://console.example.test/api/auth/recovery/exchange", {
    method: "POST",
    headers: { origin: "https://console.example.test", "content-type": "application/json" },
    body: JSON.stringify({ exchange: EXCHANGE }),
  }), {
    env: { AGENTPASS_CLOUD_API_URL: "https://cloud.example.test" },
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init });
      return json({ request_id: REQUEST_ID, recovery_session: { recovery_session_id: SESSION_ID, request_id: REQUEST_ID, member_id: MEMBER_ID, stage: "session_issued", expires_at: DATE, idle_expires_at: DATE } }, 200, { "set-cookie": setCookie });
    },
  });
  assert.equal(response.status, 200);
  assert.equal(calls[0].init.headers.has("cookie"), false);
  assert.deepEqual(JSON.parse(calls[0].init.body), { exchange: EXCHANGE });
  assert.equal(response.headers.get("set-cookie"), setCookie);
  assert.doesNotMatch(await response.text(), /tttttttt|session_token/);
});

test("recovery UI contains no browser persistence, URL, logging, or support semantics", async () => {
  const source = await readFile(new URL("../app/components/OwnerRecoveryPanel.tsx", import.meta.url), "utf8");
  assert.match(source, /一度だけ表示/);
  assert.match(source, /固定待機/);
  assert.match(source, /challengeId/);
  assert.doesNotMatch(source, /localStorage|sessionStorage|console\.(?:log|info|warn|error)|support|サポート/i);
});
