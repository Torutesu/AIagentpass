import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createSecurityClient, getSecuritySnapshot, renamePasskey, revokePasskey, SecurityClientError } from "../app/security-client.ts";

const csrf = "C".repeat(43);
const credentialId = "A".repeat(22);
const sessionId = "11111111-1111-4111-8111-111111111111";
const otherSessionId = "44444444-4444-4444-8444-444444444444";
const memberId = "22222222-2222-4222-8222-222222222222";
const organizationId = "33333333-3333-4333-8333-333333333333";
const date = "2026-08-12T10:00:00.000Z";
const authorizationId = "55555555-5555-4555-8555-555555555555";
const authorize = async () => ({ authorization_id: authorizationId });

function sessionResponse() {
  return json({ session: { organization_id: organizationId }, csrf_token: csrf }, 201);
}

function credential(status = "active") {
  return { credential_id: credentialId, version: 2, label: "Mac Touch ID", transports: ["internal"], backup_eligible: false, backup_state: false, status, created_at: date, last_used_at: null, revoked_at: status === "revoked" ? date : null };
}

function session(status = "active", current = true, id = current ? sessionId : otherSessionId) {
  return { session_id: id, version: 3, member_id: memberId, organization_id: organizationId, role: "owner", status, is_current: current, created_at: date, expires_at: "2026-08-12T18:00:00.000Z", last_seen_at: date, recent_auth_at: null, revoked_at: null };
}

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8", ...headers } });
}

test("loads only active safe metadata through the same-origin security paths", async () => {
  const calls = [];
  const value = await getSecuritySnapshot({ fetchImpl: async (url, init) => {
    calls.push({ url: String(url), init });
    if (url === "/api/auth/session") return sessionResponse();
    if (url === "/api/auth/security/passkeys") return json({ credentials: [credential(), credential("revoked")], next_cursor: null });
    if (url === "/api/auth/security/sessions") return json({ sessions: [session(), session("revoked", false)], next_cursor: null });
    throw new Error("unexpected path");
  } });

  assert.deepEqual(value.passkeys, [{ id: credentialId, version: 2, label: "Mac Touch ID", createdAt: date, lastUsedAt: null }]);
  assert.equal(value.passkeysComplete, true);
  assert.deepEqual(value.sessions, [{ id: sessionId, version: 3, label: "現在のブラウザ", platform: "Web Console", createdAt: date, lastSeenAt: date, expiresAt: "2026-08-12T18:00:00.000Z", current: true }]);
  assert.deepEqual(calls.map((call) => call.url), ["/api/auth/session", "/api/auth/security/passkeys", "/api/auth/security/sessions"]);
  for (const call of calls.slice(1)) {
    assert.equal(call.init.credentials, "same-origin");
    assert.equal(call.init.cache, "no-store");
    assert.equal(call.init.headers.get("agentpass-csrf"), csrf);
  }
});

test("reuses one bootstrap result for every read and mutation in a Security lifecycle", async () => {
  const calls = [];
  const authorizations = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url: String(url), init });
    if (url === "/api/auth/session") return sessionResponse();
    if (url === "/api/auth/security/passkeys") return json({ credentials: [credential()], next_cursor: null });
    if (url === "/api/auth/security/sessions") return json({ sessions: [session()], next_cursor: null });
    if (url.includes("/passkeys/") && init.method === "PATCH") return json({ credential: credential() });
    if (url.includes("/passkeys/") && init.method === "POST") return json({ credential: { ...credential("revoked"), revoked_at: date } });
    if (url.includes("/sessions/") && init.method === "POST") return json({ session: session("revoked", false) });
    throw new Error("unexpected path");
  };

  const client = createSecurityClient({ fetchImpl, authenticateRecentAuthImpl: async (input) => { authorizations.push(input); return { authorization_id: authorizationId }; } });
  await client.getSnapshot();
  await client.renamePasskey(credentialId, "仕事用Touch ID", 2);
  await client.revokePasskey(credentialId, 3);
  await client.revokeSession(otherSessionId, 4);

  assert.deepEqual(calls.map((call) => [call.url, call.init.method]), [
    ["/api/auth/session", "POST"],
    ["/api/auth/security/passkeys", "GET"],
    ["/api/auth/security/sessions", "GET"],
    [`/api/auth/security/passkeys/${credentialId}`, "PATCH"],
    [`/api/auth/security/passkeys/${credentialId}/revoke`, "POST"],
    [`/api/auth/security/sessions/${otherSessionId}/revoke`, "POST"],
  ]);
  assert.deepEqual(JSON.parse(calls[3].init.body), { label: "仕事用Touch ID", expected_version: 2 });
  assert.deepEqual(JSON.parse(calls[4].init.body), { expected_version: 3 });
  assert.equal(calls[4].init.headers.get("agentpass-recent-auth"), authorizationId);
  assert.deepEqual(authorizations.map(({ operation, organizationId, csrfToken }) => ({ operation, organizationId, csrfToken })), [{ operation: "human.management.credential.revoke", organizationId, csrfToken: csrf }]);
  assert.deepEqual(JSON.parse(calls[5].init.body), { expected_version: 4 });
});

test("registers a passkey through the session-bound WebAuthn client without returning ceremony material", async () => {
  const calls = [];
  const registrationInputs = [];
  const client = createSecurityClient({
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init });
      if (url === "/api/auth/session") return sessionResponse();
      throw new Error("the registration adapter owns the ceremony transport");
    },
    registerPasskeyImpl: async (input) => {
      registrationInputs.push(input);
      return { registered: true };
    },
  });

  const result = await client.addPasskey();
  assert.equal(result, undefined);
  assert.deepEqual(calls.map((call) => call.url), ["/api/auth/session"]);
  assert.equal(registrationInputs.length, 1);
  assert.deepEqual(Object.keys(registrationInputs[0]).sort(), ["csrfToken", "fetchImpl", "organizationId", "signal"]);
  assert.equal(registrationInputs[0].organizationId, organizationId);
  assert.equal(registrationInputs[0].csrfToken, csrf);
  assert.doesNotMatch(String(result), /credential|challenge|assertion|private|secret|token/i);
});

test("revokes all other sessions through the existing per-session contract", async () => {
  const calls = [];
  const client = createSecurityClient({ authenticateRecentAuthImpl: authorize, fetchImpl: async (url, init) => {
    calls.push({ url: String(url), init });
    if (url === "/api/auth/session") return sessionResponse();
    if (url === "/api/auth/security/passkeys") return json({ credentials: [], next_cursor: null });
    if (url === "/api/auth/security/sessions") return json({ sessions: [session(), session("active", false), session("active", false, "55555555-5555-4555-8555-555555555555")], next_cursor: null });
    if (url.includes("/security/sessions/") && init.method === "POST") return json({ session: session("revoked", false, String(url).split("/").at(-2)) });
    throw new Error("unexpected path");
  }});

  const snapshot = await client.getSnapshot();
  assert.equal(await client.revokeOtherSessions(snapshot.sessions), 2);
  assert.equal(calls.filter((call) => call.url === "/api/auth/session").length, 1);
  assert.deepEqual(calls.filter((call) => call.url.includes("/security/sessions/")).map((call) => call.url), [
    `/api/auth/security/sessions/${otherSessionId}/revoke`,
    "/api/auth/security/sessions/55555555-5555-4555-8555-555555555555/revoke",
  ]);
});

test("current-session revoke closes the lifecycle without bootstrapping a replacement", async () => {
  const calls = [];
  const client = createSecurityClient({ authenticateRecentAuthImpl: authorize, fetchImpl: async (url, init) => {
    calls.push({ url: String(url), init });
    if (url === "/api/auth/session") return sessionResponse();
    if (url === "/api/auth/security/passkeys") return json({ credentials: [], next_cursor: null });
    if (url === "/api/auth/security/sessions") return json({ sessions: [session()], next_cursor: null });
    if (url === `/api/auth/security/sessions/${sessionId}/revoke`) return json({ session: session("revoked", true) });
    throw new Error("unexpected path");
  }});

  const snapshot = await client.getSnapshot();
  await client.revokeCurrentSession(snapshot.sessions[0].id, snapshot.sessions[0].version);
  assert.equal(calls.at(-1).init.headers.get("agentpass-recent-auth"), authorizationId);
  await assert.rejects(() => client.getSnapshot(), (error) => error instanceof SecurityClientError && error.status === 401);
  assert.equal(calls.filter((call) => call.url === "/api/auth/session").length, 1);
});

test("keeps AbortError identity and permits a retry after an aborted bootstrap", async () => {
  let bootstraps = 0;
  const client = createSecurityClient({ fetchImpl: async (url) => {
    if (url === "/api/auth/session") {
      bootstraps += 1;
      if (bootstraps === 1) throw new DOMException("cancelled", "AbortError");
      return sessionResponse();
    }
    if (url === "/api/auth/security/passkeys") return json({ credentials: [], next_cursor: null });
    if (url === "/api/auth/security/sessions") return json({ sessions: [session()], next_cursor: null });
    throw new Error("unexpected path");
  }});

  await assert.rejects(() => client.getSnapshot(), (error) => error instanceof DOMException && error.name === "AbortError");
  await client.getSnapshot();
  assert.equal(bootstraps, 2);
});

test("does not infer the final active credential from a partial page", async () => {
  const client = createSecurityClient({ fetchImpl: async (url) => {
    if (url === "/api/auth/session") return sessionResponse();
    if (url === "/api/auth/security/passkeys") return json({ credentials: [credential()], next_cursor: "next-page" });
    if (url === "/api/auth/security/sessions") return json({ sessions: [], next_cursor: null });
    throw new Error("unexpected path");
  }});

  const snapshot = await client.getSnapshot();
  assert.deepEqual(snapshot.passkeys, [{ id: credentialId, version: 2, label: "Mac Touch ID", createdAt: date, lastUsedAt: null }]);
  assert.equal(snapshot.passkeysComplete, false);
});

test("preserves only an allow-listed Cloud management error code without replaying a mutation", async () => {
  let revokeCalls = 0;
  const client = createSecurityClient({ authenticateRecentAuthImpl: authorize, fetchImpl: async (url) => {
    if (url === "/api/auth/session") return sessionResponse();
    if (url === "/api/auth/security/passkeys") return json({ credentials: [credential()], next_cursor: null });
    if (url === "/api/auth/security/sessions") return json({ sessions: [], next_cursor: null });
    if (String(url).endsWith(`/passkeys/${credentialId}/revoke`)) {
      revokeCalls += 1;
      return json({ error: { code: "human_management_last_active_credential", message: "The last active credential cannot be revoked" } }, 409);
    }
    throw new Error("unexpected path");
  }});

  await assert.rejects(() => client.revokePasskey(credentialId, 2), (error) => error instanceof SecurityClientError && error.status === 409 && error.serviceCode === "human_management_last_active_credential");
  assert.equal(revokeCalls, 1);
});

test("accepts the legacy last-credential error variants for UI classification", async () => {
  for (const code of ["ERR_LAST_ACTIVE_CREDENTIAL", "err_sole_active_credential", "sole_active_credential", "last_credential"]) {
    const client = createSecurityClient({ authenticateRecentAuthImpl: authorize, fetchImpl: async (url) => {
      if (url === "/api/auth/session") return sessionResponse();
      if (String(url).endsWith(`/passkeys/${credentialId}/revoke`)) return json({ error: { code } }, 409);
      throw new Error("unexpected path");
    }});
    await assert.rejects(() => client.revokePasskey(credentialId, 2), (error) => error instanceof SecurityClientError && error.serviceCode === code);
  }
});

test("rejects malformed security responses and invalid mutation input", async () => {
  const malformed = await assert.rejects(() => getSecuritySnapshot({ fetchImpl: async (url) => url === "/api/auth/session" ? sessionResponse() : json({ credentials: [], next_cursor: null }) }), (error) => error instanceof SecurityClientError && error.code === "invalid_response");
  assert.equal(malformed, undefined);
  await assert.rejects(() => renamePasskey(credentialId, "", 1, { fetchImpl: async () => sessionResponse() }), (error) => error instanceof SecurityClientError && error.code === "invalid_response");
  await assert.rejects(() => revokePasskey(credentialId, 0, { fetchImpl: async () => sessionResponse() }), (error) => error instanceof SecurityClientError && error.code === "invalid_response");
});

test("does not access browser storage or log secrets, and does not return the CSRF token", async () => {
  const source = await readFile(new URL("../app/security-client.ts", import.meta.url), "utf8");
  assert.doesNotMatch(source, /localStorage|sessionStorage|console\.(?:log|info|warn|error)/);

  const originalLocalStorage = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
  const originalSessionStorage = Object.getOwnPropertyDescriptor(globalThis, "sessionStorage");
  const originalLog = console.log;
  let storageAccesses = 0;
  let logCalls = 0;
  Object.defineProperty(globalThis, "localStorage", { configurable: true, get() { storageAccesses += 1; throw new Error("storage access"); } });
  Object.defineProperty(globalThis, "sessionStorage", { configurable: true, get() { storageAccesses += 1; throw new Error("storage access"); } });
  console.log = () => { logCalls += 1; };
  try {
    const client = createSecurityClient({ fetchImpl: async (url) => {
      if (url === "/api/auth/session") return sessionResponse();
      if (url === "/api/auth/security/passkeys") return json({ credentials: [credential()], next_cursor: null });
      if (url === "/api/auth/security/sessions") return json({ sessions: [session()], next_cursor: null });
      throw new Error("unexpected path");
    }});
    const snapshot = await client.getSnapshot();
    assert.doesNotMatch(JSON.stringify(snapshot), new RegExp(csrf));
  } finally {
    console.log = originalLog;
    if (originalLocalStorage) Object.defineProperty(globalThis, "localStorage", originalLocalStorage);
    else delete globalThis.localStorage;
    if (originalSessionStorage) Object.defineProperty(globalThis, "sessionStorage", originalSessionStorage);
    else delete globalThis.sessionStorage;
  }
  assert.equal(storageAccesses, 0);
  assert.equal(logCalls, 0);
});
