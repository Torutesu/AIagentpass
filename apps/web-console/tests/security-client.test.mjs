import assert from "node:assert/strict";
import test from "node:test";
import { getSecuritySnapshot, renamePasskey, revokePasskey, revokeSession, SecurityClientError } from "../app/security-client.ts";

const csrf = "C".repeat(43);
const credentialId = "A".repeat(22);
const sessionId = "11111111-1111-4111-8111-111111111111";
const memberId = "22222222-2222-4222-8222-222222222222";
const organizationId = "33333333-3333-4333-8333-333333333333";
const date = "2026-08-12T10:00:00.000Z";

function sessionResponse() {
  return json({ session: { organization_id: organizationId }, csrf_token: csrf }, 201);
}

function credential(status = "active") {
  return { credential_id: credentialId, version: 2, label: "Mac Touch ID", transports: ["internal"], backup_eligible: false, backup_state: false, status, created_at: date, last_used_at: null, revoked_at: status === "revoked" ? date : null };
}

function session(status = "active", current = true) {
  return { session_id: sessionId, version: 3, member_id: memberId, organization_id: organizationId, role: "owner", status, is_current: current, created_at: date, expires_at: "2026-08-12T18:00:00.000Z", last_seen_at: date, recent_auth_at: null, revoked_at: null };
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
  assert.deepEqual(value.sessions, [{ id: sessionId, version: 3, label: "現在のブラウザ", platform: "Web Console", createdAt: date, lastSeenAt: date, expiresAt: "2026-08-12T18:00:00.000Z", current: true }]);
  assert.deepEqual(calls.map((call) => call.url), ["/api/auth/session", "/api/auth/security/passkeys", "/api/auth/security/sessions"]);
  for (const call of calls.slice(1)) {
    assert.equal(call.init.credentials, "same-origin");
    assert.equal(call.init.cache, "no-store");
    assert.equal(call.init.headers.get("agentpass-csrf"), csrf);
  }
});

test("sends optimistic versions and never exposes the Cloud credential to the browser client", async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url: String(url), init });
    if (url === "/api/auth/session") return sessionResponse();
    if (url.includes("/passkeys/") && init.method === "PATCH") return json({ credential: credential() });
    if (url.includes("/passkeys/") && init.method === "POST") return json({ credential: { ...credential("revoked"), revoked_at: date } });
    if (url.includes("/sessions/") && init.method === "POST") return json({ session: session("revoked", false) });
    throw new Error("unexpected path");
  };

  await renamePasskey(credentialId, "仕事用Touch ID", 2, { fetchImpl });
  await revokePasskey(credentialId, 3, { fetchImpl });
  await revokeSession(sessionId, 4, { fetchImpl });

  assert.deepEqual(calls.map((call) => [call.url, call.init.method]), [
    ["/api/auth/session", "POST"],
    [`/api/auth/security/passkeys/${credentialId}`, "PATCH"],
    ["/api/auth/session", "POST"],
    [`/api/auth/security/passkeys/${credentialId}/revoke`, "POST"],
    ["/api/auth/session", "POST"],
    [`/api/auth/security/sessions/${sessionId}/revoke`, "POST"],
  ]);
  assert.deepEqual(JSON.parse(calls[1].init.body), { label: "仕事用Touch ID", expected_version: 2 });
  assert.deepEqual(JSON.parse(calls[3].init.body), { expected_version: 3 });
  assert.deepEqual(JSON.parse(calls[5].init.body), { expected_version: 4 });
});

test("rejects malformed security responses and invalid mutation input", async () => {
  const malformed = await assert.rejects(() => getSecuritySnapshot({ fetchImpl: async (url) => url === "/api/auth/session" ? sessionResponse() : json({ credentials: [], next_cursor: null }) }), (error) => error instanceof SecurityClientError && error.code === "invalid_response");
  assert.equal(malformed, undefined);
  await assert.rejects(() => renamePasskey(credentialId, "", 1, { fetchImpl: async () => sessionResponse() }), (error) => error instanceof SecurityClientError && error.code === "invalid_response");
  await assert.rejects(() => revokePasskey(credentialId, 0, { fetchImpl: async () => sessionResponse() }), (error) => error instanceof SecurityClientError && error.code === "invalid_response");
});
