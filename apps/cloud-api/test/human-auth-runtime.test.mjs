import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { createApiTokenRecord, generateApiToken } from "../src/auth.mjs";
import { createHumanAuthRuntime } from "../src/human-auth/runtime.mjs";

const ids = { org: "11111111-1111-4111-8111-111111111111", member: "22222222-2222-4222-8222-222222222222" };

function postgres() {
  const sessions = [];
  const humanRepository = {
    async createSession(record) { sessions.push({ ...record }); return record; },
    async findSessionByTokenHash({ token_hash }) { return sessions.find((item) => item.token_hash === token_hash) ?? null; },
    async updateSessionActivity(input) { const found=sessions.find((item)=>item.session_id===input.session_id); return found ? Object.assign(found,{last_seen_at:input.last_seen_at,idle_expires_at:input.idle_expires_at}) : null; },
    async revokeSession() { return null; },
    async listSessions({ member_id }) { return sessions.filter((item) => item.member_id === member_id); },
    async bindRecentAuth() { return true; },
    async consumeRecentAuth() { return null; },
    async listCredentialsForSession() { return []; },
    async getRegistrationUser() { return { id: "EREREREREREREREREREREQ", name: "agentpass:test", display_name: "Test user" }; },
    async createCredential() { return { created: true, credential_id: "Q".repeat(22) }; },
    async listCredentialMetadataForSession() { return []; },
    async updateCredentialLabel() { return null; },
    async revokeCredential() { return null; },
    async listSafeSessions() { return []; },
    async revokeManagedSession() { return null; },
    async findCredentialForSession() { return null; },
    async updateCredentialCounter() { return false; },
  };
  return { pool: { async query(sql) { if (String(sql).includes("FROM upstream_identities")) return { rows: [{ provider: "chatgpt", subject: "siwc-user-1", member_id: ids.member, membership_id: "33333333-3333-4333-8333-333333333333", organization_id: ids.org, role: "owner" }], rowCount: 1 }; return { rows: [], rowCount: 0 }; }, async connect() { throw new Error("not used by session bootstrap"); } }, humanRepository };
}

test("composes the production human-auth boundary and bootstraps a hash-only session", async () => {
  const token = generateApiToken();
  const runtime = createHumanAuthRuntime({
    postgresRuntime: postgres(),
    tokenRecords: [createApiTokenRecord({ token, tokenId: crypto.randomUUID(), organizationId: ids.org, memberId: ids.member, role: "owner" })],
    origin: "https://console.example.test",
    rpId: "console.example.test",
    now: () => 1_800_000_000_000,
  });
  const result = await runtime.api.handle({ method: "POST", url: "/api/auth/session", headers: { authorization: `Bearer ${token}`, "agentpass-console-user-id": "siwc-user-1", origin: "https://console.example.test", "content-type": "application/json" }, body: "{}" });
  assert.equal(result.status, 201);
  assert.equal(result.body.session.organization_id, ids.org);
  assert.match(result.body.csrf_token, /^[A-Za-z0-9_-]{43}$/);
  assert.match(result.headers["Set-Cookie"], /^__Host-agentpass_session=/);
  assert.equal(runtime.allowedOperations.includes("device.enrollment.issue"), true);
  assert.equal(Object.isFrozen(runtime), true);
});

test("requires PostgreSQL and rejects unsupported recent-auth operations", async () => {
  assert.throws(() => createHumanAuthRuntime({}), /postgresRuntime/);
  const token = generateApiToken();
  const runtime = createHumanAuthRuntime({ postgresRuntime: postgres(), tokenRecords: [createApiTokenRecord({ token, organizationId: ids.org, memberId: ids.member, role: "owner" })], origin: "https://console.example.test", rpId: "console.example.test" });
  const session = await runtime.api.handle({ method: "POST", url: "/api/auth/session", headers: { authorization: `Bearer ${token}`, "agentpass-console-user-id": "siwc-user-1", origin: "https://console.example.test", "content-type": "application/json" }, body: "{}" });
  const cookie = session.headers["Set-Cookie"].split(";", 1)[0];
  const rejected = await runtime.api.handle({ method: "POST", url: "/api/auth/webauthn/options", headers: { cookie, origin: "https://console.example.test", "agentpass-csrf": session.body.csrf_token, "content-type": "application/json" }, body: JSON.stringify({ organization_id: ids.org, operation: "policy.delete" }) });
  assert.equal(rejected.status, 400);
  assert.equal(rejected.body.error.code, "human_auth_invalid_request");
});
