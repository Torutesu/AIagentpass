import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { createApiTokenRecord, generateApiToken } from "../src/auth.mjs";
import { createHumanAuthRuntime } from "../src/human-auth/runtime.mjs";

const ids = { org: "11111111-1111-4111-8111-111111111111", member: "22222222-2222-4222-8222-222222222222" };
const CURSOR_SECRET = Buffer.alloc(32, 0x42).toString("base64url");

function postgres() {
  const sessions = [];
  const humanRepository = {
    async createSession(record) { sessions.push({ ...record }); return record; },
    async findSessionByTokenHash({ token_hash }) { return sessions.find((item) => item.token_hash === token_hash) ?? null; },
    async updateSessionActivity(input) { const found=sessions.find((item)=>item.session_id===input.session_id); return found ? Object.assign(found,{last_seen_at:input.last_seen_at,idle_expires_at:input.idle_expires_at}) : null; },
    async revokeSession() { return null; },
    async listSessions({ member_id }) { return sessions.filter((item) => item.member_id === member_id); },
    async consumeConsoleIdentityJti() { return true; },
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
  const organizationRepository = {
    async listOrganizationsForMember() { return []; },
    async listMembers() { return []; },
    async createOrganizationWithOwner() { return null; },
    async renameOrganization() { return null; },
    async updateMemberRole() { return null; },
    async removeMember() { return null; },
    async createInvitation() { return null; },
    async listInvitations() { return []; },
    async revokeInvitation() { return null; },
    async acceptInvitation() { return null; }
  };
  return { pool: { async query(sql) { if (String(sql).includes("FROM upstream_identities")) return { rows: [{ provider: "chatgpt", subject: "siwc-user-1", member_id: ids.member, membership_id: "33333333-3333-4333-8333-333333333333", organization_id: ids.org, role: "owner" }], rowCount: 1 }; return { rows: [], rowCount: 0 }; }, async connect() { throw new Error("not used by session bootstrap"); } }, humanRepository, organizationRepository, sharedControlRepository: { async acquireRateLimit({ capacity }) { return { allowed: true, limit: capacity, remaining: capacity - 1, retryAfterMs: 0, resetAt: Date.now() }; } } };
}

test("composes the production human-auth boundary and bootstraps a hash-only session", async () => {
  const token = generateApiToken();
  const runtime = createHumanAuthRuntime({
    postgresRuntime: postgres(),
    tokenRecords: [createApiTokenRecord({ token, tokenId: crypto.randomUUID(), organizationId: ids.org, memberId: ids.member, role: "owner" })],
    origin: "https://console.example.test",
    rpId: "console.example.test",
    cursorSecret: CURSOR_SECRET,
    now: () => 1_800_000_000_000,
  });
  const result = await runtime.api.handle({ method: "POST", url: "/api/auth/session", headers: { authorization: `Bearer ${token}`, "agentpass-console-user-id": "siwc-user-1", origin: "https://console.example.test", "content-type": "application/json" }, body: "{}" });
  assert.equal(result.status, 201);
  assert.equal(result.body.session.organization_id, ids.org);
  assert.match(result.body.csrf_token, /^[A-Za-z0-9_-]{43}$/);
  assert.match(result.headers["Set-Cookie"], /^__Host-agentpass_session=/);
  assert.equal(runtime.allowedOperations.includes("device.enrollment.issue"), true);
  assert.equal(runtime.allowedOperations.includes("agent.session_grant.issue"), true);
  assert.equal(runtime.allowedOperations.includes("qualification.grant_batch.issue"), true);
  assert.equal(runtime.allowedOperations.includes("human.management.credential.revoke"), true);
  assert.equal(runtime.allowedOperations.includes("human.management.session.revoke"), true);
  assert.equal(runtime.allowedOperations.includes("human.organizations.member.role.update"), true);
  assert.equal(runtime.allowedOperations.includes("human.organizations.member.remove"), true);
  assert.equal(typeof runtime.organizationRepository.listMembers, "function");
  assert.equal(typeof runtime.organizationService.listMembers, "function");
  assert.equal(typeof runtime.organizationApi.handle, "function");
  assert.equal(Object.isFrozen(runtime), true);
});

test("requires PostgreSQL and rejects unsupported recent-auth operations", async () => {
  assert.throws(() => createHumanAuthRuntime({}), /postgresRuntime/);
  const token = generateApiToken();
  const runtime = createHumanAuthRuntime({ postgresRuntime: postgres(), tokenRecords: [createApiTokenRecord({ token, organizationId: ids.org, memberId: ids.member, role: "owner" })], origin: "https://console.example.test", rpId: "console.example.test", cursorSecret: CURSOR_SECRET });
  const session = await runtime.api.handle({ method: "POST", url: "/api/auth/session", headers: { authorization: `Bearer ${token}`, "agentpass-console-user-id": "siwc-user-1", origin: "https://console.example.test", "content-type": "application/json" }, body: "{}" });
  const cookie = session.headers["Set-Cookie"].split(";", 1)[0];
  const rejected = await runtime.api.handle({ method: "POST", url: "/api/auth/webauthn/options", headers: { cookie, origin: "https://console.example.test", "agentpass-csrf": session.body.csrf_token, "content-type": "application/json" }, body: JSON.stringify({ organization_id: ids.org, operation: "policy.delete" }) });
  assert.equal(rejected.status, 400);
  assert.equal(rejected.body.error.code, "human_auth_invalid_request");
});

test("fails closed when the shared Human-auth limiter dependency is missing", () => {
  const configured = postgres();
  delete configured.sharedControlRepository;
  assert.throws(() => createHumanAuthRuntime({ postgresRuntime: configured, tokenRecords: [], origin: "https://console.example.test", rpId: "console.example.test", cursorSecret: CURSOR_SECRET }), /sharedControlRepository/iu);
});

test("composes the Agent Session Human API only with the dedicated signer and issuance authority", () => {
  const configured = postgres();
  configured.agentSessionIssuanceRepository = { async issueAgentSessionGrant() { throw new Error("not invoked"); } };
  const signer = { key_id: "agent-session-2026-08", algorithm: "ed25519", async signAgentSessionGrant() { throw new Error("not invoked"); } };
  const tokenRecords = [createApiTokenRecord({ token: generateApiToken(), organizationId: ids.org, memberId: ids.member, role: "owner" })];
  const runtime = createHumanAuthRuntime({ postgresRuntime: configured, tokenRecords, origin: "https://console.example.test", rpId: "console.example.test", cursorSecret: CURSOR_SECRET, agentSessionSigner: signer });
  assert.equal(typeof runtime.agentSessionGrantApi?.handle, "function");
  assert.throws(() => createHumanAuthRuntime({ postgresRuntime: postgres(), tokenRecords, origin: "https://console.example.test", rpId: "console.example.test", cursorSecret: CURSOR_SECRET, agentSessionSigner: signer }), /issuance repository/iu);
});

test("composes qualification batch authorization only with both purpose-separated signers and repositories", () => {
  const configured = postgres();
  configured.agentSessionIssuanceRepository = { async issueAgentSessionGrant() { throw new Error("not invoked"); } };
  configured.qualificationGrantBatchRepository = { async issueQualificationGrantBatch() { throw new Error("not invoked"); } };
  const agentSessionSigner = { key_id: "agent-session-2026-08", algorithm: "ed25519", async signAgentSessionGrant() { throw new Error("not invoked"); } };
  const qualificationManifestSigner = {
    async publicKeyMetadata() { return { key_id: "qualification-manifest-2026-08" }; },
    async signQualificationGrantBatchManifest() { throw new Error("not invoked"); }
  };
  const tokenRecords = [createApiTokenRecord({ token: generateApiToken(), organizationId: ids.org, memberId: ids.member, role: "owner" })];
  const runtime = createHumanAuthRuntime({ postgresRuntime: configured, tokenRecords, origin: "https://console.example.test", rpId: "console.example.test", cursorSecret: CURSOR_SECRET, agentSessionSigner, qualificationManifestSigner });
  assert.equal(typeof runtime.qualificationGrantBatchApi?.handle, "function");
  assert.throws(() => createHumanAuthRuntime({ postgresRuntime: configured, tokenRecords, origin: "https://console.example.test", rpId: "console.example.test", cursorSecret: CURSOR_SECRET, qualificationManifestSigner }), /Agent Session signer/iu);
  delete configured.qualificationGrantBatchRepository;
  assert.throws(() => createHumanAuthRuntime({ postgresRuntime: configured, tokenRecords, origin: "https://console.example.test", rpId: "console.example.test", cursorSecret: CURSOR_SECRET, agentSessionSigner, qualificationManifestSigner }), /qualification Grant batch repository/iu);
});

test("composes the signed-console identity adapter without a browser identity header", async () => {
  const pair = crypto.generateKeyPairSync("ed25519");
  const issuer = "https://console.example.test";
  const audience = "agentpass-cloud-session";
  const now = 1_800_000_000_000;
  const sortJson = (value) => value && typeof value === "object" && !Array.isArray(value)
    ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${sortJson(value[key])}`).join(",")}}`
    : Array.isArray(value) ? `[${value.map(sortJson).join(",")}]` : JSON.stringify(value);
  const encode = (value) => Buffer.from(sortJson(value)).toString("base64url");
  const header = { alg: "EdDSA", kid: "console-2026-08", typ: "agentpass.console.identity", version: 1 };
  const payload = { aud: audience, exp: 1_800_000_030, iat: 1_800_000_000, iss: issuer, jti: "runtime-jti-42-abcdefgh", nbf: 1_800_000_000, org: ids.org, origin: "https://console.example.test", provider: "chatgpt", sub: "siwc-user-1" };
  const signingInput = `${encode(header)}.${encode(payload)}`;
  const assertion = `${signingInput}.${crypto.sign(null, Buffer.from(signingInput, "ascii"), pair.privateKey).toString("base64url")}`;
  const runtime = createHumanAuthRuntime({
    postgresRuntime: postgres(),
    origin: "https://console.example.test",
    rpId: "console.example.test",
    cursorSecret: CURSOR_SECRET,
    signedConsoleIdentity: { issuer, audience, keyId: "console-2026-08", publicKey: pair.publicKey },
    now: () => now
  });
  const result = await runtime.api.handle({ method: "POST", url: "/api/auth/session", headers: { ["agentpass-console-identity"]: assertion, origin: "https://console.example.test", "content-type": "application/json" }, body: "{}" });
  assert.equal(result.status, 201);
  assert.equal(runtime.consoleIdentity.keyId, "console-2026-08");
  const conflicting = await runtime.api.handle({ method: "POST", url: "/api/auth/session", headers: { ["agentpass-console-identity"]: assertion, "agentpass-console-user-id": "must-be-rejected", origin: "https://console.example.test", "content-type": "application/json" }, body: "{}" });
  assert.equal(conflicting.status, 401);
});
