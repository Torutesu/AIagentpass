import assert from "node:assert/strict";
import test from "node:test";
import { createPostgresHumanRepository } from "../src/postgres/human-repository.mjs";

const ids = Object.freeze({
  session: "11111111-1111-4111-8111-111111111111",
  replacement: "66666666-6666-4666-8666-666666666666",
  member: "22222222-2222-4222-8222-222222222222",
  organization: "33333333-3333-4333-8333-333333333333",
  membership: "55555555-5555-4555-8555-555555555555",
  challenge: "44444444-4444-4444-8444-444444444444"
});

const sessionInput = Object.freeze({
  session_id: ids.session,
  member_id: ids.member,
  membership_id: ids.membership,
  organization_id: ids.organization,
  role: "owner",
  token_hash: "a".repeat(64),
  csrf_token_hash: "b".repeat(64),
  created_at: "2026-08-14T00:00:00.000Z",
  expires_at: "2026-08-14T08:00:00.000Z",
  last_seen_at: "2026-08-14T00:00:00.000Z",
  idle_expires_at: "2026-08-14T00:30:00.000Z",
  recent_auth_at: null
});

test("session creation snapshots the current organization and membership epochs", async () => {
  const calls = [];
  const client = { async query(text, params) {
    calls.push({ text, params });
    return { rowCount: 1, rows: [{ session: { id: ids.session, ...sessionInput, token_hash_hex: sessionInput.token_hash, csrf_token_hash_hex: sessionInput.csrf_token_hash, revoked_at: null } }] };
  } };
  const repository = createPostgresHumanRepository({ client });

  await repository.createSession(sessionInput);

  assert.match(calls[0].text, /agentpass_human_session_create/);
  assert.equal(Buffer.isBuffer(calls[0].params[5]), true);
});

test("all authority-bearing session and credential paths require exact current epochs", async () => {
  const calls = [];
  const credentialId = Buffer.alloc(16, 7).toString("base64url");
  const client = { async query(text, params) {
    calls.push({ text, params });
    return { rowCount: 0, rows: [] };
  } };
  const repository = createPostgresHumanRepository({ client });

  assert.equal(await repository.findSessionByTokenHash({ token_hash: "a".repeat(64) }), null);
  assert.equal(await repository.updateSessionActivity({ session_id: ids.session, last_seen_at: sessionInput.last_seen_at, idle_expires_at: sessionInput.idle_expires_at }), null);
  assert.equal(await repository.revokeSession({ session_id: ids.session, revoked_at: sessionInput.created_at, reason: "logout" }), null);
  assert.deepEqual(await repository.listSessions({ member_id: ids.member }), []);
  assert.deepEqual(await repository.listSafeSessions({ member_id: ids.member, organization_id: ids.organization }), []);
  assert.equal(await repository.bindRecentAuth({ session_id: ids.session, member_id: ids.member, organization_id: ids.organization, operation: "device.enrollment.issue", challenge_id: ids.challenge, authenticated_at: sessionInput.created_at }), false);
  assert.equal(await repository.consumeRecentAuth({ session_id: ids.session, member_id: ids.member, organization_id: ids.organization, operation: "device.enrollment.issue", challenge_id: ids.challenge, consumed_at: sessionInput.created_at }), null);
  assert.deepEqual(await repository.listCredentialsForSession({ session_id: ids.session, organization_id: ids.organization }), []);
  assert.equal(await repository.findCredentialForSession({ session_id: ids.session, organization_id: ids.organization, credential_id: credentialId }), null);
  assert.deepEqual(await repository.listCredentialMetadataForSession({ session_id: ids.session, member_id: ids.member, organization_id: ids.organization }), []);
  assert.equal(await repository.updateCredentialCounter({ session_id: ids.session, organization_id: ids.organization, credential_id: credentialId, sign_count: 1, expected_sign_count: 0 }), false);

  const authorityQueries = calls.filter(({ text }) => /human_sessions/.test(text));
  assert.ok(calls.some(({ text }) => text.includes("agentpass_human_list_credentials_for_session")));
  assert.ok(calls.some(({ text }) => text.includes("agentpass_human_find_credential_for_session")));
  assert.match(calls[0].text, /agentpass_human_session_find_by_token/);
  assert.match(calls[1].text, /agentpass_human_session_touch/);
  for (const { text } of authorityQueries) {
    assert.match(text, /authority_epoch/);
    assert.match(text, /session_epoch/);
  }
});

test("token authentication and WebAuthn allow-list lookup require a currently usable session", async () => {
  const calls = [];
  const client = { async query(text, params) {
    calls.push({ text, params });
    return { rowCount: 0, rows: [] };
  } };
  const repository = createPostgresHumanRepository({ client });

  assert.equal(await repository.findSessionByTokenHash({ token_hash: "a".repeat(64) }), null);
  assert.deepEqual(await repository.listCredentialsForSession({ session_id: ids.session, organization_id: ids.organization }), []);

  const sessionLookup = calls[0].text;
  assert.match(sessionLookup, /agentpass_human_session_find_by_token/);

  const credentialLookup = calls[1].text;
  assert.match(credentialLookup, /agentpass_human_list_credentials_for_session/);
});

test("session lookup normalizes node-postgres Date values before the JSON boundary", async () => {
  const sessionRow = {
      id: ids.session,
      member_id: ids.member,
      membership_id: ids.membership,
      organization_id: ids.organization,
      role: "owner",
      token_hash_hex: "a".repeat(64),
      csrf_token_hash_hex: "b".repeat(64),
      created_at: new Date("2026-08-14T00:00:00.000Z"),
      expires_at: new Date("2026-08-14T08:00:00.000Z"),
      last_seen_at: new Date("2026-08-14T00:01:00.000Z"),
      idle_expires_at: new Date("2026-08-14T00:31:00.000Z"),
      recent_auth_at: null,
      revoked_at: null
    };
  const client = { async query(text) {
    if (text.includes("agentpass_human_session_find_by_token")) return { rowCount: 1, rows: [{ session: sessionRow }] };
    if (text.includes("agentpass_human_session_list_safe")) return { rowCount: 1, rows: [{ session: sessionRow }] };
    return { rowCount: 1, rows: [sessionRow] };
  } };
  const repository = createPostgresHumanRepository({ client });

  const session = await repository.findSessionByTokenHash({ token_hash: "a".repeat(64) });
  const [safeSession] = await repository.listSafeSessions({ member_id: ids.member, organization_id: ids.organization });
  assert.equal(session.created_at, "2026-08-14T00:00:00.000Z");
  assert.equal(session.expires_at, "2026-08-14T08:00:00.000Z");
  assert.equal(session.last_seen_at, "2026-08-14T00:01:00.000Z");
  assert.equal(session.idle_expires_at, "2026-08-14T00:31:00.000Z");
  assert.equal(session.recent_auth_at, null);
  assert.equal(session.revoked_at, null);
  assert.equal(safeSession.created_at, "2026-08-14T00:00:00.000Z");
  assert.equal(safeSession.expires_at, "2026-08-14T08:00:00.000Z");
  assert.equal(safeSession.last_seen_at, "2026-08-14T00:01:00.000Z");
  assert.equal(safeSession.idle_expires_at, "2026-08-14T00:31:00.000Z");
});

test("rotateSession atomically snapshots current epochs and revokes the exact old session", async () => {
  const client = new RotationClient();
  const repository = createPostgresHumanRepository({ client });
  const replacement = { ...sessionInput, session_id: ids.replacement, created_at: "2026-08-14T00:01:00.000Z", last_seen_at: "2026-08-14T00:01:00.000Z", idle_expires_at: "2026-08-14T00:31:00.000Z" };

  const created = await repository.rotateSession({
    old_session_id: ids.session,
    old_token_hash: sessionInput.token_hash,
    session: replacement,
    rotated_at: "2026-08-14T00:01:00.000Z",
    reason: "session_rotation"
  });

  assert.equal(created.session_id, ids.replacement);
  assert.equal(client.insertCount, 1);
  assert.equal(client.revokeCount, 1);
  assert.deepEqual(client.activeSessionIds(), [ids.replacement]);
  assert.deepEqual(client.transactionEvents, []);
  assert.match(client.calls[0].text, /agentpass_human_session_rotate/);

  // The same old token/session pair is an idempotent no-op after the first
  // commit. It cannot create a second active replacement.
  const retried = await repository.rotateSession({
    old_session_id: ids.session,
    old_token_hash: sessionInput.token_hash,
    session: { ...replacement, session_id: "77777777-7777-4777-8777-777777777777" },
    rotated_at: "2026-08-14T00:02:00.000Z",
    reason: "session_rotation"
  });
  assert.equal(retried, null);
  assert.equal(client.insertCount, 1);
  assert.deepEqual(client.activeSessionIds(), [ids.replacement]);
});

class RotationClient {
  constructor() {
    this.calls = [];
    this.transactionEvents = [];
    this.lockKeys = [];
    this.insertCount = 0;
    this.revokeCount = 0;
    this.oldSessionCurrent = true;
    this.oldQuery = "";
    this.insertQuery = "";
    this.revokeQuery = "";
    this.sessions = new Map([[ids.session, { id: ids.session, active: true }]]);
  }

  async connect() {
    return { query: (text, params) => this.query(text, params), release() {} };
  }

  async query(text, params = []) {
    this.calls.push({ text, params });
    if (text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK") {
      this.transactionEvents.push(text);
      return { rowCount: 0, rows: [] };
    }
    if (text.startsWith("SELECT public.agentpass_human_session_rotate")) {
      if (!this.oldSessionCurrent) return { rowCount: 1, rows: [{ session: null }] };
      this.insertCount += 1;
      this.revokeCount += 1;
      this.oldSessionCurrent = false;
      this.sessions.get(ids.session).active = false;
      this.sessions.set(params[2], { id: params[2], active: true });
      return { rowCount: 1, rows: [{ session: { ...sessionInput, session_id: params[2], id: params[2], token_hash_hex: Buffer.from(params[7]).toString("hex"), csrf_token_hash_hex: Buffer.from(params[8]).toString("hex"), created_at: params[9], expires_at: params[10], last_seen_at: params[11], idle_expires_at: params[12] } }] };
    }
    throw new Error(`unexpected rotation query: ${text}`);
  }

  activeSessionIds() {
    return [...this.sessions.values()].filter(({ active }) => active).map(({ id }) => id);
  }
}
