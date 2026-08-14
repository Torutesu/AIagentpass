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
  const client = { async query(text, params) { calls.push({ text, params }); return { rowCount: 1, rows: [{ id: ids.session }] }; } };
  const repository = createPostgresHumanRepository({ client });

  await repository.createSession(sessionInput);

  assert.match(calls[0].text, /organization_authority_epoch,membership_session_epoch/);
  assert.match(calls[0].text, /JOIN organizations o ON o\.id=m\.organization_id/);
  assert.match(calls[0].text, /o\.authority_epoch,m\.session_epoch/);
  assert.match(calls[0].text, /m\.organization_id=\$3/);
  assert.equal(Buffer.isBuffer(calls[0].params[4]), true);
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
  assert.ok(authorityQueries.length >= 10);
  for (const { text } of authorityQueries) {
    assert.match(text, /authority_epoch/);
    assert.match(text, /session_epoch/);
  }
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
  assert.deepEqual(client.transactionEvents, ["BEGIN", "COMMIT"]);
  assert.deepEqual(client.lockKeys, [`agentpass:organization:${ids.organization}`, ids.member]);
  assert.match(client.oldQuery, /o\.authority_epoch=s\.organization_authority_epoch/);
  assert.match(client.oldQuery, /m\.session_epoch=s\.membership_session_epoch/);
  assert.match(client.oldQuery, /s\.member_id=\$3/);
  assert.match(client.oldQuery, /s\.organization_id=\$4/);
  assert.match(client.oldQuery, /s\.membership_id=\$5/);
  assert.match(client.oldQuery, /s\.role=\$6/);
  assert.match(client.oldQuery, /s\.expires_at>\$7/);
  assert.match(client.insertQuery, /organization_authority_epoch,membership_session_epoch/);
  assert.match(client.insertQuery, /o\.authority_epoch,m\.session_epoch/);
  assert.match(client.revokeQuery, /s\.token_hash=\$4/);
  assert.match(client.revokeQuery, /o\.authority_epoch=s\.organization_authority_epoch/);

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
    if (text.startsWith("SELECT pg_advisory_xact_lock")) {
      this.lockKeys.push(params[0]);
      return { rowCount: 1, rows: [{ locked: true }] };
    }
    if (text.startsWith("SELECT s.id FROM human_sessions")) {
      this.oldQuery = text;
      return this.oldSessionCurrent ? { rowCount: 1, rows: [{ id: ids.session }] } : { rowCount: 0, rows: [] };
    }
    if (text.startsWith("INSERT INTO human_sessions")) {
      this.insertQuery = text;
      this.insertCount += 1;
      this.sessions.set(params[0], { id: params[0], active: true });
      return { rowCount: 1, rows: [{ ...sessionInput, session_id: params[0], token_hash_hex: sessionInput.token_hash, csrf_token_hash_hex: sessionInput.csrf_token_hash }] };
    }
    if (text.startsWith("UPDATE human_sessions s SET revoked_at")) {
      this.revokeQuery = text;
      this.revokeCount += 1;
      this.oldSessionCurrent = false;
      this.sessions.get(params[0]).active = false;
      return { rowCount: 1, rows: [{ id: params[0] }] };
    }
    throw new Error(`unexpected rotation query: ${text}`);
  }

  activeSessionIds() {
    return [...this.sessions.values()].filter(({ active }) => active).map(({ id }) => id);
  }
}
