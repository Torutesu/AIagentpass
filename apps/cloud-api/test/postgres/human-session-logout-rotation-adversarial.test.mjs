import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";

import { Pool } from "pg";

import { createPostgresHumanRepository } from "../../src/postgres/human-repository.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { POSTGRES_SCHEMA_HEAD } from "../../src/postgres/schema-head.mjs";

const MEMBER_ID = "11111111-1111-4111-8111-111111111111";
const ORGANIZATION_ID = "22222222-2222-4222-8222-222222222222";
const MEMBERSHIP_ID = "33333333-3333-4333-8333-333333333333";
const OLD_SESSION_ID = "44444444-4444-4444-8444-444444444444";
const REPLACEMENT_SESSION_ID = "55555555-5555-4555-8555-555555555555";
const INDEPENDENT_SESSION_ID = "66666666-6666-4666-8666-666666666666";
const OLD_TOKEN_HASH = "a".repeat(64);
const REPLACEMENT_TOKEN_HASH = "b".repeat(64);
const INDEPENDENT_TOKEN_HASH = "c".repeat(64);
const CSRF_HASH = "d".repeat(64);
const CREATED_AT = "2026-08-21T00:00:00.000Z";
const ROTATED_AT = "2026-08-21T00:01:00.000Z";
const LOGGED_OUT_AT = "2026-08-21T00:02:00.000Z";
const EXPIRES_AT = "2099-08-21T00:00:00.000Z";

function session(sessionId, tokenHash) {
  return {
    id: sessionId,
    session_id: sessionId,
    member_id: MEMBER_ID,
    organization_id: ORGANIZATION_ID,
    membership_id: MEMBERSHIP_ID,
    role: "owner",
    token_hash: tokenHash,
    csrf_token_hash: CSRF_HASH,
    token_hash_hex: tokenHash,
    csrf_token_hash_hex: CSRF_HASH,
    created_at: CREATED_AT,
    expires_at: EXPIRES_AT,
    last_seen_at: CREATED_AT,
    idle_expires_at: EXPIRES_AT,
    recent_auth_at: null,
    revoked_at: null,
    revoke_reason: null,
    version: 1
  };
}

function logoutInput() {
  return {
    session_id: OLD_SESSION_ID,
    member_id: MEMBER_ID,
    organization_id: ORGANIZATION_ID,
    token_hash: OLD_TOKEN_HASH,
    revoked_at: LOGGED_OUT_AT,
    reason: "logout"
  };
}

test("logout after rotation revokes only the exact successor lineage", async () => {
  const client = new AdversarialSessionClient([session(OLD_SESSION_ID, OLD_TOKEN_HASH), session(INDEPENDENT_SESSION_ID, INDEPENDENT_TOKEN_HASH)]);
  const repository = createPostgresHumanRepository({ client });

  const rotated = await repository.rotateSession({
    old_session_id: OLD_SESSION_ID,
    old_token_hash: OLD_TOKEN_HASH,
    session: { ...session(REPLACEMENT_SESSION_ID, REPLACEMENT_TOKEN_HASH), id: undefined },
    rotated_at: ROTATED_AT,
    reason: "session_rotation"
  });
  assert.equal(rotated.session_id, REPLACEMENT_SESSION_ID);
  assert.equal(client.sessions.get(OLD_SESSION_ID).revoke_reason, `session_rotation:${REPLACEMENT_SESSION_ID}`);
  assert.equal(client.sessions.get(INDEPENDENT_SESSION_ID).revoked_at, null);

  await repository.logoutSession(logoutInput());

  assert.notEqual(client.sessions.get(REPLACEMENT_SESSION_ID).revoked_at, null);
  assert.equal(client.sessions.get(REPLACEMENT_SESSION_ID).revoke_reason, "logout");
  assert.equal(client.sessions.get(INDEPENDENT_SESSION_ID).revoked_at, null);
  assert.deepEqual(client.activeSessionIds(), [INDEPENDENT_SESSION_ID]);
  assert.equal(client.lockKeys.filter((key) => key === MEMBER_ID).length, 2);
});

test("logout winning the member lock prevents rotation and preserves independent sessions", async () => {
  const client = new AdversarialSessionClient([session(OLD_SESSION_ID, OLD_TOKEN_HASH), session(INDEPENDENT_SESSION_ID, INDEPENDENT_TOKEN_HASH)]);
  const repository = createPostgresHumanRepository({ client });

  await repository.logoutSession(logoutInput());
  const rotated = await repository.rotateSession({
    old_session_id: OLD_SESSION_ID,
    old_token_hash: OLD_TOKEN_HASH,
    session: { ...session(REPLACEMENT_SESSION_ID, REPLACEMENT_TOKEN_HASH), id: undefined },
    rotated_at: ROTATED_AT,
    reason: "session_rotation"
  });

  assert.equal(rotated, null);
  assert.equal(client.sessions.has(REPLACEMENT_SESSION_ID), false);
  assert.equal(client.sessions.get(OLD_SESSION_ID).revoke_reason, "logout");
  assert.equal(client.sessions.get(INDEPENDENT_SESSION_ID).revoked_at, null);
  assert.deepEqual(client.activeSessionIds(), [INDEPENDENT_SESSION_ID]);
});

test("real PostgreSQL serializes concurrent logout and rotation without revoking another session", { skip: !process.env.AGENTPASS_TEST_DATABASE_URL }, async (t) => {
  const pool = new Pool({ connectionString: process.env.AGENTPASS_TEST_DATABASE_URL, max: 8 });
  t.after(() => pool.end());
  const migrationClient = await pool.connect();
  try {
    const migration = await createMigrationRunner({ client: migrationClient, applicationVersion: "human-session-logout-rotation-adversarial" }).run();
    assert.equal(migration.currentVersion, POSTGRES_SCHEMA_HEAD.version);
  } finally {
    migrationClient.release();
  }

  const memberId = randomUUID();
  const organizationId = randomUUID();
  const membershipId = randomUUID();
  const oldSessionId = randomUUID();
  const replacementSessionId = randomUUID();
  const independentSessionId = randomUUID();
  const oldTokenHash = "1".repeat(64);
  const replacementTokenHash = "2".repeat(64);
  const independentTokenHash = "3".repeat(64);
  await pool.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,'logout race member')", [memberId, `logout-race-${memberId}`]);
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,'logout race organization')", [organizationId]);
  await pool.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')", [organizationId, membershipId, memberId]);
  const repository = createPostgresHumanRepository({ client: pool });
  const sessionRecord = (sessionId, tokenHash) => ({
    session_id: sessionId,
    member_id: memberId,
    organization_id: organizationId,
    membership_id: membershipId,
    role: "owner",
    token_hash: tokenHash,
    csrf_token_hash: "4".repeat(64),
    created_at: CREATED_AT,
    expires_at: EXPIRES_AT,
    last_seen_at: CREATED_AT,
    idle_expires_at: EXPIRES_AT
  });

  await repository.createSession(sessionRecord(oldSessionId, oldTokenHash));
  await repository.createSession(sessionRecord(independentSessionId, independentTokenHash));
  const [rotation, logout] = await Promise.all([
    repository.rotateSession({
      old_session_id: oldSessionId,
      old_token_hash: oldTokenHash,
      session: sessionRecord(replacementSessionId, replacementTokenHash),
      rotated_at: ROTATED_AT,
      reason: "session_rotation"
    }),
    repository.logoutSession({
      session_id: oldSessionId,
      member_id: memberId,
      organization_id: organizationId,
      token_hash: oldTokenHash,
      revoked_at: LOGGED_OUT_AT,
      reason: "logout"
    })
  ]);

  assert.ok(rotation === null || rotation.session_id === replacementSessionId);
  assert.ok(logout === null || logout.session_id === oldSessionId);
  const active = await pool.query("SELECT id FROM human_sessions WHERE member_id=$1 AND organization_id=$2 AND revoked_at IS NULL ORDER BY id", [memberId, organizationId]);
  assert.deepEqual(active.rows.map(({ id }) => id), [independentSessionId].sort());
  assert.equal(await repository.findSessionByTokenHash({ token_hash: oldTokenHash }), null);
  assert.equal(await repository.findSessionByTokenHash({ token_hash: replacementTokenHash }), null);
  assert.ok(await repository.findSessionByTokenHash({ token_hash: independentTokenHash }));
});

class AdversarialSessionClient {
  constructor(records) {
    this.sessions = new Map(records.map((record) => [record.id, structuredClone(record)]));
    this.lockKeys = [];
    this.successors = new Map();
  }

  async query(text, params = []) {
    if (text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK") return { rowCount: 0, rows: [] };
    if (text.startsWith("SELECT pg_advisory_xact_lock")) {
      this.lockKeys.push(params[0]);
      return { rowCount: 1, rows: [{ locked: true }] };
    }
    if (text.startsWith("SELECT public.agentpass_human_session_rotate")) {
      this.lockKeys.push(MEMBER_ID);
      const old = this.sessions.get(params[0]);
      if (!old || old.revoked_at !== null) return { rowCount: 1, rows: [{ session: null }] };
      old.revoked_at = params[13];
      old.revoke_reason = `session_rotation:${params[2]}`;
      const replacement = session(params[2], Buffer.from(params[7]).toString("hex"));
      Object.assign(replacement, { created_at: params[9], expires_at: params[10], last_seen_at: params[11], idle_expires_at: params[12], csrf_token_hash: Buffer.from(params[8]).toString("hex"), csrf_token_hash_hex: Buffer.from(params[8]).toString("hex") });
      this.sessions.set(replacement.id, replacement);
      this.successors.set(params[0], replacement.id);
      return { rowCount: 1, rows: [{ session: replacement }] };
    }
    if (text.startsWith("SELECT public.agentpass_human_session_logout")) {
      this.lockKeys.push(MEMBER_ID);
      const old = this.sessions.get(params[0]);
      if (!old || old.member_id !== params[1] || old.organization_id !== params[2]) return { rowCount: 1, rows: [{ session: null }] };
      const lineageReason = old.revoke_reason;
      old.revoked_at = params[4];
      old.revoke_reason = params[5];
      const successorId = this.successors.get(params[0]) ?? (String(lineageReason).includes(":") ? String(lineageReason).split(":")[1] : null);
      if (successorId && this.sessions.has(successorId)) { this.sessions.get(successorId).revoked_at = params[4]; this.sessions.get(successorId).revoke_reason = params[5]; }
      return { rowCount: 1, rows: [{ session: old }] };
    }
    if (text.startsWith("SELECT s.*,encode(s.token_hash")) {
      const record = this.sessions.get(params[0]);
      if (!record || record.member_id !== params[1] || record.organization_id !== params[2] || Buffer.from(record.token_hash, "hex").equals(params[3]) === false) {
        return { rowCount: 0, rows: [] };
      }
      return { rowCount: 1, rows: [record] };
    }
    if (text.startsWith("SELECT id,revoked_at,revoke_reason FROM human_sessions")) {
      const record = this.sessions.get(params[0]);
      if (!record || record.member_id !== params[1] || (params.length > 2 && record.organization_id !== params[2])) return { rowCount: 0, rows: [] };
      return { rowCount: 1, rows: [{ id: record.id, revoked_at: record.revoked_at, revoke_reason: record.revoke_reason }] };
    }
    if (text.startsWith("UPDATE human_sessions SET revoked_at")) {
      const record = this.sessions.get(params[0]);
      if (!record || record.revoked_at !== null) return { rowCount: 0, rows: [] };
      record.revoked_at = params[1];
      record.revoke_reason = params[2];
      return { rowCount: 1, rows: [] };
    }
    throw new Error(`unexpected query: ${text}`);
  }

  activeSessionIds() {
    return [...this.sessions.values()].filter((record) => record.revoked_at === null).map((record) => record.id).sort();
  }
}
