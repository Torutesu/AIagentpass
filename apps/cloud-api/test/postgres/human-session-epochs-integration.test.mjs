import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { createPostgresHumanRepository } from "../../src/postgres/human-repository.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL;
const CREATED_AT = "2026-08-14T00:00:00.000Z";
const ROTATED_AT = "2026-08-14T00:01:00.000Z";
const EXPIRES_AT = "2099-08-14T00:00:00.000Z";

test("human session epochs invalidate stale authority and serialize concurrent rotation in PostgreSQL", { skip: !databaseUrl }, async (t) => {
  const pool = new Pool({ connectionString: databaseUrl, max: 8 });
  t.after(() => pool.end());
  const migrationClient = await pool.connect();
  try {
    const migration = await createMigrationRunner({ client: migrationClient, applicationVersion: "human-session-epochs-integration" }).run();
    assert.equal(migration.currentVersion, 24);
  } finally {
    migrationClient.release();
  }

  const memberId = randomUUID();
  const retainedOwnerId = randomUUID();
  const organizationId = randomUUID();
  const membershipId = randomUUID();
  const retainedOwnerMembershipId = randomUUID();
  await pool.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,'Epoch member'),($3,$4,'Retained owner')", [memberId, `epoch-${memberId}`, retainedOwnerId, `epoch-owner-${retainedOwnerId}`]);
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,'Epoch organization')", [organizationId]);
  await pool.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active'),($1,$4,$5,'owner','active')", [organizationId, membershipId, memberId, retainedOwnerMembershipId, retainedOwnerId]);

  const repository = createPostgresHumanRepository({ client: pool });
  const oldSessionId = randomUUID();
  const oldToken = "1".repeat(64);
  const session = (sessionId, token, role = "owner") => ({
    session_id: sessionId,
    member_id: memberId,
    organization_id: organizationId,
    membership_id: membershipId,
    role,
    token_hash: token,
    csrf_token_hash: token === oldToken ? "2".repeat(64) : "f".repeat(64),
    created_at: CREATED_AT,
    expires_at: EXPIRES_AT,
    last_seen_at: CREATED_AT,
    idle_expires_at: EXPIRES_AT
  });

  await repository.createSession(session(oldSessionId, oldToken));
  assert.equal((await repository.findSessionByTokenHash({ token_hash: oldToken })).session_id, oldSessionId);
  await assert.rejects(
    pool.query("UPDATE human_sessions SET role='admin' WHERE id=$1", [oldSessionId]),
    (error) => error.code === "23514" && error.constraint === "human_sessions_epoch_snapshot_immutable"
  );

  const replacementIds = [randomUUID(), randomUUID()];
  const rotations = await Promise.all([
    repository.rotateSession({ old_session_id: oldSessionId, old_token_hash: oldToken, session: session(replacementIds[0], "3".repeat(64)), rotated_at: ROTATED_AT }),
    repository.rotateSession({ old_session_id: oldSessionId, old_token_hash: oldToken, session: session(replacementIds[1], "4".repeat(64)), rotated_at: ROTATED_AT })
  ]);
  assert.equal(rotations.filter(Boolean).length, 1);
  const activeAfterRotation = await pool.query("SELECT id FROM human_sessions WHERE organization_id=$1 AND member_id=$2 AND revoked_at IS NULL", [organizationId, memberId]);
  assert.equal(activeAfterRotation.rowCount, 1);
  assert.equal(replacementIds.includes(activeAfterRotation.rows[0].id), true);

  await pool.query("UPDATE memberships SET role='admin' WHERE organization_id=$1 AND id=$2", [organizationId, membershipId]);
  const membership = await pool.query("SELECT session_epoch FROM memberships WHERE organization_id=$1 AND id=$2", [organizationId, membershipId]);
  assert.equal(Number(membership.rows[0].session_epoch), 2);
  assert.equal(await repository.findSessionByTokenHash({ token_hash: (rotations[0] ? "3" : "4").repeat(64) }), null);

  const currentToken = "5".repeat(64);
  const currentSessionId = randomUUID();
  await repository.createSession(session(currentSessionId, currentToken, "admin"));
  assert.ok(await repository.findSessionByTokenHash({ token_hash: currentToken }));

  const otherSessionId = randomUUID();
  await repository.createSession(session(otherSessionId, "6".repeat(64), "admin"));
  const challengeId = randomUUID();
  const otherSessionChallengeId = randomUUID();
  const operation = "organization.emergency_stop";
  await pool.query(`INSERT INTO webauthn_challenges
    (id,session_id,member_id,organization_id,ceremony,operation,challenge_hash,created_at,expires_at,consumed_at,rp_id,origin,user_verification,status)
    VALUES ($1,$2,$3,$4,'authentication',$5,$6,$7,$8,$7,'console.agentpass.test','https://console.agentpass.test','required','consumed')`,
  [challengeId, currentSessionId, memberId, organizationId, operation, Buffer.alloc(32, 0x71), ROTATED_AT, EXPIRES_AT]);
  await pool.query(`INSERT INTO webauthn_challenges
    (id,session_id,member_id,organization_id,ceremony,operation,challenge_hash,created_at,expires_at,consumed_at,rp_id,origin,user_verification,status)
    VALUES ($1,$2,$3,$4,'authentication',$5,$6,$7,$8,$7,'console.agentpass.test','https://console.agentpass.test','required','consumed')`,
  [otherSessionChallengeId, otherSessionId, memberId, organizationId, operation, Buffer.alloc(32, 0x72), ROTATED_AT, EXPIRES_AT]);
  assert.equal(await repository.bindRecentAuth({ session_id: currentSessionId, member_id: memberId, organization_id: organizationId, operation, challenge_id: otherSessionChallengeId, authenticated_at: ROTATED_AT }), false);
  assert.equal(await repository.bindRecentAuth({ session_id: currentSessionId, member_id: memberId, organization_id: organizationId, operation, challenge_id: challengeId, authenticated_at: ROTATED_AT }), true);
  assert.equal(await repository.consumeRecentAuth({ session_id: otherSessionId, member_id: memberId, organization_id: organizationId, operation, challenge_id: challengeId, consumed_at: ROTATED_AT }), null);
  assert.ok(await repository.consumeRecentAuth({ session_id: currentSessionId, member_id: memberId, organization_id: organizationId, operation, challenge_id: challengeId, consumed_at: ROTATED_AT }));

  await pool.query("SELECT agentpass_bump_organization_authority_epoch($1)", [organizationId]);
  assert.equal(await repository.findSessionByTokenHash({ token_hash: currentToken }), null);
});
