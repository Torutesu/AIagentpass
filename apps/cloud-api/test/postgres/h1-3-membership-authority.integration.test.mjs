import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomUUID } from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { createAuthorityReductionAuditAppender } from "../../src/postgres/authority-reduction-audit.mjs";
import { createPostgresAdminAuditRepository } from "../../src/postgres/admin-audit-repository.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createPostgresOrganizationRepository } from "../../src/postgres/organization-repository.mjs";
import { POSTGRES_SCHEMA_HEAD } from "../../src/postgres/schema-head.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const CREATED_AT = "2026-08-16T00:00:00.000Z";
const EXPIRES_AT = "2099-08-16T00:00:00.000Z";
const OPERATION = "human.organizations.member.role.update";

test("H1.3 real PostgreSQL membership authority enforces reduction, isolation, and convergence", { skip: !DATABASE_URL }, async (t) => {
  const pool = new Pool({ connectionString: DATABASE_URL, max: 12 });
  t.after(() => pool.end());
  await migrate(pool, "h1-3-membership-authority-integration");

  const fixture = await seedFixture(pool);
  const initialOrganizationEpoch = await organizationAuthorityEpoch(pool, fixture.organizationId);
  const initialOtherOrganizationEpoch = await organizationAuthorityEpoch(pool, fixture.otherOrganizationId);
  const reductions = [];
  const repository = createPostgresOrganizationRepository({
    client: pool,
    now: () => CREATED_AT,
    onAuthorityReduction: async (input) => {
      reductions.push({
        organization_id: input.organization_id,
        actor_member_id: input.actor_member_id,
        member_id: input.member_id,
        event_type: input.event_type
      });
      return { generation: reductions.length };
    }
  });

  await assert.rejects(repository.updateMemberRole({
    organization_id: fixture.organizationId,
    actor_member_id: fixture.adminId,
    member_id: fixture.ownerId,
    role: "viewer",
    expected_version: 1,
    idempotency_key: "h13-admin-owner-role"
  }), { code: "ERR_FORBIDDEN" });
  await assert.rejects(repository.updateMemberRole({
    organization_id: fixture.organizationId,
    actor_member_id: fixture.adminId,
    member_id: fixture.retainedId,
    role: "owner",
    expected_version: 1,
    idempotency_key: "h13-admin-owner-promote"
  }), { code: "ERR_FORBIDDEN" });

  await assert.rejects(repository.updateMemberRole({
    organization_id: fixture.organizationId,
    actor_member_id: fixture.ownerId,
    member_id: fixture.otherTargetId,
    role: "viewer",
    expected_version: 1,
    idempotency_key: "h13-cross-tenant-target"
  }), { code: "ERR_MEMBER_NOT_FOUND" });
  await assert.rejects(repository.removeMember({
    organization_id: fixture.organizationId,
    actor_member_id: fixture.otherOwnerId,
    member_id: fixture.targetId,
    expected_version: 1,
    removed_at: CREATED_AT,
    idempotency_key: "h13-cross-tenant-actor"
  }), { code: "ERR_FORBIDDEN" });
  assert.deepEqual(await membershipSnapshot(pool, fixture.otherOrganizationId, fixture.otherTargetId), {
    role: "viewer", status: "active", version: 1, session_epoch: 1
  });

  const downgrade = {
    organization_id: fixture.organizationId,
    actor_member_id: fixture.adminId,
    member_id: fixture.targetId,
    role: "viewer",
    expected_version: 1,
    idempotency_key: "h13-role-downgrade-contention"
  };
  const downgradeResults = await Promise.all([
    repository.updateMemberRole(downgrade),
    repository.updateMemberRole(downgrade)
  ]);
  assert.equal(downgradeResults.filter((result) => result.replayed === true).length, 1);
  assert.equal(downgradeResults.filter((result) => result.replayed !== true).length, 1);
  assert.equal(downgradeResults.every((result) => result.role === "viewer" && result.version === 2), true);
  assert.deepEqual(reductions, [{
    organization_id: fixture.organizationId,
    actor_member_id: fixture.adminId,
    member_id: fixture.targetId,
    event_type: "membership.role_reduced"
  }]);

  assert.deepEqual(await membershipSnapshot(pool, fixture.organizationId, fixture.targetId), {
    role: "viewer", status: "active", version: 2, session_epoch: 2
  });
  assert.deepEqual(await membershipSnapshot(pool, fixture.organizationId, fixture.retainedId), {
    role: "viewer", status: "active", version: 1, session_epoch: 1
  });
  assert.equal(await organizationAuthorityEpoch(pool, fixture.organizationId), initialOrganizationEpoch);
  assert.equal(await organizationAuthorityEpoch(pool, fixture.otherOrganizationId), initialOtherOrganizationEpoch);
  await assertReductionState(pool, fixture, { targetRevoked: true, retainedRevoked: false, targetChallenge: "consumed", retainedChallenge: "pending", targetCapabilityRevoked: true, retainedCapabilityRevoked: false });
  assert.deepEqual(await membershipSnapshot(pool, fixture.otherOrganizationId, fixture.targetId), {
    role: "viewer", status: "active", version: 1, session_epoch: 1
  });
  await assertCrossTenantState(pool, fixture);

  const replay = await repository.updateMemberRole(downgrade);
  assert.equal(replay.replayed, true);
  await assert.rejects(repository.updateMemberRole({ ...downgrade, role: "admin" }), { code: "ERR_IDEMPOTENCY_CONFLICT" });
  await assert.rejects(repository.removeMember({
    organization_id: fixture.organizationId,
    actor_member_id: fixture.ownerId,
    member_id: fixture.targetId,
    expected_version: 1,
    removed_at: CREATED_AT,
    idempotency_key: "h13-remove-stale-version"
  }), { code: "ERR_VERSION_CONFLICT" });
  assert.deepEqual(await membershipSnapshot(pool, fixture.organizationId, fixture.targetId), {
    role: "viewer", status: "active", version: 2, session_epoch: 2
  });

  const removal = {
    organization_id: fixture.organizationId,
    actor_member_id: fixture.ownerId,
    member_id: fixture.targetId,
    expected_version: 2,
    removed_at: CREATED_AT,
    idempotency_key: "h13-member-removal-contention"
  };
  const removalResults = await Promise.all([
    repository.removeMember(removal),
    repository.removeMember(removal)
  ]);
  assert.equal(removalResults.filter((result) => result.replayed === true).length, 1);
  assert.equal(removalResults.filter((result) => result.replayed !== true).length, 1);
  assert.equal(removalResults.every((result) => result.status === "revoked" && result.version === 3), true);
  assert.equal(reductions.length, 2);
  assert.equal(reductions[1].event_type, "membership.removed");
  assert.deepEqual(await membershipSnapshot(pool, fixture.organizationId, fixture.targetId), {
    role: "viewer", status: "revoked", version: 3, session_epoch: 3
  });
  assert.deepEqual(await membershipSnapshot(pool, fixture.organizationId, fixture.retainedId), {
    role: "viewer", status: "active", version: 1, session_epoch: 1
  });
  assert.equal(await organizationAuthorityEpoch(pool, fixture.organizationId), initialOrganizationEpoch);
  assert.equal(await organizationAuthorityEpoch(pool, fixture.otherOrganizationId), initialOtherOrganizationEpoch);
  await assertReductionState(pool, fixture, { targetRevoked: true, retainedRevoked: false, targetChallenge: "consumed", retainedChallenge: "pending", targetCapabilityRevoked: true, retainedCapabilityRevoked: false });
  assert.deepEqual(await membershipSnapshot(pool, fixture.otherOrganizationId, fixture.targetId), {
    role: "viewer", status: "active", version: 1, session_epoch: 1
  });
  await assertCrossTenantState(pool, fixture);

  const race = await seedContentionTarget(pool, fixture);
  const raceInput = {
    organization_id: fixture.organizationId,
    actor_member_id: fixture.adminId,
    member_id: race.memberId,
    role: "viewer",
    expected_version: 1
  };
  const raceResults = await Promise.allSettled([
    repository.updateMemberRole({ ...raceInput, idempotency_key: "h13-distinct-contention-a" }),
    repository.updateMemberRole({ ...raceInput, idempotency_key: "h13-distinct-contention-b" })
  ]);
  assert.equal(raceResults.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(raceResults.filter((result) => result.status === "rejected" && result.reason?.code === "ERR_VERSION_CONFLICT").length, 1);
  assert.deepEqual(await membershipSnapshot(pool, fixture.organizationId, race.memberId), {
    role: "viewer", status: "active", version: 2, session_epoch: 2
  });

  const lastOwner = await seedLastOwner(pool);
  const lastOwnerRepository = createPostgresOrganizationRepository({ client: pool, now: () => CREATED_AT, onAuthorityReduction: async () => ({ generation: 1 }) });
  await assert.rejects(lastOwnerRepository.updateMemberRole({
    organization_id: lastOwner.organizationId,
    actor_member_id: lastOwner.ownerId,
    member_id: lastOwner.ownerId,
    role: "admin",
    expected_version: 1,
    idempotency_key: "h13-last-owner-role"
  }), { code: "ERR_LAST_OWNER" });
  await assert.rejects(lastOwnerRepository.removeMember({
    organization_id: lastOwner.organizationId,
    actor_member_id: lastOwner.ownerId,
    member_id: lastOwner.ownerId,
    expected_version: 1,
    removed_at: CREATED_AT,
    idempotency_key: "h13-last-owner-remove"
  }), { code: "ERR_LAST_OWNER" });
  assert.deepEqual(await membershipSnapshot(pool, lastOwner.organizationId, lastOwner.ownerId), {
    role: "owner", status: "active", version: 1, session_epoch: 1
  });
});

test("H1.3 PostgreSQL transaction rolls back membership reduction on callback and audit failure", { skip: !DATABASE_URL }, async (t) => {
  const pool = new Pool({ connectionString: DATABASE_URL, max: 8 });
  t.after(() => pool.end());
  await migrate(pool, "h1-3-membership-authority-rollback-integration");

  const callbackFixture = await seedFixture(pool);
  const callbackFailure = new Error("injected authority callback failure");
  callbackFailure.code = "ERR_TEST_AUTHORITY_CALLBACK";
  const callbackRepository = createPostgresOrganizationRepository({
    client: pool,
    now: () => CREATED_AT,
    onAuthorityReduction: async () => { throw callbackFailure; }
  });
  await assert.rejects(callbackRepository.updateMemberRole({
    organization_id: callbackFixture.organizationId,
    actor_member_id: callbackFixture.ownerId,
    member_id: callbackFixture.targetId,
    role: "viewer",
    expected_version: 1,
    idempotency_key: "h13-callback-failure"
  }), { code: "ERR_TEST_AUTHORITY_CALLBACK" });
  await assertUnchangedAfterRollback(pool, callbackFixture);

  const auditFixture = await seedFixture(pool);
  const realAuditRepository = createPostgresAdminAuditRepository({ client: pool, now: () => CREATED_AT });
  const failingAuditAppender = createAuthorityReductionAuditAppender({
    adminAuditRepository: {
      async appendAdminAuditEventInTransaction(input) {
        await realAuditRepository.appendAdminAuditEventInTransaction(input);
        const error = new Error("injected audit failure after PostgreSQL append");
        error.code = "ERR_TEST_AUDIT_CALLBACK";
        throw error;
      }
    }
  });
  const auditFailureRepository = createPostgresOrganizationRepository({
    client: pool,
    now: () => CREATED_AT,
    onAuthorityReduction: async (input) => {
      await failingAuditAppender.appendAuthorityReductionAudit({
        tx: input.tx,
        organization_id: input.organization_id,
        actor: { member_id: input.actor_member_id },
        resource: { type: "member", id: input.member_id },
        event_type: "member.removed",
        mutation_key: "h13-audit-failure",
        occurred_at: input.occurred_at,
        reason: "integration-test",
        source: "management_api"
      });
      return { generation: 1 };
    }
  });
  await assert.rejects(auditFailureRepository.removeMember({
    organization_id: auditFixture.organizationId,
    actor_member_id: auditFixture.ownerId,
    member_id: auditFixture.targetId,
    expected_version: 1,
    removed_at: CREATED_AT,
    idempotency_key: "h13-audit-failure-removal"
  }), { code: "ERR_AUTHORITY_REDUCTION_AUDIT_UNAVAILABLE" });
  await assertUnchangedAfterRollback(pool, auditFixture);
});

async function migrate(pool, applicationVersion) {
  const client = await pool.connect();
  try {
    const result = await createMigrationRunner({ client, applicationVersion }).run();
    assert.equal(result.currentVersion, POSTGRES_SCHEMA_HEAD.version, "H1.3 must run against the complete PostgreSQL schema head");
  } finally {
    client.release();
  }
}

async function seedFixture(pool) {
  const ids = {
    organizationId: randomUUID(),
    otherOrganizationId: randomUUID(),
    ownerId: randomUUID(),
    adminId: randomUUID(),
    targetId: randomUUID(),
    retainedId: randomUUID(),
    otherOwnerId: randomUUID(),
    otherTargetId: randomUUID(),
    targetMembershipId: randomUUID(),
    retainedMembershipId: randomUUID(),
    crossTenantMembershipId: randomUUID(),
    targetSessionId: randomUUID(),
    targetSecondSessionId: randomUUID(),
    retainedSessionId: randomUUID(),
    targetChallengeId: randomUUID(),
    targetSecondChallengeId: randomUUID(),
    retainedChallengeId: randomUUID(),
    deviceId: randomUUID(),
    agentId: randomUUID(),
    targetCapabilityId: randomUUID(),
    retainedCapabilityId: randomUUID(),
    crossTenantDeviceId: randomUUID(),
    crossTenantAgentId: randomUUID(),
    crossTenantSessionId: randomUUID(),
    crossTenantChallengeId: randomUUID(),
    crossTenantCapabilityId: randomUUID()
  };
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,'H1.3 primary'),($2,'H1.3 other')", [ids.organizationId, ids.otherOrganizationId]);
  await pool.query(`INSERT INTO members (id,github_subject,display_name) VALUES
    ($1,$2,'Owner'),($3,$4,'Admin'),($5,$6,'Target'),($7,$8,'Retained'),($9,$10,'Other owner'),($11,$12,'Other target')`, [
    ids.ownerId, `h13-owner-${ids.ownerId}`,
    ids.adminId, `h13-admin-${ids.adminId}`,
    ids.targetId, `h13-target-${ids.targetId}`,
    ids.retainedId, `h13-retained-${ids.retainedId}`,
    ids.otherOwnerId, `h13-other-owner-${ids.otherOwnerId}`,
    ids.otherTargetId, `h13-other-target-${ids.otherTargetId}`
  ]);
  await pool.query(`INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES
    ($1,$2,$3,'owner','active'),($1,$4,$5,'admin','active'),($1,$6,$7,'admin','active'),($1,$8,$9,'viewer','active'),
    ($10,$11,$12,'owner','active'),($10,$13,$14,'viewer','active'),($10,$15,$7,'viewer','active')`, [
    ids.organizationId, randomUUID(), ids.ownerId,
    randomUUID(), ids.adminId,
    ids.targetMembershipId, ids.targetId,
    ids.retainedMembershipId, ids.retainedId,
    ids.otherOrganizationId, randomUUID(), ids.otherOwnerId,
    randomUUID(), ids.otherTargetId,
    ids.crossTenantMembershipId
  ]);

  const publicKey = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString().trimEnd();
  await pool.query(`INSERT INTO devices (organization_id,id,label,key_algorithm,status,public_key_pem)
    VALUES ($1,$2,'H1.3 device','ed25519','active',$3)`, [ids.organizationId, ids.deviceId, publicKey]);
  await pool.query(`INSERT INTO agents (organization_id,id,device_id,kind,name,public_key_pem,status)
    VALUES ($1,$2,$3,'custom','H1.3 agent',$4,'active')`, [ids.organizationId, ids.agentId, ids.deviceId, publicKey]);
  const crossTenantPublicKey = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString().trimEnd();
  await pool.query(`INSERT INTO devices (organization_id,id,label,key_algorithm,status,public_key_pem)
    VALUES ($1,$2,'H1.3 other device','ed25519','active',$3)`, [ids.otherOrganizationId, ids.crossTenantDeviceId, crossTenantPublicKey]);
  await pool.query(`INSERT INTO agents (organization_id,id,device_id,kind,name,public_key_pem,status)
    VALUES ($1,$2,$3,'custom','H1.3 other agent',$4,'active')`, [ids.otherOrganizationId, ids.crossTenantAgentId, ids.crossTenantDeviceId, crossTenantPublicKey]);
  await pool.query(`INSERT INTO capabilities
    (organization_id,id,agent_id,device_id,sequence,statement_hash,expires_at,issued_by_member_id,issued_membership_version)
    VALUES ($1,$2,$3,$4,1,$5,$6,$7,1),($1,$8,$3,$4,2,$9,$6,$10,1)`, [
    ids.organizationId, ids.targetCapabilityId, ids.agentId, ids.deviceId, "a".repeat(64), EXPIRES_AT, ids.targetId,
    ids.retainedCapabilityId, "b".repeat(64), ids.retainedId
  ]);
  await pool.query(`INSERT INTO capabilities
    (organization_id,id,agent_id,device_id,sequence,statement_hash,expires_at,issued_by_member_id,issued_membership_version)
    VALUES ($1,$2,$3,$4,1,$5,$6,$7,1)`, [ids.otherOrganizationId, ids.crossTenantCapabilityId, ids.crossTenantAgentId, ids.crossTenantDeviceId, "c".repeat(64), EXPIRES_AT, ids.targetId]);
  await insertSessionAndChallenge(pool, { sessionId: ids.targetSessionId, challengeId: ids.targetChallengeId, memberId: ids.targetId, membershipId: ids.targetMembershipId, role: "admin", byte: 10, operation: OPERATION, organizationId: ids.organizationId });
  await insertSessionAndChallenge(pool, { sessionId: ids.targetSecondSessionId, challengeId: ids.targetSecondChallengeId, memberId: ids.targetId, membershipId: ids.targetMembershipId, role: "admin", byte: 20, operation: "human.webauthn.credential.register", organizationId: ids.organizationId });
  await insertSessionAndChallenge(pool, { sessionId: ids.retainedSessionId, challengeId: ids.retainedChallengeId, memberId: ids.retainedId, membershipId: ids.retainedMembershipId, role: "viewer", byte: 30, operation: OPERATION, organizationId: ids.organizationId });
  await insertSessionAndChallenge(pool, { sessionId: ids.crossTenantSessionId, challengeId: ids.crossTenantChallengeId, memberId: ids.targetId, membershipId: ids.crossTenantMembershipId, role: "viewer", byte: 40, operation: "human.cross-tenant.check", organizationId: ids.otherOrganizationId });
  return ids;
}

async function seedLastOwner(pool) {
  const organizationId = randomUUID();
  const ownerId = randomUUID();
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,'H1.3 last owner')", [organizationId]);
  await pool.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,'Last owner')", [ownerId, `h13-last-owner-${ownerId}`]);
  await pool.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')", [organizationId, randomUUID(), ownerId]);
  return { organizationId, ownerId };
}

async function seedContentionTarget(pool, fixture) {
  const memberId = randomUUID();
  await pool.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,'Contention target')", [memberId, `h13-contention-${memberId}`]);
  await pool.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'admin','active')", [fixture.organizationId, randomUUID(), memberId]);
  return { memberId };
}

async function insertSessionAndChallenge(pool, { sessionId, challengeId, memberId, membershipId, role, byte, operation, organizationId }) {
  const tokenHash = createHash("sha256").update(`h1-3-token:${sessionId}`).digest();
  const csrfTokenHash = createHash("sha256").update(`h1-3-csrf:${sessionId}`).digest();
  await pool.query(`INSERT INTO human_sessions
    (id,member_id,organization_id,membership_id,role,token_hash,csrf_token_hash,created_at,expires_at,last_seen_at,idle_expires_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$8,$9)`, [sessionId, memberId, organizationId, membershipId, role, tokenHash, csrfTokenHash, CREATED_AT, EXPIRES_AT]);
  await pool.query(`INSERT INTO webauthn_challenges
    (id,session_id,member_id,organization_id,ceremony,operation,challenge_hash,created_at,expires_at,rp_id,origin,user_verification,status)
    VALUES ($1,$2,$3,$4,'authentication',$5,$6,$7,$8,'console.agentpass.test','https://console.agentpass.test','required','pending')`, [challengeId, sessionId, memberId, organizationId, operation, createHash("sha256").update(`h1-3-challenge:${challengeId}`).digest(), CREATED_AT, EXPIRES_AT]);
  await pool.query(`UPDATE human_sessions SET recent_auth_at=$2,recent_auth_challenge_id=$3,
    recent_auth_organization_id=$4,recent_auth_operation=$5 WHERE id=$1`, [sessionId, CREATED_AT, challengeId, organizationId, operation]);
}

async function membershipSnapshot(pool, organizationId, memberId) {
  const result = await pool.query("SELECT role,status,version,session_epoch FROM memberships WHERE organization_id=$1 AND member_id=$2", [organizationId, memberId]);
  assert.equal(result.rowCount, 1);
  const row = result.rows[0];
  return { role: row.role, status: row.status, version: Number(row.version), session_epoch: Number(row.session_epoch) };
}

async function organizationAuthorityEpoch(pool, organizationId) {
  const result = await pool.query("SELECT authority_epoch FROM organizations WHERE id=$1", [organizationId]);
  assert.equal(result.rowCount, 1);
  return Number(result.rows[0].authority_epoch);
}

async function assertReductionState(pool, fixture, expected) {
  const sessions = await pool.query(`SELECT id,revoked_at,revoke_reason,version,recent_auth_at,recent_auth_challenge_id,
    recent_auth_organization_id,recent_auth_operation,recent_auth_consumed_at
    FROM human_sessions WHERE organization_id=$1 AND member_id IN ($2,$3) ORDER BY id`, [fixture.organizationId, fixture.targetId, fixture.retainedId]);
  assert.equal(sessions.rowCount, 3);
  const targetSessions = sessions.rows.filter((row) => [fixture.targetSessionId, fixture.targetSecondSessionId].includes(row.id));
  const retainedSession = sessions.rows.find((row) => row.id === fixture.retainedSessionId);
  assert.equal(targetSessions.every((row) => (row.revoked_at !== null) === expected.targetRevoked && Number(row.version) === (expected.targetRevoked ? 2 : 1)), true);
  assert.equal(targetSessions.every((row) => [row.recent_auth_at, row.recent_auth_challenge_id, row.recent_auth_organization_id, row.recent_auth_operation].every((value) => (value === null) === expected.targetRevoked) && row.recent_auth_consumed_at === null), true);
  assert.equal((retainedSession.revoked_at !== null), expected.retainedRevoked);
  assert.equal(Number(retainedSession.version), expected.retainedRevoked ? 2 : 1);
  const challenges = await pool.query("SELECT id,status,consumed_at FROM webauthn_challenges WHERE organization_id=$1 AND id IN ($2,$3,$4) ORDER BY id", [fixture.organizationId, fixture.targetChallengeId, fixture.targetSecondChallengeId, fixture.retainedChallengeId]);
  assert.equal(challenges.rows.filter((row) => [fixture.targetChallengeId, fixture.targetSecondChallengeId].includes(row.id)).every((row) => row.status === expected.targetChallenge && row.consumed_at !== null), true);
  assert.equal(challenges.rows.find((row) => row.id === fixture.retainedChallengeId).status, expected.retainedChallenge);
  const capabilities = await pool.query("SELECT id,revoked_at FROM capabilities WHERE organization_id=$1 AND id IN ($2,$3) ORDER BY id", [fixture.organizationId, fixture.targetCapabilityId, fixture.retainedCapabilityId]);
  assert.equal(capabilities.rows.find((row) => row.id === fixture.targetCapabilityId).revoked_at !== null, expected.targetCapabilityRevoked);
  assert.equal(capabilities.rows.find((row) => row.id === fixture.retainedCapabilityId).revoked_at !== null, expected.retainedCapabilityRevoked);
}

async function assertUnchangedAfterRollback(pool, fixture) {
  assert.deepEqual(await membershipSnapshot(pool, fixture.organizationId, fixture.targetId), {
    role: "admin", status: "active", version: 1, session_epoch: 1
  });
  await assertReductionState(pool, fixture, { targetRevoked: false, retainedRevoked: false, targetChallenge: "pending", retainedChallenge: "pending", targetCapabilityRevoked: false, retainedCapabilityRevoked: false });
  const persisted = await pool.query(`SELECT
    (SELECT count(*)::int FROM admin_audit_events WHERE organization_id=$1) AS audit_events,
    (SELECT count(*)::int FROM outbox_events WHERE organization_id=$1) AS outbox_events,
    (SELECT count(*)::int FROM idempotency_records WHERE organization_id=$1) AS idempotency_records`, [fixture.organizationId]);
  assert.deepEqual(persisted.rows[0], { audit_events: 0, outbox_events: 0, idempotency_records: 0 });
  const auditHead = await pool.query("SELECT sequence,event_hash FROM admin_audit_heads WHERE organization_id=$1", [fixture.organizationId]);
  assert.deepEqual(auditHead.rows, [{ sequence: "0", event_hash: "0".repeat(64) }]);
}

async function assertCrossTenantState(pool, fixture) {
  const session = await pool.query("SELECT revoked_at,version,recent_auth_at,recent_auth_challenge_id FROM human_sessions WHERE id=$1", [fixture.crossTenantSessionId]);
  assert.deepEqual(session.rows, [{ revoked_at: null, version: "1", recent_auth_at: new Date(CREATED_AT), recent_auth_challenge_id: fixture.crossTenantChallengeId }]);
  const challenge = await pool.query("SELECT status,consumed_at FROM webauthn_challenges WHERE id=$1", [fixture.crossTenantChallengeId]);
  assert.deepEqual(challenge.rows, [{ status: "pending", consumed_at: null }]);
  const capability = await pool.query("SELECT revoked_at FROM capabilities WHERE id=$1 AND organization_id=$2", [fixture.crossTenantCapabilityId, fixture.otherOrganizationId]);
  assert.deepEqual(capability.rows, [{ revoked_at: null }]);
}
