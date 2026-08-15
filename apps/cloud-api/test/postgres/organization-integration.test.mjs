import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { createPostgresOrganizationService, OrganizationServiceError } from "../../src/human-auth/organizations/postgres-service.mjs";
import { createHumanCursorCodec } from "../../src/human-auth/pagination/cursor-codec.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createPostgresOrganizationRepository } from "../../src/postgres/organization-repository.mjs";

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL;
const NOW = "2026-08-12T00:00:00.000Z";
const EXPIRES = "2026-08-13T00:00:00.000Z";
const ownerId = "11111111-1111-4111-8111-111111111111";
const invitedId = "22222222-2222-4222-8222-222222222222";
const bootstrapOrganizationId = "33333333-3333-4333-8333-333333333333";
const removedId = "77777777-7777-4777-8777-777777777777";
const removedMembershipId = "88888888-8888-4888-8888-888888888888";
const roleSessionId = "99999999-9999-4999-8999-999999999999";
const roleChallengeId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const removeSessionId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const removeChallengeId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const paginationInvitationId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const deviceId = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const agentId = "ffffffff-ffff-4fff-8fff-ffffffffffff";
const TEST_PUBLIC_KEY = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString().trimEnd();

test("Organization P1 is atomic and replay-safe across real PostgreSQL connections", { skip: !databaseUrl }, async (t) => {
  const pool = new Pool({ connectionString: databaseUrl, max: 8 });
  t.after(() => pool.end());
  const migrationClient = await pool.connect();
  try { await createMigrationRunner({ client: migrationClient, applicationVersion: "organization-integration" }).run(); }
  finally { migrationClient.release(); }

  await pool.query(`INSERT INTO members (id,github_subject,display_name) VALUES
    ($1,'integration-owner','Owner'),($2,'integration-invited','Invited'),($3,'integration-removed','Removed')`, [ownerId, invitedId, removedId]);

  let randomCounter = 0;
  const repository = createPostgresOrganizationRepository({ client: pool, now: () => NOW, onAuthorityReduction: async () => ({ generation: 2 }) });
  const cursorCodec = createHumanCursorCodec({ secret: Buffer.alloc(32, 0x42) });
  const service = createPostgresOrganizationService({
    repository,
    cursorCodec,
    now: () => NOW,
    randomBytes: (size) => Buffer.alloc(size, ++randomCounter),
    randomUUID
  });
  const owner = { session_id: "44444444-4444-4444-8444-444444444444", member_id: ownerId, organization_id: bootstrapOrganizationId, role: "owner" };

  const createInput = { actor: owner, name: "Integration Team", idempotency_key: "create-organization-integration" };
  const created = await Promise.all([service.createOrganization(createInput), service.createOrganization(createInput)]);
  assert.equal(created[0].organization_id, created[1].organization_id);
  assert.equal(created.filter((item) => item.replayed === true).length, 1);
  const organizationId = created[0].organization_id;
  owner.organization_id = organizationId;

  const secondCreated = await service.createOrganization({ ...createInput, name: "Integration Team Two", idempotency_key: "create-organization-integration-2" });
  assert.notEqual(secondCreated.organization_id, organizationId);
  const firstOrganizationPage = await service.listOrganizations({ actor: owner, limit: 1 });
  assert.equal(firstOrganizationPage.items.length, 1);
  assert.match(firstOrganizationPage.next_cursor, /^[A-Za-z0-9_-]+$/u);
  const secondOrganizationPage = await service.listOrganizations({ actor: owner, limit: 1, cursor: firstOrganizationPage.next_cursor });
  assert.equal(secondOrganizationPage.items.length, 1);
  assert.equal(secondOrganizationPage.next_cursor, null);
  assert.deepEqual(new Set([firstOrganizationPage.items[0].organization_id, secondOrganizationPage.items[0].organization_id]), new Set([organizationId, secondCreated.organization_id]));

  await assert.rejects(
    service.createOrganization({ ...createInput, name: "Changed payload" }),
    (error) => error instanceof OrganizationServiceError && error.code === "idempotency_conflict"
  );

  const invitationInput = { actor: owner, organization_id: organizationId, role: "viewer", expires_at: EXPIRES, idempotency_key: "create-invitation-integration" };
  const firstInvitation = await service.createInvitation(invitationInput);
  const replayedInvitation = await service.createInvitation(invitationInput);
  assert.equal(firstInvitation.raw_token.length, 43);
  assert.equal(firstInvitation.invitation.invitation_id, replayedInvitation.invitation.invitation_id);
  assert.equal(replayedInvitation.replayed, true);
  assert.equal(Object.hasOwn(replayedInvitation, "raw_token"), false);

  const invited = { session_id: "55555555-5555-4555-8555-555555555555", member_id: invitedId, organization_id: organizationId, role: "viewer" };
  const acceptanceInput = { actor: invited, one_time_token: firstInvitation.raw_token, idempotency_key: "accept-invitation-integration" };
  const acceptedAttempts = await Promise.all([
    service.acceptInvitation(acceptanceInput),
    service.acceptInvitation(acceptanceInput)
  ]);
  const accepted = acceptedAttempts.find((result) => result.replayed !== true);
  const acceptedReplay = acceptedAttempts.find((result) => result.replayed === true);
  assert.ok(accepted);
  assert.ok(acceptedReplay);
  assert.equal(accepted.member.member_id, invitedId);
  assert.equal(accepted.member.role, "viewer");
  assert.equal(accepted.invitation.invitation_id, firstInvitation.invitation.invitation_id);
  assert.equal(accepted.invitation.status, "accepted");
  assert.equal(accepted.invitation.accepted_at, NOW);
  assert.equal(accepted.invitation.accepted_member_id, invitedId);
  assert.deepEqual({ invitation: acceptedReplay.invitation, member: acceptedReplay.member }, { invitation: accepted.invitation, member: accepted.member });

  const acceptanceState = await pool.query(`
    SELECT
      (SELECT count(*)::int FROM memberships WHERE organization_id=$1 AND member_id=$2 AND status='active') AS membership_count,
      (SELECT count(*)::int FROM organization_invitations WHERE organization_id=$1 AND id=$3 AND consumed_by=$2 AND consumed_at IS NOT NULL) AS consumed_count,
      (SELECT count(*)::int FROM admin_audit_events WHERE organization_id=$1 AND action='invitation.accepted' AND target_id=$3) AS audit_count,
      (SELECT count(*)::int FROM outbox_events WHERE organization_id=$1 AND action='invitation.accepted' AND aggregate='invitation') AS outbox_count`,
    [organizationId, invitedId, firstInvitation.invitation.invitation_id]
  );
  assert.deepEqual(acceptanceState.rows[0], { membership_count: 1, consumed_count: 1, audit_count: 1, outbox_count: 1 });

  await pool.query(`INSERT INTO memberships (organization_id,id,member_id,role,status)
    VALUES ($1,$2,$3,'viewer','active')`, [organizationId, removedMembershipId, removedId]);
  await pool.query(`INSERT INTO organization_invitations
    (organization_id,id,token_hash,role,created_by,created_at,expires_at)
    VALUES ($1,$2,$3,'viewer',$4,$5,$6)`, [organizationId, paginationInvitationId, Buffer.alloc(32, 90), ownerId, "2026-08-12T00:00:01.000Z", EXPIRES]);

  const firstMemberPage = await service.listMembers({ actor: owner, organization_id: organizationId, limit: 2 });
  const secondMemberPage = await service.listMembers({ actor: owner, organization_id: organizationId, limit: 2, cursor: firstMemberPage.next_cursor });
  assert.equal(firstMemberPage.items.length, 2);
  assert.equal(secondMemberPage.items.length, 1);
  assert.equal(secondMemberPage.next_cursor, null);
  assert.equal(new Set([...firstMemberPage.items, ...secondMemberPage.items].map((item) => item.membership_id)).size, 3);

  const firstInvitationPage = await service.listInvitations({ actor: owner, organization_id: organizationId, limit: 1 });
  const secondInvitationPage = await service.listInvitations({ actor: owner, organization_id: organizationId, limit: 1, cursor: firstInvitationPage.next_cursor });
  assert.equal(firstInvitationPage.items.length, 1);
  assert.equal(secondInvitationPage.items.length, 1);
  assert.equal(secondInvitationPage.next_cursor, null);
  assert.equal(new Set([...firstInvitationPage.items, ...secondInvitationPage.items].map((item) => item.invitation_id)).size, 2);

  await pool.query(`INSERT INTO devices (organization_id,id,label,key_algorithm,status,public_key_pem)
    VALUES ($1,$2,'Integration device','ed25519','active',$3)`, [organizationId, deviceId, TEST_PUBLIC_KEY]);
  await pool.query(`INSERT INTO agents (organization_id,id,device_id,kind,name,public_key_pem,status)
    VALUES ($1,$2,$3,'cli','Integration agent',$4,'active')`, [organizationId, agentId, deviceId, TEST_PUBLIC_KEY]);
  await pool.query(`INSERT INTO capabilities
    (organization_id,id,agent_id,device_id,sequence,statement_hash,expires_at,issued_by_member_id,issued_membership_version)
    VALUES ($1,$2,$3,$4,1,$5,$6,$7,$8),($1,$9,$3,$4,2,$10,$6,$11,1)`, [
    organizationId, randomUUID(), agentId, deviceId, "a".repeat(64), EXPIRES, invitedId, accepted.member.version,
    randomUUID(), "b".repeat(64), removedId
  ]);

  async function seedRecentAuthSession({ sessionId, challengeId, memberId, membershipId, role, operation, byte }) {
    await pool.query(`INSERT INTO human_sessions
      (id,member_id,organization_id,membership_id,role,token_hash,csrf_token_hash,created_at,expires_at,version)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,1)`, [sessionId, memberId, organizationId, membershipId, role, Buffer.alloc(32, byte), Buffer.alloc(32, byte + 1), NOW, EXPIRES]);
    await pool.query(`INSERT INTO webauthn_challenges
      (id,session_id,member_id,organization_id,ceremony,operation,challenge_hash,created_at,expires_at,rp_id,origin,user_verification,status)
      VALUES ($1,$2,$3,$4,'authentication',$5,$6,$7,$8,'app.ai-agentpass.com','https://app.ai-agentpass.com','required','pending')`, [challengeId, sessionId, memberId, organizationId, operation, Buffer.alloc(32, byte + 2), NOW, EXPIRES]);
    await pool.query(`UPDATE human_sessions SET recent_auth_at=$2,recent_auth_challenge_id=$3,
      recent_auth_organization_id=$4,recent_auth_operation=$5,recent_auth_consumed_at=NULL
      WHERE id=$1`, [sessionId, NOW, challengeId, organizationId, operation]);
  }

  await seedRecentAuthSession({ sessionId: roleSessionId, challengeId: roleChallengeId, memberId: invitedId, membershipId: accepted.member.membership_id, role: "viewer", operation: "human.organizations.member.role.update", byte: 10 });
  await seedRecentAuthSession({ sessionId: removeSessionId, challengeId: removeChallengeId, memberId: removedId, membershipId: removedMembershipId, role: "viewer", operation: "human.organizations.member.remove", byte: 20 });

  await repository.updateMemberRole({ organization_id: organizationId, actor_member_id: ownerId, member_id: invitedId, role: "owner", expected_version: accepted.member.version, idempotency_key: "promote-second-owner" });
  const roleSession = await pool.query(`SELECT revoked_at,revoke_reason,version,recent_auth_at,recent_auth_challenge_id,
    recent_auth_organization_id,recent_auth_operation,recent_auth_consumed_at
    FROM human_sessions WHERE id=$1`, [roleSessionId]);
  assert.equal(roleSession.rowCount, 1);
  assert.ok(new Date(roleSession.rows[0].revoked_at).getTime() >= Date.parse(NOW), "role-change revocation must use authoritative database time");
  assert.equal(roleSession.rows[0].revoke_reason, "membership_changed");
  assert.equal(Number(roleSession.rows[0].version), 2);
  assert.equal(roleSession.rows[0].recent_auth_at, null);
  assert.equal(roleSession.rows[0].recent_auth_challenge_id, null);
  assert.equal(roleSession.rows[0].recent_auth_organization_id, null);
  assert.equal(roleSession.rows[0].recent_auth_operation, null);
  assert.equal(roleSession.rows[0].recent_auth_consumed_at, null);
  const roleChallenge = await pool.query("SELECT status,consumed_at FROM webauthn_challenges WHERE id=$1", [roleChallengeId]);
  assert.equal(roleChallenge.rows[0].status, "consumed");
  assert.ok(new Date(roleChallenge.rows[0].consumed_at).getTime() >= Date.parse(NOW), "role-change challenge consumption must use authoritative database time");
  const roleCapabilities = await pool.query("SELECT count(*)::int AS active FROM capabilities WHERE organization_id=$1 AND issued_by_member_id=$2 AND revoked_at IS NULL", [organizationId, invitedId]);
  assert.equal(roleCapabilities.rows[0].active, 0);

  await assert.rejects(
    repository.removeMember({ organization_id: organizationId, actor_member_id: ownerId, member_id: removedId, expected_version: 99, removed_at: NOW, idempotency_key: "remove-stale-integration" }),
    (error) => error.code === "ERR_VERSION_CONFLICT"
  );
  const beforeRemoval = await pool.query(`SELECT m.status,m.version,s.revoked_at,s.recent_auth_at,s.recent_auth_challenge_id
    FROM memberships m JOIN human_sessions s ON s.member_id=m.member_id AND s.organization_id=m.organization_id
    WHERE m.organization_id=$1 AND m.member_id=$2 AND s.id=$3`, [organizationId, removedId, removeSessionId]);
  assert.equal(beforeRemoval.rows[0].status, "active");
  assert.equal(Number(beforeRemoval.rows[0].version), 1);
  assert.equal(beforeRemoval.rows[0].revoked_at, null);
  assert.equal(new Date(beforeRemoval.rows[0].recent_auth_at).toISOString(), NOW);
  assert.equal(beforeRemoval.rows[0].recent_auth_challenge_id, removeChallengeId);

  await repository.removeMember({ organization_id: organizationId, actor_member_id: ownerId, member_id: removedId, expected_version: 1, removed_at: NOW, idempotency_key: "remove-member-integration" });
  const removedSession = await pool.query(`SELECT revoked_at,revoke_reason,version,recent_auth_at,recent_auth_challenge_id,
    recent_auth_organization_id,recent_auth_operation,recent_auth_consumed_at
    FROM human_sessions WHERE id=$1`, [removeSessionId]);
  assert.ok(new Date(removedSession.rows[0].revoked_at).getTime() >= Date.parse(NOW), "member-removal revocation must use authoritative database time");
  assert.equal(removedSession.rows[0].revoke_reason, "membership_removed");
  assert.equal(Number(removedSession.rows[0].version), 2);
  assert.equal(removedSession.rows[0].recent_auth_at, null);
  assert.equal(removedSession.rows[0].recent_auth_challenge_id, null);
  assert.equal(removedSession.rows[0].recent_auth_organization_id, null);
  assert.equal(removedSession.rows[0].recent_auth_operation, null);
  assert.equal(removedSession.rows[0].recent_auth_consumed_at, null);
  const removeChallenge = await pool.query("SELECT status,consumed_at FROM webauthn_challenges WHERE id=$1", [removeChallengeId]);
  assert.equal(removeChallenge.rows[0].status, "consumed");
  assert.ok(new Date(removeChallenge.rows[0].consumed_at).getTime() >= Date.parse(NOW), "member-removal challenge consumption must use authoritative database time");
  const removedCapabilities = await pool.query("SELECT count(*)::int AS active FROM capabilities WHERE organization_id=$1 AND issued_by_member_id=$2 AND revoked_at IS NULL", [organizationId, removedId]);
  assert.equal(removedCapabilities.rows[0].active, 0);

  const memberships = await pool.query("SELECT member_id,version FROM memberships WHERE organization_id=$1 AND role='owner' AND status='active' ORDER BY member_id", [organizationId]);
  assert.equal(memberships.rowCount, 2);
  const demotions = await Promise.allSettled(memberships.rows.map((row, index) => repository.updateMemberRole({
    organization_id: organizationId,
    actor_member_id: ownerId,
    member_id: row.member_id,
    role: "admin",
    expected_version: Number(row.version),
    idempotency_key: `concurrent-owner-demotion-${index}`
  })));
  assert.equal(demotions.filter((item) => item.status === "fulfilled").length, 1);
  assert.equal(demotions.filter((item) => item.status === "rejected").length, 1);

  const evidence = await pool.query(`SELECT
    (SELECT count(*)::int FROM organizations WHERE id=$1) AS organizations,
    (SELECT count(*)::int FROM memberships WHERE organization_id=$1 AND role='owner' AND status='active') AS active_owners,
    (SELECT count(*)::int FROM admin_audit_events WHERE organization_id=$1) AS audit_events,
    (SELECT count(*)::int FROM outbox_events WHERE organization_id=$1) AS outbox_events,
    (SELECT count(*)::int FROM idempotency_records WHERE organization_id=$1) AS idempotency_records,
    (SELECT count(*)::int FROM idempotency_records WHERE organization_id=$1 AND response_json::text ~ '(raw_token|one_time_token|token_hash)') AS secret_responses`, [organizationId]);
  assert.deepEqual(evidence.rows[0], { organizations: 1, active_owners: 1, audit_events: 6, outbox_events: 6, idempotency_records: 6, secret_responses: 0 });

  const outsiderList = await repository.listMembers({ organization_id: organizationId, actor_member_id: "66666666-6666-4666-8666-666666666666" });
  assert.deepEqual(outsiderList, []);
});
