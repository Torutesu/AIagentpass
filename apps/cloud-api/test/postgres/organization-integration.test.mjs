import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { createPostgresOrganizationService, OrganizationServiceError } from "../../src/human-auth/organizations/postgres-service.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createPostgresOrganizationRepository } from "../../src/postgres/organization-repository.mjs";

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL;
const NOW = "2026-08-12T00:00:00.000Z";
const EXPIRES = "2026-08-13T00:00:00.000Z";
const ownerId = "11111111-1111-4111-8111-111111111111";
const invitedId = "22222222-2222-4222-8222-222222222222";
const bootstrapOrganizationId = "33333333-3333-4333-8333-333333333333";

test("Organization P1 is atomic and replay-safe across real PostgreSQL connections", { skip: !databaseUrl }, async (t) => {
  const pool = new Pool({ connectionString: databaseUrl, max: 8 });
  t.after(() => pool.end());
  const migrationClient = await pool.connect();
  try { await createMigrationRunner({ client: migrationClient, applicationVersion: "organization-integration" }).run(); }
  finally { migrationClient.release(); }

  await pool.query(`INSERT INTO members (id,github_subject,display_name) VALUES
    ($1,'integration-owner','Owner'),($2,'integration-invited','Invited')`, [ownerId, invitedId]);

  let randomCounter = 0;
  const repository = createPostgresOrganizationRepository({ client: pool, now: () => NOW });
  const service = createPostgresOrganizationService({
    repository,
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
  const accepted = await service.acceptInvitation(acceptanceInput);
  const acceptedReplay = await service.acceptInvitation(acceptanceInput);
  assert.equal(accepted.member_id, invitedId);
  assert.equal(acceptedReplay.member_id, invitedId);
  assert.equal(acceptedReplay.replayed, true);

  await repository.updateMemberRole({ organization_id: organizationId, actor_member_id: ownerId, member_id: invitedId, role: "owner", expected_version: accepted.version, idempotency_key: "promote-second-owner" });
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
  assert.deepEqual(evidence.rows[0], { organizations: 1, active_owners: 1, audit_events: 5, outbox_events: 5, idempotency_records: 5, secret_responses: 0 });

  const outsiderList = await repository.listMembers({ organization_id: organizationId, actor_member_id: "66666666-6666-4666-8666-666666666666" });
  assert.deepEqual(outsiderList, []);
});
