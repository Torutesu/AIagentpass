import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

const MIGRATOR_URL = process.env.AGENTPASS_TEST_MIGRATION_DATABASE_URL;
const APP_URL = process.env.AGENTPASS_TEST_APP_DATABASE_URL;
const SQLSTATE_PERMISSION_DENIED = new Set(["42501", "0LP01"]);

test("0052 enforces dual-control activation, generation revocation, session epochs, and app function-only access", {
  skip: MIGRATOR_URL && APP_URL ? false : "set actual app and migrator PostgreSQL URLs to run platform authority qualification",
  timeout: 120_000
}, async (t) => {
  const migrator = new Pool({ connectionString: MIGRATOR_URL, max: 2 });
  const app = new Pool({ connectionString: APP_URL, max: 2 });
  t.after(async () => Promise.all([migrator.end(), app.end()]));

  const ids = Object.freeze({
    organization: crypto.randomUUID(),
    membership: crypto.randomUUID(),
    session: crypto.randomUUID(),
    currentSession: crypto.randomUUID(),
    targetMember: crypto.randomUUID(),
    targetPrincipal: crypto.randomUUID(),
    approverMemberA: crypto.randomUUID(),
    approverPrincipalA: crypto.randomUUID(),
    approverMemberB: crypto.randomUUID(),
    approverPrincipalB: crypto.randomUUID(),
    assignment: crypto.randomUUID(),
    approvalA: crypto.randomUUID(),
    approvalB: crypto.randomUUID()
  });
  const digest = crypto.createHash("sha256").update(JSON.stringify({
    organization_id: ids.organization,
    principal_id: ids.targetPrincipal,
    operation: "platform.promotion.issue",
    capability: "platform.promotion.issue"
  })).digest();

  const migratorIdentity = await migrator.query("SELECT session_user,current_user");
  assert.deepEqual(migratorIdentity.rows[0], { session_user: "agentpass_migrator", current_user: "agentpass_migrator" });
  const appIdentity = await app.query("SELECT session_user,current_user");
  assert.deepEqual(appIdentity.rows[0], { session_user: "agentpass_app", current_user: "agentpass_app" });

  await migrator.query("INSERT INTO organizations(id,name) VALUES ($1,'N2 integration organization')", [ids.organization]);
  await migrator.query(`INSERT INTO members(id,github_subject,display_name) VALUES
    ($1,$2,'N2 target'),($3,$4,'N2 approver A'),($5,$6,'N2 approver B')`, [
    ids.targetMember, `n2-target-${ids.targetMember}`,
    ids.approverMemberA, `n2-approver-a-${ids.approverMemberA}`,
    ids.approverMemberB, `n2-approver-b-${ids.approverMemberB}`
  ]);
  await migrator.query(`INSERT INTO memberships(organization_id,id,member_id,role,status)
    VALUES ($1,$2,$3,'viewer','active')`, [ids.organization, ids.membership, ids.targetMember]);
  await migrator.query(`INSERT INTO human_sessions
    (id,member_id,token_hash,created_at,expires_at,organization_id,membership_id,role,
     csrf_token_hash,last_seen_at,idle_expires_at)
    VALUES ($1,$2,decode($3,'hex'),clock_timestamp(),clock_timestamp()+interval '1 hour',
      $4,$5,'viewer',decode($6,'hex'),clock_timestamp(),clock_timestamp()+interval '30 minutes')`, [
    ids.session, ids.targetMember, crypto.randomBytes(32).toString("hex"),
    ids.organization, ids.membership, crypto.randomBytes(32).toString("hex")
  ]);

  for (const [principalId, memberId] of [
    [ids.targetPrincipal, ids.targetMember],
    [ids.approverPrincipalA, ids.approverMemberA],
    [ids.approverPrincipalB, ids.approverMemberB]
  ]) {
    const provisioned = await migrator.query(
      "SELECT agentpass_platform_principal_provision($1::uuid,$2::uuid) AS principal",
      [principalId, memberId]
    );
    assert.equal(provisioned.rows[0].principal.authority_generation, 1);
  }

  const requested = await migrator.query(`SELECT agentpass_platform_operator_assignment_request(
    $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::text,$6::text,$7::bytea,
    clock_timestamp()+interval '30 minutes') AS assignment`, [
    ids.assignment, ids.targetPrincipal, ids.targetMember, ids.organization,
    "platform.promotion.issue", "platform.promotion.issue", digest
  ]);
  assert.equal(requested.rows[0].assignment.status, "pending");
  assert.equal(requested.rows[0].assignment.requested_authority_generation, 1);

  await migrator.query("SELECT agentpass_platform_operator_assignment_approve($1::uuid,$2::uuid,$3::uuid,$4::bytea)", [
    ids.approvalA, ids.assignment, ids.approverPrincipalA, digest
  ]);
  await assert.rejects(
    migrator.query("SELECT agentpass_platform_operator_assignment_activate($1::uuid)", [ids.assignment]),
    (error) => error?.code === "23514"
  );
  await migrator.query("SELECT agentpass_platform_operator_assignment_approve($1::uuid,$2::uuid,$3::uuid,$4::bytea)", [
    ids.approvalB, ids.assignment, ids.approverPrincipalB, digest
  ]);
  const activated = await migrator.query(
    "SELECT agentpass_platform_operator_assignment_activate($1::uuid) AS assignment",
    [ids.assignment]
  );
  assert.equal(activated.rows[0].assignment.status, "active");
  assert.equal(activated.rows[0].assignment.authority_generation, 2);

  const approvalReplay = await migrator.query(
    "SELECT agentpass_platform_operator_assignment_approve($1::uuid,$2::uuid,$3::uuid,$4::bytea) AS approval",
    [ids.approvalA, ids.assignment, ids.approverPrincipalA, digest]
  );
  assert.equal(approvalReplay.rows[0].approval.approval_id, ids.approvalA);
  await assert.rejects(
    migrator.query(
      "SELECT agentpass_platform_operator_assignment_approve($1::uuid,$2::uuid,$3::uuid,$4::bytea)",
      [crypto.randomUUID(), ids.assignment, ids.approverPrincipalA, digest]
    ),
    (error) => error?.code === "23505"
  );

  const lookup = () => app.query(`SELECT agentpass_platform_operator_assignment_find_active(
    $1::uuid,$2::uuid,$3::uuid,$4::text,$5::text) AS assignment`, [
    ids.organization, ids.targetMember, ids.session,
    "platform.promotion.issue", "platform.promotion.issue"
  ]);
  const found = await lookup();
  assert.equal(found.rows[0].assignment.principal_id, ids.targetPrincipal);
  assert.equal(found.rows[0].assignment.authority_generation, 2);
  assert.equal(found.rows[0].assignment.role, "platform_operator");

  await migrator.query("UPDATE memberships SET role='admin',version=version+1 WHERE organization_id=$1 AND id=$2", [
    ids.organization, ids.membership
  ]);
  assert.equal((await lookup()).rows[0].assignment, null, "a stale membership epoch must deny lookup");
  await migrator.query(`INSERT INTO human_sessions
    (id,member_id,token_hash,created_at,expires_at,organization_id,membership_id,role,
     csrf_token_hash,last_seen_at,idle_expires_at)
    VALUES ($1,$2,decode($3,'hex'),clock_timestamp(),clock_timestamp()+interval '1 hour',
      $4,$5,'admin',decode($6,'hex'),clock_timestamp(),clock_timestamp()+interval '30 minutes')`, [
    ids.currentSession, ids.targetMember, crypto.randomBytes(32).toString("hex"),
    ids.organization, ids.membership, crypto.randomBytes(32).toString("hex")
  ]);
  const currentLookup = () => app.query(`SELECT agentpass_platform_operator_assignment_find_active(
    $1::uuid,$2::uuid,$3::uuid,$4::text,$5::text) AS assignment`, [
    ids.organization, ids.targetMember, ids.currentSession,
    "platform.promotion.issue", "platform.promotion.issue"
  ]);
  assert.equal((await currentLookup()).rows[0].assignment.principal_id, ids.targetPrincipal);

  await assert.rejects(
    app.query("UPDATE platform_operator_assignments SET version=version+1 WHERE assignment_id=$1", [ids.assignment]),
    (error) => SQLSTATE_PERMISSION_DENIED.has(error?.code)
  );
  await assert.rejects(
    app.query("SELECT agentpass_platform_operator_assignment_revoke($1::uuid,$2::text)", [ids.assignment, "app bypass"]),
    (error) => SQLSTATE_PERMISSION_DENIED.has(error?.code)
  );

  const suspended = await migrator.query(
    "SELECT agentpass_platform_operator_assignment_suspend($1::uuid,$2::text) AS assignment",
    [ids.assignment, "N2 qualification suspension"]
  );
  assert.equal(suspended.rows[0].assignment.status, "suspended");
  assert.equal(suspended.rows[0].assignment.authority_generation, 3);
  assert.equal((await currentLookup()).rows[0].assignment, null);
  const replay = await migrator.query(
    "SELECT agentpass_platform_operator_assignment_suspend($1::uuid,$2::text) AS assignment",
    [ids.assignment, "ignored replay reason"]
  );
  assert.equal(replay.rows[0].assignment.authority_generation, 3);
});
