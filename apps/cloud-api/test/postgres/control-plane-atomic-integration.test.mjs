import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { createPostgresControlPlaneStore } from "../../src/postgres/control-plane-store.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL;
const scope = { operations: ["git.commit.sign"], repositories: ["/repo"], branches: { allow: ["main"], deny: [] }, remotes: { allow: ["origin"], deny: [] } };

test("commits mutation and admin audit together and rolls both back on audit failure", { skip: !databaseUrl }, async (t) => {
  const pool = new Pool({ connectionString: databaseUrl, max: 2 });
  t.after(() => pool.end());
  const migrationClient = await pool.connect();
  try {
    await createMigrationRunner({ client: migrationClient, applicationVersion: "atomic-control-plane-integration" }).run();
  } finally {
    migrationClient.release();
  }

  const organizationId = randomUUID();
  const memberId = randomUUID();
  const membershipId = randomUUID();
  const committedPolicyId = randomUUID();
  const rolledBackPolicyId = randomUUID();
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [organizationId, "atomic integration"]);
  await pool.query("INSERT INTO members (id,github_subject) VALUES ($1,$2)", [memberId, `atomic-${memberId}`]);
  await pool.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')", [organizationId, membershipId, memberId]);

  const store = createPostgresControlPlaneStore({ client: pool });
  const makePolicyMutation = (policyId, sequence, name) => async ({ tx }) => {
    await tx.query(`INSERT INTO policies
      (organization_id,id,sequence,name,scope_json,status,created_by)
      VALUES ($1,$2,$3,$4,$5::jsonb,'active',$6)`, [organizationId, policyId, sequence, name, JSON.stringify(scope), memberId]);
    return { policy_id: policyId, name };
  };

  const committed = await store.runAtomicMutation({
    organizationId,
    mutation: makePolicyMutation(committedPolicyId, 1, "committed-policy"),
    audit: ({ mutation }) => ({
      organizationId, actorId: memberId, eventType: "policy.created", targetType: "policy", targetId: mutation.policy_id,
      details: { policy_id: mutation.policy_id }, idempotencyKey: "atomic-policy-0001:audit"
    })
  });
  assert.equal(committed.mutation.policy_id, committedPolicyId);
  assert.equal((await pool.query("SELECT count(*)::int AS count FROM policies WHERE organization_id=$1 AND id=$2", [organizationId, committedPolicyId])).rows[0].count, 1);
  assert.equal((await pool.query("SELECT count(*)::int AS count FROM admin_audit_events WHERE organization_id=$1 AND id=$2", [organizationId, committed.audit.audit_event_id])).rows[0].count, 1);

  await assert.rejects(store.runAtomicMutation({
    organizationId,
    mutation: makePolicyMutation(rolledBackPolicyId, 2, "rolled-back-policy"),
    audit: {
      organizationId, actorId: memberId, eventType: "policy.created", targetType: "policy", targetId: rolledBackPolicyId,
      details: { session_token: "must-fail-before-persist" }, idempotencyKey: "atomic-policy-0002:audit"
    }
  }), { code: "ERR_SECRET_MATERIAL" });
  assert.equal((await pool.query("SELECT count(*)::int AS count FROM policies WHERE organization_id=$1 AND id=$2", [organizationId, rolledBackPolicyId])).rows[0].count, 0);
  assert.equal((await pool.query("SELECT count(*)::int AS count FROM admin_audit_events WHERE organization_id=$1 AND target_id=$2", [organizationId, rolledBackPolicyId])).rows[0].count, 0);
});
