import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { OwnerRecoveryRepositoryError, createPostgresOwnerRecoveryRepository } from "../../src/postgres/owner-recovery-repository.mjs";

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL;
const NOW = new Date("2026-08-14T12:00:00.000Z");
const DELIVERY_BINDING = Object.freeze({ binding_id: "test-owner-recovery", key_version: 1, binding_digest: "c".repeat(64) });

test("owner recovery forward-state CAS commits on fromState and rolls back with later failure", { skip: !databaseUrl }, async (t) => {
  const pool = new Pool({ connectionString: databaseUrl, max: 4 });
  const ids = {
    organization: crypto.randomUUID(),
    member: crypto.randomUUID(),
    membership: crypto.randomUUID(),
    session: crypto.randomUUID(),
    committedRequest: crypto.randomUUID(),
    rolledBackRequest: crypto.randomUUID()
  };
  t.after(async () => {
    const cleanup = await pool.connect();
    try {
      await cleanup.query("BEGIN");
      await cleanup.query("SET LOCAL session_replication_role = replica");
      for (const table of ["owner_recovery_outbox_transition_ledger", "owner_recovery_outbox_transition_heads", "owner_recovery_outbox_retention_ledger", "owner_recovery_outbox", "owner_recovery_requests", "human_sessions", "memberships", "admin_audit_events", "admin_audit_heads", "outbox_events", "control_plane_authority_generations"]) {
        await cleanup.query(`DELETE FROM ${table} WHERE organization_id=$1`, [ids.organization]);
      }
      await cleanup.query("DELETE FROM organizations WHERE id=$1", [ids.organization]);
      await cleanup.query("DELETE FROM members WHERE id=$1", [ids.member]);
      await cleanup.query("COMMIT");
    } catch (error) {
      await cleanup.query("ROLLBACK");
      throw error;
    } finally {
      cleanup.release();
    }
    await pool.end();
  });

  const migrationClient = await pool.connect();
  try {
    const migration = await createMigrationRunner({ client: migrationClient, applicationVersion: "owner-recovery-transition-integration" }).run();
    assert.equal(migration.currentVersion, 36);
  } finally {
    migrationClient.release();
  }

  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,'Recovery transition integration')", [ids.organization]);
  await pool.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,'Recovery subject')", [ids.member, `recovery-transition-${ids.member}`]);
  await pool.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')", [ids.organization, ids.membership, ids.member]);
  await pool.query(`INSERT INTO human_sessions
    (id,member_id,organization_id,membership_id,role,token_hash,csrf_token_hash,created_at,expires_at,idle_expires_at,last_seen_at)
    VALUES ($1,$2,$3,$4,'owner',$5,$6,$7,$8,$8,$7)`, [ids.session, ids.member, ids.organization, ids.membership, crypto.randomBytes(32), crypto.randomBytes(32), new Date(NOW.getTime() - 3_600_000), new Date(NOW.getTime() + 3_600_000)]);
  await insertPendingRequest(pool, ids, ids.committedRequest);

  const recorded = [];
  const metrics = { recordOwnerRecoveryStateLatency(value) { recorded.push(value); } };
  const repository = createPostgresOwnerRecoveryRepository({ client: pool, deliveryBinding: DELIVERY_BINDING, clock: () => NOW, metrics });
  const committed = await repository.expireRequest({ organization_id: ids.organization, request_id: ids.committedRequest, expected_version: 1 });
  assert.equal(committed.request.state, "expired");
  assert.equal(committed.request.version, 2);
  const stored = await pool.query("SELECT state,version,terminal_reason FROM owner_recovery_requests WHERE organization_id=$1 AND request_id=$2", [ids.organization, ids.committedRequest]);
  assert.deepEqual(stored.rows[0], { state: "expired", version: "2", terminal_reason: "recovery_request_expired" });
  assert.equal(recorded.length, 1);
  assert.ok(Number.isSafeInteger(recorded[0]) && recorded[0] >= 60_000);

  await insertPendingRequest(pool, ids, ids.rolledBackRequest);
  const failingClient = {
    query: (text, params) => pool.query(text, params),
    async connect() {
      const client = await pool.connect();
      return {
        release: (...args) => client.release(...args),
        query(text, params) {
          if (/INSERT INTO owner_recovery_outbox/u.test(text)) throw new Error("injected post-transition failure");
          return client.query(text, params);
        }
      };
    }
  };
  const failing = createPostgresOwnerRecoveryRepository({ client: failingClient, deliveryBinding: DELIVERY_BINDING, clock: () => NOW, metrics });
  await assert.rejects(
    failing.expireRequest({ organization_id: ids.organization, request_id: ids.rolledBackRequest, expected_version: 1 }),
    (error) => error instanceof OwnerRecoveryRepositoryError && error.code === "unavailable"
  );
  const rolledBack = await pool.query("SELECT state,version,terminal_reason FROM owner_recovery_requests WHERE organization_id=$1 AND request_id=$2", [ids.organization, ids.rolledBackRequest]);
  assert.deepEqual(rolledBack.rows[0], { state: "pending", version: "1", terminal_reason: null });
  assert.equal(recorded.length, 1);
});

function insertPendingRequest(pool, ids, requestId) {
  return pool.query(`INSERT INTO owner_recovery_requests
    (organization_id,request_id,schema_version,kind,subject_member_id,creator_member_id,creator_session_id,state,threshold,approved_owner_count,expires_at,created_at,updated_at)
    VALUES ($1,$2,1,'threshold-owner-recovery',$3,$3,$4,'pending',2,0,$5,clock_timestamp()-interval '60 seconds',clock_timestamp()-interval '60 seconds')`, [ids.organization, requestId, ids.member, ids.session, new Date(NOW.getTime() - 1)]);
}
