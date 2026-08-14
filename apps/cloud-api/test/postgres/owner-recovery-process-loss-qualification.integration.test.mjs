import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import {
  launchOwnerRecoveryProcessLossQualificationChild,
  requireOwnerRecoveryQualificationDatabase
} from "../support/owner-recovery-process-loss-qualification-harness.mjs";
import { OWNER_RECOVERY_DELIVERY_FAULT_BOUNDARIES } from "../support/owner-recovery-delivery-fault-controller.mjs";

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL;
const TEST_TIMEOUT_MS = 20_000;
const LEASE_MS = 1_000;
const DELIVERY_BINDING = Object.freeze({ binding_id: "test-owner-recovery", key_version: 1, binding_digest: "e".repeat(64) });

test("owner recovery delivery process loss is isolated across independent pools at every closed boundary", {
  skip: databaseUrl ? false : "set AGENTPASS_TEST_DATABASE_URL to run PostgreSQL process-loss qualification",
  timeout: TEST_TIMEOUT_MS
}, async (t) => {
  const pool = new Pool({ connectionString: requireOwnerRecoveryQualificationDatabase({ AGENTPASS_TEST_DATABASE_URL: databaseUrl }), max: 4, connectionTimeoutMillis: 1_000, idleTimeoutMillis: 500, statement_timeout: 3_000, query_timeout: 4_000 });
  t.after(async () => { await pool.end().catch(() => {}); });
  const migrationClient = await pool.connect();
  try {
    await createMigrationRunner({ client: migrationClient, applicationVersion: "owner-recovery-process-loss-qualification" }).run();
  } finally {
    migrationClient.release();
  }

  for (const boundary of OWNER_RECOVERY_DELIVERY_FAULT_BOUNDARIES) {
    await t.test(boundary, async (subtest) => {
      const fixture = await seed(pool, boundary);
      const killed = launchOwnerRecoveryProcessLossQualificationChild({
        databaseUrl,
        mode: "delivery",
        boundary,
        organizationId: fixture.organizationId,
        eventId: fixture.eventId,
        leaseMs: LEASE_MS,
        deadlineMs: 8_000
      });
      subtest.after(async () => {
        if (!killed.snapshot().settled) await killed.kill();
        await cleanup(pool, fixture);
      });

      await killed.waitForMessage("ready");
      killed.send({ type: "run" });
      assert.deepEqual(await killed.waitForMessage("boundary_reached"), { type: "boundary_reached", boundary });
      assert.deepEqual(await killed.kill("SIGKILL"), { code: null, signal: "SIGKILL" });

      const expectedStatus = boundary === "after_terminal_commit" ? "published" : "uncertain";
      if (expectedStatus === "published") await waitForStatus(pool, fixture, expectedStatus, 5_000);
      else await waitForLeaseExpiry(pool, fixture, LEASE_MS + 5_000);

      const reclaimer = launchOwnerRecoveryProcessLossQualificationChild({
        databaseUrl,
        mode: "reclaim",
        organizationId: fixture.organizationId,
        eventId: fixture.eventId,
        leaseMs: LEASE_MS,
        deadlineMs: 8_000
      });
      subtest.after(async () => { if (!reclaimer.snapshot().settled) await reclaimer.kill(); });
      await reclaimer.waitForMessage("ready");
      reclaimer.send({ type: "run" });
      const recovered = await reclaimer.waitForMessage("reclaimed");
      assert.equal(recovered.claimed, 0);
      assert.equal(recovered.state, expectedStatus);
      assert.deepEqual(await reclaimer.waitForExit(), { code: 0, signal: null });
    });
  }
});

async function seed(pool, label) {
  const organizationId = crypto.randomUUID();
  const memberId = crypto.randomUUID();
  const membershipId = crypto.randomUUID();
  const sessionId = crypto.randomUUID();
  const requestId = crypto.randomUUID();
  const eventId = crypto.randomUUID();
  const createdAt = new Date(Date.now() - 5_000);
  const expiresAt = new Date(Date.now() + 60 * 60_000);
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [organizationId, `process-loss-${label}`]);
  await pool.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,$3)", [memberId, `process-loss-${organizationId}`, "Process-loss qualification"]);
  await pool.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')", [organizationId, membershipId, memberId]);
  await pool.query(`INSERT INTO human_sessions
    (id,member_id,organization_id,membership_id,role,token_hash,csrf_token_hash,created_at,expires_at,idle_expires_at,last_seen_at)
    VALUES ($1,$2,$3,$4,'owner',$5,$6,$7,$8,$8,$7)`, [sessionId, memberId, organizationId, membershipId, Buffer.alloc(32, 0x11), Buffer.alloc(32, 0x22), createdAt, expiresAt]);
  await pool.query(`INSERT INTO owner_recovery_requests
    (organization_id,request_id,schema_version,kind,subject_member_id,creator_member_id,creator_session_id,threshold,expires_at,created_at,updated_at)
    VALUES ($1,$2,1,'threshold-owner-recovery',$3,$3,$4,2,$5,$6,$6)`, [organizationId, requestId, memberId, sessionId, expiresAt, createdAt]);
  await pool.query(`INSERT INTO owner_recovery_outbox
    (organization_id,event_id,request_id,subject_member_id,event_type,available_at,created_at,updated_at,
     provider_binding_state,provider_binding_id,provider_key_version,provider_binding_digest)
    VALUES ($1,$2,$3,$4,'recovery.request.created',$5,$5,$5,'bound',$6,$7,decode($8,'hex'))`, [organizationId, eventId, requestId, memberId, createdAt, DELIVERY_BINDING.binding_id, DELIVERY_BINDING.key_version, DELIVERY_BINDING.binding_digest]);
  return Object.freeze({ organizationId, memberId, eventId });
}

async function waitForStatus(pool, fixture, expected, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const result = await pool.query("SELECT status FROM owner_recovery_outbox WHERE organization_id=$1 AND event_id=$2", [fixture.organizationId, fixture.eventId]);
    if (result.rows[0]?.status === expected) return result.rows[0].status;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error("owner recovery process-loss status deadline exceeded");
}

async function waitForLeaseExpiry(pool, fixture, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const result = await pool.query("SELECT claim_expires_at <= clock_timestamp() AS expired FROM owner_recovery_outbox WHERE organization_id=$1 AND event_id=$2", [fixture.organizationId, fixture.eventId]);
    if (result.rows[0]?.expired === true) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error("owner recovery process-loss lease deadline exceeded");
}

async function cleanup(pool, fixture) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL session_replication_role = replica");
    for (const table of [
      "owner_recovery_outbox_transition_ledger", "owner_recovery_outbox_transition_heads", "owner_recovery_outbox_retention_ledger", "owner_recovery_outbox", "owner_recovery_webauthn_challenges",
      "owner_recovery_approvals", "owner_recovery_exchanges", "owner_recovery_sessions", "owner_recovery_idempotency_records",
      "owner_recovery_requests", "human_sessions", "memberships", "outbox_events", "admin_audit_events",
      "admin_audit_heads", "control_plane_authority_generations"
    ]) {
      await client.query(`DELETE FROM ${table} WHERE organization_id=$1`, [fixture.organizationId]);
    }
    await client.query("DELETE FROM members WHERE id=$1", [fixture.memberId]);
    await client.query("DELETE FROM organizations WHERE id=$1", [fixture.organizationId]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}
