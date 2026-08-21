import { POSTGRES_SCHEMA_HEAD } from "../../src/postgres/schema-head.mjs";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import { createPostgresHumanRepository } from "../../src/postgres/human-repository.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createPostgresOwnerRecoveryOutboxManagementRepository, OWNER_RECOVERY_OUTBOX_MANAGEMENT_OPERATIONS } from "../../src/postgres/owner-recovery-outbox-management-repository.mjs";
import { createPostgresOwnerRecoveryOutboxRepository } from "../../src/postgres/owner-recovery-outbox-repository.mjs";
import { createOwnerRecoveryOutboxWorker } from "../../src/postgres/owner-recovery-outbox-worker.mjs";
import { createOwnerRecoveryProviderAcceptanceLedger, createOwnerRecoveryFakeProvider, ensureOwnerRecoveryProviderAcceptanceLedger } from "../support/owner-recovery-provider-acceptance-ledger.mjs";
import { launchOwnerRecoveryProviderAcceptanceChild } from "../support/owner-recovery-provider-acceptance-harness.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL;
const LEASE_MS = 1_000;
const RP_ID = "console.agentpass.test";
const ORIGIN = "https://console.agentpass.test";

test("durable fake-provider acceptance converges after lost response and uncertain retry", {
  skip: DATABASE_URL ? false : "set AGENTPASS_TEST_DATABASE_URL to run PostgreSQL provider-acceptance qualification",
  timeout: 30_000
}, async (t) => {
  const pool = new Pool({ connectionString: DATABASE_URL, max: 8, connectionTimeoutMillis: 1_000, idleTimeoutMillis: 500, statement_timeout: 3_000, query_timeout: 4_000 });
  const migrationClient = await pool.connect();
  try {
    const migration = await createMigrationRunner({ client: migrationClient, applicationVersion: "owner-recovery-provider-acceptance" }).run();
    assert.equal(migration.currentVersion, POSTGRES_SCHEMA_HEAD.version);
  } finally { migrationClient.release(); }
  const fixture = await seed(pool);
  t.after(async () => { await cleanup(pool, fixture); await pool.end(); });

  await ensureOwnerRecoveryProviderAcceptanceLedger(pool);
  const ledger = createOwnerRecoveryProviderAcceptanceLedger({ client: pool });
  const child = launchOwnerRecoveryProviderAcceptanceChild({ databaseUrl: DATABASE_URL, binding: fixture.binding, leaseMs: LEASE_MS });
  t.after(async () => { await child.kill().catch(() => {}); });
  await child.waitForMessage("ready");
  child.send();
  assert.deepEqual(await child.waitForMessage("accepted"), { type: "accepted", duplicate: false });
  assert.deepEqual(await child.kill(), { code: null, signal: "SIGKILL" });

  assert.equal(await ledger.count({ binding: fixture.binding, idempotency_key: fixture.eventId }), 1);
  await waitForLease(pool, fixture);

  const reclaimRepository = createPostgresOwnerRecoveryOutboxRepository({ client: pool, deliveryBinding: fixture.binding });
  const reclaimed = await reclaimRepository.claimBatch({ limit: 1, lease_ms: LEASE_MS });
  assert.deepEqual(reclaimed.events, []);
  assert.equal((await state(pool, fixture)).status, "uncertain");

  const management = createPostgresOwnerRecoveryOutboxManagementRepository({
    client: pool,
    cursorSecret: Buffer.alloc(32, 0x61),
    auditRepository: { async appendAdminAuditEventInTransaction() {} }
  });
  const retry = await management.retryUncertain({
    actor: fixture.actor,
    event_id: fixture.eventId,
    expected_management_version: 1,
    idempotency_key: "provider-acceptance-retry-1",
    context_hash: fixture.contextHash,
    recent_authorization: fixture.authorization
  });
  assert.equal(retry.status, "pending");
  assert.equal(retry.management_version, 2);

  let retryAcceptance;
  const retryProvider = createOwnerRecoveryFakeProvider({ ledger, binding: fixture.binding, afterAcceptance: (response) => { retryAcceptance = response; } });
  const worker = createOwnerRecoveryOutboxWorker({
    repository: createPostgresOwnerRecoveryOutboxRepository({ client: pool, deliveryBinding: fixture.binding }),
    publisher: retryProvider,
    leaseMs: LEASE_MS,
    publishTimeoutMs: 100,
    drainTimeoutMs: 100,
    pollIntervalMs: 100
  });
  assert.deepEqual(await worker.runOnce(), { claimed: 1, published: 1, retried: 0, dead_lettered: 0, claim_lost: 0, uncertain: 0, confirmation_checked: 0, confirmed: 0 });
  assert.equal((await state(pool, fixture)).status, "published");
  assert.deepEqual(retryAcceptance, { accepted: true, duplicate: true, idempotency_key: fixture.eventId, delivery_attempts: 2 });
  assert.equal(await ledger.count({ binding: fixture.binding, idempotency_key: fixture.eventId }), 1, "retry must not create a second logical provider acceptance");

  const otherBinding = { ...fixture.binding, key_version: 2 };
  assert.deepEqual(await ledger.accept({ binding: otherBinding, idempotency_key: fixture.eventId }), { accepted: true, duplicate: false, idempotency_key: fixture.eventId, delivery_attempts: 1 });
  assert.equal(await ledger.count({ binding: otherBinding, idempotency_key: fixture.eventId }), 1, "the binding is part of the acceptance key");
  const transitions = await pool.query(`SELECT reason,to_status FROM owner_recovery_outbox_transition_ledger
    WHERE organization_id=$1 AND event_id=$2 ORDER BY transition_sequence`, [fixture.organizationId, fixture.eventId]);
  assert.deepEqual(transitions.rows.map((row) => [row.reason, row.to_status]), [
    ["event_created", "pending"],
    ["delivery_claimed", "pending"],
    ["process_interrupted", "uncertain"],
    ["operator_retry", "pending"],
    ["delivery_claimed", "pending"],
    ["provider_acknowledged", "published"]
  ]);
  assert.equal(JSON.stringify(transitions.rows).includes("secret"), false);
});

async function seed(pool) {
  const organizationId = crypto.randomUUID();
  const memberId = crypto.randomUUID();
  const membershipId = crypto.randomUUID();
  const sessionId = crypto.randomUUID();
  const requestId = crypto.randomUUID();
  const eventId = crypto.randomUUID();
  const challengeId = crypto.randomUUID();
  const binding = Object.freeze({ binding_id: `test-owner-recovery-${crypto.randomUUID().slice(0, 12)}`, key_version: 1, binding_digest: "e".repeat(64) });
  const createdAt = new Date(Date.now() - 5_000);
  const expiresAt = new Date(Date.now() + 60 * 60_000);
  const actor = { organization_id: organizationId, member_id: memberId, session_id: sessionId, role: "owner" };
  const contextHash = crypto.createHash("sha256").update(canonicalJson({ version: 1, organization_id: organizationId, event_id: eventId, action: "retry_uncertain", expected_management_version: 1 })).digest("hex");
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [organizationId, "Provider acceptance qualification"]);
  await pool.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,$3)", [memberId, `provider-acceptance-${organizationId}`, "Provider acceptance"]);
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
    VALUES ($1,$2,$3,$4,'recovery.request.created',$5,$5,$5,'bound',$6,$7,decode($8,'hex'))`, [organizationId, eventId, requestId, memberId, createdAt, binding.binding_id, binding.key_version, binding.binding_digest]);
  await pool.query(`INSERT INTO webauthn_challenges
    (id,session_id,member_id,organization_id,ceremony,operation,challenge_hash,created_at,expires_at,consumed_at,rp_id,origin,user_verification,status,context_hash)
    VALUES ($1,$2,$3,$4,'authentication',$5,$6,$7,$8,$7,$9,$10,'required','consumed',$11)`, [challengeId, sessionId, memberId, organizationId, OWNER_RECOVERY_OUTBOX_MANAGEMENT_OPERATIONS.retryUncertain, crypto.randomBytes(32), createdAt, expiresAt, RP_ID, ORIGIN, Buffer.from(contextHash, "hex")]);
  const human = createPostgresHumanRepository({ client: pool });
  assert.equal(await human.bindRecentAuth({ session_id: sessionId, member_id: memberId, organization_id: organizationId, operation: OWNER_RECOVERY_OUTBOX_MANAGEMENT_OPERATIONS.retryUncertain, challenge_id: challengeId, authenticated_at: createdAt.toISOString(), context_hash: contextHash }), true);
  await pool.query("UPDATE human_sessions SET recent_auth_consumed_at=$2 WHERE id=$1", [sessionId, createdAt]);
  return { organizationId, memberId, membershipId, sessionId, requestId, eventId, binding, actor, contextHash, authorization: { session_id: sessionId, challenge_id: challengeId, context_hash: contextHash, operation: OWNER_RECOVERY_OUTBOX_MANAGEMENT_OPERATIONS.retryUncertain, authenticated_at: createdAt.getTime() } };
}

async function waitForLease(pool, fixture) {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const result = await pool.query("SELECT claim_expires_at <= clock_timestamp() AS expired FROM owner_recovery_outbox WHERE organization_id=$1 AND event_id=$2", [fixture.organizationId, fixture.eventId]);
    if (result.rows[0]?.expired === true) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error("provider acceptance lease did not expire");
}

async function state(pool, fixture) {
  const result = await pool.query("SELECT status,management_version FROM owner_recovery_outbox WHERE organization_id=$1 AND event_id=$2", [fixture.organizationId, fixture.eventId]);
  return { status: result.rows[0]?.status, management_version: Number(result.rows[0]?.management_version) };
}

async function cleanup(pool, fixture) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL session_replication_role = replica");
    await client.query("DELETE FROM owner_recovery_provider_acceptance_ledger WHERE provider_binding_id=$1", [fixture.binding.binding_id]);
    for (const table of ["owner_recovery_outbox_transition_ledger", "owner_recovery_outbox_transition_heads", "owner_recovery_outbox_retention_ledger", "owner_recovery_outbox", "owner_recovery_webauthn_challenges", "owner_recovery_approvals", "owner_recovery_exchanges", "owner_recovery_sessions", "owner_recovery_idempotency_records", "owner_recovery_requests", "idempotency_records", "webauthn_challenges", "human_sessions", "memberships", "outbox_events", "admin_audit_events", "admin_audit_heads", "control_plane_authority_generations"]) {
      await client.query(`DELETE FROM ${table} WHERE organization_id=$1`, [fixture.organizationId]);
    }
    await client.query("DELETE FROM members WHERE id=$1", [fixture.memberId]);
    await client.query("DELETE FROM organizations WHERE id=$1", [fixture.organizationId]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally { client.release(); }
}
