import assert from "node:assert/strict";
import test from "node:test";
import { Pool } from "pg";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createPostgresOwnerRecoveryOutboxRepository } from "../../src/postgres/owner-recovery-outbox-repository.mjs";
import { createOwnerRecoveryOutboxWorker } from "../../src/postgres/owner-recovery-outbox-worker.mjs";

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL;
const ORG = "10000000-0000-4000-8000-000000000029";
const MEMBER = "20000000-0000-4000-8000-000000000029";
const MEMBERSHIP = "30000000-0000-4000-8000-000000000029";
const SESSION = "40000000-0000-4000-8000-000000000029";
const REQUEST = "50000000-0000-4000-8000-000000000029";
const EVENT = "60000000-0000-4000-8000-000000000029";
const DEAD_EVENT = "60000000-0000-4000-8000-000000000030";
const DELIVERY_EVENT = "60000000-0000-4000-8000-000000000031";
const DELIVERY_BINDING = Object.freeze({ binding_id: "test-owner-recovery", key_version: 1, binding_digest: "a".repeat(64) });

test("outbox claims are exclusive, process loss is quarantined, and attempt 100 dead-letters", { skip: !databaseUrl }, async (t) => {
  const pool = new Pool({ connectionString: databaseUrl, max: 8 });
  t.after(async () => { await cleanup(pool); await pool.end(); });
  const migrationClient = await pool.connect();
  try { await createMigrationRunner({ client: migrationClient, applicationVersion: "owner-recovery-outbox-integration" }).run(); }
  finally { migrationClient.release(); }

  await cleanup(pool);
  await seed(pool);
  const repositoryA = createPostgresOwnerRecoveryOutboxRepository({ client: pool, deliveryBinding: DELIVERY_BINDING, randomBytes: () => Buffer.alloc(32, 0x41) });
  const repositoryB = createPostgresOwnerRecoveryOutboxRepository({ client: pool, deliveryBinding: DELIVERY_BINDING, randomBytes: () => Buffer.alloc(32, 0x42) });
  const [claimA, claimB] = await Promise.all([
    repositoryA.claimBatch({ limit: 1, lease_ms: 1_000 }),
    repositoryB.claimBatch({ limit: 1, lease_ms: 1_000 })
  ]);
  assert.equal(claimA.events.length + claimB.events.length, 1);
  const first = claimA.events.length === 1 ? { repository: repositoryA, claim: claimA } : { repository: repositoryB, claim: claimB };
  const secondRepository = claimA.events.length === 1 ? repositoryB : repositoryA;
  const storedClaim = await pool.query("SELECT claim_token_digest,attempts FROM owner_recovery_outbox WHERE organization_id=$1 AND event_id=$2", [ORG, EVENT]);
  assert.equal(storedClaim.rows[0].claim_token_digest.length, 32);
  assert.equal(storedClaim.rows[0].attempts, 1);
  assert.notEqual(storedClaim.rows[0].claim_token_digest.toString("utf8"), first.claim.claim_token);

  await expireClaim(pool, EVENT);
  await assert.rejects(
    first.repository.markPublished({ organization_id: ORG, event_id: EVENT, attempt: 1, claim_token: first.claim.claim_token }),
    (error) => error.code === "owner_recovery_outbox_claim_lost"
  );
  await assert.rejects(
    first.repository.markFailed({ organization_id: ORG, event_id: EVENT, attempt: 1, claim_token: first.claim.claim_token, error_code: "publisher_rejected", retry_at: new Date(Date.now() + 60_000).toISOString() }),
    (error) => error.code === "owner_recovery_outbox_claim_lost"
  );
  await assert.rejects(
    first.repository.markUncertain({ organization_id: ORG, event_id: EVENT, attempt: 1, claim_token: first.claim.claim_token }),
    (error) => error.code === "owner_recovery_outbox_claim_lost"
  );
  const reclaimed = await secondRepository.claimBatch({ limit: 1, lease_ms: 1_000 });
  assert.equal(reclaimed.events.length, 0);
  const processLoss = await pool.query("SELECT status,attempts,uncertain_reason,claim_token_digest,claim_expires_at FROM owner_recovery_outbox WHERE organization_id=$1 AND event_id=$2", [ORG, EVENT]);
  assert.deepEqual(processLoss.rows[0], { status: "uncertain", attempts: 1, uncertain_reason: "process_interrupted", claim_token_digest: null, claim_expires_at: null });
  assert.equal((await first.repository.claimBatch({ limit: 1, lease_ms: 1_000 })).events.length, 0);

  await pool.query(`INSERT INTO owner_recovery_outbox
    (organization_id,event_id,request_id,subject_member_id,event_type,status,attempts,available_at,created_at,updated_at,
     provider_binding_state,provider_binding_id,provider_key_version,provider_binding_digest)
    VALUES ($1,$2,$3,$4,'recovery.request.created','pending',0,clock_timestamp(),clock_timestamp(),clock_timestamp(),'bound',$5,$6,decode($7,'hex'))`, [ORG, DELIVERY_EVENT, REQUEST, MEMBER, DELIVERY_BINDING.binding_id, DELIVERY_BINDING.key_version, DELIVERY_BINDING.binding_digest]);
  const providerCalls = [];
  const processLossRepository = {
    binding: DELIVERY_BINDING,
    claimBatch: (input) => repositoryA.claimBatch(input),
    async markPublished() { throw Object.assign(new Error("simulated process loss"), { code: "owner_recovery_outbox_unavailable" }); },
    async markFailed() { throw Object.assign(new Error("simulated process loss"), { code: "owner_recovery_outbox_unavailable" }); },
    markUncertain: (input) => repositoryA.markUncertain(input)
  };
  const firstWorker = createOwnerRecoveryOutboxWorker({
    repository: processLossRepository,
    publisher: { binding: DELIVERY_BINDING, async publish(input) { providerCalls.push(input.idempotency_key); return { accepted: true, duplicate: false, idempotency_key: input.idempotency_key }; } },
    publishTimeoutMs: 100,
    leaseMs: 1_000
  });
  assert.equal((await firstWorker.runOnce()).uncertain, 1);
  const uncertain = await pool.query("SELECT status,attempts,last_error_code,uncertain_reason,claim_token_digest,claim_expires_at FROM owner_recovery_outbox WHERE organization_id=$1 AND event_id=$2", [ORG, DELIVERY_EVENT]);
  assert.deepEqual(uncertain.rows[0], { status: "uncertain", attempts: 1, last_error_code: "delivery_uncertain", uncertain_reason: "delivery_unknown", claim_token_digest: null, claim_expires_at: null });
  assert.deepEqual(providerCalls, [DELIVERY_EVENT]);
  assert.equal((await repositoryB.claimBatch({ limit: 1, lease_ms: 1_000 })).events.length, 0);

  await pool.query(`INSERT INTO owner_recovery_outbox
    (organization_id,event_id,request_id,subject_member_id,event_type,status,attempts,available_at,created_at,updated_at,
     provider_binding_state,provider_binding_id,provider_key_version,provider_binding_digest)
    VALUES ($1,$2,$3,$4,'recovery.failed','pending',99,clock_timestamp(),clock_timestamp(),clock_timestamp(),'bound',$5,$6,decode($7,'hex'))`, [ORG, DEAD_EVENT, REQUEST, MEMBER, DELIVERY_BINDING.binding_id, DELIVERY_BINDING.key_version, DELIVERY_BINDING.binding_digest]);
  const deadWorker = createOwnerRecoveryOutboxWorker({
    repository: repositoryB,
    publisher: { binding: DELIVERY_BINDING, async publish(input) { return { accepted: false, duplicate: false, idempotency_key: input.idempotency_key }; } },
    publishTimeoutMs: 100,
    leaseMs: 1_000
  });
  const dead = await deadWorker.runOnce();
  assert.equal(dead.dead_lettered, 1);
  const final = await pool.query("SELECT status,attempts,claim_token_digest,claim_expires_at,last_error_code FROM owner_recovery_outbox WHERE organization_id=$1 AND event_id=$2", [ORG, DEAD_EVENT]);
  assert.deepEqual(final.rows[0], { status: "dead_letter", attempts: 100, claim_token_digest: null, claim_expires_at: null, last_error_code: "publisher_rejected" });

  const columns = await pool.query("SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='owner_recovery_outbox'");
  assert.equal(columns.rows.some(({ column_name }) => /claim_token$|provider_url|destination|payload|body|secret/u.test(column_name)), false);

});

async function seed(pool) {
  const createdAt = new Date(Date.now() - 60_000);
  const expiresAt = new Date(Date.now() + 24 * 60 * 60_000);
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,'Outbox integration')", [ORG]);
  await pool.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,'outbox-member','Outbox Member')", [MEMBER]);
  await pool.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')", [ORG, MEMBERSHIP, MEMBER]);
  await pool.query(`INSERT INTO human_sessions
    (id,member_id,organization_id,membership_id,role,token_hash,csrf_token_hash,created_at,expires_at,idle_expires_at,last_seen_at)
    VALUES ($1,$2,$3,$4,'owner',$5,$6,$7,$8,$8,$7)`, [SESSION, MEMBER, ORG, MEMBERSHIP, Buffer.alloc(32, 1), Buffer.alloc(32, 2), createdAt, expiresAt]);
  await pool.query(`INSERT INTO owner_recovery_requests
    (organization_id,request_id,schema_version,kind,subject_member_id,creator_member_id,creator_session_id,threshold,expires_at,created_at,updated_at)
    VALUES ($1,$2,1,'threshold-owner-recovery',$3,$3,$4,2,$5,$6,$6)`, [ORG, REQUEST, MEMBER, SESSION, expiresAt, createdAt]);
  await pool.query(`INSERT INTO owner_recovery_outbox
    (organization_id,event_id,request_id,subject_member_id,event_type,available_at,created_at,updated_at,
     provider_binding_state,provider_binding_id,provider_key_version,provider_binding_digest)
    VALUES ($1,$2,$3,$4,'recovery.request.created',$5,$5,$5,'bound',$6,$7,decode($8,'hex'))`, [ORG, EVENT, REQUEST, MEMBER, createdAt, DELIVERY_BINDING.binding_id, DELIVERY_BINDING.key_version, DELIVERY_BINDING.binding_digest]);
}

async function expireClaim(pool, eventId) {
  await pool.query(`UPDATE owner_recovery_outbox
    SET available_at=clock_timestamp()-interval '1 second',
        claim_expires_at=clock_timestamp()-interval '1 second',
        updated_at=clock_timestamp()-interval '2 seconds'
    WHERE organization_id=$1 AND event_id=$2`, [ORG, eventId]);
}

async function cleanup(pool) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL session_replication_role = replica");
    for (const table of [
      "owner_recovery_outbox_transition_ledger", "owner_recovery_outbox_transition_heads", "owner_recovery_outbox_retention_ledger", "owner_recovery_outbox", "owner_recovery_webauthn_challenges",
      "owner_recovery_approvals", "owner_recovery_exchanges", "owner_recovery_sessions", "owner_recovery_idempotency_records",
      "owner_recovery_requests", "human_sessions", "memberships", "outbox_events", "admin_audit_events",
      "admin_audit_heads", "control_plane_authority_generations"
    ]) await client.query(`DELETE FROM ${table} WHERE organization_id=$1`, [ORG]);
    await client.query("DELETE FROM organizations WHERE id=$1", [ORG]);
    await client.query("DELETE FROM members WHERE id=$1", [MEMBER]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
