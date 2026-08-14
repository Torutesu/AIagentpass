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

test("outbox claims are exclusive, process-loss retries preserve idempotency, and attempt 100 dead-letters", { skip: !databaseUrl }, async (t) => {
  const pool = new Pool({ connectionString: databaseUrl, max: 8 });
  t.after(() => pool.end());
  const migrationClient = await pool.connect();
  try { await createMigrationRunner({ client: migrationClient, applicationVersion: "owner-recovery-outbox-integration" }).run(); }
  finally { migrationClient.release(); }

  await seed(pool);
  const repositoryA = createPostgresOwnerRecoveryOutboxRepository({ client: pool, randomBytes: () => Buffer.alloc(32, 0x41) });
  const repositoryB = createPostgresOwnerRecoveryOutboxRepository({ client: pool, randomBytes: () => Buffer.alloc(32, 0x42) });
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
  const providerCalls = [];
  const processLossRepository = {
    claimBatch: (input) => secondRepository.claimBatch(input),
    async markPublished() { throw Object.assign(new Error("simulated process loss"), { code: "owner_recovery_outbox_unavailable" }); },
    async markFailed() { throw Object.assign(new Error("simulated process loss"), { code: "owner_recovery_outbox_unavailable" }); }
  };
  const firstWorker = createOwnerRecoveryOutboxWorker({
    repository: processLossRepository,
    publisher: { async publish(input) { providerCalls.push(input.idempotency_key); return { accepted: true }; } },
    publishTimeoutMs: 100,
    leaseMs: 1_000
  });
  assert.equal((await firstWorker.runOnce()).claim_lost, 1);

  await expireClaim(pool, EVENT);
  const secondWorker = createOwnerRecoveryOutboxWorker({
    repository: first.repository,
    publisher: { async publish(input) { providerCalls.push(input.idempotency_key); return { accepted: true }; } },
    publishTimeoutMs: 100,
    leaseMs: 1_000
  });
  assert.equal((await secondWorker.runOnce()).published, 1);
  assert.deepEqual(providerCalls, [EVENT, EVENT]);
  assert.equal(new Set(providerCalls).size, 1);
  await assert.rejects(
    first.repository.markPublished({ organization_id: ORG, event_id: EVENT, attempt: 1, claim_token: first.claim.claim_token }),
    (error) => error.code === "owner_recovery_outbox_claim_lost"
  );

  await pool.query(`INSERT INTO owner_recovery_outbox
    (organization_id,event_id,request_id,subject_member_id,event_type,status,attempts,available_at,created_at,updated_at)
    VALUES ($1,$2,$3,$4,'recovery.failed','pending',99,clock_timestamp(),clock_timestamp(),clock_timestamp())`, [ORG, DEAD_EVENT, REQUEST, MEMBER]);
  const maxAttemptProcessLoss = {
    claimBatch: (input) => repositoryA.claimBatch(input),
    async markPublished() { throw Object.assign(new Error("simulated process loss"), { code: "owner_recovery_outbox_unavailable" }); },
    async markFailed() { throw Object.assign(new Error("simulated process loss"), { code: "owner_recovery_outbox_unavailable" }); }
  };
  const crashingDeadWorker = createOwnerRecoveryOutboxWorker({
    repository: maxAttemptProcessLoss,
    publisher: { async publish() { return { accepted: false }; } },
    publishTimeoutMs: 100,
    leaseMs: 1_000
  });
  assert.equal((await crashingDeadWorker.runOnce()).claim_lost, 1);
  await expireClaim(pool, DEAD_EVENT);
  const deadWorker = createOwnerRecoveryOutboxWorker({
    repository: repositoryB,
    publisher: { async publish() { return { accepted: false }; } },
    publishTimeoutMs: 100,
    leaseMs: 1_000
  });
  const dead = await deadWorker.runOnce();
  assert.equal(dead.dead_lettered, 1);
  const final = await pool.query("SELECT status,attempts,claim_token_digest,claim_expires_at,last_error_code FROM owner_recovery_outbox WHERE organization_id=$1 AND event_id=$2", [ORG, DEAD_EVENT]);
  assert.deepEqual(final.rows[0], { status: "dead_letter", attempts: 100, claim_token_digest: null, claim_expires_at: null, last_error_code: "publisher_rejected" });

  const columns = await pool.query("SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='owner_recovery_outbox'");
  assert.equal(columns.rows.some(({ column_name }) => /claim_token$|provider|payload|body|secret/u.test(column_name)), false);
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
    (organization_id,event_id,request_id,subject_member_id,event_type,available_at,created_at,updated_at)
    VALUES ($1,$2,$3,$4,'recovery.request.created',$5,$5,$5)`, [ORG, EVENT, REQUEST, MEMBER, createdAt]);
}

async function expireClaim(pool, eventId) {
  await pool.query(`UPDATE owner_recovery_outbox
    SET available_at=clock_timestamp()-interval '1 second',
        claim_expires_at=clock_timestamp()-interval '1 second',
        updated_at=clock_timestamp()-interval '2 seconds'
    WHERE organization_id=$1 AND event_id=$2`, [ORG, eventId]);
}
