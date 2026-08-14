import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createPostgresOwnerRecoveryOutboxRepository } from "../../src/postgres/owner-recovery-outbox-repository.mjs";
import { createOwnerRecoveryOutboxWorker } from "../../src/postgres/owner-recovery-outbox-worker.mjs";
import {
  createOwnerRecoveryFakeProvider,
  createOwnerRecoveryProviderAcceptanceLedger,
  ensureOwnerRecoveryProviderAcceptanceLedger
} from "../support/owner-recovery-provider-acceptance-ledger.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const BINDING = Object.freeze({ binding_id: "provider-confirmation-qualification", key_version: 3, binding_digest: "f".repeat(64) });

test("0036 automatically confirms accepted uncertain delivery without retrying notification content", {
  skip: !DATABASE_URL,
  timeout: 60_000
}, async (t) => {
  const poolA = new Pool({ connectionString: DATABASE_URL, max: 6 });
  const poolB = new Pool({ connectionString: DATABASE_URL, max: 6 });
  const fixture = await seed(poolA);
  t.after(async () => {
    try { await cleanup(poolA, fixture); }
    finally { await Promise.all([poolA.end(), poolB.end()]); }
  });

  const client = await poolA.connect();
  try {
    const migration = await createMigrationRunner({ client, applicationVersion: "owner-recovery-provider-confirmation" }).run();
    assert.equal(migration.currentVersion, 36);
  } finally { client.release(); }
  await ensureOwnerRecoveryProviderAcceptanceLedger(poolA);

  const repositoryA = repository(poolA, 0x71);
  const repositoryB = repository(poolB, 0x72);
  const providerLedger = createOwnerRecoveryProviderAcceptanceLedger({ client: poolA });

  await quarantineAfterProviderOutcome({
    pool: poolA,
    repositoryA,
    repositoryB,
    eventId: fixture.acceptedEvent,
    afterClaim: async () => {
      assert.deepEqual(await providerLedger.accept({ binding: BINDING, idempotency_key: fixture.acceptedEvent }), {
        accepted: true,
        duplicate: false,
        idempotency_key: fixture.acceptedEvent,
        delivery_attempts: 1
      });
    }
  });

  await poolA.query("UPDATE owner_recovery_outbox SET available_at=clock_timestamp() WHERE event_id=$1", [fixture.notFoundEvent]);
  await quarantineAfterProviderOutcome({ pool: poolA, repositoryA, repositoryB, eventId: fixture.notFoundEvent });

  const provider = createOwnerRecoveryFakeProvider({ ledger: providerLedger, binding: BINDING });
  let publishCalls = 0;
  const worker = createOwnerRecoveryOutboxWorker({
    repository: repositoryB,
    publisher: Object.freeze({
      binding: BINDING,
      async publish() { publishCalls += 1; throw new Error("notification resend is forbidden during confirmation"); },
      lookupAcceptance: (input) => provider.lookupAcceptance(input)
    }),
    batchSize: 10,
    leaseMs: 2_000,
    publishTimeoutMs: 500
  });
  assert.deepEqual(await worker.runOnce(), {
    claimed: 0,
    published: 0,
    retried: 0,
    dead_lettered: 0,
    claim_lost: 0,
    uncertain: 0,
    confirmation_checked: 2,
    confirmed: 1
  });
  assert.equal(publishCalls, 0);

  const states = await poolA.query(`SELECT event_id::text AS event_id,status,provider_confirmation_attempts,
      provider_confirmation_next_at,uncertain_reason
    FROM owner_recovery_outbox WHERE organization_id=$1 ORDER BY event_id`, [fixture.organizationId]);
  const byEvent = new Map(states.rows.map((row) => [row.event_id, row]));
  assert.deepEqual(byEvent.get(fixture.acceptedEvent), {
    event_id: fixture.acceptedEvent,
    status: "published",
    provider_confirmation_attempts: 1,
    provider_confirmation_next_at: null,
    uncertain_reason: null
  });
  const notFound = byEvent.get(fixture.notFoundEvent);
  assert.equal(notFound.status, "uncertain");
  assert.equal(notFound.provider_confirmation_attempts, 1);
  assert.ok(notFound.provider_confirmation_next_at instanceof Date);
  assert.equal(notFound.uncertain_reason, "process_interrupted");
  assert.equal(await providerLedger.count({ binding: BINDING, idempotency_key: fixture.acceptedEvent }), 1);
  assert.equal(await providerLedger.count({ binding: BINDING, idempotency_key: fixture.notFoundEvent }), 0);

  const transitions = await poolA.query(`SELECT from_status,to_status,reason
    FROM owner_recovery_outbox_transition_ledger
    WHERE organization_id=$1 AND event_id=$2 ORDER BY transition_sequence`, [fixture.organizationId, fixture.acceptedEvent]);
  assert.deepEqual(transitions.rows.at(-1), { from_status: "uncertain", to_status: "published", reason: "provider_acknowledged" });

  const faultEvents = [fixture.notFoundEvent, crypto.randomUUID(), crypto.randomUUID(), crypto.randomUUID()];
  for (const eventId of faultEvents.slice(1)) {
    await poolA.query(`INSERT INTO owner_recovery_outbox
      (organization_id,event_id,request_id,subject_member_id,event_type,status,attempts,available_at,created_at,updated_at,
       uncertain_at,uncertain_reason,last_error_code,provider_binding_state,provider_binding_id,provider_key_version,
       provider_binding_digest,provider_confirmation_next_at)
      VALUES ($1,$2,$3,$4,'recovery.request.created','uncertain',1,clock_timestamp(),clock_timestamp(),clock_timestamp(),
        clock_timestamp(),'delivery_unknown','delivery_uncertain','bound',$5,$6,decode($7,'hex'),clock_timestamp())`, [
      fixture.organizationId, eventId, fixture.requestId, fixture.memberId,
      BINDING.binding_id, BINDING.key_version, BINDING.binding_digest
    ]);
  }
  await poolA.query("UPDATE owner_recovery_outbox SET provider_confirmation_next_at=clock_timestamp() WHERE event_id=$1", [fixture.notFoundEvent]);
  const faultProvider = Object.freeze({
    binding: BINDING,
    async publish() { throw new Error("notification content must not be retried"); },
    async lookupAcceptance({ idempotency_key }) {
      const index = faultEvents.indexOf(idempotency_key);
      if (index === 0) return { accepted: true, idempotency_key: fixture.acceptedEvent };
      if (index === 1) return { accepted: "yes", idempotency_key };
      if (index === 2) throw new Error("oversized provider response diagnostic must-not-persist");
      return new Promise(() => {});
    }
  });
  const faultResult = await createOwnerRecoveryOutboxWorker({
    repository: repositoryB,
    publisher: faultProvider,
    batchSize: 10,
    leaseMs: 2_000,
    publishTimeoutMs: 100
  }).runOnce();
  assert.equal(faultResult.confirmation_checked, 4);
  assert.equal(faultResult.confirmed, 0);
  const faultState = await poolA.query(`SELECT status,provider_confirmation_attempts,
      provider_confirmation_next_at>clock_timestamp() AS deferred,last_error_code
    FROM owner_recovery_outbox WHERE event_id=ANY($1::uuid[]) ORDER BY event_id`, [faultEvents]);
  assert.equal(faultState.rows.length, 4);
  assert.ok(faultState.rows.every((row) => row.status === "uncertain"
    && Number(row.provider_confirmation_attempts) >= 1 && row.deferred === true
    && row.last_error_code === "delivery_uncertain"));
  assert.equal(JSON.stringify(faultState.rows).includes("must-not-persist"), false);
});

async function quarantineAfterProviderOutcome({ pool, repositoryA, repositoryB, eventId, afterClaim }) {
  const claim = await repositoryA.claimBatch({ limit: 1, lease_ms: 1_000 });
  assert.deepEqual(claim.events.map((event) => event.event_id), [eventId]);
  await afterClaim?.();
  await pool.query(`UPDATE owner_recovery_outbox
    SET claim_expires_at=clock_timestamp()-interval '1 second',
        available_at=clock_timestamp()-interval '1 second',
        updated_at=clock_timestamp()-interval '2 seconds'
    WHERE event_id=$1`, [eventId]);
  assert.deepEqual((await repositoryB.claimBatch({ limit: 1, lease_ms: 1_000 })).events, []);
  const row = await pool.query(`SELECT status,provider_confirmation_next_at IS NOT NULL AS scheduled
    FROM owner_recovery_outbox WHERE event_id=$1`, [eventId]);
  assert.deepEqual(row.rows[0], { status: "uncertain", scheduled: true });
}

function repository(pool, fill) {
  return createPostgresOwnerRecoveryOutboxRepository({
    client: pool,
    deliveryBinding: BINDING,
    randomBytes: () => Buffer.alloc(32, fill)
  });
}

async function seed(pool) {
  const migrationClient = await pool.connect();
  try { await createMigrationRunner({ client: migrationClient, applicationVersion: "owner-recovery-provider-confirmation-seed" }).run(); }
  finally { migrationClient.release(); }
  const organizationId = crypto.randomUUID();
  const memberId = crypto.randomUUID();
  const membershipId = crypto.randomUUID();
  const sessionId = crypto.randomUUID();
  const requestId = crypto.randomUUID();
  const acceptedEvent = crypto.randomUUID();
  const notFoundEvent = crypto.randomUUID();
  const createdAt = new Date(Date.now() - 5_000);
  const expiresAt = new Date(Date.now() + 60 * 60_000);
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,'Provider confirmation qualification')", [organizationId]);
  await pool.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,'Provider confirmation')", [memberId, `provider-confirmation-${organizationId}`]);
  await pool.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')", [organizationId, membershipId, memberId]);
  await pool.query(`INSERT INTO human_sessions
    (id,member_id,organization_id,membership_id,role,token_hash,csrf_token_hash,created_at,expires_at,idle_expires_at,last_seen_at)
    VALUES ($1,$2,$3,$4,'owner',$5,$6,$7,$8,$8,$7)`, [sessionId, memberId, organizationId, membershipId, Buffer.alloc(32, 0x11), Buffer.alloc(32, 0x22), createdAt, expiresAt]);
  await pool.query(`INSERT INTO owner_recovery_requests
    (organization_id,request_id,schema_version,kind,subject_member_id,creator_member_id,creator_session_id,threshold,expires_at,created_at,updated_at)
    VALUES ($1,$2,1,'threshold-owner-recovery',$3,$3,$4,2,$5,$6,$6)`, [organizationId, requestId, memberId, sessionId, expiresAt, createdAt]);
  for (const [index, eventId] of [acceptedEvent, notFoundEvent].entries()) {
    await pool.query(`INSERT INTO owner_recovery_outbox
      (organization_id,event_id,request_id,subject_member_id,event_type,available_at,created_at,updated_at,
       provider_binding_state,provider_binding_id,provider_key_version,provider_binding_digest)
      VALUES ($1,$2,$3,$4,'recovery.request.created',clock_timestamp()+($5 * interval '1 hour'),$6,$6,
        'bound',$7,$8,decode($9,'hex'))`, [organizationId, eventId, requestId, memberId, index, createdAt, BINDING.binding_id, BINDING.key_version, BINDING.binding_digest]);
  }
  return { organizationId, memberId, requestId, acceptedEvent, notFoundEvent };
}

async function cleanup(pool, fixture) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL session_replication_role = replica");
    await client.query("DELETE FROM owner_recovery_provider_acceptance_ledger WHERE provider_binding_id=$1", [BINDING.binding_id]);
    for (const table of [
      "owner_recovery_outbox_transition_ledger", "owner_recovery_outbox_transition_heads", "owner_recovery_outbox_retention_ledger",
      "owner_recovery_outbox", "owner_recovery_requests", "human_sessions", "memberships", "outbox_events",
      "admin_audit_events", "admin_audit_heads", "control_plane_authority_generations"
    ]) await client.query(`DELETE FROM ${table} WHERE organization_id=$1`, [fixture.organizationId]);
    await client.query("DELETE FROM members WHERE id=$1", [fixture.memberId]);
    await client.query("DELETE FROM organizations WHERE id=$1", [fixture.organizationId]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally { client.release(); }
}
