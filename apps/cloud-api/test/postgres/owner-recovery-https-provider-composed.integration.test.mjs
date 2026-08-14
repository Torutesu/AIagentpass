import assert from "node:assert/strict";
import https from "node:https";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createOwnerRecoveryNotificationPublisher } from "../../src/postgres/owner-recovery-notification-publisher.mjs";
import { createPostgresOwnerRecoveryOutboxRepository } from "../../src/postgres/owner-recovery-outbox-repository.mjs";
import { createOwnerRecoveryOutboxWorker } from "../../src/postgres/owner-recovery-outbox-worker.mjs";
import { createOwnerRecoveryHttpsProviderHarness } from "../support/owner-recovery-https-provider-harness.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const BINDING = Object.freeze({
  binding_id: "https-provider-composed-qualification",
  key_version: 7,
  binding_digest: "a".repeat(64)
});
const AUTHORIZATION_SECRET = "owner-recovery-composed-test-secret";
const FAULT_MODES = Object.freeze([
  "malformed_json",
  "oversized_body",
  "truncated_content_length",
  "delayed_response",
  "binding_substitution",
  "idempotency_substitution"
]);

test("composed HTTPS provider, production publisher, worker, and PostgreSQL converge without blind resend", {
  skip: !DATABASE_URL,
  timeout: 60_000
}, async (t) => {
  const pool = new Pool({ connectionString: DATABASE_URL, max: 8 });
  let fixture;
  let provider;
  t.after(async () => {
    try {
      if (fixture) await cleanup(pool, fixture);
    } finally {
      try {
        await provider?.close();
      } finally {
        await pool.end();
      }
    }
  });

  const migrationClient = await pool.connect();
  try {
    const migration = await createMigrationRunner({
      client: migrationClient,
      applicationVersion: "owner-recovery-https-provider-composed"
    }).run();
    assert.equal(migration.currentVersion, 46);
  } finally {
    migrationClient.release();
  }

  fixture = await seed(pool);
  provider = await createOwnerRecoveryHttpsProviderHarness({
    binding: BINDING,
    authorizationSecret: AUTHORIZATION_SECRET,
    responseDelayMs: 350
  });
  for (const scenario of fixture.faults) provider.setLookupMode(scenario.eventId, scenario.mode);
  provider.setLookupMode(fixture.acceptedProof.eventId, "accepted");
  provider.setPublishMode(fixture.publishSmoke.eventId, "accepted");

  // The adapter still uses the production https.request implementation. The
  // wrapper adds only the ephemeral public test CA; certificate and IP SAN
  // verification remain enabled.
  const requestFn = (url, options, onResponse) => https.request(url, {
    ...options,
    ca: provider.caCertificate,
    rejectUnauthorized: true
  }, onResponse);
  const publisher = createOwnerRecoveryNotificationPublisher({
    webhookUrl: provider.webhookUrl,
    confirmationUrl: provider.confirmationUrl,
    authorizationSecret: AUTHORIZATION_SECRET,
    bindingId: BINDING.binding_id,
    bindingKeyVersion: BINDING.key_version,
    bindingDigest: BINDING.binding_digest,
    requestFn
  });
  const repository = createPostgresOwnerRecoveryOutboxRepository({
    client: pool,
    deliveryBinding: BINDING,
    randomBytes: () => Buffer.alloc(32, 0x5a)
  });
  const worker = createOwnerRecoveryOutboxWorker({
    repository,
    publisher,
    batchSize: 20,
    leaseMs: 2_000,
    publishTimeoutMs: 100
  });

  const result = await worker.runOnce();
  assert.deepEqual(result, {
    claimed: 1,
    published: 1,
    retried: 0,
    dead_lettered: 0,
    claim_lost: 0,
    uncertain: 0,
    confirmation_checked: 7,
    confirmed: 1
  });

  const state = await pool.query(`SELECT event_id::text AS event_id,status,attempts,total_attempts,
      provider_confirmation_attempts,provider_confirmation_next_at,uncertain_reason,last_error_code
    FROM owner_recovery_outbox WHERE organization_id=$1 ORDER BY event_id`, [fixture.organizationId]);
  const byEvent = new Map(state.rows.map((row) => [row.event_id, row]));

  for (const scenario of fixture.faults) {
    const row = byEvent.get(scenario.eventId);
    assert.equal(row.status, "uncertain", scenario.name);
    assert.equal(row.provider_confirmation_attempts, 1, scenario.name);
    assert.ok(row.provider_confirmation_next_at instanceof Date, scenario.name);
    assert.equal(row.uncertain_reason, "delivery_unknown", scenario.name);
    assert.equal(row.last_error_code, "delivery_uncertain", scenario.name);
    assert.equal(provider.publishCount(scenario.eventId), 0, `${scenario.name} must not resend notification content`);
    assert.equal(provider.lookupCount(scenario.eventId), 1, scenario.name);
  }

  const confirmed = byEvent.get(fixture.acceptedProof.eventId);
  assert.equal(confirmed.status, "published");
  assert.equal(confirmed.attempts, 1);
  assert.equal(confirmed.total_attempts, 1);
  assert.equal(confirmed.provider_confirmation_attempts, 1);
  assert.equal(confirmed.provider_confirmation_next_at, null);
  assert.equal(confirmed.uncertain_reason, null);
  assert.equal(confirmed.last_error_code, null);
  assert.equal(provider.publishCount(fixture.acceptedProof.eventId), 0);
  assert.equal(provider.lookupCount(fixture.acceptedProof.eventId), 1);

  const published = byEvent.get(fixture.publishSmoke.eventId);
  assert.equal(published.status, "published");
  assert.equal(published.attempts, 1);
  assert.equal(published.provider_confirmation_attempts, 0);
  assert.equal(provider.publishCount(fixture.publishSmoke.eventId), 1);
  assert.equal(provider.lookupCount(fixture.publishSmoke.eventId), 0);

  const snapshot = provider.snapshot();
  assert.equal(snapshot.publish_calls, 1);
  assert.equal(snapshot.lookup_calls, 7);
  assert.equal(snapshot.invalid_requests, 0);
  assert.equal(JSON.stringify(result).includes(AUTHORIZATION_SECRET), false);
  assert.equal(JSON.stringify(state.rows).includes(AUTHORIZATION_SECRET), false);
});

async function seed(pool) {
  const organizationId = crypto.randomUUID();
  const memberId = crypto.randomUUID();
  const membershipId = crypto.randomUUID();
  const sessionId = crypto.randomUUID();
  const requestId = crypto.randomUUID();
  const createdAt = new Date(Date.now() - 5_000);
  const expiresAt = new Date(Date.now() + 60 * 60_000);
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,'HTTPS provider composed qualification')", [organizationId]);
  await pool.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,'HTTPS provider qualification')", [memberId, `https-provider-${organizationId}`]);
  await pool.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')", [organizationId, membershipId, memberId]);
  await pool.query(`INSERT INTO human_sessions
    (id,member_id,organization_id,membership_id,role,token_hash,csrf_token_hash,created_at,expires_at,idle_expires_at,last_seen_at)
    VALUES ($1,$2,$3,$4,'owner',$5,$6,$7,$8,$8,$7)`, [
    sessionId, memberId, organizationId, membershipId,
    Buffer.alloc(32, 0x21), Buffer.alloc(32, 0x22), createdAt, expiresAt
  ]);
  await pool.query(`INSERT INTO owner_recovery_requests
    (organization_id,request_id,schema_version,kind,subject_member_id,creator_member_id,creator_session_id,threshold,expires_at,created_at,updated_at)
    VALUES ($1,$2,1,'threshold-owner-recovery',$3,$3,$4,2,$5,$6,$6)`, [
    organizationId, requestId, memberId, sessionId, expiresAt, createdAt
  ]);

  const faults = FAULT_MODES.map((mode) => ({
    name: mode,
    mode,
    eventId: crypto.randomUUID()
  }));
  const acceptedProof = { name: "accepted_proof", eventId: crypto.randomUUID() };
  const publishSmoke = { name: "publish_smoke", eventId: crypto.randomUUID() };
  for (const scenario of [...faults, acceptedProof]) {
    await pool.query(`INSERT INTO owner_recovery_outbox
      (organization_id,event_id,request_id,subject_member_id,event_type,status,attempts,total_attempts,
       available_at,created_at,updated_at,uncertain_at,uncertain_reason,last_error_code,
       provider_binding_state,provider_binding_id,provider_key_version,provider_binding_digest,provider_confirmation_next_at)
      VALUES ($1,$2,$3,$4,'recovery.request.created','uncertain',1,1,clock_timestamp(),$5,$5,
        clock_timestamp(),'delivery_unknown','delivery_uncertain','bound',$6,$7,decode($8,'hex'),clock_timestamp())`, [
      organizationId, scenario.eventId, requestId, memberId, createdAt,
      BINDING.binding_id, BINDING.key_version, BINDING.binding_digest
    ]);
  }
  await pool.query(`INSERT INTO owner_recovery_outbox
    (organization_id,event_id,request_id,subject_member_id,event_type,status,attempts,total_attempts,
     available_at,created_at,updated_at,provider_binding_state,provider_binding_id,provider_key_version,provider_binding_digest)
    VALUES ($1,$2,$3,$4,'recovery.request.created','pending',0,0,clock_timestamp(),$5,$5,'bound',$6,$7,decode($8,'hex'))`, [
    organizationId, publishSmoke.eventId, requestId, memberId, createdAt,
    BINDING.binding_id, BINDING.key_version, BINDING.binding_digest
  ]);
  return Object.freeze({ organizationId, memberId, faults, acceptedProof, publishSmoke });
}

async function cleanup(pool, fixture) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL session_replication_role = replica");
    for (const table of [
      "owner_recovery_outbox_transition_ledger",
      "owner_recovery_outbox_transition_heads",
      "owner_recovery_outbox_retention_ledger",
      "owner_recovery_outbox",
      "owner_recovery_requests",
      "human_sessions",
      "memberships",
      "outbox_events",
      "admin_audit_events",
      "admin_audit_heads",
      "control_plane_authority_generations"
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
