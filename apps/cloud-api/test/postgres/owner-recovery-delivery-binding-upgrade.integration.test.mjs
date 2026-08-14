import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import {
  createMigrationRunner,
  loadSqlMigrations,
  migrationChecksum
} from "../../src/postgres/migration-runner.mjs";

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const applicationVersion = "owner-recovery-delivery-binding-upgrade-qualification";
const ZERO_HASH = "0".repeat(64);

test("0034 to 0035 quarantines legacy delivery, preserves terminals, and starts an intact ledger", {
  skip: !databaseUrl,
  timeout: 120_000
}, async (t) => {
  const pool = new Pool({ connectionString: databaseUrl, max: 4 });
  const fixture = createFixture();
  t.after(async () => {
    try { await cleanup(pool, fixture); }
    finally { await pool.end(); }
  });

  const migrations = await loadSqlMigrations();
  assert.equal(migrations.length, 36);
  const through35 = migrations.slice(0, 35);

  const before35Client = await pool.connect();
  const before35 = createMigrationRunner({
    client: before35Client,
    migrations: migrations.slice(0, 34),
    applicationVersion
  });
  try {
    const result = await before35.run();
    assert.equal(result.currentVersion, 34);
  } finally {
    before35Client.release();
  }

  await seedAtVersion34(pool, fixture);
  const preUpgrade = await readOutbox(pool, fixture.organization, { includeBinding: false });
  assert.deepEqual(new Set(preUpgrade.map(({ status }) => status)), new Set(["pending", "published", "dead_letter", "uncertain", "suppressed"]));
  assert.ok(preUpgrade.find((row) => row.event_id === fixture.events.leased).claim_token_digest);

  const migrationClient = await pool.connect();
  let upgrade;
  try {
    upgrade = await createMigrationRunner({
      client: migrationClient,
      migrations: through35,
      applicationVersion
    }).run();
  } finally {
    migrationClient.release();
  }
  assert.equal(upgrade.currentVersion, 35);
  assert.deepEqual(upgrade.applied.map(({ version }) => version), [35]);

  const rows = await readOutbox(pool, fixture.organization);
  const byEvent = new Map(rows.map((row) => [row.event_id, row]));
  assert.deepEqual(
    [fixture.events.pending, fixture.events.leased].map((eventId) => {
      const row = byEvent.get(eventId);
      return {
        status: row.status,
        uncertain_reason: row.uncertain_reason,
        last_error_code: row.last_error_code,
        claim_token_digest: row.claim_token_digest,
        claim_expires_at: row.claim_expires_at,
        provider_binding_state: row.provider_binding_state
      };
    }),
    [fixture.events.pending, fixture.events.leased].map(() => ({
      status: "uncertain",
      uncertain_reason: "legacy_unbound",
      last_error_code: "delivery_uncertain",
      claim_token_digest: null,
      claim_expires_at: null,
      provider_binding_state: "legacy_unbound"
    }))
  );

  assert.deepEqual(terminalProjection(byEvent.get(fixture.events.published)), {
    status: "published",
    attempts: 4,
    published_at: fixture.createdAt,
    last_error_code: null,
    uncertain_at: null,
    uncertain_reason: null,
    suppressed_at: null,
    suppression_reason: null,
    claim_token_digest: null,
    claim_expires_at: null,
    provider_binding_state: "legacy_unbound"
  });
  assert.deepEqual(terminalProjection(byEvent.get(fixture.events.deadLetter)), {
    status: "dead_letter",
    attempts: 100,
    published_at: null,
    last_error_code: "publisher_rejected",
    uncertain_at: null,
    uncertain_reason: null,
    suppressed_at: null,
    suppression_reason: null,
    claim_token_digest: null,
    claim_expires_at: null,
    provider_binding_state: "legacy_unbound"
  });
  assert.deepEqual(terminalProjection(byEvent.get(fixture.events.uncertain)), {
    status: "uncertain",
    attempts: 3,
    published_at: null,
    last_error_code: "delivery_uncertain",
    uncertain_at: fixture.createdAt,
    uncertain_reason: "provider_timeout",
    suppressed_at: null,
    suppression_reason: null,
    claim_token_digest: null,
    claim_expires_at: null,
    provider_binding_state: "legacy_unbound"
  });
  assert.deepEqual(terminalProjection(byEvent.get(fixture.events.suppressed)), {
    status: "suppressed",
    attempts: 5,
    published_at: null,
    last_error_code: null,
    uncertain_at: null,
    uncertain_reason: null,
    suppressed_at: fixture.createdAt,
    suppression_reason: "operator-confirmed",
    claim_token_digest: null,
    claim_expires_at: null,
    provider_binding_state: "legacy_unbound"
  });

  const baseline = await pool.query(`SELECT organization_id::text AS organization_id,event_id::text AS event_id,
      transition_sequence,from_status,to_status,reason,attempt,total_attempts,management_version,
      provider_binding_state,provider_binding_id,provider_key_version,provider_binding_digest,
      actor_type,actor_member_id::text AS actor_member_id,previous_hash,event_hash,
      floor(extract(epoch FROM occurred_at)*1000000)::bigint::text AS occurred_epoch_us
    FROM owner_recovery_outbox_transition_ledger
    WHERE organization_id=$1 AND transition_sequence=1 ORDER BY event_id`, [fixture.organization]);
  assert.equal(baseline.rows.length, 6);
  for (const row of baseline.rows) {
    assert.equal(row.from_status, null);
    assert.equal(row.reason, "migration_baseline");
    assert.equal(row.actor_type, "migration");
    assert.equal(row.actor_member_id, null);
    assert.equal(row.previous_hash, ZERO_HASH);
    assert.equal(row.event_hash, hashTransition({
      organizationId: row.organization_id,
      eventId: row.event_id,
      sequence: row.transition_sequence,
      fromStatus: row.from_status,
      toStatus: row.to_status,
      reason: row.reason,
      attempt: row.attempt,
      totalAttempts: row.total_attempts,
      managementVersion: row.management_version,
      providerBindingState: row.provider_binding_state,
      providerBindingId: row.provider_binding_id,
      providerKeyVersion: row.provider_key_version,
      providerBindingDigest: row.provider_binding_digest,
      actorType: row.actor_type,
      actorMemberId: row.actor_member_id,
      occurredEpochUs: row.occurred_epoch_us,
      previousHash: row.previous_hash
    }));
  }

  const heads = await pool.query(`SELECT event_id::text AS event_id,sequence,event_hash
    FROM owner_recovery_outbox_transition_heads WHERE organization_id=$1 ORDER BY event_id`, [fixture.organization]);
  assert.equal(heads.rows.length, 6);
  for (const head of heads.rows) {
    const row = baseline.rows.find((candidate) => candidate.event_id === head.event_id);
    assert.deepEqual(head, { event_id: row.event_id, sequence: 1, event_hash: row.event_hash });
  }

  const bindingEvent = fixture.events.bound;
  await pool.query(`INSERT INTO owner_recovery_outbox
    (organization_id,event_id,request_id,subject_member_id,event_type,status,attempts,available_at,created_at,updated_at,
     management_version,redrive_count,total_attempts,provider_binding_state,provider_binding_id,provider_key_version,provider_binding_digest)
    VALUES ($1,$2,$3,$4,'recovery.request.created','pending',0,$5,$5,$5,1,0,0,'bound',$6,$7,decode($8,'hex'))`, [
    fixture.organization, bindingEvent, fixture.request, fixture.member, fixture.createdAt,
    fixture.binding.binding_id, fixture.binding.key_version, fixture.binding.binding_digest
  ]);

  await assert.rejects(
    () => pool.query(`UPDATE owner_recovery_outbox
      SET provider_binding_state='bound',provider_binding_id='changed-binding',provider_key_version=2,
          provider_binding_digest=decode(repeat('b',64),'hex')
      WHERE organization_id=$1 AND event_id=$2`, [fixture.organization, bindingEvent]),
    (error) => error.code === "23514" && error.constraint === "owner_recovery_outbox_identity_immutable"
  );

  await pool.query(`UPDATE owner_recovery_outbox
    SET status='published',published_at=$3,updated_at=$3
    WHERE organization_id=$1 AND event_id=$2`, [fixture.organization, bindingEvent, fixture.createdAt]);

  const live = await pool.query(`SELECT organization_id::text AS organization_id,event_id::text AS event_id,
      transition_sequence,from_status,to_status,reason,attempt,total_attempts,management_version,
      provider_binding_state,provider_binding_id,provider_key_version,provider_binding_digest,
      actor_type,actor_member_id::text AS actor_member_id,previous_hash,event_hash,
      floor(extract(epoch FROM occurred_at)*1000000)::bigint::text AS occurred_epoch_us
    FROM owner_recovery_outbox_transition_ledger
    WHERE organization_id=$1 AND event_id=$2 ORDER BY transition_sequence`, [fixture.organization, bindingEvent]);
  assert.equal(live.rows.length, 2);
  const [created, published] = live.rows;
  assert.equal(created.reason, "event_created");
  assert.equal(created.actor_type, "system");
  assert.equal(created.from_status, null);
  assert.equal(created.previous_hash, ZERO_HASH);
  assert.equal(created.event_hash, hashTransition({
    organizationId: created.organization_id,
    eventId: created.event_id,
    sequence: created.transition_sequence,
    fromStatus: created.from_status,
    toStatus: created.to_status,
    reason: created.reason,
    attempt: created.attempt,
    totalAttempts: created.total_attempts,
    managementVersion: created.management_version,
    providerBindingState: created.provider_binding_state,
    providerBindingId: created.provider_binding_id,
    providerKeyVersion: created.provider_key_version,
    providerBindingDigest: created.provider_binding_digest,
    actorType: created.actor_type,
    actorMemberId: created.actor_member_id,
    occurredEpochUs: created.occurred_epoch_us,
    previousHash: created.previous_hash
  }));
  assert.deepEqual({
    from_status: published.from_status,
    to_status: published.to_status,
    reason: published.reason,
    actor_type: published.actor_type,
    previous_hash: published.previous_hash
  }, {
    from_status: "pending",
    to_status: "published",
    reason: "provider_acknowledged",
    actor_type: "worker",
    previous_hash: created.event_hash
  });
  assert.equal(published.event_hash, hashTransition({
    organizationId: published.organization_id,
    eventId: published.event_id,
    sequence: published.transition_sequence,
    fromStatus: published.from_status,
    toStatus: published.to_status,
    reason: published.reason,
    attempt: published.attempt,
    totalAttempts: published.total_attempts,
    managementVersion: published.management_version,
    providerBindingState: published.provider_binding_state,
    providerBindingId: published.provider_binding_id,
    providerKeyVersion: published.provider_key_version,
    providerBindingDigest: published.provider_binding_digest,
    actorType: published.actor_type,
    actorMemberId: published.actor_member_id,
    occurredEpochUs: published.occurred_epoch_us,
    previousHash: published.previous_hash
  }));

  const beforeRerun = await pool.query(`SELECT count(*)::int AS count,
      (SELECT count(*)::int FROM owner_recovery_outbox_transition_ledger WHERE organization_id=$1) AS ledger_count
    FROM schema_migrations WHERE version=35`, [fixture.organization]);
  const rerunClient = await pool.connect();
  let rerun;
  try {
    rerun = await createMigrationRunner({ client: rerunClient, migrations: through35, applicationVersion }).run();
  } finally {
    rerunClient.release();
  }
  assert.deepEqual(rerun.applied, []);
  assert.equal(rerun.currentVersion, 35);
  const afterRerun = await pool.query(`SELECT count(*)::int AS count,
      (SELECT count(*)::int FROM owner_recovery_outbox_transition_ledger WHERE organization_id=$1) AS ledger_count
    FROM schema_migrations WHERE version=35`, [fixture.organization]);
  assert.deepEqual(afterRerun.rows, beforeRerun.rows);

  const history = await pool.query(`SELECT version::int AS version,checksum,application_version
    FROM schema_migrations WHERE version=35`, []);
  assert.deepEqual(history.rows, [{ version: 35, checksum: migrationChecksum(migrations[34].sql), application_version: applicationVersion }]);
});

function createFixture() {
  const createdAt = new Date(Date.now() - 60_000);
  return {
    organization: crypto.randomUUID(),
    member: crypto.randomUUID(),
    membership: crypto.randomUUID(),
    session: crypto.randomUUID(),
    request: crypto.randomUUID(),
    createdAt,
    binding: { binding_id: "qualification-owner-recovery", key_version: 7, binding_digest: "a".repeat(64) },
    events: Object.fromEntries(["pending", "leased", "published", "deadLetter", "uncertain", "suppressed", "bound"].map((name) => [name, crypto.randomUUID()]))
  };
}

async function seedAtVersion34(pool, fixture) {
  const expiresAt = new Date(fixture.createdAt.getTime() + 24 * 60 * 60_000);
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [fixture.organization, "0035 upgrade qualification"]);
  await pool.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,$3)", [fixture.member, `upgrade-${fixture.organization}`, "Upgrade qualification"]);
  await pool.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')", [fixture.organization, fixture.membership, fixture.member]);
  await pool.query(`INSERT INTO human_sessions
    (id,member_id,organization_id,membership_id,role,token_hash,csrf_token_hash,created_at,expires_at,idle_expires_at,last_seen_at)
    VALUES ($1,$2,$3,$4,'owner',$5,$6,$7,$8,$8,$7)`, [
    fixture.session, fixture.member, fixture.organization, fixture.membership,
    Buffer.alloc(32, 1), Buffer.alloc(32, 2), fixture.createdAt, expiresAt
  ]);
  await pool.query(`INSERT INTO owner_recovery_requests
    (organization_id,request_id,schema_version,kind,subject_member_id,creator_member_id,creator_session_id,threshold,expires_at,created_at,updated_at)
    VALUES ($1,$2,1,'threshold-owner-recovery',$3,$3,$4,2,$5,$6,$6)`, [
    fixture.organization, fixture.request, fixture.member, fixture.session, expiresAt, fixture.createdAt
  ]);

  const rows = [
    { event: fixture.events.pending, status: "pending", attempts: 0 },
    { event: fixture.events.leased, status: "pending", attempts: 2, claim: Buffer.alloc(32, 7), claimExpiresAt: new Date(Date.now() + 60_000), updatedAt: new Date(Date.now() - 30_000) },
    { event: fixture.events.published, status: "published", attempts: 4, publishedAt: fixture.createdAt },
    { event: fixture.events.deadLetter, status: "dead_letter", attempts: 100, lastErrorCode: "publisher_rejected" },
    { event: fixture.events.uncertain, status: "uncertain", attempts: 3, uncertainAt: fixture.createdAt, uncertainReason: "provider_timeout", lastErrorCode: "delivery_uncertain" },
    { event: fixture.events.suppressed, status: "suppressed", attempts: 5, suppressedAt: fixture.createdAt, suppressionReason: "operator-confirmed" }
  ];
  for (const row of rows) {
    await pool.query(`INSERT INTO owner_recovery_outbox
      (organization_id,event_id,request_id,subject_member_id,event_type,status,attempts,available_at,published_at,created_at,updated_at,
       claim_token_digest,claim_expires_at,last_error_code,management_version,redrive_count,total_attempts,suppressed_at,suppression_reason,
       uncertain_at,uncertain_reason)
      VALUES ($1,$2,$3,$4,'recovery.request.created',$5,$6,$7,$8,$9,$10,$11,$12,$13,1,0,$6,$14,$15,$16,$17)`, [
      fixture.organization, row.event, fixture.request, fixture.member, row.status, row.attempts,
      fixture.createdAt, row.publishedAt ?? null, fixture.createdAt, row.updatedAt ?? fixture.createdAt,
      row.claim ?? null, row.claimExpiresAt ?? null, row.lastErrorCode ?? null,
      row.suppressedAt ?? null, row.suppressionReason ?? null, row.uncertainAt ?? null, row.uncertainReason ?? null
    ]);
  }
}

async function readOutbox(pool, organizationId, { includeBinding = true } = {}) {
  const columns = [
    "event_id::text AS event_id", "status", "attempts", "published_at", "uncertain_at", "uncertain_reason",
    "suppressed_at", "suppression_reason", "claim_token_digest", "claim_expires_at", "last_error_code"
  ];
  if (includeBinding) columns.push("provider_binding_state", "provider_binding_id", "provider_key_version", "provider_binding_digest");
  const result = await pool.query(`SELECT ${columns.join(",")}
    FROM owner_recovery_outbox WHERE organization_id=$1 ORDER BY created_at,event_id`, [organizationId]);
  return result.rows;
}

function terminalProjection(row) {
  return {
    status: row.status,
    attempts: row.attempts,
    published_at: row.published_at,
    last_error_code: row.last_error_code,
    uncertain_at: row.uncertain_at,
    uncertain_reason: row.uncertain_reason,
    suppressed_at: row.suppressed_at,
    suppression_reason: row.suppression_reason,
    claim_token_digest: row.claim_token_digest,
    claim_expires_at: row.claim_expires_at,
    provider_binding_state: row.provider_binding_state
  };
}

function hashTransition({
  organizationId,
  eventId,
  sequence,
  fromStatus,
  toStatus,
  reason,
  attempt,
  totalAttempts,
  managementVersion,
  providerBindingState,
  providerBindingId,
  providerKeyVersion,
  providerBindingDigest,
  actorType,
  actorMemberId,
  occurredEpochUs,
  previousHash
}) {
  const parts = [
    organizationId, eventId, String(sequence), fromStatus ?? "", toStatus, reason,
    String(attempt), String(totalAttempts), String(managementVersion), providerBindingState,
    providerBindingId ?? "", providerKeyVersion == null ? "" : String(providerKeyVersion),
    providerBindingDigest == null ? "" : Buffer.from(providerBindingDigest).toString("hex"),
    actorType, actorMemberId ?? "", occurredEpochUs, previousHash
  ];
  return crypto.createHash("sha256").update(parts.join("|"), "utf8").digest("hex");
}

async function cleanup(pool, fixture) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL session_replication_role = replica");
    for (const table of [
      "owner_recovery_outbox_transition_ledger",
      "owner_recovery_outbox_transition_heads",
      "owner_recovery_outbox",
      "owner_recovery_requests",
      "human_sessions",
      "memberships",
      "organizations",
      "members"
    ]) {
      const relation = await client.query("SELECT to_regclass($1) AS relation", [table]);
      if (!relation.rows[0]?.relation) continue;
      const key = table === "members" || table === "organizations" ? "id" : "organization_id";
      const value = table === "members" ? fixture.member : fixture.organization;
      await client.query(`DELETE FROM ${table} WHERE ${key}=$1`, [value]);
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
