import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createPostgresHumanRepository } from "../../src/postgres/human-repository.mjs";
import { createPostgresOwnerRecoveryOutboxManagementRepository } from "../../src/postgres/owner-recovery-outbox-management-repository.mjs";
import { createPostgresOwnerRecoveryOutboxRepository } from "../../src/postgres/owner-recovery-outbox-repository.mjs";
import { createPostgresOwnerRecoveryOutboxRetentionRepository } from "../../src/postgres/owner-recovery-outbox-retention-repository.mjs";
import { createOwnerRecoveryOutboxWorker } from "../../src/postgres/owner-recovery-outbox-worker.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const ORIGIN = "https://console.agentpass.test";
const RP_ID = "console.agentpass.test";
const BINDING = Object.freeze({
  binding_id: "retention-confirmation-race-provider",
  key_version: 13,
  binding_digest: "e".repeat(64)
});

const OPERATIONS = Object.freeze({
  suppressDeadLetter: "human.recovery.outbox.suppress",
  suppressUncertain: "human.recovery.outbox.suppress_uncertain"
});

test("real PostgreSQL retention does not prune uncertain rows across management and confirmation CAS races", {
  skip: !DATABASE_URL,
  timeout: 90_000
}, async (t) => {
  const fixture = createFixture();
  const pools = {
    owner: new Pool({ connectionString: DATABASE_URL, max: 6 }),
    admin: new Pool({ connectionString: DATABASE_URL, max: 6 }),
    retention: new Pool({ connectionString: DATABASE_URL, max: 4 }),
    confirmation: new Pool({ connectionString: DATABASE_URL, max: 6 }),
    observer: new Pool({ connectionString: DATABASE_URL, max: 3 })
  };
  t.after(async () => {
    try {
      await cleanup(pools.owner, fixture);
    } finally {
      await Promise.all(Object.values(pools).map((pool) => pool.end()));
    }
  });

  const migrationClient = await pools.owner.connect();
  try {
    const migration = await createMigrationRunner({
      client: migrationClient,
      applicationVersion: "owner-recovery-retention-confirmation-races"
    }).run();
    assert.equal(migration.currentVersion, 54);
  } finally {
    migrationClient.release();
  }

  await seed(pools.owner, fixture);

  const ownerManagement = createPostgresOwnerRecoveryOutboxManagementRepository({
    client: pools.owner,
    cursorSecret: Buffer.alloc(32, 0x51)
  });
  const adminManagement = createPostgresOwnerRecoveryOutboxManagementRepository({
    client: pools.admin,
    cursorSecret: Buffer.alloc(32, 0x52)
  });
  const retention = createPostgresOwnerRecoveryOutboxRetentionRepository({ client: pools.retention });

  const terminal = await qualifyTerminalSuppressionRace({
    pools,
    fixture,
    ownerManagement,
    adminManagement,
    retention
  });
  const uncertainSuppression = await qualifyUncertainSuppressionRace({
    pools,
    fixture,
    ownerManagement,
    adminManagement,
    retention
  });
  const confirmation = await qualifyConfirmationRace({ pools, fixture, retention });

  const uncertainLedger = await pools.observer.query(`SELECT event_id::text AS event_id
    FROM owner_recovery_outbox_retention_ledger
    WHERE organization_id=$1 AND event_id=ANY($2::uuid[])`, [fixture.organization, fixture.uncertainEvents]);
  assert.deepEqual(uncertainLedger.rows, [], "uncertain events must never acquire retention evidence");

  const activeLeases = await pools.observer.query(`SELECT count(*)::integer AS count
    FROM owner_recovery_outbox
    WHERE organization_id=$1 AND (claim_token_digest IS NOT NULL OR claim_expires_at IS NOT NULL)`, [fixture.organization]);
  assert.equal(activeLeases.rows[0].count, 0, "no active lease may survive either race");

  const evidence = {
    version: 1,
    uncertain_suppression_winner_role: uncertainSuppression.winnerRole,
    uncertain_suppression_prune_total: uncertainSuppression.pruneTotal,
    suppression_winner_role: terminal.winnerRole,
    suppression_prune_total: terminal.pruneTotal,
    terminal_authoritative_outcome: terminal.outcome,
    terminal_prune_total: terminal.pruneTotal,
    confirmation_published: confirmation.published,
    confirmation_still_uncertain: confirmation.stillUncertain,
    confirmation_prune_total: confirmation.pruneTotal,
    active_leases: activeLeases.rows[0].count
  };
  assertSecretFreeEvidence(evidence, fixture);
  t.diagnostic(JSON.stringify(evidence));
});

async function qualifyUncertainSuppressionRace({ pools, fixture, ownerManagement, adminManagement, retention }) {
  const context = contextHash({
    organization_id: fixture.organization,
    event_id: fixture.suppressUncertainEvent,
    action: "suppress_uncertain",
    expected_management_version: 1
  });
  const humanRepository = createPostgresHumanRepository({ client: pools.owner });
  const ownerAuthorization = await seedAuthorization({
    pool: pools.owner,
    humanRepository,
    actor: fixture.owner,
    operation: OPERATIONS.suppressUncertain,
    contextHash: context
  });
  const adminAuthorization = await seedAuthorization({
    pool: pools.owner,
    humanRepository,
    actor: fixture.admin,
    operation: OPERATIONS.suppressUncertain,
    contextHash: context
  });

  const [owner, admin, prune] = await Promise.allSettled([
    ownerManagement.suppressUncertain(managementInput({
      actor: fixture.owner.public,
      eventId: fixture.suppressUncertainEvent,
      contextHash: context,
      authorization: ownerAuthorization,
      idempotencyKey: "retention-owner-uncertain-race",
      reason: "operator-reviewed"
    })),
    adminManagement.suppressUncertain(managementInput({
      actor: fixture.admin.public,
      eventId: fixture.suppressUncertainEvent,
      contextHash: context,
      authorization: adminAuthorization,
      idempotencyKey: "retention-admin-uncertain-race",
      reason: "operator-reviewed"
    })),
    retention.prune({ limit: 100 })
  ]);
  assert.equal(prune.status, "fulfilled");
  assert.equal(prune.value.total, 0, "retention cannot prune an uncertain or newly suppressed row");
  const winners = [owner, admin].filter((result) => result.status === "fulfilled");
  const losers = [owner, admin].filter((result) => result.status === "rejected");
  assert.equal(winners.length, 1);
  assert.equal(losers.length, 1);
  assert.equal(losers[0].reason.code, "owner_recovery_outbox_management_version_conflict");

  const row = await pools.observer.query(`SELECT status,management_version,suppressed_at,suppression_reason,
      uncertain_at,uncertain_reason,last_error_code,provider_confirmation_next_at,
      claim_token_digest,claim_expires_at
    FROM owner_recovery_outbox WHERE organization_id=$1 AND event_id=$2`, [
    fixture.organization,
    fixture.suppressUncertainEvent
  ]);
  assert.equal(row.rowCount, 1);
  assert.deepEqual({
    status: row.rows[0].status,
    management_version: Number(row.rows[0].management_version),
    suppressed: row.rows[0].suppressed_at !== null,
    suppression_reason: row.rows[0].suppression_reason,
    uncertain_at: row.rows[0].uncertain_at,
    uncertain_reason: row.rows[0].uncertain_reason,
    last_error_code: row.rows[0].last_error_code,
    confirmation_scheduled: row.rows[0].provider_confirmation_next_at !== null,
    active_lease: row.rows[0].claim_token_digest !== null || row.rows[0].claim_expires_at !== null
  }, {
    status: "suppressed",
    management_version: 2,
    suppressed: true,
    suppression_reason: "operator-reviewed",
    uncertain_at: null,
    uncertain_reason: null,
    last_error_code: null,
    confirmation_scheduled: false,
    active_lease: false
  });
  assert.deepEqual(await retentionRows(pools.observer, fixture.organization, fixture.suppressUncertainEvent), []);
  return Object.freeze({ winnerRole: winners[0] === owner ? "owner" : "admin", pruneTotal: prune.value.total });
}

async function qualifyTerminalSuppressionRace({ pools, fixture, ownerManagement, adminManagement, retention }) {
  const context = contextHash({
    organization_id: fixture.organization,
    event_id: fixture.terminalSuppressionEvent,
    action: "suppress",
    expected_management_version: 1
  });
  const humanRepository = createPostgresHumanRepository({ client: pools.owner });
  const ownerAuthorization = await seedAuthorization({
    pool: pools.owner,
    humanRepository,
    actor: fixture.owner,
    operation: OPERATIONS.suppressDeadLetter,
    contextHash: context
  });
  const adminAuthorization = await seedAuthorization({
    pool: pools.owner,
    humanRepository,
    actor: fixture.admin,
    operation: OPERATIONS.suppressDeadLetter,
    contextHash: context
  });

  const [owner, admin, prune] = await Promise.allSettled([
    ownerManagement.suppressDeadLetter(managementInput({
      actor: fixture.owner.public,
      eventId: fixture.terminalSuppressionEvent,
      contextHash: context,
      authorization: ownerAuthorization,
      idempotencyKey: "retention-owner-terminal-race",
      reason: "operator-reviewed"
    })),
    adminManagement.suppressDeadLetter(managementInput({
      actor: fixture.admin.public,
      eventId: fixture.terminalSuppressionEvent,
      contextHash: context,
      authorization: adminAuthorization,
      idempotencyKey: "retention-admin-terminal-race",
      reason: "operator-reviewed"
    })),
    retention.prune({ limit: 100 })
  ]);
  assert.equal(prune.status, "fulfilled");
  const managementResults = [owner, admin];
  const winners = managementResults.filter((result) => result.status === "fulfilled");
  const losers = managementResults.filter((result) => result.status === "rejected");
  assert.ok(winners.length === 0 || winners.length === 1);
  assert.equal(losers.length, 2 - winners.length);
  assert.ok(losers.every((result) => result.reason.code === "owner_recovery_outbox_management_version_conflict"));

  const row = await pools.observer.query(`SELECT status,management_version,suppressed_at,
      claim_token_digest,claim_expires_at
    FROM owner_recovery_outbox
    WHERE organization_id=$1 AND event_id=$2`, [fixture.organization, fixture.terminalSuppressionEvent]);
  const ledger = await retentionRows(pools.observer, fixture.organization, fixture.terminalSuppressionEvent);

  if (row.rowCount === 1) {
    assert.equal(winners.length, 1, "a suppression winner must be the sole terminal authority");
    assert.deepEqual({
      status: row.rows[0].status,
      management_version: Number(row.rows[0].management_version),
      suppressed: row.rows[0].suppressed_at !== null,
      active_lease: row.rows[0].claim_token_digest !== null || row.rows[0].claim_expires_at !== null
    }, { status: "suppressed", management_version: 2, suppressed: true, active_lease: false });
    assert.equal(prune.value.total, 0);
    assert.deepEqual(ledger, []);
    return Object.freeze({
      outcome: "suppressed",
      winnerRole: winners[0] === owner ? "owner" : "admin",
      pruneTotal: prune.value.total
    });
  }

  assert.equal(row.rowCount, 0, "a prune winner removes exactly the old terminal row");
  assert.equal(winners.length, 0, "a prune winner leaves both management CAS calls stale");
  assert.equal(prune.value.dead_letter, 1);
  assert.equal(prune.value.total, 1);
  assert.equal(ledger.length, 1);
  assert.deepEqual({
    terminal_status: ledger[0].terminal_status,
    ordered: ledger[0].terminal_at <= ledger[0].pruned_at
  }, { terminal_status: "dead_letter", ordered: true });
  await assertRetentionLedgerImmutable(pools.observer, fixture.organization, fixture.terminalSuppressionEvent);
  return Object.freeze({
    outcome: "pruned_with_immutable_evidence",
    winnerRole: "prune",
    pruneTotal: prune.value.total
  });
}

async function qualifyConfirmationRace({ pools, fixture, retention }) {
  const repository = createPostgresOwnerRecoveryOutboxRepository({
    client: pools.confirmation,
    deliveryBinding: BINDING,
    randomBytes: () => Buffer.alloc(32, 0x73)
  });
  let publishCalls = 0;
  const worker = createOwnerRecoveryOutboxWorker({
    repository,
    publisher: Object.freeze({
      binding: BINDING,
      async publish() {
        publishCalls += 1;
        throw new Error("notification content must not be resent during confirmation");
      },
      async lookupAcceptance({ idempotency_key }) {
        await delay(25);
        return {
          accepted: idempotency_key === fixture.confirmedEvent,
          idempotency_key
        };
      }
    }),
    batchSize: 10,
    leaseMs: 2_000,
    publishTimeoutMs: 500,
    random: () => 0
  });

  const [workerResult, firstPrune] = await Promise.allSettled([
    worker.runOnce(),
    retention.prune({ limit: 100 })
  ]);
  assert.equal(workerResult.status, "fulfilled");
  assert.deepEqual(workerResult.value, {
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
  assert.equal(firstPrune.status, "fulfilled");
  assert.equal(firstPrune.value.total, 0);

  // A second production prune observes the committed confirmation result. The
  // published timestamp is new, while the negative lookup remains uncertain;
  // neither branch is eligible for deletion.
  const secondPrune = await retention.prune({ limit: 100 });
  assert.equal(secondPrune.total, 0);

  const states = await pools.observer.query(`SELECT event_id::text AS event_id,status,
      provider_confirmation_attempts,provider_confirmation_next_at,published_at,
      uncertain_reason,claim_token_digest,claim_expires_at,
      published_at>clock_timestamp()-interval '30 days' AS published_within_retention
    FROM owner_recovery_outbox
    WHERE organization_id=$1 AND event_id=ANY($2::uuid[]) ORDER BY event_id`, [
    fixture.organization,
    [fixture.confirmedEvent, fixture.stillUncertainEvent]
  ]);
  assert.equal(states.rowCount, 2);
  const byEvent = new Map(states.rows.map((row) => [row.event_id, row]));
  const confirmed = byEvent.get(fixture.confirmedEvent);
  assert.deepEqual({
    status: confirmed.status,
    attempts: Number(confirmed.provider_confirmation_attempts),
    scheduled: confirmed.provider_confirmation_next_at !== null,
    uncertain_reason: confirmed.uncertain_reason,
    active_lease: confirmed.claim_token_digest !== null || confirmed.claim_expires_at !== null,
    published_within_retention: confirmed.published_within_retention
  }, {
    status: "published",
    attempts: 1,
    scheduled: false,
    uncertain_reason: null,
    active_lease: false,
    published_within_retention: true
  });
  const uncertain = byEvent.get(fixture.stillUncertainEvent);
  assert.deepEqual({
    status: uncertain.status,
    attempts: Number(uncertain.provider_confirmation_attempts),
    scheduled: uncertain.provider_confirmation_next_at !== null,
    uncertain_reason: uncertain.uncertain_reason,
    active_lease: uncertain.claim_token_digest !== null || uncertain.claim_expires_at !== null
  }, {
    status: "uncertain",
    attempts: 1,
    scheduled: true,
    uncertain_reason: "delivery_unknown",
    active_lease: false
  });
  assert.deepEqual(await retentionRows(pools.observer, fixture.organization, fixture.confirmedEvent), []);
  assert.deepEqual(await retentionRows(pools.observer, fixture.organization, fixture.stillUncertainEvent), []);

  // The worker's old CAS proof is a stale confirmation loser after the
  // accepted event has already become published. It must not resurrect or
  // rewrite the terminal row.
  await assert.rejects(
    () => repository.markProviderConfirmed({
      organization_id: fixture.organization,
      event_id: fixture.confirmedEvent,
      expected_management_version: 1,
      provider_confirmation_attempt: 1
    }),
    (error) => error.code === "owner_recovery_outbox_claim_lost"
  );
  const afterStale = await readOutboxState(pools.observer, fixture.organization, fixture.confirmedEvent);
  assert.equal(afterStale.status, "published");

  return Object.freeze({
    published: confirmed.status === "published" ? 1 : 0,
    stillUncertain: uncertain.status === "uncertain" ? 1 : 0,
    pruneTotal: firstPrune.value.total + secondPrune.total
  });
}

async function seed(pool, fixture) {
  const createdAt = new Date(Date.now() - 5_000).toISOString();
  const oldUncertainAt = new Date(Date.now() - 400 * 24 * 60 * 60_000).toISOString();
  const oldTerminalAt = new Date(Date.now() - 100 * 24 * 60 * 60_000).toISOString();
  const expiresAt = new Date(Date.now() + 60 * 60_000).toISOString();
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [fixture.organization, "Retention overlap qualification"]);
  await pool.query(`INSERT INTO members (id,github_subject,display_name) VALUES
    ($1,$2,'Retention owner'),($3,$4,'Retention admin')`, [
    fixture.owner.member_id,
    `retention-owner-${fixture.runId}`,
    fixture.admin.member_id,
    `retention-admin-${fixture.runId}`
  ]);
  await pool.query(`INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES
    ($1,$2,$3,'owner','active'),($1,$4,$5,'admin','active')`, [
    fixture.organization,
    fixture.owner.membership_id,
    fixture.owner.member_id,
    fixture.admin.membership_id,
    fixture.admin.member_id
  ]);
  const humanRepository = createPostgresHumanRepository({ client: pool });
  fixture.owner.session = await humanRepository.createSession({
    session_id: fixture.owner.session_id,
    member_id: fixture.owner.member_id,
    organization_id: fixture.organization,
    membership_id: fixture.owner.membership_id,
    role: "owner",
    token_hash: digest(`owner-token-${fixture.runId}`),
    csrf_token_hash: digest(`owner-csrf-${fixture.runId}`),
    created_at: createdAt,
    expires_at: expiresAt,
    last_seen_at: createdAt,
    idle_expires_at: expiresAt
  });
  fixture.admin.session = await humanRepository.createSession({
    session_id: fixture.admin.session_id,
    member_id: fixture.admin.member_id,
    organization_id: fixture.organization,
    membership_id: fixture.admin.membership_id,
    role: "admin",
    token_hash: digest(`admin-token-${fixture.runId}`),
    csrf_token_hash: digest(`admin-csrf-${fixture.runId}`),
    created_at: createdAt,
    expires_at: expiresAt,
    last_seen_at: createdAt,
    idle_expires_at: expiresAt
  });
  fixture.owner.public = actor(fixture.owner.session);
  fixture.admin.public = actor(fixture.admin.session);

  await pool.query(`INSERT INTO owner_recovery_requests
    (organization_id,request_id,schema_version,kind,subject_member_id,creator_member_id,creator_session_id,threshold,expires_at,created_at,updated_at)
    VALUES ($1,$2,1,'threshold-owner-recovery',$3,$3,$4,2,$5,$6,$6)`, [
    fixture.organization,
    fixture.request,
    fixture.owner.member_id,
    fixture.owner.session_id,
    expiresAt,
    oldUncertainAt
  ]);

  await insertOutbox(pool, {
    organizationId: fixture.organization,
    eventId: fixture.suppressUncertainEvent,
    requestId: fixture.request,
    memberId: fixture.owner.member_id,
    status: "uncertain",
    attempts: 1,
    createdAt: oldUncertainAt,
    uncertainAt: oldUncertainAt,
    uncertainReason: "delivery_unknown",
    lastErrorCode: "delivery_uncertain",
    confirmationNextAt: new Date(Date.now() + 60_000).toISOString()
  });
  await insertOutbox(pool, {
    organizationId: fixture.organization,
    eventId: fixture.terminalSuppressionEvent,
    requestId: fixture.request,
    memberId: fixture.owner.member_id,
    status: "dead_letter",
    attempts: 100,
    totalAttempts: 100,
    createdAt: oldTerminalAt,
    updatedAt: oldTerminalAt,
    lastErrorCode: "publisher_rejected"
  });
  await insertOutbox(pool, {
    organizationId: fixture.organization,
    eventId: fixture.confirmedEvent,
    requestId: fixture.request,
    memberId: fixture.owner.member_id,
    status: "uncertain",
    attempts: 1,
    createdAt: oldUncertainAt,
    uncertainAt: oldUncertainAt,
    uncertainReason: "delivery_unknown",
    lastErrorCode: "delivery_uncertain",
    confirmationNextAt: "clock_timestamp()"
  });
  await insertOutbox(pool, {
    organizationId: fixture.organization,
    eventId: fixture.stillUncertainEvent,
    requestId: fixture.request,
    memberId: fixture.owner.member_id,
    status: "uncertain",
    attempts: 1,
    createdAt: oldUncertainAt,
    uncertainAt: oldUncertainAt,
    uncertainReason: "delivery_unknown",
    lastErrorCode: "delivery_uncertain",
    confirmationNextAt: "clock_timestamp()"
  });
}

async function insertOutbox(pool, {
  organizationId,
  eventId,
  requestId,
  memberId,
  status,
  attempts,
  totalAttempts = attempts,
  createdAt,
  updatedAt = createdAt,
  uncertainAt = null,
  uncertainReason = null,
  lastErrorCode = null,
  confirmationNextAt = null
}) {
  const nextAtSql = confirmationNextAt === "clock_timestamp()" ? "clock_timestamp()" : "$17";
  await pool.query(`INSERT INTO owner_recovery_outbox
    (organization_id,event_id,request_id,subject_member_id,event_type,status,attempts,available_at,published_at,
     created_at,updated_at,claim_token_digest,claim_expires_at,last_error_code,management_version,redrive_count,
     total_attempts,suppressed_at,suppression_reason,uncertain_at,uncertain_reason,
     provider_binding_state,provider_binding_id,provider_key_version,provider_binding_digest,provider_confirmation_next_at)
    VALUES ($1,$2,$3,$4,'recovery.request.created',$5,$6,$7,NULL,$8,$9,NULL,NULL,$10,1,0,$11,NULL,NULL,$12,$13,
      'bound',$14,$15,decode($16,'hex'),${nextAtSql})`, [
    organizationId,
    eventId,
    requestId,
    memberId,
    status,
    attempts,
    createdAt,
    createdAt,
    updatedAt,
    lastErrorCode,
    totalAttempts,
    uncertainAt,
    uncertainReason,
    BINDING.binding_id,
    BINDING.key_version,
    BINDING.binding_digest,
    ...(confirmationNextAt === "clock_timestamp()" ? [] : [confirmationNextAt])
  ]);
}

async function seedAuthorization({ pool, humanRepository, actor: actorValue, operation, contextHash: context }) {
  const authenticatedAt = new Date(Date.now() - 1_000).toISOString();
  const challengeId = crypto.randomUUID();
  await pool.query(`INSERT INTO webauthn_challenges
    (id,session_id,member_id,organization_id,ceremony,operation,challenge_hash,created_at,expires_at,
     consumed_at,rp_id,origin,user_verification,status,context_hash)
    VALUES ($1,$2,$3,$4,'authentication',$5,$6,$7,$8,$7,$9,$10,'required','consumed',$11)`, [
    challengeId,
    actorValue.session.session_id,
    actorValue.session.member_id,
    actorValue.session.organization_id,
    operation,
    crypto.randomBytes(32),
    authenticatedAt,
    new Date(Date.parse(authenticatedAt) + 60 * 60_000).toISOString(),
    RP_ID,
    ORIGIN,
    Buffer.from(context, "hex")
  ]);
  assert.equal(await humanRepository.bindRecentAuth({
    session_id: actorValue.session.session_id,
    member_id: actorValue.session.member_id,
    organization_id: actorValue.session.organization_id,
    operation,
    challenge_id: challengeId,
    authenticated_at: authenticatedAt,
    context_hash: context
  }), true);
  // This is only the consumed authentication fixture; all recovery state
  // transitions below use the production management repository.
  await pool.query("UPDATE human_sessions SET recent_auth_consumed_at=$2 WHERE id=$1", [
    actorValue.session.session_id,
    authenticatedAt
  ]);
  return {
    session_id: actorValue.session.session_id,
    challenge_id: challengeId,
    context_hash: context,
    operation,
    authenticated_at: Date.parse(authenticatedAt)
  };
}

function managementInput({ actor: actorValue, eventId, contextHash: context, authorization, idempotencyKey, reason }) {
  return {
    actor: actorValue,
    event_id: eventId,
    expected_management_version: 1,
    idempotency_key: idempotencyKey,
    context_hash: context,
    recent_authorization: authorization,
    ...(reason === undefined ? {} : { reason })
  };
}

function contextHash(value) {
  return crypto.createHash("sha256").update(canonicalJson({
    version: 1,
    organization_id: value.organization_id,
    event_id: value.event_id,
    action: value.action,
    expected_management_version: value.expected_management_version
  })).digest("hex");
}

async function readOutboxState(pool, organizationId, eventId) {
  const result = await pool.query(`SELECT status,management_version,uncertain_reason,provider_confirmation_next_at,
      claim_token_digest,claim_expires_at
    FROM owner_recovery_outbox WHERE organization_id=$1 AND event_id=$2`, [organizationId, eventId]);
  assert.equal(result.rowCount, 1);
  const row = result.rows[0];
  return {
    status: row.status,
    management_version: Number(row.management_version),
    uncertain_reason: row.uncertain_reason,
    provider_confirmation_next_at: row.provider_confirmation_next_at,
    active_lease: row.claim_token_digest !== null || row.claim_expires_at !== null
  };
}

async function retentionRows(pool, organizationId, eventId) {
  const result = await pool.query(`SELECT terminal_status,terminal_at,pruned_at
    FROM owner_recovery_outbox_retention_ledger
    WHERE organization_id=$1 AND event_id=$2`, [organizationId, eventId]);
  return result.rows;
}

async function assertRetentionLedgerImmutable(pool, organizationId, eventId) {
  await assert.rejects(
    () => pool.query(`UPDATE owner_recovery_outbox_retention_ledger
      SET total_attempts=total_attempts+1 WHERE organization_id=$1 AND event_id=$2`, [organizationId, eventId]),
    (error) => error.code === "23514" && error.constraint === "owner_recovery_outbox_retention_ledger_immutable"
  );
  await assert.rejects(
    () => pool.query("DELETE FROM owner_recovery_outbox_retention_ledger WHERE organization_id=$1 AND event_id=$2", [organizationId, eventId]),
    (error) => error.code === "23514" && error.constraint === "owner_recovery_outbox_retention_ledger_immutable"
  );
}

function assertSecretFreeEvidence(evidence, fixture) {
  const serialized = JSON.stringify(evidence);
  assert.ok(serialized.length <= 2_048);
  for (const forbidden of [
    DATABASE_URL,
    fixture.runId,
    fixture.organization,
    fixture.owner.member_id,
    fixture.admin.member_id,
    "claim_token",
    "challenge_id",
    "token_hash",
    "provider_response",
    "notification content",
    "operator-reviewed"
  ]) assert.equal(serialized.includes(forbidden), false, `sanitized evidence contains ${forbidden}`);
}

function actor(session) {
  return {
    organization_id: session.organization_id,
    member_id: session.member_id,
    session_id: session.session_id,
    role: session.role
  };
}

function digest(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function createFixture() {
  const runId = crypto.randomUUID();
  const organization = crypto.randomUUID();
  const owner = {
    member_id: crypto.randomUUID(),
    membership_id: crypto.randomUUID(),
    session_id: crypto.randomUUID()
  };
  const admin = {
    member_id: crypto.randomUUID(),
    membership_id: crypto.randomUUID(),
    session_id: crypto.randomUUID()
  };
  const events = {
    suppressUncertainEvent: crypto.randomUUID(),
    terminalSuppressionEvent: crypto.randomUUID(),
    confirmedEvent: crypto.randomUUID(),
    stillUncertainEvent: crypto.randomUUID()
  };
  return {
    runId,
    organization,
    owner,
    admin,
    request: crypto.randomUUID(),
    ...events,
    uncertainEvents: [events.suppressUncertainEvent, events.confirmedEvent, events.stillUncertainEvent],
    allEvents: Object.values(events)
  };
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
      "idempotency_records",
      "admin_audit_events",
      "admin_audit_heads",
      "human_sessions",
      "webauthn_challenges",
      "memberships",
      "outbox_events",
      "control_plane_authority_generations"
    ]) {
      await client.query(`DELETE FROM ${table} WHERE organization_id=$1`, [fixture.organization]);
    }
    await client.query("DELETE FROM organizations WHERE id=$1", [fixture.organization]);
    await client.query("DELETE FROM members WHERE id=ANY($1::uuid[])", [[fixture.owner.member_id, fixture.admin.member_id]]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }

  const checks = [
    ["owner_recovery_outbox", "organization_id=$1"],
    ["owner_recovery_outbox_retention_ledger", "organization_id=$1"],
    ["owner_recovery_outbox_transition_ledger", "organization_id=$1"],
    ["owner_recovery_requests", "organization_id=$1"],
    ["human_sessions", "organization_id=$1"],
    ["memberships", "organization_id=$1"]
  ];
  for (const [table, predicate] of checks) {
    const result = await pool.query(`SELECT count(*)::integer AS count FROM ${table} WHERE ${predicate}`, [fixture.organization]);
    assert.equal(result.rows[0].count, 0, `cleanup left rows in ${table}`);
  }
  const members = await pool.query("SELECT count(*)::integer AS count FROM members WHERE id=ANY($1::uuid[])", [[fixture.owner.member_id, fixture.admin.member_id]]);
  assert.equal(members.rows[0].count, 0, "cleanup left member rows");
}
