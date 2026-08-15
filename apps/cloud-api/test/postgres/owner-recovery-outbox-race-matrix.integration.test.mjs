import assert from "node:assert/strict";
import crypto from "node:crypto";
import { writeFile } from "node:fs/promises";
import test from "node:test";
import { Pool } from "pg";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import { createPostgresHumanRepository } from "../../src/postgres/human-repository.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createPostgresOwnerRecoveryOutboxManagementRepository } from "../../src/postgres/owner-recovery-outbox-management-repository.mjs";
import { createPostgresOwnerRecoveryOutboxRepository } from "../../src/postgres/owner-recovery-outbox-repository.mjs";
import { createPostgresOwnerRecoveryOutboxRetentionRepository } from "../../src/postgres/owner-recovery-outbox-retention-repository.mjs";
import { createOwnerRecoveryOutboxWorker } from "../../src/postgres/owner-recovery-outbox-worker.mjs";
import {
  createOwnerRecoveryFakeProvider,
  createOwnerRecoveryProviderAcceptanceLedger,
  ensureOwnerRecoveryProviderAcceptanceLedger,
  OWNER_RECOVERY_PROVIDER_ACCEPTANCE_LEDGER_TABLE
} from "../support/owner-recovery-provider-acceptance-ledger.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const ORIGIN = "https://console.agentpass.test";
const RP_ID = "console.agentpass.test";
const BINDING = Object.freeze({ binding_id: "race-matrix-provider", key_version: 7, binding_digest: "b".repeat(64) });
const MISMATCHED_BINDING = Object.freeze({ binding_id: "other-provider", key_version: 7, binding_digest: "c".repeat(64) });

test("W1.5 real-PostgreSQL two-worker owner-recovery outbox race matrix converges", {
  skip: !DATABASE_URL,
  timeout: 90_000
}, async (t) => {
  const fixture = createFixture();
  const runId = fixture.runId;
  const poolA = new Pool({ connectionString: DATABASE_URL, max: 8 });
  const poolB = new Pool({ connectionString: DATABASE_URL, max: 8 });
  t.after(async () => {
    try {
      await cleanup(poolA, fixture, runId);
    } finally {
      await Promise.all([poolA.end(), poolB.end()]);
    }
  });

  const migrationClient = await poolA.connect();
  try {
    const migration = await createMigrationRunner({
      client: migrationClient,
      applicationVersion: "owner-recovery-outbox-race-matrix"
    }).run();
    assert.equal(migration.currentVersion, 54);
  } finally {
    migrationClient.release();
  }

  await ensureOwnerRecoveryProviderAcceptanceLedger(poolA);
  await seed(poolA, fixture);

  const repositoryA = createRepository(poolA, 0xa1);
  const repositoryB = createRepository(poolB, 0xb2);
  const mismatchedRepository = createPostgresOwnerRecoveryOutboxRepository({
    client: poolB,
    deliveryBinding: MISMATCHED_BINDING,
    randomBytes: () => Buffer.alloc(32, 0xd3)
  });
  const providerA = createMatrixProvider(createOwnerRecoveryProviderAcceptanceLedger({ client: poolA }), BINDING);
  const providerB = createMatrixProvider(createOwnerRecoveryProviderAcceptanceLedger({ client: poolB }), BINDING);

  await qualifyStaleAcknowledgements({ poolA, poolB, repositoryA, repositoryB, fixture });
  await qualifyLeaseExpiryWithPendingProviderCall({ poolA, poolB, repositoryA, repositoryB, providerA, fixture });

  const management = createPostgresOwnerRecoveryOutboxManagementRepository({
    client: poolA,
    cursorSecret: Buffer.alloc(32, 0x44)
  });
  await qualifyExplicitRetry({ poolA, management, fixture });
  await makeAvailable(poolA, fixture.leaseEvent);
  await qualifyTwoWorkers({ poolA, poolB, repositoryA, repositoryB, providerA, providerB, eventId: fixture.leaseEvent });
  const raceWinner = await qualifyRetrySuppressRace({ poolA, management, fixture });

  if (raceWinner === "retry") {
    await makeAvailable(poolA, fixture.retrySuppressEvent);
    await qualifyTwoWorkers({ poolA, poolB, repositoryA, repositoryB, providerA, providerB, eventId: fixture.retrySuppressEvent });
  }

  await makeAvailable(poolA, fixture.deliveryEvent);
  assert.equal((await mismatchedRepository.claimBatch({ limit: 1, lease_ms: 1_000 })).events.length, 0);
  await qualifyTwoWorkers({ poolA, poolB, repositoryA, repositoryB, providerA, providerB, eventId: fixture.deliveryEvent });
  const pruneRaceWinner = await qualifyPruneRedriveRace({ poolA, poolB, management, fixture });

  const final = await readFinalState(poolA, fixture);
  assert.deepEqual(final.by_event[fixture.staleEvent], {
    status: "uncertain",
    attempts: 1,
    management_version: 1,
    redrive_count: 0,
    uncertain_reason: "process_interrupted"
  });
  assert.deepEqual(final.by_event[fixture.leaseEvent], {
    status: "published",
    attempts: 2,
    management_version: 2,
    redrive_count: 1
  });
  assert.equal(final.by_event[fixture.deliveryEvent].status, "published");
  assert.equal(final.by_event[fixture.deliveryEvent].attempts, 1);
  assert.equal(final.by_event[fixture.deliveryEvent].management_version, 1);
  assert.equal(final.by_event[fixture.retrySuppressEvent].status, raceWinner === "retry" ? "published" : "suppressed");
  assert.equal(final.pending_claims, 0);
  assert.equal(final.active_leases, 0);

  const providerRows = await readProviderLedger(poolA, fixture.deliveryEvents);
  assert.deepEqual(providerRows.map(({ event_id }) => event_id).sort(), [
    fixture.leaseEvent,
    fixture.deliveryEvent,
    ...(raceWinner === "retry" ? [fixture.retrySuppressEvent] : [])
  ].sort());
  assert.ok(providerRows.every((row) => row.binding_id === BINDING.binding_id
    && row.key_version === BINDING.key_version
    && row.binding_digest === BINDING.binding_digest
    && row.acceptance_count === 1));
  assert.equal(providerRows.find((row) => row.event_id === fixture.leaseEvent).delivery_attempts, 2);

  const evidence = makeEvidence({ final, providerRows, raceWinner, pruneRaceWinner });
  assertSecretFreeEvidence(evidence, fixture, runId);
  if (process.env.AGENTPASS_W15_EVIDENCE_OUTPUT) {
    await writeFile(process.env.AGENTPASS_W15_EVIDENCE_OUTPUT, `${JSON.stringify(evidence, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600
    });
  }
  t.diagnostic(JSON.stringify(evidence));
});

async function qualifyStaleAcknowledgements({ poolA, poolB, repositoryA, repositoryB, fixture }) {
  await makeAvailable(poolA, fixture.staleEvent);
  const claim = await repositoryA.claimBatch({ limit: 1, lease_ms: 1_000 });
  assert.deepEqual(claim.events.map((event) => event.event_id), [fixture.staleEvent]);
  assert.equal(claim.events[0].provider_binding.binding_id, BINDING.binding_id);

  await expireClaim(poolA, fixture.staleEvent);
  const reclaimer = await repositoryB.claimBatch({ limit: 1, lease_ms: 1_000 });
  assert.equal(reclaimer.events.length, 0, "expired claims quarantine before another pending claim");

  const staleInputs = {
    organization_id: fixture.organization,
    event_id: fixture.staleEvent,
    attempt: claim.events[0].attempt,
    claim_token: claim.claim_token
  };
  const staleResults = await Promise.allSettled([
    repositoryA.markPublished(staleInputs),
    repositoryA.markFailed({ ...staleInputs, error_code: "publisher_rejected", retry_at: new Date(Date.now() + 60_000).toISOString() }),
    repositoryA.markUncertain(staleInputs)
  ]);
  assert.ok(staleResults.every((result) => result.status === "rejected"
    && result.reason.code === "owner_recovery_outbox_claim_lost"
    && !result.reason.message.includes(claim.claim_token)));

  const state = await readEvent(poolA, fixture.staleEvent);
  assert.deepEqual(state, {
    status: "uncertain",
    attempts: 1,
    management_version: 1,
    redrive_count: 0,
    uncertain_reason: "process_interrupted"
  });
}

async function qualifyLeaseExpiryWithPendingProviderCall({ poolA, poolB, repositoryA, repositoryB, providerA, fixture }) {
  await makeAvailable(poolA, fixture.leaseEvent);
  const claim = await repositoryA.claimBatch({ limit: 1, lease_ms: 1_000 });
  assert.deepEqual(claim.events.map((event) => event.event_id), [fixture.leaseEvent]);
  const event = claim.events[0];

  const pendingProviderCall = (async () => {
    const response = await providerA.publish({
      idempotency_key: event.event_id,
      event: publicEvent(event),
      signal: new AbortController().signal
    });
    await delay(1_250);
    return response;
  })();
  await delay(1_050);
  const reclaim = await repositoryB.claimBatch({ limit: 1, lease_ms: 1_000 });
  assert.equal(reclaim.events.length, 0);
  assert.deepEqual(await pendingProviderCall, { accepted: true, duplicate: false, idempotency_key: event.event_id });

  await assert.rejects(
    () => repositoryA.markPublished({
      organization_id: fixture.organization,
      event_id: fixture.leaseEvent,
      attempt: event.attempt,
      claim_token: claim.claim_token
    }),
    (error) => error.code === "owner_recovery_outbox_claim_lost"
  );
  assert.equal((await readProviderLedger(poolA, [fixture.leaseEvent])).length, 1);
  assert.deepEqual(await readEvent(poolA, fixture.leaseEvent), {
    status: "uncertain",
    attempts: 1,
    management_version: 1,
    redrive_count: 0,
    uncertain_reason: "process_interrupted"
  });
}

async function qualifyExplicitRetry({ poolA, management, fixture }) {
  const humanRepository = createPostgresHumanRepository({ client: poolA });
  const context = contextHash({
    organization_id: fixture.organization,
    event_id: fixture.leaseEvent,
    action: "retry_uncertain",
    expected_management_version: 1
  });
  const authorization = await installAuthorization({
    pool: poolA,
    humanRepository,
    actor: fixture.actorA,
    operation: "human.recovery.outbox.retry_uncertain",
    contextHash: context
  });
  const result = await management.retryUncertain(managementInput({
    actor: fixture.actorA.public,
    eventId: fixture.leaseEvent,
    contextHash: context,
    authorization,
    idempotencyKey: "race-matrix-lease-retry"
  }));
  assert.equal(result.status, "pending");
  assert.equal(result.management_version, 2);
  assert.equal(result.redrive_count, 1);
}

async function qualifyRetrySuppressRace({ poolA, management, fixture }) {
  const humanRepository = createPostgresHumanRepository({ client: poolA });
  const context = (action) => contextHash({
    organization_id: fixture.organization,
    event_id: fixture.retrySuppressEvent,
    action,
    expected_management_version: 1
  });
  const retryContext = context("retry_uncertain");
  const suppressContext = context("suppress_uncertain");
  const retryAuthorization = await installAuthorization({
    pool: poolA,
    humanRepository,
    actor: fixture.actorA,
    operation: "human.recovery.outbox.retry_uncertain",
    contextHash: retryContext
  });
  const suppressAuthorization = await installAuthorization({
    pool: poolA,
    humanRepository,
    actor: fixture.actorB,
    operation: "human.recovery.outbox.suppress_uncertain",
    contextHash: suppressContext
  });

  const [retry, suppress] = await Promise.allSettled([
    management.retryUncertain(managementInput({
      actor: fixture.actorA.public,
      eventId: fixture.retrySuppressEvent,
      contextHash: retryContext,
      authorization: retryAuthorization,
      idempotencyKey: "race-matrix-retry-uncertain"
    })),
    management.suppressUncertain(managementInput({
      actor: fixture.actorB.public,
      eventId: fixture.retrySuppressEvent,
      contextHash: suppressContext,
      authorization: suppressAuthorization,
      idempotencyKey: "race-matrix-suppress-uncertain",
      reason: "operator-reviewed"
    }))
  ]);
  const winners = [retry, suppress].filter((result) => result.status === "fulfilled");
  const losers = [retry, suppress].filter((result) => result.status === "rejected");
  assert.equal(winners.length, 1);
  assert.equal(losers.length, 1);
  assert.equal(losers[0].reason.code, "owner_recovery_outbox_management_version_conflict");
  const state = await readEvent(poolA, fixture.retrySuppressEvent);
  assert.equal(state.management_version, 2);
  assert.equal(state.redrive_count, retry.status === "fulfilled" ? 1 : 0);
  assert.equal(state.status, retry.status === "fulfilled" ? "pending" : "suppressed");
  return retry.status === "fulfilled" ? "retry" : "suppress";
}

async function qualifyPruneRedriveRace({ poolA, poolB, management, fixture }) {
  const humanRepository = createPostgresHumanRepository({ client: poolA });
  const context = contextHash({
    organization_id: fixture.organization,
    event_id: fixture.deadLetterPruneEvent,
    action: "redrive",
    expected_management_version: 1
  });
  const authorization = await installAuthorization({
    pool: poolA,
    humanRepository,
    actor: fixture.actorA,
    operation: "human.recovery.outbox.redrive",
    contextHash: context
  });
  const retention = createPostgresOwnerRecoveryOutboxRetentionRepository({ client: poolB });
  const [redrive, prune] = await Promise.allSettled([
    management.redriveDeadLetter(managementInput({
      actor: fixture.actorA.public,
      eventId: fixture.deadLetterPruneEvent,
      contextHash: context,
      authorization,
      idempotencyKey: "race-matrix-prune-redrive"
    })),
    retention.prune({ limit: 1_000 })
  ]);
  const row = await poolA.query("SELECT status,management_version FROM owner_recovery_outbox WHERE event_id=$1", [fixture.deadLetterPruneEvent]);
  const retained = await poolA.query(`SELECT terminal_status FROM owner_recovery_outbox_retention_ledger
    WHERE organization_id=$1 AND event_id=$2`, [fixture.organization, fixture.deadLetterPruneEvent]);
  if (row.rowCount === 1) {
    assert.equal(redrive.status, "fulfilled");
    assert.deepEqual(row.rows[0], { status: "pending", management_version: 2 });
    assert.equal(prune.status, "fulfilled");
    assert.equal(prune.value.dead_letter, 0);
    assert.equal(retained.rowCount, 0);
    return "redrive";
  }
  assert.equal(redrive.status, "rejected");
  assert.equal(redrive.reason.code, "owner_recovery_outbox_management_version_conflict");
  assert.equal(prune.status, "fulfilled");
  assert.equal(prune.value.dead_letter, 1);
  assert.deepEqual(retained.rows, [{ terminal_status: "dead_letter" }]);
  return "prune";
}

async function qualifyTwoWorkers({ poolA, poolB, repositoryA, repositoryB, providerA, providerB, eventId }) {
  const workerA = createOwnerRecoveryOutboxWorker({
    repository: repositoryA,
    publisher: providerA,
    batchSize: 1,
    leaseMs: 2_000,
    publishTimeoutMs: 500,
    random: () => 0
  });
  const workerB = createOwnerRecoveryOutboxWorker({
    repository: repositoryB,
    publisher: providerB,
    batchSize: 1,
    leaseMs: 2_000,
    publishTimeoutMs: 500,
    random: () => 0
  });
  const results = await Promise.all([workerA.runOnce(), workerB.runOnce()]);
  assert.equal(results[0].claimed + results[1].claimed, 1);
  assert.equal(results[0].published + results[1].published, 1);
  assert.equal((await readEvent(poolA, eventId)).status, "published");
}

function createRepository(pool, fill) {
  return createPostgresOwnerRecoveryOutboxRepository({
    client: pool,
    deliveryBinding: BINDING,
    randomBytes: () => Buffer.alloc(32, fill)
  });
}

function createMatrixProvider(ledger, binding) {
  const provider = createOwnerRecoveryFakeProvider({ ledger, binding });
  return Object.freeze({
    binding,
    async publish(input) {
      assert.deepEqual(Object.keys(input).sort(), ["event", "idempotency_key", "signal"]);
      assert.equal(input.idempotency_key, input.event.event_id);
      assert.deepEqual(Object.keys(input.event).sort(), [
        "created_at", "event_id", "event_type", "organization_id", "request_id", "schema_version", "subject_member_id", "kind"
      ].sort());
      return provider.publish(input);
    },
    lookupAcceptance: (input) => provider.lookupAcceptance(input)
  });
}

async function seed(pool, fixture) {
  const createdAt = new Date(Date.now() - 5_000).toISOString();
  const expiresAt = new Date(Date.now() + 60 * 60_000).toISOString();
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [fixture.organization, "W1.5 race matrix"]);
  await pool.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,$3),($4,$5,$6)", [
    fixture.memberA, `race-matrix-a-${fixture.runSuffix}`, "Race matrix actor A",
    fixture.memberB, `race-matrix-b-${fixture.runSuffix}`, "Race matrix actor B"
  ]);
  await pool.query(`INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES
    ($1,$2,$3,'admin','active'),($1,$4,$5,'admin','active')`, [
    fixture.organization, fixture.membershipA, fixture.memberA, fixture.membershipB, fixture.memberB
  ]);
  const humanRepository = createPostgresHumanRepository({ client: pool });
  const sessionExpiresAt = new Date(Date.now() + 60 * 60_000).toISOString();
  const sessionA = await humanRepository.createSession({
    session_id: fixture.sessionA,
    member_id: fixture.memberA,
    organization_id: fixture.organization,
    membership_id: fixture.membershipA,
    role: "admin",
    token_hash: digest(`token-${fixture.runSuffix}-a`),
    csrf_token_hash: digest(`csrf-${fixture.runSuffix}-a`),
    created_at: createdAt,
    expires_at: sessionExpiresAt,
    last_seen_at: createdAt,
    idle_expires_at: sessionExpiresAt
  });
  const sessionB = await humanRepository.createSession({
    session_id: fixture.sessionB,
    member_id: fixture.memberB,
    organization_id: fixture.organization,
    membership_id: fixture.membershipB,
    role: "admin",
    token_hash: digest(`token-${fixture.runSuffix}-b`),
    csrf_token_hash: digest(`csrf-${fixture.runSuffix}-b`),
    created_at: createdAt,
    expires_at: sessionExpiresAt,
    last_seen_at: createdAt,
    idle_expires_at: sessionExpiresAt
  });
  fixture.actorA = { public: actor(sessionA), session: sessionA };
  fixture.actorB = { public: actor(sessionB), session: sessionB };

  await pool.query(`INSERT INTO owner_recovery_requests
      (organization_id,request_id,schema_version,kind,subject_member_id,creator_member_id,creator_session_id,threshold,expires_at,created_at,updated_at)
    VALUES ($1,$2,1,'threshold-owner-recovery',$3,$3,$4,2,$5,$6,$6)`, [
    fixture.organization, fixture.request, fixture.memberA, fixture.sessionA, expiresAt, createdAt
  ]);
  for (const [index, eventId] of fixture.events.entries()) {
    const uncertain = eventId === fixture.retrySuppressEvent;
    const deadLetter = eventId === fixture.deadLetterPruneEvent;
    const rowCreatedAt = deadLetter ? new Date(Date.now() - 100 * 24 * 60 * 60_000).toISOString() : createdAt;
    await pool.query(`INSERT INTO owner_recovery_outbox
        (organization_id,event_id,request_id,subject_member_id,event_type,status,attempts,available_at,created_at,updated_at,
         uncertain_at,uncertain_reason,last_error_code,provider_binding_state,provider_binding_id,provider_key_version,provider_binding_digest,
         provider_confirmation_next_at)
      VALUES ($1,$2,$3,$4,'recovery.request.created',$5,$6,clock_timestamp()+interval '1 hour',$7,$7,$8,$9,$10,'bound',$11,$12,decode($13,'hex'),
        CASE WHEN $5='uncertain' THEN clock_timestamp() ELSE NULL END)`, [
      fixture.organization,
      eventId,
      fixture.request,
      fixture.memberA,
      deadLetter ? "dead_letter" : uncertain ? "uncertain" : "pending",
      deadLetter ? 100 : uncertain ? 1 : 0,
      rowCreatedAt,
      uncertain ? createdAt : null,
      uncertain ? "delivery_unknown" : null,
      deadLetter ? "publisher_rejected" : uncertain ? "delivery_uncertain" : null,
      BINDING.binding_id,
      BINDING.key_version,
      BINDING.binding_digest
    ]);
  }
}

async function installAuthorization({ pool, humanRepository, actor: actorValue, operation, contextHash: context }) {
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

async function makeAvailable(pool, eventId) {
  await pool.query("UPDATE owner_recovery_outbox SET available_at=clock_timestamp(),updated_at=LEAST(updated_at,clock_timestamp()) WHERE event_id=$1", [eventId]);
}

async function expireClaim(pool, eventId) {
  await pool.query(`UPDATE owner_recovery_outbox
    SET available_at=clock_timestamp()-interval '1 second',
        claim_expires_at=clock_timestamp()-interval '1 second',
        updated_at=clock_timestamp()-interval '2 seconds'
    WHERE event_id=$1`, [eventId]);
}

async function readEvent(pool, eventId) {
  const result = await pool.query(`SELECT status,attempts,management_version,redrive_count,uncertain_reason
    FROM owner_recovery_outbox WHERE event_id=$1`, [eventId]);
  assert.equal(result.rowCount, 1);
  const row = result.rows[0];
  return {
    status: row.status,
    attempts: Number(row.attempts),
    management_version: Number(row.management_version),
    redrive_count: Number(row.redrive_count),
    uncertain_reason: row.uncertain_reason
  };
}

async function readFinalState(pool, fixture) {
  const result = await pool.query(`SELECT event_id,status,attempts,management_version,redrive_count,uncertain_reason,
      claim_token_digest,claim_expires_at
    FROM owner_recovery_outbox WHERE organization_id=$1 AND event_id=ANY($2::uuid[]) ORDER BY event_id`, [fixture.organization, fixture.deliveryEvents]);
  const by_event = Object.fromEntries(result.rows.map((row) => [row.event_id, {
    status: row.status,
    attempts: Number(row.attempts),
    management_version: Number(row.management_version),
    redrive_count: Number(row.redrive_count),
    ...(row.uncertain_reason === null ? {} : { uncertain_reason: row.uncertain_reason })
  }]));
  return {
    by_event,
    pending_claims: result.rows.filter((row) => row.status === "pending").length,
    active_leases: result.rows.filter((row) => row.claim_token_digest !== null || row.claim_expires_at !== null).length
  };
}

async function readProviderLedger(pool, eventIds) {
  const result = await pool.query(`SELECT idempotency_key AS event_id,provider_binding_id AS binding_id,
      provider_key_version AS key_version,encode(provider_binding_digest,'hex') AS binding_digest,delivery_attempts
    FROM ${OWNER_RECOVERY_PROVIDER_ACCEPTANCE_LEDGER_TABLE}
    WHERE idempotency_key=ANY($1::text[]) ORDER BY idempotency_key`, [eventIds]);
  return result.rows.map((row) => ({
    event_id: row.event_id,
    binding_id: row.binding_id,
    key_version: Number(row.key_version),
    binding_digest: row.binding_digest,
    acceptance_count: 1,
    delivery_attempts: Number(row.delivery_attempts)
  }));
}

function makeEvidence({ final, providerRows, raceWinner, pruneRaceWinner }) {
  const eventDigest = (eventId) => digest(eventId).slice(0, 16);
  return {
    version: 1,
    scenarios: [
      "stale_acknowledgements",
      "lease_expiry_pending_provider",
      "retry_suppress_cas",
      "prune_redrive_cas",
      "two_worker_exact_binding"
    ],
    race_winner: raceWinner,
    prune_race_winner: pruneRaceWinner,
    final_state_classes: Object.values(final.by_event).map((row) => row.status).sort(),
    accepted_event_digests: providerRows.map((row) => eventDigest(row.event_id)).sort(),
    accepted_binding_ids: providerRows.map((row) => row.binding_id),
    max_attempts: Math.max(...Object.values(final.by_event).map((row) => row.attempts)),
    pending_claims: final.pending_claims,
    active_leases: final.active_leases
  };
}

function assertSecretFreeEvidence(evidence, fixture, runId) {
  const serialized = JSON.stringify(evidence);
  assert.ok(serialized.length <= 4_096);
  for (const forbidden of [DATABASE_URL, runId, fixture.organization, fixture.memberA, fixture.memberB, "claim_token", "challenge_id", "token_hash", "provider_response", "payload"]) {
    assert.equal(serialized.includes(forbidden), false, `evidence contains forbidden value: ${forbidden}`);
  }
  assert.deepEqual(Object.keys(evidence).sort(), [
    "accepted_binding_ids", "accepted_event_digests", "active_leases", "final_state_classes",
    "max_attempts", "pending_claims", "prune_race_winner", "race_winner", "scenarios", "version"
  ].sort());
}

function publicEvent(value) {
  return {
    schema_version: 1,
    kind: "owner-recovery-notification",
    event_id: value.event_id,
    organization_id: value.organization_id,
    request_id: value.request_id,
    subject_member_id: value.subject_member_id,
    event_type: value.event_type,
    created_at: value.created_at
  };
}

function createFixture() {
  const runSuffix = crypto.randomUUID();
  const deliveryEventIds = Object.fromEntries(["staleEvent", "leaseEvent", "retrySuppressEvent", "deliveryEvent"].map((key) => [key, crypto.randomUUID()]));
  const deadLetterPruneEvent = crypto.randomUUID();
  return {
    runId: runSuffix,
    runSuffix: runSuffix.replaceAll("-", ""),
    organization: crypto.randomUUID(),
    memberA: crypto.randomUUID(),
    memberB: crypto.randomUUID(),
    membershipA: crypto.randomUUID(),
    membershipB: crypto.randomUUID(),
    sessionA: crypto.randomUUID(),
    sessionB: crypto.randomUUID(),
    request: crypto.randomUUID(),
    ...deliveryEventIds,
    deadLetterPruneEvent,
    deliveryEvents: Object.values(deliveryEventIds),
    events: [...Object.values(deliveryEventIds), deadLetterPruneEvent]
  };
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

async function cleanup(pool, fixture, runId) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL session_replication_role = replica");
    await client.query(`DELETE FROM ${OWNER_RECOVERY_PROVIDER_ACCEPTANCE_LEDGER_TABLE} WHERE idempotency_key=ANY($1::text[])`, [fixture.events]);
    for (const table of [
      "owner_recovery_outbox_transition_ledger", "owner_recovery_outbox_transition_heads", "owner_recovery_outbox_retention_ledger",
      "owner_recovery_outbox", "owner_recovery_requests", "idempotency_records", "admin_audit_events", "admin_audit_heads",
      "human_sessions", "webauthn_challenges", "memberships", "outbox_events", "control_plane_authority_generations"
    ]) await client.query(`DELETE FROM ${table} WHERE organization_id=$1`, [fixture.organization]);
    await client.query("DELETE FROM organizations WHERE id=$1", [fixture.organization]);
    await client.query("DELETE FROM members WHERE id=ANY($1::uuid[])", [[fixture.memberA, fixture.memberB]]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
