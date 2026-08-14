import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import { createRecentAuthService } from "../../src/human-auth/recent-auth.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createPostgresHumanRepository } from "../../src/postgres/human-repository.mjs";
import {
  OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES,
  OWNER_RECOVERY_OUTBOX_MANAGEMENT_OPERATIONS,
  createPostgresOwnerRecoveryOutboxManagementRepository
} from "../../src/postgres/owner-recovery-outbox-management-repository.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const ORIGIN = "https://console.agentpass.test";
const RP_ID = "console.agentpass.test";
const MANAGEMENT_OPERATION = OWNER_RECOVERY_OUTBOX_MANAGEMENT_OPERATIONS.redrive;

test("real PostgreSQL 0031 qualification protects resource-bound recovery management", {
  skip: !DATABASE_URL,
  timeout: 60_000
}, async (t) => {
  const pool = new Pool({ connectionString: DATABASE_URL, max: 12 });
  const fixture = await createFixture(pool);
  t.after(async () => {
    try { await cleanup(pool, fixture); }
    finally { await pool.end(); }
  });

  const humanRepository = createPostgresHumanRepository({ client: pool });
  const recentAuth = createRecentAuthService({
    ceremony: { begin() {}, async consume() {} },
    sessionRepository: humanRepository
  });
  const management = createPostgresOwnerRecoveryOutboxManagementRepository({
    client: pool,
    cursorSecret: Buffer.alloc(32, 0x31)
  });

  const migrationClient = await pool.connect();
  try {
    const migration = await createMigrationRunner({
      client: migrationClient,
      applicationVersion: "owner-recovery-management-qualification"
    }).run();
    assert.equal(migration.currentVersion, 42);
  } finally {
    migrationClient.release();
  }

  await seedFixture(pool, humanRepository, fixture);
  await assertResourceBoundLiveChallengeIsolation(pool, fixture);

  const primaryContext = contextHash({
    organization_id: fixture.organizationA,
    event_id: fixture.eventA,
    action: "redrive",
    expected_management_version: 1
  });
  const wrongContext = contextHash({
    organization_id: fixture.organizationA,
    event_id: fixture.eventRetry,
    action: "redrive",
    expected_management_version: 1
  });

  const firstAuth = await installRecentAuth({
    pool,
    humanRepository,
    session: fixture.actorA.session,
    organizationId: fixture.organizationA,
    operation: MANAGEMENT_OPERATION,
    contextHash: primaryContext
  });

  // 0031 rejects a resource substitution at both sides of the session/challenge binding.
  await assert.rejects(
    () => pool.query(
      "UPDATE human_sessions SET recent_auth_context_hash=$2 WHERE id=$1",
      [fixture.actorA.session.session_id, Buffer.from(wrongContext, "hex")]
    ),
    (error) => error.code === "23514" && error.constraint === "human_sessions_recent_auth_context_binding"
  );
  await assert.rejects(
    () => pool.query(
      "UPDATE webauthn_challenges SET context_hash=$2 WHERE id=$1",
      [firstAuth.challengeId, Buffer.from(wrongContext, "hex")]
    ),
    (error) => error.code === "23514" && error.constraint === "human_sessions_recent_auth_context_binding"
  );

  // A proof bound to one resource cannot authorize another resource, and the
  // failed comparison must not consume the proof needed by the correct call.
  const wrongContextAttempt = await recentAuth.authorize({
    proof: firstAuth.challengeId,
    principal: fixture.actorA.session,
    organization_id: fixture.organizationA,
    operation: MANAGEMENT_OPERATION,
    context_hash: wrongContext,
    now: Date.now()
  });
  assert.equal(wrongContextAttempt.verified, false);
  const correctContextAttempt = await recentAuth.authorize({
    proof: firstAuth.challengeId,
    principal: fixture.actorA.session,
    organization_id: fixture.organizationA,
    operation: MANAGEMENT_OPERATION,
    context_hash: primaryContext,
    now: Date.now()
  });
  assert.equal(correctContextAttempt.verified, true);

  // An actor from organization A cannot retarget the event that belongs to B.
  // The management repository returns the same stale/missing-resource outcome
  // and the B row remains untouched.
  const crossTenantContext = contextHash({
    organization_id: fixture.organizationA,
    event_id: fixture.eventB,
    action: "redrive",
    expected_management_version: 1
  });
  const crossTenantAuth = await authorizeFresh({
    pool,
    humanRepository,
    recentAuth,
    session: fixture.actorA.session,
    organizationId: fixture.organizationA,
    operation: MANAGEMENT_OPERATION,
    contextHash: crossTenantContext
  });
  await assertCurrentAuthorizationState(pool, fixture.actorA.session, crossTenantAuth, crossTenantContext);
  await assert.rejects(
    () => management.redriveDeadLetter({
      actor: actor(fixture.actorA),
      event_id: fixture.eventB,
      expected_management_version: 1,
      idempotency_key: "cross-tenant-redrive-1",
      context_hash: crossTenantContext,
      recent_authorization: recentAuthorization(crossTenantAuth)
    }),
    (error) => error.code === OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.VERSION_CONFLICT
  );
  assert.deepEqual(await outboxState(pool, fixture.organizationB, fixture.eventB), {
    status: "dead_letter",
    management_version: 1,
    redrive_count: 0
  });

  // One recent-auth proof is consumable by exactly one concurrent caller.
  const replayAuth = await installRecentAuth({
    pool,
    humanRepository,
    session: fixture.actorA.session,
    organizationId: fixture.organizationA,
    operation: MANAGEMENT_OPERATION,
    contextHash: primaryContext
  });
  const concurrentAuthorization = await Promise.all([
    recentAuth.authorize({
      proof: replayAuth.challengeId,
      principal: fixture.actorA.session,
      organization_id: fixture.organizationA,
      operation: MANAGEMENT_OPERATION,
      context_hash: primaryContext,
      now: Date.now()
    }),
    recentAuth.authorize({
      proof: replayAuth.challengeId,
      principal: fixture.actorA.session,
      organization_id: fixture.organizationA,
      operation: MANAGEMENT_OPERATION,
      context_hash: primaryContext,
      now: Date.now()
    })
  ]);
  assert.equal(concurrentAuthorization.filter((result) => result.verified).length, 1);
  assert.equal(concurrentAuthorization.filter((result) => !result.verified).length, 1);

  // Two independently authorized operators race on the same management version.
  // The organization advisory lock and row CAS allow exactly one transition.
  const raceAuthA = await authorizeFresh({
    pool,
    humanRepository,
    recentAuth,
    session: fixture.actorA.session,
    organizationId: fixture.organizationA,
    operation: MANAGEMENT_OPERATION,
    contextHash: primaryContext
  });
  const raceAuthB = await authorizeFresh({
    pool,
    humanRepository,
    recentAuth,
    session: fixture.actorB.session,
    organizationId: fixture.organizationA,
    operation: MANAGEMENT_OPERATION,
    contextHash: primaryContext
  });
  const raceResults = await Promise.allSettled([
    management.redriveDeadLetter(managementInput({
      actor: actor(fixture.actorA),
      eventId: fixture.eventA,
      contextHash: primaryContext,
      authorization: raceAuthA,
      idempotencyKey: "management-version-race-a"
    })),
    management.redriveDeadLetter(managementInput({
      actor: actor(fixture.actorB),
      eventId: fixture.eventA,
      contextHash: primaryContext,
      authorization: raceAuthB,
      idempotencyKey: "management-version-race-b"
    }))
  ]);
  assert.equal(raceResults.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(raceResults.filter((result) => result.status === "rejected").length, 1);
  assert.equal(
    raceResults.find((result) => result.status === "rejected").reason.code,
    OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.VERSION_CONFLICT
  );
  assert.deepEqual(await outboxState(pool, fixture.organizationA, fixture.eventA), {
    status: "pending",
    management_version: 2,
    redrive_count: 1
  });

  // A semantic retry must present a fresh recent-auth proof, but the same
  // idempotency key/request is replayed without applying the CAS a second time.
  const retryContext = contextHash({
    organization_id: fixture.organizationA,
    event_id: fixture.eventRetry,
    action: "redrive",
    expected_management_version: 1
  });
  const retryAuthOne = await authorizeFresh({
    pool,
    humanRepository,
    recentAuth,
    session: fixture.actorA.session,
    organizationId: fixture.organizationA,
    operation: MANAGEMENT_OPERATION,
    contextHash: retryContext
  });
  const retryInput = managementInput({
    actor: actor(fixture.actorA),
    eventId: fixture.eventRetry,
    contextHash: retryContext,
    authorization: retryAuthOne,
    idempotencyKey: "semantic-redrive-retry-1"
  });
  const firstMutation = await management.redriveDeadLetter(retryInput);
  const replayedProof = await recentAuth.authorize({
    proof: retryAuthOne.challenge_id,
    principal: fixture.actorA.session,
    organization_id: fixture.organizationA,
    operation: MANAGEMENT_OPERATION,
    context_hash: retryContext,
    now: Date.now()
  });
  assert.equal(replayedProof.verified, false, "the original recent-auth proof is single-use");

  const retryAuthTwo = await authorizeFresh({
    pool,
    humanRepository,
    recentAuth,
    session: fixture.actorA.session,
    organizationId: fixture.organizationA,
    operation: MANAGEMENT_OPERATION,
    contextHash: retryContext
  });
  const replayMutation = await management.redriveDeadLetter({
    ...retryInput,
    recent_authorization: recentAuthorization(retryAuthTwo)
  });
  assert.deepEqual(replayMutation, firstMutation);
  assert.deepEqual(await outboxState(pool, fixture.organizationA, fixture.eventRetry), {
    status: "pending",
    management_version: 2,
    redrive_count: 1
  });
  const idempotency = await pool.query(
    "SELECT response_status FROM idempotency_records WHERE organization_id=$1 AND principal_id=$2 AND idempotency_key=$3",
    [fixture.organizationA, fixture.actorA.member.id, "semantic-redrive-retry-1"]
  );
  assert.deepEqual(idempotency.rows, [{ response_status: 200 }]);
});

async function createFixture(pool) {
  const organizationA = crypto.randomUUID();
  const organizationB = crypto.randomUUID();
  const members = {
    a: { id: crypto.randomUUID(), github: `management-a-${crypto.randomUUID()}`, membership: crypto.randomUUID(), session: crypto.randomUUID() },
    b: { id: crypto.randomUUID(), github: `management-b-${crypto.randomUUID()}`, membership: crypto.randomUUID(), session: crypto.randomUUID() },
    crossTenant: { id: crypto.randomUUID(), github: `management-cross-${crypto.randomUUID()}`, membership: crypto.randomUUID(), session: crypto.randomUUID() }
  };
  return {
    organizationA,
    organizationB,
    eventA: crypto.randomUUID(),
    eventB: crypto.randomUUID(),
    eventRetry: crypto.randomUUID(),
    requestA: crypto.randomUUID(),
    requestB: crypto.randomUUID(),
    requestRetry: crypto.randomUUID(),
    members
  };
}

async function seedFixture(pool, humanRepository, fixture) {
  const expiresAt = new Date(Date.now() + 60 * 60_000).toISOString();
  const createdAt = new Date(Date.now() - 1_000).toISOString();
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,$2),($3,$4)", [
    fixture.organizationA, "Management qualification A", fixture.organizationB, "Management qualification B"
  ]);
  await pool.query(
    `INSERT INTO members (id,github_subject,display_name) VALUES
      ($1,$2,'Management actor A'),($3,$4,'Management actor B'),($5,$6,'Cross tenant actor')`,
    [
      fixture.members.a.id, fixture.members.a.github,
      fixture.members.b.id, fixture.members.b.github,
      fixture.members.crossTenant.id, fixture.members.crossTenant.github
    ]
  );
  await pool.query(
    `INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES
      ($1,$2,$3,'admin','active'),($1,$4,$5,'admin','active'),
      ($6,$7,$8,'admin','active')`,
    [
      fixture.organizationA, fixture.members.a.membership, fixture.members.a.id,
      fixture.members.b.membership, fixture.members.b.id,
      fixture.organizationB, fixture.members.crossTenant.membership, fixture.members.crossTenant.id
    ]
  );
  const actors = [
    [fixture.members.a, fixture.organizationA],
    [fixture.members.b, fixture.organizationA],
    [fixture.members.crossTenant, fixture.organizationB]
  ];
  for (const [member, organizationId] of actors) {
    member.sessionRow = await humanRepository.createSession({
      session_id: member.session,
      member_id: member.id,
      organization_id: organizationId,
      membership_id: member.membership,
      role: "admin",
      token_hash: digest(`token:${member.session}`),
      csrf_token_hash: digest(`csrf:${member.session}`),
      created_at: createdAt,
      expires_at: expiresAt,
      last_seen_at: createdAt,
      idle_expires_at: expiresAt
    });
  }
  fixture.actorA = { member: fixture.members.a, session: fixture.members.a.sessionRow };
  fixture.actorB = { member: fixture.members.b, session: fixture.members.b.sessionRow };
  fixture.actorCrossTenant = { member: fixture.members.crossTenant, session: fixture.members.crossTenant.sessionRow };

  await seedRecoveryEvent(pool, {
    organizationId: fixture.organizationA,
    requestId: fixture.requestA,
    eventId: fixture.eventA,
    subjectMemberId: fixture.members.a.id,
    creatorSessionId: fixture.members.a.session
  });
  await seedRecoveryEvent(pool, {
    organizationId: fixture.organizationB,
    requestId: fixture.requestB,
    eventId: fixture.eventB,
    subjectMemberId: fixture.members.crossTenant.id,
    creatorSessionId: fixture.members.crossTenant.session
  });
  await seedRecoveryEvent(pool, {
    organizationId: fixture.organizationA,
    requestId: fixture.requestRetry,
    eventId: fixture.eventRetry,
    subjectMemberId: fixture.members.b.id,
    creatorMemberId: fixture.members.a.id,
    creatorSessionId: fixture.members.a.session
  });
}

async function seedRecoveryEvent(pool, { organizationId, requestId, eventId, subjectMemberId, creatorMemberId = subjectMemberId, creatorSessionId }) {
  const createdAt = new Date(Date.now() - 1_000).toISOString();
  const expiresAt = new Date(Date.now() + 60 * 60_000).toISOString();
  await pool.query(
    `INSERT INTO owner_recovery_requests
      (organization_id,request_id,schema_version,kind,subject_member_id,creator_member_id,creator_session_id,threshold,expires_at,created_at,updated_at)
      VALUES ($1,$2,1,'threshold-owner-recovery',$3,$4,$5,2,$6,$7,$7)`,
    [organizationId, requestId, subjectMemberId, creatorMemberId, creatorSessionId, expiresAt, createdAt]
  );
  await pool.query(
    `INSERT INTO owner_recovery_outbox
      (organization_id,event_id,request_id,subject_member_id,event_type,status,attempts,available_at,created_at,updated_at,last_error_code,
       provider_binding_state,provider_binding_id,provider_key_version,provider_binding_digest)
      VALUES ($1,$2,$3,$4,'recovery.request.created','dead_letter',100,$5,$5,$5,'publisher_unavailable','bound','test-owner-recovery',1,decode(repeat('d',64),'hex'))`,
    [organizationId, eventId, requestId, subjectMemberId, createdAt]
  );
}

async function assertResourceBoundLiveChallengeIsolation(pool, fixture) {
  const operation = "qualification.resource-bound.live";
  const contextA = "a".repeat(64);
  const contextB = "b".repeat(64);
  await insertChallenge(pool, {
    session: fixture.actorA.session,
    operation,
    contextHash: contextA,
    status: "pending"
  });
  await insertChallenge(pool, {
    session: fixture.actorA.session,
    operation,
    contextHash: contextB,
    status: "pending"
  });
  await assert.rejects(
    () => insertChallenge(pool, {
      session: fixture.actorA.session,
      operation,
      contextHash: contextA,
      status: "pending"
    }),
    (error) => error.code === "23505" && error.constraint === "webauthn_challenges_one_live_operation_bound"
  );
}

async function installRecentAuth({ pool, humanRepository, session, organizationId, operation, contextHash }) {
  const authenticatedAt = new Date(Date.now() - 1_000).toISOString();
  const challengeId = await insertChallenge(pool, {
    session,
    operation,
    contextHash,
    status: "consumed",
    authenticatedAt
  });
  assert.equal(await humanRepository.bindRecentAuth({
    session_id: session.session_id,
    member_id: session.member_id,
    organization_id: organizationId,
    operation,
    challenge_id: challengeId,
    authenticated_at: authenticatedAt,
    context_hash: contextHash
  }), true);
  return { challengeId, contextHash, authenticatedAt: Date.parse(authenticatedAt) };
}

async function authorizeFresh({ pool, humanRepository, recentAuth, session, organizationId, operation, contextHash }) {
  const installed = await installRecentAuth({ pool, humanRepository, session, organizationId, operation, contextHash });
  const authorization = await recentAuth.authorize({
    proof: installed.challengeId,
    principal: session,
    organization_id: organizationId,
    operation,
    context_hash: contextHash,
    now: Date.now()
  });
  assert.equal(authorization.verified, true);
  return { ...authorization, session_id: session.session_id };
}

async function insertChallenge(pool, { session, operation, contextHash, status, authenticatedAt = undefined }) {
  const challengeId = crypto.randomUUID();
  const createdAt = authenticatedAt ?? new Date(Date.now() - 1_000).toISOString();
  const expiresAt = new Date(Date.parse(createdAt) + 60 * 60_000).toISOString();
  const consumedAt = status === "consumed" ? authenticatedAt : null;
  await pool.query(
    `INSERT INTO webauthn_challenges
      (id,session_id,member_id,organization_id,ceremony,operation,challenge_hash,created_at,expires_at,
       consumed_at,rp_id,origin,user_verification,status,context_hash)
      VALUES ($1,$2,$3,$4,'authentication',$5,$6,$7,$8,$9,$10,$11,'required',$12,$13)`,
    [
      challengeId,
      session.session_id,
      session.member_id,
      session.organization_id,
      operation,
      crypto.randomBytes(32),
      createdAt,
      expiresAt,
      consumedAt,
      RP_ID,
      ORIGIN,
      status,
      Buffer.from(contextHash, "hex")
    ]
  );
  return challengeId;
}

function managementInput({ actor: actorValue, eventId, contextHash, authorization, idempotencyKey }) {
  return {
    actor: actorValue,
    event_id: eventId,
    expected_management_version: 1,
    idempotency_key: idempotencyKey,
    context_hash: contextHash,
    recent_authorization: recentAuthorization(authorization)
  };
}

function recentAuthorization(authorization) {
  return {
    session_id: authorization.session_id,
    challenge_id: authorization.challenge_id,
    context_hash: authorization.context_hash,
    operation: authorization.operation,
    authenticated_at: authorization.authenticated_at
  };
}

function actor(value) {
  return {
    organization_id: value.session.organization_id,
    member_id: value.session.member_id,
    session_id: value.session.session_id,
    role: value.session.role
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

async function outboxState(pool, organizationId, eventId) {
  const result = await pool.query(
    "SELECT status,management_version,redrive_count FROM owner_recovery_outbox WHERE organization_id=$1 AND event_id=$2",
    [organizationId, eventId]
  );
  assert.equal(result.rowCount, 1);
  return {
    status: result.rows[0].status,
    management_version: Number(result.rows[0].management_version),
    redrive_count: Number(result.rows[0].redrive_count)
  };
}

async function assertCurrentAuthorizationState(pool, session, authorization, expectedContextHash) {
  const result = await pool.query(`SELECT s.recent_auth_challenge_id::text AS challenge_id,
      encode(s.recent_auth_context_hash,'hex') AS context_hash,
      s.recent_auth_operation AS operation,
      extract(epoch FROM s.recent_auth_at) * 1000 AS authenticated_at,
      s.recent_auth_consumed_at IS NOT NULL AS consumed,
      s.organization_authority_epoch=o.authority_epoch AS organization_epoch_current,
      s.membership_session_epoch=m.session_epoch AS membership_epoch_current,
      m.role=s.role AS role_current
    FROM human_sessions s
    JOIN memberships m ON m.organization_id=s.organization_id AND m.id=s.membership_id AND m.member_id=s.member_id
    JOIN organizations o ON o.id=s.organization_id
    WHERE s.id=$1`, [session.session_id]);
  assert.equal(result.rowCount, 1);
  const row = result.rows[0];
  assert.deepEqual({
    challenge_id: row.challenge_id,
    context_hash: row.context_hash,
    operation: row.operation,
    authenticated_at: Number(row.authenticated_at),
    consumed: row.consumed,
    organization_epoch_current: row.organization_epoch_current,
    membership_epoch_current: row.membership_epoch_current,
    role_current: row.role_current
  }, {
    challenge_id: authorization.challenge_id,
    context_hash: expectedContextHash,
    operation: authorization.operation,
    authenticated_at: authorization.authenticated_at,
    consumed: true,
    organization_epoch_current: true,
    membership_epoch_current: true,
    role_current: true
  });
}

async function cleanup(pool, fixture) {
  const organizations = [fixture.organizationA, fixture.organizationB];
  const members = Object.values(fixture.members).map((member) => member.id);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL session_replication_role = replica");
    for (const table of ["owner_recovery_outbox_transition_ledger", "owner_recovery_outbox_transition_heads", "owner_recovery_outbox_retention_ledger", "owner_recovery_outbox", "owner_recovery_requests", "idempotency_records", "outbox_events", "control_plane_authority_generations", "admin_audit_events", "admin_audit_heads", "human_sessions", "webauthn_challenges", "memberships"]) {
      await client.query(`DELETE FROM ${table} WHERE organization_id=ANY($1::uuid[])`, [organizations]);
    }
    await client.query("DELETE FROM organizations WHERE id=ANY($1::uuid[])", [organizations]);
    await client.query("DELETE FROM members WHERE id=ANY($1::uuid[])", [members]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally { client.release(); }
}

function digest(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}
