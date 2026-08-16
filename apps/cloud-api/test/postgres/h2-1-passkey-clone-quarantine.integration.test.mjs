import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import pg from "pg";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createPostgresHumanRepository } from "../../src/postgres/human-repository.mjs";

const { Pool } = pg;
const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL;
const EXPIRES_AT = "2099-08-16T00:00:00.000Z";
const AUTHENTICATED_AT = "2026-08-16T00:00:00.000Z";
const CONTEXT_HASH = "ab".repeat(32);

test("H2.1 PostgreSQL repository boundary and clone quarantine preserve authority boundaries", {
  skip: !DATABASE_URL,
  timeout: 60_000
}, async (t) => {
  const pool = new Pool({ connectionString: DATABASE_URL, max: 16 });
  let fixture;
  t.after(async () => {
    if (fixture) await cleanup(pool, fixture);
    await pool.end();
  });

  const migrationClient = await pool.connect();
  try {
    const migration = await createMigrationRunner({
      client: migrationClient,
      applicationVersion: "h2-1-passkey-clone-quarantine-integration"
    }).run();
    assert.ok(migration.currentVersion >= 72, "migration 0072 must be applied");
  } finally {
    migrationClient.release();
  }

  fixture = await seedFixture(pool);

  const managementRepository = createPostgresHumanRepository({ client: pool });
  await assertPasskeyManagement(managementRepository, fixture);
  await assertFinalUsableCredentialProtection(pool, fixture);
  await assertRecentAuthBinding(managementRepository, pool, fixture);
  await assertCloneQuarantineAndAuthorityPropagation(pool, fixture);
});

async function assertPasskeyManagement(repository, fixture) {
  const scope = {
    session_id: fixture.management.sessionId,
    member_id: fixture.management.memberId,
    organization_id: fixture.organizationId
  };
  const rename = await repository.updateCredentialLabel({
    ...scope,
    credential_id: fixture.management.renameCredential,
    label: "Renamed Touch ID",
    expected_version: 1,
    idempotency_key: "h21-passkey-rename-01"
  });
  assert.equal(rename.id, fixture.management.renameCredential);
  assert.equal(rename.label, "Renamed Touch ID");
  assert.equal(rename.version, 2);

  const renameReplay = await repository.updateCredentialLabel({
    ...scope,
    credential_id: fixture.management.renameCredential,
    label: "Renamed Touch ID",
    expected_version: 1,
    idempotency_key: "h21-passkey-rename-01"
  });
  assert.deepEqual(renameReplay, rename, "same request must replay the exact stored DTO");
  await assert.rejects(
    repository.updateCredentialLabel({
      ...scope,
      credential_id: fixture.management.renameCredential,
      label: "Conflicting label",
      expected_version: 1,
      idempotency_key: "h21-passkey-rename-01"
    }),
    { code: "ERR_IDEMPOTENCY_CONFLICT" }
  );
  await assert.rejects(
    repository.updateCredentialLabel({
      ...scope,
      credential_id: fixture.management.renameCredential,
      label: "Stale If-Match",
      expected_version: 1,
      idempotency_key: "h21-passkey-rename-stale"
    }),
    { code: "ERR_VERSION_CONFLICT" }
  );

  const revoke = await repository.revokeCredential({
    ...scope,
    credential_id: fixture.management.revokeCredential,
    expected_version: 1,
    revoked_at: "2026-08-16T00:01:00.000Z",
    reason: "user-rotated",
    idempotency_key: "h21-passkey-revoke-01"
  });
  assert.equal(revoke.id, fixture.management.revokeCredential);
  assert.equal(revoke.revoked_at, "2026-08-16T00:01:00.000Z");
  assert.equal(revoke.version, 2);

  const revokeReplay = await repository.revokeCredential({
    ...scope,
    credential_id: fixture.management.revokeCredential,
    expected_version: 1,
    revoked_at: "2026-08-16T00:01:00.000Z",
    reason: "user-rotated",
    idempotency_key: "h21-passkey-revoke-01"
  });
  assert.deepEqual(revokeReplay, revoke, "revoke retry must replay the exact stored DTO");
  await assert.rejects(
    repository.revokeCredential({
      ...scope,
      credential_id: fixture.management.revokeCredential,
      expected_version: 1,
      revoked_at: "2026-08-16T00:01:00.000Z",
      reason: "different-reason",
      idempotency_key: "h21-passkey-revoke-01"
    }),
    { code: "ERR_IDEMPOTENCY_CONFLICT" }
  );
}

async function assertFinalUsableCredentialProtection(pool, fixture) {
  const clients = [await pool.connect(), await pool.connect()];
  const outcomes = [];
  let updates = [];
  try {
    await Promise.all(clients.map((client) => client.query("BEGIN")));
    updates = [
      issueContendedCredentialRevoke(clients[0], fixture.contention, fixture.contention.firstCredential),
      issueContendedCredentialRevoke(clients[1], fixture.contention, fixture.contention.secondCredential)
    ];
    const first = await Promise.race(updates.map((promise, index) => promise.then(
      () => ({ index, ok: true }),
      (error) => ({ index, ok: false, error })
    )));
    if (!first.ok) {
      await clients[first.index].query("ROLLBACK").catch(() => {});
      await Promise.allSettled(updates);
      throw first.error;
    }
    await clients[first.index].query("COMMIT");
    outcomes.push(...await Promise.allSettled(updates));
    for (const [index, outcome] of outcomes.entries()) {
      if (outcome.status === "rejected") await clients[index].query("ROLLBACK").catch(() => {});
    }
  } finally {
    await Promise.all(clients.map((client) => client.query("ROLLBACK").catch(() => {})));
    for (const client of clients) client.release();
  }
  assert.equal(outcomes.filter((outcome) => outcome.status === "fulfilled").length, 1);
  assert.equal(outcomes.filter((outcome) => outcome.status === "rejected").length, 1);
  const rejected = outcomes.find((outcome) => outcome.status === "rejected").reason;
  assert.equal(rejected.code, "23514");
  assert.equal(rejected.constraint, "webauthn_credentials_last_active");

  const remaining = await pool.query(
    `SELECT count(*)::int AS usable_count
       FROM webauthn_credentials
      WHERE member_id=$1 AND revoked_at IS NULL AND clone_detected_at IS NULL`,
    [fixture.contention.memberId]
  );
  assert.deepEqual(remaining.rows[0], { usable_count: 1 });
}

async function issueContendedCredentialRevoke(client, contention, credentialId) {
  const result = await client.query(
    `UPDATE webauthn_credentials
        SET revoked_at=clock_timestamp(),version=version+1
      WHERE member_id=$1 AND id=$2 AND revoked_at IS NULL AND version=1
      RETURNING id`,
    [contention.memberId, Buffer.from(credentialId, "base64url")]
  );
  assert.equal(result.rowCount, 1);
}

async function assertRecentAuthBinding(repository, pool, fixture) {
  const challenge = fixture.clone.pendingChallenge;
  const bound = await repository.bindRecentAuth({
    session_id: fixture.clone.sessionId,
    member_id: fixture.clone.memberId,
    organization_id: fixture.organizationId,
    operation: "human.webauthn.credential.rename",
    challenge_id: fixture.clone.consumedChallenge,
    context_hash: CONTEXT_HASH,
    authenticated_at: AUTHENTICATED_AT
  });
  assert.equal(bound, true);

  assert.equal(await repository.consumeRecentAuth({
    session_id: fixture.clone.sessionId,
    member_id: fixture.clone.memberId,
    organization_id: fixture.organizationId,
    operation: "human.webauthn.credential.rename",
    challenge_id: fixture.clone.consumedChallenge,
    context_hash: "cd".repeat(32),
    consumed_at: "2026-08-16T00:02:00.000Z"
  }), null, "a recent-auth proof cannot be consumed for another resource context");

  const consumed = await repository.consumeRecentAuth({
    session_id: fixture.clone.sessionId,
    member_id: fixture.clone.memberId,
    organization_id: fixture.organizationId,
    operation: "human.webauthn.credential.rename",
    challenge_id: fixture.clone.consumedChallenge,
    context_hash: CONTEXT_HASH,
    consumed_at: "2026-08-16T00:02:00.000Z"
  });
  assert.equal(consumed.context_hash, CONTEXT_HASH);

  const challengeState = await pool.query("SELECT status,context_hash FROM webauthn_challenges WHERE id=$1", [challenge]);
  assert.equal(challengeState.rows[0].status, "pending");
  assert.equal(challengeState.rows[0].context_hash.toString("hex"), CONTEXT_HASH);
}

async function assertCloneQuarantineAndAuthorityPropagation(pool, fixture) {
  const reductions = [];
  const repository = createPostgresHumanRepository({
    client: pool,
    onAuthorityReduction: async (input) => {
      reductions.push(input);
      assert.equal(input.organization_id, fixture.organizationId);
      assert.equal(input.member_id, fixture.clone.memberId);
      assert.equal(input.resource, "credential");
      assert.equal(input.reason, "webauthn_clone_detected");
      assert.ok(input.tx && typeof input.tx.query === "function");
      const result = await input.tx.query(
        "SELECT public.agentpass_invalidate_identity_epoch($1::uuid,$2::uuid,'webauthn_credential_revoked') AS authority",
        [input.organization_id, input.member_id]
      );
      const authority = result.rows[0].authority;
      return { generation: Number(authority.membership_session_epoch) };
    }
  });

  assert.equal(await repository.quarantineCredentialClone({
    session_id: fixture.clone.sessionId,
    organization_id: fixture.organizationId,
    credential_id: fixture.clone.credentialId,
    expected_sign_count: 8,
    observed_sign_count: 8
  }), true);
  assert.equal(reductions.length, 1);

  const target = await pool.query(`SELECT sign_count_state,clone_detected_at,sign_count,version
    FROM webauthn_credentials WHERE id=$1`, [Buffer.from(fixture.clone.credentialId, "base64url")]);
  assert.deepEqual(target.rows[0].sign_count_state, "clone-detected");
  assert.ok(target.rows[0].clone_detected_at instanceof Date || typeof target.rows[0].clone_detected_at === "string");
  assert.equal(Number(target.rows[0].sign_count), 8);
  assert.equal(Number(target.rows[0].version), 2);

  await assert.rejects(
    pool.query(`UPDATE webauthn_credentials
      SET sign_count_state='monotonic',clone_detected_at=NULL,sign_count=7
      WHERE id=$1`, [Buffer.from(fixture.clone.credentialId, "base64url")]),
    (error) => error?.code === "23514"
      && error?.constraint === "webauthn_credentials_clone_quarantine_monotonic"
  );
  const retainedQuarantine = await pool.query(`SELECT sign_count_state,clone_detected_at,sign_count,version
    FROM webauthn_credentials WHERE id=$1`, [Buffer.from(fixture.clone.credentialId, "base64url")]);
  assert.equal(retainedQuarantine.rows[0].sign_count_state, "clone-detected");
  assert.ok(retainedQuarantine.rows[0].clone_detected_at);
  assert.equal(Number(retainedQuarantine.rows[0].sign_count), 8);
  assert.equal(Number(retainedQuarantine.rows[0].version), 2);

  const targetState = await pool.query(`SELECT s.revoked_at,s.recent_auth_at,s.recent_auth_challenge_id,
      s.recent_auth_context_hash,m.session_epoch
    FROM human_sessions s
    JOIN memberships m ON m.id=s.membership_id AND m.organization_id=s.organization_id
    WHERE s.id=$1`, [fixture.clone.sessionId]);
  assert.equal(targetState.rows[0].revoked_at instanceof Date || typeof targetState.rows[0].revoked_at === "string", true);
  assert.equal(targetState.rows[0].recent_auth_at, null);
  assert.equal(targetState.rows[0].recent_auth_challenge_id, null);
  assert.equal(targetState.rows[0].recent_auth_context_hash, null);
  assert.equal(Number(targetState.rows[0].session_epoch), 2);

  const targetChallenge = await pool.query("SELECT status,consumed_at FROM webauthn_challenges WHERE id=$1", [fixture.clone.pendingChallenge]);
  assert.equal(targetChallenge.rows[0].status, "consumed");
  assert.ok(targetChallenge.rows[0].consumed_at);

  const targetCapability = await pool.query("SELECT revoked_at FROM capabilities WHERE id=$1 AND organization_id=$2", [fixture.clone.capabilityId, fixture.organizationId]);
  assert.ok(targetCapability.rows[0].revoked_at);

  const targetEpoch = await pool.query("SELECT authority_epoch FROM organizations WHERE id=$1", [fixture.organizationId]);
  assert.equal(Number(targetEpoch.rows[0].authority_epoch), 1, "member-scoped reduction must not advance tenant epoch");

  const isolated = await pool.query(`SELECT o.authority_epoch,m.session_epoch,s.revoked_at,s.recent_auth_at,
      c.status,c.consumed_at,cap.revoked_at AS capability_revoked
    FROM organizations o
    JOIN memberships m ON m.organization_id=o.id AND m.member_id=$2
    JOIN human_sessions s ON s.id=$3
    JOIN webauthn_challenges c ON c.id=$4
    JOIN capabilities cap ON cap.id=$5 AND cap.organization_id=o.id
    WHERE o.id=$1`, [fixture.otherOrganizationId, fixture.other.memberId, fixture.other.sessionId, fixture.other.pendingChallenge, fixture.other.capabilityId]);
  assert.deepEqual(isolated.rows[0], {
    authority_epoch: "1",
    session_epoch: "1",
    revoked_at: null,
    recent_auth_at: null,
    status: "pending",
    consumed_at: null,
    capability_revoked: null
  });

  const rollbackBefore = await readRollbackState(pool, fixture);
  const rollbackRepository = createPostgresHumanRepository({
    client: pool,
    onAuthorityReduction: async ({ tx }) => {
      await tx.query("UPDATE webauthn_challenges SET status='consumed',consumed_at=clock_timestamp() WHERE id=$1", [fixture.rollback.pendingChallenge]);
      await tx.query("UPDATE capabilities SET revoked_at=clock_timestamp() WHERE id=$1 AND organization_id=$2", [fixture.rollback.capabilityId, fixture.organizationId]);
      await tx.query("UPDATE human_sessions SET last_seen_at=clock_timestamp(),version=version+1,recent_auth_consumed_at=clock_timestamp() WHERE id=$1", [fixture.rollback.sessionId]);
      throw new Error("injected H2.1 callback failure");
    }
  });
  await assert.rejects(
    rollbackRepository.quarantineCredentialClone({
      session_id: fixture.rollback.sessionId,
      organization_id: fixture.organizationId,
      credential_id: fixture.rollback.credentialId,
      expected_sign_count: 8,
      observed_sign_count: 8
    }),
    /injected H2\.1 callback failure/u
  );
  const rollbackState = await pool.query(`SELECT sign_count_state,clone_detected_at,version
    FROM webauthn_credentials WHERE id=$1`, [Buffer.from(fixture.rollback.credentialId, "base64url")]);
  assert.deepEqual(rollbackState.rows[0], {
    sign_count_state: "monotonic",
    clone_detected_at: null,
    version: "1"
  });
  const rollbackAfter = await readRollbackState(pool, fixture);
  assert.deepEqual(rollbackAfter.session, rollbackBefore.session, "session and recent-auth changes must roll back");
  assert.deepEqual(rollbackAfter.challenge, rollbackBefore.challenge, "challenge invalidation must roll back");
  assert.deepEqual(rollbackAfter.capability, rollbackBefore.capability, "capability invalidation must roll back");
}

async function readRollbackState(pool, fixture) {
  const session = await pool.query(`SELECT s.revoked_at,s.recent_auth_at,s.recent_auth_challenge_id,
      s.recent_auth_organization_id,s.recent_auth_operation,s.recent_auth_context_hash,
      s.recent_auth_consumed_at,s.last_seen_at,s.version,m.session_epoch
    FROM human_sessions s
    JOIN memberships m ON m.id=s.membership_id AND m.organization_id=s.organization_id
    WHERE s.id=$1`, [fixture.rollback.sessionId]);
  const challenge = await pool.query("SELECT status,consumed_at FROM webauthn_challenges WHERE id=$1", [fixture.rollback.pendingChallenge]);
  const capability = await pool.query("SELECT revoked_at FROM capabilities WHERE id=$1 AND organization_id=$2", [fixture.rollback.capabilityId, fixture.organizationId]);
  return {
    session: normalizeRollbackSession(session.rows[0]),
    challenge: {
      status: challenge.rows[0].status,
      consumed_at: normalizeTimestamp(challenge.rows[0].consumed_at)
    },
    capability: { revoked_at: normalizeTimestamp(capability.rows[0].revoked_at) }
  };
}

function normalizeRollbackSession(row) {
  return {
    revoked_at: normalizeTimestamp(row.revoked_at),
    recent_auth_at: normalizeTimestamp(row.recent_auth_at),
    recent_auth_challenge_id: row.recent_auth_challenge_id,
    recent_auth_organization_id: row.recent_auth_organization_id,
    recent_auth_operation: row.recent_auth_operation,
    recent_auth_context_hash: row.recent_auth_context_hash?.toString("hex") ?? null,
    recent_auth_consumed_at: normalizeTimestamp(row.recent_auth_consumed_at),
    last_seen_at: normalizeTimestamp(row.last_seen_at),
    version: String(row.version),
    session_epoch: String(row.session_epoch)
  };
}

function normalizeTimestamp(value) {
  return value === null || value === undefined ? null : value instanceof Date ? value.toISOString() : String(value);
}

async function seedFixture(pool) {
  const fixture = {
    organizationId: crypto.randomUUID(),
    otherOrganizationId: crypto.randomUUID(),
    management: {
      memberId: crypto.randomUUID(),
      membershipId: crypto.randomUUID(),
      sessionId: crypto.randomUUID(),
      renameCredential: credentialId(),
      revokeCredential: credentialId()
    },
    clone: {
      memberId: crypto.randomUUID(),
      membershipId: crypto.randomUUID(),
      sessionId: crypto.randomUUID(),
      credentialId: credentialId(),
      pendingChallenge: crypto.randomUUID(),
      consumedChallenge: crypto.randomUUID(),
      capabilityId: crypto.randomUUID()
    },
    contention: {
      memberId: crypto.randomUUID(),
      membershipId: crypto.randomUUID(),
      firstCredential: credentialId(),
      secondCredential: credentialId()
    },
    rollback: {
      memberId: crypto.randomUUID(),
      membershipId: crypto.randomUUID(),
      sessionId: crypto.randomUUID(),
      credentialId: credentialId(),
      pendingChallenge: crypto.randomUUID(),
      consumedChallenge: crypto.randomUUID(),
      capabilityId: crypto.randomUUID()
    },
    other: {
      memberId: crypto.randomUUID(),
      membershipId: crypto.randomUUID(),
      sessionId: crypto.randomUUID(),
      pendingChallenge: crypto.randomUUID(),
      capabilityId: crypto.randomUUID(),
      credentialId: credentialId()
    }
  };
  const members = [fixture.management, fixture.clone, fixture.contention, fixture.rollback];
  const other = fixture.other;
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,'H2.1 primary'),($2,'H2.1 isolated')", [fixture.organizationId, fixture.otherOrganizationId]);
  for (const [index, member] of [...members, other].entries()) {
    await pool.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,$3)", [member.memberId, `h21-${member.memberId}`, `H2.1 member ${index}`]);
  }
  for (const member of members) {
    await pool.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')", [fixture.organizationId, member.membershipId, member.memberId]);
  }
  await pool.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')", [fixture.otherOrganizationId, other.membershipId, other.memberId]);
  await insertSession(pool, fixture.organizationId, fixture.management);
  await insertSession(pool, fixture.organizationId, fixture.clone);
  await insertSession(pool, fixture.organizationId, fixture.rollback);
  await insertSession(pool, fixture.otherOrganizationId, other);

  await pool.query(`INSERT INTO webauthn_credentials (id,member_id,public_key,sign_count,sign_count_state,transports,label,backup_eligible,backup_state)
    VALUES ($1,$2,$3,0,'zero-counter',ARRAY['internal']::text[],'Rename me',false,false),
           ($4,$2,$5,0,'zero-counter',ARRAY['internal']::text[],'Revoke me',false,false)`, [
    Buffer.from(fixture.management.renameCredential, "base64url"), fixture.management.memberId, Buffer.alloc(32, 0x31),
    Buffer.from(fixture.management.revokeCredential, "base64url"), Buffer.alloc(32, 0x32)
  ]);
  await pool.query(`INSERT INTO webauthn_credentials (id,member_id,public_key,sign_count,sign_count_state,transports,label,backup_eligible,backup_state)
    VALUES ($1,$2,$3,8,'monotonic',ARRAY['internal']::text[],'Clone candidate',false,false),
           ($4,$5,$6,0,'zero-counter',ARRAY['internal']::text[],'Other tenant',false,false)`, [
    Buffer.from(fixture.clone.credentialId, "base64url"), fixture.clone.memberId, Buffer.alloc(32, 0x33),
    Buffer.from(other.credentialId, "base64url"), other.memberId, Buffer.alloc(32, 0x34)
  ]);
  await pool.query(`INSERT INTO webauthn_credentials (id,member_id,public_key,sign_count,sign_count_state,transports,label,backup_eligible,backup_state)
    VALUES ($1,$2,$3,0,'zero-counter',ARRAY['internal']::text[],'Contention one',false,false),
           ($4,$2,$5,0,'zero-counter',ARRAY['internal']::text[],'Contention two',false,false)`, [
    Buffer.from(fixture.contention.firstCredential, "base64url"), fixture.contention.memberId, Buffer.alloc(32, 0x35),
    Buffer.from(fixture.contention.secondCredential, "base64url"), Buffer.alloc(32, 0x36)
  ]);
  await pool.query(`INSERT INTO webauthn_credentials (id,member_id,public_key,sign_count,sign_count_state,transports,label,backup_eligible,backup_state)
    VALUES ($1,$2,$3,8,'monotonic',ARRAY['internal']::text[],'Rollback candidate',false,false)`, [
    Buffer.from(fixture.rollback.credentialId, "base64url"), fixture.rollback.memberId, Buffer.alloc(32, 0x37)
  ]);

  await insertChallenge(pool, fixture.organizationId, fixture.clone.pendingChallenge, fixture.clone, { status: "pending", contextHash: CONTEXT_HASH });
  await insertChallenge(pool, fixture.organizationId, fixture.clone.consumedChallenge, fixture.clone, { status: "consumed", contextHash: CONTEXT_HASH, consumedAt: AUTHENTICATED_AT });
  await insertChallenge(pool, fixture.organizationId, fixture.rollback.pendingChallenge, fixture.rollback, { status: "pending", contextHash: CONTEXT_HASH });
  await insertChallenge(pool, fixture.organizationId, fixture.rollback.consumedChallenge, fixture.rollback, { status: "consumed", contextHash: CONTEXT_HASH, consumedAt: AUTHENTICATED_AT });
  await insertChallenge(pool, fixture.otherOrganizationId, other.pendingChallenge, other, { status: "pending", contextHash: CONTEXT_HASH });
  await insertControlPlaneRows(pool, fixture.organizationId, fixture.clone, "H2.1 primary");
  await insertControlPlaneRows(pool, fixture.organizationId, fixture.rollback, "H2.1 rollback");
  await insertControlPlaneRows(pool, fixture.otherOrganizationId, other, "H2.1 isolated");
  const rollbackRepository = createPostgresHumanRepository({ client: pool });
  assert.equal(await rollbackRepository.bindRecentAuth({
    session_id: fixture.rollback.sessionId,
    member_id: fixture.rollback.memberId,
    organization_id: fixture.organizationId,
    operation: "human.webauthn.credential.rename",
    challenge_id: fixture.rollback.consumedChallenge,
    context_hash: CONTEXT_HASH,
    authenticated_at: AUTHENTICATED_AT
  }), true);
  return fixture;
}

async function insertSession(pool, organizationId, member) {
  const now = new Date().toISOString();
  await pool.query(`INSERT INTO human_sessions
    (id,member_id,organization_id,membership_id,role,token_hash,csrf_token_hash,created_at,expires_at,last_seen_at,idle_expires_at)
    VALUES ($1,$2,$3,$4,'owner',$5,$6,$7,$8,$7,$8)`, [
    member.sessionId, member.memberId, organizationId, member.membershipId,
    crypto.randomBytes(32), crypto.randomBytes(32), now, EXPIRES_AT
  ]);
}

async function insertChallenge(pool, organizationId, challengeId, member, { status, contextHash, consumedAt = null }) {
  const createdAt = consumedAt === null
    ? new Date(Date.now() - 10_000)
    : new Date(new Date(consumedAt).getTime() - 10_000);
  await pool.query(`INSERT INTO webauthn_challenges
    (id,session_id,member_id,organization_id,ceremony,operation,challenge_hash,created_at,expires_at,rp_id,origin,user_verification,status,consumed_at,context_hash)
    VALUES ($1,$2,$3,$4,'authentication','human.webauthn.credential.rename',$5,$6,$7,'agentpass.local','https://agentpass.local','required',$8,$9,$10)`, [
    challengeId, member.sessionId, member.memberId,
    organizationId,
    crypto.randomBytes(32), createdAt, EXPIRES_AT, status, consumedAt, Buffer.from(contextHash, "hex")
  ]);
}

async function insertControlPlaneRows(pool, organizationId, member, label) {
  const deviceId = crypto.randomUUID();
  const agentId = crypto.randomUUID();
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const publicKey = keyPair.publicKey.export({ type: "spki", format: "pem" }).toString().trimEnd();
  await pool.query(`INSERT INTO devices (organization_id,id,label,key_algorithm,public_key_pem,status,metadata)
    VALUES ($1,$2,$3,'ed25519',$4,'active','{}'::jsonb)`, [organizationId, deviceId, `${label} device`, publicKey]);
  await pool.query(`INSERT INTO agents (organization_id,id,device_id,kind,name,public_key_pem,status)
    VALUES ($1,$2,$3,'claude-code',$4,$5,'active')`, [organizationId, agentId, deviceId, `${label} agent`, publicKey]);
  await pool.query(`INSERT INTO capabilities (organization_id,id,agent_id,device_id,sequence,statement_hash,expires_at,issued_by_member_id,issued_membership_version)
    VALUES ($1,$2,$3,$4,1,$5,$6,$7,1)`, [organizationId, member.capabilityId, agentId, deviceId, "a".repeat(64), EXPIRES_AT, member.memberId]);
}

async function cleanup(pool, fixture) {
  if (!fixture) return;
  const organizations = [fixture.organizationId, fixture.otherOrganizationId];
  const members = [fixture.management.memberId, fixture.clone.memberId, fixture.contention.memberId, fixture.rollback.memberId, fixture.other.memberId];
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL session_replication_role = replica");
    await client.query("DELETE FROM idempotency_records WHERE organization_id=ANY($1::uuid[])", [organizations]);
    await client.query("DELETE FROM capabilities WHERE organization_id=ANY($1::uuid[])", [organizations]);
    await client.query("DELETE FROM agents WHERE organization_id=ANY($1::uuid[])", [organizations]);
    await client.query("DELETE FROM devices WHERE organization_id=ANY($1::uuid[])", [organizations]);
    await client.query("DELETE FROM webauthn_challenges WHERE organization_id=ANY($1::uuid[])", [organizations]);
    await client.query("DELETE FROM human_sessions WHERE organization_id=ANY($1::uuid[])", [organizations]);
    await client.query("DELETE FROM webauthn_credentials WHERE member_id=ANY($1::uuid[])", [members]);
    await client.query("DELETE FROM memberships WHERE organization_id=ANY($1::uuid[])", [organizations]);
    await client.query("DELETE FROM organizations WHERE id=ANY($1::uuid[])", [organizations]);
    await client.query("DELETE FROM members WHERE id=ANY($1::uuid[])", [members]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

function credentialId() { return crypto.randomBytes(16).toString("base64url"); }
