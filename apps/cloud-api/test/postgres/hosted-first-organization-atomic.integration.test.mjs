// Real-PostgreSQL integration coverage for migration 0060.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const REDIRECT_URI = "https://console.example.test/api/auth/bootstrap/github/callback";
const ORGANIZATION_NAME = "AgentPass first organization";
const ZERO_HASH = "0".repeat(64);

const uuid = (suffix) => `00000000-0000-4000-8000-${String(suffix).padStart(12, "0")}`;
const sha256 = (value) => crypto.createHash("sha256").update(value).digest();
const hexDigest = (value) => Buffer.from(value).toString("hex");

const CASES = Object.freeze({
  sameKey: Object.freeze({
    memberId: uuid("1001"), attemptId: uuid("1002"), oauthStateId: uuid("1003"), subject: "910001",
    cookie: Buffer.alloc(32, 0x11), requestHash: sha256(ORGANIZATION_NAME),
    organizationIds: [uuid("1004"), uuid("1005")], membershipIds: [uuid("1006"), uuid("1007")], auditIds: [uuid("1008"), uuid("1009")],
    keys: ["same-key-0060", "same-key-0060"]
  }),
  differentKeys: Object.freeze({
    memberId: uuid("2001"), attemptId: uuid("2002"), oauthStateId: uuid("2003"), subject: "920001",
    cookie: Buffer.alloc(32, 0x21), requestHash: sha256(ORGANIZATION_NAME),
    organizationIds: [uuid("2004"), uuid("2005")], membershipIds: [uuid("2006"), uuid("2007")], auditIds: [uuid("2008"), uuid("2009")],
    keys: ["different-key-a", "different-key-b"]
  }),
  activeHistory: Object.freeze({
    memberId: uuid("3001"), attemptId: uuid("3002"), oauthStateId: uuid("3003"), subject: "930001",
    cookie: Buffer.alloc(32, 0x31), requestHash: sha256(ORGANIZATION_NAME),
    existingOrganizationId: uuid("3004"), existingMembershipId: uuid("3005"),
    organizationIds: [uuid("3006")], membershipIds: [uuid("3007")], auditIds: [uuid("3008")],
    keys: ["active-history-0060"]
  }),
  revokedHistory: Object.freeze({
    memberId: uuid("4001"), attemptId: uuid("4002"), oauthStateId: uuid("4003"), subject: "940001",
    cookie: Buffer.alloc(32, 0x41), requestHash: sha256(ORGANIZATION_NAME),
    existingOrganizationId: uuid("4004"), existingMembershipId: uuid("4005"),
    organizationIds: [uuid("4006")], membershipIds: [uuid("4007")], auditIds: [uuid("4008")],
    keys: ["revoked-history-0060"]
  }),
  requestMismatch: Object.freeze({
    memberId: uuid("5001"), attemptId: uuid("5002"), oauthStateId: uuid("5003"), subject: "950001",
    cookie: Buffer.alloc(32, 0x51), requestHash: sha256(ORGANIZATION_NAME), mismatchHash: Buffer.alloc(32, 0x53),
    organizationIds: [uuid("5004"), uuid("5005")], membershipIds: [uuid("5006"), uuid("5007")], auditIds: [uuid("5008"), uuid("5009")],
    keys: ["request-mismatch-0060"]
  })
});

test("0060 atomically creates the first hosted organization in real PostgreSQL", { skip: !databaseUrl, timeout: 120_000 }, async (t) => {
  const pool = new Pool({ connectionString: databaseUrl, max: 12, statement_timeout: 15_000, query_timeout: 20_000 });
  t.after(async () => {
    await cleanup(pool);
    await pool.end();
  });

  const migrationClient = await pool.connect();
  try {
    await createMigrationRunner({ client: migrationClient, applicationVersion: "hosted-identity-first-organization-integration" }).run();
  } finally {
    migrationClient.release();
  }
  await cleanup(pool);

  await t.test("same idempotency key converges to one organization, owner membership, and audit event", async () => {
    const value = CASES.sameKey;
    await seedOrganizationRequired(pool, value);
    const results = await Promise.all(value.keys.map((key, index) => commit(pool, value, {
      idempotencyKey: key,
      organizationId: value.organizationIds[index],
      membershipId: value.membershipIds[index],
      auditEventId: value.auditIds[index]
    })));

    assert.deepEqual(results.map((row) => row.response_status).sort((a, b) => a - b), [200, 201]);
    assert.deepEqual(results.map((row) => row.replayed).sort(), [false, true]);
    assert.equal(canonicalJson(results[0].response_json), canonicalJson(results[1].response_json), "same-key response_json must be byte-equivalent after canonical serialization");
    const committed = results.find((row) => row.response_status === 201);
    assert.equal(committed.replayed, false);
    assertBootstrapResponse(committed.response_json, value, value.organizationIds.find((id) => committed.response_json.organization.organization_id === id));

    assert.equal(await countByIds(pool, "organizations", value.organizationIds), 1);
    assert.equal(await countByIds(pool, "memberships", value.membershipIds), 1);
    assert.equal(await countByIds(pool, "admin_audit_events", value.auditIds), 1);
    assert.equal(await countByIds(pool, "hosted_identity_bootstrap_idempotency", value.keys, "idempotency_key"), 1);

    const attempt = await readAttempt(pool, value.attemptId);
    assert.equal(attempt.state, "webauthn_required");
    assert.equal(attempt.member_id, value.memberId);
    const owner = await pool.query("SELECT organization_id,id,member_id,role,status FROM public.memberships WHERE organization_id=$1 AND id=$2", [attempt.organization_id, attempt.membership_id]);
    assert.deepEqual(owner.rows[0], {
      organization_id: attempt.organization_id,
      id: attempt.membership_id,
      member_id: value.memberId,
      role: "owner",
      status: "active"
    });
    await assertAuditChain(pool, {
      organizationId: attempt.organization_id,
      auditEventId: attempt.organization_id === value.organizationIds[0] ? value.auditIds[0] : value.auditIds[1],
      actorId: value.memberId,
      cookieHash: value.cookie,
      requestHash: value.requestHash,
      idempotencyKey: value.keys[0],
      subject: value.subject
    });
  });

  await t.test("different keys produce one stable conflict and no second organization or orphan", async () => {
    const value = CASES.differentKeys;
    await seedOrganizationRequired(pool, value);
    const outcomes = await Promise.all(value.keys.map((key, index) => settle(() => commit(pool, value, {
      idempotencyKey: key,
      organizationId: value.organizationIds[index],
      membershipId: value.membershipIds[index],
      auditEventId: value.auditIds[index]
    }))));
    const successes = outcomes.filter((outcome) => outcome.ok).map((outcome) => outcome.value);
    const failures = outcomes.filter((outcome) => !outcome.ok).map((outcome) => outcome.error);
    assert.equal(successes.length, 1);
    assert.equal(failures.length, 1);
    assert.equal(successes[0].response_status, 201);
    assert.equal(successes[0].replayed, false);
    assertStableConflict(failures[0], "first organization bootstrap is already completed");
    assert.equal(await countByIds(pool, "organizations", value.organizationIds), 1);
    assert.equal(await countByIds(pool, "memberships", value.membershipIds), 1);
    assert.equal(await countByIds(pool, "admin_audit_events", value.auditIds), 1);
    assert.equal(await countByIds(pool, "hosted_identity_bootstrap_idempotency", value.keys, "idempotency_key"), 1);
  });

  for (const [history, expected] of [[CASES.activeHistory, "active"], [CASES.revokedHistory, "revoked"]]) {
    await t.test(`${expected} membership history is a conflict with no first-organization writes`, async () => {
      await seedOrganizationRequired(pool, history, { existingMembershipStatus: expected });
      const outcome = await settle(() => commit(pool, history, {
        idempotencyKey: history.keys[0],
        organizationId: history.organizationIds[0],
        membershipId: history.membershipIds[0],
        auditEventId: history.auditIds[0]
      }));
      assert.equal(outcome.ok, false);
      assertStableConflict(outcome.error);
      assert.equal(await countByIds(pool, "organizations", history.organizationIds), 0);
      assert.equal(await countByIds(pool, "memberships", history.membershipIds), 0);
      assert.equal(await countByIds(pool, "admin_audit_events", history.auditIds), 0);
      assert.equal(await countByIds(pool, "hosted_identity_bootstrap_idempotency", history.keys, "idempotency_key"), 0);
      const attempt = await readAttempt(pool, history.attemptId);
      assert.equal(attempt.state, "organization_required");
      assert.equal(attempt.organization_id, null);
      assert.equal(attempt.membership_id, null);
    });
  }

  await t.test("request-hash mismatch on replay is a stable conflict and does not write again", async () => {
    const value = CASES.requestMismatch;
    await seedOrganizationRequired(pool, value);
    const first = await commit(pool, value, {
      idempotencyKey: value.keys[0],
      organizationId: value.organizationIds[0],
      membershipId: value.membershipIds[0],
      auditEventId: value.auditIds[0]
    });
    const replay = await settle(() => commit(pool, value, {
      idempotencyKey: value.keys[0],
      requestHash: value.mismatchHash,
      organizationId: value.organizationIds[1],
      membershipId: value.membershipIds[1],
      auditEventId: value.auditIds[1]
    }));
    assert.equal(first.response_status, 201);
    assert.equal(first.replayed, false);
    assert.equal(replay.ok, false);
    assertStableConflict(replay.error, "idempotency key was reused with a different request");
    assert.equal(await countByIds(pool, "organizations", value.organizationIds), 1);
    assert.equal(await countByIds(pool, "memberships", value.membershipIds), 1);
    assert.equal(await countByIds(pool, "admin_audit_events", value.auditIds), 1);
    assert.equal(await countByIds(pool, "hosted_identity_bootstrap_idempotency", value.keys, "idempotency_key"), 1);
    assert.equal(canonicalJson(first.response_json), canonicalJson((await readIdempotency(pool, value.memberId, value.keys[0])).response_json));
  });
});

async function commit(pool, value, overrides = {}) {
  const requestHash = overrides.requestHash ?? value.requestHash;
  const result = await pool.query(
    "SELECT response_status,response_json,replayed FROM public.agentpass_hosted_identity_bootstrap_organization_commit_v2($1::bytea,$2::text,$3::bytea,$4::text,$5::uuid,$6::uuid,$7::uuid)",
    [value.cookie, overrides.idempotencyKey ?? value.keys[0], requestHash, ORGANIZATION_NAME, overrides.organizationId, overrides.membershipId, overrides.auditEventId]
  );
  assert.equal(result.rowCount, 1);
  return result.rows[0];
}

async function seedOrganizationRequired(pool, value, { existingMembershipStatus = null } = {}) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET CONSTRAINTS ALL DEFERRED");
    const nowResult = await client.query("SELECT clock_timestamp() AS now");
    const createdAt = new Date(nowResult.rows[0].now);
    const oauthExpiresAt = new Date(createdAt.getTime() + 10 * 60_000);
    const attemptExpiresAt = new Date(createdAt.getTime() + 15 * 60_000);
    await client.query("INSERT INTO public.members (id,github_subject,display_name) VALUES ($1,NULL,$2)", [value.memberId, `0060 ${value.subject}`]);
    await client.query("INSERT INTO public.upstream_identities (provider,subject,member_id) VALUES ('github',$1,$2)", [value.subject, value.memberId]);
    if (existingMembershipStatus) {
      await client.query("INSERT INTO public.organizations (id,name) VALUES ($1,$2)", [value.existingOrganizationId, `0060 existing ${existingMembershipStatus}`]);
      await client.query("INSERT INTO public.memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner',$4)", [value.existingOrganizationId, value.existingMembershipId, value.memberId, existingMembershipStatus]);
    }
    await client.query(`INSERT INTO public.hosted_identity_bootstrap_attempts
      (id,oauth_state_id,state,bootstrap_cookie_hash,provider,member_id,identity_subject_digest,created_at,expires_at,identity_verified_at)
      VALUES ($1,$2,'organization_required',$3,'github',$4,$5,$6,$7,$6)`,
    [value.attemptId, value.oauthStateId, value.cookie, value.memberId, sha256(value.subject), createdAt, attemptExpiresAt]);
    await client.query(`INSERT INTO public.hosted_identity_oauth_states
      (id,attempt_id,state_hash,code_hash,provider,client_id,redirect_uri,pkce_challenge,pkce_method,status,created_at,expires_at,consume_started_at,consumed_at)
      VALUES ($1,$2,$3,$4,'github','agentpass-0060',$5,$6,'S256','consumed',$7,$8,$7,$7)`,
    [value.oauthStateId, value.attemptId, sha256(`state:${value.subject}`), sha256(`code:${value.subject}`), REDIRECT_URI, "A".repeat(43), createdAt, oauthExpiresAt]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function readAttempt(pool, attemptId) {
  const result = await pool.query("SELECT state,member_id,organization_id,membership_id FROM public.hosted_identity_bootstrap_attempts WHERE id=$1", [attemptId]);
  assert.equal(result.rowCount, 1);
  return result.rows[0];
}

async function readIdempotency(pool, memberId, idempotencyKey) {
  const result = await pool.query("SELECT response_json FROM public.hosted_identity_bootstrap_idempotency WHERE member_id=$1 AND operation='first_organization_create' AND idempotency_key=$2", [memberId, idempotencyKey]);
  assert.equal(result.rowCount, 1);
  return result.rows[0];
}

function assertBootstrapResponse(response, value, organizationId) {
  assert.deepEqual(Object.keys(response).sort(), ["onboarding", "organization", "version"]);
  assert.equal(response.version, 1);
  assert.equal(response.organization.organization_id, organizationId);
  assert.equal(response.organization.name, ORGANIZATION_NAME);
  assert.equal(response.onboarding.state, "webauthn_required");
}

async function assertAuditChain(pool, { organizationId, auditEventId, actorId, cookieHash, requestHash, idempotencyKey, subject }) {
  const events = await pool.query(`SELECT id,organization_id,actor_id,action,target_type,target_id,previous_hash,event_hash,sequence,event_json,event_json::text AS event_json_text
    FROM public.admin_audit_events WHERE organization_id=$1`, [organizationId]);
  assert.equal(events.rowCount, 1);
  const event = events.rows[0];
  assert.equal(event.id, auditEventId);
  assert.equal(event.actor_id, actorId);
  assert.equal(Number(event.sequence), 1);
  assert.equal(event.previous_hash, ZERO_HASH);
  assert.match(event.event_hash, /^[0-9a-f]{64}$/u);
  assert.equal(crypto.createHash("sha256").update(event.event_json_text, "utf8").digest("hex"), event.event_hash);
  const eventText = JSON.stringify(event.event_json);
  for (const secret of [hexDigest(cookieHash), hexDigest(requestHash), idempotencyKey, subject]) {
    assert.equal(eventText.includes(secret), false, `audit event must not contain ${secret}`);
  }
  const head = await pool.query("SELECT sequence,event_hash FROM public.admin_audit_heads WHERE organization_id=$1", [organizationId]);
  assert.deepEqual({ sequence: Number(head.rows[0].sequence), event_hash: head.rows[0].event_hash }, { sequence: 1, event_hash: event.event_hash });
}

function assertStableConflict(error, expectedMessage = undefined) {
  assert.equal(error?.code, "23505");
  if (expectedMessage !== undefined) assert.equal(error.message, expectedMessage);
}

async function settle(operation) {
  try {
    return { ok: true, value: await operation() };
  } catch (error) {
    return { ok: false, error };
  }
}

async function countByIds(pool, table, ids, column = "id") {
  const result = await pool.query(`SELECT count(*)::int AS count FROM public.${table} WHERE ${column}=ANY($1::${column === "idempotency_key" ? "text" : "uuid"}[])`, [ids]);
  return result.rows[0].count;
}

async function cleanup(pool) {
  const values = Object.values(CASES);
  const memberIds = values.map((value) => value.memberId);
  const attemptIds = values.map((value) => value.attemptId);
  const oauthStateIds = values.map((value) => value.oauthStateId);
  const organizationIds = values.flatMap((value) => [value.existingOrganizationId, ...value.organizationIds]).filter(Boolean);
  const membershipIds = values.flatMap((value) => [value.existingMembershipId, ...value.membershipIds]).filter(Boolean);
  const auditIds = values.flatMap((value) => value.auditIds);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL session_replication_role = replica");
    await client.query("DELETE FROM public.hosted_identity_bootstrap_webauthn_challenges WHERE attempt_id=ANY($1::uuid[])", [attemptIds]);
    await client.query("DELETE FROM public.hosted_identity_bootstrap_idempotency WHERE member_id=ANY($1::uuid[]) OR attempt_id=ANY($2::uuid[])", [memberIds, attemptIds]);
    await client.query("DELETE FROM public.hosted_identity_oauth_pkce_envelopes WHERE oauth_state_id=ANY($1::uuid[])", [oauthStateIds]);
    await client.query("DELETE FROM public.hosted_identity_oauth_states WHERE id=ANY($1::uuid[])", [oauthStateIds]);
    await client.query("DELETE FROM public.hosted_identity_bootstrap_attempts WHERE id=ANY($1::uuid[])", [attemptIds]);
    await client.query("DELETE FROM public.admin_audit_events WHERE id=ANY($1::uuid[])", [auditIds]);
    await client.query("DELETE FROM public.admin_audit_heads WHERE organization_id=ANY($1::uuid[])", [organizationIds]);
    await client.query("DELETE FROM public.memberships WHERE id=ANY($1::uuid[])", [membershipIds]);
    await client.query("DELETE FROM public.control_plane_authority_generations WHERE organization_id=ANY($1::uuid[])", [organizationIds]);
    await client.query("DELETE FROM public.organizations WHERE id=ANY($1::uuid[])", [organizationIds]);
    await client.query("DELETE FROM public.upstream_identities WHERE member_id=ANY($1::uuid[])", [memberIds]);
    await client.query("DELETE FROM public.members WHERE id=ANY($1::uuid[])", [memberIds]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
