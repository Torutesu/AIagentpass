import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import test from "node:test";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const ADMIN_DATABASE_URL = process.env.AGENTPASS_TEST_POSTGRES_ADMIN_URL ?? DATABASE_URL;
const APP_DATABASE_URL = process.env.AGENTPASS_TEST_APP_DATABASE_URL;
const CREATED_AT = "2026-08-22T00:00:00.000Z";
const EXPIRES_AT = "2099-08-22T00:00:00.000Z";
const PERMISSION_ERRORS = new Set(["42501", "0LP01"]);
const AUTHORITY_FUNCTIONS = [
  "public.agentpass_human_session_switch(uuid,bytea,uuid,uuid,uuid,uuid,bytea,bytea,timestamptz,timestamptz,timestamptz,timestamptz,timestamptz,text)",
  "public.agentpass_human_session_revoke_managed(uuid,uuid,uuid,uuid,bigint,timestamptz,text)",
  "public.agentpass_human_session_revoke_others(uuid,uuid,uuid,timestamptz,text)",
  "public.agentpass_human_member_session_revoke(uuid,uuid,timestamptz,text)"
];

test("real PostgreSQL proves 0100-0103 human-session authority and app DML denial", {
  skip: DATABASE_URL
    ? false
    : "set AGENTPASS_TEST_DATABASE_URL or AGENTPASS_TEST_POSTGRES_URL to run live PostgreSQL authority qualification",
  timeout: 120_000
}, async (t) => {
  if (!ADMIN_DATABASE_URL) throw new Error("live qualification configuration is unavailable");

  // Keep the default lane genuinely skipped even when optional PostgreSQL
  // dependencies or a dirty schema catalog are unavailable.  Live execution
  // loads the same runtime modules used by the other integration lanes.
  const [{ Pool }, { createMigrationRunner }, { POSTGRES_SCHEMA_HEAD }] = await Promise.all([
    import("pg"),
    import("../../src/postgres/migration-runner.mjs"),
    import("../../src/postgres/schema-head.mjs")
  ]);

  const adminPool = new Pool({ connectionString: ADMIN_DATABASE_URL, max: 6 });
  let fixture;
  let appPool;
  t.after(async () => {
    if (fixture) await cleanupFixture(adminPool, fixture);
    if (appPool) await appPool.end();
    await adminPool.end();
  });

  const adminIdentity = await identity(adminPool);
  if (adminIdentity.current_user === "agentpass_app" || adminIdentity.session_user === "agentpass_app") {
    throw new Error("LIMITATION: an agentpass_app-only URL cannot migrate or seed fixtures; provide AGENTPASS_TEST_POSTGRES_ADMIN_URL");
  }

  const migration = await createMigrationRunner({
    client: adminPool,
    applicationVersion: "human-session-authority-0100-0103-integration"
  }).run();
  assert.equal(migration.currentVersion, POSTGRES_SCHEMA_HEAD.version);

  const roles = await adminPool.query(
    "SELECT rolname FROM pg_roles WHERE rolname IN ('agentpass_app','agentpass_migrator') ORDER BY rolname"
  );
  assert.deepEqual(roles.rows.map((row) => row.rolname), ["agentpass_app", "agentpass_migrator"],
    "the live lane requires the production role boundary to exist");

  fixture = await seedFixture(adminPool);
  appPool = APP_DATABASE_URL ? new Pool({ connectionString: APP_DATABASE_URL, max: 4 }) : null;

  const runAsApp = appPool
    ? (callback) => withDirectAppConnection(appPool, callback)
    : (callback) => withSessionAuthorization(adminPool, "agentpass_app", callback);

  await runAsApp(async (app) => {
    const appIdentity = await identity(app);
    assert.equal(appIdentity.session_user, "agentpass_app");
    assert.equal(appIdentity.current_user, "agentpass_app");

    for (const signature of AUTHORITY_FUNCTIONS) {
      const privilege = await app.query(
        "SELECT has_function_privilege(current_user,$1,'EXECUTE') AS allowed", [signature]
      );
      assert.equal(privilege.rows[0].allowed, true, `missing EXECUTE privilege for ${signature}`);
    }
    await assertDirectDmlDenied(app, fixture);

    const switched = await app.query(
      `SELECT public.agentpass_human_session_switch(
        $1::uuid,$2::bytea,$3::uuid,$4::uuid,$5::uuid,$6::uuid,$7::bytea,$8::bytea,
        $9::timestamptz,$10::timestamptz,$11::timestamptz,$12::timestamptz,$13::timestamptz,$14::text) AS session`,
      [fixture.oldSessionId, digest(`token:old:${fixture.oldSessionId}`), fixture.switchedSessionId, fixture.memberId,
        fixture.organizationId, fixture.targetOrganizationId, digest(`token:switched:${fixture.switchedSessionId}`),
        digest(`csrf:switched:${fixture.switchedSessionId}`), CREATED_AT, EXPIRES_AT, CREATED_AT, EXPIRES_AT,
        "2026-08-22T00:01:00.000Z", "integration-switch"]
    );
    assert.ok(switched.rows[0].session, "0100 must return a successor session");

    const managed = await app.query(
      `SELECT public.agentpass_human_session_revoke_managed(
        $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::bigint,$6::timestamptz,$7::text) AS session`,
      [fixture.actorSessionId, fixture.targetSessionId, fixture.memberId, fixture.targetOrganizationId,
        1, "2026-08-22T00:02:00.000Z", "integration-managed-revoke"]
    );
    assert.ok(managed.rows[0].session, "0101 must return the revoked target");

    const others = await app.query(
      `SELECT public.agentpass_human_session_revoke_others(
        $1::uuid,$2::uuid,$3::uuid,$4::timestamptz,$5::text) AS sessions`,
      [fixture.actorSessionId, fixture.memberId, fixture.targetOrganizationId,
        "2026-08-22T00:03:00.000Z", "integration-other-revoke"]
    );
    assert.ok(Array.isArray(others.rows[0].sessions), "0102 must return a JSON session array");

    const memberRevoke = await app.query(
      `SELECT public.agentpass_human_member_session_revoke(
        $1::uuid,$2::uuid,$3::timestamptz,$4::text) AS result`,
      [fixture.memberId, fixture.targetOrganizationId, "2026-08-22T00:04:00.000Z", "integration-member-revoke"]
    );
    assert.ok(memberRevoke.rows[0].result, "0103 must succeed through agentpass_app EXECUTE privilege");
  });

  const state = await adminPool.query(
    `SELECT id, revoked_at, version
       FROM public.human_sessions
      WHERE id = ANY($1::uuid[])
      ORDER BY id`,
    [[fixture.oldSessionId, fixture.actorSessionId, fixture.targetSessionId, fixture.otherSessionId, fixture.switchedSessionId]]
  );
  assert.equal(state.rowCount, 5);
  assert.equal(state.rows.every((row) => row.revoked_at !== null), true,
    "0100-0103 must persist revocation state for the isolated fixture");

  const challenge = await adminPool.query(
    "SELECT status, consumed_at FROM public.webauthn_challenges WHERE id=$1",
    [fixture.challengeId]
  );
  assert.equal(challenge.rows[0].status, "consumed");
  assert.ok(challenge.rows[0].consumed_at);
});

async function identity(pool) {
  const result = await pool.query("SELECT session_user, current_user");
  return result.rows[0];
}

async function withDirectAppConnection(pool, callback) {
  const app = await pool.connect();
  try {
    return await callback(app);
  } finally {
    app.release(true);
  }
}

async function withSessionAuthorization(pool, roleName, callback) {
  const client = await pool.connect();
  try {
    await client.query(`SET SESSION AUTHORIZATION ${roleName}`);
    return await callback(client);
  } finally {
    try { await client.query("RESET SESSION AUTHORIZATION"); } finally { client.release(true); }
  }
}

async function assertDirectDmlDenied(client, fixture) {
  await expectPermissionDenied(() => client.query(
    "INSERT INTO public.human_sessions (id) VALUES ($1)", [randomUUID()]
  ));
  await expectPermissionDenied(() => client.query(
    "UPDATE public.human_sessions SET revoke_reason='direct-dml' WHERE id=$1", [fixture.actorSessionId]
  ));
  await expectPermissionDenied(() => client.query(
    "DELETE FROM public.human_sessions WHERE id=$1", [fixture.actorSessionId]
  ));
  await expectPermissionDenied(() => client.query(
    "INSERT INTO public.webauthn_challenges (id) VALUES ($1)", [randomUUID()]
  ));
  await expectPermissionDenied(() => client.query(
    "UPDATE public.webauthn_challenges SET status='consumed', consumed_at=clock_timestamp() WHERE id=$1",
    [fixture.challengeId]
  ));
  await expectPermissionDenied(() => client.query(
    "DELETE FROM public.webauthn_challenges WHERE id=$1", [fixture.challengeId]
  ));
}

async function expectPermissionDenied(operation) {
  await assert.rejects(operation, (error) => {
    assert.ok(PERMISSION_ERRORS.has(error?.code), `expected permission denial, got ${error?.code ?? "unknown"}`);
    return true;
  });
}

async function seedFixture(pool) {
  const fixture = {
    organizationId: randomUUID(),
    targetOrganizationId: randomUUID(),
    memberId: randomUUID(),
    oldMembershipId: randomUUID(),
    targetMembershipId: randomUUID(),
    oldSessionId: randomUUID(),
    actorSessionId: randomUUID(),
    targetSessionId: randomUUID(),
    otherSessionId: randomUUID(),
    switchedSessionId: randomUUID(),
    challengeId: randomUUID()
  };

  await pool.query("INSERT INTO public.organizations (id,name) VALUES ($1,$2),($3,$4)", [
    fixture.organizationId, `0100-0103 primary ${fixture.organizationId}`,
    fixture.targetOrganizationId, `0100-0103 target ${fixture.targetOrganizationId}`
  ]);
  await pool.query("INSERT INTO public.members (id,github_subject,display_name) VALUES ($1,$2,$3)", [
    fixture.memberId, `0100-0103-${fixture.memberId}`, "0100-0103 member"
  ]);
  await pool.query(`INSERT INTO public.memberships (organization_id,id,member_id,role,status)
    VALUES ($1,$2,$3,'admin','active'),($4,$5,$3,'admin','active')`, [
    fixture.organizationId, fixture.oldMembershipId, fixture.memberId,
    fixture.targetOrganizationId, fixture.targetMembershipId
  ]);

  await insertSession(pool, fixture.oldSessionId, fixture.memberId, fixture.organizationId, fixture.oldMembershipId, "admin", "old");
  await insertSession(pool, fixture.actorSessionId, fixture.memberId, fixture.targetOrganizationId, fixture.targetMembershipId, "admin", "actor");
  await insertSession(pool, fixture.targetSessionId, fixture.memberId, fixture.targetOrganizationId, fixture.targetMembershipId, "admin", "target");
  await insertSession(pool, fixture.otherSessionId, fixture.memberId, fixture.targetOrganizationId, fixture.targetMembershipId, "admin", "other");
  await pool.query(`INSERT INTO public.webauthn_challenges
    (id,session_id,member_id,organization_id,ceremony,operation,challenge_hash,created_at,expires_at,rp_id,origin,user_verification,status)
    VALUES ($1,$2,$3,$4,'authentication','integration_0103',$5,$6,$7,'console.agentpass.test','https://console.agentpass.test','required','pending')`, [
    fixture.challengeId, fixture.actorSessionId, fixture.memberId, fixture.targetOrganizationId,
    digest(`challenge:${fixture.challengeId}`), CREATED_AT, EXPIRES_AT
  ]);
  return fixture;
}

async function insertSession(pool, id, memberId, organizationId, membershipId, role, label) {
  await pool.query(`INSERT INTO public.human_sessions
    (id,member_id,organization_id,membership_id,role,token_hash,csrf_token_hash,created_at,expires_at,last_seen_at,idle_expires_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$8,$9)`, [
    id, memberId, organizationId, membershipId, role,
    digest(`token:${label}:${id}`), digest(`csrf:${label}:${id}`), CREATED_AT, EXPIRES_AT
  ]);
}

async function cleanupFixture(pool, fixture) {
  await pool.query("DELETE FROM public.webauthn_challenges WHERE id=$1", [fixture.challengeId]);
  await pool.query("DELETE FROM public.human_sessions WHERE id = ANY($1::uuid[])", [[
    fixture.oldSessionId, fixture.actorSessionId, fixture.targetSessionId,
    fixture.otherSessionId, fixture.switchedSessionId
  ]]);
  await pool.query("DELETE FROM public.memberships WHERE id = ANY($1::uuid[])", [[
    fixture.oldMembershipId, fixture.targetMembershipId
  ]]);
  await pool.query("DELETE FROM public.members WHERE id=$1", [fixture.memberId]);
  await pool.query("DELETE FROM public.organizations WHERE id = ANY($1::uuid[])", [[
    fixture.organizationId, fixture.targetOrganizationId
  ]]);
}

function digest(value) {
  return createHash("sha256").update(value).digest();
}
