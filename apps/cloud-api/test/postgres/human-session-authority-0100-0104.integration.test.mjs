import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import test from "node:test";

const ADMIN_URL = process.env.AGENTPASS_TEST_POSTGRES_ADMIN_URL
  ?? process.env.AGENTPASS_TEST_DATABASE_URL
  ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const APP_URL = process.env.AGENTPASS_TEST_APP_DATABASE_URL;
const MAINTENANCE_URL = process.env.AGENTPASS_TEST_MAINTENANCE_DATABASE_URL;
const PERMISSION_ERRORS = new Set(["42501", "0LP01"]);
const CREATED_AT = "2026-08-22T00:00:00.000Z";
const EXPIRES_AT = "2099-08-22T00:00:00.000Z";
const AUTHORITY_FUNCTIONS = [
  "public.agentpass_human_session_switch(uuid,bytea,uuid,uuid,uuid,uuid,bytea,bytea,timestamptz,timestamptz,timestamptz,timestamptz,timestamptz,text)",
  "public.agentpass_human_session_revoke_managed(uuid,uuid,uuid,uuid,bigint,timestamptz,text)",
  "public.agentpass_human_session_revoke_others(uuid,uuid,uuid,timestamptz,text)",
  "public.agentpass_human_member_session_revoke(uuid,uuid,timestamptz,text)",
  "public.agentpass_human_identity_resolve(text,text,uuid)",
  "public.agentpass_human_identity_find(text,text)",
  "public.agentpass_human_identity_list_memberships(text,text,uuid)"
];

test("live PostgreSQL proves human session and identity authority 0100-0104", {
  skip: ADMIN_URL
    ? false
    : "set AGENTPASS_TEST_POSTGRES_ADMIN_URL, AGENTPASS_TEST_DATABASE_URL, or AGENTPASS_TEST_POSTGRES_URL to run live PostgreSQL authority qualification",
  timeout: 120_000
}, async (t) => {
  // Keep the default lane genuinely skipped even when the local contract
  // catalog is incomplete. Live qualification loads these modules only after
  // its explicit database URL gate has passed.
  const [{ Pool }, { createMigrationRunner }, { POSTGRES_SCHEMA_HEAD }] = await Promise.all([
    import("pg"),
    import("../../src/postgres/migration-runner.mjs"),
    import("../../src/postgres/schema-head.mjs")
  ]);
  const adminPool = new Pool({ connectionString: ADMIN_URL, max: 8 });
  const appPool = APP_URL ? new Pool({ connectionString: APP_URL, max: 4 }) : null;
  const maintenancePool = MAINTENANCE_URL ? new Pool({ connectionString: MAINTENANCE_URL, max: 2 }) : null;
  let fixture;

  // Assign before seed. Seed is transactional, and cleanup is still attempted
  // if a later insert or assertion fails.
  t.after(async () => {
    try {
      if (fixture) await cleanupFixture(adminPool, fixture);
    } finally {
      if (appPool) await appPool.end();
      if (maintenancePool) await maintenancePool.end();
      await adminPool.end();
    }
  });

  const adminIdentity = await identity(adminPool);
  assert.notEqual(adminIdentity.session_user, "agentpass_app",
    "admin URL must be able to migrate and seed fixtures");
  assert.notEqual(adminIdentity.current_user, "agentpass_app",
    "admin URL must be able to migrate and seed fixtures");

  const migration = await createMigrationRunner({
    client: adminPool,
    applicationVersion: "human-session-authority-0100-0104-integration"
  }).run();
  assert.equal(migration.currentVersion, POSTGRES_SCHEMA_HEAD.version);

  const roles = await adminPool.query(
    "SELECT rolname FROM pg_roles WHERE rolname IN ('agentpass_app','agentpass_maintenance','agentpass_migrator') ORDER BY rolname"
  );
  assert.deepEqual(roles.rows.map((row) => row.rolname), ["agentpass_app", "agentpass_maintenance", "agentpass_migrator"],
    "live lane requires the production role boundary to exist");

  fixture = createFixture();
  await seedFixture(adminPool, fixture);

  const runAsApp = APP_URL
    ? (callback) => withDirectAppConnection(appPool, callback)
    : (callback) => withSessionAuthorization(adminPool, "agentpass_app", callback);
  const runAsMaintenance = MAINTENANCE_URL
    ? (callback) => withDirectAppConnection(maintenancePool, callback)
    : (callback) => withSessionAuthorization(adminPool, "agentpass_maintenance", callback);

  await runAsMaintenance(async (maintenance) => {
    const maintenanceIdentity = await identity(maintenance);
    if (MAINTENANCE_URL) {
      assert.equal(maintenanceIdentity.session_user, "agentpass_maintenance",
        "MAINTENANCE_DATABASE_URL must connect as agentpass_maintenance");
      assert.equal(maintenanceIdentity.current_user, "agentpass_maintenance",
        "MAINTENANCE_DATABASE_URL must execute as agentpass_maintenance");
    } else {
      assert.equal(maintenanceIdentity.current_user, "agentpass_maintenance");
    }
    const bind = await maintenance.query(
      "SELECT public.agentpass_human_identity_bind($1::text,$2::text,$3::uuid,$4::uuid) AS result",
      ["github", fixture.identitySubject, fixture.memberId, fixture.organizationId]
    );
    assert.equal(bind.rows[0].result, "created", "0105 must bind a new identity through maintenance authority");

    const idempotentBind = await maintenance.query(
      "SELECT public.agentpass_human_identity_bind($1::text,$2::text,$3::uuid,$4::uuid) AS result",
      ["github", fixture.identitySubject, fixture.memberId, fixture.organizationId]
    );
    assert.equal(idempotentBind.rows[0].result, "already_exists",
      "0105 bind must be idempotent for the original member");

    await assertSqlState(
      () => maintenance.query(
        "SELECT public.agentpass_human_identity_bind($1::text,$2::text,$3::uuid,$4::uuid)",
        ["github", fixture.crossOrganizationSubject, fixture.otherMemberId, fixture.organizationId]
      ),
      "23503",
      "0105 bind must reject a member without active membership in the requested organization"
    );

    await assertSqlState(
      () => maintenance.query(
        "SELECT public.agentpass_human_identity_bind($1::text,$2::text,$3::uuid,$4::uuid)",
        ["github", fixture.identitySubject, fixture.otherMemberId, fixture.targetOrganizationId]
      ),
      "42501",
      "0105 bind must reject reassignment of an existing identity"
    );
  });

  await runAsApp(async (app) => {
    const appIdentity = await identity(app);
    if (APP_URL) {
      // This is the production-grade lane: the connection itself authenticates
      // as agentpass_app, rather than borrowing an admin connection.
      assert.equal(appIdentity.session_user, "agentpass_app",
        "APP_DATABASE_URL must connect as agentpass_app");
      assert.equal(appIdentity.current_user, "agentpass_app",
        "APP_DATABASE_URL must execute as agentpass_app");
    } else {
      // SET SESSION AUTHORIZATION proves effective privileges and SECURITY
      // DEFINER execution, but not independent app-login authentication:
      // session_user intentionally remains the admin identity.
      assert.equal(appIdentity.current_user, "agentpass_app");
      assert.notEqual(appIdentity.session_user, "agentpass_app",
        "SET SESSION AUTHORIZATION is not a real app connection");
    }

    for (const signature of AUTHORITY_FUNCTIONS) {
      const privilege = await app.query(
        "SELECT has_function_privilege(current_user,$1,'EXECUTE') AS allowed", [signature]
      );
      assert.equal(privilege.rows[0].allowed, true, "missing EXECUTE privilege for " + signature);
    }

    await assertDirectDmlDenied(app, fixture);

    const resolved = await app.query(
      "SELECT provider, subject, member_id, membership_id, organization_id, role " +
      "FROM public.agentpass_human_identity_resolve($1::text,$2::text,$3::uuid)",
      ["github", fixture.identitySubject, fixture.organizationId]
    );
    assert.equal(resolved.rowCount, 1, "0104 must positively resolve the bound identity");
    assert.equal(resolved.rows[0].member_id, fixture.memberId);
    assert.equal(resolved.rows[0].organization_id, fixture.organizationId);
    assert.equal(resolved.rows[0].role, "admin");

    const crossOrganizationResolve = await app.query(
      "SELECT * FROM public.agentpass_human_identity_resolve($1::text,$2::text,$3::uuid)",
      ["github", fixture.identitySubject, fixture.targetOrganizationId]
    );
    assert.equal(crossOrganizationResolve.rowCount, 0,
      "0104 resolve must not disclose an identity outside the requested organization");

    const switched = await app.query(
      "SELECT public.agentpass_human_session_switch(" +
      "$1::uuid,$2::bytea,$3::uuid,$4::uuid,$5::uuid,$6::uuid,$7::bytea,$8::bytea," +
      "$9::timestamptz,$10::timestamptz,$11::timestamptz,$12::timestamptz," +
      "$13::timestamptz,$14::text) AS session",
      [fixture.oldSessionId, digest("token:old:" + fixture.oldSessionId), fixture.switchedSessionId,
        fixture.memberId, fixture.organizationId, fixture.targetOrganizationId,
        digest("token:switched:" + fixture.switchedSessionId), digest("csrf:switched:" + fixture.switchedSessionId),
        CREATED_AT, EXPIRES_AT, CREATED_AT, EXPIRES_AT, "2026-08-22T00:01:00.000Z", "integration-switch"]
    );
    assert.ok(switched.rows[0].session, "0100 must return a successor session");

    const managed = await app.query(
      "SELECT public.agentpass_human_session_revoke_managed(" +
      "$1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::bigint,$6::timestamptz,$7::text) AS session",
      [fixture.actorSessionId, fixture.targetSessionId, fixture.memberId, fixture.targetOrganizationId,
        1, "2026-08-22T00:02:00.000Z", "integration-managed-revoke"]
    );
    assert.ok(managed.rows[0].session, "0101 must return the revoked target");

    const others = await app.query(
      "SELECT public.agentpass_human_session_revoke_others(" +
      "$1::uuid,$2::uuid,$3::uuid,$4::timestamptz,$5::text) AS sessions",
      [fixture.actorSessionId, fixture.memberId, fixture.targetOrganizationId,
        "2026-08-22T00:03:00.000Z", "integration-other-revoke"]
    );
    assert.ok(Array.isArray(others.rows[0].sessions), "0102 must return a JSON session array");

    const memberRevoke = await app.query(
      "SELECT public.agentpass_human_member_session_revoke(" +
      "$1::uuid,$2::uuid,$3::timestamptz,$4::text) AS result",
      [fixture.memberId, fixture.targetOrganizationId, "2026-08-22T00:04:00.000Z", "integration-member-revoke"]
    );
    assert.ok(memberRevoke.rows[0].result, "0103 must succeed through agentpass_app EXECUTE privilege");
  });

  const state = await adminPool.query(
    "SELECT id, revoked_at, version FROM public.human_sessions " +
    "WHERE id = ANY($1::uuid[]) ORDER BY id",
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

function createFixture() {
  return {
    organizationId: randomUUID(),
    targetOrganizationId: randomUUID(),
    memberId: randomUUID(),
    otherMemberId: randomUUID(),
    oldMembershipId: randomUUID(),
    targetMembershipId: randomUUID(),
    otherMembershipId: randomUUID(),
    oldSessionId: randomUUID(),
    actorSessionId: randomUUID(),
    targetSessionId: randomUUID(),
    otherSessionId: randomUUID(),
    switchedSessionId: randomUUID(),
    challengeId: randomUUID(),
    identitySubject: "0104-" + randomUUID(),
    crossOrganizationSubject: "0104-cross-" + randomUUID(),
    directIdentitySubject: "0104-direct-" + randomUUID()
  };
}

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
    await client.query("SET SESSION AUTHORIZATION " + roleName);
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
  await expectPermissionDenied(() => client.query(
    "SELECT provider,subject,member_id FROM public.upstream_identities WHERE provider='github' AND subject=$1",
    [fixture.identitySubject]
  ));
  await expectPermissionDenied(() => client.query(
    "INSERT INTO public.upstream_identities (provider,subject,member_id) VALUES ('github',$1,$2)",
    [fixture.directIdentitySubject, fixture.memberId]
  ));
  await expectPermissionDenied(() => client.query(
    "DELETE FROM public.upstream_identities WHERE provider='github' AND subject=$1", [fixture.identitySubject]
  ));
  await expectPermissionDenied(() => client.query(
    "UPDATE public.memberships SET role='viewer' WHERE organization_id=$1 AND id=$2",
    [fixture.organizationId, fixture.oldMembershipId]
  ));
  await expectPermissionDenied(() => client.query(
    "UPDATE public.organizations SET name='direct-dml' WHERE id=$1", [fixture.organizationId]
  ));
}

async function expectPermissionDenied(operation) {
  await assert.rejects(operation, (error) => {
    assert.ok(PERMISSION_ERRORS.has(error?.code),
      "expected permission denial, got " + (error?.code ?? "unknown"));
    return true;
  });
}

async function assertSqlState(operation, code, message) {
  await assert.rejects(operation, (error) => {
    assert.equal(error?.code, code, message + "; got " + (error?.code ?? "unknown"));
    return true;
  }, message);
}

async function seedFixture(pool, fixture) {
  await withTransaction(pool, async (client) => {
    await client.query("INSERT INTO public.organizations (id,name) VALUES ($1,$2),($3,$4)", [
      fixture.organizationId, "0100-0104 primary " + fixture.organizationId,
      fixture.targetOrganizationId, "0100-0104 target " + fixture.targetOrganizationId
    ]);
    await client.query("INSERT INTO public.members (id,github_subject,display_name) VALUES ($1,$2,$3),($4,$5,$6)", [
      fixture.memberId, "0100-0104-" + fixture.memberId, "0100-0104 member",
      fixture.otherMemberId, "0100-0104-" + fixture.otherMemberId, "0100-0104 other member"
    ]);
    await client.query(
      "INSERT INTO public.memberships (organization_id,id,member_id,role,status) " +
      "VALUES ($1,$2,$3,'admin','active'),($4,$5,$3,'admin','active'),($6,$7,$8,'admin','active')",
      [fixture.organizationId, fixture.oldMembershipId, fixture.memberId,
        fixture.targetOrganizationId, fixture.targetMembershipId, fixture.targetOrganizationId,
        fixture.otherMembershipId, fixture.otherMemberId]
    );

    await insertSession(client, fixture.oldSessionId, fixture.memberId, fixture.organizationId, fixture.oldMembershipId, "admin", "old");
    await insertSession(client, fixture.actorSessionId, fixture.memberId, fixture.targetOrganizationId, fixture.targetMembershipId, "admin", "actor");
    await insertSession(client, fixture.targetSessionId, fixture.memberId, fixture.targetOrganizationId, fixture.targetMembershipId, "admin", "target");
    await insertSession(client, fixture.otherSessionId, fixture.memberId, fixture.targetOrganizationId, fixture.targetMembershipId, "admin", "other");
    await client.query(
      "INSERT INTO public.webauthn_challenges " +
      "(id,session_id,member_id,organization_id,ceremony,operation,challenge_hash,created_at,expires_at,rp_id,origin,user_verification,status) " +
      "VALUES ($1,$2,$3,$4,'authentication','integration_0104',$5,$6,$7," +
      "'console.agentpass.test','https://console.agentpass.test','required','pending')",
      [fixture.challengeId, fixture.actorSessionId, fixture.memberId, fixture.targetOrganizationId,
        digest("challenge:" + fixture.challengeId), CREATED_AT, EXPIRES_AT]
    );
  });
}

async function insertSession(client, id, memberId, organizationId, membershipId, role, label) {
  await client.query(
    "INSERT INTO public.human_sessions " +
    "(id,member_id,organization_id,membership_id,role,token_hash,csrf_token_hash,created_at,expires_at,last_seen_at,idle_expires_at) " +
    "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$8,$9)",
    [id, memberId, organizationId, membershipId, role,
      digest("token:" + label + ":" + id), digest("csrf:" + label + ":" + id), CREATED_AT, EXPIRES_AT]
  );
}

async function cleanupFixture(pool, fixture) {
  await withTransaction(pool, async (client) => {
    await client.query("DELETE FROM public.webauthn_challenges WHERE id=$1", [fixture.challengeId]);
    await client.query("DELETE FROM public.human_sessions WHERE id = ANY($1::uuid[])", [[
      fixture.oldSessionId, fixture.actorSessionId, fixture.targetSessionId,
      fixture.otherSessionId, fixture.switchedSessionId
    ]]);
    await client.query(
      "DELETE FROM public.upstream_identities WHERE provider='github' AND subject=ANY($1::text[])",
      [[fixture.identitySubject, fixture.crossOrganizationSubject, fixture.directIdentitySubject]]
    );
    await client.query("DELETE FROM public.memberships WHERE id = ANY($1::uuid[])", [[
      fixture.oldMembershipId, fixture.targetMembershipId, fixture.otherMembershipId
    ]]);
    await client.query("DELETE FROM public.members WHERE id = ANY($1::uuid[])", [[
      fixture.memberId, fixture.otherMemberId
    ]]);
    await client.query("DELETE FROM public.organizations WHERE id = ANY($1::uuid[])", [[
      fixture.organizationId, fixture.targetOrganizationId
    ]]);
  });
}

async function withTransaction(pool, callback) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await callback(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release(true);
  }
}

function digest(value) {
  return createHash("sha256").update(value).digest();
}
