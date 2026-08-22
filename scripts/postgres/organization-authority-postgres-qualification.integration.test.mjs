import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createMigrationRunner } from "../../apps/cloud-api/src/postgres/migration-runner.mjs";
import { POSTGRES_SCHEMA_HEAD } from "../../apps/cloud-api/src/postgres/schema-head.mjs";

const ADMIN_DATABASE_URL = process.env.AGENTPASS_TEST_POSTGRES_ADMIN_URL;
const APP_DATABASE_URL = process.env.AGENTPASS_TEST_APP_DATABASE_URL;
const MAINTENANCE_DATABASE_URL = process.env.AGENTPASS_TEST_MAINTENANCE_DATABASE_URL;
const MISSING_CONNECTIONS = [
  ["AGENTPASS_TEST_POSTGRES_ADMIN_URL", ADMIN_DATABASE_URL],
  ["AGENTPASS_TEST_APP_DATABASE_URL", APP_DATABASE_URL],
  ["AGENTPASS_TEST_MAINTENANCE_DATABASE_URL", MAINTENANCE_DATABASE_URL],
].filter(([, value]) => typeof value !== "string" || value.length === 0).map(([name]) => name);
const { Pool } = MISSING_CONNECTIONS.length === 0 ? await import("pg") : { Pool: undefined };

const SQLSTATE_PERMISSION_DENIED = new Set(["42501", "0LP01"]);
const QUALIFICATION_TIMEOUT_MS = 120_000;
const CONCURRENT_MUTATION_TIMEOUT_MS = 10_000;

function id(label) {
  const bytes = crypto.createHash("sha256")
    .update(`organization-authority-postgres-qualification:${process.pid}:${label}`)
    .digest();
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

async function assertIdentity(pool, expectedRole) {
  const result = await pool.query("SELECT session_user, current_user");
  assert.deepEqual(result.rows[0], { session_user: expectedRole, current_user: expectedRole });
}

async function assertTls(pool, connection) {
  const result = await pool.query("SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid()");
  assert.equal(result.rowCount, 1, `${connection} TLS session is observable`);
  assert.equal(result.rows[0].ssl, true, `${connection} PostgreSQL connection must use TLS`);
  assert.match(result.rows[0].version, /^TLSv[0-9.]+$/u, `${connection} TLS version`);
  assert.ok(typeof result.rows[0].cipher === "string" && result.rows[0].cipher.length > 0, `${connection} TLS cipher`);
}

async function expectPermissionDenied(operation) {
  await assert.rejects(operation, (error) => {
    assert.ok(SQLSTATE_PERMISSION_DENIED.has(error?.code), `unexpected denial SQLSTATE: ${error?.code ?? "unknown"}`);
    return true;
  });
}

function savepointName(label) {
  return `organization_authority_${label}_${id(label).replaceAll("-", "")}`;
}

async function inSavepoint(client, operation, label = "probe") {
  const savepoint = savepointName(label);
  await client.query(`SAVEPOINT ${savepoint}`);
  try {
    return await operation();
  } finally {
    await client.query(`ROLLBACK TO SAVEPOINT ${savepoint}`);
    await client.query(`RELEASE SAVEPOINT ${savepoint}`);
  }
}

async function withTimeout(promise, timeoutMs, message) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(message)), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function assertAuthorityCatalog(appPool) {
  const signatures = [
    "public.agentpass_organization_create_with_owner(uuid,uuid,uuid,text,text,text,text,timestamptz)",
    "public.agentpass_organization_rename(uuid,uuid,text,bigint)",
    "public.agentpass_human_membership_role_update(uuid,uuid,uuid,text,bigint,timestamptz)",
    "public.agentpass_human_membership_remove(uuid,uuid,uuid,bigint,timestamptz)",
    "public.agentpass_organization_invitation_create(uuid,uuid,bytea,text,uuid,timestamptz,timestamptz)",
    "public.agentpass_organization_invitation_revoke(uuid,uuid,bigint,timestamptz,uuid,text)",
    "public.agentpass_organization_invitation_reissue(uuid,uuid,bytea,timestamptz,timestamptz,bigint,uuid)",
    "public.agentpass_organization_invitation_accept(uuid,uuid,bytea,uuid,timestamptz)",
    "public.agentpass_organization_invitation_list(uuid,uuid,timestamptz,uuid,integer)",
  ];
  const result = await appPool.query(`
    SELECT p.oid::regprocedure::text AS signature,
           p.prosecdef,
           p.proconfig,
           pg_get_userbyid(p.proowner) AS owner,
           has_function_privilege(current_user, p.oid, 'EXECUTE') AS app_execute
      FROM pg_proc AS p
      JOIN unnest($1::text[]) AS requested(signature)
        ON p.oid = to_regprocedure(requested.signature)
     ORDER BY signature`, [signatures]);
  assert.equal(result.rowCount, signatures.length, "all 0107/0108/0109 authority functions exist");
  for (const row of result.rows) {
    assert.equal(row.prosecdef, true, `${row.signature} SECURITY DEFINER`);
    assert.deepEqual(row.proconfig, ["search_path=pg_catalog, public"], `${row.signature} fixed search_path`);
    assert.equal(row.owner, "agentpass_migrator", `${row.signature} owner`);
    assert.equal(row.app_execute, true, `${row.signature} executable by agentpass_app`);
  }
}

async function assertDirectDmlDenied(appClient, { organizationId, ownerMemberId, membershipId, invitationId }) {
  await inSavepoint(appClient, () => expectPermissionDenied(() => appClient.query(
    "INSERT INTO public.organizations (id, name) VALUES ($1, 'direct DML must be denied')",
    [id("direct-organization")]
  )), "organization-insert");
  await inSavepoint(appClient, () => expectPermissionDenied(() => appClient.query(
    "UPDATE public.organizations SET name = name WHERE id = $1",
    [organizationId]
  )), "organization-update");
  await inSavepoint(appClient, () => expectPermissionDenied(() => appClient.query(
    "DELETE FROM public.organizations WHERE id = $1",
    [organizationId]
  )), "organization-delete");

  await inSavepoint(appClient, () => expectPermissionDenied(() => appClient.query(
    `INSERT INTO public.memberships (organization_id, id, member_id, role, status)
     VALUES ($1, $2, $3, 'viewer', 'active')`,
    [organizationId, membershipId, ownerMemberId]
  )), "membership-insert");
  await inSavepoint(appClient, () => expectPermissionDenied(() => appClient.query(
    "UPDATE public.memberships SET role = role WHERE organization_id = $1 AND member_id = $2",
    [organizationId, ownerMemberId]
  )), "membership-update");
  await inSavepoint(appClient, () => expectPermissionDenied(() => appClient.query(
    "DELETE FROM public.memberships WHERE organization_id = $1 AND member_id = $2",
    [organizationId, ownerMemberId]
  )), "membership-delete");

  const tokenHash = Buffer.alloc(32, 7);
  await inSavepoint(appClient, () => expectPermissionDenied(() => appClient.query(
    `INSERT INTO public.organization_invitations
       (organization_id, id, token_hash, role, created_by, expires_at)
     VALUES ($1, $2, $3, 'viewer', $4, clock_timestamp() + interval '1 hour')`,
    [organizationId, invitationId, tokenHash, ownerMemberId]
  )), "invitation-insert");
  await inSavepoint(appClient, () => expectPermissionDenied(() => appClient.query(
    "UPDATE public.organization_invitations SET role = role WHERE organization_id = $1 AND id = $2",
    [organizationId, invitationId]
  )), "invitation-update");
  await inSavepoint(appClient, () => expectPermissionDenied(() => appClient.query(
    "DELETE FROM public.organization_invitations WHERE organization_id = $1 AND id = $2",
    [organizationId, invitationId]
  )), "invitation-delete");
  await inSavepoint(appClient, () => expectPermissionDenied(() => appClient.query(
    "SELECT token_hash FROM public.organization_invitations WHERE organization_id = $1",
    [organizationId]
  )), "invitation-select");

  const acl = await appClient.query(`
    SELECT relname,
           has_table_privilege(current_user, format('public.%s', relname), 'SELECT') AS can_select,
           has_table_privilege(current_user, format('public.%s', relname), 'INSERT') AS can_insert,
           has_table_privilege(current_user, format('public.%s', relname), 'UPDATE') AS can_update,
           has_table_privilege(current_user, format('public.%s', relname), 'DELETE') AS can_delete
      FROM unnest(ARRAY['organizations','memberships','organization_invitations']::text[]) AS relation(relname)
     ORDER BY relname`);
  assert.deepEqual(acl.rows, [
    { relname: "memberships", can_select: true, can_insert: false, can_update: false, can_delete: false },
    { relname: "organization_invitations", can_select: false, can_insert: false, can_update: false, can_delete: false },
    { relname: "organizations", can_select: true, can_insert: false, can_update: false, can_delete: false },
  ]);
}

async function cleanup(adminPool, { organizationIds, memberIds }) {
  const organizationArray = organizationIds.filter(Boolean);
  const memberArray = memberIds.filter(Boolean);
  const statements = [
    ["DELETE FROM public.idempotency_records WHERE organization_id = ANY($1::uuid[])", [organizationArray]],
    ["DELETE FROM public.outbox_events WHERE organization_id = ANY($1::uuid[])", [organizationArray]],
    ["DELETE FROM public.admin_audit_events WHERE organization_id = ANY($1::uuid[])", [organizationArray]],
    ["DELETE FROM public.control_plane_authority_generations WHERE organization_id = ANY($1::uuid[])", [organizationArray]],
    ["DELETE FROM public.organization_invitations WHERE organization_id = ANY($1::uuid[])", [organizationArray]],
    ["DELETE FROM public.memberships WHERE organization_id = ANY($1::uuid[])", [organizationArray]],
    ["DELETE FROM public.admin_audit_heads WHERE organization_id = ANY($1::uuid[])", [organizationArray]],
    ["DELETE FROM public.organizations WHERE id = ANY($1::uuid[])", [organizationArray]],
    ["DELETE FROM public.members WHERE id = ANY($1::uuid[])", [memberArray]],
  ];
  const cleanupClient = await adminPool.connect();
  let began = false;
  let triggerDisabled = false;
  try {
    await cleanupClient.query("BEGIN");
    began = true;
    // The fixture deliberately exercises the last-owner denial. Administrative
    // teardown must bypass that business invariant only inside this bounded,
    // rollback-safe cleanup transaction, then restore the trigger before the
    // connection is returned to the pool.
    await cleanupClient.query("ALTER TABLE public.memberships DISABLE TRIGGER memberships_protect_last_active_owner");
    triggerDisabled = true;
    for (const [sql, parameters] of statements) await cleanupClient.query(sql, parameters);
    await cleanupClient.query("ALTER TABLE public.memberships ENABLE TRIGGER memberships_protect_last_active_owner");
    triggerDisabled = false;
    await cleanupClient.query("COMMIT");
    began = false;
    const remaining = await adminPool.query(`
      SELECT (SELECT count(*) FROM public.organizations WHERE id = ANY($1::uuid[])) AS organizations,
             (SELECT count(*) FROM public.members WHERE id = ANY($2::uuid[])) AS members,
             (SELECT count(*) FROM public.memberships WHERE organization_id = ANY($1::uuid[])) AS memberships,
             (SELECT count(*) FROM public.organization_invitations WHERE organization_id = ANY($1::uuid[])) AS invitations,
             (SELECT count(*) FROM public.idempotency_records WHERE organization_id = ANY($1::uuid[])) AS idempotency_records,
             (SELECT count(*) FROM public.outbox_events WHERE organization_id = ANY($1::uuid[])) AS outbox_events,
             (SELECT count(*) FROM public.admin_audit_events WHERE organization_id = ANY($1::uuid[])) AS audit_events,
             (SELECT count(*) FROM public.admin_audit_heads WHERE organization_id = ANY($1::uuid[])) AS audit_heads,
             (SELECT count(*) FROM public.control_plane_authority_generations WHERE organization_id = ANY($1::uuid[])) AS authority_generations`,
    [organizationArray, memberArray]);
    assert.deepEqual(remaining.rows[0], {
      organizations: "0", members: "0", memberships: "0", invitations: "0",
      idempotency_records: "0", outbox_events: "0", audit_events: "0", audit_heads: "0", authority_generations: "0",
    }, "organization qualification cleanup left rows behind");
  } finally {
    if (began) await cleanupClient.query("ROLLBACK").catch(() => {});
    if (triggerDisabled) {
      await cleanupClient.query("ALTER TABLE public.memberships ENABLE TRIGGER memberships_protect_last_active_owner").catch(() => {});
    }
    cleanupClient.release(true);
  }
}

test("PostgreSQL 0107/0108/0109 organization authority qualification", {
  skip: MISSING_CONNECTIONS.length === 0
    ? false
    : `set separate PostgreSQL URLs to run this lane; missing ${MISSING_CONNECTIONS.join(", ")}`,
  timeout: QUALIFICATION_TIMEOUT_MS,
}, async () => {
  const adminPool = new Pool({ connectionString: ADMIN_DATABASE_URL, max: 4 });
  const appPool = new Pool({ connectionString: APP_DATABASE_URL, max: 4 });
  const maintenancePool = new Pool({ connectionString: MAINTENANCE_DATABASE_URL, max: 2 });
  const primaryOrganizationId = id("primary-organization");
  const otherOrganizationId = id("other-organization");
  const ownerMemberId = id("owner-member");
  const targetMemberId = id("target-member");
  const otherActorMemberId = id("other-actor-member");
  const acceptingMemberId = id("accepting-member");
  const ownerMembershipId = id("owner-membership");
  const targetMembershipId = id("target-membership");
  const otherMembershipId = id("other-membership");
  const invitationProbeId = id("direct-invitation-probe");
  const primaryInvitationId = id("primary-invitation");
  const acceptingMembershipId = id("accepting-membership");
  const acceptedInvitationId = id("accepted-invitation");
  const ownerPrincipal = `organization-qualification-${ownerMemberId}`;
  let appClient;

  try {
    await assertIdentity(adminPool, process.env.AGENTPASS_TEST_ADMIN_ROLE ?? "postgres");
    await assertIdentity(appPool, "agentpass_app");
    await assertIdentity(maintenancePool, "agentpass_maintenance");
    await assertTls(adminPool, "admin");
    await assertTls(appPool, "app");
    await assertTls(maintenancePool, "maintenance");

    const migrationClient = await adminPool.connect();
    try {
      const migration = await createMigrationRunner({
        client: migrationClient,
        applicationVersion: "organization-authority-postgres-qualification",
      }).run();
      assert.equal(migration.currentVersion, POSTGRES_SCHEMA_HEAD.version);
    } finally {
      migrationClient.release();
    }
    const history = await adminPool.query("SELECT version, checksum FROM public.schema_migrations ORDER BY version");
    assert.deepEqual(history.rows.map((row) => Number(row.version)), POSTGRES_SCHEMA_HEAD.migrations.map(({ version }) => version));
    assert.deepEqual(history.rows.at(-1), {
      version: String(POSTGRES_SCHEMA_HEAD.version),
      checksum: POSTGRES_SCHEMA_HEAD.checksum,
    });

    await adminPool.query(`
      INSERT INTO public.members (id, github_subject, display_name) VALUES
        ($1, $2, 'organization qualification owner'),
        ($3, $4, 'organization qualification target'),
        ($5, $6, 'organization qualification other actor'),
        ($7, $8, 'organization qualification accepting member')`, [
      ownerMemberId, `organization-qualification-owner-${ownerMemberId}`,
      targetMemberId, `organization-qualification-target-${targetMemberId}`,
      otherActorMemberId, `organization-qualification-other-${otherActorMemberId}`,
      acceptingMemberId, `organization-qualification-accepting-${acceptingMemberId}`,
    ]);

    appClient = await appPool.connect();
    await appClient.query("BEGIN");
    await assertAuthorityCatalog(appPool);

    const create = await appClient.query(
      `SELECT * FROM public.agentpass_organization_create_with_owner(
         $1::uuid,$2::uuid,$3::uuid,$4::text,$5::text,$6::text,$7::text,$8::timestamptz
       )`,
      [
        primaryOrganizationId,
        ownerMemberId,
        ownerMembershipId,
        "organization authority qualification",
        ownerPrincipal,
        `qualification-${primaryOrganizationId.slice(0, 8)}`,
        crypto.createHash("sha256").update(primaryOrganizationId).digest("hex"),
        new Date().toISOString(),
      ]
    );
    assert.equal(create.rowCount, 1);
    assert.equal(create.rows[0].outcome, "created");
    assert.equal(create.rows[0].organization_id, primaryOrganizationId);
    assert.equal(create.rows[0].membership_id, ownerMembershipId);
    assert.equal(create.rows[0].role, "owner");
    await appClient.query("COMMIT");

    await adminPool.query(`
      INSERT INTO public.memberships (organization_id, id, member_id, role, status)
      VALUES ($1, $2, $3, 'viewer', 'active')`, [primaryOrganizationId, targetMembershipId, targetMemberId]);
    await adminPool.query(`
      INSERT INTO public.organizations (id, name) VALUES ($1, 'other organization authority fixture')`, [otherOrganizationId]);
    await adminPool.query(`
      INSERT INTO public.memberships (organization_id, id, member_id, role, status)
      VALUES ($1, $2, $3, 'owner', 'active')`, [otherOrganizationId, otherMembershipId, otherActorMemberId]);

    await appClient.query("BEGIN");
    await assertDirectDmlDenied(appClient, {
      organizationId: primaryOrganizationId,
      ownerMemberId,
      membershipId: id("direct-membership-probe"),
      invitationId: invitationProbeId,
    });

    const renamed = await appClient.query(
      "SELECT * FROM public.agentpass_organization_rename($1::uuid,$2::uuid,$3::text,$4::bigint)",
      [primaryOrganizationId, ownerMemberId, "organization authority qualified", 1]
    );
    assert.equal(renamed.rowCount, 1, "owner can rename through 0107 authority");
    assert.equal(renamed.rows[0].version, "2");

    const roleUpdated = await appClient.query(
      "SELECT * FROM public.agentpass_human_membership_role_update($1::uuid,$2::uuid,$3::uuid,$4::text,$5::bigint,$6::timestamptz)",
      [primaryOrganizationId, ownerMemberId, targetMemberId, "admin", 1, new Date().toISOString()]
    );
    assert.equal(roleUpdated.rowCount, 1, "owner can mutate membership through 0108 authority");
    assert.equal(roleUpdated.rows[0].role, "admin");
    assert.equal(roleUpdated.rows[0].version, "2");

    const tokenHash = Buffer.alloc(32, 11);
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    const invitation = await appClient.query(
      "SELECT * FROM public.agentpass_organization_invitation_create($1::uuid,$2::uuid,$3::bytea,$4::text,$5::uuid,$6::timestamptz,$7::timestamptz)",
      [primaryOrganizationId, primaryInvitationId, tokenHash, "viewer", ownerMemberId, new Date().toISOString(), expiresAt]
    );
    assert.equal(invitation.rowCount, 1, "owner can create an invitation through 0109 authority");
    assert.equal(invitation.rows[0].invitation_id, primaryInvitationId);
    assert.equal(invitation.rows[0].version, "1");
    assert.equal(Object.hasOwn(invitation.rows[0], "token_hash"), false);

    const listed = await appClient.query(
      "SELECT * FROM public.agentpass_organization_invitation_list($1::uuid,$2::uuid,$3::timestamptz,$4::uuid,$5::integer)",
      [primaryOrganizationId, ownerMemberId, null, null, 10]
    );
    assert.equal(listed.rowCount, 1, "authorized invitation list returns a projection");
    assert.equal(Object.hasOwn(listed.rows[0], "token_hash"), false, "invitation list projection does not expose token_hash");
    assert.deepEqual(Object.keys(listed.rows[0]).sort(), [
      "accepted_member_id", "consumed_at", "created_at", "created_by", "expires_at",
      "invitation_id", "organization_id", "revoked_at", "role", "version",
    ].sort());

    const reissued = await appClient.query(
      "SELECT * FROM public.agentpass_organization_invitation_reissue($1::uuid,$2::uuid,$3::bytea,$4::timestamptz,$5::timestamptz,$6::bigint,$7::uuid)",
      [primaryOrganizationId, primaryInvitationId, Buffer.alloc(32, 12), new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(), new Date().toISOString(), 1, ownerMemberId]
    );
    assert.equal(reissued.rowCount, 1, "owner can reissue an invitation through 0109 authority");
    assert.equal(reissued.rows[0].version, "2");

    const revoked = await appClient.query(
      "SELECT * FROM public.agentpass_organization_invitation_revoke($1::uuid,$2::uuid,$3::bigint,$4::timestamptz,$5::uuid,$6::text)",
      [primaryOrganizationId, primaryInvitationId, 2, new Date().toISOString(), ownerMemberId, "qualification revoke"]
    );
    assert.equal(revoked.rowCount, 1, "owner can revoke an invitation through 0109 authority");
    assert.equal(revoked.rows[0].version, "3");

    const acceptedTokenHash = Buffer.alloc(32, 13);
    const acceptedInvitation = await appClient.query(
      "SELECT * FROM public.agentpass_organization_invitation_create($1::uuid,$2::uuid,$3::bytea,$4::text,$5::uuid,$6::timestamptz,$7::timestamptz)",
      [primaryOrganizationId, acceptedInvitationId, acceptedTokenHash, "auditor", ownerMemberId, new Date().toISOString(), new Date(Date.now() + 60 * 60 * 1000).toISOString()]
    );
    assert.equal(acceptedInvitation.rowCount, 1);
    const accepted = await appClient.query(
      "SELECT * FROM public.agentpass_organization_invitation_accept($1::uuid,$2::uuid,$3::bytea,$4::uuid,$5::timestamptz)",
      [primaryOrganizationId, acceptingMemberId, acceptedTokenHash, acceptingMembershipId, new Date().toISOString()]
    );
    assert.equal(accepted.rowCount, 1, "invitation accept atomically creates membership and consumes invitation");
    assert.equal(accepted.rows[0].membership_id, acceptingMembershipId);
    assert.equal(accepted.rows[0].invitation_version, "2");

    // Tenant and actor bindings fail closed even though the caller can name a
    // real organization/member pair from another fixture or an unbound member.
    assert.equal((await appClient.query(
      "SELECT * FROM public.agentpass_organization_rename($1::uuid,$2::uuid,$3::text,$4::bigint)",
      [primaryOrganizationId, otherActorMemberId, "cross-tenant rename", 2]
    )).rowCount, 0, "cross-tenant actor cannot rename");
    assert.equal((await appClient.query(
      "SELECT * FROM public.agentpass_organization_rename($1::uuid,$2::uuid,$3::text,$4::bigint)",
      [primaryOrganizationId, acceptingMemberId, "unbound actor rename", 2]
    )).rowCount, 0, "unbound actor cannot rename");
    await inSavepoint(appClient, () => expectPermissionDenied(() => appClient.query(
      "SELECT * FROM public.agentpass_human_membership_role_update($1::uuid,$2::uuid,$3::uuid,$4::text,$5::bigint,$6::timestamptz)",
      [primaryOrganizationId, otherActorMemberId, targetMemberId, "viewer", 2, new Date().toISOString()]
    )), "membership-cross-tenant");
    await inSavepoint(appClient, () => expectPermissionDenied(() => appClient.query(
      "SELECT * FROM public.agentpass_human_membership_role_update($1::uuid,$2::uuid,$3::uuid,$4::text,$5::bigint,$6::timestamptz)",
      [primaryOrganizationId, acceptingMemberId, targetMemberId, "viewer", 2, new Date().toISOString()]
    )), "membership-unbound-actor");

    await inSavepoint(appClient, () => assert.rejects(
      () => appClient.query(
        "SELECT * FROM public.agentpass_human_membership_role_update($1::uuid,$2::uuid,$3::uuid,$4::text,$5::bigint,$6::timestamptz)",
        [primaryOrganizationId, ownerMemberId, targetMemberId, "viewer", 1, new Date().toISOString()]
      ),
      (error) => error?.code === "40001" && error?.constraint === "memberships_version"
    ), "membership-cas");
    assert.equal((await appClient.query(
      "SELECT * FROM public.agentpass_organization_rename($1::uuid,$2::uuid,$3::text,$4::bigint)",
      [primaryOrganizationId, ownerMemberId, "stale rename", 1]
    )).rowCount, 0, "organization rename rejects stale CAS");
    assert.equal((await appClient.query(
      "SELECT * FROM public.agentpass_organization_invitation_revoke($1::uuid,$2::uuid,$3::bigint,$4::timestamptz,$5::uuid,$6::text)",
      [primaryOrganizationId, primaryInvitationId, 2, new Date().toISOString(), ownerMemberId, "stale revoke"]
    )).rowCount, 0, "invitation revoke rejects stale CAS");

    await inSavepoint(appClient, () => assert.rejects(
      () => appClient.query(
        "SELECT * FROM public.agentpass_human_membership_role_update($1::uuid,$2::uuid,$3::uuid,$4::text,$5::bigint,$6::timestamptz)",
        [primaryOrganizationId, ownerMemberId, ownerMemberId, "admin", 1, new Date().toISOString()]
      ),
      (error) => error?.code === "23514" && error?.constraint === "memberships_last_active_owner"
    ), "final-owner-role-change");
    await inSavepoint(appClient, () => assert.rejects(
      () => appClient.query(
        "SELECT * FROM public.agentpass_human_membership_remove($1::uuid,$2::uuid,$3::uuid,$4::bigint,$5::timestamptz)",
        [primaryOrganizationId, ownerMemberId, ownerMemberId, 1, new Date().toISOString()]
      ),
      (error) => error?.code === "23514" && error?.constraint === "memberships_last_active_owner"
    ), "final-owner-remove");

    await appClient.query("COMMIT");

    const raceA = await appPool.connect();
    const raceB = await appPool.connect();
    const race = Promise.all([
      raceA.query("SET statement_timeout = '5000ms'").then(() => raceA.query(
        "SELECT * FROM public.agentpass_organization_rename($1::uuid,$2::uuid,$3::text,$4::bigint)",
        [primaryOrganizationId, ownerMemberId, "serialized rename A", 2]
      )),
      raceB.query("SET statement_timeout = '5000ms'").then(() => raceB.query(
        "SELECT * FROM public.agentpass_organization_rename($1::uuid,$2::uuid,$3::text,$4::bigint)",
        [primaryOrganizationId, ownerMemberId, "serialized rename B", 2]
      )),
    ]);
    let raceResults;
    try {
      raceResults = await withTimeout(race, CONCURRENT_MUTATION_TIMEOUT_MS, "same-organization mutation did not serialize within timeout");
    } catch (error) {
      await race.catch(() => {});
      throw error;
    } finally {
      raceA.release(true);
      raceB.release(true);
    }
    assert.equal(raceResults.filter((result) => result.rowCount === 1).length, 1, "exactly one concurrent same-CAS mutation wins");
    assert.equal(raceResults.filter((result) => result.rowCount === 0).length, 1, "the losing concurrent mutation observes stale CAS");
    const finalOrganization = await appPool.query(
      "SELECT name, version FROM public.organizations WHERE id = $1",
      [primaryOrganizationId],
    );
    assert.deepEqual(finalOrganization.rows, [{
      name: raceResults.find((result) => result.rowCount === 1).rows[0].name,
      version: "3",
    }], "same-CAS race must leave one committed version increment");
  } catch (error) {
    await appClient?.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    appClient?.release(true);
    await cleanup(adminPool, {
      organizationIds: [primaryOrganizationId, otherOrganizationId],
      memberIds: [ownerMemberId, targetMemberId, otherActorMemberId, acceptingMemberId],
    });
    await Promise.all([adminPool.end(), appPool.end(), maintenancePool.end()]);
  }
});
