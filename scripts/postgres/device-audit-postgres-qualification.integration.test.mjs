import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createMigrationRunner } from "../../apps/cloud-api/src/postgres/migration-runner.mjs";
import { POSTGRES_SCHEMA_HEAD } from "../../apps/cloud-api/src/postgres/schema-head.mjs";

const ADMIN_DATABASE_URL = process.env.AGENTPASS_TEST_POSTGRES_ADMIN_URL ?? process.env.AGENTPASS_TEST_DATABASE_URL;
const APP_DATABASE_URL = process.env.AGENTPASS_TEST_APP_DATABASE_URL;
const { Pool } = ADMIN_DATABASE_URL && APP_DATABASE_URL ? await import("pg") : { Pool: undefined };
const SQLSTATE_PERMISSION_DENIED = new Set(["42501", "0LP01"]);

function id(label) {
  const bytes = crypto.createHash("sha256").update(`device-audit-qualification:${process.pid}:${label}`).digest();
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

async function assertIdentity(pool, expectedRole) {
  const result = await pool.query("SELECT session_user, current_user");
  assert.deepEqual(result.rows[0], { session_user: expectedRole, current_user: expectedRole });
  return result.rows[0];
}

async function expectPermissionDenied(operation) {
  await assert.rejects(operation, (error) => {
    assert.ok(SQLSTATE_PERMISSION_DENIED.has(error?.code), `unexpected denial SQLSTATE: ${error?.code ?? "unknown"}`);
    return true;
  });
}

async function inSavepoint(client, operation) {
  const savepoint = `p2_probe_${id("savepoint").replaceAll("-", "")}`;
  await client.query(`SAVEPOINT ${savepoint}`);
  try {
    return await operation();
  } finally {
    await client.query(`ROLLBACK TO SAVEPOINT ${savepoint}`);
    await client.query(`RELEASE SAVEPOINT ${savepoint}`);
  }
}

test("P2 PostgreSQL device-audit qualification uses the application role for security probes", {
  skip: ADMIN_DATABASE_URL && APP_DATABASE_URL
    ? false
    : "set AGENTPASS_TEST_POSTGRES_ADMIN_URL (or AGENTPASS_TEST_DATABASE_URL) and AGENTPASS_TEST_APP_DATABASE_URL to run the P2 PostgreSQL lane",
  timeout: 120_000,
}, async (t) => {
  const adminPool = new Pool({ connectionString: ADMIN_DATABASE_URL, max: 4 });
  const appPool = new Pool({ connectionString: APP_DATABASE_URL, max: 4 });
  const organizationId = id("organization");
  const otherOrganizationId = id("other-organization");
  const deviceId = id("device");
  const otherDeviceId = id("other-device");
  const agentId = id("agent");
  const otherAgentId = id("other-agent");
  try {
    // The administrator identity is limited to schema migration and fixture
    // setup. All online authorization, DML, RLS, and trigger probes below use
    // the separately authenticated application identity.
    await assertIdentity(adminPool, process.env.AGENTPASS_TEST_ADMIN_ROLE ?? "postgres");
    await assertIdentity(appPool, "agentpass_app");

    const migrationClient = await adminPool.connect();
    try {
      const migration = await createMigrationRunner({ client: migrationClient, applicationVersion: "device-audit-postgres-qualification" }).run();
      assert.equal(migration.currentVersion, POSTGRES_SCHEMA_HEAD.version);
    } finally {
      migrationClient.release();
    }

    await adminPool.query(`
      INSERT INTO organizations (id, name) VALUES
        ($1, $3),
        ($2, $4)`, [organizationId, otherOrganizationId, `audit qualification ${organizationId.slice(0, 8)}`, `other audit qualification ${otherOrganizationId.slice(0, 8)}`]);
    await adminPool.query(`
      INSERT INTO devices (organization_id, id, label, key_algorithm, public_key_pem, status) VALUES
        ($1, $2, 'qualification device', 'ed25519', $3, 'active'),
        ($4, $5, 'other qualification device', 'ed25519', $6, 'active')`, [
      organizationId, deviceId, "-----BEGIN PUBLIC KEY-----\nqualification\n-----END PUBLIC KEY-----",
      otherOrganizationId, otherDeviceId, "-----BEGIN PUBLIC KEY-----\nother-qualification\n-----END PUBLIC KEY-----"
    ]);
    await adminPool.query(`
      INSERT INTO agents (organization_id, id, device_id, kind, name, public_key_pem, status) VALUES
        ($1, $2, $3, 'cli', 'qualification agent', $4, 'active'),
        ($5, $6, $7, 'cli', 'other qualification agent', $8, 'active')`, [
      organizationId, agentId, deviceId, "-----BEGIN PUBLIC KEY-----\nqualification-agent\n-----END PUBLIC KEY-----",
      otherOrganizationId, otherAgentId, otherDeviceId, "-----BEGIN PUBLIC KEY-----\nother-qualification-agent\n-----END PUBLIC KEY-----"
    ]);

    const appClient = await appPool.connect();
    try {
      await assertIdentity(appClient, "agentpass_app");
      await appClient.query("BEGIN");
      await appClient.query("SELECT set_config('agentpass.organization_id', $1, true)", [organizationId]);

      // Query effective privileges and trigger ownership from the online
      // connection itself. An administrator must not be able to mask an ACL
      // or RLS defect in the security-sensitive path.
      const catalog = await appClient.query(`
      SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
             has_table_privilege(current_user, c.oid, 'SELECT') AS app_select,
             has_table_privilege(current_user, c.oid, 'INSERT') AS app_insert,
             has_table_privilege(current_user, c.oid, 'UPDATE') AS app_update,
             has_table_privilege(current_user, c.oid, 'DELETE') AS app_delete,
             p.prosecdef, p.proconfig,
             p.proowner = (SELECT oid FROM pg_roles WHERE rolname = 'agentpass_migrator') AS trigger_owner,
             NOT has_function_privilege(current_user, p.oid, 'EXECUTE') AS app_cannot_execute_trigger
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
      CROSS JOIN LATERAL (SELECT oid, prosecdef, proconfig, proowner
                          FROM pg_proc WHERE oid = to_regprocedure('public.agentpass_record_device_audit_head()')) p
      WHERE c.relname = ANY($1::text[])
      ORDER BY c.relname`, [["device_audit_events", "device_audit_heads", "device_audit_gaps"]]);
      assert.equal(catalog.rows.length, 3);
      for (const row of catalog.rows) {
        assert.equal(row.relrowsecurity, true, `${row.relname} RLS`);
        assert.equal(row.relforcerowsecurity, true, `${row.relname} FORCE RLS`);
        assert.equal(row.app_select, true, `${row.relname} app SELECT`);
        assert.equal(row.app_insert, row.relname === "device_audit_events", `${row.relname} app INSERT`);
        assert.equal(row.app_update, false, `${row.relname} app UPDATE`);
        assert.equal(row.app_delete, false, `${row.relname} app DELETE`);
        assert.equal(row.prosecdef, true);
        assert.deepEqual(row.proconfig, ["search_path=pg_catalog, public"]);
        assert.equal(row.trigger_owner, true);
        assert.equal(row.app_cannot_execute_trigger, true);
      }

      const event = (label, previousHash) => {
        const eventId = id(label);
        const evidence = { agent_id: agentId, event_id: eventId, previous_hash: previousHash };
        const eventHash = crypto.createHash("sha256").update(JSON.stringify(evidence)).digest("hex");
        return [organizationId, deviceId, eventId, previousHash, eventHash, { ...evidence, event_hash: eventHash }];
      };
      const insertEvent = (values) => appClient.query(`
        INSERT INTO device_audit_events
          (organization_id, device_id, event_id, previous_hash, event_hash, redacted_json)
        VALUES ($1, $2, $3, $4, $5, $6::jsonb)`, values);
      await Promise.all([
        insertEvent(event("one", "0".repeat(64))),
        insertEvent(event("two", "0".repeat(64))),
      ]);
      const head = await appClient.query("SELECT sequence, gap_count, chain_status FROM device_audit_heads WHERE organization_id=$1 AND device_id=$2", [organizationId, deviceId]);
      assert.deepEqual(head.rows, [{ sequence: "2", gap_count: "1", chain_status: "gap" }]);

      // The application connection cannot update or delete the trigger-owned
      // projections, even when the request is scoped to its own tenant.
      await inSavepoint(appClient, () => expectPermissionDenied(() => appClient.query(
        "UPDATE public.device_audit_heads SET sequence=sequence WHERE organization_id=$1 AND device_id=$2",
        [organizationId, deviceId]
      )));
      await inSavepoint(appClient, () => expectPermissionDenied(() => appClient.query(
        "DELETE FROM public.device_audit_gaps WHERE organization_id=$1 AND device_id=$2",
        [organizationId, deviceId]
      )));

      // A tenant switch on the same authenticated app session cannot expose
      // evidence belonging to another organization.
      await appClient.query("SELECT set_config('agentpass.organization_id', $1, true)", [otherOrganizationId]);
      assert.equal((await appClient.query("SELECT count(*)::int AS count FROM device_audit_events")).rows[0].count, 0);
      await appClient.query("SELECT set_config('agentpass.organization_id', $1, true)", [organizationId]);
      assert.equal((await appClient.query("SELECT count(*)::int AS count FROM device_audit_events")).rows[0].count, 2);

      // Bypass the repository and prove the migration-owned validation trigger
      // rejects a forged stored hash before it can advance any projection.
      const forgedEventId = id("forged-event");
      await inSavepoint(appClient, () => assert.rejects(
        () => appClient.query(`INSERT INTO public.device_audit_events
        (organization_id,device_id,event_id,previous_hash,event_hash,redacted_json,received_at)
        VALUES ($1,$2,$3,$4,$5,$6::jsonb)`, [
          organizationId, deviceId, forgedEventId, "0".repeat(64), "0".repeat(64),
          { agent_id: agentId, event_id: forgedEventId, previous_hash: "0".repeat(64), event_hash: "0".repeat(64) }
        ]),
        (error) => error?.code === "23514"
      ));
      assert.equal((await appClient.query(
        "SELECT count(*)::int AS count FROM device_audit_events WHERE organization_id=$1 AND event_id=$2",
        [organizationId, forgedEventId]
      )).rows[0].count, 0);
      await appClient.query("ROLLBACK");
    } catch (error) {
      await appClient.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      appClient.release(true);
    }
  } finally {
    // Fixture teardown is administrative cleanup after the app transaction
    // has rolled back all security-sensitive writes.
    await adminPool.query("DELETE FROM agents WHERE organization_id = ANY($1::uuid[])", [[organizationId, otherOrganizationId]]).catch(() => {});
    await adminPool.query("DELETE FROM devices WHERE organization_id = ANY($1::uuid[])", [[organizationId, otherOrganizationId]]).catch(() => {});
    await adminPool.query("DELETE FROM organizations WHERE id = ANY($1::uuid[])", [[organizationId, otherOrganizationId]]).catch(() => {});
    await Promise.all([adminPool.end(), appPool.end()]);
  }
});

test("P2 tenant RLS remains fail-closed without application tenant context", {
  skip: APP_DATABASE_URL ? false : "set AGENTPASS_TEST_APP_DATABASE_URL to run the P2 RLS negative case",
}, async () => {
  const pool = new Pool({ connectionString: APP_DATABASE_URL, max: 2 });
  try {
    await assertIdentity(pool, "agentpass_app");
    await pool.query("RESET agentpass.organization_id");
    const result = await pool.query("SELECT count(*)::int AS count FROM device_audit_events");
    assert.equal(result.rows[0].count, 0);
  } finally {
    await pool.end();
  }
});
