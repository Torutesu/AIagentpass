import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createMigrationRunner } from "../../apps/cloud-api/src/postgres/migration-runner.mjs";
import { POSTGRES_SCHEMA_HEAD } from "../../apps/cloud-api/src/postgres/schema-head.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL;
const APP_DATABASE_URL = process.env.AGENTPASS_TEST_APP_DATABASE_URL;
const { Pool } = DATABASE_URL ? await import("pg") : { Pool: undefined };

function id(label) {
  const bytes = crypto.createHash("sha256").update(`device-audit-qualification:${process.pid}:${label}`).digest();
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

test("PostgreSQL device-audit qualification is guarded by AGENTPASS_TEST_DATABASE_URL", { skip: !DATABASE_URL }, async () => {
  const pool = new Pool({ connectionString: DATABASE_URL, max: 8 });
  const organizationId = id("organization");
  const deviceId = id("device");
  const agentId = id("agent");
  try {
    const migrationClient = await pool.connect();
    try {
      const migration = await createMigrationRunner({ client: migrationClient, applicationVersion: "device-audit-postgres-qualification" }).run();
      assert.equal(migration.currentVersion, POSTGRES_SCHEMA_HEAD.version);
    } finally {
      migrationClient.release();
    }

    const catalog = await pool.query(`
      SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
             has_table_privilege('agentpass_app', c.oid, 'SELECT') AS app_select,
             has_table_privilege('agentpass_app', c.oid, 'INSERT') AS app_insert,
             has_table_privilege('agentpass_app', c.oid, 'UPDATE') AS app_update,
             has_table_privilege('agentpass_app', c.oid, 'DELETE') AS app_delete,
             p.prosecdef, p.proconfig,
             p.proowner = (SELECT oid FROM pg_roles WHERE rolname = 'agentpass_migrator') AS trigger_owner,
             NOT has_function_privilege('agentpass_app', p.oid, 'EXECUTE') AS app_cannot_execute_trigger
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

    await pool.query("INSERT INTO organizations (id, name) VALUES ($1, $2)", [organizationId, `audit qualification ${organizationId.slice(0, 8)}`]);
    await pool.query("INSERT INTO devices (organization_id, id, label, key_algorithm, public_key_pem, status) VALUES ($1, $2, 'qualification device', 'ed25519', $3, 'active')", [organizationId, deviceId, "-----BEGIN PUBLIC KEY-----\nqualification\n-----END PUBLIC KEY-----"]);
    await pool.query("INSERT INTO agents (organization_id, id, device_id, kind, name, public_key_pem, status) VALUES ($1, $2, $3, 'cli', 'qualification agent', $4, 'active')", [organizationId, agentId, deviceId, "-----BEGIN PUBLIC KEY-----\nqualification-agent\n-----END PUBLIC KEY-----"]);
    const event = (label, previousHash) => [organizationId, deviceId, agentId, id(label), previousHash];
    const insertEvent = (values) => pool.query(`
      WITH base AS (
        SELECT jsonb_build_object('agent_id', $3::text, 'event_id', $4::text, 'previous_hash', $5::text) AS evidence
      ), hashed AS (
        SELECT evidence, encode(digest(convert_to(public.agentpass_canonical_audit_json(evidence), 'UTF8'), 'sha256'), 'hex') AS event_hash
        FROM base
      )
      INSERT INTO device_audit_events (organization_id, device_id, event_id, previous_hash, event_hash, redacted_json)
      SELECT $1, $2, $4, $5, event_hash, jsonb_set(evidence, '{event_hash}', to_jsonb(event_hash), true)
      FROM hashed`, values);
    await Promise.all([
      insertEvent(event("one", "0".repeat(64))),
      insertEvent(event("two", "0".repeat(64))),
    ]);
    const head = await pool.query("SELECT sequence, gap_count, chain_status FROM device_audit_heads WHERE organization_id=$1 AND device_id=$2", [organizationId, deviceId]);
    assert.deepEqual(head.rows, [{ sequence: "2", gap_count: "1", chain_status: "gap" }]);
  } finally {
    await pool.query("DELETE FROM organizations WHERE id = $1", [organizationId]).catch(() => {});
    await pool.end();
  }
});

test("tenant RLS behavior requires a separately authenticated application connection", { skip: !DATABASE_URL || !APP_DATABASE_URL }, async () => {
  const pool = new Pool({ connectionString: APP_DATABASE_URL, max: 2 });
  try {
    await pool.query("SELECT set_config('agentpass.organization_id', $1, false)", [id("tenant-a")]);
    const result = await pool.query("SELECT count(*)::int AS count FROM device_audit_events");
    assert.equal(result.rows[0].count, 0);
  } finally {
    await pool.end();
  }
});
