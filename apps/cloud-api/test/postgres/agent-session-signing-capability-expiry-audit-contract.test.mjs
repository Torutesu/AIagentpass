import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL(
  "../../../../contracts/postgres/0075_agent_session_signing_capability_expiry_audit.sql",
  import.meta.url,
);

async function migration() {
  return readFile(migrationUrl, "utf8");
}

function functionBody(sql, name) {
  const start = sql.search(new RegExp(`CREATE (?:OR REPLACE )?FUNCTION public\\.${name}\\(`, "u"));
  assert.notEqual(start, -1, `missing function ${name}`);
  const bodyStart = sql.indexOf("AS $$", start);
  const bodyEnd = sql.indexOf("$$;", bodyStart);
  assert.ok(bodyStart > start && bodyEnd > bodyStart, `unterminated function ${name}`);
  return sql.slice(start, bodyEnd + 3);
}

test("0075 is forward-only, tenant-qualified, append-only, and secret-free", async () => {
  const sql = await migration();
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.doesNotMatch(sql, /\b(?:DROP|TRUNCATE)\s+(?:TABLE|COLUMN|INDEX|FUNCTION)/iu);
  assert.match(sql, /CREATE TABLE public\.agent_session_signing_capability_expiry_audit_events/u);
  assert.match(sql, /CREATE TABLE public\.agent_session_signing_capability_expiry_audit_heads/u);
  assert.match(sql, /UNIQUE \(organization_id, reservation_id\)/u);
  assert.match(sql, /FOREIGN KEY \(organization_id, reservation_id\)[\s\S]*agent_session_signing_capability_reservations/u);
  assert.match(sql, /sha256\(convert_to\(/u);
  assert.match(sql, /previous_event_hash bytea/u);
  assert.match(sql, /event_hash bytea/u);
  assert.match(sql, /transition_expires_at <= capability_expires_at/u);
  assert.match(sql, /observed_at >= transition_expires_at/u);
  assert.match(sql, /date_trunc\('milliseconds', observed_at\) = observed_at/u);
  assert.match(sql, /BEFORE UPDATE OR DELETE ON public\.agent_session_signing_capability_expiry_audit_events/u);
  assert.match(sql, /BEFORE UPDATE OR DELETE ON public\.agent_session_signing_capability_expiry_audit_heads/u);
  assert.match(sql, /ENABLE ROW LEVEL SECURITY/u);
  assert.match(sql, /FORCE ROW LEVEL SECURITY/u);
  assert.match(sql, /organization_id = public\.agentpass_current_organization_id\(\)/u);
  assert.match(sql, /cap_expiry_events_backup_select[\s\S]*FOR SELECT TO agentpass_backup[\s\S]*USING \(true\)/u);
  assert.match(sql, /cap_expiry_heads_backup_select[\s\S]*FOR SELECT TO agentpass_backup[\s\S]*USING \(true\)/u);
  for (const [, policyName] of sql.matchAll(/CREATE POLICY ([a-z0-9_]+)/gu)) {
    assert.ok(Buffer.byteLength(policyName, "utf8") <= 63, `${policyName} exceeds PostgreSQL's identifier limit`);
  }
  const auditSection = sql.slice(0, sql.indexOf("CREATE OR REPLACE FUNCTION public.agentpass_agent_signing_capability_reserve"));
  assert.doesNotMatch(auditSection, /\b(?:member_id|claim_token|scope_json|response_json|provider_request|signature)\b/iu);
  assert.match(auditSection, /does not require a Human member actor/iu);
});

test("0075 records each expiry transition at its locked state boundary", async () => {
  const sql = await migration();
  const reserve = functionBody(sql, "agentpass_agent_signing_capability_reserve");
  const replay = functionBody(sql, "agentpass_agent_signing_capability_replay");
  const maintenance = functionBody(sql, "agentpass_agent_signing_capability_recover_expired");
  const append = "agentpass_append_agent_session_signing_capability_expiry_audit";

  assert.match(reserve, new RegExp(`state = 'reserved'[\\s\\S]*claim_expires_at[\\s\\S]*PERFORM public\\.${append}[\\s\\S]*'reserve'`, "u"));
  assert.match(replay, new RegExp(`state = 'completed'[\\s\\S]*expires_at[\\s\\S]*UPDATE public\\.agent_session_signing_capability_reservations[\\s\\S]*PERFORM public\\.${append}[\\s\\S]*'completed', 'expired', 'replay'`, "u"));
  assert.match(maintenance, new RegExp(`state = 'completed'[\\s\\S]*SET state = 'expired'[\\s\\S]*PERFORM public\\.${append}[\\s\\S]*'maintenance'`, "u"));
  assert.match(maintenance, new RegExp(`state = 'reserved'[\\s\\S]*claim_expires_at[\\s\\S]*SET state = 'outcome_unknown'[\\s\\S]*PERFORM public\\.${append}[\\s\\S]*'maintenance'`, "u"));
  assert.match(sql, /UNIQUE \(organization_id, reservation_id\)/u);
  assert.match(sql, /FOR UPDATE SKIP LOCKED LIMIT p_batch_size/u);
  assert.match(sql, /WHERE r\.organization_id = p_organization_id AND r\.request_id = p_request_id FOR UPDATE/u);
  assert.match(sql, /WHERE r\.organization_id = p_organization_id AND r\.request_id = p_request_id FOR UPDATE/u);
});

test("0075 keeps the audit append helper internal and uses the existing role boundary", async () => {
  const sql = await migration();
  const append = functionBody(sql, "agentpass_append_agent_session_signing_capability_expiry_audit");
  assert.match(append, /SECURITY DEFINER/u);
  assert.match(append, /SET search_path = pg_catalog, public/u);
  assert.match(append, /FOR UPDATE/u);
  assert.match(append, /INSERT INTO public\.agent_session_signing_capability_expiry_audit_events/u);
  assert.match(append, /p_cause NOT IN \('maintenance', 'reserve', 'replay'\)/u);
  assert.match(sql, /REVOKE ALL ON TABLE public\.agent_session_signing_capability_expiry_audit_events,[\s\S]*FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_maintenance/u);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_append_agent_session_signing_capability_expiry_audit/u);
});

test("0075 applies beneath the current schema head when PostgreSQL qualification is configured", {
  skip: process.env.AGENTPASS_TEST_DATABASE_URL || process.env.AGENTPASS_TEST_POSTGRES_URL ? false : "set AGENTPASS_TEST_DATABASE_URL to run PostgreSQL qualification",
  timeout: 120_000
}, async (t) => {
  const { Pool } = await import("pg");
  const { POSTGRES_SCHEMA_HEAD } = await import("../../src/postgres/schema-head.mjs");
  const { createMigrationRunner } = await import("../../src/postgres/migration-runner.mjs");
  const pool = new Pool({ connectionString: process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL, max: 2 });
  const client = await pool.connect();
  t.after(async () => { client.release(true); await pool.end(); });
  const result = await createMigrationRunner({ client, applicationVersion: "agent-session-signing-capability-expiry-audit-contract" }).run();
  assert.equal(POSTGRES_SCHEMA_HEAD.version, 76);
  assert.equal(result.currentVersion, 76);
  const relations = await client.query(`
    SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
      FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relname = ANY($1::text[])
     ORDER BY c.relname`, [[
    "agent_session_signing_capability_expiry_audit_events",
    "agent_session_signing_capability_expiry_audit_heads"
  ]]);
  assert.equal(relations.rowCount, 2);
  assert.ok(relations.rows.every((row) => row.relrowsecurity && row.relforcerowsecurity));
});
