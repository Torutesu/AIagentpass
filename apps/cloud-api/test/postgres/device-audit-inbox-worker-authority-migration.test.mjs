import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0084_device_audit_inbox_worker_authority.sql", import.meta.url);

function compact(sql) { return sql.replace(/--[^\n]*/gu, "").replace(/\s+/gu, " ").trim(); }

test("0084 makes inbox worker authority maintenance-only and validates payload identity in SQL", async () => {
  const sql = compact(await readFile(migrationUrl, "utf8"));
  assert.match(sql, /agentpass_canonical_audit_json\(p_payload\)/u);
  assert.match(sql, /p_payload_sha256 IS DISTINCT FROM expected_digest/u);
  assert.match(sql, /p_batch_id IS DISTINCT FROM 'audit-' \|\| expected_digest/u);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON TABLE public\.device_audit_inbox FROM agentpass_app/u);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON FUNCTION public\.agentpass_device_audit_inbox_claim\(bytea,integer,integer\) FROM agentpass_app/u);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_device_audit_inbox_claim\(bytea,integer,integer\) TO agentpass_maintenance/u);
  assert.match(sql, /CREATE OR REPLACE FUNCTION public\.agentpass_device_audit_inbox_health\(\)/u);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_device_audit_inbox_health\(\) TO agentpass_maintenance/u);
});
