import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

const migrationUrl = new URL("../../../../contracts/postgres/0137_maintenance_job_result_pr_authority.sql", import.meta.url);

test("0137 provides tenant-bound job/result/PR authority functions without table DML grants", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /CREATE FUNCTION public\.agentpass_reserve_maintenance_job\(p_input jsonb\)[\s\S]*ON CONFLICT \(job_id\) DO UPDATE/u);
  assert.match(sql, /CREATE FUNCTION public\.agentpass_get_maintenance_job\(p_organization_id uuid, p_job_id uuid\)/u);
  assert.match(sql, /CREATE FUNCTION public\.agentpass_update_maintenance_job\(p_organization_id uuid, p_job_id uuid, p_patch jsonb\)/u);
  assert.match(sql, /CREATE FUNCTION public\.agentpass_record_maintenance_result\(p_input jsonb\)/u);
  assert.match(sql, /CREATE FUNCTION public\.agentpass_record_maintenance_pull_request\(p_input jsonb\)/u);
  assert.match(sql, /agentpass_current_organization_id\(\) IS DISTINCT FROM/u);
  assert.match(sql, /REVOKE ALL ON FUNCTION[\s\S]*FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup/u);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION[\s\S]*TO agentpass_maintenance/u);
  assert.doesNotMatch(sql, /GRANT (?:ALL|INSERT|UPDATE|DELETE) ON TABLE public\.maintenance_/u);
});
