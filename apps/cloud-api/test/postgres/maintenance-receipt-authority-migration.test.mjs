import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

test("0138 stores append-only receipts through a tenant-bound function", async () => {
  const sql = await readFile(new URL("../../../../contracts/postgres/0138_maintenance_receipt_authority.sql", import.meta.url), "utf8");
  assert.match(sql, /CREATE FUNCTION public\.agentpass_record_maintenance_receipt\(p_input jsonb\)/u);
  assert.match(sql, /maintenance_current_organization|agentpass_current_organization_id\(\)/u);
  assert.match(sql, /ON CONFLICT \(receipt_digest\) DO NOTHING/u);
  assert.match(sql, /REVOKE ALL ON FUNCTION[\s\S]*FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup/u);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION[\s\S]*TO agentpass_maintenance/u);
});
