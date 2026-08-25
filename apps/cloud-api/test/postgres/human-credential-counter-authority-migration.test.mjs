import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migration = new URL("../../../../contracts/postgres/0091_human_credential_counter_authority.sql", import.meta.url);
const repository = new URL("../../src/postgres/human-repository.mjs", import.meta.url);

test("credential counter authority preserves CAS, backup, clone, and session boundaries", async () => {
  const sql = await readFile(migration, "utf8");
  assert.match(sql, /CREATE FUNCTION public\.agentpass_human_update_credential_counter\(/u);
  assert.match(sql, /CREATE FUNCTION public\.agentpass_human_quarantine_credential_clone\(/u);
  assert.equal((sql.match(/^SECURITY DEFINER$/gmu) ?? []).length, 2);
  assert.equal((sql.match(/SET search_path = pg_catalog, public/g) ?? []).length, 2);
  for (const fragment of [
    "c.sign_count = p_expected_sign_count",
    "p_sign_count > p_expected_sign_count",
    "p_backup_state IS TRUE",
    "p_expected_backup_state IS TRUE",
    "c.clone_detected_at IS NULL",
    "c.sign_count_state <> 'clone-detected'",
    "p_observed_sign_count > p_expected_sign_count",
    "c.sign_count >= p_expected_sign_count",
    "s.revoked_at IS NULL",
    "m.status = 'active'",
    "m.role = s.role",
    "o.authority_epoch = s.organization_authority_epoch",
    "m.session_epoch = s.membership_session_epoch",
  ]) assert.match(sql, new RegExp(fragment.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
  assert.match(sql, /RETURNS TABLE\(id bytea, member_id uuid, clone_detected_at timestamptz\)/u);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_human_update_credential_counter/u);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_human_quarantine_credential_clone/u);
});

test("repository routes counter and clone transitions through reviewed functions", async () => {
  const source = await readFile(repository, "utf8");
  assert.match(source, /agentpass_human_update_credential_counter\(\$1::uuid,\$2::uuid,\$3::bytea,\$4::bigint,\$5::bigint/u);
  assert.match(source, /agentpass_human_quarantine_credential_clone\(\$1::uuid,\$2::uuid,\$3::bytea,\$4::bigint,\$5::bigint\)/u);
  assert.match(source, /clone_detected_at/u);
});
