import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migration = new URL("../../../../contracts/postgres/0090_human_credential_lookup_authority.sql", import.meta.url);
const repository = new URL("../../src/postgres/human-repository.mjs", import.meta.url);

test("credential lookup functions preserve session and clone quarantine boundaries", async () => {
  const sql = await readFile(migration, "utf8");
  assert.match(sql, /CREATE FUNCTION public\.agentpass_human_list_credentials_for_session\(/u);
  assert.match(sql, /CREATE FUNCTION public\.agentpass_human_find_credential_for_session\(/u);
  assert.equal((sql.match(/^SECURITY DEFINER$/gmu) ?? []).length, 2);
  assert.equal((sql.match(/SET search_path = pg_catalog, public/g) ?? []).length, 2);
  for (const fragment of [
    "s.organization_id = p_organization_id",
    "s.revoked_at IS NULL",
    "m.status = 'active'",
    "m.role = s.role",
    "o.authority_epoch = s.organization_authority_epoch",
    "m.session_epoch = s.membership_session_epoch",
    "c.revoked_at IS NULL",
    "c.clone_detected_at IS NULL",
    "c.sign_count_state <> 'clone-detected'",
  ]) assert.match(sql, new RegExp(fragment.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
  assert.match(sql, /RETURNS TABLE \(\s*id bytea,\s*transports text\[\]/u);
  assert.match(sql, /public_key bytea,\s*sign_count bigint/u);
});

test("repository routes credential list and verifier lookup through reviewed functions", async () => {
  const source = await readFile(repository, "utf8");
  assert.match(source, /agentpass_human_list_credentials_for_session\(\$1::uuid,\$2::uuid\)/u);
  assert.match(source, /agentpass_human_find_credential_for_session\(\$1::uuid,\$2::uuid,\$3::bytea\)/u);
});
