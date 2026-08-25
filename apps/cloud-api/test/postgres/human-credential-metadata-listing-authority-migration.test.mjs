import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migration = new URL("../../../../contracts/postgres/0093_human_credential_metadata_listing_authority.sql", import.meta.url);
const repository = new URL("../../src/postgres/human-repository.mjs", import.meta.url);

test("credential metadata listing is safe, session-bound, and keyset paginated", async () => {
  const sql = await readFile(migration, "utf8");
  assert.match(sql, /CREATE FUNCTION public\.agentpass_human_list_credential_metadata_for_session\(/u);
  assert.match(sql, /RETURNS TABLE \([\s\S]*id bytea[\s\S]*version bigint/u);
  assert.match(sql, /LIMIT \(p_limit \+ 1\)/u);
  assert.match(sql, /date_trunc\('milliseconds'/u);
  assert.doesNotMatch(sql, /public_key/u);
  for (const fragment of ["s.member_id = p_member_id", "s.organization_id = p_organization_id", "s.idle_expires_at", "m.role = s.role", "o.authority_epoch = s.organization_authority_epoch", "m.session_epoch = s.membership_session_epoch"]) {
    assert.match(sql, new RegExp(fragment.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
  }
  assert.equal((sql.match(/^SECURITY DEFINER$/gmu) ?? []).length, 1);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_human_list_credential_metadata_for_session/u);
});

test("repository uses metadata listing authority", async () => {
  const source = await readFile(repository, "utf8");
  assert.match(source, /agentpass_human_list_credential_metadata_for_session\(\$1::uuid,\$2::uuid,\$3::uuid/u);
  assert.doesNotMatch(source, /SELECT c\.id,c\.member_id,c\.label,c\.transports,c\.backup_eligible/u);
});
