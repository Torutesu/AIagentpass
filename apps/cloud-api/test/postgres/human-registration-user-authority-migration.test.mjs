import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migration = new URL("../../../../contracts/postgres/0095_human_registration_user_authority.sql", import.meta.url);
const repository = new URL("../../src/postgres/human-repository.mjs", import.meta.url);

test("registration user authority binds live session lifetime and epochs", async () => {
  const sql = await readFile(migration, "utf8");
  assert.match(sql, /CREATE FUNCTION public\.agentpass_human_get_registration_user\(/u);
  assert.equal((sql.match(/^SECURITY DEFINER$/gmu) ?? []).length, 1);
  assert.match(sql, /s\.member_id = p_member_id/u);
  assert.match(sql, /s\.organization_id = p_organization_id/u);
  assert.match(sql, /s\.idle_expires_at/u);
  assert.match(sql, /m\.role = s\.role/u);
  assert.match(sql, /o\.authority_epoch = s\.organization_authority_epoch/u);
  assert.match(sql, /m\.session_epoch = s\.membership_session_epoch/u);
  assert.doesNotMatch(sql, /token_hash|csrf_token_hash|public_key/u);
});

test("repository routes registration user lookup through authority", async () => {
  const source = await readFile(repository, "utf8");
  assert.match(source, /agentpass_human_get_registration_user\(\$1::uuid,\$2::uuid,\$3::uuid\)/u);
});
