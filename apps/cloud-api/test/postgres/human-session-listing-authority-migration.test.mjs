import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migration = new URL("../../../../contracts/postgres/0089_human_session_listing_authority.sql", import.meta.url);
const repository = new URL("../../src/postgres/human-repository.mjs", import.meta.url);

test("session listing functions expose separate safe projections", async () => {
  const sql = await readFile(migration, "utf8");
  assert.match(sql, /CREATE FUNCTION public\.agentpass_human_session_list\(/u);
  assert.match(sql, /CREATE FUNCTION public\.agentpass_human_session_list_safe\(/u);
  assert.equal((sql.match(/^SECURITY DEFINER$/gmu) ?? []).length, 2);
  assert.equal((sql.match(/SET search_path = pg_catalog, public/g) ?? []).length, 2);
  assert.match(sql, /LIMIT 100/u);
  assert.match(sql, /LIMIT \(p_limit \+ 1\)/u);
  assert.match(sql, /date_trunc\('milliseconds', s\.created_at\), s\.id/u);
  assert.match(sql, /m\.status = 'active'/u);
  assert.match(sql, /o\.authority_epoch = s\.organization_authority_epoch/u);
  assert.doesNotMatch(sql, /'token_hash'|'csrf_token_hash'|s\.\*/u);
});

test("repository routes both listing methods through the reviewed functions", async () => {
  const source = await readFile(repository, "utf8");
  assert.match(source, /agentpass_human_session_list\(\$1::uuid\)/u);
  assert.match(source, /agentpass_human_session_list_safe\(\$1::uuid,\$2::uuid,\$3::timestamptz,\$4::uuid,\$5::integer\)/u);
});
