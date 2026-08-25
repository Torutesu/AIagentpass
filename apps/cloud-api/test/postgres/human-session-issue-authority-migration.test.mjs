import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migration = new URL("../../../../contracts/postgres/0087_human_session_issue_authority.sql", import.meta.url);
const repository = new URL("../../src/postgres/human-repository.mjs", import.meta.url);
const roles = new URL("../../../../scripts/postgres/roles.sql", import.meta.url);

test("human session issue authority has separate bounded and ceiling functions", async () => {
  const sql = await readFile(migration, "utf8");
  for (const name of [
    "agentpass_human_session_create",
    "agentpass_human_session_reduce_to_ceiling",
    "agentpass_human_session_create_with_ceiling",
  ]) assert.match(sql, new RegExp(`CREATE FUNCTION public\\.${name}\\(`, "u"));
  assert.equal((sql.match(/^SECURITY DEFINER$/gmu) ?? []).length, 3);
  assert.equal((sql.match(/SET search_path = pg_catalog, public/g) ?? []).length, 3);
  assert.match(sql, /hashtextextended\('agentpass:human:sessions:'/u);
  assert.match(sql, /o\.authority_epoch/u);
  assert.match(sql, /m\.session_epoch/u);
  assert.match(sql, /position >= p_max_concurrent_sessions/u);
  assert.match(sql, /GET DIAGNOSTICS reduced_count = ROW_COUNT/u);
});

test("repository calls the 11-argument or 14-argument issue function explicitly", async () => {
  const [source, roleSql] = await Promise.all([readFile(repository, "utf8"), readFile(roles, "utf8")]);
  assert.match(source, /agentpass_human_session_create\(\$1::uuid,\$2::uuid,\$3::uuid,\$4::uuid,\$5::text,\$6::bytea,\$7::bytea,\$8::timestamptz,\$9::timestamptz,\$10::timestamptz,\$11::timestamptz\)/u);
  assert.match(source, /agentpass_human_session_create_with_ceiling\(\$1::uuid,\$2::uuid,\$3::uuid,\$4::uuid,\$5::text,\$6::bytea,\$7::bytea,\$8::timestamptz,\$9::timestamptz,\$10::timestamptz,\$11::timestamptz,\$12::integer,\$13::text,\$14::timestamptz\)/u);
  assert.match(roleSql, /agentpass_human_session_create\(uuid,uuid,uuid,uuid,text,bytea,bytea,timestamptz,timestamptz,timestamptz,timestamptz\)/u);
  assert.match(roleSql, /agentpass_human_session_create_with_ceiling\(uuid,uuid,uuid,uuid,text,bytea,bytea,timestamptz,timestamptz,timestamptz,timestamptz,integer,text,timestamptz\)/u);
});
