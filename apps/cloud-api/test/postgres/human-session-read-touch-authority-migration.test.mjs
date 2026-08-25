import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migration = new URL("../../../../contracts/postgres/0085_human_session_read_touch_authority.sql", import.meta.url);
const repository = new URL("../../src/postgres/human-repository.mjs", import.meta.url);

test("human session lookup and activity touch are function-only authority entry points", async () => {
  const sql = await readFile(migration, "utf8");
  assert.match(sql, /CREATE FUNCTION public\.agentpass_human_session_find_by_token\(\s*p_token_hash bytea\s*\)/u);
  assert.match(sql, /CREATE FUNCTION public\.agentpass_human_session_touch\(\s*p_session_id uuid,\s*p_last_seen_at timestamptz,\s*p_idle_expires_at timestamptz\s*\)/u);
  assert.equal((sql.match(/^SECURITY DEFINER$/gmu) ?? []).length, 2);
  assert.equal((sql.match(/SET search_path = pg_catalog, public/gu) ?? []).length, 2);
  assert.match(sql, /Direct table privileges remain in place until every human-session/u);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_human_session_find_by_token\(bytea\) TO agentpass_app/u);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_human_session_touch\(uuid,timestamptz,timestamptz\) TO agentpass_app/u);
});

test("repository routes lookup and activity touch through the reviewed functions", async () => {
  const source = await readFile(repository, "utf8");
  assert.match(source, /SELECT public\.agentpass_human_session_find_by_token\(\$1::bytea\) AS session/u);
  assert.match(source, /SELECT public\.agentpass_human_session_touch\(\$1::uuid,\$2::timestamptz,\$3::timestamptz\) AS session/u);
});
