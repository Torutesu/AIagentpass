import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migration = new URL("../../../../contracts/postgres/0088_human_session_recent_auth_authority.sql", import.meta.url);
const repository = new URL("../../src/postgres/human-repository.mjs", import.meta.url);

test("recent-auth session authority is function-only and keeps exact challenge binding", async () => {
  const sql = await readFile(migration, "utf8");
  assert.match(sql, /CREATE FUNCTION public\.agentpass_human_session_bind_recent_auth\(/u);
  assert.match(sql, /CREATE FUNCTION public\.agentpass_human_session_consume_recent_auth\(/u);
  assert.equal((sql.match(/^SECURITY DEFINER$/gmu) ?? []).length, 2);
  assert.equal((sql.match(/SET search_path = pg_catalog, public/g) ?? []).length, 2);
  for (const fragment of [
    "c.session_id = s.id",
    "c.member_id = s.member_id",
    "c.organization_id = s.organization_id",
    "c.context_hash IS NOT DISTINCT FROM p_context_hash",
    "c.status = 'consumed'",
    "o.authority_epoch = s.organization_authority_epoch",
    "m.session_epoch = s.membership_session_epoch",
    "INTERVAL '5 minutes'",
  ]) assert.match(sql, new RegExp(fragment.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
});

test("repository routes bind and consume through the reviewed functions", async () => {
  const source = await readFile(repository, "utf8");
  assert.match(source, /agentpass_human_session_bind_recent_auth\(\$1::uuid,\$2::uuid,\$3::uuid,\$4::text,\$5::uuid,\$6::bytea,\$7::timestamptz\)/u);
  assert.match(source, /agentpass_human_session_consume_recent_auth\(\$1::uuid,\$2::uuid,\$3::uuid,\$4::text,\$5::uuid,\$6::bytea,\$7::timestamptz\)/u);
});
