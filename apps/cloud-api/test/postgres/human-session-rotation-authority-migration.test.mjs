import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migration = new URL("../../../../contracts/postgres/0096_human_session_rotation_authority.sql", import.meta.url);
const repository = new URL("../../src/postgres/human-repository.mjs", import.meta.url);

test("session rotation is one member-serialized authority operation", async () => {
  const sql = await readFile(migration, "utf8");
  assert.match(sql, /CREATE FUNCTION public\.agentpass_human_session_rotate\(/u);
  assert.match(sql, /RETURNS jsonb/u);
  assert.match(sql, /pg_advisory_xact_lock/u);
  assert.match(sql, /s\.token_hash = p_old_token_hash/u);
  assert.match(sql, /s\.membership_id = p_membership_id/u);
  assert.match(sql, /m\.session_epoch = s\.membership_session_epoch/u);
  assert.match(sql, /INSERT INTO public\.human_sessions/u);
  assert.match(sql, /UPDATE public\.human_sessions AS s/u);
  assert.match(sql, /successor is missing or invalid/u);
  assert.equal((sql.match(/^SECURITY DEFINER$/gmu) ?? []).length, 1);
});

test("repository routes rotation through authority", async () => {
  const source = await readFile(repository, "utf8");
  assert.match(source, /agentpass_human_session_rotate\(\$1::uuid,\$2::bytea,\$3::uuid/u);
});
