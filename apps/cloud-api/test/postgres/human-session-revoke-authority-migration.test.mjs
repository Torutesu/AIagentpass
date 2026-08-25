import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const managedMigration = new URL("../../../../contracts/postgres/0101_human_session_managed_revoke_authority.sql", import.meta.url);
const othersMigration = new URL("../../../../contracts/postgres/0102_human_session_revoke_others_authority.sql", import.meta.url);
const repository = new URL("../../src/postgres/human-repository.mjs", import.meta.url);

test("managed revoke is actor-bound, versioned, and function-owned", async () => {
  const sql = await readFile(managedMigration, "utf8");
  assert.match(sql, /CREATE FUNCTION public\.agentpass_human_session_revoke_managed\(/u);
  assert.match(sql, /actor\.id = p_actor_session_id/u);
  assert.match(sql, /target\.version = p_expected_version/u);
  assert.match(sql, /actor_organization\.authority_epoch = actor\.organization_authority_epoch/u);
  assert.match(sql, /target_membership\.session_epoch = target\.membership_session_epoch/u);
  assert.match(sql, /pg_advisory_xact_lock/u);
  assert.match(sql, /SECURITY DEFINER/u);
  assert.match(sql, /SET search_path = pg_catalog, public/u);
});

test("other-session revoke is one member-serialized, actor-excluding batch", async () => {
  const sql = await readFile(othersMigration, "utf8");
  assert.match(sql, /CREATE FUNCTION public\.agentpass_human_session_revoke_others\(/u);
  assert.match(sql, /target\.id <> p_actor_session_id/u);
  assert.match(sql, /jsonb_agg\(to_jsonb\(changed\)/u);
  assert.match(sql, /pg_advisory_xact_lock/u);
  assert.match(sql, /SECURITY DEFINER/u);
});

test("repository contains no direct human-session DML in managed or batch revoke", async () => {
  const source = await readFile(repository, "utf8");
  for (const name of ["revokeManagedSession", "revokeOtherSessions"]) {
    const start = source.indexOf(`async function ${name}`);
    const end = source.indexOf("\n  async function ", start + 1);
    const method = source.slice(start, end < 0 ? source.length : end);
    assert.match(method, /agentpass_human_session_revoke_/u, name);
    assert.doesNotMatch(method, /UPDATE human_sessions/u, name);
  }
});
