import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migration = new URL("../../../../contracts/postgres/0100_human_session_switch_authority.sql", import.meta.url);
const repository = new URL("../../src/postgres/human-repository.mjs", import.meta.url);

test("session switch is a single authority operation across two organizations", async () => {
  const sql = await readFile(migration, "utf8");
  assert.match(sql, /CREATE FUNCTION public\.agentpass_human_session_switch\(/u);
  assert.match(sql, /p_old_token_hash bytea[\s\S]*p_target_organization_id uuid[\s\S]*p_token_hash bytea/u);
  assert.match(sql, /pg_advisory_xact_lock/u);
  assert.match(sql, /ORDER BY o\.id[\s\S]*FOR UPDATE/u);
  assert.match(sql, /s\.token_hash = p_old_token_hash[\s\S]*s\.organization_authority_epoch/u);
  assert.match(sql, /INSERT INTO public\.human_sessions/u);
  assert.match(sql, /UPDATE public\.human_sessions AS s/u);
  assert.match(sql, /SECURITY DEFINER/u);
  assert.match(sql, /SET search_path = pg_catalog, public/u);
});

test("human repository routes organization switching through the authority", async () => {
  const source = await readFile(repository, "utf8");
  const method = source.slice(source.indexOf("async function switchSessionOrganization"), source.indexOf("async function findSessionByTokenHash"));
  assert.match(method, /agentpass_human_session_switch/u);
  assert.doesNotMatch(method, /INSERT INTO human_sessions/u);
  assert.doesNotMatch(method, /UPDATE human_sessions/u);
  assert.doesNotMatch(method, /inTransaction\(/u);
});
