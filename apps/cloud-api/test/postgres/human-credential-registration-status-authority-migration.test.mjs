import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migration = new URL("../../../../contracts/postgres/0099_human_credential_registration_status_authority.sql", import.meta.url);
const repository = new URL("../../src/postgres/human-repository.mjs", import.meta.url);

test("registration status binds an active session and returns only bounded credential state", async () => {
  const sql = await readFile(migration, "utf8");
  assert.match(sql, /CREATE FUNCTION public\.agentpass_human_credential_registration_status\(/u);
  assert.match(sql, /credential_exists boolean[\s\S]*active_count bigint[\s\S]*total_count bigint/u);
  assert.match(sql, /human_sessions[\s\S]*memberships[\s\S]*organizations/u);
  assert.match(sql, /SECURITY DEFINER/u);
  assert.match(sql, /SET search_path = pg_catalog, public/u);
  assert.doesNotMatch(sql, /public_key/u);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON FUNCTION public\.agentpass_human_credential_registration_status\(uuid,uuid,uuid,bytea\)/u);
});

test("human repository routes registration conflict, counts, and scoped existence through authorities", async () => {
  const source = await readFile(repository, "utf8");
  assert.match(source, /agentpass_human_credential_registration_status/u);
  assert.doesNotMatch(source, /SELECT 1 FROM webauthn_credentials/u);
  assert.doesNotMatch(source, /SELECT COUNT\(\*\).*FROM webauthn_credentials/u);
  assert.match(source, /agentpass_human_find_credential_for_session/u);
});
