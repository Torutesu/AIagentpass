import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migration = new URL("../../../../contracts/postgres/0098_owner_recovery_activation_authority.sql", import.meta.url);
const epochMigration = new URL("../../../../contracts/postgres/0056_identity_epoch_invalidation.sql", import.meta.url);
const repository = new URL("../../src/postgres/owner-recovery-repository.mjs", import.meta.url);

test("activation authority is bound to the request, recovery session, proof, and credential", async () => {
  const sql = await readFile(migration, "utf8");
  assert.match(sql, /CREATE FUNCTION public\.agentpass_owner_recovery_activate_authority\(/u);
  assert.match(sql, /p_request_id uuid[\s\S]*p_recovery_session_id uuid[\s\S]*p_authorization_id uuid[\s\S]*p_credential_id bytea/u);
  assert.match(sql, /request_state <> 'activated'/u);
  assert.match(sql, /stage = 'credential_enrolled'/u);
  assert.match(sql, /status = 'consuming'/u);
  assert.match(sql, /session_credential_id IS DISTINCT FROM p_credential_id/u);
  assert.match(sql, /SECURITY DEFINER/u);
  assert.match(sql, /SET search_path = pg_catalog, public/u);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON FUNCTION public\.agentpass_owner_recovery_activate_authority\(uuid, uuid, uuid, uuid, uuid, bytea\)/u);
  assert.doesNotMatch(sql, /agentpass\.recovery_epoch_bump/u);
});

test("activation repository lets the state trigger own invalidation", async () => {
  const [source, epochSql] = await Promise.all([readFile(repository, "utf8"), readFile(epochMigration, "utf8")]);
  const activation = source.slice(source.indexOf("async function activateRecoveryStateInTransaction"), source.indexOf("function normalizeCreateInput"));
  assert.doesNotMatch(activation, /UPDATE memberships SET session_epoch/u);
  assert.doesNotMatch(activation, /UPDATE human_sessions SET revoked_at/u);
  assert.match(activation, /transitionRequest\(tx,[\s\S]*toState: "activated"/u);
  assert.match(activation, /agentpass_owner_recovery_activate_authority/u);
  assert.doesNotMatch(epochSql, /current_setting\('agentpass\.recovery_epoch_bump'/u);
});
