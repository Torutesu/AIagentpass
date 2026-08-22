import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migration = new URL("../../../../contracts/postgres/0097_owner_recovery_credential_authority.sql", import.meta.url);
const repository = new URL("../../src/postgres/owner-recovery-repository.mjs", import.meta.url);

test("owner-recovery credential authority binds request, recovery session, challenge, and member", async () => {
  const sql = await readFile(migration, "utf8");
  for (const name of ["agentpass_owner_recovery_register_credential", "agentpass_owner_recovery_find_credential", "agentpass_owner_recovery_update_credential_counter", "agentpass_owner_recovery_credential_exists"]) assert.match(sql, new RegExp(`CREATE FUNCTION public\\.${name}\\(`, "u"));
  assert.equal((sql.match(/^SECURITY DEFINER$/gmu) ?? []).length, 4);
  assert.equal((sql.match(/SET search_path = pg_catalog, public/g) ?? []).length, 4);
  for (const fragment of ["owner_recovery_sessions", "owner_recovery_requests", "p_request_id", "p_recovery_session_id", "p_member_id", "p_backup_state", "p_expected_sign_count", "c.revoked_at IS NULL", "c.clone_detected_at IS NULL"]) assert.match(sql, new RegExp(fragment.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
  assert.match(sql, /REVOKE INSERT, UPDATE, DELETE ON TABLE public\.webauthn_credentials/u);
});

test("owner-recovery repository uses the authority functions for credential paths", async () => {
  const source = await readFile(repository, "utf8");
  assert.match(source, /agentpass_owner_recovery_register_credential/u);
  assert.match(source, /agentpass_owner_recovery_find_credential/u);
  assert.match(source, /agentpass_owner_recovery_update_credential_counter/u);
  assert.doesNotMatch(source, /INSERT INTO webauthn_credentials/u);
  assert.doesNotMatch(source, /SELECT id FROM webauthn_credentials/u);
});
