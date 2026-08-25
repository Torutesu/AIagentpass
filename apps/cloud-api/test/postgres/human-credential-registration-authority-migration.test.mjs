import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migration = new URL("../../../../contracts/postgres/0092_human_credential_registration_authority.sql", import.meta.url);
const repository = new URL("../../src/postgres/human-repository.mjs", import.meta.url);

test("credential registration authority binds the active session and closes direct INSERT", async () => {
  const sql = await readFile(migration, "utf8");
  assert.match(sql, /CREATE FUNCTION public\.agentpass_human_register_credential\(/u);
  assert.match(sql, /RETURNS TABLE \([\s\S]*id bytea[\s\S]*public_key bytea[\s\S]*created_at timestamptz/u);
  assert.equal((sql.match(/^SECURITY DEFINER$/gmu) ?? []).length, 1);
  assert.match(sql, /SET search_path = pg_catalog, public/u);
  for (const fragment of [
    "s.member_id = p_member_id",
    "s.organization_id = p_organization_id",
    "s.revoked_at IS NULL",
    "s.expires_at > now_value",
    "m.status = 'active'",
    "m.role = s.role",
    "o.authority_epoch = s.organization_authority_epoch",
    "m.session_epoch = s.membership_session_epoch",
    "ON CONFLICT (id) DO NOTHING",
    "p_backup_state IS TRUE",
    "REVOKE INSERT ON TABLE public.webauthn_credentials",
  ]) assert.match(sql, new RegExp(fragment.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
});

test("credential registration paths use the authority function", async () => {
  const source = await readFile(repository, "utf8");
  assert.equal((source.match(/agentpass_human_register_credential\(/gu) ?? []).length, 2);
  assert.doesNotMatch(source, /INSERT INTO webauthn_credentials \(id,member_id,public_key/u);
});
