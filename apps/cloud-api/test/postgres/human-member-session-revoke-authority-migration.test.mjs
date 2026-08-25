import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migration = new URL("../../../../contracts/postgres/0103_human_member_session_revoke_authority.sql", import.meta.url);
const repository = new URL("../../src/postgres/organization-repository.mjs", import.meta.url);

test("0103 exposes member revocation as one reviewed authority operation", async () => {
  const sql = await readFile(migration, "utf8");
  assert.match(sql, /CREATE FUNCTION public\.agentpass_human_member_session_revoke\(\s*p_member_id uuid,\s*p_organization_id uuid,\s*p_revoked_at timestamptz,\s*p_reason text\s*\)/u);
  assert.match(sql, /SECURITY DEFINER\s+SET search_path = pg_catalog, public/u);
  assert.match(sql, /pg_advisory_xact_lock\(\s*hashtextextended\('agentpass:human:sessions:'/u);
  assert.match(sql, /UPDATE public\.human_sessions[\s\S]*recent_auth_context_hash = NULL/u);
  assert.match(sql, /UPDATE public\.webauthn_challenges[\s\S]*status = 'consumed'/u);
  assert.match(sql, /ALTER FUNCTION public\.agentpass_human_member_session_revoke\(uuid,uuid,timestamptz,text\)\s+OWNER TO agentpass_migrator/u);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_human_member_session_revoke\(uuid,uuid,timestamptz,text\)\s+TO agentpass_app/u);
});

test("organization repository has no direct session or challenge DML", async () => {
  const source = await readFile(repository, "utf8");
  assert.doesNotMatch(source, /(?:INSERT INTO|UPDATE|DELETE FROM)\s+(?:public\.)?(?:human_sessions|webauthn_challenges)\b/u);
  assert.match(source, /SELECT public\.agentpass_human_member_session_revoke\(/u);
});
