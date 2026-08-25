import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migration = new URL("../../../../contracts/postgres/0105_human_identity_boundary_hardening.sql", import.meta.url);
const resolver = new URL("../../src/human-auth/identity/postgres-resolver.mjs", import.meta.url);
const binder = new URL("../../src/identity-bind.mjs", import.meta.url);
const repository = new URL("../../src/postgres/human-repository.mjs", import.meta.url);

test("0105 identity projections and bind are SECURITY DEFINER, caller-bound authority functions", async () => {
  const sql = await readFile(migration, "utf8");
  const compactSql = sql.replace(/\s+/gu, " ");
  for (const signature of [
    "agentpass_human_identity_resolve(text,text,uuid)",
    "agentpass_human_identity_bind(text,text,uuid,uuid)",
    "agentpass_human_identity_find(text,text)",
    "agentpass_human_identity_list_memberships(text,text,uuid)"
  ]) {
    assert.match(sql, new RegExp(`CREATE(?: OR REPLACE)? FUNCTION public\\.${signature.split("(")[0]}\\(`, "u"));
    assert.match(sql, /SECURITY DEFINER\s+SET search_path = pg_catalog, public/u);
    const escapedSignature = signature.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
    assert.match(compactSql, new RegExp(`ALTER FUNCTION public\\.${escapedSignature} OWNER TO agentpass_migrator`, "u"));
  }
  assert.match(compactSql, /GRANT EXECUTE ON FUNCTION public\.agentpass_human_identity_bind\(text,text,uuid,uuid\) TO agentpass_maintenance/u);
  assert.match(compactSql, /GRANT EXECUTE ON FUNCTION public\.agentpass_human_identity_find\(text,text\) TO agentpass_app/u);
  assert.match(compactSql, /GRANT EXECUTE ON FUNCTION public\.agentpass_human_identity_list_memberships\(text,text,uuid\) TO agentpass_app/u);
  assert.doesNotMatch(compactSql, /GRANT EXECUTE ON FUNCTION public\.agentpass_human_identity_bind\(text,text,uuid,uuid\) TO agentpass_app/u);
  assert.match(sql, /session_user <> 'agentpass_maintenance'/u);
  assert.match(sql, /octet_length\(p_subject\) > 512/u);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON TABLE public\.upstream_identities FROM agentpass_app/u);
  assert.match(sql, /REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER[\s\S]*public\.organizations, public\.memberships FROM agentpass_app/u);
  assert.match(sql, /m\.organization_id = p_organization_id[\s\S]*m\.status = 'active'/u);
  assert.match(sql, /p_member_id IS NULL OR p_organization_id IS NULL/u);
  assert.match(sql, /existing_member_id IS DISTINCT FROM p_member_id/u);
});

test("application identity paths call authority functions instead of direct identity SQL", async () => {
  const [resolverSource, binderSource, repositorySource] = await Promise.all([readFile(resolver, "utf8"), readFile(binder, "utf8"), readFile(repository, "utf8")]);
  assert.match(resolverSource, /agentpass_human_identity_resolve/u);
  assert.doesNotMatch(resolverSource, /FROM upstream_identities|JOIN memberships|JOIN organizations/u);
  assert.match(binderSource, /agentpass_human_identity_bind/u);
  assert.doesNotMatch(binderSource, /INSERT INTO upstream_identities|SELECT member_id FROM upstream_identities/u);
  assert.match(repositorySource, /agentpass_human_identity_bind/u);
  assert.match(repositorySource, /agentpass_human_identity_find/u);
  assert.match(repositorySource, /agentpass_human_identity_list_memberships/u);
  assert.doesNotMatch(repositorySource, /FROM upstream_identities|JOIN memberships|JOIN organizations/u);
});

test("role bootstrap and qualification keep immutable identity mappings function-only", async () => {
  const [roles, checker] = await Promise.all([
    readFile(new URL("../../../../scripts/postgres/roles.sql", import.meta.url), "utf8"),
    readFile(new URL("../../../../scripts/postgres/role-privilege-check.mjs", import.meta.url), "utf8")
  ]);
  assert.match(roles, /'upstream_identities'/u);
  assert.match(roles, /agentpass_human_identity_find\(text,text\)/u);
  assert.match(roles, /agentpass_human_identity_list_memberships\(text,text,uuid\)/u);
  assert.match(roles, /agentpass_human_identity_bind\(text,text,uuid,uuid\)/u);
  assert.doesNotMatch(roles, /'agentpass_human_identity_bind\(text,text,uuid,uuid\)'\s*\) TO agentpass_app/u);
  assert.match(checker, /'upstream_identities'/u);
  assert.match(checker, /'agentpass_human_identity_bind\(text,text,uuid,uuid\)'/u);
  assert.match(checker, /maintenance_function_allowlist/u);
});
