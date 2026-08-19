import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL(
  "../../../../contracts/postgres/0077_agent_session_launch_authority_handoff.sql",
  import.meta.url,
);
const rolesUrl = new URL("../../../../scripts/postgres/roles.sql", import.meta.url);
const privilegeCheckUrl = new URL(
  "../../../../scripts/postgres/role-privilege-check.mjs",
  import.meta.url,
);

async function read(url) {
  return readFile(url, "utf8");
}

function functionBody(sql, name) {
  const start = sql.indexOf(`CREATE FUNCTION public.${name}(`);
  assert.notEqual(start, -1, `missing function ${name}`);
  const bodyStart = sql.indexOf("AS $$", start);
  const bodyEnd = sql.indexOf("$$;", bodyStart);
  assert.ok(bodyStart > start && bodyEnd > bodyStart, `unterminated function ${name}`);
  return sql.slice(start, bodyEnd + 3);
}

test("0077 is a transactional, append-only handoff marker migration", async () => {
  const sql = await read(migrationUrl);
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.doesNotMatch(sql, /\b(?:DROP|TRUNCATE)\s+(?:TABLE|COLUMN|INDEX|FUNCTION)/iu);
  assert.match(sql, /CREATE TABLE public\.agent_session_launch_authority_handoffs/u);
  assert.match(sql, /PRIMARY KEY \(organization_id, session_id\)/u);
  assert.match(sql, /UNIQUE \(organization_id, request_id\)/u);
  assert.match(sql, /UNIQUE \(organization_id, grant_id\)/u);
  assert.match(sql, /REFERENCES public\.agent_sessions\(organization_id, session_id, grant_id, device_id\)/u);
  assert.match(sql, /REFERENCES public\.agent_session_grants\(organization_id, grant_id, device_id, agent_id, grant_hash\)/u);
  assert.match(sql, /REFERENCES public\.control_plane_authority_generations\(organization_id, generation\)/u);
  assert.match(sql, /BEFORE UPDATE OR DELETE ON public\.agent_session_launch_authority_handoffs/u);
  assert.match(sql, /ENABLE ROW LEVEL SECURITY/u);
  assert.match(sql, /FORCE ROW LEVEL SECURITY/u);
});

test("0077 locks and rechecks the existing Session/Grant authority projection", async () => {
  const sql = await read(migrationUrl);
  const handoff = functionBody(sql, "agentpass_agent_launch_authority_handoff");
  assert.match(handoff, /SECURITY DEFINER/u);
  assert.match(handoff, /SET search_path = pg_catalog, public/u);
  assert.match(handoff, /public\.agentpass_current_organization_id\(\) IS DISTINCT FROM p_organization_id/u);
  assert.match(handoff, /gr\.status = 'consumed'/u);
  assert.match(handoff, /gr\.consumed_session_id = s\.session_id/u);
  assert.match(handoff, /s\.max_signatures = 2/u);
  assert.match(handoff, /authority\.superseded_at IS NULL/u);
  assert.match(handoff, /d\.status = 'active'/u);
  assert.match(handoff, /a\.status = 'active'/u);
  assert.match(handoff, /FROM public\.revocations AS r[\s\S]*r\.status = 'active'/u);
  assert.match(handoff, /FOR SHARE OF s, d, a, gr, authority/u);

  const organizationLock = handoff.indexOf(
    "PERFORM pg_advisory_xact_lock(hashtextextended(\n    'agentpass:organization:' || p_organization_id::text, 0\n  ));",
  );
  const authorityQuery = handoff.indexOf("SELECT s, gr");
  const activeRevocationQuery = handoff.indexOf("FROM public.revocations AS r");
  assert.ok(organizationLock >= 0, "0077 must acquire the organization advisory lock with the shared key derivation");
  assert.ok(organizationLock < authorityQuery, "0077 must acquire the organization lock before the authority query");
  assert.ok(organizationLock < activeRevocationQuery, "0077 must acquire the organization lock before checking active revocations");

  assert.match(handoff, /INSERT INTO public\.agent_session_launch_authority_handoffs/u);
  assert.match(handoff, /ON CONFLICT DO NOTHING/u);
  assert.match(handoff, /'state', 'issued'/u);
  assert.match(handoff, /'state', 'already_returned'/u);
  assert.match(sql, /agent_session_launch_authority_handoffs_tenant_select[\s\S]*organization_id = public\.agentpass_current_organization_id\(\)/u);
  assert.match(sql, /agent_session_launch_authority_handoffs_migrator_authority[\s\S]*TO agentpass_migrator[\s\S]*USING \(true\) WITH CHECK \(true\)/u);
  assert.match(sql, /agent_session_launch_authority_handoffs_backup_select[\s\S]*FOR SELECT TO agentpass_backup[\s\S]*USING \(true\)/u);
  assert.doesNotMatch(sql, /GRANT (?:SELECT|INSERT|UPDATE|DELETE).*TO agentpass_app/iu);
});

test("0077 is included in the reviewed role manifests and privilege contract", async () => {
  const [roles, privilegeCheck] = await Promise.all([read(rolesUrl), read(privilegeCheckUrl)]);
  const signature = "agentpass_agent_launch_authority_handoff(uuid,uuid,uuid,uuid,uuid,text,uuid,text,uuid,bytea,timestamptz,timestamptz,bigint,bigint,bytea,bytea,bytea)";
  assert.match(roles, new RegExp(signature.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "u"));
  assert.match(roles, /agent_session_launch_authority_handoffs/u);
  assert.match(privilegeCheck, new RegExp(signature.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "u"));
  assert.match(privilegeCheck, /agent_session_launch_authority_handoffs/u);
  assert.match(privilegeCheck, /agent_session_launch_authority_handoffs_tenant_select/u);
  assert.match(privilegeCheck, /agent_session_launch_authority_handoffs_migrator_authority/u);
  assert.match(privilegeCheck, /agent_session_launch_authority_handoffs_backup_select/u);
});
