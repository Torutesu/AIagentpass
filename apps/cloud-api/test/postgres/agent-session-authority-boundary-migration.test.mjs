import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL(
  "../../../../contracts/postgres/0078_agent_session_authority_boundary.sql",
  import.meta.url,
);
const rolesUrl = new URL("../../../../scripts/postgres/roles.sql", import.meta.url);
const privilegeCheckUrl = new URL(
  "../../../../scripts/postgres/role-privilege-check.mjs",
  import.meta.url,
);
const authorityRepositoryUrl = new URL(
  "../../src/postgres/agent-session-authority-repository.mjs",
  import.meta.url,
);
const lifecycleRepositoryUrl = new URL(
  "../../src/postgres/agent-session-lifecycle-repository.mjs",
  import.meta.url,
);
const qualificationRepositoryUrl = new URL(
  "../../src/postgres/qualification-grant-batch-repository.mjs",
  import.meta.url,
);

async function read(url) {
  return readFile(url, "utf8");
}

test("0078 removes direct online table access from Agent Session authority", async () => {
  const sql = await read(migrationUrl);

  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.doesNotMatch(sql, /\b(?:DROP|TRUNCATE)\s+(?:TABLE|COLUMN|INDEX|FUNCTION)/iu);
  for (const table of ["agent_session_grants", "agent_sessions"]) {
    assert.match(sql, new RegExp(`ALTER TABLE public\\.${table} ENABLE ROW LEVEL SECURITY`, "u"));
    assert.match(sql, new RegExp(`ALTER TABLE public\\.${table} FORCE ROW LEVEL SECURITY`, "u"));
    assert.match(sql, new RegExp(`REVOKE ALL ON TABLE public\\.agent_session_grants, public\\.agent_sessions`, "u"));
  }
  for (const policy of [
    "agent_session_grants_migrator_authority",
    "agent_session_grants_backup_select",
    "agent_sessions_migrator_authority",
    "agent_sessions_backup_select",
  ]) assert.match(sql, new RegExp(`CREATE POLICY ${policy}`, "u"));
  assert.match(sql, /GRANT SELECT ON TABLE public\.agent_session_grants, public\.agent_sessions TO agentpass_backup/u);
  assert.doesNotMatch(sql, /GRANT (?:SELECT|INSERT|UPDATE|DELETE).*TO agentpass_app/iu);
});

test("0078 is represented in the role SQL and live catalog checker", async () => {
  const [roles, checker] = await Promise.all([read(rolesUrl), read(privilegeCheckUrl)]);

  for (const relation of ["agent_session_grants", "agent_sessions"]) {
    assert.match(roles, new RegExp(`\\b${relation}\\b`, "u"));
    assert.match(checker, new RegExp(`'${relation}'`, "u"));
  }
  for (const policy of [
    "agent_session_grants_migrator_authority",
    "agent_session_grants_backup_select",
    "agent_sessions_migrator_authority",
    "agent_sessions_backup_select",
  ]) assert.match(checker, new RegExp(`'${policy}'`, "u"));
  assert.match(checker, /agent_session_authority_boundary_ok/u);
  assert.match(checker, /agent_session_authority_diagnostics/u);
  assert.match(checker, /has_table_privilege\('agentpass_app', t\.oid, 'INSERT'\)/u);
});

test("authority repositories do not issue direct Agent Session DML", async () => {
  const sources = await Promise.all([
    read(authorityRepositoryUrl),
    read(lifecycleRepositoryUrl),
    read(qualificationRepositoryUrl),
  ]);
  for (const source of sources) {
    assert.doesNotMatch(source, /(?:INSERT|UPDATE|DELETE)\s+INTO?\s+(?:public\.)?agent_session_(?:grants|sessions)/iu);
    assert.doesNotMatch(source, /(?:UPDATE|DELETE)\s+(?:public\.)?agent_session_(?:grants|sessions)/iu);
  }
});

test("0078 publishes the SECURITY DEFINER EXECUTE contract", async () => {
  const sql = await read(migrationUrl);
  const signatures = [
    "agentpass_agent_session_grant_issue",
    "agentpass_agent_session_grant_get",
    "agentpass_agent_session_consume",
    "agentpass_agent_session_lifecycle_expire_due",
    "agentpass_agent_session_lifecycle_revoke",
  ];
  assert.match(sql, /REVOKE ALL ON FUNCTION public\.%s FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance/u);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION public\.%s TO agentpass_app/u);
  for (const name of signatures) {
    assert.match(sql, new RegExp(`CREATE FUNCTION public\\.${name}`, "u"));
    assert.match(sql, new RegExp(`'${name}\\(`, "u"));
  }
});

test("0078 reports expired and revoked lifecycle outcomes separately", async () => {
  const sql = await read(migrationUrl);
  assert.match(sql, /RETURNING g\.status[\s\S]*COUNT\(\*\) FILTER \(WHERE status = 'expired'\)[\s\S]*INTO grant_expired_count, grant_revoked_count/u);
  assert.match(sql, /RETURNING s\.status[\s\S]*COUNT\(\*\) FILTER \(WHERE status = 'expired'\)[\s\S]*INTO session_expired_count, session_revoked_count/u);
  assert.doesNotMatch(sql, /grant_expired_count := 0;[\s\S]*grant_revoked_count := grant_count;/u);
  assert.doesNotMatch(sql, /session_expired_count := 0;[\s\S]*session_revoked_count := session_count;/u);
});
