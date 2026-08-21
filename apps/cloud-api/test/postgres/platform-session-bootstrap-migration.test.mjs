import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0055_platform_session_bootstrap.sql", import.meta.url);

function definitions(sql) {
  const starts = [...sql.matchAll(/CREATE FUNCTION public\.([a-z0-9_]+)\(([^)]*)\)/gu)];
  return starts.map((match, index) => {
    const end = starts[index + 1]?.index ?? sql.indexOf("-- No table DML is added", match.index);
    return { name: match[1], signature: match[2].replace(/\s+/gu, " ").trim(), body: sql.slice(match.index, end < 0 ? sql.length : end) };
  });
}

function bodyOf(sql, name) {
  return definitions(sql).find((item) => item.name === name)?.body ?? "";
}

test("0055 is transactional and leaves durable assignments unchanged", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN|INDEX)|TRUNCATE\s+TABLE/iu);
  assert.doesNotMatch(sql, /ADD COLUMN human_session_id|platform_operator_assignments_human_session|ALTER TABLE public\.platform_operator_assignments/iu);
});

test("0055 exposes only a hash-and-scope bootstrap function with a fixed table contract", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  const bootstrap = bodyOf(sql, "agentpass_platform_session_bootstrap_context");
  assert.match(bootstrap, /p_human_session_token_hash bytea/u);
  assert.match(bootstrap, /p_organization_id uuid/u);
  assert.match(bootstrap, /p_operation text/u);
  assert.match(bootstrap, /p_capability text/u);
  assert.match(bootstrap, /RETURNS TABLE \([\s\S]*allowed_webauthn_credential_ids bytea\[\][\s\S]*platform_credentials jsonb/u);
  assert.match(bootstrap, /VOLATILE[\s\S]*SECURITY DEFINER/u);
  assert.match(bootstrap, /SET search_path = pg_catalog, public/u);
  assert.doesNotMatch(bootstrap, /(?:csrf|assertion|private_key|raw_bearer|plain_bearer)/iu);
  assert.doesNotMatch(bootstrap, /p_(?:principal|member|assignment|generation|allowed)/iu);
});

test("0055 locks and rechecks the complete authority chain with DB time", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  const bootstrap = bodyOf(sql, "agentpass_platform_session_bootstrap_context");
  for (const fragment of [
    "WHERE session_value.token_hash = p_human_session_token_hash",
    "FOR UPDATE",
    "session_row.revoked_at IS NOT NULL",
    "session_row.expires_at <= now_value",
    "session_row.idle_expires_at <= now_value",
    "organization_row.authority_epoch IS DISTINCT FROM session_row.organization_authority_epoch",
    "membership_row.session_epoch IS DISTINCT FROM session_row.membership_session_epoch",
    "candidate.status = 'active'",
    "principal_row.status <> 'active'",
    "platform_credential.status = 'active'",
    "webauthn_credential.revoked_at",
    "platform_sign_count_state <> 'clone-detected'",
    "clock_timestamp()",
  ]) {
    assert.match(bootstrap, new RegExp(fragment.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"), fragment);
  }
  assert.match(bootstrap, /candidate_count <> 1[\s\S]*RETURN;/u);
  assert.match(bootstrap, /FOR UPDATE OF platform_credential, webauthn_credential/u);
  assert.match(bootstrap, /SELECT DISTINCT allowed_id[\s\S]*ORDER BY allowed_id/u);
  assert.match(bootstrap, /allowed_ids bytea\[\]/u);
  assert.doesNotMatch(
    bootstrap,
    /assignment_row\.requested_authority_generation\s+IS DISTINCT FROM\s+principal_row\.authority_generation/u,
    "0055 must not fence bootstrap on the activation request generation",
  );
  assert.match(bootstrap, /principal_authority_generation := principal_row\.authority_generation/u);
});

test("0055 grants only the new function and never grants application table DML", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  const grants = [...sql.matchAll(/\bGRANT\s+([\s\S]*?)\s+TO\s+agentpass_app\s*;/gmu)].map((match) => match[1]);
  assert.deepEqual(grants, ["EXECUTE ON FUNCTION\n  public.agentpass_platform_session_bootstrap_context(bytea, uuid, text, text)"]);
  assert.doesNotMatch(sql, /GRANT\s+[^;]*\bON\s+(?:TABLE|ALL\s+TABLES)/iu);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON FUNCTION[\s\S]*agentpass_platform_session_bootstrap_context\(bytea, uuid, text, text\)[\s\S]*FROM PUBLIC/u);
});
