import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL(
  "../../../../contracts/postgres/0053_platform_sessions.sql",
  import.meta.url
);

const readMigration = () => readFile(migrationUrl, "utf8");

function withoutSqlComments(sql) {
  return sql.replace(/--[^\n]*$/gmu, "").replace(/\/\*[\s\S]*?\*\//gu, "");
}

function functionDefinitions(sql) {
  const starts = [...sql.matchAll(/CREATE FUNCTION public\.([a-z0-9_]+)\(([^)]*)\)/gu)];
  return starts.map((match, index) => {
    const end = starts[index + 1]?.index ?? sql.indexOf("-- Authority tables are function-only", match.index);
    const body = sql.slice(match.index, end < 0 ? sql.length : end);
    const signature = match[2].trim() === ""
      ? ""
      : match[2].split(",").map((argument) => argument.trim().split(/\s+/u).at(-1)).join(",");
    return { name: match[1], signature, body };
  });
}

function functionBody(sql, name) {
  return functionDefinitions(sql).find((definition) => definition.name === name)?.body ?? "";
}

function signaturePattern(signature) {
  return signature.split(",").map((part) => part.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")).join("\\s*,\\s*");
}

test("0053 is a forward-only, seed-free platform namespace separate from human sessions", async () => {
  const sql = await readMigration();
  const executableSql = withoutSqlComments(sql);
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.match(sql, /separate from human_sessions/iu);
  assert.doesNotMatch(executableSql, /(?:FROM|JOIN|UPDATE|INSERT INTO|REFERENCES)\s+human_sessions/iu);
  assert.doesNotMatch(sql, /INSERT INTO\s+platform_(?:credentials|sessions)\s*\([^)]*\)\s*SELECT/isu);
  assert.match(sql, /no implicit|never creates a principal/iu);

  for (const relation of ["platform_credentials", "platform_sessions"]) {
    assert.match(sql, new RegExp(`CREATE TABLE ${relation} \\(`, "u"));
    assert.match(sql, new RegExp(`CREATE TRIGGER ${relation}_forward_only`, "u"));
  }
  assert.match(sql, /CREATE TRIGGER platform_credentials_forward_only[\s\S]*BEFORE INSERT OR UPDATE OR DELETE/u);
  assert.match(sql, /CREATE TRIGGER platform_sessions_forward_only[\s\S]*BEFORE INSERT OR UPDATE OR DELETE/u);
});

test("0053 stores only hashes for bearer material and binds WebAuthn clone state", async () => {
  const sql = await readMigration();
  assert.match(sql, /session_material_hash bytea NOT NULL UNIQUE CHECK \(octet_length\(session_material_hash\) = 32\)/u);
  assert.match(sql, /webauthn_credential_id bytea NOT NULL REFERENCES webauthn_credentials\(id\)/u);
  assert.match(sql, /sign_count bigint NOT NULL DEFAULT 0 CHECK \(sign_count >= 0\)/u);
  assert.match(sql, /sign_count_state text NOT NULL DEFAULT 'unknown'[\s\S]*'zero-counter'[\s\S]*'monotonic'[\s\S]*'clone-detected'/u);
  assert.match(sql, /backup_eligible boolean NOT NULL/u);
  assert.match(sql, /backup_state boolean NOT NULL/u);
  assert.match(sql, /platform_credentials_sign_count_forward_only/u);
  assert.match(sql, /platform_credentials_clone_detected_terminal/u);
  assert.match(sql, /platform_credential_advance_sign_count/u);
  assert.match(functionBody(sql, "agentpass_platform_credential_advance_sign_count"), /p_sign_count = 0/iu);
  assert.match(functionBody(sql, "agentpass_platform_credential_advance_sign_count"), /clone-detected/iu);
  assert.doesNotMatch(sql, /(?:bearer|session|token|jti|assertion|challenge)_material\s+text/iu);
  assert.doesNotMatch(sql, /(?:raw|plain)_?(?:token|bearer|session|assertion)/iu);
});

test("0053 binds principal, assignment, credential generations, operation, and capability", async () => {
  const sql = await readMigration();
  for (const column of [
    "principal_authority_generation bigint NOT NULL CHECK (principal_authority_generation > 0)",
    "assignment_version bigint NOT NULL CHECK (assignment_version > 0)",
    "credential_version bigint NOT NULL CHECK (credential_version > 0)",
    "assignment_id uuid NOT NULL REFERENCES platform_operator_assignments(assignment_id)",
    "credential_id uuid NOT NULL REFERENCES platform_credentials(credential_id)"
  ]) assert.match(sql, new RegExp(column.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
  assert.match(sql, /operation text NOT NULL[\s\S]*capability text NOT NULL[\s\S]*'platform\.promotion\.issue'/u);
  assert.match(sql, /CHECK \(operation = capability\)/u);
  assert.match(sql, /platform_sessions_assignment_binding/u);
  assert.match(sql, /platform_sessions_credential_binding/u);
  const guard = functionBody(sql, "agentpass_guard_platform_session");
  assert.match(guard, /IF TG_OP = 'INSERT' THEN[\s\S]*platform_sessions_assignment_binding[\s\S]*platform_sessions_credential_binding/u);
  assert.match(functionBody(sql, "agentpass_platform_session_issue"), /principal_row\.authority_generation/u);
  assert.match(functionBody(sql, "agentpass_platform_session_issue"), /assignment_row\.version/u);
  assert.match(functionBody(sql, "agentpass_platform_session_issue"), /credential_row\.version/u);
  assert.match(functionBody(sql, "agentpass_platform_session_find_active"), /principal\.authority_generation = platform_session\.principal_authority_generation/u);
  assert.match(functionBody(sql, "agentpass_platform_session_find_active"), /assignment\.version = platform_session\.assignment_version/u);
  assert.match(functionBody(sql, "agentpass_platform_session_find_active"), /credential\.version = platform_session\.credential_version/u);
});

test("0053 uses database clock and forward-only expiry, idle, and revocation state", async () => {
  const sql = await readMigration();
  assert.match(sql, /created_at timestamptz NOT NULL DEFAULT clock_timestamp\(\)/u);
  assert.match(sql, /authenticated_at timestamptz NOT NULL/u);
  assert.match(sql, /last_seen_at timestamptz NOT NULL/u);
  assert.match(sql, /expires_at timestamptz NOT NULL/u);
  assert.match(sql, /idle_expires_at timestamptz NOT NULL/u);
  assert.match(sql, /idle_timeout_seconds integer NOT NULL CHECK \(idle_timeout_seconds BETWEEN 1 AND 86400\)/u);
  assert.match(sql, /status text NOT NULL DEFAULT 'active' CHECK \(status IN \('active', 'expired', 'revoked'\)\)/u);
  assert.match(sql, /platform_sessions_terminal/u);
  assert.match(sql, /platform_sessions_lifecycle_forward_only/u);
  assert.match(sql, /expired_at = now_value/u);
  assert.match(sql, /revoked_at = now_value/u);
  assert.match(sql, /clock_timestamp\(\)/u);
  assert.match(functionBody(sql, "agentpass_platform_session_find_active"), /expires_at > now_value/u);
  assert.match(functionBody(sql, "agentpass_platform_session_find_active"), /idle_expires_at > now_value/u);
  assert.match(functionBody(sql, "agentpass_platform_session_touch"), /FOR UPDATE/u);
  const issue = functionBody(sql, "agentpass_platform_session_issue");
  assert.ok(
    issue.indexOf("FROM platform_sessions") < issue.indexOf("FROM platform_principals"),
    "lost-response replay must be resolved before mutable authority is consulted"
  );
  assert.match(issue, /assignment_row\.issued_at > now_value/u);
});

test("0053 keeps SECURITY DEFINER routines narrow and search_path fixed", async () => {
  const sql = await readMigration();
  const definitions = functionDefinitions(sql);
  const securityDefiners = definitions.filter(({ body }) => /SECURITY DEFINER/u.test(body));
  assert.ok(securityDefiners.length >= 7);
  for (const definition of definitions) {
    assert.match(definition.body, /SET search_path = pg_catalog, public/u, `search_path missing for ${definition.name}`);
  }
  for (const definition of securityDefiners) {
    assert.match(sql, new RegExp(
      `REVOKE ALL PRIVILEGES ON FUNCTION public\\.${definition.name}\\(${signaturePattern(definition.signature)}\\) FROM PUBLIC`,
      "u"
    ));
  }
  assert.match(sql, /REVOKE ALL PRIVILEGES ON TABLE[\s\S]*platform_credentials[\s\S]*platform_sessions[\s\S]*FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup/u);
  assert.doesNotMatch(sql, /GRANT\s+(?:SELECT|INSERT|UPDATE|DELETE|ALL)[^;]*ON\s+TABLE[^;]*TO\s+agentpass_app/iu);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_platform_session_find_active\(bytea, uuid, text, text\) TO agentpass_migrator, agentpass_app/u);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_platform_session_touch\(bytea, uuid, text, text\) TO agentpass_migrator, agentpass_app/u);
  for (const signature of [
    "agentpass_platform_credential_provision(uuid, uuid, uuid, bytea, text)",
    "agentpass_platform_credential_advance_sign_count(uuid, bigint)",
    "agentpass_platform_credential_revoke(uuid, text)",
    "agentpass_platform_session_issue(uuid, bytea, uuid, uuid, uuid, uuid, uuid, text, text, integer, integer)",
    "agentpass_platform_session_revoke(uuid, text)"
  ]) {
    assert.match(sql, new RegExp(`GRANT EXECUTE ON FUNCTION public\\.${signature.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")} TO agentpass_migrator`, "u"));
    assert.doesNotMatch(sql, new RegExp(`GRANT EXECUTE ON FUNCTION public\\.${signature.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")} TO [^;]*agentpass_app`, "u"));
  }
});
