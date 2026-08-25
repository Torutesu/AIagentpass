import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const migrationDirectory = path.join(root, "contracts", "postgres");

function readMigration(name) {
  return fs.readFileSync(path.join(migrationDirectory, name), "utf8");
}

function withoutSqlComments(sql) {
  return sql
    .replace(/\/\*[\s\S]*?\*\//gu, "")
    .replace(/--[^\n]*/gu, "");
}

function tableColumns(sql, table) {
  const source = withoutSqlComments(sql);
  const match = source.match(new RegExp(`CREATE TABLE ${table} \\(([\\s\\S]*?)\\n\\);`, "u"));
  assert.ok(match, `${table} table definition must exist`);
  return new Set([...match[1].matchAll(/^\s{2}([a-z][a-z0-9_]*)\s+/gmu)].map((item) => item[1]));
}

function assertTransactional(sql, name) {
  assert.match(sql, /^BEGIN;\s/iu, `${name} must begin a transaction`);
  assert.match(sql, /COMMIT;\s*$/iu, `${name} must commit a transaction`);
  assert.doesNotMatch(sql, /\b(?:DROP\s+(?:TABLE|COLUMN)|TRUNCATE)\b/iu, `${name} must be forward-only`);
}

const grantSql = readMigration("0018_agent_session_grants.sql");
const sessionSql = readMigration("0019_agent_sessions.sql");
const auditSql = readMigration("0020_agent_audit_binding.sql");
const authorityGenerationSql = readMigration("0021_agent_session_authority_generation.sql");
const cloudAuditSql = readMigration("0022_cloud_agent_audit.sql");

test("M2 migrations are ordered, transactional, and non-destructive", () => {
  for (const [name, sql] of [
    ["0018_agent_session_grants.sql", grantSql],
    ["0019_agent_sessions.sql", sessionSql],
    ["0020_agent_audit_binding.sql", auditSql],
    ["0021_agent_session_authority_generation.sql", authorityGenerationSql],
    ["0022_cloud_agent_audit.sql", cloudAuditSql]
  ]) assertTransactional(sql, name);

  assert.ok(fs.existsSync(path.join(migrationDirectory, "0017_device_possession_verification.sql")));
  const orderedMigrations = fs.readdirSync(migrationDirectory)
    .filter((name) => /^00(?:1[89]|2[0-2])_[a-z0-9_]+\.sql$/u.test(name))
    .sort();
  assert.deepEqual(
    orderedMigrations,
    ["0018_agent_session_grants.sql", "0019_agent_sessions.sql", "0020_agent_audit_binding.sql", "0021_agent_session_authority_generation.sql", "0022_cloud_agent_audit.sql"]
  );
});

test("grant schema binds one tenant/device/agent identity and excludes secret-bearing columns", () => {
  const columns = tableColumns(grantSql, "agent_session_grants");
  columns.add("authority_generation");
  for (const column of [
    "organization_id", "grant_id", "device_id", "agent_id", "agent_kind", "adapter_id",
    "worktree_binding_sha256", "process_binding_policy_id", "scope_json", "max_signatures",
    "not_before", "expires_at", "control_sequence", "grant_hash", "statement_hash",
    "authority_generation",
    "signature_base64url", "status", "consumed_at", "consumed_session_id", "expired_at",
    "consumed_process_binding_sha256", "revoked_at", "created_by"
  ]) assert.ok(columns.has(column), `grant column ${column} is required`);

  const forbidden = /(?:^|_)(?:private(?:_key)?|secret|token|credential|password|raw_audit_token|argv|environment|payload)(?:_|$)/iu;
  for (const column of columns) assert.doesNotMatch(column, forbidden, `grant column ${column} must not hold secret material`);

  assert.match(grantSql, /FOREIGN KEY \(organization_id, device_id\)\s+REFERENCES devices\(organization_id, id\)/iu);
  assert.match(grantSql, /FOREIGN KEY \(organization_id, agent_id, device_id\)\s+REFERENCES agents\(organization_id, id, device_id\)/iu);
  assert.match(authorityGenerationSql, /ALTER TABLE agent_session_grants[\s\S]*ADD COLUMN authority_generation bigint/iu);
  assert.match(authorityGenerationSql, /agent_session_grants_authority_generation_positive[\s\S]*CHECK \(authority_generation > 0\)/iu);
  assert.match(authorityGenerationSql, /FOREIGN KEY \(organization_id, authority_generation\)\s+REFERENCES control_plane_authority_generations\(organization_id, generation\)/iu);
  assert.match(grantSql, /FOREIGN KEY \(organization_id, created_by\)\s+REFERENCES memberships\(organization_id, member_id\)/iu);
  assert.match(grantSql, /UNIQUE \(organization_id, grant_id, device_id, agent_id\)/iu);
  assert.match(grantSql, /UNIQUE \(organization_id, consumed_session_id\)/iu);
  assert.match(grantSql, /consumed_process_binding_sha256 text[\s\S]*\^\[0-9a-f\]\{64\}\$/iu);
  assert.match(grantSql, /status = 'consumed'[\s\S]*consumed_process_binding_sha256 IS NOT NULL/iu);
  assert.match(grantSql, /NEW\.consumed_process_binding_sha256 IS DISTINCT FROM OLD\.consumed_process_binding_sha256/iu);
  assert.match(authorityGenerationSql, /NEW\.authority_generation <> OLD\.authority_generation/iu);
  assert.match(grantSql, /scope_json jsonb NOT NULL[\s\S]*agentpass_public_scope_json_valid/iu);
  assert.match(grantSql, /grant_hash text NOT NULL[\s\S]*\^\[0-9a-f\]\{64\}\$/iu);
});

test("grant lifecycle is immutable, one-way, time-bounded, and tenant-isolated", () => {
  assert.match(grantSql, /status IN \('issued', 'consumed', 'expired', 'revoked'\)/iu);
  assert.match(grantSql, /status = 'issued'[\s\S]*consumed_at IS NULL[\s\S]*expired_at IS NULL[\s\S]*revoked_at IS NULL/iu);
  assert.match(grantSql, /status = 'consumed'[\s\S]*consumed_session_id IS NOT NULL[\s\S]*consumed_at <= expires_at/iu);
  assert.match(grantSql, /status = 'expired'[\s\S]*expired_at >= expires_at/iu);
  assert.match(grantSql, /agentpass_guard_agent_session_grant_forward_only/iu);
  assert.match(grantSql, /OLD\.status <> 'issued' OR NEW\.status NOT IN \('consumed', 'expired', 'revoked'\)/iu);
  assert.match(grantSql, /clock_timestamp\(\) < OLD\.expires_at/iu);
  assert.match(grantSql, /CHECK \(not_before <= issued_at \+ interval '5 minutes'\)/iu);
  assert.doesNotMatch(grantSql, /CHECK \(not_before >= issued_at\)/iu);
  assert.match(grantSql, /ALTER TABLE agent_session_grants ENABLE ROW LEVEL SECURITY/iu);
  assert.match(grantSql, /ALTER TABLE agent_session_grants FORCE ROW LEVEL SECURITY/iu);
  assert.match(grantSql, /organization_id = agentpass_current_organization_id\(\)/iu);
  assert.match(grantSql, /WITH CHECK \(organization_id = agentpass_current_organization_id\(\)\)/iu);
});

test("session schema enforces grant identity, one active session, and used<=max", () => {
  const columns = tableColumns(sessionSql, "agent_sessions");
  columns.add("authority_generation");
  for (const column of [
    "organization_id", "session_id", "grant_id", "device_id", "agent_id", "adapter_id", "grant_hash",
    "process_binding_sha256", "ancestry_binding_sha256", "worktree_binding_sha256",
    "control_sequence", "authority_generation", "max_signatures", "used_signatures", "reserved_signatures",
    "status", "active_request_id", "last_request_id", "not_before", "expires_at"
  ]) assert.ok(columns.has(column), `session column ${column} is required`);

  const forbidden = /(?:^|_)(?:private(?:_key)?|secret|token|credential|password|raw_audit_token|argv|environment|payload)(?:_|$)/iu;
  for (const column of columns) assert.doesNotMatch(column, forbidden, `session column ${column} must not hold secret material`);

  assert.match(sessionSql, /FOREIGN KEY \(organization_id, grant_id, device_id, agent_id, grant_hash\)\s+REFERENCES agent_session_grants\(organization_id, grant_id, device_id, agent_id, grant_hash\)/iu);
  assert.match(authorityGenerationSql, /ALTER TABLE agent_sessions[\s\S]*ADD COLUMN authority_generation bigint/iu);
  assert.match(authorityGenerationSql, /agent_sessions_authority_generation_positive[\s\S]*CHECK \(authority_generation > 0\)/iu);
  assert.match(authorityGenerationSql, /FOREIGN KEY \(organization_id, authority_generation\)\s+REFERENCES control_plane_authority_generations\(organization_id, generation\)/iu);
  assert.match(sessionSql, /NEW\.not_before <> grant_row\.not_before/iu);
  assert.match(sessionSql, /NEW\.not_before <> OLD\.not_before/iu);
  assert.match(sessionSql, /UNIQUE \(organization_id, grant_id\)/iu);
  assert.match(sessionSql, /CREATE UNIQUE INDEX agent_sessions_one_active_per_grant[\s\S]*WHERE status IN \('challenge_pending', 'active', 'request_reserved', 'signing_intent', 'signed'\)/iu);
  assert.match(sessionSql, /CREATE UNIQUE INDEX agent_sessions_grant_process_binding_identity[\s\S]*ON agent_sessions \(organization_id, grant_hash, process_binding_sha256\)/iu);
  assert.match(sessionSql, /CHECK \(used_signatures <= max_signatures\)/iu);
  assert.match(sessionSql, /CHECK \(used_signatures \+ reserved_signatures <= max_signatures\)/iu);
  assert.match(sessionSql, /SELECT grant_record\.\* INTO grant_row[\s\S]*FOR UPDATE/iu);
  assert.match(sessionSql, /UPDATE agent_session_grants[\s\S]*SET status = 'consumed'[\s\S]*consumed_session_id = NEW\.session_id/iu);
  assert.match(sessionSql, /consumed_process_binding_sha256 = NEW\.process_binding_sha256/iu);
  assert.match(sessionSql, /NEW\.grant_hash <> grant_row\.grant_hash/iu);
  assert.match(authorityGenerationSql, /NEW\.authority_generation <> grant_generation/iu);
  assert.match(authorityGenerationSql, /NEW\.authority_generation <> OLD\.authority_generation/iu);
  assert.match(sessionSql, /serialization_failure/iu);
});

test("session lifecycle has strict forward-only states, expiry, replay correlation, and RLS", () => {
  assert.match(sessionSql, /status IN \([\s\S]*'outcome_unknown'[\s\S]*\)/iu);
  assert.match(sessionSql, /OLD\.status = 'active'[\s\S]*NEW\.status IN \('request_reserved', 'expired', 'revoked', 'process_lost', 'closed'\)/iu);
  assert.match(sessionSql, /OLD\.status = 'signing_intent'[\s\S]*NEW\.status IN \('signed', 'outcome_unknown'\)/iu);
  assert.match(sessionSql, /terminal agent sessions cannot be reactivated/iu);
  assert.match(sessionSql, /clock_timestamp\(\) < OLD\.expires_at/iu);
  assert.match(sessionSql, /NEW\.last_request_id IS DISTINCT FROM OLD\.active_request_id/iu);
  assert.match(sessionSql, /ALTER TABLE agent_sessions ENABLE ROW LEVEL SECURITY/iu);
  assert.match(sessionSql, /ALTER TABLE agent_sessions FORCE ROW LEVEL SECURITY/iu);
  assert.match(sessionSql, /CREATE POLICY agent_sessions_tenant_select/iu);
  assert.match(sessionSql, /CREATE POLICY agent_sessions_tenant_update/iu);
  assert.match(sessionSql, /DEFERRABLE INITIALLY DEFERRED/iu);
});

test("audit binding stores only public ids/digests and preserves tenant identity", () => {
  const addedColumns = [...auditSql.matchAll(/ADD COLUMN\s+([a-z][a-z0-9_]*)\s+/giu)].map((item) => item[1]);
  assert.deepEqual(addedColumns, [
    "session_id", "grant_id", "adapter_id", "adapter_kind", "process_binding_sha256",
    "ancestry_binding_sha256", "worktree_binding_sha256", "capability_id", "capability_sequence"
  ]);
  const forbidden = /(?:^|_)(?:private(?:_key)?|secret|token|credential|password|raw_audit_token|argv|environment|payload)(?:_|$)/iu;
  for (const column of addedColumns) assert.doesNotMatch(column, forbidden, `audit column ${column} must not hold secret material`);

  assert.match(auditSql, /device_audit_events_m2_binding_complete[\s\S]*session_id IS NOT NULL[\s\S]*process_binding_sha256 IS NOT NULL[\s\S]*worktree_binding_sha256 IS NOT NULL/iu);
  assert.match(auditSql, /FOREIGN KEY \(organization_id, grant_id\)\s+REFERENCES agent_session_grants\(organization_id, grant_id\)/iu);
  assert.match(auditSql, /FOREIGN KEY \(organization_id, session_id, grant_id, device_id\)\s+REFERENCES agent_sessions\(organization_id, session_id, grant_id, device_id\)/iu);
  assert.match(auditSql, /FOREIGN KEY \(organization_id, capability_id, capability_sequence\)\s+REFERENCES capabilities\(organization_id, id, sequence\)/iu);
  assert.match(auditSql, /CREATE INDEX device_audit_events_agent_session_lookup/iu);
  assert.doesNotMatch(auditSql, /ALTER TABLE device_audit_events (?:ENABLE|FORCE) ROW LEVEL SECURITY/iu);
  assert.match(auditSql, /every added foreign key is tenant-qualified/iu);
});

test("Cloud audit is a separate tenant-isolated consume hash chain", () => {
  const eventColumns = tableColumns(cloudAuditSql, "cloud_agent_audit_events");
  const headColumns = tableColumns(cloudAuditSql, "cloud_agent_audit_heads");
  for (const column of [
    "organization_id", "event_id", "sequence", "event_type", "grant_id", "session_id",
    "device_id", "agent_id", "grant_hash", "statement_hash", "signer_key_id",
    "process_binding_sha256", "ancestry_binding_sha256", "worktree_binding_sha256",
    "control_sequence", "authority_generation", "consumed_at", "previous_hash", "event_hash", "recorded_at"
  ]) assert.ok(eventColumns.has(column), `cloud audit event column ${column} is required`);
  for (const column of ["organization_id", "sequence", "last_event_id", "last_event_hash", "updated_at"])
    assert.ok(headColumns.has(column), `cloud audit head column ${column} is required`);

  const forbidden = /(?:^|_)(?:private(?:_key)?|secret|token|credential|password|raw_audit_token|argv|environment|payload)(?:_|$)/iu;
  for (const column of [...eventColumns, ...headColumns]) assert.doesNotMatch(column, forbidden, `cloud audit column ${column} must not hold secret material`);

  assert.doesNotMatch(cloudAuditSql, /device_audit_(?:events|heads)/iu);
  assert.match(cloudAuditSql, /event_type text NOT NULL CHECK \(event_type = 'agent_session_grant\.consumed'\)/iu);
  assert.match(cloudAuditSql, /UNIQUE \(organization_id, grant_id\)/iu);
  assert.match(cloudAuditSql, /FOREIGN KEY \(organization_id, grant_id, device_id, agent_id, grant_hash\)\s+REFERENCES agent_session_grants\(organization_id, grant_id, device_id, agent_id, grant_hash\)/iu);
  assert.match(cloudAuditSql, /FOREIGN KEY \(organization_id, session_id, grant_id, device_id\)\s+REFERENCES agent_sessions\(organization_id, session_id, grant_id, device_id\)/iu);
  assert.match(cloudAuditSql, /sequence bigint NOT NULL CHECK \(sequence > 0\)/iu);
  assert.match(cloudAuditSql, /last_event_hash text NOT NULL DEFAULT repeat\('0', 64\)[\s\S]*CHECK \(last_event_hash ~ '\^\[0-9a-f\]\{64\}\$'\)/iu);
  assert.match(cloudAuditSql, /NEW\.sequence <> head\.sequence \+ 1[\s\S]*NEW\.previous_hash <> head\.last_event_hash/iu);
  assert.match(cloudAuditSql, /CREATE TRIGGER cloud_agent_audit_events_record_head/iu);
  assert.match(cloudAuditSql, /cloud_agent_audit_events_append_only/iu);
  assert.match(cloudAuditSql, /cloud_agent_audit_heads_forward_only/iu);
  for (const table of ["cloud_agent_audit_events", "cloud_agent_audit_heads"]) {
    assert.match(cloudAuditSql, new RegExp(`ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY`, "iu"));
    assert.match(cloudAuditSql, new RegExp(`ALTER TABLE ${table} FORCE ROW LEVEL SECURITY`, "iu"));
    assert.match(cloudAuditSql, new RegExp(`CREATE POLICY ${table}_tenant_select`, "iu"));
    assert.match(cloudAuditSql, new RegExp(`organization_id = agentpass_current_organization_id\\(\\)`, "iu"));
  }
});
