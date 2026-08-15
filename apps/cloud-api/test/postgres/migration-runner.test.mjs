import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  MigrationChecksumError,
  MigrationDirtyError,
  MigrationRunnerError,
  createMigrationRunner,
  defaultContractDirectory,
  loadSqlMigrations,
  migrationChecksum,
  runMigrations,
  stripTransactionEnvelope
} from "../../src/postgres/index.mjs";
import { FakePgClient } from "./fake-client.mjs";

const SQL_ONE = "BEGIN;\nCREATE TABLE example_one (id integer);\nCOMMIT;\n";
const SQL_TWO = "BEGIN;\nCREATE TABLE example_two (id integer);\nCOMMIT;\n";
const migrations = [
  { name: "0001_example_one.sql", sql: SQL_ONE },
  { name: "0002_example_two.sql", sql: SQL_TWO }
];

test("runs ordered migrations under one advisory-locked transaction and records exact checksums", async () => {
  const client = new FakePgClient({ schemaMigrationsExists: false });
  const result = await runMigrations({ client, migrations, applicationVersion: "test-1" });
  assert.deepEqual(result.applied.map(({ version, checksum }) => ({ version, checksum })), [
    { version: 1, checksum: migrationChecksum(SQL_ONE) },
    { version: 2, checksum: migrationChecksum(SQL_TWO) }
  ]);
  assert.equal(result.currentVersion, 2);
  assert.equal(client.calls[0].text, "BEGIN");
  assert.match(client.calls[1].text, /pg_advisory_xact_lock/);
  assert.deepEqual(client.calls.at(-1), { text: "COMMIT", params: [] });
  assert.equal(client.calls.filter(({ text }) => text.startsWith("CREATE TABLE")).length, 2);
  assert.deepEqual(client.calls.filter(({ text }) => text.startsWith("INSERT INTO schema_migrations")).map(({ params }) => params[2] ?? "legacy"), ["legacy", "test-1"]);
  assert.ok(client.calls.every(({ params }) => Array.isArray(params)), "every injected query receives params");
  assert.deepEqual(client.calls.filter(({ text }) => text === "SELECT to_regclass($1) AS relation").map(({ params }) => params[0]), ["schema_migrations", "schema_migration_attempts"]);
  assert.equal(client.calls.some(({ text }) => text.startsWith("SELECT version, checksum FROM schema_migrations")), false, "a missing relation is never queried inside the transaction");
});

test("is idempotent for an unchanged history", async () => {
  const client = new FakePgClient({ applied: migrations.map((migration, index) => ({ version: index + 1, checksum: migrationChecksum(migration.sql) })) });
  const result = await runMigrations({ client, migrations });
  assert.deepEqual(result.applied, []);
  assert.equal(client.calls.filter(({ text }) => text.startsWith("CREATE TABLE")).length, 0);
});

test("fails closed on checksum drift and rolls back", async () => {
  const client = new FakePgClient({ applied: [{ version: 1, checksum: "a".repeat(64) }] });
  await assert.rejects(runMigrations({ client, migrations }), MigrationChecksumError);
  assert.equal(client.calls.at(-1).text, "ROLLBACK");
  assert.equal(client.calls.some(({ text }) => text.startsWith("CREATE TABLE")), false);
});

test("fails closed when migration attempts report dirty state", async () => {
  const client = new FakePgClient({ migrationAttemptsExists: true, dirty: [{ version: 1, checksum: migrationChecksum(SQL_ONE), status: "failed", finished_at: "now" }] });
  await assert.rejects(runMigrations({ client, migrations }), MigrationDirtyError);
  assert.equal(client.calls.at(-1).text, "ROLLBACK");
});

test("fails closed on an unknown or out-of-order applied version", async () => {
  const client = new FakePgClient({ applied: [{ version: 3, checksum: "b".repeat(64) }] });
  await assert.rejects(runMigrations({ client, migrations }), (error) => error.code === "ERR_MIGRATION_HISTORY");
  assert.equal(client.calls.at(-1).text, "ROLLBACK");
});

test("loads the reviewed contract migrations in contiguous order without rewriting their SQL", async () => {
  const loaded = await loadSqlMigrations(defaultContractDirectory());
  assert.deepEqual(loaded.map((migration) => migration.name), ["0001_control_plane.sql", "0002_webauthn_challenges.sql", "0003_webauthn_challenge_bindings.sql", "0004_human_identity_and_webauthn_registration.sql", "0005_human_credential_session_management.sql", "0006_organization_membership_invitations.sql", "0007_capability_membership_authority.sql", "0008_capability_revocation_bundle_lookup.sql", "0009_human_identity_assertion_replays.sql", "0010_device_audit_activity_keyset.sql", "0011_control_plane_hosted_cutover.sql", "0012_device_refresh_authority.sql", "0013_refresh_nonce_key_id.sql", "0014_refresh_hint_notify.sql", "0015_refresh_state_rollover.sql", "0016_device_manual_wake.sql", "0017_device_possession_verification.sql", "0018_agent_session_grants.sql", "0019_agent_sessions.sql", "0020_agent_audit_binding.sql", "0021_agent_session_authority_generation.sql", "0022_cloud_agent_audit.sql", "0023_qualification_grant_batches.sql", "0024_human_session_epochs.sql", "0025_threshold_owner_recovery.sql", "0026_owner_recovery_webauthn.sql", "0027_owner_recovery_idempotency.sql", "0028_anonymous_rate_limits.sql", "0029_owner_recovery_outbox_delivery.sql", "0030_owner_recovery_outbox_management.sql", "0031_resource_bound_recent_authorization.sql", "0032_owner_recovery_outbox_retention.sql", "0033_shared_abuse_control_hardening.sql", "0034_owner_recovery_outbox_uncertain.sql", "0035_owner_recovery_delivery_binding_ledger.sql", "0036_owner_recovery_provider_confirmation.sql", "0037_managed_signer_lifecycle.sql", "0038_managed_signer_fencing.sql", "0039_managed_signer_provider_receipts.sql", "0040_managed_signer_provider_operations.sql", "0041_managed_signer_provider_operation_maintenance.sql", "0042_managed_signer_provider_operation_query_indexes.sql", "0043_audit_export_issuance.sql", "0044_platform_promotion_approvals.sql", "0045_device_audit_export_sequence.sql", "0046_audit_export_payloads.sql", "0047_platform_promotion_issuance.sql"]);
  assert.match(loaded[0].sql, /^BEGIN;/);
  assert.match(loaded[0].sql, /CREATE TABLE schema_migrations/);
  assert.match(loaded[0].sql.trim(), /COMMIT;$/);
});

test("migration 0006 defines tenant-scoped invitations, audit heads, outbox delivery, and owner protection", async () => {
  const sql = await readFile(new URL("../../../../contracts/postgres/0006_organization_membership_invitations.sql", import.meta.url), "utf8");
  const invitations = sql.slice(sql.indexOf("CREATE TABLE organization_invitations"), sql.indexOf("CREATE TABLE admin_audit_heads"));

  assert.match(invitations, /organization_id uuid NOT NULL REFERENCES organizations\(id\)/);
  assert.match(invitations, /id uuid NOT NULL/);
  assert.match(invitations, /token_hash bytea NOT NULL UNIQUE CHECK \(octet_length\(token_hash\) = 32\)/);
  assert.match(invitations, /role text NOT NULL CHECK \(role IN \('admin', 'auditor', 'viewer'\)\)/);
  assert.doesNotMatch(invitations, /role IN \([^)]*'owner'/);
  assert.match(invitations, /created_by uuid NOT NULL REFERENCES members\(id\)/);
  assert.match(invitations, /version bigint NOT NULL DEFAULT 1 CHECK \(version > 0\)/);
  assert.match(invitations, /created_at timestamptz NOT NULL DEFAULT clock_timestamp\(\)/);
  assert.match(invitations, /updated_at timestamptz NOT NULL DEFAULT clock_timestamp\(\)/);
  assert.match(invitations, /FOREIGN KEY \(organization_id, created_by\) REFERENCES memberships\(organization_id, member_id\)/);
  assert.match(invitations, /FOREIGN KEY \(organization_id, consumed_by\) REFERENCES memberships\(organization_id, member_id\)/);
  assert.match(invitations, /FOREIGN KEY \(organization_id, revoked_by\) REFERENCES memberships\(organization_id, member_id\)/);
  assert.match(invitations, /consumed_by IS NULL AND consumed_at IS NULL/);
  assert.match(invitations, /revoked_by IS NULL AND revoked_at IS NULL AND revoke_reason IS NULL/);
  assert.match(invitations, /NOT \(consumed_at IS NOT NULL AND revoked_at IS NOT NULL\)/);
  assert.match(invitations, /CREATE INDEX organization_invitations_active_lookup/);
  assert.match(invitations, /CREATE INDEX organization_invitations_expiry_lookup/);

  assert.match(sql, /CREATE TABLE admin_audit_heads \([\s\S]*organization_id uuid PRIMARY KEY REFERENCES organizations\(id\)/);
  assert.match(sql, /sequence bigint NOT NULL DEFAULT 0 CHECK \(sequence >= 0\)/);
  assert.match(sql, /event_hash text NOT NULL DEFAULT repeat\('0', 64\) CHECK \(event_hash ~ '\^\[0-9a-f\]\{64\}\$'\)/);
  assert.match(sql, /ALTER TABLE admin_audit_events[\s\S]*ADD COLUMN sequence bigint[\s\S]*ADD COLUMN event_json jsonb/);
  assert.match(sql, /INSERT INTO admin_audit_heads \(organization_id,sequence,event_hash\)[\s\S]*LEFT JOIN LATERAL/);

  assert.match(sql, /aggregate text NOT NULL CHECK \(char_length\(aggregate\) BETWEEN 1 AND 128\)/);
  assert.match(sql, /action text NOT NULL CHECK \(char_length\(action\) BETWEEN 1 AND 128\)/);
  assert.match(sql, /payload jsonb NOT NULL CHECK \(jsonb_typeof\(payload\) = 'object'\)/);
  assert.match(sql, /status text NOT NULL DEFAULT 'pending' CHECK \(status IN \('pending', 'published'\)\)/);
  assert.match(sql, /attempts integer NOT NULL DEFAULT 0 CHECK \(attempts BETWEEN 0 AND 100\)/);
  assert.match(sql, /available_at timestamptz NOT NULL DEFAULT clock_timestamp\(\)/);
  assert.match(sql, /published_at timestamptz/);
  assert.match(sql, /status = 'pending' AND published_at IS NULL/);
  assert.match(sql, /status = 'published' AND published_at IS NOT NULL/);
  assert.match(sql, /CREATE INDEX outbox_events_pending_delivery[\s\S]*WHERE status = 'pending'/);
  assert.match(sql, /CREATE INDEX outbox_events_organization_pending[\s\S]*WHERE status = 'pending'/);

  assert.match(sql, /CREATE FUNCTION agentpass_prevent_last_active_owner\(\)/);
  assert.match(sql, /pg_advisory_xact_lock\([\s\S]*hashtextextended\('agentpass:memberships:owners:' \|\| OLD\.organization_id::text, 0\)/);
  assert.match(sql, /CREATE TRIGGER memberships_protect_last_active_owner\s+BEFORE UPDATE OF organization_id, role, status OR DELETE ON memberships\s+FOR EACH ROW\s+EXECUTE FUNCTION agentpass_prevent_last_active_owner\(\)/);
  assert.match(sql, /ERRCODE = 'check_violation'/);
  assert.match(sql, /CONSTRAINT = 'memberships_last_active_owner'/);
});

test("migration 0005 preserves version defaults and protects the final active credential", async () => {
  const sql = await readFile(new URL("../../../../contracts/postgres/0005_human_credential_session_management.sql", import.meta.url), "utf8");

  assert.match(sql, /ALTER TABLE webauthn_credentials\s+ADD COLUMN version bigint NOT NULL DEFAULT 1/);
  assert.match(sql, /ALTER TABLE human_sessions\s+ADD COLUMN version bigint NOT NULL DEFAULT 1/);
  assert.match(sql, /webauthn_credentials_version_valid CHECK \(version > 0\)/);
  assert.match(sql, /human_sessions_version_valid CHECK \(version > 0\)/);
  assert.doesNotMatch(sql, /ALTER TABLE (?:webauthn_credentials|human_sessions)[\s\S]*?version[\s\S]*?DROP DEFAULT/);

  assert.match(sql, /CREATE FUNCTION agentpass_prevent_last_webauthn_credential_revoke\(\)/);
  assert.match(sql, /ERRCODE = 'check_violation'/);
  assert.match(sql, /CONSTRAINT = 'webauthn_credentials_last_active'/);
  assert.match(sql, /MESSAGE = 'cannot revoke the last active WebAuthn credential'/);
  assert.match(sql, /CREATE TRIGGER webauthn_credentials_protect_last_active/);
  assert.match(sql, /BEFORE UPDATE OF revoked_at ON webauthn_credentials/);
  assert.match(sql, /WHEN \(OLD\.revoked_at IS NULL AND NEW\.revoked_at IS NOT NULL\)/);
});

test("migration 0008 indexes unexpired revoked capabilities for bounded ControlBundle reads", async () => {
  const sql = await readFile(new URL("../../../../contracts/postgres/0008_capability_revocation_bundle_lookup.sql", import.meta.url), "utf8");
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/);
  assert.match(sql, /CREATE INDEX capabilities_revoked_bundle_lookup/);
  assert.match(sql, /ON capabilities \(organization_id, expires_at, id\)/);
  assert.match(sql, /WHERE revoked_at IS NOT NULL/);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN)|TRUNCATE/iu);
});

test("migration 0009 stores only namespaced jti replay state and provides atomic one-time consume", async () => {
  const sql = await readFile(new URL("../../../../contracts/postgres/0009_human_identity_assertion_replays.sql", import.meta.url), "utf8");
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/);
  assert.match(sql, /CREATE TABLE human_identity_assertion_replays \(/);
  assert.match(sql, /jti_digest bytea PRIMARY KEY CHECK \(octet_length\(jti_digest\) = 32\)/);
  assert.match(sql, /expires_at timestamptz NOT NULL/);
  assert.doesNotMatch(sql, /consumed_at|created_at/);
  assert.doesNotMatch(sql, /subject|member_id|membership_id|role|assertion_payload|raw_jti/i);
  assert.match(sql, /CREATE INDEX human_identity_assertion_replays_expiry/);
  assert.match(sql, /CREATE FUNCTION agentpass_consume_human_identity_assertion\(/);
  assert.match(sql, /ON CONFLICT \(jti_digest\) DO NOTHING/);
  assert.match(sql, /RETURN FOUND/);
  assert.match(sql, /assertion_expires_at <= clock_timestamp\(\)/);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN)|TRUNCATE/iu);
});

test("migration 0011 closes the hosted control-plane schema gaps transactionally", async () => {
  const sql = await readFile(new URL("../../../../contracts/postgres/0011_control_plane_hosted_cutover.sql", import.meta.url), "utf8");
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/);
  assert.match(sql, /devices[\s\S]*ADD COLUMN metadata jsonb NOT NULL/);
  assert.match(sql, /devices_pending_key_state/);
  assert.match(sql, /devices[\s\S]*ALTER COLUMN key_algorithm DROP NOT NULL/);
  assert.match(sql, /device_enrollments[\s\S]*ADD COLUMN label text[\s\S]*ADD COLUMN platform text[\s\S]*ADD COLUMN completion_hash text/);
  assert.doesNotMatch(sql, /completed_by/);
  assert.match(sql, /device_enrollments_completion_evidence_complete/);
  assert.match(sql, /policies[\s\S]*ADD COLUMN version bigint NOT NULL DEFAULT 1[\s\S]*ADD COLUMN updated_at timestamptz/);
  assert.match(sql, /revocations[\s\S]*ADD COLUMN revoked_by uuid[\s\S]*ADD COLUMN revoked_at timestamptz[\s\S]*ADD COLUMN version bigint/);
  assert.match(sql, /issued_by_member_id/);
  assert.match(sql, /issued_membership_version/);
  assert.match(sql, /capabilities[\s\S]*ADD COLUMN issuer text[\s\S]*ADD COLUMN key_id text[\s\S]*ADD COLUMN scope_json jsonb[\s\S]*ADD COLUMN nonce_digest bytea/);
  assert.match(sql, /bundle_heads[\s\S]*ADD COLUMN expires_at timestamptz[\s\S]*ALTER COLUMN expires_at SET NOT NULL/);
  assert.match(sql, /bundle_acknowledgements_head_fk[\s\S]*FOREIGN KEY \(organization_id, device_id, format_epoch, sequence, statement_hash\)[\s\S]*REFERENCES bundle_heads\(organization_id, device_id, format_epoch, sequence, statement_hash\)/);
  assert.match(sql, /CREATE TABLE device_audit_heads \(/);
  assert.match(sql, /CREATE TABLE device_audit_gaps \(/);
  assert.match(sql, /CREATE TRIGGER device_audit_events_record_head/);
  assert.match(sql, /CREATE TABLE device_request_nonces \([\s\S]*nonce_digest bytea NOT NULL CHECK \(octet_length\(nonce_digest\) = 32\)/);
  assert.match(sql, /CREATE TABLE rate_limit_buckets \(/);
  assert.match(sql, /CREATE INDEX (?:idempotency_records_expiry|device_request_nonces_expiry|rate_limit_buckets_expiry)/);
  assert.match(sql, /CREATE FUNCTION agentpass_consume_device_request_nonce\(/);
  assert.match(sql, /CREATE FUNCTION agentpass_acquire_rate_limit\(/);
  assert.match(sql, /CREATE FUNCTION agentpass_prune_shared_control_expired\(/);
  assert.match(sql, /ON CONFLICT \(organization_id, device_id, nonce_digest\) DO NOTHING/);
  assert.match(sql, /FOR UPDATE/);
  assert.match(sql, /LIMIT remaining/);
  assert.doesNotMatch(sql, /raw_nonce|raw credential|private key|bearer token|session secret/i);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN)|TRUNCATE/iu);
});

test("fails closed when the database skips a migration version", async () => {
  const client = new FakePgClient({ applied: [{ version: 2, checksum: migrationChecksum(SQL_TWO) }] });
  await assert.rejects(runMigrations({ client, migrations }), (error) => error.code === "ERR_MIGRATION_HISTORY");
  assert.equal(client.calls.at(-1).text, "ROLLBACK");
});

test("rolls back a failed migration and does not leave an applied row", async () => {
  const client = new FakePgClient({ schemaMigrationsExists: false, failWhen: (text) => text.includes("example_two") ? new Error("statement failed") : undefined });
  await assert.rejects(runMigrations({ client, migrations }), (error) => error.code === "ERR_MIGRATION_FAILED");
  assert.deepEqual(client.applied, []);
  assert.equal(client.calls.at(-1).text, "ROLLBACK");
});

test("serializes concurrent calls on one runner", async () => {
  const client = new FakePgClient({ schemaMigrationsExists: false });
  const runner = createMigrationRunner({ client, migrations });
  const [first, second] = await Promise.all([runner.run(), runner.run()]);
  assert.deepEqual(first.applied.map((item) => item.version), [1, 2]);
  assert.deepEqual(second.applied.map((item) => item.version), [1, 2]);
  assert.equal(client.calls.filter(({ text }) => text === "BEGIN").length, 1);
});

test("removes only the outer transaction envelope", () => {
  assert.equal(stripTransactionEnvelope(SQL_ONE), "CREATE TABLE example_one (id integer);");
  assert.equal(stripTransactionEnvelope("BEGIN; CREATE FUNCTION f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$; COMMIT;"), "CREATE FUNCTION f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$;");
  assert.equal(stripTransactionEnvelope("BEGIN; SELECT '-----BEGIN PUBLIC KEY-----'; -- ROLLBACK\nCOMMIT;"), "SELECT '-----BEGIN PUBLIC KEY-----'; -- ROLLBACK");
  assert.throws(() => stripTransactionEnvelope("BEGIN; SELECT 1; ROLLBACK; COMMIT;"), MigrationRunnerError);
});
