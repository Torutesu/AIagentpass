import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { defaultContractDirectory, loadSqlMigrations } from "../../src/postgres/migration-runner.mjs";

const migrationUrl = new URL("../../../../contracts/postgres/0025_threshold_owner_recovery.sql", import.meta.url);

test("0025 is the contiguous current migration and remains forward-only", async () => {
  const migrations = await loadSqlMigrations(defaultContractDirectory());
  assert.equal(migrations.at(-1)?.version, 25);
  assert.equal(migrations.at(-1)?.name, "0025_threshold_owner_recovery.sql");
  assert.match(migrations.at(-1)?.sql ?? "", /^BEGIN;[\s\S]*COMMIT;\s*$/);
  assert.match(migrations.at(-1)?.sql ?? "", /owner_recovery_request_state_forward_only/);
});

test("0025 permits terminal recovery-session history after credential enrollment", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  const sessionTable = sql.slice(sql.indexOf("CREATE TABLE owner_recovery_sessions"), sql.indexOf("CREATE INDEX owner_recovery_sessions_active_lookup"));
  assert.match(sessionTable, /stage text NOT NULL DEFAULT 'session_issued'/);
  assert.match(sessionTable, /stage IN \('session_issued', 'credential_enrolled', 'activated', 'revoked', 'expired'\)/);
  assert.match(sessionTable, /stage IN \('session_issued', 'revoked', 'expired'\) AND activated_at IS NULL/);
  assert.doesNotMatch(sessionTable, /stage IN \('session_issued', 'revoked', 'expired'\)[^\n]*credential_enrolled_at IS NULL/);
  assert.match(sessionTable, /stage = 'credential_enrolled' AND credential_enrolled_at IS NOT NULL/);
  assert.match(sessionTable, /stage = 'activated' AND activated_at IS NOT NULL/);
  assert.match(sessionTable, /\(stage IN \('revoked', 'expired'\)\) = \(revoked_at IS NOT NULL\)/);
  assert.match(sql, /owner_recovery_request_state_forward_only/);
});

test("0025 keeps secret material out of durable recovery tables", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /exchange_digest bytea NOT NULL UNIQUE CHECK \(octet_length\(exchange_digest\) = 32\)/);
  assert.match(sql, /session_digest bytea NOT NULL UNIQUE CHECK \(octet_length\(session_digest\) = 32\)/);
  assert.doesNotMatch(sql, /approval_material|raw_token|notification_target|email_address|assertion bytea/iu);
  assert.match(sql, /CREATE TABLE owner_recovery_outbox/);
  assert.doesNotMatch(sql.slice(sql.indexOf("CREATE TABLE owner_recovery_outbox")), /payload jsonb|token|cookie|credential_id|challenge/iu);
});
