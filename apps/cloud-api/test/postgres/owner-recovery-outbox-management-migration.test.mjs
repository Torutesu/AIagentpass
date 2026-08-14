import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { loadSqlMigrations } from "../../src/postgres/migration-runner.mjs";

const migrationUrl = new URL("../../../../contracts/postgres/0030_owner_recovery_outbox_management.sql", import.meta.url);

test("0030 is a transactional, non-destructive management-invariant migration", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN)|TRUNCATE/iu);
  assert.match(sql, /UPDATE owner_recovery_outbox[\s\S]*SET total_attempts = attempts/);
  assert.match(sql, /ALTER COLUMN total_attempts SET NOT NULL/);
});

test("0030 binds outbox request and subject as one tenant-qualified identity", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /UNIQUE \(organization_id, request_id, subject_member_id\)/);
  assert.match(sql, /FOREIGN KEY \(organization_id, request_id, subject_member_id\)[\s\S]*REFERENCES owner_recovery_requests \(organization_id, request_id, subject_member_id\)/);
  assert.match(sql, /owner_recovery_outbox_identity_immutable/);
  for (const field of ["organization_id", "event_id", "request_id", "subject_member_id", "event_type", "created_at"]) {
    assert.match(sql, new RegExp(`NEW\\.${field} IS DISTINCT FROM OLD\\.${field}`));
  }
  assert.match(sql, /CREATE TRIGGER owner_recovery_outbox_identity_guard/);
});

test("0030 enforces bounded management counters and preserves existing attempts", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /management_version integer NOT NULL DEFAULT 1/);
  assert.match(sql, /management_version >= 1/);
  assert.match(sql, /redrive_count integer NOT NULL DEFAULT 0/);
  assert.match(sql, /redrive_count BETWEEN 0 AND 3/);
  assert.match(sql, /total_attempts >= attempts/);
  assert.match(sql, /agentpass_normalize_owner_recovery_outbox_attempts/);
  assert.match(sql, /OLD\.total_attempts \+ \(NEW\.attempts - OLD\.attempts\)/);
  assert.match(sql, /owner_recovery_outbox_total_attempts_monotonic/);
  assert.match(sql, /suppression_reason[\s\S]*octet_length\(suppression_reason\) BETWEEN 1 AND 128/);
});

test("0030 makes suppression terminal and indexes tenant management paths", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /status IN \('pending', 'published', 'dead_letter', 'suppressed'\)/);
  assert.match(sql, /status = 'suppressed' AND published_at IS NULL[\s\S]*claim_token_digest IS NULL/);
  assert.match(sql, /status = 'suppressed' AND suppressed_at IS NOT NULL AND suppression_reason IS NOT NULL/);
  assert.match(sql, /status <> 'suppressed' AND suppressed_at IS NULL AND suppression_reason IS NULL/);
  assert.match(sql, /owner_recovery_outbox_suppressed_terminal/);
  assert.match(sql, /CREATE TRIGGER owner_recovery_outbox_suppressed_guard/);
  assert.match(sql, /CREATE INDEX owner_recovery_outbox_dead_letter_tenant_page[\s\S]*WHERE status = 'dead_letter'/);
  assert.match(sql, /CREATE INDEX owner_recovery_outbox_pending_health[\s\S]*WHERE status = 'pending'/);
});

test("0030 is loaded as migration 30 with a content-derived checksum", async () => {
  const migrations = await loadSqlMigrations();
  const migration = migrations.find((item) => item.version === 30);
  assert.equal(migration?.name, "0030_owner_recovery_outbox_management.sql");
  assert.match(migration?.checksum ?? "", /^[0-9a-f]{64}$/);
});
