import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { loadSqlMigrations } from "../../src/postgres/migration-runner.mjs";

const migrationUrl = new URL("../../../../contracts/postgres/0032_owner_recovery_outbox_retention.sql", import.meta.url);

test("0032 fixes distinct terminal retention periods and a bounded skip-locked prune", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.match(sql, /status = 'published'[\s\S]*interval '30 days'/u);
  assert.match(sql, /status = 'dead_letter'[\s\S]*interval '90 days'/u);
  assert.match(sql, /status = 'suppressed'[\s\S]*interval '365 days'/u);
  assert.match(sql, /FOR UPDATE SKIP LOCKED/u);
  assert.match(sql, /prune_limit > 1000/u);
  assert.match(sql, /LIMIT prune_limit/u);
  assert.doesNotMatch(sql, /TRUNCATE|DROP\s+(?:TABLE|COLUMN)/iu);
});

test("0032 archives exact secret-free terminal evidence before deletion and makes it immutable", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /CREATE TABLE owner_recovery_outbox_retention_ledger/u);
  for (const field of ["organization_id", "event_id", "request_id", "subject_member_id", "event_type", "terminal_status", "terminal_at", "pruned_at", "total_attempts", "management_version", "redrive_count"]) {
    assert.match(sql, new RegExp(`\\b${field}\\b`, "u"));
  }
  assert.match(sql, /INSERT INTO owner_recovery_outbox_retention_ledger[\s\S]*DELETE FROM owner_recovery_outbox/u);
  assert.match(sql, /owner_recovery_outbox_retention_ledger_immutable/u);
  assert.match(sql, /BEFORE UPDATE OR DELETE ON owner_recovery_outbox_retention_ledger/u);
  assert.doesNotMatch(sql, /provider_response|response_body|destination|credential|authorization|cookie|suppression_reason/iu);
});

test("0032 is loaded as migration 32 with a content-derived checksum", async () => {
  const migrations = await loadSqlMigrations();
  const migration = migrations.find((item) => item.version === 32);
  assert.equal(migration?.name, "0032_owner_recovery_outbox_retention.sql");
  assert.match(migration?.checksum ?? "", /^[0-9a-f]{64}$/u);
});
