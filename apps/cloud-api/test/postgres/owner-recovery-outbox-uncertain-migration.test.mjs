import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0034_owner_recovery_outbox_uncertain.sql", import.meta.url);

const readMigration = () => readFile(migrationUrl, "utf8");

test("0034 is a transactional forward-only migration with no destructive DDL", async () => {
  const sql = await readMigration();
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN)|TRUNCATE/iu);
  assert.match(sql, /ADD COLUMN uncertain_at timestamptz/u);
  assert.match(sql, /ADD COLUMN uncertain_reason text/u);
  assert.match(sql, /CREATE INDEX owner_recovery_outbox_uncertain_lookup/u);
});

test("0034 closes uncertain reasons to a bounded fixed vocabulary", async () => {
  const sql = await readMigration();
  assert.match(sql, /uncertain_at IS NULL OR uncertain_at >= created_at/u);
  assert.match(sql, /char_length\(uncertain_reason\) BETWEEN 1 AND 64/u);
  assert.match(sql, /uncertain_reason IN \([\s\S]*provider_timeout[\s\S]*provider_transport_error[\s\S]*provider_response_invalid[\s\S]*terminal_commit_unknown[\s\S]*process_interrupted[\s\S]*delivery_unknown[\s\S]*\)/u);
  assert.doesNotMatch(sql, /response_body\s+(?:text|jsonb)|destination\s+(?:text|jsonb)|authorization\s+(?:text|jsonb)|cookie\s+(?:text|jsonb)/iu);
});

test("0034 makes uncertain a non-claimable, non-terminal-delivery state", async () => {
  const sql = await readMigration();
  assert.match(sql, /status IN \('pending', 'published', 'uncertain', 'dead_letter', 'suppressed'\)/u);
  assert.match(sql, /status = 'uncertain'[\s\S]*published_at IS NULL[\s\S]*uncertain_at IS NOT NULL[\s\S]*uncertain_reason IS NOT NULL[\s\S]*claim_token_digest IS NULL[\s\S]*claim_expires_at IS NULL[\s\S]*last_error_code = 'delivery_uncertain'/u);
  assert.match(sql, /status IN \('published', 'uncertain', 'dead_letter', 'suppressed'\)[\s\S]*claim_token_digest IS NULL[\s\S]*claim_expires_at IS NULL/u);
  assert.match(sql, /UPDATE owner_recovery_outbox[\s\S]*SET status = 'uncertain'[\s\S]*uncertain_reason = 'delivery_unknown'[\s\S]*claim_token_digest = NULL[\s\S]*WHERE status = 'pending'[\s\S]*last_error_code = 'delivery_uncertain'/u);
  assert.match(sql, /UPDATE owner_recovery_outbox[\s\S]*uncertain_reason = 'process_interrupted'[\s\S]*claim_token_digest = NULL[\s\S]*claim_expires_at = NULL[\s\S]*claim_expires_at <= clock_timestamp\(\)/u);
});

test("0034 prevents pending and terminal rows from retaining uncertain metadata", async () => {
  const sql = await readMigration();
  assert.match(sql, /status = 'pending'[\s\S]*uncertain_at IS NULL[\s\S]*uncertain_reason IS NULL[\s\S]*last_error_code IS NULL OR last_error_code <> 'delivery_uncertain'/u);
  assert.match(sql, /status = 'published'[\s\S]*uncertain_at IS NULL[\s\S]*uncertain_reason IS NULL/u);
  assert.match(sql, /status = 'dead_letter'[\s\S]*uncertain_at IS NULL[\s\S]*uncertain_reason IS NULL[\s\S]*last_error_code <> 'delivery_uncertain'/u);
  assert.match(sql, /status = 'suppressed'[\s\S]*uncertain_at IS NULL[\s\S]*uncertain_reason IS NULL/u);
  assert.match(sql, /status IN \('pending', 'published', 'uncertain', 'dead_letter'\)[\s\S]*suppressed_at IS NULL[\s\S]*suppression_reason IS NULL/u);
});

test("0034 updates status, delivery, claim, and suppression invariants together", async () => {
  const sql = await readMigration();
  for (const constraint of [
    "owner_recovery_outbox_status_check",
    "owner_recovery_outbox_delivery_state_check",
    "owner_recovery_outbox_claim_state_check",
    "owner_recovery_outbox_suppression_state_check"
  ]) {
    assert.match(sql, new RegExp(`DROP CONSTRAINT ${constraint}`));
    assert.match(sql, new RegExp(`ADD CONSTRAINT ${constraint}`));
  }
  assert.match(sql, /uncertain rows are excluded from pending claims/u);
  assert.match(sql, /accepted-but-unconfirmed/u);
});
