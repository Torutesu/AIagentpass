import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { loadSqlMigrations } from "../../src/postgres/migration-runner.mjs";

const migrationUrl = new URL("../../../../contracts/postgres/0031_resource_bound_recent_authorization.sql", import.meta.url);

test("0031 is transactional, additive, nullable, and safe for legacy rows", async () => {
  const sql = await readFile(migrationUrl, "utf8");

  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN)|TRUNCATE/iu);
  assert.match(sql, /ALTER TABLE webauthn_challenges[\s\S]*ADD COLUMN context_hash bytea/u);
  assert.match(sql, /ALTER TABLE human_sessions[\s\S]*ADD COLUMN recent_auth_context_hash bytea/u);
  assert.doesNotMatch(sql, /context_hash bytea NOT NULL/u);
  assert.doesNotMatch(sql, /context_hash bytea[^,;]*DEFAULT/u);
  assert.doesNotMatch(sql, /UPDATE\s+(?:webauthn_challenges|human_sessions)/iu);
});

test("0031 limits both context columns to nullable 32-byte digests", async () => {
  const sql = await readFile(migrationUrl, "utf8");

  assert.match(sql, /webauthn_challenges_context_hash_valid CHECK \([\s\S]*context_hash IS NULL OR octet_length\(context_hash\) = 32[\s\S]*\)/u);
  assert.match(sql, /human_sessions_context_hash_valid CHECK \([\s\S]*recent_auth_context_hash IS NULL OR octet_length\(recent_auth_context_hash\) = 32[\s\S]*\)/u);
});

test("0031 makes legacy and bound recent-auth states complete, including reset", async () => {
  const sql = await readFile(migrationUrl, "utf8");

  assert.match(sql, /DROP CONSTRAINT human_sessions_recent_auth_complete/u);
  assert.match(sql, /ADD CONSTRAINT human_sessions_recent_auth_complete CHECK \([\s\S]*recent_auth_context_hash IS NULL[\s\S]*recent_auth_consumed_at IS NULL[\s\S]*recent_auth_context_hash IS NULL OR octet_length\(recent_auth_context_hash\) = 32[\s\S]*\)/u);
  assert.match(sql, /CREATE FUNCTION agentpass_validate_recent_auth_context\(\)/u);
  assert.match(sql, /challenge_context_hash IS DISTINCT FROM NEW\.recent_auth_context_hash/u);
  assert.match(sql, /CREATE TRIGGER human_sessions_recent_auth_context_binding/u);
  assert.match(sql, /CREATE FUNCTION agentpass_guard_recent_auth_context_update\(\)/u);
  assert.match(sql, /CREATE TRIGGER webauthn_challenges_recent_auth_context_guard/u);
});

test("0031 separates one-live legacy identity from resource-bound identity", async () => {
  const sql = await readFile(migrationUrl, "utf8");

  assert.match(sql, /DROP INDEX webauthn_challenges_one_live_operation/u);
  assert.match(sql, /CREATE UNIQUE INDEX webauthn_challenges_one_live_operation\s+[\s\S]*context_hash IS NULL/u);
  assert.match(sql, /CREATE UNIQUE INDEX webauthn_challenges_one_live_operation_bound\s+[\s\S]*operation, context_hash\)[\s\S]*context_hash IS NOT NULL/u);
  assert.match(sql, /treats NULL values as distinct/u);
});

test("0031 is loaded as migration 31 with a content-derived checksum", async () => {
  const migrations = await loadSqlMigrations();
  const migration = migrations.find((item) => item.version === 31);
  assert.equal(migration?.name, "0031_resource_bound_recent_authorization.sql");
  assert.match(migration?.checksum ?? "", /^[0-9a-f]{64}$/u);
});
