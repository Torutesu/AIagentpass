import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0033_shared_abuse_control_hardening.sql", import.meta.url);

const functionSource = (sql, name) => {
  const start = sql.indexOf(`CREATE OR REPLACE FUNCTION public.${name}(`);
  assert.notEqual(start, -1, `${name} must be replaced in 0033`);
  const end = sql.indexOf("\nCREATE ", start + 1);
  return sql.slice(start, end === -1 ? sql.length : end);
};

const readMigration = () => readFile(migrationUrl, "utf8");

test("0033 is a forward-only transactional migration with no destructive DDL", async () => {
  const sql = await readMigration();
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.doesNotMatch(sql, /\b(?:DROP|TRUNCATE|ALTER\s+TABLE|CREATE\s+TABLE)\b/iu);
  assert.match(sql, /CREATE OR REPLACE FUNCTION public\.agentpass_acquire_rate_limit\(/u);
  assert.match(sql, /CREATE OR REPLACE FUNCTION public\.agentpass_acquire_anonymous_rate_limit\(/u);
});

test("0033 preserves both rate-limit function signatures and token decision semantics", async () => {
  const sql = await readMigration();
  const tenant = functionSource(sql, "agentpass_acquire_rate_limit");
  const anonymous = functionSource(sql, "agentpass_acquire_anonymous_rate_limit");

  assert.match(tenant, /request_organization_id uuid,\s*request_principal_type text,\s*request_principal_id uuid,\s*request_capacity integer,\s*request_refill_per_second numeric,\s*request_cost integer,\s*idle_ttl_ms integer/u);
  assert.match(anonymous, /request_operation text,\s*request_principal_id uuid,\s*request_capacity integer,\s*request_refill_per_second numeric,\s*request_cost integer,\s*idle_ttl_ms integer/u);
  for (const source of [tenant, anonymous]) {
    assert.match(source, /RETURNS TABLE \([\s\S]*allowed boolean[\s\S]*rate_limit integer[\s\S]*remaining integer[\s\S]*retry_after_ms bigint[\s\S]*reset_at timestamptz/u);
    assert.match(source, /new_tokens := LEAST\(request_capacity::numeric, bucket\.tokens \+ elapsed_seconds \* request_refill_per_second\)/u);
    assert.match(source, /decision := new_tokens >= request_cost/u);
    assert.match(source, /FLOOR\(new_tokens\)::integer/u);
  }
});

test("0033 samples the wall clock only after locking the bucket and prevents time regression", async () => {
  const sql = await readMigration();
  for (const name of ["agentpass_acquire_rate_limit", "agentpass_acquire_anonymous_rate_limit"]) {
    const source = functionSource(sql, name);
    const lockIndex = source.indexOf("FOR UPDATE;");
    const sampleIndex = source.indexOf("now_value := GREATEST(clock_timestamp(), bucket.updated_at);");
    assert.ok(lockIndex >= 0, `${name} must lock its bucket row`);
    assert.ok(sampleIndex > lockIndex, `${name} must sample after the row lock`);
    assert.doesNotMatch(source.slice(0, lockIndex), /clock_timestamp\(\)/u, `${name} samples too early`);
    assert.match(source, /GREATEST\(clock_timestamp\(\), bucket\.updated_at\)/u);
    assert.match(source, /updated_at = now_value/u);
  }
});

test("0033 makes every abuse-control prune bounded and cooperative", async () => {
  const sql = await readMigration();
  const pruneNames = [
    "agentpass_prune_shared_control_expired",
    "agentpass_prune_anonymous_rate_limits",
    "agentpass_prune_human_identity_assertion_replays"
  ];
  for (const name of pruneNames) {
    const source = functionSource(sql, name);
    assert.match(source, /prune_limit IS NULL OR prune_limit < 1 OR prune_limit > 10000/u);
    assert.match(source, /FOR UPDATE SKIP LOCKED/u);
    assert.match(source, /LIMIT (?:remaining|prune_limit)/u);
  }
  const shared = functionSource(sql, "agentpass_prune_shared_control_expired");
  assert.equal((shared.match(/FOR UPDATE SKIP LOCKED/g) ?? []).length, 4);
  assert.match(sql, /CREATE OR REPLACE FUNCTION public\.agentpass_prune_human_identity_assertion_replays\(/u);
  assert.doesNotMatch(sql, /DELETE FROM human_identity_assertion_replays\s+WHERE\s+expires_at/iu);
});
