import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0028_anonymous_rate_limits.sql", import.meta.url);

test("0028 creates a non-tenant anonymous limiter without storing raw exchange material", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /CREATE TABLE anonymous_rate_limit_buckets \(/);
  assert.match(sql, /PRIMARY KEY \(operation, principal_id\)/);
  assert.match(sql, /CREATE FUNCTION agentpass_acquire_anonymous_rate_limit\(/);
  assert.match(sql, /CREATE FUNCTION agentpass_prune_anonymous_rate_limits\(/);
  assert.doesNotMatch(sql, /REFERENCES organizations|organization_id|exchange_value|raw_exchange|recovery_session_token/iu);
  assert.match(sql, /FOR UPDATE/);
});
