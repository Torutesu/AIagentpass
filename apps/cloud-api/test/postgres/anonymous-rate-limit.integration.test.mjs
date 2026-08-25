import assert from "node:assert/strict";
import test from "node:test";
import { Pool } from "pg";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createSharedControlRepository } from "../../src/postgres/shared-control-repository.mjs";

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL;

test("anonymous exchange limiter works in PostgreSQL without an organization row", { skip: !databaseUrl }, async (t) => {
  const pool = new Pool({ connectionString: databaseUrl, max: 4 });
  t.after(() => pool.end());
  const migrationClient = await pool.connect();
  try { await createMigrationRunner({ client: migrationClient, applicationVersion: "anonymous-rate-limit-integration" }).run(); }
  finally { migrationClient.release(); }

  const repository = createSharedControlRepository({ client: pool });
  const principalId = "60000000-0000-4000-8000-000000000001";
  await pool.query("DELETE FROM anonymous_rate_limit_buckets WHERE operation=$1 AND principal_id=$2", ["human.recovery.exchange", principalId]);
  const first = await repository.acquireAnonymousRateLimit({ operation: "human.recovery.exchange", principalId, capacity: 2, refillPerSecond: 0.1, cost: 1, idleTtlMs: 60_000 });
  const second = await repository.acquireAnonymousRateLimit({ operation: "human.recovery.exchange", principalId, capacity: 2, refillPerSecond: 0.1, cost: 1, idleTtlMs: 60_000 });
  const denied = await repository.acquireAnonymousRateLimit({ operation: "human.recovery.exchange", principalId, capacity: 2, refillPerSecond: 0.1, cost: 1, idleTtlMs: 60_000 });
  assert.equal(first.allowed, true);
  assert.equal(second.allowed, true);
  assert.equal(denied.allowed, false);
  assert.equal(denied.retryAfterMs > 0, true);
  const organizations = await pool.query("SELECT count(*)::int AS count FROM organizations WHERE id=$1", [principalId]);
  assert.equal(organizations.rows[0].count, 0);
  await pool.query("UPDATE anonymous_rate_limit_buckets SET updated_at=clock_timestamp()-interval '2 seconds',expires_at=clock_timestamp()-interval '1 second' WHERE operation=$1 AND principal_id=$2", ["human.recovery.exchange", principalId]);
  const pruned = await repository.pruneExpired({ limit: 10_000 });
  assert.equal(pruned.removed >= 1 && pruned.removed <= 10_000, true);
  const buckets = await pool.query("SELECT count(*)::int AS count FROM anonymous_rate_limit_buckets WHERE operation=$1 AND principal_id=$2", ["human.recovery.exchange", principalId]);
  assert.equal(buckets.rows[0].count, 0);
});
