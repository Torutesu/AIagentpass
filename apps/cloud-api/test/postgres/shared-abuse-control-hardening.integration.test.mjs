import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createSharedControlRepository } from "../../src/postgres/shared-control-repository.mjs";

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL;

test("0033 samples a contended anonymous bucket clock after its row lock", { skip: !databaseUrl }, async (t) => {
  const pool = new Pool({ connectionString: databaseUrl, max: 4 });
  await migrate(pool);

  const operation = `test.clock.${crypto.randomUUID()}`;
  const principalId = crypto.randomUUID();
  await pool.query(
    `INSERT INTO anonymous_rate_limit_buckets
      (operation,principal_id,capacity,refill_per_second,tokens,updated_at,expires_at)
     VALUES ($1,$2,1,5,0,clock_timestamp(),clock_timestamp()+interval '1 hour')`,
    [operation, principalId]
  );
  t.after(async () => {
    await pool.query("DELETE FROM anonymous_rate_limit_buckets WHERE operation=$1 AND principal_id=$2", [operation, principalId]);
    await pool.end();
  });

  const locker = await pool.connect();
  await locker.query("BEGIN");
  await locker.query("SELECT 1 FROM anonymous_rate_limit_buckets WHERE operation=$1 AND principal_id=$2 FOR UPDATE", [operation, principalId]);
  const repository = createSharedControlRepository({ client: pool });
  const waiting = repository.acquireAnonymousRateLimit({ operation, principalId, capacity: 1, refillPerSecond: 5, cost: 1, idleTtlMs: 60_000 });
  await new Promise((resolve) => setTimeout(resolve, 300));
  await locker.query("COMMIT");
  locker.release();

  const decision = await waiting;
  assert.equal(decision.allowed, true, "lock wait time must contribute to refill");

  const future = new Date(Date.now() + 2_000);
  await pool.query("UPDATE anonymous_rate_limit_buckets SET updated_at=$3 WHERE operation=$1 AND principal_id=$2", [operation, principalId, future]);
  await repository.acquireAnonymousRateLimit({ operation, principalId, capacity: 1, refillPerSecond: 5, cost: 1, idleTtlMs: 60_000 });
  const stored = await pool.query("SELECT updated_at FROM anonymous_rate_limit_buckets WHERE operation=$1 AND principal_id=$2", [operation, principalId]);
  assert.equal(stored.rows[0].updated_at.getTime() >= future.getTime(), true, "updated_at must never move backward");
});

test("0033 anonymous pruning skips locked expired rows and keeps its total bound", { skip: !databaseUrl }, async (t) => {
  const pool = new Pool({ connectionString: databaseUrl, max: 4 });
  await migrate(pool);

  const operation = `test.prune.${crypto.randomUUID()}`;
  const lockedId = crypto.randomUUID();
  const freeId = crypto.randomUUID();
  await pool.query(
    `INSERT INTO anonymous_rate_limit_buckets
      (operation,principal_id,capacity,refill_per_second,tokens,updated_at,expires_at)
     VALUES
      ($1,$2,1,1,0,clock_timestamp()-interval '3 hours',clock_timestamp()-interval '2 hours'),
      ($1,$3,1,1,0,clock_timestamp()-interval '2 hours',clock_timestamp()-interval '1 hour')`,
    [operation, lockedId, freeId]
  );
  t.after(async () => {
    await pool.query("DELETE FROM anonymous_rate_limit_buckets WHERE operation=$1", [operation]);
    await pool.end();
  });

  const locker = await pool.connect();
  await locker.query("BEGIN");
  await locker.query("SELECT 1 FROM anonymous_rate_limit_buckets WHERE operation=$1 AND principal_id=$2 FOR UPDATE", [operation, lockedId]);
  const pruned = await pool.query("SELECT removed FROM agentpass_prune_anonymous_rate_limits(1)");
  assert.equal(Number(pruned.rows[0].removed), 1);
  const visible = await pool.query("SELECT principal_id FROM anonymous_rate_limit_buckets WHERE operation=$1 ORDER BY principal_id", [operation]);
  assert.deepEqual(visible.rows.map(({ principal_id }) => principal_id), [lockedId]);
  await locker.query("ROLLBACK");
  locker.release();
});

async function migrate(pool) {
  const client = await pool.connect();
  try {
    const result = await createMigrationRunner({ client, applicationVersion: "shared-abuse-control-hardening-integration" }).run();
    assert.equal(result.currentVersion, 34);
  } finally {
    client.release();
  }
}
