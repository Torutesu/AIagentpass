import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { createPostgresHumanRepository } from "../../src/postgres/human-repository.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL;

test("signed-console jti consumption is one-shot across concurrent PostgreSQL callers", { skip: !databaseUrl }, async (t) => {
  const pool = new Pool({ connectionString: databaseUrl, max: 4 });
  t.after(() => pool.end());
  const migrationClient = await pool.connect();
  try { await createMigrationRunner({ client: migrationClient, applicationVersion: "signed-console-replay-integration" }).run(); }
  finally { migrationClient.release(); }

  const repository = createPostgresHumanRepository({ client: pool });
  const input = { jti_digest: randomBytes(32).toString("hex"), expires_at: "2099-01-01T00:00:00.000Z" };
  const results = await Promise.all([
    repository.consumeConsoleIdentityJti(input),
    repository.consumeConsoleIdentityJti(input)
  ]);
  assert.deepEqual(results.sort(), [false, true]);
  const stored = await pool.query("SELECT jti_digest,expires_at FROM human_identity_assertion_replays WHERE jti_digest=$1", [Buffer.from(input.jti_digest, "hex")]);
  assert.equal(stored.rowCount, 1);
  assert.equal(Buffer.from(stored.rows[0].jti_digest).toString("hex"), input.jti_digest);
});
