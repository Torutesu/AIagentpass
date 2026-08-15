import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import pg from "pg";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";

const { Pool } = pg;
const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const INDEX_NAMES = Object.freeze([
  "managed_signer_provider_operations_nonterminal_created_at",
  "managed_signer_provider_operations_reconciliation",
  "managed_signer_provider_operations_committed_expiry"
]);

test("0042 uses PostgreSQL 17 index-backed ordered paths for health and maintenance", {
  skip: DATABASE_URL ? false : "set AGENTPASS_TEST_DATABASE_URL to run PostgreSQL 17 plan qualification"
}, async (t) => {
  const pool = new Pool({ connectionString: DATABASE_URL, max: 4, connectionTimeoutMillis: 2_000, statement_timeout: 10_000, query_timeout: 12_000 });
  let purpose;
  t.after(async () => {
    try {
      if (purpose !== undefined) {
        await pool.query("DELETE FROM managed_signer_signing_idempotency WHERE purpose=$1", [purpose]);
        await pool.query("DELETE FROM managed_signer_provider_operations WHERE purpose=$1", [purpose]);
        await pool.query("DELETE FROM managed_signer_keys WHERE purpose=$1", [purpose]);
        await pool.query("DELETE FROM managed_signer_key_lifecycles WHERE purpose=$1", [purpose]);
      }
    } finally {
      await pool.end();
    }
  });

  const version = await pool.query("SELECT current_setting('server_version_num')::integer AS version");
  assert.equal(Math.floor(Number(version.rows[0].version) / 10_000), 17, "qualification must run on PostgreSQL 17");

  const migrationClient = await pool.connect();
  try {
    const migration = await createMigrationRunner({ client: migrationClient, applicationVersion: "provider-operation-query-indexes-integration" }).run();
    assert.equal(migration.currentVersion, 54);
  } finally {
    migrationClient.release();
  }

  const indexes = await pool.query(`SELECT indexname, indexdef
    FROM pg_indexes
    WHERE schemaname='public' AND indexname = ANY($1::text[])
    ORDER BY indexname`, [INDEX_NAMES]);
  assert.deepEqual(indexes.rows.map((row) => row.indexname), [...INDEX_NAMES].sort());
  for (const row of indexes.rows) assert.match(row.indexdef, /managed_signer_provider_operations/u);

  const runId = crypto.randomUUID().replaceAll("-", "");
  purpose = `migration42.index.${runId}`;
  const keyId = `index-key-${runId}`;

  await pool.query(`INSERT INTO managed_signer_key_lifecycles
      (purpose,algorithm,version,max_keys,max_verification_overlap_ms)
    VALUES ($1,'ed25519',1,4,7776000000)`, [purpose]);
  await pool.query(`INSERT INTO managed_signer_keys
      (purpose,key_id,key_version,algorithm,public_key_fingerprint,public_key_pem,
       state,state_version,verification_until,key_position)
    VALUES ($1,$2,1,'ed25519',decode(repeat('22',32),'hex'),NULL,'active',1,NULL,0)`, [purpose, keyId]);

  // A production-shaped 100k+ mixed ledger makes each selective ordered path
  // observable with actual matching rows instead of an empty-plan estimate.
  await pool.query(`INSERT INTO managed_signer_provider_operations
      (purpose,operation_id,algorithm,bytes_length,request_digest,key_id,key_version,state,
       claim_token_digest,claim_expires_at,provider_started_at,created_at,updated_at,expires_at)
    SELECT $1, 'health-' || n::text, 'ed25519', 32, decode(repeat('00', 32), 'hex'), 'key', 1, 'pending',
       decode(repeat('11', 32), 'hex'), clock_timestamp() + interval '1 day', NULL,
       clock_timestamp() - (n::text || ' seconds')::interval,
       clock_timestamp() - (n::text || ' seconds')::interval,
       clock_timestamp() + interval '2 days'
    FROM generate_series(1, 100000) AS series(n)`, [purpose]);

  await pool.query(`INSERT INTO managed_signer_signing_idempotency
      (purpose,operation_id,request_digest,key_id,key_version,status,signature,
       created_at,updated_at,expires_at,claim_token_digest,claim_expires_at,
       provider_started_at,reserved_lifecycle_version,provider_receipt_provider,provider_receipt_id)
    SELECT $1,'reconcile-' || n::text,decode(repeat('88',32),'hex'),$2,1,'committed',
       decode(repeat('33',64),'hex'),clock_timestamp()-interval '1 hour',clock_timestamp()-interval '1 hour',
       clock_timestamp()+interval '1 day',NULL,NULL,clock_timestamp()-interval '1 hour',1,
       'fixture-kms','reconcile-' || n::text
    FROM generate_series(1,10000) AS series(n)`, [purpose, keyId]);
  await pool.query(`INSERT INTO managed_signer_provider_operations
      (purpose,operation_id,algorithm,bytes_length,request_digest,key_id,key_version,state,
       claim_token_digest,claim_expires_at,provider_started_at,signature,public_key_der,
       provider_receipt_provider,provider_receipt_id,created_at,updated_at,expires_at)
    SELECT $1,'reconcile-' || n::text,'ed25519',32,decode(repeat('88',32),'hex'),$2,1,'accepted',
       decode(repeat('44',32),'hex'),clock_timestamp()+interval '1 day',clock_timestamp()-interval '1 hour',
       decode(repeat('33',64),'hex'),decode(repeat('55',44),'hex'),
       'fixture-kms','reconcile-' || n::text,
       clock_timestamp()-interval '1 hour',clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 day'
    FROM generate_series(1,10000) AS series(n)`, [purpose, keyId]);

  await pool.query(`INSERT INTO managed_signer_signing_idempotency
      (purpose,operation_id,request_digest,key_id,key_version,status,signature,
       created_at,updated_at,expires_at,claim_token_digest,claim_expires_at,
       provider_started_at,reserved_lifecycle_version,provider_receipt_provider,provider_receipt_id)
    SELECT $1,'prune-' || n::text,decode(repeat('99',32),'hex'),$2,1,'committed',
       decode(repeat('66',64),'hex'),clock_timestamp()-interval '2 days',clock_timestamp()-interval '2 days',
       clock_timestamp()-interval '1 day',NULL,NULL,clock_timestamp()-interval '2 days',1,
       'fixture-kms','prune-' || n::text
    FROM generate_series(1,10000) AS series(n)`, [purpose, keyId]);
  await pool.query(`INSERT INTO managed_signer_provider_operations
      (purpose,operation_id,algorithm,bytes_length,request_digest,key_id,key_version,state,
       claim_token_digest,claim_expires_at,provider_started_at,signature,public_key_der,
       provider_receipt_provider,provider_receipt_id,created_at,updated_at,expires_at)
    SELECT $1,'prune-' || n::text,'ed25519',32,decode(repeat('99',32),'hex'),$2,1,'committed',
       NULL,NULL,clock_timestamp()-interval '2 days',decode(repeat('66',64),'hex'),decode(repeat('77',44),'hex'),
       'fixture-kms','prune-' || n::text,
       clock_timestamp()-interval '2 days',clock_timestamp()-interval '2 days',clock_timestamp()-interval '1 day'
    FROM generate_series(1,10000) AS series(n)`, [purpose, keyId]);
  await pool.query("ANALYZE managed_signer_provider_operations");
  await pool.query("ANALYZE managed_signer_signing_idempotency");

  const oldestPlan = await explain(pool, `SELECT created_at
    FROM managed_signer_provider_operations
    WHERE state IN ('pending','started','accepted','uncertain')
    ORDER BY created_at ASC
    LIMIT 1`);
  assert.ok(findIndexScan(oldestPlan, INDEX_NAMES[0]), JSON.stringify(oldestPlan));

  const reconciliationPlan = await explain(pool, `WITH candidates AS MATERIALIZED (
      SELECT provider.purpose,provider.operation_id
      FROM managed_signer_provider_operations provider
      JOIN managed_signer_signing_idempotency signing
        ON signing.purpose=provider.purpose AND signing.operation_id=provider.operation_id
      WHERE provider.state IN ('accepted','uncertain')
        AND signing.status='committed'
        AND provider.request_digest=signing.request_digest
        AND provider.key_id=signing.key_id
        AND provider.key_version=signing.key_version
        AND provider.signature=signing.signature
        AND provider.provider_receipt_provider=signing.provider_receipt_provider
        AND provider.provider_receipt_id=signing.provider_receipt_id
      ORDER BY provider.updated_at ASC,provider.purpose ASC,provider.operation_id ASC
      LIMIT 100
      FOR UPDATE OF provider,signing SKIP LOCKED
    ) SELECT count(*) FROM candidates`);
  assert.ok(findIndexScan(reconciliationPlan, INDEX_NAMES[1]), JSON.stringify(reconciliationPlan));

  const prunePlan = await explain(pool, `WITH candidates AS MATERIALIZED (
      SELECT provider.purpose,provider.operation_id
      FROM managed_signer_provider_operations provider
      JOIN managed_signer_signing_idempotency signing
        ON signing.purpose=provider.purpose AND signing.operation_id=provider.operation_id
      WHERE provider.state='committed'
        AND signing.status='committed'
        AND provider.expires_at<=clock_timestamp()
        AND signing.expires_at<=clock_timestamp()
      ORDER BY provider.expires_at ASC,signing.expires_at ASC,provider.purpose ASC,provider.operation_id ASC
      LIMIT 100
      FOR UPDATE OF provider,signing SKIP LOCKED
    ) SELECT count(*) FROM candidates`);
  assert.ok(findIndexScan(prunePlan, INDEX_NAMES[2]), JSON.stringify(prunePlan));
});

async function explain(pool, text) {
  const result = await pool.query(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON, COSTS OFF) ${text}`);
  assert.equal(result.rows.length, 1);
  return result.rows[0]["QUERY PLAN"][0].Plan;
}

function findIndexScan(plan, indexName) {
  if (!plan || typeof plan !== "object") return false;
  if (["Index Scan", "Index Only Scan", "Bitmap Index Scan"].includes(plan["Node Type"])
    && plan["Index Name"] === indexName) return true;
  return Object.values(plan).some((value) => Array.isArray(value)
    ? value.some((item) => findIndexScan(item, indexName))
    : findIndexScan(value, indexName));
}
