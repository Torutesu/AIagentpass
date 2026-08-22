import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import pg from "pg";
import { measurePostgresSchemaIdentity, postgresSchemaIdentityDigest, POSTGRES_SCHEMA_IDENTITY_QUERY } from "../../src/postgres/schema-identity.mjs";

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;

test("real PostgreSQL schema identity detects RLS drift in the same snapshot contract", { skip: databaseUrl ? false : "set AGENTPASS_TEST_DATABASE_URL to run real PostgreSQL schema identity qualification" }, async (t) => {
  const pool = new pg.Pool({ connectionString: databaseUrl, max: 2, connectionTimeoutMillis: 3_000, statement_timeout: 8_000, query_timeout: 10_000 });
  const client = await pool.connect();
  const schema = `agentpass_identity_${crypto.randomUUID().replaceAll("-", "")}`;
  t.after(async () => { try { await client.query(`DROP SCHEMA IF EXISTS \"${schema}\" CASCADE`); } finally { client.release(true); await pool.end(); } });
  await client.query(`CREATE SCHEMA \"${schema}\"`);
  await client.query(`CREATE TABLE \"${schema}\".probe (id integer PRIMARY KEY, value text DEFAULT 'safe')`);
  await client.query(`ALTER TABLE \"${schema}\".probe ENABLE ROW LEVEL SECURITY`);
  await client.query(`CREATE POLICY probe_public ON \"${schema}\".probe FOR SELECT TO PUBLIC USING (true)`);
  await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
  await client.query("SET LOCAL search_path TO pg_catalog, public");
  const baselineResult = await client.query(POSTGRES_SCHEMA_IDENTITY_QUERY);
  const baselineDigest = postgresSchemaIdentityDigest(baselineResult.rows[0].snapshot);
  await client.query("ROLLBACK");
  const pathProbe = await client.query("SELECT pg_catalog.current_setting('search_path', false) AS raw_search_path, pg_catalog.current_schemas(false) AS resolved_search_path");
  console.error(`schema-identity-path: ${JSON.stringify(pathProbe.rows[0])}`);
  const baselineMeasurement = await measurePostgresSchemaIdentity({ client, expectedDigest: baselineDigest, onFailure: (stage) => console.error(`schema-identity-diagnostic: ${stage}`) });
  assert.equal(baselineMeasurement.code, "verified", JSON.stringify(baselineMeasurement));
  await client.query(`ALTER TABLE \"${schema}\".probe DISABLE ROW LEVEL SECURITY`);
  assert.equal((await measurePostgresSchemaIdentity({ client, expectedDigest: baselineDigest })).code, "schema_identity_mismatch");
});
