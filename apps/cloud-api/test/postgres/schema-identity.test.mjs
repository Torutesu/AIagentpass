import assert from "node:assert/strict";
import test from "node:test";
import { measurePostgresSchemaIdentity, postgresSchemaIdentityDigest, POSTGRES_SCHEMA_IDENTITY_QUERY } from "../../src/postgres/schema-identity.mjs";

const snapshot = { tables: [{ schema_name: "public", relation_name: "devices", relkind: "r" }], columns: [], constraints: [], indexes: [], functions: [], triggers: [], policies: [] };

test("schema identity uses one repeatable-read transaction and canonical snapshot bytes", async () => {
  for (const required of ["relrowsecurity", "relforcerowsecurity", "atthasdef", "convalidated", "seqincrement", "polroles", "tgenabled", "object_acls", "default_privileges", "migration_ledger", "'version', 2"]) assert.match(POSTGRES_SCHEMA_IDENTITY_QUERY, new RegExp(required.replace(/[.*+?^${}()|[\\]\\]/g, "\\\\$&")));
  const calls = [];
  const client = { async query(sql) { calls.push(sql); if (sql === POSTGRES_SCHEMA_IDENTITY_QUERY) return { rows: [{ snapshot }] }; if (sql.startsWith("SELECT pg_catalog.current_setting")) return { rows: [{ resolved_search_path: ["pg_catalog", "public"] }] }; return { rows: [] }; } };
  const result = await measurePostgresSchemaIdentity({ client, expectedDigest: postgresSchemaIdentityDigest(snapshot) });
  assert.deepEqual(result, { ok: true, code: "verified", digest: postgresSchemaIdentityDigest(snapshot), destroy: false });
  assert.deepEqual(calls, ["BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY", "SELECT pg_catalog.current_setting('search_path', false) AS raw_search_path, pg_catalog.current_schemas(false) AS resolved_search_path", "SET LOCAL search_path TO pg_catalog, public", POSTGRES_SCHEMA_IDENTITY_QUERY, "ROLLBACK"]);
});

test("schema identity fails closed on mismatch, query failure, or missing expected digest", async () => {
  const mismatch = await measurePostgresSchemaIdentity({ client: { async query(sql) { return sql === POSTGRES_SCHEMA_IDENTITY_QUERY ? { rows: [{ snapshot }] } : sql.startsWith("SELECT pg_catalog.current_setting") ? { rows: [{ resolved_search_path: ["pg_catalog", "public"] }] } : { rows: [] }; } }, expectedDigest: "0".repeat(64) });
  assert.equal(mismatch.ok, false); assert.equal(mismatch.code, "schema_identity_mismatch");
  const failed = await measurePostgresSchemaIdentity({ client: { async query() { throw new Error("db failure"); } }, expectedDigest: "a".repeat(64) });
  assert.deepEqual(failed, { ok: false, code: "schema_identity_unavailable", digest: null, destroy: false });
  assert.equal((await measurePostgresSchemaIdentity({ client: {}, expectedDigest: undefined })).code, "schema_identity_unconfigured");
});

test("schema identity destroys a connection when rollback cannot be confirmed", async () => {
  const result = await measurePostgresSchemaIdentity({ client: { async query(sql) { if (sql === "ROLLBACK") throw new Error("rollback lost"); if (sql === POSTGRES_SCHEMA_IDENTITY_QUERY) return { rows: [{ snapshot }] }; if (sql.startsWith("SELECT pg_catalog.current_setting")) return { rows: [{ resolved_search_path: ["pg_catalog", "public"] }] }; return { rows: [] }; } }, expectedDigest: postgresSchemaIdentityDigest({ ...snapshot, version: 2 }) });
  assert.deepEqual(result, { ok: false, code: "schema_identity_unavailable", digest: null, destroy: true });
});

test("schema identity fails closed for a hostile resolved search_path", async () => {
  const result = await measurePostgresSchemaIdentity({ client: { async query(sql) { if (sql.startsWith("SELECT pg_catalog.current_setting")) return { rows: [{ resolved_search_path: ["attacker", "public"] }] }; return { rows: [] }; } }, expectedDigest: "a".repeat(64) });
  assert.deepEqual(result, { ok: false, code: "schema_identity_unavailable", digest: null, destroy: false });
});
