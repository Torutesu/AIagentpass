import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { POSTGRES_SCHEMA_HEAD } from "../../src/postgres/schema-head.mjs";

const migrationUrl = new URL("../../../../contracts/postgres/0068_platform_challenge_database_clock.sql", import.meta.url);
const catalogUrl = new URL("../../../../contracts/catalog-v1.json", import.meta.url);

test("0068 binds Platform challenge creation timestamps to one database instant", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /CREATE OR REPLACE FUNCTION public\.agentpass_platform_session_challenge_create/u);
  assert.match(sql, /issued_at, expires_at, created_at[\s\S]*now_value \+ \(p_ttl_ms::double precision \* interval '1 millisecond'\), now_value/u);
  assert.match(sql, /SECURITY DEFINER[\s\S]*SET search_path = pg_catalog, public/u);
  assert.match(sql, /REVOKE ALL ON FUNCTION public\.agentpass_platform_session_challenge_create/u);
  assert.doesNotMatch(sql, /ALTER TABLE[\s\S]*DROP CONSTRAINT/u);
});

test("0068 remains catalogued at the current schema head", async () => {
  const catalog = JSON.parse(await readFile(catalogUrl, "utf8"));
  assert.equal(POSTGRES_SCHEMA_HEAD.version, POSTGRES_SCHEMA_HEAD.migration_count);
  assert.equal(POSTGRES_SCHEMA_HEAD.name, "0109_invitation_authority.sql");
  assert.equal(catalog.entries.filter((entry) => entry.kind === "postgres-migration").length, POSTGRES_SCHEMA_HEAD.migration_count);
  assert.equal(catalog.entries.find((entry) => entry.version === 68)?.id, "migration.0068_platform_challenge_database_clock");
});
