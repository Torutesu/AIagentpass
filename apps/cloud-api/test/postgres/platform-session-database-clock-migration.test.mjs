import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { POSTGRES_SCHEMA_HEAD } from "../../src/postgres/schema-head.mjs";

const migrationUrl = new URL("../../../../contracts/postgres/0069_platform_session_database_clock.sql", import.meta.url);
const catalogUrl = new URL("../../../../contracts/catalog-v1.json", import.meta.url);

test("0069 keeps Platform Session creation on the database clock and preserves ordering", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /ALTER TABLE public\.platform_sessions[\s\S]*ALTER COLUMN created_at SET DEFAULT statement_timestamp\(\)/u);
  assert.doesNotMatch(sql, /DROP CONSTRAINT|DISABLE TRIGGER|SET DEFAULT now\(\)/iu);
  assert.match(sql, /COMMIT;\s*$/u);
});

test("0069 remains catalogued at the current schema head", async () => {
  const catalog = JSON.parse(await readFile(catalogUrl, "utf8"));
  assert.equal(POSTGRES_SCHEMA_HEAD.version, POSTGRES_SCHEMA_HEAD.migration_count);
  assert.equal(POSTGRES_SCHEMA_HEAD.name, "0111_human_credential_registration_binding.sql");
  assert.equal(catalog.entries.filter((entry) => entry.kind === "postgres-migration").length, POSTGRES_SCHEMA_HEAD.migration_count);
  assert.equal(catalog.entries.find((entry) => entry.version === 69)?.id, "migration.0069_platform_session_database_clock");
});
