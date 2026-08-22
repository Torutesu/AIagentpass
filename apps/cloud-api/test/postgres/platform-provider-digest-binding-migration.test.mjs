import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { POSTGRES_SCHEMA_HEAD } from "../../src/postgres/schema-head.mjs";

const migrationUrl = new URL("../../../../contracts/postgres/0070_platform_provider_digest_binding.sql", import.meta.url);
const catalogUrl = new URL("../../../../contracts/catalog-v1.json", import.meta.url);

test("0070 separates canonical signer and exact-byte provider digests", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /signer_row\.request_digest IS DISTINCT FROM expected_request_digest/u);
  assert.match(sql, /provider_row\.request_digest IS DISTINCT FROM sha256\(expected_signing_bytes\)/u);
  assert.doesNotMatch(sql, /provider_row\.request_digest IS DISTINCT FROM expected_request_digest/u);
  assert.match(sql, /SECURITY DEFINER[\s\S]*SET search_path = pg_catalog, public/u);
  assert.match(sql, /REVOKE ALL ON FUNCTION public\.agentpass_platform_promotion_issuance_commit/u);
  assert.match(sql, /COMMIT;\s*$/u);
});

test("0070 remains catalogued below the current schema head", async () => {
  const catalog = JSON.parse(await readFile(catalogUrl, "utf8"));
  assert.equal(POSTGRES_SCHEMA_HEAD.version, POSTGRES_SCHEMA_HEAD.migration_count);
  assert.equal(POSTGRES_SCHEMA_HEAD.name, "0111_human_credential_registration_binding.sql");
  assert.equal(catalog.entries.filter((entry) => entry.kind === "postgres-migration").length, POSTGRES_SCHEMA_HEAD.migration_count);
  assert.equal(catalog.entries.find((entry) => entry.version === 70)?.id, "migration.0070_platform_provider_digest_binding");
});
