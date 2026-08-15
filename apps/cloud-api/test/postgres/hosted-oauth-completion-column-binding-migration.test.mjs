import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { POSTGRES_SCHEMA_HEAD } from "../../src/postgres/schema-head.mjs";

const migrationUrl = new URL("../../../../contracts/postgres/0067_hosted_oauth_completion_column_binding.sql", import.meta.url);
const catalogUrl = new URL("../../../../contracts/catalog-v1.json", import.meta.url);

test("0067 pins PL/pgSQL column binding for atomic Hosted OAuth completion", async () => {
  const [migration, catalogText] = await Promise.all([
    readFile(migrationUrl, "utf8"),
    readFile(catalogUrl, "utf8"),
  ]);
  assert.match(migration, /^BEGIN;/u);
  assert.match(migration, /CREATE OR REPLACE FUNCTION public\.agentpass_hosted_identity_oauth_complete_v2\(/u);
  assert.match(migration, /#variable_conflict use_column/u);
  assert.match(migration, /UPDATE public\.hosted_identity_bootstrap_attempts AS attempt/u);
  assert.match(migration, /version = attempt\.version \+ 1/u);
  assert.match(migration, /WHERE attempt\.id = attempt_row\.id AND attempt\.state = 'oauth_started'/u);
  assert.match(migration, /REVOKE ALL PRIVILEGES ON FUNCTION[\s\S]*?FROM PUBLIC;/u);
  assert.doesNotMatch(migration, /DROP FUNCTION|GRANT EXECUTE|ALTER TABLE/iu);
  assert.match(migration, /COMMIT;\s*$/u);

  assert.equal(POSTGRES_SCHEMA_HEAD.version, 71);
  assert.equal(POSTGRES_SCHEMA_HEAD.name, "0071_managed_signer_snapshot_timestamp.sql");
  const catalog = JSON.parse(catalogText);
  assert.equal(catalog.entries.filter((entry) => entry.kind === "postgres-migration").length, 71);
  assert.equal(catalog.entries.find((entry) => entry.version === 67)?.id, "migration.0067_hosted_oauth_completion_column_binding");
});
