import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0071_managed_signer_snapshot_timestamp.sql", import.meta.url);
const historicalMigrationUrl = new URL("../../../../contracts/postgres/0051_managed_signer_lifecycle_signing_authority.sql", import.meta.url);

test("0071 forward-replaces the snapshot validator without rewriting migration 0051", async () => {
  const [migration, historical] = await Promise.all([
    readFile(migrationUrl, "utf8"),
    readFile(historicalMigrationUrl, "utf8"),
  ]);

  assert.match(migration, /CREATE OR REPLACE FUNCTION public\.agentpass_managed_signer_snapshot_is_valid\(/u);
  assert.equal(migration.includes("verification_text !~ '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$'"), true);
  assert.equal(migration.includes("verification_text !~ '^\\\\d{4}-\\\\d{2}-\\\\d{2}T\\\\d{2}:\\\\d{2}:\\\\d{2}\\\\.\\\\d{3}Z$'"), false);
  assert.equal(historical.includes("verification_text !~ '^\\\\d{4}-\\\\d{2}-\\\\d{2}T\\\\d{2}:\\\\d{2}:\\\\d{2}\\\\.\\\\d{3}Z$'"), true);
  assert.match(migration, /REVOKE ALL ON FUNCTION public\.agentpass_managed_signer_snapshot_is_valid\([\s\S]*FROM PUBLIC/u);
  assert.match(migration, /^BEGIN;[\s\S]*COMMIT;\s*$/u);
});
