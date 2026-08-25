import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { loadSqlMigrations } from "../../src/postgres/migration-runner.mjs";

const migrationUrl = new URL("../../../../contracts/postgres/0042_managed_signer_provider_operation_query_indexes.sql", import.meta.url);

test("0042 is transactional, additive, and only adds deployment-wide provider-operation query indexes", async () => {
  const sql = await readFile(migrationUrl, "utf8");

  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN|INDEX)|TRUNCATE|ALTER\s+TABLE/iu);
  assert.match(sql, /CREATE INDEX managed_signer_provider_operations_nonterminal_created_at[\s\S]*ON managed_signer_provider_operations \(created_at\)[\s\S]*state IN \('pending', 'started', 'accepted', 'uncertain'\)/u);
  assert.match(sql, /CREATE INDEX managed_signer_provider_operations_reconciliation[\s\S]*ON managed_signer_provider_operations \(updated_at, purpose, operation_id\)[\s\S]*state IN \('accepted', 'uncertain'\)/u);
  assert.match(sql, /CREATE INDEX managed_signer_provider_operations_committed_expiry[\s\S]*ON managed_signer_provider_operations \(expires_at, purpose, operation_id\)[\s\S]*state = 'committed'/u);
  assert.doesNotMatch(sql, /claim_expiry|started_claim_expiry/u, "0041 already owns the claim-expiry path");
});

test("0042 indexes match the current deployment-wide maintenance authority orderings", async () => {
  const [migration, authority] = await Promise.all([
    readFile(migrationUrl, "utf8"),
    readFile(new URL("../../../../contracts/postgres/0050_managed_signer_provider_operation_maintenance_authority.sql", import.meta.url), "utf8")
  ]);

  assert.match(authority, /state IN \('pending', 'started', 'accepted', 'uncertain'\)[\s\S]*ORDER BY created_at, purpose, operation_id[\s\S]*LIMIT 1/u);
  assert.match(authority, /provider\.state IN \('accepted', 'uncertain'\)[\s\S]*ORDER BY provider\.updated_at, provider\.purpose, provider\.operation_id[\s\S]*LIMIT remaining/u);
  assert.match(authority, /provider\.state = 'committed'[\s\S]*ORDER BY provider\.expires_at, signing\.expires_at, provider\.purpose, provider\.operation_id[\s\S]*LIMIT remaining/u);
  assert.match(migration, /nonterminal_created_at[\s\S]*reconciliation[\s\S]*committed_expiry/u);
});

test("0042 is loaded as migration 42 with a content-derived checksum", async () => {
  const migrations = await loadSqlMigrations();
  const migration = migrations.find((item) => item.version === 42);

  assert.equal(migration?.name, "0042_managed_signer_provider_operation_query_indexes.sql");
  assert.match(migration?.checksum ?? "", /^[0-9a-f]{64}$/u);
});
