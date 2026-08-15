import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { loadSqlMigrations } from "../../src/postgres/migration-runner.mjs";

const migrationUrls = Object.freeze([
  new URL("../../../../contracts/postgres/0049_managed_signer_provider_operation_authority.sql", import.meta.url),
  new URL("../../../../contracts/postgres/0050_managed_signer_provider_operation_maintenance_authority.sql", import.meta.url)
]);

const REQUIRED_FAMILIES = Object.freeze([
  "agentpass_managed_signer_provider_operation_",
  "agentpass_maintain_managed_signer_provider_operations",
  "agentpass_health_managed_signer_provider_operations"
]);
const INVOKER_HELPERS = new Set([
  "agentpass_managed_signer_provider_operation_error",
  "agentpass_managed_signer_provider_operation_not_found",
  "agentpass_managed_signer_provider_operation_binding_valid",
  "agentpass_managed_signer_provider_operation_record"
]);

test("0049-0050 expose only fixed-search-path SECURITY DEFINER signer functions", async () => {
  const sources = await Promise.all(migrationUrls.map((url) => readFile(url, "utf8")));
  const sql = sources.join("\n");
  for (const source of sources) {
    assert.match(source, /^BEGIN;/mu);
    assert.match(source, /^COMMIT;/mu);
    assert.doesNotMatch(source, /\bEXECUTE\s+(?:format\s*\(|[^;]*\|\|)/iu);
  }

  const functions = functionDefinitions(sql);
  assert.ok(functions.length >= 16, "the signer boundary must use narrow operation-specific entry points");
  for (const family of REQUIRED_FAMILIES) {
    assert.ok(functions.some(({ name }) => name.startsWith(family)), `missing ${family} function family`);
  }
  for (const definition of functions) {
    if (INVOKER_HELPERS.has(definition.name)) assert.match(definition.body, /\bSECURITY INVOKER\b/u);
    else assert.match(definition.body, /\bSECURITY DEFINER\b/u, `${definition.name} must be SECURITY DEFINER`);
    assert.match(definition.body, /SET search_path = pg_catalog, public/u, `${definition.name} must pin search_path`);
    assert.match(sql, new RegExp(`REVOKE ALL ON FUNCTION\\s+(?:public\\.)?${escapeRegex(definition.signature)}\\s+FROM PUBLIC`, "u"));
  }
});

test("0051 remains the reviewed signer authority slice and all signer slices are catalogued", async () => {
  const migrations = await loadSqlMigrations();
  const migration = migrations.find(({ version }) => version === 51);
  assert.equal(migration?.version, 51);
  assert.equal(migration?.name, "0051_managed_signer_lifecycle_signing_authority.sql");
  assert.match(migration?.checksum ?? "", /^[0-9a-f]{64}$/u);

  const catalog = JSON.parse(await readFile(new URL("../../../../contracts/catalog-v1.json", import.meta.url), "utf8"));
  for (const expected of [
    ["migration.0049_managed_signer_provider_operation_authority", "postgres/0049_managed_signer_provider_operation_authority.sql", 49],
    ["migration.0050_managed_signer_provider_operation_maintenance_authority", "postgres/0050_managed_signer_provider_operation_maintenance_authority.sql", 50],
    ["migration.0051_managed_signer_lifecycle_signing_authority", "postgres/0051_managed_signer_lifecycle_signing_authority.sql", 51]
  ]) {
    const entry = catalog.entries.find((item) => item.id === expected[0]);
    assert.equal(entry?.source, expected[1]);
    assert.equal(entry?.version, expected[2]);
    assert.equal(entry?.implementation_status, "implemented");
  }
});

test("provider-operation repositories have no direct ledger SQL and role policy grants their functions only", async () => {
  const repositoryUrls = [
    "../../src/postgres/provider-operation-repository.mjs",
    "../../src/postgres/provider-operation-maintenance-repository.mjs"
  ];
  const repositories = await Promise.all(repositoryUrls.map((url) => readFile(new URL(url, import.meta.url), "utf8")));
  for (const source of repositories) {
    assert.doesNotMatch(source, /\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM|FROM|JOIN)\s+managed_signer_/iu);
  }

  const roles = await readFile(new URL("../../../../scripts/postgres/roles.sql", import.meta.url), "utf8");
  assert.doesNotMatch(roles, /'managed_signer_provider_operations'[\s\S]{0,300}TO agentpass_signer/iu);
  assert.match(roles, /REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM agentpass_app, agentpass_signer, agentpass_backup/iu);
  assert.match(roles, /EXECUTE format\('GRANT EXECUTE ON FUNCTION public\.%s TO agentpass_signer'/iu);
});

function functionDefinitions(sql) {
  const starts = [...sql.matchAll(/CREATE FUNCTION\s+(?:public\.)?([a-z0-9_]+)\s*\(([^)]*)\)/gu)];
  return starts.map((match, index) => {
    const end = starts[index + 1]?.index ?? sql.length;
    const args = match[2].split(",").map((argument) => argument.trim().split(/\s+/u).at(-1)).filter(Boolean).join(",");
    return {
      name: match[1],
      signature: `${match[1]}(${args})`,
      body: sql.slice(match.index, end)
    };
  });
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}
