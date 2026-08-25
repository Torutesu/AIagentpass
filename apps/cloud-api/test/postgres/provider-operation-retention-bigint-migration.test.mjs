import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { POSTGRES_SCHEMA_HEAD } from "../../src/postgres/schema-head.mjs";
import { createPostgresProviderOperationRepository } from "../../src/postgres/provider-operation-repository.mjs";

const migrationUrl = new URL("../../../../contracts/postgres/0066_provider_operation_retention_bigint.sql", import.meta.url);
const rolesUrl = new URL("../../../../scripts/postgres/roles.sql", import.meta.url);
const privilegeCheckUrl = new URL("../../../../scripts/postgres/role-privilege-check.mjs", import.meta.url);
const catalogUrl = new URL("../../../../contracts/catalog-v1.json", import.meta.url);

test("0066 supports the documented 30-to-365-day retention range without removing the integer overload", async () => {
  const [migration, roles, privilegeCheck, catalogText] = await Promise.all([
    readFile(migrationUrl, "utf8"),
    readFile(rolesUrl, "utf8"),
    readFile(privilegeCheckUrl, "utf8"),
    readFile(catalogUrl, "utf8"),
  ]);
  const signature = "agentpass_managed_signer_provider_operation_reserve(text,text,text,integer,bytea,text,bigint,bytea,integer,bigint)";

  assert.match(migration, /^BEGIN;/u);
  assert.match(migration, /p_retention_ms bigint/u);
  assert.match(migration, /p_retention_ms > 31536000000/u);
  assert.match(migration, /p_retention_ms \* interval '1 millisecond'/u);
  assert.match(migration, /REVOKE ALL ON FUNCTION[\s\S]*?integer, bigint[\s\S]*?FROM PUBLIC;/u);
  assert.doesNotMatch(migration, /DROP FUNCTION|ALTER TABLE|GRANT EXECUTE/iu);
  assert.match(migration, /COMMIT;\s*$/u);
  assert.ok(30 * 24 * 60 * 60 * 1_000 > 2_147_483_647, "30-day retention must prove why integer is insufficient");
  assert.match(roles, new RegExp(signature.replace(/[()]/gu, "\\$&"), "u"));
  assert.match(privilegeCheck, new RegExp(signature.replace(/[()]/gu, "\\$&"), "u"));

  assert.equal(POSTGRES_SCHEMA_HEAD.version, POSTGRES_SCHEMA_HEAD.migration_count);
  const catalog = JSON.parse(catalogText);
  assert.equal(catalog.entries.filter((entry) => entry.kind === "postgres-migration").length, POSTGRES_SCHEMA_HEAD.migration_count);
  assert.equal(catalog.entries.find((entry) => entry.version === 66)?.id, "migration.0066_provider_operation_retention_bigint");
});

test("provider operation reserve binds retention as bigint and preserves the full value", async () => {
  const calls = [];
  const client = {
    async query(text, params) {
      calls.push({ text, params });
      return { rowCount: 1, rows: [{ result: { status: "not_found" } }] };
    },
  };
  const repository = createPostgresProviderOperationRepository({
    client,
    purpose: "agentpass.capability",
    keyId: "retention-bigint-test",
    keyVersion: "1",
    randomBytes: () => Buffer.alloc(32, 0x42),
  });
  await repository.reserveOperation({
    purpose: "agentpass.capability",
    operation_id: "retention-bigint-operation",
    algorithm: "ed25519",
    bytes_length: 32,
    request_digest: "a".repeat(64),
    key_id: "retention-bigint-test",
    key_version: "1",
  });
  assert.match(calls[0].text, /\$10::bigint/u);
  assert.equal(calls[0].params[9], 2_592_000_000);
});
