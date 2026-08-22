import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { POSTGRES_SCHEMA_HEAD } from "../../src/postgres/schema-head.mjs";

const migrationUrl = new URL("../../../../contracts/postgres/0065_managed_signer_signature_base64_canonical.sql", import.meta.url);
const previousMigrationUrl = new URL("../../../../contracts/postgres/0051_managed_signer_lifecycle_signing_authority.sql", import.meta.url);
const catalogUrl = new URL("../../../../contracts/catalog-v1.json", import.meta.url);
const rolesUrl = new URL("../../../../scripts/postgres/roles.sql", import.meta.url);

const SIGNING_RECORD_SIGNATURE = "text, text, bytea, text, bigint, text, bigint, timestamptz, timestamptz, timestamptz, timestamptz, timestamptz, bytea, text, text";

function postgresBase64WithLineWrapping(value) {
  const encoded = value.toString("base64");
  return encoded.replace(/.{76}(?=.)/gu, "$&\n");
}

test("0065 emits canonical unwrapped base64 without widening execution authority", async () => {
  const [migration, previousMigration, catalogText, roles] = await Promise.all([
    readFile(migrationUrl, "utf8"),
    readFile(previousMigrationUrl, "utf8"),
    readFile(catalogUrl, "utf8"),
    readFile(rolesUrl, "utf8")
  ]);
  const catalog = JSON.parse(catalogText);
  const migrationChecksum = (await import("../../src/postgres/migration-runner.mjs")).migrationChecksum(migration);

  assert.match(migration, /^BEGIN;/u);
  assert.match(migration, /CREATE OR REPLACE FUNCTION public\.agentpass_managed_signer_signing_record_json\(/u);
  assert.doesNotMatch(migration, /(?:^|\n)CREATE FUNCTION public\.agentpass_managed_signer_signing_record_json\(/u);
  assert.match(migration, /RETURNS jsonb[\s\S]*?LANGUAGE sql[\s\S]*?STABLE[\s\S]*?PARALLEL SAFE[\s\S]*?SECURITY INVOKER[\s\S]*?SET search_path = pg_catalog, public/u);
  assert.match(migration, /replace\(encode\(p_signature, 'base64'\), chr\(10\), ''\)/u);
  assert.match(migration, new RegExp(`REVOKE ALL ON FUNCTION public\\.agentpass_managed_signer_signing_record_json\\(\\s*${SIGNING_RECORD_SIGNATURE.replaceAll(", ", "\\s*,\\s*")}\\s*\\) FROM PUBLIC;`, "u"));
  assert.match(migration, /COMMIT;\s*$/u);
  assert.doesNotMatch(migration, /\b(?:ALTER|DROP)\s+(?:FUNCTION|ROUTINE)/iu);
  assert.doesNotMatch(migration, /\bOWNER\s+TO\b/iu);
  assert.doesNotMatch(migration, /\bGRANT\s+(?:ALL\s+)?(?:PRIVILEGES\s+ON\s+)?FUNCTION/iu);

  // 0051 owns the original signature and closes PUBLIC.  0065 must replace
  // that exact object: CREATE OR REPLACE preserves both owner and ACL.
  assert.match(previousMigration, new RegExp(`CREATE FUNCTION public\\.agentpass_managed_signer_signing_record_json\\([\\s\\S]*?\\)\\s*RETURNS jsonb`, "u"));
  assert.match(previousMigration, new RegExp(`REVOKE ALL ON FUNCTION public\\.agentpass_managed_signer_signing_record_json\\(\\s*${SIGNING_RECORD_SIGNATURE.replaceAll(", ", "\\s*,\\s*")}\\s*\\) FROM PUBLIC;`, "u"));
  assert.doesNotMatch(roles, /agentpass_managed_signer_signing_record_json/u);

  // A 64-byte Ed25519 signature is 88 base64 characters. PostgreSQL's
  // RFC-2045 encoder inserts one LF after character 76; stripping that LF
  // yields the exact standard base64 value with no trailing whitespace.
  const signature = Buffer.alloc(64, 0xff);
  const wrapped = postgresBase64WithLineWrapping(signature);
  const canonical = wrapped.replaceAll("\n", "");
  assert.equal(wrapped.includes("\n"), true);
  assert.equal(canonical, signature.toString("base64"));
  assert.equal(canonical.length, 88);
  assert.match(canonical, /^[A-Za-z0-9+/]+={0,2}$/u);
  assert.match(migration, /CASE WHEN p_signature IS NULL THEN NULL/u);

  assert.equal(POSTGRES_SCHEMA_HEAD.version, POSTGRES_SCHEMA_HEAD.migration_count);
  assert.equal(POSTGRES_SCHEMA_HEAD.name, "0110_device_audit_trigger_authority.sql");
  const previousCatalogEntry = catalog.entries.find((entry) => entry.version === 64 && entry.kind === "postgres-migration");
  const currentCatalogEntries = catalog.entries.filter((entry) => entry.version === 65 && entry.kind === "postgres-migration");
  assert.equal(previousCatalogEntry?.version, 64);
  assert.equal(currentCatalogEntries.length, 1);
  assert.deepEqual(catalog.entries.find((entry) => entry.id === "migration.0065_managed_signer_signature_base64_canonical"), {
    id: "migration.0065_managed_signer_signature_base64_canonical",
    kind: "postgres-migration",
    source: "postgres/0065_managed_signer_signature_base64_canonical.sql",
    version: 65,
    sha256: migrationChecksum,
    profile: "migration-global",
    purpose: "migration.0065.managed-signer-signature-base64-canonical",
    implementation_status: "implemented",
    implementation_refs: [
      "contracts/postgres/0065_managed_signer_signature_base64_canonical.sql",
      "apps/cloud-api/src/postgres/managed-signer-key-lifecycle-repository.mjs"
    ],
    compatibility_fixtures: [
      "apps/cloud-api/test/postgres/managed-signer-signature-base64-canonical-migration.test.mjs",
      "apps/cloud-api/test/postgres/managed-signer-key-lifecycle-repository.integration.test.mjs"
    ]
  });
});
