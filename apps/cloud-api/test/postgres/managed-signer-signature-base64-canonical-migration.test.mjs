import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { POSTGRES_SCHEMA_HEAD } from "../../src/postgres/schema-head.mjs";

const migrationUrl = new URL("../../../../contracts/postgres/0065_managed_signer_signature_base64_canonical.sql", import.meta.url);
const catalogUrl = new URL("../../../../contracts/catalog-v1.json", import.meta.url);

test("0065 emits canonical unwrapped base64 without widening execution authority", async () => {
  const [migration, catalogText] = await Promise.all([
    readFile(migrationUrl, "utf8"),
    readFile(catalogUrl, "utf8")
  ]);
  const catalog = JSON.parse(catalogText);

  assert.match(migration, /^BEGIN;/u);
  assert.match(migration, /CREATE OR REPLACE FUNCTION public\.agentpass_managed_signer_signing_record_json\(/u);
  assert.match(migration, /replace\(encode\(p_signature, 'base64'\), chr\(10\), ''\)/u);
  assert.match(migration, /REVOKE ALL ON FUNCTION public\.agentpass_managed_signer_signing_record_json\(/u);
  assert.match(migration, /FROM PUBLIC;/u);
  assert.match(migration, /COMMIT;\s*$/u);
  assert.doesNotMatch(migration, /GRANT\s+EXECUTE/u);

  assert.equal(POSTGRES_SCHEMA_HEAD.version, 65);
  assert.equal(POSTGRES_SCHEMA_HEAD.name, "0065_managed_signer_signature_base64_canonical.sql");
  assert.deepEqual(catalog.entries.find((entry) => entry.id === "migration.0065_managed_signer_signature_base64_canonical"), {
    id: "migration.0065_managed_signer_signature_base64_canonical",
    kind: "postgres-migration",
    source: "postgres/0065_managed_signer_signature_base64_canonical.sql",
    version: 65,
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
