import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import { AGENT_SESSION_GRANT_SIGNATURE_DOMAIN } from "../apps/cloud-api/src/agent-session-grant.mjs";
import { POSSESSION_RECEIPT_SIGNATURE_DOMAIN } from "../apps/cloud-api/src/possession-receipt-signer.mjs";
import { QUALIFICATION_GRANT_BATCH_MANIFEST_SIGNATURE_DOMAIN } from "../apps/cloud-api/src/qualification-grant-batch-manifest.mjs";
import {
  BUNDLE_ACK_SIGNATURE_DOMAIN,
  REFRESH_HINT_SIGNATURE_DOMAIN
} from "../packages/protocol/src/index.mjs";

const repositoryRoot = path.resolve(import.meta.dirname, "..");
const catalogPath = path.join(repositoryRoot, "contracts", "catalog-v1.json");
const validatorPath = path.join(repositoryRoot, "scripts", "validate-contracts.mjs");

function readCatalog() {
  return JSON.parse(fs.readFileSync(catalogPath, "utf8"));
}

function runValidatorWithCatalog(mutator = () => {}) {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-contract-catalog-"));
  const temporaryContracts = path.join(temporaryRoot, "contracts");
  fs.cpSync(path.join(repositoryRoot, "contracts"), temporaryContracts, { recursive: true });
  const temporaryCatalogPath = path.join(temporaryContracts, "catalog-v1.json");
  const catalog = JSON.parse(fs.readFileSync(temporaryCatalogPath, "utf8"));
  mutator(catalog);
  fs.writeFileSync(temporaryCatalogPath, `${JSON.stringify(catalog, null, 2)}\n`);
  const result = spawnSync(process.execPath, [validatorPath], {
    cwd: repositoryRoot,
    env: { ...process.env, AGENTPASS_CONTRACTS_DIR: temporaryContracts },
    encoding: "utf8"
  });
  fs.rmSync(temporaryRoot, { recursive: true, force: true });
  return result;
}

function runValidatorWithFixture(name, mutator) {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-contract-fixture-"));
  const temporaryContracts = path.join(temporaryRoot, "contracts");
  fs.cpSync(path.join(repositoryRoot, "contracts"), temporaryContracts, { recursive: true });
  const fixturePath = path.join(temporaryContracts, "fixtures", name);
  const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  mutator(fixture);
  fs.writeFileSync(fixturePath, `${JSON.stringify(fixture, null, 2)}\n`);
  const result = spawnSync(process.execPath, [validatorPath], {
    cwd: repositoryRoot,
    env: { ...process.env, AGENTPASS_CONTRACTS_DIR: temporaryContracts },
    encoding: "utf8"
  });
  fs.rmSync(temporaryRoot, { recursive: true, force: true });
  return result;
}

test("catalog signed domains exactly match implementation constants", () => {
  const catalog = readCatalog();
  const expected = new Map([
    ["schema.agent-session-grant-v1", AGENT_SESSION_GRANT_SIGNATURE_DOMAIN],
    ["schema.bundle-ack-v1", BUNDLE_ACK_SIGNATURE_DOMAIN],
    ["schema.device-possession-receipt-v1", POSSESSION_RECEIPT_SIGNATURE_DOMAIN],
    ["schema.qualification-grant-batch-manifest-v1", QUALIFICATION_GRANT_BATCH_MANIFEST_SIGNATURE_DOMAIN],
    ["schema.refresh-hint-v1", REFRESH_HINT_SIGNATURE_DOMAIN]
  ]);
  for (const [id, domain] of expected) {
    const entry = catalog.entries.find((item) => item.id === id);
    assert.ok(entry, `${id} catalog entry`);
    assert.equal(entry.signature.domain, domain, `${id} signature domain`);
    assert.equal(domain.endsWith("\0"), true, `${id} implementation domain has NUL terminator`);
    assert.equal(entry.signature.domain.endsWith("\0"), true, `${id} catalog domain has NUL terminator`);
    assert.equal(entry.signature.domain.includes("\\u0000"), false, `${id} catalog domain is not a literal escape`);
  }
});

test("catalog freezes the complete current contract inventory", () => {
  const catalog = readCatalog();
  assert.equal(catalog.catalog_id, "agentpass.contract-catalog");
  assert.equal(catalog.catalog_version, 1);
  assert.equal(catalog.status, "frozen");
  assert.equal(catalog.entries.length, 106);
  const counts = catalog.entries.reduce((result, entry) => ({ ...result, [entry.kind]: (result[entry.kind] ?? 0) + 1 }), {});
  assert.deepEqual(counts, { "json-schema": 29, "openapi-operation": 49, "postgres-migration": 28 });
  assert.equal(new Set(catalog.entries.map((entry) => entry.purpose)).size, catalog.entries.length);
  for (const entry of catalog.entries) {
    assert.ok(catalog.profiles[entry.profile], `${entry.id} profile`);
    assert.ok(entry.implementation_refs.length > 0, `${entry.id} implementation refs`);
    assert.ok(entry.compatibility_fixtures.length > 0, `${entry.id} compatibility fixtures`);
  }
  const result = runValidatorWithCatalog();
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /validated frozen contract catalog: 106 entries/);
});

test("catalog includes every promoted Phase 1 schema and fixture", () => {
  const catalog = readCatalog();
  const promoted = [
    "organization-v1",
    "membership-v1",
    "invitation-v1",
    "webauthn-credential-v1",
    "webauthn-ceremony-v1",
    "recent-authorization-v1",
    "policy-v1",
    "capability-v1",
    "control-bundle-v2",
    "purge-authorization-v1",
    "purge-receipt-v1",
    "promotion-evidence-v1"
  ];
  for (const name of promoted) {
    const entry = catalog.entries.find((item) => item.id === `schema.${name}`);
    assert.ok(entry, `${name} catalog entry`);
    assert.equal(entry.source, `schemas/${name}.schema.json`);
    assert.deepEqual(entry.compatibility_fixtures, [`contracts/fixtures/${name.replace(/-v\d+$/, "")}.valid.json`]);
  }
});

test("catalog distinguishes implemented contracts from future specified envelopes", () => {
  const catalog = readCatalog();
  for (const id of ["schema.purge-authorization-v1", "schema.purge-receipt-v1", "schema.promotion-evidence-v1"]) {
    assert.equal(catalog.entries.find((entry) => entry.id === id)?.implementation_status, "specified", `${id} is not represented as implemented`);
  }
  for (const id of ["schema.capability-v1", "schema.control-bundle-v2"]) {
    assert.equal(catalog.entries.find((entry) => entry.id === id)?.signature.domain, "none:raw-canonical-json-statement", `${id} records its legacy preimage truthfully`);
  }
});

test("promoted fixtures are validated against their complete JSON Schema", () => {
  const nestedUnknown = runValidatorWithFixture("capability.valid.json", (fixture) => {
    fixture.audience.unreviewed = true;
  });
  assert.notEqual(nestedUnknown.status, 0);
  assert.match(nestedUnknown.stderr, /does not satisfy capability-v1\.schema\.json/);

  const invalidUnion = runValidatorWithFixture("webauthn-ceremony.valid.json", (fixture) => {
    fixture.status = "consumed";
  });
  assert.notEqual(invalidUnion.status, 0);
  assert.match(invalidUnion.stderr, /does not satisfy webauthn-ceremony-v1\.schema\.json/);
});

test("catalog validation fails closed when an entry is missing", () => {
  const result = runValidatorWithCatalog((catalog) => {
    catalog.entries.pop();
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /catalog is missing an entry/);
});

test("catalog validation fails closed on an unknown source entry", () => {
  const result = runValidatorWithCatalog((catalog) => {
    catalog.entries.push({
      ...catalog.entries[0],
      id: "schema.unknown-v1",
      source: "schemas/unknown-v1.schema.json",
      purpose: "format.unknown.v1"
    });
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /unknown or malformed source entry/);
});

test("catalog validation rejects duplicate purposes", () => {
  const result = runValidatorWithCatalog((catalog) => {
    catalog.entries[1].purpose = catalog.entries[0].purpose;
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /duplicate purpose/);
});

test("catalog validation rejects unknown metadata and duplicate identifiers", () => {
  const unknown = runValidatorWithCatalog((catalog) => {
    catalog.unreviewed_authority = true;
  });
  assert.notEqual(unknown.status, 0);
  assert.match(unknown.stderr, /catalog has an unexpected field set/);

  const duplicate = runValidatorWithCatalog((catalog) => {
    catalog.entries[1].id = catalog.entries[0].id;
  });
  assert.notEqual(duplicate.status, 0);
  assert.match(duplicate.stderr, /duplicate id/);
});

test("catalog validation rejects a missing tenant binding", () => {
  const result = runValidatorWithCatalog((catalog) => {
    const entry = catalog.entries.find((item) => item.id === "schema.agent-session-grant-v1");
    entry.tenant_binding = { required: false, source: "none", paths: [] };
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /missing a required tenant binding/);
});

test("catalog distinguishes document and runtime tenant bindings", () => {
  const catalog = readCatalog();
  for (const id of ["schema.agent-sign-request-v2", "schema.qualification-grant-batch-claim-v1", "schema.scope-v1"]) {
    const entry = catalog.entries.find((item) => item.id === id);
    const binding = entry.tenant_binding ?? catalog.profiles[entry.profile].tenant_binding;
    assert.equal(binding.source, "runtime", `${id} derives tenant from the verified runtime boundary`);
    assert.deepEqual(binding.paths, ["runtime.organization_id"]);
  }

  const result = runValidatorWithCatalog((candidate) => {
    const entry = candidate.entries.find((item) => item.id === "schema.agent-session-grant-v1");
    entry.tenant_binding = { required: true, source: "document", paths: ["missing_tenant"] };
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /path is absent from its JSON Schema/);
});

test("catalog validation rejects absent implementation references", () => {
  const result = runValidatorWithCatalog((catalog) => {
    catalog.entries[0].implementation_refs = ["does-not-exist/implementation.mjs"];
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /absent or invalid implementation_refs file/);
});
