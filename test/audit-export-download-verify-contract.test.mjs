import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const root = path.resolve(import.meta.dirname, "..");
const readJson = (relativePath) => JSON.parse(fs.readFileSync(path.join(root, relativePath), "utf8"));

test("audit export download and verify fixtures are strict and secret-free", () => {
  const schemas = [
    readJson("contracts/schemas/audit-anchor-v1.schema.json"),
    readJson("contracts/schemas/audit-export-payload-v1.schema.json"),
    readJson("contracts/schemas/audit-export-response-v1.schema.json"),
    readJson("contracts/schemas/audit-export-verification-result-v1.schema.json")
  ];
  const exportValue = readJson("contracts/fixtures/audit-export-response.contract.json");
  const verification = readJson("contracts/fixtures/audit-export-verification-result.contract.json");
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  for (const schema of schemas) ajv.addSchema(schema);

  const validExport = ajv.getSchema("https://agentpass.dev/contracts/audit-export-response-v1.schema.json");
  const validVerification = ajv.getSchema("https://agentpass.dev/contracts/audit-export-verification-result-v1.schema.json");
  assert.equal(validExport(exportValue), true, JSON.stringify(validExport.errors));
  assert.equal(validVerification(verification), true, JSON.stringify(validVerification.errors));

  const exportWithRequestMetadata = { ...exportValue, request_id: "request-metadata-is-forbidden" };
  assert.equal(validExport(exportWithRequestMetadata), false);
  assert.ok(validExport.errors.some((error) => error.keyword === "additionalProperties"));
  const verificationWithSecret = { ...verification, secret: "must-not-be-returned" };
  assert.equal(validVerification(verificationWithSecret), false);
  assert.ok(validVerification.errors.some((error) => error.keyword === "additionalProperties"));
  assert.deepEqual(Object.keys(verification).sort(), ["anchor", "historical_key", "payload_digest", "reason", "root", "valid"]);
});

test("catalog inventory includes the C2 download and verification contracts", () => {
  const catalog = readJson("contracts/catalog-v1.json");
  const counts = catalog.entries.reduce((result, entry) => ({ ...result, [entry.kind]: (result[entry.kind] ?? 0) + 1 }), {});
  const schemaCount = fs.readdirSync(path.join(root, "contracts", "schemas"))
    .filter((name) => name.endsWith(".schema.json")).length;
  const migrationCount = fs.readdirSync(path.join(root, "contracts", "postgres"))
    .filter((name) => /^\d{4}_.+\.sql$/u.test(name)).length;
  const operationMethods = new Set(["delete", "get", "head", "options", "patch", "post", "put", "trace"]);
  const catalogOpenApiSources = [...new Set(catalog.entries
    .filter((entry) => entry.kind === "openapi-operation")
    .map((entry) => entry.source))];
  const operationCount = catalogOpenApiSources
    .map((source) => readJson(path.join("contracts", source)))
    .reduce((total, document) => total + Object.values(document.paths ?? {}).reduce(
      (pathTotal, pathItem) => pathTotal + Object.keys(pathItem).filter((key) => operationMethods.has(key)).length,
      0
    ), 0);
  assert.deepEqual(counts, {
    "json-schema": schemaCount,
    "openapi-operation": operationCount,
    "postgres-migration": migrationCount
  });
  assert.equal(catalog.entries.length, schemaCount + operationCount + migrationCount);
  for (const id of ["schema.audit-export-verification-result-v1", "api.human.downloadAuditExport", "api.human.verifyAuditExport"]) {
    assert.ok(catalog.entries.some((entry) => entry.id === id), `${id} catalog entry`);
  }
});
