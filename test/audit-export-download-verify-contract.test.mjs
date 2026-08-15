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

test("audit export download freezes attachment transport and auditor access", () => {
  const document = readJson("contracts/openapi/human-v1.json");
  const operation = document.paths["/organizations/{organization_id}/audit/exports/{export_id}/download"].get;
  assert.equal(operation.operationId, "downloadAuditExport");
  assert.deepEqual(operation.security, [{ humanSession: [], recentWebAuthn: [] }]);
  assert.deepEqual(operation.parameters.map((parameter) => parameter.$ref), [
    "#/components/parameters/OrganizationId",
    "#/components/parameters/AuditExportId",
    "#/components/parameters/AuditExportEnvironment",
    "#/components/parameters/AuditExportChain"
  ]);
  assert.equal(Object.hasOwn(operation, "requestBody"), false);
  assert.equal(operation.parameters.some((parameter) => parameter.$ref.endsWith("CsrfToken") || parameter.$ref.endsWith("IdempotencyKey")), false);
  assert.equal(operation["x-agentpass-contract-status"], "frozen-c2");
  assert.equal(operation["x-agentpass-minimum-role"], "auditor");
  assert.equal(operation["x-agentpass-recent-auth-operation"], "audit.export.download");
  assert.deepEqual(operation.responses["200"], { $ref: "#/components/responses/AuditExportDownload" });

  const response = document.components.responses.AuditExportDownload;
  assert.deepEqual(Object.keys(response.content), ["application/json"]);
  assert.deepEqual(response.content["application/json"].schema, { $ref: "#/components/schemas/AuditExport" });
  assert.equal(response.headers["Content-Type"].schema.const, "application/json");
  assert.equal(response.headers["Content-Disposition"].schema.const, "attachment; filename=\"agentpass-audit-export.json\"");
  assert.equal(response.headers["Cache-Control"].schema.const, "no-store, max-age=0");
  assert.equal(response.headers["X-Content-Type-Options"].schema.const, "nosniff");
});

test("audit export verify freezes exact public input, CSRF, recent WebAuthn, and result fields", () => {
  const document = readJson("contracts/openapi/human-v1.json");
  const operation = document.paths["/organizations/{organization_id}/audit/exports/verify"].post;
  assert.equal(operation.operationId, "verifyAuditExport");
  assert.deepEqual(operation.security, [{ humanSession: [], recentWebAuthn: [] }]);
  assert.deepEqual(operation.parameters.map((parameter) => parameter.$ref), [
    "#/components/parameters/OrganizationId",
    "#/components/parameters/CsrfToken"
  ]);
  assert.equal(operation.parameters.some((parameter) => parameter.$ref.endsWith("IdempotencyKey")), false);
  assert.deepEqual(operation.requestBody, { $ref: "#/components/requestBodies/VerifyAuditExport" });
  assert.equal(operation["x-agentpass-contract-status"], "frozen-c2");
  assert.equal(operation["x-agentpass-recent-auth-operation"], "audit.export.verify");
  assert.deepEqual(operation.responses["200"], { $ref: "#/components/responses/AuditExportVerificationResult" });

  assert.deepEqual(document.components.schemas.AuditExportVerifyRequest, { $ref: "#/components/schemas/AuditExport" });
  assert.deepEqual(document.components.schemas.AuditExportVerificationResult, { $ref: "../schemas/audit-export-verification-result-v1.schema.json" });
  const result = document.components.responses.AuditExportVerificationResult;
  assert.deepEqual(result.content["application/json"].schema, { $ref: "#/components/schemas/AuditExportVerificationResult" });
  assert.equal(result.headers["Cache-Control"].schema.const, "no-store, max-age=0");
  assert.equal(result.headers["X-Content-Type-Options"].schema.const, "nosniff");
});

test("catalog inventory includes the C2 download and verification contracts", () => {
  const catalog = readJson("contracts/catalog-v1.json");
  const counts = catalog.entries.reduce((result, entry) => ({ ...result, [entry.kind]: (result[entry.kind] ?? 0) + 1 }), {});
  assert.equal(catalog.entries.length, 147);
  assert.deepEqual(counts, { "json-schema": 39, "openapi-operation": 61, "postgres-migration": 47 });
  for (const id of ["schema.audit-export-verification-result-v1", "api.human.downloadAuditExport", "api.human.verifyAuditExport"]) {
    assert.ok(catalog.entries.some((entry) => entry.id === id), `${id} catalog entry`);
  }
});
