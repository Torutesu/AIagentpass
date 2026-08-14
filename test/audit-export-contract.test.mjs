import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const root = path.resolve(import.meta.dirname, "..");
const readJson = (relativePath) => JSON.parse(fs.readFileSync(path.join(root, relativePath), "utf8"));

const schemas = {
  anchor: readJson("contracts/schemas/audit-anchor-v1.schema.json"),
  create: readJson("contracts/schemas/audit-export-create-v1.schema.json"),
  payload: readJson("contracts/schemas/audit-export-payload-v1.schema.json"),
  response: readJson("contracts/schemas/audit-export-response-v1.schema.json")
};
const fixtures = {
  create: readJson("contracts/fixtures/audit-export-create.contract.json"),
  payload: readJson("contracts/fixtures/audit-export-payload.contract.json"),
  response: readJson("contracts/fixtures/audit-export-response.contract.json")
};

function createValidators() {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  for (const schema of Object.values(schemas)) ajv.addSchema(schema);
  return {
    create: ajv.getSchema(schemas.create.$id),
    payload: ajv.getSchema(schemas.payload.$id),
    response: ajv.getSchema(schemas.response.$id)
  };
}

test("audit export fixtures validate the exact C2 request, payload, and response envelopes", () => {
  const validators = createValidators();
  assert.equal(validators.create(fixtures.create), true, JSON.stringify(validators.create.errors));
  assert.equal(validators.payload(fixtures.payload), true, JSON.stringify(validators.payload.errors));
  assert.equal(validators.response(fixtures.response), true, JSON.stringify(validators.response.errors));

  const requestWithExtraField = { ...fixtures.create, idempotency_key: "transport-only" };
  assert.equal(validators.create(requestWithExtraField), false);
  assert.ok(validators.create.errors.some((error) => error.keyword === "additionalProperties"));

  const responseKeys = Object.keys(fixtures.response).sort();
  assert.deepEqual(responseKeys, [
    "audit_anchor", "chain", "environment", "export_id", "organization_id",
    "payload", "payload_digest", "range", "validity"
  ]);
  for (const forbidden of ["idempotency_key", "request_id", "request_digest", "claim_token", "provider", "provider_receipt", "replayed"]) {
    assert.equal(Object.hasOwn(fixtures.response, forbidden), false, `response must not expose ${forbidden}`);
  }
});

test("audit export OpenAPI operations freeze transport, role, and response linkage", () => {
  const openapi = readJson("contracts/openapi/human-v1.json");
  const create = openapi.paths["/organizations/{organization_id}/audit/exports"].post;
  const get = openapi.paths["/organizations/{organization_id}/audit/exports/{export_id}"].get;

  assert.equal(create["x-agentpass-contract-status"], "frozen-c2");
  assert.deepEqual(create.security, [{ humanSession: [], recentWebAuthn: [] }]);
  assert.equal(create["x-agentpass-minimum-role"], "admin");
  assert.equal(create["x-agentpass-recent-auth-operation"], "audit.export.create");
  assert.deepEqual(create.parameters.map((parameter) => parameter.$ref), [
    "#/components/parameters/OrganizationId",
    "#/components/parameters/CsrfToken",
    "#/components/parameters/IdempotencyKey"
  ]);
  assert.deepEqual(create.requestBody, { $ref: "#/components/requestBodies/CreateAuditExport" });
  assert.deepEqual(create.responses["201"], { $ref: "#/components/responses/AuditExportCreated" });
  assert.match(create.description, /only export_id, environment, and chain/u);
  assert.match(create.description, /recent operation-bound WebAuthn/u);

  assert.equal(get["x-agentpass-contract-status"], "frozen-c2");
  assert.deepEqual(get.security, [{ humanSession: [], recentWebAuthn: [] }]);
  assert.equal(get["x-agentpass-minimum-role"], "auditor");
  assert.equal(get["x-agentpass-recent-auth-operation"], "audit.export.retrieve");
  assert.deepEqual(get.parameters.map((parameter) => parameter.$ref), [
    "#/components/parameters/OrganizationId",
    "#/components/parameters/AuditExportId",
    "#/components/parameters/AuditExportEnvironment",
    "#/components/parameters/AuditExportChain"
  ]);
  assert.deepEqual(get.responses["200"], { $ref: "#/components/responses/AuditExportRetrieved" });
  assert.match(get.description, /exact committed immutable payload, payload_digest, audit_anchor, range, and validity/u);
  assert.match(get.description, /no idempotency, request, claim, provider, or private material fields/u);

  const createSchema = openapi.components.schemas.AuditExportCreateRequest;
  assert.deepEqual(createSchema, { $ref: "../schemas/audit-export-create-v1.schema.json" });
  assert.deepEqual(openapi.components.schemas.AuditExportPayloadV1, { $ref: "../schemas/audit-export-payload-v1.schema.json" });
  assert.deepEqual(openapi.components.schemas.AuditExport, { $ref: "../schemas/audit-export-response-v1.schema.json" });
  assert.deepEqual(openapi.components.schemas.AuditExportResponse.required, ["request_id", "audit_export"]);
  assert.equal(openapi.components.schemas.AuditExportResponse.additionalProperties, false);
  assert.equal(openapi.components.parameters.AuditExportEnvironment.required, true);
  assert.equal(openapi.components.parameters.AuditExportChain.required, true);
});
