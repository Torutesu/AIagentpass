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
