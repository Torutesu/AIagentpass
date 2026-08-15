import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { platformPromotionAuthorizationRequestDigest } from "../apps/cloud-api/src/platform-promotion-http-contract.mjs";

const root = path.resolve(import.meta.dirname, "..");
const schemaDirectory = path.join(root, "contracts", "schemas");
const fixtureDirectory = path.join(root, "contracts", "fixtures");
const openapi = readJson(path.join(root, "contracts", "openapi", "platform-v1.json"));
const catalog = readJson(path.join(root, "contracts", "catalog-v1.json"));
const schemaNames = [
  "platform-promotion-issue-request-v1.schema.json",
  "platform-promotion-issue-result-v1.schema.json",
  "platform-promotion-issue-envelope-v1.schema.json"
];

const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
addFormats(ajv);
for (const name of fs.readdirSync(schemaDirectory).filter((item) => item.endsWith(".schema.json"))) {
  ajv.addSchema(readJson(path.join(schemaDirectory, name)));
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function validate(name, value) {
  const schema = readJson(path.join(schemaDirectory, name));
  const check = ajv.getSchema(schema.$id);
  assert.ok(check, `${name} must be registered in AJV`);
  assert.equal(check(value), true, `${name}: ${ajv.errorsText(check.errors)}`);
}

function invalid(name, value) {
  const schema = readJson(path.join(schemaDirectory, name));
  const check = ajv.getSchema(schema.$id);
  assert.ok(check, `${name} must be registered in AJV`);
  assert.equal(check(value), false, `${name} unexpectedly accepted invalid data`);
}

function fixture(name) {
  return readJson(path.join(fixtureDirectory, name));
}

function vector(name) {
  return readJson(path.join(root, "contracts", "vectors", name));
}

function walkKeys(value, visitor) {
  if (!value || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) walkKeys(item, visitor);
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    visitor(key, child);
    walkKeys(child, visitor);
  }
}

test("Platform promotion issue request is exactly the six public intent fields", () => {
  const request = fixture("platform-promotion-issue-request.contract.json");
  validate("platform-promotion-issue-request-v1.schema.json", request);
  assert.deepEqual(Object.keys(request).sort(), [
    "candidate_id", "deployment_id", "environment", "operation", "organization_id", "promotion_id"
  ]);

  for (const forbidden of ["idempotency_key", "proof_id", "jti", "claim_token", "principal_id", "assignment_id", "authority_generation"]) {
    invalid("platform-promotion-issue-request-v1.schema.json", { ...request, [forbidden]: "forbidden" });
  }
  invalid("platform-promotion-issue-request-v1.schema.json", { ...request, operation: "platform.promotion.replay" });
  invalid("platform-promotion-issue-request-v1.schema.json", { ...request, organization_id: "not-a-uuid" });
});

test("Platform promotion result and envelope reuse only the safe public projection", () => {
  const result = fixture("platform-promotion-issue-result.contract.json");
  const created = fixture("platform-promotion-issue-201.contract.json");
  const retried = fixture("platform-promotion-issue-200-retry.contract.json");
  validate("platform-promotion-issue-result-v1.schema.json", result);
  validate("platform-promotion-issue-envelope-v1.schema.json", created);
  validate("platform-promotion-issue-envelope-v1.schema.json", retried);
  assert.equal(result.replayed, false);
  assert.equal(created.promotion.replayed, false);
  assert.equal(retried.promotion.replayed, true);
  assert.equal(created.request_id, retried.request_id);

  const forbidden = new Set([
    "proof_id", "jti", "cookie", "csrf_token", "claim_token", "principal_id", "member_id",
    "assignment_id", "authority_generation", "provider_diagnostics", "provider_operation_id"
  ]);
  for (const value of [result, created, retried]) {
    walkKeys(value, (key) => assert.equal(forbidden.has(key), false, `forbidden response field leaked: ${key}`));
  }
  assert.deepEqual(Object.keys(result).sort(), [
    "candidate_id", "deployment_id", "environment", "promotion_evidence", "promotion_id", "replayed"
  ]);
  assert.deepEqual(Object.keys(created).sort(), ["promotion", "request_id"]);
});

test("Platform v1 exposes one POST issue endpoint with exact proof transport", () => {
  const route = "/api/platform/v1/promotions";
  const operation = openapi.paths[route]?.post;
  assert.ok(operation, "promotion issue POST operation is present");
  assert.deepEqual(Object.keys(openapi.paths).filter((item) => item.startsWith("/api/platform/v1/promotions")), [route]);
  assert.equal(operation.operationId, "issuePlatformPromotion");
  assert.equal(operation.requestBody.content["application/json"].schema.$ref, "../schemas/platform-promotion-issue-request-v1.schema.json");
  assert.deepEqual(operation.security, [{
    sameOrigin: [],
    platformSessionCookie: [],
    platformSessionCsrf: [],
    platformSessionProofId: [],
    platformSessionJti: []
  }]);
  assert.deepEqual(operation.parameters.map((item) => item.$ref), [
    "#/components/parameters/Origin",
    "#/components/parameters/PlatformSessionCsrf",
    "#/components/parameters/PlatformSessionProofId",
    "#/components/parameters/PlatformSessionJti",
    "#/components/parameters/IdempotencyKey"
  ]);
  assert.deepEqual(Object.keys(operation.responses).sort(), ["200", "201", "400", "401", "403", "409", "413", "429", "503"]);
  assert.equal(operation.responses["201"].$ref, "#/components/responses/PlatformPromotionIssued");
  assert.equal(operation.responses["200"].$ref, "#/components/responses/PlatformPromotionRetried");
  assert.equal(operation.responses["429"].$ref, "#/components/responses/TooManyRequests");
  assert.equal(operation.responses["503"].$ref, "#/components/responses/ServiceUnavailable");
  assert.equal(operation["x-agentpass-request-binding"]["canonical-form"], "canonical-json({candidate_id,deployment_id,environment,idempotency_key,operation,organization_id,promotion_id})");
  assert.match(operation["x-agentpass-retry"]["201"], /replayed=false/u);
  assert.match(operation["x-agentpass-retry"]["200"], /replayed=true/u);
  assert.match(operation["x-agentpass-retry"]["409"], /different canonical request digest/u);

  assert.equal(openapi.components.securitySchemes.platformSessionCookie.name, "__Host-agentpass_platform_session");
  assert.equal(openapi.components.securitySchemes.platformSessionCsrf.name, "agentpass-platform-csrf");
  assert.equal(openapi.components.securitySchemes.platformSessionProofId.name, "agentpass-platform-proof-id");
  assert.equal(openapi.components.securitySchemes.platformSessionJti.name, "agentpass-platform-jti");
  assert.equal(openapi.components.securitySchemes.platformSessionProofId.in, "header");
  assert.equal(openapi.components.securitySchemes.platformSessionJti.in, "header");
  assert.equal(openapi.components.securitySchemes.Authorization, undefined);
  assert.equal(openapi.components.securitySchemes.bearer, undefined);
  assert.deepEqual(openapi.components.parameters.PlatformSessionProofId.schema.format, "uuid");
  assert.deepEqual(openapi.components.parameters.PlatformSessionJti.schema.format, "uuid");
  assert.equal(openapi.components.parameters.IdempotencyKey.name, "Idempotency-Key");
  assert.equal(openapi.components.parameters.IdempotencyKey.required, true);
});

test("Platform promotion responses have no bearer or proof response transport", () => {
  for (const name of ["PlatformPromotionIssued", "PlatformPromotionRetried"]) {
    const response = openapi.components.responses[name];
    assert.equal(response.content["application/json"].schema.$ref, "#/components/schemas/PlatformPromotionIssueEnvelope");
    assert.equal(Object.hasOwn(response.headers, "Set-Cookie"), false);
    assert.equal(Object.hasOwn(response.headers, "agentpass-platform-csrf"), false);
    assert.equal(Object.hasOwn(response.headers, "agentpass-platform-proof-id"), false);
    assert.equal(Object.hasOwn(response.headers, "agentpass-platform-jti"), false);
  }
  const forbidden = openapi.paths["/api/platform/v1/promotions"].post["x-agentpass-result-projection"]["forbidden-response-fields"];
  for (const field of ["proof_id", "jti", "cookie", "csrf_token", "claim_token", "principal_id", "member_id", "assignment_id", "authority_generation"]) {
    assert.ok(forbidden.includes(field), `${field} must be forbidden in the result projection`);
  }
});

test("Platform promotion digest vector freezes the exact request binding", () => {
  const value = vector("platform-promotion-request-digest-v1.json");
  assert.deepEqual(Object.keys(value).sort(), ["canonical_form", "input", "request_digest_sha256", "type", "version"]);
  assert.equal(value.version, 1);
  assert.equal(value.type, "agentpass.platform-promotion-request-digest-vector");
  assert.equal(value.canonical_form, "canonical-json({candidate_id,deployment_id,environment,idempotency_key,operation,organization_id,promotion_id})");
  assert.equal(platformPromotionAuthorizationRequestDigest({
    promotion_id: value.input.promotion_id,
    deployment_id: value.input.deployment_id,
    environment: value.input.environment,
    candidate_id: value.input.candidate_id,
    idempotency_key: value.input.idempotency_key
  }, { organizationId: value.input.organization_id, operation: value.input.operation }), value.request_digest_sha256);
});

test("The new issue schemas and fixtures are catalogued without changing source boundaries", () => {
  for (const [id, source, fixtures] of [
    ["schema.platform-promotion-issue-request-v1", "schemas/platform-promotion-issue-request-v1.schema.json", ["contracts/fixtures/platform-promotion-issue-request.contract.json"]],
    ["schema.platform-promotion-issue-result-v1", "schemas/platform-promotion-issue-result-v1.schema.json", ["contracts/fixtures/platform-promotion-issue-result.contract.json"]],
    ["schema.platform-promotion-issue-envelope-v1", "schemas/platform-promotion-issue-envelope-v1.schema.json", ["contracts/fixtures/platform-promotion-issue-201.contract.json", "contracts/fixtures/platform-promotion-issue-200-retry.contract.json"]]
  ]) {
    const entry = catalog.entries.find((item) => item.id === id);
    assert.ok(entry, `${id} catalog entry`);
    assert.equal(entry.source, source);
    assert.ok(entry.implementation_refs.includes("contracts/openapi/platform-v1.json"));
    for (const file of fixtures) assert.ok(entry.compatibility_fixtures.includes(file), `${id} fixture ${file}`);
  }
});
