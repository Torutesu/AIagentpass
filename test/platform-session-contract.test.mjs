import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const root = path.resolve(import.meta.dirname, "..");
const schemaDirectory = path.join(root, "contracts", "schemas");
const openapiPath = path.join(root, "contracts", "openapi", "platform-v1.json");
const catalogPath = path.join(root, "contracts", "catalog-v1.json");
const responseFixturePath = path.join(root, "contracts", "fixtures", "platform-session-http-assertion-response.contract.json");

const schemaFiles = Object.freeze([
  "platform-session-challenge-v1.schema.json",
  "platform-session-assertion-v1.schema.json",
  "platform-session-response-v1.schema.json",
  "platform-session-http-assertion-response-v1.schema.json",
  "platform-session-revoke-request-v1.schema.json",
  "platform-session-revoke-response-v1.schema.json"
]);

const ids = Object.freeze({
  challenge: "55555555-5555-4555-8555-555555555555",
  jti: "77777777-7777-4777-8777-777777777777",
  session: "66666666-6666-4666-8666-666666666666",
  principal: "11111111-1111-4111-8111-111111111111",
  assignment: "44444444-4444-4444-8444-444444444444",
  organization: "33333333-3333-4333-8333-333333333333",
  promotion: "88888888-8888-4888-8888-888888888888"
});
const timestamp = "2026-08-15T00:00:00.000Z";
const expiresAt = "2026-08-15T00:15:00.000Z";
const digest = "ab".repeat(32);
const credentialId = Buffer.alloc(32, 7).toString("base64url");
const challengeBytes = Buffer.alloc(32, 3).toString("base64url");

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

const schemas = Object.freeze(Object.fromEntries(schemaFiles.map((file) => [file, readJson(path.join(schemaDirectory, file))])));
const openapi = readJson(openapiPath);
const catalog = readJson(catalogPath);
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
addFormats(ajv);
for (const schema of Object.values(schemas)) ajv.addSchema(schema);

function validator(file) {
  return ajv.getSchema(schemas[file].$id) ?? ajv.compile(schemas[file]);
}

function assertValid(file, value) {
  const validate = validator(file);
  assert.equal(validate(value), true, `${file}: ${ajv.errorsText(validate.errors)}`);
}

function assertInvalid(file, value) {
  const validate = validator(file);
  assert.equal(validate(value), false, `${file} unexpectedly accepted invalid input`);
}

function challengeResponse() {
  return {
    version: 1,
    type: "agentpass.platform-session-challenge",
    challenge_id: ids.challenge,
    challenge: challengeBytes,
    jti: ids.jti,
    allowed_credential_ids: [credentialId],
    operation: "platform.promotion.issue",
    rp_id: "console.agentpass.test",
    origin: "https://console.agentpass.test",
    user_verification: "required",
    issued_at: timestamp,
    expires_at: "2026-08-15T00:02:00.000Z",
    one_use: true
  };
}

function assertionBody() {
  return {
    version: 1,
    type: "agentpass.platform-session-assertion",
    challenge_id: ids.challenge,
    jti: ids.jti,
    credential_id: credentialId,
    client_data_json: Buffer.from("client-data").toString("base64url"),
    authenticator_data: Buffer.from("authenticator-data").toString("base64url"),
    signature: Buffer.from("signature").toString("base64url")
  };
}

function sessionMetadata() {
  return {
    version: 1,
    type: "agentpass.platform-session",
    session_id: ids.session,
    principal_id: ids.principal,
    assignment_id: ids.assignment,
    authority_generation: 4,
    operation: "platform.promotion.issue",
    capability: "platform.promotion.issue",
    request_digest_sha256: digest,
    authenticated_at: timestamp,
    issued_at: timestamp,
    expires_at: expiresAt,
    status: "active"
  };
}

function challengeIntent() {
  return {
    operation: "platform.promotion.issue",
    organization_id: ids.organization,
    promotion_id: ids.promotion,
    deployment_id: "cloud-prod-2026-08",
    environment: "production",
    candidate_id: `release-pkg-sha256-v1-${"a".repeat(64)}`
  };
}

test("Platform v1 contract assets are strict and complete", () => {
  for (const file of schemaFiles) {
    assert.equal(schemas[file].$schema, "https://json-schema.org/draft/2020-12/schema", file);
    assert.equal(schemas[file].type, "object", file);
    assert.equal(schemas[file].additionalProperties, false, file);
    assert.ok(Number.isInteger(schemas[file].maxProperties), `${file} must bound object size`);
  }
  assertValid("platform-session-challenge-v1.schema.json", challengeResponse());
  assertValid("platform-session-assertion-v1.schema.json", assertionBody());
  assertValid("platform-session-response-v1.schema.json", sessionMetadata());
  assertValid("platform-session-http-assertion-response-v1.schema.json", readJson(responseFixturePath));
  assertValid("platform-session-revoke-request-v1.schema.json", {});
  assertValid("platform-session-revoke-response-v1.schema.json", { session: null });
  for (const [file, value] of [
    ["platform-session-challenge-v1.schema.json", challengeResponse()],
    ["platform-session-assertion-v1.schema.json", assertionBody()],
    ["platform-session-response-v1.schema.json", sessionMetadata()],
    ["platform-session-http-assertion-response-v1.schema.json", readJson(responseFixturePath)],
    ["platform-session-revoke-response-v1.schema.json", { session: null }]
  ]) assertInvalid(file, { ...value, unexpected: true });
});

test("challenge request accepts only public mutation intent and binds Idempotency-Key", () => {
  const requestSchema = openapi.components.schemas.PlatformSessionChallengeRequest;
  assert.deepEqual(Object.keys(requestSchema.properties).sort(), [
    "candidate_id", "deployment_id", "environment", "operation", "organization_id", "promotion_id"
  ]);
  assert.equal(requestSchema.additionalProperties, false);
  assert.equal(requestSchema.minProperties, 6);
  assert.equal(requestSchema.maxProperties, 6);
  assert.deepEqual([...requestSchema.required].sort(), Object.keys(challengeIntent()).sort());
  assert.equal(requestSchema.properties.operation.const, "platform.promotion.issue");
  for (const forbidden of ["principal_id", "member_id", "assignment_id", "authority_generation", "credential_id", "allowed_credential_ids"]) {
    assert.equal(Object.hasOwn(requestSchema.properties, forbidden), false, `${forbidden} must not be browser input`);
  }
  const challengeOperation = openapi.paths["/api/platform/v1/sessions/challenges"].post;
  assert.equal(challengeOperation.requestBody.required, true);
  assert.equal(challengeOperation.requestBody.content["application/json"].schema.$ref, "#/components/schemas/PlatformSessionChallengeRequest");
  assert.equal(challengeOperation.parameters.some((parameter) => parameter.$ref === "#/components/parameters/IdempotencyKey"), true);
  assert.equal(openapi.components.parameters.IdempotencyKey.required, true);
  assert.equal(openapi.components.parameters.IdempotencyKey.name, "Idempotency-Key");
  assert.match(openapi.components.parameters.IdempotencyKey.schema.pattern, /A-Za-z0-9/);
  assert.match(challengeOperation["x-agentpass-request-binding"]["canonical-form"], /idempotency_key/);
  assert.deepEqual(challengeOperation["x-agentpass-request-binding"]["browser-authority-fields"], []);
});

test("challenge response is server-derived and contains no internal member/org/session identifiers", () => {
  const schema = schemas["platform-session-challenge-v1.schema.json"];
  assert.deepEqual(Object.keys(schema.properties).sort(), [
    "allowed_credential_ids", "challenge", "challenge_id", "expires_at", "issued_at", "jti", "one_use", "operation", "origin", "rp_id", "type", "user_verification", "version"
  ]);
  for (const forbidden of ["principal_id", "member_id", "organization_id", "platform_session_id", "assignment_id", "authority_generation", "capability", "request_digest_sha256"]) {
    assert.equal(Object.hasOwn(schema.properties, forbidden), false, `${forbidden} must not be returned`);
  }
  assert.equal(schema.properties.operation.const, "platform.promotion.issue");
  assert.equal(openapi.paths["/api/platform/v1/sessions/challenges"].post.responses["201"].$ref, "#/components/responses/PlatformSessionChallengeCreated");
  assert.deepEqual(openapi.paths["/api/platform/v1/sessions/challenges"].post.security, [{ sameOrigin: [], humanSessionCookie: [] }]);
  assert.equal(openapi.components.securitySchemes.humanSessionCookie.name, "__Host-agentpass_session");
  assert.equal(openapi.paths["/api/platform/v1/sessions/challenges"].post["x-agentpass-transport"]["platform-session-bearer"], "absent and forbidden on this endpoint");
});

test("assertion request is exactly the public eight/nine-field WebAuthn boundary", () => {
  const schema = schemas["platform-session-assertion-v1.schema.json"];
  assert.deepEqual(Object.keys(schema.properties).sort(), [
    "authenticator_data", "challenge_id", "client_data_json", "credential_id", "jti", "signature", "type", "user_handle", "version"
  ]);
  assert.deepEqual([...schema.required].sort(), [
    "authenticator_data", "challenge_id", "client_data_json", "credential_id", "jti", "signature", "type", "version"
  ]);
  for (const forbidden of ["challenge", "principal_id", "member_id", "organization_id", "assignment_id", "authority_generation"]) {
    assertInvalid("platform-session-assertion-v1.schema.json", { ...assertionBody(), [forbidden]: "not-accepted" });
  }
  const operation = openapi.paths["/api/platform/v1/sessions"].post;
  assert.equal(operation.requestBody.content["application/json"].schema.$ref, "../schemas/platform-session-assertion-v1.schema.json");
});

test("session and revoke HTTP envelopes keep bearer and internal identity out of JSON", () => {
  const sessionSchema = schemas["platform-session-response-v1.schema.json"];
  const responseSchema = schemas["platform-session-http-assertion-response-v1.schema.json"];
  const forbidden = ["credential_id", "credential_id_sha256", "member_id", "organization_id", "session_bearer", "session_token", "access_token"];
  for (const name of forbidden) {
    assert.equal(Object.hasOwn(sessionSchema.properties, name), false, `${name} leaked from session metadata`);
    assert.equal(Object.hasOwn(responseSchema.properties, name), false, `${name} leaked from HTTP envelope`);
  }
  assert.equal(responseSchema.properties.csrf_token.type, "string");
  assert.equal(responseSchema.properties.csrf_token.minLength, 43);
  assert.equal(openapi.paths["/api/platform/v1/sessions"].post.responses["201"].$ref, "#/components/responses/PlatformSessionIssued");
  assert.equal(openapi.paths["/api/platform/v1/sessions/revoke"].post.requestBody, undefined);
  assert.equal(openapi.paths["/api/platform/v1/sessions/revoke"].post.responses["200"].$ref, "#/components/responses/PlatformSessionRevoked");
  assert.equal(openapi.components.schemas.PlatformSessionRevokeRequest.$ref, "../schemas/platform-session-revoke-request-v1.schema.json");
  assert.equal(openapi.components.schemas.PlatformSessionRevokeResponse.$ref, "../schemas/platform-session-revoke-response-v1.schema.json");
  const assertionAuthentication = openapi.paths["/api/platform/v1/sessions"].post["x-agentpass-authentication"];
  assert.equal(assertionAuthentication["human-session-cookie"], "not read during assertion resolution");
  assert.equal(assertionAuthentication["platform-session-cookie"], "not read during assertion resolution");
  assert.match(assertionAuthentication.origin, /not an identity assertion/iu);
});

test("cookie, CSRF, origin, no-store, and operation surface are explicit", () => {
  assert.deepEqual(Object.keys(openapi.paths).sort(), [
    "/api/platform/v1/sessions",
    "/api/platform/v1/sessions/challenges",
    "/api/platform/v1/sessions/revoke"
  ]);
  assert.deepEqual(Object.keys(openapi.components.securitySchemes).sort(), ["humanSessionCookie", "platformSessionCookie", "platformSessionCsrf", "sameOrigin"]);
  assert.equal(openapi.components.securitySchemes.platformSessionCookie.in, "cookie");
  assert.equal(openapi.components.securitySchemes.platformSessionCookie.name, "__Host-agentpass_platform_session");
  assert.equal(openapi.components.securitySchemes.platformSessionCsrf.in, "header");
  assert.equal(openapi.components.securitySchemes.platformSessionCsrf.name, "agentpass-platform-csrf");
  assert.deepEqual(openapi.paths["/api/platform/v1/sessions/revoke"].post.security, [{ platformSessionCookie: [], platformSessionCsrf: [] }]);
  assert.equal(openapi.paths["/api/platform/v1/sessions/challenges"].post["x-agentpass-request-binding"]["canonical-form"], "canonical-json({candidate_id,deployment_id,environment,idempotency_key,operation,organization_id,promotion_id})");
  assert.equal(openapi.paths["/api/platform/v1/sessions/challenges"].post["x-agentpass-request-binding"].digest, "sha256(UTF-8 canonical-form)");
  assert.match(openapi.components.headers.PlatformSessionSetCookie.schema.pattern, /HttpOnly/);
  assert.match(openapi.components.headers.PlatformSessionSetCookie.schema.pattern, /Secure/);
  assert.match(openapi.components.headers.PlatformSessionSetCookie.schema.pattern, /SameSite=Strict/);
  for (const operation of Object.values(openapi.paths).map((pathValue) => pathValue.post)) {
    for (const response of Object.values(operation.responses)) {
      if (!response.$ref?.includes("#/components/responses/")) continue;
      const responseName = response.$ref.split("/").at(-1);
      const responseDefinition = openapi.components.responses[responseName];
      assert.ok(responseDefinition, responseName);
      if (responseDefinition.headers?.["Cache-Control"]) assert.equal(responseDefinition.headers["Cache-Control"].$ref, "#/components/headers/CacheControlNoStore");
    }
  }
  assert.equal(JSON.stringify(openapi).includes("platform.promotion.replay"), false);
  assert.equal(JSON.stringify(openapi).includes("platform.promotion.verify"), false);
  assert.equal(JSON.stringify(openapi).includes("platform.promotion.reconcile"), false);
});

test("catalog records every platform-session schema and its public HTTP references", () => {
  const expected = [
    "platform-session-challenge-v1",
    "platform-session-assertion-v1",
    "platform-session-response-v1",
    "platform-session-http-assertion-response-v1",
    "platform-session-revoke-request-v1",
    "platform-session-revoke-response-v1"
  ];
  for (const id of expected) {
    const entry = catalog.entries.find((candidate) => candidate.id === `schema.${id}`);
    assert.ok(entry, `catalog entry for ${id}`);
    assert.equal(entry.source, `schemas/${id}.schema.json`);
    assert.ok(entry.implementation_refs.includes("contracts/openapi/platform-v1.json"), `${id} is linked to platform-v1 OpenAPI`);
    assert.ok(entry.compatibility_fixtures.includes("test/platform-session-contract.test.mjs"), `${id} has a contract test`);
  }
});
