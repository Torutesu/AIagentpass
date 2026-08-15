import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const root = path.resolve(import.meta.dirname, "..");
const schemaDirectory = path.join(root, "contracts", "schemas");

const files = Object.freeze([
  "platform-credential-v1.schema.json",
  "platform-session-challenge-v1.schema.json",
  "platform-session-assertion-v1.schema.json",
  "platform-session-response-v1.schema.json",
  "platform-session-revoke-request-v1.schema.json",
  "platform-session-revoke-response-v1.schema.json"
]);

const responseFiles = Object.freeze([
  "platform-credential-v1.schema.json",
  "platform-session-challenge-v1.schema.json",
  "platform-session-response-v1.schema.json",
  "platform-session-revoke-request-v1.schema.json",
  "platform-session-revoke-response-v1.schema.json"
]);

const ids = Object.freeze({
  request: "11111111-1111-4111-8111-111111111111",
  session: "22222222-2222-4222-8222-222222222222",
  challenge: "33333333-3333-4333-8333-333333333333",
  principal: "44444444-4444-4444-8444-444444444444",
  assignment: "55555555-5555-4555-8555-555555555555"
});

const digest = "a".repeat(64);
const credentialId = "A".repeat(43);
const challenge = "B".repeat(43);
const jti = "C".repeat(43);
const timestamp = "2026-08-15T00:00:00.000Z";
const expiresAt = "2026-08-15T00:05:00.000Z";

function readSchema(file) {
  return JSON.parse(fs.readFileSync(path.join(schemaDirectory, file), "utf8"));
}

const schemas = Object.freeze(Object.fromEntries(files.map((file) => [file, readSchema(file)])));
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

function propertyNames(schema) {
  return Object.keys(schema.properties ?? {});
}

function sampleCredential() {
  return {
    version: 1,
    type: "agentpass.platform-credential",
    credential_id: credentialId,
    principal_id: ids.principal,
    algorithm: "es256",
    transports: ["internal"],
    backup_eligible: false,
    backup_state: false,
    status: "active",
    created_at: timestamp,
    last_used_at: null
  };
}

function sampleChallenge() {
  return {
    version: 1,
    type: "agentpass.platform-session-challenge",
    challenge_id: ids.challenge,
    jti,
    challenge,
    allowed_credential_ids: [credentialId],
    operation: "platform.promotion.issue",
    capability: "platform.promotion.issue",
    principal_id: ids.principal,
    assignment_id: ids.assignment,
    authority_generation: 7,
    request_digest_sha256: digest,
    rp_id: "console.agentpass.dev",
    origin: "https://console.agentpass.dev",
    user_verification: "required",
    issued_at: timestamp,
    expires_at: expiresAt,
    one_use: true
  };
}

function sampleAssertion() {
  return {
    version: 1,
    type: "agentpass.platform-session-assertion",
    challenge_id: ids.challenge,
    jti,
    credential_id: credentialId,
    client_data_json: "D".repeat(64),
    authenticator_data: "E".repeat(64),
    signature: "F".repeat(86),
    user_handle: "G".repeat(22)
  };
}

function sampleSessionResponse() {
  return {
    version: 1,
    type: "agentpass.platform-session",
    request_id: ids.request,
    session_id: ids.session,
    challenge_id: ids.challenge,
    principal_id: ids.principal,
    assignment_id: ids.assignment,
    authority_generation: 7,
    operation: "platform.promotion.issue",
    capability: "platform.promotion.issue",
    request_digest_sha256: digest,
    credential_id_sha256: digest,
    authenticated_at: timestamp,
    issued_at: timestamp,
    expires_at: expiresAt,
    session_transport: "secure-http-only-cookie",
    replayed: false
  };
}

function sampleRevokeRequest() {
  return {
    version: 1,
    type: "agentpass.platform-session-revoke-request",
    request_id: ids.request,
    session_id: ids.session,
    principal_id: ids.principal,
    assignment_id: ids.assignment,
    authority_generation: 7,
    operation: "platform.promotion.issue",
    capability: "platform.promotion.issue",
    request_digest_sha256: digest,
    reason: "self"
  };
}

function sampleRevokeResponse() {
  return {
    version: 1,
    type: "agentpass.platform-session-revoke-response",
    request_id: ids.request,
    session_id: ids.session,
    principal_id: ids.principal,
    assignment_id: ids.assignment,
    authority_generation: 7,
    operation: "platform.promotion.issue",
    capability: "platform.promotion.issue",
    status: "revoked",
    revoked_at: timestamp,
    replayed: false
  };
}

test("N3a adds exactly the frozen platform session contract files", () => {
  assert.deepEqual(files.map((file) => fs.existsSync(path.join(schemaDirectory, file))), files.map(() => true));
  for (const file of files) {
    const schema = schemas[file];
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema", file);
    assert.match(schema.$id, new RegExp(`/${file.replaceAll(".", "\\.")}$`), file);
    assert.equal(schema.type, "object", file);
    assert.equal(schema.additionalProperties, false, file);
    assert.ok(Number.isInteger(schema.maxProperties), `${file} must bound its object size`);
  }
});

test("N3a examples validate and every public object rejects unknown fields", () => {
  const examples = {
    "platform-credential-v1.schema.json": sampleCredential(),
    "platform-session-challenge-v1.schema.json": sampleChallenge(),
    "platform-session-assertion-v1.schema.json": sampleAssertion(),
    "platform-session-response-v1.schema.json": sampleSessionResponse(),
    "platform-session-revoke-request-v1.schema.json": sampleRevokeRequest(),
    "platform-session-revoke-response-v1.schema.json": sampleRevokeResponse()
  };
  for (const [file, value] of Object.entries(examples)) {
    assertValid(file, value);
    assertInvalid(file, { ...value, unexpected: true });
  }
});

test("challenge is operation-bound, generation-bound, and explicitly one-use", () => {
  const schema = schemas["platform-session-challenge-v1.schema.json"];
  assert.deepEqual(schema.required, [
    "version", "type", "challenge_id", "jti", "challenge", "allowed_credential_ids",
    "operation", "capability", "principal_id", "assignment_id", "authority_generation",
    "request_digest_sha256", "rp_id", "origin", "user_verification", "issued_at", "expires_at", "one_use"
  ]);
  assert.equal(schema.properties.one_use.const, true);
  assert.equal(schema.properties.user_verification.const, "required");
  assert.equal(schema.properties.challenge.minLength, 43);
  assert.equal(schema.properties.challenge.maxLength, 43);
  for (const field of ["operation", "capability", "principal_id", "assignment_id", "authority_generation", "request_digest_sha256"]) {
    assert.ok(schema.required.includes(field), `${field} must bind the challenge`);
  }
  assertInvalid("platform-session-challenge-v1.schema.json", { ...sampleChallenge(), one_use: false });
  assertInvalid("platform-session-challenge-v1.schema.json", { ...sampleChallenge(), jti: "short" });
  assertInvalid("platform-session-challenge-v1.schema.json", { ...sampleChallenge(), challenge: "not-a-32-byte-challenge" });
});

test("assertion is the only transient DTO that contains WebAuthn assertion bytes", () => {
  const assertion = schemas["platform-session-assertion-v1.schema.json"];
  assert.deepEqual(new Set(propertyNames(assertion)), new Set([
    "version", "type", "challenge_id", "jti", "credential_id", "client_data_json",
    "authenticator_data", "signature", "user_handle"
  ]));
  for (const field of ["client_data_json", "authenticator_data", "signature"]) assert.ok(assertion.required.includes(field));
  for (const file of responseFiles) {
    const names = propertyNames(schemas[file]);
    for (const forbidden of ["private_key", "session_token", "access_token", "assertion", "client_data_json", "authenticator_data", "signature"]) {
      assert.equal(names.includes(forbidden), false, `${file} must not expose ${forbidden}`);
    }
  }
  assertInvalid("platform-session-assertion-v1.schema.json", { ...sampleAssertion(), private_key: "must-not-be-accepted" });
  assertInvalid("platform-session-assertion-v1.schema.json", { ...sampleAssertion(), session_token: "must-not-be-accepted" });
});

test("session and revoke DTOs preserve authority bindings without bearer material", () => {
  const session = schemas["platform-session-response-v1.schema.json"];
  const revokeRequest = schemas["platform-session-revoke-request-v1.schema.json"];
  const revokeResponse = schemas["platform-session-revoke-response-v1.schema.json"];
  for (const [file, schema] of [
    ["platform-session-response-v1.schema.json", session],
    ["platform-session-revoke-request-v1.schema.json", revokeRequest],
    ["platform-session-revoke-response-v1.schema.json", revokeResponse]
  ]) {
    for (const field of ["operation", "capability", "principal_id", "assignment_id", "authority_generation"]) {
      assert.ok(schema.required.includes(field), `${file} must bind ${field}`);
    }
  }
  assert.equal(session.properties.session_transport.const, "secure-http-only-cookie");
  assert.deepEqual(revokeRequest.properties.operation.enum, session.properties.capability.enum);
  assert.deepEqual(revokeResponse.properties.operation.enum, session.properties.capability.enum);
  assertInvalid("platform-session-response-v1.schema.json", { ...sampleSessionResponse(), session_token: "raw-token" });
  assertInvalid("platform-session-revoke-request-v1.schema.json", { ...sampleRevokeRequest(), assertion: sampleAssertion() });
  assertInvalid("platform-session-revoke-response-v1.schema.json", { ...sampleRevokeResponse(), client_data_json: "raw" });
});

test("credential DTO exposes only public binding metadata", () => {
  const schema = schemas["platform-credential-v1.schema.json"];
  for (const field of ["private_key", "public_key", "secret", "session_token", "assertion", "client_data_json", "authenticator_data", "signature"]) {
    assert.equal(propertyNames(schema).includes(field), false, `credential must not expose ${field}`);
  }
  assert.ok(schema.required.includes("principal_id"));
  for (const field of ["assignment_id", "authority_generation"]) assert.equal(schema.required.includes(field), false);
  assertInvalid("platform-credential-v1.schema.json", { ...sampleCredential(), private_key: "must-not-be-accepted" });
  assertInvalid("platform-credential-v1.schema.json", { ...sampleCredential(), backup_state: true, backup_eligible: false });
});
