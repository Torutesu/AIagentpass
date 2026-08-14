import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const contracts = path.join(root, "contracts");

function readJson(relative) {
  return JSON.parse(fs.readFileSync(path.join(root, relative), "utf8"));
}

function resolve(schema, rootSchema) {
  if (!schema?.$ref?.startsWith("#/$defs/")) return schema;
  return rootSchema.$defs[schema.$ref.slice("#/$defs/".length)];
}

function matchesType(value, type) {
  if (type === "object") return value !== null && typeof value === "object" && !Array.isArray(value);
  if (type === "array") return Array.isArray(value);
  if (type === "integer") return Number.isInteger(value);
  if (type === "string") return typeof value === "string";
  if (type === "boolean") return typeof value === "boolean";
  return true;
}

function assertSchemaValue(schema, value, rootSchema, label) {
  schema = resolve(schema, rootSchema);
  if (schema.const !== undefined) assert.deepEqual(value, schema.const, `${label} const`);
  if (schema.enum) assert.ok(schema.enum.includes(value), `${label} enum`);
  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    assert.ok(types.some((type) => type === "null" ? value === null : matchesType(value, type)), `${label} type`);
  }
  if (schema.oneOf) {
    const matches = schema.oneOf.filter((candidate) => {
      try { assertSchemaValue(candidate, value, rootSchema, label); return true; } catch { return false; }
    });
    assert.equal(matches.length, 1, `${label} oneOf`);
    return;
  }
  if (typeof value === "string") {
    if (schema.minLength !== undefined) assert.ok(value.length >= schema.minLength, `${label} minLength`);
    if (schema.maxLength !== undefined) assert.ok(value.length <= schema.maxLength, `${label} maxLength`);
    if (schema.pattern) assert.match(value, new RegExp(schema.pattern), `${label} pattern`);
  }
  if (typeof value === "number") {
    if (schema.minimum !== undefined) assert.ok(value >= schema.minimum, `${label} minimum`);
    if (schema.maximum !== undefined) assert.ok(value <= schema.maximum, `${label} maximum`);
  }
  if (schema.type === "object") {
    for (const required of schema.required ?? []) assert.ok(Object.hasOwn(value, required), `${label}.${required} required`);
    if (schema.maxProperties !== undefined) assert.ok(Object.keys(value).length <= schema.maxProperties, `${label} maxProperties`);
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) assert.ok(Object.hasOwn(schema.properties ?? {}, key), `${label}.${key} unknown`);
    }
    for (const [key, property] of Object.entries(schema.properties ?? {})) {
      if (Object.hasOwn(value, key)) assertSchemaValue(property, value[key], rootSchema, `${label}.${key}`);
    }
  }
}

const issueV2 = readJson("contracts/schemas/device-enrollment-issue-v2.schema.json");
const completionV2 = readJson("contracts/schemas/device-enrollment-completion-v2.schema.json");
const receiptV1 = readJson("contracts/schemas/device-possession-receipt-v1.schema.json");
const receiptVerificationV1 = readJson("contracts/schemas/device-possession-receipt-verification-v1.schema.json");

const ids = [issueV2, completionV2, receiptV1, receiptVerificationV1].map((schema) => schema.$id);

test("Cloud possession schemas are strict, bounded, and uniquely identified", () => {
  assert.equal(new Set(ids).size, ids.length);
  for (const schema of [issueV2, completionV2, receiptV1, receiptVerificationV1]) {
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    assert.equal(schema.type, "object");
    assert.equal(schema.additionalProperties, false);
  }
  assert.equal(issueV2.maxProperties, 8);
  assert.equal(completionV2.maxProperties, 11);
  assert.equal(receiptV1.$defs.receipt.additionalProperties, false);
  assert.equal(receiptV1.$defs.receiptStatement.additionalProperties, false);
  assert.equal(completionV2.properties.device_key.additionalProperties, false);
  assert.equal(completionV2.properties.challenge.additionalProperties, false);
  assert.equal(receiptVerificationV1.maxProperties, 3);
  assert.deepEqual(receiptVerificationV1.required, ["key_id", "algorithm", "public_key"]);
});

test("v2 issue response exposes only closed public possession receipt verification metadata", () => {
  const metadata = {
    key_id: "possession-receipt-v1",
    algorithm: "ed25519",
    public_key: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA6tOzXpegx8uirXcRscbgSA9jsm/JG0Odtv7b56m0pxw=\n-----END PUBLIC KEY-----\n"
  };
  assertSchemaValue(receiptVerificationV1, metadata, receiptVerificationV1, "possession_receipt_verification");
  for (const extra of [
    { ...metadata, purpose: "other-purpose" },
    { ...metadata, private_key: "must-not-cross-boundary" },
    { ...metadata, secret: "must-not-cross-boundary" }
  ]) assert.throws(() => assertSchemaValue(receiptVerificationV1, extra, receiptVerificationV1, "possession_receipt_verification"), /unknown|maxProperties/);
  const openapi = readJson("contracts/openapi/human-v1.json");
  const operation = openapi.paths["/organizations/{organization_id}/device-enrollments"].post;
  assert.equal(operation.responses["201"].$ref, "#/components/responses/DeviceEnrollmentIssued");
  assert.equal(openapi.components.schemas.PossessionReceiptVerificationV1.$ref, "../schemas/device-possession-receipt-verification-v1.schema.json");
  assert.equal(openapi.components.schemas.DeviceEnrollmentIssueResponseV2.properties.enrollment.properties.possession_receipt_verification.$ref, "#/components/schemas/PossessionReceiptVerificationV1");
});

test("v2 issue request accepts only candidate and public-key bindings", () => {
  const request = {
    proof_version: 2,
    candidate_id: "release-2026-08-13-01",
    device_key_fingerprint: `SHA256:${"A".repeat(43)}`,
    enrollment_id: "11111111-1111-4111-8111-111111111111",
    device_id: "22222222-2222-4222-8222-222222222222",
    label: "build-agent",
    platform: "macos",
    ttl_ms: 3600000
  };
  assertSchemaValue(issueV2, request, issueV2, "issue");
  for (const forbidden of ["artifact_sha256", "source_commit", "team_id", "manifest_sha256", "private_key", "credential"]) {
    const substituted = { ...request, [forbidden]: "attacker-controlled" };
    assert.throws(() => assertSchemaValue(issueV2, substituted, issueV2, "issue"), /unknown|maxProperties/);
  }
  assert.throws(() => assertSchemaValue(issueV2, { ...request, proof_version: 1 }, issueV2, "issue"), /const/);
  assert.throws(() => assertSchemaValue(issueV2, { ...request, device_key_fingerprint: "SHA256:short" }, issueV2, "issue"), /minLength|pattern/);
});

test("v1 issue shape remains represented beside v2 in Human OpenAPI", () => {
  const openapi = readJson("contracts/openapi/human-v1.json");
  const operation = openapi.paths["/organizations/{organization_id}/device-enrollments"].post;
  const body = openapi.components.requestBodies.DeviceEnrollmentIssue;
  assert.equal(operation.requestBody.$ref, "#/components/requestBodies/DeviceEnrollmentIssue");
  assert.equal(body.content["application/json"].schema.oneOf.length, 2);
  assert.equal(body.content["application/json"].schema.oneOf[0].$ref, "#/components/schemas/DeviceEnrollmentIssueRequestV1");
  assert.equal(body.content["application/json"].schema.oneOf[1].$ref, "../schemas/device-enrollment-issue-v2.schema.json");
  assert.equal(openapi.components.schemas.DeviceEnrollmentIssueRequestV1.additionalProperties, false);
  assert.ok(operation["x-agentpass-enrollment-v2"].forbidden_request_fields.includes("artifact_sha256"));
});

test("v2 completion binds the challenge to the candidate and key fingerprint", () => {
  const request = {
    version: 2,
    proof_version: 2,
    enrollment_id: "11111111-1111-4111-8111-111111111111",
    organization_id: "33333333-3333-4333-8333-333333333333",
    device_id: "22222222-2222-4222-8222-222222222222",
    label: "build-agent",
    platform: "macos",
    device_key: { algorithm: "p256-sha256", spki_pem: `${"-----BEGIN PUBLIC KEY-----\n"}${"A".repeat(80)}${"\n-----END PUBLIC KEY-----\n"}` },
    candidate_id: "release-2026-08-13-01",
    device_key_fingerprint: `SHA256:${"A".repeat(43)}`,
    challenge: {
      challenge_id: "44444444-4444-4444-8444-444444444444",
      nonce: "A".repeat(43),
      expires_at: "2026-08-13T10:00:00.000Z",
      candidate_id: "release-2026-08-13-01",
      device_key_fingerprint: `SHA256:${"A".repeat(43)}`
    }
  };
  assertSchemaValue(completionV2, request, completionV2, "completion");
  for (const forbidden of ["artifact_sha256", "source_commit", "team_id", "manifest_sha256"]) {
    assert.throws(() => assertSchemaValue(completionV2, { ...request, [forbidden]: "attacker-controlled" }, completionV2, "completion"), /unknown|maxProperties/);
  }
  assert.throws(() => assertSchemaValue(completionV2, { ...request, challenge: { ...request.challenge, nonce: "short" } }, completionV2, "completion"), /minLength|pattern/);
  const openapi = readJson("contracts/openapi/device-v1.json");
  const requestSchema = openapi.paths["/enrollments/{enrollment_id}"].post.requestBody.content["application/json"].schema;
  assert.equal(requestSchema.oneOf[0].$ref, "../schemas/device-enrollment-v1.schema.json");
  assert.equal(requestSchema.oneOf[1].$ref, "../schemas/device-enrollment-completion-v2.schema.json");
});

test("device-authenticated receipt endpoint returns a strict signed receipt", () => {
  const openapi = readJson("contracts/openapi/device-v1.json");
  const operation = openapi.paths["/organizations/{organization_id}/devices/{device_id}/enrollment-receipt"].get;
  assert.equal(operation.operationId, "getDeviceEnrollmentPossessionReceipt");
  assert.deepEqual(operation.security, [{ deviceSignature: [] }]);
  assert.equal(operation.responses["200"].$ref, "#/components/responses/DeviceEnrollmentReceipt");
  assert.equal(openapi.components.responses.DeviceEnrollmentReceipt.content["application/json"].schema.$ref, "#/components/schemas/DevicePossessionReceiptV1");

  const receipt = {
    receipt: {
      version: 1,
      purpose: "device-enrollment-possession-receipt",
      key_id: "possession-receipt-v1",
      algorithm: "ed25519",
      statement: {
        version: 1,
        enrollment_id: "11111111-1111-4111-8111-111111111111",
        organization_id: "33333333-3333-4333-8333-333333333333",
        device_id: "22222222-2222-4222-8222-222222222222",
        candidate_id: "release-2026-08-13-01",
        artifact_sha256: "b".repeat(64),
        source_commit: "c".repeat(40),
        team_id: "ABCDE12345",
        device_key_fingerprint: `SHA256:${"D".repeat(43)}`,
        device_key_epoch: 1,
        challenge_nonce_digest: "e".repeat(64),
        issued_at: "2026-08-13T10:00:00.000Z"
      },
      statement_hash: "a".repeat(64),
      signature: "A".repeat(86)
    },
    request_id: "55555555-5555-4555-8555-555555555555"
  };
  assertSchemaValue(receiptV1, receipt, receiptV1, "receipt");
  const receiptFieldNames = [
    ...Object.keys(receiptV1.properties),
    ...Object.keys(receiptV1.$defs.receipt.properties),
    ...Object.keys(receiptV1.$defs.receiptStatement.properties)
  ].join(",");
  assert.doesNotMatch(receiptFieldNames, /private|credential|raw_nonce/i);
});

test("all possession contract files are JSON and OpenAPI external refs exist", () => {
  for (const relative of [
    "contracts/schemas/device-enrollment-issue-v2.schema.json",
    "contracts/schemas/device-enrollment-completion-v2.schema.json",
    "contracts/schemas/device-possession-receipt-v1.schema.json",
    "contracts/schemas/device-possession-receipt-verification-v1.schema.json",
    "contracts/openapi/human-v1.json",
    "contracts/openapi/device-v1.json"
  ]) assert.doesNotThrow(() => readJson(relative));
  for (const relative of [
    "contracts/schemas/device-enrollment-issue-v2.schema.json",
    "contracts/schemas/device-enrollment-completion-v2.schema.json",
    "contracts/schemas/device-possession-receipt-v1.schema.json",
    "contracts/schemas/device-possession-receipt-verification-v1.schema.json"
  ]) assert.equal(fs.statSync(path.join(root, relative)).isFile(), true);
});
