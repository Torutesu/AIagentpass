import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import { canonicalJson } from "../packages/protocol/src/index.mjs";

const root = path.resolve(import.meta.dirname, "..");
const schemaDirectory = path.join(root, "contracts", "schemas");
const openapi = JSON.parse(fs.readFileSync(path.join(root, "contracts", "openapi", "device-v1.json"), "utf8"));
const catalog = JSON.parse(fs.readFileSync(path.join(root, "contracts", "catalog-v1.json"), "utf8"));
const schemaNames = Object.freeze([
  "scope-v1.schema.json",
  "agent-session-signing-capability-request-v1.schema.json",
  "agent-signing-capability-v1.schema.json",
  "agent-session-signing-capability-response-v1.schema.json"
]);
const schemas = Object.freeze(Object.fromEntries(schemaNames.map((name) => [name, JSON.parse(fs.readFileSync(path.join(schemaDirectory, name), "utf8"))])));
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
addFormats(ajv);
for (const schema of Object.values(schemas)) ajv.addSchema(schema);

const ids = Object.freeze({
  organization: "11111111-1111-4111-8111-111111111111",
  device: "22222222-2222-4222-8222-222222222222",
  agent: "33333333-3333-4333-8333-333333333333",
  session: "44444444-4444-4444-8444-444444444444",
  capability: "55555555-5555-4555-8555-555555555555",
  request: "66666666-6666-4666-8666-666666666666"
});
const timestamps = Object.freeze({
  issued: "2026-08-16T00:00:00.000Z",
  expires: "2026-08-16T00:00:30.000Z"
});

function validate(name, value) {
  const validator = ajv.getSchema(schemas[name].$id);
  assert.ok(validator, `${name} validator is registered`);
  return validator(value);
}

function assertValid(name, value) {
  assert.equal(validate(name, value), true, `${name}: ${ajv.errorsText(ajv.getSchema(schemas[name].$id).errors)}`);
}

function assertInvalid(name, value) {
  assert.equal(validate(name, value), false, `${name} unexpectedly accepted invalid input`);
}

function scope() {
  return {
    operations: ["git.commit.sign"],
    repositories: ["/work/project"],
    branches: { allow: ["feature/*"], deny: ["main"] },
    remotes: { allow: ["git@example.test:project.git"], deny: [] }
  };
}

function capabilityStatement() {
  return {
    version: 1,
    type: "agentpass.agent-signing-capability",
    capability_id: ids.capability,
    organization_id: ids.organization,
    session_id: ids.session,
    device_id: ids.device,
    agent_id: ids.agent,
    one_use: true,
    operation: "git.commit.sign",
    scope: scope(),
    key_purpose: "git.commit.sign",
    key_id: "git-commit-signing-v1",
    algorithm: "ed25519",
    max_signatures: 1,
    issued_at: timestamps.issued,
    not_before: timestamps.issued,
    expires_at: timestamps.expires,
    sequence: 13,
    control_sequence: 12,
    authority_generation: 7,
    issuer: "agentpass-cloud"
  };
}

function capability() {
  const statement = capabilityStatement();
  return {
    version: 1,
    type: "agentpass.agent-signing-capability",
    statement,
    statement_hash: crypto.createHash("sha256").update(canonicalJson(statement)).digest("hex"),
    signature: Buffer.alloc(64, 0x22).toString("base64url")
  };
}

function response() {
  return {
    capability: capability(),
    metadata: {
      operation: "git.commit.sign",
      key_purpose: "git.commit.sign",
      issued_at: timestamps.issued,
      expires_at: timestamps.expires,
      sequence: 13,
      remaining_session_signatures: 1,
      replayed: false
    },
    request_id: ids.request
  };
}

function scanJsonForDuplicateKeys(text) {
  let index = 0;
  const whitespace = () => { while (/\s/u.test(text[index] ?? "")) index += 1; };
  const parseString = () => {
    const start = index;
    index += 1;
    while (index < text.length) {
      if (text[index] === "\\") { index += 2; continue; }
      if (text[index] === '"') { index += 1; return JSON.parse(text.slice(start, index)); }
      index += 1;
    }
    throw new Error("unterminated JSON string");
  };
  const parseValue = () => {
    whitespace();
    if (text[index] === "{") return parseObject();
    if (text[index] === "[") return parseArray();
    if (text[index] === '"') { parseString(); return; }
    const start = index;
    while (index < text.length && !/[\s,\]}]/u.test(text[index])) index += 1;
    if (start === index) throw new Error("missing JSON value");
    JSON.parse(text.slice(start, index));
  };
  const parseObject = () => {
    index += 1;
    const keys = new Set();
    whitespace();
    if (text[index] === "}") { index += 1; return; }
    while (true) {
      whitespace();
      if (text[index] !== '"') throw new Error("invalid JSON object key");
      const key = parseString();
      if (keys.has(key)) throw new Error(`duplicate JSON key: ${key}`);
      keys.add(key);
      whitespace();
      if (text[index++] !== ":") throw new Error("missing JSON colon");
      parseValue();
      whitespace();
      if (text[index] === "}") { index += 1; return; }
      if (text[index++] !== ",") throw new Error("missing JSON comma");
    }
  };
  const parseArray = () => {
    index += 1;
    whitespace();
    if (text[index] === "]") { index += 1; return; }
    while (true) {
      parseValue();
      whitespace();
      if (text[index] === "]") { index += 1; return; }
      if (text[index++] !== ",") throw new Error("missing JSON comma");
    }
  };
  parseValue();
  whitespace();
  if (index !== text.length) throw new Error("trailing JSON data");
}

function parseCanonicalJson(text) {
  scanJsonForDuplicateKeys(text);
  const value = JSON.parse(text);
  assert.equal(canonicalJson(value), text, "JSON must use canonical encoding");
  return value;
}

test("F1a schemas are strict, bounded, and expose exact public key sets", () => {
  for (const schema of Object.values(schemas).filter((value) => value !== schemas["scope-v1.schema.json"])) {
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    assert.equal(schema.type, "object");
    assert.equal(schema.additionalProperties, false);
    assert.ok(Number.isInteger(schema.maxProperties));
  }

  const request = schemas["agent-session-signing-capability-request-v1.schema.json"];
  assert.deepEqual(Object.keys(request.properties), ["request_id"]);
  assert.deepEqual(request.required, ["request_id"]);
  assert.equal(request.maxProperties, 1);
  assert.equal(request.minProperties, 1);

  const envelope = schemas["agent-signing-capability-v1.schema.json"];
  assert.deepEqual(Object.keys(envelope.properties), ["version", "type", "statement", "statement_hash", "signature"]);
  assert.deepEqual(Object.keys(envelope.$defs.statement.properties), [
    "version", "type", "capability_id", "organization_id", "session_id", "device_id", "agent_id", "one_use", "operation", "scope",
    "key_purpose", "key_id", "algorithm", "max_signatures", "issued_at", "not_before", "expires_at", "sequence", "control_sequence",
    "authority_generation", "issuer"
  ]);

  const result = schemas["agent-session-signing-capability-response-v1.schema.json"];
  assert.deepEqual(Object.keys(result.properties), ["capability", "metadata", "request_id"]);
  assert.deepEqual(Object.keys(result.$defs.metadata.properties), ["operation", "key_purpose", "issued_at", "expires_at", "sequence", "remaining_session_signatures", "replayed"]);
  assert.equal(result.properties.capability.$ref, "https://agentpass.dev/contracts/agent-signing-capability-v1.schema.json");
  assertValid("agent-session-signing-capability-request-v1.schema.json", { request_id: ids.request });
  assertValid("agent-signing-capability-v1.schema.json", capability());
  assertValid("agent-session-signing-capability-response-v1.schema.json", response());
});

test("F1a request body contains no caller authority and OpenAPI binds only path plus Device auth", () => {
  const route = "/organizations/{organization_id}/devices/{device_id}/agent-sessions/{session_id}/signing-capabilities";
  const operation = openapi.paths[route]?.post;
  assert.ok(operation);
  assert.equal(operation.operationId, "issueAgentSessionSigningCapability");
  assert.deepEqual(operation.security, [{ deviceSignature: [] }]);
  assert.deepEqual(operation.parameters.map((parameter) => parameter.$ref), [
    "#/components/parameters/OrganizationId",
    "#/components/parameters/DeviceId",
    "#/components/parameters/AgentSessionId"
  ]);
  assert.deepEqual(operation.requestBody, { $ref: "#/components/requestBodies/IssueAgentSessionSigningCapability" });
  assert.deepEqual(operation.responses, {
    "201": { $ref: "#/components/responses/AgentSessionSigningCapabilityIssued" },
    "400": { $ref: "#/components/responses/BadRequest" },
    "401": { $ref: "#/components/responses/Unauthorized" },
    "403": { $ref: "#/components/responses/Forbidden" },
    "404": { $ref: "#/components/responses/NotFound" },
    "409": { $ref: "#/components/responses/Conflict" },
    "429": { $ref: "#/components/responses/RateLimited" },
    "503": { $ref: "#/components/responses/ServiceUnavailable" }
  });
  assert.equal(operation["x-agentpass-contract-status"], "frozen-f1a");
  assert.equal(operation["x-agentpass-runtime-path"], `/v1${route}`);
  assert.deepEqual(operation["x-agentpass-request-binding"]["caller-authority-fields"], []);
  assert.deepEqual(operation["x-agentpass-authority"]["derived-fields"], [
    "organization_id", "operation", "scope", "key_purpose", "key_id", "algorithm", "max_signatures", "one_use", "issued_at", "not_before", "expires_at",
    "sequence", "remaining_session_signatures", "control_sequence", "authority_generation"
  ]);
  assert.equal(operation["x-agentpass-authority"]["one-use"], true);
  assert.equal(operation["x-agentpass-authority"]["signature-domain"], "AgentPass-Agent-Signing-Capability-v1\u0000");
  assert.equal(operation["x-agentpass-transport"]["cache-control"], "no-store");
  assert.deepEqual(openapi.components.schemas.AgentSessionSigningCapabilityRequest, { $ref: "../schemas/agent-session-signing-capability-request-v1.schema.json" });
  assert.deepEqual(openapi.components.schemas.AgentSigningCapabilityV1, { $ref: "../schemas/agent-signing-capability-v1.schema.json" });
  assert.deepEqual(openapi.components.schemas.AgentSessionSigningCapabilityResponse, { $ref: "../schemas/agent-session-signing-capability-response-v1.schema.json" });
  assert.deepEqual(openapi.components.requestBodies.IssueAgentSessionSigningCapability.content["application/json"].schema, { $ref: "#/components/schemas/AgentSessionSigningCapabilityRequest" });
  assert.deepEqual(openapi.components.responses.AgentSessionSigningCapabilityIssued.content["application/json"].schema, { $ref: "#/components/schemas/AgentSessionSigningCapabilityResponse" });
  assert.equal(openapi.components.responses.AgentSessionSigningCapabilityIssued.headers["Cache-Control"].$ref, "#/components/headers/CacheControl");
  assert.equal(operation.parameters.some((parameter) => parameter.name === "Idempotency-Key"), false);
});

test("F1a rejects unknown, duplicate, noncanonical, downgrade, and caller-authority input", () => {
  const request = { request_id: ids.request };
  for (const field of [
    "organization_id", "device_id", "session_id", "agent_id", "operation", "scope", "key_purpose", "key_id", "algorithm",
    "ttl_seconds", "max_signatures", "control_sequence", "authority_generation", "not_before", "expires_at", "sequence"
  ]) assertInvalid("agent-session-signing-capability-request-v1.schema.json", { ...request, [field]: field === "scope" ? scope() : "caller-selected" });

  for (const [name, value, field] of [
    ["agent-session-signing-capability-request-v1.schema.json", request, "unexpected"],
    ["agent-signing-capability-v1.schema.json", capability(), "unexpected"],
    ["agent-session-signing-capability-response-v1.schema.json", response(), "unexpected"]
  ]) assertInvalid(name, { ...value, [field]: true });

  const downgradedRequest = { request_id: ids.request, version: 0 };
  assertInvalid("agent-session-signing-capability-request-v1.schema.json", downgradedRequest);
  for (const mutate of [
    (value) => { value.version = 0; },
    (value) => { value.type = "agentpass.capability"; },
    (value) => { value.statement.one_use = false; },
    (value) => { value.statement.operation = "git.push"; },
    (value) => { value.statement.key_purpose = "other"; },
    (value) => { value.statement.algorithm = "rsa-sha256"; },
    (value) => { value.statement.max_signatures = 2; },
    (value) => { delete value.statement.organization_id; },
    (value) => { delete value.statement.issued_at; },
    (value) => { value.statement.authority_generation = 0; }
  ]) {
    const mutated = structuredClone(capability());
    mutate(mutated);
    assertInvalid("agent-signing-capability-v1.schema.json", mutated);
  }
  const expired = capability();
  expired.statement.expires_at = expired.statement.not_before;
  assertValid("agent-signing-capability-v1.schema.json", expired);
  assert.notEqual(Date.parse(expired.statement.expires_at) > Date.parse(expired.statement.not_before), true, "schema leaves temporal ordering to the runtime invariant");

  const overBudgetResponse = response();
  overBudgetResponse.metadata.remaining_session_signatures = 2;
  assertInvalid("agent-session-signing-capability-response-v1.schema.json", overBudgetResponse);

  const encoded = canonicalJson(request);
  assert.deepEqual(parseCanonicalJson(encoded), request);
  assert.throws(() => parseCanonicalJson('{"request_id":"66666666-6666-4666-8666-666666666666","request_id":"77777777-7777-4777-8777-777777777777"}'), /duplicate JSON key: request_id/u);
  assert.throws(() => parseCanonicalJson(`${encoded}\n`), /canonical encoding/u);
  assert.throws(() => parseCanonicalJson(JSON.stringify(request, null, 2)), /canonical encoding/u);

  const duplicateNested = canonicalJson(capability()).replace('"one_use":true', '"one_use":true,"one_use":true');
  assert.throws(() => parseCanonicalJson(duplicateNested), /duplicate JSON key: one_use/u);
  const encodedCapability = canonicalJson(capability());
  assert.deepEqual(parseCanonicalJson(encodedCapability), capability());
  assert.throws(() => parseCanonicalJson(`${encodedCapability}\n`), /canonical encoding/u);
  assert.throws(() => parseCanonicalJson(JSON.stringify(capability(), null, 2)), /canonical encoding/u);
});

test("F1a binds safe metadata to the signed capability and freezes the signing domain", () => {
  const value = response();
  assert.equal(value.metadata.operation, value.capability.statement.operation);
  assert.equal(value.metadata.key_purpose, value.capability.statement.key_purpose);
  assert.equal(value.metadata.issued_at, value.capability.statement.issued_at);
  assert.equal(value.metadata.expires_at, value.capability.statement.expires_at);
  assert.equal(value.metadata.sequence, value.capability.statement.sequence);
  assert.ok(value.metadata.remaining_session_signatures >= 0);
  assert.ok(value.metadata.remaining_session_signatures <= 1);
  assert.equal(crypto.createHash("sha256").update(canonicalJson(value.capability.statement)).digest("hex"), value.capability.statement_hash);
  assert.doesNotMatch(JSON.stringify(value), /(?:private[_-]?key|secret|bearer|access[_-]?token|provider[_-]?diagnostic|credential)/iu);

  const tamperedHash = structuredClone(value);
  tamperedHash.capability.statement_hash = "a".repeat(64);
  assertValid("agent-session-signing-capability-response-v1.schema.json", tamperedHash);
  assert.notEqual(crypto.createHash("sha256").update(canonicalJson(tamperedHash.capability.statement)).digest("hex"), tamperedHash.capability.statement_hash, "schema shape alone cannot authorize a mismatched statement hash");

  const tamperedMetadata = structuredClone(value);
  tamperedMetadata.metadata.sequence += 1;
  assertValid("agent-session-signing-capability-response-v1.schema.json", tamperedMetadata);
  assert.notEqual(tamperedMetadata.metadata.sequence, tamperedMetadata.capability.statement.sequence, "metadata cannot silently become authority");

  const domain = catalog.profiles["cloud-agent-signing-capability"].signature.domain;
  assert.equal(domain, "AgentPass-Agent-Signing-Capability-v1\u0000");
  assert.equal(domain.includes("Agent-Session-Grant"), false);
  assert.equal(domain.includes("\\u0000"), false);
});

test("F1a catalog freezes ownership, server derivation, and contract-only implementation status", () => {
  const expected = {
    "schema.agent-session-signing-capability-request-v1": "cloud-tenant-device-agent-session",
    "schema.agent-signing-capability-v1": "cloud-agent-signing-capability",
    "schema.agent-session-signing-capability-response-v1": "cloud-tenant-device-agent-session",
    "api.device.issueAgentSessionSigningCapability": "cloud-tenant-device-agent-session"
  };
  for (const [id, profile] of Object.entries(expected)) {
    const entry = catalog.entries.find((item) => item.id === id);
    assert.ok(entry, `${id} catalog entry`);
    assert.equal(entry.profile, profile);
    assert.equal(entry.implementation_status, "specified");
    assert.deepEqual(entry.compatibility_fixtures, ["test/agent-session-signing-capability-contract.test.mjs"]);
  }
  const profile = catalog.profiles["cloud-agent-signing-capability"];
  assert.deepEqual(profile.signature, { signed: true, algorithm: "ed25519", domain: "AgentPass-Agent-Signing-Capability-v1\u0000" });
  assert.deepEqual(profile.tenant_binding, { required: true, source: "document", paths: ["statement.organization_id"] });
  assert.deepEqual(catalog.profiles["cloud-tenant-device-agent-session"].idempotency, {
    required: true,
    key_paths: ["path.organization_id", "path.device_id", "path.session_id", "body.request_id"],
    scope: "session",
    replay: "same-result"
  });
});
