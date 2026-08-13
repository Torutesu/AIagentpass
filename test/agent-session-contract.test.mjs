import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { canonicalJson } from "../packages/protocol/src/index.mjs";

const root = path.resolve(import.meta.dirname, "..");
const scopeSchema = readJson("contracts/schemas/scope-v1.schema.json");
const grantSchema = readJson("contracts/schemas/agent-session-grant-v1.schema.json");
const leaseSchema = readJson("contracts/schemas/agent-session-lease-v1.schema.json");
const requestSchema = readJson("contracts/schemas/agent-sign-request-v2.schema.json");
const SCOPE_ID = "https://agentpass.dev/contracts/scope-v1.schema.json";

const ids = {
  organization: "11111111-1111-4111-8111-111111111111",
  device: "22222222-2222-4222-8222-222222222222",
  agent: "33333333-3333-4333-8333-333333333333",
  adapter: "44444444-4444-4444-8444-444444444444",
  grant: "55555555-5555-4555-8555-555555555555",
  session: "66666666-6666-4666-8666-666666666666",
  request: "77777777-7777-4777-8777-777777777777",
  capability: "88888888-8888-4888-8888-888888888888"
};

const timestamps = {
  notBefore: "2026-08-13T10:00:00.000Z",
  expiresAt: "2026-08-13T10:15:00.000Z"
};

function readJson(relative) {
  return JSON.parse(fs.readFileSync(path.join(root, relative), "utf8"));
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function scope() {
  return {
    operations: ["git.commit.sign"],
    repositories: ["/work/project"],
    branches: { allow: ["feature/*"], deny: ["main"] },
    remotes: { allow: ["git@example.test:project.git"], deny: [] }
  };
}

function grantStatement() {
  return {
    version: 1,
    grant_id: ids.grant,
    organization_id: ids.organization,
    device_id: ids.device,
    agent_id: ids.agent,
    agent_kind: "claude-code",
    adapter_id: ids.adapter,
    adapter_version: "1.0.0",
    worktree_binding_sha256: "a".repeat(64),
    process_binding_policy_id: "claude-code-v1",
    scope: scope(),
    max_signatures: 2,
    not_before: timestamps.notBefore,
    expires_at: timestamps.expiresAt,
    control_sequence: 12,
    issuer: "agentpass-cloud",
    key_id: "session-grant-2026-08"
  };
}

function grant() {
  const statement = grantStatement();
  return {
    version: 1,
    type: "agentpass.agent-session-grant",
    statement,
    statement_hash: sha256(canonicalJson(statement)),
    signature: Buffer.alloc(64, 0x11).toString("base64url")
  };
}

function lease() {
  return {
    version: 1,
    type: "agentpass.agent-session-lease",
    session_id: ids.session,
    grant_id: ids.grant,
    organization_id: ids.organization,
    device_id: ids.device,
    agent_id: ids.agent,
    agent_kind: "claude-code",
    adapter_id: ids.adapter,
    adapter_version: "1.0.0",
    process_binding_sha256: "b".repeat(64),
    ancestry_binding_sha256: "c".repeat(64),
    worktree_binding_sha256: "a".repeat(64),
    max_signatures: 2,
    used_signatures: 0,
    not_before: timestamps.notBefore,
    expires_at: timestamps.expiresAt,
    control_sequence: 12
  };
}

function capability() {
  return {
    version: 1,
    capability_id: ids.capability,
    nonce: "capability-nonce-2026-08-13-abcdefghijklmnopqrstuvwxyz",
    issuer: "agentpass-cloud",
    key_id: "capability-2026-08",
    audience: { agent_id: ids.agent, device_id: ids.device },
    scope: scope(),
    not_before: timestamps.notBefore,
    expires_at: timestamps.expiresAt,
    sequence: 13,
    signature: Buffer.alloc(64, 0x22).toString("base64")
  };
}

function signRequest() {
  return {
    version: 2,
    request_id: ids.request,
    operation: "git.commit.sign",
    session_id: ids.session,
    cwd: "/work/project",
    payload_base64: Buffer.from("tree aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nauthor A <a@example.test> 0 +0000\ncommitter A <a@example.test> 0 +0000\n\ncommit\n").toString("base64"),
    capability: capability(),
    timestamp_ms: 1780000000000,
    nonce: Buffer.alloc(32, 0x33).toString("base64url")
  };
}

function resolve(schema, rootSchema) {
  if (!schema?.$ref) return { schema, rootSchema };
  if (schema.$ref === SCOPE_ID) return { schema: scopeSchema, rootSchema: scopeSchema };
  assert.match(schema.$ref, /^#\/\$defs\//u, "unexpected schema reference");
  return { schema: rootSchema.$defs[schema.$ref.slice("#/$defs/".length)], rootSchema };
}

function matchesType(value, type) {
  if (type === "object") return value !== null && typeof value === "object" && !Array.isArray(value);
  if (type === "array") return Array.isArray(value);
  if (type === "integer") return Number.isInteger(value);
  if (type === "string") return typeof value === "string";
  if (type === "boolean") return typeof value === "boolean";
  if (type === "null") return value === null;
  return false;
}

function assertSchemaValue(schema, value, rootSchema, label) {
  ({ schema, rootSchema } = resolve(schema, rootSchema));
  if (!schema) throw new Error(`${label} resolved to no schema`);
  if (schema.const !== undefined) assert.deepEqual(value, schema.const, `${label} const`);
  if (schema.enum) assert.ok(schema.enum.includes(value), `${label} enum`);
  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    assert.ok(types.some((type) => matchesType(value, type)), `${label} type`);
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
  if (schema.type === "array") {
    if (schema.minItems !== undefined) assert.ok(value.length >= schema.minItems, `${label} minItems`);
    if (schema.maxItems !== undefined) assert.ok(value.length <= schema.maxItems, `${label} maxItems`);
    if (schema.uniqueItems) assert.equal(new Set(value.map((item) => canonicalJson(item))).size, value.length, `${label} uniqueItems`);
    if (schema.items) for (const [index, item] of value.entries()) assertSchemaValue(schema.items, item, rootSchema, `${label}[${index}]`);
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

function assertValid(schema, value, label) {
  assertSchemaValue(schema, value, schema, label);
}

function assertGrantContext(value, expected = grantStatement()) {
  assert.equal(value.type, "agentpass.agent-session-grant");
  assert.equal(value.statement_hash, sha256(canonicalJson(value.statement)), "grant statement hash");
  for (const key of ["organization_id", "device_id", "agent_id", "agent_kind", "adapter_id", "adapter_version", "worktree_binding_sha256", "max_signatures", "control_sequence"]) {
    assert.equal(value.statement[key], expected[key], `grant binding ${key}`);
  }
  assert.ok(Date.parse(value.statement.expires_at) > Date.parse(value.statement.not_before), "grant expiry must be after not-before");
}

function assertLeaseContext(value, expectedGrant = grantStatement()) {
  for (const key of ["organization_id", "device_id", "agent_id", "agent_kind", "adapter_id", "adapter_version", "worktree_binding_sha256", "max_signatures", "control_sequence"]) {
    assert.equal(value[key], expectedGrant[key], `lease binding ${key}`);
  }
  assert.equal(value.grant_id, expectedGrant.grant_id, "lease grant binding");
  assert.ok(value.used_signatures >= 0 && value.used_signatures <= value.max_signatures, "lease signature budget");
  assert.ok(Date.parse(value.expires_at) > Date.parse(value.not_before), "lease expiry must be after not-before");
}

function assertRequestContext(value, expectedLease = lease()) {
  assert.equal(value.operation, "git.commit.sign");
  assert.equal(value.session_id, expectedLease.session_id, "request session binding");
  assert.equal(value.capability.audience.agent_id, expectedLease.agent_id, "capability agent binding");
  assert.equal(value.capability.audience.device_id, expectedLease.device_id, "capability device binding");
  assert.equal(value.capability.scope.operations[0], "git.commit.sign");
  assert.equal(Object.hasOwn(value, "signature"), false, "request must not carry an agent signature");
}

function parseCanonicalJson(text) {
  assert.equal(typeof text, "string");
  scanJsonForDuplicateKeys(text);
  const value = JSON.parse(text);
  assert.equal(canonicalJson(value), text, "JSON must use canonical encoding");
  return value;
}

function scanJsonForDuplicateKeys(text) {
  let index = 0;
  const whitespace = () => { while (/\s/u.test(text[index] ?? "")) index += 1; };
  const string = () => {
    const start = index;
    index += 1;
    while (index < text.length) {
      if (text[index] === "\\") { index += 2; continue; }
      if (text[index] === '"') { index += 1; return JSON.parse(text.slice(start, index)); }
      index += 1;
    }
    throw new Error("unterminated JSON string");
  };
  const value = () => {
    whitespace();
    if (text[index] === "{") return object();
    if (text[index] === "[") return array();
    if (text[index] === '"') { string(); return; }
    const start = index;
    while (index < text.length && !/[\s,\]}]/u.test(text[index])) index += 1;
    if (start === index) throw new Error("missing JSON value");
    JSON.parse(text.slice(start, index));
  };
  const object = () => {
    index += 1;
    const keys = new Set();
    whitespace();
    if (text[index] === "}") { index += 1; return; }
    while (true) {
      whitespace();
      if (text[index] !== '"') throw new Error("invalid JSON object key");
      const key = string();
      if (keys.has(key)) throw new Error(`duplicate JSON key: ${key}`);
      keys.add(key);
      whitespace();
      if (text[index++] !== ":") throw new Error("missing JSON colon");
      value();
      whitespace();
      if (text[index] === "}") { index += 1; return; }
      if (text[index++] !== ",") throw new Error("missing JSON comma");
    }
  };
  const array = () => {
    index += 1;
    whitespace();
    if (text[index] === "]") { index += 1; return; }
    while (true) {
      value();
      whitespace();
      if (text[index] === "]") { index += 1; return; }
      if (text[index++] !== ",") throw new Error("missing JSON array comma");
    }
  };
  value();
  whitespace();
  if (index !== text.length) throw new Error("trailing JSON data");
}

test("M2 schemas are frozen, strict, bounded, and reuse scope-v1 exactly", () => {
  for (const schema of [grantSchema, leaseSchema, requestSchema]) {
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    assert.equal(schema.type, "object");
    assert.equal(schema.additionalProperties, false);
    assert.ok(schema.maxProperties > 0);
  }
  assert.equal(new Set([grantSchema.$id, leaseSchema.$id, requestSchema.$id]).size, 3);
  assert.equal(grantSchema.maxProperties, grantSchema.required.length);
  assert.equal(leaseSchema.maxProperties, leaseSchema.required.length);
  assert.equal(requestSchema.maxProperties, requestSchema.required.length);
  assert.equal(grantSchema.$defs.statement.properties.scope.$ref, SCOPE_ID);
  assert.equal(requestSchema.$defs.capability.properties.scope.$ref, SCOPE_ID);
  assert.equal(leaseSchema.properties.type.const, "agentpass.agent-session-lease");
  assert.equal(requestSchema.properties.operation.const, "git.commit.sign");
});

test("Grant validates signed statement separation, bindings, bounds, and canonical timestamps", () => {
  const value = grant();
  assertValid(grantSchema, value, "grant");
  assertValid(scopeSchema, value.statement.scope, "grant.scope");
  assertGrantContext(value);
  assert.doesNotMatch(JSON.stringify(value), /(?:private_key|secret|access_token|bearer|audit_token|argv|pid|session_token)/iu);

  for (const mutate of [
    (item) => { item.extra = true; },
    (item) => { delete item.statement.key_id; },
    (item) => { item.statement.extra = true; },
    (item) => { item.statement.max_signatures = 0; },
    (item) => { item.statement.max_signatures = 65; },
    (item) => { item.statement.expires_at = "2026-08-13T10:15:00Z"; },
    (item) => { item.statement.adapter_version = "01.0.0"; }
  ]) {
    const mutated = structuredClone(value);
    mutate(mutated);
    assert.throws(() => assertValid(grantSchema, mutated, "grant"));
  }

  const substituted = structuredClone(value);
  substituted.statement.device_id = "99999999-9999-4999-8999-999999999999";
  substituted.statement_hash = sha256(canonicalJson(substituted.statement));
  assert.throws(() => assertGrantContext(substituted), /grant binding device_id/);
});

test("Lease exposes only bounded public bindings and prevents cross-binding or budget mutation", () => {
  const value = lease();
  assertValid(leaseSchema, value, "lease");
  assertLeaseContext(value);
  assert.doesNotMatch(JSON.stringify(value), /(?:private_key|secret|access_token|bearer|audit_token|argv|pid|session_token|path)/iu);

  for (const mutate of [
    (item) => { item.unexpected = true; },
    (item) => { delete item.process_binding_sha256; },
    (item) => { item.used_signatures = 65; },
    (item) => { item.max_signatures = 0; },
    (item) => { item.expires_at = item.not_before; }
  ]) {
    const mutated = structuredClone(value);
    mutate(mutated);
    assert.throws(() => {
      assertValid(leaseSchema, mutated, "lease");
      assertLeaseContext(mutated);
    });
  }

  const substituted = structuredClone(value);
  substituted.agent_id = "99999999-9999-4999-8999-999999999999";
  assert.throws(() => assertLeaseContext(substituted), /lease binding agent_id/);
});

test("Request v2 fixes the signing operation and accepts only a Cloud capability", () => {
  const value = signRequest();
  assertValid(requestSchema, value, "request");
  assertValid(scopeSchema, value.capability.scope, "request.capability.scope");
  assertRequestContext(value);
  assert.equal(Object.hasOwn(value, "agent_signature"), false);
  assert.equal(Object.hasOwn(value, "sign_args"), false);
  assert.equal(Object.hasOwn(value, "signer_args"), false);

  for (const mutate of [
    (item) => { item.sign_args = ["-f", "/tmp/key"]; },
    (item) => { item.agent_signature = "forged"; },
    (item) => { item.session = "bearer-token"; },
    (item) => { item.timestamp_ms = -1; },
    (item) => { item.nonce = "short"; },
    (item) => { item.operation = "git.push"; },
    (item) => { item.capability.audience.device_id = "99999999-9999-4999-8999-999999999999"; }
  ]) {
    const mutated = structuredClone(value);
    mutate(mutated);
    if (mutated.capability?.audience?.device_id !== value.capability.audience.device_id) {
      assert.throws(() => assertRequestContext(mutated), /capability device binding/);
    } else {
      assert.throws(() => assertValid(requestSchema, mutated, "request"));
    }
  }

  const oversized = structuredClone(value);
  oversized.payload_base64 = "A".repeat(11184813);
  assert.throws(() => assertValid(requestSchema, oversized, "request"), /maxLength/);
});

test("Canonical JSON rejects duplicate keys and noncanonical encodings at the contract boundary", () => {
  const value = grant();
  const encoded = canonicalJson(value);
  assert.equal(parseCanonicalJson(encoded).statement_hash, value.statement_hash);
  assert.throws(() => parseCanonicalJson(JSON.stringify(value, null, 2)), /canonical encoding/);
  assert.throws(() => parseCanonicalJson('{"version":1,"version":1}'), /duplicate JSON key/);
  assert.throws(() => parseCanonicalJson(`${encoded}\n`), /canonical encoding/);
});
