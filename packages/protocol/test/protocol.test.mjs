import test from "node:test";
import assert from "node:assert/strict";
import {
  AGENT_KINDS,
  ALLOWED_AGENT_KINDS,
  ALLOWED_OPERATIONS,
  AUDIT_DECISIONS,
  DECISION_REASONS,
  LIMITS,
  OPERATIONS,
  PROTOCOL_VERSION,
  ProtocolValidationError,
  canonicalJson,
  isValidAgentDescriptor,
  isValidScope,
  normalizeAgentDescriptor,
  normalizeAuditEvent,
  normalizeDecision,
  normalizeOperationRequest,
  normalizeScope
} from "../src/index.mjs";

const ids = {
  agent: "11111111-1111-4111-8111-111111111111",
  request: "22222222-2222-4222-8222-222222222222",
  event: "33333333-3333-4333-8333-333333333333"
};
const digest = "a".repeat(64);
const timestamp = "2026-08-11T01:00:00.000Z";

function scope() {
  return {
    operations: ["git.commit.sign"],
    repositories: ["/work/project"],
    branches: { allow: ["feature/*"], deny: ["main"] },
    remotes: { allow: ["git@example.test:project.git"] }
  };
}

function agent() {
  return {
    version: 1,
    agent_id: ids.agent,
    name: "Claude Code",
    kind: "claude-code",
    public_key: "-----BEGIN PUBLIC KEY-----\nexample\n-----END PUBLIC KEY-----",
    created_at: timestamp
  };
}

function request() {
  return {
    version: 1,
    request_id: ids.request,
    agent_id: ids.agent,
    operation: "git.commit.sign",
    nonce: "0123456789abcdef0123456789abcdef",
    requested_at: timestamp,
    repository: "/work/project",
    branch: "feature/protocol",
    remote: "git@example.test:project.git",
    payload_digest: digest
  };
}

function audit() {
  return {
    version: 1,
    event_id: ids.event,
    request_id: ids.request,
    agent_id: ids.agent,
    operation: "git.commit.sign",
    decision: "allow",
    reason: "allowed",
    policy_sequence: 3,
    capability_sequence: 7,
    repository: "/work/project",
    branch: "feature/protocol",
    remote: "git@example.test:project.git",
    payload_digest: digest,
    device_timestamp: timestamp,
    previous_hash: "0".repeat(64),
    event_hash: "b".repeat(64)
  };
}

test("exports frozen v1 protocol constants", () => {
  assert.equal(PROTOCOL_VERSION, 1);
  assert.deepEqual(ALLOWED_AGENT_KINDS, ["claude-code", "cursor", "mcp", "cli", "custom"]);
  assert.deepEqual(ALLOWED_OPERATIONS, ["git.commit.sign"]);
  assert.equal(AGENT_KINDS, ALLOWED_AGENT_KINDS);
  assert.equal(OPERATIONS, ALLOWED_OPERATIONS);
  assert.equal(Object.isFrozen(ALLOWED_AGENT_KINDS), true);
  assert.equal(Object.isFrozen(ALLOWED_OPERATIONS), true);
  assert.ok(AUDIT_DECISIONS.includes("error"));
  assert.ok(DECISION_REASONS.includes("session_required"));
});

test("normalizes valid protocol values and canonical timestamps", () => {
  const descriptor = normalizeAgentDescriptor({ ...agent(), created_at: "2026-08-11T01:00:00Z" });
  assert.equal(descriptor.created_at, timestamp);
  assert.equal(Object.isFrozen(descriptor), true);
  assert.equal(Object.isFrozen(descriptor.agent_id), true);

  assert.deepEqual(normalizeScope(scope()), { ...scope(), remotes: { ...scope().remotes, deny: [] } });
  assert.deepEqual(normalizeOperationRequest(request()), request());
  assert.deepEqual(normalizeDecision({
    version: 1,
    allowed: true,
    reason: "allowed",
    operation: "git.commit.sign",
    request_id: ids.request,
    evaluated_at: timestamp
  }), {
    version: 1,
    allowed: true,
    reason: "allowed",
    operation: "git.commit.sign",
    request_id: ids.request,
    evaluated_at: timestamp
  });
  assert.deepEqual(normalizeAuditEvent(audit()), audit());
});

test("rejects unknown fields with stable security-sensitive errors", () => {
  assert.throws(() => normalizeAgentDescriptor({ ...agent(), extra: true }), (error) => {
    assert.ok(error instanceof ProtocolValidationError);
    assert.equal(error.code, "ERR_PROTOCOL_VALIDATION");
    assert.deepEqual(error.issues, [{ path: "agent.extra", code: "unknown_field", message: "field is not allowed" }]);
    assert.equal(error.message, "unknown_field at agent.extra: field is not allowed");
    return true;
  });
  assert.throws(() => normalizeOperationRequest({ ...request(), payload: "secret" }), /unknown_field at request\.payload/);
  assert.throws(() => normalizeScope({ ...scope(), token: "bearer" }), /unknown_field at scope\.token/);
});

test("reports deterministic invalid values and rejects inconsistent decisions", () => {
  assert.throws(() => normalizeDecision({
    version: 1,
    allowed: true,
    reason: "branch_denied",
    operation: "git.commit.sign",
    request_id: ids.request,
    evaluated_at: timestamp
  }), /inconsistent_value at decision\.reason/);

  assert.equal(isValidAgentDescriptor({ ...agent(), agent_id: "nope" }), false);
  assert.equal(isValidScope({ ...scope(), operations: ["git.push"] }), false);
  assert.throws(() => normalizeOperationRequest({ ...request(), payload_digest: "A".repeat(64) }), /invalid_digest/);
});

test("enforces bounded strings and arrays", () => {
  assert.throws(() => normalizeScope({ ...scope(), operations: Array.from({ length: LIMITS.maxArrayItems + 1 }, () => "git.commit.sign") }), /limit_exceeded at scope\.operations/);
  assert.throws(() => normalizeAgentDescriptor({ ...agent(), name: "x".repeat(LIMITS.maxNameBytes + 1) }), /limit_exceeded at agent\.name/);
  assert.throws(() => normalizeOperationRequest({ ...request(), branch: "\u0000" }), /unsafe_string at request\.branch/);
  assert.throws(() => normalizeOperationRequest({ ...request(), repository: "/work/../secret" }), /invalid_path/);
  assert.throws(() => normalizeScope({ ...scope(), repositories: ["/work//project"] }), /invalid_path/);
});

test("canonical JSON sorts keys recursively and rejects unsafe values", () => {
  assert.equal(canonicalJson({ z: 1, a: { d: true, c: ["x", null] } }), '{"a":{"c":["x",null],"d":true},"z":1}');
  assert.equal(canonicalJson(-0), "0");
  assert.throws(() => canonicalJson({ value: undefined }), /invalid_json/);
  const cyclic = {};
  cyclic.self = cyclic;
  assert.throws(() => canonicalJson(cyclic), /invalid_json/);
});
