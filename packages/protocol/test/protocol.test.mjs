import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import {
  AGENT_KINDS,
  ALLOWED_AGENT_KINDS,
  ALLOWED_OPERATIONS,
  AUDIT_DECISIONS,
  DECISION_REASONS,
  DEVICE_REFRESH_STATES,
  LIMITS,
  OPERATIONS,
  PROTOCOL_VERSION,
  ProtocolValidationError,
  canonicalJson,
  BUNDLE_ACK_REASON_CODES,
  BUNDLE_ACK_SIGNATURE_DOMAIN,
  REFRESH_HINT_SIGNATURE_DOMAIN,
  bundleAcknowledgementSigningData,
  isValidAgentDescriptor,
  isValidScope,
  normalizeAgentDescriptor,
  normalizeAuditEvent,
  normalizeBundleAcknowledgement,
  normalizeDecision,
  normalizeOperationRequest,
  normalizeRefreshHint,
  normalizeScope,
  parseBundleAcknowledgementJson,
  parseRefreshHintJson,
  refreshHintSigningData
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
  assert.deepEqual(DEVICE_REFRESH_STATES, ["pending", "fetching", "applied", "blocked", "stale", "offline", "revoked"]);
  assert.ok(Object.isFrozen(DEVICE_REFRESH_STATES));
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

const syncNonce = Buffer.alloc(16, 0x11).toString("base64url");
const syncSignature = Buffer.alloc(64, 0x22).toString("base64url");

function refreshHint() {
  return {
    version: 1,
    type: "agentpass.refresh-hint",
    organization_id: ids.request,
    device_id: ids.event,
    authority_generation: 42,
    published_at: "2026-08-13T12:00:00.000Z",
    expires_at: "2026-08-13T12:05:00.000Z",
    nonce: syncNonce,
    key_id: "refresh-2026-08",
    signature_algorithm: "ed25519",
    signature: syncSignature
  };
}

function bundleAcknowledgement() {
  return {
    version: 1,
    type: "agentpass.bundle-ack",
    organization_id: ids.request,
    device_id: ids.event,
    device_key_epoch: 3,
    format_epoch: 2,
    sequence: 7,
    statement_hash: digest,
    result: "applied",
    observed_at: "2026-08-13T12:00:01.000Z",
    nonce: syncNonce,
    signature_algorithm: "p256-sha256",
    signature: syncSignature
  };
}

test("normalizes signed refresh hints without treating them as authority", () => {
  assert.deepEqual(normalizeRefreshHint(refreshHint()), refreshHint());
  assert.equal(refreshHintSigningData(refreshHint()).subarray(0, Buffer.byteLength(REFRESH_HINT_SIGNATURE_DOMAIN)).toString(), REFRESH_HINT_SIGNATURE_DOMAIN);
  assert.equal(crypto.createHash("sha256").update(refreshHintSigningData(refreshHint())).digest("hex"), "2b6bc66090c5192d93c6d8cc45086d393d3d402a3e62ed4575464b1d6d69297e");
  for (const mutation of [
    { policy: {} },
    { authority_generation: 0 },
    { expires_at: "2026-08-13T12:05:00.001Z" },
    { nonce: "A".repeat(21) },
    { signature: "A".repeat(85) },
    { signature_algorithm: "p256-sha256" }
  ]) assert.throws(() => normalizeRefreshHint({ ...refreshHint(), ...mutation }), ProtocolValidationError);
});

test("normalizes signed bundle acknowledgements and binds stable blocked reasons", () => {
  assert.deepEqual(normalizeBundleAcknowledgement(bundleAcknowledgement()), bundleAcknowledgement());
  assert.equal(bundleAcknowledgementSigningData(bundleAcknowledgement()).subarray(0, Buffer.byteLength(BUNDLE_ACK_SIGNATURE_DOMAIN)).toString(), BUNDLE_ACK_SIGNATURE_DOMAIN);
  assert.equal(crypto.createHash("sha256").update(bundleAcknowledgementSigningData(bundleAcknowledgement())).digest("hex"), "69cd2a29479c88cca77ce18c0dfe49ebd6e93279d7f16b779e2b4a4a2683f36e");
  const blocked = { ...bundleAcknowledgement(), result: "blocked", reason_code: BUNDLE_ACK_REASON_CODES[0] };
  assert.equal(normalizeBundleAcknowledgement(blocked).reason_code, "bundle_expired");
  assert.throws(() => normalizeBundleAcknowledgement({ ...bundleAcknowledgement(), result: "blocked" }), /missing_field/);
  assert.throws(() => normalizeBundleAcknowledgement({ ...bundleAcknowledgement(), reason_code: "internal_error" }), /inconsistent_value/);
  for (const mutation of [{ device_key_epoch: 0 }, { format_epoch: 1 }, { statement_hash: "A".repeat(64) }, { signature_algorithm: "ed25519" }, { signature: Buffer.concat([Buffer.alloc(32, 1), Buffer.alloc(32, 0xff)]).toString("base64url") }, { token: "secret" }]) {
    assert.throws(() => normalizeBundleAcknowledgement({ ...bundleAcknowledgement(), ...mutation }), ProtocolValidationError);
  }
});

test("Node canonical signing inputs match the shared G4 fixtures", () => {
  const fixture = (name) => fs.readFileSync(new URL(`../../../contracts/fixtures/${name}`, import.meta.url));
  const hint = parseRefreshHintJson(fixture("refresh-hint.valid.json"));
  const acknowledgement = parseBundleAcknowledgementJson(fixture("bundle-ack.valid.json"));
  assert.deepEqual(normalizeRefreshHint(hint), hint);
  assert.deepEqual(normalizeBundleAcknowledgement(acknowledgement), acknowledgement);
  assert.equal(crypto.createHash("sha256").update(refreshHintSigningData(hint)).digest("hex"), "a059221ce35bb6149443a20d1a7c137717d6bb2ab2baee06c727bdcf43407dd3");
  assert.equal(crypto.createHash("sha256").update(bundleAcknowledgementSigningData(acknowledgement)).digest("hex"), "ab820c77106f942649f3853ae76e1c96dbc9d9f1d5dbdbd0df05efa9cde05f55");
});

test("strict JSON decoders reject unsafe boundary inputs with stable issue codes", () => {
  const validHint = JSON.stringify(refreshHint());
  const validAck = JSON.stringify(bundleAcknowledgement());
  const expectIssue = (decode, input, code) => assert.throws(() => decode(input), (error) => {
    assert.ok(error instanceof ProtocolValidationError);
    assert.equal(error.code, "ERR_PROTOCOL_VALIDATION");
    assert.equal(error.issues[0].code, code);
    return true;
  });

  assert.deepEqual(parseRefreshHintJson(validHint), refreshHint());
  assert.deepEqual(parseBundleAcknowledgementJson(Buffer.from(validAck, "utf8")), bundleAcknowledgement());
  expectIssue(parseRefreshHintJson, Buffer.from([0x7b, 0xff, 0x7d]), "invalid_utf8");
  expectIssue(parseRefreshHintJson, "[]", "invalid_type");
  expectIssue(parseRefreshHintJson, "{\"version\":1", "malformed_json");
  expectIssue(parseRefreshHintJson, `{"version":1,"type":"agentpass.refresh-hint","organization_id":"${ids.request}","device_id":"${ids.event}","authority_generation":42,"published_at":"2026-08-13T12:00:00.000Z","expires_at":"2026-08-13T12:05:00.000Z","nonce":"${syncNonce}","key_id":"refresh-2026-08","signature_algorithm":"ed25519","signature":"${syncSignature}","signature":"${syncSignature}"}`, "duplicate_field");
  expectIssue(parseRefreshHintJson, JSON.stringify({ ...refreshHint(), unknown: true }), "unknown_field");
  expectIssue(parseRefreshHintJson, "{" + "\"x\":{".repeat(LIMITS.maxJsonDepth) + "\"version\":1" + "".padEnd(LIMITS.maxJsonDepth, "}") , "json_too_deep");
  expectIssue(parseRefreshHintJson, "x".repeat(LIMITS.maxDocumentBytes + 1), "limit_exceeded");

  const highS = Buffer.concat([Buffer.alloc(32, 1), Buffer.from("7fffffffffffffffffffffffffffffffde737d56d38bcf4279dce5617e3192b8", "hex")]).toString("base64url");
  expectIssue(parseBundleAcknowledgementJson, JSON.stringify({ ...bundleAcknowledgement(), signature: highS }), "noncanonical_signature");
  expectIssue(parseBundleAcknowledgementJson, "{\"result\":true,}", "malformed_json");
  expectIssue(parseBundleAcknowledgementJson, `{"nested":{"duplicate":1,"duplicate":2}}`, "duplicate_field");
});

test("P-256 acknowledgement low-S boundary matches the P-256 group order", () => {
  const halfOrder = Buffer.from("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8", "hex");
  const justAbove = Buffer.from(halfOrder);
  for (let index = justAbove.length - 1; index >= 0; index -= 1) {
    justAbove[index] += 1;
    if (justAbove[index] !== 0) break;
  }
  const atBoundary = Buffer.concat([Buffer.alloc(32, 1), halfOrder]).toString("base64url");
  const aboveBoundary = Buffer.concat([Buffer.alloc(32, 1), justAbove]).toString("base64url");
  assert.equal(normalizeBundleAcknowledgement({ ...bundleAcknowledgement(), signature: atBoundary }).signature, atBoundary);
  assert.throws(() => normalizeBundleAcknowledgement({ ...bundleAcknowledgement(), signature: aboveBoundary }), /noncanonical_signature/);
});
