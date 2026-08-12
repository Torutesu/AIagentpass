import crypto from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";
import {
  CAPABILITY_REASONS,
  CapabilityError,
  effectiveScope,
  intersectScopes,
  issueCapability,
  scopeAllows,
  verifyCapability
} from "../src/index.mjs";

const NOW = Date.parse("2026-08-12T00:00:00.000Z");
const agentId = crypto.randomUUID();
const deviceId = crypto.randomUUID();
const issuer = "org-example";
const keyId = "offline-capability-1";
const keys = crypto.generateKeyPairSync("ed25519");
const scope = {
  operations: ["git.commit.sign"],
  repositories: ["/work/project"],
  branches: { allow: ["feature/*"], deny: ["main"] },
  remotes: { allow: ["git@github.com:example/*"] }
};

function issue(overrides = {}) {
  return issueCapability({
    issuer,
    key_id: keyId,
    audience: { agent_id: agentId, device_id: deviceId },
    scope,
    sequence: 4,
    ttl_ms: 5 * 60 * 1000,
    ...overrides
  }, keys.privateKey, { now: NOW });
}

test("issues and verifies a short-lived Ed25519 capability", () => {
  const capability = issue();
  assert.equal(capability.version, 1);
  assert.equal(verifyCapability(capability, { issuers: { [issuer]: { [keyId]: keys.publicKey } } }, {
    now: NOW + 1_000,
    audience: { agent_id: agentId, device_id: deviceId }
  }).sequence, 4);
});

test("rejects unknown fields and invalid identity, audience, nonce, and signature", () => {
  assert.throws(() => issue({ extra: true }), (error) => error instanceof CapabilityError && error.reason === CAPABILITY_REASONS.UNKNOWN_FIELD);
  assert.throws(() => verifyCapability({ ...issue(), extra: true }, { keys: { [keyId]: keys.publicKey } }, { now: NOW }), /unknown field/);
  assert.throws(() => issue({ capability_id: "not-a-uuid" }), /UUID/);
  assert.throws(() => issue({ nonce: "too-short" }), (error) => error.reason === CAPABILITY_REASONS.INVALID_NONCE);
  const tampered = { ...issue(), sequence: 5 };
  assert.throws(() => verifyCapability(tampered, { keys: { [keyId]: keys.publicKey } }, { now: NOW }), /signature is invalid/);
  assert.throws(() => issue({ key_id: keyId, keyId }), /cannot contain both/);
  assert.throws(() => verifyCapability({ ...issue(), signature: "AAAA" }, { keys: { [keyId]: keys.publicKey } }, { now: NOW }), (error) => error.reason === CAPABILITY_REASONS.INVALID_SIGNATURE_ENCODING);
});

test("checks issuer/key binding, audience, time bounds, and maximum TTL", () => {
  const capability = issue();
  assert.throws(() => verifyCapability(capability, { issuers: { other: { [keyId]: keys.publicKey } } }, { now: NOW }), /issuer is not trusted/);
  assert.throws(() => verifyCapability(capability, { issuers: { [issuer]: { [keyId]: keys.publicKey } } }, { now: NOW, audience: { agent_id: crypto.randomUUID(), device_id: deviceId } }), /audience/);
  assert.throws(() => issue({ ttl_ms: 16 * 60 * 1000 }), /maximum TTL/);
  assert.throws(() => verifyCapability(issue({ not_before: new Date(NOW + 61_000).toISOString() }), { keys: { [keyId]: keys.publicKey } }, { now: NOW }), /not yet valid/);
  assert.throws(() => verifyCapability(issue({ ttl_ms: 30_000 }), { keys: { [keyId]: keys.publicKey } }, { now: NOW + 31_000 }), /expired/);
});

test("enforces monotonic sequences only after signature verification", () => {
  const state = { highestSequence: 3 };
  const first = issue({ sequence: 4 });
  assert.equal(verifyCapability(first, { keys: { [keyId]: keys.publicKey } }, { now: NOW, sequenceState: state }).sequence, 4);
  assert.equal(state.highestSequence, 4);
  assert.equal(typeof state.highestCapabilityHash, "string");
  assert.equal(verifyCapability(first, { keys: { [keyId]: keys.publicKey } }, { now: NOW, sequenceState: state }).sequence, 4);
  assert.throws(() => verifyCapability(issue({ sequence: 4 }), { keys: { [keyId]: keys.publicKey } }, { now: NOW, sequenceState: state }), (error) => error.reason === CAPABILITY_REASONS.SEQUENCE_CONFLICT);
  assert.throws(() => verifyCapability(issue({ sequence: 3 }), { keys: { [keyId]: keys.publicKey } }, { now: NOW, sequenceState: state }), /rolled back/);
  assert.throws(() => verifyCapability(issue({ sequence: 5 }), { keys: { [keyId]: keys.publicKey } }, { now: NOW, sequenceHook: () => false }), /rejected|rolled back/);
  const unchanged = { highestSequence: 4, highestCapabilityHash: state.highestCapabilityHash };
  assert.throws(() => verifyCapability(issue({ sequence: 5 }), { keys: { [keyId]: keys.publicKey } }, { now: NOW, sequenceState: unchanged, onSequence: () => { throw new Error("storage failed"); } }), /rejected/);
  assert.equal(unchanged.highestSequence, 4);
});

test("binds direct trust aliases and requires a complete expected audience", () => {
  const capability = issue();
  assert.throws(() => verifyCapability(capability, { public_key: keys.publicKey, keyId: "other" }, { now: NOW }), (error) => error.reason === CAPABILITY_REASONS.KEY_ID_NOT_TRUSTED);
  assert.throws(() => verifyCapability(capability, { keys: { [keyId]: keys.publicKey } }, { now: NOW, agent_id: agentId }), (error) => error.reason === CAPABILITY_REASONS.INVALID_AUDIENCE);
});

test("effective scope is the conservative intersection and cannot widen local policy", () => {
  const local = {
    operations: ["git.commit.sign"],
    repositories: ["/work/*"],
    branches: { allow: ["feature/*"], deny: ["feature/blocked"] },
    remotes: { allow: ["git@github.com:example/*"] }
  };
  const capabilityScope = {
    operations: ["git.commit.sign", "git.push"],
    repositories: ["/work/project"],
    branches: { allow: ["feature/agent-*"], deny: [] },
    remotes: { allow: ["git@github.com:example/project.git"] }
  };
  const effective = effectiveScope(local, capabilityScope);
  assert.deepEqual(effective.operations, ["git.commit.sign"]);
  assert.deepEqual(effective.repositories, ["/work/project"]);
  assert.deepEqual(effective.branches.allow, ["feature/agent-*"]);
  assert.deepEqual(effective.branches.deny, ["feature/blocked"]);
  assert.equal(scopeAllows(effective, { operation: "git.commit.sign", repository: "/work/project", branch: "feature/agent-one", remote: "git@github.com:example/project.git" }), true);
  assert.equal(scopeAllows(effective, { operation: "git.push", repository: "/work/project", branch: "feature/agent-one", remote: "git@github.com:example/project.git" }), false);
  assert.equal(scopeAllows(effective, { operation: "git.commit.sign", repository: "/work/../secret", branch: "feature/agent-one", remote: "git@github.com:example/project.git" }), false);
  assert.deepEqual(intersectScopes(local, capabilityScope), effective);
});

test("tag constraints and sequence floors fail closed when required context is missing", () => {
  const tagged = { ...scope, tags: { allow: ["release/*"], deny: [] } };
  assert.equal(scopeAllows(tagged, { operation: "git.commit.sign", repository: "/work/project", branch: "feature/x", remote: "git@github.com:example/x" }), false);
  const capability = issue({ sequence: 4 });
  assert.throws(() => verifyCapability(capability, { keys: { [keyId]: keys.publicKey }, highestSequence: 4 }, { now: NOW }), (error) => error.reason === CAPABILITY_REASONS.SEQUENCE_CONFLICT);
});
