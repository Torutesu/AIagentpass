import crypto from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";
import {
  BUNDLE_REASONS,
  BundleError,
  canonicalBundle,
  consumePolicyBundle,
  evaluateRevocations,
  issuePolicyBundle,
  issueRevocationBundle,
  narrowPolicyScope,
  verifyCachedBundle,
  verifyDeviceBundle,
  verifyIssuerBundle
} from "../src/bundles.mjs";

const NOW = Date.parse("2026-08-12T00:00:00.000Z");
const organizationId = crypto.randomUUID();
const deviceId = crypto.randomUUID();
const agentId = crypto.randomUUID();
const otherAgentId = crypto.randomUUID();
const capabilityId = crypto.randomUUID();
const issuer = "cloud-control";
const keyId = "control-v1";
const keys = crypto.generateKeyPairSync("ed25519");
const audience = { organization_id: organizationId, device_id: deviceId };
const scope = {
  operations: ["git.commit.sign", "git.push"],
  repositories: ["/work/project"],
  branches: { allow: ["feature/*"], deny: ["main"] },
  remotes: { allow: ["git@github.com:example/*"] }
};

function issue(overrides = {}) {
  return issuePolicyBundle({
    issuer,
    organization_id: organizationId,
    device_id: deviceId,
    audience,
    key_id: keyId,
    policy_scope: scope,
    sequence: 1,
    issued_at: new Date(NOW).toISOString(),
    expires_at: new Date(NOW + 60_000).toISOString(),
    offline_ttl_ms: 120_000,
    ...overrides
  }, keys.privateKey, { now: NOW });
}

function trust(extra = {}) {
  return { public_key: keys.publicKey, issuer, key_id: keyId, ...extra };
}

test("issues canonical policy and revocation envelopes and verifies issuer/device trust", () => {
  const policy = issue();
  assert.deepEqual(Object.keys(policy).sort(), [
    "audience", "bundle_type", "device_id", "expires_at", "global_revoked", "issued_at", "issuer",
    "key_id", "offline_ttl_ms", "organization_id", "policy_scope", "revoked_agents", "revoked_capabilities", "revoked_devices",
    "sequence", "signature", "version"
  ]);
  assert.equal(verifyIssuerBundle(policy, trust(), { now: NOW + 1_000 }).sequence, 1);
  assert.equal(verifyDeviceBundle(policy, trust(), { now: NOW + 1_000, audience }).device_id, deviceId);

  const revokedAgents = [agentId, otherAgentId].sort();
  const revocation = issueRevocationBundle({
    ...Object.fromEntries(Object.entries(policy).filter(([key]) => key !== "signature")),
    bundle_type: "revocation",
    revoked_agents: revokedAgents
  }, keys.privateKey, { now: NOW });
  assert.equal(revocation.bundle_type, "revocation");
  assert.deepEqual(revocation.revoked_agents, revokedAgents);
});

test("binds the exact canonical statement and rejects tampering, noncanonical timestamps, signatures, and fields", () => {
  const bundle = issue();
  assert.equal(canonicalBundle(bundle), canonicalBundle({ ...bundle, signature: "ignored" }));
  assert.throws(() => verifyDeviceBundle({ ...bundle, policy_scope: { ...scope, extra: true } }, trust(), { now: NOW, audience }), (error) => error.code === BUNDLE_REASONS.UNKNOWN_FIELD);
  assert.throws(() => verifyDeviceBundle({ ...bundle, extra: true }, trust(), { now: NOW, audience }), (error) => error.code === BUNDLE_REASONS.UNKNOWN_FIELD);
  assert.throws(() => verifyDeviceBundle({ ...bundle, issued_at: "2026-08-12T00:00:00Z" }, trust(), { now: NOW, audience }), (error) => error.code === BUNDLE_REASONS.INVALID_TIMESTAMP);
  assert.throws(() => verifyDeviceBundle({ ...bundle, signature: `${bundle.signature}=` }, trust(), { now: NOW, audience }), (error) => error.code === BUNDLE_REASONS.INVALID_SIGNATURE_ENCODING);
  assert.throws(() => verifyDeviceBundle({ ...bundle, sequence: 2 }, trust(), { now: NOW, audience }), (error) => error.code === BUNDLE_REASONS.INVALID_SIGNATURE);
  assert.throws(() => issue({ key_id: keyId, keyId }), (error) => error.code === BUNDLE_REASONS.UNKNOWN_FIELD);
  assert.throws(() => issue({ signature: bundle.signature }), (error) => error.code === BUNDLE_REASONS.UNKNOWN_FIELD);
});

test("rejects invalid IDs, duplicate or oversized revocations, and ambiguous audience binding", () => {
  assert.throws(() => issue({ organization_id: "org-example" }), (error) => error.code === BUNDLE_REASONS.INVALID_ORGANIZATION_ID);
  assert.throws(() => issue({ audience: { ...audience, device_id: crypto.randomUUID() } }), (error) => error.code === BUNDLE_REASONS.AUDIENCE_MISMATCH);
  assert.throws(() => issue({ revoked_agents: [agentId, agentId] }), (error) => error.code === BUNDLE_REASONS.DUPLICATE_REVOCATION);
  assert.throws(() => issue({ revoked_devices: Array.from({ length: 257 }, () => crypto.randomUUID()).sort() }), (error) => error.code === BUNDLE_REASONS.LIST_TOO_LARGE);
  assert.throws(() => issue({ revoked_agents: ["not-an-agent"] }), (error) => error.code === BUNDLE_REASONS.INVALID_AGENT_ID);
  assert.equal(evaluateRevocations(issue({ revoked_capabilities: [capabilityId] }), { capability_id: capabilityId }).reason, "capability_revoked");
});

test("enforces audience, issuer/key pinning, time bounds, TTL, and fail-closed signatures", () => {
  const bundle = issue();
  assert.throws(() => verifyDeviceBundle(bundle, trust(), { now: NOW, audience: { organization_id: organizationId, device_id: crypto.randomUUID() } }), (error) => error.code === BUNDLE_REASONS.AUDIENCE_MISMATCH);
  assert.throws(() => verifyIssuerBundle(bundle, { public_key: keys.publicKey, issuer: "other", key_id: keyId }, { now: NOW }), (error) => error.code === BUNDLE_REASONS.ISSUER_KEY_MISMATCH);
  assert.throws(() => verifyDeviceBundle(bundle, { public_key: keys.publicKey, key_id: "other" }, { now: NOW, audience }), (error) => error.code === BUNDLE_REASONS.KEY_ID_NOT_TRUSTED);
  assert.throws(() => verifyDeviceBundle(bundle, trust(), { now: NOW - 61_000, audience }), (error) => error.code === BUNDLE_REASONS.ISSUED_IN_FUTURE);
  assert.throws(() => verifyDeviceBundle(bundle, trust(), { now: NOW + 60_000, audience }), (error) => error.code === BUNDLE_REASONS.EXPIRED);
  assert.throws(() => issue({ expires_at: new Date(NOW + 8 * 24 * 60 * 60 * 1000).toISOString() }), (error) => error.code === BUNDLE_REASONS.TTL_EXCEEDED);
  assert.throws(() => verifyDeviceBundle(bundle, { public_key: crypto.generateKeyPairSync("ed25519").publicKey }, { now: NOW, audience }), (error) => error.code === BUNDLE_REASONS.INVALID_SIGNATURE);
  assert.throws(() => verifyDeviceBundle(bundle, keys.publicKey, { now: NOW }), (error) => error.code === BUNDLE_REASONS.INVALID_AUDIENCE);
});

test("rejects rollback and same-sequence equivocation only after valid signature", () => {
  const state = { highestSequence: 1 };
  const first = issue({ sequence: 1 });
  assert.equal(verifyDeviceBundle(first, trust({ sequenceState: state }), { now: NOW, audience }).sequence, 1);
  assert.equal(typeof state.highestBundleHash, "string");
  assert.equal(verifyDeviceBundle(first, trust({ sequenceState: state }), { now: NOW, audience }).sequence, 1);

  const equivocation = issue({ sequence: 1, global_revoked: true });
  assert.throws(() => verifyDeviceBundle(equivocation, trust({ sequenceState: state }), { now: NOW, audience }), (error) => error.code === BUNDLE_REASONS.SEQUENCE_CONFLICT);
  assert.throws(() => verifyDeviceBundle(issue({ sequence: 0 }), trust({ sequenceState: state }), { now: NOW, audience }), (error) => error.code === BUNDLE_REASONS.INVALID_SEQUENCE);
  assert.throws(() => verifyDeviceBundle(issue({ sequence: 2 }), trust({ sequenceState: state }), { now: NOW, audience, sequenceHook: () => false }), (error) => error.code === BUNDLE_REASONS.SEQUENCE_ROLLBACK);
  assert.equal(state.highestSequence, 1);
});

test("offline use is explicit and bounded, and policy consumption can only narrow", () => {
  const bundle = issue({ expires_at: new Date(NOW + 10_000).toISOString(), offline_ttl_ms: 20_000 });
  assert.throws(() => verifyDeviceBundle(bundle, trust(), { now: NOW + 15_000, audience }), (error) => error.code === BUNDLE_REASONS.EXPIRED);
  assert.equal(verifyCachedBundle(bundle, trust(), { now: NOW + 15_000, audience }).sequence, 1);
  assert.throws(() => verifyCachedBundle(bundle, trust(), { now: NOW + 30_001, audience }), (error) => error.code === BUNDLE_REASONS.OFFLINE_TTL_EXPIRED);

  const local = {
    operations: ["git.commit.sign"],
    repositories: ["/work/*"],
    branches: { allow: ["feature/*"], deny: ["feature/blocked"] },
    remotes: { allow: ["git@github.com:example/*"] }
  };
  const effective = narrowPolicyScope(local, bundle);
  assert.deepEqual(effective.operations, ["git.commit.sign"]);
  assert.deepEqual(effective.repositories, ["/work/project"]);
  assert.equal(effective.branches.deny.includes("feature/blocked"), true);
  assert.equal(consumePolicyBundle(bundle, local, trust(), { now: NOW, audience }).effective_scope.operations[0], "git.commit.sign");
  assert.equal(evaluateRevocations(bundle, { organization_id: organizationId, device_id: deviceId, agent_id: agentId }).reason, "not_revoked");
  const revoked = issue({ revoked_agents: [agentId] });
  assert.equal(evaluateRevocations(revoked, { organization_id: organizationId, device_id: deviceId, agent_id: agentId }).reason, "agent_revoked");
  assert.throws(() => consumePolicyBundle({ ...bundle, bundle_type: "revocation" }, local, trust(), { now: NOW, audience }), (error) => error.code === BUNDLE_REASONS.INVALID_SIGNATURE);
});

test("uses stable BundleError codes for malformed trust and sequence hooks", () => {
  const bundle = issue();
  assert.throws(() => verifyIssuerBundle(bundle, {}, { now: NOW }), (error) => error instanceof BundleError && error.code === BUNDLE_REASONS.ISSUER_NOT_TRUSTED);
  assert.throws(() => verifyDeviceBundle(bundle, { public_key: keys.publicKey }, { now: NOW, audience, onSequence: () => { throw new Error("storage unavailable"); } }), (error) => error.code === BUNDLE_REASONS.SEQUENCE_REJECTED);
});
