import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";

import { signControlBundle as signLegacyBundle } from "../lib/remote-control.mjs";
import {
  CONTROL_BUNDLE_KEYS,
  CONTROL_BUNDLE_REASONS,
  FORMAT_EPOCH,
  applyControlBundle,
  canonicalControlBundle,
  controlBundleStatementHash,
  createControlBundleState,
  evaluateControlBundle,
  issueControlBundle,
  loadControlBundleState,
  loadMinimumFormatEpoch,
  narrowPolicyScope,
  parseControlBundleJson,
  persistMinimumFormatEpoch,
  policyScopeAllows,
  saveControlBundleState,
  verifyCachedControlBundle,
  verifyControlBundle
} from "../lib/control-bundle-v2.mjs";

const NOW = Date.parse("2026-08-12T00:00:00.000Z");
const keys = crypto.generateKeyPairSync("ed25519");
const organizationId = crypto.randomUUID();
const deviceId = crypto.randomUUID();
const agentId = crypto.randomUUID();
const otherDeviceId = crypto.randomUUID();
const otherAgentId = crypto.randomUUID();
const capabilityId = crypto.randomUUID();
const audience = { organization_id: organizationId, device_id: deviceId };
const scope = {
  operations: ["git.commit.sign"],
  repositories: ["/work/project"],
  branches: { allow: ["feature/*"], deny: ["main", "release/*"] },
  remotes: { allow: ["git@github.com:org/repo.git"], deny: [] }
};

function issue(overrides = {}, now = NOW) {
  return issueControlBundle({
    issuer: "cloud-control",
    organization_id: organizationId,
    device_id: deviceId,
    audience,
    issued_at: new Date(now).toISOString(),
    expires_at: new Date(now + 60_000).toISOString(),
    sequence: 1,
    policy_scope: scope,
    global_revoked: false,
    revoked_devices: [],
    revoked_agents: [],
    revoked_capabilities: [],
    offline_ttl_ms: 120_000,
    key_id: "control-v2",
    ...overrides
  }, keys.privateKey, { now });
}

function trust(extra = {}) {
  return { public_key: keys.publicKey, issuer: "cloud-control", key_id: "control-v2", ...extra };
}

function tempStatePath() {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-control-v2-")), "state.json");
}

function reason(expected) {
  return (error) => error?.reason === expected || error?.code === expected;
}

test("issues the exact canonical v2 Ed25519 envelope and verifies its audience", () => {
  const bundle = issue();
  assert.equal(bundle.format_epoch, FORMAT_EPOCH);
  assert.deepEqual(Object.keys(bundle).sort(), [...CONTROL_BUNDLE_KEYS].sort());
  assert.equal(verifyControlBundle(bundle, trust(), { now: NOW + 1_000, audience }).sequence, 1);
  assert.equal(canonicalControlBundle(bundle), canonicalControlBundle({ ...bundle, signature: "ignored" }));
  assert.equal(controlBundleStatementHash(bundle).length, 64);
});

test("rejects unknown fields, aliases, malformed objects, and non-v2 epochs", () => {
  const bundle = issue();
  assert.throws(() => verifyControlBundle({ ...bundle, extra: true }, trust(), { now: NOW, audience }), reason(CONTROL_BUNDLE_REASONS.UNKNOWN_FIELD));
  assert.throws(() => verifyControlBundle({ ...bundle, policyScope: scope }, trust(), { now: NOW, audience }), reason(CONTROL_BUNDLE_REASONS.UNKNOWN_FIELD));
  assert.throws(() => issue({ format_epoch: 1 }), reason(CONTROL_BUNDLE_REASONS.INVALID_FORMAT_EPOCH));
  assert.throws(() => verifyControlBundle({ ...bundle, audience: { ...audience, extra: true } }, trust(), { now: NOW, audience }), reason(CONTROL_BUNDLE_REASONS.UNKNOWN_FIELD));
  assert.throws(() => verifyControlBundle({ ...bundle, policy_scope: { ...scope, extra: true } }, trust(), { now: NOW, audience }), reason(CONTROL_BUNDLE_REASONS.UNKNOWN_FIELD));
  assert.throws(() => verifyControlBundle({ ...bundle, policy_scope: null }, trust(), { now: NOW, audience }), reason(CONTROL_BUNDLE_REASONS.INVALID_SCOPE));
  assert.throws(() => verifyControlBundle({ ...bundle, signature: 42 }, trust(), { now: NOW, audience }), reason(CONTROL_BUNDLE_REASONS.INVALID_SIGNATURE_ENCODING));
  assert.throws(() => verifyControlBundle([], trust(), { now: NOW, audience }), reason(CONTROL_BUNDLE_REASONS.INVALID_BUNDLE));
});

test("rejects tampering, wrong keys, wrong key IDs, issuers, and audiences", () => {
  const bundle = issue();
  const otherKeys = crypto.generateKeyPairSync("ed25519");
  assert.throws(() => verifyControlBundle({ ...bundle, sequence: 2 }, trust(), { now: NOW, audience }), reason(CONTROL_BUNDLE_REASONS.INVALID_SIGNATURE));
  assert.throws(() => verifyControlBundle(bundle, otherKeys.publicKey, { now: NOW, audience }), reason(CONTROL_BUNDLE_REASONS.INVALID_SIGNATURE));
  assert.throws(() => verifyControlBundle(bundle, trust({ key_id: "other" }), { now: NOW, audience }), reason(CONTROL_BUNDLE_REASONS.KEY_ID_NOT_TRUSTED));
  assert.throws(() => verifyControlBundle(bundle, trust({ issuer: "other" }), { now: NOW, audience }), reason(CONTROL_BUNDLE_REASONS.ISSUER_KEY_MISMATCH));
  assert.throws(() => verifyControlBundle(bundle, trust(), { now: NOW, audience: { organization_id: organizationId, device_id: otherDeviceId } }), reason(CONTROL_BUNDLE_REASONS.AUDIENCE_MISMATCH));
  assert.throws(() => verifyControlBundle(bundle, trust(), { now: NOW, audience: undefined }), reason(CONTROL_BUNDLE_REASONS.INVALID_AUDIENCE));
  assert.throws(() => verifyControlBundle({ ...bundle, signature: `${bundle.signature}=` }, trust(), { now: NOW, audience }), reason(CONTROL_BUNDLE_REASONS.INVALID_SIGNATURE_ENCODING));
});

test("enforces canonical timestamps, issuance/expiry TTLs, and bounded offline use", () => {
  const bundle = issue({ expires_at: new Date(NOW + 10_000).toISOString(), offline_ttl_ms: 20_000 });
  assert.throws(() => verifyControlBundle(bundle, trust(), { now: NOW - 61_001, audience }), reason(CONTROL_BUNDLE_REASONS.ISSUED_IN_FUTURE));
  assert.throws(() => verifyControlBundle({ ...bundle, issued_at: "2026-08-12T00:00:00Z" }, trust(), { now: NOW, audience }), reason(CONTROL_BUNDLE_REASONS.INVALID_TIMESTAMP));
  assert.throws(() => verifyControlBundle(bundle, trust(), { now: NOW + 10_000, audience }), reason(CONTROL_BUNDLE_REASONS.EXPIRED));
  assert.equal(verifyCachedControlBundle(bundle, trust(), { now: NOW + 10_001, audience }).sequence, 1);
  assert.throws(() => verifyCachedControlBundle(bundle, trust(), { now: NOW + 30_000, audience }), reason(CONTROL_BUNDLE_REASONS.OFFLINE_TTL_EXPIRED));
  assert.throws(() => issue({ expires_at: new Date(NOW + MAX_TTL_PLUS_ONE).toISOString() }), reason(CONTROL_BUNDLE_REASONS.TTL_EXCEEDED));
  assert.throws(() => issue({ offline_ttl_ms: 0 }), reason(CONTROL_BUNDLE_REASONS.INVALID_OFFLINE_TTL));
});

const MAX_TTL_PLUS_ONE = 7 * 24 * 60 * 60 * 1000 + 1;

test("enforces scope intersection and refuses a wider or unsupported policy", () => {
  const local = {
    operations: ["git.commit.sign"],
    repositories: ["/work/*"],
    branches: { allow: ["feature/*"], deny: ["feature/blocked"] },
    remotes: { allow: ["git@github.com:org/*"] }
  };
  const effective = narrowPolicyScope(local, issue().policy_scope);
  assert.deepEqual(effective.operations, ["git.commit.sign"]);
  assert.equal(policyScopeAllows(effective, { operation: "git.commit.sign", repository: "/work/project", branch: "feature/new", remote: "git@github.com:org/repo.git" }), true);
  assert.equal(policyScopeAllows(effective, { operation: "git.push", repository: "/work/project", branch: "feature/new", remote: "git@github.com:org/repo.git" }), false);
  assert.equal(policyScopeAllows(effective, { operation: "git.commit.sign", repository: "/work/project", branch: "feature/blocked", remote: "git@github.com:org/repo.git" }), false);
  assert.throws(() => issue({ policy_scope: { ...scope, operations: ["git.push"] } }), reason(CONTROL_BUNDLE_REASONS.INVALID_SCOPE));
  assert.throws(() => issue({ policy_scope: { ...scope, repositories: ["/work/../project"] } }), reason(CONTROL_BUNDLE_REASONS.INVALID_SCOPE));
  assert.throws(() => issue({ policy_scope: { ...scope, branches: { allow: ["feature/*"], deny: ["feature/*", "feature/*"] } } }), reason(CONTROL_BUNDLE_REASONS.INVALID_SCOPE));
});

test("fail-closed revocation evaluation covers organization, device, agent, and global stop", () => {
  assert.deepEqual(evaluateControlBundle(issue({ global_revoked: true }), { organization_id: organizationId, device_id: deviceId, agent_id: agentId }).allowed, false);
  assert.equal(evaluateControlBundle(issue({ revoked_devices: [deviceId] }), { organization_id: organizationId, device_id: deviceId }).reason, CONTROL_BUNDLE_REASONS.DEVICE_REVOKED);
  assert.equal(evaluateControlBundle(issue({ revoked_agents: [agentId] }), { organization_id: organizationId, device_id: deviceId, agent_id: agentId }).reason, CONTROL_BUNDLE_REASONS.AGENT_REVOKED);
  assert.equal(evaluateControlBundle(issue({ revoked_capabilities: [capabilityId] }), { capability_id: capabilityId }).reason, CONTROL_BUNDLE_REASONS.CAPABILITY_REVOKED);
  assert.equal(evaluateControlBundle(issue(), { organization_id: crypto.randomUUID(), device_id: deviceId }).reason, CONTROL_BUNDLE_REASONS.ORGANIZATION_MISMATCH);
  assert.equal(evaluateControlBundle(issue(), { organization_id: organizationId, device_id: otherDeviceId }).reason, CONTROL_BUNDLE_REASONS.AUDIENCE_MISMATCH);
  assert.equal(evaluateControlBundle({ ...issue(), revoked_devices: ["not-a-uuid"] }, { device_id: deviceId }).allowed, false);
  assert.throws(() => issue({ revoked_agents: [agentId, agentId] }), reason(CONTROL_BUNDLE_REASONS.DUPLICATE_REVOCATION));
  assert.throws(() => issue({ revoked_agents: [...[agentId, otherAgentId].sort()].reverse() }), reason(CONTROL_BUNDLE_REASONS.INVALID_REVOCATION));
});

test("requires monotonic sequence and same-sequence hash evidence without mutating on failure", () => {
  const state = createControlBundleState();
  const first = issue();
  assert.equal(verifyControlBundle(first, trust({ sequenceState: state }), { now: NOW, audience }).sequence, 1);
  assert.equal(state.highest_sequence, 1);
  assert.equal(state.statement_hash, controlBundleStatementHash(first));
  assert.equal(verifyControlBundle(first, trust({ sequenceState: state }), { now: NOW, audience }).sequence, 1);
  const equivocation = issue({ global_revoked: true });
  assert.throws(() => verifyControlBundle(equivocation, trust({ sequenceState: state }), { now: NOW, audience }), reason(CONTROL_BUNDLE_REASONS.SEQUENCE_CONFLICT));
  assert.throws(() => verifyControlBundle(issue({ sequence: 0 }), trust({ sequenceState: state }), { now: NOW, audience }), reason(CONTROL_BUNDLE_REASONS.INVALID_SEQUENCE));
  const before = { ...state };
  assert.throws(() => verifyControlBundle({ ...issue({ sequence: 2 }), signature: "bad" }, trust({ sequenceState: state }), { now: NOW, audience }), reason(CONTROL_BUNDLE_REASONS.INVALID_SIGNATURE_ENCODING));
  assert.deepEqual(state, before);
  const emptyEvidence = { highest_sequence: 1, statement_hash: null, minimum_format_epoch: 2, active_bundle: null };
  assert.throws(() => verifyControlBundle(first, trust({ sequenceState: emptyEvidence }), { now: NOW, audience }), reason(CONTROL_BUNDLE_REASONS.SEQUENCE_EVIDENCE_REQUIRED));
});

test("rejects oversized, duplicate-key, deeply nested, invalid UTF-8, and malformed JSON", () => {
  assert.throws(() => parseControlBundleJson(Buffer.alloc(256 * 1024 + 1)), reason(CONTROL_BUNDLE_REASONS.JSON_TOO_LARGE));
  assert.throws(() => parseControlBundleJson('{"a":1,"a":2}'), reason(CONTROL_BUNDLE_REASONS.DUPLICATE_FIELD));
  assert.throws(() => parseControlBundleJson(Buffer.from([0xc3, 0x28])), reason(CONTROL_BUNDLE_REASONS.INVALID_JSON));
  assert.throws(() => parseControlBundleJson(`${"[".repeat(34)}0${"]".repeat(34)}`), reason(CONTROL_BUNDLE_REASONS.JSON_TOO_DEEP));
  assert.throws(() => parseControlBundleJson('{"a":}'), reason(CONTROL_BUNDLE_REASONS.INVALID_JSON));
  const bundle = issue();
  assert.equal(parseControlBundleJson(JSON.stringify({ ...bundle, extra: "x" })).extra, "x");
});

test("persists an atomic state head and permanently rejects legacy v1 after first v2", () => {
  const statePath = tempStatePath();
  const first = issue();
  assert.equal(applyControlBundle(first, trust(), statePath, { now: NOW, audience }).sequence, first.sequence);
  const state = loadControlBundleState(statePath);
  assert.equal(state.minimum_format_epoch, 2);
  assert.equal(loadMinimumFormatEpoch(`${statePath}.minimum-format-epoch`), 2);
  assert.equal(state.statement_hash, controlBundleStatementHash(first));
  assert.equal(JSON.parse(fs.readFileSync(statePath, "utf8")).active_bundle.signature, first.signature);
});

test("allows legacy v1 only in explicit legacy mode before migration, then raises a permanent floor", () => {
  const statePath = tempStatePath();
  const legacyKeys = crypto.generateKeyPairSync("ed25519");
  const keyDir = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-legacy-key-"));
  const keyFile = path.join(keyDir, "private.pem");
  fs.writeFileSync(keyFile, legacyKeys.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  const legacy = signLegacyBundle({ sequence: 1, expiresAt: Date.now() + 60_000 }, keyFile);
  assert.equal(applyControlBundle(legacy, { public_key: legacyKeys.publicKey }, statePath, { legacyMode: true }).sequence, 1);
  assert.equal(loadControlBundleState(statePath).minimum_format_epoch, 1);
  const v2 = issue({ sequence: 2 });
  applyControlBundle(v2, trust(), statePath, { now: NOW, audience });
  assert.equal(loadMinimumFormatEpoch(`${statePath}.minimum-format-epoch`), 2);
  assert.throws(() => applyControlBundle(legacy, { public_key: legacyKeys.publicKey }, statePath, { legacyMode: true }), reason(CONTROL_BUNDLE_REASONS.LEGACY_PERMANENTLY_REJECTED));
  assert.throws(() => applyControlBundle(legacy, { public_key: legacyKeys.publicKey }, tempStatePath()), reason(CONTROL_BUNDLE_REASONS.LEGACY_MODE_REQUIRED));
});

test("rejects symlink state files/parents and refuses epoch rollback", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-control-v2-links-"));
  const real = path.join(root, "real"); fs.mkdirSync(real);
  const statePath = path.join(real, "state.json");
  persistMinimumFormatEpoch(`${statePath}.minimum-format-epoch`, 2);
  assert.throws(() => persistMinimumFormatEpoch(`${statePath}.minimum-format-epoch`, 1), reason(CONTROL_BUNDLE_REASONS.INVALID_FORMAT_EPOCH));
  const link = path.join(root, "link"); fs.symlinkSync(real, link, "dir");
  assert.throws(() => saveControlBundleState(path.join(link, "state.json"), createControlBundleState()), reason(CONTROL_BUNDLE_REASONS.STATE_SYMLINK));
  const target = path.join(root, "target.json"); fs.writeFileSync(target, "{}", { mode: 0o600 });
  const finalLink = path.join(root, "state-link.json"); fs.symlinkSync(target, finalLink);
  assert.throws(() => saveControlBundleState(finalLink, createControlBundleState()), reason(CONTROL_BUNDLE_REASONS.STATE_SYMLINK));
});
