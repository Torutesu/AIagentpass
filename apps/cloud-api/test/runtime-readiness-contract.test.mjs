import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createHostedReadiness, createHostedSignerCanary } from "../src/runtime.mjs";

const PURPOSES = [
  "agentpass.agent-session-grant",
  "agentpass.qualification-grant-batch-manifest",
  "device-enrollment-possession-receipt",
  "agentpass.refresh-hint",
  "agentpass.capability",
  "agentpass.control-bundle",
  "agentpass.audit-anchor",
  "agentpass.promotion-evidence"
];

function signer(purpose, { failing = false, rich = false, canaryFailing = false } = {}) {
  const pair = crypto.generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
  const fingerprint = crypto.createHash("sha256").update(pair.publicKey.export({ type: "spki", format: "der" })).digest("hex");
  const metadata = { purpose, algorithm: "ed25519", key_id: `${purpose}-key`, public_key: publicKey };
  const health = { ready: true, purpose, algorithm: "ed25519", key_id: metadata.key_id, public_key_fingerprint: fingerprint };
  return {
    fingerprint,
    async publicKeyMetadata() { if (failing) throw new Error("provider unavailable"); return metadata; },
    canary: createHostedSignerCanary({
      provider: { async sign({ bytes }) { if (canaryFailing) throw new Error("sign operation failed"); return crypto.sign(null, bytes, pair.privateKey); } },
      purpose,
      keyId: metadata.key_id,
      version: 1,
      publicKey
    }),
    ...(rich ? {
      async health() { return health; },
      async verificationKeyMetadata() { return { version: 1, purpose, active_key_id: metadata.key_id, keys: [{ key_id: metadata.key_id, algorithm: "ed25519", public_key_fingerprint: fingerprint, status: "active" }] }; }
    } : {})
  };
}

function dependencies(failingPurpose, canaryFailingPurpose) {
  const registryNames = ["agent_session_grant", "qualification_manifest", "possession_receipt", "refresh_hint", "capability", "control_bundle", "audit_anchor", "promotion_evidence"];
  return PURPOSES.map((purpose, index) => {
    const implementation = signer(purpose, { failing: purpose === failingPurpose, canaryFailing: purpose === canaryFailingPurpose, rich: index < 4 });
    return {
      name: `${purpose.replaceAll(/[^a-z0-9]+/giu, "_")}_signer`,
      registryName: registryNames[index],
      purpose,
      unavailableCode: `${purpose.replaceAll(/[^a-z0-9]+/giu, "_")}_unavailable`,
      signer: implementation,
      canary: implementation.canary,
      lifecycle: { version: 1, purpose, algorithm: "ed25519", keys: [{ key_id: `${purpose}-key`, key_version: 1, purpose, algorithm: "ed25519", public_key_fingerprint: implementation.fingerprint, state: "active", state_version: 1 }] }
    };
  });
}

test("hosted readiness covers all eight purposes and normalizes metadata-only signers", async () => {
  const readiness = createHostedReadiness(async () => ({ ready: true, status: "ok", code: "ready", checks: {} }), dependencies());
  const report = await readiness();
  assert.equal(report.ready, true);
  assert.equal(report.checks.managed_signers.cardinality, 8);
  assert.equal(report.checks.managed_signers.ok, true);
  assert.deepEqual(Object.keys(report.checks.managed_signers.signers).sort(), ["agent_session_grant", "audit_anchor", "capability", "control_bundle", "possession_receipt", "promotion_evidence", "qualification_manifest", "refresh_hint"]);
  assert.deepEqual(Object.keys(report.checks).filter((name) => name !== "managed_signers").sort(), dependencies().map(({ name }) => name).sort());
  for (const check of Object.values(report.checks).filter((value) => value?.purpose)) {
    assert.equal(check.ok, true);
    assert.equal(check.algorithm, "ed25519");
    assert.match(check.public_key_fingerprint, /^[0-9a-f]{64}$/u);
  }
});

test("hosted readiness rejects registry purpose substitution before serving", () => {
  const substituted = dependencies();
  substituted[0] = { ...substituted[0], purpose: "agentpass.attacker-purpose" };
  assert.throws(
    () => createHostedReadiness(async () => ({ ready: true, status: "ok", code: "ready", checks: {} }), substituted),
    /Hosted readiness signer registry is unavailable/u,
  );
});

test("managed signer canary failure makes readiness fail closed", async () => {
  const readiness = createHostedReadiness(async () => ({ ready: true, status: "ok", code: "ready", checks: {} }), dependencies(undefined, "agentpass.capability"));
  const report = await readiness();
  assert.equal(report.ready, false);
  assert.equal(report.code, "agentpass_capability_unavailable");
  assert.equal(report.checks.managed_signers.signers.capability.code, "provider_unavailable");
});

test("managed signer canary rejects a signature from the wrong key", async () => {
  const expected = crypto.generateKeyPairSync("ed25519");
  const wrong = crypto.generateKeyPairSync("ed25519");
  const publicKey = expected.publicKey.export({ type: "spki", format: "pem" }).toString();
  const canary = createHostedSignerCanary({
    provider: { async sign({ bytes }) { return crypto.sign(null, bytes, wrong.privateKey); } },
    purpose: "agentpass.test-canary",
    keyId: "test-key",
    version: 1,
    publicKey
  });
  await assert.rejects(canary(), /verification failed/u);
});

test("managed signer purpose mismatch makes readiness fail closed", async () => {
  const current = dependencies();
  const implementation = current[0].signer;
  const health = await implementation.health();
  const keyRing = await implementation.verificationKeyMetadata();
  implementation.health = async () => ({ ...health, purpose: "agentpass.wrong-purpose" });
  implementation.verificationKeyMetadata = async () => ({ ...keyRing, purpose: "agentpass.wrong-purpose" });
  const readiness = createHostedReadiness(async () => ({ ready: true, status: "ok", code: "ready", checks: {} }), current);
  const report = await readiness();
  assert.equal(report.ready, false);
  assert.equal(report.code, "agentpass_agent_session_grant_unavailable");
  assert.equal(report.checks.managed_signers.signers.agent_session_grant.ok, false);
});

test("authoritative lifecycle key mismatch makes readiness fail closed", async () => {
  const current = dependencies();
  current[0].lifecycle.keys[0].public_key_fingerprint = "0".repeat(64);
  const readiness = createHostedReadiness(async () => ({ ready: true, status: "ok", code: "ready", checks: {} }), current);
  const report = await readiness();
  assert.equal(report.ready, false);
  assert.equal(report.code, "agentpass_agent_session_grant_unavailable");
  assert.equal(report.checks.managed_signers.signers.agent_session_grant.state, "failed");
  assert.equal(report.checks.managed_signers.signers.agent_session_grant.key_id, null);
});

test("retiring lifecycle keys must be present in the signer verification ring", async () => {
  const current = dependencies();
  current[0].lifecycle.keys.push({
    key_id: "retiring-key-not-published",
    key_version: 2,
    purpose: current[0].purpose,
    algorithm: "ed25519",
    public_key_fingerprint: "1".repeat(64),
    state: "retiring",
    state_version: 1,
  });
  const readiness = createHostedReadiness(async () => ({ ready: true, status: "ok", code: "ready", checks: {} }), current);
  const report = await readiness();
  assert.equal(report.ready, false);
  assert.equal(report.code, "agentpass_agent_session_grant_unavailable");
});

test("hosted readiness rejects duplicate or missing signer registry names", () => {
  const current = dependencies();
  current[1].registryName = current[0].registryName;
  assert.throws(
    () => createHostedReadiness(async () => ({ ready: true, status: "ok", code: "ready", checks: {} }), current),
    /signer registry is unavailable/u
  );
});

test("concurrent readiness calls share one canary per active key", async () => {
  const current = dependencies();
  const originalCanary = current[0].canary;
  let calls = 0;
  current[0].canary = async () => {
    calls += 1;
    await new Promise((resolve) => setTimeout(resolve, 5));
    return originalCanary();
  };
  const readiness = createHostedReadiness(async () => ({ ready: true, status: "ok", code: "ready", checks: {} }), current);
  await Promise.all([readiness(), readiness(), readiness()]);
  assert.equal(calls, 1);
});

test("one purpose failure makes hosted readiness fail closed without exposing provider details", async () => {
  const readiness = createHostedReadiness(async () => ({ ready: true, status: "ok", code: "ready", checks: {} }), dependencies("agentpass.audit-anchor"));
  const report = await readiness();
  assert.equal(report.ready, false);
  assert.equal(report.code, "agentpass_audit_anchor_unavailable");
  assert.equal(report.checks.managed_signers.ok, false);
  assert.deepEqual(report.checks.agentpass_audit_anchor_signer, {
    ok: false,
    purpose: "agentpass.audit-anchor",
    algorithm: "ed25519",
    key_id: null,
    public_key_fingerprint: null
  });
  assert.equal(JSON.stringify(report).includes("provider unavailable"), false);
});

test("partial deployment identity cannot be accepted as ready", () => {
  assert.throws(
    () => createHostedReadiness(async () => ({ ready: true, status: "ok", code: "ready", checks: {} }), dependencies(), {
      version: 1,
      configured: true,
      ready: true
    }),
    /deployment identity is invalid/u
  );
});

test("unconfigured deployment identity keeps hosted readiness fail closed", async () => {
  const readiness = createHostedReadiness(async () => ({ ready: true, status: "ok", code: "ready", checks: {} }), dependencies(), {
    version: 1,
    configured: false,
    ready: false,
    source_commit: null,
    source_tree: null,
    image_digest: null,
    deployment_id: null,
    revision: null,
    schema_digest: null,
    catalog_digest: null,
    database_schema_digest: null
  });
  const report = await readiness();
  assert.equal(report.ready, false);
  assert.equal(report.code, "deployment_identity_unavailable");
});
