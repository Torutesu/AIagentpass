import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createHostedReadiness } from "../src/runtime.mjs";

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

function signer(purpose, { failing = false, rich = false } = {}) {
  const pair = crypto.generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
  const fingerprint = crypto.createHash("sha256").update(pair.publicKey.export({ type: "spki", format: "der" })).digest("hex");
  const metadata = { purpose, algorithm: "ed25519", key_id: `${purpose}-key`, public_key: publicKey };
  const health = { ready: true, purpose, algorithm: "ed25519", key_id: metadata.key_id, public_key_fingerprint: fingerprint };
  return {
    fingerprint,
    async publicKeyMetadata() { if (failing) throw new Error("provider unavailable"); return metadata; },
    ...(rich ? {
      async health() { return health; },
      async verificationKeyMetadata() { return { version: 1, purpose, active_key_id: metadata.key_id, keys: [{ key_id: metadata.key_id, algorithm: "ed25519", public_key_fingerprint: fingerprint, status: "active" }] }; }
    } : {})
  };
}

function dependencies(failingPurpose) {
  const registryNames = ["agent_session_grant", "qualification_manifest", "possession_receipt", "refresh_hint", "capability", "control_bundle", "audit_anchor", "promotion_evidence"];
  return PURPOSES.map((purpose, index) => {
    const implementation = signer(purpose, { failing: purpose === failingPurpose, rich: index < 4 });
    return {
      name: `${purpose.replaceAll(/[^a-z0-9]+/giu, "_")}_signer`,
      registryName: registryNames[index],
      purpose,
      unavailableCode: `${purpose.replaceAll(/[^a-z0-9]+/giu, "_")}_unavailable`,
      signer: implementation,
      lifecycle: { version: 1, purpose, algorithm: "ed25519", keys: [{ key_id: `${purpose}-key`, key_version: 1, public_key_fingerprint: implementation.fingerprint, state: "active", state_version: 1 }] }
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
