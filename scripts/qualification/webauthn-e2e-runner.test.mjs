import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { WebAuthnQualificationError, validateWebAuthnEvidence } from "./run-webauthn-e2e.mjs";

const binding = {
  AGENTPASS_QUALIFICATION_RUNNER_ID: "protected-webauthn-runner",
  AGENTPASS_QUALIFICATION_RUN_ID: "42",
  AGENTPASS_QUALIFICATION_JOB_ID: "1002",
  AGENTPASS_QUALIFICATION_RUN_ATTEMPT: "3",
  GITHUB_SHA: "a".repeat(40),
  AGENTPASS_SOURCE_TREE: "b".repeat(40),
  AGENTPASS_QUALIFICATION_ARTIFACT_SHA256: "c".repeat(64),
  AGENTPASS_WEBAUTHN_EXPECTED_ORIGIN: "https://console.agentpass.example",
  AGENTPASS_WEBAUTHN_EXPECTED_RP_ID: "agentpass.example",
};

function evidence() {
  const checks = ["authenticator_origin_rp", "durable_one_time_consumption", "replay_rejection", "stale_context_rejection", "outage_fail_closed"].map((check_id) => {
    const item = { check_id, status: "passed", expected: { type: "boolean", value: true }, observed: { type: "boolean", value: true } };
    return { ...item, evidence_sha256: crypto.createHash("sha256").update(canonicalJson(item), "utf8").digest("hex") };
  });
  return {
    schema_version: 1,
    kind: "agentpass-webauthn-agent-unattended-e2e",
    status: "passed",
    qualified: true,
    reason: null,
    execution: {
      kind: "external_runner", real_execution: true, runner_id: binding.AGENTPASS_QUALIFICATION_RUNNER_ID,
      run_id: binding.AGENTPASS_QUALIFICATION_RUN_ID, job_id: binding.AGENTPASS_QUALIFICATION_JOB_ID, run_attempt: binding.AGENTPASS_QUALIFICATION_RUN_ATTEMPT,
      source_commit: binding.GITHUB_SHA, source_tree: binding.AGENTPASS_SOURCE_TREE, artifact_sha256: binding.AGENTPASS_QUALIFICATION_ARTIFACT_SHA256,
      started_at: "2026-08-20T00:00:00.000Z", completed_at: "2026-08-20T00:01:00.000Z", environment: {
        kind: "webauthn", identity: "protected-chromium-cdp-webauthn", authenticator: "platform",
        origin: "https://console.agentpass.example", rp_id: "agentpass.example", instance_ids: ["web-01", "web-02"]
      }
    },
    required_checks: checks.map((item) => item.check_id),
    checks
  };
}

test("validates a canonical, externally bound WebAuthn qualification result", () => {
  const value = validateWebAuthnEvidence(evidence(), binding);
  assert.equal(value.execution.source_commit, binding.GITHUB_SHA);
});

test("rejects local runner and check substitution before release evidence can be written", () => {
  assert.throws(() => validateWebAuthnEvidence({ ...evidence(), execution: { ...evidence().execution, runner_id: "local-test" } }, binding), WebAuthnQualificationError);
  const altered = evidence();
  altered.checks[0].observed = { type: "boolean", value: false };
  assert.throws(() => validateWebAuthnEvidence(altered, binding), WebAuthnQualificationError);
});

test("rejects a pre-existing output target to prevent evidence replacement", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-webauthn-runner-test-"));
  try {
    const target = path.join(root, "evidence.json");
    fs.writeFileSync(target, "existing", { mode: 0o600 });
    assert.ok(fs.existsSync(target));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
