import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { validateXpcQualificationEvidence } from "./verify-xpc-qualification.mjs";

const digest = (character) => character.repeat(64);
const canonicalJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
};
const bindingDigest = (binding) => createHash("sha256").update(canonicalJson(binding), "utf8").digest("hex");

const evidence = () => {
  const binding = {
    artifact_sha256: digest("a"),
    candidate_sha256: digest("b"),
    job_id: "987654321",
    run_attempt: "2",
    run_id: "123456789",
    source_commit: "0123456789abcdef0123456789abcdef01234567",
    source_tree: "fedcba9876543210fedcba9876543210fedcba98"
  };
  const bound = bindingDigest(binding);
  return {
    schema_version: 3,
    binding,
    execution: { ...binding, completed_at: "2026-08-22T00:01:00.000Z", environment: "protected_macos", kind: "external_runner", real_execution: true, runner_id: "github-actions/macos-xpc-arm64", started_at: "2026-08-22T00:00:00.000Z", status: "passed" },
    host_activation: { audit_token_capture: "live_eight_field", audit_token_sha256: digest("c"), audit_token_source: "kernel_live_audit_token_t", binding_sha256: bound, child_process_identity_sha256: digest("d"), child_requirement_sha256: digest("e"), observation: "live_nsxpc_activation", projection_sha256: digest("f"), status: "passed", transport: "authenticated_xpc" },
    launch_observation: { ...binding, artifact_sha256: binding.artifact_sha256, binding_sha256: bound, child_mach_service: "dev.agentpass.child-git", child_pid: 2002, child_process_identity_sha256: digest("d"), child_start_time_ns: "1700000000000000002", host_mach_service: "dev.agentpass.agent-host", host_pid: 2001, host_start_time_ns: "1700000000000000001", mode: "launchd_mach_nsxpc", status: "passed" },
    child_requirement: { ...binding, artifact_sha256: binding.artifact_sha256, binding_sha256: bound, evaluation: "passed", observation: "live_codesign_requirement", principal: "dev.agentpass.git-sign-xpc", sha256: digest("e") },
    negative_cases: [
      { case: "same_uid_wrong_child", observation: "live_macos_probe", result: "denied_before_sign", sign_attempts: 0 },
      { case: "wrong_team", observation: "live_macos_probe", result: "denied_before_sign", sign_attempts: 0 },
      { case: "wrong_entitlement", observation: "live_macos_probe", result: "denied_before_sign", sign_attempts: 0 },
      { case: "stale_or_reused_audit_token", observation: "live_macos_probe", result: "denied_before_sign", sign_attempts: 0 }
    ]
  };
};

test("accepts only a closed candidate/source/tree/artifact/run-bound external projection", () => {
  const result = validateXpcQualificationEvidence(evidence());
  assert.equal(result.schema_version, 3);
  assert.equal(result.candidate_sha256, digest("b"));
  assert.equal(result.artifact_sha256, digest("a"));
  assert.equal(result.source_tree, "fedcba9876543210fedcba9876543210fedcba98");
  assert.equal(result.run_id, "123456789");
  assert.match(result.binding_sha256, /^[0-9a-f]{64}$/u);
  assert.match(result.evidence_sha256, /^[0-9a-f]{64}$/u);
});

test("requires every release binding and propagates it to execution records", () => {
  for (const field of ["source_tree", "artifact_sha256", "run_id", "run_attempt", "job_id"]) {
    const value = evidence();
    delete value.binding[field];
    assert.throws(() => validateXpcQualificationEvidence(value), /missing or unknown|invalid/u, field);
  }
  const substituted = evidence();
  substituted.execution.run_id = "123456788";
  assert.throws(() => validateXpcQualificationEvidence(substituted), /execution is not bound to run_id/u);
  const launchSubstituted = evidence();
  launchSubstituted.launch_observation.source_tree = "0123456789abcdef0123456789abcdef01234567";
  assert.throws(() => validateXpcQualificationEvidence(launchSubstituted), /launch observation is not bound to source_tree/u);
});

test("rejects local, static, simulator, mock, sandbox, and not_proven execution claims", () => {
  for (const runner of ["local", "static", "simulator", "mock", "sandbox", "not_proven"]) {
    const value = evidence();
    value.execution.runner_id = runner;
    assert.throws(() => validateXpcQualificationEvidence(value), /local\/static\/simulated|protected external/u, runner);
  }
  const unqualified = evidence();
  unqualified.execution.status = "not_proven";
  assert.throws(() => validateXpcQualificationEvidence(unqualified), /not_proven marker/u);
  const notReal = evidence();
  notReal.execution.real_execution = false;
  assert.throws(() => validateXpcQualificationEvidence(notReal), /protected external/u);
});

test("requires a live kernel audit token, launchd Mach services, and distinct process generations", () => {
  const audit = evidence();
  audit.host_activation.audit_token_source = "mock_audit_token";
  assert.throws(() => validateXpcQualificationEvidence(audit), /local\/static\/simulated|live kernel/u);
  const mode = evidence();
  mode.launch_observation.mode = "synthetic";
  assert.throws(() => validateXpcQualificationEvidence(mode), /local\/static\/simulated|real launchd/u);
  const pid = evidence();
  pid.launch_observation.child_pid = pid.launch_observation.host_pid;
  assert.throws(() => validateXpcQualificationEvidence(pid), /distinct/u);
  const start = evidence();
  start.launch_observation.child_start_time_ns = "0";
  assert.throws(() => validateXpcQualificationEvidence(start), /Child start time/u);
});

test("requires a live, artifact/source/run-bound Child code requirement", () => {
  const value = evidence();
  value.child_requirement.observation = "static_codesign_requirement";
  assert.throws(() => validateXpcQualificationEvidence(value), /local\/static\/simulated|live requirement/u);
  const digestMismatch = evidence();
  digestMismatch.child_requirement.sha256 = digest("1");
  assert.throws(() => validateXpcQualificationEvidence(digestMismatch), /not bound to Host activation/u);
  const sourceMismatch = evidence();
  sourceMismatch.child_requirement.source_commit = "fedcba9876543210fedcba9876543210fedcba98";
  assert.throws(() => validateXpcQualificationEvidence(sourceMismatch), /Child requirement is not bound to source_commit/u);
});

test("requires all four live denial-before-sign cases with zero sign attempts", () => {
  for (const [index, field] of ["same_uid_wrong_child", "wrong_team", "wrong_entitlement", "stale_or_reused_audit_token"].entries()) {
    const value = evidence();
    value.negative_cases[index].sign_attempts = 1;
    assert.throws(() => validateXpcQualificationEvidence(value), /did not deny before sign/u, field);
  }
  const missing = evidence();
  missing.negative_cases.pop();
  assert.throws(() => validateXpcQualificationEvidence(missing), /fixed denial matrix/u);
  const duplicate = evidence();
  duplicate.negative_cases[3].case = duplicate.negative_cases[0].case;
  assert.throws(() => validateXpcQualificationEvidence(duplicate), /negative case set is not exact/u);
});

test("rejects not_proven or raw secret-bearing fields before production pass", () => {
  const value = evidence();
  value.host_activation.audit_token_sha256 = "not_proven";
  assert.throws(() => validateXpcQualificationEvidence(value), /local\/static\/simulated|digest/u);
  const raw = evidence();
  raw.host_activation.raw_token = "must-not-be-recorded";
  assert.throws(() => validateXpcQualificationEvidence(raw), /unknown fields/u);
});
