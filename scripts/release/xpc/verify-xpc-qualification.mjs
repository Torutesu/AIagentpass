#!/usr/bin/env node
import fs from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

const SCHEMA_VERSION = 3;
const HEX64 = /^[0-9a-f]{64}$/u;
const SHA = /^[0-9a-f]{40,64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const RUN_ATTEMPT = /^[1-9][0-9]{0,8}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const PROTECTED_RUNNER = /^github-actions\/[A-Za-z0-9][A-Za-z0-9._-]{2,127}$/u;
const FORBIDDEN_MARKER = /(?:^|[/:._-])(local|static|simulator|mock|sandbox|not[_-]?proven|not[_-]?run|fixture|synthetic)(?:$|[/:._-])/iu;

const REQUIRED_KEYS = Object.freeze(["binding", "child_requirement", "execution", "host_activation", "launch_observation", "negative_cases", "schema_version"]);
const BINDING_KEYS = Object.freeze(["artifact_sha256", "candidate_sha256", "job_id", "run_attempt", "run_id", "source_commit", "source_tree"]);
const EXECUTION_KEYS = Object.freeze(["artifact_sha256", "candidate_sha256", "completed_at", "environment", "job_id", "kind", "real_execution", "run_attempt", "run_id", "runner_id", "source_commit", "source_tree", "started_at", "status"]);
const ACTIVATION_KEYS = Object.freeze(["audit_token_capture", "audit_token_sha256", "audit_token_source", "binding_sha256", "child_process_identity_sha256", "child_requirement_sha256", "observation", "projection_sha256", "status", "transport"]);
const REQUIREMENT_KEYS = Object.freeze(["artifact_sha256", "binding_sha256", "candidate_sha256", "evaluation", "job_id", "observation", "principal", "run_attempt", "run_id", "sha256", "source_commit", "source_tree"]);
const LAUNCH_OBSERVATION_KEYS = Object.freeze(["artifact_sha256", "binding_sha256", "candidate_sha256", "child_mach_service", "child_pid", "child_process_identity_sha256", "child_start_time_ns", "host_mach_service", "host_pid", "host_start_time_ns", "job_id", "mode", "run_attempt", "run_id", "source_commit", "source_tree", "status"]);
const NEGATIVE_CASE_KEYS = Object.freeze(["case", "observation", "result", "sign_attempts"]);
const NEGATIVE_CASES = Object.freeze(["same_uid_wrong_child", "wrong_team", "wrong_entitlement", "stale_or_reused_audit_token"]);

const exactKeys = (value, keys, label) => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error(`${label} has missing or unknown fields`);
};

const digest = (value, label) => {
  if (typeof value !== "string" || !HEX64.test(value) || value === "0".repeat(64)) throw new Error(`${label} must be a non-zero lowercase SHA-256 digest`);
};

const sha = (value, label) => {
  if (typeof value !== "string" || !SHA.test(value) || /^0+$/u.test(value)) throw new Error(`${label} must be a non-zero commit/tree SHA`);
};

const canonicalJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
};

const bindingDigest = (binding) => createHash("sha256").update(canonicalJson(binding), "utf8").digest("hex");

const assertBindingEqual = (record, binding, label) => {
  for (const key of BINDING_KEYS) if (record[key] !== binding[key]) throw new Error(`${label} is not bound to ${key}`);
};

const assertNoForbiddenMarkers = (value) => {
  const visit = (item, path = "evidence") => {
    if (typeof item === "string" && FORBIDDEN_MARKER.test(item)) throw new Error(`${path} contains a local/static/simulated or not_proven marker`);
    if (Array.isArray(item)) item.forEach((child, index) => visit(child, `${path}[${index}]`));
    else if (item !== null && typeof item === "object") for (const [key, child] of Object.entries(item)) visit(child, `${path}.${key}`);
  };
  visit(value);
};

const assertTimestamp = (value, label) => {
  if (typeof value !== "string" || !TIMESTAMP.test(value) || Number.isNaN(Date.parse(value))) throw new Error(`${label} is invalid`);
};

export function validateXpcQualificationEvidence(value) {
  exactKeys(value, REQUIRED_KEYS, "XPC qualification evidence");
  if (value.schema_version !== SCHEMA_VERSION) throw new Error("XPC qualification schema_version is unsupported");
  assertNoForbiddenMarkers(value);

  exactKeys(value.binding, BINDING_KEYS, "XPC release binding");
  digest(value.binding.candidate_sha256, "candidate_sha256");
  digest(value.binding.artifact_sha256, "artifact_sha256");
  sha(value.binding.source_commit, "source_commit");
  sha(value.binding.source_tree, "source_tree");
  for (const [field, pattern] of [["run_id", RUN_ID], ["job_id", RUN_ID], ["run_attempt", RUN_ATTEMPT]]) {
    if (typeof value.binding[field] !== "string" || !pattern.test(value.binding[field])) throw new Error(`${field} is invalid`);
  }
  const expectedBindingDigest = bindingDigest(value.binding);

  exactKeys(value.execution, EXECUTION_KEYS, "XPC execution");
  assertBindingEqual(value.execution, value.binding, "XPC execution");
  if (value.execution.kind !== "external_runner" || value.execution.environment !== "protected_macos" || value.execution.real_execution !== true || value.execution.status !== "passed" || typeof value.execution.runner_id !== "string" || !PROTECTED_RUNNER.test(value.execution.runner_id)) throw new Error("XPC execution is not a passed protected external macOS runner execution");
  assertTimestamp(value.execution.started_at, "XPC execution start time");
  assertTimestamp(value.execution.completed_at, "XPC execution completion time");
  if (Date.parse(value.execution.completed_at) < Date.parse(value.execution.started_at)) throw new Error("XPC execution timestamps are reversed");

  exactKeys(value.host_activation, ACTIVATION_KEYS, "host_activation");
  for (const [field, label] of [["audit_token_sha256", "live audit-token digest"], ["child_process_identity_sha256", "Child process identity digest"], ["child_requirement_sha256", "Child requirement digest"], ["projection_sha256", "Host activation projection digest"]]) digest(value.host_activation[field], label);
  if (value.host_activation.audit_token_capture !== "live_eight_field" || value.host_activation.audit_token_source !== "kernel_live_audit_token_t" || value.host_activation.observation !== "live_nsxpc_activation") throw new Error("audit-token evidence is not a live kernel NSXPC observation");
  if (value.host_activation.binding_sha256 !== expectedBindingDigest) throw new Error("Host activation is not bound to the release binding");
  if (value.host_activation.status !== "passed" || value.host_activation.transport !== "authenticated_xpc") throw new Error("Host activation is not authenticated and passed");

  exactKeys(value.launch_observation, LAUNCH_OBSERVATION_KEYS, "launch_observation");
  assertBindingEqual(value.launch_observation, value.binding, "launch observation");
  digest(value.launch_observation.artifact_sha256, "launch observation artifact digest");
  if (value.launch_observation.binding_sha256 !== expectedBindingDigest) throw new Error("launch observation binding digest is invalid");
  if (value.launch_observation.mode !== "launchd_mach_nsxpc") throw new Error("launch observation is not a real launchd Mach NSXPC observation");
  if (value.launch_observation.host_mach_service !== "dev.agentpass.agent-host" || value.launch_observation.child_mach_service !== "dev.agentpass.child-git") throw new Error("launch observation Mach service identity is not fixed");
  for (const [field, label] of [["host_pid", "Host PID"], ["child_pid", "Child PID"]]) if (!Number.isSafeInteger(value.launch_observation[field]) || value.launch_observation[field] <= 0) throw new Error(`${label} is invalid`);
  if (value.launch_observation.host_pid === value.launch_observation.child_pid) throw new Error("Host and Child PID must be distinct");
  for (const [field, label] of [["host_start_time_ns", "Host start time"], ["child_start_time_ns", "Child start time"]]) if (typeof value.launch_observation[field] !== "string" || !/^[1-9][0-9]+$/u.test(value.launch_observation[field])) throw new Error(`${label} is invalid`);
  if (value.launch_observation.child_process_identity_sha256 !== value.host_activation.child_process_identity_sha256) throw new Error("Child process identity is not bound to live activation");
  if (value.launch_observation.status !== "passed") throw new Error("launch observation is not passed");

  exactKeys(value.child_requirement, REQUIREMENT_KEYS, "child_requirement");
  assertBindingEqual(value.child_requirement, value.binding, "Child requirement");
  digest(value.child_requirement.sha256, "child_requirement.sha256");
  if (value.child_requirement.binding_sha256 !== expectedBindingDigest) throw new Error("Child requirement binding digest is invalid");
  if (value.child_requirement.principal !== "dev.agentpass.git-sign-xpc" || value.child_requirement.evaluation !== "passed" || value.child_requirement.observation !== "live_codesign_requirement") throw new Error("Child-specific live requirement evaluation is not passed");
  if (value.child_requirement.sha256 !== value.host_activation.child_requirement_sha256) throw new Error("Child requirement digest is not bound to Host activation");

  if (!Array.isArray(value.negative_cases) || value.negative_cases.length !== NEGATIVE_CASES.length) throw new Error("negative_cases must contain the fixed denial matrix");
  const seen = new Set();
  for (const entry of value.negative_cases) {
    exactKeys(entry, NEGATIVE_CASE_KEYS, "negative case");
    if (!NEGATIVE_CASES.includes(entry.case) || seen.has(entry.case)) throw new Error("negative case set is not exact");
    seen.add(entry.case);
    if (entry.observation !== "live_macos_probe" || entry.result !== "denied_before_sign" || entry.sign_attempts !== 0) throw new Error(`negative case ${entry.case} did not deny before sign on a live probe`);
  }
  if (seen.size !== NEGATIVE_CASES.length) throw new Error("negative case set is incomplete");

  const serialized = canonicalJson(value);
  if (/(?:audit[_-]?token|raw[_-]?token|private[_-]?key|credential|signature)\s*:/iu.test(serialized)) throw new Error("evidence contains a prohibited raw secret-bearing field");
  return Object.freeze({ schema_version: value.schema_version, ...value.binding, binding_sha256: expectedBindingDigest, evidence_sha256: createHash("sha256").update(serialized, "utf8").digest("hex") });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  const input = process.argv[2];
  if (!input || process.argv.length !== 3) throw new Error("Usage: verify-xpc-qualification.mjs EVIDENCE.json");
  const result = validateXpcQualificationEvidence(JSON.parse(fs.readFileSync(input, "utf8")));
  process.stdout.write(`XPC qualification evidence valid: candidate=${result.candidate_sha256}, source_tree=${result.source_tree}, run=${result.run_id}/${result.run_attempt}, evidence=${result.evidence_sha256}\n`);
}
