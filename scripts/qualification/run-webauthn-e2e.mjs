#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";

const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const LOCAL_MARKER = /(^|[._:/ -])(local|static|unit|mock|fixture|fake|simulator|emulator|test|macos-latest)($|[._:/ -])/iu;
const REQUIRED_CHECKS = Object.freeze([
  "authenticator_origin_rp",
  "durable_one_time_consumption",
  "replay_rejection",
  "stale_context_rejection",
  "outage_fail_closed",
]);
const EVIDENCE_KEYS = Object.freeze(["checks", "execution", "kind", "qualified", "reason", "required_checks", "schema_version", "status"]);
const EXECUTION_KEYS = Object.freeze(["artifact_sha256", "completed_at", "environment", "job_id", "kind", "real_execution", "run_attempt", "run_id", "runner_id", "source_commit", "source_tree", "started_at"]);
const EXECUTION_KEYS_WITH_QUALIFICATION_BINDING = Object.freeze([...EXECUTION_KEYS, "ci_run_attempt", "ci_run_id", "qualification_job_id", "qualification_run_attempt", "qualification_run_id"]);

export class WebAuthnQualificationError extends Error {
  constructor(message) {
    super(message);
    this.name = "WebAuthnQualificationError";
  }
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new WebAuthnQualificationError(`${label} is not an object`);
  const actual = Object.keys(value).sort();
  const required = [...expected].sort();
  if (actual.length !== required.length || actual.some((item, index) => item !== required[index])) throw new WebAuthnQualificationError(`${label} has unknown or missing fields`);
}

function requireEnv(env, name, pattern) {
  const value = env[name];
  if (typeof value !== "string" || !pattern.test(value)) throw new WebAuthnQualificationError(`${name} is missing or invalid`);
  return value;
}

export function qualificationBinding(env = process.env) {
  const runnerId = requireEnv(env, "AGENTPASS_QUALIFICATION_RUNNER_ID", IDENTIFIER);
  if (LOCAL_MARKER.test(runnerId)) throw new WebAuthnQualificationError("qualification runner is not an external runner");
  return Object.freeze({
    runner_id: runnerId,
    run_id: requireEnv(env, "AGENTPASS_QUALIFICATION_RUN_ID", RUN_ID),
    job_id: requireEnv(env, "AGENTPASS_QUALIFICATION_JOB_ID", RUN_ID),
    run_attempt: requireEnv(env, "AGENTPASS_QUALIFICATION_RUN_ATTEMPT", RUN_ID),
    source_commit: requireEnv(env, "GITHUB_SHA", SHA),
    source_tree: requireEnv(env, "AGENTPASS_SOURCE_TREE", SHA),
    artifact_sha256: requireEnv(env, "AGENTPASS_QUALIFICATION_ARTIFACT_SHA256", DIGEST),
  });
}

function timestamp(value, label) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) {
    throw new WebAuthnQualificationError(`${label} is invalid`);
  }
}

export function validateWebAuthnEvidence(value, env = process.env) {
  const binding = qualificationBinding(env);
  exactKeys(value, EVIDENCE_KEYS, "WebAuthn qualification evidence");
  if (value.schema_version !== 1 || value.kind !== "agentpass-webauthn-agent-unattended-e2e" || value.status !== "passed" || value.qualified !== true || value.reason !== null) {
    throw new WebAuthnQualificationError("WebAuthn qualification evidence is not a passing result");
  }
  if (!Array.isArray(value.required_checks) || value.required_checks.length !== REQUIRED_CHECKS.length || value.required_checks.some((item, index) => item !== REQUIRED_CHECKS[index])) {
    throw new WebAuthnQualificationError("WebAuthn qualification check inventory is invalid");
  }
  const hasQualificationBinding = Object.prototype.hasOwnProperty.call(value.execution, "ci_run_id");
  exactKeys(value.execution, hasQualificationBinding ? EXECUTION_KEYS_WITH_QUALIFICATION_BINDING : EXECUTION_KEYS, "WebAuthn qualification execution");
  if (hasQualificationBinding && ["ci_run_id", "ci_run_attempt", "qualification_run_id", "qualification_run_attempt", "qualification_job_id"].some((key) => typeof value.execution[key] !== "string" || !RUN_ID.test(value.execution[key]))) throw new WebAuthnQualificationError("WebAuthn qualification execution qualification binding is invalid");
  for (const [key, expected] of Object.entries(binding)) if (value.execution[key] !== expected) throw new WebAuthnQualificationError(`WebAuthn qualification ${key} binding is mismatched`);
  if (value.execution.kind !== "external_runner" || value.execution.real_execution !== true || LOCAL_MARKER.test(value.execution.runner_id)) throw new WebAuthnQualificationError("WebAuthn qualification execution is not external");
  timestamp(value.execution.started_at, "execution.started_at");
  timestamp(value.execution.completed_at, "execution.completed_at");
  if (Date.parse(value.execution.completed_at) < Date.parse(value.execution.started_at)) throw new WebAuthnQualificationError("execution timestamps are reversed");
  exactKeys(value.execution.environment, ["authenticator", "identity", "instance_ids", "kind", "origin", "rp_id"], "WebAuthn qualification environment");
  const environment = value.execution.environment;
  if (environment.kind !== "webauthn" || typeof environment.identity !== "string" || LOCAL_MARKER.test(environment.identity)) throw new WebAuthnQualificationError("WebAuthn qualification environment is not external");
  if (!["platform", "cross-platform"].includes(environment.authenticator) || typeof environment.origin !== "string" || !/^https:\/\//u.test(environment.origin) || LOCAL_MARKER.test(environment.origin)
    || typeof environment.rp_id !== "string" || !/^[a-z0-9](?:[a-z0-9.-]{0,127})[a-z0-9]$/u.test(environment.rp_id) || LOCAL_MARKER.test(environment.rp_id)) throw new WebAuthnQualificationError("WebAuthn origin, RP ID, or authenticator is not external");
  let origin;
  try { origin = new URL(environment.origin); } catch { throw new WebAuthnQualificationError("WebAuthn origin is invalid"); }
  if (origin.protocol !== "https:" || origin.hostname !== environment.rp_id && !origin.hostname.endsWith(`.${environment.rp_id}`)) throw new WebAuthnQualificationError("WebAuthn origin is not bound to the RP ID");
  if (!Array.isArray(environment.instance_ids) || environment.instance_ids.length !== 2 || new Set(environment.instance_ids).size !== 2
    || environment.instance_ids.some((item) => typeof item !== "string" || !IDENTIFIER.test(item) || LOCAL_MARKER.test(item))) throw new WebAuthnQualificationError("WebAuthn qualification must bind two external instances");
  if (typeof env.AGENTPASS_WEBAUTHN_EXPECTED_ORIGIN === "string" && environment.origin !== env.AGENTPASS_WEBAUTHN_EXPECTED_ORIGIN) throw new WebAuthnQualificationError("WebAuthn origin does not match the deployed origin binding");
  if (typeof env.AGENTPASS_WEBAUTHN_EXPECTED_RP_ID === "string" && environment.rp_id !== env.AGENTPASS_WEBAUTHN_EXPECTED_RP_ID) throw new WebAuthnQualificationError("WebAuthn RP ID does not match the deployed RP binding");
  if (!Array.isArray(value.checks) || value.checks.length !== REQUIRED_CHECKS.length) throw new WebAuthnQualificationError("WebAuthn qualification checks are incomplete");
  const seen = new Set();
  value.checks.forEach((item, index) => {
    exactKeys(item, ["check_id", "evidence_sha256", "expected", "observed", "status"], `WebAuthn check ${index}`);
    if (item.check_id !== REQUIRED_CHECKS[index] || seen.has(item.check_id) || item.status !== "passed") throw new WebAuthnQualificationError("WebAuthn qualification check identity/status is invalid");
    seen.add(item.check_id);
    for (const field of ["expected", "observed"]) {
      exactKeys(item[field], ["type", "value"], `WebAuthn check ${field}`);
      if (item[field].type !== "boolean" || item[field].value !== true) throw new WebAuthnQualificationError("WebAuthn qualification check is not a positive boolean");
    }
    if (!DIGEST.test(item.evidence_sha256)) throw new WebAuthnQualificationError("WebAuthn qualification check digest is invalid");
    const material = { check_id: item.check_id, status: item.status, expected: item.expected, observed: item.observed };
    if (crypto.createHash("sha256").update(canonicalJson(material), "utf8").digest("hex") !== item.evidence_sha256) throw new WebAuthnQualificationError("WebAuthn qualification check digest is mismatched");
  });
  return Object.freeze({ ...value, binding });
}

function findEvidenceFiles(root) {
  const matches = [];
  function walk(current) {
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) throw new WebAuthnQualificationError("qualification output contains a symlink");
    if (stat.isDirectory()) {
      for (const entry of fs.readdirSync(current)) walk(path.join(current, entry));
    } else if (stat.isFile() && path.basename(current) === "webauthn-agent-unattended-qualification.json") matches.push(current);
  }
  walk(root);
  return matches;
}

export function runQualification({ env = process.env, runner = spawnSync } = {}) {
  const binding = qualificationBinding(env);
  const target = path.resolve(requireEnv(env, "AGENTPASS_WEBAUTHN_QUALIFICATION_EVIDENCE_PATH", /^[^\0]+$/u));
  if (fs.existsSync(target)) throw new WebAuthnQualificationError("qualification evidence target already exists");
  const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-webauthn-qualification-"));
  try {
    const webConsole = path.resolve("apps/web-console");
    const result = runner(process.execPath, ["node_modules/@playwright/test/cli.js", "test", "--grep", "qualification: real-browser WebAuthn", "--reporter=line"], {
      cwd: webConsole,
      env: { ...env, CI: "true", AGENTPASS_PLAYWRIGHT_OUTPUT_DIR: outputDir },
      encoding: "utf8",
      stdio: "inherit",
    });
    if (result.status !== 0) throw new WebAuthnQualificationError(`WebAuthn browser qualification exited with ${String(result.status)}`);
    const files = findEvidenceFiles(outputDir);
    if (files.length !== 1) throw new WebAuthnQualificationError("qualification must produce exactly one typed evidence attachment");
    const bytes = fs.readFileSync(files[0]);
    const evidence = validateWebAuthnEvidence(JSON.parse(bytes.toString("utf8")), { ...env, ...binding });
    if (bytes.toString("utf8") !== canonicalJson(evidenceWithoutBinding(evidence))) throw new WebAuthnQualificationError("qualification evidence is not canonical JSON");
    fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    const fd = fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    try { fs.writeFileSync(fd, canonicalJson(evidenceWithoutBinding(evidence)), { encoding: "utf8" }); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    return Object.freeze({ status: "passed", qualified: true, evidence_path: target, source_commit: binding.source_commit, run_id: binding.run_id, job_id: binding.job_id, artifact_sha256: binding.artifact_sha256 });
  } finally {
    fs.rmSync(outputDir, { recursive: true, force: true });
  }
}

function evidenceWithoutBinding(value) {
  const { binding: _binding, ...evidence } = value;
  return evidence;
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  try {
    process.stdout.write(`${canonicalJson(runQualification())}\n`);
  } catch (error) {
    process.stderr.write(`webauthn qualification failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
