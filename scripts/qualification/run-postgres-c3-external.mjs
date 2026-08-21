#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import {
  runC3Migration0047Qualification,
  verifyQualificationEvidence
} from "./postgres-c3-migration-0047.mjs";

const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const MAJOR = /^(?:16|17)$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const LOCAL_MARKER = /(^|[._:/ -])(local|static|unit|mock|fixture|fake|simulator|emulator|test|macos-latest)($|[._:/ -])/iu;
const CHECK_IDS = Object.freeze([
  "postgresql_version",
  "migration_contract",
  "role_rls_boundary",
  "concurrency_rollback"
]);

export class PostgresExternalQualificationRunnerError extends Error {
  constructor(message) { super(message); this.name = "PostgresExternalQualificationRunnerError"; }
}

function required(env, name, pattern) {
  const value = env[name];
  if (typeof value !== "string" || !pattern.test(value)) throw new PostgresExternalQualificationRunnerError(`${name} is missing or invalid`);
  return value;
}

function digest(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function typedString(value) { return { type: "string", value: String(value) }; }
function check(checkId, expected, observed, evidenceSha256) {
  const expectedValue = typedString(expected);
  const observedValue = typedString(observed);
  return Object.freeze({
    check_id: checkId,
    status: expectedValue.value === observedValue.value ? "passed" : "failed",
    expected: expectedValue,
    observed: observedValue,
    evidence_sha256: evidenceSha256
  });
}

function adapterExecution(env, runnerId) {
  return Object.freeze({
    kind: "external_runner",
    real_execution: true,
    runner_id: runnerId,
    environment: Object.freeze({
      kind: "postgresql",
      identity: required(env, "AGENTPASS_POSTGRES_QUALIFICATION_ENVIRONMENT_ID", IDENTIFIER)
    })
  });
}

function externalBinding(env) {
  const runnerId = required(env, "AGENTPASS_POSTGRES_QUALIFICATION_RUNNER_ID", IDENTIFIER);
  if (LOCAL_MARKER.test(runnerId)) throw new PostgresExternalQualificationRunnerError("PostgreSQL qualification runner is not external");
  return Object.freeze({
    source_commit: required(env, "AGENTPASS_POSTGRES_QUALIFICATION_SOURCE_COMMIT", SHA),
    source_tree: required(env, "AGENTPASS_POSTGRES_QUALIFICATION_SOURCE_TREE", SHA),
    run_id: required(env, "AGENTPASS_POSTGRES_QUALIFICATION_RUN_ID", RUN_ID),
    run_attempt: required(env, "AGENTPASS_POSTGRES_QUALIFICATION_RUN_ATTEMPT", RUN_ID),
    job_id: required(env, "AGENTPASS_POSTGRES_QUALIFICATION_JOB_ID", RUN_ID),
    artifact_sha256: required(env, "AGENTPASS_POSTGRES_QUALIFICATION_ARTIFACT_SHA256", DIGEST),
    postgres_major: required(env, "AGENTPASS_POSTGRES_QUALIFICATION_POSTGRES_MAJOR", MAJOR),
    runner_id
  });
}

function reportChecks(c3, major, c3Digest) {
  const passed = c3.status === "passed" && c3.qualified === true;
  const statuses = new Map((c3.checks ?? []).map((item) => [item.check_id, item.status]));
  const versionCheck = check("postgresql_version", major, String(c3.server_version ?? "").split(".")[0], c3Digest);
  const other = [
    check("migration_contract", "passed", passed && statuses.get("migration_checksum") === "passed" && statuses.get("schema_objects") === "passed" ? "passed" : "failed", c3Digest),
    check("role_rls_boundary", "passed", passed && statuses.get("role_privileges_and_ownership") === "passed" && statuses.get("rls_policy_catalog") === "passed" ? "passed" : "failed", c3Digest),
    check("concurrency_rollback", "passed", passed && statuses.get("generation_contention_single_winner") === "passed" && statuses.get("transaction_rollback") === "passed" ? "passed" : "failed", c3Digest)
  ];
  return [versionCheck, ...other];
}

export function verifyPostgresExternalQualificationEvidence(input, expected = {}) {
  const value = typeof input === "string" ? JSON.parse(input) : input;
  const requiredKeys = ["schema_version", "kind", "status", "qualified", "reason", "source_commit", "source_tree", "run_id", "run_attempt", "job_id", "artifact_sha256", "postgres_major", "migration_artifact_sha256", "c3_evidence_sha256", "execution", "checks", "started_at", "completed_at"];
  if (!value || Object.keys(value).sort().join("|") !== requiredKeys.slice().sort().join("|")
    || value.schema_version !== 1 || value.kind !== "agentpass-postgresql-external-qualification"
    || !["passed", "failed"].includes(value.status) || value.qualified !== (value.status === "passed")
    || value.reason !== (value.status === "passed" ? null : "gate_failed") || !SHA.test(value.source_commit) || !SHA.test(value.source_tree)
    || !RUN_ID.test(value.run_id) || !RUN_ID.test(value.run_attempt) || !IDENTIFIER.test(value.job_id)
    || !DIGEST.test(value.artifact_sha256) || !MAJOR.test(value.postgres_major)
    || !DIGEST.test(value.migration_artifact_sha256) || !DIGEST.test(value.c3_evidence_sha256)
    || !Array.isArray(value.checks) || value.checks.length !== CHECK_IDS.length
    || CHECK_IDS.some((id, index) => value.checks[index]?.check_id !== id)
    || typeof value.started_at !== "string" || typeof value.completed_at !== "string"
    || Date.parse(value.completed_at) < Date.parse(value.started_at)) {
    throw new PostgresExternalQualificationRunnerError("PostgreSQL external evidence is invalid");
  }
  for (const [key, pattern] of [["source_commit", SHA], ["source_tree", SHA], ["run_id", RUN_ID], ["run_attempt", RUN_ID], ["artifact_sha256", DIGEST], ["postgres_major", MAJOR]]) {
    if (expected[key] !== undefined && value[key] !== expected[key]) throw new PostgresExternalQualificationRunnerError(`PostgreSQL external evidence ${key} binding is mismatched`);
    if (!pattern.test(value[key])) throw new PostgresExternalQualificationRunnerError(`PostgreSQL external evidence ${key} is invalid`);
  }
  if (expected.job_id !== undefined && value.job_id !== expected.job_id) throw new PostgresExternalQualificationRunnerError("PostgreSQL external evidence job binding is mismatched");
  if (!value.execution || value.execution.kind !== "external_runner" || value.execution.real_execution !== true
    || typeof value.execution.runner_id !== "string" || LOCAL_MARKER.test(value.execution.runner_id)
    || value.execution.environment?.kind !== "postgresql" || typeof value.execution.environment.identity !== "string") {
    throw new PostgresExternalQualificationRunnerError("PostgreSQL external execution binding is invalid");
  }
  const allPassed = value.checks.every((item) => item.status === "passed");
  if (value.status !== (allPassed ? "passed" : "failed")) throw new PostgresExternalQualificationRunnerError("PostgreSQL external status is not derived from checks");
  return Object.freeze({ status: value.status, qualified: value.qualified, evidence_sha256: digest(canonicalJson(value)) });
}

export async function runExternalPostgresC3Qualification({ env = process.env } = {}) {
  if (env.AGENTPASS_POSTGRES_QUALIFICATION_ENABLED !== "true"
    || env.AGENTPASS_POSTGRES_QUALIFICATION_EXECUTION !== "external"
    || env.AGENTPASS_POSTGRES_QUALIFICATION_REAL_EXECUTION !== "true") {
    throw new PostgresExternalQualificationRunnerError("external PostgreSQL qualification mode is not enabled");
  }
  const binding = externalBinding(env);
  const output = path.resolve(required(env, "AGENTPASS_POSTGRES_QUALIFICATION_EVIDENCE_PATH", /^[^\0]+$/u));
  if (fs.existsSync(output)) throw new PostgresExternalQualificationRunnerError("PostgreSQL qualification evidence target already exists");
  const c3Env = { ...env };
  for (const name of ["GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "AGENTPASS_C3_ARTIFACT_SHA256", "AGENTPASS_QUALIFICATION_ARTIFACT_SHA256"]) delete c3Env[name];
  Object.assign(c3Env, {
    AGENTPASS_C3_SOURCE_COMMIT: binding.source_commit,
    AGENTPASS_C3_SOURCE_TREE: binding.source_tree,
    AGENTPASS_C3_CI_RUN_ID: binding.run_id,
    AGENTPASS_C3_CI_RUN_ATTEMPT: binding.run_attempt,
    AGENTPASS_C3_CI_JOB_ID: `postgres-authority-${binding.postgres_major}`,
    AGENTPASS_C3_EXPECTED_POSTGRES_MAJOR: binding.postgres_major
  });
  const c3 = await runC3Migration0047Qualification({ env: c3Env });
  const c3Text = canonicalJson(c3);
  const c3Digest = digest(c3Text);
  const report = {
    schema_version: 1,
    kind: "agentpass-postgresql-external-qualification",
    status: "failed",
    qualified: false,
    reason: null,
    source_commit: binding.source_commit,
    source_tree: binding.source_tree,
    run_id: binding.run_id,
    run_attempt: binding.run_attempt,
    job_id: binding.job_id,
    artifact_sha256: binding.artifact_sha256,
    postgres_major: binding.postgres_major,
    migration_artifact_sha256: c3.artifact_sha256 ?? "0".repeat(64),
    c3_evidence_sha256: c3Digest,
    execution: adapterExecution(env, binding.runner_id),
    checks: reportChecks(c3, binding.postgres_major, c3Digest),
    started_at: c3.started_at,
    completed_at: c3.completed_at
  };
  report.status = report.checks.every((item) => item.status === "passed") ? "passed" : "failed";
  report.qualified = report.status === "passed";
  report.reason = report.status === "passed" ? null : "gate_failed";
  verifyPostgresExternalQualificationEvidence(report, binding);
  fs.mkdirSync(path.dirname(output), { recursive: true, mode: 0o700 });
  const fd = fs.openSync(output, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, `${canonicalJson(report)}\n`, "utf8"); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  return Object.freeze({ status: report.status, qualified: report.qualified, evidence_path: output, artifact_sha256: binding.artifact_sha256, migration_artifact_sha256: report.migration_artifact_sha256 });
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  runExternalPostgresC3Qualification().then((result) => process.stdout.write(`${canonicalJson(result)}\n`)).catch((error) => {
    process.stderr.write(`external PostgreSQL qualification failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
