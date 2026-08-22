#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { POSTGRES_SCHEMA_HEAD } from "../../apps/cloud-api/src/postgres/schema-head.mjs";

const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const MAJOR = /^(?:16|17)$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const DISALLOWED_IDENTITY = /(^|[._:/ -])(local|static|unit|mock|fixture|fake|simulator|emulator|test|macos-latest|unknown|unidentified|unspecified|placeholder|redacted|n\/a|none|null)($|[._:/ -])/iu;
const CHECK_IDS = Object.freeze([
  "postgresql_version",
  "migration_contract",
  "role_rls_boundary",
  "concurrency_rollback"
]);
const REQUIRED_C3_CHECKS = Object.freeze([
  "migration_checksum",
  "schema_objects",
  "catalog_constraints_validated",
  "role_privileges_and_ownership",
  "rls_policy_catalog",
  "cross_role_privilege_boundary",
  "generation_contention_single_winner",
  "transaction_rollback"
]);
const EXPECTED_SCHEMA_HEAD = POSTGRES_SCHEMA_HEAD.version;
const CHECK_KEYS = Object.freeze(["check_id", "status", "expected", "observed", "evidence_sha256"]);

export class PostgresExternalQualificationRunnerError extends Error {
  constructor(message, code = "qualification_error") { super(message); this.name = "PostgresExternalQualificationRunnerError"; this.code = code; }
}

export function classifyQualificationDependencyError(error) {
  if (error?.code === "ERR_MODULE_NOT_FOUND" && /package ['"]pg['"]|node_modules[\\/]pg/u.test(String(error.message ?? error))) {
    return "required PostgreSQL qualification dependency is unavailable";
  }
  return null;
}

async function loadC3Qualification() {
  try {
    return await import("./postgres-c3-migration-0047.mjs");
  } catch (error) {
    const classified = classifyQualificationDependencyError(error);
    if (classified) throw new PostgresExternalQualificationRunnerError(classified, "dependency_unavailable");
    throw error;
  }
}

function required(env, name, pattern) {
  const value = env[name];
  if (typeof value !== "string" || !pattern.test(value)) throw new PostgresExternalQualificationRunnerError(`${name} is missing or invalid`);
  return value;
}

function digest(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function optionalFileDigest(file) {
  if (typeof file !== "string" || !path.isAbsolute(file)) return null;
  try {
    const metadata = fs.lstatSync(file);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || (metadata.mode & 0o022) !== 0) return null;
    return digest(fs.readFileSync(file));
  } catch {
    return null;
  }
}

function typedString(value) { return { type: "string", value: String(value) }; }
function check(checkId, expected, observed, evidenceSha256) {
  const expectedValue = typedString(expected);
  const observedValue = typedString(observed);
  const value = {
    check_id: checkId,
    status: expectedValue.value === observedValue.value ? "passed" : "failed",
    expected: expectedValue,
    observed: observedValue,
    evidence_sha256: evidenceSha256
  };
  return Object.freeze(value);
}

function adapterExecution(env, runnerId) {
  const value = {
    kind: "external_runner",
    real_execution: true,
    runner_id: runnerId,
    environment: Object.freeze({
      kind: "postgresql",
      identity: required(env, "AGENTPASS_POSTGRES_QUALIFICATION_ENVIRONMENT_ID", IDENTIFIER)
    })
  };
  return Object.freeze(value);
}

function externalBinding(env) {
  const runnerId = required(env, "AGENTPASS_POSTGRES_QUALIFICATION_RUNNER_ID", IDENTIFIER);
  if (DISALLOWED_IDENTITY.test(runnerId)) throw new PostgresExternalQualificationRunnerError("PostgreSQL qualification runner is not external");
  const value = {
    source_commit: required(env, "AGENTPASS_POSTGRES_QUALIFICATION_SOURCE_COMMIT", SHA),
    source_tree: required(env, "AGENTPASS_POSTGRES_QUALIFICATION_SOURCE_TREE", SHA),
    ci_run_id: required(env, "AGENTPASS_POSTGRES_QUALIFICATION_CI_RUN_ID", RUN_ID),
    ci_run_attempt: required(env, "AGENTPASS_POSTGRES_QUALIFICATION_CI_RUN_ATTEMPT", RUN_ID),
    qualification_run_id: required(env, "AGENTPASS_POSTGRES_QUALIFICATION_RUN_ID", RUN_ID),
    qualification_run_attempt: required(env, "AGENTPASS_POSTGRES_QUALIFICATION_RUN_ATTEMPT", RUN_ID),
    qualification_job_id: required(env, "AGENTPASS_POSTGRES_QUALIFICATION_JOB_ID", RUN_ID),
    artifact_sha256: required(env, "AGENTPASS_POSTGRES_QUALIFICATION_ARTIFACT_SHA256", DIGEST),
    postgres_major: required(env, "AGENTPASS_POSTGRES_QUALIFICATION_POSTGRES_MAJOR", MAJOR),
    runner_id
  };
  if (value.ci_run_id === value.qualification_run_id) throw new PostgresExternalQualificationRunnerError("canonical CI and qualification runs must be distinct");
  return Object.freeze(value);
}

function reportChecks(c3, major, c3Digest) {
  const passed = c3.status === "passed" && c3.qualified === true;
  const statuses = new Map((c3.checks ?? []).map((item) => [item.check_id, item.status]));
  const versionCheck = check("postgresql_version", major, String(c3.server_version ?? "").split(".")[0], c3Digest);
  const other = [
    check("migration_contract", "passed", passed && c3.current_version === EXPECTED_SCHEMA_HEAD
      && c3.migration_checksum === c3.artifact_sha256
      && statuses.get("migration_checksum") === "passed"
      && statuses.get("schema_objects") === "passed"
      && statuses.get("catalog_constraints_validated") === "passed" ? "passed" : "failed", c3Digest),
    check("role_rls_boundary", "passed", passed
      && statuses.get("role_privileges_and_ownership") === "passed"
      && statuses.get("rls_policy_catalog") === "passed"
      && statuses.get("cross_role_privilege_boundary") === "passed" ? "passed" : "failed", c3Digest),
    check("concurrency_rollback", "passed", passed && statuses.get("generation_contention_single_winner") === "passed" && statuses.get("transaction_rollback") === "passed" ? "passed" : "failed", c3Digest)
  ];
  return [versionCheck, ...other];
}

function reportC3CheckStatuses(c3) {
  const statuses = new Map((c3.checks ?? []).map((item) => [item.id ?? item.check_id, item.status]));
  return Object.freeze(Object.fromEntries(REQUIRED_C3_CHECKS.map((id) => [id, statuses.get(id) ?? "not_run"])));
}

export function verifyPostgresExternalQualificationEvidence(input, expected = {}) {
  const value = typeof input === "string" ? JSON.parse(input) : input;
  const requiredKeys = ["schema_version", "kind", "status", "qualified", "reason", "source_commit", "source_tree", "run_id", "run_attempt", "job_id", "ci_run_id", "ci_run_attempt", "qualification_run_id", "qualification_run_attempt", "qualification_job_id", "artifact_sha256", "postgres_major", "migration_artifact_sha256", "c3_evidence_sha256", "c3_server_version", "c3_database_name", "c3_server_port", "c3_schema_head", "c3_migration_checksum", "backup_pitr_evidence_sha256", "c3_check_statuses", "execution", "checks", "started_at", "completed_at"];
  if (!value || Object.keys(value).sort().join("|") !== requiredKeys.slice().sort().join("|")
    || value.schema_version !== 1 || value.kind !== "agentpass-postgresql-external-qualification"
    || !["passed", "failed"].includes(value.status) || value.qualified !== (value.status === "passed")
    || value.reason !== (value.status === "passed" ? null : "gate_failed") || !SHA.test(value.source_commit) || !SHA.test(value.source_tree)
    || !RUN_ID.test(value.run_id) || !RUN_ID.test(value.run_attempt) || !IDENTIFIER.test(value.job_id)
    || !RUN_ID.test(value.ci_run_id) || !RUN_ID.test(value.ci_run_attempt)
    || !RUN_ID.test(value.qualification_run_id) || !RUN_ID.test(value.qualification_run_attempt) || !RUN_ID.test(value.qualification_job_id)
    || !DIGEST.test(value.artifact_sha256) || !MAJOR.test(value.postgres_major)
    || !DIGEST.test(value.migration_artifact_sha256) || !DIGEST.test(value.c3_evidence_sha256)
    || (value.c3_server_version !== null && typeof value.c3_server_version !== "string")
    || (value.c3_database_name !== null && typeof value.c3_database_name !== "string")
    || (value.c3_server_port !== null && (!Number.isInteger(value.c3_server_port) || value.c3_server_port < 1 || value.c3_server_port > 65535))
    || (value.c3_schema_head !== null && !Number.isSafeInteger(value.c3_schema_head))
    || (value.c3_migration_checksum !== null && !DIGEST.test(value.c3_migration_checksum))
    || (value.backup_pitr_evidence_sha256 !== null && !DIGEST.test(value.backup_pitr_evidence_sha256))
    || !value.c3_check_statuses || typeof value.c3_check_statuses !== "object" || Array.isArray(value.c3_check_statuses)
    || JSON.stringify(Object.keys(value.c3_check_statuses).sort()) !== JSON.stringify(REQUIRED_C3_CHECKS.slice().sort())
    || Object.values(value.c3_check_statuses).some((status) => !["passed", "failed", "not_run"].includes(status))
    || !Array.isArray(value.checks) || value.checks.length !== CHECK_IDS.length
    || CHECK_IDS.some((id, index) => value.checks[index]?.check_id !== id)
    || typeof value.started_at !== "string" || typeof value.completed_at !== "string"
    || Date.parse(value.completed_at) < Date.parse(value.started_at)) {
    throw new PostgresExternalQualificationRunnerError("PostgreSQL external evidence is invalid");
  }
  for (const [key, pattern] of [["source_commit", SHA], ["source_tree", SHA], ["run_id", RUN_ID], ["run_attempt", RUN_ID], ["ci_run_id", RUN_ID], ["ci_run_attempt", RUN_ID], ["qualification_run_id", RUN_ID], ["qualification_run_attempt", RUN_ID], ["qualification_job_id", RUN_ID], ["artifact_sha256", DIGEST], ["postgres_major", MAJOR]]) {
    if (expected[key] !== undefined && value[key] !== expected[key]) throw new PostgresExternalQualificationRunnerError(`PostgreSQL external evidence ${key} binding is mismatched`);
    if (!pattern.test(value[key])) throw new PostgresExternalQualificationRunnerError(`PostgreSQL external evidence ${key} is invalid`);
  }
  if (expected.job_id !== undefined && value.job_id !== expected.job_id) throw new PostgresExternalQualificationRunnerError("PostgreSQL external evidence job binding is mismatched");
  if (value.run_id !== value.qualification_run_id || value.run_attempt !== value.qualification_run_attempt || value.job_id !== value.qualification_job_id) {
    throw new PostgresExternalQualificationRunnerError("PostgreSQL external evidence qualification aliases are mismatched");
  }
  for (const [key, expectedKey] of [["ci_run_id", "ci_run_id"], ["ci_run_attempt", "ci_run_attempt"], ["qualification_run_id", "run_id"], ["qualification_run_attempt", "run_attempt"], ["qualification_job_id", "job_id"]]) {
    if (expected[key] !== undefined && value[key] !== expected[key]) throw new PostgresExternalQualificationRunnerError(`PostgreSQL external evidence ${key} binding is mismatched`);
    if (expected[expectedKey] !== undefined && value[key] !== expected[expectedKey]) throw new PostgresExternalQualificationRunnerError(`PostgreSQL external evidence ${key} binding is mismatched`);
  }
  if (!value.execution || value.execution.kind !== "external_runner" || value.execution.real_execution !== true
    || typeof value.execution.runner_id !== "string" || !IDENTIFIER.test(value.execution.runner_id) || DISALLOWED_IDENTITY.test(value.execution.runner_id)
    || value.execution.environment?.kind !== "postgresql" || typeof value.execution.environment.identity !== "string"
    || !IDENTIFIER.test(value.execution.environment.identity) || DISALLOWED_IDENTITY.test(value.execution.environment.identity)) {
    throw new PostgresExternalQualificationRunnerError("PostgreSQL external execution binding is invalid");
  }
  for (const [index, item] of value.checks.entries()) {
    if (!item || Object.keys(item).sort().join("|") !== CHECK_KEYS.slice().sort().join("|")
      || item.check_id !== CHECK_IDS[index] || !["passed", "failed"].includes(item.status)
      || !item.expected || !item.observed
      || Object.keys(item.expected).sort().join("|") !== "type|value"
      || Object.keys(item.observed).sort().join("|") !== "type|value"
      || item.expected.type !== "string" || item.observed.type !== "string"
      || typeof item.expected.value !== "string" || typeof item.observed.value !== "string"
      || !DIGEST.test(item.evidence_sha256)
      || item.status !== (item.expected.value === item.observed.value ? "passed" : "failed")) {
      throw new PostgresExternalQualificationRunnerError("PostgreSQL external check evidence is invalid");
    }
  }
  const allPassed = value.checks.every((item) => item.status === "passed");
  if (value.status !== (allPassed ? "passed" : "failed")) throw new PostgresExternalQualificationRunnerError("PostgreSQL external status is not derived from checks");
  if (value.status === "passed" && (value.c3_server_version === null || value.c3_database_name === null
    || value.c3_server_port === null || value.c3_schema_head === null || value.c3_migration_checksum === null
    || value.backup_pitr_evidence_sha256 === null
    || value.c3_schema_head !== EXPECTED_SCHEMA_HEAD
    || value.c3_migration_checksum !== value.migration_artifact_sha256
    || !String(value.c3_server_version).startsWith(`${value.postgres_major}.`)
    || REQUIRED_C3_CHECKS.some((id) => value.c3_check_statuses[id] !== "passed"))) {
    throw new PostgresExternalQualificationRunnerError("PostgreSQL external passed evidence is missing runtime provenance");
  }
  return Object.freeze({ status: value.status, qualified: value.qualified, evidence_sha256: digest(canonicalJson(value)) });
}

export function externalQualificationExitCode(result) {
  return result?.status === "passed" && result?.qualified === true ? 0 : 1;
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
  const { runC3Migration0047Qualification } = await loadC3Qualification();
  const c3Env = { ...env };
  for (const name of ["GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "AGENTPASS_C3_ARTIFACT_SHA256", "AGENTPASS_QUALIFICATION_ARTIFACT_SHA256"]) delete c3Env[name];
  Object.assign(c3Env, {
    AGENTPASS_C3_SOURCE_COMMIT: binding.source_commit,
    AGENTPASS_C3_SOURCE_TREE: binding.source_tree,
    AGENTPASS_C3_CI_RUN_ID: binding.ci_run_id,
    AGENTPASS_C3_CI_RUN_ATTEMPT: binding.ci_run_attempt,
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
    run_id: binding.qualification_run_id,
    run_attempt: binding.qualification_run_attempt,
    job_id: binding.qualification_job_id,
    ci_run_id: binding.ci_run_id,
    ci_run_attempt: binding.ci_run_attempt,
    qualification_run_id: binding.qualification_run_id,
    qualification_run_attempt: binding.qualification_run_attempt,
    qualification_job_id: binding.qualification_job_id,
    artifact_sha256: binding.artifact_sha256,
    postgres_major: binding.postgres_major,
    migration_artifact_sha256: c3.artifact_sha256 ?? "0".repeat(64),
    c3_evidence_sha256: c3Digest,
    c3_server_version: c3.server_version ?? null,
    c3_database_name: c3.database_name ?? null,
    c3_server_port: c3.server_port ?? null,
    c3_schema_head: c3.current_version ?? null,
    c3_migration_checksum: c3.migration_checksum ?? null,
    backup_pitr_evidence_sha256: optionalFileDigest(c3Env.AGENTPASS_C3_BACKUP_PITR_EVIDENCE),
    c3_check_statuses: reportC3CheckStatuses(c3),
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

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runExternalPostgresC3Qualification().then((result) => {
    process.stdout.write(`${canonicalJson(result)}\n`);
    process.exitCode = externalQualificationExitCode(result);
  }).catch((error) => {
    if (error?.code === "dependency_unavailable") {
      process.stdout.write(`${canonicalJson({ status: "not_proven", reason: "dependency_unavailable" })}\n`);
      process.exitCode = 2;
      return;
    }
    process.stderr.write(`external PostgreSQL qualification failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
