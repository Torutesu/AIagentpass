#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { verifyPostgresExternalQualificationEvidence } from "./run-postgres-c3-external.mjs";

const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const REQUIRED_CHECKS = Object.freeze([
  "postgresql_16_version",
  "postgresql_17_version",
  "migration_contract",
  "role_rls_boundary",
  "concurrency_rollback"
]);

export class PostgresGateAggregationError extends Error {
  constructor(message) { super(message); this.name = "PostgresGateAggregationError"; }
}

function required(value, name, pattern) {
  if (typeof value !== "string" || !pattern.test(value)) throw new PostgresGateAggregationError(`${name} is missing or invalid`);
  return value;
}

function digest(text) { return crypto.createHash("sha256").update(text, "utf8").digest("hex"); }

function typed(value) { return { type: "string", value: String(value) }; }

function childCheck(child, childId, expected, actualId) {
  const item = child.checks.find((entry) => entry.check_id === actualId);
  if (!item) throw new PostgresGateAggregationError(`${childId} is missing ${actualId}`);
  const observed = item.observed?.value;
  const passed = item.status === "passed" && observed === expected;
  return {
    check_id: childId,
    status: passed ? "passed" : "failed",
    expected: typed(expected),
    observed: typed(observed ?? "missing"),
    evidence_sha256: child.c3_evidence_sha256
  };
}

function pairedCheck(child16, child17, checkId, childCheckId) {
  const first = child16.checks.find((entry) => entry.check_id === childCheckId);
  const second = child17.checks.find((entry) => entry.check_id === childCheckId);
  if (!first || !second) throw new PostgresGateAggregationError(`children are missing ${childCheckId}`);
  const passed = first.status === "passed" && second.status === "passed" && first.observed?.value === "passed" && second.observed?.value === "passed";
  return {
    check_id: checkId,
    status: passed ? "passed" : "failed",
    expected: typed("passed"),
    observed: typed(passed ? "passed" : "failed"),
    evidence_sha256: digest(`${child16.c3_evidence_sha256}:${child17.c3_evidence_sha256}:${checkId}`)
  };
}

export function aggregatePostgresGate({ child16, child17, sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, jobId, bundleArtifactSha256, runnerId, environmentId, startedAt, completedAt }) {
  verifyPostgresExternalQualificationEvidence(child16, { source_commit: sourceCommit, source_tree: sourceTree, artifact_sha256: releaseArtifactSha256, run_id: child16.run_id, run_attempt: runAttempt, job_id: child16.job_id, postgres_major: "16" });
  verifyPostgresExternalQualificationEvidence(child17, { source_commit: sourceCommit, source_tree: sourceTree, artifact_sha256: releaseArtifactSha256, run_id: child17.run_id, run_attempt: runAttempt, job_id: child17.job_id, postgres_major: "17" });
  if (child16.run_id !== runId || child17.run_id !== runId || child16.run_attempt !== runAttempt || child17.run_attempt !== runAttempt) throw new PostgresGateAggregationError("PostgreSQL child run binding is mismatched");
  required(sourceCommit, "source_commit", SHA); required(sourceTree, "source_tree", SHA); required(releaseArtifactSha256, "release_artifact_sha256", DIGEST); required(runId, "run_id", RUN_ID); required(runAttempt, "run_attempt", RUN_ID); required(jobId, "job_id", RUN_ID); required(bundleArtifactSha256, "bundle_artifact_sha256", DIGEST); required(runnerId, "runner_id", IDENTIFIER); required(environmentId, "environment_id", IDENTIFIER);
  if (!TIMESTAMP.test(startedAt) || !TIMESTAMP.test(completedAt) || Date.parse(completedAt) < Date.parse(startedAt)) throw new PostgresGateAggregationError("PostgreSQL aggregate timestamps are invalid");
  const checks = [
    childCheck(child16, "postgresql_16_version", "16", "postgresql_version"),
    childCheck(child17, "postgresql_17_version", "17", "postgresql_version"),
    pairedCheck(child16, child17, "migration_contract", "migration_contract"),
    pairedCheck(child16, child17, "role_rls_boundary", "role_rls_boundary"),
    pairedCheck(child16, child17, "concurrency_rollback", "concurrency_rollback")
  ];
  const passed = checks.every((item) => item.status === "passed");
  return Object.freeze({
    status: passed ? "passed" : "failed",
    qualified: passed,
    reason: passed ? null : "gate_failed",
    execution: Object.freeze({
      kind: "external_runner",
      real_execution: true,
      runner_id: runnerId,
      run_id: runId,
      job_id: jobId,
      run_attempt: runAttempt,
      source_commit: sourceCommit,
      source_tree: sourceTree,
      artifact_sha256: bundleArtifactSha256,
      started_at: startedAt,
      completed_at: completedAt,
      environment: Object.freeze({ kind: "postgresql", identity: environmentId })
    }),
    required_checks: REQUIRED_CHECKS,
    checks: Object.freeze(checks)
  });
}

export function bundleArtifactSha256(child16Text, child17Text) {
  if (typeof child16Text !== "string" || typeof child17Text !== "string") throw new PostgresGateAggregationError("PostgreSQL child evidence must be text");
  return digest(`${child16Text}${child17Text}`);
}

function main(env = process.env) {
  const child16Path = path.resolve(required(env.AGENTPASS_POSTGRES_16_EVIDENCE_PATH, "AGENTPASS_POSTGRES_16_EVIDENCE_PATH", /^[^\0]+$/u));
  const child17Path = path.resolve(required(env.AGENTPASS_POSTGRES_17_EVIDENCE_PATH, "AGENTPASS_POSTGRES_17_EVIDENCE_PATH", /^[^\0]+$/u));
  const output = path.resolve(required(env.AGENTPASS_POSTGRES_GATE_EVIDENCE_PATH, "AGENTPASS_POSTGRES_GATE_EVIDENCE_PATH", /^[^\0]+$/u));
  if (fs.existsSync(output)) throw new PostgresGateAggregationError("PostgreSQL gate evidence target already exists");
  const child16Text = fs.readFileSync(child16Path, "utf8");
  const child17Text = fs.readFileSync(child17Path, "utf8");
  const child16 = JSON.parse(child16Text); const child17 = JSON.parse(child17Text);
  const computedBundleDigest = bundleArtifactSha256(child16Text, child17Text);
  const expectedBundleDigest = required(env.AGENTPASS_POSTGRES_QUALIFICATION_BUNDLE_ARTIFACT_SHA256, "bundle_artifact_sha256", DIGEST);
  if (computedBundleDigest !== expectedBundleDigest) throw new PostgresGateAggregationError("PostgreSQL child bundle digest is mismatched");
  const report = aggregatePostgresGate({
    child16, child17,
    sourceCommit: required(env.AGENTPASS_POSTGRES_QUALIFICATION_SOURCE_COMMIT, "source_commit", SHA),
    sourceTree: required(env.AGENTPASS_POSTGRES_QUALIFICATION_SOURCE_TREE, "source_tree", SHA),
    releaseArtifactSha256: required(env.AGENTPASS_POSTGRES_QUALIFICATION_RELEASE_ARTIFACT_SHA256, "release_artifact_sha256", DIGEST),
    runId: required(env.AGENTPASS_POSTGRES_QUALIFICATION_RUN_ID, "run_id", RUN_ID),
    runAttempt: required(env.AGENTPASS_POSTGRES_QUALIFICATION_RUN_ATTEMPT, "run_attempt", RUN_ID),
    jobId: required(env.AGENTPASS_POSTGRES_QUALIFICATION_JOB_ID, "job_id", RUN_ID),
    bundleArtifactSha256: expectedBundleDigest,
    runnerId: required(env.AGENTPASS_POSTGRES_QUALIFICATION_RUNNER_ID, "runner_id", IDENTIFIER),
    environmentId: required(env.AGENTPASS_POSTGRES_QUALIFICATION_ENVIRONMENT_ID, "environment_id", IDENTIFIER),
    startedAt: child16.started_at < child17.started_at ? child16.started_at : child17.started_at,
    completedAt: child16.completed_at > child17.completed_at ? child16.completed_at : child17.completed_at
  });
  fs.mkdirSync(path.dirname(output), { recursive: true, mode: 0o700 });
  const fd = fs.openSync(output, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, `${canonicalJson(report)}\n`, "utf8"); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  process.stdout.write(`${canonicalJson({ status: report.status, qualified: report.qualified, artifact_sha256: report.execution.artifact_sha256 })}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  try { main(); } catch (error) { process.stderr.write(`PostgreSQL gate aggregation failed: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; }
}
