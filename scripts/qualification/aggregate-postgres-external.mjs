#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { POSTGRES_SCHEMA_HEAD } from "../../apps/cloud-api/src/postgres/schema-head.mjs";
import { verifyPostgresExternalQualificationEvidence } from "./run-postgres-c3-external.mjs";

const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const JOB_NAME = /^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const DISALLOWED_IDENTITY = /(^|[._:/ -])(local|static|unit|mock|fixture|fake|simulator|emulator|test|macos-latest|unknown|unidentified|unspecified|placeholder|redacted|n\/a|none|null)($|[._:/ -])/iu;
const CONTROLLER_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const REQUIRED_CHECKS = Object.freeze([
  "postgresql_16_version",
  "postgresql_17_version",
  "migration_contract",
  "role_rls_boundary",
  "concurrency_rollback"
]);
const EXPECTED_SCHEMA_HEAD = POSTGRES_SCHEMA_HEAD.version;

export class PostgresGateAggregationError extends Error {
  constructor(message) { super(message); this.name = "PostgresGateAggregationError"; }
}

function required(value, name, pattern) {
  if (typeof value !== "string" || !pattern.test(value)) throw new PostgresGateAggregationError(`${name} is missing or invalid`);
  return value;
}

function digest(text) { return crypto.createHash("sha256").update(text, "utf8").digest("hex"); }

function backupEvidenceDigest(text, child, label) {
  if (typeof text !== "string" || !DIGEST.test(child.backup_pitr_evidence_sha256 ?? "")
    || digest(text) !== child.backup_pitr_evidence_sha256) {
    throw new PostgresGateAggregationError(`${label} backup/PITR evidence digest is mismatched`);
  }
  return child.backup_pitr_evidence_sha256;
}

function typed(value) { return { type: "string", value: String(value) }; }

function exactObject(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) {
    throw new PostgresGateAggregationError(`${label} has missing or unknown fields`);
  }
}

function childBindingDigest(child) {
  return digest(canonicalJson(child));
}

function controllerUnsigned(controller) {
  const { signature: _signature, ...unsigned } = controller;
  return unsigned;
}

export function postgresControllerSigningData(controller) {
  return Buffer.from(canonicalJson(controllerUnsigned(controller)), "utf8");
}

function verifyController(controller, expected, child16, child17) {
  exactObject(controller, [
    "artifact_sha256", "bundle_artifact_sha256", "child_evidence_sha256", "controller_id",
    "environment_id", "job_id", "kind", "release_artifact_sha256", "run_attempt", "run_id",
    "runner_id", "source_commit", "source_tree", "signature"
  ], "PostgreSQL aggregate controller binding");
  if (controller.kind !== "external_qualification_controller"
    || !CONTROLLER_ID.test(controller.controller_id) || DISALLOWED_IDENTITY.test(controller.controller_id)
    || !IDENTIFIER.test(controller.runner_id) || DISALLOWED_IDENTITY.test(controller.runner_id)
    || !IDENTIFIER.test(controller.environment_id) || DISALLOWED_IDENTITY.test(controller.environment_id)
    || !RUN_ID.test(controller.run_id) || !RUN_ID.test(controller.run_attempt) || !RUN_ID.test(controller.job_id)
    || controller.run_id !== expected.runId || controller.run_attempt !== expected.runAttempt || controller.job_id !== expected.jobId
    || controller.source_commit !== expected.sourceCommit || controller.source_tree !== expected.sourceTree
    || controller.release_artifact_sha256 !== expected.releaseArtifactSha256
    || controller.artifact_sha256 !== expected.bundleArtifactSha256
    || controller.bundle_artifact_sha256 !== expected.bundleArtifactSha256
    || controller.child_evidence_sha256?.postgres_16 !== childBindingDigest(child16)
    || controller.child_evidence_sha256?.postgres_17 !== childBindingDigest(child17)) {
    throw new PostgresGateAggregationError("PostgreSQL aggregate controller identity binding is invalid");
  }
  exactObject(controller.child_evidence_sha256, ["postgres_16", "postgres_17"], "PostgreSQL child evidence digest binding");
  for (const [name, value] of Object.entries(controller.child_evidence_sha256)) required(value, `${name}_child_evidence_sha256`, DIGEST);
  exactObject(controller.signature, ["algorithm", "public_key_der_base64url", "public_key_fingerprint", "value"], "PostgreSQL aggregate controller signature");
  if (controller.signature.algorithm !== "ed25519" || !FINGERPRINT.test(controller.signature.public_key_fingerprint)
    || !BASE64URL.test(controller.signature.public_key_der_base64url) || !BASE64URL.test(controller.signature.value)) {
    throw new PostgresGateAggregationError("PostgreSQL aggregate controller signature is invalid");
  }
  let publicKey;
  try {
    publicKey = crypto.createPublicKey({ key: Buffer.from(controller.signature.public_key_der_base64url, "base64url"), format: "der", type: "spki" });
  } catch { throw new PostgresGateAggregationError("PostgreSQL aggregate controller public key is invalid"); }
  if (publicKey.asymmetricKeyType !== "ed25519") throw new PostgresGateAggregationError("PostgreSQL aggregate controller key is not Ed25519");
  const der = publicKey.export({ type: "spki", format: "der" });
  const fingerprint = `SHA256:${crypto.createHash("sha256").update(der).digest("base64url")}`;
  if (fingerprint !== controller.signature.public_key_fingerprint
    || !crypto.verify(null, postgresControllerSigningData(controller), publicKey, Buffer.from(controller.signature.value, "base64url"))) {
    throw new PostgresGateAggregationError("PostgreSQL aggregate controller signature does not verify");
  }
  return Object.freeze(structuredClone(controller));
}

function validateChildBinding(child, major, { sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, ciRunId, ciRunAttempt }) {
  if (child.source_commit !== sourceCommit || child.source_tree !== sourceTree || child.artifact_sha256 !== releaseArtifactSha256
    || child.run_id !== runId || child.run_attempt !== runAttempt || child.ci_run_id !== ciRunId || child.ci_run_attempt !== ciRunAttempt
    || child.qualification_run_id !== runId || child.qualification_run_attempt !== runAttempt
    || child.qualification_job_id !== child.job_id || !RUN_ID.test(child.job_id)
    || child.postgres_major !== major || !child.execution || child.execution.kind !== "external_runner"
    || child.execution.real_execution !== true || !IDENTIFIER.test(child.execution.runner_id)
    || DISALLOWED_IDENTITY.test(child.execution.runner_id) || child.execution.environment?.kind !== "postgresql"
    || !IDENTIFIER.test(child.execution.environment.identity) || DISALLOWED_IDENTITY.test(child.execution.environment.identity)) {
    throw new PostgresGateAggregationError(`PostgreSQL ${major} child identity binding is invalid`);
  }
  return Object.freeze({
    job_id: child.job_id,
    runner_id: child.execution.runner_id,
    environment_id: child.execution.environment.identity
  });
}

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

export function aggregatePostgresGate({ child16, child17, backupPitr16Text, backupPitr17Text, sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, jobId, bundleArtifactSha256, runnerId, environmentId, startedAt, completedAt, ciRunId, ciRunAttempt, qualificationJobName, controller }) {
  required(sourceCommit, "source_commit", SHA); required(sourceTree, "source_tree", SHA); required(releaseArtifactSha256, "release_artifact_sha256", DIGEST); required(runId, "run_id", RUN_ID); required(runAttempt, "run_attempt", RUN_ID); required(jobId, "job_id", RUN_ID); required(bundleArtifactSha256, "bundle_artifact_sha256", DIGEST); required(runnerId, "runner_id", IDENTIFIER); required(environmentId, "environment_id", IDENTIFIER);
  if (DISALLOWED_IDENTITY.test(runnerId) || DISALLOWED_IDENTITY.test(environmentId)) throw new PostgresGateAggregationError("PostgreSQL aggregate runner or environment is not external");
  required(ciRunId, "ci_run_id", RUN_ID); required(ciRunAttempt, "ci_run_attempt", RUN_ID); required(qualificationJobName, "qualification_job_name", JOB_NAME);
  if (ciRunId === runId) throw new PostgresGateAggregationError("PostgreSQL canonical CI and qualification runs must be distinct");
  verifyPostgresExternalQualificationEvidence(child16, { source_commit: sourceCommit, source_tree: sourceTree, artifact_sha256: releaseArtifactSha256, run_id: runId, run_attempt: runAttempt, ci_run_id: ciRunId, ci_run_attempt: ciRunAttempt, qualification_run_id: runId, qualification_run_attempt: runAttempt, qualification_job_id: child16.job_id, job_id: child16.job_id, postgres_major: "16" });
  verifyPostgresExternalQualificationEvidence(child17, { source_commit: sourceCommit, source_tree: sourceTree, artifact_sha256: releaseArtifactSha256, run_id: runId, run_attempt: runAttempt, ci_run_id: ciRunId, ci_run_attempt: ciRunAttempt, qualification_run_id: runId, qualification_run_attempt: runAttempt, qualification_job_id: child17.job_id, job_id: child17.job_id, postgres_major: "17" });
  const child16Identity = validateChildBinding(child16, "16", { sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, ciRunId, ciRunAttempt });
  const child17Identity = validateChildBinding(child17, "17", { sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, ciRunId, ciRunAttempt });
  if (child16Identity.job_id === child17Identity.job_id || child16Identity.runner_id === child17Identity.runner_id
    || child16Identity.environment_id === child17Identity.environment_id
    || new Set([child16Identity.job_id, child17Identity.job_id]).has(jobId)
    || new Set([child16Identity.runner_id, child17Identity.runner_id]).has(runnerId)
    || new Set([child16Identity.environment_id, child17Identity.environment_id]).has(environmentId)) {
    throw new PostgresGateAggregationError("PostgreSQL child and aggregate identities are not distinct");
  }
  if (!TIMESTAMP.test(startedAt) || !TIMESTAMP.test(completedAt) || Date.parse(completedAt) < Date.parse(startedAt)) throw new PostgresGateAggregationError("PostgreSQL aggregate timestamps are invalid");
  const checks = [
    childCheck(child16, "postgresql_16_version", "16", "postgresql_version"),
    childCheck(child17, "postgresql_17_version", "17", "postgresql_version"),
    pairedCheck(child16, child17, "migration_contract", "migration_contract"),
    pairedCheck(child16, child17, "role_rls_boundary", "role_rls_boundary"),
    pairedCheck(child16, child17, "concurrency_rollback", "concurrency_rollback")
  ];
  const backupPitrEvidence = {
    postgres_16_sha256: backupEvidenceDigest(backupPitr16Text, child16, "PostgreSQL 16"),
    postgres_17_sha256: backupEvidenceDigest(backupPitr17Text, child17, "PostgreSQL 17"),
    bundle_sha256: digest(`${backupPitr16Text}${backupPitr17Text}`)
  };
  const passed = checks.every((item) => item.status === "passed");
  const qualificationBinding = {
    ci_run_id: ciRunId,
    ci_run_attempt: ciRunAttempt,
    qualification_run_id: runId,
    qualification_run_attempt: runAttempt,
    qualification_job_id: jobId,
    qualification_job_name: qualificationJobName
  };
  const readiness = Object.freeze({
    status: passed ? "ready" : "not_ready",
    migration_head: Math.min(child16.c3_schema_head, child17.c3_schema_head),
    catalog_constraints_validated: checks.find((item) => item.check_id === "migration_contract")?.status === "passed",
    role_boundary_verified: checks.find((item) => item.check_id === "role_rls_boundary")?.status === "passed"
  });
  const verifiedController = verifyController(controller, { sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, jobId, bundleArtifactSha256 }, child16, child17);
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
      release_artifact_sha256: releaseArtifactSha256,
      artifact_sha256: bundleArtifactSha256,
      ...qualificationBinding,
      started_at: startedAt,
      completed_at: completedAt,
      environment: Object.freeze({ kind: "postgresql", identity: environmentId })
    }),
    required_checks: REQUIRED_CHECKS,
    checks: Object.freeze(checks),
    backup_pitr_evidence: Object.freeze(backupPitrEvidence),
    readiness,
    controller: verifiedController
  });
}

export function verifyPostgresGateEvidence(report, { sourceCommit, sourceTree, releaseArtifactSha256, runId, runAttempt, jobId, ciRunId, ciRunAttempt, qualificationJobName, requireControllerBinding = false } = {}) {
  const baseKeys = ["status", "qualified", "reason", "execution", "required_checks", "checks", "backup_pitr_evidence", "readiness"];
  const hasController = report && typeof report === "object" && Object.prototype.hasOwnProperty.call(report, "controller");
  const expectedKeys = hasController || requireControllerBinding ? [...baseKeys, "controller"] : baseKeys;
  if (!report || typeof report !== "object" || Array.isArray(report)
    || JSON.stringify(Object.keys(report).sort()) !== JSON.stringify(expectedKeys.slice().sort())
    || report.status !== "passed" || report.qualified !== true || report.reason !== null
    || JSON.stringify(report.required_checks) !== JSON.stringify(REQUIRED_CHECKS)
    || !Array.isArray(report.checks) || report.checks.length !== REQUIRED_CHECKS.length
    || report.checks.some((item, index) => item?.check_id !== REQUIRED_CHECKS[index] || item.status !== "passed")
    || !report.readiness || JSON.stringify(Object.keys(report.readiness).sort()) !== JSON.stringify(["catalog_constraints_validated", "migration_head", "role_boundary_verified", "status"])
    || report.readiness.status !== "ready" || report.readiness.migration_head !== EXPECTED_SCHEMA_HEAD
    || report.readiness.catalog_constraints_validated !== true || report.readiness.role_boundary_verified !== true) {
    throw new PostgresGateAggregationError("PostgreSQL aggregate readiness or required checks are invalid");
  }
  const execution = report.execution;
  const executionKeys = ["artifact_sha256", "ci_run_attempt", "ci_run_id", "completed_at", "environment", "job_id", "kind", "qualification_job_id", "qualification_job_name", "qualification_run_attempt", "qualification_run_id", "real_execution", "release_artifact_sha256", "run_attempt", "run_id", "runner_id", "source_commit", "source_tree", "started_at"];
  if (ciRunId === runId || !execution || JSON.stringify(Object.keys(execution).sort()) !== JSON.stringify(executionKeys.slice().sort())
    || execution.kind !== "external_runner" || execution.real_execution !== true
    || execution.source_commit !== sourceCommit || execution.source_tree !== sourceTree
    || (releaseArtifactSha256 !== undefined && execution.release_artifact_sha256 !== releaseArtifactSha256)
    || !DIGEST.test(execution.release_artifact_sha256) || execution.run_id !== runId
    || execution.run_attempt !== runAttempt || execution.job_id !== jobId
    || execution.ci_run_id !== ciRunId || execution.ci_run_attempt !== ciRunAttempt
    || execution.qualification_run_id !== runId || execution.qualification_run_attempt !== runAttempt
    || execution.qualification_job_id !== jobId || execution.qualification_job_name !== qualificationJobName
    || !DIGEST.test(execution.artifact_sha256)
    || typeof execution.runner_id !== "string" || !IDENTIFIER.test(execution.runner_id) || DISALLOWED_IDENTITY.test(execution.runner_id)
    || !execution.environment || JSON.stringify(Object.keys(execution.environment).sort()) !== JSON.stringify(["identity", "kind"])
    || execution.environment.kind !== "postgresql" || typeof execution.environment.identity !== "string"
    || !IDENTIFIER.test(execution.environment.identity) || DISALLOWED_IDENTITY.test(execution.environment.identity)
    || !TIMESTAMP.test(execution.started_at) || !TIMESTAMP.test(execution.completed_at)
    || Date.parse(execution.completed_at) < Date.parse(execution.started_at)) {
    throw new PostgresGateAggregationError("PostgreSQL aggregate execution binding is invalid");
  }
  let controllerId;
  if (hasController || requireControllerBinding) {
    const controller = report.controller;
    exactObject(controller, [
      "artifact_sha256", "bundle_artifact_sha256", "child_evidence_sha256", "controller_id",
      "environment_id", "job_id", "kind", "release_artifact_sha256", "run_attempt", "run_id",
      "runner_id", "source_commit", "source_tree", "signature"
    ], "PostgreSQL aggregate controller binding");
    if (controller.kind !== "external_qualification_controller"
      || !CONTROLLER_ID.test(controller.controller_id) || DISALLOWED_IDENTITY.test(controller.controller_id)
      || !IDENTIFIER.test(controller.runner_id) || DISALLOWED_IDENTITY.test(controller.runner_id)
      || !IDENTIFIER.test(controller.environment_id) || DISALLOWED_IDENTITY.test(controller.environment_id)
      || controller.source_commit !== sourceCommit || controller.source_tree !== sourceTree || controller.release_artifact_sha256 !== releaseArtifactSha256
      || controller.run_id !== runId || controller.run_attempt !== runAttempt || controller.job_id !== jobId
      || controller.artifact_sha256 !== execution.artifact_sha256 || controller.bundle_artifact_sha256 !== execution.artifact_sha256) {
      throw new PostgresGateAggregationError("PostgreSQL aggregate controller binding is mismatched");
    }
    exactObject(controller.signature, ["algorithm", "public_key_der_base64url", "public_key_fingerprint", "value"], "PostgreSQL aggregate controller signature");
    if (controller.signature.algorithm !== "ed25519" || !FINGERPRINT.test(controller.signature.public_key_fingerprint)
      || !BASE64URL.test(controller.signature.public_key_der_base64url) || !BASE64URL.test(controller.signature.value)) {
      throw new PostgresGateAggregationError("PostgreSQL aggregate controller signature is invalid");
    }
    if (!crypto.verify) throw new PostgresGateAggregationError("PostgreSQL aggregate signature verifier is unavailable");
    try {
      const publicKey = crypto.createPublicKey({ key: Buffer.from(controller.signature.public_key_der_base64url, "base64url"), format: "der", type: "spki" });
      if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("key type");
      const der = publicKey.export({ type: "spki", format: "der" });
      const fingerprint = `SHA256:${crypto.createHash("sha256").update(der).digest("base64url")}`;
      if (fingerprint !== controller.signature.public_key_fingerprint
        || !crypto.verify(null, postgresControllerSigningData(controller), publicKey, Buffer.from(controller.signature.value, "base64url"))) throw new Error("invalid");
    } catch { throw new PostgresGateAggregationError("PostgreSQL aggregate controller signature is invalid"); }
    controllerId = controller.controller_id;
  }
  return Object.freeze({ status: "passed", source_commit: sourceCommit, source_tree: sourceTree, release_artifact_sha256: releaseArtifactSha256, run_id: runId, run_attempt: runAttempt, job_id: jobId, ci_run_id: ciRunId, ci_run_attempt: ciRunAttempt, ...(controllerId ? { controller_id: controllerId } : {}) });
}

export function bundleArtifactSha256(child16Text, child17Text) {
  if (typeof child16Text !== "string" || typeof child17Text !== "string") throw new PostgresGateAggregationError("PostgreSQL child evidence must be text");
  return digest(`${child16Text}${child17Text}`);
}

function main(env = process.env) {
  const child16Path = path.resolve(required(env.AGENTPASS_POSTGRES_16_EVIDENCE_PATH, "AGENTPASS_POSTGRES_16_EVIDENCE_PATH", /^[^\0]+$/u));
  const child17Path = path.resolve(required(env.AGENTPASS_POSTGRES_17_EVIDENCE_PATH, "AGENTPASS_POSTGRES_17_EVIDENCE_PATH", /^[^\0]+$/u));
  const backupPitr16Path = path.resolve(required(env.AGENTPASS_POSTGRES_16_BACKUP_PITR_EVIDENCE_PATH, "AGENTPASS_POSTGRES_16_BACKUP_PITR_EVIDENCE_PATH", /^[^\0]+$/u));
  const backupPitr17Path = path.resolve(required(env.AGENTPASS_POSTGRES_17_BACKUP_PITR_EVIDENCE_PATH, "AGENTPASS_POSTGRES_17_BACKUP_PITR_EVIDENCE_PATH", /^[^\0]+$/u));
  const output = path.resolve(required(env.AGENTPASS_POSTGRES_GATE_EVIDENCE_PATH, "AGENTPASS_POSTGRES_GATE_EVIDENCE_PATH", /^[^\0]+$/u));
  if (fs.existsSync(output)) throw new PostgresGateAggregationError("PostgreSQL gate evidence target already exists");
  const child16Text = fs.readFileSync(child16Path, "utf8");
  const child17Text = fs.readFileSync(child17Path, "utf8");
  const backupPitr16Text = fs.readFileSync(backupPitr16Path, "utf8");
  const backupPitr17Text = fs.readFileSync(backupPitr17Path, "utf8");
  const child16 = JSON.parse(child16Text); const child17 = JSON.parse(child17Text);
  const computedBundleDigest = bundleArtifactSha256(child16Text, child17Text);
  const expectedBundleDigest = required(env.AGENTPASS_POSTGRES_QUALIFICATION_BUNDLE_ARTIFACT_SHA256, "bundle_artifact_sha256", DIGEST);
  if (computedBundleDigest !== expectedBundleDigest) throw new PostgresGateAggregationError("PostgreSQL child bundle digest is mismatched");
  const report = aggregatePostgresGate({
    child16, child17, backupPitr16Text, backupPitr17Text,
    sourceCommit: required(env.AGENTPASS_POSTGRES_QUALIFICATION_SOURCE_COMMIT, "source_commit", SHA),
    sourceTree: required(env.AGENTPASS_POSTGRES_QUALIFICATION_SOURCE_TREE, "source_tree", SHA),
    releaseArtifactSha256: required(env.AGENTPASS_POSTGRES_QUALIFICATION_RELEASE_ARTIFACT_SHA256, "release_artifact_sha256", DIGEST),
    runId: required(env.AGENTPASS_POSTGRES_QUALIFICATION_RUN_ID, "run_id", RUN_ID),
    runAttempt: required(env.AGENTPASS_POSTGRES_QUALIFICATION_RUN_ATTEMPT, "run_attempt", RUN_ID),
    jobId: required(env.AGENTPASS_POSTGRES_QUALIFICATION_JOB_ID, "job_id", RUN_ID),
    bundleArtifactSha256: expectedBundleDigest,
    ciRunId: required(env.AGENTPASS_POSTGRES_QUALIFICATION_CI_RUN_ID, "ci_run_id", RUN_ID),
    ciRunAttempt: required(env.AGENTPASS_POSTGRES_QUALIFICATION_CI_RUN_ATTEMPT, "ci_run_attempt", RUN_ID),
    qualificationJobName: required(env.GITHUB_JOB, "qualification_job_name", JOB_NAME),
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
