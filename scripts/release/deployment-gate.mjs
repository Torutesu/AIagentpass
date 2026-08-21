#!/usr/bin/env node

import fs from "node:fs";
import crypto from "node:crypto";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";

export const DEPLOYMENT_GATE_SCHEMA_VERSION = 1;
const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const JOB_ID = /^[A-Za-z0-9_-]{1,100}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/u;
const STATUS = new Set(["passed", "failed", "not_run"]);
const ENVIRONMENTS = new Set(["staging", "production"]);
const DEPLOYMENT_KEYS = Object.freeze([
  "artifact_sha256", "checks", "completed_at", "deployment_digest", "environment",
  "deployment_id", "job_id", "qualified", "release_manifest_sha256", "revision", "rollback", "run_attempt", "run_id",
  "image_digest", "schema_digest", "catalog_digest", "database_schema_digest", "schema_version", "service", "source_commit", "source_tree", "started_at", "status"
]);
const CHECK_KEYS = Object.freeze(["check_id", "expected", "observed", "status"]);
const ROLLBACK_KEYS = Object.freeze(["artifact_sha256", "completed_at", "current_revision", "deployment_digest", "deployment_id", "deployment_identity", "post_rollback_ready", "rollback_target_revision", "run_id", "status", "tested"]);
const BINDING_KEYS = Object.freeze(["artifactSha256", "catalogDigest", "databaseSchemaDigest", "deploymentDigest", "deploymentId", "environment", "imageDigest", "jobId", "releaseManifestSha256", "revision", "runAttempt", "runId", "schemaDigest", "service", "sourceCommit", "sourceTree"]);
const REQUIRED_CHECK_IDS = Object.freeze(["application_readiness", "traffic_drain", "combined_cutover", "console_readiness"]);
const MAX_ROLLBACK_AGE_MS = 24 * 60 * 60 * 1_000;

export function deploymentEvidenceSHA256(value) {
  return crypto.createHash("sha256").update(canonicalJson(normalizeDeploymentEvidence(value)), "utf8").digest("hex");
}

export function normalizeDeploymentEvidence(value) {
  exactObject(value, DEPLOYMENT_KEYS);
  if (value.schema_version !== DEPLOYMENT_GATE_SCHEMA_VERSION || !STATUS.has(value.status)
    || typeof value.qualified !== "boolean" || value.qualified !== (value.status === "passed")
    || !ENVIRONMENTS.has(value.environment) || typeof value.service !== "string" || typeof value.deployment_id !== "string" || typeof value.revision !== "string"
    || !IDENTIFIER.test(value.service) || !IDENTIFIER.test(value.deployment_id) || !IDENTIFIER.test(value.revision)
    || typeof value.source_commit !== "string" || typeof value.source_tree !== "string" || typeof value.artifact_sha256 !== "string"
    || typeof value.release_manifest_sha256 !== "string" || typeof value.deployment_digest !== "string"
    || typeof value.image_digest !== "string" || !/^sha256:[0-9a-f]{64}$/u.test(value.image_digest)
    || typeof value.database_schema_digest !== "string" || !DIGEST.test(value.database_schema_digest)
    || !SHA.test(value.source_commit) || !SHA.test(value.source_tree)
    || !DIGEST.test(value.artifact_sha256) || !DIGEST.test(value.release_manifest_sha256)
    || !DIGEST.test(value.deployment_digest) || typeof value.schema_digest !== "string" || !DIGEST.test(value.schema_digest) || typeof value.catalog_digest !== "string" || !DIGEST.test(value.catalog_digest)
    || typeof value.run_id !== "string" || !RUN_ID.test(value.run_id)
    || typeof value.run_attempt !== "string" || !RUN_ID.test(value.run_attempt) || typeof value.job_id !== "string" || !JOB_ID.test(value.job_id)
    || !isTimestamp(value.started_at) || !isTimestamp(value.completed_at)
    || !Array.isArray(value.checks) || value.checks.length === 0 || value.checks.length > 64) {
    throw new TypeError("deployment evidence is invalid");
  }
  const checks = value.checks.map(normalizeCheck);
  if (checks.length !== REQUIRED_CHECK_IDS.length || checks.map((item) => item.check_id).sort().join(",") !== REQUIRED_CHECK_IDS.slice().sort().join(",")) {
    throw new TypeError("deployment check inventory is invalid");
  }
  const rollback = normalizeRollback(value.rollback);
  if (rollback.artifact_sha256 !== value.artifact_sha256 || rollback.deployment_digest !== value.deployment_digest || rollback.run_id !== value.run_id
    || rollback.deployment_id !== value.deployment_id || rollback.current_revision !== value.revision) {
    throw new TypeError("rollback evidence binding is invalid");
  }
  // A rollback to the currently deployed revision is not a rollback test. It
  // can report healthy traffic while proving no recovery path at all, so the
  // promotion gate must reject it for every aggregate status.
  if (rollback.rollback_target_revision === value.revision) {
    throw new TypeError("rollback target revision must differ from current revision");
  }
  const completedAtMs = Date.parse(value.completed_at);
  const rollbackAtMs = Date.parse(rollback.completed_at);
  if (rollbackAtMs > completedAtMs || completedAtMs - rollbackAtMs > MAX_ROLLBACK_AGE_MS) throw new TypeError("rollback evidence is stale");
  const derivedStatus = checks.some((item) => item.status === "failed") || rollback.status === "failed" ? "failed"
    : checks.some((item) => item.status === "not_run") || rollback.status === "not_run" ? "not_run" : "passed";
  if (value.status !== derivedStatus) throw new TypeError("deployment aggregate status is invalid");
  if (value.status === "passed" && (checks.some((item) => item.status !== "passed") || rollback.status !== "passed" || rollback.tested !== true)) {
    throw new TypeError("deployment evidence is not qualified");
  }
  return Object.freeze({ ...value, checks: Object.freeze(checks), rollback });
}

export function verifyDeploymentEvidence(value, binding = {}) {
  const normalized = normalizeDeploymentEvidence(value);
  const expectedBinding = normalizeDeploymentBinding(binding);
  if (normalized.status !== "passed") throw new TypeError("deployment evidence is not passed");
  for (const [key, expected] of Object.entries({
    source_commit: expectedBinding.sourceCommit,
    source_tree: expectedBinding.sourceTree,
    artifact_sha256: expectedBinding.artifactSha256,
    release_manifest_sha256: expectedBinding.releaseManifestSha256,
    deployment_digest: expectedBinding.deploymentDigest,
    deployment_id: expectedBinding.deploymentId,
    environment: expectedBinding.environment,
    image_digest: expectedBinding.imageDigest,
    revision: expectedBinding.revision,
    schema_digest: expectedBinding.schemaDigest,
    catalog_digest: expectedBinding.catalogDigest,
    database_schema_digest: expectedBinding.databaseSchemaDigest,
    service: expectedBinding.service,
    run_id: expectedBinding.runId,
    run_attempt: expectedBinding.runAttempt,
    job_id: expectedBinding.jobId,
  })) {
    if (String(normalized[key]) !== String(expected)) throw new TypeError(`deployment binding mismatch: ${key}`);
  }
  return Object.freeze({
    schema_version: normalized.schema_version,
    environment: normalized.environment,
    service: normalized.service,
    status: normalized.status,
    qualified: normalized.qualified,
    source_commit: normalized.source_commit,
    source_tree: normalized.source_tree,
    artifact_sha256: normalized.artifact_sha256,
    release_manifest_sha256: normalized.release_manifest_sha256,
    deployment_digest: normalized.deployment_digest,
    image_digest: normalized.image_digest,
    schema_digest: normalized.schema_digest,
    catalog_digest: normalized.catalog_digest,
    database_schema_digest: normalized.database_schema_digest,
    run_id: normalized.run_id,
    run_attempt: normalized.run_attempt,
    job_id: normalized.job_id,
    evidence_sha256: deploymentEvidenceSHA256(normalized),
  });
}

function normalizeDeploymentBinding(value) {
  exactObject(value, BINDING_KEYS);
  if (typeof value.sourceCommit !== "string" || typeof value.sourceTree !== "string" || typeof value.artifactSha256 !== "string"
    || typeof value.releaseManifestSha256 !== "string" || typeof value.deploymentDigest !== "string"
    || typeof value.schemaDigest !== "string" || typeof value.catalogDigest !== "string" || typeof value.databaseSchemaDigest !== "string"
    || typeof value.deploymentId !== "string" || typeof value.revision !== "string" || typeof value.environment !== "string" || typeof value.service !== "string"
    || typeof value.imageDigest !== "string"
    || !SHA.test(value.sourceCommit) || !SHA.test(value.sourceTree) || !DIGEST.test(value.artifactSha256)
    || !DIGEST.test(value.releaseManifestSha256) || !DIGEST.test(value.deploymentDigest) || !DIGEST.test(value.schemaDigest) || !DIGEST.test(value.catalogDigest) || !DIGEST.test(value.databaseSchemaDigest)
    || !IDENTIFIER.test(value.deploymentId) || !IDENTIFIER.test(value.revision) || !IDENTIFIER.test(value.service) || !ENVIRONMENTS.has(value.environment)
    || !/^sha256:[0-9a-f]{64}$/u.test(value.imageDigest)
    || typeof value.runId !== "string" || typeof value.runAttempt !== "string" || typeof value.jobId !== "string"
    || !RUN_ID.test(value.runId) || !RUN_ID.test(value.runAttempt) || !JOB_ID.test(value.jobId)) {
    throw new TypeError("deployment binding is invalid");
  }
  return Object.freeze({ ...value });
}

function normalizeCheck(value) {
  exactObject(value, CHECK_KEYS);
  if (!IDENTIFIER.test(value.check_id) || typeof value.expected !== "string" || typeof value.observed !== "string"
    || value.expected.length === 0 || value.expected.length > 256 || value.observed.length === 0 || value.observed.length > 256
    || !STATUS.has(value.status)) throw new TypeError("deployment check is invalid");
  const derived = value.status === "not_run"
    ? value.expected === "not_run" && value.observed === "not_run" ? "not_run" : "invalid"
    : value.expected === "not_run" || value.observed === "not_run" ? "invalid" : value.expected === value.observed ? "passed" : "failed";
  if (value.status !== derived) {
    throw new TypeError("deployment check is invalid");
  }
  return Object.freeze({ ...value });
}

function normalizeRollback(value) {
  exactObject(value, ROLLBACK_KEYS);
  if (typeof value.artifact_sha256 !== "string" || typeof value.deployment_digest !== "string" || typeof value.run_id !== "string"
    || typeof value.deployment_id !== "string" || typeof value.current_revision !== "string" || typeof value.rollback_target_revision !== "string"
    || typeof value.completed_at !== "string" || !isTimestamp(value.completed_at) || typeof value.post_rollback_ready !== "boolean"
    || !DIGEST.test(value.artifact_sha256) || !DIGEST.test(value.deployment_digest)
    || !IDENTIFIER.test(value.deployment_id) || !IDENTIFIER.test(value.current_revision) || !IDENTIFIER.test(value.rollback_target_revision)
    || !RUN_ID.test(value.run_id) || !STATUS.has(value.status) || typeof value.tested !== "boolean"
    || (value.tested ? !["passed", "failed"].includes(value.status) : value.status !== "not_run")) throw new TypeError("rollback evidence is invalid");
  if (value.deployment_identity !== null && !validDeploymentIdentity(value.deployment_identity)) throw new TypeError("rollback deployment identity is invalid");
  if (value.status === "passed" && (value.deployment_identity === null || value.deployment_identity.deployment_id !== value.deployment_id || value.deployment_identity.revision !== value.rollback_target_revision)) throw new TypeError("rollback deployment identity does not prove the target revision");
  if (value.status === "passed" && value.post_rollback_ready !== true) throw new TypeError("rollback readiness is invalid");
  return Object.freeze({ ...value });
}

function validDeploymentIdentity(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = ["version", "configured", "ready", "source_commit", "source_tree", "image_digest", "deployment_id", "revision", "schema_digest", "catalog_digest", "database_schema_digest"];
  return Object.keys(value).sort().join(",") === keys.slice().sort().join(",")
    && value.version === 1 && value.configured === true && value.ready === true
    && SHA.test(value.source_commit) && SHA.test(value.source_tree)
    && /^sha256:[0-9a-f]{64}$/u.test(value.image_digest)
    && IDENTIFIER.test(value.deployment_id) && IDENTIFIER.test(value.revision)
    && DIGEST.test(value.schema_digest) && DIGEST.test(value.catalog_digest) && DIGEST.test(value.database_schema_digest);
}

function exactObject(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError("object is invalid");
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) throw new TypeError("object fields are invalid");
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, "value")) throw new TypeError("object property is not a data property");
  }
}

function isTimestamp(value) { return typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(value) && Number.isFinite(Date.parse(value)); }

if (process.argv[1] && new URL(`file://${process.argv[1]}`).pathname === new URL(import.meta.url).pathname) {
  const [evidencePath, bindingPath] = process.argv.slice(2);
  if (!evidencePath || !bindingPath || process.argv.length !== 4) throw new Error("Usage: deployment-gate.mjs EVIDENCE.json BINDING.json");
  const evidence = readJsonFile(evidencePath);
  const binding = readJsonFile(bindingPath);
  const result = verifyDeploymentEvidence(evidence, binding);
  process.stdout.write(`${canonicalJson(result)}\n`);
}

function readJsonFile(filePath) {
  try {
    if (typeof filePath !== "string" || filePath.length === 0 || filePath.length > 1_024) throw new Error("invalid path");
    const handle = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    try {
      const stat = fs.fstatSync(handle);
      if (!stat.isFile() || stat.size > 256 * 1024) throw new Error("invalid file");
      return JSON.parse(fs.readFileSync(handle, "utf8"));
    } finally { fs.closeSync(handle); }
  } catch { throw new Error("deployment evidence input is unavailable"); }
}
