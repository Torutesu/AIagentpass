#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";

export const STAGING_READINESS_SCHEMA_VERSION = 1;
export const STAGING_READINESS_KIND = "agentpass.staging-readiness";
export const STAGING_READINESS_MAX_TTL_MS = 24 * 60 * 60 * 1_000;
export const STAGING_READINESS_CHECK_IDS = Object.freeze(["application", "database_schema", "audit_path", "console"]);
export const STAGING_CANDIDATE_KEYS = Object.freeze(["artifact_sha256", "candidate_id", "release_manifest_sha256", "source_commit", "source_tree"]);
export const STAGING_DEPLOYMENT_KEYS = Object.freeze(["deployment_digest", "deployment_id", "environment", "image_digest", "revision", "service"]);
export const STAGING_BINDING_KEYS = Object.freeze(["candidate", "deployment", "rollback_target"]);

const ROOT_KEYS = Object.freeze([
  "canary", "candidate", "deployment", "drain", "evidence_sha256", "environment", "expires_at", "issued_at", "kind", "qualified", "readiness", "rollback_target", "schema_version", "service", "status"
]);
const CHECK_KEYS = Object.freeze(["check_id", "expected", "observed", "status"]);
const READINESS_KEYS = Object.freeze(["checks", "configured", "ready", "status"]);
const CANARY_KEYS = Object.freeze(["completed_at", "error_count", "expected", "observed", "requests", "started_at", "status", "successful_requests", "traffic_percent"]);
const DRAIN_KEYS = Object.freeze(["completed_at", "drained", "from_revision", "in_flight_after", "in_flight_before", "new_work_stopped", "started_at", "status", "to_revision"]);
const TARGET_KEYS = Object.freeze(["candidate", "deployment", "status", "target_ready"]);
const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const CANDIDATE_ID = /^release-pkg-sha256-v1-[0-9a-f]{64}$/u;
const IMAGE = /^sha256:[0-9a-f]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const STATUS = new Set(["failed", "not_run", "passed"]);

export class StagingReadinessError extends Error {
  constructor(code) {
    super(code);
    this.name = "StagingReadinessError";
    this.code = code;
  }
}

export function normalizeStagingCandidate(value) {
  exactObject(value, STAGING_CANDIDATE_KEYS, "ERR_STAGING_READINESS_INPUT");
  if (!DIGEST.test(value.artifact_sha256) || !CANDIDATE_ID.test(value.candidate_id)
    || value.candidate_id !== `release-pkg-sha256-v1-${value.artifact_sha256}`
    || !DIGEST.test(value.release_manifest_sha256) || !SHA.test(value.source_commit) || !SHA.test(value.source_tree)) {
    throw new StagingReadinessError("ERR_STAGING_READINESS_CANDIDATE_BINDING");
  }
  return Object.freeze({ ...value });
}

export function normalizeStagingDeployment(value, { environment = "staging" } = {}) {
  exactObject(value, STAGING_DEPLOYMENT_KEYS, "ERR_STAGING_READINESS_INPUT");
  if (value.environment !== environment || value.environment !== "staging"
    || !DIGEST.test(value.deployment_digest) || !IDENTIFIER.test(value.deployment_id)
    || !IMAGE.test(value.image_digest) || !IDENTIFIER.test(value.revision) || !IDENTIFIER.test(value.service)) {
    throw new StagingReadinessError("ERR_STAGING_READINESS_DEPLOYMENT_BINDING");
  }
  return Object.freeze({ ...value });
}

export function normalizeStagingBinding(value) {
  exactObject(value, STAGING_BINDING_KEYS, "ERR_STAGING_READINESS_BINDING");
  const candidate = normalizeStagingCandidate(value.candidate);
  const deployment = normalizeStagingDeployment(value.deployment);
  const rollbackTarget = normalizeStagingTarget(value.rollback_target, deployment);
  return Object.freeze({ candidate, deployment, rollback_target: rollbackTarget });
}

export function normalizeStagingReadiness(input, { now = Date.now(), allowExpired = false, allowFuture = false } = {}) {
  const value = normalizeStagingReadinessShape(input);
  validateWindow(value.issued_at, value.expires_at, { now, allowExpired, allowFuture });
  if (!allowFuture && (Date.parse(value.canary.completed_at) > now || Date.parse(value.drain.completed_at) > now)) {
    throw new StagingReadinessError("ERR_STAGING_READINESS_TIME");
  }
  if (value.evidence_sha256 !== stagingReadinessSHA256(value, { skipNormalize: true })) {
    throw new StagingReadinessError("ERR_STAGING_READINESS_DIGEST");
  }
  return Object.freeze(value);
}

export function stagingReadinessSHA256(input, { skipNormalize = false } = {}) {
  const value = skipNormalize ? input : normalizeStagingReadinessShape(input);
  const { evidence_sha256: _ignored, ...payload } = value;
  return crypto.createHash("sha256").update(canonicalJson(payload), "utf8").digest("hex");
}

export function attachStagingReadinessDigest(input) {
  const value = normalizeStagingReadinessShape({ ...input, evidence_sha256: "0".repeat(64) });
  return Object.freeze({ ...value, evidence_sha256: stagingReadinessSHA256(value, { skipNormalize: true }) });
}

export function verifyStagingReadiness(input, { expected, now = Date.now() } = {}) {
  const value = normalizeStagingReadiness(input, { now });
  const binding = normalizeStagingBinding(expected);
  if (value.status !== "passed" || value.qualified !== true) throw new StagingReadinessError("ERR_STAGING_READINESS_NOT_QUALIFIED");
  if (value.environment !== "staging" || value.service !== binding.deployment.service
    || !sameObject(value.candidate, binding.candidate) || !sameObject(value.deployment, binding.deployment)
    || !sameObject(value.rollback_target.candidate, binding.rollback_target.candidate)
    || !sameObject(value.rollback_target.deployment, binding.rollback_target.deployment)) {
    throw new StagingReadinessError("ERR_STAGING_READINESS_BINDING");
  }
  return Object.freeze({
    schema_version: value.schema_version,
    kind: value.kind,
    status: value.status,
    qualified: value.qualified,
    environment: value.environment,
    service: value.service,
    candidate: value.candidate,
    deployment: value.deployment,
    rollback_target: value.rollback_target,
    issued_at: value.issued_at,
    expires_at: value.expires_at,
    evidence_sha256: stagingReadinessSHA256(value, { skipNormalize: true })
  });
}

function normalizeStagingReadinessShape(input) {
  exactObject(input, ROOT_KEYS, "ERR_STAGING_READINESS_INPUT");
  if (input.schema_version !== STAGING_READINESS_SCHEMA_VERSION || input.kind !== STAGING_READINESS_KIND
    || input.environment !== "staging" || !IDENTIFIER.test(input.service) || !STATUS.has(input.status)
    || input.qualified !== (input.status === "passed") || !DIGEST.test(input.evidence_sha256)
    || !TIME.test(input.issued_at) || !TIME.test(input.expires_at)) {
    throw new StagingReadinessError("ERR_STAGING_READINESS_INPUT");
  }
  const candidate = normalizeStagingCandidate(input.candidate);
  const deployment = normalizeStagingDeployment(input.deployment);
  if (deployment.service !== input.service || deployment.environment !== input.environment) throw new StagingReadinessError("ERR_STAGING_READINESS_DEPLOYMENT_BINDING");
  const readiness = normalizeReadiness(input.readiness);
  const canary = normalizeCanary(input.canary);
  const drain = normalizeDrain(input.drain, deployment.revision);
  const rollbackTarget = normalizeStagingTarget(input.rollback_target, deployment);
  const derivedStatus = [readiness.status, canary.status, drain.status, rollbackTarget.status].includes("failed") ? "failed"
    : [readiness.status, canary.status, drain.status, rollbackTarget.status].includes("not_run") ? "not_run" : "passed";
  if (input.status !== derivedStatus) throw new StagingReadinessError("ERR_STAGING_READINESS_STATUS");
  if (input.status === "passed" && (readiness.ready !== true || canary.status !== "passed" || drain.status !== "passed" || rollbackTarget.target_ready !== true)) {
    throw new StagingReadinessError("ERR_STAGING_READINESS_NOT_QUALIFIED");
  }
  return { ...input, candidate, deployment, readiness, canary, drain, rollback_target: rollbackTarget };
}

function normalizeReadiness(value) {
  exactObject(value, READINESS_KEYS, "ERR_STAGING_READINESS_INPUT");
  if (!STATUS.has(value.status) || typeof value.configured !== "boolean" || typeof value.ready !== "boolean" || !Array.isArray(value.checks)
    || value.checks.length !== STAGING_READINESS_CHECK_IDS.length) throw new StagingReadinessError("ERR_STAGING_READINESS_CHECKS");
  const checks = value.checks.map(normalizeCheck);
  if (checks.map((item) => item.check_id).sort().join(",") !== STAGING_READINESS_CHECK_IDS.slice().sort().join(",")) throw new StagingReadinessError("ERR_STAGING_READINESS_CHECKS");
  const derivedStatus = checks.some((item) => item.status === "failed") || value.configured === false || value.ready === false ? "failed"
    : checks.some((item) => item.status === "not_run") ? "not_run" : "passed";
  if (value.status !== derivedStatus || (value.status === "passed" && (value.configured !== true || value.ready !== true))) throw new StagingReadinessError("ERR_STAGING_READINESS_CHECKS");
  return Object.freeze({ ...value, checks: Object.freeze(checks) });
}

function normalizeCheck(value) {
  exactObject(value, CHECK_KEYS, "ERR_STAGING_READINESS_CHECK");
  if (!IDENTIFIER.test(value.check_id) || typeof value.expected !== "string" || typeof value.observed !== "string"
    || value.expected.length === 0 || value.expected.length > 128 || value.observed.length === 0 || value.observed.length > 128 || !STATUS.has(value.status)) {
    throw new StagingReadinessError("ERR_STAGING_READINESS_CHECK");
  }
  const derived = value.status === "not_run" ? value.expected === "not_run" && value.observed === "not_run" ? "not_run" : "invalid"
    : value.expected === "not_run" || value.observed === "not_run" ? "invalid" : value.expected === value.observed ? "passed" : "failed";
  if (value.status !== derived) throw new StagingReadinessError("ERR_STAGING_READINESS_CHECK");
  return Object.freeze({ ...value });
}

function normalizeCanary(value) {
  exactObject(value, CANARY_KEYS, "ERR_STAGING_READINESS_CANARY");
  if (!STATUS.has(value.status) || !TIME.test(value.started_at) || !TIME.test(value.completed_at)
    || !Number.isInteger(value.traffic_percent) || value.traffic_percent < 1 || value.traffic_percent > 50
    || !Number.isSafeInteger(value.requests) || value.requests < 0 || !Number.isSafeInteger(value.successful_requests) || value.successful_requests < 0
    || !Number.isSafeInteger(value.error_count) || value.error_count < 0 || value.successful_requests > value.requests || value.error_count > value.requests
    || typeof value.expected !== "string" || typeof value.observed !== "string" || value.expected.length === 0 || value.observed.length === 0
    || Date.parse(value.completed_at) < Date.parse(value.started_at)) throw new StagingReadinessError("ERR_STAGING_READINESS_CANARY");
  const derived = value.status === "not_run" ? value.expected === "not_run" && value.observed === "not_run" ? "not_run" : "invalid" : value.expected === "healthy" && value.observed === "healthy" && value.requests > 0
    && value.successful_requests === value.requests && value.error_count === 0 ? "passed" : "failed";
  if (value.status !== derived) throw new StagingReadinessError("ERR_STAGING_READINESS_CANARY");
  return Object.freeze({ ...value });
}

function normalizeDrain(value, currentRevision) {
  exactObject(value, DRAIN_KEYS, "ERR_STAGING_READINESS_DRAIN");
  if (!STATUS.has(value.status) || !TIME.test(value.started_at) || !TIME.test(value.completed_at)
    || !IDENTIFIER.test(value.from_revision) || !IDENTIFIER.test(value.to_revision) || value.to_revision !== currentRevision
    || typeof value.new_work_stopped !== "boolean" || typeof value.drained !== "boolean"
    || !Number.isSafeInteger(value.in_flight_before) || value.in_flight_before < 0 || !Number.isSafeInteger(value.in_flight_after) || value.in_flight_after < 0
    || value.in_flight_after > value.in_flight_before || Date.parse(value.completed_at) < Date.parse(value.started_at)) throw new StagingReadinessError("ERR_STAGING_READINESS_DRAIN");
  const derived = value.status === "not_run" ? "not_run" : value.from_revision !== value.to_revision && value.new_work_stopped === true
    && value.drained === true && value.in_flight_after === 0 ? "passed" : "failed";
  if (value.status !== derived) throw new StagingReadinessError("ERR_STAGING_READINESS_DRAIN");
  return Object.freeze({ ...value });
}

function normalizeStagingTarget(value, currentDeployment) {
  exactObject(value, TARGET_KEYS, "ERR_STAGING_READINESS_ROLLBACK_TARGET");
  const candidate = normalizeStagingCandidate(value.candidate);
  const deployment = normalizeStagingDeployment(value.deployment);
  if (deployment.environment !== currentDeployment.environment || deployment.service !== currentDeployment.service
    || deployment.deployment_id !== currentDeployment.deployment_id || deployment.revision === currentDeployment.revision) {
    throw new StagingReadinessError("ERR_STAGING_READINESS_ROLLBACK_TARGET");
  }
  if (!STATUS.has(value.status) || typeof value.target_ready !== "boolean") throw new StagingReadinessError("ERR_STAGING_READINESS_ROLLBACK_TARGET");
  if (value.status === "passed" && value.target_ready !== true) throw new StagingReadinessError("ERR_STAGING_READINESS_ROLLBACK_TARGET");
  if (value.status !== "passed" && value.target_ready !== false) throw new StagingReadinessError("ERR_STAGING_READINESS_ROLLBACK_TARGET");
  return Object.freeze({ ...value, candidate, deployment });
}

function validateWindow(issuedAt, expiresAt, { now, allowExpired, allowFuture }) {
  if (!Number.isFinite(now) || !TIME.test(issuedAt) || !TIME.test(expiresAt)) throw new StagingReadinessError("ERR_STAGING_READINESS_TIME");
  const issued = Date.parse(issuedAt); const expires = Date.parse(expiresAt);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires <= issued || expires - issued > STAGING_READINESS_MAX_TTL_MS
    || (!allowFuture && now < issued) || (!allowExpired && now >= expires)) throw new StagingReadinessError("ERR_STAGING_READINESS_TIME");
}

function sameObject(left, right) { return canonicalJson(left) === canonicalJson(right); }

function exactObject(value, keys, code) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new StagingReadinessError(code);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) throw new StagingReadinessError(code);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, "value")) throw new StagingReadinessError(code);
  }
}

function readCanonicalJson(filePath) {
  if (typeof filePath !== "string" || !filePath.startsWith("/") || filePath.length > 1_024) throw new StagingReadinessError("ERR_STAGING_READINESS_FILE");
  try {
    const fd = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    try {
      const stat = fs.fstatSync(fd, { bigint: true });
      if (!stat.isFile() || stat.nlink !== 1n || stat.size === 0n || stat.size > 512n * 1024n) throw new Error("unsafe file");
      const text = fs.readFileSync(fd, "utf8");
      const value = JSON.parse(text);
      if (text !== `${canonicalJson(value)}\n`) throw new Error("noncanonical JSON");
      return value;
    } finally { fs.closeSync(fd); }
  } catch { throw new StagingReadinessError("ERR_STAGING_READINESS_FILE"); }
}

if (process.argv[1] && new URL(`file://${process.argv[1]}`).pathname === new URL(import.meta.url).pathname) {
  const [command, evidencePath, bindingPath, nowOption] = process.argv.slice(2);
  if (command !== "verify" || !evidencePath || !bindingPath || (nowOption !== undefined && !nowOption.startsWith("--now=")) || process.argv.length > 6) {
    throw new Error("Usage: staging-readiness.mjs verify EVIDENCE.json BINDING.json [--now=YYYY-MM-DDTHH:mm:ss.sssZ]");
  }
  try {
    const result = verifyStagingReadiness(readCanonicalJson(evidencePath), { expected: readCanonicalJson(bindingPath), now: nowOption ? Date.parse(nowOption.slice(6)) : Date.now() });
    process.stdout.write(`${canonicalJson(result)}\n`);
  } catch (error) {
    process.stderr.write(`staging readiness failed: ${error instanceof Error ? error.code ?? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
