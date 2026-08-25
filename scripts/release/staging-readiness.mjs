#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";

export const STAGING_READINESS_SCHEMA_VERSION = 1;
export const STAGING_READINESS_KIND = "agentpass.staging-readiness";
export const STAGING_READINESS_MAX_TTL_MS = 24 * 60 * 60 * 1_000;
export const STAGING_READINESS_CHECK_IDS = Object.freeze(["application", "database_schema", "audit_path", "console"]);
export const STAGING_OPERATION_IDS = Object.freeze(["canary", "drain", "failover", "pitr", "signer_outage", "recovery"]);
export const STAGING_CANDIDATE_KEYS = Object.freeze(["artifact_sha256", "candidate_id", "release_manifest_sha256", "source_commit", "source_tree"]);
export const STAGING_DEPLOYMENT_KEYS = Object.freeze(["catalog_digest", "database_schema_digest", "deployment_digest", "deployment_id", "deployment_identity", "environment", "image_digest", "revision", "schema_digest", "service"]);
export const STAGING_BINDING_KEYS = Object.freeze(["candidate", "deployment", "rollback_target"]);

const ROOT_KEYS = Object.freeze([
  "canary", "candidate", "deployment", "drain", "evidence_sha256", "environment", "expires_at", "failover", "issued_at", "kind", "pitr", "qualified", "readiness", "recovery", "rollback_target", "schema_version", "service", "signer_outage", "status"
]);
const CHECK_KEYS = Object.freeze(["check_id", "expected", "observed", "status"]);
const READINESS_KEYS = Object.freeze(["checks", "configured", "ready", "status"]);
const OPERATION_BINDING_KEYS = Object.freeze(["artifact_sha256", "candidate_id", "catalog_digest", "database_schema_digest", "deployment_digest", "image_digest", "rollback_target_sha256", "schema_digest", "source_commit", "source_tree"]);
const OPERATION_EXECUTION_KEYS = Object.freeze(["environment", "kind", "real_execution", "run_attempt", "run_id", "runner_id"]);
const OPERATION_MEASUREMENT_KEYS = Object.freeze(["rpo_ms", "rto_ms", "slo_ms"]);
const OPERATION_OBSERVER_KEYS = Object.freeze(["evidence_sha256", "independent", "observed_at", "observer_execution_id", "observer_id", "source"]);
const OPERATION_COMMON_KEYS = Object.freeze(["binding", "completed_at", "execution", "execution_id", "expected", "limits", "measurements", "observed", "observer", "started_at", "status"]);
const CANARY_KEYS = Object.freeze(["binding", "completed_at", "error_count", "execution", "execution_id", "expected", "limits", "measurements", "observed", "observer", "requests", "started_at", "status", "successful_requests", "traffic_percent"]);
const DRAIN_KEYS = Object.freeze(["binding", "completed_at", "drained", "execution", "execution_id", "expected", "from_revision", "in_flight_after", "in_flight_before", "limits", "measurements", "new_work_stopped", "observed", "observer", "started_at", "status", "to_revision"]);
const TARGET_KEYS = Object.freeze(["candidate", "deployment", "status", "target_ready"]);
const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const CANDIDATE_ID = /^release-pkg-sha256-v1-[0-9a-f]{64}$/u;
const IMAGE = /^sha256:[0-9a-f]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const POSITIVE_ID = /^[1-9][0-9]{0,19}$/u;
const AMBIGUOUS_IDENTIFIERS = new Set(["local", "mock", "placeholder", "simulator", "synthetic", "unknown", "unspecified", "not_proven", "not_run", "self_reported", "fixture", "fake", "unit", "static", "test"]);
const DISALLOWED_EXECUTION_IDENTITY = /(^|[._:/ -])(local|mock|placeholder|simulator|synthetic|unknown|unspecified|not[_ -]?proven|not[_ -]?run|self[_ -]?reported|fixture|fake|unit|static|test)($|[._:/ -])/iu;
const STAGING_DEPLOYMENT_IDENTITY_KEYS = Object.freeze([
  "artifact_sha256", "candidate_id", "catalog_digest", "configured", "database_schema_digest", "deployment_digest", "deployment_id",
  "environment", "image_digest", "ready", "release_manifest_sha256", "revision", "schema_digest", "service", "source_commit", "source_tree", "version"
]);
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

export function normalizeStagingDeployment(value, { environment = "staging", candidate = null } = {}) {
  exactObject(value, STAGING_DEPLOYMENT_KEYS, "ERR_STAGING_READINESS_INPUT");
  if (value.environment !== environment || value.environment !== "staging"
    || !DIGEST.test(value.deployment_digest) || !concreteIdentifier(value.deployment_id)
    || !IMAGE.test(value.image_digest) || !concreteIdentifier(value.revision) || !concreteIdentifier(value.service)
    || !DIGEST.test(value.schema_digest) || !DIGEST.test(value.catalog_digest) || !DIGEST.test(value.database_schema_digest)) {
    throw new StagingReadinessError("ERR_STAGING_READINESS_DEPLOYMENT_BINDING");
  }
  const identity = normalizeStagingDeploymentIdentity(value.deployment_identity);
  if (candidate) assertStagingDeploymentIdentity({ ...value, deployment_identity: identity }, candidate);
  return Object.freeze({ ...value, deployment_identity: identity });
}

export function normalizeStagingBinding(value) {
  exactObject(value, STAGING_BINDING_KEYS, "ERR_STAGING_READINESS_BINDING");
  const candidate = normalizeStagingCandidate(value.candidate);
  const deployment = normalizeStagingDeployment(value.deployment, { candidate });
  const rollbackTarget = normalizeStagingTarget(value.rollback_target, deployment);
  return Object.freeze({ candidate, deployment, rollback_target: rollbackTarget });
}

export function normalizeStagingReadiness(input, { now = Date.now(), allowExpired = false, allowFuture = false } = {}) {
  const value = normalizeStagingReadinessShape(input);
  validateWindow(value.issued_at, value.expires_at, { now, allowExpired, allowFuture });
  if (!allowFuture && STAGING_OPERATION_IDS.some((id) => Date.parse(value[id].completed_at) > now)) {
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

export function stagingOperationObserverSHA256(input) {
  if (!input || typeof input !== "object" || !input.observer || typeof input.observer !== "object") {
    throw new StagingReadinessError("ERR_STAGING_READINESS_OBSERVER");
  }
  const { evidence_sha256: _ignored, ...observer } = input.observer;
  const payload = { ...input, observer };
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
    canary: value.canary,
    drain: value.drain,
    failover: value.failover,
    pitr: value.pitr,
    signer_outage: value.signer_outage,
    recovery: value.recovery,
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
  const deployment = normalizeStagingDeployment(input.deployment, { candidate });
  if (deployment.service !== input.service || deployment.environment !== input.environment) throw new StagingReadinessError("ERR_STAGING_READINESS_DEPLOYMENT_BINDING");
  const readiness = normalizeReadiness(input.readiness);
  const rollbackTarget = normalizeStagingTarget(input.rollback_target, deployment);
  const operationContext = { candidate, deployment, rollbackTarget };
  const canary = normalizeCanary(input.canary, operationContext);
  const drain = normalizeDrain(input.drain, deployment.revision, operationContext);
  const failover = normalizeGenericOperation(input.failover, "failover", operationContext);
  const pitr = normalizeGenericOperation(input.pitr, "pitr", operationContext);
  const signerOutage = normalizeGenericOperation(input.signer_outage, "signer_outage", operationContext);
  const recovery = normalizeGenericOperation(input.recovery, "recovery", operationContext);
  const operations = [canary, drain, failover, pitr, signerOutage, recovery];
  const issued = Date.parse(input.issued_at); const expires = Date.parse(input.expires_at);
  if (!Number.isFinite(issued) || !Number.isFinite(expires)
    || operations.some((item) => Date.parse(item.started_at) < issued || Date.parse(item.completed_at) > expires)) {
    throw new StagingReadinessError("ERR_STAGING_READINESS_TIME");
  }
  const derivedStatus = [readiness.status, ...operations.map((item) => item.status), rollbackTarget.status].includes("failed") ? "failed"
    : [readiness.status, ...operations.map((item) => item.status), rollbackTarget.status].includes("not_run") ? "not_run" : "passed";
  if (input.status !== derivedStatus) throw new StagingReadinessError("ERR_STAGING_READINESS_STATUS");
  if (input.status === "passed" && (readiness.ready !== true || operations.some((item) => item.status !== "passed") || rollbackTarget.target_ready !== true)) {
    throw new StagingReadinessError("ERR_STAGING_READINESS_NOT_QUALIFIED");
  }
  return { ...input, candidate, deployment, readiness, canary, drain, failover, pitr, signer_outage: signerOutage, recovery, rollback_target: rollbackTarget };
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

function normalizeCanary(value, context) {
  exactObject(value, CANARY_KEYS, "ERR_STAGING_READINESS_CANARY");
  if (!STATUS.has(value.status) || !TIME.test(value.started_at) || !TIME.test(value.completed_at)
    || !Number.isInteger(value.traffic_percent) || value.traffic_percent < 1 || value.traffic_percent > 50
    || !Number.isSafeInteger(value.requests) || value.requests < 0 || !Number.isSafeInteger(value.successful_requests) || value.successful_requests < 0
    || !Number.isSafeInteger(value.error_count) || value.error_count < 0 || value.successful_requests > value.requests || value.error_count > value.requests
    || typeof value.expected !== "string" || typeof value.observed !== "string" || value.expected.length === 0 || value.observed.length === 0
    || Date.parse(value.completed_at) < Date.parse(value.started_at)) throw new StagingReadinessError("ERR_STAGING_READINESS_CANARY");
  const common = normalizeOperationCommon(value, "canary", context, "ERR_STAGING_READINESS_CANARY");
  const derived = value.status === "not_run" ? value.expected === "not_run" && value.observed === "not_run" ? "not_run" : "invalid" : value.expected === "healthy" && value.observed === "healthy" && value.requests > 0
    && value.successful_requests === value.requests && value.error_count === 0 ? "passed" : "failed";
  if (value.status !== derived) throw new StagingReadinessError("ERR_STAGING_READINESS_CANARY");
  return Object.freeze({ ...common });
}

function normalizeDrain(value, currentRevision, context) {
  exactObject(value, DRAIN_KEYS, "ERR_STAGING_READINESS_DRAIN");
  if (!STATUS.has(value.status) || !TIME.test(value.started_at) || !TIME.test(value.completed_at)
    || !IDENTIFIER.test(value.from_revision) || !IDENTIFIER.test(value.to_revision) || value.to_revision !== currentRevision
    || typeof value.new_work_stopped !== "boolean" || typeof value.drained !== "boolean"
    || !Number.isSafeInteger(value.in_flight_before) || value.in_flight_before < 0 || !Number.isSafeInteger(value.in_flight_after) || value.in_flight_after < 0
    || value.in_flight_after > value.in_flight_before || Date.parse(value.completed_at) < Date.parse(value.started_at)) throw new StagingReadinessError("ERR_STAGING_READINESS_DRAIN");
  const common = normalizeOperationCommon(value, "drain", context, "ERR_STAGING_READINESS_DRAIN");
  const derived = value.status === "not_run" ? "not_run" : value.from_revision !== value.to_revision && value.new_work_stopped === true
    && value.drained === true && value.in_flight_after === 0 ? "passed" : "failed";
  if (value.status !== derived) throw new StagingReadinessError("ERR_STAGING_READINESS_DRAIN");
  return Object.freeze({ ...common });
}

function normalizeGenericOperation(value, operationId, context) {
  exactObject(value, OPERATION_COMMON_KEYS, `ERR_STAGING_READINESS_${operationId.toUpperCase()}`);
  const common = normalizeOperationCommon(value, operationId, context, `ERR_STAGING_READINESS_${operationId.toUpperCase()}`);
  const expected = { failover: "available", pitr: "restored", signer_outage: "denied", recovery: "recovered" }[operationId];
  const derived = value.status === "not_run" ? value.expected === "not_run" && value.observed === "not_run" ? "not_run" : "invalid"
    : value.expected === expected && value.observed === expected ? "passed" : "failed";
  if (value.status !== derived) throw new StagingReadinessError(`ERR_STAGING_READINESS_${operationId.toUpperCase()}`);
  return Object.freeze({ ...common });
}

function normalizeOperationCommon(value, operationId, { candidate, deployment, rollbackTarget }, errorCode) {
  if (!STATUS.has(value.status) || typeof value.expected !== "string" || typeof value.observed !== "string"
    || value.expected.length === 0 || value.observed.length === 0 || !concreteIdentifier(value.execution_id)
    || DISALLOWED_EXECUTION_IDENTITY.test(value.execution_id)) {
    throw new StagingReadinessError(errorCode);
  }
  const operationExpected = { canary: "healthy", drain: "drained", failover: "available", pitr: "restored", signer_outage: "denied", recovery: "recovered" }[operationId];
  if (value.status !== "not_run" && value.expected !== operationExpected) throw new StagingReadinessError(errorCode);
  const binding = normalizeOperationBinding(value.binding, candidate, deployment, rollbackTarget, errorCode);
  const execution = normalizeOperationExecution(value.execution, value.execution_id, errorCode);
  const normalizedMeasurements = normalizeOperationMeasurements(value.measurements, value.limits, errorCode);
  const observer = normalizeOperationObserver(value.observer, value, execution, errorCode);
  const started = Date.parse(value.started_at); const completed = Date.parse(value.completed_at);
  if (!TIME.test(value.started_at) || !TIME.test(value.completed_at) || !Number.isFinite(started) || !Number.isFinite(completed) || completed < started
    || !Number.isFinite(Date.parse(observer.observed_at)) || Date.parse(observer.observed_at) < started || Date.parse(observer.observed_at) > completed) {
    throw new StagingReadinessError(errorCode);
  }
  if (value.status === "not_run" && (value.execution_id !== "not_run" || value.execution.real_execution !== false || value.observer.source !== "not_run")) {
    throw new StagingReadinessError(errorCode);
  }
  return { ...value, binding, execution, measurements: normalizedMeasurements.measurements, limits: normalizedMeasurements.limits, observer };
}

function normalizeOperationBinding(value, candidate, deployment, rollbackTarget, errorCode) {
  exactObject(value, OPERATION_BINDING_KEYS, errorCode);
  const expected = {
    artifact_sha256: candidate.artifact_sha256,
    candidate_id: candidate.candidate_id,
    catalog_digest: deployment.catalog_digest,
    database_schema_digest: deployment.database_schema_digest,
    deployment_digest: deployment.deployment_digest,
    image_digest: deployment.image_digest,
    rollback_target_sha256: crypto.createHash("sha256").update(canonicalJson(rollbackTarget), "utf8").digest("hex"),
    schema_digest: deployment.schema_digest,
    source_commit: candidate.source_commit,
    source_tree: candidate.source_tree
  };
  if (!sameObject(value, expected)) throw new StagingReadinessError(errorCode);
  return Object.freeze({ ...value });
}

function normalizeOperationExecution(value, executionId, errorCode) {
  exactObject(value, OPERATION_EXECUTION_KEYS, errorCode);
  if (value.environment !== "staging" || value.kind !== "protected_runner" || value.real_execution !== true
    || !POSITIVE_ID.test(value.run_id) || !POSITIVE_ID.test(value.run_attempt) || !concreteIdentifier(value.runner_id)
    || DISALLOWED_EXECUTION_IDENTITY.test(value.runner_id) || executionId === value.run_id || executionId === value.runner_id) {
    throw new StagingReadinessError(errorCode);
  }
  return Object.freeze({ ...value });
}

function normalizeOperationMeasurements(value, limits, errorCode) {
  exactObject(value, OPERATION_MEASUREMENT_KEYS, errorCode);
  exactObject(limits, OPERATION_MEASUREMENT_KEYS, errorCode);
  for (const key of OPERATION_MEASUREMENT_KEYS) {
    if (!Number.isSafeInteger(value[key]) || value[key] < 0 || !Number.isSafeInteger(limits[key]) || limits[key] < 0 || value[key] > limits[key]) {
      throw new StagingReadinessError(errorCode);
    }
  }
  return Object.freeze({ measurements: Object.freeze({ ...value }), limits: Object.freeze({ ...limits }) });
}

function normalizeOperationObserver(value, operation, execution, errorCode) {
  exactObject(value, OPERATION_OBSERVER_KEYS, errorCode);
  if (value.source !== "independent_observer" || value.independent !== true || !concreteIdentifier(value.observer_id)
    || !concreteIdentifier(value.observer_execution_id) || value.observer_id === execution.runner_id
    || value.observer_id === operation.execution_id || value.observer_execution_id === operation.execution_id
    || value.observer_execution_id === execution.run_id || value.observer_id === value.observer_execution_id
    || DISALLOWED_EXECUTION_IDENTITY.test(value.observer_id)
    || DISALLOWED_EXECUTION_IDENTITY.test(value.observer_execution_id) || !TIME.test(value.observed_at) || !DIGEST.test(value.evidence_sha256)
    || value.evidence_sha256 !== stagingOperationObserverSHA256(operation)) {
    throw new StagingReadinessError(errorCode);
  }
  return Object.freeze({ ...value });
}

function normalizeStagingTarget(value, currentDeployment) {
  exactObject(value, TARGET_KEYS, "ERR_STAGING_READINESS_ROLLBACK_TARGET");
  const candidate = normalizeStagingCandidate(value.candidate);
  const deployment = normalizeStagingDeployment(value.deployment, { candidate });
  if (deployment.environment !== currentDeployment.environment || deployment.service !== currentDeployment.service
    || deployment.deployment_id !== currentDeployment.deployment_id || deployment.revision === currentDeployment.revision) {
    throw new StagingReadinessError("ERR_STAGING_READINESS_ROLLBACK_TARGET");
  }
  if (!STATUS.has(value.status) || typeof value.target_ready !== "boolean") throw new StagingReadinessError("ERR_STAGING_READINESS_ROLLBACK_TARGET");
  if (value.status === "passed" && value.target_ready !== true) throw new StagingReadinessError("ERR_STAGING_READINESS_ROLLBACK_TARGET");
  if (value.status !== "passed" && value.target_ready !== false) throw new StagingReadinessError("ERR_STAGING_READINESS_ROLLBACK_TARGET");
  return Object.freeze({ ...value, candidate, deployment });
}

function normalizeStagingDeploymentIdentity(value) {
  exactObject(value, STAGING_DEPLOYMENT_IDENTITY_KEYS, "ERR_STAGING_READINESS_DEPLOYMENT_IDENTITY");
  if (value.version !== 1 || value.configured !== true || value.ready !== true
    || !DIGEST.test(value.artifact_sha256) || !CANDIDATE_ID.test(value.candidate_id)
    || value.candidate_id !== `release-pkg-sha256-v1-${value.artifact_sha256}` || !DIGEST.test(value.release_manifest_sha256)
    || !DIGEST.test(value.schema_digest) || !DIGEST.test(value.catalog_digest) || !DIGEST.test(value.database_schema_digest)
    || !DIGEST.test(value.deployment_digest) || !SHA.test(value.source_commit) || !SHA.test(value.source_tree) || value.environment !== "staging"
    || !IMAGE.test(value.image_digest) || !concreteIdentifier(value.deployment_id) || !concreteIdentifier(value.revision) || !concreteIdentifier(value.service)) {
    throw new StagingReadinessError("ERR_STAGING_READINESS_DEPLOYMENT_IDENTITY");
  }
  return Object.freeze({ ...value });
}

export function assertStagingDeploymentIdentity(deployment, candidate, ErrorClass = StagingReadinessError, errorCode = "ERR_STAGING_READINESS_DEPLOYMENT_IDENTITY") {
  const identity = normalizeStagingDeploymentIdentity(deployment.deployment_identity);
  if (identity.artifact_sha256 !== candidate.artifact_sha256 || identity.candidate_id !== candidate.candidate_id
    || identity.release_manifest_sha256 !== candidate.release_manifest_sha256 || identity.source_commit !== candidate.source_commit || identity.source_tree !== candidate.source_tree
    || identity.image_digest !== deployment.image_digest || identity.deployment_id !== deployment.deployment_id
    || identity.environment !== deployment.environment || identity.revision !== deployment.revision || identity.schema_digest !== deployment.schema_digest
    || identity.catalog_digest !== deployment.catalog_digest || identity.database_schema_digest !== deployment.database_schema_digest
    || identity.deployment_digest !== deployment.deployment_digest || identity.service !== deployment.service) {
    throw new ErrorClass(errorCode);
  }
}

function validateWindow(issuedAt, expiresAt, { now, allowExpired, allowFuture }) {
  if (!Number.isFinite(now) || !TIME.test(issuedAt) || !TIME.test(expiresAt)) throw new StagingReadinessError("ERR_STAGING_READINESS_TIME");
  const issued = Date.parse(issuedAt); const expires = Date.parse(expiresAt);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires <= issued || expires - issued > STAGING_READINESS_MAX_TTL_MS
    || (!allowFuture && now < issued) || (!allowExpired && now >= expires)) throw new StagingReadinessError("ERR_STAGING_READINESS_TIME");
}

function sameObject(left, right) { return canonicalJson(left) === canonicalJson(right); }

function concreteIdentifier(value) {
  return typeof value === "string" && IDENTIFIER.test(value) && !AMBIGUOUS_IDENTIFIERS.has(value.toLowerCase());
}

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
