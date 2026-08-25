#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import {
  STAGING_READINESS_MAX_TTL_MS,
  assertStagingDeploymentIdentity,
  normalizeStagingBinding,
  normalizeStagingCandidate,
  normalizeStagingDeployment
} from "./staging-readiness.mjs";

export const STAGING_ROLLBACK_SCHEMA_VERSION = 1;
export const STAGING_ROLLBACK_KIND = "agentpass.staging-rollback";
export const STAGING_RESILIENCE_EVENT_TYPES = Object.freeze(["failover", "pitr", "recovery", "rollback", "signer_outage"]);

const ROOT_KEYS = Object.freeze([
  "candidate", "completed_at", "current_deployment", "environment", "evidence_sha256", "expires_at", "issued_at", "kind", "qualified", "resilience", "rollback", "schema_version", "service", "status"
]);
const ROLLBACK_KEYS = Object.freeze(["completed_at", "current_revision", "deployment_identity", "executed", "executed_at", "execution_id", "reused_artifact", "started_at", "status", "target", "target_ready", "tested", "traffic_restored"]);
const TARGET_KEYS = Object.freeze(["candidate", "deployment", "status", "target_ready"]);
const RESILIENCE_KEYS = Object.freeze(["events"]);
const RESILIENCE_EVENT_KEYS = Object.freeze(["candidate", "completed_at", "deployment", "event_type", "execution_id", "measurements", "observer", "started_at", "status", "target"]);
const RESILIENCE_EXPECTED_KEYS = Object.freeze(["events"]);
const RESILIENCE_EXPECTED_EVENT_KEYS = Object.freeze(["event_type", "execution_id", "observer_id", "observer_key_fingerprint", "rpo_ms", "rto_ms", "slo_ms"]);
const MEASUREMENT_KEYS = Object.freeze(["rpo_ms", "rto_ms", "slo_ms"]);
const OBSERVER_KEYS = Object.freeze(["attestation", "kind", "observed_at", "observer_id", "observer_key_fingerprint", "public_key_pem", "signature"]);
const SHA = /^[0-9a-f]{64}$/u;
const FINGERPRINT = /^[0-9a-f]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const AMBIGUOUS_IDENTIFIERS = new Set(["local", "mock", "placeholder", "simulator", "synthetic", "unknown", "unspecified"]);
const PROTECTED_RUNNER = /^(?:protected|github-actions|macos|postgresql|cloud)[A-Za-z0-9._:/-]{2,127}$/u;
const NON_EXTERNAL_MARKER = /(?:local|mock|fixture|simulated|sandbox|self|internal|static|test)/iu;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const STATUS = new Set(["failed", "not_run", "passed"]);
const MAX_MEASUREMENT_MS = 24 * 60 * 60 * 1_000;
const ROLLBACK_BINDING_KEYS = Object.freeze(["candidate", "deployment", "resilience", "rollback_target"]);

export class StagingRollbackError extends Error {
  constructor(code) {
    super(code);
    this.name = "StagingRollbackError";
    this.code = code;
  }
}

export function normalizeStagingRollback(input, { now = Date.now(), allowExpired = false, allowFuture = false } = {}) {
  const value = normalizeStagingRollbackShape(input);
  validateWindow(value.issued_at, value.expires_at, { now, allowExpired, allowFuture });
  if (Date.parse(value.completed_at) > now && !allowFuture) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_TIME");
  const issuedAt = Date.parse(value.issued_at);
  for (const event of value.resilience.events) {
    if (!Number.isFinite(issuedAt) || Date.parse(event.started_at) < issuedAt
      || !allowFuture && (Date.parse(event.started_at) > now || Date.parse(event.completed_at) > now || Date.parse(event.observer.observed_at) > now)) {
      throw new StagingRollbackError("ERR_STAGING_ROLLBACK_TIME");
    }
    if (Date.parse(event.completed_at) > Date.parse(value.completed_at)) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_TIME");
  }
  if (value.evidence_sha256 !== stagingRollbackSHA256(value, { skipNormalize: true })) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_DIGEST");
  return Object.freeze(value);
}

export function stagingRollbackSHA256(input, { skipNormalize = false } = {}) {
  const value = skipNormalize ? input : normalizeStagingRollbackShape(input);
  const { evidence_sha256: _ignored, ...payload } = value;
  return crypto.createHash("sha256").update(canonicalJson(payload), "utf8").digest("hex");
}

export function attachStagingRollbackDigest(input) {
  const value = normalizeStagingRollbackShape({ ...input, evidence_sha256: "0".repeat(64) });
  return Object.freeze({ ...value, evidence_sha256: stagingRollbackSHA256(value, { skipNormalize: true }) });
}

export function verifyStagingRollback(input, { expected, now = Date.now() } = {}) {
  const value = normalizeStagingRollback(input, { now });
  const binding = normalizeStagingRollbackBinding(expected);
  if (value.status !== "passed" || value.qualified !== true
    || !sameObject(value.candidate, binding.candidate)
    || !sameObject(value.current_deployment, binding.deployment)
    || !sameObject(value.rollback.target.candidate, binding.rollback_target.candidate)
    || !sameObject(value.rollback.target.deployment, binding.rollback_target.deployment)
    || !sameObject(value.resilience, normalizeResilienceAgainstBinding(value.resilience, binding, value.candidate, value.current_deployment, value.rollback.target))) {
    throw new StagingRollbackError("ERR_STAGING_ROLLBACK_BINDING");
  }
  return Object.freeze({
    schema_version: value.schema_version,
    kind: value.kind,
    status: value.status,
    qualified: value.qualified,
    environment: value.environment,
    service: value.service,
    candidate: value.candidate,
    current_deployment: value.current_deployment,
    resilience: value.resilience,
    rollback: value.rollback,
    issued_at: value.issued_at,
    expires_at: value.expires_at,
    completed_at: value.completed_at,
    evidence_sha256: stagingRollbackSHA256(value, { skipNormalize: true })
  });
}

function normalizeStagingRollbackShape(input) {
  exactObject(input, ROOT_KEYS, "ERR_STAGING_ROLLBACK_INPUT");
  if (input.schema_version !== STAGING_ROLLBACK_SCHEMA_VERSION || input.kind !== STAGING_ROLLBACK_KIND
    || input.environment !== "staging" || !IDENTIFIER.test(input.service) || !STATUS.has(input.status)
    || input.qualified !== (input.status === "passed") || !SHA.test(input.evidence_sha256)
    || !TIME.test(input.issued_at) || !TIME.test(input.expires_at) || !TIME.test(input.completed_at)) {
    throw new StagingRollbackError("ERR_STAGING_ROLLBACK_INPUT");
  }
  const candidate = normalizeStagingCandidate(input.candidate);
  const currentDeployment = normalizeStagingDeployment(input.current_deployment);
  assertStagingDeploymentIdentity(currentDeployment, candidate, StagingRollbackError, "ERR_STAGING_ROLLBACK_DEPLOYMENT_IDENTITY");
  if (currentDeployment.environment !== input.environment || currentDeployment.service !== input.service
    || NON_EXTERNAL_MARKER.test(`${currentDeployment.deployment_id} ${currentDeployment.revision} ${currentDeployment.service}`)
    || !Number.isFinite(Date.parse(input.completed_at))) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_DEPLOYMENT_BINDING");
  const rollback = normalizeRollback(input.rollback, currentDeployment);
  const resilience = normalizeResilience(input.resilience, { candidate, deployment: currentDeployment, target: rollback.target, rollbackExecutionId: rollback.execution_id });
  if (rollback.completed_at !== input.completed_at) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_TIME");
  const derivedStatus = [rollback.status, resilience.events.some((event) => event.status === "failed") ? "failed" : resilience.events.some((event) => event.status === "not_run") ? "not_run" : "passed"].includes("failed") ? "failed"
    : [rollback.status, resilience.events.some((event) => event.status === "not_run") ? "not_run" : "passed"].includes("not_run") ? "not_run" : "passed";
  if (input.status !== derivedStatus) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_STATUS");
  return { ...input, candidate, current_deployment: currentDeployment, resilience, rollback };
}

export function normalizeStagingRollbackBinding(value) {
  exactObject(value, ROLLBACK_BINDING_KEYS, "ERR_STAGING_ROLLBACK_BINDING");
  const base = normalizeStagingBinding({ candidate: value.candidate, deployment: value.deployment, rollback_target: value.rollback_target });
  const resilience = normalizeExpectedResilience(value.resilience);
  return Object.freeze({ ...base, resilience });
}

function normalizeRollback(value, currentDeployment) {
  exactObject(value, ROLLBACK_KEYS, "ERR_STAGING_ROLLBACK_INPUT");
  if (!STATUS.has(value.status) || !TIME.test(value.started_at) || !TIME.test(value.completed_at)
    || value.current_revision !== currentDeployment.revision || typeof value.executed !== "boolean"
    || typeof value.execution_id !== "string" || !concreteIdentifier(value.execution_id) || !PROTECTED_RUNNER.test(value.execution_id) || NON_EXTERNAL_MARKER.test(value.execution_id) || !TIME.test(value.executed_at)
    || typeof value.reused_artifact !== "boolean" || typeof value.target_ready !== "boolean"
    || typeof value.tested !== "boolean" || typeof value.traffic_restored !== "boolean"
    || !Number.isFinite(Date.parse(value.started_at)) || !Number.isFinite(Date.parse(value.completed_at)) || !Number.isFinite(Date.parse(value.executed_at))
    || Date.parse(value.executed_at) < Date.parse(value.started_at) || Date.parse(value.executed_at) > Date.parse(value.completed_at)
    || Date.parse(value.completed_at) < Date.parse(value.started_at)) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_INPUT");
  const target = normalizeTarget(value.target, currentDeployment);
  if (target.deployment.revision === value.current_revision) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_TARGET");
  if (value.deployment_identity !== null && (!value.deployment_identity || typeof value.deployment_identity !== "object"
    || !sameObject(value.deployment_identity, target.deployment.deployment_identity))) {
    throw new StagingRollbackError("ERR_STAGING_ROLLBACK_IDENTITY");
  }
  if (value.status === "passed" && value.deployment_identity === null) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_IDENTITY");
  const executed = value.executed === true && value.execution_id !== "not_run";
  const derived = value.status === "not_run" ? value.executed === false && value.tested === false && value.target_ready === false
    && value.traffic_restored === false && value.reused_artifact === false && value.execution_id === "not_run" && value.executed_at === value.completed_at && value.deployment_identity === null ? "not_run" : "invalid"
    : executed && value.tested === true && value.reused_artifact === true && value.target_ready === true
      && value.traffic_restored === true && target.status === "passed" && target.target_ready === true && value.deployment_identity !== null ? "passed" : executed ? "failed" : "invalid";
  if (value.status !== derived) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_STATUS");
  return Object.freeze({ ...value, target });
}

function normalizeTarget(value, currentDeployment) {
  exactObject(value, TARGET_KEYS, "ERR_STAGING_ROLLBACK_TARGET");
  const candidate = normalizeStagingCandidate(value.candidate);
  const deployment = normalizeStagingDeployment(value.deployment);
  assertStagingDeploymentIdentity(deployment, candidate, StagingRollbackError, "ERR_STAGING_ROLLBACK_DEPLOYMENT_IDENTITY");
  if (deployment.environment !== currentDeployment.environment || deployment.service !== currentDeployment.service
    || deployment.deployment_id !== currentDeployment.deployment_id || deployment.revision === currentDeployment.revision
    || NON_EXTERNAL_MARKER.test(`${deployment.deployment_id} ${deployment.revision} ${deployment.service}`)
    || !STATUS.has(value.status) || typeof value.target_ready !== "boolean") throw new StagingRollbackError("ERR_STAGING_ROLLBACK_TARGET");
  if (value.status === "passed" && value.target_ready !== true) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_TARGET");
  if (value.status !== "passed" && value.target_ready !== false) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_TARGET");
  return Object.freeze({ ...value, candidate, deployment });
}

function normalizeResilience(value, { candidate, deployment, target, rollbackExecutionId }) {
  exactObject(value, RESILIENCE_KEYS, "ERR_STAGING_ROLLBACK_RESILIENCE");
  if (!Array.isArray(value.events) || value.events.length !== STAGING_RESILIENCE_EVENT_TYPES.length) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_RESILIENCE");
  const seen = new Set();
  const events = value.events.map((event) => {
    const normalized = normalizeResilienceEvent(event, { candidate, deployment, target, rollbackExecutionId });
    if (seen.has(normalized.event_type)) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_RESILIENCE");
    seen.add(normalized.event_type);
    return normalized;
  });
  if (seen.size !== STAGING_RESILIENCE_EVENT_TYPES.length || STAGING_RESILIENCE_EVENT_TYPES.some((type) => !seen.has(type))) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_RESILIENCE");
  return Object.freeze({ events: Object.freeze(events) });
}

function normalizeResilienceEvent(value, { candidate, deployment, target, rollbackExecutionId }) {
  exactObject(value, RESILIENCE_EVENT_KEYS, "ERR_STAGING_ROLLBACK_RESILIENCE_EVENT");
  if (!STAGING_RESILIENCE_EVENT_TYPES.includes(value.event_type) || !STATUS.has(value.status)
    || !TIME.test(value.started_at) || !TIME.test(value.completed_at) || !Number.isFinite(Date.parse(value.started_at)) || !Number.isFinite(Date.parse(value.completed_at)) || Date.parse(value.completed_at) < Date.parse(value.started_at)
    || !sameObject(value.candidate, candidate) || !sameObject(value.deployment, deployment) || !sameObject(value.target, target)) {
    throw new StagingRollbackError("ERR_STAGING_ROLLBACK_RESILIENCE_BINDING");
  }
  if (value.status !== "passed") throw new StagingRollbackError(value.status === "not_run" ? "ERR_STAGING_ROLLBACK_NOT_RUN" : "ERR_STAGING_ROLLBACK_RESILIENCE_NOT_PROVEN");
  if (!concreteIdentifier(value.execution_id) || !PROTECTED_RUNNER.test(value.execution_id) || NON_EXTERNAL_MARKER.test(value.execution_id)
    || (value.event_type === "rollback" && value.execution_id !== rollbackExecutionId)) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_EXECUTION");
  const measurements = normalizeMeasurements(value.measurements);
  const observer = normalizeObserver(value.observer);
  const observerTime = Date.parse(observer.observed_at);
  if (!Number.isFinite(observerTime) || observer.observer_id === value.execution_id || observerTime < Date.parse(value.started_at) || observerTime > Date.parse(value.completed_at)) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_OBSERVER");
  verifyObserverSignature(value, observer);
  return Object.freeze({ ...value, measurements, observer });
}

function normalizeMeasurements(value) {
  exactObject(value, MEASUREMENT_KEYS, "ERR_STAGING_ROLLBACK_MEASUREMENT");
  if (!Number.isSafeInteger(value.slo_ms) || value.slo_ms <= 0 || value.slo_ms > MAX_MEASUREMENT_MS
    || !Number.isSafeInteger(value.rpo_ms) || value.rpo_ms < 0 || value.rpo_ms > MAX_MEASUREMENT_MS
    || !Number.isSafeInteger(value.rto_ms) || value.rto_ms <= 0 || value.rto_ms > MAX_MEASUREMENT_MS) {
    throw new StagingRollbackError("ERR_STAGING_ROLLBACK_MEASUREMENT");
  }
  return Object.freeze({ ...value });
}

function normalizeObserver(value) {
  exactObject(value, OBSERVER_KEYS, "ERR_STAGING_ROLLBACK_OBSERVER");
  if (value.attestation !== "independent_external" || value.kind !== "protected_observer"
    || !TIME.test(value.observed_at) || !concreteIdentifier(value.observer_id) || !PROTECTED_RUNNER.test(value.observer_id)
    || !FINGERPRINT.test(value.observer_key_fingerprint) || typeof value.public_key_pem !== "string" || value.public_key_pem.length < 64 || value.public_key_pem.length > 4_096
    || typeof value.signature !== "string" || !/^[A-Za-z0-9_-]{86,1024}$/u.test(value.signature)) {
    throw new StagingRollbackError("ERR_STAGING_ROLLBACK_OBSERVER");
  }
  if (NON_EXTERNAL_MARKER.test(value.observer_id)) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_OBSERVER");
  return Object.freeze({ ...value });
}

function verifyObserverSignature(event, observer) {
  let publicKey;
  try { publicKey = crypto.createPublicKey(observer.public_key_pem); } catch { throw new StagingRollbackError("ERR_STAGING_ROLLBACK_OBSERVER_SIGNATURE"); }
  if (publicKey.asymmetricKeyType !== "ed25519") throw new StagingRollbackError("ERR_STAGING_ROLLBACK_OBSERVER_SIGNATURE");
  let der;
  try { der = publicKey.export({ type: "spki", format: "der" }); } catch { throw new StagingRollbackError("ERR_STAGING_ROLLBACK_OBSERVER_SIGNATURE"); }
  if (crypto.createHash("sha256").update(der).digest("hex") !== observer.observer_key_fingerprint) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_OBSERVER_SIGNATURE");
  let signature;
  try { signature = Buffer.from(observer.signature, "base64url"); } catch { throw new StagingRollbackError("ERR_STAGING_ROLLBACK_OBSERVER_SIGNATURE"); }
  const unsignedObserver = { ...observer };
  delete unsignedObserver.signature;
  const unsignedEvent = { ...event, observer: unsignedObserver };
  if (!crypto.verify(null, Buffer.from(canonicalJson(unsignedEvent), "utf8"), publicKey, signature)) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_OBSERVER_SIGNATURE");
}

function normalizeExpectedResilience(value) {
  exactObject(value, RESILIENCE_EXPECTED_KEYS, "ERR_STAGING_ROLLBACK_RESILIENCE");
  if (!Array.isArray(value.events) || value.events.length !== STAGING_RESILIENCE_EVENT_TYPES.length) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_RESILIENCE");
  const seen = new Set();
  const events = value.events.map((event) => {
    exactObject(event, RESILIENCE_EXPECTED_EVENT_KEYS, "ERR_STAGING_ROLLBACK_RESILIENCE");
    if (!STAGING_RESILIENCE_EVENT_TYPES.includes(event.event_type) || seen.has(event.event_type)
      || !concreteIdentifier(event.execution_id) || !PROTECTED_RUNNER.test(event.execution_id)
      || !concreteIdentifier(event.observer_id) || !PROTECTED_RUNNER.test(event.observer_id)
      || NON_EXTERNAL_MARKER.test(`${event.execution_id} ${event.observer_id}`)
      || !FINGERPRINT.test(event.observer_key_fingerprint)) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_RESILIENCE");
    normalizeMeasurements({ slo_ms: event.slo_ms, rpo_ms: event.rpo_ms, rto_ms: event.rto_ms });
    seen.add(event.event_type);
    return Object.freeze({ ...event });
  });
  if (seen.size !== STAGING_RESILIENCE_EVENT_TYPES.length) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_RESILIENCE");
  return Object.freeze({ events: Object.freeze(events) });
}

function normalizeResilienceAgainstBinding(value, binding, candidate, deployment, target) {
  const expectedByType = new Map(binding.resilience.events.map((event) => [event.event_type, event]));
  if (value.events.length !== expectedByType.size) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_RESILIENCE");
  for (const event of value.events) {
    const expected = expectedByType.get(event.event_type);
    if (!expected || event.execution_id !== expected.execution_id || event.observer.observer_id !== expected.observer_id
      || event.observer.observer_key_fingerprint !== expected.observer_key_fingerprint
      || !sameObject(event.candidate, candidate) || !sameObject(event.deployment, deployment) || !sameObject(event.target, target)
      || event.measurements.slo_ms > expected.slo_ms || event.measurements.rpo_ms > expected.rpo_ms || event.measurements.rto_ms > expected.rto_ms) {
      throw new StagingRollbackError("ERR_STAGING_ROLLBACK_RESILIENCE_BINDING");
    }
  }
  return value;
}

function validateWindow(issuedAt, expiresAt, { now, allowExpired, allowFuture }) {
  if (!Number.isFinite(now)) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_TIME");
  const issued = Date.parse(issuedAt); const expires = Date.parse(expiresAt);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires <= issued || expires - issued > STAGING_READINESS_MAX_TTL_MS
    || (!allowFuture && now < issued) || (!allowExpired && now >= expires)) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_TIME");
}

function sameObject(left, right) { return canonicalJson(left) === canonicalJson(right); }

function concreteIdentifier(value) {
  return typeof value === "string" && IDENTIFIER.test(value) && !AMBIGUOUS_IDENTIFIERS.has(value.toLowerCase()) && !NON_EXTERNAL_MARKER.test(value);
}

function exactObject(value, keys, code) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new StagingRollbackError(code);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) throw new StagingRollbackError(code);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, "value")) throw new StagingRollbackError(code);
  }
}

function readCanonicalJson(filePath) {
  if (typeof filePath !== "string" || !filePath.startsWith("/") || filePath.length > 1_024) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_FILE");
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
  } catch { throw new StagingRollbackError("ERR_STAGING_ROLLBACK_FILE"); }
}

if (process.argv[1] && new URL(`file://${process.argv[1]}`).pathname === new URL(import.meta.url).pathname) {
  const [command, evidencePath, bindingPath, nowOption] = process.argv.slice(2);
  if (command !== "verify" || !evidencePath || !bindingPath || (nowOption !== undefined && !nowOption.startsWith("--now=")) || process.argv.length > 6) {
    throw new Error("Usage: staging-rollback.mjs verify EVIDENCE.json BINDING.json [--now=YYYY-MM-DDTHH:mm:ss.sssZ]");
  }
  try {
    const result = verifyStagingRollback(readCanonicalJson(evidencePath), { expected: readCanonicalJson(bindingPath), now: nowOption ? Date.parse(nowOption.slice(6)) : Date.now() });
    process.stdout.write(`${canonicalJson(result)}\n`);
  } catch (error) {
    process.stderr.write(`staging rollback failed: ${error instanceof Error ? error.code ?? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
