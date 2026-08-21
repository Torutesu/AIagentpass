#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import {
  STAGING_READINESS_MAX_TTL_MS,
  normalizeStagingBinding,
  normalizeStagingCandidate,
  normalizeStagingDeployment
} from "./staging-readiness.mjs";

export const STAGING_ROLLBACK_SCHEMA_VERSION = 1;
export const STAGING_ROLLBACK_KIND = "agentpass.staging-rollback";

const ROOT_KEYS = Object.freeze([
  "candidate", "completed_at", "current_deployment", "environment", "evidence_sha256", "expires_at", "issued_at", "kind", "qualified", "rollback", "schema_version", "service", "status"
]);
const ROLLBACK_KEYS = Object.freeze(["completed_at", "current_revision", "executed", "reused_artifact", "started_at", "status", "target", "target_ready", "tested", "traffic_restored"]);
const TARGET_KEYS = Object.freeze(["candidate", "deployment", "status", "target_ready"]);
const SHA = /^[0-9a-f]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const STATUS = new Set(["failed", "not_run", "passed"]);

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
  const binding = normalizeStagingBinding(expected);
  if (value.status !== "passed" || value.qualified !== true
    || !sameObject(value.candidate, binding.candidate)
    || !sameObject(value.current_deployment, binding.deployment)
    || !sameObject(value.rollback.target.candidate, binding.rollback_target.candidate)
    || !sameObject(value.rollback.target.deployment, binding.rollback_target.deployment)) {
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
  if (currentDeployment.environment !== input.environment || currentDeployment.service !== input.service) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_DEPLOYMENT_BINDING");
  const rollback = normalizeRollback(input.rollback, currentDeployment);
  if (rollback.completed_at !== input.completed_at) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_TIME");
  if (input.status !== rollback.status) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_STATUS");
  return { ...input, candidate, current_deployment: currentDeployment, rollback };
}

function normalizeRollback(value, currentDeployment) {
  exactObject(value, ROLLBACK_KEYS, "ERR_STAGING_ROLLBACK_INPUT");
  if (!STATUS.has(value.status) || !TIME.test(value.started_at) || !TIME.test(value.completed_at)
    || value.current_revision !== currentDeployment.revision || typeof value.executed !== "boolean"
    || typeof value.reused_artifact !== "boolean" || typeof value.target_ready !== "boolean"
    || typeof value.tested !== "boolean" || typeof value.traffic_restored !== "boolean"
    || Date.parse(value.completed_at) < Date.parse(value.started_at)) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_INPUT");
  const target = normalizeTarget(value.target, currentDeployment);
  if (target.deployment.revision === value.current_revision) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_TARGET");
  const derived = value.status === "not_run" ? value.executed === false && value.tested === false && value.target_ready === false
    && value.traffic_restored === false && value.reused_artifact === false ? "not_run" : "invalid"
    : value.executed === true && value.tested === true && value.reused_artifact === true && value.target_ready === true
      && value.traffic_restored === true && target.status === "passed" && target.target_ready === true ? "passed" : "failed";
  if (value.status !== derived) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_STATUS");
  return Object.freeze({ ...value, target });
}

function normalizeTarget(value, currentDeployment) {
  exactObject(value, TARGET_KEYS, "ERR_STAGING_ROLLBACK_TARGET");
  const candidate = normalizeStagingCandidate(value.candidate);
  const deployment = normalizeStagingDeployment(value.deployment);
  if (deployment.environment !== currentDeployment.environment || deployment.service !== currentDeployment.service
    || deployment.deployment_id !== currentDeployment.deployment_id || deployment.revision === currentDeployment.revision
    || !STATUS.has(value.status) || typeof value.target_ready !== "boolean") throw new StagingRollbackError("ERR_STAGING_ROLLBACK_TARGET");
  if (value.status === "passed" && value.target_ready !== true) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_TARGET");
  if (value.status !== "passed" && value.target_ready !== false) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_TARGET");
  return Object.freeze({ ...value, candidate, deployment });
}

function validateWindow(issuedAt, expiresAt, { now, allowExpired, allowFuture }) {
  if (!Number.isFinite(now)) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_TIME");
  const issued = Date.parse(issuedAt); const expires = Date.parse(expiresAt);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires <= issued || expires - issued > STAGING_READINESS_MAX_TTL_MS
    || (!allowFuture && now < issued) || (!allowExpired && now >= expires)) throw new StagingRollbackError("ERR_STAGING_ROLLBACK_TIME");
}

function sameObject(left, right) { return canonicalJson(left) === canonicalJson(right); }

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
