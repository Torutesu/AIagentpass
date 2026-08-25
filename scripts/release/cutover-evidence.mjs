#!/usr/bin/env node

import fs from "node:fs";
import crypto from "node:crypto";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { normalizeDeploymentEvidence } from "./deployment-gate.mjs";

const METADATA_KEYS = Object.freeze([
  "artifact_sha256", "deployment_digest", "environment", "image_digest", "job_id",
  "deployment_id", "release_manifest_sha256", "revision", "rollback_target_revision", "run_attempt", "run_id", "service", "cutover_sha256", "rollback_sha256",
  "schema_digest", "catalog_digest", "database_schema_digest", "source_commit", "source_tree", "started_at", "completed_at"
]);
const CUTOVER_KEYS = Object.freeze(["schema", "ok", "command", "phase", "code"]);
const ROLLBACK_KEYS = Object.freeze(["schema", "ok", "command", "phase", "code"]);
const CONSOLE_READINESS_KEYS = Object.freeze(["configured", "ready", "status", "code", "deployment_identity"]);

/**
 * Projects the reviewed cutover CLI envelopes into the provider-neutral
 * deployment evidence contract. This function never treats a missing probe
 * as success and never infers rollback from a cutover result.
 */
export function projectCutoverDeploymentEvidence({ metadata, cutover, rollback = undefined, consoleReadiness = undefined } = {}) {
  exactObject(metadata, METADATA_KEYS);
  exactEnvelopeObject(cutover, CUTOVER_KEYS);
  assertCutoverEnvelope(cutover, "cutover");
  assertDataTree(cutover.result);
  if (!/^[0-9a-f]{64}$/u.test(metadata.cutover_sha256) || metadata.cutover_sha256 !== dataSHA256(cutover)) throw new TypeError("cutover evidence digest binding is invalid");
  if (rollback !== undefined) {
    exactEnvelopeObject(rollback, ROLLBACK_KEYS);
    assertCutoverEnvelope(rollback, "rollback");
    assertDataTree(rollback.result);
    if (!/^[0-9a-f]{64}$/u.test(metadata.rollback_sha256) || metadata.rollback_sha256 !== dataSHA256(rollback)) throw new TypeError("rollback evidence digest binding is invalid");
  } else if (metadata.rollback_sha256 !== "0".repeat(64)) {
    throw new TypeError("missing rollback digest binding is invalid");
  }
  if (consoleReadiness !== undefined) {
    exactObject(consoleReadiness, CONSOLE_READINESS_KEYS);
    if (typeof consoleReadiness.configured !== "boolean" || typeof consoleReadiness.ready !== "boolean"
      || typeof consoleReadiness.status !== "string" || typeof consoleReadiness.code !== "string"
      || consoleReadiness.status.length === 0 || consoleReadiness.code.length === 0 || !validIdentity(consoleReadiness.deployment_identity)) throw new TypeError("console readiness is invalid");
  }

  const readiness = cutover.result && typeof cutover.result === "object" && !Array.isArray(cutover.result)
    ? cutover.result.readiness
    : undefined;
  const drain = cutover.result && typeof cutover.result === "object" && !Array.isArray(cutover.result)
    ? cutover.result.drain
    : undefined;
  const cutoverReady = cutover.result && typeof cutover.result === "object" && !Array.isArray(cutover.result)
    ? cutover.result.ready
    : undefined;
  const rollbackExecuted = rollback?.result && typeof rollback.result === "object" && !Array.isArray(rollback.result)
    ? rollback.result.executed
    : undefined;
  const rollbackResult = rollback?.result && typeof rollback.result === "object" && !Array.isArray(rollback.result) ? rollback.result : undefined;
  const rollbackIdentityValid = rollbackResult !== undefined
    && rollbackResult.deployment_id === metadata.deployment_id
    && rollbackResult.current_revision === metadata.revision
    && rollbackResult.rollback_target_revision === metadata.rollback_target_revision
    && rollbackResult.deployment_identity?.deployment_id === metadata.deployment_id
    && rollbackResult.deployment_identity?.revision === metadata.rollback_target_revision
    && typeof rollbackResult.completed_at === "string"
    && Number.isFinite(Date.parse(rollbackResult.completed_at))
    && rollbackResult.post_rollback_ready === true
    && identityMatchesRollbackTarget(rollbackResult.deployment_identity, metadata);
  const applicationIdentity = readiness?.application?.deployment_identity;
  const applicationReady = readiness?.ready === true && identityMatchesMetadata(applicationIdentity, metadata);
  const consoleReady = consoleReadiness?.configured === true && consoleReadiness.ready === true
    && identityMatchesMetadata(consoleReadiness.deployment_identity, metadata);

  const checks = [
    booleanCheck("application_readiness", applicationReady, cutover.ok !== true ? "false" : readiness === undefined ? "not_run" : String(applicationReady)),
    booleanCheck("traffic_drain", drain?.ready === true, cutover.ok !== true ? "false" : drain === undefined ? "not_run" : String(drain?.ready === true)),
    booleanCheck("combined_cutover", cutoverReady === true, cutover.ok !== true ? "false" : cutoverReady === undefined ? "not_run" : String(cutoverReady)),
    booleanCheck("console_readiness", consoleReady, consoleReadiness === undefined ? "not_run" : String(consoleReady))
  ];
  const rollbackStatus = rollback === undefined
    ? "not_run"
    : rollbackExecuted === true && rollback.ok === true && rollbackIdentityValid ? "passed" : "failed";
  const status = checks.every((check) => check.status === "passed") && rollbackStatus === "passed" ? "passed" :
    checks.some((check) => check.status === "failed") || rollbackStatus === "failed" ? "failed" : "not_run";

  return normalizeDeploymentEvidence({
    schema_version: 1,
    artifact_sha256: metadata.artifact_sha256,
    checks,
    completed_at: metadata.completed_at,
    deployment_digest: metadata.deployment_digest,
    deployment_id: metadata.deployment_id,
    environment: metadata.environment,
    image_digest: metadata.image_digest,
    job_id: metadata.job_id,
    qualified: status === "passed",
    release_manifest_sha256: metadata.release_manifest_sha256,
    revision: metadata.revision,
    rollback: {
      artifact_sha256: metadata.artifact_sha256,
      completed_at: rollbackResult?.completed_at ?? metadata.completed_at,
      current_revision: metadata.revision,
      deployment_digest: metadata.deployment_digest,
      deployment_id: metadata.deployment_id,
      deployment_identity: rollbackResult?.deployment_identity ?? null,
      post_rollback_ready: rollbackStatus === "passed",
      rollback_target_revision: metadata.rollback_target_revision,
      run_id: metadata.run_id,
      status: rollbackStatus,
      tested: rollbackStatus !== "not_run"
    },
    run_attempt: metadata.run_attempt,
    run_id: metadata.run_id,
    schema_digest: metadata.schema_digest,
    catalog_digest: metadata.catalog_digest,
    database_schema_digest: metadata.database_schema_digest,
    service: metadata.service,
    source_commit: metadata.source_commit,
    source_tree: metadata.source_tree,
    started_at: metadata.started_at,
    status
  });
}

function booleanCheck(checkId, passed, observed) {
  return {
    check_id: checkId,
    expected: observed === "not_run" ? "not_run" : "true",
    observed,
    status: observed === "not_run" ? "not_run" : passed ? "passed" : "failed"
  };
}

function validIdentity(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = ["version", "configured", "ready", "source_commit", "source_tree", "image_digest", "deployment_id", "revision", "schema_digest", "catalog_digest", "database_schema_digest"];
  return Object.keys(value).sort().join(",") === keys.slice().sort().join(",")
    && value.version === 1 && value.configured === true && value.ready === true
    && /^[0-9a-f]{40}$/u.test(value.source_commit) && /^[0-9a-f]{40}$/u.test(value.source_tree)
    && /^sha256:[0-9a-f]{64}$/u.test(value.image_digest)
    && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value.deployment_id)
    && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value.revision)
    && /^[0-9a-f]{64}$/u.test(value.schema_digest) && /^[0-9a-f]{64}$/u.test(value.catalog_digest) && /^[0-9a-f]{64}$/u.test(value.database_schema_digest);
}

function identityMatchesMetadata(value, metadata) {
  return validIdentity(value)
    && value.source_commit === metadata.source_commit
    && value.source_tree === metadata.source_tree
    && value.image_digest === metadata.image_digest
    && value.deployment_id === metadata.deployment_id
    && value.revision === metadata.revision
    && value.schema_digest === metadata.schema_digest
    && value.catalog_digest === metadata.catalog_digest
    && value.database_schema_digest === metadata.database_schema_digest;
}

function identityMatchesRollbackTarget(value, metadata) {
  return validIdentity(value)
    && value.source_commit === metadata.source_commit
    && value.source_tree === metadata.source_tree
    && value.image_digest === metadata.image_digest
    && value.deployment_id === metadata.deployment_id
    && value.revision === metadata.rollback_target_revision
    && value.schema_digest === metadata.schema_digest
    && value.catalog_digest === metadata.catalog_digest
    && value.database_schema_digest === metadata.database_schema_digest;
}

function assertCutoverEnvelope(value, command) {
  if (value.schema !== "agentpass.cutover.v1" || value.command !== command
    || typeof value.ok !== "boolean" || typeof value.phase !== "string"
    || typeof value.code !== "string" || value.phase.length === 0 || value.code.length === 0) {
    throw new TypeError(`${command} envelope is invalid`);
  }
  if (value.ok && value.phase !== command) throw new TypeError(`${command} success phase is invalid`);
  if (value.ok && (value.code !== "OK" || value.result === undefined)) throw new TypeError(`${command} success envelope is incomplete`);
}

function exactEnvelopeObject(value, requiredKeys) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError("envelope is invalid");
  const actual = Reflect.ownKeys(value);
  if (actual.some((key) => typeof key !== "string" || (!requiredKeys.includes(key) && key !== "result"))
    || actual.length < requiredKeys.length || actual.length > requiredKeys.length + 1
    || requiredKeys.some((key) => !actual.includes(key))) throw new TypeError("envelope fields are invalid");
  for (const key of actual) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, "value")) throw new TypeError("envelope property is not a data property");
  }
}

function dataSHA256(value) {
  const hashable = value.result === undefined ? Object.fromEntries(Object.entries(value).filter(([key]) => key !== "result")) : value;
  return crypto.createHash("sha256").update(canonicalJson(hashable), "utf8").digest("hex");
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

function assertDataTree(value, seen = new Set(), depth = 0) {
  if (value === undefined || value === null || typeof value === "string" || typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value))) return;
  if (depth > 12 || (typeof value !== "object") || seen.has(value)) throw new TypeError("cutover result data tree is invalid");
  seen.add(value);
  if (!Array.isArray(value) && Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError("cutover result prototype is invalid");
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") throw new TypeError("cutover result key is invalid");
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, "value")) throw new TypeError("cutover result property is not a data property");
    assertDataTree(descriptor.value, seen, depth + 1);
  }
  seen.delete(value);
}

if (process.argv[1] && new URL(`file://${process.argv[1]}`).pathname === new URL(import.meta.url).pathname) {
  const [metadataPath, cutoverPath, rollbackPath, consoleReadinessPath] = process.argv.slice(2);
  if (!metadataPath || !cutoverPath || process.argv.length < 4 || process.argv.length > 6) throw new Error("Usage: cutover-evidence.mjs METADATA.json CUTOVER.json [ROLLBACK.json] [CONSOLE-READINESS.json]");
  const metadata = readJsonFile(metadataPath);
  const cutover = readJsonFile(cutoverPath);
  const rollback = rollbackPath === undefined ? undefined : readJsonFile(rollbackPath);
  const consoleReadiness = consoleReadinessPath === undefined ? undefined : readJsonFile(consoleReadinessPath);
  process.stdout.write(`${canonicalJson(projectCutoverDeploymentEvidence({ metadata, cutover, rollback, consoleReadiness }))}\n`);
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
  } catch { throw new Error("cutover evidence input is unavailable"); }
}
