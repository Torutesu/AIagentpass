import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import {
  attachStagingReadinessDigest,
  normalizeStagingReadiness,
  stagingOperationObserverSHA256,
  stagingReadinessSHA256,
  verifyStagingReadiness
} from "./staging-readiness.mjs";

const now = Date.parse("2026-08-20T00:30:00.000Z");
const candidate = (suffix) => ({
  artifact_sha256: suffix.repeat(64),
  candidate_id: `release-pkg-sha256-v1-${suffix.repeat(64)}`,
  release_manifest_sha256: (suffix === "c" ? "d" : "e").repeat(64),
  source_commit: (suffix === "c" ? "a" : "f").repeat(40),
  source_tree: (suffix === "c" ? "b" : "0").repeat(40)
});
const deployment = (revision, suffix, environment = "staging") => ({
  catalog_digest: (suffix === "e" ? "7" : "8").repeat(64),
  database_schema_digest: (suffix === "e" ? "9" : "a").repeat(64),
  deployment_digest: suffix.repeat(64), deployment_id: "staging-api", environment,
  image_digest: `sha256:${(suffix === "e" ? "1" : "2").repeat(64)}`,
  revision,
  schema_digest: (suffix === "e" ? "5" : "6").repeat(64),
  service: "agentpass-cloud-api",
  deployment_identity: {
    artifact_sha256: (suffix === "e" ? "c" : "f").repeat(64),
    candidate_id: `release-pkg-sha256-v1-${(suffix === "e" ? "c" : "f").repeat(64)}`,
    catalog_digest: (suffix === "e" ? "7" : "8").repeat(64), configured: true,
    database_schema_digest: (suffix === "e" ? "9" : "a").repeat(64), deployment_id: "staging-api",
    deployment_digest: suffix.repeat(64), environment,
    image_digest: `sha256:${(suffix === "e" ? "1" : "2").repeat(64)}`, ready: true,
    release_manifest_sha256: (suffix === "e" ? "d" : "e").repeat(64), revision,
    schema_digest: (suffix === "e" ? "5" : "6").repeat(64), service: "agentpass-cloud-api",
    source_commit: (suffix === "e" ? "a" : "f").repeat(40), source_tree: (suffix === "e" ? "b" : "0").repeat(40), version: 1
  }
});

const binding = () => ({
  candidate: candidate("c"),
  deployment: deployment("current-revision", "e"),
  rollback_target: { candidate: candidate("f"), deployment: deployment("previous-revision", "2"), status: "passed", target_ready: true }
});

const operationBinding = () => {
  const expected = binding();
  return {
    artifact_sha256: expected.candidate.artifact_sha256,
    candidate_id: expected.candidate.candidate_id,
    catalog_digest: expected.deployment.catalog_digest,
    database_schema_digest: expected.deployment.database_schema_digest,
    deployment_digest: expected.deployment.deployment_digest,
    image_digest: expected.deployment.image_digest,
    rollback_target_sha256: crypto.createHash("sha256").update(canonicalJson(expected.rollback_target), "utf8").digest("hex"),
    schema_digest: expected.deployment.schema_digest,
    source_commit: expected.candidate.source_commit,
    source_tree: expected.candidate.source_tree
  };
};

const operation = (executionId, expected, observed = expected, { startedAt = "2026-08-20T00:16:00.000Z", completedAt = "2026-08-20T00:20:00.000Z", observedAt = "2026-08-20T00:19:00.000Z" } = {}) => {
  const value = {
    binding: operationBinding(), completed_at: completedAt,
    execution: { environment: "staging", kind: "protected_runner", real_execution: true, run_attempt: "1", run_id: "1001", runner_id: "protected-staging-runner-1" },
    execution_id: executionId, expected, limits: { rpo_ms: 1_000, rto_ms: 1_000, slo_ms: 1_000 },
    measurements: { rpo_ms: 100, rto_ms: 200, slo_ms: 300 }, observed,
    observer: { evidence_sha256: "0".repeat(64), independent: true, observed_at: observedAt, observer_execution_id: `observer-execution-${executionId}`, observer_id: `independent-${executionId}`, source: "independent_observer" },
    started_at: startedAt, status: "passed"
  };
  value.observer.evidence_sha256 = stagingOperationObserverSHA256(value);
  return value;
};

const refreshObserver = (value) => {
  value.observer.evidence_sha256 = stagingOperationObserverSHA256(value);
  return value;
};

const readiness = () => attachStagingReadinessDigest({
  schema_version: 1, kind: "agentpass.staging-readiness", environment: "staging", service: "agentpass-cloud-api", qualified: true, status: "passed",
  candidate: candidate("c"), deployment: deployment("current-revision", "e"),
  readiness: {
    configured: true, ready: true, status: "passed",
    checks: ["application", "database_schema", "audit_path", "console"].map((check_id) => ({ check_id, expected: "ready", observed: "ready", status: "passed" }))
  },
  canary: refreshObserver({ ...operation("staging-canary-1", "healthy", "healthy", { startedAt: "2026-08-20T00:05:00.000Z", completedAt: "2026-08-20T00:10:00.000Z", observedAt: "2026-08-20T00:09:00.000Z" }), traffic_percent: 10, requests: 100, successful_requests: 100, error_count: 0 }),
  drain: refreshObserver({ ...operation("staging-drain-1", "drained", "drained", { startedAt: "2026-08-20T00:10:00.000Z", completedAt: "2026-08-20T00:15:00.000Z", observedAt: "2026-08-20T00:14:00.000Z" }), from_revision: "previous-revision", to_revision: "current-revision", in_flight_before: 7, in_flight_after: 0, new_work_stopped: true, drained: true }),
  failover: operation("staging-failover-1", "available"),
  pitr: operation("staging-pitr-1", "restored"),
  signer_outage: operation("staging-signer-outage-1", "denied"),
  recovery: operation("staging-recovery-1", "recovered"),
  rollback_target: { candidate: candidate("f"), deployment: deployment("previous-revision", "2"), status: "passed", target_ready: true },
  issued_at: "2026-08-20T00:00:00.000Z", expires_at: "2026-08-20T12:00:00.000Z", evidence_sha256: "0".repeat(64)
});

test("staging readiness is qualified only when candidate, deployment, canary, drain, and rollback target are bound", () => {
  const value = readiness();
  const normalized = normalizeStagingReadiness(value, { now });
  const result = verifyStagingReadiness(normalized, { expected: binding(), now });
  assert.equal(result.qualified, true);
  assert.equal(result.evidence_sha256, stagingReadinessSHA256(value));
});

test("staging readiness fails closed on candidate/source/tree/deployment substitutions", () => {
  for (const mutate of [
    (value) => { value.candidate = { ...value.candidate, source_commit: "9".repeat(40) }; },
    (value) => { value.candidate = { ...value.candidate, source_tree: "9".repeat(40) }; },
    (value) => { value.deployment = { ...value.deployment, deployment_digest: "9".repeat(64) }; },
    (value) => { value.deployment = { ...value.deployment, schema_digest: "9".repeat(64) }; },
    (value) => { value.deployment = { ...value.deployment, catalog_digest: "9".repeat(64) }; },
    (value) => { value.deployment = { ...value.deployment, deployment_identity: { ...value.deployment.deployment_identity, source_tree: "9".repeat(40) } }; },
    (value) => { value.rollback_target = { ...value.rollback_target, deployment: { ...value.rollback_target.deployment, revision: "current-revision" } }; },
    (value) => { value.evidence_sha256 = "9".repeat(64); }
  ]) {
    const value = structuredClone(readiness());
    mutate(value);
    assert.throws(() => verifyStagingReadiness(value, { expected: binding(), now }), /ERR_STAGING_READINESS/);
  }
});

test("staging readiness rejects incomplete or ambiguous deployment identity", () => {
  for (const [index, mutate] of [
    (value) => { delete value.deployment.schema_digest; },
    (value) => { delete value.deployment.catalog_digest; },
    (value) => { delete value.deployment.database_schema_digest; },
    (value) => { delete value.deployment.deployment_identity; },
    (value) => { value.deployment.deployment_identity = { ...value.deployment.deployment_identity, ready: false }; }
  ].entries()) {
    const value = structuredClone(readiness());
    mutate(value);
    assert.throws(() => normalizeStagingReadiness(value, { now }), /ERR_STAGING_READINESS/);
  }
});

test("staging readiness rejects canary/drain values that merely claim passed", () => {
  const badCanary = structuredClone(readiness());
  badCanary.canary = { ...badCanary.canary, error_count: 1 };
  assert.throws(() => normalizeStagingReadiness(badCanary, { now }), /ERR_STAGING_READINESS_CANARY|ERR_STAGING_READINESS_DIGEST/);
  const badDrain = structuredClone(readiness());
  badDrain.drain = { ...badDrain.drain, in_flight_after: 1 };
  assert.throws(() => normalizeStagingReadiness(badDrain, { now }), /ERR_STAGING_READINESS_DRAIN|ERR_STAGING_READINESS_DIGEST/);
  const notRun = structuredClone(readiness());
  notRun.canary = { ...notRun.canary, status: "not_run", expected: "not_run", observed: "not_run", requests: 0, successful_requests: 0, error_count: 0 };
  notRun.status = "not_run"; notRun.qualified = false;
  assert.throws(() => normalizeStagingReadiness(notRun, { now }), /ERR_STAGING_READINESS/);
});

test("staging readiness requires every resilience operation and rejects unproven or self-reported observations", () => {
  for (const operationId of ["canary", "drain", "failover", "pitr", "signer_outage", "recovery"]) {
    const missing = structuredClone(readiness());
    delete missing[operationId];
    assert.throws(() => normalizeStagingReadiness(missing, { now }), /ERR_STAGING_READINESS/);
  }
  for (const [index, mutate] of [
    (value) => { value.failover.binding.source_tree = "9".repeat(40); },
    (value) => { value.pitr.binding.database_schema_digest = "8".repeat(64); },
    (value) => { value.signer_outage.binding.rollback_target_sha256 = "9".repeat(64); },
    (value) => { value.recovery.execution_id = "self_reported"; },
    (value) => { value.recovery.execution_id = "mock-run-1"; },
    (value) => { value.recovery.execution = { ...value.recovery.execution, kind: "mock", real_execution: false }; },
    (value) => { value.failover.observer = { ...value.failover.observer, source: "self_reported" }; },
    (value) => { value.pitr.observer = { ...value.pitr.observer, independent: false }; },
    (value) => { value.signer_outage.observer.evidence_sha256 = "0".repeat(64); },
    (value) => { value.recovery.measurements = { ...value.recovery.measurements, rto_ms: 2_000 }; },
    (value) => { value.failover.status = "not_run"; },
    (value) => { value.pitr.status = "not_proven"; }
  ].entries()) {
    const value = structuredClone(readiness());
    mutate(value);
    assert.throws(() => verifyStagingReadiness(value, { expected: binding(), now }), /ERR_STAGING_READINESS/, `mutation ${index}`);
  }
});

test("staging readiness rejects failed and expired evidence as a promotion result", () => {
  const failed = structuredClone(readiness());
  failed.status = "failed";
  failed.qualified = false;
  failed.canary = { ...failed.canary, status: "failed", observed: "degraded" };
  assert.throws(() => verifyStagingReadiness(failed, { expected: binding(), now }), /ERR_STAGING_READINESS/);
  const expired = structuredClone(readiness());
  expired.expires_at = "2026-08-20T00:29:00.000Z";
  expired.evidence_sha256 = stagingReadinessSHA256(expired);
  assert.throws(() => verifyStagingReadiness(expired, { expected: binding(), now }), /ERR_STAGING_READINESS/);
});

test("staging readiness enforces a bounded, current evidence window and exact objects", () => {
  const expired = structuredClone(readiness());
  expired.expires_at = "2026-08-20T00:29:00.000Z";
  assert.throws(() => verifyStagingReadiness(expired, { expected: binding(), now }), /ERR_STAGING_READINESS/);
  const extra = structuredClone(readiness());
  extra.secret = "must not enter evidence";
  assert.throws(() => normalizeStagingReadiness(extra, { now }), /ERR_STAGING_READINESS/);
  const getter = structuredClone(readiness());
  Object.defineProperty(getter, "service", { enumerable: true, get() { throw new Error("accessor"); } });
  assert.throws(() => normalizeStagingReadiness(getter, { now }), /ERR_STAGING_READINESS/);
});

test("staging readiness CLI emits canonical output and rejects symlink evidence", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-staging-readiness-"));
  try {
    const evidencePath = path.join(root, "readiness.json");
    const bindingPath = path.join(root, "binding.json");
    fs.writeFileSync(evidencePath, `${canonicalJson(readiness())}\n`, { mode: 0o600 });
    fs.writeFileSync(bindingPath, `${canonicalJson(binding())}\n`, { mode: 0o600 });
    const script = path.resolve("scripts/release/staging-readiness.mjs");
    const args = [script, "verify", evidencePath, bindingPath, "--now=2026-08-20T00:30:00.000Z"];
    const ok = spawnSync(process.execPath, args, { encoding: "utf8" });
    assert.equal(ok.status, 0, ok.stderr);
    assert.equal(ok.stdout, `${canonicalJson(JSON.parse(ok.stdout))}\n`);
    fs.rmSync(bindingPath);
    fs.symlinkSync(evidencePath, bindingPath);
    const rejected = spawnSync(process.execPath, args, { encoding: "utf8" });
    assert.notEqual(rejected.status, 0);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
