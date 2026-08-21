import assert from "node:assert/strict";
import test from "node:test";
import { attachStagingReadinessDigest } from "./staging-readiness.mjs";
import {
  attachStagingRollbackDigest,
  normalizeStagingRollback,
  stagingRollbackSHA256,
  verifyStagingRollback
} from "./staging-rollback.mjs";

const now = Date.parse("2026-08-20T00:30:00.000Z");
const candidate = (suffix) => ({
  artifact_sha256: suffix.repeat(64), candidate_id: `release-pkg-sha256-v1-${suffix.repeat(64)}`,
  release_manifest_sha256: (suffix === "c" ? "d" : "e").repeat(64), source_commit: (suffix === "c" ? "a" : "f").repeat(40), source_tree: (suffix === "c" ? "b" : "0").repeat(40)
});
const deployment = (revision, suffix) => ({
  deployment_digest: suffix.repeat(64), deployment_id: "staging-api", environment: "staging",
  image_digest: `sha256:${(suffix === "e" ? "1" : "2").repeat(64)}`, revision, service: "agentpass-cloud-api"
});
const target = () => ({ candidate: candidate("f"), deployment: deployment("previous-revision", "2"), status: "passed", target_ready: true });
const binding = () => ({ candidate: candidate("c"), deployment: deployment("current-revision", "e"), rollback_target: target() });

const rollback = () => attachStagingRollbackDigest({
  schema_version: 1, kind: "agentpass.staging-rollback", environment: "staging", service: "agentpass-cloud-api", qualified: true, status: "passed",
  candidate: candidate("c"), current_deployment: deployment("current-revision", "e"),
  rollback: {
    status: "passed", executed: true, tested: true, reused_artifact: true, target_ready: true, traffic_restored: true,
    current_revision: "current-revision", started_at: "2026-08-20T00:05:00.000Z", completed_at: "2026-08-20T00:10:00.000Z", target: target()
  },
  issued_at: "2026-08-20T00:00:00.000Z", expires_at: "2026-08-20T12:00:00.000Z", completed_at: "2026-08-20T00:10:00.000Z", evidence_sha256: "0".repeat(64)
});

test("staging rollback proves executed, tested, artifact-reused target readiness and restored traffic", () => {
  const value = rollback();
  const normalized = normalizeStagingRollback(value, { now });
  const result = verifyStagingRollback(normalized, { expected: binding(), now });
  assert.equal(result.qualified, true);
  assert.equal(result.rollback.target.deployment.revision, "previous-revision");
  assert.equal(result.evidence_sha256, stagingRollbackSHA256(value));
});

test("staging rollback fails closed for untested, non-reused, future, and substituted targets", () => {
  for (const mutate of [
    (value) => { value.rollback.tested = false; },
    (value) => { value.rollback.reused_artifact = false; },
    (value) => { value.rollback.target_ready = false; },
    (value) => { value.rollback.target = { ...value.rollback.target, deployment: { ...value.rollback.target.deployment, deployment_digest: "9".repeat(64) } }; },
    (value) => { value.completed_at = "2026-08-20T00:40:00.000Z"; value.rollback.completed_at = value.completed_at; }
  ]) {
    const value = structuredClone(rollback());
    mutate(value);
    assert.throws(() => verifyStagingRollback(value, { expected: binding(), now }), /ERR_STAGING_ROLLBACK/);
  }
});

test("staging rollback rejects same-revision targets, missing execution, stale expiry, and secret-shaped fields", () => {
  const sameRevision = structuredClone(rollback());
  sameRevision.rollback.target = { ...sameRevision.rollback.target, deployment: { ...sameRevision.rollback.target.deployment, revision: "current-revision" } };
  assert.throws(() => normalizeStagingRollback(sameRevision, { now }), /ERR_STAGING_ROLLBACK/);
  const notRun = structuredClone(rollback());
  notRun.status = "not_run"; notRun.qualified = false;
  notRun.rollback = { ...notRun.rollback, status: "not_run", executed: false, tested: false, reused_artifact: false, target_ready: false, traffic_restored: false, target: { ...notRun.rollback.target, status: "not_run", target_ready: false } };
  assert.throws(() => normalizeStagingRollback(notRun, { now }), /ERR_STAGING_ROLLBACK/);
  const expired = structuredClone(rollback());
  expired.expires_at = "2026-08-20T00:29:00.000Z";
  assert.throws(() => verifyStagingRollback(expired, { expected: binding(), now }), /ERR_STAGING_ROLLBACK/);
  const extra = structuredClone(rollback());
  extra.secret = "never retain credentials";
  assert.throws(() => normalizeStagingRollback(extra, { now }), /ERR_STAGING_ROLLBACK/);
});

test("staging rollback rejects failed and expired evidence as a promotion result", () => {
  const failed = structuredClone(rollback());
  failed.status = "failed";
  failed.qualified = false;
  failed.rollback = { ...failed.rollback, status: "failed", tested: false, target_ready: false, traffic_restored: false };
  assert.throws(() => verifyStagingRollback(failed, { expected: binding(), now }), /ERR_STAGING_ROLLBACK/);
  const expired = structuredClone(rollback());
  expired.expires_at = "2026-08-20T00:29:00.000Z";
  expired.evidence_sha256 = stagingRollbackSHA256(expired);
  assert.throws(() => verifyStagingRollback(expired, { expected: binding(), now }), /ERR_STAGING_ROLLBACK/);
});
