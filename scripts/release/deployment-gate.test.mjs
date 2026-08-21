import assert from "node:assert/strict";
import test from "node:test";
import {
  deploymentEvidenceSHA256,
  normalizeDeploymentEvidence,
  verifyDeploymentEvidence,
} from "./deployment-gate.mjs";

const binding = {
  sourceCommit: "a".repeat(40), sourceTree: "b".repeat(40), artifactSha256: "c".repeat(64),
  releaseManifestSha256: "d".repeat(64), deploymentDigest: "e".repeat(64), deploymentId: "deployment-123", environment: "staging", imageDigest: `sha256:${"1".repeat(64)}`, revision: "revision-current", schemaDigest: "f".repeat(64), catalogDigest: "0".repeat(64), databaseSchemaDigest: "1".repeat(64), service: "agentpass-cloud-api", runId: "123", runAttempt: "1", jobId: "deploy-staging"
};
function evidence(status = "passed") {
  return {
    schema_version: 1, artifact_sha256: binding.artifactSha256, release_manifest_sha256: binding.releaseManifestSha256,
    checks: ["application_readiness", "traffic_drain", "combined_cutover", "console_readiness"].map((check_id) => ({ check_id, expected: status === "not_run" ? "not_run" : "true", observed: status === "passed" ? "true" : status === "not_run" ? "not_run" : "timeout", status })),
    completed_at: "2099-08-20T01:05:00Z", deployment_digest: binding.deploymentDigest, deployment_id: binding.deploymentId, environment: binding.environment, image_digest: binding.imageDigest, schema_digest: binding.schemaDigest, catalog_digest: binding.catalogDigest, database_schema_digest: binding.databaseSchemaDigest,
    job_id: binding.jobId, qualified: status === "passed", revision: binding.revision, rollback: { artifact_sha256: binding.artifactSha256, completed_at: "2099-08-20T01:01:00Z", current_revision: binding.revision, deployment_digest: binding.deploymentDigest, deployment_id: binding.deploymentId, deployment_identity: status === "passed" ? { version: 1, configured: true, ready: true, source_commit: binding.sourceCommit, source_tree: binding.sourceTree, image_digest: binding.imageDigest, deployment_id: binding.deploymentId, revision: "revision-previous", schema_digest: binding.schemaDigest, catalog_digest: binding.catalogDigest, database_schema_digest: binding.databaseSchemaDigest } : null, post_rollback_ready: status === "passed", rollback_target_revision: "revision-previous", run_id: binding.runId, status, tested: status === "passed" },
    run_attempt: binding.runAttempt, run_id: binding.runId, service: binding.service, source_commit: binding.sourceCommit,
    source_tree: binding.sourceTree, started_at: "2099-08-20T00:00:00Z", status
  };
}

test("deployment gate accepts only fully ready, rollback-tested evidence bound to one candidate", () => {
  const normalized = normalizeDeploymentEvidence(evidence());
  const result = verifyDeploymentEvidence(normalized, binding);
  assert.equal(result.qualified, true);
  assert.equal(result.evidence_sha256, deploymentEvidenceSHA256(normalized));
});

test("deployment gate rejects not_run, failed, and binding substitutions", () => {
  assert.throws(() => verifyDeploymentEvidence(evidence("not_run"), binding));
  assert.throws(() => verifyDeploymentEvidence(evidence("failed"), binding));
  assert.throws(() => verifyDeploymentEvidence(evidence(), {}));
  assert.throws(() => verifyDeploymentEvidence(evidence(), { ...binding, extra: "reject" }));
  assert.throws(() => verifyDeploymentEvidence(evidence(), { ...binding, sourceTree: "0".repeat(40) }));
  assert.throws(() => verifyDeploymentEvidence({ ...evidence(), artifact_sha256: "f".repeat(64) }, binding));
  assert.throws(() => verifyDeploymentEvidence(evidence(), { ...binding, deploymentId: "deployment-other" }));
  assert.throws(() => verifyDeploymentEvidence(evidence(), { ...binding, revision: "revision-other" }));
  assert.throws(() => verifyDeploymentEvidence(evidence(), { ...binding, environment: "production" }));
  assert.throws(() => normalizeDeploymentEvidence({ ...evidence(), rollback: { ...evidence().rollback, tested: false, status: "passed" } }));
});

test("deployment gate rejects a rollback that targets the currently deployed revision", () => {
  const value = evidence();
  value.rollback = {
    ...value.rollback,
    deployment_identity: { ...value.rollback.deployment_identity, revision: binding.revision },
    rollback_target_revision: binding.revision,
  };
  assert.throws(() => normalizeDeploymentEvidence(value), /rollback target revision must differ from current revision/u);
});

test("deployment gate preserves an executed failed rollback as failure evidence", () => {
  const value = evidence("failed");
  value.rollback = { ...value.rollback, status: "failed", tested: true };
  assert.equal(normalizeDeploymentEvidence(value).status, "failed");
});

test("deployment gate rejects secret-bearing or accessor-shaped evidence", () => {
  assert.throws(() => normalizeDeploymentEvidence({ ...evidence(), provider_token: "secret" }));
  const getter = evidence();
  Object.defineProperty(getter, "service", { enumerable: true, get() { throw new Error("secret"); } });
  assert.throws(() => normalizeDeploymentEvidence(getter));
});

test("deployment gate rejects not_run disguised as passed and incomplete inventories", () => {
  const value = evidence();
  value.checks[0] = { check_id: "application_readiness", expected: "not_run", observed: "not_run", status: "passed" };
  assert.throws(() => normalizeDeploymentEvidence(value));
  const incomplete = evidence();
  incomplete.checks = incomplete.checks.slice(0, 3);
  assert.throws(() => normalizeDeploymentEvidence(incomplete));
  const substitutedRollback = evidence();
  substitutedRollback.rollback = { ...substitutedRollback.rollback, run_id: "999" };
  assert.throws(() => normalizeDeploymentEvidence(substitutedRollback));
  const missingRollbackIdentity = evidence();
  delete missingRollbackIdentity.rollback.rollback_target_revision;
  assert.throws(() => normalizeDeploymentEvidence(missingRollbackIdentity));
  const staleRollback = evidence();
  staleRollback.rollback.completed_at = "2000-01-01T00:00:00Z";
  assert.throws(() => normalizeDeploymentEvidence(staleRollback));
  const coerced = evidence();
  coerced.deployment_id = 123;
  assert.throws(() => normalizeDeploymentEvidence(coerced));
});
