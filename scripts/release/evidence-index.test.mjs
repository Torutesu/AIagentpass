import assert from "node:assert/strict";
import test from "node:test";
import { deploymentEvidenceSHA256 } from "./deployment-gate.mjs";
import { evidenceIndexSHA256, verifyEvidenceIndex } from "./evidence-index.mjs";

const sourceCommit = "a".repeat(40);
const sourceTree = "b".repeat(40);
const artifactSha256 = "c".repeat(64);
const releaseManifestSha256 = "d".repeat(64);
const imageDigest = `sha256:${"e".repeat(64)}`;
const deploymentDigest = "f".repeat(64);
const schemaDigest = "1".repeat(64);
const catalogDigest = "2".repeat(64);
const databaseSchemaDigest = "3".repeat(64);
const candidateId = `release-pkg-sha256-v1-${artifactSha256}`;

const manifest = {
  candidate_id: candidateId,
  source: { commit: sourceCommit, tree: sourceTree },
  artifacts: [{ name: "AgentPass-v1.2.3.pkg", role: "product", sha256: artifactSha256 }]
};

const identity = (revision) => ({
  version: 1, configured: true, ready: true, source_commit: sourceCommit, source_tree: sourceTree,
  image_digest: imageDigest, deployment_id: "staging-api", revision, schema_digest: schemaDigest,
  catalog_digest: catalogDigest, database_schema_digest: databaseSchemaDigest
});

const deploymentEvidence = {
  schema_version: 1, artifact_sha256: artifactSha256, release_manifest_sha256: releaseManifestSha256,
  deployment_digest: deploymentDigest, environment: "staging", deployment_id: "staging-api", service: "agentpass-cloud-api",
  source_commit: sourceCommit, source_tree: sourceTree, image_digest: imageDigest, revision: "current-revision",
  schema_digest: schemaDigest, catalog_digest: catalogDigest, database_schema_digest: databaseSchemaDigest,
  run_id: "999", run_attempt: "1", job_id: "promote", started_at: "2099-08-20T01:00:00.000Z", completed_at: "2099-08-20T01:05:00.000Z",
  qualified: true, status: "passed",
  checks: [
    { check_id: "application_readiness", expected: "true", observed: "true", status: "passed" },
    { check_id: "traffic_drain", expected: "true", observed: "true", status: "passed" },
    { check_id: "combined_cutover", expected: "true", observed: "true", status: "passed" },
    { check_id: "console_readiness", expected: "true", observed: "true", status: "passed" }
  ],
  rollback: {
    artifact_sha256: artifactSha256, completed_at: "2099-08-20T01:04:00.000Z", current_revision: "current-revision",
    deployment_digest: deploymentDigest, deployment_id: "staging-api", deployment_identity: identity("previous-revision"),
    post_rollback_ready: true, rollback_target_revision: "previous-revision", run_id: "999", status: "passed", tested: true
  }
};

const run = (id) => ({ id, run_attempt: 2, status: "completed", conclusion: "success", head_sha: sourceCommit });
const releaseJobs = { total_count: 2, jobs: [
  { id: 1001, name: "signed-candidate", run_id: "101", status: "completed", conclusion: "success", head_sha: sourceCommit },
  { id: 1002, name: "verify-source", run_id: "101", status: "completed", conclusion: "success", head_sha: sourceCommit }
] };
const qualificationJobs = { total_count: 1, jobs: [{ id: 2001, name: "aggregate-qualification", run_id: "202", status: "completed", conclusion: "success", head_sha: sourceCommit }] };
const ciJobs = { total_count: 1, jobs: [{ id: 3001, name: "test", run_id: "303", status: "completed", conclusion: "success", head_sha: sourceCommit }] };
const runs = { release: run("101"), qualification: run("202"), ci: run("303") };

const baseIndex = () => {
  const evidenceSha256 = deploymentEvidenceSHA256(deploymentEvidence);
  return {
    schema_version: 1,
    candidate: { artifact_name: manifest.artifacts[0].name, artifact_sha256: artifactSha256, candidate_id: candidateId, release_manifest_sha256: releaseManifestSha256, source_commit: sourceCommit, source_tree: sourceTree },
    runs: {
      release: { job_id: "1001", run_attempt: "2", run_id: "101" },
      qualification: { job_id: "2001", run_attempt: "2", run_id: "202" },
      ci: { job_id: "3001", run_attempt: "2", run_id: "303" },
      staging: { job_id: "promote", run_attempt: "1", run_id: "999" }
    },
    artifacts: [{ job_id: "1001", name: manifest.artifacts[0].name, run_attempt: "2", run_id: "101", sha256: artifactSha256 }],
    reviewer: { id: "security-reviewer@example.test", report_sha256: "4".repeat(64), candidate_id: candidateId, source_commit: sourceCommit, source_tree: sourceTree, artifact_sha256: artifactSha256, evidence_sha256: evidenceSha256, reviewed_at: "2099-08-20T02:00:00.000Z", expires_at: "2099-08-25T02:00:00.000Z" },
    rollback: { artifact_sha256: artifactSha256, candidate_id: candidateId, completed_at: deploymentEvidence.rollback.completed_at, current_revision: "current-revision", deployment_id: "staging-api", evidence_sha256: evidenceSha256, job_id: "promote", rollback_target_revision: "previous-revision", run_attempt: "1", run_id: "999", source_commit: sourceCommit, source_tree: sourceTree, status: "passed", tested: true }
  };
};

const expected = () => ({
  manifest,
  manifestSha256: releaseManifestSha256,
  artifactSha256,
  deploymentEvidence,
  releaseRun: runs.release,
  releaseJobs,
  qualificationRun: runs.qualification,
  qualificationJobs,
  ciRun: runs.ci,
  ciJobs,
  now: new Date("2099-08-20T03:00:00.000Z")
});

test("evidence index binds candidate, successful run/jobs, reviewer expiry, and rollback", () => {
  const normalized = verifyEvidenceIndex(baseIndex(), expected());
  assert.equal(normalized.candidate.candidate_id, candidateId);
  assert.equal(normalized.rollback.tested, true);
  assert.match(evidenceIndexSHA256(normalized), /^[0-9a-f]{64}$/u);
});

test("evidence index rejects candidate artifact substitution", () => {
  const value = baseIndex();
  value.artifacts[0].sha256 = "9".repeat(64);
  assert.throws(() => verifyEvidenceIndex(value, expected()), /candidate artifact binding/u);
});

test("evidence index rejects reviewer substitution or stale expiry", () => {
  const substituted = baseIndex();
  substituted.reviewer.candidate_id = "release-pkg-sha256-v1-" + "9".repeat(64);
  assert.throws(() => verifyEvidenceIndex(substituted, expected()), /reviewer binding/u);
  const stale = baseIndex();
  stale.reviewer.expires_at = "2099-08-20T02:59:59.000Z";
  assert.throws(() => verifyEvidenceIndex(stale, expected()), /reviewer expiry/u);
});

test("evidence index rejects rollback run substitution and untested rollback", () => {
  const runMismatch = baseIndex();
  runMismatch.rollback.run_id = "998";
  assert.throws(() => verifyEvidenceIndex(runMismatch, expected()), /rollback binding/u);
  const untested = baseIndex();
  untested.rollback.tested = false;
  assert.throws(() => verifyEvidenceIndex(untested, expected()), /rollback binding/u);
});

test("evidence index rejects a job not present in the exact successful run", () => {
  const value = baseIndex();
  value.runs.ci.job_id = "9999";
  assert.throws(() => verifyEvidenceIndex(value, expected()), /ci job binding/u);
});
