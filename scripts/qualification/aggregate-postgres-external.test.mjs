import assert from "node:assert/strict";
import test from "node:test";
import { aggregatePostgresGate, bundleArtifactSha256, PostgresGateAggregationError } from "./aggregate-postgres-external.mjs";

const SHA = "a".repeat(40);
const TREE = "b".repeat(40);
const RELEASE = "c".repeat(64);
const child = (major, jobId, status = "passed") => ({
  schema_version: 1, kind: "agentpass-postgresql-external-qualification", status, qualified: status === "passed", reason: status === "passed" ? null : "gate_failed",
  source_commit: SHA, source_tree: TREE, run_id: "42", run_attempt: "3", job_id: jobId, artifact_sha256: RELEASE, postgres_major: major,
  migration_artifact_sha256: "d".repeat(64), c3_evidence_sha256: `${major}${"e".repeat(62)}`,
  execution: { kind: "external_runner", real_execution: true, runner_id: "protected-postgresql", environment: { kind: "postgresql", identity: "pg-protected" } },
  checks: [
    { check_id: "postgresql_version", status, expected: { type: "string", value: major }, observed: { type: "string", value: major }, evidence_sha256: "f".repeat(64) },
    ...["migration_contract", "role_rls_boundary", "concurrency_rollback"].map((id) => ({ check_id: id, status, expected: { type: "string", value: "passed" }, observed: { type: "string", value: "passed" }, evidence_sha256: "f".repeat(64) }))
  ], started_at: "2026-08-21T00:00:00.000Z", completed_at: "2026-08-21T00:01:00.000Z"
});

test("aggregates both PostgreSQL majors into the release-facing gate", () => {
  const result = aggregatePostgresGate({ child16: child("16", "1601"), child17: child("17", "1701"), sourceCommit: SHA, sourceTree: TREE, releaseArtifactSha256: RELEASE, runId: "42", runAttempt: "3", jobId: "9001", bundleArtifactSha256: bundleArtifactSha256("16", "17"), runnerId: "protected-postgresql", environmentId: "pg-protected", startedAt: "2026-08-21T00:00:00.000Z", completedAt: "2026-08-21T00:01:00.000Z" });
  assert.equal(result.status, "passed");
  assert.deepEqual(result.required_checks, ["postgresql_16_version", "postgresql_17_version", "migration_contract", "role_rls_boundary", "concurrency_rollback"]);
  assert.ok(result.checks.every((item) => item.status === "passed"));
  assert.equal(result.execution.artifact_sha256, bundleArtifactSha256("16", "17"));
});

test("does not aggregate a failed or mismatched child", () => {
  const result = aggregatePostgresGate({ child16: child("16", "1601", "failed"), child17: child("17", "1701"), sourceCommit: SHA, sourceTree: TREE, releaseArtifactSha256: RELEASE, runId: "42", runAttempt: "3", jobId: "9001", bundleArtifactSha256: "1".repeat(64), runnerId: "protected-postgresql", environmentId: "pg-protected", startedAt: "2026-08-21T00:00:00.000Z", completedAt: "2026-08-21T00:01:00.000Z" });
  assert.equal(result.status, "failed");
  assert.equal(result.qualified, false);
});
