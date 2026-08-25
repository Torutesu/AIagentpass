import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { POSTGRES_SCHEMA_HEAD } from "../../apps/cloud-api/src/postgres/schema-head.mjs";
import { aggregatePostgresGate as aggregatePostgresGateImpl, bundleArtifactSha256, postgresControllerSigningData } from "./aggregate-postgres-external.mjs";

const SHA = "a".repeat(40);
const TREE = "b".repeat(40);
const RELEASE = "c".repeat(64);
const BACKUP_16 = "backup-16-evidence\n";
const BACKUP_17 = "backup-17-evidence\n";
const C3_CHECK_STATUSES = Object.freeze({ migration_checksum: "passed", schema_objects: "passed", catalog_constraints_validated: "passed", role_privileges_and_ownership: "passed", rls_policy_catalog: "passed", cross_role_privilege_boundary: "passed", generation_contention_single_winner: "passed", transaction_rollback: "passed" });
const CONTROLLER_KEYS = crypto.generateKeyPairSync("ed25519");
const CONTROLLER_DER = CONTROLLER_KEYS.publicKey.export({ type: "spki", format: "der" });
const CONTROLLER_FINGERPRINT = `SHA256:${crypto.createHash("sha256").update(CONTROLLER_DER).digest("base64url")}`;
const child = (major, jobId, status = "passed") => ({
  schema_version: 1, kind: "agentpass-postgresql-external-qualification", status, qualified: status === "passed", reason: status === "passed" ? null : "gate_failed",
  source_commit: SHA, source_tree: TREE, run_id: "42", run_attempt: "3", job_id: jobId, ci_run_id: "41", ci_run_attempt: "2", qualification_run_id: "42", qualification_run_attempt: "3", qualification_job_id: jobId, artifact_sha256: RELEASE, postgres_major: major,
  migration_artifact_sha256: "e".repeat(64), c3_evidence_sha256: `${major}${"e".repeat(62)}`,
  c3_server_version: `${major}.1`, c3_database_name: "agentpass", c3_server_port: 5432, c3_schema_head: POSTGRES_SCHEMA_HEAD.version,
  c3_migration_checksum: "e".repeat(64), backup_pitr_evidence_sha256: "f".repeat(64),
  c3_check_statuses: { ...C3_CHECK_STATUSES },
  execution: { kind: "external_runner", real_execution: true, runner_id: `protected-postgresql-${major}`, environment: { kind: "postgresql", identity: `pg-${major}` } },
  checks: [
    { check_id: "postgresql_version", status, expected: { type: "string", value: major }, observed: { type: "string", value: status === "passed" ? major : "unknown" }, evidence_sha256: "f".repeat(64) },
    ...["migration_contract", "role_rls_boundary", "concurrency_rollback"].map((id) => ({ check_id: id, status, expected: { type: "string", value: "passed" }, observed: { type: "string", value: status === "passed" ? "passed" : "failed" }, evidence_sha256: "f".repeat(64) }))
  ], started_at: "2026-08-21T00:00:00.000Z", completed_at: "2026-08-21T00:01:00.000Z"
});

function controllerFor(input) {
  const controller = {
    kind: "external_qualification_controller",
    controller_id: "postgres-gate-controller",
    runner_id: input.runnerId,
    environment_id: input.environmentId,
    run_id: input.runId,
    run_attempt: input.runAttempt,
    job_id: input.jobId,
    source_commit: input.sourceCommit,
    source_tree: input.sourceTree,
    release_artifact_sha256: input.releaseArtifactSha256,
    artifact_sha256: input.bundleArtifactSha256,
    bundle_artifact_sha256: input.bundleArtifactSha256,
    child_evidence_sha256: {
      postgres_16: crypto.createHash("sha256").update(canonicalJson(input.child16), "utf8").digest("hex"),
      postgres_17: crypto.createHash("sha256").update(canonicalJson(input.child17), "utf8").digest("hex")
    },
    signature: { algorithm: "ed25519", public_key_der_base64url: CONTROLLER_DER.toString("base64url"), public_key_fingerprint: CONTROLLER_FINGERPRINT, value: "" }
  };
  controller.signature.value = crypto.sign(null, postgresControllerSigningData(controller), CONTROLLER_KEYS.privateKey).toString("base64url");
  return controller;
}

const aggregatePostgresGate = (input) => aggregatePostgresGateImpl({ ...input, controller: input.controller ?? controllerFor(input) });

test("aggregates both PostgreSQL majors into the release-facing gate", () => {
  const child16 = child("16", "1601");
  const child17 = child("17", "1701");
  child16.backup_pitr_evidence_sha256 = crypto.createHash("sha256").update(BACKUP_16).digest("hex");
  child17.backup_pitr_evidence_sha256 = crypto.createHash("sha256").update(BACKUP_17).digest("hex");
  const result = aggregatePostgresGate({ child16, child17, backupPitr16Text: BACKUP_16, backupPitr17Text: BACKUP_17, sourceCommit: SHA, sourceTree: TREE, releaseArtifactSha256: RELEASE, runId: "42", runAttempt: "3", jobId: "9001", bundleArtifactSha256: bundleArtifactSha256("16", "17"), runnerId: "protected-postgresql", environmentId: "pg-protected", startedAt: "2026-08-21T00:00:00.000Z", completedAt: "2026-08-21T00:01:00.000Z", ciRunId: "41", ciRunAttempt: "2", qualificationJobName: "postgres-gate" });
  assert.equal(result.status, "passed");
  assert.deepEqual(result.required_checks, ["postgresql_16_version", "postgresql_17_version", "migration_contract", "role_rls_boundary", "concurrency_rollback"]);
  assert.ok(result.checks.every((item) => item.status === "passed"));
  assert.equal(result.execution.artifact_sha256, bundleArtifactSha256("16", "17"));
  assert.equal(result.execution.ci_run_id, "41");
  assert.equal(result.execution.qualification_job_id, "9001");
  assert.equal(result.execution.qualification_job_name, "postgres-gate");
  assert.equal(result.execution.release_artifact_sha256, RELEASE);
  assert.deepEqual(result.readiness, { status: "ready", migration_head: POSTGRES_SCHEMA_HEAD.version, catalog_constraints_validated: true, role_boundary_verified: true });
});

test("does not aggregate a failed or mismatched child", () => {
  const child16 = child("16", "1601", "failed");
  const child17 = child("17", "1701");
  child16.backup_pitr_evidence_sha256 = crypto.createHash("sha256").update(BACKUP_16).digest("hex");
  child17.backup_pitr_evidence_sha256 = crypto.createHash("sha256").update(BACKUP_17).digest("hex");
  const result = aggregatePostgresGate({ child16, child17, backupPitr16Text: BACKUP_16, backupPitr17Text: BACKUP_17, sourceCommit: SHA, sourceTree: TREE, releaseArtifactSha256: RELEASE, runId: "42", runAttempt: "3", jobId: "9001", bundleArtifactSha256: "1".repeat(64), runnerId: "protected-postgresql", environmentId: "pg-protected", startedAt: "2026-08-21T00:00:00.000Z", completedAt: "2026-08-21T00:01:00.000Z", ciRunId: "41", ciRunAttempt: "2", qualificationJobName: "postgres-gate" });
  assert.equal(result.status, "failed");
  assert.equal(result.qualified, false);
});

test("rejects a child that self-reports a passed check without matching observations", () => {
  const child16 = child("16", "1601");
  const child17 = child("17", "1701");
  child16.checks[0] = { ...child16.checks[0], status: "passed", observed: { type: "string", value: "15" } };
  child16.backup_pitr_evidence_sha256 = crypto.createHash("sha256").update(BACKUP_16).digest("hex");
  child17.backup_pitr_evidence_sha256 = crypto.createHash("sha256").update(BACKUP_17).digest("hex");
  assert.throws(() => aggregatePostgresGate({ child16, child17, backupPitr16Text: BACKUP_16, backupPitr17Text: BACKUP_17, sourceCommit: SHA, sourceTree: TREE, releaseArtifactSha256: RELEASE, runId: "42", runAttempt: "3", jobId: "9001", bundleArtifactSha256: bundleArtifactSha256("16", "17"), runnerId: "protected-postgresql", environmentId: "pg-protected", startedAt: "2026-08-21T00:00:00.000Z", completedAt: "2026-08-21T00:01:00.000Z", ciRunId: "41", ciRunAttempt: "2", qualificationJobName: "postgres-gate" }), /check evidence is invalid/u);
});

test("rejects a stale migration head or child CI/job substitution even when summary checks say passed", () => {
  const child16 = child("16", "1601");
  const child17 = child("17", "1701");
  child16.backup_pitr_evidence_sha256 = crypto.createHash("sha256").update(BACKUP_16).digest("hex");
  child17.backup_pitr_evidence_sha256 = crypto.createHash("sha256").update(BACKUP_17).digest("hex");
  child16.c3_schema_head = POSTGRES_SCHEMA_HEAD.version - 1;
  assert.throws(() => aggregatePostgresGate({ child16, child17, backupPitr16Text: BACKUP_16, backupPitr17Text: BACKUP_17, sourceCommit: SHA, sourceTree: TREE, releaseArtifactSha256: RELEASE, runId: "42", runAttempt: "3", jobId: "9001", bundleArtifactSha256: bundleArtifactSha256("16", "17"), runnerId: "protected-postgresql", environmentId: "pg-protected", startedAt: "2026-08-21T00:00:00.000Z", completedAt: "2026-08-21T00:01:00.000Z", ciRunId: "41", ciRunAttempt: "2", qualificationJobName: "postgres-gate" }), /runtime provenance/u);

  const substituted = child("16", "1601");
  substituted.backup_pitr_evidence_sha256 = crypto.createHash("sha256").update(BACKUP_16).digest("hex");
  substituted.ci_run_id = "999";
  assert.throws(() => aggregatePostgresGate({ child16: substituted, child17, backupPitr16Text: BACKUP_16, backupPitr17Text: BACKUP_17, sourceCommit: SHA, sourceTree: TREE, releaseArtifactSha256: RELEASE, runId: "42", runAttempt: "3", jobId: "9001", bundleArtifactSha256: bundleArtifactSha256("16", "17"), runnerId: "protected-postgresql", environmentId: "pg-protected", startedAt: "2026-08-21T00:00:00.000Z", completedAt: "2026-08-21T00:01:00.000Z", ciRunId: "41", ciRunAttempt: "2", qualificationJobName: "postgres-gate" }), /ci_run_id binding/u);
});

test("rejects a locally labelled aggregate runner or environment", () => {
  const child16 = child("16", "1601");
  const child17 = child("17", "1701");
  child16.backup_pitr_evidence_sha256 = crypto.createHash("sha256").update(BACKUP_16).digest("hex");
  child17.backup_pitr_evidence_sha256 = crypto.createHash("sha256").update(BACKUP_17).digest("hex");
  const input = { child16, child17, backupPitr16Text: BACKUP_16, backupPitr17Text: BACKUP_17, sourceCommit: SHA, sourceTree: TREE, releaseArtifactSha256: RELEASE, runId: "42", runAttempt: "3", jobId: "9001", bundleArtifactSha256: bundleArtifactSha256("16", "17"), environmentId: "pg-protected", startedAt: "2026-08-21T00:00:00.000Z", completedAt: "2026-08-21T00:01:00.000Z", ciRunId: "41", ciRunAttempt: "2", qualificationJobName: "postgres-gate" };
  assert.throws(() => aggregatePostgresGate({ ...input, runnerId: "local-runner" }), /not external/u);
  assert.throws(() => aggregatePostgresGate({ ...input, runnerId: "protected-postgresql", environmentId: "local-postgres" }), /not external/u);
  assert.throws(() => aggregatePostgresGate({ ...input, runnerId: "unknown-runner" }), /not external/u);
  assert.throws(() => aggregatePostgresGate({ ...input, runnerId: "protected-postgresql", environmentId: "unknown" }), /not external/u);
});

test("binds distinct child lanes and rejects a tampered controller signature", () => {
  const child16 = child("16", "1601");
  const child17 = child("17", "1701");
  child16.backup_pitr_evidence_sha256 = crypto.createHash("sha256").update(BACKUP_16).digest("hex");
  child17.backup_pitr_evidence_sha256 = crypto.createHash("sha256").update(BACKUP_17).digest("hex");
  const input = { child16, child17, backupPitr16Text: BACKUP_16, backupPitr17Text: BACKUP_17, sourceCommit: SHA, sourceTree: TREE, releaseArtifactSha256: RELEASE, runId: "42", runAttempt: "3", jobId: "9001", bundleArtifactSha256: bundleArtifactSha256("16", "17"), runnerId: "protected-postgresql", environmentId: "pg-protected", startedAt: "2026-08-21T00:00:00.000Z", completedAt: "2026-08-21T00:01:00.000Z", ciRunId: "41", ciRunAttempt: "2", qualificationJobName: "postgres-gate" };
  const report = aggregatePostgresGate(input);
  assert.equal(report.controller.signature.algorithm, "ed25519");
  const tamperedController = structuredClone(report.controller);
  tamperedController.source_tree = SHA;
  assert.throws(() => aggregatePostgresGateImpl({ ...input, controller: tamperedController }), /controller (?:signature|identity)/u);
  const duplicateChild = structuredClone(child17);
  duplicateChild.execution.runner_id = child16.execution.runner_id;
  assert.throws(() => aggregatePostgresGate({ ...input, child17: duplicateChild }), /identities are not distinct/u);
});
