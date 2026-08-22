import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { POSTGRES_SCHEMA_HEAD } from "../../apps/cloud-api/src/postgres/schema-head.mjs";

const run = promisify(execFile);
const script = new URL("./verify-release-preflight.mjs", import.meta.url).pathname;
const commitSha = "a".repeat(40);
const treeSha = "d".repeat(40);
const artifactDigest = `sha256:${"b".repeat(64)}`;
const checkNames = [
  "native_audit_delivery",
  "cloud_production_deploy",
  "real_postgresql",
  "developer_id_signing",
  "apple_notarization",
  "hardware_qualification",
  "external_qualification_provenance",
];

function postgresGateEvidence(check) {
  const checks = ["postgresql_16_version", "postgresql_17_version", "migration_contract", "role_rls_boundary", "concurrency_rollback"];
  return {
    status: "passed", qualified: true, reason: null,
    execution: {
      kind: "external_runner", real_execution: true, runner_id: "protected-postgresql",
      run_id: check.qualification_run_id, run_attempt: check.qualification_run_attempt, job_id: check.qualification_job_id,
      source_commit: commitSha, source_tree: treeSha, release_artifact_sha256: artifactDigest.slice("sha256:".length), artifact_sha256: "e".repeat(64),
      ci_run_id: check.ci_run_id, ci_run_attempt: check.ci_run_attempt,
      qualification_run_id: check.qualification_run_id, qualification_run_attempt: check.qualification_run_attempt,
      qualification_job_id: check.qualification_job_id, qualification_job_name: check.qualification_job_name,
      started_at: "2026-08-21T00:00:00.000Z", completed_at: "2026-08-21T00:01:00.000Z",
      environment: { kind: "postgresql", identity: "pg-protected" }
    },
    required_checks: checks,
    checks: checks.map((check_id) => ({ check_id, status: "passed" })),
    backup_pitr_evidence: { postgres_16_sha256: "f".repeat(64), postgres_17_sha256: "f".repeat(64), bundle_sha256: "f".repeat(64) },
    readiness: { status: "ready", migration_head: POSTGRES_SCHEMA_HEAD.version, catalog_constraints_validated: true, role_boundary_verified: true }
  };
}

function externalProvenanceVerification(check) {
  const artifacts = ["kms", "platform-auth", "webauthn", "postgres-authority-16", "postgres-authority-17", "postgres-gate"].map((job, index) => ({
    job,
    job_id: String(300 + index),
    job_name: job,
    artifact_id: String(400 + index),
    name: `external-${job}-${commitSha}-101-1`,
    digest: `sha256:${"e".repeat(64)}`,
    run_id: check.qualification_run_id,
    run_attempt: check.qualification_run_attempt,
    source_commit: commitSha,
    source_tree: treeSha,
    archive_sha256: "f".repeat(64),
    archive_bytes: 1,
    evidence_members: ["evidence.json"],
  }));
  const report = {
    schema_version: 1,
    kind: "agentpass-external-qualification-artifact-provenance",
    repository: "Torutesu/AIagentpass",
    source_commit: commitSha,
    source_tree: treeSha,
    run_id: check.qualification_run_id,
    run_attempt: check.qualification_run_attempt,
    canonical_ci_run_id: check.ci_run_id,
    canonical_ci_run_attempt: check.ci_run_attempt,
    provenance_job_id: check.qualification_job_id,
    provenance_job_name: check.qualification_job_name,
    artifacts,
  };
  return { ...report, evidence_sha256: createHash("sha256").update(canonicalJson(report), "utf8").digest("hex") };
}

function validEvidence() {
  const checks = Object.fromEntries(checkNames.map((name) => {
    const check = {
      status: "passed",
      evidence_ref: `${name}.json`,
      verification_ref: `${name}.verification.json`,
      verification_sha256: "0".repeat(64),
      evidence_origin: "protected_external",
      execution_mode: "protected_external",
      verifier_kind: "independent_protected_verifier",
      verifier_status: "verified",
      commit_sha: commitSha,
      artifact_digest: artifactDigest,
      ...(name === "real_postgresql" ? { source_tree: treeSha, ci_run_id: "100", ci_run_attempt: "1", qualification_run_id: "101", qualification_run_attempt: "1", qualification_job_id: "200", qualification_job_name: "postgres-gate" } : {}),
      ...(name === "developer_id_signing" ? { team_id: "TEAM123456", signature_identity: "Developer ID Installer: AgentPass Release (TEAM123456)", signature_verified: true } : {}),
      ...(name === "apple_notarization" ? { notary_submission_id: "12345678-1234-1234-8123-123456789abc", stapled: true, stapler_verified: true, gatekeeper_verified: true } : {}),
      ...(name === "external_qualification_provenance" ? { source_tree: treeSha, ci_run_id: "100", ci_run_attempt: "1", qualification_run_id: "101", qualification_run_attempt: "1", qualification_job_id: "200", qualification_job_name: "external-qualification-provenance" } : {}),
    };
    const evidence = name === "real_postgresql" ? JSON.stringify(postgresGateEvidence(check)) : `evidence:${name}`;
    const verification = name === "external_qualification_provenance" ? JSON.stringify(externalProvenanceVerification(check)) : `verification:${name}`;
    return [name, {
      ...check,
      verification_sha256: createHash("sha256").update(verification).digest("hex"),
      evidence_sha256: createHash("sha256").update(evidence).digest("hex"),
    }];
  }));
  return {
    schema_version: 1,
    candidate: { commit_sha: commitSha, tree_sha: treeSha, artifact_digest: artifactDigest },
    checks,
  };
}

async function writeEvidence(value) {
  const dir = await mkdtemp(join(tmpdir(), "agentpass-release-preflight-"));
  for (const [name, check] of Object.entries(value.checks ?? {})) {
    if (check.status !== "passed") continue;
    const target = join(dir, check.evidence_ref);
    await mkdir(dirname(target), { recursive: true });
    const bytes = name === "real_postgresql" ? JSON.stringify(postgresGateEvidence(check)) : `evidence:${name}`;
    await writeFile(target, bytes);
    if (check.verification_ref) {
      const verification = name === "external_qualification_provenance" ? JSON.stringify(externalProvenanceVerification(check)) : `verification:${name}`;
      await writeFile(join(dir, check.verification_ref), verification);
    }
  }
  const file = join(dir, "evidence.json");
  await writeFile(file, `${JSON.stringify(value)}\n`);
  return file;
}

test("passes only when all seven gates are passed and independently verified", async () => {
  const file = await writeEvidence(validEvidence());
  const { stdout } = await run(process.execPath, [script, file, "--candidate-commit-sha", commitSha]);
  const report = JSON.parse(stdout);
  assert.equal(report.status, "passed");
  assert.deepEqual(Object.values(report.checks).map((check) => check.status), checkNames.map(() => "passed"));
});

test("returns unknown when evidence is absent", async () => {
  await assert.rejects(
    run(process.execPath, [script, "/tmp/agentpass-release-evidence-does-not-exist.json"]),
    (error) => error.code === 2 && /release preflight unknown/u.test(error.stderr),
  );
});

test("returns unknown when a live production gate is not verified", async () => {
  const evidence = validEvidence();
  evidence.checks.real_postgresql = { status: "unknown", evidence_ref: "qualification/live-postgresql.json", evidence_sha256: "0".repeat(64) };
  const file = await writeEvidence(evidence);
  await assert.rejects(
    run(process.execPath, [script, file]),
    (error) => error.code === 2 && /release preflight unknown/u.test(error.stderr),
  );
});

test("fails closed when a passed gate references a missing or tampered file", async () => {
  const missing = validEvidence();
  missing.checks.hardware_qualification.evidence_ref = "missing.json";
  const missingFile = await writeEvidence(missing);
  await rm(join(dirname(missingFile), "missing.json"));
  await assert.rejects(run(process.execPath, [script, missingFile]), (error) => error.code === 1 && /release preflight failed/u.test(error.stderr));
  const tampered = validEvidence();
  const tamperedFile = await writeEvidence(tampered);
  await writeFile(join(dirname(tamperedFile), "native_audit_delivery.json"), "tampered");
  await assert.rejects(run(process.execPath, [script, tamperedFile]), (error) => error.code === 1);
});

test("fails a failed gate or a candidate binding mismatch", async () => {
  const failed = validEvidence();
  failed.checks.apple_notarization.status = "failed";
  const failedFile = await writeEvidence(failed);
  await assert.rejects(
    run(process.execPath, [script, failedFile]),
    (error) => error.code === 1 && /release preflight failed/u.test(error.stderr),
  );

  const mismatch = validEvidence();
  mismatch.checks.hardware_qualification.commit_sha = "c".repeat(40);
  const mismatchFile = await writeEvidence(mismatch);
  await assert.rejects(run(process.execPath, [script, mismatchFile]), (error) => error.code === 1);
});

test("rejects self-reported protected evidence without an independent verification artifact", async () => {
  const evidence = validEvidence();
  delete evidence.checks.external_qualification_provenance.verification_ref;
  const file = await writeEvidence(evidence);
  await assert.rejects(run(process.execPath, [script, file]), (error) => error.code === 1);

  const substituted = validEvidence();
  substituted.checks.external_qualification_provenance.qualification_run_id = "100";
  const substitutedFile = await writeEvidence(substituted);
  await assert.rejects(run(process.execPath, [script, substitutedFile]), (error) => error.code === 1);
});

test("does not close the seven-gate preflight when PostgreSQL readiness regresses behind a passed summary", async () => {
  const evidence = validEvidence();
  const file = await writeEvidence(evidence);
  const gatePath = join(dirname(file), "real_postgresql.json");
  const gate = JSON.parse(await readFile(gatePath, "utf8"));
  gate.readiness.migration_head = 46;
  const serialized = JSON.stringify(gate);
  await writeFile(gatePath, serialized);
  evidence.checks.real_postgresql.evidence_sha256 = createHash("sha256").update(serialized).digest("hex");
  await writeFile(file, `${JSON.stringify(evidence)}\n`);
  await assert.rejects(run(process.execPath, [script, file]), (error) => error.code === 1);
});

test("binds the external provenance verifier output to the same source, runs, and provenance job", async () => {
  for (const [field, value] of [["source_tree", "c".repeat(40)], ["run_id", "999"], ["provenance_job_id", "999"]]) {
    const evidence = validEvidence();
    const file = await writeEvidence(evidence);
    const verificationPath = join(dirname(file), evidence.checks.external_qualification_provenance.verification_ref);
    const verification = JSON.parse(await readFile(verificationPath, "utf8"));
    verification[field] = value;
    const verificationBytes = JSON.stringify(verification);
    await writeFile(verificationPath, verificationBytes);
    evidence.checks.external_qualification_provenance.verification_sha256 = createHash("sha256").update(verificationBytes).digest("hex");
    await writeFile(file, `${JSON.stringify(evidence)}\n`);
    await assert.rejects(run(process.execPath, [script, file]), (error) => error.code === 1);
  }
});

test("fails closed when Developer ID identity or stapler verification is absent", async () => {
  const missingIdentity = validEvidence();
  delete missingIdentity.checks.developer_id_signing.signature_identity;
  const identityFile = await writeEvidence(missingIdentity);
  await assert.rejects(run(process.execPath, [script, identityFile]), (error) => error.code === 1);

  const mismatchedIdentity = validEvidence();
  mismatchedIdentity.checks.developer_id_signing.signature_identity = "Developer ID Installer: AgentPass Release (OTHER12345)";
  const mismatchedIdentityFile = await writeEvidence(mismatchedIdentity);
  await assert.rejects(run(process.execPath, [script, mismatchedIdentityFile]), (error) => error.code === 1);

  const missingStapler = validEvidence();
  delete missingStapler.checks.apple_notarization.stapler_verified;
  const missingStaplerFile = await writeEvidence(missingStapler);
  await assert.rejects(run(process.execPath, [script, missingStaplerFile]), (error) => error.code === 1);
});
