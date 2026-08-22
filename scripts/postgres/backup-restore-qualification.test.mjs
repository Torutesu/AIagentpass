import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { POSTGRES_SCHEMA_HEAD } from "../../apps/cloud-api/src/postgres/schema-head.mjs";
import { NOT_PROVEN, verifyBackupRestoreQualification } from "./backup-restore-qualification.mjs";

const SCRIPT = path.resolve("scripts/postgres/backup-restore-qualification.mjs");
const CANDIDATE = `release-pkg-sha256-v1-${"a".repeat(64)}`;
const SOURCE = "b".repeat(40);
const SOURCE_TREE = "e".repeat(40);
const OTHER_CANDIDATE = `release-pkg-sha256-v1-${"c".repeat(64)}`;
const OTHER_SOURCE = "d".repeat(40);
const RUN = { ci_run_id: "42", ci_run_attempt: "2", ci_job_id: "1001" };
const OTHER_RUN = { ci_run_id: "43", ci_run_attempt: "3", ci_job_id: "1002" };
const HASH_1 = "1".repeat(64);
const HASH_2 = "2".repeat(64);
const HASH_3 = "3".repeat(64);
const HASH_4 = "4".repeat(64);
const HASH_5 = "5".repeat(64);
const EXPECTED_SCHEMA_HEAD = {
  version: POSTGRES_SCHEMA_HEAD.version,
  name: POSTGRES_SCHEMA_HEAD.name,
  checksum: POSTGRES_SCHEMA_HEAD.checksum
};

function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function role() {
  return { current_user: "agentpass_backup", dml_denied: true, name: "agentpass_backup", read_only: true, session_user: "agentpass_backup", tls: true };
}
function instance(purpose, id, identity, attestation, artifact) {
  return {
    artifact_sha256: artifact,
    candidate_id: CANDIDATE,
    instance_attestation_sha256: attestation,
    instance_id: id,
    instance_identity_sha256: identity,
    purpose,
    role: role(),
    run: { ...RUN },
    schema_head: { ...EXPECTED_SCHEMA_HEAD },
    source_commit: SOURCE,
    source_tree: SOURCE_TREE
  };
}
function aggregateRoleEvidence(instances) {
  return sha256(Buffer.from(canonicalJson(instances.map((item) => ({
    instance_id: item.instance_id,
    purpose: item.purpose,
    role_evidence_sha256: sha256(Buffer.from(canonicalJson(item.role), "utf8"))
  }))), "utf8"));
}
function qualificationEvidence() {
  const instances = [
    instance("restore", "postgres-restore", HASH_3, HASH_4, HASH_2),
    instance("pitr", "postgres-pitr", HASH_4, HASH_5, HASH_1)
  ];
  return {
    after_manifest_sha256: HASH_1,
    artifact_sha256: HASH_5,
    backup_artifact_sha256: HASH_1,
    before_manifest_sha256: HASH_1,
    candidate_id: CANDIDATE,
    compare_same: true,
    execution: { environment: "postgresql", evidence_origin: "protected_external", real_execution: true, runner_id: "protected-postgresql/backup-pitr" },
    instances,
    kind: "agentpass-postgres-backup-restore-qualification",
    pitr: {
      candidate_id: CANDIDATE,
      instance_id: "postgres-pitr",
      recovery_target: "2026-08-19T00:00:00Z",
      recovery_target_sha256: sha256("2026-08-19T00:00:00Z"),
      restored_manifest_sha256: HASH_1,
      status: "verified",
      wal_replay: { instance_id: "postgres-pitr", recovery_state: "promoted", replayed: true, replay_lsn_sha256: HASH_2, status: "verified" }
    },
    restore_artifact_sha256: HASH_2,
    role_evidence_sha256: aggregateRoleEvidence(instances),
    run: { ...RUN },
    schema_head: { ...EXPECTED_SCHEMA_HEAD },
    source_commit: SOURCE,
    source_tree: SOURCE_TREE,
    version: 1
  };
}
function assertRejected(value, reason = "invalid_or_unclosed_evidence", options = {}) {
  assert.throws(
    () => verifyBackupRestoreQualification(value, {
      expectedCandidateId: CANDIDATE,
      expectedSourceCommit: SOURCE,
      expectedSourceTree: SOURCE_TREE,
      expectedRun: RUN,
      ...options
    }),
    (error) => error?.code === reason
  );
}
function runCli(...args) { return spawnSync(process.execPath, [SCRIPT, ...args], { encoding: "utf8" }); }
function stdoutJson(result) { assert.equal(result.stderr, ""); return JSON.parse(result.stdout); }
function cliArgs(file) { return ["verify", file, CANDIDATE, SOURCE, SOURCE_TREE, RUN.ci_run_id, RUN.ci_run_attempt, RUN.ci_job_id]; }

test("a canonical external qualification envelope closes with distinct restore/PITR instances", () => {
  const result = verifyBackupRestoreQualification(qualificationEvidence(), {
    expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE, expectedSourceTree: SOURCE_TREE, expectedRun: RUN
  });
  assert.equal(result.status, "closed");
  assert.equal(result.candidate_id, CANDIDATE);
  assert.equal(result.source_tree, SOURCE_TREE);
  assert.deepEqual(result.run, RUN);
  assert.equal(result.instance_count, 2);
  assert.equal(result.pitr_restore, "verified");
  assert.equal(result.wal_replay, "verified");
  assert.match(result.evidence_sha256, /^[0-9a-f]{64}$/u);
});

test("unknown fields and secret-bearing values are rejected", () => {
  const topLevel = qualificationEvidence();
  topLevel.unexpected = "attacker-controlled";
  assertRejected(topLevel);
  const nested = qualificationEvidence();
  nested.instances[0].unexpected = true;
  assertRejected(nested, "instance_binding_mismatch");
  const secret = qualificationEvidence();
  secret.execution.runner_id = "postgresql://user:secret@example.invalid/db";
  assertRejected(secret, "sensitive_evidence");
});

test("restore and PITR instance identity, purpose, artifact, and attestation substitutions fail closed", () => {
  const duplicatePurpose = qualificationEvidence();
  duplicatePurpose.instances[1].purpose = "restore";
  duplicatePurpose.instances[1].artifact_sha256 = duplicatePurpose.restore_artifact_sha256;
  assertRejected(duplicatePurpose, "duplicate_or_misbound_instance");
  const duplicateIdentity = qualificationEvidence();
  duplicateIdentity.instances[1].instance_identity_sha256 = duplicateIdentity.instances[0].instance_identity_sha256;
  assertRejected(duplicateIdentity, "duplicate_or_misbound_instance");
  const artifact = qualificationEvidence();
  artifact.instances[0].artifact_sha256 = HASH_1;
  assertRejected(artifact, "instance_binding_mismatch");
  const attestation = qualificationEvidence();
  attestation.instances[1].instance_attestation_sha256 = attestation.instances[0].instance_attestation_sha256;
  assertRejected(attestation, "instance_attestation_mismatch");
});

test("candidate, source/tree, run, role, and schema substitutions fail closed", () => {
  const candidate = qualificationEvidence();
  candidate.candidate_id = OTHER_CANDIDATE;
  assertRejected(candidate);
  const source = qualificationEvidence();
  source.source_commit = OTHER_SOURCE;
  assertRejected(source);
  const tree = qualificationEvidence();
  tree.source_tree = OTHER_SOURCE;
  assertRejected(tree);
  const run = qualificationEvidence();
  run.run = { ...OTHER_RUN };
  assertRejected(run, "binding_mismatch");
  const roleSubstitution = qualificationEvidence();
  roleSubstitution.instances[0].role.current_user = "agentpass_app";
  assertRejected(roleSubstitution, "role_evidence_mismatch");
  const schema = qualificationEvidence();
  schema.schema_head = { ...schema.schema_head, checksum: HASH_3 };
  assertRejected(schema, "schema_head_mismatch");
});

test("PITR recovery target, manifest, WAL replay, and status are bound", () => {
  const target = qualificationEvidence();
  target.pitr.recovery_target_sha256 = HASH_3;
  assertRejected(target, "pitr_binding_mismatch");
  const manifest = qualificationEvidence();
  manifest.pitr.restored_manifest_sha256 = HASH_2;
  assertRejected(manifest, "pitr_binding_mismatch");
  const wal = qualificationEvidence();
  wal.pitr.wal_replay.replayed = false;
  assertRejected(wal, "wal_replay_unverified");
  const lsn = qualificationEvidence();
  lsn.pitr.wal_replay.replay_lsn_sha256 = "not-a-digest";
  assertRejected(lsn, "wal_replay_unverified");
});

test("CLI rejects noncanonical evidence bytes as not_proven", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-postgres-qualification-"));
  const file = path.join(directory, "evidence.json");
  fs.writeFileSync(file, `${JSON.stringify(qualificationEvidence())}\n`, { mode: 0o600 });
  const result = runCli(...cliArgs(file));
  assert.equal(result.status, 2);
  assert.deepEqual(stdoutJson(result), { status: "not_proven", reason: "noncanonical_evidence" });
});

test("CLI returns stable not_proven and nonzero status when live evidence is unavailable", () => {
  const result = runCli();
  assert.equal(result.status, 2);
  assert.deepEqual(stdoutJson(result), NOT_PROVEN);
});

test("the canonical fixture is newline-terminated canonical JSON and the expected run is required", () => {
  const bytes = `${canonicalJson(qualificationEvidence())}\n`;
  assert.equal(JSON.parse(bytes).candidate_id, CANDIDATE);
  assert.equal(bytes.endsWith("\n"), true);
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-postgres-qualification-")), "evidence.json");
  fs.writeFileSync(file, bytes, { mode: 0o600 });
  const result = runCli("verify", file, CANDIDATE, SOURCE, SOURCE_TREE, RUN.ci_run_id, RUN.ci_run_attempt, "9999");
  assert.equal(result.status, 2);
  assert.deepEqual(stdoutJson(result), { status: "not_proven", reason: "binding_mismatch" });
});
