#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { POSTGRES_SCHEMA_HEAD } from "../../apps/cloud-api/src/postgres/schema-head.mjs";

const SHA256 = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const CANDIDATE = /^release-pkg-sha256-v1-[0-9a-f]{64}$/u;
const POSITIVE_ID = /^[1-9][0-9]{0,19}$/u;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const INSTANCE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$/u;
const RUNNER_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const RECOVERY_TARGET = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;
const DISALLOWED_RUNNER = /(?:^|[._:/ -])(local|static|unit|mock|fixture|fake|simulator|emulator|test|macos-latest)(?:$|[._:/ -])/iu;
const EXPECTED_BACKUP_ROLE = "agentpass_backup";
const INSTANCE_PURPOSES = Object.freeze(["restore", "pitr"]);
const MAX_BYTES = 128 * 1024;
const TOP_LEVEL_KEYS = Object.freeze([
  "after_manifest_sha256", "artifact_sha256", "backup_artifact_sha256", "before_manifest_sha256",
  "candidate_id", "compare_same", "execution", "instances", "kind", "pitr", "restore_artifact_sha256",
  "role_evidence_sha256", "run", "schema_head", "source_commit", "source_tree", "version"
].sort());
const RUN_KEYS = Object.freeze(["ci_job_id", "ci_run_attempt", "ci_run_id"]);
const EXECUTION_KEYS = Object.freeze(["environment", "evidence_origin", "real_execution", "runner_id"]);
const INSTANCE_KEYS = Object.freeze([
  "artifact_sha256", "candidate_id", "instance_attestation_sha256", "instance_id", "instance_identity_sha256",
  "purpose", "role", "run", "schema_head", "source_commit", "source_tree"
].sort());
const ROLE_KEYS = Object.freeze(["current_user", "dml_denied", "name", "read_only", "session_user", "tls"]);
const SCHEMA_KEYS = Object.freeze(["checksum", "name", "version"]);
const PITR_KEYS = Object.freeze([
  "candidate_id", "instance_id", "recovery_target", "recovery_target_sha256", "restored_manifest_sha256", "status", "wal_replay"
].sort());
const WAL_KEYS = Object.freeze(["instance_id", "recovery_state", "replayed", "replay_lsn_sha256", "status"]);

export const NOT_PROVEN = Object.freeze({
  status: "not_proven",
  reason: "live_postgres_qualification_unavailable",
  required: Object.freeze([
    "two_distinct_postgres_instances_for_restore_and_pitr",
    "external_real_execution_attestation",
    "role_privilege_evidence_for_each_instance",
    "schema_head_evidence_for_each_instance",
    "candidate_source_tree_run_and_artifact_binding",
    "backup_and_restore_artifact_binding",
    "pitr_restore_and_manifest_compare",
    "wal_replay_confirmation"
  ])
});

export class BackupRestoreQualificationError extends Error {
  constructor(code) {
    super(code);
    this.name = "BackupRestoreQualificationError";
    this.code = code;
  }
}

function fail(code) { throw new BackupRestoreQualificationError(code); }
function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}
function sameArray(left, right) {
  return Array.isArray(left) && left.length === right.length && left.every((item, index) => item === right[index]);
}
function exactKeys(value, keys) { return plainObject(value) && sameArray(Object.keys(value).sort(), [...keys].sort()); }
function validDigest(value) { return typeof value === "string" && SHA256.test(value); }
function validCommit(value) { return typeof value === "string" && COMMIT.test(value); }
function validRun(value) {
  return exactKeys(value, RUN_KEYS)
    && POSITIVE_ID.test(value.ci_run_id ?? "")
    && POSITIVE_ID.test(value.ci_run_attempt ?? "")
    && SAFE_ID.test(value.ci_job_id ?? "");
}
function validateExpected(value, expected) { if (expected !== undefined && canonicalJson(value) !== canonicalJson(expected)) fail("binding_mismatch"); }

function validateSchemaHead(value) {
  if (!exactKeys(value, SCHEMA_KEYS)
    || value.version !== POSTGRES_SCHEMA_HEAD.version
    || value.name !== POSTGRES_SCHEMA_HEAD.name
    || value.checksum !== POSTGRES_SCHEMA_HEAD.checksum) fail("schema_head_mismatch");
}

function validateExecution(value) {
  if (!exactKeys(value, EXECUTION_KEYS)
    || value.environment !== "postgresql"
    || value.evidence_origin !== "protected_external"
    || value.real_execution !== true
    || typeof value.runner_id !== "string"
    || !RUNNER_ID.test(value.runner_id)
    || DISALLOWED_RUNNER.test(value.runner_id)) fail("execution_not_external");
}

function validateRole(value) {
  if (!exactKeys(value, ROLE_KEYS)
    || value.name !== EXPECTED_BACKUP_ROLE
    || value.current_user !== EXPECTED_BACKUP_ROLE
    || value.session_user !== EXPECTED_BACKUP_ROLE
    || value.dml_denied !== true || value.read_only !== true || value.tls !== true) {
    fail("role_evidence_mismatch");
  }
}

function validateInstance(value, expected, expectedRun, expectedSourceCommit, expectedSourceTree) {
  if (!exactKeys(value, INSTANCE_KEYS)
    || value.candidate_id !== expected.candidateId
    || !INSTANCE_ID.test(value.instance_id ?? "")
    || !INSTANCE_PURPOSES.includes(value.purpose)
    || !validDigest(value.instance_identity_sha256)
    || !validDigest(value.instance_attestation_sha256)
    || value.source_commit !== expectedSourceCommit
    || value.source_tree !== expectedSourceTree
    || value.artifact_sha256 !== (value.purpose === "restore" ? expected.restoreArtifact : expected.backupArtifact)) {
    fail("instance_binding_mismatch");
  }
  validateExpected(value.run, expectedRun);
  if (!validRun(value.run)) fail("run_binding_mismatch");
  validateSchemaHead(value.schema_head);
  validateRole(value.role);
  if (value.instance_identity_sha256 === value.instance_attestation_sha256) fail("instance_attestation_mismatch");
}

function validateWalReplay(value, pitrInstanceId) {
  if (!exactKeys(value, WAL_KEYS)
    || value.instance_id !== pitrInstanceId
    || value.status !== "verified"
    || value.replayed !== true
    || !["recovery", "promoted"].includes(value.recovery_state)
    || !validDigest(value.replay_lsn_sha256)) fail("wal_replay_unverified");
}

function validatePitr(value, candidateId, afterManifestSha256, pitrInstanceId) {
  if (!exactKeys(value, PITR_KEYS)
    || value.candidate_id !== candidateId
    || value.instance_id !== pitrInstanceId
    || value.status !== "verified"
    || typeof value.recovery_target !== "string"
    || !RECOVERY_TARGET.test(value.recovery_target)
    || !validDigest(value.recovery_target_sha256)
    || value.recovery_target_sha256 !== sha256(value.recovery_target)
    || value.restored_manifest_sha256 !== afterManifestSha256) fail("pitr_binding_mismatch");
  validateWalReplay(value.wal_replay, pitrInstanceId);
}

function aggregateRoleEvidence(instances) {
  return sha256(Buffer.from(canonicalJson(instances.map((instance) => ({
    instance_id: instance.instance_id,
    purpose: instance.purpose,
    role_evidence_sha256: sha256(Buffer.from(canonicalJson(instance.role), "utf8"))
  }))), "utf8"));
}

function assertSecretFree(value, key = "") {
  const sensitiveKey = /(?:password|secret|private[._ -]*key|credential|authorization|cookie|api[._ -]*key|connection[._ -]*(?:string|url)|token|dsn)/iu;
  if (sensitiveKey.test(key)) fail("sensitive_evidence");
  if (typeof value === "string" && (/postgres(?:ql)?:\/\//iu.test(value) || /-----BEGIN [A-Z ]+-----/u.test(value))) {
    fail("sensitive_evidence");
  }
  if (Array.isArray(value)) value.forEach((item) => assertSecretFree(item, key));
  else if (plainObject(value)) Object.entries(value).forEach(([name, item]) => assertSecretFree(item, name));
}

export function verifyBackupRestoreQualification(value, {
  expectedCandidateId,
  expectedSourceCommit,
  expectedSourceTree,
  expectedRun
} = {}) {
  if (!exactKeys(value, TOP_LEVEL_KEYS)
    || value.version !== 1
    || value.kind !== "agentpass-postgres-backup-restore-qualification"
    || !CANDIDATE.test(value.candidate_id ?? "")
    || !CANDIDATE.test(expectedCandidateId ?? "")
    || value.candidate_id !== expectedCandidateId
    || !validCommit(value.source_commit)
    || !validCommit(expectedSourceCommit ?? "")
    || value.source_commit !== expectedSourceCommit
    || !validCommit(value.source_tree)
    || !validCommit(expectedSourceTree ?? "")
    || value.source_tree !== expectedSourceTree
    || !validDigest(value.artifact_sha256)
    || !validDigest(value.backup_artifact_sha256)
    || !validDigest(value.restore_artifact_sha256)
    || value.compare_same !== true
    || !validRun(value.run)
    || !Array.isArray(value.instances)
    || value.instances.length !== INSTANCE_PURPOSES.length
    || !validDigest(value.before_manifest_sha256)
    || !validDigest(value.after_manifest_sha256)
    || value.before_manifest_sha256 !== value.after_manifest_sha256
    || !validDigest(value.role_evidence_sha256)) fail("invalid_or_unclosed_evidence");

  assertSecretFree(value);
  validateExecution(value.execution);
  validateExpected(value.run, expectedRun);
  const expected = {
    candidateId: value.candidate_id,
    backupArtifact: value.backup_artifact_sha256,
    restoreArtifact: value.restore_artifact_sha256
  };
  value.instances.forEach((instance) => validateInstance(instance, expected, value.run, value.source_commit, value.source_tree));
  const purposes = new Set(value.instances.map((instance) => instance.purpose));
  const identities = new Set(value.instances.map((instance) => instance.instance_identity_sha256));
  const attestations = new Set(value.instances.map((instance) => instance.instance_attestation_sha256));
  if (purposes.size !== 2 || identities.size !== 2 || attestations.size !== 2
    || value.instances.some((instance) => instance.purpose === "restore" && instance.artifact_sha256 !== value.restore_artifact_sha256)
    || value.instances.some((instance) => instance.purpose === "pitr" && instance.artifact_sha256 !== value.backup_artifact_sha256)) {
    fail("duplicate_or_misbound_instance");
  }
  if (value.role_evidence_sha256 !== aggregateRoleEvidence(value.instances)) fail("role_evidence_mismatch");
  validateSchemaHead(value.schema_head);
  if (value.instances.some((instance) => canonicalJson(instance.schema_head) !== canonicalJson(value.schema_head))) fail("schema_head_mismatch");
  const pitrInstance = value.instances.find((instance) => instance.purpose === "pitr");
  validatePitr(value.pitr, value.candidate_id, value.after_manifest_sha256, pitrInstance.instance_id);

  return Object.freeze({
    status: "closed",
    candidate_id: value.candidate_id,
    source_commit: value.source_commit,
    source_tree: value.source_tree,
    run: Object.freeze({ ...value.run }),
    instance_count: 2,
    schema_head: Object.freeze({ version: value.schema_head.version, checksum: value.schema_head.checksum }),
    pitr_restore: "verified",
    wal_replay: "verified",
    evidence_sha256: sha256(Buffer.from(`${canonicalJson(value)}\n`, "utf8"))
  });
}

async function readEvidence(file) {
  if (typeof file !== "string" || !path.isAbsolute(file)) throw new BackupRestoreQualificationError("invalid_evidence_file");
  let stat;
  try { stat = fs.statSync(file); } catch { throw new BackupRestoreQualificationError("invalid_evidence_file"); }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0
    || stat.size < 1 || stat.size > MAX_BYTES) throw new BackupRestoreQualificationError("invalid_evidence_file");
  let text;
  try { text = fs.readFileSync(file, "utf8"); } catch { throw new BackupRestoreQualificationError("invalid_evidence_file"); }
  if (!text.endsWith("\n")) throw new BackupRestoreQualificationError("invalid_evidence_file");
  let value;
  try { value = JSON.parse(text); } catch { throw new BackupRestoreQualificationError("invalid_evidence_file"); }
  if (`${canonicalJson(value)}\n` !== text) throw new BackupRestoreQualificationError("noncanonical_evidence");
  return value;
}

function output(value) { process.stdout.write(`${JSON.stringify(value)}\n`); }

async function main() {
  const [command, file, expectedCandidateId, expectedSourceCommit, expectedSourceTree, runId, runAttempt, jobId] = process.argv.slice(2);
  if (command !== "verify" || !file || !expectedCandidateId || !expectedSourceCommit || !expectedSourceTree
    || !runId || !runAttempt || !jobId || process.argv.length !== 10) {
    output(NOT_PROVEN);
    process.exitCode = 2;
    return;
  }
  try {
    const result = verifyBackupRestoreQualification(await readEvidence(path.resolve(file)), {
      expectedCandidateId,
      expectedSourceCommit,
      expectedSourceTree,
      expectedRun: { ci_run_id: runId, ci_run_attempt: runAttempt, ci_job_id: jobId }
    });
    output(result);
  } catch (error) {
    output({ status: "not_proven", reason: error instanceof BackupRestoreQualificationError ? error.code : "verification_failed" });
    process.exitCode = 2;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
