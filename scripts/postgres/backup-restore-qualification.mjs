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
const MAX_BYTES = 128 * 1024;
const TOP_LEVEL_KEYS = Object.freeze([
  "after_manifest_sha256", "artifact_sha256", "before_manifest_sha256", "candidate_id",
  "compare_same", "instances", "kind", "pitr", "role_evidence_sha256", "schema_head",
  "source_commit", "version"
].sort());

export const NOT_PROVEN = Object.freeze({
  status: "not_proven",
  reason: "live_postgres_qualification_unavailable",
  required: Object.freeze([
    "two_distinct_postgres_instances",
    "role_privilege_evidence_for_each_instance",
    "schema_head_evidence_for_each_instance",
    "candidate_bound_backup_and_restore_artifact",
    "pitr_restore_and_manifest_compare"
  ])
});

export class BackupRestoreQualificationError extends Error {
  constructor(code) {
    super(code);
    this.name = "BackupRestoreQualificationError";
    this.code = code;
  }
}

export function verifyBackupRestoreQualification(value, { expectedCandidateId, expectedSourceCommit } = {}) {
  if (!plainObject(value) || !sameArray(Object.keys(value).sort(), TOP_LEVEL_KEYS)
    || value.version !== 1 || value.kind !== "agentpass-postgres-backup-restore-qualification"
    || !CANDIDATE.test(value.candidate_id) || !CANDIDATE.test(expectedCandidateId ?? "") || value.candidate_id !== expectedCandidateId
    || !COMMIT.test(value.source_commit) || !COMMIT.test(expectedSourceCommit ?? "") || value.source_commit !== expectedSourceCommit
    || !SHA256.test(value.artifact_sha256) || !SHA256.test(value.before_manifest_sha256)
    || !SHA256.test(value.after_manifest_sha256) || !SHA256.test(value.role_evidence_sha256)
    || value.compare_same !== true || !Array.isArray(value.instances) || value.instances.length !== 2
    || !value.instances.every((instance) => validInstance(instance, value.candidate_id))
    || !validPitr(value.pitr, value.before_manifest_sha256, value.after_manifest_sha256, value.candidate_id)
    || !validSchemaHead(value.schema_head)) {
    throw new BackupRestoreQualificationError("invalid_or_unclosed_evidence");
  }
  if (value.instances[0].instance_id === value.instances[1].instance_id
    || value.instances[0].role_evidence_sha256 === value.instances[1].role_evidence_sha256) {
    throw new BackupRestoreQualificationError("duplicate_instance_evidence");
  }
  return Object.freeze({
    status: "closed",
    candidate_id: value.candidate_id,
    source_commit: value.source_commit,
    instance_count: 2,
    schema_head: Object.freeze({ version: value.schema_head.version, checksum: value.schema_head.checksum }),
    pitr_restore: "verified",
    evidence_sha256: sha256(Buffer.from(`${canonicalJson(value)}\n`, "utf8"))
  });
}

async function readEvidence(file) {
  if (typeof file !== "string" || !path.isAbsolute(file)) throw new BackupRestoreQualificationError("invalid_evidence_file");
  let stat;
  try { stat = fs.statSync(file); } catch { throw new BackupRestoreQualificationError("invalid_evidence_file"); }
  if (!stat.isFile() || stat.size < 1 || stat.size > MAX_BYTES) throw new BackupRestoreQualificationError("invalid_evidence_file");
  let text;
  try { text = fs.readFileSync(file, "utf8"); } catch { throw new BackupRestoreQualificationError("invalid_evidence_file"); }
  if (!text.endsWith("\n")) throw new BackupRestoreQualificationError("invalid_evidence_file");
  let value;
  try { value = JSON.parse(text); } catch { throw new BackupRestoreQualificationError("invalid_evidence_file"); }
  if (`${canonicalJson(value)}\n` !== text) throw new BackupRestoreQualificationError("noncanonical_evidence");
  return value;
}

function validInstance(value, candidateId) {
  return plainObject(value)
    && sameArray(Object.keys(value).sort(), ["candidate_id", "instance_id", "role_evidence_sha256", "schema_head"].sort())
    && value.candidate_id === candidateId
    && typeof value.instance_id === "string" && /^[A-Za-z0-9._-]{1,96}$/u.test(value.instance_id)
    && SHA256.test(value.role_evidence_sha256)
    && validSchemaHead(value.schema_head);
}

function validPitr(value, before, after, candidateId) {
  return plainObject(value)
    && sameArray(Object.keys(value).sort(), ["candidate_id", "recovery_target", "restored_manifest_sha256", "status"].sort())
    && value.candidate_id === candidateId && value.status === "verified"
    && typeof value.recovery_target === "string" && value.recovery_target.length >= 1 && value.recovery_target.length <= 128
    && value.restored_manifest_sha256 === after && before === after;
}

function validSchemaHead(value) {
  return plainObject(value)
    && sameArray(Object.keys(value).sort(), ["checksum", "name", "version"].sort())
    && value.version === POSTGRES_SCHEMA_HEAD.version
    && value.name === POSTGRES_SCHEMA_HEAD.name
    && value.checksum === POSTGRES_SCHEMA_HEAD.checksum;
}

function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function sameArray(left, right) { return Array.isArray(left) && left.length === right.length && left.every((item, index) => item === right[index]); }
function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function output(value) { process.stdout.write(`${JSON.stringify(value)}\n`); }

async function main() {
  const [command, file, expectedCandidateId, expectedSourceCommit] = process.argv.slice(2);
  if (command !== "verify" || !file || !expectedCandidateId || !expectedSourceCommit || process.argv.length !== 6) {
    output(NOT_PROVEN);
    process.exitCode = 2;
    return;
  }
  try {
    const result = verifyBackupRestoreQualification(await readEvidence(path.resolve(file)), { expectedCandidateId, expectedSourceCommit });
    output(result);
  } catch (error) {
    output({ status: "not_proven", reason: error instanceof BackupRestoreQualificationError ? error.code : "verification_failed" });
    process.exitCode = 2;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
