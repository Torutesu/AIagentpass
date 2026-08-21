#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import {
  assertExternalQualificationEvidence,
  scanProtectedArtifacts
} from "./ci-preflight.mjs";

const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._@:/-]{1,127}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const MAX_REVIEW_VALIDITY_MS = 30 * 24 * 60 * 60 * 1_000;
const MAX_EVIDENCE_BYTES = 16 * 1024 * 1024;
const MAX_ARTIFACT_BYTES = 16 * 1024 * 1024 * 1024;
const PLACEHOLDER = /^(?:0+|f+|x+|unknown|unset|null|none|n\/a|not[_ -]?run|placeholder|example|dummy|fake|fixture|simulated)$/iu;

const PREFLIGHT_KEYS = Object.freeze([
  "backup_pitr", "ca", "candidate", "external", "expiry", "kind", "operator_id", "rollback", "schema_version"
]);
const CANDIDATE_KEYS = Object.freeze([
  "artifact_name", "artifact_sha256", "candidate_id", "manifest_sha256", "source_commit", "source_tree"
]);
const DIGEST_REF_KEYS = Object.freeze(["evidence_sha256"]);
const EXTERNAL_REF_KEYS = Object.freeze(["binding_sha256", "evidence_sha256"]);
const EXPIRY_KEYS = Object.freeze(["expires_at", "report_sha256", "reviewed_at", "reviewer_id"]);

export class OperatorPreflightError extends Error {
  constructor(message) {
    super(message);
    this.name = "OperatorPreflightError";
  }
}

export function verifyOperatorPreflight(packet, {
  manifestPath,
  artifactPath,
  caEvidencePath,
  backupPitrEvidencePath,
  externalEvidencePath,
  externalBindingPath,
  rollbackEvidencePath,
  reviewerReportPath,
  now = new Date()
} = {}) {
  const nowMs = parseNow(now);
  const normalizedPacket = normalizePacket(packet);
  const manifest = readCanonicalFile(manifestPath, "release manifest", MAX_EVIDENCE_BYTES);
  const artifact = snapshotRegularFile(artifactPath, "release artifact", MAX_ARTIFACT_BYTES);
  const ca = readCanonicalFile(caEvidencePath, "CA evidence", MAX_EVIDENCE_BYTES);
  const backup = readCanonicalFile(backupPitrEvidencePath, "backup/PITR evidence", MAX_EVIDENCE_BYTES);
  const external = readCanonicalFile(externalEvidencePath, "external qualification evidence", MAX_EVIDENCE_BYTES);
  const externalBinding = readCanonicalFile(externalBindingPath, "external qualification binding", MAX_EVIDENCE_BYTES);
  const rollback = readCanonicalFile(rollbackEvidencePath, "rollback evidence", MAX_EVIDENCE_BYTES);
  const reviewerReport = snapshotRegularFile(reviewerReportPath, "review report", MAX_EVIDENCE_BYTES);

  assertReference(normalizedPacket.ca.evidence_sha256, ca.sha256, "CA evidence");
  assertReference(normalizedPacket.backup_pitr.evidence_sha256, backup.sha256, "backup/PITR evidence");
  assertReference(normalizedPacket.external.evidence_sha256, external.sha256, "external qualification evidence");
  assertReference(normalizedPacket.external.binding_sha256, externalBinding.sha256, "external qualification binding");
  assertReference(normalizedPacket.rollback.evidence_sha256, rollback.sha256, "rollback evidence");
  assertCandidateBinding(normalizedPacket.candidate, manifest.value, manifest.sha256, artifact, artifactPath);
  assertCaEvidence(ca.value, normalizedPacket, nowMs);
  assertBackupPitrEvidence(backup.value, normalizedPacket, nowMs);
  assertExternalEvidence(external.value, externalBinding.value, normalizedPacket.candidate);
  assertRollbackEvidence(rollback.value, normalizedPacket.candidate, nowMs);
  assertExpiry(normalizedPacket.expiry, reviewerReport.sha256, nowMs, ca.value.expires_at);

  return Object.freeze({
    schema_version: 1,
    kind: "agentpass-protected-operator-preflight",
    status: "passed",
    qualified: true,
    operator_id: normalizedPacket.operator_id,
    candidate: Object.freeze({ ...normalizedPacket.candidate }),
    evidence: Object.freeze({
      artifact_sha256: artifact.sha256,
      manifest_sha256: manifest.sha256,
      ca_sha256: ca.sha256,
      backup_pitr_sha256: backup.sha256,
      external_sha256: external.sha256,
      external_binding_sha256: externalBinding.sha256,
      rollback_sha256: rollback.sha256,
      reviewer_report_sha256: reviewerReport.sha256
    }),
    expiry: Object.freeze({ ...normalizedPacket.expiry }),
    checks: Object.freeze({
      ca: "passed",
      backup_pitr: "passed",
      artifact_binding: "passed",
      external_evidence: "passed",
      expiry: "passed",
      rollback: "passed"
    })
  });
}

function normalizePacket(value) {
  exactObject(value, PREFLIGHT_KEYS, "operator preflight packet");
  if (value.schema_version !== 1 || value.kind !== "agentpass-protected-operator-preflight") {
    throw new OperatorPreflightError("operator preflight packet kind/version is invalid");
  }
  assertIdentifier(value.operator_id, "operator_id");
  exactObject(value.candidate, CANDIDATE_KEYS, "operator preflight candidate");
  assertDigest(value.candidate.artifact_sha256, "candidate artifact SHA-256");
  assertDigest(value.candidate.manifest_sha256, "candidate manifest SHA-256");
  assertSha(value.candidate.source_commit, "candidate source commit");
  assertSha(value.candidate.source_tree, "candidate source tree");
  assertIdentifier(value.candidate.artifact_name, "candidate artifact name");
  if (!/^release-pkg-sha256-v1-[0-9a-f]{64}$/u.test(value.candidate.candidate_id)
    || value.candidate.candidate_id !== `release-pkg-sha256-v1-${value.candidate.artifact_sha256}`) {
    throw new OperatorPreflightError("candidate_id is not derived from the declared artifact digest");
  }
  exactObject(value.ca, DIGEST_REF_KEYS, "CA evidence reference");
  assertDigest(value.ca.evidence_sha256, "CA evidence digest");
  exactObject(value.backup_pitr, DIGEST_REF_KEYS, "backup/PITR evidence reference");
  assertDigest(value.backup_pitr.evidence_sha256, "backup/PITR evidence digest");
  exactObject(value.external, EXTERNAL_REF_KEYS, "external evidence reference");
  assertDigest(value.external.evidence_sha256, "external evidence digest");
  assertDigest(value.external.binding_sha256, "external binding digest");
  exactObject(value.rollback, DIGEST_REF_KEYS, "rollback evidence reference");
  assertDigest(value.rollback.evidence_sha256, "rollback evidence digest");
  exactObject(value.expiry, EXPIRY_KEYS, "review expiry");
  assertIdentifier(value.expiry.reviewer_id, "reviewer_id");
  assertDigest(value.expiry.report_sha256, "review report digest");
  assertTimestamp(value.expiry.reviewed_at, "reviewed_at");
  assertTimestamp(value.expiry.expires_at, "expires_at");
  return Object.freeze({ ...value });
}

function assertCandidateBinding(candidate, manifest, manifestSha256, artifact, artifactPath) {
  if (candidate.manifest_sha256 !== manifestSha256 || candidate.artifact_sha256 !== artifact.sha256) {
    throw new OperatorPreflightError("manifest or artifact digest does not match the operator packet");
  }
  if (path.basename(path.resolve(artifactPath)) !== candidate.artifact_name) {
    throw new OperatorPreflightError("artifact basename is not bound to candidate artifact_name");
  }
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)
    || !manifest.source || manifest.source.commit !== candidate.source_commit || manifest.source.tree !== candidate.source_tree
    || manifest.candidate_id !== candidate.candidate_id || !Array.isArray(manifest.artifacts)) {
    throw new OperatorPreflightError("release manifest source or candidate binding is invalid");
  }
  const products = manifest.artifacts.filter((item) => item?.role === "product");
  if (products.length !== 1 || products[0].name !== candidate.artifact_name || products[0].sha256 !== candidate.artifact_sha256) {
    throw new OperatorPreflightError("release manifest product artifact binding is invalid");
  }
}

function assertCaEvidence(value, packet, nowMs) {
  exactObject(value, [
    "artifact_sha256", "expires_at", "kind", "leaf_sha256", "qualified", "schema_version", "server_name",
    "source_commit", "source_tree", "status", "trust_anchor_sha256", "trust_store", "verified_at"
  ], "CA evidence");
  if (value.schema_version !== 1 || value.kind !== "agentpass-ca-verification"
    || value.status !== "passed" || value.qualified !== true
    || value.artifact_sha256 !== packet.candidate.artifact_sha256
    || value.source_commit !== packet.candidate.source_commit || value.source_tree !== packet.candidate.source_tree) {
    throw new OperatorPreflightError("CA evidence is not a passed candidate-bound result");
  }
  assertDigest(value.leaf_sha256, "CA leaf fingerprint");
  assertDigest(value.trust_anchor_sha256, "CA trust-anchor fingerprint");
  assertIdentifier(value.server_name, "CA server name");
  assertIdentifier(value.trust_store, "CA trust store");
  assertTimestamp(value.verified_at, "CA verified_at");
  assertTimestamp(value.expires_at, "CA expires_at");
  const verifiedAtMs = Date.parse(value.verified_at);
  const expiresAtMs = Date.parse(value.expires_at);
  if (verifiedAtMs > nowMs || expiresAtMs <= verifiedAtMs || expiresAtMs <= nowMs || expiresAtMs < Date.parse(packet.expiry.expires_at)) {
    throw new OperatorPreflightError("CA evidence is expired, future-dated, or does not cover the review window");
  }
}

function assertBackupPitrEvidence(value, packet, nowMs) {
  exactObject(value, [
    "artifact_sha256", "authority_compared", "backup_completed_at", "backup_id", "kind", "qualified", "provider",
    "recovery_point_at", "restore_completed_at", "restore_target_id", "restored_authority_sha256", "rpo_seconds",
    "rto_seconds", "schema_version", "source_authority_sha256", "source_commit", "source_tree", "status",
    "isolated_restore", "no_live_restore"
  ], "backup/PITR evidence");
  if (value.schema_version !== 1 || value.kind !== "agentpass-backup-pitr-verification"
    || value.status !== "passed" || value.qualified !== true || value.artifact_sha256 !== packet.candidate.artifact_sha256
    || value.source_commit !== packet.candidate.source_commit || value.source_tree !== packet.candidate.source_tree
    || value.authority_compared !== true || value.isolated_restore !== true || value.no_live_restore !== true) {
    throw new OperatorPreflightError("backup/PITR evidence is not a passed isolated candidate-bound result");
  }
  assertIdentifier(value.provider, "backup provider");
  assertIdentifier(value.backup_id, "backup ID");
  assertIdentifier(value.restore_target_id, "PITR restore target ID");
  assertDigest(value.source_authority_sha256, "source authority digest");
  assertDigest(value.restored_authority_sha256, "restored authority digest");
  if (value.source_authority_sha256 !== value.restored_authority_sha256) {
    throw new OperatorPreflightError("PITR authority comparison does not match");
  }
  if (!Number.isSafeInteger(value.rpo_seconds) || value.rpo_seconds < 0
    || !Number.isSafeInteger(value.rto_seconds) || value.rto_seconds <= 0) {
    throw new OperatorPreflightError("backup/PITR RPO/RTO are not measured values");
  }
  for (const [key, label] of [["backup_completed_at", "backup_completed_at"], ["recovery_point_at", "recovery_point_at"], ["restore_completed_at", "restore_completed_at"]]) {
    assertTimestamp(value[key], label);
  }
  const backupAt = Date.parse(value.backup_completed_at);
  const recoveryAt = Date.parse(value.recovery_point_at);
  const restoreAt = Date.parse(value.restore_completed_at);
  if (backupAt > restoreAt || recoveryAt > restoreAt || restoreAt > nowMs) {
    throw new OperatorPreflightError("backup/PITR evidence timestamps are not an executed completed sequence");
  }
}

function assertExternalEvidence(value, binding, candidate) {
  exactObject(binding, [
    "ci_run_attempt", "ci_run_id", "gate_artifacts", "gate_job_ids", "release_artifact_sha256", "repository", "source_commit", "source_tree"
  ], "external qualification binding");
  const verified = assertExternalQualificationEvidence(value, {
    expectedRepository: binding.repository,
    expectedSourceCommit: candidate.source_commit,
    expectedSourceTree: candidate.source_tree,
    expectedReleaseArtifactSha256: candidate.artifact_sha256,
    expectedCiRunId: binding.ci_run_id,
    expectedCiRunAttempt: binding.ci_run_attempt,
    expectedGateArtifacts: binding.gate_artifacts,
    expectedGateJobIds: binding.gate_job_ids
  });
  if (verified.status !== "passed" || verified.qualified !== true
    || binding.source_commit !== candidate.source_commit || binding.source_tree !== candidate.source_tree
    || binding.release_artifact_sha256 !== candidate.artifact_sha256) {
    throw new OperatorPreflightError("external qualification evidence is not a passed candidate-bound result");
  }
}

function assertRollbackEvidence(value, candidate, nowMs) {
  exactObject(value, [
    "artifact_sha256", "candidate_id", "current_revision", "deployment_id", "environment", "executed_at", "job_id",
    "kind", "qualified", "reused_artifact", "rollback_target_revision", "run_attempt", "run_id", "schema_version",
    "source_commit", "source_tree", "status", "target_ready", "tested", "traffic_restored"
  ], "rollback evidence");
  if (value.schema_version !== 1 || value.kind !== "agentpass-rollback-verification" || value.status !== "passed"
    || value.qualified !== true || value.tested !== true || value.target_ready !== true || value.traffic_restored !== true
    || value.reused_artifact !== true || value.environment !== "staging"
    || value.candidate_id !== candidate.candidate_id || value.artifact_sha256 !== candidate.artifact_sha256
    || value.source_commit !== candidate.source_commit || value.source_tree !== candidate.source_tree) {
    throw new OperatorPreflightError("rollback evidence is not an executed immutable-candidate result");
  }
  assertIdentifier(value.deployment_id, "rollback deployment ID");
  assertIdentifier(value.current_revision, "rollback current revision");
  assertIdentifier(value.rollback_target_revision, "rollback target revision");
  assertIdentifier(value.job_id, "rollback job ID");
  if (value.current_revision === value.rollback_target_revision || !RUN_ID.test(value.run_id) || !RUN_ID.test(value.run_attempt)) {
    throw new OperatorPreflightError("rollback revisions or run binding are invalid");
  }
  assertTimestamp(value.executed_at, "rollback executed_at");
  if (Date.parse(value.executed_at) > nowMs) throw new OperatorPreflightError("rollback evidence is future-dated");
}

function assertExpiry(value, reviewerReportSha256, nowMs, caExpiresAt) {
  if (value.report_sha256 !== reviewerReportSha256) throw new OperatorPreflightError("review report digest is not bound");
  const reviewedAtMs = Date.parse(value.reviewed_at);
  const expiresAtMs = Date.parse(value.expires_at);
  if (reviewedAtMs > nowMs || expiresAtMs <= nowMs || expiresAtMs <= reviewedAtMs
    || expiresAtMs - reviewedAtMs > MAX_REVIEW_VALIDITY_MS || expiresAtMs > Date.parse(caExpiresAt)) {
    throw new OperatorPreflightError("review or CA expiry is invalid");
  }
}

function readCanonicalFile(input, label, maximumBytes) {
  const snapshot = snapshotRegularFile(input, label, maximumBytes, true);
  let value;
  try { value = JSON.parse(snapshot.bytes.toString("utf8")); }
  catch { throw new OperatorPreflightError(`${label} is not valid JSON`); }
  if (canonicalJson(value) !== snapshot.bytes.toString("utf8")) throw new OperatorPreflightError(`${label} is not canonical JSON`);
  try { scanProtectedArtifacts([snapshot.path]); }
  catch { throw new OperatorPreflightError(`${label} failed secret/file safety scan`); }
  return { ...snapshot, value };
}

function snapshotRegularFile(input, label, maximumBytes, capture = false) {
  if (typeof input !== "string" || input.length === 0 || input.length > 1_024) throw new OperatorPreflightError(`${label} path is invalid`);
  let fd;
  try { fd = fs.openSync(path.resolve(input), fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0)); }
  catch { throw new OperatorPreflightError(`${label} is unavailable`); }
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(maximumBytes)) throw new OperatorPreflightError(`${label} must be a nonempty single-link regular file`);
    const hash = crypto.createHash("sha256");
    const chunks = capture ? [] : undefined;
    const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, Number(before.size)));
    let offset = 0;
    while (offset < Number(before.size)) {
      const wanted = Math.min(buffer.length, Number(before.size) - offset);
      const count = fs.readSync(fd, buffer, 0, wanted, offset);
      if (count === 0) throw new OperatorPreflightError(`${label} changed while being read`);
      const chunk = buffer.subarray(0, count);
      hash.update(chunk);
      if (chunks) chunks.push(Buffer.from(chunk));
      offset += count;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.mode !== after.mode || before.nlink !== after.nlink || before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) throw new OperatorPreflightError(`${label} changed while being read`);
    return { path: path.resolve(input), bytes: chunks ? Buffer.concat(chunks, Number(before.size)) : undefined, sha256: hash.digest("hex") };
  } finally { fs.closeSync(fd); }
}

function assertReference(expected, actual, label) {
  if (expected !== actual) throw new OperatorPreflightError(`${label} digest is not bound to the supplied file`);
}

function parseNow(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new OperatorPreflightError("preflight clock is invalid");
  return date.getTime();
}

function assertTimestamp(value, label) {
  if (typeof value !== "string" || !TIMESTAMP.test(value) || !Number.isFinite(Date.parse(value))) throw new OperatorPreflightError(`${label} is invalid`);
}

function assertSha(value, label) {
  if (typeof value !== "string" || !SHA.test(value) || PLACEHOLDER.test(value)) throw new OperatorPreflightError(`${label} is invalid or placeholder`);
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !DIGEST.test(value) || PLACEHOLDER.test(value)) throw new OperatorPreflightError(`${label} is invalid or placeholder`);
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER.test(value) || PLACEHOLDER.test(value)) throw new OperatorPreflightError(`${label} is invalid or placeholder`);
}

function exactObject(value, keys, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new OperatorPreflightError(`${label} is invalid`);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) throw new OperatorPreflightError(`${label} fields are invalid`);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, "value")) throw new OperatorPreflightError(`${label} property is not a data property`);
  }
}

function usage() {
  return [
    "usage:",
    "  operator-preflight.mjs verify PACKET.json MANIFEST.json ARTIFACT CA.json BACKUP-PITR.json EXTERNAL.json EXTERNAL-BINDING.json ROLLBACK.json REVIEW-REPORT"
  ].join("\n");
}

export function runCli(argv = process.argv.slice(2)) {
  const [command, ...args] = argv;
  // The CLI is the production operator gate.  A caller must never be able to
  // move its clock backwards and make expired evidence pass.  Deterministic
  // replay tests use verifyOperatorPreflight() directly with an explicit `now`.
  if (command !== "verify" || args.length !== 9) throw new OperatorPreflightError(usage());
  const packet = readCanonicalFile(args[0], "operator preflight packet", MAX_EVIDENCE_BYTES).value;
  const result = verifyOperatorPreflight(packet, {
    manifestPath: args[1], artifactPath: args[2], caEvidencePath: args[3], backupPitrEvidencePath: args[4],
    externalEvidencePath: args[5], externalBindingPath: args[6], rollbackEvidencePath: args[7], reviewerReportPath: args[8],
    now: new Date()
  });
  return result;
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  try { process.stdout.write(`${canonicalJson(runCli())}\n`); }
  catch (error) {
    process.stderr.write(`operator preflight failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
