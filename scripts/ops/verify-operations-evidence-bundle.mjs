#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalJson } from "../../packages/protocol/src/index.mjs";

export const OPERATIONS_EVIDENCE_BUNDLE_KIND = "agentpass.operations-evidence-bundle";
export const OPERATIONS_EVIDENCE_BUNDLE_SCHEMA_VERSION = 1;
export const OPERATIONS_QUALIFICATION_EVIDENCE_KIND = "agentpass.operations-qualification-evidence";
export const OPERATIONS_QUALIFICATION_EVIDENCE_SCHEMA_VERSION = 1;
export const INDEPENDENT_SECURITY_REVIEW_KIND = "agentpass.independent-security-review";
export const INDEPENDENT_SECURITY_REVIEW_SCHEMA_VERSION = 2;
export const OPERATIONS_EVIDENCE_IDS = Object.freeze([
  "rollback",
  "backup_restore_pitr",
  "emergency_stop",
  "fleet_propagation",
  "alert_delivery"
]);
const CHILD_ASSERTIONS = Object.freeze({
  rollback: ["authority_not_widened", "deployment_rollback_verified", "health_gate_verified", "previous_revision_rejected", "rollback_artifact_digest"],
  backup_restore_pitr: ["backup_created", "restore_verified", "pitr_verified", "schema_head_verified", "tenant_integrity_verified"],
  emergency_stop: ["ack_quorum_verified", "emergency_stop_propagation_verified", "existing_capability_denied", "new_capability_denied", "revoke_propagation_verified", "terminal_state_verified"],
  fleet_propagation: ["all_instances_observed", "revocation_propagation_verified", "stale_instance_rejected", "propagation_deadline_verified"],
  alert_delivery: ["policy_digest_verified", "warning_delivered", "critical_delivered", "escalation_verified", "exporter_reset_fail_closed"]
});
const EMERGENCY_STOP_MEASUREMENT_KEYS = Object.freeze(["propagation_bound_ms", "propagation_observed_ms"]);
const MAX_PROPAGATION_BOUND_MS = 24 * 60 * 60 * 1000;

const SHA256 = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const CANDIDATE = /^release-pkg-sha256-v1-[0-9a-f]{64}$/u;
const IMAGE = /^sha256:[0-9a-f]{64}$/u;
const FINGERPRINT = /^[0-9a-f]{64}$/u;
const FILE = /^[a-z0-9][a-z0-9._-]{0,127}\.json$/u;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const MAX_INDEX_BYTES = 128 * 1024;
const MAX_EVIDENCE_BYTES = 8 * 1024 * 1024;
const MAX_AGE_MS = 24 * 60 * 60 * 1000;
const MAX_REVIEW_BYTES = 1024 * 1024;
const MAX_REVIEW_AGE_MS = 90 * 24 * 60 * 60 * 1000;
const MAX_REVIEW_WINDOW_MS = 90 * 24 * 60 * 60 * 1000;

const ROOT_KEYS = Object.freeze(["candidate_id", "completed_at", "evidence", "image_digest", "kind", "schema_version", "signature", "source_commit", "started_at"]);
const ITEM_KEYS = Object.freeze(["file", "id", "image_digest", "sha256", "source_commit", "status"]);
const SIGNATURE_KEYS = Object.freeze(["algorithm", "public_key_fingerprint", "value"]);
const QUALIFICATION_ROOT_KEYS = Object.freeze(["candidate_id", "completed_at", "evidence_bundle_sha256", "image_digest", "kind", "measurements", "schema_version", "signature", "source_commit", "started_at", "witness"]);
const QUALIFICATION_MEASUREMENT_KEYS = Object.freeze(["check", "evidence_origin", "measurement_sha256", "observed_at", "status"]);
const QUALIFICATION_WITNESS_KEYS = Object.freeze(["kind", "runner_id"]);
const REVIEW_ROOT_KEYS = Object.freeze(["approval", "artifact_digest", "candidate_id", "completed_at", "evidence_bundle_sha256", "expires_at", "findings", "image_digest", "kind", "qualification_evidence_sha256", "reviewer", "retest_evidence", "schema_digest", "schema_version", "signature", "source_commit", "source_tree_sha256", "started_at", "status"]);
const REVIEW_FINDING_KEYS = Object.freeze(["critical", "high", "open_critical_high"]);
const REVIEWER_KEYS = Object.freeze(["kind", "organization", "public_key_fingerprint", "reviewer_id", "role"]);
const RETEST_EVIDENCE_KEYS = Object.freeze(["completed_at", "evidence_sha256", "status"]);
const APPROVAL_KEYS = Object.freeze(["approver_id", "organization", "decision", "public_key_fingerprint", "signature"]);
const LOCAL_WITNESS_MARKER = /(?:^|[-_])(local|fixture|mock|simulated|sandbox|test)(?:$|[-_])/iu;
const NON_INDEPENDENT_REVIEW_MARKER = /\b(?:self|internal|author|owner|local|fixture|mock|simulated|sandbox|static|test)\b/iu;

const REVIEW_SCHEMA_DESCRIPTOR = Object.freeze({
  kind: INDEPENDENT_SECURITY_REVIEW_KIND,
  schema_version: INDEPENDENT_SECURITY_REVIEW_SCHEMA_VERSION,
  root_keys: REVIEW_ROOT_KEYS,
  reviewer_keys: REVIEWER_KEYS,
  findings_keys: REVIEW_FINDING_KEYS,
  retest_evidence_keys: RETEST_EVIDENCE_KEYS,
  approval_keys: Object.freeze(APPROVAL_KEYS.filter((key) => key !== "signature")),
  signature_keys: SIGNATURE_KEYS
});

export class OperationsEvidenceBundleError extends Error {
  constructor(code) { super(code); this.name = "OperationsEvidenceBundleError"; this.code = code; }
}

function fail(code) { throw new OperationsEvidenceBundleError(code); }
function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}
function exactKeys(value, keys, code = "invalid_schema") {
  if (!plainObject(value)) fail(code);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(code);
}
function timestamp(value, code = "invalid_timestamp") {
  if (typeof value !== "string" || !ISO_UTC.test(value) || new Date(value).toISOString() !== value) fail(code);
  return Date.parse(value);
}
function canonicalText(value) { return `${canonicalJson(value)}\n`; }
function sha256(bytes) { return crypto.createHash("sha256").update(bytes).digest("hex"); }

export const INDEPENDENT_SECURITY_REVIEW_SCHEMA_DIGEST = sha256(Buffer.from(canonicalText(REVIEW_SCHEMA_DESCRIPTOR), "utf8"));

function verifyEmergencyStopMeasurement(child) {
  if (!plainObject(child.measurements)) fail("missing_propagation_measurement");
  exactKeys(child.measurements, EMERGENCY_STOP_MEASUREMENT_KEYS, "invalid_propagation_measurement");
  const { propagation_bound_ms: bound, propagation_observed_ms: observed } = child.measurements;
  if (!Number.isSafeInteger(bound) || bound < 1 || bound > MAX_PROPAGATION_BOUND_MS
    || !Number.isSafeInteger(observed) || observed < 0 || observed > bound) {
    fail(observed > bound ? "propagation_bound_exceeded" : "invalid_propagation_measurement");
  }
}

export function readOperationsEvidenceProtectedFile(file, maxBytes, code) {
  if (!path.isAbsolute(file)) fail(code);
  let fd;
  try { fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); } catch { fail(code); }
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size < 1n || before.size > BigInt(maxBytes)) fail(code);
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count === 0) fail(code);
      offset += count;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    const fields = ["dev", "ino", "mode", "nlink", "size", "mtimeNs", "ctimeNs"];
    if (fields.some((field) => before[field] !== after[field])) fail(code);
    return bytes;
  } finally { fs.closeSync(fd); }
}

function parseCanonical(bytes, code) {
  const text = bytes.toString("utf8");
  if (!text.endsWith("\n")) fail("noncanonical_evidence");
  let value;
  try { value = JSON.parse(text); } catch { fail(code); }
  if (`${canonicalJson(value)}\n` !== text) fail("noncanonical_evidence");
  return value;
}

function verifyDetachedSignature(unsigned, signature, publicKeyPem, expectedFingerprint, code = "invalid_signature") {
  exactKeys(signature, SIGNATURE_KEYS, code);
  if (signature.algorithm !== "ed25519" || !FINGERPRINT.test(signature.public_key_fingerprint)
    || signature.public_key_fingerprint !== expectedFingerprint || typeof signature.value !== "string"
    || signature.value.length < 1 || signature.value.length > 4096) fail(code);
  let publicKey;
  try { publicKey = publicKeyPem?.type === "public" ? publicKeyPem : crypto.createPublicKey(publicKeyPem); } catch { fail(code); }
  const der = publicKey.export({ type: "spki", format: "der" });
  if (publicKey.asymmetricKeyType !== "ed25519" || sha256(der) !== expectedFingerprint) fail(code);
  let signatureBytes;
  try { signatureBytes = Buffer.from(signature.value, "base64url"); } catch { fail(code); }
  if (!crypto.verify(null, Buffer.from(canonicalText(unsigned), "utf8"), publicKey, signatureBytes)) fail(code);
  return Object.freeze({ publicKeyFingerprint: expectedFingerprint });
}

function verifySignature(value, publicKeyPem, expectedFingerprint, code = "invalid_signature") {
  exactKeys(value.signature, SIGNATURE_KEYS, code);
  const { signature, ...unsigned } = value;
  return verifyDetachedSignature(unsigned, signature, publicKeyPem, expectedFingerprint, code);
}

export function verifyOperationsEvidenceIntegrity({ indexPath, evidenceDirectory, expectedCandidateId, expectedSourceCommit, expectedImageDigest, publicKeyPem, expectedFingerprint, now = () => new Date() } = {}) {
  if (typeof indexPath !== "string" || typeof evidenceDirectory !== "string" || !path.isAbsolute(evidenceDirectory)) fail("invalid_evidence_directory");
  let directory;
  try { directory = fs.lstatSync(evidenceDirectory); } catch { fail("invalid_evidence_directory"); }
  if (!directory.isDirectory() || directory.isSymbolicLink()) fail("invalid_evidence_directory");
  if (path.resolve(indexPath) !== path.join(path.resolve(evidenceDirectory), "index.json")) fail("invalid_index_file");
  const index = parseCanonical(readOperationsEvidenceProtectedFile(indexPath, MAX_INDEX_BYTES, "invalid_index_file"), "invalid_index_file");
  exactKeys(index, ROOT_KEYS);
  if (index.schema_version !== OPERATIONS_EVIDENCE_BUNDLE_SCHEMA_VERSION || index.kind !== OPERATIONS_EVIDENCE_BUNDLE_KIND
    || !CANDIDATE.test(index.candidate_id) || index.candidate_id !== expectedCandidateId
    || !COMMIT.test(index.source_commit) || index.source_commit !== expectedSourceCommit
    || !IMAGE.test(index.image_digest) || index.image_digest !== expectedImageDigest) fail("binding_mismatch");
  const started = timestamp(index.started_at); const completed = timestamp(index.completed_at);
  const observedNow = now();
  const current = observedNow instanceof Date ? observedNow.getTime() : Date.parse(observedNow);
  if (!(completed > started) || completed - started > MAX_AGE_MS || !Number.isFinite(current) || completed > current + 5 * 60 * 1000 || current - completed > MAX_AGE_MS) fail("stale_evidence");
  if (!Array.isArray(index.evidence) || index.evidence.length !== OPERATIONS_EVIDENCE_IDS.length) fail("incomplete_evidence");
  const ids = new Set();
  const expectedFiles = new Set(["index.json", ...OPERATIONS_EVIDENCE_IDS.map((id) => `${id}.json`)]);
  let directoryEntries;
  try { directoryEntries = fs.readdirSync(evidenceDirectory, { withFileTypes: true }); } catch { fail("invalid_evidence_directory"); }
  if (directoryEntries.length !== expectedFiles.size || directoryEntries.some((entry) => !expectedFiles.has(entry.name) || !entry.isFile() || entry.isSymbolicLink())) fail("unexpected_evidence_file");
  for (const item of index.evidence) {
    exactKeys(item, ITEM_KEYS, "invalid_evidence_item");
    if (!OPERATIONS_EVIDENCE_IDS.includes(item.id) || ids.has(item.id)) fail("incomplete_evidence");
    ids.add(item.id);
    if (!FILE.test(item.file) || item.file === "index.json" || !SHA256.test(item.sha256)
      || item.status !== "reported" || item.source_commit !== index.source_commit || item.image_digest !== index.image_digest) fail("invalid_evidence_item");
    const evidencePath = path.join(evidenceDirectory, item.file);
    if (path.dirname(evidencePath) !== path.resolve(evidenceDirectory)) fail("invalid_evidence_item");
    const bytes = readOperationsEvidenceProtectedFile(evidencePath, MAX_EVIDENCE_BYTES, "missing_evidence_file");
    if (sha256(bytes) !== item.sha256) fail("evidence_digest_mismatch");
    const child = parseCanonical(bytes, "invalid_evidence_file");
    const assertionKeys = CHILD_ASSERTIONS[item.id];
    const childKeys = ["assertions", "candidate_id", "check", "evidence_origin", "execution_mode", "image_digest", "kind", "observed_at", "source_commit", "status"];
    if (child.check === "emergency_stop") childKeys.push("measurements");
    exactKeys(child, childKeys, "invalid_evidence_file");
    if (child.kind !== `agentpass.operations.${item.id}.v1` || child.check !== item.id || child.status !== "reported"
      || child.candidate_id !== index.candidate_id || child.image_digest !== index.image_digest || child.source_commit !== index.source_commit
      || child.evidence_origin !== "self_attested" || child.execution_mode !== "protected_external") fail("invalid_evidence_file");
    const observed = timestamp(child.observed_at, "invalid_evidence_file");
    if (observed > current + 5 * 60 * 1000 || current - observed > MAX_AGE_MS) fail("stale_evidence");
    if (!plainObject(child.assertions) || Object.keys(child.assertions).sort().join(",") !== [...assertionKeys].sort().join(",") || Object.values(child.assertions).some((value) => value !== true)) fail("semantic_evidence_not_proven");
    if (child.check === "emergency_stop") verifyEmergencyStopMeasurement(child);
  }
  if (ids.size !== OPERATIONS_EVIDENCE_IDS.length) fail("incomplete_evidence");
  verifySignature(index, publicKeyPem, expectedFingerprint);
  return Object.freeze({ status: "structure_verified", qualification_required: true, candidate_id: index.candidate_id, source_commit: index.source_commit, image_digest: index.image_digest, evidence: Object.freeze(index.evidence.map((item) => Object.freeze({ id: item.id, sha256: item.sha256 }))), evidence_count: index.evidence.length, index_sha256: sha256(Buffer.from(canonicalText(index), "utf8")), self_attested_key_fingerprint: expectedFingerprint });
}

function verifyIndependentQualificationEvidence({ qualificationEvidencePath, evidenceDirectory, integrity, qualificationPublicKeyPem, expectedQualificationFingerprint, now = () => new Date() }) {
  if (typeof qualificationEvidencePath !== "string" || !path.isAbsolute(qualificationEvidencePath)
    || path.resolve(qualificationEvidencePath) === path.resolve(path.join(evidenceDirectory, "index.json"))
    || path.relative(path.resolve(evidenceDirectory), path.resolve(qualificationEvidencePath))
      .split(path.sep)[0] !== "..") fail("invalid_qualification_evidence");
  const bytes = readOperationsEvidenceProtectedFile(qualificationEvidencePath, MAX_INDEX_BYTES, "invalid_qualification_evidence");
  const attestation = parseCanonical(bytes, "invalid_qualification_evidence");
  exactKeys(attestation, QUALIFICATION_ROOT_KEYS, "invalid_qualification_evidence");
  if (attestation.schema_version !== OPERATIONS_QUALIFICATION_EVIDENCE_SCHEMA_VERSION
    || attestation.kind !== OPERATIONS_QUALIFICATION_EVIDENCE_KIND
    || attestation.candidate_id !== integrity.candidate_id
    || attestation.source_commit !== integrity.source_commit
    || attestation.image_digest !== integrity.image_digest
    || attestation.evidence_bundle_sha256 !== integrity.index_sha256) fail("qualification_binding_mismatch");
  exactKeys(attestation.witness, QUALIFICATION_WITNESS_KEYS, "invalid_qualification_witness");
  if (attestation.witness.kind !== "independent_protected_operations_runner"
    || typeof attestation.witness.runner_id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$/u.test(attestation.witness.runner_id)
    || LOCAL_WITNESS_MARKER.test(attestation.witness.runner_id)) fail("invalid_qualification_witness");
  const started = timestamp(attestation.started_at, "invalid_qualification_evidence");
  const completed = timestamp(attestation.completed_at, "invalid_qualification_evidence");
  const observedNow = now();
  const current = observedNow instanceof Date ? observedNow.getTime() : Date.parse(observedNow);
  if (!(completed > started) || completed - started > MAX_AGE_MS || !Number.isFinite(current)
    || completed > current + 5 * 60 * 1000 || current - completed > MAX_AGE_MS) fail("stale_qualification_evidence");
  if (!Array.isArray(attestation.measurements) || attestation.measurements.length !== OPERATIONS_EVIDENCE_IDS.length) fail("incomplete_qualification_evidence");
  const expected = new Map(integrity.evidence.map((item) => [item.id, item.sha256]));
  const seen = new Set();
  for (const measurement of attestation.measurements) {
    exactKeys(measurement, QUALIFICATION_MEASUREMENT_KEYS, "invalid_qualification_measurement");
    if (!OPERATIONS_EVIDENCE_IDS.includes(measurement.check) || seen.has(measurement.check)
      || measurement.evidence_origin !== "independent_external"
      || measurement.status !== "qualified" || !SHA256.test(measurement.measurement_sha256)
      || measurement.measurement_sha256 === expected.get(measurement.check)) fail("invalid_qualification_measurement");
    seen.add(measurement.check);
    timestamp(measurement.observed_at, "invalid_qualification_measurement");
    const observed = Date.parse(measurement.observed_at);
    if (observed > current + 5 * 60 * 1000 || current - observed > MAX_AGE_MS) fail("stale_qualification_evidence");
  }
  if (seen.size !== OPERATIONS_EVIDENCE_IDS.length) fail("incomplete_qualification_evidence");
  if (expectedQualificationFingerprint === integrity.self_attested_key_fingerprint) fail("qualification_key_not_separate");
  verifySignature(attestation, qualificationPublicKeyPem, expectedQualificationFingerprint, "invalid_qualification_signature");
  return Object.freeze({ status: "independently_qualified", evidence_sha256: sha256(bytes), witness_runner_id: attestation.witness.runner_id });
}

function identity(value, code) {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._ -]{2,127}$/u.test(value)
    || /[\u0000-\u001f\u007f\u2028\u2029\r\n]/u.test(value)) fail(code);
  return value;
}

export function verifyIndependentSecurityReviewEvidence({ securityReviewEvidencePath, evidenceDirectory, qualificationEvidencePath, integrity, qualification, expectedArtifactDigest, expectedSecurityReviewFingerprint, expectedQualificationFingerprint, expectedReviewerId, expectedReviewerOrganization, expectedSourceTreeSha256, securityReviewPublicKeyPem, expectedApprovalFingerprint, expectedApprovalId, expectedApprovalOrganization, approvalPublicKeyPem, now = () => new Date() }) {
  if (typeof securityReviewEvidencePath !== "string" || !path.isAbsolute(securityReviewEvidencePath)
    || path.resolve(securityReviewEvidencePath) === path.resolve(path.join(evidenceDirectory, "index.json"))
    || path.resolve(securityReviewEvidencePath) === path.resolve(qualificationEvidencePath)
    || path.relative(path.resolve(evidenceDirectory), path.resolve(securityReviewEvidencePath)).split(path.sep)[0] !== "..") fail("invalid_security_review_evidence");
  if (!SHA256.test(expectedSourceTreeSha256 ?? "")) fail("security_review_source_tree_missing");
  if (!IMAGE.test(expectedArtifactDigest ?? "")) fail("security_review_artifact_missing");
  if (!FINGERPRINT.test(expectedSecurityReviewFingerprint ?? "")) fail("invalid_security_review_identity");
  const reviewerId = identity(expectedReviewerId, "invalid_security_review_identity");
  const reviewerOrganization = identity(expectedReviewerOrganization, "invalid_security_review_identity");
  if (NON_INDEPENDENT_REVIEW_MARKER.test(reviewerId) || NON_INDEPENDENT_REVIEW_MARKER.test(reviewerOrganization)) fail("invalid_security_review_identity");
  if (!FINGERPRINT.test(expectedApprovalFingerprint ?? "")) fail("invalid_security_review_approval");
  const approvalId = identity(expectedApprovalId, "invalid_security_review_approval");
  const approvalOrganization = identity(expectedApprovalOrganization, "invalid_security_review_approval");
  if (NON_INDEPENDENT_REVIEW_MARKER.test(approvalId) || NON_INDEPENDENT_REVIEW_MARKER.test(approvalOrganization)) fail("invalid_security_review_approval");
  if (approvalId === reviewerId || expectedApprovalFingerprint === expectedSecurityReviewFingerprint) fail("security_review_approval_not_separate");
  const bytes = readOperationsEvidenceProtectedFile(securityReviewEvidencePath, MAX_REVIEW_BYTES, "invalid_security_review_evidence");
  const review = parseCanonical(bytes, "invalid_security_review_evidence");
  exactKeys(review, REVIEW_ROOT_KEYS, "invalid_security_review_evidence");
  if (review.schema_version !== INDEPENDENT_SECURITY_REVIEW_SCHEMA_VERSION
    || review.schema_digest !== INDEPENDENT_SECURITY_REVIEW_SCHEMA_DIGEST
    || review.kind !== INDEPENDENT_SECURITY_REVIEW_KIND
    || review.status !== "completed"
    || review.candidate_id !== integrity.candidate_id
    || review.source_commit !== integrity.source_commit
    || review.source_tree_sha256 !== expectedSourceTreeSha256
    || review.artifact_digest !== expectedArtifactDigest
    || review.image_digest !== integrity.image_digest
    || review.evidence_bundle_sha256 !== integrity.index_sha256
    || review.qualification_evidence_sha256 !== qualification.evidence_sha256) fail("security_review_binding_mismatch");
  exactKeys(review.reviewer, REVIEWER_KEYS, "invalid_security_review_identity");
  if (review.reviewer.kind !== "independent_external"
    || review.reviewer.role !== "security_reviewer"
    || review.reviewer.reviewer_id !== reviewerId
    || review.reviewer.organization !== reviewerOrganization
    || review.reviewer.public_key_fingerprint !== expectedSecurityReviewFingerprint
    || NON_INDEPENDENT_REVIEW_MARKER.test(review.reviewer.reviewer_id)
    || NON_INDEPENDENT_REVIEW_MARKER.test(review.reviewer.organization)) fail("invalid_security_review_identity");
  exactKeys(review.findings, REVIEW_FINDING_KEYS, "invalid_security_review_findings");
  for (const key of REVIEW_FINDING_KEYS) {
    if (!Number.isSafeInteger(review.findings[key]) || review.findings[key] < 0 || review.findings[key] > 100000) fail("invalid_security_review_findings");
  }
  if (review.findings.critical !== 0 || review.findings.high !== 0 || review.findings.open_critical_high !== 0) fail("security_review_findings_open");
  exactKeys(review.retest_evidence, RETEST_EVIDENCE_KEYS, "invalid_security_review_retest");
  if (review.retest_evidence.status !== "passed" || !SHA256.test(review.retest_evidence.evidence_sha256)) fail("invalid_security_review_retest");
  exactKeys(review.approval, APPROVAL_KEYS, "invalid_security_review_approval");
  if (review.approval.approver_id !== approvalId
    || review.approval.organization !== approvalOrganization
    || review.approval.decision !== "approved"
    || review.approval.public_key_fingerprint !== expectedApprovalFingerprint
    || NON_INDEPENDENT_REVIEW_MARKER.test(review.approval.approver_id)
    || NON_INDEPENDENT_REVIEW_MARKER.test(review.approval.organization)) fail("invalid_security_review_approval");
  const started = timestamp(review.started_at, "invalid_security_review_evidence");
  const completed = timestamp(review.completed_at, "invalid_security_review_evidence");
  const expires = timestamp(review.expires_at, "invalid_security_review_evidence");
  const retestCompleted = timestamp(review.retest_evidence.completed_at, "invalid_security_review_retest");
  const observedNow = now();
  const current = observedNow instanceof Date ? observedNow.getTime() : Date.parse(observedNow);
  if (!(completed > started) || completed - started > 90 * 24 * 60 * 60 * 1000
    || retestCompleted < started || retestCompleted > completed
    || !(expires > completed) || !Number.isFinite(current)
    || completed > current + 5 * 60 * 1000 || current - completed > MAX_REVIEW_AGE_MS) {
    fail("stale_security_review");
  }
  if (current >= expires) fail("security_review_expired");
  if (expires - completed > MAX_REVIEW_WINDOW_MS) fail("invalid_security_review_expiry");
  verifySignature(review, securityReviewPublicKeyPem, expectedSecurityReviewFingerprint, "invalid_security_review_signature");
  const { signature: approvalSignature, ...approvalUnsigned } = review.approval;
  const { signature: ignoredReviewSignature, ...reviewUnsigned } = review;
  verifyDetachedSignature({ ...reviewUnsigned, approval: approvalUnsigned }, approvalSignature, approvalPublicKeyPem, expectedApprovalFingerprint, "invalid_security_review_approval_signature");
  if (expectedSecurityReviewFingerprint === integrity.self_attested_key_fingerprint
    || expectedSecurityReviewFingerprint === expectedQualificationFingerprint
    || expectedApprovalFingerprint === integrity.self_attested_key_fingerprint
    || expectedApprovalFingerprint === expectedQualificationFingerprint) fail("security_review_key_not_separate");
  return Object.freeze({ status: "review_record_verified", evidence_sha256: sha256(bytes), reviewer_id: review.reviewer.reviewer_id, reviewer_organization: review.reviewer.organization, approver_id: review.approval.approver_id, approval_organization: review.approval.organization, expires_at: review.expires_at, retest_evidence_sha256: review.retest_evidence.evidence_sha256, artifact_digest: review.artifact_digest });
}

export function verifyOperationsEvidenceBundle(options) {
  const integrity = verifyOperationsEvidenceIntegrity(options);
  if (!options?.qualificationEvidencePath || !options?.qualificationPublicKeyPem || !options?.expectedQualificationFingerprint) fail("independent_qualification_evidence_missing");
  const qualification = verifyIndependentQualificationEvidence({ ...options, integrity });
  const reviewArguments = ["securityReviewEvidencePath", "securityReviewPublicKeyPem", "expectedSecurityReviewFingerprint", "expectedReviewerId", "expectedReviewerOrganization", "expectedSourceTreeSha256", "expectedArtifactDigest", "approvalPublicKeyPem", "expectedApprovalFingerprint", "expectedApprovalId", "expectedApprovalOrganization"];
  const reviewSupplied = reviewArguments.some((key) => options?.[key] !== undefined);
  if (options?.requireProductionReadiness || reviewSupplied) {
    if (!reviewArguments.every((key) => options?.[key])) fail("independent_security_review_evidence_missing");
    const securityReview = verifyIndependentSecurityReviewEvidence({ ...options, integrity, qualification });
    return Object.freeze({ status: "verified", production_ready: true, integrity_status: integrity.status, qualification_required: true, qualification_status: qualification.status, security_review_required: true, security_review_status: securityReview.status, candidate_id: integrity.candidate_id, source_commit: integrity.source_commit, image_digest: integrity.image_digest, artifact_digest: securityReview.artifact_digest, evidence_count: integrity.evidence_count, index_sha256: integrity.index_sha256, qualification_evidence_sha256: qualification.evidence_sha256, security_review_evidence_sha256: securityReview.evidence_sha256, witness_runner_id: qualification.witness_runner_id, reviewer_id: securityReview.reviewer_id, reviewer_organization: securityReview.reviewer_organization, approver_id: securityReview.approver_id, approval_organization: securityReview.approval_organization, retest_evidence_sha256: securityReview.retest_evidence_sha256, security_review_expires_at: securityReview.expires_at });
  }
  return Object.freeze({ status: "verified", production_ready: false, production_readiness_blocker: "independent_security_review_required", integrity_status: integrity.status, qualification_required: true, qualification_status: qualification.status, security_review_required: true, candidate_id: integrity.candidate_id, source_commit: integrity.source_commit, image_digest: integrity.image_digest, evidence_count: integrity.evidence_count, index_sha256: integrity.index_sha256, qualification_evidence_sha256: qualification.evidence_sha256, witness_runner_id: qualification.witness_runner_id });
}

export function verifyOperationsEvidenceForProduction(options) {
  return verifyOperationsEvidenceBundle({ ...options, requireProductionReadiness: true });
}

async function main() {
  const args = process.argv.slice(2);
  let command, indexPath, evidenceDirectory, candidate, source, image, artifactDigest, publicKeyPath, fingerprint, qualificationEvidencePath, qualificationPublicKeyPath, qualificationFingerprint, securityReviewEvidencePath, securityReviewPublicKeyPath, securityReviewFingerprint, reviewerId, reviewerOrganization, approvalPublicKeyPath, approvalFingerprint, approverId, approverOrganization, sourceTreeSha256;
  if (args[0] === "verify-production") {
    [command, indexPath, evidenceDirectory, candidate, source, image, artifactDigest, publicKeyPath, fingerprint, qualificationEvidencePath, qualificationPublicKeyPath, qualificationFingerprint, securityReviewEvidencePath, securityReviewPublicKeyPath, securityReviewFingerprint, reviewerId, reviewerOrganization, approvalPublicKeyPath, approvalFingerprint, approverId, approverOrganization, sourceTreeSha256] = args;
  } else {
    [command, indexPath, evidenceDirectory, candidate, source, image, publicKeyPath, fingerprint, qualificationEvidencePath, qualificationPublicKeyPath, qualificationFingerprint] = args;
  }
  const absolute = (value) => typeof value === "string" && path.isAbsolute(value);
  const productionCommand = command === "verify-production";
  const expectedArgumentCount = productionCommand ? 24 : 13;
  if (!(["verify", "verify-production"].includes(command)) || process.argv.length !== expectedArgumentCount || !absolute(indexPath) || !absolute(evidenceDirectory)
    || !CANDIDATE.test(candidate) || !COMMIT.test(source) || !IMAGE.test(image) || (productionCommand && !IMAGE.test(artifactDigest)) || !absolute(publicKeyPath)
    || !FINGERPRINT.test(fingerprint) || !absolute(qualificationEvidencePath) || !absolute(qualificationPublicKeyPath)
    || !FINGERPRINT.test(qualificationFingerprint)
    || (productionCommand && (!absolute(securityReviewEvidencePath) || !absolute(securityReviewPublicKeyPath) || !FINGERPRINT.test(securityReviewFingerprint) || !absolute(approvalPublicKeyPath) || !FINGERPRINT.test(approvalFingerprint) || !SHA256.test(sourceTreeSha256)))) {
    process.stdout.write(`${JSON.stringify({ status: "not_proven", reason: "invalid_arguments" })}\n`); process.exitCode = 2; return;
  }
  try {
    const publicKeyPem = readOperationsEvidenceProtectedFile(publicKeyPath, 16 * 1024, "invalid_public_key");
    const qualificationPublicKeyPem = readOperationsEvidenceProtectedFile(qualificationPublicKeyPath, 16 * 1024, "invalid_qualification_public_key");
    const securityReviewPublicKeyPem = productionCommand ? readOperationsEvidenceProtectedFile(securityReviewPublicKeyPath, 16 * 1024, "invalid_security_review_public_key") : undefined;
    const approvalPublicKeyPem = productionCommand ? readOperationsEvidenceProtectedFile(approvalPublicKeyPath, 16 * 1024, "invalid_approval_public_key") : undefined;
    const result = verifyOperationsEvidenceBundle({ indexPath, evidenceDirectory, expectedCandidateId: candidate, expectedSourceCommit: source, expectedImageDigest: image, publicKeyPem, expectedFingerprint: fingerprint, qualificationEvidencePath, qualificationPublicKeyPem, expectedQualificationFingerprint: qualificationFingerprint, ...(productionCommand ? { requireProductionReadiness: true, expectedArtifactDigest: artifactDigest, securityReviewEvidencePath, securityReviewPublicKeyPem, expectedSecurityReviewFingerprint: securityReviewFingerprint, expectedReviewerId: reviewerId, expectedReviewerOrganization: reviewerOrganization, expectedSourceTreeSha256: sourceTreeSha256, approvalPublicKeyPem, expectedApprovalFingerprint: approvalFingerprint, expectedApprovalId: approverId, expectedApprovalOrganization: approverOrganization } : {}) });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ status: "not_proven", reason: error instanceof OperationsEvidenceBundleError ? error.code : "verification_failed" })}\n`); process.exitCode = 2;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
