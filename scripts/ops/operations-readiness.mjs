#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { OperationsEvidenceBundleError, readOperationsEvidenceProtectedFile, verifyOperationsEvidenceBundle } from "./verify-operations-evidence-bundle.mjs";

export const OPERATIONS_READINESS_SCHEMA_VERSION = 1;
export const OPERATIONS_READINESS_KIND = "agentpass.operations-readiness-checklist";
export const OPERATIONS_READINESS_CHECKS = Object.freeze(["rollback", "pitr", "revoke_emergency_stop", "alerting", "tenant_isolation"]);
export const NOT_PROVEN = Object.freeze({
  status: "not_proven",
  reason: "protected_external_evidence_unavailable",
  required: OPERATIONS_READINESS_CHECKS
});

const MAX_BYTES = 64 * 1024;
const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40,64}$/u;
const CANDIDATE = /^release-pkg-sha256-v1-[0-9a-f]{64}$/u;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const SAFE_TEXT = /^[A-Za-z0-9][A-Za-z0-9 ._:/+@-]{0,255}$/u;
const CONTROL_REF = /^[A-Za-z0-9][A-Za-z0-9._:/-]{1,127}$/u;
const IMAGE = /^sha256:[0-9a-f]{64}$/u;
const ROOT_KEYS = ["artifact_digest", "candidate_id", "checks", "completed_at", "evidence_origin", "execution_mode", "kind", "operational_controls", "schema_version", "source_commit", "started_at"];
const CHECK_KEYS = ["assertions", "candidate_id", "evidence_digest", "evidence_origin", "observed_at", "source_commit", "status"];
const OPERATIONAL_CONTROL_KEYS = Object.freeze(["artifact_digest", "candidate_id", "evidence_digest", "evidence_origin", "evidence_retention", "execution_id", "execution_mode", "expiry", "incident", "kill_switch", "observed_at", "on_call", "reviewer", "rollback", "source_commit"]);
const EVIDENCE_RETENTION_KEYS = Object.freeze(["access_audit_enabled", "delete_protection_enabled", "location_ref", "retention_days", "storage_class"]);
const EXPIRY_KEYS = Object.freeze(["expires_at"]);
const ON_CALL_KEYS = Object.freeze(["acknowledged_at", "owner_ref", "page_tested_at", "route_ref", "status"]);
const INCIDENT_KEYS = Object.freeze(["incident_owner_ref", "on_call_owner_ref", "revoke_owner_ref", "revoke_runbook_ref", "revoke_status", "revoke_verified_at", "rollback_owner_ref"]);
const REVIEWER_KEYS = Object.freeze(["approval_authority", "independent", "organization", "reviewer_id", "separate_signing_key"]);
const ROLLBACK_KEYS = Object.freeze(["fail_closed", "last_verified_at", "owner_ref", "runbook_ref", "status", "target_binding_verified"]);
const KILL_SWITCH_KEYS = Object.freeze(["fail_closed", "last_verified_at", "operation", "owner_ref", "propagation_bound_ms", "propagation_observed_ms", "runbook_ref", "status"]);
const CONTROL_STATUS = "verified";
const MAX_CONTROL_AGE_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_RETENTION_DAYS = 3650;
const MAX_PROPAGATION_BOUND_MS = 24 * 60 * 60 * 1000;
const ASSERTION_KEYS = Object.freeze({
  rollback: ["authority_not_widened", "deployment_rollback_verified", "health_gate_verified", "previous_revision_rejected", "rollback_artifact_digest"],
  pitr: ["backup_artifact_digest", "backup_manifest_verified", "pitr_restore_verified", "recovery_target_bound", "schema_head_match", "tenant_integrity_verified"],
  revoke_emergency_stop: ["ack_quorum_verified", "emergency_stop_propagation_verified", "existing_capability_denied", "new_capability_denied", "revoke_propagation_verified", "terminal_state_verified"],
  alerting: ["alert_rules_verified", "counter_reset_fail_closed", "delivery_verified", "escalation_verified", "policy_digest", "secret_free_evidence"],
  tenant_isolation: ["admin_scope_verified", "cross_tenant_denied", "no_cross_tenant_rows", "pair_count", "rls_policy_verified", "same_tenant_allowed", "tenant_pair_matrix_verified"]
});

export class OperationsReadinessError extends Error {
  constructor(code, message = code) { super(message); this.name = "OperationsReadinessError"; this.code = code; }
}
function invalid(code, message = code) { throw new OperationsReadinessError(code, message); }
function plainObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) invalid("invalid_shape", `${label} must be a plain object`);
  return value;
}
function exactKeys(value, expected, label) {
  plainObject(value, label);
  const actual = Reflect.ownKeys(value);
  if (actual.some((key) => typeof key !== "string" || !Object.prototype.propertyIsEnumerable.call(value, key))) invalid("unknown_field", `${label} contains a non-enumerable or symbol field`);
  const left = actual.sort(); const right = [...expected].sort();
  if (left.length !== right.length || left.some((key, index) => key !== right[index])) invalid("unknown_field", `${label} has an unknown or missing field`);
}
function safeString(value, label, pattern = SAFE_TEXT) {
  if (typeof value !== "string" || value.length === 0 || value.length > 256 || /[\u0000-\u001f\u007f\u2028\u2029\r\n]/u.test(value) || !pattern.test(value)) invalid("invalid_value", `${label} is invalid`);
  return value;
}
function digest(value, label) { return safeString(value, label, SHA256); }
function controlRef(value, label) {
  safeString(value, label, CONTROL_REF);
  if (/(^|[._:/-])(local|mock|fixture|fake|simulator|emulator|test|unknown|placeholder)([._:/-]|$)/iu.test(value)) invalid("not_proven", `${label} must identify a protected operational resource`);
  return value;
}
function timestamp(value, label) {
  safeString(value, label, ISO_UTC);
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) invalid("invalid_timestamp", `${label} is invalid`);
  return value;
}

function validateOperationalControls(value, { completedAt, expectedCandidateId, expectedSourceCommit, expectedArtifactDigest, now = new Date() } = {}) {
  exactKeys(value, OPERATIONAL_CONTROL_KEYS, "operational_controls");
  if (!CANDIDATE.test(value.candidate_id) || value.candidate_id !== expectedCandidateId
    || !COMMIT.test(value.source_commit) || value.source_commit !== expectedSourceCommit
    || !IMAGE.test(value.artifact_digest) || value.artifact_digest !== expectedArtifactDigest) invalid("binding_mismatch", "operational controls are not bound to the candidate, source, and artifact");
  digest(value.evidence_digest, "operational_controls.evidence_digest");
  if (value.evidence_origin !== "protected_external" || value.execution_mode !== "protected_external") invalid("not_proven", "operational controls require protected external execution");
  controlRef(value.execution_id, "operational_controls.execution_id");
  const observedAt = Date.parse(timestamp(value.observed_at, "operational_controls.observed_at"));
  const completedMs = Date.parse(completedAt);
  const nowMs = now instanceof Date ? now.getTime() : Date.parse(now);
  if (!Number.isFinite(nowMs) || observedAt > nowMs || observedAt > completedMs || nowMs - observedAt > MAX_CONTROL_AGE_MS) invalid("stale_operational_controls", "operational controls are stale or outside the evidence window");

  const retention = value.evidence_retention;
  exactKeys(retention, EVIDENCE_RETENTION_KEYS, "evidence_retention");
  controlRef(retention.location_ref, "evidence_retention.location_ref");
  if (!["immutable_worm", "versioned_object_lock"].includes(retention.storage_class)) invalid("invalid_operational_controls", "evidence retention storage is not immutable");
  if (!Number.isSafeInteger(retention.retention_days) || retention.retention_days < 90 || retention.retention_days > MAX_RETENTION_DAYS) invalid("invalid_operational_controls", "evidence retention period is invalid");
  if (retention.access_audit_enabled !== true || retention.delete_protection_enabled !== true) invalid("not_proven", "evidence retention is not protected");

  const expiry = value.expiry;
  exactKeys(expiry, EXPIRY_KEYS, "operational_controls.expiry");
  const expiresAt = Date.parse(timestamp(expiry.expires_at, "operational_controls.expiry.expires_at"));
  if (!Number.isFinite(nowMs) || expiresAt <= nowMs) invalid("operational_controls_expired", "operational controls are expired");
  if (!(expiresAt > completedMs) || expiresAt - completedMs > MAX_CONTROL_AGE_MS) invalid("invalid_operational_expiry", "operational control expiry window is invalid");

  const incident = value.incident;
  exactKeys(incident, INCIDENT_KEYS, "operational_controls.incident");
  for (const key of ["incident_owner_ref", "on_call_owner_ref", "revoke_owner_ref", "rollback_owner_ref", "revoke_runbook_ref"]) controlRef(incident[key], `incident.${key}`);
  const incidentTimes = Date.parse(timestamp(incident.revoke_verified_at, "incident.revoke_verified_at"));
  if (incident.revoke_status !== CONTROL_STATUS || incidentTimes > nowMs || incidentTimes > completedMs || nowMs - incidentTimes > MAX_CONTROL_AGE_MS) invalid("revoke_operation_not_ready", "revoke operation is not current and verified");
  if (new Set([incident.incident_owner_ref, incident.on_call_owner_ref, incident.revoke_owner_ref, incident.rollback_owner_ref]).size !== 4) invalid("reviewer_separation_required", "incident roles must have distinct owners");

  const onCall = value.on_call;
  exactKeys(onCall, ON_CALL_KEYS, "operational_controls.on_call");
  controlRef(onCall.owner_ref, "on_call.owner_ref"); controlRef(onCall.route_ref, "on_call.route_ref");
  const pageTestedAt = Date.parse(timestamp(onCall.page_tested_at, "on_call.page_tested_at"));
  const acknowledgedAt = Date.parse(timestamp(onCall.acknowledged_at, "on_call.acknowledged_at"));
  if (onCall.status !== CONTROL_STATUS || onCall.owner_ref !== incident.on_call_owner_ref || pageTestedAt > acknowledgedAt || acknowledgedAt > nowMs || acknowledgedAt > completedMs || nowMs - pageTestedAt > MAX_CONTROL_AGE_MS) invalid("on_call_operation_not_ready", "on-call page and acknowledgement are not verified");

  const reviewer = value.reviewer;
  exactKeys(reviewer, REVIEWER_KEYS, "operational_controls.reviewer");
  controlRef(reviewer.reviewer_id, "reviewer.reviewer_id");
  controlRef(reviewer.organization, "reviewer.organization");
  if (reviewer.approval_authority !== "review_only" || reviewer.independent !== true || reviewer.separate_signing_key !== true) invalid("reviewer_separation_required", "reviewer separation is not proven");
  if (Object.values(incident).includes(reviewer.reviewer_id)) invalid("reviewer_separation_required", "reviewer must not own incident operations");

  const rollback = value.rollback;
  exactKeys(rollback, ROLLBACK_KEYS, "operational_controls.rollback");
  controlRef(rollback.owner_ref, "rollback.owner_ref"); controlRef(rollback.runbook_ref, "rollback.runbook_ref");
  const rollbackVerifiedAt = Date.parse(timestamp(rollback.last_verified_at, "rollback.last_verified_at"));
  if (rollbackVerifiedAt > nowMs || rollbackVerifiedAt > completedMs || nowMs - rollbackVerifiedAt > MAX_CONTROL_AGE_MS) invalid("rollback_operation_not_ready", "rollback verification is stale or outside the evidence window");
  if (rollback.status !== CONTROL_STATUS || rollback.fail_closed !== true || rollback.target_binding_verified !== true) invalid("rollback_operation_not_ready", "rollback operation is not fail-closed and verified");
  if (rollback.owner_ref !== incident.rollback_owner_ref) invalid("rollback_operation_not_ready", "rollback owner is not bound to incident owner");

  const killSwitch = value.kill_switch;
  exactKeys(killSwitch, KILL_SWITCH_KEYS, "operational_controls.kill_switch");
  controlRef(killSwitch.owner_ref, "kill_switch.owner_ref"); controlRef(killSwitch.runbook_ref, "kill_switch.runbook_ref");
  const killSwitchVerifiedAt = Date.parse(timestamp(killSwitch.last_verified_at, "kill_switch.last_verified_at"));
  if (killSwitchVerifiedAt > nowMs || killSwitchVerifiedAt > completedMs || nowMs - killSwitchVerifiedAt > MAX_CONTROL_AGE_MS) invalid("kill_switch_operation_not_ready", "kill-switch verification is stale or outside the evidence window");
  if (killSwitch.status !== CONTROL_STATUS || killSwitch.fail_closed !== true || killSwitch.operation !== "deny_new_and_existing_capabilities") invalid("kill_switch_operation_not_ready", "kill-switch operation is not fail-closed and verified");
  if (!Number.isSafeInteger(killSwitch.propagation_bound_ms) || killSwitch.propagation_bound_ms < 1 || killSwitch.propagation_bound_ms > MAX_PROPAGATION_BOUND_MS
    || !Number.isSafeInteger(killSwitch.propagation_observed_ms) || killSwitch.propagation_observed_ms < 0 || killSwitch.propagation_observed_ms > killSwitch.propagation_bound_ms) invalid("kill_switch_operation_not_ready", "kill-switch propagation measurement is invalid");
  if (killSwitch.owner_ref !== incident.incident_owner_ref) invalid("kill_switch_operation_not_ready", "kill-switch owner is not bound to incident owner");

  return Object.freeze({ status: CONTROL_STATUS, expires_at: expiry.expires_at, retention_days: retention.retention_days });
}

// JSON.parse cannot detect duplicate members; this small scanner rejects them before parsing.
function parseDuplicateSafeJson(text) {
  let offset = 0;
  const whitespace = () => { while (offset < text.length && /[ \t\r\n]/u.test(text[offset])) offset += 1; };
  const fail = () => invalid("invalid_json", "evidence JSON is invalid");
  const parseString = () => {
    const start = offset; if (text[offset++] !== '"') fail();
    while (offset < text.length) {
      const character = text[offset++];
      if (character === '"') { try { return JSON.parse(text.slice(start, offset)); } catch { fail(); } }
      if (character === "\\") {
        if (offset >= text.length) fail(); const escaped = text[offset++];
        if (escaped === "u") { if (!/^[0-9a-f]{4}$/iu.test(text.slice(offset, offset + 4))) fail(); offset += 4; }
        else if (!/["\\/bfnrt]/u.test(escaped)) fail();
      } else if (character.charCodeAt(0) < 0x20) fail();
    }
    fail();
  };
  const parseValue = () => {
    whitespace();
    if (text[offset] === '"') { parseString(); return; }
    if (text[offset] === "{") { parseObject(); return; }
    if (text[offset] === "[") { parseArray(); return; }
    const literal = text.slice(offset).match(/^(?:true|false|null)/u);
    if (literal) { offset += literal[0].length; return; }
    const number = text.slice(offset).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u);
    if (!number) fail(); offset += number[0].length;
  };
  const parseArray = () => {
    offset += 1; whitespace(); if (text[offset] === "]") { offset += 1; return; }
    while (true) { parseValue(); whitespace(); if (text[offset] === "]") { offset += 1; return; } if (text[offset++] !== ",") fail(); }
  };
  const parseObject = () => {
    offset += 1; whitespace(); const keys = new Set(); if (text[offset] === "}") { offset += 1; return; }
    while (true) {
      const key = parseString(); if (keys.has(key)) invalid("duplicate_field", "evidence JSON has duplicate fields"); keys.add(key);
      whitespace(); if (text[offset++] !== ":") fail(); parseValue(); whitespace();
      if (text[offset] === "}") { offset += 1; return; } if (text[offset++] !== ",") fail();
    }
  };
  parseValue(); whitespace(); if (offset !== text.length) fail(); return JSON.parse(text);
}

function validateAssertions(name, assertions) {
  exactKeys(assertions, ASSERTION_KEYS[name], `${name} assertions`);
  for (const [key, value] of Object.entries(assertions)) {
    if (key.endsWith("_digest") || key === "policy_digest") digest(value, `${name}.${key}`);
    else if (key === "pair_count") { if (!Number.isSafeInteger(value) || value < 2 || value > 100000) invalid("invalid_assertion", `${name}.${key} is invalid`); }
    else if (value !== true) invalid("not_proven", `${name}.${key} is not proven`);
  }
}

export function verifyOperationsReadiness(value, { expectedCandidateId, expectedSourceCommit, expectedArtifactDigest, now = new Date() } = {}) {
  exactKeys(value, ROOT_KEYS, "checklist");
  if (value.schema_version !== OPERATIONS_READINESS_SCHEMA_VERSION || value.kind !== OPERATIONS_READINESS_KIND) invalid("invalid_schema", "unsupported checklist schema");
  if (!CANDIDATE.test(value.candidate_id) || !COMMIT.test(value.source_commit)) invalid("invalid_binding", "candidate or source binding is invalid");
  if (expectedCandidateId !== value.candidate_id || expectedSourceCommit !== value.source_commit) invalid("source_mismatch", "candidate or source binding mismatch");
  if (value.execution_mode !== "protected_external" || value.evidence_origin !== "protected_external") invalid("not_proven", "protected external evidence is required");
  const startedAt = timestamp(value.started_at, "started_at"); const completedAt = timestamp(value.completed_at, "completed_at");
  const started = Date.parse(startedAt); const completed = Date.parse(completedAt);
  const nowMs = now instanceof Date ? now.getTime() : Date.parse(now);
  if (!Number.isFinite(nowMs) || !(completed > started) || completed > nowMs || completed - started > 24 * 60 * 60 * 1000) invalid("invalid_time_window", "checklist time window is invalid");
  exactKeys(value.checks, OPERATIONS_READINESS_CHECKS, "checks");
  for (const name of OPERATIONS_READINESS_CHECKS) {
    const check = value.checks[name]; exactKeys(check, CHECK_KEYS, `${name} check`);
    if (check.status !== "verified" || check.evidence_origin !== "protected_external") invalid("not_proven", `${name} is not verified by protected evidence`);
    if (check.candidate_id !== value.candidate_id || check.source_commit !== value.source_commit) invalid("source_mismatch", `${name} binding mismatch`);
    digest(check.evidence_digest, `${name}.evidence_digest`); timestamp(check.observed_at, `${name}.observed_at`); validateAssertions(name, check.assertions);
  }
  if (!IMAGE.test(value.artifact_digest) || expectedArtifactDigest !== value.artifact_digest) invalid("binding_mismatch", "readiness artifact is not bound to the expected artifact");
  const controls = validateOperationalControls(value.operational_controls, { completedAt, expectedCandidateId, expectedSourceCommit, expectedArtifactDigest, now });
  const operationalControlsStatus = controls.status;
  const operationalControlsExpiresAt = controls.expires_at;
  return Object.freeze({ status: "structure_verified", production_ready: false, production_readiness_blocker: "independent_qualification_required", operational_controls_required: true, operational_controls_status: operationalControlsStatus, ...(operationalControlsExpiresAt ? { operational_controls_expires_at: operationalControlsExpiresAt } : {}), qualification_required: true, candidate_id: value.candidate_id, source_commit: value.source_commit, artifact_digest: value.artifact_digest, checks: OPERATIONS_READINESS_CHECKS,
    evidence_sha256: crypto.createHash("sha256").update(`${canonicalJson(value)}\n`, "utf8").digest("hex") });
}

function readOperationsReadinessValue(file) {
  if (typeof file !== "string" || !path.isAbsolute(file)) invalid("invalid_evidence_file", "evidence path must be absolute");
  let fd;
  try { fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); }
  catch { invalid("not_proven", "protected external evidence is unavailable"); }
  let text;
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size < 1n || before.size > BigInt(MAX_BYTES)) invalid("invalid_evidence_file", "evidence must be a regular file");
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count === 0) invalid("invalid_evidence_file", "evidence changed while reading");
      offset += count;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    if ([before.dev, before.ino, before.mode, before.nlink, before.size, before.mtimeNs, before.ctimeNs].join(":")
      !== [after.dev, after.ino, after.mode, after.nlink, after.size, after.mtimeNs, after.ctimeNs].join(":")) invalid("invalid_evidence_file", "evidence changed while reading");
    text = bytes.toString("utf8");
  } finally { fs.closeSync(fd); }
  if (!text.endsWith("\n")) invalid("noncanonical_evidence", "evidence must end with one newline");
  const value = parseDuplicateSafeJson(text); if (`${canonicalJson(value)}\n` !== text) invalid("noncanonical_evidence", "evidence is not canonical JSON");
  return value;
}

export function readOperationsReadinessEvidence(file, options) {
  return verifyOperationsReadiness(readOperationsReadinessValue(file), options);
}

export function verifyOperationsReadinessWithBundle(value, { expectedCandidateId, expectedSourceCommit, operationsEvidenceBundle, now = new Date() } = {}) {
  if (!operationsEvidenceBundle || typeof operationsEvidenceBundle !== "object" || !IMAGE.test(operationsEvidenceBundle.expectedImageDigest)) invalid("independent_qualification_evidence_missing", "an independently signed qualification bundle with an artifact binding is required");
  const structure = verifyOperationsReadiness(value, { expectedCandidateId, expectedSourceCommit, expectedArtifactDigest: operationsEvidenceBundle.expectedImageDigest, now });
  let qualification;
  try {
    qualification = verifyOperationsEvidenceBundle(operationsEvidenceBundle);
  } catch (error) {
    const code = error instanceof OperationsEvidenceBundleError ? error.code : "qualification_verification_failed";
    invalid(code, "independent qualification bundle verification failed");
  }
  if (qualification.candidate_id !== structure.candidate_id || qualification.source_commit !== structure.source_commit) {
    invalid("source_mismatch", "qualification bundle candidate or source binding mismatch");
  }
  if (structure.operational_controls_status !== "verified") invalid("operational_controls_not_configured", "operational controls are required for the readiness gate");
  const productionReady = structure.operational_controls_status === "verified" && qualification.production_ready === true;
  return Object.freeze({
    status: "verified",
    production_ready: productionReady,
    production_readiness_blocker: productionReady ? null : structure.operational_controls_status !== "verified" ? "operational_controls_not_configured" : qualification.production_readiness_blocker ?? "independent_security_review_required",
    readiness_status: structure.status,
    operational_controls_required: true,
    operational_controls_status: structure.operational_controls_status,
    qualification_status: qualification.qualification_status,
    qualification_required: true,
    candidate_id: structure.candidate_id,
    source_commit: structure.source_commit,
    artifact_digest: structure.artifact_digest,
    readiness_evidence_sha256: structure.evidence_sha256,
    qualification_evidence_sha256: qualification.qualification_evidence_sha256,
    qualification_index_sha256: qualification.index_sha256,
    witness_runner_id: qualification.witness_runner_id
  });
}

function output(value) { process.stdout.write(`${JSON.stringify(value)}\n`); }
async function main() {
  const args = process.argv.slice(2);
  const [command, readinessPath, candidate, source, indexPath, evidenceDirectory, imageDigest, publicKeyPath, fingerprint, qualificationEvidencePath, qualificationPublicKeyPath, qualificationFingerprint] = args;
  const absolute = (value) => typeof value === "string" && path.isAbsolute(value);
  if (args.length !== 12 || command !== "verify" || !absolute(readinessPath) || !CANDIDATE.test(candidate) || !COMMIT.test(source)
    || !absolute(indexPath) || !absolute(evidenceDirectory) || !absolute(publicKeyPath) || !absolute(qualificationEvidencePath)
    || !absolute(qualificationPublicKeyPath) || !/^sha256:[0-9a-f]{64}$/u.test(imageDigest)
    || !/^[0-9a-f]{64}$/u.test(fingerprint) || !/^[0-9a-f]{64}$/u.test(qualificationFingerprint)) { output(NOT_PROVEN); process.exitCode = 2; return; }
  try {
    const publicKeyPem = readOperationsEvidenceProtectedFile(publicKeyPath, 16 * 1024, "invalid_public_key");
    const qualificationPublicKeyPem = readOperationsEvidenceProtectedFile(qualificationPublicKeyPath, 16 * 1024, "invalid_qualification_public_key");
    output(verifyOperationsReadinessWithBundle(readOperationsReadinessValue(readinessPath), {
      expectedCandidateId: candidate,
      expectedSourceCommit: source,
      now: new Date(),
      operationsEvidenceBundle: {
        indexPath,
        evidenceDirectory,
        expectedCandidateId: candidate,
        expectedSourceCommit: source,
        expectedImageDigest: imageDigest,
        publicKeyPem,
        expectedFingerprint: fingerprint,
        qualificationEvidencePath,
        qualificationPublicKeyPem,
        expectedQualificationFingerprint: qualificationFingerprint
      }
    }));
  }
  catch (error) { output({ status: "not_proven", reason: error instanceof OperationsReadinessError ? error.code : "verification_failed" }); process.exitCode = 2; }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
