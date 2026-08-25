import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import { canonicalJson } from "../packages/protocol/src/index.mjs";
import { OPERATIONS_READINESS_CHECKS, OperationsReadinessError, readOperationsReadinessEvidence, verifyOperationsReadiness, verifyOperationsReadinessWithBundle } from "../scripts/ops/operations-readiness.mjs";

const SOURCE = "a".repeat(40);
const CANDIDATE = `release-pkg-sha256-v1-${"b".repeat(64)}`;
const DIGEST = `sha256:${"c".repeat(64)}`;
const ARTIFACT = `sha256:${"d".repeat(64)}`;
const SCRIPT = path.resolve("scripts/ops/operations-readiness.mjs");
const CONTROL_NOW = new Date("2026-08-19T10:00:00.000Z");
const check = (assertions) => ({ status: "verified", evidence_origin: "protected_external", candidate_id: CANDIDATE, source_commit: SOURCE, evidence_digest: DIGEST, observed_at: "2026-08-19T10:00:00.000Z", assertions });

function evidence(overrides = {}) {
  const value = {
    schema_version: 1, kind: "agentpass.operations-readiness-checklist", candidate_id: CANDIDATE, source_commit: SOURCE, artifact_digest: ARTIFACT,
    execution_mode: "protected_external", evidence_origin: "protected_external", started_at: "2026-08-19T09:00:00.000Z", completed_at: "2026-08-19T10:00:00.000Z",
    checks: {
      rollback: check({ authority_not_widened: true, deployment_rollback_verified: true, health_gate_verified: true, previous_revision_rejected: true, rollback_artifact_digest: DIGEST }),
      pitr: check({ backup_artifact_digest: DIGEST, backup_manifest_verified: true, pitr_restore_verified: true, recovery_target_bound: true, schema_head_match: true, tenant_integrity_verified: true }),
      revoke_emergency_stop: check({ ack_quorum_verified: true, emergency_stop_propagation_verified: true, existing_capability_denied: true, new_capability_denied: true, revoke_propagation_verified: true, terminal_state_verified: true }),
      alerting: check({ alert_rules_verified: true, counter_reset_fail_closed: true, delivery_verified: true, escalation_verified: true, policy_digest: DIGEST, secret_free_evidence: true }),
      tenant_isolation: check({ admin_scope_verified: true, cross_tenant_denied: true, no_cross_tenant_rows: true, pair_count: 4, rls_policy_verified: true, same_tenant_allowed: true, tenant_pair_matrix_verified: true })
    },
    operational_controls: operationalControls()
  };
  return merge(value, overrides);
}
function merge(base, overrides) {
  if (!overrides || typeof overrides !== "object" || Array.isArray(overrides)) return overrides ?? base;
  const result = { ...base }; for (const [key, value] of Object.entries(overrides)) result[key] = value && typeof value === "object" && !Array.isArray(value) ? merge(result[key] ?? {}, value) : value; return result;
}
function fixture(value, canonical = true) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-ops-readiness-")); const file = path.join(directory, "evidence.json");
  fs.writeFileSync(file, canonical ? `${canonicalJson(value)}\n` : `${JSON.stringify(value)}\n`, { mode: 0o600 }); return { directory, file };
}
function codeOf(fn) { try { fn(); return null; } catch (error) { return error instanceof OperationsReadinessError ? error.code : error; } }
function operationalControls(overrides = {}) {
  return merge({
    artifact_digest: ARTIFACT,
    candidate_id: CANDIDATE,
    evidence_digest: DIGEST,
    evidence_origin: "protected_external",
    evidence_retention: { access_audit_enabled: true, delete_protection_enabled: true, location_ref: "object-lock:operations-evidence-prod", retention_days: 365, storage_class: "immutable_worm" },
    execution_id: "ops-run-prod-20260819",
    execution_mode: "protected_external",
    expiry: { expires_at: "2026-09-01T10:00:00.000Z" },
    incident: { incident_owner_ref: "incident-command-prod", on_call_owner_ref: "oncall-primary-prod", revoke_owner_ref: "revoke-owner-prod", revoke_runbook_ref: "runbook:revoke:v1", revoke_status: "verified", revoke_verified_at: "2026-08-19T09:40:00.000Z", rollback_owner_ref: "rollback-owner-prod" },
    kill_switch: { fail_closed: true, last_verified_at: "2026-08-19T09:30:00.000Z", operation: "deny_new_and_existing_capabilities", owner_ref: "incident-command-prod", propagation_bound_ms: 30000, propagation_observed_ms: 125, runbook_ref: "runbook:kill-switch:v1", status: "verified" },
    observed_at: "2026-08-19T09:50:00.000Z",
    on_call: { acknowledged_at: "2026-08-19T09:16:00.000Z", owner_ref: "oncall-primary-prod", page_tested_at: "2026-08-19T09:15:00.000Z", route_ref: "rotation:oncall-primary-prod", status: "verified" },
    reviewer: { approval_authority: "review_only", independent: true, organization: "external-security-lab", reviewer_id: "reviewer-external-001", separate_signing_key: true },
    rollback: { fail_closed: true, last_verified_at: "2026-08-19T09:20:00.000Z", owner_ref: "rollback-owner-prod", runbook_ref: "runbook:rollback:v1", status: "verified", target_binding_verified: true },
    source_commit: SOURCE
  }, overrides);
}

test("verifies a complete protected-external operational gate but keeps it closed until independent qualification", () => {
  const result = verifyOperationsReadiness(evidence(), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE, expectedArtifactDigest: ARTIFACT, now: CONTROL_NOW });
  assert.equal(result.status, "structure_verified"); assert.equal(result.production_ready, false); assert.equal(result.production_readiness_blocker, "independent_qualification_required"); assert.equal(result.operational_controls_status, "verified"); assert.equal(result.artifact_digest, ARTIFACT); assert.equal(result.qualification_required, true); assert.deepEqual(result.checks, [...OPERATIONS_READINESS_CHECKS]); assert.match(result.evidence_sha256, /^[0-9a-f]{64}$/u);
});

test("rejects a checklist with no operational controls instead of treating it as a legacy pass", () => {
  const incomplete = evidence(); delete incomplete.operational_controls;
  assert.equal(codeOf(() => verifyOperationsReadiness(incomplete, { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE, expectedArtifactDigest: ARTIFACT, now: CONTROL_NOW })), "unknown_field");
});

test("accepts a complete operational preflight but keeps readiness closed until independent qualification", () => {
  const result = verifyOperationsReadiness(evidence({ operational_controls: operationalControls() }), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE, expectedArtifactDigest: ARTIFACT, now: CONTROL_NOW });
  assert.equal(result.status, "structure_verified"); assert.equal(result.operational_controls_status, "verified"); assert.equal(result.production_ready, false); assert.equal(result.production_readiness_blocker, "independent_qualification_required"); assert.equal(result.operational_controls_expires_at, "2026-09-01T10:00:00.000Z");
});

test("fails closed for missing or unsafe retention, owners, expiry, reviewer, rollback, and kill-switch controls", () => {
  const cases = [
    ["retention delete protection", { evidence_retention: { delete_protection_enabled: false } }, "not_proven"],
    ["expired controls", { expiry: { expires_at: "2026-08-19T09:59:59.000Z" } }, "operational_controls_expired"],
    ["unbound artifact", { artifact_digest: `sha256:${"e".repeat(64)}` }, "binding_mismatch"],
    ["unacknowledged on-call page", { on_call: { status: "pending" } }, "on_call_operation_not_ready"],
    ["unverified revoke operation", { incident: { revoke_status: "pending" } }, "revoke_operation_not_ready"],
    ["reviewer owner collision", { reviewer: { reviewer_id: "incident-command-prod" } }, "reviewer_separation_required"],
    ["rollback not verified", { rollback: { target_binding_verified: false } }, "rollback_operation_not_ready"],
    ["kill-switch operation incomplete", { kill_switch: { operation: "deny_new_only" } }, "kill_switch_operation_not_ready"],
    ["kill-switch measurement exceeded", { kill_switch: { propagation_observed_ms: 30001 } }, "kill_switch_operation_not_ready"],
    ["stale rollback verification", { rollback: { last_verified_at: "2026-07-18T09:20:00.000Z" } }, "rollback_operation_not_ready"],
    ["stale kill-switch verification", { kill_switch: { last_verified_at: "2026-07-18T09:30:00.000Z" } }, "kill_switch_operation_not_ready"]
  ];
  assert.equal(codeOf(() => verifyOperationsReadiness(evidence({ artifact_digest: `sha256:${"e".repeat(64)}` }), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE, expectedArtifactDigest: ARTIFACT, now: CONTROL_NOW })), "binding_mismatch", "root artifact substitution");
  for (const [label, overrides, expected] of cases) {
    assert.equal(codeOf(() => verifyOperationsReadiness(evidence({ operational_controls: operationalControls(overrides) }), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE, expectedArtifactDigest: ARTIFACT, now: CONTROL_NOW })), expected, label);
  }
});

test("requires the expected artifact binding and protected operational execution", () => {
  assert.equal(codeOf(() => verifyOperationsReadiness(evidence({ operational_controls: operationalControls() }), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE, now: CONTROL_NOW })), "binding_mismatch");
  assert.equal(codeOf(() => verifyOperationsReadiness(evidence({ operational_controls: operationalControls({ evidence_origin: "self_attested" }) }), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE, expectedArtifactDigest: ARTIFACT, now: CONTROL_NOW })), "not_proven");
});

test("never treats the structural envelope as qualification without an independent signed bundle", () => {
  assert.equal(codeOf(() => verifyOperationsReadinessWithBundle(evidence(), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE })), "independent_qualification_evidence_missing");
});

test("missing evidence is not_proven and never a local success", () => {
  const missing = path.join(os.tmpdir(), `agentpass-missing-${crypto.randomUUID()}.json`);
  assert.equal(codeOf(() => readOperationsReadinessEvidence(missing, { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE, expectedArtifactDigest: ARTIFACT })), "not_proven");
  const result = spawnSync(process.execPath, [SCRIPT, "verify", missing, CANDIDATE, SOURCE], { encoding: "utf8" }); assert.equal(result.status, 2); assert.equal(JSON.parse(result.stdout).status, "not_proven");
});

test("rejects unknown fields at root, check, and assertion boundaries", () => {
  assert.equal(codeOf(() => verifyOperationsReadiness(evidence({ unexpected: true }), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE, expectedArtifactDigest: ARTIFACT, now: CONTROL_NOW })), "unknown_field");
  assert.equal(codeOf(() => verifyOperationsReadiness(evidence({ checks: { rollback: { unexpected: true } } }), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE, expectedArtifactDigest: ARTIFACT, now: CONTROL_NOW })), "unknown_field");
  assert.equal(codeOf(() => verifyOperationsReadiness(evidence({ checks: { alerting: { assertions: { extra: true } } } }), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE, expectedArtifactDigest: ARTIFACT, now: CONTROL_NOW })), "unknown_field");
});

test("rejects candidate/source substitution at root and check level", () => {
  assert.equal(codeOf(() => verifyOperationsReadiness(evidence({ source_commit: "d".repeat(40) }), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE, expectedArtifactDigest: ARTIFACT, now: CONTROL_NOW })), "source_mismatch");
  assert.equal(codeOf(() => verifyOperationsReadiness(evidence({ checks: { pitr: { source_commit: "d".repeat(40) } } }), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE, expectedArtifactDigest: ARTIFACT, now: CONTROL_NOW })), "source_mismatch");
  assert.equal(codeOf(() => verifyOperationsReadiness(evidence({ checks: { tenant_isolation: { candidate_id: `release-pkg-sha256-v1-${"d".repeat(64)}` } } }), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE, expectedArtifactDigest: ARTIFACT, now: CONTROL_NOW })), "source_mismatch");
});

test("requires protected execution and every safety assertion", () => {
  assert.equal(codeOf(() => verifyOperationsReadiness(evidence({ execution_mode: "mock" }), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE, expectedArtifactDigest: ARTIFACT, now: CONTROL_NOW })), "not_proven");
  assert.equal(codeOf(() => verifyOperationsReadiness(evidence({ checks: { revoke_emergency_stop: { assertions: { emergency_stop_propagation_verified: false } } } }), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE, expectedArtifactDigest: ARTIFACT, now: CONTROL_NOW })), "not_proven");
  assert.equal(codeOf(() => verifyOperationsReadiness(evidence({ checks: { tenant_isolation: { assertions: { pair_count: 1 } } } }), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE, expectedArtifactDigest: ARTIFACT, now: CONTROL_NOW })), "invalid_assertion");
});

test("rejects duplicate keys and noncanonical files", () => {
  const value = fixture(evidence()); const duplicate = path.join(value.directory, "duplicate.json"); fs.writeFileSync(duplicate, '{"candidate_id":"x","candidate_id":"y"}\n', { mode: 0o600 });
  assert.equal(codeOf(() => readOperationsReadinessEvidence(duplicate, { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE, expectedArtifactDigest: ARTIFACT, now: CONTROL_NOW })), "duplicate_field");
  const noncanonical = fixture(evidence(), false); assert.equal(codeOf(() => readOperationsReadinessEvidence(noncanonical.file, { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE, expectedArtifactDigest: ARTIFACT, now: CONTROL_NOW })), "noncanonical_evidence");
});

test("CLI requires the independent bundle arguments and never closes a checklist alone", () => {
  const value = fixture(evidence()); const result = spawnSync(process.execPath, [SCRIPT, "verify", value.file, CANDIDATE, SOURCE], { encoding: "utf8" }); assert.equal(result.status, 2, result.stderr); assert.equal(JSON.parse(result.stdout).status, "not_proven");
  const relative = spawnSync(process.execPath, [SCRIPT, "verify", path.relative(process.cwd(), value.file), CANDIDATE, SOURCE], { encoding: "utf8" }); assert.equal(relative.status, 2); assert.equal(JSON.parse(relative.stdout).status, "not_proven");
});

test("checked-in runbook policy matches the validator's fixed five-check contract", () => {
  const policy = JSON.parse(fs.readFileSync(path.resolve("ops/operations-readiness/staging-checklist.v1.json"), "utf8"));
  assert.equal(policy.kind, "agentpass.operations-readiness-checklist-policy");
  assert.deepEqual(Object.keys(policy.checks).sort(), [...OPERATIONS_READINESS_CHECKS].sort());
  const expectedFields = Object.fromEntries(OPERATIONS_READINESS_CHECKS.map((name) => [name, Object.keys(evidence().checks[name].assertions).sort()]));
  assert.deepEqual(Object.fromEntries(Object.entries(policy.checks).map(([name, fields]) => [name, [...fields].sort()])), expectedFields);
  assert.deepEqual(policy.closure_rules, [
    "all_five_checks_verified",
    "all_checks_protected_external",
    "candidate_and_source_bound_at_root_and_check",
    "canonical_json_without_duplicate_or_unknown_fields",
    "missing_or_fixture_evidence_is_not_proven"
  ]);
});
