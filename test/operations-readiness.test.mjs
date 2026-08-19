import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import { canonicalJson } from "../packages/protocol/src/index.mjs";
import { OPERATIONS_READINESS_CHECKS, OperationsReadinessError, readOperationsReadinessEvidence, verifyOperationsReadiness } from "../scripts/ops/operations-readiness.mjs";

const SOURCE = "a".repeat(40);
const CANDIDATE = `release-pkg-sha256-v1-${"b".repeat(64)}`;
const DIGEST = `sha256:${"c".repeat(64)}`;
const SCRIPT = path.resolve("scripts/ops/operations-readiness.mjs");
const check = (assertions) => ({ status: "verified", evidence_origin: "protected_external", candidate_id: CANDIDATE, source_commit: SOURCE, evidence_digest: DIGEST, observed_at: "2026-08-19T10:00:00.000Z", assertions });

function evidence(overrides = {}) {
  const value = {
    schema_version: 1, kind: "agentpass.operations-readiness-checklist", candidate_id: CANDIDATE, source_commit: SOURCE,
    execution_mode: "protected_external", evidence_origin: "protected_external", started_at: "2026-08-19T09:00:00.000Z", completed_at: "2026-08-19T10:00:00.000Z",
    checks: {
      rollback: check({ authority_not_widened: true, deployment_rollback_verified: true, health_gate_verified: true, previous_revision_rejected: true, rollback_artifact_digest: DIGEST }),
      pitr: check({ backup_artifact_digest: DIGEST, backup_manifest_verified: true, pitr_restore_verified: true, recovery_target_bound: true, schema_head_match: true, tenant_integrity_verified: true }),
      revoke_emergency_stop: check({ ack_quorum_verified: true, emergency_stop_propagation_verified: true, existing_capability_denied: true, new_capability_denied: true, revoke_propagation_verified: true, terminal_state_verified: true }),
      alerting: check({ alert_rules_verified: true, counter_reset_fail_closed: true, delivery_verified: true, escalation_verified: true, policy_digest: DIGEST, secret_free_evidence: true }),
      tenant_isolation: check({ admin_scope_verified: true, cross_tenant_denied: true, no_cross_tenant_rows: true, pair_count: 4, rls_policy_verified: true, same_tenant_allowed: true, tenant_pair_matrix_verified: true })
    }
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

test("closes only a complete protected-external five-check bundle", () => {
  const result = verifyOperationsReadiness(evidence(), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE });
  assert.equal(result.status, "closed"); assert.deepEqual(result.checks, [...OPERATIONS_READINESS_CHECKS]); assert.match(result.evidence_sha256, /^[0-9a-f]{64}$/u);
});

test("missing evidence is not_proven and never a local success", () => {
  const missing = path.join(os.tmpdir(), `agentpass-missing-${crypto.randomUUID()}.json`);
  assert.equal(codeOf(() => readOperationsReadinessEvidence(missing, { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE })), "not_proven");
  const result = spawnSync(process.execPath, [SCRIPT, "verify", missing, CANDIDATE, SOURCE], { encoding: "utf8" }); assert.equal(result.status, 2); assert.equal(JSON.parse(result.stdout).status, "not_proven");
});

test("rejects unknown fields at root, check, and assertion boundaries", () => {
  assert.equal(codeOf(() => verifyOperationsReadiness(evidence({ unexpected: true }), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE })), "unknown_field");
  assert.equal(codeOf(() => verifyOperationsReadiness(evidence({ checks: { rollback: { unexpected: true } } }), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE })), "unknown_field");
  assert.equal(codeOf(() => verifyOperationsReadiness(evidence({ checks: { alerting: { assertions: { extra: true } } } }), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE })), "unknown_field");
});

test("rejects candidate/source substitution at root and check level", () => {
  assert.equal(codeOf(() => verifyOperationsReadiness(evidence({ source_commit: "d".repeat(40) }), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE })), "source_mismatch");
  assert.equal(codeOf(() => verifyOperationsReadiness(evidence({ checks: { pitr: { source_commit: "d".repeat(40) } } }), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE })), "source_mismatch");
  assert.equal(codeOf(() => verifyOperationsReadiness(evidence({ checks: { tenant_isolation: { candidate_id: `release-pkg-sha256-v1-${"d".repeat(64)}` } } }), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE })), "source_mismatch");
});

test("requires protected execution and every safety assertion", () => {
  assert.equal(codeOf(() => verifyOperationsReadiness(evidence({ execution_mode: "mock" }), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE })), "not_proven");
  assert.equal(codeOf(() => verifyOperationsReadiness(evidence({ checks: { revoke_emergency_stop: { assertions: { emergency_stop_propagation_verified: false } } } }), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE })), "not_proven");
  assert.equal(codeOf(() => verifyOperationsReadiness(evidence({ checks: { tenant_isolation: { assertions: { pair_count: 1 } } } }), { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE })), "invalid_assertion");
});

test("rejects duplicate keys and noncanonical files", () => {
  const value = fixture(evidence()); const duplicate = path.join(value.directory, "duplicate.json"); fs.writeFileSync(duplicate, '{"candidate_id":"x","candidate_id":"y"}\n', { mode: 0o600 });
  assert.equal(codeOf(() => readOperationsReadinessEvidence(duplicate, { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE })), "duplicate_field");
  const noncanonical = fixture(evidence(), false); assert.equal(codeOf(() => readOperationsReadinessEvidence(noncanonical.file, { expectedCandidateId: CANDIDATE, expectedSourceCommit: SOURCE })), "noncanonical_evidence");
});

test("CLI closes only for an absolute candidate-bound file", () => {
  const value = fixture(evidence()); const result = spawnSync(process.execPath, [SCRIPT, "verify", value.file, CANDIDATE, SOURCE], { encoding: "utf8" }); assert.equal(result.status, 0, result.stderr); assert.equal(JSON.parse(result.stdout).status, "closed");
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
