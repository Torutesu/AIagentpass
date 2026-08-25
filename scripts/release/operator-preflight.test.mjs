import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { verifyOperatorPreflight } from "./operator-preflight.mjs";

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const sourceCommit = sha256("protected-source").slice(0, 40);
const sourceTree = sha256("protected-tree").slice(0, 40);
const artifactBytes = Buffer.from("protected-release-artifact\n");
const artifactSha256 = sha256(artifactBytes);
const candidateId = `release-pkg-sha256-v1-${artifactSha256}`;
const testClockMs = Date.now();
const at = (offsetMs) => new Date(testClockMs + offsetMs).toISOString();
const now = at(0);

const externalCheck = (checkId, artifactDigest) => ({
  check_id: checkId, status: "passed", expected: { type: "boolean", value: true }, observed: { type: "boolean", value: true }, evidence_sha256: artifactDigest
});
const required = {
  github_actions: ["canonical_push_run", "exact_six_lanes", "source_sha_binding", "artifact_inventory_binding"],
  postgresql: ["postgresql_16_version", "postgresql_17_version", "migration_contract", "role_rls_boundary", "concurrency_rollback"],
  kms: ["provider_identity", "key_version_binding", "iam_matrix", "rotation_disable", "response_loss_reconciliation", "canary_sign_verify"],
  webauthn: ["authenticator_origin_rp", "durable_one_time_consumption", "replay_rejection", "stale_context_rejection", "outage_fail_closed"],
  macos_hardware: ["apple_silicon_signed_notarized", "intel_t2_signed_notarized", "secure_enclave_identity", "negative_identity_entitlement", "lifecycle_recovery"]
};

function externalEvidence() {
  const gateArtifacts = Object.fromEntries(Object.keys(required).map((name, index) => [name, sha256(`gate-${name}-${index}`)]));
  const gateJobIds = Object.fromEntries(Object.keys(required).map((name, index) => [name, String(2000 + index)]));
  const gates = Object.fromEntries(Object.entries(required).map(([name, checks], index) => [name, {
    status: "passed", qualified: true, reason: null,
    execution: {
      kind: "external_runner", real_execution: true, runner_id: `runner-${name}`, run_id: "42", job_id: gateJobIds[name], run_attempt: "3",
      source_commit: sourceCommit, source_tree: sourceTree, artifact_sha256: gateArtifacts[name], started_at: "2026-08-20T00:00:00.000Z", completed_at: "2026-08-20T00:01:00.000Z",
      environment: { kind: name === "kms" ? "managed_kms" : name, identity: `${name}-qualification` }
    },
    required_checks: checks,
    checks: checks.map((checkId) => externalCheck(checkId, sha256(`check-${name}-${checkId}`)))
  }]));
  return {
    evidence: { schema_version: 1, kind: "agentpass-external-qualification", status: "passed", qualified: true, reason: null,
      release: { repository: "Torutesu/AIagentpass", source_commit: sourceCommit, source_tree: sourceTree, artifact_sha256: artifactSha256, ci_run_id: "42", ci_run_attempt: "3" }, gates },
    binding: { repository: "Torutesu/AIagentpass", source_commit: sourceCommit, source_tree: sourceTree, release_artifact_sha256: artifactSha256, ci_run_id: "42", ci_run_attempt: "3", gate_artifacts: gateArtifacts, gate_job_ids: gateJobIds }
  };
}

function fixtures(root) {
  const manifest = { schema_version: 4, product: "AgentPass", version: "1.2.3", source: { commit: sourceCommit, tree: sourceTree, tag: "v1.2.3" }, generated_at: now,
    candidate_id: candidateId, artifacts: [{ name: "AgentPass-1.2.3.pkg", role: "product", media_type: "application/vnd.apple.installer+xml", bytes: artifactBytes.length, sha256: artifactSha256 }] };
  const ca = { schema_version: 1, kind: "agentpass-ca-verification", status: "passed", qualified: true, source_commit: sourceCommit, source_tree: sourceTree, artifact_sha256: artifactSha256,
    server_name: "staging-api.agentpass.example", trust_store: "protected-system-ca", trust_anchor_sha256: sha256("trust-anchor"), leaf_sha256: sha256("leaf"), verified_at: at(-2 * 60 * 60 * 1_000), expires_at: at(21 * 24 * 60 * 60 * 1_000) };
  const backup = { schema_version: 1, kind: "agentpass-backup-pitr-verification", status: "passed", qualified: true, source_commit: sourceCommit, source_tree: sourceTree, artifact_sha256: artifactSha256,
    provider: "managed-postgres-backup", backup_id: "backup-preflight-001", recovery_point_at: at(-3 * 60 * 60 * 1_000), backup_completed_at: at(-2.5 * 60 * 60 * 1_000), restore_target_id: "pitr-isolated-001", restore_completed_at: at(-2 * 60 * 60 * 1_000),
    source_authority_sha256: sha256("authority"), restored_authority_sha256: sha256("authority"), rpo_seconds: 300, rto_seconds: 900, authority_compared: true, isolated_restore: true, no_live_restore: true };
  const rollback = { schema_version: 1, kind: "agentpass-rollback-verification", status: "passed", qualified: true, environment: "staging", candidate_id: candidateId, source_commit: sourceCommit, source_tree: sourceTree, artifact_sha256: artifactSha256,
    deployment_id: "staging-api", current_revision: "rev-current-42", rollback_target_revision: "rev-previous-41", run_id: "999", run_attempt: "1", job_id: "rollback-verify", executed_at: at(-90 * 60 * 1_000), tested: true, target_ready: true, traffic_restored: true, reused_artifact: true };
  const external = externalEvidence();
  const report = Buffer.from("signed reviewer report for protected candidate\n");
  const packet = { schema_version: 1, kind: "agentpass-protected-operator-preflight", operator_id: "release-operator@example.test",
    candidate: { artifact_name: "AgentPass-1.2.3.pkg", artifact_sha256: artifactSha256, candidate_id: candidateId, manifest_sha256: sha256(canonicalJson(manifest)), source_commit: sourceCommit, source_tree: sourceTree },
    ca: { evidence_sha256: sha256(canonicalJson(ca)) }, backup_pitr: { evidence_sha256: sha256(canonicalJson(backup)) },
    external: { evidence_sha256: sha256(canonicalJson(external.evidence)), binding_sha256: sha256(canonicalJson(external.binding)) },
    expiry: { reviewer_id: "security-reviewer@example.test", report_sha256: sha256(report), reviewed_at: at(-2 * 60 * 60 * 1_000), expires_at: at(5 * 24 * 60 * 60 * 1_000) },
    rollback: { evidence_sha256: sha256(canonicalJson(rollback)) } };
  const values = { manifest, ca, backup, rollback, external: external.evidence, binding: external.binding, report, packet };
  const files = {};
  for (const [name, value] of Object.entries(values)) {
    const file = path.join(root, `${name}.${name === "report" ? "txt" : "json"}`);
    fs.writeFileSync(file, Buffer.isBuffer(value) ? value : canonicalJson(value), { mode: 0o600 });
    files[name] = file;
  }
  const artifact = path.join(root, "AgentPass-1.2.3.pkg");
  fs.writeFileSync(artifact, artifactBytes, { mode: 0o600 });
  files.artifact = artifact;
  return { files, values };
}

function verifyArgs(fixture) {
  return { manifestPath: fixture.files.manifest, artifactPath: fixture.files.artifact, caEvidencePath: fixture.files.ca, backupPitrEvidencePath: fixture.files.backup,
    externalEvidencePath: fixture.files.external, externalBindingPath: fixture.files.binding, rollbackEvidencePath: fixture.files.rollback, reviewerReportPath: fixture.files.report, now: new Date(now) };
}

test("operator preflight passes only for exact artifact, real CA/PITR, external evidence, expiry, and rollback bindings", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-operator-preflight-"));
  try {
    const fixture = fixtures(root);
    const result = verifyOperatorPreflight(fixture.values.packet, verifyArgs(fixture));
    assert.equal(result.status, "passed");
    assert.equal(result.qualified, true);
    assert.deepEqual(Object.keys(result.checks).sort(), ["artifact_binding", "backup_pitr", "ca", "expiry", "external_evidence", "rollback"]);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("operator preflight rejects missing, placeholder, stale, substituted, and unexecuted proof", () => {
  const mutations = [
    ["expired review", (f) => { f.values.packet.expiry.expires_at = at(-1_000); }],
    ["placeholder CA", (f) => { f.values.ca.leaf_sha256 = "0".repeat(64); fs.writeFileSync(f.files.ca, canonicalJson(f.values.ca)); }],
    ["PITR authority mismatch", (f) => { f.values.backup.restored_authority_sha256 = sha256("different-authority"); fs.writeFileSync(f.files.backup, canonicalJson(f.values.backup)); }],
    ["artifact substitution", (f) => { fs.writeFileSync(f.files.artifact, "substituted\n"); }],
    ["external not_run", (f) => { f.values.external.status = "not_run"; f.values.external.qualified = false; f.values.external.reason = "external_runner_unavailable"; fs.writeFileSync(f.files.external, canonicalJson(f.values.external)); }],
    ["rollback not tested", (f) => { f.values.rollback.tested = false; fs.writeFileSync(f.files.rollback, canonicalJson(f.values.rollback)); }]
  ];
  for (const [label, mutate] of mutations) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-operator-preflight-negative-"));
    try { const fixture = fixtures(root); mutate(fixture); assert.throws(() => verifyOperatorPreflight(fixture.values.packet, verifyArgs(fixture)), /invalid|mismatch|does not match|not derived|not bound|expired|not_run|not tested|not executed|immutable|substitution|passed|binding/iu, label); }
    finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
});

test("operator preflight CLI emits canonical pass and fails closed on noncanonical or symlink evidence", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-operator-preflight-cli-"));
  try {
    const fixture = fixtures(root);
    const script = path.resolve("scripts/release/operator-preflight.mjs");
    const args = [script, "verify", fixture.files.packet, fixture.files.manifest, fixture.files.artifact, fixture.files.ca, fixture.files.backup, fixture.files.external, fixture.files.binding, fixture.files.rollback, fixture.files.report];
    const ok = spawnSync(process.execPath, args, { encoding: "utf8" });
    assert.equal(ok.status, 0, ok.stderr);
    assert.equal(ok.stdout, `${canonicalJson(JSON.parse(ok.stdout))}\n`);
    const staleClock = spawnSync(process.execPath, [...args, "--now=1970-01-01T00:00:00.000Z"], { encoding: "utf8" });
    assert.notEqual(staleClock.status, 0);
    assert.match(staleClock.stderr, /usage/u);
    fs.writeFileSync(fixture.files.ca, `${canonicalJson(fixture.values.ca)}\n`);
    const badCanonical = spawnSync(process.execPath, args, { encoding: "utf8" });
    assert.notEqual(badCanonical.status, 0);
    fs.rmSync(fixture.files.ca);
    fs.symlinkSync(fixture.files.backup, fixture.files.ca);
    const badLink = spawnSync(process.execPath, args, { encoding: "utf8" });
    assert.notEqual(badLink.status, 0);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
